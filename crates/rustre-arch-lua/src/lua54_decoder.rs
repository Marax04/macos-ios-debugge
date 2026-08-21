//! Lua 5.4 bytecode decoder — extended types, proto parser, and disassembler.
//!
//! Lua 5.4 header magic: `\x1bLua` (0x1b 0x4c 0x75 0x61) followed by
//! version byte `0x54`.
//!
//! New opcodes in 5.4 vs 5.3:
//! LOADI, LOADF, GETI, POWI, POWF, IDIVI, BANDI, BORI, BXORI, SHRI, SHLI,
//! TBC (to-be-closed), CLOSE, MMBINI, MMBINK, VARARGPREP, RETURN0, RETURN1,
//! TFORPREP, EQI, EQK, LTI, GTI, LEI, GEI.

use crate::{
    LuaArch, LuaConst, LuaVersion, decode_lua54, get_a54, get_b54, get_c54, get_k54, get_op54,
    get_sbx54, get_sj54,
};
pub use crate::{MAXARG_SBX, get_ax54, get_bx54};
pub use rustre_core::arch::Architecture;
use rustre_core::arch::InstrFlags;
use rustre_core::address::Address;
pub use rustre_core::errors::CoreError;
use std::fmt;

use anyhow::Context as _;

// ── Lua54Header ───────────────────────────────────────────────────────────────

/// Lua 5.4 binary chunk header.
///
/// Layout (total: variable):
/// ```text
/// [0..4]  Magic  \x1b L u a
/// [4]     Version  0x54
/// [5]     Format   0x00 (official)
/// [6..12] LUAC_DATA  \x19\x93\r\n\x1a\n
/// [12]    Size of instruction  4
/// [13]    Size of lua_Integer  8
/// [14]    Size of lua_Number   8
/// [15..23] LUAC_INT  0x5678 (as lua_Integer)
/// [23..31] LUAC_NUM  370.5  (as lua_Number)
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Lua54Header {
    pub version: u8,
    pub format: u8,
    pub instruction_size: u8,
    pub integer_size: u8,
    pub number_size: u8,
    pub luac_int: i64,
    pub luac_num: f64,
}

/// Magic bytes for a Lua binary chunk.
pub const LUA_MAGIC: [u8; 4] = [0x1b, b'L', b'u', b'a'];
/// Version byte for Lua 5.4.
pub const LUA54_VERSION: u8 = 0x54;
/// Lua 5.4 `LUAC_DATA` bytes (endian/integrity check).
pub const LUAC_DATA: [u8; 6] = [0x19, 0x93, 0x0d, 0x0a, 0x1a, 0x0a];

/// Errors from Lua 5.4 header / proto parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lua54Error {
    TooShort,
    BadMagic,
    WrongVersion(u8),
    BadFormat,
    BadLuacData,
    TruncatedProto,
    UnsupportedOpcode(u8),
}

impl fmt::Display for Lua54Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "buffer too short"),
            Self::BadMagic => write!(f, "bad Lua magic"),
            Self::WrongVersion(v) => write!(f, "expected Lua 5.4, got {v:#04x}"),
            Self::BadFormat => write!(f, "non-zero format byte"),
            Self::BadLuacData => write!(f, "LUAC_DATA mismatch"),
            Self::TruncatedProto => write!(f, "truncated proto"),
            Self::UnsupportedOpcode(o) => write!(f, "unsupported opcode {o}"),
        }
    }
}

/// Parse the first 31 bytes of a Lua 5.4 chunk header.
///
/// # Errors
///
/// Returns an error when the input bytes are malformed, truncated, or
/// otherwise cannot be decoded.
///
/// # Panics
///
/// Panics when an argument is outside the range the instruction encoding
/// can represent; callers must validate untrusted values first.
pub fn parse_lua54_header(data: &[u8]) -> Result<Lua54Header, Lua54Error> {
    if data.len() < 31 {
        return Err(Lua54Error::TooShort);
    }
    if data[0..4] != LUA_MAGIC {
        return Err(Lua54Error::BadMagic);
    }
    let version = data[4];
    if version != LUA54_VERSION {
        return Err(Lua54Error::WrongVersion(version));
    }
    let format = data[5];
    if format != 0 {
        return Err(Lua54Error::BadFormat);
    }
    if data[6..12] != LUAC_DATA {
        return Err(Lua54Error::BadLuacData);
    }
    let instruction_size = data[12];
    let integer_size = data[13];
    let number_size = data[14];
    let luac_int = i64::from_le_bytes(data[15..23].try_into().unwrap());
    let luac_num = f64::from_le_bytes(data[23..31].try_into().unwrap());
    Ok(Lua54Header {
        version,
        format,
        instruction_size,
        integer_size,
        number_size,
        luac_int,
        luac_num,
    })
}

/// Parse a Lua 5.4 chunk header, returning an [`anyhow::Error`] on failure.
///
/// This is a convenience wrapper over [`parse_lua54_header`] for callers that
/// use `anyhow` error chains across multiple fallible parsing steps.
///
/// # Errors
///
/// Returns an error when the input bytes are malformed, truncated, or
/// otherwise cannot be decoded.
pub fn parse_lua54_header_anyhow(data: &[u8]) -> anyhow::Result<Lua54Header> {
    parse_lua54_header(data)
        .map_err(|e| anyhow::anyhow!("{e}"))
        .with_context(|| format!("failed to parse Lua 5.4 header ({} bytes)", data.len()))
}

// ── i/k mode variations ───────────────────────────────────────────────────────

/// Whether an operand uses the "k" (constant pool) flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandMode {
    /// Register mode.
    Register,
    /// Constant-pool mode (k bit = 1).
    Constant,
}

/// Decode the k-mode for operand B in an iABC instruction.
#[must_use] 
pub const fn b_mode(word: u32) -> OperandMode {
    if get_k54(word) != 0 {
        OperandMode::Constant
    } else {
        OperandMode::Register
    }
}

/// Decode the k-mode for operand C in an iABC instruction.
/// In Lua 5.4 the C operand uses the bit above C for k.
#[must_use] 
pub const fn c_mode_from_next_word(next_word: u32) -> OperandMode {
    // Next instruction may be EXTRAARG providing k for C.
    let next_op = get_op54(next_word);
    if next_op == 80 {
        OperandMode::Constant
    } else {
        OperandMode::Register
    }
}

// ── Decoded instruction ───────────────────────────────────────────────────────

/// A fully-decoded Lua 5.4 instruction with all operands extracted.
#[derive(Debug, Clone)]
pub struct Lua54Insn {
    pub op: u8,
    pub mnemonic: String,
    pub operands: String,
    pub flags: InstrFlags,
    /// Raw 32-bit word.
    pub word: u32,
    /// A operand (8-bit).
    pub a: u32,
    /// B operand (8-bit).
    pub b: u32,
    /// C operand (8-bit).
    pub c: u32,
    /// k flag.
    pub k: u32,
}

impl fmt::Display for Lua54Insn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.operands.is_empty() {
            write!(f, "{}", self.mnemonic)
        } else {
            write!(f, "{:<12} {}", self.mnemonic, self.operands)
        }
    }
}

/// Decode a single Lua 5.4 instruction word into a [`Lua54Insn`].
///
/// # Errors
///
/// Returns an error when the input bytes are malformed, truncated, or
/// otherwise cannot be decoded.
pub fn decode_lua54_insn(word: u32, address: Address) -> Result<Lua54Insn, Lua54Error> {
    let op = get_op54(word);
    let (mnemonic, operands, flags) =
        decode_lua54(word, address).map_err(|_| Lua54Error::UnsupportedOpcode(op))?;
    Ok(Lua54Insn {
        op,
        mnemonic,
        operands,
        flags,
        word,
        a: get_a54(word),
        b: get_b54(word),
        c: get_c54(word),
        k: get_k54(word),
    })
}

// ── Lua54Proto ────────────────────────────────────────────────────────────────

/// A Lua 5.4 function prototype parsed from bytecode.
#[derive(Debug, Clone)]
pub struct Lua54Proto {
    /// Source name (debug info).
    pub source_name: String,
    /// First and last lines defined.
    pub line_defined: u32,
    pub last_line_defined: u32,
    /// Number of parameters.
    pub num_params: u8,
    /// Whether this proto is a vararg function.
    pub is_vararg: bool,
    /// Maximum stack size (register count).
    pub max_stack: u8,
    /// Raw instruction words.
    pub instructions: Vec<u32>,
    /// Constant pool.
    pub constants: Vec<Lua54Const>,
    /// Upvalue count.
    pub upvalue_count: u8,
    /// Nested protos (child functions).
    pub protos: Vec<Self>,
}

impl Lua54Proto {
    /// Return the number of instructions in this proto.
    #[must_use] 
    pub const fn insn_count(&self) -> usize {
        self.instructions.len()
    }

    /// Disassemble all instructions in this proto.
    #[must_use] 
    pub fn disassemble(&self) -> Vec<Result<Lua54Insn, Lua54Error>> {
        self.instructions
            .iter()
            .enumerate()
            .map(|(i, &word)| decode_lua54_insn(word, Address::new(i as u64 * 4)))
            .collect()
    }

    /// Count instructions of a given opcode.
    #[must_use] 
    pub fn count_opcode(&self, op: u8) -> usize {
        self.instructions
            .iter()
            .filter(|&&w| get_op54(w) == op)
            .count()
    }

    /// Find all jump targets (absolute instruction indices).
    #[must_use] 
    pub fn jump_targets(&self) -> Vec<usize> {
        let mut targets = Vec::with_capacity(self.instructions.len() / 8);
        for (i, &word) in self.instructions.iter().enumerate() {
            let op = get_op54(word);
            // JMP = 54 (isJ format), FORPREP/FORLOOP/TFORPREP/TFORLOOP = 71-73,75
            if op == 54 {
                let sj = get_sj54(word);
                let raw = i64::try_from(i)
                        .unwrap_or(i64::MAX)
                        .wrapping_add(1)
                        .wrapping_add(i64::from(sj));
                if let Ok(target) = usize::try_from(raw) {
                        targets.push(target);
                    }
            } else if matches!(op, 71 | 72 | 73 | 75) {
                let sbx = get_sbx54(word);
                let raw = i64::try_from(i)
                        .unwrap_or(i64::MAX)
                        .wrapping_add(1)
                        .wrapping_add(i64::from(sbx));
                if let Ok(target) = usize::try_from(raw) {
                        targets.push(target);
                    }
            }
        }
        targets
    }
}

impl fmt::Display for Lua54Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Lua54Proto({:?}, insns={}, consts={})",
            self.source_name,
            self.instructions.len(),
            self.constants.len()
        )
    }
}

// ── Lua54Const ────────────────────────────────────────────────────────────────

/// A constant in the Lua 5.4 constant pool.
#[derive(Debug, Clone, PartialEq)]
pub enum Lua54Const {
    Nil,
    False,
    True,
    Integer(i64),
    Float(f64),
    ShortString(String),
    LongString(String),
}

impl fmt::Display for Lua54Const {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nil => write!(f, "nil"),
            Self::False => write!(f, "false"),
            Self::True => write!(f, "true"),
            Self::Integer(i) => write!(f, "{i}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::ShortString(s) | Self::LongString(s) => write!(f, "{s:?}"),
        }
    }
}

impl From<Lua54Const> for LuaConst {
    fn from(c: Lua54Const) -> Self {
        match c {
            Lua54Const::Nil => Self::Nil,
            Lua54Const::False => Self::Bool(false),
            Lua54Const::True => Self::Bool(true),
            Lua54Const::Integer(i) => Self::Int(i),
            Lua54Const::Float(f) => Self::Float(f),
            Lua54Const::ShortString(s) | Lua54Const::LongString(s) => Self::String(s),
        }
    }
}

// ── Lua54Disassembler ─────────────────────────────────────────────────────────

/// Disassembler for Lua 5.4 bytecode chunks.
pub struct Lua54Disassembler {
    arch: LuaArch,
    /// Whether to include opcode numbers in output.
    pub show_opcode_number: bool,
    /// Whether to show raw hex words.
    pub show_hex: bool,
}

impl Lua54Disassembler {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            arch: LuaArch::with_version(LuaVersion::Lua54),
            show_opcode_number: false,
            show_hex: false,
        }
    }

    /// Borrow the underlying [`LuaArch`] (always pinned to Lua 5.4).
    #[must_use]
    pub const fn arch(&self) -> &LuaArch {
        &self.arch
    }

    /// Disassemble a sequence of 4-byte words starting at `base_insn_index`.
    #[must_use] 
    pub fn disassemble_words(
        &self,
        words: &[u32],
        base_insn_index: usize,
    ) -> Vec<Result<Lua54Insn, Lua54Error>> {
        words
            .iter()
            .enumerate()
            .map(|(i, &word)| {
                let idx = base_insn_index + i;
                decode_lua54_insn(word, Address::new(idx as u64 * 4))
            })
            .collect()
    }

    /// Disassemble raw bytes (must be a multiple of 4).
    #[must_use] 
    pub fn disassemble_bytes(
        &self,
        bytes: &[u8],
        base_offset: u64,
    ) -> Vec<Result<Lua54Insn, Lua54Error>> {
        let mut results = Vec::with_capacity(bytes.len() / 4);
        let mut offset = 0usize;
        while offset + 4 <= bytes.len() {
            let word = u32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]);
            let addr = Address::new(base_offset + offset as u64);
            results.push(decode_lua54_insn(word, addr));
            offset += 4;
        }
        results
    }

    /// Format a disassembly listing for a sequence of words.
    #[must_use] 
    pub fn listing(&self, words: &[u32]) -> String {
        let mut lines = Vec::with_capacity(words.len());
        for (i, &word) in words.iter().enumerate() {
            let addr = i as u64 * 4;
            match decode_lua54_insn(word, Address::new(addr)) {
                Ok(insn) => {
                    let hex = if self.show_hex {
                        format!(" [{word:08x}]")
                    } else {
                        String::new()
                    };
                    let num = if self.show_opcode_number {
                        format!("[{:02x}] ", insn.op)
                    } else {
                        String::new()
                    };
                    lines.push(format!("{i:4}: {num}{insn}{hex}"));
                }
                Err(e) => {
                    lines.push(format!("{i:4}: ERROR({e})"));
                }
            }
        }
        lines.join("\n")
    }

    /// Count the number of each opcode in a sequence of words.
    #[must_use] 
    pub fn opcode_histogram(&self, words: &[u32]) -> std::collections::HashMap<u8, usize> {
        let mut hist = std::collections::HashMap::with_capacity(64);
        for &w in words {
            let op = get_op54(w);
            *hist.entry(op).or_insert(0) += 1;
        }
        hist
    }

    /// Check whether a byte slice looks like Lua 5.4 bytecode.
    #[must_use] 
    pub fn sniff(data: &[u8]) -> bool {
        if data.len() < 5 {
            return false;
        }
        data[0..4] == LUA_MAGIC && data[4] == LUA54_VERSION
    }
}

impl Default for Lua54Disassembler {
    fn default() -> Self {
        Self::new()
    }
}

// ── Instruction builder helpers ───────────────────────────────────────────────

/// Build a Lua 5.4 LOADI instruction (iAsBx: load integer into R(A)).
#[must_use] 
pub fn make_loadi(a: u32, i: i32) -> u32 {
    // LOADI = opcode 1
    crate::make_iasbx(1, a, i)
}

/// Build a Lua 5.4 LOADF instruction (iAsBx: load float into R(A)).
#[must_use] 
pub fn make_loadf(a: u32, f: i32) -> u32 {
    // LOADF = opcode 2
    crate::make_iasbx(2, a, f)
}

/// Build a Lua 5.4 GETI instruction (iABC: R(A) = R(B)[C]).
#[must_use] 
pub const fn make_geti(a: u32, b: u32, c: u32) -> u32 {
    // GETI = opcode 11
    crate::make_iabc(11, a, b, c, 0)
}

/// Build a Lua 5.4 TBC instruction (A = to-be-closed variable).
#[must_use] 
pub const fn make_tbc(a: u32) -> u32 {
    // TBC = opcode 53
    crate::make_iabc(53, a, 0, 0, 0)
}

/// Build a Lua 5.4 CLOSE instruction.
#[must_use] 
pub const fn make_close(a: u32) -> u32 {
    // CLOSE = opcode 52
    crate::make_iabc(52, a, 0, 0, 0)
}

/// Build a Lua 5.4 SHRI instruction (R(A) = R(B) >> C).
#[must_use] 
pub const fn make_shri(a: u32, b: u32, c: i32) -> u32 {
    // SHRI = opcode 30; C is signed (bias 127)
    let c_biased = (c + 127).cast_unsigned() & 0xff;
    crate::make_iabc(30, a, b, c_biased, 0)
}

/// Build a Lua 5.4 SHLI instruction (R(A) = R(B) << C).
#[must_use] 
pub const fn make_shli(a: u32, b: u32, c: i32) -> u32 {
    // SHLI = opcode 31
    let c_biased = (c + 127).cast_unsigned() & 0xff;
    crate::make_iabc(31, a, b, c_biased, 0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LUA54_OPCODES, make_iabc, make_iabx, make_iasbx, make_isj};

    // ── Header parsing ────────────────────────────────────────────────────────

    fn valid_header() -> Vec<u8> {
        let mut h = vec![0u8; 31];
        h[0..4].copy_from_slice(&LUA_MAGIC);
        h[4] = LUA54_VERSION;
        h[5] = 0;
        h[6..12].copy_from_slice(&LUAC_DATA);
        h[12] = 4;
        h[13] = 8;
        h[14] = 8;
        h[15..23].copy_from_slice(&0x5678i64.to_le_bytes());
        h[23..31].copy_from_slice(&370.5f64.to_le_bytes());
        h
    }

    #[test]
    fn test_parse_header_ok() {
        let h = valid_header();
        let hdr = parse_lua54_header(&h).unwrap();
        assert_eq!(hdr.version, 0x54);
        assert_eq!(hdr.instruction_size, 4);
        assert_eq!(hdr.integer_size, 8);
        assert_eq!(hdr.luac_int, 0x5678);
        assert!((hdr.luac_num - 370.5).abs() < 1e-9);
    }

    #[test]
    fn test_parse_header_too_short() {
        assert_eq!(parse_lua54_header(&[0u8; 4]), Err(Lua54Error::TooShort));
    }

    #[test]
    fn test_parse_header_bad_magic() {
        let mut h = valid_header();
        h[0] = 0x00;
        assert_eq!(parse_lua54_header(&h), Err(Lua54Error::BadMagic));
    }

    #[test]
    fn test_parse_header_wrong_version() {
        let mut h = valid_header();
        h[4] = 0x53;
        assert!(matches!(
            parse_lua54_header(&h),
            Err(Lua54Error::WrongVersion(0x53))
        ));
    }

    #[test]
    fn test_parse_header_bad_luac_data() {
        let mut h = valid_header();
        h[6] = 0xFF;
        assert_eq!(parse_lua54_header(&h), Err(Lua54Error::BadLuacData));
    }

    // ── decode_lua54_insn ─────────────────────────────────────────────────────

    #[test]
    fn test_decode_move() {
        // MOVE = opcode 0: iABC
        let word = make_iabc(0, 1, 2, 3, 0);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.op, 0);
        assert_eq!(insn.mnemonic, "move");
        assert_eq!(insn.a, 1);
        assert_eq!(insn.b, 2);
        assert_eq!(insn.c, 3);
    }

    #[test]
    fn test_decode_loadi() {
        let word = make_loadi(5, -10);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.op, 1);
        assert_eq!(insn.mnemonic, "loadi");
        assert_eq!(insn.a, 5);
    }

    #[test]
    fn test_decode_loadf() {
        let word = make_loadf(3, 42);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.op, 2);
        assert_eq!(insn.mnemonic, "loadf");
    }

    #[test]
    fn test_decode_geti() {
        let word = make_geti(1, 2, 5);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.mnemonic, "geti");
        assert_eq!(insn.a, 1);
        assert_eq!(insn.b, 2);
        assert_eq!(insn.c, 5);
    }

    #[test]
    fn test_decode_tbc() {
        let word = make_tbc(7);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.mnemonic, "tbc");
    }

    #[test]
    fn test_decode_close() {
        let word = make_close(4);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.mnemonic, "close");
    }

    #[test]
    fn test_decode_shri() {
        let word = make_shri(0, 1, 3);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.mnemonic, "shri");
    }

    #[test]
    fn test_decode_shli() {
        let word = make_shli(0, 1, 4);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.mnemonic, "shli");
    }

    #[test]
    fn test_decode_jmp() {
        // JMP = opcode 54 (isJ format)
        let word = make_isj(54, 10);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.mnemonic, "jmp");
        assert!(insn.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_decode_call() {
        // CALL = opcode 66
        let word = make_iabc(66, 0, 2, 1, 0);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.mnemonic, "call");
        assert!(insn.flags.contains(InstrFlags::CALL));
    }

    #[test]
    fn test_decode_return() {
        // RETURN = opcode 68
        let word = make_iabc(68, 0, 1, 0, 0);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.mnemonic, "return");
        assert!(insn.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_decode_return0() {
        let word = make_iabc(69, 0, 0, 0, 0);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.mnemonic, "return0");
        assert!(insn.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_decode_return1() {
        let word = make_iabc(70, 2, 0, 0, 0);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.mnemonic, "return1");
        assert!(insn.flags.contains(InstrFlags::RET));
    }

    #[test]
    fn test_decode_forloop() {
        // FORLOOP = opcode 71 (iAsBx)
        let word = make_iasbx(71, 0, -5);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.mnemonic, "forloop");
        assert!(insn.flags.contains(InstrFlags::BRANCH));
    }

    #[test]
    fn test_decode_forprep() {
        let word = make_iasbx(72, 0, 3);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.mnemonic, "forprep");
    }

    #[test]
    fn test_decode_loadk() {
        // LOADK = opcode 3 (iABx)
        let word = make_iabx(3, 2, 7);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.mnemonic, "loadk");
        assert_eq!(insn.a, 2);
    }

    #[test]
    fn test_decode_extraarg() {
        // EXTRAARG = opcode 80 (iAx)
        let word = crate::make_iax(80, 0x1234);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.mnemonic, "extraarg");
    }

    #[test]
    fn test_decode_eq_comparison() {
        // EQ = opcode 55 (TestJump)
        let word = make_iabc(55, 0, 1, 0, 0);
        let insn = decode_lua54_insn(word, Address::new(0)).unwrap();
        assert_eq!(insn.mnemonic, "eq");
        assert!(insn.flags.contains(InstrFlags::BRANCH));
        assert!(insn.flags.contains(InstrFlags::CONDITIONAL));
    }

    // ── b_mode ────────────────────────────────────────────────────────────────

    #[test]
    fn test_b_mode_register() {
        let word = make_iabc(0, 0, 0, 0, 0);
        assert_eq!(b_mode(word), OperandMode::Register);
    }

    #[test]
    fn test_b_mode_constant() {
        // k bit = 1
        let word = make_iabc(0, 0, 0, 0, 1);
        assert_eq!(b_mode(word), OperandMode::Constant);
    }

    // ── Lua54Disassembler ─────────────────────────────────────────────────────

    #[test]
    fn test_disassembler_sniff_valid() {
        let mut data = vec![0u8; 10];
        data[0..4].copy_from_slice(&LUA_MAGIC);
        data[4] = LUA54_VERSION;
        assert!(Lua54Disassembler::sniff(&data));
    }

    #[test]
    fn test_disassembler_sniff_invalid() {
        assert!(!Lua54Disassembler::sniff(&[0u8; 10]));
    }

    #[test]
    fn test_disassembler_disassemble_words() {
        let dis = Lua54Disassembler::new();
        let words = vec![make_iabc(0, 1, 2, 3, 0), make_iabc(68, 0, 1, 0, 0)];
        let result = dis.disassemble_words(&words, 0);
        assert_eq!(result.len(), 2);
        assert!(result[0].is_ok());
        assert!(result[1].is_ok());
    }

    #[test]
    fn test_disassembler_disassemble_bytes() {
        let dis = Lua54Disassembler::new();
        let word: u32 = make_iabc(0, 0, 1, 2, 0);
        let bytes = word.to_le_bytes();
        let result = dis.disassemble_bytes(&bytes, 0x100);
        assert_eq!(result.len(), 1);
        assert!(result[0].is_ok());
    }

    #[test]
    fn test_disassembler_listing() {
        let dis = Lua54Disassembler::new();
        let words = vec![make_iabc(0, 1, 2, 3, 0)];
        let listing = dis.listing(&words);
        assert!(listing.contains("move"));
    }

    #[test]
    fn test_disassembler_opcode_histogram() {
        let dis = Lua54Disassembler::new();
        let words = vec![
            make_iabc(0, 0, 1, 2, 0),  // MOVE
            make_iabc(0, 1, 2, 3, 0),  // MOVE
            make_iabc(66, 0, 2, 1, 0), // CALL
        ];
        let hist = dis.opcode_histogram(&words);
        assert_eq!(*hist.get(&0).unwrap(), 2);
        assert_eq!(*hist.get(&66).unwrap(), 1);
        // Sanity-check opcode names from the canonical table.
        assert_eq!(LUA54_OPCODES[0], "MOVE");
        assert_eq!(LUA54_OPCODES[66], "CALL");
    }

    // ── Lua54Proto ────────────────────────────────────────────────────────────

    #[test]
    fn test_proto_jump_targets() {
        let proto = Lua54Proto {
            source_name: "test".to_string(),
            line_defined: 0,
            last_line_defined: 10,
            num_params: 0,
            is_vararg: false,
            max_stack: 4,
            instructions: vec![
                make_isj(54, 3), // JMP +3 → target = 1 + 3 = 4
            ],
            constants: vec![],
            upvalue_count: 0,
            protos: vec![],
        };
        let targets = proto.jump_targets();
        assert_eq!(targets, vec![4]);
    }

    #[test]
    fn test_proto_count_opcode() {
        let proto = Lua54Proto {
            source_name: String::new(),
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            is_vararg: false,
            max_stack: 2,
            instructions: vec![
                make_iabc(0, 0, 1, 2, 0),
                make_iabc(0, 1, 2, 3, 0),
                make_iabc(68, 0, 1, 0, 0),
            ],
            constants: vec![],
            upvalue_count: 0,
            protos: vec![],
        };
        assert_eq!(proto.count_opcode(0), 2);
        assert_eq!(proto.count_opcode(68), 1);
        assert_eq!(proto.count_opcode(99), 0);
    }

    #[test]
    fn test_proto_display() {
        let proto = Lua54Proto {
            source_name: "myscript.lua".to_string(),
            line_defined: 1,
            last_line_defined: 20,
            num_params: 2,
            is_vararg: false,
            max_stack: 8,
            instructions: vec![make_iabc(0, 0, 1, 2, 0); 5],
            constants: vec![Lua54Const::Integer(42)],
            upvalue_count: 1,
            protos: vec![],
        };
        let s = proto.to_string();
        assert!(s.contains("myscript"));
        assert!(s.contains('5'));
    }

    // ── Lua54Const ────────────────────────────────────────────────────────────

    #[test]
    fn test_const_display_integer() {
        assert_eq!(Lua54Const::Integer(99).to_string(), "99");
    }

    #[test]
    fn test_const_display_string() {
        assert_eq!(
            Lua54Const::ShortString("hello".to_string()).to_string(),
            "\"hello\""
        );
    }

    #[test]
    fn test_const_into_lua_const() {
        let c: LuaConst = Lua54Const::Integer(7).into();
        assert_eq!(c.as_int(), Some(7));
    }
}
