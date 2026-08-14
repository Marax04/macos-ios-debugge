//! Full `LuaJIT` 2.x bytecode file parser.
//!
//! Parses the binary format from disk or memory:
//! * Header: magic `[0x1B, 'L', 'J']`, version byte, flags ULEB128, optional debug name.
//! * Proto stream: ULEB128 size, then proto body; size=0 terminates the stream.
//! * Proto body: flags, framesize, `num_upvalues`, `num_params`, fixedparams,
//!   vararg; counts for KGC/KN/BC/debug; bytecode words; upvalue descriptors;
//!   KGC objects; KN numeric constants; debug block.
//!
//! The types here are independent from those in `lib.rs`; they carry extra
//! parse metadata and richer error reporting.

use std::collections::HashMap;
use std::fmt;

// â”€â”€â”€ LjParseError â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Errors produced by the `LuaJIT` parser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LjParseError {
    TruncatedData { offset: usize, needed: usize },
    InvalidMagic { got: [u8; 3] },
    UnsupportedVersion(u8),
    Leb128Overflow { offset: usize },
    InvalidProto { proto_idx: usize, reason: String },
    InvalidConstType { ktype: u64, offset: usize },
}

impl fmt::Display for LjParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedData { offset, needed } => {
                write!(f, "truncated data at offset {offset:#x}: needed {needed} more bytes")
            }
            Self::InvalidMagic { got } => {
                write!(f, "invalid magic: {:02x} {:02x} {:02x}", got[0], got[1], got[2])
            }
            Self::UnsupportedVersion(v) => write!(f, "unsupported LuaJIT version {v:#04x}"),
            Self::Leb128Overflow { offset } => {
                write!(f, "LEB128 overflow at offset {offset:#x}")
            }
            Self::InvalidProto { proto_idx, reason } => {
                write!(f, "invalid proto #{proto_idx}: {reason}")
            }
            Self::InvalidConstType { ktype, offset } => {
                write!(f, "invalid KGC type {ktype} at offset {offset:#x}")
            }
        }
    }
}

// â”€â”€â”€ Magic & version â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

pub const LJ_MAGIC: [u8; 3] = [0x1B, b'L', b'J'];
pub const LJ_VERSION_20: u8 = 1;
pub const LJ_VERSION_21: u8 = 2;

// Flag bits in the file header flags ULEB128.
pub const LJ_FLAG_BE: u8 = 0x01;
pub const LJ_FLAG_STRIP: u8 = 0x02;
pub const LJ_FLAG_FFI: u8 = 0x04;
pub const LJ_FLAG_FR2: u8 = 0x08;

// Proto flag bits.
pub const LJ_PROTO_CHILD: u8 = 0x01;
pub const LJ_PROTO_VARARG: u8 = 0x02;
pub const LJ_PROTO_FFI: u8 = 0x04;
pub const LJ_PROTO_NOJIT: u8 = 0x08;
pub const LJ_PROTO_ILOOP: u8 = 0x10;

// â”€â”€â”€ LjHeader â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Parsed `LuaJIT` file header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LjHeader {
    /// Raw version byte (1 = `LuaJIT` 2.0, 2 = 2.1).
    pub version: u8,
    /// Raw flags byte (see `LJ_FLAG_*` constants).
    pub flags: u8,
    /// Optional source file name (present unless STRIP flag set).
    pub debug_name: Option<String>,
    /// Byte offset of the first proto in the file.
    pub protos_start: usize,
}

impl LjHeader {
    /// Is this a big-endian file?
    #[must_use]
    pub const fn is_be(&self) -> bool {
        (self.flags & LJ_FLAG_BE) != 0
    }

    /// Is the debug info stripped?
    #[must_use]
    pub const fn is_stripped(&self) -> bool {
        (self.flags & LJ_FLAG_STRIP) != 0
    }

    /// Does this file use the FFI extension?
    #[must_use]
    pub const fn uses_ffi(&self) -> bool {
        (self.flags & LJ_FLAG_FFI) != 0
    }

    /// Does this file use the FR2 register layout (`LuaJIT` 2.1)?
    #[must_use]
    pub const fn uses_fr2(&self) -> bool {
        (self.flags & LJ_FLAG_FR2) != 0
    }
}

impl fmt::Display for LjHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LjHeader {{ version={}, flags={:#04x}, stripped={}, ffi={}, fr2={}, src={:?} }}",
            self.version,
            self.flags,
            self.is_stripped(),
            self.uses_ffi(),
            self.uses_fr2(),
            self.debug_name,
        )
    }
}

// â”€â”€â”€ LjInstruction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A single 32-bit `LuaJIT` bytecode instruction (opaque wrapper).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LjInstruction {
    pub word: u32,
}

impl LjInstruction {
    #[must_use]
    pub const fn new(word: u32) -> Self {
        Self { word }
    }

    #[must_use]
    pub const fn opcode(self) -> u8 {
        (self.word & 0xFF) as u8
    }

    #[must_use]
    pub const fn a(self) -> u8 {
        ((self.word >> 8) & 0xFF) as u8
    }

    #[must_use]
    pub const fn c(self) -> u8 {
        ((self.word >> 16) & 0xFF) as u8
    }

    #[must_use]
    pub const fn b(self) -> u8 {
        ((self.word >> 24) & 0xFF) as u8
    }

    #[must_use]
    pub const fn d(self) -> u16 {
        ((self.word >> 16) & 0xFFFF) as u16
    }

    /// Signed jump offset: D - 0x8000.
    #[must_use]
    pub const fn jump_offset(self) -> i16 {
        (self.d() as i16).wrapping_sub(0x8000_u16 as i16)
    }

    /// Whether this instruction is a call.
    #[must_use]
    pub const fn is_call(self) -> bool {
        matches!(self.opcode(), 0x41..=0x44)
    }

    /// Whether this instruction is a return.
    #[must_use]
    pub const fn is_return(self) -> bool {
        matches!(self.opcode(), 0x49..=0x4C)
    }

    /// Whether this instruction is a branch or loop.
    #[must_use]
    pub const fn is_branch(self) -> bool {
        matches!(self.opcode(), 0x4D..=0x60)
    }
}

impl fmt::Display for LjInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LjInstruction {{ op={:#04x} A={} B={} C={} D={} }}",
            self.opcode(),
            self.a(),
            self.b(),
            self.c(),
            self.d()
        )
    }
}

// â”€â”€â”€ LjConst â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A constant from a proto's KGC or KN table.
#[derive(Debug, Clone, PartialEq)]
pub enum LjConst {
    /// Reference to a child prototype (index into the proto list).
    ChildProto(usize),
    /// Table template placeholder.
    Tab,
    /// 64-bit signed integer cdata.
    I64(i64),
    /// 64-bit unsigned integer cdata.
    U64(u64),
    /// Complex number cdata.
    Complex(f64, f64),
    /// String constant.
    Str(String),
    /// 32-bit integer from KN table.
    Int(i32),
    /// 64-bit float from KN table.
    Float(f64),
    /// Unknown KGC type.
    Unknown(u64),
}

impl LjConst {
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        if let Self::Str(s) = self {
            Some(s.as_str())
        } else {
            None
        }
    }

    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::ChildProto(_) => "child_proto",
            Self::Tab => "tab",
            Self::I64(_) => "i64",
            Self::U64(_) => "u64",
            Self::Complex(_, _) => "complex",
            Self::Str(_) => "str",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::Unknown(_) => "unknown",
        }
    }
}

impl fmt::Display for LjConst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChildProto(i) => write!(f, "proto[{i}]"),
            Self::Tab => write!(f, "<table>"),
            Self::I64(n) => write!(f, "{n}i64"),
            Self::U64(n) => write!(f, "{n}u64"),
            Self::Complex(r, im) => write!(f, "{r}+{im}i"),
            Self::Str(s) => write!(f, "\"{s}\""),
            Self::Int(n) => write!(f, "{n}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Unknown(t) => write!(f, "<unk-kgc-{t}>"),
        }
    }
}

// â”€â”€â”€ LjUpvalueDesc â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// An upvalue descriptor: 16-bit word encoding locality and slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LjUpvalueDesc {
    pub raw: u16,
    pub slot: u8,
    pub is_local: bool,
    pub is_immutable: bool,
    pub name: Option<String>,
}

impl LjUpvalueDesc {
    #[must_use]
    pub const fn from_raw(raw: u16) -> Self {
        Self {
            raw,
            slot: (raw & 0xFF) as u8,
            is_local: (raw >> 15) != 0,
            is_immutable: ((raw >> 8) & 1) != 0,
            name: None,
        }
    }
}

impl fmt::Display for LjUpvalueDesc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "upval[{}] local={} immutable={} name={:?}",
            self.slot, self.is_local, self.is_immutable, self.name
        )
    }
}

// â”€â”€â”€ LjLocalVar â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A local variable debug record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LjLocalVar {
    pub name: String,
    pub start_pc: u32,
    pub end_pc: u32,
}

impl LjLocalVar {
    #[must_use]
    pub const fn live_at(&self, pc: u32) -> bool {
        pc >= self.start_pc && pc < self.end_pc
    }
}

// â”€â”€â”€ LjProto â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// A fully parsed `LuaJIT` prototype (function).
#[derive(Debug, Clone)]
pub struct LjProto {
    /// Index in the proto list (0 = outermost / root).
    pub index: usize,
    /// Raw flags byte.
    pub flags: u8,
    /// Number of fixed parameters.
    pub num_params: u8,
    /// Total frame size (number of registers).
    pub frame_size: u8,
    /// Number of upvalue descriptors.
    pub num_upvalues: u8,
    /// Whether this proto accepts variable arguments.
    pub is_vararg: bool,
    /// Decoded instructions.
    pub instructions: Vec<LjInstruction>,
    /// Upvalue descriptor array.
    pub upvalues: Vec<LjUpvalueDesc>,
    /// GC constants (KGC table).
    pub kgc: Vec<LjConst>,
    /// Numeric constants (KN table).
    pub kn: Vec<LjConst>,
    /// Per-instruction source line numbers (empty if stripped).
    pub line_info: Vec<u32>,
    /// Local variable records (empty if stripped).
    pub local_vars: Vec<LjLocalVar>,
    /// Upvalue name strings (empty if stripped).
    pub upvalue_names: Vec<String>,
    /// Source file name (from debug block).
    pub source_name: Option<String>,
    /// First source line covered by this proto.
    pub first_line: u32,
    /// Number of source lines covered.
    pub num_lines: u32,
    /// Size of the proto body in the file.
    pub body_size: usize,
    /// Child proto indices (protos directly enclosed by this one).
    pub child_indices: Vec<usize>,
}

impl LjProto {
    /// Count instructions of a specific opcode.
    #[must_use]
    pub fn opcode_count(&self, op: u8) -> usize {
        self.instructions.iter().filter(|i| i.opcode() == op).count()
    }

    /// All string constants from the KGC table.
    #[must_use]
    pub fn strings(&self) -> Vec<&str> {
        self.kgc.iter().filter_map(|c| c.as_str()).collect()
    }

    /// Return the source line for a given PC (0-indexed).
    #[must_use]
    pub fn source_line(&self, pc: usize) -> Option<u32> {
        self.line_info.get(pc).copied()
    }

    /// Return all local variables live at `pc`.
    #[must_use]
    pub fn locals_at(&self, pc: u32) -> Vec<&LjLocalVar> {
        self.local_vars.iter().filter(|v| v.live_at(pc)).collect()
    }

    /// Compute basic opcode-frequency statistics.
    #[must_use]
    pub fn opcode_freq(&self) -> HashMap<u8, usize> {
        let mut freq = HashMap::new();
        for instr in &self.instructions {
            *freq.entry(instr.opcode()).or_insert(0) += 1;
        }
        freq
    }

    #[must_use]
    pub fn call_count(&self) -> usize {
        self.instructions.iter().filter(|i| i.is_call()).count()
    }

    #[must_use]
    pub fn return_count(&self) -> usize {
        self.instructions.iter().filter(|i| i.is_return()).count()
    }

    #[must_use]
    pub fn branch_count(&self) -> usize {
        self.instructions.iter().filter(|i| i.is_branch()).count()
    }
}

impl fmt::Display for LjProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LjProto {{ idx={}, params={}, frame={}, upvals={}, instrs={}, vararg={} }}",
            self.index,
            self.num_params,
            self.frame_size,
            self.num_upvalues,
            self.instructions.len(),
            self.is_vararg
        )
    }
}

// â”€â”€â”€ LjParser â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Full `LuaJIT` 2.x bytecode file parser.
///
/// Call [`LjParser::parse`] to parse an entire `.ljbc` file.
#[derive(Debug, Default)]
pub struct LjParser;

impl LjParser {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    // â”€â”€ Low-level helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    const fn check(data: &[u8], offset: usize, n: usize) -> Result<(), LjParseError> {
        if offset + n > data.len() {
            Err(LjParseError::TruncatedData {
                offset,
                needed: n,
            })
        } else {
            Ok(())
        }
    }

    /// Read a single byte at `offset`, returning `(byte, new_offset)`.
    pub fn read_u8(data: &[u8], offset: usize) -> Result<(u8, usize), LjParseError> {
        Self::check(data, offset, 1)?;
        Ok((data[offset], offset + 1))
    }

    /// Read a little-endian `u32` at `offset`, returning `(value, new_offset)`.
    pub fn read_u32_le(data: &[u8], offset: usize) -> Result<(u32, usize), LjParseError> {
        Self::check(data, offset, 4)?;
        let word = u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
        Ok((word, offset + 4))
    }

    /// Read a big-endian `u32` at `offset`, returning `(value, new_offset)`.
    pub fn read_u32_be(data: &[u8], offset: usize) -> Result<(u32, usize), LjParseError> {
        Self::check(data, offset, 4)?;
        let word = u32::from_be_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]]);
        Ok((word, offset + 4))
    }

    /// Read a `u32` at `offset` using `endian` ("le" or "be"), returning
    /// `(value, new_offset)`. Convenience helper around [`Self::read_u32_le`]
    /// and [`Self::read_u32_be`].
    pub fn read_u32_endian(
        data: &[u8],
        offset: usize,
        big_endian: bool,
    ) -> Result<(u32, usize), LjParseError> {
        if big_endian {
            Self::read_u32_be(data, offset)
        } else {
            Self::read_u32_le(data, offset)
        }
    }

    fn read_uleb128(data: &[u8], mut pos: usize) -> Result<(u64, usize), LjParseError> {
        let start = pos;
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            if pos >= data.len() {
                return Err(LjParseError::TruncatedData { offset: start, needed: 1 });
            }
            let byte = data[pos];
            pos += 1;
            result |= u64::from(byte & 0x7F) << shift;
            if (byte & 0x80) == 0 {
                break;
            }
            shift += 7;
            if shift > 63 {
                return Err(LjParseError::Leb128Overflow { offset: start });
            }
        }
        Ok((result, pos))
    }

    fn read_bytes(data: &[u8], offset: usize, n: usize) -> Result<(&[u8], usize), LjParseError> {
        Self::check(data, offset, n)?;
        Ok((&data[offset..offset + n], offset + n))
    }

    fn read_string(data: &[u8], offset: usize, len: usize) -> Result<(String, usize), LjParseError> {
        let (bytes, new_pos) = Self::read_bytes(data, offset, len)?;
        Ok((String::from_utf8_lossy(bytes).into_owned(), new_pos))
    }

    // â”€â”€ Header parsing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn parse_header(data: &[u8]) -> Result<LjHeader, LjParseError> {
        Self::check(data, 0, 4)?;
        if data[0] != LJ_MAGIC[0] || data[1] != LJ_MAGIC[1] || data[2] != LJ_MAGIC[2] {
            return Err(LjParseError::InvalidMagic {
                got: [data[0], data[1], data[2]],
            });
        }
        let version = data[3];
        if version != LJ_VERSION_20 && version != LJ_VERSION_21 {
            return Err(LjParseError::UnsupportedVersion(version));
        }
        let mut pos = 4usize;
        let (flags_raw, new_pos) = Self::read_uleb128(data, pos)?;
        pos = new_pos;
        let flags = (flags_raw & 0xFF) as u8;

        let debug_name = if (flags & LJ_FLAG_STRIP) == 0 {
            let (name_len, new_pos2) = Self::read_uleb128(data, pos)?;
            pos = new_pos2;
            if name_len > 0 {
                let (s, new_pos3) = Self::read_string(data, pos, name_len as usize)?;
                pos = new_pos3;
                if s.is_empty() { None } else { Some(s) }
            } else {
                None
            }
        } else {
            None
        };

        Ok(LjHeader {
            version,
            flags,
            debug_name,
            protos_start: pos,
        })
    }

    // â”€â”€ Proto parsing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn parse_proto(
        data: &[u8],
        offset: usize,
        proto_idx: usize,
        is_be: bool,
    ) -> Result<Option<(LjProto, usize)>, LjParseError> {
        // Size ULEB128 â€” 0 means end of stream.
        let (proto_size, pos) = Self::read_uleb128(data, offset)?;
        if proto_size == 0 {
            return Ok(None);
        }
        // proto_size is an attacker-controlled u64; cap before casting to prevent
        // truncation on 32-bit targets, then use saturating_add to avoid overflow.
        let proto_size_usize = usize::try_from(proto_size).unwrap_or(usize::MAX);
        let proto_end = pos.saturating_add(proto_size_usize);
        if proto_end > data.len() {
            return Err(LjParseError::TruncatedData {
                offset: pos,
                needed: proto_size_usize,
            });
        }
        let pd = &data[pos..proto_end];
        let mut p = 0usize;

        if pd.len() < 4 {
            return Err(LjParseError::InvalidProto {
                proto_idx,
                reason: "body too short for fixed header".into(),
            });
        }

        let flags = pd[p]; p += 1;
        let num_params = pd[p]; p += 1;
        let frame_size = pd[p]; p += 1;
        let num_upvalues = pd[p]; p += 1;
        let is_vararg = (flags & LJ_PROTO_VARARG) != 0;

        let (num_kgc, np) = Self::read_uleb128(pd, p)?; p = np;
        let (num_kn, np) = Self::read_uleb128(pd, p)?; p = np;
        let (bc_count, np) = Self::read_uleb128(pd, p)?; p = np;
        let (dbg_info_size, np) = Self::read_uleb128(pd, p)?; p = np;

        let (first_line, np) = if dbg_info_size > 0 {
            Self::read_uleb128(pd, p)?
        } else {
            (0, p)
        };
        p = np;
        let (num_lines, np) = if dbg_info_size > 0 {
            Self::read_uleb128(pd, p)?
        } else {
            (0, p)
        };
        p = np;

        // Bytecode â€” use saturating arithmetic to avoid overflow when bc_count is large.
        let bc_count_usize = usize::try_from(bc_count).unwrap_or(usize::MAX);
        let bc_bytes = bc_count_usize.saturating_mul(4);
        if p + bc_bytes > pd.len() {
            return Err(LjParseError::InvalidProto {
                proto_idx,
                reason: format!("bytecode section out of bounds (need {bc_bytes})"),
            });
        }
        let mut instructions = Vec::with_capacity(bc_count_usize);
        for i in 0..bc_count_usize {
            let off = p + i * 4;
            let word = if is_be {
                u32::from_be_bytes([pd[off], pd[off+1], pd[off+2], pd[off+3]])
            } else {
                u32::from_le_bytes([pd[off], pd[off+1], pd[off+2], pd[off+3]])
            };
            instructions.push(LjInstruction::new(word));
        }
        p += bc_bytes;

        // Upvalue descriptors (2 bytes each).
        let uv_bytes = (num_upvalues as usize) * 2;
        if p + uv_bytes > pd.len() {
            return Err(LjParseError::InvalidProto {
                proto_idx,
                reason: "upvalue descriptors out of bounds".into(),
            });
        }
        let mut upvalues: Vec<LjUpvalueDesc> = Vec::with_capacity(num_upvalues as usize);
        for i in 0..num_upvalues as usize {
            let off = p + i * 2;
            let raw = u16::from_le_bytes([pd[off], pd[off + 1]]);
            upvalues.push(LjUpvalueDesc::from_raw(raw));
        }
        p += uv_bytes;

        // KGC constants. The count is an attacker-controlled ULEB128 and the
        // entries are variable-length, so there is no total-size check to lean
        // on; each entry needs at least a one-byte type tag, which bounds the
        // real count by the remaining input.
        let mut kgc: Vec<LjConst> =
            Vec::with_capacity((num_kgc as usize).min(pd.len().saturating_sub(p)));
        let mut child_indices: Vec<usize> = Vec::new();
        for _ in 0..num_kgc {
            let (ktype, np) = Self::read_uleb128(pd, p)?;
            p = np;
            match ktype {
                0 => {
                    // Child proto â€” placeholder (resolved by caller).
                    child_indices.push(0);
                    kgc.push(LjConst::ChildProto(child_indices.len() - 1));
                }
                1 => kgc.push(LjConst::Tab),
                2 => {
                    // i64: lo u32 + hi u32
                    if p + 8 > pd.len() { break; }
                    let lo = u32::from_le_bytes([pd[p], pd[p+1], pd[p+2], pd[p+3]]);
                    let hi = u32::from_le_bytes([pd[p+4], pd[p+5], pd[p+6], pd[p+7]]);
                    p += 8;
                    kgc.push(LjConst::I64((i64::from(hi) << 32) | i64::from(lo)));
                }
                3 => {
                    // u64
                    if p + 8 > pd.len() { break; }
                    let lo = u32::from_le_bytes([pd[p], pd[p+1], pd[p+2], pd[p+3]]);
                    let hi = u32::from_le_bytes([pd[p+4], pd[p+5], pd[p+6], pd[p+7]]);
                    p += 8;
                    kgc.push(LjConst::U64((u64::from(hi) << 32) | u64::from(lo)));
                }
                4 => {
                    // complex: two f64
                    if p + 16 > pd.len() { break; }
                    let r_bits = u64::from_le_bytes([pd[p],pd[p+1],pd[p+2],pd[p+3],pd[p+4],pd[p+5],pd[p+6],pd[p+7]]);
                    let i_bits = u64::from_le_bytes([pd[p+8],pd[p+9],pd[p+10],pd[p+11],pd[p+12],pd[p+13],pd[p+14],pd[p+15]]);
                    p += 16;
                    kgc.push(LjConst::Complex(f64::from_bits(r_bits), f64::from_bits(i_bits)));
                }
                n => {
                    // String of length (n - 5).
                    let slen = (n as usize).saturating_sub(5);
                    if p + slen > pd.len() { break; }
                    let s = String::from_utf8_lossy(&pd[p..p + slen]).into_owned();
                    p += slen;
                    kgc.push(LjConst::Str(s));
                }
            }
        }

        // KN numeric constants. Same reasoning as KGC above.
        let mut kn: Vec<LjConst> =
            Vec::with_capacity((num_kn as usize).min(pd.len().saturating_sub(p)));
        for _ in 0..num_kn {
            if p >= pd.len() { break; }
            let (kval, np) = Self::read_uleb128(pd, p)?;
            p = np;
            if (kval & 1) != 0 {
                kn.push(LjConst::Int((kval >> 1) as i32));
            } else {
                if p + 4 > pd.len() { break; }
                let lo = u32::from_le_bytes([pd[p], pd[p+1], pd[p+2], pd[p+3]]);
                p += 4;
                // Mask kval to 32 bits: it encodes only the high word of the double.
                let bits: u64 = ((kval & 0xFFFF_FFFF) << 32) | u64::from(lo);
                kn.push(LjConst::Float(f64::from_bits(bits)));
            }
        }

        // Debug info block.
        let mut line_info = vec![0u32; bc_count_usize];
        let mut local_vars: Vec<LjLocalVar> = Vec::new();
        let mut upvalue_names: Vec<String> = Vec::new();
        let mut source_name: Option<String> = None;

        if dbg_info_size > 0 && p < pd.len() {
            let bytes_per_line = if num_lines < 256 { 1usize }
                else if num_lines < 65536 { 2 }
                else { 4 };

            for i in 0..bc_count_usize {
                if p + bytes_per_line > pd.len() { break; }
                let line = match bytes_per_line {
                    1 => { let v = u32::from(pd[p]); p += 1; v }
                    2 => { let v = u32::from(u16::from_le_bytes([pd[p], pd[p+1]])); p += 2; v }
                    4 => { let v = u32::from_le_bytes([pd[p],pd[p+1],pd[p+2],pd[p+3]]); p += 4; v }
                    _ => 0,
                };
                if i < line_info.len() {
                    line_info[i] = first_line as u32 + line;
                }
            }

            // Local variables.
            loop {
                if p >= pd.len() { break; }
                let (name_len, np) = Self::read_uleb128(pd, p).unwrap_or((0, p));
                if name_len == 0 { p = np; break; }
                p = np;
                let slen = (name_len as usize).saturating_sub(1);
                if slen == 0 || p + slen > pd.len() { break; }
                let name = String::from_utf8_lossy(&pd[p..p + slen]).into_owned();
                p += slen;
                let (start, np) = Self::read_uleb128(pd, p).unwrap_or((0, p)); p = np;
                let (end, np) = Self::read_uleb128(pd, p).unwrap_or((0, p)); p = np;
                local_vars.push(LjLocalVar { name, start_pc: start as u32, end_pc: end as u32 });
            }

            // Upvalue names.
            for _ in 0..num_upvalues {
                if p >= pd.len() { break; }
                let (nlen, np) = Self::read_uleb128(pd, p).unwrap_or((0, p)); p = np;
                let slen = nlen as usize;
                if slen == 0 || p + slen > pd.len() {
                    upvalue_names.push(String::new());
                    continue;
                }
                let name = String::from_utf8_lossy(&pd[p..p + slen]).into_owned();
                p += slen;
                upvalue_names.push(name);
            }

            // Source name.
            if p < pd.len() {
                let (slen, np) = Self::read_uleb128(pd, p).unwrap_or((0, p)); p = np;
                let slen = slen as usize;
                if slen > 0 && p + slen <= pd.len() {
                    let s = String::from_utf8_lossy(&pd[p..p + slen]).into_owned();
                    p += slen;
                    if !s.is_empty() { source_name = Some(s); }
                }
            }
            let _ = p;
        }

        // Patch upvalue names into descriptors.
        for (uv, name) in upvalues.iter_mut().zip(upvalue_names.iter()) {
            if !name.is_empty() {
                uv.name = Some(name.clone());
            }
        }

        let proto = LjProto {
            index: proto_idx,
            flags,
            num_params,
            frame_size,
            num_upvalues,
            is_vararg,
            instructions,
            upvalues,
            kgc,
            kn,
            line_info,
            local_vars,
            upvalue_names,
            source_name,
            first_line: first_line as u32,
            num_lines: num_lines as u32,
            body_size: proto_size as usize,
            child_indices,
        };
        Ok(Some((proto, proto_end)))
    }

    // â”€â”€ Public API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Parse a complete `LuaJIT` bytecode file.
    ///
    /// Returns `(header, protos)` where `protos[0]` is the outermost function.
    pub fn parse(data: &[u8]) -> Result<(LjHeader, Vec<LjProto>), LjParseError> {
        let header = Self::parse_header(data)?;
        let is_be = header.is_be();
        let mut pos = header.protos_start;
        let mut protos: Vec<LjProto> = Vec::new();

        loop {
            match Self::parse_proto(data, pos, protos.len(), is_be)? {
                None => break,
                Some((mut proto, new_pos)) => {
                    proto.index = protos.len();
                    pos = new_pos;
                    protos.push(proto);
                }
            }
        }

        Ok((header, protos))
    }

    /// Quick check: does `data` start with the `LuaJIT` magic?
    #[must_use]
    pub fn is_luajit(data: &[u8]) -> bool {
        data.len() >= 3
            && data[0] == LJ_MAGIC[0]
            && data[1] == LJ_MAGIC[1]
            && data[2] == LJ_MAGIC[2]
    }

    /// Parse only the header without processing protos.
    pub fn parse_header_only(data: &[u8]) -> Result<LjHeader, LjParseError> {
        Self::parse_header(data)
    }

    /// Count the number of protos without full parsing (just reads size ULEB128).
    #[must_use]
    pub fn count_protos(data: &[u8]) -> usize {
        let header = match Self::parse_header(data) {
            Ok(h) => h,
            Err(_) => return 0,
        };
        let mut pos = header.protos_start;
        let mut count = 0usize;
        loop {
            match Self::read_uleb128(data, pos) {
                Ok((0, _)) => break,
                Ok((size, new_pos)) => {
                    count += 1;
                    let size_usize = usize::try_from(size).unwrap_or(usize::MAX);
                    pos = new_pos.saturating_add(size_usize);
                    if pos >= data.len() { break; }
                }
                Err(_) => break,
            }
        }
        count
    }
}

// â”€â”€â”€ ParsedBytecode â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// The complete result of parsing a `LuaJIT` bytecode file.
#[derive(Debug, Clone)]
pub struct ParsedBytecode {
    pub header: LjHeader,
    pub protos: Vec<LjProto>,
}

impl ParsedBytecode {
    /// Parse from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, LjParseError> {
        let (header, protos) = LjParser::parse(data)?;
        Ok(Self { header, protos })
    }

    /// Return all string constants across all protos (deduplicated).
    #[must_use]
    pub fn all_strings(&self) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        for proto in &self.protos {
            for s in proto.strings() {
                if seen.insert(s) {
                    result.push(s);
                }
            }
        }
        result
    }

    /// Return the total instruction count.
    #[must_use]
    pub fn total_instructions(&self) -> usize {
        self.protos.iter().map(|p| p.instructions.len()).sum()
    }

    /// Find a proto by source name.
    #[must_use]
    pub fn proto_by_source(&self, name: &str) -> Option<&LjProto> {
        self.protos.iter().find(|p| {
            p.source_name.as_deref() == Some(name)
        })
    }
}

impl fmt::Display for ParsedBytecode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ParsedBytecode {{ version={}, protos={}, total_instrs={} }}",
            self.header.version,
            self.protos.len(),
            self.total_instructions()
        )
    }
}
