//! `rustre-loader-luajit`
//!
//! Full `LuaJIT` 2.x bytecode loader implementing proto parsing, instruction
//! decoding, upvalue resolution, constant table parsing, and debug info
//! extraction for both `LuaJIT` 2.0 and 2.1.

pub mod bytecode_format;
pub mod constant_tables;
pub mod instruction_decoder;
pub mod liftable_functions;
pub mod luajit_decompiler;
pub mod luajit_opcode_table;
pub mod luajit_parser;
pub mod luajit_profiler_data;
pub mod luajit_vm_analysis;
pub mod upvalue_analysis;
pub mod luajit_bytecode_analyzer;
pub mod luajit_string_extractor;
pub mod luajit_cfg_builder;

pub use luajit_vm_analysis::{
    IrConst, IrInstruction, IrOp, IrSnapshot, JitOptimization, LjError, LuaJitVmAnalysis,
    SnapshotEntry, TraceIr,
};

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;

use bitflags::bitflags;
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

/// Errors produced by the `LuaJIT` loader.
#[derive(Debug, thiserror::Error)]
pub enum LjLoaderError {
    #[error("invalid magic")]
    InvalidMagic,
    #[error("unsupported version: {0:#04x}")]
    UnsupportedVersion(u8),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("truncated data")]
    TruncatedData,
    #[error("LEB128 overflow")]
    Leb128Overflow,
}

// ─────────────────────────────────────────────────────────────────────────────
// Magic & detection
// ─────────────────────────────────────────────────────────────────────────────

pub const LJ_MAGIC: [u8; 3] = [0x1B, b'L', b'J'];

#[must_use]
pub fn is_luajit(data: &[u8]) -> bool {
    data.len() >= 3 && data.starts_with(&LJ_MAGIC)
}

// ─────────────────────────────────────────────────────────────────────────────
// LEB128 utilities
// ─────────────────────────────────────────────────────────────────────────────

#[must_use]
pub fn read_uleb128(data: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        if pos >= data.len() {
            return None;
        }
        let byte = data[pos];
        pos += 1;
        result |= u64::from(byte & 0x7F) << shift;
        if (byte & 0x80) == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    Some((result, pos))
}

#[must_use]
pub fn read_sleb128(data: &[u8], mut pos: usize) -> Option<(i64, usize)> {
    let mut result = 0i64;
    let mut shift = 0u32;
    let mut byte;
    loop {
        if pos >= data.len() {
            return None;
        }
        byte = data[pos];
        pos += 1;
        result |= i64::from(byte & 0x7F) << shift;
        shift += 7;
        if (byte & 0x80) == 0 {
            break;
        }
        if shift >= 63 {
            return None;
        }
    }
    if shift < 64 && (byte & 0x40) != 0 {
        result |= -(1i64 << shift);
    }
    Some((result, pos))
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaJIT version
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LjVersion {
    Lj20,
    Lj21,
    Unknown(u8),
}

impl LjVersion {
    #[must_use]
    pub const fn from_byte(b: u8) -> Self {
        match b {
            1 => Self::Lj20,
            2 => Self::Lj21,
            other => Self::Unknown(other),
        }
    }
    #[must_use]
    pub const fn is_known(self) -> bool {
        matches!(self, Self::Lj20 | Self::Lj21)
    }
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        match self {
            Self::Lj20 => 1,
            Self::Lj21 => 2,
            Self::Unknown(b) => b,
        }
    }
}

impl fmt::Display for LjVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lj20 => write!(f, "LuaJIT 2.0"),
            Self::Lj21 => write!(f, "LuaJIT 2.1"),
            Self::Unknown(v) => write!(f, "LuaJIT unknown(0x{v:02x})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Flags
// ─────────────────────────────────────────────────────────────────────────────

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub struct LjFlags: u8 {
        const BE   = 0x01;
        const STRIP = 0x02;
        const FFI  = 0x04;
        const FR2  = 0x08;
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub struct LjProtoFlags: u8 {
        const CHILD  = 0x01;
        const VARARG = 0x02;
        const FFI    = 0x04;
        const NOJIT  = 0x08;
        const ILOOP  = 0x10;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Header
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LjHeader {
    pub version: LjVersion,
    pub flags: LjFlags,
    pub debug_name: Option<String>,
}

impl LjHeader {
    /// Parses a `LuaJIT` bytecode header from the given data slice.
    ///
    /// # Errors
    /// Returns `LjLoaderError::TruncatedData` if the data is too short or a length field overruns
    /// the buffer, and `LjLoaderError::InvalidMagic` if the magic bytes do not match.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), LjLoaderError> {
        if data.len() < 4 {
            return Err(LjLoaderError::TruncatedData);
        }
        if !is_luajit(data) {
            return Err(LjLoaderError::InvalidMagic);
        }
        let version = LjVersion::from_byte(data[3]);
        let mut pos = 4usize;
        let (flags_raw, new_pos) = read_uleb128(data, pos).ok_or(LjLoaderError::TruncatedData)?;
        pos = new_pos;
        let flags = LjFlags::from_bits_truncate(u8::try_from(flags_raw).unwrap_or(u8::MAX));
        let debug_name = if flags.contains(LjFlags::STRIP) {
            None
        } else {
            let (name_len, new_pos2) =
                read_uleb128(data, pos).ok_or(LjLoaderError::TruncatedData)?;
            pos = new_pos2;
            let name_len = usize::try_from(name_len).unwrap_or(usize::MAX);
            if pos + name_len > data.len() {
                return Err(LjLoaderError::TruncatedData);
            }
            let name = String::from_utf8_lossy(&data[pos..pos + name_len]).into_owned();
            pos += name_len;
            if name.is_empty() { None } else { Some(name) }
        };
        Ok((
            Self {
                version,
                flags,
                debug_name,
            },
            pos,
        ))
    }
}

impl fmt::Display for LjHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} flags={:#04x} stripped={} ffi={} fr2={}",
            self.version,
            self.flags.bits(),
            self.flags.contains(LjFlags::STRIP),
            self.flags.contains(LjFlags::FFI),
            self.flags.contains(LjFlags::FR2)
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Opcode table — all 97 LuaJIT 2.x opcodes
// ─────────────────────────────────────────────────────────────────────────────

/// All `LuaJIT` 2.0/2.1 opcodes indexed by opcode byte.
///
/// Format A instructions: bits 0-7=opcode, 8-15=A, 16-23=C, 24-31=B
/// Format D instructions: bits 0-7=opcode, 8-15=A, 16-31=D (signed or unsigned)
pub static LJ_OPCODES: &[&str] = &[
    // 0x00 — Comparison (format AD: A=reg, D=reg)
    "ISLT", // 0x00  A < D
    "ISGE", // 0x01  A >= D
    "ISLE", // 0x02  A <= D
    "ISGT", // 0x03  A > D
    // 0x04 — Equality comparisons (various operand types)
    "ISEQV", // 0x04  A == D (value)
    "ISNEV", // 0x05  A ~= D (value)
    "ISEQS", // 0x06  A == D (string constant index)
    "ISNES", // 0x07  A ~= D (string constant index)
    "ISEQN", // 0x08  A == D (numeric constant index)
    "ISNEN", // 0x09  A ~= D (numeric constant index)
    "ISEQP", // 0x0A  A == D (primitive: nil/false/true)
    "ISNEP", // 0x0B  A ~= D (primitive)
    // 0x0C — Unary test + copy
    "ISTC",   // 0x0C  if A then D = A
    "ISFC",   // 0x0D  if not A then D = A
    "IST",    // 0x0E  if A (no copy)
    "ISF",    // 0x0F  if not A (no copy)
    "ISTYPE", // 0x10  type(A) == D  (LJ2.1+)
    "ISNUM",  // 0x11  isnumber(A)   (LJ2.1+)
    // 0x12 — Copy + unary ops
    "MOV", // 0x12  A = D
    "NOT", // 0x13  A = not D
    "UNM", // 0x14  A = -D
    "LEN", // 0x15  A = #D
    // 0x16 — Binary arithmetic: register op number-constant
    "ADDVN", // 0x16  A = B + C (C=numconst)
    "SUBVN", // 0x17  A = B - C
    "MULVN", // 0x18  A = B * C
    "DIVVN", // 0x19  A = B / C
    "MODVN", // 0x1A  A = B % C
    // 0x1B — Binary arithmetic: number-constant op register
    "ADDNV", // 0x1B  A = C + B (C=numconst)
    "SUBNV", // 0x1C  A = C - B
    "MULNV", // 0x1D  A = C * B
    "DIVNV", // 0x1E  A = C / B
    "MODNV", // 0x1F  A = C % B
    // 0x20 — Binary arithmetic: register op register
    "ADDVV", // 0x20  A = B + C
    "SUBVV", // 0x21  A = B - C
    "MULVV", // 0x22  A = B * C
    "DIVVV", // 0x23  A = B / C
    "MODVV", // 0x24  A = B % C
    "POW",   // 0x25  A = B ^ C
    "CAT",   // 0x26  A = B .. (B+1) .. .. C (concat range)
    // 0x27 — Constant loads
    "KSTR",   // 0x27  A = str_const[D]
    "KCDATA", // 0x28  A = cdata_const[D]
    "KSHORT", // 0x29  A = (int16)D
    "KNUM",   // 0x2A  A = num_const[D]
    "KPRI",   // 0x2B  A = primitive(D)  0=nil 1=false 2=true
    "KNIL",   // 0x2C  A..D = nil
    // 0x2D — Upvalue ops
    "UGET",  // 0x2D  A = upvalue[D]
    "USETV", // 0x2E  upvalue[A] = D
    "USETS", // 0x2F  upvalue[A] = str_const[D]
    "USETN", // 0x30  upvalue[A] = num_const[D]
    "USETP", // 0x31  upvalue[A] = primitive(D)
    "UCLO",  // 0x32  close upvalues up to A, jump to target D
    "FNEW",  // 0x33  A = new closure(proto_const[D])
    // 0x34 — Table ops
    "TNEW",  // 0x34  A = new table(asize=D&0x7FF, hsize=D>>11)
    "TDUP",  // 0x35  A = dup(template_table[D])
    "GGET",  // 0x36  A = _ENV[str_const[D]]
    "GSET",  // 0x37  _ENV[str_const[D]] = A
    "TGETV", // 0x38  A = B[C]  (C=register)
    "TGETS", // 0x39  A = B[str_const[C]]
    "TGETB", // 0x3A  A = B[C]  (C=uint8 immediate)
    "TGETM", // 0x3B  A..A+D-1 = B[M]  (LJ2.1 multi-result)
    "TSETV", // 0x3C  B[C] = A
    "TSETS", // 0x3D  B[str_const[C]] = A
    "TSETB", // 0x3E  B[C] = A  (C=uint8 immediate)
    "TSETM", // 0x3F  B[M..M+A-1] = stack A..  (M=num key base)
    // 0x40
    "TSETR",  // 0x40  (LJ2.1) raw table set
    "CALLM",  // 0x41  A..A+B-2 = A(A+1..A+C+NRESULTS-1)
    "CALL",   // 0x42  A..A+B-2 = A(A+1..A+C)
    "CALLMT", // 0x43  return A(A+1..A+C+NRESULTS-1)  (tail)
    "CALLT",  // 0x44  return A(A+1..A+C)  (tail call)
    "ITERC",  // 0x45  A, A+1, A+2 = A-3(A-2, A-1)  (call iterator)
    "ITERN",  // 0x46  A, A+1, A+2 = A-3(A-2, A-1)  (numeric for iterator)
    "VARG",   // 0x47  A..A+B-2 = vararg (C=nwanted)
    "ISNEXT", // 0x48  check next iterator, jump to D if exhausted
    // 0x49 — Return
    "RETM", // 0x49  return A..A+D+NRESULTS-1
    "RET",  // 0x4A  return A..A+D-2
    "RET0", // 0x4B  return (no values)
    "RET1", // 0x4C  return A
    // 0x4D — For loops
    "FORI",   // 0x4D  for-init numeric: check loop, jump to D if done
    "JFORI",  // 0x4E  JIT for-init
    "FORL",   // 0x4F  for-loop numeric: update + branch back
    "IFORL",  // 0x50  interpreter for-loop
    "JFORL",  // 0x51  JIT for-loop
    "ITERL",  // 0x52  iterator loop: branch if done
    "IITERL", // 0x53  interpreter iterator loop
    "JITERL", // 0x54  JIT iterator loop
    "LOOP",   // 0x55  generic loop hint (no-op semantically)
    "ILOOP",  // 0x56  interpreted loop hint
    "JLOOP",  // 0x57  JIT loop entry
    // 0x58 — Jump + function headers
    "JMP",    // 0x58  PC += D-BIAS
    "FUNCF",  // 0x59  fixed-arg function header (frame=A)
    "IFUNCF", // 0x5A  interpreted fixed-arg function header
    "JFUNCF", // 0x5B  JIT fixed-arg function header
    "FUNCV",  // 0x5C  vararg function header
    "IFUNCV", // 0x5D  interpreted vararg function header
    "JFUNCV", // 0x5E  JIT vararg function header
    "FUNCC",  // 0x5F  C function wrapper header
    "FUNCCW", // 0x60  C function wrapper + vararg header
];

// ─────────────────────────────────────────────────────────────────────────────
// Instruction
// ─────────────────────────────────────────────────────────────────────────────

/// A single 32-bit `LuaJIT` bytecode instruction.
///
/// Encoding (little-endian stored):
/// - Bits  7-0 : opcode
/// - Bits 15-8 : A operand
/// - Bits 23-16: C operand (low byte of D)
/// - Bits 31-24: B operand (high byte of D)
///
/// D = (B<<8)|C gives the 16-bit combined D field.
/// Signed jump offset = D - 0x8000.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LjInstr(pub u32);

impl LjInstr {
    #[must_use]
    pub const fn opcode(self) -> u8 {
        (self.0 & 0xFF) as u8
    }
    #[must_use]
    pub const fn a(self) -> u8 {
        ((self.0 >> 8) & 0xFF) as u8
    }
    #[must_use]
    pub const fn b(self) -> u8 {
        ((self.0 >> 24) & 0xFF) as u8
    }
    #[must_use]
    pub const fn c(self) -> u8 {
        ((self.0 >> 16) & 0xFF) as u8
    }
    #[must_use]
    pub const fn d(self) -> u16 {
        ((self.0 >> 16) & 0xFFFF) as u16
    }
    #[must_use]
    pub const fn jump_offset(self) -> i16 {
        self.d().cast_signed().wrapping_sub(0x8000_u16.cast_signed())
    }
    #[must_use]
    pub fn mnemonic(self) -> &'static str {
        LJ_OPCODES
            .get(self.opcode() as usize)
            .copied()
            .unwrap_or("UNK")
    }
    #[must_use]
    pub const fn is_call(self) -> bool {
        matches!(self.opcode(), 0x41..=0x44)
    }
    #[must_use]
    pub const fn is_return(self) -> bool {
        matches!(self.opcode(), 0x49..=0x4C)
    }
    #[must_use]
    pub const fn is_branch(self) -> bool {
        matches!(self.opcode(), 0x4D..=0x60)
    }
    #[must_use]
    pub const fn is_compare(self) -> bool {
        matches!(self.opcode(), 0x00..=0x11)
    }
    #[must_use]
    pub const fn is_load_const(self) -> bool {
        matches!(self.opcode(), 0x27..=0x2C)
    }
    #[must_use]
    pub const fn is_table_op(self) -> bool {
        matches!(self.opcode(), 0x34..=0x40)
    }
    #[must_use]
    pub const fn is_upvalue_op(self) -> bool {
        matches!(self.opcode(), 0x2D..=0x33)
    }
    #[must_use]
    pub const fn is_loop(self) -> bool {
        matches!(self.opcode(), 0x4D..=0x57)
    }
    #[must_use]
    pub const fn is_function_header(self) -> bool {
        matches!(self.opcode(), 0x59..=0x60)
    }
    #[must_use]
    pub const fn is_arith(self) -> bool {
        matches!(self.opcode(), 0x16..=0x26)
    }
}

impl fmt::Display for LjInstr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} A={} B={} C={} D={}",
            self.mnemonic(),
            self.a(),
            self.b(),
            self.c(),
            self.d()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Upvalue
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LjUpvalue {
    pub slot: u8,
    pub is_local: bool,
    pub name: Option<String>,
}

impl fmt::Display for LjUpvalue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "upval[{}] local={} name={}",
            self.slot,
            self.is_local,
            self.name.as_deref().unwrap_or("?")
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KGC — Garbage-collected constant (spec §3.9)
// ─────────────────────────────────────────────────────────────────────────────

/// GC-object constant kinds stored in the KGC table.
///
/// Tag encoding (ULEB128 type field):
/// - 0  → `KGCT_CHILD`  (child prototype reference)
/// - 1  → `KGCT_TAB`    (table template)
/// - 2  → `KGCT_I64`    (64-bit signed integer cdata)
/// - 3  → `KGCT_U64`    (64-bit unsigned integer cdata)
/// - 4  → `KGCT_COMPLEX` (complex number cdata: two f64)
/// - n≥5 → `KGCT_STR`   (string of length n-5)
#[derive(Debug, Clone)]
pub enum KGC {
    /// Reference to a nested child prototype.
    Child(Box<LjProto>),
    /// Table template constant.
    Tab,
    /// 64-bit signed integer cdata.
    I64(i64),
    /// 64-bit unsigned integer cdata.
    U64(u64),
    /// Complex number cdata (real, imag).
    Complex(f64, f64),
    /// String constant.
    String(String),
    /// Unknown/unsupported GC constant type.
    Unknown(u32),
}

impl KGC {
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        if let Self::String(s) = self {
            Some(s.as_str())
        } else {
            None
        }
    }
    #[must_use]
    pub const fn is_child(&self) -> bool {
        matches!(self, Self::Child(_))
    }
    #[must_use]
    pub const fn is_string(&self) -> bool {
        matches!(self, Self::String(_))
    }
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Child(_) => "child",
            Self::Tab => "tab",
            Self::I64(_) => "i64",
            Self::U64(_) => "u64",
            Self::Complex(_, _) => "complex",
            Self::String(_) => "string",
            Self::Unknown(_) => "unknown",
        }
    }
}

impl fmt::Display for KGC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Child(_) => write!(f, "<child-proto>"),
            Self::Tab => write!(f, "<table>"),
            Self::I64(n) => write!(f, "cdata({n}i64)"),
            Self::U64(n) => write!(f, "cdata({n}u64)"),
            Self::Complex(r, i) => write!(f, "cdata({r}+{i}i)"),
            Self::String(s) => write!(f, "\"{s}\""),
            Self::Unknown(t) => write!(f, "<unknown-kgc-type={t}>"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// KNumConst — numeric constant
// ─────────────────────────────────────────────────────────────────────────────

/// A numeric constant from the `KN` table.
///
/// `LuaJIT` encodes KN entries with a flag bit:
/// - If the least significant bit of the first ULEB128 word is 1, it is an
///   integer: value = word >> 1.
/// - Otherwise it is a double: the high 32 bits come from the first word, and
///   the low 32 bits follow as a raw u32.
#[derive(Debug, Clone, PartialEq)]
pub enum KNumConst {
    Int(i32),
    Float(f64),
}

impl fmt::Display for KNumConst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Int(i) => write!(f, "{i}"),
            Self::Float(v) => write!(f, "{v}"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy LjConst (kept for API compatibility)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum LjConst {
    Nil,
    Bool(bool),
    Int(i32),
    Num(f64),
    Str(String),
    Upval(u16),
    Proto(u32),
}

impl fmt::Display for LjConst {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nil => write!(f, "nil"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(i) => write!(f, "{i}"),
            Self::Num(n) => write!(f, "{n}"),
            Self::Str(s) => write!(f, "\"{s}\""),
            Self::Upval(i) => write!(f, "upval[{i}]"),
            Self::Proto(i) => write!(f, "proto[{i}]"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VarName — debug local variable info
// ─────────────────────────────────────────────────────────────────────────────

/// Debug info for a single local variable: name + live PC range [start, end).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VarName {
    pub name: String,
    pub start_pc: u32,
    pub end_pc: u32,
}

impl VarName {
    #[must_use]
    pub const fn is_live_at(&self, pc: u32) -> bool {
        pc >= self.start_pc && pc < self.end_pc
    }
}

impl fmt::Display for VarName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}  [{}, {})", self.name, self.start_pc, self.end_pc)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LjLocalVar (alias for VarName, used in LjProto)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LjLocalVar {
    pub name: String,
    pub start_pc: u32,
    pub end_pc: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// DebugInfo
// ─────────────────────────────────────────────────────────────────────────────

/// Full debug information block for one prototype.
#[derive(Debug, Clone, Default)]
pub struct DebugInfo {
    /// Source file name (may start with '@' for file paths).
    pub source_name: Option<String>,
    /// First source line covered.
    pub first_line: u32,
    /// Number of source lines covered.
    pub num_lines: u32,
    /// Per-instruction source line (index = PC).
    pub line_info: Vec<u32>,
    /// Local variable records.
    pub local_vars: Vec<LjLocalVar>,
    /// Upvalue names (parallel to upvalue descriptor array).
    pub upvalue_names: Vec<String>,
}

impl DebugInfo {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.line_info.is_empty()
    }

    #[must_use]
    pub fn source_line_for_pc(&self, pc: usize) -> Option<u32> {
        self.line_info.get(pc).copied()
    }

    #[must_use]
    pub fn locals_at(&self, pc: u32) -> Vec<&LjLocalVar> {
        self.local_vars
            .iter()
            .filter(|v| v.start_pc <= pc && pc < v.end_pc)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LjProto
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed `LuaJIT` function prototype.
///
/// This is the central data structure produced by the loader. It contains the
/// complete representation of a single function: bytecode, upvalue descriptors,
/// GC constants (KGC), numeric constants (KN), and optional debug info.
#[derive(Debug, Clone)]
pub struct LjProto {
    pub flags: LjProtoFlags,
    pub num_params: u8,
    pub frame_size: u8,
    pub num_upvalues: u8,
    pub is_vararg: bool,
    /// Decoded instructions (one per BC word).
    pub instructions: Vec<LjInstr>,
    /// Upvalue descriptors.
    pub upvalues: Vec<LjUpvalue>,
    /// GC constants (KGC table, in reverse order from file).
    pub kgc: Vec<KGC>,
    /// Numeric constants (KN table).
    pub kn: Vec<KNumConst>,
    /// Legacy flat constant list (strings + ints/floats merged).
    pub constants: Vec<LjConst>,
    pub instruction_count: u32,
    /// Optional debug info block.
    pub debug_info: Option<DebugInfo>,
    // Convenience aliases populated from debug_info if present:
    pub source_name: Option<String>,
    pub first_line: u32,
    pub num_lines: u32,
    pub line_info: Vec<u32>,
    pub local_vars: Vec<LjLocalVar>,
    pub upvalue_names: Vec<String>,
}

impl LjProto {
    #[must_use]
    pub fn mock() -> Self {
        Self {
            flags: LjProtoFlags::VARARG,
            num_params: 0,
            frame_size: 4,
            num_upvalues: 1,
            is_vararg: true,
            instructions: vec![LjInstr(0x0000_004B)],
            upvalues: vec![LjUpvalue {
                slot: 0,
                is_local: false,
                name: Some("_ENV".to_string()),
            }],
            kgc: vec![KGC::String("hello".to_string())],
            kn: vec![],
            constants: vec![LjConst::Str("hello".to_string())],
            instruction_count: 1,
            debug_info: None,
            source_name: Some("@test.lua".to_string()),
            first_line: 1,
            num_lines: 10,
            line_info: vec![1],
            local_vars: vec![],
            upvalue_names: vec!["_ENV".to_string()],
        }
    }

    /// Parse a single prototype from `data[offset..]`.
    ///
    /// Returns `(proto, new_offset)` where `new_offset` is the byte position
    /// after this prototype's data (i.e. the start of the next prototype or EOF).
    /// Returns `None` if a proto-size of 0 is read (end-of-chain marker) or if
    /// the buffer is too short.
    #[must_use]
    pub fn parse(data: &[u8], mut offset: usize, is_be: bool) -> Option<(Self, usize)> {
        let (proto_size, new_off) = read_uleb128(data, offset)?;
        offset = new_off;
        if proto_size == 0 {
            return None;
        }
        // Guard against proto_size overflow: proto_size is a u64 from untrusted input;
        // cap it before casting to usize to prevent silent truncation on 32-bit targets.
        let proto_size_usize = usize::try_from(proto_size).unwrap_or(usize::MAX);
        let proto_end = offset.saturating_add(proto_size_usize);
        if proto_end > data.len() {
            return None;
        }
        let pd = &data[offset..proto_end]; // proto data slice
        let mut p = 0usize;
        if pd.len() < 4 {
            return None;
        }

        let flags_byte = pd[p];
        p += 1;
        let flags = LjProtoFlags::from_bits_truncate(flags_byte);
        let num_params = pd[p];
        p += 1;
        let frame_size = pd[p];
        p += 1;
        let num_upvalues = pd[p];
        p += 1;

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

        // Bytecode — use checked arithmetic to prevent multiplication overflow
        // when bc_count is a large attacker-controlled ULEB128 value.
        let bc_count_usize = usize::try_from(bc_count).unwrap_or(usize::MAX);
        let bc_bytes = bc_count_usize.saturating_mul(4);
        if p + bc_bytes > pd.len() {
            return None;
        }
        let mut instructions = Vec::with_capacity(bc_count_usize);
        for i in 0..bc_count_usize {
            let off = p + i * 4;
            if off + 4 > pd.len() {
                break;
            }
            let word = if is_be {
                u32::from_be_bytes(pd[off..off + 4].try_into().ok()?)
            } else {
                u32::from_le_bytes(pd[off..off + 4].try_into().ok()?)
            };
            instructions.push(LjInstr(word));
        }
        p += bc_bytes;

        // Upvalue descriptors (2 bytes each)
        let num_upvalues_usize = usize::from(num_upvalues);
        let uv_bytes = num_upvalues_usize.saturating_mul(2);
        if p + uv_bytes > pd.len() {
            return None;
        }
        let mut upvalues = Vec::with_capacity(num_upvalues_usize);
        for i in 0..num_upvalues_usize {
            let off = p + i * 2;
            let raw = u16::from_le_bytes(pd[off..off + 2].try_into().ok()?);
            upvalues.push(LjUpvalue {
                slot: (raw & 0xFF) as u8,
                is_local: (raw >> 15) != 0,
                name: None,
            });
        }
        p += uv_bytes;

        // KGC constants (GC objects)
        let num_kgc_usize = usize::try_from(num_kgc).unwrap_or(usize::MAX);
        // Unlike the bytecode and upvalue sections above, KGC entries are
        // variable-length so there is no total-size check to lean on. The count
        // is an attacker-controlled ULEB128, and each entry needs at least one
        // byte for its type tag — bound the reservation by the bytes left.
        let mut kgc: Vec<KGC> = Vec::with_capacity(num_kgc_usize.min(pd.len().saturating_sub(p)));
        let mut constants: Vec<LjConst> = Vec::new();
        for _ in 0..num_kgc {
            let (ktype, np) = read_uleb128(pd, p)?;
            p = np;
            match ktype {
                0 => {
                    // Child proto — reference by index; actual proto data is
                    // handled at the LjBytecode level. Store placeholder.
                    kgc.push(KGC::Unknown(0)); // placeholder
                    constants.push(LjConst::Proto(0));
                }
                1 => {
                    kgc.push(KGC::Tab);
                }
                2 => {
                    // i64: lo word + hi word
                    if p + 8 > pd.len() {
                        break;
                    }
                    let lo = u32::from_le_bytes(pd[p..p + 4].try_into().unwrap_or([0; 4]));
                    let hi = u32::from_le_bytes(pd[p + 4..p + 8].try_into().unwrap_or([0; 4]));
                    p += 8;
                    let val = (i64::from(hi) << 32) | i64::from(lo);
                    kgc.push(KGC::I64(val));
                }
                3 => {
                    // u64
                    if p + 8 > pd.len() {
                        break;
                    }
                    let lo = u32::from_le_bytes(pd[p..p + 4].try_into().unwrap_or([0; 4]));
                    let hi = u32::from_le_bytes(pd[p + 4..p + 8].try_into().unwrap_or([0; 4]));
                    p += 8;
                    let val = (u64::from(hi) << 32) | u64::from(lo);
                    kgc.push(KGC::U64(val));
                }
                4 => {
                    // complex (two f64)
                    if p + 16 > pd.len() {
                        break;
                    }
                    let r_bits = u64::from_le_bytes(pd[p..p + 8].try_into().unwrap_or([0; 8]));
                    let i_bits = u64::from_le_bytes(pd[p + 8..p + 16].try_into().unwrap_or([0; 8]));
                    p += 16;
                    kgc.push(KGC::Complex(f64::from_bits(r_bits), f64::from_bits(i_bits)));
                }
                n => {
                    // String: type >= 5, length = n - 5
                    let slen = usize::try_from(n.saturating_sub(5)).unwrap_or(usize::MAX);
                    if p + slen > pd.len() {
                        break;
                    }
                    let s = String::from_utf8_lossy(&pd[p..p + slen]).into_owned();
                    p += slen;
                    constants.push(LjConst::Str(s.clone()));
                    kgc.push(KGC::String(s));
                }
            }
        }

        // KN numeric constants
        let num_kn_usize = usize::try_from(num_kn).unwrap_or(usize::MAX);
        // Same reasoning as KGC: variable-length entries, at least one byte each.
        let mut kn: Vec<KNumConst> =
            Vec::with_capacity(num_kn_usize.min(pd.len().saturating_sub(p)));
        for _ in 0..num_kn {
            if p >= pd.len() {
                break;
            }
            let Some((kval, np)) = read_uleb128(pd, p) else { break };
            p = np;
            if kval & 1 != 0 {
                // Integer: drop the flag bit. The encoder stores the *bit
                // pattern* of the i32 (see `cast_unsigned` in the encoder), so
                // a negative value arrives here as a large u32 — reinterpreting
                // is correct, whereas `i32::try_from` fails for anything with
                // the sign bit set and silently yielded `i32::MAX`.
                // This matches `constant_tables.rs` and `luajit_parser.rs`.
                let ival = u32::try_from(kval >> 1).unwrap_or(u32::MAX).cast_signed();
                kn.push(KNumConst::Int(ival));
                constants.push(LjConst::Int(ival));
            } else {
                // Double: high bits in kval, low 32 bits follow
                if p + 4 > pd.len() {
                    break;
                }
                let lo = u32::from_le_bytes(pd[p..p + 4].try_into().unwrap_or([0; 4]));
                p += 4;
                // kval carries only the high 32 bits of the double; mask to prevent
                // corruption if the ULEB128 decoder produced bits above bit 31.
                let bits = ((kval & 0xFFFF_FFFF) << 32) | u64::from(lo);
                let fval = f64::from_bits(bits);
                kn.push(KNumConst::Float(fval));
                constants.push(LjConst::Num(fval));
            }
        }

        // Debug info
        let mut debug_info_block: Option<DebugInfo> = None;
        let mut line_info_vec = vec![0u32; bc_count_usize];
        let mut local_vars_vec: Vec<LjLocalVar> = Vec::new();
        let mut upvalue_names_vec: Vec<String> = Vec::new();
        let mut source_name_opt: Option<String> = None;

        if dbg_info_size > 0 && p < pd.len() {
            let bytes_per_line = if num_lines < 256 {
                1usize
            } else if num_lines < 65536 {
                2
            } else {
                4
            };
            for i in 0..bc_count_usize {
                if p + bytes_per_line > pd.len() {
                    break;
                }
                let line = match bytes_per_line {
                    1 => {
                        let v = u32::from(pd[p]);
                        p += 1;
                        v
                    }
                    2 => {
                        let v = u32::from(
                            u16::from_le_bytes(pd[p..p + 2].try_into().unwrap_or([0; 2])),
                        );
                        p += 2;
                        v
                    }
                    4 => {
                        let v = u32::from_le_bytes(pd[p..p + 4].try_into().unwrap_or([0; 4]));
                        p += 4;
                        v
                    }
                    _ => 0,
                };
                if i < line_info_vec.len() {
                    line_info_vec[i] = u32::try_from(first_line).unwrap_or(u32::MAX).saturating_add(line);
                }
            }

            // Local variable records
            loop {
                if p >= pd.len() {
                    break;
                }
                let (name_len, np) = read_uleb128(pd, p).unwrap_or((0, p));
                if name_len == 0 {
                    p = np;
                    break;
                }
                p = np;
                // name_len encodes length+1 (1 = terminator convention in LJ)
                let slen = usize::try_from(name_len).unwrap_or(usize::MAX).saturating_sub(1);
                if slen == 0 || p + slen > pd.len() {
                    break;
                }
                let name = String::from_utf8_lossy(&pd[p..p + slen]).into_owned();
                p += slen;
                let (start, np) = read_uleb128(pd, p).unwrap_or((0, p));
                p = np;
                let (end, np) = read_uleb128(pd, p).unwrap_or((0, p));
                p = np;
                local_vars_vec.push(LjLocalVar {
                    name,
                    start_pc: u32::try_from(start).unwrap_or(u32::MAX),
                    end_pc: u32::try_from(end).unwrap_or(u32::MAX),
                });
            }

            // Upvalue names
            for _ in 0..num_upvalues {
                if p >= pd.len() {
                    break;
                }
                let (name_len, np) = read_uleb128(pd, p).unwrap_or((0, p));
                p = np;
                let slen = usize::try_from(name_len).unwrap_or(usize::MAX);
                if slen == 0 || p + slen > pd.len() {
                    upvalue_names_vec.push(String::new());
                    continue;
                }
                let name = String::from_utf8_lossy(&pd[p..p + slen]).into_owned();
                p += slen;
                upvalue_names_vec.push(name);
            }

            // Source name
            if p < pd.len() {
                let (slen, np) = read_uleb128(pd, p).unwrap_or((0, p));
                p = np;
                let slen = usize::try_from(slen).unwrap_or(usize::MAX);
                if slen > 0 && p + slen <= pd.len() {
                    let s = String::from_utf8_lossy(&pd[p..p + slen]).into_owned();
                    p += slen;
                    if !s.is_empty() {
                        source_name_opt = Some(s);
                    }
                }
            }
            let _ = p;

            debug_info_block = Some(DebugInfo {
                source_name: source_name_opt.clone(),
                first_line: u32::try_from(first_line).unwrap_or(u32::MAX),
                num_lines: u32::try_from(num_lines).unwrap_or(u32::MAX),
                line_info: line_info_vec.clone(),
                local_vars: local_vars_vec.clone(),
                upvalue_names: upvalue_names_vec.clone(),
            });
        }

        // Apply upvalue names to upvalue structs
        for (uv, name) in upvalues.iter_mut().zip(upvalue_names_vec.iter()) {
            if !name.is_empty() {
                uv.name = Some(name.clone());
            }
        }

        let proto = Self {
            flags,
            num_params,
            frame_size,
            num_upvalues,
            is_vararg: flags.contains(LjProtoFlags::VARARG),
            instructions,
            upvalues,
            kgc,
            kn,
            constants,
            instruction_count: u32::try_from(bc_count_usize).unwrap_or(u32::MAX),
            debug_info: debug_info_block,
            source_name: source_name_opt,
            first_line: u32::try_from(first_line).unwrap_or(u32::MAX),
            num_lines: u32::try_from(num_lines).unwrap_or(u32::MAX),
            line_info: line_info_vec,
            local_vars: local_vars_vec,
            upvalue_names: upvalue_names_vec,
        };
        Some((proto, proto_end))
    }

    #[must_use]
    pub fn source_line(&self, pc: usize) -> Option<u32> {
        self.line_info.get(pc).copied()
    }

    #[must_use]
    pub fn string_constants(&self) -> Vec<&str> {
        self.constants
            .iter()
            .filter_map(|c| {
                if let LjConst::Str(s) = c {
                    Some(s.as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    #[must_use]
    pub fn kgc_strings(&self) -> Vec<&str> {
        self.kgc.iter().filter_map(|k| k.as_str()).collect()
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
    #[must_use]
    pub fn has_loops(&self) -> bool {
        self.instructions.iter().any(|i| i.is_loop())
    }
    #[must_use]
    pub fn upvalue_name(&self, idx: usize) -> Option<&str> {
        self.upvalue_names.get(idx).map(String::as_str)
    }

    /// Return all local variable names live at `pc`.
    #[must_use]
    pub fn locals_at_pc(&self, pc: u32) -> Vec<&LjLocalVar> {
        self.local_vars
            .iter()
            .filter(|v| v.start_pc <= pc && pc < v.end_pc)
            .collect()
    }

    /// Return all string constants referenced by KSTR/GGET/GSET at a given PC.
    #[must_use]
    pub fn string_at_pc(&self, pc: usize) -> Option<&str> {
        let instr = self.instructions.get(pc)?;
        let d = instr.d() as usize;
        match instr.opcode() {
            0x27 | 0x36 | 0x37 => {
                // KSTR, GGET, GSET — KGC index counts from the END of the table
                let rev_idx = self.kgc.len().saturating_sub(1).saturating_sub(d);
                self.kgc.get(rev_idx).and_then(|k| k.as_str())
            }
            _ => None,
        }
    }
}

impl fmt::Display for LjProto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "proto params={} upvals={} vararg={} frame={} instrs={} src={}",
            self.num_params,
            self.num_upvalues,
            self.is_vararg,
            self.frame_size,
            self.instruction_count,
            self.source_name.as_deref().unwrap_or("?")
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LjBytecode — full file parse result
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LjBytecode {
    pub header: LjHeader,
    pub protos: Vec<LjProto>,
}

impl LjBytecode {
    /// Parses a complete `LuaJIT` bytecode file.
    ///
    /// # Errors
    /// Returns `LjLoaderError` variants if the header or any proto is malformed.
    pub fn parse(data: &[u8]) -> Result<Self, LjLoaderError> {
        let (header, mut pos) = LjHeader::parse(data)?;
        let is_be = header.flags.contains(LjFlags::BE);
        let mut protos = Vec::new();
        while pos < data.len() {
            match LjProto::parse(data, pos, is_be) {
                Some((proto, new_pos)) => {
                    protos.push(proto);
                    pos = new_pos;
                }
                None => break,
            }
        }
        Ok(Self { header, protos })
    }

    #[must_use]
    pub fn total_instructions(&self) -> usize {
        self.protos.iter().map(|p| p.instructions.len()).sum()
    }

    #[must_use]
    pub fn all_strings(&self) -> Vec<&str> {
        let mut seen = std::collections::HashSet::new();
        self.protos
            .iter()
            .flat_map(|p| p.kgc_strings())
            .filter(|s| seen.insert(*s))
            .collect()
    }

    #[must_use]
    pub fn protos_referencing_string(&self, target: &str) -> Vec<usize> {
        self.protos
            .iter()
            .enumerate()
            .filter(|(_, p)| p.kgc_strings().contains(&target))
            .map(|(i, _)| i)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LjModule — high-level single-root module
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LjModule {
    pub header: LjHeader,
    pub root_proto: LjProto,
}

impl LjModule {
    #[must_use]
    pub fn all_protos(&self) -> Vec<&LjProto> {
        vec![&self.root_proto]
    }
    #[must_use]
    pub const fn total_instructions(&self) -> usize {
        self.root_proto.instructions.len()
    }
    #[must_use]
    pub fn string_constants(&self) -> Vec<String> {
        self.root_proto
            .kgc
            .iter()
            .filter_map(|k| {
                if let KGC::String(s) = k {
                    Some(s.clone())
                } else {
                    None
                }
            })
            .collect()
    }
    #[must_use]
    pub fn source_name(&self) -> Option<&str> {
        self.header
            .debug_name
            .as_deref()
            .or(self.root_proto.source_name.as_deref())
    }
    #[must_use]
    pub const fn is_stripped(&self) -> bool {
        self.header.flags.contains(LjFlags::STRIP)
    }
    #[must_use]
    pub const fn is_big_endian(&self) -> bool {
        self.header.flags.contains(LjFlags::BE)
    }
    #[must_use]
    pub const fn version(&self) -> LjVersion {
        self.header.version
    }
    #[must_use]
    pub const fn uses_ffi(&self) -> bool {
        self.header.flags.contains(LjFlags::FFI)
    }
    #[must_use]
    pub const fn uses_fr2(&self) -> bool {
        self.header.flags.contains(LjFlags::FR2)
    }
}

impl fmt::Display for LjModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LjModule {{ version={}, stripped={}, instrs={}, src={:?} }}",
            self.header.version,
            self.is_stripped(),
            self.total_instructions(),
            self.source_name()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaJitLoader
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, Copy)]
pub struct LuaJitLoader;

impl LuaJitLoader {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Loads a `LuaJIT` module from raw bytecode data.
    ///
    /// # Errors
    /// Returns `LjLoaderError` if parsing fails or no prototypes are found.
    pub fn load(data: &[u8]) -> Result<LjModule, LjLoaderError> {
        let (header, mut pos) = LjHeader::parse(data)?;
        let is_be = header.flags.contains(LjFlags::BE);
        let mut protos: Vec<LjProto> = Vec::new();
        while pos < data.len() {
            match LjProto::parse(data, pos, is_be) {
                Some((proto, new_pos)) => {
                    protos.push(proto);
                    pos = new_pos;
                }
                None => break,
            }
        }
        let root_proto = protos.into_iter().last().ok_or_else(|| {
            LjLoaderError::ParseError("no prototypes found in bytecode dump".into())
        })?;
        Ok(LjModule { header, root_proto })
    }

    #[must_use]
    pub fn can_load(data: &[u8]) -> bool {
        is_luajit(data)
    }

    /// Loads all prototypes from a `LuaJIT` bytecode dump.
    ///
    /// # Errors
    /// Returns `LjLoaderError` if parsing fails.
    pub fn load_all(data: &[u8]) -> Result<LjBytecode, LjLoaderError> {
        LjBytecode::parse(data)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProtoStats
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtoStats {
    pub total: usize,
    pub calls: usize,
    pub returns: usize,
    pub branches: usize,
    pub compares: usize,
    pub arith: usize,
    pub loads: usize,
    pub table_ops: usize,
    pub upvalue_ops: usize,
    pub loop_instrs: usize,
    pub opcode_freq: Vec<(u8, usize)>,
}

impl ProtoStats {
    #[must_use]
    pub fn compute(proto: &LjProto) -> Self {
        let mut freq: HashMap<u8, usize> = HashMap::new();
        let mut calls = 0usize;
        let mut returns = 0;
        let mut branches = 0;
        let mut compares = 0;
        let mut arith = 0;
        let mut loads = 0;
        let mut table_ops = 0;
        let mut upvalue_ops = 0;
        let mut loop_instrs = 0;
        for instr in &proto.instructions {
            *freq.entry(instr.opcode()).or_insert(0) += 1;
            if instr.is_call() {
                calls += 1;
            }
            if instr.is_return() {
                returns += 1;
            }
            if instr.is_branch() {
                branches += 1;
            }
            if instr.is_compare() {
                compares += 1;
            }
            if instr.is_arith() {
                arith += 1;
            }
            if instr.is_load_const() {
                loads += 1;
            }
            if instr.is_table_op() {
                table_ops += 1;
            }
            if instr.is_upvalue_op() {
                upvalue_ops += 1;
            }
            if instr.is_loop() {
                loop_instrs += 1;
            }
        }
        let mut opcode_freq: Vec<(u8, usize)> = freq.into_iter().collect();
        opcode_freq.sort_by_key(|(op, _)| *op);
        Self {
            total: proto.instructions.len(),
            calls,
            returns,
            branches,
            compares,
            arith,
            loads,
            table_ops,
            upvalue_ops,
            loop_instrs,
            opcode_freq,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LjDisassembler
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct LjDisassembler;

impl LjDisassembler {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn disassemble_proto(proto: &LjProto) -> Vec<String> {
        proto
            .instructions
            .iter()
            .enumerate()
            .map(|(pc, instr)| Self::format_instr(pc, *instr, proto))
            .collect()
    }

    #[must_use]
    pub fn disassemble_all(module: &LjModule) -> String {
        let mut out = String::with_capacity(4096);
        writeln!(
            out,
            "; LuaJIT bytecode  version={}  stripped={}",
            module.version(),
            module.is_stripped()
        )
        .unwrap();
        if let Some(src) = module.source_name() {
            writeln!(out, "; source: {src}").unwrap();
        }
        out.push('\n');
        Self::append_proto_listing(&mut out, 0, &module.root_proto);
        out
    }

    #[must_use]
    pub fn disassemble_bytecode(bc: &LjBytecode) -> String {
        let mut out = String::with_capacity(8192);
        writeln!(out, "; LuaJIT bytecode  {}  protos={}\n", bc.header, bc.protos.len()).unwrap();
        for (i, proto) in bc.protos.iter().enumerate() {
            Self::append_proto_listing(&mut out, i, proto);
        }
        out
    }

    fn append_proto_listing(out: &mut String, idx: usize, proto: &LjProto) {
        writeln!(
            out,
            "; proto #{idx}  params={}  upvals={}  frame={}  vararg={}  src={}",
            proto.num_params,
            proto.num_upvalues,
            proto.frame_size,
            proto.is_vararg,
            proto.source_name.as_deref().unwrap_or("?")
        )
        .unwrap();
        if proto.first_line > 0 {
            writeln!(
                out,
                ";   lines {}-{}",
                proto.first_line,
                proto.first_line + proto.num_lines.saturating_sub(1)
            )
            .unwrap();
        }
        for line in Self::disassemble_proto(proto) {
            out.push_str(&line);
            out.push('\n');
        }
        out.push('\n');
    }

    #[must_use]
    pub fn format_instr(pc: usize, instr: LjInstr, proto: &LjProto) -> String {
        use rustre_arch_luajit as arch_lj;
        const BIAS: i32 = 0x8000;
        let op = instr.opcode();
        let a = instr.a();
        let d = instr.d();
        let d_signed: i32 = i32::from(d) - BIAS;
        let mnem: &'static str = arch_lj::LjOp::from_u8(op)
            .map_or("???", arch_lj::LjOp::mnemonic);
        let full = arch_lj::format_instruction(pc, instr.0);
        let operands: &str = if full.len() > 16 { &full[16..] } else { "" };
        let comment =
            Self::make_comment(pc, op, a, instr.b(), instr.c(), d, d_signed, instr, proto);
        let line_annotation = proto
            .source_line(pc)
            .map(|ln| format!(" line:{ln}"))
            .unwrap_or_default();
        if comment.is_empty() {
            format!("{pc:04}  {mnem:<8}  {operands:<22}  ;{line_annotation}")
        } else {
            format!("{pc:04}  {mnem:<8}  {operands:<22}  ;{line_annotation}  {comment}")
        }
    }

    fn make_comment(
        pc: usize,
        op: u8,
        a: u8,
        _b: u8,
        c: u8,
        d: u16,
        d_signed: i32,
        _instr: LjInstr,
        proto: &LjProto,
    ) -> String {
        let kgc_str = |idx: usize| -> Option<String> {
            proto
                .kgc
                .get(idx)
                .and_then(|k| k.as_str())
                .map(String::from)
        };
        match op {
            0x27 => kgc_str(d as usize).unwrap_or_default(), // KSTR
            0x28 => format!("cdata[{d}]"),                   // KCDATA
            0x29 => format!("{d_signed}"),                   // KSHORT
            0x2A => kgc_str(d as usize).unwrap_or_default(), // KNUM
            0x2B => match d {
                0 => "nil".into(),
                1 => "false".into(),
                2 => "true".into(),
                _ => format!("pri({d})"),
            }, // KPRI
            0x2C => format!("R{a}..R{d}"),                   // KNIL
            0x2D | 0x2E => proto
                .upvalue_names
                .get(d as usize)
                .cloned()
                .unwrap_or_else(|| format!("uv[{d}]")), // UGET/USETV
            0x2F => kgc_str(d as usize).unwrap_or_default(), // USETS
            0x33 => format!("proto[{d}]"),                   // FNEW
            0x36 | 0x37 => kgc_str(d as usize).unwrap_or_default(), // GGET/GSET
            0x39 | 0x3D => kgc_str(c as usize).unwrap_or_default(), // TGETS/TSETS
            0x4D | 0x4F | 0x52 | 0x55 | 0x58 => {
                let target = usize::try_from(
                    isize::try_from(pc).unwrap_or(isize::MAX)
                        .wrapping_add(1)
                        .wrapping_add(d_signed as isize),
                )
                .unwrap_or(0);
                format!("-> {target:04}")
            }
            _ => String::new(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Architecture stub
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct LuaJitArch;

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
        // A LuaJIT bytecode instruction is exactly four bytes. Fewer than that
        // is the end of the buffer, not a `nop`: reporting one invents an
        // instruction that the caller cannot distinguish from a real nop.
        if bytes.len() < 4 {
            return Err(CoreError::Truncated {
                expected: 4,
                got: bytes.len(),
            });
        }
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let instr = LjInstr(word);
        let mut decoded = Instruction::new(address, 4, instr.mnemonic(), bytes[..4].to_vec());
        decoded.operands = format!("A={} B={} C={}", instr.a(), instr.b(), instr.c());
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
            CallingConvention::new("luajit")
                .with_int_args(vec!["r0".to_string(), "r1".to_string()])
                .with_return_regs(vec!["r0".to_string()]),
        ]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LjLoader (rustre-core Loader trait)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct LjLoader;

impl LjLoader {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Loader for LjLoader {
    fn name(&self) -> &'static str {
        "luajit"
    }
    fn can_load(&self, input: &LoaderInput) -> bool {
        is_luajit(&input.data)
    }

    async fn load(&self, input: LoaderInput) -> Result<LoadResult, CoreError> {
        let base = input.hints.base_address().map_or(0_u64, Address::as_u64);
        let mut mem = Memory::new();
        let size = input.data.len() as u64;
        if size > 0 {
            mem.add_segment(Segment {
                range: AddressRange::new(Address::new(base), Address::new(base + size)),
                permissions: Permissions::READ | Permissions::EXECUTE,
                data: input.data.clone(),
            });
        }
        let arch = Arc::new(LuaJitArch);
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
// Convenience wrappers
// ─────────────────────────────────────────────────────────────────────────────

/// Parses a single proto from a `LuaJIT` bytecode stream, advancing the offset.
///
/// # Errors
/// Returns `LjLoaderError::TruncatedData` if the data is incomplete.
pub fn parse_proto(
    data: &[u8],
    offset: &mut usize,
    parent_flags: u32,
) -> Result<LjProto, LjLoaderError> {
    let is_be = (parent_flags & u32::from(LjFlags::BE.bits())) != 0;
    match LjProto::parse(data, *offset, is_be) {
        Some((proto, new_offset)) => {
            *offset = new_offset;
            Ok(proto)
        }
        None => Err(LjLoaderError::TruncatedData),
    }
}

/// Reads a ULEB128-encoded value, advancing the mutable offset.
///
/// # Errors
/// Returns `LjLoaderError::TruncatedData` if the data ends before a complete encoding.
pub fn read_uleb128_mut(data: &[u8], offset: &mut usize) -> Result<u64, LjLoaderError> {
    match read_uleb128(data, *offset) {
        Some((val, new_off)) => {
            *offset = new_off;
            Ok(val)
        }
        None => Err(LjLoaderError::TruncatedData),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UpvalInfo (detailed upvalue descriptor)
// ─────────────────────────────────────────────────────────────────────────────

/// Detailed upvalue descriptor as stored in the binary format.
///
/// Each upvalue is encoded as a 16-bit word:
/// - bit 15   : 1 = on-stack (closed over local), 0 = from parent upvalue
/// - bits 14-8: immutable flag and other attrs
/// - bits  7-0: slot index (stack slot if on-stack, or parent upval index)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpvalInfo {
    pub index: u8,
    pub is_local: bool,
    pub is_immutable: bool,
    pub raw: u16,
}

impl UpvalInfo {
    #[must_use]
    pub const fn from_raw(raw: u16) -> Self {
        Self {
            index: (raw & 0xFF) as u8,
            is_local: (raw >> 15) != 0,
            is_immutable: ((raw >> 8) & 0x01) != 0,
            raw,
        }
    }
}

impl fmt::Display for UpvalInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "upval idx={} local={} immutable={}",
            self.index, self.is_local, self.is_immutable
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ProtoBuilder — programmatic prototype construction (useful in tests)
// ─────────────────────────────────────────────────────────────────────────────

/// Builder for constructing `LjProto` instances programmatically.
#[derive(Debug)]
pub struct ProtoBuilder {
    flags: LjProtoFlags,
    num_params: u8,
    frame_size: u8,
    instructions: Vec<LjInstr>,
    upvalues: Vec<LjUpvalue>,
    kgc: Vec<KGC>,
    kn: Vec<KNumConst>,
    constants: Vec<LjConst>,
    source_name: Option<String>,
}

impl Default for ProtoBuilder {
    fn default() -> Self {
        Self {
            flags: LjProtoFlags::empty(),
            num_params: 0,
            frame_size: 0,
            instructions: Vec::new(),
            upvalues: Vec::new(),
            kgc: Vec::new(),
            kn: Vec::new(),
            constants: Vec::new(),
            source_name: None,
        }
    }
}

impl ProtoBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn params(mut self, n: u8) -> Self {
        self.num_params = n;
        self
    }
    #[must_use]
    pub const fn frame(mut self, n: u8) -> Self {
        self.frame_size = n;
        self
    }
    #[must_use]
    pub fn vararg(mut self) -> Self {
        self.flags |= LjProtoFlags::VARARG;
        self
    }
    #[must_use]
    pub fn source(mut self, s: impl Into<String>) -> Self {
        self.source_name = Some(s.into());
        self
    }
    #[must_use]
    pub fn add_instr(mut self, i: LjInstr) -> Self {
        self.instructions.push(i);
        self
    }
    #[must_use]
    pub fn add_kgc_str(mut self, s: impl Into<String>) -> Self {
        let s = s.into();
        self.constants.push(LjConst::Str(s.clone()));
        self.kgc.push(KGC::String(s));
        self
    }
    #[must_use]
    pub fn add_kn_int(mut self, v: i32) -> Self {
        self.constants.push(LjConst::Int(v));
        self.kn.push(KNumConst::Int(v));
        self
    }
    #[must_use]
    pub fn add_upvalue(mut self, slot: u8, is_local: bool, name: Option<String>) -> Self {
        self.upvalues.push(LjUpvalue {
            slot,
            is_local,
            name,
        });
        self
    }

    #[must_use]
    pub fn build(self) -> LjProto {
        let ic = u32::try_from(self.instructions.len()).unwrap_or(u32::MAX);
        LjProto {
            num_upvalues: u8::try_from(self.upvalues.len()).unwrap_or(u8::MAX),
            is_vararg: self.flags.contains(LjProtoFlags::VARARG),
            instruction_count: ic,
            upvalue_names: self
                .upvalues
                .iter()
                .map(|u| u.name.clone().unwrap_or_default())
                .collect(),
            flags: self.flags,
            num_params: self.num_params,
            frame_size: self.frame_size,
            instructions: self.instructions,
            upvalues: self.upvalues,
            kgc: self.kgc,
            kn: self.kn,
            constants: self.constants,
            debug_info: None,
            source_name: self.source_name,
            first_line: 0,
            num_lines: 0,
            line_info: vec![0; ic as usize],
            local_vars: vec![],
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BytecodeEncoder — minimal encoder for round-trip testing
// ─────────────────────────────────────────────────────────────────────────────

/// Produces a minimal valid `LuaJIT` bytecode byte stream from a header + a
/// single prototype. Useful for unit-testing the parser with known inputs.
pub struct BytecodeEncoder;

impl BytecodeEncoder {
    fn write_uleb128(out: &mut Vec<u8>, mut v: u64) {
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
    }

    /// Encode a complete `LuaJIT` bytecode file (stripped) with one prototype.
    #[must_use]
    pub fn encode_stripped(version: LjVersion, proto: &LjProto) -> Vec<u8> {
        let mut out = Vec::new();
        // Header: magic + version + flags (STRIP=2) as ULEB128
        out.extend_from_slice(&LJ_MAGIC);
        out.push(version.as_byte());
        Self::write_uleb128(&mut out, u64::from(LjFlags::STRIP.bits()));
        // Proto body
        let body = Self::encode_proto(proto);
        Self::write_uleb128(&mut out, body.len() as u64);
        out.extend_from_slice(&body);
        // End marker
        out.push(0);
        out
    }

    fn encode_proto(proto: &LjProto) -> Vec<u8> {
        // Mandatory proto header bytes (flags, num_params, frame_size, num_upvalues)
        let mut body = vec![
            proto.flags.bits(),
            proto.num_params,
            proto.frame_size,
            u8::try_from(proto.upvalues.len()).unwrap_or(u8::MAX),
        ];
        let num_kgc = proto
            .kgc
            .iter()
            .filter(|k| matches!(k, KGC::String(_)))
            .count();
        Self::write_uleb128(&mut body, num_kgc as u64);
        Self::write_uleb128(&mut body, proto.kn.len() as u64);
        Self::write_uleb128(&mut body, proto.instructions.len() as u64);
        Self::write_uleb128(&mut body, 0); // no debug info
        // Bytecode
        for instr in &proto.instructions {
            body.extend_from_slice(&instr.0.to_le_bytes());
        }
        // Upvalues (2 bytes each)
        for uv in &proto.upvalues {
            let raw = u16::from(uv.slot) | if uv.is_local { 0x8000 } else { 0 };
            body.extend_from_slice(&raw.to_le_bytes());
        }
        // KGC strings
        for k in &proto.kgc {
            if let KGC::String(s) = k {
                let len = s.len() as u64 + 5; // KGCT_STR offset
                Self::write_uleb128(&mut body, len);
                body.extend_from_slice(s.as_bytes());
            }
        }
        // KN
        for kn in &proto.kn {
            match kn {
                KNumConst::Int(v) => {
                    // Reinterpret bits as u32, shift left 1, set flag bit
                    Self::write_uleb128(&mut body, (u64::from((*v).cast_unsigned()) << 1) | 1);
                }
                KNumConst::Float(v) => {
                    let bits = v.to_bits();
                    let hi = u32::try_from(bits >> 32).unwrap_or(0);
                    let lo = u32::try_from(bits & 0xFFFF_FFFF).unwrap_or(0);
                    Self::write_uleb128(&mut body, u64::from(hi));
                    body.extend_from_slice(&lo.to_le_bytes());
                }
            }
        }
        body
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_lj_header(version: u8, flags: u8) -> Vec<u8> {
        let mut data = vec![0x1Bu8, b'L', b'J', version];
        data.push(flags);
        if (flags & LjFlags::STRIP.bits()) == 0 {
            data.push(0);
        }
        data
    }

    fn make_lj_stripped(version: u8) -> Vec<u8> {
        vec![0x1Bu8, b'L', b'J', version, LjFlags::STRIP.bits()]
    }

    fn make_module() -> LjModule {
        let data = vec![0x1Bu8, b'L', b'J', 2, LjFlags::STRIP.bits()];
        let (header, _) = LjHeader::parse(&data).unwrap();
        LjModule {
            header,
            root_proto: LjProto::mock(),
        }
    }

    // ── Magic detection ───────────────────────────────────────────────────────

    #[test]
    fn test_is_luajit_valid() {
        assert!(is_luajit(b"\x1bLJfoo"));
    }
    #[test]
    fn test_is_luajit_too_short() {
        assert!(!is_luajit(b"\x1bL"));
    }
    #[test]
    fn test_is_luajit_wrong_magic() {
        assert!(!is_luajit(b"\x1bLua"));
    }
    #[test]
    fn test_is_luajit_empty() {
        assert!(!is_luajit(b""));
    }

    // ── LjVersion ─────────────────────────────────────────────────────────────

    #[test]
    fn test_version_lj20() {
        assert_eq!(LjVersion::from_byte(1), LjVersion::Lj20);
    }
    #[test]
    fn test_version_lj21() {
        assert_eq!(LjVersion::from_byte(2), LjVersion::Lj21);
    }
    #[test]
    fn test_version_unknown() {
        assert_eq!(LjVersion::from_byte(99), LjVersion::Unknown(99));
    }
    #[test]
    fn test_version_is_known() {
        assert!(LjVersion::Lj20.is_known());
        assert!(LjVersion::Lj21.is_known());
        assert!(!LjVersion::Unknown(9).is_known());
    }
    #[test]
    fn test_version_as_byte() {
        assert_eq!(LjVersion::Lj20.as_byte(), 1);
        assert_eq!(LjVersion::Lj21.as_byte(), 2);
    }
    #[test]
    fn test_version_display_lj20() {
        assert_eq!(LjVersion::Lj20.to_string(), "LuaJIT 2.0");
    }
    #[test]
    fn test_version_display_lj21() {
        assert_eq!(LjVersion::Lj21.to_string(), "LuaJIT 2.1");
    }
    #[test]
    fn test_version_display_unknown() {
        assert!(LjVersion::Unknown(0x55).to_string().contains("unknown"));
    }

    // ── LjFlags ───────────────────────────────────────────────────────────────

    #[test]
    fn test_flags_be() {
        let f = LjFlags::BE;
        assert!(f.contains(LjFlags::BE));
        assert!(!f.contains(LjFlags::STRIP));
    }
    #[test]
    fn test_flags_strip() {
        let f = LjFlags::STRIP;
        assert!(f.contains(LjFlags::STRIP));
        assert!(!f.contains(LjFlags::FFI));
    }
    #[test]
    fn test_flags_combined() {
        let f = LjFlags::FFI | LjFlags::FR2;
        assert!(f.contains(LjFlags::FFI));
        assert!(f.contains(LjFlags::FR2));
        assert!(!f.contains(LjFlags::BE));
    }

    // ── LjHeader ──────────────────────────────────────────────────────────────

    #[test]
    fn test_header_parse_v21() {
        let data = make_lj_header(2, 0);
        let (hdr, _) = LjHeader::parse(&data).unwrap();
        assert_eq!(hdr.version, LjVersion::Lj21);
        assert!(!hdr.flags.contains(LjFlags::STRIP));
    }
    #[test]
    fn test_header_parse_stripped() {
        let data = make_lj_stripped(2);
        let (hdr, _) = LjHeader::parse(&data).unwrap();
        assert!(hdr.flags.contains(LjFlags::STRIP));
        assert!(hdr.debug_name.is_none());
    }
    #[test]
    fn test_header_wrong_magic() {
        let err = LjHeader::parse(b"\x1bLua00").unwrap_err();
        assert!(matches!(err, LjLoaderError::InvalidMagic));
    }
    #[test]
    fn test_header_too_short() {
        let err = LjHeader::parse(b"\x1b").unwrap_err();
        assert!(matches!(err, LjLoaderError::TruncatedData));
    }
    #[test]
    fn test_header_with_debug_name() {
        let mut data = vec![0x1Bu8, b'L', b'J', 2, 0];
        data.push(8);
        data.extend_from_slice(b"@test.lu");
        let (hdr, _) = LjHeader::parse(&data).unwrap();
        assert_eq!(hdr.debug_name.as_deref(), Some("@test.lu"));
    }
    #[test]
    fn test_header_display() {
        let data = make_lj_header(2, 0);
        let (hdr, _) = LjHeader::parse(&data).unwrap();
        assert!(hdr.to_string().contains("LuaJIT 2.1"));
    }

    // ── LEB128 ────────────────────────────────────────────────────────────────

    #[test]
    fn test_uleb128_single_byte() {
        assert_eq!(read_uleb128(&[0x42], 0), Some((0x42, 1)));
    }
    #[test]
    fn test_uleb128_two_bytes() {
        assert_eq!(read_uleb128(&[0x81, 0x01], 0), Some((129, 2)));
    }
    #[test]
    fn test_uleb128_zero() {
        assert_eq!(read_uleb128(&[0x00], 0), Some((0, 1)));
    }
    #[test]
    fn test_uleb128_eof() {
        assert_eq!(read_uleb128(&[], 0), None);
    }
    #[test]
    fn test_sleb128_positive() {
        assert_eq!(read_sleb128(&[0x10], 0), Some((16, 1)));
    }
    #[test]
    fn test_sleb128_negative() {
        let result = read_sleb128(&[0x7F], 0);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, -1);
    }
    #[test]
    fn test_uleb128_300() {
        let mut off = 0;
        let val = read_uleb128_mut(&[0xAC, 0x02], &mut off).unwrap();
        assert_eq!(val, 300);
        assert_eq!(off, 2);
    }

    // ── LjInstr ───────────────────────────────────────────────────────────────

    #[test]
    fn test_instr_opcode() {
        let instr = LjInstr(0x0102_034B);
        assert_eq!(instr.opcode(), 0x4B);
    }
    #[test]
    fn test_instr_a() {
        let instr = LjInstr(0x0000_0200);
        assert_eq!(instr.a(), 2);
    }
    #[test]
    fn test_instr_b() {
        let instr = LjInstr(0x0300_0000);
        assert_eq!(instr.b(), 3);
    }
    #[test]
    fn test_instr_c() {
        let instr = LjInstr(0x0004_0000);
        assert_eq!(instr.c(), 4);
    }
    #[test]
    fn test_instr_d() {
        let instr = LjInstr(0x0102_0000);
        assert_eq!(instr.d(), 0x0102);
    }
    #[test]
    fn test_instr_mnemonic_ret0() {
        let instr = LjInstr(0x0000_004B);
        assert_eq!(instr.mnemonic(), "RET0");
    }
    #[test]
    fn test_instr_mnemonic_jmp() {
        let instr = LjInstr(0x0000_0058);
        assert_eq!(instr.mnemonic(), "JMP");
    }
    #[test]
    fn test_instr_is_call() {
        assert!(LjInstr(0x0000_0042).is_call());
    }
    #[test]
    fn test_instr_is_return() {
        assert!(LjInstr(0x0000_004B).is_return());
    }
    #[test]
    fn test_instr_is_branch() {
        assert!(LjInstr(0x0000_0058).is_branch());
    }
    #[test]
    fn test_instr_is_compare() {
        assert!(LjInstr(0x0000_0000).is_compare());
        assert!(!LjInstr(0x0000_0058).is_compare());
    }
    #[test]
    fn test_instr_is_arith() {
        assert!(LjInstr(0x0000_0020).is_arith());
    }
    #[test]
    fn test_instr_is_table_op() {
        assert!(LjInstr(0x0000_0034).is_table_op());
    }
    #[test]
    fn test_instr_display() {
        let s = LjInstr(0x0000_004B).to_string();
        assert!(s.contains("RET0"));
    }

    // ── LjProto mock ──────────────────────────────────────────────────────────

    #[test]
    fn test_proto_mock() {
        let p = LjProto::mock();
        assert!(p.is_vararg);
        assert_eq!(p.num_params, 0);
    }
    #[test]
    fn test_proto_string_constants() {
        let p = LjProto::mock();
        assert!(p.kgc_strings().contains(&"hello"));
    }
    #[test]
    fn test_proto_display() {
        let s = LjProto::mock().to_string();
        assert!(s.contains("proto"));
    }
    #[test]
    fn test_proto_call_count() {
        assert_eq!(LjProto::mock().call_count(), 0);
    }
    #[test]
    fn test_proto_return_count() {
        let _ = LjProto::mock().return_count();
    }
    #[test]
    fn test_proto_has_loops() {
        assert!(!LjProto::mock().has_loops());
    }

    // ── LjConst ───────────────────────────────────────────────────────────────

    #[test]
    fn test_const_nil() {
        assert_eq!(LjConst::Nil.to_string(), "nil");
    }
    #[test]
    fn test_const_bool() {
        assert_eq!(LjConst::Bool(true).to_string(), "true");
    }
    #[test]
    fn test_const_int() {
        assert_eq!(LjConst::Int(42).to_string(), "42");
    }
    #[test]
    fn test_const_str() {
        assert_eq!(LjConst::Str("hello".to_string()).to_string(), "\"hello\"");
    }
    #[test]
    fn test_const_upval() {
        assert_eq!(LjConst::Upval(3).to_string(), "upval[3]");
    }

    // ── KGC ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_kgc_string_as_str() {
        assert_eq!(KGC::String("hello".to_string()).as_str(), Some("hello"));
    }
    #[test]
    fn test_kgc_child_is_child() {
        assert!(KGC::Child(Box::new(LjProto::mock())).is_child());
    }
    #[test]
    fn test_kgc_tab_as_str_none() {
        assert!(KGC::Tab.as_str().is_none());
    }
    #[test]
    fn test_kgc_i64_display() {
        assert!(KGC::I64(-7).to_string().contains("-7"));
    }
    #[test]
    fn test_kgc_u64_display() {
        assert!(KGC::U64(42).to_string().contains("42"));
    }
    #[test]
    fn test_kgc_tab_display() {
        assert_eq!(KGC::Tab.to_string(), "<table>");
    }
    #[test]
    fn test_kgc_unknown_display() {
        assert!(KGC::Unknown(99).to_string().contains("99"));
    }
    #[test]
    fn test_kgc_kind_name() {
        assert_eq!(KGC::Tab.kind_name(), "tab");
        assert_eq!(KGC::String("x".into()).kind_name(), "string");
    }

    // ── KNumConst ─────────────────────────────────────────────────────────────

    #[test]
    fn test_knum_int_display() {
        assert_eq!(KNumConst::Int(5).to_string(), "5");
    }
    #[test]
    fn test_knum_float_display() {
        assert!(KNumConst::Float(3.14_f64).to_string().contains("3.14"));
    }

    // ── VarName ───────────────────────────────────────────────────────────────

    #[test]
    fn test_varname_live_at() {
        let v = VarName {
            name: "x".to_string(),
            start_pc: 2,
            end_pc: 8,
        };
        assert!(!v.is_live_at(1));
        assert!(v.is_live_at(2));
        assert!(!v.is_live_at(8));
    }
    #[test]
    fn test_varname_display() {
        let v = VarName {
            name: "i".to_string(),
            start_pc: 0,
            end_pc: 10,
        };
        let s = v.to_string();
        assert!(s.contains('i'));
        assert!(s.contains("10"));
    }
    #[test]
    fn test_varname_empty_range() {
        let v = VarName {
            name: "n".to_string(),
            start_pc: 5,
            end_pc: 5,
        };
        assert!(!v.is_live_at(5));
    }

    // ── LjBytecode ────────────────────────────────────────────────────────────

    #[test]
    fn test_bytecode_parse_minimal() {
        let mut data = make_lj_stripped(2);
        data.push(0x00);
        let bc = LjBytecode::parse(&data).unwrap();
        assert!(bc.protos.is_empty());
    }
    #[test]
    fn test_bytecode_header_version() {
        let mut data = make_lj_stripped(1);
        data.push(0x00);
        let bc = LjBytecode::parse(&data).unwrap();
        assert_eq!(bc.header.version, LjVersion::Lj20);
    }
    #[test]
    fn test_bytecode_all_strings_from_mock() {
        let mut data = make_lj_stripped(2);
        data.push(0x00);
        let mut bc = LjBytecode::parse(&data).unwrap();
        bc.protos.push(LjProto::mock());
        assert!(bc.all_strings().contains(&"hello"));
    }

    // ── ProtoStats ────────────────────────────────────────────────────────────

    #[test]
    fn test_proto_stats_compute() {
        let p = LjProto::mock();
        let s = ProtoStats::compute(&p);
        assert_eq!(s.total, p.instructions.len());
    }
    #[test]
    fn test_proto_stats_empty() {
        let mut p = LjProto::mock();
        p.instructions.clear();
        let s = ProtoStats::compute(&p);
        assert_eq!(s.total, 0);
    }
    #[test]
    fn test_proto_stats_fields() {
        let p = ProtoBuilder::new()
            .vararg()
            .add_instr(LjInstr(0x0000_0042)) // CALL
            .add_instr(LjInstr(0x0000_004B)) // RET0
            .add_instr(LjInstr(0x0000_0000)) // ISLT
            .build();
        let s = ProtoStats::compute(&p);
        assert_eq!(s.calls, 1);
        assert_eq!(s.returns, 1);
        assert_eq!(s.compares, 1);
    }

    // ── Loader ────────────────────────────────────────────────────────────────

    #[test]
    fn test_loader_name() {
        assert_eq!(LjLoader::new().name(), "luajit");
    }
    #[test]
    fn test_loader_can_load_true() {
        let data = make_lj_stripped(2);
        let input = LoaderInput::new("test.ljbc", data);
        assert!(LjLoader::new().can_load(&input));
    }
    #[test]
    fn test_loader_can_load_false() {
        let input = LoaderInput::new("test.bin", vec![0xDE, 0xAD]);
        assert!(!LjLoader::new().can_load(&input));
    }
    #[tokio::test]
    async fn test_loader_load() {
        let data = make_lj_stripped(2);
        let input = LoaderInput::new("test.ljbc", data);
        let result = LjLoader::new().load(input).await.unwrap();
        assert_eq!(result.view.uri, "test.ljbc");
    }
    #[tokio::test]
    async fn test_loader_find_nested() {
        let data = make_lj_stripped(2);
        let input = LoaderInput::new("test.ljbc", data);
        assert!(
            LjLoader::new()
                .find_nested(&input)
                .await
                .unwrap()
                .is_empty()
        );
    }

    // ── LuaJitArch ───────────────────────────────────────────────────────────

    #[test]
    fn test_arch_name() {
        assert_eq!(LuaJitArch.name(), "luajit");
    }
    #[test]
    fn test_arch_pointer_size() {
        assert_eq!(LuaJitArch.pointer_size(), 8);
    }

    #[test]
    fn luajit_arch_refuses_a_partial_instruction() {
        // 0..3 bytes are the tail of a buffer, not a one-byte nop.
        for len in 0..4usize {
            assert!(
                LuaJitArch.disassemble(Address::new(0), &vec![0u8; len]).is_err(),
                "{len} bytes must not yield an instruction"
            );
        }
        // Four bytes still decode, so the guard has not become a blanket refusal.
        assert!(LuaJitArch.disassemble(Address::new(0), &[0u8; 4]).is_ok());
    }
    #[test]
    fn test_arch_endian() {
        assert_eq!(LuaJitArch.endian(), Endian::Little);
    }
    #[test]
    fn test_arch_registers() {
        assert!(!LuaJitArch.registers().is_empty());
    }
    #[test]
    fn test_arch_calling_conventions() {
        let convs = LuaJitArch.calling_conventions();
        assert!(!convs.is_empty());
        assert_eq!(convs[0].name, "luajit");
    }
    #[test]
    fn test_arch_disassemble() {
        let bytes = [0x4Bu8, 0x00, 0x00, 0x00];
        let instr = LuaJitArch.disassemble(Address::new(0), &bytes).unwrap();
        assert_eq!(instr.mnemonic, "RET0");
    }

    // ── LjUpvalue ────────────────────────────────────────────────────────────

    #[test]
    fn test_upvalue_display() {
        let uv = LjUpvalue {
            slot: 0,
            is_local: true,
            name: Some("_ENV".to_string()),
        };
        let s = uv.to_string();
        assert!(s.contains("upval[0]"));
        assert!(s.contains("_ENV"));
    }

    // ── UpvalInfo ────────────────────────────────────────────────────────────

    #[test]
    fn test_upval_info_from_raw_local() {
        let ui = UpvalInfo::from_raw(0x8005);
        assert!(ui.is_local);
        assert_eq!(ui.index, 5);
    }
    #[test]
    fn test_upval_info_from_raw_nonlocal() {
        let ui = UpvalInfo::from_raw(0x0003);
        assert!(!ui.is_local);
        assert_eq!(ui.index, 3);
    }
    #[test]
    fn test_upval_info_display() {
        let s = UpvalInfo::from_raw(0x8002).to_string();
        assert!(s.contains("local=true"));
    }

    // ── Opcode table ──────────────────────────────────────────────────────────

    #[test]
    fn test_opcode_table_not_empty() {
        assert!(!LJ_OPCODES.is_empty());
    }
    #[test]
    fn test_opcode_islt() {
        assert_eq!(LJ_OPCODES[0x00], "ISLT");
    }
    #[test]
    fn test_opcode_jmp() {
        assert_eq!(LJ_OPCODES[0x58], "JMP");
    }
    #[test]
    fn test_opcode_ret0() {
        assert_eq!(LJ_OPCODES[0x4B], "RET0");
    }
    #[test]
    fn test_opcode_funcc() {
        assert_eq!(LJ_OPCODES[0x5F], "FUNCC");
    }
    #[test]
    fn test_opcode_funccw() {
        assert_eq!(LJ_OPCODES[0x60], "FUNCCW");
    }
    #[test]
    fn test_opcode_kstr() {
        assert_eq!(LJ_OPCODES[0x27], "KSTR");
    }
    #[test]
    fn test_opcode_call() {
        assert_eq!(LJ_OPCODES[0x42], "CALL");
    }

    // ── LjModule ──────────────────────────────────────────────────────────────

    #[test]
    fn test_module_version() {
        assert_eq!(make_module().version(), LjVersion::Lj21);
    }
    #[test]
    fn test_module_is_stripped() {
        assert!(make_module().is_stripped());
    }
    #[test]
    fn test_module_is_not_big_endian() {
        assert!(!make_module().is_big_endian());
    }
    #[test]
    fn test_module_all_protos() {
        assert_eq!(make_module().all_protos().len(), 1);
    }
    #[test]
    fn test_module_total_instructions() {
        let m = make_module();
        assert_eq!(m.total_instructions(), m.root_proto.instructions.len());
    }
    #[test]
    fn test_module_string_constants() {
        let m = make_module();
        assert!(m.string_constants().iter().any(|s| s == "hello"));
    }
    #[test]
    fn test_module_source_name() {
        assert_eq!(make_module().source_name(), Some("@test.lua"));
    }
    #[test]
    fn test_module_display() {
        assert!(make_module().to_string().contains("LjModule"));
    }

    // ── LuaJitLoader ─────────────────────────────────────────────────────────

    #[test]
    fn test_luajitloader_can_load_true() {
        assert!(LuaJitLoader::can_load(&make_lj_stripped(2)));
    }
    #[test]
    fn test_luajitloader_can_load_false() {
        assert!(!LuaJitLoader::can_load(b"\x00\x01\x02"));
    }
    #[test]
    fn test_luajitloader_invalid_magic() {
        assert!(matches!(
            LuaJitLoader::load(b"\x00\x00\x00\x00").unwrap_err(),
            LjLoaderError::InvalidMagic
        ));
    }
    #[test]
    fn test_luajitloader_too_short() {
        assert!(matches!(
            LuaJitLoader::load(b"\x1b").unwrap_err(),
            LjLoaderError::TruncatedData
        ));
    }
    #[test]
    fn test_luajitloader_no_protos() {
        let mut data = make_lj_stripped(2);
        data.push(0x00);
        assert!(matches!(
            LuaJitLoader::load(&data).unwrap_err(),
            LjLoaderError::ParseError(_)
        ));
    }
    #[test]
    fn test_luajitloader_load_all_empty() {
        let mut data = make_lj_stripped(2);
        data.push(0x00);
        let bc = LuaJitLoader::load_all(&data).unwrap();
        assert!(bc.protos.is_empty());
    }

    // ── parse_proto / read_uleb128_mut ────────────────────────────────────────

    #[test]
    fn test_parse_proto_truncated() {
        let mut off = 0;
        assert!(matches!(
            parse_proto(b"\x00", &mut off, 0).unwrap_err(),
            LjLoaderError::TruncatedData
        ));
    }
    #[test]
    fn test_read_uleb128_mut_empty() {
        let mut off = 0;
        assert!(matches!(
            read_uleb128_mut(&[], &mut off).unwrap_err(),
            LjLoaderError::TruncatedData
        ));
    }

    // ── ProtoBuilder ─────────────────────────────────────────────────────────

    #[test]
    fn test_proto_builder_basic() {
        let p = ProtoBuilder::new()
            .params(2)
            .frame(8)
            .vararg()
            .add_instr(LjInstr(0x0000_004B))
            .add_kgc_str("test")
            .build();
        assert_eq!(p.num_params, 2);
        assert_eq!(p.frame_size, 8);
        assert!(p.is_vararg);
        assert_eq!(p.instruction_count, 1);
    }
    #[test]
    fn test_proto_builder_upvalue() {
        let p = ProtoBuilder::new()
            .add_upvalue(0, true, Some("_ENV".into()))
            .build();
        assert_eq!(p.num_upvalues, 1);
        assert_eq!(p.upvalue_names[0], "_ENV");
    }
    #[test]
    fn test_proto_builder_kn() {
        let p = ProtoBuilder::new().add_kn_int(42).build();
        assert_eq!(p.kn.len(), 1);
        assert_eq!(p.kn[0], KNumConst::Int(42));
    }

    // ── BytecodeEncoder ───────────────────────────────────────────────────────

    #[test]
    fn test_encoder_round_trip_header() {
        let proto = ProtoBuilder::new().add_instr(LjInstr(0x0000_004B)).build();
        let bytes = BytecodeEncoder::encode_stripped(LjVersion::Lj21, &proto);
        assert!(is_luajit(&bytes));
        let (hdr, _) = LjHeader::parse(&bytes).unwrap();
        assert_eq!(hdr.version, LjVersion::Lj21);
        assert!(hdr.flags.contains(LjFlags::STRIP));
    }
    #[test]
    fn test_encoder_parseable() {
        let proto = ProtoBuilder::new()
            .add_instr(LjInstr(0x0000_004B))
            .add_kgc_str("hello")
            .build();
        let bytes = BytecodeEncoder::encode_stripped(LjVersion::Lj21, &proto);
        let bc = LjBytecode::parse(&bytes).unwrap();
        assert_eq!(bc.protos.len(), 1);
        assert_eq!(bc.protos[0].instruction_count, 1);
    }

    // ── DebugInfo ─────────────────────────────────────────────────────────────

    #[test]
    fn test_debug_info_empty() {
        let d = DebugInfo::default();
        assert!(d.is_empty());
    }
    #[test]
    fn test_debug_info_source_line() {
        let d = DebugInfo {
            line_info: vec![10, 11, 12],
            ..Default::default()
        };
        assert_eq!(d.source_line_for_pc(1), Some(11));
        assert_eq!(d.source_line_for_pc(5), None);
    }
    #[test]
    fn test_debug_info_locals_at() {
        let d = DebugInfo {
            local_vars: vec![LjLocalVar {
                name: "x".into(),
                start_pc: 0,
                end_pc: 5,
            }],
            ..Default::default()
        };
        assert_eq!(d.locals_at(2).len(), 1);
        assert_eq!(d.locals_at(5).len(), 0);
    }

    // ── Disassembler ─────────────────────────────────────────────────────────

    #[test]
    fn test_disassembler_proto_length() {
        let p = LjProto::mock();
        assert_eq!(
            LjDisassembler::disassemble_proto(&p).len(),
            p.instructions.len()
        );
    }
    #[test]
    fn test_disassembler_contains_ret0() {
        let lines = LjDisassembler::disassemble_proto(&LjProto::mock());
        assert!(!lines.is_empty());
        assert!(lines[0].contains("RET0"), "got: {}", lines[0]);
    }
    #[test]
    fn test_disassembler_starts_with_index() {
        let lines = LjDisassembler::disassemble_proto(&LjProto::mock());
        assert!(lines[0].starts_with("0000"), "got: {}", lines[0]);
    }
    #[test]
    fn test_disassembler_all_contains_header() {
        assert!(LjDisassembler::disassemble_all(&make_module()).contains("; LuaJIT bytecode"));
    }
    #[test]
    fn test_disassembler_all_contains_proto_header() {
        assert!(LjDisassembler::disassemble_all(&make_module()).contains("; proto #0"));
    }
    #[test]
    fn test_disassembler_bytecode() {
        let mut data = make_lj_stripped(2);
        data.push(0x00);
        let bc = LjBytecode::parse(&data).unwrap();
        assert!(LjDisassembler::disassemble_bytecode(&bc).contains("; LuaJIT bytecode"));
    }
    #[test]
    fn test_disassembler_kpri_true() {
        let word = 0x2Bu32 | (2u32 << 16);
        let line = LjDisassembler::format_instr(0, LjInstr(word), &LjProto::mock());
        assert!(line.contains("true"), "got: {line}");
    }
    #[test]
    fn test_disassembler_kpri_nil() {
        let word = 0x2Bu32;
        let line = LjDisassembler::format_instr(0, LjInstr(word), &LjProto::mock());
        assert!(line.contains("nil"), "got: {line}");
    }
    #[test]
    fn test_disassembler_kshort_neg7() {
        let d: u16 = (0x8000u32 as i32 + (-7i32)) as u16;
        let b = (d >> 8) as u8;
        let c = (d & 0xFF) as u8;
        let word = 0x29u32 | ((c as u32) << 16) | ((b as u32) << 24);
        let line = LjDisassembler::format_instr(0, LjInstr(word), &LjProto::mock());
        assert!(line.contains("-7"), "got: {line}");
    }
}
