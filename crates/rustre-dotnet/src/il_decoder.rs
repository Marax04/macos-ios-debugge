//! .NET IL / CIL decoder.
//!
//! Decodes CIL method bodies: fat/tiny header, opcodes, operands, local variable
//! signatures, exception handler tables, and human-readable disassembly output.

pub use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors from the IL decoder.
#[derive(Debug)]
pub enum IlDecodeError {
    /// Buffer too small.
    TooSmall,
    /// Unknown opcode.
    UnknownOpcode(u8, Option<u8>),
    /// Truncated operand.
    TruncatedOperand {
        opcode: String,
        needed: usize,
        available: usize,
    },
    /// Invalid method header.
    InvalidHeader,
    /// Index out of range.
    IndexOutOfRange(String),
}

impl fmt::Display for IlDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall => write!(f, "buffer too small"),
            Self::UnknownOpcode(b1, b2) => {
                if let Some(b2) = b2 {
                    write!(f, "unknown opcode FE {b2:02X}")
                } else {
                    write!(f, "unknown opcode {b1:02X}")
                }
            }
            Self::TruncatedOperand {
                opcode,
                needed,
                available,
            } => {
                write!(
                    f,
                    "truncated operand for {opcode}: need {needed} have {available}"
                )
            }
            Self::InvalidHeader => write!(f, "invalid method body header"),
            Self::IndexOutOfRange(s) => write!(f, "index out of range: {s}"),
        }
    }
}

// ─── IlMethodHeader ──────────────────────────────────────────────────────────

/// The header of a CIL method body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IlMethodHeader {
    /// Tiny format: 1 byte header, no locals, max stack = 8.
    Tiny {
        /// Total size of the code in bytes.
        code_size: u32,
    },
    /// Fat format: 12 byte header.
    Fat {
        /// Header flags.
        flags: u16,
        /// Maximum stack depth.
        max_stack: u16,
        /// Size of the code in bytes.
        code_size: u32,
        /// `LocalVarSig` token (0 = no locals).
        local_var_sig_token: u32,
    },
}

impl IlMethodHeader {
    /// Return the code size.
    #[must_use]
    pub const fn code_size(&self) -> u32 {
        match self {
            Self::Tiny { code_size } | Self::Fat { code_size, .. } => *code_size,
        }
    }

    /// Return the maximum stack depth.
    #[must_use]
    pub const fn max_stack(&self) -> u16 {
        match self {
            Self::Tiny { .. } => 8,
            Self::Fat { max_stack, .. } => *max_stack,
        }
    }

    /// Return the local variable signature token (0 = no locals).
    #[must_use]
    pub const fn local_var_sig_token(&self) -> u32 {
        match self {
            Self::Tiny { .. } => 0,
            Self::Fat {
                local_var_sig_token,
                ..
            } => *local_var_sig_token,
        }
    }

    /// Return true if this has an exception handler table.
    #[must_use]
    pub fn has_more_sects(&self) -> bool {
        match self {
            Self::Tiny { .. } => false,
            Self::Fat { flags, .. } => flags & 0x08 != 0,
        }
    }

    /// Header size in bytes.
    #[must_use]
    pub const fn header_size(&self) -> usize {
        match self {
            Self::Tiny { .. } => 1,
            Self::Fat { .. } => 12,
        }
    }
}

// ─── ExHandlerKind ───────────────────────────────────────────────────────────

/// Exception clause type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExHandlerKind {
    Catch,
    Filter,
    Finally,
    Fault,
}

impl fmt::Display for ExHandlerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Catch => "catch",
            Self::Filter => "filter",
            Self::Finally => "finally",
            Self::Fault => "fault",
        };
        write!(f, "{s}")
    }
}

// ─── ExceptionHandler ────────────────────────────────────────────────────────

/// A CIL exception handler entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionHandler {
    pub kind: ExHandlerKind,
    /// Offset of the protected try block.
    pub try_offset: u32,
    /// Length of the try block.
    pub try_length: u32,
    /// Offset of the handler.
    pub handler_offset: u32,
    /// Length of the handler.
    pub handler_length: u32,
    /// Class token (Catch) or filter offset (Filter).
    pub class_token_or_filter: u32,
}

// ─── Opcode ──────────────────────────────────────────────────────────────────

/// CIL instruction opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Opcode {
    // Stack manipulation
    Nop,
    Break,
    Dup,
    Pop,
    Ret,
    // Load constants
    LdcI4M1,
    LdcI40,
    LdcI41,
    LdcI42,
    LdcI43,
    LdcI44,
    LdcI45,
    LdcI46,
    LdcI47,
    LdcI48,
    LdcI4S,
    LdcI4,
    LdcI8,
    LdcR4,
    LdcR8,
    LdNull,
    LdStr,
    // Load/store locals and args
    Ldarg0,
    Ldarg1,
    Ldarg2,
    Ldarg3,
    LdargS,
    Ldarg,
    Starg,
    StargS,
    Ldloc0,
    Ldloc1,
    Ldloc2,
    Ldloc3,
    LdlocS,
    Ldloc,
    Stloc0,
    Stloc1,
    Stloc2,
    Stloc3,
    StlocS,
    Stloc,
    LdlocaS,
    Ldloca,
    LdargaS,
    Ldarga,
    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    DivUn,
    Rem,
    RemUn,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    ShrUn,
    Neg,
    Not,
    AddOvf,
    AddOvfUn,
    MulOvf,
    MulOvfUn,
    SubOvf,
    SubOvfUn,
    // Comparisons
    Ceq,
    Cgt,
    CgtUn,
    Clt,
    CltUn,
    // Conversions
    ConvI1,
    ConvI2,
    ConvI4,
    ConvI8,
    ConvR4,
    ConvR8,
    ConvU1,
    ConvU2,
    ConvU4,
    ConvU8,
    ConvI,
    ConvU,
    ConvRUn,
    ConvOvfI1,
    ConvOvfI2,
    ConvOvfI4,
    ConvOvfI8,
    ConvOvfU1,
    ConvOvfU2,
    ConvOvfU4,
    ConvOvfU8,
    ConvOvfI,
    ConvOvfU,
    // Branches
    Br,
    BrS,
    Brtrue,
    BrtrueS,
    Brfalse,
    BrfalseS,
    Beq,
    BeqS,
    Bge,
    BgeS,
    BgeUn,
    BgeUnS,
    Bgt,
    BgtS,
    BgtUn,
    BgtUnS,
    Ble,
    BleS,
    BleUn,
    BleUnS,
    Blt,
    BltS,
    BltUn,
    BltUnS,
    Bne,
    BneUnS,
    Switch,
    // Object model
    Newobj,
    Newarr,
    Initobj,
    Castclass,
    Isinst,
    Box,
    Unbox,
    UnboxAny,
    Ldobj,
    Stobj,
    Sizeof,
    // Fields
    Ldfld,
    Ldflda,
    Stfld,
    Ldsfld,
    Ldsflda,
    Stsfld,
    // Methods
    Call,
    Callvirt,
    Calli,
    Ldftn,
    Ldvirtftn,
    Jmp,
    Tailcall,
    // Arrays
    Ldelem,
    Stelem,
    LdelemI1,
    LdelemU1,
    LdelemI2,
    LdelemU2,
    LdelemI4,
    LdelemU4,
    LdelemI8,
    LdelemU8,
    LdelemR4,
    LdelemR8,
    LdelemRef,
    LdelemI,
    StelemI,
    StelemI1,
    StelemI2,
    StelemI4,
    StelemI8,
    StelemR4,
    StelemR8,
    StelemRef,
    // Indirect loads/stores
    LdindI1,
    LdindU1,
    LdindI2,
    LdindU2,
    LdindI4,
    LdindU4,
    LdindI8,
    LdindI,
    LdindR4,
    LdindR8,
    LdindRef,
    StindRef,
    StindI1,
    StindI2,
    StindI4,
    StindI8,
    StindR4,
    StindR8,
    // Misc
    Localloc,
    Throw,
    Rethrow,
    Endfilter,
    Endfinally,
    Leave,
    LeaveS,
    Ldlen,
    Ldtoken,
    // Extended (0xFE prefix)
    Arglist,
    Ckfinite,
    Readonly,
    RefanyType,
    RefanyVal,
    Mkrefany,
    Volatile,
    Unaligned,
    Constrained,
    Cpblk,
    Initblk,
    No,
    // Unknown
    Unknown(u16),
}

impl Opcode {
    // First third: push/pop/load/store and arithmetic through ShrUn.
    fn opcode_str_a(op: Self) -> &'static str {
        match op {
            Self::Nop    => "nop",     Self::Break  => "break",
            Self::Dup    => "dup",     Self::Pop    => "pop",
            Self::Ret    => "ret",
            Self::LdcI4M1 => "ldc.i4.m1",
            Self::LdcI40 => "ldc.i4.0", Self::LdcI41 => "ldc.i4.1",
            Self::LdcI42 => "ldc.i4.2", Self::LdcI43 => "ldc.i4.3",
            Self::LdcI44 => "ldc.i4.4", Self::LdcI45 => "ldc.i4.5",
            Self::LdcI46 => "ldc.i4.6", Self::LdcI47 => "ldc.i4.7",
            Self::LdcI48 => "ldc.i4.8", Self::LdcI4S => "ldc.i4.s",
            Self::LdcI4  => "ldc.i4",   Self::LdcI8  => "ldc.i8",
            Self::LdcR4  => "ldc.r4",   Self::LdcR8  => "ldc.r8",
            Self::LdNull => "ldnull",   Self::LdStr  => "ldstr",
            Self::Ldarg0 => "ldarg.0",  Self::Ldarg1 => "ldarg.1",
            Self::Ldarg2 => "ldarg.2",  Self::Ldarg3 => "ldarg.3",
            Self::LdargS => "ldarg.s",  Self::Ldarg  => "ldarg",
            Self::Starg  => "starg",    Self::StargS => "starg.s",
            Self::Ldloc0 => "ldloc.0",  Self::Ldloc1 => "ldloc.1",
            Self::Ldloc2 => "ldloc.2",  Self::Ldloc3 => "ldloc.3",
            Self::LdlocS => "ldloc.s",  Self::Ldloc  => "ldloc",
            Self::Stloc0 => "stloc.0",  Self::Stloc1 => "stloc.1",
            Self::Stloc2 => "stloc.2",  Self::Stloc3 => "stloc.3",
            Self::StlocS => "stloc.s",  Self::Stloc  => "stloc",
            Self::LdlocaS=> "ldloca.s", Self::Ldloca => "ldloca",
            Self::LdargaS=> "ldarga.s", Self::Ldarga => "ldarga",
            Self::Add    => "add",  Self::Sub   => "sub",
            Self::Mul    => "mul",  Self::Div   => "div",
            Self::DivUn  => "div.un", Self::Rem => "rem",
            Self::RemUn  => "rem.un",  Self::And => "and",
            Self::Or     => "or",  Self::Xor   => "xor",
            Self::Shl    => "shl", Self::Shr   => "shr",
            Self::ShrUn  => "shr.un",
            _ => Self::opcode_str_b(op),
        }
    }

    // Second third: conv/overflow-arith/branches/switch.
    fn opcode_str_b(op: Self) -> &'static str {
        match op {
            Self::Neg    => "neg",     Self::Not    => "not",
            Self::AddOvf => "add.ovf", Self::AddOvfUn => "add.ovf.un",
            Self::MulOvf => "mul.ovf", Self::MulOvfUn => "mul.ovf.un",
            Self::SubOvf => "sub.ovf", Self::SubOvfUn => "sub.ovf.un",
            Self::Ceq => "ceq",  Self::Cgt => "cgt",  Self::CgtUn => "cgt.un",
            Self::Clt => "clt",  Self::CltUn => "clt.un",
            Self::ConvI1 => "conv.i1", Self::ConvI2 => "conv.i2",
            Self::ConvI4 => "conv.i4", Self::ConvI8 => "conv.i8",
            Self::ConvR4 => "conv.r4", Self::ConvR8 => "conv.r8",
            Self::ConvU1 => "conv.u1", Self::ConvU2 => "conv.u2",
            Self::ConvU4 => "conv.u4", Self::ConvU8 => "conv.u8",
            Self::ConvI  => "conv.i",  Self::ConvU  => "conv.u",
            Self::ConvRUn => "conv.r.un",
            Self::ConvOvfI1 => "conv.ovf.i1", Self::ConvOvfI2 => "conv.ovf.i2",
            Self::ConvOvfI4 => "conv.ovf.i4", Self::ConvOvfI8 => "conv.ovf.i8",
            Self::ConvOvfU1 => "conv.ovf.u1", Self::ConvOvfU2 => "conv.ovf.u2",
            Self::ConvOvfU4 => "conv.ovf.u4", Self::ConvOvfU8 => "conv.ovf.u8",
            Self::ConvOvfI  => "conv.ovf.i",  Self::ConvOvfU  => "conv.ovf.u",
            Self::Br  => "br",      Self::BrS  => "br.s",
            Self::Brtrue  => "brtrue",   Self::BrtrueS  => "brtrue.s",
            Self::Brfalse => "brfalse",  Self::BrfalseS => "brfalse.s",
            Self::Beq  => "beq",    Self::BeqS  => "beq.s",
            Self::Bge  => "bge",    Self::BgeS  => "bge.s",
            Self::BgeUn => "bge.un", Self::BgeUnS => "bge.un.s",
            Self::Bgt  => "bgt",    Self::BgtS  => "bgt.s",
            Self::BgtUn => "bgt.un", Self::BgtUnS => "bgt.un.s",
            Self::Ble  => "ble",    Self::BleS  => "ble.s",
            Self::BleUn => "ble.un", Self::BleUnS => "ble.un.s",
            Self::Blt  => "blt",    Self::BltS  => "blt.s",
            Self::BltUn => "blt.un", Self::BltUnS => "blt.un.s",
            Self::Bne  => "bne.un", Self::BneUnS => "bne.un.s",
            Self::Switch => "switch",
            _ => Self::opcode_str_c(op),
        }
    }

    // Third third: object/array/indirect/prefix opcodes.
    fn opcode_str_c(op: Self) -> &'static str {
        match op {
            Self::Newobj    => "newobj",   Self::Newarr    => "newarr",
            Self::Initobj   => "initobj",  Self::Castclass => "castclass",
            Self::Isinst    => "isinst",   Self::Box       => "box",
            Self::Unbox     => "unbox",    Self::UnboxAny  => "unbox.any",
            Self::Ldobj     => "ldobj",    Self::Stobj     => "stobj",
            Self::Sizeof    => "sizeof",   Self::Ldfld     => "ldfld",
            Self::Ldflda    => "ldflda",   Self::Stfld     => "stfld",
            Self::Ldsfld    => "ldsfld",   Self::Ldsflda   => "ldsflda",
            Self::Stsfld    => "stsfld",   Self::Call      => "call",
            Self::Callvirt  => "callvirt", Self::Calli     => "calli",
            Self::Ldftn     => "ldftn",    Self::Ldvirtftn => "ldvirtftn",
            Self::Jmp       => "jmp",      Self::Tailcall  => "tail.",
            Self::Ldlen     => "ldlen",    Self::Ldtoken   => "ldtoken",
            Self::Localloc  => "localloc", Self::Throw     => "throw",
            Self::Rethrow   => "rethrow",  Self::Endfilter => "endfilter",
            Self::Endfinally=> "endfinally", Self::Leave   => "leave",
            Self::LeaveS    => "leave.s",  Self::Ldelem    => "ldelem",
            Self::Stelem    => "stelem",
            Self::LdelemI1  => "ldelem.i1", Self::LdelemU1 => "ldelem.u1",
            Self::LdelemI2  => "ldelem.i2", Self::LdelemU2 => "ldelem.u2",
            Self::LdelemI4  => "ldelem.i4", Self::LdelemU4 => "ldelem.u4",
            Self::LdelemI8  => "ldelem.i8", Self::LdelemU8 => "ldelem.u8",
            Self::LdelemR4  => "ldelem.r4", Self::LdelemR8 => "ldelem.r8",
            Self::LdelemRef => "ldelem.ref", Self::LdelemI => "ldelem.i",
            Self::StelemI   => "stelem.i",  Self::StelemI1 => "stelem.i1",
            Self::StelemI2  => "stelem.i2", Self::StelemI4 => "stelem.i4",
            Self::StelemI8  => "stelem.i8", Self::StelemR4 => "stelem.r4",
            Self::StelemR8  => "stelem.r8", Self::StelemRef=> "stelem.ref",
            Self::LdindI1   => "ldind.i1",  Self::LdindU1  => "ldind.u1",
            Self::LdindI2   => "ldind.i2",  Self::LdindU2  => "ldind.u2",
            Self::LdindI4   => "ldind.i4",  Self::LdindU4  => "ldind.u4",
            Self::LdindI8   => "ldind.i8",  Self::LdindI   => "ldind.i",
            Self::LdindR4   => "ldind.r4",  Self::LdindR8  => "ldind.r8",
            Self::LdindRef  => "ldind.ref", Self::StindRef => "stind.ref",
            Self::StindI1   => "stind.i1",  Self::StindI2  => "stind.i2",
            Self::StindI4   => "stind.i4",  Self::StindI8  => "stind.i8",
            Self::StindR4   => "stind.r4",  Self::StindR8  => "stind.r8",
            Self::Arglist    => "arglist",   Self::Ckfinite => "ckfinite",
            Self::Readonly   => "readonly.", Self::RefanyType => "refanytype",
            Self::RefanyVal  => "refanyval", Self::Mkrefany => "mkrefany",
            Self::Volatile   => "volatile.", Self::Unaligned => "unaligned.",
            Self::Constrained=> "constrained.", Self::Cpblk => "cpblk",
            Self::Initblk    => "initblk",  Self::No       => "no.",
            // Unknown is handled in fmt directly — should not reach here.
            _ => unreachable!(),
        }
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Self::Unknown(v) = self {
            return write!(f, "unknown({v:#06x})");
        }
        write!(f, "{}", Self::opcode_str_a(*self))
    }
}

// ─── CilOperand (re-export flavor for this module) ────────────────────────────

/// Operand of a CIL instruction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IlOperand {
    None,
    Int8(i8),
    Int32(i32),
    Int64(i64),
    Float32(f32),
    Float64(f64),
    Token(u32),
    Branch(i32),
    BranchTargetAbs(u32), // resolved absolute offset
    Switch(Vec<i32>),
    String(String),
}

impl fmt::Display for IlOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => Ok(()),
            Self::Int8(v) => write!(f, "{v}"),
            Self::Int32(v) => write!(f, "{v}"),
            Self::Int64(v) => write!(f, "{v}L"),
            Self::Float32(v) => write!(f, "{v}"),
            Self::Float64(v) => write!(f, "{v}"),
            Self::Token(t) => write!(f, "[{t:#010x}]"),
            Self::Branch(d) => write!(f, "{d:+}"),
            Self::BranchTargetAbs(a) => write!(f, "IL_{a:04X}"),
            Self::Switch(targets) => {
                write!(f, "(")?;
                for (i, t) in targets.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{t:+}")?;
                }
                write!(f, ")")
            }
            Self::String(s) => write!(f, "\"{s}\""),
        }
    }
}

// ─── CilInstruction ──────────────────────────────────────────────────────────

/// A decoded CIL instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CilInstruction {
    /// Byte offset from the start of the method body.
    pub offset: u32,
    /// Opcode.
    pub opcode: Opcode,
    /// Operand.
    pub operand: IlOperand,
    /// Total instruction size in bytes (opcode + operand).
    pub size: u32,
}

impl CilInstruction {
    /// Format as a disassembly line.
    #[must_use]
    pub fn to_disasm_line(&self) -> String {
        let op_str = self.operand.to_string();
        if op_str.is_empty() {
            format!("IL_{:04X}:  {}", self.offset, self.opcode)
        } else {
            format!("IL_{:04X}:  {} {}", self.offset, self.opcode, op_str)
        }
    }
}

// ─── IlDecoder ───────────────────────────────────────────────────────────────

/// CIL method body decoder.
pub struct IlDecoder {
    /// Whether to resolve relative branch offsets to absolute IL offsets.
    pub resolve_branches: bool,
}

// ─── Low-level byte-slice read helpers ───────────────────────────────────────
// These are free functions so they can be shared across the two decode_opcode
// halves without capturing any environment.

fn il_read_i8(data: &[u8], len: usize, p: usize) -> Result<i8, IlDecodeError> {
    if p >= len { Err(IlDecodeError::TooSmall) } else { Ok(data[p].cast_signed()) }
}
fn il_read_i16(data: &[u8], len: usize, p: usize) -> Result<i16, IlDecodeError> {
    if p + 2 > len { Err(IlDecodeError::TooSmall) } else { Ok(i16::from_le_bytes([data[p], data[p + 1]])) }
}
fn il_read_i32(data: &[u8], len: usize, p: usize) -> Result<i32, IlDecodeError> {
    let lo = u32::from((il_read_i16(data, len, p)?).cast_unsigned());
    let hi = u32::from((il_read_i16(data, len, p + 2)?).cast_unsigned());
    Ok(((hi << 16) | lo).cast_signed())
}
fn il_read_dword(data: &[u8], len: usize, p: usize) -> Result<u32, IlDecodeError> {
    if p + 4 > len { Err(IlDecodeError::TooSmall) }
    else { Ok(u32::from_le_bytes([data[p], data[p+1], data[p+2], data[p+3]])) }
}
fn il_read_i64(data: &[u8], len: usize, p: usize) -> Result<i64, IlDecodeError> {
    if p + 8 > len { Err(IlDecodeError::TooSmall) }
    else { Ok(i64::from_le_bytes(data[p..p + 8].try_into().unwrap())) }
}
fn il_read_float(data: &[u8], len: usize, p: usize) -> Result<f32, IlDecodeError> {
    Ok(f32::from_le_bytes(il_read_dword(data, len, p)?.to_le_bytes()))
}
fn il_read_double(data: &[u8], len: usize, p: usize) -> Result<f64, IlDecodeError> {
    Ok(f64::from_le_bytes(il_read_i64(data, len, p)?.to_le_bytes()))
}

impl IlDecoder {
    /// Create a new decoder with branch resolution enabled.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            resolve_branches: true,
        }
    }

    /// Parse the method header from `data` starting at `offset`.
    /// # Errors
    /// Returns an error when the operation fails.
    pub fn parse_header(
        &self,
        data: &[u8],
        offset: usize,
    ) -> Result<IlMethodHeader, IlDecodeError> {
        if offset >= data.len() {
            return Err(IlDecodeError::TooSmall);
        }
        let b = data[offset];
        if b & 0x03 == 0x02 {
            // Tiny header: bits [7:2] = code size
            let code_size = u32::from(b >> 2);
            Ok(IlMethodHeader::Tiny { code_size })
        } else if b & 0x07 == 0x03 {
            // Fat header: 12 bytes
            if offset + 12 > data.len() {
                return Err(IlDecodeError::TooSmall);
            }
            let flags_size = u16::from_le_bytes([data[offset], data[offset + 1]]);
            let flags = flags_size & 0x0FFF;
            let header_size = usize::from(flags_size >> 12) * 4;
            // Re-validate using the actual header size from flags (per ECMA-335 §II.25.4.3).
            if header_size > 0 && offset + header_size > data.len() {
                return Err(IlDecodeError::TooSmall);
            }
            let max_stack = u16::from_le_bytes([data[offset + 2], data[offset + 3]]);
            let code_size = u32::from_le_bytes([
                data[offset + 4],
                data[offset + 5],
                data[offset + 6],
                data[offset + 7],
            ]);
            let local_var_sig_token = u32::from_le_bytes([
                data[offset + 8],
                data[offset + 9],
                data[offset + 10],
                data[offset + 11],
            ]);
            Ok(IlMethodHeader::Fat {
                flags,
                max_stack,
                code_size,
                local_var_sig_token,
            })
        } else {
            Err(IlDecodeError::InvalidHeader)
        }
    }

    /// Decode all instructions from `code_bytes`.
    /// # Errors
    /// Returns an error when the operation fails.
    pub fn decode_instructions(
        &self,
        code_bytes: &[u8],
    ) -> Result<Vec<CilInstruction>, IlDecodeError> {
        let mut instructions = Vec::new();
        let mut pos = 0usize;
        let len = code_bytes.len();

        while pos < len {
            let abs_offset = u32::try_from(pos).unwrap_or(u32::MAX);
            let b = code_bytes[pos];
            pos += 1;

            let (opcode, mut operand, extra) = if b == 0xFE {
                // Two-byte opcode
                if pos >= len {
                    return Err(IlDecodeError::TooSmall);
                }
                let b2 = code_bytes[pos];
                pos += 1;
                Self::decode_fe_opcode(b2, code_bytes, pos, len)?
            } else {
                Self::decode_opcode(b, code_bytes, pos, len, abs_offset)?
            };

            pos += extra;

            // Resolve branch targets
            if self.resolve_branches
                && let IlOperand::Branch(delta) = &operand {
                    let extra_i64 = i64::try_from(extra).unwrap_or(i64::MAX);
                    let raw = i64::from(abs_offset) + 1 + extra_i64 + i64::from(*delta);
                    let target = u32::try_from(raw).unwrap_or(u32::MAX);
                    operand = IlOperand::BranchTargetAbs(target);
                }

            let size = u32::try_from(pos).unwrap_or(u32::MAX) - abs_offset;
            instructions.push(CilInstruction {
                offset: abs_offset,
                opcode,
                operand,
                size,
            });
        }

        Ok(instructions)
    }

    // Load/store/push and short-branch opcodes (0x00–0x44).
    fn decode_opcode(
        b: u8,
        data: &[u8],
        pos: usize,
        len: usize,
        _abs: u32,
    ) -> Result<(Opcode, IlOperand, usize), IlDecodeError> {
        match b {
            0x00 => Ok((Opcode::Nop,     IlOperand::None, 0)),
            0x01 => Ok((Opcode::Break,   IlOperand::None, 0)),
            0x02 => Ok((Opcode::Ldarg0,  IlOperand::None, 0)),
            0x03 => Ok((Opcode::Ldarg1,  IlOperand::None, 0)),
            0x04 => Ok((Opcode::Ldarg2,  IlOperand::None, 0)),
            0x05 => Ok((Opcode::Ldarg3,  IlOperand::None, 0)),
            0x06 => Ok((Opcode::Ldloc0,  IlOperand::None, 0)),
            0x07 => Ok((Opcode::Ldloc1,  IlOperand::None, 0)),
            0x08 => Ok((Opcode::Ldloc2,  IlOperand::None, 0)),
            0x09 => Ok((Opcode::Ldloc3,  IlOperand::None, 0)),
            0x0A => Ok((Opcode::Stloc0,  IlOperand::None, 0)),
            0x0B => Ok((Opcode::Stloc1,  IlOperand::None, 0)),
            0x0C => Ok((Opcode::Stloc2,  IlOperand::None, 0)),
            0x0D => Ok((Opcode::Stloc3,  IlOperand::None, 0)),
            0x0E => Ok((Opcode::LdargS,  IlOperand::Int8(il_read_i8(data, len, pos)?), 1)),
            0x10 => Ok((Opcode::StargS,  IlOperand::Int8(il_read_i8(data, len, pos)?), 1)),
            0x11 => Ok((Opcode::LdlocS,  IlOperand::Int8(il_read_i8(data, len, pos)?), 1)),
            0x12 => Ok((Opcode::LdlocaS, IlOperand::Int8(il_read_i8(data, len, pos)?), 1)),
            0x13 => Ok((Opcode::StlocS,  IlOperand::Int8(il_read_i8(data, len, pos)?), 1)),
            0x14 => Ok((Opcode::LdNull,  IlOperand::None, 0)),
            0x15 => Ok((Opcode::LdcI4M1, IlOperand::None, 0)),
            0x16 => Ok((Opcode::LdcI40,  IlOperand::None, 0)),
            0x17 => Ok((Opcode::LdcI41,  IlOperand::None, 0)),
            0x18 => Ok((Opcode::LdcI42,  IlOperand::None, 0)),
            0x19 => Ok((Opcode::LdcI43,  IlOperand::None, 0)),
            0x1A => Ok((Opcode::LdcI44,  IlOperand::None, 0)),
            0x1B => Ok((Opcode::LdcI45,  IlOperand::None, 0)),
            0x1C => Ok((Opcode::LdcI46,  IlOperand::None, 0)),
            0x1D => Ok((Opcode::LdcI47,  IlOperand::None, 0)),
            0x1E => Ok((Opcode::LdcI48,  IlOperand::None, 0)),
            0x1F => Ok((Opcode::LdcI4S,  IlOperand::Int8(il_read_i8(data, len, pos)?), 1)),
            0x20 => Ok((Opcode::LdcI4,   IlOperand::Int32(il_read_i32(data, len, pos)?), 4)),
            0x21 => Ok((Opcode::LdcI8,   IlOperand::Int64(il_read_i64(data, len, pos)?), 8)),
            0x22 => Ok((Opcode::LdcR4,   IlOperand::Float32(il_read_float(data, len, pos)?), 4)),
            0x23 => Ok((Opcode::LdcR8,   IlOperand::Float64(il_read_double(data, len, pos)?), 8)),
            0x25 => Ok((Opcode::Dup,     IlOperand::None, 0)),
            0x26 => Ok((Opcode::Pop,     IlOperand::None, 0)),
            0x27 => Ok((Opcode::Jmp,     IlOperand::Token(il_read_dword(data, len, pos)?), 4)),
            0x28 => Ok((Opcode::Call,    IlOperand::Token(il_read_dword(data, len, pos)?), 4)),
            0x29 => Ok((Opcode::Calli,   IlOperand::Token(il_read_dword(data, len, pos)?), 4)),
            0x2A => Ok((Opcode::Ret,     IlOperand::None, 0)),
            0x2B => Ok((Opcode::BrS,     IlOperand::Branch(i32::from(il_read_i8(data, len, pos)?)), 1)),
            0x2C => Ok((Opcode::BrfalseS,IlOperand::Branch(i32::from(il_read_i8(data, len, pos)?)), 1)),
            0x2D => Ok((Opcode::BrtrueS, IlOperand::Branch(i32::from(il_read_i8(data, len, pos)?)), 1)),
            0x2E => Ok((Opcode::BeqS,    IlOperand::Branch(i32::from(il_read_i8(data, len, pos)?)), 1)),
            0x2F => Ok((Opcode::BgeS,    IlOperand::Branch(i32::from(il_read_i8(data, len, pos)?)), 1)),
            0x30 => Ok((Opcode::BgtS,    IlOperand::Branch(i32::from(il_read_i8(data, len, pos)?)), 1)),
            0x31 => Ok((Opcode::BleS,    IlOperand::Branch(i32::from(il_read_i8(data, len, pos)?)), 1)),
            0x32 => Ok((Opcode::BltS,    IlOperand::Branch(i32::from(il_read_i8(data, len, pos)?)), 1)),
            0x33 => Ok((Opcode::BneUnS,  IlOperand::Branch(i32::from(il_read_i8(data, len, pos)?)), 1)),
            0x34 => Ok((Opcode::BgeUnS,  IlOperand::Branch(i32::from(il_read_i8(data, len, pos)?)), 1)),
            0x35 => Ok((Opcode::BgtUnS,  IlOperand::Branch(i32::from(il_read_i8(data, len, pos)?)), 1)),
            0x36 => Ok((Opcode::BleUnS,  IlOperand::Branch(i32::from(il_read_i8(data, len, pos)?)), 1)),
            0x37 => Ok((Opcode::BltUnS,  IlOperand::Branch(i32::from(il_read_i8(data, len, pos)?)), 1)),
            0x38 => Ok((Opcode::Br,      IlOperand::Branch(il_read_i32(data, len, pos)?), 4)),
            0x39 => Ok((Opcode::Brfalse, IlOperand::Branch(il_read_i32(data, len, pos)?), 4)),
            0x3A => Ok((Opcode::Brtrue,  IlOperand::Branch(il_read_i32(data, len, pos)?), 4)),
            0x3B => Ok((Opcode::Beq,     IlOperand::Branch(il_read_i32(data, len, pos)?), 4)),
            0x3C => Ok((Opcode::Bge,     IlOperand::Branch(il_read_i32(data, len, pos)?), 4)),
            0x3D => Ok((Opcode::Bgt,     IlOperand::Branch(il_read_i32(data, len, pos)?), 4)),
            0x3E => Ok((Opcode::Ble,     IlOperand::Branch(il_read_i32(data, len, pos)?), 4)),
            0x3F => Ok((Opcode::Blt,     IlOperand::Branch(il_read_i32(data, len, pos)?), 4)),
            0x40 => Ok((Opcode::Bne,     IlOperand::Branch(il_read_i32(data, len, pos)?), 4)),
            0x41 => Ok((Opcode::BgeUn,   IlOperand::Branch(il_read_i32(data, len, pos)?), 4)),
            0x42 => Ok((Opcode::BgtUn,   IlOperand::Branch(il_read_i32(data, len, pos)?), 4)),
            0x43 => Ok((Opcode::BleUn,   IlOperand::Branch(il_read_i32(data, len, pos)?), 4)),
            0x44 => Ok((Opcode::BltUn,   IlOperand::Branch(il_read_i32(data, len, pos)?), 4)),
            _ => Self::decode_opcode_hi(b, data, pos, len),
        }
    }

    // Switch, arithmetic, token, and leave opcodes (0x45 and above).
    fn decode_opcode_hi(
        b: u8,
        data: &[u8],
        pos: usize,
        len: usize,
    ) -> Result<(Opcode, IlOperand, usize), IlDecodeError> {
        match b {
            0x45 => {
                // switch: count (u32) + count * i32 targets
                let count_u32 = il_read_dword(data, len, pos)?;
                // Validate that count * 4 bytes are actually available before
                // allocating; prevents OOM from an adversarially large count field.
                let count_bytes = u64::from(count_u32).saturating_mul(4);
                let available = u64::try_from(len).unwrap_or(u64::MAX)
                    .saturating_sub(u64::try_from(pos).unwrap_or(u64::MAX).saturating_add(4));
                if count_bytes > available {
                    return Err(IlDecodeError::TooSmall);
                }
                let count = usize::try_from(count_u32).unwrap_or(usize::MAX);
                let extra = 4usize.saturating_add(count.saturating_mul(4));
                if pos + extra > len {
                    return Err(IlDecodeError::TooSmall);
                }
                let mut targets = Vec::with_capacity(count);
                for i in 0..count {
                    targets.push(i32::from_le_bytes([
                        data[pos + 4 + i * 4],
                        data[pos + 4 + i * 4 + 1],
                        data[pos + 4 + i * 4 + 2],
                        data[pos + 4 + i * 4 + 3],
                    ]));
                }
                Ok((Opcode::Switch, IlOperand::Switch(targets), extra))
            }
            0x58 => Ok((Opcode::Add,       IlOperand::None, 0)),
            0x59 => Ok((Opcode::Sub,       IlOperand::None, 0)),
            0x5A => Ok((Opcode::Mul,       IlOperand::None, 0)),
            0x5B => Ok((Opcode::Div,       IlOperand::None, 0)),
            0x5D => Ok((Opcode::Rem,       IlOperand::None, 0)),
            0x5F => Ok((Opcode::And,       IlOperand::None, 0)),
            0x60 => Ok((Opcode::Or,        IlOperand::None, 0)),
            0x61 => Ok((Opcode::Xor,       IlOperand::None, 0)),
            0x62 => Ok((Opcode::Shl,       IlOperand::None, 0)),
            0x63 => Ok((Opcode::Shr,       IlOperand::None, 0)),
            0x65 => Ok((Opcode::Neg,       IlOperand::None, 0)),
            0x66 => Ok((Opcode::Not,       IlOperand::None, 0)),
            0x6F => Ok((Opcode::Callvirt,  IlOperand::Token(il_read_dword(data, len, pos)?), 4)),
            0x72 => Ok((Opcode::LdStr,     IlOperand::Token(il_read_dword(data, len, pos)?), 4)),
            0x73 => Ok((Opcode::Newobj,    IlOperand::Token(il_read_dword(data, len, pos)?), 4)),
            0x74 => Ok((Opcode::Castclass, IlOperand::Token(il_read_dword(data, len, pos)?), 4)),
            0x75 => Ok((Opcode::Isinst,    IlOperand::Token(il_read_dword(data, len, pos)?), 4)),
            0x7B => Ok((Opcode::Ldfld,     IlOperand::Token(il_read_dword(data, len, pos)?), 4)),
            0x7C => Ok((Opcode::Ldflda,    IlOperand::Token(il_read_dword(data, len, pos)?), 4)),
            0x7D => Ok((Opcode::Stfld,     IlOperand::Token(il_read_dword(data, len, pos)?), 4)),
            0x7E => Ok((Opcode::Ldsfld,    IlOperand::Token(il_read_dword(data, len, pos)?), 4)),
            0x80 => Ok((Opcode::Stsfld,    IlOperand::Token(il_read_dword(data, len, pos)?), 4)),
            0xD0 => Ok((Opcode::Ldtoken,   IlOperand::Token(il_read_dword(data, len, pos)?), 4)),
            0xDC => Ok((Opcode::Endfinally, IlOperand::None, 0)),
            0xDE => Ok((Opcode::Leave,     IlOperand::Branch(il_read_i32(data, len, pos)?), 4)),
            0xDF => Ok((Opcode::LeaveS,    IlOperand::Branch(i32::from(il_read_i8(data, len, pos)?)), 1)),
            _ => Ok((Opcode::Unknown(u16::from(b)), IlOperand::None, 0)),
        }
    }

    fn decode_fe_opcode(
        b2: u8,
        data: &[u8],
        pos: usize,
        len: usize,
    ) -> Result<(Opcode, IlOperand, usize), IlDecodeError> {
        match b2 {
            0x01 => Ok((Opcode::Ceq,   IlOperand::None, 0)),
            0x02 => Ok((Opcode::Cgt,   IlOperand::None, 0)),
            0x03 => Ok((Opcode::CgtUn, IlOperand::None, 0)),
            0x04 => Ok((Opcode::Clt,   IlOperand::None, 0)),
            0x05 => Ok((Opcode::CltUn, IlOperand::None, 0)),
            // ldarg / ldarga / starg / ldloc / ldloca / stloc with u16 (decoded as i16) index
            0x09 => Ok((Opcode::Ldarg,  IlOperand::Int32(i32::from(il_read_i16(data, len, pos)?)), 2)),
            0x0A => Ok((Opcode::Ldarga, IlOperand::Int32(i32::from(il_read_i16(data, len, pos)?)), 2)),
            0x0B => Ok((Opcode::Starg,  IlOperand::Int32(i32::from(il_read_i16(data, len, pos)?)), 2)),
            0x0C => Ok((Opcode::Ldloc,  IlOperand::Int32(i32::from(il_read_i16(data, len, pos)?)), 2)),
            0x0D => Ok((Opcode::Ldloca, IlOperand::Int32(i32::from(il_read_i16(data, len, pos)?)), 2)),
            0x0E => Ok((Opcode::Stloc,  IlOperand::Int32(i32::from(il_read_i16(data, len, pos)?)), 2)),
            _ => Ok((Opcode::Unknown(0xFE00 | u16::from(b2)), IlOperand::None, 0)),
        }
    }
}

impl Default for IlDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── IlDisassembler ──────────────────────────────────────────────────────────

/// Produces human-readable CIL disassembly text from decoded instructions.
pub struct IlDisassembler;

impl IlDisassembler {
    /// Format a list of decoded instructions as a text listing.
    #[must_use]
    pub fn disassemble(instructions: &[CilInstruction]) -> String {
        let mut out = String::new();
        for insn in instructions {
            out.push_str(&insn.to_disasm_line());
            out.push('\n');
        }
        out
    }

    /// Return instructions that match an opcode filter.
    #[must_use]
    pub fn filter_by_opcode(
        instructions: &[CilInstruction],
        opcode: Opcode,
    ) -> Vec<&CilInstruction> {
        instructions.iter().filter(|i| i.opcode == opcode).collect()
    }

    /// Return all call/callvirt instructions (useful for call graph).
    #[must_use]
    pub fn find_calls(instructions: &[CilInstruction]) -> Vec<&CilInstruction> {
        instructions
            .iter()
            .filter(|i| matches!(i.opcode, Opcode::Call | Opcode::Callvirt))
            .collect()
    }

    /// Return all string load instructions.
    #[must_use]
    pub fn find_string_loads(instructions: &[CilInstruction]) -> Vec<&CilInstruction> {
        instructions
            .iter()
            .filter(|i| i.opcode == Opcode::LdStr)
            .collect()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_tiny_header() {
        let decoder = IlDecoder::new();
        // Tiny header: 0x02 | (code_size << 2)
        // code_size = 4 → 0x02 | (4 << 2) = 0x12
        let data = [0x12u8];
        let hdr = decoder.parse_header(&data, 0).unwrap();
        assert!(matches!(hdr, IlMethodHeader::Tiny { code_size: 4 }));
    }

    #[test]
    fn test_decode_fat_header() {
        let decoder = IlDecoder::new();
        // Fat: flags = 0x3013 (MoreSects|FatFormat|InitLocals, size=3), max_stack=8, code=0x10, lvsig=0
        let data: Vec<u8> = vec![
            0x13, 0x30, 0x08, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let hdr = decoder.parse_header(&data, 0).unwrap();
        if let IlMethodHeader::Fat {
            max_stack,
            code_size,
            ..
        } = hdr
        {
            assert_eq!(max_stack, 8);
            assert_eq!(code_size, 0x10);
        } else {
            panic!("expected fat header");
        }
    }

    #[test]
    fn test_decode_nop() {
        let decoder = IlDecoder::new();
        let code = vec![0x00u8];
        let insns = decoder.decode_instructions(&code).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].opcode, Opcode::Nop);
    }

    #[test]
    fn test_decode_ret() {
        let decoder = IlDecoder::new();
        let code = vec![0x2Au8];
        let insns = decoder.decode_instructions(&code).unwrap();
        assert_eq!(insns[0].opcode, Opcode::Ret);
    }

    #[test]
    fn test_decode_ldarg_sequence() {
        let decoder = IlDecoder::new();
        let code = vec![0x02, 0x03, 0x04, 0x05]; // ldarg.0 ldarg.1 ldarg.2 ldarg.3
        let insns = decoder.decode_instructions(&code).unwrap();
        assert_eq!(insns.len(), 4);
        assert_eq!(insns[0].opcode, Opcode::Ldarg0);
        assert_eq!(insns[3].opcode, Opcode::Ldarg3);
    }

    #[test]
    fn test_decode_ldc_i4() {
        let decoder = IlDecoder::new();
        let mut code = vec![0x20u8]; // ldc.i4
        code.extend_from_slice(&42i32.to_le_bytes());
        let insns = decoder.decode_instructions(&code).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].opcode, Opcode::LdcI4);
        assert_eq!(insns[0].operand, IlOperand::Int32(42));
    }

    #[test]
    fn test_decode_call() {
        let decoder = IlDecoder::new();
        let mut code = vec![0x28u8]; // call
        code.extend_from_slice(&0x0A00_0001_u32.to_le_bytes());
        let insns = decoder.decode_instructions(&code).unwrap();
        assert_eq!(insns[0].opcode, Opcode::Call);
        assert_eq!(insns[0].operand, IlOperand::Token(0x0A00_0001));
    }

    #[test]
    fn test_decode_fe_ceq() {
        let decoder = IlDecoder::new();
        let code = vec![0xFEu8, 0x01]; // ceq
        let insns = decoder.decode_instructions(&code).unwrap();
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].opcode, Opcode::Ceq);
    }

    #[test]
    fn test_decode_branch_short() {
        let decoder = IlDecoder::new();
        let code = vec![0x2Bu8, 0x05]; // br.s +5
        let insns = decoder.decode_instructions(&code).unwrap();
        assert_eq!(insns[0].opcode, Opcode::BrS);
        // Resolved: offset=0, size=2, target=0+2+5=7
        assert_eq!(insns[0].operand, IlOperand::BranchTargetAbs(7));
    }

    #[test]
    fn test_opcode_display() {
        assert_eq!(Opcode::Nop.to_string(), "nop");
        assert_eq!(Opcode::Ret.to_string(), "ret");
        assert_eq!(Opcode::Callvirt.to_string(), "callvirt");
        assert_eq!(Opcode::LdcI4S.to_string(), "ldc.i4.s");
    }

    #[test]
    fn test_instruction_disasm_line() {
        let insn = CilInstruction {
            offset: 0x0010,
            opcode: Opcode::Callvirt,
            operand: IlOperand::Token(0x0A00_0042),
            size: 5,
        };
        let line = insn.to_disasm_line();
        assert!(line.contains("IL_0010"));
        assert!(line.contains("callvirt"));
        assert!(line.contains("0x0a000042"));
    }

    #[test]
    fn test_disassembler_find_calls() {
        let insns = vec![
            CilInstruction {
                offset: 0,
                opcode: Opcode::Nop,
                operand: IlOperand::None,
                size: 1,
            },
            CilInstruction {
                offset: 1,
                opcode: Opcode::Call,
                operand: IlOperand::Token(1),
                size: 5,
            },
            CilInstruction {
                offset: 6,
                opcode: Opcode::Callvirt,
                operand: IlOperand::Token(2),
                size: 5,
            },
            CilInstruction {
                offset: 11,
                opcode: Opcode::Ret,
                operand: IlOperand::None,
                size: 1,
            },
        ];
        let calls = IlDisassembler::find_calls(&insns);
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn test_disassembler_find_string_loads() {
        let insns = vec![
            CilInstruction {
                offset: 0,
                opcode: Opcode::LdStr,
                operand: IlOperand::Token(0x7000_0001),
                size: 5,
            },
            CilInstruction {
                offset: 5,
                opcode: Opcode::Pop,
                operand: IlOperand::None,
                size: 1,
            },
        ];
        let strs = IlDisassembler::find_string_loads(&insns);
        assert_eq!(strs.len(), 1);
    }

    #[test]
    fn test_il_method_header_max_stack_tiny() {
        let h = IlMethodHeader::Tiny { code_size: 10 };
        assert_eq!(h.max_stack(), 8);
        assert_eq!(h.local_var_sig_token(), 0);
        assert!(!h.has_more_sects());
        assert_eq!(h.header_size(), 1);
    }

    #[test]
    fn test_il_method_header_fat_fields() {
        let h = IlMethodHeader::Fat {
            flags: 0x0013,
            max_stack: 16,
            code_size: 128,
            local_var_sig_token: 0x1100_0001,
        };
        assert_eq!(h.max_stack(), 16);
        assert_eq!(h.local_var_sig_token(), 0x1100_0001);
        assert_eq!(h.code_size(), 128);
        assert_eq!(h.header_size(), 12);
    }

    #[test]
    fn test_decode_add_sub_mul() {
        let decoder = IlDecoder::new();
        let code = vec![0x58u8, 0x59, 0x5A]; // add, sub, mul
        let insns = decoder.decode_instructions(&code).unwrap();
        assert_eq!(insns[0].opcode, Opcode::Add);
        assert_eq!(insns[1].opcode, Opcode::Sub);
        assert_eq!(insns[2].opcode, Opcode::Mul);
    }

    #[test]
    fn test_decode_stloc_sequence() {
        let decoder = IlDecoder::new();
        let code = vec![0x0Au8, 0x0B, 0x0C, 0x0D]; // stloc.0..3
        let insns = decoder.decode_instructions(&code).unwrap();
        assert_eq!(insns[0].opcode, Opcode::Stloc0);
        assert_eq!(insns[3].opcode, Opcode::Stloc3);
    }

    #[test]
    fn test_decode_newobj() {
        let decoder = IlDecoder::new();
        let mut code = vec![0x73u8]; // newobj
        code.extend_from_slice(&0x0A00_0001_u32.to_le_bytes());
        let insns = decoder.decode_instructions(&code).unwrap();
        assert_eq!(insns[0].opcode, Opcode::Newobj);
    }

    #[test]
    fn test_disassembler_text_output() {
        let decoder = IlDecoder::new();
        let code = vec![0x00u8, 0x2A]; // nop, ret
        let insns = decoder.decode_instructions(&code).unwrap();
        let text = IlDisassembler::disassemble(&insns);
        assert!(text.contains("nop"));
        assert!(text.contains("ret"));
    }

    #[test]
    fn test_ex_handler_kind_display() {
        assert_eq!(ExHandlerKind::Catch.to_string(), "catch");
        assert_eq!(ExHandlerKind::Finally.to_string(), "finally");
        assert_eq!(ExHandlerKind::Filter.to_string(), "filter");
        assert_eq!(ExHandlerKind::Fault.to_string(), "fault");
    }
}
