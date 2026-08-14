//! `cil_decoder` — CIL (Common Intermediate Language) instruction decoder (production layer).
//!
//! Decodes all CIL opcodes as defined in ECMA-335 §III. Handles both single-byte
//! and two-byte (0xFE prefix) opcodes, inline operands (none, int8, int32, int64,
//! float32, float64, token, string, switch, method sig), branch targets, and
//! provides a complete decoded instruction list with source offsets.
//!
//! # Design note — relation to `cil_disasm`
//! This is the **production** decoder used by [`DotnetArch::disassemble`] and
//! the wider loader pipeline.  It carries serde serialisation, per-opcode
//! stack-delta metadata, control-flow graph construction, and token statistics.
//! [`cil_disasm`] is a separate **lightweight diagnostic** layer with no
//! external dependencies — it should remain distinct from this module.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::DotnetLoaderError;

// ---------------------------------------------------------------------------
// Operand type
// ---------------------------------------------------------------------------

/// The operand encoding of a CIL instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OperandKind {
    /// No inline operand.
    None,
    /// 8-bit signed integer (e.g. ldc.i4.s, ldarg.s, stloc.s).
    InlineI8,
    /// 32-bit signed integer.
    InlineI32,
    /// 64-bit signed integer.
    InlineI64,
    /// 32-bit floating point.
    InlineR32,
    /// 64-bit floating point.
    InlineR64,
    /// Metadata token (4 bytes).
    InlineToken,
    /// Metadata token pointing to a string in the #US heap.
    InlineString,
    /// Relative branch offset (int8).
    ShortBrTarget,
    /// Relative branch offset (int32).
    BrTarget,
    /// Switch table: int32 count followed by count × int32 offsets.
    Switch,
    /// Method signature token (calli).
    InlineSig,
    /// Local variable index (uint8).
    ShortVar,
    /// Local variable index (uint16).
    Var,
    /// Argument index (uint8).
    ShortArg,
    /// Argument index (uint16).
    Arg,
}

// ---------------------------------------------------------------------------
// Decoded operand value
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operand {
    None,
    I8(i8),
    I32(i32),
    I64(i64),
    R32(f32),
    R64(f64),
    Token(u32),
    StringToken(u32),
    BranchOffset(i32),
    SwitchOffsets(Vec<i32>),
    LocalIndex(u16),
    ArgIndex(u16),
}

impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => Ok(()),
            Self::I8(v) => write!(f, "{v}"),
            Self::I32(v) => write!(f, "{v}"),
            Self::I64(v) => write!(f, "{v}L"),
            Self::R32(v) => write!(f, "{v}f"),
            Self::R64(v) => write!(f, "{v}"),
            Self::Token(t) => write!(f, "0x{t:08X}"),
            Self::StringToken(t) => write!(f, "#US[0x{t:08X}]"),
            Self::BranchOffset(o) => write!(f, "{o:+}"),
            Self::SwitchOffsets(v) => write!(f, "[{}]", v.iter().map(std::string::ToString::to_string).collect::<Vec<_>>().join(", ")),
            Self::LocalIndex(i) => write!(f, "V_{i}"),
            Self::ArgIndex(i) => write!(f, "A_{i}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Opcode table
// ---------------------------------------------------------------------------

/// A CIL opcode descriptor.
#[derive(Debug, Clone, Copy)]
pub struct OpcodeInfo {
    pub mnemonic: &'static str,
    pub operand: OperandKind,
    pub stack_delta: i8,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_return: bool,
    pub is_prefix: bool,
}

impl OpcodeInfo {
    const fn new(mnemonic: &'static str, operand: OperandKind, stack_delta: i8) -> Self {
        Self { mnemonic, operand, stack_delta, is_branch: false, is_call: false, is_return: false, is_prefix: false }
    }
    const fn branch(mnemonic: &'static str, operand: OperandKind) -> Self {
        Self { mnemonic, operand, stack_delta: -1, is_branch: true, is_call: false, is_return: false, is_prefix: false }
    }
    const fn call(mnemonic: &'static str, operand: OperandKind) -> Self {
        Self { mnemonic, operand, stack_delta: 0, is_branch: false, is_call: true, is_return: false, is_prefix: false }
    }
    const fn ret() -> Self {
        Self { mnemonic: "ret", operand: OperandKind::None, stack_delta: -1, is_branch: false, is_call: false, is_return: true, is_prefix: false }
    }
    const fn prefix(mnemonic: &'static str) -> Self {
        Self { mnemonic, operand: OperandKind::None, stack_delta: 0, is_branch: false, is_call: false, is_return: false, is_prefix: true }
    }
}

static OPCODE_TABLE: &[Option<OpcodeInfo>; 256] = &[
    /* 0x00 */ Some(OpcodeInfo::new("nop", OperandKind::None, 0)),
    /* 0x01 */ Some(OpcodeInfo::new("break", OperandKind::None, 0)),
    /* 0x02 */ Some(OpcodeInfo::new("ldarg.0", OperandKind::None, 1)),
    /* 0x03 */ Some(OpcodeInfo::new("ldarg.1", OperandKind::None, 1)),
    /* 0x04 */ Some(OpcodeInfo::new("ldarg.2", OperandKind::None, 1)),
    /* 0x05 */ Some(OpcodeInfo::new("ldarg.3", OperandKind::None, 1)),
    /* 0x06 */ Some(OpcodeInfo::new("ldloc.0", OperandKind::None, 1)),
    /* 0x07 */ Some(OpcodeInfo::new("ldloc.1", OperandKind::None, 1)),
    /* 0x08 */ Some(OpcodeInfo::new("ldloc.2", OperandKind::None, 1)),
    /* 0x09 */ Some(OpcodeInfo::new("ldloc.3", OperandKind::None, 1)),
    /* 0x0A */ Some(OpcodeInfo::new("stloc.0", OperandKind::None, -1)),
    /* 0x0B */ Some(OpcodeInfo::new("stloc.1", OperandKind::None, -1)),
    /* 0x0C */ Some(OpcodeInfo::new("stloc.2", OperandKind::None, -1)),
    /* 0x0D */ Some(OpcodeInfo::new("stloc.3", OperandKind::None, -1)),
    /* 0x0E */ Some(OpcodeInfo::new("ldarg.s", OperandKind::ShortArg, 1)),
    /* 0x0F */ Some(OpcodeInfo::new("ldarga.s", OperandKind::ShortArg, 1)),
    /* 0x10 */ Some(OpcodeInfo::new("starg.s", OperandKind::ShortArg, -1)),
    /* 0x11 */ Some(OpcodeInfo::new("ldloc.s", OperandKind::ShortVar, 1)),
    /* 0x12 */ Some(OpcodeInfo::new("ldloca.s", OperandKind::ShortVar, 1)),
    /* 0x13 */ Some(OpcodeInfo::new("stloc.s", OperandKind::ShortVar, -1)),
    /* 0x14 */ Some(OpcodeInfo::new("ldnull", OperandKind::None, 1)),
    /* 0x15 */ Some(OpcodeInfo::new("ldc.i4.m1", OperandKind::None, 1)),
    /* 0x16 */ Some(OpcodeInfo::new("ldc.i4.0", OperandKind::None, 1)),
    /* 0x17 */ Some(OpcodeInfo::new("ldc.i4.1", OperandKind::None, 1)),
    /* 0x18 */ Some(OpcodeInfo::new("ldc.i4.2", OperandKind::None, 1)),
    /* 0x19 */ Some(OpcodeInfo::new("ldc.i4.3", OperandKind::None, 1)),
    /* 0x1A */ Some(OpcodeInfo::new("ldc.i4.4", OperandKind::None, 1)),
    /* 0x1B */ Some(OpcodeInfo::new("ldc.i4.5", OperandKind::None, 1)),
    /* 0x1C */ Some(OpcodeInfo::new("ldc.i4.6", OperandKind::None, 1)),
    /* 0x1D */ Some(OpcodeInfo::new("ldc.i4.7", OperandKind::None, 1)),
    /* 0x1E */ Some(OpcodeInfo::new("ldc.i4.8", OperandKind::None, 1)),
    /* 0x1F */ Some(OpcodeInfo::new("ldc.i4.s", OperandKind::InlineI8, 1)),
    /* 0x20 */ Some(OpcodeInfo::new("ldc.i4", OperandKind::InlineI32, 1)),
    /* 0x21 */ Some(OpcodeInfo::new("ldc.i8", OperandKind::InlineI64, 1)),
    /* 0x22 */ Some(OpcodeInfo::new("ldc.r4", OperandKind::InlineR32, 1)),
    /* 0x23 */ Some(OpcodeInfo::new("ldc.r8", OperandKind::InlineR64, 1)),
    /* 0x24 */ None,
    /* 0x25 */ Some(OpcodeInfo::new("dup", OperandKind::None, 1)),
    /* 0x26 */ Some(OpcodeInfo::new("pop", OperandKind::None, -1)),
    /* 0x27 */ Some(OpcodeInfo::new("jmp", OperandKind::InlineToken, 0)),
    /* 0x28 */ Some(OpcodeInfo::call("call", OperandKind::InlineToken)),
    /* 0x29 */ Some(OpcodeInfo::call("calli", OperandKind::InlineSig)),
    /* 0x2A */ Some(OpcodeInfo::ret()),
    /* 0x2B */ Some(OpcodeInfo::branch("br.s", OperandKind::ShortBrTarget)),
    /* 0x2C */ Some(OpcodeInfo::branch("brfalse.s", OperandKind::ShortBrTarget)),
    /* 0x2D */ Some(OpcodeInfo::branch("brtrue.s", OperandKind::ShortBrTarget)),
    /* 0x2E */ Some(OpcodeInfo::branch("beq.s", OperandKind::ShortBrTarget)),
    /* 0x2F */ Some(OpcodeInfo::branch("bge.s", OperandKind::ShortBrTarget)),
    /* 0x30 */ Some(OpcodeInfo::branch("bgt.s", OperandKind::ShortBrTarget)),
    /* 0x31 */ Some(OpcodeInfo::branch("ble.s", OperandKind::ShortBrTarget)),
    /* 0x32 */ Some(OpcodeInfo::branch("blt.s", OperandKind::ShortBrTarget)),
    /* 0x33 */ Some(OpcodeInfo::branch("bne.un.s", OperandKind::ShortBrTarget)),
    /* 0x34 */ Some(OpcodeInfo::branch("bge.un.s", OperandKind::ShortBrTarget)),
    /* 0x35 */ Some(OpcodeInfo::branch("bgt.un.s", OperandKind::ShortBrTarget)),
    /* 0x36 */ Some(OpcodeInfo::branch("ble.un.s", OperandKind::ShortBrTarget)),
    /* 0x37 */ Some(OpcodeInfo::branch("blt.un.s", OperandKind::ShortBrTarget)),
    /* 0x38 */ Some(OpcodeInfo::branch("br", OperandKind::BrTarget)),
    /* 0x39 */ Some(OpcodeInfo::branch("brfalse", OperandKind::BrTarget)),
    /* 0x3A */ Some(OpcodeInfo::branch("brtrue", OperandKind::BrTarget)),
    /* 0x3B */ Some(OpcodeInfo::branch("beq", OperandKind::BrTarget)),
    /* 0x3C */ Some(OpcodeInfo::branch("bge", OperandKind::BrTarget)),
    /* 0x3D */ Some(OpcodeInfo::branch("bgt", OperandKind::BrTarget)),
    /* 0x3E */ Some(OpcodeInfo::branch("ble", OperandKind::BrTarget)),
    /* 0x3F */ Some(OpcodeInfo::branch("blt", OperandKind::BrTarget)),
    /* 0x40 */ Some(OpcodeInfo::branch("bne.un", OperandKind::BrTarget)),
    /* 0x41 */ Some(OpcodeInfo::branch("bge.un", OperandKind::BrTarget)),
    /* 0x42 */ Some(OpcodeInfo::branch("bgt.un", OperandKind::BrTarget)),
    /* 0x43 */ Some(OpcodeInfo::branch("ble.un", OperandKind::BrTarget)),
    /* 0x44 */ Some(OpcodeInfo::branch("blt.un", OperandKind::BrTarget)),
    /* 0x45 */ Some(OpcodeInfo::branch("switch", OperandKind::Switch)),
    /* 0x46 */ Some(OpcodeInfo::new("ldind.i1", OperandKind::None, 0)),
    /* 0x47 */ Some(OpcodeInfo::new("ldind.u1", OperandKind::None, 0)),
    /* 0x48 */ Some(OpcodeInfo::new("ldind.i2", OperandKind::None, 0)),
    /* 0x49 */ Some(OpcodeInfo::new("ldind.u2", OperandKind::None, 0)),
    /* 0x4A */ Some(OpcodeInfo::new("ldind.i4", OperandKind::None, 0)),
    /* 0x4B */ Some(OpcodeInfo::new("ldind.u4", OperandKind::None, 0)),
    /* 0x4C */ Some(OpcodeInfo::new("ldind.i8", OperandKind::None, 0)),
    /* 0x4D */ Some(OpcodeInfo::new("ldind.i", OperandKind::None, 0)),
    /* 0x4E */ Some(OpcodeInfo::new("ldind.r4", OperandKind::None, 0)),
    /* 0x4F */ Some(OpcodeInfo::new("ldind.r8", OperandKind::None, 0)),
    /* 0x50 */ Some(OpcodeInfo::new("ldind.ref", OperandKind::None, 0)),
    /* 0x51 */ Some(OpcodeInfo::new("stind.ref", OperandKind::None, -2)),
    /* 0x52 */ Some(OpcodeInfo::new("stind.i1", OperandKind::None, -2)),
    /* 0x53 */ Some(OpcodeInfo::new("stind.i2", OperandKind::None, -2)),
    /* 0x54 */ Some(OpcodeInfo::new("stind.i4", OperandKind::None, -2)),
    /* 0x55 */ Some(OpcodeInfo::new("stind.i8", OperandKind::None, -2)),
    /* 0x56 */ Some(OpcodeInfo::new("stind.r4", OperandKind::None, -2)),
    /* 0x57 */ Some(OpcodeInfo::new("stind.r8", OperandKind::None, -2)),
    /* 0x58 */ Some(OpcodeInfo::new("add", OperandKind::None, -1)),
    /* 0x59 */ Some(OpcodeInfo::new("sub", OperandKind::None, -1)),
    /* 0x5A */ Some(OpcodeInfo::new("mul", OperandKind::None, -1)),
    /* 0x5B */ Some(OpcodeInfo::new("div", OperandKind::None, -1)),
    /* 0x5C */ Some(OpcodeInfo::new("div.un", OperandKind::None, -1)),
    /* 0x5D */ Some(OpcodeInfo::new("rem", OperandKind::None, -1)),
    /* 0x5E */ Some(OpcodeInfo::new("rem.un", OperandKind::None, -1)),
    /* 0x5F */ Some(OpcodeInfo::new("and", OperandKind::None, -1)),
    /* 0x60 */ Some(OpcodeInfo::new("or", OperandKind::None, -1)),
    /* 0x61 */ Some(OpcodeInfo::new("xor", OperandKind::None, -1)),
    /* 0x62 */ Some(OpcodeInfo::new("shl", OperandKind::None, -1)),
    /* 0x63 */ Some(OpcodeInfo::new("shr", OperandKind::None, -1)),
    /* 0x64 */ Some(OpcodeInfo::new("shr.un", OperandKind::None, -1)),
    /* 0x65 */ Some(OpcodeInfo::new("neg", OperandKind::None, 0)),
    /* 0x66 */ Some(OpcodeInfo::new("not", OperandKind::None, 0)),
    /* 0x67 */ Some(OpcodeInfo::new("conv.i1", OperandKind::None, 0)),
    /* 0x68 */ Some(OpcodeInfo::new("conv.i2", OperandKind::None, 0)),
    /* 0x69 */ Some(OpcodeInfo::new("conv.i4", OperandKind::None, 0)),
    /* 0x6A */ Some(OpcodeInfo::new("conv.i8", OperandKind::None, 0)),
    /* 0x6B */ Some(OpcodeInfo::new("conv.r4", OperandKind::None, 0)),
    /* 0x6C */ Some(OpcodeInfo::new("conv.r8", OperandKind::None, 0)),
    /* 0x6D */ Some(OpcodeInfo::new("conv.u4", OperandKind::None, 0)),
    /* 0x6E */ Some(OpcodeInfo::new("conv.u8", OperandKind::None, 0)),
    /* 0x6F */ Some(OpcodeInfo::call("callvirt", OperandKind::InlineToken)),
    /* 0x70 */ Some(OpcodeInfo::new("cpobj", OperandKind::InlineToken, -2)),
    /* 0x71 */ Some(OpcodeInfo::new("ldobj", OperandKind::InlineToken, 0)),
    /* 0x72 */ Some(OpcodeInfo::new("ldstr", OperandKind::InlineString, 1)),
    /* 0x73 */ Some(OpcodeInfo::new("newobj", OperandKind::InlineToken, 1)),
    /* 0x74 */ Some(OpcodeInfo::new("castclass", OperandKind::InlineToken, 0)),
    /* 0x75 */ Some(OpcodeInfo::new("isinst", OperandKind::InlineToken, 0)),
    /* 0x76 */ Some(OpcodeInfo::new("conv.r.un", OperandKind::None, 0)),
    /* 0x77 */ None,
    /* 0x78 */ None,
    /* 0x79 */ Some(OpcodeInfo::new("unbox", OperandKind::InlineToken, 0)),
    /* 0x7A */ Some(OpcodeInfo::new("throw", OperandKind::None, -1)),
    /* 0x7B */ Some(OpcodeInfo::new("ldfld", OperandKind::InlineToken, 0)),
    /* 0x7C */ Some(OpcodeInfo::new("ldflda", OperandKind::InlineToken, 0)),
    /* 0x7D */ Some(OpcodeInfo::new("stfld", OperandKind::InlineToken, -2)),
    /* 0x7E */ Some(OpcodeInfo::new("ldsfld", OperandKind::InlineToken, 1)),
    /* 0x7F */ Some(OpcodeInfo::new("ldsflda", OperandKind::InlineToken, 1)),
    /* 0x80 */ Some(OpcodeInfo::new("stsfld", OperandKind::InlineToken, -1)),
    /* 0x81 */ Some(OpcodeInfo::new("stobj", OperandKind::InlineToken, -2)),
    /* 0x82 */ Some(OpcodeInfo::new("conv.ovf.i1.un", OperandKind::None, 0)),
    /* 0x83 */ Some(OpcodeInfo::new("conv.ovf.i2.un", OperandKind::None, 0)),
    /* 0x84 */ Some(OpcodeInfo::new("conv.ovf.i4.un", OperandKind::None, 0)),
    /* 0x85 */ Some(OpcodeInfo::new("conv.ovf.i8.un", OperandKind::None, 0)),
    /* 0x86 */ Some(OpcodeInfo::new("conv.ovf.u1.un", OperandKind::None, 0)),
    /* 0x87 */ Some(OpcodeInfo::new("conv.ovf.u2.un", OperandKind::None, 0)),
    /* 0x88 */ Some(OpcodeInfo::new("conv.ovf.u4.un", OperandKind::None, 0)),
    /* 0x89 */ Some(OpcodeInfo::new("conv.ovf.u8.un", OperandKind::None, 0)),
    /* 0x8A */ Some(OpcodeInfo::new("conv.ovf.i.un", OperandKind::None, 0)),
    /* 0x8B */ Some(OpcodeInfo::new("conv.ovf.u.un", OperandKind::None, 0)),
    /* 0x8C */ Some(OpcodeInfo::new("box", OperandKind::InlineToken, 0)),
    /* 0x8D */ Some(OpcodeInfo::new("newarr", OperandKind::InlineToken, 0)),
    /* 0x8E */ Some(OpcodeInfo::new("ldlen", OperandKind::None, 0)),
    /* 0x8F */ Some(OpcodeInfo::new("ldelema", OperandKind::InlineToken, -1)),
    /* 0x90 */ Some(OpcodeInfo::new("ldelem.i1", OperandKind::None, -1)),
    /* 0x91 */ Some(OpcodeInfo::new("ldelem.u1", OperandKind::None, -1)),
    /* 0x92 */ Some(OpcodeInfo::new("ldelem.i2", OperandKind::None, -1)),
    /* 0x93 */ Some(OpcodeInfo::new("ldelem.u2", OperandKind::None, -1)),
    /* 0x94 */ Some(OpcodeInfo::new("ldelem.i4", OperandKind::None, -1)),
    /* 0x95 */ Some(OpcodeInfo::new("ldelem.u4", OperandKind::None, -1)),
    /* 0x96 */ Some(OpcodeInfo::new("ldelem.i8", OperandKind::None, -1)),
    /* 0x97 */ Some(OpcodeInfo::new("ldelem.i", OperandKind::None, -1)),
    /* 0x98 */ Some(OpcodeInfo::new("ldelem.r4", OperandKind::None, -1)),
    /* 0x99 */ Some(OpcodeInfo::new("ldelem.r8", OperandKind::None, -1)),
    /* 0x9A */ Some(OpcodeInfo::new("ldelem.ref", OperandKind::None, -1)),
    /* 0x9B */ Some(OpcodeInfo::new("stelem.i", OperandKind::None, -3)),
    /* 0x9C */ Some(OpcodeInfo::new("stelem.i1", OperandKind::None, -3)),
    /* 0x9D */ Some(OpcodeInfo::new("stelem.i2", OperandKind::None, -3)),
    /* 0x9E */ Some(OpcodeInfo::new("stelem.i4", OperandKind::None, -3)),
    /* 0x9F */ Some(OpcodeInfo::new("stelem.i8", OperandKind::None, -3)),
    /* 0xA0 */ Some(OpcodeInfo::new("stelem.r4", OperandKind::None, -3)),
    /* 0xA1 */ Some(OpcodeInfo::new("stelem.r8", OperandKind::None, -3)),
    /* 0xA2 */ Some(OpcodeInfo::new("stelem.ref", OperandKind::None, -3)),
    /* 0xA3 */ Some(OpcodeInfo::new("ldelem", OperandKind::InlineToken, -1)),
    /* 0xA4 */ Some(OpcodeInfo::new("stelem", OperandKind::InlineToken, -3)),
    /* 0xA5 */ Some(OpcodeInfo::new("unbox.any", OperandKind::InlineToken, 0)),
    /* 0xA6 */ None, /* 0xA7 */ None, /* 0xA8 */ None, /* 0xA9 */ None,
    /* 0xAA */ None, /* 0xAB */ None, /* 0xAC */ None, /* 0xAD */ None,
    /* 0xAE */ None, /* 0xAF */ None,
    /* 0xB0 */ None, /* 0xB1 */ None, /* 0xB2 */ None,
    /* 0xB3 */ Some(OpcodeInfo::new("conv.ovf.i1", OperandKind::None, 0)),
    /* 0xB4 */ Some(OpcodeInfo::new("conv.ovf.u1", OperandKind::None, 0)),
    /* 0xB5 */ Some(OpcodeInfo::new("conv.ovf.i2", OperandKind::None, 0)),
    /* 0xB6 */ Some(OpcodeInfo::new("conv.ovf.u2", OperandKind::None, 0)),
    /* 0xB7 */ Some(OpcodeInfo::new("conv.ovf.i4", OperandKind::None, 0)),
    /* 0xB8 */ Some(OpcodeInfo::new("conv.ovf.u4", OperandKind::None, 0)),
    /* 0xB9 */ Some(OpcodeInfo::new("conv.ovf.i8", OperandKind::None, 0)),
    /* 0xBA */ Some(OpcodeInfo::new("conv.ovf.u8", OperandKind::None, 0)),
    /* 0xBB */ None, /* 0xBC */ None, /* 0xBD */ None, /* 0xBE */ None, /* 0xBF */ None,
    /* 0xC0 */ None, /* 0xC1 */ None,
    /* 0xC2 */ Some(OpcodeInfo::new("refanyval", OperandKind::InlineToken, 0)),
    /* 0xC3 */ Some(OpcodeInfo::new("ckfinite", OperandKind::None, 0)),
    /* 0xC4 */ None, /* 0xC5 */ None,
    /* 0xC6 */ Some(OpcodeInfo::new("mkrefany", OperandKind::InlineToken, 0)),
    /* 0xC7 */ None, /* 0xC8 */ None, /* 0xC9 */ None, /* 0xCA */ None, /* 0xCB */ None,
    /* 0xCC */ None, /* 0xCD */ None, /* 0xCE */ None, /* 0xCF */ None,
    /* 0xD0 */ Some(OpcodeInfo::new("ldtoken", OperandKind::InlineToken, 1)),
    /* 0xD1 */ Some(OpcodeInfo::new("conv.u2", OperandKind::None, 0)),
    /* 0xD2 */ Some(OpcodeInfo::new("conv.u1", OperandKind::None, 0)),
    /* 0xD3 */ Some(OpcodeInfo::new("conv.i", OperandKind::None, 0)),
    /* 0xD4 */ Some(OpcodeInfo::new("conv.ovf.i", OperandKind::None, 0)),
    /* 0xD5 */ Some(OpcodeInfo::new("conv.ovf.u", OperandKind::None, 0)),
    /* 0xD6 */ Some(OpcodeInfo::new("add.ovf", OperandKind::None, -1)),
    /* 0xD7 */ Some(OpcodeInfo::new("add.ovf.un", OperandKind::None, -1)),
    /* 0xD8 */ Some(OpcodeInfo::new("mul.ovf", OperandKind::None, -1)),
    /* 0xD9 */ Some(OpcodeInfo::new("mul.ovf.un", OperandKind::None, -1)),
    /* 0xDA */ Some(OpcodeInfo::new("sub.ovf", OperandKind::None, -1)),
    /* 0xDB */ Some(OpcodeInfo::new("sub.ovf.un", OperandKind::None, -1)),
    /* 0xDC */ Some(OpcodeInfo::new("endfinally", OperandKind::None, 0)),
    /* 0xDD */ Some(OpcodeInfo::branch("leave", OperandKind::BrTarget)),
    /* 0xDE */ Some(OpcodeInfo::branch("leave.s", OperandKind::ShortBrTarget)),
    /* 0xDF */ Some(OpcodeInfo::new("stind.i", OperandKind::None, -2)),
    /* 0xE0 */ Some(OpcodeInfo::new("conv.u", OperandKind::None, 0)),
    /* 0xE1 */ None, /* 0xE2 */ None, /* 0xE3 */ None, /* 0xE4 */ None, /* 0xE5 */ None,
    /* 0xE6 */ None, /* 0xE7 */ None, /* 0xE8 */ None, /* 0xE9 */ None, /* 0xEA */ None,
    /* 0xEB */ None, /* 0xEC */ None, /* 0xED */ None, /* 0xEE */ None, /* 0xEF */ None,
    /* 0xF0 */ None, /* 0xF1 */ None, /* 0xF2 */ None, /* 0xF3 */ None, /* 0xF4 */ None,
    /* 0xF5 */ None, /* 0xF6 */ None, /* 0xF7 */ None, /* 0xF8 */ None, /* 0xF9 */ None,
    /* 0xFA */ None, /* 0xFB */ None, /* 0xFC */ None, /* 0xFD */ None,
    /* 0xFE */ Some(OpcodeInfo::prefix("prefix.fe")),
    /* 0xFF */ Some(OpcodeInfo::prefix("prefix.ff")),
];

/// Two-byte opcodes (first byte 0xFE).
const fn fe_opcode(b: u8) -> Option<OpcodeInfo> {
    match b {
        0x00 => Some(OpcodeInfo::new("arglist", OperandKind::None, 1)),
        0x01 => Some(OpcodeInfo::new("ceq", OperandKind::None, -1)),
        0x02 => Some(OpcodeInfo::new("cgt", OperandKind::None, -1)),
        0x03 => Some(OpcodeInfo::new("cgt.un", OperandKind::None, -1)),
        0x04 => Some(OpcodeInfo::new("clt", OperandKind::None, -1)),
        0x05 => Some(OpcodeInfo::new("clt.un", OperandKind::None, -1)),
        0x06 => Some(OpcodeInfo::new("ldftn", OperandKind::InlineToken, 1)),
        0x07 => Some(OpcodeInfo::new("ldvirtftn", OperandKind::InlineToken, 0)),
        0x09 => Some(OpcodeInfo::new("ldarg", OperandKind::Arg, 1)),
        0x0A => Some(OpcodeInfo::new("ldarga", OperandKind::Arg, 1)),
        0x0B => Some(OpcodeInfo::new("starg", OperandKind::Arg, -1)),
        0x0C => Some(OpcodeInfo::new("ldloc", OperandKind::Var, 1)),
        0x0D => Some(OpcodeInfo::new("ldloca", OperandKind::Var, 1)),
        0x0E => Some(OpcodeInfo::new("stloc", OperandKind::Var, -1)),
        0x0F => Some(OpcodeInfo::new("localloc", OperandKind::None, 0)),
        0x11 => Some(OpcodeInfo::new("endfilter", OperandKind::None, -1)),
        0x12 => Some(OpcodeInfo::prefix("unaligned.")),
        0x13 => Some(OpcodeInfo::prefix("volatile.")),
        0x14 => Some(OpcodeInfo::prefix("tail.")),
        0x15 => Some(OpcodeInfo::new("initobj", OperandKind::InlineToken, -1)),
        0x16 => Some(OpcodeInfo::new("constrained.", OperandKind::InlineToken, 0)),
        0x17 => Some(OpcodeInfo::new("cpblk", OperandKind::None, -3)),
        0x18 => Some(OpcodeInfo::new("initblk", OperandKind::None, -3)),
        0x19 => Some(OpcodeInfo::new("no.", OperandKind::InlineI8, 0)),
        0x1A => Some(OpcodeInfo::new("rethrow", OperandKind::None, 0)),
        0x1C => Some(OpcodeInfo::new("sizeof", OperandKind::InlineToken, 1)),
        0x1D => Some(OpcodeInfo::new("refanytype", OperandKind::None, 0)),
        0x1E => Some(OpcodeInfo::new("readonly.", OperandKind::None, 0)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Decoded instruction
// ---------------------------------------------------------------------------

/// A single decoded CIL instruction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CilInstruction {
    /// Byte offset within the method body code bytes.
    pub offset: u32,
    /// Opcode byte(s): [b0] or [0xFE, b1].
    pub opcode_bytes: [u8; 2],
    /// Whether this is a two-byte (0xFE prefix) opcode.
    pub is_two_byte: bool,
    pub mnemonic: String,
    pub operand: Operand,
    pub is_branch: bool,
    pub is_call: bool,
    pub is_return: bool,
    /// Absolute target offset for branch instructions (offset + operand size + `branch_delta`).
    pub branch_target: Option<u32>,
    /// All switch case targets (for switch instruction).
    pub switch_targets: Vec<u32>,
    /// Total byte length of this instruction (opcode + operand).
    pub byte_len: u32,
}

impl CilInstruction {
    #[must_use] 
    pub const fn token(&self) -> Option<u32> {
        match &self.operand {
            Operand::Token(t) | Operand::StringToken(t) => Some(*t),
            _ => None,
        }
    }
}

impl fmt::Display for CilInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IL_{:04X}: {}", self.offset, self.mnemonic)?;
        match &self.operand {
            Operand::None => {}
            op => write!(f, " {op}")?,
        }
        if let Some(t) = self.branch_target {
            write!(f, " -> IL_{t:04X}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

pub struct CilDecoder<'a> {
    code: &'a [u8],
    pos: usize,
}

impl<'a> CilDecoder<'a> {
    #[must_use] 
    pub const fn new(code: &'a [u8]) -> Self { Self { code, pos: 0 } }

    fn read_u8(&mut self) -> Option<u8> {
        let b = *self.code.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
    fn read_i8(&mut self) -> Option<i8> { self.read_u8().map(|b| b as i8) }
    /// Read a little-endian `i16`, advancing the cursor.
    pub fn read_i16(&mut self) -> Option<i16> {
        let b = self.code.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(i16::from_le_bytes([b[0], b[1]]))
    }
    fn read_u16(&mut self) -> Option<u16> {
        let b = self.code.get(self.pos..self.pos + 2)?;
        self.pos += 2;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }
    fn read_i32(&mut self) -> Option<i32> {
        let b = self.code.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn read_u32(&mut self) -> Option<u32> {
        let b = self.code.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn read_i64(&mut self) -> Option<i64> {
        let b = self.code.get(self.pos..self.pos + 8)?;
        self.pos += 8;
        Some(i64::from_le_bytes(b.try_into().unwrap()))
    }
    fn read_f32(&mut self) -> Option<f32> {
        let b = self.code.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn read_f64(&mut self) -> Option<f64> {
        let b = self.code.get(self.pos..self.pos + 8)?;
        self.pos += 8;
        Some(f64::from_le_bytes(b.try_into().unwrap()))
    }

    fn decode_next(&mut self) -> Option<Result<CilInstruction, DotnetLoaderError>> {
        if self.pos >= self.code.len() { return None; }
        let start_pos = self.pos as u32;
        let b0 = self.read_u8()?;
        let (opcode_bytes, info, is_two_byte) = if b0 == 0xFE {
            let b1 = self.read_u8()?;
            let info = fe_opcode(b1)?;
            ([b0, b1], info, true)
        } else {
            let info = OPCODE_TABLE[b0 as usize]?;
            ([b0, 0], info, false)
        };
        let before_operand = self.pos;
        let (operand, branch_target, switch_targets) = match info.operand {
            OperandKind::None => (Operand::None, None, vec![]),
            OperandKind::InlineI8 => {
                let v = self.read_i8()?;
                (Operand::I8(v), None, vec![])
            }
            OperandKind::InlineI32 => {
                let v = self.read_i32()?;
                (Operand::I32(v), None, vec![])
            }
            OperandKind::InlineI64 => {
                let v = self.read_i64()?;
                (Operand::I64(v), None, vec![])
            }
            OperandKind::InlineR32 => {
                let v = self.read_f32()?;
                (Operand::R32(v), None, vec![])
            }
            OperandKind::InlineR64 => {
                let v = self.read_f64()?;
                (Operand::R64(v), None, vec![])
            }
            OperandKind::InlineToken | OperandKind::InlineSig => {
                let t = self.read_u32()?;
                (Operand::Token(t), None, vec![])
            }
            OperandKind::InlineString => {
                let t = self.read_u32()?;
                (Operand::StringToken(t), None, vec![])
            }
            OperandKind::ShortBrTarget => {
                let delta = i32::from(self.read_i8()?);
                let target = (self.pos as i64 + i64::from(delta)) as u32;
                (Operand::BranchOffset(delta), Some(target), vec![])
            }
            OperandKind::BrTarget => {
                let delta = self.read_i32()?;
                let target = (self.pos as i64 + i64::from(delta)) as u32;
                (Operand::BranchOffset(delta), Some(target), vec![])
            }
            OperandKind::Switch => {
                let count = self.read_u32()? as usize;
                // Cap pre-allocation by remaining bytes: each target is 4 bytes.
                let mut offsets =
                    Vec::with_capacity(count.min(self.code.len().saturating_sub(self.pos) / 4));
                for _ in 0..count {
                    offsets.push(self.read_i32()?);
                }
                let after = self.pos as i64;
                let targets: Vec<u32> = offsets.iter().map(|&d| (after + i64::from(d)) as u32).collect();
                let offsets_clone = offsets.clone();
                (Operand::SwitchOffsets(offsets_clone), None, targets)
            }
            OperandKind::ShortVar | OperandKind::ShortArg => {
                let v = u16::from(self.read_u8()?);
                let op = if matches!(info.operand, OperandKind::ShortVar) {
                    Operand::LocalIndex(v)
                } else { Operand::ArgIndex(v) };
                (op, None, vec![])
            }
            OperandKind::Var | OperandKind::Arg => {
                let v = self.read_u16()?;
                let op = if matches!(info.operand, OperandKind::Var) {
                    Operand::LocalIndex(v)
                } else { Operand::ArgIndex(v) };
                (op, None, vec![])
            }
        };
        let byte_len = (self.pos - start_pos as usize) as u32;
        let _ = before_operand;
        Some(Ok(CilInstruction {
            offset: start_pos,
            opcode_bytes,
            is_two_byte,
            mnemonic: info.mnemonic.to_owned(),
            operand,
            is_branch: info.is_branch,
            is_call: info.is_call,
            is_return: info.is_return,
            branch_target,
            switch_targets,
            byte_len,
        }))
    }
}

impl Iterator for CilDecoder<'_> {
    type Item = Result<CilInstruction, DotnetLoaderError>;
    fn next(&mut self) -> Option<Self::Item> { self.decode_next() }
}

// ---------------------------------------------------------------------------
// Decode a full method body
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CilMethodBody {
    pub instructions: Vec<CilInstruction>,
    pub total_bytes: u32,
    pub has_branch_error: bool,
}

#[must_use] 
pub fn decode_method_body(code: &[u8]) -> CilMethodBody {
    let mut instructions = Vec::new();
    let mut has_branch_error = false;
    for result in CilDecoder::new(code) {
        if let Ok(insn) = result { instructions.push(insn) } else { has_branch_error = true; break; }
    }
    CilMethodBody { total_bytes: code.len() as u32, instructions, has_branch_error }
}

// ---------------------------------------------------------------------------
// Control flow analysis
// ---------------------------------------------------------------------------

/// Basic block within a CIL method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CilBasicBlock {
    pub id: u32,
    pub start_offset: u32,
    pub end_offset: u32,
    pub successor_offsets: Vec<u32>,
    pub is_entry: bool,
    pub instruction_count: u32,
}

/// Build a list of basic blocks from decoded instructions.
#[must_use] 
pub fn build_basic_blocks(body: &CilMethodBody) -> Vec<CilBasicBlock> {
    use std::collections::BTreeSet;
    // Collect leaders (block starts)
    let mut leaders: BTreeSet<u32> = BTreeSet::new();
    if let Some(first) = body.instructions.first() {
        leaders.insert(first.offset);
    }
    for insn in &body.instructions {
        if insn.is_branch || insn.is_return {
            // Next instruction is a leader
            let next = insn.offset + insn.byte_len;
            leaders.insert(next);
            if let Some(t) = insn.branch_target { leaders.insert(t); }
            for &t in &insn.switch_targets { leaders.insert(t); }
        }
    }
    // Build blocks
    let leaders_vec: Vec<u32> = leaders.into_iter().collect();
    let mut blocks: Vec<CilBasicBlock> = Vec::new();
    for (i, &start) in leaders_vec.iter().enumerate() {
        let end = leaders_vec.get(i + 1).copied().unwrap_or(body.total_bytes);
        let insns_in_block: Vec<&CilInstruction> = body.instructions.iter()
            .filter(|ins| ins.offset >= start && ins.offset < end)
            .collect();
        let mut successors = Vec::new();
        if let Some(last) = insns_in_block.last() {
            if last.is_branch {
                if let Some(t) = last.branch_target { successors.push(t); }
                for &t in &last.switch_targets { successors.push(t); }
                // Conditional branches also fall through
                let mnemonic = &last.mnemonic;
                let unconditional = matches!(mnemonic.as_str(), "br" | "br.s" | "ret" | "throw" | "rethrow" | "leave" | "leave.s");
                if !unconditional {
                    successors.push(last.offset + last.byte_len);
                }
            } else if !last.is_return {
                successors.push(end);
            }
        }
        blocks.push(CilBasicBlock {
            id: i as u32,
            start_offset: start,
            end_offset: end,
            successor_offsets: successors,
            is_entry: i == 0,
            instruction_count: insns_in_block.len() as u32,
        });
    }
    blocks
}

// ---------------------------------------------------------------------------
// Token kind
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenKind {
    Module = 0x00,
    TypeRef = 0x01,
    TypeDef = 0x02,
    FieldDef = 0x04,
    MethodDef = 0x06,
    ParamDef = 0x08,
    InterfaceImpl = 0x09,
    MemberRef = 0x0A,
    CustomAttribute = 0x0C,
    Permission = 0x0E,
    Signature = 0x11,
    Event = 0x14,
    Property = 0x17,
    ModuleRef = 0x1A,
    TypeSpec = 0x1B,
    Assembly = 0x20,
    AssemblyRef = 0x23,
    File = 0x26,
    ExportedType = 0x27,
    ManifestResource = 0x28,
    GenericParam = 0x2A,
    MethodSpec = 0x2B,
    GenericParamConstraint = 0x2C,
    UserString = 0x70,
    Unknown = 0xFF,
}

impl TokenKind {
    #[must_use] 
    pub const fn from_token(token: u32) -> Self {
        match (token >> 24) as u8 {
            0x00 => Self::Module, 0x01 => Self::TypeRef, 0x02 => Self::TypeDef,
            0x04 => Self::FieldDef, 0x06 => Self::MethodDef, 0x08 => Self::ParamDef,
            0x09 => Self::InterfaceImpl, 0x0A => Self::MemberRef, 0x0C => Self::CustomAttribute,
            0x11 => Self::Signature, 0x1A => Self::ModuleRef, 0x1B => Self::TypeSpec,
            0x20 => Self::Assembly, 0x23 => Self::AssemblyRef, 0x2A => Self::GenericParam,
            0x2B => Self::MethodSpec, 0x70 => Self::UserString,
            _ => Self::Unknown,
        }
    }
    #[must_use] 
    pub const fn row(token: u32) -> u32 { token & 0x00FFFFFF }
}

// ---------------------------------------------------------------------------
// Instruction statistics
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MethodStats {
    pub total_instructions: u32,
    pub branch_count: u32,
    pub call_count: u32,
    pub field_access_count: u32,
    pub token_refs: BTreeMap<u32, u32>,
    pub estimated_complexity: u32,
}

#[must_use] 
pub fn compute_method_stats(body: &CilMethodBody) -> MethodStats {
    let mut stats = MethodStats::default();
    stats.total_instructions = body.instructions.len() as u32;
    for insn in &body.instructions {
        if insn.is_branch { stats.branch_count += 1; stats.estimated_complexity += 1; }
        if insn.is_call { stats.call_count += 1; }
        if matches!(insn.mnemonic.as_str(), "ldfld" | "ldflda" | "stfld" | "ldsfld" | "ldsflda" | "stsfld") {
            stats.field_access_count += 1;
        }
        if let Some(tok) = insn.token() {
            *stats.token_refs.entry(tok).or_insert(0) += 1;
        }
    }
    stats
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_nop_ret() {
        // nop (0x00) + ret (0x2A)
        let code = [0x00u8, 0x2A];
        let body = decode_method_body(&code);
        assert_eq!(body.instructions.len(), 2);
        assert_eq!(body.instructions[0].mnemonic, "nop");
        assert_eq!(body.instructions[1].mnemonic, "ret");
        assert!(body.instructions[1].is_return);
    }

    #[test]
    fn test_decode_ldc_i4() {
        // ldc.i4 42 (0x20 0x2A 0x00 0x00 0x00) + ret
        let code = [0x20u8, 42, 0, 0, 0, 0x2A];
        let body = decode_method_body(&code);
        assert_eq!(body.instructions[0].mnemonic, "ldc.i4");
        if let Operand::I32(v) = body.instructions[0].operand { assert_eq!(v, 42); } else { panic!(); }
    }

    #[test]
    fn test_decode_ldc_i4_s() {
        // ldc.i4.s -1
        let code = [0x1Fu8, 0xFFu8, 0x2A];
        let body = decode_method_body(&code);
        assert_eq!(body.instructions[0].mnemonic, "ldc.i4.s");
        if let Operand::I8(v) = body.instructions[0].operand { assert_eq!(v, -1i8); } else { panic!(); }
    }

    #[test]
    fn test_decode_call() {
        // call token 0x0A000001
        let mut code = vec![0x28u8];
        code.extend_from_slice(&0x0A000001u32.to_le_bytes());
        code.push(0x2A);
        let body = decode_method_body(&code);
        assert!(body.instructions[0].is_call);
        assert_eq!(body.instructions[0].mnemonic, "call");
        assert_eq!(body.instructions[0].token(), Some(0x0A000001));
    }

    #[test]
    fn test_decode_br_s() {
        // br.s +2, nop, nop, ret
        let code = [0x2Bu8, 0x02, 0x00, 0x00, 0x2A];
        let body = decode_method_body(&code);
        assert!(body.instructions[0].is_branch);
        assert_eq!(body.instructions[0].branch_target, Some(4));
    }

    #[test]
    fn test_decode_switch() {
        // switch 2 cases: [+1, +2]
        let mut code = vec![0x45u8];
        code.extend_from_slice(&2u32.to_le_bytes());
        code.extend_from_slice(&1i32.to_le_bytes());
        code.extend_from_slice(&2i32.to_le_bytes());
        code.push(0x2A);
        let body = decode_method_body(&code);
        assert_eq!(body.instructions[0].mnemonic, "switch");
        assert_eq!(body.instructions[0].switch_targets.len(), 2);
    }

    #[test]
    fn test_fe_prefix_ceq() {
        // ceq = 0xFE 0x01
        let code = [0xFEu8, 0x01, 0x2A];
        let body = decode_method_body(&code);
        assert_eq!(body.instructions[0].mnemonic, "ceq");
        assert!(body.instructions[0].is_two_byte);
    }

    #[test]
    fn test_basic_blocks() {
        // br.s +2 (target=4), nop, nop, ret
        let code = [0x2Bu8, 0x02, 0x00, 0x00, 0x2A];
        let body = decode_method_body(&code);
        let blocks = build_basic_blocks(&body);
        assert!(!blocks.is_empty());
        assert!(blocks[0].is_entry);
    }

    #[test]
    fn test_token_kind() {
        assert_eq!(TokenKind::from_token(0x0A000001), TokenKind::MemberRef);
        assert_eq!(TokenKind::from_token(0x06000010), TokenKind::MethodDef);
        assert_eq!(TokenKind::row(0x06000010), 0x10);
    }

    #[test]
    fn test_method_stats() {
        let code = [0x00u8, 0x28, 0x01, 0x00, 0x00, 0x0A, 0x2A];
        let body = decode_method_body(&code);
        let stats = compute_method_stats(&body);
        assert_eq!(stats.call_count, 1);
        assert_eq!(stats.total_instructions, 3);
    }

    // ── Extra edge-case coverage ────────────────────────────────────────────

    #[test]
    fn test_decode_empty_body() {
        let body = decode_method_body(&[]);
        assert!(body.instructions.is_empty());
    }

    #[test]
    fn test_decode_truncated_ldc_i4() {
        // Opcode 0x20 needs 4 bytes; provide only 2. Should not panic.
        let code = [0x20u8, 0x01, 0x02];
        let _ = decode_method_body(&code);
    }

    #[test]
    fn test_decode_truncated_switch() {
        // switch with claimed 5 cases but only 4 bytes of payload.
        let mut code = vec![0x45u8];
        code.extend_from_slice(&5u32.to_le_bytes());
        // No target bytes.
        let _ = decode_method_body(&code);
    }

    #[test]
    fn test_token_kind_unknown() {
        // Unknown high byte yields Unknown.
        assert_eq!(TokenKind::from_token(0xFF000001), TokenKind::Unknown);
    }

    #[test]
    fn test_token_kind_row_extraction() {
        assert_eq!(TokenKind::row(0x00000000), 0);
        assert_eq!(TokenKind::row(0x06FFFFFF), 0xFFFFFF);
        // Max row is 24 bits.
        assert!(TokenKind::row(u32::MAX) <= 0x00FFFFFF);
    }

    #[test]
    fn test_method_stats_empty_body() {
        let body = decode_method_body(&[]);
        let stats = compute_method_stats(&body);
        assert_eq!(stats.total_instructions, 0);
        assert_eq!(stats.call_count, 0);
        assert_eq!(stats.branch_count, 0);
        assert!(stats.token_refs.is_empty());
    }

    #[test]
    fn test_decode_only_nops() {
        let code = vec![0x00u8; 32];
        let body = decode_method_body(&code);
        assert_eq!(body.instructions.len(), 32);
        for ins in &body.instructions {
            assert_eq!(ins.mnemonic, "nop");
            assert!(!ins.is_branch);
            assert!(!ins.is_call);
        }
    }

    #[test]
    fn test_basic_blocks_single_ret() {
        let body = decode_method_body(&[0x2A]);
        let blocks = build_basic_blocks(&body);
        assert!(!blocks.is_empty());
        assert!(blocks[0].is_entry);
    }
}
