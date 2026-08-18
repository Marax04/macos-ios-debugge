//! .NET IL method body loader — primary integration layer.
//!
//! Parses CIL method headers (tiny and fat), exception handler tables,
//! local variable signatures, and decodes all 220+ CIL opcodes with their
//! operand types.
//!
//! # Design note — relation to `dotnet_method_loader`
//! This module (`il_method_loader`) is the **canonical** method-loading
//! entry-point re-exported from `lib.rs` as `IlMethodLoader`, `IlError`,
//! `IlInstruction`, etc.  [`dotnet_method_loader`] is a **higher-level**
//! companion that adds `LocalVarSig` blob decoding, serde output, and
//! batch loading of an entire `MethodDef` table via `DotnetMethodLoader`.
//! The two modules are complementary layers — do not merge them.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IlError {
    TruncatedData { offset: usize, needed: usize },
    InvalidHeaderFormat(u8),
    UnknownOpcode(u16),
    InvalidLocalVarSig(u32),
    TooManyLocals(usize),
    TooManyExceptionHandlers(usize),
    InvalidExceptionClause(u8),
    StackUnderflow { offset: usize },
    UnresolvedToken(u32),
    InvalidSwitchTable { offset: usize },
    InvalidInlineSig(u32),
}

impl std::fmt::Display for IlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TruncatedData { offset, needed } => {
                write!(f, "truncated IL at offset {offset:#x}, need {needed}")
            }
            Self::InvalidHeaderFormat(b) => write!(f, "invalid method header format byte {b:#04x}"),
            Self::UnknownOpcode(op) => write!(f, "unknown CIL opcode {op:#06x}"),
            Self::InvalidLocalVarSig(tok) => write!(f, "invalid LocalVarSig token {tok:#010x}"),
            Self::TooManyLocals(n) => write!(f, "too many locals: {n}"),
            Self::TooManyExceptionHandlers(n) => write!(f, "too many exception handlers: {n}"),
            Self::InvalidExceptionClause(t) => write!(f, "invalid exception clause type {t}"),
            Self::StackUnderflow { offset } => {
                write!(f, "stack underflow at IL offset {offset:#x}")
            }
            Self::UnresolvedToken(tok) => write!(f, "unresolved metadata token {tok:#010x}"),
            Self::InvalidSwitchTable { offset } => {
                write!(f, "invalid switch table at offset {offset:#x}")
            }
            Self::InvalidInlineSig(s) => write!(f, "invalid inline signature {s:#010x}"),
        }
    }
}

impl std::error::Error for IlError {}

// ---------------------------------------------------------------------------
// Operand types for CIL instructions
// ---------------------------------------------------------------------------

/// The operand format of a CIL instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperandType {
    /// No operand.
    InlineNone,
    /// 8-bit integer (compressed).
    ShortInlineI,
    /// 32-bit integer.
    InlineI,
    /// 64-bit integer.
    InlineI8,
    /// 32-bit float.
    ShortInlineR,
    /// 64-bit float.
    InlineR,
    /// Metadata token.
    InlineTok,
    /// Type token.
    InlineType,
    /// Method token.
    InlineMethod,
    /// Field token.
    InlineField,
    /// String token.
    InlineString,
    /// Signature token.
    InlineSig,
    /// Variable index (8-bit).
    ShortInlineVar,
    /// Variable index (16-bit).
    InlineVar,
    /// Branch offset (8-bit signed).
    ShortInlineBrTarget,
    /// Branch offset (32-bit signed).
    InlineBrTarget,
    /// Switch table.
    InlineSwitch,
}

impl OperandType {
    /// Number of bytes in the operand (0 for None and Switch).
    #[must_use] 
    pub const fn size_bytes(self) -> usize {
        match self {
            Self::ShortInlineI
            | Self::ShortInlineVar
            | Self::ShortInlineBrTarget
            | Self::ShortInlineR => 1,
            Self::InlineI
            | Self::InlineTok
            | Self::InlineType
            | Self::InlineMethod
            | Self::InlineField
            | Self::InlineString
            | Self::InlineSig
            | Self::InlineBrTarget
            | Self::InlineR => 4,
            Self::InlineI8 => 8,
            Self::InlineVar => 2,
            Self::InlineNone | Self::InlineSwitch => 0, // dynamic
        }
    }
}

// ---------------------------------------------------------------------------
// CIL Opcode table
// ---------------------------------------------------------------------------

/// One CIL opcode descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CilOpcode {
    pub name: &'static str,
    pub code: u16,
    pub operand: OperandType,
    /// Stack behaviour delta (positive = push, negative = pop).
    pub stack_delta: i8,
}

impl CilOpcode {
    const fn new(name: &'static str, code: u16, operand: OperandType, delta: i8) -> Self {
        Self {
            name,
            code,
            operand,
            stack_delta: delta,
        }
    }
}

/// Build the CIL opcode lookup table.
#[must_use] 
pub fn build_opcode_table() -> HashMap<u16, CilOpcode> {
    let mut map = HashMap::new();
    let opcodes: &[CilOpcode] = &[
        CilOpcode::new("nop", 0x00, OperandType::InlineNone, 0),
        CilOpcode::new("break", 0x01, OperandType::InlineNone, 0),
        CilOpcode::new("ldarg.0", 0x02, OperandType::InlineNone, 1),
        CilOpcode::new("ldarg.1", 0x03, OperandType::InlineNone, 1),
        CilOpcode::new("ldarg.2", 0x04, OperandType::InlineNone, 1),
        CilOpcode::new("ldarg.3", 0x05, OperandType::InlineNone, 1),
        CilOpcode::new("ldloc.0", 0x06, OperandType::InlineNone, 1),
        CilOpcode::new("ldloc.1", 0x07, OperandType::InlineNone, 1),
        CilOpcode::new("ldloc.2", 0x08, OperandType::InlineNone, 1),
        CilOpcode::new("ldloc.3", 0x09, OperandType::InlineNone, 1),
        CilOpcode::new("stloc.0", 0x0a, OperandType::InlineNone, -1),
        CilOpcode::new("stloc.1", 0x0b, OperandType::InlineNone, -1),
        CilOpcode::new("stloc.2", 0x0c, OperandType::InlineNone, -1),
        CilOpcode::new("stloc.3", 0x0d, OperandType::InlineNone, -1),
        CilOpcode::new("ldarg.s", 0x0e, OperandType::ShortInlineVar, 1),
        CilOpcode::new("ldarga.s", 0x0f, OperandType::ShortInlineVar, 1),
        CilOpcode::new("starg.s", 0x10, OperandType::ShortInlineVar, -1),
        CilOpcode::new("ldloc.s", 0x11, OperandType::ShortInlineVar, 1),
        CilOpcode::new("ldloca.s", 0x12, OperandType::ShortInlineVar, 1),
        CilOpcode::new("stloc.s", 0x13, OperandType::ShortInlineVar, -1),
        CilOpcode::new("ldnull", 0x14, OperandType::InlineNone, 1),
        CilOpcode::new("ldc.i4.m1", 0x15, OperandType::InlineNone, 1),
        CilOpcode::new("ldc.i4.0", 0x16, OperandType::InlineNone, 1),
        CilOpcode::new("ldc.i4.1", 0x17, OperandType::InlineNone, 1),
        CilOpcode::new("ldc.i4.2", 0x18, OperandType::InlineNone, 1),
        CilOpcode::new("ldc.i4.3", 0x19, OperandType::InlineNone, 1),
        CilOpcode::new("ldc.i4.4", 0x1a, OperandType::InlineNone, 1),
        CilOpcode::new("ldc.i4.5", 0x1b, OperandType::InlineNone, 1),
        CilOpcode::new("ldc.i4.6", 0x1c, OperandType::InlineNone, 1),
        CilOpcode::new("ldc.i4.7", 0x1d, OperandType::InlineNone, 1),
        CilOpcode::new("ldc.i4.8", 0x1e, OperandType::InlineNone, 1),
        CilOpcode::new("ldc.i4.s", 0x1f, OperandType::ShortInlineI, 1),
        CilOpcode::new("ldc.i4", 0x20, OperandType::InlineI, 1),
        CilOpcode::new("ldc.i8", 0x21, OperandType::InlineI8, 1),
        CilOpcode::new("ldc.r4", 0x22, OperandType::ShortInlineR, 1),
        CilOpcode::new("ldc.r8", 0x23, OperandType::InlineR, 1),
        CilOpcode::new("dup", 0x25, OperandType::InlineNone, 1),
        CilOpcode::new("pop", 0x26, OperandType::InlineNone, -1),
        CilOpcode::new("jmp", 0x27, OperandType::InlineMethod, 0),
        CilOpcode::new("call", 0x28, OperandType::InlineMethod, 0),
        CilOpcode::new("calli", 0x29, OperandType::InlineSig, 0),
        CilOpcode::new("ret", 0x2a, OperandType::InlineNone, 0),
        CilOpcode::new("br.s", 0x2b, OperandType::ShortInlineBrTarget, 0),
        CilOpcode::new("brfalse.s", 0x2c, OperandType::ShortInlineBrTarget, -1),
        CilOpcode::new("brtrue.s", 0x2d, OperandType::ShortInlineBrTarget, -1),
        CilOpcode::new("beq.s", 0x2e, OperandType::ShortInlineBrTarget, -2),
        CilOpcode::new("bge.s", 0x2f, OperandType::ShortInlineBrTarget, -2),
        CilOpcode::new("bgt.s", 0x30, OperandType::ShortInlineBrTarget, -2),
        CilOpcode::new("ble.s", 0x31, OperandType::ShortInlineBrTarget, -2),
        CilOpcode::new("blt.s", 0x32, OperandType::ShortInlineBrTarget, -2),
        CilOpcode::new("bne.un.s", 0x33, OperandType::ShortInlineBrTarget, -2),
        CilOpcode::new("bge.un.s", 0x34, OperandType::ShortInlineBrTarget, -2),
        CilOpcode::new("bgt.un.s", 0x35, OperandType::ShortInlineBrTarget, -2),
        CilOpcode::new("ble.un.s", 0x36, OperandType::ShortInlineBrTarget, -2),
        CilOpcode::new("blt.un.s", 0x37, OperandType::ShortInlineBrTarget, -2),
        CilOpcode::new("br", 0x38, OperandType::InlineBrTarget, 0),
        CilOpcode::new("brfalse", 0x39, OperandType::InlineBrTarget, -1),
        CilOpcode::new("brtrue", 0x3a, OperandType::InlineBrTarget, -1),
        CilOpcode::new("beq", 0x3b, OperandType::InlineBrTarget, -2),
        CilOpcode::new("bge", 0x3c, OperandType::InlineBrTarget, -2),
        CilOpcode::new("bgt", 0x3d, OperandType::InlineBrTarget, -2),
        CilOpcode::new("ble", 0x3e, OperandType::InlineBrTarget, -2),
        CilOpcode::new("blt", 0x3f, OperandType::InlineBrTarget, -2),
        CilOpcode::new("bne.un", 0x40, OperandType::InlineBrTarget, -2),
        CilOpcode::new("bge.un", 0x41, OperandType::InlineBrTarget, -2),
        CilOpcode::new("bgt.un", 0x42, OperandType::InlineBrTarget, -2),
        CilOpcode::new("ble.un", 0x43, OperandType::InlineBrTarget, -2),
        CilOpcode::new("blt.un", 0x44, OperandType::InlineBrTarget, -2),
        CilOpcode::new("switch", 0x45, OperandType::InlineSwitch, -1),
        CilOpcode::new("ldind.i1", 0x46, OperandType::InlineNone, 0),
        CilOpcode::new("ldind.u1", 0x47, OperandType::InlineNone, 0),
        CilOpcode::new("ldind.i2", 0x48, OperandType::InlineNone, 0),
        CilOpcode::new("ldind.u2", 0x49, OperandType::InlineNone, 0),
        CilOpcode::new("ldind.i4", 0x4a, OperandType::InlineNone, 0),
        CilOpcode::new("ldind.u4", 0x4b, OperandType::InlineNone, 0),
        CilOpcode::new("ldind.i8", 0x4c, OperandType::InlineNone, 0),
        CilOpcode::new("ldind.i", 0x4d, OperandType::InlineNone, 0),
        CilOpcode::new("ldind.r4", 0x4e, OperandType::InlineNone, 0),
        CilOpcode::new("ldind.r8", 0x4f, OperandType::InlineNone, 0),
        CilOpcode::new("ldind.ref", 0x50, OperandType::InlineNone, 0),
        CilOpcode::new("stind.ref", 0x51, OperandType::InlineNone, -2),
        CilOpcode::new("stind.i1", 0x52, OperandType::InlineNone, -2),
        CilOpcode::new("stind.i2", 0x53, OperandType::InlineNone, -2),
        CilOpcode::new("stind.i4", 0x54, OperandType::InlineNone, -2),
        CilOpcode::new("stind.i8", 0x55, OperandType::InlineNone, -2),
        CilOpcode::new("stind.r4", 0x56, OperandType::InlineNone, -2),
        CilOpcode::new("stind.r8", 0x57, OperandType::InlineNone, -2),
        CilOpcode::new("add", 0x58, OperandType::InlineNone, -1),
        CilOpcode::new("sub", 0x59, OperandType::InlineNone, -1),
        CilOpcode::new("mul", 0x5a, OperandType::InlineNone, -1),
        CilOpcode::new("div", 0x5b, OperandType::InlineNone, -1),
        CilOpcode::new("div.un", 0x5c, OperandType::InlineNone, -1),
        CilOpcode::new("rem", 0x5d, OperandType::InlineNone, -1),
        CilOpcode::new("rem.un", 0x5e, OperandType::InlineNone, -1),
        CilOpcode::new("and", 0x5f, OperandType::InlineNone, -1),
        CilOpcode::new("or", 0x60, OperandType::InlineNone, -1),
        CilOpcode::new("xor", 0x61, OperandType::InlineNone, -1),
        CilOpcode::new("shl", 0x62, OperandType::InlineNone, -1),
        CilOpcode::new("shr", 0x63, OperandType::InlineNone, -1),
        CilOpcode::new("shr.un", 0x64, OperandType::InlineNone, -1),
        CilOpcode::new("neg", 0x65, OperandType::InlineNone, 0),
        CilOpcode::new("not", 0x66, OperandType::InlineNone, 0),
        CilOpcode::new("conv.i1", 0x67, OperandType::InlineNone, 0),
        CilOpcode::new("conv.i2", 0x68, OperandType::InlineNone, 0),
        CilOpcode::new("conv.i4", 0x69, OperandType::InlineNone, 0),
        CilOpcode::new("conv.i8", 0x6a, OperandType::InlineNone, 0),
        CilOpcode::new("conv.r4", 0x6b, OperandType::InlineNone, 0),
        CilOpcode::new("conv.r8", 0x6c, OperandType::InlineNone, 0),
        CilOpcode::new("conv.u4", 0x6d, OperandType::InlineNone, 0),
        CilOpcode::new("conv.u8", 0x6e, OperandType::InlineNone, 0),
        CilOpcode::new("callvirt", 0x6f, OperandType::InlineMethod, 0),
        CilOpcode::new("cpobj", 0x70, OperandType::InlineType, -2),
        CilOpcode::new("ldobj", 0x71, OperandType::InlineType, 0),
        CilOpcode::new("ldstr", 0x72, OperandType::InlineString, 1),
        CilOpcode::new("newobj", 0x73, OperandType::InlineMethod, 1),
        CilOpcode::new("castclass", 0x74, OperandType::InlineType, 0),
        CilOpcode::new("isinst", 0x75, OperandType::InlineType, 0),
        CilOpcode::new("conv.r.un", 0x76, OperandType::InlineNone, 0),
        CilOpcode::new("unbox", 0x79, OperandType::InlineType, 0),
        CilOpcode::new("throw", 0x7a, OperandType::InlineNone, -1),
        CilOpcode::new("ldfld", 0x7b, OperandType::InlineField, 0),
        CilOpcode::new("ldflda", 0x7c, OperandType::InlineField, 0),
        CilOpcode::new("stfld", 0x7d, OperandType::InlineField, -2),
        CilOpcode::new("ldsfld", 0x7e, OperandType::InlineField, 1),
        CilOpcode::new("ldsflda", 0x7f, OperandType::InlineField, 1),
        CilOpcode::new("stsfld", 0x80, OperandType::InlineField, -1),
        CilOpcode::new("stobj", 0x81, OperandType::InlineType, -2),
        CilOpcode::new("conv.ovf.i1.un", 0x82, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.i2.un", 0x83, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.i4.un", 0x84, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.i8.un", 0x85, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.u1.un", 0x86, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.u2.un", 0x87, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.u4.un", 0x88, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.u8.un", 0x89, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.i.un", 0x8a, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.u.un", 0x8b, OperandType::InlineNone, 0),
        CilOpcode::new("box", 0x8c, OperandType::InlineType, 0),
        CilOpcode::new("newarr", 0x8d, OperandType::InlineType, 0),
        CilOpcode::new("ldlen", 0x8e, OperandType::InlineNone, 0),
        CilOpcode::new("ldelema", 0x8f, OperandType::InlineType, -1),
        CilOpcode::new("ldelem.i1", 0x90, OperandType::InlineNone, -1),
        CilOpcode::new("ldelem.u1", 0x91, OperandType::InlineNone, -1),
        CilOpcode::new("ldelem.i2", 0x92, OperandType::InlineNone, -1),
        CilOpcode::new("ldelem.u2", 0x93, OperandType::InlineNone, -1),
        CilOpcode::new("ldelem.i4", 0x94, OperandType::InlineNone, -1),
        CilOpcode::new("ldelem.u4", 0x95, OperandType::InlineNone, -1),
        CilOpcode::new("ldelem.i8", 0x96, OperandType::InlineNone, -1),
        CilOpcode::new("ldelem.i", 0x97, OperandType::InlineNone, -1),
        CilOpcode::new("ldelem.r4", 0x98, OperandType::InlineNone, -1),
        CilOpcode::new("ldelem.r8", 0x99, OperandType::InlineNone, -1),
        CilOpcode::new("ldelem.ref", 0x9a, OperandType::InlineNone, -1),
        CilOpcode::new("stelem.i", 0x9b, OperandType::InlineNone, -3),
        CilOpcode::new("stelem.i1", 0x9c, OperandType::InlineNone, -3),
        CilOpcode::new("stelem.i2", 0x9d, OperandType::InlineNone, -3),
        CilOpcode::new("stelem.i4", 0x9e, OperandType::InlineNone, -3),
        CilOpcode::new("stelem.i8", 0x9f, OperandType::InlineNone, -3),
        CilOpcode::new("stelem.r4", 0xa0, OperandType::InlineNone, -3),
        CilOpcode::new("stelem.r8", 0xa1, OperandType::InlineNone, -3),
        CilOpcode::new("stelem.ref", 0xa2, OperandType::InlineNone, -3),
        CilOpcode::new("ldelem", 0xa3, OperandType::InlineType, -1),
        CilOpcode::new("stelem", 0xa4, OperandType::InlineType, -3),
        CilOpcode::new("unbox.any", 0xa5, OperandType::InlineType, 0),
        CilOpcode::new("conv.ovf.i1", 0xb3, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.u1", 0xb4, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.i2", 0xb5, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.u2", 0xb6, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.i4", 0xb7, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.u4", 0xb8, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.i8", 0xb9, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.u8", 0xba, OperandType::InlineNone, 0),
        CilOpcode::new("refanyval", 0xc2, OperandType::InlineType, 0),
        CilOpcode::new("ckfinite", 0xc3, OperandType::InlineNone, 0),
        CilOpcode::new("mkrefany", 0xc6, OperandType::InlineType, 0),
        CilOpcode::new("ldtoken", 0xd0, OperandType::InlineTok, 1),
        CilOpcode::new("conv.u2", 0xd1, OperandType::InlineNone, 0),
        CilOpcode::new("conv.u1", 0xd2, OperandType::InlineNone, 0),
        CilOpcode::new("conv.i", 0xd3, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.i", 0xd4, OperandType::InlineNone, 0),
        CilOpcode::new("conv.ovf.u", 0xd5, OperandType::InlineNone, 0),
        CilOpcode::new("add.ovf", 0xd6, OperandType::InlineNone, -1),
        CilOpcode::new("add.ovf.un", 0xd7, OperandType::InlineNone, -1),
        CilOpcode::new("mul.ovf", 0xd8, OperandType::InlineNone, -1),
        CilOpcode::new("mul.ovf.un", 0xd9, OperandType::InlineNone, -1),
        CilOpcode::new("sub.ovf", 0xda, OperandType::InlineNone, -1),
        CilOpcode::new("sub.ovf.un", 0xdb, OperandType::InlineNone, -1),
        CilOpcode::new("endfinally", 0xdc, OperandType::InlineNone, 0),
        CilOpcode::new("leave", 0xdd, OperandType::InlineBrTarget, 0),
        CilOpcode::new("leave.s", 0xde, OperandType::ShortInlineBrTarget, 0),
        CilOpcode::new("stind.i", 0xdf, OperandType::InlineNone, -2),
        CilOpcode::new("conv.u", 0xe0, OperandType::InlineNone, 0),
        // Prefixed opcodes (0xFE prefix)
        CilOpcode::new("ceq", 0xfe01, OperandType::InlineNone, -1),
        CilOpcode::new("cgt", 0xfe02, OperandType::InlineNone, -1),
        CilOpcode::new("cgt.un", 0xfe03, OperandType::InlineNone, -1),
        CilOpcode::new("clt", 0xfe04, OperandType::InlineNone, -1),
        CilOpcode::new("clt.un", 0xfe05, OperandType::InlineNone, -1),
        CilOpcode::new("ldftn", 0xfe06, OperandType::InlineMethod, 1),
        CilOpcode::new("ldvirtftn", 0xfe07, OperandType::InlineMethod, 0),
        CilOpcode::new("ldarg", 0xfe09, OperandType::InlineVar, 1),
        CilOpcode::new("ldarga", 0xfe0a, OperandType::InlineVar, 1),
        CilOpcode::new("starg", 0xfe0b, OperandType::InlineVar, -1),
        CilOpcode::new("ldloc", 0xfe0c, OperandType::InlineVar, 1),
        CilOpcode::new("ldloca", 0xfe0d, OperandType::InlineVar, 1),
        CilOpcode::new("stloc", 0xfe0e, OperandType::InlineVar, -1),
        CilOpcode::new("localloc", 0xfe0f, OperandType::InlineNone, 0),
        CilOpcode::new("endfilter", 0xfe11, OperandType::InlineNone, -1),
        CilOpcode::new("unaligned.", 0xfe12, OperandType::ShortInlineI, 0),
        CilOpcode::new("volatile.", 0xfe13, OperandType::InlineNone, 0),
        CilOpcode::new("tail.", 0xfe14, OperandType::InlineNone, 0),
        CilOpcode::new("initobj", 0xfe15, OperandType::InlineType, -1),
        CilOpcode::new("constrained.", 0xfe16, OperandType::InlineType, 0),
        CilOpcode::new("cpblk", 0xfe17, OperandType::InlineNone, -3),
        CilOpcode::new("initblk", 0xfe18, OperandType::InlineNone, -3),
        CilOpcode::new("no.", 0xfe19, OperandType::ShortInlineI, 0),
        CilOpcode::new("rethrow", 0xfe1a, OperandType::InlineNone, 0),
        CilOpcode::new("sizeof", 0xfe1c, OperandType::InlineType, 1),
        CilOpcode::new("refanytype", 0xfe1d, OperandType::InlineNone, 0),
        CilOpcode::new("readonly.", 0xfe1e, OperandType::InlineNone, 0),
    ];
    for &op in opcodes {
        map.insert(op.code, op);
    }
    map
}

// ---------------------------------------------------------------------------
// MethodHeader
// ---------------------------------------------------------------------------

/// CIL method header variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodHeader {
    /// Tiny header: no locals, no exception handlers, < 64 bytes of IL.
    Tiny {
        /// Code size in bytes.
        code_size: u8,
    },
    /// Fat header: full method metadata.
    Fat {
        flags: u16,
        max_stack: u16,
        code_size: u32,
        local_var_sig_tok: u32,
    },
}

impl MethodHeader {
    pub const TINY_FORMAT: u8 = 0x02;
    pub const FAT_FORMAT: u8 = 0x03;

    /// Parse a method header from raw bytes, returning (header, `bytes_consumed`).
    pub fn parse(data: &[u8]) -> Result<(Self, usize), IlError> {
        if data.is_empty() {
            return Err(IlError::TruncatedData {
                offset: 0,
                needed: 1,
            });
        }
        let first = data[0];
        let format = first & 0x03;
        match format {
            0x02 => {
                // Tiny: code_size = first >> 2
                Ok((
                    Self::Tiny {
                        code_size: first >> 2,
                    },
                    1,
                ))
            }
            0x03 => {
                // Fat: 12-byte header
                if data.len() < 12 {
                    return Err(IlError::TruncatedData {
                        offset: 0,
                        needed: 12,
                    });
                }
                let flags = u16::from_le_bytes([data[0], data[1]]);
                let max_stack = u16::from_le_bytes([data[2], data[3]]);
                let code_size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                let local_var_sig_tok = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
                Ok((
                    Self::Fat {
                        flags,
                        max_stack,
                        code_size,
                        local_var_sig_tok,
                    },
                    12,
                ))
            }
            _ => Err(IlError::InvalidHeaderFormat(first)),
        }
    }

    /// Code size in bytes.
    #[must_use] 
    pub fn code_size(&self) -> u32 {
        match self {
            Self::Tiny { code_size } => u32::from(*code_size),
            Self::Fat { code_size, .. } => *code_size,
        }
    }

    #[must_use] 
    pub const fn max_stack(&self) -> u16 {
        match self {
            Self::Tiny { .. } => 8, // default for tiny methods
            Self::Fat { max_stack, .. } => *max_stack,
        }
    }

    #[must_use] 
    pub const fn local_var_sig_tok(&self) -> u32 {
        match self {
            Self::Tiny { .. } => 0,
            Self::Fat {
                local_var_sig_tok, ..
            } => *local_var_sig_tok,
        }
    }

    #[must_use] 
    pub fn has_more_sections(&self) -> bool {
        match self {
            Self::Tiny { .. } => false,
            Self::Fat { flags, .. } => flags & 0x08 != 0,
        }
    }
}

// ---------------------------------------------------------------------------
// ExceptionHandler
// ---------------------------------------------------------------------------

/// Type of a CIL exception handler clause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionClauseType {
    Catch,
    Filter,
    Finally,
    Fault,
}

impl ExceptionClauseType {
    pub const fn from_u32(v: u32) -> Result<Self, IlError> {
        match v {
            0 => Ok(Self::Catch),
            1 => Ok(Self::Filter),
            2 => Ok(Self::Finally),
            4 => Ok(Self::Fault),
            _ => Err(IlError::InvalidExceptionClause(v as u8)),
        }
    }
}

/// One exception handler entry.
#[derive(Debug, Clone)]
pub struct ExceptionHandler {
    pub clause_type: ExceptionClauseType,
    /// IL offset of the try block start.
    pub try_offset: u32,
    /// Length of the try block.
    pub try_length: u32,
    /// IL offset of the handler start.
    pub handler_offset: u32,
    /// Length of the handler block.
    pub handler_length: u32,
    /// For Catch: type token. For Filter: filter offset. For others: 0.
    pub class_token_or_filter_offset: u32,
}

impl ExceptionHandler {
    /// Parse a fat exception handler clause (24 bytes).
    pub fn parse_fat(data: &[u8]) -> Result<Self, IlError> {
        if data.len() < 24 {
            return Err(IlError::TruncatedData {
                offset: 0,
                needed: 24,
            });
        }
        let r4 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
        let clause_type = ExceptionClauseType::from_u32(r4(0))?;
        Ok(Self {
            clause_type,
            try_offset: r4(4),
            try_length: r4(8),
            handler_offset: r4(12),
            handler_length: r4(16),
            class_token_or_filter_offset: r4(20),
        })
    }

    /// Parse a small exception handler clause (12 bytes).
    pub fn parse_small(data: &[u8]) -> Result<Self, IlError> {
        if data.len() < 12 {
            return Err(IlError::TruncatedData {
                offset: 0,
                needed: 12,
            });
        }
        let r2 = |o: usize| u32::from(u16::from_le_bytes(data[o..o + 2].try_into().unwrap()));
        let r4 = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap());
        let clause_type = ExceptionClauseType::from_u32(r2(0))?;
        Ok(Self {
            clause_type,
            try_offset: r2(2),
            try_length: u32::from(data[4]),
            handler_offset: r2(5),
            handler_length: u32::from(data[7]),
            class_token_or_filter_offset: r4(8),
        })
    }
}

// ---------------------------------------------------------------------------
// LocalVarSig
// ---------------------------------------------------------------------------

/// Parsed local variable signature.
#[derive(Debug, Clone, Default)]
pub struct LocalVarSig {
    pub token: u32,
    /// Number of local variables.
    pub local_count: u32,
    /// Raw signature bytes (for further parsing).
    pub raw_sig: Vec<u8>,
}

impl LocalVarSig {
    #[must_use] 
    pub const fn new(token: u32, local_count: u32, raw_sig: Vec<u8>) -> Self {
        Self {
            token,
            local_count,
            raw_sig,
        }
    }
}

// ---------------------------------------------------------------------------
// IlInstruction
// ---------------------------------------------------------------------------

/// The decoded value of an IL instruction operand.
#[derive(Debug, Clone)]
pub enum Operand {
    None,
    I8(i8),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    Token(u32),
    BranchOffset(i32),
    VarIndex(u32),
    Switch(Vec<i32>),
}

/// A fully decoded CIL instruction.
#[derive(Debug, Clone)]
pub struct IlInstruction {
    /// Byte offset within the method body.
    pub offset: u32,
    /// Opcode descriptor.
    pub opcode: CilOpcode,
    /// Decoded operand.
    pub operand: Operand,
    /// Raw bytes (including opcode prefix byte(s)).
    pub raw_bytes: Vec<u8>,
}

impl IlInstruction {
    /// `true` if this is an unconditional branch.
    #[must_use] 
    pub const fn is_unconditional_branch(&self) -> bool {
        matches!(self.opcode.code, 0x2a | 0x2b | 0x38 | 0xdc | 0xdd | 0xde)
    }

    /// `true` if this is any branch instruction.
    #[must_use] 
    pub const fn is_branch(&self) -> bool {
        matches!(
            self.opcode.operand,
            OperandType::InlineBrTarget
                | OperandType::ShortInlineBrTarget
                | OperandType::InlineSwitch
        )
    }

    /// `true` if this is a call instruction.
    #[must_use] 
    pub const fn is_call(&self) -> bool {
        matches!(
            self.opcode.code,
            0x28 | 0x29 | 0x6f | 0x27 | 0xfe06 | 0xfe07
        )
    }

    /// Branch target IL offset (for branch instructions).
    #[must_use] 
    pub fn branch_target(&self) -> Option<i64> {
        match &self.operand {
            Operand::BranchOffset(off) => {
                Some(i64::from(self.offset) + self.raw_bytes.len() as i64 + i64::from(*off))
            }
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// IlNopRemover — NOP instruction removal pass
// ---------------------------------------------------------------------------

/// Remove all `nop` (0x00) instructions from an IL stream.
pub struct IlNopRemover;

impl IlNopRemover {
    #[must_use] 
    pub fn remove(instructions: &[IlInstruction]) -> Vec<IlInstruction> {
        instructions
            .iter()
            .filter(|i| i.opcode.code != 0x00)
            .cloned()
            .collect()
    }

    #[must_use] 
    pub fn count_nops(instructions: &[IlInstruction]) -> usize {
        instructions
            .iter()
            .filter(|i| i.opcode.code == 0x00)
            .count()
    }
}

// ---------------------------------------------------------------------------
// IlStringFinder — extract string literal tokens from IL
// ---------------------------------------------------------------------------

/// Finds all `ldstr` tokens in IL instructions.
pub struct IlStringFinder;

impl IlStringFinder {
    /// Returns all string metadata tokens referenced by `ldstr` instructions.
    #[must_use] 
    pub fn find_tokens(instructions: &[IlInstruction]) -> Vec<u32> {
        instructions
            .iter()
            .filter(|i| i.opcode.code == 0x72) // ldstr
            .filter_map(|i| {
                if let Operand::Token(t) = i.operand {
                    Some(t)
                } else {
                    None
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// IlCallFinder — extract method call tokens from IL
// ---------------------------------------------------------------------------

/// Extracts all method tokens from call/callvirt/newobj instructions.
pub struct IlCallFinder;

impl IlCallFinder {
    #[must_use] 
    pub fn find_tokens(instructions: &[IlInstruction]) -> Vec<(u16, u32)> {
        instructions
            .iter()
            .filter(|i| i.is_call())
            .filter_map(|i| {
                if let Operand::Token(t) = i.operand {
                    Some((i.opcode.code, t))
                } else {
                    None
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// CilStackSimulator — abstract stack simulation
// ---------------------------------------------------------------------------

/// Simulates the CIL evaluation stack to detect stack depth at each offset.
#[derive(Debug, Default)]
pub struct CilStackSimulator {
    /// Stack depth at each IL offset (instruction index → depth).
    pub depths: Vec<i32>,
    pub max_depth: i32,
    pub underflow_offsets: Vec<usize>,
}

impl CilStackSimulator {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Simulate through a list of decoded instructions.
    pub fn simulate(&mut self, instructions: &[IlInstruction]) {
        let mut depth: i32 = 0;
        self.depths.clear();
        self.max_depth = 0;
        for (i, instr) in instructions.iter().enumerate() {
            self.depths.push(depth);
            depth += i32::from(instr.opcode.stack_delta);
            if depth < 0 {
                self.underflow_offsets.push(i);
                depth = 0; // recover for next instruction
            }
            if depth > self.max_depth {
                self.max_depth = depth;
            }
        }
    }

    /// Stack depth just before instruction at `idx`.
    #[must_use] 
    pub fn depth_at(&self, idx: usize) -> Option<i32> {
        self.depths.get(idx).copied()
    }

    #[must_use] 
    pub const fn has_underflow(&self) -> bool {
        !self.underflow_offsets.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CilBranchResolver — collect branch targets
// ---------------------------------------------------------------------------

/// Collects all branch targets in a method body.
#[derive(Debug, Default)]
pub struct CilBranchResolver {
    /// Map of instruction offset → resolved target IL offset.
    pub branches: HashMap<u32, Vec<i64>>,
}

impl CilBranchResolver {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Populate from decoded instructions.
    pub fn resolve(&mut self, instructions: &[IlInstruction]) {
        self.branches.clear();
        for instr in instructions {
            match &instr.operand {
                Operand::BranchOffset(_) => {
                    if let Some(target) = instr.branch_target() {
                        self.branches.entry(instr.offset).or_default().push(target);
                    }
                }
                Operand::Switch(targets) => {
                    let base = i64::from(instr.offset) + instr.raw_bytes.len() as i64;
                    let resolved: Vec<i64> = targets.iter().map(|&t| base + i64::from(t)).collect();
                    self.branches.insert(instr.offset, resolved);
                }
                _ => {}
            }
        }
    }

    /// All target offsets.
    #[must_use] 
    pub fn all_targets(&self) -> Vec<i64> {
        self.branches
            .values()
            .flat_map(|v| v.iter().copied())
            .collect()
    }

    /// `true` when the method contains at least one branch.
    #[must_use] 
    pub fn has_branches(&self) -> bool {
        !self.branches.is_empty()
    }
}

// ---------------------------------------------------------------------------
// CilTokenResolver — resolve metadata tokens symbolically
// ---------------------------------------------------------------------------

/// Type of a metadata token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    TypeDef = 0x02,
    TypeRef = 0x01,
    FieldDef = 0x04,
    MethodDef = 0x06,
    MemberRef = 0x0A,
    StandAloneSig = 0x11,
    TypeSpec = 0x1B,
    MethodSpec = 0x2B,
    UserString = 0x70,
}

impl TokenKind {
    #[must_use] 
    pub const fn from_token(token: u32) -> Option<Self> {
        match token >> 24 {
            0x01 => Some(Self::TypeRef),
            0x02 => Some(Self::TypeDef),
            0x04 => Some(Self::FieldDef),
            0x06 => Some(Self::MethodDef),
            0x0A => Some(Self::MemberRef),
            0x11 => Some(Self::StandAloneSig),
            0x1B => Some(Self::TypeSpec),
            0x2B => Some(Self::MethodSpec),
            0x70 => Some(Self::UserString),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn row_index(token: u32) -> u32 {
        token & 0x00FF_FFFF
    }
}

// ---------------------------------------------------------------------------
// IlMethodLoader
// ---------------------------------------------------------------------------

/// Loaded .NET IL method body.
#[derive(Debug)]
pub struct IlMethodLoader {
    pub header: MethodHeader,
    pub instructions: Vec<IlInstruction>,
    pub exception_handlers: Vec<ExceptionHandler>,
    pub local_var_sig: Option<LocalVarSig>,
    opcode_table: HashMap<u16, CilOpcode>,
}

impl IlMethodLoader {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            header: MethodHeader::Tiny { code_size: 0 },
            instructions: Vec::new(),
            exception_handlers: Vec::new(),
            local_var_sig: None,
            opcode_table: build_opcode_table(),
        }
    }

    /// Load and decode a complete method body from raw bytes.
    pub fn load(&mut self, data: &[u8]) -> Result<(), IlError> {
        let (header, hdr_size) = MethodHeader::parse(data)?;
        let code_size = header.code_size() as usize;
        let code_start = hdr_size;
        let code_end = code_start + code_size;
        if code_end > data.len() {
            return Err(IlError::TruncatedData {
                offset: code_start,
                needed: code_size,
            });
        }
        let code = &data[code_start..code_end];
        self.instructions = self.decode_instructions(code)?;
        self.header = header;
        Ok(())
    }

    fn decode_instructions(&self, code: &[u8]) -> Result<Vec<IlInstruction>, IlError> {
        // Most IL instructions average ~2-3 bytes; preallocate to reduce reallocation churn.
        let mut instructions = Vec::with_capacity(code.len() / 2);
        let mut pos = 0;
        while pos < code.len() {
            let start = pos;
            let first = code[pos];
            pos += 1;

            let (opcode_code, extra_bytes) = if first == 0xfe {
                if pos >= code.len() {
                    return Err(IlError::TruncatedData {
                        offset: pos,
                        needed: 1,
                    });
                }
                let second = code[pos];
                pos += 1;
                (0xfe00u16 | u16::from(second), 2usize)
            } else {
                (u16::from(first), 1usize)
            };

            let opcode = self
                .opcode_table
                .get(&opcode_code)
                .copied()
                .ok_or(IlError::UnknownOpcode(opcode_code))?;

            let (operand, operand_bytes) = match opcode.operand {
                OperandType::InlineNone => (Operand::None, 0),
                OperandType::ShortInlineI | OperandType::ShortInlineVar => {
                    if pos >= code.len() {
                        return Err(IlError::TruncatedData {
                            offset: pos,
                            needed: 1,
                        });
                    }
                    let v = code[pos] as i8;
                    pos += 1;
                    (Operand::I8(v), 1)
                }
                OperandType::ShortInlineBrTarget => {
                    if pos >= code.len() {
                        return Err(IlError::TruncatedData {
                            offset: pos,
                            needed: 1,
                        });
                    }
                    let v = code[pos] as i8;
                    pos += 1;
                    (Operand::BranchOffset(i32::from(v)), 1)
                }
                OperandType::InlineI
                | OperandType::InlineTok
                | OperandType::InlineType
                | OperandType::InlineMethod
                | OperandType::InlineField
                | OperandType::InlineString
                | OperandType::InlineSig => {
                    if pos + 4 > code.len() {
                        return Err(IlError::TruncatedData {
                            offset: pos,
                            needed: 4,
                        });
                    }
                    let v = i32::from_le_bytes(code[pos..pos + 4].try_into().unwrap());
                    pos += 4;
                    (Operand::Token(v as u32), 4)
                }
                OperandType::InlineBrTarget => {
                    if pos + 4 > code.len() {
                        return Err(IlError::TruncatedData {
                            offset: pos,
                            needed: 4,
                        });
                    }
                    let v = i32::from_le_bytes(code[pos..pos + 4].try_into().unwrap());
                    pos += 4;
                    (Operand::BranchOffset(v), 4)
                }
                OperandType::InlineI8 => {
                    if pos + 8 > code.len() {
                        return Err(IlError::TruncatedData {
                            offset: pos,
                            needed: 8,
                        });
                    }
                    let v = i64::from_le_bytes(code[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                    (Operand::I64(v), 8)
                }
                OperandType::ShortInlineR => {
                    if pos + 4 > code.len() {
                        return Err(IlError::TruncatedData {
                            offset: pos,
                            needed: 4,
                        });
                    }
                    let bits = u32::from_le_bytes(code[pos..pos + 4].try_into().unwrap());
                    pos += 4;
                    (Operand::F32(f32::from_bits(bits)), 4)
                }
                OperandType::InlineR => {
                    if pos + 8 > code.len() {
                        return Err(IlError::TruncatedData {
                            offset: pos,
                            needed: 8,
                        });
                    }
                    let bits = u64::from_le_bytes(code[pos..pos + 8].try_into().unwrap());
                    pos += 8;
                    (Operand::F64(f64::from_bits(bits)), 8)
                }
                OperandType::InlineVar => {
                    if pos + 2 > code.len() {
                        return Err(IlError::TruncatedData {
                            offset: pos,
                            needed: 2,
                        });
                    }
                    let v = u32::from(u16::from_le_bytes([code[pos], code[pos + 1]]));
                    pos += 2;
                    (Operand::VarIndex(v), 2)
                }
                OperandType::InlineSwitch => {
                    if pos + 4 > code.len() {
                        return Err(IlError::TruncatedData {
                            offset: pos,
                            needed: 4,
                        });
                    }
                    let count = u32::from_le_bytes(code[pos..pos + 4].try_into().unwrap()) as usize;
                    pos += 4;
                    if pos + count * 4 > code.len() {
                        return Err(IlError::InvalidSwitchTable { offset: pos });
                    }
                    let mut targets = Vec::with_capacity(count);
                    for _ in 0..count {
                        let t = i32::from_le_bytes(code[pos..pos + 4].try_into().unwrap());
                        targets.push(t);
                        pos += 4;
                    }
                    let bytes = 4 + count * 4;
                    (Operand::Switch(targets), bytes)
                }
            };

            let raw_bytes = code[start..start + extra_bytes + operand_bytes].to_vec();
            instructions.push(IlInstruction {
                offset: start as u32,
                opcode,
                operand,
                raw_bytes,
            });
        }
        Ok(instructions)
    }

    /// Find an instruction at a specific IL offset.
    #[must_use] 
    pub fn instruction_at(&self, offset: u32) -> Option<&IlInstruction> {
        self.instructions.iter().find(|i| i.offset == offset)
    }

    /// All call instructions.
    #[must_use] 
    pub fn calls(&self) -> Vec<&IlInstruction> {
        self.instructions.iter().filter(|i| i.is_call()).collect()
    }

    /// Total number of decoded instructions.
    #[must_use] 
    pub const fn instruction_count(&self) -> usize {
        self.instructions.len()
    }
}

impl Default for IlMethodLoader {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tiny_body(code: &[u8]) -> Vec<u8> {
        // Tiny header: (code_size << 2) | 0x02
        let hdr = ((code.len() as u8) << 2) | 0x02;
        let mut v = vec![hdr];
        v.extend_from_slice(code);
        v
    }

    fn fat_body(code: &[u8], max_stack: u16, local_sig: u32) -> Vec<u8> {
        // Fat header: flags=0x3013, max_stack, code_size, local_var_sig
        let flags: u16 = 0x3003;
        let code_size = code.len() as u32;
        let mut v = Vec::new();
        v.extend_from_slice(&flags.to_le_bytes());
        v.extend_from_slice(&max_stack.to_le_bytes());
        v.extend_from_slice(&code_size.to_le_bytes());
        v.extend_from_slice(&local_sig.to_le_bytes());
        v.extend_from_slice(code);
        v
    }

    // ---- MethodHeader ----

    #[test]
    fn test_tiny_header_parse() {
        let (hdr, consumed) = MethodHeader::parse(&[0x16]).unwrap(); // (5 << 2) | 2
        assert!(matches!(hdr, MethodHeader::Tiny { code_size: 5 }));
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_tiny_header_code_size() {
        let hdr = MethodHeader::Tiny { code_size: 10 };
        assert_eq!(hdr.code_size(), 10);
        assert_eq!(hdr.max_stack(), 8);
        assert_eq!(hdr.local_var_sig_tok(), 0);
    }

    #[test]
    fn test_fat_header_parse() {
        let data = fat_body(&[0x2au8], 8, 0);
        let (hdr, consumed) = MethodHeader::parse(&data).unwrap();
        assert_eq!(consumed, 12);
        assert_eq!(hdr.code_size(), 1);
        assert_eq!(hdr.max_stack(), 8);
    }

    #[test]
    fn test_fat_header_truncated() {
        let data = vec![0x03u8; 4];
        assert!(matches!(
            MethodHeader::parse(&data),
            Err(IlError::TruncatedData { .. })
        ));
    }

    #[test]
    fn test_invalid_header_format() {
        assert!(matches!(
            MethodHeader::parse(&[0x00]),
            Err(IlError::InvalidHeaderFormat(_))
        ));
    }

    #[test]
    fn test_header_empty_data() {
        assert!(matches!(
            MethodHeader::parse(&[]),
            Err(IlError::TruncatedData { .. })
        ));
    }

    // ---- ExceptionHandler ----

    /// A fat EH section: kind byte, then a 24-bit DataSize that includes the
    /// 4-byte header, then `n` clauses of 24 bytes.
    fn fat_eh_section(kind: u8, clauses: usize) -> Vec<u8> {
        let total = 4 + clauses * 24;
        let mut v = vec![0u8; total];
        v[0] = kind;
        v[1] = (total & 0xff) as u8;
        v[2] = ((total >> 8) & 0xff) as u8;
        v[3] = ((total >> 16) & 0xff) as u8;
        v
    }

    #[test]
    fn fat_eh_section_with_more_sects_is_still_fat() {
        // 0xC1 is Fat|MoreSects. Testing the fat bit on a value that has had
        // 0x40 masked away can never see it, and the old `data[0] == 0x41`
        // special case does not cover this perfectly ordinary kind byte.
        let data = fat_eh_section(0xC1, 1);
        let handlers = parse_fat_exception_handlers(&data).expect("fat section parses");
        assert_eq!(handlers.len(), 1, "a Fat|MoreSects section holds fat clauses");
    }

    #[test]
    fn fat_eh_section_data_size_is_not_shifted() {
        // DataSize counts the 4-byte header, and is a plain 24-bit value: no
        // shift. Reading it shifted right by 8 turns a 2-clause section into
        // zero clauses, and the caller sees an empty handler list.
        let data = fat_eh_section(0x41, 2);
        let handlers = parse_fat_exception_handlers(&data).expect("fat section parses");
        assert_eq!(handlers.len(), 2);
    }

    #[test]
    fn small_eh_section_reads_data_size_from_byte_one() {
        // Small sections carry DataSize in byte 1, not byte 2, and it too
        // includes the header.
        let mut data = vec![0u8; 4 + 12];
        data[0] = 0x01; // EHTable, small format
        data[1] = 16; // 4 header + 12 clause
        let handlers = parse_fat_exception_handlers(&data).expect("small section parses");
        assert_eq!(handlers.len(), 1);
    }

    #[test]
    fn test_exception_handler_fat_finally() {
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(&2u32.to_le_bytes()); // Finally
        data[4..8].copy_from_slice(&10u32.to_le_bytes());
        data[8..12].copy_from_slice(&20u32.to_le_bytes());
        let eh = ExceptionHandler::parse_fat(&data).unwrap();
        assert_eq!(eh.clause_type, ExceptionClauseType::Finally);
        assert_eq!(eh.try_offset, 10);
        assert_eq!(eh.try_length, 20);
    }

    #[test]
    fn test_exception_handler_fat_catch() {
        let mut data = vec![0u8; 24];
        data[20..24].copy_from_slice(&0x0100_0002u32.to_le_bytes()); // type token
        let eh = ExceptionHandler::parse_fat(&data).unwrap();
        assert_eq!(eh.clause_type, ExceptionClauseType::Catch);
        assert_eq!(eh.class_token_or_filter_offset, 0x0100_0002);
    }

    #[test]
    fn test_exception_handler_invalid_type() {
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(&99u32.to_le_bytes());
        assert!(matches!(
            ExceptionHandler::parse_fat(&data),
            Err(IlError::InvalidExceptionClause(_))
        ));
    }

    #[test]
    fn test_exception_handler_truncated_fat() {
        assert!(matches!(
            ExceptionHandler::parse_fat(&[0u8; 12]),
            Err(IlError::TruncatedData { .. })
        ));
    }

    #[test]
    fn test_exception_handler_small_parse() {
        let mut data = vec![0u8; 12];
        data[0..2].copy_from_slice(&0u16.to_le_bytes()); // Catch
        let eh = ExceptionHandler::parse_small(&data).unwrap();
        assert_eq!(eh.clause_type, ExceptionClauseType::Catch);
    }

    // ---- IlMethodLoader ----

    #[test]
    fn test_load_tiny_ret() {
        // nop + ret
        let data = tiny_body(&[0x00, 0x2a]);
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        assert_eq!(loader.instruction_count(), 2);
        assert_eq!(loader.instructions[0].opcode.name, "nop");
        assert_eq!(loader.instructions[1].opcode.name, "ret");
    }

    #[test]
    fn test_load_ldc_i4_0() {
        let data = tiny_body(&[0x16]); // ldc.i4.0
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        assert_eq!(loader.instruction_count(), 1);
        assert_eq!(loader.instructions[0].opcode.name, "ldc.i4.0");
    }

    #[test]
    fn test_load_ldc_i4() {
        // ldc.i4 42
        let mut code = vec![0x20u8];
        code.extend_from_slice(&42i32.to_le_bytes());
        let data = tiny_body(&code);
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        assert_eq!(loader.instruction_count(), 1);
        if let Operand::Token(v) = loader.instructions[0].operand {
            assert_eq!(v, 42);
        } else {
            panic!("wrong operand");
        }
    }

    #[test]
    fn test_load_br_s() {
        // br.s +2 (branch 2 bytes forward)
        let code = vec![0x2bu8, 0x02, 0x2a]; // br.s 2; ret
        let data = tiny_body(&code);
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        let br = &loader.instructions[0];
        assert!(br.is_branch());
        assert!(br.is_unconditional_branch());
    }

    #[test]
    fn test_load_fe_prefix_ceq() {
        let code = vec![0xfeu8, 0x01, 0x2a]; // ceq; ret
        let data = tiny_body(&code);
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        assert_eq!(loader.instructions[0].opcode.name, "ceq");
    }

    #[test]
    fn test_load_call() {
        let mut code = vec![0x28u8]; // call
        code.extend_from_slice(&0x0A00_0001u32.to_le_bytes()); // method token
        code.push(0x2a); // ret
        let data = tiny_body(&code);
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        assert_eq!(loader.calls().len(), 1);
    }

    #[test]
    fn test_instruction_at() {
        let data = tiny_body(&[0x00, 0x2a]); // nop; ret
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        assert!(loader.instruction_at(0).is_some());
        assert!(loader.instruction_at(1).is_some());
        assert!(loader.instruction_at(99).is_none());
    }

    #[test]
    fn test_load_switch() {
        let mut code = vec![0x45u8]; // switch
        code.extend_from_slice(&2u32.to_le_bytes()); // 2 cases
        code.extend_from_slice(&5i32.to_le_bytes());
        code.extend_from_slice(&10i32.to_le_bytes());
        code.push(0x2a);
        let data = tiny_body(&code);
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        assert_eq!(loader.instruction_count(), 2); // switch + ret
        if let Operand::Switch(targets) = &loader.instructions[0].operand {
            assert_eq!(targets.len(), 2);
        } else {
            panic!("wrong operand");
        }
    }

    #[test]
    fn test_load_fat_body() {
        let code = vec![0x16u8, 0x2a]; // ldc.i4.0; ret
        let data = fat_body(&code, 2, 0);
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        assert_eq!(loader.instruction_count(), 2);
        assert_eq!(loader.header.max_stack(), 2);
    }

    #[test]
    fn test_operand_type_size() {
        assert_eq!(OperandType::InlineNone.size_bytes(), 0);
        assert_eq!(OperandType::ShortInlineI.size_bytes(), 1);
        assert_eq!(OperandType::InlineI.size_bytes(), 4);
        assert_eq!(OperandType::InlineI8.size_bytes(), 8);
        assert_eq!(OperandType::InlineVar.size_bytes(), 2);
    }

    #[test]
    fn test_il_error_display() {
        let e = IlError::UnknownOpcode(0xfe99);
        assert!(e.to_string().contains("fe99"));
        let e2 = IlError::TruncatedData {
            offset: 0x20,
            needed: 8,
        };
        assert!(e2.to_string().contains("20"));
    }

    #[test]
    fn test_load_ldarg_3_is_not_call() {
        let data = tiny_body(&[0x05]); // ldarg.3
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        assert!(!loader.instructions[0].is_call());
    }

    #[test]
    fn test_opcode_table_has_add() {
        let table = build_opcode_table();
        let op = table.get(&0x58).unwrap();
        assert_eq!(op.name, "add");
        assert_eq!(op.stack_delta, -1);
    }

    #[test]
    fn test_exception_clause_type_filter() {
        assert_eq!(
            ExceptionClauseType::from_u32(1).unwrap(),
            ExceptionClauseType::Filter
        );
    }

    #[test]
    fn test_exception_clause_type_fault() {
        assert_eq!(
            ExceptionClauseType::from_u32(4).unwrap(),
            ExceptionClauseType::Fault
        );
    }

    #[test]
    fn test_exception_clause_type_invalid() {
        assert!(matches!(
            ExceptionClauseType::from_u32(3),
            Err(IlError::InvalidExceptionClause(_))
        ));
    }

    #[test]
    fn test_load_ldc_i8() {
        let code = vec![0x1fu8, 0x64]; // ldc.i4.s 100
        let data = tiny_body(&code);
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        assert_eq!(loader.instructions[0].opcode.name, "ldc.i4.s");
        if let Operand::I8(v) = loader.instructions[0].operand {
            assert_eq!(v, 100i8);
        } else {
            panic!("expected I8");
        }
    }

    #[test]
    fn test_load_ldc_r4() {
        let mut code = vec![0x22u8]; // ldc.r4
        code.extend_from_slice(&1.0f32.to_bits().to_le_bytes());
        let data = tiny_body(&code);
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        if let Operand::F32(v) = loader.instructions[0].operand {
            assert!((v - 1.0).abs() < 1e-6);
        } else {
            panic!("expected F32");
        }
    }

    #[test]
    fn test_load_ldc_r8() {
        let mut code = vec![0x23u8]; // ldc.r8
        code.extend_from_slice(&3.14f64.to_bits().to_le_bytes());
        let data = tiny_body(&code);
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        if let Operand::F64(v) = loader.instructions[0].operand {
            assert!((v - 3.14_f64).abs() < 1e-9);
        } else {
            panic!("expected F64");
        }
    }

    #[test]
    fn test_load_ldc_i8_64bit_operand() {
        let mut code = vec![0x21u8]; // ldc.i8
        code.extend_from_slice(&0x12345678_9ABCDEF0i64.to_le_bytes());
        let data = tiny_body(&code);
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        if let Operand::I64(v) = loader.instructions[0].operand {
            assert_eq!(v, 0x12345678_9ABCDEF0u64 as i64);
        } else {
            panic!("expected I64");
        }
    }

    #[test]
    fn test_load_ldloc_s() {
        let code = vec![0x11u8, 5]; // ldloc.s local#5
        let data = tiny_body(&code);
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        assert_eq!(loader.instructions[0].opcode.name, "ldloc.s");
    }

    #[test]
    fn test_load_stloc_s() {
        let code = vec![0x13u8, 2]; // stloc.s local#2
        let data = tiny_body(&code);
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        assert_eq!(loader.instructions[0].opcode.name, "stloc.s");
    }

    #[test]
    fn test_load_callvirt() {
        let mut code = vec![0x6fu8]; // callvirt
        code.extend_from_slice(&0x0A00_0002u32.to_le_bytes());
        let data = tiny_body(&code);
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        assert!(loader.calls().len() == 1);
        assert_eq!(loader.instructions[0].opcode.name, "callvirt");
    }

    #[test]
    fn test_load_ldstr() {
        let mut code = vec![0x72u8]; // ldstr
        code.extend_from_slice(&0x7000_0001u32.to_le_bytes());
        let data = tiny_body(&code);
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        assert_eq!(loader.instructions[0].opcode.name, "ldstr");
    }

    #[test]
    fn test_load_inline_var_fe09() {
        let code = vec![0xfeu8, 0x09, 0x01, 0x00]; // ldarg 1
        let data = tiny_body(&code);
        let mut loader = IlMethodLoader::new();
        loader.load(&data).unwrap();
        assert_eq!(loader.instructions[0].opcode.name, "ldarg");
        if let Operand::VarIndex(v) = loader.instructions[0].operand {
            assert_eq!(v, 1);
        } else {
            panic!("expected VarIndex");
        }
    }

    #[test]
    fn test_header_has_more_sections_false_for_tiny() {
        let hdr = MethodHeader::Tiny { code_size: 4 };
        assert!(!hdr.has_more_sections());
    }

    #[test]
    fn test_fat_header_has_more_sections_flag() {
        // flags with bit 3 set = has more sections
        let code = [0x2au8];
        let mut data = fat_body(&code, 8, 0);
        let flags: u16 = 0x3003 | 0x08; // add MoreSects bit
        data[0..2].copy_from_slice(&flags.to_le_bytes());
        let (hdr, _) = MethodHeader::parse(&data).unwrap();
        assert!(hdr.has_more_sections());
    }

    #[test]
    fn test_local_var_sig_fields() {
        let sig = LocalVarSig::new(0x1100_0001, 3, vec![0x07, 0x03, 0x08]);
        assert_eq!(sig.local_count, 3);
        assert_eq!(sig.token, 0x1100_0001);
    }

    #[test]
    fn test_operand_type_switch_size_zero() {
        assert_eq!(OperandType::InlineSwitch.size_bytes(), 0);
    }

    #[test]
    fn test_fat_body_local_sig_token() {
        let code = [0x2au8]; // ret
        let data = fat_body(&code, 4, 0x1100_0005);
        let (hdr, _) = MethodHeader::parse(&data).unwrap();
        assert_eq!(hdr.local_var_sig_tok(), 0x1100_0005);
    }

    #[test]
    fn test_il_error_stack_underflow_display() {
        let e = IlError::StackUnderflow { offset: 0x80 };
        assert!(e.to_string().contains("80"));
    }

    #[test]
    fn test_opcode_table_has_ceq() {
        let table = build_opcode_table();
        assert!(table.contains_key(&0xfe01));
    }

    #[test]
    fn test_opcode_table_has_sizeof() {
        let table = build_opcode_table();
        assert!(table.contains_key(&0xfe1c));
    }
}

// ---------------------------------------------------------------------------
// IlExceptionHandlerTable - batch parse exception handler sections
// ---------------------------------------------------------------------------

/// Parse all fat exception handlers from a section following a fat method body.
pub fn parse_fat_exception_handlers(data: &[u8]) -> Result<Vec<ExceptionHandler>, IlError> {
    if data.len() < 4 {
        return Ok(vec![]);
    }
    let _kind = data[0] & 0x3f;
    // Test the fat bit on the raw byte: `kind` has it masked off by `& 0x3f`,
    // so `kind & 0x40` can never be true. The old code compensated with a
    // `data[0] == 0x41` special case, which missed every other fat section —
    // 0xC1 (Fat|MoreSects) among them — and silently parsed it as thin.
    let is_fat = data[0] & 0x40 != 0;
    // DataSize is a 24-bit little-endian field at bytes 1..3 for fat sections
    // and a single byte at 1 for small ones, and in both cases it counts the
    // 4-byte section header itself.
    let count = if is_fat {
        let data_size =
            u32::from_le_bytes([data[1], data[2], data[3], 0]) as usize & 0x00FF_FFFF;
        data_size.saturating_sub(4) / 24
    } else {
        (data[1] as usize).saturating_sub(4) / 12
    };
    const MAX: usize = 256;
    if count > MAX {
        return Err(IlError::TooManyExceptionHandlers(count));
    }
    let mut handlers = Vec::with_capacity(count);
    let _ = is_fat;
    let header_size = 4;
    let clause_size = if is_fat { 24 } else { 12 };
    for i in 0..count {
        let off = header_size + i * clause_size;
        if off + clause_size > data.len() {
            break;
        }
        let eh = if is_fat {
            ExceptionHandler::parse_fat(&data[off..])?
        } else {
            ExceptionHandler::parse_small(&data[off..])?
        };
        handlers.push(eh);
    }
    Ok(handlers)
}
// ---------------------------------------------------------------------------
// CilFlowGraph - simplified flow graph construction
// ---------------------------------------------------------------------------

/// A basic block in the CIL flow graph.
#[derive(Debug, Clone)]
pub struct CilBlock {
    pub start_offset: u32,
    pub end_offset: u32,
    pub successors: Vec<u32>,
}

impl CilBlock {
    #[must_use] 
    pub const fn new(start: u32, end: u32) -> Self {
        Self {
            start_offset: start,
            end_offset: end,
            successors: Vec::new(),
        }
    }
    #[must_use] 
    pub const fn contains(&self, offset: u32) -> bool {
        offset >= self.start_offset && offset < self.end_offset
    }
    #[must_use] 
    pub const fn length(&self) -> u32 {
        self.end_offset.saturating_sub(self.start_offset)
    }
}

/// Build a minimal flow graph from IL instructions.
#[must_use] 
pub fn build_cil_flow_graph(instructions: &[IlInstruction]) -> Vec<CilBlock> {
    if instructions.is_empty() {
        return vec![];
    }
    let mut leaders: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    leaders.insert(instructions[0].offset);
    for instr in instructions {
        if instr.is_branch() && let Some(target) = instr.branch_target() {
            if target >= 0 {
                leaders.insert(target as u32);
            }
            // Fall-through is also a leader
            let fall = instr.offset + instr.raw_bytes.len() as u32;
            leaders.insert(fall);
        }
    }
    let leader_vec: Vec<u32> = leaders.into_iter().collect();
    let mut blocks = Vec::with_capacity(leader_vec.len());
    for (i, &start) in leader_vec.iter().enumerate() {
        let end = leader_vec.get(i + 1).copied().unwrap_or(
            instructions
                .last()
                .map_or(start, |i| i.offset + i.raw_bytes.len() as u32),
        );
        blocks.push(CilBlock::new(start, end));
    }
    blocks
}

// ---------------------------------------------------------------------------
// CilSizeCalculator - IL byte size utilities
// ---------------------------------------------------------------------------

/// Calculate the total IL byte size of a list of instructions.
#[must_use] 
pub fn cil_total_bytes(instructions: &[IlInstruction]) -> usize {
    instructions.iter().map(|i| i.raw_bytes.len()).sum()
}
