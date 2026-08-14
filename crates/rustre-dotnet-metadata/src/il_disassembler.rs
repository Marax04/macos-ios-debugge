//! `il_disassembler` — .NET CIL (Common Intermediate Language) disassembler.
//!
//! Decodes all CIL opcodes including the 0xFE prefix extended set, decodes
//! all operand kinds, produces human-readable IL text, and computes per-
//! instruction stack deltas.

use std::fmt;
use std::collections::HashMap;

// ── IlOperand ─────────────────────────────────────────────────────────────────

/// Decoded operand of a CIL instruction.
#[derive(Debug, Clone, PartialEq)]
pub enum IlOperand {
    /// No operand.
    None,
    /// Inline 8-bit signed integer.
    InlineI8(i8),
    /// Inline 8-bit unsigned integer (short branch target or variable index).
    InlineU8(u8),
    /// Inline 16-bit unsigned integer.
    InlineU16(u16),
    /// Inline 32-bit signed integer.
    InlineI32(i32),
    /// Inline 64-bit signed integer.
    InlineI64(i64),
    /// Inline 32-bit float.
    InlineR4(f32),
    /// Inline 64-bit float.
    InlineR8(f64),
    /// Inline metadata token (TypeRef/TypeDef/TypeSpec/MethodRef/FieldRef etc.).
    InlineToken(u32),
    /// Inline string token (index into `#US` heap).
    InlineString(u32),
    /// Inline method token.
    InlineMethod(u32),
    /// Inline field token.
    InlineField(u32),
    /// Inline type token.
    InlineType(u32),
    /// Inline sig token (StandAloneSig).
    InlineSig(u32),
    /// Inline branch target (byte offset from instruction end).
    BranchTarget(i32),
    /// Short branch target (byte offset, 8-bit signed).
    ShortBranchTarget(i8),
    /// Switch table: default fallthrough + list of branch targets.
    Switch(Vec<i32>),
    /// Local variable index.
    VarIndex(u16),
    /// Argument index.
    ArgIndex(u16),
}

impl fmt::Display for IlOperand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => Ok(()),
            Self::InlineI8(v) => write!(f, "{v}"),
            Self::InlineU8(v) => write!(f, "{v}"),
            Self::InlineU16(v) => write!(f, "{v}"),
            Self::InlineI32(v) => write!(f, "{v}"),
            Self::InlineI64(v) => write!(f, "{v}L"),
            Self::InlineR4(v) => write!(f, "{v:.6}"),
            Self::InlineR8(v) => write!(f, "{v:.10}"),
            Self::InlineToken(t) | Self::InlineMethod(t)
          | Self::InlineField(t) | Self::InlineType(t)
          | Self::InlineSig(t) => write!(f, "0x{t:08X}"),
            Self::InlineString(s) => write!(f, "0x{s:08X}"),
            Self::BranchTarget(o) => write!(f, "{o:+}"),
            Self::ShortBranchTarget(o) => write!(f, "{o:+}"),
            Self::Switch(targets) => {
                write!(f, "(")?;
                for (i, t) in targets.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{t:+}")?;
                }
                write!(f, ")")
            }
            Self::VarIndex(i) => write!(f, "V_{i}"),
            Self::ArgIndex(i) => write!(f, "A_{i}"),
        }
    }
}

// ── IlOpcode ──────────────────────────────────────────────────────────────────

/// All CIL opcodes (ECMA-335 §III).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IlOpcode {
    // ── Single-byte opcodes ────────────────────────────────────────────────
    Nop, Break,
    Ldarg0, Ldarg1, Ldarg2, Ldarg3,
    Ldloc0, Ldloc1, Ldloc2, Ldloc3,
    Stloc0, Stloc1, Stloc2, Stloc3,
    LdargS, LdargaS, StargS,
    LdlocS, LdlocaS, StlocS,
    Ldnull,
    LdcI4M1, LdcI40, LdcI41, LdcI42, LdcI43, LdcI44,
    LdcI45, LdcI46, LdcI47, LdcI48,
    LdcI4S, LdcI4, LdcI8, LdcR4, LdcR8,
    Dup, Pop,
    Jmp, Call, Calli, Ret,
    BrS, BrfalseS, BrtrueS,
    BeqS, BgeS, BgtS, BleS, BltS, BneUnS, BgeUnS, BgtUnS, BleUnS, BltUnS,
    Br, Brfalse, Brtrue,
    Beq, Bge, Bgt, Ble, Blt, BneUn, BgeUn, BgtUn, BleUn, BltUn,
    Switch,
    LdindI1, LdindU1, LdindI2, LdindU2, LdindI4, LdindU4,
    LdindI8, LdindI, LdindR4, LdindR8, LdindRef,
    StindRef, StindI1, StindI2, StindI4, StindI8, StindR4, StindR8,
    Add, Sub, Mul, Div, DivUn, Rem, RemUn,
    And, Or, Xor, Shl, Shr, ShrUn,
    Neg, Not,
    ConvI1, ConvI2, ConvI4, ConvI8,
    ConvR4, ConvR8, ConvU4, ConvU8,
    Callvirt, Cpobj, Ldobj, Ldstr,
    Newobj, Castclass, Isinst,
    ConvRUn, Unbox, Throw,
    Ldfld, Ldflda, Stfld, Ldsfld, Ldsflda, Stsfld,
    Stobj, ConvOvfI1Un, ConvOvfI2Un, ConvOvfI4Un, ConvOvfI8Un,
    ConvOvfU1Un, ConvOvfU2Un, ConvOvfU4Un, ConvOvfU8Un,
    ConvOvfIUn, ConvOvfUUn,
    Box, Newarr, Ldlen, Ldelema,
    LdelemI1, LdelemU1, LdelemI2, LdelemU2, LdelemI4, LdelemU4,
    LdelemI8, LdelemI, LdelemR4, LdelemR8, LdelemRef,
    StelemI, StelemI1, StelemI2, StelemI4, StelemI8, StelemR4, StelemR8, StelemRef,
    Stelem, Ldelem, UnboxAny,
    ConvOvfI1, ConvOvfU1, ConvOvfI2, ConvOvfU2, ConvOvfI4, ConvOvfU4,
    ConvOvfI8, ConvOvfU8,
    Refanyval, Ckfinite, Mkrefany,
    Ldtoken, ConvU2, ConvU1, ConvI, ConvOvfI, ConvOvfU, AddOvf, AddOvfUn,
    MulOvf, MulOvfUn, SubOvf, SubOvfUn, Endfinally, Leave, LeaveS, StindI,
    ConvU,
    // ── 0xFE prefixed opcodes ──────────────────────────────────────────────
    Arglist, Ceq, Cgt, CgtUn, Clt, CltUn,
    Ldftn, Ldvirtftn, Ldarg, Ldarga, Starg,
    Ldloc, Ldloca, Stloc, Localloc,
    Endfilter, Unaligned, Volatile, Tail, Initobj,
    Constrained, Cpblk, Initblk, No, Rethrow,
    Sizeof, Refanytype, Readonly,
    /// Unknown / reserved opcode.
    Unknown(u8, u8),
}

impl IlOpcode {
    pub fn mnemonic(self) -> &'static str {
        match self {
            Self::Nop => "nop", Self::Break => "break",
            Self::Ldarg0 => "ldarg.0", Self::Ldarg1 => "ldarg.1",
            Self::Ldarg2 => "ldarg.2", Self::Ldarg3 => "ldarg.3",
            Self::Ldloc0 => "ldloc.0", Self::Ldloc1 => "ldloc.1",
            Self::Ldloc2 => "ldloc.2", Self::Ldloc3 => "ldloc.3",
            Self::Stloc0 => "stloc.0", Self::Stloc1 => "stloc.1",
            Self::Stloc2 => "stloc.2", Self::Stloc3 => "stloc.3",
            Self::LdargS => "ldarg.s", Self::LdargaS => "ldarga.s",
            Self::StargS => "starg.s",
            Self::LdlocS => "ldloc.s", Self::LdlocaS => "ldloca.s",
            Self::StlocS => "stloc.s",
            Self::Ldnull => "ldnull",
            Self::LdcI4M1 => "ldc.i4.m1", Self::LdcI40 => "ldc.i4.0",
            Self::LdcI41 => "ldc.i4.1",   Self::LdcI42 => "ldc.i4.2",
            Self::LdcI43 => "ldc.i4.3",   Self::LdcI44 => "ldc.i4.4",
            Self::LdcI45 => "ldc.i4.5",   Self::LdcI46 => "ldc.i4.6",
            Self::LdcI47 => "ldc.i4.7",   Self::LdcI48 => "ldc.i4.8",
            Self::LdcI4S => "ldc.i4.s",   Self::LdcI4 => "ldc.i4",
            Self::LdcI8 => "ldc.i8",       Self::LdcR4 => "ldc.r4",
            Self::LdcR8 => "ldc.r8",
            Self::Dup => "dup",             Self::Pop => "pop",
            Self::Jmp => "jmp",             Self::Call => "call",
            Self::Calli => "calli",         Self::Ret => "ret",
            Self::BrS => "br.s",           Self::BrfalseS => "brfalse.s",
            Self::BrtrueS => "brtrue.s",
            Self::BeqS => "beq.s",         Self::BgeS => "bge.s",
            Self::BgtS => "bgt.s",         Self::BleS => "ble.s",
            Self::BltS => "blt.s",         Self::BneUnS => "bne.un.s",
            Self::BgeUnS => "bge.un.s",    Self::BgtUnS => "bgt.un.s",
            Self::BleUnS => "ble.un.s",    Self::BltUnS => "blt.un.s",
            Self::Br => "br",              Self::Brfalse => "brfalse",
            Self::Brtrue => "brtrue",
            Self::Beq => "beq",            Self::Bge => "bge",
            Self::Bgt => "bgt",            Self::Ble => "ble",
            Self::Blt => "blt",            Self::BneUn => "bne.un",
            Self::BgeUn => "bge.un",       Self::BgtUn => "bgt.un",
            Self::BleUn => "ble.un",       Self::BltUn => "blt.un",
            Self::Switch => "switch",
            Self::LdindI1 => "ldind.i1",  Self::LdindU1 => "ldind.u1",
            Self::LdindI2 => "ldind.i2",  Self::LdindU2 => "ldind.u2",
            Self::LdindI4 => "ldind.i4",  Self::LdindU4 => "ldind.u4",
            Self::LdindI8 => "ldind.i8",  Self::LdindI  => "ldind.i",
            Self::LdindR4 => "ldind.r4",  Self::LdindR8 => "ldind.r8",
            Self::LdindRef => "ldind.ref",
            Self::StindRef => "stind.ref", Self::StindI1 => "stind.i1",
            Self::StindI2 => "stind.i2",  Self::StindI4 => "stind.i4",
            Self::StindI8 => "stind.i8",  Self::StindR4 => "stind.r4",
            Self::StindR8 => "stind.r8",
            Self::Add => "add",            Self::Sub => "sub",
            Self::Mul => "mul",            Self::Div => "div",
            Self::DivUn => "div.un",       Self::Rem => "rem",
            Self::RemUn => "rem.un",
            Self::And => "and",            Self::Or => "or",
            Self::Xor => "xor",            Self::Shl => "shl",
            Self::Shr => "shr",            Self::ShrUn => "shr.un",
            Self::Neg => "neg",            Self::Not => "not",
            Self::ConvI1 => "conv.i1",     Self::ConvI2 => "conv.i2",
            Self::ConvI4 => "conv.i4",     Self::ConvI8 => "conv.i8",
            Self::ConvR4 => "conv.r4",     Self::ConvR8 => "conv.r8",
            Self::ConvU4 => "conv.u4",     Self::ConvU8 => "conv.u8",
            Self::Callvirt => "callvirt",  Self::Cpobj => "cpobj",
            Self::Ldobj => "ldobj",        Self::Ldstr => "ldstr",
            Self::Newobj => "newobj",      Self::Castclass => "castclass",
            Self::Isinst => "isinst",
            Self::ConvRUn => "conv.r.un",  Self::Unbox => "unbox",
            Self::Throw => "throw",
            Self::Ldfld => "ldfld",        Self::Ldflda => "ldflda",
            Self::Stfld => "stfld",        Self::Ldsfld => "ldsfld",
            Self::Ldsflda => "ldsflda",    Self::Stsfld => "stsfld",
            Self::Stobj => "stobj",
            Self::ConvOvfI1Un => "conv.ovf.i1.un",
            Self::ConvOvfI2Un => "conv.ovf.i2.un",
            Self::ConvOvfI4Un => "conv.ovf.i4.un",
            Self::ConvOvfI8Un => "conv.ovf.i8.un",
            Self::ConvOvfU1Un => "conv.ovf.u1.un",
            Self::ConvOvfU2Un => "conv.ovf.u2.un",
            Self::ConvOvfU4Un => "conv.ovf.u4.un",
            Self::ConvOvfU8Un => "conv.ovf.u8.un",
            Self::ConvOvfIUn => "conv.ovf.i.un",
            Self::ConvOvfUUn => "conv.ovf.u.un",
            Self::Box => "box",            Self::Newarr => "newarr",
            Self::Ldlen => "ldlen",        Self::Ldelema => "ldelema",
            Self::LdelemI1 => "ldelem.i1", Self::LdelemU1 => "ldelem.u1",
            Self::LdelemI2 => "ldelem.i2", Self::LdelemU2 => "ldelem.u2",
            Self::LdelemI4 => "ldelem.i4", Self::LdelemU4 => "ldelem.u4",
            Self::LdelemI8 => "ldelem.i8", Self::LdelemI  => "ldelem.i",
            Self::LdelemR4 => "ldelem.r4", Self::LdelemR8 => "ldelem.r8",
            Self::LdelemRef => "ldelem.ref",
            Self::StelemI  => "stelem.i",  Self::StelemI1 => "stelem.i1",
            Self::StelemI2 => "stelem.i2", Self::StelemI4 => "stelem.i4",
            Self::StelemI8 => "stelem.i8", Self::StelemR4 => "stelem.r4",
            Self::StelemR8 => "stelem.r8", Self::StelemRef => "stelem.ref",
            Self::Stelem => "stelem",      Self::Ldelem => "ldelem",
            Self::UnboxAny => "unbox.any",
            Self::ConvOvfI1 => "conv.ovf.i1", Self::ConvOvfU1 => "conv.ovf.u1",
            Self::ConvOvfI2 => "conv.ovf.i2", Self::ConvOvfU2 => "conv.ovf.u2",
            Self::ConvOvfI4 => "conv.ovf.i4", Self::ConvOvfU4 => "conv.ovf.u4",
            Self::ConvOvfI8 => "conv.ovf.i8", Self::ConvOvfU8 => "conv.ovf.u8",
            Self::Refanyval => "refanyval", Self::Ckfinite => "ckfinite",
            Self::Mkrefany => "mkrefany",
            Self::Ldtoken => "ldtoken",    Self::ConvU2 => "conv.u2",
            Self::ConvU1 => "conv.u1",     Self::ConvI => "conv.i",
            Self::ConvOvfI => "conv.ovf.i", Self::ConvOvfU => "conv.ovf.u",
            Self::AddOvf => "add.ovf",     Self::AddOvfUn => "add.ovf.un",
            Self::MulOvf => "mul.ovf",     Self::MulOvfUn => "mul.ovf.un",
            Self::SubOvf => "sub.ovf",     Self::SubOvfUn => "sub.ovf.un",
            Self::Endfinally => "endfinally", Self::Leave => "leave",
            Self::LeaveS => "leave.s",     Self::StindI => "stind.i",
            Self::ConvU => "conv.u",
            // 0xFE prefixed
            Self::Arglist => "arglist",    Self::Ceq => "ceq",
            Self::Cgt => "cgt",            Self::CgtUn => "cgt.un",
            Self::Clt => "clt",            Self::CltUn => "clt.un",
            Self::Ldftn => "ldftn",        Self::Ldvirtftn => "ldvirtftn",
            Self::Ldarg => "ldarg",        Self::Ldarga => "ldarga",
            Self::Starg => "starg",        Self::Ldloc => "ldloc",
            Self::Ldloca => "ldloca",      Self::Stloc => "stloc",
            Self::Localloc => "localloc",  Self::Endfilter => "endfilter",
            Self::Unaligned => "unaligned.", Self::Volatile => "volatile.",
            Self::Tail => "tail.",         Self::Initobj => "initobj",
            Self::Constrained => "constrained.", Self::Cpblk => "cpblk",
            Self::Initblk => "initblk",    Self::No => "no.",
            Self::Rethrow => "rethrow",    Self::Sizeof => "sizeof",
            Self::Refanytype => "refanytype", Self::Readonly => "readonly.",
            Self::Unknown(_, _) => "unknown",
        }
    }
}

impl fmt::Display for IlOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.mnemonic())
    }
}

// ── StackEffect ───────────────────────────────────────────────────────────────

/// Net change to the evaluation stack depth caused by one instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StackEffect {
    /// How many values are popped.
    pub pop: i32,
    /// How many values are pushed.
    pub push: i32,
}

impl StackEffect {
    pub const fn new(pop: i32, push: i32) -> Self { Self { pop, push } }
    /// Net delta (+push − pop).
    pub const fn delta(self) -> i32 { self.push - self.pop }
    pub const ZERO: Self = Self::new(0, 0);
    pub const PUSH1: Self = Self::new(0, 1);
    pub const POP1: Self  = Self::new(1, 0);
    pub const POP2: Self  = Self::new(2, 0);
    pub const POP2_PUSH1: Self = Self::new(2, 1);
    pub const POP1_PUSH1: Self = Self::new(1, 1);
}

// ── IlInstruction ─────────────────────────────────────────────────────────────

/// A decoded CIL instruction.
#[derive(Debug, Clone)]
pub struct IlInstruction {
    /// Byte offset within the method body (from start of IL stream).
    pub offset: u32,
    /// Opcode.
    pub opcode: IlOpcode,
    /// Decoded operand.
    pub operand: IlOperand,
    /// Total byte size of this instruction (opcode + operand bytes).
    pub size: u32,
    /// Stack effect.
    pub stack_effect: StackEffect,
}

impl IlInstruction {
    /// Compute the absolute branch target offset for branch instructions.
    pub fn branch_target(&self) -> Option<u32> {
        let base = self.offset + self.size;
        match &self.operand {
            IlOperand::BranchTarget(delta) => {
                let target = (base as i64) + (*delta as i64);
                if target >= 0 { Some(target as u32) } else { None }
            }
            IlOperand::ShortBranchTarget(delta) => {
                let target = (base as i64) + (*delta as i64);
                if target >= 0 { Some(target as u32) } else { None }
            }
            _ => None,
        }
    }
}

impl fmt::Display for IlInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IL_{:04X}: {}", self.offset, self.opcode)?;
        match &self.operand {
            IlOperand::None => Ok(()),
            op => write!(f, " {op}"),
        }
    }
}

// ── Decode helpers ─────────────────────────────────────────────────────────────

fn read_u8(data: &[u8], pos: usize) -> Option<u8> {
    data.get(pos).copied()
}
fn read_i8(data: &[u8], pos: usize) -> Option<i8> {
    data.get(pos).map(|&b| b as i8)
}

fn read_u16(data: &[u8], pos: usize) -> Option<u16> {
    if pos + 2 > data.len() { return None; }
    Some(u16::from_le_bytes([data[pos], data[pos+1]]))
}
fn read_i32(data: &[u8], pos: usize) -> Option<i32> {
    if pos + 4 > data.len() { return None; }
    Some(i32::from_le_bytes(data[pos..pos+4].try_into().unwrap()))
}
fn read_u32(data: &[u8], pos: usize) -> Option<u32> {
    if pos + 4 > data.len() { return None; }
    Some(u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()))
}
fn read_i64(data: &[u8], pos: usize) -> Option<i64> {
    if pos + 8 > data.len() { return None; }
    Some(i64::from_le_bytes(data[pos..pos+8].try_into().unwrap()))
}
fn read_f32(data: &[u8], pos: usize) -> Option<f32> {
    if pos + 4 > data.len() { return None; }
    let bits = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap());
    Some(f32::from_bits(bits))
}
fn read_f64(data: &[u8], pos: usize) -> Option<f64> {
    if pos + 8 > data.len() { return None; }
    let bits = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap());
    Some(f64::from_bits(bits))
}

// ── IlDisassembler ────────────────────────────────────────────────────────────

/// Decodes a raw byte slice as CIL method body instructions.
pub struct IlDisassembler<'a> {
    /// Raw IL bytes (method body, starting after the fat/tiny header).
    pub data: &'a [u8],
}

impl<'a> IlDisassembler<'a> {
    pub fn new(data: &'a [u8]) -> Self { Self { data } }

    /// Decode all instructions in the IL stream, returning them in order.
    pub fn decode_all(&self) -> Vec<IlInstruction> {
        // IL instructions average ~2 bytes; pre-allocate a reasonable estimate.
        let mut result = Vec::with_capacity(self.data.len() / 2 + 1);
        let mut pos = 0usize;
        while pos < self.data.len() {
            match self.decode_one(pos as u32) {
                Some(instr) => {
                    pos += instr.size as usize;
                    result.push(instr);
                }
                None => break,
            }
        }
        result
    }

    /// Decode a single instruction at byte offset `at`.
    pub fn decode_one(&self, at: u32) -> Option<IlInstruction> {
        let base = at as usize;
        let b0 = read_u8(self.data, base)?;
        if b0 == 0xFE {
            // Extended opcode
            let b1 = read_u8(self.data, base + 1)?;
            let (opcode, operand, op_size) = self.decode_fe(b1, base + 2)?;
            let size = 2 + op_size;
            let effect = stack_effect_fe(b1);
            return Some(IlInstruction {
                offset: at, opcode, operand,
                size: size as u32, stack_effect: effect,
            });
        }
        let (opcode, operand, op_size) = self.decode_single(b0, base + 1)?;
        let size = 1 + op_size;
        let effect = stack_effect_single(b0);
        Some(IlInstruction {
            offset: at, opcode, operand,
            size: size as u32, stack_effect: effect,
        })
    }

    fn decode_single(&self, b: u8, pos: usize) -> Option<(IlOpcode, IlOperand, usize)> {
        let d = self.data;
        let r = match b {
            0x00 => (IlOpcode::Nop,     IlOperand::None, 0),
            0x01 => (IlOpcode::Break,   IlOperand::None, 0),
            0x02 => (IlOpcode::Ldarg0,  IlOperand::None, 0),
            0x03 => (IlOpcode::Ldarg1,  IlOperand::None, 0),
            0x04 => (IlOpcode::Ldarg2,  IlOperand::None, 0),
            0x05 => (IlOpcode::Ldarg3,  IlOperand::None, 0),
            0x06 => (IlOpcode::Ldloc0,  IlOperand::None, 0),
            0x07 => (IlOpcode::Ldloc1,  IlOperand::None, 0),
            0x08 => (IlOpcode::Ldloc2,  IlOperand::None, 0),
            0x09 => (IlOpcode::Ldloc3,  IlOperand::None, 0),
            0x0A => (IlOpcode::Stloc0,  IlOperand::None, 0),
            0x0B => (IlOpcode::Stloc1,  IlOperand::None, 0),
            0x0C => (IlOpcode::Stloc2,  IlOperand::None, 0),
            0x0D => (IlOpcode::Stloc3,  IlOperand::None, 0),
            0x0E => (IlOpcode::LdargS,  IlOperand::ArgIndex(read_u8(d,pos)? as u16), 1),
            0x0F => (IlOpcode::LdargaS, IlOperand::ArgIndex(read_u8(d,pos)? as u16), 1),
            0x10 => (IlOpcode::StargS,  IlOperand::ArgIndex(read_u8(d,pos)? as u16), 1),
            0x11 => (IlOpcode::LdlocS,  IlOperand::VarIndex(read_u8(d,pos)? as u16), 1),
            0x12 => (IlOpcode::LdlocaS, IlOperand::VarIndex(read_u8(d,pos)? as u16), 1),
            0x13 => (IlOpcode::StlocS,  IlOperand::VarIndex(read_u8(d,pos)? as u16), 1),
            0x14 => (IlOpcode::Ldnull,  IlOperand::None, 0),
            0x15 => (IlOpcode::LdcI4M1, IlOperand::None, 0),
            0x16 => (IlOpcode::LdcI40,  IlOperand::None, 0),
            0x17 => (IlOpcode::LdcI41,  IlOperand::None, 0),
            0x18 => (IlOpcode::LdcI42,  IlOperand::None, 0),
            0x19 => (IlOpcode::LdcI43,  IlOperand::None, 0),
            0x1A => (IlOpcode::LdcI44,  IlOperand::None, 0),
            0x1B => (IlOpcode::LdcI45,  IlOperand::None, 0),
            0x1C => (IlOpcode::LdcI46,  IlOperand::None, 0),
            0x1D => (IlOpcode::LdcI47,  IlOperand::None, 0),
            0x1E => (IlOpcode::LdcI48,  IlOperand::None, 0),
            0x1F => (IlOpcode::LdcI4S,  IlOperand::InlineI8(read_i8(d,pos)?), 1),
            0x20 => (IlOpcode::LdcI4,   IlOperand::InlineI32(read_i32(d,pos)?), 4),
            0x21 => (IlOpcode::LdcI8,   IlOperand::InlineI64(read_i64(d,pos)?), 8),
            0x22 => (IlOpcode::LdcR4,   IlOperand::InlineR4(read_f32(d,pos)?), 4),
            0x23 => (IlOpcode::LdcR8,   IlOperand::InlineR8(read_f64(d,pos)?), 8),
            0x25 => (IlOpcode::Dup,     IlOperand::None, 0),
            0x26 => (IlOpcode::Pop,     IlOperand::None, 0),
            0x27 => (IlOpcode::Jmp,     IlOperand::InlineMethod(read_u32(d,pos)?), 4),
            0x28 => (IlOpcode::Call,    IlOperand::InlineMethod(read_u32(d,pos)?), 4),
            0x29 => (IlOpcode::Calli,   IlOperand::InlineSig(read_u32(d,pos)?), 4),
            0x2A => (IlOpcode::Ret,     IlOperand::None, 0),
            0x2B => (IlOpcode::BrS,     IlOperand::ShortBranchTarget(read_i8(d,pos)?), 1),
            0x2C => (IlOpcode::BrfalseS,IlOperand::ShortBranchTarget(read_i8(d,pos)?), 1),
            0x2D => (IlOpcode::BrtrueS, IlOperand::ShortBranchTarget(read_i8(d,pos)?), 1),
            0x2E => (IlOpcode::BeqS,    IlOperand::ShortBranchTarget(read_i8(d,pos)?), 1),
            0x2F => (IlOpcode::BgeS,    IlOperand::ShortBranchTarget(read_i8(d,pos)?), 1),
            0x30 => (IlOpcode::BgtS,    IlOperand::ShortBranchTarget(read_i8(d,pos)?), 1),
            0x31 => (IlOpcode::BleS,    IlOperand::ShortBranchTarget(read_i8(d,pos)?), 1),
            0x32 => (IlOpcode::BltS,    IlOperand::ShortBranchTarget(read_i8(d,pos)?), 1),
            0x33 => (IlOpcode::BneUnS,  IlOperand::ShortBranchTarget(read_i8(d,pos)?), 1),
            0x34 => (IlOpcode::BgeUnS,  IlOperand::ShortBranchTarget(read_i8(d,pos)?), 1),
            0x35 => (IlOpcode::BgtUnS,  IlOperand::ShortBranchTarget(read_i8(d,pos)?), 1),
            0x36 => (IlOpcode::BleUnS,  IlOperand::ShortBranchTarget(read_i8(d,pos)?), 1),
            0x37 => (IlOpcode::BltUnS,  IlOperand::ShortBranchTarget(read_i8(d,pos)?), 1),
            0x38 => (IlOpcode::Br,      IlOperand::BranchTarget(read_i32(d,pos)?), 4),
            0x39 => (IlOpcode::Brfalse, IlOperand::BranchTarget(read_i32(d,pos)?), 4),
            0x3A => (IlOpcode::Brtrue,  IlOperand::BranchTarget(read_i32(d,pos)?), 4),
            0x3B => (IlOpcode::Beq,     IlOperand::BranchTarget(read_i32(d,pos)?), 4),
            0x3C => (IlOpcode::Bge,     IlOperand::BranchTarget(read_i32(d,pos)?), 4),
            0x3D => (IlOpcode::Bgt,     IlOperand::BranchTarget(read_i32(d,pos)?), 4),
            0x3E => (IlOpcode::Ble,     IlOperand::BranchTarget(read_i32(d,pos)?), 4),
            0x3F => (IlOpcode::Blt,     IlOperand::BranchTarget(read_i32(d,pos)?), 4),
            0x40 => (IlOpcode::BneUn,   IlOperand::BranchTarget(read_i32(d,pos)?), 4),
            0x41 => (IlOpcode::BgeUn,   IlOperand::BranchTarget(read_i32(d,pos)?), 4),
            0x42 => (IlOpcode::BgtUn,   IlOperand::BranchTarget(read_i32(d,pos)?), 4),
            0x43 => (IlOpcode::BleUn,   IlOperand::BranchTarget(read_i32(d,pos)?), 4),
            0x44 => (IlOpcode::BltUn,   IlOperand::BranchTarget(read_i32(d,pos)?), 4),
            0x45 => {
                let n_raw = read_u32(d, pos)?;
                // Guard against attacker-controlled count: each entry is 4 bytes plus the
                // 4-byte count field.  If n * 4 would exceed remaining bytes, the stream
                // is truncated; we stop here rather than allocating gigabytes or wrapping.
                let remaining_after_count = d.len().saturating_sub(pos + 4);
                let n = n_raw as usize;
                let total_bytes = n.saturating_mul(4);
                if total_bytes > remaining_after_count {
                    return None; // truncated switch table
                }
                let mut targets = Vec::with_capacity(n);
                for i in 0..n {
                    targets.push(read_i32(d, pos + 4 + i * 4)?);
                }
                (IlOpcode::Switch, IlOperand::Switch(targets), 4 + n * 4)
            }
            0x46 => (IlOpcode::LdindI1,  IlOperand::None, 0),
            0x47 => (IlOpcode::LdindU1,  IlOperand::None, 0),
            0x48 => (IlOpcode::LdindI2,  IlOperand::None, 0),
            0x49 => (IlOpcode::LdindU2,  IlOperand::None, 0),
            0x4A => (IlOpcode::LdindI4,  IlOperand::None, 0),
            0x4B => (IlOpcode::LdindU4,  IlOperand::None, 0),
            0x4C => (IlOpcode::LdindI8,  IlOperand::None, 0),
            0x4D => (IlOpcode::LdindI,   IlOperand::None, 0),
            0x4E => (IlOpcode::LdindR4,  IlOperand::None, 0),
            0x4F => (IlOpcode::LdindR8,  IlOperand::None, 0),
            0x50 => (IlOpcode::LdindRef, IlOperand::None, 0),
            0x51 => (IlOpcode::StindRef, IlOperand::None, 0),
            0x52 => (IlOpcode::StindI1,  IlOperand::None, 0),
            0x53 => (IlOpcode::StindI2,  IlOperand::None, 0),
            0x54 => (IlOpcode::StindI4,  IlOperand::None, 0),
            0x55 => (IlOpcode::StindI8,  IlOperand::None, 0),
            0x56 => (IlOpcode::StindR4,  IlOperand::None, 0),
            0x57 => (IlOpcode::StindR8,  IlOperand::None, 0),
            0x58 => (IlOpcode::Add,    IlOperand::None, 0),
            0x59 => (IlOpcode::Sub,    IlOperand::None, 0),
            0x5A => (IlOpcode::Mul,    IlOperand::None, 0),
            0x5B => (IlOpcode::Div,    IlOperand::None, 0),
            0x5C => (IlOpcode::DivUn,  IlOperand::None, 0),
            0x5D => (IlOpcode::Rem,    IlOperand::None, 0),
            0x5E => (IlOpcode::RemUn,  IlOperand::None, 0),
            0x5F => (IlOpcode::And,    IlOperand::None, 0),
            0x60 => (IlOpcode::Or,     IlOperand::None, 0),
            0x61 => (IlOpcode::Xor,    IlOperand::None, 0),
            0x62 => (IlOpcode::Shl,    IlOperand::None, 0),
            0x63 => (IlOpcode::Shr,    IlOperand::None, 0),
            0x64 => (IlOpcode::ShrUn,  IlOperand::None, 0),
            0x65 => (IlOpcode::Neg,    IlOperand::None, 0),
            0x66 => (IlOpcode::Not,    IlOperand::None, 0),
            0x67 => (IlOpcode::ConvI1, IlOperand::None, 0),
            0x68 => (IlOpcode::ConvI2, IlOperand::None, 0),
            0x69 => (IlOpcode::ConvI4, IlOperand::None, 0),
            0x6A => (IlOpcode::ConvI8, IlOperand::None, 0),
            0x6B => (IlOpcode::ConvR4, IlOperand::None, 0),
            0x6C => (IlOpcode::ConvR8, IlOperand::None, 0),
            0x6D => (IlOpcode::ConvU4, IlOperand::None, 0),
            0x6E => (IlOpcode::ConvU8, IlOperand::None, 0),
            0x6F => (IlOpcode::Callvirt, IlOperand::InlineMethod(read_u32(d,pos)?), 4),
            0x70 => (IlOpcode::Cpobj,    IlOperand::InlineType(read_u32(d,pos)?), 4),
            0x71 => (IlOpcode::Ldobj,    IlOperand::InlineType(read_u32(d,pos)?), 4),
            0x72 => (IlOpcode::Ldstr,    IlOperand::InlineString(read_u32(d,pos)?), 4),
            0x73 => (IlOpcode::Newobj,   IlOperand::InlineMethod(read_u32(d,pos)?), 4),
            0x74 => (IlOpcode::Castclass,IlOperand::InlineType(read_u32(d,pos)?), 4),
            0x75 => (IlOpcode::Isinst,   IlOperand::InlineType(read_u32(d,pos)?), 4),
            0x76 => (IlOpcode::ConvRUn,  IlOperand::None, 0),
            0x79 => (IlOpcode::Unbox,    IlOperand::InlineType(read_u32(d,pos)?), 4),
            0x7A => (IlOpcode::Throw,    IlOperand::None, 0),
            0x7B => (IlOpcode::Ldfld,    IlOperand::InlineField(read_u32(d,pos)?), 4),
            0x7C => (IlOpcode::Ldflda,   IlOperand::InlineField(read_u32(d,pos)?), 4),
            0x7D => (IlOpcode::Stfld,    IlOperand::InlineField(read_u32(d,pos)?), 4),
            0x7E => (IlOpcode::Ldsfld,   IlOperand::InlineField(read_u32(d,pos)?), 4),
            0x7F => (IlOpcode::Ldsflda,  IlOperand::InlineField(read_u32(d,pos)?), 4),
            0x80 => (IlOpcode::Stsfld,   IlOperand::InlineField(read_u32(d,pos)?), 4),
            0x81 => (IlOpcode::Stobj,    IlOperand::InlineType(read_u32(d,pos)?), 4),
            0x82 => (IlOpcode::ConvOvfI1Un, IlOperand::None, 0),
            0x83 => (IlOpcode::ConvOvfI2Un, IlOperand::None, 0),
            0x84 => (IlOpcode::ConvOvfI4Un, IlOperand::None, 0),
            0x85 => (IlOpcode::ConvOvfI8Un, IlOperand::None, 0),
            0x86 => (IlOpcode::ConvOvfU1Un, IlOperand::None, 0),
            0x87 => (IlOpcode::ConvOvfU2Un, IlOperand::None, 0),
            0x88 => (IlOpcode::ConvOvfU4Un, IlOperand::None, 0),
            0x89 => (IlOpcode::ConvOvfU8Un, IlOperand::None, 0),
            0x8A => (IlOpcode::ConvOvfIUn,  IlOperand::None, 0),
            0x8B => (IlOpcode::ConvOvfUUn,  IlOperand::None, 0),
            0x8C => (IlOpcode::Box,     IlOperand::InlineType(read_u32(d,pos)?), 4),
            0x8D => (IlOpcode::Newarr,  IlOperand::InlineType(read_u32(d,pos)?), 4),
            0x8E => (IlOpcode::Ldlen,   IlOperand::None, 0),
            0x8F => (IlOpcode::Ldelema, IlOperand::InlineType(read_u32(d,pos)?), 4),
            0x90 => (IlOpcode::LdelemI1, IlOperand::None, 0),
            0x91 => (IlOpcode::LdelemU1, IlOperand::None, 0),
            0x92 => (IlOpcode::LdelemI2, IlOperand::None, 0),
            0x93 => (IlOpcode::LdelemU2, IlOperand::None, 0),
            0x94 => (IlOpcode::LdelemI4, IlOperand::None, 0),
            0x95 => (IlOpcode::LdelemU4, IlOperand::None, 0),
            0x96 => (IlOpcode::LdelemI8, IlOperand::None, 0),
            0x97 => (IlOpcode::LdelemI,  IlOperand::None, 0),
            0x98 => (IlOpcode::LdelemR4, IlOperand::None, 0),
            0x99 => (IlOpcode::LdelemR8, IlOperand::None, 0),
            0x9A => (IlOpcode::LdelemRef,IlOperand::None, 0),
            0x9B => (IlOpcode::StelemI,  IlOperand::None, 0),
            0x9C => (IlOpcode::StelemI1, IlOperand::None, 0),
            0x9D => (IlOpcode::StelemI2, IlOperand::None, 0),
            0x9E => (IlOpcode::StelemI4, IlOperand::None, 0),
            0x9F => (IlOpcode::StelemI8, IlOperand::None, 0),
            0xA0 => (IlOpcode::StelemR4, IlOperand::None, 0),
            0xA1 => (IlOpcode::StelemR8, IlOperand::None, 0),
            0xA2 => (IlOpcode::StelemRef,IlOperand::None, 0),
            0xA3 => (IlOpcode::Stelem,  IlOperand::InlineType(read_u32(d,pos)?), 4),
            0xA4 => (IlOpcode::Ldelem,  IlOperand::InlineType(read_u32(d,pos)?), 4),
            0xA5 => (IlOpcode::UnboxAny,IlOperand::InlineType(read_u32(d,pos)?), 4),
            0xB3 => (IlOpcode::ConvOvfI1,IlOperand::None, 0),
            0xB4 => (IlOpcode::ConvOvfU1,IlOperand::None, 0),
            0xB5 => (IlOpcode::ConvOvfI2,IlOperand::None, 0),
            0xB6 => (IlOpcode::ConvOvfU2,IlOperand::None, 0),
            0xB7 => (IlOpcode::ConvOvfI4,IlOperand::None, 0),
            0xB8 => (IlOpcode::ConvOvfU4,IlOperand::None, 0),
            0xB9 => (IlOpcode::ConvOvfI8,IlOperand::None, 0),
            0xBA => (IlOpcode::ConvOvfU8,IlOperand::None, 0),
            0xC2 => (IlOpcode::Refanyval,IlOperand::InlineType(read_u32(d,pos)?), 4),
            0xC3 => (IlOpcode::Ckfinite, IlOperand::None, 0),
            0xC6 => (IlOpcode::Mkrefany, IlOperand::InlineType(read_u32(d,pos)?), 4),
            0xD0 => (IlOpcode::Ldtoken,  IlOperand::InlineToken(read_u32(d,pos)?), 4),
            0xD1 => (IlOpcode::ConvU2,   IlOperand::None, 0),
            0xD2 => (IlOpcode::ConvU1,   IlOperand::None, 0),
            0xD3 => (IlOpcode::ConvI,    IlOperand::None, 0),
            0xD4 => (IlOpcode::ConvOvfI, IlOperand::None, 0),
            0xD5 => (IlOpcode::ConvOvfU, IlOperand::None, 0),
            0xD6 => (IlOpcode::AddOvf,   IlOperand::None, 0),
            0xD7 => (IlOpcode::AddOvfUn, IlOperand::None, 0),
            0xD8 => (IlOpcode::MulOvf,   IlOperand::None, 0),
            0xD9 => (IlOpcode::MulOvfUn, IlOperand::None, 0),
            0xDA => (IlOpcode::SubOvf,   IlOperand::None, 0),
            0xDB => (IlOpcode::SubOvfUn, IlOperand::None, 0),
            0xDC => (IlOpcode::Endfinally, IlOperand::None, 0),
            0xDD => (IlOpcode::Leave,    IlOperand::BranchTarget(read_i32(d,pos)?), 4),
            0xDE => (IlOpcode::LeaveS,   IlOperand::ShortBranchTarget(read_i8(d,pos)?), 1),
            0xDF => (IlOpcode::StindI,   IlOperand::None, 0),
            0xE0 => (IlOpcode::ConvU,    IlOperand::None, 0),
            _ => (IlOpcode::Unknown(b, 0), IlOperand::None, 0),
        };
        Some(r)
    }

    fn decode_fe(&self, b: u8, pos: usize) -> Option<(IlOpcode, IlOperand, usize)> {
        let d = self.data;
        let r = match b {
            0x00 => (IlOpcode::Arglist,    IlOperand::None, 0),
            0x01 => (IlOpcode::Ceq,        IlOperand::None, 0),
            0x02 => (IlOpcode::Cgt,        IlOperand::None, 0),
            0x03 => (IlOpcode::CgtUn,      IlOperand::None, 0),
            0x04 => (IlOpcode::Clt,        IlOperand::None, 0),
            0x05 => (IlOpcode::CltUn,      IlOperand::None, 0),
            0x06 => (IlOpcode::Ldftn,      IlOperand::InlineMethod(read_u32(d,pos)?), 4),
            0x07 => (IlOpcode::Ldvirtftn,  IlOperand::InlineMethod(read_u32(d,pos)?), 4),
            0x09 => (IlOpcode::Ldarg,      IlOperand::ArgIndex(read_u16(d,pos)?), 2),
            0x0A => (IlOpcode::Ldarga,     IlOperand::ArgIndex(read_u16(d,pos)?), 2),
            0x0B => (IlOpcode::Starg,      IlOperand::ArgIndex(read_u16(d,pos)?), 2),
            0x0C => (IlOpcode::Ldloc,      IlOperand::VarIndex(read_u16(d,pos)?), 2),
            0x0D => (IlOpcode::Ldloca,     IlOperand::VarIndex(read_u16(d,pos)?), 2),
            0x0E => (IlOpcode::Stloc,      IlOperand::VarIndex(read_u16(d,pos)?), 2),
            0x0F => (IlOpcode::Localloc,   IlOperand::None, 0),
            0x11 => (IlOpcode::Endfilter,  IlOperand::None, 0),
            0x12 => (IlOpcode::Unaligned,  IlOperand::InlineU8(read_u8(d,pos)?), 1),
            0x13 => (IlOpcode::Volatile,   IlOperand::None, 0),
            0x14 => (IlOpcode::Tail,       IlOperand::None, 0),
            0x15 => (IlOpcode::Initobj,    IlOperand::InlineType(read_u32(d,pos)?), 4),
            0x16 => (IlOpcode::Constrained,IlOperand::InlineType(read_u32(d,pos)?), 4),
            0x17 => (IlOpcode::Cpblk,      IlOperand::None, 0),
            0x18 => (IlOpcode::Initblk,    IlOperand::None, 0),
            0x19 => (IlOpcode::No,         IlOperand::InlineU8(read_u8(d,pos)?), 1),
            0x1A => (IlOpcode::Rethrow,    IlOperand::None, 0),
            0x1C => (IlOpcode::Sizeof,     IlOperand::InlineType(read_u32(d,pos)?), 4),
            0x1D => (IlOpcode::Refanytype, IlOperand::None, 0),
            0x1E => (IlOpcode::Readonly,   IlOperand::None, 0),
            _ => (IlOpcode::Unknown(0xFE, b), IlOperand::None, 0),
        };
        Some(r)
    }
}

// ── Stack effect tables ────────────────────────────────────────────────────────

fn stack_effect_single(b: u8) -> StackEffect {
    match b {
        0x00 | 0x01 => StackEffect::ZERO, // nop, break
        0x02..=0x05 => StackEffect::PUSH1, // ldarg.0..3
        0x06..=0x09 => StackEffect::PUSH1, // ldloc.0..3
        0x0A..=0x0D => StackEffect::POP1,  // stloc.0..3
        0x0E | 0x0F => StackEffect::PUSH1, // ldarg.s, ldarga.s
        0x10 => StackEffect::POP1,          // starg.s
        0x11 | 0x12 => StackEffect::PUSH1, // ldloc.s, ldloca.s
        0x13 => StackEffect::POP1,          // stloc.s
        0x14..=0x1E => StackEffect::PUSH1, // ldnull, ldc.i4.*
        0x1F | 0x20 => StackEffect::PUSH1, // ldc.i4.s, ldc.i4
        0x21..=0x23 => StackEffect::PUSH1, // ldc.i8, ldc.r4, ldc.r8
        0x25 => StackEffect::PUSH1,         // dup
        0x26 => StackEffect::POP1,          // pop
        0x27 => StackEffect::ZERO,          // jmp (clears stack)
        0x28 => StackEffect::new(0, 1),     // call (approximate — depends on sig)
        0x29 => StackEffect::new(0, 1),     // calli
        0x2A => StackEffect::ZERO,          // ret
        0x2B => StackEffect::ZERO,          // br.s
        0x2C | 0x2D => StackEffect::POP1,  // brfalse.s, brtrue.s
        0x2E..=0x37 => StackEffect::POP2,  // beq.s .. blt.un.s
        0x38 => StackEffect::ZERO,          // br
        0x39 | 0x3A => StackEffect::POP1,  // brfalse, brtrue
        0x3B..=0x44 => StackEffect::POP2,  // beq .. blt.un
        0x45 => StackEffect::POP1,          // switch
        0x46..=0x50 => StackEffect::POP1_PUSH1, // ldind.*
        0x51..=0x57 => StackEffect::POP2,  // stind.*
        0x58..=0x64 => StackEffect::POP2_PUSH1, // add..not (binary/unary)
        0x65 | 0x66 => StackEffect::POP1_PUSH1, // neg, not
        0x67..=0x6E => StackEffect::POP1_PUSH1, // conv.*
        0x6F => StackEffect::new(1, 1),    // callvirt (approx)
        0x70 => StackEffect::POP2,          // cpobj
        0x71 => StackEffect::POP1_PUSH1,   // ldobj
        0x72 => StackEffect::PUSH1,         // ldstr
        0x73 => StackEffect::PUSH1,         // newobj (approx)
        0x74 | 0x75 => StackEffect::POP1_PUSH1, // castclass, isinst
        0x76 => StackEffect::POP1_PUSH1,   // conv.r.un
        0x79 => StackEffect::POP1_PUSH1,   // unbox
        0x7A => StackEffect::POP1,          // throw
        0x7B => StackEffect::POP1_PUSH1,   // ldfld
        0x7C => StackEffect::POP1_PUSH1,   // ldflda
        0x7D => StackEffect::POP2,          // stfld
        0x7E => StackEffect::PUSH1,         // ldsfld
        0x7F => StackEffect::PUSH1,         // ldsflda
        0x80 => StackEffect::POP1,          // stsfld
        0x81 => StackEffect::POP2,          // stobj
        0x82..=0x8B => StackEffect::POP1_PUSH1, // conv.ovf.*
        0x8C | 0x8D => StackEffect::POP1_PUSH1, // box, newarr
        0x8E => StackEffect::POP1_PUSH1,   // ldlen
        0x8F => StackEffect::new(2, 1),    // ldelema
        0x90..=0x9A => StackEffect::new(2, 1), // ldelem.*
        0x9B..=0xA2 => StackEffect::new(3, 0), // stelem.*
        0xA3..=0xA5 => StackEffect::POP1_PUSH1,
        0xB3..=0xBA => StackEffect::POP1_PUSH1, // conv.ovf.*
        0xC2 | 0xC6 => StackEffect::POP1_PUSH1,
        0xC3 => StackEffect::POP1_PUSH1,
        0xD0 => StackEffect::PUSH1,
        0xD1..=0xD5 => StackEffect::POP1_PUSH1,
        0xD6..=0xDB => StackEffect::POP2_PUSH1,
        0xDC | 0xDE => StackEffect::ZERO,  // endfinally, leave.s
        0xDD => StackEffect::ZERO,          // leave
        0xDF => StackEffect::POP2,          // stind.i
        0xE0 => StackEffect::POP1_PUSH1,   // conv.u
        _ => StackEffect::ZERO,
    }
}

fn stack_effect_fe(b: u8) -> StackEffect {
    match b {
        0x00 => StackEffect::PUSH1,         // arglist
        0x01..=0x05 => StackEffect::POP2_PUSH1, // ceq, cgt, cgt.un, clt, clt.un
        0x06 | 0x07 => StackEffect::PUSH1, // ldftn, ldvirtftn
        0x09 | 0x0A => StackEffect::PUSH1, // ldarg, ldarga
        0x0B => StackEffect::POP1,          // starg
        0x0C | 0x0D => StackEffect::PUSH1, // ldloc, ldloca
        0x0E => StackEffect::POP1,          // stloc
        0x0F => StackEffect::POP1_PUSH1,   // localloc
        0x11 => StackEffect::POP1,          // endfilter
        0x12 => StackEffect::ZERO,          // unaligned.
        0x13 | 0x14 => StackEffect::ZERO,  // volatile., tail.
        0x15 => StackEffect::POP1,          // initobj
        0x16 => StackEffect::ZERO,          // constrained.
        0x17 => StackEffect::new(3, 0),    // cpblk
        0x18 => StackEffect::new(3, 0),    // initblk
        0x19 => StackEffect::ZERO,          // no.
        0x1A => StackEffect::ZERO,          // rethrow
        0x1C => StackEffect::PUSH1,         // sizeof
        0x1D => StackEffect::POP1_PUSH1,   // refanytype
        0x1E => StackEffect::ZERO,          // readonly.
        _ => StackEffect::ZERO,
    }
}

// ── Disassemble to text ────────────────────────────────────────────────────────

/// Disassemble a raw IL byte slice to a multi-line string.
pub fn disassemble_to_text(il_bytes: &[u8]) -> String {
    let disasm = IlDisassembler::new(il_bytes);
    let instrs = disasm.decode_all();
    let mut out = String::new();
    for instr in &instrs {
        out.push_str(&instr.to_string());
        out.push('\n');
    }
    out
}

/// Build a map from IL offset to instruction index.
pub fn build_offset_map(instrs: &[IlInstruction]) -> HashMap<u32, usize> {
    instrs.iter().enumerate().map(|(i, ins)| (ins.offset, i)).collect()
}

/// Compute max stack depth (simple linear scan, not full CFG analysis).
pub fn compute_max_stack(instrs: &[IlInstruction]) -> i32 {
    let mut depth: i32 = 0;
    let mut max: i32 = 0;
    for instr in instrs {
        depth += instr.stack_effect.delta();
        if depth < 0 { depth = 0; }
        if depth > max { max = depth; }
    }
    max
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_nop() {
        let disasm = IlDisassembler::new(&[0x00]);
        let instrs = disasm.decode_all();
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].opcode, IlOpcode::Nop);
        assert_eq!(instrs[0].size, 1);
    }

    #[test]
    fn decode_ldarg0_through_3() {
        let bytes = [0x02, 0x03, 0x04, 0x05];
        let d = IlDisassembler::new(&bytes);
        let instrs = d.decode_all();
        assert_eq!(instrs.len(), 4);
        assert_eq!(instrs[0].opcode, IlOpcode::Ldarg0);
        assert_eq!(instrs[3].opcode, IlOpcode::Ldarg3);
    }

    #[test]
    fn decode_ldc_i4() {
        let bytes = [0x20, 0x2A, 0x00, 0x00, 0x00]; // ldc.i4 42
        let d = IlDisassembler::new(&bytes);
        let instrs = d.decode_all();
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].opcode, IlOpcode::LdcI4);
        assert_eq!(instrs[0].operand, IlOperand::InlineI32(42));
        assert_eq!(instrs[0].size, 5);
    }

    #[test]
    fn decode_call() {
        let bytes = [0x28, 0x01, 0x00, 0x00, 0x0A]; // call token
        let d = IlDisassembler::new(&bytes);
        let instrs = d.decode_all();
        assert_eq!(instrs[0].opcode, IlOpcode::Call);
        assert!(matches!(instrs[0].operand, IlOperand::InlineMethod(_)));
    }

    #[test]
    fn decode_ret() {
        let bytes = [0x2A];
        let d = IlDisassembler::new(&bytes);
        let instrs = d.decode_all();
        assert_eq!(instrs[0].opcode, IlOpcode::Ret);
    }

    #[test]
    fn decode_br_short() {
        let bytes = [0x2B, 0x01]; // br.s +1
        let d = IlDisassembler::new(&bytes);
        let instrs = d.decode_all();
        assert_eq!(instrs[0].opcode, IlOpcode::BrS);
        assert_eq!(instrs[0].branch_target(), Some(3));
    }

    #[test]
    fn decode_ldstr() {
        let bytes = [0x72, 0x01, 0x00, 0x00, 0x70];
        let d = IlDisassembler::new(&bytes);
        let instrs = d.decode_all();
        assert_eq!(instrs[0].opcode, IlOpcode::Ldstr);
    }

    #[test]
    fn decode_switch() {
        // switch 2 targets
        let bytes = [0x45, 0x02, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00];
        let d = IlDisassembler::new(&bytes);
        let instrs = d.decode_all();
        assert_eq!(instrs[0].opcode, IlOpcode::Switch);
        assert!(matches!(instrs[0].operand, IlOperand::Switch(ref v) if v.len() == 2));
    }

    #[test]
    fn decode_fe_ceq() {
        let bytes = [0xFE, 0x01];
        let d = IlDisassembler::new(&bytes);
        let instrs = d.decode_all();
        assert_eq!(instrs[0].opcode, IlOpcode::Ceq);
        assert_eq!(instrs[0].size, 2);
    }

    #[test]
    fn decode_fe_ldarg() {
        let bytes = [0xFE, 0x09, 0x0F, 0x00]; // ldarg 15
        let d = IlDisassembler::new(&bytes);
        let instrs = d.decode_all();
        assert_eq!(instrs[0].opcode, IlOpcode::Ldarg);
        assert_eq!(instrs[0].operand, IlOperand::ArgIndex(15));
    }

    #[test]
    fn decode_multiple_instructions() {
        // ldarg.0, ldarg.1, add, ret
        let bytes = [0x02, 0x03, 0x58, 0x2A];
        let d = IlDisassembler::new(&bytes);
        let instrs = d.decode_all();
        assert_eq!(instrs.len(), 4);
        assert_eq!(instrs[2].opcode, IlOpcode::Add);
    }

    #[test]
    fn stack_effect_add() {
        let bytes = [0x58];
        let d = IlDisassembler::new(&bytes);
        let instrs = d.decode_all();
        assert_eq!(instrs[0].stack_effect.pop, 2);
        assert_eq!(instrs[0].stack_effect.push, 1);
        assert_eq!(instrs[0].stack_effect.delta(), -1);
    }

    #[test]
    fn max_stack_simple() {
        // ldarg.0, ldarg.1, add, ret — max depth 2
        let bytes = [0x02, 0x03, 0x58, 0x2A];
        let d = IlDisassembler::new(&bytes);
        let instrs = d.decode_all();
        assert_eq!(compute_max_stack(&instrs), 2);
    }

    #[test]
    fn disassemble_to_text_nonempty() {
        let bytes = [0x00, 0x2A]; // nop, ret
        let text = disassemble_to_text(&bytes);
        assert!(text.contains("nop"));
        assert!(text.contains("ret"));
    }

    #[test]
    fn opcode_mnemonic_display() {
        assert_eq!(IlOpcode::Callvirt.mnemonic(), "callvirt");
        assert_eq!(IlOpcode::Newobj.mnemonic(), "newobj");
        assert_eq!(IlOpcode::Sizeof.mnemonic(), "sizeof");
    }

    #[test]
    fn instruction_display() {
        let instr = IlInstruction {
            offset: 0,
            opcode: IlOpcode::LdcI4,
            operand: IlOperand::InlineI32(100),
            size: 5,
            stack_effect: StackEffect::PUSH1,
        };
        assert_eq!(instr.to_string(), "IL_0000: ldc.i4 100");
    }

    #[test]
    fn offset_map_built_correctly() {
        let bytes = [0x02, 0x03, 0x58, 0x2A];
        let d = IlDisassembler::new(&bytes);
        let instrs = d.decode_all();
        let map = build_offset_map(&instrs);
        assert_eq!(map[&0], 0);
        assert_eq!(map[&1], 1);
        assert_eq!(map[&2], 2);
        assert_eq!(map[&3], 3);
    }

    #[test]
    fn empty_il_produces_no_instructions() {
        let d = IlDisassembler::new(&[]);
        assert!(d.decode_all().is_empty());
    }
}
