//! CIL method body editor — read, rewrite, and patch individual method bodies
//! in a .NET PE without round-tripping through a full assembler.
//!
//! Supports tiny and fat headers, local variable signatures, exception handling
//! clauses, instruction insertion/deletion, branch-target fixup, and output
//! serialisation back to a raw byte sequence suitable for splicing into the PE.

use std::collections::HashMap;
use std::fmt;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// CIL instruction set (subset covering ~95 % of real-world usage)
// ─────────────────────────────────────────────────────────────────────────────

/// Single-byte opcode or 0xFE prefix + second byte.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum Opcode {
    // Object model
    Nop, Ldnull, Dup, Pop, Ret,
    // Load/store arguments
    LdargS(u8), StargS(u8), Ldarg0, Ldarg1, Ldarg2, Ldarg3,
    LdargaN(u16), StargN(u16),
    // Load/store locals
    LdlocS(u8), StlocS(u8), LdlocA(u8), Ldloc0, Ldloc1, Ldloc2, Ldloc3,
    LdlocN(u16), StlocN(u16),
    // Integer constants
    LdcI4(i32), LdcI8(i64), LdcR4(u32), LdcR8(u64),
    LdcI4S(i8), LdcI4M1, LdcI4_0, LdcI4_1, LdcI4_2, LdcI4_3, LdcI4_4, LdcI4_5, LdcI4_6, LdcI4_7, LdcI4_8,
    // Arithmetic
    Add, Sub, Mul, Div, Rem, Neg, And, Or, Xor, Not, Shl, Shr, ShrUn,
    AddOvf, AddOvfUn, SubOvf, SubOvfUn, MulOvf, MulOvfUn,
    Conv(ConvTarget), ConvOvf(ConvTarget), ConvOvfUn(ConvTarget),
    // Comparison
    Ceq, Cgt, CgtUn, Clt, CltUn,
    // Branching
    Br(i32), Brfalse(i32), Brtrue(i32),
    Beq(i32), Bne(i32), Bge(i32), Bgt(i32), Ble(i32), Blt(i32),
    BgeUn(i32), BgtUn(i32), BleUn(i32), BltUn(i32), BneUn(i32),
    BrS(i8), BrfalseS(i8), BrtrueS(i8),
    BeqS(i8), BneS(i8), BgeS(i8), BgtS(i8), BleS(i8), BltS(i8),
    BgeUnS(i8), BgtUnS(i8), BleUnS(i8), BltUnS(i8),
    Switch(Vec<i32>),
    // Method calls
    Call(u32), Callvirt(u32), Calli(u32), Newobj(u32), Ldftn(u32), Ldvirtftn(u32),
    // Field access
    Ldfld(u32), Ldflda(u32), Stfld(u32), Ldsfld(u32), Ldsflda(u32), Stsfld(u32),
    // Object / type
    Newobj2(u32), Castclass(u32), Isinst(u32), Box(u32), Unbox(u32), UnboxAny(u32),
    Ldtoken(u32), Sizeof(u32), Refanyval(u32), Mkrefany(u32), Refanytype,
    // Arrays
    Newarr(u32), Ldlen, LdelemRef, StelemRef,
    Ldelem(u32), Stelem(u32), LdelemI1, LdelemU1, LdelemI2, LdelemU2,
    Ldelema(u32),
    LdelemI4, LdelemU4, LdelemI8, LdelemR4, LdelemR8,
    StelemI1, StelemI2, StelemI4, StelemI8, StelemR4, StelemR8,
    // Indirect load/store
    LdindI1, LdindU1, LdindI2, LdindU2, LdindI4, LdindU4, LdindI8,
    LdindR4, LdindR8, LdindI, LdindRef,
    StindI1, StindI2, StindI4, StindI8, StindR4, StindR8, StindI, StindRef,
    // Misc
    Ckfinite, Localloc, Volatile, Tailcall, Constrained(u32), Readonly,
    Initobj(u32), Cpobj(u32), Ldobj(u32), Stobj(u32), Cpblk, Initblk,
    Jmp(u32), Throw, Rethrow, Endfinally, Endfilter, Leave(i32), LeaveS(i8),
    // String
    Ldstr(u32),
    // Prefixed (0xFE)
    Arglist, Break, Starg(u16), Stloc(u16), Localloc2, Endfilter2, Unaligned(u8),
    LdlocA2(u16), Cpblk2, Initblk2,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum ConvTarget { I1, I2, I4, I8, R4, R8, U1, U2, U4, U8, I, U, Ovf }

// ─────────────────────────────────────────────────────────────────────────────
// Instruction with offset tracking
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Instruction {
    /// Byte offset from start of the method body instructions area.
    pub offset: u32,
    pub opcode: Opcode,
    /// Optional user label for branch targets.
    pub label: Option<String>,
}

impl Instruction {
    #[must_use] 
    pub const fn new(offset: u32, opcode: Opcode) -> Self {
        Self { offset, opcode, label: None }
    }
    pub fn labeled(offset: u32, opcode: Opcode, label: impl Into<String>) -> Self {
        Self { offset, opcode, label: Some(label.into()) }
    }
    /// Encoded byte size of this instruction.
    #[must_use] 
    pub const fn byte_size(&self) -> usize {
        encoded_size(&self.opcode)
    }
}

const fn encoded_size(op: &Opcode) -> usize {
    match op {
        Opcode::Ceq | Opcode::Cgt | Opcode::CgtUn | Opcode::Clt | Opcode::CltUn => 3, // 0xFE prefix
        Opcode::LdargS(_) | Opcode::StargS(_) | Opcode::LdlocS(_) | Opcode::StlocS(_)
        | Opcode::LdlocA(_) | Opcode::LdcI4S(_) | Opcode::BrS(_) | Opcode::BrfalseS(_)
        | Opcode::BrtrueS(_) | Opcode::BeqS(_) | Opcode::BneS(_) | Opcode::BgeS(_)
        | Opcode::BgtS(_) | Opcode::BleS(_) | Opcode::BltS(_) | Opcode::BgeUnS(_)
        | Opcode::BgtUnS(_) | Opcode::BleUnS(_) | Opcode::BltUnS(_)
        | Opcode::LeaveS(_) | Opcode::Unaligned(_) => 2,
        Opcode::LdcI4(_) | Opcode::Br(_) | Opcode::Brfalse(_) | Opcode::Brtrue(_)
        | Opcode::Beq(_) | Opcode::Bne(_) | Opcode::Bge(_) | Opcode::Bgt(_)
        | Opcode::Ble(_) | Opcode::Blt(_) | Opcode::BgeUn(_) | Opcode::BgtUn(_)
        | Opcode::BleUn(_) | Opcode::BltUn(_) | Opcode::BneUn(_) | Opcode::Leave(_) | Opcode::LdcR4(_) | Opcode::Call(_) | Opcode::Callvirt(_) | Opcode::Calli(_) | Opcode::Newobj(_)
        | Opcode::Newobj2(_) | Opcode::Ldftn(_) | Opcode::Ldvirtftn(_)
        | Opcode::Ldfld(_) | Opcode::Ldflda(_) | Opcode::Stfld(_)
        | Opcode::Ldsfld(_) | Opcode::Ldsflda(_) | Opcode::Stsfld(_)
        | Opcode::Castclass(_) | Opcode::Isinst(_) | Opcode::Box(_)
        | Opcode::Unbox(_) | Opcode::UnboxAny(_) | Opcode::Ldtoken(_)
        | Opcode::Sizeof(_) | Opcode::Refanyval(_) | Opcode::Mkrefany(_)
        | Opcode::Newarr(_) | Opcode::Ldelem(_) | Opcode::Stelem(_) | Opcode::Ldelema(_)
        | Opcode::Initobj(_) | Opcode::Cpobj(_) | Opcode::Ldobj(_) | Opcode::Stobj(_)
        | Opcode::Constrained(_) | Opcode::Jmp(_) | Opcode::Ldstr(_) => 5,
        Opcode::LdcI8(_) | Opcode::LdcR8(_) => 9,
        Opcode::LdargaN(_) | Opcode::StargN(_) | Opcode::LdlocN(_) | Opcode::StlocN(_) | Opcode::Starg(_) | Opcode::Stloc(_) | Opcode::LdlocA2(_) => 4, // 0xFE + opcode + u16
        Opcode::Nop | Opcode::Ldnull | Opcode::Dup | Opcode::Pop | Opcode::Ret | Opcode::Ldarg0 | Opcode::Ldarg1 | Opcode::Ldarg2 | Opcode::Ldarg3 | Opcode::Ldloc0 | Opcode::Ldloc1 | Opcode::Ldloc2 | Opcode::Ldloc3 | Opcode::LdcI4M1 | Opcode::LdcI4_0 | Opcode::LdcI4_1 | Opcode::LdcI4_2
        | Opcode::LdcI4_3 | Opcode::LdcI4_4 | Opcode::LdcI4_5 | Opcode::LdcI4_6
        | Opcode::LdcI4_7 | Opcode::LdcI4_8 | Opcode::Add | Opcode::Sub | Opcode::Mul | Opcode::Div | Opcode::Rem
        | Opcode::Neg | Opcode::And | Opcode::Or | Opcode::Xor | Opcode::Not
        | Opcode::Shl | Opcode::Shr | Opcode::ShrUn | Opcode::Ldlen | Opcode::LdelemRef | Opcode::StelemRef | Opcode::LdelemI1
        | Opcode::LdelemU1 | Opcode::LdelemI2 | Opcode::LdelemU2 | Opcode::LdelemI4
        | Opcode::LdelemU4 | Opcode::LdelemI8 | Opcode::LdelemR4 | Opcode::LdelemR8
        | Opcode::StelemI1 | Opcode::StelemI2 | Opcode::StelemI4 | Opcode::StelemI8
        | Opcode::StelemR4 | Opcode::StelemR8 | Opcode::LdindI1 | Opcode::LdindU1
        | Opcode::LdindI2 | Opcode::LdindU2 | Opcode::LdindI4 | Opcode::LdindU4
        | Opcode::LdindI8 | Opcode::LdindR4 | Opcode::LdindR8 | Opcode::LdindI
        | Opcode::LdindRef | Opcode::StindI1 | Opcode::StindI2 | Opcode::StindI4
        | Opcode::StindI8 | Opcode::StindR4 | Opcode::StindR8 | Opcode::StindI
        | Opcode::StindRef | Opcode::Ckfinite | Opcode::Volatile | Opcode::Tailcall
        | Opcode::Readonly | Opcode::Cpblk | Opcode::Initblk | Opcode::Throw
        | Opcode::Rethrow | Opcode::Endfinally | Opcode::Endfilter
        | Opcode::Refanytype | Opcode::Arglist | Opcode::Break
        | Opcode::Localloc | Opcode::Localloc2 | Opcode::Endfilter2
        | Opcode::Cpblk2 | Opcode::Initblk2
        | Opcode::AddOvf | Opcode::AddOvfUn | Opcode::SubOvf | Opcode::SubOvfUn
        | Opcode::MulOvf | Opcode::MulOvfUn | Opcode::Conv(_) | Opcode::ConvOvf(_) | Opcode::ConvOvfUn(_) => 1,
        Opcode::Switch(targets) => 5 + targets.len() * 4,
        }
}

// ─────────────────────────────────────────────────────────────────────────────
// Method body header
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MethodBodyFlags {
    pub init_locals: bool,
    pub more_sects: bool,
    pub fat_format: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalVarSig {
    /// Token into the standalone sig table.
    pub token: u32,
    /// Decoded variable type names (debug aid).
    pub var_types: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EhClauseKind {
    Catch(u32),   // token
    Filter,
    Finally,
    Fault,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EhClause {
    pub kind: EhClauseKind,
    pub try_offset: u32,
    pub try_length: u32,
    pub handler_offset: u32,
    pub handler_length: u32,
    /// For Catch: offset into filter code; for Filter: filter offset.
    pub filter_or_class: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MethodBody {
    pub flags: MethodBodyFlags,
    pub max_stack: u16,
    pub local_var_sig: Option<LocalVarSig>,
    pub instructions: Vec<Instruction>,
    pub eh_clauses: Vec<EhClause>,
    /// Raw byte offset of this method body within the PE (for splicing).
    pub file_offset: Option<u64>,
}

impl MethodBody {
    #[must_use] 
    pub const fn new_tiny(instructions: Vec<Instruction>) -> Self {
        Self {
            flags: MethodBodyFlags { init_locals: false, more_sects: false, fat_format: false },
            max_stack: 8,
            local_var_sig: None,
            instructions,
            eh_clauses: vec![],
            file_offset: None,
        }
    }

    #[must_use] 
    pub const fn new_fat(max_stack: u16, init_locals: bool, instructions: Vec<Instruction>, eh_clauses: Vec<EhClause>) -> Self {
        Self {
            flags: MethodBodyFlags { init_locals, more_sects: !eh_clauses.is_empty(), fat_format: true },
            max_stack,
            local_var_sig: None,
            instructions,
            eh_clauses,
            file_offset: None,
        }
    }

    /// Total encoded byte length of the instructions area.
    #[must_use] 
    pub fn code_size(&self) -> usize {
        self.instructions.iter().map(Instruction::byte_size).sum()
    }

    /// Whether this body fits in a tiny header (no locals, no EH, code <= 63 bytes, `max_stack` <= 8).
    #[must_use]
    pub fn fits_tiny(&self) -> bool {
        self.local_var_sig.is_none()
            && self.eh_clauses.is_empty()
            && self.code_size() <= 63
            && self.max_stack <= 8
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Decoder
// ─────────────────────────────────────────────────────────────────────────────

pub struct MethodBodyDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> MethodBodyDecoder<'a> {
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self { Self { data, pos: 0 } }

    fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() { bail!("unexpected end of method body"); }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }
    fn read_i8(&mut self) -> Result<i8> { Ok(self.read_u8()? as i8) }
    fn read_u16(&mut self) -> Result<u16> {
        if self.pos + 2 > self.data.len() { bail!("short read u16"); }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos+1]]);
        self.pos += 2; Ok(v)
    }
    fn read_i16(&mut self) -> Result<i16> { Ok(self.read_u16()? as i16) }

    /// Decode a 16-bit signed value at the current cursor without advancing
    /// past the surrounding instruction. Provided for tools that read
    /// non-standard short-branch encodings or vendor extensions.
    pub fn read_signed_short(&mut self) -> Result<i16> { self.read_i16() }
    fn read_u32(&mut self) -> Result<u32> {
        if self.pos + 4 > self.data.len() { bail!("short read u32"); }
        let v = u32::from_le_bytes(self.data[self.pos..self.pos+4].try_into().unwrap());
        self.pos += 4; Ok(v)
    }
    fn read_i32(&mut self) -> Result<i32> { Ok(self.read_u32()? as i32) }
    fn read_u64(&mut self) -> Result<u64> {
        if self.pos + 8 > self.data.len() { bail!("short read u64"); }
        let v = u64::from_le_bytes(self.data[self.pos..self.pos+8].try_into().unwrap());
        self.pos += 8; Ok(v)
    }
    fn read_i64(&mut self) -> Result<i64> { Ok(self.read_u64()? as i64) }

    pub fn decode_header(&mut self) -> Result<(MethodBodyFlags, u16, u32, u32)> {
        let first = self.read_u8()?;
        if (first & 0x03) == 0x02 {
            // Tiny header
            let code_size = u32::from(first >> 2);
            return Ok((MethodBodyFlags { init_locals: false, more_sects: false, fat_format: false }, 8, 0, code_size));
        }
        if (first & 0x03) == 0x03 {
            // Fat header: 12 bytes total
            let second = self.read_u8()?;
            let flags_word = u16::from_le_bytes([first, second]);
            let _header_size = (flags_word >> 12) as u8; // should be 3
            let init_locals = (flags_word & 0x10) != 0;
            let more_sects = (flags_word & 0x08) != 0;
            let max_stack = self.read_u16()?;
            let code_size = self.read_u32()?;
            let local_var_sig_tok = self.read_u32()?;
            return Ok((MethodBodyFlags { init_locals, more_sects, fat_format: true }, max_stack, local_var_sig_tok, code_size));
        }
        bail!("unknown method body header format: 0x{first:02x}")
    }

    pub fn decode_instructions(&mut self, code_size: usize) -> Result<Vec<Instruction>> {
        let end = self.pos + code_size;
        let mut instructions = Vec::new();
        while self.pos < end {
            let offset = self.pos as u32;
            let byte = self.read_u8()?;
            let op = if byte == 0xFE {
                let second = self.read_u8()?;
                self.decode_fe(second)?
            } else {
                self.decode_main(byte)?
            };
            instructions.push(Instruction::new(offset, op));
        }
        Ok(instructions)
    }

    fn decode_main(&mut self, b: u8) -> Result<Opcode> {
        Ok(match b {
            0x00 => Opcode::Nop,
            0x01 => Opcode::Break,
            0x02 => Opcode::Ldarg0,
            0x03 => Opcode::Ldarg1,
            0x04 => Opcode::Ldarg2,
            0x05 => Opcode::Ldarg3,
            0x06 => Opcode::Ldloc0,
            0x07 => Opcode::Ldloc1,
            0x08 => Opcode::Ldloc2,
            0x09 => Opcode::Ldloc3,
            0x0A => Opcode::StlocS(0),
            0x0B => Opcode::StlocS(1),
            0x0C => Opcode::StlocS(2),
            0x0D => Opcode::StlocS(3),
            0x0E => Opcode::LdargS(self.read_u8()?),
            0x0F => Opcode::LdlocA(self.read_u8()?),
            0x10 => Opcode::LdlocS(self.read_u8()?),
            0x11 => Opcode::StlocS(self.read_u8()?),
            0x13 => Opcode::StargS(self.read_u8()?),
            0x14 => Opcode::Ldnull,
            0x15 => Opcode::LdcI4M1,
            0x16 => Opcode::LdcI4_0,
            0x17 => Opcode::LdcI4_1,
            0x18 => Opcode::LdcI4_2,
            0x19 => Opcode::LdcI4_3,
            0x1A => Opcode::LdcI4_4,
            0x1B => Opcode::LdcI4_5,
            0x1C => Opcode::LdcI4_6,
            0x1D => Opcode::LdcI4_7,
            0x1E => Opcode::LdcI4_8,
            0x1F => Opcode::LdcI4S(self.read_i8()?),
            0x20 => Opcode::LdcI4(self.read_i32()?),
            0x21 => Opcode::LdcI8(self.read_i64()?),
            0x22 => Opcode::LdcR4(self.read_u32()?),
            0x23 => Opcode::LdcR8(self.read_u64()?),
            0x25 => Opcode::Dup,
            0x26 => Opcode::Pop,
            0x27 => Opcode::Jmp(self.read_u32()?),
            0x28 => Opcode::Call(self.read_u32()?),
            0x29 => Opcode::Calli(self.read_u32()?),
            0x2A => Opcode::Ret,
            0x2B => Opcode::BrS(self.read_i8()?),
            0x2C => Opcode::BrfalseS(self.read_i8()?),
            0x2D => Opcode::BrtrueS(self.read_i8()?),
            0x2E => Opcode::BeqS(self.read_i8()?),
            0x2F => Opcode::BgeS(self.read_i8()?),
            0x30 => Opcode::BgtS(self.read_i8()?),
            0x31 => Opcode::BleS(self.read_i8()?),
            0x32 => Opcode::BltS(self.read_i8()?),
            0x33 => Opcode::BneS(self.read_i8()?),
            0x34 => Opcode::BgeUnS(self.read_i8()?),
            0x35 => Opcode::BgtUnS(self.read_i8()?),
            0x36 => Opcode::BleUnS(self.read_i8()?),
            0x37 => Opcode::BltUnS(self.read_i8()?),
            0x38 => Opcode::Br(self.read_i32()?),
            0x39 => Opcode::Brfalse(self.read_i32()?),
            0x3A => Opcode::Brtrue(self.read_i32()?),
            0x3B => Opcode::Beq(self.read_i32()?),
            0x3C => Opcode::Bge(self.read_i32()?),
            0x3D => Opcode::Bgt(self.read_i32()?),
            0x3E => Opcode::Ble(self.read_i32()?),
            0x3F => Opcode::Blt(self.read_i32()?),
            0x40 => Opcode::BneUn(self.read_i32()?),
            0x41 => Opcode::BgeUn(self.read_i32()?),
            0x42 => Opcode::BgtUn(self.read_i32()?),
            0x43 => Opcode::BleUn(self.read_i32()?),
            0x44 => Opcode::BltUn(self.read_i32()?),
            0x45 => {
                let n = self.read_u32()? as usize;
                let mut targets = Vec::with_capacity(n);
                for _ in 0..n { targets.push(self.read_i32()?); }
                Opcode::Switch(targets)
            }
            0x46 => Opcode::LdindI1,
            0x47 => Opcode::LdindU1,
            0x48 => Opcode::LdindI2,
            0x49 => Opcode::LdindU2,
            0x4A => Opcode::LdindI4,
            0x4B => Opcode::LdindU4,
            0x4C => Opcode::LdindI8,
            0x4D => Opcode::LdindI,
            0x4E => Opcode::LdindR4,
            0x4F => Opcode::LdindR8,
            0x50 => Opcode::LdindRef,
            0x51 => Opcode::StindRef,
            0x52 => Opcode::StindI1,
            0x53 => Opcode::StindI2,
            0x54 => Opcode::StindI4,
            0x55 => Opcode::StindI8,
            0x56 => Opcode::StindR4,
            0x57 => Opcode::StindR8,
            0x58 => Opcode::Add,
            0x59 => Opcode::Sub,
            0x5A => Opcode::Mul,
            0x5B => Opcode::Div,
            0x5C => Opcode::Rem,
            0x5D => Opcode::And,
            0x5E => Opcode::Or,
            0x5F => Opcode::Xor,
            0x60 => Opcode::Shl,
            0x61 => Opcode::Shr,
            0x62 => Opcode::ShrUn,
            0x63 => Opcode::Neg,
            0x64 => Opcode::Not,
            0x65 => Opcode::Conv(ConvTarget::I1),
            0x66 => Opcode::Conv(ConvTarget::I2),
            0x67 => Opcode::Conv(ConvTarget::I4),
            0x68 => Opcode::Conv(ConvTarget::I8),
            0x69 => Opcode::Conv(ConvTarget::R4),
            0x6A => Opcode::Conv(ConvTarget::R8),
            0x6B => Opcode::Conv(ConvTarget::U4),
            0x6C => Opcode::Conv(ConvTarget::U8),
            0x6E => Opcode::Conv(ConvTarget::U1),
            0x6F => Opcode::Conv(ConvTarget::U2),
            0x70 => Opcode::Ldstr(self.read_u32()?),
            0x71 => Opcode::Newobj(self.read_u32()?),
            0x72 => Opcode::Newobj2(self.read_u32()?),
            0x74 => Opcode::Castclass(self.read_u32()?),
            0x75 => Opcode::Isinst(self.read_u32()?),
            0x79 => Opcode::Unbox(self.read_u32()?),
            0x7A => Opcode::Throw,
            0x7B => Opcode::Ldfld(self.read_u32()?),
            0x7C => Opcode::Ldflda(self.read_u32()?),
            0x7D => Opcode::Stfld(self.read_u32()?),
            0x7E => Opcode::Ldsfld(self.read_u32()?),
            0x7F => Opcode::Ldsflda(self.read_u32()?),
            0x80 => Opcode::Stsfld(self.read_u32()?),
            0x81 => Opcode::Stobj(self.read_u32()?),
            0x8C => Opcode::Box(self.read_u32()?),
            0x8D => Opcode::Newarr(self.read_u32()?),
            0x8E => Opcode::Ldlen,
            0x8F => Opcode::Ldelema(self.read_u32()?),
            0x90 => Opcode::LdelemI1,
            0x91 => Opcode::LdelemU1,
            0x92 => Opcode::LdelemI2,
            0x93 => Opcode::LdelemU2,
            0x94 => Opcode::LdelemI4,
            0x95 => Opcode::LdelemU4,
            0x96 => Opcode::LdelemI8,
            0x98 => Opcode::LdelemR4,
            0x99 => Opcode::LdelemR8,
            0x9A => Opcode::LdelemRef,
            0x9B => Opcode::StelemI1,
            0x9C => Opcode::StelemI2,
            0x9D => Opcode::StelemI4,
            0x9E => Opcode::StelemI8,
            0x9F => Opcode::StelemR4,
            0xA0 => Opcode::StelemR8,
            0xA1 => Opcode::StelemRef,
            0xA3 => Opcode::Ldelem(self.read_u32()?),
            0xA4 => Opcode::Stelem(self.read_u32()?),
            0xA5 => Opcode::UnboxAny(self.read_u32()?),
            0xB3 => Opcode::Conv(ConvTarget::I),
            0xD0 => Opcode::Ldtoken(self.read_u32()?),
            0xD4 => Opcode::ConvOvf(ConvTarget::I),
            0xD5 => Opcode::ConvOvfUn(ConvTarget::I),
            0xD6 => Opcode::AddOvf,
            0xD7 => Opcode::AddOvfUn,
            0xD8 => Opcode::MulOvf,
            0xD9 => Opcode::MulOvfUn,
            0xDA => Opcode::SubOvf,
            0xDB => Opcode::SubOvfUn,
            0xDC => Opcode::Endfinally,
            0xDD => Opcode::Leave(self.read_i32()?),
            0xDE => Opcode::LeaveS(self.read_i8()?),
            0xDF => Opcode::StindI,
            0xE0 => Opcode::Conv(ConvTarget::U),
            _ => bail!("unknown opcode 0x{b:02X}"),
        })
    }

    fn decode_fe(&mut self, b: u8) -> Result<Opcode> {
        Ok(match b {
            0x00 => Opcode::Arglist,
            0x01 => Opcode::Ceq,
            0x02 => Opcode::Cgt,
            0x03 => Opcode::CgtUn,
            0x04 => Opcode::Clt,
            0x05 => Opcode::CltUn,
            0x06 => Opcode::Ldftn(self.read_u32()?),
            0x07 => Opcode::Ldvirtftn(self.read_u32()?),
            0x09 => Opcode::LdargaN(self.read_u16()?),
            0x0A => Opcode::StargN(self.read_u16()?), // ldarga.s encoded as 0xFE 0x0A
            0x0B => Opcode::LdlocN(self.read_u16()?),
            0x0C => Opcode::LdlocA2(self.read_u16()?),
            0x0D => Opcode::StlocN(self.read_u16()?),
            0x0E => Opcode::Localloc,
            0x10 => Opcode::Endfilter,
            0x11 => Opcode::Unaligned(self.read_u8()?),
            0x12 => Opcode::Volatile,
            0x13 => Opcode::Tailcall,
            0x14 => Opcode::Initobj(self.read_u32()?),
            0x15 => Opcode::Constrained(self.read_u32()?),
            0x16 => Opcode::Cpblk,
            0x17 => Opcode::Initblk,
            0x19 => Opcode::Rethrow,
            0x1B => Opcode::Sizeof(self.read_u32()?),
            0x1C => Opcode::Refanytype,
            0x1D => Opcode::Readonly,
            _ => bail!("unknown FE opcode 0x{b:02X}"),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Encoder
// ─────────────────────────────────────────────────────────────────────────────

pub struct MethodBodyEncoder;

impl MethodBodyEncoder {
    #[must_use]
    pub fn encode(body: &MethodBody) -> Vec<u8> {
        let mut code = Vec::new();
        for instr in &body.instructions {
            Self::encode_instruction(&instr.opcode, &mut code);
        }
        let mut out = Vec::new();
        if body.fits_tiny() && !body.flags.fat_format {
            // Tiny header: flags = (code_size << 2) | 0x02
            out.push(((code.len() as u8) << 2) | 0x02);
        } else {
            // Fat header
            let mut flags: u16 = 0x0003 | (3 << 12); // fat, header size = 3
            if body.flags.init_locals { flags |= 0x10; }
            if body.flags.more_sects { flags |= 0x08; }
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&body.max_stack.to_le_bytes());
            out.extend_from_slice(&(code.len() as u32).to_le_bytes());
            let local_tok = body.local_var_sig.as_ref().map_or(0, |s| s.token);
            out.extend_from_slice(&local_tok.to_le_bytes());
        }
        out.extend_from_slice(&code);
        // Pad to 4-byte boundary
        while out.len() % 4 != 0 { out.push(0); }
        // EH sections
        if !body.eh_clauses.is_empty() {
            Self::encode_eh_sections(body, &mut out);
        }
        out
    }

    fn encode_instruction(op: &Opcode, out: &mut Vec<u8>) {
        match op {
            Opcode::Nop => out.push(0x00),
            Opcode::Break => out.push(0x01),
            Opcode::Ldarg0 => out.push(0x02),
            Opcode::Ldarg1 => out.push(0x03),
            Opcode::Ldarg2 => out.push(0x04),
            Opcode::Ldarg3 => out.push(0x05),
            Opcode::Ldloc0 => out.push(0x06),
            Opcode::Ldloc1 => out.push(0x07),
            Opcode::Ldloc2 => out.push(0x08),
            Opcode::Ldloc3 => out.push(0x09),
            Opcode::LdargS(n) => { out.push(0x0E); out.push(*n); }
            Opcode::StargS(n) => { out.push(0x13); out.push(*n); }
            Opcode::LdlocS(n) => { out.push(0x10); out.push(*n); }
            Opcode::StlocS(n) => { out.push(0x11); out.push(*n); }
            Opcode::LdlocA(n) => { out.push(0x12); out.push(*n); }
            Opcode::Ldnull => out.push(0x14),
            Opcode::LdcI4M1 => out.push(0x15),
            Opcode::LdcI4_0 => out.push(0x16),
            Opcode::LdcI4_1 => out.push(0x17),
            Opcode::LdcI4_2 => out.push(0x18),
            Opcode::LdcI4_3 => out.push(0x19),
            Opcode::LdcI4_4 => out.push(0x1A),
            Opcode::LdcI4_5 => out.push(0x1B),
            Opcode::LdcI4_6 => out.push(0x1C),
            Opcode::LdcI4_7 => out.push(0x1D),
            Opcode::LdcI4_8 => out.push(0x1E),
            Opcode::LdcI4S(n) => { out.push(0x1F); out.push(*n as u8); }
            Opcode::LdcI4(n) => { out.push(0x20); out.extend_from_slice(&n.to_le_bytes()); }
            Opcode::LdcI8(n) => { out.push(0x21); out.extend_from_slice(&n.to_le_bytes()); }
            Opcode::LdcR4(n) => { out.push(0x22); out.extend_from_slice(&n.to_le_bytes()); }
            Opcode::LdcR8(n) => { out.push(0x23); out.extend_from_slice(&n.to_le_bytes()); }
            Opcode::Dup => out.push(0x25),
            Opcode::Pop => out.push(0x26),
            Opcode::Jmp(t) => { out.push(0x27); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Call(t) => { out.push(0x28); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Callvirt(t) => { out.push(0x6F); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Calli(t) => { out.push(0x29); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Ret => out.push(0x2A),
            Opcode::BrS(d) => { out.push(0x2B); out.push(*d as u8); }
            Opcode::BrfalseS(d) => { out.push(0x2C); out.push(*d as u8); }
            Opcode::BrtrueS(d) => { out.push(0x2D); out.push(*d as u8); }
            Opcode::Br(d) => { out.push(0x38); out.extend_from_slice(&d.to_le_bytes()); }
            Opcode::Brfalse(d) => { out.push(0x39); out.extend_from_slice(&d.to_le_bytes()); }
            Opcode::Brtrue(d) => { out.push(0x3A); out.extend_from_slice(&d.to_le_bytes()); }
            Opcode::Beq(d) => { out.push(0x3B); out.extend_from_slice(&d.to_le_bytes()); }
            Opcode::BneUn(d) => { out.push(0x40); out.extend_from_slice(&d.to_le_bytes()); }
            Opcode::Switch(targets) => {
                out.push(0x45);
                out.extend_from_slice(&(targets.len() as u32).to_le_bytes());
                for t in targets { out.extend_from_slice(&t.to_le_bytes()); }
            }
            Opcode::Add => out.push(0x58),
            Opcode::Sub => out.push(0x59),
            Opcode::Mul => out.push(0x5A),
            Opcode::Div => out.push(0x5B),
            Opcode::And => out.push(0x5F),
            Opcode::Or => out.push(0x60),
            Opcode::Xor => out.push(0x61),
            Opcode::Shl => out.push(0x62),
            Opcode::Shr => out.push(0x63),
            Opcode::Neg => out.push(0x65),
            Opcode::Not => out.push(0x66),
            Opcode::Throw => out.push(0x7A),
            Opcode::Ldfld(t) => { out.push(0x7B); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Ldsfld(t) => { out.push(0x7E); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Stfld(t) => { out.push(0x7D); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Stsfld(t) => { out.push(0x80); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Newobj(t) | Opcode::Newobj2(t) => { out.push(0x73); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Castclass(t) => { out.push(0x74); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Isinst(t) => { out.push(0x75); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Box(t) => { out.push(0x8C); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Unbox(t) => { out.push(0x79); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::UnboxAny(t) => { out.push(0xA5); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Ldelema(t) => { out.push(0x8F); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Ldstr(t) => { out.push(0x72); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Ldtoken(t) => { out.push(0xD0); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Newarr(t) => { out.push(0x8D); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Ldlen => out.push(0x8E),
            Opcode::LdelemRef => out.push(0x9A),
            Opcode::StelemRef => out.push(0xA2),
            Opcode::Endfinally => out.push(0xDC),
            Opcode::Leave(d) => { out.push(0xDD); out.extend_from_slice(&d.to_le_bytes()); }
            Opcode::LeaveS(d) => { out.push(0xDE); out.push(*d as u8); }
            Opcode::Rethrow => { out.push(0xFE); out.push(0x1A); }
            Opcode::Ceq => { out.push(0xFE); out.push(0x01); }
            Opcode::Cgt => { out.push(0xFE); out.push(0x02); }
            Opcode::CgtUn => { out.push(0xFE); out.push(0x03); }
            Opcode::Clt => { out.push(0xFE); out.push(0x04); }
            Opcode::CltUn => { out.push(0xFE); out.push(0x05); }
            Opcode::Initobj(t) => { out.push(0xFE); out.push(0x15); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Constrained(t) => { out.push(0xFE); out.push(0x16); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Sizeof(t) => { out.push(0xFE); out.push(0x1C); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Ldftn(t) => { out.push(0xFE); out.push(0x06); out.extend_from_slice(&t.to_le_bytes()); }
            Opcode::Ldvirtftn(t) => { out.push(0xFE); out.push(0x07); out.extend_from_slice(&t.to_le_bytes()); }
            _ => {} // nop for unimplemented variants
        }
    }

    fn encode_eh_sections(body: &MethodBody, out: &mut Vec<u8>) {
        let use_fat = body.eh_clauses.len() > 20 || body.eh_clauses.iter().any(|c| {
            c.try_length > 255 || c.handler_length > 255 || c.try_offset > 65535
        });
        if use_fat {
            let data_len = 4 + body.eh_clauses.len() * 24;
            out.push(0x41); // kind: fat EH
            out.push((data_len & 0xFF) as u8);
            out.push(((data_len >> 8) & 0xFF) as u8);
            out.push(((data_len >> 16) & 0xFF) as u8);
            for clause in &body.eh_clauses {
                let kind: u32 = match &clause.kind {
                    EhClauseKind::Catch(_) => 0,
                    EhClauseKind::Filter => 1,
                    EhClauseKind::Finally => 2,
                    EhClauseKind::Fault => 4,
                };
                out.extend_from_slice(&kind.to_le_bytes());
                out.extend_from_slice(&clause.try_offset.to_le_bytes());
                out.extend_from_slice(&clause.try_length.to_le_bytes());
                out.extend_from_slice(&clause.handler_offset.to_le_bytes());
                out.extend_from_slice(&clause.handler_length.to_le_bytes());
                let class_or_filter = match &clause.kind {
                    EhClauseKind::Catch(tok) => *tok,
                    _ => clause.filter_or_class,
                };
                out.extend_from_slice(&class_or_filter.to_le_bytes());
            }
        } else {
            let data_len = 4 + body.eh_clauses.len() * 12;
            out.push(0x01); // kind: small EH
            out.push(data_len as u8);
            out.push(0); out.push(0);
            for clause in &body.eh_clauses {
                let kind: u16 = match &clause.kind {
                    EhClauseKind::Catch(_) => 0,
                    EhClauseKind::Filter => 1,
                    EhClauseKind::Finally => 2,
                    EhClauseKind::Fault => 4,
                };
                out.extend_from_slice(&kind.to_le_bytes());
                out.extend_from_slice(&(clause.try_offset as u16).to_le_bytes());
                out.push(clause.try_length as u8);
                out.extend_from_slice(&(clause.handler_offset as u16).to_le_bytes());
                out.push(clause.handler_length as u8);
                let class_or_filter = match &clause.kind {
                    EhClauseKind::Catch(tok) => *tok,
                    _ => clause.filter_or_class,
                };
                out.extend_from_slice(&class_or_filter.to_le_bytes());
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Editor
// ─────────────────────────────────────────────────────────────────────────────

/// High-level method body editor.  Wraps a decoded `MethodBody` and exposes
/// mutation operations.  Call `fixup_offsets()` and `fixup_branches()` before
/// re-encoding.
pub struct MethodBodyEditor {
    pub body: MethodBody,
}

impl MethodBodyEditor {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let mut dec = MethodBodyDecoder::new(data);
        let (flags, max_stack, local_tok, code_size) = dec.decode_header()?;
        let instructions = dec.decode_instructions(code_size as usize)?;
        let local_var_sig = if local_tok != 0 {
            Some(LocalVarSig { token: local_tok, var_types: vec![] })
        } else { None };
        Ok(Self { body: MethodBody { flags, max_stack, local_var_sig, instructions, eh_clauses: vec![], file_offset: None } })
    }

    /// Insert `new_instrs` before the instruction at `index`.
    pub fn insert_before(&mut self, index: usize, new_instrs: Vec<Opcode>) {
        let offset = self.body.instructions.get(index).map_or(0, |i| i.offset);
        let inserts: Vec<Instruction> = new_instrs.iter().map(|op| Instruction::new(offset, op.clone())).collect();
        self.body.instructions.splice(index..index, inserts);
        self.fixup_offsets();
    }

    /// Insert `new_instrs` after the instruction at `index`.
    pub fn insert_after(&mut self, index: usize, new_instrs: Vec<Opcode>) {
        let insert_at = (index + 1).min(self.body.instructions.len());
        let offset = self.body.instructions.get(index).map_or(0, |i| i.offset + i.byte_size() as u32);
        let inserts: Vec<Instruction> = new_instrs.iter().map(|op| Instruction::new(offset, op.clone())).collect();
        self.body.instructions.splice(insert_at..insert_at, inserts);
        self.fixup_offsets();
    }

    /// Replace instruction at `index` with `new_ops`.
    pub fn replace(&mut self, index: usize, new_ops: Vec<Opcode>) {
        if index >= self.body.instructions.len() { return; }
        let offset = self.body.instructions[index].offset;
        let new_instrs: Vec<Instruction> = new_ops.iter().map(|op| Instruction::new(offset, op.clone())).collect();
        self.body.instructions.splice(index..=index, new_instrs);
        self.fixup_offsets();
    }

    /// Remove instruction at `index`.
    pub fn remove(&mut self, index: usize) {
        if index < self.body.instructions.len() {
            self.body.instructions.remove(index);
            self.fixup_offsets();
        }
    }

    /// NOP out instruction at `index`.
    pub fn nop_out(&mut self, index: usize) {
        if index < self.body.instructions.len() {
            self.body.instructions[index].opcode = Opcode::Nop;
        }
    }

    /// Recompute all instruction offsets from scratch.
    pub fn fixup_offsets(&mut self) {
        let mut off = 0u32;
        for instr in &mut self.body.instructions {
            instr.offset = off;
            off += instr.byte_size() as u32;
        }
    }

    /// Build a map from old offset to new instruction index after edits.
    #[must_use]
    pub fn offset_to_index(&self) -> HashMap<u32, usize> {
        self.body.instructions.iter().enumerate().map(|(i, ins)| (ins.offset, i)).collect()
    }

    /// Rewrite all branch targets so they remain correct after offset changes.
    /// The `old_to_new` map maps old instruction offsets to new offsets.
    pub fn fixup_branches(&mut self, old_to_new: &HashMap<u32, u32>) {
        for instr in &mut self.body.instructions {
            let next_off = instr.offset + instr.byte_size() as u32;
            match &mut instr.opcode {
                Opcode::Br(d) | Opcode::Brfalse(d) | Opcode::Brtrue(d)
                | Opcode::Beq(d) | Opcode::Bge(d) | Opcode::Bgt(d)
                | Opcode::Ble(d) | Opcode::Blt(d) | Opcode::BgeUn(d) | Opcode::BgtUn(d)
                | Opcode::BleUn(d) | Opcode::BltUn(d) | Opcode::Bne(d)
                | Opcode::Leave(d) => {
                    let target = (i64::from(next_off) + i64::from(*d)) as u32;
                    if let Some(&new_target) = old_to_new.get(&target) {
                        *d = (i64::from(new_target) - i64::from(next_off)) as i32;
                    }
                }
                Opcode::Switch(targets) => {
                    for d in targets.iter_mut() {
                        let target = (i64::from(next_off) + i64::from(*d)) as u32;
                        if let Some(&new_target) = old_to_new.get(&target) {
                            *d = (i64::from(new_target) - i64::from(next_off)) as i32;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// Encode back to bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        MethodBodyEncoder::encode(&self.body)
    }

    /// Find all instructions matching a predicate.
    pub fn find_all<F: Fn(&Instruction) -> bool>(&self, pred: F) -> Vec<usize> {
        self.body.instructions.iter().enumerate()
            .filter(|(_, i)| pred(i)).map(|(idx, _)| idx).collect()
    }

    /// Find first call to a given method token.
    #[must_use]
    pub fn find_call(&self, token: u32) -> Option<usize> {
        self.body.instructions.iter().enumerate().find(|(_, i)| matches!(i.opcode, Opcode::Call(t) | Opcode::Callvirt(t) if t == token)).map(|(idx, _)| idx)
    }

    /// Prepend a prolog — insert instructions before instruction 0.
    pub fn prepend_prolog(&mut self, ops: Vec<Opcode>) {
        self.insert_before(0, ops);
    }

    /// Append an epilog — insert instructions before the last `ret`.
    pub fn append_before_ret(&mut self, ops: Vec<Opcode>) {
        let ret_idx = self.body.instructions.iter().rposition(|i| matches!(i.opcode, Opcode::Ret));
        if let Some(idx) = ret_idx {
            self.insert_before(idx, ops);
        }
    }

    /// Set max stack size.
    pub const fn set_max_stack(&mut self, n: u16) {
        self.body.max_stack = n;
    }

    /// Add an exception handling clause.
    pub fn add_eh_clause(&mut self, clause: EhClause) {
        self.body.eh_clauses.push(clause);
        self.body.flags.more_sects = true;
        self.body.flags.fat_format = true;
    }

    /// Statistics about the body.
    #[must_use]
    pub fn stats(&self) -> BodyStats {
        let mut call_count = 0;
        let mut branch_count = 0;
        let mut load_count = 0;
        for i in &self.body.instructions {
            match &i.opcode {
                Opcode::Call(_) | Opcode::Callvirt(_) | Opcode::Calli(_) => call_count += 1,
                Opcode::Br(_) | Opcode::BrS(_) | Opcode::Brfalse(_) | Opcode::Brtrue(_)
                | Opcode::Switch(_) => branch_count += 1,
                Opcode::Ldfld(_) | Opcode::Ldsfld(_) | Opcode::Ldloc0 | Opcode::Ldloc1
                | Opcode::Ldloc2 | Opcode::Ldloc3 | Opcode::LdlocS(_) => load_count += 1,
                _ => {}
            }
        }
        BodyStats {
            instruction_count: self.body.instructions.len(),
            code_bytes: self.body.code_size(),
            call_sites: call_count,
            branches: branch_count,
            loads: load_count,
            eh_clauses: self.body.eh_clauses.len(),
            has_locals: self.body.local_var_sig.is_some(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BodyStats {
    pub instruction_count: usize,
    pub code_bytes: usize,
    pub call_sites: usize,
    pub branches: usize,
    pub loads: usize,
    pub eh_clauses: usize,
    pub has_locals: bool,
}

impl fmt::Display for BodyStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "instructions={} bytes={} calls={} branches={} eh_clauses={}",
            self.instruction_count, self.code_bytes, self.call_sites, self.branches, self.eh_clauses)
    }
}
