//! CIL (Common Intermediate Language) disassembler — lightweight standalone layer.
//!
//! Decodes ECMA-335 CIL bytecode into typed instruction representations
//! and formats them as human-readable mnemonics.
//!
//! # Design note — relation to `cil_decoder`
//! [`cil_decoder`] is the **production** decoder: it carries serde support,
//! stack-delta metadata, control-flow / basic-block analysis, and integrates
//! with [`DotnetLoaderError`].  This module (`cil_disasm`) is a **self-contained
//! diagnostic layer** with no external crate dependencies; it is suitable for
//! use in contexts where pulling in serde or the loader error type is undesirable
//! (e.g. unit test helpers, CLI dump tools).  The two modules must be kept
//! distinct: do not merge them.

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CilError {
    #[error("unknown CIL opcode {0:#04x}")]
    UnknownOpcode(u8),
    #[error("truncated CIL stream")]
    Truncated,
    #[error("invalid operand")]
    InvalidOperand,
}

// ── Operand ───────────────────────────────────────────────────────────────────

/// Operand of a CIL instruction.
#[derive(Debug, Clone, PartialEq)]
pub enum CilOperand {
    None,
    I1(i8),
    I4(i32),
    I8(i64),
    R4(f32),
    R8(f64),
    Token(u32),
    BrTarget(i32),
    Switch(Vec<i32>),
    VarIdx(u16),
    ArgIdx(u16),
}

// ── Opcodes ───────────────────────────────────────────────────────────────────

/// CIL opcode variants (single-byte and 0xFE-prefixed two-byte).
#[derive(Debug, Clone, PartialEq)]
pub enum CilOpCode {
    // Single-byte opcodes
    Nop,
    Break,
    LdargS(u8),
    LdargS0, LdargS1, LdargS2, LdargS3,
    LdlocS(u8),
    LdlocS0, LdlocS1, LdlocS2, LdlocS3,
    StlocS(u8),
    StlocS0, StlocS1, StlocS2, StlocS3,
    LdnullObj,
    LdcI4M1,
    LdcI4_0, LdcI4_1, LdcI4_2, LdcI4_3,
    LdcI4_4, LdcI4_5, LdcI4_6, LdcI4_7, LdcI4_8,
    LdcI4S(i8),
    LdcI4(i32),
    LdcI8(i64),
    LdcR4(f32),
    LdcR8(f64),
    Dup,
    Pop,
    Jmp(u32),
    Call(u32),
    Calli(u32),
    Ret,
    BrS(i8), BrfalseS(i8), BrtrueS(i8),
    BeqS(i8), BgeS(i8), BgtS(i8), BleS(i8), BltS(i8),
    BneUnS(i8), BgeUnS(i8), BgtUnS(i8), BleUnS(i8), BltUnS(i8),
    Br(i32), Brfalse(i32), Brtrue(i32),
    Beq(i32), Bge(i32), Bgt(i32), Ble(i32), Blt(i32),
    BneUn(i32), BgeUn(i32), BgtUn(i32), BleUn(i32), BltUn(i32),
    Switch(Vec<i32>),
    LdindI1, LdindU1, LdindI2, LdindU2, LdindI4, LdindU4,
    LdindI8, LdindI, LdindR4, LdindR8, LdindRef,
    StindRef, StindI1, StindI2, StindI4, StindI8, StindR4, StindR8,
    Add, Sub, Mul, Div, DivUn, Rem, RemUn,
    And, Or, Xor, Shl, Shr, ShrUn,
    Neg, Not,
    ConvI1, ConvI2, ConvI4, ConvI8,
    ConvR4, ConvR8, ConvU4, ConvU8,
    Callvirt(u32),
    Cpobj(u32),
    Ldobj(u32),
    Ldstr(u32),
    Newobj(u32),
    Castclass(u32),
    Isinst(u32),
    ConvRUn,
    Unbox(u32),
    Throw,
    Ldfld(u32), Ldflda(u32), Stfld(u32),
    Ldsfld(u32), Ldsflda(u32), Stsfld(u32),
    Stobj(u32),
    ConvOvfI1Un,
    Box(u32),
    Newarr(u32),
    Ldlen,
    Ldelema(u32),
    Ldelem(u32),
    Stelem(u32),
    UnboxAny(u32),
    Ldtoken(u32),
    ConvU2, ConvU1, ConvI,
    Endfinally,
    Leave(i32), LeaveS(i8),
    StindI, ConvU,
    PrefixN, Prefix7, Prefix6, Prefix5, Prefix4, Prefix3, Prefix2, Prefix1, Prefixref,

    // 0xFE-prefixed two-byte opcodes
    Arglist,
    Ceq, Cgt, CgtUn, Clt, CltUn,
    Ldftn(u32),
    Ldvirtftn(u32),
    Ldarg(u16), Ldarga(u16), Starg(u16),
    Ldloc(u16), Ldloca(u16), Stloc(u16),
    Localloc,
    Endfilter,
    Unaligned,
    Volatile,
    Tail,
    Initobj(u32),
    Constrained(u32),
    Cpblk,
    Initblk,
    No,
    Rethrow,
    Sizeof(u32),
    Refanytype,
    Readonly,
}

// ── Instruction ───────────────────────────────────────────────────────────────

/// A single decoded CIL instruction.
#[derive(Debug, Clone)]
pub struct CilInstr {
    pub offset: u32,
    pub opcode: CilOpCode,
    pub size:   u32,
}

impl CilInstr {
    /// Return a human-readable mnemonic + operand string.
    #[must_use] 
    pub fn mnemonic(&self) -> String {
        match &self.opcode {
            CilOpCode::Nop           => "nop".into(),
            CilOpCode::Break         => "break".into(),
            CilOpCode::LdargS(n)     => format!("ldarg.s {n}"),
            CilOpCode::LdargS0      => "ldarg.0".into(),
            CilOpCode::LdargS1      => "ldarg.1".into(),
            CilOpCode::LdargS2      => "ldarg.2".into(),
            CilOpCode::LdargS3      => "ldarg.3".into(),
            CilOpCode::LdlocS(n)     => format!("ldloc.s {n}"),
            CilOpCode::LdlocS0      => "ldloc.0".into(),
            CilOpCode::LdlocS1      => "ldloc.1".into(),
            CilOpCode::LdlocS2      => "ldloc.2".into(),
            CilOpCode::LdlocS3      => "ldloc.3".into(),
            CilOpCode::StlocS(n)     => format!("stloc.s {n}"),
            CilOpCode::StlocS0      => "stloc.0".into(),
            CilOpCode::StlocS1      => "stloc.1".into(),
            CilOpCode::StlocS2      => "stloc.2".into(),
            CilOpCode::StlocS3      => "stloc.3".into(),
            CilOpCode::LdnullObj     => "ldnull".into(),
            CilOpCode::LdcI4M1       => "ldc.i4.m1".into(),
            CilOpCode::LdcI4_0       => "ldc.i4.0".into(),
            CilOpCode::LdcI4_1       => "ldc.i4.1".into(),
            CilOpCode::LdcI4_2       => "ldc.i4.2".into(),
            CilOpCode::LdcI4_3       => "ldc.i4.3".into(),
            CilOpCode::LdcI4_4       => "ldc.i4.4".into(),
            CilOpCode::LdcI4_5       => "ldc.i4.5".into(),
            CilOpCode::LdcI4_6       => "ldc.i4.6".into(),
            CilOpCode::LdcI4_7       => "ldc.i4.7".into(),
            CilOpCode::LdcI4_8       => "ldc.i4.8".into(),
            CilOpCode::LdcI4S(v)     => format!("ldc.i4.s {v}"),
            CilOpCode::LdcI4(v)      => format!("ldc.i4 {v}"),
            CilOpCode::LdcI8(v)      => format!("ldc.i8 {v}"),
            CilOpCode::LdcR4(v)      => format!("ldc.r4 {v}"),
            CilOpCode::LdcR8(v)      => format!("ldc.r8 {v}"),
            CilOpCode::Dup           => "dup".into(),
            CilOpCode::Pop           => "pop".into(),
            CilOpCode::Jmp(t)        => format!("jmp {t:#010x}"),
            CilOpCode::Call(t)       => format!("call {t:#010x}"),
            CilOpCode::Calli(t)      => format!("calli {t:#010x}"),
            CilOpCode::Ret           => "ret".into(),
            CilOpCode::BrS(off)      => format!("br.s {off}"),
            CilOpCode::BrfalseS(off) => format!("brfalse.s {off}"),
            CilOpCode::BrtrueS(off)  => format!("brtrue.s {off}"),
            CilOpCode::BeqS(off)     => format!("beq.s {off}"),
            CilOpCode::BgeS(off)     => format!("bge.s {off}"),
            CilOpCode::BgtS(off)     => format!("bgt.s {off}"),
            CilOpCode::BleS(off)     => format!("ble.s {off}"),
            CilOpCode::BltS(off)     => format!("blt.s {off}"),
            CilOpCode::BneUnS(off)   => format!("bne.un.s {off}"),
            CilOpCode::BgeUnS(off)   => format!("bge.un.s {off}"),
            CilOpCode::BgtUnS(off)   => format!("bgt.un.s {off}"),
            CilOpCode::BleUnS(off)   => format!("ble.un.s {off}"),
            CilOpCode::BltUnS(off)   => format!("blt.un.s {off}"),
            CilOpCode::Br(off)       => format!("br {off}"),
            CilOpCode::Brfalse(off)  => format!("brfalse {off}"),
            CilOpCode::Brtrue(off)   => format!("brtrue {off}"),
            CilOpCode::Beq(off)      => format!("beq {off}"),
            CilOpCode::Bge(off)      => format!("bge {off}"),
            CilOpCode::Bgt(off)      => format!("bgt {off}"),
            CilOpCode::Ble(off)      => format!("ble {off}"),
            CilOpCode::Blt(off)      => format!("blt {off}"),
            CilOpCode::BneUn(off)    => format!("bne.un {off}"),
            CilOpCode::BgeUn(off)    => format!("bge.un {off}"),
            CilOpCode::BgtUn(off)    => format!("bgt.un {off}"),
            CilOpCode::BleUn(off)    => format!("ble.un {off}"),
            CilOpCode::BltUn(off)    => format!("blt.un {off}"),
            CilOpCode::Switch(offs)  => format!("switch ({})", offs.iter().map(std::string::ToString::to_string).collect::<Vec<_>>().join(", ")),
            CilOpCode::LdindI1       => "ldind.i1".into(),
            CilOpCode::LdindU1       => "ldind.u1".into(),
            CilOpCode::LdindI2       => "ldind.i2".into(),
            CilOpCode::LdindU2       => "ldind.u2".into(),
            CilOpCode::LdindI4       => "ldind.i4".into(),
            CilOpCode::LdindU4       => "ldind.u4".into(),
            CilOpCode::LdindI8       => "ldind.i8".into(),
            CilOpCode::LdindI        => "ldind.i".into(),
            CilOpCode::LdindR4       => "ldind.r4".into(),
            CilOpCode::LdindR8       => "ldind.r8".into(),
            CilOpCode::LdindRef      => "ldind.ref".into(),
            CilOpCode::StindRef      => "stind.ref".into(),
            CilOpCode::StindI1       => "stind.i1".into(),
            CilOpCode::StindI2       => "stind.i2".into(),
            CilOpCode::StindI4       => "stind.i4".into(),
            CilOpCode::StindI8       => "stind.i8".into(),
            CilOpCode::StindR4       => "stind.r4".into(),
            CilOpCode::StindR8       => "stind.r8".into(),
            CilOpCode::Add           => "add".into(),
            CilOpCode::Sub           => "sub".into(),
            CilOpCode::Mul           => "mul".into(),
            CilOpCode::Div           => "div".into(),
            CilOpCode::DivUn         => "div.un".into(),
            CilOpCode::Rem           => "rem".into(),
            CilOpCode::RemUn         => "rem.un".into(),
            CilOpCode::And           => "and".into(),
            CilOpCode::Or            => "or".into(),
            CilOpCode::Xor           => "xor".into(),
            CilOpCode::Shl           => "shl".into(),
            CilOpCode::Shr           => "shr".into(),
            CilOpCode::ShrUn         => "shr.un".into(),
            CilOpCode::Neg           => "neg".into(),
            CilOpCode::Not           => "not".into(),
            CilOpCode::ConvI1        => "conv.i1".into(),
            CilOpCode::ConvI2        => "conv.i2".into(),
            CilOpCode::ConvI4        => "conv.i4".into(),
            CilOpCode::ConvI8        => "conv.i8".into(),
            CilOpCode::ConvR4        => "conv.r4".into(),
            CilOpCode::ConvR8        => "conv.r8".into(),
            CilOpCode::ConvU4        => "conv.u4".into(),
            CilOpCode::ConvU8        => "conv.u8".into(),
            CilOpCode::Callvirt(t)   => format!("callvirt {t:#010x}"),
            CilOpCode::Cpobj(t)      => format!("cpobj {t:#010x}"),
            CilOpCode::Ldobj(t)      => format!("ldobj {t:#010x}"),
            CilOpCode::Ldstr(t)      => format!("ldstr {t:#010x}"),
            CilOpCode::Newobj(t)     => format!("newobj {t:#010x}"),
            CilOpCode::Castclass(t)  => format!("castclass {t:#010x}"),
            CilOpCode::Isinst(t)     => format!("isinst {t:#010x}"),
            CilOpCode::ConvRUn       => "conv.r.un".into(),
            CilOpCode::Unbox(t)      => format!("unbox {t:#010x}"),
            CilOpCode::Throw         => "throw".into(),
            CilOpCode::Ldfld(t)      => format!("ldfld {t:#010x}"),
            CilOpCode::Ldflda(t)     => format!("ldflda {t:#010x}"),
            CilOpCode::Stfld(t)      => format!("stfld {t:#010x}"),
            CilOpCode::Ldsfld(t)     => format!("ldsfld {t:#010x}"),
            CilOpCode::Ldsflda(t)    => format!("ldsflda {t:#010x}"),
            CilOpCode::Stsfld(t)     => format!("stsfld {t:#010x}"),
            CilOpCode::Stobj(t)      => format!("stobj {t:#010x}"),
            CilOpCode::ConvOvfI1Un   => "conv.ovf.i1.un".into(),
            CilOpCode::Box(t)        => format!("box {t:#010x}"),
            CilOpCode::Newarr(t)     => format!("newarr {t:#010x}"),
            CilOpCode::Ldlen         => "ldlen".into(),
            CilOpCode::Ldelema(t)    => format!("ldelema {t:#010x}"),
            CilOpCode::Ldelem(t)     => format!("ldelem {t:#010x}"),
            CilOpCode::Stelem(t)     => format!("stelem {t:#010x}"),
            CilOpCode::UnboxAny(t)   => format!("unbox.any {t:#010x}"),
            CilOpCode::Ldtoken(t)    => format!("ldtoken {t:#010x}"),
            CilOpCode::ConvU2        => "conv.u2".into(),
            CilOpCode::ConvU1        => "conv.u1".into(),
            CilOpCode::ConvI         => "conv.i".into(),
            CilOpCode::Endfinally    => "endfinally".into(),
            CilOpCode::Leave(off)    => format!("leave {off}"),
            CilOpCode::LeaveS(off)   => format!("leave.s {off}"),
            CilOpCode::StindI        => "stind.i".into(),
            CilOpCode::ConvU         => "conv.u".into(),
            CilOpCode::PrefixN       => "prefix.n".into(),
            CilOpCode::Prefix7       => "prefix7".into(),
            CilOpCode::Prefix6       => "prefix6".into(),
            CilOpCode::Prefix5       => "prefix5".into(),
            CilOpCode::Prefix4       => "prefix4".into(),
            CilOpCode::Prefix3       => "prefix3".into(),
            CilOpCode::Prefix2       => "prefix2".into(),
            CilOpCode::Prefix1       => "prefix1".into(),
            CilOpCode::Prefixref     => "prefixref".into(),
            // 0xFE opcodes
            CilOpCode::Arglist       => "arglist".into(),
            CilOpCode::Ceq           => "ceq".into(),
            CilOpCode::Cgt           => "cgt".into(),
            CilOpCode::CgtUn         => "cgt.un".into(),
            CilOpCode::Clt           => "clt".into(),
            CilOpCode::CltUn         => "clt.un".into(),
            CilOpCode::Ldftn(t)      => format!("ldftn {t:#010x}"),
            CilOpCode::Ldvirtftn(t)  => format!("ldvirtftn {t:#010x}"),
            CilOpCode::Ldarg(n)      => format!("ldarg {n}"),
            CilOpCode::Ldarga(n)     => format!("ldarga {n}"),
            CilOpCode::Starg(n)      => format!("starg {n}"),
            CilOpCode::Ldloc(n)      => format!("ldloc {n}"),
            CilOpCode::Ldloca(n)     => format!("ldloca {n}"),
            CilOpCode::Stloc(n)      => format!("stloc {n}"),
            CilOpCode::Localloc      => "localloc".into(),
            CilOpCode::Endfilter     => "endfilter".into(),
            CilOpCode::Unaligned     => "unaligned".into(),
            CilOpCode::Volatile      => "volatile".into(),
            CilOpCode::Tail          => "tail".into(),
            CilOpCode::Initobj(t)    => format!("initobj {t:#010x}"),
            CilOpCode::Constrained(t) => format!("constrained {t:#010x}"),
            CilOpCode::Cpblk         => "cpblk".into(),
            CilOpCode::Initblk       => "initblk".into(),
            CilOpCode::No            => "no".into(),
            CilOpCode::Rethrow       => "rethrow".into(),
            CilOpCode::Sizeof(t)     => format!("sizeof {t:#010x}"),
            CilOpCode::Refanytype    => "refanytype".into(),
            CilOpCode::Readonly      => "readonly".into(),
        }
    }
}

// ── Disassembler ──────────────────────────────────────────────────────────────

/// CIL bytecode disassembler.
pub struct CilDisassembler;

impl CilDisassembler {
    /// Disassemble all instructions from `data`.
    #[must_use] 
    pub fn disassemble(data: &[u8]) -> Vec<CilInstr> {
        // Most CIL instructions average ~2-3 bytes; preallocate to avoid repeated growth.
        let mut instrs = Vec::with_capacity(data.len() / 2);
        let mut pos = 0usize;
        while pos < data.len() {
            let start = pos;
            match Self::disassemble_one(data, &mut pos) {
                Some(mut instr) => {
                    instr.offset = start as u32;
                    instr.size   = (pos - start) as u32;
                    instrs.push(instr);
                }
                None => break,
            }
        }
        instrs
    }

    /// Disassemble a single instruction, advancing `pos`.
    pub fn disassemble_one(data: &[u8], pos: &mut usize) -> Option<CilInstr> {
        if *pos >= data.len() { return None; }
        let start = *pos;
        let op = data[*pos];
        *pos += 1;

        let opcode = match op {
            0x00 => CilOpCode::Nop,
            0x01 => CilOpCode::Break,
            0x02 => CilOpCode::LdargS0,
            0x03 => CilOpCode::LdargS1,
            0x04 => CilOpCode::LdargS2,
            0x05 => CilOpCode::LdargS3,
            0x06 => CilOpCode::LdlocS0,
            0x07 => CilOpCode::LdlocS1,
            0x08 => CilOpCode::LdlocS2,
            0x09 => CilOpCode::LdlocS3,
            0x0A => CilOpCode::StlocS0,
            0x0B => CilOpCode::StlocS1,
            0x0C => CilOpCode::StlocS2,
            0x0D => CilOpCode::StlocS3,
            0x0E => { let n = read_u8(data, pos)?; CilOpCode::LdargS(n) }
            // 0x0F = ldarga.s (not in our list, treat as prefix)
            0x10 => { let n = read_u8(data, pos)?; CilOpCode::StlocS(n) }
            // 0x11 = starg.s
            0x12 => { let n = read_u8(data, pos)?; CilOpCode::LdlocS(n) }
            0x14 => CilOpCode::LdnullObj,
            0x15 => CilOpCode::LdcI4M1,
            0x16 => CilOpCode::LdcI4_0,
            0x17 => CilOpCode::LdcI4_1,
            0x18 => CilOpCode::LdcI4_2,
            0x19 => CilOpCode::LdcI4_3,
            0x1A => CilOpCode::LdcI4_4,
            0x1B => CilOpCode::LdcI4_5,
            0x1C => CilOpCode::LdcI4_6,
            0x1D => CilOpCode::LdcI4_7,
            0x1E => CilOpCode::LdcI4_8,
            0x1F => { let v = read_i8(data, pos)?; CilOpCode::LdcI4S(v) }
            0x20 => { let v = read_i32(data, pos)?; CilOpCode::LdcI4(v) }
            0x21 => { let v = read_i64(data, pos)?; CilOpCode::LdcI8(v) }
            0x22 => { let v = read_f32(data, pos)?; CilOpCode::LdcR4(v) }
            0x23 => { let v = read_f64(data, pos)?; CilOpCode::LdcR8(v) }
            0x25 => CilOpCode::Dup,
            0x26 => CilOpCode::Pop,
            0x27 => { let t = read_u32(data, pos)?; CilOpCode::Jmp(t) }
            0x28 => { let t = read_u32(data, pos)?; CilOpCode::Call(t) }
            0x29 => { let t = read_u32(data, pos)?; CilOpCode::Calli(t) }
            0x2A => CilOpCode::Ret,
            0x2B => { let v = read_i8(data, pos)?; CilOpCode::BrS(v) }
            0x2C => { let v = read_i8(data, pos)?; CilOpCode::BrfalseS(v) }
            0x2D => { let v = read_i8(data, pos)?; CilOpCode::BrtrueS(v) }
            0x2E => { let v = read_i8(data, pos)?; CilOpCode::BeqS(v) }
            0x2F => { let v = read_i8(data, pos)?; CilOpCode::BgeS(v) }
            0x30 => { let v = read_i8(data, pos)?; CilOpCode::BgtS(v) }
            0x31 => { let v = read_i8(data, pos)?; CilOpCode::BleS(v) }
            0x32 => { let v = read_i8(data, pos)?; CilOpCode::BltS(v) }
            0x33 => { let v = read_i8(data, pos)?; CilOpCode::BneUnS(v) }
            0x34 => { let v = read_i8(data, pos)?; CilOpCode::BgeUnS(v) }
            0x35 => { let v = read_i8(data, pos)?; CilOpCode::BgtUnS(v) }
            0x36 => { let v = read_i8(data, pos)?; CilOpCode::BleUnS(v) }
            0x37 => { let v = read_i8(data, pos)?; CilOpCode::BltUnS(v) }
            0x38 => { let v = read_i32(data, pos)?; CilOpCode::Br(v) }
            0x39 => { let v = read_i32(data, pos)?; CilOpCode::Brfalse(v) }
            0x3A => { let v = read_i32(data, pos)?; CilOpCode::Brtrue(v) }
            0x3B => { let v = read_i32(data, pos)?; CilOpCode::Beq(v) }
            0x3C => { let v = read_i32(data, pos)?; CilOpCode::Bge(v) }
            0x3D => { let v = read_i32(data, pos)?; CilOpCode::Bgt(v) }
            0x3E => { let v = read_i32(data, pos)?; CilOpCode::Ble(v) }
            0x3F => { let v = read_i32(data, pos)?; CilOpCode::Blt(v) }
            0x40 => { let v = read_i32(data, pos)?; CilOpCode::BneUn(v) }
            0x41 => { let v = read_i32(data, pos)?; CilOpCode::BgeUn(v) }
            0x42 => { let v = read_i32(data, pos)?; CilOpCode::BgtUn(v) }
            0x43 => { let v = read_i32(data, pos)?; CilOpCode::BleUn(v) }
            0x44 => { let v = read_i32(data, pos)?; CilOpCode::BltUn(v) }
            0x45 => {
                let n = read_u32(data, pos)? as usize;
                // Cap pre-allocation by remaining bytes: each target is 4 bytes.
                let mut offs = Vec::with_capacity(n.min(data.len().saturating_sub(*pos) / 4));
                for _ in 0..n { offs.push(read_i32(data, pos)?); }
                CilOpCode::Switch(offs)
            }
            0x46 => CilOpCode::LdindI1, 0x47 => CilOpCode::LdindU1,
            0x48 => CilOpCode::LdindI2, 0x49 => CilOpCode::LdindU2,
            0x4A => CilOpCode::LdindI4, 0x4B => CilOpCode::LdindU4,
            0x4C => CilOpCode::LdindI8, 0x4D => CilOpCode::LdindI,
            0x4E => CilOpCode::LdindR4, 0x4F => CilOpCode::LdindR8,
            0x50 => CilOpCode::LdindRef,
            0x51 => CilOpCode::StindRef, 0x52 => CilOpCode::StindI1,
            0x53 => CilOpCode::StindI2,  0x54 => CilOpCode::StindI4,
            0x55 => CilOpCode::StindI8,  0x56 => CilOpCode::StindR4,
            0x57 => CilOpCode::StindR8,
            0x58 => CilOpCode::Add, 0x59 => CilOpCode::Sub, 0x5A => CilOpCode::Mul,
            0x5B => CilOpCode::Div, 0x5C => CilOpCode::DivUn,
            0x5D => CilOpCode::Rem, 0x5E => CilOpCode::RemUn,
            0x5F => CilOpCode::And, 0x60 => CilOpCode::Or, 0x61 => CilOpCode::Xor,
            0x62 => CilOpCode::Shl, 0x63 => CilOpCode::Shr, 0x64 => CilOpCode::ShrUn,
            0x65 => CilOpCode::Neg, 0x66 => CilOpCode::Not,
            0x67 => CilOpCode::ConvI1, 0x68 => CilOpCode::ConvI2,
            0x69 => CilOpCode::ConvI4, 0x6A => CilOpCode::ConvI8,
            0x6B => CilOpCode::ConvR4, 0x6C => CilOpCode::ConvR8,
            0x6D => CilOpCode::ConvU4, 0x6E => CilOpCode::ConvU8,
            0x6F => { let t = read_u32(data, pos)?; CilOpCode::Callvirt(t) }
            0x70 => { let t = read_u32(data, pos)?; CilOpCode::Cpobj(t) }
            0x71 => { let t = read_u32(data, pos)?; CilOpCode::Ldobj(t) }
            0x72 => { let t = read_u32(data, pos)?; CilOpCode::Ldstr(t) }
            0x73 => { let t = read_u32(data, pos)?; CilOpCode::Newobj(t) }
            0x74 => { let t = read_u32(data, pos)?; CilOpCode::Castclass(t) }
            0x75 => { let t = read_u32(data, pos)?; CilOpCode::Isinst(t) }
            0x76 => CilOpCode::ConvRUn,
            0x79 => { let t = read_u32(data, pos)?; CilOpCode::Unbox(t) }
            0x7A => CilOpCode::Throw,
            0x7B => { let t = read_u32(data, pos)?; CilOpCode::Ldfld(t) }
            0x7C => { let t = read_u32(data, pos)?; CilOpCode::Ldflda(t) }
            0x7D => { let t = read_u32(data, pos)?; CilOpCode::Stfld(t) }
            0x7E => { let t = read_u32(data, pos)?; CilOpCode::Ldsfld(t) }
            0x7F => { let t = read_u32(data, pos)?; CilOpCode::Ldsflda(t) }
            0x80 => { let t = read_u32(data, pos)?; CilOpCode::Stsfld(t) }
            0x81 => { let t = read_u32(data, pos)?; CilOpCode::Stobj(t) }
            0x82 => CilOpCode::ConvOvfI1Un,
            0x8C => { let t = read_u32(data, pos)?; CilOpCode::Box(t) }
            0x8D => { let t = read_u32(data, pos)?; CilOpCode::Newarr(t) }
            0x8E => CilOpCode::Ldlen,
            0x8F => { let t = read_u32(data, pos)?; CilOpCode::Ldelema(t) }
            0x90 => { let t = read_u32(data, pos)?; CilOpCode::Ldelem(t) }
            0x9E => { let t = read_u32(data, pos)?; CilOpCode::Stelem(t) }
            0xA5 => { let t = read_u32(data, pos)?; CilOpCode::UnboxAny(t) }
            0xD0 => { let t = read_u32(data, pos)?; CilOpCode::Ldtoken(t) }
            0xD1 => CilOpCode::ConvU2,
            0xD2 => CilOpCode::ConvU1,
            0xD3 => CilOpCode::ConvI,
            0xDC => CilOpCode::Endfinally,
            0xDD => { let v = read_i32(data, pos)?; CilOpCode::Leave(v) }
            0xDE => { let v = read_i8(data, pos)?; CilOpCode::LeaveS(v) }
            0xDF => CilOpCode::StindI,
            0xE0 => CilOpCode::ConvU,
            0xF8 => CilOpCode::PrefixN,
            0xF9 => CilOpCode::Prefix7,
            0xFA => CilOpCode::Prefix6,
            0xFB => CilOpCode::Prefix5,
            0xFC => CilOpCode::Prefix4,
            0xFD => CilOpCode::Prefix3,
            // 0xFE => two-byte opcodes
            0xFE => {
                if *pos >= data.len() { return None; }
                let op2 = data[*pos];
                *pos += 1;
                match op2 {
                    0x00 => CilOpCode::Arglist,
                    0x01 => CilOpCode::Ceq,
                    0x02 => CilOpCode::Cgt,
                    0x03 => CilOpCode::CgtUn,
                    0x04 => CilOpCode::Clt,
                    0x05 => CilOpCode::CltUn,
                    0x06 => { let t = read_u32(data, pos)?; CilOpCode::Ldftn(t) }
                    0x07 => { let t = read_u32(data, pos)?; CilOpCode::Ldvirtftn(t) }
                    0x09 => { let n = read_u16(data, pos)?; CilOpCode::Ldarg(n) }
                    0x0A => { let n = read_u16(data, pos)?; CilOpCode::Ldarga(n) }
                    0x0B => { let n = read_u16(data, pos)?; CilOpCode::Starg(n) }
                    0x0C => { let n = read_u16(data, pos)?; CilOpCode::Ldloc(n) }
                    0x0D => { let n = read_u16(data, pos)?; CilOpCode::Ldloca(n) }
                    0x0E => { let n = read_u16(data, pos)?; CilOpCode::Stloc(n) }
                    0x0F => CilOpCode::Localloc,
                    0x11 => CilOpCode::Endfilter,
                    0x12 => CilOpCode::Unaligned,
                    0x13 => CilOpCode::Volatile,
                    0x14 => CilOpCode::Tail,
                    0x15 => { let t = read_u32(data, pos)?; CilOpCode::Initobj(t) }
                    0x16 => { let t = read_u32(data, pos)?; CilOpCode::Constrained(t) }
                    0x17 => CilOpCode::Cpblk,
                    0x18 => CilOpCode::Initblk,
                    0x19 => CilOpCode::No,
                    0x1A => CilOpCode::Rethrow,
                    0x1C => { let t = read_u32(data, pos)?; CilOpCode::Sizeof(t) }
                    0x1D => CilOpCode::Refanytype,
                    0x1E => CilOpCode::Readonly,
                    _ => return None,
                }
            }
            _ => return None,
        };

        Some(CilInstr {
            offset: start as u32,
            opcode,
            size: (*pos - start) as u32,
        })
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn read_u8(data: &[u8], pos: &mut usize) -> Option<u8> {
    if *pos >= data.len() { return None; }
    let v = data[*pos]; *pos += 1; Some(v)
}
fn read_i8(data: &[u8], pos: &mut usize) -> Option<i8> {
    read_u8(data, pos).map(|v| v as i8)
}
fn read_u16(data: &[u8], pos: &mut usize) -> Option<u16> {
    if *pos + 2 > data.len() { return None; }
    let v = u16::from_le_bytes(data[*pos..*pos+2].try_into().ok()?);
    *pos += 2; Some(v)
}
fn read_i32(data: &[u8], pos: &mut usize) -> Option<i32> {
    if *pos + 4 > data.len() { return None; }
    let v = i32::from_le_bytes(data[*pos..*pos+4].try_into().ok()?);
    *pos += 4; Some(v)
}
fn read_u32(data: &[u8], pos: &mut usize) -> Option<u32> {
    read_i32(data, pos).map(|v| v as u32)
}
fn read_i64(data: &[u8], pos: &mut usize) -> Option<i64> {
    if *pos + 8 > data.len() { return None; }
    let v = i64::from_le_bytes(data[*pos..*pos+8].try_into().ok()?);
    *pos += 8; Some(v)
}
fn read_f32(data: &[u8], pos: &mut usize) -> Option<f32> {
    read_u32(data, pos).map(f32::from_bits)
}
fn read_f64(data: &[u8], pos: &mut usize) -> Option<f64> {
    if *pos + 8 > data.len() { return None; }
    let bits = u64::from_le_bytes(data[*pos..*pos+8].try_into().ok()?);
    *pos += 8; Some(f64::from_bits(bits))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── CilError ──────────────────────────────────────────────────────────────

    #[test]
    fn test_error_display_unknown() {
        let e = CilError::UnknownOpcode(0xAB);
        assert!(e.to_string().contains("0xab"));
    }

    #[test]
    fn test_error_truncated() {
        let e = CilError::Truncated;
        assert!(e.to_string().contains("truncated"));
    }

    // ── CilInstr.mnemonic ─────────────────────────────────────────────────────

    #[test]
    fn test_mnemonic_nop() {
        let i = CilInstr { offset: 0, opcode: CilOpCode::Nop, size: 1 };
        assert_eq!(i.mnemonic(), "nop");
    }

    #[test]
    fn test_mnemonic_ret() {
        let i = CilInstr { offset: 0, opcode: CilOpCode::Ret, size: 1 };
        assert_eq!(i.mnemonic(), "ret");
    }

    #[test]
    fn test_mnemonic_ldarg0() {
        let i = CilInstr { offset: 0, opcode: CilOpCode::LdargS0, size: 1 };
        assert_eq!(i.mnemonic(), "ldarg.0");
    }

    #[test]
    fn test_mnemonic_ldc_i4() {
        let i = CilInstr { offset: 0, opcode: CilOpCode::LdcI4(42), size: 5 };
        assert_eq!(i.mnemonic(), "ldc.i4 42");
    }

    #[test]
    fn test_mnemonic_call() {
        let i = CilInstr { offset: 0, opcode: CilOpCode::Call(0x0600_0001), size: 5 };
        assert_eq!(i.mnemonic(), "call 0x06000001");
    }

    #[test]
    fn test_mnemonic_br_s() {
        let i = CilInstr { offset: 0, opcode: CilOpCode::BrS(10), size: 2 };
        assert_eq!(i.mnemonic(), "br.s 10");
    }

    #[test]
    fn test_mnemonic_add() {
        let i = CilInstr { offset: 0, opcode: CilOpCode::Add, size: 1 };
        assert_eq!(i.mnemonic(), "add");
    }

    #[test]
    fn test_mnemonic_ceq() {
        let i = CilInstr { offset: 0, opcode: CilOpCode::Ceq, size: 2 };
        assert_eq!(i.mnemonic(), "ceq");
    }

    #[test]
    fn test_mnemonic_ldstr() {
        let i = CilInstr { offset: 0, opcode: CilOpCode::Ldstr(0x7000_0001), size: 5 };
        assert!(i.mnemonic().contains("ldstr"));
    }

    #[test]
    fn test_mnemonic_switch() {
        let i = CilInstr { offset: 0, opcode: CilOpCode::Switch(vec![1, 2, 3]), size: 17 };
        let m = i.mnemonic();
        assert!(m.starts_with("switch"));
        assert!(m.contains("1, 2, 3"));
    }

    // ── Disassembler::disassemble_one ─────────────────────────────────────────

    #[test]
    fn test_disassemble_nop() {
        let mut pos = 0;
        let i = CilDisassembler::disassemble_one(&[0x00], &mut pos).unwrap();
        assert!(matches!(i.opcode, CilOpCode::Nop));
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_disassemble_ret() {
        let mut pos = 0;
        let i = CilDisassembler::disassemble_one(&[0x2A], &mut pos).unwrap();
        assert!(matches!(i.opcode, CilOpCode::Ret));
    }

    #[test]
    fn test_disassemble_ldc_i4_s() {
        let mut pos = 0;
        let i = CilDisassembler::disassemble_one(&[0x1F, 0x07], &mut pos).unwrap();
        assert!(matches!(i.opcode, CilOpCode::LdcI4S(7)));
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_disassemble_call() {
        let mut pos = 0;
        let data = [0x28u8, 0x01, 0x00, 0x00, 0x06]; // call 0x06000001
        let i = CilDisassembler::disassemble_one(&data, &mut pos).unwrap();
        assert!(matches!(i.opcode, CilOpCode::Call(0x0600_0001)));
        assert_eq!(pos, 5);
    }

    #[test]
    fn test_disassemble_fe_ceq() {
        let mut pos = 0;
        let data = [0xFEu8, 0x01];
        let i = CilDisassembler::disassemble_one(&data, &mut pos).unwrap();
        assert!(matches!(i.opcode, CilOpCode::Ceq));
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_disassemble_br() {
        let mut pos = 0;
        let data = [0x38u8, 0x05, 0x00, 0x00, 0x00]; // br +5
        let i = CilDisassembler::disassemble_one(&data, &mut pos).unwrap();
        assert!(matches!(i.opcode, CilOpCode::Br(5)));
    }

    #[test]
    fn test_disassemble_unknown_returns_none() {
        let mut pos = 0;
        // 0x24 is unused/unknown in CIL
        assert!(CilDisassembler::disassemble_one(&[0x24], &mut pos).is_none());
    }

    // ── Disassembler::disassemble (full) ──────────────────────────────────────

    #[test]
    fn test_disassemble_multi() {
        // nop (0x00), ldarg.0 (0x02), ret (0x2A)
        let data = [0x00u8, 0x02, 0x2A];
        let instrs = CilDisassembler::disassemble(&data);
        assert_eq!(instrs.len(), 3);
        assert_eq!(instrs[0].offset, 0);
        assert_eq!(instrs[1].offset, 1);
        assert_eq!(instrs[2].offset, 2);
    }

    #[test]
    fn test_disassemble_empty() {
        let instrs = CilDisassembler::disassemble(&[]);
        assert!(instrs.is_empty());
    }

    #[test]
    fn test_disassemble_offsets_correct() {
        // ldc.i4 42 (5 bytes), ret (1 byte)
        let data = [0x20u8, 42, 0, 0, 0, 0x2A];
        let instrs = CilDisassembler::disassemble(&data);
        assert_eq!(instrs[0].offset, 0);
        assert_eq!(instrs[0].size, 5);
        assert_eq!(instrs[1].offset, 5);
        assert_eq!(instrs[1].size, 1);
    }

    #[test]
    fn test_disassemble_sizes_correct() {
        let data = [0x00u8, 0x2A]; // nop + ret
        let instrs = CilDisassembler::disassemble(&data);
        assert_eq!(instrs[0].size, 1);
        assert_eq!(instrs[1].size, 1);
    }

    #[test]
    fn test_disassemble_switch() {
        // switch n=2, offsets=[1, 2]
        let data = [0x45u8, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00];
        let instrs = CilDisassembler::disassemble(&data);
        assert_eq!(instrs.len(), 1);
        if let CilOpCode::Switch(offs) = &instrs[0].opcode {
            assert_eq!(offs, &[1, 2]);
        } else {
            panic!("expected Switch");
        }
    }

    #[test]
    fn test_mnemonic_newobj() {
        let i = CilInstr { offset: 0, opcode: CilOpCode::Newobj(0x0A00_0001), size: 5 };
        assert!(i.mnemonic().starts_with("newobj"));
    }

    #[test]
    fn test_mnemonic_ldloc_0() {
        let i = CilInstr { offset: 0, opcode: CilOpCode::LdlocS0, size: 1 };
        assert_eq!(i.mnemonic(), "ldloc.0");
    }
}
