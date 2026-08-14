//! Decryption loop analyzer — identify and characterise self-decryption routines.
//!
//! Analyses x86/x64 disassembly to detect loops that decrypt or unpack code at
//! runtime.  Extracts key material, algorithm type (XOR, ADD, ROL/ROR, multi-key),
//! loop bounds, and produces a simulation output.

use std::collections::HashMap;
use std::fmt;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Instruction model (lightweight, no external disassembler)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Reg { Eax, Ebx, Ecx, Edx, Esi, Edi, Esp, Ebp, Rax, Rbx, Rcx, Rdx, Rsi, Rdi, Rsp, Rbp, Al, Bl, Cl, Dl, Unknown }

impl Reg {
    const fn from_modrm_reg(n: u8, wide: bool) -> Self {
        if wide {
            match n & 7 { 0 => Self::Rax, 1 => Self::Rcx, 2 => Self::Rdx, 3 => Self::Rbx,
                          4 => Self::Rsp, 5 => Self::Rbp, 6 => Self::Rsi, 7 => Self::Rdi, _ => Self::Unknown }
        } else {
            match n & 7 { 0 => Self::Eax, 1 => Self::Ecx, 2 => Self::Edx, 3 => Self::Ebx,
                          4 => Self::Esp, 5 => Self::Ebp, 6 => Self::Esi, 7 => Self::Edi, _ => Self::Unknown }
        }
    }
    const fn is_counter(self) -> bool { matches!(self, Self::Ecx | Self::Rcx | Self::Edx | Self::Rdx | Self::Eax | Self::Rax) }
    const fn is_pointer(self) -> bool { matches!(self, Self::Esi | Self::Rsi | Self::Edi | Self::Rdi | Self::Ebx | Self::Rbx) }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Operand {
    Reg(Reg),
    Imm(i64),
    Mem { base: Reg, index: Option<Reg>, scale: u8, disp: i32 },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Mnemonic {
    Mov, Xor, Add, Sub, And, Or, Not, Neg, Rol, Ror, Shl, Shr, Sar,
    Inc, Dec, Cmp, Test, Je, Jne, Jz, Jnz, Ja, Jb, Jge, Jle,
    Loop, Loopnz, Loopz, Jmp, Call, Ret, Push, Pop, Lea, Nop, Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Insn {
    pub offset: u64,
    pub mnemonic: Mnemonic,
    pub operands: Vec<Operand>,
    pub size: u8,
    pub raw: Vec<u8>,
}

impl Insn {
    #[must_use]
    pub const fn is_branch(&self) -> bool {
        matches!(self.mnemonic, Mnemonic::Je | Mnemonic::Jne | Mnemonic::Jz | Mnemonic::Jnz
            | Mnemonic::Ja | Mnemonic::Jb | Mnemonic::Jge | Mnemonic::Jle
            | Mnemonic::Loop | Mnemonic::Loopnz | Mnemonic::Loopz | Mnemonic::Jmp)
    }

    #[must_use]
    pub fn branch_target(&self, base_offset: u64) -> Option<u64> {
        if let Some(Operand::Imm(rel)) = self.operands.first() {
            Some((base_offset + u64::from(self.size)).wrapping_add((*rel).cast_unsigned()))
        } else { None }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Lightweight x86 decoder (handles the patterns that appear in crypto loops)
// ─────────────────────────────────────────────────────────────────────────────

pub struct X86Decoder<'a> {
    pub data: &'a [u8],
    pub pos: usize,
    pub base: u64,
    pub x64: bool,
}

impl<'a> X86Decoder<'a> {
    #[must_use]
    pub const fn new(data: &'a [u8], base: u64, x64: bool) -> Self { Self { data, pos: 0, base, x64 } }

    fn _peek(&self) -> Option<u8> { self.data.get(self.pos).copied() }
    fn eat(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() { bail!("unexpected end"); }
        let b = self.data[self.pos]; self.pos += 1; Ok(b)
    }
    fn _eat_u16(&mut self) -> Result<u16> { Ok(u16::from_le_bytes([self.eat()?, self.eat()?])) }
    fn eat_u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes([self.eat()?, self.eat()?, self.eat()?, self.eat()?]))
    }
    fn eat_i32(&mut self) -> Result<i32> { Ok(self.eat_u32()?.cast_signed()) }
    fn eat_i8(&mut self) -> Result<i8> { Ok(self.eat()?.cast_signed()) }

    /// Decode ALU group with 8-bit immediate (opcode `0x80`).
    fn decode_alu8_imm(&mut self) -> Result<(Mnemonic, Vec<Operand>)> {
        let modrm = self.eat()?;
        let op = (modrm >> 3) & 7;
        let rm = Reg::from_modrm_reg(modrm & 7, false);
        let imm = i64::from(self.eat()?);
        let mn = match op { 6 => Mnemonic::Xor, 0 => Mnemonic::Add, 5 => Mnemonic::Sub, 4 => Mnemonic::And, _ => Mnemonic::Unknown };
        Ok((mn, vec![Operand::Reg(rm), Operand::Imm(imm)]))
    }

    /// Decode ALU group with 32-bit immediate (`0x81`) or sign-extended 8-bit (`0x83`).
    fn decode_alu_imm(&mut self, wide: bool, sx8: bool) -> Result<(Mnemonic, Vec<Operand>)> {
        let modrm = self.eat()?;
        let op = (modrm >> 3) & 7;
        let rm = Reg::from_modrm_reg(modrm & 7, wide);
        let imm = if sx8 { i64::from(self.eat_i8()?) } else { i64::from(self.eat_i32()?) };
        let mn = match op { 6 => Mnemonic::Xor, 0 => Mnemonic::Add, 5 => Mnemonic::Sub, 4 => Mnemonic::And, 1 => Mnemonic::Or, 7 => Mnemonic::Cmp, _ => Mnemonic::Unknown };
        Ok((mn, vec![Operand::Reg(rm), Operand::Imm(imm)]))
    }

    /// Decode shift/rotate with immediate count (opcodes `0xC0` and `0xC1`).
    fn decode_shift_imm(&mut self, wide: bool) -> Result<(Mnemonic, Vec<Operand>)> {
        let modrm = self.eat()?;
        let op = (modrm >> 3) & 7;
        let rm = Reg::from_modrm_reg(modrm & 7, wide);
        let cnt = i64::from(self.eat()?);
        let mn = match op { 0 => Mnemonic::Rol, 1 => Mnemonic::Ror, 4 => Mnemonic::Shl, 5 => Mnemonic::Shr, 7 => Mnemonic::Sar, _ => Mnemonic::Unknown };
        Ok((mn, vec![Operand::Reg(rm), Operand::Imm(cnt)]))
    }

    /// Decode two-byte escape (opcode `0x0F`).
    fn decode_0x0f(&mut self) -> Result<(Mnemonic, Vec<Operand>)> {
        let second = self.eat()?;
        match second {
            0x84 => { let rel = i64::from(self.eat_i32()?); Ok((Mnemonic::Je,  vec![Operand::Imm(rel)])) }
            0x85 => { let rel = i64::from(self.eat_i32()?); Ok((Mnemonic::Jne, vec![Operand::Imm(rel)])) }
            _ => Ok((Mnemonic::Unknown, vec![]))
        }
    }

    /// Decode `NOT`/`NEG` group (opcodes `0xF6` and `0xF7`).
    fn decode_not_neg(&mut self, wide: bool) -> Result<(Mnemonic, Vec<Operand>)> {
        let modrm = self.eat()?;
        let rm = Reg::from_modrm_reg(modrm & 7, wide);
        let op = (modrm >> 3) & 7;
        let mn = match op { 2 => Mnemonic::Not, 3 => Mnemonic::Neg, _ => Mnemonic::Unknown };
        Ok((mn, vec![Operand::Reg(rm)]))
    }

    /// Decode a single instruction from the current position.
    ///
    /// # Errors
    ///
    /// Returns an error if the byte stream is exhausted before a complete
    /// instruction can be read.
    pub fn decode_one(&mut self) -> Result<Insn> {
        let start = self.pos;
        let base_off = self.base + start as u64;
        // REX prefix
        let first = self.eat()?;
        let (first, wide) = if self.x64 && (first & 0xF0) == 0x40 {
            let rex = first;
            let b = self.eat()?;
            (b, (rex & 8) != 0)
        } else { (first, false) };

        let (mnemonic, operands) = match first {
            0x90 => (Mnemonic::Nop, vec![]),
            0xC3 | 0xCB => (Mnemonic::Ret, vec![]),
            0x50..=0x57 => (Mnemonic::Push, vec![Operand::Reg(Reg::from_modrm_reg(first & 7, wide))]),
            0x58..=0x5F => (Mnemonic::Pop,  vec![Operand::Reg(Reg::from_modrm_reg(first & 7, wide))]),
            0x40..=0x47 if !self.x64 => (Mnemonic::Inc, vec![Operand::Reg(Reg::from_modrm_reg(first & 7, false))]),
            0x48..=0x4F if !self.x64 => (Mnemonic::Dec, vec![Operand::Reg(Reg::from_modrm_reg(first & 7, false))]),
            0xFE => {
                let modrm = self.eat()?;
                let rm_reg = Reg::from_modrm_reg(modrm & 7, false);
                if (modrm >> 3).trailing_zeros() >= 3 { (Mnemonic::Inc, vec![Operand::Reg(rm_reg)]) }
                else { (Mnemonic::Dec, vec![Operand::Reg(rm_reg)]) }
            }
            0xFF => {
                let modrm = self.eat()?;
                let rm_reg = Reg::from_modrm_reg(modrm & 7, wide);
                let op = (modrm >> 3) & 7;
                match op {
                    0 => (Mnemonic::Inc, vec![Operand::Reg(rm_reg)]),
                    1 => (Mnemonic::Dec, vec![Operand::Reg(rm_reg)]),
                    _ => (Mnemonic::Unknown, vec![])
                }
            }
            0x31 | 0x33 => { let (d, s) = self.decode_modrm_rr(wide)?; (Mnemonic::Xor, vec![d, s]) }
            0x35 => { let imm = i64::from(self.eat_u32()?); (Mnemonic::Xor, vec![Operand::Reg(if wide { Reg::Rax } else { Reg::Eax }), Operand::Imm(imm)]) }
            0x80 => self.decode_alu8_imm()?,
            0x81 => self.decode_alu_imm(wide, false)?,
            0x83 => self.decode_alu_imm(wide, true)?,
            0x01 | 0x03 => { let (d, s) = self.decode_modrm_rr(wide)?; (Mnemonic::Add, vec![d, s]) }
            0x29 | 0x2B => { let (d, s) = self.decode_modrm_rr(wide)?; (Mnemonic::Sub, vec![d, s]) }
            0x39 | 0x3B => { let (d, s) = self.decode_modrm_rr(wide)?; (Mnemonic::Cmp, vec![d, s]) }
            0x3D => { let imm = i64::from(self.eat_u32()?); (Mnemonic::Cmp, vec![Operand::Reg(Reg::Eax), Operand::Imm(imm)]) }
            0x85 => { let (d, s) = self.decode_modrm_rr(wide)?; (Mnemonic::Test, vec![d, s]) }
            0x89 | 0x8B => { let (d, s) = self.decode_modrm_rr(wide)?; (Mnemonic::Mov, vec![d, s]) }
            0x8D => { let (d, s) = self.decode_modrm_rr(wide)?; (Mnemonic::Lea, vec![d, s]) }
            0xB0..=0xB7 => { let imm = i64::from(self.eat()?); (Mnemonic::Mov, vec![Operand::Reg(Reg::from_modrm_reg(first & 7, false)), Operand::Imm(imm)]) }
            0xB8..=0xBF => {
                let imm = if wide {
                    let lo = u64::from(self.eat_u32()?);
                    let hi = u64::from(self.eat_u32()?);
                    (lo | (hi << 32)).cast_signed()
                } else { i64::from(self.eat_u32()?) };
                (Mnemonic::Mov, vec![Operand::Reg(Reg::from_modrm_reg(first & 7, wide)), Operand::Imm(imm)])
            }
            0xC0 => self.decode_shift_imm(false)?,
            0xC1 => self.decode_shift_imm(wide)?,
            0xD0 => { let modrm = self.eat()?; let rm = Reg::from_modrm_reg(modrm & 7, false); (Mnemonic::Rol, vec![Operand::Reg(rm), Operand::Imm(1)]) }
            0xD1 => { let modrm = self.eat()?; let rm = Reg::from_modrm_reg(modrm & 7, wide);  (Mnemonic::Rol, vec![Operand::Reg(rm), Operand::Imm(1)]) }
            0xE2 => { let rel = i64::from(self.eat_i8()?); (Mnemonic::Loop,   vec![Operand::Imm(rel)]) }
            0xE0 => { let rel = i64::from(self.eat_i8()?); (Mnemonic::Loopnz, vec![Operand::Imm(rel)]) }
            0xE1 => { let rel = i64::from(self.eat_i8()?); (Mnemonic::Loopz,  vec![Operand::Imm(rel)]) }
            0x74 => { let rel = i64::from(self.eat_i8()?); (Mnemonic::Je,     vec![Operand::Imm(rel)]) }
            0x75 => { let rel = i64::from(self.eat_i8()?); (Mnemonic::Jne,    vec![Operand::Imm(rel)]) }
            0x72 => { let rel = i64::from(self.eat_i8()?); (Mnemonic::Jb,     vec![Operand::Imm(rel)]) }
            0x73 => { let rel = i64::from(self.eat_i8()?); (Mnemonic::Ja,     vec![Operand::Imm(rel)]) }
            0x7C => { let rel = i64::from(self.eat_i8()?); (Mnemonic::Jle,    vec![Operand::Imm(rel)]) }
            0x7D => { let rel = i64::from(self.eat_i8()?); (Mnemonic::Jge,    vec![Operand::Imm(rel)]) }
            0xEB => { let rel = i64::from(self.eat_i8()?); (Mnemonic::Jmp,    vec![Operand::Imm(rel)]) }
            0xE9 => { let rel = i64::from(self.eat_i32()?); (Mnemonic::Jmp,   vec![Operand::Imm(rel)]) }
            0xE8 => { let rel = i64::from(self.eat_i32()?); (Mnemonic::Call,  vec![Operand::Imm(rel)]) }
            0xF6 => self.decode_not_neg(false)?,
            0xF7 => self.decode_not_neg(wide)?,
            0x0F => self.decode_0x0f()?,
            _ => (Mnemonic::Unknown, vec![]),
        };
        let end = self.pos;
        let raw = self.data[start..end].to_vec();
        Ok(Insn { offset: base_off, mnemonic, operands, size: u8::try_from(end - start).unwrap_or(u8::MAX), raw })
    }

    fn decode_modrm_rr(&mut self, wide: bool) -> Result<(Operand, Operand)> {
        let modrm = self.eat()?;
        let reg = Reg::from_modrm_reg((modrm >> 3) & 7, wide);
        let rm = Reg::from_modrm_reg(modrm & 7, wide);
        let mode = modrm >> 6;
        let operand = match mode {
            3 => Operand::Reg(rm),
            0 => Operand::Mem { base: rm, index: None, scale: 1, disp: 0 },
            1 => { let d = i32::from(self.eat_i8()?); Operand::Mem { base: rm, index: None, scale: 1, disp: d } }
            2 => { let d = self.eat_i32()?; Operand::Mem { base: rm, index: None, scale: 1, disp: d } }
            _ => Operand::Reg(Reg::Unknown),
        };
        Ok((Operand::Reg(reg), operand))
    }

    /// Decode all instructions until end or error.
    #[must_use]
    pub fn decode_all(&mut self) -> Vec<Insn> {
        let mut out = Vec::new();
        while self.pos < self.data.len() {
            match self.decode_one() {
                Ok(i) => out.push(i),
                Err(_) => { self.pos += 1; } // skip unknown
            }
        }
        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Loop detection
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoopBounds {
    pub start_offset: u64,
    pub end_offset: u64,
    pub branch_offset: u64,
    pub branch_mnemonic: String,
}

fn find_loops(insns: &[Insn]) -> Vec<LoopBounds> {
    let mut loops = Vec::new();
    let offset_to_idx: HashMap<u64, usize> = insns.iter().enumerate().map(|(i, ins)| (ins.offset, i)).collect();
    for insn in insns {
        if !insn.is_branch() { continue; }
        let Some(target) = insn.branch_target(insn.offset) else { continue };
        // backward branch = loop back-edge
        if target < insn.offset && let Some(&start_idx) = offset_to_idx.get(&target) {
            loops.push(LoopBounds {
                start_offset: insns[start_idx].offset,
                end_offset: insn.offset,
                branch_offset: insn.offset,
                branch_mnemonic: format!("{:?}", insn.mnemonic),
            });
        }
    }
    loops
}

// ─────────────────────────────────────────────────────────────────────────────
// Decryption pattern classifier
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum DecryptAlgo {
    Xor,
    XorRolling,
    Add,
    Sub,
    Rol,
    Ror,
    XorThenAdd,
    AddThenXor,
    MultiKey,
    Unknown,
}

impl fmt::Display for DecryptAlgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{self:?}") }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptionLoop {
    pub bounds: LoopBounds,
    pub algorithm: DecryptAlgo,
    /// XOR/ADD key bytes extracted from immediate operands.
    pub keys: Vec<i64>,
    /// Which register is used as the data pointer.
    pub data_ptr_reg: Option<String>,
    /// Which register is used as the loop counter.
    pub counter_reg: Option<String>,
    /// Whether the key is updated each iteration (rolling/counter key).
    pub rolling_key: bool,
    /// Estimated number of iterations, if determinable.
    pub iteration_count: Option<u64>,
    /// Whether this loop also changes the instruction pointer (self-modifying).
    pub writes_execute_region: bool,
}

fn classify_loop(insns: &[Insn], bounds: &LoopBounds) -> DecryptionLoop {
    let loop_insns: Vec<&Insn> = insns.iter().filter(|i| i.offset >= bounds.start_offset && i.offset <= bounds.end_offset).collect();
    let mut xor_count = 0usize;
    let mut add_count = 0usize;
    let mut rotate_left_n = 0usize;
    let mut rotate_right_n = 0usize;
    let mut keys = Vec::new();
    let mut ptr_reg = None;
    let mut ctr_reg = None;
    let mut rolling = false;
    let mut iteration_count = None;

    for insn in &loop_insns {
        match insn.mnemonic {
            Mnemonic::Xor => {
                xor_count += 1;
                if let Some(Operand::Imm(v)) = insn.operands.get(1) { keys.push(*v); }
            }
            Mnemonic::Add => {
                add_count += 1;
                if let Some(Operand::Imm(v)) = insn.operands.get(1) { keys.push(*v); }
            }
            Mnemonic::Sub => {
                add_count += 1;
                if let Some(Operand::Imm(v)) = insn.operands.get(1) { keys.push(-*v); }
            }
            Mnemonic::Rol => {
                rotate_left_n += 1;
                if let Some(Operand::Imm(v)) = insn.operands.get(1) { keys.push(*v); }
            }
            Mnemonic::Ror => {
                rotate_right_n += 1;
                if let Some(Operand::Imm(v)) = insn.operands.get(1) { keys.push(*v); }
            }
            Mnemonic::Inc | Mnemonic::Dec => {
                // If we're incrementing a register that was used as key, it's rolling
                if let Some(Operand::Reg(r)) = insn.operands.first() {
                    if r.is_counter() { rolling = true; }
                    if r.is_pointer() { ptr_reg = Some(format!("{r:?}")); }
                }
            }
            Mnemonic::Mov | Mnemonic::Lea => {
                if let Some(Operand::Reg(r)) = insn.operands.first() && r.is_pointer() {
                    ptr_reg = Some(format!("{r:?}"));
                }
            }
            Mnemonic::Loop | Mnemonic::Loopnz | Mnemonic::Loopz => {
                ctr_reg = Some("Ecx".to_owned());
            }
            Mnemonic::Cmp => {
                if let Some(Operand::Imm(v)) = insn.operands.get(1) && *v > 0 && *v < 0x1000_0000 {
                    iteration_count = Some((*v).cast_unsigned());
                }
            }
            _ => {}
        }
    }

    let algorithm = if xor_count > 0 && (rotate_left_n > 0 || add_count > 0) { DecryptAlgo::XorThenAdd }
        else if add_count > 0 && xor_count > 0 { DecryptAlgo::AddThenXor }
        else if xor_count > 1 { DecryptAlgo::MultiKey }
        else if xor_count > 0 && rolling { DecryptAlgo::XorRolling }
        else if xor_count > 0 { DecryptAlgo::Xor }
        else if add_count > 0 { DecryptAlgo::Add }
        else if rotate_left_n > 0 { DecryptAlgo::Rol }
        else if rotate_right_n > 0 { DecryptAlgo::Ror }
        else { DecryptAlgo::Unknown };

    DecryptionLoop {
        bounds: bounds.clone(),
        algorithm,
        keys,
        data_ptr_reg: ptr_reg,
        counter_reg: ctr_reg,
        rolling_key: rolling,
        iteration_count,
        writes_execute_region: false,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Emulated decryption
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EmulatedResult {
    pub decrypted: Vec<u8>,
    pub iterations: usize,
    pub algo: DecryptAlgo,
}

/// Apply a detected decryption loop to plaintext `data` by emulating its effect.
#[must_use]
pub fn emulate_decrypt(data: &[u8], loop_info: &DecryptionLoop) -> EmulatedResult {
    let mut out = data.to_vec();
    let _count = out.len();
    let mut iters = 0;
    match loop_info.algorithm {
        DecryptAlgo::Xor => {
            let key = u8::try_from(loop_info.keys.first().copied().unwrap_or(0) & 0xFF).unwrap_or(0);
            for b in &mut out { *b ^= key; iters += 1; }
        }
        DecryptAlgo::XorRolling => {
            let mut key = u8::try_from(loop_info.keys.first().copied().unwrap_or(0) & 0xFF).unwrap_or(0);
            for b in &mut out { *b ^= key; key = key.wrapping_add(1); iters += 1; }
        }
        DecryptAlgo::Add => {
            let key = u8::try_from(loop_info.keys.first().copied().unwrap_or(0) & 0xFF).unwrap_or(0);
            for b in &mut out { *b = b.wrapping_sub(key); iters += 1; }
        }
        DecryptAlgo::Sub => {
            let key = u8::try_from(loop_info.keys.first().copied().unwrap_or(0) & 0xFF).unwrap_or(0);
            for b in &mut out { *b = b.wrapping_add(key); iters += 1; }
        }
        DecryptAlgo::Rol => {
            let shift = u32::try_from(loop_info.keys.first().copied().unwrap_or(1) & 7).unwrap_or(1);
            for b in &mut out { *b = b.rotate_left(shift); iters += 1; }
        }
        DecryptAlgo::Ror => {
            let shift = u32::try_from(loop_info.keys.first().copied().unwrap_or(1) & 7).unwrap_or(1);
            for b in &mut out { *b = b.rotate_right(shift); iters += 1; }
        }
        DecryptAlgo::XorThenAdd => {
            let xk = u8::try_from(loop_info.keys.first().copied().unwrap_or(0) & 0xFF).unwrap_or(0);
            let ak = u8::try_from(loop_info.keys.get(1).copied().unwrap_or(0) & 0xFF).unwrap_or(0);
            for b in &mut out { *b = (*b ^ xk).wrapping_sub(ak); iters += 1; }
        }
        DecryptAlgo::AddThenXor => {
            let ak = u8::try_from(loop_info.keys.first().copied().unwrap_or(0) & 0xFF).unwrap_or(0);
            let xk = u8::try_from(loop_info.keys.get(1).copied().unwrap_or(0) & 0xFF).unwrap_or(0);
            for b in &mut out { *b = b.wrapping_sub(ak) ^ xk; iters += 1; }
        }
        DecryptAlgo::MultiKey => {
            let keys: Vec<u8> = loop_info.keys.iter().map(|&k| u8::try_from(k & 0xFF).unwrap_or(0)).collect();
            if !keys.is_empty() {
                for (i, b) in out.iter_mut().enumerate() {
                    *b ^= keys[i % keys.len()];
                    iters += 1;
                }
            }
        }
        DecryptAlgo::Unknown => {}
    }
    EmulatedResult { decrypted: out, iterations: iters, algo: loop_info.algorithm }
}

// ─────────────────────────────────────────────────────────────────────────────
// Main analyzer
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub total_instructions: usize,
    pub loops_found: usize,
    pub decryption_loops: Vec<DecryptionLoop>,
    pub unique_algorithms: Vec<DecryptAlgo>,
    pub key_bytes: Vec<u8>,
}

pub struct DecryptionLoopAnalyzer {
    pub x64: bool,
    pub base_address: u64,
}

impl DecryptionLoopAnalyzer {
    #[must_use]
    pub const fn new(x64: bool, base_address: u64) -> Self { Self { x64, base_address } }

    #[must_use]
    pub fn analyze(&self, code: &[u8]) -> AnalysisResult {
        let mut dec = X86Decoder::new(code, self.base_address, self.x64);
        let insns = dec.decode_all();
        let loop_bounds = find_loops(&insns);
        let mut decryption_loops: Vec<DecryptionLoop> = loop_bounds.iter()
            .map(|b| classify_loop(&insns, b))
            .filter(|l| l.algorithm != DecryptAlgo::Unknown || !l.keys.is_empty())
            .collect();
        // Mark write-execute overlaps
        let exec_ranges: Vec<(u64, u64)> = vec![(self.base_address, self.base_address + code.len() as u64)];
        for l in &mut decryption_loops {
            l.writes_execute_region = exec_ranges.iter().any(|(s, e)| l.bounds.start_offset >= *s && l.bounds.end_offset <= *e);
        }
        let mut algos: Vec<DecryptAlgo> = decryption_loops.iter().map(|l| l.algorithm).collect();
        algos.dedup();
        let key_bytes: Vec<u8> = decryption_loops.iter().flat_map(|l| l.keys.iter().map(|&k| u8::try_from(k & 0xFF).unwrap_or(0))).collect();
        AnalysisResult {
            total_instructions: insns.len(),
            loops_found: loop_bounds.len(),
            decryption_loops,
            unique_algorithms: algos,
            key_bytes,
        }
    }

    #[must_use]
    pub fn analyze_and_decrypt(&self, code: &[u8], data: &[u8]) -> Vec<EmulatedResult> {
        let result = self.analyze(code);
        result.decryption_loops.iter().map(|l| emulate_decrypt(data, l)).collect()
    }

    /// Brute-force single-byte XOR key search by looking for valid x86 prologs.
    #[must_use]
    pub fn brute_force_xor_key(&self, encrypted: &[u8]) -> Option<u8> {
        for key in 0u8..=255 {
            let decrypted: Vec<u8> = encrypted.iter().map(|&b| b ^ key).collect();
            if looks_like_code_prolog(&decrypted) { return Some(key); }
        }
        None
    }

    /// Brute-force single-byte ADD key.
    #[must_use]
    pub fn brute_force_add_key(&self, encrypted: &[u8]) -> Option<u8> {
        for key in 0u8..=255 {
            if key == 0 { continue; }
            let decrypted: Vec<u8> = encrypted.iter().map(|&b| b.wrapping_sub(key)).collect();
            if looks_like_code_prolog(&decrypted) { return Some(key); }
        }
        None
    }
}

fn looks_like_code_prolog(data: &[u8]) -> bool {
    if data.len() < 4 { return false; }
    // Common x86 function prologues
    matches!(
        (data[0], data[1], data[2]),
        (0x55, 0x8B, 0xEC) | // push ebp; mov ebp, esp
        (0x55, 0x48, 0x89) | // push rbp; mov rbp, rsp (x64)
        (0x53, 0x56, 0x57) | // push ebx; push esi; push edi
        (0x56, 0x57, 0x55) | // push esi; push edi; push ebp
        (0x83, 0xEC, _)    | // sub esp, N
        (0x48, 0x83, 0xEC)   // sub rsp, N (x64)
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Key schedule analysis
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySchedule {
    pub initial_key: Vec<u8>,
    pub transformed_keys: Vec<Vec<u8>>,
    pub transformation: String,
}

/// Reconstruct a simple linear key schedule from a rolling-XOR loop.
#[must_use]
pub fn reconstruct_key_schedule(initial_key: &[u8], length: usize, step: u8) -> KeySchedule {
    let mut transformed = Vec::with_capacity(length);
    let mut k = initial_key.to_vec();
    for _ in 0..length {
        transformed.push(k.clone());
        for b in &mut k { *b = b.wrapping_add(step); }
    }
    KeySchedule {
        initial_key: initial_key.to_vec(),
        transformed_keys: transformed,
        transformation: format!("key[i+1] = key[i] + 0x{step:02X}"),
    }
}

/// Identify constant-XOR multi-byte keys by analysing byte-frequency of decrypted output.
#[must_use]
pub fn identify_xor_key_from_frequency(ciphertext: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = vec![0u8; key_len];
    for (k, key_byte) in key.iter_mut().enumerate() {
        let mut freq = [0u32; 256];
        let mut i = k;
        while i < ciphertext.len() {
            freq[usize::from(ciphertext[i])] += 1;
            i += key_len;
        }
        *key_byte = freq.iter().enumerate()
            .max_by_key(|&(_, &c)| c)
            .map_or(0, |(b, _)| u8::try_from(b).unwrap_or(u8::MAX));
    }
    key
}
