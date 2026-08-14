//! Pure-Rust ARM Thumb2 interpreter implementing the [`Emulator`] trait.
//!
//! Covers the most common Thumb/Thumb-2 instructions: data processing (MOV, ADD,
//! SUB, AND, ORR, EOR, LSL, LSR, ASR, ROR, BIC, MVN), memory access
//! (LDR/STR in byte/halfword/word variants), branch instructions
//! (B, BL, BX, BLX, Bcc), comparison (CMP, CMN, TST), PUSH/POP, and
//! two-register forms with shifted operands.
//!
//! The interpreter uses a flat `BTreeMap`-backed address space identical to
//! [`SimpleInterpreter`] so all `Emulator` plumbing is self-contained.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{EmulatorArch, EmulatorError, HookHandle, HookKind, MemPerms, MemRegion};

// ── memory helpers (local copies so this module is self-contained) ────────────

fn arm_mem_read(
    memory: &BTreeMap<u64, Vec<u8>>,
    regions: &[MemRegion],
    addr: u64,
    len: usize,
) -> Result<Vec<u8>, EmulatorError> {
    let region =
        regions
            .iter()
            .find(|r| r.contains(addr))
            .ok_or_else(|| EmulatorError::MemFault {
                addr,
                op: "read".into(),
            })?;
    if !region.perms.contains(MemPerms::READ) {
        return Err(EmulatorError::MemFault {
            addr,
            op: "read-perm".into(),
        });
    }
    let base = region.start;
    let buf = memory.get(&base).ok_or_else(|| EmulatorError::MemFault {
        addr,
        op: "read".into(),
    })?;
    let offset = usize::try_from(addr - base).unwrap_or(usize::MAX);
    if offset + len > buf.len() {
        return Err(EmulatorError::MemFault {
            addr: addr + (buf.len().saturating_sub(offset)) as u64,
            op: "read-oob".into(),
        });
    }
    Ok(buf[offset..offset + len].to_vec())
}

fn arm_mem_write(
    memory: &mut BTreeMap<u64, Vec<u8>>,
    regions: &[MemRegion],
    addr: u64,
    data: &[u8],
) -> Result<(), EmulatorError> {
    let region =
        regions
            .iter()
            .find(|r| r.contains(addr))
            .ok_or_else(|| EmulatorError::MemFault {
                addr,
                op: "write".into(),
            })?;
    if !region.perms.contains(MemPerms::WRITE) {
        return Err(EmulatorError::MemFault {
            addr,
            op: "write-perm".into(),
        });
    }
    let base = region.start;
    let buf = memory
        .get_mut(&base)
        .ok_or_else(|| EmulatorError::MemFault {
            addr,
            op: "write".into(),
        })?;
    let offset = usize::try_from(addr - base).unwrap_or(usize::MAX);
    if offset + data.len() > buf.len() {
        return Err(EmulatorError::MemFault {
            addr: addr + (buf.len().saturating_sub(offset)) as u64,
            op: "write-oob".into(),
        });
    }
    buf[offset..offset + data.len()].copy_from_slice(data);
    Ok(())
}

// ── CPSR flag bits ────────────────────────────────────────────────────────────

/// Negative flag
const CPSR_N: u32 = 1 << 31;
/// Zero flag
const CPSR_Z: u32 = 1 << 30;
/// Carry flag
const CPSR_C: u32 = 1 << 29;
/// Overflow flag
const CPSR_V: u32 = 1 << 28;
/// Thumb state bit
const CPSR_T: u32 = 1 << 5;

// ── Register file ─────────────────────────────────────────────────────────────

/// ARM register file: R0–R15 + CPSR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmRegFile {
    /// General-purpose registers, index 0–15 (R0–R15 / SP/LR/PC).
    pub r: [u32; 16],
    /// Current Program Status Register.
    pub cpsr: u32,
}

impl Default for ArmRegFile {
    fn default() -> Self {
        Self {
            r: [0u32; 16],
            cpsr: CPSR_T,
        }
    }
}

impl ArmRegFile {
    #[inline]
    #[must_use]
    pub const fn pc(&self) -> u32 {
        self.r[15]
    }
    #[inline]
    pub const fn set_pc(&mut self, v: u32) {
        self.r[15] = v & !1;
    }
    #[inline]
    #[must_use]
    pub const fn sp(&self) -> u32 {
        self.r[13]
    }
    #[inline]
    pub const fn set_sp(&mut self, v: u32) {
        self.r[13] = v;
    }
    #[inline]
    #[must_use]
    pub const fn lr(&self) -> u32 {
        self.r[14]
    }
    #[inline]
    pub const fn set_lr(&mut self, v: u32) {
        self.r[14] = v;
    }

    /// Negative flag (CPSR.N).
    #[inline]
    #[must_use]
    pub const fn nf(&self) -> bool {
        (self.cpsr & CPSR_N) != 0
    }
    /// Zero flag (CPSR.Z).
    #[inline]
    #[must_use]
    pub const fn zf(&self) -> bool {
        (self.cpsr & CPSR_Z) != 0
    }
    /// Carry flag (CPSR.C).
    #[inline]
    #[must_use]
    pub const fn cf(&self) -> bool {
        (self.cpsr & CPSR_C) != 0
    }
    /// Overflow flag (CPSR.V).
    #[inline]
    #[must_use]
    pub const fn vf(&self) -> bool {
        (self.cpsr & CPSR_V) != 0
    }

    const fn set_nzc(&mut self, result: u32, carry: bool) {
        let mut cpsr = self.cpsr & !(CPSR_N | CPSR_Z | CPSR_C);
        if result == 0 {
            cpsr |= CPSR_Z;
        }
        if (result & (1 << 31)) != 0 {
            cpsr |= CPSR_N;
        }
        if carry {
            cpsr |= CPSR_C;
        }
        self.cpsr = cpsr;
    }

    const fn set_nzcv(&mut self, result: u32, carry: bool, overflow: bool) {
        let mut cpsr = self.cpsr & !(CPSR_N | CPSR_Z | CPSR_C | CPSR_V);
        if result == 0 {
            cpsr |= CPSR_Z;
        }
        if (result & (1 << 31)) != 0 {
            cpsr |= CPSR_N;
        }
        if carry {
            cpsr |= CPSR_C;
        }
        if overflow {
            cpsr |= CPSR_V;
        }
        self.cpsr = cpsr;
    }
}

// ── Hook storage types ────────────────────────────────────────────────────────

type ArmCodeHook = (u64, u64, Box<dyn Fn(u64, u32) + Send + Sync>);
type ArmMemHook = (HookKind, Box<dyn Fn(u64, usize, u64) + Send + Sync>);

// ── ArmThumbInterpreter ───────────────────────────────────────────────────────

/// Pure-Rust ARM Thumb / Thumb-2 interpreter.
///
/// Executes 16-bit Thumb instructions and a subset of the 32-bit Thumb-2
/// encoding. Implements [`crate::Emulator`] so it can be used anywhere the
/// trait is expected.
pub struct ArmThumbInterpreter {
    pub regs: ArmRegFile,
    memory: BTreeMap<u64, Vec<u8>>,
    regions: Vec<MemRegion>,
    hook_counter: u64,
    code_hooks: Vec<(HookHandle, ArmCodeHook)>,
    mem_hooks: Vec<(HookHandle, ArmMemHook)>,
    stop_requested: bool,
}

impl ArmThumbInterpreter {
    /// Create a new interpreter. The CPSR Thumb bit is set by default.
    #[must_use]
    pub fn new() -> Self {
        Self {
            regs: ArmRegFile::default(),
            memory: BTreeMap::new(),
            regions: Vec::new(),
            hook_counter: 0,
            code_hooks: Vec::new(),
            mem_hooks: Vec::new(),
            stop_requested: false,
        }
    }

    const fn next_handle(&mut self) -> HookHandle {
        self.hook_counter += 1;
        HookHandle(self.hook_counter)
    }

    // ── hook fires ───────────────────────────────────────────────────────────

    fn fire_code_hooks(&self, pc: u64, size: u32) {
        for (_, (b, e, cb)) in &self.code_hooks {
            if pc >= *b && pc < *e {
                cb(pc, size);
            }
        }
    }

    fn fire_mem_hooks(&self, kind: &HookKind, addr: u64, size: usize, val: u64) {
        for (_, (k, cb)) in &self.mem_hooks {
            if k == kind {
                cb(addr, size, val);
            }
        }
    }

    // ── SP push/pop helpers ───────────────────────────────────────────────────

    fn push_u32(&mut self, val: u32) -> Result<(), EmulatorError> {
        let sp = self.regs.sp().wrapping_sub(4);
        self.regs.set_sp(sp);
        let bytes = val.to_le_bytes();
        self.fire_mem_hooks(&HookKind::MemWrite, u64::from(sp), 4, u64::from(val));
        arm_mem_write(&mut self.memory, &self.regions, u64::from(sp), &bytes)
    }

    fn pop_u32(&mut self) -> Result<u32, EmulatorError> {
        let sp = self.regs.sp();
        self.fire_mem_hooks(&HookKind::MemRead, u64::from(sp), 4, 0);
        let bytes = arm_mem_read(&self.memory, &self.regions, u64::from(sp), 4)?;
        self.regs.set_sp(sp.wrapping_add(4));
        Ok(u32::from_le_bytes(bytes.try_into().unwrap_or([0u8; 4])))
    }

    // ── helpers to read/write words from memory ───────────────────────────────

    fn mem_read_u32(&self, addr: u32) -> Result<u32, EmulatorError> {
        let bytes = arm_mem_read(&self.memory, &self.regions, u64::from(addr), 4)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap_or([0u8; 4])))
    }

    fn mem_write_u32(&mut self, addr: u32, val: u32) -> Result<(), EmulatorError> {
        arm_mem_write(
            &mut self.memory,
            &self.regions,
            u64::from(addr),
            &val.to_le_bytes(),
        )
    }

    fn mem_read_u16(&self, addr: u32) -> Result<u16, EmulatorError> {
        let bytes = arm_mem_read(&self.memory, &self.regions, u64::from(addr), 2)?;
        Ok(u16::from_le_bytes(bytes.try_into().unwrap_or([0u8; 2])))
    }

    fn mem_write_u16(&mut self, addr: u32, val: u16) -> Result<(), EmulatorError> {
        arm_mem_write(
            &mut self.memory,
            &self.regions,
            u64::from(addr),
            &val.to_le_bytes(),
        )
    }

    fn mem_read_u8(&self, addr: u32) -> Result<u8, EmulatorError> {
        let bytes = arm_mem_read(&self.memory, &self.regions, u64::from(addr), 1)?;
        Ok(bytes[0])
    }

    fn mem_write_u8(&mut self, addr: u32, val: u8) -> Result<(), EmulatorError> {
        arm_mem_write(&mut self.memory, &self.regions, u64::from(addr), &[val])
    }

    // ── condition evaluation ──────────────────────────────────────────────────

    /// Evaluate a 4-bit condition code against CPSR flags.
    const fn eval_cond(&self, cond: u8) -> bool {
        let n = self.regs.nf();
        let z = self.regs.zf();
        let c = self.regs.cf();
        let v = self.regs.vf();
        match cond & 0xF {
            0x0 => z,              // EQ
            0x1 => !z,             // NE
            0x2 => c,              // CS/HS
            0x3 => !c,             // CC/LO
            0x4 => n,              // MI
            0x5 => !n,             // PL
            0x6 => v,              // VS
            0x7 => !v,             // VC
            0x8 => c && !z,        // HI
            0x9 => !c || z,        // LS
            0xA => n == v,         // GE
            0xB => n != v,         // LT
            0xC => !z && (n == v), // GT
            0xD => z || (n != v),  // LE
            0xE => true,           // AL
            _ => false,
        }
    }

    // ── barrel-shifter helper ─────────────────────────────────────────────────

    const fn lsl_c(val: u32, shift: u32) -> (u32, bool) {
        if shift == 0 {
            return (val, false);
        }
        if shift >= 32 {
            return (0, shift == 32 && (val & 1) != 0);
        }
        let carry = ((val >> (32 - shift)) & 1) != 0;
        (val << shift, carry)
    }

    const fn lsr_c(val: u32, shift: u32) -> (u32, bool) {
        if shift == 0 {
            return (val, false);
        }
        if shift >= 32 {
            return (0, shift == 32 && (val >> 31 & 1) != 0);
        }
        let carry = ((val >> (shift - 1)) & 1) != 0;
        (val >> shift, carry)
    }

    fn asr_c(val: u32, shift: u32) -> (u32, bool) {
        if shift == 0 {
            return (val, false);
        }
        // The carry-out of a right shift is the LAST bit shifted OUT, i.e. bit
        // `shift - 1`. Reading bit `shift` returned the lowest bit that
        // SURVIVES, so a following BCS/BCC branched the wrong way. The sibling
        // `lsr_c` above already does this correctly.
        let shift = shift.min(32);
        let carry = ((val >> (shift - 1).min(31)) & 1) != 0;
        let result = (val.cast_signed() >> shift.min(31)).cast_unsigned();
        (result, carry)
    }

    const fn ror_c(val: u32, shift: u32) -> (u32, bool) {
        if shift == 0 {
            return (val, false);
        }
        let shift = shift & 31;
        if shift == 0 {
            return (val, (val >> 31) != 0);
        }
        let result = val.rotate_right(shift);
        (result, (result >> 31) != 0)
    }

    // ── ADD with carry-out / overflow ─────────────────────────────────────────

    fn add_with_carry(a: u32, b: u32, cin: u32) -> (u32, bool, bool) {
        let r64 = u64::from(a) + u64::from(b) + u64::from(cin);
        let result = u32::try_from(r64 & 0xFFFF_FFFF).unwrap_or(0);
        let carry = r64 > 0xFFFF_FFFF;
        let overflow = (!(a ^ b) & (a ^ result)) >> 31 != 0;
        (result, carry, overflow)
    }

    // ── 16-bit instruction decode ─────────────────────────────────────────────

    /// Decode and execute one 16-bit Thumb instruction.
    /// Returns (`insn_bytes_consumed`, Option<`new_pc`>).
    fn step_thumb16(&mut self, insn: u16, pc: u32) -> Result<(u32, Option<u32>), EmulatorError> {
        let op15_13 = (insn >> 13) as u8;
        match op15_13 {
            // ── Shift / Add / Sub / Move ──────────────────────────────────────
            0b000 => Ok(self.exec_shift_add_sub(insn, pc)),
            0b001 => Ok(self.exec_cmp_mov_imm(insn, pc)),
            0b010 => self.exec_dp_or_ldr_lit(insn, pc),
            0b011 => self.exec_ldr_str_imm(insn, pc),
            0b100 => self.exec_ldr_str_reg_sp(insn, pc),
            0b101 => self.exec_adr_sp_misc(insn, pc),
            0b110 => self.exec_ldm_stm_branch(insn, pc),
            0b111 => self.exec_svc_branch(insn, pc),
            _ => Err(EmulatorError::InvalidInsn {
                addr: u64::from(pc),
            }),
        }
    }

    fn exec_shift_add_sub(&mut self, insn: u16, pc: u32) -> (u32, Option<u32>) {
        let op = (insn >> 11) & 0x3;
        match op {
            0 => {
                // LSL (immediate) T1: imm5 != 0
                let imm5 = u32::from((insn >> 6) & 0x1F);
                let rm = ((insn >> 3) & 0x7) as usize;
                let rd = (insn & 0x7) as usize;
                let (result, carry) = Self::lsl_c(self.regs.r[rm], imm5);
                self.regs.r[rd] = result;
                self.regs
                    .set_nzc(result, if imm5 == 0 { self.regs.cf() } else { carry });
            }
            1 => {
                // LSR (immediate) T1
                let imm5 = u32::from((insn >> 6) & 0x1F);
                let rm = ((insn >> 3) & 0x7) as usize;
                let rd = (insn & 0x7) as usize;
                let shift = if imm5 == 0 { 32 } else { imm5 };
                let (result, carry) = Self::lsr_c(self.regs.r[rm], shift);
                self.regs.r[rd] = result;
                self.regs.set_nzc(result, carry);
            }
            2 => {
                // ASR (immediate) T1
                let imm5 = u32::from((insn >> 6) & 0x1F);
                let rm = ((insn >> 3) & 0x7) as usize;
                let rd = (insn & 0x7) as usize;
                let shift = if imm5 == 0 { 32 } else { imm5 };
                let (result, carry) = Self::asr_c(self.regs.r[rm], shift);
                self.regs.r[rd] = result;
                self.regs.set_nzc(result, carry);
            }
            3 => {
                // ADD/SUB register or imm3
                let sub_flag = (insn >> 9) & 1 != 0;
                let imm_flag = (insn >> 10) & 1 != 0;
                let rn_or_imm3 = u32::from((insn >> 6) & 0x7);
                let rn = ((insn >> 3) & 0x7) as usize;
                let rd = (insn & 0x7) as usize;
                let operand2 = if imm_flag {
                    rn_or_imm3
                } else {
                    self.regs.r[rn_or_imm3 as usize]
                };
                let (result, carry, overflow) = if sub_flag {
                    Self::add_with_carry(self.regs.r[rn], !operand2, 1)
                } else {
                    Self::add_with_carry(self.regs.r[rn], operand2, 0)
                };
                self.regs.r[rd] = result;
                self.regs.set_nzcv(result, carry, overflow);
            }
            _ => unreachable!(),
        }
        (2, Some(pc.wrapping_add(2)))
    }

    fn exec_cmp_mov_imm(&mut self, insn: u16, pc: u32) -> (u32, Option<u32>) {
        let op = (insn >> 11) & 0x3;
        let rdn = ((insn >> 8) & 0x7) as usize;
        let imm8 = u32::from(insn & 0xFF);
        match op {
            0 => {
                // MOV (immediate) T1
                self.regs.r[rdn] = imm8;
                self.regs.set_nzc(imm8, self.regs.cf());
            }
            1 => {
                // CMP (immediate) T1
                let (result, carry, overflow) = Self::add_with_carry(self.regs.r[rdn], !imm8, 1);
                self.regs.set_nzcv(result, carry, overflow);
            }
            2 => {
                // ADD (immediate) T2
                let (result, carry, overflow) = Self::add_with_carry(self.regs.r[rdn], imm8, 0);
                self.regs.r[rdn] = result;
                self.regs.set_nzcv(result, carry, overflow);
            }
            3 => {
                // SUB (immediate) T2
                let (result, carry, overflow) = Self::add_with_carry(self.regs.r[rdn], !imm8, 1);
                self.regs.r[rdn] = result;
                self.regs.set_nzcv(result, carry, overflow);
            }
            _ => unreachable!(),
        }
        (2, Some(pc.wrapping_add(2)))
    }

    fn exec_dp_or_ldr_lit(
        &mut self,
        insn: u16,
        pc: u32,
    ) -> Result<(u32, Option<u32>), EmulatorError> {
        let b12 = (insn >> 12) & 1;
        if b12 == 0 {
            // Data-processing or special data instructions
            let op11_10 = (insn >> 10) & 3;
            if op11_10 == 0b01 {
                // Special data instructions and BX/BLX
                return self.exec_special_dp(insn, pc);
            }
            if op11_10 == 0b11 {
                // LDR (literal) T1
                let rt = ((insn >> 8) & 0x7) as usize;
                let imm8 = u32::from(insn & 0xFF);
                let base = (pc.wrapping_add(4)) & !3;
                let addr = base.wrapping_add(imm8 << 2);
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 4, 0);
                let val = self.mem_read_u32(addr)?;
                self.regs.r[rt] = val;
                return Ok((2, Some(pc.wrapping_add(2))));
            }
            // Data-processing (register)
            self.exec_dp_reg(insn, pc)
        } else {
            // `0101` — load/store with a register offset.
            self.exec_ldr_str_reg_offset(insn, pc)
        }
    }

    fn exec_dp_reg(&mut self, insn: u16, pc: u32) -> Result<(u32, Option<u32>), EmulatorError> {
        let opcode = ((insn >> 6) & 0xF) as u8;
        let rm = ((insn >> 3) & 0x7) as usize;
        let rdn = (insn & 0x7) as usize;
        let a = self.regs.r[rdn];
        let b = self.regs.r[rm];
        match opcode {
            0x0 => {
                // AND
                let r = a & b;
                self.regs.r[rdn] = r;
                self.regs.set_nzc(r, self.regs.cf());
            }
            0x1 => {
                // EOR
                let r = a ^ b;
                self.regs.r[rdn] = r;
                self.regs.set_nzc(r, self.regs.cf());
            }
            0x2 => {
                // LSL (register) T1
                let shift = b & 0xFF;
                let (r, carry) = Self::lsl_c(a, shift);
                self.regs.r[rdn] = r;
                self.regs.set_nzc(r, carry);
            }
            0x3 => {
                // LSR (register) T1
                let shift = b & 0xFF;
                let (r, carry) = Self::lsr_c(a, shift);
                self.regs.r[rdn] = r;
                self.regs.set_nzc(r, carry);
            }
            0x4 => {
                // ASR (register) T1
                let shift = b & 0xFF;
                let (r, carry) = Self::asr_c(a, shift);
                self.regs.r[rdn] = r;
                self.regs.set_nzc(r, carry);
            }
            0x5 => {
                // ADC
                let cin = u32::from(self.regs.cf());
                let (r, carry, overflow) = Self::add_with_carry(a, b, cin);
                self.regs.r[rdn] = r;
                self.regs.set_nzcv(r, carry, overflow);
            }
            0x6 => {
                // SBC
                let cin = u32::from(self.regs.cf());
                let (r, carry, overflow) = Self::add_with_carry(a, !b, cin);
                self.regs.r[rdn] = r;
                self.regs.set_nzcv(r, carry, overflow);
            }
            0x7 => {
                // ROR (register) T1
                let shift = b & 0xFF;
                let (r, carry) = Self::ror_c(a, shift);
                self.regs.r[rdn] = r;
                self.regs.set_nzc(r, carry);
            }
            0x8 => {
                // TST
                let r = a & b;
                self.regs.set_nzc(r, self.regs.cf());
            }
            0x9 => {
                // RSB (NEG) imm=0 — `RSB rdn, rm, #0` computes `0 - rm`.
                // Negating `a` (the DESTINATION) instead of `b` made
                // `RSB r0, r1, #0` return `0 - r0`, i.e. the wrong register
                // entirely; with r0 == 0 it produced 0 and set Z.
                let (r, carry, overflow) = Self::add_with_carry(!b, 0, 1);
                self.regs.r[rdn] = r;
                self.regs.set_nzcv(r, carry, overflow);
            }
            0xA => {
                // CMP (register) T1
                let (r, carry, overflow) = Self::add_with_carry(a, !b, 1);
                self.regs.set_nzcv(r, carry, overflow);
            }
            0xB => {
                // CMN
                let (r, carry, overflow) = Self::add_with_carry(a, b, 0);
                self.regs.set_nzcv(r, carry, overflow);
            }
            0xC => {
                // ORR
                let r = a | b;
                self.regs.r[rdn] = r;
                self.regs.set_nzc(r, self.regs.cf());
            }
            0xD => {
                // MUL T1
                let r = a.wrapping_mul(b);
                self.regs.r[rdn] = r;
                self.regs.set_nzc(r, self.regs.cf());
            }
            0xE => {
                // BIC
                let r = a & !b;
                self.regs.r[rdn] = r;
                self.regs.set_nzc(r, self.regs.cf());
            }
            0xF => {
                // MVN
                let r = !b;
                self.regs.r[rdn] = r;
                self.regs.set_nzc(r, self.regs.cf());
            }
            _ => {
                return Err(EmulatorError::InvalidInsn {
                    addr: u64::from(pc),
                });
            }
        }
        Ok((2, Some(pc.wrapping_add(2))))
    }

    fn exec_special_dp(&mut self, insn: u16, pc: u32) -> Result<(u32, Option<u32>), EmulatorError> {
        let op = (insn >> 8) & 0x3;
        let dn = (insn >> 7) & 1;
        let rm = ((insn >> 3) & 0xF) as usize;
        let rd_lo = (insn & 0x7) as usize;
        let rdn = rd_lo | ((dn as usize) << 3);
        match op {
            0x0 => {
                // ADD (register) T2 — high registers
                let result = self.regs.r[rdn].wrapping_add(self.regs.r[rm]);
                if rdn == 15 {
                    let target = result & !1;
                    return Ok((2, Some(target)));
                }
                self.regs.r[rdn] = result;
            }
            0x1 => {
                // CMP (register) T2
                let (r, carry, overflow) =
                    Self::add_with_carry(self.regs.r[rdn], !self.regs.r[rm], 1);
                self.regs.set_nzcv(r, carry, overflow);
            }
            0x2 => {
                // MOV (register) T1 — high registers
                if rdn == 15 {
                    let target = self.regs.r[rm] & !1;
                    return Ok((2, Some(target)));
                }
                self.regs.r[rdn] = self.regs.r[rm];
            }
            0x3 => {
                // BX / BLX (register)
                let target_lo = (insn >> 7) & 1 != 0;
                let rm_val = self.regs.r[rm];
                if target_lo {
                    // BLX
                    self.regs.set_lr(pc.wrapping_add(2) | 1);
                }
                // If bit 0 clear → switch to ARM (we stay Thumb for simplicity)
                let target = rm_val & !1;
                return Ok((2, Some(target)));
            }
            _ => {
                return Err(EmulatorError::InvalidInsn {
                    addr: u64::from(pc),
                });
            }
        }
        Ok((2, Some(pc.wrapping_add(2))))
    }

    fn exec_ldr_str_imm(
        &mut self,
        insn: u16,
        pc: u32,
    ) -> Result<(u32, Option<u32>), EmulatorError> {
        // Encoding covers STR/LDR word/byte with imm5 offset
        let b12 = (insn >> 12) & 1;
        let load = (insn >> 11) & 1 != 0;
        let byte = b12 != 0;
        let imm5 = u32::from((insn >> 6) & 0x1F);
        let rn = ((insn >> 3) & 0x7) as usize;
        let rt = (insn & 0x7) as usize;
        let shift = if byte { 0 } else { 2 };
        let addr = self.regs.r[rn].wrapping_add(imm5 << shift);
        if load {
            if byte {
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 1, 0);
                self.regs.r[rt] = u32::from(self.mem_read_u8(addr)?);
            } else {
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 4, 0);
                self.regs.r[rt] = self.mem_read_u32(addr)?;
            }
        } else if byte {
            let val = (self.regs.r[rt] & 0xFF) as u8;
            self.fire_mem_hooks(&HookKind::MemWrite, u64::from(addr), 1, u64::from(val));
            self.mem_write_u8(addr, val)?;
        } else {
            let val = self.regs.r[rt];
            self.fire_mem_hooks(&HookKind::MemWrite, u64::from(addr), 4, u64::from(val));
            self.mem_write_u32(addr, val)?;
        }
        Ok((2, Some(pc.wrapping_add(2))))
    }

    /// Load/store group `bits[15:13] == 0b100`.
    ///
    /// This group is EXACTLY four encodings:
    /// * `1000 0` STRH (immediate) T1  * `1000 1` LDRH (immediate) T1
    /// * `1001 0` STR  (immediate, SP) * `1001 1` LDR  (immediate, SP)
    ///
    /// The previous version demultiplexed on `(insn >> 9) & 0xF`, a bit field
    /// that does not identify these encodings at all, and dispatched to
    /// register-offset arms that never legitimately arrive here. The result was
    /// that `LDRH r0,[r1,#0]` executed as `STRB (register)` — a LOAD that WROTE
    /// to emulated memory — `STR r4,[sp,#0]` executed as a load, and
    /// `STR r0,[sp,#0]` was rejected as an invalid instruction.
    ///
    /// The register-offset forms (`0101`) reach `exec_dp_or_ldr_lit` instead
    /// and are decoded there.
    fn exec_ldr_str_reg_sp(
        &mut self,
        insn: u16,
        pc: u32,
    ) -> Result<(u32, Option<u32>), EmulatorError> {
        let sp_relative = (insn >> 12) & 1 == 1;
        let is_load = (insn >> 11) & 1 == 1;

        if sp_relative {
            // STR/LDR (immediate, SP-relative) T2: rt = bits[10:8],
            // imm8 = bits[7:0] scaled by 4.
            let rt = ((insn >> 8) & 0x7) as usize;
            let imm8 = u32::from(insn & 0xFF);
            let addr = self.regs.sp().wrapping_add(imm8 << 2);
            if is_load {
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 4, 0);
                self.regs.r[rt] = self.mem_read_u32(addr)?;
            } else {
                let v = self.regs.r[rt];
                self.fire_mem_hooks(&HookKind::MemWrite, u64::from(addr), 4, u64::from(v));
                self.mem_write_u32(addr, v)?;
            }
        } else {
            // STRH/LDRH (immediate) T1: imm5 = bits[10:6] scaled by 2,
            // rn = bits[5:3], rt = bits[2:0].
            let imm5 = u32::from((insn >> 6) & 0x1F);
            let rn = ((insn >> 3) & 0x7) as usize;
            let rt = (insn & 0x7) as usize;
            let addr = self.regs.r[rn].wrapping_add(imm5 << 1);
            if is_load {
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 2, 0);
                self.regs.r[rt] = u32::from(self.mem_read_u16(addr)?);
            } else {
                let v = (self.regs.r[rt] & 0xFFFF) as u16;
                self.fire_mem_hooks(&HookKind::MemWrite, u64::from(addr), 2, u64::from(v));
                self.mem_write_u16(addr, v)?;
            }
        }
        Ok((2, Some(pc.wrapping_add(2))))
    }

    /// Load/store with a register offset, encoding `0101 opB rm rn rt`.
    ///
    /// `opB` (bits[11:9]) selects the operation; this code previously lived in
    /// `exec_ldr_str_reg_sp`, where these instructions never arrive, while the
    /// branch that does receive them returned `InvalidInsn` — so the whole
    /// group was effectively unimplemented.
    fn exec_ldr_str_reg_offset(
        &mut self,
        insn: u16,
        pc: u32,
    ) -> Result<(u32, Option<u32>), EmulatorError> {
        let op_b = (insn >> 9) & 0x7;
        let rm = ((insn >> 6) & 0x7) as usize;
        let rn = ((insn >> 3) & 0x7) as usize;
        let rt = (insn & 0x7) as usize;
        let addr = self.regs.r[rn].wrapping_add(self.regs.r[rm]);

        match op_b {
            0b000 => {
                // STR (register)
                let v = self.regs.r[rt];
                self.fire_mem_hooks(&HookKind::MemWrite, u64::from(addr), 4, u64::from(v));
                self.mem_write_u32(addr, v)?;
            }
            0b001 => {
                // STRH (register)
                let v = (self.regs.r[rt] & 0xFFFF) as u16;
                self.fire_mem_hooks(&HookKind::MemWrite, u64::from(addr), 2, u64::from(v));
                self.mem_write_u16(addr, v)?;
            }
            0b010 => {
                // STRB (register)
                let v = (self.regs.r[rt] & 0xFF) as u8;
                self.fire_mem_hooks(&HookKind::MemWrite, u64::from(addr), 1, u64::from(v));
                self.mem_write_u8(addr, v)?;
            }
            0b011 => {
                // LDRSB (register) — sign-extended byte.
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 1, 0);
                let b = self.mem_read_u8(addr)?;
                self.regs.r[rt] = i32::from(b as i8).cast_unsigned();
            }
            0b100 => {
                // LDR (register)
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 4, 0);
                self.regs.r[rt] = self.mem_read_u32(addr)?;
            }
            0b101 => {
                // LDRH (register) — zero-extended halfword.
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 2, 0);
                self.regs.r[rt] = u32::from(self.mem_read_u16(addr)?);
            }
            0b110 => {
                // LDRB (register) — zero-extended byte.
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 1, 0);
                self.regs.r[rt] = u32::from(self.mem_read_u8(addr)?);
            }
            _ => {
                // 0b111 — LDRSH (register), sign-extended halfword.
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 2, 0);
                let h = self.mem_read_u16(addr)?;
                self.regs.r[rt] = i32::from(h as i16).cast_unsigned();
            }
        }
        Ok((2, Some(pc.wrapping_add(2))))
    }

    fn exec_adr_sp_misc(
        &mut self,
        insn: u16,
        pc: u32,
    ) -> Result<(u32, Option<u32>), EmulatorError> {
        let op = (insn >> 11) & 3;
        match op {
            0 => {
                // ADD (SP or PC, immediate) — ADR T1
                let rd = ((insn >> 8) & 0x7) as usize;
                let imm8 = u32::from(insn & 0xFF);
                let base = (pc.wrapping_add(4)) & !3;
                self.regs.r[rd] = base.wrapping_add(imm8 << 2);
            }
            1 => {
                // ADD (SP plus immediate) T1
                let rd = ((insn >> 8) & 0x7) as usize;
                let imm8 = u32::from(insn & 0xFF);
                self.regs.r[rd] = self.regs.sp().wrapping_add(imm8 << 2);
            }
            2 | 3 => {
                // Miscellaneous 16-bit instructions
                let op2 = (insn >> 8) & 0xF;
                match op2 {
                    0x0 | 0x1 => {
                        // ADD/SUB SP immediate T2/T1
                        let sub = (insn >> 7) & 1 != 0;
                        let imm7 = u32::from(insn & 0x7F);
                        let sp = self.regs.sp();
                        self.regs.set_sp(if sub {
                            sp.wrapping_sub(imm7 << 2)
                        } else {
                            sp.wrapping_add(imm7 << 2)
                        });
                    }
                    0x4 | 0x5 => {
                        // PUSH T1
                        let reglist = (insn & 0xFF) as u8;
                        let push_lr = (insn >> 8) & 1 != 0;
                        if push_lr {
                            self.push_u32(self.regs.lr())?;
                        }
                        for i in (0u32..8).rev() {
                            if (reglist >> i) & 1 != 0 {
                                let v = self.regs.r[i as usize];
                                self.push_u32(v)?;
                            }
                        }
                    }
                    0xC | 0xD => {
                        // POP T1
                        let reglist = (insn & 0xFF) as u8;
                        let pop_pc = (insn >> 8) & 1 != 0;
                        for i in 0u32..8 {
                            if (reglist >> i) & 1 != 0 {
                                let v = self.pop_u32()?;
                                self.regs.r[i as usize] = v;
                            }
                        }
                        if pop_pc {
                            let target = self.pop_u32()? & !1;
                            return Ok((2, Some(target)));
                        }
                    }
                    0xE => {
                        // BKPT — treat as stop
                        return Ok((2, None));
                    }
                    _ => {}
                }
            }
            _ => unreachable!(),
        }
        Ok((2, Some(pc.wrapping_add(2))))
    }

    fn exec_ldm_stm_branch(
        &mut self,
        insn: u16,
        pc: u32,
    ) -> Result<(u32, Option<u32>), EmulatorError> {
        let op = (insn >> 11) & 3;
        match op {
            0 => {
                // STM T1
                let rn = ((insn >> 8) & 0x7) as usize;
                let reglist = (insn & 0xFF) as u8;
                let mut addr = self.regs.r[rn];
                for i in 0u32..8 {
                    if (reglist >> i) & 1 != 0 {
                        let v = self.regs.r[i as usize];
                        self.fire_mem_hooks(&HookKind::MemWrite, u64::from(addr), 4, u64::from(v));
                        self.mem_write_u32(addr, v)?;
                        addr = addr.wrapping_add(4);
                    }
                }
                self.regs.r[rn] = addr; // write-back
            }
            1 => {
                // LDM T1
                let rn = ((insn >> 8) & 0x7) as usize;
                let reglist = (insn & 0xFF) as u8;
                let mut addr = self.regs.r[rn];
                for i in 0u32..8 {
                    if (reglist >> i) & 1 != 0 {
                        self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 4, 0);
                        let v = self.mem_read_u32(addr)?;
                        self.regs.r[i as usize] = v;
                        addr = addr.wrapping_add(4);
                    }
                }
                if (reglist >> rn) & 1 == 0 {
                    self.regs.r[rn] = addr;
                } // write-back if not in list
            }
            2 => {
                // Conditional branch T1
                let cond = ((insn >> 8) & 0xF) as u8;
                if cond == 0xE {
                    return Err(EmulatorError::InvalidInsn {
                        addr: u64::from(pc),
                    });
                }
                if cond == 0xF {
                    // SVC
                    self.fire_mem_hooks(
                        &HookKind::Interrupt,
                        u64::from(pc),
                        2,
                        u64::from(insn & 0xFF),
                    );
                    return Ok((2, Some(pc.wrapping_add(2))));
                }
                let imm8 = ((insn & 0xFF) as u8).cast_signed();
                let offset = i32::from(imm8) << 1;
                if self.eval_cond(cond) {
                    let target = pc.wrapping_add(4).wrapping_add_signed(offset);
                    return Ok((2, Some(target)));
                }
            }
            3 => {
                // Unconditional branch T2
                let imm11 = i32::from(insn & 0x7FF);
                let signed_offset = (imm11 << 21) >> 20; // sign-extend * 2
                let target = pc.wrapping_add(4).wrapping_add_signed(signed_offset);
                return Ok((2, Some(target)));
            }
            _ => unreachable!(),
        }
        Ok((2, Some(pc.wrapping_add(2))))
    }

    fn exec_svc_branch(&self, insn: u16, pc: u32) -> Result<(u32, Option<u32>), EmulatorError> {
        // Bits 15:11 discriminate the encoding within the 0b111x group.
        let op11 = (insn >> 11) & 0x1F; // bits 15:11
        match op11 {
            0b11100 => {
                // B T2: unconditional branch, imm11 field
                let imm11 = i32::from(insn & 0x7FF);
                let signed_offset = (imm11 << 21) >> 20; // sign-extend then *2
                let target = pc.wrapping_add(4).wrapping_add_signed(signed_offset);
                Ok((2, Some(target)))
            }
            0b11110 | 0b11111 => {
                // 32-bit Thumb-2 instruction prefix (BL T1 etc.) — handled in step()
                Err(EmulatorError::InvalidInsn {
                    addr: u64::from(pc),
                })
            }
            0b11101 | 0b11001 | 0b11010 | 0b11011 => {
                // SVC / undefined — treat as BKPT-style stop
                let svc_imm = u64::from(insn & 0xFF);
                self.fire_mem_hooks(&HookKind::Interrupt, u64::from(pc), 2, svc_imm);
                Ok((2, Some(pc.wrapping_add(2))))
            }
            _ => {
                // Undefined; treat as NOP and advance
                Ok((2, Some(pc.wrapping_add(2))))
            }
        }
    }

    // ── 32-bit Thumb-2 decode ─────────────────────────────────────────────────

    /// Decode and execute one 32-bit Thumb-2 instruction.
    fn step_thumb32(
        &mut self,
        hi: u16,
        lo: u16,
        pc: u32,
    ) -> Result<(u32, Option<u32>), EmulatorError> {
        let op1 = (hi >> 11) & 3;
        let op2 = (hi >> 4) & 0x7F;
        match (op1, op2 >> 5) {
            (0b10, 0b000 | 0b001) => {
                // Data-processing (modified immediate) or plain
                self.exec_t32_dp(hi, lo, pc)
            }
            (0b10, _) => {
                // Branch / misc
                Ok(self.exec_t32_branch(hi, lo, pc))
            }
            (0b11, 0b000 | 0b001) => {
                // Load/store
                self.exec_t32_ldst(hi, lo, pc)
            }
            _ => Err(EmulatorError::InvalidInsn {
                addr: u64::from(pc),
            }),
        }
    }

    fn exec_t32_dp(
        &mut self,
        hi: u16,
        lo: u16,
        pc: u32,
    ) -> Result<(u32, Option<u32>), EmulatorError> {
        let op = (hi >> 5) & 0xF;
        let s = (hi >> 4) & 1 != 0;
        let rn = (hi & 0xF) as usize;
        let rd = ((lo >> 8) & 0xF) as usize;
        // Modified 12-bit immediate
        let imm12 =
            u32::from(lo & 0xFF) | u32::from((lo >> 8) & 7) << 8 | u32::from(hi & 0x400) << 1;
        let imm = Self::thumb_expand_imm(imm12);
        match op {
            0x0 => {
                let r = self.regs.r[rn] & imm;
                if rd == 15 {
                    self.regs.set_nzc(r, self.regs.cf());
                } else {
                    self.regs.r[rd] = r;
                    if s {
                        self.regs.set_nzc(r, self.regs.cf());
                    }
                }
            }
            0x4 => {
                let (r, c, v) = Self::add_with_carry(self.regs.r[rn], imm, 0);
                self.regs.r[rd] = r;
                if s {
                    self.regs.set_nzcv(r, c, v);
                }
            }
            0x8 => {
                let (r, c, v) = Self::add_with_carry(self.regs.r[rn], !imm, 1);
                if rd == 15 {
                    self.regs.set_nzcv(r, c, v);
                } else {
                    self.regs.r[rd] = r;
                    if s {
                        self.regs.set_nzcv(r, c, v);
                    }
                }
            }
            0xD => {
                let r = !imm;
                self.regs.r[rd] = r;
                if s {
                    self.regs.set_nzc(r, self.regs.cf());
                }
            }
            _ => {
                return Err(EmulatorError::InvalidInsn {
                    addr: u64::from(pc),
                });
            }
        }
        Ok((4, Some(pc.wrapping_add(4))))
    }

    fn exec_t32_branch(&mut self, hi: u16, lo: u16, pc: u32) -> (u32, Option<u32>) {
        // BL T1: unconditional long branch with link
        // Encoding: 11110 | S | imm10 / 11 | J1 | 1 | J2 | imm11
        let s = (hi >> 10) & 1 != 0;
        let imm10 = u32::from(hi & 0x3FF);
        let j1 = (lo >> 13) & 1 != 0;
        let j2 = (lo >> 11) & 1 != 0;
        let imm11 = u32::from(lo & 0x7FF);
        let i1 = !(j1 ^ s);
        let i2 = !(j2 ^ s);
        let offset = (u32::from(s) << 24)
            | (u32::from(i1) << 23)
            | (u32::from(i2) << 22)
            | (imm10 << 12)
            | (imm11 << 1);
        let signed_offset = if s {
            (offset | 0xFF00_0000).cast_signed()
        } else {
            offset.cast_signed()
        };
        let target = pc.wrapping_add(4).wrapping_add_signed(signed_offset);
        let bl = (lo >> 14) & 1 != 0; // BL vs B
        if bl {
            self.regs.set_lr(pc.wrapping_add(4) | 1);
        }
        (4, Some(target))
    }

    fn exec_t32_ldst(
        &mut self,
        hi: u16,
        lo: u16,
        pc: u32,
    ) -> Result<(u32, Option<u32>), EmulatorError> {
        let size = (hi >> 5) & 3;
        let load = (hi >> 4) & 1 != 0;
        let rn = (hi & 0xF) as usize;
        let rt = ((lo >> 12) & 0xF) as usize;
        let imm12 = u32::from(lo & 0xFFF);
        let addr = self.regs.r[rn].wrapping_add(imm12);
        match (load, size) {
            (true, 0b10) => {
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 4, 0);
                self.regs.r[rt] = self.mem_read_u32(addr)?;
            }
            (true, 0b01) => {
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 2, 0);
                self.regs.r[rt] = u32::from(self.mem_read_u16(addr)?);
            }
            (true, 0b00) => {
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 1, 0);
                self.regs.r[rt] = u32::from(self.mem_read_u8(addr)?);
            }
            (false, 0b10) => {
                let v = self.regs.r[rt];
                self.fire_mem_hooks(&HookKind::MemWrite, u64::from(addr), 4, u64::from(v));
                self.mem_write_u32(addr, v)?;
            }
            (false, 0b01) => {
                let v = (self.regs.r[rt] & 0xFFFF) as u16;
                self.fire_mem_hooks(&HookKind::MemWrite, u64::from(addr), 2, u64::from(v));
                self.mem_write_u16(addr, v)?;
            }
            (false, 0b00) => {
                let v = (self.regs.r[rt] & 0xFF) as u8;
                self.fire_mem_hooks(&HookKind::MemWrite, u64::from(addr), 1, u64::from(v));
                self.mem_write_u8(addr, v)?;
            }
            _ => {
                return Err(EmulatorError::InvalidInsn {
                    addr: u64::from(pc),
                });
            }
        }
        Ok((4, Some(pc.wrapping_add(4))))
    }

    /// Expand a 12-bit modified immediate constant (ARMv7-M thumb-expand-imm).
    const fn thumb_expand_imm(imm12: u32) -> u32 {
        let top2 = imm12 >> 10;
        if top2 == 0b00 {
            let sub = (imm12 >> 8) & 3;
            let imm8 = imm12 & 0xFF;
            match sub {
                0 => imm8,
                1 => (imm8 << 16) | imm8,
                2 => (imm8 << 24) | (imm8 << 8),
                3 => (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8,
                _ => 0,
            }
        } else {
            let rot = imm12 >> 7;
            let base = 0x80 | (imm12 & 0x7F);
            base.rotate_right(rot)
        }
    }

    // ── Main step ─────────────────────────────────────────────────────────────

    fn step(&mut self, until: u32) -> Result<Option<u32>, EmulatorError> {
        if self.stop_requested {
            return Ok(None);
        }
        let pc = self.regs.pc();
        if pc == until {
            return Ok(None);
        }

        // Fetch 2 bytes
        let bytes = arm_mem_read(&self.memory, &self.regions, u64::from(pc), 2).map_err(|_| {
            EmulatorError::MemFault {
                addr: u64::from(pc),
                op: "fetch".into(),
            }
        })?;
        let hw0 = u16::from_le_bytes([bytes[0], bytes[1]]);

        // Is this a 32-bit Thumb-2 instruction?
        let is_32bit = (hw0 >> 11) >= 0b11101;
        let (consumed, new_pc) =
            if is_32bit {
                let bytes2 = arm_mem_read(&self.memory, &self.regions, u64::from(pc + 2), 2)
                    .map_err(|_| EmulatorError::MemFault {
                        addr: u64::from(pc + 2),
                        op: "fetch".into(),
                    })?;
                let hw1 = u16::from_le_bytes([bytes2[0], bytes2[1]]);
                self.step_thumb32(hw0, hw1, pc)?
            } else {
                self.step_thumb16(hw0, pc)?
            };
        self.fire_code_hooks(u64::from(pc), consumed);
        self.regs.set_pc(new_pc.unwrap_or(pc));
        Ok(new_pc)
    }
}

impl Default for ArmThumbInterpreter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Emulator trait impl ───────────────────────────────────────────────────────

impl crate::Emulator for ArmThumbInterpreter {
    fn arch(&self) -> EmulatorArch {
        EmulatorArch::ArmThumb
    }

    fn map_memory(&mut self, addr: u64, size: usize, perms: MemPerms) -> Result<(), EmulatorError> {
        if size == 0 {
            return Err(EmulatorError::InvalidArg("size must be > 0".into()));
        }
        for r in &self.regions {
            let r_end = r.start.saturating_add(r.size as u64);
            let end = addr.saturating_add(size as u64);
            if addr < r_end && end > r.start {
                return Err(EmulatorError::InvalidArg(format!("overlap at 0x{addr:x}")));
            }
        }
        self.regions.push(MemRegion::new(addr, size, perms));
        self.memory.insert(addr, vec![0u8; size]);
        Ok(())
    }

    fn unmap_memory(&mut self, addr: u64) -> Result<(), EmulatorError> {
        let pos = self
            .regions
            .iter()
            .position(|r| r.start == addr)
            .ok_or_else(|| EmulatorError::InvalidArg(format!("no region at 0x{addr:x}")))?;
        self.regions.remove(pos);
        self.memory.remove(&addr);
        Ok(())
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), EmulatorError> {
        self.fire_mem_hooks(&HookKind::MemWrite, addr, data.len(), 0);
        arm_mem_write(&mut self.memory, &self.regions, addr, data)
    }

    fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>, EmulatorError> {
        self.fire_mem_hooks(&HookKind::MemRead, addr, len, 0);
        arm_mem_read(&self.memory, &self.regions, addr, len)
    }

    fn read_register(&self, reg: u32) -> Result<u64, EmulatorError> {
        match reg {
            0..=15 => Ok(u64::from(self.regs.r[reg as usize])),
            16 => Ok(u64::from(self.regs.cpsr)),
            _ => Err(EmulatorError::InvalidArg(format!("unknown ARM reg {reg}"))),
        }
    }

    fn write_register(&mut self, reg: u32, value: u64) -> Result<(), EmulatorError> {
        match reg {
            0..=15 => {
                self.regs.r[reg as usize] = (value & 0xFFFF_FFFF) as u32;
                Ok(())
            }
            16 => {
                self.regs.cpsr = (value & 0xFFFF_FFFF) as u32;
                Ok(())
            }
            _ => Err(EmulatorError::InvalidArg(format!("unknown ARM reg {reg}"))),
        }
    }

    fn start(
        &mut self,
        begin: u64,
        until: u64,
        timeout_ms: u64,
        count: u64,
    ) -> Result<(), EmulatorError> {
        self.stop_requested = false;
        self.regs.set_pc((begin & 0xFFFF_FFFF) as u32);
        let deadline = if timeout_ms > 0 {
            Some(std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms))
        } else {
            None
        };
        let until32 = (until & 0xFFFF_FFFF) as u32;
        let mut steps: u64 = 0;
        loop {
            if self.stop_requested {
                break;
            }
            if let Some(dl) = deadline
                && std::time::Instant::now() >= dl
            {
                return Err(EmulatorError::Timeout);
            }
            if count > 0 && steps >= count {
                break;
            }
            match self.step(until32)? {
                None => break,
                Some(new_pc) if new_pc == until32 => break,
                _ => {}
            }
            steps += 1;
        }
        Ok(())
    }

    fn stop(&mut self) -> Result<(), EmulatorError> {
        self.stop_requested = true;
        Ok(())
    }

    fn add_code_hook(
        &mut self,
        begin: u64,
        end: u64,
        callback: Box<dyn Fn(u64, u32) + Send + Sync>,
    ) -> Result<HookHandle, EmulatorError> {
        let h = self.next_handle();
        self.code_hooks.push((h, (begin, end, callback)));
        Ok(h)
    }

    fn add_mem_hook(
        &mut self,
        kind: HookKind,
        callback: Box<dyn Fn(u64, usize, u64) + Send + Sync>,
    ) -> Result<HookHandle, EmulatorError> {
        let h = self.next_handle();
        self.mem_hooks.push((h, (kind, callback)));
        Ok(h)
    }

    fn remove_hook(&mut self, handle: HookHandle) -> Result<(), EmulatorError> {
        let before = self.code_hooks.len() + self.mem_hooks.len();
        self.code_hooks.retain(|(h, _)| *h != handle);
        self.mem_hooks.retain(|(h, _)| *h != handle);
        let after = self.code_hooks.len() + self.mem_hooks.len();
        if before == after {
            Err(EmulatorError::HookError(format!(
                "hook {handle:?} not found"
            )))
        } else {
            Ok(())
        }
    }

    fn context_save(&self) -> Result<Vec<u8>, EmulatorError> {
        serde_json::to_vec(&self.regs)
            .map_err(|e| EmulatorError::HookError(format!("serialize: {e}")))
    }

    fn context_restore(&mut self, ctx: &[u8]) -> Result<(), EmulatorError> {
        let regs: ArmRegFile = serde_json::from_slice(ctx)
            .map_err(|e| EmulatorError::HookError(format!("deserialize: {e}")))?;
        self.regs = regs;
        Ok(())
    }

    fn regions(&self) -> Vec<MemRegion> {
        self.regions.clone()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Emulator, MemPerms};

    fn make() -> ArmThumbInterpreter {
        ArmThumbInterpreter::new()
    }

    fn setup(emu: &mut ArmThumbInterpreter, base: u32, code: &[u8]) {
        let size = code.len().max(0x1000);
        emu.map_memory(u64::from(base), size, MemPerms::ALL)
            .unwrap();
        emu.write_memory(u64::from(base), code).unwrap();
        emu.regs.set_pc(base);
    }

    // ── MOV imm ───────────────────────────────────────────────────────────────

    #[test]
    fn test_mov_imm() {
        let mut e = make();
        // MOV R0, #42 (T1: 0x2A00)
        // BKPT (0xBE00 = stop)
        setup(&mut e, 0x1000, &[0x2A, 0x20, 0x00, 0xBE]);
        e.start(0x1000, 0x2000, 0, 100).unwrap();
        assert_eq!(e.regs.r[0], 42);
    }

    // ── ADD imm ───────────────────────────────────────────────────────────────

    #[test]
    fn test_add_imm() {
        let mut e = make();
        // MOV R0, #10   (0x0A20)
        // ADD R0, R0, #5 (T2: 0x05 30 = ADD R0, #5)
        // BKPT
        setup(&mut e, 0x1000, &[0x0A, 0x20, 0x05, 0x30, 0x00, 0xBE]);
        e.start(0x1000, 0x2000, 0, 100).unwrap();
        assert_eq!(e.regs.r[0], 15);
    }

    // ── SUB imm ───────────────────────────────────────────────────────────────

    #[test]
    fn test_sub_imm() {
        let mut e = make();
        // MOV R0, #20 / SUB R0, R0, #7 / BKPT
        setup(&mut e, 0x1000, &[0x14, 0x20, 0x07, 0x38, 0x00, 0xBE]);
        e.start(0x1000, 0x2000, 0, 100).unwrap();
        assert_eq!(e.regs.r[0], 13);
    }

    // ── CMP / conditional branch ──────────────────────────────────────────────

    #[test]
    fn test_cmp_beq_taken() {
        let mut e = make();
        // MOV R0, #5 | CMP R0, #5 | BEQ +2 | MOV R0, #0xFF | BKPT
        // MOV R0,#5:  2005
        // CMP R0,#5:  2D05
        // BEQ +2:     02D0  (branch offset=2 → skips next insn)
        // MOV R0,#FF: FF20
        // BKPT:       00BE
        let code: &[u8] = &[0x05, 0x20, 0x05, 0x28, 0x02, 0xD0, 0xFF, 0x20, 0x00, 0xBE];
        setup(&mut e, 0x1000, code);
        e.start(0x1000, 0x2000, 0, 100).unwrap();
        // BEQ taken → R0 stays 5
        assert_eq!(e.regs.r[0], 5);
    }

    // ── AND / ORR / EOR ───────────────────────────────────────────────────────

    #[test]
    fn test_and_orr_eor() {
        let mut e = make();
        // MOV R0,#0xF0 / MOV R1,#0x0F / AND R0,R1 / BKPT
        // 0xF0, 0x20 = MOV R0,#0xF0
        // 0x0F, 0x21 = MOV R1,#0x0F
        // AND R0,R1 = 0b0100_0000_1000_1000 = 0x4008? Let's use direct encoding:
        // Thumb16 DP: 0100 00 0000 001 000 = AND Rd=R0,Rm=R1 → 0x4008
        let code: &[u8] = &[0xF0, 0x20, 0x0F, 0x21, 0x08, 0x40, 0x00, 0xBE];
        setup(&mut e, 0x1000, code);
        e.start(0x1000, 0x2000, 0, 100).unwrap();
        assert_eq!(e.regs.r[0], 0);
    }

    // ── PUSH / POP ────────────────────────────────────────────────────────────

    #[test]
    fn test_push_pop() {
        let mut e = make();
        // Stack at 0x4000 (separate from code region 0x1000..0x2000)
        e.map_memory(0x3000, 0x2000, MemPerms::READ | MemPerms::WRITE)
            .unwrap();
        e.regs.set_sp(0x4000);
        // MOV R0,#0x42 / PUSH {R0} / MOV R0,#0 / POP {R0} / BKPT
        // PUSH {R0} = 0b1011_0100_0000_0001 = 0xB401
        // POP {R0}  = 0b1011_1100_0000_0001 = 0xBC01
        let code: &[u8] = &[0x42, 0x20, 0x01, 0xB4, 0x00, 0x20, 0x01, 0xBC, 0x00, 0xBE];
        setup(&mut e, 0x1000, code);
        e.start(0x1000, 0x2000, 0, 100).unwrap();
        assert_eq!(e.regs.r[0], 0x42);
    }

    // ── LDR / STR ─────────────────────────────────────────────────────────────

    #[test]
    fn test_ldr_str_word() {
        let mut e = make();
        e.map_memory(0x5000, 0x1000, MemPerms::READ | MemPerms::WRITE)
            .unwrap();
        e.regs.r[1] = 0x5000;
        e.regs.r[0] = 0xDEAD_BEEF;
        // STR R0,[R1,#0]: 0110 0 00000 001 000 = 0b0110_0000_0000_1000 = 0x6008
        // LDR R2,[R1,#0]: 0110 1 00000 001 010 = 0b0110_1000_0000_1010 = 0x680A
        let code: &[u8] = &[0x08, 0x60, 0x0A, 0x68, 0x00, 0xBE];
        setup(&mut e, 0x1000, code);
        e.start(0x1000, 0x2000, 0, 100).unwrap();
        assert_eq!(e.regs.r[2], 0xDEAD_BEEF);
    }

    // ── Context save/restore ──────────────────────────────────────────────────

    #[test]
    fn test_ctx_save_restore() {
        let mut e = make();
        e.regs.r[0] = 0xCAFE;
        let ctx = e.context_save().unwrap();
        e.regs.r[0] = 0;
        e.context_restore(&ctx).unwrap();
        assert_eq!(e.regs.r[0], 0xCAFE);
    }

    // ── CPSR flags ────────────────────────────────────────────────────────────

    #[test]
    fn test_cmp_flags_zero() {
        let mut e = make();
        // MOV R0,#7 / CMP R0,#7 → ZF should be set
        setup(&mut e, 0x1000, &[0x07, 0x20, 0x07, 0x28, 0x00, 0xBE]);
        e.start(0x1000, 0x2000, 0, 100).unwrap();
        assert!(e.regs.zf(), "ZF should be set after CMP R0,#7 with R0=7");
    }

    // ── Unconditional branch ──────────────────────────────────────────────────

    #[test]
    fn test_unconditional_branch() {
        let mut e = make();
        // B +4 = skip 2 bytes (the MOV R0,#0xFF below) then BKPT
        // B.n to label: offset = +2 from end of insn, so imm11 encodes +2
        // Thumb B T2: 1110 0 00000000010 = 0xE002 → branch to pc+4+4=pc+8
        let code: &[u8] = &[0x02, 0xE0, 0xFF, 0x20, 0x00, 0xBE];
        setup(&mut e, 0x1000, code);
        e.start(0x1000, 0x2000, 0, 100).unwrap();
        // MOV R0,#0xFF skipped; R0 remains 0
        assert_eq!(e.regs.r[0], 0);
    }

    // ── LSL ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_lsl_imm() {
        let mut e = make();
        // MOV R1,#1 / LSL R0,R1,#4 / BKPT
        // LSL Rd=R0, Rm=R1, imm5=4: 0000 0 00100 001 000 = 0x0108
        let code: &[u8] = &[0x01, 0x21, 0x08, 0x01, 0x00, 0xBE];
        setup(&mut e, 0x1000, code);
        e.start(0x1000, 0x2000, 0, 100).unwrap();
        assert_eq!(e.regs.r[0], 16);
    }

    // ── MUL ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_mul() {
        let mut e = make();
        // MOV R0,#6 / MOV R1,#7 / MUL R0,R1,R0 (actually MUL R0,R1 in T1)
        // MUL T1: 0100 0011 01 Rm Rdm → Rm=R1, Rdm=R0
        // 0100 0011 01 001 000 = 0x4348
        let code: &[u8] = &[0x06, 0x20, 0x07, 0x21, 0x48, 0x43, 0x00, 0xBE];
        setup(&mut e, 0x1000, code);
        e.start(0x1000, 0x2000, 0, 100).unwrap();
        assert_eq!(e.regs.r[0], 42);
    }
}
