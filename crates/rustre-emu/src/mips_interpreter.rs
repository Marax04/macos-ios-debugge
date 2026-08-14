//! Pure-Rust MIPS32 interpreter implementing the [`Emulator`] trait.
//!
//! Covers the most common MIPS32 instructions:
//!
//! * R-type: ADD/ADDU/SUB/SUBU/AND/OR/XOR/NOR/SLT/SLTU/SLL/SRL/SRA/SLLV/SRLV/SRAV/
//!   MULT/MULTU/DIV/DIVU/MFHI/MFLO/MTHI/MTLO/JR/JALR
//! * I-type: ADDI/ADDIU/ANDI/ORI/XORI/SLTI/SLTIU/LUI/LW/SW/LB/LBU/LH/LHU/SB/SH/
//!   BEQ/BNE/BGTZ/BLEZ/BLTZ/BGEZ/BLTZAL/BGEZAL
//! * J-type: J/JAL
//!
//! Delay-slot semantics are emulated: after every branch/jump the instruction
//! immediately following is always executed before the branch takes effect.
//!
//! Syscalls (`syscall` opcode) fire an interrupt hook so the OS emulation layer
//! can intercept them.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{EmulatorArch, EmulatorError, HookHandle, HookKind, MemPerms, MemRegion};

// ── memory helpers ────────────────────────────────────────────────────────────

fn mips_mem_read(
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

fn mips_mem_write(
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

// ── MIPS register file ────────────────────────────────────────────────────────

/// MIPS32 CPU state: 32 general-purpose registers + PC + HI/LO.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MipsRegFile {
    /// R0–R31. R0 is always zero.
    pub r: [u32; 32],
    /// Program counter.
    pub pc: u32,
    /// HI register (result of MULT/DIV).
    pub hi: u32,
    /// LO register (result of MULT/DIV).
    pub lo: u32,
}

impl MipsRegFile {
    /// Write a register, enforcing that R0 always stays zero.
    #[inline]
    pub const fn write(&mut self, reg: usize, val: u32) {
        if reg != 0 {
            self.r[reg] = val;
        }
    }
    /// Read a register.
    #[inline]
    #[must_use]
    pub const fn read(&self, reg: usize) -> u32 {
        self.r[reg]
    }
}

// ── Hook types ────────────────────────────────────────────────────────────────

type MipsCodeHook = (u64, u64, Box<dyn Fn(u64, u32) + Send + Sync>);
type MipsMemHook = (HookKind, Box<dyn Fn(u64, usize, u64) + Send + Sync>);

// ── Branch target ─────────────────────────────────────────────────────────────

/// Result of decoding a single MIPS instruction.
#[derive(Debug)]
enum StepResult {
    /// Normal sequential execution (no branch).
    Next,
    /// Branch/jump: target pc for after the delay slot.
    Branch(u32),
    /// Halt (break/stop).
    Halt,
}

// ── Mips32Interpreter ─────────────────────────────────────────────────────────

/// Pure-Rust MIPS32 big-endian interpreter.
pub struct Mips32Interpreter {
    pub regs: MipsRegFile,
    memory: BTreeMap<u64, Vec<u8>>,
    regions: Vec<MemRegion>,
    hook_counter: u64,
    code_hooks: Vec<(HookHandle, MipsCodeHook)>,
    mem_hooks: Vec<(HookHandle, MipsMemHook)>,
    stop_requested: bool,
    /// Whether the target is little-endian (`MIPS32El`).
    pub little_endian: bool,
}

impl Mips32Interpreter {
    /// Create a big-endian MIPS32 interpreter.
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_endian(false)
    }

    /// Create an interpreter with explicit endianness selection.
    #[must_use]
    pub fn new_with_endian(little_endian: bool) -> Self {
        Self {
            regs: MipsRegFile::default(),
            memory: BTreeMap::new(),
            regions: Vec::new(),
            hook_counter: 0,
            code_hooks: Vec::new(),
            mem_hooks: Vec::new(),
            stop_requested: false,
            little_endian,
        }
    }

    const fn next_handle(&mut self) -> HookHandle {
        self.hook_counter += 1;
        HookHandle(self.hook_counter)
    }

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

    // ── endian-aware fetch ────────────────────────────────────────────────────

    fn fetch_insn(&self, pc: u32) -> Result<u32, EmulatorError> {
        let bytes = mips_mem_read(&self.memory, &self.regions, u64::from(pc), 4).map_err(|_| {
            EmulatorError::MemFault {
                addr: u64::from(pc),
                op: "fetch".into(),
            }
        })?;
        Ok(if self.little_endian {
            u32::from_le_bytes(bytes.try_into().unwrap_or([0u8; 4]))
        } else {
            u32::from_be_bytes(bytes.try_into().unwrap_or([0u8; 4]))
        })
    }

    // ── memory helpers ────────────────────────────────────────────────────────

    fn load_u32(&self, addr: u32) -> Result<u32, EmulatorError> {
        let bytes = mips_mem_read(&self.memory, &self.regions, u64::from(addr), 4)?;
        Ok(if self.little_endian {
            u32::from_le_bytes(bytes.try_into().unwrap_or([0u8; 4]))
        } else {
            u32::from_be_bytes(bytes.try_into().unwrap_or([0u8; 4]))
        })
    }

    fn store_u32(&mut self, addr: u32, val: u32) -> Result<(), EmulatorError> {
        let bytes = if self.little_endian {
            val.to_le_bytes()
        } else {
            val.to_be_bytes()
        };
        mips_mem_write(&mut self.memory, &self.regions, u64::from(addr), &bytes)
    }

    fn load_u16(&self, addr: u32) -> Result<u16, EmulatorError> {
        let bytes = mips_mem_read(&self.memory, &self.regions, u64::from(addr), 2)?;
        Ok(if self.little_endian {
            u16::from_le_bytes(bytes.try_into().unwrap_or([0u8; 2]))
        } else {
            u16::from_be_bytes(bytes.try_into().unwrap_or([0u8; 2]))
        })
    }

    fn store_u16(&mut self, addr: u32, val: u16) -> Result<(), EmulatorError> {
        let bytes = if self.little_endian {
            val.to_le_bytes()
        } else {
            val.to_be_bytes()
        };
        mips_mem_write(&mut self.memory, &self.regions, u64::from(addr), &bytes)
    }

    fn load_u8(&self, addr: u32) -> Result<u8, EmulatorError> {
        let bytes = mips_mem_read(&self.memory, &self.regions, u64::from(addr), 1)?;
        Ok(bytes[0])
    }

    fn store_u8(&mut self, addr: u32, val: u8) -> Result<(), EmulatorError> {
        mips_mem_write(&mut self.memory, &self.regions, u64::from(addr), &[val])
    }

    // ── sign-extend helpers ───────────────────────────────────────────────────

    #[inline]
    fn sext16(v: u16) -> u32 {
        i32::from(v.cast_signed()).cast_unsigned()
    }

    // ── R-type decode ─────────────────────────────────────────────────────────

    const fn exec_rtype_shift(
        &mut self,
        rs: usize,
        rt: usize,
        rd: usize,
        shamt: u32,
        funct: u32,
    ) -> bool {
        match funct {
            0x00 => {
                self.regs.write(rd, self.regs.read(rt) << shamt);
                true
            }
            0x02 => {
                self.regs.write(rd, self.regs.read(rt) >> shamt);
                true
            }
            0x03 => {
                self.regs.write(
                    rd,
                    (self.regs.read(rt).cast_signed() >> shamt).cast_unsigned(),
                );
                true
            }
            0x04 => {
                self.regs
                    .write(rd, self.regs.read(rt) << (self.regs.read(rs) & 31));
                true
            }
            0x06 => {
                self.regs
                    .write(rd, self.regs.read(rt) >> (self.regs.read(rs) & 31));
                true
            }
            0x07 => {
                self.regs.write(
                    rd,
                    (self.regs.read(rt).cast_signed() >> (self.regs.read(rs) & 31)).cast_unsigned(),
                );
                true
            }
            _ => false,
        }
    }

    fn exec_rtype_muldiv(&mut self, rs: usize, rt: usize, rd: usize, funct: u32) -> bool {
        match funct {
            0x10 => {
                self.regs.write(rd, self.regs.hi);
                true
            }
            0x11 => {
                self.regs.hi = self.regs.read(rs);
                true
            }
            0x12 => {
                self.regs.write(rd, self.regs.lo);
                true
            }
            0x13 => {
                self.regs.lo = self.regs.read(rs);
                true
            }
            0x18 => {
                let a = i64::from(self.regs.read(rs).cast_signed());
                let b = i64::from(self.regs.read(rt).cast_signed());
                let r = a.wrapping_mul(b).cast_unsigned();
                self.regs.hi = ((r >> 32) & 0xFFFF_FFFF) as u32;
                self.regs.lo = (r & 0xFFFF_FFFF) as u32;
                true
            }
            0x19 => {
                let a = u64::from(self.regs.read(rs));
                let b = u64::from(self.regs.read(rt));
                let r = a.wrapping_mul(b);
                self.regs.hi = ((r >> 32) & 0xFFFF_FFFF) as u32;
                self.regs.lo = (r & 0xFFFF_FFFF) as u32;
                true
            }
            0x1A => {
                let a = self.regs.read(rs).cast_signed();
                let b = self.regs.read(rt).cast_signed();
                if b != 0 {
                    self.regs.lo = a.wrapping_div(b).cast_unsigned();
                    self.regs.hi = a.wrapping_rem(b).cast_unsigned();
                }
                true
            }
            0x1B => {
                let a = self.regs.read(rs);
                let b = self.regs.read(rt);
                if b != 0 {
                    self.regs.lo = a / b;
                    self.regs.hi = a % b;
                }
                true
            }
            _ => false,
        }
    }

    fn exec_rtype_alu(&mut self, rs: usize, rt: usize, rd: usize, funct: u32) -> bool {
        match funct {
            0x20 | 0x21 => {
                self.regs
                    .write(rd, self.regs.read(rs).wrapping_add(self.regs.read(rt)));
                true
            }
            0x22 | 0x23 => {
                self.regs
                    .write(rd, self.regs.read(rs).wrapping_sub(self.regs.read(rt)));
                true
            }
            0x24 => {
                self.regs.write(rd, self.regs.read(rs) & self.regs.read(rt));
                true
            }
            0x25 => {
                self.regs.write(rd, self.regs.read(rs) | self.regs.read(rt));
                true
            }
            0x26 => {
                self.regs.write(rd, self.regs.read(rs) ^ self.regs.read(rt));
                true
            }
            0x27 => {
                self.regs
                    .write(rd, !(self.regs.read(rs) | self.regs.read(rt)));
                true
            }
            0x2A => {
                let a = self.regs.read(rs).cast_signed();
                let b = self.regs.read(rt).cast_signed();
                self.regs.write(rd, u32::from(a < b));
                true
            }
            0x2B => {
                self.regs
                    .write(rd, u32::from(self.regs.read(rs) < self.regs.read(rt)));
                true
            }
            _ => false,
        }
    }

    fn exec_rtype(&mut self, insn: u32, pc: u32) -> Result<StepResult, EmulatorError> {
        let rs = ((insn >> 21) & 0x1F) as usize;
        let rt = ((insn >> 16) & 0x1F) as usize;
        let rd = ((insn >> 11) & 0x1F) as usize;
        let shamt = (insn >> 6) & 0x1F;
        let funct = insn & 0x3F;
        // Special control-flow / system functs first
        match funct {
            0x08 => {
                // JR
                let target = self.regs.read(rs);
                return Ok(StepResult::Branch(target));
            }
            0x09 => {
                // JALR
                let target = self.regs.read(rs);
                self.regs.write(rd, pc.wrapping_add(8));
                return Ok(StepResult::Branch(target));
            }
            0x0C => {
                // SYSCALL
                let code = (insn >> 6) & 0xFFFFF;
                self.fire_mem_hooks(&HookKind::Interrupt, u64::from(pc), 4, u64::from(code));
                return Ok(StepResult::Next);
            }
            0x0D => return Ok(StepResult::Halt), // BREAK
            _ => {}
        }
        if self.exec_rtype_shift(rs, rt, rd, shamt, funct)
            || self.exec_rtype_muldiv(rs, rt, rd, funct)
            || self.exec_rtype_alu(rs, rt, rd, funct)
        {
            Ok(StepResult::Next)
        } else {
            Err(EmulatorError::InvalidInsn {
                addr: u64::from(pc),
            })
        }
    }

    // ── REGIMM (opcode 1) decode ──────────────────────────────────────────────

    fn exec_regimm(&mut self, insn: u32, pc: u32) -> Result<StepResult, EmulatorError> {
        let rs = ((insn >> 21) & 0x1F) as usize;
        let rt = ((insn >> 16) & 0x1F) as u8;
        let imm16 = (insn & 0xFFFF) as u16;
        let offset = (Self::sext16(imm16) << 2).cast_signed();
        let target = pc.wrapping_add(4).wrapping_add_signed(offset);
        match rt {
            0x00 => {
                // BLTZ
                if self.regs.read(rs).cast_signed() < 0 {
                    return Ok(StepResult::Branch(target));
                }
            }
            0x01 => {
                // BGEZ
                if self.regs.read(rs).cast_signed() >= 0 {
                    return Ok(StepResult::Branch(target));
                }
            }
            0x10 => {
                // BLTZAL
                self.regs.write(31, pc.wrapping_add(8));
                if self.regs.read(rs).cast_signed() < 0 {
                    return Ok(StepResult::Branch(target));
                }
            }
            0x11 => {
                // BGEZAL
                self.regs.write(31, pc.wrapping_add(8));
                if self.regs.read(rs).cast_signed() >= 0 {
                    return Ok(StepResult::Branch(target));
                }
            }
            _ => {
                return Err(EmulatorError::InvalidInsn {
                    addr: u64::from(pc),
                });
            }
        }
        Ok(StepResult::Next)
    }

    // ── Main decode ───────────────────────────────────────────────────────────

    /// Execute one MIPS instruction (at `pc`) and return the branch target
    /// for the delay slot handler.
    fn exec_branch(
        &self,
        opcode: u32,
        rs: usize,
        rt: usize,
        imm16: u16,
        pc: u32,
    ) -> Option<StepResult> {
        let offset = (Self::sext16(imm16) << 2).cast_signed();
        let target = pc.wrapping_add(4).wrapping_add_signed(offset);
        let taken = match opcode {
            0x04 => self.regs.read(rs) == self.regs.read(rt),
            0x05 => self.regs.read(rs) != self.regs.read(rt),
            0x06 => self.regs.read(rs).cast_signed() <= 0,
            0x07 => self.regs.read(rs).cast_signed() > 0,
            _ => return None,
        };
        Some(if taken {
            StepResult::Branch(target)
        } else {
            StepResult::Next
        })
    }

    fn exec_itype_alu(&mut self, opcode: u32, rs: usize, rt: usize, imm16: u16) -> bool {
        match opcode {
            0x08 | 0x09 => self
                .regs
                .write(rt, self.regs.read(rs).wrapping_add(Self::sext16(imm16))),
            0x0A => {
                let r = self.regs.read(rs).cast_signed() < Self::sext16(imm16).cast_signed();
                self.regs.write(rt, u32::from(r));
            }
            0x0B => {
                let r = self.regs.read(rs) < Self::sext16(imm16);
                self.regs.write(rt, u32::from(r));
            }
            0x0C => self.regs.write(rt, self.regs.read(rs) & u32::from(imm16)),
            0x0D => self.regs.write(rt, self.regs.read(rs) | u32::from(imm16)),
            0x0E => self.regs.write(rt, self.regs.read(rs) ^ u32::from(imm16)),
            0x0F => self.regs.write(rt, u32::from(imm16) << 16),
            _ => return false,
        }
        true
    }

    fn exec_load(
        &mut self,
        opcode: u32,
        rs: usize,
        rt: usize,
        imm16: u16,
    ) -> Result<bool, EmulatorError> {
        let addr = self.regs.read(rs).wrapping_add(Self::sext16(imm16));
        match opcode {
            0x20 => {
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 1, 0);
                let v = self.load_u8(addr)?;
                self.regs
                    .write(rt, i32::from(v.cast_signed()).cast_unsigned());
            }
            0x21 => {
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 2, 0);
                let v = self.load_u16(addr)?;
                self.regs
                    .write(rt, i32::from(v.cast_signed()).cast_unsigned());
            }
            0x23 => {
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 4, 0);
                let v = self.load_u32(addr)?;
                self.regs.write(rt, v);
            }
            0x24 => {
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 1, 0);
                let v = self.load_u8(addr)?;
                self.regs.write(rt, u32::from(v));
            }
            0x25 => {
                self.fire_mem_hooks(&HookKind::MemRead, u64::from(addr), 2, 0);
                let v = self.load_u16(addr)?;
                self.regs.write(rt, u32::from(v));
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn exec_store(
        &mut self,
        opcode: u32,
        rs: usize,
        rt: usize,
        imm16: u16,
    ) -> Result<bool, EmulatorError> {
        let addr = self.regs.read(rs).wrapping_add(Self::sext16(imm16));
        match opcode {
            0x28 => {
                let v = (self.regs.read(rt) & 0xFF) as u8;
                self.fire_mem_hooks(&HookKind::MemWrite, u64::from(addr), 1, u64::from(v));
                self.store_u8(addr, v)?;
            }
            0x29 => {
                let v = (self.regs.read(rt) & 0xFFFF) as u16;
                self.fire_mem_hooks(&HookKind::MemWrite, u64::from(addr), 2, u64::from(v));
                self.store_u16(addr, v)?;
            }
            0x2B => {
                let v = self.regs.read(rt);
                self.fire_mem_hooks(&HookKind::MemWrite, u64::from(addr), 4, u64::from(v));
                self.store_u32(addr, v)?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn exec_one(&mut self, pc: u32) -> Result<StepResult, EmulatorError> {
        let insn = self.fetch_insn(pc)?;
        let opcode = insn >> 26;
        let rs = ((insn >> 21) & 0x1F) as usize;
        let rt = ((insn >> 16) & 0x1F) as usize;
        let imm16 = (insn & 0xFFFF) as u16;
        match opcode {
            0x00 => self.exec_rtype(insn, pc),
            0x01 => self.exec_regimm(insn, pc),
            0x02 => {
                let instr_index = (insn & 0x03FF_FFFF) << 2;
                let target = (pc.wrapping_add(4) & 0xF000_0000) | instr_index;
                Ok(StepResult::Branch(target))
            }
            0x03 => {
                let instr_index = (insn & 0x03FF_FFFF) << 2;
                let target = (pc.wrapping_add(4) & 0xF000_0000) | instr_index;
                self.regs.write(31, pc.wrapping_add(8));
                Ok(StepResult::Branch(target))
            }
            0x04..=0x07 => self.exec_branch(opcode, rs, rt, imm16, pc).ok_or_else(|| {
                EmulatorError::InvalidInsn {
                    addr: u64::from(pc),
                }
            }),
            0x08..=0x0F => {
                if self.exec_itype_alu(opcode, rs, rt, imm16) {
                    Ok(StepResult::Next)
                } else {
                    Err(EmulatorError::InvalidInsn {
                        addr: u64::from(pc),
                    })
                }
            }
            0x20..=0x25 => {
                if self.exec_load(opcode, rs, rt, imm16)? {
                    Ok(StepResult::Next)
                } else {
                    Err(EmulatorError::InvalidInsn {
                        addr: u64::from(pc),
                    })
                }
            }
            0x28..=0x2B => {
                if self.exec_store(opcode, rs, rt, imm16)? {
                    Ok(StepResult::Next)
                } else {
                    Err(EmulatorError::InvalidInsn {
                        addr: u64::from(pc),
                    })
                }
            }
            _ => Err(EmulatorError::InvalidInsn {
                addr: u64::from(pc),
            }),
        }
    }

    /// Execute one instruction at `pc` with proper delay-slot handling.
    /// Returns the next PC (or None on halt).
    fn step(&mut self, pc: u32, until: u32) -> Result<Option<u32>, EmulatorError> {
        if self.stop_requested || pc == until {
            return Ok(None);
        }
        let result = self.exec_one(pc)?;
        self.fire_code_hooks(u64::from(pc), 4);
        match result {
            StepResult::Halt => {
                self.regs.pc = pc;
                Ok(None)
            }
            StepResult::Next => {
                let next = pc.wrapping_add(4);
                self.regs.pc = next;
                Ok(Some(next))
            }
            StepResult::Branch(target) => {
                // Execute delay slot
                let ds_pc = pc.wrapping_add(4);
                let ds_insn = self.fetch_insn(ds_pc)?;
                let _ = ds_insn; // delay slot: just advance (simplified)
                let ds_result = self.exec_one(ds_pc);
                self.fire_code_hooks(u64::from(ds_pc), 4);
                // Ignore branch results from delay-slot instruction
                let _ = ds_result;
                self.regs.pc = target;
                Ok(Some(target))
            }
        }
    }
}

impl Default for Mips32Interpreter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Emulator trait impl ───────────────────────────────────────────────────────

impl crate::Emulator for Mips32Interpreter {
    fn arch(&self) -> EmulatorArch {
        if self.little_endian {
            EmulatorArch::Mips32El
        } else {
            EmulatorArch::Mips32
        }
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
        mips_mem_write(&mut self.memory, &self.regions, addr, data)
    }

    fn read_memory(&self, addr: u64, len: usize) -> Result<Vec<u8>, EmulatorError> {
        self.fire_mem_hooks(&HookKind::MemRead, addr, len, 0);
        mips_mem_read(&self.memory, &self.regions, addr, len)
    }

    fn read_register(&self, reg: u32) -> Result<u64, EmulatorError> {
        match reg {
            0..=31 => Ok(u64::from(self.regs.r[reg as usize])),
            32 => Ok(u64::from(self.regs.pc)),
            33 => Ok(u64::from(self.regs.hi)),
            34 => Ok(u64::from(self.regs.lo)),
            _ => Err(EmulatorError::InvalidArg(format!("unknown MIPS reg {reg}"))),
        }
    }

    fn write_register(&mut self, reg: u32, value: u64) -> Result<(), EmulatorError> {
        match reg {
            0..=31 => {
                self.regs.write(reg as usize, (value & 0xFFFF_FFFF) as u32);
                Ok(())
            }
            32 => {
                self.regs.pc = (value & 0xFFFF_FFFF) as u32;
                Ok(())
            }
            33 => {
                self.regs.hi = (value & 0xFFFF_FFFF) as u32;
                Ok(())
            }
            34 => {
                self.regs.lo = (value & 0xFFFF_FFFF) as u32;
                Ok(())
            }
            _ => Err(EmulatorError::InvalidArg(format!("unknown MIPS reg {reg}"))),
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
        self.regs.pc = (begin & 0xFFFF_FFFF) as u32;
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
            let pc = self.regs.pc;
            match self.step(pc, until32)? {
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
        let regs: MipsRegFile = serde_json::from_slice(ctx)
            .map_err(|e| EmulatorError::HookError(format!("deserialize: {e}")))?;
        self.regs = regs;
        Ok(())
    }

    fn regions(&self) -> Vec<MemRegion> {
        self.regions.clone()
    }
}

// ── Convenience constructor ───────────────────────────────────────────────────

/// Little-endian variant.
pub struct Mips32ElInterpreter(pub Mips32Interpreter);

impl Mips32ElInterpreter {
    #[must_use]
    pub fn new() -> Self {
        Self(Mips32Interpreter::new_with_endian(true))
    }
}

impl Default for Mips32ElInterpreter {
    fn default() -> Self {
        Self::new()
    }
}

// ── MIPS backend helper ───────────────────────────────────────────────────────

/// Encode a MIPS R-type instruction.
#[inline]
#[must_use]
pub const fn encode_rtype(opcode: u32, rs: u32, rt: u32, rd: u32, shamt: u32, funct: u32) -> u32 {
    (opcode << 26) | (rs << 21) | (rt << 16) | (rd << 11) | (shamt << 6) | funct
}

/// Encode a MIPS I-type instruction.
#[inline]
#[must_use]
pub fn encode_itype(opcode: u32, rs: u32, rt: u32, imm: u16) -> u32 {
    (opcode << 26) | (rs << 21) | (rt << 16) | u32::from(imm)
}

/// Encode a MIPS J-type instruction.
#[inline]
#[must_use]
pub const fn encode_jtype(opcode: u32, target: u32) -> u32 {
    (opcode << 26) | (target & 0x03FF_FFFF)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Emulator, MemPerms, mips_regs};

    // little-endian MIPS for tests (easier to construct opcodes)
    fn make() -> Mips32Interpreter {
        Mips32Interpreter::new_with_endian(true)
    }

    fn setup(emu: &mut Mips32Interpreter, base: u32, code: &[u8]) {
        emu.map_memory(u64::from(base), code.len().max(0x1000), MemPerms::ALL)
            .unwrap();
        emu.write_memory(u64::from(base), code).unwrap();
    }

    fn write_insn(emu: &mut Mips32Interpreter, addr: u32, insn: u32) {
        emu.write_memory(u64::from(addr), &insn.to_le_bytes())
            .unwrap();
    }

    // ── ADDIU ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_addiu() {
        let mut e = make();
        setup(&mut e, 0x1000, &[0u8; 0x100]);
        // ADDIU $v0, $zero, 42
        let insn = encode_itype(0x09, 0, mips_regs::V0, 42_u16);
        write_insn(&mut e, 0x1000, insn);
        // BREAK
        write_insn(&mut e, 0x1004, encode_rtype(0, 0, 0, 0, 0, 0x0D));
        e.start(0x1000, 0x9999, 0, 100).unwrap();
        assert_eq!(e.regs.read(mips_regs::V0 as usize), 42);
    }

    // ── LUI + ORI ─────────────────────────────────────────────────────────────

    #[test]
    fn test_lui_ori() {
        let mut e = make();
        setup(&mut e, 0x1000, &[0u8; 0x100]);
        // LUI $t0, 0xDEAD
        write_insn(&mut e, 0x1000, encode_itype(0x0F, 0, mips_regs::T0, 0xDEAD));
        // ORI $t0, $t0, 0xBEEF
        write_insn(
            &mut e,
            0x1004,
            encode_itype(0x0D, mips_regs::T0, mips_regs::T0, 0xBEEF),
        );
        // BREAK
        write_insn(&mut e, 0x1008, encode_rtype(0, 0, 0, 0, 0, 0x0D));
        e.start(0x1000, 0x9999, 0, 100).unwrap();
        assert_eq!(e.regs.read(mips_regs::T0 as usize), 0xDEAD_BEEF);
    }

    // ── ADD/SUB ───────────────────────────────────────────────────────────────

    #[test]
    fn test_add_sub() {
        let mut e = make();
        setup(&mut e, 0x1000, &[0u8; 0x100]);
        // ADDIU $t0, $zero, 10
        write_insn(&mut e, 0x1000, encode_itype(0x09, 0, mips_regs::T0, 10));
        // ADDIU $t1, $zero, 3
        write_insn(&mut e, 0x1004, encode_itype(0x09, 0, mips_regs::T1, 3));
        // ADDU $t2, $t0, $t1 (funct=0x21)
        write_insn(
            &mut e,
            0x1008,
            encode_rtype(0, mips_regs::T0, mips_regs::T1, mips_regs::T2, 0, 0x21),
        );
        // SUBU $t3, $t0, $t1 (funct=0x23)
        write_insn(
            &mut e,
            0x100C,
            encode_rtype(0, mips_regs::T0, mips_regs::T1, mips_regs::T3, 0, 0x23),
        );
        // BREAK
        write_insn(&mut e, 0x1010, encode_rtype(0, 0, 0, 0, 0, 0x0D));
        e.start(0x1000, 0x9999, 0, 100).unwrap();
        assert_eq!(e.regs.read(mips_regs::T2 as usize), 13);
        assert_eq!(e.regs.read(mips_regs::T3 as usize), 7);
    }

    // ── AND / OR / XOR / NOR ─────────────────────────────────────────────────

    #[test]
    fn test_logic_ops() {
        let mut e = make();
        setup(&mut e, 0x1000, &[0u8; 0x100]);
        write_insn(&mut e, 0x1000, encode_itype(0x09, 0, mips_regs::T0, 0xFF));
        write_insn(&mut e, 0x1004, encode_itype(0x09, 0, mips_regs::T1, 0x0F));
        // AND
        write_insn(
            &mut e,
            0x1008,
            encode_rtype(0, mips_regs::T0, mips_regs::T1, mips_regs::T2, 0, 0x24),
        );
        // OR
        write_insn(
            &mut e,
            0x100C,
            encode_rtype(0, mips_regs::T0, mips_regs::T1, mips_regs::T3, 0, 0x25),
        );
        // XOR
        write_insn(
            &mut e,
            0x1010,
            encode_rtype(0, mips_regs::T0, mips_regs::T1, mips_regs::T4, 0, 0x26),
        );
        // BREAK
        write_insn(&mut e, 0x1014, encode_rtype(0, 0, 0, 0, 0, 0x0D));
        e.start(0x1000, 0x9999, 0, 100).unwrap();
        assert_eq!(e.regs.read(mips_regs::T2 as usize), 0x0F);
        assert_eq!(e.regs.read(mips_regs::T3 as usize), 0xFF);
        assert_eq!(e.regs.read(mips_regs::T4 as usize), 0xF0);
    }

    // ── SLT ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_slt() {
        let mut e = make();
        setup(&mut e, 0x1000, &[0u8; 0x100]);
        write_insn(&mut e, 0x1000, encode_itype(0x09, 0, mips_regs::T0, 3));
        write_insn(&mut e, 0x1004, encode_itype(0x09, 0, mips_regs::T1, 5));
        // SLT $t2, $t0, $t1 (3 < 5 = true)
        write_insn(
            &mut e,
            0x1008,
            encode_rtype(0, mips_regs::T0, mips_regs::T1, mips_regs::T2, 0, 0x2A),
        );
        // SLT $t3, $t1, $t0 (5 < 3 = false)
        write_insn(
            &mut e,
            0x100C,
            encode_rtype(0, mips_regs::T1, mips_regs::T0, mips_regs::T3, 0, 0x2A),
        );
        // BREAK
        write_insn(&mut e, 0x1010, encode_rtype(0, 0, 0, 0, 0, 0x0D));
        e.start(0x1000, 0x9999, 0, 100).unwrap();
        assert_eq!(e.regs.read(mips_regs::T2 as usize), 1);
        assert_eq!(e.regs.read(mips_regs::T3 as usize), 0);
    }

    // ── LW / SW ───────────────────────────────────────────────────────────────

    #[test]
    fn test_lw_sw() {
        let mut e = make();
        setup(&mut e, 0x1000, &[0u8; 0x100]);
        // Use address 0x8000 (fits in signed 16-bit positive immediate via ADDIU)
        e.map_memory(0x8000, 0x100, MemPerms::READ | MemPerms::WRITE)
            .unwrap();
        // ADDIU $t0, $zero, 0x8000 — note: 0x8000 is negative in i16, but ADDIU sign-extends
        // to give 0xFFFF_8000. Use ORI instead (zero-extends) to get exact 0x8000.
        // ORI $t0, $zero, 0x8000
        write_insn(
            &mut e,
            0x1000,
            encode_itype(0x0D, 0, mips_regs::T0, 0x8000_u16),
        );
        // ORI $t1, $zero, 0x1234  (safe positive value)
        write_insn(
            &mut e,
            0x1004,
            encode_itype(0x0D, 0, mips_regs::T1, 0x1234_u16),
        );
        // SW $t1, 0($t0)
        write_insn(
            &mut e,
            0x1008,
            encode_itype(0x2B, mips_regs::T0, mips_regs::T1, 0),
        );
        // LW $t2, 0($t0)
        write_insn(
            &mut e,
            0x100C,
            encode_itype(0x23, mips_regs::T0, mips_regs::T2, 0),
        );
        // BREAK
        write_insn(&mut e, 0x1010, encode_rtype(0, 0, 0, 0, 0, 0x0D));
        e.start(0x1000, 0x9999, 0, 100).unwrap();
        assert_eq!(e.regs.read(mips_regs::T2 as usize), 0x1234);
    }

    // ── MULT / MFHI / MFLO ───────────────────────────────────────────────────

    #[test]
    fn test_mult() {
        let mut e = make();
        setup(&mut e, 0x1000, &[0u8; 0x100]);
        write_insn(&mut e, 0x1000, encode_itype(0x09, 0, mips_regs::T0, 6));
        write_insn(&mut e, 0x1004, encode_itype(0x09, 0, mips_regs::T1, 7));
        // MULT $t0,$t1
        write_insn(
            &mut e,
            0x1008,
            encode_rtype(0, mips_regs::T0, mips_regs::T1, 0, 0, 0x18),
        );
        // MFLO $t2
        write_insn(
            &mut e,
            0x100C,
            encode_rtype(0, 0, 0, mips_regs::T2, 0, 0x12),
        );
        // BREAK
        write_insn(&mut e, 0x1010, encode_rtype(0, 0, 0, 0, 0, 0x0D));
        e.start(0x1000, 0x9999, 0, 100).unwrap();
        assert_eq!(e.regs.read(mips_regs::T2 as usize), 42);
    }

    // ── BEQ branch ────────────────────────────────────────────────────────────

    #[test]
    fn test_beq() {
        let mut e = make();
        setup(&mut e, 0x1000, &[0u8; 0x200]);
        write_insn(&mut e, 0x1000, encode_itype(0x09, 0, mips_regs::T0, 5));
        write_insn(&mut e, 0x1004, encode_itype(0x09, 0, mips_regs::T1, 5));
        // BEQ $t0,$t1, +2 insns (offset=2 → imm=2; actual branch target = pc+4 + 2*4 = 0x1010)
        write_insn(
            &mut e,
            0x1008,
            encode_itype(0x04, mips_regs::T0, mips_regs::T1, 2_u16),
        );
        // NOP (delay slot)
        write_insn(&mut e, 0x100C, 0x0000_0000);
        // ADDIU $t2, $zero, 0xFF (should be skipped)
        write_insn(&mut e, 0x1010, encode_itype(0x09, 0, mips_regs::T2, 0xFF));
        // BREAK
        write_insn(&mut e, 0x1014, encode_rtype(0, 0, 0, 0, 0, 0x0D));
        // Target of BEQ at 0x1018
        write_insn(&mut e, 0x1018, encode_rtype(0, 0, 0, 0, 0, 0x0D));
        e.start(0x1000, 0x9999, 0, 200).unwrap();
        // T2 should still be 0xFF because BEQ skips over the ADDIU
        // Actually target is 0x1014 (pc=0x1008+4 + 2*4 = 0x1018)... let me correct
        // offset=1 to land at 0x1014 (pc+4+1*4=0x1014 — the BREAK)
        // We already ran; just check T2 not set (BEQ taken, jumped past)
        // In our encoding above, offset=2 means target=0x1018 (the second BREAK)
        // So the ADDIU at 0x1010 IS executed. Re-verify:
        // branch target = 0x100C + 4 + 2*4 = 0x1018. Delay slot at 0x100C.
        // So 0x1010 (ADDIU) is skipped. T2 should remain 0.
        assert_eq!(
            e.regs.read(mips_regs::T2 as usize),
            0,
            "BEQ should skip ADDIU at 0x1010"
        );
    }

    // ── JR / JALR ─────────────────────────────────────────────────────────────

    #[test]
    fn test_jr() {
        let mut e = make();
        setup(&mut e, 0x1000, &[0u8; 0x200]);
        // LUI $t0, 0 / ORI $t0, $t0, 0x1010 — set $t0 = 0x1010
        write_insn(
            &mut e,
            0x1000,
            encode_itype(0x0D, 0, mips_regs::T0, 0x1010_u16),
        ); // ORI $t0, $zero, 0x1010
        // JR $t0
        write_insn(
            &mut e,
            0x1004,
            encode_rtype(0, mips_regs::T0, 0, 0, 0, 0x08),
        );
        // NOP delay slot
        write_insn(&mut e, 0x1008, 0x0000_0000);
        // ADDIU $t1,$zero,0xFF (should be skipped)
        write_insn(&mut e, 0x100C, encode_itype(0x09, 0, mips_regs::T1, 0xFF));
        // BREAK at 0x1010 (jump target)
        write_insn(&mut e, 0x1010, encode_rtype(0, 0, 0, 0, 0, 0x0D));
        e.start(0x1000, 0x9999, 0, 100).unwrap();
        assert_eq!(
            e.regs.read(mips_regs::T1 as usize),
            0,
            "JR should skip 0x100C"
        );
    }

    // ── Context save/restore ──────────────────────────────────────────────────

    #[test]
    fn test_ctx_save_restore() {
        let mut e = make();
        e.regs.write(mips_regs::V0 as usize, 0xCAFE);
        let ctx = e.context_save().unwrap();
        e.regs.write(mips_regs::V0 as usize, 0);
        e.context_restore(&ctx).unwrap();
        assert_eq!(e.regs.read(mips_regs::V0 as usize), 0xCAFE);
    }
}
