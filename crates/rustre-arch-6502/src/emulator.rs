//! Software emulator for the MOS 6502, WDC 65C02, and WDC 65816.
//!
//! # 6502 / 65C02 emulator
//!
//! [`Cpu6502State`] is a complete register snapshot; [`Cpu6502Emu`] is the
//! stateless driver that operates on it.  Key entry points:
//!
//! * [`Cpu6502Emu::step`] — execute one instruction.
//! * [`Cpu6502Emu::run_until_brk`] — run until a BRK is encountered.
//! * [`Cpu6502Emu::run_until_pc`] — run until PC equals a target.
//! * [`Cpu6502Emu::irq`] — trigger a maskable IRQ.
//! * [`Cpu6502Emu::nmi`] — trigger a non-maskable interrupt.
//!
//! Decimal-mode ADC/SBC is **fully implemented** for BCD correctness.
//!
//! # 65816 emulator
//!
//! [`Cpu65816State`] extends the 6502 state with the D, PBR, and DBR
//! registers and a 16 MiB address bus.  [`Cpu65816Emu`] mirrors the same
//! driver pattern but is mode-aware (m/x flags, emulation bit).

use crate::{
    AddrMode, CpuMode, CpuVariant,
    decoder_65816::{AddrMode816, Mode65816, decode_65816},
    opcode_table, status,
};

// ── 6502 CPU state ────────────────────────────────────────────────────────────

/// Complete architectural state of the MOS 6502 / 65C02.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpu6502State {
    pub a: u8,
    pub x: u8,
    pub y: u8,
    pub sp: u8,
    pub pc: u16,
    pub p: u8,
    /// Total cycles accumulated since construction.
    pub cycles: u64,
}

impl Default for Cpu6502State {
    fn default() -> Self {
        Self::new()
    }
}

impl Cpu6502State {
    /// Create an initial state with SP=0xFD, P=I|U, everything else zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            a: 0,
            x: 0,
            y: 0,
            sp: 0xFD,
            pc: 0,
            p: status::U | status::I,
            cycles: 0,
        }
    }

    /// Initialise from the 6502 RESET vector at 0xFFFC.
    #[must_use]
    pub fn from_reset_vector(mem: &[u8]) -> Self {
        let mut s = Self::new();
        let lo = u16::from(*mem.get(0xFFFC).unwrap_or(&0));
        let hi = u16::from(*mem.get(0xFFFD).unwrap_or(&0));
        s.pc = (hi << 8) | lo;
        s
    }

    // ── Flag helpers ──────────────────────────────────────────────────────────

    #[inline]
    #[must_use]
    pub const fn carry(&self) -> bool {
        self.p & status::C != 0
    }
    #[inline]
    #[must_use]
    pub const fn zero(&self) -> bool {
        self.p & status::Z != 0
    }
    #[inline]
    #[must_use]
    pub const fn irq_disable(&self) -> bool {
        self.p & status::I != 0
    }
    #[inline]
    #[must_use]
    pub const fn decimal(&self) -> bool {
        self.p & status::D != 0
    }
    #[inline]
    #[must_use]
    pub const fn overflow(&self) -> bool {
        self.p & status::V != 0
    }
    #[inline]
    #[must_use]
    pub const fn negative(&self) -> bool {
        self.p & status::N != 0
    }

    #[inline]
    pub const fn set_flag(&mut self, mask: u8, v: bool) {
        if v {
            self.p |= mask;
        } else {
            self.p &= !mask;
        }
    }

    #[inline]
    pub const fn set_nz(&mut self, v: u8) {
        self.set_flag(status::Z, v == 0);
        self.set_flag(status::N, v & 0x80 != 0);
    }

    // ── Stack helpers ─────────────────────────────────────────────────────────

    #[inline]
    pub fn push(&mut self, mem: &mut [u8], v: u8) {
        if mem.len() > 0x01FF {
            mem[0x0100 | self.sp as usize] = v;
        }
        self.sp = self.sp.wrapping_sub(1);
    }

    #[inline]
    pub fn pop(&mut self, mem: &[u8]) -> u8 {
        self.sp = self.sp.wrapping_add(1);
        *mem.get(0x0100 | self.sp as usize).unwrap_or(&0)
    }

    #[inline]
    pub fn push16(&mut self, mem: &mut [u8], v: u16) {
        let [lo, hi] = v.to_le_bytes();
        self.push(mem, hi);
        self.push(mem, lo);
    }

    #[inline]
    pub fn pop16(&mut self, mem: &[u8]) -> u16 {
        let lo = u16::from(self.pop(mem));
        let hi = u16::from(self.pop(mem));
        (hi << 8) | lo
    }

    // ── Addressing ───────────────────────────────────────────────────────────

    /// Effective address for all non-immediate modes.
    #[must_use]
    pub fn eff_addr(&self, mem: &[u8], mode: AddrMode, op1: u8, op2: u8) -> (u16, bool) {
        let rd = |a: u16| -> u8 { *mem.get(a as usize).unwrap_or(&0) };
        match mode {
            AddrMode::ZeroPageX => (u16::from(op1.wrapping_add(self.x)), false),
            AddrMode::ZeroPageY => (u16::from(op1.wrapping_add(self.y)), false),
            AddrMode::Absolute => (u16::from_le_bytes([op1, op2]), false),
            AddrMode::AbsoluteX => {
                let base = u16::from_le_bytes([op1, op2]);
                let addr = base.wrapping_add(u16::from(self.x));
                (addr, base & 0xFF00 != addr & 0xFF00)
            }
            AddrMode::AbsoluteY => {
                let base = u16::from_le_bytes([op1, op2]);
                let addr = base.wrapping_add(u16::from(self.y));
                (addr, base & 0xFF00 != addr & 0xFF00)
            }
            AddrMode::Indirect => {
                let ptr = u16::from_le_bytes([op1, op2]);
                let lo = u16::from(rd(ptr));
                // Classic page-wrap bug.
                let hi = u16::from(rd((ptr & 0xFF00) | (ptr.wrapping_add(1) & 0x00FF)));
                ((hi << 8) | lo, false)
            }
            AddrMode::IndirectX => {
                let zp = u16::from(op1.wrapping_add(self.x));
                let lo = u16::from(rd(zp & 0xFF));
                let hi = u16::from(rd((zp + 1) & 0xFF));
                ((hi << 8) | lo, false)
            }
            AddrMode::IndirectY => {
                let lo = u16::from(rd(u16::from(op1)));
                let hi = u16::from(rd(u16::from(op1.wrapping_add(1))));
                let base = (hi << 8) | lo;
                let addr = base.wrapping_add(u16::from(self.y));
                (addr, base & 0xFF00 != addr & 0xFF00)
            }
            AddrMode::ZeroPageIndirect => {
                let lo = u16::from(rd(u16::from(op1)));
                let hi = u16::from(rd(u16::from(op1.wrapping_add(1))));
                ((hi << 8) | lo, false)
            }
            AddrMode::AbsoluteIndirectX => {
                let base = u16::from_le_bytes([op1, op2]).wrapping_add(u16::from(self.x));
                let lo = u16::from(rd(base));
                let hi = u16::from(rd(base.wrapping_add(1)));
                ((hi << 8) | lo, false)
            }
            _ => (u16::from(op1), false),
        }
    }

    fn read_val(&self, mem: &[u8], mode: AddrMode, op1: u8, op2: u8) -> u8 {
        match mode {
            AddrMode::Immediate => op1,
            AddrMode::Accumulator => self.a,
            _ => {
                let (addr, _) = self.eff_addr(mem, mode, op1, op2);
                *mem.get(addr as usize).unwrap_or(&0)
            }
        }
    }

    fn write_val(&mut self, mem: &mut [u8], mode: AddrMode, op1: u8, op2: u8, v: u8) {
        if mode == AddrMode::Accumulator { self.a = v } else {
            let (addr, _) = self.eff_addr(mem, mode, op1, op2);
            if (addr as usize) < mem.len() {
                mem[addr as usize] = v;
            }
        }
    }

    // ── BCD ADC / SBC ────────────────────────────────────────────────────────

    fn adc_bcd(&mut self, v: u8) {
        let a = self.a;
        let c = u16::from(self.carry());
        let mut lo = u16::from(a & 0x0F) + u16::from(v & 0x0F) + c;
        if lo >= 10 {
            lo = (lo - 10) | 0x10;
        }
        let mut hi = u16::from(a >> 4) + u16::from(v >> 4) + (lo >> 4);
        let out_lo = (lo & 0x0F).to_le_bytes()[0];
        if hi >= 10 {
            self.set_flag(status::C, true);
            hi -= 10;
        } else {
            self.set_flag(status::C, false);
        }
        let result = (hi & 0x0F).to_le_bytes()[0] << 4 | out_lo;
        // V flag: binary overflow (not BCD-corrected on NMOS, approximation here)
        let bin_result = u16::from(a) + u16::from(v) + c;
        let overflow = (!(u16::from(a) ^ u16::from(v)) & (u16::from(a) ^ bin_result) & 0x80) != 0;
        self.set_flag(status::V, overflow);
        self.a = result;
        self.set_nz(result);
    }

    fn sbc_bcd(&mut self, v: u8) {
        let a = self.a;
        let orig_carry = self.carry();
        let borrow = i16::from(!orig_carry);
        let mut lo = i16::from(a & 0x0F) - i16::from(v & 0x0F) - borrow;
        if lo < 0 {
            lo += 10;
            lo -= 16;
        }
        let mut hi = i16::from(a >> 4) - i16::from(v >> 4) + if lo < 0 { -1 } else { 0 };
        let out_lo = (lo & 0x0F).to_le_bytes()[0];
        if hi < 0 {
            self.set_flag(status::C, false);
            hi += 10;
        } else {
            self.set_flag(status::C, true);
        }
        let result = (hi & 0x0F).to_le_bytes()[0] << 4 | out_lo;
        // V flag: binary approximation
        let bin_borrow = u16::from(!orig_carry);
        let bin_result = u16::from(a).wrapping_sub(u16::from(v)).wrapping_sub(bin_borrow);
        let overflow = ((a ^ v) & (a ^ bin_result.to_le_bytes()[0]) & 0x80) != 0;
        self.set_flag(status::V, overflow);
        self.a = result;
        self.set_nz(result);
    }
}

// ── 6502 emulator driver ─────────────────────────────────────────────────────

/// Stateless MOS 6502 / WDC 65C02 emulator driver.
#[derive(Debug, Clone, Default)]
pub struct Cpu6502Emu {
    pub mode: CpuMode,
}

/// Everything one decoded instruction needs, gathered once so the opcode groups
/// below can share a single parameter.
#[derive(Clone, Copy)]
struct StepArgs {
    opcode: u8,
    op1: u8,
    op2: u8,
    mode: AddrMode,
    pc: u16,
    next_pc: u16,
    eff_addr: u16,
    base_c: u8,
}

/// Result of offering one opcode to a group of arms.
enum StepArm {
    /// The opcode does not belong to this group; try the next one.
    Unmatched,
    /// The opcode executed; the caller finishes the PC and cycle bookkeeping.
    Executed,
    /// The opcode set the PC and cycle count itself; return this total.
    Completed(u8),
}

impl Cpu6502Emu {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            mode: CpuMode::Cpu6502,
        }
    }

    #[must_use]
    pub const fn new_65c02() -> Self {
        Self {
            mode: CpuMode::Cpu65C02,
        }
    }

    /// Trigger a maskable IRQ.  Does nothing if the I flag is set.
    pub fn irq(state: &mut Cpu6502State, mem: &mut [u8]) {
        if state.irq_disable() {
            return;
        }
        state.push16(mem, state.pc);
        state.push(mem, (state.p | status::U) & !status::B);
        state.set_flag(status::I, true);
        let lo = u16::from(*mem.get(0xFFFE).unwrap_or(&0));
        let hi = u16::from(*mem.get(0xFFFF).unwrap_or(&0));
        state.pc = (hi << 8) | lo;
        state.cycles = state.cycles.saturating_add(7);
    }

    /// Trigger a non-maskable interrupt (always accepted).
    pub fn nmi(state: &mut Cpu6502State, mem: &mut [u8]) {
        state.push16(mem, state.pc);
        state.push(mem, (state.p | status::U) & !status::B);
        state.set_flag(status::I, true);
        let lo = u16::from(*mem.get(0xFFFA).unwrap_or(&0));
        let hi = u16::from(*mem.get(0xFFFB).unwrap_or(&0));
        state.pc = (hi << 8) | lo;
        state.cycles = state.cycles.saturating_add(7);
    }

    /// Execute one instruction.  Returns cycle count.
    pub fn step(&self, state: &mut Cpu6502State, mem: &mut [u8]) -> u8 {
        let pc = state.pc;
        let opcode = *mem.get(pc as usize).unwrap_or(&0);
        let op1 = *mem.get(pc.wrapping_add(1) as usize).unwrap_or(&0);
        let op2 = *mem.get(pc.wrapping_add(2) as usize).unwrap_or(&0);

        let Some(entry) = opcode_table(opcode) else {
            state.pc = pc.wrapping_add(1);
            state.cycles = state.cycles.saturating_add(2);
            return 2;
        };

        // 65C02-only opcodes are undefined on the NMOS 6502: treat as a
        // one-byte NOP rather than executing the CMOS behaviour.
        if entry.variant == CpuVariant::Cpu65C02 && self.mode == CpuMode::Cpu6502 {
            state.pc = pc.wrapping_add(1);
            state.cycles = state.cycles.saturating_add(2);
            return 2;
        }

        let mode = entry.mode;
        let instr_len = 1 + mode.extra_bytes();
        let next_pc = pc.wrapping_add(instr_len);
        let (eff_addr, page_cross) = state.eff_addr(mem, mode, op1, op2);
        let base_c = entry.cycles;
        let page_pen = u8::from(page_cross);

        let mut extra = page_pen;
        let mut branched = false;

        let args = StepArgs {
            opcode,
            op1,
            op2,
            mode,
            pc,
            next_pc,
            eff_addr,
            base_c,
        };

        for group in [
            Self::step_load_store,
            Self::step_arith,
            Self::step_logic_cmp,
            Self::step_shift_jump,
            Self::step_branch_stack_flags,
        ] {
            match group(state, mem, &args, &mut extra, &mut branched) {
                StepArm::Unmatched => {}
                StepArm::Executed => break,
                StepArm::Completed(c) => return c,
            }
        }

        if !branched {
            state.pc = next_pc;
        }
        let total = base_c + extra;
        state.cycles = state.cycles.saturating_add(u64::from(total));
        total
    }

    /// Loads and stores.
    fn step_load_store(
        state: &mut Cpu6502State,
        mem: &mut [u8],
        args: &StepArgs,
        _extra: &mut u8,
        _branched: &mut bool,
    ) -> StepArm {
        let StepArgs {
            opcode,
            op1,
            op2,
            mode,
            eff_addr,
            ..
        } = *args;
        match opcode {
            // ── LDA / LDX / LDY ──────────────────────────────────────────────
            0xA9 | 0xA5 | 0xB5 | 0xAD | 0xBD | 0xB9 | 0xA1 | 0xB1 | 0xB2 => {
                let v = state.read_val(mem, mode, op1, op2);
                state.a = v;
                state.set_nz(v);
            }
            0xA2 | 0xA6 | 0xB6 | 0xAE | 0xBE => {
                let v = state.read_val(mem, mode, op1, op2);
                state.x = v;
                state.set_nz(v);
            }
            0xA0 | 0xA4 | 0xB4 | 0xAC | 0xBC => {
                let v = state.read_val(mem, mode, op1, op2);
                state.y = v;
                state.set_nz(v);
            }
            // ── STA / STX / STY / STZ ────────────────────────────────────────
            0x85 | 0x95 | 0x8D | 0x9D | 0x99 | 0x81 | 0x91 | 0x92 => {
                if (eff_addr as usize) < mem.len() {
                    mem[eff_addr as usize] = state.a;
                }
            }
            0x86 | 0x96 | 0x8E => {
                if (eff_addr as usize) < mem.len() {
                    mem[eff_addr as usize] = state.x;
                }
            }
            0x84 | 0x94 | 0x8C => {
                if (eff_addr as usize) < mem.len() {
                    mem[eff_addr as usize] = state.y;
                }
            }
            0x64 | 0x74 | 0x9C | 0x9E => {
                if (eff_addr as usize) < mem.len() {
                    mem[eff_addr as usize] = 0;
                }
            }
            _ => return StepArm::Unmatched,
        }
        StepArm::Executed
    }

    /// ADC and SBC.
    fn step_arith(
        state: &mut Cpu6502State,
        mem: &mut [u8],
        args: &StepArgs,
        _extra: &mut u8,
        _branched: &mut bool,
    ) -> StepArm {
        let StepArgs {
            opcode,
            op1,
            op2,
            mode,
            ..
        } = *args;
        match opcode {
            // ── ADC ──────────────────────────────────────────────────────────
            0x69 | 0x65 | 0x75 | 0x6D | 0x7D | 0x79 | 0x61 | 0x71 | 0x72 => {
                let v = state.read_val(mem, mode, op1, op2);
                if state.decimal() {
                    state.adc_bcd(v);
                } else {
                    let c_in = u16::from(state.carry());
                    let result = u16::from(state.a) + u16::from(v) + c_in;
                    let overflow = (!(state.a ^ v) & (state.a ^ result.to_le_bytes()[0]) & 0x80) != 0;
                    state.set_flag(status::C, result > 0xFF);
                    state.set_flag(status::V, overflow);
                    state.a = result.to_le_bytes()[0];
                    state.set_nz(state.a);
                }
            }
            // ── SBC ──────────────────────────────────────────────────────────
            0xE9 | 0xE5 | 0xF5 | 0xED | 0xFD | 0xF9 | 0xE1 | 0xF1 | 0xF2 => {
                let v = state.read_val(mem, mode, op1, op2);
                if state.decimal() {
                    state.sbc_bcd(v);
                } else {
                    let borrow = u16::from(!state.carry());
                    let result = u16::from(state.a).wrapping_sub(u16::from(v)).wrapping_sub(borrow);
                    let overflow = ((state.a ^ v) & (state.a ^ result.to_le_bytes()[0]) & 0x80) != 0;
                    state.set_flag(status::C, result < 0x100);
                    state.set_flag(status::V, overflow);
                    state.a = result.to_le_bytes()[0];
                    state.set_nz(state.a);
                }
            }
            _ => return StepArm::Unmatched,
        }
        StepArm::Executed
    }

    /// Bitwise AND/ORA/EOR, compares, BIT and INC/DEC.
    fn step_logic_cmp(
        state: &mut Cpu6502State,
        mem: &mut [u8],
        args: &StepArgs,
        _extra: &mut u8,
        _branched: &mut bool,
    ) -> StepArm {
        let StepArgs {
            opcode,
            op1,
            op2,
            mode,
            eff_addr,
            ..
        } = *args;
        match opcode {
            // ── AND / ORA / EOR ──────────────────────────────────────────────
            0x29 | 0x25 | 0x35 | 0x2D | 0x3D | 0x39 | 0x21 | 0x31 | 0x32 => {
                let v = state.read_val(mem, mode, op1, op2);
                state.a &= v;
                state.set_nz(state.a);
            }
            0x09 | 0x05 | 0x15 | 0x0D | 0x1D | 0x19 | 0x01 | 0x11 | 0x12 => {
                let v = state.read_val(mem, mode, op1, op2);
                state.a |= v;
                state.set_nz(state.a);
            }
            0x49 | 0x45 | 0x55 | 0x4D | 0x5D | 0x59 | 0x41 | 0x51 | 0x52 => {
                let v = state.read_val(mem, mode, op1, op2);
                state.a ^= v;
                state.set_nz(state.a);
            }
            // ── CMP / CPX / CPY ──────────────────────────────────────────────
            0xC9 | 0xC5 | 0xD5 | 0xCD | 0xDD | 0xD9 | 0xC1 | 0xD1 | 0xD2 => {
                let v = state.read_val(mem, mode, op1, op2);
                let r = state.a.wrapping_sub(v);
                state.set_flag(status::C, state.a >= v);
                state.set_nz(r);
            }
            0xE0 | 0xE4 | 0xEC => {
                let v = state.read_val(mem, mode, op1, op2);
                let r = state.x.wrapping_sub(v);
                state.set_flag(status::C, state.x >= v);
                state.set_nz(r);
            }
            0xC0 | 0xC4 | 0xCC => {
                let v = state.read_val(mem, mode, op1, op2);
                let r = state.y.wrapping_sub(v);
                state.set_flag(status::C, state.y >= v);
                state.set_nz(r);
            }
            // ── BIT ──────────────────────────────────────────────────────────
            0x24 | 0x2C | 0x89 | 0x34 | 0x3C => {
                let v = state.read_val(mem, mode, op1, op2);
                state.set_flag(status::Z, state.a & v == 0);
                if mode != AddrMode::Immediate {
                    state.set_flag(status::V, v & 0x40 != 0);
                    state.set_flag(status::N, v & 0x80 != 0);
                }
            }
            // ── INC / DEC ────────────────────────────────────────────────────
            0xE6 | 0xF6 | 0xEE | 0xFE => {
                if (eff_addr as usize) < mem.len() {
                    let v = mem[eff_addr as usize].wrapping_add(1);
                    mem[eff_addr as usize] = v;
                    state.set_nz(v);
                }
            }
            0x1A => {
                state.a = state.a.wrapping_add(1);
                state.set_nz(state.a);
            } // INC A
            0xE8 => {
                state.x = state.x.wrapping_add(1);
                state.set_nz(state.x);
            } // INX
            0xC8 => {
                state.y = state.y.wrapping_add(1);
                state.set_nz(state.y);
            } // INY
            0xC6 | 0xD6 | 0xCE | 0xDE => {
                if (eff_addr as usize) < mem.len() {
                    let v = mem[eff_addr as usize].wrapping_sub(1);
                    mem[eff_addr as usize] = v;
                    state.set_nz(v);
                }
            }
            0x3A => {
                state.a = state.a.wrapping_sub(1);
                state.set_nz(state.a);
            } // DEC A
            0xCA => {
                state.x = state.x.wrapping_sub(1);
                state.set_nz(state.x);
            } // DEX
            0x88 => {
                state.y = state.y.wrapping_sub(1);
                state.set_nz(state.y);
            } // DEY
            _ => return StepArm::Unmatched,
        }
        StepArm::Executed
    }

    /// Shifts, rotates, TRB/TSB and the jump/return/BRK family.
    fn step_shift_jump(
        state: &mut Cpu6502State,
        mem: &mut [u8],
        args: &StepArgs,
        _extra: &mut u8,
        _branched: &mut bool,
    ) -> StepArm {
        let StepArgs {
            opcode,
            op1,
            op2,
            mode,
            pc,
            next_pc,
            eff_addr,
            base_c,
        } = *args;
        match opcode {
            // ── ASL / LSR / ROL / ROR ────────────────────────────────────────
            0x0A | 0x06 | 0x16 | 0x0E | 0x1E => {
                let v = state.read_val(mem, mode, op1, op2);
                state.set_flag(status::C, v & 0x80 != 0);
                let r = v << 1;
                state.set_nz(r);
                state.write_val(mem, mode, op1, op2, r);
            }
            0x4A | 0x46 | 0x56 | 0x4E | 0x5E => {
                let v = state.read_val(mem, mode, op1, op2);
                state.set_flag(status::C, v & 0x01 != 0);
                let r = v >> 1;
                state.set_nz(r);
                state.write_val(mem, mode, op1, op2, r);
            }
            0x2A | 0x26 | 0x36 | 0x2E | 0x3E => {
                let v = state.read_val(mem, mode, op1, op2);
                let c = u8::from(state.carry());
                state.set_flag(status::C, v & 0x80 != 0);
                let r = (v << 1) | c;
                state.set_nz(r);
                state.write_val(mem, mode, op1, op2, r);
            }
            0x6A | 0x66 | 0x76 | 0x6E | 0x7E => {
                let v = state.read_val(mem, mode, op1, op2);
                let c = if state.carry() { 0x80u8 } else { 0 };
                state.set_flag(status::C, v & 0x01 != 0);
                let r = (v >> 1) | c;
                state.set_nz(r);
                state.write_val(mem, mode, op1, op2, r);
            }
            // ── TRB / TSB ────────────────────────────────────────────────────
            0x14 | 0x1C => {
                // TRB
                if (eff_addr as usize) < mem.len() {
                    let v = mem[eff_addr as usize];
                    state.set_flag(status::Z, state.a & v == 0);
                    mem[eff_addr as usize] = v & !state.a;
                }
            }
            0x04 | 0x0C => {
                // TSB
                if (eff_addr as usize) < mem.len() {
                    let v = mem[eff_addr as usize];
                    state.set_flag(status::Z, state.a & v == 0);
                    mem[eff_addr as usize] = v | state.a;
                }
            }
            // ── JMP ──────────────────────────────────────────────────────────
            0x4C => {
                state.pc = u16::from_le_bytes([op1, op2]);
                state.cycles += u64::from(base_c);
                return StepArm::Completed(base_c);
            }
            0x6C | 0x7C => {
                state.pc = eff_addr;
                state.cycles += u64::from(base_c);
                return StepArm::Completed(base_c);
            }
            // ── JSR ──────────────────────────────────────────────────────────
            0x20 => {
                state.push16(mem, next_pc.wrapping_sub(1));
                state.pc = u16::from_le_bytes([op1, op2]);
                state.cycles += u64::from(base_c);
                return StepArm::Completed(base_c);
            }
            // ── RTS / RTI ────────────────────────────────────────────────────
            0x60 => {
                state.pc = state.pop16(mem).wrapping_add(1);
                state.cycles += u64::from(base_c);
                return StepArm::Completed(base_c);
            }
            0x40 => {
                let p = state.pop(mem);
                state.p = (p | status::U) & !status::B;
                state.pc = state.pop16(mem);
                state.cycles += u64::from(base_c);
                return StepArm::Completed(base_c);
            }
            // ── BRK ──────────────────────────────────────────────────────────
            0x00 => {
                state.push16(mem, pc.wrapping_add(2));
                state.push(mem, state.p | status::B | status::U);
                state.set_flag(status::I, true);
                let lo = u16::from(*mem.get(0xFFFE).unwrap_or(&0));
                let hi = u16::from(*mem.get(0xFFFF).unwrap_or(&0));
                state.pc = (hi << 8) | lo;
                state.cycles += u64::from(base_c);
                return StepArm::Completed(base_c);
            }
            _ => return StepArm::Unmatched,
        }
        StepArm::Executed
    }

    /// Branches, stack push/pull, register transfers and flag ops.
    fn step_branch_stack_flags(
        state: &mut Cpu6502State,
        mem: &mut [u8],
        args: &StepArgs,
        extra: &mut u8,
        branched: &mut bool,
    ) -> StepArm {
        let StepArgs {
            opcode,
            op1,
            pc,
            next_pc,
            base_c,
            ..
        } = *args;
        match opcode {
            // ── Branches ─────────────────────────────────────────────────────
            0x90 | 0xB0 | 0xF0 | 0x30 | 0xD0 | 0x10 | 0x50 | 0x70 | 0x80 => {
                let taken = match opcode {
                    0x90 => !state.carry(),    // BCC
                    0xB0 => state.carry(),     // BCS
                    0xF0 => state.zero(),      // BEQ
                    0x30 => state.negative(),  // BMI
                    0xD0 => !state.zero(),     // BNE
                    0x10 => !state.negative(), // BPL
                    0x50 => !state.overflow(), // BVC
                    0x70 => state.overflow(),  // BVS
                    0x80 => true,              // BRA
                    _ => false,
                };
                if taken {
                    let new_pc = next_pc.wrapping_add_signed(i16::from(op1.cast_signed()));
                    let cross = (next_pc & 0xFF00) != (new_pc & 0xFF00);
                    state.pc = new_pc;
                    *extra = 1 + u8::from(cross);
                    *branched = true;
                }
            }
            // ── Stack push/pull ───────────────────────────────────────────────
            0x48 => state.push(mem, state.a),
            0x08 => state.push(mem, state.p | status::B | status::U),
            0xDA => state.push(mem, state.x), // PHX
            0x5A => state.push(mem, state.y), // PHY
            0x68 => {
                let v = state.pop(mem);
                state.a = v;
                state.set_nz(v);
            }
            0x28 => {
                let v = state.pop(mem);
                state.p = (v | status::U) & !status::B;
            }
            0xFA => {
                let v = state.pop(mem);
                state.x = v;
                state.set_nz(v);
            } // PLX
            0x7A => {
                let v = state.pop(mem);
                state.y = v;
                state.set_nz(v);
            } // PLY
            // ── Transfers ────────────────────────────────────────────────────
            0xAA => {
                state.x = state.a;
                state.set_nz(state.x);
            }
            0xA8 => {
                state.y = state.a;
                state.set_nz(state.y);
            }
            0xBA => {
                state.x = state.sp;
                state.set_nz(state.x);
            }
            0x8A => {
                state.a = state.x;
                state.set_nz(state.a);
            }
            0x9A => {
                state.sp = state.x;
            }
            0x98 => {
                state.a = state.y;
                state.set_nz(state.a);
            }
            // ── Flag ops ─────────────────────────────────────────────────────
            0x18 => state.set_flag(status::C, false),
            0x38 => state.set_flag(status::C, true),
            0x58 => state.set_flag(status::I, false),
            0x78 => state.set_flag(status::I, true),
            0xB8 => state.set_flag(status::V, false),
            0xD8 => state.set_flag(status::D, false),
            0xF8 => state.set_flag(status::D, true),
            // WAI (0xCB) – wait for interrupt; in emulation it falls through to
            // the NOP wildcard arm below.
            0xDB => {
                /* STP – halt; in emulation treat as infinite loop */
                state.pc = pc;
                state.cycles += u64::from(base_c);
                return StepArm::Completed(base_c);
            }
            // ── NOP / unimplemented ───────────────────────────────────────────
            _ => return StepArm::Unmatched,
        }
        StepArm::Executed
    }

    /// Run until a BRK instruction is executed.  Returns cycle count.
    pub fn run_until_brk(&self, state: &mut Cpu6502State, mem: &mut [u8], max_cycles: u64) -> u64 {
        let start = state.cycles;
        loop {
            if state.cycles.saturating_sub(start) >= max_cycles {
                break;
            }
            let opcode = *mem.get(state.pc as usize).unwrap_or(&0);
            if opcode == 0x00 {
                break;
            }
            self.step(state, mem);
        }
        state.cycles.saturating_sub(start)
    }

    /// Run until `state.pc == stop_pc`.  Returns cycle count.
    pub fn run_until_pc(
        &self,
        state: &mut Cpu6502State,
        mem: &mut [u8],
        stop_pc: u16,
        max_cycles: u64,
    ) -> u64 {
        let start = state.cycles;
        loop {
            if state.pc == stop_pc {
                break;
            }
            if state.cycles.saturating_sub(start) >= max_cycles {
                break;
            }
            self.step(state, mem);
        }
        state.cycles.saturating_sub(start)
    }
}

// ── 65816 state ───────────────────────────────────────────────────────────────

/// Complete architectural state of the WDC 65816.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cpu65816State {
    /// 16-bit accumulator (C when m=0, A low byte / B high byte when m=1).
    pub c: u16,
    /// 16-bit index register X.
    pub x: u16,
    /// 16-bit index register Y.
    pub y: u16,
    /// Stack pointer (16-bit in native mode, 0x0100-0x01FF in emulation mode).
    pub sp: u16,
    /// 16-bit program counter.
    pub pc: u16,
    /// Processor status byte.
    pub p: u8,
    /// Direct-page register (16-bit).
    pub d: u16,
    /// Program bank register (8-bit).
    pub pbr: u8,
    /// Data bank register (8-bit).
    pub dbr: u8,
    /// Current M/X/E mode flags.
    pub mode: Mode65816,
    /// Total cycles accumulated.
    pub cycles: u64,
}

impl Default for Cpu65816State {
    fn default() -> Self {
        Self::new()
    }
}

impl Cpu65816State {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            c: 0,
            x: 0,
            y: 0,
            sp: 0x01FF,
            pc: 0,
            p: status::U | status::I,
            d: 0,
            pbr: 0,
            dbr: 0,
            mode: Mode65816::emulation(),
            cycles: 0,
        }
    }

    /// 8-bit accumulator view (low byte of C).
    #[must_use]
    pub const fn a(&self) -> u8 {
        self.c.to_le_bytes()[0]
    }

    /// Initialise from the 65816 RESET vector (same location as 6502: 0xFFFC).
    #[must_use]
    pub fn from_reset_vector(mem: &[u8]) -> Self {
        let mut s = Self::new();
        let lo = u16::from(*mem.get(0xFFFC).unwrap_or(&0));
        let hi = u16::from(*mem.get(0xFFFD).unwrap_or(&0));
        s.pc = (hi << 8) | lo;
        s
    }

    const fn effective_pc(&self) -> u32 {
        ((self.pbr as u32) << 16) | self.pc as u32
    }

    pub const fn set_nz8(&mut self, v: u8) {
        let p = &mut self.p;
        if v == 0 {
            *p |= status::Z;
        } else {
            *p &= !status::Z;
        }
        if v & 0x80 != 0 {
            *p |= status::N;
        } else {
            *p &= !status::N;
        }
    }
}

// ── 65816 emulator driver ─────────────────────────────────────────────────────

/// Stateless WDC 65816 emulator driver.
///
/// Operates on a 24-bit flat `Vec<u8>` address space.
#[derive(Debug, Clone, Default)]
pub struct Cpu65816Emu;

/// Decoded 65816 instruction fields shared by the opcode groups below.
#[derive(Clone, Copy)]
struct Decoded816Args {
    mnemonic: &'static str,
    op1: u8,
    op2: u8,
    op3: u8,
    next_pc: u16,
    base_c: u8,
    mode: AddrMode816,
}

/// Result of offering one 65816 opcode to a group of arms.
enum Arm816 {
    /// The mnemonic does not belong to this group; try the next one.
    Unmatched,
    /// The mnemonic executed; the caller finishes the PC and cycle bookkeeping.
    Executed,
    /// The mnemonic set the PC and cycle count itself; return this total.
    Completed(u8),
}

impl Cpu65816Emu {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    fn rd8(mem: &[u8], addr: u32) -> u8 {
        *mem.get(addr as usize).unwrap_or(&0)
    }

    fn wr8(mem: &mut [u8], addr: u32, v: u8) {
        if (addr as usize) < mem.len() {
            mem[addr as usize] = v;
        }
    }

    fn rd16(mem: &[u8], addr: u32) -> u16 {
        let lo = u16::from(Self::rd8(mem, addr));
        let hi = u16::from(Self::rd8(mem, addr.wrapping_add(1)));
        (hi << 8) | lo
    }

    fn push8(state: &mut Cpu65816State, mem: &mut [u8], v: u8) {
        Self::wr8(mem, u32::from(state.sp), v);
        state.sp = state.sp.wrapping_sub(1);
        if state.mode.e {
            state.sp = 0x0100 | (state.sp & 0x00FF);
        }
    }

    fn pop8(state: &mut Cpu65816State, mem: &[u8]) -> u8 {
        state.sp = state.sp.wrapping_add(1);
        if state.mode.e {
            state.sp = 0x0100 | (state.sp & 0x00FF);
        }
        Self::rd8(mem, u32::from(state.sp))
    }

    fn push16(state: &mut Cpu65816State, mem: &mut [u8], v: u16) {
        let [lo, hi] = v.to_le_bytes();
        Self::push8(state, mem, hi);
        Self::push8(state, mem, lo);
    }

    fn pop16(state: &mut Cpu65816State, mem: &[u8]) -> u16 {
        let lo = u16::from(Self::pop8(state, mem));
        let hi = u16::from(Self::pop8(state, mem));
        (hi << 8) | lo
    }

    /// Execute one 65816 instruction.  Returns cycle count.
    pub fn step(state: &mut Cpu65816State, mem: &mut [u8]) -> u8 {
        let full_pc = state.effective_pc();
        let opcode = Self::rd8(mem, full_pc);
        let op1 = Self::rd8(mem, full_pc.wrapping_add(1));
        let op2 = Self::rd8(mem, full_pc.wrapping_add(2));
        let op3 = Self::rd8(mem, full_pc.wrapping_add(3));

        let Some(decoded) = decode_65816(&[opcode, op1, op2, op3], state.mode) else {
            state.pc = state.pc.wrapping_add(1);
            state.cycles = state.cycles.saturating_add(2);
            return 2;
        };

        let size = u16::try_from(decoded.size).unwrap_or(1);
        let next_pc = state.pc.wrapping_add(size);
        let base_c = decoded.base_cycles;
        let mut branched = false;

        let args = Decoded816Args {
            mnemonic: decoded.mnemonic,
            op1,
            op2,
            op3,
            next_pc,
            base_c,
            mode: decoded.mode,
        };

        for group in [Self::step816_load_store, Self::step816_control] {
            match group(state, mem, &args, &mut branched) {
                Arm816::Unmatched => {}
                Arm816::Executed => break,
                Arm816::Completed(c) => return c,
            }
        }

        if !branched {
            state.pc = next_pc;
        }
        state.cycles = state.cycles.saturating_add(u64::from(base_c));
        base_c
    }

    /// 65816 loads and stores.
    fn step816_load_store(
        state: &mut Cpu65816State,
        mem: &mut [u8],
        d: &Decoded816Args,
        _branched: &mut bool,
    ) -> Arm816 {
        let Decoded816Args {
            mnemonic: _,
            op1,
            op2,
            mode,
            ..
        } = *d;
        match d.mnemonic {
            "LDA" => {
                let v = match mode {
                    AddrMode816::Immediate16 => u16::from_le_bytes([op1, op2]),
                    AddrMode816::DirectPage => {
                        let ea = u32::from(state.d.wrapping_add(u16::from(op1)));
                        if state.mode.m {
                            u16::from(Self::rd8(mem, ea))
                        } else {
                            Self::rd16(mem, ea)
                        }
                    }
                    // Immediate8 and every remaining mode take the operand byte
                    // directly as the value.
                    _ => u16::from(op1),
                };
                if state.mode.acc_width() == 1 {
                    state.c = (state.c & 0xFF00) | (v & 0xFF);
                } else {
                    state.c = v;
                }
                state.set_nz8(state.a());
            }
            "STA" => {
                let ea: u32 = match mode {
                    AddrMode816::DirectPage => u32::from(state.d.wrapping_add(u16::from(op1))),
                    AddrMode816::Absolute16 => u32::from(u16::from_le_bytes([op1, op2])),
                    _ => u32::from(op1),
                };
                Self::wr8(mem, ea, state.a());
            }
            _ => return Arm816::Unmatched,
        }
        Arm816::Executed
    }

    /// 65816 jumps, returns and processor-mode instructions.
    fn step816_control(
        state: &mut Cpu65816State,
        mem: &mut [u8],
        d: &Decoded816Args,
        branched: &mut bool,
    ) -> Arm816 {
        let Decoded816Args {
            mnemonic: _,
            op1,
            op2,
            op3,
            next_pc,
            base_c,
            mode: _,
        } = *d;
        match d.mnemonic {
            "JSL" => {
                let target = u32::from(op3) << 16 | u32::from(op2) << 8 | u32::from(op1);
                // Push PBR and return PC-1.
                Self::push8(state, mem, state.pbr);
                Self::push16(state, mem, next_pc.wrapping_sub(1));
                let [t0, t1, t2, _] = target.to_le_bytes();
                state.pbr = t2;
                state.pc = u16::from_le_bytes([t0, t1]);
                state.cycles = state.cycles.saturating_add(u64::from(base_c));
                return Arm816::Completed(base_c);
            }
            "RTL" => {
                let ret_pc = Self::pop16(state, mem).wrapping_add(1);
                let ret_pbr = Self::pop8(state, mem);
                state.pc = ret_pc;
                state.pbr = ret_pbr;
                state.cycles = state.cycles.saturating_add(u64::from(base_c));
                return Arm816::Completed(base_c);
            }
            "JSR" => {
                let target = u16::from_le_bytes([op1, op2]);
                Self::push16(state, mem, next_pc.wrapping_sub(1));
                state.pc = target;
                state.cycles = state.cycles.saturating_add(u64::from(base_c));
                return Arm816::Completed(base_c);
            }
            "RTS" => {
                state.pc = Self::pop16(state, mem).wrapping_add(1);
                state.cycles = state.cycles.saturating_add(u64::from(base_c));
                return Arm816::Completed(base_c);
            }
            "JML" => {
                let target = u32::from(op3) << 16 | u32::from(op2) << 8 | u32::from(op1);
                let [t0, t1, t2, _] = target.to_le_bytes();
                state.pbr = t2;
                state.pc = u16::from_le_bytes([t0, t1]);
                state.cycles = state.cycles.saturating_add(u64::from(base_c));
                return Arm816::Completed(base_c);
            }
            "XCE" => {
                let old_c = state.p & status::C != 0;
                let old_e = state.mode.e;
                state.mode.e = old_c;
                state.mode.m = state.mode.e;
                state.mode.x = state.mode.e;
                if old_e {
                    state.p |= status::C;
                } else {
                    state.p &= !status::C;
                }
            }
            "REP" => {
                state.p &= !op1;
                state.mode.m = state.p & 0x20 != 0;
                state.mode.x = state.p & 0x10 != 0;
            }
            "SEP" => {
                state.p |= op1;
                state.mode.m = state.p & 0x20 != 0;
                state.mode.x = state.p & 0x10 != 0;
            }
            "STP" => {
                // Stall: PC does not advance past the STP opcode.
                state.pc = state.pc.wrapping_add(0);
                state.cycles = state.cycles.saturating_add(u64::from(base_c));
                return Arm816::Completed(base_c);
            }
            "BRL" => {
                state.pc = next_pc.wrapping_add_signed(i16::from_le_bytes([op1, op2]));
                *branched = true;
            }
            _ => return Arm816::Unmatched,
        }
        Arm816::Executed
    }

    /// Run until PC equals `stop_pc` in the current bank.
    pub fn run_until_pc(
        state: &mut Cpu65816State,
        mem: &mut [u8],
        stop_pc: u16,
        max_cycles: u64,
    ) -> u64 {
        let start = state.cycles;
        loop {
            if state.pc == stop_pc {
                break;
            }
            if state.cycles.saturating_sub(start) >= max_cycles {
                break;
            }
            Self::step(state, mem);
        }
        state.cycles.saturating_sub(start)
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mem(size: usize) -> Vec<u8> {
        vec![0u8; size]
    }

    fn run6502(prog: &[u8]) -> (Cpu6502State, Vec<u8>) {
        let mut mem = make_mem(65536);
        mem[0xFFFC] = 0x00;
        mem[0xFFFD] = 0x02;
        mem[0x0200..0x0200 + prog.len()].copy_from_slice(prog);
        let mut state = Cpu6502State::from_reset_vector(&mem);
        let end = 0x0200u16
            .wrapping_add(u16::try_from(prog.len()).expect("test program must fit in 16 bits"));
        let mut guard = 0u32;
        while state.pc < end && guard < 10_000 {
            let opcode = mem[state.pc as usize];
            if opcode == 0x00 {
                break;
            }
            Cpu6502Emu::new_65c02().step(&mut state, &mut mem);
            guard += 1;
        }
        (state, mem)
    }

    #[test]
    fn test_lda_sta_basic() {
        let (state, mem) = run6502(&[0xA9, 0x42, 0x85, 0x10]);
        assert_eq!(state.a, 0x42);
        assert_eq!(mem[0x10], 0x42);
    }

    #[test]
    fn test_adc_binary() {
        let (state, _) = run6502(&[0xA9, 0x10, 0x69, 0x20]);
        assert_eq!(state.a, 0x30);
    }

    #[test]
    fn test_adc_bcd() {
        // SED ; LDA #$19 ; ADC #$01 → result $20 in BCD
        let (state, _) = run6502(&[0xF8, 0xA9, 0x19, 0x69, 0x01]);
        assert_eq!(state.a, 0x20);
        assert!(!state.carry());
    }

    #[test]
    fn test_sbc_bcd() {
        // SED ; SEC ; LDA #$30 ; SBC #$10 → result $20
        let (state, _) = run6502(&[0xF8, 0x38, 0xA9, 0x30, 0xE9, 0x10]);
        assert_eq!(state.a, 0x20);
        assert!(state.carry());
    }

    #[test]
    fn test_nmi() {
        let mut mem = make_mem(65536);
        mem[0xFFFA] = 0x00;
        mem[0xFFFB] = 0x03;
        let mut state = Cpu6502State::new();
        state.pc = 0x0200;
        Cpu6502Emu::nmi(&mut state, &mut mem);
        assert_eq!(state.pc, 0x0300);
    }

    #[test]
    fn test_irq_masked() {
        let mut mem = make_mem(65536);
        mem[0xFFFE] = 0x00;
        mem[0xFFFF] = 0x04;
        let mut state = Cpu6502State::new();
        state.p |= status::I; // IRQ disabled
        state.pc = 0x0200;
        Cpu6502Emu::irq(&mut state, &mut mem);
        assert_eq!(state.pc, 0x0200); // unchanged
    }

    #[test]
    fn test_irq_fires() {
        let mut mem = make_mem(65536);
        mem[0xFFFE] = 0x00;
        mem[0xFFFF] = 0x04;
        let mut state = Cpu6502State::new();
        state.p &= !status::I; // IRQ enabled
        state.pc = 0x0200;
        Cpu6502Emu::irq(&mut state, &mut mem);
        assert_eq!(state.pc, 0x0400);
    }

    #[test]
    fn test_65c02_stz() {
        let mut mem = make_mem(65536);
        mem[0xFFFC] = 0x00;
        mem[0xFFFD] = 0x02;
        mem[0x0200] = 0x64;
        mem[0x0201] = 0x30; // STZ $30
        mem[0x30] = 0xFF;
        let mut state = Cpu6502State::from_reset_vector(&mem);
        Cpu6502Emu::new_65c02().step(&mut state, &mut mem);
        assert_eq!(mem[0x30], 0x00);
    }

    #[test]
    fn test_65c02_phx_plx() {
        let (state, _) = run6502(&[0xA2, 0x55, 0xDA, 0xA2, 0x00, 0xFA]);
        assert_eq!(state.x, 0x55);
    }

    #[test]
    fn test_65816_basic_step() {
        let mut mem = make_mem(0x10000);
        mem[0xFFFC] = 0x00;
        mem[0xFFFD] = 0x10;
        mem[0x1000] = 0xA9;
        mem[0x1001] = 0x42; // LDA #$42 (8-bit)
        mem[0x1002] = 0xEA; // NOP
        let mut state = Cpu65816State::from_reset_vector(&mem);
        Cpu65816Emu::step(&mut state, &mut mem);
        assert_eq!(state.a(), 0x42);
    }

    #[test]
    fn test_run_until_brk() {
        let mut mem = make_mem(65536);
        mem[0xFFFC] = 0x00;
        mem[0xFFFD] = 0x02;
        // LDA #$42 ; BRK
        mem[0x0200] = 0xA9;
        mem[0x0201] = 0x42;
        mem[0x0202] = 0x00;
        let mut state = Cpu6502State::from_reset_vector(&mem);
        Cpu6502Emu::new().run_until_brk(&mut state, &mut mem, 10_000);
        assert_eq!(state.a, 0x42);
    }
}
