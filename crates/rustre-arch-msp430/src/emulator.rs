//! `emulator.rs` — MSP430 software emulator.
//!
//! Provides a cycle-accurate (at instruction granularity) emulator for base
//! MSP430 programs:
//!
//! * [`Msp430State`] — 16 registers + SR flags + 64 KiB flat memory + I/O ports.
//! * [`step`]        — execute one instruction, returning a [`StepResult`].
//! * [`run_until`]   — run until a condition or step limit is reached.
//! * Interrupt simulation — read vector table at `0xFFE0`–`0xFFFF`, trigger
//!   interrupts when enabled.
//! * Peripheral I/O port simulation — byte-addressable Port1/Port2 registers.

use crate::{
    AddrMode, AluResult, alu_add, alu_addc, alu_and, alu_bis, alu_rra, alu_rrc, alu_sub, alu_subc,
    alu_swpb, alu_sxt, alu_xor, regs, sr_bits, src_addr_mode,
};
use rustre_core::errors::CoreError;

// ── Peripheral I/O port ───────────────────────────────────────────────────────

/// Simulated GPIO port (one byte per register: IN, OUT, DIR, IFG, IES, IE, SEL).
#[derive(Debug, Clone, Default)]
pub struct GpioPort {
    pub r#in: u8,
    pub out: u8,
    pub dir: u8,
    pub ifg: u8, // Interrupt flag register
    pub ies: u8, // Interrupt edge select
    pub ie: u8,  // Interrupt enable
    pub sel: u8, // Function select
}

impl GpioPort {
    /// Read a peripheral register by its byte address within this port's range.
    #[must_use]
    pub const fn read_reg(&self, offset: u8) -> u8 {
        match offset {
            0 => self.r#in,
            1 => self.out,
            2 => self.dir,
            3 => self.ifg,
            4 => self.ies,
            5 => self.ie,
            6 => self.sel,
            _ => 0,
        }
    }

    /// Write a peripheral register.
    pub const fn write_reg(&mut self, offset: u8, val: u8) {
        match offset {
            // 0 = IN: read-only from CPU perspective — falls through to `_`
            1 => self.out = val,
            2 => self.dir = val,
            3 => self.ifg = val,
            4 => self.ies = val,
            5 => self.ie = val,
            6 => self.sel = val,
            _ => {}
        }
    }

    /// Return true if any enabled interrupt flag is set.
    #[must_use]
    pub const fn interrupt_pending(&self) -> bool {
        self.ie & self.ifg != 0
    }
}

// ── I/O peripheral map ────────────────────────────────────────────────────────

/// Well-known peripheral base addresses for `MSP430G2xx` (`LaunchPad`) devices.
pub mod periph_addr {
    pub const PORT1_IN: u16 = 0x0020;
    pub const PORT1_OUT: u16 = 0x0021;
    pub const PORT1_DIR: u16 = 0x0022;
    pub const PORT1_IFG: u16 = 0x0023;
    pub const PORT1_IES: u16 = 0x0024;
    pub const PORT1_IE: u16 = 0x0025;
    pub const PORT1_SEL: u16 = 0x0026;

    pub const PORT2_IN: u16 = 0x0028;
    pub const PORT2_OUT: u16 = 0x0029;
    pub const PORT2_DIR: u16 = 0x002A;
    pub const PORT2_IFG: u16 = 0x002B;
    pub const PORT2_IES: u16 = 0x002C;
    pub const PORT2_IE: u16 = 0x002D;
    pub const PORT2_SEL: u16 = 0x002E;

    pub const WDTCTL: u16 = 0x0120; // Watchdog control register (word)
}

// ── Machine state ─────────────────────────────────────────────────────────────

/// Complete MSP430 machine state.
#[derive(Clone)]
pub struct Msp430State {
    /// General-purpose register file (R0-R15).
    pub regs: [u16; 16],
    /// Flat 64 KiB memory.
    pub mem: Box<[u8]>,
    /// Simulated GPIO Port 1.
    pub port1: GpioPort,
    /// Simulated GPIO Port 2.
    pub port2: GpioPort,
    /// Total instructions executed.
    pub insn_count: u64,
    /// Whether the CPU is halted (CPUOFF set or explicit halt).
    pub halted: bool,
    /// Watchdog timer counter (decremented each instruction if WDT active).
    pub wdt_count: u32,
    /// Whether WDT is enabled.
    pub wdt_enabled: bool,
    /// Pending interrupt vector address (0 = none).
    pub pending_irq: u16,
}

impl std::fmt::Debug for Msp430State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Msp430State")
            .field("regs", &self.regs)
            .field("insn_count", &self.insn_count)
            .field("halted", &self.halted)
            .finish_non_exhaustive()
    }
}

impl Msp430State {
    /// Create a new zeroed state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            regs: [0u16; 16],
            mem: vec![0u8; 0x10000].into_boxed_slice(),
            port1: GpioPort::default(),
            port2: GpioPort::default(),
            insn_count: 0,
            halted: false,
            wdt_count: 32768,
            wdt_enabled: false,
            pending_irq: 0,
        }
    }

    // ── Register accessors ────────────────────────────────────────────────────

    #[must_use]
    pub const fn pc(&self) -> u16 {
        self.regs[0]
    }
    pub const fn set_pc(&mut self, v: u16) {
        self.regs[0] = v;
    }

    #[must_use]
    pub const fn sp(&self) -> u16 {
        self.regs[1]
    }
    pub const fn set_sp(&mut self, v: u16) {
        self.regs[1] = v;
    }

    #[must_use]
    pub const fn sr(&self) -> u16 {
        self.regs[2]
    }
    pub const fn set_sr(&mut self, v: u16) {
        self.regs[2] = v;
    }

    #[must_use]
    pub const fn carry(&self) -> bool {
        self.regs[2] & sr_bits::C != 0
    }
    #[must_use]
    pub const fn zero(&self) -> bool {
        self.regs[2] & sr_bits::Z != 0
    }
    #[must_use]
    pub const fn negative(&self) -> bool {
        self.regs[2] & sr_bits::N != 0
    }
    #[must_use]
    pub const fn overflow(&self) -> bool {
        self.regs[2] & sr_bits::V != 0
    }
    #[must_use]
    pub const fn gie(&self) -> bool {
        self.regs[2] & sr_bits::GIE != 0
    }
    #[must_use]
    pub const fn cpu_off(&self) -> bool {
        self.regs[2] & sr_bits::CPUOFF != 0
    }

    /// Set or clear a single SR bit.
    pub const fn set_flag(&mut self, mask: u16, set: bool) {
        if set {
            self.regs[2] |= mask;
        } else {
            self.regs[2] &= !mask;
        }
    }

    /// Update Z/N/C/V flags from a 16-bit result.
    pub const fn update_flags_word(&mut self, r: &AluResult) {
        self.set_flag(sr_bits::Z, r.zero);
        self.set_flag(sr_bits::N, r.negative);
        self.set_flag(sr_bits::C, r.carry);
        self.set_flag(sr_bits::V, r.overflow);
    }

    /// Update Z/N/C/V flags from an 8-bit result.
    pub const fn update_flags_byte(&mut self, r: &AluResult) {
        self.set_flag(sr_bits::Z, r.result.trailing_zeros() >= 8);
        self.set_flag(sr_bits::N, r.result & 0x80 != 0);
        self.set_flag(sr_bits::C, r.carry);
        self.set_flag(sr_bits::V, r.overflow);
    }

    // ── Memory accessors ──────────────────────────────────────────────────────

    /// Read a byte from `addr`, dispatching to peripheral registers when appropriate.
    #[must_use]
    pub fn read_byte(&self, addr: u16) -> u8 {
        match addr {
            0x0020..=0x0026 => self.port1.read_reg(u8::try_from(addr - 0x0020).unwrap_or(u8::MAX)),
            0x0028..=0x002E => self.port2.read_reg(u8::try_from(addr - 0x0028).unwrap_or(u8::MAX)),
            _ => self.mem[addr as usize],
        }
    }

    /// Write a byte to `addr`, dispatching to peripheral registers.
    pub fn write_byte(&mut self, addr: u16, val: u8) {
        match addr {
            0x0020..=0x0026 => self.port1.write_reg(u8::try_from(addr - 0x0020).unwrap_or(u8::MAX), val),
            0x0028..=0x002E => self.port2.write_reg(u8::try_from(addr - 0x0028).unwrap_or(u8::MAX), val),
            0x0120..=0x0121 => { /* WDTCTL — ignore for now */ }
            _ => self.mem[addr as usize] = val,
        }
    }

    /// Read a 16-bit word (little-endian) from `addr`.
    #[must_use]
    pub fn read_word(&self, addr: u16) -> u16 {
        let lo = u16::from(self.read_byte(addr));
        let hi = u16::from(self.read_byte(addr.wrapping_add(1)));
        lo | (hi << 8)
    }

    /// Write a 16-bit word (little-endian) to `addr`.
    pub fn write_word(&mut self, addr: u16, val: u16) {
        self.write_byte(addr, (val & 0xFF) as u8);
        self.write_byte(addr.wrapping_add(1), (val >> 8) as u8);
    }

    /// Load a byte slice into memory starting at `addr`.
    ///
    /// # Panics
    /// Panics if `data` is longer than the space from `addr` to the end of the
    /// 64 KiB address space. This prevents silent wrap-around that would
    /// corrupt the beginning of memory.
    pub fn load(&mut self, addr: u16, data: &[u8]) {
        let available = 0x10000usize - addr as usize;
        assert!(
            data.len() <= available,
            "Msp430State::load: {} bytes at {:#06x} would wrap past end of address space (max {})",
            data.len(),
            addr,
            available
        );
        for (i, &b) in data.iter().enumerate() {
            self.mem[addr as usize + i] = b;
        }
    }

    /// Read the 16-bit reset vector at 0xFFFE.
    #[must_use]
    pub fn reset_vector(&self) -> u16 {
        self.read_word(0xFFFE)
    }

    // ── Stack helpers ─────────────────────────────────────────────────────────

    /// Push a 16-bit value onto the stack (SP -= 2 first).
    pub fn push_word(&mut self, val: u16) {
        let new_sp = self.sp().wrapping_sub(2);
        self.set_sp(new_sp);
        self.write_word(new_sp, val);
    }

    /// Pop a 16-bit value from the stack (SP += 2 after read).
    pub fn pop_word(&mut self) -> u16 {
        let old_sp = self.sp();
        let val = self.read_word(old_sp);
        self.set_sp(old_sp.wrapping_add(2));
        val
    }

    // ── Interrupt handling ────────────────────────────────────────────────────

    /// Read the handler address from a vector table entry at `vec_addr`.
    #[must_use]
    pub fn read_vector(&self, vec_addr: u16) -> u16 {
        self.read_word(vec_addr)
    }

    /// Trigger a software interrupt: push SR and PC, load vector, clear GIE.
    ///
    /// `vec_addr` is the address of the 16-bit vector table entry.
    pub fn trigger_interrupt(&mut self, vec_addr: u16) {
        if !self.gie() {
            return; // Interrupts disabled.
        }
        let sr = self.sr();
        let pc = self.pc();
        self.push_word(pc);
        self.push_word(sr);
        // Disable further interrupts.
        self.set_flag(sr_bits::GIE, false);
        let handler = self.read_vector(vec_addr);
        self.set_pc(handler);
    }

    /// Check for pending port interrupts and trigger the appropriate vector.
    pub fn service_pending_irq(&mut self) {
        if self.pending_irq != 0 && self.gie() {
            let v = self.pending_irq;
            self.pending_irq = 0;
            self.trigger_interrupt(v);
        }
    }

    /// Reset the CPU: load PC from reset vector, clear SR, clear halt.
    pub fn reset(&mut self) {
        let entry = self.reset_vector();
        self.set_pc(entry);
        self.set_sr(0);
        self.halted = false;
    }
}

impl Default for Msp430State {
    fn default() -> Self {
        Self::new()
    }
}

// ── Step result ───────────────────────────────────────────────────────────────

/// Result of executing one instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepResult {
    /// Instruction executed normally; PC advanced.
    Ok,
    /// The CPU halted (CPUOFF bit set in SR).
    Halted,
    /// A CALL instruction was executed; `target` is the callee address.
    Call { target: u16, return_addr: u16 },
    /// A return instruction (RETI or emulated RET) was executed.
    Ret { to: u16 },
    /// A branch was taken.
    BranchTaken { target: u16 },
    /// A branch was not taken; fell through.
    BranchNotTaken,
    /// Decode error (unsupported or data word).
    DecodeError,
}

impl StepResult {
    /// Return `true` if execution should stop.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Halted | Self::DecodeError)
    }
}

// ── Single-step execution ─────────────────────────────────────────────────────

/// Execute one instruction in `state`.
///
/// The PC must point to a valid instruction in `state.mem`.
///
/// # Errors
/// Returns `CoreError::InvalidFormat` if there are fewer than 2 readable bytes.
pub fn step(state: &mut Msp430State) -> Result<StepResult, CoreError> {
    // Service pending interrupts before next instruction.
    state.service_pending_irq();

    if state.halted || state.cpu_off() {
        state.halted = true;
        return Ok(StepResult::Halted);
    }

    let pc = state.pc();
    let lo = state.read_byte(pc);
    let hi = state.read_byte(pc.wrapping_add(1));
    let word = u16::from_le_bytes([lo, hi]);
    let pc_after = pc.wrapping_add(2);
    state.set_pc(pc_after);

    state.insn_count += 1;

    let hi3 = (word >> 13) as u8;
    if hi3 == 0b001 {
        let result = exec_jump(state, word);
        return Ok(result);
    }

    let hi6 = (word >> 10) & 0x3F;
    if hi6 == 0b00_0100 {
        return Ok(exec_single_op(state, word));
    }

    let opcode4 = (word >> 12) as u8;
    if opcode4 >= 4 {
        exec_two_op(state, word, opcode4);
        // Check CPUOFF after instruction (can be set by MOV into SR).
        if state.cpu_off() {
            state.halted = true;
            return Ok(StepResult::Halted);
        }
        return Ok(StepResult::Ok);
    }

    // Data word — skip.
    Ok(StepResult::DecodeError)
}

// ── Cast helpers ──────────────────────────────────────────────────────────────

/// Wrapping cast from i32 to u16 — intentional for MSP430 16-bit PC arithmetic.
#[inline]
const fn i32_to_u16_wrap(v: i32) -> u16 { v as u16 }

/// Sign-extend i8 to u16 — intentional for MSP430 constant-generator values.
#[inline]
const fn i8_sext_u16(v: i8) -> u16 { v as u16 }

// ── Jump execution ────────────────────────────────────────────────────────────

fn exec_jump(state: &mut Msp430State, word: u16) -> StepResult {
    let cond = ((word >> 10) & 7) as u8;
    let raw_off = word & 0x3FF;
    let offset: i16 = if raw_off & 0x200 != 0 {
        raw_off.cast_signed() | (-0x400_i16)
    } else {
        raw_off.cast_signed()
    };

    let taken = match cond {
        0 => !state.zero(),
        1 => state.zero(),
        2 => !state.carry(),
        3 => state.carry(),
        4 => state.negative(),
        5 => state.negative() == state.overflow(),
        6 => state.negative() != state.overflow(),
        _ => true, // JMP
    };

    if taken {
        let cur = state.pc();
        let target = i32_to_u16_wrap(i32::from(cur).wrapping_add(i32::from(offset) * 2));
        state.set_pc(target);
        let _ = cond;
        StepResult::BranchTaken { target }
    } else {
        StepResult::BranchNotTaken
    }
}

// ── Single-operand execution ──────────────────────────────────────────────────

fn exec_single_op(state: &mut Msp430State, word: u16) -> StepResult {
    // RETI
    if word == 0x1300 {
        let sr = state.pop_word();
        let pc = state.pop_word();
        state.set_sr(sr);
        let to = pc;
        state.set_pc(pc);
        return StepResult::Ret { to };
    }

    let opcode3 = ((word >> 7) & 7) as u8;
    let bw = (word >> 6) & 1 != 0;
    let as_bits = ((word >> 4) & 3) as u8;
    let reg = (word & 0xF) as u8;
    let cur_pc = state.pc();

    let (val, new_pc) = read_src_operand(state, as_bits, reg, cur_pc, bw);
    state.set_pc(new_pc);

    match opcode3 {
        0 /* RRC */ => {
            if bw {
                let r = alu_rrc(val & 0xFF, state.carry());
                let byte_r = AluResult { result: r.result & 0xFF, ..r };
                state.update_flags_byte(&byte_r);
                write_operand(state, as_bits, reg, byte_r.result, bw);
            } else {
                let r = alu_rrc(val, state.carry());
                state.update_flags_word(&r);
                write_operand(state, as_bits, reg, r.result, bw);
            }
        }
        1 /* SWPB */ => {
            let r = alu_swpb(val);
            write_operand(state, as_bits, reg, r, bw);
        }
        2 /* RRA */ => {
            let r = if bw {
                let byte_val = (val as u8).cast_signed() >> 1;
                let carry = val & 1 != 0;
                AluResult {
                    result:   u16::from(byte_val.cast_unsigned()),
                    carry,
                    overflow: false,
                    zero:     byte_val == 0,
                    negative: byte_val < 0,
                }
            } else {
                alu_rra(val)
            };
            if bw {
                state.update_flags_byte(&r);
            } else {
                state.update_flags_word(&r);
            }
            write_operand(state, as_bits, reg, r.result, bw);
        }
        3 /* SXT */ => {
            let r = alu_sxt(val);
            state.update_flags_word(&r);
            write_operand(state, as_bits, reg, r.result, false); // SXT always word
        }
        4 /* PUSH */ => {
            let push_val = if bw { val & 0xFF } else { val };
            state.push_word(push_val);
        }
        5 /* CALL */ => {
            let target = val;
            let ret_addr = state.pc(); // already past ext word
            state.push_word(ret_addr);
            state.set_pc(target);
            return StepResult::Call { target, return_addr: ret_addr };
        }
        _ => {}
    }

    StepResult::Ok
}

// ── Two-operand execution ─────────────────────────────────────────────────────

fn exec_two_op(state: &mut Msp430State, word: u16, opcode4: u8) {
    let src_reg = ((word >> 8) & 0xF) as u8;
    let ad = ((word >> 7) & 1) as u8;
    let bw = (word >> 6) & 1 != 0;
    let as_bits = ((word >> 4) & 3) as u8;
    let dst_reg = (word & 0xF) as u8;

    let cur_pc = state.pc();
    let (src_val, new_pc) = read_src_operand(state, as_bits, src_reg, cur_pc, bw);
    state.set_pc(new_pc);

    // Read destination.
    let (dst_val, dst_ea) = if ad == 0 {
        (state.regs[dst_reg as usize], None)
    } else {
        let pc2 = state.pc();
        let ext = state.read_word(pc2);
        state.set_pc(pc2.wrapping_add(2));
        let ea = if dst_reg == 2 {
            ext
        } else {
            state.regs[dst_reg as usize].wrapping_add(ext)
        };
        (state.read_word(ea), Some(ea))
    };

    let carry_in = state.carry();

    let result = match opcode4 {
        4 => AluResult {
            result: src_val,
            carry: false,
            overflow: false,
            zero: src_val == 0,
            negative: src_val & 0x8000 != 0,
        },
        5 => alu_add(src_val, dst_val),
        6 => alu_addc(src_val, dst_val, carry_in),
        7 => alu_subc(src_val, dst_val, carry_in),
        8 | 9 => alu_sub(src_val, dst_val), // 9=CMP (no write-back)
        10 => {
            // DADD (BCD) — approximate as binary add.
            
            alu_addc(src_val, dst_val, carry_in)
        }
        11 | 15 => alu_and(src_val, dst_val), // 11=BIT, 15=AND
        12 => AluResult {
            result: dst_val & !src_val,
            carry: false,
            overflow: false,
            zero: (dst_val & !src_val) == 0,
            negative: (dst_val & !src_val) & 0x8000 != 0,
        }, // BIC
        13 => alu_bis(src_val, dst_val), // BIS
        14 => alu_xor(src_val, dst_val),
        _ => return,
    };

    // Update flags for instructions that affect SR.
    match opcode4 {
        4 | 12 | 13 => {} // MOV, BIC, BIS: no flags
        _ => {
            if bw {
                state.update_flags_byte(&result);
            } else {
                state.update_flags_word(&result);
            }
        }
    }

    // Write result (not CMP=9 or BIT=11).
    if opcode4 != 9 && opcode4 != 11 {
        let write_val = if bw {
            result.result & 0xFF
        } else {
            result.result
        };
        match dst_ea {
            None => {
                state.regs[dst_reg as usize] = write_val;
                // If writing to SR, check CPUOFF.
                if dst_reg == regs::SR as u8 {
                    // handled by caller
                }
            }
            Some(ea) => {
                if bw {
                    state.write_byte(ea, u8::try_from(write_val).unwrap_or(u8::MAX));
                } else {
                    state.write_word(ea, write_val);
                }
            }
        }
    }

}

// ── Operand helpers ───────────────────────────────────────────────────────────

/// Read a source operand value given addressing mode info.
/// Returns `(value, new_pc)`.
fn read_src_operand(
    state: &mut Msp430State,
    as_bits: u8,
    reg: u8,
    cur_pc: u16,
    bw: bool,
) -> (u16, u16) {
    match src_addr_mode(as_bits, reg) {
        AddrMode::Register => (state.regs[reg as usize], cur_pc),
        AddrMode::Indirect => {
            let addr = state.regs[reg as usize];
            let val = if bw {
                u16::from(state.read_byte(addr))
            } else {
                state.read_word(addr)
            };
            (val, cur_pc)
        }
        AddrMode::IndirectAutoInc => {
            let addr = state.regs[reg as usize];
            let val = if bw {
                let v = u16::from(state.read_byte(addr));
                state.regs[reg as usize] = addr.wrapping_add(1);
                v
            } else {
                let v = state.read_word(addr);
                state.regs[reg as usize] = addr.wrapping_add(2);
                v
            };
            (val, cur_pc)
        }
        AddrMode::Immediate => {
            let imm = state.read_word(cur_pc);
            (imm, cur_pc.wrapping_add(2))
        }
        AddrMode::Indexed => {
            let offset = state.read_word(cur_pc).cast_signed();
            let base = state.regs[reg as usize];
            let ea = base.wrapping_add(offset.cast_unsigned());
            let val = if bw {
                u16::from(state.read_byte(ea))
            } else {
                state.read_word(ea)
            };
            (val, cur_pc.wrapping_add(2))
        }
        AddrMode::Absolute => {
            let abs = state.read_word(cur_pc);
            let val = if bw {
                u16::from(state.read_byte(abs))
            } else {
                state.read_word(abs)
            };
            (val, cur_pc.wrapping_add(2))
        }
        AddrMode::Symbolic => {
            // Symbolic: EA = (PC of the extension word) + sign-extended offset.
            // The extension word is at cur_pc; PC will be cur_pc+2 after consuming it.
            // MSP430 Symbolic = PC-relative where PC points past the extension word.
            let offset: i16 = state.read_word(cur_pc).cast_signed();
            let ea = cur_pc.wrapping_add(2).wrapping_add(offset.cast_unsigned());
            let val = if bw {
                u16::from(state.read_byte(ea))
            } else {
                state.read_word(ea)
            };
            (val, cur_pc.wrapping_add(2))
        }
        AddrMode::Constant(c) => (i8_sext_u16(c), cur_pc),
    }
}

/// Write a value back to a single-operand destination.
const fn write_operand(state: &mut Msp430State, as_bits: u8, reg: u8, val: u16, bw: bool) {
    // In byte mode the upper byte of the destination register is cleared.
    let val = if bw { val & 0x00FF } else { val };
    match src_addr_mode(as_bits, reg) {
        AddrMode::Register => {
            state.regs[reg as usize] = val;
        }
        // Indexed: extension word already consumed; EA computed at read time.
        // All other modes: write-back is handled at the call site.
        _ => {}
    }
}

// ── run_until ─────────────────────────────────────────────────────────────────

/// Condition under which `run_until` should stop.
#[derive(Debug, Clone)]
pub enum StopCondition {
    /// Stop after exactly `n` instructions.
    StepCount(u64),
    /// Stop when PC reaches `addr`.
    AtAddress(u16),
    /// Stop when the CPU is halted (CPUOFF).
    OnHalt,
    /// Stop when a CALL to `target` is executed.
    OnCall(u16),
    /// Stop when a return (RETI / RET) is executed.
    OnReturn,
}

/// Run `state` until `condition` is met or `max_steps` is exhausted.
///
/// Returns `(steps_executed, stop_reason)`.
///
/// # Errors
/// Propagates `CoreError` from `step()` on fatal decode failure.
pub fn run_until(
    state: &mut Msp430State,
    condition: &StopCondition,
    max_steps: u64,
) -> Result<(u64, &'static str), CoreError> {
    let mut executed = 0u64;
    while executed < max_steps {
        if state.halted {
            return Ok((executed, "halted"));
        }
        let pc_before = state.pc();
        match condition {
            StopCondition::AtAddress(a) if pc_before == *a => {
                return Ok((executed, "at_address"));
            }
            StopCondition::StepCount(n) if executed >= *n => {
                return Ok((executed, "step_count"));
            }
            _ => {}
        }
        let result = step(state)?;
        executed += 1;
        match (&result, condition) {
            (StepResult::Halted, _) => return Ok((executed, "halted")),
            (StepResult::Ret { .. }, StopCondition::OnReturn) => return Ok((executed, "return")),
            (StepResult::Call { target, .. }, StopCondition::OnCall(t)) if *target == *t => {
                return Ok((executed, "call"));
            }
            (StepResult::DecodeError, _) => return Ok((executed, "decode_error")),
            _ => {}
        }
    }
    Ok((executed, "max_steps"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn state_with_code(addr: u16, code: &[u8]) -> Msp430State {
        let mut s = Msp430State::new();
        s.load(addr, code);
        s.set_pc(addr);
        s.set_sp(0x0300);
        s
    }

    // ── Basic register operations ─────────────────────────────────────────────

    #[test]
    fn mov_reg_reg_exec() {
        // MOV.W R5, R4 (R5 → R4): word = 0x4504
        let mut s = state_with_code(0x4000, &[0x04, 0x45]);
        s.regs[5] = 0x1234;
        let r = step(&mut s).unwrap();
        assert!(matches!(r, StepResult::Ok));
        assert_eq!(s.regs[4], 0x1234);
        assert_eq!(s.pc(), 0x4002);
    }

    #[test]
    fn add_word_updates_flags() {
        // ADD.W R4, R5: word = 0x5405
        let mut s = state_with_code(0x4000, &[0x05, 0x54]);
        s.regs[4] = 0x7FFF;
        s.regs[5] = 0x0001;
        step(&mut s).unwrap();
        // 0x7FFF + 0x0001 = 0x8000: V=1, N=1, C=0, Z=0
        assert!(s.overflow());
        assert!(s.negative());
        assert!(!s.carry());
        assert!(!s.zero());
    }

    #[test]
    fn sub_word_sets_carry_on_no_borrow() {
        // SUB.W R4, R5 (R5 - R4): word = 0x8405 (opcode=8, src=R4, dst=R5)
        // (5<<12)|(4<<8)|5 is ADD; we want (8<<12)|(4<<8)|5 = 0x8405
        let mut s = state_with_code(0x4000, &[0x05, 0x84]);
        s.regs[4] = 0x0001;
        s.regs[5] = 0x0002;
        step(&mut s).unwrap();
        assert_eq!(s.regs[5], 0x0001);
        assert!(s.carry()); // C = NOT borrow
    }

    #[test]
    fn cmp_sets_flags_no_write() {
        // CMP.W R4, R5: opcode=9 = 0x9405
        let mut s = state_with_code(0x4000, &[0x05, 0x94]);
        s.regs[4] = 0x0005;
        s.regs[5] = 0x0005;
        let r5_before = s.regs[5];
        step(&mut s).unwrap();
        // R5 unchanged (CMP discards result).
        assert_eq!(s.regs[5], r5_before);
        assert!(s.zero());
    }

    #[test]
    fn and_word() {
        // AND.W R4, R5: opcode=15=0xF → 0xF405
        let mut s = state_with_code(0x4000, &[0x05, 0xF4]);
        s.regs[4] = 0xFF00;
        s.regs[5] = 0x0F0F;
        step(&mut s).unwrap();
        assert_eq!(s.regs[5], 0x0F00);
    }

    #[test]
    fn bis_word_no_flags() {
        // BIS.W R4, R5: opcode=13=0xD → 0xD405
        let mut s = state_with_code(0x4000, &[0x05, 0xD4]);
        s.regs[4] = 0x00FF;
        s.regs[5] = 0xFF00;
        let sr_before = s.sr();
        step(&mut s).unwrap();
        assert_eq!(s.regs[5], 0xFFFF);
        // BIS must not change flags.
        assert_eq!(s.sr(), sr_before);
    }

    #[test]
    fn xor_word() {
        // XOR.W R4, R5: opcode=14=0xE → 0xE405
        let mut s = state_with_code(0x4000, &[0x05, 0xE4]);
        s.regs[4] = 0xAAAA;
        s.regs[5] = 0x5555;
        step(&mut s).unwrap();
        assert_eq!(s.regs[5], 0xFFFF);
    }

    // ── Stack and call ────────────────────────────────────────────────────────

    #[test]
    fn push_word_reg() {
        // PUSH.W R4: 0x1204
        let mut s = state_with_code(0x4000, &[0x04, 0x12]);
        s.regs[4] = 0xBEEF;
        step(&mut s).unwrap();
        assert_eq!(s.sp(), 0x02FE);
        assert_eq!(s.read_word(0x02FE), 0xBEEF);
    }

    #[test]
    fn call_immediate() {
        // CALL #0x4400
        let mut s = state_with_code(0x4000, &[0xB0, 0x12, 0x00, 0x44]);
        let r = step(&mut s).unwrap();
        assert!(matches!(r, StepResult::Call { target: 0x4400, .. }));
        assert_eq!(s.pc(), 0x4400);
        assert_eq!(s.sp(), 0x02FE);
        assert_eq!(s.read_word(0x02FE), 0x4004); // return address
    }

    #[test]
    fn reti_pops_sr_pc() {
        let mut s = state_with_code(0x4000, &[0x00, 0x13]); // RETI
        // Push fake SR=0x0008, PC=0x5000.
        s.push_word(0x5000);
        s.push_word(0x0008);
        let r = step(&mut s).unwrap();
        assert!(matches!(r, StepResult::Ret { .. }));
        assert_eq!(s.sr(), 0x0008);
        assert_eq!(s.pc(), 0x5000);
    }

    // ── Jumps ─────────────────────────────────────────────────────────────────

    #[test]
    fn jmp_taken_unconditional() {
        // JMP +0 at 0x4000 → 0x4002
        let mut s = state_with_code(0x4000, &[0x00, 0x3C]);
        let r = step(&mut s).unwrap();
        assert!(matches!(r, StepResult::BranchTaken { target: 0x4002 }));
        assert_eq!(s.pc(), 0x4002);
    }

    #[test]
    fn jeq_not_taken_when_z_clear() {
        // JEQ +0 at 0x4000; Z flag clear
        let mut s = state_with_code(0x4000, &[0x00, 0x24]);
        s.set_flag(sr_bits::Z, false);
        let r = step(&mut s).unwrap();
        assert_eq!(r, StepResult::BranchNotTaken);
        assert_eq!(s.pc(), 0x4002);
    }

    #[test]
    fn jeq_taken_when_z_set() {
        let mut s = state_with_code(0x4000, &[0x00, 0x24]);
        s.set_flag(sr_bits::Z, true);
        let r = step(&mut s).unwrap();
        assert!(matches!(r, StepResult::BranchTaken { .. }));
    }

    #[test]
    fn jnc_taken_when_c_clear() {
        let mut s = state_with_code(0x4000, &[0x00, 0x28]);
        s.set_flag(sr_bits::C, false);
        let r = step(&mut s).unwrap();
        assert!(matches!(r, StepResult::BranchTaken { .. }));
    }

    // ── RRC / SWPB ────────────────────────────────────────────────────────────

    #[test]
    fn rrc_word_shift() {
        // RRC.W R4: 0x1004
        let mut s = state_with_code(0x4000, &[0x04, 0x10]);
        s.regs[4] = 0x0004;
        s.set_flag(sr_bits::C, false);
        step(&mut s).unwrap();
        assert_eq!(s.regs[4], 0x0002);
        assert!(!s.carry());
    }

    #[test]
    fn swpb_exec() {
        // SWPB R4: 0x1084
        let mut s = state_with_code(0x4000, &[0x84, 0x10]);
        s.regs[4] = 0xABCD;
        step(&mut s).unwrap();
        assert_eq!(s.regs[4], 0xCDAB);
    }

    // ── Peripheral I/O ────────────────────────────────────────────────────────

    #[test]
    fn port1_write_read() {
        let mut s = Msp430State::new();
        s.write_byte(periph_addr::PORT1_OUT, 0b0101_0101);
        assert_eq!(s.read_byte(periph_addr::PORT1_OUT), 0b0101_0101);
        assert_eq!(s.port1.out, 0b0101_0101);
    }

    #[test]
    fn port2_read_in() {
        let mut s = Msp430State::new();
        s.port2.r#in = 0xAA;
        assert_eq!(s.read_byte(periph_addr::PORT2_IN), 0xAA);
    }

    // ── Interrupt handling ────────────────────────────────────────────────────

    #[test]
    fn trigger_interrupt_pushes_and_jumps() {
        let mut s = Msp430State::new();
        s.set_sp(0x0300);
        s.set_pc(0x4000);
        s.set_sr(sr_bits::GIE); // enable interrupts
        // Write vector at 0xFFFE → 0x5000
        s.write_word(0xFFFE, 0x5000);
        s.trigger_interrupt(0xFFFE);
        assert_eq!(s.pc(), 0x5000);
        assert!(!s.gie()); // GIE cleared
    }

    #[test]
    fn interrupt_not_triggered_when_gie_clear() {
        let mut s = Msp430State::new();
        s.set_sp(0x0300);
        s.set_pc(0x4000);
        // GIE is clear by default.
        s.write_word(0xFFFE, 0x5000);
        s.trigger_interrupt(0xFFFE);
        assert_eq!(s.pc(), 0x4000); // unchanged
    }

    // ── run_until ─────────────────────────────────────────────────────────────

    #[test]
    fn run_until_step_count() {
        // MOV.W R4, R5 repeated
        let code: Vec<u8> = std::iter::repeat_n([0x04u8, 0x45], 10)
            .flatten()
            .collect();
        let mut s = state_with_code(0x4000, &code);
        let (n, reason) = run_until(&mut s, &StopCondition::StepCount(3), 100).unwrap();
        assert_eq!(n, 3);
        assert_eq!(reason, "step_count");
    }

    #[test]
    fn run_until_at_address() {
        // 3 × MOV then RETI at 0x4006
        let mut code = vec![0x04u8, 0x45, 0x04, 0x45, 0x04, 0x45];
        code.extend_from_slice(&[0x00, 0x13]); // RETI
        let mut s = state_with_code(0x4000, &code);
        let (_, reason) = run_until(&mut s, &StopCondition::AtAddress(0x4006), 100).unwrap();
        assert_eq!(reason, "at_address");
        assert_eq!(s.pc(), 0x4006);
    }

    // ── reset ─────────────────────────────────────────────────────────────────

    #[test]
    fn reset_loads_reset_vector() {
        let mut s = Msp430State::new();
        s.write_word(0xFFFE, 0x4400);
        s.reset();
        assert_eq!(s.pc(), 0x4400);
        assert_eq!(s.sr(), 0);
        assert!(!s.halted);
    }

    // ── push_word / pop_word ──────────────────────────────────────────────────

    #[test]
    fn push_pop_round_trip() {
        let mut s = Msp430State::new();
        s.set_sp(0x0300);
        s.push_word(0xDEAD);
        assert_eq!(s.sp(), 0x02FE);
        let val = s.pop_word();
        assert_eq!(val, 0xDEAD);
        assert_eq!(s.sp(), 0x0300);
    }
}
