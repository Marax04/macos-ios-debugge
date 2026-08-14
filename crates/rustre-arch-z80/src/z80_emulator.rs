//! Z80 software emulator: full register set, shadow registers, I/O ports, NMI/INT.

use crate::Flags;
pub use rustre_core::arch::InstrFlags;

// ---------------------------------------------------------------------------
// Port I/O trait
// ---------------------------------------------------------------------------

/// Trait for Z80 port I/O.  Implement this to hook IN/OUT instructions.
pub trait IoPortHandler {
    /// Handle an `IN A,(port)` or `IN r,(C)` instruction.
    fn port_in(&mut self, port: u16) -> u8;
    /// Handle an `OUT (port),A` or `OUT (C),r` instruction.
    fn port_out(&mut self, port: u16, value: u8);
}

/// A no-op port handler (returns 0xFF for all reads).
#[derive(Debug, Clone, Default)]
pub struct NullPortHandler;

impl IoPortHandler for NullPortHandler {
    fn port_in(&mut self, _port: u16) -> u8 {
        0xFF
    }
    fn port_out(&mut self, _port: u16, _value: u8) {}
}

// ---------------------------------------------------------------------------
// Memory (64 KiB flat)
// ---------------------------------------------------------------------------

/// 64 KiB flat memory for the Z80.
pub struct Z80Memory {
    data: Box<[u8; 0x10000]>,
}

impl Z80Memory {
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: Box::new([0u8; 0x10000]),
        }
    }

    pub fn load(&mut self, addr: u16, bytes: &[u8]) {
        let start = addr as usize;
        let end = start.saturating_add(bytes.len()).min(0x10000);
        let len = end.saturating_sub(start);
        if len == 0 {
            return;
        }
        self.data[start..end].copy_from_slice(&bytes[..len]);
    }

    #[must_use]
    pub fn read8(&self, addr: u16) -> u8 {
        self.data[addr as usize]
    }

    pub fn write8(&mut self, addr: u16, val: u8) {
        self.data[addr as usize] = val;
    }

    #[must_use]
    pub fn read16(&self, addr: u16) -> u16 {
        let lo = self.data[addr as usize];
        let hi = self.data[addr.wrapping_add(1) as usize];
        u16::from(lo) | (u16::from(hi) << 8)
    }

    pub fn write16(&mut self, addr: u16, val: u16) {
        self.data[addr as usize] = val as u8;
        self.data[addr.wrapping_add(1) as usize] = (val >> 8) as u8;
    }
}

impl Default for Z80Memory {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Z80 CPU state
// ---------------------------------------------------------------------------

/// Interrupt mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IMode {
    M0,
    M1,
    M2,
}

/// Z80 CPU state.
pub struct Z80State {
    // Main registers
    pub a: u8,
    pub f: Flags,
    pub b: u8,
    pub c: u8,
    pub d: u8,
    pub e: u8,
    pub h: u8,
    pub l: u8,

    // Index registers
    pub ix: u16,
    pub iy: u16,

    // Special purpose
    pub sp: u16,
    pub pc: u16,
    pub i: u8, // Interrupt page address
    pub r: u8, // Memory refresh counter

    // Shadow registers (AF'/BC'/DE'/HL')
    pub a2: u8,
    pub f2: Flags,
    pub b2: u8,
    pub c2: u8,
    pub d2: u8,
    pub e2: u8,
    pub h2: u8,
    pub l2: u8,

    // Interrupt flip-flops
    pub iff1: bool,
    pub iff2: bool,

    // Interrupt mode
    pub int_mode: IMode,

    // Halt state
    pub halted: bool,

    // Pending NMI / INT
    pub nmi_pending: bool,
    pub int_pending: bool,
    pub int_data: u8, // data bus byte for IM0/IM2

    // Total cycles
    pub cycles: u64,

    // Memory
    pub mem: Z80Memory,
}

impl Z80State {
    /// Create a new Z80 state (all registers zeroed, SP = 0xFFFF).
    #[must_use]
    pub fn new() -> Self {
        Self {
            a: 0xFF,
            f: Flags::all(),
            b: 0,
            c: 0,
            d: 0,
            e: 0,
            h: 0,
            l: 0,
            ix: 0,
            iy: 0,
            sp: 0xFFFF,
            pc: 0,
            i: 0,
            r: 0,
            a2: 0xFF,
            f2: Flags::all(),
            b2: 0,
            c2: 0,
            d2: 0,
            e2: 0,
            h2: 0,
            l2: 0,
            iff1: false,
            iff2: false,
            int_mode: IMode::M1,
            halted: false,
            nmi_pending: false,
            int_pending: false,
            int_data: 0xFF,
            cycles: 0,
            mem: Z80Memory::new(),
        }
    }

    // --- Register pairs ---

    #[must_use]
    pub fn af(&self) -> u16 {
        (u16::from(self.a) << 8) | u16::from(self.f.bits())
    }
    #[must_use]
    pub fn bc(&self) -> u16 {
        (u16::from(self.b) << 8) | u16::from(self.c)
    }
    #[must_use]
    pub fn de(&self) -> u16 {
        (u16::from(self.d) << 8) | u16::from(self.e)
    }
    #[must_use]
    pub fn hl(&self) -> u16 {
        (u16::from(self.h) << 8) | u16::from(self.l)
    }

    pub fn set_af(&mut self, v: u16) {
        self.a = (v >> 8) as u8;
        self.f = Flags::from_bits_retain(v as u8);
    }
    pub fn set_bc(&mut self, v: u16) {
        self.b = (v >> 8) as u8;
        self.c = v as u8;
    }
    pub fn set_de(&mut self, v: u16) {
        self.d = (v >> 8) as u8;
        self.e = v as u8;
    }
    pub fn set_hl(&mut self, v: u16) {
        self.h = (v >> 8) as u8;
        self.l = v as u8;
    }

    // --- Flag helpers ---

    fn flag_c(&self) -> bool {
        self.f.contains(Flags::C)
    }
    fn flag_z(&self) -> bool {
        self.f.contains(Flags::Z)
    }
    fn flag_s(&self) -> bool {
        self.f.contains(Flags::S)
    }
    fn flag_pv(&self) -> bool {
        self.f.contains(Flags::PV)
    }

    fn set_c(&mut self, v: bool) {
        self.f.set(Flags::C, v);
    }
    fn set_z(&mut self, v: bool) {
        self.f.set(Flags::Z, v);
    }
    fn set_s(&mut self, v: bool) {
        self.f.set(Flags::S, v);
    }
    fn set_h(&mut self, v: bool) {
        self.f.set(Flags::H, v);
    }
    fn set_n(&mut self, v: bool) {
        self.f.set(Flags::N, v);
    }
    fn set_pv(&mut self, v: bool) {
        self.f.set(Flags::PV, v);
    }

    fn update_szpv_byte(&mut self, val: u8) {
        self.set_z(val == 0);
        self.set_s(val & 0x80 != 0);
        // Parity: even number of bits set → PV=1
        self.set_pv((val.count_ones()).is_multiple_of(2));
        self.set_n(false);
    }

    // --- Stack ---

    fn push16(&mut self, val: u16) {
        self.sp = self.sp.wrapping_sub(2);
        self.mem.write16(self.sp, val);
    }

    fn pop16(&mut self) -> u16 {
        let v = self.mem.read16(self.sp);
        self.sp = self.sp.wrapping_add(2);
        v
    }

    // --- Register read/write by 3-bit code ---

    fn reg8_read(&self, r: u8) -> u8 {
        match r & 7 {
            0 => self.b,
            1 => self.c,
            2 => self.d,
            3 => self.e,
            4 => self.h,
            5 => self.l,
            6 => self.mem.read8(self.hl()),
            _ => self.a,
        }
    }

    fn reg8_write(&mut self, r: u8, val: u8) {
        let hl = self.hl();
        match r & 7 {
            0 => self.b = val,
            1 => self.c = val,
            2 => self.d = val,
            3 => self.e = val,
            4 => self.h = val,
            5 => self.l = val,
            6 => self.mem.write8(hl, val),
            _ => self.a = val,
        }
    }

    fn rp_read(&self, p: u8) -> u16 {
        match p & 3 {
            0 => self.bc(),
            1 => self.de(),
            2 => self.hl(),
            _ => self.sp,
        }
    }

    fn rp_write(&mut self, p: u8, val: u16) {
        match p & 3 {
            0 => self.set_bc(val),
            1 => self.set_de(val),
            2 => self.set_hl(val),
            _ => self.sp = val,
        }
    }

    fn rp2_read(&self, p: u8) -> u16 {
        match p & 3 {
            0 => self.bc(),
            1 => self.de(),
            2 => self.hl(),
            _ => self.af(),
        }
    }

    fn rp2_write(&mut self, p: u8, val: u16) {
        match p & 3 {
            0 => self.set_bc(val),
            1 => self.set_de(val),
            2 => self.set_hl(val),
            _ => self.set_af(val),
        }
    }

    // --- Interrupt servicing ---

    /// Trigger a non-maskable interrupt.
    pub fn nmi(&mut self) {
        self.nmi_pending = true;
    }

    /// Trigger a maskable interrupt (provides the data-bus byte for IM0/IM2).
    pub fn int(&mut self, data: u8) {
        self.int_pending = true;
        self.int_data = data;
    }

    fn service_nmi(&mut self) {
        self.halted = false;
        self.iff2 = self.iff1;
        self.iff1 = false;
        self.push16(self.pc);
        self.pc = 0x0066;
        self.nmi_pending = false;
        self.cycles += 11;
    }

    fn service_int(&mut self) {
        if !self.iff1 {
            return;
        }
        self.halted = false;
        self.iff1 = false;
        self.iff2 = false;
        match self.int_mode {
            IMode::M0 => {
                // Execute RST opcode placed on data bus (simplified: jump to vector * 8)
                let v = (self.int_data >> 3) & 7;
                self.push16(self.pc);
                self.pc = u16::from(v) * 8;
            }
            IMode::M1 => {
                self.push16(self.pc);
                self.pc = 0x0038;
            }
            IMode::M2 => {
                let vec_addr = (u16::from(self.i) << 8) | u16::from(self.int_data & 0xFE);
                let target = self.mem.read16(vec_addr);
                self.push16(self.pc);
                self.pc = target;
            }
        }
        self.int_pending = false;
        self.cycles += 13;
    }

    // ---------------------------------------------------------------------------
    // Single-step execution
    // ---------------------------------------------------------------------------

    /// Execute one instruction at the current PC.
    ///
    /// Returns the number of T-states (cycles) consumed.
    ///
    /// # Errors
    /// Returns a string describing unimplemented instructions.
    pub fn step(&mut self, io: &mut dyn IoPortHandler) -> Result<u32, String> {
        if self.nmi_pending {
            self.service_nmi();
            // fall through to execute instruction at new PC
        } else if self.int_pending {
            self.service_int();
            // fall through to execute instruction at new PC
        }
        if self.halted {
            self.cycles += 4;
            return Ok(4);
        }

        let pc0 = self.pc;
        let op = self.mem.read8(self.pc);
        self.pc = self.pc.wrapping_add(1);
        self.r = self.r.wrapping_add(1);

        let t = self.execute(op, pc0, io)?;
        self.cycles += u64::from(t);
        Ok(t)
    }

    fn execute(&mut self, op: u8, pc0: u16, io: &mut dyn IoPortHandler) -> Result<u32, String> {
        let fetch8 = |mem: &Z80Memory, pc: &mut u16| -> u8 {
            let b = mem.read8(*pc);
            *pc = pc.wrapping_add(1);
            b
        };
        let fetch16 = |mem: &Z80Memory, pc: &mut u16| -> u16 {
            let lo = mem.read8(*pc);
            *pc = pc.wrapping_add(1);
            let hi = mem.read8(*pc);
            *pc = pc.wrapping_add(1);
            u16::from(lo) | (u16::from(hi) << 8)
        };
        let _ = pc0;

        match op as u16 {
            // NOP
            0x00 => Ok(4),
            // LD rp,nn
            0x01 | 0x11 | 0x21 | 0x31 => {
                let nn = fetch16(&self.mem, &mut self.pc);
                let p = (op >> 4) & 3;
                self.rp_write(p, nn);
                Ok(10)
            }
            // LD (BC/DE),A  or  LD A,(BC/DE)
            0x02 => {
                self.mem.write8(self.bc(), self.a);
                Ok(7)
            }
            0x12 => {
                self.mem.write8(self.de(), self.a);
                Ok(7)
            }
            0x0A => {
                self.a = self.mem.read8(self.bc());
                Ok(7)
            }
            0x1A => {
                self.a = self.mem.read8(self.de());
                Ok(7)
            }
            // INC/DEC rp
            0x03 | 0x13 | 0x23 | 0x33 => {
                let p = (op >> 4) & 3;
                self.rp_write(p, self.rp_read(p).wrapping_add(1));
                Ok(6)
            }
            0x0B | 0x1B | 0x2B | 0x3B => {
                let p = (op >> 4) & 3;
                self.rp_write(p, self.rp_read(p).wrapping_sub(1));
                Ok(6)
            }
            // INC r
            0x04 | 0x0C | 0x14 | 0x1C | 0x24 | 0x2C | 0x34 | 0x3C => {
                let r = (op >> 3) & 7;
                let v = self.reg8_read(r);
                let result = v.wrapping_add(1);
                let ovf = v == 0x7F;
                self.reg8_write(r, result);
                self.update_szpv_byte(result);
                self.set_h((v & 0x0F) == 0x0F);
                self.set_pv(ovf);
                self.set_n(false);
                Ok(if r == 6 { 11 } else { 4 })
            }
            // DEC r
            0x05 | 0x0D | 0x15 | 0x1D | 0x25 | 0x2D | 0x35 | 0x3D => {
                let r = (op >> 3) & 7;
                let v = self.reg8_read(r);
                let result = v.wrapping_sub(1);
                let ovf = v == 0x80;
                self.reg8_write(r, result);
                self.update_szpv_byte(result);
                self.set_h((v & 0x0F) == 0x00);
                self.set_pv(ovf);
                self.set_n(true);
                Ok(if r == 6 { 11 } else { 4 })
            }
            // LD r,n
            0x06 | 0x0E | 0x16 | 0x1E | 0x26 | 0x2E | 0x36 | 0x3E => {
                let r = (op >> 3) & 7;
                let n = fetch8(&self.mem, &mut self.pc);
                self.reg8_write(r, n);
                Ok(if r == 6 { 10 } else { 7 })
            }
            // Rotate accumulator
            0x07 => {
                // RLCA
                let c = self.a >> 7;
                self.a = (self.a << 1) | c;
                self.set_c(c != 0);
                self.set_h(false);
                self.set_n(false);
                Ok(4)
            }
            0x0F => {
                // RRCA
                let c = self.a & 1;
                self.a = (self.a >> 1) | (c << 7);
                self.set_c(c != 0);
                self.set_h(false);
                self.set_n(false);
                Ok(4)
            }
            0x17 => {
                // RLA
                let old_c = if self.flag_c() { 1u8 } else { 0 };
                let new_c = self.a >> 7;
                self.a = (self.a << 1) | old_c;
                self.set_c(new_c != 0);
                self.set_h(false);
                self.set_n(false);
                Ok(4)
            }
            0x1F => {
                // RRA
                let old_c = if self.flag_c() { 0x80u8 } else { 0 };
                let new_c = self.a & 1;
                self.a = (self.a >> 1) | old_c;
                self.set_c(new_c != 0);
                self.set_h(false);
                self.set_n(false);
                Ok(4)
            }
            // EX AF,AF'
            0x08 => {
                std::mem::swap(&mut self.a, &mut self.a2);
                std::mem::swap(&mut self.f, &mut self.f2);
                Ok(4)
            }
            // DJNZ
            0x10 => {
                let e = fetch8(&self.mem, &mut self.pc) as i8;
                self.b = self.b.wrapping_sub(1);
                if self.b != 0 {
                    self.pc = self.pc.wrapping_add_signed(i16::from(e));
                    Ok(13)
                } else {
                    Ok(8)
                }
            }
            // JR
            0x18 => {
                let e = fetch8(&self.mem, &mut self.pc) as i8;
                self.pc = self.pc.wrapping_add_signed(i16::from(e));
                Ok(12)
            }
            // JR cc
            0x20 => {
                let e = fetch8(&self.mem, &mut self.pc) as i8;
                if !self.flag_z() {
                    self.pc = self.pc.wrapping_add_signed(i16::from(e));
                    Ok(12)
                } else {
                    Ok(7)
                }
            }
            0x28 => {
                let e = fetch8(&self.mem, &mut self.pc) as i8;
                if self.flag_z() {
                    self.pc = self.pc.wrapping_add_signed(i16::from(e));
                    Ok(12)
                } else {
                    Ok(7)
                }
            }
            0x30 => {
                let e = fetch8(&self.mem, &mut self.pc) as i8;
                if !self.flag_c() {
                    self.pc = self.pc.wrapping_add_signed(i16::from(e));
                    Ok(12)
                } else {
                    Ok(7)
                }
            }
            0x38 => {
                let e = fetch8(&self.mem, &mut self.pc) as i8;
                if self.flag_c() {
                    self.pc = self.pc.wrapping_add_signed(i16::from(e));
                    Ok(12)
                } else {
                    Ok(7)
                }
            }
            // ADD HL,rp
            0x09 | 0x19 | 0x29 | 0x39 => {
                let p = (op >> 4) & 3;
                let hl = self.hl();
                let rr = self.rp_read(p);
                let (result, carry) = hl.overflowing_add(rr);
                let h = (hl & 0x0FFF) + (rr & 0x0FFF) > 0x0FFF;
                self.set_hl(result);
                self.set_c(carry);
                self.set_h(h);
                self.set_n(false);
                Ok(11)
            }
            // LD (nn),HL  /  LD HL,(nn)
            0x22 => {
                let nn = fetch16(&self.mem, &mut self.pc);
                self.mem.write16(nn, self.hl());
                Ok(16)
            }
            0x2A => {
                let nn = fetch16(&self.mem, &mut self.pc);
                let v = self.mem.read16(nn);
                self.set_hl(v);
                Ok(16)
            }
            // LD (nn),A  /  LD A,(nn)
            0x32 => {
                let nn = fetch16(&self.mem, &mut self.pc);
                self.mem.write8(nn, self.a);
                Ok(13)
            }
            0x3A => {
                let nn = fetch16(&self.mem, &mut self.pc);
                self.a = self.mem.read8(nn);
                Ok(13)
            }
            // HALT
            0x76 => {
                self.halted = true;
                self.pc = self.pc.wrapping_sub(1);
                Ok(4)
            }
            // LD r,r' (x=1)
            0x40..=0x7F => {
                let y = (op >> 3) & 7;
                let z = op & 7;
                let val = self.reg8_read(z);
                self.reg8_write(y, val);
                Ok(if y == 6 || z == 6 { 7 } else { 4 })
            }
            // ALU A,r (x=2)
            0x80..=0xBF => {
                let y = (op >> 3) & 7;
                let z = op & 7;
                let rhs = self.reg8_read(z);
                self.alu8(y, rhs);
                Ok(if z == 6 { 7 } else { 4 })
            }
            // RET cc (x=3, z=0)
            0xC0 | 0xC8 | 0xD0 | 0xD8 | 0xE0 | 0xE8 | 0xF0 | 0xF8 => {
                let y = (op >> 3) & 7;
                if self.eval_cc(y) {
                    self.pc = self.pop16();
                    Ok(11)
                } else {
                    Ok(5)
                }
            }
            // POP rp2 (x=3, z=1, q=0)
            0xC1 | 0xD1 | 0xE1 | 0xF1 => {
                let p = (op >> 4) & 3;
                let v = self.pop16();
                self.rp2_write(p, v);
                Ok(10)
            }
            // RET
            0xC9 => {
                self.pc = self.pop16();
                Ok(10)
            }
            // EXX
            0xD9 => {
                std::mem::swap(&mut self.b, &mut self.b2);
                std::mem::swap(&mut self.c, &mut self.c2);
                std::mem::swap(&mut self.d, &mut self.d2);
                std::mem::swap(&mut self.e, &mut self.e2);
                std::mem::swap(&mut self.h, &mut self.h2);
                std::mem::swap(&mut self.l, &mut self.l2);
                Ok(4)
            }
            // JP (HL)
            0xE9 => {
                self.pc = self.hl();
                Ok(4)
            }
            // LD SP,HL
            0xF9 => {
                self.sp = self.hl();
                Ok(6)
            }
            // JP cc,nn (x=3, z=2)
            0xC2 | 0xCA | 0xD2 | 0xDA | 0xE2 | 0xEA | 0xF2 | 0xFA => {
                let y = (op >> 3) & 7;
                let nn = fetch16(&self.mem, &mut self.pc);
                if self.eval_cc(y) {
                    self.pc = nn;
                }
                Ok(10)
            }
            // JP nn
            0xC3 => {
                self.pc = fetch16(&self.mem, &mut self.pc);
                Ok(10)
            }
            // OUT (n),A
            0xD3 => {
                let n = u16::from(fetch8(&self.mem, &mut self.pc));
                io.port_out(n, self.a);
                Ok(11)
            }
            // IN A,(n)
            0xDB => {
                let n = u16::from(fetch8(&self.mem, &mut self.pc));
                self.a = io.port_in(n);
                Ok(11)
            }
            // EX (SP),HL
            0xE3 => {
                let top = self.mem.read16(self.sp);
                let hl = self.hl();
                self.mem.write16(self.sp, hl);
                self.set_hl(top);
                Ok(19)
            }
            // EX DE,HL
            0xEB => {
                let de = self.de();
                let hl = self.hl();
                self.set_de(hl);
                self.set_hl(de);
                Ok(4)
            }
            // DI / EI
            0xF3 => {
                self.iff1 = false;
                self.iff2 = false;
                Ok(4)
            }
            0xFB => {
                self.iff1 = true;
                self.iff2 = true;
                Ok(4)
            }
            // CALL cc,nn (x=3, z=4)
            0xC4 | 0xCC | 0xD4 | 0xDC | 0xE4 | 0xEC | 0xF4 | 0xFC => {
                let y = (op >> 3) & 7;
                let nn = fetch16(&self.mem, &mut self.pc);
                if self.eval_cc(y) {
                    self.push16(self.pc);
                    self.pc = nn;
                    Ok(17)
                } else {
                    Ok(10)
                }
            }
            // PUSH rp2 (x=3, z=5, q=0)
            0xC5 | 0xD5 | 0xE5 | 0xF5 => {
                let p = (op >> 4) & 3;
                let v = self.rp2_read(p);
                self.push16(v);
                Ok(11)
            }
            // CALL nn
            0xCD => {
                let nn = fetch16(&self.mem, &mut self.pc);
                self.push16(self.pc);
                self.pc = nn;
                Ok(17)
            }
            // ALU A,n (x=3, z=6)
            0xC6 | 0xCE | 0xD6 | 0xDE | 0xE6 | 0xEE | 0xF6 | 0xFE => {
                let y = (op >> 3) & 7;
                let n = fetch8(&self.mem, &mut self.pc);
                self.alu8(y, n);
                Ok(7)
            }
            // RST (x=3, z=7)
            0xC7 | 0xCF | 0xD7 | 0xDF | 0xE7 | 0xEF | 0xF7 | 0xFF => {
                let y = (op >> 3) & 7;
                self.push16(self.pc);
                self.pc = u16::from(y) * 8;
                Ok(11)
            }
            // DAA
            0x27 => {
                self.daa();
                Ok(4)
            }
            // CPL
            0x2F => {
                self.a = !self.a;
                self.set_h(true);
                self.set_n(true);
                Ok(4)
            }
            // SCF
            0x37 => {
                self.set_c(true);
                self.set_h(false);
                self.set_n(false);
                Ok(4)
            }
            // CCF
            0x3F => {
                let c = self.flag_c();
                self.set_h(c);
                self.set_c(!c);
                self.set_n(false);
                Ok(4)
            }
            // CB prefix
            0xCB => {
                let op2 = fetch8(&self.mem, &mut self.pc);
                self.execute_cb(op2)
            }
            // ED prefix
            0xED => {
                let op2 = fetch8(&self.mem, &mut self.pc);
                self.execute_ed(op2, io)
            }
            // DD prefix (IX)
            0xDD => {
                let op2 = fetch8(&self.mem, &mut self.pc);
                self.execute_index(op2, true, io)
            }
            // FD prefix (IY)
            0xFD => {
                let op2 = fetch8(&self.mem, &mut self.pc);
                self.execute_index(op2, false, io)
            }
            _ => Err(format!("unimplemented Z80 opcode 0x{op:02X}")),
        }
    }

    fn alu8(&mut self, op_kind: u8, rhs: u8) {
        match op_kind {
            0 => {
                // ADD A,r
                let (result, carry) = self.a.overflowing_add(rhs);
                let half = (self.a & 0x0F) + (rhs & 0x0F) > 0x0F;
                // simplified ovf calc (first line intentionally discarded)
                let _discarded = (self.a ^ rhs ^ 0x80) & (rhs ^ result) == 0;
                let overflow = (!(self.a ^ rhs) & (self.a ^ result)) & 0x80 != 0;
                self.a = result;
                self.update_szpv_byte(result);
                self.set_c(carry);
                self.set_h(half);
                self.set_pv(overflow);
                self.set_n(false);
            }
            1 => {
                // ADC A,r
                let carry_in = if self.flag_c() { 1u8 } else { 0 };
                let (partial, carry1) = self.a.overflowing_add(rhs);
                let (result, carry2) = partial.overflowing_add(carry_in);
                let half = (self.a & 0x0F) + (rhs & 0x0F) + carry_in > 0x0F;
                let overflow = (!(self.a ^ rhs) & (self.a ^ result)) & 0x80 != 0;
                self.a = result;
                self.update_szpv_byte(result);
                self.set_c(carry1 | carry2);
                self.set_h(half);
                self.set_pv(overflow);
                self.set_n(false);
            }
            2 => {
                // SUB r
                let (result, carry) = self.a.overflowing_sub(rhs);
                let half = (self.a & 0x0F) < (rhs & 0x0F);
                let overflow = ((self.a ^ rhs) & (self.a ^ result)) & 0x80 != 0;
                self.a = result;
                self.update_szpv_byte(result);
                self.set_c(carry);
                self.set_h(half);
                self.set_pv(overflow);
                self.set_n(true);
            }
            3 => {
                // SBC A,r
                let carry_in = if self.flag_c() { 1u8 } else { 0 };
                let (partial, carry1) = self.a.overflowing_sub(rhs);
                let (result, carry2) = partial.overflowing_sub(carry_in);
                let half = (self.a & 0x0F) < (rhs & 0x0F) + carry_in;
                let overflow = ((self.a ^ rhs) & (self.a ^ result)) & 0x80 != 0;
                self.a = result;
                self.update_szpv_byte(result);
                self.set_c(carry1 | carry2);
                self.set_h(half);
                self.set_pv(overflow);
                self.set_n(true);
            }
            4 => {
                // AND r
                self.a &= rhs;
                self.update_szpv_byte(self.a);
                self.set_c(false);
                self.set_h(true);
                self.set_n(false);
            }
            5 => {
                // XOR r
                self.a ^= rhs;
                self.update_szpv_byte(self.a);
                self.set_c(false);
                self.set_h(false);
                self.set_n(false);
            }
            6 => {
                // OR r
                self.a |= rhs;
                self.update_szpv_byte(self.a);
                self.set_c(false);
                self.set_h(false);
                self.set_n(false);
            }
            _ => {
                // CP r
                let (result, carry) = self.a.overflowing_sub(rhs);
                let half = (self.a & 0x0F) < (rhs & 0x0F);
                let overflow = ((self.a ^ rhs) & (self.a ^ result)) & 0x80 != 0;
                self.update_szpv_byte(result);
                self.set_c(carry);
                self.set_h(half);
                self.set_pv(overflow);
                self.set_n(true);
            }
        }
    }

    fn eval_cc(&self, cc: u8) -> bool {
        match cc & 7 {
            0 => !self.flag_z(),
            1 => self.flag_z(),
            2 => !self.flag_c(),
            3 => self.flag_c(),
            4 => !self.flag_pv(),
            5 => self.flag_pv(),
            6 => !self.flag_s(),
            _ => self.flag_s(),
        }
    }

    fn daa(&mut self) {
        let mut corr = 0u8;
        let n = self.f.contains(Flags::N);
        if self.f.contains(Flags::H) || (!n && (self.a & 0x0F) > 9) {
            corr |= 6;
        }
        if self.f.contains(Flags::C) || (!n && self.a > 0x99) {
            corr |= 0x60;
            self.set_c(true);
        }
        if n {
            self.a = self.a.wrapping_sub(corr);
        } else {
            self.a = self.a.wrapping_add(corr);
        }
        self.update_szpv_byte(self.a);
        self.set_h(false);
    }

    fn execute_cb(&mut self, op2: u8) -> Result<u32, String> {
        let x = (op2 >> 6) & 3;
        let y = (op2 >> 3) & 7;
        let z = op2 & 7;
        let val = self.reg8_read(z);
        match x {
            0 => {
                let result = match y {
                    0 => {
                        let c = val >> 7;
                        self.set_c(c != 0);
                        (val << 1) | c
                    } // RLC
                    1 => {
                        let c = val & 1;
                        self.set_c(c != 0);
                        (val >> 1) | (c << 7)
                    } // RRC
                    2 => {
                        let c = val >> 7;
                        let oc = if self.flag_c() { 1 } else { 0 };
                        self.set_c(c != 0);
                        (val << 1) | oc
                    } // RL
                    3 => {
                        let c = val & 1;
                        let oc = if self.flag_c() { 0x80 } else { 0 };
                        self.set_c(c != 0);
                        (val >> 1) | oc
                    } // RR
                    4 => {
                        self.set_c(val >> 7 != 0);
                        val << 1
                    } // SLA
                    5 => {
                        self.set_c(val & 1 != 0);
                        ((val as i8) >> 1) as u8
                    } // SRA
                    6 => {
                        self.set_c(val >> 7 != 0);
                        (val << 1) | 1
                    } // SLL (undocumented)
                    _ => {
                        self.set_c(val & 1 != 0);
                        val >> 1
                    } // SRL
                };
                self.update_szpv_byte(result);
                self.set_h(false);
                self.set_n(false);
                self.reg8_write(z, result);
            }
            1 => {
                // BIT
                let bit = val & (1 << y);
                self.set_z(bit == 0);
                self.set_h(true);
                self.set_n(false);
                self.set_s(y == 7 && bit != 0);
            }
            2 => {
                // RES
                self.reg8_write(z, val & !(1 << y));
            }
            _ => {
                // SET
                self.reg8_write(z, val | (1 << y));
            }
        }
        Ok(if z == 6 {
            if x == 1 { 12 } else { 15 }
        } else {
            8
        })
    }

    fn execute_ed(&mut self, op2: u8, io: &mut dyn IoPortHandler) -> Result<u32, String> {
        match op2 {
            0x44 | 0x4C | 0x54 | 0x5C | 0x64 | 0x6C | 0x74 | 0x7C => {
                self.a = 0u8.wrapping_sub(self.a);
                let is_neg = self.a != 0;
                self.set_c(is_neg);
                self.set_pv(self.a == 0x80);
                self.update_szpv_byte(self.a);
                self.set_n(true);
                Ok(8)
            }
            0x45 | 0x55 | 0x5D | 0x65 | 0x6D | 0x75 | 0x7D => {
                // RETN
                self.iff1 = self.iff2;
                self.pc = self.pop16();
                Ok(14)
            }
            0x4D => {
                // RETI
                self.iff1 = self.iff2;
                self.pc = self.pop16();
                Ok(14)
            }
            0x46 | 0x66 => {
                self.int_mode = IMode::M0;
                Ok(8)
            }
            0x56 | 0x76 => {
                self.int_mode = IMode::M1;
                Ok(8)
            }
            0x5E | 0x7E => {
                self.int_mode = IMode::M2;
                Ok(8)
            }
            0x47 => {
                self.i = self.a;
                Ok(9)
            }
            0x4F => {
                self.r = self.a;
                Ok(9)
            }
            0x57 => {
                self.a = self.i;
                Ok(9)
            }
            0x5F => {
                self.a = self.r;
                Ok(9)
            }
            // IN r,(C)
            0x40 | 0x48 | 0x50 | 0x58 | 0x60 | 0x68 | 0x78 => {
                let r = (op2 >> 3) & 7;
                let port = self.bc();
                let v = io.port_in(port);
                self.reg8_write(r, v);
                self.update_szpv_byte(v);
                self.set_h(false);
                self.set_n(false);
                Ok(12)
            }
            // OUT (C),r
            0x41 | 0x49 | 0x51 | 0x59 | 0x61 | 0x69 | 0x79 => {
                let r = (op2 >> 3) & 7;
                io.port_out(self.bc(), self.reg8_read(r));
                Ok(12)
            }
            // LDI
            0xA0 => {
                let v = self.mem.read8(self.hl());
                self.mem.write8(self.de(), v);
                self.set_hl(self.hl().wrapping_add(1));
                self.set_de(self.de().wrapping_add(1));
                let bc = self.bc().wrapping_sub(1);
                self.set_bc(bc);
                self.set_pv(bc != 0);
                self.set_h(false);
                self.set_n(false);
                Ok(16)
            }
            // LDD
            0xA8 => {
                let v = self.mem.read8(self.hl());
                self.mem.write8(self.de(), v);
                self.set_hl(self.hl().wrapping_sub(1));
                self.set_de(self.de().wrapping_sub(1));
                let bc = self.bc().wrapping_sub(1);
                self.set_bc(bc);
                self.set_pv(bc != 0);
                self.set_h(false);
                self.set_n(false);
                Ok(16)
            }
            // LDIR
            0xB0 => {
                loop {
                    let v = self.mem.read8(self.hl());
                    self.mem.write8(self.de(), v);
                    self.set_hl(self.hl().wrapping_add(1));
                    self.set_de(self.de().wrapping_add(1));
                    let bc = self.bc().wrapping_sub(1);
                    self.set_bc(bc);
                    if bc == 0 {
                        break;
                    }
                }
                self.set_pv(false);
                self.set_h(false);
                self.set_n(false);
                Ok(21)
            }
            // LDDR
            0xB8 => {
                loop {
                    let v = self.mem.read8(self.hl());
                    self.mem.write8(self.de(), v);
                    self.set_hl(self.hl().wrapping_sub(1));
                    self.set_de(self.de().wrapping_sub(1));
                    let bc = self.bc().wrapping_sub(1);
                    self.set_bc(bc);
                    if bc == 0 {
                        break;
                    }
                }
                self.set_pv(false);
                self.set_h(false);
                self.set_n(false);
                Ok(21)
            }
            _ => Err(format!("unimplemented ED opcode 0xED {op2:02X}")),
        }
    }

    fn execute_index(
        &mut self,
        op2: u8,
        is_dd: bool,
        io: &mut dyn IoPortHandler,
    ) -> Result<u32, String> {
        let (_idx, _other_idx) = if is_dd {
            (self.ix, self.iy)
        } else {
            (self.iy, self.ix)
        };
        match op2 {
            0x21 => {
                let lo = self.mem.read8(self.pc);
                self.pc = self.pc.wrapping_add(1);
                let hi = self.mem.read8(self.pc);
                self.pc = self.pc.wrapping_add(1);
                let nn = u16::from(lo) | (u16::from(hi) << 8);
                if is_dd {
                    self.ix = nn;
                } else {
                    self.iy = nn;
                }
                Ok(14)
            }
            0xE5 => {
                let v = if is_dd { self.ix } else { self.iy };
                self.push16(v);
                Ok(15)
            }
            0xE1 => {
                let v = self.pop16();
                if is_dd {
                    self.ix = v;
                } else {
                    self.iy = v;
                }
                Ok(14)
            }
            0xE9 => {
                self.pc = if is_dd { self.ix } else { self.iy };
                Ok(8)
            }
            0x46 | 0x4E | 0x56 | 0x5E | 0x66 | 0x6E | 0x7E => {
                let disp = self.mem.read8(self.pc) as i8;
                self.pc = self.pc.wrapping_add(1);
                let addr =
                    (if is_dd { self.ix } else { self.iy }).wrapping_add_signed(i16::from(disp));
                let v = self.mem.read8(addr);
                let r = (op2 >> 3) & 7;
                self.reg8_write(r, v);
                Ok(19)
            }
            0x70..=0x77 => {
                let z = op2 & 7;
                let disp = self.mem.read8(self.pc) as i8;
                self.pc = self.pc.wrapping_add(1);
                let addr =
                    (if is_dd { self.ix } else { self.iy }).wrapping_add_signed(i16::from(disp));
                let v = self.reg8_read(z);
                self.mem.write8(addr, v);
                Ok(19)
            }
            0x86 => {
                let disp = self.mem.read8(self.pc) as i8;
                self.pc = self.pc.wrapping_add(1);
                let addr =
                    (if is_dd { self.ix } else { self.iy }).wrapping_add_signed(i16::from(disp));
                let v = self.mem.read8(addr);
                self.alu8(0, v);
                Ok(19)
            }
            0xBE => {
                let disp = self.mem.read8(self.pc) as i8;
                self.pc = self.pc.wrapping_add(1);
                let addr =
                    (if is_dd { self.ix } else { self.iy }).wrapping_add_signed(i16::from(disp));
                let v = self.mem.read8(addr);
                self.alu8(7, v);
                Ok(19)
            }
            0xF9 => {
                self.sp = if is_dd { self.ix } else { self.iy };
                Ok(10)
            }
            _ => {
                // Unknown index prefix opcode: fall back
                let _ = io;
                self.execute(op2, self.pc, io)
            }
        }
    }
}

impl Default for Z80State {
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

    fn state() -> Z80State {
        Z80State::new()
    }
    fn null_io() -> NullPortHandler {
        NullPortHandler
    }

    fn run(data: &[u8]) -> Z80State {
        let mut s = state();
        s.mem.load(0x0000, data);
        s.step(&mut null_io()).unwrap();
        s
    }

    #[test]
    fn test_nop() {
        let s = run(&[0x00]);
        assert_eq!(s.pc, 1);
        assert_eq!(s.cycles, 4);
    }

    #[test]
    fn test_ld_bc_nn() {
        let s = run(&[0x01, 0x34, 0x12]);
        assert_eq!(s.bc(), 0x1234);
        assert_eq!(s.pc, 3);
    }

    #[test]
    fn test_ld_a_b() {
        let mut s = state();
        s.b = 0x42;
        s.mem.load(0, &[0x78]); // LD A,B
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.a, 0x42);
    }

    #[test]
    fn test_add_a_b() {
        let mut s = state();
        s.a = 10;
        s.b = 5;
        s.mem.load(0, &[0x80]); // ADD A,B
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.a, 15);
        assert!(!s.flag_c());
        assert!(!s.flag_z());
    }

    #[test]
    fn test_add_overflow_carry() {
        let mut s = state();
        s.a = 0xFF;
        s.b = 1;
        s.mem.load(0, &[0x80]);
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.a, 0);
        assert!(s.flag_z());
        assert!(s.flag_c());
    }

    #[test]
    fn test_sub_b() {
        let mut s = state();
        s.a = 10;
        s.b = 3;
        s.mem.load(0, &[0x90]); // SUB B
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.a, 7);
        assert!(!s.flag_c());
    }

    #[test]
    fn test_and_b() {
        let mut s = state();
        s.a = 0xFF;
        s.b = 0xAA;
        s.mem.load(0, &[0xA0]); // AND B
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.a, 0xAA);
    }

    #[test]
    fn test_or_b() {
        let mut s = state();
        s.a = 0x55;
        s.b = 0xAA;
        s.mem.load(0, &[0xB0]); // OR B
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.a, 0xFF);
    }

    #[test]
    fn test_xor_a_zero() {
        let mut s = state();
        s.a = 0xFF;
        s.mem.load(0, &[0xAF]); // XOR A
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.a, 0);
        assert!(s.flag_z());
    }

    #[test]
    fn test_jp_nn() {
        let mut s = state();
        s.mem.load(0, &[0xC3, 0x00, 0x10]); // JP 0x1000
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.pc, 0x1000);
    }

    #[test]
    fn test_call_ret() {
        let mut s = state();
        s.mem.load(0x0000, &[0xCD, 0x00, 0x10]); // CALL 0x1000
        s.mem.load(0x1000, &[0xC9]); // RET
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.pc, 0x1000);
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.pc, 0x0003);
    }

    #[test]
    fn test_push_pop() {
        let mut s = state();
        s.set_bc(0x1234);
        s.mem.load(0, &[0xC5, 0xC1]); // PUSH BC, POP BC
        s.step(&mut null_io()).unwrap();
        s.b = 0;
        s.c = 0;
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.bc(), 0x1234);
    }

    #[test]
    fn test_jr_taken() {
        let mut s = state();
        s.mem.load(0, &[0x18, 0x05]); // JR +5
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.pc, 7); // 2 + 5
    }

    #[test]
    fn test_jr_nz_not_taken() {
        let mut s = state();
        s.f.insert(Flags::Z);
        s.mem.load(0, &[0x20, 0x05]); // JR NZ,+5  (Z=1 → not taken)
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.pc, 2);
    }

    #[test]
    fn test_djnz_loop() {
        let mut s = state();
        s.b = 3;
        // DJNZ -2 at PC=0: target = 0+2+(-2) = 0 (self-loop)
        s.mem.load(0, &[0x10, 0xFE]);
        for _ in 0..3 {
            s.step(&mut null_io()).unwrap();
        }
        assert_eq!(s.b, 0);
        assert_eq!(s.pc, 2);
    }

    #[test]
    fn test_ex_af() {
        let mut s = state();
        s.a = 1;
        s.a2 = 2;
        s.mem.load(0, &[0x08]);
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.a, 2);
        assert_eq!(s.a2, 1);
    }

    #[test]
    fn test_exx() {
        let mut s = state();
        s.b = 1;
        s.b2 = 2;
        s.mem.load(0, &[0xD9]);
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.b, 2);
        assert_eq!(s.b2, 1);
    }

    #[test]
    fn test_di_ei() {
        let mut s = state();
        s.iff1 = true;
        s.mem.load(0, &[0xF3, 0xFB]); // DI, EI
        s.step(&mut null_io()).unwrap();
        assert!(!s.iff1);
        s.step(&mut null_io()).unwrap();
        assert!(s.iff1);
    }

    #[test]
    fn test_halt() {
        let mut s = state();
        s.mem.load(0, &[0x76]);
        s.step(&mut null_io()).unwrap();
        assert!(s.halted);
    }

    #[test]
    fn test_cb_rlc_b() {
        let mut s = state();
        s.b = 0x80;
        s.mem.load(0, &[0xCB, 0x00]); // RLC B
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.b, 0x01);
        assert!(s.flag_c());
    }

    #[test]
    fn test_cb_bit_3_b() {
        let mut s = state();
        s.b = 0x08; // bit 3 set
        s.mem.load(0, &[0xCB, 0x58]); // BIT 3,B → x=1, y=3, z=0
        s.step(&mut null_io()).unwrap();
        assert!(!s.flag_z()); // bit is set → Z=0
    }

    #[test]
    fn test_nmi_triggers() {
        let mut s = state();
        s.mem.load(0x0066, &[0x00]); // NOP at NMI handler
        s.nmi();
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.pc, 0x0067); // NMI handler executed NOP
        assert!(!s.iff1);
    }

    #[test]
    fn test_int_mode1() {
        let mut s = state();
        s.iff1 = true;
        s.int_mode = IMode::M1;
        s.mem.load(0x0038, &[0x00]); // NOP at IM1 handler
        s.int(0xFF);
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.pc, 0x0039);
    }

    #[test]
    fn test_shadow_registers_bc_de_hl() {
        let mut s = state();
        s.set_bc(0x1111);
        s.set_de(0x2222);
        s.set_hl(0x3333);
        s.b2 = 0xAA;
        s.c2 = 0xBB;
        s.mem.load(0, &[0xD9]); // EXX
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.b, 0xAA);
        assert_eq!(s.c, 0xBB);
    }

    #[test]
    fn test_ldir() {
        let mut s = state();
        s.mem.load(0x1000, &[1, 2, 3]);
        s.set_hl(0x1000);
        s.set_de(0x2000);
        s.set_bc(3);
        s.mem.load(0, &[0xED, 0xB0]); // LDIR
        s.step(&mut null_io()).unwrap();
        assert_eq!(s.mem.read8(0x2000), 1);
        assert_eq!(s.mem.read8(0x2001), 2);
        assert_eq!(s.mem.read8(0x2002), 3);
        assert_eq!(s.bc(), 0);
    }

    #[test]
    fn test_out_in_port() {
        struct MockIo {
            last_out: u8,
            supply: u8,
        }
        impl IoPortHandler for MockIo {
            fn port_in(&mut self, _p: u16) -> u8 {
                self.supply
            }
            fn port_out(&mut self, _p: u16, v: u8) {
                self.last_out = v;
            }
        }
        let mut io = MockIo {
            last_out: 0,
            supply: 0x42,
        };
        let mut s = state();
        s.a = 0xFF;
        s.mem.load(0, &[0xD3, 0x10, 0xDB, 0x10]); // OUT ($10),A then IN A,($10)
        s.step(&mut io).unwrap();
        assert_eq!(io.last_out, 0xFF);
        s.step(&mut io).unwrap();
        assert_eq!(s.a, 0x42);
    }
}
