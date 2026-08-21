//! M68000 software emulator.
//!
//! Provides `M68kState` (registers), `step()` for key instructions, `EffectiveAddress`
//! computation, and `M68kFlags`.

use crate::{CondCode, Size};
use std::collections::HashMap;

// ─── Flags ────────────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// M68000 Condition Code Register flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct M68kFlags: u8 {
        /// Carry flag (bit 0).
        const C = 1 << 0;
        /// Overflow flag (bit 1).
        const V = 1 << 1;
        /// Zero flag (bit 2).
        const Z = 1 << 2;
        /// Negative flag (bit 3).
        const N = 1 << 3;
        /// Extend flag (bit 4).
        const X = 1 << 4;
    }
}

impl M68kFlags {
    /// Encode as the low 5 bits of the CCR.
    #[must_use]
    pub const fn as_ccr(self) -> u8 {
        self.bits()
    }

    /// Decode from the low 5 bits of the CCR.
    #[must_use]
    pub const fn from_ccr(v: u8) -> Self {
        Self::from_bits_truncate(v)
    }

    /// Update N and Z for a 32-bit result, clearing V and C.
    pub fn update_nz32(&mut self, result: u32) {
        self.set(Self::N, (result >> 31) != 0);
        self.set(Self::Z, result == 0);
        self.remove(Self::V | Self::C);
    }

    /// Update N and Z for a 16-bit result.
    pub fn update_nz16(&mut self, result: u16) {
        self.set(Self::N, (result >> 15) != 0);
        self.set(Self::Z, result == 0);
        self.remove(Self::V | Self::C);
    }

    /// Update N and Z for an 8-bit result.
    pub fn update_nz8(&mut self, result: u8) {
        self.set(Self::N, (result >> 7) != 0);
        self.set(Self::Z, result == 0);
        self.remove(Self::V | Self::C);
    }

    /// Test the current flags against a `CondCode`.
    #[must_use]
    pub const fn test(self, cond: CondCode) -> bool {
        let c = self.contains(Self::C);
        let v = self.contains(Self::V);
        let z = self.contains(Self::Z);
        let n = self.contains(Self::N);
        match cond {
            CondCode::T => true,
            CondCode::F => false,
            CondCode::Hi => !c && !z,
            CondCode::Ls => c || z,
            CondCode::Cc => !c,
            CondCode::Cs => c,
            CondCode::Ne => !z,
            CondCode::Eq => z,
            CondCode::Vc => !v,
            CondCode::Vs => v,
            CondCode::Pl => !n,
            CondCode::Mi => n,
            CondCode::Ge => n == v,
            CondCode::Lt => n != v,
            CondCode::Gt => !z && (n == v),
            CondCode::Le => z || (n != v),
        }
    }
}

// ─── CPU State ────────────────────────────────────────────────────────────────

/// Emulated M68000 CPU state.
#[derive(Debug, Clone)]
pub struct M68kState {
    /// Data registers D0–D7.
    pub d: [u32; 8],
    /// Address registers A0–A7 (A7 = stack pointer).
    pub a: [u32; 8],
    /// Program counter.
    pub pc: u32,
    /// Status register (high byte) + CCR (low byte).
    pub sr: u16,
    /// Condition code register (cached from `sr`).
    pub flags: M68kFlags,
}

impl Default for M68kState {
    fn default() -> Self {
        Self {
            d: [0u32; 8],
            a: [0u32; 8],
            pc: 0,
            sr: 0x2700, // supervisor mode, all interrupts masked
            flags: M68kFlags::default(),
        }
    }
}

impl M68kState {
    /// Create a new state with PC set to `pc`.
    #[must_use]
    pub fn new(pc: u32) -> Self {
        Self {
            pc,
            ..Default::default()
        }
    }

    /// Stack pointer (A7).
    #[must_use]
    pub const fn sp(&self) -> u32 {
        self.a[7]
    }

    /// Set stack pointer.
    pub const fn set_sp(&mut self, v: u32) {
        self.a[7] = v;
    }

    /// Flush flags into the SR CCR byte.
    pub fn flush_flags(&mut self) {
        self.sr = (self.sr & 0xFF00) | u16::from(self.flags.as_ccr());
    }

    /// Load flags from the SR CCR byte.
    pub const fn load_flags(&mut self) {
        self.flags = M68kFlags::from_ccr(self.sr.to_le_bytes()[0]);
    }
}

// ─── Effective Address ────────────────────────────────────────────────────────

/// Resolved effective address for an instruction operand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectiveAddress {
    /// Data register Dn.
    DataReg(usize),
    /// Address register An.
    AddrReg(usize),
    /// Memory address.
    Memory(u32),
    /// Immediate value.
    Immediate(u32),
}

impl EffectiveAddress {
    /// Read a 32-bit value from this EA given the CPU state and memory.
    #[must_use]
    pub fn read32(&self, state: &M68kState, mem: &M68kMemory) -> u32 {
        match self {
            Self::DataReg(n) => state.d[*n],
            Self::AddrReg(n) => state.a[*n],
            Self::Immediate(v) => *v,
            Self::Memory(addr) => mem.read32(*addr),
        }
    }

    /// Write a 32-bit value to this EA.
    pub fn write32(&self, state: &mut M68kState, mem: &mut M68kMemory, val: u32) {
        match self {
            Self::DataReg(n) => state.d[*n] = val,
            Self::AddrReg(n) => state.a[*n] = val,
            Self::Memory(addr) => mem.write32(*addr, val),
            Self::Immediate(_) => {} // writes to immediate are no-ops
        }
    }

    /// Read a 16-bit value.
    #[must_use]
    pub fn read16(&self, state: &M68kState, mem: &M68kMemory) -> u16 {
        match self {
            Self::DataReg(n) => (state.d[*n] & 0xFFFF) as u16,
            Self::AddrReg(n) => (state.a[*n] & 0xFFFF) as u16,
            Self::Immediate(v) => (*v & 0xFFFF) as u16,
            Self::Memory(addr) => mem.read16(*addr),
        }
    }

    /// Write a 16-bit value (merges into low word for data registers).
    pub fn write16(&self, state: &mut M68kState, mem: &mut M68kMemory, val: u16) {
        match self {
            Self::DataReg(n) => {
                state.d[*n] = (state.d[*n] & 0xFFFF_0000) | u32::from(val);
            }
            Self::AddrReg(n) => {
                // Address registers sign-extend on write
                state.a[*n] = i32::from(val.cast_signed()).cast_unsigned();
            }
            Self::Memory(addr) => mem.write16(*addr, val),
            Self::Immediate(_) => {}
        }
    }

    /// Read an 8-bit value.
    #[must_use]
    pub fn read8(&self, state: &M68kState, mem: &M68kMemory) -> u8 {
        match self {
            Self::DataReg(n) => (state.d[*n] & 0xFF) as u8,
            Self::AddrReg(n) => (state.a[*n] & 0xFF) as u8,
            Self::Immediate(v) => (*v & 0xFF) as u8,
            Self::Memory(addr) => mem.read8(*addr),
        }
    }

    /// Return the memory address for a Memory EA, or the register value for
    /// an address register.  Used by JMP/JSR where the EA IS the target address.
    #[must_use]
    pub const fn address(&self, state: &M68kState) -> u32 {
        match self {
            Self::Memory(addr) => *addr,
            Self::AddrReg(n) => state.a[*n],
            Self::DataReg(n) => state.d[*n],
            Self::Immediate(v) => *v,
        }
    }

    /// Write an 8-bit value (merges into low byte for data registers).
    pub fn write8(&self, state: &mut M68kState, mem: &mut M68kMemory, val: u8) {
        match self {
            Self::DataReg(n) => {
                state.d[*n] = (state.d[*n] & 0xFFFF_FF00) | u32::from(val);
            }
            Self::AddrReg(n) => {
                state.a[*n] = (state.a[*n] & 0xFFFF_FF00) | u32::from(val);
            }
            Self::Memory(addr) => mem.write8(*addr, val),
            Self::Immediate(_) => {}
        }
    }
}

// ─── Memory model ─────────────────────────────────────────────────────────────

/// Flat M68000 memory model (24-bit address space).
#[derive(Debug, Clone, Default)]
pub struct M68kMemory {
    pages: HashMap<u32, Box<[u8; 4096]>>,
}

impl M68kMemory {
    /// Create an empty memory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn page_mut(&mut self, addr: u32) -> (&mut [u8; 4096], usize) {
        let addr = addr & 0x00FF_FFFF; // 24-bit mask
        let page_key = addr >> 12;
        let off = (addr & 0xFFF) as usize;
        let page = self
            .pages
            .entry(page_key)
            .or_insert_with(|| Box::new([0u8; 4096]));
        (page, off)
    }

    fn page(&self, addr: u32) -> Option<(&[u8; 4096], usize)> {
        let addr = addr & 0x00FF_FFFF;
        let page_key = addr >> 12;
        let off = (addr & 0xFFF) as usize;
        self.pages.get(&page_key).map(|p| (p.as_ref(), off))
    }

    /// Write a byte.
    pub fn write8(&mut self, addr: u32, val: u8) {
        let (page, off) = self.page_mut(addr);
        page[off] = val;
    }

    /// Write a big-endian 16-bit word.
    pub fn write16(&mut self, addr: u32, val: u16) {
        self.write8(addr, (val >> 8) as u8);
        self.write8(addr.wrapping_add(1), (val & 0xFF) as u8);
    }

    /// Write a big-endian 32-bit long.
    pub fn write32(&mut self, addr: u32, val: u32) {
        self.write16(addr, (val >> 16) as u16);
        self.write16(addr.wrapping_add(2), (val & 0xFFFF) as u16);
    }

    /// Write a byte slice starting at `addr`.
    pub fn write_bytes(&mut self, addr: u32, data: &[u8]) {
        let mut cur = addr;
        for &b in data {
            self.write8(cur, b);
            cur = cur.wrapping_add(1);
        }
    }

    /// Read a byte (returns 0 for unmapped pages).
    #[must_use]
    pub fn read8(&self, addr: u32) -> u8 {
        self.page(addr).map_or(0, |(p, off)| p[off])
    }

    /// Read a big-endian 16-bit word.
    #[must_use]
    pub fn read16(&self, addr: u32) -> u16 {
        (u16::from(self.read8(addr)) << 8) | u16::from(self.read8(addr.wrapping_add(1)))
    }

    /// Read a big-endian 32-bit long.
    #[must_use]
    pub fn read32(&self, addr: u32) -> u32 {
        (u32::from(self.read16(addr)) << 16) | u32::from(self.read16(addr.wrapping_add(2)))
    }

    /// Push a 32-bit value onto the stack (pre-decrement).
    pub fn push32(&mut self, state: &mut M68kState, val: u32) {
        state.a[7] = state.a[7].wrapping_sub(4);
        self.write32(state.a[7], val);
    }

    /// Pop a 32-bit value from the stack (post-increment).
    #[must_use]
    pub fn pop32(&mut self, state: &mut M68kState) -> u32 {
        let val = self.read32(state.a[7]);
        state.a[7] = state.a[7].wrapping_add(4);
        val
    }
}

// ─── Emulator ─────────────────────────────────────────────────────────────────

/// Error type for M68k emulation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmulatorError {
    /// Execution halted normally (e.g. RTS with empty stack, infinite loop guard).
    Halted,
    /// Unimplemented instruction at PC.
    UnimplementedInstruction(u32),
    /// Bus error reading/writing.
    BusError(u32),
    /// Reached step limit.
    StepLimitReached,
}

impl std::fmt::Display for EmulatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Halted => write!(f, "halted"),
            Self::UnimplementedInstruction(pc) => {
                write!(f, "unimplemented instruction at {pc:#010x}")
            }
            Self::BusError(addr) => write!(f, "bus error at {addr:#010x}"),
            Self::StepLimitReached => write!(f, "step limit reached"),
        }
    }
}

/// M68000 software emulator.
pub struct M68kEmulator {
    pub state: M68kState,
    pub mem: M68kMemory,
    /// Maximum number of steps before `StepLimitReached`.
    pub step_limit: u64,
    steps_taken: u64,
}

impl M68kEmulator {
    /// Create a new emulator with the given initial PC and 512 KiB RAM.
    #[must_use]
    pub fn new(pc: u32) -> Self {
        let mut mem = M68kMemory::new();
        // Initialize the supervisor stack to 0x80000.
        let mut state = M68kState::new(pc);
        state.a[7] = 0x0008_0000;
        // Write a sentinel "HALT" word at the top of the initial stack
        // so that an RTS from the top level terminates cleanly.
        mem.write16(0x0008_0000, 0x4E71); // NOP as sentinel
        Self {
            state,
            mem,
            step_limit: 1_000_000,
            steps_taken: 0,
        }
    }

    /// Fetch a 16-bit instruction word at PC and advance PC by 2.
    fn fetch_word(&mut self) -> u16 {
        let w = self.mem.read16(self.state.pc);
        self.state.pc = self.state.pc.wrapping_add(2);
        w
    }

    /// Fetch a 32-bit instruction extension at PC and advance PC by 4.
    fn fetch_long(&mut self) -> u32 {
        let hi = u32::from(self.fetch_word());
        let lo = u32::from(self.fetch_word());
        (hi << 16) | lo
    }

    /// Resolve an effective address from mode/reg fields (reads extension words).
    fn resolve_ea(&mut self, mode: u8, reg: u8, size: Size) -> EffectiveAddress {
        match mode {
            0 => EffectiveAddress::DataReg(reg as usize),
            1 => EffectiveAddress::AddrReg(reg as usize),
            2 => EffectiveAddress::Memory(self.state.a[reg as usize]),
            3 => {
                // Address register indirect with post-increment
                let addr = self.state.a[reg as usize];
                let inc = if reg == 7 && size == Size::Byte {
                    2
                } else {
                    u32::try_from(size.bytes()).unwrap_or(4)
                };
                self.state.a[reg as usize] = addr.wrapping_add(inc);
                EffectiveAddress::Memory(addr)
            }
            4 => {
                // Address register indirect with pre-decrement
                let dec = if reg == 7 && size == Size::Byte {
                    2
                } else {
                    u32::try_from(size.bytes()).unwrap_or(4)
                };
                self.state.a[reg as usize] = self.state.a[reg as usize].wrapping_sub(dec);
                EffectiveAddress::Memory(self.state.a[reg as usize])
            }
            5 => {
                // Address register indirect with 16-bit displacement
                let disp = i32::from(self.fetch_word().cast_signed());
                let addr = self.state.a[reg as usize].wrapping_add_signed(disp);
                EffectiveAddress::Memory(addr)
            }
            6 => {
                // Address register indirect with index (brief extension word)
                let ext = self.fetch_word();
                let idx_reg = usize::from((ext >> 12) & 7);
                let idx_raw = if ext & 0x8000 != 0 {
                    self.state.a[idx_reg]
                } else {
                    self.state.d[idx_reg]
                };
                let idx = if ext & 0x0800 != 0 {
                    idx_raw.cast_signed()
                } else {
                    // Index registers use only the low word in .W mode; select the
                    // bytes instead of narrowing so the discard is explicit.
                    i32::from(i16::from_le_bytes([idx_raw.to_le_bytes()[0], idx_raw.to_le_bytes()[1]]))
                };
                let disp = i32::from(ext.to_le_bytes()[0].cast_signed());
                let addr = self.state.a[reg as usize]
                    .wrapping_add_signed(disp)
                    .wrapping_add_signed(idx);
                EffectiveAddress::Memory(addr)
            }
            7 => match reg {
                0 => {
                    // Absolute short
                    let abs = self.fetch_word();
                    EffectiveAddress::Memory(i32::from(abs.cast_signed()).cast_unsigned())
                }
                1 => {
                    // Absolute long
                    let abs = self.fetch_long();
                    EffectiveAddress::Memory(abs)
                }
                2 => {
                    // PC-relative displacement
                    let base_pc = self.state.pc;
                    let disp = i32::from(self.fetch_word().cast_signed());
                    let addr = base_pc.wrapping_add_signed(disp);
                    EffectiveAddress::Memory(addr)
                }
                4 => {
                    // Immediate
                    let val = match size {
                        Size::Byte => u32::from(self.fetch_word()) & 0xFF,
                        Size::Word => u32::from(self.fetch_word()),
                        _ => self.fetch_long(),
                    };
                    EffectiveAddress::Immediate(val)
                }
                _ => EffectiveAddress::Memory(0),
            },
            _ => EffectiveAddress::Memory(0),
        }
    }

    /// Sign-extend the low 16 bits of `v` to a full 32-bit value.
    fn sext16(v: u32) -> u32 {
        i32::from(((v & 0xFFFF) as u16).cast_signed()).cast_unsigned()
    }

    /// Decode the common EA / register fields from an opcode word.
    const fn decode_fields(word: u16) -> (u8, u8, usize, u8) {
        (
            ((word >> 3) & 7) as u8,
            (word & 7) as u8,
            ((word >> 9) & 7) as usize,
            ((word >> 6) & 3) as u8,
        )
    }

    /// Execute one instruction.
    ///
    /// # Errors
    /// Returns `EmulatorError` on unimplemented instruction or step limit.
    pub fn step(&mut self) -> Result<(), EmulatorError> {
        if self.steps_taken >= self.step_limit {
            return Err(EmulatorError::StepLimitReached);
        }
        self.steps_taken += 1;

        let pc_before = self.state.pc;
        let word = self.fetch_word();
        match (word >> 12) as u8 {
            0x0 => self.op_group0(word),
            0x1..=0x3 => self.op_move(word),
            0x4 => self.op_group4(word, pc_before)?,
            0x5 => self.op_group5(word),
            0x6 => self.op_branch(word),
            0x7 => self.op_moveq(word),
            0x8 => self.op_or_div(word),
            0x9 => self.op_sub(word),
            0xB => self.op_cmp_eor(word),
            0xC => self.op_and_mul(word),
            0xD => self.op_add(word),
            0xE => self.op_shift(word),
            _ => {
                self.state.pc = pc_before;
                return Err(EmulatorError::UnimplementedInstruction(pc_before));
            }
        }

        self.state.flush_flags();
        Ok(())
    }

    /// MOVE / MOVEA (0x1/0x2/0x3).
    fn op_move(&mut self, word: u16) {
        let (ea_mode, ea_reg, _, _) = Self::decode_fields(word);
        let move_sz = match (word >> 12) & 0xF {
            0x1 => Size::Byte,
            0x3 => Size::Word,
            _ => Size::Long,
        };
        let src_ea = self.resolve_ea(ea_mode, ea_reg, move_sz);
        let dst_mode = ((word >> 6) & 7) as u8;
        let dst_reg = ((word >> 9) & 7) as u8;
        let dst_ea = self.resolve_ea(dst_mode, dst_reg, move_sz);
        match move_sz {
            Size::Byte => {
                let v = src_ea.read8(&self.state, &self.mem);
                dst_ea.write8(&mut self.state, &mut self.mem, v);
                if dst_mode != 1 {
                    self.state.flags.update_nz8(v);
                }
            }
            Size::Word => {
                let v = src_ea.read16(&self.state, &self.mem);
                dst_ea.write16(&mut self.state, &mut self.mem, v);
                if dst_mode != 1 {
                    self.state.flags.update_nz16(v);
                }
            }
            _ => {
                let v = src_ea.read32(&self.state, &self.mem);
                dst_ea.write32(&mut self.state, &mut self.mem, v);
                if dst_mode != 1 {
                    self.state.flags.update_nz32(v);
                }
            }
        }
    }

    /// Group 0 (immediate ops / BTST).
    fn op_group0(&mut self, word: u16) {
        let (ea_mode, ea_reg, reg_field, _) = Self::decode_fields(word);
        // BTST Dn (reg): bit test
        if (word & 0x0FC0) == 0x0100 {
            let bit_num = self.state.d[reg_field] & 31;
            let ea = self.resolve_ea(ea_mode, ea_reg, Size::Long);
            let v = ea.read32(&self.state, &self.mem);
            self.state.flags.set(M68kFlags::Z, (v >> bit_num) & 1 == 0);
        }
        // MOVEQ-like ADDQ/SUBQ: decoded in group 5, fall through
    }

    /// Group 4 unary ALU ops (CLR / NEG / NOT / TST).
    fn op_group4_unary(&mut self, word: u16) {
        let (ea_mode, ea_reg, _, sz_bits) = Self::decode_fields(word);
        let sz = Size::from_bits2(sz_bits);
        let ea = self.resolve_ea(ea_mode, ea_reg, sz);
        match word & 0xFF00 {
            0x4200 => {
                // CLR
                match sz {
                    Size::Byte => ea.write8(&mut self.state, &mut self.mem, 0),
                    Size::Word => ea.write16(&mut self.state, &mut self.mem, 0),
                    _ => ea.write32(&mut self.state, &mut self.mem, 0),
                }
                self.state.flags.update_nz32(0);
            }
            0x4400 => {
                // NEG
                let v = ea.read32(&self.state, &self.mem);
                let r = (!v).wrapping_add(1);
                ea.write32(&mut self.state, &mut self.mem, r);
                self.state.flags.update_nz32(r);
                self.state.flags.set(M68kFlags::C, r != 0);
                self.state.flags.set(M68kFlags::X, r != 0);
            }
            0x4600 => {
                // NOT
                let v = ea.read32(&self.state, &self.mem);
                let r = !v;
                ea.write32(&mut self.state, &mut self.mem, r);
                self.state.flags.update_nz32(r);
            }
            _ => {
                // TST
                let v = ea.read32(&self.state, &self.mem);
                self.state.flags.update_nz32(v);
            }
        }
    }

    /// Group 4 (misc / control flow).
    fn op_group4(&mut self, word: u16, pc_before: u32) -> Result<(), EmulatorError> {
        let (ea_mode, ea_reg, reg_field, sz_bits) = Self::decode_fields(word);
        let masked = word & 0xFF00;
        if masked == 0x4200
            || ((masked == 0x4400 || masked == 0x4600 || masked == 0x4A00) && sz_bits < 3)
        {
            self.op_group4_unary(word);
            return Ok(());
        }
        match word {
            0x4E71 => {} // NOP
            0x4E75 => {
                // RTS
                let ret_addr = self.mem.pop32(&mut self.state);
                self.state.pc = ret_addr;
            }
            0x4E73 => {
                // RTE: pop SR then PC
                let new_sr = self.mem.read16(self.state.a[7]);
                self.state.a[7] = self.state.a[7].wrapping_add(2);
                let new_pc = self.mem.pop32(&mut self.state);
                self.state.sr = new_sr;
                self.state.pc = new_pc;
                self.state.load_flags();
            }
            _ if (word & 0xFFC0) == 0x4E80 => {
                // JSR ea — target is the EA *address*, not the value stored there
                let ea = self.resolve_ea(ea_mode, ea_reg, Size::Long);
                let target = ea.address(&self.state);
                let ret = self.state.pc;
                self.mem.push32(&mut self.state, ret);
                self.state.pc = target;
            }
            _ if (word & 0xFFC0) == 0x4EC0 => {
                // JMP ea — target is the EA *address*, not the value stored there
                let ea = self.resolve_ea(ea_mode, ea_reg, Size::Long);
                self.state.pc = ea.address(&self.state);
            }
            _ if (word & 0xFFF8) == 0x4E50 => {
                // LINK An, #disp
                let an = (word & 7) as usize;
                let disp = i32::from(self.fetch_word().cast_signed());
                // Push An
                let an_val = self.state.a[an];
                self.mem.push32(&mut self.state, an_val);
                // An = SP
                self.state.a[an] = self.state.a[7];
                // SP = SP + disp
                self.state.a[7] = self.state.a[7].wrapping_add_signed(disp);
            }
            _ if (word & 0xFFF8) == 0x4E58 => {
                // UNLK An
                let an = (word & 7) as usize;
                self.state.a[7] = self.state.a[an];
                self.state.a[an] = self.mem.pop32(&mut self.state);
            }
            _ if (word & 0xFFC0) == 0x4840 && ea_mode != 0 => {
                // PEA ea
                let ea = self.resolve_ea(ea_mode, ea_reg, Size::Long);
                let addr = match &ea {
                    EffectiveAddress::Memory(a) => *a,
                    _ => 0,
                };
                self.mem.push32(&mut self.state, addr);
            }
            _ if (word & 0xFFF8) == 0x4840 => {
                // SWAP Dn
                let dn = (word & 7) as usize;
                let v = self.state.d[dn];
                self.state.d[dn] = v.rotate_right(16);
                self.state.flags.update_nz32(self.state.d[dn]);
            }
            _ if (word & 0xF1C0) == 0x41C0 => {
                // LEA ea, An
                let ea = self.resolve_ea(ea_mode, ea_reg, Size::Long);
                let addr = match &ea {
                    EffectiveAddress::Memory(a) => *a,
                    _ => 0,
                };
                self.state.a[reg_field] = addr;
            }
            _ => {
                self.state.pc = pc_before;
                return Err(EmulatorError::UnimplementedInstruction(pc_before));
            }
        }
        Ok(())
    }

    /// ADDQ / SUBQ / `Scc` / `DBcc` (0x5).
    fn op_group5(&mut self, word: u16) {
        let (ea_mode, ea_reg, _, sz_bits) = Self::decode_fields(word);
        let sz = Size::from_bits2(sz_bits);
        if (word & 0xF0F8) == 0x50C8 {
            // DBcc Dn, disp
            let cond = CondCode::from_bits(((word >> 8) & 0xF) as u8);
            let dn = (word & 7) as usize;
            let disp = i32::from(self.fetch_word().cast_signed());
            if !self.state.flags.test(cond) {
                let counter = ((self.state.d[dn] & 0xFFFF) as u16).wrapping_sub(1);
                self.state.d[dn] = (self.state.d[dn] & 0xFFFF_0000) | u32::from(counter);
                if counter != 0xFFFF {
                    // branch taken
                    self.state.pc = self.state.pc.wrapping_add_signed(disp);
                }
            }
        } else if (word & 0x00C0) == 0x00C0 {
            // Scc
            let cond = CondCode::from_bits(((word >> 8) & 0xF) as u8);
            let ea = self.resolve_ea(ea_mode, ea_reg, Size::Byte);
            let val: u8 = if self.state.flags.test(cond) {
                0xFF
            } else {
                0x00
            };
            ea.write8(&mut self.state, &mut self.mem, val);
        } else {
            // ADDQ / SUBQ
            let data = u32::from((word >> 9) & 7);
            let data_val = if data == 0 { 8 } else { data };
            let is_sub = (word & 0x0100) != 0;
            let ea = self.resolve_ea(ea_mode, ea_reg, sz);
            let v = ea.read32(&self.state, &self.mem);
            let r = if is_sub {
                v.wrapping_sub(data_val)
            } else {
                v.wrapping_add(data_val)
            };
            ea.write32(&mut self.state, &mut self.mem, r);
            if ea_mode != 1 {
                self.state.flags.update_nz32(r);
            }
        }
    }

    /// Bcc / BSR / BRA (0x6).
    fn op_branch(&mut self, word: u16) {
        let cond = (word >> 8) & 0xF;
        let disp8 = ((word & 0xFF) as u8).cast_signed();
        let disp = if disp8 == 0 {
            i32::from(self.fetch_word().cast_signed()) - 2
        } else {
            i32::from(disp8)
        };
        match cond {
            0 => {
                // BRA
                self.state.pc = self.state.pc.wrapping_add_signed(disp);
            }
            1 => {
                // BSR
                let ret = self.state.pc;
                self.mem.push32(&mut self.state, ret);
                self.state.pc = self.state.pc.wrapping_add_signed(disp);
            }
            _ => {
                // Bcc
                let cc = CondCode::from_bits((cond & 0xF) as u8);
                if self.state.flags.test(cc) {
                    self.state.pc = self.state.pc.wrapping_add_signed(disp);
                }
            }
        }
    }

    /// MOVEQ (0x7).
    fn op_moveq(&mut self, word: u16) {
        let (_, _, reg_field, _) = Self::decode_fields(word);
        let data = i32::from(((word & 0xFF) as u8).cast_signed()).cast_unsigned();
        self.state.d[reg_field] = data;
        self.state.flags.update_nz32(data);
    }

    /// DIVU / DIVS / OR / SBCD (0x8).
    fn op_or_div(&mut self, word: u16) {
        let (ea_mode, ea_reg, reg_field, sz_bits) = Self::decode_fields(word);
        let sz = Size::from_bits2(sz_bits);
        if (word & 0x01C0) == 0x00C0 {
            let is_divs = (word & 0x0100) != 0;
            let ea = self.resolve_ea(ea_mode, ea_reg, Size::Word);
            let divisor = ea.read16(&self.state, &self.mem);
            let dividend = self.state.d[reg_field];
            if divisor == 0 {
                // Divide-by-zero trap (simplified: just set V)
                self.state.flags.insert(M68kFlags::V);
            } else if is_divs {
                let q = dividend.cast_signed() / i32::from(divisor.cast_signed());
                let r = dividend.cast_signed() % i32::from(divisor.cast_signed());
                self.state.d[reg_field] = (r.cast_unsigned() << 16) | (q.cast_unsigned() & 0xFFFF);
                self.state
                    .flags
                    .update_nz16((q.cast_unsigned() & 0xFFFF) as u16);
            } else {
                let q = dividend / u32::from(divisor);
                let r = dividend % u32::from(divisor);
                self.state.d[reg_field] = (r << 16) | (q & 0xFFFF);
                self.state.flags.update_nz16((q & 0xFFFF) as u16);
            }
        } else {
            // OR
            let ea = self.resolve_ea(ea_mode, ea_reg, sz);
            let v = ea.read32(&self.state, &self.mem);
            let r = v | self.state.d[reg_field];
            if (word & 0x0100) != 0 {
                ea.write32(&mut self.state, &mut self.mem, r);
            } else {
                self.state.d[reg_field] = r;
            }
            self.state.flags.update_nz32(r);
        }
    }

    /// SUB / SUBA / SUBX (0x9).
    fn op_sub(&mut self, word: u16) {
        let (ea_mode, ea_reg, reg_field, sz_bits) = Self::decode_fields(word);
        let sz = Size::from_bits2(sz_bits);
        let ea = self.resolve_ea(ea_mode, ea_reg, sz);
        let v = ea.read32(&self.state, &self.mem);
        if (word & 0x00C0) == 0x00C0 {
            // SUBA
            let ext = if (word & 0x0100) != 0 {
                v
            } else {
                Self::sext16(v)
            };
            self.state.a[reg_field] = self.state.a[reg_field].wrapping_sub(ext);
        } else if (word & 0x0100) != 0 {
            let r = v.wrapping_sub(self.state.d[reg_field]);
            ea.write32(&mut self.state, &mut self.mem, r);
            let borrow = v < self.state.d[reg_field];
            self.state.flags.set(M68kFlags::C, borrow);
            self.state.flags.set(M68kFlags::X, borrow);
            self.state.flags.update_nz32(r);
        } else {
            let r = self.state.d[reg_field].wrapping_sub(v);
            let borrow = self.state.d[reg_field] < v;
            self.state.flags.set(M68kFlags::C, borrow);
            self.state.flags.set(M68kFlags::X, borrow);
            self.state.d[reg_field] = r;
            self.state.flags.update_nz32(r);
        }
    }

    /// CMP / CMPA / EOR (0xB).
    fn op_cmp_eor(&mut self, word: u16) {
        let (ea_mode, ea_reg, reg_field, sz_bits) = Self::decode_fields(word);
        let sz = Size::from_bits2(sz_bits);
        let ea = self.resolve_ea(ea_mode, ea_reg, sz);
        let v = ea.read32(&self.state, &self.mem);
        if (word & 0x00C0) == 0x00C0 {
            // CMPA
            let ext = if (word & 0x0100) != 0 {
                v
            } else {
                Self::sext16(v)
            };
            let r = self.state.a[reg_field].wrapping_sub(ext);
            self.state
                .flags
                .set(M68kFlags::C, self.state.a[reg_field] < ext);
            self.state.flags.update_nz32(r);
        } else if (word & 0x0100) != 0 {
            // EOR
            let r = v ^ self.state.d[reg_field];
            ea.write32(&mut self.state, &mut self.mem, r);
            self.state.flags.update_nz32(r);
        } else {
            // CMP
            let r = self.state.d[reg_field].wrapping_sub(v);
            self.state
                .flags
                .set(M68kFlags::C, self.state.d[reg_field] < v);
            self.state.flags.update_nz32(r);
        }
    }

    /// AND / MULU / MULS (0xC).
    fn op_and_mul(&mut self, word: u16) {
        let (ea_mode, ea_reg, reg_field, sz_bits) = Self::decode_fields(word);
        let sz = Size::from_bits2(sz_bits);
        if (word & 0x00C0) == 0x00C0 {
            let is_muls = (word & 0x0100) != 0;
            let ea = self.resolve_ea(ea_mode, ea_reg, Size::Word);
            let v = ea.read16(&self.state, &self.mem);
            let r = if is_muls {
                i32::from(((self.state.d[reg_field] & 0xFFFF) as u16).cast_signed())
                    .wrapping_mul(i32::from(v.cast_signed()))
                    .cast_unsigned()
            } else {
                (self.state.d[reg_field] & 0xFFFF).wrapping_mul(u32::from(v))
            };
            self.state.d[reg_field] = r;
            self.state.flags.update_nz32(r);
        } else {
            // AND
            let ea = self.resolve_ea(ea_mode, ea_reg, sz);
            let v = ea.read32(&self.state, &self.mem);
            let r = v & self.state.d[reg_field];
            if (word & 0x0100) != 0 {
                ea.write32(&mut self.state, &mut self.mem, r);
            } else {
                self.state.d[reg_field] = r;
            }
            self.state.flags.update_nz32(r);
        }
    }

    /// ADD / ADDA / ADDX (0xD).
    fn op_add(&mut self, word: u16) {
        let (ea_mode, ea_reg, reg_field, sz_bits) = Self::decode_fields(word);
        let sz = Size::from_bits2(sz_bits);
        let ea = self.resolve_ea(ea_mode, ea_reg, sz);
        let v = ea.read32(&self.state, &self.mem);
        if (word & 0x00C0) == 0x00C0 {
            // ADDA
            let ext = if (word & 0x0100) != 0 {
                v
            } else {
                Self::sext16(v)
            };
            self.state.a[reg_field] = self.state.a[reg_field].wrapping_add(ext);
        } else if (word & 0x0100) != 0 {
            let r = v.wrapping_add(self.state.d[reg_field]);
            ea.write32(&mut self.state, &mut self.mem, r);
            self.state.flags.update_nz32(r);
            self.state.flags.set(M68kFlags::C, r < v);
            self.state.flags.set(M68kFlags::X, r < v);
        } else {
            let dn = self.state.d[reg_field];
            let r = dn.wrapping_add(v);
            self.state.d[reg_field] = r;
            self.state.flags.update_nz32(r);
            self.state.flags.set(M68kFlags::C, r < dn);
            self.state.flags.set(M68kFlags::X, r < dn);
        }
    }

    /// Shift / Rotate (0xE).
    fn op_shift(&mut self, word: u16) {
        let (ea_mode, ea_reg, _, _) = Self::decode_fields(word);
        let direction = (word & 0x0100) != 0;
        let type_bits = (word >> 3) & 3;
        let count_or_reg = u32::from((word >> 9) & 7);
        let use_reg = (word & 0x0020) != 0;
        let dn = (word & 7) as usize;
        let count = if use_reg {
            self.state.d[count_or_reg as usize] & 63
        } else if count_or_reg == 0 {
            8
        } else {
            count_or_reg
        };
        let v = self.state.d[dn];
        let r = match (type_bits, direction) {
            // ASR
            (0, false) => v
                .cast_signed()
                .checked_shr(count)
                .unwrap_or_else(|| if v.cast_signed() < 0 { -1 } else { 0 })
                .cast_unsigned(),
            // ASL / LSL
            (0 | 1, true) => v.checked_shl(count).unwrap_or(0),
            // LSR
            (1, false) => v.checked_shr(count).unwrap_or(0),
            // ROR
            (_, false) => v.rotate_right(count & 31),
            // ROL
            _ => v.rotate_left(count & 31),
        };
        if (word & 0x00C0) == 0x00C0 {
            // memory shift — EA word
            let ea = self.resolve_ea(ea_mode, ea_reg, Size::Word);
            let v16 = ea.read16(&self.state, &self.mem);
            let r16 = if direction { v16 << 1 } else { v16 >> 1 };
            ea.write16(&mut self.state, &mut self.mem, r16);
            self.state.flags.update_nz16(r16);
        } else {
            self.state.d[dn] = r;
            self.state.flags.update_nz32(r);
        }
    }

    /// Run until RTS unwinds past the initial frame, step limit, or error.
    ///
    /// # Errors
    /// Returns `EmulatorError` on unimplemented instruction or step limit.
    pub fn run(&mut self) -> Result<(), EmulatorError> {
        let initial_sp = self.state.a[7];
        loop {
            self.step()?;
            // Detect return past initial frame
            if self.state.a[7] >= initial_sp + 4 {
                return Ok(());
            }
        }
    }

    /// Steps taken so far.
    #[must_use]
    pub const fn steps_taken(&self) -> u64 {
        self.steps_taken
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_emu(code: &[u8]) -> M68kEmulator {
        let base = 0x0000_1000_u32;
        let mut emu = M68kEmulator::new(base);
        emu.mem.write_bytes(base, code);
        emu
    }

    #[test]
    fn test_nop() {
        let mut emu = make_emu(&[0x4E, 0x71]); // NOP
        assert!(emu.step().is_ok());
        assert_eq!(emu.state.pc, 0x0000_1002);
    }

    #[test]
    fn test_moveq() {
        let mut emu = make_emu(&[0x70, 0x42]); // MOVEQ #0x42, D0
        emu.step().unwrap();
        assert_eq!(emu.state.d[0], 0x42);
        assert!(!emu.state.flags.contains(M68kFlags::Z));
        assert!(!emu.state.flags.contains(M68kFlags::N));
    }

    #[test]
    fn test_moveq_negative() {
        let mut emu = make_emu(&[0x70, 0xFF]); // MOVEQ #-1, D0
        emu.step().unwrap();
        assert_eq!(emu.state.d[0], 0xFFFF_FFFF);
        assert!(emu.state.flags.contains(M68kFlags::N));
    }

    #[test]
    fn test_move_long_d0_d1() {
        // MOVE.L D0,D1 = 0x2200
        let mut emu = make_emu(&[0x22, 0x00]);
        emu.state.d[0] = 0xDEAD_BEEF;
        emu.step().unwrap();
        assert_eq!(emu.state.d[1], 0xDEAD_BEEF);
    }

    #[test]
    fn test_add() {
        // ADDQ.L #1, D0
        let mut emu = make_emu(&[0x52, 0x80]);
        emu.state.d[0] = 10;
        emu.step().unwrap();
        assert_eq!(emu.state.d[0], 11);
    }

    #[test]
    fn test_sub() {
        // SUBQ.L #1, D0
        let mut emu = make_emu(&[0x53, 0x80]);
        emu.state.d[0] = 10;
        emu.step().unwrap();
        assert_eq!(emu.state.d[0], 9);
    }

    #[test]
    fn test_jsr_rts() {
        // JSR 0x001010; RTS
        // JSR (0x001010).L: 4E B9 00 00 10 10
        // RTS at 0x001006: 4E 75
        // NOP at 0x001010: 4E 71; RTS: 4E 75
        let mut code = [0u8; 32];
        code[0] = 0x4E;
        code[1] = 0xB9;
        code[2] = 0x00;
        code[3] = 0x00;
        code[4] = 0x10;
        code[5] = 0x10; // target = 0x1010
        code[6] = 0x4E;
        code[7] = 0x75; // RTS at 0x1006
        // Place NOP and RTS at 0x1010 (offset 0x10 from base 0x1000)
        code[0x10] = 0x4E;
        code[0x11] = 0x71; // NOP
        code[0x12] = 0x4E;
        code[0x13] = 0x75; // RTS
        let mut emu = make_emu(&code);
        // JSR
        emu.step().unwrap();
        assert_eq!(emu.state.pc, 0x0000_1010);
        // NOP
        emu.step().unwrap();
        // RTS at 0x001012 → returns to 0x001006
        emu.step().unwrap();
        assert_eq!(emu.state.pc, 0x0000_1006);
    }

    #[test]
    fn test_bra_forward() {
        // BRA.B +2 (skip one NOP word): 60 02; NOP; MOVEQ #1,D0; MOVEQ #2,D1
        let code = [0x60u8, 0x02, 0x4E, 0x71, 0x72, 0x01, 0x74, 0x02];
        let mut emu = make_emu(&code);
        emu.step().unwrap(); // BRA +2 → jumps to MOVEQ
        assert_eq!(emu.state.pc, 0x0000_1004); // skipped NOP at 0x1002
    }

    #[test]
    fn test_beq_taken() {
        // BEQ +4; NOP; MOVEQ #7,D0
        let code = [0x67u8, 0x02, 0x4E, 0x71, 0x70, 0x07];
        let mut emu = make_emu(&code);
        emu.state.flags.insert(M68kFlags::Z);
        emu.step().unwrap();
        assert_eq!(emu.state.pc, 0x0000_1004);
    }

    #[test]
    fn test_beq_not_taken() {
        let code = [0x67u8, 0x02, 0x4E, 0x71, 0x70, 0x07];
        let mut emu = make_emu(&code);
        emu.state.flags.remove(M68kFlags::Z);
        emu.step().unwrap();
        assert_eq!(emu.state.pc, 0x0000_1002); // fell through
    }

    #[test]
    fn test_clr_d0() {
        // CLR.L D0 = 42 80
        let mut emu = make_emu(&[0x42, 0x80]);
        emu.state.d[0] = 0xDEAD;
        emu.step().unwrap();
        assert_eq!(emu.state.d[0], 0);
        assert!(emu.state.flags.contains(M68kFlags::Z));
    }

    #[test]
    fn test_neg_d0() {
        // NEG.L D0 = 44 80
        let mut emu = make_emu(&[0x44, 0x80]);
        emu.state.d[0] = 5;
        emu.step().unwrap();
        assert_eq!(emu.state.d[0], 0xFFFF_FFFB);
        assert!(emu.state.flags.contains(M68kFlags::N));
    }

    #[test]
    fn test_not_d0() {
        // NOT.L D0 = 46 80
        let mut emu = make_emu(&[0x46, 0x80]);
        emu.state.d[0] = 0xFFFF_FFFF;
        emu.step().unwrap();
        assert_eq!(emu.state.d[0], 0);
        assert!(emu.state.flags.contains(M68kFlags::Z));
    }

    #[test]
    fn test_tst_d0() {
        // TST.L D0 = 4A 80
        let mut emu = make_emu(&[0x4A, 0x80]);
        emu.state.d[0] = 0;
        emu.step().unwrap();
        assert!(emu.state.flags.contains(M68kFlags::Z));
    }

    #[test]
    fn test_muls() {
        // MULS.W D1,D0: 0xC1C1
        let mut emu = make_emu(&[0xC1, 0xC1]);
        emu.state.d[0] = 7;
        emu.state.d[1] = 6;
        emu.step().unwrap();
        assert_eq!(emu.state.d[0] & 0xFFFF, 42);
    }

    #[test]
    fn test_mulu() {
        // MULU.W D1,D0: 0xC0C1
        let mut emu = make_emu(&[0xC0, 0xC1]);
        emu.state.d[0] = 100;
        emu.state.d[1] = 3;
        emu.step().unwrap();
        assert_eq!(emu.state.d[0] & 0xFFFF, 300);
    }

    #[test]
    fn test_divu() {
        // DIVU.W D1,D0: 0x80C1
        let mut emu = make_emu(&[0x80, 0xC1]);
        emu.state.d[0] = 100;
        emu.state.d[1] = 4;
        emu.step().unwrap();
        let quotient = emu.state.d[0] & 0xFFFF;
        assert_eq!(quotient, 25);
    }

    #[test]
    fn test_link_unlk() {
        // LINK A6, #-16 = 4E 56 FF F0; UNLK A6 = 4E 5E
        let mut emu = make_emu(&[0x4E, 0x56, 0xFF, 0xF0, 0x4E, 0x5E]);
        emu.state.a[6] = 0xABCD;
        let sp_before = emu.state.a[7];
        emu.step().unwrap();
        assert_eq!(emu.state.a[6], sp_before - 4);
        assert_eq!(emu.state.a[7], sp_before - 4 - 16);
        emu.step().unwrap();
        assert_eq!(emu.state.a[6], 0xABCD);
    }

    #[test]
    fn test_swap() {
        // SWAP D0 = 48 40
        let mut emu = make_emu(&[0x48, 0x40]);
        emu.state.d[0] = 0x1234_ABCD;
        emu.step().unwrap();
        assert_eq!(emu.state.d[0], 0xABCD_1234);
    }

    #[test]
    fn test_flags_default() {
        let flags = M68kFlags::default();
        assert!(flags.is_empty());
    }

    #[test]
    fn test_flags_ccr_roundtrip() {
        let f = M68kFlags::N | M68kFlags::V | M68kFlags::X;
        let ccr = f.as_ccr();
        let f2 = M68kFlags::from_ccr(ccr);
        assert_eq!(f, f2);
    }

    #[test]
    fn test_cond_eq() {
        let f = M68kFlags::Z;
        assert!(f.test(CondCode::Eq));
        assert!(!f.test(CondCode::Ne));
    }

    #[test]
    fn test_memory_roundtrip() {
        let mut mem = M68kMemory::new();
        mem.write32(0x1000, 0xDEAD_BEEF);
        assert_eq!(mem.read32(0x1000), 0xDEAD_BEEF);
        assert_eq!(mem.read16(0x1000), 0xDEAD);
        assert_eq!(mem.read8(0x1001), 0xAD);
    }

    #[test]
    fn test_step_limit() {
        // Infinite loop: BRA -2 (self): 60 FE
        let mut emu = make_emu(&[0x60, 0xFE]);
        emu.step_limit = 5;
        let err = emu.run().unwrap_err();
        assert!(matches!(err, EmulatorError::StepLimitReached));
    }

    #[test]
    fn test_lsl_d0() {
        // LSL.L #1,D0 = E3 80
        let mut emu = make_emu(&[0xE3, 0x80]);
        emu.state.d[0] = 1;
        emu.step().unwrap();
        assert_eq!(emu.state.d[0], 2);
    }

    #[test]
    fn test_lsr_d0() {
        // LSR.L #1,D0 = E2 80
        let mut emu = make_emu(&[0xE2, 0x80]);
        emu.state.d[0] = 4;
        emu.step().unwrap();
        assert_eq!(emu.state.d[0], 2);
    }

    #[test]
    fn test_dbcc_loop() {
        // DBRA D0, -4 (0x51 0xC8 0xFF 0xFC): count D0 down to -1
        // Place at 0x1000
        let code = [0x51u8, 0xC8, 0xFF, 0xFC];
        let mut emu = make_emu(&code);
        emu.state.d[0] = 2; // counter = 2
        // First execution: counter=1, branch back to 0x1000
        emu.step().unwrap();
        assert_eq!(emu.state.d[0] & 0xFFFF, 1);
    }
}
