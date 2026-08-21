//! SPARC V8 CPU emulator with register windows, traps, and a simple memory model.
//!
//! Implements `SparcState` with the eight register windows (G/O/L/I sets),
//! the PC / nPC pair, PSR, WIM, and TBR. `step()` dispatches to individual
//! instruction handlers and manages the SAVE/RESTORE window rotation.

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of register windows in a SPARC V8 implementation (IU architecture).
pub const NWINDOWS: usize = 8;
/// Total number of windowed registers (24 per window * 8 windows = 192, but
/// the 8 globals are separate).
pub const GLOBAL_REGS: usize = 8;

// ── PSR bits ──────────────────────────────────────────────────────────────────
pub const PSR_ICC_N: u32 = 1 << 23;
pub const PSR_ICC_Z: u32 = 1 << 22;
pub const PSR_ICC_V: u32 = 1 << 21;
pub const PSR_ICC_C: u32 = 1 << 20;
pub const PSR_EF: u32 = 1 << 12; // FPU enable
pub const PSR_S: u32 = 1 << 7; // supervisor mode
pub const PSR_ET: u32 = 1 << 5; // enable traps

// ── Error / Trap types ────────────────────────────────────────────────────────

/// SPARC trap types (tt field in TBR).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrapType {
    Reset = 0x00,
    InstructionAccess = 0x01,
    IllegalInstruction = 0x02,
    PrivilegedInstruction = 0x03,
    FpDisabled = 0x04,
    WindowOverflow = 0x05,
    WindowUnderflow = 0x06,
    MemoryAddressNotAligned = 0x07,
    FpException = 0x08,
    DataAccess = 0x09,
    TagOverflow = 0x0A,
    DivisionByZero = 0x2A,
    SoftwareTrapped(u8),
}

impl TrapType {
    #[must_use]
    pub const fn tt(self) -> u8 {
        match self {
            Self::Reset => 0x00,
            Self::InstructionAccess => 0x01,
            Self::IllegalInstruction => 0x02,
            Self::PrivilegedInstruction => 0x03,
            Self::FpDisabled => 0x04,
            Self::WindowOverflow => 0x05,
            Self::WindowUnderflow => 0x06,
            Self::MemoryAddressNotAligned => 0x07,
            Self::FpException => 0x08,
            Self::DataAccess => 0x09,
            Self::TagOverflow => 0x0A,
            Self::DivisionByZero => 0x2A,
            Self::SoftwareTrapped(v) => 0x80 + v,
        }
    }
}

/// Errors returned from `step()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SparcError {
    /// Fetch from unmapped address.
    InstructionFault(u32),
    /// Data access fault.
    DataFault { addr: u32, write: bool },
    /// Unimplemented opcode (op, op2/op3).
    Unimplemented(u32),
    /// Trap was taken.
    Trap(TrapType),
}

impl std::fmt::Display for SparcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InstructionFault(a) => write!(f, "instruction fault at 0x{a:08x}"),
            Self::DataFault { addr, write } => write!(
                f,
                "data fault at 0x{addr:08x} ({} access)",
                if *write { "write" } else { "read" }
            ),
            Self::Unimplemented(op) => write!(f, "unimplemented opcode 0x{op:08x}"),
            Self::Trap(t) => write!(f, "trap {t:?}"),
        }
    }
}

pub type SparcResult<T> = Result<T, SparcError>;

// ── Memory ────────────────────────────────────────────────────────────────────

/// Maximum number of mapped pages (prevents `DoS` via unbounded memory allocation
/// when loading attacker-controlled binary data).
pub const MAX_MAPPED_PAGES: usize = 4096; // 4096 × 4 KiB = 16 MiB

/// Simple byte-addressed big-endian memory.
///
/// Uses `ahash`-backed storage to resist hash-collision `DoS` attacks where the
/// adversary controls the addresses (and therefore the page-table keys).
#[derive(Debug, Default)]
pub struct SparcMemory {
    pages: ahash::AHashMap<u32, Box<[u8; 4096]>>,
}

impl SparcMemory {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    const fn page_key(addr: u32) -> u32 {
        addr & !0xFFF
    }
    const fn page_off(addr: u32) -> usize {
        (addr & 0xFFF) as usize
    }

    /// Map `data` starting at `base` (must be page-aligned, length arbitrary).
    ///
    /// Silently stops mapping once [`MAX_MAPPED_PAGES`] pages have been
    /// allocated.  This caps the per-`SparcMemory` allocation at 16 MiB even
    /// when `data` is gigabytes long (dos-memory-exhaustion mitigation).
    ///
    /// # Panics
    ///
    /// Panics only on an allocation failure while creating a new 4 KiB page;
    /// the page index itself is derived by masking, so it cannot go out of
    /// range for any `base`/`data` pair.
    pub fn load(&mut self, base: u32, data: &[u8]) {
        for (i, &b) in data.iter().enumerate() {
            let addr = base.wrapping_add(crate::sparc_narrow::low_u32_of_usize(i));
            let key = Self::page_key(addr);
            // Enforce the page-count cap before creating a new page.
            if !self.pages.contains_key(&key) {
                if self.pages.len() >= MAX_MAPPED_PAGES {
                    break;
                }
                self.pages.insert(key, Box::new([0u8; 4096]));
            }
            let page = self.pages.get_mut(&key).unwrap();
            page[Self::page_off(addr)] = b;
        }
    }

    #[must_use]
    pub fn read_byte(&self, addr: u32) -> Option<u8> {
        let page = self.pages.get(&Self::page_key(addr))?;
        Some(page[Self::page_off(addr)])
    }

    pub fn write_byte(&mut self, addr: u32, val: u8) -> bool {
        let key = Self::page_key(addr);
        self.pages.get_mut(&key).is_some_and(|page| {
            page[Self::page_off(addr)] = val;
            true
        })
    }

    #[must_use]
    pub fn read_u32(&self, addr: u32) -> Option<u32> {
        let b0 = self.read_byte(addr)?;
        let b1 = self.read_byte(addr.wrapping_add(1))?;
        let b2 = self.read_byte(addr.wrapping_add(2))?;
        let b3 = self.read_byte(addr.wrapping_add(3))?;
        Some(u32::from_be_bytes([b0, b1, b2, b3]))
    }

    pub fn write_u32(&mut self, addr: u32, val: u32) -> bool {
        let bytes = val.to_be_bytes();
        self.write_byte(addr, bytes[0])
            && self.write_byte(addr.wrapping_add(1), bytes[1])
            && self.write_byte(addr.wrapping_add(2), bytes[2])
            && self.write_byte(addr.wrapping_add(3), bytes[3])
    }
}

// ── Register windows ──────────────────────────────────────────────────────────

/// One SPARC register window: 8 out-regs, 8 local-regs, 8 in-regs.
/// The out-regs of window N are the in-regs of window N-1 (mod NWINDOWS).
#[derive(Debug, Clone, Default)]
pub struct Window {
    pub out: [u32; 8],   // %o0..%o7
    pub local: [u32; 8], // %l0..%l7
    pub inp: [u32; 8],   // %i0..%i7 (== next window's %o0..%o7)
}

// ── CPU state ─────────────────────────────────────────────────────────────────

/// Full SPARC V8 CPU state.
#[derive(Debug)]
pub struct SparcState {
    /// Global registers %g0..%g7 (%g0 is always 0).
    pub globals: [u32; GLOBAL_REGS],
    /// Register windows (0 = oldest).
    pub windows: [Window; NWINDOWS],
    /// Current Window Pointer (0..NWINDOWS-1).
    pub cwp: usize,
    /// Program Counter.
    pub pc: u32,
    /// Next Program Counter (delay-slot model).
    pub npc: u32,
    /// Processor State Register.
    pub psr: u32,
    /// Window Invalid Mask.
    pub wim: u32,
    /// Trap Base Register.
    pub tbr: u32,
    /// Emulated memory.
    pub mem: SparcMemory,
    /// Cycle counter (instructions retired).
    pub cycles: u64,
    /// Pending trap (None = no trap).
    pub pending_trap: Option<TrapType>,
}

impl Default for SparcState {
    fn default() -> Self {
        Self::new()
    }
}

impl SparcState {
    /// Create a reset CPU state (PSR.S=1, PSR.ET=0, CWP=0).
    #[must_use]
    pub fn new() -> Self {
        Self {
            globals: [0u32; GLOBAL_REGS],
            windows: Default::default(),
            cwp: 0,
            pc: 0,
            npc: 4,
            psr: PSR_S,  // supervisor, traps disabled
            wim: 1 << 1, // window 1 invalid
            tbr: 0,
            mem: SparcMemory::new(),
            cycles: 0,
            pending_trap: None,
        }
    }

    // ── Register access ───────────────────────────────────────────────────────

    /// Read register `rn` (0..31) using the SPARC window mapping.
    /// r0 = %g0 (always 0), r1..r7 = %g1..%g7,
    /// r8..r15 = %o0..%o7 (CWP window), r16..r23 = %l0..%l7,
    /// r24..r31 = %i0..%i7.
    #[must_use]
    pub fn rget(&self, rn: u32) -> u32 {
        match rn {
            0 => 0,
            1..=7 => self.globals[rn as usize],
            8..=15 => self.windows[self.cwp].out[(rn - 8) as usize],
            16..=23 => self.windows[self.cwp].local[(rn - 16) as usize],
            24..=31 => self.windows[self.cwp].inp[(rn - 24) as usize],
            _ => unreachable!(),
        }
    }

    /// Write register `rn` (writes to %g0 are silently discarded).
    pub fn rset(&mut self, rn: u32, val: u32) {
        match rn {
            0 => {}
            1..=7 => self.globals[rn as usize] = val,
            8..=15 => self.windows[self.cwp].out[(rn - 8) as usize] = val,
            16..=23 => self.windows[self.cwp].local[(rn - 16) as usize] = val,
            24..=31 => self.windows[self.cwp].inp[(rn - 24) as usize] = val,
            _ => unreachable!(),
        }
    }

    // ── PSR condition codes ───────────────────────────────────────────────────

    #[must_use]
    pub const fn icc_n(&self) -> bool {
        self.psr & PSR_ICC_N != 0
    }
    #[must_use]
    pub const fn icc_z(&self) -> bool {
        self.psr & PSR_ICC_Z != 0
    }
    #[must_use]
    pub const fn icc_v(&self) -> bool {
        self.psr & PSR_ICC_V != 0
    }
    #[must_use]
    pub const fn icc_c(&self) -> bool {
        self.psr & PSR_ICC_C != 0
    }

    const fn set_icc(&mut self, n: bool, z: bool, v: bool, c: bool) {
        self.psr &= !(PSR_ICC_N | PSR_ICC_Z | PSR_ICC_V | PSR_ICC_C);
        if n {
            self.psr |= PSR_ICC_N;
        }
        if z {
            self.psr |= PSR_ICC_Z;
        }
        if v {
            self.psr |= PSR_ICC_V;
        }
        if c {
            self.psr |= PSR_ICC_C;
        }
    }

    fn update_icc_add(&mut self, lhs: u32, rhs: u32, result: u32) {
        let neg = result >> 31 != 0;
        let zero = result == 0;
        let overflow = ((lhs ^ result) & (rhs ^ result)) >> 31 != 0;
        let carry = u64::from(result) < u64::from(lhs) + u64::from(rhs);
        self.set_icc(neg, zero, overflow, carry);
    }

    fn update_icc_sub(&mut self, lhs: u32, rhs: u32, result: u32) {
        let neg = result >> 31 != 0;
        let zero = result == 0;
        let overflow = ((lhs ^ rhs) & (lhs ^ result)) >> 31 != 0;
        let carry = u64::from(lhs) < u64::from(rhs);
        self.set_icc(neg, zero, overflow, carry);
    }

    // ── Window management ─────────────────────────────────────────────────────

    /// SAVE: decrement CWP (mod NWINDOWS), check WIM.
    ///
    /// # Errors
    ///
    /// Returns [`SparcError::Trap`] with [`TrapType::WindowOverflow`] when the
    /// new CWP is marked invalid in the window-invalid mask.
    pub const fn do_save(&mut self) -> SparcResult<()> {
        let new_cwp = (self.cwp + NWINDOWS - 1) % NWINDOWS;
        if self.wim & (1 << new_cwp) != 0 {
            self.pending_trap = Some(TrapType::WindowOverflow);
            return Err(SparcError::Trap(TrapType::WindowOverflow));
        }
        // The out-regs of the old window become the in-regs of the new window.
        let old_out = self.windows[self.cwp].out;
        self.windows[new_cwp].inp = old_out;
        self.cwp = new_cwp;
        Ok(())
    }

    /// RESTORE: increment CWP (mod NWINDOWS), check WIM.
    ///
    /// # Errors
    ///
    /// Returns [`SparcError::Trap`] with [`TrapType::WindowUnderflow`] when the
    /// new CWP is marked invalid in the window-invalid mask.
    pub const fn do_restore(&mut self) -> SparcResult<()> {
        let new_cwp = (self.cwp + 1) % NWINDOWS;
        if self.wim & (1 << new_cwp) != 0 {
            self.pending_trap = Some(TrapType::WindowUnderflow);
            return Err(SparcError::Trap(TrapType::WindowUnderflow));
        }
        self.cwp = new_cwp;
        Ok(())
    }

    // ── Trap dispatch ─────────────────────────────────────────────────────────

    /// Deliver a trap: saves PC/nPC into %l1/%l2 of the trap window,
    /// sets PSR.S, clears PSR.ET, jumps to TBR.
    pub fn take_trap(&mut self, tt: TrapType) {
        let old_cwp = self.cwp;
        // Decrement CWP without checking WIM (privileged window switch).
        self.cwp = (self.cwp + NWINDOWS - 1) % NWINDOWS;
        // Save old PSR in %l0, PC in %l1, nPC in %l2.
        self.windows[self.cwp].local[0] = self.psr;
        self.windows[self.cwp].local[1] = self.pc;
        self.windows[self.cwp].local[2] = self.npc;
        // Update PSR: supervisor, traps disabled, update CWP field.
        self.psr = (self.psr | PSR_S) & !PSR_ET;
        self.psr = (self.psr & !0x1F) | (crate::sparc_narrow::low_u32_of_usize(old_cwp) & 0x1F);
        // Build TBR with tt.
        let tt_val = u32::from(tt.tt()) << 4;
        self.tbr = (self.tbr & !0xFF0) | tt_val;
        self.pc = self.tbr;
        self.npc = self.tbr + 4;
    }

    // ── Single-step ───────────────────────────────────────────────────────────

    /// Fetch and execute one instruction.
    ///
    /// # Errors
    ///
    /// Returns [`SparcError::InstructionFault`] when the program counter points
    /// at unmapped memory, or whichever error the executed instruction raises
    /// (a window trap, an unimplemented opcode, a memory fault).
    pub fn step(&mut self) -> SparcResult<()> {
        let instr = self
            .mem
            .read_u32(self.pc)
            .ok_or(SparcError::InstructionFault(self.pc))?;

        let op = instr >> 30;
        let rd = (instr >> 25) & 0x1F;
        let next_pc = self.npc;
        let following_pc = self.npc.wrapping_add(4);

        match op {
            0 => self.exec_fmt0(instr, rd)?,
            1 => self.exec_call(instr),
            2 => self.exec_fmt2(instr, rd)?,
            3 => self.exec_fmt3(instr, rd)?,
            _ => return Err(SparcError::Unimplemented(instr)),
        }

        // Advance PC unless instruction already modified it (branches/calls).
        if self.pc == next_pc.wrapping_sub(4) {
            // Not yet advanced — normal sequential flow.
            self.pc = next_pc;
            self.npc = following_pc;
        }

        self.cycles += 1;
        Ok(())
    }

    // ── Format 0: SETHI / Bicc ────────────────────────────────────────────────

    fn exec_fmt0(&mut self, instr: u32, rd: u32) -> SparcResult<()> {
        let op2 = (instr >> 22) & 0x7;
        match op2 {
            0b100 => {
                // SETHI
                let imm22 = instr & 0x3F_FFFF;
                self.rset(rd, imm22 << 10);
                self.pc = self.npc;
                self.npc = self.npc.wrapping_add(4);
            }
            0b010 => {
                // Bicc (Branch on Integer Condition Codes)
                let cond = (instr >> 25) & 0xF;
                let a = (instr >> 29) & 0x1; // annul bit
                let disp22 = (instr & 0x3F_FFFF).cast_signed() << 10 >> 10; // sign extend
                let target = self.pc.wrapping_add((disp22.wrapping_mul(4)).cast_unsigned());
                let taken = self.eval_bicc(cond);
                if taken {
                    self.pc = self.npc; // execute delay slot
                    self.npc = target;
                } else if a == 1 {
                    // Annul delay slot: skip it
                    self.pc = self.npc.wrapping_add(4);
                    self.npc = self.pc.wrapping_add(4);
                } else {
                    self.pc = self.npc;
                    self.npc = self.npc.wrapping_add(4);
                }
            }
            _ => return Err(SparcError::Unimplemented(instr)),
        }
        Ok(())
    }

    const fn eval_bicc(&self, cond: u32) -> bool {
        let n = self.icc_n();
        let z = self.icc_z();
        let v = self.icc_v();
        let c = self.icc_c();
        match cond {
            0x1 => z,               // BE
            0x2 => n ^ v,           // BL (signed <)
            0x3 => z || (n ^ v),    // BLE (signed ≤)
            0x4 => c || z,          // BLEU (unsigned ≤)
            0x5 => c,               // BCS/BLU (carry / unsigned <)
            0x6 => n,               // BNEG (negative)
            0x7 => v,               // BVS (overflow)
            0x8 => true,            // BA (always)
            0x9 => !z,              // BNE
            0xA => !(c || z),       // BGU (unsigned >)
            0xB => !c,              // BCC/BGEU (no carry / unsigned ≥)
            0xC => !n,              // BPOS (positive)
            0xD => !v,              // BVC (no overflow)
            0xE => !(z || (n ^ v)), // BGE (signed ≥)  [inv of BLE]
            0xF => !(n ^ v),        // BG (signed >)   [inv of BL]
            // 0x0 is BN, "branch never"; anything above 0xF cannot occur in a
            // 4-bit condition field. Both answer false.
            _ => false,
        }
    }

    // ── Format 1: CALL ────────────────────────────────────────────────────────

    /// Execute `CALL`. Infallible: every 30-bit displacement names a valid
    /// target, so there is no error for the caller to propagate.
    fn exec_call(&mut self, instr: u32) {
        // Sign-extend the 30-bit disp field to i32, then scale by 4.
        // We work in i64 to avoid any overflow before the sign extension,
        // sign-extend by shifting left then right, and truncate to i32.
        let field = i64::from(instr & 0x3FFF_FFFF);
        // Sign-extend 30-bit value: shift MSB to bit 63, arithmetic-shift back.
        let sign_ext = (field << 34) >> 34; // 64 - 30 = 34
        // `sign_ext` holds a sign-extended 30-bit value, i.e. -2^29..2^29-1;
        // multiplied by 4 that is -2^31..2^31-4, exactly the i32 range. Take the
        // low word so the narrowing is a total operation rather than a cast.
        let disp30 = crate::sparc_narrow::low_i32_of_u64((sign_ext * 4).cast_unsigned());
        // %o7 = current PC (return address for CALL)
        let ret_addr = self.pc;
        self.rset(15, ret_addr); // r15 = %o7
        let target = self.pc.wrapping_add((disp30).cast_unsigned());
        self.pc = self.npc; // execute delay slot
        self.npc = target;
    }

    // ── Format 2: SETHI (same as fmt0 really) ────────────────────────────────

    fn exec_fmt2(&mut self, instr: u32, rd: u32) -> SparcResult<()> {
        let op3 = (instr >> 19) & 0x3F;
        let rs1 = (instr >> 14) & 0x1F;
        let i = (instr >> 13) & 1;
        let rs2 = instr & 0x1F;
        let simm13 = (instr & 0x1FFF).cast_signed() << 19 >> 19;

        let src2 = if i == 1 {
            (simm13).cast_unsigned()
        } else {
            self.rget(rs2)
        };
        let src1 = self.rget(rs1);

        match op3 {
            // ALU
            0x00 => {
                // ADD
                let r = src1.wrapping_add(src2);
                self.rset(rd, r);
            }
            0x10 => {
                // ADDcc
                let r = src1.wrapping_add(src2);
                self.update_icc_add(src1, src2, r);
                self.rset(rd, r);
            }
            0x04 => {
                // SUB
                let r = src1.wrapping_sub(src2);
                self.rset(rd, r);
            }
            0x14 => {
                // SUBcc
                let r = src1.wrapping_sub(src2);
                self.update_icc_sub(src1, src2, r);
                self.rset(rd, r);
            }
            0x01 => {
                // AND
                self.rset(rd, src1 & src2);
            }
            0x11 => {
                // ANDcc
                let r = src1 & src2;
                self.set_icc(r >> 31 != 0, r == 0, false, false);
                self.rset(rd, r);
            }
            0x02 => {
                // OR
                self.rset(rd, src1 | src2);
            }
            0x12 => {
                // ORcc
                let r = src1 | src2;
                self.set_icc(r >> 31 != 0, r == 0, false, false);
                self.rset(rd, r);
            }
            0x03 => {
                // XOR
                self.rset(rd, src1 ^ src2);
            }
            0x25 => {
                // SLL
                let sh = src2 & 31;
                self.rset(rd, src1 << sh);
            }
            0x26 => {
                // SRL
                let sh = src2 & 31;
                self.rset(rd, src1 >> sh);
            }
            0x27 => {
                // SRA
                let sh = src2 & 31;
                self.rset(rd, (src1.cast_signed() >> sh).cast_unsigned());
            }
            0x38 => {
                // JMPL
                let target = src1.wrapping_add(src2);
                self.rset(rd, self.pc); // save PC
                self.pc = self.npc;
                self.npc = target;
            }
            0x3C => {
                // SAVE
                let saved_sp = src1.wrapping_add(src2);
                self.do_save()?;
                self.rset(rd, saved_sp); // %sp in new window
            }
            0x3D => {
                // RESTORE
                let result = src1.wrapping_add(src2);
                self.do_restore()?;
                self.rset(rd, result);
            }
            0x3A => {
                // Tcc (Trap on condition)
                let cond = (instr >> 25) & 0xF;
                if self.eval_bicc(cond) {
                    let sw_tt = (src1.wrapping_add(src2) & 0x7F) as u8;
                    let trap = TrapType::SoftwareTrapped(sw_tt);
                    self.take_trap(trap);
                    return Err(SparcError::Trap(trap));
                }
            }
            _ => return Err(SparcError::Unimplemented((op3 << 19) | instr)),
        }
        self.pc = self.npc;
        self.npc = self.npc.wrapping_add(4);
        Ok(())
    }

    // ── Format 3: Load / Store ────────────────────────────────────────────────

    fn exec_fmt3(&mut self, instr: u32, rd: u32) -> SparcResult<()> {
        let op3 = (instr >> 19) & 0x3F;
        let rs1 = (instr >> 14) & 0x1F;
        let i = (instr >> 13) & 1;
        let rs2 = instr & 0x1F;
        let simm13 = (instr & 0x1FFF).cast_signed() << 19 >> 19;
        let src2 = if i == 1 {
            (simm13).cast_unsigned()
        } else {
            self.rget(rs2)
        };
        let addr = self.rget(rs1).wrapping_add(src2);

        match op3 {
            0x00 => {
                // LD (32-bit load)
                let val = self
                    .mem
                    .read_u32(addr)
                    .ok_or(SparcError::DataFault { addr, write: false })?;
                self.rset(rd, val);
            }
            0x01 => {
                // LDUB (unsigned byte)
                let val = self
                    .mem
                    .read_byte(addr)
                    .ok_or(SparcError::DataFault { addr, write: false })?;
                self.rset(rd, u32::from(val));
            }
            0x02 => {
                // LDUH (unsigned half)
                // Use wrapping_add to avoid overflow when addr == 0xFFFF_FFFF
                // (parser-trailing-data-ignored / integer-overflow guard).
                let hi = u32::from(self
                    .mem
                    .read_byte(addr)
                    .ok_or(SparcError::DataFault { addr, write: false })?);
                let addr1 = addr.wrapping_add(1);
                let lo = u32::from(self.mem.read_byte(addr1).ok_or(SparcError::DataFault {
                    addr: addr1,
                    write: false,
                })?);
                self.rset(rd, (hi << 8) | lo);
            }
            0x09 => {
                // LDSB (signed byte)
                let val = (self
                    .mem
                    .read_byte(addr)
                    .ok_or(SparcError::DataFault { addr, write: false })?).cast_signed();
                self.rset(rd, (i32::from(val)).cast_unsigned());
            }
            0x04 => {
                // ST (32-bit store)
                let val = self.rget(rd);
                if !self.mem.write_u32(addr, val) {
                    return Err(SparcError::DataFault { addr, write: true });
                }
            }
            0x05 => {
                // STB (byte store)
                let val = crate::sparc_narrow::low_u8_of_u32(self.rget(rd));
                if !self.mem.write_byte(addr, val) {
                    return Err(SparcError::DataFault { addr, write: true });
                }
            }
            _ => return Err(SparcError::Unimplemented(instr)),
        }
        self.pc = self.npc;
        self.npc = self.npc.wrapping_add(4);
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    fn cpu() -> SparcState {
        SparcState::new()
    }

    fn load(cpu: &mut SparcState, base: u32, words: &[u32]) {
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_be_bytes()).collect();
        cpu.mem.load(base, &bytes);
        cpu.pc = base;
        cpu.npc = base + 4;
    }

    /// Encode a Format-2 (integer ALU) instruction.
    fn fmt2(op3: u32, rd: u32, rs1: u32, i: u32, rs2_or_simm: u32) -> u32 {
        (2 << 30) | (rd << 25) | (op3 << 19) | (rs1 << 14) | (i << 13) | (rs2_or_simm & 0x1FFF)
    }

    #[test]
    fn test_sethi() {
        let mut c = cpu();
        // SETHI 0x3FFFFF, %g1
        let instr: u32 = (1 << 25) | (0b100 << 22) | 0x3F_FFFF;
        load(&mut c, 0x1000, &[instr]);
        c.step().unwrap();
        assert_eq!(c.rget(1), 0x3F_FFFF << 10);
    }

    #[test]
    fn test_add_immediate() {
        let mut c = cpu();
        c.rset(2, 10);
        // ADD %g2, 5, %g3
        let instr = fmt2(0x00, 3, 2, 1, 5);
        load(&mut c, 0x1000, &[instr]);
        c.step().unwrap();
        assert_eq!(c.rget(3), 15);
    }

    #[test]
    fn test_sub_reg() {
        let mut c = cpu();
        c.rset(1, 20);
        c.rset(2, 7);
        let instr = fmt2(0x04, 3, 1, 0, 2);
        load(&mut c, 0x1000, &[instr]);
        c.step().unwrap();
        assert_eq!(c.rget(3), 13);
    }

    #[test]
    fn test_and() {
        let mut c = cpu();
        c.rset(1, 0xFF);
        c.rset(2, 0x0F);
        let instr = fmt2(0x01, 3, 1, 0, 2);
        load(&mut c, 0x1000, &[instr]);
        c.step().unwrap();
        assert_eq!(c.rget(3), 0x0F);
    }

    #[test]
    fn test_or_immediate() {
        let mut c = cpu();
        c.rset(1, 0xF0);
        let instr = fmt2(0x02, 2, 1, 1, 0x0F);
        load(&mut c, 0x1000, &[instr]);
        c.step().unwrap();
        assert_eq!(c.rget(2), 0xFF);
    }

    #[test]
    fn test_sll() {
        let mut c = cpu();
        c.rset(1, 1);
        // SPARC v8 SLL op3 = 0x25 (not 0x0D, which is a reserved encoding)
        let instr = fmt2(0x25, 2, 1, 1, 4);
        load(&mut c, 0x1000, &[instr]);
        c.step().unwrap();
        assert_eq!(c.rget(2), 16);
    }

    #[test]
    fn test_sra_sign_extends() {
        let mut c = cpu();
        c.rset(1, 0x8000_0000u32);
        // SPARC v8 SRA op3 = 0x27 (not 0x0F)
        let instr = fmt2(0x27, 2, 1, 1, 1);
        load(&mut c, 0x1000, &[instr]);
        c.step().unwrap();
        assert_eq!(c.rget(2), 0xC000_0000u32);
    }

    #[test]
    fn test_subcc_sets_z() {
        let mut c = cpu();
        c.rset(1, 5);
        let instr = fmt2(0x14, 2, 1, 1, 5);
        load(&mut c, 0x1000, &[instr]);
        c.step().unwrap();
        assert!(c.icc_z());
        assert!(!c.icc_n());
    }

    #[test]
    fn test_addcc_sets_carry() {
        let mut c = cpu();
        c.rset(1, 0xFFFF_FFFFu32);
        let instr = fmt2(0x10, 2, 1, 1, 1);
        load(&mut c, 0x1000, &[instr]);
        c.step().unwrap();
        assert!(c.icc_c());
        assert!(c.icc_z());
    }

    #[test]
    fn test_load_store() {
        let mut c = cpu();
        c.mem.load(0x2000, &[0xDE, 0xAD, 0xBE, 0xEF]);
        c.rset(1, 0x2000);
        // LD [%g1 + 0], %g2  (op3=0x00, fmt3)
        let instr: u32 = ((3 << 30) | (2 << 25)) | (1 << 14) | (1 << 13);
        load(&mut c, 0x1000, &[instr]);
        c.step().unwrap();
        assert_eq!(c.rget(2), 0xDEAD_BEEFu32);
    }

    #[test]
    fn test_store_byte() {
        let mut c = cpu();
        c.mem.load(0x3000, &[0u8; 4096]);
        c.rset(1, 0x3000);
        c.rset(2, 0xAB);
        let instr: u32 = (3 << 30) | (2 << 25) | (0x05 << 19) | (1 << 14) | (1 << 13);
        load(&mut c, 0x1000, &[instr]);
        c.step().unwrap();
        assert_eq!(c.mem.read_byte(0x3000), Some(0xAB));
    }

    #[test]
    fn test_save_restore_window() {
        let mut c = cpu();
        // Make sure window 7 (cwp-1 from 0) is not in WIM.
        c.wim = 0; // no invalid windows for this test
        let old_cwp = c.cwp;
        c.do_save().unwrap();
        assert_ne!(c.cwp, old_cwp);
        c.do_restore().unwrap();
        assert_eq!(c.cwp, old_cwp);
    }

    #[test]
    fn test_save_window_overflow() {
        let mut c = cpu();
        c.cwp = 0;
        c.wim = 1 << 7; // window 7 is invalid
        assert!(matches!(
            c.do_save(),
            Err(SparcError::Trap(TrapType::WindowOverflow))
        ));
    }

    #[test]
    fn test_call_sets_o7() {
        let mut c = cpu();
        // CALL offset 4 (next-next instruction)
        let call_instr: u32 = (1 << 30) | 1; // disp30=1 → +4 bytes
        load(&mut c, 0x1000, &[call_instr, 0, 0, 0]);
        let pc_before = c.pc;
        c.step().unwrap();
        assert_eq!(c.rget(15), pc_before); // %o7 = return addr
    }

    #[test]
    fn test_trap_take_updates_tbr() {
        let mut c = cpu();
        c.psr |= PSR_ET; // enable traps
        c.tbr = 0x0000_0000;
        c.take_trap(TrapType::DivisionByZero);
        // TBR should have tt=0x2A in bits [11:4]
        assert_eq!((c.tbr >> 4) & 0xFF, 0x2A);
    }

    #[test]
    fn test_pc_advances_after_alu() {
        let mut c = cpu();
        let instr = fmt2(0x02, 1, 0, 1, 0); // OR %g0, 0, %g1
        load(&mut c, 0x1000, &[instr]);
        c.step().unwrap();
        assert_eq!(c.pc, 0x1004);
    }

    #[test]
    fn test_g0_always_zero() {
        let mut c = cpu();
        c.rset(0, 0xDEAD_BEEF);
        assert_eq!(c.rget(0), 0);
    }

    #[test]
    fn test_cycles_increment() {
        let mut c = cpu();
        let instr = fmt2(0x02, 1, 0, 1, 0);
        load(&mut c, 0x1000, &[instr, instr, instr]);
        c.step().unwrap();
        c.step().unwrap();
        c.step().unwrap();
        assert_eq!(c.cycles, 3);
    }

    #[test]
    fn test_unimplemented_returns_error() {
        let mut c = cpu();
        // op=2, op3=0x3F (reserved)
        let instr: u32 = (2 << 30) | (0x3F << 19) | (1 << 13) | 0x3F;
        load(&mut c, 0x1000, &[instr]);
        assert!(matches!(c.step(), Err(SparcError::Unimplemented(_))));
    }

    #[test]
    fn test_instruction_fault_on_unmapped() {
        let mut c = cpu();
        c.pc = 0xDEAD_0000;
        c.npc = 0xDEAD_0004;
        assert!(matches!(
            c.step(),
            Err(SparcError::InstructionFault(0xDEAD_0000))
        ));
    }
}
