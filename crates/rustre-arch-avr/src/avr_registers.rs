//! AVR register file: 32 8-bit GPRs, special pairs X/Y/Z, SREG, SP, PC.
// ── Register indices ─────────────────────────────────────────────────────────

/// A single 8-bit AVR general-purpose register (R0..R31).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AvrReg(pub u8);

impl AvrReg {
    pub const R0: Self  = Self(0);
    pub const R1: Self  = Self(1);
    pub const R2: Self  = Self(2);
    pub const R3: Self  = Self(3);
    pub const R4: Self  = Self(4);
    pub const R5: Self  = Self(5);
    pub const R6: Self  = Self(6);
    pub const R7: Self  = Self(7);
    pub const R8: Self  = Self(8);
    pub const R9: Self  = Self(9);
    pub const R10: Self = Self(10);
    pub const R11: Self = Self(11);
    pub const R12: Self = Self(12);
    pub const R13: Self = Self(13);
    pub const R14: Self = Self(14);
    pub const R15: Self = Self(15);
    pub const R16: Self = Self(16);
    pub const R17: Self = Self(17);
    pub const R18: Self = Self(18);
    pub const R19: Self = Self(19);
    pub const R20: Self = Self(20);
    pub const R21: Self = Self(21);
    pub const R22: Self = Self(22);
    pub const R23: Self = Self(23);
    pub const R24: Self = Self(24);
    pub const R25: Self = Self(25);
    pub const R26: Self = Self(26);  // XL
    pub const R27: Self = Self(27);  // XH
    pub const R28: Self = Self(28);  // YL (frame pointer low)
    pub const R29: Self = Self(29);  // YH (frame pointer high)
    pub const R30: Self = Self(30);  // ZL
    pub const R31: Self = Self(31);  // ZH

    /// Return the register index (0-31).
    #[must_use]
    #[inline]
    pub const fn index(self) -> u8 { self.0 }

    /// True for upper half R16-R31 (immediate instructions only work here).
    #[must_use]
    #[inline]
    pub const fn is_upper(self) -> bool { self.0 >= 16 }

    /// True for R26-R31 (pointer pair registers).
    #[must_use]
    #[inline]
    pub const fn is_pointer(self) -> bool { self.0 >= 26 }

    /// Return a static name string ("r0".."r31").
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self.0 {
            0  => "r0",  1  => "r1",  2  => "r2",  3  => "r3",
            4  => "r4",  5  => "r5",  6  => "r6",  7  => "r7",
            8  => "r8",  9  => "r9",  10 => "r10", 11 => "r11",
            12 => "r12", 13 => "r13", 14 => "r14", 15 => "r15",
            16 => "r16", 17 => "r17", 18 => "r18", 19 => "r19",
            20 => "r20", 21 => "r21", 22 => "r22", 23 => "r23",
            24 => "r24", 25 => "r25",
            26 => "xl",  27 => "xh",
            28 => "yl",  29 => "yh",
            30 => "zl",  31 => "zh",
            _  => "??",
        }
    }

    /// Return the pointer-pair name for this register if it is a pair low byte.
    #[must_use]
    pub const fn pair_name(self) -> Option<&'static str> {
        match self.0 {
            26 => Some("X"),
            28 => Some("Y"),
            30 => Some("Z"),
            _  => None,
        }
    }
}

impl core::fmt::Display for AvrReg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

impl core::fmt::Debug for AvrReg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AvrReg({}={})", self.0, self.name())
    }
}

// ── 16-bit register pairs ─────────────────────────────────────────────────────

/// Encoding of the three named 16-bit pointer pairs: X, Y, Z.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AvrRegPair {
    /// X register pair: R27:R26.
    X,
    /// Y register pair: R29:R28 — used as frame pointer in GCC ABI.
    Y,
    /// Z register pair: R31:R30 — used for indirect jumps/calls (IJMP/ICALL) and LPM/ELPM.
    Z,
    /// Word-operation pair for ADIW/SBIW: R25:R24, R27:R26, R29:R28, R31:R30.
    WordPair(u8),
}

impl AvrRegPair {
    /// Decode the 2-bit pair selector from ADIW/SBIW encoding (0-3 → r24/r26/r28/r30).
    #[must_use]
    pub const fn from_adiw_bits(bits: u8) -> Self {
        match bits & 3 {
            0 => Self::WordPair(24),
            1 => Self::X,
            2 => Self::Y,
            3 => Self::Z,
            _ => unreachable!(),
        }
    }

    /// Return the low-byte register of this pair.
    #[must_use]
    pub const fn low(self) -> AvrReg {
        match self {
            Self::X             => AvrReg::R26,
            Self::Y             => AvrReg::R28,
            Self::Z             => AvrReg::R30,
            Self::WordPair(n)   => AvrReg(n),
        }
    }

    /// Return the high-byte register of this pair.
    #[must_use]
    pub const fn high(self) -> AvrReg {
        match self {
            Self::X             => AvrReg::R27,
            Self::Y             => AvrReg::R29,
            Self::Z             => AvrReg::R31,
            Self::WordPair(n)   => AvrReg(n + 1),
        }
    }

    /// Name string.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X | Self::WordPair(26) => "X",
            Self::Y | Self::WordPair(28) => "Y",
            Self::Z | Self::WordPair(30) => "Z",
            Self::WordPair(24) => "r25:r24",
            Self::WordPair(_)  => "??",
        }
    }
}

impl core::fmt::Display for AvrRegPair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

// ── SREG — Status Register ────────────────────────────────────────────────────

/// Bit positions in the AVR Status Register (SREG = I/O address 0x3F).
pub mod sreg_bits {
    /// Carry flag (bit 0).
    pub const C: u8 = 0;
    /// Zero flag (bit 1).
    pub const Z: u8 = 1;
    /// Negative flag (bit 2).
    pub const N: u8 = 2;
    /// Overflow flag (bit 3).
    pub const V: u8 = 3;
    /// Sign flag S = N XOR V (bit 4).
    pub const S: u8 = 4;
    /// Half-carry flag (bit 5).
    pub const H: u8 = 5;
    /// Bit copy storage / transfer flag (bit 6).
    pub const T: u8 = 6;
    /// Global interrupt enable (bit 7).
    pub const I: u8 = 7;

    pub const C_MASK: u8 = 1 << C;
    pub const Z_MASK: u8 = 1 << Z;
    pub const N_MASK: u8 = 1 << N;
    pub const V_MASK: u8 = 1 << V;
    pub const S_MASK: u8 = 1 << S;
    pub const H_MASK: u8 = 1 << H;
    pub const T_MASK: u8 = 1 << T;
    pub const I_MASK: u8 = 1 << I;
}

/// The AVR Status Register value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AvrSreg(pub u8);

impl AvrSreg {
    /// Carry flag.
    #[must_use] #[inline] pub const fn c(self)  -> bool { self.0 & sreg_bits::C_MASK != 0 }
    /// Zero flag.
    #[must_use] #[inline] pub const fn z(self)  -> bool { self.0 & sreg_bits::Z_MASK != 0 }
    /// Negative flag.
    #[must_use] #[inline] pub const fn n(self)  -> bool { self.0 & sreg_bits::N_MASK != 0 }
    /// Overflow flag.
    #[must_use] #[inline] pub const fn v(self)  -> bool { self.0 & sreg_bits::V_MASK != 0 }
    /// Sign flag.
    #[must_use] #[inline] pub const fn s(self)  -> bool { self.0 & sreg_bits::S_MASK != 0 }
    /// Half-carry flag.
    #[must_use] #[inline] pub const fn h(self)  -> bool { self.0 & sreg_bits::H_MASK != 0 }
    /// Transfer bit.
    #[must_use] #[inline] pub const fn t(self)  -> bool { self.0 & sreg_bits::T_MASK != 0 }
    /// Global interrupt enable.
    #[must_use] #[inline] pub const fn i(self)  -> bool { self.0 & sreg_bits::I_MASK != 0 }

    #[inline] pub const fn set_c(&mut self, v: bool)  { self.set_bit(sreg_bits::C, v); }
    #[inline] pub const fn set_z(&mut self, v: bool)  { self.set_bit(sreg_bits::Z, v); }
    #[inline] pub const fn set_n(&mut self, v: bool)  { self.set_bit(sreg_bits::N, v); }
    #[inline] pub const fn set_v(&mut self, v: bool)  { self.set_bit(sreg_bits::V, v); }
    #[inline] pub const fn set_s(&mut self, v: bool)  { self.set_bit(sreg_bits::S, v); }
    #[inline] pub const fn set_h(&mut self, v: bool)  { self.set_bit(sreg_bits::H, v); }
    #[inline] pub const fn set_t(&mut self, v: bool)  { self.set_bit(sreg_bits::T, v); }
    #[inline] pub const fn set_i(&mut self, v: bool)  { self.set_bit(sreg_bits::I, v); }

    const fn set_bit(&mut self, bit: u8, v: bool) {
        if v { self.0 |= 1 << bit; } else { self.0 &= !(1 << bit); }
    }

    /// Update SREG from an 8-bit arithmetic result (Carry, Zero, Negative, Sign).
    /// `carry` is the carry-out of bit 7; `overflow` is the signed overflow.
    pub const fn update_arith(&mut self, result: u8, carry: bool, overflow: bool, half_carry: bool) {
        let n = result & 0x80 != 0;
        let z = result == 0;
        self.set_c(carry);
        self.set_z(z);
        self.set_n(n);
        self.set_v(overflow);
        self.set_s(n ^ overflow);
        self.set_h(half_carry);
    }

    /// Pretty-print (e.g. "ITHSVNZC" with uppercase = set).
    #[must_use]
    pub fn display_string(self) -> [u8; 8] {
        let flags = [
            (sreg_bits::I_MASK, b'I', b'i'),
            (sreg_bits::T_MASK, b'T', b't'),
            (sreg_bits::H_MASK, b'H', b'h'),
            (sreg_bits::S_MASK, b'S', b's'),
            (sreg_bits::V_MASK, b'V', b'v'),
            (sreg_bits::N_MASK, b'N', b'n'),
            (sreg_bits::Z_MASK, b'Z', b'z'),
            (sreg_bits::C_MASK, b'C', b'c'),
        ];
        let mut out = [0u8; 8];
        for (i, (mask, up, lo)) in flags.iter().enumerate() {
            out[i] = if self.0 & mask != 0 { *up } else { *lo };
        }
        out
    }
}

impl core::fmt::Debug for AvrSreg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = self.display_string();
        write!(f, "SREG({:02x} = {})", self.0, core::str::from_utf8(&s).unwrap_or("??"))
    }
}

impl core::fmt::Display for AvrSreg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = self.display_string();
        f.write_str(core::str::from_utf8(&s).unwrap_or("??"))
    }
}

// ── Stack Pointer ─────────────────────────────────────────────────────────────

/// AVR stack pointer.  On devices with more than 256 bytes of SRAM the SP is
/// two bytes (SPH:SPL at I/O 0x3E:0x3D).  On tiny devices only SPL exists.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct AvrSp {
    /// Full 16-bit stack pointer value.
    pub value: u16,
    /// True if the device has SPH (> 256 bytes SRAM).
    pub has_sph: bool,
}

impl AvrSp {
    #[must_use]
    pub const fn new(value: u16, has_sph: bool) -> Self { Self { value, has_sph } }

    /// Low byte (SPL, I/O 0x3D).
    #[must_use]
    pub const fn spl(self) -> u8 { (self.value & 0xFF) as u8 }

    /// High byte (SPH, I/O 0x3E).  Returns 0 on tiny devices.
    #[must_use]
    pub const fn sph(self) -> u8 { (self.value >> 8) as u8 }

    /// Push: decrement SP by `size` bytes.
    pub const fn push(&mut self, size: u16) { self.value = self.value.wrapping_sub(size); }

    /// Pop: increment SP by `size` bytes.
    pub const fn pop(&mut self, size: u16) { self.value = self.value.wrapping_add(size); }

    /// Write SPL and optionally SPH.
    pub const fn write_spl(&mut self, v: u8) {
        self.value = (self.value & 0xFF00) | (v as u16);
    }
    pub const fn write_sph(&mut self, v: u8) {
        if self.has_sph {
            self.value = (self.value & 0x00FF) | ((v as u16) << 8);
        }
    }
}

impl core::fmt::Display for AvrSp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SP=0x{:04x}", self.value)
    }
}

// ── Program Counter ───────────────────────────────────────────────────────────

/// Program counter width on AVR devices.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum PcWidth { #[default] Pc16, Pc22 }

/// AVR program counter.  Word-addressed; byte address = value * 2.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct AvrPc {
    /// Current PC value in words.
    pub words: u32,
    /// Width determines wrap-around mask.
    pub width: PcWidth,
}

impl AvrPc {
    #[must_use]
    pub const fn new(words: u32, width: PcWidth) -> Self { Self { words, width } }

    /// Byte address of the current instruction.
    #[must_use]
    pub const fn byte_addr(self) -> u32 { self.words << 1 }

    /// Advance by `n` words (instruction size).
    pub const fn advance(&mut self, words: u32) {
        self.words = self.next(words);
    }

    /// Return the PC after advancing by `n` words without mutating.
    #[must_use]
    pub const fn next(self, words: u32) -> u32 {
        let mask = match self.width {
            PcWidth::Pc16 => 0x0000_FFFF,
            PcWidth::Pc22 => 0x003F_FFFF,
        };
        self.words.wrapping_add(words) & mask
    }

    /// Jump to an absolute word address.
    pub const fn jump(&mut self, addr: u32) {
        let mask = match self.width {
            PcWidth::Pc16 => 0x0000_FFFF,
            PcWidth::Pc22 => 0x003F_FFFF,
        };
        self.words = addr & mask;
    }

    /// Relative branch (offset in words, signed).
    pub const fn branch(&mut self, offset: i32) {
        let new_val = self.words.wrapping_add_signed(offset);
        let mask = match self.width {
            PcWidth::Pc16 => 0x0000_FFFF,
            PcWidth::Pc22 => 0x003F_FFFF,
        };
        self.words = new_val & mask;
    }
}

impl core::fmt::Debug for AvrPc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PC(0x{:06x})", self.byte_addr())
    }
}

impl core::fmt::Display for AvrPc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{:06x}", self.byte_addr())
    }
}

// ── Full Register File ────────────────────────────────────────────────────────

/// Complete AVR CPU register state.
#[derive(Clone, Debug, Default)]
pub struct AvrRegFile {
    /// General-purpose registers R0..R31.
    pub gpr: [u8; 32],
    /// Status register.
    pub sreg: AvrSreg,
    /// Stack pointer.
    pub sp: AvrSp,
    /// Program counter (word-addressed).
    pub pc: AvrPc,
    /// RAMPX register (extended address for X pointer on >64 KB devices).
    pub rampx: u8,
    /// RAMPY register.
    pub rampy: u8,
    /// RAMPZ register (used with ELPM/ESPM/EIJMP on large-flash devices).
    pub rampz: u8,
    /// RAMPD register (used with LDS/STS on >64 KB data-space devices).
    pub rampd: u8,
    /// EIND register (extended indirect jump base).
    pub eind: u8,
}

impl AvrRegFile {
    /// Create a new zeroed register file for a specific PC width and SP size.
    #[must_use]
    pub fn new(pc_width: PcWidth, has_sph: bool) -> Self {
        Self {
            sp: AvrSp::new(0, has_sph),
            pc: AvrPc::new(0, pc_width),
            ..Default::default()
        }
    }

    /// Read a GPR by index (panics if out of range).
    #[must_use]
    #[inline]
    pub const fn read(&self, reg: AvrReg) -> u8 { self.gpr[reg.0 as usize] }

    /// Write a GPR by index (panics if out of range).
    #[inline]
    pub const fn write(&mut self, reg: AvrReg, val: u8) { self.gpr[reg.0 as usize] = val; }

    /// Read 16-bit X pointer (R27:R26).
    #[must_use]
    pub const fn read_x(&self) -> u16 {
        (self.gpr[26] as u16) | ((self.gpr[27] as u16) << 8)
    }

    /// Write 16-bit X pointer.
    pub fn write_x(&mut self, val: u16) {
        self.gpr[26] = u8::try_from(val & 0xFF).unwrap_or(u8::MAX);
        self.gpr[27] = u8::try_from(val >> 8).unwrap_or(u8::MAX);
    }

    /// Read 16-bit Y pointer (R29:R28 — frame pointer).
    #[must_use]
    pub fn read_y(&self) -> u16 {
        u16::from(self.gpr[28]) | (u16::from(self.gpr[29]) << 8)
    }

    /// Write 16-bit Y pointer.
    pub fn write_y(&mut self, val: u16) {
        self.gpr[28] = u8::try_from(val & 0xFF).unwrap_or(u8::MAX);
        self.gpr[29] = u8::try_from(val >> 8).unwrap_or(u8::MAX);
    }

    /// Read 16-bit Z pointer (R31:R30).
    #[must_use]
    pub fn read_z(&self) -> u16 {
        u16::from(self.gpr[30]) | (u16::from(self.gpr[31]) << 8)
    }

    /// Write 16-bit Z pointer.
    pub fn write_z(&mut self, val: u16) {
        self.gpr[30] = u8::try_from(val & 0xFF).unwrap_or(u8::MAX);
        self.gpr[31] = u8::try_from(val >> 8).unwrap_or(u8::MAX);
    }

    /// Extended 24-bit X pointer including RAMPX.
    #[must_use]
    pub fn read_x_ext(&self) -> u32 {
        u32::from(self.read_x()) | (u32::from(self.rampx) << 16)
    }

    /// Extended 24-bit Y pointer including RAMPY.
    #[must_use]
    pub fn read_y_ext(&self) -> u32 {
        u32::from(self.read_y()) | (u32::from(self.rampy) << 16)
    }

    /// Extended 24-bit Z pointer including RAMPZ.
    #[must_use]
    pub fn read_z_ext(&self) -> u32 {
        u32::from(self.read_z()) | (u32::from(self.rampz) << 16)
    }

    /// Read a 16-bit word pair (lo = rN, hi = rN+1).  `lo_reg` must be even.
    #[must_use]
    pub fn read_pair(&self, lo_reg: u8) -> u16 {
        let lo = self.gpr[lo_reg as usize];
        let hi = self.gpr[(lo_reg + 1) as usize];
        u16::from(lo) | (u16::from(hi) << 8)
    }

    /// Write a 16-bit word pair.  `lo_reg` must be even.
    pub fn write_pair(&mut self, lo_reg: u8, val: u16) {
        self.gpr[lo_reg as usize]       = u8::try_from(val & 0xFF).unwrap_or(u8::MAX);
        self.gpr[(lo_reg + 1) as usize] = u8::try_from(val >> 8).unwrap_or(u8::MAX);
    }

    /// Reset all state to power-on defaults (GPRs=0, SREG=0, SP=0, PC=0).
    pub fn reset(&mut self) {
        self.gpr = [0u8; 32];
        self.sreg = AvrSreg::default();
        self.sp.value = 0;
        self.pc.words = 0;
        self.rampx = 0; self.rampy = 0; self.rampz = 0;
        self.rampd = 0; self.eind  = 0;
    }

    /// Dump a human-readable register summary to a string.
    #[must_use]
    pub fn dump(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(512);
        for i in (0usize..32).step_by(8) {
            for j in i..(i + 8) {
                let _ = write!(s, "r{j:<2}={:02x} ", self.gpr[j]);
            }
            s.push('\n');
        }
        let _ = writeln!(s, "SREG={} SP={:04x} PC={:06x}",
            self.sreg, self.sp.value, self.pc.byte_addr());
        let _ = writeln!(s, "X={:04x} Y={:04x} Z={:04x}",
            self.read_x(), self.read_y(), self.read_z());
        s
    }

    /// Return `true` if the specified SREG bit is set.
    #[must_use]
    pub const fn flag(&self, bit: u8) -> bool { self.sreg.0 & (1 << bit) != 0 }

    /// Set a specific SREG bit.
    pub const fn set_flag(&mut self, bit: u8, val: bool) {
        if val { self.sreg.0 |= 1 << bit; } else { self.sreg.0 &= !(1 << bit); }
    }

    /// Perform ADD Rd, Rr and update SREG.
    pub const fn exec_add(&mut self, rd: AvrReg, rr: AvrReg) {
        let a = self.read(rd);
        let b = self.read(rr);
        let (result, carry) = a.overflowing_add(b);
        let half_carry = ((a & 0x0F) + (b & 0x0F)) > 0x0F;
        let overflow = ((a ^ result) & (b ^ result) & 0x80) != 0;
        self.write(rd, result);
        self.sreg.update_arith(result, carry, overflow, half_carry);
    }

    /// Perform SUB Rd, Rr and update SREG.
    pub const fn exec_sub(&mut self, rd: AvrReg, rr: AvrReg) {
        let a = self.read(rd);
        let b = self.read(rr);
        let (result, borrow) = a.overflowing_sub(b);
        let half_borrow = (a & 0x0F) < (b & 0x0F);
        let overflow = ((a ^ b) & (a ^ result) & 0x80) != 0;
        self.write(rd, result);
        self.sreg.update_arith(result, borrow, overflow, half_borrow);
    }

    /// Perform AND Rd, Rr and update SREG.
    pub const fn exec_and(&mut self, rd: AvrReg, rr: AvrReg) {
        let result = self.read(rd) & self.read(rr);
        self.write(rd, result);
        let n = result & 0x80 != 0;
        let z = result == 0;
        self.sreg.set_n(n); self.sreg.set_z(z);
        self.sreg.set_v(false); self.sreg.set_s(n);
    }

    /// Perform OR Rd, Rr and update SREG.
    pub const fn exec_or(&mut self, rd: AvrReg, rr: AvrReg) {
        let result = self.read(rd) | self.read(rr);
        self.write(rd, result);
        let n = result & 0x80 != 0;
        let z = result == 0;
        self.sreg.set_n(n); self.sreg.set_z(z);
        self.sreg.set_v(false); self.sreg.set_s(n);
    }

    /// Perform EOR Rd, Rr and update SREG.
    pub const fn exec_eor(&mut self, rd: AvrReg, rr: AvrReg) {
        let result = self.read(rd) ^ self.read(rr);
        self.write(rd, result);
        let n = result & 0x80 != 0;
        let z = result == 0;
        self.sreg.set_n(n); self.sreg.set_z(z);
        self.sreg.set_v(false); self.sreg.set_s(n);
    }

    /// Perform INC Rd and update SREG (C unchanged per spec).
    pub const fn exec_inc(&mut self, rd: AvrReg) {
        let result = self.read(rd).wrapping_add(1);
        self.write(rd, result);
        let n = result & 0x80 != 0;
        let z = result == 0;
        let v = result == 0x80;  // overflow from 0x7F
        self.sreg.set_n(n); self.sreg.set_z(z);
        self.sreg.set_v(v); self.sreg.set_s(n ^ v);
    }

    /// Perform DEC Rd and update SREG (C unchanged per spec).
    pub const fn exec_dec(&mut self, rd: AvrReg) {
        let result = self.read(rd).wrapping_sub(1);
        self.write(rd, result);
        let n = result & 0x80 != 0;
        let z = result == 0;
        let v = result == 0x7F;  // overflow from 0x80
        self.sreg.set_n(n); self.sreg.set_z(z);
        self.sreg.set_v(v); self.sreg.set_s(n ^ v);
    }

    /// Perform LSR Rd and update SREG.
    pub const fn exec_lsr(&mut self, rd: AvrReg) {
        let a = self.read(rd);
        let carry = a & 0x01 != 0;
        let result = a >> 1;
        self.write(rd, result);
        let z = result == 0;
        let v = carry; // N=0, so V=N^C=C
        self.sreg.set_c(carry); self.sreg.set_n(false);
        self.sreg.set_z(z); self.sreg.set_v(v); self.sreg.set_s(v);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reg_names() {
        assert_eq!(AvrReg::R0.name(),  "r0");
        assert_eq!(AvrReg::R26.name(), "xl");
        assert_eq!(AvrReg::R28.name(), "yl");
        assert_eq!(AvrReg::R30.name(), "zl");
        assert_eq!(AvrReg::R31.name(), "zh");
    }

    #[test]
    fn reg_properties() {
        assert!(!AvrReg::R15.is_upper());
        assert!(AvrReg::R16.is_upper());
        assert!(!AvrReg::R25.is_pointer());
        assert!(AvrReg::R26.is_pointer());
    }

    #[test]
    fn sreg_bits() {
        let mut s = AvrSreg::default();
        assert!(!s.c());
        s.set_c(true);
        assert!(s.c());
        s.set_z(true);
        assert!(s.z());
        s.set_i(true);
        assert!(s.i());
        let disp = s.display_string();
        assert_eq!(disp[7], b'C');
        assert_eq!(disp[6], b'Z');
        assert_eq!(disp[0], b'I');
    }

    #[test]
    fn sreg_update_arith() {
        let mut s = AvrSreg::default();
        s.update_arith(0, true, false, false);
        assert!(s.z());
        assert!(s.c());
        assert!(!s.n());
    }

    #[test]
    fn sp_push_pop() {
        let mut sp = AvrSp::new(0x08FF, true);
        sp.push(1);
        assert_eq!(sp.value, 0x08FE);
        sp.pop(1);
        assert_eq!(sp.value, 0x08FF);
        assert_eq!(sp.spl(), 0xFF);
        assert_eq!(sp.sph(), 0x08);
    }

    #[test]
    fn pc_advance_branch() {
        let mut pc = AvrPc::new(0, PcWidth::Pc16);
        pc.advance(1);
        assert_eq!(pc.words, 1);
        assert_eq!(pc.byte_addr(), 2);
        pc.branch(-2);
        assert_eq!(pc.words, 0xFFFF);
    }

    #[test]
    fn regfile_pairs() {
        let mut rf = AvrRegFile::new(PcWidth::Pc16, true);
        rf.write_x(0xABCD);
        assert_eq!(rf.read_x(), 0xABCD);
        assert_eq!(rf.gpr[26], 0xCD);
        assert_eq!(rf.gpr[27], 0xAB);
        rf.write_y(0x1234);
        assert_eq!(rf.read_y(), 0x1234);
        rf.write_z(0x0001);
        assert_eq!(rf.read_z(), 0x0001);
    }

    #[test]
    fn exec_add_overflow() {
        let mut rf = AvrRegFile::new(PcWidth::Pc16, true);
        rf.write(AvrReg::R0, 0x7F);
        rf.write(AvrReg::R1, 0x01);
        rf.exec_add(AvrReg::R0, AvrReg::R1);
        assert_eq!(rf.read(AvrReg::R0), 0x80);
        assert!(rf.sreg.v());
        assert!(rf.sreg.n());
        assert!(!rf.sreg.z());
    }

    #[test]
    fn exec_lsr() {
        let mut rf = AvrRegFile::new(PcWidth::Pc16, true);
        rf.write(AvrReg::R2, 0x01);
        rf.exec_lsr(AvrReg::R2);
        assert_eq!(rf.read(AvrReg::R2), 0x00);
        assert!(rf.sreg.z());
        assert!(rf.sreg.c());
    }

    #[test]
    fn regfile_dump_contains_regs() {
        let rf = AvrRegFile::default();
        let dump = rf.dump();
        assert!(dump.contains("r0 =00") || dump.contains("r0 =0x") || dump.contains("r0=00"));
    }

    #[test]
    fn avrregpair_from_adiw() {
        assert_eq!(AvrRegPair::from_adiw_bits(0).low(), AvrReg(24));
        assert_eq!(AvrRegPair::from_adiw_bits(1), AvrRegPair::X);
        assert_eq!(AvrRegPair::from_adiw_bits(2), AvrRegPair::Y);
        assert_eq!(AvrRegPair::from_adiw_bits(3), AvrRegPair::Z);
    }
}
