/// Z80 register file: main and alternate sets, IX/IY, SP, PC, I, R, flags.

// ── 8-bit register names ──────────────────────────────────────────────────────

/// All addressable 8-bit Z80 registers.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Z80Reg {
    B, C, D, E, H, L,
    /// The (HL) memory pseudo-register used in many instructions.
    MemHL,
    A,
    /// IXH — high byte of IX (undocumented).
    IXH,
    /// IXL — low byte of IX (undocumented).
    IXL,
    /// IYH — high byte of IY (undocumented).
    IYH,
    /// IYL — low byte of IY (undocumented).
    IYL,
    /// Interrupt vector register I.
    I,
    /// Memory refresh register R.
    R,
    /// F register (flags) — rarely named directly but used in PUSH AF / POP AF.
    F,
}

impl Z80Reg {
    /// The 3-bit encoding used in most opcodes (0=B..6=(HL), 7=A).
    /// Returns None for registers not addressable via this encoding.
    #[must_use]
    pub const fn opcode_bits(self) -> Option<u8> {
        match self {
            Z80Reg::B     => Some(0),
            Z80Reg::C     => Some(1),
            Z80Reg::D     => Some(2),
            Z80Reg::E     => Some(3),
            Z80Reg::H     => Some(4),
            Z80Reg::L     => Some(5),
            Z80Reg::MemHL => Some(6),
            Z80Reg::A     => Some(7),
            _             => None,
        }
    }

    /// Decode a 3-bit field from an opcode to a `Z80Reg`.
    #[must_use]
    pub fn from_bits(bits: u8) -> Z80Reg {
        match bits & 7 {
            0 => Z80Reg::B,
            1 => Z80Reg::C,
            2 => Z80Reg::D,
            3 => Z80Reg::E,
            4 => Z80Reg::H,
            5 => Z80Reg::L,
            6 => Z80Reg::MemHL,
            7 => Z80Reg::A,
            _ => unreachable!(),
        }
    }

    /// Assembler name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Z80Reg::B     => "B",
            Z80Reg::C     => "C",
            Z80Reg::D     => "D",
            Z80Reg::E     => "E",
            Z80Reg::H     => "H",
            Z80Reg::L     => "L",
            Z80Reg::MemHL => "(HL)",
            Z80Reg::A     => "A",
            Z80Reg::IXH   => "IXH",
            Z80Reg::IXL   => "IXL",
            Z80Reg::IYH   => "IYH",
            Z80Reg::IYL   => "IYL",
            Z80Reg::I     => "I",
            Z80Reg::R     => "R",
            Z80Reg::F     => "F",
        }
    }

    /// True for the (HL) / (IX+d) / (IY+d) pseudo-registers.
    #[must_use]
    pub const fn is_memory_ref(self) -> bool { matches!(self, Z80Reg::MemHL) }
}

impl core::fmt::Display for Z80Reg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

// ── 16-bit register pairs ─────────────────────────────────────────────────────

/// 16-bit register pairs used in Z80 instructions.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Z80RegPair16 {
    BC,
    DE,
    HL,
    SP,
    /// IX index register (DD-prefixed instructions).
    IX,
    /// IY index register (FD-prefixed instructions).
    IY,
    /// AF — used only in PUSH/POP AF.
    AF,
}

impl Z80RegPair16 {
    /// The 2-bit encoding used in most opcodes (0=BC, 1=DE, 2=HL, 3=SP).
    #[must_use]
    pub const fn opcode_bits(self) -> Option<u8> {
        match self {
            Z80RegPair16::BC => Some(0),
            Z80RegPair16::DE => Some(1),
            Z80RegPair16::HL => Some(2),
            Z80RegPair16::SP => Some(3),
            _                => None,
        }
    }

    /// Decode a 2-bit field.
    #[must_use]
    pub fn from_bits(bits: u8) -> Z80RegPair16 {
        match bits & 3 {
            0 => Z80RegPair16::BC,
            1 => Z80RegPair16::DE,
            2 => Z80RegPair16::HL,
            3 => Z80RegPair16::SP,
            _ => unreachable!(),
        }
    }

    /// Decode a 2-bit field from PUSH/POP encoding (3 → AF instead of SP).
    #[must_use]
    pub fn from_push_bits(bits: u8) -> Z80RegPair16 {
        match bits & 3 {
            0 => Z80RegPair16::BC,
            1 => Z80RegPair16::DE,
            2 => Z80RegPair16::HL,
            3 => Z80RegPair16::AF,
            _ => unreachable!(),
        }
    }

    /// Assembler name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Z80RegPair16::BC => "BC",
            Z80RegPair16::DE => "DE",
            Z80RegPair16::HL => "HL",
            Z80RegPair16::SP => "SP",
            Z80RegPair16::IX => "IX",
            Z80RegPair16::IY => "IY",
            Z80RegPair16::AF => "AF",
        }
    }

    /// High byte register.
    #[must_use]
    pub const fn high(self) -> Z80Reg {
        match self {
            Z80RegPair16::BC => Z80Reg::B,
            Z80RegPair16::DE => Z80Reg::D,
            Z80RegPair16::HL => Z80Reg::H,
            Z80RegPair16::AF => Z80Reg::A,
            Z80RegPair16::IX => Z80Reg::IXH,
            Z80RegPair16::IY => Z80Reg::IYH,
            Z80RegPair16::SP => Z80Reg::H, // no single 8-bit for SP
        }
    }

    /// Low byte register.
    #[must_use]
    pub const fn low(self) -> Z80Reg {
        match self {
            Z80RegPair16::BC => Z80Reg::C,
            Z80RegPair16::DE => Z80Reg::E,
            Z80RegPair16::HL => Z80Reg::L,
            Z80RegPair16::AF => Z80Reg::F,
            Z80RegPair16::IX => Z80Reg::IXL,
            Z80RegPair16::IY => Z80Reg::IYL,
            Z80RegPair16::SP => Z80Reg::L, // no single 8-bit for SP
        }
    }
}

impl core::fmt::Display for Z80RegPair16 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

// ── Alternate register set ────────────────────────────────────────────────────

/// The Z80 alternate (primed) register set.  EX AF,AF' and EXX swap these.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Z80AltReg {
    AltAF,
    AltBC,
    AltDE,
    AltHL,
}

impl Z80AltReg {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Z80AltReg::AltAF => "AF'",
            Z80AltReg::AltBC => "BC'",
            Z80AltReg::AltDE => "DE'",
            Z80AltReg::AltHL => "HL'",
        }
    }
}

impl core::fmt::Display for Z80AltReg {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

// ── Flags register ────────────────────────────────────────────────────────────

/// Bit positions in the Z80 Flags register.
pub mod flag_bits {
    pub const C:  u8 = 0;  // Carry
    pub const N:  u8 = 1;  // Add/Subtract
    pub const PV: u8 = 2;  // Parity/Overflow
    pub const F3: u8 = 3;  // Undocumented (copy of bit 3 of result)
    pub const H:  u8 = 4;  // Half-carry
    pub const F5: u8 = 5;  // Undocumented (copy of bit 5 of result)
    pub const Z:  u8 = 6;  // Zero
    pub const S:  u8 = 7;  // Sign

    pub const C_MASK:  u8 = 1 << C;
    pub const N_MASK:  u8 = 1 << N;
    pub const PV_MASK: u8 = 1 << PV;
    pub const H_MASK:  u8 = 1 << H;
    pub const Z_MASK:  u8 = 1 << Z;
    pub const S_MASK:  u8 = 1 << S;
}

/// Z80 Flags register.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Z80Flags(pub u8);

impl Z80Flags {
    #[inline] #[must_use]
    pub const fn c(self)  -> bool { self.0 & flag_bits::C_MASK  != 0 }
    #[inline] #[must_use]
    pub const fn n(self)  -> bool { self.0 & flag_bits::N_MASK  != 0 }
    #[inline] #[must_use]
    pub const fn pv(self) -> bool { self.0 & flag_bits::PV_MASK != 0 }
    #[inline] #[must_use]
    pub const fn h(self)  -> bool { self.0 & flag_bits::H_MASK  != 0 }
    #[inline] #[must_use]
    pub const fn z(self)  -> bool { self.0 & flag_bits::Z_MASK  != 0 }
    #[inline] #[must_use]
    pub const fn s(self)  -> bool { self.0 & flag_bits::S_MASK  != 0 }

    const fn set_bit(&mut self, bit: u8, v: bool) {
        if v { self.0 |= 1 << bit; } else { self.0 &= !(1 << bit); }
    }

    #[inline] pub fn set_c(&mut self, v: bool)  { self.set_bit(flag_bits::C,  v); }
    #[inline] pub fn set_n(&mut self, v: bool)  { self.set_bit(flag_bits::N,  v); }
    #[inline] pub fn set_pv(&mut self, v: bool) { self.set_bit(flag_bits::PV, v); }
    #[inline] pub fn set_h(&mut self, v: bool)  { self.set_bit(flag_bits::H,  v); }
    #[inline] pub fn set_z(&mut self, v: bool)  { self.set_bit(flag_bits::Z,  v); }
    #[inline] pub fn set_s(&mut self, v: bool)  { self.set_bit(flag_bits::S,  v); }

    /// Update flags after an 8-bit addition.
    pub fn update_add8(&mut self, a: u8, b: u8, carry_in: bool) {
        let ci = u16::from(carry_in);
        let result16 = u16::from(a) + u16::from(b) + ci;
        let result = result16 as u8;
        let half = ((a & 0x0F) + (b & 0x0F) + carry_in as u8) > 0x0F;
        let overflow = ((a ^ result) & (b ^ result) & 0x80) != 0;
        self.set_s(result & 0x80 != 0);
        self.set_z(result == 0);
        self.set_h(half);
        self.set_pv(overflow);
        self.set_n(false);
        self.set_c(result16 > 0xFF);
    }

    /// Update flags after an 8-bit subtraction.
    pub fn update_sub8(&mut self, a: u8, b: u8, borrow_in: bool) {
        let bi = u16::from(borrow_in);
        let result16 = (u16::from(a)).wrapping_sub(u16::from(b)).wrapping_sub(bi);
        let result = result16 as u8;
        let half = (a & 0x0F) < (b & 0x0F) + borrow_in as u8;
        let overflow = ((a ^ b) & (a ^ result) & 0x80) != 0;
        self.set_s(result & 0x80 != 0);
        self.set_z(result == 0);
        self.set_h(half);
        self.set_pv(overflow);
        self.set_n(true);
        self.set_c(result16 > 0xFF);
    }

    /// Update flags for logical AND.
    pub fn update_and(&mut self, result: u8) {
        self.set_s(result & 0x80 != 0);
        self.set_z(result == 0);
        self.set_h(true);
        self.set_pv(parity(result));
        self.set_n(false);
        self.set_c(false);
    }

    /// Update flags for logical OR/XOR.
    pub fn update_or(&mut self, result: u8) {
        self.set_s(result & 0x80 != 0);
        self.set_z(result == 0);
        self.set_h(false);
        self.set_pv(parity(result));
        self.set_n(false);
        self.set_c(false);
    }

    /// Condition code check (bits 3:0 of the condition encoding in an opcode).
    /// Returns true if this flags state satisfies the condition.
    #[must_use]
    pub fn condition_met(self, cc: u8) -> bool {
        match cc & 7 {
            0 => !self.z(),   // NZ
            1 => self.z(),    // Z
            2 => !self.c(),   // NC
            3 => self.c(),    // C
            4 => !self.pv(),  // PO (parity odd)
            5 => self.pv(),   // PE (parity even)
            6 => !self.s(),   // P  (positive)
            7 => self.s(),    // M  (minus)
            _ => unreachable!(),
        }
    }

    /// Assembler name for a condition code.
    #[must_use]
    pub const fn condition_name(cc: u8) -> &'static str {
        match cc & 7 {
            0 => "NZ", 1 => "Z",
            2 => "NC", 3 => "C",
            4 => "PO", 5 => "PE",
            6 => "P",  7 => "M",
            _ => "?",
        }
    }

    #[must_use]
    pub fn display_string(self) -> [u8; 8] {
        let fs = [
            (flag_bits::S_MASK,  b'S', b's'),
            (flag_bits::Z_MASK,  b'Z', b'z'),
            (1 << flag_bits::F5, b'5', b'.'),
            (flag_bits::H_MASK,  b'H', b'h'),
            (1 << flag_bits::F3, b'3', b'.'),
            (flag_bits::PV_MASK, b'V', b'v'),
            (flag_bits::N_MASK,  b'N', b'n'),
            (flag_bits::C_MASK,  b'C', b'c'),
        ];
        let mut out = [0u8; 8];
        for (i, (mask, up, lo)) in fs.iter().enumerate() {
            out[i] = if self.0 & mask != 0 { *up } else { *lo };
        }
        out
    }
}

const fn parity(mut v: u8) -> bool {
    v ^= v >> 4; v ^= v >> 2; v ^= v >> 1; (v & 1) == 0
}

impl core::fmt::Debug for Z80Flags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = self.display_string();
        write!(f, "F({:02x}={})", self.0, core::str::from_utf8(&s).unwrap_or("??"))
    }
}

impl core::fmt::Display for Z80Flags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = self.display_string();
        f.write_str(core::str::from_utf8(&s).unwrap_or("??"))
    }
}

// ── Full register file ────────────────────────────────────────────────────────

/// Complete Z80 CPU register state.
#[derive(Clone, Debug)]
pub struct Z80RegFile {
    // Main register set
    pub a: u8,
    pub f: Z80Flags,
    pub b: u8,
    pub c: u8,
    pub d: u8,
    pub e: u8,
    pub h: u8,
    pub l: u8,
    // Alternate register set
    pub a_alt: u8,
    pub f_alt: Z80Flags,
    pub b_alt: u8,
    pub c_alt: u8,
    pub d_alt: u8,
    pub e_alt: u8,
    pub h_alt: u8,
    pub l_alt: u8,
    // Index registers
    pub ix: u16,
    pub iy: u16,
    // Control registers
    pub sp: u16,
    pub pc: u16,
    pub i: u8,
    pub r: u8,
    // Interrupt mode (0, 1, or 2)
    pub im: u8,
    /// Interrupt flip-flop 1 (IFF1) — masks maskable interrupts.
    pub iff1: bool,
    /// Interrupt flip-flop 2 (IFF2) — saved during NMI.
    pub iff2: bool,
    /// Halted state.
    pub halted: bool,
}

impl Default for Z80RegFile {
    fn default() -> Self {
        Z80RegFile {
            a: 0xFF, f: Z80Flags(0xFF),
            b: 0, c: 0, d: 0, e: 0, h: 0, l: 0,
            a_alt: 0xFF, f_alt: Z80Flags(0xFF),
            b_alt: 0, c_alt: 0, d_alt: 0, e_alt: 0, h_alt: 0, l_alt: 0,
            ix: 0xFFFF, iy: 0xFFFF,
            sp: 0xFFFF, pc: 0,
            i: 0, r: 0, im: 0,
            iff1: false, iff2: false,
            halted: false,
        }
    }
}

impl Z80RegFile {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    // ── 16-bit pair accessors ────────────────────────────────────────────────

    #[must_use]
    pub fn bc(&self) -> u16 { u16::from(self.b) << 8 | u16::from(self.c) }
    #[must_use]
    pub fn de(&self) -> u16 { u16::from(self.d) << 8 | u16::from(self.e) }
    #[must_use]
    pub fn hl(&self) -> u16 { u16::from(self.h) << 8 | u16::from(self.l) }
    #[must_use]
    pub fn af(&self) -> u16 { u16::from(self.a) << 8 | u16::from(self.f.0) }

    pub const fn set_bc(&mut self, v: u16) { self.b = (v >> 8) as u8; self.c = (v & 0xFF) as u8; }
    pub const fn set_de(&mut self, v: u16) { self.d = (v >> 8) as u8; self.e = (v & 0xFF) as u8; }
    pub const fn set_hl(&mut self, v: u16) { self.h = (v >> 8) as u8; self.l = (v & 0xFF) as u8; }
    pub const fn set_af(&mut self, v: u16) { self.a = (v >> 8) as u8; self.f.0 = (v & 0xFF) as u8; }

    /// Read any 16-bit register pair.
    #[must_use]
    pub fn read_pair(&self, pair: Z80RegPair16) -> u16 {
        match pair {
            Z80RegPair16::BC => self.bc(),
            Z80RegPair16::DE => self.de(),
            Z80RegPair16::HL => self.hl(),
            Z80RegPair16::SP => self.sp,
            Z80RegPair16::IX => self.ix,
            Z80RegPair16::IY => self.iy,
            Z80RegPair16::AF => self.af(),
        }
    }

    /// Write any 16-bit register pair.
    pub fn write_pair(&mut self, pair: Z80RegPair16, v: u16) {
        match pair {
            Z80RegPair16::BC => self.set_bc(v),
            Z80RegPair16::DE => self.set_de(v),
            Z80RegPair16::HL => self.set_hl(v),
            Z80RegPair16::SP => self.sp = v,
            Z80RegPair16::IX => self.ix = v,
            Z80RegPair16::IY => self.iy = v,
            Z80RegPair16::AF => self.set_af(v),
        }
    }

    /// Read an 8-bit register (excluding (HL) — that is a memory reference).
    #[must_use]
    pub const fn read8(&self, r: Z80Reg) -> u8 {
        match r {
            Z80Reg::A   => self.a,
            Z80Reg::B   => self.b,
            Z80Reg::C   => self.c,
            Z80Reg::D   => self.d,
            Z80Reg::E   => self.e,
            Z80Reg::H   => self.h,
            Z80Reg::L   => self.l,
            Z80Reg::F   => self.f.0,
            Z80Reg::IXH => (self.ix >> 8) as u8,
            Z80Reg::IXL => (self.ix & 0xFF) as u8,
            Z80Reg::IYH => (self.iy >> 8) as u8,
            Z80Reg::IYL => (self.iy & 0xFF) as u8,
            Z80Reg::I   => self.i,
            Z80Reg::R   => self.r,
            Z80Reg::MemHL => 0, // caller must handle memory reference
        }
    }

    /// Write an 8-bit register.
    pub fn write8(&mut self, r: Z80Reg, v: u8) {
        match r {
            Z80Reg::A   => self.a = v,
            Z80Reg::B   => self.b = v,
            Z80Reg::C   => self.c = v,
            Z80Reg::D   => self.d = v,
            Z80Reg::E   => self.e = v,
            Z80Reg::H   => self.h = v,
            Z80Reg::L   => self.l = v,
            Z80Reg::F   => self.f.0 = v,
            Z80Reg::IXH => self.ix = (self.ix & 0x00FF) | (u16::from(v) << 8),
            Z80Reg::IXL => self.ix = (self.ix & 0xFF00) | u16::from(v),
            Z80Reg::IYH => self.iy = (self.iy & 0x00FF) | (u16::from(v) << 8),
            Z80Reg::IYL => self.iy = (self.iy & 0xFF00) | u16::from(v),
            Z80Reg::I   => self.i = v,
            Z80Reg::R   => self.r = v,
            Z80Reg::MemHL => {} // caller must handle memory reference
        }
    }

    // ── Exchange operations ──────────────────────────────────────────────────

    /// EX AF, AF' — exchange AF with alternate AF.
    pub const fn ex_af(&mut self) {
        std::mem::swap(&mut self.a, &mut self.a_alt);
        std::mem::swap(&mut self.f, &mut self.f_alt);
    }

    /// EXX — exchange BC, DE, HL with alternates.
    pub const fn exx(&mut self) {
        std::mem::swap(&mut self.b, &mut self.b_alt);
        std::mem::swap(&mut self.c, &mut self.c_alt);
        std::mem::swap(&mut self.d, &mut self.d_alt);
        std::mem::swap(&mut self.e, &mut self.e_alt);
        std::mem::swap(&mut self.h, &mut self.h_alt);
        std::mem::swap(&mut self.l, &mut self.l_alt);
    }

    /// EX DE, HL.
    pub const fn ex_de_hl(&mut self) {
        std::mem::swap(&mut self.d, &mut self.h);
        std::mem::swap(&mut self.e, &mut self.l);
    }

    /// Advance PC by `n` bytes.
    pub const fn advance_pc(&mut self, n: u16) {
        self.pc = self.pc.wrapping_add(n);
    }

    /// Dump to a string.
    #[must_use]
    pub fn dump(&self) -> String {
        format!(
            "AF={:04x} BC={:04x} DE={:04x} HL={:04x} IX={:04x} IY={:04x} SP={:04x} PC={:04x}\n\
             AF'={:02x}{:02x} BC'={:02x}{:02x} DE'={:02x}{:02x} HL'={:02x}{:02x}\n\
             I={:02x} R={:02x} IM={} IFF1={} IFF2={} F=[{}]",
            self.af(), self.bc(), self.de(), self.hl(),
            self.ix, self.iy, self.sp, self.pc,
            self.a_alt, self.f_alt.0,
            self.b_alt, self.c_alt, self.d_alt, self.e_alt, self.h_alt, self.l_alt,
            self.i, self.r, self.im, self.iff1, self.iff2,
            self.f,
        )
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reg_round_trip() {
        assert_eq!(Z80Reg::from_bits(0), Z80Reg::B);
        assert_eq!(Z80Reg::from_bits(7), Z80Reg::A);
        assert_eq!(Z80Reg::B.opcode_bits(), Some(0));
        assert_eq!(Z80Reg::A.opcode_bits(), Some(7));
        assert_eq!(Z80Reg::IXH.opcode_bits(), None);
    }

    #[test]
    fn pair_round_trip() {
        assert_eq!(Z80RegPair16::from_bits(0), Z80RegPair16::BC);
        assert_eq!(Z80RegPair16::from_bits(3), Z80RegPair16::SP);
        assert_eq!(Z80RegPair16::from_push_bits(3), Z80RegPair16::AF);
    }

    #[test]
    fn flags_add() {
        let mut f = Z80Flags::default();
        f.update_add8(0xFF, 0x01, false);
        assert!(f.z());
        assert!(f.c());
        assert!(!f.n());
    }

    #[test]
    fn flags_sub() {
        let mut f = Z80Flags::default();
        f.update_sub8(0x10, 0x01, false);
        assert!(!f.z());
        assert!(!f.c());
        assert!(f.n());
    }

    #[test]
    fn condition_codes() {
        let mut f = Z80Flags::default();
        f.set_z(true);
        assert!(f.condition_met(1));  // Z
        assert!(!f.condition_met(0)); // NZ
        f.set_c(true);
        assert!(f.condition_met(3));  // C
        assert!(!f.condition_met(2)); // NC
    }

    #[test]
    fn regfile_pair_access() {
        let mut rf = Z80RegFile::new();
        rf.set_hl(0x1234);
        assert_eq!(rf.h, 0x12);
        assert_eq!(rf.l, 0x34);
        assert_eq!(rf.hl(), 0x1234);
        rf.write_pair(Z80RegPair16::IX, 0xABCD);
        assert_eq!(rf.ix, 0xABCD);
    }

    #[test]
    fn regfile_ex_af() {
        let mut rf = Z80RegFile::new();
        rf.a = 0x11; rf.f.0 = 0x22;
        rf.a_alt = 0x33; rf.f_alt.0 = 0x44;
        rf.ex_af();
        assert_eq!(rf.a, 0x33); assert_eq!(rf.f.0, 0x44);
        assert_eq!(rf.a_alt, 0x11); assert_eq!(rf.f_alt.0, 0x22);
    }

    #[test]
    fn regfile_exx() {
        let mut rf = Z80RegFile::new();
        rf.set_hl(0x1234); rf.h_alt = 0x56; rf.l_alt = 0x78;
        rf.exx();
        assert_eq!(rf.hl(), 0x5678);
    }

    #[test]
    fn parity_check() {
        assert!(parity(0x00)); // 0 bits set → even parity
        assert!(!parity(0x01)); // 1 bit set → odd parity
        assert!(parity(0x03)); // 2 bits set → even parity
    }

    #[test]
    fn regfile_dump_contains_af() {
        let rf = Z80RegFile::new();
        let d = rf.dump();
        assert!(d.contains("AF="));
        assert!(d.contains("SP="));
    }
}
