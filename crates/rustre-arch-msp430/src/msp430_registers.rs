// msp430_registers.rs — MSP430 register file and status register
//
// Types: Msp430Reg, StatusReg, ConstGen, RegMode, Msp430RegFile.
// Models R0(PC), R1(SP), R2(SR/CG1), R3(CG2), R4-R15.
//
// Only std is used; no external crates.

use std::fmt;
use std::fmt::Write as _;

// ────────────────────────────────────────────────────────────────────────────
// Msp430Reg
// ────────────────────────────────────────────────────────────────────────────

/// MSP430 general-purpose register.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[repr(u8)]
pub enum Msp430Reg {
    R0  = 0,  // PC — Program Counter
    R1  = 1,  // SP — Stack Pointer
    R2  = 2,  // SR — Status Register / CG1
    R3  = 3,  // CG2 — Constant Generator 2
    R4  = 4,
    R5  = 5,
    R6  = 6,
    R7  = 7,
    R8  = 8,
    R9  = 9,
    R10 = 10,
    R11 = 11,
    R12 = 12,
    R13 = 13,
    R14 = 14,
    R15 = 15,
}

impl Msp430Reg {
    #[must_use] 
    pub const fn from_u8(n: u8) -> Option<Self> {
        match n & 0xf {
            0  => Some(Self::R0),  1  => Some(Self::R1),
            2  => Some(Self::R2),  3  => Some(Self::R3),
            4  => Some(Self::R4),  5  => Some(Self::R5),
            6  => Some(Self::R6),  7  => Some(Self::R7),
            8  => Some(Self::R8),  9  => Some(Self::R9),
            10 => Some(Self::R10), 11 => Some(Self::R11),
            12 => Some(Self::R12), 13 => Some(Self::R13),
            14 => Some(Self::R14), 15 => Some(Self::R15),
            _  => None,
        }
    }
    #[must_use] 
    pub const fn index(self) -> usize { self as usize }

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::R0  => "PC",
            Self::R1  => "SP",
            Self::R2  => "SR",
            Self::R3  => "CG2",
            Self::R4  => "R4",  Self::R5  => "R5",
            Self::R6  => "R6",  Self::R7  => "R7",
            Self::R8  => "R8",  Self::R9  => "R9",
            Self::R10 => "R10", Self::R11 => "R11",
            Self::R12 => "R12", Self::R13 => "R13",
            Self::R14 => "R14", Self::R15 => "R15",
        }
    }

    #[must_use] 
    pub fn is_pc(self)  -> bool { self == Self::R0 }
    #[must_use] 
    pub fn is_sp(self)  -> bool { self == Self::R1 }
    #[must_use] 
    pub fn is_sr(self)  -> bool { self == Self::R2 }
    #[must_use] 
    pub fn is_cg2(self) -> bool { self == Self::R3 }

    /// True if this is a general-purpose register (R4-R15).
    #[must_use] 
    pub const fn is_gp(self) -> bool { self as u8 >= 4 }

    /// All registers.
    #[must_use] 
    pub const fn all() -> [Self; 16] {
        [
            Self::R0,  Self::R1,  Self::R2,  Self::R3,
            Self::R4,  Self::R5,  Self::R6,  Self::R7,
            Self::R8,  Self::R9,  Self::R10, Self::R11,
            Self::R12, Self::R13, Self::R14, Self::R15,
        ]
    }

    /// General-purpose registers R4-R15.
    #[must_use] 
    pub const fn gp_regs() -> [Self; 12] {
        [
            Self::R4,  Self::R5,  Self::R6,  Self::R7,
            Self::R8,  Self::R9,  Self::R10, Self::R11,
            Self::R12, Self::R13, Self::R14, Self::R15,
        ]
    }
}

impl fmt::Display for Msp430Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.name()) }
}

// ────────────────────────────────────────────────────────────────────────────
// StatusReg
// ────────────────────────────────────────────────────────────────────────────

/// MSP430 Status Register (R2) bit fields.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct StatusReg(pub u16);

impl StatusReg {
    pub const C:    u16 = 0x0001; // Carry
    pub const Z:    u16 = 0x0002; // Zero
    pub const N:    u16 = 0x0004; // Negative
    pub const GIE:  u16 = 0x0008; // General interrupt enable
    pub const CPUOFF: u16 = 0x0010; // CPU off (LPM)
    pub const OSCOFF: u16 = 0x0020; // Oscillator off
    pub const SCG0: u16 = 0x0040; // System clock generator 0
    pub const SCG1: u16 = 0x0080; // System clock generator 1
    pub const V:    u16 = 0x0100; // Overflow

    #[must_use] 
    pub const fn carry(self)   -> bool { self.0 & Self::C != 0 }
    #[must_use] 
    pub const fn zero(self)    -> bool { self.0 & Self::Z != 0 }
    #[must_use] 
    pub const fn negative(self)-> bool { self.0 & Self::N != 0 }
    #[must_use] 
    pub const fn gie(self)     -> bool { self.0 & Self::GIE != 0 }
    #[must_use] 
    pub const fn cpuoff(self)  -> bool { self.0 & Self::CPUOFF != 0 }
    #[must_use] 
    pub const fn overflow(self)-> bool { self.0 & Self::V != 0 }

    pub const fn set_carry(&mut self, v: bool)    { self.set_bit(Self::C, v); }
    pub const fn set_zero(&mut self, v: bool)     { self.set_bit(Self::Z, v); }
    pub const fn set_negative(&mut self, v: bool) { self.set_bit(Self::N, v); }
    pub const fn set_gie(&mut self, v: bool)      { self.set_bit(Self::GIE, v); }
    pub const fn set_cpuoff(&mut self, v: bool)   { self.set_bit(Self::CPUOFF, v); }
    pub const fn set_overflow(&mut self, v: bool) { self.set_bit(Self::V, v); }

    const fn set_bit(&mut self, bit: u16, v: bool) {
        if v { self.0 |= bit; } else { self.0 &= !bit; }
    }

    /// Low power mode level (0 = active, 1-4 = LPM1-4).
    #[must_use] 
    pub fn lpm_level(self) -> u8 {
        let cpuoff = i32::from(self.cpuoff());
        let scg0 = i32::from(self.0 & Self::SCG0 != 0);
        let scg1 = i32::from(self.0 & Self::SCG1 != 0);
        let oscoff = i32::from(self.0 & Self::OSCOFF != 0);
        // LPM4 = CPUOFF + OSCOFF + SCG0 + SCG1
        // LPM3 = CPUOFF + SCG0 + SCG1
        // LPM2 = CPUOFF + SCG1
        // LPM1 = CPUOFF + SCG0
        // LPM0 = CPUOFF
        if oscoff == 1 && scg0 == 1 && scg1 == 1 && cpuoff == 1 { 4 }
        else if scg0 == 1 && scg1 == 1 && cpuoff == 1 { 3 }
        else if scg1 == 1 && cpuoff == 1 { 2 }
        else if scg0 == 1 && cpuoff == 1 { 1 }
        else if cpuoff == 1 { 0 } // LPM0 — only CPU stopped
        else { u8::MAX } // Active mode — CPU is running (not an LPM state)
    }

    /// Update N and Z flags from a 16-bit ALU result.
    pub const fn update_nz16(&mut self, result: u16) {
        self.set_zero(result == 0);
        self.set_negative(result & 0x8000 != 0);
    }
    /// Update N and Z flags from an 8-bit ALU result.
    pub const fn update_nz8(&mut self, result: u8) {
        self.set_zero(result == 0);
        self.set_negative(result & 0x80 != 0);
    }

    #[must_use] 
    pub const fn as_u16(self) -> u16 { self.0 }
}

impl fmt::Debug for StatusReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SR[V={} N={} Z={} C={} GIE={} CPUOFF={}]",
            u8::from(self.overflow()), u8::from(self.negative()),
            u8::from(self.zero()), u8::from(self.carry()),
            u8::from(self.gie()), u8::from(self.cpuoff()))
    }
}

impl fmt::Display for StatusReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Debug::fmt(self, f) }
}

// ────────────────────────────────────────────────────────────────────────────
// ConstGen
// ────────────────────────────────────────────────────────────────────────────

/// Constant Generator values (R2/R3 encoding).
///
/// The MSP430 constant generator allows encoding of six common
/// constants without an extension word.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ConstGen {
    Zero,       // R3 As=00
    PlusOne,    // R3 As=01
    PlusTwo,    // R3 As=10
    MinusOne,   // R3 As=11
    PlusFour,   // R2 As=10
    PlusEight,  // R2 As=11
}

impl ConstGen {
    /// Decode from (reg, `as_bits`).
    #[must_use] 
    pub const fn decode(reg: u8, as_bits: u8) -> Option<Self> {
        match (reg, as_bits) {
            (3, 0) => Some(Self::Zero),
            (3, 1) => Some(Self::PlusOne),
            (3, 2) => Some(Self::PlusTwo),
            (3, 3) => Some(Self::MinusOne),
            (2, 2) => Some(Self::PlusFour),
            (2, 3) => Some(Self::PlusEight),
            _      => None,
        }
    }

    #[must_use] 
    pub const fn value(self) -> i16 {
        match self {
            Self::Zero      => 0,
            Self::PlusOne   => 1,
            Self::PlusTwo   => 2,
            Self::MinusOne  => -1,
            Self::PlusFour  => 4,
            Self::PlusEight => 8,
        }
    }

    #[must_use] 
    pub const fn value_u16(self) -> u16 {
        self.value().cast_unsigned()
    }
}

impl fmt::Display for ConstGen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.value())
    }
}

// ────────────────────────────────────────────────────────────────────────────
// RegMode — addressing mode semantics
// ────────────────────────────────────────────────────────────────────────────

/// The effective behaviour of a register in an addressing mode.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum RegMode {
    /// Direct register read/write.
    Direct,
    /// Register holds a memory address; memory is accessed.
    Indirect,
    /// Indirect + auto-increment after access.
    IndirectAutoInc,
    /// Register + extension word offset.
    Indexed,
}

impl fmt::Display for RegMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct           => write!(f, "direct"),
            Self::Indirect         => write!(f, "indirect"),
            Self::IndirectAutoInc  => write!(f, "indirect++"),
            Self::Indexed          => write!(f, "indexed"),
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Msp430RegFile
// ────────────────────────────────────────────────────────────────────────────

/// Complete MSP430 register file.
///
/// R0 = PC, R1 = SP, R2 = SR, R3 = CG2 (constant, not generally writable),
/// R4-R15 = general-purpose.
#[derive(Clone, Debug)]
#[derive(Default)]
pub struct Msp430RegFile {
    /// All 16 registers (R0-R15).
    regs: [u16; 16],
}


impl Msp430RegFile {
    #[must_use] 
    pub fn new() -> Self { Self::default() }

    /// Read a register.
    #[must_use] 
    pub const fn read(&self, r: Msp430Reg) -> u16 {
        self.regs[r.index()]
    }

    /// Write a register.
    pub const fn write(&mut self, r: Msp430Reg, v: u16) {
        self.regs[r.index()] = v;
    }

    /// Read by number (0-15).
    #[must_use] 
    pub const fn read_n(&self, n: u8) -> u16 {
        self.regs[(n & 0xf) as usize]
    }

    /// Write by number (0-15).
    pub const fn write_n(&mut self, n: u8, v: u16) {
        self.regs[(n & 0xf) as usize] = v;
    }

    // ──── Specific register accessors ───────────────────────────────────────

    #[must_use] 
    pub const fn pc(&self) -> u16 { self.regs[0] }
    #[must_use] 
    pub const fn sp(&self) -> u16 { self.regs[1] }
    #[must_use] 
    pub const fn sr(&self) -> StatusReg { StatusReg(self.regs[2]) }

    pub const fn set_pc(&mut self, v: u16) { self.regs[0] = v; }
    pub const fn set_sp(&mut self, v: u16) { self.regs[1] = v; }
    pub const fn set_sr(&mut self, sr: StatusReg) { self.regs[2] = sr.as_u16(); }

    /// Increment PC by `n` bytes.
    pub const fn advance_pc(&mut self, n: u16) {
        self.regs[0] = self.regs[0].wrapping_add(n);
    }

    /// Push a word: SP -= 2, return new SP.
    pub const fn push(&mut self) -> u16 {
        self.regs[1] = self.regs[1].wrapping_sub(2);
        self.regs[1]
    }

    /// Pop a word: return old SP, SP += 2.
    pub const fn pop(&mut self) -> u16 {
        let addr = self.regs[1];
        self.regs[1] = self.regs[1].wrapping_add(2);
        addr
    }

    // ──── Status register helpers ─────────────────────────────────────────────

    pub const fn set_carry(&mut self, v: bool) {
        let mut sr = self.sr();
        sr.set_carry(v);
        self.set_sr(sr);
    }
    pub const fn set_zero(&mut self, v: bool) {
        let mut sr = self.sr();
        sr.set_zero(v);
        self.set_sr(sr);
    }
    pub const fn set_negative(&mut self, v: bool) {
        let mut sr = self.sr();
        sr.set_negative(v);
        self.set_sr(sr);
    }
    pub const fn set_overflow(&mut self, v: bool) {
        let mut sr = self.sr();
        sr.set_overflow(v);
        self.set_sr(sr);
    }
    pub const fn set_gie(&mut self, v: bool) {
        let mut sr = self.sr();
        sr.set_gie(v);
        self.set_sr(sr);
    }

    // ──── Named access ───────────────────────────────────────────────────────

    #[must_use] 
    pub fn get_named(&self, name: &str) -> Option<u16> {
        let upper = name.to_uppercase();
        match upper.as_str() {
            "PC" | "R0" => Some(self.regs[0]),
            "SP" | "R1" => Some(self.regs[1]),
            "SR" | "R2" => Some(self.regs[2]),
            "CG2" | "R3" => Some(self.regs[3]),
            _ => {
                if let Some(stripped) = upper.strip_prefix('R')
                    && let Ok(n) = stripped.parse::<u8>()
                        && n < 16 { return Some(self.regs[n as usize]); }
                None
            }
        }
    }

    pub fn set_named(&mut self, name: &str, value: u16) -> bool {
        let upper = name.to_uppercase();
        match upper.as_str() {
            "PC" | "R0" => { self.regs[0] = value; true }
            "SP" | "R1" => { self.regs[1] = value; true }
            "SR" | "R2" => { self.regs[2] = value; true }
            "CG2" | "R3" => { self.regs[3] = value; true }
            _ => {
                if let Some(stripped) = upper.strip_prefix('R')
                    && let Ok(n) = stripped.parse::<u8>()
                        && n < 16 { self.regs[n as usize] = value; return true; }
                false
            }
        }
    }

    /// Reset all registers to 0.
    pub const fn reset(&mut self) {
        self.regs = [0; 16];
    }

    /// Dump all register values.
    #[must_use] 
    pub fn dump(&self) -> String {
        // `fold` with `writeln!` instead of `map(format!).collect()`: it
        // reuses one buffer rather than allocating a String per register.
        // Writing to a String is infallible, so the Result carries no
        // information here.
        Msp430Reg::all().into_iter().fold(String::new(), |mut acc, r| {
            let _ = writeln!(acc, "{:4}: {:04X}", r.name(), self.regs[r.index()]);
            acc
        })
    }

    /// Return a snapshot of all register values.
    #[must_use] 
    pub const fn snapshot(&self) -> [u16; 16] { self.regs }

    /// Restore from a snapshot.
    pub const fn restore(&mut self, snap: [u16; 16]) { self.regs = snap; }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reg_names() {
        assert_eq!(Msp430Reg::R0.name(), "PC");
        assert_eq!(Msp430Reg::R1.name(), "SP");
        assert_eq!(Msp430Reg::R2.name(), "SR");
        assert_eq!(Msp430Reg::R3.name(), "CG2");
        assert_eq!(Msp430Reg::R15.name(), "R15");
    }

    #[test]
    fn test_reg_from_u8() {
        assert_eq!(Msp430Reg::from_u8(0), Some(Msp430Reg::R0));
        assert_eq!(Msp430Reg::from_u8(15), Some(Msp430Reg::R15));
    }

    #[test]
    fn test_status_reg_flags() {
        let mut sr = StatusReg::default();
        sr.set_carry(true);
        assert!(sr.carry());
        sr.set_zero(true);
        assert!(sr.zero());
        sr.update_nz16(0);
        assert!(sr.zero());
        assert!(!sr.negative());
        sr.update_nz16(0x8000);
        assert!(sr.negative());
    }

    #[test]
    fn test_lpm_level() {
        let mut sr = StatusReg::default();
        // Active mode: CPU running — u8::MAX sentinel means "not an LPM state".
        assert_eq!(sr.lpm_level(), u8::MAX);
        sr.set_cpuoff(true);
        // LPM0: only CPUOFF set.
        assert_eq!(sr.lpm_level(), 0);
    }

    #[test]
    fn test_const_gen() {
        assert_eq!(ConstGen::decode(3, 0), Some(ConstGen::Zero));
        assert_eq!(ConstGen::decode(3, 3), Some(ConstGen::MinusOne));
        assert_eq!(ConstGen::MinusOne.value(), -1);
        assert_eq!(ConstGen::PlusEight.value(), 8);
    }

    #[test]
    fn test_regfile_rw() {
        let mut rf = Msp430RegFile::new();
        rf.write(Msp430Reg::R5, 0xABCD);
        assert_eq!(rf.read(Msp430Reg::R5), 0xABCD);
        rf.set_pc(0x4000);
        assert_eq!(rf.pc(), 0x4000);
    }

    #[test]
    fn test_regfile_push_pop() {
        let mut rf = Msp430RegFile::new();
        rf.set_sp(0x0300);
        let sp = rf.push();
        assert_eq!(sp, 0x02FE);
        let old_sp = rf.pop();
        assert_eq!(old_sp, 0x02FE);
        assert_eq!(rf.sp(), 0x0300);
    }

    #[test]
    fn test_regfile_named() {
        let mut rf = Msp430RegFile::new();
        rf.set_named("R7", 0x1234);
        assert_eq!(rf.get_named("R7"), Some(0x1234));
        rf.set_named("PC", 0x4000);
        assert_eq!(rf.get_named("PC"), Some(0x4000));
    }

    #[test]
    fn test_regfile_snapshot() {
        let mut rf = Msp430RegFile::new();
        rf.write(Msp430Reg::R4, 42);
        let snap = rf.snapshot();
        rf.write(Msp430Reg::R4, 99);
        rf.restore(snap);
        assert_eq!(rf.read(Msp430Reg::R4), 42);
    }

    #[test]
    fn test_sr_set_and_retrieve() {
        let mut rf = Msp430RegFile::new();
        let mut sr = rf.sr();
        sr.set_carry(true);
        sr.set_gie(true);
        rf.set_sr(sr);
        let sr2 = rf.sr();
        assert!(sr2.carry());
        assert!(sr2.gie());
    }
}
