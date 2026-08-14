// m68k_registers.rs — Full M68000 register file
//
// Types: M68kDReg, M68kAReg, M68kSr, M68kCcr, M68kRegFile.
// Models D0-D7, A0-A7 (SP=A7), PC, SR, CCR, USP, MSP, ISP, VBR, SFC, DFC, CACR.
//
// Only std is used; no external crates.

use std::fmt;

// ────────────────────────────────────────────────────────────────────────────
// Register identifiers
// ────────────────────────────────────────────────────────────────────────────

/// M68000 data register D0-D7.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
#[repr(u8)]
pub enum M68kDReg { D0=0, D1, D2, D3, D4, D5, D6, D7 }

impl M68kDReg {
    pub fn from_u8(n: u8) -> Option<Self> {
        match n & 7 {
            0 => Some(M68kDReg::D0), 1 => Some(M68kDReg::D1),
            2 => Some(M68kDReg::D2), 3 => Some(M68kDReg::D3),
            4 => Some(M68kDReg::D4), 5 => Some(M68kDReg::D5),
            6 => Some(M68kDReg::D6), 7 => Some(M68kDReg::D7),
            _ => None,
        }
    }
    pub fn index(self) -> usize { self as usize }
    pub fn name(self) -> &'static str {
        match self {
            M68kDReg::D0 => "D0", M68kDReg::D1 => "D1",
            M68kDReg::D2 => "D2", M68kDReg::D3 => "D3",
            M68kDReg::D4 => "D4", M68kDReg::D5 => "D5",
            M68kDReg::D6 => "D6", M68kDReg::D7 => "D7",
        }
    }
    pub fn all() -> [M68kDReg; 8] {
        [M68kDReg::D0, M68kDReg::D1, M68kDReg::D2, M68kDReg::D3,
         M68kDReg::D4, M68kDReg::D5, M68kDReg::D6, M68kDReg::D7]
    }
}

impl fmt::Display for M68kDReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.name()) }
}

/// M68000 address register A0-A7 (A7 = SP in user mode).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
#[repr(u8)]
pub enum M68kAReg { A0=0, A1, A2, A3, A4, A5, A6, A7 }

impl M68kAReg {
    pub fn from_u8(n: u8) -> Option<Self> {
        match n & 7 {
            0 => Some(M68kAReg::A0), 1 => Some(M68kAReg::A1),
            2 => Some(M68kAReg::A2), 3 => Some(M68kAReg::A3),
            4 => Some(M68kAReg::A4), 5 => Some(M68kAReg::A5),
            6 => Some(M68kAReg::A6), 7 => Some(M68kAReg::A7),
            _ => None,
        }
    }
    pub fn index(self) -> usize { self as usize }
    pub fn name(self) -> &'static str {
        match self {
            M68kAReg::A0 => "A0", M68kAReg::A1 => "A1",
            M68kAReg::A2 => "A2", M68kAReg::A3 => "A3",
            M68kAReg::A4 => "A4", M68kAReg::A5 => "A5",
            M68kAReg::A6 => "A6", M68kAReg::A7 => "SP",
        }
    }
    pub fn is_sp(self) -> bool { self == M68kAReg::A7 }
    pub fn all() -> [M68kAReg; 8] {
        [M68kAReg::A0, M68kAReg::A1, M68kAReg::A2, M68kAReg::A3,
         M68kAReg::A4, M68kAReg::A5, M68kAReg::A6, M68kAReg::A7]
    }
}

impl fmt::Display for M68kAReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.name()) }
}

// ────────────────────────────────────────────────────────────────────────────
// M68kCcr — Condition Code Register (lower 5 bits of SR)
// ────────────────────────────────────────────────────────────────────────────

/// Condition Code Register — bits 0-4 of SR.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct M68kCcr(pub u8);

impl M68kCcr {
    pub const C_BIT: u8 = 0x01; // Carry
    pub const V_BIT: u8 = 0x02; // Overflow
    pub const Z_BIT: u8 = 0x04; // Zero
    pub const N_BIT: u8 = 0x08; // Negative
    pub const X_BIT: u8 = 0x10; // Extend

    pub fn carry(self)    -> bool { self.0 & Self::C_BIT != 0 }
    pub fn overflow(self) -> bool { self.0 & Self::V_BIT != 0 }
    pub fn zero(self)     -> bool { self.0 & Self::Z_BIT != 0 }
    pub fn negative(self) -> bool { self.0 & Self::N_BIT != 0 }
    pub fn extend(self)   -> bool { self.0 & Self::X_BIT != 0 }

    pub fn set_carry(&mut self, v: bool)    { self.set_bit(Self::C_BIT, v); }
    pub fn set_overflow(&mut self, v: bool) { self.set_bit(Self::V_BIT, v); }
    pub fn set_zero(&mut self, v: bool)     { self.set_bit(Self::Z_BIT, v); }
    pub fn set_negative(&mut self, v: bool) { self.set_bit(Self::N_BIT, v); }
    pub fn set_extend(&mut self, v: bool)   { self.set_bit(Self::X_BIT, v); }

    fn set_bit(&mut self, bit: u8, v: bool) {
        if v { self.0 |= bit; } else { self.0 &= !bit; }
    }

    /// Update N and Z flags from a 32-bit result.
    pub fn update_nz32(&mut self, result: u32) {
        self.set_negative(result & 0x8000_0000 != 0);
        self.set_zero(result == 0);
    }
    /// Update N and Z flags from a 16-bit result.
    pub fn update_nz16(&mut self, result: u16) {
        self.set_negative(result & 0x8000 != 0);
        self.set_zero(result == 0);
    }
    /// Update N and Z flags from an 8-bit result.
    pub fn update_nz8(&mut self, result: u8) {
        self.set_negative(result & 0x80 != 0);
        self.set_zero(result == 0);
    }

    pub fn as_u8(self) -> u8 { self.0 & 0x1f }
}

impl fmt::Debug for M68kCcr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CCR[X={} N={} Z={} V={} C={}]",
            self.extend() as u8, self.negative() as u8,
            self.zero() as u8, self.overflow() as u8, self.carry() as u8)
    }
}

impl fmt::Display for M68kCcr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// M68kSr — Status Register (16-bit)
// ────────────────────────────────────────────────────────────────────────────

/// Full Status Register.
///
/// Upper byte (supervisor byte): T1, T0, S, M, -, I2, I1, I0.
/// Lower byte: X, N, Z, V, C (same as CCR).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct M68kSr(pub u16);

impl M68kSr {
    // Supervisor byte bits
    pub const T1_BIT: u16 = 0x8000; // Trace mode bit 1 (trace on any instruction)
    pub const T0_BIT: u16 = 0x4000; // Trace mode bit 0 (trace on change of flow)
    pub const S_BIT:  u16 = 0x2000; // Supervisor state
    pub const M_BIT:  u16 = 0x1000; // Master/interrupt state (68020+)
    pub const I_MASK: u16 = 0x0700; // Interrupt priority mask
    pub const I_SHIFT: u32 = 8;

    pub fn trace1(self)      -> bool { self.0 & Self::T1_BIT != 0 }
    pub fn trace0(self)      -> bool { self.0 & Self::T0_BIT != 0 }
    pub fn supervisor(self)  -> bool { self.0 & Self::S_BIT != 0 }
    pub fn master(self)      -> bool { self.0 & Self::M_BIT != 0 }
    pub fn int_mask(self)    -> u8   { ((self.0 & Self::I_MASK) >> Self::I_SHIFT) as u8 }

    pub fn set_supervisor(&mut self, v: bool) {
        if v { self.0 |= Self::S_BIT; } else { self.0 &= !Self::S_BIT; }
    }
    pub fn set_int_mask(&mut self, level: u8) {
        self.0 = (self.0 & !Self::I_MASK) | (((level & 7) as u16) << Self::I_SHIFT);
    }

    /// Extract the CCR (lower byte, 5 bits).
    pub fn ccr(self) -> M68kCcr { M68kCcr((self.0 & 0x1f) as u8) }

    /// Merge a CCR value into the SR.
    pub fn set_ccr(&mut self, ccr: M68kCcr) {
        self.0 = (self.0 & 0xff00) | (ccr.as_u8() as u16);
    }

    pub fn as_u16(self) -> u16 { self.0 }
}

impl fmt::Debug for M68kSr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SR[T1={} T0={} S={} M={} I={} X={} N={} Z={} V={} C={}]",
            self.trace1() as u8, self.trace0() as u8,
            self.supervisor() as u8, self.master() as u8,
            self.int_mask(),
            self.ccr().extend() as u8, self.ccr().negative() as u8,
            self.ccr().zero() as u8, self.ccr().overflow() as u8,
            self.ccr().carry() as u8)
    }
}

impl fmt::Display for M68kSr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { fmt::Debug::fmt(self, f) }
}

// ────────────────────────────────────────────────────────────────────────────
// Supervisor / control registers
// ────────────────────────────────────────────────────────────────────────────

/// Supervisor stack pointer kind.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SpKind { Usp, Isp, Msp }

/// VBR — Vector Base Register (68010+).
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Vbr(pub u32);

/// CACR — Cache Control Register (68020+).
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Cacr(pub u32);

impl Cacr {
    pub const ENABLE_INSTR_CACHE: u32 = 0x0001;
    pub const FLUSH_INSTR_CACHE:  u32 = 0x0008;
    pub const ENABLE_DATA_CACHE:  u32 = 0x0100; // 68030
    pub fn instr_cache_enabled(self) -> bool { self.0 & Self::ENABLE_INSTR_CACHE != 0 }
    pub fn data_cache_enabled(self)  -> bool { self.0 & Self::ENABLE_DATA_CACHE != 0 }
}

/// SFC/DFC — Source/Destination Function Codes (68010+, 3-bit).
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct FunctionCode(pub u8);

impl FunctionCode {
    pub const USER_DATA: u8 = 1;
    pub const USER_PROG: u8 = 2;
    pub const SUPER_DATA: u8 = 5;
    pub const SUPER_PROG: u8 = 6;
    pub const CPU_SPACE: u8 = 7;
    pub fn as_u8(self) -> u8 { self.0 & 7 }
}

// ────────────────────────────────────────────────────────────────────────────
// M68kRegFile — the complete register file
// ────────────────────────────────────────────────────────────────────────────

/// Complete M68000 register file.
///
/// Contains D0-D7, A0-A7, PC, SR, USP, ISP (supervisor), MSP (master stack, 68020+),
/// VBR (68010+), SFC, DFC (68010+), CACR (68020+).
#[derive(Clone, Debug)]
pub struct M68kRegFile {
    /// Data registers D0-D7.
    pub d: [u32; 8],
    /// Address registers A0-A7. A7 is the active stack pointer.
    pub a: [u32; 8],
    /// Program counter.
    pub pc: u32,
    /// Status register.
    pub sr: M68kSr,
    /// User Stack Pointer (saved when in supervisor mode).
    pub usp: u32,
    /// Interrupt Stack Pointer (supervisor, 68010+).
    pub isp: u32,
    /// Master Stack Pointer (68020+ only).
    pub msp: u32,
    /// Vector Base Register (68010+).
    pub vbr: Vbr,
    /// Source Function Code (68010+).
    pub sfc: FunctionCode,
    /// Destination Function Code (68010+).
    pub dfc: FunctionCode,
    /// Cache Control Register (68020+).
    pub cacr: Cacr,
}

impl Default for M68kRegFile {
    fn default() -> Self {
        M68kRegFile {
            d: [0; 8], a: [0; 8], pc: 0,
            sr: M68kSr(0x2700), // supervisor, int mask=7
            usp: 0, isp: 0, msp: 0,
            vbr: Vbr(0), sfc: FunctionCode(0),
            dfc: FunctionCode(0), cacr: Cacr(0),
        }
    }
}

impl M68kRegFile {
    pub fn new() -> Self { Self::default() }

    // ──── Data registers ────────────────────────────────────────────────────

    pub fn dreg(&self, r: M68kDReg) -> u32 { self.d[r.index()] }
    pub fn dreg_n(&self, n: u8) -> u32 { self.d[(n & 7) as usize] }
    pub fn set_dreg(&mut self, r: M68kDReg, v: u32) { self.d[r.index()] = v; }
    pub fn set_dreg_n(&mut self, n: u8, v: u32) { self.d[(n & 7) as usize] = v; }

    /// Read data register as byte (bits 0-7).
    pub fn dreg_byte(&self, r: M68kDReg) -> u8 { self.d[r.index()] as u8 }
    /// Read data register as word (bits 0-15).
    pub fn dreg_word(&self, r: M68kDReg) -> u16 { self.d[r.index()] as u16 }

    /// Write lower 8 bits, preserving upper 24.
    pub fn set_dreg_byte(&mut self, r: M68kDReg, v: u8) {
        let cur = self.d[r.index()];
        self.d[r.index()] = (cur & 0xffff_ff00) | (v as u32);
    }
    /// Write lower 16 bits, preserving upper 16.
    pub fn set_dreg_word(&mut self, r: M68kDReg, v: u16) {
        let cur = self.d[r.index()];
        self.d[r.index()] = (cur & 0xffff_0000) | (v as u32);
    }

    // ──── Address registers ──────────────────────────────────────────────────

    pub fn areg(&self, r: M68kAReg) -> u32 { self.a[r.index()] }
    pub fn areg_n(&self, n: u8) -> u32 { self.a[(n & 7) as usize] }
    pub fn set_areg(&mut self, r: M68kAReg, v: u32) { self.a[r.index()] = v; }
    pub fn set_areg_n(&mut self, n: u8, v: u32) { self.a[(n & 7) as usize] = v; }

    /// Get the active stack pointer (A7).
    pub fn sp(&self) -> u32 { self.a[7] }
    pub fn set_sp(&mut self, v: u32) { self.a[7] = v; }

    // ──── Status register / CCR ──────────────────────────────────────────────

    pub fn ccr(&self) -> M68kCcr { self.sr.ccr() }
    pub fn set_ccr(&mut self, ccr: M68kCcr) { self.sr.set_ccr(ccr); }

    pub fn supervisor(&self) -> bool { self.sr.supervisor() }

    /// Switch to supervisor mode, saving USP.
    pub fn enter_supervisor(&mut self) {
        if !self.supervisor() {
            self.usp = self.a[7];
            self.a[7] = self.isp;
            self.sr.set_supervisor(true);
        }
    }

    /// Return to user mode, restoring USP.
    pub fn exit_supervisor(&mut self) {
        if self.supervisor() {
            self.isp = self.a[7];
            self.a[7] = self.usp;
            self.sr.set_supervisor(false);
        }
    }

    // ──── Stack operations ────────────────────────────────────────────────────

    /// Push 4 bytes to A7 (SP).
    pub fn push_long(&mut self) -> u32 {
        self.a[7] = self.a[7].wrapping_sub(4);
        self.a[7]
    }
    /// Pop 4 bytes from A7 (SP).
    pub fn pop_long(&mut self) -> u32 {
        let addr = self.a[7];
        self.a[7] = self.a[7].wrapping_add(4);
        addr
    }
    /// Push 2 bytes to A7 (SP).
    pub fn push_word(&mut self) -> u32 {
        self.a[7] = self.a[7].wrapping_sub(2);
        self.a[7]
    }
    /// Pop 2 bytes from A7 (SP).
    pub fn pop_word(&mut self) -> u32 {
        let addr = self.a[7];
        self.a[7] = self.a[7].wrapping_add(2);
        addr
    }

    // ──── Control registers ───────────────────────────────────────────────────

    pub fn vbr(&self) -> u32 { self.vbr.0 }
    pub fn set_vbr(&mut self, v: u32) { self.vbr.0 = v; }

    // ──── Misc ────────────────────────────────────────────────────────────────

    /// Reset all registers to power-on state.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Format a named register by string (e.g. "D0", "A7", "PC", "SR").
    pub fn get_named(&self, name: &str) -> Option<u32> {
        let upper = name.to_uppercase();
        if upper.starts_with('D') {
            let n: u8 = upper[1..].parse().ok()?;
            if n > 7 { return None; }
            return Some(self.d[n as usize]);
        }
        if upper.starts_with('A') {
            let n: u8 = upper[1..].parse().ok()?;
            if n > 7 { return None; }
            return Some(self.a[n as usize]);
        }
        match upper.as_str() {
            "PC"  => Some(self.pc),
            "SR"  => Some(self.sr.as_u16() as u32),
            "CCR" => Some(self.ccr().as_u8() as u32),
            "USP" => Some(self.usp),
            "ISP" | "SSP" => Some(self.isp),
            "MSP" => Some(self.msp),
            "VBR" => Some(self.vbr.0),
            "SFC" => Some(self.sfc.as_u8() as u32),
            "DFC" => Some(self.dfc.as_u8() as u32),
            "CACR"=> Some(self.cacr.0),
            "SP"  => Some(self.a[7]),
            _     => None,
        }
    }

    pub fn set_named(&mut self, name: &str, value: u32) -> bool {
        let upper = name.to_uppercase();
        if upper.starts_with('D') {
            if let Ok(n) = upper[1..].parse::<u8>() {
                if n <= 7 { self.d[n as usize] = value; return true; }
            }
            return false;
        }
        if upper.starts_with('A') {
            if let Ok(n) = upper[1..].parse::<u8>() {
                if n <= 7 { self.a[n as usize] = value; return true; }
            }
            return false;
        }
        match upper.as_str() {
            "PC"   => { self.pc = value; true }
            "SR"   => { self.sr = M68kSr(value as u16); true }
            "CCR"  => { self.set_ccr(M68kCcr(value as u8)); true }
            "USP"  => { self.usp = value; true }
            "ISP" | "SSP" => { self.isp = value; true }
            "MSP"  => { self.msp = value; true }
            "VBR"  => { self.vbr.0 = value; true }
            "SFC"  => { self.sfc = FunctionCode(value as u8); true }
            "DFC"  => { self.dfc = FunctionCode(value as u8); true }
            "CACR" => { self.cacr.0 = value; true }
            "SP"   => { self.a[7] = value; true }
            _      => false,
        }
    }

    /// Dump all register values as a formatted string.
    pub fn dump(&self) -> String {
        let mut s = String::new();
        s.push_str("D registers:\n");
        for i in 0..8 {
            s.push_str(&format!("  D{}: {:08X}\n", i, self.d[i]));
        }
        s.push_str("A registers:\n");
        for i in 0..7 {
            s.push_str(&format!("  A{}: {:08X}\n", i, self.a[i]));
        }
        s.push_str(&format!("  SP: {:08X}\n", self.a[7]));
        s.push_str(&format!("PC:  {:08X}\n", self.pc));
        s.push_str(&format!("{}\n", self.sr));
        s.push_str(&format!("USP: {:08X}  ISP: {:08X}  MSP: {:08X}\n",
            self.usp, self.isp, self.msp));
        s.push_str(&format!("VBR: {:08X}  SFC: {}  DFC: {}  CACR: {:08X}\n",
            self.vbr.0, self.sfc.0, self.dfc.0, self.cacr.0));
        s
    }
}

// ────────────────────────────────────────────────────────────────────────────
// RegList — MOVEM register list bitmask
// ────────────────────────────────────────────────────────────────────────────

/// Register list bitmask used by MOVEM.
///
/// For predecrement (ea=-(An)): D7 is bit 0, D0 is bit 7, A7 is bit 8, A0 is bit 15.
/// For all other modes: D0 is bit 0, D7 is bit 7, A0 is bit 8, A7 is bit 15.
#[derive(Clone, Copy, Default, Debug)]
pub struct RegList(pub u16);

impl RegList {
    /// Standard mode: D0=bit0 .. D7=bit7, A0=bit8 .. A7=bit15.
    pub fn data_regs(self) -> [bool; 8] {
        let mut r = [false; 8];
        for i in 0..8 { r[i] = (self.0 >> i) & 1 == 1; }
        r
    }
    pub fn addr_regs(self) -> [bool; 8] {
        let mut r = [false; 8];
        for i in 0..8 { r[i] = (self.0 >> (i + 8)) & 1 == 1; }
        r
    }
    pub fn count(self) -> u32 { self.0.count_ones() }

    /// Predecrement form: D7=bit0 .. D0=bit7, A7=bit8 .. A0=bit15.
    pub fn data_regs_predec(self) -> [bool; 8] {
        let mut r = [false; 8];
        for i in 0..8 { r[7-i] = (self.0 >> i) & 1 == 1; }
        r
    }
    pub fn addr_regs_predec(self) -> [bool; 8] {
        let mut r = [false; 8];
        for i in 0..8 { r[7-i] = (self.0 >> (i + 8)) & 1 == 1; }
        r
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dreg_enum() {
        assert_eq!(M68kDReg::from_u8(0), Some(M68kDReg::D0));
        assert_eq!(M68kDReg::from_u8(7), Some(M68kDReg::D7));
        assert_eq!(M68kDReg::D3.name(), "D3");
    }

    #[test]
    fn test_areg_enum() {
        assert_eq!(M68kAReg::from_u8(7), Some(M68kAReg::A7));
        assert!(M68kAReg::A7.is_sp());
        assert_eq!(M68kAReg::A7.name(), "SP");
    }

    #[test]
    fn test_ccr_flags() {
        let mut ccr = M68kCcr::default();
        ccr.set_carry(true);
        assert!(ccr.carry());
        assert!(!ccr.zero());
        ccr.update_nz32(0);
        assert!(ccr.zero());
        assert!(!ccr.negative());
        ccr.update_nz32(0x80000000);
        assert!(ccr.negative());
        assert!(!ccr.zero());
    }

    #[test]
    fn test_sr_supervisor() {
        let mut sr = M68kSr(0x2000); // S bit set
        assert!(sr.supervisor());
        sr.set_int_mask(3);
        assert_eq!(sr.int_mask(), 3);
    }

    #[test]
    fn test_regfile_default() {
        let rf = M68kRegFile::new();
        assert_eq!(rf.pc, 0);
        assert!(rf.supervisor());
        assert_eq!(rf.sr.int_mask(), 7);
    }

    #[test]
    fn test_regfile_dreg_rw() {
        let mut rf = M68kRegFile::new();
        rf.set_dreg(M68kDReg::D3, 0xDEADBEEF);
        assert_eq!(rf.dreg(M68kDReg::D3), 0xDEADBEEF);
        rf.set_dreg_byte(M68kDReg::D3, 0xAA);
        assert_eq!(rf.dreg(M68kDReg::D3), 0xDEADBEAA);
        rf.set_dreg_word(M68kDReg::D3, 0x1234);
        assert_eq!(rf.dreg(M68kDReg::D3), 0xDEAD1234);
    }

    #[test]
    fn test_regfile_areg_rw() {
        let mut rf = M68kRegFile::new();
        rf.set_areg(M68kAReg::A5, 0x100000);
        assert_eq!(rf.areg(M68kAReg::A5), 0x100000);
    }

    #[test]
    fn test_regfile_sp() {
        let mut rf = M68kRegFile::new();
        // 0x00100000 → push_long decrements by 4 → 0x000FFFFC
        rf.set_sp(0x00100000);
        assert_eq!(rf.sp(), 0x00100000);
        let addr = rf.push_long();
        assert_eq!(addr, 0x00FFFFC);
        let pop = rf.pop_long();
        assert_eq!(pop, 0x00FFFFC);
        assert_eq!(rf.sp(), 0x00100000);
    }

    #[test]
    fn test_regfile_supervisor_switch() {
        let mut rf = M68kRegFile::new();
        rf.set_sp(0xFF0000);
        rf.usp = 0xEE0000;
        rf.exit_supervisor();
        assert!(!rf.supervisor());
        assert_eq!(rf.sp(), 0xEE0000);
        rf.enter_supervisor();
        assert!(rf.supervisor());
    }

    #[test]
    fn test_named_access() {
        let mut rf = M68kRegFile::new();
        rf.set_named("D4", 0xABCD);
        assert_eq!(rf.get_named("D4"), Some(0xABCD));
        rf.set_named("PC", 0x401000);
        assert_eq!(rf.get_named("PC"), Some(0x401000));
    }

    #[test]
    fn test_reglist_count() {
        let rl = RegList(0b0000_0000_0000_1111); // D0-D3
        assert_eq!(rl.count(), 4);
        let dr = rl.data_regs();
        assert!(dr[0] && dr[1] && dr[2] && dr[3] && !dr[4]);
    }

    #[test]
    fn test_cacr_flags() {
        let c = Cacr(Cacr::ENABLE_INSTR_CACHE);
        assert!(c.instr_cache_enabled());
        assert!(!c.data_cache_enabled());
    }
}
