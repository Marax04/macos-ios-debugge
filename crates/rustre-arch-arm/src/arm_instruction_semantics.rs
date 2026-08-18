//! `arm_instruction_semantics` — Complete ARM instruction semantic model.
//!
//! Covers:
//! - All 16 ARM condition codes
//! - Flag computation (NZCV) for all ALU operations
//! - Barrel shifter (LSL/LSR/ASR/ROR/RRX)
//! - CPSR / SPSR bit manipulation
//! - Memory ordering (barriers: DMB/DSB/ISB)
//! - Exclusive monitors (LDREX/STREX)
//! - Thumb interworking and BX/BLX semantics

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Condition codes
// ---------------------------------------------------------------------------

/// All 16 ARM condition codes (4-bit encoding in instruction bits [31:28]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ConditionCode {
    /// Equal — Z == 1
    EQ = 0b0000,
    /// Not Equal — Z == 0
    NE = 0b0001,
    /// Carry Set / Unsigned Higher or Same — C == 1
    CS = 0b0010,
    /// Carry Clear / Unsigned Lower — C == 0
    CC = 0b0011,
    /// Minus / Negative — N == 1
    MI = 0b0100,
    /// Plus / Positive or Zero — N == 0
    PL = 0b0101,
    /// Overflow — V == 1
    VS = 0b0110,
    /// No Overflow — V == 0
    VC = 0b0111,
    /// Unsigned Higher — C == 1 AND Z == 0
    HI = 0b1000,
    /// Unsigned Lower or Same — C == 0 OR Z == 1
    LS = 0b1001,
    /// Signed Greater or Equal — N == V
    GE = 0b1010,
    /// Signed Less Than — N != V
    LT = 0b1011,
    /// Signed Greater Than — Z == 0 AND N == V
    GT = 0b1100,
    /// Signed Less or Equal — Z == 1 OR N != V
    LE = 0b1101,
    /// Always (unconditional)
    AL = 0b1110,
    /// Never / Unconditional extended (some architectures)
    NV = 0b1111,
}

impl ConditionCode {
    /// Decode from the 4-bit encoding in an instruction word.
    #[must_use]
    pub fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0xF {
            0b0000 => Some(Self::EQ),
            0b0001 => Some(Self::NE),
            0b0010 => Some(Self::CS),
            0b0011 => Some(Self::CC),
            0b0100 => Some(Self::MI),
            0b0101 => Some(Self::PL),
            0b0110 => Some(Self::VS),
            0b0111 => Some(Self::VC),
            0b1000 => Some(Self::HI),
            0b1001 => Some(Self::LS),
            0b1010 => Some(Self::GE),
            0b1011 => Some(Self::LT),
            0b1100 => Some(Self::GT),
            0b1101 => Some(Self::LE),
            0b1110 => Some(Self::AL),
            0b1111 => Some(Self::NV),
            _ => unreachable!(),
        }
    }

    /// The bit-encoding value.
    #[must_use]
    pub const fn encoding(self) -> u8 {
        self as u8
    }

    /// Human-readable suffix used in mnemonics.
    #[must_use]
    pub const fn mnemonic(self) -> &'static str {
        match self {
            Self::EQ => "eq",
            Self::NE => "ne",
            Self::CS => "cs",
            Self::CC => "cc",
            Self::MI => "mi",
            Self::PL => "pl",
            Self::VS => "vs",
            Self::VC => "vc",
            Self::HI => "hi",
            Self::LS => "ls",
            Self::GE => "ge",
            Self::LT => "lt",
            Self::GT => "gt",
            Self::LE => "le",
            Self::AL => "",
            Self::NV => "nv",
        }
    }

    /// Evaluate the condition against a [`CpsrFlags`] snapshot.
    #[must_use]
    pub fn evaluate(self, flags: CpsrFlags) -> bool {
        let n = flags.n();
        let z = flags.z();
        let c = flags.c();
        let v = flags.v();
        match self {
            Self::EQ => z,
            Self::NE => !z,
            Self::CS => c,
            Self::CC => !c,
            Self::MI => n,
            Self::PL => !n,
            Self::VS => v,
            Self::VC => !v,
            Self::HI => c && !z,
            Self::LS => !c || z,
            Self::GE => n == v,
            Self::LT => n != v,
            Self::GT => !z && (n == v),
            Self::LE => z || (n != v),
            Self::AL | Self::NV => true,
        }
    }

    /// Returns the inverse/opposite condition (swap last bit).
    #[must_use]
    pub fn invert(self) -> Self {
        Self::from_bits(self.encoding() ^ 1).unwrap()
    }
}

impl fmt::Display for ConditionCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.mnemonic())
    }
}

// ---------------------------------------------------------------------------
// CPSR / SPSR bit layout
// ---------------------------------------------------------------------------

/// Bit positions within CPSR/SPSR.
pub mod cpsr_bits {
    pub const N: u32 = 31;
    pub const Z: u32 = 30;
    pub const C: u32 = 29;
    pub const V: u32 = 28;
    pub const Q: u32 = 27;
    pub const J: u32 = 24;
    pub const GE_HI: u32 = 19;
    pub const GE_LO: u32 = 16;
    pub const E: u32 = 9;
    pub const A: u32 = 8;
    pub const I: u32 = 7;
    pub const F: u32 = 6;
    pub const T: u32 = 5;
    pub const MODE_HI: u32 = 4;
    pub const MODE_LO: u32 = 0;

    pub const NZCV_MASK: u32 = 0xF000_0000;
    pub const GE_MASK: u32 = 0x000F_0000;
    pub const MODE_MASK: u32 = 0x0000_001F;
    pub const IT_MASK: u32 = 0x0600_FC00;
}

/// Snapshot of the NZCV condition flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash, Serialize, Deserialize)]
pub struct CpsrFlags {
    raw: u32,
}

impl CpsrFlags {
    /// Construct from raw CPSR value.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self { raw }
    }

    /// Construct from individual flag values.
    #[must_use]
    pub const fn from_flags(n: bool, z: bool, c: bool, v: bool) -> Self {
        let mut raw = 0u32;
        if n { raw |= 1 << cpsr_bits::N; }
        if z { raw |= 1 << cpsr_bits::Z; }
        if c { raw |= 1 << cpsr_bits::C; }
        if v { raw |= 1 << cpsr_bits::V; }
        Self { raw }
    }

    #[must_use]
    pub const fn raw(self) -> u32 { self.raw }
    #[must_use]
    pub const fn n(self) -> bool { (self.raw >> cpsr_bits::N) & 1 != 0 }
    #[must_use]
    pub const fn z(self) -> bool { (self.raw >> cpsr_bits::Z) & 1 != 0 }
    #[must_use]
    pub const fn c(self) -> bool { (self.raw >> cpsr_bits::C) & 1 != 0 }
    #[must_use]
    pub const fn v(self) -> bool { (self.raw >> cpsr_bits::V) & 1 != 0 }
    #[must_use]
    pub const fn q(self) -> bool { (self.raw >> cpsr_bits::Q) & 1 != 0 }
    #[must_use]
    pub const fn t(self) -> bool { (self.raw >> cpsr_bits::T) & 1 != 0 }

    /// Processor mode field (bits [4:0]).
    #[must_use]
    pub fn mode(self) -> ProcessorMode {
        ProcessorMode::from_bits((self.raw & cpsr_bits::MODE_MASK) as u8)
    }

    /// GE flags (bits [19:16]).
    #[must_use]
    pub const fn ge(self) -> u8 {
        ((self.raw & cpsr_bits::GE_MASK) >> cpsr_bits::GE_LO) as u8
    }

    /// Update only the NZCV bits in this flags snapshot.
    #[must_use]
    pub const fn with_nzcv(self, n: bool, z: bool, c: bool, v: bool) -> Self {
        let mut raw = self.raw & !cpsr_bits::NZCV_MASK;
        if n { raw |= 1 << cpsr_bits::N; }
        if z { raw |= 1 << cpsr_bits::Z; }
        if c { raw |= 1 << cpsr_bits::C; }
        if v { raw |= 1 << cpsr_bits::V; }
        Self { raw }
    }

    /// Set or clear the Thumb bit (T).
    #[must_use]
    pub const fn with_thumb(self, thumb: bool) -> Self {
        if thumb {
            Self { raw: self.raw | (1 << cpsr_bits::T) }
        } else {
            Self { raw: self.raw & !(1 << cpsr_bits::T) }
        }
    }

    /// Set the processor mode.
    #[must_use]
    pub fn with_mode(self, mode: ProcessorMode) -> Self {
        let raw = (self.raw & !cpsr_bits::MODE_MASK) | (mode.encoding() as u32);
        Self { raw }
    }

    /// Mask to disable IRQ (set I bit).
    #[must_use]
    pub const fn with_irq_disabled(self, disable: bool) -> Self {
        if disable {
            Self { raw: self.raw | (1 << cpsr_bits::I) }
        } else {
            Self { raw: self.raw & !(1 << cpsr_bits::I) }
        }
    }
}

impl fmt::Display for CpsrFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}{}{}",
            if self.n() { 'N' } else { 'n' },
            if self.z() { 'Z' } else { 'z' },
            if self.c() { 'C' } else { 'c' },
            if self.v() { 'V' } else { 'v' },
        )
    }
}

// ---------------------------------------------------------------------------
// Processor modes
// ---------------------------------------------------------------------------

/// ARM processor modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ProcessorMode {
    User       = 0b10000,
    Fiq        = 0b10001,
    Irq        = 0b10010,
    Supervisor = 0b10011,
    Monitor    = 0b10110,
    Abort      = 0b10111,
    Hypervisor = 0b11010,
    Undefined  = 0b11011,
    System     = 0b11111,
}

impl ProcessorMode {
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        match bits & 0x1F {
            0b10000 => Self::User,
            0b10001 => Self::Fiq,
            0b10010 => Self::Irq,
            0b10011 => Self::Supervisor,
            0b10110 => Self::Monitor,
            0b10111 => Self::Abort,
            0b11010 => Self::Hypervisor,
            0b11011 => Self::Undefined,
            0b11111 => Self::System,
            _ => Self::User,
        }
    }

    #[must_use]
    pub const fn encoding(self) -> u8 { self as u8 }

    #[must_use]
    pub const fn is_privileged(self) -> bool {
        !matches!(self, Self::User)
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::User => "usr",
            Self::Fiq => "fiq",
            Self::Irq => "irq",
            Self::Supervisor => "svc",
            Self::Monitor => "mon",
            Self::Abort => "abt",
            Self::Hypervisor => "hyp",
            Self::Undefined => "und",
            Self::System => "sys",
        }
    }

    /// Whether this mode has its own banked SPSR.
    #[must_use]
    pub const fn has_spsr(self) -> bool {
        !matches!(self, Self::User | Self::System)
    }
}

// ---------------------------------------------------------------------------
// Barrel shifter
// ---------------------------------------------------------------------------

/// Shift type encoded in instruction bits [6:5].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ShiftType {
    /// Logical Shift Left
    LSL = 0b00,
    /// Logical Shift Right
    LSR = 0b01,
    /// Arithmetic Shift Right
    ASR = 0b10,
    /// Rotate Right (amount=0 means RRX)
    ROR = 0b11,
}

impl ShiftType {
    #[must_use]
    pub fn from_bits(bits: u8) -> Self {
        match bits & 3 {
            0 => Self::LSL,
            1 => Self::LSR,
            2 => Self::ASR,
            3 => Self::ROR,
            _ => unreachable!(),
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::LSL => "lsl",
            Self::LSR => "lsr",
            Self::ASR => "asr",
            Self::ROR => "ror",
        }
    }
}

/// Result of the barrel shifter: shifted value and carry-out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShifterResult {
    pub value: u32,
    pub carry_out: bool,
}

/// The ARM barrel shifter — produces a shifted value and carry-out bit.
pub struct BarrelShifter;

impl BarrelShifter {
    /// Apply `shift_type` with immediate `amount` to `value`, given current C flag.
    #[must_use]
    pub fn shift_immediate(
        value: u32,
        shift_type: ShiftType,
        amount: u32,
        carry_in: bool,
    ) -> ShifterResult {
        if amount == 0 && shift_type == ShiftType::LSL {
            return ShifterResult { value, carry_out: carry_in };
        }
        match shift_type {
            ShiftType::LSL => Self::lsl(value, amount, carry_in),
            ShiftType::LSR => Self::lsr(value, amount, carry_in),
            ShiftType::ASR => Self::asr(value, amount, carry_in),
            ShiftType::ROR => {
                if amount == 0 {
                    Self::rrx(value, carry_in)
                } else {
                    Self::ror(value, amount)
                }
            }
        }
    }

    /// Logical shift left.
    #[must_use]
    pub const fn lsl(value: u32, amount: u32, carry_in: bool) -> ShifterResult {
        if amount == 0 {
            return ShifterResult { value, carry_out: carry_in };
        }
        if amount >= 32 {
            let carry_out = if amount == 32 { (value & 1) != 0 } else { false };
            return ShifterResult { value: 0, carry_out };
        }
        let carry_out = ((value >> (32 - amount)) & 1) != 0;
        ShifterResult { value: value << amount, carry_out }
    }

    /// Logical shift right.
    #[must_use]
    pub const fn lsr(value: u32, amount: u32, carry_in: bool) -> ShifterResult {
        if amount == 0 {
            return ShifterResult { value, carry_out: carry_in };
        }
        if amount >= 32 {
            let carry_out = if amount == 32 { (value >> 31) != 0 } else { false };
            return ShifterResult { value: 0, carry_out };
        }
        let carry_out = ((value >> (amount - 1)) & 1) != 0;
        ShifterResult { value: value >> amount, carry_out }
    }

    /// Arithmetic shift right.
    #[must_use]
    pub const fn asr(value: u32, amount: u32, carry_in: bool) -> ShifterResult {
        if amount == 0 {
            return ShifterResult { value, carry_out: carry_in };
        }
        let signed = value as i32;
        if amount >= 32 {
            let result = if signed < 0 { u32::MAX } else { 0 };
            let carry_out = (value >> 31) != 0;
            return ShifterResult { value: result, carry_out };
        }
        let carry_out = ((value >> (amount - 1)) & 1) != 0;
        ShifterResult { value: (signed >> amount) as u32, carry_out }
    }

    /// Rotate right.
    #[must_use]
    pub const fn ror(value: u32, amount: u32) -> ShifterResult {
        let amount = amount & 31;
        if amount == 0 {
            let carry_out = (value >> 31) != 0;
            return ShifterResult { value, carry_out };
        }
        let result = value.rotate_right(amount);
        let carry_out = ((result >> 31) & 1) != 0;
        ShifterResult { value: result, carry_out }
    }

    /// Rotate right extended (RRX) — 33-bit rotate through carry.
    #[must_use]
    pub const fn rrx(value: u32, carry_in: bool) -> ShifterResult {
        let carry_out = (value & 1) != 0;
        let result = (value >> 1) | ((carry_in as u32) << 31);
        ShifterResult { value: result, carry_out }
    }
}

// ---------------------------------------------------------------------------
// ALU flag computation
// ---------------------------------------------------------------------------

/// Result of an ALU operation with full flag computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AluResult {
    pub value: u32,
    pub n: bool,
    pub z: bool,
    pub c: bool,
    pub v: bool,
}

impl AluResult {
    #[must_use]
    pub fn to_flags(self) -> CpsrFlags {
        CpsrFlags::from_flags(self.n, self.z, self.c, self.v)
    }
}

/// ARM ALU semantic operations with full NZCV computation.
pub struct AluOps;

impl AluOps {
    const fn nz(value: u32) -> (bool, bool) {
        ((value >> 31) != 0, value == 0)
    }

    /// ADD — a + b, updates NZCV.
    #[must_use]
    pub fn add(a: u32, b: u32) -> AluResult {
        let result64 = (a as u64).wrapping_add(b as u64);
        let value = result64 as u32;
        let (n, z) = Self::nz(value);
        let c = result64 > u32::MAX as u64;
        let v = ((!(a ^ b)) & (a ^ value) & 0x8000_0000) != 0;
        AluResult { value, n, z, c, v }
    }

    /// ADD with carry.
    #[must_use]
    pub fn adc(a: u32, b: u32, carry_in: bool) -> AluResult {
        let result64 = (a as u64).wrapping_add(b as u64).wrapping_add(carry_in as u64);
        let value = result64 as u32;
        let (n, z) = Self::nz(value);
        let c = result64 > u32::MAX as u64;
        let v = ((!(a ^ b)) & (a ^ value) & 0x8000_0000) != 0;
        AluResult { value, n, z, c, v }
    }

    /// SUB — a - b, updates NZCV.
    #[must_use]
    pub fn sub(a: u32, b: u32) -> AluResult {
        Self::add(a, (!b).wrapping_add(1))
    }

    /// SUB with borrow (SBC).
    #[must_use]
    pub fn sbc(a: u32, b: u32, carry_in: bool) -> AluResult {
        Self::adc(a, !b, carry_in)
    }

    /// RSB — b - a (reverse subtract).
    #[must_use]
    pub fn rsb(a: u32, b: u32) -> AluResult {
        Self::sub(b, a)
    }

    /// AND — bitwise, updates NZ, C from shifter, V unchanged.
    #[must_use]
    pub fn and(a: u32, b: u32, shifter_carry: bool, old_v: bool) -> AluResult {
        let value = a & b;
        let (n, z) = Self::nz(value);
        AluResult { value, n, z, c: shifter_carry, v: old_v }
    }

    /// ORR — bitwise OR.
    #[must_use]
    pub fn orr(a: u32, b: u32, shifter_carry: bool, old_v: bool) -> AluResult {
        let value = a | b;
        let (n, z) = Self::nz(value);
        AluResult { value, n, z, c: shifter_carry, v: old_v }
    }

    /// EOR — exclusive OR.
    #[must_use]
    pub fn eor(a: u32, b: u32, shifter_carry: bool, old_v: bool) -> AluResult {
        let value = a ^ b;
        let (n, z) = Self::nz(value);
        AluResult { value, n, z, c: shifter_carry, v: old_v }
    }

    /// BIC — bit clear (a AND NOT b).
    #[must_use]
    pub fn bic(a: u32, b: u32, shifter_carry: bool, old_v: bool) -> AluResult {
        let value = a & !b;
        let (n, z) = Self::nz(value);
        AluResult { value, n, z, c: shifter_carry, v: old_v }
    }

    /// MOV — move (sets NZ, C from shifter).
    #[must_use]
    pub fn mov(b: u32, shifter_carry: bool, old_v: bool) -> AluResult {
        let (n, z) = Self::nz(b);
        AluResult { value: b, n, z, c: shifter_carry, v: old_v }
    }

    /// MVN — move NOT.
    #[must_use]
    pub fn mvn(b: u32, shifter_carry: bool, old_v: bool) -> AluResult {
        Self::mov(!b, shifter_carry, old_v)
    }

    /// CMP — compare (same as SUB but result discarded).
    #[must_use]
    pub fn cmp(a: u32, b: u32) -> AluResult {
        Self::sub(a, b)
    }

    /// CMN — compare negative (same as ADD but result discarded).
    #[must_use]
    pub fn cmn(a: u32, b: u32) -> AluResult {
        Self::add(a, b)
    }

    /// TST — test (same as AND but result discarded).
    /// V flag is unchanged per the ARM Architecture Reference Manual.
    #[must_use]
    pub fn tst(a: u32, b: u32, shifter_carry: bool, old_v: bool) -> AluResult {
        let value = a & b;
        let (n, z) = Self::nz(value);
        AluResult { value, n, z, c: shifter_carry, v: old_v }
    }

    /// TEQ — test equivalence (same as EOR but result discarded).
    /// V flag is unchanged per the ARM Architecture Reference Manual.
    #[must_use]
    pub fn teq(a: u32, b: u32, shifter_carry: bool, old_v: bool) -> AluResult {
        let value = a ^ b;
        let (n, z) = Self::nz(value);
        AluResult { value, n, z, c: shifter_carry, v: old_v }
    }

    /// MUL — 32-bit multiply (result is low 32 bits); N and Z updated, C and V unpredictable.
    #[must_use]
    pub fn mul(a: u32, b: u32, old_c: bool, old_v: bool) -> AluResult {
        let value = a.wrapping_mul(b);
        let (n, z) = Self::nz(value);
        AluResult { value, n, z, c: old_c, v: old_v }
    }

    /// UMULL — unsigned 64-bit multiply.
    #[must_use]
    pub const fn umull(a: u32, b: u32) -> (u32, u32) {
        let result = (a as u64).wrapping_mul(b as u64);
        (result as u32, (result >> 32) as u32)
    }

    /// SMULL — signed 64-bit multiply.
    #[must_use]
    pub const fn smull(a: u32, b: u32) -> (u32, u32) {
        let result = ((a as i32) as i64).wrapping_mul((b as i32) as i64) as u64;
        (result as u32, (result >> 32) as u32)
    }
}

// ---------------------------------------------------------------------------
// Memory ordering barriers
// ---------------------------------------------------------------------------

/// ARM memory barrier options (bits [3:0] in DMB/DSB).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BarrierOption {
    /// Full system (SY)
    Sy     = 0b1111,
    /// Stores only to full system (ST)
    St     = 0b1110,
    /// Load-load, load-store to full system (LD) — `ARMv8`+
    Ld     = 0b1101,
    /// Inner shareable (ISH)
    Ish    = 0b1011,
    /// Inner shareable, stores only (ISHST)
    IshSt  = 0b1010,
    /// Inner shareable, loads only (ISHLD)
    IshLd  = 0b1001,
    /// Non-shareable (NSH)
    Nsh    = 0b0111,
    /// Non-shareable, stores only (NSHST)
    NshSt  = 0b0110,
    /// Non-shareable, loads only (NSHLD)
    NshLd  = 0b0101,
    /// Outer shareable (OSH)
    Osh    = 0b0011,
    /// Outer shareable, stores only (OSHST)
    OshSt  = 0b0010,
    /// Outer shareable, loads only (OSHLD)
    OshLd  = 0b0001,
}

impl BarrierOption {
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0xF {
            0b1111 => Some(Self::Sy),
            0b1110 => Some(Self::St),
            0b1101 => Some(Self::Ld),
            0b1011 => Some(Self::Ish),
            0b1010 => Some(Self::IshSt),
            0b1001 => Some(Self::IshLd),
            0b0111 => Some(Self::Nsh),
            0b0110 => Some(Self::NshSt),
            0b0101 => Some(Self::NshLd),
            0b0011 => Some(Self::Osh),
            0b0010 => Some(Self::OshSt),
            0b0001 => Some(Self::OshLd),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sy => "sy",
            Self::St => "st",
            Self::Ld => "ld",
            Self::Ish => "ish",
            Self::IshSt => "ishst",
            Self::IshLd => "ishld",
            Self::Nsh => "nsh",
            Self::NshSt => "nshst",
            Self::NshLd => "nshld",
            Self::Osh => "osh",
            Self::OshSt => "oshst",
            Self::OshLd => "oshld",
        }
    }
}

/// Type of memory barrier instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BarrierKind {
    /// Data Memory Barrier.
    Dmb,
    /// Data Synchronization Barrier.
    Dsb,
    /// Instruction Synchronization Barrier.
    Isb,
}

impl BarrierKind {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Dmb => "dmb",
            Self::Dsb => "dsb",
            Self::Isb => "isb",
        }
    }

    /// ISB only takes SY option.
    #[must_use]
    pub const fn accepts_option(self) -> bool {
        matches!(self, Self::Dmb | Self::Dsb)
    }
}

/// A decoded memory barrier instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemBarrier {
    pub kind: BarrierKind,
    pub option: BarrierOption,
}

impl MemBarrier {
    #[must_use]
    pub const fn new(kind: BarrierKind, option: BarrierOption) -> Self {
        Self { kind, option }
    }

    #[must_use]
    pub fn dmb_sy() -> Self { Self::new(BarrierKind::Dmb, BarrierOption::Sy) }
    #[must_use]
    pub fn dsb_sy() -> Self { Self::new(BarrierKind::Dsb, BarrierOption::Sy) }
    #[must_use]
    pub fn isb_sy() -> Self { Self::new(BarrierKind::Isb, BarrierOption::Sy) }
}

impl fmt::Display for MemBarrier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.kind.name(), self.option.name())
    }
}

// ---------------------------------------------------------------------------
// Exclusive monitors
// ---------------------------------------------------------------------------

/// State of the ARM exclusive monitor for a single core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExclusiveMonitor {
    /// The physical address being monitored, if any.
    tagged_address: Option<u32>,
    /// Granule size in bytes (processor-defined, typically 4 or 64).
    granule: u32,
}

impl ExclusiveMonitor {
    #[must_use]
    pub fn new(granule: u32) -> Self {
        assert!(granule > 0 && granule.is_power_of_two(),
            "ExclusiveMonitor granule must be a non-zero power of two, got {granule}");
        Self { tagged_address: None, granule }
    }

    /// Mark an address as exclusively reserved (LDREX/LDREXB/LDREXH/LDREXD).
    pub const fn mark_exclusive(&mut self, address: u32) {
        let aligned = address & !(self.granule - 1);
        self.tagged_address = Some(aligned);
    }

    /// Attempt to complete an exclusive store (STREX).
    /// Returns `true` if the store succeeds (monitor was tagged).
    /// Returns `false` if it fails (monitor was cleared).
    pub fn attempt_store(&mut self, address: u32) -> bool {
        let aligned = address & !(self.granule - 1);
        if self.tagged_address == Some(aligned) {
            self.tagged_address = None;
            true
        } else {
            false
        }
    }

    /// Clear the monitor (e.g., on context switch, exception entry).
    pub const fn clear(&mut self) {
        self.tagged_address = None;
    }

    #[must_use]
    pub const fn is_tagged(&self) -> bool {
        self.tagged_address.is_some()
    }

    #[must_use]
    pub const fn tagged_address(&self) -> Option<u32> {
        self.tagged_address
    }
}

// ---------------------------------------------------------------------------
// ArmInstructionSemantics — main type
// ---------------------------------------------------------------------------

/// Instruction category for the semantic model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArmInstrCategory {
    DataProcessing,
    Multiply,
    MultiplyLong,
    SaturatingAdd,
    ExtraLoadStore,
    MiscArithmetic,
    Synchronization,
    LoadStore,
    LoadStoreMultiple,
    Branch,
    Coprocessor,
    Undefined,
    MediaExtensions,
    SystemControl,
    Barrier,
}

/// A decoded ARM instruction with full semantic information attached.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmDecodedInsn {
    /// Raw 32-bit (A32) or 16/32-bit (T32) encoding.
    pub encoding: u32,
    /// Condition code.
    pub cond: ConditionCode,
    /// Instruction category.
    pub category: ArmInstrCategory,
    /// Mnemonic string.
    pub mnemonic: String,
    /// Whether the S-suffix (flag update) is set.
    pub set_flags: bool,
    /// Destination register index (0..15), if any.
    pub rd: Option<u8>,
    /// First source register, if any.
    pub rn: Option<u8>,
    /// Barrel-shifted second operand result, if any.
    pub shifter: Option<ShifterResult>,
}

/// Complete ARM instruction semantic model.
///
/// Provides:
/// - Condition code evaluation
/// - Flag computation for all ALU operations
/// - Barrel shifter
/// - CPSR/SPSR bit manipulation
/// - Memory barriers
/// - Exclusive monitor management
pub struct ArmInstructionSemantics {
    cpsr: CpsrFlags,
    spsr: HashMap<ProcessorMode, CpsrFlags>,
    monitors: Vec<ExclusiveMonitor>,
}

impl ArmInstructionSemantics {
    /// Create a new semantics context in User mode, all flags clear.
    #[must_use]
    pub fn new() -> Self {
        let mut spsr = HashMap::new();
        for mode in &[
            ProcessorMode::Fiq,
            ProcessorMode::Irq,
            ProcessorMode::Supervisor,
            ProcessorMode::Abort,
            ProcessorMode::Undefined,
            ProcessorMode::Monitor,
            ProcessorMode::Hypervisor,
        ] {
            spsr.insert(*mode, CpsrFlags::default());
        }
        Self {
            cpsr: CpsrFlags::from_raw(0x10), // User mode
            spsr,
            monitors: vec![ExclusiveMonitor::new(64)],
        }
    }

    /// Current CPSR.
    #[must_use]
    pub const fn cpsr(&self) -> CpsrFlags { self.cpsr }

    /// Read the SPSR for the current mode (returns None in User/System).
    #[must_use]
    pub fn spsr(&self) -> Option<CpsrFlags> {
        let mode = self.cpsr.mode();
        self.spsr.get(&mode).copied()
    }

    /// Write CPSR with mode change support.
    pub const fn write_cpsr(&mut self, value: CpsrFlags) {
        self.cpsr = value;
    }

    /// Write SPSR for the current privileged mode.
    pub fn write_spsr(&mut self, value: CpsrFlags) {
        let mode = self.cpsr.mode();
        if mode.has_spsr() {
            self.spsr.insert(mode, value);
        }
    }

    /// Evaluate whether the given condition is true in the current CPSR.
    #[must_use]
    pub fn condition_passes(&self, cond: ConditionCode) -> bool {
        cond.evaluate(self.cpsr)
    }

    /// Execute a barrel shift and optionally update the carry flag.
    #[must_use]
    pub fn barrel_shift(
        &self,
        value: u32,
        shift_type: ShiftType,
        amount: u32,
    ) -> ShifterResult {
        BarrelShifter::shift_immediate(value, shift_type, amount, self.cpsr.c())
    }

    /// Apply ALU flags to CPSR (when S bit is set).
    pub fn apply_alu_flags(&mut self, result: AluResult) {
        self.cpsr = self.cpsr.with_nzcv(result.n, result.z, result.c, result.v);
    }

    /// Exception entry: save CPSR to SPSR, switch mode, set PC.
    pub fn exception_entry(&mut self, target_mode: ProcessorMode, thumb: bool) {
        let current_cpsr = self.cpsr;
        self.cpsr = self.cpsr.with_mode(target_mode);
        self.write_spsr(current_cpsr);
        if thumb {
            self.cpsr = self.cpsr.with_thumb(true);
        }
        self.cpsr = self.cpsr.with_irq_disabled(true);
    }

    /// Exception return: restore CPSR from SPSR.
    pub fn exception_return(&mut self) {
        if let Some(saved) = self.spsr() {
            self.cpsr = saved;
        }
    }

    /// Mark exclusive: corresponds to LDREX instruction.
    pub fn ldrex(&mut self, address: u32) {
        for m in &mut self.monitors {
            m.mark_exclusive(address);
        }
    }

    /// Attempt exclusive store: corresponds to STREX instruction.
    /// Returns 0 (success) or 1 (failure).
    pub fn strex(&mut self, address: u32) -> u32 {
        for m in &mut self.monitors {
            if m.attempt_store(address) {
                return 0;
            }
        }
        1
    }

    /// Clear all exclusive monitors (e.g., on context switch).
    pub fn clrex(&mut self) {
        for m in &mut self.monitors {
            m.clear();
        }
    }

    /// Decode a memory barrier instruction.
    #[must_use]
    pub fn decode_barrier(&self, encoding: u32) -> Option<MemBarrier> {
        // A32 barrier encodings (F57FF0XX / F57FF4XX / F57FF5XX / F57FF6XX):
        //   bits [7:4] — sub-opcode distinguishing DSB/DMB/ISB (0x4/0x5/0x6)
        //   bits [3:0] — barrier option (SY, ISH, NSH, OSH, ...)
        let subop  = (encoding >> 4) & 0xF;
        let option = BarrierOption::from_bits((encoding & 0xF) as u8)?;
        let kind = match subop {
            0x4 => BarrierKind::Dsb,
            0x5 => BarrierKind::Dmb,
            0x6 => BarrierKind::Isb,
            _ => return None,
        };
        Some(MemBarrier::new(kind, option))
    }

    /// Check whether a given instruction encoding is unconditional.
    #[must_use]
    pub const fn is_unconditional(encoding: u32) -> bool {
        let cond = (encoding >> 28) & 0xF;
        cond == 0xE || cond == 0xF
    }

    /// Extract the condition code from an A32 encoding.
    #[must_use]
    pub fn extract_condition(encoding: u32) -> ConditionCode {
        ConditionCode::from_bits(((encoding >> 28) & 0xF) as u8)
            .unwrap_or(ConditionCode::AL)
    }

    /// Extract the S bit from an A32 data-processing encoding.
    #[must_use]
    pub const fn extract_s_bit(encoding: u32) -> bool {
        (encoding >> 20) & 1 != 0
    }

    /// Returns true if the given PC offset is Thumb-interworked (bit 0 == 1).
    #[must_use]
    pub const fn is_thumb_target(address: u32) -> bool {
        address & 1 != 0
    }
}

impl Default for ArmInstructionSemantics {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Condition code tests ---

    #[test]
    fn test_cond_eq_true_when_z_set() {
        let flags = CpsrFlags::from_flags(false, true, false, false);
        assert!(ConditionCode::EQ.evaluate(flags));
    }

    #[test]
    fn test_cond_eq_false_when_z_clear() {
        let flags = CpsrFlags::from_flags(false, false, false, false);
        assert!(!ConditionCode::EQ.evaluate(flags));
    }

    #[test]
    fn test_cond_ne_false_when_z_set() {
        let flags = CpsrFlags::from_flags(false, true, false, false);
        assert!(!ConditionCode::NE.evaluate(flags));
    }

    #[test]
    fn test_cond_cs_true_when_c_set() {
        let flags = CpsrFlags::from_flags(false, false, true, false);
        assert!(ConditionCode::CS.evaluate(flags));
    }

    #[test]
    fn test_cond_cc_true_when_c_clear() {
        let flags = CpsrFlags::from_flags(false, false, false, false);
        assert!(ConditionCode::CC.evaluate(flags));
    }

    #[test]
    fn test_cond_mi_true_when_n_set() {
        let flags = CpsrFlags::from_flags(true, false, false, false);
        assert!(ConditionCode::MI.evaluate(flags));
    }

    #[test]
    fn test_cond_pl_true_when_n_clear() {
        let flags = CpsrFlags::from_flags(false, false, false, false);
        assert!(ConditionCode::PL.evaluate(flags));
    }

    #[test]
    fn test_cond_vs_true_when_v_set() {
        let flags = CpsrFlags::from_flags(false, false, false, true);
        assert!(ConditionCode::VS.evaluate(flags));
    }

    #[test]
    fn test_cond_hi_requires_c_and_not_z() {
        let f1 = CpsrFlags::from_flags(false, false, true, false);
        assert!(ConditionCode::HI.evaluate(f1));
        let f2 = CpsrFlags::from_flags(false, true, true, false);
        assert!(!ConditionCode::HI.evaluate(f2));
    }

    #[test]
    fn test_cond_ge_when_n_eq_v() {
        let f1 = CpsrFlags::from_flags(true, false, false, true);
        assert!(ConditionCode::GE.evaluate(f1));
        let f2 = CpsrFlags::from_flags(false, false, false, false);
        assert!(ConditionCode::GE.evaluate(f2));
        let f3 = CpsrFlags::from_flags(true, false, false, false);
        assert!(!ConditionCode::GE.evaluate(f3));
    }

    #[test]
    fn test_cond_gt() {
        let f = CpsrFlags::from_flags(true, false, false, true);
        assert!(ConditionCode::GT.evaluate(f));
        let f2 = CpsrFlags::from_flags(true, true, false, true);
        assert!(!ConditionCode::GT.evaluate(f2));
    }

    #[test]
    fn test_cond_al_always_true() {
        for raw in [0u32, 0xFFFF_FFFFu32] {
            let flags = CpsrFlags::from_raw(raw);
            assert!(ConditionCode::AL.evaluate(flags));
        }
    }

    #[test]
    fn test_cond_invert_eq_ne() {
        assert_eq!(ConditionCode::EQ.invert(), ConditionCode::NE);
        assert_eq!(ConditionCode::NE.invert(), ConditionCode::EQ);
    }

    #[test]
    fn test_cond_from_bits_roundtrip() {
        for bits in 0u8..=15 {
            let cc = ConditionCode::from_bits(bits).unwrap();
            assert_eq!(cc.encoding(), bits);
        }
    }

    // --- Barrel shifter tests ---

    #[test]
    fn test_lsl_by_zero_preserves_carry_in() {
        let r = BarrelShifter::lsl(0xABCD, 0, true);
        assert_eq!(r.value, 0xABCD);
        assert!(r.carry_out);
    }

    #[test]
    fn test_lsl_basic() {
        let r = BarrelShifter::lsl(1, 1, false);
        assert_eq!(r.value, 2);
        assert!(!r.carry_out);
    }

    #[test]
    fn test_lsl_carry_out() {
        let r = BarrelShifter::lsl(0x8000_0000, 1, false);
        assert_eq!(r.value, 0);
        assert!(r.carry_out);
    }

    #[test]
    fn test_lsr_basic() {
        let r = BarrelShifter::lsr(4, 1, false);
        assert_eq!(r.value, 2);
        assert!(!r.carry_out);
    }

    #[test]
    fn test_lsr_carry_out() {
        let r = BarrelShifter::lsr(3, 1, false);
        assert_eq!(r.value, 1);
        assert!(r.carry_out);
    }

    #[test]
    fn test_asr_sign_extends() {
        let r = BarrelShifter::asr(0x8000_0000, 1, false);
        assert_eq!(r.value, 0xC000_0000);
    }

    #[test]
    fn test_asr_by_32_fills_sign() {
        let r = BarrelShifter::asr(0x8000_0000, 32, false);
        assert_eq!(r.value, 0xFFFF_FFFF);
        assert!(r.carry_out);
    }

    #[test]
    fn test_ror_basic() {
        let r = BarrelShifter::ror(1, 1);
        assert_eq!(r.value, 0x8000_0000);
        assert!(r.carry_out);
    }

    #[test]
    fn test_rrx_shifts_carry_in() {
        let r = BarrelShifter::rrx(2, true);
        assert_eq!(r.value, 0x8000_0001);
        assert!(!r.carry_out);
    }

    #[test]
    fn test_rrx_carry_out_from_bit0() {
        let r = BarrelShifter::rrx(1, false);
        assert_eq!(r.value, 0);
        assert!(r.carry_out);
    }

    // --- ALU tests ---

    #[test]
    fn test_add_zero() {
        let r = AluOps::add(0, 0);
        assert_eq!(r.value, 0);
        assert!(r.z);
        assert!(!r.n);
        assert!(!r.c);
        assert!(!r.v);
    }

    #[test]
    fn test_add_carry() {
        let r = AluOps::add(0xFFFF_FFFF, 1);
        assert_eq!(r.value, 0);
        assert!(r.c);
        assert!(r.z);
    }

    #[test]
    fn test_add_overflow() {
        let r = AluOps::add(0x7FFF_FFFF, 1);
        assert!(r.v);
        assert!(r.n);
    }

    #[test]
    fn test_sub_basic() {
        let r = AluOps::sub(10, 5);
        assert_eq!(r.value, 5);
        assert!(!r.n);
        assert!(!r.z);
    }

    #[test]
    fn test_sub_zero_result() {
        let r = AluOps::sub(5, 5);
        assert_eq!(r.value, 0);
        assert!(r.z);
    }

    #[test]
    fn test_mul_basic() {
        let r = AluOps::mul(3, 4, false, false);
        assert_eq!(r.value, 12);
    }

    #[test]
    fn test_umull() {
        let (lo, hi) = AluOps::umull(0xFFFF_FFFF, 2);
        assert_eq!(lo, 0xFFFF_FFFE);
        assert_eq!(hi, 1);
    }

    #[test]
    fn test_smull_negative() {
        let (lo, hi) = AluOps::smull(0xFFFF_FFFF, 2); // -1 * 2 = -2
        let combined = (lo as u64) | ((hi as u64) << 32);
        assert_eq!(combined as i64, -2i64);
    }

    #[test]
    fn test_and() {
        let r = AluOps::and(0xFF, 0x0F, false, false);
        assert_eq!(r.value, 0x0F);
    }

    #[test]
    fn test_orr() {
        let r = AluOps::orr(0xF0, 0x0F, false, false);
        assert_eq!(r.value, 0xFF);
    }

    #[test]
    fn test_eor() {
        let r = AluOps::eor(0xFF, 0xFF, false, false);
        assert_eq!(r.value, 0);
        assert!(r.z);
    }

    #[test]
    fn test_bic() {
        let r = AluOps::bic(0xFF, 0x0F, false, false);
        assert_eq!(r.value, 0xF0);
    }

    #[test]
    fn test_mvn() {
        let r = AluOps::mvn(0, false, false);
        assert_eq!(r.value, 0xFFFF_FFFF);
        assert!(r.n);
    }

    // --- CPSR tests ---

    #[test]
    fn test_cpsr_flags_roundtrip() {
        let f = CpsrFlags::from_flags(true, false, true, false);
        assert!(f.n());
        assert!(!f.z());
        assert!(f.c());
        assert!(!f.v());
    }

    #[test]
    fn test_cpsr_mode() {
        let f = CpsrFlags::from_raw(0x13); // SVC
        assert_eq!(f.mode(), ProcessorMode::Supervisor);
    }

    #[test]
    fn test_cpsr_with_mode() {
        let f = CpsrFlags::from_raw(0x10);
        let f2 = f.with_mode(ProcessorMode::Supervisor);
        assert_eq!(f2.mode(), ProcessorMode::Supervisor);
    }

    #[test]
    fn test_cpsr_thumb_bit() {
        let f = CpsrFlags::from_raw(0x10);
        assert!(!f.t());
        let f2 = f.with_thumb(true);
        assert!(f2.t());
    }

    #[test]
    fn test_cpsr_display() {
        let f = CpsrFlags::from_flags(true, false, true, false);
        assert_eq!(format!("{f}"), "NzCv");
    }

    // --- ExclusiveMonitor tests ---

    #[test]
    fn test_exclusive_monitor_basic() {
        let mut m = ExclusiveMonitor::new(64);
        m.mark_exclusive(0x1000);
        assert!(m.is_tagged());
        assert!(m.attempt_store(0x1000));
        assert!(!m.is_tagged());
    }

    #[test]
    fn test_exclusive_monitor_fails_after_clear() {
        let mut m = ExclusiveMonitor::new(64);
        m.mark_exclusive(0x1000);
        m.clear();
        assert!(!m.attempt_store(0x1000));
    }

    #[test]
    fn test_exclusive_monitor_wrong_address() {
        let mut m = ExclusiveMonitor::new(64);
        m.mark_exclusive(0x1000);
        assert!(!m.attempt_store(0x2000));
    }

    #[test]
    fn test_exclusive_monitor_granule_alignment() {
        let mut m = ExclusiveMonitor::new(64);
        m.mark_exclusive(0x1004); // should align to 0x1000
        assert!(m.attempt_store(0x1020)); // also in same 64-byte granule
    }

    // --- ArmInstructionSemantics tests ---

    #[test]
    fn test_semantics_new_user_mode() {
        let sem = ArmInstructionSemantics::new();
        assert_eq!(sem.cpsr().mode(), ProcessorMode::User);
    }

    #[test]
    fn test_semantics_condition_passes() {
        let mut sem = ArmInstructionSemantics::new();
        sem.write_cpsr(CpsrFlags::from_flags(false, true, false, false));
        assert!(sem.condition_passes(ConditionCode::EQ));
        assert!(!sem.condition_passes(ConditionCode::NE));
    }

    #[test]
    fn test_semantics_apply_alu_flags() {
        let mut sem = ArmInstructionSemantics::new();
        let result = AluOps::add(0xFFFF_FFFF, 1);
        sem.apply_alu_flags(result);
        assert!(sem.cpsr().z());
        assert!(sem.cpsr().c());
    }

    #[test]
    fn test_semantics_exception_entry_and_return() {
        let mut sem = ArmInstructionSemantics::new();
        sem.write_cpsr(CpsrFlags::from_flags(true, false, true, false));
        let before = sem.cpsr();
        sem.exception_entry(ProcessorMode::Supervisor, false);
        assert_eq!(sem.cpsr().mode(), ProcessorMode::Supervisor);
        // SPSR should have the old CPSR
        assert_eq!(sem.spsr(), Some(before));
        sem.exception_return();
        assert_eq!(sem.cpsr(), before);
    }

    #[test]
    fn test_semantics_strex_success() {
        let mut sem = ArmInstructionSemantics::new();
        sem.ldrex(0x1000);
        assert_eq!(sem.strex(0x1000), 0);
    }

    #[test]
    fn test_semantics_strex_fail_after_clrex() {
        let mut sem = ArmInstructionSemantics::new();
        sem.ldrex(0x1000);
        sem.clrex();
        assert_eq!(sem.strex(0x1000), 1);
    }

    #[test]
    fn test_is_unconditional() {
        assert!(ArmInstructionSemantics::is_unconditional(0xE000_0000));
        assert!(ArmInstructionSemantics::is_unconditional(0xF000_0000));
        assert!(!ArmInstructionSemantics::is_unconditional(0x0000_0000));
    }

    #[test]
    fn test_is_thumb_target() {
        assert!(ArmInstructionSemantics::is_thumb_target(0x1001));
        assert!(!ArmInstructionSemantics::is_thumb_target(0x1000));
    }

    #[test]
    fn test_extract_condition() {
        let enc = 0x1A00_0000u32; // NE (0001)
        assert_eq!(ArmInstructionSemantics::extract_condition(enc), ConditionCode::NE);
    }

    #[test]
    fn test_extract_s_bit() {
        let enc_s = 0xE010_0000u32; // S bit set
        let enc_no_s = 0xE000_0000u32;
        assert!(ArmInstructionSemantics::extract_s_bit(enc_s));
        assert!(!ArmInstructionSemantics::extract_s_bit(enc_no_s));
    }

    #[test]
    fn test_processor_mode_privileged() {
        assert!(!ProcessorMode::User.is_privileged());
        assert!(ProcessorMode::Supervisor.is_privileged());
        assert!(ProcessorMode::Fiq.is_privileged());
    }

    #[test]
    fn test_processor_mode_has_spsr() {
        assert!(!ProcessorMode::User.has_spsr());
        assert!(!ProcessorMode::System.has_spsr());
        assert!(ProcessorMode::Supervisor.has_spsr());
        assert!(ProcessorMode::Irq.has_spsr());
    }

    #[test]
    fn test_barrier_option_from_bits() {
        assert_eq!(BarrierOption::from_bits(0xF), Some(BarrierOption::Sy));
        assert_eq!(BarrierOption::from_bits(0xB), Some(BarrierOption::Ish));
        assert_eq!(BarrierOption::from_bits(0x0), None);
    }

    #[test]
    fn test_mem_barrier_display() {
        let b = MemBarrier::dmb_sy();
        assert_eq!(format!("{b}"), "dmb sy");
    }

    #[test]
    fn test_adc_with_carry() {
        let r = AluOps::adc(0xFFFF_FFFF, 0, true);
        assert_eq!(r.value, 0);
        assert!(r.c);
        assert!(r.z);
    }

    #[test]
    fn test_rsb() {
        let r = AluOps::rsb(10, 20); // 20 - 10
        assert_eq!(r.value, 10);
    }

    #[test]
    fn test_cmp_equal() {
        let r = AluOps::cmp(5, 5);
        assert!(r.z);
    }

    #[test]
    fn test_cmn() {
        let r = AluOps::cmn(1, 0xFFFF_FFFF);
        assert!(r.z);
        assert!(r.c);
    }

    #[test]
    fn test_tst_zero() {
        let r = AluOps::tst(0xFF, 0, false, false);
        assert!(r.z);
    }

    #[test]
    fn test_teq_same_values() {
        let r = AluOps::teq(0xAB, 0xAB, false, false);
        assert!(r.z);
    }

    #[test]
    fn test_shift_type_from_bits() {
        assert_eq!(ShiftType::from_bits(0), ShiftType::LSL);
        assert_eq!(ShiftType::from_bits(1), ShiftType::LSR);
        assert_eq!(ShiftType::from_bits(2), ShiftType::ASR);
        assert_eq!(ShiftType::from_bits(3), ShiftType::ROR);
    }

    #[test]
    fn test_barrel_shifter_ror_by_32_same_value() {
        let r = BarrelShifter::ror(0xDEAD_BEEF, 32);
        assert_eq!(r.value, 0xDEAD_BEEF);
    }

    #[test]
    fn test_lsl_by_32_gives_zero() {
        let r = BarrelShifter::lsl(0x1, 32, false);
        assert_eq!(r.value, 0);
        assert!(r.carry_out);
    }

    #[test]
    fn test_lsr_by_32() {
        let r = BarrelShifter::lsr(0x8000_0000, 32, false);
        assert_eq!(r.value, 0);
        assert!(r.carry_out);
    }
}
