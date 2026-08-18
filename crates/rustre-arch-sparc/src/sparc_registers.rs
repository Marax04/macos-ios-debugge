//! SPARC register file model: global/out/local/in integer registers,
//! register window semantics, condition codes, floating-point registers,
//! and ASR (ancillary state registers).
//!
//! Covers both SPARC v8 (32-bit) and v9 (64-bit) register sets.

use std::collections::HashMap;
use std::fmt;

// ── Register classes ──────────────────────────────────────────────────────────

/// Categories of SPARC integer registers in the windowed register file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegClass {
    /// %g0–%g7: global registers, shared across all windows.
    Global,
    /// %o0–%o7: output registers, %o6 = %sp, %o7 = return address after CALL.
    Out,
    /// %l0–%l7: local registers, private to the current window.
    Local,
    /// %i0–%i7: input registers, %i6 = %fp, %i7 = return address on entry.
    In,
}

impl RegClass {
    /// Return the human-readable prefix for this register class.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Global => "g",
            Self::Out => "o",
            Self::Local => "l",
            Self::In => "i",
        }
    }

    /// Window-relative base register index (0, 8, 16, 24).
    #[must_use]
    pub const fn base_index(self) -> u32 {
        match self {
            Self::Global => 0,
            Self::Out => 8,
            Self::Local => 16,
            Self::In => 24,
        }
    }
}

// ── SparcReg ──────────────────────────────────────────────────────────────────

/// A SPARC integer register identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SparcReg {
    /// The hardware register number 0–31.
    pub index: u8,
}

impl SparcReg {
    /// Create from a hardware index (0–31).
    ///
    /// # Panics
    /// Panics if `index > 31`.
    #[must_use]
    pub fn new(index: u8) -> Self {
        assert!(index < 32, "SPARC integer register index must be 0–31");
        Self { index }
    }

    /// The windowed register class for this register.
    #[must_use]
    pub fn class(self) -> RegClass {
        match self.index {
            0..=7 => RegClass::Global,
            8..=15 => RegClass::Out,
            16..=23 => RegClass::Local,
            24..=31 => RegClass::In,
            _ => unreachable!(),
        }
    }

    /// The within-class sub-index (0–7).
    #[must_use]
    pub const fn sub_index(self) -> u8 {
        self.index % 8
    }

    /// Return the canonical assembly name, e.g. `%g0`, `%sp`, `%fp`.
    #[must_use]
    pub fn name(self) -> &'static str {
        SPARC_INT_REG_NAMES[self.index as usize]
    }

    /// Whether this register is always zero (%g0).
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.index == 0
    }

    /// Whether this is the stack pointer (%o6 = %sp).
    #[must_use]
    pub const fn is_sp(self) -> bool {
        self.index == 14
    }

    /// Whether this is the frame pointer (%i6 = %fp).
    #[must_use]
    pub const fn is_fp(self) -> bool {
        self.index == 30
    }

    /// Whether this is the call-link register (%o7).
    #[must_use]
    pub const fn is_o7(self) -> bool {
        self.index == 15
    }

    /// Whether this is the return-address register (%i7).
    #[must_use]
    pub const fn is_i7(self) -> bool {
        self.index == 31
    }

    /// Well-known register constants.
    pub const G0: Self = Self { index: 0 };
    pub const G1: Self = Self { index: 1 };
    pub const G2: Self = Self { index: 2 };
    pub const G3: Self = Self { index: 3 };
    pub const G4: Self = Self { index: 4 };
    pub const G5: Self = Self { index: 5 };
    pub const G6: Self = Self { index: 6 };
    pub const G7: Self = Self { index: 7 };

    pub const O0: Self = Self { index: 8 };
    pub const O1: Self = Self { index: 9 };
    pub const O2: Self = Self { index: 10 };
    pub const O3: Self = Self { index: 11 };
    pub const O4: Self = Self { index: 12 };
    pub const O5: Self = Self { index: 13 };
    pub const SP: Self = Self { index: 14 }; // %o6
    pub const O7: Self = Self { index: 15 };

    pub const L0: Self = Self { index: 16 };
    pub const L1: Self = Self { index: 17 };
    pub const L2: Self = Self { index: 18 };
    pub const L3: Self = Self { index: 19 };
    pub const L4: Self = Self { index: 20 };
    pub const L5: Self = Self { index: 21 };
    pub const L6: Self = Self { index: 22 };
    pub const L7: Self = Self { index: 23 };

    pub const I0: Self = Self { index: 24 };
    pub const I1: Self = Self { index: 25 };
    pub const I2: Self = Self { index: 26 };
    pub const I3: Self = Self { index: 27 };
    pub const I4: Self = Self { index: 28 };
    pub const I5: Self = Self { index: 29 };
    pub const FP: Self = Self { index: 30 }; // %i6
    pub const I7: Self = Self { index: 31 };
}

static SPARC_INT_REG_NAMES: [&str; 32] = [
    "%g0", "%g1", "%g2", "%g3", "%g4", "%g5", "%g6", "%g7",
    "%o0", "%o1", "%o2", "%o3", "%o4", "%o5", "%sp", "%o7",
    "%l0", "%l1", "%l2", "%l3", "%l4", "%l5", "%l6", "%l7",
    "%i0", "%i1", "%i2", "%i3", "%i4", "%i5", "%fp", "%i7",
];

impl fmt::Display for SparcReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ── FpReg ─────────────────────────────────────────────────────────────────────

/// A SPARC floating-point register.
///
/// v8 has 32 single-precision registers %f0–%f31.
/// v9 has 64 single-precision registers %f0–%f63; pairs form double-precision
/// (%d0, %d2, …, %d62) and quads form quad-precision (%q0, %q4, …, %q60).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FpReg {
    /// Register index, 0–63 (v9) or 0–31 (v8).
    pub index: u8,
    /// Precision of this register view.
    pub precision: FpPrecision,
}

/// Floating-point register precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FpPrecision {
    /// Single-precision (32-bit): %f<n>.
    Single,
    /// Double-precision (64-bit): %d<n>, n must be even.
    Double,
    /// Quad-precision (128-bit): %q<n>, n must be divisible by 4.
    Quad,
}

impl FpReg {
    /// Create a single-precision register.
    ///
    /// # Panics
    /// Panics if `index >= 64`.
    #[must_use]
    pub fn single(index: u8) -> Self {
        assert!(index < 64, "FP register index must be 0–63");
        Self {
            index,
            precision: FpPrecision::Single,
        }
    }

    /// Create a double-precision register.
    ///
    /// # Panics
    /// Panics if `index >= 64` or if index is odd.
    #[must_use]
    pub fn double(index: u8) -> Self {
        assert!(index < 64 && index % 2 == 0, "double FP index must be even, 0–62");
        Self {
            index,
            precision: FpPrecision::Double,
        }
    }

    /// Create a quad-precision register.
    ///
    /// # Panics
    /// Panics if `index >= 64` or if index is not divisible by 4.
    #[must_use]
    pub fn quad(index: u8) -> Self {
        assert!(index < 64 && index % 4 == 0, "quad FP index must be 0,4,8,…,60");
        Self {
            index,
            precision: FpPrecision::Quad,
        }
    }

    /// Return the assembly name for this register.
    #[must_use]
    pub fn name(&self) -> String {
        match self.precision {
            FpPrecision::Single => format!("%f{}", self.index),
            FpPrecision::Double => format!("%d{}", self.index),
            FpPrecision::Quad => format!("%q{}", self.index),
        }
    }

    /// Number of bytes used by this register.
    #[must_use]
    pub const fn byte_size(&self) -> u8 {
        match self.precision {
            FpPrecision::Single => 4,
            FpPrecision::Double => 8,
            FpPrecision::Quad => 16,
        }
    }
}

impl fmt::Display for FpReg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ── SparcCondCode ─────────────────────────────────────────────────────────────

/// SPARC condition code flags, stored in PSR (v8) or CCR (v9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SparcCondCode {
    /// Negative flag.
    pub n: bool,
    /// Zero flag.
    pub z: bool,
    /// Overflow flag.
    pub v: bool,
    /// Carry flag.
    pub c: bool,
}

impl SparcCondCode {
    /// Create all-zero condition codes.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            n: false,
            z: false,
            v: false,
            c: false,
        }
    }

    /// Update condition codes from an integer result.
    pub const fn update_from_result(&mut self, result: i64, prev_a: i64, prev_b: i64, width: u8) {
        let mask: i64 = match width {
            8 => 0xFF,
            16 => 0xFFFF,
            32 => 0xFFFF_FFFF,
            _ => i64::MIN, // 64-bit: sign bit check via shift
        };
        let sign_bit: u64 = match width {
            8 => 0x80,
            16 => 0x8000,
            32 => 0x8000_0000,
            _ => 0x8000_0000_0000_0000,
        };
        let masked = if width == 64 {
            result as u64
        } else {
            (result & mask) as u64
        };
        self.z = masked == 0;
        self.n = (masked & sign_bit) != 0;
        // Overflow: sign of result differs from expected
        let a_sign = (prev_a as u64 & sign_bit) != 0;
        let b_sign = (prev_b as u64 & sign_bit) != 0;
        let r_sign = self.n;
        self.v = (a_sign == b_sign) && (a_sign != r_sign);
        // Carry: unsigned overflow
        let ua = prev_a as u64;
        let _ub = prev_b as u64;
        let ur = masked;
        self.c = if width == 64 {
            ur < ua
        } else {
            (result as u64) > mask as u64
        };
    }

    /// Evaluate a branch condition (Bicc / `BPcc`).
    ///
    /// Condition codes follow SPARC v9 Table 3-2.
    #[must_use]
    pub const fn evaluate(&self, cond: u8) -> bool {
        match cond & 0xF {
            0x0 => false,                          // BN  (never)
            0x1 => self.z,                         // BE
            0x2 => self.z || (self.n ^ self.v),    // BLE
            0x3 => self.n ^ self.v,                // BL
            0x4 => self.c || self.z,               // BLEU
            0x5 => self.c,                         // BCS / BLU
            0x6 => self.n,                         // BNEG
            0x7 => self.v,                         // BVS
            0x8 => true,                           // BA  (always)
            0x9 => !self.z,                        // BNE
            0xA => !(self.z || (self.n ^ self.v)), // BG
            0xB => !(self.n ^ self.v),             // BGE
            0xC => !(self.c || self.z),            // BGU
            0xD => !self.c,                        // BCC / BGEU
            0xE => !self.n,                        // BPOS
            0xF => !self.v,                        // BVC
            _ => false,
        }
    }

    /// Pack into the 4-bit icc field of PSR/CCR.
    #[must_use]
    pub fn pack_icc(&self) -> u8 {
        (u8::from(self.n) << 3)
            | (u8::from(self.z) << 2)
            | (u8::from(self.v) << 1)
            | u8::from(self.c)
    }

    /// Unpack from the 4-bit icc field.
    #[must_use]
    pub const fn unpack_icc(bits: u8) -> Self {
        Self {
            n: (bits >> 3) & 1 != 0,
            z: (bits >> 2) & 1 != 0,
            v: (bits >> 1) & 1 != 0,
            c: bits & 1 != 0,
        }
    }
}

impl fmt::Display for SparcCondCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "N={} Z={} V={} C={}",
            u8::from(self.n),
            u8::from(self.z),
            u8::from(self.v),
            u8::from(self.c)
        )
    }
}

// ── RegWindow ─────────────────────────────────────────────────────────────────

/// A single SPARC register window (the visible slice of the circular window buffer).
///
/// The full register file contains `NWINDOWS` overlapping windows (typically 7–32).
/// Each window has 8 local registers and shares its out-registers with the next
/// window's in-registers.
#[derive(Debug, Clone)]
pub struct RegWindow {
    /// Local registers %l0–%l7 (private to this window).
    pub locals: [u64; 8],
    /// Input registers %i0–%i7 (%i6=%fp, %i7=return-addr).
    pub ins: [u64; 8],
    /// Output registers %o0–%o7 (%o6=%sp, %o7=link).
    /// When SAVE is executed, the current out-regs become the new window's in-regs.
    pub outs: [u64; 8],
}

impl RegWindow {
    /// Create a zeroed register window.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self {
            locals: [0u64; 8],
            ins: [0u64; 8],
            outs: [0u64; 8],
        }
    }

    /// Read a windowed register by hardware index (8–31).
    ///
    /// # Panics
    /// Panics if `index < 8` or `index > 31`.
    #[must_use]
    pub fn read(&self, index: u8) -> u64 {
        match index {
            8..=15 => self.outs[(index - 8) as usize],
            16..=23 => self.locals[(index - 16) as usize],
            24..=31 => self.ins[(index - 24) as usize],
            _ => panic!("RegWindow::read index out of range: {index}"),
        }
    }

    /// Write a windowed register by hardware index (8–31).
    ///
    /// # Panics
    /// Panics if `index < 8` or `index > 31`.
    pub fn write(&mut self, index: u8, value: u64) {
        match index {
            8..=15 => self.outs[(index - 8) as usize] = value,
            16..=23 => self.locals[(index - 16) as usize] = value,
            24..=31 => self.ins[(index - 24) as usize] = value,
            _ => panic!("RegWindow::write index out of range: {index}"),
        }
    }

    /// Return the stack pointer (%o6).
    #[must_use]
    pub const fn sp(&self) -> u64 {
        self.outs[6]
    }

    /// Return the frame pointer (%i6).
    #[must_use]
    pub const fn fp(&self) -> u64 {
        self.ins[6]
    }

    /// Return the return address (%i7 + 8 is the real return address in v8).
    #[must_use]
    pub const fn return_addr(&self) -> u64 {
        self.ins[7].wrapping_add(8)
    }
}

// ── RegWindowState ────────────────────────────────────────────────────────────

/// Maximum supported register windows.
pub const MAX_WINDOWS: usize = 32;

/// The full SPARC register window state machine.
#[derive(Debug)]
pub struct RegWindowState {
    /// Circular buffer of register windows.
    windows: Vec<RegWindow>,
    /// Total number of windows (typically 7–32).
    pub nwindows: usize,
    /// Current Window Pointer (CWP): index of the currently active window.
    pub cwp: usize,
    /// Window Invalid Mask (WIM): bitmask of windows that trap on entry.
    pub wim: u32,
    /// Global registers %g0–%g7.
    pub globals: [u64; 8],
    /// Floating-point registers %f0–%f63.
    pub fp_regs: [f64; 64],
    /// Integer condition codes (icc).
    pub icc: SparcCondCode,
    /// Extended condition codes (xcc, v9 only).
    pub xcc: SparcCondCode,
    /// Program counter.
    pub pc: u64,
    /// Next program counter (delay slot support).
    pub npc: u64,
    /// Y register (used by MULCC/MULSCC).
    pub y: u64,
    /// Tick register (v9 per-CPU timestamp).
    pub tick: u64,
}

impl RegWindowState {
    /// Create a new register window state with `nwindows` windows.
    ///
    /// # Panics
    /// Panics if `nwindows < 2` or `nwindows > MAX_WINDOWS`.
    #[must_use]
    pub fn new(nwindows: usize) -> Self {
        assert!(
            (2..=MAX_WINDOWS).contains(&nwindows),
            "nwindows must be 2..=MAX_WINDOWS"
        );
        Self {
            windows: vec![RegWindow::zeroed(); nwindows],
            nwindows,
            cwp: 0,
            wim: 1, // Window 0 initially invalid (trap on underflow)
            globals: [0u64; 8],
            fp_regs: [0f64; 64],
            icc: SparcCondCode::new(),
            xcc: SparcCondCode::new(),
            pc: 0,
            npc: 4,
            y: 0,
            tick: 0,
        }
    }

    /// Read any integer register by hardware index (0–31).
    /// %g0 always returns 0.
    #[must_use]
    pub fn read_reg(&self, index: u8) -> u64 {
        match index {
            0 => 0, // %g0 = always 0
            1..=7 => self.globals[index as usize],
            8..=31 => self.windows[self.cwp].read(index),
            _ => 0,
        }
    }

    /// Write any integer register by hardware index (0–31).
    /// Writes to %g0 are silently discarded.
    pub fn write_reg(&mut self, index: u8, value: u64) {
        match index {
            0 => {} // discard writes to %g0
            1..=7 => self.globals[index as usize] = value,
            8..=31 => self.windows[self.cwp].write(index, value),
            _ => {}
        }
    }

    /// Execute a SAVE instruction: advance CWP, potentially trap on overflow.
    ///
    /// Returns `true` if a window overflow trap should be taken.
    pub fn save(&mut self) -> bool {
        let new_cwp = self.cwp.wrapping_sub(1) % self.nwindows;
        let trap = (self.wim >> new_cwp) & 1 != 0;
        if !trap {
            // Transfer current out-regs to new window's in-regs.
            let old_outs = self.windows[self.cwp].outs;
            self.cwp = new_cwp;
            self.windows[self.cwp].ins = old_outs;
        }
        trap
    }

    /// Execute a RESTORE instruction: advance CWP, potentially trap on underflow.
    ///
    /// Returns `true` if a window underflow trap should be taken.
    pub fn restore(&mut self) -> bool {
        let new_cwp = (self.cwp + 1) % self.nwindows;
        let trap = (self.wim >> new_cwp) & 1 != 0;
        if !trap {
            // Transfer current in-regs to previous window's out-regs.
            let old_ins = self.windows[self.cwp].ins;
            self.cwp = new_cwp;
            self.windows[self.cwp].outs = old_ins;
        }
        trap
    }

    /// Flush all windows to memory (conceptually — here we just reset WIM).
    pub const fn flush_windows(&mut self) {
        self.wim = 1 << ((self.cwp + 1) % self.nwindows);
    }

    /// Read a single-precision floating-point register.
    #[must_use]
    pub const fn read_fp_single(&self, index: u8) -> f32 {
        (self.fp_regs[(index & 63) as usize]) as f32
    }

    /// Write a single-precision floating-point register.
    pub fn write_fp_single(&mut self, index: u8, value: f32) {
        self.fp_regs[(index & 63) as usize] = f64::from(value);
    }

    /// Read a double-precision floating-point register.
    #[must_use]
    pub const fn read_fp_double(&self, index: u8) -> f64 {
        self.fp_regs[(index & 63) as usize]
    }

    /// Write a double-precision floating-point register.
    pub const fn write_fp_double(&mut self, index: u8, value: f64) {
        self.fp_regs[(index & 63) as usize] = value;
    }

    /// Advance the program counter (step to next instruction).
    pub const fn advance_pc(&mut self) {
        self.pc = self.npc;
        self.npc = self.npc.wrapping_add(4);
    }

    /// Perform a branch: set NPC to `target`.
    pub const fn branch_to(&mut self, target: u64) {
        self.pc = self.npc;
        self.npc = target;
    }

    /// Return a snapshot of all visible integer registers.
    #[must_use]
    pub fn dump_integer_regs(&self) -> Vec<(String, u64)> {
        (0u8..32)
            .map(|i| {
                let name = SPARC_INT_REG_NAMES[i as usize].to_string();
                let value = self.read_reg(i);
                (name, value)
            })
            .collect()
    }
}

// ── ASR register names ────────────────────────────────────────────────────────

/// SPARC Ancillary State Register (ASR) identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AncillaryReg {
    /// %asr0 = %y (multiply / divide auxiliary register).
    Y,
    /// %asr2 = %ccr (condition code register, v9).
    Ccr,
    /// %asr3 = %asi (address space identifier, v9).
    Asi,
    /// %asr4 = %tick (CPU tick counter, v9).
    Tick,
    /// %asr5 = %pc (program counter as ASR, v9).
    PcAsAsr,
    /// %asr6 = %fprs (floating-point register state, v9).
    Fprs,
    /// Unknown ASR index.
    Unknown(u8),
}

impl AncillaryReg {
    /// Decode from an ASR hardware index (0–31).
    #[must_use]
    pub const fn from_index(idx: u8) -> Self {
        match idx {
            0 => Self::Y,
            2 => Self::Ccr,
            3 => Self::Asi,
            4 => Self::Tick,
            5 => Self::PcAsAsr,
            6 => Self::Fprs,
            other => Self::Unknown(other),
        }
    }

    /// Return the assembly name for this ASR.
    #[must_use]
    pub fn name(&self) -> String {
        match self {
            Self::Y => "%y".to_string(),
            Self::Ccr => "%ccr".to_string(),
            Self::Asi => "%asi".to_string(),
            Self::Tick => "%tick".to_string(),
            Self::PcAsAsr => "%pc".to_string(),
            Self::Fprs => "%fprs".to_string(),
            Self::Unknown(n) => format!("%asr{n}"),
        }
    }
}

// ── RegisterFile ──────────────────────────────────────────────────────────────

/// A named register file: maps register names to their current values.
///
/// Useful for lightweight analysis without full window simulation.
#[derive(Debug, Clone, Default)]
pub struct RegisterFile {
    values: HashMap<String, u64>,
}

impl RegisterFile {
    /// Create an empty register file.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-populate with all 32 integer registers set to zero.
    #[must_use]
    pub fn with_integer_regs() -> Self {
        let mut rf = Self::new();
        for i in 0u8..32 {
            rf.values
                .insert(SPARC_INT_REG_NAMES[i as usize].to_string(), 0);
        }
        rf.values.insert("%pc".to_string(), 0);
        rf.values.insert("%npc".to_string(), 4);
        rf.values.insert("%y".to_string(), 0);
        rf
    }

    /// Set a register value by name (e.g. `"%o0"`, `"%sp"`).
    pub fn set(&mut self, name: &str, value: u64) {
        self.values.insert(name.to_string(), value);
    }

    /// Get a register value by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<u64> {
        self.values.get(name).copied()
    }

    /// Read register value, returning 0 for unknown registers.
    #[must_use]
    pub fn get_or_zero(&self, name: &str) -> u64 {
        self.values.get(name).copied().unwrap_or(0)
    }

    /// Set the stack pointer.
    pub fn set_sp(&mut self, value: u64) {
        self.values.insert("%sp".to_string(), value);
    }

    /// Set the frame pointer.
    pub fn set_fp(&mut self, value: u64) {
        self.values.insert("%fp".to_string(), value);
    }

    /// Read the stack pointer.
    #[must_use]
    pub fn sp(&self) -> u64 {
        self.get_or_zero("%sp")
    }

    /// Read the frame pointer.
    #[must_use]
    pub fn fp(&self) -> u64 {
        self.get_or_zero("%fp")
    }

    /// Return a sorted list of all register names.
    #[must_use]
    pub fn register_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.values.keys().cloned().collect();
        names.sort();
        names
    }

    /// Dump all registers as name=value pairs.
    #[must_use]
    pub fn dump(&self) -> Vec<(String, u64)> {
        let mut pairs: Vec<(String, u64)> = self.values.iter().map(|(k, v)| (k.clone(), *v)).collect();
        pairs.sort_by(|(a, _), (b, _)| a.cmp(b));
        pairs
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparc_reg_class() {
        assert_eq!(SparcReg::G0.class(), RegClass::Global);
        assert_eq!(SparcReg::O0.class(), RegClass::Out);
        assert_eq!(SparcReg::L0.class(), RegClass::Local);
        assert_eq!(SparcReg::I0.class(), RegClass::In);
    }

    #[test]
    fn test_sparc_reg_names() {
        assert_eq!(SparcReg::G0.name(), "%g0");
        assert_eq!(SparcReg::SP.name(), "%sp");
        assert_eq!(SparcReg::FP.name(), "%fp");
        assert_eq!(SparcReg::I7.name(), "%i7");
    }

    #[test]
    fn test_sparc_reg_special_predicates() {
        assert!(SparcReg::G0.is_zero());
        assert!(SparcReg::SP.is_sp());
        assert!(SparcReg::FP.is_fp());
        assert!(SparcReg::O7.is_o7());
        assert!(SparcReg::I7.is_i7());
        assert!(!SparcReg::O0.is_sp());
    }

    #[test]
    fn test_fp_reg_names() {
        assert_eq!(FpReg::single(0).name(), "%f0");
        assert_eq!(FpReg::double(2).name(), "%d2");
        assert_eq!(FpReg::quad(4).name(), "%q4");
    }

    #[test]
    fn test_fp_reg_sizes() {
        assert_eq!(FpReg::single(0).byte_size(), 4);
        assert_eq!(FpReg::double(0).byte_size(), 8);
        assert_eq!(FpReg::quad(0).byte_size(), 16);
    }

    #[test]
    fn test_cond_code_always_never() {
        let cc = SparcCondCode::new();
        assert!(cc.evaluate(0x8)); // BA: always
        assert!(!cc.evaluate(0x0)); // BN: never
    }

    #[test]
    fn test_cond_code_zero() {
        let cc = SparcCondCode { z: true, ..Default::default() };
        assert!(cc.evaluate(0x1)); // BE (z=1)
        assert!(!cc.evaluate(0x9)); // BNE (!z)
    }

    #[test]
    fn test_cond_code_pack_unpack() {
        let cc = SparcCondCode { n: true, z: false, v: true, c: false };
        let packed = cc.pack_icc();
        let unpacked = SparcCondCode::unpack_icc(packed);
        assert_eq!(unpacked.n, cc.n);
        assert_eq!(unpacked.z, cc.z);
        assert_eq!(unpacked.v, cc.v);
        assert_eq!(unpacked.c, cc.c);
    }

    #[test]
    fn test_reg_window_read_write() {
        let mut w = RegWindow::zeroed();
        w.write(8, 0xDEAD); // %o0
        assert_eq!(w.read(8), 0xDEAD);
        w.write(20, 0xBEEF); // %l4
        assert_eq!(w.read(20), 0xBEEF);
        w.write(24, 0xCAFE); // %i0
        assert_eq!(w.read(24), 0xCAFE);
    }

    #[test]
    fn test_reg_window_state_g0_zero() {
        let mut state = RegWindowState::new(8);
        state.write_reg(0, 0xFFFF);
        assert_eq!(state.read_reg(0), 0); // %g0 always 0
    }

    #[test]
    fn test_reg_window_state_global() {
        let mut state = RegWindowState::new(8);
        state.write_reg(1, 42); // %g1
        assert_eq!(state.read_reg(1), 42);
    }

    #[test]
    fn test_reg_window_state_save_restore() {
        let mut state = RegWindowState::new(8);
        state.write_reg(14, 0x1000); // %sp
        state.wim = 0; // disable traps for test
        let trap = state.save();
        assert!(!trap);
        // out-regs should have been transferred
    }

    #[test]
    fn test_reg_window_dump() {
        let state = RegWindowState::new(8);
        let dump = state.dump_integer_regs();
        assert_eq!(dump.len(), 32);
        assert_eq!(dump[0].0, "%g0");
    }

    #[test]
    fn test_register_file_set_get() {
        let mut rf = RegisterFile::with_integer_regs();
        rf.set("%o0", 100);
        assert_eq!(rf.get("%o0"), Some(100));
        assert_eq!(rf.get_or_zero("%g0"), 0);
    }

    #[test]
    fn test_register_file_sp_fp() {
        let mut rf = RegisterFile::new();
        rf.set_sp(0x7FFF_0000);
        rf.set_fp(0x7FFF_0100);
        assert_eq!(rf.sp(), 0x7FFF_0000);
        assert_eq!(rf.fp(), 0x7FFF_0100);
    }

    #[test]
    fn test_asr_names() {
        assert_eq!(AncillaryReg::from_index(0).name(), "%y");
        assert_eq!(AncillaryReg::from_index(2).name(), "%ccr");
        assert_eq!(AncillaryReg::from_index(99).name(), "%asr99");
    }

    #[test]
    fn test_advance_pc() {
        let mut state = RegWindowState::new(8);
        state.pc = 0x1000;
        state.npc = 0x1004;
        state.advance_pc();
        assert_eq!(state.pc, 0x1004);
        assert_eq!(state.npc, 0x1008);
    }

    #[test]
    fn test_fp_double_read_write() {
        let mut state = RegWindowState::new(8);
        state.write_fp_double(0, 3.14);
        let v = state.read_fp_double(0);
        assert!((v - 3.14).abs() < 1e-10);
    }

    #[test]
    fn test_reg_class_prefix() {
        assert_eq!(RegClass::Global.prefix(), "g");
        assert_eq!(RegClass::Out.prefix(), "o");
        assert_eq!(RegClass::Local.prefix(), "l");
        assert_eq!(RegClass::In.prefix(), "i");
    }
}
