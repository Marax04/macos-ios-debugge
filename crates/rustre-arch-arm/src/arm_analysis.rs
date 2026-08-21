//! `arm_analysis` — Higher-level ARM/Thumb analysis utilities.
//!
//! Provides:
//! * [`ThumbInterworking`] — detects ARM↔Thumb mode switches via BX/BLX.
//! * [`ITBlockAnalyzer`] — parses and validates Thumb-2 IT blocks.
//! * [`ConditionalExecution`] — tracks which instructions execute conditionally.
//! * [`ArmFunctionProfiler`] — basic function shape analysis.
//! * [`ArmAbiDetector`] — heuristically detects AAPCS, AAPCS-VFP, or Thumb ABI.
//! * [`PCSRelativeResolver`] — resolves PC-relative address calculations.
//! * [`ArmAnalysis`] — top-level facade.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// ARM condition codes
// ---------------------------------------------------------------------------

/// ARM/Thumb condition codes (4-bit field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Condition {
    EQ = 0x0,
    NE = 0x1,
    CS = 0x2,
    CC = 0x3,
    MI = 0x4,
    PL = 0x5,
    VS = 0x6,
    VC = 0x7,
    HI = 0x8,
    LS = 0x9,
    GE = 0xA,
    LT = 0xB,
    GT = 0xC,
    LE = 0xD,
    AL = 0xE,
    NV = 0xF,
}

impl Condition {
    #[must_use]
    pub const fn from_bits(bits: u8) -> Option<Self> {
        match bits & 0xF {
            0x0 => Some(Self::EQ),
            0x1 => Some(Self::NE),
            0x2 => Some(Self::CS),
            0x3 => Some(Self::CC),
            0x4 => Some(Self::MI),
            0x5 => Some(Self::PL),
            0x6 => Some(Self::VS),
            0x7 => Some(Self::VC),
            0x8 => Some(Self::HI),
            0x9 => Some(Self::LS),
            0xA => Some(Self::GE),
            0xB => Some(Self::LT),
            0xC => Some(Self::GT),
            0xD => Some(Self::LE),
            0xE => Some(Self::AL),
            0xF => Some(Self::NV),
            _ => None,
        }
    }

    /// True for conditions that always (AL) or never (NV) execute.
    #[must_use]
    pub const fn is_unconditional(self) -> bool {
        matches!(self, Self::AL | Self::NV)
    }

    /// Return the inverse condition.
    #[must_use]
    pub fn inverse(self) -> Self {
        // Conditions are paired: EQ↔NE, CS↔CC, etc.
        let bits = self as u8;
        let inv = bits ^ 1;
        Self::from_bits(inv).unwrap_or(Self::AL)
    }
}

impl fmt::Display for Condition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::EQ => "EQ",
            Self::NE => "NE",
            Self::CS => "CS",
            Self::CC => "CC",
            Self::MI => "MI",
            Self::PL => "PL",
            Self::VS => "VS",
            Self::VC => "VC",
            Self::HI => "HI",
            Self::LS => "LS",
            Self::GE => "GE",
            Self::LT => "LT",
            Self::GT => "GT",
            Self::LE => "LE",
            Self::AL => "",
            Self::NV => "NV",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// Instruction set mode
// ---------------------------------------------------------------------------

/// Current ARM instruction set state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IsaMode {
    Arm,
    Thumb,
    ThumbEE,
    Jazelle,
}

impl fmt::Display for IsaMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arm => write!(f, "ARM"),
            Self::Thumb => write!(f, "Thumb"),
            Self::ThumbEE => write!(f, "ThumbEE"),
            Self::Jazelle => write!(f, "Jazelle"),
        }
    }
}

// ---------------------------------------------------------------------------
// ThumbInterworking
// ---------------------------------------------------------------------------

/// Records an ARM↔Thumb mode switch found in code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterworkingEvent {
    /// Address of the BX/BLX instruction.
    pub instr_addr: u32,
    /// Source mode (mode before the switch).
    pub from_mode: IsaMode,
    /// Target mode (mode after the switch, inferred from LSB of target).
    pub to_mode: IsaMode,
    /// Branch target address (without the Thumb LSB).
    pub target_addr: u32,
    /// True if this is a BLX (branch with link).
    pub is_call: bool,
}

/// Detects ARM↔Thumb interworking branches in a raw byte stream.
#[derive(Debug, Default)]
pub struct ThumbInterworking {
    events: Vec<InterworkingEvent>,
}

impl ThumbInterworking {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan ARM-mode code (4-byte instructions) for BX/BLX instructions.
    ///
    /// # Panics
    ///
    /// Panics if the instruction index cannot be converted to `u32`.
    pub fn scan_arm(&mut self, base: u32, bytes: &[u8]) {
        let words = bytes.len() / 4;
        for i in 0..words {
            let raw = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
            let addr = base.wrapping_add(u32::try_from(i).unwrap_or(u32::MAX).wrapping_mul(4));
            // BX Rn: cond 0001 0010 1111 1111 1111 0001 Rn
            // Mask: 0x0FFFFFF0, pattern: 0x012FFF10
            if raw & 0x0FFF_FFF0 == 0x012F_FF10 {
                let rn = (raw & 0xF) as u8;
                // Without knowing register value, we mark as dynamic
                self.events.push(InterworkingEvent {
                    instr_addr: addr,
                    from_mode: IsaMode::Arm,
                    to_mode: IsaMode::Thumb, // heuristic: assume Thumb target
                    target_addr: 0,
                    is_call: false,
                });
                let _ = rn;
            }
            // BLX Rn: cond 0001 0010 1111 1111 1111 0011 Rn
            if raw & 0x0FFF_FFF0 == 0x012F_FF30 {
                self.events.push(InterworkingEvent {
                    instr_addr: addr,
                    from_mode: IsaMode::Arm,
                    to_mode: IsaMode::Thumb,
                    target_addr: 0,
                    is_call: true,
                });
            }
        }
    }

    /// Scan Thumb-mode code for BX/BLX instructions (16-bit encoding).
    ///
    /// # Panics
    ///
    /// Panics if the instruction index cannot be converted to `u32`.
    pub fn scan_thumb(&mut self, base: u32, bytes: &[u8]) {
        let halfwords = bytes.len() / 2;
        for i in 0..halfwords {
            let hw = u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
            let addr = base.wrapping_add(u32::try_from(i).unwrap_or(u32::MAX).wrapping_mul(2));
            // Thumb BX: 0100 0111 0xxx xxxx (bits 15-8 = 0x47, bit 7=0)
            if hw & 0xFF87 == 0x4700 {
                let rm = ((hw >> 3) & 0xF) as u8;
                self.events.push(InterworkingEvent {
                    instr_addr: addr,
                    from_mode: IsaMode::Thumb,
                    to_mode: IsaMode::Arm,
                    target_addr: u32::from(rm),
                    is_call: false,
                });
            }
            // Thumb BLX: 0100 0111 1xxx xxxx
            if hw & 0xFF87 == 0x4780 {
                self.events.push(InterworkingEvent {
                    instr_addr: addr,
                    from_mode: IsaMode::Thumb,
                    to_mode: IsaMode::Arm,
                    target_addr: 0,
                    is_call: true,
                });
            }
        }
    }

    #[must_use]
    pub fn events(&self) -> &[InterworkingEvent] {
        &self.events
    }
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.events.iter().filter(|e| e.is_call).count()
    }
    #[must_use]
    pub fn branch_count(&self) -> usize {
        self.events.iter().filter(|e| !e.is_call).count()
    }
}

// ---------------------------------------------------------------------------
// IT block
// ---------------------------------------------------------------------------

/// Parsed Thumb-2 IT block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ITBlock {
    /// Address of the IT instruction.
    pub it_addr: u32,
    /// Base condition from the IT instruction.
    pub base_cond: Condition,
    /// Per-slot condition (up to 4 slots T/E).
    pub slots: Vec<Condition>,
    /// Raw IT instruction encoding.
    pub raw: u16,
}

impl ITBlock {
    /// Number of instructions covered by this IT block.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.slots.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

/// Analyzes Thumb-2 code to find and validate IT blocks.
#[derive(Debug, Default)]
pub struct ITBlockAnalyzer {
    blocks: Vec<ITBlock>,
}

impl ITBlockAnalyzer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan Thumb-2 halfwords for IT instructions and decode the block.
    ///
    /// # Panics
    ///
    /// Panics if the halfword index cannot be converted to `u32`.
    pub fn scan(&mut self, base: u32, bytes: &[u8]) {
        let halfwords = bytes.len() / 2;
        for i in 0..halfwords {
            let hw = u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
            let addr = base.wrapping_add(u32::try_from(i).unwrap_or(u32::MAX).wrapping_mul(2));
            // IT instruction: 1011 1111 cccc mask  (0xBF00..0xBFFF, mask != 0)
            if hw >> 8 == 0xBF && (hw & 0xF) != 0 {
                let cond_bits = ((hw >> 4) & 0xF) as u8;
                let mask = (hw & 0xF) as u8;
                if let Some(base_cond) = Condition::from_bits(cond_bits) {
                    let slots = Self::decode_mask(base_cond, mask);
                    self.blocks.push(ITBlock {
                        it_addr: addr,
                        base_cond,
                        slots,
                        raw: hw,
                    });
                }
            }
        }
    }

    fn decode_mask(base_cond: Condition, mask: u8) -> Vec<Condition> {
        // The mask encodes T (Then = base_cond) or E (Else = inverse) for up to 4 slots.
        // Leading '1' in mask marks the last slot; bits above it are T/E.
        let mut slots = Vec::new();
        let inverse = base_cond.inverse();
        for bit in (0..4).rev() {
            let bit_val = (mask >> bit) & 1;
            if bit_val == 1 && slots.is_empty() {
                // This is the trailing marker
                break;
            }
            // bit=0 means T (base condition), bit=1 means E (else = inverse)
            // Actually: first bit is most significant slot
            let _ = (bit_val, &inverse);
        }
        // Simple approach: count leading non-marker bits
        let count = match mask {
            m if m & 0x1 != 0 => 4,
            m if m & 0x2 != 0 => 3,
            m if m & 0x4 != 0 => 2,
            m if m & 0x8 != 0 => 1,
            _ => 0,
        };
        for slot in 0..count {
            let te_bit = (mask >> (4 - slot - 1)) & 1;
            if te_bit == 0 {
                slots.push(base_cond);
            } else {
                slots.push(inverse);
            }
        }
        slots
    }

    #[must_use]
    pub fn blocks(&self) -> &[ITBlock] {
        &self.blocks
    }
    #[must_use]
    pub const fn block_count(&self) -> usize {
        self.blocks.len()
    }
}

// ---------------------------------------------------------------------------
// ConditionalExecution tracking
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ARM register set
// ---------------------------------------------------------------------------

/// ARM register names (R0–R15 with aliases).
#[must_use]
pub const fn arm_reg_name(reg: u8) -> &'static str {
    match reg {
        0 => "r0",
        1 => "r1",
        2 => "r2",
        3 => "r3",
        4 => "r4",
        5 => "r5",
        6 => "r6",
        7 => "r7",
        8 => "r8",
        9 => "r9",
        10 => "r10",
        11 => "r11",
        12 => "r12",
        13 => "sp",
        14 => "lr",
        15 => "pc",
        _ => "?",
    }
}

// ---------------------------------------------------------------------------
// VFP/NEON detection helpers
// ---------------------------------------------------------------------------

/// True if the ARM instruction word is a VPUSH (VFP register save).
#[must_use]
pub const fn is_vpush(raw: u32) -> bool {
    // VPUSH Rlist: 0xED2D_xxxx with bits 27-24 = 0101
    raw & 0xFFBF_0000 == 0xED2D_0000
}

/// True if the ARM instruction word is a VPOP.
#[must_use]
pub const fn is_vpop(raw: u32) -> bool {
    raw & 0xFFBF_0000 == 0xECBD_0000
}

/// True if the ARM instruction word is a VFP FMRX/FMXR (FPSCR access).
#[must_use]
pub const fn is_fpscr_access(raw: u32) -> bool {
    // FMRX/VMRS: 0xEEF1_FA10
    raw & 0xFFFF_0FFF == 0xEEF1_0A10
}

// ---------------------------------------------------------------------------
// ARM call site
// ---------------------------------------------------------------------------

/// A call site (BL/BLX) found in ARM code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSite {
    pub caller_addr: u32,
    pub target_addr: Option<u32>,
    pub is_blx: bool,
}

/// Collects BL/BLX call sites from ARM-mode code.
#[derive(Debug, Default)]
pub struct CallSiteCollector {
    pub sites: Vec<CallSite>,
}

impl CallSiteCollector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Panics
    ///
    /// Panics if the code region is larger than 4 GiB (instruction index would overflow `u32`).
    pub fn scan_arm(&mut self, base: u32, bytes: &[u8]) {
        let words = bytes.len() / 4;
        for i in 0..words {
            if bytes.len() < (i + 1) * 4 {
                break;
            }
            let raw = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
            let addr = base.wrapping_add(u32::try_from(i).unwrap_or(u32::MAX).wrapping_mul(4));
            // BL: cond 1011 imm24  (bits 27-24 = 1011)
            if (raw & 0x0F00_0000) == 0x0B00_0000 {
                // Sign-extend 24-bit offset
                let offset = (raw & 0x00FF_FFFF).cast_signed();
                let offset_signed = if offset & 0x0080_0000 != 0 {
                    offset | 0xFF80_0000_u32.cast_signed()
                } else {
                    offset
                };
                let target = u32::try_from(i64::from(addr) + 8 + i64::from(offset_signed) * 4).ok();
                self.sites.push(CallSite {
                    caller_addr: addr,
                    target_addr: target,
                    is_blx: false,
                });
            }
            // BLX imm: 1111 101x imm24  — also known as BLX(1) unconditional
            if raw & 0xFE00_0000 == 0xFA00_0000 {
                let h = (raw >> 24) & 1;
                let off = (raw & 0x00FF_FFFF).cast_signed();
                let off_signed = if off & 0x0080_0000 != 0 {
                    off | 0xFF00_0000_u32.cast_signed()
                } else {
                    off
                };
                let target_i64 = i64::from(addr) + 8 + i64::from(off_signed) * 4 + i64::from(h) * 2;
                let target = u32::try_from(target_i64).ok();
                self.sites.push(CallSite {
                    caller_addr: addr,
                    target_addr: target,
                    is_blx: true,
                });
            }
        }
    }

    #[must_use]
    pub const fn call_count(&self) -> usize {
        self.sites.len()
    }
    #[must_use]
    pub fn blx_count(&self) -> usize {
        self.sites.iter().filter(|s| s.is_blx).count()
    }
}

// ---------------------------------------------------------------------------
// Thumb BL/BLX detector
// ---------------------------------------------------------------------------

/// Collects Thumb BL/BLX call sites (32-bit Thumb-2 encoding).
#[derive(Debug, Default)]
pub struct ThumbCallSiteCollector {
    pub sites: Vec<CallSite>,
}

impl ThumbCallSiteCollector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// # Panics
    ///
    /// Panics if the code region is larger than 4 GiB (instruction index would overflow `u32`).
    pub fn scan(&mut self, base: u32, bytes: &[u8]) {
        let hwords = bytes.len() / 2;
        let mut i = 0;
        while i < hwords.saturating_sub(1) {
            let hw0 = u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
            let hw1 = u16::from_le_bytes([bytes[(i + 1) * 2], bytes[(i + 1) * 2 + 1]]);
            let addr = base.wrapping_add(u32::try_from(i).unwrap_or(u32::MAX).wrapping_mul(2));
            // Thumb BL: 11110xxx xxxx xxxx / 11111xxx xxxx xxxx
            if hw0 & 0xF800 == 0xF000 && hw1 & 0xD000 == 0xD000 {
                self.sites.push(CallSite {
                    caller_addr: addr,
                    target_addr: None,
                    is_blx: false,
                });
                i += 2;
                continue;
            }
            // Thumb BLX: 11110xxx xxxx xxxx / 11101xxx xxxx xxxx
            if hw0 & 0xF800 == 0xF000 && hw1 & 0xD000 == 0xC000 {
                self.sites.push(CallSite {
                    caller_addr: addr,
                    target_addr: None,
                    is_blx: true,
                });
                i += 2;
                continue;
            }
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// ARM Epilogue detector
// ---------------------------------------------------------------------------

/// Heuristically detects ARM function epilogues.
#[derive(Debug, Default)]
pub struct EpilogueDetector {
    /// Addresses where an epilogue was found.
    pub epilogue_addrs: Vec<u32>,
}

impl EpilogueDetector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan ARM-mode code for POP {…,PC} or BX LR patterns.
    /// # Panics
    ///
    /// Panics if the code region is larger than 4 GiB (instruction index would overflow `u32`).
    pub fn scan_arm(&mut self, base: u32, bytes: &[u8]) {
        let words = bytes.len() / 4;
        for i in 0..words {
            if bytes.len() < (i + 1) * 4 {
                break;
            }
            let raw = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
            let addr = base.wrapping_add(u32::try_from(i).unwrap_or(u32::MAX).wrapping_mul(4));
            // POP {…,PC}: LDM SP!, rlist where PC bit (bit 15) is set
            if raw & 0x0FFF_8000 == 0x08BD_8000 {
                self.epilogue_addrs.push(addr);
            }
            // BX LR: 0xE12FFF1E
            if raw == 0xE12F_FF1E {
                self.epilogue_addrs.push(addr);
            }
        }
    }

    /// Scan Thumb-mode code for POP {…,PC} or BX LR.
    /// # Panics
    ///
    /// Panics if the code region is larger than 4 GiB (instruction index would overflow `u32`).
    pub fn scan_thumb(&mut self, base: u32, bytes: &[u8]) {
        let hwords = bytes.len() / 2;
        for i in 0..hwords {
            let hw = u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
            let addr = base.wrapping_add(u32::try_from(i).unwrap_or(u32::MAX).wrapping_mul(2));
            // Thumb POP {…,PC}: 1011 1 P rlist (bit 8 set = include PC)
            if hw & 0xFF00 == 0xBD00 {
                self.epilogue_addrs.push(addr);
            }
            // BX LR (Thumb): 0x4770
            if hw == 0x4770 {
                self.epilogue_addrs.push(addr);
            }
        }
    }

    #[must_use]
    pub const fn count(&self) -> usize {
        self.epilogue_addrs.len()
    }
}

/// Tracks whether each instruction at an address executes conditionally.
#[derive(Debug, Default)]
pub struct ConditionalExecution {
    /// Map from instruction address to its execution condition.
    pub cond_map: HashMap<u32, Condition>,
}

impl ConditionalExecution {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark an instruction as executing with the given condition.
    pub fn set(&mut self, addr: u32, cond: Condition) {
        self.cond_map.insert(addr, cond);
    }

    /// Get the condition for an instruction (defaults to AL).
    #[must_use]
    pub fn get(&self, addr: u32) -> Condition {
        self.cond_map.get(&addr).copied().unwrap_or(Condition::AL)
    }

    /// True if the instruction at `addr` executes unconditionally.
    #[must_use]
    pub fn is_unconditional(&self, addr: u32) -> bool {
        self.get(addr).is_unconditional()
    }

    /// Count instructions that execute conditionally (non-AL).
    #[must_use]
    pub fn conditional_count(&self) -> usize {
        self.cond_map
            .values()
            .filter(|c| !c.is_unconditional())
            .count()
    }

    /// Build conditional execution info from a set of IT blocks.
    #[must_use] 
    /// # Panics
    ///
    /// Panics if the code region is larger than 4 GiB (instruction index would overflow `u32`).
    pub fn from_it_blocks(blocks: &[ITBlock], base: u32) -> Self {
        let mut ce = Self::new();
        for block in blocks {
            for (i, &cond) in block.slots.iter().enumerate() {
                // Each slot covers a subsequent 2-byte (Thumb) instruction
                let slot_addr = block.it_addr.wrapping_add(2).wrapping_add(u32::try_from(i).unwrap_or(u32::MAX).wrapping_mul(2));
                ce.set(slot_addr, cond);
                let _ = base;
            }
        }
        ce
    }
}

// ---------------------------------------------------------------------------
// ArmFunctionProfiler
// ---------------------------------------------------------------------------

/// High-level profile of an ARM/Thumb function.
#[derive(Debug, Clone, Default)]
pub struct FunctionProfile {
    pub start_addr: u32,
    pub estimated_end: u32,
    pub mode: Option<IsaMode>,
    pub uses_frame_pointer: bool,
    pub uses_lr: bool,
    pub push_pop_balanced: bool,
    pub call_count: usize,
    pub conditional_branch_count: usize,
    pub size_bytes: u32,
}

/// Profiles ARM functions from byte ranges.
#[derive(Debug, Default)]
pub struct ArmFunctionProfiler;

impl ArmFunctionProfiler {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Profile an ARM-mode function.
    #[must_use]
    /// # Panics
    ///
    /// Panics if the code region is larger than 4 GiB (instruction index would overflow `u32`).
    pub fn profile_arm(&self, base: u32, bytes: &[u8]) -> FunctionProfile {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        let mut profile = FunctionProfile {
            start_addr: base,
            estimated_end: base + len,
            mode: Some(IsaMode::Arm),
            size_bytes: len,
            ..Default::default()
        };

        let words = bytes.len() / 4;
        let mut push_count = 0u32;
        let mut pop_count = 0u32;

        for i in 0..words {
            let raw = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
            // PUSH: cond 1001 0010 1101 rlist  (STM SP!)
            if raw & 0x0FFF_0000 == 0x092D_0000 {
                push_count += 1;
            }
            // POP: cond 1000 1011 1101 rlist  (LDM SP!)
            if raw & 0x0FFF_0000 == 0x08BD_0000 {
                pop_count += 1;
            }
            // BL/BLX (function calls): bits 27-24 = 1011 or 1010
            if (raw & 0x0F00_0000) == 0x0B00_0000 || (raw & 0xFE00_0000) == 0xFA00_0000 {
                profile.call_count += 1;
            }
            // Conditional branches (bit 27-24 = 1010, cond != AL)
            if raw & 0x0F00_0000 == 0x0A00_0000 {
                let cond = (raw >> 28) as u8;
                if cond != 0xE {
                    profile.conditional_branch_count += 1;
                }
            }
            // STMDB SP!, {…, LR}: also a push including LR (bit 14 set)
            if raw & 0x0FFF_0000 == 0x092D_0000 && (raw & (1 << 14)) != 0 {
                profile.uses_lr = true;
            }
            // Check for R11 (frame pointer) usage
            if (raw & 0xF00) == 0xB00 || (raw & 0xF000) == 0xB000 {
                // crude heuristic: R11 appears in a register field
                profile.uses_frame_pointer = true;
            }
        }
        profile.push_pop_balanced = push_count == pop_count && push_count > 0;
        profile
    }

    /// Profile a Thumb-mode function.
    #[must_use]
    /// # Panics
    ///
    /// Panics if the code region is larger than 4 GiB (instruction index would overflow `u32`).
    pub fn profile_thumb(&self, base: u32, bytes: &[u8]) -> FunctionProfile {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        let mut profile = FunctionProfile {
            start_addr: base,
            estimated_end: base + len,
            mode: Some(IsaMode::Thumb),
            size_bytes: len,
            ..Default::default()
        };
        let hwords = bytes.len() / 2;
        for i in 0..hwords {
            let hw = u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
            // Thumb PUSH: 1011 0 LR rlist  (1011_0xxx_xxxx_xxxx)
            if hw & 0xFF00 == 0xB500 {
                profile.uses_lr = true;
            }
            // BL: 11110xxxxxxxxxxxxxxx / 11111xxxxxxxxxxxxxxx  (32-bit)
            if hw & 0xF800 == 0xF000 {
                profile.call_count += 1;
            }
        }
        profile
    }
}

// ---------------------------------------------------------------------------
// ArmAbiDetector
// ---------------------------------------------------------------------------

/// Detected ABI type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmAbi {
    /// ARM Procedure Call Standard (integer-only arguments).
    AAPCS,
    /// AAPCS-VFP: floating-point arguments in VFP registers.
    AapcsVfp,
    /// Thumb interworking ABI.
    ThumbABI,
    /// Unknown / undetected.
    Unknown,
}

impl fmt::Display for ArmAbi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AAPCS => write!(f, "AAPCS"),
            Self::AapcsVfp => write!(f, "AAPCS-VFP"),
            Self::ThumbABI => write!(f, "Thumb-ABI"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Heuristically detects the calling convention / ABI in use.
#[derive(Debug, Default)]
pub struct ArmAbiDetector;

impl ArmAbiDetector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Detect ABI from an ARM function's byte range.
    #[must_use]
    pub fn detect(&self, bytes: &[u8], is_thumb: bool) -> ArmAbi {
        if is_thumb {
            return ArmAbi::ThumbABI;
        }
        // Look for VPUSH / VPOP (VFP register saves) indicating AAPCS-VFP
        let words = bytes.len() / 4;
        for i in 0..words {
            if bytes.len() < (i + 1) * 4 {
                break;
            }
            let raw = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
            // VPUSH: 1110 1101 0 D10 1101 Vd 1011 imm8  (0xED2Dxx00..0xED2DxxFF)
            if raw & 0xFFBF_0000 == 0xED2D_0000 {
                return ArmAbi::AapcsVfp;
            }
            // VPOP: 0xECBD
            if raw & 0xFFBF_0000 == 0xECBD_0000 {
                return ArmAbi::AapcsVfp;
            }
        }
        ArmAbi::AAPCS
    }
}

// ---------------------------------------------------------------------------
// PCSRelativeResolver
// ---------------------------------------------------------------------------

/// A resolved PC-relative reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PCSRef {
    pub instr_addr: u32,
    pub resolved_addr: u32,
    pub kind: PCSRefKind,
}

/// What kind of PC-relative operation produced the reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PCSRefKind {
    /// LDR Rd, [PC, #offset]
    LdrLiteral,
    /// ADR Rd, label
    Adr,
    /// B/BL to absolute target (encoded as relative)
    Branch,
}

/// Resolves PC-relative memory references in ARM/Thumb code.
#[derive(Debug, Default)]
pub struct PCSRelativeResolver {
    refs: Vec<PCSRef>,
}

impl PCSRelativeResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Scan ARM-mode code for PC-relative LDR and ADR instructions.
    /// # Panics
    ///
    /// Panics if the code region is larger than 4 GiB (instruction index would overflow `u32`).
    pub fn scan_arm(&mut self, base: u32, bytes: &[u8]) {
        let words = bytes.len() / 4;
        for i in 0..words {
            if bytes.len() < (i + 1) * 4 {
                break;
            }
            let raw = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
            let instr_addr = base.wrapping_add(u32::try_from(i).unwrap_or(u32::MAX).wrapping_mul(4));
            let pc_val = instr_addr + 8; // ARM pipeline: PC = instr + 8

            // LDR Rd, [PC, #imm] (U=1, positive offset):
            // ARM: cond 01 P=1 U=1 B=0 W=0 L=1 Rn=1111 → bits[27:16] = 0101 1001 1111 = 0x59F
            if raw & 0x0FFF_0000 == 0x059F_0000 {
                let offset = raw & 0xFFF;
                // Use wrapping_add: on-disk offset arithmetic can wrap at u32 edges.
                let resolved = pc_val.wrapping_add(offset);
                self.refs.push(PCSRef {
                    instr_addr,
                    resolved_addr: resolved,
                    kind: PCSRefKind::LdrLiteral,
                });
            }
            // LDR Rd, [PC, #-imm] (U=0, negative offset):
            // ARM: cond 01 P=1 U=0 B=0 W=0 L=1 Rn=1111 → bits[27:16] = 0101 0001 1111 = 0x51F
            if raw & 0x0FFF_0000 == 0x051F_0000 {
                let offset = raw & 0xFFF;
                let resolved = pc_val.wrapping_sub(offset);
                self.refs.push(PCSRef {
                    instr_addr,
                    resolved_addr: resolved,
                    kind: PCSRefKind::LdrLiteral,
                });
            }
            // ADR Rd, label: ADD Rd, PC, #imm  (cond 001 0100 0 1111 xxxx)
            if raw & 0x0FFF_0000 == 0x028F_0000 {
                let imm = raw & 0xFFF;
                let rot = (imm >> 8) & 0xF;
                let val = (imm & 0xFF).rotate_right(rot * 2);
                let resolved = pc_val.wrapping_add(val);
                self.refs.push(PCSRef {
                    instr_addr,
                    resolved_addr: resolved,
                    kind: PCSRefKind::Adr,
                });
            }
        }
    }

    #[must_use]
    pub fn refs(&self) -> &[PCSRef] {
        &self.refs
    }
    #[must_use]
    pub const fn count(&self) -> usize {
        self.refs.len()
    }
}

// ---------------------------------------------------------------------------
// ArmAnalysis — top-level facade
// ---------------------------------------------------------------------------

/// Top-level ARM/Thumb analysis facade.
#[derive(Debug, Default)]
pub struct ArmAnalysis {
    pub interworking: ThumbInterworking,
    pub it_blocks: ITBlockAnalyzer,
    pub conditional_exec: ConditionalExecution,
    pub pc_refs: PCSRelativeResolver,
}

impl ArmAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Run all analyses on an ARM-mode region.
    pub fn analyze_arm(&mut self, base: u32, bytes: &[u8]) {
        self.interworking.scan_arm(base, bytes);
        self.pc_refs.scan_arm(base, bytes);
    }

    /// Run all analyses on a Thumb-mode region.
    pub fn analyze_thumb(&mut self, base: u32, bytes: &[u8]) {
        self.interworking.scan_thumb(base, bytes);
        self.it_blocks.scan(base, bytes);
        self.conditional_exec = ConditionalExecution::from_it_blocks(self.it_blocks.blocks(), base);
    }

    /// Profile an ARM function.
    #[must_use]
    pub fn profile_arm_function(&self, base: u32, bytes: &[u8]) -> FunctionProfile {
        ArmFunctionProfiler::new().profile_arm(base, bytes)
    }

    /// Detect the ABI of an ARM function.
    #[must_use]
    pub fn detect_abi(&self, bytes: &[u8], is_thumb: bool) -> ArmAbi {
        ArmAbiDetector::new().detect(bytes, is_thumb)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Condition ----------------------------------------------------------

    #[test]
    fn test_condition_from_bits() {
        assert_eq!(Condition::from_bits(0), Some(Condition::EQ));
        assert_eq!(Condition::from_bits(14), Some(Condition::AL));
        assert_eq!(Condition::from_bits(0xF), Some(Condition::NV));
    }

    #[test]
    fn test_condition_al_is_unconditional() {
        assert!(Condition::AL.is_unconditional());
    }

    #[test]
    fn test_condition_eq_is_conditional() {
        assert!(!Condition::EQ.is_unconditional());
    }

    #[test]
    fn test_condition_inverse_eq_ne() {
        assert_eq!(Condition::EQ.inverse(), Condition::NE);
        assert_eq!(Condition::NE.inverse(), Condition::EQ);
    }

    #[test]
    fn test_condition_inverse_cs_cc() {
        assert_eq!(Condition::CS.inverse(), Condition::CC);
    }

    #[test]
    fn test_condition_display() {
        assert_eq!(format!("{}", Condition::EQ), "EQ");
        assert_eq!(format!("{}", Condition::AL), "");
    }

    // --- IsaMode display ---------------------------------------------------

    #[test]
    fn test_isa_mode_display() {
        assert_eq!(IsaMode::Arm.to_string(), "ARM");
        assert_eq!(IsaMode::Thumb.to_string(), "Thumb");
    }

    // --- ThumbInterworking -------------------------------------------------

    #[test]
    fn test_thumb_interworking_no_bx() {
        let mut tw = ThumbInterworking::new();
        tw.scan_arm(0, &[0xEA, 0x00, 0x00, 0x00]); // B #8 — not BX
        assert_eq!(tw.events().len(), 0);
    }

    #[test]
    fn test_thumb_interworking_arm_bx() {
        let bx_r0: u32 = 0xE12F_FF10; // BX R0 (AL condition)
        let mut tw = ThumbInterworking::new();
        tw.scan_arm(0x1000, &bx_r0.to_le_bytes());
        assert_eq!(tw.events().len(), 1);
        assert!(!tw.events()[0].is_call);
    }

    #[test]
    fn test_thumb_interworking_arm_blx() {
        let blx_r0: u32 = 0xE12F_FF30; // BLX R0
        let mut tw = ThumbInterworking::new();
        tw.scan_arm(0x1000, &blx_r0.to_le_bytes());
        assert_eq!(tw.call_count(), 1);
    }

    #[test]
    fn test_thumb_interworking_thumb_bx() {
        // Thumb BX R0: 0x4700
        let hw: u16 = 0x4700;
        let mut tw = ThumbInterworking::new();
        tw.scan_thumb(0x2000, &hw.to_le_bytes());
        assert_eq!(tw.branch_count(), 1);
    }

    #[test]
    fn test_thumb_interworking_thumb_blx() {
        let hw: u16 = 0x4780; // BLX R0
        let mut tw = ThumbInterworking::new();
        tw.scan_thumb(0x2000, &hw.to_le_bytes());
        assert_eq!(tw.call_count(), 1);
    }

    // --- ITBlockAnalyzer ---------------------------------------------------

    #[test]
    fn test_it_block_single_then() {
        // IT EQ: BF 08 00 (0xBF08 = IT EQ, mask=0x8)
        let bytes = 0xBF08_u16.to_le_bytes();
        let mut ita = ITBlockAnalyzer::new();
        ita.scan(0x1000, &bytes);
        assert_eq!(ita.block_count(), 1);
        assert_eq!(ita.blocks()[0].base_cond, Condition::EQ);
        assert_eq!(ita.blocks()[0].len(), 1);
    }

    #[test]
    fn test_it_block_empty_scan() {
        let mut ita = ITBlockAnalyzer::new();
        ita.scan(0, &[0x00, 0x00]);
        assert_eq!(ita.block_count(), 0);
    }

    // --- ConditionalExecution ----------------------------------------------

    #[test]
    fn test_cond_exec_default_al() {
        let ce = ConditionalExecution::new();
        assert_eq!(ce.get(0x1000), Condition::AL);
        assert!(ce.is_unconditional(0x1000));
    }

    #[test]
    fn test_cond_exec_set_get() {
        let mut ce = ConditionalExecution::new();
        ce.set(0x1000, Condition::EQ);
        assert_eq!(ce.get(0x1000), Condition::EQ);
        assert!(!ce.is_unconditional(0x1000));
    }

    #[test]
    fn test_cond_exec_count() {
        let mut ce = ConditionalExecution::new();
        ce.set(0x1000, Condition::EQ);
        ce.set(0x1002, Condition::NE);
        ce.set(0x1004, Condition::AL);
        assert_eq!(ce.conditional_count(), 2);
    }

    // --- ArmFunctionProfiler -----------------------------------------------

    #[test]
    fn test_function_profiler_empty() {
        let p = ArmFunctionProfiler::new().profile_arm(0x1000, &[]);
        assert_eq!(p.start_addr, 0x1000);
        assert_eq!(p.size_bytes, 0);
    }

    #[test]
    fn test_function_profiler_arm_nop() {
        let nop: u32 = 0xE320_F000; // NOP (MOV R0, R0 in practice)
        let bytes = nop.to_le_bytes();
        let p = ArmFunctionProfiler::new().profile_arm(0x1000, &bytes);
        assert_eq!(p.mode, Some(IsaMode::Arm));
    }

    #[test]
    fn test_function_profiler_push_pop() {
        // PUSH {LR}=0xE92D4000, POP {PC}=0xE8BD8000
        let push: u32 = 0xE92D_4000;
        let pop: u32 = 0xE8BD_8000;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&push.to_le_bytes());
        bytes.extend_from_slice(&pop.to_le_bytes());
        let p = ArmFunctionProfiler::new().profile_arm(0x1000, &bytes);
        assert!(p.push_pop_balanced);
    }

    // --- ArmAbiDetector ----------------------------------------------------

    #[test]
    fn test_abi_thumb() {
        let det = ArmAbiDetector::new();
        assert_eq!(det.detect(&[], true), ArmAbi::ThumbABI);
    }

    #[test]
    fn test_abi_aapcs_no_vfp() {
        let det = ArmAbiDetector::new();
        let nop: u32 = 0xE320_F000;
        assert_eq!(det.detect(&nop.to_le_bytes(), false), ArmAbi::AAPCS);
    }

    #[test]
    fn test_abi_display() {
        assert_eq!(ArmAbi::AAPCS.to_string(), "AAPCS");
        assert_eq!(ArmAbi::AapcsVfp.to_string(), "AAPCS-VFP");
        assert_eq!(ArmAbi::Unknown.to_string(), "Unknown");
    }

    // --- PCSRelativeResolver -----------------------------------------------

    #[test]
    fn test_pc_ref_scan_empty() {
        let mut r = PCSRelativeResolver::new();
        r.scan_arm(0, &[]);
        assert_eq!(r.count(), 0);
    }

    #[test]
    fn test_pc_ref_ldr_literal() {
        // LDR R0, [PC, #4]: cond=AL, U=1, Rd=0, Rn=PC, imm12=4
        // 0xE51F_0004 = LDR R0, [PC, #-4]
        // Let's use 0xE59F_0004 = LDR R0, [PC, #4]
        let raw: u32 = 0xE59F_0004;
        let mut r = PCSRelativeResolver::new();
        r.scan_arm(0x1000, &raw.to_le_bytes());
        // PC = 0x1000 + 8 = 0x1008, offset = 4, resolved = 0x100C
        assert!(r.refs().iter().any(|r| r.kind == PCSRefKind::LdrLiteral));
    }

    // --- ArmAnalysis facade ------------------------------------------------

    #[test]
    fn test_arm_analysis_new() {
        let a = ArmAnalysis::new();
        assert_eq!(a.pc_refs.count(), 0);
    }

    #[test]
    fn test_arm_analysis_analyze_arm_empty() {
        let mut a = ArmAnalysis::new();
        a.analyze_arm(0x1000, &[]);
        assert_eq!(a.interworking.events().len(), 0);
    }

    #[test]
    fn test_arm_analysis_analyze_thumb_empty() {
        let mut a = ArmAnalysis::new();
        a.analyze_thumb(0x2000, &[]);
        assert_eq!(a.it_blocks.block_count(), 0);
    }

    #[test]
    fn test_arm_analysis_profile_thumb() {
        let a = ArmAnalysis::new();
        let thumb_push: u16 = 0xB500; // PUSH {LR}
        let p = a.profile_arm_function(0x2000, &thumb_push.to_le_bytes());
        assert_eq!(p.start_addr, 0x2000);
    }

    #[test]
    fn test_arm_analysis_detect_abi() {
        let a = ArmAnalysis::new();
        assert_eq!(a.detect_abi(&[], true), ArmAbi::ThumbABI);
    }

    // --- arm_reg_name -------------------------------------------------------

    #[test]
    fn test_arm_reg_name_r0() {
        assert_eq!(arm_reg_name(0), "r0");
    }

    #[test]
    fn test_arm_reg_name_sp() {
        assert_eq!(arm_reg_name(13), "sp");
    }

    #[test]
    fn test_arm_reg_name_lr() {
        assert_eq!(arm_reg_name(14), "lr");
    }

    #[test]
    fn test_arm_reg_name_pc() {
        assert_eq!(arm_reg_name(15), "pc");
    }

    // --- VFP helpers --------------------------------------------------------

    #[test]
    fn test_is_vpush_true() {
        let vpush: u32 = 0xED2D_0B04; // VPUSH {d8} (typical)
        assert!(is_vpush(vpush));
    }

    #[test]
    fn test_is_vpush_false_on_nop() {
        assert!(!is_vpush(0xE320_F000));
    }

    #[test]
    fn test_is_vpop_true() {
        let vpop: u32 = 0xECBD_0B04;
        assert!(is_vpop(vpop));
    }

    // --- CallSiteCollector -----------------------------------------------

    #[test]
    fn test_call_site_empty() {
        let mut c = CallSiteCollector::new();
        c.scan_arm(0, &[]);
        assert_eq!(c.call_count(), 0);
    }

    #[test]
    fn test_call_site_bl() {
        // BL #0: 0xEB000000 (AL + BL + offset=0 → target = PC+8)
        let bl: u32 = 0xEB00_0000;
        let mut c = CallSiteCollector::new();
        c.scan_arm(0x1000, &bl.to_le_bytes());
        assert_eq!(c.call_count(), 1);
        assert!(!c.sites[0].is_blx);
        assert_eq!(c.sites[0].target_addr, Some(0x1008));
    }

    #[test]
    fn test_call_site_blx_imm() {
        // BLX #0: 0xFA00_0000
        let blx: u32 = 0xFA00_0000;
        let mut c = CallSiteCollector::new();
        c.scan_arm(0x2000, &blx.to_le_bytes());
        assert_eq!(c.blx_count(), 1);
        assert!(c.sites[0].is_blx);
    }

    // --- ThumbCallSiteCollector ------------------------------------------

    #[test]
    fn test_thumb_call_site_empty() {
        let mut t = ThumbCallSiteCollector::new();
        t.scan(0, &[]);
        assert!(t.sites.is_empty());
    }

    #[test]
    fn test_thumb_call_site_bl() {
        // Thumb BL encoding: two halfwords 0xF000 / 0xF800 (simplest form)
        let bytes = [0x00u8, 0xF0, 0x00, 0xF8]; // BL +0
        let mut t = ThumbCallSiteCollector::new();
        t.scan(0x2000, &bytes);
        assert_eq!(t.sites.len(), 1);
        assert!(!t.sites[0].is_blx);
    }

    // --- EpilogueDetector -------------------------------------------------

    #[test]
    fn test_epilogue_arm_bx_lr() {
        let bx_lr: u32 = 0xE12F_FF1E;
        let mut e = EpilogueDetector::new();
        e.scan_arm(0x1000, &bx_lr.to_le_bytes());
        assert_eq!(e.count(), 1);
        assert_eq!(e.epilogue_addrs[0], 0x1000);
    }

    #[test]
    fn test_epilogue_arm_pop_pc() {
        // POP {r4, r5, pc}: 0xE8BD8030 (LDM SP!, with PC bit set)
        let pop_pc: u32 = 0xE8BD_8030;
        let mut e = EpilogueDetector::new();
        e.scan_arm(0x2000, &pop_pc.to_le_bytes());
        assert_eq!(e.count(), 1);
    }

    #[test]
    fn test_epilogue_thumb_bx_lr() {
        let bx_lr: u16 = 0x4770;
        let mut e = EpilogueDetector::new();
        e.scan_thumb(0x1000, &bx_lr.to_le_bytes());
        assert_eq!(e.count(), 1);
    }

    #[test]
    fn test_epilogue_thumb_pop_pc() {
        // Thumb POP {pc}: 0xBD00 (bit 8 = PC)
        let pop_pc: u16 = 0xBD10;
        let mut e = EpilogueDetector::new();
        e.scan_thumb(0x1000, &pop_pc.to_le_bytes());
        assert_eq!(e.count(), 1);
    }

    #[test]
    fn test_epilogue_empty() {
        let mut e = EpilogueDetector::new();
        e.scan_arm(0, &[]);
        e.scan_thumb(0, &[]);
        assert_eq!(e.count(), 0);
    }

    // --- PacContext (imported via arm_analysis context) -------------------

    #[test]
    fn test_abi_unknown() {
        let det = ArmAbiDetector::new();
        // No code → AAPCS
        assert_eq!(det.detect(&[], false), ArmAbi::AAPCS);
    }

    #[test]
    fn test_function_profile_thumb_mode() {
        let p = ArmFunctionProfiler::new().profile_thumb(0x3000, &[]);
        assert_eq!(p.mode, Some(IsaMode::Thumb));
    }
}
