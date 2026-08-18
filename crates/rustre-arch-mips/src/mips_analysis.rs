//! `mips_analysis` — Higher-level MIPS analysis utilities.
//!
//! Provides:
//! * [`DelaySlotAnalyzer`] — tracks branch delay slots and flags misuse.
//! * [`GlobalPointerUsage`] — tracks GP-relative accesses.
//! * [`MipsAbi`] — O32/N32/N64 calling convention models.
//! * [`MipsExceptionHandler`] — locates exception/interrupt handlers.
//! * [`MipsTlb`] — TLB operation detection.
//! * [`MipsBranchTargetTable`] — builds a table of all branch targets.
//! * [`MipsAnalysis`] — top-level facade.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

/// Re-exported map type used by MIPS analysis tables.
/// `BTreeMap` is used instead of `HashMap` to prevent hash-collision `DoS` when
/// keys derive from attacker-controlled binary content (addresses, offsets).
pub type MipsMap<K, V> = BTreeMap<K, V>;

// ---------------------------------------------------------------------------
// MIPS ABI
// ---------------------------------------------------------------------------

/// MIPS Application Binary Interface variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum MipsAbi {
    /// Classic 32-bit O32 ABI (a0-a3, v0-v1, at, sp, fp, ra).
    #[default]
    O32,
    /// 64-bit N32 ABI (32-bit addresses, 64-bit registers).
    N32,
    /// 64-bit N64 ABI (a0-a7, v0-v1, at, sp, fp, ra).
    N64,
    /// EABI (MIPS embedded ABI).
    EABI,
    /// Unknown/undetected.
    Unknown,
}

impl fmt::Display for MipsAbi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::O32 => "O32",
            Self::N32 => "N32",
            Self::N64 => "N64",
            Self::EABI => "EABI",
            Self::Unknown => "Unknown",
        };
        write!(f, "{s}")
    }
}

impl MipsAbi {
    /// Number of integer argument registers.
    #[must_use]
    pub const fn arg_reg_count(self) -> u8 {
        match self {
            Self::O32 | Self::EABI => 4,
            Self::N32 | Self::N64 => 8,
            Self::Unknown => 4,
        }
    }

    /// Starting register index for integer arguments.
    #[must_use]
    pub const fn first_arg_reg(self) -> u8 {
        4
    } // $a0 = $4 in all MIPS ABIs

    /// Return-value registers.
    #[must_use]
    pub const fn return_regs(self) -> &'static [u8] {
        match self {
            Self::O32 | Self::EABI => &[2, 3], // $v0, $v1
            Self::N32 | Self::N64 => &[2, 3],
            Self::Unknown => &[2],
        }
    }
}

// ---------------------------------------------------------------------------
// MIPS register helpers
// ---------------------------------------------------------------------------

#[must_use]
pub const fn mips_reg_name(reg: u8) -> &'static str {
    match reg {
        0 => "$zero",
        1 => "$at",
        2 => "$v0",
        3 => "$v1",
        4 => "$a0",
        5 => "$a1",
        6 => "$a2",
        7 => "$a3",
        8 => "$t0",
        9 => "$t1",
        10 => "$t2",
        11 => "$t3",
        12 => "$t4",
        13 => "$t5",
        14 => "$t6",
        15 => "$t7",
        16 => "$s0",
        17 => "$s1",
        18 => "$s2",
        19 => "$s3",
        20 => "$s4",
        21 => "$s5",
        22 => "$s6",
        23 => "$s7",
        24 => "$t8",
        25 => "$t9",
        26 => "$k0",
        27 => "$k1",
        28 => "$gp",
        29 => "$sp",
        30 => "$fp",
        31 => "$ra",
        _ => "$?",
    }
}

// ---------------------------------------------------------------------------
// Raw MIPS instruction helpers
// ---------------------------------------------------------------------------

/// Decode a MIPS instruction word.
#[derive(Debug, Clone, Copy)]
pub struct MipsInsn(pub u32);

impl MipsInsn {
    #[must_use]
    pub const fn op(self) -> u8 {
        ((self.0 >> 26) & 0x3F) as u8
    }
    #[must_use]
    pub const fn rs(self) -> u8 {
        ((self.0 >> 21) & 0x1F) as u8
    }
    #[must_use]
    pub const fn rt(self) -> u8 {
        ((self.0 >> 16) & 0x1F) as u8
    }
    #[must_use]
    pub const fn rd(self) -> u8 {
        ((self.0 >> 11) & 0x1F) as u8
    }
    #[must_use]
    pub const fn sa(self) -> u8 {
        ((self.0 >> 6) & 0x1F) as u8
    }
    #[must_use]
    pub const fn funct(self) -> u8 {
        (self.0 & 0x3F) as u8
    }
    #[must_use]
    pub const fn imm16(self) -> i16 {
        self.0 as i16
    }
    #[must_use]
    pub const fn instr_index(self) -> u32 {
        self.0 & 0x03FF_FFFF
    }

    /// True for branch instructions (BEQ/BNE/BLEZ/BGTZ/BLTZ/BGEZ and variants,
    /// plus COP1 FPU conditional branches BC1F/BC1T/BC1FL/BC1TL).
    #[must_use]
    pub fn is_branch(self) -> bool {
        if matches!(self.op(), 0x01 | 0x04 | 0x05 | 0x06 | 0x07) {
            return true;
        }
        // COP1 (op=0x11) with rs=0x08 encodes BC1F/BC1T/BC1FL/BC1TL, all of
        // which have a delay slot and must be treated as branches.
        if self.op() == 0x11 && self.rs() == 0x08 {
            return true;
        }
        false
    }

    /// True for jump instructions (J/JAL).
    #[must_use]
    pub fn is_jump(self) -> bool {
        matches!(self.op(), 0x02 | 0x03)
    }

    /// True for JR / JALR (SPECIAL funct 0x08 / 0x09).
    #[must_use]
    pub fn is_jr_jalr(self) -> bool {
        self.op() == 0x00 && matches!(self.funct(), 0x08 | 0x09)
    }

    /// True for any control-transfer instruction (has a delay slot).
    #[must_use]
    pub fn has_delay_slot(self) -> bool {
        self.is_branch() || self.is_jump() || self.is_jr_jalr()
    }

    /// True for GP-relative load/store (LW/SW/LH/SH/LB/SB with rs=$gp).
    #[must_use]
    pub fn is_gp_relative(self) -> bool {
        matches!(
            self.op(),
            0x23 | 0x21 | 0x20 | 0x25 | 0x24 | 0x28 | 0x29 | 0x2B
        ) && self.rs() == 28
    }

    /// True for SYSCALL.
    #[must_use]
    pub fn is_syscall(self) -> bool {
        self.op() == 0x00 && self.funct() == 0x0C
    }

    /// True for MFC0/MTC0 (coprocessor 0 moves — used for TLB).
    #[must_use]
    pub fn is_cop0(self) -> bool {
        self.op() == 0x10
    }

    /// True for TLBWI/TLBWR/TLBR/TLBP.
    #[must_use]
    pub fn is_tlb_op(self) -> bool {
        self.op() == 0x10 && self.rs() == 0x10 && matches!(self.funct(), 0x01 | 0x02 | 0x06 | 0x08)
    }

    /// Branch target address (PC-relative, i-type).
    #[must_use]
    pub fn branch_target(self, pc: u32) -> u32 {
        let offset = i32::from(self.imm16()) * 4;
        (pc as i32 + 4 + offset) as u32
    }

    /// Jump target (j-type absolute in 256 MB page).
    #[must_use]
    pub fn jump_target(self, pc: u32) -> u32 {
        (pc & 0xF000_0000) | (self.instr_index() << 2)
    }
}

// ---------------------------------------------------------------------------
// DelaySlotAnalyzer
// ---------------------------------------------------------------------------

/// Information about a branch/jump and its delay slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelaySlotInfo {
    pub branch_addr: u32,
    pub delay_slot_addr: u32,
    /// True if the delay slot contains another branch/jump (illegal).
    pub delay_slot_is_branch: bool,
    /// True if the delay slot is a NOP.
    pub delay_slot_is_nop: bool,
}

/// Scans MIPS code and builds delay-slot information.
#[derive(Debug, Default)]
pub struct DelaySlotAnalyzer {
    pub entries: Vec<DelaySlotInfo>,
}

// ---------------------------------------------------------------------------
// MIPS function profiler
// ---------------------------------------------------------------------------

/// High-level profile of a MIPS function.
#[derive(Debug, Clone, Default)]
pub struct MipsFunctionProfile {
    pub start_addr: u32,
    pub size_bytes: u32,
    pub abi: MipsAbi,
    pub saves_ra: bool,
    pub stack_frame_size: Option<i16>,
    pub call_count: usize,
    pub branch_count: usize,
    pub delay_slot_nop_count: usize,
}

/// Profiles MIPS functions.
#[derive(Debug, Default)]
pub struct MipsFunctionProfiler;

impl MipsFunctionProfiler {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn profile(&self, base: u32, bytes: &[u8], abi: MipsAbi) -> MipsFunctionProfile {
        let mut profile = MipsFunctionProfile {
            start_addr: base,
            // Saturate rather than silently truncate for buffers larger than 4 GiB.
            size_bytes: bytes.len().try_into().unwrap_or(u32::MAX),
            abi,
            ..Default::default()
        };
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
            let insn = MipsInsn(raw);
            // SW RA, offset(SP): saves return address (op=0x2B, rs=$sp=29, rt=$ra=31)
            if raw & 0xFFFF_0000 == 0xAFBF_0000 {
                profile.saves_ra = true;
            }
            // ADDIU SP, SP, -N: stack frame setup (op=0x09, rs=29, rt=29, imm<0)
            if raw & 0xFFFF_0000 == 0x27BD_0000 {
                let imm = raw as i16;
                if imm < 0 {
                    profile.stack_frame_size = Some(imm);
                }
            }
            // JAL / JALR: function calls
            if insn.op() == 0x03 || (insn.op() == 0x00 && insn.funct() == 0x09) {
                profile.call_count += 1;
            }
            // Branch instructions
            if insn.is_branch() {
                profile.branch_count += 1;
            }
            // NOP in delay slot
            if insn.has_delay_slot() && i + 1 < words {
                let ds = u32::from_le_bytes([
                    bytes[(i + 1) * 4],
                    bytes[(i + 1) * 4 + 1],
                    bytes[(i + 1) * 4 + 2],
                    bytes[(i + 1) * 4 + 3],
                ]);
                if ds == 0 {
                    profile.delay_slot_nop_count += 1;
                }
            }
        }
        profile
    }
}

// ---------------------------------------------------------------------------
// MIPS string scanner
// ---------------------------------------------------------------------------

/// Scans a MIPS binary for printable ASCII strings (min 4 chars).
#[must_use]
pub fn scan_mips_strings(base: u32, bytes: &[u8], min_len: usize) -> Vec<(u32, String)> {
    let mut result = Vec::new();
    let mut run_start: Option<usize> = None;
    let mut buf = String::new();
    for (i, &b) in bytes.iter().enumerate() {
        if b.is_ascii() && !b.is_ascii_control() {
            if run_start.is_none() {
                run_start = Some(i);
            }
            buf.push(b as char);
        } else {
            if buf.len() >= min_len {
                result.push((base + run_start.unwrap() as u32, std::mem::take(&mut buf)));
            } else {
                buf.clear();
            }
            run_start = None;
        }
    }
    if buf.len() >= min_len {
        // run_start is always Some when buf is non-empty; unwrap_or(0) would silently
        // produce a wrong address, so use unwrap() to expose logic errors early.
        result.push((base + run_start.unwrap() as u32, buf));
    }
    result
}

// ---------------------------------------------------------------------------
// MIPS ABI stack frame constants
// ---------------------------------------------------------------------------

pub mod mips_o32 {
    /// O32: integer argument registers
    pub const ARG_REGS: [u8; 4] = [4, 5, 6, 7];
    /// O32: return value registers
    pub const RET_REGS: [u8; 2] = [2, 3];
    /// O32: callee-saved registers
    pub const SAVED_REGS: [u8; 9] = [16, 17, 18, 19, 20, 21, 22, 23, 30];
    /// Register $ra (return address)
    pub const RA: u8 = 31;
    /// Register $sp (stack pointer)
    pub const SP: u8 = 29;
    /// Register $gp (global pointer)
    pub const GP: u8 = 28;
    /// Minimum stack frame alignment (bytes)
    pub const STACK_ALIGN: u32 = 8;
}

pub mod mips_n64 {
    pub const ARG_REGS: [u8; 8] = [4, 5, 6, 7, 8, 9, 10, 11];
    pub const RET_REGS: [u8; 2] = [2, 3];
    pub const SAVED_REGS: [u8; 9] = [16, 17, 18, 19, 20, 21, 22, 23, 30];
    pub const RA: u8 = 31;
    pub const SP: u8 = 29;
    pub const GP: u8 = 28;
    pub const STACK_ALIGN: u32 = 16;
}

impl DelaySlotAnalyzer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn scan(&mut self, base: u32, bytes: &[u8]) {
        let words = bytes.len() / 4;
        for i in 0..words {
            let raw = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
            let insn = MipsInsn(raw);
            let addr = base + (i as u32) * 4;
            if insn.has_delay_slot() {
                let ds_addr = addr + 4;
                let (ds_is_branch, ds_is_nop) = if i + 1 < words {
                    let ds_raw = u32::from_le_bytes([
                        bytes[(i + 1) * 4],
                        bytes[(i + 1) * 4 + 1],
                        bytes[(i + 1) * 4 + 2],
                        bytes[(i + 1) * 4 + 3],
                    ]);
                    let ds = MipsInsn(ds_raw);
                    (ds.has_delay_slot(), ds_raw == 0x00000000) // NOP = SLL $0,$0,0
                } else {
                    (false, false)
                };
                self.entries.push(DelaySlotInfo {
                    branch_addr: addr,
                    delay_slot_addr: ds_addr,
                    delay_slot_is_branch: ds_is_branch,
                    delay_slot_is_nop: ds_is_nop,
                });
            }
        }
    }

    /// Count branches with NOP in delay slot (wasted slot).
    #[must_use]
    pub fn nop_slot_count(&self) -> usize {
        self.entries.iter().filter(|e| e.delay_slot_is_nop).count()
    }

    /// Count illegal delay slots (branch in delay slot).
    #[must_use]
    pub fn illegal_slot_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.delay_slot_is_branch)
            .count()
    }
}

// ---------------------------------------------------------------------------
// GlobalPointerUsage
// ---------------------------------------------------------------------------

/// A GP-relative access found in code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpAccess {
    pub addr: u32,
    pub offset: i16,
    pub is_load: bool,
}

/// Tracks global pointer ($gp) usage in MIPS code.
#[derive(Debug, Default)]
pub struct GlobalPointerUsage {
    pub accesses: Vec<GpAccess>,
    pub gp_value: Option<u32>,
}

impl GlobalPointerUsage {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn set_gp(&mut self, gp: u32) {
        self.gp_value = Some(gp);
    }

    pub fn scan(&mut self, base: u32, bytes: &[u8]) {
        let words = bytes.len() / 4;
        for i in 0..words {
            let raw = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
            let insn = MipsInsn(raw);
            let addr = base + (i as u32) * 4;
            if insn.is_gp_relative() {
                let is_load = matches!(insn.op(), 0x23 | 0x21 | 0x20 | 0x25 | 0x24);
                self.accesses.push(GpAccess {
                    addr,
                    offset: insn.imm16(),
                    is_load,
                });
            }
        }
    }

    /// Resolve a GP-relative offset to an absolute address.
    #[must_use]
    pub fn resolve(&self, offset: i16) -> Option<u32> {
        self.gp_value.map(|gp| (i64::from(gp) + i64::from(offset)) as u32)
    }

    #[must_use]
    pub const fn access_count(&self) -> usize {
        self.accesses.len()
    }
}

// ---------------------------------------------------------------------------
// MipsExceptionHandler
// ---------------------------------------------------------------------------

/// An identified exception/interrupt handler entry point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionHandler {
    pub addr: u32,
    pub kind: ExceptionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionKind {
    GeneralException, // typically at BFC00180 or 80000080
    TLBMiss,          // typically at BFC00000 or 80000000
    CacheError,       // typically at BFC00100 or A0000100
    Interrupt,
    Syscall,
    Unknown,
}

/// Detects MIPS exception handlers by well-known addresses and patterns.
#[derive(Debug, Default)]
pub struct MipsExceptionHandler {
    pub handlers: Vec<ExceptionHandler>,
}

impl MipsExceptionHandler {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check well-known MIPS exception vector addresses.
    pub fn check_address(&mut self, addr: u32) {
        let kind = match addr {
            0xBFC0_0000 | 0x8000_0000 => ExceptionKind::TLBMiss,
            0xBFC0_0100 | 0xA000_0100 => ExceptionKind::CacheError,
            0xBFC0_0180 | 0x8000_0080 => ExceptionKind::GeneralException,
            0xBFC0_0200 | 0x8000_0180 => ExceptionKind::Interrupt,
            _ => return,
        };
        self.handlers.push(ExceptionHandler { addr, kind });
    }

    /// Scan for ERET instruction (return from exception) to hint at handler bodies.
    pub fn scan_for_eret(&mut self, base: u32, bytes: &[u8]) {
        let words = bytes.len() / 4;
        for i in 0..words {
            let raw = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
            // ERET: COP0 (op=0x10), CO=1, funct=0x18 → 0x42000018
            if raw == 0x4200_0018 {
                let addr = base + (i as u32) * 4;
                self.handlers.push(ExceptionHandler {
                    addr,
                    kind: ExceptionKind::Unknown,
                });
            }
        }
    }

    #[must_use]
    pub const fn handler_count(&self) -> usize {
        self.handlers.len()
    }
}

// ---------------------------------------------------------------------------
// MipsTlb
// ---------------------------------------------------------------------------

/// A TLB operation found in code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlbOp {
    pub addr: u32,
    pub kind: TlbOpKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlbOpKind {
    Tlbwi, // Write Indexed
    Tlbwr, // Write Random
    Tlbr,  // Read Indexed
    Tlbp,  // Probe
}

/// Detects TLB operations in MIPS code.
#[derive(Debug, Default)]
pub struct MipsTlb {
    pub ops: Vec<TlbOp>,
}

impl MipsTlb {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn scan(&mut self, base: u32, bytes: &[u8]) {
        let words = bytes.len() / 4;
        for i in 0..words {
            let raw = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
            let insn = MipsInsn(raw);
            let addr = base + (i as u32) * 4;
            if insn.is_tlb_op() {
                let kind = match insn.funct() {
                    0x02 => TlbOpKind::Tlbwi,
                    0x06 => TlbOpKind::Tlbwr,
                    0x01 => TlbOpKind::Tlbr,
                    0x08 => TlbOpKind::Tlbp,
                    _ => continue,
                };
                self.ops.push(TlbOp { addr, kind });
            }
        }
    }

    #[must_use]
    pub const fn op_count(&self) -> usize {
        self.ops.len()
    }
}

// ---------------------------------------------------------------------------
// MipsBranchTargetTable
// ---------------------------------------------------------------------------

/// Collects all branch targets from a MIPS code region.
#[derive(Debug, Default)]
pub struct MipsBranchTargetTable {
    pub targets: HashSet<u32>,
    /// All branch source addresses.
    pub sources: Vec<u32>,
}

impl MipsBranchTargetTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn scan(&mut self, base: u32, bytes: &[u8]) {
        let words = bytes.len() / 4;
        for i in 0..words {
            let raw = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
            let insn = MipsInsn(raw);
            let addr = base + (i as u32) * 4;
            if insn.is_branch() {
                let target = insn.branch_target(addr);
                self.targets.insert(target);
                self.sources.push(addr);
            } else if insn.is_jump() {
                let target = insn.jump_target(addr);
                self.targets.insert(target);
                self.sources.push(addr);
            }
        }
    }

    #[must_use]
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }
    #[must_use]
    pub fn is_target(&self, addr: u32) -> bool {
        self.targets.contains(&addr)
    }
}

// ---------------------------------------------------------------------------
// MipsAnalysis — top-level facade
// ---------------------------------------------------------------------------

/// Top-level MIPS analysis facade.
#[derive(Debug, Default)]
pub struct MipsAnalysis {
    pub abi: MipsAbi,
    pub delay_slots: DelaySlotAnalyzer,
    pub gp_usage: GlobalPointerUsage,
    pub exceptions: MipsExceptionHandler,
    pub tlb: MipsTlb,
    pub branch_targets: MipsBranchTargetTable,
}

impl MipsAnalysis {
    #[must_use]
    pub fn new(abi: MipsAbi) -> Self {
        Self {
            abi,
            ..Default::default()
        }
    }

    /// Run all sub-analyses on a MIPS code region.
    pub fn analyze(&mut self, base: u32, bytes: &[u8]) {
        self.delay_slots.scan(base, bytes);
        self.gp_usage.scan(base, bytes);
        self.exceptions.scan_for_eret(base, bytes);
        self.tlb.scan(base, bytes);
        self.branch_targets.scan(base, bytes);
        // Check exception vector addresses
        self.exceptions.check_address(base);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn bytes_from(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    // --- MipsAbi -----------------------------------------------------------

    #[test]
    fn test_abi_display() {
        assert_eq!(MipsAbi::O32.to_string(), "O32");
        assert_eq!(MipsAbi::N64.to_string(), "N64");
    }

    #[test]
    fn test_abi_o32_args() {
        assert_eq!(MipsAbi::O32.arg_reg_count(), 4);
        assert_eq!(MipsAbi::O32.first_arg_reg(), 4);
    }

    #[test]
    fn test_abi_n64_args() {
        assert_eq!(MipsAbi::N64.arg_reg_count(), 8);
    }

    #[test]
    fn test_abi_return_regs() {
        assert_eq!(MipsAbi::O32.return_regs(), &[2, 3]);
    }

    // --- MipsInsn ----------------------------------------------------------

    #[test]
    fn test_mips_insn_nop_no_delay() {
        // NOP = 0x00000000 (SLL $0,$0,0)
        let insn = MipsInsn(0x00000000);
        assert!(!insn.has_delay_slot());
    }

    #[test]
    fn test_mips_insn_j_has_delay() {
        // J target: op=0x02
        let insn = MipsInsn(0x0800_0000);
        assert!(insn.is_jump());
        assert!(insn.has_delay_slot());
    }

    #[test]
    fn test_mips_insn_jr_has_delay() {
        // JR $ra: 0x03E00008
        let insn = MipsInsn(0x03E0_0008);
        assert!(insn.is_jr_jalr());
        assert!(insn.has_delay_slot());
    }

    #[test]
    fn test_mips_insn_beq_branch() {
        // BEQ $a0, $zero, offset: op=0x04
        let insn = MipsInsn(0x1080_0002); // BEQ $a0, $zero, +8
        assert!(insn.is_branch());
        assert!(insn.has_delay_slot());
    }

    #[test]
    fn test_mips_insn_branch_target() {
        // BEQ $a0, $zero, +2 (imm=2) at PC=0x1000
        let insn = MipsInsn(0x1080_0002);
        let target = insn.branch_target(0x1000);
        // target = 0x1000 + 4 + 2*4 = 0x100C
        assert_eq!(target, 0x100C);
    }

    #[test]
    fn test_mips_insn_jump_target() {
        // J 0x00400000 (index=0x100000) at PC=0x80400000
        let insn = MipsInsn(0x0810_0000);
        let target = insn.jump_target(0x8000_0000);
        assert_eq!(target, 0x8040_0000);
    }

    #[test]
    fn test_mips_insn_gp_relative() {
        // LW rt, offset($gp): op=0x23, rs=28
        let insn = MipsInsn((0x23u32 << 26) | (28u32 << 21) | (1u32 << 16) | 0x10);
        assert!(insn.is_gp_relative());
    }

    #[test]
    fn test_mips_insn_tlb_op() {
        // TLBWI = 0x42000002
        let insn = MipsInsn(0x4200_0002);
        assert!(insn.is_tlb_op());
    }

    #[test]
    fn test_mips_reg_name() {
        assert_eq!(mips_reg_name(0), "$zero");
        assert_eq!(mips_reg_name(31), "$ra");
        assert_eq!(mips_reg_name(28), "$gp");
    }

    // --- DelaySlotAnalyzer ------------------------------------------------

    #[test]
    fn test_delay_slot_nop() {
        let jr: u32 = 0x03E0_0008; // JR $ra
        let nop: u32 = 0x0000_0000; // NOP
        let bytes = bytes_from(&[jr, nop]);
        let mut dsa = DelaySlotAnalyzer::new();
        dsa.scan(0x1000, &bytes);
        assert_eq!(dsa.entries.len(), 1);
        assert!(dsa.entries[0].delay_slot_is_nop);
        assert_eq!(dsa.nop_slot_count(), 1);
    }

    #[test]
    fn test_delay_slot_no_branch() {
        let nop: u32 = 0x0000_0000;
        let bytes = bytes_from(&[nop, nop]);
        let mut dsa = DelaySlotAnalyzer::new();
        dsa.scan(0, &bytes);
        assert_eq!(dsa.entries.len(), 0);
    }

    #[test]
    fn test_delay_slot_illegal() {
        let jr1: u32 = 0x03E0_0008;
        let jr2: u32 = 0x03E0_0008; // branch in delay slot
        let bytes = bytes_from(&[jr1, jr2]);
        let mut dsa = DelaySlotAnalyzer::new();
        dsa.scan(0x1000, &bytes);
        assert_eq!(dsa.illegal_slot_count(), 1);
    }

    // --- GlobalPointerUsage -----------------------------------------------

    #[test]
    fn test_gp_usage_scan() {
        // LW $t0, 0x10($gp): op=0x23, rs=28, rt=8, imm=0x10
        let raw: u32 = (0x23u32 << 26) | (28u32 << 21) | (8u32 << 16) | 0x10;
        let bytes = bytes_from(&[raw]);
        let mut gpu = GlobalPointerUsage::new();
        gpu.scan(0x1000, &bytes);
        assert_eq!(gpu.access_count(), 1);
        assert!(gpu.accesses[0].is_load);
        assert_eq!(gpu.accesses[0].offset, 0x10);
    }

    #[test]
    fn test_gp_usage_resolve() {
        let mut gpu = GlobalPointerUsage::new();
        gpu.set_gp(0x10000000);
        assert_eq!(gpu.resolve(0x100), Some(0x10000100));
    }

    #[test]
    fn test_gp_usage_resolve_none() {
        let gpu = GlobalPointerUsage::new();
        assert!(gpu.resolve(0).is_none());
    }

    // --- MipsExceptionHandler ---------------------------------------------

    #[test]
    fn test_exception_check_tlb_miss() {
        let mut eh = MipsExceptionHandler::new();
        eh.check_address(0xBFC0_0000);
        assert_eq!(eh.handler_count(), 1);
        assert_eq!(eh.handlers[0].kind, ExceptionKind::TLBMiss);
    }

    #[test]
    fn test_exception_scan_eret() {
        let eret: u32 = 0x4200_0018;
        let bytes = bytes_from(&[eret]);
        let mut eh = MipsExceptionHandler::new();
        eh.scan_for_eret(0x8000_0080, &bytes);
        assert_eq!(eh.handler_count(), 1);
    }

    #[test]
    fn test_exception_no_eret() {
        let bytes = bytes_from(&[0x0000_0000u32]);
        let mut eh = MipsExceptionHandler::new();
        eh.scan_for_eret(0, &bytes);
        assert_eq!(eh.handler_count(), 0);
    }

    // --- MipsTlb ----------------------------------------------------------

    #[test]
    fn test_tlb_scan_tlbwi() {
        let tlbwi: u32 = 0x4200_0002;
        let bytes = bytes_from(&[tlbwi]);
        let mut tlb = MipsTlb::new();
        tlb.scan(0x1000, &bytes);
        assert_eq!(tlb.op_count(), 1);
        assert_eq!(tlb.ops[0].kind, TlbOpKind::Tlbwi);
    }

    #[test]
    fn test_tlb_scan_empty() {
        let bytes = bytes_from(&[0x0000_0000u32]);
        let mut tlb = MipsTlb::new();
        tlb.scan(0, &bytes);
        assert_eq!(tlb.op_count(), 0);
    }

    // --- MipsBranchTargetTable -------------------------------------------

    #[test]
    fn test_branch_target_table_beq() {
        let beq: u32 = 0x1080_0002; // BEQ $a0, $zero, +2 (target = PC+4+8)
        let bytes = bytes_from(&[beq, 0, 0, 0]);
        let mut btt = MipsBranchTargetTable::new();
        btt.scan(0x1000, &bytes);
        assert!(btt.target_count() > 0);
        assert!(btt.is_target(0x100C));
    }

    #[test]
    fn test_branch_target_table_no_branches() {
        let bytes = bytes_from(&[0x0000_0000u32]);
        let mut btt = MipsBranchTargetTable::new();
        btt.scan(0, &bytes);
        assert_eq!(btt.target_count(), 0);
    }

    // --- MipsAnalysis -----------------------------------------------------

    #[test]
    fn test_mips_analysis_new() {
        let a = MipsAnalysis::new(MipsAbi::O32);
        assert_eq!(a.abi, MipsAbi::O32);
    }

    #[test]
    fn test_mips_analysis_analyze_empty() {
        let mut a = MipsAnalysis::new(MipsAbi::O32);
        a.analyze(0x1000, &[]);
        assert_eq!(a.delay_slots.entries.len(), 0);
    }

    #[test]
    fn test_mips_analysis_analyze_jr_ra() {
        let jr: u32 = 0x03E0_0008;
        let nop: u32 = 0x0000_0000;
        let bytes = bytes_from(&[jr, nop]);
        let mut a = MipsAnalysis::new(MipsAbi::O32);
        a.analyze(0x1000, &bytes);
        assert_eq!(a.delay_slots.entries.len(), 1);
    }

    #[test]
    fn test_mips_exception_general_exception() {
        let mut eh = MipsExceptionHandler::new();
        eh.check_address(0xBFC0_0180);
        assert_eq!(eh.handlers[0].kind, ExceptionKind::GeneralException);
    }

    // --- Additional MipsAbi tests ---

    #[test]
    fn test_abi_eabi_args() {
        assert_eq!(MipsAbi::EABI.arg_reg_count(), 4);
    }

    #[test]
    fn test_abi_unknown_display() {
        assert_eq!(MipsAbi::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_abi_n32_display() {
        assert_eq!(MipsAbi::N32.to_string(), "N32");
    }

    // --- Additional MipsInsn tests ---

    #[test]
    fn test_mips_insn_jal_has_delay() {
        // JAL: op=0x03
        let insn = MipsInsn(0x0C00_0000);
        assert!(insn.is_jump());
        assert!(insn.has_delay_slot());
    }

    #[test]
    fn test_mips_insn_syscall() {
        let insn = MipsInsn(0x0000_000C);
        assert!(insn.is_syscall());
    }

    #[test]
    fn test_mips_insn_cop0() {
        let insn = MipsInsn(0x4000_0000); // op=0x10
        assert!(insn.is_cop0());
    }

    #[test]
    fn test_mips_insn_jalr_has_delay() {
        // JALR $ra, $t9: 0x0320F809
        let insn = MipsInsn(0x0320_F809);
        assert!(insn.is_jr_jalr());
        assert!(insn.has_delay_slot());
    }

    #[test]
    fn test_mips_insn_bne_is_branch() {
        // BNE $a0, $a1, offset: op=0x05
        let insn = MipsInsn(0x1485_0010);
        assert!(insn.is_branch());
    }

    #[test]
    fn test_mips_reg_name_gp() {
        assert_eq!(mips_reg_name(28), "$gp");
    }

    #[test]
    fn test_mips_reg_name_sp() {
        assert_eq!(mips_reg_name(29), "$sp");
    }

    #[test]
    fn test_mips_reg_name_fp() {
        assert_eq!(mips_reg_name(30), "$fp");
    }

    // --- DelaySlotAnalyzer additional ---

    #[test]
    fn test_delay_slot_jal() {
        let jal: u32 = 0x0C00_0000; // JAL
        let nop: u32 = 0x0000_0000;
        let bytes = bytes_from(&[jal, nop]);
        let mut dsa = DelaySlotAnalyzer::new();
        dsa.scan(0x1000, &bytes);
        assert_eq!(dsa.entries.len(), 1);
    }

    #[test]
    fn test_delay_slot_branch_count() {
        let jr: u32 = 0x03E0_0008;
        let add: u32 = 0x0120_1020; // ADDU r2,r1,r0 (not a branch)
        let bytes = bytes_from(&[jr, add]);
        let mut dsa = DelaySlotAnalyzer::new();
        dsa.scan(0, &bytes);
        assert!(!dsa.entries[0].delay_slot_is_nop);
        assert!(!dsa.entries[0].delay_slot_is_branch);
    }

    // --- GlobalPointerUsage additional ---

    #[test]
    fn test_gp_usage_negative_offset() {
        let mut gpu = GlobalPointerUsage::new();
        gpu.set_gp(0x10001000);
        assert_eq!(gpu.resolve(-0x100i16), Some(0x10000F00));
    }

    #[test]
    fn test_gp_usage_multiple_accesses() {
        // Two LW $gp instructions
        let lw1: u32 = (0x23u32 << 26) | (28u32 << 21) | (8u32 << 16) | 0x10;
        let lw2: u32 = (0x23u32 << 26) | (28u32 << 21) | (9u32 << 16) | 0x20;
        let bytes = bytes_from(&[lw1, lw2]);
        let mut gpu = GlobalPointerUsage::new();
        gpu.scan(0, &bytes);
        assert_eq!(gpu.access_count(), 2);
    }

    // --- MipsExceptionHandler additional ---

    #[test]
    fn test_exception_check_interrupt() {
        let mut eh = MipsExceptionHandler::new();
        eh.check_address(0x8000_0180);
        assert_eq!(eh.handlers[0].kind, ExceptionKind::Interrupt);
    }

    #[test]
    fn test_exception_check_cache_error() {
        let mut eh = MipsExceptionHandler::new();
        eh.check_address(0xBFC0_0100);
        assert_eq!(eh.handlers[0].kind, ExceptionKind::CacheError);
    }

    // --- MipsTlb additional ---

    #[test]
    fn test_tlb_scan_tlbp() {
        let tlbp: u32 = 0x4200_0008; // TLBP
        let bytes = bytes_from(&[tlbp]);
        let mut tlb = MipsTlb::new();
        tlb.scan(0, &bytes);
        assert_eq!(tlb.op_count(), 1);
        assert_eq!(tlb.ops[0].kind, TlbOpKind::Tlbp);
    }

    #[test]
    fn test_tlb_scan_tlbwr() {
        let tlbwr: u32 = 0x4200_0006; // TLBWR
        let bytes = bytes_from(&[tlbwr]);
        let mut tlb = MipsTlb::new();
        tlb.scan(0, &bytes);
        assert_eq!(tlb.op_count(), 1);
        assert_eq!(tlb.ops[0].kind, TlbOpKind::Tlbwr);
    }

    // --- MipsBranchTargetTable additional ---

    #[test]
    fn test_branch_target_multiple_branches() {
        let beq: u32 = 0x1080_0002;
        let bne: u32 = 0x1480_0004;
        let bytes = bytes_from(&[beq, 0, 0, bne, 0, 0]);
        let mut btt = MipsBranchTargetTable::new();
        btt.scan(0x1000, &bytes);
        assert!(btt.target_count() >= 2);
    }

    #[test]
    fn test_branch_target_is_target_false() {
        let btt = MipsBranchTargetTable::new();
        assert!(!btt.is_target(0x0000));
    }

    // --- MipsAnalysis additional ---

    #[test]
    fn test_mips_analysis_abi_n64() {
        let a = MipsAnalysis::new(MipsAbi::N64);
        assert_eq!(a.abi, MipsAbi::N64);
    }

    #[test]
    fn test_mips_analysis_tlb_detection() {
        let tlbwi: u32 = 0x4200_0002;
        let bytes = bytes_from(&[tlbwi]);
        let mut a = MipsAnalysis::new(MipsAbi::O32);
        a.analyze(0x1000, &bytes);
        assert_eq!(a.tlb.op_count(), 1);
    }

    // --- MipsFunctionProfiler ---

    #[test]
    fn test_function_profiler_empty() {
        let p = MipsFunctionProfiler::new().profile(0x8000, &[], MipsAbi::O32);
        assert_eq!(p.size_bytes, 0);
        assert_eq!(p.call_count, 0);
    }

    #[test]
    fn test_function_profiler_saves_ra() {
        // SW $ra, 0($sp): 0xAFBF_0000
        let sw_ra: u32 = 0xAFBF_0000;
        let bytes = bytes_from(&[sw_ra]);
        let p = MipsFunctionProfiler::new().profile(0x8000, &bytes, MipsAbi::O32);
        assert!(p.saves_ra);
    }

    #[test]
    fn test_function_profiler_stack_frame() {
        // ADDIU $sp, $sp, -32: 0x27BD_FFE0
        let addiu: u32 = 0x27BD_FFE0;
        let bytes = bytes_from(&[addiu]);
        let p = MipsFunctionProfiler::new().profile(0x8000, &bytes, MipsAbi::O32);
        assert_eq!(p.stack_frame_size, Some(-32));
    }

    #[test]
    fn test_function_profiler_jal_call() {
        let jal: u32 = 0x0C00_0000;
        let nop: u32 = 0x0000_0000;
        let bytes = bytes_from(&[jal, nop]);
        let p = MipsFunctionProfiler::new().profile(0x8000, &bytes, MipsAbi::O32);
        assert_eq!(p.call_count, 1);
    }

    #[test]
    fn test_function_profiler_delay_slot_nop() {
        let jr: u32 = 0x03E0_0008;
        let nop: u32 = 0x0000_0000;
        let bytes = bytes_from(&[jr, nop]);
        let p = MipsFunctionProfiler::new().profile(0x8000, &bytes, MipsAbi::O32);
        assert_eq!(p.delay_slot_nop_count, 1);
    }

    // --- scan_mips_strings ---

    #[test]
    fn test_scan_mips_strings_finds() {
        let data = b"HELLO\x00";
        let strings = scan_mips_strings(0x8000, data, 4);
        assert!(!strings.is_empty());
        assert_eq!(strings[0].1, "HELLO");
    }

    #[test]
    fn test_scan_mips_strings_empty() {
        let strings = scan_mips_strings(0, &[], 4);
        assert!(strings.is_empty());
    }

    // --- ABI constants ---

    #[test]
    fn test_o32_arg_regs() {
        assert_eq!(mips_o32::ARG_REGS[0], 4);
        assert_eq!(mips_o32::ARG_REGS[3], 7);
    }

    #[test]
    fn test_n64_arg_regs_count() {
        assert_eq!(mips_n64::ARG_REGS.len(), 8);
    }

    #[test]
    fn test_o32_stack_align() {
        assert_eq!(mips_o32::STACK_ALIGN, 8);
    }

    #[test]
    fn test_n64_stack_align() {
        assert_eq!(mips_n64::STACK_ALIGN, 16);
    }

    #[test]
    fn test_mips_ra_register() {
        assert_eq!(mips_o32::RA, 31);
        assert_eq!(mips_reg_name(mips_o32::RA), "$ra");
    }

    #[test]
    fn test_exception_kind_variants() {
        let _ = ExceptionKind::Syscall;
        let _ = ExceptionKind::TLBMiss;
        let _ = ExceptionKind::GeneralException;
    }

    #[test]
    fn test_tlb_op_kind_variants() {
        let _ = TlbOpKind::Tlbr;
        let _ = TlbOpKind::Tlbwi;
    }
}
