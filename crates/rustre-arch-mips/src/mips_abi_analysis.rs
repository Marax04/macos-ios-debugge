//! `mips_abi_analysis` — MIPS ABI analysis: O32, N64, EABI calling conventions,
//! argument passing rules, global-pointer tracking, and GOT entries.
//!
//! Provides:
//! * [`O32Abi`]            — classic 32-bit O32 ABI descriptor
//! * [`N64Abi`]            — 64-bit N64 ABI descriptor
//! * [`MipsEabi`]          — embedded MIPS EABI descriptor
//! * [`ArgPassingRules`]   — unified argument-passing rule engine
//! * [`GlobalPointerUsage`]— GP-relative access tracker
//! * [`GotEntry`]          — single GOT slot record
//! * [`MipsAbiAnalysis`]   — top-level analysis facade

use std::collections::{BTreeMap, HashSet};
use std::fmt;

// ---------------------------------------------------------------------------
// ABI identifiers
// ---------------------------------------------------------------------------

/// MIPS ABI variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MipsAbiKind {
    O32,
    N32,
    N64,
    Eabi,
    Unknown,
}

impl fmt::Display for MipsAbiKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::O32 => "o32",
            Self::N32 => "n32",
            Self::N64 => "n64",
            Self::Eabi => "eabi",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// O32 ABI
// ---------------------------------------------------------------------------

/// O32 integer argument registers (a0–a3).
pub const O32_INT_ARG: [&str; 4] = ["a0", "a1", "a2", "a3"];
/// O32 float argument registers (f12, f14).
pub const O32_FP_ARG: [&str; 2] = ["f12", "f14"];
/// O32 return value registers.
pub const O32_RET: [&str; 2] = ["v0", "v1"];
/// O32 callee-saved registers.
pub const O32_CALLEE_SAVED: [&str; 8] = ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"];
/// O32 temporary (caller-saved) registers.
pub const O32_TEMPORARIES: [&str; 9] = ["t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8"];

/// O32 ABI calling convention descriptor.
#[derive(Debug, Clone)]
pub struct O32Abi {
    /// Integer argument registers.
    pub int_args: Vec<String>,
    /// FP argument registers.
    pub fp_args: Vec<String>,
    /// Return registers.
    pub return_regs: Vec<String>,
    /// Callee-saved registers.
    pub callee_saved: Vec<String>,
    /// Temporaries.
    pub temporaries: Vec<String>,
}

impl O32Abi {
    /// Create an O32 ABI descriptor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            int_args: O32_INT_ARG.iter().map(|s| s.to_string()).collect(),
            fp_args: O32_FP_ARG.iter().map(|s| s.to_string()).collect(),
            return_regs: O32_RET.iter().map(|s| s.to_string()).collect(),
            callee_saved: O32_CALLEE_SAVED.iter().map(|s| s.to_string()).collect(),
            temporaries: O32_TEMPORARIES.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Whether a register is used for argument passing (integer).
    #[must_use]
    pub fn is_int_arg(&self, reg: &str) -> bool {
        self.int_args.iter().any(|s| s == reg)
    }

    /// Whether a register is FP argument.
    #[must_use]
    pub fn is_fp_arg(&self, reg: &str) -> bool {
        self.fp_args.iter().any(|s| s == reg)
    }

    /// Whether a register is callee-saved.
    #[must_use]
    pub fn is_callee_saved(&self, reg: &str) -> bool {
        self.callee_saved.iter().any(|s| s == reg)
    }

    /// Stack pointer name.
    #[must_use]
    pub fn stack_pointer() -> &'static str {
        "sp"
    }

    /// Return address register.
    #[must_use]
    pub fn return_address() -> &'static str {
        "ra"
    }

    /// Global pointer register.
    #[must_use]
    pub fn global_pointer() -> &'static str {
        "gp"
    }

    /// Frame pointer register.
    #[must_use]
    pub fn frame_pointer() -> &'static str {
        "fp"
    }

    /// Stack alignment in bytes.
    #[must_use]
    pub fn stack_alignment() -> usize {
        8
    }

    /// Minimum stack frame size (back-chain + saved-ra area in O32).
    #[must_use]
    pub fn min_frame_size() -> usize {
        32
    }
}

impl Default for O32Abi {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// N64 ABI
// ---------------------------------------------------------------------------

/// N64 integer argument registers (a0–a7).
pub const N64_INT_ARG: [&str; 8] = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"];
/// N64 FP argument registers (f12–f19, even only).
pub const N64_FP_ARG: [&str; 8] = ["f12", "f13", "f14", "f15", "f16", "f17", "f18", "f19"];
/// N64 return registers.
pub const N64_RET: [&str; 2] = ["v0", "v1"];

/// N64 ABI calling convention descriptor.
#[derive(Debug, Clone)]
pub struct N64Abi {
    /// Integer argument registers.
    pub int_args: Vec<String>,
    /// FP argument registers.
    pub fp_args: Vec<String>,
    /// Return registers.
    pub return_regs: Vec<String>,
    /// Callee-saved integer registers.
    pub callee_saved: Vec<String>,
}

impl N64Abi {
    /// Create an N64 ABI descriptor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            int_args: N64_INT_ARG.iter().map(|s| s.to_string()).collect(),
            fp_args: N64_FP_ARG.iter().map(|s| s.to_string()).collect(),
            return_regs: N64_RET.iter().map(|s| s.to_string()).collect(),
            callee_saved: vec!["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        }
    }

    /// Whether `reg` is an integer argument register.
    #[must_use]
    pub fn is_int_arg(&self, reg: &str) -> bool {
        self.int_args.iter().any(|s| s == reg)
    }

    /// Whether `reg` is a floating-point argument register.
    #[must_use]
    pub fn is_fp_arg(&self, reg: &str) -> bool {
        self.fp_args.iter().any(|s| s == reg)
    }

    /// Maximum integer args in registers.
    #[must_use]
    pub fn max_int_args_in_regs(&self) -> usize {
        self.int_args.len()
    }

    /// Stack alignment for N64 (16 bytes).
    #[must_use]
    pub fn stack_alignment() -> usize {
        16
    }

    /// Whether `reg` is callee-saved.
    #[must_use]
    pub fn is_callee_saved(&self, reg: &str) -> bool {
        self.callee_saved.iter().any(|s| s == reg)
    }
}

impl Default for N64Abi {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MIPS EABI
// ---------------------------------------------------------------------------

/// MIPS EABI integer argument registers (a0–a7, same as N64).
pub const EABI_INT_ARG: [&str; 8] = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"];
/// MIPS EABI FP argument registers.
pub const EABI_FP_ARG: [&str; 8] = ["f12", "f13", "f14", "f15", "f16", "f17", "f18", "f19"];

/// MIPS EABI calling convention.
#[derive(Debug, Clone)]
pub struct MipsEabi {
    /// Whether 32-bit (vs 64-bit mode).
    pub is_32bit: bool,
    pub int_args: Vec<String>,
    pub fp_args: Vec<String>,
    pub return_regs: Vec<String>,
    pub callee_saved: Vec<String>,
}

impl MipsEabi {
    /// Create an EABI descriptor.
    #[must_use]
    pub fn new(is_32bit: bool) -> Self {
        Self {
            is_32bit,
            int_args: EABI_INT_ARG.iter().map(|s| s.to_string()).collect(),
            fp_args: EABI_FP_ARG.iter().map(|s| s.to_string()).collect(),
            return_regs: vec!["v0".to_string(), "v1".to_string()],
            callee_saved: vec!["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"]
                .into_iter()
                .map(str::to_string)
                .collect(),
        }
    }

    /// Stack alignment for EABI.
    #[must_use]
    pub fn stack_alignment(&self) -> usize {
        if self.is_32bit { 8 } else { 16 }
    }

    /// Whether `reg` is an argument register.
    #[must_use]
    pub fn is_arg_reg(&self, reg: &str) -> bool {
        self.int_args.iter().any(|s| s == reg) || self.fp_args.iter().any(|s| s == reg)
    }
}

// ---------------------------------------------------------------------------
// Argument passing rules
// ---------------------------------------------------------------------------

/// How a single argument is passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgLocation {
    /// Passed in an integer register.
    IntReg(String),
    /// Passed in a floating-point register.
    FpReg(String),
    /// Passed on the stack at a given offset.
    Stack(usize),
    /// Passed split across a register and the stack.
    SplitRegStack { reg: String, stack_offset: usize },
}

/// Argument passing rules engine for MIPS ABIs.
#[derive(Debug, Clone)]
pub struct ArgPassingRules {
    /// ABI kind.
    pub abi: MipsAbiKind,
    /// Integer argument registers available (in order).
    pub int_regs: Vec<String>,
    /// FP argument registers available (in order).
    pub fp_regs: Vec<String>,
    /// Stack alignment.
    pub stack_align: usize,
    /// Next available integer register index.
    next_int: usize,
    /// Next available FP register index.
    next_fp: usize,
    /// Current stack offset.
    stack_offset: usize,
}

impl ArgPassingRules {
    /// Create an O32 argument-passing rule engine.
    #[must_use]
    pub fn for_o32() -> Self {
        Self {
            abi: MipsAbiKind::O32,
            int_regs: O32_INT_ARG.iter().map(|s| s.to_string()).collect(),
            fp_regs: O32_FP_ARG.iter().map(|s| s.to_string()).collect(),
            stack_align: 8,
            next_int: 0,
            next_fp: 0,
            stack_offset: 0,
        }
    }

    /// Create an N64 argument-passing rule engine.
    #[must_use]
    pub fn for_n64() -> Self {
        Self {
            abi: MipsAbiKind::N64,
            int_regs: N64_INT_ARG.iter().map(|s| s.to_string()).collect(),
            fp_regs: N64_FP_ARG.iter().map(|s| s.to_string()).collect(),
            stack_align: 16,
            next_int: 0,
            next_fp: 0,
            stack_offset: 0,
        }
    }

    /// Allocate location for an integer argument of `size` bytes.
    pub fn next_int_arg(&mut self, size: usize) -> ArgLocation {
        if self.next_int < self.int_regs.len() {
            let reg = self.int_regs[self.next_int].clone();
            self.next_int += 1;
            ArgLocation::IntReg(reg)
        } else {
            let off = self.stack_offset;
            self.stack_offset += size.max(self.stack_align);
            ArgLocation::Stack(off)
        }
    }

    /// Allocate location for a floating-point argument.
    pub fn next_fp_arg(&mut self) -> ArgLocation {
        if self.next_fp < self.fp_regs.len() {
            let reg = self.fp_regs[self.next_fp].clone();
            self.next_fp += 1;
            ArgLocation::FpReg(reg)
        } else {
            let off = self.stack_offset;
            self.stack_offset += 8;
            ArgLocation::Stack(off)
        }
    }

    /// Reset for a new function call.
    pub fn reset(&mut self) {
        self.next_int = 0;
        self.next_fp = 0;
        self.stack_offset = 0;
    }

    /// Number of arguments that fit in registers.
    #[must_use]
    pub fn regs_used(&self) -> usize {
        self.next_int + self.next_fp
    }
}

// ---------------------------------------------------------------------------
// Global Pointer Usage
// ---------------------------------------------------------------------------

/// A single GP-relative access record.
#[derive(Debug, Clone)]
pub struct GpAccess {
    /// Address of the instruction.
    pub address: u64,
    /// GP-relative offset.
    pub offset: i32,
    /// Whether it is a load (true) or store (false).
    pub is_load: bool,
    /// Access size in bytes.
    pub size: usize,
}

/// Tracks usage of the MIPS global pointer (GP/gp = $28).
#[derive(Debug, Clone, Default)]
pub struct GlobalPointerUsage {
    /// Base value of GP (set from .got/.sdata analysis).
    pub gp_value: u64,
    /// All GP-relative accesses recorded.
    pub accesses: Vec<GpAccess>,
    /// Unique GP offsets seen.
    pub offsets: HashSet<i32>,
    /// Whether GP was explicitly initialized (lui $gp / addiu $gp).
    pub gp_initialized: bool,
}

impl GlobalPointerUsage {
    /// Create a new GP usage tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the GP base value.
    pub fn set_gp(&mut self, value: u64) {
        self.gp_value = value;
        self.gp_initialized = true;
    }

    /// Record a GP-relative access.
    pub fn record_access(&mut self, address: u64, offset: i32, is_load: bool, size: usize) {
        self.offsets.insert(offset);
        self.accesses.push(GpAccess {
            address,
            offset,
            is_load,
            size,
        });
    }

    /// Number of unique GP offsets.
    #[must_use]
    pub fn unique_offset_count(&self) -> usize {
        self.offsets.len()
    }

    /// Absolute address of a GP-relative offset.
    #[must_use]
    pub fn absolute_addr(&self, offset: i32) -> u64 {
        self.gp_value.wrapping_add_signed(i64::from(offset))
    }

    /// GP-relative loads.
    #[must_use]
    pub fn loads(&self) -> Vec<&GpAccess> {
        self.accesses.iter().filter(|a| a.is_load).collect()
    }

    /// GP-relative stores.
    #[must_use]
    pub fn stores(&self) -> Vec<&GpAccess> {
        self.accesses.iter().filter(|a| !a.is_load).collect()
    }

    /// Range of GP offsets seen.
    #[must_use]
    pub fn offset_range(&self) -> Option<(i32, i32)> {
        if self.offsets.is_empty() {
            None
        } else {
            let min = *self.offsets.iter().min().unwrap();
            let max = *self.offsets.iter().max().unwrap();
            Some((min, max))
        }
    }
}

// ---------------------------------------------------------------------------
// GOT Entry
// ---------------------------------------------------------------------------

/// Kind of a MIPS GOT entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GotEntryKind {
    /// Local symbol or absolute address.
    Local,
    /// Global symbol (function or variable).
    Global,
    /// PLT stub entry.
    Plt,
    /// Thread-local storage entry.
    Tls,
}

/// A single MIPS GOT (Global Offset Table) entry.
#[derive(Debug, Clone)]
pub struct GotEntry {
    /// GOT index.
    pub index: usize,
    /// Byte offset from GOT base.
    pub offset: usize,
    /// Kind of entry.
    pub kind: GotEntryKind,
    /// Symbol name if known.
    pub symbol: Option<String>,
    /// Resolved target address.
    pub target: Option<u64>,
}

/// MIPS GOT manager.
#[derive(Debug, Clone, Default)]
pub struct MipsGot {
    /// Base address of the GOT.
    pub base: u64,
    /// All entries.
    pub entries: Vec<GotEntry>,
    /// Map from offset to entry index.
    /// Uses BTreeMap rather than HashMap to prevent hash-collision DoS when
    /// keys come from attacker-controlled GOT offsets in binary input.
    offset_to_idx: BTreeMap<usize, usize>,
}

impl MipsGot {
    /// Create a new GOT manager.
    #[must_use]
    pub fn new(base: u64) -> Self {
        Self {
            base,
            ..Default::default()
        }
    }

    /// Add a new entry.
    pub fn add_entry(
        &mut self,
        kind: GotEntryKind,
        offset: usize,
        symbol: Option<String>,
        target: Option<u64>,
    ) {
        let index = self.entries.len();
        self.offset_to_idx.entry(offset).or_insert(index);
        self.entries.push(GotEntry {
            index,
            offset,
            kind,
            symbol,
            target,
        });
    }

    /// Look up an entry by byte offset.
    #[must_use]
    pub fn lookup_by_offset(&self, offset: usize) -> Option<&GotEntry> {
        self.offset_to_idx.get(&offset).and_then(|&i| self.entries.get(i))
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the GOT is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// PLT entries.
    #[must_use]
    pub fn plt_entries(&self) -> Vec<&GotEntry> {
        self.entries
            .iter()
            .filter(|e| e.kind == GotEntryKind::Plt)
            .collect()
    }

    /// Global symbol entries.
    #[must_use]
    pub fn global_entries(&self) -> Vec<&GotEntry> {
        self.entries
            .iter()
            .filter(|e| e.kind == GotEntryKind::Global)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Top-level facade
// ---------------------------------------------------------------------------

/// Analysis finding.
#[derive(Debug, Clone)]
pub struct AbiAnalysisFinding {
    pub address: u64,
    pub message: String,
}

/// Top-level MIPS ABI analysis facade.
#[derive(Debug, Clone)]
pub struct MipsAbiAnalysis {
    /// Detected ABI kind.
    pub abi: MipsAbiKind,
    /// O32 descriptor (present for O32 ABI).
    pub o32: Option<O32Abi>,
    /// N64 descriptor (present for N64 ABI).
    pub n64: Option<N64Abi>,
    /// EABI descriptor (present for EABI).
    pub eabi: Option<MipsEabi>,
    /// Argument passing rules.
    pub arg_rules: ArgPassingRules,
    /// GP usage tracker.
    pub gp_usage: GlobalPointerUsage,
    /// GOT manager.
    pub got: MipsGot,
    /// Findings.
    pub findings: Vec<AbiAnalysisFinding>,
    /// Function entries.
    pub function_entries: HashSet<u64>,
    /// Total instructions.
    pub total_instructions: usize,
}

impl MipsAbiAnalysis {
    /// Create for O32 ABI.
    #[must_use]
    pub fn for_o32() -> Self {
        Self {
            abi: MipsAbiKind::O32,
            o32: Some(O32Abi::new()),
            n64: None,
            eabi: None,
            arg_rules: ArgPassingRules::for_o32(),
            gp_usage: GlobalPointerUsage::new(),
            got: MipsGot::new(0),
            findings: Vec::new(),
            function_entries: HashSet::new(),
            total_instructions: 0,
        }
    }

    /// Create for N64 ABI.
    #[must_use]
    pub fn for_n64() -> Self {
        Self {
            abi: MipsAbiKind::N64,
            o32: None,
            n64: Some(N64Abi::new()),
            eabi: None,
            arg_rules: ArgPassingRules::for_n64(),
            gp_usage: GlobalPointerUsage::new(),
            got: MipsGot::new(0),
            findings: Vec::new(),
            function_entries: HashSet::new(),
            total_instructions: 0,
        }
    }

    /// Create for EABI.
    #[must_use]
    pub fn for_eabi(is_32bit: bool) -> Self {
        Self {
            abi: MipsAbiKind::Eabi,
            o32: None,
            n64: None,
            eabi: Some(MipsEabi::new(is_32bit)),
            arg_rules: ArgPassingRules::for_n64(), // EABI uses same reg layout
            gp_usage: GlobalPointerUsage::new(),
            got: MipsGot::new(0),
            findings: Vec::new(),
            function_entries: HashSet::new(),
            total_instructions: 0,
        }
    }

    /// Record an instruction at an address.
    pub fn record_instruction(&mut self, _mnemonic: &str, _address: u64) {
        self.total_instructions += 1;
    }

    /// Record a GP-relative access.
    pub fn record_gp_access(&mut self, address: u64, offset: i32, is_load: bool, size: usize) {
        self.gp_usage.record_access(address, offset, is_load, size);
        self.findings.push(AbiAnalysisFinding {
            address,
            message: format!(
                "GP-relative {} at offset {offset}",
                if is_load { "load" } else { "store" }
            ),
        });
    }

    /// Add a function entry point.
    pub fn add_function_entry(&mut self, addr: u64) {
        self.function_entries.insert(addr);
    }

    /// Set the GOT base address.
    pub fn set_got_base(&mut self, base: u64) {
        self.got.base = base;
        self.gp_usage.set_gp(base);
    }

    /// ABI name.
    #[must_use]
    pub fn abi_name(&self) -> String {
        self.abi.to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── O32Abi ────────────────────────────────────────────────────────────────

    #[test]
    fn test_o32_int_args() {
        let abi = O32Abi::new();
        assert_eq!(abi.int_args.len(), 4);
        assert_eq!(abi.int_args[0], "a0");
    }

    #[test]
    fn test_o32_fp_args() {
        let abi = O32Abi::new();
        assert_eq!(abi.fp_args.len(), 2);
        assert_eq!(abi.fp_args[0], "f12");
    }

    #[test]
    fn test_o32_is_int_arg() {
        let abi = O32Abi::new();
        assert!(abi.is_int_arg("a0"));
        assert!(abi.is_int_arg("a3"));
        assert!(!abi.is_int_arg("a4"));
    }

    #[test]
    fn test_o32_is_fp_arg() {
        let abi = O32Abi::new();
        assert!(abi.is_fp_arg("f12"));
        assert!(!abi.is_fp_arg("f13"));
    }

    #[test]
    fn test_o32_is_callee_saved() {
        let abi = O32Abi::new();
        assert!(abi.is_callee_saved("s0"));
        assert!(abi.is_callee_saved("s7"));
        assert!(!abi.is_callee_saved("t0"));
    }

    #[test]
    fn test_o32_special_regs() {
        assert_eq!(O32Abi::stack_pointer(), "sp");
        assert_eq!(O32Abi::return_address(), "ra");
        assert_eq!(O32Abi::global_pointer(), "gp");
        assert_eq!(O32Abi::frame_pointer(), "fp");
    }

    #[test]
    fn test_o32_stack_alignment() {
        assert_eq!(O32Abi::stack_alignment(), 8);
    }

    #[test]
    fn test_o32_min_frame_size() {
        assert_eq!(O32Abi::min_frame_size(), 32);
    }

    // ── N64Abi ────────────────────────────────────────────────────────────────

    #[test]
    fn test_n64_int_args_count() {
        let abi = N64Abi::new();
        assert_eq!(abi.int_args.len(), 8);
        assert_eq!(abi.int_args[7], "a7");
    }

    #[test]
    fn test_n64_fp_args_count() {
        let abi = N64Abi::new();
        assert_eq!(abi.fp_args.len(), 8);
    }

    #[test]
    fn test_n64_is_int_arg() {
        let abi = N64Abi::new();
        assert!(abi.is_int_arg("a4"));
        assert!(!abi.is_int_arg("t0"));
    }

    #[test]
    fn test_n64_is_fp_arg() {
        let abi = N64Abi::new();
        assert!(abi.is_fp_arg("f12"));
        assert!(abi.is_fp_arg("f19"));
    }

    #[test]
    fn test_n64_stack_alignment() {
        assert_eq!(N64Abi::stack_alignment(), 16);
    }

    #[test]
    fn test_n64_max_int_args() {
        let abi = N64Abi::new();
        assert_eq!(abi.max_int_args_in_regs(), 8);
    }

    #[test]
    fn test_n64_callee_saved() {
        let abi = N64Abi::new();
        assert!(abi.is_callee_saved("s0"));
        assert!(!abi.is_callee_saved("t0"));
    }

    // ── MipsEabi ──────────────────────────────────────────────────────────────

    #[test]
    fn test_eabi_32bit_stack_align() {
        let abi = MipsEabi::new(true);
        assert_eq!(abi.stack_alignment(), 8);
    }

    #[test]
    fn test_eabi_64bit_stack_align() {
        let abi = MipsEabi::new(false);
        assert_eq!(abi.stack_alignment(), 16);
    }

    #[test]
    fn test_eabi_is_arg_reg() {
        let abi = MipsEabi::new(true);
        assert!(abi.is_arg_reg("a0"));
        assert!(abi.is_arg_reg("f12"));
        assert!(!abi.is_arg_reg("s0"));
    }

    // ── ArgPassingRules ───────────────────────────────────────────────────────

    #[test]
    fn test_arg_rules_o32_int_in_reg() {
        let mut rules = ArgPassingRules::for_o32();
        let loc = rules.next_int_arg(4);
        assert_eq!(loc, ArgLocation::IntReg("a0".to_string()));
    }

    #[test]
    fn test_arg_rules_o32_overflow_to_stack() {
        let mut rules = ArgPassingRules::for_o32();
        for _ in 0..4 {
            rules.next_int_arg(4);
        }
        let loc = rules.next_int_arg(4);
        assert!(matches!(loc, ArgLocation::Stack(_)));
    }

    #[test]
    fn test_arg_rules_n64_int_in_regs() {
        let mut rules = ArgPassingRules::for_n64();
        for i in 0..8 {
            let loc = rules.next_int_arg(8);
            assert!(
                matches!(loc, ArgLocation::IntReg(_)),
                "arg {i} should be in reg"
            );
        }
    }

    #[test]
    fn test_arg_rules_fp_in_reg() {
        let mut rules = ArgPassingRules::for_o32();
        let loc = rules.next_fp_arg();
        assert!(matches!(loc, ArgLocation::FpReg(_)));
    }

    #[test]
    fn test_arg_rules_fp_overflow() {
        let mut rules = ArgPassingRules::for_o32();
        rules.next_fp_arg();
        rules.next_fp_arg();
        let loc = rules.next_fp_arg();
        assert!(matches!(loc, ArgLocation::Stack(_)));
    }

    #[test]
    fn test_arg_rules_reset() {
        let mut rules = ArgPassingRules::for_o32();
        rules.next_int_arg(4);
        rules.next_int_arg(4);
        rules.reset();
        assert_eq!(rules.regs_used(), 0);
        let loc = rules.next_int_arg(4);
        assert_eq!(loc, ArgLocation::IntReg("a0".to_string()));
    }

    // ── GlobalPointerUsage ────────────────────────────────────────────────────

    #[test]
    fn test_gp_set_gp() {
        let mut gp = GlobalPointerUsage::new();
        gp.set_gp(0x10000);
        assert!(gp.gp_initialized);
        assert_eq!(gp.gp_value, 0x10000);
    }

    #[test]
    fn test_gp_absolute_addr() {
        let mut gp = GlobalPointerUsage::new();
        gp.set_gp(0x10000);
        assert_eq!(gp.absolute_addr(8), 0x10008);
        assert_eq!(gp.absolute_addr(-8), 0x0FFF8);
    }

    #[test]
    fn test_gp_record_access() {
        let mut gp = GlobalPointerUsage::new();
        gp.record_access(0x1000, -32, true, 4);
        assert_eq!(gp.accesses.len(), 1);
        assert_eq!(gp.unique_offset_count(), 1);
    }

    #[test]
    fn test_gp_offset_range() {
        let mut gp = GlobalPointerUsage::new();
        gp.record_access(0, -100, true, 4);
        gp.record_access(0, 200, false, 4);
        let (min, max) = gp.offset_range().unwrap();
        assert_eq!(min, -100);
        assert_eq!(max, 200);
    }

    #[test]
    fn test_gp_loads_stores() {
        let mut gp = GlobalPointerUsage::new();
        gp.record_access(0, 0, true, 4);
        gp.record_access(4, 4, false, 4);
        assert_eq!(gp.loads().len(), 1);
        assert_eq!(gp.stores().len(), 1);
    }

    // ── MipsGot ───────────────────────────────────────────────────────────────

    #[test]
    fn test_got_add_and_lookup() {
        let mut got = MipsGot::new(0x30000);
        got.add_entry(
            GotEntryKind::Global,
            8,
            Some("printf".to_string()),
            Some(0x40000),
        );
        let e = got.lookup_by_offset(8).unwrap();
        assert_eq!(e.symbol.as_deref(), Some("printf"));
        assert_eq!(e.kind, GotEntryKind::Global);
    }

    #[test]
    fn test_got_plt_entries() {
        let mut got = MipsGot::new(0);
        got.add_entry(GotEntryKind::Plt, 0, Some("f".to_string()), None);
        got.add_entry(GotEntryKind::Global, 8, None, None);
        assert_eq!(got.plt_entries().len(), 1);
        assert_eq!(got.global_entries().len(), 1);
    }

    #[test]
    fn test_got_len() {
        let mut got = MipsGot::new(0);
        assert!(got.is_empty());
        got.add_entry(GotEntryKind::Local, 0, None, None);
        assert_eq!(got.len(), 1);
    }

    // ── MipsAbiAnalysis ───────────────────────────────────────────────────────

    #[test]
    fn test_analysis_for_o32() {
        let a = MipsAbiAnalysis::for_o32();
        assert_eq!(a.abi, MipsAbiKind::O32);
        assert!(a.o32.is_some());
        assert_eq!(a.abi_name(), "o32");
    }

    #[test]
    fn test_analysis_for_n64() {
        let a = MipsAbiAnalysis::for_n64();
        assert_eq!(a.abi, MipsAbiKind::N64);
        assert!(a.n64.is_some());
    }

    #[test]
    fn test_analysis_for_eabi() {
        let a = MipsAbiAnalysis::for_eabi(true);
        assert_eq!(a.abi, MipsAbiKind::Eabi);
        assert!(a.eabi.is_some());
    }

    #[test]
    fn test_analysis_record_gp_access() {
        let mut a = MipsAbiAnalysis::for_o32();
        a.record_gp_access(0x1000, -16, true, 4);
        assert_eq!(a.gp_usage.accesses.len(), 1);
        assert_eq!(a.findings.len(), 1);
    }

    #[test]
    fn test_analysis_function_entries() {
        let mut a = MipsAbiAnalysis::for_n64();
        a.add_function_entry(0x1000);
        assert!(a.function_entries.contains(&0x1000));
    }

    #[test]
    fn test_analysis_set_got_base() {
        let mut a = MipsAbiAnalysis::for_o32();
        a.set_got_base(0x50000);
        assert_eq!(a.got.base, 0x50000);
        assert_eq!(a.gp_usage.gp_value, 0x50000);
    }

    #[test]
    fn test_analysis_total_instructions() {
        let mut a = MipsAbiAnalysis::for_o32();
        a.record_instruction("lw", 0x1000);
        a.record_instruction("sw", 0x1004);
        assert_eq!(a.total_instructions, 2);
    }
}
