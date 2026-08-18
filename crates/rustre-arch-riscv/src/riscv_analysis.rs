//! `riscv_analysis` — RISC-V higher-level analysis: ABI, compressed extension,
//! calling convention, soft-float detection, and PIC analysis.
//!
//! Provides:
//! * [`RiscVAbi`]          — ILP32 / LP64 / ILP32F / ILP32D / LP64F / LP64D
//! * [`RiscVCallingConv`]  — integer/float argument registers, return registers
//! * [`CompressedInsn`]    — C extension (RVC) decode and detection
//! * [`SoftFloat`]         — detection of soft-float emulation calls
//! * [`PicCode`]           — PIC/GOT pattern analysis
//! * [`RiscVAnalysis`]     — top-level facade

use std::collections::{HashMap, HashSet};
use std::fmt;

// ---------------------------------------------------------------------------
// RISC-V ABI
// ---------------------------------------------------------------------------

/// RISC-V Application Binary Interface variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiscVAbi {
    /// ILP32 — 32-bit integers, longs, and pointers; no floating-point regs.
    Ilp32,
    /// ILP32F — ILP32 with 32-bit float regs (F extension).
    Ilp32f,
    /// ILP32D — ILP32 with 64-bit double regs (D extension).
    Ilp32d,
    /// LP64 — 64-bit longs and pointers; no floating-point regs.
    Lp64,
    /// LP64F — LP64 with 32-bit float regs.
    Lp64f,
    /// LP64D — LP64 with 64-bit double regs.
    Lp64d,
    /// Unknown / not yet detected.
    Unknown,
}

impl RiscVAbi {
    /// Pointer size in bytes for this ABI.
    #[must_use]
    pub const fn pointer_size(self) -> usize {
        match self {
            Self::Ilp32 | Self::Ilp32f | Self::Ilp32d => 4,
            Self::Lp64 | Self::Lp64f | Self::Lp64d => 8,
            Self::Unknown => 4,
        }
    }

    /// Whether this ABI uses hardware floating-point registers.
    #[must_use]
    pub const fn has_fp_regs(self) -> bool {
        matches!(
            self,
            Self::Ilp32f | Self::Ilp32d | Self::Lp64f | Self::Lp64d
        )
    }

    /// Whether this ABI supports double-precision hardware float.
    #[must_use]
    pub const fn has_double_fp(self) -> bool {
        matches!(self, Self::Ilp32d | Self::Lp64d)
    }

    /// Return the `EF_RISCV_FLOAT_ABI` ELF flag value for this ABI.
    #[must_use]
    pub const fn elf_float_flag(self) -> u32 {
        match self {
            Self::Ilp32 | Self::Lp64 | Self::Unknown => 0x0000,
            Self::Ilp32f | Self::Lp64f => 0x0002,
            Self::Ilp32d | Self::Lp64d => 0x0004,
        }
    }

    /// Attempt to detect the ABI from an ELF `e_flags` value.
    #[must_use]
    pub const fn from_elf_flags(flags: u32, bits: u32) -> Self {
        let float_flag = flags & 0x0006;
        match (bits, float_flag) {
            (32, 0x0000) => Self::Ilp32,
            (32, 0x0002) => Self::Ilp32f,
            (32, 0x0004) => Self::Ilp32d,
            (64, 0x0000) => Self::Lp64,
            (64, 0x0002) => Self::Lp64f,
            (64, 0x0004) => Self::Lp64d,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for RiscVAbi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Ilp32 => "ilp32",
            Self::Ilp32f => "ilp32f",
            Self::Ilp32d => "ilp32d",
            Self::Lp64 => "lp64",
            Self::Lp64f => "lp64f",
            Self::Lp64d => "lp64d",
            Self::Unknown => "unknown",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// Calling Convention
// ---------------------------------------------------------------------------

/// Integer argument registers for RISC-V (a0–a7).
pub const INT_ARG_REGS: [&str; 8] = ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"];
/// Float argument registers for RISC-V (fa0–fa7).
pub const FLOAT_ARG_REGS: [&str; 8] = ["fa0", "fa1", "fa2", "fa3", "fa4", "fa5", "fa6", "fa7"];
/// Return value registers.
pub const RET_REGS: [&str; 2] = ["a0", "a1"];
/// Caller-saved (temporary) integer registers.
pub const CALLER_SAVED: [&str; 7] = ["t0", "t1", "t2", "t3", "t4", "t5", "t6"];
/// Callee-saved integer registers.
pub const CALLEE_SAVED: [&str; 12] = [
    "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
];

/// RISC-V calling convention descriptor.
#[derive(Debug, Clone)]
pub struct RiscVCallingConv {
    /// ABI this convention belongs to.
    pub abi: RiscVAbi,
    /// Integer argument registers (by ABI name).
    pub int_args: Vec<String>,
    /// Floating-point argument registers (by ABI name, empty if soft-float).
    pub fp_args: Vec<String>,
    /// Return value registers.
    pub return_regs: Vec<String>,
    /// Callee-saved registers.
    pub callee_saved: Vec<String>,
}

impl RiscVCallingConv {
    /// Build calling convention descriptor for a given ABI.
    #[must_use]
    pub fn for_abi(abi: RiscVAbi) -> Self {
        let fp_args = if abi.has_fp_regs() {
            FLOAT_ARG_REGS.iter().map(std::string::ToString::to_string).collect()
        } else {
            Vec::new()
        };
        Self {
            abi,
            int_args: INT_ARG_REGS.iter().map(std::string::ToString::to_string).collect(),
            fp_args,
            return_regs: RET_REGS.iter().map(std::string::ToString::to_string).collect(),
            callee_saved: CALLEE_SAVED.iter().map(std::string::ToString::to_string).collect(),
        }
    }

    /// Whether the named register is used for argument passing.
    #[must_use]
    pub fn is_arg_reg(&self, name: &str) -> bool {
        self.int_args.iter().any(|s| s == name) || self.fp_args.iter().any(|s| s == name)
    }

    /// Whether the named register is callee-saved.
    #[must_use]
    pub fn is_callee_saved(&self, name: &str) -> bool {
        self.callee_saved.iter().any(|s| s == name)
    }

    /// Maximum number of integer arguments passed in registers.
    #[must_use]
    pub const fn max_int_args_in_regs(&self) -> usize {
        self.int_args.len()
    }
}

// ---------------------------------------------------------------------------
// Compressed (RVC) instruction representation
// ---------------------------------------------------------------------------

/// A decoded RISC-V C-extension (16-bit) instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedInsn {
    /// Raw 16-bit encoding.
    pub raw: u16,
    /// Mnemonic string.
    pub mnemonic: String,
    /// Operands string.
    pub operands: String,
    /// Equivalent 32-bit instruction mnemonic (if unambiguous).
    pub expanded_mnemonic: Option<String>,
    /// Whether this is a valid RVC instruction.
    pub valid: bool,
}

impl CompressedInsn {
    /// Decode a 16-bit compressed instruction.
    #[must_use]
    pub fn decode(raw: u16) -> Self {
        let op = raw & 0x3; // bits[1:0]
        let funct3 = (raw >> 13) & 0x7; // bits[15:13]

        match op {
            0b00 => Self::decode_q0(raw, funct3),
            0b01 => Self::decode_q1(raw, funct3),
            0b10 => Self::decode_q2(raw, funct3),
            _ => Self::invalid(raw),
        }
    }

    fn reg3(r: u16) -> String {
        // 3-bit register encoding: maps to x8..x15
        let full = (r & 7) + 8;
        format!("x{full}")
    }

    fn reg5(r: u16) -> String {
        format!("x{r}")
    }

    fn invalid(raw: u16) -> Self {
        Self {
            raw,
            mnemonic: "c.illegal".to_string(),
            operands: format!("{raw:#06x}"),
            expanded_mnemonic: None,
            valid: false,
        }
    }

    fn make(raw: u16, mn: &str, ops: &str, expanded: Option<&str>) -> Self {
        Self {
            raw,
            mnemonic: mn.to_string(),
            operands: ops.to_string(),
            expanded_mnemonic: expanded.map(str::to_string),
            valid: true,
        }
    }

    fn decode_q0(raw: u16, funct3: u16) -> Self {
        let rd_s = (raw >> 2) & 7;
        let rs1_s = (raw >> 7) & 7;
        match funct3 {
            0b000 => {
                // C.ADDI4SPN
                let nzuimm = ((raw >> 6) & 1) << 2
                    | ((raw >> 5) & 1) << 3
                    | ((raw >> 11) & 3) << 4
                    | ((raw >> 7) & 0xF) << 6;
                if nzuimm == 0 {
                    return Self::invalid(raw);
                }
                Self::make(
                    raw,
                    "c.addi4spn",
                    &format!("{},{}", Self::reg3(rd_s), nzuimm),
                    Some("addi"),
                )
            }
            0b010 => {
                let uimm = ((raw >> 6) & 1) << 2 | ((raw >> 10) & 3) << 3 | ((raw >> 5) & 1) << 6;
                Self::make(
                    raw,
                    "c.lw",
                    &format!("{},{}({})", Self::reg3(rd_s), uimm, Self::reg3(rs1_s)),
                    Some("lw"),
                )
            }
            0b110 => {
                let uimm = ((raw >> 6) & 1) << 2 | ((raw >> 10) & 3) << 3 | ((raw >> 5) & 1) << 6;
                Self::make(
                    raw,
                    "c.sw",
                    &format!("{},{}({})", Self::reg3(rd_s), uimm, Self::reg3(rs1_s)),
                    Some("sw"),
                )
            }
            _ => Self::invalid(raw),
        }
    }

    fn decode_q1(raw: u16, funct3: u16) -> Self {
        let rd = (raw >> 7) & 31;
        match funct3 {
            0b000 => {
                if rd == 0 {
                    Self::make(raw, "c.nop", "", Some("addi"))
                } else {
                    let imm6 = ((raw >> 2) & 0x1F) as i16
                        | (if (raw >> 12) & 1 != 0 { -32i16 } else { 0 });
                    Self::make(
                        raw,
                        "c.addi",
                        &format!("{},{}", Self::reg5(rd), imm6),
                        Some("addi"),
                    )
                }
            }
            0b001 => {
                // C.JAL (RV32) / C.ADDIW (RV64)
                Self::make(raw, "c.jal", "<offset>", Some("jal"))
            }
            0b010 => {
                let imm =
                    ((raw >> 2) & 0x1F) as i16 | (if (raw >> 12) & 1 != 0 { -32i16 } else { 0 });
                Self::make(
                    raw,
                    "c.li",
                    &format!("{},{}", Self::reg5(rd), imm),
                    Some("addi"),
                )
            }
            0b011 => {
                if rd == 2 {
                    Self::make(raw, "c.addi16sp", "<nzimm*16>", Some("addi"))
                } else {
                    Self::make(
                        raw,
                        "c.lui",
                        &format!("{},<nzimm>", Self::reg5(rd)),
                        Some("lui"),
                    )
                }
            }
            0b100 => Self::decode_q1_misc(raw),
            0b101 => Self::make(raw, "c.j", "<offset>", Some("jal")),
            0b110 => {
                let rs1_s = (raw >> 7) & 7;
                Self::make(
                    raw,
                    "c.beqz",
                    &format!("{},<offset>", Self::reg3(rs1_s)),
                    Some("beq"),
                )
            }
            0b111 => {
                let rs1_s = (raw >> 7) & 7;
                Self::make(
                    raw,
                    "c.bnez",
                    &format!("{},<offset>", Self::reg3(rs1_s)),
                    Some("bne"),
                )
            }
            _ => Self::invalid(raw),
        }
    }

    fn decode_q1_misc(raw: u16) -> Self {
        let funct2 = (raw >> 10) & 3;
        let rs1_s = (raw >> 7) & 7;
        match funct2 {
            0b00 => Self::make(
                raw,
                "c.srli",
                &format!("{},<shamt>", Self::reg3(rs1_s)),
                Some("srli"),
            ),
            0b01 => Self::make(
                raw,
                "c.srai",
                &format!("{},<shamt>", Self::reg3(rs1_s)),
                Some("srai"),
            ),
            0b10 => Self::make(
                raw,
                "c.andi",
                &format!("{},<imm>", Self::reg3(rs1_s)),
                Some("andi"),
            ),
            0b11 => {
                let rs2_s = (raw >> 2) & 7;
                let funct6_hi = (raw >> 12) & 1;
                let funct2b = (raw >> 5) & 3;
                match (funct6_hi, funct2b) {
                    (0, 0b00) => Self::make(
                        raw,
                        "c.sub",
                        &format!("{},{}", Self::reg3(rs1_s), Self::reg3(rs2_s)),
                        Some("sub"),
                    ),
                    (0, 0b01) => Self::make(
                        raw,
                        "c.xor",
                        &format!("{},{}", Self::reg3(rs1_s), Self::reg3(rs2_s)),
                        Some("xor"),
                    ),
                    (0, 0b10) => Self::make(
                        raw,
                        "c.or",
                        &format!("{},{}", Self::reg3(rs1_s), Self::reg3(rs2_s)),
                        Some("or"),
                    ),
                    (0, 0b11) => Self::make(
                        raw,
                        "c.and",
                        &format!("{},{}", Self::reg3(rs1_s), Self::reg3(rs2_s)),
                        Some("and"),
                    ),
                    _ => Self::invalid(raw),
                }
            }
            _ => Self::invalid(raw),
        }
    }

    fn decode_q2(raw: u16, funct3: u16) -> Self {
        let rd = (raw >> 7) & 31;
        match funct3 {
            0b000 => Self::make(
                raw,
                "c.slli",
                &format!("{},<shamt>", Self::reg5(rd)),
                Some("slli"),
            ),
            0b010 => Self::make(
                raw,
                "c.lwsp",
                &format!("{},<uimm>(sp)", Self::reg5(rd)),
                Some("lw"),
            ),
            0b100 => {
                let rs2 = (raw >> 2) & 31;
                let j = (raw >> 12) & 1;
                match (j, rd, rs2) {
                    (0, _, 0) => {
                        Self::make(raw, "c.jr", &Self::reg5(rd).to_string(), Some("jalr"))
                    }
                    (0, _, _) => Self::make(
                        raw,
                        "c.mv",
                        &format!("{},{}", Self::reg5(rd), Self::reg5(rs2)),
                        Some("add"),
                    ),
                    (1, 0, 0) => Self::make(raw, "c.ebreak", "", Some("ebreak")),
                    (1, _, 0) => {
                        Self::make(raw, "c.jalr", &Self::reg5(rd).to_string(), Some("jalr"))
                    }
                    (1, _, _) => Self::make(
                        raw,
                        "c.add",
                        &format!("{},{}", Self::reg5(rd), Self::reg5(rs2)),
                        Some("add"),
                    ),
                    _ => Self::invalid(raw),
                }
            }
            0b110 => Self::make(raw, "c.swsp", "<rs2>,<uimm>(sp)", Some("sw")),
            _ => Self::invalid(raw),
        }
    }

    /// Detect whether a 2-byte sequence is a valid RVC instruction.
    #[must_use]
    pub fn is_compressed(bytes: &[u8]) -> bool {
        if bytes.len() < 2 {
            return false;
        }
        let raw = u16::from_le_bytes([bytes[0], bytes[1]]);
        // 32-bit instructions have both bits[1:0] == 11; anything else is compressed.
        (raw & 0x3) != 0x3
    }
}

// ---------------------------------------------------------------------------
// Soft-Float Detection
// ---------------------------------------------------------------------------

/// Known soft-float emulation function name prefixes (GCC-style).
const SOFT_FLOAT_PREFIXES: &[&str] = &[
    "__addsf3",
    "__adddf3",
    "__subsf3",
    "__subdf3",
    "__mulsf3",
    "__muldf3",
    "__divsf3",
    "__divdf3",
    "__negsf2",
    "__negdf2",
    "__fixsfsi",
    "__fixdfsi",
    "__floatsisf",
    "__floatsidf",
    "__eqsf2",
    "__eqdf2",
    "__nesf2",
    "__nedf2",
    "__ltsf2",
    "__ltdf2",
    "__lesf2",
    "__ledf2",
    "__gtsf2",
    "__gtdf2",
    "__gesf2",
    "__gedf2",
    "__unordsf2",
    "__unorddf2",
    "__truncdfsf2",
    "__extendsfdf2",
];

/// Soft-float usage analysis result.
#[derive(Debug, Clone, Default)]
pub struct SoftFloat {
    /// Whether soft-float calls were detected.
    pub detected: bool,
    /// Set of soft-float function names called.
    pub calls: HashSet<String>,
    /// Number of soft-float call sites found.
    pub call_count: usize,
}

impl SoftFloat {
    /// Create a new, empty detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a function call target by name.
    pub fn record_call(&mut self, name: &str) {
        if SOFT_FLOAT_PREFIXES.iter().any(|p| name.starts_with(p)) {
            self.detected = true;
            self.calls.insert(name.to_string());
            self.call_count += 1;
        }
    }

    /// Check whether a name is a known soft-float emulation function.
    #[must_use]
    pub fn is_soft_float_name(name: &str) -> bool {
        SOFT_FLOAT_PREFIXES.iter().any(|p| name.starts_with(p))
    }

    /// Merge another detector's results into this one.
    pub fn merge(&mut self, other: &Self) {
        if other.detected {
            self.detected = true;
        }
        for c in &other.calls {
            self.calls.insert(c.clone());
        }
        self.call_count += other.call_count;
    }

    /// Classify the float ABI from detected symbols.
    #[must_use]
    pub const fn infer_abi(&self) -> RiscVAbi {
        if !self.detected {
            RiscVAbi::Unknown
        } else {
            RiscVAbi::Ilp32 // Soft-float implies integer-only ABI
        }
    }
}

// ---------------------------------------------------------------------------
// PIC / GOT analysis
// ---------------------------------------------------------------------------

/// A GOT (Global Offset Table) entry as seen in RISC-V PIC code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GotEntry {
    /// GOT slot index.
    pub index: usize,
    /// GOT-relative offset (from GOT base).
    pub offset: i64,
    /// Symbol name if known.
    pub symbol: Option<String>,
    /// Whether this is a PLT stub reference.
    pub is_plt: bool,
}

/// PIC code analysis — tracks AUIPC+ADDI/LD pairs used to build PC-relative
/// addresses, and GOT slot references.
#[derive(Debug, Clone, Default)]
pub struct PicCode {
    /// AUIPC instructions encountered: maps destination register → PC at instruction.
    pub auipc_sites: HashMap<u8, u64>,
    /// GOT entries discovered.
    pub got_entries: Vec<GotEntry>,
    /// Number of PC-relative address-forming pairs detected.
    pub pic_pairs: usize,
    /// Whether the binary appears to use PIC/PIE.
    pub is_pic: bool,
}

impl PicCode {
    /// Create a new, empty PIC analysis context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an AUIPC instruction at `pc` targeting register `rd`.
    pub fn record_auipc(&mut self, rd: u8, pc: u64) {
        self.auipc_sites.insert(rd, pc);
        self.is_pic = true;
    }

    /// Record an ADDI or LD that completes an AUIPC pair with register `rs1`.
    /// Returns `Some(base_pc)` if a pairing was found.
    #[must_use]
    pub fn complete_pair(&mut self, rs1: u8) -> Option<u64> {
        if let Some(base) = self.auipc_sites.remove(&rs1) {
            self.pic_pairs += 1;
            Some(base)
        } else {
            None
        }
    }

    /// Maximum number of GOT entries retained before silently dropping new ones.
    ///
    /// Prevents dos-memory-exhaustion when `record_got_entry` is driven from
    /// untrusted binary data.
    pub const MAX_GOT_ENTRIES: usize = 1_048_576; // 1 M entries ≈ ~64 MB

    /// Record a GOT entry reference.
    ///
    /// Silently drops the entry once [`Self::MAX_GOT_ENTRIES`] have been
    /// accumulated.
    pub fn record_got_entry(
        &mut self,
        index: usize,
        offset: i64,
        symbol: Option<String>,
        is_plt: bool,
    ) {
        if self.got_entries.len() >= Self::MAX_GOT_ENTRIES {
            return;
        }
        self.got_entries.push(GotEntry {
            index,
            offset,
            symbol,
            is_plt,
        });
    }

    /// Returns all PLT-type GOT entries.
    #[must_use]
    pub fn plt_entries(&self) -> Vec<&GotEntry> {
        self.got_entries.iter().filter(|e| e.is_plt).collect()
    }

    /// Returns all data GOT entries.
    #[must_use]
    pub fn data_entries(&self) -> Vec<&GotEntry> {
        self.got_entries.iter().filter(|e| !e.is_plt).collect()
    }
}

// ---------------------------------------------------------------------------
// Top-level analysis facade
// ---------------------------------------------------------------------------

/// Severity level for analysis findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
}

/// A single analysis finding.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Severity.
    pub severity: FindingSeverity,
    /// Address where the finding was made (0 if global).
    pub address: u64,
    /// Human-readable description.
    pub message: String,
}

impl Finding {
    fn info(address: u64, message: impl Into<String>) -> Self {
        Self {
            severity: FindingSeverity::Info,
            address,
            message: message.into(),
        }
    }
    fn warning(address: u64, message: impl Into<String>) -> Self {
        Self {
            severity: FindingSeverity::Warning,
            address,
            message: message.into(),
        }
    }
}

/// Maximum number of analysis findings retained before new ones are dropped.
///
/// Prevents dos-memory-exhaustion when analysing adversarially crafted
/// binaries that contain millions of invalid / soft-float instructions.
pub const MAX_FINDINGS: usize = 1_000_000;

/// Top-level RISC-V binary analysis facade.
#[derive(Debug, Clone, Default)]
pub struct RiscVAnalysis {
    /// Detected ABI.
    pub abi: Option<RiscVAbi>,
    /// Calling convention (populated once ABI is known).
    pub calling_conv: Option<RiscVCallingConv>,
    /// Soft-float detector.
    pub soft_float: SoftFloat,
    /// PIC/GOT analysis.
    pub pic: PicCode,
    /// Analysis findings.
    pub findings: Vec<Finding>,
    /// Set of function entry points identified.
    pub function_entries: HashSet<u64>,
    /// Compressed instruction count.
    pub compressed_count: usize,
    /// Uncompressed (32-bit) instruction count.
    pub uncompressed_count: usize,
}

impl RiscVAnalysis {
    /// Create a new analysis context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the detected ABI and populate the calling convention.
    pub fn set_abi(&mut self, abi: RiscVAbi) {
        self.calling_conv = Some(RiscVCallingConv::for_abi(abi));
        self.abi = Some(abi);
    }

    /// Record a decoded compressed instruction.
    pub fn record_compressed(&mut self, insn: &CompressedInsn, addr: u64) {
        self.compressed_count += 1;
        if !insn.valid && self.findings.len() < MAX_FINDINGS {
            self.findings.push(Finding::warning(
                addr,
                format!("invalid C-extension encoding {:#06x}", insn.raw),
            ));
        }
    }

    /// Record a 32-bit instruction.
    pub const fn record_uncompressed(&mut self) {
        self.uncompressed_count += 1;
    }

    /// Record a function call by name (for soft-float detection).
    pub fn record_call_by_name(&mut self, name: &str, addr: u64) {
        self.soft_float.record_call(name);
        if SoftFloat::is_soft_float_name(name) && self.findings.len() < MAX_FINDINGS {
            self.findings
                .push(Finding::info(addr, format!("soft-float call: {name}")));
        }
    }

    /// Register a function entry point.
    pub fn add_function_entry(&mut self, addr: u64) {
        self.function_entries.insert(addr);
    }

    /// Compression ratio: fraction of 16-bit vs total instructions.
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        let total = self.compressed_count + self.uncompressed_count;
        if total == 0 {
            0.0
        } else {
            self.compressed_count as f64 / total as f64
        }
    }

    /// Whether the code uses the C extension (>0 compressed instructions).
    #[must_use]
    pub const fn uses_compressed(&self) -> bool {
        self.compressed_count > 0
    }

    /// Return only findings at or above `min_severity`.
    #[must_use]
    pub fn findings_above(&self, min_severity: FindingSeverity) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.severity >= min_severity)
            .collect()
    }

    /// Infer ABI from soft-float data if not yet set.
    pub fn infer_abi_from_symbols(&mut self) {
        if self.abi.is_none() {
            let inferred = self.soft_float.infer_abi();
            if inferred != RiscVAbi::Unknown {
                self.set_abi(inferred);
                self.findings.push(Finding::info(
                    0,
                    format!("ABI inferred from symbols: {inferred}"),
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── RiscVAbi ──────────────────────────────────────────────────────────────

    #[test]
    fn test_abi_pointer_size_ilp32() {
        assert_eq!(RiscVAbi::Ilp32.pointer_size(), 4);
        assert_eq!(RiscVAbi::Ilp32f.pointer_size(), 4);
        assert_eq!(RiscVAbi::Ilp32d.pointer_size(), 4);
    }

    #[test]
    fn test_abi_pointer_size_lp64() {
        assert_eq!(RiscVAbi::Lp64.pointer_size(), 8);
        assert_eq!(RiscVAbi::Lp64f.pointer_size(), 8);
        assert_eq!(RiscVAbi::Lp64d.pointer_size(), 8);
    }

    #[test]
    fn test_abi_has_fp_regs() {
        assert!(!RiscVAbi::Ilp32.has_fp_regs());
        assert!(!RiscVAbi::Lp64.has_fp_regs());
        assert!(RiscVAbi::Ilp32f.has_fp_regs());
        assert!(RiscVAbi::Ilp32d.has_fp_regs());
        assert!(RiscVAbi::Lp64f.has_fp_regs());
        assert!(RiscVAbi::Lp64d.has_fp_regs());
    }

    #[test]
    fn test_abi_has_double_fp() {
        assert!(RiscVAbi::Ilp32d.has_double_fp());
        assert!(RiscVAbi::Lp64d.has_double_fp());
        assert!(!RiscVAbi::Ilp32f.has_double_fp());
        assert!(!RiscVAbi::Lp64f.has_double_fp());
    }

    #[test]
    fn test_abi_elf_float_flag() {
        assert_eq!(RiscVAbi::Ilp32.elf_float_flag(), 0x0000);
        assert_eq!(RiscVAbi::Ilp32f.elf_float_flag(), 0x0002);
        assert_eq!(RiscVAbi::Ilp32d.elf_float_flag(), 0x0004);
        assert_eq!(RiscVAbi::Lp64.elf_float_flag(), 0x0000);
    }

    #[test]
    fn test_abi_from_elf_flags_32bit() {
        assert_eq!(RiscVAbi::from_elf_flags(0x0000, 32), RiscVAbi::Ilp32);
        assert_eq!(RiscVAbi::from_elf_flags(0x0002, 32), RiscVAbi::Ilp32f);
        assert_eq!(RiscVAbi::from_elf_flags(0x0004, 32), RiscVAbi::Ilp32d);
    }

    #[test]
    fn test_abi_from_elf_flags_64bit() {
        assert_eq!(RiscVAbi::from_elf_flags(0x0000, 64), RiscVAbi::Lp64);
        assert_eq!(RiscVAbi::from_elf_flags(0x0002, 64), RiscVAbi::Lp64f);
        assert_eq!(RiscVAbi::from_elf_flags(0x0004, 64), RiscVAbi::Lp64d);
    }

    #[test]
    fn test_abi_display() {
        assert_eq!(RiscVAbi::Ilp32.to_string(), "ilp32");
        assert_eq!(RiscVAbi::Lp64d.to_string(), "lp64d");
        assert_eq!(RiscVAbi::Unknown.to_string(), "unknown");
    }

    // ── RiscVCallingConv ──────────────────────────────────────────────────────

    #[test]
    fn test_calling_conv_ilp32_has_no_fp_args() {
        let cc = RiscVCallingConv::for_abi(RiscVAbi::Ilp32);
        assert!(cc.fp_args.is_empty());
        assert_eq!(cc.int_args.len(), 8);
    }

    #[test]
    fn test_calling_conv_ilp32f_has_fp_args() {
        let cc = RiscVCallingConv::for_abi(RiscVAbi::Ilp32f);
        assert_eq!(cc.fp_args.len(), 8);
        assert_eq!(cc.fp_args[0], "fa0");
    }

    #[test]
    fn test_calling_conv_is_arg_reg() {
        let cc = RiscVCallingConv::for_abi(RiscVAbi::Ilp32);
        assert!(cc.is_arg_reg("a0"));
        assert!(cc.is_arg_reg("a7"));
        assert!(!cc.is_arg_reg("t0"));
        assert!(!cc.is_arg_reg("s0"));
    }

    #[test]
    fn test_calling_conv_is_callee_saved() {
        let cc = RiscVCallingConv::for_abi(RiscVAbi::Lp64);
        assert!(cc.is_callee_saved("s0"));
        assert!(cc.is_callee_saved("s11"));
        assert!(!cc.is_callee_saved("t0"));
        assert!(!cc.is_callee_saved("a0"));
    }

    #[test]
    fn test_calling_conv_max_int_args() {
        let cc = RiscVCallingConv::for_abi(RiscVAbi::Lp64);
        assert_eq!(cc.max_int_args_in_regs(), 8);
    }

    #[test]
    fn test_calling_conv_return_regs() {
        let cc = RiscVCallingConv::for_abi(RiscVAbi::Lp64);
        assert_eq!(cc.return_regs, vec!["a0", "a1"]);
    }

    // ── CompressedInsn ────────────────────────────────────────────────────────

    #[test]
    fn test_compressed_c_nop() {
        // C.NOP = 0x0001
        let insn = CompressedInsn::decode(0x0001);
        assert!(insn.valid);
        assert_eq!(insn.mnemonic, "c.nop");
    }

    #[test]
    fn test_compressed_c_jr_x1() {
        // C.JR x1 = Q2, funct3=100, j=0, rd=1, rs2=0 → 0x8082
        let insn = CompressedInsn::decode(0x8082);
        assert!(insn.valid);
        assert_eq!(insn.mnemonic, "c.jr");
    }

    #[test]
    fn test_compressed_c_ebreak() {
        // C.EBREAK = 0x9002
        let insn = CompressedInsn::decode(0x9002);
        assert!(insn.valid);
        assert_eq!(insn.mnemonic, "c.ebreak");
    }

    #[test]
    fn test_compressed_c_li() {
        // C.LI x10, 1 = op=01, funct3=010, rd=10, imm=1 → 0x4505
        let insn = CompressedInsn::decode(0x4505);
        assert!(insn.valid);
        assert_eq!(insn.mnemonic, "c.li");
    }

    #[test]
    fn test_is_compressed_true() {
        // 0x4505 = C.LI
        assert!(CompressedInsn::is_compressed(&[0x05, 0x45]));
    }

    #[test]
    fn test_is_compressed_false_for_32bit() {
        // 32-bit instruction has bits[1:0] == 11
        assert!(!CompressedInsn::is_compressed(&[0x13, 0x00, 0x00, 0x00]));
    }

    #[test]
    fn test_compressed_decode_c_j() {
        // Q1, funct3=101 → C.J
        let raw: u16 = (0b101 << 13) | 0x01;
        let insn = CompressedInsn::decode(raw);
        assert_eq!(insn.mnemonic, "c.j");
    }

    #[test]
    fn test_compressed_decode_c_beqz() {
        // Q1, funct3=110 → C.BEQZ
        let raw: u16 = (0b110 << 13) | 0x01;
        let insn = CompressedInsn::decode(raw);
        assert_eq!(insn.mnemonic, "c.beqz");
    }

    #[test]
    fn test_compressed_decode_c_bnez() {
        let raw: u16 = (0b111 << 13) | 0x01;
        let insn = CompressedInsn::decode(raw);
        assert_eq!(insn.mnemonic, "c.bnez");
    }

    // ── SoftFloat ─────────────────────────────────────────────────────────────

    #[test]
    fn test_soft_float_detection() {
        let mut sf = SoftFloat::new();
        sf.record_call("__addsf3");
        assert!(sf.detected);
        assert_eq!(sf.call_count, 1);
        assert!(sf.calls.contains("__addsf3"));
    }

    #[test]
    fn test_soft_float_non_sf_name() {
        let mut sf = SoftFloat::new();
        sf.record_call("my_function");
        assert!(!sf.detected);
        assert_eq!(sf.call_count, 0);
    }

    #[test]
    fn test_soft_float_is_soft_float_name() {
        assert!(SoftFloat::is_soft_float_name("__muldf3"));
        assert!(SoftFloat::is_soft_float_name("__addsf3_extra"));
        assert!(!SoftFloat::is_soft_float_name("regular_func"));
    }

    #[test]
    fn test_soft_float_merge() {
        let mut sf1 = SoftFloat::new();
        sf1.record_call("__addsf3");
        let mut sf2 = SoftFloat::new();
        sf2.record_call("__muldf3");
        sf1.merge(&sf2);
        assert_eq!(sf1.call_count, 2);
        assert!(sf1.calls.contains("__muldf3"));
    }

    #[test]
    fn test_soft_float_infer_abi() {
        let mut sf = SoftFloat::new();
        sf.record_call("__addsf3");
        assert_eq!(sf.infer_abi(), RiscVAbi::Ilp32);
    }

    #[test]
    fn test_soft_float_no_detection_infer_unknown() {
        let sf = SoftFloat::new();
        assert_eq!(sf.infer_abi(), RiscVAbi::Unknown);
    }

    // ── PicCode ───────────────────────────────────────────────────────────────

    #[test]
    fn test_pic_record_auipc() {
        let mut pic = PicCode::new();
        pic.record_auipc(1, 0x1000);
        assert!(pic.is_pic);
        assert_eq!(*pic.auipc_sites.get(&1).unwrap(), 0x1000);
    }

    #[test]
    fn test_pic_complete_pair() {
        let mut pic = PicCode::new();
        pic.record_auipc(5, 0x2000);
        let base = pic.complete_pair(5);
        assert_eq!(base, Some(0x2000));
        assert_eq!(pic.pic_pairs, 1);
        assert!(!pic.auipc_sites.contains_key(&5));
    }

    #[test]
    fn test_pic_complete_pair_miss() {
        let mut pic = PicCode::new();
        let base = pic.complete_pair(3);
        assert_eq!(base, None);
        assert_eq!(pic.pic_pairs, 0);
    }

    #[test]
    fn test_pic_got_entries() {
        let mut pic = PicCode::new();
        pic.record_got_entry(0, 0, Some("printf".to_string()), true);
        pic.record_got_entry(1, 8, Some("data_sym".to_string()), false);
        assert_eq!(pic.plt_entries().len(), 1);
        assert_eq!(pic.data_entries().len(), 1);
    }

    // ── RiscVAnalysis ─────────────────────────────────────────────────────────

    #[test]
    fn test_analysis_set_abi() {
        let mut a = RiscVAnalysis::new();
        a.set_abi(RiscVAbi::Lp64d);
        assert_eq!(a.abi, Some(RiscVAbi::Lp64d));
        assert!(a.calling_conv.is_some());
    }

    #[test]
    fn test_analysis_compression_ratio_empty() {
        let a = RiscVAnalysis::new();
        assert_eq!(a.compression_ratio(), 0.0);
        assert!(!a.uses_compressed());
    }

    #[test]
    fn test_analysis_compression_ratio_mixed() {
        let mut a = RiscVAnalysis::new();
        a.compressed_count = 1;
        a.uncompressed_count = 3;
        let ratio = a.compression_ratio();
        assert!((ratio - 0.25).abs() < 1e-9);
    }

    #[test]
    fn test_analysis_record_call_soft_float() {
        let mut a = RiscVAnalysis::new();
        a.record_call_by_name("__addsf3", 0x1000);
        assert!(a.soft_float.detected);
        assert_eq!(a.findings.len(), 1);
        assert_eq!(a.findings[0].severity, FindingSeverity::Info);
    }

    #[test]
    fn test_analysis_function_entries() {
        let mut a = RiscVAnalysis::new();
        a.add_function_entry(0x1000);
        a.add_function_entry(0x2000);
        assert_eq!(a.function_entries.len(), 2);
        assert!(a.function_entries.contains(&0x1000));
    }

    #[test]
    fn test_analysis_infer_abi_from_symbols() {
        let mut a = RiscVAnalysis::new();
        a.soft_float.record_call("__addsf3");
        a.infer_abi_from_symbols();
        assert_eq!(a.abi, Some(RiscVAbi::Ilp32));
    }

    #[test]
    fn test_analysis_findings_above_severity() {
        let mut a = RiscVAnalysis::new();
        a.findings.push(Finding::info(0, "info msg"));
        a.findings.push(Finding::warning(0, "warn msg"));
        let warnings = a.findings_above(FindingSeverity::Warning);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].severity, FindingSeverity::Warning);
    }

    #[test]
    fn test_analysis_record_compressed_invalid() {
        let mut a = RiscVAnalysis::new();
        // Encode an invalid compressed insn (Q3 — all bits[1:0]=11 is 32-bit, decode it anyway)
        let bad = CompressedInsn {
            raw: 0xFFFF,
            mnemonic: "c.illegal".into(),
            operands: String::new(),
            expanded_mnemonic: None,
            valid: false,
        };
        a.record_compressed(&bad, 0x100);
        assert_eq!(a.compressed_count, 1);
        assert_eq!(a.findings.len(), 1);
    }
}
