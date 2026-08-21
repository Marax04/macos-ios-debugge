//! `ppc_analysis` — PowerPC higher-level analysis: EABI calling convention,
//! Book E embedded specifics, VLE (Variable Length Encoding), SPE (Signal
//! Processing Engine), and TOC section detection.
//!
//! Provides:
//! * [`EabiCalling`]   — PowerPC EABI calling convention descriptor
//! * [`BookE`]         — Book E embedded CPU specifics (MSR, TSR, TCR, …)
//! * [`VleMode`]       — VLE 16/32-bit mixed-encoding support
//! * [`PpcSPE`]        — e500-series Signal Processing Engine detection
//! * [`TOCSection`]    — Table of Contents tracking for 64-bit PPC ELF
//! * [`PpcAnalysis`]   — top-level facade

use std::collections::HashSet;
use ahash::AHashMap;

pub use std::fmt;

// ---------------------------------------------------------------------------
// EABI calling convention
// ---------------------------------------------------------------------------

/// PowerPC EABI integer argument registers (r3–r10).
pub const EABI_INT_ARG_REGS: [&str; 8] = ["r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"];
/// PowerPC EABI return registers.
pub const EABI_RET_REGS: [&str; 2] = ["r3", "r4"];
/// PowerPC EABI callee-saved registers.
pub const EABI_CALLEE_SAVED: [&str; 19] = [
    "r13", "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25",
    "r26", "r27", "r28", "r29", "r30", "r31",
];
/// PowerPC EABI FP argument registers (f1–f8).
pub const EABI_FP_ARG_REGS: [&str; 8] = ["f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8"];

/// PowerPC EABI calling convention descriptor.
#[derive(Debug, Clone)]
pub struct EabiCalling {
    /// Whether this is the 32-bit EABI (vs 64-bit `ELFv2`).
    pub is_32bit: bool,
    /// Integer argument registers.
    pub int_args: Vec<String>,
    /// FP argument registers.
    pub fp_args: Vec<String>,
    /// Return registers.
    pub return_regs: Vec<String>,
    /// Callee-saved registers.
    pub callee_saved: Vec<String>,
    /// Whether small data area (SDA) is used.
    pub uses_sda: bool,
}

impl EabiCalling {
    /// Create a 32-bit EABI descriptor.
    #[must_use]
    pub fn eabi32() -> Self {
        Self {
            is_32bit: true,
            int_args: EABI_INT_ARG_REGS.iter().map(ToString::to_string).collect(),
            fp_args: EABI_FP_ARG_REGS.iter().map(ToString::to_string).collect(),
            return_regs: EABI_RET_REGS.iter().map(ToString::to_string).collect(),
            callee_saved: EABI_CALLEE_SAVED.iter().map(ToString::to_string).collect(),
            uses_sda: false,
        }
    }

    /// Create a 64-bit `ELFv2` (Linux PPC64LE) descriptor.
    #[must_use]
    pub fn elfv2_64() -> Self {
        Self {
            is_32bit: false,
            int_args: EABI_INT_ARG_REGS.iter().map(ToString::to_string).collect(),
            fp_args: EABI_FP_ARG_REGS.iter().map(ToString::to_string).collect(),
            return_regs: EABI_RET_REGS.iter().map(ToString::to_string).collect(),
            callee_saved: EABI_CALLEE_SAVED.iter().map(ToString::to_string).collect(),
            uses_sda: false,
        }
    }

    /// Whether a register name is an integer argument register.
    #[must_use]
    pub fn is_int_arg(&self, name: &str) -> bool {
        self.int_args.iter().any(|s| s == name)
    }

    /// Whether a register is callee-saved.
    #[must_use]
    pub fn is_callee_saved(&self, name: &str) -> bool {
        self.callee_saved.iter().any(|s| s == name)
    }

    /// Stack pointer register name.
    #[must_use]
    pub const fn stack_pointer(&self) -> &'static str {
        "r1"
    }

    /// Small data area register (r2 in EABI/SYSV).
    #[must_use]
    pub const fn sda_register(&self) -> &'static str {
        if self.uses_sda { "r13" } else { "r2" }
    }
}

// ---------------------------------------------------------------------------
// Book E embedded specifics
// ---------------------------------------------------------------------------

/// Book E (PowerPC Embedded Application Binary Interface) MSR bit definitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BookEMsrBit {
    /// Machine check enable.
    Me = 19,
    /// Critical interrupt enable.
    Ce = 17,
    /// External interrupt enable.
    Ee = 15,
    /// Problem state.
    Pr = 14,
    /// Floating-point available.
    Fp = 13,
    /// Machine check available.
    Me2 = 12,
    /// Debug interrupt enable.
    De = 9,
    /// Instruction address space.
    Is = 5,
    /// Data address space.
    Ds = 4,
}

impl BookEMsrBit {
    /// Name of this MSR bit.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Me | Self::Me2 => "ME",
            Self::Ce => "CE",
            Self::Ee => "EE",
            Self::Pr => "PR",
            Self::Fp => "FP",
            Self::De => "DE",
            Self::Is => "IS",
            Self::Ds => "DS",
        }
    }
}

/// Book E-specific SPR numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BookESpr {
    /// Timer Status Register.
    Tsr = 336,
    /// Timer Control Register.
    Tcr = 340,
    /// Decrementer Auto-Reload.
    Decar = 54,
    /// Machine Status Save/Restore 0 for Critical interrupt.
    Csrr0 = 58,
    /// Machine Status Save/Restore 1 for Critical interrupt.
    Csrr1 = 59,
    /// Machine Status Save/Restore 0 for Machine Check.
    Mcsrr0 = 570,
    /// Machine Status Save/Restore 1 for Machine Check.
    Mcsrr1 = 571,
    /// Exception Syndrome Register.
    Esr = 62,
    /// Data Exception Address Register.
    Dear = 61,
    /// Interrupt Vector Prefix Register.
    Ivpr = 63,
    /// Interrupt Vector Offset Register base (IVOR0–IVOR15 = 400–415).
    Ivor0 = 400,
}

/// Book E CPU analysis context.
#[derive(Debug, Clone, Default)]
pub struct BookE {
    /// Set of Book E SPR numbers accessed.
    pub accessed_sprs: HashSet<u32>,
    /// Number of `rfmci` (Return From Machine Check Interrupt) instructions.
    pub rfmci_count: usize,
    /// Number of `rfci` (Return From Critical Interrupt) instructions.
    pub rfci_count: usize,
    /// Whether any IVOR was set (interrupt vector offset).
    pub ivor_set: bool,
    /// Whether TCR was written (timer control).
    pub tcr_written: bool,
    /// Whether TSR was accessed.
    pub tsr_accessed: bool,
}

impl BookE {
    /// Create a new `BookE` context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an SPR access by SPR number.
    pub fn record_spr_access(&mut self, spr: u32) {
        self.accessed_sprs.insert(spr);
        if spr == BookESpr::Tcr as u32 {
            self.tcr_written = true;
        }
        if spr == BookESpr::Tsr as u32 {
            self.tsr_accessed = true;
        }
        if (400..416).contains(&spr) {
            self.ivor_set = true;
        }
    }

    /// Record a `rfmci` instruction.
    pub const fn record_rfmci(&mut self) {
        self.rfmci_count += 1;
    }

    /// Record a `rfci` instruction.
    pub const fn record_rfci(&mut self) {
        self.rfci_count += 1;
    }

    /// Whether this binary targets a Book E core.
    #[must_use]
    pub fn is_book_e(&self) -> bool {
        self.rfmci_count > 0
            || self.rfci_count > 0
            || self.ivor_set
            || !self.accessed_sprs.is_empty()
    }
}

// ---------------------------------------------------------------------------
// VLE (Variable Length Encoding) for embedded PPC
// ---------------------------------------------------------------------------

/// VLE instruction width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VleWidth {
    /// 16-bit SE (Short Encoding) instruction.
    Short,
    /// 32-bit LE (Long Encoding) instruction.
    Long,
}

/// A decoded VLE instruction record.
#[derive(Debug, Clone)]
pub struct VleInsn {
    /// Address.
    pub address: u64,
    /// Encoding width.
    pub width: VleWidth,
    /// Raw bytes (2 or 4).
    pub bytes: Vec<u8>,
    /// Mnemonic.
    pub mnemonic: String,
    /// Operands string.
    pub operands: String,
}

impl VleInsn {
    /// Byte length of the instruction.
    #[must_use]
    pub const fn len(&self) -> usize {
        match self.width {
            VleWidth::Short => 2,
            VleWidth::Long => 4,
        }
    }

    /// Whether the instruction is zero-length (always false).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

/// Widen a `usize` count to `f64` for ratio calculations.
///
/// Built arithmetically from two 32-bit halves rather than with `as`. Each
/// half converts exactly (`f64::from(u32)` is lossless) and `hi * 2^32` is
/// exact, so the single fused multiply-add performs one round-to-nearest-even
/// — the same result `n as f64` would give, without an unchecked cast.
fn vle_usize_to_f64(n: usize) -> f64 {
    let wide = n as u64;
    let hi = u32::try_from(wide >> 32).unwrap_or(u32::MAX);
    let lo = u32::try_from(wide & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    f64::from(hi).mul_add(4_294_967_296.0, f64::from(lo))
}

/// VLE mode analyzer — detects SE/LE instruction boundaries.
#[derive(Debug, Clone, Default)]
pub struct VleMode {
    /// Total SE (16-bit) instructions decoded.
    pub se_count: usize,
    /// Total LE (32-bit) instructions decoded.
    pub le_count: usize,
    /// Instruction records.
    pub instructions: Vec<VleInsn>,
}

impl VleMode {
    /// Create a new VLE mode analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Determine whether a 2-byte value is a VLE SE (16-bit) instruction.
    ///
    /// SE opcodes have bits[15:11] in the range 0x00–0x17 (i.e. bits[15:11] < 0x18).
    #[must_use]
    pub const fn is_se(half: u16) -> bool {
        (half >> 11) < 0x18
    }

    /// Decode the next VLE instruction from `bytes` at `address`.
    /// Returns `None` if less than 2 bytes remain.
    #[must_use]
    pub fn decode_one(bytes: &[u8], address: u64) -> Option<VleInsn> {
        if bytes.len() < 2 {
            return None;
        }
        let half = u16::from_be_bytes([bytes[0], bytes[1]]);
        if Self::is_se(half) {
            Some(VleInsn {
                address,
                width: VleWidth::Short,
                bytes: bytes[..2].to_vec(),
                mnemonic: "se_insn".to_string(),
                operands: format!("{half:#06x}"),
            })
        } else {
            if bytes.len() < 4 {
                return None;
            }
            let word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            Some(VleInsn {
                address,
                width: VleWidth::Long,
                bytes: bytes[..4].to_vec(),
                mnemonic: "le_insn".to_string(),
                operands: format!("{word:#010x}"),
            })
        }
    }

    /// Decode a VLE code sequence.
    pub fn decode_sequence(&mut self, bytes: &[u8], base: u64) {
        // Reserve a bounded amount — at most 4096 slots — regardless of how
        // large `bytes` is.  An untrusted caller could pass a multi-GB slice;
        // reserving bytes.len()/3 slots would exhaust memory before decoding
        // a single instruction.  The Vec will grow as needed beyond 4096.
        let initial_reserve = (bytes.len() / 3 + 1).min(4096);
        self.instructions.reserve(initial_reserve);
        let mut off = 0usize;
        while off < bytes.len() {
            if let Some(insn) = Self::decode_one(&bytes[off..], base + off as u64) {
                let len = insn.len();
                match insn.width {
                    VleWidth::Short => self.se_count += 1,
                    VleWidth::Long => self.le_count += 1,
                }
                self.instructions.push(insn);
                off += len;
            } else {
                break;
            }
        }
    }

    /// Compression ratio (SE instructions / total).
    #[must_use]
    pub fn compression_ratio(&self) -> f64 {
        let total = self.se_count + self.le_count;
        if total == 0 {
            0.0
        } else {
            vle_usize_to_f64(self.se_count) / vle_usize_to_f64(total)
        }
    }
}

// ---------------------------------------------------------------------------
// PPC SPE (Signal Processing Engine)
// ---------------------------------------------------------------------------

/// Known SPE instruction mnemonic prefixes.
const SPE_PREFIXES: &[&str] = &[
    "evabs",
    "evadd",
    "evand",
    "evandc",
    "evbyte",
    "evcmpeq",
    "evcmpgts",
    "evcmpgtu",
    "evcmplts",
    "evcmpltu",
    "evcntlsw",
    "evcntlzw",
    "evdivws",
    "evdivwu",
    "eveqv",
    "evextsb",
    "evextsh",
    "evfcfui",
    "evfctuiz",
    "evfscfui",
    "evfsabs",
    "evfsadd",
    "evfscmpgt",
    "evfsmadd",
    "evfsmul",
    "evfsub",
    "evldd",
    "evlddx",
    "evldh",
    "evldhx",
    "evldw",
    "evldwx",
    "evlhhesplat",
    "evlhhossplat",
    "evlhhousplat",
    "evlwhe",
    "evlwhex",
    "evlwhos",
    "evlwhosx",
    "evlwhou",
    "evlwhoux",
    "evlwhsplat",
    "evlwhsplatx",
    "evlwwsplat",
    "evlwwsplatx",
    "evmergehi",
    "evmergelo",
    "evmergehilo",
    "evmhegsmfaa",
    "evmhegsmfan",
    "evmhegumiaa",
    "evmhesmfa",
    "evmhesmfaaw",
    "evmhesmfanw",
    "evmhesmiaa",
    "evmhessf",
    "evmhessfa",
    "evmhessfaaw",
    "evmhessfanw",
    "evmhessiaaw",
    "evmhessianw",
    "evmheumi",
    "evmheumiaa",
    "evmhogsmiaa",
    "evmhogssfaaw",
    "evmhogssfanw",
    "evmhogumian",
    "evmhosmfa",
    "evmhosmfaaw",
    "evmhosmfanw",
    "evmhosmiaa",
    "evmhossf",
    "evmhossfa",
    "evmhossfaaw",
    "evmhossfanw",
    "evmhossiaaw",
    "evmhossianw",
    "evmhoumi",
    "evmhoumiaa",
    "evmra",
    "evmul",
    "evnand",
    "evneg",
    "evnor",
    "evor",
    "evorc",
    "evrlw",
    "evrlwi",
    "evrndw",
    "evsel",
    "evslw",
    "evslwi",
    "evsplatfi",
    "evsplati",
    "evsrwis",
    "evsrwiu",
    "evstdd",
    "evstddx",
    "evstdh",
    "evstdhx",
    "evstdw",
    "evstdwx",
    "evsubfsmiaaw",
    "evsubfssiaaw",
    "evsubfusiaw",
    "evsubfumiaaw",
    "evsubfw",
    "evsubifw",
    "evxor",
];

/// SPE usage analysis.
#[derive(Debug, Clone, Default)]
pub struct PpcSPE {
    /// Whether any SPE instructions were detected.
    pub detected: bool,
    /// Set of unique SPE mnemonics encountered.
    pub mnemonics: HashSet<String>,
    /// Total SPE instruction count.
    pub count: usize,
    /// SPE vector load count.
    pub vector_loads: usize,
    /// SPE vector store count.
    pub vector_stores: usize,
}

impl PpcSPE {
    /// Create a new SPE detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether `mnemonic` is an SPE instruction.
    #[must_use]
    pub fn is_spe(mnemonic: &str) -> bool {
        let lower = mnemonic.to_lowercase();
        SPE_PREFIXES.iter().any(|p| lower.starts_with(p))
    }

    /// Record a decoded mnemonic.
    pub fn record(&mut self, mnemonic: &str) {
        let lower = mnemonic.to_lowercase();
        if SPE_PREFIXES.iter().any(|p| lower.starts_with(p)) {
            self.detected = true;
            self.count += 1;
            if lower.starts_with("evld") || lower.starts_with("evlw") || lower.starts_with("evlh") {
                self.vector_loads += 1;
            }
            if lower.starts_with("evst") {
                self.vector_stores += 1;
            }
            self.mnemonics.insert(lower);
        }
    }

    /// Summary statistics.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "SPE detected={}, count={}, unique_mnemonics={}",
            self.detected,
            self.count,
            self.mnemonics.len()
        )
    }
}

// ---------------------------------------------------------------------------
// TOC Section (64-bit PPC ELF)
// ---------------------------------------------------------------------------

/// A single TOC entry.
#[derive(Debug, Clone)]
pub struct TocEntry {
    /// TOC-relative offset.
    pub toc_offset: i64,
    /// Absolute address of the referenced data/function.
    pub target_address: u64,
    /// Symbol name if known.
    pub symbol: Option<String>,
    /// Whether this entry is a function descriptor.
    pub is_func_desc: bool,
}

/// TOC (Table of Contents) section tracker for 64-bit PowerPC ELF binaries.
///
/// PPC64 `ELFv1` binaries use a TOC anchored at the start of .toc/.got,
/// accessed via r2 (the TOC pointer). `ELFv2` uses a smaller TOC offset scheme.
#[derive(Debug, Clone, Default)]
pub struct TOCSection {
    /// Base address of the TOC (value of r2).
    pub toc_base: u64,
    /// All recorded TOC entries.
    pub entries: Vec<TocEntry>,
    /// Map from TOC offset to entry index.
    /// Uses a randomised hasher (ahash) to prevent hash-collision `DoS` when an
    /// attacker controls the binary's TOC offsets.
    offset_map: AHashMap<i64, usize>,
    /// Number of TOC accesses seen.
    pub access_count: usize,
}

impl TOCSection {
    /// Create a new TOC section with the given base address.
    #[must_use]
    pub fn new(toc_base: u64) -> Self {
        Self {
            toc_base,
            ..Default::default()
        }
    }

    /// Record an access to a TOC-relative address.
    pub fn record_access(
        &mut self,
        toc_offset: i64,
        target_address: u64,
        symbol: Option<String>,
        is_func_desc: bool,
    ) {
        self.access_count += 1;
        if let std::collections::hash_map::Entry::Vacant(e) = self.offset_map.entry(toc_offset) {
            let idx = self.entries.len();
            e.insert(idx);
            self.entries.push(TocEntry {
                toc_offset,
                target_address,
                symbol,
                is_func_desc,
            });
        }
    }

    /// Look up a TOC entry by offset.
    #[must_use]
    pub fn lookup(&self, toc_offset: i64) -> Option<&TocEntry> {
        self.offset_map.get(&toc_offset).map(|&i| &self.entries[i])
    }

    /// Absolute address from TOC offset.
    #[must_use]
    pub const fn absolute_addr(&self, toc_offset: i64) -> u64 {
        self.toc_base.wrapping_add_signed(toc_offset)
    }

    /// Number of unique TOC entries.
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Function descriptor entries only.
    #[must_use]
    pub fn func_descriptors(&self) -> Vec<&TocEntry> {
        self.entries.iter().filter(|e| e.is_func_desc).collect()
    }
}

// ---------------------------------------------------------------------------
// Top-level facade
// ---------------------------------------------------------------------------

/// Analysis finding severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

/// An analysis finding.
#[derive(Debug, Clone)]
pub struct PpcFinding {
    pub severity: Severity,
    pub address: u64,
    pub message: String,
}

impl PpcFinding {
    pub fn info(address: u64, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Info,
            address,
            message: message.into(),
        }
    }
    pub fn warning(address: u64, message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            address,
            message: message.into(),
        }
    }
}

/// Top-level PowerPC analysis facade.
#[derive(Debug, Clone)]
pub struct PpcAnalysis {
    /// Detected calling convention.
    pub calling_conv: EabiCalling,
    /// Book E specifics.
    pub book_e: BookE,
    /// VLE mode tracker.
    pub vle: VleMode,
    /// SPE detector.
    pub spe: PpcSPE,
    /// TOC section (64-bit only).
    pub toc: Option<TOCSection>,
    /// Findings.
    pub findings: Vec<PpcFinding>,
    /// Total instructions analyzed.
    pub total_instructions: usize,
    /// Function entries detected.
    pub function_entries: HashSet<u64>,
}

impl Default for PpcAnalysis {
    fn default() -> Self {
        Self::new_32bit()
    }
}

impl PpcAnalysis {
    /// Create a 32-bit EABI analysis context.
    #[must_use]
    pub fn new_32bit() -> Self {
        Self {
            calling_conv: EabiCalling::eabi32(),
            book_e: BookE::new(),
            vle: VleMode::new(),
            spe: PpcSPE::new(),
            toc: None,
            findings: Vec::new(),
            total_instructions: 0,
            function_entries: HashSet::new(),
        }
    }

    /// Create a 64-bit `ELFv2` analysis context with a TOC base.
    #[must_use]
    pub fn new_64bit(toc_base: u64) -> Self {
        Self {
            calling_conv: EabiCalling::elfv2_64(),
            book_e: BookE::new(),
            vle: VleMode::new(),
            spe: PpcSPE::new(),
            toc: Some(TOCSection::new(toc_base)),
            findings: Vec::new(),
            total_instructions: 0,
            function_entries: HashSet::new(),
        }
    }

    /// Record an instruction mnemonic at an address.
    pub fn record_instruction(&mut self, mnemonic: &str, address: u64) {
        self.total_instructions += 1;
        self.spe.record(mnemonic);
        if mnemonic.eq_ignore_ascii_case("rfmci") {
            self.book_e.record_rfmci();
            self.findings.push(PpcFinding::info(
                address,
                "rfmci — Book E machine check return",
            ));
        } else if mnemonic.eq_ignore_ascii_case("rfci") {
            self.book_e.record_rfci();
            self.findings.push(PpcFinding::info(
                address,
                "rfci — Book E critical interrupt return",
            ));
        }
    }

    /// Record an SPR access.
    pub fn record_spr(&mut self, spr: u32, address: u64) {
        self.book_e.record_spr_access(spr);
        if (400..416).contains(&spr) {
            self.findings.push(PpcFinding::info(
                address,
                format!("IVOR{} set — interrupt vector", spr - 400),
            ));
        }
    }

    /// Add a function entry point.
    pub fn add_function_entry(&mut self, addr: u64) {
        self.function_entries.insert(addr);
    }

    /// Whether the binary uses Book E extensions.
    #[must_use]
    pub fn is_book_e(&self) -> bool {
        self.book_e.is_book_e()
    }

    /// Whether SPE extensions are present.
    #[must_use]
    pub const fn has_spe(&self) -> bool {
        self.spe.detected
    }

    /// Whether VLE encoding is used.
    #[must_use]
    pub const fn has_vle(&self) -> bool {
        self.vle.se_count > 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── EabiCalling ───────────────────────────────────────────────────────────

    #[test]
    fn test_eabi32_int_args() {
        let cc = EabiCalling::eabi32();
        assert_eq!(cc.int_args.len(), 8);
        assert_eq!(cc.int_args[0], "r3");
    }

    #[test]
    fn test_eabi32_fp_args() {
        let cc = EabiCalling::eabi32();
        assert_eq!(cc.fp_args.len(), 8);
        assert_eq!(cc.fp_args[0], "f1");
    }

    #[test]
    fn test_eabi32_callee_saved_count() {
        let cc = EabiCalling::eabi32();
        assert_eq!(cc.callee_saved.len(), 19);
    }

    #[test]
    fn test_eabi32_is_int_arg() {
        let cc = EabiCalling::eabi32();
        assert!(cc.is_int_arg("r3"));
        assert!(cc.is_int_arg("r10"));
        assert!(!cc.is_int_arg("r11"));
    }

    #[test]
    fn test_eabi32_is_callee_saved() {
        let cc = EabiCalling::eabi32();
        assert!(cc.is_callee_saved("r13"));
        assert!(cc.is_callee_saved("r31"));
        assert!(!cc.is_callee_saved("r3"));
    }

    #[test]
    fn test_eabi32_stack_pointer() {
        let cc = EabiCalling::eabi32();
        assert_eq!(cc.stack_pointer(), "r1");
    }

    #[test]
    fn test_elfv2_64() {
        let cc = EabiCalling::elfv2_64();
        assert!(!cc.is_32bit);
        assert_eq!(cc.int_args.len(), 8);
    }

    // ── BookE ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_book_e_spr_tcr() {
        let mut be = BookE::new();
        be.record_spr_access(BookESpr::Tcr as u32);
        assert!(be.tcr_written);
        assert!(be.is_book_e());
    }

    #[test]
    fn test_book_e_spr_tsr() {
        let mut be = BookE::new();
        be.record_spr_access(BookESpr::Tsr as u32);
        assert!(be.tsr_accessed);
    }

    #[test]
    fn test_book_e_ivor_range() {
        let mut be = BookE::new();
        be.record_spr_access(405);
        assert!(be.ivor_set);
    }

    #[test]
    fn test_book_e_rfmci() {
        let mut be = BookE::new();
        be.record_rfmci();
        assert_eq!(be.rfmci_count, 1);
        assert!(be.is_book_e());
    }

    #[test]
    fn test_book_e_rfci() {
        let mut be = BookE::new();
        be.record_rfci();
        assert_eq!(be.rfci_count, 1);
    }

    #[test]
    fn test_book_e_not_detected_empty() {
        let be = BookE::new();
        assert!(!be.is_book_e());
    }

    #[test]
    fn test_book_e_msr_bit_names() {
        assert_eq!(BookEMsrBit::Ee.name(), "EE");
        assert_eq!(BookEMsrBit::De.name(), "DE");
    }

    // ── VleMode ───────────────────────────────────────────────────────────────

    #[test]
    fn test_vle_is_se_true() {
        // half >> 11 < 0x18 → bits[15:11] = 0x10 (value 0x8000) → 0x8000>>11=16 < 24 → SE
        assert!(VleMode::is_se(0x8000));
    }

    #[test]
    fn test_vle_is_se_false_for_large() {
        // half >> 11 = 0x1F (0xF800) → 31 >= 24 → LE
        assert!(!VleMode::is_se(0xF800));
    }

    #[test]
    fn test_vle_decode_se() {
        let bytes = [0x00u8, 0x10]; // half = 0x0010, >>11 = 0 < 24 → SE
        let insn = VleMode::decode_one(&bytes, 0x1000).unwrap();
        assert_eq!(insn.width, VleWidth::Short);
        assert_eq!(insn.len(), 2);
    }

    #[test]
    fn test_vle_decode_le() {
        // Use bytes that produce half>>11 >= 24
        let bytes = [0xC0u8, 0x00, 0x00, 0x00]; // half=0xC000, >>11=24 → LE
        let insn = VleMode::decode_one(&bytes, 0x1000).unwrap();
        assert_eq!(insn.width, VleWidth::Long);
        assert_eq!(insn.len(), 4);
    }

    #[test]
    fn test_vle_decode_sequence() {
        let mut vle = VleMode::new();
        // SE + LE + SE
        let bytes = [0x00u8, 0x10, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x20];
        vle.decode_sequence(&bytes, 0x0);
        assert_eq!(vle.se_count, 2);
        assert_eq!(vle.le_count, 1);
    }

    #[test]
    fn test_vle_compression_ratio() {
        let mut vle = VleMode::new();
        vle.se_count = 3;
        vle.le_count = 1;
        let ratio = vle.compression_ratio();
        assert!((ratio - 0.75).abs() < 1e-9);
    }

    #[test]
    fn test_vle_empty_ratio() {
        let vle = VleMode::new();
        assert!(vle.compression_ratio().abs() < f64::EPSILON);
    }

    // ── PpcSPE ────────────────────────────────────────────────────────────────

    #[test]
    fn test_spe_is_spe_true() {
        assert!(PpcSPE::is_spe("evabs"));
        assert!(PpcSPE::is_spe("EVABS"));
        assert!(PpcSPE::is_spe("evfscfui"));
    }

    #[test]
    fn test_spe_is_spe_false() {
        assert!(!PpcSPE::is_spe("addi"));
        assert!(!PpcSPE::is_spe("stw"));
    }

    #[test]
    fn test_spe_record() {
        let mut spe = PpcSPE::new();
        spe.record("evabs");
        assert!(spe.detected);
        assert_eq!(spe.count, 1);
    }

    #[test]
    fn test_spe_vector_loads() {
        let mut spe = PpcSPE::new();
        spe.record("evldd");
        spe.record("evlwhe");
        assert_eq!(spe.vector_loads, 2);
    }

    #[test]
    fn test_spe_vector_stores() {
        let mut spe = PpcSPE::new();
        spe.record("evstdd");
        assert_eq!(spe.vector_stores, 1);
    }

    #[test]
    fn test_spe_not_detected_by_default() {
        let spe = PpcSPE::new();
        assert!(!spe.detected);
    }

    // ── TOCSection ────────────────────────────────────────────────────────────

    #[test]
    fn test_toc_absolute_addr() {
        let toc = TOCSection::new(0x10000);
        assert_eq!(toc.absolute_addr(8), 0x10008);
        assert_eq!(toc.absolute_addr(-8), 0x0FFF8);
    }

    #[test]
    fn test_toc_record_and_lookup() {
        let mut toc = TOCSection::new(0x10000);
        toc.record_access(0, 0x20000, Some("printf".to_string()), true);
        let e = toc.lookup(0).unwrap();
        assert_eq!(e.target_address, 0x20000);
        assert!(e.is_func_desc);
    }

    #[test]
    fn test_toc_lookup_missing() {
        let toc = TOCSection::new(0x10000);
        assert!(toc.lookup(99).is_none());
    }

    #[test]
    fn test_toc_dedup() {
        let mut toc = TOCSection::new(0x10000);
        toc.record_access(0, 0x20000, None, false);
        toc.record_access(0, 0x20000, None, false); // duplicate
        assert_eq!(toc.entry_count(), 1);
        assert_eq!(toc.access_count, 2);
    }

    #[test]
    fn test_toc_func_descriptors() {
        let mut toc = TOCSection::new(0x10000);
        toc.record_access(0, 0x20000, Some("f".to_string()), true);
        toc.record_access(8, 0x30000, Some("d".to_string()), false);
        assert_eq!(toc.func_descriptors().len(), 1);
    }

    // ── PpcAnalysis ───────────────────────────────────────────────────────────

    #[test]
    fn test_analysis_new_32bit() {
        let a = PpcAnalysis::new_32bit();
        assert!(a.calling_conv.is_32bit);
        assert!(a.toc.is_none());
    }

    #[test]
    fn test_analysis_new_64bit() {
        let a = PpcAnalysis::new_64bit(0x10000);
        assert!(!a.calling_conv.is_32bit);
        assert!(a.toc.is_some());
    }

    #[test]
    fn test_analysis_record_rfmci() {
        let mut a = PpcAnalysis::new_32bit();
        a.record_instruction("rfmci", 0x1000);
        assert!(a.is_book_e());
        assert_eq!(a.findings.len(), 1);
    }

    #[test]
    fn test_analysis_record_spe() {
        let mut a = PpcAnalysis::new_32bit();
        a.record_instruction("evabs", 0x1000);
        assert!(a.has_spe());
    }

    #[test]
    fn test_analysis_total_instructions() {
        let mut a = PpcAnalysis::new_32bit();
        a.record_instruction("addi", 0x1000);
        a.record_instruction("blr", 0x1004);
        assert_eq!(a.total_instructions, 2);
    }

    #[test]
    fn test_analysis_ivor_finding() {
        let mut a = PpcAnalysis::new_32bit();
        a.record_spr(404, 0x2000); // IVOR4
        assert!(a.is_book_e());
        assert_eq!(a.findings.len(), 1);
    }

    #[test]
    fn test_analysis_function_entries() {
        let mut a = PpcAnalysis::new_32bit();
        a.add_function_entry(0x1000);
        a.add_function_entry(0x2000);
        assert_eq!(a.function_entries.len(), 2);
    }
}
