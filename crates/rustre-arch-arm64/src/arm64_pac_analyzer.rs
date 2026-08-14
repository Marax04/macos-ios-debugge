//! ARM64 Pointer Authentication Code (PAC) analysis.
//!
//! Detects PAC instructions in `AArch64` disassembly, classifies key usage
//! (IA, IB, DA, DB, GA), identifies signing and authentication sites, and
//! provides a mask for stripping PAC bits from a pointer.

use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// PacKey
// ─────────────────────────────────────────────────────────────────────────────

/// The five PAC key identifiers used in `AArch64` pointer authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacKey {
    /// Instruction Address Key A (used by PACIA/AUTIA/BRAA etc.)
    Ia,
    /// Instruction Address Key B (PACIB/AUTIB/BRAB etc.)
    Ib,
    /// Data Address Key A (PACDA/AUTDA etc.)
    Da,
    /// Data Address Key B (PACDB/AUTDB etc.)
    Db,
    /// Generic Key (PACGA only — returns a PAC in the upper half of Xd)
    Generic,
}

impl PacKey {
    /// Return a human-readable name for the key.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ia => "IA",
            Self::Ib => "IB",
            Self::Da => "DA",
            Self::Db => "DB",
            Self::Generic => "GA",
        }
    }

    /// Returns `true` when this key is used for instruction pointers.
    #[must_use]
    pub const fn is_instruction_key(self) -> bool {
        matches!(self, Self::Ia | Self::Ib)
    }

    /// Returns `true` when this key is used for data pointers.
    #[must_use]
    pub const fn is_data_key(self) -> bool {
        matches!(self, Self::Da | Self::Db)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PacInstrKind
// ─────────────────────────────────────────────────────────────────────────────

/// The broad category of a PAC-related instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacInstrKind {
    /// Sign a pointer (PAC*, PACG*).
    Sign,
    /// Authenticate a pointer (AUT*).
    Authenticate,
    /// Authenticate and branch (BRAA/BRAB/BLRAA/BLRAB).
    AuthenticateAndBranch,
    /// Strip a PAC and return the raw pointer (XPAC*).
    Strip,
    /// Combined return with authentication (RETAA/RETAB).
    AuthenticateAndReturn,
}

// ─────────────────────────────────────────────────────────────────────────────
// PacInstr
// ─────────────────────────────────────────────────────────────────────────────

/// A decoded PAC-related instruction found during analysis.
#[derive(Debug, Clone)]
pub struct PacInstr {
    /// Virtual address of the instruction.
    pub address: u64,
    /// Raw mnemonic string (lower-case).
    pub mnemonic: String,
    /// Instruction category.
    pub kind: PacInstrKind,
    /// PAC key used.
    pub key: PacKey,
    /// Whether the modifier register (Xm) is the stack pointer (SP).
    pub uses_sp: bool,
    /// Whether this is a zero-modifier variant (suffix `Z`).
    pub zero_context: bool,
}

impl PacInstr {
    /// Returns `true` when this instruction signs a pointer (i.e. introduces
    /// a PAC into the pointer's high bits).
    #[must_use]
    pub fn is_sign(&self) -> bool {
        self.kind == PacInstrKind::Sign
    }

    /// Returns `true` when this instruction authenticates a pointer.
    #[must_use]
    pub const fn is_auth(&self) -> bool {
        matches!(
            self.kind,
            PacInstrKind::Authenticate
                | PacInstrKind::AuthenticateAndBranch
                | PacInstrKind::AuthenticateAndReturn
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mnemonic recognition
// ─────────────────────────────────────────────────────────────────────────────

/// Attempt to classify a mnemonic string as a PAC instruction.
///
/// Returns `Some((PacInstrKind, PacKey, uses_sp, zero_context))` on success,
/// `None` for non-PAC mnemonics.
#[must_use]
pub fn classify_pac_mnemonic(mnemonic: &str) -> Option<(PacInstrKind, PacKey, bool, bool)> {
    let m = mnemonic.to_ascii_lowercase();
    let m = m.as_str();

    // Authenticate-and-return
    if m == "retaa" { return Some((PacInstrKind::AuthenticateAndReturn, PacKey::Ia, false, false)); }
    if m == "retab" { return Some((PacInstrKind::AuthenticateAndReturn, PacKey::Ib, false, false)); }

    // Authenticate-and-branch (BRAA/BRAB, BLRAA/BLRAB — with register modifier)
    if m == "braa"  { return Some((PacInstrKind::AuthenticateAndBranch, PacKey::Ia, false, false)); }
    if m == "brab"  { return Some((PacInstrKind::AuthenticateAndBranch, PacKey::Ib, false, false)); }
    if m == "braaz" { return Some((PacInstrKind::AuthenticateAndBranch, PacKey::Ia, false, true)); }
    if m == "brabz" { return Some((PacInstrKind::AuthenticateAndBranch, PacKey::Ib, false, true)); }
    if m == "blraa" { return Some((PacInstrKind::AuthenticateAndBranch, PacKey::Ia, false, false)); }
    if m == "blrab" { return Some((PacInstrKind::AuthenticateAndBranch, PacKey::Ib, false, false)); }
    if m == "blraaz"{ return Some((PacInstrKind::AuthenticateAndBranch, PacKey::Ia, false, true)); }
    if m == "blrabz"{ return Some((PacInstrKind::AuthenticateAndBranch, PacKey::Ib, false, true)); }

    // Strip
    if m == "xpacd" { return Some((PacInstrKind::Strip, PacKey::Da, false, false)); }
    if m == "xpaci" { return Some((PacInstrKind::Strip, PacKey::Ia, false, false)); }
    if m == "xpaclri" { return Some((PacInstrKind::Strip, PacKey::Ia, false, false)); }

    // Sign
    if m == "pacia"   { return Some((PacInstrKind::Sign, PacKey::Ia, false, false)); }
    if m == "paciasp" { return Some((PacInstrKind::Sign, PacKey::Ia, true,  false)); }
    if m == "paciaz"  { return Some((PacInstrKind::Sign, PacKey::Ia, false, true)); }
    if m == "pacib"   { return Some((PacInstrKind::Sign, PacKey::Ib, false, false)); }
    if m == "pacibsp" { return Some((PacInstrKind::Sign, PacKey::Ib, true,  false)); }
    if m == "pacibz"  { return Some((PacInstrKind::Sign, PacKey::Ib, false, true)); }
    if m == "pacda"   { return Some((PacInstrKind::Sign, PacKey::Da, false, false)); }
    if m == "pacdaap" { return Some((PacInstrKind::Sign, PacKey::Da, true,  false)); }
    if m == "pacdaz"  { return Some((PacInstrKind::Sign, PacKey::Da, false, true)); }
    if m == "pacdb"   { return Some((PacInstrKind::Sign, PacKey::Db, false, false)); }
    if m == "pacdbsp" { return Some((PacInstrKind::Sign, PacKey::Db, true,  false)); }
    if m == "pacdbz"  { return Some((PacInstrKind::Sign, PacKey::Db, false, true)); }
    if m == "pacga"   { return Some((PacInstrKind::Sign, PacKey::Generic, false, false)); }

    // Authenticate
    if m == "autia"   { return Some((PacInstrKind::Authenticate, PacKey::Ia, false, false)); }
    if m == "autiasp" { return Some((PacInstrKind::Authenticate, PacKey::Ia, true,  false)); }
    if m == "autiaz"  { return Some((PacInstrKind::Authenticate, PacKey::Ia, false, true)); }
    if m == "autib"   { return Some((PacInstrKind::Authenticate, PacKey::Ib, false, false)); }
    if m == "autibsp" { return Some((PacInstrKind::Authenticate, PacKey::Ib, true,  false)); }
    if m == "autibz"  { return Some((PacInstrKind::Authenticate, PacKey::Ib, false, true)); }
    if m == "autda"   { return Some((PacInstrKind::Authenticate, PacKey::Da, false, false)); }
    if m == "autdasp" { return Some((PacInstrKind::Authenticate, PacKey::Da, true,  false)); }
    if m == "autdaz"  { return Some((PacInstrKind::Authenticate, PacKey::Da, false, true)); }
    if m == "autdb"   { return Some((PacInstrKind::Authenticate, PacKey::Db, false, false)); }
    if m == "autdbsp" { return Some((PacInstrKind::Authenticate, PacKey::Db, true,  false)); }
    if m == "autdbz"  { return Some((PacInstrKind::Authenticate, PacKey::Db, false, true)); }

    None
}

// ─────────────────────────────────────────────────────────────────────────────
// pac_strip_mask
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the mask used to strip PAC bits from a pointer.
///
/// On `AArch64` with a 48-bit virtual address space (the most common case),
/// bits[63:56] and bits[55:48] of a signed pointer contain the PAC.
/// Specifically, bits `[63:55]` minus the top address bit constitute the PAC
/// field; the exact width depends on `TBI` and `VA_SIZE`.
///
/// This function returns a conservative mask that, when `ANDed` with a signed
/// pointer, zeroes the PAC bits and sign-extends from bit 55 (the typical
/// configuration).
///
/// `va_bits` is the number of virtual-address bits (default 48 on most
/// `AArch64` systems; Apple Silicon uses 47+1).
///
/// Returns a 64-bit mask where `1` bits indicate address bits and `0` bits
/// indicate PAC bits.
#[must_use]
pub const fn pac_strip_mask(va_bits: u8) -> u64 {
    // The PAC occupies bits [63 : va_bits - 1] for the non-TBI case.
    // We want to keep bits [va_bits-2 : 0] plus the top sign bit (bit 63).
    if va_bits == 0 || va_bits > 63 {
        return u64::MAX;
    }
    // Keep bits [va_bits-2 : 0] (address bits below the PAC field) plus the
    // sign bit (63). Bit va_bits-1 and above (excluding 63) are PAC bits.
    let low_mask: u64 = (1u64 << (va_bits - 1)).wrapping_sub(1);
    let sign_bit: u64 = 1u64 << 63;
    sign_bit | low_mask
}

/// Strip the PAC from a pointer value using a pre-computed mask.
///
/// This is a heuristic operation: it zeroes the PAC field but does not
/// cryptographically verify the pointer.
#[must_use]
pub const fn pac_strip_pointer(ptr: u64, va_bits: u8) -> u64 {
    let mask = pac_strip_mask(va_bits);
    // Pure mask: zero the PAC bits. The top sign bit (63) is preserved from
    // the original pointer to distinguish user vs. kernel pointers.
    let top_sign = ptr & (1u64 << 63);
    let low = ptr & mask & !(1u64 << 63);
    low | top_sign
}

// ─────────────────────────────────────────────────────────────────────────────
// PacFinding
// ─────────────────────────────────────────────────────────────────────────────

/// A notable PAC-related finding during analysis.
#[derive(Debug, Clone)]
pub enum PacFinding {
    /// A function prologue signs the link register (LR) with PACIASP/PACIBSP.
    FunctionPrologue {
        /// Address of the signing instruction.
        sign_addr: u64,
        /// PAC key used.
        key: PacKey,
    },
    /// A function epilogue authenticates LR with AUTIASP/AUTIBSP.
    FunctionEpilogue {
        /// Address of the authentication instruction.
        auth_addr: u64,
        /// PAC key used.
        key: PacKey,
    },
    /// Mismatched sign/authenticate keys within the same function.
    KeyMismatch {
        /// Sign address.
        sign_addr: u64,
        /// Authentication address.
        auth_addr: u64,
        /// Key used for signing.
        sign_key: PacKey,
        /// Key used for authentication.
        auth_key: PacKey,
    },
    /// XPACI/XPACD without a preceding authentication — potential bypass.
    UnauthenticatedStrip {
        /// Address of the strip instruction.
        addr: u64,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// Arm64PacAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Analyzer that processes a linear sequence of `(address, mnemonic)` pairs
/// and accumulates PAC instruction information.
///
/// # Usage
/// ```no_run
/// use rustre_arch_arm64::arm64_pac_analyzer::Arm64PacAnalyzer;
///
/// let mut analyzer = Arm64PacAnalyzer::new(48);
/// analyzer.process_instruction(0x1000, "paciasp");
/// analyzer.process_instruction(0x1004, "autiasp");
/// let report = analyzer.finish();
/// assert_eq!(report.sign_count, 1);
/// assert_eq!(report.auth_count, 1);
/// ```
#[derive(Debug)]
pub struct Arm64PacAnalyzer {
    /// Number of virtual address bits (typically 48).
    pub va_bits: u8,
    /// All decoded PAC instructions in encounter order.
    pub instructions: Vec<PacInstr>,
    /// Findings accumulated during analysis.
    pub findings: Vec<PacFinding>,
    /// Count by key (sign operations).
    sign_by_key: HashMap<PacKey, usize>,
    /// Count by key (auth operations).
    auth_by_key: HashMap<PacKey, usize>,
    /// Last sign instruction per key (for mismatch detection).
    last_sign: HashMap<PacKey, u64>,
}

impl Arm64PacAnalyzer {
    /// Create a new analyzer for the given virtual-address bit width.
    #[must_use]
    pub fn new(va_bits: u8) -> Self {
        Self {
            va_bits,
            instructions: Vec::new(),
            findings: Vec::new(),
            sign_by_key: HashMap::new(),
            auth_by_key: HashMap::new(),
            last_sign: HashMap::new(),
        }
    }

    /// Process one instruction, identified by its address and mnemonic.
    ///
    /// Returns `true` when the instruction is a PAC-related instruction.
    pub fn process_instruction(&mut self, address: u64, mnemonic: &str) -> bool {
        let Some((kind, key, uses_sp, zero_context)) = classify_pac_mnemonic(mnemonic) else {
            return false;
        };

        let instr = PacInstr {
            address,
            mnemonic: mnemonic.to_ascii_lowercase(),
            kind,
            key,
            uses_sp,
            zero_context,
        };

        // Accumulate statistics and findings
        match kind {
            PacInstrKind::Sign => {
                *self.sign_by_key.entry(key).or_insert(0) += 1;
                self.last_sign.insert(key, address);
                if uses_sp {
                    self.findings.push(PacFinding::FunctionPrologue {
                        sign_addr: address,
                        key,
                    });
                }
            }
            PacInstrKind::Authenticate => {
                *self.auth_by_key.entry(key).or_insert(0) += 1;
                if uses_sp {
                    self.findings.push(PacFinding::FunctionEpilogue {
                        auth_addr: address,
                        key,
                    });
                    // Detect mismatch: last sign used a different key
                    for (&sk, &sa) in &self.last_sign {
                        if sk != key {
                            self.findings.push(PacFinding::KeyMismatch {
                                sign_addr: sa,
                                auth_addr: address,
                                sign_key: sk,
                                auth_key: key,
                            });
                        }
                    }
                }
            }
            PacInstrKind::AuthenticateAndReturn => {
                *self.auth_by_key.entry(key).or_insert(0) += 1;
                self.findings.push(PacFinding::FunctionEpilogue {
                    auth_addr: address,
                    key,
                });
            }
            PacInstrKind::AuthenticateAndBranch => {
                *self.auth_by_key.entry(key).or_insert(0) += 1;
            }
            PacInstrKind::Strip => {
                // Strip without prior auth in this window is suspicious
                if self.auth_by_key.values().sum::<usize>() == 0 {
                    self.findings.push(PacFinding::UnauthenticatedStrip {
                        addr: address,
                    });
                }
            }
        }

        self.instructions.push(instr);
        true
    }

    /// Finish analysis and return a summary report.
    #[must_use]
    pub fn finish(self) -> PacReport {
        let sign_count: usize = self.sign_by_key.values().sum();
        let auth_count: usize = self.auth_by_key.values().sum();
        PacReport {
            sign_count,
            auth_count,
            instructions: self.instructions,
            findings: self.findings,
            sign_by_key: self.sign_by_key,
            auth_by_key: self.auth_by_key,
            va_bits: self.va_bits,
        }
    }

    /// Total number of PAC instructions encountered so far.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.instructions.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PacReport
// ─────────────────────────────────────────────────────────────────────────────

/// Summary report produced by [`Arm64PacAnalyzer::finish`].
#[derive(Debug)]
pub struct PacReport {
    /// Total number of signing instructions.
    pub sign_count: usize,
    /// Total number of authentication instructions.
    pub auth_count: usize,
    /// All PAC instructions in encounter order.
    pub instructions: Vec<PacInstr>,
    /// Interesting findings (prologues, epilogues, mismatches).
    pub findings: Vec<PacFinding>,
    /// Sign count broken down by key.
    pub sign_by_key: HashMap<PacKey, usize>,
    /// Auth count broken down by key.
    pub auth_by_key: HashMap<PacKey, usize>,
    /// Virtual address bit width used.
    pub va_bits: u8,
}

impl PacReport {
    /// Returns `true` when any PAC instructions were found.
    #[must_use]
    pub const fn has_pac(&self) -> bool {
        !self.instructions.is_empty()
    }

    /// Returns `true` when every signing operation has a matching authenticate.
    #[must_use]
    pub const fn is_balanced(&self) -> bool {
        self.sign_count == self.auth_count
    }

    /// All key-mismatch findings.
    #[must_use]
    pub fn key_mismatches(&self) -> Vec<&PacFinding> {
        self.findings
            .iter()
            .filter(|f| matches!(f, PacFinding::KeyMismatch { .. }))
            .collect()
    }

    /// Strip the PAC from a pointer using the VA size stored in this report.
    #[must_use]
    pub const fn strip_pac(&self, ptr: u64) -> u64 {
        pac_strip_pointer(ptr, self.va_bits)
    }

    /// Count function prologues (PACIASP / PACIBSP).
    #[must_use]
    pub fn prologue_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| matches!(f, PacFinding::FunctionPrologue { .. }))
            .count()
    }

    /// Count function epilogues (AUTIASP / AUTIBSP / RETAA / RETAB).
    #[must_use]
    pub fn epilogue_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| matches!(f, PacFinding::FunctionEpilogue { .. }))
            .count()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pac_key_names() {
        assert_eq!(PacKey::Ia.name(), "IA");
        assert_eq!(PacKey::Ib.name(), "IB");
        assert_eq!(PacKey::Da.name(), "DA");
        assert_eq!(PacKey::Db.name(), "DB");
        assert_eq!(PacKey::Generic.name(), "GA");
    }

    #[test]
    fn pac_key_classification() {
        assert!(PacKey::Ia.is_instruction_key());
        assert!(PacKey::Ib.is_instruction_key());
        assert!(!PacKey::Da.is_instruction_key());
        assert!(PacKey::Da.is_data_key());
        assert!(PacKey::Db.is_data_key());
        assert!(!PacKey::Ia.is_data_key());
    }

    #[test]
    fn classify_paciasp() {
        let r = classify_pac_mnemonic("paciasp").unwrap();
        assert_eq!(r.0, PacInstrKind::Sign);
        assert_eq!(r.1, PacKey::Ia);
        assert!(r.2); // uses_sp
    }

    #[test]
    fn classify_autibsp() {
        let r = classify_pac_mnemonic("autibsp").unwrap();
        assert_eq!(r.0, PacInstrKind::Authenticate);
        assert_eq!(r.1, PacKey::Ib);
        assert!(r.2); // uses_sp
    }

    #[test]
    fn classify_retaa() {
        let r = classify_pac_mnemonic("retaa").unwrap();
        assert_eq!(r.0, PacInstrKind::AuthenticateAndReturn);
        assert_eq!(r.1, PacKey::Ia);
    }

    #[test]
    fn classify_braa() {
        let r = classify_pac_mnemonic("braa").unwrap();
        assert_eq!(r.0, PacInstrKind::AuthenticateAndBranch);
        assert_eq!(r.1, PacKey::Ia);
    }

    #[test]
    fn classify_xpaci() {
        let r = classify_pac_mnemonic("xpaci").unwrap();
        assert_eq!(r.0, PacInstrKind::Strip);
    }

    #[test]
    fn classify_non_pac_returns_none() {
        assert!(classify_pac_mnemonic("add").is_none());
        assert!(classify_pac_mnemonic("ldr").is_none());
        assert!(classify_pac_mnemonic("").is_none());
    }

    #[test]
    fn pac_strip_mask_48bit() {
        let mask = pac_strip_mask(48);
        // Bit 63 (sign) and bits 0..46 should be 1, PAC bits should be 0
        assert!(mask & (1u64 << 63) != 0, "sign bit must be kept");
        assert!(mask & (1u64 << 47) == 0, "PAC bit 47 must be zeroed");
        assert!(mask & (1u64 << 0) != 0, "bit 0 must be kept");
    }

    #[test]
    fn pac_strip_pointer_user_space() {
        // A 48-bit user pointer with some garbage in the PAC bits
        let ptr: u64 = 0x00AA_BBCC_1234_5678; // upper bits are PAC
        let stripped = pac_strip_pointer(ptr, 48);
        // Should keep only bits [46:0]
        assert_eq!(stripped & 0xFFFF_0000_0000_0000, 0);
    }

    #[test]
    fn analyzer_basic_flow() {
        let mut a = Arm64PacAnalyzer::new(48);
        assert!(a.process_instruction(0x1000, "paciasp"));
        assert!(a.process_instruction(0x1004, "autiasp"));
        assert!(!a.process_instruction(0x1008, "add"));
        assert_eq!(a.total(), 2);
        let report = a.finish();
        assert_eq!(report.sign_count, 1);
        assert_eq!(report.auth_count, 1);
        assert!(report.is_balanced());
        assert!(report.has_pac());
    }

    #[test]
    fn analyzer_prologue_epilogue_findings() {
        let mut a = Arm64PacAnalyzer::new(48);
        a.process_instruction(0x1000, "paciasp");
        a.process_instruction(0x1200, "autiasp");
        let report = a.finish();
        assert_eq!(report.prologue_count(), 1);
        assert_eq!(report.epilogue_count(), 1);
    }

    #[test]
    fn analyzer_retab_epilogue() {
        let mut a = Arm64PacAnalyzer::new(48);
        a.process_instruction(0x1000, "pacibsp");
        a.process_instruction(0x1100, "retab");
        let report = a.finish();
        assert_eq!(report.epilogue_count(), 1);
    }

    #[test]
    fn analyzer_unauthenticated_strip() {
        let mut a = Arm64PacAnalyzer::new(48);
        // No prior auth — strip is suspicious
        a.process_instruction(0x2000, "xpaci");
        let report = a.finish();
        let strips: Vec<_> = report
            .findings
            .iter()
            .filter(|f| matches!(f, PacFinding::UnauthenticatedStrip { .. }))
            .collect();
        assert!(!strips.is_empty());
    }

    #[test]
    fn pac_strip_mask_zero_va_bits() {
        // Edge case: 0 va_bits → MAX mask
        assert_eq!(pac_strip_mask(0), u64::MAX);
    }

    #[test]
    fn pac_key_generic_not_instruction_or_data() {
        assert!(!PacKey::Generic.is_instruction_key());
        assert!(!PacKey::Generic.is_data_key());
    }
}
