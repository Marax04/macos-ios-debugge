//! `aarch64_pac` — ARM64 Pointer Authentication Code (PAC) analysis.
//!
//! Tracks PAC-signing, authentication, and stripping instructions to help
//! reverse-engineers understand PAC usage patterns, key assignments, and
//! potential PAC-bypass vulnerabilities.
//!
//! # Covered instructions
//! `PACIA`, `PACIB`, `PACDA`, `PACDB`,
//! `AUTIA`, `AUTIB`, `AUTDA`, `AUTDB`,
//! `XPACI`, `XPACD`,
//! `RETAA`, `RETAB`,
//! `BLRAA`, `BLRAB`, `BLRAAZ`, `BLRABZ`,
//! `PACIZA`, `PACIZB`, `PACDZA`, `PACDZB`,
//! `AUTIZA`, `AUTIZB`, `AUTDZA`, `AUTDZB`.

use std::collections::HashMap;
use std::fmt;

/// Modifier operand for a PAC instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacModifier {
    /// A general-purpose register is used as the modifier.
    Register(u8),
    /// The zero value is used as the modifier (PACIZA etc.).
    Zero,
}

// ---------------------------------------------------------------------------
// PAC key
// ---------------------------------------------------------------------------

/// Which PAC key is used by an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacKey {
    /// Instruction Address Key A.
    IA,
    /// Instruction Address Key B.
    IB,
    /// Data Address Key A.
    DA,
    /// Data Address Key B.
    DB,
}

impl fmt::Display for PacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IA => write!(f, "IA"),
            Self::IB => write!(f, "IB"),
            Self::DA => write!(f, "DA"),
            Self::DB => write!(f, "DB"),
        }
    }
}

impl PacKey {
    /// True for instruction-address keys (IA/IB).
    #[must_use]
    pub const fn is_instruction_key(self) -> bool {
        matches!(self, Self::IA | Self::IB)
    }

    /// True for data-address keys (DA/DB).
    #[must_use]
    pub const fn is_data_key(self) -> bool {
        matches!(self, Self::DA | Self::DB)
    }
}

// ---------------------------------------------------------------------------
// PAC instruction type
// ---------------------------------------------------------------------------

/// Categorisation of a single PAC-related instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacInstructionKind {
    /// Sign a pointer (add PAC).
    Sign,
    /// Authenticate a pointer (verify PAC, may fault on failure).
    Auth,
    /// Strip the PAC without authentication.
    Strip,
    /// Authenticate + Return (combined AUTIA/AUTIB + RET).
    AuthReturn,
    /// Authenticate + Branch Register.
    AuthBranchRegister,
}

// ---------------------------------------------------------------------------
// PacInstruction
// ---------------------------------------------------------------------------

/// A decoded PAC instruction with all semantic metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacInstruction {
    /// Virtual address of this instruction.
    pub address: u64,
    /// The raw 32-bit instruction word.
    pub raw: u32,
    /// Mnemonic string (e.g. "PACIA").
    pub mnemonic: String,
    /// What kind of operation this is.
    pub kind: PacInstructionKind,
    /// Which key is used.
    pub key: PacKey,
    /// Destination / source register index (0-30).
    pub reg: u8,
    /// Modifier operand, if present.
    pub modifier: Option<PacModifier>,
}

impl PacInstruction {
    /// Construct from parsed fields.
    pub fn new(
        address: u64,
        raw: u32,
        mnemonic: impl Into<String>,
        kind: PacInstructionKind,
        key: PacKey,
        reg: u8,
        modifier: Option<PacModifier>,
    ) -> Self {
        Self {
            address,
            raw,
            mnemonic: mnemonic.into(),
            kind,
            key,
            reg,
            modifier,
        }
    }

    /// Modifier register index, if a GPR modifier is used.
    #[must_use]
    pub const fn modifier_reg(&self) -> Option<u8> {
        if let Some(PacModifier::Register(r)) = self.modifier { Some(r) } else { None }
    }

    /// True if the zero value is used as the modifier.
    #[must_use]
    pub const fn uses_zero_modifier(&self) -> bool {
        matches!(self.modifier, Some(PacModifier::Zero))
    }

    /// True if this instruction signs a pointer.
    #[must_use]
    pub fn is_sign(&self) -> bool {
        self.kind == PacInstructionKind::Sign
    }
    /// True if this instruction authenticates a pointer.
    #[must_use]
    pub const fn is_auth(&self) -> bool {
        matches!(
            self.kind,
            PacInstructionKind::Auth
                | PacInstructionKind::AuthReturn
                | PacInstructionKind::AuthBranchRegister
        )
    }
    /// True if this instruction strips a PAC.
    #[must_use]
    pub fn is_strip(&self) -> bool {
        self.kind == PacInstructionKind::Strip
    }
}

impl fmt::Display for PacInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format address as "0x0000_1000" with underscore separator
        // Keep the full u64 value: a narrowing `as u32` here silently
        // dropped bits 48..64 of any address at or above 2^48.
        let hi = self.address >> 16;
        let lo = self.address & 0xFFFF;
        write!(f, "0x{hi:04x}_{lo:04x}  {}", self.mnemonic)?;
        if let Some(PacModifier::Register(m)) = self.modifier {
            write!(f, "  x{}, x{}", self.reg, m)?;
        } else {
            write!(f, "  x{}", self.reg)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PAC signature record
// ---------------------------------------------------------------------------

/// Records a PAC signing event observed at analysis time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacSignature {
    pub sign_addr: u64,
    pub key: PacKey,
    pub target_reg: u8,
    pub context_reg: Option<u8>,
    /// Corresponding AUTH site, if found.
    pub auth_addr: Option<u64>,
}

// ---------------------------------------------------------------------------
// Decode helpers for AArch64 PAC encoding
// ---------------------------------------------------------------------------

/// `AArch64` PAC instructions all fall in the Data Processing – Register
/// encoding space.  The canonical encoding is:
/// ```text
///   [31:29] = 110   (or 101 for some variants)
///   [28:24] = 11010
///   [21]    = 1
///   [20:16] = opcode2
///   [15:10] = opcode3
///   [9:5]   = Rn
///   [4:0]   = Rd
/// ```
fn decode_pac_op2_00001(address: u64, raw: u32, op3: u32, rd: u8, rn: u8) -> Option<PacInstruction> {
    let reg_mod = Some(PacModifier::Register(rn));
    let zero_mod = Some(PacModifier::Zero);
    match op3 {
        0b00_0100 => Some(PacInstruction::new(address, raw, "PACIA",  PacInstructionKind::Sign,       PacKey::IA, rd, reg_mod)),
        0b00_0101 => Some(PacInstruction::new(address, raw, "PACIB",  PacInstructionKind::Sign,       PacKey::IB, rd, reg_mod)),
        0b00_0110 => Some(PacInstruction::new(address, raw, "PACDA",  PacInstructionKind::Sign,       PacKey::DA, rd, reg_mod)),
        0b00_0111 => Some(PacInstruction::new(address, raw, "PACDB",  PacInstructionKind::Sign,       PacKey::DB, rd, reg_mod)),
        0b00_1100 => Some(PacInstruction::new(address, raw, "AUTIA",  PacInstructionKind::Auth,       PacKey::IA, rd, reg_mod)),
        0b00_1101 => Some(PacInstruction::new(address, raw, "AUTIB",  PacInstructionKind::Auth,       PacKey::IB, rd, reg_mod)),
        0b00_1110 => Some(PacInstruction::new(address, raw, "AUTDA",  PacInstructionKind::Auth,       PacKey::DA, rd, reg_mod)),
        0b00_1111 => Some(PacInstruction::new(address, raw, "AUTDB",  PacInstructionKind::Auth,       PacKey::DB, rd, reg_mod)),
        0b01_0000 => Some(PacInstruction::new(address, raw, "XPACI",  PacInstructionKind::Strip,      PacKey::IA, rd, zero_mod)),
        0b01_0001 => Some(PacInstruction::new(address, raw, "XPACD",  PacInstructionKind::Strip,      PacKey::DA, rd, zero_mod)),
        0b00_1000 => Some(PacInstruction::new(address, raw, "PACIZA", PacInstructionKind::Sign,       PacKey::IA, rd, zero_mod)),
        0b00_1001 => Some(PacInstruction::new(address, raw, "PACIZB", PacInstructionKind::Sign,       PacKey::IB, rd, zero_mod)),
        0b01_1000 => Some(PacInstruction::new(address, raw, "AUTIZA", PacInstructionKind::Auth,       PacKey::IA, rd, zero_mod)),
        0b01_1001 => Some(PacInstruction::new(address, raw, "AUTIZB", PacInstructionKind::Auth,       PacKey::IB, rd, zero_mod)),
        0b10_1010 => Some(PacInstruction::new(address, raw, "RETAA",  PacInstructionKind::AuthReturn, PacKey::IA, 30, zero_mod)),
        0b10_1011 => Some(PacInstruction::new(address, raw, "RETAB",  PacInstructionKind::AuthReturn, PacKey::IB, 30, zero_mod)),
        _ => None,
    }
}

fn decode_pac_op2_00010(address: u64, raw: u32, op3: u32, rd: u8, rn: u8) -> Option<PacInstruction> {
    let zero_mod = Some(PacModifier::Zero);
    match op3 {
        0b00_1000 => Some(PacInstruction::new(address, raw, "BLRAA",  PacInstructionKind::AuthBranchRegister, PacKey::IA, rn, Some(PacModifier::Register(rd)))),
        0b00_1001 => Some(PacInstruction::new(address, raw, "BLRAB",  PacInstructionKind::AuthBranchRegister, PacKey::IB, rn, Some(PacModifier::Register(rd)))),
        0b00_1100 => Some(PacInstruction::new(address, raw, "BLRAAZ", PacInstructionKind::AuthBranchRegister, PacKey::IA, rn, zero_mod)),
        0b00_1101 => Some(PacInstruction::new(address, raw, "BLRABZ", PacInstructionKind::AuthBranchRegister, PacKey::IB, rn, zero_mod)),
        _ => None,
    }
}

/// This function tries to identify PAC instructions from a 32-bit word.
#[must_use]
pub fn decode_pac_instruction(address: u64, raw: u32) -> Option<PacInstruction> {
    // Check the top-level encoding group (bits 31-23)
    let op0 = (raw >> 29) & 0x7;
    let op1 = (raw >> 24) & 0x1F;
    let op2 = (raw >> 16) & 0x1F;
    let op3 = (raw >> 10) & 0x3F;
    let rd = (raw & 0x1F) as u8;
    let rn = ((raw >> 5) & 0x1F) as u8;

    // All PAC instructions: op0=1 1x, op1=1 1010
    if op1 != 0b1_1010 {
        return None;
    }

    if op0 != 0b110 {
        return None;
    }
    match op2 {
        0b0_0001 => decode_pac_op2_00001(address, raw, op3, rd, rn),
        0b0_0010 => decode_pac_op2_00010(address, raw, op3, rd, rn),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// PAC signing context
// ---------------------------------------------------------------------------

/// The context that is mixed with the pointer when computing the PAC.
/// On `AArch64`, the context is typically the stack pointer (SP) or a GPR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacContext {
    /// SP is used as modifier (most common for return-address signing).
    StackPointer,
    /// Zero is used as modifier (PACIZA/PACIZB/etc.).
    Zero,
    /// A general-purpose register is used.
    Register(u8),
}

impl PacContext {
    #[must_use]
    pub const fn from_insn(insn: &PacInstruction) -> Self {
        match insn.modifier {
            Some(PacModifier::Zero) | None => Self::Zero,
            Some(PacModifier::Register(29 | 31)) => Self::StackPointer,
            Some(PacModifier::Register(r)) => Self::Register(r),
        }
    }
}

impl fmt::Display for PacContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StackPointer => write!(f, "sp"),
            Self::Zero => write!(f, "zero"),
            Self::Register(r) => write!(f, "x{r}"),
        }
    }
}

// ---------------------------------------------------------------------------
// PAC vulnerability classifier
// ---------------------------------------------------------------------------

/// Potential PAC-related vulnerability class.
#[derive(Debug, Clone, PartialEq)]
pub enum PacVulnClass {
    /// XPACI/XPACD strips PAC without authentication — possible bypass.
    UnauthenticatedStrip { addr: u64 },
    /// AUTH site with no matching prior SIGN for the same register.
    OrphanAuth { addr: u64 },
    /// The same key is used for both instruction and data pointers.
    KeyReuse { ia_addr: u64, da_addr: u64 },
    /// Very large number of strip operations relative to sign+auth.
    ExcessiveStripping { strip_ratio: f64 },
}

impl fmt::Display for PacVulnClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnauthenticatedStrip { addr } => {
                write!(f, "unauthenticated strip at {addr:#010x}")
            }
            Self::OrphanAuth { addr } => write!(f, "orphan auth at {addr:#010x}"),
            Self::KeyReuse { ia_addr, da_addr } => {
                write!(f, "key reuse IA@{ia_addr:#010x} DA@{da_addr:#010x}")
            }
            Self::ExcessiveStripping { strip_ratio } => {
                write!(f, "excessive stripping (ratio {strip_ratio:.2})")
            }
        }
    }
}

/// Classifies vulnerabilities from a PAC analysis result.
pub struct PacVulnClassifier;

impl PacVulnClassifier {
    #[must_use]
    pub fn classify(result: &PacAnalysisResult) -> Vec<PacVulnClass> {
        let mut vulns = Vec::new();
        // Strip sites
        for &addr in &result.strip_sites {
            vulns.push(PacVulnClass::UnauthenticatedStrip { addr });
        }
        // Orphan auth sites
        for &addr in &result.orphan_auth_sites {
            vulns.push(PacVulnClass::OrphanAuth { addr });
        }
        // Excessive stripping
        let sign_auth = result.stats.total_sign + result.stats.total_auth;
        if sign_auth > 0 {
            let strip_u32 = u32::try_from(result.stats.total_strip).unwrap_or(u32::MAX);
            let total_u32 = u32::try_from(sign_auth).unwrap_or(u32::MAX);
            let ratio = f64::from(strip_u32) / f64::from(total_u32);
            if ratio > 0.5 {
                vulns.push(PacVulnClass::ExcessiveStripping { strip_ratio: ratio });
            }
        }
        // Key reuse: IA and DA both used at non-zero addresses
        let has_ia = result.instructions.iter().any(|i| i.key == PacKey::IA);
        let key_da_used = result.instructions.iter().any(|i| i.key == PacKey::DA);
        if has_ia && key_da_used {
            let ia_addr = result
                .instructions
                .iter()
                .find(|i| i.key == PacKey::IA)
                .map_or(0, |i| i.address);
            let da_addr = result
                .instructions
                .iter()
                .find(|i| i.key == PacKey::DA)
                .map_or(0, |i| i.address);
            vulns.push(PacVulnClass::KeyReuse { ia_addr, da_addr });
        }
        vulns
    }
}

// ---------------------------------------------------------------------------
// PacAnalyzer
// ---------------------------------------------------------------------------

/// Statistics collected by [`PacAnalyzer`].
#[derive(Debug, Default, Clone)]
pub struct PacStats {
    pub total_sign: usize,
    pub total_auth: usize,
    pub total_strip: usize,
    pub total_auth_return: usize,
    pub total_auth_branch: usize,
    pub by_key: HashMap<String, usize>,
}

/// Full PAC analysis result for a function / binary region.
#[derive(Debug, Default)]
pub struct PacAnalysisResult {
    pub instructions: Vec<PacInstruction>,
    pub signatures: Vec<PacSignature>,
    pub stats: PacStats,
    /// Addresses where XPACI/XPACD strip without auth — potential bypass.
    pub strip_sites: Vec<u64>,
    /// Auth sites with no matching prior sign — potential misuse.
    pub orphan_auth_sites: Vec<u64>,
}

impl PacAnalysisResult {
    /// True if any PAC instructions were found.
    #[must_use]
    pub const fn has_pac(&self) -> bool {
        !self.instructions.is_empty()
    }

    /// True if there are potential bypass sites.
    #[must_use]
    pub const fn has_bypass_risk(&self) -> bool {
        !self.strip_sites.is_empty()
    }
}

/// Analyzes a region of `AArch64` code for PAC instruction usage.
///
/// # Example
/// ```rust
/// # use rustre_arch_arm64::aarch64_pac::PacAnalyzer;
/// let bytes = &[0x00_u8; 0]; // empty — just showing API
/// let result = PacAnalyzer::new().analyze(0x1000, bytes);
/// assert!(!result.has_pac());
/// ```
#[derive(Debug, Default)]
pub struct PacAnalyzer {
    /// If true, emit warnings for unmatched AUTH without prior SIGN.
    pub strict_pairing: bool,
}

impl PacAnalyzer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub const fn with_strict_pairing(mut self) -> Self {
        self.strict_pairing = true;
        self
    }

    /// Scan `bytes` (assumed to be 4-byte-aligned `AArch64` code) starting at
    /// virtual `base_address` and return the full analysis result.
    #[must_use]
    pub fn analyze(&self, base_address: u64, bytes: &[u8]) -> PacAnalysisResult {
        let mut result = PacAnalysisResult::default();
        let words = bytes.len() / 4;
        // Reserve upper-bound capacity for the per-word vectors so the hot
        // loop never reallocates. Most words won't be PAC instructions, so
        // we use a conservative fraction to avoid massive over-allocation.
        // Cap the pre-reservation so a huge untrusted buffer cannot force a
        // single massive allocation even before any instruction is found.
        result.instructions.reserve((words / 8).min(4096));
        // Track sign sites by register for orphan detection
        let mut signed_regs: HashMap<u8, u64> = HashMap::with_capacity(16);

        for i in 0..words {
            let raw = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
            let addr = base_address.wrapping_add((i as u64).wrapping_mul(4));
            if let Some(pac) = decode_pac_instruction(addr, raw) {
                // Update stats
                match pac.kind {
                    PacInstructionKind::Sign => {
                        result.stats.total_sign += 1;
                        signed_regs.insert(pac.reg, addr);
                        result.signatures.push(PacSignature {
                            sign_addr: addr,
                            key: pac.key,
                            target_reg: pac.reg,
                            context_reg: pac.modifier_reg(),
                            auth_addr: None,
                        });
                    }
                    PacInstructionKind::Auth => {
                        result.stats.total_auth += 1;
                        if self.strict_pairing && !signed_regs.contains_key(&pac.reg) {
                            result.orphan_auth_sites.push(addr);
                        }
                        // Link back to sign site
                        if let Some(sig) = result
                            .signatures
                            .iter_mut()
                            .rev()
                            .find(|s| s.target_reg == pac.reg && s.auth_addr.is_none())
                        {
                            sig.auth_addr = Some(addr);
                        }
                    }
                    PacInstructionKind::Strip => {
                        result.stats.total_strip += 1;
                        result.strip_sites.push(addr);
                    }
                    PacInstructionKind::AuthReturn => result.stats.total_auth_return += 1,
                    PacInstructionKind::AuthBranchRegister => result.stats.total_auth_branch += 1,
                }
                *result.stats.by_key.entry(pac.key.to_string()).or_insert(0) += 1;
                result.instructions.push(pac);
            }
        }
        result
    }

    /// Scan a slice that may contain mixed PAC and non-PAC instructions and
    /// return only the PAC instructions.
    #[must_use]
    pub fn filter_pac_instructions(&self, base: u64, bytes: &[u8]) -> Vec<PacInstruction> {
        self.analyze(base, bytes).instructions
    }
}

// ---------------------------------------------------------------------------
// Helper: build a PACIA encoding for testing
// ---------------------------------------------------------------------------

/// Build a synthetic PACIA Xd, Xn instruction word for unit tests.
/// This uses the canonical `AArch64` encoding.
#[must_use]
pub const fn encode_pacia(rd: u8, rn: u8) -> u32 {
    // op0=110 (bits 31-29), op1=11010 (bits 28-24=0x1A), op2=00001 (20-16), op3=000100 (15-10)
    // Rn in [9:5], Rd in [4:0]
    let op0: u32 = 0b110 << 29;
    let op1: u32 = 0b1_1010 << 24;
    let op2: u32 = 0b0_0001 << 16;
    let op3: u32 = 0b00_0100 << 10;
    op0 | op1 | op2 | op3 | ((rn as u32) << 5) | (rd as u32)
}

#[must_use]
pub const fn encode_autia(rd: u8, rn: u8) -> u32 {
    let op0: u32 = 0b110 << 29;
    let op1: u32 = 0b1_1010 << 24;
    let op2: u32 = 0b0_0001 << 16;
    let op3: u32 = 0b00_1100 << 10;
    op0 | op1 | op2 | op3 | ((rn as u32) << 5) | (rd as u32)
}

#[must_use]
pub const fn encode_xpaci(rd: u8) -> u32 {
    let op0: u32 = 0b110 << 29;
    let op1: u32 = 0b1_1010 << 24;
    let op2: u32 = 0b0_0001 << 16;
    let op3: u32 = 0b01_0000 << 10;
    op0 | op1 | op2 | op3 | (rd as u32)
}

#[must_use]
pub const fn encode_retaa() -> u32 {
    let op0: u32 = 0b110 << 29;
    let op1: u32 = 0b1_1010 << 24;
    let op2: u32 = 0b0_0001 << 16;
    let op3: u32 = 0b10_1010 << 10;
    op0 | op1 | op2 | op3 | 0b1_1110u32
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_bytes(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    // --- PacKey -----------------------------------------------------------

    #[test]
    fn test_pac_key_ia_is_instruction() {
        assert!(PacKey::IA.is_instruction_key());
    }
    #[test]
    fn test_pac_key_ib_is_instruction() {
        assert!(PacKey::IB.is_instruction_key());
    }
    #[test]
    fn test_pac_key_da_is_data() {
        assert!(PacKey::DA.is_data_key());
    }
    #[test]
    fn test_pac_key_db_is_data() {
        assert!(PacKey::DB.is_data_key());
    }
    #[test]
    fn test_pac_key_display() {
        assert_eq!(PacKey::IA.to_string(), "IA");
    }
    #[test]
    fn test_pac_key_ia_not_data() {
        assert!(!PacKey::IA.is_data_key());
    }
    #[test]
    fn test_pac_key_da_not_instruction() {
        assert!(!PacKey::DA.is_instruction_key());
    }

    // --- Decode PACIA -------------------------------------------------------

    #[test]
    fn test_decode_pacia() {
        let raw = encode_pacia(0, 1); // PACIA X0, X1
        let instr = decode_pac_instruction(0x1000, raw).unwrap();
        assert_eq!(instr.mnemonic, "PACIA");
        assert_eq!(instr.kind, PacInstructionKind::Sign);
        assert_eq!(instr.key, PacKey::IA);
        assert_eq!(instr.reg, 0);
        assert_eq!(instr.modifier_reg(), Some(1));
    }

    #[test]
    fn test_decode_autia() {
        let raw = encode_autia(0, 1);
        let instr = decode_pac_instruction(0x1004, raw).unwrap();
        assert_eq!(instr.mnemonic, "AUTIA");
        assert_eq!(instr.kind, PacInstructionKind::Auth);
        assert_eq!(instr.key, PacKey::IA);
    }

    #[test]
    fn test_decode_xpaci() {
        let raw = encode_xpaci(5);
        let instr = decode_pac_instruction(0x1008, raw).unwrap();
        assert_eq!(instr.mnemonic, "XPACI");
        assert_eq!(instr.kind, PacInstructionKind::Strip);
        assert_eq!(instr.reg, 5);
    }

    #[test]
    fn test_decode_retaa() {
        let raw = encode_retaa();
        let instr = decode_pac_instruction(0x100C, raw).unwrap();
        assert_eq!(instr.mnemonic, "RETAA");
        assert_eq!(instr.kind, PacInstructionKind::AuthReturn);
        assert_eq!(instr.key, PacKey::IA);
    }

    #[test]
    fn test_decode_none_for_nop() {
        // NOP = 0xD503_201F
        let result = decode_pac_instruction(0, 0xD503_201F);
        assert!(result.is_none());
    }

    #[test]
    fn test_decode_none_for_zero() {
        let result = decode_pac_instruction(0, 0x0000_0000);
        assert!(result.is_none());
    }

    // --- PacInstruction helpers -------------------------------------------

    #[test]
    fn test_pac_instr_is_sign() {
        let raw = encode_pacia(0, 1);
        let instr = decode_pac_instruction(0, raw).unwrap();
        assert!(instr.is_sign());
        assert!(!instr.is_auth());
        assert!(!instr.is_strip());
    }

    #[test]
    fn test_pac_instr_is_auth() {
        let raw = encode_autia(0, 1);
        let instr = decode_pac_instruction(0, raw).unwrap();
        assert!(instr.is_auth());
    }

    #[test]
    fn test_pac_instr_is_strip() {
        let raw = encode_xpaci(0);
        let instr = decode_pac_instruction(0, raw).unwrap();
        assert!(instr.is_strip());
    }

    #[test]
    fn test_pac_instr_display() {
        let raw = encode_pacia(0, 1);
        let instr = decode_pac_instruction(0x1000, raw).unwrap();
        let s = instr.to_string();
        assert!(s.contains("PACIA"));
        assert!(s.contains("0x0000_1000"));
    }

    // --- PacAnalyzer --------------------------------------------------------

    #[test]
    fn test_analyzer_empty() {
        let result = PacAnalyzer::new().analyze(0, &[]);
        assert!(!result.has_pac());
        assert!(!result.has_bypass_risk());
    }

    #[test]
    fn test_analyzer_single_pacia() {
        let words = vec![encode_pacia(0, 1)];
        let bytes = raw_bytes(&words);
        let result = PacAnalyzer::new().analyze(0x1000, &bytes);
        assert!(result.has_pac());
        assert_eq!(result.instructions.len(), 1);
        assert_eq!(result.stats.total_sign, 1);
        assert_eq!(result.stats.total_auth, 0);
    }

    #[test]
    fn test_analyzer_sign_auth_pair() {
        let words = vec![encode_pacia(0, 1), encode_autia(0, 1)];
        let bytes = raw_bytes(&words);
        let result = PacAnalyzer::new().analyze(0x1000, &bytes);
        assert_eq!(result.stats.total_sign, 1);
        assert_eq!(result.stats.total_auth, 1);
        // Signature should have auth_addr linked
        assert!(result.signatures[0].auth_addr.is_some());
    }

    #[test]
    fn test_analyzer_strip_site_flagged() {
        let words = vec![encode_xpaci(0)];
        let bytes = raw_bytes(&words);
        let result = PacAnalyzer::new().analyze(0x2000, &bytes);
        assert!(result.has_bypass_risk());
        assert_eq!(result.strip_sites[0], 0x2000);
    }

    #[test]
    fn test_analyzer_retaa_counted() {
        let words = vec![encode_retaa()];
        let bytes = raw_bytes(&words);
        let result = PacAnalyzer::new().analyze(0, &bytes);
        assert_eq!(result.stats.total_auth_return, 1);
    }

    #[test]
    fn test_analyzer_stats_by_key() {
        let words = vec![encode_pacia(0, 1), encode_pacia(1, 2)];
        let bytes = raw_bytes(&words);
        let result = PacAnalyzer::new().analyze(0, &bytes);
        assert_eq!(result.stats.by_key["IA"], 2);
    }

    #[test]
    fn test_analyzer_orphan_auth_strict() {
        // AUTH without prior SIGN for that register
        let words = vec![encode_autia(5, 6)];
        let bytes = raw_bytes(&words);
        let result = PacAnalyzer::new().with_strict_pairing().analyze(0, &bytes);
        assert_eq!(result.orphan_auth_sites.len(), 1);
    }

    #[test]
    fn test_analyzer_no_orphan_when_paired() {
        let words = vec![encode_pacia(5, 6), encode_autia(5, 6)];
        let bytes = raw_bytes(&words);
        let result = PacAnalyzer::new().with_strict_pairing().analyze(0, &bytes);
        assert!(result.orphan_auth_sites.is_empty());
    }

    #[test]
    fn test_filter_pac_instructions() {
        let words = vec![0xD503_201F_u32, encode_pacia(0, 1), 0xD503_201F]; // NOP, PACIA, NOP
        let bytes = raw_bytes(&words);
        let instrs = PacAnalyzer::new().filter_pac_instructions(0, &bytes);
        assert_eq!(instrs.len(), 1);
        assert_eq!(instrs[0].mnemonic, "PACIA");
    }

    // --- PacSignature -------------------------------------------------------

    #[test]
    fn test_pac_signature_fields() {
        let sig = PacSignature {
            sign_addr: 0x1000,
            key: PacKey::IA,
            target_reg: 0,
            context_reg: Some(29),
            auth_addr: Some(0x1010),
        };
        assert_eq!(sig.sign_addr, 0x1000);
        assert_eq!(sig.key, PacKey::IA);
        assert_eq!(sig.auth_addr, Some(0x1010));
    }

    // --- encode helpers stability -----------------------------------------

    #[test]
    fn test_encode_pacia_roundtrip() {
        let raw = encode_pacia(3, 4);
        let instr = decode_pac_instruction(0, raw).unwrap();
        assert_eq!(instr.key, PacKey::IA);
        assert_eq!(instr.reg, 3);
        assert_eq!(instr.modifier_reg(), Some(4));
    }

    #[test]
    fn test_encode_xpaci_roundtrip() {
        let raw = encode_xpaci(7);
        let instr = decode_pac_instruction(0, raw).unwrap();
        assert_eq!(instr.mnemonic, "XPACI");
        assert_eq!(instr.reg, 7);
        assert!(instr.uses_zero_modifier());
    }

    #[test]
    fn test_encode_retaa_roundtrip() {
        let raw = encode_retaa();
        let instr = decode_pac_instruction(0, raw).unwrap();
        assert_eq!(instr.mnemonic, "RETAA");
        assert_eq!(instr.key, PacKey::IA);
        assert_eq!(instr.kind, PacInstructionKind::AuthReturn);
    }

    #[test]
    fn test_multiple_pac_instructions_ordering() {
        let words = vec![
            encode_pacia(0, 1),
            encode_autia(0, 1),
            encode_xpaci(2),
            encode_retaa(),
        ];
        let bytes = raw_bytes(&words);
        let result = PacAnalyzer::new().analyze(0x5000, &bytes);
        assert_eq!(result.instructions.len(), 4);
        assert_eq!(result.instructions[0].address, 0x5000);
        assert_eq!(result.instructions[3].address, 0x500C);
    }

    #[test]
    fn test_pac_key_ib_not_data() {
        assert!(!PacKey::IB.is_data_key());
    }

    #[test]
    fn test_pac_key_db_not_instruction() {
        assert!(!PacKey::DB.is_instruction_key());
    }

    #[test]
    fn test_pac_instr_auth_return_is_auth() {
        let raw = encode_retaa();
        let instr = decode_pac_instruction(0, raw).unwrap();
        assert!(instr.is_auth());
    }

    #[test]
    fn test_encode_autia_roundtrip() {
        let raw = encode_autia(2, 3);
        let instr = decode_pac_instruction(0, raw).unwrap();
        assert_eq!(instr.key, PacKey::IA);
        assert_eq!(instr.reg, 2);
        assert_eq!(instr.modifier_reg(), Some(3));
    }

    #[test]
    fn test_analyzer_retab() {
        // Build a RETAB encoding (RETAB = op3=101011)
        let op0: u32 = 0b110 << 29;
        let op1: u32 = 0b1_1010 << 24;
        let op2: u32 = 0b0_0001 << 16;
        let op3: u32 = 0b10_1011 << 10;
        let raw = op0 | op1 | op2 | op3 | 0b1_1110u32;
        let instr = decode_pac_instruction(0, raw).unwrap();
        assert_eq!(instr.mnemonic, "RETAB");
        assert_eq!(instr.key, PacKey::IB);
    }

    #[test]
    fn test_pac_analyzer_multiple_sign_keys() {
        // Mix IA and IB signs
        let ia = encode_pacia(0, 1);
        let ib = {
            let op0: u32 = 0b110 << 29;
            let op1: u32 = 0b1_1010 << 24;
            let op2: u32 = 0b0_0001 << 16;
            let op3: u32 = 0b00_0101 << 10;
            op0 | op1 | op2 | op3 | (1u32 << 5) | 1u32
        };
        let bytes = raw_bytes(&[ia, ib]);
        let result = PacAnalyzer::new().analyze(0, &bytes);
        assert!(result.stats.by_key.contains_key("IA"));
    }

    #[test]
    fn test_pac_signature_no_auth_initially() {
        let words = vec![encode_pacia(0, 1)];
        let bytes = raw_bytes(&words);
        let result = PacAnalyzer::new().analyze(0, &bytes);
        assert_eq!(result.signatures[0].auth_addr, None);
    }

    #[test]
    fn test_pac_instr_raw_preserved() {
        let raw = encode_pacia(5, 6);
        let instr = decode_pac_instruction(0x2000, raw).unwrap();
        assert_eq!(instr.raw, raw);
        assert_eq!(instr.address, 0x2000);
    }

    #[test]
    fn test_pac_key_ib_display() {
        assert_eq!(PacKey::IB.to_string(), "IB");
    }

    #[test]
    fn test_pac_key_da_display() {
        assert_eq!(PacKey::DA.to_string(), "DA");
    }

    #[test]
    fn test_pac_key_db_display() {
        assert_eq!(PacKey::DB.to_string(), "DB");
    }

    #[test]
    fn test_analyzer_total_sign_multiple() {
        let w = vec![encode_pacia(0, 1), encode_pacia(1, 2), encode_pacia(2, 3)];
        let b = raw_bytes(&w);
        let r = PacAnalyzer::new().analyze(0, &b);
        assert_eq!(r.stats.total_sign, 3);
    }

    #[test]
    fn test_analyzer_strip_not_counted_as_sign() {
        let w = vec![encode_xpaci(0)];
        let b = raw_bytes(&w);
        let r = PacAnalyzer::new().analyze(0, &b);
        assert_eq!(r.stats.total_sign, 0);
        assert_eq!(r.stats.total_strip, 1);
    }

    #[test]
    fn test_pac_instruction_kind_sign() {
        assert_eq!(PacInstructionKind::Sign, PacInstructionKind::Sign);
    }

    #[test]
    fn test_pac_instruction_kind_auth() {
        assert_ne!(PacInstructionKind::Auth, PacInstructionKind::Sign);
    }

    #[test]
    fn test_analyze_nop_sequence_no_pac() {
        let nops = vec![0xD503_201F_u32; 8];
        let bytes = raw_bytes(&nops);
        let r = PacAnalyzer::new().analyze(0, &bytes);
        assert_eq!(r.instructions.len(), 0);
    }

    #[test]
    fn test_pac_analysis_result_has_pac_false_empty() {
        let r = PacAnalysisResult::default();
        assert!(!r.has_pac());
    }

    #[test]
    fn test_pac_analysis_result_no_bypass_risk_empty() {
        let r = PacAnalysisResult::default();
        assert!(!r.has_bypass_risk());
    }

    #[test]
    fn test_analyzer_strict_pairing_no_orphan_when_not_strict() {
        let words = vec![encode_autia(5, 6)];
        let bytes = raw_bytes(&words);
        let result = PacAnalyzer::new().analyze(0, &bytes); // not strict
        assert!(result.orphan_auth_sites.is_empty());
    }

    #[test]
    fn test_pac_multiple_strip_sites() {
        let words = vec![encode_xpaci(0), encode_xpaci(1), encode_xpaci(2)];
        let bytes = raw_bytes(&words);
        let r = PacAnalyzer::new().analyze(0x1000, &bytes);
        assert_eq!(r.strip_sites.len(), 3);
        assert_eq!(r.stats.total_strip, 3);
    }
}
