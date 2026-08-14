//! Pointer Authentication Code (PAC) analysis for `ARM64e`.
//!
//! PAC instructions sign and authenticate pointers using cryptographic keys.
//! This module identifies PAC instructions in disassembled `ARM64e` binaries and
//! provides utilities for stripping PAC bits from pointers.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PacError {
    #[error("not an arm64e binary")]
    NotArm64e,
    #[error("truncated instruction stream at offset {0}")]
    Truncated(usize),
    #[error("analysis error: {0}")]
    Analysis(String),
}

// ─── PacKey ───────────────────────────────────────────────────────────────────

/// The PAC key used for signing/authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacKey {
    /// Instruction address key A.
    IA,
    /// Instruction address key B.
    IB,
    /// Data address key A.
    DA,
    /// Data address key B.
    DB,
    /// Generic key A (used by PACGA).
    GA,
}

impl fmt::Display for PacKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IA => write!(f, "IA"),
            Self::IB => write!(f, "IB"),
            Self::DA => write!(f, "DA"),
            Self::DB => write!(f, "DB"),
            Self::GA => write!(f, "GA"),
        }
    }
}

// ─── PacKind ──────────────────────────────────────────────────────────────────

/// Whether the PAC instruction signs, authenticates, or strips.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacKind {
    /// PACIA/PACIB/PACDA/PACDB — signs a pointer, adding a PAC.
    Sign,
    /// AUTIA/AUTIB/AUTDA/AUTDB — authenticates a signed pointer.
    Authenticate,
    /// XPACI/XPACD/XPACLRI — strips the PAC from a pointer.
    Strip,
    /// BLRAA/BLRAB — branch with link and authenticate.
    BranchAndLink,
    /// BRAA/BRAB — branch (no link) and authenticate.
    Branch,
    /// RETAA/RETAB — return and authenticate.
    Return,
    /// LDRAA/LDRAB — load with authenticate.
    Load,
}

impl fmt::Display for PacKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sign => write!(f, "sign"),
            Self::Authenticate => write!(f, "authenticate"),
            Self::Strip => write!(f, "strip"),
            Self::BranchAndLink => write!(f, "branch-link"),
            Self::Branch => write!(f, "branch"),
            Self::Return => write!(f, "return"),
            Self::Load => write!(f, "load"),
        }
    }
}

// ─── PacInstruction ───────────────────────────────────────────────────────────

/// A PAC-related instruction found in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacInstruction {
    /// Virtual address of the instruction.
    pub address: u64,
    /// Operation kind.
    pub kind: PacKind,
    /// Key used.
    pub key: PacKey,
    /// Mnemonic (e.g. `"PACIA"`, `"BLRAA"`).
    pub mnemonic: String,
    /// A context discriminator mixed into the PAC hash (if present).
    pub context_discriminator: Option<u64>,
    /// A modifier mixed into the PAC hash (if applicable).
    pub modifier: Option<u64>,
    /// The raw 32-bit instruction encoding.
    pub encoding: u32,
    /// Target register (e.g. `"x0"`, `"lr"`).
    pub target_register: String,
    /// Source register for the context (e.g. `"sp"`, `"x16"`).
    pub context_register: Option<String>,
}

impl PacInstruction {
    /// Return the assembly text representation.
    #[must_use]
    pub fn assembly(&self) -> String {
        self.context_register.as_ref().map_or_else(
            || format!("{} {}", self.mnemonic, self.target_register),
            |ctx| format!("{} {}, {}", self.mnemonic, self.target_register, ctx),
        )
    }
}

// ─── AuthenticatedPointer ─────────────────────────────────────────────────────

/// A pointer found in data sections that has a PAC embedded in its high bits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedPointer {
    /// Virtual address where the pointer is stored.
    pub address: u64,
    /// The raw signed pointer value.
    pub raw_value: u64,
    /// The pointer value with PAC bits stripped.
    pub stripped_value: u64,
    /// Whether this is a data pointer (DA/DB) or code pointer (IA/IB).
    pub key: PacKey,
    /// The discriminator embedded in the pointer.
    pub discriminator: u16,
    /// Whether the pointer is in a chained fixup chain.
    pub is_chained: bool,
}

// ─── PAC instruction decoder ──────────────────────────────────────────────────

// `ARM64e` instruction encodings for PAC operations.
// See ARM DDI 0487 for the full encoding tables.

/// PACIA/PACIAZ encoding mask and match.
const PACIA_MASK: u32 = 0xFFFF_FC00;
const PACIA_MATCH: u32 = 0xDAC1_0000;

/// AUTIA encoding.
const AUTIA_MASK: u32 = 0xFFFF_FC00;
const AUTIA_MATCH: u32 = 0xDAC1_1000;

/// PACIB encoding.
const PACIB_MASK: u32 = 0xFFFF_FC00;
const PACIB_MATCH: u32 = 0xDAC1_0400;

/// AUTIB encoding.
const AUTIB_MASK: u32 = 0xFFFF_FC00;
const AUTIB_MATCH: u32 = 0xDAC1_1400;

/// PACDA encoding.
const PACDA_MASK: u32 = 0xFFFF_FC00;
const PACDA_MATCH: u32 = 0xDAC1_0800;

/// AUTDA encoding.
const AUTDA_MASK: u32 = 0xFFFF_FC00;
const AUTDA_MATCH: u32 = 0xDAC1_1800;

/// PACDB encoding.
const PACDB_MASK: u32 = 0xFFFF_FC00;
const PACDB_MATCH: u32 = 0xDAC1_0C00;

/// AUTDB encoding.
const AUTDB_MASK: u32 = 0xFFFF_FC00;
const AUTDB_MATCH: u32 = 0xDAC1_1C00;

/// BLRAA encoding.
const BLRAA_MASK: u32 = 0xFFFF_FC1F;
const BLRAA_MATCH: u32 = 0xD63F_0800;

/// BLRAB encoding.
const BLRAB_MASK: u32 = 0xFFFF_FC1F;
const BLRAB_MATCH: u32 = 0xD63F_0C00;

/// BRAA encoding.
const BRAA_MASK: u32 = 0xFFFF_FC1F;
const BRAA_MATCH: u32 = 0xD61F_0800;

/// BRAB encoding.
const BRAB_MASK: u32 = 0xFFFF_FC1F;
const BRAB_MATCH: u32 = 0xD61F_0C00;

/// RETAA encoding.
const RETAA_ENC: u32 = 0xD65F_0BFF;
/// RETAB encoding.
const RETAB_ENC: u32 = 0xD65F_0FFF;

/// XPACI encoding.
const XPACI_MASK: u32 = 0xFFFF_FFE0;
const XPACI_MATCH: u32 = 0xDAC1_43E0;

/// XPACD encoding.
const XPACD_MASK: u32 = 0xFFFF_FFE0;
const XPACD_MATCH: u32 = 0xDAC1_47E0;

/// Attempt to decode a 32-bit `ARM64e` instruction as a PAC instruction.
///
/// Returns `None` if the encoding does not match any known PAC instruction.
#[must_use]
pub fn decode_pac_instruction(encoding: u32, address: u64) -> Option<PacInstruction> {
    let rd = (encoding & 0x1F) as usize;
    let rn = ((encoding >> 5) & 0x1F) as usize;

    let reg_name = |n: usize| -> String {
        match n {
            0..=28 => format!("x{n}"),
            29 => "fp".to_string(),
            30 => "lr".to_string(),
            31 => "sp".to_string(),
            _ => "xzr".to_string(),
        }
    };

    if encoding == RETAA_ENC {
        return Some(PacInstruction {
            address,
            kind: PacKind::Return,
            key: PacKey::IA,
            mnemonic: "RETAA".to_string(),
            context_discriminator: None,
            modifier: None,
            encoding,
            target_register: "lr".to_string(),
            context_register: None,
        });
    }
    if encoding == RETAB_ENC {
        return Some(PacInstruction {
            address,
            kind: PacKind::Return,
            key: PacKey::IB,
            mnemonic: "RETAB".to_string(),
            context_discriminator: None,
            modifier: None,
            encoding,
            target_register: "lr".to_string(),
            context_register: None,
        });
    }

    macro_rules! check_pac {
        ($mask:expr, $match:expr, $kind:expr, $key:expr, $mnemonic:expr) => {
            if encoding & $mask == $match {
                return Some(PacInstruction {
                    address,
                    kind: $kind,
                    key: $key,
                    mnemonic: $mnemonic.to_string(),
                    context_discriminator: None,
                    modifier: None,
                    encoding,
                    target_register: reg_name(rd),
                    context_register: Some(reg_name(rn)),
                });
            }
        };
    }

    check_pac!(PACIA_MASK, PACIA_MATCH, PacKind::Sign, PacKey::IA, "PACIA");
    check_pac!(
        AUTIA_MASK,
        AUTIA_MATCH,
        PacKind::Authenticate,
        PacKey::IA,
        "AUTIA"
    );
    check_pac!(PACIB_MASK, PACIB_MATCH, PacKind::Sign, PacKey::IB, "PACIB");
    check_pac!(
        AUTIB_MASK,
        AUTIB_MATCH,
        PacKind::Authenticate,
        PacKey::IB,
        "AUTIB"
    );
    check_pac!(PACDA_MASK, PACDA_MATCH, PacKind::Sign, PacKey::DA, "PACDA");
    check_pac!(
        AUTDA_MASK,
        AUTDA_MATCH,
        PacKind::Authenticate,
        PacKey::DA,
        "AUTDA"
    );
    check_pac!(PACDB_MASK, PACDB_MATCH, PacKind::Sign, PacKey::DB, "PACDB");
    check_pac!(
        AUTDB_MASK,
        AUTDB_MATCH,
        PacKind::Authenticate,
        PacKey::DB,
        "AUTDB"
    );
    check_pac!(
        BLRAA_MASK,
        BLRAA_MATCH,
        PacKind::BranchAndLink,
        PacKey::IA,
        "BLRAA"
    );
    check_pac!(
        BLRAB_MASK,
        BLRAB_MATCH,
        PacKind::BranchAndLink,
        PacKey::IB,
        "BLRAB"
    );
    check_pac!(BRAA_MASK, BRAA_MATCH, PacKind::Branch, PacKey::IA, "BRAA");
    check_pac!(BRAB_MASK, BRAB_MATCH, PacKind::Branch, PacKey::IB, "BRAB");

    if encoding & XPACI_MASK == XPACI_MATCH {
        return Some(PacInstruction {
            address,
            kind: PacKind::Strip,
            key: PacKey::IA,
            mnemonic: "XPACI".to_string(),
            context_discriminator: None,
            modifier: None,
            encoding,
            target_register: reg_name(rd),
            context_register: None,
        });
    }
    if encoding & XPACD_MASK == XPACD_MATCH {
        return Some(PacInstruction {
            address,
            kind: PacKind::Strip,
            key: PacKey::DA,
            mnemonic: "XPACD".to_string(),
            context_discriminator: None,
            modifier: None,
            encoding,
            target_register: reg_name(rd),
            context_register: None,
        });
    }

    None
}

// ─── strip_pac ────────────────────────────────────────────────────────────────

/// Strip PAC bits from a 64-bit pointer value.
///
/// `ARM64e` uses the high bits of the virtual address space for the PAC.
/// The number of address bits varies by CPU (39, 48, or 52 bit VAs).
/// This function masks to the lower 48 bits for typical iPhone hardware
/// and sign-extends from bit 47 to restore the canonical VA.
#[must_use]
pub const fn strip_pac(ptr: u64) -> u64 {
    // Mask to 48-bit address space (typical for A12+).
    let masked = ptr & 0x0000_FFFF_FFFF_FFFF;
    // Sign-extend from bit 47.
    if masked & (1 << 47) != 0 {
        masked | 0xFFFF_0000_0000_0000
    } else {
        masked
    }
}

/// Strip PAC bits using a configurable VA width.
#[must_use]
pub const fn strip_pac_with_width(ptr: u64, va_bits: u32) -> u64 {
    let mask = (1u64 << va_bits) - 1;
    let masked = ptr & mask;
    // Sign extend from bit (va_bits - 1).
    let sign_bit = 1u64 << (va_bits - 1);
    if masked & sign_bit != 0 {
        masked | !mask
    } else {
        masked
    }
}

// ─── PacAnalysis ──────────────────────────────────────────────────────────────

/// The result of scanning a binary for PAC usage.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PacAnalysis {
    pub pac_instructions: Vec<PacInstruction>,
    pub authenticated_pointers: Vec<AuthenticatedPointer>,
    /// Number of instructions scanned.
    pub instructions_scanned: u64,
    /// Summary counts by operation kind.
    pub sign_count: u64,
    pub authenticate_count: u64,
    pub strip_count: u64,
    pub branch_auth_count: u64,
    pub return_auth_count: u64,
}

impl PacAnalysis {
    /// Scan a byte slice of ARM64 instructions for PAC usage.
    ///
    /// # Errors
    /// Returns [`PacError::Truncated`] if the slice has a non-aligned length.
    pub fn scan(code: &[u8], base_address: u64) -> Result<Self, PacError> {
        if !code.len().is_multiple_of(4) {
            return Err(PacError::Truncated(code.len()));
        }

        let mut analysis = Self::default();
        let mut offset = 0usize;

        while offset + 4 <= code.len() {
            let encoding = u32::from_le_bytes([
                code[offset],
                code[offset + 1],
                code[offset + 2],
                code[offset + 3],
            ]);
            let address = base_address + offset as u64;

            if let Some(instr) = decode_pac_instruction(encoding, address) {
                match instr.kind {
                    PacKind::Sign => analysis.sign_count += 1,
                    PacKind::Authenticate => analysis.authenticate_count += 1,
                    PacKind::Strip => analysis.strip_count += 1,
                    PacKind::BranchAndLink | PacKind::Branch | PacKind::Load => {
                        analysis.branch_auth_count += 1;
                    }
                    PacKind::Return => analysis.return_auth_count += 1,
                }
                analysis.pac_instructions.push(instr);
            }

            analysis.instructions_scanned += 1;
            offset += 4;
        }

        Ok(analysis)
    }

    /// Return the total PAC instruction count.
    #[must_use]
    pub const fn total_pac_instructions(&self) -> usize {
        self.pac_instructions.len()
    }

    /// Return `true` if any PAC instructions were found (arm64e binary).
    #[must_use]
    pub const fn uses_pac(&self) -> bool {
        !self.pac_instructions.is_empty()
    }

    /// Return all RETAA/RETAB instructions (function returns secured by PAC).
    #[must_use]
    pub fn authenticated_returns(&self) -> Vec<&PacInstruction> {
        self.pac_instructions
            .iter()
            .filter(|i| matches!(i.kind, PacKind::Return))
            .collect()
    }

    /// Return all sign instructions.
    #[must_use]
    pub fn sign_instructions(&self) -> Vec<&PacInstruction> {
        self.pac_instructions
            .iter()
            .filter(|i| matches!(i.kind, PacKind::Sign))
            .collect()
    }

    /// Return all instructions using a specific key.
    #[must_use]
    pub fn instructions_by_key(&self, key: PacKey) -> Vec<&PacInstruction> {
        self.pac_instructions
            .iter()
            .filter(|i| i.key == key)
            .collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_pac_lower() {
        // A normal kernel address should be unchanged.
        let addr: u64 = 0xFFFF_8000_1000_4000;
        let stripped = strip_pac(addr);
        // Low 48 bits.
        assert_eq!(
            stripped & 0x0000_FFFF_FFFF_FFFF,
            addr & 0x0000_FFFF_FFFF_FFFF
        );
    }

    #[test]
    fn test_strip_pac_userspace() {
        let addr: u64 = 0x0000_0001_8000_4000;
        assert_eq!(strip_pac(addr), addr);
    }

    #[test]
    fn test_strip_pac_with_width() {
        let addr: u64 = 0x0000_DEAD_BEEF_1234;
        let stripped = strip_pac_with_width(addr, 48);
        assert_eq!(
            stripped & 0x0000_FFFF_FFFF_FFFF,
            addr & 0x0000_FFFF_FFFF_FFFF
        );
    }

    #[test]
    fn test_decode_retaa() {
        let instr = decode_pac_instruction(RETAA_ENC, 0x1000);
        assert!(instr.is_some());
        let i = instr.unwrap();
        assert_eq!(i.mnemonic, "RETAA");
        assert!(matches!(i.kind, PacKind::Return));
        assert!(matches!(i.key, PacKey::IA));
    }

    #[test]
    fn test_decode_retab() {
        let instr = decode_pac_instruction(RETAB_ENC, 0x1004);
        assert!(instr.is_some());
        let i = instr.unwrap();
        assert_eq!(i.mnemonic, "RETAB");
        assert!(matches!(i.key, PacKey::IB));
    }

    #[test]
    fn test_decode_nop_returns_none() {
        // NOP = 0xD503201F
        let instr = decode_pac_instruction(0xD503_201F, 0x1000);
        assert!(instr.is_none());
    }

    #[test]
    fn test_scan_retaa_retab() {
        // Two instructions: RETAA, RETAB.
        let code: [u8; 8] = [
            0xFF, 0x0B, 0x5F, 0xD6, // RETAA
            0xFF, 0x0F, 0x5F, 0xD6, // RETAB
        ];
        let analysis = PacAnalysis::scan(&code, 0x1000).unwrap();
        assert_eq!(analysis.total_pac_instructions(), 2);
        assert!(analysis.uses_pac());
        assert_eq!(analysis.return_auth_count, 2);
    }

    #[test]
    fn test_scan_no_pac() {
        // NOP x 4
        let code: [u8; 8] = [0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5];
        let analysis = PacAnalysis::scan(&code, 0x1000).unwrap();
        assert!(!analysis.uses_pac());
    }

    #[test]
    fn test_scan_odd_length_fails() {
        let code: [u8; 5] = [0xFF, 0x0B, 0x5F, 0xD6, 0x00];
        let err = PacAnalysis::scan(&code, 0).unwrap_err();
        assert!(matches!(err, PacError::Truncated(_)));
    }

    #[test]
    fn test_pac_key_display() {
        assert_eq!(PacKey::IA.to_string(), "IA");
        assert_eq!(PacKey::DB.to_string(), "DB");
    }

    #[test]
    fn test_pac_kind_display() {
        assert_eq!(PacKind::Sign.to_string(), "sign");
        assert_eq!(PacKind::Return.to_string(), "return");
    }

    #[test]
    fn test_pac_instruction_assembly() {
        let i = PacInstruction {
            address: 0x1000,
            kind: PacKind::Sign,
            key: PacKey::IA,
            mnemonic: "PACIA".to_string(),
            context_discriminator: None,
            modifier: None,
            encoding: PACIA_MATCH,
            target_register: "lr".to_string(),
            context_register: Some("sp".to_string()),
        };
        assert_eq!(i.assembly(), "PACIA lr, sp");
    }

    #[test]
    fn test_pac_error_display() {
        assert!(PacError::NotArm64e.to_string().contains("arm64e"));
        assert!(PacError::Truncated(64).to_string().contains("64"));
    }

    #[test]
    fn test_authenticated_returns() {
        let code: [u8; 8] = [
            0xFF, 0x0B, 0x5F, 0xD6, // RETAA
            0xFF, 0x0F, 0x5F, 0xD6, // RETAB
        ];
        let analysis = PacAnalysis::scan(&code, 0x1000).unwrap();
        let rets = analysis.authenticated_returns();
        assert_eq!(rets.len(), 2);
    }

    #[test]
    fn test_instructions_by_key() {
        let code: [u8; 8] = [
            0xFF, 0x0B, 0x5F, 0xD6, // RETAA (IA)
            0xFF, 0x0F, 0x5F, 0xD6, // RETAB (IB)
        ];
        let analysis = PacAnalysis::scan(&code, 0x1000).unwrap();
        assert_eq!(analysis.instructions_by_key(PacKey::IA).len(), 1);
        assert_eq!(analysis.instructions_by_key(PacKey::IB).len(), 1);
        assert!(analysis.instructions_by_key(PacKey::DA).is_empty());
    }
}
