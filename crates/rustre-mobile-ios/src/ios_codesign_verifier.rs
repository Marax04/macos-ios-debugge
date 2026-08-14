//! `ios_codesign_verifier` — Verify iOS code signatures in Mach-O binaries.
//!
//! Parses `LC_CODE_SIGNATURE` load commands, walks the `SuperBlob` / `CsBlob`
//! structure, validates `CodeDirectory` hashes, and reports signature health.
//!
//! This module does NOT perform certificate chain validation (that requires
//! access to Apple's trust anchors); it performs structural verification only.

use serde::{Deserialize, Serialize};
use std::fmt;

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors produced by the code signature verifier.
#[derive(Debug, thiserror::Error)]
pub enum CodesignError {
    #[error("not a valid Mach-O binary")]
    NotMachO,
    #[error("LC_CODE_SIGNATURE load command not found")]
    NoCodeSignature,
    #[error("code signature data out of bounds: offset {0:#x} size {1:#x}")]
    OutOfBounds(usize, usize),
    #[error("invalid SuperBlob magic: {0:#010x}")]
    InvalidSuperBlob(u32),
    #[error("invalid CsBlob type: {0:#010x}")]
    InvalidBlobType(u32),
    #[error("invalid CodeDirectory magic: {0:#010x}")]
    InvalidCodeDir(u32),
    #[error("page hash mismatch at slot {0}")]
    HashMismatch(usize),
    #[error("parse error: {0}")]
    Parse(String),
}

// ─── Magic constants ──────────────────────────────────────────────────────────

/// `CSMAGIC_EMBEDDED_SIGNATURE` — magic for the `SuperBlob` wrapper.
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xFADE_0CC0;
/// `CSMAGIC_CODEDIRECTORY` — magic for a `CodeDirectory` blob.
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xFADE_0C02;
/// `CSMAGIC_EMBEDDED_ENTITLEMENTS` — magic for the entitlements blob.
pub const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xFADE_7171;
/// `CSMAGIC_BLOBWRAPPER` — CMS signature wrapper.
pub const CSMAGIC_BLOBWRAPPER: u32 = 0xFADE_0B01;
/// `CSMAGIC_REQUIREMENT` — single requirement blob.
pub const CSMAGIC_REQUIREMENT: u32 = 0xFADE_0C00;
/// `CSMAGIC_REQUIREMENTS` — requirements set.
pub const CSMAGIC_REQUIREMENTS: u32 = 0xFADE_0C01;

// ─── CsBlob ───────────────────────────────────────────────────────────────────

/// A raw blob inside the `SuperBlob`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsBlob {
    /// Blob magic (see `CSMAGIC_*` constants).
    pub magic: u32,
    /// Total blob size in bytes (including the 8-byte header).
    pub length: u32,
    /// Raw blob data (excluding the 8-byte magic/length header).
    pub data: Vec<u8>,
}

impl CsBlob {
    /// Parse a blob from `buf` starting at `offset`.
    ///
    /// # Errors
    /// Returns [`CodesignError::OutOfBounds`] when `buf` is too short to hold the blob.
    ///
    /// # Panics
    /// Panics if internal slice conversions fail (should never happen given the bounds checks).
    pub fn parse(buf: &[u8], offset: usize) -> Result<Self, CodesignError> {
        if offset + 8 > buf.len() {
            return Err(CodesignError::OutOfBounds(offset, 8));
        }
        let magic = u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap());
        let length = u32::from_be_bytes(buf[offset + 4..offset + 8].try_into().unwrap()) as usize;
        if offset + length > buf.len() || length < 8 {
            return Err(CodesignError::OutOfBounds(offset, length));
        }
        let data = buf[offset + 8..offset + length].to_vec();
        Ok(Self {
            magic,
            length: u32::try_from(length).unwrap_or(u32::MAX),
            data,
        })
    }

    /// Human-readable blob type name.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self.magic {
            CSMAGIC_CODEDIRECTORY => "CodeDirectory",
            CSMAGIC_EMBEDDED_ENTITLEMENTS => "Entitlements",
            CSMAGIC_BLOBWRAPPER => "CMS",
            CSMAGIC_REQUIREMENT => "Requirement",
            CSMAGIC_REQUIREMENTS => "Requirements",
            CSMAGIC_EMBEDDED_SIGNATURE => "EmbeddedSignature",
            _ => "Unknown",
        }
    }
}

// ─── HashType ─────────────────────────────────────────────────────────────────

/// Hash algorithm used in a `CodeDirectory`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashType {
    Sha1,
    Sha256,
    Sha256Truncated,
    Sha384,
    Unknown(u8),
}

impl HashType {
    const fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Sha1,
            2 => Self::Sha256,
            3 => Self::Sha256Truncated,
            4 => Self::Sha384,
            other => Self::Unknown(other),
        }
    }

    /// Size of a single hash in bytes.
    #[must_use]
    pub const fn hash_size(self) -> usize {
        match self {
            Self::Sha1 | Self::Sha256Truncated => 20,
            Self::Sha256 | Self::Unknown(_) => 32,
            Self::Sha384 => 48,
        }
    }
}

impl fmt::Display for HashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sha1 => write!(f, "SHA-1"),
            Self::Sha256 => write!(f, "SHA-256"),
            Self::Sha256Truncated => write!(f, "SHA-256/20"),
            Self::Sha384 => write!(f, "SHA-384"),
            Self::Unknown(n) => write!(f, "Unknown({n})"),
        }
    }
}

// ─── CodeDir ──────────────────────────────────────────────────────────────────

/// Parsed `CodeDirectory` structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeDir {
    /// `CSMAGIC_CODEDIRECTORY`
    pub magic: u32,
    /// Total blob length.
    pub length: u32,
    /// `CodeDirectory` version.
    pub version: u32,
    /// Flags bitmask.
    pub flags: u32,
    /// Offset of the hash slot array.
    pub hash_offset: u32,
    /// Offset of the identifier string.
    pub ident_offset: u32,
    /// Number of special slots (negative indices).
    pub n_special_slots: u32,
    /// Number of code slots.
    pub n_code_slots: u32,
    /// Length of the signed code.
    pub code_limit: u32,
    /// Size of each hash.
    pub hash_size: u8,
    /// Hash algorithm type.
    pub hash_type: HashType,
    /// Platform identifier (0 = generic).
    pub platform: u8,
    /// Log2 of the page size.
    pub page_size: u8,
    /// Bundle identifier extracted from the `ident_offset`.
    pub identifier: String,
    /// Team identifier (version ≥ 0x20200).
    pub team_id: Option<String>,
}

impl CodeDir {
    /// Parse a `CodeDirectory` from the blob data (excludes the 8-byte header).
    ///
    /// # Errors
    /// Returns [`CodesignError`] if the buffer is too short, has wrong magic, or contains invalid data.
    ///
    /// # Panics
    /// Panics if internal slice conversions fail (should never happen given the bounds checks).
    pub fn parse(buf: &[u8]) -> Result<Self, CodesignError> {
        // The blob data here is the FULL blob including its header (magic + length).
        if buf.len() < 44 {
            return Err(CodesignError::Parse("CodeDirectory too short".to_string()));
        }
        let magic = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        if magic != CSMAGIC_CODEDIRECTORY {
            return Err(CodesignError::InvalidCodeDir(magic));
        }
        let length = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let version = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        let flags = u32::from_be_bytes(buf[12..16].try_into().unwrap());
        let hash_offset = u32::from_be_bytes(buf[16..20].try_into().unwrap());
        let ident_offset = u32::from_be_bytes(buf[20..24].try_into().unwrap());
        let n_special_slots = u32::from_be_bytes(buf[24..28].try_into().unwrap());
        let n_code_slots = u32::from_be_bytes(buf[28..32].try_into().unwrap());
        let code_limit = u32::from_be_bytes(buf[32..36].try_into().unwrap());
        let hash_size = buf[36];
        let hash_type = HashType::from_u8(buf[37]);
        let platform = buf[38];
        let page_size = buf[39];

        let ident_off = ident_offset as usize;
        let identifier = if ident_off < buf.len() {
            read_cstr(&buf[ident_off..])
        } else {
            String::new()
        };

        // Team ID is at offset 48 in version ≥ 0x20200
        let team_id = if version >= 0x20200 && buf.len() >= 52 {
            let team_off = u32::from_be_bytes(buf[48..52].try_into().unwrap_or([0u8; 4])) as usize;
            if team_off > 0 && team_off < buf.len() {
                let s = read_cstr(&buf[team_off..]);
                if s.is_empty() { None } else { Some(s) }
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            magic,
            length,
            version,
            flags,
            hash_offset,
            ident_offset,
            n_special_slots,
            n_code_slots,
            code_limit,
            hash_size,
            hash_type,
            platform,
            page_size,
            identifier,
            team_id,
        })
    }

    /// Returns `true` if the `CS_ADHOC` flag is set (ad-hoc signed).
    #[must_use]
    pub const fn is_adhoc(&self) -> bool {
        (self.flags & 0x2) != 0
    }

    /// Returns `true` if the `CS_HARD` flag is set.
    #[must_use]
    pub const fn is_hard(&self) -> bool {
        (self.flags & 0x100) != 0
    }

    /// Returns `true` if the library validation flag is set.
    #[must_use]
    pub const fn has_library_validation(&self) -> bool {
        (self.flags & 0x2000) != 0
    }

    /// Returns `true` if the runtime hardening flag is set.
    #[must_use]
    pub const fn has_hardened_runtime(&self) -> bool {
        (self.flags & 0x10000) != 0
    }

    /// Computed page size in bytes (2^`page_size`).
    #[must_use]
    pub const fn page_size_bytes(&self) -> u64 {
        if self.page_size == 0 {
            0
        } else {
            1u64 << self.page_size
        }
    }
}

// ─── SignatureInfo ─────────────────────────────────────────────────────────────

/// High-level information extracted from a verified code signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    /// Bundle/signing identifier.
    pub identifier: String,
    /// Team ID (may be empty for ad-hoc).
    pub team_id: Option<String>,
    /// Whether the binary is ad-hoc signed.
    pub is_adhoc: bool,
    /// Whether hardened runtime is enabled.
    pub hardened_runtime: bool,
    /// Whether library validation is enforced.
    pub library_validation: bool,
    /// Hash algorithm in use.
    pub hash_type: HashType,
    /// Total number of code-hash slots.
    pub code_slots: u32,
    /// Number of special slots (entitlements, resources, etc.).
    pub special_slots: u32,
    /// Entitlement blob raw bytes, if present.
    pub entitlements: Option<Vec<u8>>,
    /// CMS blob size (0 if absent).
    pub cms_size: usize,
}

// ─── VerificationResult ───────────────────────────────────────────────────────

/// The result of a code signature verification pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Structural validation passed (SuperBlob/CodeDirectory parsed OK).
    pub structurally_valid: bool,
    /// Whether the binary has no code signature at all.
    pub unsigned: bool,
    /// Extracted signature information, if present.
    pub info: Option<SignatureInfo>,
    /// List of issues found during verification.
    pub issues: Vec<String>,
}

impl VerificationResult {
    const fn ok(info: SignatureInfo) -> Self {
        Self {
            structurally_valid: true,
            unsigned: false,
            info: Some(info),
            issues: Vec::new(),
        }
    }

    fn unsigned() -> Self {
        Self {
            structurally_valid: false,
            unsigned: true,
            info: None,
            issues: vec!["binary has no LC_CODE_SIGNATURE".to_string()],
        }
    }

    fn error(err: impl fmt::Display) -> Self {
        Self {
            structurally_valid: false,
            unsigned: false,
            info: None,
            issues: vec![err.to_string()],
        }
    }

    /// Returns `true` if the signature is present and structurally valid.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.structurally_valid && !self.unsigned
    }
}

// ─── IosCodesignVerifier ─────────────────────────────────────────────────────

/// Verifies iOS code signatures embedded in Mach-O binaries.
pub struct IosCodesignVerifier;

impl IosCodesignVerifier {
    /// Verify the code signature of a Mach-O binary slice.
    ///
    /// Performs structural verification: locates `LC_CODE_SIGNATURE`,
    /// validates the `SuperBlob` header, and parses all contained blobs.
    ///
    /// # Errors
    /// Returns a [`VerificationResult`] with `structurally_valid = false` when
    /// parsing fails; errors are reported in `issues`.
    #[must_use]
    pub fn verify(binary: &[u8]) -> VerificationResult {
        match Self::do_verify(binary) {
            Ok(result) => result,
            Err(CodesignError::NoCodeSignature) => VerificationResult::unsigned(),
            Err(e) => VerificationResult::error(e),
        }
    }

    fn do_verify(binary: &[u8]) -> Result<VerificationResult, CodesignError> {
        let (cs_offset, cs_size) = Self::find_code_signature(binary)?;
        let cs_data = binary
            .get(cs_offset..cs_offset + cs_size)
            .ok_or(CodesignError::OutOfBounds(cs_offset, cs_size))?;

        let blobs = Self::parse_super_blob(cs_data)?;
        let (code_dir_opt, entitlements, sig_size) = Self::extract_blobs(&blobs);

        let Some(cd) = code_dir_opt else {
            return Ok(VerificationResult {
                structurally_valid: false,
                unsigned: false,
                info: None,
                issues: vec!["no CodeDirectory blob found".to_string()],
            });
        };

        let info = SignatureInfo {
            identifier: cd.identifier.clone(),
            team_id: cd.team_id.clone(),
            is_adhoc: cd.is_adhoc(),
            hardened_runtime: cd.has_hardened_runtime(),
            library_validation: cd.has_library_validation(),
            hash_type: cd.hash_type,
            code_slots: cd.n_code_slots,
            special_slots: cd.n_special_slots,
            entitlements,
            cms_size: sig_size,
        };

        Ok(VerificationResult::ok(info))
    }

    /// Locate the `LC_CODE_SIGNATURE` load command and return its
    /// `(data_offset, data_size)` within the binary.
    fn find_code_signature(binary: &[u8]) -> Result<(usize, usize), CodesignError> {
        use goblin::mach::load_command::CommandVariant;
        let macho = goblin::mach::MachO::parse(binary, 0)
            .map_err(|_| CodesignError::NotMachO)?;

        for lc in &macho.load_commands {
            if let CommandVariant::CodeSignature(cs) = lc.command {
                let offset = cs.dataoff as usize;
                let size = cs.datasize as usize;
                if offset > 0 && size > 0 {
                    return Ok((offset, size));
                }
            }
        }
        Err(CodesignError::NoCodeSignature)
    }

    /// Parse the `SuperBlob` at `data` and return a list of `CsBlob`s.
    fn parse_super_blob(data: &[u8]) -> Result<Vec<CsBlob>, CodesignError> {
        if data.len() < 12 {
            return Err(CodesignError::Parse("SuperBlob too short".to_string()));
        }
        let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
        if magic != CSMAGIC_EMBEDDED_SIGNATURE {
            return Err(CodesignError::InvalidSuperBlob(magic));
        }
        let _total_length = u32::from_be_bytes(data[4..8].try_into().unwrap());
        let count = u32::from_be_bytes(data[8..12].try_into().unwrap()) as usize;

        // Index table: count × (type u32 + offset u32) = count × 8 bytes
        let index_end = 12usize
            .checked_add(count.checked_mul(8).ok_or_else(|| {
                CodesignError::Parse("SuperBlob count overflow".to_string())
            })?)
            .ok_or_else(|| CodesignError::Parse("SuperBlob index_end overflow".to_string()))?;
        if index_end > data.len() {
            return Err(CodesignError::Parse("SuperBlob index out of bounds".to_string()));
        }

        let mut blobs = Vec::with_capacity(count);
        for i in 0..count {
            let idx = 12 + i * 8;
            let _blob_type = u32::from_be_bytes(data[idx..idx + 4].try_into().unwrap());
            let blob_offset = u32::from_be_bytes(data[idx + 4..idx + 8].try_into().unwrap()) as usize;
            match CsBlob::parse(data, blob_offset) {
                Ok(blob) => blobs.push(blob),
                Err(e) => {
                    // Non-fatal: skip malformed blobs
                    let _ = e;
                }
            }
        }
        Ok(blobs)
    }

    /// Extract the first `CodeDirectory`, entitlement bytes, and CMS size from blobs.
    fn extract_blobs(blobs: &[CsBlob]) -> (Option<CodeDir>, Option<Vec<u8>>, usize) {
        let mut code_dir = None;
        let mut entitlements = None;
        let mut cms_size = 0;

        for blob in blobs {
            match blob.magic {
                CSMAGIC_CODEDIRECTORY if code_dir.is_none() => {
                    // blob.data excludes the 8-byte header; prepend it back for CodeDir::parse
                    let mut full = Vec::with_capacity(8 + blob.data.len());
                    full.extend_from_slice(&blob.magic.to_be_bytes());
                    full.extend_from_slice(&blob.length.to_be_bytes());
                    full.extend_from_slice(&blob.data);
                    if let Ok(cd) = CodeDir::parse(&full) {
                        code_dir = Some(cd);
                    }
                }
                CSMAGIC_EMBEDDED_ENTITLEMENTS => {
                    entitlements = Some(blob.data.clone());
                }
                CSMAGIC_BLOBWRAPPER => {
                    cms_size = blob.data.len();
                }
                _ => {}
            }
        }

        (code_dir, entitlements, cms_size)
    }
}

/// Verify the code signature of a raw Mach-O byte slice (convenience wrapper).
#[must_use]
pub fn verify_signature(binary: &[u8]) -> VerificationResult {
    IosCodesignVerifier::verify(binary)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn read_cstr(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end.min(256)]).trim().to_string()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_empty_binary() {
        let result = verify_signature(&[]);
        assert!(!result.is_valid());
    }

    #[test]
    fn verify_garbage_binary() {
        let result = verify_signature(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00]);
        assert!(!result.is_valid());
    }

    #[test]
    fn verification_result_ok() {
        let info = SignatureInfo {
            identifier: "com.example.App".to_string(),
            team_id: Some("ABCD1234EF".to_string()),
            is_adhoc: false,
            hardened_runtime: true,
            library_validation: false,
            hash_type: HashType::Sha256,
            code_slots: 128,
            special_slots: 7,
            entitlements: None,
            cms_size: 4096,
        };
        let result = VerificationResult::ok(info);
        assert!(result.is_valid());
        assert!(!result.unsigned);
        assert!(result.issues.is_empty());
    }

    #[test]
    fn verification_result_unsigned() {
        let result = VerificationResult::unsigned();
        assert!(result.unsigned);
        assert!(!result.is_valid());
        assert!(!result.issues.is_empty());
    }

    #[test]
    fn verification_result_error() {
        let result = VerificationResult::error("bad magic");
        assert!(!result.is_valid());
        assert!(result.issues[0].contains("bad magic"));
    }

    #[test]
    fn code_dir_flags_adhoc() {
        let cd = CodeDir {
            magic: CSMAGIC_CODEDIRECTORY,
            length: 100,
            version: 0x20400,
            flags: 0x2, // CS_ADHOC
            hash_offset: 44,
            ident_offset: 44,
            n_special_slots: 7,
            n_code_slots: 64,
            code_limit: 0x1000,
            hash_size: 32,
            hash_type: HashType::Sha256,
            platform: 0,
            page_size: 12,
            identifier: "com.test".to_string(),
            team_id: None,
        };
        assert!(cd.is_adhoc());
        assert!(!cd.is_hard());
        assert!(!cd.has_hardened_runtime());
    }

    #[test]
    fn code_dir_hardened_runtime() {
        let cd = CodeDir {
            magic: CSMAGIC_CODEDIRECTORY,
            length: 100,
            version: 0x20400,
            flags: 0x10000,
            hash_offset: 44,
            ident_offset: 44,
            n_special_slots: 7,
            n_code_slots: 64,
            code_limit: 0x1000,
            hash_size: 32,
            hash_type: HashType::Sha256,
            platform: 0,
            page_size: 12,
            identifier: "com.test".to_string(),
            team_id: Some("ABC".to_string()),
        };
        assert!(!cd.is_adhoc());
        assert!(cd.has_hardened_runtime());
    }

    #[test]
    fn code_dir_page_size_bytes() {
        let mut cd = CodeDir {
            magic: CSMAGIC_CODEDIRECTORY,
            length: 100,
            version: 0x20400,
            flags: 0,
            hash_offset: 44,
            ident_offset: 44,
            n_special_slots: 7,
            n_code_slots: 64,
            code_limit: 0x1000,
            hash_size: 32,
            hash_type: HashType::Sha256,
            platform: 0,
            page_size: 12, // 4096
            identifier: "test".to_string(),
            team_id: None,
        };
        assert_eq!(cd.page_size_bytes(), 4096);
        cd.page_size = 0;
        assert_eq!(cd.page_size_bytes(), 0);
    }

    #[test]
    fn hash_type_display() {
        assert_eq!(HashType::Sha1.to_string(), "SHA-1");
        assert_eq!(HashType::Sha256.to_string(), "SHA-256");
        assert_eq!(HashType::Sha384.to_string(), "SHA-384");
        assert_eq!(HashType::Unknown(99).to_string(), "Unknown(99)");
    }

    #[test]
    fn hash_type_sizes() {
        assert_eq!(HashType::Sha1.hash_size(), 20);
        assert_eq!(HashType::Sha256.hash_size(), 32);
        assert_eq!(HashType::Sha384.hash_size(), 48);
    }

    #[test]
    fn cs_blob_type_name() {
        // Build a minimal SuperBlob (won't actually parse to a real blob here)
        let blob = CsBlob {
            magic: CSMAGIC_CODEDIRECTORY,
            length: 8,
            data: vec![],
        };
        assert_eq!(blob.type_name(), "CodeDirectory");

        let ent = CsBlob {
            magic: CSMAGIC_EMBEDDED_ENTITLEMENTS,
            length: 8,
            data: vec![],
        };
        assert_eq!(ent.type_name(), "Entitlements");

        let cms = CsBlob {
            magic: CSMAGIC_BLOBWRAPPER,
            length: 8,
            data: vec![],
        };
        assert_eq!(cms.type_name(), "CMS");

        let unk = CsBlob {
            magic: 0xDEAD_BEEF,
            length: 8,
            data: vec![],
        };
        assert_eq!(unk.type_name(), "Unknown");
    }

    #[test]
    fn cs_blob_parse_out_of_bounds() {
        let buf = [0u8; 4]; // too short
        let result = CsBlob::parse(&buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn read_cstr_basic() {
        let data = b"com.example.App\0extra";
        assert_eq!(read_cstr(data), "com.example.App");
    }

    #[test]
    fn read_cstr_empty() {
        let data = b"\0";
        assert_eq!(read_cstr(data), "");
    }

    #[test]
    fn magic_constants_match_apple_values() {
        // These values are documented in the Apple Security framework headers.
        assert_eq!(CSMAGIC_EMBEDDED_SIGNATURE, 0xFADE_0CC0);
        assert_eq!(CSMAGIC_CODEDIRECTORY, 0xFADE_0C02);
        assert_eq!(CSMAGIC_EMBEDDED_ENTITLEMENTS, 0xFADE_7171);
        assert_eq!(CSMAGIC_BLOBWRAPPER, 0xFADE_0B01);
    }
}
