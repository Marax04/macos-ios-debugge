//! `macho_code_sign` — Mach-O code signing structures decoder.
//!
//! Parses the code-signature `SuperBlob` found at the file offset described by
//! `LC_CODE_SIGNATURE`. Supports:
//!
//! - **`SuperBlob`** (`CSMAGIC_EMBEDDED_SIGNATURE 0xFADE_0CC0`): index of blob
//!   slots.
//! - **`CodeDirectory`** (`CSMAGIC_CODEDIRECTORY 0xFADE_0C02`): version, flags,
//!   hash type, identifier, team ID, hash slots (info / requirements /
//!   resources / application / entitlements / DER entitlements / code pages).
//! - **Requirements** (`CSMAGIC_REQUIREMENTS 0xFADE_0C01`) and individual
//!   `Requirement` (`CSMAGIC_REQUIREMENT 0xFADE_0C00`): raw blob storage.
//! - **CMS blob** (`CSMAGIC_BLOBWRAPPER 0xFADE_0B01`): signature payload.
//! - **Entitlements XML** (`CSMAGIC_ENTITLEMENTS 0xFADE_7171`): embedded
//!   plist XML text.
//! - **DER entitlements** (`CSMAGIC_ENTITLEMENTS_DER 0xFADE_7172`): DER-
//!   encoded entitlements blob.
//! - **Notarization** detection heuristic: presence of a CMS blob whose size
//!   exceeds the typical ad-hoc signature threshold (> 2 KiB).

use std::fmt;

// ─── Magic constants ──────────────────────────────────────────────────────────

pub const CSMAGIC_REQUIREMENT:          u32 = 0xFADE_0C00;
pub const CSMAGIC_REQUIREMENTS:         u32 = 0xFADE_0C01;
pub const CSMAGIC_CODEDIRECTORY:        u32 = 0xFADE_0C02;
pub const CSMAGIC_EMBEDDED_SIGNATURE:   u32 = 0xFADE_0CC0;
pub const CSMAGIC_DETACHED_SIGNATURE:   u32 = 0xFADE_0CC1;
pub const CSMAGIC_BLOBWRAPPER:          u32 = 0xFADE_0B01;
pub const CSMAGIC_ENTITLEMENTS:         u32 = 0xFADE_7171;
pub const CSMAGIC_ENTITLEMENTS_DER:     u32 = 0xFADE_7172;

// ─── Slot type constants ──────────────────────────────────────────────────────

// ── CodeDirectory flag bits ──────────────────────────────────────────────────
// Values cross-checked against rustre-mobile-ios/src/codesign.rs, which is an
// independent reconstruction of the same Apple header.
/// Signature is ad-hoc (no signing identity).
pub const CS_ADHOC: u32 = 0x0000_0002;
/// Kill the process if the signature becomes invalid.
pub const CS_HARD: u32 = 0x0000_0100;
/// Binary is an Apple platform binary.
///
/// Note the magnitude: this is *not* `0x0000_0004`, which is
/// `CS_GET_TASK_ALLOW` — a flag meaning the process is debuggable, i.e. close
/// to the opposite security posture.
pub const CS_PLATFORM_BINARY: u32 = 0x0400_0000;
/// Library Validation is required.
pub const CS_REQUIRE_LV: u32 = 0x0000_2000;
/// Signature expiry is checked. Recorded because the shipped
/// `requires_library_validation` tested this bit by mistake.
pub const CS_CHECK_EXPIRATION: u32 = 0x0000_0400;
/// The process is debuggable. Recorded because the shipped
/// `is_platform_binary` tested this bit by mistake.
pub const CS_GET_TASK_ALLOW: u32 = 0x0000_0004;

pub const CS_SLOT_CODEDIRECTORY:        u32 = 0;
pub const CS_SLOT_INFOSLOT:             u32 = 1;
pub const CS_SLOT_REQUIREMENTS:         u32 = 2;
pub const CS_SLOT_RESOURCEDIR:          u32 = 3;
pub const CS_SLOT_APPLICATION:          u32 = 4;
pub const CS_SLOT_ENTITLEMENTS:         u32 = 5;
pub const CS_SLOT_DER_ENTITLEMENTS:     u32 = 7;
pub const CS_SLOT_ALTERNATE_BASE:       u32 = 0x1000;

// ─── Hash type constants ──────────────────────────────────────────────────────

/// Hash algorithm identifier used in a `CodeDirectory`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CsHashType {
    NoHash,
    Sha1,
    Sha256,
    Sha256Truncated,
    Sha384,
    Sha512,
    Unknown(u8),
}

impl CsHashType {
    #[must_use] 
    pub const fn from_raw(v: u8) -> Self {
        match v {
            0 => Self::NoHash,
            1 => Self::Sha1,
            2 => Self::Sha256,
            3 => Self::Sha256Truncated,
            4 => Self::Sha384,
            5 => Self::Sha512,
            _ => Self::Unknown(v),
        }
    }

    #[must_use] 
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha1 | Self::Sha256Truncated => 20,
            Self::Sha256  => 32,
            Self::Sha384  => 48,
            Self::Sha512  => 64,
            _             => 0,
        }
    }

    #[must_use] 
    pub const fn name(self) -> &'static str {
        match self {
            Self::NoHash          => "none",
            Self::Sha1            => "SHA-1",
            Self::Sha256          => "SHA-256",
            Self::Sha256Truncated => "SHA-256/Truncated",
            Self::Sha384          => "SHA-384",
            Self::Sha512          => "SHA-512",
            Self::Unknown(_)      => "unknown",
        }
    }
}

// ─── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeSignError {
    TooShort(&'static str),
    BadMagic { got: u32, expected: u32 },
    InvalidOffset { slot: u32, offset: usize },
    InvalidSlotCount(u32),
}

impl fmt::Display for CodeSignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort(ctx)               => write!(f, "truncated code-signature blob: {ctx}"),
            Self::BadMagic { got, expected }  => write!(f, "magic mismatch: expected {expected:#010x}, got {got:#010x}"),
            Self::InvalidOffset { slot, offset } => write!(f, "slot {slot:#010x} has offset {offset} beyond blob"),
            Self::InvalidSlotCount(n)         => write!(f, "unreasonable slot count: {n}"),
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn rbe32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_be_bytes(s.try_into().unwrap()))
}

#[must_use] 
pub fn rbe64(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8)
        .map(|s| u64::from_be_bytes(s.try_into().unwrap()))
}

fn cstr_nul(b: &[u8], off: usize) -> String {
    if off >= b.len() { return String::new(); }
    let s = &b[off..];
    let nul = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf8_lossy(&s[..nul]).into_owned()
}

// ─────────────────────────────────────────────────────────────────────────────
// CodeDirectory
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed `CodeDirectory` blob (`CSMAGIC_CODEDIRECTORY`).
///
/// All multi-byte fields in the on-disk structure are **big-endian**.
#[derive(Debug, Clone)]
pub struct CodeDirectory {
    /// Structure version (e.g. `0x20400`).
    pub version: u32,
    /// Flags bitmask (see `CS_*` flag constants).
    pub flags: u32,
    /// File offset to the start of the hash slots.
    pub hash_offset: u32,
    /// File offset to the identifier string.
    pub ident_offset: u32,
    /// Number of special (negative-index) hash slots.
    pub n_special_slots: u32,
    /// Number of code hash slots (code page hashes).
    pub n_code_slots: u32,
    /// Length of the signed code.
    pub code_limit: u32,
    /// Size of each hash in bytes.
    pub hash_size: u8,
    /// Hash type (see [`CsHashType`]).
    pub hash_type: CsHashType,
    /// Platform identifier (0 = not platform binary).
    pub platform: u8,
    /// Page size (as log2; 0 = no paging).
    pub page_size: u8,
    /// Spare2 / reserved field.
    pub spare2: u32,
    /// Bundle identifier string (e.g. `"com.apple.dyld"`).
    pub identifier: String,
    /// Team identifier string (present if `version >= 0x20200`).
    pub team_id: Option<String>,
    /// The raw bytes of each special slot, indexed `[0..n_special_slots]`.
    /// Index 0 = slot -1 (closest to code), index `n_special_slots-1` = slot
    /// `-n_special_slots`.
    pub special_hashes: Vec<Vec<u8>>,
}

impl CodeDirectory {
    /// Parse a `CodeDirectory` from the blob at `data[0..]`.
    ///
    /// `data` must begin at the `magic` field of the `CodeDirectory`.
    pub fn parse(data: &[u8]) -> Result<Self, CodeSignError> {
        // Minimum size for version 0x20000: 44 bytes
        if data.len() < 44 {
            return Err(CodeSignError::TooShort("CodeDirectory header"));
        }
        let magic = rbe32(data, 0).unwrap();
        if magic != CSMAGIC_CODEDIRECTORY {
            return Err(CodeSignError::BadMagic { got: magic, expected: CSMAGIC_CODEDIRECTORY });
        }
        let _length        = rbe32(data, 4).unwrap_or(0);
        let version        = rbe32(data, 8).unwrap_or(0);
        let flags          = rbe32(data, 12).unwrap_or(0);
        let hash_offset    = rbe32(data, 16).unwrap_or(0);
        let ident_offset   = rbe32(data, 20).unwrap_or(0);
        let n_special_slots= rbe32(data, 24).unwrap_or(0);
        let n_code_slots   = rbe32(data, 28).unwrap_or(0);
        let code_limit     = rbe32(data, 32).unwrap_or(0);
        let hash_size      = data.get(36).copied().unwrap_or(0);
        let hash_type      = CsHashType::from_raw(data.get(37).copied().unwrap_or(0));
        let platform       = data.get(38).copied().unwrap_or(0);
        let page_size      = data.get(39).copied().unwrap_or(0);
        let spare2         = rbe32(data, 40).unwrap_or(0);

        let identifier = cstr_nul(data, ident_offset as usize);

        // Team ID present at offset 48 if version >= 0x20200
        let team_id = if version >= 0x20200 && data.len() >= 52 {
            let tid_off = rbe32(data, 44).unwrap_or(0) as usize;
            if tid_off != 0 && tid_off < data.len() {
                let s = cstr_nul(data, tid_off);
                if s.is_empty() { None } else { Some(s) }
            } else {
                None
            }
        } else {
            None
        };

        // Parse special hash slots (negative-indexed; stored before code slots)
        // hash_offset points to the first code slot (slot 0).
        // Special slots occupy positions [hash_offset - n_special_slots * hash_size ..
        //                                  hash_offset)
        let mut special_hashes = Vec::new();
        let ho = hash_offset as usize;
        let hs = hash_size as usize;
        if hs > 0 && n_special_slots > 0 {
            let special_start = ho.saturating_sub(n_special_slots as usize * hs);
            for i in 0..n_special_slots as usize {
                let off = special_start + i * hs;
                let end = (off + hs).min(data.len());
                if off >= data.len() { break; }
                special_hashes.push(data[off..end].to_vec());
            }
        }

        Ok(Self {
            version, flags, hash_offset, ident_offset,
            n_special_slots, n_code_slots, code_limit,
            hash_size, hash_type, platform, page_size, spare2,
            identifier, team_id, special_hashes,
        })
    }

    /// Return the hash for a named special slot, if present.
    ///
    /// Slot numbers: 1=Info, 2=Requirements, 3=ResourceDir, 4=Application,
    /// 5=Entitlements, 7=DER-entitlements.
    pub fn special_hash(&self, slot: u32) -> Option<&[u8]> {
        if slot == 0 || slot > self.n_special_slots {
            return None;
        }
        let idx = (self.n_special_slots - slot) as usize;
        self.special_hashes.get(idx).map(Vec::as_slice)
    }

    /// True if the binary is ad-hoc signed (`CS_ADHOC` flag).
    #[must_use] 
    pub const fn is_adhoc(&self) -> bool {
        self.flags & CS_ADHOC != 0
    }

    /// True if the binary has the `CS_PLATFORM_BINARY` flag.
    #[must_use] 
    pub const fn is_platform_binary(&self) -> bool {
        self.flags & CS_PLATFORM_BINARY != 0
    }

    /// True if the binary has the `CS_HARD` flag (kill-on-invalidity).
    #[must_use] 
    pub const fn is_hard(&self) -> bool {
        self.flags & CS_HARD != 0
    }

    /// True if Library Validation (`CS_REQUIRE_LV`) is set.
    ///
    /// This shipped testing `0x0000_0400`, which xnu's `cs_blobs.h` defines as
    /// `CS_CHECK_EXPIRATION` — an unrelated bit about certificate expiry.
    #[must_use]
    pub const fn requires_library_validation(&self) -> bool {
        self.flags & CS_REQUIRE_LV != 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Requirement blob
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed Requirement or `RequirementSet` blob.
#[derive(Debug, Clone)]
pub struct RequirementBlob {
    pub magic: u32,
    pub length: u32,
    /// Raw blob data (excludes the 8-byte magic+length header).
    pub data: Vec<u8>,
}

impl RequirementBlob {
    pub fn parse(blob: &[u8]) -> Result<Self, CodeSignError> {
        if blob.len() < 8 {
            return Err(CodeSignError::TooShort("RequirementBlob"));
        }
        let magic  = rbe32(blob, 0).unwrap();
        let length = rbe32(blob, 4).unwrap();
        let end = (length as usize).min(blob.len());
        let data = blob[8..end.max(8)].to_vec();
        Ok(Self { magic, length, data })
    }

    #[must_use] 
    pub const fn is_requirements_set(&self) -> bool {
        self.magic == CSMAGIC_REQUIREMENTS
    }
    #[must_use] 
    pub const fn is_single_requirement(&self) -> bool {
        self.magic == CSMAGIC_REQUIREMENT
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entitlements
// ─────────────────────────────────────────────────────────────────────────────

/// Decoded entitlements from the code signature.
#[derive(Debug, Clone)]
pub struct EntitlementsBlob {
    /// Raw XML plist text (UTF-8).
    pub xml: String,
    /// Whether a `com.apple.security.get-task-allow` key is present.
    pub has_get_task_allow: bool,
    /// Whether a `com.apple.security.cs.debugger` key is present.
    pub has_debugger: bool,
    /// Whether `platform-application` is set.
    pub is_platform_app: bool,
}

impl EntitlementsBlob {
    pub fn parse(blob: &[u8]) -> Result<Self, CodeSignError> {
        if blob.len() < 8 {
            return Err(CodeSignError::TooShort("EntitlementsBlob"));
        }
        let magic = rbe32(blob, 0).unwrap_or(0);
        if magic != CSMAGIC_ENTITLEMENTS {
            return Err(CodeSignError::BadMagic { got: magic, expected: CSMAGIC_ENTITLEMENTS });
        }
        let length = rbe32(blob, 4).unwrap_or(0) as usize;
        let data_end = length.min(blob.len());
        let xml_bytes = if data_end > 8 { &blob[8..data_end] } else { b"" };
        let xml = String::from_utf8_lossy(xml_bytes).into_owned();
        let has_get_task_allow = xml.contains("get-task-allow");
        let has_debugger       = xml.contains("cs.debugger");
        let is_platform_app    = xml.contains("platform-application");
        Ok(Self { xml, has_get_task_allow, has_debugger, is_platform_app })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Slot descriptor
// ─────────────────────────────────────────────────────────────────────────────

/// A single slot entry within the `SuperBlob` index.
#[derive(Debug, Clone)]
pub struct SuperBlobSlot {
    /// Slot type constant (`CS_SLOT`_*).
    pub slot_type: u32,
    /// Offset from the `SuperBlob` start to this blob's magic field.
    pub offset: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Full code-signature parse result
// ─────────────────────────────────────────────────────────────────────────────

/// Fully decoded code signature.
#[derive(Debug, Clone)]
pub struct CodeSignature {
    /// All slot index entries from the `SuperBlob`.
    pub slots: Vec<SuperBlobSlot>,
    /// Parsed `CodeDirectory`, if present.
    pub code_directory: Option<CodeDirectory>,
    /// Entitlements XML plist, if present.
    pub entitlements: Option<EntitlementsBlob>,
    /// Length of the DER entitlements blob in bytes (if present).
    pub der_entitlements_len: Option<usize>,
    /// Whether a CMS blob (`BlobWrapper` / PKCS#7) is present.
    pub has_cms: bool,
    /// Size of the CMS blob in bytes.
    pub cms_size: usize,
    /// Whether a `RequirementSet` blob is present.
    pub has_requirements: bool,
    /// Raw requirements blob bytes.
    pub requirements_blob: Option<RequirementBlob>,
    /// Heuristic: notarisation ticket / stapled notarisation detected.
    ///
    /// This is a simple size heuristic: a CMS blob > 2 KiB is very likely a
    /// real notarisation CMS signature rather than an ad-hoc stub.
    pub likely_notarised: bool,
}

impl CodeSignature {
    /// Slot name for display.
    #[must_use] 
    pub const fn slot_name(slot_type: u32) -> &'static str {
        match slot_type {
            CS_SLOT_CODEDIRECTORY  => "CodeDirectory",
            CS_SLOT_INFOSLOT       => "Info.plist",
            CS_SLOT_REQUIREMENTS   => "Requirements",
            CS_SLOT_RESOURCEDIR    => "ResourceDirectory",
            CS_SLOT_APPLICATION    => "Application",
            CS_SLOT_ENTITLEMENTS   => "Entitlements",
            CS_SLOT_DER_ENTITLEMENTS => "DER Entitlements",
            _                      => "unknown",
        }
    }

    /// Return the bundle identifier from the `CodeDirectory`.
    #[must_use] 
    pub fn bundle_identifier(&self) -> Option<&str> {
        self.code_directory.as_ref().map(|cd| cd.identifier.as_str())
    }

    /// Return the team identifier, if present.
    #[must_use] 
    pub fn team_id(&self) -> Option<&str> {
        self.code_directory.as_ref()?.team_id.as_deref()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Parser
// ─────────────────────────────────────────────────────────────────────────────

/// Parser for the code-signature blob pointed to by `LC_CODE_SIGNATURE`.
pub struct CodeSignParser;

impl CodeSignParser {
    /// Parse the entire code-signature `SuperBlob` from `data`.
    ///
    /// `data` must be the slice `[file[cs_offset .. cs_offset + cs_size]]`.
    pub fn parse(data: &[u8]) -> Result<CodeSignature, CodeSignError> {
        if data.len() < 8 {
            return Err(CodeSignError::TooShort("SuperBlob"));
        }
        let magic = rbe32(data, 0).unwrap();
        if magic != CSMAGIC_EMBEDDED_SIGNATURE && magic != CSMAGIC_DETACHED_SIGNATURE {
            return Err(CodeSignError::BadMagic { got: magic, expected: CSMAGIC_EMBEDDED_SIGNATURE });
        }
        let _total_length = rbe32(data, 4).unwrap_or(0);
        let count = rbe32(data, 8).unwrap_or(0);
        if count > 64 {
            return Err(CodeSignError::InvalidSlotCount(count));
        }

        // Parse the index (each entry is 8 bytes: type(4) + offset(4))
        let mut slots = Vec::with_capacity(count as usize);
        let index_base = 12usize;
        for i in 0..count as usize {
            let entry_off = index_base + i * 8;
            if entry_off + 8 > data.len() { break; }
            let slot_type = rbe32(data, entry_off).unwrap_or(0);
            let offset    = rbe32(data, entry_off + 4).unwrap_or(0);
            slots.push(SuperBlobSlot { slot_type, offset });
        }

        let mut code_directory       = None;
        let mut entitlements         = None;
        let mut der_entitlements_len = None;
        let mut has_cms              = false;
        let mut cms_size             = 0usize;
        let mut has_requirements     = false;
        let mut requirements_blob    = None;

        for slot in &slots {
            let off = slot.offset as usize;
            if off + 8 > data.len() { continue; }
            let blob_magic = rbe32(data, off).unwrap_or(0);
            let blob_len   = rbe32(data, off + 4).unwrap_or(0) as usize;
            let blob_end   = (off + blob_len).min(data.len());
            let blob       = &data[off..blob_end];

            match blob_magic {
                CSMAGIC_CODEDIRECTORY => {
                    if let Ok(cd) = CodeDirectory::parse(blob) {
                        code_directory = Some(cd);
                    }
                }
                CSMAGIC_ENTITLEMENTS => {
                    if let Ok(e) = EntitlementsBlob::parse(blob) {
                        entitlements = Some(e);
                    }
                }
                CSMAGIC_ENTITLEMENTS_DER => {
                    der_entitlements_len = Some(blob_len.saturating_sub(8));
                }
                CSMAGIC_BLOBWRAPPER => {
                    has_cms  = true;
                    cms_size = blob_len;
                }
                CSMAGIC_REQUIREMENTS => {
                    has_requirements = true;
                    if let Ok(rb) = RequirementBlob::parse(blob) {
                        requirements_blob = Some(rb);
                    }
                }
                _ => {}
            }
        }

        let likely_notarised = has_cms && cms_size > 2048;

        Ok(CodeSignature {
            slots,
            code_directory,
            entitlements,
            der_entitlements_len,
            has_cms,
            cms_size,
            has_requirements,
            requirements_blob,
            likely_notarised,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cd_with_flags(flags: u32) -> CodeDirectory {
        CodeDirectory {
            version: 0x0002_0100,
            flags,
            hash_offset: 0,
            ident_offset: 0,
            n_special_slots: 0,
            n_code_slots: 0,
            code_limit: 0,
            hash_size: 32,
            hash_type: CsHashType::Sha256,
            platform: 0,
            page_size: 12,
            spare2: 0,
            identifier: String::new(),
            team_id: None,
            special_hashes: Vec::new(),
        }
    }

    #[test]
    fn platform_binary_flag_is_not_get_task_allow() {
        // 0x4 is CS_GET_TASK_ALLOW — the process is debuggable. Reading it as
        // "Apple platform binary" inverts the security meaning, so the two must
        // never agree.
        assert!(
            !cd_with_flags(0x0000_0004).is_platform_binary(),
            "CS_GET_TASK_ALLOW must not be reported as a platform binary"
        );
        assert!(cd_with_flags(CS_PLATFORM_BINARY).is_platform_binary());
    }

    #[test]
    fn library_validation_flag_is_not_expiry_check() {
        // 0x400 is CS_CHECK_EXPIRATION, about certificate expiry, not library
        // validation. Conflating them reports a hardening property the binary
        // may not have.
        assert!(
            !cd_with_flags(CS_CHECK_EXPIRATION).requires_library_validation(),
            "CS_CHECK_EXPIRATION must not be read as Library Validation"
        );
        assert!(cd_with_flags(CS_REQUIRE_LV).requires_library_validation());
    }

    #[test]
    fn adhoc_and_hard_flags_are_independent() {
        let adhoc = cd_with_flags(CS_ADHOC);
        assert!(adhoc.is_adhoc() && !adhoc.is_hard());
        let hard = cd_with_flags(CS_HARD);
        assert!(hard.is_hard() && !hard.is_adhoc());
        assert!(!cd_with_flags(0).is_adhoc());
    }

    fn make_superblob_empty() -> Vec<u8> {
        let mut v = vec![0u8; 12];
        v[0..4].copy_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        v[4..8].copy_from_slice(&12u32.to_be_bytes()); // total length
        v[8..12].copy_from_slice(&0u32.to_be_bytes()); // count = 0
        v
    }

    #[test]
    fn superblob_empty_parses() {
        let data = make_superblob_empty();
        let cs = CodeSignParser::parse(&data).unwrap();
        assert!(cs.slots.is_empty());
        assert!(cs.code_directory.is_none());
        assert!(!cs.has_cms);
        assert!(!cs.likely_notarised);
    }

    #[test]
    fn superblob_bad_magic() {
        let mut data = make_superblob_empty();
        data[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        assert!(matches!(CodeSignParser::parse(&data), Err(CodeSignError::BadMagic { .. })));
    }

    #[test]
    fn superblob_too_short() {
        let data = [0u8; 4];
        assert!(matches!(CodeSignParser::parse(&data), Err(CodeSignError::TooShort(_))));
    }

    #[test]
    fn cs_hash_type_names() {
        assert_eq!(CsHashType::from_raw(1).name(), "SHA-1");
        assert_eq!(CsHashType::from_raw(2).name(), "SHA-256");
        assert_eq!(CsHashType::from_raw(4).name(), "SHA-384");
        assert_eq!(CsHashType::from_raw(99).name(), "unknown");
    }

    #[test]
    fn cs_hash_type_digest_len() {
        assert_eq!(CsHashType::Sha1.digest_len(), 20);
        assert_eq!(CsHashType::Sha256.digest_len(), 32);
        assert_eq!(CsHashType::Sha384.digest_len(), 48);
        assert_eq!(CsHashType::Sha512.digest_len(), 64);
    }

    #[test]
    fn codedirectory_bad_magic() {
        let mut blob = vec![0u8; 44];
        blob[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        blob[4..8].copy_from_slice(&44u32.to_be_bytes());
        assert!(matches!(CodeDirectory::parse(&blob), Err(CodeSignError::BadMagic { .. })));
    }

    #[test]
    fn codedirectory_minimum_parse() {
        let mut blob = vec![0u8; 44];
        blob[0..4].copy_from_slice(&CSMAGIC_CODEDIRECTORY.to_be_bytes());
        blob[4..8].copy_from_slice(&44u32.to_be_bytes());
        // version = 0x20000, hash_type = SHA-256 (2), hash_size = 32
        blob[8..12].copy_from_slice(&0x0002_0000u32.to_be_bytes());
        blob[37] = 2; // SHA-256
        blob[36] = 32;
        let cd = CodeDirectory::parse(&blob).unwrap();
        assert_eq!(cd.hash_type, CsHashType::Sha256);
        assert_eq!(cd.hash_size, 32);
        assert!(!cd.is_adhoc());
    }

    #[test]
    fn entitlements_bad_magic() {
        let mut blob = vec![0u8; 16];
        blob[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        blob[4..8].copy_from_slice(&16u32.to_be_bytes());
        assert!(matches!(EntitlementsBlob::parse(&blob), Err(CodeSignError::BadMagic { .. })));
    }

    #[test]
    fn entitlements_parse_xml() {
        let xml = b"<?xml version=\"1.0\"?>\
            <dict><key>com.apple.security.get-task-allow</key><true/></dict>";
        let mut blob = vec![0u8; 8 + xml.len()];
        blob[0..4].copy_from_slice(&CSMAGIC_ENTITLEMENTS.to_be_bytes());
        let len = 8u32 + xml.len() as u32;
        blob[4..8].copy_from_slice(&len.to_be_bytes());
        blob[8..].copy_from_slice(xml);
        let e = EntitlementsBlob::parse(&blob).unwrap();
        assert!(e.has_get_task_allow);
        assert!(!e.has_debugger);
    }

    #[test]
    fn requirement_blob_parse() {
        let mut blob = vec![0u8; 16];
        blob[0..4].copy_from_slice(&CSMAGIC_REQUIREMENTS.to_be_bytes());
        blob[4..8].copy_from_slice(&16u32.to_be_bytes());
        let rb = RequirementBlob::parse(&blob).unwrap();
        assert!(rb.is_requirements_set());
        assert!(!rb.is_single_requirement());
    }

    #[test]
    fn slot_names() {
        assert_eq!(CodeSignature::slot_name(CS_SLOT_CODEDIRECTORY), "CodeDirectory");
        assert_eq!(CodeSignature::slot_name(CS_SLOT_ENTITLEMENTS), "Entitlements");
        assert_eq!(CodeSignature::slot_name(0xFF), "unknown");
    }

    #[test]
    fn notarisation_heuristic() {
        let mut v = make_superblob_empty();
        v[8..12].copy_from_slice(&1u32.to_be_bytes()); // count = 1
        // extend to hold one slot entry + a fake CMS blob
        let cms_size: u32 = 3000;
        v.extend_from_slice(&CS_SLOT_CODEDIRECTORY.to_be_bytes()); // wrong type; use blobwrapper
        v.extend_from_slice(&0u32.to_be_bytes()); // placeholder for slot offset
        let cms_magic_field: [u8; 4] = CSMAGIC_BLOBWRAPPER.to_be_bytes();
        // slot offset points right after the 12-byte superblob header + 8-byte index
        let slot_offset: u32 = 12 + 8;
        v[12..16].copy_from_slice(&(CS_SLOT_CODEDIRECTORY + 0x100).to_be_bytes());
        v[16..20].copy_from_slice(&slot_offset.to_be_bytes());
        // add CMS blob at the slot offset (relative to data start = 0)
        // Current length = 12+8 = 20; we need to pad to slot_offset (=20)
        v.extend_from_slice(&cms_magic_field);
        v.extend_from_slice(&cms_size.to_be_bytes());
        let pad = vec![0u8; (cms_size - 8) as usize];
        v.extend_from_slice(&pad);
        // Update total length
        let total = v.len() as u32;
        v[4..8].copy_from_slice(&total.to_be_bytes());

        // Force the slot type to BLOBWRAPPER so the parser treats it as CMS
        v[12..16].copy_from_slice(&(0xFADE_0B01u32).to_be_bytes());

        let cs = CodeSignParser::parse(&v).unwrap();
        assert!(cs.has_cms);
        assert!(cs.likely_notarised);
    }
}
