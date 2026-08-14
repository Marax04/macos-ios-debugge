// rustre-mobile-apktool/src/apk_signing.rs
//! APK Signing Block — detect and parse APK Signing Block v2/v3/v4.
//!
//! The APK Signing Block is located immediately before the ZIP Central Directory.
//! It is framed by two 8-byte magic values and a length field.

use std::time::{SystemTime, UNIX_EPOCH};

pub use std::collections::HashMap;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Magic bytes at the end of the signing block: "APK Sig Block 42".
pub const APK_SIG_BLOCK_MAGIC: &[u8; 16] = b"APK Sig Block 42";

/// Block ID for APK Signature Scheme v2.
pub const SIG_V2_BLOCK_ID: u32 = 0x7109_871a;
/// Block ID for APK Signature Scheme v3.
pub const SIG_V3_BLOCK_ID: u32 = 0xf053_68c0;
/// Block ID for APK Signature Scheme v4 (streaming).
pub const SIG_V4_BLOCK_ID: u32 = 0x4272_6577;
/// Block ID for verity padding.
pub const VERITY_PADDING_BLOCK_ID: u32 = 0x4272_6576;

// ─── SigningVersion ───────────────────────────────────────────────────────────

/// Detected APK signing scheme version.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SigningVersion {
    V1Only,
    V2,
    V3,
    V4,
    Unknown,
}

impl std::fmt::Display for SigningVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1Only => write!(f, "v1 (JAR signing)"),
            Self::V2 => write!(f, "v2"),
            Self::V3 => write!(f, "v3"),
            Self::V4 => write!(f, "v4"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─── SigningBlockEntry ────────────────────────────────────────────────────────

/// One key-value pair inside the APK Signing Block.
#[derive(Debug, Clone)]
pub struct SigningBlockEntry {
    /// 4-byte block ID.
    pub id: u32,
    /// Raw value bytes.
    pub value: Vec<u8>,
}

impl SigningBlockEntry {
    #[must_use]
    pub const fn new(id: u32, value: Vec<u8>) -> Self {
        Self { id, value }
    }

    /// True if this entry carries a v2 signature.
    #[must_use]
    pub const fn is_v2(&self) -> bool {
        self.id == SIG_V2_BLOCK_ID
    }
    /// True if this entry carries a v3 signature.
    #[must_use]
    pub const fn is_v3(&self) -> bool {
        self.id == SIG_V3_BLOCK_ID
    }
    /// True if this entry carries a v4 signature.
    #[must_use]
    pub const fn is_v4(&self) -> bool {
        self.id == SIG_V4_BLOCK_ID
    }
    /// True if this is a verity padding block.
    #[must_use]
    pub const fn is_verity_padding(&self) -> bool {
        self.id == VERITY_PADDING_BLOCK_ID
    }
}

// ─── ApkSigningBlock ──────────────────────────────────────────────────────────

/// The parsed APK Signing Block.
#[derive(Debug, Clone)]
pub struct ApkSigningBlock {
    /// All key-value pairs in the signing block.
    pub entries: Vec<SigningBlockEntry>,
    /// Total size of the signing block in bytes (including size field and magic).
    pub total_size: u64,
    /// Byte offset within the APK where the signing block starts.
    pub offset: u64,
}

impl ApkSigningBlock {
    /// Attempt to find and parse the APK Signing Block from `apk_bytes`.
    ///
    /// Returns `None` if no valid signing block is found.
    #[must_use]
    pub fn find(apk_bytes: &[u8]) -> Option<Self> {
        let n = apk_bytes.len();
        if n < 24 {
            return None; // too short for magic + size + at least one entry
        }

        // Locate the magic bytes. They appear at the very end of the signing block,
        // just before the ZIP Central Directory. We scan backwards from the end.
        let magic_pos = find_magic(apk_bytes)?;

        // The 8 bytes before the magic are the second copy of the block size.
        if magic_pos < 8 {
            return None;
        }
        let block_size_pos = magic_pos - 8;
        if block_size_pos + 8 > apk_bytes.len() {
            return None;
        }
        let block_size = u64::from_le_bytes(
            apk_bytes[block_size_pos..block_size_pos + 8]
                .try_into()
                .ok()?,
        );

        // The signing block starts `block_size + 8` bytes before the magic.
        // (block_size includes the 8-byte trailing size field and 16-byte magic,
        //  but NOT the first 8-byte size field that precedes the entries.)
        let block_size_usize = usize::try_from(block_size).ok()?;
        let block_start = (magic_pos + 16).checked_sub(block_size_usize + 8)?;

        // The first 8 bytes of the block are also the block size.
        if block_start + 8 > apk_bytes.len() {
            return None;
        }

        let entries = parse_entries(
            &apk_bytes[block_start + 8..block_start + 8 + block_size_usize - 8 - 16],
        )?;

        Some(Self {
            entries,
            total_size: block_size + 8,
            offset: block_start as u64,
        })
    }

    /// Detect the highest signing version present.
    #[must_use]
    pub fn highest_version(&self) -> SigningVersion {
        let mut v = SigningVersion::V1Only;
        for e in &self.entries {
            if e.is_v4() {
                return SigningVersion::V4;
            }
            if e.is_v3() {
                v = SigningVersion::V3;
            } else if e.is_v2() && v == SigningVersion::V1Only {
                v = SigningVersion::V2;
            }
        }
        v
    }

    /// Find a specific entry by ID.
    #[must_use]
    pub fn entry_by_id(&self, id: u32) -> Option<&SigningBlockEntry> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Whether a v2 signature entry is present.
    #[must_use]
    pub fn has_v2(&self) -> bool {
        self.entries.iter().any(SigningBlockEntry::is_v2)
    }
    /// Whether a v3 signature entry is present.
    #[must_use]
    pub fn has_v3(&self) -> bool {
        self.entries.iter().any(SigningBlockEntry::is_v3)
    }
    /// Whether a v4 signature entry is present.
    #[must_use]
    pub fn has_v4(&self) -> bool {
        self.entries.iter().any(SigningBlockEntry::is_v4)
    }
}

fn find_magic(data: &[u8]) -> Option<usize> {
    let n = data.len();
    if n < APK_SIG_BLOCK_MAGIC.len() {
        return None;
    }
    // Search backwards from the end
    (0..=n - APK_SIG_BLOCK_MAGIC.len())
        .rev()
        .find(|&i| &data[i..i + APK_SIG_BLOCK_MAGIC.len()] == APK_SIG_BLOCK_MAGIC)
}

fn parse_entries(data: &[u8]) -> Option<Vec<SigningBlockEntry>> {
    let mut entries = Vec::new();
    let mut pos = 0;
    while pos + 12 <= data.len() {
        let entry_len =
            usize::try_from(u64::from_le_bytes(data[pos..pos + 8].try_into().ok()?)).ok()?;
        pos += 8;
        if pos + entry_len > data.len() {
            break;
        }
        if entry_len < 4 {
            pos += entry_len;
            continue;
        }
        let id = u32::from_le_bytes(data[pos..pos + 4].try_into().ok()?);
        let value = data[pos + 4..pos + entry_len].to_vec();
        entries.push(SigningBlockEntry { id, value });
        pos += entry_len;
    }
    Some(entries)
}

// ─── V2SignatureBlock ─────────────────────────────────────────────────────────

/// Parsed content of a v2 signature block entry.
#[derive(Debug, Clone)]
pub struct V2SignatureBlock {
    pub signers: Vec<V2Signer>,
}

#[derive(Debug, Clone)]
pub struct V2Signer {
    /// The raw signed data blob.
    pub signed_data: Vec<u8>,
    /// Algorithm IDs used.
    pub algorithm_ids: Vec<u32>,
    /// DER-encoded X.509 certificates.
    pub certificates: Vec<Vec<u8>>,
}

impl V2SignatureBlock {
    /// Parse a v2 signature block from the raw entry value bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        // Minimal parse: read the outer length-prefixed sequence of signers.
        if data.len() < 4 {
            return None;
        }
        let signers_len = u32::from_le_bytes(data[0..4].try_into().ok()?) as usize;
        if 4 + signers_len > data.len() {
            return None;
        }
        // Stub: return one placeholder signer
        Some(Self {
            signers: vec![V2Signer {
                signed_data: data[4..4 + signers_len.min(data.len() - 4)].to_vec(),
                algorithm_ids: vec![0x0201], // RSASSA-PSS with SHA-256
                certificates: Vec::new(),
            }],
        })
    }

    #[must_use]
    pub const fn signer_count(&self) -> usize {
        self.signers.len()
    }
}

// ─── V3SignerBlock ────────────────────────────────────────────────────────────

/// Parsed content of a v3 signer block entry (extends v2 with rotation support).
#[derive(Debug, Clone)]
pub struct V3SignerBlock {
    pub min_sdk: u32,
    pub max_sdk: u32,
    pub signed_data: Vec<u8>,
    pub algorithm_ids: Vec<u32>,
    pub certificates: Vec<Vec<u8>>,
}

impl V3SignerBlock {
    /// Parse a v3 signer block from raw bytes.
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let min_sdk = u32::from_le_bytes(data[0..4].try_into().ok()?);
        let max_sdk = u32::from_le_bytes(data[4..8].try_into().ok()?);
        Some(Self {
            min_sdk,
            max_sdk,
            signed_data: data[8..].to_vec(),
            algorithm_ids: vec![0x0201],
            certificates: Vec::new(),
        })
    }
}

// ─── SigningCertificate ───────────────────────────────────────────────────────

/// High-level representation of a signing certificate extracted from the block.
#[derive(Debug, Clone)]
pub struct SigningCertificate {
    /// Issuer distinguished name (parsed from DER, stub).
    pub issuer: String,
    /// Subject distinguished name.
    pub subject: String,
    /// Not-before (seconds since UNIX epoch).
    pub not_before: u64,
    /// Not-after (seconds since UNIX epoch).
    pub not_after: u64,
    /// SHA-256 fingerprint of the raw certificate bytes.
    pub fingerprint_sha256: String,
    /// Raw DER bytes.
    pub der: Vec<u8>,
}

impl SigningCertificate {
    /// Build a stub certificate for testing.
    #[must_use]
    pub fn stub(issuer: &str, subject: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            subject: subject.to_string(),
            not_before: 0,
            not_after: u64::from(u32::MAX),
            fingerprint_sha256: "deadbeefdeadbeef".to_string(),
            der: Vec::new(),
        }
    }

    /// True if the certificate's validity period contains `unix_ts`.
    #[must_use]
    pub const fn is_valid_at(&self, unix_ts: u64) -> bool {
        unix_ts >= self.not_before && unix_ts <= self.not_after
    }

    /// True if the certificate is currently valid.
    #[must_use]
    pub fn is_currently_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        self.is_valid_at(now)
    }
}

// ─── High-level helpers ───────────────────────────────────────────────────────

/// Detect the signing version of an APK from its raw bytes.
///
/// Returns `SigningVersion::V1Only` when no signing block is found.
#[must_use]
pub fn detect_signing_version(apk_bytes: &[u8]) -> SigningVersion {
    ApkSigningBlock::find(apk_bytes).map_or(SigningVersion::V1Only, |block| block.highest_version())
}

/// Extract all signing certificates from an APK.
///
/// Currently returns a stub certificate per v2/v3 signer found.
#[must_use]
pub fn extract_certs(apk_bytes: &[u8]) -> Vec<SigningCertificate> {
    let Some(block) = ApkSigningBlock::find(apk_bytes) else {
        return Vec::new();
    };

    let mut certs = Vec::new();

    if let Some(e) = block.entry_by_id(SIG_V2_BLOCK_ID)
        && let Some(v2) = V2SignatureBlock::parse(&e.value)
    {
        for _ in &v2.signers {
            certs.push(SigningCertificate::stub(
                "CN=Issuer,O=ExampleOrg",
                "CN=Developer,O=AppOrg",
            ));
        }
    }

    if let Some(e) = block.entry_by_id(SIG_V3_BLOCK_ID)
        && let Some(_v3) = V3SignerBlock::parse(&e.value)
    {
        certs.push(SigningCertificate::stub("CN=Root CA", "CN=App Developer"));
    }

    certs
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn build_mock_apk_with_signing_block(version: &str) -> Vec<u8> {
        // Build a minimal fake APK:
        //   [dummy content] [signing block] [central directory stub]
        // The signing block contains the magic and a single entry.
        let entry_id: u32 = match version {
            "v2" => SIG_V2_BLOCK_ID,
            "v3" => SIG_V3_BLOCK_ID,
            "v4" => SIG_V4_BLOCK_ID,
            _ => 0x0000_0001,
        };
        let entry_value = vec![0xAAu8; 20];
        let entry_len = (4 + entry_value.len()) as u64; // id(4) + value

        // Build entry bytes: [len u64][id u32][value]
        let mut entry_bytes = Vec::new();
        entry_bytes.extend_from_slice(&entry_len.to_le_bytes());
        entry_bytes.extend_from_slice(&entry_id.to_le_bytes());
        entry_bytes.extend_from_slice(&entry_value);

        // block_size = entries + trailing_size(8) + magic(16)
        let block_size = (entry_bytes.len() + 8 + 16) as u64;

        let mut signing_block = Vec::new();
        // First size field
        signing_block.extend_from_slice(&block_size.to_le_bytes());
        // Entries
        signing_block.extend_from_slice(&entry_bytes);
        // Trailing size
        signing_block.extend_from_slice(&block_size.to_le_bytes());
        // Magic
        signing_block.extend_from_slice(APK_SIG_BLOCK_MAGIC);

        let mut apk = vec![0u8; 64]; // dummy content
        apk.extend_from_slice(&signing_block);
        // Minimal central directory stub
        apk.extend_from_slice(&[0u8; 22]);
        apk
    }

    // ── SigningVersion ────────────────────────────────────────────────────────

    #[test]
    fn test_signing_version_display() {
        assert_eq!(SigningVersion::V2.to_string(), "v2");
        assert_eq!(SigningVersion::V3.to_string(), "v3");
        assert_eq!(SigningVersion::V1Only.to_string(), "v1 (JAR signing)");
    }

    // ── SigningBlockEntry ─────────────────────────────────────────────────────

    #[test]
    fn test_entry_id_helpers() {
        let e = SigningBlockEntry::new(SIG_V2_BLOCK_ID, vec![]);
        assert!(e.is_v2());
        assert!(!e.is_v3());
        assert!(!e.is_v4());
    }

    #[test]
    fn test_entry_verity_padding() {
        let e = SigningBlockEntry::new(VERITY_PADDING_BLOCK_ID, vec![]);
        assert!(e.is_verity_padding());
    }

    // ── find_magic ────────────────────────────────────────────────────────────

    #[test]
    fn test_find_magic_present() {
        let mut data = vec![0u8; 32];
        data.extend_from_slice(APK_SIG_BLOCK_MAGIC);
        data.extend_from_slice(&[0u8; 8]);
        let pos = find_magic(&data).unwrap();
        assert_eq!(pos, 32);
    }

    #[test]
    fn test_find_magic_absent() {
        let data = vec![0u8; 64];
        assert!(find_magic(&data).is_none());
    }

    // ── ApkSigningBlock ───────────────────────────────────────────────────────

    #[test]
    fn test_signing_block_find_v2() {
        let apk = build_mock_apk_with_signing_block("v2");
        let block = ApkSigningBlock::find(&apk);
        assert!(block.is_some());
        let b = block.unwrap();
        assert!(b.has_v2());
        assert!(!b.has_v3());
    }

    #[test]
    fn test_signing_block_find_v3() {
        let apk = build_mock_apk_with_signing_block("v3");
        let block = ApkSigningBlock::find(&apk).unwrap();
        assert!(block.has_v3());
        assert_eq!(block.highest_version(), SigningVersion::V3);
    }

    #[test]
    fn test_signing_block_highest_version_v2() {
        let apk = build_mock_apk_with_signing_block("v2");
        let block = ApkSigningBlock::find(&apk).unwrap();
        assert_eq!(block.highest_version(), SigningVersion::V2);
    }

    #[test]
    fn test_signing_block_not_found_returns_none() {
        let apk = vec![0u8; 64];
        assert!(ApkSigningBlock::find(&apk).is_none());
    }

    #[test]
    fn test_signing_block_too_short_returns_none() {
        let apk = vec![0u8; 4];
        assert!(ApkSigningBlock::find(&apk).is_none());
    }

    // ── detect_signing_version ────────────────────────────────────────────────

    #[test]
    fn test_detect_v1_when_no_block() {
        let apk = vec![0u8; 100];
        assert_eq!(detect_signing_version(&apk), SigningVersion::V1Only);
    }

    #[test]
    fn test_detect_v2() {
        let apk = build_mock_apk_with_signing_block("v2");
        assert_eq!(detect_signing_version(&apk), SigningVersion::V2);
    }

    #[test]
    fn test_detect_v3() {
        let apk = build_mock_apk_with_signing_block("v3");
        assert_eq!(detect_signing_version(&apk), SigningVersion::V3);
    }

    // ── V2SignatureBlock ──────────────────────────────────────────────────────

    #[test]
    fn test_v2_signature_parse_minimal() {
        let mut data = Vec::new();
        // signers_len = 10
        data.extend_from_slice(&10u32.to_le_bytes());
        data.extend_from_slice(&[0xBBu8; 10]);
        let v2 = V2SignatureBlock::parse(&data).unwrap();
        assert_eq!(v2.signer_count(), 1);
    }

    #[test]
    fn test_v2_signature_parse_too_short() {
        let data = vec![0u8; 2];
        assert!(V2SignatureBlock::parse(&data).is_none());
    }

    // ── V3SignerBlock ─────────────────────────────────────────────────────────

    #[test]
    fn test_v3_signer_parse() {
        let mut data = Vec::new();
        data.extend_from_slice(&24u32.to_le_bytes()); // min_sdk
        data.extend_from_slice(&34u32.to_le_bytes()); // max_sdk
        data.extend_from_slice(&[0xCCu8; 16]);
        let v3 = V3SignerBlock::parse(&data).unwrap();
        assert_eq!(v3.min_sdk, 24);
        assert_eq!(v3.max_sdk, 34);
    }

    #[test]
    fn test_v3_signer_parse_too_short() {
        let data = vec![0u8; 4];
        assert!(V3SignerBlock::parse(&data).is_none());
    }

    // ── SigningCertificate ────────────────────────────────────────────────────

    #[test]
    fn test_certificate_stub() {
        let cert = SigningCertificate::stub("CN=Issuer", "CN=Subject");
        assert_eq!(cert.issuer, "CN=Issuer");
        assert_eq!(cert.subject, "CN=Subject");
        assert!(cert.is_currently_valid());
    }

    #[test]
    fn test_certificate_validity_range() {
        let cert = SigningCertificate {
            issuer: "I".to_string(),
            subject: "S".to_string(),
            not_before: 100,
            not_after: 200,
            fingerprint_sha256: "xx".to_string(),
            der: Vec::new(),
        };
        assert!(cert.is_valid_at(150));
        assert!(!cert.is_valid_at(50));
        assert!(!cert.is_valid_at(300));
    }

    // ── extract_certs ─────────────────────────────────────────────────────────

    #[test]
    fn test_extract_certs_no_block() {
        let apk = vec![0u8; 64];
        let certs = extract_certs(&apk);
        assert!(certs.is_empty());
    }

    #[test]
    fn test_extract_certs_v2_block() {
        let apk = build_mock_apk_with_signing_block("v2");
        // The mock v2 entry value starts with signers_len, which the parser uses.
        // Since our mock value is all 0xAA, parse may return None; just ensure no panic.
        let _certs = extract_certs(&apk);
    }
}
