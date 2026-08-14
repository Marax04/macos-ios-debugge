//! `apk_signature_verifier` — Verify APK signatures.
//!
//! Supports:
//! - **v1** (JAR signing): parse `META-INF/*.SF` and `META-INF/*.RSA`/`*.DSA`
//!   manifest entries from the APK ZIP central directory.
//! - **v2/v3** (APK Signing Block): find and parse the APK Signing Block
//!   located between the last ZIP entry data and the Central Directory.
//! - **v4** (.idsig sidecar): basic structure validation.
//!
//! This module performs *structural* verification — it checks that the signing
//! structures are present and well-formed.  Full cryptographic verification of
//! signatures requires an RSA/EC library and is out of scope for this module.
//!
//! Reference: <https://source.android.com/security/apksigning>

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the APK signature verifier.
#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("APK Signing Block not found")]
    SigningBlockNotFound,
    #[error("APK Signing Block magic mismatch")]
    SigningBlockMagicMismatch,
    #[error("truncated data at offset {0:#x}")]
    Truncated(usize),
    #[error("invalid ZIP structure")]
    InvalidZip,
    #[error("no v1 signatures found (META-INF .SF files missing)")]
    NoV1Signatures,
    #[error("unsupported signature algorithm {0:#x}")]
    UnsupportedAlgorithm(u32),
    #[error("signature block pair length {0} exceeds data boundary")]
    PairLengthExceedsBounds(u64),
}

// ─────────────────────────────────────────────────────────────────────────────
// SignatureVersion
// ─────────────────────────────────────────────────────────────────────────────

/// APK signing scheme version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SignatureVersion {
    /// v1: JAR signing (META-INF/*.SF + META-INF/*.RSA/DSA/EC).
    V1,
    /// v2: APK Signature Block v2.
    V2,
    /// v3: APK Signature Block v3 with key rotation proof.
    V3,
    /// v4: .idsig sidecar file.
    V4,
}

impl fmt::Display for SignatureVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1 => write!(f, "v1"),
            Self::V2 => write!(f, "v2"),
            Self::V3 => write!(f, "v3"),
            Self::V4 => write!(f, "v4"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignatureAlgorithm
// ─────────────────────────────────────────────────────────────────────────────

/// Signature algorithm ID as used in the APK Signing Block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// RSA PKCS#1 with SHA-256 (ID 0x0101).
    RsaPkcs1v15WithSha256,
    /// RSA PKCS#1 with SHA-512 (ID 0x0102).
    RsaPkcs1v15WithSha512,
    /// RSA PSS with SHA-256 and 32-byte salt (ID 0x0103).
    RsaPssWithSha256,
    /// RSA PSS with SHA-512 and 64-byte salt (ID 0x0104).
    RsaPssWithSha512,
    /// ECDSA with SHA-256 (ID 0x0201).
    EcdsaWithSha256,
    /// ECDSA with SHA-512 (ID 0x0202).
    EcdsaWithSha512,
    /// DSA with SHA-256 (ID 0x0301).
    DsaWithSha256,
    /// Unknown algorithm.
    Unknown(u32),
}

impl SignatureAlgorithm {
    /// Decode a 32-bit algorithm ID.
    #[must_use]
    pub const fn from_id(id: u32) -> Self {
        match id {
            0x0101 => Self::RsaPkcs1v15WithSha256,
            0x0102 => Self::RsaPkcs1v15WithSha512,
            0x0103 => Self::RsaPssWithSha256,
            0x0104 => Self::RsaPssWithSha512,
            0x0201 => Self::EcdsaWithSha256,
            0x0202 => Self::EcdsaWithSha512,
            0x0301 => Self::DsaWithSha256,
            other => Self::Unknown(other),
        }
    }

    /// Human-readable name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::RsaPkcs1v15WithSha256 => "RSA-PKCS1v15-SHA256",
            Self::RsaPkcs1v15WithSha512 => "RSA-PKCS1v15-SHA512",
            Self::RsaPssWithSha256 => "RSA-PSS-SHA256",
            Self::RsaPssWithSha512 => "RSA-PSS-SHA512",
            Self::EcdsaWithSha256 => "ECDSA-SHA256",
            Self::EcdsaWithSha512 => "ECDSA-SHA512",
            Self::DsaWithSha256 => "DSA-SHA256",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// V1SignatureFile
// ─────────────────────────────────────────────────────────────────────────────

/// One `META-INF/*.SF` entry found in the APK's central directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct V1SignatureFile {
    /// File name inside the APK (e.g. `META-INF/CERT.SF`).
    pub sf_name: String,
    /// Paired certificate block file (`.RSA`, `.DSA`, or `.EC`).
    pub cert_name: Option<String>,
    /// Whether the pairing was found.
    pub has_cert: bool,
    /// Compressed size of the `.SF` file in the ZIP.
    pub sf_compressed_size: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// ApkSigningBlockPair
// ─────────────────────────────────────────────────────────────────────────────

/// One ID-value pair from the APK Signing Block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApkSigningBlockPair {
    /// Block ID (e.g. 0x7109871a = v2, 0xF05368C0 = v3).
    pub id: u32,
    /// Byte length of the value.
    pub value_len: usize,
    /// First 32 bytes of the value (for identification / debug).
    pub value_prefix: Vec<u8>,
}

impl ApkSigningBlockPair {
    /// Returns `true` if this pair carries a v2 signature block.
    #[must_use]
    pub const fn is_v2(&self) -> bool {
        self.id == 0x7109_871a
    }

    /// Returns `true` if this pair carries a v3 signature block.
    #[must_use]
    pub const fn is_v3(&self) -> bool {
        self.id == 0xF053_68C0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SignatureBlock
// ─────────────────────────────────────────────────────────────────────────────

/// Parsed APK Signing Block (v2/v3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureBlock {
    /// Byte offset of the block in the APK.
    pub offset: usize,
    /// Total size of the block in bytes (excluding the final 8-byte size field).
    pub block_size: u64,
    /// All ID-value pairs found inside the block.
    pub pairs: Vec<ApkSigningBlockPair>,
    /// Whether a v2 signature pair was found.
    pub has_v2: bool,
    /// Whether a v3 signature pair was found.
    pub has_v3: bool,
}

impl SignatureBlock {
    /// Return all algorithm IDs extracted from the first v2/v3 pair value.
    ///
    /// Full parsing of the `signer` structure is complex; this returns a best-
    /// effort list of algorithm IDs found in the first 256 bytes of the block.
    #[must_use]
    pub fn heuristic_algorithm_ids(&self) -> Vec<SignatureAlgorithm> {
        let known_ids: &[u32] = &[0x0101, 0x0102, 0x0103, 0x0104, 0x0201, 0x0202, 0x0301];
        let mut found = Vec::new();
        for pair in &self.pairs {
            if pair.is_v2() || pair.is_v3() {
                for &kid in known_ids {
                    let bytes = kid.to_le_bytes();
                    if pair.value_prefix.windows(4).any(|w| w == bytes) {
                        found.push(SignatureAlgorithm::from_id(kid));
                    }
                }
            }
        }
        found.dedup_by_key(|a| a.name());
        found
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VerificationReport
// ─────────────────────────────────────────────────────────────────────────────

/// Summary of signature verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Scheme versions detected in this APK.
    pub versions: Vec<SignatureVersion>,
    /// v1 signature files (if any).
    pub v1_files: Vec<V1SignatureFile>,
    /// Parsed APK Signing Block (v2/v3), if present.
    pub signing_block: Option<SignatureBlock>,
    /// Detected signature algorithms.
    pub algorithms: Vec<String>,
    /// Whether at least one valid structure was found.
    pub structurally_valid: bool,
    /// Human-readable notes.
    pub notes: Vec<String>,
}

impl VerificationReport {
    /// Returns the highest signing scheme version detected.
    #[must_use]
    pub fn max_version(&self) -> Option<SignatureVersion> {
        self.versions.iter().copied().max()
    }

    /// Returns `true` when at least v2 signing was detected.
    #[must_use]
    pub fn has_v2_or_higher(&self) -> bool {
        self.versions.iter().any(|v| *v >= SignatureVersion::V2)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ApkSignatureVerifier
// ─────────────────────────────────────────────────────────────────────────────

/// Structural APK signature verifier.
///
/// Parses the APK ZIP central directory and APK Signing Block to produce a
/// [`VerificationReport`] without requiring a cryptographic library.
///
/// # Usage
/// ```rust,ignore
/// let apk_bytes = std::fs::read("app.apk").unwrap();
/// let verifier = ApkSignatureVerifier::new();
/// let report = verifier.verify_apk(&apk_bytes).unwrap();
/// println!("max version: {:?}", report.max_version());
/// ```
#[derive(Debug, Clone, Default)]
pub struct ApkSignatureVerifier;

impl ApkSignatureVerifier {
    /// Create a new verifier.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Verify an APK byte buffer and return a [`VerificationReport`].
    ///
    /// # Errors
    /// Returns `SignatureError::InvalidZip` when the ZIP structure is absent.
    pub fn verify_apk(&self, data: &[u8]) -> Result<VerificationReport, SignatureError> {
        if data.len() < 22 {
            return Err(SignatureError::InvalidZip);
        }

        let eocd_off = Self::find_eocd(data).ok_or(SignatureError::InvalidZip)?;
        let (cd_off, _cd_count) = Self::read_eocd(data, eocd_off)?;

        let v1_files = Self::scan_v1_signatures(data, cd_off, eocd_off);
        let signing_block = Self::find_signing_block(data, cd_off);

        let mut versions = Vec::new();
        if !v1_files.is_empty() {
            versions.push(SignatureVersion::V1);
        }
        let mut algorithms = Vec::new();
        if let Some(ref blk) = signing_block {
            if blk.has_v2 {
                versions.push(SignatureVersion::V2);
            }
            if blk.has_v3 {
                versions.push(SignatureVersion::V3);
            }
            for algo in blk.heuristic_algorithm_ids() {
                algorithms.push(algo.to_string());
            }
        }

        versions.sort();
        versions.dedup();

        let structurally_valid = !versions.is_empty();
        let mut notes = Vec::new();
        if !structurally_valid {
            notes.push("No signature structures found; APK may be unsigned.".to_string());
        }
        if versions.contains(&SignatureVersion::V1) && !versions.contains(&SignatureVersion::V2) {
            notes.push("Only v1 signatures found; v2/v3 provide stronger integrity guarantees.".to_string());
        }

        Ok(VerificationReport {
            versions,
            v1_files,
            signing_block,
            algorithms,
            structurally_valid,
            notes,
        })
    }

    // ── ZIP helpers ───────────────────────────────────────────────────────────

    fn find_eocd(data: &[u8]) -> Option<usize> {
        let sig = [0x50, 0x4B, 0x05, 0x06];
        data.windows(4).rposition(|w| w == sig)
    }

    fn read_eocd(data: &[u8], eocd: usize) -> Result<(usize, usize), SignatureError> {
        if eocd + 22 > data.len() {
            return Err(SignatureError::Truncated(eocd));
        }
        let cd_count = u16::from_le_bytes([data[eocd + 8], data[eocd + 9]]) as usize;
        let cd_off = u32::from_le_bytes([
            data[eocd + 16], data[eocd + 17],
            data[eocd + 18], data[eocd + 19],
        ]) as usize;
        Ok((cd_off, cd_count))
    }

    fn read_central_dir_entries(data: &[u8], cd_off: usize, end: usize) -> Vec<(String, u32)> {
        let mut entries = Vec::new();
        let mut pos = cd_off;
        while pos + 46 <= end && pos + 46 <= data.len() {
            if data[pos..pos+4] != [0x50, 0x4B, 0x01, 0x02] {
                break;
            }
            let fname_len = u16::from_le_bytes([data[pos+28], data[pos+29]]) as usize;
            let extra_len = u16::from_le_bytes([data[pos+30], data[pos+31]]) as usize;
            let comment_len = u16::from_le_bytes([data[pos+32], data[pos+33]]) as usize;
            let comp_size = u32::from_le_bytes([data[pos+20], data[pos+21], data[pos+22], data[pos+23]]);
            let name_start = pos + 46;
            let name_end = name_start + fname_len;
            if name_end > data.len() {
                break;
            }
            let name = String::from_utf8_lossy(&data[name_start..name_end]).into_owned();
            entries.push((name, comp_size));
            pos = name_end + extra_len + comment_len;
        }
        entries
    }

    // ── v1 scanning ───────────────────────────────────────────────────────────

    fn scan_v1_signatures(
        data: &[u8],
        cd_off: usize,
        eocd_off: usize,
    ) -> Vec<V1SignatureFile> {
        let entries = Self::read_central_dir_entries(data, cd_off, eocd_off);

        // Build set of cert names
        let cert_names: HashMap<String, String> = entries
            .iter()
            .filter(|(n, _)| {
                if !n.starts_with("META-INF/") { return false; }
                let ext = std::path::Path::new(n.as_str())
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("");
                ext.eq_ignore_ascii_case("RSA") || ext.eq_ignore_ascii_case("DSA") || ext.eq_ignore_ascii_case("EC")
            })
            .map(|(n, _)| {
                let stem = n.trim_start_matches("META-INF/")
                    .trim_end_matches(".RSA")
                    .trim_end_matches(".DSA")
                    .trim_end_matches(".EC");
                (stem.to_string(), n.clone())
            })
            .collect();

        entries
            .iter()
            .filter(|(n, _)| n.starts_with("META-INF/") && n.to_ascii_uppercase().ends_with(".SF"))
            .cloned()
            .map(|(sf_name, sf_compressed_size)| {
                let stem = sf_name.trim_start_matches("META-INF/").trim_end_matches(".SF");
                let cert_name = cert_names.get(stem).cloned();
                let has_cert = cert_name.is_some();
                V1SignatureFile { sf_name, cert_name, has_cert, sf_compressed_size }
            })
            .collect()
    }

    // ── v2/v3 APK Signing Block ───────────────────────────────────────────────

    fn find_signing_block(data: &[u8], cd_off: usize) -> Option<SignatureBlock> {
        // The APK Signing Block ends at `cd_off`. The 16-byte magic
        // `"APK Sig Block 42"` is at `cd_off - 16 - 8` (before the 8-byte
        // block-size footer).
        if cd_off < 24 {
            return None;
        }
        let magic_off = cd_off - 16;
        let magic = b"APK Sig Block 42";
        if &data[magic_off..cd_off] != magic {
            return None;
        }

        // Read the block size from the 8 bytes immediately before the magic
        let size_off = magic_off - 8;
        if size_off + 8 > data.len() {
            return None;
        }
        let block_size = u64::from_le_bytes([
            data[size_off], data[size_off+1], data[size_off+2], data[size_off+3],
            data[size_off+4], data[size_off+5], data[size_off+6], data[size_off+7],
        ]);

        // Block starts at cd_off - block_size - 8 (not counting the magic).
        let block_start = cd_off.checked_sub(usize::try_from(block_size).unwrap_or(usize::MAX).saturating_add(8))?;
        if block_start + 8 > data.len() {
            return None;
        }

        // Parse ID-value pairs
        let pairs = Self::parse_signing_block_pairs(data, block_start, magic_off.saturating_sub(8));
        let has_v2 = pairs.iter().any(ApkSigningBlockPair::is_v2);
        let has_v3 = pairs.iter().any(ApkSigningBlockPair::is_v3);

        Some(SignatureBlock {
            offset: block_start,
            block_size,
            pairs,
            has_v2,
            has_v3,
        })
    }

    fn parse_signing_block_pairs(
        data: &[u8],
        start: usize,
        end: usize,
    ) -> Vec<ApkSigningBlockPair> {
        let mut pairs = Vec::new();
        // Skip the block-size prefix (8 bytes)
        let mut pos = start + 8;
        while pos + 12 <= end && pos + 12 <= data.len() {
            let pair_len = u64::from_le_bytes([
                data[pos], data[pos+1], data[pos+2], data[pos+3],
                data[pos+4], data[pos+5], data[pos+6], data[pos+7],
            ]);
            if pair_len < 4 {
                break;
            }
            let id = u32::from_le_bytes([data[pos+8], data[pos+9], data[pos+10], data[pos+11]]);
            let value_start = pos + 12;
            let value_len = usize::try_from(pair_len - 4).unwrap_or(usize::MAX);
            // `value_len` comes straight from a u64 in the file, so this addition
            // wraps in release builds and yields an end BELOW `value_start`, which
            // then survives the `.min` chain and panics on the slice.
            // `rustre-fuzz-net::decode_frame_u32_le` saturates for the same reason.
            let value_end = value_start.saturating_add(value_len);

            let prefix_end = value_end.min(value_start + 32).min(data.len());
            let value_prefix = data[value_start..prefix_end].to_vec();

            pairs.push(ApkSigningBlockPair { id, value_len, value_prefix });

            // Same wrap as above: unchecked, a huge `pair_len` sends `next` back
            // BELOW the buffer instead of past it, and the `next <= pos` guard —
            // written for exactly this — is defeated because the wrapped value can
            // still land ahead of `pos`, so the walk resumes on garbage.
            let Some(next) = pos
                .checked_add(8)
                .and_then(|v| v.checked_add(usize::try_from(pair_len).unwrap_or(usize::MAX)))
            else {
                break;
            };
            if next <= pos {
                break;
            }
            pos = next;
        }
        pairs
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// verify_apk() — convenience function
// ─────────────────────────────────────────────────────────────────────────────

/// Convenience wrapper around [`ApkSignatureVerifier::verify_apk`].
///
/// # Errors
/// Returns `SignatureError::InvalidZip` when the file has no ZIP structure.
pub fn verify_apk(data: &[u8]) -> Result<VerificationReport, SignatureError> {
    ApkSignatureVerifier::new().verify_apk(data)
}

/// Check whether `data` contains any APK signing structures.
#[must_use]
pub fn has_any_signature(data: &[u8]) -> bool {
    verify_apk(data).is_ok_and(|r| r.structurally_valid)
}

/// Return the highest signing version present in `data`, or `None` if unsigned.
#[must_use]
pub fn detect_max_version(data: &[u8]) -> Option<SignatureVersion> {
    verify_apk(data).ok().and_then(|r| r.max_version())
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        // Build a minimal valid ZIP with the given entries (all stored/no compression)
        let mut local_data: Vec<u8> = Vec::new();
        let mut cd_entries: Vec<u8> = Vec::new();
        let mut offsets: Vec<u32> = Vec::new();

        for (name, content) in files {
            let name_bytes = name.as_bytes();
            offsets.push(u32::try_from(local_data.len()).unwrap());
            // Local file header
            local_data.extend_from_slice(b"PK\x03\x04");
            local_data.extend_from_slice(&[0x0A, 0x00]); // version
            local_data.extend_from_slice(&[0u8; 4]);     // flags + compression
            local_data.extend_from_slice(&[0u8; 4]);     // mod time + date
            local_data.extend_from_slice(&[0u8; 4]);     // crc
            let csize = u32::try_from(content.len()).unwrap();
            local_data.extend_from_slice(&csize.to_le_bytes());
            local_data.extend_from_slice(&csize.to_le_bytes());
            local_data.extend_from_slice(&u16::try_from(name_bytes.len()).unwrap().to_le_bytes());
            local_data.extend_from_slice(&[0u8; 2]); // extra
            local_data.extend_from_slice(name_bytes);
            local_data.extend_from_slice(content);
        }

        let cd_off = u32::try_from(local_data.len()).unwrap();
        for (i, (name, content)) in files.iter().enumerate() {
            let name_bytes = name.as_bytes();
            cd_entries.extend_from_slice(b"PK\x01\x02");
            cd_entries.extend_from_slice(&[0u8; 4]); // version
            cd_entries.extend_from_slice(&[0u8; 4]); // flags + compression
            cd_entries.extend_from_slice(&[0u8; 4]); // mod time
            cd_entries.extend_from_slice(&[0u8; 4]); // crc
            let csize = u32::try_from(content.len()).unwrap();
            cd_entries.extend_from_slice(&csize.to_le_bytes());
            cd_entries.extend_from_slice(&csize.to_le_bytes());
            cd_entries.extend_from_slice(&u16::try_from(name_bytes.len()).unwrap().to_le_bytes());
            cd_entries.extend_from_slice(&[0u8; 2]); // extra
            cd_entries.extend_from_slice(&[0u8; 2]); // comment
            cd_entries.extend_from_slice(&[0u8; 4]); // disk + attrs
            cd_entries.extend_from_slice(&[0u8; 4]); // internal attrs
            cd_entries.extend_from_slice(&offsets[i].to_le_bytes());
            cd_entries.extend_from_slice(name_bytes);
        }

        let mut out = local_data;
        out.extend_from_slice(&cd_entries);
        let cd_size = u32::try_from(cd_entries.len()).unwrap();
        let count = u16::try_from(files.len()).unwrap();
        // EOCD
        out.extend_from_slice(b"PK\x05\x06");
        out.extend_from_slice(&[0u8; 4]); // disk info
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_off.to_le_bytes());
        out.extend_from_slice(&[0u8; 2]); // comment len
        out
    }

    #[test]
    fn test_unsigned_apk_no_versions() {
        let zip = minimal_zip(&[("classes.dex", b"dex\n035\0")]);
        let report = verify_apk(&zip).unwrap();
        assert!(!report.structurally_valid);
        assert!(report.versions.is_empty());
    }

    #[test]
    fn test_v1_signature_detected() {
        let zip = minimal_zip(&[
            ("classes.dex", b"dex\n035\0"),
            ("META-INF/CERT.SF", b"Signature-Version: 1.0\r\n"),
            ("META-INF/CERT.RSA", b"\x30\x82\x01\x00"),
        ]);
        let report = verify_apk(&zip).unwrap();
        assert!(report.versions.contains(&SignatureVersion::V1));
        assert!(!report.v1_files.is_empty());
        assert!(report.v1_files[0].has_cert);
    }

    #[test]
    fn test_v1_sf_without_cert() {
        let zip = minimal_zip(&[
            ("META-INF/NOCERT.SF", b"Signature-Version: 1.0\r\n"),
        ]);
        let report = verify_apk(&zip).unwrap();
        assert!(report.versions.contains(&SignatureVersion::V1));
        assert!(!report.v1_files[0].has_cert);
    }

    #[test]
    fn test_invalid_zip_returns_error() {
        let data = vec![0u8; 10];
        assert!(verify_apk(&data).is_err());
    }

    #[test]
    fn test_has_any_signature_false_for_unsigned() {
        let zip = minimal_zip(&[("classes.dex", b"dex\n035\0")]);
        assert!(!has_any_signature(&zip));
    }

    #[test]
    fn test_detect_max_version_none_for_unsigned() {
        let zip = minimal_zip(&[("classes.dex", b"dex\n035\0")]);
        assert!(detect_max_version(&zip).is_none());
    }

    #[test]
    fn test_signature_algorithm_from_id() {
        let a = SignatureAlgorithm::from_id(0x0201);
        assert_eq!(a.name(), "ECDSA-SHA256");
    }

    #[test]
    fn test_signature_algorithm_unknown() {
        let a = SignatureAlgorithm::from_id(0xFFFF);
        assert_eq!(a.name(), "Unknown");
    }

    #[test]
    fn test_signature_version_ordering() {
        assert!(SignatureVersion::V3 > SignatureVersion::V1);
        assert!(SignatureVersion::V2 > SignatureVersion::V1);
    }

    #[test]
    fn test_verification_report_max_version() {
        let report = VerificationReport {
            versions: vec![SignatureVersion::V1, SignatureVersion::V2],
            v1_files: vec![],
            signing_block: None,
            algorithms: vec![],
            structurally_valid: true,
            notes: vec![],
        };
        assert_eq!(report.max_version(), Some(SignatureVersion::V2));
        assert!(report.has_v2_or_higher());
    }

    #[test]
    fn test_verification_report_empty_versions() {
        let report = VerificationReport {
            versions: vec![],
            v1_files: vec![],
            signing_block: None,
            algorithms: vec![],
            structurally_valid: false,
            notes: vec![],
        };
        assert!(report.max_version().is_none());
        assert!(!report.has_v2_or_higher());
    }

    #[test]
    fn test_signing_block_pair_flags() {
        let pair_v2 = ApkSigningBlockPair {
            id: 0x7109_871a, value_len: 100, value_prefix: vec![],
        };
        let pair_v3 = ApkSigningBlockPair {
            id: 0xF053_68C0, value_len: 100, value_prefix: vec![],
        };
        assert!(pair_v2.is_v2());
        assert!(!pair_v2.is_v3());
        assert!(pair_v3.is_v3());
        assert!(!pair_v3.is_v2());
    }

    #[test]
    fn test_signing_block_pair_len_near_u64_max_does_not_panic() {
        // A pair whose declared length is close to u64::MAX. `value_start + value_len`
        // wraps in release builds and lands BELOW value_start; the `.min` chain keeps
        // that wrapped value, so the slice used to start after it ended.
        let mut data = vec![0u8; 8]; // block-size prefix the parser skips
        data.extend_from_slice(&(u64::MAX - 3).to_le_bytes()); // pair_len
        data.extend_from_slice(&0xdead_beefu32.to_le_bytes()); // id
        data.extend_from_slice(&[0xAA; 16]); // some value bytes
        let end = data.len();
        let pairs = ApkSignatureVerifier::parse_signing_block_pairs(&data, 0, end);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].id, 0xdead_beef);
        // Only what the buffer really holds may be captured.
        assert!(pairs[0].value_prefix.len() <= 16);
    }
}
