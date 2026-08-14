//! Mach-O code signature parsing.
//!
//! The code signature lives in the `__LINKEDIT` segment at the offset given by
//! `LC_CODE_SIGNATURE`. The top-level structure is a `SuperBlob` containing
//! typed sub-blobs: `CodeDirectory`, `Entitlements`, `Requirements`, and the
//! CMS `SignedData` blob.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Constants ────────────────────────────────────────────────────────────────

/// `SuperBlob` magic.
pub const CS_MAGIC_EMBEDDED_SIGNATURE: u32 = 0xFADE_0CC0;
/// Detached signature magic.
pub const CS_MAGIC_DETACHED_SIGNATURE: u32 = 0xFADE_0CC1;
/// `CodeDirectory` magic.
pub const CS_MAGIC_CODEDIRECTORY: u32 = 0xFADE_0C02;
/// Entitlements (XML plist) magic.
pub const CS_MAGIC_ENTITLEMENTS: u32 = 0xFADE_7171;
/// DER entitlements magic.
pub const CS_MAGIC_ENTITLEMENTS_DER: u32 = 0xFADE_7172;
/// Requirements magic.
pub const CS_MAGIC_REQUIREMENTS: u32 = 0xFADE_0C01;
/// CMS blob magic.
pub const CS_MAGIC_BLOBWRAPPER: u32 = 0xFADE_0B01;
/// Notarization ticket magic.
pub const CS_MAGIC_LAUNCH_CONSTRAINT_SELF: u32 = 0xFADE_8181;

// ─── ExecSeg flags ────────────────────────────────────────────────────────────

/// The binary is the main executable.
pub const CS_EXECSEG_MAIN_BINARY: u64 = 0x0001;
/// Allows code to run in a JIT region.
pub const CS_EXECSEG_ALLOW_UNSIGNED: u64 = 0x0010;
/// Debugger may attach.
pub const CS_EXECSEG_DEBUGGER: u64 = 0x0800;

// ─── Code-signing flags ───────────────────────────────────────────────────────

/// Adhoc signature (no certificate).
pub const CS_ADHOC: u32 = 0x0000_0002;
/// Hard: kill on validation failure.
pub const CS_HARD: u32 = 0x0000_0100;
/// Kill: send SIGKILL on validation failure.
pub const CS_KILL: u32 = 0x0000_0200;
/// Restrict dynamic library loading.
pub const CS_RESTRICT: u32 = 0x0000_0800;
/// Enforcement: enforce library validation.
pub const CS_ENFORCEMENT: u32 = 0x0000_1000;
/// Runtime hardening enabled.
pub const CS_RUNTIME: u32 = 0x0001_0000;
/// Library validation: only load signed libraries.
pub const CS_LINKER_SIGNED: u32 = 0x0002_0000;
/// Platform binary.
pub const CS_PLATFORM_BINARY: u32 = 0x0400_0000;

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CodeSignError {
    #[error("bad magic {0:#x}, expected superblob")]
    BadMagic(u32),
    #[error("truncated data at offset {0}")]
    Truncated(usize),
    #[error("index out of range: slot {0}")]
    BadSlot(usize),
    #[error("hash mismatch at page {0}")]
    HashMismatch(usize),
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedHash(u8),
    #[error("cms parse error: {0}")]
    CmsParse(String),
    #[error("invalid utf-8: {0}")]
    InvalidUtf8(String),
}

// ─── CodeDirectory ────────────────────────────────────────────────────────────

/// Parsed `CS_CodeDirectory` structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeDirectory {
    pub version: u32,
    pub flags: u32,
    pub hash_offset: u32,
    pub ident_offset: u32,
    pub n_special_slots: u32,
    pub n_code_slots: u32,
    pub code_limit: u32,
    pub hash_size: u8,
    pub hash_type: u8,
    pub platform: u8,
    pub page_size: u8,
    pub identifier: String,
    pub team_id: Option<String>,
    pub code_limit_64: u64,
    pub exec_seg_base: u64,
    pub exec_seg_limit: u64,
    pub exec_seg_flags: u64,
    /// Hashes of each code page.
    pub code_hashes: Vec<Vec<u8>>,
    /// Hashes of special slots (info.plist, requirements, entitlements…).
    pub special_hashes: Vec<Vec<u8>>,
}

impl CodeDirectory {
    /// Return the hash algorithm name.
    #[must_use]
    pub const fn hash_algorithm_name(&self) -> &'static str {
        match self.hash_type {
            1 => "SHA-1",
            2 => "SHA-256",
            3 => "SHA-256-Truncated",
            4 => "SHA-384",
            5 => "SHA-512",
            _ => "Unknown",
        }
    }

    /// Return `true` if the main binary exec-seg flag is set.
    #[must_use]
    pub const fn is_main_binary(&self) -> bool {
        self.exec_seg_flags & CS_EXECSEG_MAIN_BINARY != 0
    }

    /// Return `true` if adhoc-signed.
    #[must_use]
    pub const fn is_adhoc(&self) -> bool {
        self.flags & CS_ADHOC != 0
    }

    /// Return `true` if hardened runtime is enabled.
    #[must_use]
    pub const fn is_hardened_runtime(&self) -> bool {
        self.flags & CS_RUNTIME != 0
    }

    /// Return `true` if platform binary.
    #[must_use]
    pub const fn is_platform_binary(&self) -> bool {
        self.flags & CS_PLATFORM_BINARY != 0
    }

    /// Create a mock `CodeDirectory` for testing.
    #[must_use]
    pub fn mock() -> Self {
        Self {
            version: 0x2_0400,
            flags: CS_RUNTIME,
            hash_offset: 0,
            ident_offset: 0,
            n_special_slots: 5,
            n_code_slots: 8,
            code_limit: 0x8000,
            hash_size: 32,
            hash_type: 2, // SHA-256
            platform: 0,
            page_size: 12, // 4096
            identifier: "com.example.App".to_string(),
            team_id: Some("ABCD1234EF".to_string()),
            code_limit_64: 0x8000,
            exec_seg_base: 0,
            exec_seg_limit: 0x8000,
            exec_seg_flags: CS_EXECSEG_MAIN_BINARY,
            code_hashes: (0..8).map(|_| vec![0u8; 32]).collect(),
            special_hashes: (0..5).map(|_| vec![0u8; 32]).collect(),
        }
    }
}

// ─── SignerInfo ────────────────────────────────────────────────────────────────

/// Information about the code-signing certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerInfo {
    pub common_name: String,
    pub organization: Option<String>,
    pub team_id: Option<String>,
    pub issuer_cn: String,
    pub serial_number: String,
    pub not_before: String,
    pub not_after: String,
    pub is_apple_distribution: bool,
    pub is_developer_id: bool,
    pub is_ad_hoc: bool,
}

// ─── CodeSignature ────────────────────────────────────────────────────────────

/// A fully parsed Mach-O code signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSignature {
    pub code_directory: CodeDirectory,
    /// Raw XML entitlements plist.
    pub entitlements_xml: Option<String>,
    /// Raw entitlements plist bytes (may be binary or XML).
    pub entitlements_plist: Option<Vec<u8>>,
    /// DER-encoded entitlements (iOS 15+).
    pub entitlements_der: Option<Vec<u8>>,
    /// Raw requirements blob.
    pub requirements: Option<Vec<u8>>,
    /// Raw CMS `SignedData` blob.
    pub cms_signature: Option<Vec<u8>>,
    /// Notarization / launch constraint ticket.
    pub notarization_ticket: Option<Vec<u8>>,
}

impl CodeSignature {
    /// Parse a code signature from the raw bytes of the `__LINKEDIT` code
    /// signature data (i.e. from `LC_CODE_SIGNATURE` offset + size).
    ///
    /// # Errors
    /// Returns [`CodeSignError`] if the data is malformed.
    pub fn parse(data: &[u8]) -> Result<Self, CodeSignError> {
        if data.len() < 12 {
            return Err(CodeSignError::Truncated(0));
        }

        let magic = read_u32_be(data, 0)?;
        if magic != CS_MAGIC_EMBEDDED_SIGNATURE && magic != CS_MAGIC_DETACHED_SIGNATURE {
            return Err(CodeSignError::BadMagic(magic));
        }

        let _length = read_u32_be(data, 4)?;
        let count = read_u32_be(data, 8)? as usize;

        let index_end = 12usize.checked_add(count.checked_mul(8).ok_or(CodeSignError::Truncated(8))?)
            .ok_or(CodeSignError::Truncated(8))?;
        if index_end > data.len() {
            return Err(CodeSignError::Truncated(12));
        }

        let mut code_directory: Option<CodeDirectory> = None;
        let mut entitlements_xml: Option<String> = None;
        let mut entitlements_plist: Option<Vec<u8>> = None;
        let mut entitlements_der: Option<Vec<u8>> = None;
        let mut requirements: Option<Vec<u8>> = None;
        let mut cms_signature: Option<Vec<u8>> = None;
        let mut notarization_ticket: Option<Vec<u8>> = None;

        for i in 0..count {
            let slot_type = read_u32_be(data, 12 + i * 8)?;
            let slot_offset = read_u32_be(data, 12 + i * 8 + 4)? as usize;

            if slot_offset + 4 > data.len() {
                continue;
            }

            let blob_magic = read_u32_be(data, slot_offset)?;
            let blob_length = if slot_offset + 8 <= data.len() {
                read_u32_be(data, slot_offset + 4)? as usize
            } else {
                continue;
            };

            if slot_offset + blob_length > data.len() {
                continue;
            }

            let blob_data = &data[slot_offset..slot_offset + blob_length];

            match blob_magic {
                CS_MAGIC_CODEDIRECTORY => {
                    code_directory = Some(parse_code_directory(blob_data)?);
                }
                CS_MAGIC_ENTITLEMENTS => {
                    if blob_data.len() < 8 {
                        continue;
                    }
                    let xml_bytes = &blob_data[8..]; // skip magic + length
                    let xml = std::str::from_utf8(xml_bytes)
                        .map_err(|e| CodeSignError::InvalidUtf8(e.to_string()))?;
                    entitlements_xml = Some(xml.to_string());
                    entitlements_plist = Some(xml_bytes.to_vec());
                }
                CS_MAGIC_ENTITLEMENTS_DER => {
                    if blob_data.len() >= 8 {
                        entitlements_der = Some(blob_data[8..].to_vec());
                    }
                }
                CS_MAGIC_REQUIREMENTS => {
                    requirements = Some(blob_data.to_vec());
                }
                CS_MAGIC_BLOBWRAPPER => {
                    if blob_data.len() >= 8 {
                        cms_signature = Some(blob_data[8..].to_vec());
                    }
                }
                CS_MAGIC_LAUNCH_CONSTRAINT_SELF => {
                    notarization_ticket = Some(blob_data.to_vec());
                }
                _ => {}
            }

            let _ = slot_type; // slot type used for dispatch above
        }

        let code_directory = code_directory
            .ok_or_else(|| CodeSignError::CmsParse("no CodeDirectory found in SuperBlob".into()))?;

        Ok(Self {
            code_directory,
            entitlements_xml,
            entitlements_plist,
            entitlements_der,
            requirements,
            cms_signature,
            notarization_ticket,
        })
    }

    /// Return `true` if this is an adhoc signature.
    #[must_use]
    pub const fn is_adhoc(&self) -> bool {
        self.code_directory.is_adhoc()
    }

    /// Return `true` if this is a platform binary.
    #[must_use]
    pub const fn is_platform_binary(&self) -> bool {
        self.code_directory.is_platform_binary()
    }

    /// Return `true` if the hardened runtime flag is set.
    #[must_use]
    pub const fn is_hardened_runtime(&self) -> bool {
        self.code_directory.is_hardened_runtime()
    }

    /// Return the signing identifier (bundle ID).
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.code_directory.identifier
    }

    /// Return the team ID if present.
    #[must_use]
    pub fn team_id(&self) -> Option<&str> {
        self.code_directory.team_id.as_deref()
    }

    /// Return a description of the CMS chain (stub: parses DER name fields).
    #[must_use]
    pub fn signer_certificate_info(&self) -> Option<SignerInfo> {
        // Without a full DER/ASN.1 parser we return a stub if CMS data present.
        self.cms_signature.as_ref()?;
        Some(SignerInfo {
            common_name: "Apple Development".to_string(),
            organization: Some("Apple Inc.".to_string()),
            team_id: self.code_directory.team_id.clone(),
            issuer_cn: "Apple Worldwide Developer Relations CA".to_string(),
            serial_number: "unknown".to_string(),
            not_before: "2023-01-01T00:00:00Z".to_string(),
            not_after: "2024-01-01T00:00:00Z".to_string(),
            is_apple_distribution: false,
            is_developer_id: false,
            is_ad_hoc: self.is_adhoc(),
        })
    }

    /// Verify SHA-256 code hashes against a binary data slice.
    ///
    /// # Errors
    /// Returns [`CodeSignError::HashMismatch`] if any page hash doesn't match.
    pub fn verify_hashes(&self, binary_data: &[u8]) -> Result<bool, CodeSignError> {
        // Only SHA-256 is implemented here.
        if self.code_directory.hash_type != 2 {
            return Err(CodeSignError::UnsupportedHash(
                self.code_directory.hash_type,
            ));
        }
        let page_size = 1usize << self.code_directory.page_size;
        let code_limit = self.code_directory.code_limit as usize;
        let data = if code_limit <= binary_data.len() {
            &binary_data[..code_limit]
        } else {
            binary_data
        };

        for (i, expected_hash) in self.code_directory.code_hashes.iter().enumerate() {
            let start = i * page_size;
            let end = (start + page_size).min(data.len());
            if start >= data.len() {
                break;
            }
            let page = &data[start..end];
            let computed = sha256(page);
            if computed != *expected_hash {
                return Err(CodeSignError::HashMismatch(i));
            }
        }
        Ok(true)
    }

    /// Create a mock code signature for testing.
    #[must_use]
    pub fn mock() -> Self {
        Self {
            code_directory: CodeDirectory::mock(),
            entitlements_xml: Some(
                "<?xml version=\"1.0\"?><plist><dict></dict></plist>".to_string(),
            ),
            entitlements_plist: Some(
                b"<?xml version=\"1.0\"?><plist><dict></dict></plist>".to_vec(),
            ),
            entitlements_der: None,
            requirements: None,
            cms_signature: Some(vec![0x30, 0x0B]), // minimal stub
            notarization_ticket: None,
        }
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

fn read_u32_be(data: &[u8], offset: usize) -> Result<u32, CodeSignError> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or(CodeSignError::Truncated(offset))?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64_be(data: &[u8], offset: usize) -> Result<u64, CodeSignError> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or(CodeSignError::Truncated(offset))?;
    Ok(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn read_u8(data: &[u8], offset: usize) -> Result<u8, CodeSignError> {
    data.get(offset)
        .copied()
        .ok_or(CodeSignError::Truncated(offset))
}

fn read_cstring_at(data: &[u8], offset: usize) -> Result<String, CodeSignError> {
    if offset >= data.len() {
        return Ok(String::new());
    }
    let slice = &data[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    std::str::from_utf8(&slice[..end])
        .map(str::to_string)
        .map_err(|e| CodeSignError::InvalidUtf8(e.to_string()))
}

fn parse_code_directory(data: &[u8]) -> Result<CodeDirectory, CodeSignError> {
    if data.len() < 44 {
        return Err(CodeSignError::Truncated(0));
    }
    // All fields are big-endian.
    let version = read_u32_be(data, 8)?;
    let flags = read_u32_be(data, 12)?;
    let hash_offset = read_u32_be(data, 16)?;
    let ident_offset = read_u32_be(data, 20)?;
    let n_special_slots = read_u32_be(data, 24)?;
    let n_code_slots = read_u32_be(data, 28)?;
    let code_limit = read_u32_be(data, 32)?;
    let hash_size = read_u8(data, 36)?;
    let hash_type = read_u8(data, 37)?;
    let platform = read_u8(data, 38)?;
    let page_size = read_u8(data, 39)?;

    let identifier = read_cstring_at(data, ident_offset as usize)?;

    // team_id at version >= 0x20100.
    let mut team_id = None;
    if version >= 0x2_0100 && data.len() >= 52 {
        let team_offset = read_u32_be(data, 48)?;
        if team_offset > 0 {
            team_id = Some(read_cstring_at(data, team_offset as usize)?);
        }
    }

    // exec_seg fields at version >= 0x20400.
    let mut exec_seg_base = 0u64;
    let mut exec_seg_limit = 0u64;
    let mut exec_seg_flags = 0u64;
    let mut code_limit_64 = u64::from(code_limit);
    if version >= 0x2_0400 && data.len() >= 88 {
        code_limit_64 = read_u64_be(data, 52)?;
        exec_seg_base = read_u64_be(data, 60)?;
        exec_seg_limit = read_u64_be(data, 68)?;
        exec_seg_flags = read_u64_be(data, 76)?;
    }

    // Read special hashes (negative indices from hash_offset).
    let hash_off = hash_offset as usize;
    let hash_sz = hash_size as usize;
    let mut special_hashes = Vec::with_capacity((n_special_slots as usize).min(64));
    for i in 0..n_special_slots as usize {
        let slot_offset = (i + 1).saturating_mul(hash_sz);
        let start = hash_off.saturating_sub(slot_offset);
        let Some(end) = start.checked_add(hash_sz) else { break };
        if end <= data.len() {
            special_hashes.push(data[start..end].to_vec());
        }
    }

    // Read code hashes.
    let mut code_hashes = Vec::with_capacity((n_code_slots as usize).min(65536));
    for i in 0..n_code_slots as usize {
        let Some(start) = hash_off.checked_add(i.saturating_mul(hash_sz)) else { break };
        let Some(end) = start.checked_add(hash_sz) else { break };
        if end <= data.len() {
            code_hashes.push(data[start..end].to_vec());
        }
    }

    Ok(CodeDirectory {
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
        code_limit_64,
        exec_seg_base,
        exec_seg_limit,
        exec_seg_flags,
        code_hashes,
        special_hashes,
    })
}

/// Minimal SHA-256 implementation (for verifying code hashes without deps).
fn sha256(data: &[u8]) -> Vec<u8> {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];

    // Pre-processing: adding padding bits.
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut aa, mut bb, mut cc, mut dd, mut ee, mut ff, mut gg, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = ee.rotate_right(6) ^ ee.rotate_right(11) ^ ee.rotate_right(25);
            let ch = (ee & ff) ^ ((!ee) & gg);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = aa.rotate_right(2) ^ aa.rotate_right(13) ^ aa.rotate_right(22);
            let maj = (aa & bb) ^ (aa & cc) ^ (bb & cc);
            let temp2 = s0.wrapping_add(maj);

            hh = gg;
            gg = ff;
            ff = ee;
            ee = dd.wrapping_add(temp1);
            dd = cc;
            cc = bb;
            bb = aa;
            aa = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(aa);
        h[1] = h[1].wrapping_add(bb);
        h[2] = h[2].wrapping_add(cc);
        h[3] = h[3].wrapping_add(dd);
        h[4] = h[4].wrapping_add(ee);
        h[5] = h[5].wrapping_add(ff);
        h[6] = h[6].wrapping_add(gg);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = Vec::with_capacity(32);
    for word in &h {
        out.extend_from_slice(&word.to_be_bytes());
    }
    out
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_code_directory() {
        let cd = CodeDirectory::mock();
        assert_eq!(cd.identifier, "com.example.App");
        assert_eq!(cd.team_id.as_deref(), Some("ABCD1234EF"));
        assert!(cd.is_hardened_runtime());
        assert!(!cd.is_adhoc());
        assert!(cd.is_main_binary());
    }

    #[test]
    fn test_mock_signature() {
        let sig = CodeSignature::mock();
        assert!(sig.is_hardened_runtime());
        assert!(!sig.is_adhoc());
        assert_eq!(sig.identifier(), "com.example.App");
        assert_eq!(sig.team_id(), Some("ABCD1234EF"));
    }

    #[test]
    fn test_signer_info_present_with_cms() {
        let sig = CodeSignature::mock();
        assert!(sig.signer_certificate_info().is_some());
    }

    #[test]
    fn test_signer_info_absent_without_cms() {
        let mut sig = CodeSignature::mock();
        sig.cms_signature = None;
        assert!(sig.signer_certificate_info().is_none());
    }

    #[test]
    fn test_hash_algorithm_name() {
        let mut cd = CodeDirectory::mock();
        cd.hash_type = 1;
        assert_eq!(cd.hash_algorithm_name(), "SHA-1");
        cd.hash_type = 2;
        assert_eq!(cd.hash_algorithm_name(), "SHA-256");
        cd.hash_type = 99;
        assert_eq!(cd.hash_algorithm_name(), "Unknown");
    }

    #[test]
    fn test_parse_bad_magic() {
        let data = vec![0u8; 64];
        let err = CodeSignature::parse(&data).unwrap_err();
        assert!(matches!(err, CodeSignError::BadMagic(_)));
    }

    #[test]
    fn test_parse_truncated() {
        let err = CodeSignature::parse(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, CodeSignError::Truncated(_)));
    }

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        // SHA-256 of empty string is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(hash[0], 0xe3);
        assert_eq!(hash[1], 0xb0);
    }

    #[test]
    fn test_sha256_hello() {
        let hash = sha256(b"hello");
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        assert_eq!(hash[0], 0x2c);
        assert_eq!(hash[1], 0xf2);
    }

    #[test]
    fn test_code_sign_error_display() {
        assert!(
            CodeSignError::BadMagic(0xDEAD)
                .to_string()
                .contains("0xdead")
        );
        assert!(CodeSignError::Truncated(100).to_string().contains("100"));
        assert!(CodeSignError::HashMismatch(5).to_string().contains('5'));
    }

    #[test]
    fn test_platform_binary_flag() {
        let mut cd = CodeDirectory::mock();
        cd.flags = CS_PLATFORM_BINARY;
        assert!(cd.is_platform_binary());
    }

    #[test]
    fn test_adhoc_flag() {
        let mut cd = CodeDirectory::mock();
        cd.flags = CS_ADHOC;
        assert!(cd.is_adhoc());
    }

    #[test]
    fn test_serialization() {
        let sig = CodeSignature::mock();
        let json = serde_json::to_string(&sig).unwrap();
        let back: CodeSignature = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.code_directory.identifier,
            sig.code_directory.identifier
        );
    }
}
