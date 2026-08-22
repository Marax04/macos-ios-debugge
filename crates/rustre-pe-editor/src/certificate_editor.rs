//! `certificate_editor` — PE Authenticode certificate management
//!
//! Provides operations on the `WIN_CERTIFICATE` structure stored in the
//! Security data directory (index 4).  Supports:
//!
//! * Stripping the Authenticode signature from a signed PE.
//! * Replacing the signature with another DER blob.
//! * Extracting the raw certificate chain as PEM-encoded certificates.
//! * Appending / removing individual certificates.
//! * Querying timestamp countersignature info.
//! * Checking catalog-based signature presence.
//!
//! # References
//! * Microsoft PE/COFF spec section 5.6.1 — Security Data Directory.
//! * `WIN_CERTIFICATE` structure in `wintrust.h`.
//! * RFC 2315 (PKCS#7 / CMS) for the `SignedData` wrapper.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Write as FmtWrite;

use crate::EditError;

// ---------------------------------------------------------------------------
// WIN_CERTIFICATE header constants
// ---------------------------------------------------------------------------

/// Size of a `WIN_CERTIFICATE` header in bytes (dwLength + wRevision + wCertType).
pub const WIN_CERT_HEADER_SIZE: usize = 8;

/// `WIN_CERTIFICATE` revision: PKCS#7 / CMS signed data (the most common).
pub const WIN_CERT_REVISION_2_0: u16 = 0x0200;

/// `WIN_CERTIFICATE` type: PKCS#7 `SignedData`.
pub const WIN_CERT_TYPE_PKCS_SIGNED_DATA: u16 = 0x0002;

/// `WIN_CERTIFICATE` type: X.509 certificate (rarely used in PE).
pub const WIN_CERT_TYPE_X509: u16 = 0x0001;

/// `WIN_CERT` attribute type: PKCS#1 (v1) signature.
pub const WIN_CERT_TYPE_PKCS1_SIGN: u16 = 0x0009;

// ---------------------------------------------------------------------------
// OID constants (BER/DER OID bytes, prefix-encoded)
// ---------------------------------------------------------------------------

/// OID 1.2.840.113549.1.9.5 — signingTime attribute.
pub const OID_SIGNING_TIME: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05];
/// OID 1.2.840.113549.1.9.6 — counterSignature attribute.
pub const OID_COUNTER_SIGNATURE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x06];
/// OID 1.3.6.1.4.1.311.2.4.1 — nested Authenticode attribute (RFC 3161 ts).
pub const OID_SPC_NESTED_SIGNATURE: &[u8] =
    &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01];

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors specific to certificate editing.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    #[error("no security data directory present")]
    NoSecurityDirectory,
    #[error("WIN_CERTIFICATE header truncated (need {need}, got {got})")]
    HeaderTruncated { need: usize, got: usize },
    #[error("certificate blob too large: {0} bytes")]
    BlobTooLarge(usize),
    #[error("invalid WIN_CERTIFICATE revision: {0:#06x}")]
    InvalidRevision(u16),
    #[error("DER parse error: {0}")]
    DerParseError(String),
    #[error("security directory offset out of bounds")]
    OffsetOutOfBounds,
    #[error("signature strip failed: {0}")]
    StripFailed(String),
    #[error("timestamp not present")]
    NoTimestamp,
}

impl From<CertError> for EditError {
    fn from(e: CertError) -> Self {
        Self::SignError(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// WIN_CERTIFICATE structure
// ---------------------------------------------------------------------------

/// Parsed representation of a `WIN_CERTIFICATE` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinCertificate {
    /// Total length including header (8-byte aligned per spec).
    pub dw_length: u32,
    /// Revision field (0x0200 for PKCS#7).
    pub w_revision: u16,
    /// Certificate type (`WIN_CERT_TYPE_*`).
    pub w_cert_type: u16,
    /// Raw certificate bytes (DER for PKCS#7, X.509, etc.).
    pub cert_data: Vec<u8>,
}

impl WinCertificate {
    /// Parse a `WIN_CERTIFICATE` from `data` at byte offset `offset`.
    ///
    /// # Errors
    /// Returns [`CertError::HeaderTruncated`] if the data is too short.
    ///
    /// # Panics
    /// Panics on internal `try_into` failure for valid-length slices (should never occur).
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, CertError> {
        if offset + WIN_CERT_HEADER_SIZE > data.len() {
            return Err(CertError::HeaderTruncated {
                need: WIN_CERT_HEADER_SIZE,
                got: data.len().saturating_sub(offset),
            });
        }
        let dw_length =
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let w_revision =
            u16::from_le_bytes(data[offset + 4..offset + 6].try_into().unwrap());
        let w_cert_type =
            u16::from_le_bytes(data[offset + 6..offset + 8].try_into().unwrap());
        let end = (offset + dw_length as usize).min(data.len());
        let cert_data = data[offset + WIN_CERT_HEADER_SIZE..end].to_vec();
        Ok(Self { dw_length, w_revision, w_cert_type, cert_data })
    }

    /// Serialize back to bytes (8-byte aligned length, zero-padded).
    ///
    /// # Panics
    /// Panics if the aligned length exceeds `u32::MAX` (not possible for valid PE files).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let payload_len = self.cert_data.len();
        let total = WIN_CERT_HEADER_SIZE + payload_len;
        let aligned = (total + 7) & !7;
        let mut out = vec![0u8; aligned];
        out[0..4].copy_from_slice(&u32::try_from(aligned).expect("aligned size fits in u32").to_le_bytes());
        out[4..6].copy_from_slice(&self.w_revision.to_le_bytes());
        out[6..8].copy_from_slice(&self.w_cert_type.to_le_bytes());
        out[WIN_CERT_HEADER_SIZE..WIN_CERT_HEADER_SIZE + payload_len]
            .copy_from_slice(&self.cert_data);
        out
    }

    /// Returns true if this is a PKCS#7 `SignedData` blob.
    #[must_use] 
    pub const fn is_pkcs7(&self) -> bool {
        self.w_cert_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA
    }

    /// Human-readable type string.
    #[must_use] 
    pub const fn cert_type_str(&self) -> &'static str {
        match self.w_cert_type {
            WIN_CERT_TYPE_PKCS_SIGNED_DATA => "PKCS#7 SignedData",
            WIN_CERT_TYPE_X509 => "X.509",
            WIN_CERT_TYPE_PKCS1_SIGN => "PKCS#1 v1",
            _ => "Unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// DER certificate record
// ---------------------------------------------------------------------------

/// DER certificate record extracted from a PKCS#7 blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerCertificate {
    /// Subject common name (best-effort from DER, may be empty).
    pub subject_cn: String,
    /// Issuer common name (best-effort from DER, may be empty).
    pub issuer_cn: String,
    /// Raw DER bytes.
    pub der: Vec<u8>,
}

impl DerCertificate {
    /// Encode this certificate as a PEM string.
    #[must_use] 
    pub fn to_pem(&self) -> String {
        let b64 = base64_encode(&self.der);
        let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }
}

// ---------------------------------------------------------------------------
// Timestamp info
// ---------------------------------------------------------------------------

/// Timestamp information extracted from a countersignature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampInfo {
    /// Signing timestamp (raw `UTCTime` / `GeneralizedTime` string from DER).
    pub signing_time: String,
    /// TSA subject common name (if found).
    pub tsa_cn: String,
    /// Whether this is an RFC 3161 timestamp token vs. legacy PKCS#9 countersig.
    pub is_rfc3161: bool,
    /// Raw DER bytes of the timestamp token.
    pub token_der: Vec<u8>,
}

impl fmt::Display for TimestampInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TimestampInfo {{ time={}, tsa={}, rfc3161={} }}",
            self.signing_time, self.tsa_cn, self.is_rfc3161
        )
    }
}

// ---------------------------------------------------------------------------
// CertificateEditor
// ---------------------------------------------------------------------------

/// Edits the Security data directory of a PE file held as a raw byte buffer.
pub struct CertificateEditor {
    data: Vec<u8>,
    /// Byte offset of the COFF header (= `e_lfanew` + 4-byte PE sig).
    coff_offset: usize,
    /// True for PE32+ (64-bit optional header magic 0x020B).
    is_pe32plus: bool,
}

impl CertificateEditor {
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    /// Construct from raw PE bytes.
    ///
    /// # Errors
    /// Returns [`CertError::OffsetOutOfBounds`] if the PE headers are malformed.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, CertError> {
        let coff_offset = locate_coff(&data).ok_or(CertError::OffsetOutOfBounds)?;
        let is_pe32plus = detect_pe32plus(&data, coff_offset);
        Ok(Self { data, coff_offset, is_pe32plus })
    }

    // -----------------------------------------------------------------------
    // Layout helpers
    // -----------------------------------------------------------------------

    const fn opt_header_offset(&self) -> usize {
        // PE sig (4) + COFF header (20) = 24 bytes after coff_offset.
        self.coff_offset + 4 + 20
    }

    /// Byte offset of the Security data directory entry inside the optional header.
    ///
    /// Security directory is data directory entry index 4 (0-based).
    /// PE32:  OptHdr+96 + 4*8 = OptHdr+128
    /// PE32+: OptHdr+112 + 4*8 = OptHdr+144
    const fn security_dir_offset(&self) -> usize {
        let opt = self.opt_header_offset();
        if self.is_pe32plus { opt + 144 } else { opt + 128 }
    }

    fn read_security_dir(&self) -> Result<(u32, u32), CertError> {
        let off = self.security_dir_offset();
        if off + 8 > self.data.len() {
            return Err(CertError::NoSecurityDirectory);
        }
        let va = u32::from_le_bytes(self.data[off..off + 4].try_into().unwrap());
        let sz = u32::from_le_bytes(self.data[off + 4..off + 8].try_into().unwrap());
        if va == 0 || sz == 0 {
            return Err(CertError::NoSecurityDirectory);
        }
        Ok((va, sz))
    }

    fn write_security_dir(&mut self, va: u32, sz: u32) -> Result<(), CertError> {
        let off = self.security_dir_offset();
        if off + 8 > self.data.len() {
            return Err(CertError::OffsetOutOfBounds);
        }
        self.data[off..off + 4].copy_from_slice(&va.to_le_bytes());
        self.data[off + 4..off + 8].copy_from_slice(&sz.to_le_bytes());
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Query
    // -----------------------------------------------------------------------

    /// Return all `WIN_CERTIFICATE` entries present in the Security directory.
    ///
    /// # Errors
    /// Returns [`CertError`] if the security directory is absent or malformed.
    pub fn raw_certificates(&self) -> Result<Vec<WinCertificate>, CertError> {
        let (va, sz) = self.read_security_dir()?;
        let start = va as usize;
        let end = (start + sz as usize).min(self.data.len());
        let mut pos = start;
        let mut certs = Vec::new();
        while pos + WIN_CERT_HEADER_SIZE <= end {
            let cert = WinCertificate::parse(&self.data, pos)?;
            let aligned_len = ((cert.dw_length as usize) + 7) & !7;
            pos += aligned_len.max(WIN_CERT_HEADER_SIZE);
            certs.push(cert);
        }
        Ok(certs)
    }

    /// Check whether the PE carries any Authenticode signature.
    #[must_use] 
    pub fn is_signed(&self) -> bool {
        self.read_security_dir().is_ok()
    }

    /// Extract the certificate chain from all PKCS#7 blobs as PEM records.
    ///
    /// # Errors
    /// Returns [`CertError`] if the security directory or certificate data is invalid.
    pub fn extract_pem_chain(&self) -> Result<Vec<DerCertificate>, CertError> {
        let certs = self.raw_certificates()?;
        let mut results = Vec::new();
        for wc in &certs {
            if !wc.is_pkcs7() { continue; }
            let mut found = extract_der_sequences(&wc.cert_data);
            results.append(&mut found);
        }
        Ok(results)
    }

    /// Extract timestamp countersignature info from the PKCS#7 blob.
    ///
    /// # Errors
    /// Returns [`CertError::NoTimestamp`] if no timestamp is found, or other [`CertError`] on parse failure.
    pub fn timestamp_info(&self) -> Result<TimestampInfo, CertError> {
        let certs = self.raw_certificates()?;
        for wc in &certs {
            if !wc.is_pkcs7() { continue; }
            if let Some(ts) = find_timestamp_in_pkcs7(&wc.cert_data) {
                return Ok(ts);
            }
        }
        Err(CertError::NoTimestamp)
    }

    // -----------------------------------------------------------------------
    // Modification
    // -----------------------------------------------------------------------

    /// Strip the Authenticode signature entirely.
    ///
    /// Per the Authenticode spec the certificate table always sits at the end
    /// of the file, so we truncate there and zero the data directory entry.
    ///
    /// # Errors
    /// Returns [`CertError`] if the security directory is absent or the header cannot be written.
    pub fn strip_signature(&mut self) -> Result<Vec<u8>, CertError> {
        let (va, sz) = self.read_security_dir()?;
        self.write_security_dir(0, 0)?;
        let start = va as usize;
        let end = (start + sz as usize).min(self.data.len());
        if start <= self.data.len() {
            self.data.truncate(start);
        } else {
            for b in &mut self.data[start..end] { *b = 0; }
        }
        Ok(self.data.clone())
    }

    /// Replace the signature with `new_der` (a PKCS#7 `SignedData` DER blob).
    ///
    /// # Errors
    /// Returns [`CertError`] if the security directory header cannot be written.
    ///
    /// # Panics
    /// Panics if the file or blob size exceeds `u32::MAX` (not possible for valid PE files).
    pub fn replace_signature(&mut self, new_der: Vec<u8>) -> Result<Vec<u8>, CertError> {
        let _ = self.strip_signature();
        let new_va = u32::try_from(self.data.len()).expect("PE size fits in u32");
        let wc = WinCertificate {
            dw_length: 0,
            w_revision: WIN_CERT_REVISION_2_0,
            w_cert_type: WIN_CERT_TYPE_PKCS_SIGNED_DATA,
            cert_data: new_der,
        };
        let blob = wc.to_bytes();
        let sz = u32::try_from(blob.len()).expect("blob size fits in u32");
        self.data.extend_from_slice(&blob);
        self.write_security_dir(new_va, sz)?;
        Ok(self.data.clone())
    }

    /// Remove all certificates of a specific `cert_type` from the table.
    ///
    /// # Errors
    /// Returns [`CertError`] if the certificate table is malformed or the header cannot be written.
    pub fn remove_certificates_of_type(
        &mut self,
        cert_type: u16,
    ) -> Result<Vec<u8>, CertError> {
        let certs = self.raw_certificates()?;
        let filtered: Vec<WinCertificate> =
            certs.into_iter().filter(|c| c.w_cert_type != cert_type).collect();
        self.rebuild_certificate_table(&filtered)
    }

    /// Append an additional `WIN_CERTIFICATE` entry to the table.
    ///
    /// # Errors
    /// Returns [`CertError`] if the security directory header cannot be written.
    pub fn add_certificate(
        &mut self,
        cert_type: u16,
        der: Vec<u8>,
    ) -> Result<Vec<u8>, CertError> {
        let mut certs = self.raw_certificates().unwrap_or_default();
        certs.push(WinCertificate {
            dw_length: 0,
            w_revision: WIN_CERT_REVISION_2_0,
            w_cert_type: cert_type,
            cert_data: der,
        });
        self.rebuild_certificate_table(&certs)
    }

    fn rebuild_certificate_table(
        &mut self,
        certs: &[WinCertificate],
    ) -> Result<Vec<u8>, CertError> {
        let old_va = self.read_security_dir().map_or(0, |(va, _)| va);
        let new_va = if old_va > 0 { old_va } else { u32::try_from(self.data.len()).expect("PE size fits in u32") };
        let mut blob = Vec::new();
        for wc in certs { blob.extend_from_slice(&wc.to_bytes()); }
        let sz = u32::try_from(blob.len()).expect("blob size fits in u32");
        let start = new_va as usize;
        if start <= self.data.len() { self.data.truncate(start); }
        self.data.extend_from_slice(&blob);
        if sz > 0 {
            self.write_security_dir(new_va, sz)?;
        } else {
            self.write_security_dir(0, 0)?;
        }
        Ok(self.data.clone())
    }

    /// Consume the editor and return the inner byte buffer.
    #[must_use] 
    pub fn into_bytes(self) -> Vec<u8> { self.data }
}

// ---------------------------------------------------------------------------
// Catalog verification stub
// ---------------------------------------------------------------------------

/// Result of a catalog-based signature check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogVerificationResult {
    /// SHA-1 hash of the file content (used for catalog lookup).
    pub file_sha1: String,
    /// SHA-256 hash of the file content.
    pub file_sha256: String,
    /// Whether a matching catalog entry was found.
    /// Always `false` in the offline implementation (requires `WinTrust` API).
    pub catalog_match: bool,
    /// Catalog file path (empty in offline stub).
    pub catalog_path: String,
}

/// Compute a catalog verification result (hash-only offline stub).
#[must_use] 
pub fn catalog_verify(data: &[u8]) -> CatalogVerificationResult {
    CatalogVerificationResult {
        file_sha1: hex_sha1(data),
        file_sha256: hex_sha256(data),
        catalog_match: false,
        catalog_path: String::new(),
    }
}

// ---------------------------------------------------------------------------
// High-level convenience functions
// ---------------------------------------------------------------------------

/// Strip the Authenticode signature from `data` and return the modified bytes.
///
/// # Errors
/// Returns [`CertError`] if the PE is malformed or has no security directory.
pub fn strip_signature(data: Vec<u8>) -> Result<Vec<u8>, CertError> {
    let mut ed = CertificateEditor::from_bytes(data)?;
    ed.strip_signature()
}

/// Extract all certificates from `data` as PEM strings.
///
/// # Errors
/// Returns [`CertError`] if the PE is malformed or has no valid certificate table.
pub fn extract_pem(data: &[u8]) -> Result<Vec<String>, CertError> {
    let ed = CertificateEditor::from_bytes(data.to_vec())?;
    Ok(ed.extract_pem_chain()?.into_iter().map(|c| c.to_pem()).collect())
}

/// Return `true` if `data` carries an embedded Authenticode signature.
#[must_use] 
pub fn has_signature(data: &[u8]) -> bool {
    CertificateEditor::from_bytes(data.to_vec())
        .is_ok_and(|ed| ed.is_signed())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn locate_coff(data: &[u8]) -> Option<usize> {
    if data.len() < 0x40 { return None; }
    if data[0] != b'M' || data[1] != b'Z' { return None; }
    let lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
    if lfanew + 4 > data.len() { return None; }
    if &data[lfanew..lfanew + 4] != b"PE\0\0" { return None; }
    Some(lfanew)
}

fn detect_pe32plus(data: &[u8], coff_offset: usize) -> bool {
    let opt = coff_offset + 4 + 20;
    if opt + 2 > data.len() { return false; }
    u16::from_le_bytes(data[opt..opt + 2].try_into().unwrap()) == 0x020B
}

/// Walk a DER byte stream and extract SEQUENCE objects that resemble X.509 certs.
fn extract_der_sequences(data: &[u8]) -> Vec<DerCertificate> {
    let mut results = Vec::new();
    let mut pos = 0;
    while pos + 2 <= data.len() {
        if data[pos] != 0x30 { pos += 1; continue; }
        let Some((len, hdr)) = der_length(&data[pos + 1..]) else { pos += 1; continue; };
        let total = 1 + hdr + len;
        if pos + total > data.len() { pos += 1; continue; }
        let der = data[pos..pos + total].to_vec();
        results.push(DerCertificate {
            subject_cn: best_effort_cn(&der),
            issuer_cn: String::new(),
            der,
        });
        pos += total;
    }
    results
}

/// Parse DER length field.  Returns `(length, header_bytes_consumed)`.
#[must_use] 
pub fn der_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()? as usize;
    if first < 0x80 { return Some((first, 1)); }
    let num_bytes = first & 0x7F;
    if num_bytes == 0 || num_bytes > 4 || data.len() < 1 + num_bytes { return None; }
    let mut len = 0usize;
    for &b in &data[1..=num_bytes] { len = (len << 8) | b as usize; }
    Some((len, 1 + num_bytes))
}

/// Best-effort Common Name extraction from a DER X.509 certificate.
fn best_effort_cn(der: &[u8]) -> String {
    // OID 2.5.4.3 (id-at-commonName) in DER: 55 04 03
    let cn_oid = &[0x55u8, 0x04, 0x03];
    if let Some(pos) = find_subsequence(der, cn_oid) {
        let vs = pos + cn_oid.len();
        if vs + 2 < der.len() {
            let tag = der[vs];
            if matches!(tag, 0x0C | 0x13 | 0x16 | 0x1E)
                && let Some((len, hdr)) = der_length(&der[vs + 1..]) {
                    let s = vs + 1 + hdr;
                    if s + len <= der.len() {
                        return String::from_utf8_lossy(&der[s..s + len]).into_owned();
                    }
                }
        }
    }
    String::new()
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// True if the PKCS#7 blob carries a legacy `counterSignature` attribute.
///
/// This is the marker of an old-style Authenticode timestamp, as opposed to
/// an RFC 3161 token (`OID_SPC_NESTED_SIGNATURE`).
#[must_use]
pub fn has_countersignature(pkcs7: &[u8]) -> bool {
    find_subsequence(pkcs7, OID_COUNTER_SIGNATURE).is_some()
}

fn find_timestamp_in_pkcs7(pkcs7: &[u8]) -> Option<TimestampInfo> {
    // OID_COUNTER_SIGNATURE was declared and never read, so a legacy
    // countersigned blob that carries its signingTime inside the
    // counterSignature attribute -- after the point this scan starts from --
    // was reported as having no timestamp at all. Search from the
    // signingTime OID when present, and fall back to the countersignature.
    let start = find_subsequence(pkcs7, OID_SIGNING_TIME)
        .map(|p| p + OID_SIGNING_TIME.len())
        .or_else(|| {
            find_subsequence(pkcs7, OID_COUNTER_SIGNATURE)
                .map(|p| p + OID_COUNTER_SIGNATURE.len())
        });
    if let Some(after) = start {
        let limit = (after + 64).min(pkcs7.len());
        let search = &pkcs7[after..limit];
        for offset in 0..search.len().saturating_sub(4) {
            let tag = search[offset];
            if (tag == 0x17 || tag == 0x18)
                && let Some((len, hdr)) = der_length(&search[offset + 1..]) {
                    let s = offset + 1 + hdr;
                    let e = s + len;
                    if e <= search.len() {
                        let signing_time =
                            String::from_utf8_lossy(&search[s..e]).into_owned();
                        return Some(TimestampInfo {
                            signing_time,
                            tsa_cn: String::new(),
                            is_rfc3161: find_subsequence(
                                pkcs7,
                                OID_SPC_NESTED_SIGNATURE,
                            )
                            .is_some(),
                            token_der: pkcs7.to_vec(),
                        });
                    }
                }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Minimal SHA-1 (FIPS PUB 180-4)
// ---------------------------------------------------------------------------

fn hex_sha1(data: &[u8]) -> String {
    sha1_digest(data).iter().fold(String::new(), |mut acc, byte| {
        let _ = write!(acc, "{byte:02x}");
        acc
    })
}

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut state: [u32; 5] =
        [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut sched = [0u32; 80];
        for (idx, word) in sched[..16].iter_mut().enumerate() {
            *word = u32::from_be_bytes(chunk[idx * 4..idx * 4 + 4].try_into().unwrap());
        }
        for idx in 16..80 {
            sched[idx] = (sched[idx - 3] ^ sched[idx - 8] ^ sched[idx - 14] ^ sched[idx - 16]).rotate_left(1);
        }
        let (mut va, mut vb, mut vc, mut vd, mut ve) = (state[0], state[1], state[2], state[3], state[4]);
        for (idx, &wi) in sched.iter().enumerate() {
            let (round_fn, round_k): (u32, u32) = match idx {
                0..=19  => ((vb & vc) | (!vb & vd), 0x5A82_7999),
                20..=39 => (vb ^ vc ^ vd,           0x6ED9_EBA1),
                40..=59 => ((vb & vc) | (vb & vd) | (vc & vd), 0x8F1B_BCDC),
                _       => (vb ^ vc ^ vd,           0xCA62_C1D6),
            };
            let temp = va
                .rotate_left(5)
                .wrapping_add(round_fn)
                .wrapping_add(ve)
                .wrapping_add(round_k)
                .wrapping_add(wi);
            ve = vd; vd = vc; vc = vb.rotate_left(30); vb = va; va = temp;
        }
        state[0] = state[0].wrapping_add(va); state[1] = state[1].wrapping_add(vb);
        state[2] = state[2].wrapping_add(vc); state[3] = state[3].wrapping_add(vd);
        state[4] = state[4].wrapping_add(ve);
    }
    let mut out = [0u8; 20];
    for (idx, &val) in state.iter().enumerate() {
        out[idx * 4..idx * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    out
}

// ---------------------------------------------------------------------------
// Minimal SHA-256 (FIPS PUB 180-4)
// ---------------------------------------------------------------------------

fn hex_sha256(data: &[u8]) -> String {
    sha256_digest(data).iter().fold(String::new(), |mut acc, byte| {
        let _ = write!(acc, "{byte:02x}");
        acc
    })
}

#[rustfmt::skip]
fn sha256_digest(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
        0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
        0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
        0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7, 0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
        0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
        0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
        0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
        0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut sched = [0u32; 64];
        for (idx, word) in sched[..16].iter_mut().enumerate() {
            *word = u32::from_be_bytes(chunk[idx * 4..idx * 4 + 4].try_into().unwrap());
        }
        for idx in 16..64 {
            let sg0 = sched[idx-15].rotate_right(7) ^ sched[idx-15].rotate_right(18) ^ (sched[idx-15] >> 3);
            let sg1 = sched[idx-2].rotate_right(17) ^ sched[idx-2].rotate_right(19) ^ (sched[idx-2] >> 10);
            sched[idx] = sched[idx-16].wrapping_add(sg0).wrapping_add(sched[idx-7]).wrapping_add(sg1);
        }
        let (mut va, mut vb, mut vc, mut vd, mut ve, mut vf, mut vg, mut vh) =
            (state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]);
        for (idx, &wi) in sched.iter().enumerate() {
            let ep1 = ve.rotate_right(6)^ve.rotate_right(11)^ve.rotate_right(25);
            let ch = (ve & vf) ^ (!ve & vg);
            let t1 = vh.wrapping_add(ep1).wrapping_add(ch).wrapping_add(K[idx]).wrapping_add(wi);
            let ep0 = va.rotate_right(2)^va.rotate_right(13)^va.rotate_right(22);
            let maj = (va & vb) ^ (va & vc) ^ (vb & vc);
            let t2 = ep0.wrapping_add(maj);
            vh=vg; vg=vf; vf=ve; ve=vd.wrapping_add(t1); vd=vc; vc=vb; vb=va; va=t1.wrapping_add(t2);
        }
        state[0]=state[0].wrapping_add(va); state[1]=state[1].wrapping_add(vb);
        state[2]=state[2].wrapping_add(vc); state[3]=state[3].wrapping_add(vd);
        state[4]=state[4].wrapping_add(ve); state[5]=state[5].wrapping_add(vf);
        state[6]=state[6].wrapping_add(vg); state[7]=state[7].wrapping_add(vh);
    }
    let mut out = [0u8; 32];
    for (idx, &val) in state.iter().enumerate() { out[idx*4..idx*4+4].copy_from_slice(&val.to_be_bytes()); }
    out
}

// ---------------------------------------------------------------------------
// Base-64 encoder (RFC 4648, standard alphabet)
// ---------------------------------------------------------------------------

fn base64_encode(data: &[u8]) -> String {
    const ALPHA: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = if chunk.len() > 1 { u32::from(chunk[1]) } else { 0 };
        let b2 = if chunk.len() > 2 { u32::from(chunk[2]) } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHA[((n >> 18) & 0x3F) as usize]);
        out.push(ALPHA[((n >> 12) & 0x3F) as usize]);
        out.push(if chunk.len() > 1 { ALPHA[((n >> 6) & 0x3F) as usize] } else { b'=' });
        out.push(if chunk.len() > 2 { ALPHA[(n & 0x3F) as usize] } else { b'=' });
    }
    String::from_utf8(out).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_hello() {
        assert_eq!(base64_encode(b"Hello, World!"), "SGVsbG8sIFdvcmxkIQ==");
    }

    #[test]
    fn sha1_empty() {
        assert_eq!(hex_sha1(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn sha256_empty() {
        assert_eq!(
            hex_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb924\
             27ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn win_cert_to_bytes_length_set() {
        let wc = WinCertificate {
            dw_length: 0,
            w_revision: WIN_CERT_REVISION_2_0,
            w_cert_type: WIN_CERT_TYPE_PKCS_SIGNED_DATA,
            cert_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let bytes = wc.to_bytes();
        let dw = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        assert!(dw >= WIN_CERT_HEADER_SIZE as u32 + 4);
    }

    #[test]
    fn der_length_short_form() {
        assert_eq!(der_length(&[0x0A]), Some((10, 1)));
    }

    #[test]
    fn der_length_long_form() {
        assert_eq!(der_length(&[0x82, 0x01, 0x00]), Some((256, 3)));
    }

    #[test]
    fn catalog_verify_hashes_not_empty() {
        let r = catalog_verify(b"test data");
        assert!(!r.file_sha1.is_empty());
        assert!(!r.file_sha256.is_empty());
        assert!(!r.catalog_match);
    }
    #[test]
    fn legacy_countersignature_timestamp_is_found() {
        // A blob whose signingTime lives inside the counterSignature
        // attribute, with no bare signingTime OID before it: previously
        // reported as "no timestamp".
        let mut blob = vec![0u8; 8];
        blob.extend_from_slice(OID_COUNTER_SIGNATURE);
        blob.push(0x17); // UTCTime
        let ts = b"230115120000Z";
        blob.push(u8::try_from(ts.len()).expect("fixture timestamp fits in a byte"));
        blob.extend_from_slice(ts);

        assert!(has_countersignature(&blob));
        let found = find_timestamp_in_pkcs7(&blob).expect("legacy timestamp found");
        assert_eq!(found.signing_time, "230115120000Z");
        assert!(!found.is_rfc3161);

        assert!(!has_countersignature(&[0u8; 32]));
        assert!(find_timestamp_in_pkcs7(&[0u8; 32]).is_none());
    }

}
