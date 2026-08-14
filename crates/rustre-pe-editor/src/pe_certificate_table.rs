//! `pe_certificate_table` — PE Authenticode / `WIN_CERTIFICATE` table.
//!
//! Provides [`PeCertTable`] for parsing, iterating, and manipulating the
//! certificate table stored in `DataDirectory[4]` (the security directory) of a
//! PE image.  The format is described in the PE/COFF specification as an array
//! of `WIN_CERTIFICATE` structures, each 8-byte-aligned.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by certificate table operations.
#[derive(Debug, Error, Clone)]
pub enum CertError {
    /// The PE buffer is too short.
    #[error("buffer too short: need {needed}, have {got}")]
    TooShort { needed: usize, got: usize },
    /// The PE/DOS header is invalid.
    #[error("invalid PE header: {0}")]
    InvalidHeader(String),
    /// A `WIN_CERTIFICATE` entry is malformed (e.g. zero length).
    #[error("malformed certificate at offset {offset:#x}: {reason}")]
    MalformedEntry { offset: usize, reason: String },
    /// No certificate table is present in this PE image.
    #[error("no certificate table in PE image")]
    NoCertTable,
    /// A requested certificate index is out of range.
    #[error("certificate index {0} out of range")]
    IndexOutOfRange(usize),
}

// ─────────────────────────────────────────────────────────────────────────────
// CertificateType
// ─────────────────────────────────────────────────────────────────────────────

/// Certificate type discriminant from `WIN_CERTIFICATE.wCertificateType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertificateType {
    /// X.509 certificate (rarely used in practice).
    X509,
    /// PKCS#7 `SignedData` blob (most Authenticode signatures use this).
    PkcsSignedData,
    /// Reserved / Terminal Server Protocol Stack certificate.
    Reserved1,
    /// TS Stack certificate.
    TsStackSigned,
    /// Unknown/vendor type.
    Unknown(u16),
}

impl CertificateType {
    /// Construct from the raw `wCertificateType` value.
    #[must_use]
    pub const fn from_raw(v: u16) -> Self {
        match v {
            0x0001 => Self::X509,
            0x0002 => Self::PkcsSignedData,
            0x0003 => Self::Reserved1,
            0x0004 => Self::TsStackSigned,
            other => Self::Unknown(other),
        }
    }

    /// Return the raw `u16` value.
    #[must_use]
    pub const fn to_raw(self) -> u16 {
        match self {
            Self::X509 => 0x0001,
            Self::PkcsSignedData => 0x0002,
            Self::Reserved1 => 0x0003,
            Self::TsStackSigned => 0x0004,
            Self::Unknown(v) => v,
        }
    }

    /// Returns `true` if this is the common PKCS#7 `SignedData` type used by
    /// Authenticode.
    #[must_use]
    pub const fn is_authenticode(self) -> bool {
        matches!(self, Self::PkcsSignedData)
    }
}

impl fmt::Display for CertificateType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X509 => write!(f, "X509"),
            Self::PkcsSignedData => write!(f, "PKCS#7 SignedData"),
            Self::Reserved1 => write!(f, "Reserved1"),
            Self::TsStackSigned => write!(f, "TS Stack Signed"),
            Self::Unknown(v) => write!(f, "Unknown({v:#06x})"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WinCertificate
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed `WIN_CERTIFICATE` structure.
///
/// ```text
/// typedef struct _WIN_CERTIFICATE {
///     DWORD dwLength;       // total length including header
///     WORD  wRevision;      // 0x0200 for WIN_CERT_REVISION_2_0
///     WORD  wCertificateType;
///     BYTE  bCertificate[]; // DER-encoded certificate data
/// } WIN_CERTIFICATE;
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WinCertificate {
    /// File offset at which this entry was found.
    pub file_offset: usize,
    /// Total length of the entry including the 8-byte header.
    pub dw_length: u32,
    /// Revision (0x0200 for spec-conformant entries).
    pub w_revision: u16,
    /// Certificate type.
    pub cert_type: CertificateType,
    /// The raw certificate payload (everything after the 8-byte header).
    pub payload: Vec<u8>,
}

impl WinCertificate {
    /// Parse a single `WIN_CERTIFICATE` from `data` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`CertError`] if the buffer is too short or the entry is
    /// malformed.
    pub fn parse(data: &[u8], offset: usize) -> Result<Self, CertError> {
        let header_end = offset + 8;
        if data.len() < header_end {
            return Err(CertError::TooShort {
                needed: header_end,
                got: data.len(),
            });
        }
        let dw_length = r32(data, offset);
        if dw_length < 8 {
            return Err(CertError::MalformedEntry {
                offset,
                reason: format!("dwLength={dw_length} is less than the 8-byte header"),
            });
        }
        let end = offset + dw_length as usize;
        if data.len() < end {
            return Err(CertError::TooShort {
                needed: end,
                got: data.len(),
            });
        }
        let w_revision = r16(data, offset + 4);
        let cert_type = CertificateType::from_raw(r16(data, offset + 6));
        let payload = data[offset + 8..end].to_vec();
        Ok(Self {
            file_offset: offset,
            dw_length,
            w_revision,
            cert_type,
            payload,
        })
    }

    /// Serialize this `WIN_CERTIFICATE` to bytes (8-byte aligned).
    ///
    /// # Panics
    /// Panics if the total serialized size exceeds `u32::MAX`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let raw_len = 8 + self.payload.len();
        let pad = (8 - raw_len % 8) % 8;
        let total = raw_len + pad;
        let mut out = Vec::with_capacity(total);
        let dw = u32::try_from(total).expect("certificate size fits in u32");
        out.extend_from_slice(&dw.to_le_bytes());
        out.extend_from_slice(&self.w_revision.to_le_bytes());
        out.extend_from_slice(&self.cert_type.to_raw().to_le_bytes());
        out.extend_from_slice(&self.payload);
        out.extend(std::iter::repeat_n(0u8, pad));
        out
    }

    /// Returns `true` if `w_revision == 0x0200` (spec-conformant revision).
    #[must_use]
    pub const fn is_spec_revision(&self) -> bool {
        self.w_revision == 0x0200
    }

    /// Payload length in bytes (excluding the 8-byte header).
    #[must_use]
    pub const fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// Total on-disk size rounded up to 8-byte alignment.
    #[must_use]
    pub const fn aligned_size(&self) -> usize {
        let raw = 8 + self.payload.len();
        align_up(raw, 8)
    }
}

impl fmt::Display for WinCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WIN_CERTIFICATE @ {:#x}: type={} rev={:#06x} payload={} bytes",
            self.file_offset,
            self.cert_type,
            self.w_revision,
            self.payload.len(),
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PeCertTable
// ─────────────────────────────────────────────────────────────────────────────

/// Manages the certificate table of a PE binary.
///
/// The certificate table lives at a file offset (not an RVA) recorded in the
/// security data directory entry.  [`PeCertTable`] reads the table from an
/// existing PE buffer, provides iteration and query operations, and can produce
/// a modified PE buffer with updated certificate entries.
pub struct PeCertTable {
    /// The underlying PE bytes.
    data: Vec<u8>,
    /// File offset of the certificate table.
    cert_offset: usize,
    /// Total byte size of the certificate table.
    cert_size: usize,
    /// Parsed entries.
    entries: Vec<WinCertificate>,
}

impl PeCertTable {
    /// Parse the certificate table from a PE image buffer.
    ///
    /// If no security data directory is present, returns
    /// [`CertError::NoCertTable`].
    ///
    /// # Errors
    ///
    /// Returns [`CertError`] on truncated data or malformed PE structure.
    pub fn parse(data: Vec<u8>) -> Result<Self, CertError> {
        let (cert_offset, cert_size) = security_directory(&data)?;
        if cert_offset == 0 || cert_size == 0 {
            return Err(CertError::NoCertTable);
        }
        let end = cert_offset + cert_size;
        if data.len() < end {
            return Err(CertError::TooShort {
                needed: end,
                got: data.len(),
            });
        }
        let entries = parse_entries(&data, cert_offset, cert_offset + cert_size)?;
        Ok(Self {
            data,
            cert_offset,
            cert_size,
            entries,
        })
    }

    /// Parse a PE image that may not have a certificate table.  In that case
    /// the table is treated as empty.
    ///
    /// # Errors
    ///
    /// Returns [`CertError`] if the PE header is invalid.
    pub fn parse_or_empty(data: Vec<u8>) -> Result<Self, CertError> {
        let (cert_offset, cert_size) = security_directory(&data).unwrap_or((0, 0));
        let entries = if cert_offset > 0 && cert_size > 0 {
            let end = cert_offset + cert_size;
            if data.len() >= end {
                parse_entries(&data, cert_offset, end).unwrap_or_default()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        Ok(Self {
            data,
            cert_offset,
            cert_size,
            entries,
        })
    }

    /// Number of certificate entries in the table.
    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Iterate over all parsed certificate entries.
    pub fn iter(&self) -> impl Iterator<Item = &WinCertificate> {
        self.entries.iter()
    }

    /// Return the certificate at `index`.
    ///
    /// # Errors
    ///
    /// Returns [`CertError::IndexOutOfRange`] if the index is invalid.
    pub fn get(&self, index: usize) -> Result<&WinCertificate, CertError> {
        self.entries
            .get(index)
            .ok_or(CertError::IndexOutOfRange(index))
    }

    /// Return all entries whose type matches `cert_type`.
    #[must_use]
    pub fn by_type(&self, cert_type: CertificateType) -> Vec<&WinCertificate> {
        self.entries
            .iter()
            .filter(|e| e.cert_type == cert_type)
            .collect()
    }

    /// Returns `true` if any Authenticode (PKCS#7 `SignedData`) entry is present.
    #[must_use]
    pub fn has_authenticode(&self) -> bool {
        self.entries.iter().any(|e| e.cert_type.is_authenticode())
    }

    /// File offset of the certificate table.
    #[must_use]
    pub const fn cert_offset(&self) -> usize {
        self.cert_offset
    }

    /// Total byte size of the certificate table as recorded in the data directory.
    #[must_use]
    pub const fn cert_size(&self) -> usize {
        self.cert_size
    }

    /// Strip all existing certificate entries and return the modified PE bytes.
    ///
    /// This overwrites the certificate table data with zeros and clears the
    /// security data directory entry.
    ///
    /// # Errors
    ///
    /// Returns [`CertError`] if the buffer is too short or the PE header is
    /// malformed.
    pub fn strip_all(mut self) -> Result<Vec<u8>, CertError> {
        if self.cert_offset > 0 && self.cert_size > 0 {
            let end = (self.cert_offset + self.cert_size).min(self.data.len());
            self.data[self.cert_offset..end].fill(0);
        }
        clear_security_directory(&mut self.data)?;
        Ok(self.data)
    }

    /// Replace all existing certificates with a single new entry and return the
    /// modified PE bytes.
    ///
    /// The new entry is appended at the end of the file; the existing table
    /// (if any) is zeroed.
    ///
    /// # Errors
    ///
    /// Returns [`CertError`] on malformed PE header.
    ///
    /// # Panics
    /// Panics if the new certificate offset or size exceeds `u32::MAX`.
    pub fn replace_with(mut self, new_cert: &WinCertificate) -> Result<Vec<u8>, CertError> {
        // Zero old table
        if self.cert_offset > 0 && self.cert_size > 0 {
            let end = (self.cert_offset + self.cert_size).min(self.data.len());
            self.data[self.cert_offset..end].fill(0);
        }
        // Append new entry
        let new_offset = self.data.len();
        let blob = new_cert.to_bytes();
        let new_size = blob.len();
        self.data.extend_from_slice(&blob);
        update_security_directory(
            &mut self.data,
            u32::try_from(new_offset).expect("offset fits in u32"),
            u32::try_from(new_size).expect("size fits in u32"),
        )?;
        Ok(self.data)
    }

    /// Append a new certificate entry to the PE without removing existing ones.
    ///
    /// # Errors
    ///
    /// Returns [`CertError`] on malformed PE header.
    ///
    /// # Panics
    /// Panics if the certificate offset or combined size exceeds `u32::MAX`.
    pub fn append(mut self, new_cert: &WinCertificate) -> Result<Vec<u8>, CertError> {
        let blob = new_cert.to_bytes();
        let extra = blob.len();
        let new_offset = if self.cert_offset == 0 {
            self.data.len()
        } else {
            self.cert_offset
        };
        let new_size = self.cert_size.checked_add(extra).ok_or_else(|| {
            CertError::MalformedEntry {
                offset: self.cert_offset,
                reason: "certificate table size overflow".to_string(),
            }
        })?;
        // Place blob after existing table (or at end)
        let append_offset = self.cert_offset + self.cert_size;
        if append_offset >= self.data.len() {
            self.data.extend_from_slice(&blob);
        } else {
            // Insert is not efficient, but correctness over performance here
            let tail = self.data[append_offset..].to_vec();
            self.data.truncate(append_offset);
            self.data.extend_from_slice(&blob);
            self.data.extend_from_slice(&tail);
        }
        update_security_directory(
            &mut self.data,
            u32::try_from(new_offset).expect("offset fits in u32"),
            u32::try_from(new_size).expect("size fits in u32"),
        )?;
        Ok(self.data)
    }

    /// Summary of the certificate table.
    #[must_use]
    pub fn summary(&self) -> CertTableSummary {
        CertTableSummary {
            offset: self.cert_offset,
            total_size: self.cert_size,
            entry_count: self.entries.len(),
            has_authenticode: self.has_authenticode(),
        }
    }
}

impl fmt::Debug for PeCertTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PeCertTable {{ offset={:#x} size={} entries={} }}",
            self.cert_offset,
            self.cert_size,
            self.entries.len()
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CertTableSummary
// ─────────────────────────────────────────────────────────────────────────────

/// Summary information about the certificate table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertTableSummary {
    /// File offset of the table.
    pub offset: usize,
    /// Total size of the table in bytes.
    pub total_size: usize,
    /// Number of parsed entries.
    pub entry_count: usize,
    /// Whether at least one Authenticode entry is present.
    pub has_authenticode: bool,
}

impl fmt::Display for CertTableSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CertTable @ {:#x}: {} bytes, {} entries, authenticode={}",
            self.offset, self.total_size, self.entry_count, self.has_authenticode
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CertificateBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Builder for constructing a new `WIN_CERTIFICATE` entry.
#[derive(Debug, Default)]
pub struct CertificateBuilder {
    revision: u16,
    cert_type: Option<CertificateType>,
    payload: Vec<u8>,
}

impl CertificateBuilder {
    /// Create a new builder defaulting to revision 2.0 and PKCS#7 type.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            revision: 0x0200,
            cert_type: Some(CertificateType::PkcsSignedData),
            payload: Vec::new(),
        }
    }

    /// Set the revision field.
    #[must_use]
    pub const fn revision(mut self, rev: u16) -> Self {
        self.revision = rev;
        self
    }

    /// Set the certificate type.
    #[must_use]
    pub const fn cert_type(mut self, ct: CertificateType) -> Self {
        self.cert_type = Some(ct);
        self
    }

    /// Set the payload (DER-encoded PKCS#7 or X.509 data).
    #[must_use]
    pub fn payload(mut self, data: Vec<u8>) -> Self {
        self.payload = data;
        self
    }

    /// Consume the builder and produce a [`WinCertificate`].
    ///
    /// # Panics
    /// Panics if `8 + payload.len()` exceeds `u32::MAX`.
    #[must_use]
    pub fn build(self) -> WinCertificate {
        let cert_type = self.cert_type.unwrap_or(CertificateType::PkcsSignedData);
        let dw_length = u32::try_from(8 + self.payload.len()).expect("certificate length fits in u32");
        WinCertificate {
            file_offset: 0,
            dw_length,
            w_revision: self.revision,
            cert_type,
            payload: self.payload,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Private helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the (`file_offset`, size) of the security data directory from the PE.
fn security_directory(data: &[u8]) -> Result<(usize, usize), CertError> {
    if data.len() < 64 {
        return Err(CertError::TooShort {
            needed: 64,
            got: data.len(),
        });
    }
    let pe_off = r32(data, 60) as usize;
    if pe_off + 24 + 2 > data.len() {
        return Err(CertError::InvalidHeader(format!(
            "pe_off={pe_off:#x} + 26 > len={}",
            data.len()
        )));
    }
    let sig = r32(data, pe_off);
    if sig != 0x0000_4550 {
        return Err(CertError::InvalidHeader("PE signature missing".to_string()));
    }
    let opt_off = pe_off + 24;
    let magic = r16(data, opt_off);
    let is_64 = magic == 0x020B;
    let dd_base = if is_64 { opt_off + 112 } else { opt_off + 96 };
    let sec_off = dd_base + 4 * 8; // DataDirectory[4]
    if sec_off + 8 > data.len() {
        return Ok((0, 0));
    }
    let rva = r32(data, sec_off) as usize;
    let sz = r32(data, sec_off + 4) as usize;
    Ok((rva, sz))
}

/// Parse all `WIN_CERTIFICATE` entries in `data[start..end]`.
fn parse_entries(
    data: &[u8],
    start: usize,
    end: usize,
) -> Result<Vec<WinCertificate>, CertError> {
    let mut off = start;
    let mut result = Vec::new();
    while off < end {
        if off + 8 > end {
            break;
        }
        let cert = WinCertificate::parse(data, off)?;
        let aligned = align_up(cert.dw_length as usize, 8);
        off += aligned.max(8);
        result.push(cert);
    }
    Ok(result)
}

/// Clear the security data directory entry.
fn clear_security_directory(data: &mut [u8]) -> Result<(), CertError> {
    update_security_directory(data, 0, 0)
}

/// Update the security data directory entry.
fn update_security_directory(data: &mut [u8], rva: u32, size: u32) -> Result<(), CertError> {
    if data.len() < 64 {
        return Err(CertError::TooShort {
            needed: 64,
            got: data.len(),
        });
    }
    let pe_off = r32(data, 60) as usize;
    if pe_off + 24 + 2 > data.len() {
        return Err(CertError::InvalidHeader("truncated".to_string()));
    }
    let opt_off = pe_off + 24;
    let magic = r16(data, opt_off);
    let is_64 = magic == 0x020B;
    let dd_base = if is_64 { opt_off + 112 } else { opt_off + 96 };
    let sec_off = dd_base + 4 * 8;
    if sec_off + 8 > data.len() {
        return Err(CertError::TooShort {
            needed: sec_off + 8,
            got: data.len(),
        });
    }
    w32(data, sec_off, rva);
    w32(data, sec_off + 4, size);
    Ok(())
}

#[inline]
const fn align_up(v: usize, align: usize) -> usize {
    (v + align - 1) & !(align - 1)
}

#[inline]
fn r16(data: &[u8], off: usize) -> u16 {
    if off + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[off], data[off + 1]])
}

#[inline]
fn r32(data: &[u8], off: usize) -> u32 {
    if off + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

#[inline]
fn w32(data: &mut [u8], off: usize, val: u32) {
    data[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cert_type_roundtrip() {
        for &raw in &[0x0001u16, 0x0002, 0x0003, 0x0004, 0xFFFF] {
            assert_eq!(CertificateType::from_raw(raw).to_raw(), raw);
        }
    }

    #[test]
    fn test_cert_type_authenticode() {
        assert!(CertificateType::PkcsSignedData.is_authenticode());
        assert!(!CertificateType::X509.is_authenticode());
    }

    #[test]
    fn test_win_certificate_to_bytes_alignment() {
        let cert = CertificateBuilder::new().payload(vec![0xAAu8; 5]).build();
        let bytes = cert.to_bytes();
        // 8-byte header + 5 bytes payload → 13 bytes → pad to 16
        assert_eq!(bytes.len(), 16);
        assert_eq!(bytes.len() % 8, 0);
    }

    #[test]
    fn test_win_certificate_parse_roundtrip() {
        let payload = vec![0x30u8, 0x82, 0x01, 0x00];
        let orig = CertificateBuilder::new().payload(payload.clone()).build();
        let blob = orig.to_bytes();
        let parsed = WinCertificate::parse(&blob, 0).unwrap();
        assert_eq!(parsed.cert_type, CertificateType::PkcsSignedData);
        assert_eq!(parsed.w_revision, 0x0200);
        assert_eq!(&parsed.payload[..payload.len()], payload.as_slice());
    }

    #[test]
    fn test_win_certificate_display() {
        let cert = CertificateBuilder::new().payload(vec![0u8; 10]).build();
        let s = format!("{cert}");
        assert!(s.contains("PKCS#7"));
    }

    #[test]
    fn test_parse_malformed_too_short_header() {
        let data = vec![0u8; 4]; // need at least 8
        assert!(matches!(
            WinCertificate::parse(&data, 0),
            Err(CertError::TooShort { .. })
        ));
    }

    #[test]
    fn test_parse_malformed_zero_length() {
        let mut data = vec![0u8; 16];
        // dwLength = 0 → malformed
        data[0] = 0;
        data[1] = 0;
        data[2] = 0;
        data[3] = 0;
        assert!(matches!(
            WinCertificate::parse(&data, 0),
            Err(CertError::MalformedEntry { .. })
        ));
    }

    #[test]
    fn test_cert_builder_defaults() {
        let cert = CertificateBuilder::new().build();
        assert_eq!(cert.w_revision, 0x0200);
        assert_eq!(cert.cert_type, CertificateType::PkcsSignedData);
        assert!(cert.is_spec_revision());
        assert_eq!(cert.payload_len(), 0);
    }

    #[test]
    fn test_aligned_size() {
        let cert = CertificateBuilder::new().payload(vec![0u8; 1]).build();
        assert_eq!(cert.aligned_size(), 16); // 8+1 → pad to 16
        let cert2 = CertificateBuilder::new().payload(vec![0u8; 8]).build();
        assert_eq!(cert2.aligned_size(), 16); // 8+8 = 16 exactly
    }
}
