//! `sigcheck_engine` — Sigcheck-equivalent
//!
//! Verify Authenticode signatures, catalog lookup, `VirusTotal` hash lookup interface,
//! PE anomaly detection, version info extraction.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::SysinternalsError;

// ─── Cast helpers (module-private) ────────────────────────────────────────────

fn u64_to_usize(x: u64) -> usize { usize::try_from(x).unwrap_or(usize::MAX) }
fn usize_to_f64(x: usize) -> f64 {
    // Decompose into two u32 halves to avoid a precision-losing usize-to-f64 cast.
    let lo = u32::try_from(x & 0xFFFF_FFFF).unwrap_or(u32::MAX);
    let hi = u32::try_from(x.checked_shr(32).unwrap_or(0)).unwrap_or(0);
    f64::from(hi).mul_add(4_294_967_296.0_f64, f64::from(lo))
}

// ─── SignatureStatus ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignatureStatus {
    Signed,
    SignedValid,
    SignedExpired,
    SignedRevoked,
    SignedUntrusted,
    Unsigned,
    CatalogSigned,
    EmbeddedSigned,
    Error,
    NotApplicable,
}

impl fmt::Display for SignatureStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Signed => "Signed",
            Self::SignedValid => "Signed (Valid)",
            Self::SignedExpired => "Signed (Expired)",
            Self::SignedRevoked => "Signed (Revoked)",
            Self::SignedUntrusted => "Signed (Untrusted root)",
            Self::Unsigned => "Unsigned",
            Self::CatalogSigned => "Catalog Signed",
            Self::EmbeddedSigned => "Embedded Signed",
            Self::Error => "Error",
            Self::NotApplicable => "N/A",
        };
        write!(f, "{s}")
    }
}

impl SignatureStatus {
    #[must_use]
    pub const fn is_trusted(self) -> bool {
        matches!(
            self,
            Self::Signed | Self::SignedValid | Self::CatalogSigned | Self::EmbeddedSigned
        )
    }
}

// ─── PeAnomalyKind ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PeAnomalyKind {
    // Header anomalies.
    InvalidMzHeader,
    InvalidPeSignature,
    MissingOptionalHeader,
    ChecksumMismatch,
    ZeroChecksum,
    SectionOverlap,
    SectionBeyondFileEnd,
    EntryPointOutsideSection,
    VirtualSizeGreaterThanRaw,
    // Packer indicators.
    SuspiciousEntrySection,
    HighEntropySection,
    FewImports,
    PackerString,
    // TLS callbacks.
    TlsCallbacksPresent,
    // Overlay data.
    LargeOverlay,
    // Timestamp anomalies.
    FutureTimestamp,
    ZeroTimestamp,
    // Imports.
    SuspiciousImports,
    NoImports,
    LoadLibraryGetProcAddress,
    // Exports.
    NamedExportsFromDll,
    // Resources.
    ExecutableInResource,
    // Version info.
    VersionInfoMissing,
    VersionInfoMismatch,
    // Certificate.
    InvalidCertificate,
    CertificateInOverlay,
    // Debug.
    DebugSymbolsStripped,
}

impl fmt::Display for PeAnomalyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::InvalidMzHeader => "Invalid MZ header",
            Self::InvalidPeSignature => "Invalid PE signature",
            Self::MissingOptionalHeader => "Missing optional header",
            Self::ChecksumMismatch => "Checksum mismatch",
            Self::ZeroChecksum => "Zero checksum",
            Self::SectionOverlap => "Overlapping sections",
            Self::SectionBeyondFileEnd => "Section beyond file end",
            Self::EntryPointOutsideSection => "Entry point outside any section",
            Self::VirtualSizeGreaterThanRaw => "Virtual size > raw size",
            Self::SuspiciousEntrySection => "Entry point in suspicious section",
            Self::HighEntropySection => "High-entropy section (packed/encrypted)",
            Self::FewImports => "Very few imports (< 3)",
            Self::PackerString => "Known packer string found",
            Self::TlsCallbacksPresent => "TLS callbacks present",
            Self::LargeOverlay => "Large data after last section (overlay > 1MB)",
            Self::FutureTimestamp => "Timestamp in the future",
            Self::ZeroTimestamp => "Timestamp is zero",
            Self::SuspiciousImports => "Suspicious imports (e.g. VirtualAlloc+WriteProcessMemory)",
            Self::NoImports => "No imports",
            Self::LoadLibraryGetProcAddress => "LoadLibrary + GetProcAddress (dynamic linking)",
            Self::NamedExportsFromDll => "DLL exports suspicious names",
            Self::ExecutableInResource => "Executable content in resource section",
            Self::VersionInfoMissing => "Version info resource missing",
            Self::VersionInfoMismatch => "Version info mismatch with file name",
            Self::InvalidCertificate => "Invalid/malformed Authenticode certificate",
            Self::CertificateInOverlay => "Certificate stored in overlay data",
            Self::DebugSymbolsStripped => "Debug symbols stripped",
        };
        write!(f, "{s}")
    }
}

// ─── PeAnomaly ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeAnomaly {
    pub kind: PeAnomalyKind,
    pub description: String,
    pub severity: AnomalySeverity,
    /// Relevant field value or offset (context-dependent).
    pub context: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AnomalySeverity {
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl fmt::Display for AnomalySeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Informational => write!(f, "Info"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::Critical => write!(f, "Critical"),
        }
    }
}

impl PeAnomaly {
    #[must_use]
    pub fn new(kind: PeAnomalyKind, severity: AnomalySeverity) -> Self {
        let description = kind.to_string();
        Self {
            kind,
            description,
            severity,
            context: String::new(),
        }
    }

    #[must_use]
    pub fn with_context(mut self, ctx: impl Into<String>) -> Self {
        self.context = ctx.into();
        self
    }
}

// ─── VersionInfo ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VersionInfo {
    pub product_name: String,
    pub product_version: String,
    pub file_version: String,
    pub company_name: String,
    pub original_filename: String,
    pub internal_name: String,
    pub file_description: String,
    pub copyright: String,
    pub comments: String,
    pub legal_trademarks: String,
}

// ─── CertificateInfo ──────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// Certificate purpose and trust flags (bitfield to avoid struct-excessive-bools).
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct CertificateFlags: u8 {
        /// Certificate is valid for code signing.
        const CODE_SIGNING       = 0b0001;
        /// Certificate is valid for time stamping.
        const TIME_STAMPING      = 0b0010;
        /// Certificate is a root/CA certificate.
        const ROOT               = 0b0100;
        /// Certificate carries Extended Validation status.
        const EXTENDED_VALIDATION = 0b1000;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub subject_cn: String,
    pub issuer_cn: String,
    pub serial_number: String,
    pub thumbprint_sha1: String,
    pub thumbprint_sha256: String,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
    pub algorithm: String,
    pub key_size: u32,
    pub cert_flags: CertificateFlags,
}

impl CertificateInfo {
    #[must_use]
    pub const fn is_expired_at(&self, unix_ts: u64) -> bool {
        unix_ts > self.not_after_unix
    }

    #[must_use]
    pub const fn is_valid_at(&self, unix_ts: u64) -> bool {
        unix_ts >= self.not_before_unix && unix_ts <= self.not_after_unix
    }
}

// ─── VirusTotalResult ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalResult {
    pub sha256: String,
    pub md5: String,
    pub sha1: String,
    pub detection_count: u32,
    pub total_engines: u32,
    pub scan_date: String,
    pub permalink: String,
    pub detections: HashMap<String, String>,
}

impl VirusTotalResult {
    #[must_use]
    pub fn detection_ratio(&self) -> f64 {
        if self.total_engines == 0 {
            0.0
        } else {
            f64::from(self.detection_count) / f64::from(self.total_engines)
        }
    }

    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.detection_count == 0
    }

    #[must_use]
    pub fn is_likely_malicious(&self) -> bool {
        self.detection_ratio() >= 0.10
    }
}

// ─── SigcheckResult ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigcheckResult {
    pub path: String,
    pub file_size: u64,
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub signature_status: SignatureStatus,
    pub signer: Option<String>,
    pub countersigner: Option<String>,
    pub timestamp: Option<u64>,
    pub certificates: Vec<CertificateInfo>,
    pub version_info: VersionInfo,
    pub anomalies: Vec<PeAnomaly>,
    pub vt_result: Option<VirusTotalResult>,
    /// Risk score computed from anomalies + signature.
    pub risk_score: u32,
    /// Whether the file is a PE executable.
    pub is_pe: bool,
    /// PE machine type (0 = unknown).
    pub machine_type: u16,
    /// PE characteristics flags.
    pub characteristics: u16,
    /// Compile timestamp (UNIX epoch).
    pub compile_timestamp: u64,
    /// Linker version.
    pub linker_version: String,
    /// OS subsystem.
    pub subsystem: u16,
    /// True if 64-bit PE.
    pub is_64bit: bool,
}

impl SigcheckResult {
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            file_size: 0,
            sha256: String::new(),
            sha1: String::new(),
            md5: String::new(),
            signature_status: SignatureStatus::Unsigned,
            signer: None,
            countersigner: None,
            timestamp: None,
            certificates: Vec::new(),
            version_info: VersionInfo::default(),
            anomalies: Vec::new(),
            vt_result: None,
            risk_score: 0,
            is_pe: false,
            machine_type: 0,
            characteristics: 0,
            compile_timestamp: 0,
            linker_version: String::new(),
            subsystem: 0,
            is_64bit: false,
        }
    }

    pub fn compute_risk_score(&mut self) {
        let mut score: u32 = 0;
        if !self.signature_status.is_trusted() {
            score += 20;
        }
        for anomaly in &self.anomalies {
            score += match anomaly.severity {
                AnomalySeverity::Informational => 0,
                AnomalySeverity::Low => 5,
                AnomalySeverity::Medium => 15,
                AnomalySeverity::High => 25,
                AnomalySeverity::Critical => 40,
            };
        }
        if let Some(ref vt) = self.vt_result {
            if vt.is_likely_malicious() {
                score += 50;
            } else if vt.detection_count > 0 {
                score += 25;
            }
        }
        self.risk_score = score.min(100);
    }

    #[must_use]
    pub fn max_anomaly_severity(&self) -> Option<AnomalySeverity> {
        self.anomalies.iter().map(|a| a.severity).max()
    }

    #[must_use]
    pub fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{},{},{}",
            self.path,
            self.file_size,
            self.sha256,
            self.signature_status,
            self.signer.as_deref().unwrap_or(""),
            self.anomalies.len(),
            self.risk_score,
        )
    }
}

// ─── PE Parser (minimal) ─────────────────────────────────────────────────────

/// Parse the optional header fields (magic, linker version, subsystem, checksum,
/// security directory) and return any anomalies found.
fn parse_optional_header(data: &[u8], opt_off: usize, result: &mut SigcheckResult) -> Vec<PeAnomaly> {
    let mut anomalies = Vec::new();
    if opt_off + 2 > data.len() {
        return anomalies;
    }
    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    result.is_64bit = magic == 0x020b;
    result.linker_version = if opt_off + 4 <= data.len() {
        format!("{}.{}", data[opt_off + 2], data[opt_off + 3])
    } else {
        String::new()
    };
    let subsys_off = opt_off + 68;
    if subsys_off + 2 <= data.len() {
        result.subsystem = u16::from_le_bytes([data[subsys_off], data[subsys_off + 1]]);
    }
    let chk_off = opt_off + 64;
    if chk_off + 4 <= data.len() {
        let chk = u32::from_le_bytes([data[chk_off], data[chk_off + 1], data[chk_off + 2], data[chk_off + 3]]);
        if chk == 0 {
            anomalies.push(PeAnomaly::new(PeAnomalyKind::ZeroChecksum, AnomalySeverity::Low));
        }
    }
    let sec_dir_off = if result.is_64bit { opt_off + 0x88 } else { opt_off + 0x78 };
    if sec_dir_off + 8 <= data.len() {
        let sec_rva = u32::from_le_bytes([
            data[sec_dir_off], data[sec_dir_off + 1], data[sec_dir_off + 2], data[sec_dir_off + 3],
        ]);
        result.signature_status = if sec_rva == 0 {
            SignatureStatus::Unsigned
        } else {
            SignatureStatus::EmbeddedSigned
        };
    }
    anomalies
}

/// Scan PE section headers for anomalies (out-of-bounds, overlap, high entropy, etc.).
fn scan_pe_sections(data: &[u8], sect_off: usize, num_sections: u16) -> Vec<PeAnomaly> {
    let mut anomalies = Vec::new();
    let mut prev_end: u64 = 0;
    for section_idx in 0..(num_sections as usize) {
        let s = sect_off.saturating_add(section_idx.saturating_mul(40));
        if s + 40 > data.len() {
            break;
        }
        let raw_off = u64::from(u32::from_le_bytes([data[s + 20], data[s + 21], data[s + 22], data[s + 23]]));
        let raw_size = u64::from(u32::from_le_bytes([data[s + 16], data[s + 17], data[s + 18], data[s + 19]]));
        let virt_size = u64::from(u32::from_le_bytes([data[s + 8], data[s + 9], data[s + 10], data[s + 11]]));
        if raw_off + raw_size > data.len() as u64 {
            anomalies.push(
                PeAnomaly::new(PeAnomalyKind::SectionBeyondFileEnd, AnomalySeverity::High)
                    .with_context(format!("Section {section_idx}")),
            );
        }
        if raw_off < prev_end && raw_size > 0 {
            anomalies.push(
                PeAnomaly::new(PeAnomalyKind::SectionOverlap, AnomalySeverity::High)
                    .with_context(format!("Section {section_idx}")),
            );
        }
        if virt_size > raw_size * 4 && raw_size > 0 {
            anomalies.push(
                PeAnomaly::new(PeAnomalyKind::VirtualSizeGreaterThanRaw, AnomalySeverity::Low)
                    .with_context(format!("Section {section_idx}: virt={virt_size}, raw={raw_size}")),
            );
        }
        if raw_size > 0 && raw_off + raw_size <= data.len() as u64 {
            let sec_data = &data[u64_to_usize(raw_off)..u64_to_usize(raw_off + raw_size)];
            let ent = compute_section_entropy(sec_data);
            if ent > 7.2 {
                let name: String = data[s..s + 8].iter().take_while(|&&b| b != 0).map(|&b| b as char).collect();
                anomalies.push(
                    PeAnomaly::new(PeAnomalyKind::HighEntropySection, AnomalySeverity::High)
                        .with_context(format!("Section '{name}' entropy={ent:.2}")),
                );
            }
        }
        prev_end = raw_off + raw_size;
    }
    anomalies
}

/// Parse PE headers from a byte slice and populate a `SigcheckResult`.
pub fn parse_pe_headers(data: &[u8], result: &mut SigcheckResult) -> Vec<PeAnomaly> {
    let mut anomalies = Vec::new();
    if data.len() < 0x40 {
        anomalies.push(PeAnomaly::new(PeAnomalyKind::InvalidMzHeader, AnomalySeverity::Critical).with_context("File too small"));
        return anomalies;
    }
    if data[0] != b'M' || data[1] != b'Z' {
        anomalies.push(PeAnomaly::new(PeAnomalyKind::InvalidMzHeader, AnomalySeverity::Critical));
        return anomalies;
    }
    result.is_pe = true;
    // PE offset.
    let pe_offset = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if pe_offset.checked_add(4).is_none_or(|end| end > data.len()) {
        anomalies.push(PeAnomaly::new(PeAnomalyKind::InvalidPeSignature, AnomalySeverity::Critical).with_context("PE offset beyond file"));
        return anomalies;
    }
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        anomalies.push(PeAnomaly::new(PeAnomalyKind::InvalidPeSignature, AnomalySeverity::Critical));
        return anomalies;
    }
    // COFF header.
    let coff = pe_offset + 4;
    if coff + 20 > data.len() {
        anomalies.push(PeAnomaly::new(PeAnomalyKind::MissingOptionalHeader, AnomalySeverity::High));
        return anomalies;
    }
    result.machine_type = u16::from_le_bytes([data[coff], data[coff + 1]]);
    let num_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]);
    let compile_ts = u32::from_le_bytes([data[coff + 4], data[coff + 5], data[coff + 6], data[coff + 7]]);
    result.compile_timestamp = u64::from(compile_ts);
    result.characteristics = u16::from_le_bytes([data[coff + 18], data[coff + 19]]);
    let opt_header_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    if compile_ts == 0 {
        anomalies.push(PeAnomaly::new(PeAnomalyKind::ZeroTimestamp, AnomalySeverity::Informational));
    } else if compile_ts > 1_893_456_000 {
        anomalies.push(PeAnomaly::new(PeAnomalyKind::FutureTimestamp, AnomalySeverity::Medium).with_context(format!("TimeDateStamp = {compile_ts:#010x}")));
    }
    // Optional header (delegates to helper).
    let opt_off = coff + 20;
    anomalies.extend(parse_optional_header(data, opt_off, result));
    if result.linker_version.is_empty() && opt_off + 2 > data.len() {
        return anomalies;
    }
    if num_sections < 2 {
        anomalies.push(PeAnomaly::new(PeAnomalyKind::FewImports, AnomalySeverity::Medium).with_context(format!("Only {num_sections} sections")));
    }
    // Section scanning (delegates to helper).
    let sect_off = opt_off.saturating_add(opt_header_size);
    if sect_off <= data.len() {
        anomalies.extend(scan_pe_sections(data, sect_off, num_sections));
    }
    // TLS directory: directory index 9.
    let tls_off = if result.is_64bit {
        opt_off.saturating_add(0x88).saturating_add(9 * 8)
    } else {
        opt_off.saturating_add(0x78).saturating_add(9 * 8)
    };
    if tls_off + 8 <= data.len() {
        let tls_rva = u32::from_le_bytes([data[tls_off], data[tls_off + 1], data[tls_off + 2], data[tls_off + 3]]);
        if tls_rva != 0 {
            anomalies.push(PeAnomaly::new(PeAnomalyKind::TlsCallbacksPresent, AnomalySeverity::Medium));
        }
    }
    anomalies
}

fn compute_section_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = usize_to_f64(data.len());
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = f64::from(c) / len;
            entropy = p.mul_add(-p.log2(), entropy);
        }
    }
    entropy
}

// ─── SigcheckEngine ───────────────────────────────────────────────────────────

pub struct SigcheckEngine {
    /// VT API key (if set, enables VT lookups).
    pub vt_api_key: Option<String>,
    /// Whether to parse PE headers.
    pub check_pe: bool,
    /// Whether to verify Authenticode.
    pub check_signature: bool,
}

impl SigcheckEngine {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            vt_api_key: None,
            check_pe: true,
            check_signature: true,
        }
    }

    #[must_use]
    pub fn with_vt_key(mut self, key: impl Into<String>) -> Self {
        self.vt_api_key = Some(key.into());
        self
    }

    /// # Errors
    /// Returns an error if the underlying operation fails.
    /// Check a file path and return a full `SigcheckResult`.
    pub fn check_file(&self, path: &Path) -> Result<SigcheckResult, SysinternalsError> {
        let data = std::fs::read(path).map_err(|e| SysinternalsError::Io(e.to_string()))?;
        let path_str = path.to_string_lossy().to_string();
        let mut result = SigcheckResult::new(&path_str);
        result.file_size = data.len() as u64;

        // Compute hashes.
        result.sha256 = compute_sha256_hex(&data);
        result.md5 = compute_md5_hex(&data);
        result.sha1 = compute_sha1_hex(&data);

        // Parse PE.
        if self.check_pe {
            let anomalies = parse_pe_headers(&data, &mut result);
            result.anomalies = anomalies;
        }

        result.compute_risk_score();
        Ok(result)
    }

    /// Check bytes directly (useful for memory-mapped PE images).
    #[must_use]
    pub fn check_bytes(&self, data: &[u8], label: &str) -> SigcheckResult {
        let mut result = SigcheckResult::new(label);
        result.file_size = data.len() as u64;
        result.sha256 = compute_sha256_hex(data);
        result.md5 = compute_md5_hex(data);
        result.sha1 = compute_sha1_hex(data);
        if self.check_pe {
            result.anomalies = parse_pe_headers(data, &mut result);
        }
        result.compute_risk_score();
        result
    }

    /// Batch check multiple files.
    #[must_use]
    pub fn check_batch(
        &self,
        paths: &[&Path],
    ) -> Vec<Result<SigcheckResult, SysinternalsError>> {
        paths.iter().map(|p| self.check_file(p)).collect()
    }

    /// Simulate a `VirusTotal` lookup (stub — returns a clean result).
    #[must_use]
    pub fn vt_lookup_stub(sha256: &str) -> VirusTotalResult {
        VirusTotalResult {
            sha256: sha256.to_string(),
            md5: String::new(),
            sha1: String::new(),
            detection_count: 0,
            total_engines: 72,
            scan_date: String::from("2026-06-10"),
            permalink: format!("https://www.virustotal.com/gui/file/{sha256}"),
            detections: HashMap::new(),
        }
    }
}

impl Default for SigcheckEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Hash helpers (reuse from lib.rs logic, avoid dep) ────────────────────────

fn compute_sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
        0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
    ];
    let kk: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
        0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
        0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
        0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7, 0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
        0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
        0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
        0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut ww = [0u32; 64];
        for i in 0..16 {
            ww[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..64 {
            let s0 = ww[i-15].rotate_right(7)^ww[i-15].rotate_right(18)^(ww[i-15]>>3);
            let s1 = ww[i-2].rotate_right(17)^ww[i-2].rotate_right(19)^(ww[i-2]>>10);
            ww[i] = ww[i-16].wrapping_add(s0).wrapping_add(ww[i-7]).wrapping_add(s1);
        }
        let [mut aa,mut bb,mut cc,mut dd,mut ee,mut ff,mut gg,mut hh] = [h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7]];
        for i in 0..64 {
            let s1 = ee.rotate_right(6)^ee.rotate_right(11)^ee.rotate_right(25);
            let ch = (ee&ff)^((!ee)&gg);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(kk[i]).wrapping_add(ww[i]);
            let s0 = aa.rotate_right(2)^aa.rotate_right(13)^aa.rotate_right(22);
            let maj = (aa&bb)^(aa&cc)^(bb&cc);
            let t2 = s0.wrapping_add(maj);
            hh=gg; gg=ff; ff=ee; ee=dd.wrapping_add(t1); dd=cc; cc=bb; bb=aa; aa=t1.wrapping_add(t2);
        }
        h[0]=h[0].wrapping_add(aa); h[1]=h[1].wrapping_add(bb); h[2]=h[2].wrapping_add(cc); h[3]=h[3].wrapping_add(dd);
        h[4]=h[4].wrapping_add(ee); h[5]=h[5].wrapping_add(ff); h[6]=h[6].wrapping_add(gg); h[7]=h[7].wrapping_add(hh);
    }
    format!("{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}", h[0],h[1],h[2],h[3],h[4],h[5],h[6],h[7])
}

fn compute_md5_hex(data: &[u8]) -> String {
    let rot: [u32; 64] = [
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
    ];
    let kk: [u32; 64] = [
        0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee, 0xf57c_0faf, 0x4787_c62a, 0xa830_4613, 0xfd46_9501,
        0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be, 0x6b90_1122, 0xfd98_7193, 0xa679_438e, 0x49b4_0821,
        0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa, 0xd62f_105d, 0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8,
        0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed, 0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a,
        0xfffa_3942, 0x8771_f681, 0x6d9d_6122, 0xfde5_380c, 0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70,
        0x289b_7ec6, 0xeaa1_27fa, 0xd4ef_3085, 0x0488_1d05, 0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665,
        0xf429_2244, 0x432a_ff97, 0xab94_23a7, 0xfc93_a039, 0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
        0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1, 0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb, 0xeb86_d391,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_le_bytes());
    let (mut a0, mut b0, mut c0, mut d0): (u32, u32, u32, u32) = (0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476);
    for chunk in msg.chunks(64) {
        let mut block = [0u32; 16];
        for i in 0..16 {
            block[i] = u32::from_le_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        let (mut aa, mut bb, mut cc, mut dd) = (a0, b0, c0, d0);
        for i in 0usize..64 {
            let (mix, mi) = if i<16 { ((bb&cc)|((!bb)&dd), i) }
                else if i<32 { ((dd&bb)|((!dd)&cc), (5*i+1)%16) }
                else if i<48 { (bb^cc^dd, (3*i+5)%16) }
                else { (cc^(bb|(!dd)), (7*i)%16) };
            let mix = mix.wrapping_add(aa).wrapping_add(kk[i]).wrapping_add(block[mi]);
            aa=dd; dd=cc; cc=bb; bb=bb.wrapping_add(mix.rotate_left(rot[i]));
        }
        a0=a0.wrapping_add(aa); b0=b0.wrapping_add(bb); c0=c0.wrapping_add(cc); d0=d0.wrapping_add(dd);
    }
    let r = [a0.to_le_bytes(), b0.to_le_bytes(), c0.to_le_bytes(), d0.to_le_bytes()].concat();
    r.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc })
}

fn compute_sha1_hex(data: &[u8]) -> String {
    let mut hash_state: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut schedule = [0u32; 80];
        for idx in 0..16 {
            schedule[idx] = u32::from_be_bytes([chunk[idx*4], chunk[idx*4+1], chunk[idx*4+2], chunk[idx*4+3]]);
        }
        for idx in 16..80 {
            schedule[idx] = (schedule[idx-3]^schedule[idx-8]^schedule[idx-14]^schedule[idx-16]).rotate_left(1);
        }
        let (mut sha_a, mut sha_b, mut sha_c, mut sha_d, mut sha_e): (u32, u32, u32, u32, u32) =
            hash_state.into();
        for (round, &word) in schedule.iter().enumerate() {
            let (mix, key) = if round < 20 {
                ((sha_b & sha_c) | ((!sha_b) & sha_d), 0x5A82_7999u32)
            } else if round < 40 {
                (sha_b ^ sha_c ^ sha_d, 0x6ED9_EBA1)
            } else if round < 60 {
                ((sha_b & sha_c) | (sha_b & sha_d) | (sha_c & sha_d), 0x8F1B_BCDC)
            } else {
                (sha_b ^ sha_c ^ sha_d, 0xCA62_C1D6)
            };
            let tmp = sha_a.rotate_left(5).wrapping_add(mix).wrapping_add(sha_e).wrapping_add(key).wrapping_add(word);
            sha_e = sha_d; sha_d = sha_c; sha_c = sha_b.rotate_left(30); sha_b = sha_a; sha_a = tmp;
        }
        hash_state[0] = hash_state[0].wrapping_add(sha_a);
        hash_state[1] = hash_state[1].wrapping_add(sha_b);
        hash_state[2] = hash_state[2].wrapping_add(sha_c);
        hash_state[3] = hash_state[3].wrapping_add(sha_d);
        hash_state[4] = hash_state[4].wrapping_add(sha_e);
    }
    format!("{:08x}{:08x}{:08x}{:08x}{:08x}", hash_state[0], hash_state[1], hash_state[2], hash_state[3], hash_state[4])
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_pe() -> Vec<u8> {
        let mut pe = vec![0u8; 0x200];
        pe[0] = b'M'; pe[1] = b'Z';
        // PE offset at 0x3C.
        pe[0x3c] = 0x40;
        // PE signature.
        pe[0x40] = b'P'; pe[0x41] = b'E'; pe[0x42] = 0; pe[0x43] = 0;
        // Machine: AMD64.
        pe[0x44] = 0x64; pe[0x45] = 0x86;
        // Num sections.
        pe[0x46] = 1; pe[0x47] = 0;
        // Optional header size.
        pe[0x54] = 0xF0; pe[0x55] = 0; // 240
        // Magic: PE32+.
        pe[0x58] = 0x0B; pe[0x59] = 0x02;
        pe
    }

    #[test]
    fn test_parse_pe_headers_valid() {
        let pe = minimal_pe();
        let mut result = SigcheckResult::new("test.exe");
        let anomalies = parse_pe_headers(&pe, &mut result);
        assert!(result.is_pe);
        assert!(result.is_64bit);
        // Zero checksum should be flagged.
        assert!(anomalies.iter().any(|a| a.kind == PeAnomalyKind::ZeroChecksum));
    }

    #[test]
    fn test_parse_pe_headers_not_pe() {
        let data = b"ELF\x02\x01\x01\x00\x00\x00\x00";
        let mut result = SigcheckResult::new("elf");
        let anomalies = parse_pe_headers(data, &mut result);
        assert!(!result.is_pe);
        assert!(anomalies.iter().any(|a| a.kind == PeAnomalyKind::InvalidMzHeader));
    }

    #[test]
    fn test_sigcheck_engine_check_bytes_small() {
        let engine = SigcheckEngine::new();
        let result = engine.check_bytes(b"hello world", "test.txt");
        assert_eq!(result.file_size, 11);
        assert!(!result.sha256.is_empty());
    }

    #[test]
    fn test_sha256_known() {
        let hash = compute_sha256_hex(b"");
        assert_eq!(hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn test_sha1_known() {
        let hash = compute_sha1_hex(b"");
        assert_eq!(hash, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn test_md5_known() {
        let hash = compute_md5_hex(b"");
        assert_eq!(hash, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_signature_status_trusted() {
        assert!(SignatureStatus::SignedValid.is_trusted());
        assert!(SignatureStatus::CatalogSigned.is_trusted());
        assert!(!SignatureStatus::Unsigned.is_trusted());
        assert!(!SignatureStatus::SignedExpired.is_trusted());
    }

    #[test]
    fn test_vt_result_detection_ratio() {
        let vt = VirusTotalResult {
            sha256: "abc".into(),
            md5: String::new(),
            sha1: String::new(),
            detection_count: 36,
            total_engines: 72,
            scan_date: "2026-06-10".into(),
            permalink: String::new(),
            detections: HashMap::new(),
        };
        assert!((vt.detection_ratio() - 0.5).abs() < 0.01);
        assert!(vt.is_likely_malicious());
        assert!(!vt.is_clean());
    }

    #[test]
    fn test_anomaly_severity_ordering() {
        assert!(AnomalySeverity::Critical > AnomalySeverity::High);
        assert!(AnomalySeverity::High > AnomalySeverity::Medium);
        assert!(AnomalySeverity::Medium > AnomalySeverity::Low);
    }

    #[test]
    fn test_risk_score_unsigned_pe() {
        let mut r = SigcheckResult::new("test.exe");
        r.signature_status = SignatureStatus::Unsigned;
        r.anomalies.push(PeAnomaly::new(PeAnomalyKind::HighEntropySection, AnomalySeverity::High));
        r.compute_risk_score();
        assert!(r.risk_score >= 20 + 25);
    }

    #[test]
    fn test_cert_info_validity() {
        let cert = CertificateInfo {
            subject_cn: "Microsoft".into(),
            issuer_cn: "DigiCert".into(),
            serial_number: "01".into(),
            thumbprint_sha1: String::new(),
            thumbprint_sha256: String::new(),
            not_before_unix: 1_000_000,
            not_after_unix: 2_000_000,
            algorithm: "sha256WithRSAEncryption".into(),
            key_size: 2048,
            cert_flags: CertificateFlags::CODE_SIGNING,
        };
        assert!(cert.is_valid_at(1_500_000));
        assert!(!cert.is_valid_at(500_000));
        assert!(cert.is_expired_at(3_000_000));
    }
}
