/// overlay_extractor.rs — Extract and classify data appended after the last PE section.
///
/// A PE overlay is any data that appears after the end of the last raw section.
/// This module:
///   * Locates the overlay region in a PE file
///   * Identifies the overlay format (ZIP, PKCS#7 certificate, self-extractor config, etc.)
///   * Extracts sub-regions (e.g. central directory in a ZIP overlay)
///   * Reports overall characteristics (size, entropy, magic bytes)
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum OverlayError {
    #[error("File buffer is empty")]
    EmptyFile,
    #[error("PE header is malformed: {reason}")]
    MalformedPe { reason: String },
    #[error("No overlay present — file ends at section boundary")]
    NoOverlay,
    #[error("Overlay extraction failed: {detail}")]
    ExtractionFailed { detail: String },
}

// ---------------------------------------------------------------------------
// Section info (minimal — caller supplies this)
// ---------------------------------------------------------------------------

/// Minimal section descriptor needed to locate the overlay.
/// Typically populated from a PE parser (goblin, pelite, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionBoundary {
    /// Name of the section (for diagnostic purposes).
    pub name: String,
    /// Offset within the file where this section's raw data begins.
    pub raw_offset: u32,
    /// Size of the raw data on disk.
    pub raw_size: u32,
}

impl SectionBoundary {
    /// Returns the exclusive end offset of this section's raw data in the file.
    pub fn end_offset(&self) -> u64 {
        self.raw_offset as u64 + self.raw_size as u64
    }
}

// ---------------------------------------------------------------------------
// Overlay kind taxonomy
// ---------------------------------------------------------------------------

/// High-level classification of the detected overlay format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverlayKind {
    /// ZIP archive (local file header magic `PK\x03\x04`).
    Zip,
    /// PKCS#7 / Authenticode signature (DER sequence tag `0x30 0x82`).
    Pkcs7Certificate,
    /// Cabinet file (`.cab`, magic `MSCF`).
    Cabinet,
    /// PDF document (starts with `%PDF`).
    Pdf,
    /// PNG image.
    Png,
    /// JPEG image.
    Jpeg,
    /// 7-Zip archive (`7z\xBC\xAF\x27\x1C`).
    SevenZip,
    /// RAR archive (magic `Rar!\x1A\x07`).
    Rar,
    /// Windows Portable Executable embedded as overlay (MZ header).
    EmbeddedPe,
    /// UEFI firmware volume (`_FVH` header).
    UefiFirmwareVolume,
    /// InnoSetup installer configuration block.
    InnoSetupConfig,
    /// NSIS installer block (magic `NullsoftInst`).
    NsisInstaller,
    /// AutoIt compiled script marker.
    AutoItScript,
    /// UPX decompression stub configuration (`UPX!`).
    UpxStub,
    /// High-entropy blob (likely encrypted or compressed payload).
    HighEntropyBlob,
    /// Raw data that does not match any known format.
    Unknown,
}

impl std::fmt::Display for OverlayKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            OverlayKind::Zip => "ZIP",
            OverlayKind::Pkcs7Certificate => "PKCS7_CERTIFICATE",
            OverlayKind::Cabinet => "CABINET",
            OverlayKind::Pdf => "PDF",
            OverlayKind::Png => "PNG",
            OverlayKind::Jpeg => "JPEG",
            OverlayKind::SevenZip => "7ZIP",
            OverlayKind::Rar => "RAR",
            OverlayKind::EmbeddedPe => "EMBEDDED_PE",
            OverlayKind::UefiFirmwareVolume => "UEFI_FIRMWARE_VOLUME",
            OverlayKind::InnoSetupConfig => "INNO_SETUP_CONFIG",
            OverlayKind::NsisInstaller => "NSIS_INSTALLER",
            OverlayKind::AutoItScript => "AUTOIT_SCRIPT",
            OverlayKind::UpxStub => "UPX_STUB",
            OverlayKind::HighEntropyBlob => "HIGH_ENTROPY_BLOB",
            OverlayKind::Unknown => "UNKNOWN",
        };
        write!(f, "{}", s)
    }
}

// ---------------------------------------------------------------------------
// Magic-byte table
// ---------------------------------------------------------------------------

struct MagicEntry {
    magic: &'static [u8],
    offset: usize,
    kind: OverlayKind,
}

static MAGIC_TABLE: &[MagicEntry] = &[
    MagicEntry { magic: b"PK\x03\x04", offset: 0, kind: OverlayKind::Zip },
    MagicEntry { magic: b"PK\x05\x06", offset: 0, kind: OverlayKind::Zip }, // empty ZIP
    MagicEntry { magic: b"MSCF", offset: 0, kind: OverlayKind::Cabinet },
    MagicEntry { magic: b"%PDF", offset: 0, kind: OverlayKind::Pdf },
    MagicEntry { magic: b"\x89PNG\r\n\x1A\n", offset: 0, kind: OverlayKind::Png },
    MagicEntry { magic: b"\xFF\xD8\xFF", offset: 0, kind: OverlayKind::Jpeg },
    MagicEntry { magic: b"7z\xBC\xAF\x27\x1C", offset: 0, kind: OverlayKind::SevenZip },
    MagicEntry { magic: b"Rar!\x1A\x07", offset: 0, kind: OverlayKind::Rar },
    MagicEntry { magic: b"MZ", offset: 0, kind: OverlayKind::EmbeddedPe },
    MagicEntry { magic: b"NullsoftInst", offset: 4, kind: OverlayKind::NsisInstaller },
    MagicEntry { magic: b"AU3!", offset: 0, kind: OverlayKind::AutoItScript },
    MagicEntry { magic: b"UPX!", offset: 0, kind: OverlayKind::UpxStub },
    // UEFI firmware volume signature at offset 0x28
    MagicEntry { magic: b"_FVH", offset: 0x28, kind: OverlayKind::UefiFirmwareVolume },
    // PKCS#7 DER SEQUENCE tag + long-form length
    MagicEntry { magic: b"\x30\x82", offset: 0, kind: OverlayKind::Pkcs7Certificate },
    // InnoSetup: "Inno Setup Setup Data"
    MagicEntry { magic: b"Inno Setup Setup Data", offset: 0, kind: OverlayKind::InnoSetupConfig },
];

fn detect_overlay_kind(data: &[u8]) -> OverlayKind {
    for entry in MAGIC_TABLE {
        let end = entry.offset + entry.magic.len();
        if data.len() >= end {
            if &data[entry.offset..end] == entry.magic {
                return entry.kind.clone();
            }
        }
    }
    // Fallback: entropy-based classification.
    let entropy = crate_shannon_entropy(data);
    if entropy >= 7.2 {
        OverlayKind::HighEntropyBlob
    } else {
        OverlayKind::Unknown
    }
}

/// Minimal copy of the entropy function so this module has no dep on section_analyzer.
fn crate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

// ---------------------------------------------------------------------------
// ZIP overlay helper
// ---------------------------------------------------------------------------

/// Parsed ZIP End-of-Central-Directory record (EOCD).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZipEocd {
    /// Offset of the EOCD record within the overlay data.
    pub eocd_offset: u64,
    /// Number of entries in the central directory.
    pub total_entries: u16,
    /// Size of the central directory.
    pub cd_size: u32,
    /// Offset of the central directory relative to the start of the overlay.
    pub cd_offset: u32,
    /// ZIP comment (if any).
    pub comment: String,
}

fn find_zip_eocd(data: &[u8]) -> Option<ZipEocd> {
    const EOCD_SIG: &[u8] = b"PK\x05\x06";
    // Search from the end (comment can be up to 64 KiB).
    let min_offset = data.len().saturating_sub(65535 + 22);
    let search_slice = &data[min_offset..];
    for i in (0..search_slice.len().saturating_sub(22)).rev() {
        if &search_slice[i..i + 4] == EOCD_SIG {
            let abs = min_offset + i;
            if abs + 22 > data.len() {
                continue;
            }
            let disk_entries = u16::from_le_bytes([data[abs + 8], data[abs + 9]]);
            let cd_size = u32::from_le_bytes([
                data[abs + 12],
                data[abs + 13],
                data[abs + 14],
                data[abs + 15],
            ]);
            let cd_offset = u32::from_le_bytes([
                data[abs + 16],
                data[abs + 17],
                data[abs + 18],
                data[abs + 19],
            ]);
            let comment_len = u16::from_le_bytes([data[abs + 20], data[abs + 21]]) as usize;
            let comment = if abs.saturating_add(22).saturating_add(comment_len) <= data.len() {
                String::from_utf8_lossy(&data[abs + 22..abs + 22 + comment_len]).into_owned()
            } else {
                String::new()
            };
            return Some(ZipEocd {
                eocd_offset: abs as u64,
                total_entries: disk_entries,
                cd_size,
                cd_offset,
                comment,
            });
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Overlay description
// ---------------------------------------------------------------------------

/// A sub-region identified within the overlay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayRegion {
    /// Offset from the start of the overlay.
    pub offset: u64,
    /// Length of this sub-region in bytes.
    pub length: u64,
    /// Optional label (e.g. "ZIP central directory").
    pub label: String,
}

/// Full description of the overlay found in a PE file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayInfo {
    /// Absolute offset in the original file where the overlay begins.
    pub file_offset: u64,
    /// Total size of the overlay in bytes.
    pub size: u64,
    /// Detected format kind.
    pub kind: OverlayKind,
    /// Shannon entropy of the overlay data.
    pub entropy: f64,
    /// First 16 bytes of the overlay (hex-encoded).
    pub magic_bytes_hex: String,
    /// Sub-regions identified within the overlay (e.g. ZIP directory).
    pub regions: Vec<OverlayRegion>,
    /// Additional format-specific metadata key=value pairs.
    pub metadata: HashMap<String, String>,
}

impl OverlayInfo {
    /// Returns `true` if the overlay is likely a certificate (Authenticode signature).
    pub fn is_certificate(&self) -> bool {
        self.kind == OverlayKind::Pkcs7Certificate
    }

    /// Returns `true` if the overlay appears to be an archive.
    pub fn is_archive(&self) -> bool {
        matches!(
            self.kind,
            OverlayKind::Zip
                | OverlayKind::Cabinet
                | OverlayKind::SevenZip
                | OverlayKind::Rar
        )
    }

    /// Returns `true` if the overlay looks like a second executable.
    pub fn is_embedded_pe(&self) -> bool {
        self.kind == OverlayKind::EmbeddedPe
    }
}

// ---------------------------------------------------------------------------
// Extraction options
// ---------------------------------------------------------------------------

/// Configuration for the overlay extractor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayExtractorConfig {
    /// Maximum number of bytes to read for magic / entropy computation.
    /// `0` means read the entire overlay.
    pub max_sample_bytes: usize,
    /// Whether to attempt sub-region parsing (ZIP EOCD, etc.).
    pub parse_sub_regions: bool,
}

impl Default for OverlayExtractorConfig {
    fn default() -> Self {
        Self {
            max_sample_bytes: 0,
            parse_sub_regions: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Main extractor
// ---------------------------------------------------------------------------

/// Extracts and describes the overlay region of a PE file.
pub struct OverlayExtractor {
    config: OverlayExtractorConfig,
}

impl OverlayExtractor {
    pub fn new(config: OverlayExtractorConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(OverlayExtractorConfig::default())
    }

    /// Compute the end of the last section given section boundaries.
    ///
    /// Returns the byte offset immediately after the last section's raw data.
    pub fn pe_data_end(sections: &[SectionBoundary]) -> u64 {
        sections.iter().map(|s| s.end_offset()).max().unwrap_or(0)
    }

    /// Locate and describe the overlay in `file_data`.
    ///
    /// `sections` must be the list of PE sections (as parsed from the PE header).
    /// Returns `Err(OverlayError::NoOverlay)` when there is no trailing data.
    pub fn extract(
        &self,
        file_data: &[u8],
        sections: &[SectionBoundary],
    ) -> Result<OverlayInfo, OverlayError> {
        if file_data.is_empty() {
            return Err(OverlayError::EmptyFile);
        }

        let pe_end = Self::pe_data_end(sections);
        if pe_end == 0 {
            return Err(OverlayError::MalformedPe {
                reason: "no sections with non-zero raw data found".to_string(),
            });
        }

        let file_size = file_data.len() as u64;
        if pe_end >= file_size {
            return Err(OverlayError::NoOverlay);
        }

        let offset = pe_end;
        let size = file_size - offset;
        let offset_usize = usize::try_from(offset).map_err(|_| OverlayError::MalformedPe {
            reason: format!("overlay offset 0x{offset:X} exceeds address space"),
        })?;
        let overlay_data = &file_data[offset_usize..];

        // Sample for entropy computation.
        let sample = if self.config.max_sample_bytes > 0 && overlay_data.len() > self.config.max_sample_bytes {
            &overlay_data[..self.config.max_sample_bytes]
        } else {
            overlay_data
        };

        let entropy = crate_shannon_entropy(sample);
        let kind = detect_overlay_kind(overlay_data);

        // Hex-encode first 16 bytes.
        let preview_len = overlay_data.len().min(16);
        let magic_bytes_hex = overlay_data[..preview_len]
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(" ");

        let mut regions = Vec::new();
        let mut metadata: HashMap<String, String> = HashMap::new();

        if self.config.parse_sub_regions {
            self.parse_sub_regions(overlay_data, &kind, &mut regions, &mut metadata);
        }

        Ok(OverlayInfo {
            file_offset: offset,
            size,
            kind,
            entropy,
            magic_bytes_hex,
            regions,
            metadata,
        })
    }

    /// Attempt to extract a copy of the overlay bytes from the file.
    ///
    /// Returns `None` if there is no overlay.
    pub fn extract_bytes<'a>(
        &self,
        file_data: &'a [u8],
        sections: &[SectionBoundary],
    ) -> Option<&'a [u8]> {
        let pe_end = Self::pe_data_end(sections);
        if pe_end == 0 || pe_end >= file_data.len() as u64 {
            return None;
        }
        let pe_end_usize = usize::try_from(pe_end).ok()?;
        Some(&file_data[pe_end_usize..])
    }

    /// Returns `true` if the file has an overlay.
    pub fn has_overlay(file_data: &[u8], sections: &[SectionBoundary]) -> bool {
        let pe_end = Self::pe_data_end(sections);
        pe_end > 0 && pe_end < file_data.len() as u64
    }

    // ------------------------------------------------------------------
    // Private: sub-region parsing
    // ------------------------------------------------------------------

    fn parse_sub_regions(
        &self,
        overlay: &[u8],
        kind: &OverlayKind,
        regions: &mut Vec<OverlayRegion>,
        metadata: &mut HashMap<String, String>,
    ) {
        match kind {
            OverlayKind::Zip => self.parse_zip_regions(overlay, regions, metadata),
            OverlayKind::Pkcs7Certificate => self.parse_pkcs7_regions(overlay, regions, metadata),
            OverlayKind::EmbeddedPe => self.parse_embedded_pe_regions(overlay, regions, metadata),
            OverlayKind::Cabinet => self.parse_cabinet_regions(overlay, regions, metadata),
            _ => {}
        }
    }

    fn parse_zip_regions(
        &self,
        overlay: &[u8],
        regions: &mut Vec<OverlayRegion>,
        metadata: &mut HashMap<String, String>,
    ) {
        if let Some(eocd) = find_zip_eocd(overlay) {
            metadata.insert("zip_total_entries".to_string(), eocd.total_entries.to_string());
            metadata.insert("zip_comment".to_string(), eocd.comment.clone());

            // Central directory region.
            regions.push(OverlayRegion {
                offset: eocd.cd_offset as u64,
                length: eocd.cd_size as u64,
                label: "ZIP central directory".to_string(),
            });

            // EOCD record.
            regions.push(OverlayRegion {
                offset: eocd.eocd_offset,
                length: 22 + eocd.comment.len() as u64,
                label: "ZIP end-of-central-directory".to_string(),
            });

            // Estimate local file data region (before CD).
            if eocd.cd_offset > 0 {
                regions.push(OverlayRegion {
                    offset: 0,
                    length: eocd.cd_offset as u64,
                    label: "ZIP local file data".to_string(),
                });
            }
        }
    }

    fn parse_pkcs7_regions(
        &self,
        overlay: &[u8],
        regions: &mut Vec<OverlayRegion>,
        metadata: &mut HashMap<String, String>,
    ) {
        // DER SEQUENCE: tag 0x30, then length encoding.
        if overlay.len() < 4 {
            return;
        }
        let total_len = der_total_length(overlay);
        metadata.insert("pkcs7_der_length".to_string(), total_len.to_string());
        regions.push(OverlayRegion {
            offset: 0,
            length: total_len as u64,
            label: "PKCS#7 DER SEQUENCE".to_string(),
        });
    }

    fn parse_embedded_pe_regions(
        &self,
        overlay: &[u8],
        regions: &mut Vec<OverlayRegion>,
        metadata: &mut HashMap<String, String>,
    ) {
        // Check e_lfanew at offset 0x3C to locate PE signature.
        if overlay.len() < 0x40 {
            return;
        }
        let e_lfanew = u32::from_le_bytes([
            overlay[0x3C],
            overlay[0x3D],
            overlay[0x3E],
            overlay[0x3F],
        ]) as usize;
        metadata.insert("embedded_pe_e_lfanew".to_string(), format!("0x{:X}", e_lfanew));
        if e_lfanew.saturating_add(4) <= overlay.len() && &overlay[e_lfanew..e_lfanew + 4] == b"PE\0\0" {
            metadata.insert("embedded_pe_valid_signature".to_string(), "true".to_string());
            regions.push(OverlayRegion {
                offset: 0,
                length: overlay.len() as u64,
                label: "Embedded PE file".to_string(),
            });
        }
    }

    fn parse_cabinet_regions(
        &self,
        overlay: &[u8],
        regions: &mut Vec<OverlayRegion>,
        metadata: &mut HashMap<String, String>,
    ) {
        // CAB header: MSCF (4), reserved1 (4), cabinet_size (4), …
        if overlay.len() < 12 {
            return;
        }
        let cabinet_size = u32::from_le_bytes([
            overlay[8],
            overlay[9],
            overlay[10],
            overlay[11],
        ]);
        metadata.insert("cabinet_size".to_string(), cabinet_size.to_string());
        regions.push(OverlayRegion {
            offset: 0,
            length: cabinet_size.min(overlay.len() as u32) as u64,
            label: "Cabinet archive".to_string(),
        });
    }
}

/// Parse the total length encoded in a DER object starting at `data[0]`.
fn der_total_length(data: &[u8]) -> u64 {
    if data.len() < 2 {
        return data.len() as u64;
    }
    let first_len_byte = data[1];
    if first_len_byte < 0x80 {
        // Short form: length is first_len_byte.
        2 + first_len_byte as u64
    } else {
        let num_bytes = (first_len_byte & 0x7F) as usize;
        if 2 + num_bytes > data.len() {
            return data.len() as u64;
        }
        let mut length: u64 = 0;
        for i in 0..num_bytes {
            length = (length << 8) | data[2 + i] as u64;
        }
        2 + num_bytes as u64 + length
    }
}

// ---------------------------------------------------------------------------
// Overlay certificate checker (Authenticode)
// ---------------------------------------------------------------------------

/// Checks whether the overlay is an Authenticode/PKCS#7 certificate block and
/// whether its encoded length is consistent with the actual overlay size.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateCheckResult {
    pub is_certificate: bool,
    /// True if the DER-encoded length matches the overlay size.
    pub length_consistent: bool,
    /// The DER-encoded total length.
    pub der_total_length: u64,
    /// Actual overlay size.
    pub actual_size: u64,
}

/// Quick certificate check without full extraction.
pub fn check_certificate_overlay(
    file_data: &[u8],
    sections: &[SectionBoundary],
) -> CertificateCheckResult {
    let pe_end = OverlayExtractor::pe_data_end(sections);
    let file_size = file_data.len() as u64;
    if pe_end == 0 || pe_end >= file_size {
        return CertificateCheckResult {
            is_certificate: false,
            length_consistent: false,
            der_total_length: 0,
            actual_size: 0,
        };
    }
    let pe_end_usize = match usize::try_from(pe_end) {
        Ok(v) if v < file_data.len() => v,
        _ => return CertificateCheckResult {
            is_certificate: false,
            length_consistent: false,
            der_total_length: 0,
            actual_size: 0,
        },
    };
    let overlay = &file_data[pe_end_usize..];
    let actual_size = overlay.len() as u64;
    let kind = detect_overlay_kind(overlay);
    let is_certificate = kind == OverlayKind::Pkcs7Certificate;
    let der_len = if is_certificate {
        der_total_length(overlay)
    } else {
        0
    };
    CertificateCheckResult {
        is_certificate,
        length_consistent: is_certificate && der_len == actual_size,
        der_total_length: der_len,
        actual_size,
    }
}

// ---------------------------------------------------------------------------
// Bulk analysis helper
// ---------------------------------------------------------------------------

/// Result of analysing multiple PE files for overlays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkOverlayResult {
    /// How many files were analysed.
    pub total: usize,
    /// How many had an overlay.
    pub with_overlay: usize,
    /// Distribution of overlay kinds.
    pub kind_counts: HashMap<String, usize>,
    /// Average entropy of overlays (0.0 if none had overlays).
    pub average_entropy: f64,
}

/// Analyse a batch of `(file_data, sections)` pairs and summarise overlay statistics.
pub fn bulk_overlay_stats(
    files: &[(&[u8], Vec<SectionBoundary>)],
) -> BulkOverlayResult {
    let extractor = OverlayExtractor::with_defaults();
    let mut total = 0usize;
    let mut with_overlay = 0usize;
    let mut kind_counts: HashMap<String, usize> = HashMap::new();
    let mut entropy_sum = 0.0f64;

    for (data, sections) in files {
        total += 1;
        match extractor.extract(data, sections) {
            Ok(info) => {
                with_overlay += 1;
                *kind_counts.entry(info.kind.to_string()).or_insert(0) += 1;
                entropy_sum += info.entropy;
            }
            Err(OverlayError::NoOverlay) => {}
            Err(_) => {}
        }
    }

    let average_entropy = if with_overlay > 0 {
        entropy_sum / with_overlay as f64
    } else {
        0.0
    };

    BulkOverlayResult {
        total,
        with_overlay,
        kind_counts,
        average_entropy,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_section(offset: u32, size: u32) -> SectionBoundary {
        SectionBoundary {
            name: ".text".to_string(),
            raw_offset: offset,
            raw_size: size,
        }
    }

    #[test]
    fn test_no_overlay_detected() {
        let file = vec![0u8; 0x1000];
        let sections = vec![make_section(0x400, 0xC00)]; // ends exactly at 0x1000
        assert!(!OverlayExtractor::has_overlay(&file, &sections));
    }

    #[test]
    fn test_overlay_detected() {
        let mut file = vec![0u8; 0x1100];
        // Place a ZIP magic at the overlay offset.
        file[0x1000] = b'P';
        file[0x1001] = b'K';
        file[0x1002] = 0x03;
        file[0x1003] = 0x04;
        let sections = vec![make_section(0x400, 0xC00)]; // ends at 0x1000
        assert!(OverlayExtractor::has_overlay(&file, &sections));

        let ext = OverlayExtractor::with_defaults();
        let info = ext.extract(&file, &sections).unwrap();
        assert_eq!(info.file_offset, 0x1000);
        assert_eq!(info.size, 0x100);
        assert_eq!(info.kind, OverlayKind::Zip);
    }

    #[test]
    fn test_embedded_pe_detection() {
        let mut file = vec![0u8; 0x2000];
        // PE sections end at 0x1000.
        // Embed an MZ header in the overlay.
        file[0x1000] = b'M';
        file[0x1001] = b'Z';
        let sections = vec![make_section(0x400, 0xC00)];
        let ext = OverlayExtractor::with_defaults();
        let info = ext.extract(&file, &sections).unwrap();
        assert_eq!(info.kind, OverlayKind::EmbeddedPe);
    }

    #[test]
    fn test_pkcs7_detection() {
        let mut file = vec![0u8; 0x2000];
        file[0x1000] = 0x30;
        file[0x1001] = 0x82;
        file[0x1002] = 0x0F;
        file[0x1003] = 0xF8;
        let sections = vec![make_section(0x400, 0xC00)];
        let ext = OverlayExtractor::with_defaults();
        let info = ext.extract(&file, &sections).unwrap();
        assert_eq!(info.kind, OverlayKind::Pkcs7Certificate);
        assert!(info.is_certificate());
    }

    #[test]
    fn test_unknown_overlay() {
        let mut file = vec![0u8; 0x1100];
        // Fill overlay with a repeated non-magic byte.
        for b in &mut file[0x1000..] {
            *b = 0xCC;
        }
        let sections = vec![make_section(0x400, 0xC00)];
        let ext = OverlayExtractor::with_defaults();
        let info = ext.extract(&file, &sections).unwrap();
        // 0xCC repeated → low entropy → Unknown, not HighEntropyBlob.
        assert_eq!(info.kind, OverlayKind::Unknown);
    }

    #[test]
    fn test_der_total_length_short_form() {
        let data = &[0x30u8, 0x10u8];
        assert_eq!(der_total_length(data), 18); // 2 + 16
    }

    #[test]
    fn test_der_total_length_long_form() {
        // Long form: 0x82 means next 2 bytes are length.
        let data = &[0x30u8, 0x82u8, 0x01u8, 0x00u8];
        assert_eq!(der_total_length(data), 2 + 2 + 256); // header=4, body=256
    }

    #[test]
    fn test_bulk_overlay_stats() {
        let file1 = vec![0u8; 0x1000]; // no overlay
        let sections1 = vec![make_section(0x400, 0xC00)];

        let mut file2 = vec![0u8; 0x1100];
        file2[0x1000] = b'P';
        file2[0x1001] = b'K';
        file2[0x1002] = 0x03;
        file2[0x1003] = 0x04;
        let sections2 = vec![make_section(0x400, 0xC00)];

        let result = bulk_overlay_stats(&[
            (file1.as_slice(), sections1),
            (file2.as_slice(), sections2),
        ]);
        assert_eq!(result.total, 2);
        assert_eq!(result.with_overlay, 1);
        assert!(result.kind_counts.contains_key("ZIP"));
    }

    #[test]
    fn test_extract_bytes() {
        let mut file = vec![0u8; 0x1100];
        file[0x1000..].iter_mut().enumerate().for_each(|(i, b)| *b = i as u8);
        let sections = vec![make_section(0x400, 0xC00)];
        let ext = OverlayExtractor::with_defaults();
        let bytes = ext.extract_bytes(&file, &sections).unwrap();
        assert_eq!(bytes.len(), 0x100);
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x01);
    }

    #[test]
    fn test_certificate_check() {
        let mut file = vec![0u8; 0x2000];
        file[0x1000] = 0x30;
        file[0x1001] = 0x82;
        // Encode length of 0x0FF6 = 4086, so total is 4 + 4086 = 4090.
        // Overlay size = 0x2000 - 0x1000 = 0x1000 = 4096 ≠ 4090; inconsistent.
        file[0x1002] = 0x0F;
        file[0x1003] = 0xF6;
        let sections = vec![make_section(0x400, 0xC00)];
        let result = check_certificate_overlay(&file, &sections);
        assert!(result.is_certificate);
        assert!(!result.length_consistent);
    }
}
