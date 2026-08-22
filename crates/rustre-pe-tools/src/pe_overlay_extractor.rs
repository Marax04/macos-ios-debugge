//! PE overlay extraction — isolate data appended after the last PE section.
//!
//! Many packers, self-extracting archives, and malware droppers store their
//! payload in the *overlay*: bytes that follow the last mapped section and are
//! ignored by the Windows loader.  [`PeOverlayExtractor`] locates the overlay
//! boundary, classifies the content, and returns an [`Overlay`] descriptor.

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// OverlayKind — semantic classification of the overlay content
// ---------------------------------------------------------------------------

/// Classification of what the overlay contains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OverlayKind {
    /// Standard ZIP archive (PK magic `50 4B 03 04`).
    Zip,
    /// 7-Zip archive (`37 7A BC AF 27 1C`).
    SevenZip,
    /// RAR archive (v4: `52 61 72 21 1A 07 00`, v5: ... `00`).
    Rar,
    /// NSIS installer signature.
    Nsis,
    /// Self-extracting archive with WinZip/WinRAR SFX signature.
    SfxArchive,
    /// Certificate / Authenticode signature block.
    Certificate,
    /// High-entropy data (>7.5 bits/byte) — likely encrypted or compressed.
    HighEntropy,
    /// Low-entropy data — possibly a plain-text config or resources.
    LowEntropy,
    /// No overlay present.
    None,
    /// Could not be classified.
    Unknown,
}

impl fmt::Display for OverlayKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Zip         => "ZIP",
            Self::SevenZip    => "7Z",
            Self::Rar         => "RAR",
            Self::Nsis        => "NSIS",
            Self::SfxArchive  => "SFX",
            Self::Certificate => "CERT",
            Self::HighEntropy => "HIGH-ENTROPY",
            Self::LowEntropy  => "LOW-ENTROPY",
            Self::None        => "NONE",
            Self::Unknown     => "UNKNOWN",
        };
        f.write_str(s)
    }
}

impl OverlayKind {
    /// Returns `true` when the overlay may contain a hidden payload.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        matches!(self, Self::HighEntropy | Self::Unknown | Self::SfxArchive | Self::Nsis)
    }
}

// ---------------------------------------------------------------------------
// Overlay — descriptor returned by the extractor
// ---------------------------------------------------------------------------

/// Describes a PE overlay region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Overlay {
    /// Byte offset of the overlay start within the file.
    pub offset: usize,
    /// Length of the overlay in bytes.
    pub size: usize,
    /// Semantic classification.
    pub kind: OverlayKind,
    /// Shannon entropy of the overlay bytes (0.0–8.0 bits/byte).
    pub entropy: f64,
    /// Up to 16 leading bytes of the overlay (for magic detection).
    pub magic_bytes: Vec<u8>,
    /// Analyst notes.
    pub notes: Vec<String>,
}

impl Overlay {
    /// Create an "empty" overlay indicating no overlay was found.
    #[must_use]
    pub const fn none(file_size: usize) -> Self {
        Self {
            offset: file_size,
            size: 0,
            kind: OverlayKind::None,
            entropy: 0.0,
            magic_bytes: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// Returns `true` when the overlay is empty / absent.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Returns `true` when the overlay should be investigated further.
    #[must_use]
    pub const fn is_suspicious(&self) -> bool {
        self.kind.is_suspicious() && self.size > 0
    }

    /// Add a diagnostic note.
    pub fn add_note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }
}

impl fmt::Display for Overlay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "overlay offset={:#x} size={} kind={} entropy={:.2}",
            self.offset, self.size, self.kind, self.entropy
        )
    }
}

// ---------------------------------------------------------------------------
// OverlayError
// ---------------------------------------------------------------------------

/// Errors from [`PeOverlayExtractor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayError {
    /// The data is too short to be a valid PE.
    TooShort { got: usize },
    /// The `e_lfanew` pointer is out of range.
    BadElfanew { offset: u32 },
    /// The PE signature was not found.
    NoPeSignature,
    /// The section table is malformed.
    MalformedSections,
}

impl fmt::Display for OverlayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { got } => write!(f, "file too short: {got} bytes"),
            Self::BadElfanew { offset } => write!(f, "e_lfanew={offset:#x} is out of range"),
            Self::NoPeSignature => write!(f, "PE signature not found"),
            Self::MalformedSections => write!(f, "section table is malformed"),
        }
    }
}

impl std::error::Error for OverlayError {}

// ---------------------------------------------------------------------------
// PeOverlayExtractor
// ---------------------------------------------------------------------------

/// Locates and classifies the overlay region of a PE file.
pub struct PeOverlayExtractor {
    /// Minimum overlay size to report (smaller overlays are treated as padding).
    pub min_size: usize,
    /// Entropy threshold above which an overlay is classified as high-entropy.
    pub high_entropy_threshold: f64,
}

impl Default for PeOverlayExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl PeOverlayExtractor {
    /// Create a new extractor with default thresholds.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            min_size: 8,
            high_entropy_threshold: 7.5,
        }
    }

    /// Override the minimum overlay size to report.
    #[must_use] 
    pub const fn with_min_size(mut self, n: usize) -> Self {
        self.min_size = n;
        self
    }

    /// Override the high-entropy threshold (bits/byte, 0.0–8.0).
    #[must_use] 
    pub const fn with_high_entropy_threshold(mut self, t: f64) -> Self {
        self.high_entropy_threshold = t;
        self
    }

    /// Locate and classify the overlay in `data`.
    ///
    /// # Errors
    /// Returns [`OverlayError`] if the PE structure is invalid.
    pub fn extract(&self, data: &[u8]) -> Result<Overlay, OverlayError> {
        let overlay_offset = Self::find_overlay_offset(data)?;

        if overlay_offset >= data.len() {
            return Ok(Overlay::none(data.len()));
        }

        let size = data.len() - overlay_offset;
        if size < self.min_size {
            return Ok(Overlay::none(data.len()));
        }

        let overlay_bytes = &data[overlay_offset..];
        let entropy = shannon_entropy(overlay_bytes);
        let magic_bytes: Vec<u8> = overlay_bytes.iter().take(16).copied().collect();
        let kind = self.classify(overlay_bytes, entropy);

        let mut overlay = Overlay {
            offset: overlay_offset,
            size,
            kind,
            entropy,
            magic_bytes,
            notes: Vec::new(),
        };
        overlay.add_note(format!("overlay starts at file offset {overlay_offset:#x}"));
        Ok(overlay)
    }

    /// Find the byte offset where the overlay starts (= end of last section).
    fn find_overlay_offset(data: &[u8]) -> Result<usize, OverlayError> {
        const SECTION_ENTRY_SIZE: usize = 40;
        if data.len() < 64 {
            return Err(OverlayError::TooShort { got: data.len() });
        }

        let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]);
        let nt_offset = e_lfanew as usize;

        if nt_offset + 24 > data.len() {
            return Err(OverlayError::BadElfanew { offset: e_lfanew });
        }
        if &data[nt_offset..nt_offset + 4] != b"PE\0\0" {
            return Err(OverlayError::NoPeSignature);
        }

        // FileHeader fields
        let file_header_offset = nt_offset + 4;
        let num_sections = u16::from_le_bytes([
            data[file_header_offset + 2],
            data[file_header_offset + 3],
        ]) as usize;
        let size_of_opt_header = u16::from_le_bytes([
            data[file_header_offset + 16],
            data[file_header_offset + 17],
        ]) as usize;

        // Section table starts after FileHeader (20 bytes) + OptionalHeader
        let section_table_offset = nt_offset + 4 + 20 + size_of_opt_header;

        let mut max_raw_end: usize = 0;

        for i in 0..num_sections {
            let entry_offset = section_table_offset + i * SECTION_ENTRY_SIZE;
            if entry_offset + SECTION_ENTRY_SIZE > data.len() {
                return Err(OverlayError::MalformedSections);
            }
            // PointerToRawData at +20, SizeOfRawData at +16
            let raw_ptr = u32::from_le_bytes([
                data[entry_offset + 20],
                data[entry_offset + 21],
                data[entry_offset + 22],
                data[entry_offset + 23],
            ]) as usize;
            let raw_size = u32::from_le_bytes([
                data[entry_offset + 16],
                data[entry_offset + 17],
                data[entry_offset + 18],
                data[entry_offset + 19],
            ]) as usize;

            if raw_ptr == 0 {
                continue; // BSS-style section
            }
            let end = raw_ptr.saturating_add(raw_size);
            if end > max_raw_end {
                max_raw_end = end;
            }
        }

        Ok(max_raw_end)
    }

    /// Classify overlay content from the leading bytes and entropy.
    fn classify(&self, bytes: &[u8], entropy: f64) -> OverlayKind {
        if bytes.is_empty() {
            return OverlayKind::None;
        }

        // Magic-byte checks
        if bytes.len() >= 4 && bytes[0] == 0x50 && bytes[1] == 0x4B && bytes[2] == 0x03 && bytes[3] == 0x04 {
            return OverlayKind::Zip;
        }
        if bytes.len() >= 6
            && bytes[0] == 0x37 && bytes[1] == 0x7A && bytes[2] == 0xBC
            && bytes[3] == 0xAF && bytes[4] == 0x27 && bytes[5] == 0x1C
        {
            return OverlayKind::SevenZip;
        }
        if bytes.len() >= 7
            && bytes[0] == 0x52 && bytes[1] == 0x61 && bytes[2] == 0x72
            && bytes[3] == 0x21 && bytes[4] == 0x1A && bytes[5] == 0x07
        {
            return OverlayKind::Rar;
        }
        // NSIS: look for "Nullsoft" in first 512 bytes
        let window = bytes.len().min(512);
        if bytes[..window].windows(8).any(|w| w == b"Nullsoft") {
            return OverlayKind::Nsis;
        }
        // Authenticode / PKCS#7: DER TLV with 30 82 or 30 83
        if bytes.len() >= 4 && bytes[0] == 0x30 && (bytes[1] == 0x82 || bytes[1] == 0x83) {
            return OverlayKind::Certificate;
        }
        // Entropy-based fallback
        if entropy >= self.high_entropy_threshold {
            return OverlayKind::HighEntropy;
        }
        if entropy < 2.0 {
            return OverlayKind::LowEntropy;
        }
        OverlayKind::Unknown
    }
}

// ---------------------------------------------------------------------------
// Shannon entropy helper
// ---------------------------------------------------------------------------

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / len;
            -p * p.log2()
        })
        .sum()
}

// ---------------------------------------------------------------------------
// extract_overlay — free function
// ---------------------------------------------------------------------------

/// Locate and classify the overlay of a PE file from raw bytes.
///
/// # Errors
/// Returns [`OverlayError`] if the PE structure is invalid.
pub fn extract_overlay(data: &[u8]) -> Result<Overlay, OverlayError> {
    PeOverlayExtractor::new().extract(data)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal PE32+ with one section whose raw end is at byte 0x200.
    fn make_pe_with_section(overlay: &[u8]) -> Vec<u8> {
        let raw_section_end = 0x200usize;
        let mut data = vec![0u8; raw_section_end];
        // MZ
        data[0] = b'M'; data[1] = b'Z';
        // e_lfanew = 0x40
        data[0x3C] = 0x40;
        // PE signature
        data[0x40] = b'P'; data[0x41] = b'E'; data[0x42] = 0; data[0x43] = 0;
        // NumberOfSections = 1
        data[0x44] = 0x64; data[0x45] = 0x86; // machine (ignored)
        data[0x46] = 0x01; data[0x47] = 0x00; // NumberOfSections = 1
        // SizeOfOptionalHeader = 0xF0
        data[0x54] = 0xF0; data[0x55] = 0x00;
        // Section table at 0x40 + 4 + 20 + 0xF0 = 0x158
        let sec_off = 0x40 + 4 + 20 + 0xF0;
        // Section: SizeOfRawData = 0x100, PointerToRawData = 0x100
        data[sec_off + 16] = 0x00; data[sec_off + 17] = 0x01; // SizeOfRawData = 0x100
        data[sec_off + 20] = 0x00; data[sec_off + 21] = 0x01; // PointerToRawData = 0x100
        data.extend_from_slice(overlay);
        data
    }

    #[test]
    fn test_no_overlay() {
        let data = make_pe_with_section(&[]);
        let ov = extract_overlay(&data).unwrap();
        assert!(ov.is_empty());
        assert_eq!(ov.kind, OverlayKind::None);
    }

    #[test]
    fn test_zip_overlay() {
        let zip_magic = [0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00];
        let data = make_pe_with_section(&zip_magic);
        let ov = extract_overlay(&data).unwrap();
        assert_eq!(ov.kind, OverlayKind::Zip);
    }

    #[test]
    fn test_7z_overlay() {
        let magic = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let data = make_pe_with_section(&magic);
        let ov = extract_overlay(&data).unwrap();
        assert_eq!(ov.kind, OverlayKind::SevenZip);
    }

    #[test]
    fn test_high_entropy_overlay() {
        // ~uniform random bytes → high entropy
        let random: Vec<u8> = (0u8..=255).cycle().take(256).collect();
        let data = make_pe_with_section(&random);
        let ov = extract_overlay(&data).unwrap();
        // The uniform distribution → entropy = 8.0
        assert_eq!(ov.kind, OverlayKind::HighEntropy);
    }

    #[test]
    fn test_low_entropy_overlay() {
        let low: Vec<u8> = vec![0x00u8; 256];
        let data = make_pe_with_section(&low);
        let ov = extract_overlay(&data).unwrap();
        assert_eq!(ov.kind, OverlayKind::LowEntropy);
    }

    #[test]
    fn test_overlay_size_and_offset() {
        let payload = vec![0x50u8, 0x4B, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let data = make_pe_with_section(&payload);
        let ov = extract_overlay(&data).unwrap();
        assert_eq!(ov.offset, 0x200);
        assert_eq!(ov.size, payload.len());
    }

    #[test]
    fn test_overlay_display() {
        let ov = Overlay {
            offset: 0x1000,
            size: 256,
            kind: OverlayKind::Zip,
            entropy: 7.8,
            magic_bytes: vec![],
            notes: vec![],
        };
        let s = ov.to_string();
        assert!(s.contains("ZIP"));
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn test_overlay_is_suspicious() {
        let high = Overlay {
            offset: 0, size: 100, kind: OverlayKind::HighEntropy,
            entropy: 7.9, magic_bytes: vec![], notes: vec![],
        };
        assert!(high.is_suspicious());
        let zip = Overlay {
            offset: 0, size: 100, kind: OverlayKind::Zip,
            entropy: 7.9, magic_bytes: vec![], notes: vec![],
        };
        assert!(!zip.is_suspicious());
    }

    #[test]
    fn test_too_short() {
        let err = extract_overlay(&[0u8; 10]);
        assert!(matches!(err, Err(OverlayError::TooShort { got: 10 })));
    }

    #[test]
    fn test_no_pe_sig() {
        let mut data = vec![0u8; 256];
        data[0x3C] = 0x40;
        let err = extract_overlay(&data);
        assert!(matches!(err, Err(OverlayError::NoPeSignature)));
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = shannon_entropy(&data);
        assert!((e - 8.0).abs() < 0.01, "expected 8.0, got {e}");
    }

    #[test]
    fn test_shannon_entropy_single_byte() {
        let data = vec![0xAAu8; 256];
        let e = shannon_entropy(&data);
        assert_eq!(e, 0.0);
    }

    #[test]
    fn test_overlay_kind_display() {
        assert_eq!(OverlayKind::Zip.to_string(), "ZIP");
        assert_eq!(OverlayKind::HighEntropy.to_string(), "HIGH-ENTROPY");
        assert_eq!(OverlayKind::None.to_string(), "NONE");
    }

    #[test]
    fn test_extractor_min_size() {
        // Overlay of only 4 bytes — below default min_size of 16
        let small: Vec<u8> = vec![0x50, 0x4B, 0x03, 0x04];
        let data = make_pe_with_section(&small);
        let ov = PeOverlayExtractor::new().extract(&data).unwrap();
        // Too small → treated as "none"
        assert!(ov.is_empty());
    }
}
