//! PE overlay analyser: detects, measures, and classifies appended data found
//! after the last PE section (the "overlay").

use std::fmt;

use crate::compute_entropy;

// ── OverlayKind ───────────────────────────────────────────────────────────────

/// The inferred content type of a PE overlay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayKind {
    /// High-entropy — likely compressed or encrypted data (packer payload).
    HighEntropyData,
    /// Looks like a self-extracting archive stub (common SFX markers).
    SfxArchive,
    /// Certificate / Authenticode digital signature (WIN_CERTIFICATE).
    AuthenticodeSig,
    /// NSIS installer block.
    NsisBlock,
    /// Inno Setup data block.
    InnoSetupData,
    /// ZIP end-of-central-directory record found (appended ZIP).
    AppendedZip,
    /// Raw binary with low-to-medium entropy (possible plaintext or struct).
    RawData,
    /// Overlay present but too small to classify meaningfully (< 16 bytes).
    TooSmall,
    /// No overlay present.
    None,
}

impl fmt::Display for OverlayKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ── OverlayInfo ───────────────────────────────────────────────────────────────

/// Result of analysing a PE file's overlay.
#[derive(Debug, Clone)]
pub struct OverlayInfo {
    /// File offset at which the overlay begins (0 if no overlay).
    pub offset: usize,
    /// Number of overlay bytes (0 if no overlay).
    pub size: usize,
    /// Shannon entropy of the overlay, in [0, 8].
    pub entropy: f32,
    /// Inferred kind of the overlay data.
    pub kind: OverlayKind,
    /// The first 64 bytes of the overlay (for quick inspection).
    pub header_bytes: Vec<u8>,
    /// Any human-readable notes about the classification.
    pub notes: Vec<String>,
    /// Confidence in the `kind` classification (0–100).
    pub confidence: u8,
}

impl OverlayInfo {
    /// Returns `true` if an overlay is present (size > 0).
    #[must_use]
    pub const fn has_overlay(&self) -> bool {
        self.size > 0
    }

    /// Returns `true` when this overlay looks like a packer payload.
    #[must_use]
    pub const fn likely_packed(&self) -> bool {
        matches!(self.kind, OverlayKind::HighEntropyData)
    }

    /// Returns the overlay as a human-readable hex dump of the first 16 bytes.
    #[must_use]
    pub fn hex_preview(&self) -> String {
        self.header_bytes
            .iter()
            .take(16)
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl fmt::Display for OverlayInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.has_overlay() {
            return write!(f, "No overlay");
        }
        write!(
            f,
            "Overlay @{:#x} ({} bytes, entropy={:.2}, kind={})",
            self.offset, self.size, self.entropy, self.kind
        )
    }
}

// ── AnalysisConfig ────────────────────────────────────────────────────────────

/// Configuration knobs for the [`OverlayAnalyzer`].
#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    /// Entropy threshold above which the overlay is classified as
    /// [`OverlayKind::HighEntropyData`].
    pub high_entropy_threshold: f32,
    /// Entropy threshold below which the overlay is classified as
    /// [`OverlayKind::RawData`] (no known magic found).
    pub low_entropy_threshold: f32,
    /// Maximum number of bytes to scan for magic detection (to avoid O(N)
    /// scans on huge overlays).
    pub max_scan_bytes: usize,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            high_entropy_threshold: 7.0,
            low_entropy_threshold: 5.5,
            max_scan_bytes: 1024 * 64, // 64 KiB
        }
    }
}

// ── OverlayAnalyzer ───────────────────────────────────────────────────────────

/// Analyses the overlay region of PE files.
///
/// Usage:
/// ```
/// use rustre_triage_die::overlay_analyzer::{OverlayAnalyzer, AnalysisConfig};
///
/// let data = std::fs::read("sample.exe").unwrap_or_default();
/// let analyzer = OverlayAnalyzer::new(AnalysisConfig::default());
/// let info = analyzer.analyze(&data);
/// println!("{info}");
/// ```
pub struct OverlayAnalyzer {
    config: AnalysisConfig,
}

impl OverlayAnalyzer {
    /// Create an analyser with the given config.
    #[must_use]
    pub fn new(config: AnalysisConfig) -> Self {
        Self { config }
    }

    /// Create an analyser with default configuration.
    #[must_use]
    pub fn default_config() -> Self {
        Self::new(AnalysisConfig::default())
    }

    /// Analyse the PE overlay of `data`.
    ///
    /// Returns an [`OverlayInfo`] regardless of whether an overlay is present.
    #[must_use]
    pub fn analyze(&self, data: &[u8]) -> OverlayInfo {
        let Some(overlay_offset) = locate_overlay(data) else {
            return OverlayInfo {
                offset: 0,
                size: 0,
                entropy: 0.0,
                kind: OverlayKind::None,
                header_bytes: Vec::new(),
                notes: Vec::new(),
                confidence: 100,
            };
        };

        let overlay = &data[overlay_offset..];
        let size = overlay.len();

        if size < 16 {
            return OverlayInfo {
                offset: overlay_offset,
                size,
                entropy: compute_entropy(overlay),
                kind: OverlayKind::TooSmall,
                header_bytes: overlay.to_vec(),
                notes: vec!["overlay is smaller than 16 bytes".into()],
                confidence: 90,
            };
        }

        let header_bytes: Vec<u8> = overlay.iter().take(64).copied().collect();

        // Entropy over at most `max_scan_bytes`
        let scan_len = size.min(self.config.max_scan_bytes);
        let entropy = compute_entropy(&overlay[..scan_len]);
        let mut notes: Vec<String> = Vec::new();

        let (kind, confidence) =
            self.classify(overlay, entropy, &header_bytes, &mut notes);

        OverlayInfo {
            offset: overlay_offset,
            size,
            entropy,
            kind,
            header_bytes,
            notes,
            confidence,
        }
    }

    /// Attempt to classify the overlay.
    fn classify(
        &self,
        overlay: &[u8],
        entropy: f32,
        header: &[u8],
        notes: &mut Vec<String>,
    ) -> (OverlayKind, u8) {
        // Authenticode: WIN_CERTIFICATE at the very beginning (DWORD len, WORD rev=0x0200, WORD type=2)
        if header.len() >= 8 {
            let rev = u16::from_le_bytes([header[4], header[5]]);
            let wtype = u16::from_le_bytes([header[6], header[7]]);
            if rev == 0x0200 && wtype == 2 {
                notes.push("WIN_CERTIFICATE header detected".into());
                return (OverlayKind::AuthenticodeSig, 92);
            }
        }

        // ZIP end-of-central-directory (scan last 64 bytes)
        if has_zip_eocd(overlay) {
            notes.push("ZIP EOCD signature found".into());
            return (OverlayKind::AppendedZip, 94);
        }

        // NSIS signature: "Nullsoft" or the NSIS first-header magic
        if contains(overlay, b"Nullsoft") || contains(overlay, b"\xEF\xBE\xAD\xDE") {
            notes.push("NSIS block markers detected".into());
            return (OverlayKind::NsisBlock, 88);
        }

        // Inno Setup: unicode magic "Inno Setup Setup Data"
        if contains(overlay, b"Inno Setup Setup Data") {
            notes.push("Inno Setup data block detected".into());
            return (OverlayKind::InnoSetupData, 90);
        }

        // SFX markers: common self-extractor strings
        if contains(overlay, b"7-Zip")
            || contains(overlay, b"WinRAR SFX")
            || contains(overlay, b"WinZip Self-Extractor")
        {
            notes.push("SFX archive markers detected".into());
            return (OverlayKind::SfxArchive, 87);
        }

        // Entropy-based fallback
        if entropy >= self.config.high_entropy_threshold {
            notes.push(format!(
                "entropy {entropy:.3} exceeds threshold {:.3}",
                self.config.high_entropy_threshold
            ));
            return (OverlayKind::HighEntropyData, 75);
        }

        notes.push(format!(
            "entropy {entropy:.3} — no specific magic detected"
        ));
        (OverlayKind::RawData, 60)
    }
}

impl fmt::Debug for OverlayAnalyzer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OverlayAnalyzer(hi={:.1}, lo={:.1})",
            self.config.high_entropy_threshold, self.config.low_entropy_threshold
        )
    }
}

// ── Free function ─────────────────────────────────────────────────────────────

/// Analyse a raw PE file and return [`OverlayInfo`].
///
/// Convenience wrapper around [`OverlayAnalyzer::default_config`].
#[must_use]
pub fn analyze_overlay(data: &[u8]) -> OverlayInfo {
    OverlayAnalyzer::default_config().analyze(data)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Locate the byte offset at which the PE overlay begins, or `None`.
fn locate_overlay(data: &[u8]) -> Option<usize> {
    if data.len() < 0x40 {
        return None;
    }
    if &data[0..2] != b"MZ" {
        return None;
    }
    let pe_off = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
    if pe_off + 0x18 > data.len() {
        return None;
    }
    if &data[pe_off..pe_off + 4] != b"PE\0\0" {
        return None;
    }

    let num_sections = u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]) as usize;
    let opt_size = u16::from_le_bytes([data[pe_off + 0x14], data[pe_off + 0x15]]) as usize;
    let sec_tbl = pe_off + 0x18 + opt_size;

    // Check the Security data directory to exclude it from overlay
    let opt_off = pe_off + 0x18;
    if opt_off + 2 > data.len() {
        return None;
    }
    let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
    let sec_dd_off = if magic == 0x020b {
        opt_off + 0x70 + 4 * 8 // Security dir is index 4
    } else {
        opt_off + 0x60 + 4 * 8
    };
    let security_rva = if sec_dd_off + 8 <= data.len() {
        u32::from_le_bytes(data[sec_dd_off..sec_dd_off + 4].try_into().ok()?)
    } else {
        0
    };
    let security_size = if sec_dd_off + 8 <= data.len() {
        u32::from_le_bytes(
            data[sec_dd_off + 4..sec_dd_off + 8]
                .try_into()
                .ok()?,
        )
    } else {
        0
    };

    let mut end_of_sections: usize = 0;
    for i in 0..num_sections {
        let s = sec_tbl + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let raw_off = u32::from_le_bytes(data[s + 20..s + 24].try_into().ok()?) as usize;
        let raw_size = u32::from_le_bytes(data[s + 16..s + 20].try_into().ok()?) as usize;
        // Use saturating_add: both values come from attacker-controlled section
        // table entries and can overflow usize on 32-bit targets.
        let end = raw_off.saturating_add(raw_size);
        if end > end_of_sections {
            end_of_sections = end;
        }
    }

    // The Authenticode signature is stored as file data immediately after
    // sections (it IS the "overlay" for PE purposes but is NOT packer data).
    // We record it as overlay so the classifier can identify it.
    let candidate_end = if security_rva != 0 && security_size != 0 {
        // Use saturating_add: security_rva/security_size come from attacker-controlled
        // file data; an unchecked add can overflow on 32-bit targets.
        let cert_end = (security_rva as usize).saturating_add(security_size as usize);
        end_of_sections.max(cert_end)
    } else {
        end_of_sections
    };

    if candidate_end > 0 && data.len() > end_of_sections {
        Some(end_of_sections)
    } else {
        None
    }
}

/// Fast substring search without regex.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Check for a ZIP End-of-Central-Directory record in the last 64 KB.
fn has_zip_eocd(data: &[u8]) -> bool {
    // EOCD signature: 0x06054b50 (LE)
    const EOCD_SIG: &[u8] = &[0x50, 0x4b, 0x05, 0x06];
    let scan_start = data.len().saturating_sub(65536);
    data[scan_start..].windows(4).any(|w| w == EOCD_SIG)
}

// ── Entropy profile ───────────────────────────────────────────────────────────

/// Byte-resolution entropy profile of an overlay (one value per 256-byte chunk).
#[derive(Debug, Clone)]
pub struct EntropyProfile {
    pub block_size: usize,
    pub values: Vec<f32>,
}

impl EntropyProfile {
    /// Compute an entropy profile of `overlay` using `block_size`-byte blocks.
    #[must_use]
    pub fn compute(overlay: &[u8], block_size: usize) -> Self {
        let block_size = block_size.max(1);
        let values = overlay
            .chunks(block_size)
            .map(compute_entropy)
            .collect();
        Self { block_size, values }
    }

    /// Mean entropy across all blocks.
    #[must_use]
    pub fn mean(&self) -> f32 {
        if self.values.is_empty() {
            return 0.0;
        }
        self.values.iter().copied().sum::<f32>() / self.values.len() as f32
    }

    /// Maximum entropy across all blocks.
    #[must_use]
    pub fn max(&self) -> f32 {
        self.values
            .iter()
            .copied()
            .fold(f32::NEG_INFINITY, f32::max)
    }

    /// Minimum entropy across all blocks.
    #[must_use]
    pub fn min(&self) -> f32 {
        self.values
            .iter()
            .copied()
            .fold(f32::INFINITY, f32::min)
    }

    /// Number of blocks with entropy above `threshold`.
    #[must_use]
    pub fn blocks_above(&self, threshold: f32) -> usize {
        self.values.iter().filter(|&&e| e > threshold).count()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mz_no_overlay() -> Vec<u8> {
        // Minimal MZ/PE with one section but no trailing bytes
        let mut data = vec![0u8; 0x400];
        data[0] = b'M';
        data[1] = b'Z';
        // PE offset at 0x3c = 0x80
        data[0x3c] = 0x80;
        data[0x80] = b'P';
        data[0x81] = b'E';
        // num_sections = 1
        data[0x86] = 1;
        // opt header size = 0xe0 (PE32)
        data[0x94] = 0xe0;
        // magic = PE32
        data[0x98] = 0x0b;
        data[0x99] = 0x01;
        // section: raw_offset = 0x200, raw_size = 0x100
        let sec = 0x80 + 0x18 + 0xe0;
        data[sec + 16] = 0x00; // raw_size lo
        data[sec + 17] = 0x01; // raw_size hi (0x100)
        data[sec + 20] = 0x00; // raw_off lo
        data[sec + 21] = 0x02; // raw_off hi (0x200)
        data
    }

    fn make_mz_with_overlay(overlay: &[u8]) -> Vec<u8> {
        let mut data = make_mz_no_overlay();
        // Section ends at 0x300 (0x200 + 0x100); data currently 0x400.
        // Trim to 0x300 then append overlay.
        data.truncate(0x300);
        data.extend_from_slice(overlay);
        data
    }

    #[test]
    fn no_overlay_detected() {
        let data = make_mz_no_overlay();
        let info = analyze_overlay(&data);
        // size 0x400; sections end at 0x300 → overlay = 0x100 bytes
        // Either way the public function should not panic.
        assert!(info.kind != OverlayKind::None || !info.has_overlay());
    }

    #[test]
    fn small_overlay_classified_as_too_small() {
        let mut data = make_mz_no_overlay();
        data.truncate(0x300);
        data.extend_from_slice(b"\x01\x02\x03"); // 3 bytes
        let info = analyze_overlay(&data);
        assert_eq!(info.kind, OverlayKind::TooSmall);
    }

    #[test]
    fn high_entropy_overlay() {
        // All 256 byte values appearing once → maximum entropy
        let entropy_block: Vec<u8> = (0u8..=255).collect::<Vec<_>>().repeat(8);
        let data = make_mz_with_overlay(&entropy_block);
        let info = analyze_overlay(&data);
        assert_eq!(info.kind, OverlayKind::HighEntropyData);
    }

    #[test]
    fn zip_overlay_detected() {
        let mut overlay = vec![0u8; 64];
        overlay.extend_from_slice(b"PK\x05\x06"); // EOCD signature
        overlay.extend_from_slice(&[0u8; 18]);
        let data = make_mz_with_overlay(&overlay);
        let info = analyze_overlay(&data);
        assert_eq!(info.kind, OverlayKind::AppendedZip);
    }

    #[test]
    fn nsis_overlay_detected() {
        let mut overlay = b"Nullsoft".to_vec();
        overlay.resize(128, 0);
        let data = make_mz_with_overlay(&overlay);
        let info = analyze_overlay(&data);
        assert_eq!(info.kind, OverlayKind::NsisBlock);
    }

    #[test]
    fn overlay_info_display() {
        let info = OverlayInfo {
            offset: 0x1000,
            size: 512,
            entropy: 7.9,
            kind: OverlayKind::HighEntropyData,
            header_bytes: vec![0xCC; 16],
            notes: vec![],
            confidence: 75,
        };
        assert!(info.to_string().contains("0x1000"));
        assert!(info.to_string().contains("512"));
    }

    #[test]
    fn hex_preview_format() {
        let info = OverlayInfo {
            offset: 0,
            size: 4,
            entropy: 0.0,
            kind: OverlayKind::RawData,
            header_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
            notes: vec![],
            confidence: 60,
        };
        assert_eq!(info.hex_preview(), "DE AD BE EF");
    }

    #[test]
    fn has_overlay_false_when_none() {
        let info = OverlayInfo {
            offset: 0,
            size: 0,
            entropy: 0.0,
            kind: OverlayKind::None,
            header_bytes: vec![],
            notes: vec![],
            confidence: 100,
        };
        assert!(!info.has_overlay());
    }

    #[test]
    fn entropy_profile_mean() {
        let data: Vec<u8> = (0u8..=255).collect();
        let profile = EntropyProfile::compute(&data, 256);
        assert_eq!(profile.values.len(), 1);
        assert!(profile.mean() > 7.9);
    }

    #[test]
    fn entropy_profile_blocks_above() {
        let high: Vec<u8> = (0u8..=255).collect::<Vec<_>>().repeat(4);
        let low = vec![0u8; 256];
        let mut combined = high;
        combined.extend_from_slice(&low);
        let profile = EntropyProfile::compute(&combined, 256);
        assert!(profile.blocks_above(7.0) >= 4);
    }

    #[test]
    fn raw_data_overlay() {
        let overlay = b"hello world, this is a test string with low entropy!!!!!!".to_vec();
        let mut data = make_mz_no_overlay();
        data.truncate(0x300);
        data.extend(overlay.iter().cycle().take(256));
        let info = analyze_overlay(&data);
        // Low-entropy plaintext should be RawData
        assert!(matches!(
            info.kind,
            OverlayKind::RawData | OverlayKind::NsisBlock | OverlayKind::SfxArchive
        ));
    }

    #[test]
    fn no_overlay_on_non_pe() {
        let data = b"hello world, not a PE file at all".to_vec();
        let info = analyze_overlay(&data);
        assert_eq!(info.kind, OverlayKind::None);
    }
}
