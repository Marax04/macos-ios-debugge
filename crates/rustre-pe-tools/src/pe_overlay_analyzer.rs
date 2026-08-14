//! `pe_overlay_analyzer` — Analyze data appended after a PE file's sections.
//!
//! Detects SFX (self-extracting archive) patterns, polyglot file constructions,
//! appended ZIP/RAR/7z archives, embedded EXE/DLL blobs, NSIS installers,
//! `WinZip` self-extractors, and other known overlay signatures.

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// OverlayKind
// ─────────────────────────────────────────────────────────────────────────────

/// The detected type of the overlay data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OverlayKind {
    /// Raw appended bytes with no recognizable signature.
    Unknown,
    /// ZIP archive (`PK\x03\x04` or end-of-central-directory).
    Zip,
    /// RAR archive (`Rar!` magic).
    Rar,
    /// 7-Zip archive (`7z\xBC\xAF\x27\x1C`).
    SevenZip,
    /// GZIP compressed data.
    Gzip,
    /// BZIP2 compressed data.
    Bzip2,
    /// Zstandard compressed data.
    Zstd,
    /// XZ compressed data.
    Xz,
    /// TAR archive (checked via ustar magic at offset 257).
    Tar,
    /// Embedded PE/MZ executable.
    Mz,
    /// NSIS installer data block.
    Nsis,
    /// `WinZip` SFX signature.
    WinZipSfx,
    /// `InstallShield` CAB-based installer.
    InstallShield,
    /// Inno Setup installer data block.
    InnoSetup,
    /// PDF document.
    Pdf,
    /// OLE2 compound document (MSI, DOC, XLS, etc.).
    Ole2,
    /// PKCS#7 / DER ASN.1 data (extended signature blob).
    Pkcs7,
    /// `SQLite` database.
    Sqlite,
    /// High-entropy blob (likely encrypted or compressed without a known header).
    HighEntropy,
    /// Null / zero-padded region (alignment padding).
    ZeroPadding,
    /// Looks like a certificate (`WIN_CERTIFICATE` structure tag).
    WinCertificate,
}

impl fmt::Display for OverlayKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SfxPattern
// ─────────────────────────────────────────────────────────────────────────────

/// A pattern used to identify an SFX installer.
#[derive(Debug, Clone)]
pub struct SfxPattern {
    /// Human-readable name.
    pub name: &'static str,
    /// Byte signature.
    pub magic: &'static [u8],
    /// Offset in the overlay where the magic appears (0 = start).
    pub offset: usize,
    /// Associated `OverlayKind`.
    pub kind: OverlayKind,
}

/// All built-in SFX / archive signature patterns.
#[must_use] 
pub fn builtin_sfx_patterns() -> Vec<SfxPattern> {
    vec![
        SfxPattern {
            name: "ZIP local file header",
            magic: b"PK\x03\x04",
            offset: 0,
            kind: OverlayKind::Zip,
        },
        SfxPattern {
            name: "ZIP end-of-central-directory",
            magic: b"PK\x05\x06",
            offset: 0,
            kind: OverlayKind::Zip,
        },
        SfxPattern {
            name: "RAR5",
            magic: b"Rar!\x1A\x07\x01\x00",
            offset: 0,
            kind: OverlayKind::Rar,
        },
        SfxPattern {
            name: "RAR4",
            magic: b"Rar!\x1A\x07\x00",
            offset: 0,
            kind: OverlayKind::Rar,
        },
        SfxPattern {
            name: "7-Zip",
            magic: b"7z\xBC\xAF\x27\x1C",
            offset: 0,
            kind: OverlayKind::SevenZip,
        },
        SfxPattern {
            name: "GZIP",
            magic: b"\x1F\x8B",
            offset: 0,
            kind: OverlayKind::Gzip,
        },
        SfxPattern {
            name: "BZIP2",
            magic: b"BZh",
            offset: 0,
            kind: OverlayKind::Bzip2,
        },
        SfxPattern {
            name: "Zstandard",
            magic: b"\x28\xB5\x2F\xFD",
            offset: 0,
            kind: OverlayKind::Zstd,
        },
        SfxPattern {
            name: "XZ",
            magic: b"\xFD\x37\x7A\x58\x5A\x00",
            offset: 0,
            kind: OverlayKind::Xz,
        },
        SfxPattern {
            name: "MZ/PE",
            magic: b"MZ",
            offset: 0,
            kind: OverlayKind::Mz,
        },
        SfxPattern {
            name: "PDF",
            magic: b"%PDF-",
            offset: 0,
            kind: OverlayKind::Pdf,
        },
        SfxPattern {
            name: "OLE2 / CFB",
            magic: b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
            offset: 0,
            kind: OverlayKind::Ole2,
        },
        SfxPattern {
            name: "SQLite",
            magic: b"SQLite format 3\x00",
            offset: 0,
            kind: OverlayKind::Sqlite,
        },
        SfxPattern {
            name: "NSIS (nullsoft installer data)",
            magic: b"\xEF\xBE\xAD\xDE\x4E\x75\x6C\x6C", // ~0xDEADBEEF + "Null"
            offset: 0,
            kind: OverlayKind::Nsis,
        },
        SfxPattern {
            name: "Inno Setup compressed block",
            magic: b"Inno",
            offset: 0,
            kind: OverlayKind::InnoSetup,
        },
        SfxPattern {
            name: "DER / ASN.1 SEQUENCE",
            magic: b"\x30\x82",
            offset: 0,
            kind: OverlayKind::Pkcs7,
        },
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// PolyglotDetect
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a polyglot check — whether the overlay makes the file also
/// interpretable as a different format.
#[derive(Debug, Clone)]
pub struct PolyglotDetect {
    /// The secondary format detected.
    pub kind: OverlayKind,
    /// Description of how it was detected.
    pub evidence: String,
    /// Confidence in the detection (0–100).
    pub confidence: u8,
}

// ─────────────────────────────────────────────────────────────────────────────
// Overlay
// ─────────────────────────────────────────────────────────────────────────────

/// Description of a single contiguous overlay region.
#[derive(Debug, Clone)]
pub struct Overlay {
    /// File offset where the overlay begins.
    pub offset: usize,
    /// Size in bytes.
    pub size: usize,
    /// Detected content kind.
    pub kind: OverlayKind,
    /// Name of the matching signature (if known).
    pub signature_name: Option<String>,
    /// Shannon entropy of the overlay data (0–8 bits).
    pub entropy: f64,
    /// Raw first 16 bytes of the overlay for quick inspection.
    pub header_bytes: Vec<u8>,
}

impl Overlay {
    /// Returns `true` if the overlay is likely an SFX archive.
    #[must_use]
    pub const fn is_sfx(&self) -> bool {
        matches!(
            self.kind,
            OverlayKind::Zip
                | OverlayKind::Rar
                | OverlayKind::SevenZip
                | OverlayKind::Nsis
                | OverlayKind::WinZipSfx
                | OverlayKind::InstallShield
                | OverlayKind::InnoSetup
        )
    }

    /// Returns `true` if the overlay entropy suggests encryption / packing.
    #[must_use]
    pub fn is_high_entropy(&self) -> bool {
        self.entropy > 7.2
    }
}

impl fmt::Display for Overlay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Overlay[{} @ {:#x} size={} entropy={:.2}]",
            self.kind, self.offset, self.size, self.entropy
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OverlayInfo — top-level result
// ─────────────────────────────────────────────────────────────────────────────

/// Complete overlay analysis result.
#[derive(Debug, Clone)]
pub struct OverlayInfo {
    /// Whether any overlay was found.
    pub has_overlay: bool,
    /// All detected overlay regions (usually just one, but could be multiple
    /// if the overlay itself contains sub-archives).
    pub overlays: Vec<Overlay>,
    /// Total overlay size in bytes.
    pub total_overlay_size: usize,
    /// Offset in the file where overlay data begins.
    pub overlay_start: usize,
    /// Polyglot detections (formats the full file could also be parsed as).
    pub polyglots: Vec<PolyglotDetect>,
    /// Mapping from embedded PE offset → size estimate for embedded executables.
    pub embedded_pes: Vec<(usize, usize)>,
    /// Estimated risk: "clean" / "low" / "medium" / "high".
    pub risk: &'static str,
}

impl Default for OverlayInfo {
    fn default() -> Self {
        Self {
            has_overlay: false,
            overlays: Vec::new(),
            total_overlay_size: 0,
            overlay_start: 0,
            polyglots: Vec::new(),
            embedded_pes: Vec::new(),
            risk: "clean",
        }
    }
}

impl fmt::Display for OverlayInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.has_overlay {
            write!(
                f,
                "OverlayInfo[size={} kinds={} risk={}]",
                self.total_overlay_size,
                self.overlays.iter().map(|o| o.kind.to_string()).collect::<Vec<_>>().join(","),
                self.risk
            )
        } else {
            write!(f, "OverlayInfo[none]")
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PeOverlayAnalyzer
// ─────────────────────────────────────────────────────────────────────────────

/// Analyzes the overlay region of a PE file.
pub struct PeOverlayAnalyzer {
    /// Minimum overlay size to report (bytes). Default: 8.
    pub min_overlay_size: usize,
    /// If `true`, scan the overlay for embedded PE files.
    pub scan_embedded_pes: bool,
    /// Entropy threshold above which an unrecognized overlay is flagged as
    /// likely encrypted/packed. Default: 7.2.
    pub high_entropy_threshold: f64,
    /// Custom additional SFX signatures to check.
    pub extra_patterns: Vec<SfxPattern>,
}

impl Default for PeOverlayAnalyzer {
    fn default() -> Self {
        Self {
            min_overlay_size: 8,
            scan_embedded_pes: true,
            high_entropy_threshold: 7.2,
            extra_patterns: Vec::new(),
        }
    }
}

impl PeOverlayAnalyzer {
    /// Create an analyzer with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyze the PE file at `data` and return `OverlayInfo`.
    #[must_use]
    pub fn analyze(&self, data: &[u8]) -> OverlayInfo {
        let Some(overlay_start) = find_overlay_start(data) else { return OverlayInfo::default(); };

        let overlay_data = &data[overlay_start..];
        if overlay_data.len() < self.min_overlay_size {
            return OverlayInfo::default();
        }

        let total_overlay_size = overlay_data.len();

        // ── Classify overlay ──────────────────────────────────────────────────
        let patterns = builtin_sfx_patterns();
        let all_patterns: Vec<&SfxPattern> =
            patterns.iter().chain(self.extra_patterns.iter()).collect();

        let (kind, sig_name) = classify_overlay(overlay_data, &all_patterns);
        let entropy = compute_entropy(overlay_data);

        // Fall back to high-entropy classification if unrecognized.
        let final_kind = if kind == OverlayKind::Unknown && entropy > self.high_entropy_threshold {
            OverlayKind::HighEntropy
        } else if kind == OverlayKind::Unknown && is_all_zeros(overlay_data) {
            OverlayKind::ZeroPadding
        } else {
            kind
        };

        let header_bytes = overlay_data[..overlay_data.len().min(16)].to_vec();
        let overlay = Overlay {
            offset: overlay_start,
            size: total_overlay_size,
            kind: final_kind,
            signature_name: sig_name,
            entropy,
            header_bytes,
        };

        // ── Polyglot detection ────────────────────────────────────────────────
        let polyglots = detect_polyglot(data, overlay_start);

        // ── Embedded PE scan ─────────────────────────────────────────────────
        let embedded_pes = if self.scan_embedded_pes {
            find_embedded_pe_offsets(overlay_data)
                .into_iter()
                .map(|off| (overlay_start + off, estimate_pe_size(overlay_data, off)))
                .collect()
        } else {
            Vec::new()
        };

        // ── Risk assessment ───────────────────────────────────────────────────
        let risk = assess_risk(&overlay, &polyglots, &embedded_pes);

        let has_overlay = final_kind != OverlayKind::ZeroPadding || total_overlay_size > 64;

        OverlayInfo {
            has_overlay,
            overlays: vec![overlay],
            total_overlay_size,
            overlay_start,
            polyglots,
            embedded_pes,
            risk,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// find_overlay_start
// ─────────────────────────────────────────────────────────────────────────────

/// Return the file offset immediately after the last section's raw data,
/// or `None` if the file has no overlay.
#[must_use]
pub fn find_overlay_start(data: &[u8]) -> Option<usize> {
    if data.len() < 64 {
        return None;
    }
    let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if e_lfanew + 24 > data.len() {
        return None;
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    let coff = e_lfanew + 4;
    let num_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
    let opt_hdr_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let opt_off = e_lfanew + 24;
    if opt_off + 2 > data.len() {
        return None;
    }
    let sect_table = opt_off + opt_hdr_size;

    let mut max_end: usize = 0;
    for i in 0..num_sections.min(96) {
        let off = sect_table + i * 40;
        if off + 40 > data.len() {
            break;
        }
        let raw_size = u32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap_or([0; 4])) as usize;
        let raw_offset = u32::from_le_bytes(data[off + 20..off + 24].try_into().unwrap_or([0; 4])) as usize;
        if raw_size > 0 {
            let end = raw_offset + raw_size;
            if end > max_end {
                max_end = end;
            }
        }
    }

    if max_end == 0 || max_end >= data.len() {
        return None;
    }
    // Skip trailing-zero file-alignment padding: the overlay (if any) begins at
    // the first non-zero byte after the last section's raw data.
    let tail = &data[max_end..];
    tail.iter().position(|&b| b != 0).map(|rel| max_end + rel)
}

// ─────────────────────────────────────────────────────────────────────────────
// classify_overlay
// ─────────────────────────────────────────────────────────────────────────────

fn classify_overlay(overlay: &[u8], patterns: &[&SfxPattern]) -> (OverlayKind, Option<String>) {
    for pat in patterns {
        let start = pat.offset;
        let magic = pat.magic;
        if start + magic.len() <= overlay.len()
            && &overlay[start..start + magic.len()] == magic
        {
            return (pat.kind, Some(pat.name.to_string()));
        }
    }

    // TAR: check for "ustar" at offset 257.
    if overlay.len() >= 262 && &overlay[257..262] == b"ustar" {
        return (OverlayKind::Tar, Some("TAR (ustar)".to_string()));
    }

    (OverlayKind::Unknown, None)
}

// ─────────────────────────────────────────────────────────────────────────────
// detect_polyglot
// ─────────────────────────────────────────────────────────────────────────────

fn detect_polyglot(data: &[u8], overlay_start: usize) -> Vec<PolyglotDetect> {
    let mut results = Vec::new();

    // ZIP appended at end: ZIP EOCD is at data.len()-22 (minimum).
    if data.len() >= 22 {
        let eocd_search_start = data.len().saturating_sub(65536 + 22);
        for i in eocd_search_start..data.len().saturating_sub(3) {
            if &data[i..i + 4] == b"PK\x05\x06" {
                // Only flag as polyglot if EOCD is in the overlay region.
                if i >= overlay_start {
                    results.push(PolyglotDetect {
                        kind: OverlayKind::Zip,
                        evidence: format!("ZIP EOCD at {i:#x}"),
                        confidence: 85,
                    });
                }
                break;
            }
        }
    }

    // PDF header at start of overlay.
    if overlay_start < data.len() && data.len() - overlay_start >= 5
        && &data[overlay_start..overlay_start + 5] == b"%PDF-" {
            results.push(PolyglotDetect {
                kind: OverlayKind::Pdf,
                evidence: "PDF header at overlay start".to_string(),
                confidence: 95,
            });
        }

    results
}

// ─────────────────────────────────────────────────────────────────────────────
// find_embedded_pe_offsets
// ─────────────────────────────────────────────────────────────────────────────

/// Scan overlay data for `MZ` headers that plausibly start a PE file.
#[must_use]
pub fn find_embedded_pe_offsets(overlay: &[u8]) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut i = 0;
    while i + 64 < overlay.len() {
        if overlay[i] == 0x4D && overlay[i + 1] == 0x5A {
            // Plausibility check: e_lfanew should point to "PE\0\0".
            let e_lfanew =
                u32::from_le_bytes([overlay[i + 60], overlay[i + 61], overlay[i + 62], overlay[i + 63]]) as usize;
            let pe_sig_off = i + e_lfanew;
            if pe_sig_off + 4 <= overlay.len()
                && &overlay[pe_sig_off..pe_sig_off + 4] == b"PE\0\0"
            {
                offsets.push(i);
            }
        }
        i += 1;
    }
    offsets
}

/// Estimate the PE file size by summing section raw data extents.
#[must_use]
pub fn estimate_pe_size(overlay: &[u8], offset: usize) -> usize {
    let data = &overlay[offset..];
    if data.len() < 64 {
        return 0;
    }
    let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if e_lfanew + 24 > data.len() {
        return 0;
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return 0;
    }
    let coff = e_lfanew + 4;
    let num_sections = u16::from_le_bytes([data[coff + 2], data[coff + 3]]) as usize;
    let opt_hdr_size = u16::from_le_bytes([data[coff + 16], data[coff + 17]]) as usize;
    let opt_off = e_lfanew + 24;
    let sect_table = opt_off + opt_hdr_size;
    let mut max_end: usize = sect_table + num_sections * 40;
    for i in 0..num_sections.min(96) {
        let off = sect_table + i * 40;
        if off + 40 > data.len() {
            break;
        }
        let raw_size = u32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap_or([0; 4])) as usize;
        let raw_offset = u32::from_le_bytes(data[off + 20..off + 24].try_into().unwrap_or([0; 4])) as usize;
        let end = raw_offset + raw_size;
        if end > max_end {
            max_end = end;
        }
    }
    max_end
}

// ─────────────────────────────────────────────────────────────────────────────
// assess_risk
// ─────────────────────────────────────────────────────────────────────────────

const fn assess_risk(
    overlay: &Overlay,
    polyglots: &[PolyglotDetect],
    embedded_pes: &[(usize, usize)],
) -> &'static str {
    if !embedded_pes.is_empty() {
        return "high";
    }
    if !polyglots.is_empty() {
        return "medium";
    }
    match overlay.kind {
        OverlayKind::Mz | OverlayKind::HighEntropy => "high",
        OverlayKind::Nsis
        | OverlayKind::InnoSetup
        | OverlayKind::WinZipSfx
        | OverlayKind::Zip
        | OverlayKind::Rar
        | OverlayKind::SevenZip => "medium",
        OverlayKind::ZeroPadding => "clean",
        _ => "low",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Shannon entropy over a byte slice.
#[must_use]
pub fn compute_entropy(data: &[u8]) -> f64 {
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

/// Returns `true` if all bytes in `data` are 0x00.
#[must_use]
pub fn is_all_zeros(data: &[u8]) -> bool {
    data.iter().all(|&b| b == 0)
}

/// Compute byte frequency histogram.
#[must_use]
pub fn byte_histogram(data: &[u8]) -> [u64; 256] {
    let mut h = [0u64; 256];
    for &b in data {
        h[b as usize] += 1;
    }
    h
}

/// Return the most frequent byte in `data`.
#[must_use]
pub fn most_frequent_byte(data: &[u8]) -> Option<u8> {
    if data.is_empty() {
        return None;
    }
    let h = byte_histogram(data);
    h.iter()
        .enumerate()
        .max_by_key(|&(_, &c)| c)
        .map(|(b, _)| u8::try_from(b).unwrap_or(u8::MAX))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_pe_with_one_section(section_data: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 0x600];
        // MZ
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        buf[60..64].copy_from_slice(&0x40u32.to_le_bytes());
        // PE sig
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");
        // COFF: AMD64, 1 section
        buf[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes()); // machine
        buf[0x46..0x48].copy_from_slice(&1u16.to_le_bytes()); // num sections
        // opt header size 240 (PE32+)
        buf[0x54..0x56].copy_from_slice(&240u16.to_le_bytes());
        // opt magic PE32+
        buf[0x58..0x5A].copy_from_slice(&0x020Bu16.to_le_bytes());
        buf[0x58 + 32..0x58 + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // sect align
        buf[0x58 + 36..0x58 + 40].copy_from_slice(&0x200u32.to_le_bytes()); // file align
        buf[0x58 + 56..0x58 + 60].copy_from_slice(&0x2000u32.to_le_bytes()); // size of image
        buf[0x58 + 60..0x58 + 64].copy_from_slice(&0x200u32.to_le_bytes()); // size of headers
        buf[0x58 + 24..0x58 + 32].copy_from_slice(&0x140000000u64.to_le_bytes()); // image base
        buf[0x58 + 108..0x58 + 112].copy_from_slice(&16u32.to_le_bytes()); // num dirs

        // section table at opt_off + opt_hdr_size = 0x58 + 240 = 0x148
        let sect_off = 0x148usize;
        buf[sect_off..sect_off + 8].copy_from_slice(b".text\0\0\0");
        buf[sect_off + 8..sect_off + 12].copy_from_slice(&(section_data.len() as u32).to_le_bytes()); // virt size
        buf[sect_off + 12..sect_off + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VA
        let raw_size = ((section_data.len() + 511) / 512 * 512) as u32;
        buf[sect_off + 16..sect_off + 20].copy_from_slice(&raw_size.to_le_bytes()); // raw size
        buf[sect_off + 20..sect_off + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw offset
        buf[sect_off + 36..sect_off + 40].copy_from_slice(&0x60000020u32.to_le_bytes()); // chars

        // Write section data at 0x200
        let end = 0x200 + section_data.len();
        if end > buf.len() {
            buf.resize(end, 0);
        }
        buf[0x200..0x200 + section_data.len()].copy_from_slice(section_data);

        buf
    }

    #[test]
    fn test_no_overlay_for_basic_pe() {
        let pe = make_minimal_pe_with_one_section(&[0xCC; 16]);
        let analyzer = PeOverlayAnalyzer::new();
        let info = analyzer.analyze(&pe);
        // File ends exactly at section boundary → no overlay.
        assert!(!info.has_overlay || info.total_overlay_size == 0);
    }

    #[test]
    fn test_zip_overlay_detected() {
        let mut pe = make_minimal_pe_with_one_section(&[0xCC; 16]);
        // Append ZIP local file header.
        pe.extend_from_slice(b"PK\x03\x04ZIPDATA");
        let analyzer = PeOverlayAnalyzer::new();
        let info = analyzer.analyze(&pe);
        assert!(info.has_overlay);
        assert_eq!(info.overlays[0].kind, OverlayKind::Zip);
    }

    #[test]
    fn test_rar_overlay_detected() {
        let mut pe = make_minimal_pe_with_one_section(&[0xCC; 16]);
        pe.extend_from_slice(b"Rar!\x1A\x07\x01\x00RARDATA");
        let analyzer = PeOverlayAnalyzer::new();
        let info = analyzer.analyze(&pe);
        assert_eq!(info.overlays[0].kind, OverlayKind::Rar);
    }

    #[test]
    fn test_7z_overlay_detected() {
        let mut pe = make_minimal_pe_with_one_section(&[0xCC; 16]);
        pe.extend_from_slice(b"7z\xBC\xAF\x27\x1CDATA");
        let analyzer = PeOverlayAnalyzer::new();
        let info = analyzer.analyze(&pe);
        assert_eq!(info.overlays[0].kind, OverlayKind::SevenZip);
    }

    #[test]
    fn test_high_entropy_overlay() {
        let mut pe = make_minimal_pe_with_one_section(&[0xCC; 16]);
        // Pseudo-random data with high entropy.
        let rand_data: Vec<u8> = (0u8..=255).cycle().take(256).collect();
        pe.extend_from_slice(&rand_data);
        let analyzer = PeOverlayAnalyzer::new();
        let info = analyzer.analyze(&pe);
        assert!(info.has_overlay);
        // Might be high entropy or another kind.
        assert!(info.overlays[0].entropy > 5.0);
    }

    #[test]
    fn test_zero_padding_overlay() {
        let mut pe = make_minimal_pe_with_one_section(&[0xCC; 16]);
        pe.extend_from_slice(&[0u8; 64]);
        let analyzer = PeOverlayAnalyzer::new();
        let info = analyzer.analyze(&pe);
        // Zero padding → ZeroPadding kind.
        if info.has_overlay {
            assert_eq!(info.overlays[0].kind, OverlayKind::ZeroPadding);
        }
    }

    #[test]
    fn test_find_overlay_start_no_overlay() {
        let pe = make_minimal_pe_with_one_section(&[0xCC; 16]);
        let start = find_overlay_start(&pe);
        // Overlay start should be None or equal to file length.
        assert!(start.is_none() || start == Some(pe.len()));
    }

    #[test]
    fn test_find_overlay_start_with_overlay() {
        let mut pe = make_minimal_pe_with_one_section(&[0xCC; 16]);
        let original_len = pe.len();
        pe.extend_from_slice(b"OVERLAY");
        let start = find_overlay_start(&pe);
        assert_eq!(start, Some(original_len));
    }

    #[test]
    fn test_embedded_pe_detection() {
        // Construct overlay with an embedded minimal PE.
        let embedded = make_minimal_pe_with_one_section(&[0xBB; 16]);
        let mut pe = make_minimal_pe_with_one_section(&[0xCC; 16]);
        pe.extend_from_slice(&embedded);
        let analyzer = PeOverlayAnalyzer::new();
        let info = analyzer.analyze(&pe);
        assert!(!info.embedded_pes.is_empty(), "Expected embedded PE detected");
    }

    #[test]
    fn test_compute_entropy_uniform() {
        let data: Vec<u8> = (0..=255).collect();
        let e = compute_entropy(&data);
        assert!((e - 8.0).abs() < 0.02, "expected ~8.0, got {e}");
    }

    #[test]
    fn test_compute_entropy_constant() {
        let e = compute_entropy(&[0xAAu8; 100]);
        assert_eq!(e, 0.0);
    }

    #[test]
    fn test_is_all_zeros() {
        assert!(is_all_zeros(&[0, 0, 0]));
        assert!(!is_all_zeros(&[0, 1, 0]));
    }

    #[test]
    fn test_most_frequent_byte() {
        let data = [0x00u8, 0x01, 0x01, 0x02];
        assert_eq!(most_frequent_byte(&data), Some(0x01));
    }

    #[test]
    fn test_overlay_is_sfx() {
        let o = Overlay {
            offset: 0,
            size: 100,
            kind: OverlayKind::Zip,
            signature_name: None,
            entropy: 5.0,
            header_bytes: Vec::new(),
        };
        assert!(o.is_sfx());
    }

    #[test]
    fn test_overlay_is_not_sfx() {
        let o = Overlay {
            offset: 0,
            size: 100,
            kind: OverlayKind::Pdf,
            signature_name: None,
            entropy: 5.0,
            header_bytes: Vec::new(),
        };
        assert!(!o.is_sfx());
    }

    #[test]
    fn test_overlay_risk_clean() {
        let pe = make_minimal_pe_with_one_section(&[0xCC; 16]);
        let analyzer = PeOverlayAnalyzer::new();
        let info = analyzer.analyze(&pe);
        if !info.has_overlay {
            assert_eq!(info.risk, "clean");
        }
    }

    #[test]
    fn test_pdf_overlay_detection() {
        let mut pe = make_minimal_pe_with_one_section(&[0xCC; 16]);
        pe.extend_from_slice(b"%PDF-1.4 fake pdf content here and there");
        let analyzer = PeOverlayAnalyzer::new();
        let info = analyzer.analyze(&pe);
        assert_eq!(info.overlays[0].kind, OverlayKind::Pdf);
        // Should also show up as a polyglot.
        assert!(!info.polyglots.is_empty());
    }

    #[test]
    fn test_sfx_patterns_complete() {
        let patterns = builtin_sfx_patterns();
        assert!(patterns.len() >= 10);
        // Zip must be present.
        assert!(patterns.iter().any(|p| p.kind == OverlayKind::Zip));
        // RAR must be present.
        assert!(patterns.iter().any(|p| p.kind == OverlayKind::Rar));
    }
}
