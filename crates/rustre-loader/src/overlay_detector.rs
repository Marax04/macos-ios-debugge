//! Overlay detector — identifies data appended beyond the declared end of a
//! binary's mapped image (PE, ELF, Mach-O, or raw blobs).
//!
//! Overlays are often used to attach configuration, certificates, packed
//! payloads, or self-extracting archives to an executable.

use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the overlay detector.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OverlayError {
    #[error("data too short: need {need}, have {have}")]
    TooShort { need: usize, have: usize },
    #[error("malformed binary header: {0}")]
    MalformedHeader(String),
    #[error("overlay region {offset}+{size} overflows file of {total} bytes")]
    Overflow { offset: usize, size: usize, total: usize },
}

pub type OverlayResult<T> = Result<T, OverlayError>;

// ─────────────────────────────────────────────────────────────────────────────
// OverlayKind
// ─────────────────────────────────────────────────────────────────────────────

/// Classifies the content or origin of a detected overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayKind {
    /// A PE-style certificate (`WIN_CERTIFICATE`) table appended beyond the image.
    PeCertificate,
    /// A ZIP archive (PK magic).
    Zip,
    /// A RAR archive (Rar! magic).
    Rar,
    /// A 7-zip archive (7z magic).
    SevenZip,
    /// A gzip stream.
    Gzip,
    /// A zlib stream (common DEFLATE wrapper).
    Zlib,
    /// An lzma / xz stream.
    Lzma,
    /// A zstd frame.
    Zstd,
    /// A bzip2 stream (BZ header).
    Bzip2,
    /// A PDF document.
    Pdf,
    /// Raw entropy-based heuristic: likely compressed or encrypted.
    HighEntropy,
    /// Raw entropy-based heuristic: likely plaintext.
    LowEntropy,
    /// SFX self-extracting marker (e.g. `AutoIt`, NSIS, Inno).
    SelfExtractor { signature: String },
    /// Generic digital signature blob.
    Signature,
    /// Configuration or resource block (low entropy).
    Config,
    /// Unknown / unclassified overlay.
    Unknown,
}

impl fmt::Display for OverlayKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeCertificate => write!(f, "PE Certificate"),
            Self::Zip => write!(f, "ZIP Archive"),
            Self::Rar => write!(f, "RAR Archive"),
            Self::SevenZip => write!(f, "7-Zip Archive"),
            Self::Gzip => write!(f, "Gzip Stream"),
            Self::Zlib => write!(f, "Zlib Stream"),
            Self::Lzma => write!(f, "LZMA/XZ Stream"),
            Self::Zstd => write!(f, "Zstd Frame"),
            Self::Bzip2 => write!(f, "Bzip2 Stream"),
            Self::Pdf => write!(f, "PDF Document"),
            Self::HighEntropy => write!(f, "High-Entropy Blob"),
            Self::LowEntropy => write!(f, "Low-Entropy Data"),
            Self::SelfExtractor { signature } => write!(f, "Self-Extractor ({signature})"),
            Self::Signature => write!(f, "Digital Signature"),
            Self::Config => write!(f, "Config / Resource"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OverlayRegion
// ─────────────────────────────────────────────────────────────────────────────

/// A detected overlay region within a binary file.
#[derive(Debug, Clone)]
pub struct OverlayRegion {
    /// Byte offset of the overlay start within the file.
    pub offset: usize,
    /// Size of the overlay in bytes.
    pub size: usize,
    /// Classified kind.
    pub kind: OverlayKind,
    /// Shannon entropy of the overlay data (0.0 = uniform, 8.0 = maximum).
    pub entropy: f64,
    /// MD5 hex digest of the overlay bytes (for deduplication / `IoC` matching).
    pub md5_hex: String,
}

impl OverlayRegion {
    /// End offset (exclusive) of the overlay.
    #[must_use]
    pub const fn end(&self) -> usize {
        self.offset + self.size
    }

    /// Return `true` if the overlay is potentially suspicious (high entropy or
    /// known archive format).
    #[must_use]
    pub fn is_suspicious(&self) -> bool {
        self.entropy > 7.0
            || matches!(
                self.kind,
                OverlayKind::Zip
                    | OverlayKind::Rar
                    | OverlayKind::SevenZip
                    | OverlayKind::HighEntropy
                    | OverlayKind::SelfExtractor { .. }
            )
    }
}

impl fmt::Display for OverlayRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Overlay @ {:#x}+{} ({}) entropy={:.2}",
            self.offset, self.size, self.kind, self.entropy
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Entropy calculation
// ─────────────────────────────────────────────────────────────────────────────

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = f64::from(u32::try_from(data.len()).unwrap_or(u32::MAX));
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / len;
            entropy = p.mul_add(-p.log2(), entropy);
        }
    }
    entropy
}

// ─────────────────────────────────────────────────────────────────────────────
// Naïve MD5 (no external deps — for identification only)
// ─────────────────────────────────────────────────────────────────────────────

fn md5_hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    // A minimal MD5 implementation to avoid external dependencies.
    // Based on the RFC 1321 reference algorithm.
    const S: [u32; 64] = [
        7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
        5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
        4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
        6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
    ];
    const K: [u32; 64] = [
        0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee,
        0xf57c_0faf, 0x4787_c62a, 0xa830_4613, 0xfd46_9501,
        0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be,
        0x6b90_1122, 0xfd98_7193, 0xa679_438e, 0x49b4_0821,
        0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa,
        0xd62f_105d, 0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8,
        0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed,
        0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a,
        0xfffa_3942, 0x8771_f681, 0x6d9d_6122, 0xfde5_380c,
        0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70,
        0x289b_7ec6, 0xeaa1_27fa, 0xd4ef_3085, 0x0488_1d05,
        0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665,
        0xf429_2244, 0x432a_ff97, 0xab94_23a7, 0xfc93_a039,
        0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
        0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1,
        0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb, 0xeb86_d391,
    ];

    let msg_len = data.len();
    let mut msg: Vec<u8> = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    let bit_len = u64::try_from(msg_len).unwrap_or(u64::MAX).wrapping_mul(8);
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xefcd_ab89;
    let mut c0: u32 = 0x98ba_dcfe;
    let mut d0: u32 = 0x1032_5476;

    for chunk in msg.chunks(64) {
        let mut msg_words = [0u32; 16];
        for (round_idx, word) in msg_words.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                chunk[round_idx*4], chunk[round_idx*4+1], chunk[round_idx*4+2], chunk[round_idx*4+3],
            ]);
        }
        let (mut md5_a, mut md5_b, mut md5_c, mut md5_d) = (a0, b0, c0, d0);
        for round_idx in 0usize..64 {
            let (mut md5_f, word_idx) = match round_idx {
                0..=15  => (md5_b & md5_c | !md5_b & md5_d, round_idx),
                16..=31 => (md5_d & md5_b | !md5_d & md5_c, (5*round_idx + 1) % 16),
                32..=47 => (md5_b ^ md5_c ^ md5_d,          (3*round_idx + 5) % 16),
                _       => (md5_c ^ (md5_b | !md5_d),       (7*round_idx)     % 16),
            };
            md5_f = md5_f.wrapping_add(md5_a).wrapping_add(K[round_idx]).wrapping_add(msg_words[word_idx]);
            md5_a = md5_d;
            md5_d = md5_c;
            md5_c = md5_b;
            md5_b = md5_b.wrapping_add(md5_f.rotate_left(S[round_idx]));
        }
        a0 = a0.wrapping_add(md5_a);
        b0 = b0.wrapping_add(md5_b);
        c0 = c0.wrapping_add(md5_c);
        d0 = d0.wrapping_add(md5_d);
    }

    let mut digest = [0u8; 16];
    digest[0..4].copy_from_slice(&a0.to_le_bytes());
    digest[4..8].copy_from_slice(&b0.to_le_bytes());
    digest[8..12].copy_from_slice(&c0.to_le_bytes());
    digest[12..16].copy_from_slice(&d0.to_le_bytes());

    digest.iter().fold(String::with_capacity(32), |mut acc, b| { let _ = write!(acc, "{b:02x}"); acc })
}

// ─────────────────────────────────────────────────────────────────────────────
// Format-specific image-end calculation
// ─────────────────────────────────────────────────────────────────────────────

/// Determine the end of the mapped image for a PE binary.
/// Returns `None` if the file is not a valid PE or has no overlay.
fn pe_image_end(data: &[u8]) -> Option<usize> {
    if data.len() < 64 || &data[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if e_lfanew + 4 > data.len() {
        return None;
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\x00\x00" {
        return None;
    }
    let coff_off = e_lfanew + 4;
    if coff_off + 20 > data.len() {
        return None;
    }
    let num_sections = u16::from_le_bytes([data[coff_off + 2], data[coff_off + 3]]) as usize;
    let opt_header_size = u16::from_le_bytes([data[coff_off + 16], data[coff_off + 17]]) as usize;

    // Check for security directory (certificate table) in optional header.
    let opt_off = coff_off + 20;
    let sections_off = opt_off + opt_header_size;

    // Optional header: magic at opt_off.
    let cert_table_offset = if opt_header_size > 0 && opt_off + 2 <= data.len() {
        let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
        let dir_off = match magic {
            0x10b => opt_off + 128, // PE32
            0x20b => opt_off + 144, // PE32+
            _ => return None,
        };
        if dir_off + 8 <= data.len() {
            let cert_off = u32::from_le_bytes([
                data[dir_off], data[dir_off+1], data[dir_off+2], data[dir_off+3],
            ]) as usize;
            let cert_sz = u32::from_le_bytes([
                data[dir_off+4], data[dir_off+5], data[dir_off+6], data[dir_off+7],
            ]) as usize;
            if cert_off > 0 && cert_sz > 0 {
                Some((cert_off, cert_sz))
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    // Compute end of last section raw data.
    let mut max_end = sections_off + num_sections * 40;
    for i in 0..num_sections {
        let s = sections_off + i * 40;
        if s + 40 > data.len() {
            break;
        }
        let raw_off = u32::from_le_bytes([data[s+20], data[s+21], data[s+22], data[s+23]]) as usize;
        let raw_sz  = u32::from_le_bytes([data[s+16], data[s+17], data[s+18], data[s+19]]) as usize;
        let end = raw_off.saturating_add(raw_sz);
        if end > max_end {
            max_end = end;
        }
    }

    // If a certificate table exists beyond section data, extend the image end.
    if let Some((cert_off, cert_sz)) = cert_table_offset {
        let cert_end = cert_off.saturating_add(cert_sz);
        if cert_end > max_end {
            max_end = cert_end;
        }
    }

    if max_end < data.len() {
        Some(max_end)
    } else {
        None
    }
}

/// Determine the end of the mapped image for an ELF binary.
fn elf_image_end(data: &[u8]) -> Option<usize> {
    if data.len() < 16 || &data[0..4] != b"\x7fELF" {
        return None;
    }
    let bits = data[4]; // 1 = 32, 2 = 64
    let le = data[5] == 1; // 1 = LE, 2 = BE

    let read16 = |off: usize| -> u16 {
        let b = [data[off], data[off+1]];
        if le { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) }
    };
    let read32 = |off: usize| -> u32 {
        let b = [data[off], data[off+1], data[off+2], data[off+3]];
        if le { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }
    };
    let read64 = |off: usize| -> u64 {
        let b = [data[off],data[off+1],data[off+2],data[off+3],
                 data[off+4],data[off+5],data[off+6],data[off+7]];
        if le { u64::from_le_bytes(b) } else { u64::from_be_bytes(b) }
    };

    let mut max_end = 0usize;
    if bits == 1 {
        // ELF32
        if data.len() < 52 { return None; }
        let shoff = read32(32) as usize;
        let shnum = read16(48) as usize;
        let shentsize = read16(46) as usize;
        for i in 0..shnum {
            let s = shoff + i * shentsize;
            if s + 40 > data.len() { break; }
            let off = read32(s + 16) as usize;
            let sz  = read32(s + 20) as usize;
            let t   = read32(s + 4);
            if t != 8 { // SHT_NOBITS
                let end = off.saturating_add(sz);
                if end > max_end { max_end = end; }
            }
        }
    } else {
        // ELF64
        if data.len() < 64 { return None; }
        let shoff = usize::try_from(read64(40)).unwrap_or(usize::MAX);
        let shnum = read16(60) as usize;
        let shentsize = read16(58) as usize;
        for i in 0..shnum {
            let s = shoff + i * shentsize;
            if s + 64 > data.len() { break; }
            let off = usize::try_from(read64(s + 24)).unwrap_or(usize::MAX);
            let sz  = usize::try_from(read64(s + 32)).unwrap_or(usize::MAX);
            let t   = read32(s + 4);
            if t != 8 { // SHT_NOBITS
                let end = off.saturating_add(sz);
                if end > max_end { max_end = end; }
            }
        }
    }

    if max_end > 0 && max_end < data.len() {
        Some(max_end)
    } else {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Magic-based classification
// ─────────────────────────────────────────────────────────────────────────────

fn classify_overlay(data: &[u8]) -> OverlayKind {
    if data.len() < 2 {
        return OverlayKind::Unknown;
    }

    // ZIP
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        return OverlayKind::Zip;
    }
    // RAR
    if data.starts_with(b"Rar!\x1a\x07") {
        return OverlayKind::Rar;
    }
    // 7z
    if data.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return OverlayKind::SevenZip;
    }
    // Gzip
    if data.starts_with(&[0x1f, 0x8b]) {
        return OverlayKind::Gzip;
    }
    // Zlib (most common: 0x78 0x9C / 0x78 0xDA / 0x78 0x01)
    if data[0] == 0x78 && matches!(data[1], 0x01 | 0x9c | 0xda | 0x5e) {
        return OverlayKind::Zlib;
    }
    // XZ / LZMA
    if data.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]) {
        return OverlayKind::Lzma;
    }
    // Zstd
    if data.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return OverlayKind::Zstd;
    }
    // Bzip2
    if data.starts_with(b"BZ") {
        return OverlayKind::Bzip2;
    }
    // PDF
    if data.starts_with(b"%PDF") {
        return OverlayKind::Pdf;
    }
    // Known SFX markers
    if data.starts_with(b"NSIS") || data.starts_with(b"MSCF") {
        return OverlayKind::SelfExtractor { signature: String::from_utf8_lossy(&data[..4]).into_owned() };
    }
    // PKCS#7 / DER signature
    if data[0] == 0x30 && data.len() > 4 {
        return OverlayKind::Signature;
    }

    // Entropy-based fallback
    let e = shannon_entropy(data);
    if e > 7.2 {
        OverlayKind::HighEntropy
    } else if e < 3.5 {
        OverlayKind::Config
    } else {
        OverlayKind::Unknown
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// detect_overlay — public function
// ─────────────────────────────────────────────────────────────────────────────

/// Detect overlay regions in `data`, returning any overlays found.
///
/// The function inspects the binary's header (PE, ELF, or raw) to determine
/// where the declared image ends, then classifies any trailing bytes.
///
/// # Errors
/// Returns [`OverlayError`] on severe header parse failures.
pub fn detect_overlay(data: &[u8]) -> OverlayResult<Vec<OverlayRegion>> {
    let mut regions = Vec::new();

    let image_end = if data.starts_with(b"MZ") {
        pe_image_end(data)
    } else if data.starts_with(&[0x7f, b'E', b'L', b'F']) {
        elf_image_end(data)
    } else {
        None
    };

    if let Some(end) = image_end
        && end < data.len() {
            let overlay_data = &data[end..];
            let entropy = shannon_entropy(overlay_data);
            let kind = classify_overlay(overlay_data);
            let md5 = md5_hex(overlay_data);
            regions.push(OverlayRegion {
                offset: end,
                size: overlay_data.len(),
                kind,
                entropy,
                md5_hex: md5,
            });
        }

    Ok(regions)
}

// ─────────────────────────────────────────────────────────────────────────────
// OverlayDetector
// ─────────────────────────────────────────────────────────────────────────────

/// Stateful overlay detector — accumulates findings across multiple files.
#[derive(Debug, Default)]
pub struct OverlayDetector {
    /// All detected overlay regions across all files analysed.
    findings: Vec<(String, OverlayRegion)>,
    /// Total files scanned.
    files_scanned: u64,
    /// Files where at least one overlay was found.
    files_with_overlay: u64,
}

impl OverlayDetector {
    /// Create a new detector.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Analyse a single file, identified by `name`, for overlays.
    ///
    /// All detected regions are accumulated internally and also returned.
    ///
    /// # Errors
    /// Propagates [`OverlayError`] from [`detect_overlay`].
    pub fn analyse(&mut self, name: impl Into<String>, data: &[u8]) -> OverlayResult<Vec<OverlayRegion>> {
        self.files_scanned += 1;
        let name = name.into();
        let regions = detect_overlay(data)?;
        if !regions.is_empty() {
            self.files_with_overlay += 1;
            for r in &regions {
                self.findings.push((name.clone(), r.clone()));
            }
        }
        Ok(regions)
    }

    /// Return all accumulated findings as `(filename, region)` pairs.
    #[must_use]
    pub fn findings(&self) -> &[(String, OverlayRegion)] {
        &self.findings
    }

    /// Return only suspicious findings.
    #[must_use]
    pub fn suspicious_findings(&self) -> Vec<(&str, &OverlayRegion)> {
        self.findings
            .iter()
            .filter(|(_, r)| r.is_suspicious())
            .map(|(n, r)| (n.as_str(), r))
            .collect()
    }

    /// Total files scanned.
    #[must_use]
    pub const fn files_scanned(&self) -> u64 {
        self.files_scanned
    }

    /// Files where at least one overlay was found.
    #[must_use]
    pub const fn files_with_overlay(&self) -> u64 {
        self.files_with_overlay
    }

    /// Clear all accumulated state.
    pub fn reset(&mut self) {
        self.findings.clear();
        self.files_scanned = 0;
        self.files_with_overlay = 0;
    }

    /// Return the overlay ratio (`files_with_overlay` / `files_scanned`).
    #[must_use]
    pub fn overlay_ratio(&self) -> f64 {
        if self.files_scanned == 0 {
            return 0.0;
        }
        f64::from(u32::try_from(self.files_with_overlay).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.files_scanned).unwrap_or(u32::MAX))
    }

    /// Return counts grouped by [`OverlayKind`] display name.
    #[must_use]
    pub fn kind_counts(&self) -> std::collections::HashMap<String, usize> {
        let mut map = std::collections::HashMap::new();
        for (_, r) in &self.findings {
            *map.entry(r.kind.to_string()).or_insert(0) += 1;
        }
        map
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_uniform() {
        let data = vec![0u8; 1024];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn entropy_random_ish() {
        let data: Vec<u8> = (0..=255u8).cycle().take(512).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.9, "expected near-8 entropy, got {e}");
    }

    #[test]
    fn classify_zip() {
        let data = b"PK\x03\x04some data";
        assert_eq!(classify_overlay(data), OverlayKind::Zip);
    }

    #[test]
    fn classify_gzip() {
        let data = &[0x1f, 0x8b, 0x08, 0x00, 0x00];
        assert_eq!(classify_overlay(data), OverlayKind::Gzip);
    }

    #[test]
    fn no_overlay_raw_blob() {
        let data = vec![0xAA; 100];
        let regions = detect_overlay(&data).unwrap();
        assert!(regions.is_empty());
    }

    #[test]
    fn md5_known() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        let digest = md5_hex(b"");
        assert_eq!(digest, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn overlay_detector_counts() {
        let mut d = OverlayDetector::new();
        let plain = vec![0u8; 64];
        d.analyse("clean.bin", &plain).unwrap();
        assert_eq!(d.files_scanned(), 1);
        assert_eq!(d.files_with_overlay(), 0);
    }
}
