//! `extractor` — Firmware extraction engine.
//!
//! Implements a binwalk-equivalent recursive extraction pipeline.
//! Given a raw binary blob, the extractor:
//!
//! 1. Runs the [`crate::signature_db::SignatureDb`] scanner to locate embedded
//!    file-format regions.
//! 2. For each candidate region, estimates the payload size (where known from
//!    the format header) or falls back to entropy-based boundary detection.
//! 3. Records each found region as an [`ExtractionResult`].
//! 4. Optionally recurses into extracted regions (depth-limited).
//!
//! # Usage
//! ```rust,no_run
//! use rustre_loader_firmware::extractor::FirmwareExtractor;
//! let data: Vec<u8> = std::fs::read("firmware.bin").unwrap();
//! let extractor = FirmwareExtractor::new();
//! let results = extractor.extract(&data);
//! for r in &results {
//!     println!("{r}");
//! }
//! ```

use crate::entropy_analysis::{EntropyAnalyzer, EntropyClass};
use crate::signature_db::{SignatureCategory, SignatureDb};
use std::fmt;

// ─────────────────────────────────────────────────────────────────────────────
// Result types
// ─────────────────────────────────────────────────────────────────────────────

/// Type tag for a found region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegionType {
    Compressed,
    Filesystem,
    Executable,
    Bootloader,
    Certificate,
    Encrypted,
    Archive,
    Config,
    FirmwareContainer,
    Unknown,
}

impl fmt::Display for RegionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Compressed => "compressed",
            Self::Filesystem => "filesystem",
            Self::Executable => "executable",
            Self::Bootloader => "bootloader",
            Self::Certificate => "certificate",
            Self::Encrypted => "encrypted",
            Self::Archive => "archive",
            Self::Config => "config",
            Self::FirmwareContainer => "firmware-container",
            Self::Unknown => "unknown",
        };
        write!(f, "{s}")
    }
}

impl From<SignatureCategory> for RegionType {
    fn from(c: SignatureCategory) -> Self {
        match c {
            SignatureCategory::Compression => Self::Compressed,
            SignatureCategory::Filesystem => Self::Filesystem,
            SignatureCategory::Executable => Self::Executable,
            SignatureCategory::Bootloader => Self::Bootloader,
            SignatureCategory::Certificate => Self::Certificate,
            SignatureCategory::Encrypted => Self::Encrypted,
            SignatureCategory::Archive => Self::Archive,
            SignatureCategory::Config => Self::Config,
            SignatureCategory::FirmwareContainer => Self::FirmwareContainer,
            SignatureCategory::OsImage => Self::Bootloader,
            SignatureCategory::Generic => Self::Unknown,
        }
    }
}

/// A single extracted (or detected) region in a firmware image.
#[derive(Debug, Clone)]
pub struct ExtractionResult {
    /// Byte offset of the region within the top-level firmware image.
    pub offset: usize,
    /// Detected byte size of the region.
    /// May be approximate when size cannot be determined from the header.
    pub size: usize,
    /// High-level type of the region.
    pub region_type: RegionType,
    /// Human-readable format name from the signature database.
    pub format_name: String,
    /// Confidence score (0–100) from the signature database.
    pub confidence: u8,
    /// Shannon entropy of the region (0.0 – 8.0).
    pub entropy: f64,
    /// Whether the entropy suggests this region is compressed / encrypted.
    pub high_entropy: bool,
    /// Nested extractions (populated only when recursion is enabled).
    pub nested: Vec<ExtractionResult>,
}

impl fmt::Display for ExtractionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#010x}  size={:>10}  {:20}  {:18}  conf={:3}  H={:.2}{}",
            self.offset,
            self.size,
            self.format_name,
            self.region_type,
            self.confidence,
            self.entropy,
            if self.high_entropy {
                "  [high-entropy]"
            } else {
                ""
            },
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Size estimators
// ─────────────────────────────────────────────────────────────────────────────

/// Attempt to read the payload size from a U-Boot legacy header.
fn size_from_uboot(data: &[u8], offset: usize) -> Option<usize> {
    if offset + 64 > data.len() {
        return None;
    }
    let magic = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    if magic != 0x2705_1956 {
        return None;
    }
    let payload_size = u32::from_be_bytes([
        data[offset + 12],
        data[offset + 13],
        data[offset + 14],
        data[offset + 15],
    ]) as usize;
    Some(64 + payload_size)
}

/// Read SquashFS total size from the LE or BE superblock.
fn size_from_squashfs(data: &[u8], offset: usize) -> Option<usize> {
    if offset + 40 > data.len() {
        return None;
    }
    // LE squashfs: bytes_used at offset 40 in header (8 bytes, LE u64)
    let magic = u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ]);
    let le = magic == 0x7371_7368 || magic == 0x6873_7173;
    let be = magic == 0x7173_6873 || magic == 0x7368_7371;
    if !le && !be {
        return None;
    }
    // bytes_used is at offset 40 within the squashfs superblock
    if offset + 48 > data.len() {
        return None;
    }
    let bytes_used = if le {
        u64::from_le_bytes(data[offset + 40..offset + 48].try_into().ok()?) as usize
    } else {
        u64::from_be_bytes(data[offset + 40..offset + 48].try_into().ok()?) as usize
    };
    if bytes_used == 0 || bytes_used > data.len() - offset {
        return None;
    }
    Some(bytes_used)
}

/// Estimate size by scanning forward from `offset` until entropy drops below
/// the compressed/encrypted threshold.  Falls back to end-of-buffer.
fn size_by_entropy_scan(data: &[u8], offset: usize, window: usize, step: usize) -> usize {
    let analyzer = EntropyAnalyzer::default();
    let region = &data[offset..];
    if region.len() <= window {
        return region.len();
    }

    let mut last_high = 0usize;
    let mut pos = 0usize;
    while pos + window <= region.len() {
        let chunk = &region[pos..pos + window];
        let ec = analyzer.classify_block(chunk);
        match ec {
            EntropyClass::High | EntropyClass::Encrypted | EntropyClass::Compressed => {
                last_high = pos + window;
            }
            _ => {
                // Once entropy drops, stop if we've moved at least 2 windows past start
                if last_high >= window * 2 {
                    break;
                }
            }
        }
        pos += step;
    }
    if last_high == 0 {
        region.len()
    } else {
        last_high
    }
}

/// Try to read a CPIO archive size by walking the headers.
fn size_from_cpio_newc(data: &[u8], offset: usize) -> Option<usize> {
    // CPIO newc: each header is 110 bytes ASCII, then pathname, then data
    if offset + 110 > data.len() {
        return None;
    }
    if &data[offset..offset + 6] != b"070701" && &data[offset..offset + 6] != b"070702" {
        return None;
    }
    let mut pos = offset;
    loop {
        if pos + 110 > data.len() {
            break;
        }
        if &data[pos..pos + 6] != b"070701" && &data[pos..pos + 6] != b"070702" {
            break;
        }
        // namesize at field offset 94 (8 hex chars)
        let namesize_hex = std::str::from_utf8(&data[pos + 94..pos + 102]).ok()?;
        let namesize = usize::from_str_radix(namesize_hex.trim(), 16).ok()?;
        // filesize at field offset 54 (8 hex chars)
        let filesize_hex = std::str::from_utf8(&data[pos + 54..pos + 62]).ok()?;
        let filesize = usize::from_str_radix(filesize_hex.trim(), 16).ok()?;
        // Advance: header + namesize (rounded to 4) + filesize (rounded to 4)
        let after_hdr = pos + 110;
        let after_name = after_hdr + namesize;
        let after_name_aligned = (after_name + 3) & !3;
        let after_data = after_name_aligned + filesize;
        let after_data_aligned = (after_data + 3) & !3;
        if after_data_aligned > data.len() {
            break;
        }
        // Trailer record is named "TRAILER!!!"
        if &data[after_hdr..after_hdr + namesize.min(11)] == b"TRAILER!!!\0" {
            return Some(after_data_aligned - offset);
        }
        pos = after_data_aligned;
    }
    None
}

/// Try to get ZIP file total size from EOCD record.
fn size_from_zip(data: &[u8], offset: usize) -> Option<usize> {
    // Scan backwards for EOCD magic PK\x05\x06
    if offset + 4 > data.len() {
        return None;
    }
    let search_start = (data.len().saturating_sub(65536 + 22)).max(offset);
    let eocd_marker = b"PK\x05\x06";
    let eocd_pos = data[search_start..]
        .windows(4)
        .position(|w| w == eocd_marker)?
        + search_start;
    if eocd_pos + 22 > data.len() {
        return None;
    }
    // comment_length at offset 20 within EOCD
    let comment_len = u16::from_le_bytes([data[eocd_pos + 20], data[eocd_pos + 21]]) as usize;
    Some(eocd_pos + 22 + comment_len - offset)
}

/// Estimate size for a gzip stream by scanning for the end marker or using
/// raw size field if available.
fn size_from_gzip(data: &[u8], offset: usize) -> Option<usize> {
    // Minimal: at least 18 bytes (10-byte header + 8-byte footer)
    if offset + 18 > data.len() {
        return None;
    }
    if data[offset] != 0x1F || data[offset + 1] != 0x8B {
        return None;
    }
    // ISIZE is the last 4 bytes of the gzip member.  We cannot know the exact
    // member end without decompressing, so we use heuristic entropy scan.
    let est = size_by_entropy_scan(data, offset, 512, 256);
    if est < 18 {
        Some(data.len() - offset)
    } else {
        Some(est)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FirmwareExtractor
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the extractor.
#[derive(Debug, Clone)]
pub struct ExtractorConfig {
    /// Minimum confidence threshold for signature matches to be reported.
    pub min_confidence: u8,
    /// Maximum recursion depth (0 = no recursion, just top-level scan).
    pub max_depth: usize,
    /// Minimum region size in bytes to emit.
    pub min_region_size: usize,
    /// Entropy window size used for boundary detection.
    pub entropy_window: usize,
    /// Entropy step size.
    pub entropy_step: usize,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        Self {
            min_confidence: 50,
            max_depth: 3,
            min_region_size: 16,
            entropy_window: 512,
            entropy_step: 256,
        }
    }
}

/// Firmware extraction engine.
pub struct FirmwareExtractor {
    db: SignatureDb,
    pub config: ExtractorConfig,
}

impl FirmwareExtractor {
    /// Create a new extractor with default configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            db: SignatureDb::new(),
            config: ExtractorConfig::default(),
        }
    }

    /// Create with custom configuration.
    #[must_use]
    pub fn with_config(config: ExtractorConfig) -> Self {
        Self {
            db: SignatureDb::new(),
            config,
        }
    }

    /// Scan `data` for embedded regions and return extraction results.
    /// This is the primary entry point.
    #[must_use]
    pub fn extract(&self, data: &[u8]) -> Vec<ExtractionResult> {
        self.extract_at(data, 0, self.config.max_depth)
    }

    /// Scan `data` (interpreted as starting at `base_offset` in the original
    /// image) for embedded regions.  `remaining_depth` controls recursion.
    #[must_use]
    pub fn extract_at(
        &self,
        data: &[u8],
        base_offset: usize,
        remaining_depth: usize,
    ) -> Vec<ExtractionResult> {
        let matches = self
            .db
            .scan_with_min_confidence(data, self.config.min_confidence);
        let analyzer = EntropyAnalyzer::default();
        let _ = &analyzer;
        let mut results: Vec<ExtractionResult> = Vec::new();

        for m in &matches {
            let offset = m.entry.magic_offset;
            let local_start = m.offset;
            // Absolute offset in the original image
            let abs_offset = base_offset + local_start;

            if local_start >= data.len() {
                continue;
            }
            let region_data = &data[local_start..];

            // Estimate size
            let size = self.estimate_size(region_data, offset, m.entry.name);
            if size < self.config.min_region_size {
                continue;
            }
            let size = size.min(data.len() - local_start);

            let chunk = &data[local_start..local_start + size];
            let entropy = EntropyAnalyzer::block_entropy(chunk);
            let high_entropy = entropy > 7.0;
            let region_type = RegionType::from(m.entry.category);

            // Recurse if possible
            let nested = if remaining_depth > 0 && size > self.config.min_region_size * 2 {
                self.extract_at(chunk, abs_offset, remaining_depth - 1)
                    .into_iter()
                    // Avoid re-reporting the parent match
                    .filter(|n| n.offset != abs_offset || n.format_name != m.entry.name)
                    .collect()
            } else {
                vec![]
            };

            results.push(ExtractionResult {
                offset: abs_offset,
                size,
                region_type,
                format_name: m.entry.name.to_string(),
                confidence: m.entry.confidence,
                entropy,
                high_entropy,
                nested,
            });
        }

        // Deduplicate: if multiple signatures fire at the same offset, keep
        // the one with the highest confidence.
        results.sort_by(|a, b| {
            a.offset
                .cmp(&b.offset)
                .then(b.confidence.cmp(&a.confidence))
        });
        results.dedup_by(|a, b| {
            // b is kept (comes first after sort); a is dropped if same offset+name
            a.offset == b.offset && a.format_name == b.format_name
        });

        results
    }

    /// Estimate the byte size of a region starting at `data[magic_offset..]`.
    fn estimate_size(&self, data: &[u8], _magic_off: usize, name: &str) -> usize {
        match name {
            "uboot-legacy" => size_from_uboot(data, 0).unwrap_or(data.len()),
            "squashfs-le" | "squashfs-be" | "squashfs-le3" | "squashfs-be3" => {
                size_from_squashfs(data, 0).unwrap_or(data.len())
            }
            "zip-local" => size_from_zip(data, 0).unwrap_or(data.len()),
            "gzip" => size_from_gzip(data, 0).unwrap_or(data.len()),
            "initramfs-cpio" | "initramfs-cpio-crc" => {
                size_from_cpio_newc(data, 0).unwrap_or(data.len())
            }
            "xz" | "bzip2" | "zstd" | "lz4-frame" | "lz4-legacy" | "lzo" | "lzma-alone" => {
                size_by_entropy_scan(
                    data,
                    0,
                    self.config.entropy_window,
                    self.config.entropy_step,
                )
            }
            _ => data.len(),
        }
    }

    /// Run entropy-based region detection on `data`, returning contiguous
    /// high-entropy blocks as [`ExtractionResult`]s with `format_name =
    /// "entropy-region"`.
    #[must_use]
    pub fn detect_entropy_regions(&self, data: &[u8]) -> Vec<ExtractionResult> {
        let analyzer = EntropyAnalyzer::new(
            self.config.entropy_window,
            self.config.entropy_step,
            self.config.min_region_size,
        );
        let windows = analyzer.sliding_entropy(data);
        let mut results = Vec::new();
        let mut region_start: Option<usize> = None;

        for &(off, entropy) in &windows {
            let class = EntropyAnalyzer::classify(entropy);
            let is_high = matches!(
                class,
                EntropyClass::High | EntropyClass::Encrypted | EntropyClass::Compressed
            );
            match (region_start, is_high) {
                (None, true) => {
                    region_start = Some(off);
                }
                (Some(start), false) => {
                    let size = off - start;
                    if size >= self.config.min_region_size {
                        let chunk = &data[start..start + size.min(data.len() - start)];
                        results.push(ExtractionResult {
                            offset: start,
                            size,
                            region_type: RegionType::Compressed,
                            format_name: "entropy-region".to_string(),
                            confidence: 50,
                            entropy: EntropyAnalyzer::block_entropy(chunk),
                            high_entropy: true,
                            nested: vec![],
                        });
                    }
                    region_start = None;
                }
                _ => {}
            }
        }
        // Close any open region at the end
        if let Some(start) = region_start {
            let size = data.len() - start;
            if size >= self.config.min_region_size {
                let chunk = &data[start..];
                results.push(ExtractionResult {
                    offset: start,
                    size,
                    region_type: RegionType::Compressed,
                    format_name: "entropy-region".to_string(),
                    confidence: 50,
                    entropy: EntropyAnalyzer::block_entropy(chunk),
                    high_entropy: true,
                    nested: vec![],
                });
            }
        }
        let _ = analyzer;
        results
    }

    /// Combined extraction: signature scan + entropy regions.
    /// Deduplicates overlapping results.
    #[must_use]
    pub fn full_extract(&self, data: &[u8]) -> Vec<ExtractionResult> {
        let mut all = self.extract(data);
        let entropy_regions = self.detect_entropy_regions(data);
        // Only add entropy regions not already covered by a signature match
        for er in entropy_regions {
            let already_covered = all
                .iter()
                .any(|r| er.offset >= r.offset && er.offset < r.offset + r.size);
            if !already_covered {
                all.push(er);
            }
        }
        all.sort_by_key(|r| r.offset);
        all
    }

    /// Summarize extraction results: returns (total_regions, compressed_count,
    /// filesystem_count, executable_count, highest_entropy).
    #[must_use]
    pub fn summarize(results: &[ExtractionResult]) -> ExtractionSummary {
        let total = results.len();
        let compressed = results
            .iter()
            .filter(|r| r.region_type == RegionType::Compressed)
            .count();
        let filesystems = results
            .iter()
            .filter(|r| r.region_type == RegionType::Filesystem)
            .count();
        let executables = results
            .iter()
            .filter(|r| r.region_type == RegionType::Executable)
            .count();
        let encrypted = results
            .iter()
            .filter(|r| r.region_type == RegionType::Encrypted)
            .count();
        let highest_entropy = results.iter().map(|r| r.entropy).fold(0.0f64, f64::max);
        ExtractionSummary {
            total,
            compressed,
            filesystems,
            executables,
            encrypted,
            highest_entropy,
        }
    }
}

/// Summary statistics for a set of extraction results.
#[derive(Debug, Clone)]
pub struct ExtractionSummary {
    pub total: usize,
    pub compressed: usize,
    pub filesystems: usize,
    pub executables: usize,
    pub encrypted: usize,
    pub highest_entropy: f64,
}

impl fmt::Display for ExtractionSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "total={} compressed={} filesystems={} executables={} encrypted={} max_entropy={:.2}",
            self.total,
            self.compressed,
            self.filesystems,
            self.executables,
            self.encrypted,
            self.highest_entropy,
        )
    }
}

impl Default for FirmwareExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FirmwareExtractor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FirmwareExtractor(min_conf={}, max_depth={})",
            self.config.min_confidence, self.config.max_depth
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn extractor() -> FirmwareExtractor {
        FirmwareExtractor::new()
    }

    // ── basic extraction ──────────────────────────────────────────────────────

    #[test]
    fn test_extract_empty_data() {
        let res = extractor().extract(&[]);
        assert!(res.is_empty());
    }

    #[test]
    fn test_extract_gzip_at_start() {
        let mut data = vec![0u8; 512];
        data[0] = 0x1F;
        data[1] = 0x8B;
        let res = extractor().extract(&data);
        assert!(res.iter().any(|r| r.format_name == "gzip" && r.offset == 0));
    }

    #[test]
    fn test_extract_gzip_at_offset() {
        let mut data = vec![0u8; 512];
        data[128] = 0x1F;
        data[129] = 0x8B;
        let res = extractor().extract(&data);
        assert!(
            res.iter()
                .any(|r| r.format_name == "gzip" && r.offset == 128)
        );
    }

    #[test]
    fn test_extract_elf() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        let res = extractor().extract(&data);
        assert!(res.iter().any(|r| r.format_name == "elf"));
    }

    #[test]
    fn test_extract_uboot_estimates_size() {
        let mut data = vec![0u8; 1024];
        // Write U-Boot magic + data_size = 512
        data[0..4].copy_from_slice(&0x2705_1956_u32.to_be_bytes());
        data[12..16].copy_from_slice(&512_u32.to_be_bytes());
        let res = extractor().extract(&data);
        let uboot_res = res.iter().find(|r| r.format_name == "uboot-legacy");
        assert!(uboot_res.is_some());
        assert_eq!(uboot_res.unwrap().size, 64 + 512);
    }

    #[test]
    fn test_extract_sorted_by_offset() {
        let mut data = vec![0u8; 256];
        data[200..204].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        data[50..52].copy_from_slice(&[0x1F, 0x8B]);
        let res = extractor().extract(&data);
        let offsets: Vec<usize> = res.iter().map(|r| r.offset).collect();
        assert!(offsets.windows(2).all(|w| w[0] <= w[1]));
    }

    // ── entropy region detection ──────────────────────────────────────────────

    #[test]
    fn test_entropy_regions_high_entropy_block() {
        // Build a buffer with a high-entropy blob in the middle
        let mut data = vec![0u8; 4096];
        // Fill bytes 1024..3072 with pseudo-random (all 256 byte values)
        for i in 1024..3072 {
            data[i] = (i.wrapping_mul(167).wrapping_add(13) & 0xFF) as u8;
        }
        let ext = FirmwareExtractor::with_config(ExtractorConfig {
            entropy_window: 256,
            entropy_step: 128,
            min_region_size: 128,
            ..Default::default()
        });
        let regions = ext.detect_entropy_regions(&data);
        assert!(
            !regions.is_empty(),
            "expected at least one high-entropy region"
        );
    }

    #[test]
    fn test_entropy_regions_empty() {
        let data = vec![0xAA_u8; 4096];
        let ext = FirmwareExtractor::with_config(ExtractorConfig {
            entropy_window: 256,
            entropy_step: 128,
            min_region_size: 32,
            ..Default::default()
        });
        let regions = ext.detect_entropy_regions(&data);
        // All same byte → entropy = 0, no high-entropy regions
        assert!(regions.is_empty());
    }

    // ── full_extract deduplication ────────────────────────────────────────────

    #[test]
    fn test_full_extract_no_duplicates_at_same_offset() {
        let mut data = vec![0x7F, b'E', b'L', b'F'];
        data.extend(std::iter::repeat_n(0u8, 60));
        let res = extractor().full_extract(&data);
        // All results at offset 0 must have unique format names
        let at_zero: Vec<_> = res.iter().filter(|r| r.offset == 0).collect();
        let names: std::collections::HashSet<_> = at_zero.iter().map(|r| &r.format_name).collect();
        assert_eq!(at_zero.len(), names.len());
    }

    // ── summarize ─────────────────────────────────────────────────────────────

    #[test]
    fn test_summarize_empty() {
        let s = FirmwareExtractor::summarize(&[]);
        assert_eq!(s.total, 0);
        assert_eq!(s.highest_entropy, 0.0);
    }

    #[test]
    fn test_summarize_counts() {
        let results = vec![
            ExtractionResult {
                offset: 0,
                size: 100,
                region_type: RegionType::Compressed,
                format_name: "gzip".to_string(),
                confidence: 80,
                entropy: 7.5,
                high_entropy: true,
                nested: vec![],
            },
            ExtractionResult {
                offset: 100,
                size: 200,
                region_type: RegionType::Filesystem,
                format_name: "squashfs-le".to_string(),
                confidence: 99,
                entropy: 5.0,
                high_entropy: false,
                nested: vec![],
            },
            ExtractionResult {
                offset: 300,
                size: 64,
                region_type: RegionType::Executable,
                format_name: "elf".to_string(),
                confidence: 99,
                entropy: 4.5,
                high_entropy: false,
                nested: vec![],
            },
        ];
        let s = FirmwareExtractor::summarize(&results);
        assert_eq!(s.total, 3);
        assert_eq!(s.compressed, 1);
        assert_eq!(s.filesystems, 1);
        assert_eq!(s.executables, 1);
        assert!((s.highest_entropy - 7.5).abs() < 0.01);
    }

    // ── Display ───────────────────────────────────────────────────────────────

    #[test]
    fn test_extraction_result_display() {
        let r = ExtractionResult {
            offset: 0x1000,
            size: 4096,
            region_type: RegionType::Compressed,
            format_name: "gzip".to_string(),
            confidence: 80,
            entropy: 7.8,
            high_entropy: true,
            nested: vec![],
        };
        let s = r.to_string();
        assert!(s.contains("gzip"));
        assert!(s.contains("compressed"));
        assert!(s.contains("high-entropy"));
    }

    #[test]
    fn test_extraction_summary_display() {
        let s = ExtractionSummary {
            total: 5,
            compressed: 2,
            filesystems: 1,
            executables: 1,
            encrypted: 0,
            highest_entropy: 7.9,
        };
        let text = s.to_string();
        assert!(text.contains("total=5"));
        assert!(text.contains("compressed=2"));
    }

    #[test]
    fn test_extractor_debug() {
        let s = format!("{:?}", extractor());
        assert!(s.contains("FirmwareExtractor"));
    }

    // ── RegionType conversions ────────────────────────────────────────────────

    #[test]
    fn test_region_type_from_category() {
        assert_eq!(
            RegionType::from(SignatureCategory::Compression),
            RegionType::Compressed
        );
        assert_eq!(
            RegionType::from(SignatureCategory::Filesystem),
            RegionType::Filesystem
        );
        assert_eq!(
            RegionType::from(SignatureCategory::Executable),
            RegionType::Executable
        );
        assert_eq!(
            RegionType::from(SignatureCategory::Certificate),
            RegionType::Certificate
        );
    }

    #[test]
    fn test_region_type_display() {
        assert_eq!(RegionType::Filesystem.to_string(), "filesystem");
        assert_eq!(RegionType::Encrypted.to_string(), "encrypted");
    }

    // ── config ────────────────────────────────────────────────────────────────

    #[test]
    fn test_extractor_with_high_confidence_skips_low() {
        let data = [0x1F, 0x8B, 0x00]; // gzip confidence = 80
        let ext = FirmwareExtractor::with_config(ExtractorConfig {
            min_confidence: 99, // should skip gzip (80)
            ..Default::default()
        });
        // gzip at confidence 80 should be skipped
        let res = ext.extract(&data);
        assert!(!res.iter().any(|r| r.format_name == "gzip"));
    }

    #[test]
    fn test_extractor_min_region_size_filter() {
        // Very short data — extractor should not emit regions below min_region_size
        let data = [0x1F, 0x8B]; // only 2 bytes
        let ext = FirmwareExtractor::with_config(ExtractorConfig {
            min_region_size: 100,
            ..Default::default()
        });
        let res = ext.extract(&data);
        assert!(res.is_empty());
    }

    #[test]
    fn test_extractor_default_same_as_new() {
        let a = FirmwareExtractor::new();
        let b = FirmwareExtractor::default();
        assert_eq!(a.config.min_confidence, b.config.min_confidence);
    }

    // ── size estimators ───────────────────────────────────────────────────────

    #[test]
    fn test_size_from_uboot_valid() {
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(&0x2705_1956_u32.to_be_bytes());
        data[12..16].copy_from_slice(&100_u32.to_be_bytes());
        assert_eq!(size_from_uboot(&data, 0), Some(164));
    }

    #[test]
    fn test_size_from_uboot_wrong_magic() {
        let data = vec![0u8; 64];
        assert_eq!(size_from_uboot(&data, 0), None);
    }

    #[test]
    fn test_size_from_zip_finds_eocd() {
        // Build a minimal ZIP with EOCD
        let mut data = vec![0u8; 128];
        // EOCD at offset 100
        data[100..104].copy_from_slice(b"PK\x05\x06");
        // comment_length = 0
        data[120..122].copy_from_slice(&[0u8, 0u8]);
        let size = size_from_zip(&data, 0);
        assert!(size.is_some());
    }
}
