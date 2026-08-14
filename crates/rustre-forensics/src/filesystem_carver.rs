//! Filesystem carver — recover files from raw disk images using file signatures.
//!
//! Implements a multi-signature scanner that locates file headers and footers
//! in a byte stream, extracts candidate files, and produces [`CarvedFile`]
//! records with metadata.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ForensicsError;
use std::fmt::Write as _;

// ─── CarvingRule ──────────────────────────────────────────────────────────────

/// Describes how to locate and bound a single file type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvingRule {
    /// Human-readable name for this file type (e.g. `"JPEG"`, `"PDF"`).
    pub name: String,
    /// Header signature bytes.
    pub header: Vec<u8>,
    /// Optional footer signature bytes.  When present, carving ends at the
    /// first occurrence of the footer *after* the header.
    pub footer: Option<Vec<u8>>,
    /// Maximum size in bytes to carve when no footer is found (default 10 MiB).
    pub max_size: usize,
    /// File extension to assign to carved files (e.g. `"jpg"`).
    pub extension: String,
}

impl CarvingRule {
    /// Create a new rule with a header and optional footer.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        header: Vec<u8>,
        footer: Option<Vec<u8>>,
        max_size: usize,
        extension: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            header,
            footer,
            max_size,
            extension: extension.into(),
        }
    }

    /// Convenience constructor: JPEG (SOI … EOI).
    #[must_use]
    pub fn jpeg() -> Self {
        Self::new(
            "JPEG",
            vec![0xff, 0xd8, 0xff],
            Some(vec![0xff, 0xd9]),
            10 * 1024 * 1024,
            "jpg",
        )
    }

    /// Convenience constructor: PNG.
    #[must_use]
    pub fn png() -> Self {
        Self::new(
            "PNG",
            vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a],
            Some(b"IEND\xaeB`\x82".to_vec()),
            20 * 1024 * 1024,
            "png",
        )
    }

    /// Convenience constructor: PDF.
    #[must_use]
    pub fn pdf() -> Self {
        Self::new(
            "PDF",
            b"%PDF".to_vec(),
            Some(b"%%EOF".to_vec()),
            50 * 1024 * 1024,
            "pdf",
        )
    }

    /// Convenience constructor: ZIP / Office Open XML.
    #[must_use]
    pub fn zip() -> Self {
        Self::new(
            "ZIP",
            vec![0x50, 0x4b, 0x03, 0x04],
            Some(vec![0x50, 0x4b, 0x05, 0x06]),
            100 * 1024 * 1024,
            "zip",
        )
    }

    /// Convenience constructor: Windows PE executable.
    #[must_use]
    pub fn pe() -> Self {
        Self::new(
            "PE",
            b"MZ".to_vec(),
            None,
            64 * 1024 * 1024,
            "exe",
        )
    }

    /// Convenience constructor: ELF binary.
    #[must_use]
    pub fn elf() -> Self {
        Self::new(
            "ELF",
            vec![0x7f, b'E', b'L', b'F'],
            None,
            64 * 1024 * 1024,
            "elf",
        )
    }

    /// Convenience constructor: GIF.
    #[must_use]
    pub fn gif() -> Self {
        Self::new(
            "GIF",
            b"GIF8".to_vec(),
            Some(vec![0x00, 0x3b]),
            5 * 1024 * 1024,
            "gif",
        )
    }

    /// Convenience constructor: `SQLite` database.
    #[must_use]
    pub fn sqlite() -> Self {
        Self::new(
            "SQLite",
            b"SQLite format 3\x00".to_vec(),
            None,
            500 * 1024 * 1024,
            "db",
        )
    }
}

// ─── CarvedFile ───────────────────────────────────────────────────────────────

/// A single file recovered from a raw image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvedFile {
    /// Offset (in bytes) within the source image where this file starts.
    pub offset: usize,
    /// Offset where this file ends (exclusive).
    pub end_offset: usize,
    /// The file type rule that matched.
    pub rule_name: String,
    /// File extension.
    pub extension: String,
    /// Whether a footer was used to determine the end (as opposed to `max_size`).
    pub has_footer: bool,
    /// SHA-256 hex digest of the carved bytes.
    pub sha256: String,
    /// The raw bytes of the carved file.
    pub data: Vec<u8>,
    /// Additional metadata gathered during carving.
    pub metadata: HashMap<String, String>,
}

impl CarvedFile {
    /// Size in bytes of the carved file.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.data.len()
    }

    /// Suggested filename for saving.
    #[must_use]
    pub fn suggested_filename(&self) -> String {
        format!("carved_{:08x}.{}", self.offset, self.extension)
    }

    /// Save the carved file to `dir`, returning the written path.
    ///
    /// # Errors
    /// Returns [`ForensicsError::Io`] on write failure.
    pub fn save(&self, dir: &Path) -> Result<PathBuf, ForensicsError> {
        let path = dir.join(self.suggested_filename());
        std::fs::write(&path, &self.data).map_err(ForensicsError::from)?;
        Ok(path)
    }
}

// ─── CarvingStats ─────────────────────────────────────────────────────────────

/// Statistics produced by a carving run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CarvingStats {
    /// Number of bytes scanned.
    pub bytes_scanned: usize,
    /// Total carved files.
    pub files_carved: usize,
    /// Files per type name.
    pub files_by_type: HashMap<String, usize>,
    /// Total carved bytes across all files.
    pub total_carved_bytes: usize,
    /// Number of files with confirmed footers.
    pub footer_confirmed: usize,
    /// Number of files truncated at `max_size`.
    pub max_size_truncated: usize,
}

impl CarvingStats {
    /// Record a carved file.
    pub fn record(&mut self, file: &CarvedFile) {
        self.files_carved += 1;
        *self.files_by_type.entry(file.rule_name.clone()).or_insert(0) += 1;
        self.total_carved_bytes += file.size();
        if file.has_footer {
            self.footer_confirmed += 1;
        } else {
            self.max_size_truncated += 1;
        }
    }
}

// ─── FilesystemCarver ─────────────────────────────────────────────────────────

/// Scans a byte buffer for known file signatures and extracts embedded files.
///
/// # Example
///
/// ```no_run
/// use rustre_forensics::filesystem_carver::FilesystemCarver;
///
/// let image = std::fs::read("disk.img").unwrap();
/// let mut carver = FilesystemCarver::with_default_rules();
/// let (files, stats) = carver.carve(&image);
/// println!("Carved {} files", stats.files_carved);
/// ```
#[derive(Debug, Default, Clone)]
pub struct FilesystemCarver {
    /// Active carving rules.
    pub rules: Vec<CarvingRule>,
    /// Skip overlapping matches within this many bytes of a previous match.
    pub overlap_skip: usize,
    /// Maximum number of files to carve (0 = unlimited).
    pub max_files: usize,
}

impl FilesystemCarver {
    /// Create a carver with no rules.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rules: Vec::new(),
            overlap_skip: 0,
            max_files: 0,
        }
    }

    /// Create a carver pre-loaded with common rules.
    #[must_use]
    pub fn with_default_rules() -> Self {
        let mut c = Self::new();
        c.add_rule(CarvingRule::jpeg());
        c.add_rule(CarvingRule::png());
        c.add_rule(CarvingRule::pdf());
        c.add_rule(CarvingRule::zip());
        c.add_rule(CarvingRule::pe());
        c.add_rule(CarvingRule::elf());
        c.add_rule(CarvingRule::gif());
        c.add_rule(CarvingRule::sqlite());
        c
    }

    /// Add a carving rule.
    pub fn add_rule(&mut self, rule: CarvingRule) {
        self.rules.push(rule);
    }

    /// Remove all rules.
    pub fn clear_rules(&mut self) {
        self.rules.clear();
    }

    /// Carve `data`, returning all found files and run statistics.
    #[must_use]
    pub fn carve(&self, data: &[u8]) -> (Vec<CarvedFile>, CarvingStats) {
        let mut files: Vec<CarvedFile> = Vec::new();
        let mut stats = CarvingStats {
            bytes_scanned: data.len(),
            ..Default::default()
        };

        for rule in &self.rules {
            if rule.header.is_empty() {
                continue;
            }
            let mut offset = 0usize;
            while offset + rule.header.len() <= data.len() {
                if self.max_files > 0 && files.len() >= self.max_files {
                    break;
                }
                if !data[offset..].starts_with(&rule.header) {
                    offset += 1;
                    continue;
                }
                // Found a header.
                let start = offset;
                let (end, has_footer) = Self::find_end(data, start, rule);
                let slice = &data[start..end];
                let sha256 = crate::compute_sha256(slice);
                let mut metadata = HashMap::new();
                metadata.insert("rule".to_string(), rule.name.clone());
                metadata.insert("offset_hex".to_string(), format!("0x{start:08x}"));
                metadata.insert("size".to_string(), slice.len().to_string());

                // Extra metadata for known types.
                extract_type_metadata(rule, slice, &mut metadata);

                let carved = CarvedFile {
                    offset: start,
                    end_offset: end,
                    rule_name: rule.name.clone(),
                    extension: rule.extension.clone(),
                    has_footer,
                    sha256,
                    data: slice.to_vec(),
                    metadata,
                };
                stats.record(&carved);
                files.push(carved);

                // Advance past what we carved (or by 1 if overlap allowed).
                offset = if self.overlap_skip > 0 {
                    start + self.overlap_skip
                } else {
                    end.max(start + 1)
                };
            }
        }

        // Sort by offset.
        files.sort_by_key(|f| f.offset);
        (files, stats)
    }

    /// Find the end of a carved region starting at `start`.
    fn find_end(data: &[u8], start: usize, rule: &CarvingRule) -> (usize, bool) {
        let search_end = (start + rule.max_size).min(data.len());
        if let Some(footer) = &rule.footer
            && !footer.is_empty() {
                // Search for footer after the header.
                let search_from = start + rule.header.len();
                for i in search_from..search_end.saturating_sub(footer.len() - 1) {
                    if data[i..].starts_with(footer) {
                        return (i + footer.len(), true);
                    }
                }
            }
        (search_end, false)
    }
}

/// Extract type-specific metadata fields.
fn extract_type_metadata(rule: &CarvingRule, data: &[u8], meta: &mut HashMap<String, String>) {
    match rule.name.as_str() {
        "JPEG" => {
            // Extract JPEG APP0/APP1 marker info.
            if data.len() >= 4 {
                meta.insert("marker_soi".to_string(), format!("{:02x}{:02x}", data[0], data[1]));
            }
        }
        "PNG" => {
            // PNG IHDR is at offset 8: 4-byte length + "IHDR" + 8 bytes width/height.
            if data.len() >= 24 {
                let width = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
                let height = u32::from_be_bytes([data[20], data[21], data[22], data[23]]);
                meta.insert("width".to_string(), width.to_string());
                meta.insert("height".to_string(), height.to_string());
            }
        }
        "PE" => {
            // Read e_lfanew at offset 0x3C.
            if data.len() >= 0x40 {
                let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]);
                meta.insert("e_lfanew".to_string(), format!("0x{e_lfanew:x}"));
            }
        }
        "ELF" => {
            if data.len() >= 5 {
                let class = match data[4] {
                    1 => "ELF32",
                    2 => "ELF64",
                    _ => "unknown",
                };
                meta.insert("elf_class".to_string(), class.to_string());
            }
        }
        "PDF"
            // Extract version from header.
            if data.len() >= 8 => {
                let ver: String = data[5..8.min(data.len())]
                    .iter()
                    .map(|&b| b as char)
                    .collect();
                meta.insert("pdf_version".to_string(), ver);
            }
        _ => {}
    }
}

// ─── carve_raw_image ──────────────────────────────────────────────────────────

/// Carve files from a raw disk image file.
///
/// Reads the entire image into memory and runs [`FilesystemCarver`] with
/// default rules.
///
/// # Errors
/// Returns [`ForensicsError::Io`] if the file cannot be read.
pub fn carve_raw_image(image_path: &Path) -> Result<(Vec<CarvedFile>, CarvingStats), ForensicsError> {
    let data = std::fs::read(image_path).map_err(ForensicsError::from)?;
    let carver = FilesystemCarver::with_default_rules();
    Ok(carver.carve(&data))
}

/// Carve files from a raw disk image file using custom rules.
///
/// # Errors
/// Returns [`ForensicsError::Io`] if the file cannot be read.
pub fn carve_raw_image_with_rules(
    image_path: &Path,
    rules: Vec<CarvingRule>,
) -> Result<(Vec<CarvedFile>, CarvingStats), ForensicsError> {
    let data = std::fs::read(image_path).map_err(ForensicsError::from)?;
    let mut carver = FilesystemCarver::new();
    for rule in rules {
        carver.add_rule(rule);
    }
    Ok(carver.carve(&data))
}

// ─── SectorCarver ─────────────────────────────────────────────────────────────

/// A sector-aware carver that operates on 512-byte (or configurable) sectors.
///
/// Useful for forensic recovery from FAT/NTFS images where files are sector-
/// aligned.
#[derive(Debug, Clone)]
pub struct SectorCarver {
    /// Underlying carver.
    pub carver: FilesystemCarver,
    /// Sector size in bytes (typically 512).
    pub sector_size: usize,
}

impl SectorCarver {
    /// Create a sector carver with default rules and 512-byte sectors.
    #[must_use]
    pub fn new() -> Self {
        Self {
            carver: FilesystemCarver::with_default_rules(),
            sector_size: 512,
        }
    }

    /// Carve, but only consider data starting at sector boundaries.
    #[must_use]
    pub fn carve_sectors(&self, data: &[u8]) -> (Vec<CarvedFile>, CarvingStats) {
        if self.sector_size == 0 || data.is_empty() {
            return (Vec::new(), CarvingStats::default());
        }
        let mut all_files = Vec::new();
        let mut stats = CarvingStats {
            bytes_scanned: data.len(),
            ..Default::default()
        };

        let num_sectors = data.len() / self.sector_size;
        for sector_idx in 0..num_sectors {
            let sector_start = sector_idx * self.sector_size;
            let sector_end = (sector_start + self.sector_size * 64).min(data.len());
            let slice = &data[sector_start..sector_end];

            for rule in &self.carver.rules {
                if rule.header.is_empty() || !slice.starts_with(&rule.header) {
                    continue;
                }
                let (local_end, has_footer) = FilesystemCarver::find_end(slice, 0, rule);
                let carved_data = slice[..local_end].to_vec();
                let sha256 = crate::compute_sha256(&carved_data);
                let mut metadata = HashMap::new();
                metadata.insert("sector".to_string(), sector_idx.to_string());
                metadata.insert("sector_offset".to_string(), format!("0x{sector_start:08x}"));

                let carved = CarvedFile {
                    offset: sector_start,
                    end_offset: sector_start + local_end,
                    rule_name: rule.name.clone(),
                    extension: rule.extension.clone(),
                    has_footer,
                    sha256,
                    data: carved_data,
                    metadata,
                };
                stats.record(&carved);
                all_files.push(carved);
            }
        }
        all_files.sort_by_key(|f| f.offset);
        (all_files, stats)
    }
}

impl Default for SectorCarver {
    fn default() -> Self {
        Self::new()
    }
}

// ─── DuplicateFilter ──────────────────────────────────────────────────────────

/// Removes duplicate carved files based on SHA-256 hash.
#[derive(Debug, Default)]
pub struct DuplicateFilter;

impl DuplicateFilter {
    /// Remove duplicates from `files`, keeping the first occurrence of each hash.
    #[must_use]
    pub fn deduplicate(&self, files: Vec<CarvedFile>) -> Vec<CarvedFile> {
        let mut seen = std::collections::HashSet::new();
        files
            .into_iter()
            .filter(|f| seen.insert(f.sha256.clone()))
            .collect()
    }

    /// Count duplicates in a slice.
    #[must_use]
    pub fn count_duplicates(&self, files: &[CarvedFile]) -> usize {
        let unique: std::collections::HashSet<&str> =
            files.iter().map(|f| f.sha256.as_str()).collect();
        files.len().saturating_sub(unique.len())
    }
}

// ─── MagicScanner ─────────────────────────────────────────────────────────────

/// A fast scanner that checks the first 16 bytes of every 512-byte sector for
/// any registered magic number, without full carving.
#[derive(Debug, Clone)]
pub struct MagicScanner {
    /// (`magic_bytes`, `type_name`) pairs.
    magic_db: Vec<(Vec<u8>, String)>,
}

impl MagicScanner {
    /// Create an empty scanner.
    #[must_use]
    pub const fn new() -> Self {
        Self { magic_db: Vec::new() }
    }

    /// Add a magic signature.
    pub fn add(&mut self, magic: Vec<u8>, name: impl Into<String>) {
        self.magic_db.push((magic, name.into()));
    }

    /// Create a scanner pre-loaded with common signatures.
    #[must_use]
    pub fn default_scanner() -> Self {
        let mut s = Self::new();
        s.add(vec![0xff, 0xd8, 0xff], "JPEG");
        s.add(vec![0x89, b'P', b'N', b'G'], "PNG");
        s.add(b"%PDF".to_vec(), "PDF");
        s.add(vec![0x50, 0x4b, 0x03, 0x04], "ZIP");
        s.add(b"MZ".to_vec(), "PE");
        s.add(vec![0x7f, b'E', b'L', b'F'], "ELF");
        s.add(b"GIF8".to_vec(), "GIF");
        s.add(b"SQLite format 3".to_vec(), "SQLite");
        s.add(b"RIFF".to_vec(), "RIFF/WAV/AVI");
        s.add(b"fLaC".to_vec(), "FLAC");
        s.add(vec![0x1f, 0x8b], "GZIP");
        s.add(b"BZh".to_vec(), "BZIP2");
        s
    }

    /// Scan `data` in 512-byte sectors and return `(offset, type_name)` hits.
    #[must_use]
    pub fn scan_sectors(&self, data: &[u8], sector_size: usize) -> Vec<(usize, String)> {
        if sector_size == 0 || data.is_empty() {
            return Vec::new();
        }
        let mut hits = Vec::new();
        let num_sectors = data.len().div_ceil(sector_size);
        for idx in 0..num_sectors {
            let start = idx * sector_size;
            let end = start.saturating_add(16).min(data.len());
            let sector_head = &data[start..end];
            for (magic, name) in &self.magic_db {
                if sector_head.starts_with(magic) {
                    hits.push((start, name.clone()));
                    break;
                }
            }
        }
        hits
    }

    /// Scan raw bytes (no sector alignment) for magic signatures.
    #[must_use]
    pub fn scan_raw(&self, data: &[u8]) -> Vec<(usize, String)> {
        let mut hits = Vec::new();
        for offset in 0..data.len() {
            for (magic, name) in &self.magic_db {
                if magic.len() <= data.len() - offset
                    && data[offset..offset + magic.len()] == magic[..]
                {
                    hits.push((offset, name.clone()));
                }
            }
        }
        hits
    }
}

impl Default for MagicScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ─── CarvingReport ────────────────────────────────────────────────────────────

/// A human-readable carving report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvingReport {
    /// Source image path (if any).
    pub source: String,
    /// Statistics from the carving run.
    pub stats: CarvingStats,
    /// Summary of each carved file (without data bytes).
    pub entries: Vec<CarvingReportEntry>,
}

/// One entry in a carving report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarvingReportEntry {
    pub offset: usize,
    pub size: usize,
    pub rule_name: String,
    pub extension: String,
    pub sha256: String,
    pub has_footer: bool,
}

impl CarvingReport {
    /// Build a report from a slice of carved files.
    #[must_use]
    pub fn build(source: impl Into<String>, files: &[CarvedFile], stats: CarvingStats) -> Self {
        let entries = files
            .iter()
            .map(|f| CarvingReportEntry {
                offset: f.offset,
                size: f.size(),
                rule_name: f.rule_name.clone(),
                extension: f.extension.clone(),
                sha256: f.sha256.clone(),
                has_footer: f.has_footer,
            })
            .collect();
        Self {
            source: source.into(),
            stats,
            entries,
        }
    }

    /// Render the report as a plain-text table.
    #[must_use]
    pub fn to_text_table(&self) -> String {
        let mut out = format!(
            "Carving Report: {}\n\
             Scanned: {} bytes, Carved: {} files ({} bytes total)\n\
             Footer-confirmed: {}   Max-size truncated: {}\n\n\
             {:<12} {:<10} {:<10} {:<8} {:<12}\n\
             {}\n",
            self.source,
            self.stats.bytes_scanned,
            self.stats.files_carved,
            self.stats.total_carved_bytes,
            self.stats.footer_confirmed,
            self.stats.max_size_truncated,
            "Offset",
            "Size",
            "Type",
            "Ext",
            "SHA-256",
            "-".repeat(60)
        );
        for e in &self.entries {
            let _ = writeln!(out, "0x{:<10x} {:<10} {:<10} {:<8} {}",
                e.offset,
                e.size,
                e.rule_name,
                e.extension,
                &e.sha256[..e.sha256.len().min(16)]);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_rules_count() {
        let carver = FilesystemCarver::with_default_rules();
        assert!(carver.rules.len() >= 6);
    }

    #[test]
    fn carve_embedded_png() {
        let mut data = vec![0u8; 512];
        // Embed a tiny PNG header.
        let png_header = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        data[100..108].copy_from_slice(&png_header);
        let carver = FilesystemCarver::with_default_rules();
        let (files, stats) = carver.carve(&data);
        let png_files: Vec<_> = files.iter().filter(|f| f.rule_name == "PNG").collect();
        assert!(!png_files.is_empty());
        assert_eq!(png_files[0].offset, 100);
        assert!(stats.files_carved >= 1);
    }

    #[test]
    fn carve_jpeg_with_footer() {
        let mut data = vec![0u8; 512];
        let header = [0xff, 0xd8, 0xff, 0xe0];
        let footer = [0xff, 0xd9];
        data[50..54].copy_from_slice(&header);
        data[200..202].copy_from_slice(&footer);
        let carver = FilesystemCarver::with_default_rules();
        let (files, _stats) = carver.carve(&data);
        let jpeg: Vec<_> = files.iter().filter(|f| f.rule_name == "JPEG").collect();
        assert!(!jpeg.is_empty());
        assert!(jpeg[0].has_footer);
        assert_eq!(jpeg[0].end_offset, 202);
    }

    #[test]
    fn duplicate_filter() {
        let mut data = vec![0u8; 256];
        let header = [0xff, 0xd8, 0xff];
        data[0..3].copy_from_slice(&header);
        data[100..103].copy_from_slice(&header);
        let carver = FilesystemCarver::with_default_rules();
        let (files, _) = carver.carve(&data);
        let filter = DuplicateFilter;
        let unique = filter.deduplicate(files.clone());
        assert!(unique.len() <= files.len());
    }

    #[test]
    fn magic_scanner_raw() {
        let mut data = vec![0u8; 256];
        data[50] = 0x7f;
        data[51] = b'E';
        data[52] = b'L';
        data[53] = b'F';
        let scanner = MagicScanner::default_scanner();
        let hits = scanner.scan_raw(&data);
        let elf_hits: Vec<_> = hits.iter().filter(|(_, n)| n == "ELF").collect();
        assert!(!elf_hits.is_empty());
        assert_eq!(elf_hits[0].0, 50);
    }

    #[test]
    fn carving_rule_jpeg_name() {
        let r = CarvingRule::jpeg();
        assert_eq!(r.name, "JPEG");
        assert_eq!(r.extension, "jpg");
    }

    #[test]
    fn carving_report_text_table() {
        let files: Vec<CarvedFile> = Vec::new();
        let stats = CarvingStats::default();
        let report = CarvingReport::build("test_image.dd", &files, stats);
        let text = report.to_text_table();
        assert!(text.contains("test_image.dd"));
    }

    #[test]
    fn sector_carver_finds_pe() {
        let mut data = vec![0u8; 1024];
        data[512] = b'M';
        data[513] = b'Z';
        let sc = SectorCarver::new();
        let (files, _) = sc.carve_sectors(&data);
        assert!(!files.is_empty());
        let pe_files: Vec<_> = files.iter().filter(|f| f.rule_name == "PE").collect();
        assert!(!pe_files.is_empty());
    }
}
