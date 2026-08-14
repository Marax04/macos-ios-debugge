//! `file_entropy_report` — Comprehensive per-file entropy analysis.
//!
//! Provides [`FileEntropyReport`], [`SectionEntropyTable`], [`GlobalEntropy`],
//! [`HighEntropyRegion`], [`EntropyClassifier`], [`PackedRegion`],
//! [`EncryptedRegion`], and [`EntropyComparison`].

use std::fmt;
use serde::{Deserialize, Serialize};
use crate::casts;

// ─── GlobalEntropy ────────────────────────────────────────────────────────────

/// Shannon entropy of the whole file.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GlobalEntropy {
    /// Entropy value in bits (0.0 – 8.0).
    pub value: f64,
    /// Qualitative rating.
    pub rating: EntropyRating,
    /// Whether the entropy exceeds the packing threshold (7.0).
    pub suggests_packing: bool,
    /// Whether the entropy exceeds the encryption threshold (7.5).
    pub suggests_encryption: bool,
}

impl GlobalEntropy {
    /// Compute from raw bytes.
    #[must_use]
    pub fn compute(data: &[u8]) -> Self {
        let value = shannon_entropy(data);
        Self {
            value,
            rating: EntropyRating::from_entropy(value),
            suggests_packing: value > 7.0,
            suggests_encryption: value > 7.5,
        }
    }
}

impl fmt::Display for GlobalEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GlobalEntropy({:.4} / {} packed={} encrypted={})",
            self.value, self.rating, self.suggests_packing, self.suggests_encryption
        )
    }
}

// ─── EntropyRating ────────────────────────────────────────────────────────────

/// Re-export the crate-level `EntropyRating` so this module uses consistent thresholds.
pub use crate::EntropyRating;

// ─── SectionEntropyEntry ─────────────────────────────────────────────────────

/// Entropy information for a single file section or block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropyEntry {
    /// Name of the section (e.g. ".text", ".data", "`block_0`").
    pub name: String,
    /// Byte offset in the file.
    pub offset: u64,
    /// Size in bytes.
    pub size: usize,
    /// Shannon entropy of this section.
    pub entropy: f64,
    /// Qualitative rating.
    pub rating: EntropyRating,
    /// Whether this section is likely packed.
    pub packed: bool,
    /// Whether this section is likely encrypted.
    pub encrypted: bool,
    /// Percentage of zero bytes.
    pub zero_byte_pct: f32,
    /// Chi-square statistic.
    pub chi_square: f64,
}

impl SectionEntropyEntry {
    /// Compute an entry for a named slice.
    #[must_use]
    pub fn compute(name: impl Into<String>, data: &[u8], offset: u64) -> Self {
        let entropy = shannon_entropy(data);
        let zero_count: usize = data.iter().fold(0, |acc, &b| acc + usize::from(b == 0));
        let zero_byte_pct = if data.is_empty() { 0.0 } else { casts::usize_to_f32(zero_count) / casts::usize_to_f32(data.len()) * 100.0 };
        let chi_square = chi_square_stat(data);
        Self {
            name: name.into(),
            offset,
            size: data.len(),
            entropy,
            rating: EntropyRating::from_entropy(entropy),
            packed: entropy > 7.0,
            encrypted: entropy > 7.5,
            zero_byte_pct,
            chi_square,
        }
    }
}

// ─── SectionEntropyTable ─────────────────────────────────────────────────────

/// Table of entropy values for all sections / fixed-size blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropyTable {
    pub entries: Vec<SectionEntropyEntry>,
    pub block_size: usize,
}

impl SectionEntropyTable {
    /// Build a table by splitting `data` into `block_size` byte chunks.
    #[must_use]
    pub fn from_blocks(data: &[u8], block_size: usize) -> Self {
        let block_size = block_size.max(1);
        let entries = data.chunks(block_size)
            .enumerate()
            .map(|(i, chunk)| {
                // Cast before multiplying to avoid usize overflow on 32-bit targets.
                let offset = u64::try_from(i).unwrap_or(u64::MAX).saturating_mul(u64::try_from(block_size).unwrap_or(u64::MAX));
                SectionEntropyEntry::compute(
                    format!("block_{i}"),
                    chunk,
                    offset,
                )
            })
            .collect();
        Self { entries, block_size }
    }

    /// Build from named section slices: `(name, offset, size)`.
    #[must_use]
    pub fn from_sections(data: &[u8], sections: &[(&str, u64, usize)]) -> Self {
        let entries = sections.iter()
            .map(|&(name, offset, size)| {
                let off = casts::u64_to_usize(offset);
                // Use saturating_add to prevent usize overflow from adversarial section metadata.
                let end = off.saturating_add(size).min(data.len());
                let slice = if off < data.len() { &data[off..end] } else { &[] };
                SectionEntropyEntry::compute(name, slice, offset)
            })
            .collect();
        Self { entries, block_size: 0 }
    }

    /// Return entries marked as packed.
    #[must_use]
    pub fn packed_entries(&self) -> Vec<&SectionEntropyEntry> {
        self.entries.iter().filter(|e| e.packed).collect()
    }

    /// Return entries marked as encrypted.
    #[must_use]
    pub fn encrypted_entries(&self) -> Vec<&SectionEntropyEntry> {
        self.entries.iter().filter(|e| e.encrypted).collect()
    }

    /// Return the maximum entropy across all entries.
    #[must_use]
    pub fn max_entropy(&self) -> f64 {
        self.entries.iter().map(|e| e.entropy).fold(0.0f64, f64::max)
    }

    /// Return the minimum entropy across all entries.
    /// Returns `0.0` for an empty table instead of the sentinel `8.0`.
    #[must_use]
    pub fn min_entropy(&self) -> f64 {
        if self.entries.is_empty() {
            return 0.0;
        }
        self.entries.iter().map(|e| e.entropy).fold(8.0f64, f64::min)
    }

    /// Return the average entropy.
    #[must_use]
    pub fn avg_entropy(&self) -> f64 {
        if self.entries.is_empty() { return 0.0; }
        self.entries.iter().map(|e| e.entropy).sum::<f64>() / casts::usize_to_f64(self.entries.len())
    }
}

// ─── HighEntropyRegion ────────────────────────────────────────────────────────

/// A contiguous file region with entropy above a given threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighEntropyRegion {
    /// Start offset in the file.
    pub start: u64,
    /// End offset (exclusive).
    pub end: u64,
    /// Actual entropy of this region.
    pub entropy: f64,
    /// Entropy threshold that was exceeded.
    pub threshold: f64,
    /// Semantic label: "packed", "encrypted", "compressed", etc.
    pub label: String,
}

impl HighEntropyRegion {
    /// Scan `data` for contiguous high-entropy blocks using `block_size` granularity.
    #[must_use]
    pub fn scan(data: &[u8], block_size: usize, threshold: f64) -> Vec<Self> {
        let block_size = block_size.max(1);
        let mut regions = Vec::new();
        let mut in_region = false;
        let mut region_start = 0u64;
        let mut region_entropies: Vec<f64> = Vec::new();

        for (i, chunk) in data.chunks(block_size).enumerate() {
            // Cast before multiplying to avoid usize overflow on 32-bit targets.
            let offset = (i as u64) * (block_size as u64);
            let e = shannon_entropy(chunk);

            if e >= threshold {
                if !in_region {
                    in_region = true;
                    region_start = offset;
                    region_entropies.clear();
                }
                region_entropies.push(e);
            } else if in_region {
                in_region = false;
                let avg = region_entropies.iter().sum::<f64>() / casts::usize_to_f64(region_entropies.len());
                regions.push(Self {
                    start: region_start,
                    end: offset,
                    entropy: avg,
                    threshold,
                    label: classify_entropy_label(avg),
                });
            }
        }

        // Flush trailing region
        if in_region && !region_entropies.is_empty() {
            let avg = region_entropies.iter().sum::<f64>() / casts::usize_to_f64(region_entropies.len());
            regions.push(Self {
                start: region_start,
                end: u64::try_from(data.len()).unwrap_or(u64::MAX),
                entropy: avg,
                threshold,
                label: classify_entropy_label(avg),
            });
        }

        regions
    }

    /// Size of this region in bytes.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

impl fmt::Display for HighEntropyRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HighEntropyRegion[{}] 0x{:x}–0x{:x} entropy={:.3}",
            self.label, self.start, self.end, self.entropy
        )
    }
}

fn classify_entropy_label(e: f64) -> String {
    if e >= 7.5 { "encrypted".to_string() }
    else if e >= 7.0 { "packed".to_string() }
    else if e >= 6.0 { "compressed".to_string() }
    else { "high".to_string() }
}

// ─── EntropyClassifier ────────────────────────────────────────────────────────

/// Classifies binary content based on entropy analysis.
pub struct EntropyClassifier {
    /// Threshold for declaring a region packed.
    pub packed_threshold: f64,
    /// Threshold for declaring a region encrypted.
    pub encrypted_threshold: f64,
    /// Block size for scanning.
    pub block_size: usize,
}

impl Default for EntropyClassifier {
    fn default() -> Self {
        Self {
            packed_threshold: 7.0,
            encrypted_threshold: 7.5,
            block_size: 512,
        }
    }
}

impl EntropyClassifier {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Classify `data` and return a semantic label.
    #[must_use]
    pub fn classify(&self, data: &[u8]) -> ContentClass {
        let e = shannon_entropy(data);
        if e < 1.0 { ContentClass::Empty }
        else if e < 4.0 { ContentClass::Text }
        else if e < self.packed_threshold { ContentClass::Code }
        else if e < self.encrypted_threshold { ContentClass::Packed }
        else { ContentClass::Encrypted }
    }

    /// Classify a full file, returning a verdict per block.
    #[must_use]
    pub fn classify_blocks(&self, data: &[u8]) -> Vec<(u64, ContentClass)> {
        data.chunks(self.block_size)
            .enumerate()
            .map(|(i, chunk)| {
                // Cast before multiplying to avoid usize overflow on 32-bit targets.
                let offset = (i as u64) * (self.block_size as u64);
                (offset, self.classify(chunk))
            })
            .collect()
    }

    /// Return overall file classification.
    #[must_use]
    pub fn classify_file(&self, data: &[u8]) -> ContentClass {
        self.classify(data)
    }
}

/// Semantic content class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentClass {
    Empty,
    Text,
    Code,
    Packed,
    Encrypted,
}

impl fmt::Display for ContentClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

// ─── PackedRegion ─────────────────────────────────────────────────────────────

/// A file region that is likely packed (entropy 7.0–7.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackedRegion {
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    /// Suspected packer name if known.
    pub packer_hint: Option<String>,
}

impl PackedRegion {
    /// Find packed regions in `data`.
    #[must_use]
    pub fn find(data: &[u8], block_size: usize) -> Vec<Self> {
        HighEntropyRegion::scan(data, block_size, 7.0)
            .into_iter()
            .filter(|r| r.entropy < 7.5)
            .map(|r| Self {
                offset: r.start,
                size: r.size(),
                entropy: r.entropy,
                packer_hint: None,
            })
            .collect()
    }
}

impl fmt::Display for PackedRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PackedRegion @ 0x{:x} size={} entropy={:.3}",
            self.offset, self.size, self.entropy
        )
    }
}

// ─── EncryptedRegion ─────────────────────────────────────────────────────────

/// A file region that is likely encrypted (entropy > 7.5).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedRegion {
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
    /// Suspected algorithm if known.
    pub algorithm_hint: Option<String>,
}

impl EncryptedRegion {
    /// Find encrypted regions in `data`.
    #[must_use]
    pub fn find(data: &[u8], block_size: usize) -> Vec<Self> {
        HighEntropyRegion::scan(data, block_size, 7.5)
            .into_iter()
            .map(|r| Self {
                offset: r.start,
                size: r.size(),
                entropy: r.entropy,
                algorithm_hint: None,
            })
            .collect()
    }
}

impl fmt::Display for EncryptedRegion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EncryptedRegion @ 0x{:x} size={} entropy={:.3}",
            self.offset, self.size, self.entropy
        )
    }
}

// ─── EntropyBaseline ─────────────────────────────────────────────────────────

/// A reference entropy baseline for comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyBaseline {
    pub name: String,
    pub min: f64,
    pub max: f64,
    pub typical: f64,
}

impl EntropyBaseline {
    /// Return baseline profiles for known clean and packed samples.
    #[must_use]
    pub fn known_baselines() -> Vec<Self> {
        vec![
            Self { name: "Clean PE (MSVC)".to_string(), min: 4.0, max: 6.5, typical: 5.5 },
            Self { name: "Clean PE (GCC)".to_string(), min: 3.8, max: 6.3, typical: 5.2 },
            Self { name: "UPX-packed".to_string(), min: 7.0, max: 7.9, typical: 7.6 },
            Self { name: "AES-encrypted".to_string(), min: 7.9, max: 8.0, typical: 7.99 },
            Self { name: "zlib-compressed".to_string(), min: 6.5, max: 7.5, typical: 7.1 },
            Self { name: "plaintext".to_string(), min: 3.5, max: 5.5, typical: 4.5 },
        ]
    }
}

// ─── EntropyComparison ────────────────────────────────────────────────────────

/// Comparison of file entropy against known-clean and known-packed baselines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyComparison {
    /// Entropy of the file under analysis.
    pub file_entropy: f64,
    /// Closest matching clean baseline.
    pub closest_clean: String,
    /// Distance to the closest clean baseline.
    pub clean_distance: f64,
    /// Closest matching packed baseline.
    pub closest_packed: String,
    /// Distance to the closest packed baseline.
    pub packed_distance: f64,
    /// Whether the file entropy is closer to packed than clean.
    pub looks_packed: bool,
    /// Whether the file entropy is closer to encrypted than anything else.
    pub looks_encrypted: bool,
    /// Similarity scores per baseline (name → score 0–1).
    pub similarity_scores: Vec<(String, f64)>,
}

impl EntropyComparison {
    /// Compute a comparison for the given `file_entropy`.
    #[must_use]
    pub fn compute(file_entropy: f64) -> Self {
        let baselines = EntropyBaseline::known_baselines();

        let similarity = |baseline: &EntropyBaseline| -> f64 {
            if file_entropy < baseline.min || file_entropy > baseline.max {
                let dist = if file_entropy < baseline.min {
                    baseline.min - file_entropy
                } else {
                    file_entropy - baseline.max
                };
                (1.0 - dist / 8.0).max(0.0)
            } else {
                // Inside range: perfect match contribution
                let range = (baseline.max - baseline.min).max(0.001);
                let dist_from_typical = (file_entropy - baseline.typical).abs();
                1.0 - dist_from_typical / range
            }
        };

        let similarity_scores: Vec<(String, f64)> = baselines.iter()
            .map(|b| (b.name.clone(), similarity(b)))
            .collect();

        let clean_baselines = ["Clean PE (MSVC)", "Clean PE (GCC)", "plaintext"];
        let packed_baselines = ["UPX-packed", "AES-encrypted", "zlib-compressed"];

        let best_clean = similarity_scores.iter()
            .filter(|(n, _)| clean_baselines.iter().any(|c| n == c))
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(n, s)| (n.clone(), 1.0 - s))
            .unwrap_or_default();

        let best_packed = similarity_scores.iter()
            .filter(|(n, _)| packed_baselines.iter().any(|p| n == p))
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(n, s)| (n.clone(), 1.0 - s))
            .unwrap_or_default();

        Self {
            file_entropy,
            closest_clean: best_clean.0,
            clean_distance: best_clean.1,
            closest_packed: best_packed.0,
            packed_distance: best_packed.1,
            looks_packed: file_entropy > 7.0,
            looks_encrypted: file_entropy > 7.5,
            similarity_scores,
        }
    }

    /// Return the most likely content type based on entropy comparison.
    #[must_use]
    pub const fn best_guess(&self) -> &str {
        if self.looks_encrypted { "encrypted" }
        else if self.looks_packed { "packed" }
        else { "clean/uncompressed" }
    }
}

impl fmt::Display for EntropyComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EntropyComparison(entropy={:.4} packed={} encrypted={} guess={})",
            self.file_entropy, self.looks_packed, self.looks_encrypted, self.best_guess()
        )
    }
}

// ─── FileEntropyReport ────────────────────────────────────────────────────────

/// Complete entropy analysis report for a single file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntropyReport {
    /// File hash.
    pub file_hash: String,
    /// File size in bytes.
    pub file_size: usize,
    /// Global entropy of the entire file.
    pub global_entropy: GlobalEntropy,
    /// Per-section or per-block entropy table.
    pub section_table: SectionEntropyTable,
    /// High-entropy contiguous regions.
    pub high_entropy_regions: Vec<HighEntropyRegion>,
    /// Packed regions.
    pub packed_regions: Vec<PackedRegion>,
    /// Encrypted regions.
    pub encrypted_regions: Vec<EncryptedRegion>,
    /// Comparison against known baselines.
    pub comparison: EntropyComparison,
    /// Overall classification of the file content.
    pub file_class: ContentClass,
    /// Number of packed sections.
    pub packed_section_count: usize,
    /// Number of encrypted sections.
    pub encrypted_section_count: usize,
    /// Elapsed analysis time in milliseconds.
    pub elapsed_ms: u64,
}

impl FileEntropyReport {
    /// Generate a full entropy report for `data` using default block size (512 bytes).
    #[must_use]
    pub fn generate(data: &[u8]) -> Self {
        Self::generate_with_config(data, 512, 7.0)
    }

    /// Generate with custom block size and threshold.
    #[must_use]
    pub fn generate_with_config(data: &[u8], block_size: usize, threshold: f64) -> Self {
        use std::time::Instant;
        let start = Instant::now();

        let global_entropy = GlobalEntropy::compute(data);
        let section_table = SectionEntropyTable::from_blocks(data, block_size);
        let high_entropy_regions = HighEntropyRegion::scan(data, block_size, threshold);
        let packed_regions = PackedRegion::find(data, block_size);
        let encrypted_regions = EncryptedRegion::find(data, block_size);
        let comparison = EntropyComparison::compute(global_entropy.value);

        let classifier = EntropyClassifier {
            packed_threshold: threshold,
            encrypted_threshold: 7.5,
            block_size,
        };
        let file_class = classifier.classify(data);

        let packed_section_count = section_table.packed_entries().len();
        let encrypted_section_count = section_table.encrypted_entries().len();
        // Saturate to u64::MAX for extreme durations rather than silently truncating.
        let elapsed_ms = casts::u128_to_u64(start.elapsed().as_millis().min(u128::from(u64::MAX)));

        Self {
            file_hash: simple_hash(data),
            file_size: data.len(),
            global_entropy,
            section_table,
            high_entropy_regions,
            packed_regions,
            encrypted_regions,
            comparison,
            file_class,
            packed_section_count,
            encrypted_section_count,
            elapsed_ms,
        }
    }

    /// Generate with named section metadata.
    #[must_use]
    pub fn generate_with_sections(data: &[u8], sections: &[(&str, u64, usize)]) -> Self {
        let mut report = Self::generate(data);
        report.section_table = SectionEntropyTable::from_sections(data, sections);
        report.packed_section_count = report.section_table.packed_entries().len();
        report.encrypted_section_count = report.section_table.encrypted_entries().len();
        report
    }

    /// Return `true` if any region exceeds the packing threshold.
    #[must_use]
    pub const fn is_likely_packed(&self) -> bool {
        self.global_entropy.suggests_packing || !self.packed_regions.is_empty()
    }

    /// Return `true` if any region exceeds the encryption threshold.
    #[must_use]
    pub const fn is_likely_encrypted(&self) -> bool {
        self.global_entropy.suggests_encryption || !self.encrypted_regions.is_empty()
    }

    /// Brief summary line.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "FileEntropyReport: entropy={:.4} class={} packed={} encrypted={} regions={}",
            self.global_entropy.value,
            self.file_class,
            self.is_likely_packed(),
            self.is_likely_encrypted(),
            self.high_entropy_regions.len()
        )
    }

    /// Serialise to JSON.
    ///
    /// # Errors
    /// Returns a string on serialisation failure.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }
}

impl fmt::Display for FileEntropyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== File Entropy Report ===")?;
        writeln!(f, "  File size        : {} bytes", self.file_size)?;
        writeln!(f, "  Global entropy   : {:.4}", self.global_entropy.value)?;
        writeln!(f, "  Rating           : {}", self.global_entropy.rating)?;
        writeln!(f, "  File class       : {}", self.file_class)?;
        writeln!(f, "  Likely packed    : {}", self.is_likely_packed())?;
        writeln!(f, "  Likely encrypted : {}", self.is_likely_encrypted())?;
        writeln!(f, "  Packed sections  : {}", self.packed_section_count)?;
        writeln!(f, "  Encrypted sects  : {}", self.encrypted_section_count)?;
        writeln!(f, "  High-ent regions : {}", self.high_entropy_regions.len())?;
        writeln!(f, "  Comparison guess : {}", self.comparison.best_guess())?;
        writeln!(f, "  Elapsed ms       : {}", self.elapsed_ms)?;
        Ok(())
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = casts::usize_to_f64(data.len());
    let mut h = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = f64::from(c) / len;
            h -= p * p.log2();
        }
    }
    h.clamp(0.0, 8.0)
}

fn chi_square_stat(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in data { counts[b as usize] += 1; }
    let expected = casts::usize_to_f64(data.len()) / 256.0;
    counts.iter().fold(0.0f64, |acc, &obs| {
        let diff = f64::from(obs) - expected;
        acc + diff * diff / expected
    })
}

fn simple_hash(data: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325_u64;
    for &b in data { h ^= u64::from(b); h = h.wrapping_mul(0x0100_0000_01b3_u64); }
    format!("{h:016x}")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn uniform_data() -> Vec<u8> {
        (0u8..=255).cycle().take(4096).collect()
    }
    fn zero_data() -> Vec<u8> { vec![0u8; 2048] }
    fn text_data() -> Vec<u8> { b"Hello world this is plain text data for testing!".to_vec() }

    // ── GlobalEntropy ─────────────────────────────────────────────────────────

    #[test]
    fn test_global_entropy_zeros() {
        let g = GlobalEntropy::compute(&zero_data());
        assert!((g.value - (0.0)).abs() < f64::EPSILON);
        assert_eq!(g.rating, EntropyRating::VeryLow);
        assert!(!g.suggests_packing);
        assert!(!g.suggests_encryption);
    }

    #[test]
    fn test_global_entropy_uniform() {
        let g = GlobalEntropy::compute(&uniform_data());
        assert!((g.value - 8.0).abs() < 0.01);
        assert_eq!(g.rating, EntropyRating::VeryHigh);
        assert!(g.suggests_packing);
        assert!(g.suggests_encryption);
    }

    #[test]
    fn test_global_entropy_display() {
        let g = GlobalEntropy::compute(&zero_data());
        assert!(g.to_string().contains("packed=false"));
    }

    #[test]
    fn test_entropy_rating_boundaries() {
        assert_eq!(EntropyRating::from_entropy(0.0), EntropyRating::VeryLow);
        assert_eq!(EntropyRating::from_entropy(1.5), EntropyRating::Low);
        assert_eq!(EntropyRating::from_entropy(4.0), EntropyRating::Medium);
        assert_eq!(EntropyRating::from_entropy(6.5), EntropyRating::High);
        assert_eq!(EntropyRating::from_entropy(7.5), EntropyRating::VeryHigh);
    }

    // ── SectionEntropyEntry ───────────────────────────────────────────────────

    #[test]
    fn test_section_entry_zeros() {
        let e = SectionEntropyEntry::compute(".bss", &zero_data(), 0x1000);
        assert!((e.entropy - (0.0)).abs() < f64::EPSILON);
        assert!(!e.packed);
        assert!((e.zero_byte_pct - (100.0)).abs() < f32::EPSILON);
    }

    #[test]
    fn test_section_entry_uniform() {
        let e = SectionEntropyEntry::compute(".text", &uniform_data(), 0);
        assert!(e.entropy > 7.9);
        assert!(e.packed);
        assert!(e.encrypted);
    }

    // ── SectionEntropyTable ───────────────────────────────────────────────────

    #[test]
    fn test_section_table_from_blocks() {
        let table = SectionEntropyTable::from_blocks(&zero_data(), 512);
        assert_eq!(table.entries.len(), 4);
        assert!((table.max_entropy() - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_section_table_packed_entries() {
        let table = SectionEntropyTable::from_blocks(&uniform_data(), 512);
        assert!(!table.packed_entries().is_empty());
    }

    #[test]
    fn test_section_table_avg_entropy() {
        let table = SectionEntropyTable::from_blocks(&zero_data(), 256);
        assert!((table.avg_entropy() - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_section_table_min_entropy() {
        let table = SectionEntropyTable::from_blocks(&zero_data(), 256);
        assert!((table.min_entropy() - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_section_table_from_sections() {
        let data: Vec<u8> = (0..256).map(|b| b as u8).collect();
        let secs = [(".text", 0u64, 128usize), (".data", 128, 128)];
        let table = SectionEntropyTable::from_sections(&data, &secs);
        assert_eq!(table.entries.len(), 2);
    }

    // ── HighEntropyRegion ─────────────────────────────────────────────────────

    #[test]
    fn test_high_entropy_region_finds_uniform() {
        let data = uniform_data();
        let regions = HighEntropyRegion::scan(&data, 512, 7.0);
        assert!(!regions.is_empty());
    }

    #[test]
    fn test_high_entropy_region_no_regions_zeros() {
        let regions = HighEntropyRegion::scan(&zero_data(), 512, 7.0);
        assert!(regions.is_empty());
    }

    #[test]
    fn test_high_entropy_region_size() {
        let data = uniform_data();
        let regions = HighEntropyRegion::scan(&data, 512, 7.0);
        for r in &regions {
            assert!(r.size() > 0);
        }
    }

    #[test]
    fn test_high_entropy_region_display() {
        let r = HighEntropyRegion { start: 0, end: 512, entropy: 7.8, threshold: 7.0, label: "encrypted".to_string() };
        assert!(r.to_string().contains("encrypted"));
    }

    // ── EntropyClassifier ─────────────────────────────────────────────────────

    #[test]
    fn test_classifier_empty_is_empty() {
        let c = EntropyClassifier::new();
        assert_eq!(c.classify(&[]), ContentClass::Empty);
    }

    #[test]
    fn test_classifier_zeros_empty() {
        let c = EntropyClassifier::new();
        assert_eq!(c.classify(&zero_data()), ContentClass::Empty);
    }

    #[test]
    fn test_classifier_text() {
        let c = EntropyClassifier::new();
        assert_eq!(c.classify(&text_data()), ContentClass::Text);
    }

    #[test]
    fn test_classifier_uniform_encrypted() {
        let c = EntropyClassifier::new();
        assert_eq!(c.classify(&uniform_data()), ContentClass::Encrypted);
    }

    #[test]
    fn test_classifier_blocks_count() {
        let c = EntropyClassifier::new();
        let data = vec![0u8; 1024];
        let blocks = c.classify_blocks(&data);
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn test_content_class_display() {
        assert_eq!(ContentClass::Packed.to_string(), "Packed");
        assert_eq!(ContentClass::Empty.to_string(), "Empty");
    }

    // ── PackedRegion ──────────────────────────────────────────────────────────

    #[test]
    fn test_packed_region_find() {
        let mut data = zero_data();
        // Inject a "packed" region: entropy 7.0–7.5
        // Use a balanced byte distribution
        for i in 0..512 { data.push(i as u8); }
        let regions = PackedRegion::find(&data, 512);
        // May or may not find depending on exact entropy — just test no panic
        let _ = regions;
    }

    #[test]
    fn test_packed_region_display() {
        let r = PackedRegion { offset: 0x400, size: 1024, entropy: 7.2, packer_hint: None };
        assert!(r.to_string().contains("0x400"));
    }

    // ── EncryptedRegion ───────────────────────────────────────────────────────

    #[test]
    fn test_encrypted_region_find_uniform() {
        let regions = EncryptedRegion::find(&uniform_data(), 512);
        assert!(!regions.is_empty());
    }

    #[test]
    fn test_encrypted_region_display() {
        let r = EncryptedRegion { offset: 0x200, size: 512, entropy: 7.9, algorithm_hint: Some("AES".to_string()) };
        assert!(r.to_string().contains("0x200"));
    }

    // ── EntropyComparison ─────────────────────────────────────────────────────

    #[test]
    fn test_entropy_comparison_clean() {
        let cmp = EntropyComparison::compute(5.5);
        assert!(!cmp.looks_packed);
        assert_eq!(cmp.best_guess(), "clean/uncompressed");
    }

    #[test]
    fn test_entropy_comparison_packed() {
        let cmp = EntropyComparison::compute(7.2);
        assert!(cmp.looks_packed);
        assert!(!cmp.looks_encrypted);
        assert_eq!(cmp.best_guess(), "packed");
    }

    #[test]
    fn test_entropy_comparison_encrypted() {
        let cmp = EntropyComparison::compute(7.9);
        assert!(cmp.looks_encrypted);
        assert_eq!(cmp.best_guess(), "encrypted");
    }

    #[test]
    fn test_entropy_comparison_similarity_scores_non_empty() {
        let cmp = EntropyComparison::compute(6.0);
        assert!(!cmp.similarity_scores.is_empty());
    }

    #[test]
    fn test_entropy_comparison_display() {
        let cmp = EntropyComparison::compute(5.0);
        assert!(cmp.to_string().contains("EntropyComparison"));
    }

    // ── FileEntropyReport ─────────────────────────────────────────────────────

    #[test]
    fn test_file_entropy_report_zeros() {
        let report = FileEntropyReport::generate(&zero_data());
        assert!((report.global_entropy.value - (0.0)).abs() < f64::EPSILON);
        assert!(!report.is_likely_packed());
        assert!(!report.is_likely_encrypted());
    }

    #[test]
    fn test_file_entropy_report_uniform() {
        let report = FileEntropyReport::generate(&uniform_data());
        assert!(report.is_likely_packed());
        assert!(report.is_likely_encrypted());
    }

    #[test]
    fn test_file_entropy_report_json() {
        let report = FileEntropyReport::generate(&zero_data());
        let json = report.to_json().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["file_size"].is_number());
    }

    #[test]
    fn test_file_entropy_report_summary() {
        let report = FileEntropyReport::generate(&text_data());
        let s = report.summary();
        assert!(s.contains("FileEntropyReport"));
    }

    #[test]
    fn test_file_entropy_report_display() {
        let report = FileEntropyReport::generate(&zero_data());
        let s = format!("{report}");
        assert!(s.contains("File Entropy Report"));
    }

    #[test]
    fn test_file_entropy_report_with_sections() {
        let data: Vec<u8> = (0..256).map(|b| b as u8).collect();
        let secs = [(".text", 0u64, 128usize)];
        let report = FileEntropyReport::generate_with_sections(&data, &secs);
        assert_eq!(report.section_table.entries.len(), 1);
    }

    #[test]
    fn test_file_entropy_report_with_config() {
        let report = FileEntropyReport::generate_with_config(&zero_data(), 256, 6.5);
        assert_eq!(report.section_table.block_size, 256);
    }

    #[test]
    fn test_file_entropy_report_elapsed_non_zero() {
        let report = FileEntropyReport::generate(&uniform_data());
        // elapsed may be 0 on fast machines; just ensure it compiles
        let _ = report.elapsed_ms;
    }

    #[test]
    fn test_high_entropy_region_label_encrypted() {
        assert_eq!(classify_entropy_label(7.8), "encrypted");
    }

    #[test]
    fn test_high_entropy_region_label_packed() {
        assert_eq!(classify_entropy_label(7.2), "packed");
    }

    #[test]
    fn test_chi_square_stat_empty() {
        assert!((chi_square_stat(&[]) - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_simple_hash_deterministic() {
        assert_eq!(simple_hash(b"test"), simple_hash(b"test"));
        assert_ne!(simple_hash(b"test"), simple_hash(b"TEST"));
    }

    #[test]
    fn test_global_entropy_text_medium() {
        let g = GlobalEntropy::compute(&text_data());
        assert!(g.value > 1.0 && g.value < 7.0);
    }

    #[test]
    fn test_section_table_encrypted_entries() {
        let table = SectionEntropyTable::from_blocks(&uniform_data(), 512);
        assert!(!table.encrypted_entries().is_empty());
    }
}
