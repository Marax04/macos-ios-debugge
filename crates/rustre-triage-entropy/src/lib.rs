//! `rustre-triage-entropy` — Shannon entropy analysis for binary triage.
//!
//! Provides [`shannon_entropy`], [`EntropyRating`], [`SectionEntropy`],
//! [`EntropyResult`], and [`EntropyAnalyzer`] for detecting packed/encrypted data.

pub mod casts;
pub mod file_entropy_report;
pub mod compression_oracle;
pub mod entropy_heuristics;
pub mod packer_identifier;
pub mod anomaly;
pub mod byte_histogram;
pub mod classify;
pub mod compression_detector;
pub mod entropy_viz_data;
pub mod entropy_visualization;
pub mod heatmap_data;
pub mod histogram_analysis;
pub mod packer_entropy_profile;
pub mod randomness;
pub mod section_entropy;
pub mod shannon;
pub mod visual_entropy_map;
pub mod entropy_visualizer;
pub mod packer_detector;
pub mod section_entropy_analyzer;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use casts::{usize_to_f64, usize_to_f32, usize_to_u8, u64_to_usize, u32_to_f32, f64_to_f32, f32_to_usize};

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors from the entropy analysis subsystem.
#[derive(Debug, Error)]
pub enum EntropyError {
    /// Empty input data.
    #[error("empty input")]
    EmptyInput,
    /// Invalid chunk size.
    #[error("invalid chunk size: {0}")]
    InvalidChunk(usize),
}

// ─── Core function ────────────────────────────────────────────────────────────

/// Compute the Shannon entropy of `data` in bits (0.0 – 8.0).
///
/// H = -sum(p * log2(p)) for each byte value with non-zero frequency.
/// Returns 0.0 for empty or single-value slices.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = usize_to_f64(data.len());
    let mut h = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = f64::from(c) / len;
            h -= p * p.log2();
        }
    }
    h.clamp(0.0, 8.0)
}

// ─── EntropyRating ────────────────────────────────────────────────────────────

/// Qualitative entropy rating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntropyRating {
    /// Entropy < 1.0
    VeryLow,
    /// Entropy in [1.0, 3.0)
    Low,
    /// Entropy in [3.0, 5.0)
    Medium,
    /// Entropy in [5.0, 7.0)
    High,
    /// Entropy >= 7.0
    VeryHigh,
}

impl EntropyRating {
    /// Classify an entropy value.
    #[must_use]
    pub fn from_entropy(h: f64) -> Self {
        if h < 1.0 {
            Self::VeryLow
        } else if h < 3.0 {
            Self::Low
        } else if h < 5.0 {
            Self::Medium
        } else if h < 7.0 {
            Self::High
        } else {
            Self::VeryHigh
        }
    }
}

impl std::fmt::Display for EntropyRating {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::VeryLow => write!(f, "VeryLow"),
            Self::Low => write!(f, "Low"),
            Self::Medium => write!(f, "Medium"),
            Self::High => write!(f, "High"),
            Self::VeryHigh => write!(f, "VeryHigh"),
        }
    }
}

// ─── SectionEntropy ───────────────────────────────────────────────────────────

/// Entropy analysis for a named section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropy {
    /// Section name (e.g. `.text`, `.data`).
    pub name: String,
    /// Shannon entropy of this section.
    pub entropy: f64,
    /// Size of the section in bytes.
    pub size: usize,
    /// Byte offset of the section in the file.
    pub offset: usize,
    /// Qualitative rating.
    pub rating: EntropyRating,
}

impl SectionEntropy {
    /// Compute a [`SectionEntropy`] for `data` at `offset`.
    #[must_use]
    pub fn new(name: impl Into<String>, data: &[u8], offset: usize) -> Self {
        let entropy = shannon_entropy(data);
        Self {
            name: name.into(),
            entropy,
            size: data.len(),
            offset,
            rating: EntropyRating::from_entropy(entropy),
        }
    }

    /// Returns `true` if the section is likely packed (entropy > 7.0).
    #[must_use]
    pub fn is_packed(&self) -> bool {
        self.entropy > 7.0
    }

    /// Returns `true` if the section is likely encrypted (entropy > 7.5).
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.entropy > 7.5
    }
}

// ─── EntropyResult ────────────────────────────────────────────────────────────

/// Full entropy analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyResult {
    /// Overall entropy of the full data.
    pub overall: f64,
    /// Qualitative rating of the overall entropy.
    pub rating: EntropyRating,
    /// Per-section entropy breakdowns.
    pub sections: Vec<SectionEntropy>,
    /// Per-chunk entropy values.
    pub chunks: Vec<f64>,
}

impl EntropyResult {
    /// Return all sections with entropy > 7.0 (likely packed).
    #[must_use]
    pub fn packed_sections(&self) -> Vec<&SectionEntropy> {
        self.sections.iter().filter(|s| s.is_packed()).collect()
    }

    /// Return the maximum entropy across all chunks.
    #[must_use]
    pub fn max_chunk_entropy(&self) -> f64 {
        self.chunks.iter().copied().fold(0.0_f64, f64::max)
    }
}

// ─── EntropyAnalyzer ──────────────────────────────────────────────────────────

/// Entropy analyzer that operates on fixed-size chunks.
pub struct EntropyAnalyzer {
    /// Chunk size in bytes.
    pub chunk_size: usize,
}

impl EntropyAnalyzer {
    /// Create a new analyzer with the given chunk size.
    #[must_use]
    pub const fn new(chunk_size: usize) -> Self {
        Self { chunk_size }
    }

    /// Analyze `data`, splitting it into chunks of `chunk_size`.
    #[must_use]
    pub fn analyze(&self, data: &[u8]) -> EntropyResult {
        let overall = shannon_entropy(data);
        let rating = EntropyRating::from_entropy(overall);
        let chunks = if self.chunk_size == 0 || data.is_empty() {
            vec![]
        } else {
            data.chunks(self.chunk_size).map(shannon_entropy).collect()
        };
        EntropyResult {
            overall,
            rating,
            sections: vec![],
            chunks,
        }
    }

    /// Analyze `data` split into named sections, where each section is
    /// described as `(name, offset, size)`.
    ///
    /// Sections that extend beyond `data` are clamped.
    #[must_use]
    pub fn analyze_sections(
        &self,
        data: &[u8],
        sections: &[(&str, usize, usize)],
    ) -> EntropyResult {
        let overall = shannon_entropy(data);
        let rating = EntropyRating::from_entropy(overall);
        let chunks = if self.chunk_size == 0 || data.is_empty() {
            vec![]
        } else {
            data.chunks(self.chunk_size).map(shannon_entropy).collect()
        };
        let section_entropies = sections
            .iter()
            .map(|&(name, off, size)| {
                // Use saturating_add to prevent usize overflow from adversarial section metadata.
                let end = off.saturating_add(size).min(data.len());
                let slice = if off < data.len() {
                    &data[off..end]
                } else {
                    &[]
                };
                SectionEntropy::new(name, slice, off)
            })
            .collect();
        EntropyResult {
            overall,
            rating,
            sections: section_entropies,
            chunks,
        }
    }
}

// ─── EntropyCategory ─────────────────────────────────────────────────────────

/// Semantic content category inferred from Shannon entropy.
///
/// Maps entropy ranges to probable content types to aid triage decisions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EntropyCategory {
    /// Entropy < 1.0 — mostly-null or single-byte padding.
    Empty,
    /// Entropy in [1.0, 4.0) — human-readable text or markup.
    Text,
    /// Entropy in [4.0, 5.0) — source code or structured binary tables.
    Code,
    /// Entropy in [5.0, 6.0) — compiled data or mixed binary/text.
    Data,
    /// Entropy in [6.0, 7.0) — compressed data (deflate, zlib, lz4…).
    Compressed,
    /// Entropy in [7.0, 7.5) — strongly compressed or encrypted material.
    Encrypted,
    /// Entropy >= 7.5 — effectively random; ciphertext or PRNG output.
    Random,
}

impl EntropyCategory {
    /// Classify a floating-point entropy value into a [`EntropyCategory`].
    #[must_use]
    pub fn classify(e: f32) -> Self {
        if e < 1.0 {
            Self::Empty
        } else if e < 4.0 {
            Self::Text
        } else if e < 5.0 {
            Self::Code
        } else if e < 6.0 {
            Self::Data
        } else if e < 7.0 {
            Self::Compressed
        } else if e < 7.5 {
            Self::Encrypted
        } else {
            Self::Random
        }
    }

    /// Short human-readable label for use in ASCII heatmaps and reports.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Empty => "Empty",
            Self::Text => "Text",
            Self::Code => "Code",
            Self::Data => "Data",
            Self::Compressed => "Compressed",
            Self::Encrypted => "Encrypted",
            Self::Random => "Random",
        }
    }
}

impl std::fmt::Display for EntropyCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// ─── Shannon entropy (f32 variant) ───────────────────────────────────────────

/// Compute Shannon entropy of `data` returning an `f32` in [0.0, 8.0].
///
/// This is a convenience wrapper used internally by the block-analysis
/// pipeline where f32 precision is sufficient and avoids unnecessary widening.
#[must_use]
pub fn shannon_entropy_f32(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in data {
        counts[*b as usize] += 1;
    }
    let len = usize_to_f32(data.len());
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = u32_to_f32(c) / len;
            -p * p.log2()
        })
        .sum::<f32>()
        .clamp(0.0, 8.0)
}

// ─── EntropyBlock ─────────────────────────────────────────────────────────────

/// Entropy measurement for a contiguous region of a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyBlock {
    /// Byte offset within the parent buffer.
    pub offset: u64,
    /// Number of bytes in this block.
    pub size: usize,
    /// Shannon entropy of this block (0.0 – 8.0).
    pub entropy: f32,
    /// Semantic content category inferred from entropy.
    pub category: EntropyCategory,
}

impl EntropyBlock {
    /// Create an [`EntropyBlock`] by computing entropy of `data` at `offset`.
    #[must_use]
    pub fn from_slice(offset: u64, data: &[u8]) -> Self {
        let entropy = shannon_entropy_f32(data);
        Self {
            offset,
            size: data.len(),
            entropy,
            category: EntropyCategory::classify(entropy),
        }
    }
}

/// Split `data` into non-overlapping blocks of `block_size` bytes and compute
/// the entropy of each block.
///
/// The final block may be smaller than `block_size` if the data length is not
/// an exact multiple. Returns an empty vector when `data` is empty or
/// `block_size` is zero.
#[must_use]
pub fn analyze_blocks(data: &[u8], block_size: usize) -> Vec<EntropyBlock> {
    if data.is_empty() || block_size == 0 {
        return vec![];
    }
    data.chunks(block_size)
        .enumerate()
        .map(|(i, chunk)| {
            // Cast before multiplying to avoid usize overflow on 32-bit targets.
            let offset = (i as u64) * (block_size as u64);
            EntropyBlock::from_slice(offset, chunk)
        })
        .collect()
}

// ─── SectionDescriptor / analyze_with_sections ───────────────────────────────

/// Caller-supplied description of a section within a raw byte buffer.
///
/// Used by [`analyze_with_sections`] so callers control naming without having
/// to depend on any particular PE/ELF parser type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionDescriptor {
    /// Section name (e.g. `.text`, `.rdata`).
    pub name: String,
    /// Byte offset of the section within the parent buffer.
    pub raw_offset: u64,
    /// Number of raw bytes occupied by the section.
    pub raw_size: u64,
}

/// Compute entropy for each described section plus the full buffer, sorted by
/// entropy descending.
///
/// The final element is the whole-buffer entropy with name `"<whole>"`.
/// Sections that fall outside `data` are clamped; out-of-range offsets produce
/// an empty slice (entropy 0.0).
#[must_use]
pub fn analyze_with_sections(
    data: &[u8],
    sections: &[SectionDescriptor],
) -> Vec<EntropyBlock> {
    let mut out: Vec<EntropyBlock> = sections
        .iter()
        .map(|s| {
            let off = u64_to_usize(s.raw_offset);
            let size = u64_to_usize(s.raw_size);
            let end = off.saturating_add(size).min(data.len());
            let slice: &[u8] = if off < data.len() { &data[off..end] } else { &[] };
            let entropy = shannon_entropy_f32(slice);
            EntropyBlock {
                offset: s.raw_offset,
                size: slice.len(),
                entropy,
                category: EntropyCategory::classify(entropy),
            }
        })
        .collect();

    let whole_entropy = shannon_entropy_f32(data);
    out.push(EntropyBlock {
        offset: 0,
        size: data.len(),
        entropy: whole_entropy,
        category: EntropyCategory::classify(whole_entropy),
    });

    // Sort by entropy desc; NaN-safe via partial_cmp fallback.
    out.sort_by(|a, b| {
        b.entropy
            .partial_cmp(&a.entropy)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    out
}

// We need a parallel name list since EntropyBlock has no name field; expose
// a small helper struct for callers that want both. Kept here as a re-export
// convenience so existing EntropyBlock consumers are unaffected.

// ─── ByteHistogram ────────────────────────────────────────────────────────────

/// Per-byte frequency counts and derived statistics for a byte sequence.
///
/// Useful for chi-square randomness testing and frequency profiling.
///
/// `counts` is stored as a `Vec<u32>` of length 256 so that serde can
/// serialize/deserialize it without requiring a third-party array crate.
/// Use [`ByteHistogram::count_of`] for indexed access.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ByteHistogram {
    /// Raw byte counts (length 256): `counts[b]` is the frequency of byte `b`.
    pub counts: Vec<u32>,
    /// Total number of bytes counted.
    pub total: usize,
}

impl ByteHistogram {
    /// Build a [`ByteHistogram`] from `data`.
    #[must_use]
    pub fn new(data: &[u8]) -> Self {
        let mut counts = vec![0u32; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        Self {
            counts,
            total: data.len(),
        }
    }

    /// Return the frequency of a specific byte value.
    #[must_use]
    pub fn count_of(&self, byte: u8) -> u32 {
        self.counts[byte as usize]
    }

    /// Compute the chi-square statistic under the null hypothesis of a
    /// uniform distribution (all 256 byte values equally probable).
    ///
    /// χ² = Σ (Oᵢ − Eᵢ)² / Eᵢ  where Eᵢ = n / 256.
    ///
    /// Returns `0.0` for empty histograms (avoids division by zero).
    #[must_use]
    pub fn chi_square_statistic(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let expected = usize_to_f64(self.total) / 256.0;
        self.counts.iter().fold(0.0f64, |acc, &observed| {
            let diff = f64::from(observed) - expected;
            acc + (diff * diff) / expected
        })
    }

    /// Returns `true` when the data is likely random.
    ///
    /// A truly uniform random byte stream has χ² ≈ 255 (degrees of freedom).
    /// We accept the range [200, 310] as "close to uniform", which corresponds
    /// roughly to p-values above 0.01 for a two-tailed test.
    #[must_use]
    pub fn is_likely_random(&self) -> bool {
        let chi2 = self.chi_square_statistic();
        (200.0..=310.0).contains(&chi2)
    }

    /// Return the `n` most-frequent byte values in descending order of count.
    ///
    /// Each element is `(byte_value, count)`. If `n` exceeds 256 it is clamped.
    #[must_use]
    pub fn most_common_bytes(&self, n: usize) -> Vec<(u8, u32)> {
        let n = n.min(256);
        let mut pairs: Vec<(u8, u32)> = self
            .counts
            .iter()
            .enumerate()
            .map(|(b, &c)| (usize_to_u8(b), c))
            .collect();
        pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1));
        pairs.truncate(n);
        pairs
    }
}

// ─── HeatmapData ──────────────────────────────────────────────────────────────

/// Entropy heatmap built from a sequence of [`EntropyBlock`]s.
///
/// Provides both ASCII-art and RGB colour representations suitable for
/// terminal output and GUI widgets respectively.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapData {
    /// The ordered blocks whose entropy is visualised.
    pub blocks: Vec<EntropyBlock>,
}

impl HeatmapData {
    /// Build a [`HeatmapData`] by calling [`analyze_blocks`] on `data`.
    #[must_use]
    pub fn from_data(data: &[u8], block_size: usize) -> Self {
        Self {
            blocks: analyze_blocks(data, block_size),
        }
    }

    /// Construct from an existing block list.
    #[must_use]
    pub const fn from_blocks(blocks: Vec<EntropyBlock>) -> Self {
        Self { blocks }
    }

    /// Render the entropy of each block as a single row of ASCII characters.
    ///
    /// The palette `" .:;+=xX$#"` maps linearly from 0.0 (space) to 8.0 (`#`).
    /// Blocks are merged or split to fit within `width` columns using
    /// simple averaging when the block count exceeds `width`.
    #[must_use]
    pub fn to_ascii_heatmap(&self, width: usize) -> String {
        const PALETTE: &[u8] = b" .:;+=xX$#";
        if self.blocks.is_empty() || width == 0 {
            return String::new();
        }
        let n = self.blocks.len();
        // Build a row of exactly `width` characters by sampling blocks.
        let chars: String = (0..width)
            .map(|col| {
                // Map column index to block range
                let start = col * n / width;
                let end = ((col + 1) * n / width).max(start + 1).min(n);
                let avg_entropy: f32 = self.blocks[start..end]
                    .iter()
                    .map(|b| b.entropy)
                    .sum::<f32>()
                    / usize_to_f32(end - start);
                let palette_max = usize_to_f32(PALETTE.len() - 1);
                let idx = f32_to_usize(((avg_entropy / 8.0) * palette_max).min(palette_max));
                PALETTE[idx] as char
            })
            .collect();

        // Wrap with a border and a scale legend.
        let border = "-".repeat(width + 2);
        format!(
            "{border}\n|{chars}|\n{border}\n0{:^width$}8.0\n",
            "",
            width = width.saturating_sub(1)
        )
    }

    /// Map an entropy value to an RGB colour for use in GUI heatmaps.
    ///
    /// Colour ramp (low → high entropy):
    /// - `[0, 2)` → dark blue  `[0, 0, 128]`
    /// - `[2, 4)` → light blue `[0, 128, 255]`
    /// - `[4, 6)` → green      `[0, 200, 0]`
    /// - `[6, 7)` → amber      `[255, 200, 0]`
    /// - `[7, 8]` → red        `[200, 0, 0]`
    #[must_use]
    pub fn color_rgb(e: f32) -> [u8; 3] {
        if e < 2.0 {
            [0, 0, 128]
        } else if e < 4.0 {
            [0, 128, 255]
        } else if e < 6.0 {
            [0, 200, 0]
        } else if e < 7.0 {
            [255, 200, 0]
        } else {
            [200, 0, 0]
        }
    }

    /// Return the RGB colour for every block in order.
    #[must_use]
    pub fn to_rgb_colors(&self) -> Vec<[u8; 3]> {
        self.blocks
            .iter()
            .map(|b| Self::color_rgb(b.entropy))
            .collect()
    }
}

// ─── PackingDetector ──────────────────────────────────────────────────────────

/// Heuristic PE packing detector.
///
/// Inspects raw PE bytes and returns a list of human-readable indicator
/// strings, each describing a single suspicious observation.  An empty list
/// means no packing indicators were found.
pub struct PackingDetector;

impl PackingDetector {
    /// Detect common packing indicators in `pe_data`.
    ///
    /// # Indicators checked
    /// - High entropy `.text` section (entropy > 7.0)
    /// - Suspiciously low import count (< 5 named imports)
    /// - UPX magic bytes / section names (`UPX0`, `UPX1`)
    /// - Known packer section names (`.tmd`, `.vmp0`, `.nsp0`, `.themida`,
    ///   `.petite`, `.aspack`, `.mpress`, `.obsidium`)
    /// - Data overlay (bytes after last declared section)
    #[must_use]
    pub fn detect_packing_indicators(pe_data: &[u8]) -> Vec<String> {
        const SECTION_ENTRY_SIZE: usize = 40;
        const PACKER_NAMES: &[&str] = &[
            ".tmd", ".vmp0", ".nsp0", ".themida", ".petite", ".aspack", ".mpress", ".obsidium",
        ];
        const UPX_NAMES: &[&str] = &["UPX0", "UPX1", "UPX2"];
        let mut indicators = Vec::new();

        // ── UPX file-level magic ─────────────────────────────────────────────
        // UPX prepends "UPX!" at offset 0x1c8 in the DOS stub / PE header area.
        // Count non-overlapping occurrences so we can distinguish a single
        // header marker (normal UPX) from repeated copies (re-packed / nested
        // UPX, a stronger indicator).
        let upx_marker_count = Self::count_nonoverlapping(pe_data, b"UPX!");
        if upx_marker_count > 0 {
            indicators.push(format!(
                "UPX magic bytes found in file ({upx_marker_count} occurrence(s))"
            ));
        }

        // Bail out early if the data is too small to contain a valid PE header.
        if pe_data.len() < 64 {
            return indicators;
        }

        // ── Locate PE header ─────────────────────────────────────────────────
        let e_lfanew = usize::try_from(
            u32::from_le_bytes([pe_data[0x3c], pe_data[0x3d], pe_data[0x3e], pe_data[0x3f]])
        ).unwrap_or(usize::MAX);

        // Guard against overflow: e_lfanew + 24 must not wrap.
        if e_lfanew > pe_data.len().saturating_sub(24) {
            return indicators;
        }

        // Check PE signature.
        if &pe_data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return indicators;
        }

        // Valid PE header confirmed — set flag so heuristics below are gated.
        let valid_pe = true;

        // ── COFF header fields ───────────────────────────────────────────────
        let num_sections =
            usize::from(u16::from_le_bytes([pe_data[e_lfanew + 6], pe_data[e_lfanew + 7]]));

        let opt_header_size =
            usize::from(u16::from_le_bytes([pe_data[e_lfanew + 20], pe_data[e_lfanew + 21]]));

        // ── Optional header: import directory ────────────────────────────────
        // The import directory RVA lives at a fixed offset within the optional
        // header (offset 104 for PE32, 120 for PE32+).
        let opt_magic_offset = e_lfanew + 24;
        if opt_magic_offset + 2 <= pe_data.len() {
            let opt_magic =
                u16::from_le_bytes([pe_data[opt_magic_offset], pe_data[opt_magic_offset + 1]]);
            let import_dir_offset = match opt_magic {
                0x10b => opt_magic_offset + 104, // PE32
                0x20b => opt_magic_offset + 120, // PE32+
                _ => 0,
            };
            if import_dir_offset + 8 <= pe_data.len() {
                let import_rva = u32::from_le_bytes([
                    pe_data[import_dir_offset],
                    pe_data[import_dir_offset + 1],
                    pe_data[import_dir_offset + 2],
                    pe_data[import_dir_offset + 3],
                ]);
                // Heuristic: if the import RVA is 0 there are no imports at all.
                if import_rva == 0 {
                    indicators.push("No import directory (0 imports)".to_string());
                }
            }
        }

        // ── Section table ────────────────────────────────────────────────────
        let section_table_start = e_lfanew + 24 + opt_header_size;
        let last_section_end = Self::walk_section_table(
            pe_data, section_table_start, num_sections, SECTION_ENTRY_SIZE,
            PACKER_NAMES, UPX_NAMES, &mut indicators,
        );

        // Walk the actual PE import descriptor table to count imported DLLs,
        // rather than the previous cheap ".dll" substring proxy (which was the
        // source of FIX F: large PEs whose import tables sat past 64KB always
        // came back as "Few imports (<5)" even when they had dozens of imports).
        // Bonus: this also counts DLLs whose name strings live in a section
        // beyond the 64KB probe window.
        // Count once and reuse: the previous form called `count_pe_imports`
        // twice, walking the whole descriptor table a second time purely to
        // format the message.
        if valid_pe {
            if let Some(dll_count) =
                Self::count_pe_imports(pe_data, e_lfanew, opt_header_size, num_sections)
            {
                if dll_count < 5 {
                    indicators
                        .push(format!("Few imports (<5) — {dll_count} DLL(s) in import table"));
                }
            }
        }

        // ── Overlay detection ────────────────────────────────────────────────
        if last_section_end > 0 && last_section_end < pe_data.len() {
            let overlay_size = pe_data.len() - last_section_end;
            indicators.push(format!(
                "Overlay detected: {overlay_size} bytes after last section (offset 0x{last_section_end:x})"
            ));
        }

        indicators
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn walk_section_table(
        pe_data: &[u8],
        section_table_start: usize,
        num_sections: usize,
        entry_size: usize,
        packer_names: &[&str],
        upx_names: &[&str],
        indicators: &mut Vec<String>,
    ) -> usize {
        let mut last_section_end: usize = 0;
        for i in 0..num_sections {
            let entry_start = section_table_start.saturating_add(i * entry_size);
            if entry_start + entry_size > pe_data.len() { break; }
            let entry = &pe_data[entry_start..entry_start + entry_size];
            let raw_name = &entry[0..8];
            let name_end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            let name = std::str::from_utf8(&raw_name[..name_end]).unwrap_or("");
            let raw_offset = usize::try_from(u32::from_le_bytes([entry[20], entry[21], entry[22], entry[23]])).unwrap_or(usize::MAX);
            let raw_size = usize::try_from(u32::from_le_bytes([entry[16], entry[17], entry[18], entry[19]])).unwrap_or(usize::MAX);
            let section_end = raw_offset.saturating_add(raw_size);
            if section_end > last_section_end { last_section_end = section_end; }
            if upx_names.contains(&name) {
                indicators.push(format!("UPX magic in section name: \"{name}\""));
            }
            if packer_names.iter().any(|&p| name.eq_ignore_ascii_case(p)) {
                indicators.push(format!("Section name indicates packer: \"{name}\""));
            }
            if (name == ".text" || name == "CODE") && raw_offset.saturating_add(raw_size) <= pe_data.len() && raw_size > 0 {
                let section_data = &pe_data[raw_offset..raw_offset + raw_size];
                let e = shannon_entropy_f32(section_data);
                if e > 7.0 {
                    indicators.push(format!("High entropy .text section (>7.0) — entropy={e:.3}"));
                }
            }
        }
        last_section_end
    }

    /// Load a binary from `path` and run [`PackingDetector::detect_packing_indicators`].
    ///
    /// Path-accepting counterpart for MCP wrappers (`triage_entropy_packing_indicators`)
    /// that receive a `path` parameter when no session buffer is loaded.
    ///
    /// # Errors
    ///
    /// Returns an [`std::io::Error`] if the file at `path` cannot be read.
    pub fn detect_packing_indicators_from_path<P: AsRef<std::path::Path>>(
        path: P,
    ) -> std::io::Result<Vec<String>> {
        let data = std::fs::read(path)?;
        Ok(Self::detect_packing_indicators(&data))
    }

    /// Number of `IMAGE_IMPORT_DESCRIPTOR` entries in `pe_data`, or `None`
    /// when it is not a PE with a usable import directory.
    ///
    /// This is the evidence behind the "Few imports (<5)" indicator. That
    /// indicator was previously the only observable output of the import
    /// walk, so a caller could see the verdict but never the number it came
    /// from — and could not tell "5 imports, not packed" from "the walk found
    /// no import directory at all". Exposing the count makes the indicator
    /// auditable; it does not change how the indicator is decided.
    #[must_use]
    pub fn pe_import_count(pe_data: &[u8]) -> Option<usize> {
        if pe_data.len() < 64 {
            return None;
        }
        let e_lfanew = usize::try_from(u32::from_le_bytes([
            pe_data[0x3c],
            pe_data[0x3d],
            pe_data[0x3e],
            pe_data[0x3f],
        ]))
        .ok()?;
        if e_lfanew > pe_data.len().saturating_sub(24) {
            return None;
        }
        if &pe_data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return None;
        }
        let num_sections =
            usize::from(u16::from_le_bytes([pe_data[e_lfanew + 6], pe_data[e_lfanew + 7]]));
        let opt_header_size = usize::from(u16::from_le_bytes([
            pe_data[e_lfanew + 20],
            pe_data[e_lfanew + 21],
        ]));
        Self::count_pe_imports(pe_data, e_lfanew, opt_header_size, num_sections)
    }

    /// [`Self::pe_import_count`] for a file on disk.
    ///
    /// # Errors
    /// Propagates any I/O error from reading `path`.
    pub fn pe_import_count_from_path<P: AsRef<std::path::Path>>(
        path: P,
    ) -> std::io::Result<Option<usize>> {
        let data = std::fs::read(path)?;
        Ok(Self::pe_import_count(&data))
    }

    /// Returns `true` if `haystack` contains `needle` as a contiguous sequence.
    fn contains_sequence(haystack: &[u8], needle: &[u8]) -> bool {
        if needle.is_empty() {
            return true;
        }
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// Walk the PE import directory and count distinct imported DLL descriptors.
    ///
    /// Returns `None` when the PE doesn't have a usable import directory (no
    /// optional-header data directory, RVA is zero, or the RVA cannot be
    /// translated to a file offset). Returns `Some(count)` otherwise, where
    /// `count` is the number of `IMAGE_IMPORT_DESCRIPTOR` entries before the
    /// null terminator descriptor.
    ///
    /// This replaces the previous ".dll" substring proxy that incorrectly
    /// reported "Few imports (<5)" on PEs whose imports were past the 64KB
    /// probe window — the root cause of FIX F.
    fn count_pe_imports(
        pe_data: &[u8],
        e_lfanew: usize,
        opt_header_size: usize,
        num_sections: usize,
    ) -> Option<usize> {
        const SECTION_ENTRY_SIZE: usize = 40;
        const DESC_SIZE: usize = 20;
        let opt_magic_off = e_lfanew.checked_add(24)?;
        if opt_magic_off + 2 > pe_data.len() {
            return None;
        }
        let opt_magic =
            u16::from_le_bytes([pe_data[opt_magic_off], pe_data[opt_magic_off + 1]]);
        let import_dir_off = match opt_magic {
            0x10b => opt_magic_off + 104, // PE32
            0x20b => opt_magic_off + 120, // PE32+
            _ => return None,
        };
        if import_dir_off + 8 > pe_data.len() {
            return None;
        }
        let import_rva = u32::from_le_bytes([
            pe_data[import_dir_off],
            pe_data[import_dir_off + 1],
            pe_data[import_dir_off + 2],
            pe_data[import_dir_off + 3],
        ]);
        if import_rva == 0 {
            return None;
        }

        // Translate RVA -> file offset by walking the section table.
        let section_table_start = opt_magic_off.checked_add(opt_header_size)?;
        let mut import_file_off: Option<usize> = None;
        for i in 0..num_sections {
            let entry_start = section_table_start.checked_add(i.checked_mul(SECTION_ENTRY_SIZE)?)?;
            if entry_start + SECTION_ENTRY_SIZE > pe_data.len() {
                break;
            }
            let entry = &pe_data[entry_start..entry_start + SECTION_ENTRY_SIZE];
            let virt_size = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]);
            let virt_addr = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]);
            let raw_off = u32::from_le_bytes([entry[20], entry[21], entry[22], entry[23]]);
            let raw_size = u32::from_le_bytes([entry[16], entry[17], entry[18], entry[19]]);
            let span = virt_size.max(raw_size);
            if import_rva >= virt_addr && import_rva < virt_addr.saturating_add(span) {
                let delta = import_rva - virt_addr;
                import_file_off = Some(usize::try_from(raw_off).unwrap_or(usize::MAX).saturating_add(usize::try_from(delta).unwrap_or(usize::MAX)));
                break;
            }
        }
        let mut off = import_file_off?;
        // Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes; the table is null-terminated.
        let mut count = 0usize;
        while off + DESC_SIZE <= pe_data.len() {
            let entry = &pe_data[off..off + DESC_SIZE];
            // Bytes 12..16 = Name RVA. Null terminator: all fields zero.
            let name_rva =
                u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]);
            let original_first_thunk =
                u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
            let first_thunk =
                u32::from_le_bytes([entry[16], entry[17], entry[18], entry[19]]);
            if name_rva == 0 && original_first_thunk == 0 && first_thunk == 0 {
                break;
            }
            if name_rva != 0 {
                count += 1;
            }
            off += DESC_SIZE;
            // Hard cap to avoid pathological loops on malformed PEs.
            if count > 4096 {
                break;
            }
        }
        Some(count)
    }

    /// Count non-overlapping occurrences of `needle` in `haystack`.
    fn count_nonoverlapping(haystack: &[u8], needle: &[u8]) -> usize {
        if needle.is_empty() {
            return 0;
        }
        // Fast-reject when the needle is absent — `contains_sequence` is a
        // single-pass windowed equality that lets the optimizer vectorize the
        // common "no match" case and skip the counting loop entirely.
        if !Self::contains_sequence(haystack, needle) {
            return 0;
        }
        let mut count = 0usize;
        let mut i = 0usize;
        while i + needle.len() <= haystack.len() {
            if &haystack[i..i + needle.len()] == needle {
                count += 1;
                i += needle.len();
            } else {
                i += 1;
            }
        }
        count
    }
}

// ─── EntropyReport ────────────────────────────────────────────────────────────

/// Comprehensive entropy analysis report for a binary file.
///
/// Generated by [`EntropyReport::generate`], combining overall entropy,
/// per-block breakdown, packing indicators, and the full byte histogram.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyReport {
    /// Shannon entropy of the entire input (0.0 – 8.0).
    pub overall_entropy: f32,
    /// Semantic category inferred from the overall entropy.
    pub category: EntropyCategory,
    /// Whether the binary shows signs of packing or encryption.
    pub is_likely_packed: bool,
    /// Human-readable packing/obfuscation indicator strings.
    pub packing_indicators: Vec<String>,
    /// Fixed-size entropy blocks covering the full input.
    pub sections: Vec<EntropyBlock>,
    /// Full byte-frequency histogram.
    pub histogram: ByteHistogram,
}

impl EntropyReport {
    /// Default block size used when generating reports.
    pub const DEFAULT_BLOCK_SIZE: usize = 512;

    /// Generate a complete entropy report for `data`.
    ///
    /// Blocks are computed with [`Self::DEFAULT_BLOCK_SIZE`] (512 bytes).
    /// Packing indicators are produced via [`PackingDetector`].
    #[must_use]
    pub fn generate(data: &[u8]) -> Self {
        Self::generate_with_block_size(data, Self::DEFAULT_BLOCK_SIZE)
    }

    /// Generate a complete entropy report using a custom `block_size`.
    #[must_use]
    pub fn generate_with_block_size(data: &[u8], block_size: usize) -> Self {
        let overall_entropy = shannon_entropy_f32(data);
        let category = EntropyCategory::classify(overall_entropy);
        let packing_indicators = PackingDetector::detect_packing_indicators(data);
        let is_likely_packed = !packing_indicators.is_empty();
        let sections = analyze_blocks(data, block_size.max(1));
        let histogram = ByteHistogram::new(data);
        Self {
            overall_entropy,
            category,
            is_likely_packed,
            packing_indicators,
            sections,
            histogram,
        }
    }

    /// Return a [`HeatmapData`] view over the report's block list.
    #[must_use]
    pub fn heatmap(&self) -> HeatmapData {
        HeatmapData::from_blocks(self.sections.clone())
    }

    /// Return blocks whose entropy exceeds `threshold`.
    #[must_use]
    pub fn high_entropy_blocks(&self, threshold: f32) -> Vec<&EntropyBlock> {
        self.sections
            .iter()
            .filter(|b| b.entropy > threshold)
            .collect()
    }

    /// Summary string suitable for quick triage output.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "EntropyReport {{ overall: {:.3}, category: {}, packed: {}, indicators: {} }}",
            self.overall_entropy,
            self.category,
            self.is_likely_packed,
            self.packing_indicators.len(),
        )
    }
}

impl std::fmt::Display for EntropyReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Entropy Report ===")?;
        writeln!(f, "  Overall entropy : {:.4}", self.overall_entropy)?;
        writeln!(f, "  Category        : {}", self.category)?;
        writeln!(f, "  Likely packed   : {}", self.is_likely_packed)?;
        writeln!(
            f,
            "  Chi-square      : {:.2}",
            self.histogram.chi_square_statistic()
        )?;
        writeln!(
            f,
            "  Likely random   : {}",
            self.histogram.is_likely_random()
        )?;
        if !self.packing_indicators.is_empty() {
            writeln!(f, "  Packing indicators:")?;
            for ind in &self.packing_indicators {
                writeln!(f, "    - {ind}")?;
            }
        }
        writeln!(f, "  Blocks          : {}", self.sections.len())?;
        Ok(())
    }
}

// ─── survey_binary ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SurveySection {
    pub name: String,
    pub virtual_address: u32,
    pub size: u32,
    pub entropy: f64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SurveyCryptoHit {
    pub algorithm: String,
    pub constant_name: String,
    pub offset: u64,
    pub confidence: f32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SurveyResult {
    pub file_kind: String,
    pub size: usize,
    pub is_pe: bool,
    pub overall_entropy: f64,
    pub packing_indicators: Vec<String>,
    pub import_count: usize,
    pub sections: Vec<SurveySection>,
    pub crypto_hits: Vec<SurveyCryptoHit>,
    pub crypto_hit_count: usize,
}

/// One-shot triage of a binary: file kind, PE sections, import count,
/// overall entropy, packing indicators, and crypto-constant hits.
#[must_use]
pub fn survey_binary(data: &[u8]) -> SurveyResult {
    use rustre_triage::detect_file_kind;

    let file_kind = detect_file_kind(data).to_string();
    let overall_entropy = shannon_entropy(data);
    let mut packing_indicators = PackingDetector::detect_packing_indicators(data);

    let (sections, import_count, is_pe) =
        if let Ok(mut pe) = rustre_pe_tools::PeFile::parse(data) {
            let _ = pe.parse_imports(data);
            let ic = pe.imports.len();
            packing_indicators.retain(|s: &String| !s.contains("Few imports"));
            if ic < 5 {
                packing_indicators
                    .push(format!("Few imports ({ic} total) — possible packing"));
            }
            let secs: Vec<SurveySection> = pe
                .sections
                .iter()
                .map(|s| {
                    let start = s.raw_offset as usize;
                    let end = (start + s.raw_size as usize).min(data.len());
                    let sec_data = if start < data.len() { &data[start..end] } else { &[] };
                    SurveySection {
                        name: s.name.clone(),
                        virtual_address: s.virtual_address,
                        size: s.virtual_size,
                        entropy: shannon_entropy(sec_data),
                    }
                })
                .collect();
            (secs, ic, true)
        } else {
            (vec![], 0, false)
        };

    let raw_hits = rustre_crypto_id::scan_binary_for_crypto_constants(data);
    let crypto_hit_count = raw_hits.len();
    let crypto_hits: Vec<SurveyCryptoHit> = raw_hits
        .into_iter()
        .map(|h| SurveyCryptoHit {
            algorithm: h.algorithm,
            constant_name: h.constant_name,
            offset: h.offset,
            confidence: f64_to_f32(h.confidence),
        })
        .collect();

    SurveyResult {
        file_kind,
        size: data.len(),
        is_pe,
        overall_entropy,
        packing_indicators,
        import_count,
        sections,
        crypto_hits,
        crypto_hit_count,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PackingDetector::contains_sequence ────────────────────────────────

    #[test]
    fn test_contains_sequence_basic() {
        // Empty needle is trivially contained.
        assert!(PackingDetector::contains_sequence(b"anything", b""));
        // Hit at offset > 0.
        assert!(PackingDetector::contains_sequence(b"prefix-UPX!-suffix", b"UPX!"));
        // Hit at start.
        assert!(PackingDetector::contains_sequence(b"UPX!rest", b"UPX!"));
        // Miss.
        assert!(!PackingDetector::contains_sequence(b"no marker here", b"UPX!"));
        // Needle longer than haystack.
        assert!(!PackingDetector::contains_sequence(b"ab", b"abc"));
    }

    // ── shannon_entropy ───────────────────────────────────────────────────

    #[test]
    fn test_entropy_empty_is_zero() {
        assert!((shannon_entropy(&[]) - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_entropy_all_zeros_is_zero() {
        assert!((shannon_entropy(&[0u8; 1000]) - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_entropy_repeated_single_byte_is_zero() {
        assert!((shannon_entropy(&[0xABu8; 256]) - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_entropy_uniform_256_values_is_eight() {
        let data: Vec<u8> = (0u8..=255).collect();
        let h = shannon_entropy(&data);
        assert!((h - 8.0).abs() < 1e-9, "expected ~8.0, got {h}");
    }

    #[test]
    fn test_entropy_two_equal_frequencies_is_one() {
        let mut data = vec![0u8; 50];
        data.extend(vec![1u8; 50]);
        let h = shannon_entropy(&data);
        assert!((h - 1.0).abs() < 1e-9, "expected 1.0, got {h}");
    }

    #[test]
    fn test_entropy_single_byte_slice() {
        assert!((shannon_entropy(&[42u8]) - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_entropy_range_clamped() {
        let h = shannon_entropy(&[0u8; 100]);
        assert!((0.0..=8.0).contains(&h));
    }

    // ── EntropyRating ─────────────────────────────────────────────────────

    #[test]
    fn test_rating_very_low() {
        assert_eq!(EntropyRating::from_entropy(0.5), EntropyRating::VeryLow);
    }

    #[test]
    fn test_rating_low() {
        assert_eq!(EntropyRating::from_entropy(2.0), EntropyRating::Low);
    }

    #[test]
    fn test_rating_medium() {
        assert_eq!(EntropyRating::from_entropy(4.0), EntropyRating::Medium);
    }

    #[test]
    fn test_rating_high() {
        assert_eq!(EntropyRating::from_entropy(6.0), EntropyRating::High);
    }

    #[test]
    fn test_rating_very_high() {
        assert_eq!(EntropyRating::from_entropy(7.5), EntropyRating::VeryHigh);
        assert_eq!(EntropyRating::from_entropy(8.0), EntropyRating::VeryHigh);
    }

    #[test]
    fn test_rating_boundary_exactly_seven() {
        // >= 7.0 → VeryHigh
        assert_eq!(EntropyRating::from_entropy(7.0), EntropyRating::VeryHigh);
    }

    #[test]
    fn test_rating_display() {
        assert_eq!(EntropyRating::VeryLow.to_string(), "VeryLow");
        assert_eq!(EntropyRating::VeryHigh.to_string(), "VeryHigh");
    }

    // ── SectionEntropy ────────────────────────────────────────────────────

    #[test]
    fn test_section_entropy_new() {
        let data = vec![0u8; 100];
        let se = SectionEntropy::new(".bss", &data, 0x1000);
        assert_eq!(se.name, ".bss");
        assert!((se.entropy - (0.0)).abs() < f64::EPSILON);
        assert_eq!(se.size, 100);
        assert_eq!(se.offset, 0x1000);
        assert_eq!(se.rating, EntropyRating::VeryLow);
    }

    #[test]
    fn test_section_is_packed() {
        // Simulate high-entropy section
        let data: Vec<u8> = (0..256).cycle().take(1024).map(|x| x as u8).collect();
        let se = SectionEntropy::new(".text", &data, 0);
        // uniform 256 → entropy=8.0 → is_packed
        assert!(se.is_packed());
        assert!(se.is_encrypted());
    }

    #[test]
    fn test_section_not_packed() {
        let data = vec![0u8; 100];
        let se = SectionEntropy::new(".data", &data, 0);
        assert!(!se.is_packed());
        assert!(!se.is_encrypted());
    }

    // ── EntropyAnalyzer ───────────────────────────────────────────────────

    #[test]
    fn test_analyzer_analyze_all_zeros() {
        let a = EntropyAnalyzer::new(256);
        let r = a.analyze(&[0u8; 512]);
        assert!((r.overall - (0.0)).abs() < f64::EPSILON);
        assert_eq!(r.rating, EntropyRating::VeryLow);
    }

    #[test]
    fn test_analyzer_chunks() {
        let a = EntropyAnalyzer::new(256);
        let data = vec![0u8; 512];
        let r = a.analyze(&data);
        assert_eq!(r.chunks.len(), 2);
        assert!(r.chunks.iter().all(|&h| h == 0.0));
    }

    #[test]
    fn test_analyzer_analyze_sections() {
        let data: Vec<u8> = (0u8..=255).collect();
        let a = EntropyAnalyzer::new(64);
        let sections = [(".text", 0, 128), (".data", 128, 128)];
        let r = a.analyze_sections(&data, &sections);
        assert_eq!(r.sections.len(), 2);
        assert_eq!(r.sections[0].name, ".text");
    }

    #[test]
    fn test_analyzer_max_chunk_entropy() {
        let a = EntropyAnalyzer::new(256);
        // First chunk: all zeros; second chunk: all distinct values
        let mut data = vec![0u8; 256];
        data.extend(0u8..=255u8);
        let r = a.analyze(&data);
        let max = r.max_chunk_entropy();
        assert!((max - 8.0).abs() < 1e-9, "max={max}");
    }

    #[test]
    fn test_analyzer_packed_sections() {
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let a = EntropyAnalyzer::new(256);
        let sections = [(".packed", 0, 256)];
        let r = a.analyze_sections(&data, &sections);
        let packed = r.packed_sections();
        assert_eq!(packed.len(), 1);
    }

    // ── EntropyError ──────────────────────────────────────────────────────

    #[test]
    fn test_entropy_error_empty_input() {
        let e = EntropyError::EmptyInput;
        assert_eq!(e.to_string(), "empty input");
    }

    #[test]
    fn test_entropy_error_invalid_chunk() {
        let e = EntropyError::InvalidChunk(0);
        assert!(e.to_string().contains('0'));
    }

    #[test]
    fn test_entropy_zero_chunk_size_produces_empty_chunks() {
        let a = EntropyAnalyzer::new(0);
        let r = a.analyze(&[1, 2, 3, 4]);
        assert!(r.chunks.is_empty());
    }

    // ── EntropyCategory ───────────────────────────────────────────────────

    #[test]
    fn test_category_empty() {
        assert_eq!(EntropyCategory::classify(0.5), EntropyCategory::Empty);
        assert_eq!(EntropyCategory::classify(0.0), EntropyCategory::Empty);
    }

    #[test]
    fn test_category_text() {
        assert_eq!(EntropyCategory::classify(1.0), EntropyCategory::Text);
        assert_eq!(EntropyCategory::classify(3.9), EntropyCategory::Text);
    }

    #[test]
    fn test_category_code() {
        assert_eq!(EntropyCategory::classify(4.0), EntropyCategory::Code);
        assert_eq!(EntropyCategory::classify(4.9), EntropyCategory::Code);
    }

    #[test]
    fn test_category_data() {
        assert_eq!(EntropyCategory::classify(5.0), EntropyCategory::Data);
        assert_eq!(EntropyCategory::classify(5.9), EntropyCategory::Data);
    }

    #[test]
    fn test_category_compressed() {
        assert_eq!(EntropyCategory::classify(6.0), EntropyCategory::Compressed);
        assert_eq!(EntropyCategory::classify(6.9), EntropyCategory::Compressed);
    }

    #[test]
    fn test_category_encrypted() {
        assert_eq!(EntropyCategory::classify(7.0), EntropyCategory::Encrypted);
        assert_eq!(EntropyCategory::classify(7.4), EntropyCategory::Encrypted);
    }

    #[test]
    fn test_category_random() {
        assert_eq!(EntropyCategory::classify(7.5), EntropyCategory::Random);
        assert_eq!(EntropyCategory::classify(8.0), EntropyCategory::Random);
    }

    #[test]
    fn test_category_display() {
        assert_eq!(EntropyCategory::Empty.to_string(), "Empty");
        assert_eq!(EntropyCategory::Random.to_string(), "Random");
    }

    // ── shannon_entropy_f32 ───────────────────────────────────────────────

    #[test]
    fn test_entropy_f32_empty_is_zero() {
        assert!((shannon_entropy_f32(&[]) - (0.0f32)).abs() < f32::EPSILON);
    }

    #[test]
    fn test_entropy_f32_all_zeros() {
        assert!((shannon_entropy_f32(&[0u8; 512]) - (0.0f32)).abs() < f32::EPSILON);
    }

    #[test]
    fn test_entropy_f32_uniform_is_eight() {
        let data: Vec<u8> = (0u8..=255).collect();
        let h = shannon_entropy_f32(&data);
        assert!((h - 8.0f32).abs() < 1e-5, "expected ~8.0, got {h}");
    }

    // ── EntropyBlock / analyze_blocks ─────────────────────────────────────

    #[test]
    fn test_entropy_block_from_slice_zeros() {
        let block = EntropyBlock::from_slice(0, &[0u8; 64]);
        assert!((block.entropy - (0.0)).abs() < f32::EPSILON);
        assert_eq!(block.category, EntropyCategory::Empty);
        assert_eq!(block.size, 64);
        assert_eq!(block.offset, 0);
    }

    #[test]
    fn test_analyze_blocks_empty_data() {
        assert!(analyze_blocks(&[], 256).is_empty());
    }

    #[test]
    fn test_analyze_blocks_zero_block_size() {
        assert!(analyze_blocks(&[1, 2, 3], 0).is_empty());
    }

    #[test]
    fn test_analyze_blocks_count() {
        let data = vec![0u8; 1024];
        let blocks = analyze_blocks(&data, 256);
        assert_eq!(blocks.len(), 4);
    }

    #[test]
    fn test_analyze_blocks_offsets() {
        let data = vec![0u8; 768];
        let blocks = analyze_blocks(&data, 256);
        assert_eq!(blocks[0].offset, 0);
        assert_eq!(blocks[1].offset, 256);
        assert_eq!(blocks[2].offset, 512);
    }

    #[test]
    fn test_analyze_blocks_partial_last_block() {
        let data = vec![0u8; 300];
        let blocks = analyze_blocks(&data, 256);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[1].size, 44);
    }

    // ── ByteHistogram ─────────────────────────────────────────────────────

    #[test]
    fn test_histogram_counts() {
        let data = vec![0u8, 1u8, 0u8];
        let h = ByteHistogram::new(&data);
        assert_eq!(h.count_of(0), 2);
        assert_eq!(h.count_of(1), 1);
        assert_eq!(h.total, 3);
    }

    #[test]
    fn test_histogram_chi_square_empty() {
        let h = ByteHistogram::new(&[]);
        assert!((h.chi_square_statistic() - (0.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn test_histogram_chi_square_uniform() {
        // Exact uniform distribution → chi-square should be ~0.
        let data: Vec<u8> = (0u8..=255).collect();
        let h = ByteHistogram::new(&data);
        let chi2 = h.chi_square_statistic();
        // Each count = 1, expected = 1 → diff = 0 → chi2 = 0
        assert!(chi2.abs() < 1e-9, "chi2={chi2}");
    }

    #[test]
    fn test_histogram_is_likely_random_uniform() {
        // A single perfectly uniform sample is NOT "random" by the chi-square
        // test because chi2 = 0, which is outside [200, 310].
        let data: Vec<u8> = (0u8..=255).collect();
        let h = ByteHistogram::new(&data);
        // chi2 == 0 → not in [200,310] → false
        assert!(!h.is_likely_random());
    }

    #[test]
    fn test_histogram_most_common_bytes() {
        let mut data = vec![0u8; 100];
        data.extend(vec![1u8; 50]);
        let h = ByteHistogram::new(&data);
        let top = h.most_common_bytes(2);
        assert_eq!(top[0].0, 0u8);
        assert_eq!(top[0].1, 100);
        assert_eq!(top[1].0, 1u8);
        assert_eq!(top[1].1, 50);
    }

    #[test]
    fn test_histogram_most_common_bytes_clamp() {
        let data: Vec<u8> = (0u8..=255).collect();
        let h = ByteHistogram::new(&data);
        // Asking for more than 256 should not panic.
        let top = h.most_common_bytes(1000);
        assert_eq!(top.len(), 256);
    }

    // ── HeatmapData ───────────────────────────────────────────────────────

    #[test]
    fn test_heatmap_color_rgb_ranges() {
        assert_eq!(HeatmapData::color_rgb(0.0), [0, 0, 128]);
        assert_eq!(HeatmapData::color_rgb(1.9), [0, 0, 128]);
        assert_eq!(HeatmapData::color_rgb(2.0), [0, 128, 255]);
        assert_eq!(HeatmapData::color_rgb(3.9), [0, 128, 255]);
        assert_eq!(HeatmapData::color_rgb(4.0), [0, 200, 0]);
        assert_eq!(HeatmapData::color_rgb(5.9), [0, 200, 0]);
        assert_eq!(HeatmapData::color_rgb(6.0), [255, 200, 0]);
        assert_eq!(HeatmapData::color_rgb(6.9), [255, 200, 0]);
        assert_eq!(HeatmapData::color_rgb(7.0), [200, 0, 0]);
        assert_eq!(HeatmapData::color_rgb(8.0), [200, 0, 0]);
    }

    #[test]
    fn test_heatmap_ascii_empty() {
        let hm = HeatmapData::from_blocks(vec![]);
        assert!(hm.to_ascii_heatmap(80).is_empty());
    }

    #[test]
    fn test_heatmap_ascii_zero_width() {
        let data = vec![0u8; 512];
        let hm = HeatmapData::from_data(&data, 64);
        assert!(hm.to_ascii_heatmap(0).is_empty());
    }

    #[test]
    fn test_heatmap_ascii_contains_border() {
        let data = vec![0u8; 512];
        let hm = HeatmapData::from_data(&data, 64);
        let art = hm.to_ascii_heatmap(40);
        assert!(art.contains('-'));
        assert!(art.contains('|'));
    }

    #[test]
    fn test_heatmap_to_rgb_colors_length() {
        let data = vec![0u8; 256];
        let hm = HeatmapData::from_data(&data, 64);
        let colors = hm.to_rgb_colors();
        assert_eq!(colors.len(), hm.blocks.len());
    }

    // ── PackingDetector ───────────────────────────────────────────────────

    #[test]
    fn test_packing_detector_empty_data() {
        let indicators = PackingDetector::detect_packing_indicators(&[]);
        // Too small for PE header, no UPX magic → empty
        assert!(indicators.is_empty());
    }

    #[test]
    fn test_packing_detector_upx_magic() {
        let mut data = vec![0u8; 512];
        // Inject UPX! magic bytes
        data[100..104].copy_from_slice(b"UPX!");
        let indicators = PackingDetector::detect_packing_indicators(&data);
        assert!(indicators.iter().any(|s| s.contains("UPX magic")));
    }

    // ── EntropyReport ─────────────────────────────────────────────────────

    #[test]
    fn test_entropy_report_zeros() {
        let data = vec![0u8; 2048];
        let report = EntropyReport::generate(&data);
        assert!((report.overall_entropy - (0.0f32)).abs() < f32::EPSILON);
        assert_eq!(report.category, EntropyCategory::Empty);
        assert!(!report.sections.is_empty());
    }

    #[test]
    fn test_entropy_report_uniform() {
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let report = EntropyReport::generate(&data);
        assert!((report.overall_entropy - 8.0).abs() < 0.01);
        assert_eq!(report.category, EntropyCategory::Random);
    }

    #[test]
    fn test_entropy_report_heatmap() {
        let data = vec![0u8; 1024];
        let report = EntropyReport::generate(&data);
        let hm = report.heatmap();
        assert_eq!(hm.blocks.len(), report.sections.len());
    }

    #[test]
    fn test_entropy_report_high_entropy_blocks() {
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let report = EntropyReport::generate(&data);
        let high = report.high_entropy_blocks(7.0);
        assert!(!high.is_empty());
    }

    #[test]
    fn test_entropy_report_summary_contains_fields() {
        let data = vec![0u8; 512];
        let report = EntropyReport::generate(&data);
        let s = report.summary();
        assert!(s.contains("EntropyReport"));
        assert!(s.contains("overall"));
    }

    #[test]
    fn test_entropy_report_display() {
        let data = vec![0u8; 512];
        let report = EntropyReport::generate(&data);
        let s = format!("{report}");
        assert!(s.contains("Overall entropy"));
        assert!(s.contains("Category"));
    }

    #[test]
    fn test_entropy_report_generate_with_block_size() {
        let data = vec![0u8; 1024];
        let report = EntropyReport::generate_with_block_size(&data, 128);
        assert_eq!(report.sections.len(), 8);
    }

    /// Build a minimal valid PE32+ with `n` import descriptors so we exercise
    /// the real import-walk path used by FIX F.
    fn make_pe_with_imports(n_imports: usize) -> Vec<u8> {
        // Layout:
        //   0x000: DOS header (e_lfanew @ 0x3c -> 0x80)
        //   0x080: PE\0\0 + COFF (24 bytes incl signature) + optional header (240) + 1 section
        //   0x200: .idata section raw data: n IMAGE_IMPORT_DESCRIPTORs (20 each) + null term + DLL names
        let mut buf = vec![0u8; 0x2000];
        buf[0..2].copy_from_slice(b"MZ");
        let e_lfanew = 0x80u32;
        buf[0x3c..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let pe = e_lfanew as usize;
        buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
        // Machine = AMD64 (0x8664)
        buf[pe + 4..pe + 6].copy_from_slice(&0x8664u16.to_le_bytes());
        // NumberOfSections = 1
        buf[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes());
        // SizeOfOptionalHeader = 240
        buf[pe + 20..pe + 22].copy_from_slice(&240u16.to_le_bytes());
        let opt = pe + 24;
        // Magic = PE32+
        buf[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        // Import directory at opt + 120 (PE32+): RVA + size
        // Choose section virt addr = 0x1000, raw_offset = 0x200.
        let section_va: u32 = 0x1000;
        let section_raw: u32 = 0x200;
        let import_rva = section_va; // descriptors start at section start
        buf[opt + 120..opt + 124].copy_from_slice(&import_rva.to_le_bytes());
        buf[opt + 124..opt + 128].copy_from_slice(&(((n_imports + 1) * 20) as u32).to_le_bytes());
        // Section table starts at opt + 240
        let sec = opt + 240;
        // Name ".idata\0\0"
        buf[sec..sec + 8].copy_from_slice(b".idata\0\0");
        // VirtualSize, VirtualAddress
        buf[sec + 8..sec + 12].copy_from_slice(&0x800u32.to_le_bytes());
        buf[sec + 12..sec + 16].copy_from_slice(&section_va.to_le_bytes());
        // SizeOfRawData, PointerToRawData
        buf[sec + 16..sec + 20].copy_from_slice(&0x800u32.to_le_bytes());
        buf[sec + 20..sec + 24].copy_from_slice(&section_raw.to_le_bytes());
        // Write n IMAGE_IMPORT_DESCRIPTORs at section raw offset, each with a non-zero NameRVA
        for i in 0..n_imports {
            let off = section_raw as usize + i * 20;
            // OriginalFirstThunk -> non-zero so terminator detection still works
            buf[off..off + 4].copy_from_slice(&((section_va + 0x400) as u32 + i as u32 * 4).to_le_bytes());
            // Name RVA -> point somewhere inside the section (content doesn't matter for counting)
            let name_rva: u32 = section_va + 0x200 + (i as u32) * 16;
            buf[off + 12..off + 16].copy_from_slice(&name_rva.to_le_bytes());
        }
        // null terminator descriptor is already zeroed
        buf
    }

    /// FIX F regression: a PE with many real import descriptors must NOT
    /// trigger the "Few imports (<5)" indicator. The old proxy counted ".dll"
    /// substrings and returned 0 here even though there are 20 imports.
    #[test]
    fn fix_f_many_imports_not_flagged_as_few() {
        let pe = make_pe_with_imports(20);
        let indicators = PackingDetector::detect_packing_indicators(&pe);
        assert!(
            !indicators.iter().any(|s| s.contains("Few imports")),
            "FIX F regression: got Few imports indicator on PE with 20 real \
             import descriptors: {indicators:?}"
        );
    }

    /// FIX F: with only 2 imports, the indicator SHOULD fire.
    #[test]
    fn fix_f_few_imports_is_flagged() {
        let pe = make_pe_with_imports(2);
        let indicators = PackingDetector::detect_packing_indicators(&pe);
        assert!(
            indicators.iter().any(|s| s.contains("Few imports")),
            "Expected Few imports indicator on PE with 2 imports: {indicators:?}"
        );
    }

    #[test]
    fn test_analyze_with_sections_basic_and_sorted() {
        let mut data = vec![0u8; 256];
        data.extend((0u8..=255).collect::<Vec<u8>>()); // high-entropy tail
        let secs = vec![
            SectionDescriptor { name: ".low".into(), raw_offset: 0, raw_size: 256 },
            SectionDescriptor { name: ".high".into(), raw_offset: 256, raw_size: 256 },
        ];
        let out = analyze_with_sections(&data, &secs);
        assert_eq!(out.len(), 3); // 2 sections + whole
        // Sorted desc by entropy.
        for w in out.windows(2) {
            assert!(w[0].entropy >= w[1].entropy);
        }
        // High section should be near 8.0.
        assert!(out[0].entropy > 7.9);
    }

    #[test]
    fn test_analyze_with_sections_out_of_range_is_clamped() {
        let data = vec![0u8; 64];
        let secs = vec![SectionDescriptor {
            name: ".oob".into(),
            raw_offset: 1000,
            raw_size: 100,
        }];
        let out = analyze_with_sections(&data, &secs);
        assert_eq!(out.len(), 2);
        // OOB section yields size 0, entropy 0.
        let oob = out.iter().find(|b| b.offset == 1000).unwrap();
        assert_eq!(oob.size, 0);
        assert_eq!(oob.entropy, 0.0);
    }

    /// FIX F path-loader: read a synthetic PE from disk and verify detection.
    #[test]
    fn fix_f_packing_indicators_from_path() {
        let pe = make_pe_with_imports(20);
        let path = std::env::temp_dir().join("rustre_triage_entropy_fixf.bin");
        std::fs::write(&path, &pe).unwrap();
        let indicators = PackingDetector::detect_packing_indicators_from_path(&path).unwrap();
        assert!(!indicators.iter().any(|s| s.contains("Few imports")));
        let _ = std::fs::remove_file(&path);
    }
}
