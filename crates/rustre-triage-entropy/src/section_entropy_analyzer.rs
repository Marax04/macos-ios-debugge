//! `section_entropy_analyzer` — per-section entropy analysis for PE/ELF/Mach-O.
//!
//! Provides [`SectionEntropyAnalyzer`], [`SectionEntropy`], and [`EntropyReport`]
//! that compute and summarise the Shannon entropy of each named section in a
//! binary, enabling triage decisions about packing, encryption, or obfuscation.

use std::fmt;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::{shannon_entropy, shannon_entropy_f32, EntropyCategory, EntropyRating, casts};

// ─── SectionEntropy ───────────────────────────────────────────────────────────

/// Entropy analysis result for a single named binary section.
use std::fmt::Write as _;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropy {
    /// Section name (e.g. `.text`, `.data`, `__TEXT`).
    pub name: String,
    /// Byte offset of the section's raw data within the file.
    pub file_offset: u64,
    /// Size of the section's raw data in bytes.
    pub raw_size: usize,
    /// Virtual address of the section.
    pub virtual_address: u64,
    /// Virtual size of the section.
    pub virtual_size: usize,
    /// Shannon entropy of the raw data (0.0 – 8.0).
    pub entropy: f64,
    /// Qualitative entropy rating.
    pub rating: EntropyRating,
    /// Semantic category inferred from entropy.
    pub category: EntropyCategory,
    /// Byte frequency distribution (256 buckets).
    pub byte_histogram: Vec<u32>,
    /// Whether the section has executable permissions.
    pub is_executable: bool,
    /// Whether the section has writable permissions.
    pub is_writable: bool,
}

impl SectionEntropy {
    /// Compute a [`SectionEntropy`] for `data` at the given parameters.
    #[must_use]
    pub fn compute(
        name: impl Into<String>,
        data: &[u8],
        file_offset: u64,
        virtual_address: u64,
        virtual_size: usize,
    ) -> Self {
        let entropy = shannon_entropy(data);
        let mut hist = vec![0u32; 256];
        for &b in data { hist[b as usize] += 1; }
        Self {
            name: name.into(),
            file_offset,
            raw_size: data.len(),
            virtual_address,
            virtual_size,
            entropy,
            rating: EntropyRating::from_entropy(entropy),
            category: EntropyCategory::classify(casts::f64_to_f32(entropy)),
            byte_histogram: hist,
            is_executable: false,
            is_writable: false,
        }
    }

    /// Set section permissions and return the modified value.
    #[must_use]
    pub const fn with_permissions(mut self, executable: bool, writable: bool) -> Self {
        self.is_executable = executable;
        self.is_writable = writable;
        self
    }

    /// Return `true` when this section is likely packed (entropy > 7.0).
    #[must_use]
    pub fn is_packed(&self) -> bool { self.entropy > 7.0 }

    /// Return `true` when this section is likely encrypted (entropy > 7.5).
    #[must_use]
    pub fn is_encrypted(&self) -> bool { self.entropy > 7.5 }

    /// Return the null-byte ratio — useful for detecting zero-padded sections.
    #[must_use]
    pub fn null_byte_ratio(&self) -> f64 {
        if self.raw_size == 0 { return 1.0; }
        f64::from(self.byte_histogram[0]) / casts::usize_to_f64(self.raw_size)
    }

    /// Compute the chi-square statistic for this section's byte distribution.
    #[must_use]
    pub fn chi_square(&self) -> f64 {
        if self.raw_size == 0 { return 0.0; }
        let expected = casts::usize_to_f64(self.raw_size) / 256.0;
        self.byte_histogram.iter().fold(0.0f64, |acc, &c| {
            let diff = f64::from(c) - expected;
            acc + (diff * diff) / expected
        })
    }

    /// Return the most frequent byte value.
    #[must_use]
    pub fn most_frequent_byte(&self) -> u8 {
        self.byte_histogram
            .iter()
            .enumerate()
            .max_by_key(|&(_, &c)| c)
            .map_or(0, |(b, _)| casts::usize_to_u8(b))
    }

    /// Brief one-line summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "{:>12}  off={:#010x}  size={:8}  entropy={:.3}  {}{}",
            self.name,
            self.file_offset,
            self.raw_size,
            self.entropy,
            if self.is_executable { "x" } else { "-" },
            if self.is_writable { "w" } else { "-" },
        )
    }
}

impl fmt::Display for SectionEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SectionEntropy {{ name: {}, entropy: {:.3}, rating: {}, packed: {} }}",
            self.name, self.entropy, self.rating, self.is_packed()
        )
    }
}

// ─── EntropyReport ────────────────────────────────────────────────────────────

/// Comprehensive entropy report combining per-section and whole-file analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyReport {
    /// Overall file Shannon entropy (0.0 – 8.0).
    pub overall_entropy: f64,
    /// Qualitative rating for the overall entropy.
    pub overall_rating: EntropyRating,
    /// Semantic category for the overall entropy.
    pub overall_category: EntropyCategory,
    /// Per-section entropy results.
    pub sections: Vec<SectionEntropy>,
    /// Total size of the analysed data.
    pub total_size: usize,
    /// Number of sections with entropy > 7.0.
    pub packed_section_count: usize,
    /// Whether any executable section has entropy > 7.0.
    pub likely_packed: bool,
    /// Human-readable triage notes.
    pub notes: Vec<String>,
}

impl EntropyReport {
    /// Build an [`EntropyReport`] from a completed list of [`SectionEntropy`]
    /// objects and the raw file data.
    #[must_use]
    pub fn from_sections(sections: Vec<SectionEntropy>, file_data: &[u8]) -> Self {
        let overall_entropy = shannon_entropy(file_data);
        let overall_rating = EntropyRating::from_entropy(overall_entropy);
        let overall_category = EntropyCategory::classify(casts::f64_to_f32(overall_entropy));
        let packed_section_count = sections.iter().filter(|s| s.is_packed()).count();
        let likely_packed = sections.iter().any(|s| s.is_executable && s.is_packed());
        let total_size = file_data.len();

        let mut notes = Vec::new();
        if likely_packed {
            notes.push("Executable section has entropy > 7.0 — likely packed.".to_string());
        }
        if overall_entropy > 7.5 {
            notes.push(format!("Overall entropy {overall_entropy:.3} is very high — possible encryption."));
        }
        for s in &sections {
            if s.null_byte_ratio() > 0.9 {
                notes.push(format!("Section '{}' is mostly null bytes ({:.0}%).", s.name, s.null_byte_ratio() * 100.0));
            }
        }

        Self {
            overall_entropy,
            overall_rating,
            overall_category,
            sections,
            total_size,
            packed_section_count,
            likely_packed,
            notes,
        }
    }

    /// Return all sections whose entropy exceeds `threshold`.
    #[must_use]
    pub fn high_entropy_sections(&self, threshold: f64) -> Vec<&SectionEntropy> {
        self.sections.iter().filter(|s| s.entropy > threshold).collect()
    }

    /// Return sections sorted by entropy descending.
    #[must_use]
    pub fn sections_by_entropy(&self) -> Vec<&SectionEntropy> {
        let mut v: Vec<&SectionEntropy> = self.sections.iter().collect();
        v.sort_by(|a, b| b.entropy.partial_cmp(&a.entropy).unwrap_or(std::cmp::Ordering::Equal));
        v
    }

    /// Return the section with the highest entropy, if any.
    #[must_use]
    pub fn hottest_section(&self) -> Option<&SectionEntropy> {
        self.sections.iter().max_by(|a, b| {
            a.entropy.partial_cmp(&b.entropy).unwrap_or(std::cmp::Ordering::Equal)
        })
    }

    /// Return a per-category breakdown: how many sections fall into each
    /// [`EntropyCategory`].
    #[must_use]
    pub fn category_breakdown(&self) -> HashMap<String, usize> {
        let mut map: HashMap<String, usize> = HashMap::new();
        for s in &self.sections {
            *map.entry(s.category.label().to_string()).or_insert(0) += 1;
        }
        map
    }

    /// Render the report as a concise ASCII table.
    #[must_use]
    pub fn to_table(&self) -> String {
        let mut out = String::new();
        out.push_str("=== Section Entropy Report ===\n");
        writeln!(out, "  File size   : {} bytes", self.total_size).unwrap();
        writeln!(out, "  Overall     : {:.3} ({})", self.overall_entropy, self.overall_rating).unwrap();
        writeln!(out, "  Likely packed: {}\n", self.likely_packed).unwrap();

        let header = format!(
            "{:>12}  {:>12}  {:>8}  {:>8}  {:>2}  Category\n",
            "Section", "Offset", "RawSz", "Entropy", "Fl"
        );
        out.push_str(&header);
        out.push_str(&"-".repeat(header.trim_end_matches('\n').len()));
        out.push('\n');

        for s in &self.sections {
            out.push_str(&s.summary());
            writeln!(out, "  {}", s.category).unwrap();
        }

        if !self.notes.is_empty() {
            out.push_str("\nNotes:\n");
            for note in &self.notes {
                writeln!(out, "  * {note}").unwrap();
            }
        }
        out
    }
}

impl fmt::Display for EntropyReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_table())
    }
}

// ─── SectionDataSpec ─────────────────────────────────────────────────────────

/// Parameters for [`SectionEntropyAnalyzer::add_section_data`].
pub struct SectionDataSpec<'a> {
    pub name: &'a str,
    pub data: &'a [u8],
    pub file_offset: u64,
    pub virtual_address: u64,
    pub virtual_size: usize,
    pub executable: bool,
    pub writable: bool,
}

// ─── SectionEntropyAnalyzer ───────────────────────────────────────────────────

/// Analyses binary sections by computing per-section Shannon entropy.
///
/// Feed it section descriptors via [`Self::add_section`] or
/// [`Self::analyze_pe_raw`], then call [`Self::report`] to produce an
/// [`EntropyReport`].
pub struct SectionEntropyAnalyzer {
    sections: Vec<SectionEntropy>,
    /// Block size used for intra-section chunked analysis.
    pub chunk_size: usize,
}

impl SectionEntropyAnalyzer {
    /// Create a new analyser with a 256-byte intra-section chunk size.
    #[must_use]
    pub const fn new() -> Self {
        Self { sections: Vec::new(), chunk_size: 256 }
    }

    /// Set the intra-section chunk size and return the modified analyser.
    #[must_use]
    pub const fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size;
        self
    }

    /// Add a pre-computed [`SectionEntropy`] record.
    pub fn add_section(&mut self, section: SectionEntropy) {
        self.sections.push(section);
    }

    /// Add a section by computing its entropy from `spec.data`.
    pub fn add_section_data(&mut self, spec: &SectionDataSpec<'_>) {
        let section = SectionEntropy::compute(
            spec.name, spec.data, spec.file_offset, spec.virtual_address, spec.virtual_size,
        ).with_permissions(spec.executable, spec.writable);
        self.sections.push(section);
    }

    /// Parse a raw PE file and add entropy records for each section.
    ///
    /// Returns the number of sections successfully parsed.
    pub fn analyze_pe_raw(&mut self, data: &[u8]) -> usize {
        let mut count = 0;
        if data.len() < 64 { return 0; }
        let e_lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
        // Guard: e_lfanew + 24 must not overflow and must be within the buffer.
        if e_lfanew > data.len().saturating_sub(24) { return 0; }
        if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" { return 0; }

        let num_sections = u16::from_le_bytes([data[e_lfanew + 6], data[e_lfanew + 7]]) as usize;
        let opt_size = u16::from_le_bytes([data[e_lfanew + 20], data[e_lfanew + 21]]) as usize;
        let table = e_lfanew + 24 + opt_size;

        for i in 0..num_sections {
            let entry = table + i * 40;
            if entry + 40 > data.len() { break; }

            let raw_name = &data[entry..entry + 8];
            let end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            let name = std::str::from_utf8(&raw_name[..end]).unwrap_or("??").to_string();

            let vsize = u32::from_le_bytes([data[entry + 8], data[entry + 9], data[entry + 10], data[entry + 11]]) as usize;
            let vaddr = u64::from(u32::from_le_bytes([data[entry + 12], data[entry + 13], data[entry + 14], data[entry + 15]]));
            let raw_size = u32::from_le_bytes([data[entry + 16], data[entry + 17], data[entry + 18], data[entry + 19]]) as usize;
            let raw_off = u32::from_le_bytes([data[entry + 20], data[entry + 21], data[entry + 22], data[entry + 23]]) as usize;
            let characteristics = u32::from_le_bytes([data[entry + 36], data[entry + 37], data[entry + 38], data[entry + 39]]);

            let is_executable = characteristics & 0x2000_0000 != 0;
            let is_writable   = characteristics & 0x8000_0000 != 0;

            // Use saturating_add to prevent usize overflow from adversarial raw_off/raw_size values.
            let end_off = raw_off.saturating_add(raw_size).min(data.len());
            let section_data = if raw_off < data.len() { &data[raw_off..end_off] } else { &[] };

            let section = SectionEntropy::compute(&name, section_data, raw_off as u64, vaddr, vsize)
                .with_permissions(is_executable, is_writable);
            self.sections.push(section);
            count += 1;
        }
        count
    }

    /// Produce the final [`EntropyReport`] from all added sections.
    ///
    /// `file_data` is used to compute the overall file entropy.
    #[must_use]
    pub fn report(&self, file_data: &[u8]) -> EntropyReport {
        EntropyReport::from_sections(self.sections.clone(), file_data)
    }

    /// Return a quick summary for each section as a `Vec<String>`.
    #[must_use]
    pub fn section_summaries(&self) -> Vec<String> {
        self.sections.iter().map(SectionEntropy::summary).collect()
    }

    /// Return all sections with entropy above `threshold`.
    #[must_use]
    pub fn suspicious_sections(&self, threshold: f64) -> Vec<&SectionEntropy> {
        self.sections.iter().filter(|s| s.entropy > threshold).collect()
    }

    /// Compute per-chunk entropy within `section_name` and return the chunk
    /// entropies.  Returns `None` if the section is not found.
    #[must_use]
    pub fn intra_section_chunks(&self, section_name: &str, file_data: &[u8]) -> Option<Vec<f32>> {
        let sec = self.sections.iter().find(|s| s.name == section_name)?;
        let off = casts::u64_to_usize(sec.file_offset);
        // Use saturating_add to prevent overflow with large file_offset or raw_size values.
        let end = off.saturating_add(sec.raw_size).min(file_data.len());
        if off >= file_data.len() { return Some(Vec::new()); }
        let section_data = &file_data[off..end];
        let chunks: Vec<f32> = section_data
            .chunks(self.chunk_size.max(1))
            .map(shannon_entropy_f32)
            .collect();
        Some(chunks)
    }

    /// Return the number of sections currently tracked.
    #[must_use]
    pub const fn section_count(&self) -> usize {
        self.sections.len()
    }

    /// Clear all sections and reset the analyser.
    pub fn reset(&mut self) {
        self.sections.clear();
    }
}

impl Default for SectionEntropyAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ─── SectionComparison ────────────────────────────────────────────────────────

/// Compare entropy profiles between two binaries section by section.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionComparison {
    /// Name of the section.
    pub name: String,
    /// Entropy in the first binary.
    pub entropy_a: f64,
    /// Entropy in the second binary.
    pub entropy_b: f64,
    /// Absolute difference.
    pub delta: f64,
}

impl SectionComparison {
    /// Compare two [`EntropyReport`]s section by section.
    #[must_use]
    pub fn compare(report_a: &EntropyReport, report_b: &EntropyReport) -> Vec<Self> {
        let map_a: HashMap<&str, f64> = report_a.sections.iter().map(|s| (s.name.as_str(), s.entropy)).collect();
        let map_b: HashMap<&str, f64> = report_b.sections.iter().map(|s| (s.name.as_str(), s.entropy)).collect();
        let mut names: Vec<&str> = map_a.keys().chain(map_b.keys()).copied().collect();
        names.sort_unstable();
        names.dedup();
        names.iter().map(|&name| {
            let ea = *map_a.get(name).unwrap_or(&0.0);
            let eb = *map_b.get(name).unwrap_or(&0.0);
            Self { name: name.to_string(), entropy_a: ea, entropy_b: eb, delta: (ea - eb).abs() }
        }).collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_analyzer_with_sections() -> (SectionEntropyAnalyzer, Vec<u8>) {
        let mut analyzer = SectionEntropyAnalyzer::new();
        let zeros = vec![0u8; 256];
        let uniform: Vec<u8> = (0u8..=255).cycle().take(256).collect();
        analyzer.add_section_data(&SectionDataSpec { name: ".bss", data: &zeros, file_offset: 0x200, virtual_address: 0x1000, virtual_size: 256, executable: false, writable: true });
        analyzer.add_section_data(&SectionDataSpec { name: ".text", data: &uniform, file_offset: 0x400, virtual_address: 0x2000, virtual_size: 256, executable: true, writable: false });
        // The synthetic file must honour the offsets the sections declare:
        // .bss sits at 0x200 and .text at 0x400. The previous body built a
        // 512-byte file (`zeros + uniform`), so .bss began at 0x200 == EOF and
        // `intra_section_chunks(".bss")` correctly returned an empty vector —
        // the fixture contradicted itself, not the code under test.
        let mut file_data = vec![0u8; 0x400];
        file_data[0x200..0x300].copy_from_slice(&zeros[..0x100]);
        file_data.extend_from_slice(&uniform);
        (analyzer, file_data)
    }

    #[test]
    fn section_entropy_compute_zeros() {
        let se = SectionEntropy::compute(".bss", &[0u8; 64], 0, 0x1000, 64);
        assert!((se.entropy - (0.0)).abs() < f64::EPSILON);
        assert!(se.null_byte_ratio() > 0.99);
    }

    #[test]
    fn section_entropy_compute_uniform() {
        let data: Vec<u8> = (0u8..=255).collect();
        let se = SectionEntropy::compute(".text", &data, 0x400, 0x1000, 256);
        assert!((se.entropy - 8.0).abs() < 1e-6);
        assert!(se.is_packed());
        assert!(se.is_encrypted());
    }

    #[test]
    fn section_entropy_chi_square_uniform() {
        let data: Vec<u8> = (0u8..=255).collect();
        let se = SectionEntropy::compute(".text", &data, 0, 0, 256);
        let chi2 = se.chi_square();
        // Perfect uniform → chi2 = 0
        assert!(chi2 < 1e-6);
    }

    #[test]
    fn section_entropy_most_frequent_byte() {
        let mut data = vec![0u8; 100];
        data.extend(vec![0xFFu8; 10]);
        let se = SectionEntropy::compute(".data", &data, 0, 0, 110);
        assert_eq!(se.most_frequent_byte(), 0);
    }

    #[test]
    fn analyzer_add_and_count() {
        let (analyzer, _) = make_analyzer_with_sections();
        assert_eq!(analyzer.section_count(), 2);
    }

    #[test]
    fn analyzer_suspicious_sections() {
        let (analyzer, _) = make_analyzer_with_sections();
        let suspicious = analyzer.suspicious_sections(7.0);
        assert_eq!(suspicious.len(), 1);
        assert_eq!(suspicious[0].name, ".text");
    }

    #[test]
    fn analyzer_report_likely_packed() {
        let (analyzer, file_data) = make_analyzer_with_sections();
        let report = analyzer.report(&file_data);
        assert!(report.likely_packed);
        assert_eq!(report.packed_section_count, 1);
    }

    #[test]
    fn analyzer_report_hot_section() {
        let (analyzer, file_data) = make_analyzer_with_sections();
        let report = analyzer.report(&file_data);
        let hot = report.hottest_section().unwrap();
        assert_eq!(hot.name, ".text");
    }

    #[test]
    fn analyzer_intra_section_chunks_zeros() {
        let (analyzer, file_data) = make_analyzer_with_sections();
        let chunks = analyzer.intra_section_chunks(".bss", &file_data).unwrap();
        assert!(!chunks.is_empty());
        assert!(chunks.iter().all(|&e| e == 0.0));
    }

    #[test]
    fn analyzer_section_summaries_count() {
        let (analyzer, _) = make_analyzer_with_sections();
        let sums = analyzer.section_summaries();
        assert_eq!(sums.len(), 2);
    }

    #[test]
    fn analyzer_reset() {
        let (mut analyzer, _) = make_analyzer_with_sections();
        analyzer.reset();
        assert_eq!(analyzer.section_count(), 0);
    }

    #[test]
    fn report_sections_by_entropy_order() {
        let (analyzer, file_data) = make_analyzer_with_sections();
        let report = analyzer.report(&file_data);
        let sorted = report.sections_by_entropy();
        assert!(sorted[0].entropy >= sorted[sorted.len() - 1].entropy);
    }

    #[test]
    fn report_high_entropy_sections() {
        let (analyzer, file_data) = make_analyzer_with_sections();
        let report = analyzer.report(&file_data);
        let high = report.high_entropy_sections(7.0);
        assert_eq!(high.len(), 1);
    }

    #[test]
    fn report_category_breakdown() {
        let (analyzer, file_data) = make_analyzer_with_sections();
        let report = analyzer.report(&file_data);
        let breakdown = report.category_breakdown();
        assert!(!breakdown.is_empty());
    }

    #[test]
    fn report_to_table_contains_sections() {
        let (analyzer, file_data) = make_analyzer_with_sections();
        let report = analyzer.report(&file_data);
        let table = report.to_table();
        assert!(table.contains(".text"));
        assert!(table.contains(".bss"));
    }

    #[test]
    fn section_comparison_delta() {
        let (analyzer, file_data) = make_analyzer_with_sections();
        let report_a = analyzer.report(&file_data);
        let mut analyzer_b = SectionEntropyAnalyzer::new();
        analyzer_b.add_section_data(&SectionDataSpec { name: ".text", data: &[0u8; 256], file_offset: 0, virtual_address: 0x2000, virtual_size: 256, executable: true, writable: false });
        let report_b = analyzer_b.report(&[0u8; 256]);
        let comparisons = SectionComparison::compare(&report_a, &report_b);
        let text_cmp = comparisons.iter().find(|c| c.name == ".text").unwrap();
        assert!(text_cmp.delta > 0.0);
    }

    #[test]
    fn section_entropy_display() {
        let se = SectionEntropy::compute(".data", &[0u8; 64], 0, 0, 64);
        let s = se.to_string();
        assert!(s.contains(".data"));
    }

    #[test]
    fn report_display() {
        let (analyzer, file_data) = make_analyzer_with_sections();
        let report = analyzer.report(&file_data);
        let s = format!("{report}");
        assert!(s.contains("Section Entropy Report"));
    }
}
