//! Full FLIRT `.sig` file generator for `rustre-flirt-gen`.
//!
//! Provides [`SigGenerator`] — an end-to-end pipeline that takes a collection
//! of [`FunctionSample`]s, extracts masked patterns, computes CRC-16s,
//! deduplicates, verifies, and emits a complete `.sig` v9 binary file.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;

use rustre_flirt::{
    FlirtArch, FlirtError, FlirtName, FlirtOs, FlirtPattern, PatternByte, ReferencedName,
    crc16_flirt,
};
pub use rustre_flirt::{FlirtLibrary, TailByte};

use crate::{GenError, PatternGenerator, RelocationEntry};

// ---------------------------------------------------------------------------
// FunctionSample
// ---------------------------------------------------------------------------

/// A sample of a function's bytes together with relocation info and xref names.
#[derive(Debug, Clone)]
pub struct FunctionSample {
    /// Raw function bytes.
    pub bytes: Vec<u8>,
    /// Human-readable function name.
    pub name: String,
    /// Library this function belongs to.
    pub lib_name: String,
    /// Relocation entries inside the function body.
    pub relocations: Vec<RelocationEntry>,
    /// Cross-references embedded in the function body (offset, `target_name`).
    pub xrefs: Vec<(u16, String)>,
}

impl FunctionSample {
    /// Create a sample with no relocations or xrefs.
    #[must_use]
    pub fn new(name: impl Into<String>, bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            name: name.into(),
            lib_name: String::new(),
            relocations: Vec::new(),
            xrefs: Vec::new(),
        }
    }

    /// Set the library name.
    #[must_use]
    pub fn with_lib(mut self, lib: impl Into<String>) -> Self {
        self.lib_name = lib.into();
        self
    }

    /// Add a relocation at the given offset (default size 4 bytes).
    #[must_use]
    pub fn with_reloc(mut self, offset: u16) -> Self {
        self.relocations.push(RelocationEntry { offset, size: 4 });
        self
    }

    /// Add a relocation with a specific byte size.
    #[must_use]
    pub fn with_reloc_sized(mut self, offset: u16, size: u8) -> Self {
        self.relocations.push(RelocationEntry { offset, size });
        self
    }

    /// Add a cross-reference name at the given offset.
    #[must_use]
    pub fn with_xref(mut self, offset: u16, name: impl Into<String>) -> Self {
        self.xrefs.push((offset, name.into()));
        self
    }
}

// ---------------------------------------------------------------------------
// PatternExtractor
// ---------------------------------------------------------------------------

/// Extracts FLIRT patterns from [`FunctionSample`]s.
///
/// Handles:
/// - Masking relocated bytes as wildcards.
/// - Optional variant detection: if the same function appears multiple times
///   with differing bytes at non-relocated positions, those positions are also
///   wildcarded.
pub struct PatternExtractor {
    generator: PatternGenerator,
    /// If `true`, collect multiple samples of the same name and compute a
    /// variant mask (bytes that differ across samples become wildcards).
    pub detect_variants: bool,
    /// Minimum pattern length to emit (shorter patterns are discarded).
    pub min_pattern_len: usize,
}

impl PatternExtractor {
    /// Create an extractor with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            generator: PatternGenerator::new(),
            detect_variants: true,
            min_pattern_len: 4,
        }
    }

    /// Extract a single pattern from a sample.
    ///
    /// # Errors
    /// Returns [`FlirtError::InvalidPattern`] if the sample is too short.
    pub fn extract_one(&self, sample: &FunctionSample) -> Result<FlirtPattern, FlirtError> {
        if sample.bytes.len() < self.min_pattern_len {
            return Err(FlirtError::InvalidPattern(format!(
                "sample '{}' too short: {} bytes (min {})",
                sample.name,
                sample.bytes.len(),
                self.min_pattern_len
            )));
        }
        let fname = FlirtName {
            name: sample.name.clone(),
            offset: 0,
            is_public: true,
            is_local: false,
        };
        let referenced: Vec<ReferencedName> = sample
            .xrefs
            .iter()
            .map(|(off, name)| ReferencedName {
                offset: *off,
                name: name.clone(),
            })
            .collect();

        let mut pat = self
            .generator
            .generate(&sample.bytes, &sample.relocations, vec![fname])?;
        pat.referenced_names = referenced;
        Ok(pat)
    }

    /// Extract patterns from a batch of samples, detecting variants if enabled.
    ///
    /// When `detect_variants` is `true`, multiple samples with the same name
    /// are merged: byte positions that differ across instances become wildcards.
    #[must_use]
    pub fn extract_batch(&self, samples: &[FunctionSample]) -> Vec<FlirtPattern> {
        if self.detect_variants {
            self.extract_with_variant_detection(samples)
        } else {
            samples
                .iter()
                .filter_map(|s| self.extract_one(s).ok())
                .collect()
        }
    }

    fn extract_with_variant_detection(&self, samples: &[FunctionSample]) -> Vec<FlirtPattern> {
        // Group by name.
        // Use BTreeMap instead of HashMap: function names are attacker-controlled
        // (parsed from library files) and hash-collision attacks would cause
        // O(n²) degradation in a HashMap keyed by untrusted strings.
        let mut groups: std::collections::BTreeMap<&str, Vec<&FunctionSample>> =
            std::collections::BTreeMap::new();
        for s in samples {
            groups.entry(s.name.as_str()).or_default().push(s);
        }

        let mut results = Vec::new();
        for group in groups.values() {
            if group.len() == 1 {
                if let Ok(p) = self.extract_one(group[0]) {
                    results.push(p);
                }
                continue;
            }

            // Compute variant mask.
            let first = &group[0].bytes;
            let max_len = group.iter().map(|s| s.bytes.len()).min().unwrap_or(0);
            let max_len = max_len.min(self.generator.initial_length);

            let mut initial_bytes: Vec<PatternByte> = (0..max_len)
                .map(|i| {
                    let first_byte = first.get(i).copied().unwrap_or(0);
                    let all_same = group
                        .iter()
                        .all(|s| s.bytes.get(i).copied().unwrap_or(0xFF) == first_byte);
                    if all_same {
                        PatternByte::Exact(first_byte)
                    } else {
                        PatternByte::Wildcard
                    }
                })
                .collect();

            // Also apply relocations from the first sample.
            for reloc in &group[0].relocations {
                let start = reloc.offset as usize;
                for item in initial_bytes
                    .iter_mut()
                    .skip(start)
                    .take(reloc.size as usize)
                {
                    *item = PatternByte::Wildcard;
                }
            }

            // CRC over the first sample.
            let crc_start = max_len;
            let crc_end = (crc_start + self.generator.crc_length).min(first.len());
            let (crc16, crc_len) = if crc_end > crc_start {
                (
                    crc16_flirt(&first[crc_start..crc_end]),
                    u8::try_from(crc_end - crc_start).unwrap_or(u8::MAX),
                )
            } else {
                (0, 0)
            };

            let fname = FlirtName {
                name: group[0].name.clone(),
                offset: 0,
                is_public: true,
                is_local: false,
            };

            let mut pat = FlirtPattern::new(initial_bytes);
            pat.crc16 = crc16;
            pat.crc_length = crc_len;
            pat.pattern_length = u16::try_from(first.len()).unwrap_or(u16::MAX);
            pat.names = vec![fname];
            results.push(pat);
        }
        results
    }
}

impl Default for PatternExtractor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CrcComputer
// ---------------------------------------------------------------------------

/// Utility for CRC-16 computation over function byte regions.
#[derive(Debug, Clone, Default)]
pub struct CrcComputer;

impl CrcComputer {
    /// Compute the FLIRT CRC-16 over `data[start..start+len]`.
    ///
    /// Returns `(crc16, actual_length)` — `actual_length` may be less than
    /// `len` if the slice runs past the end of `data`.
    #[must_use]
    pub fn compute(data: &[u8], start: usize, len: usize) -> (u16, u8) {
        let end = (start + len).min(data.len());
        if end <= start {
            return (0, 0);
        }
        let crc = crc16_flirt(&data[start..end]);
        let actual = u8::try_from(end - start).unwrap_or(u8::MAX);
        (crc, actual)
    }

    /// Compute the CRC-16 over the region of `data` that follows the
    /// initial pattern block (`initial_len` bytes), excluding masked offsets.
    #[must_use]
    pub fn compute_stable(
        data: &[u8],
        initial_len: usize,
        crc_len: usize,
        masked: &HashSet<usize>,
    ) -> (u16, u8) {
        let mut region: Vec<u8> = Vec::with_capacity(crc_len);
        for (off, &b) in data.iter().enumerate().skip(initial_len) {
            if region.len() >= crc_len {
                break;
            }
            if !masked.contains(&off) {
                region.push(b);
            }
        }
        if region.is_empty() {
            return (0, 0);
        }
        (
            crc16_flirt(&region),
            u8::try_from(region.len()).unwrap_or(u8::MAX),
        )
    }

    /// Verify the CRC-16 of a region in `data`.
    #[must_use]
    pub fn verify(data: &[u8], start: usize, len: usize, expected: u16) -> bool {
        let (actual, _) = Self::compute(data, start, len);
        actual == expected
    }
}

// ---------------------------------------------------------------------------
// SigOptimizer
// ---------------------------------------------------------------------------

/// Optimizes a set of patterns by removing duplicates and merging overlapping
/// variants into single wildcard-extended patterns.
#[derive(Debug)]
pub struct SigOptimizer {
    /// Whether to remove exact duplicates (same initial bytes + CRC + primary name).
    pub remove_duplicates: bool,
    /// Minimum exact bytes in the initial block to keep a pattern.
    pub min_exact_bytes: usize,
}

/// Delegates to [`SigOptimizer::new`].
///
/// BUG FIX: this used to be `#[derive(Default)]`, which set
/// `min_exact_bytes` to 0 while `new()` sets it to 4. A threshold of zero is
/// not a neutral default — it silently disables the check it guards.
impl Default for SigOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

impl SigOptimizer {
    /// Create an optimizer with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            remove_duplicates: true,
            min_exact_bytes: 4,
        }
    }

    /// Optimize a list of patterns in-place.
    #[must_use]
    pub fn optimize(&self, mut patterns: Vec<FlirtPattern>) -> Vec<FlirtPattern> {
        if self.remove_duplicates {
            patterns = Self::dedup(patterns);
        }
        if self.min_exact_bytes > 0 {
            patterns.retain(|p| Self::count_exact(p) >= self.min_exact_bytes);
        }
        patterns
    }

    fn dedup(patterns: Vec<FlirtPattern>) -> Vec<FlirtPattern> {
        let mut seen: HashSet<String> = HashSet::new();
        patterns
            .into_iter()
            .filter(|p| {
                let key = format!(
                    "{}:{}:{}",
                    p.pattern_hex(),
                    p.crc16,
                    p.primary_name().unwrap_or("")
                );
                seen.insert(key)
            })
            .collect()
    }

    fn count_exact(pat: &FlirtPattern) -> usize {
        pat.initial_bytes
            .iter()
            .filter(|b| matches!(b, PatternByte::Exact(_)))
            .count()
    }

    /// Return duplicate groups: patterns with identical initial bytes but
    /// different names.
    #[must_use]
    pub fn find_duplicates(patterns: &[FlirtPattern]) -> Vec<Vec<usize>> {
        let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, p) in patterns.iter().enumerate() {
            groups.entry(p.pattern_hex()).or_default().push(i);
        }
        groups.into_values().filter(|g| g.len() > 1).collect()
    }
}

// ---------------------------------------------------------------------------
// SigVerifier
// ---------------------------------------------------------------------------

/// Verifies generated patterns against their source samples.
#[derive(Debug, Default)]
pub struct SigVerifier;

impl SigVerifier {
    /// Verify that `pattern` matches `sample.bytes`.
    #[must_use]
    pub fn verify_pattern(pattern: &FlirtPattern, sample: &FunctionSample) -> bool {
        pattern.matches_all(&sample.bytes)
    }

    /// Verify a batch of patterns against their corresponding samples.
    ///
    /// Returns a list of `(pattern_index, sample_name)` pairs for failures.
    #[must_use]
    pub fn verify_batch(
        patterns: &[FlirtPattern],
        samples: &[FunctionSample],
    ) -> Vec<(usize, String)> {
        patterns
            .iter()
            .enumerate()
            .zip(samples.iter())
            .filter_map(|((idx, pat), samp)| {
                if Self::verify_pattern(pat, samp) {
                    None
                } else {
                    Some((idx, samp.name.clone()))
                }
            })
            .collect()
    }

    /// Check that all required fields of a pattern are within valid ranges.
    #[must_use]
    pub fn validate_fields(pattern: &FlirtPattern) -> Vec<String> {
        let mut errors = Vec::new();
        if pattern.initial_bytes.is_empty() {
            errors.push("initial_bytes is empty".to_string());
        }
        if pattern.names.is_empty() {
            errors.push("no names".to_string());
        }
        if pattern.pattern_length == 0 {
            errors.push("pattern_length is zero".to_string());
        }
        if pattern.crc_length > 0 && pattern.crc16 == 0 {
            errors.push("crc_length > 0 but crc16 == 0 (suspicious)".to_string());
        }
        errors
    }
}

// ---------------------------------------------------------------------------
// SigFile
// ---------------------------------------------------------------------------

/// In-memory representation of a complete `.sig` file.
///
/// Can be written to disk using [`SigFile::write`].
#[derive(Debug, Clone)]
pub struct SigFile {
    /// Library name embedded in the header.
    pub library_name: String,
    /// CPU architecture.
    pub arch: FlirtArch,
    /// All patterns.
    pub patterns: Vec<FlirtPattern>,
    /// Format version (9 is default).
    pub version: u8,
}

impl SigFile {
    /// Create an empty sig file for the given library.
    #[must_use]
    pub fn new(library_name: impl Into<String>, arch: FlirtArch) -> Self {
        Self {
            library_name: library_name.into(),
            arch,
            patterns: Vec::new(),
            version: 9,
        }
    }

    /// Add a pattern.
    pub fn add_pattern(&mut self, pat: FlirtPattern) {
        self.patterns.push(pat);
    }

    /// Number of patterns.
    #[must_use]
    pub const fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Write this sig file to `path` using the built-in v9 writer.
    ///
    /// # Errors
    /// Returns [`GenError::Serialize`] on I/O failures.
    pub fn write(&self, path: &Path) -> Result<(), GenError> {
        crate::write_sig_file(&self.patterns, &self.library_name, self.arch.to_u8(), path)
    }

    /// Serialize to bytes without writing to disk.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let writer = crate::SigWriter {
            arch: self.arch.to_u8(),
            ..crate::SigWriter::default()
        };
        writer.build(&self.patterns, &self.library_name)
    }
}

impl fmt::Display for SigFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SigFile({}, arch={:?}, {} patterns)",
            self.library_name,
            self.arch,
            self.patterns.len()
        )
    }
}

// ---------------------------------------------------------------------------
// SigGenerator
// ---------------------------------------------------------------------------

/// End-to-end `.sig` file generator.
///
/// # Pipeline
/// 1. Accept [`FunctionSample`]s.
/// 2. Extract patterns via [`PatternExtractor`].
/// 3. Optimize via [`SigOptimizer`].
/// 4. Verify via [`SigVerifier`].
/// 5. Produce a [`SigFile`] ready for writing.
pub struct SigGenerator {
    extractor: PatternExtractor,
    optimizer: SigOptimizer,
    /// Library name to embed in the sig file.
    pub library_name: String,
    /// Target architecture.
    pub arch: FlirtArch,
    /// Operating system (for textual metadata only).
    pub os: FlirtOs,
    /// Whether to run [`SigVerifier`] after extraction.
    pub verify: bool,
}

impl SigGenerator {
    /// Create a generator for the given library.
    #[must_use]
    pub fn new(library_name: impl Into<String>, arch: FlirtArch, os: FlirtOs) -> Self {
        Self {
            extractor: PatternExtractor::new(),
            optimizer: SigOptimizer::new(),
            library_name: library_name.into(),
            arch,
            os,
            verify: true,
        }
    }

    /// Set the initial pattern length.
    pub const fn set_initial_length(&mut self, len: usize) {
        self.extractor.generator.initial_length = len;
    }

    /// Set the CRC region length.
    pub const fn set_crc_length(&mut self, len: usize) {
        self.extractor.generator.crc_length = len;
    }

    /// Disable variant detection.
    pub const fn disable_variant_detection(&mut self) {
        self.extractor.detect_variants = false;
    }

    /// Disable post-extraction verification.
    pub const fn disable_verification(&mut self) {
        self.verify = false;
    }

    /// Generate a [`SigFile`] from a batch of [`FunctionSample`]s.
    ///
    /// # Errors
    /// Returns [`GenError::InvalidPattern`] if verification fails on any pattern.
    pub fn generate(&self, samples: &[FunctionSample]) -> Result<SigFile, GenError> {
        // Step 1: Extract patterns.
        let raw_patterns = self.extractor.extract_batch(samples);

        // Step 2: Optimize.
        let optimized = self.optimizer.optimize(raw_patterns);

        // Step 3: Verify (if enabled).
        if self.verify && optimized.len() == samples.len() {
            let failures = SigVerifier::verify_batch(&optimized, samples);
            if !failures.is_empty() {
                let names: Vec<String> = failures.into_iter().map(|(_, n)| n).collect();
                return Err(GenError::InvalidPattern(format!(
                    "pattern verification failed for: {}",
                    names.join(", ")
                )));
            }
        }

        // Step 4: Build SigFile.
        let mut sig = SigFile::new(self.library_name.clone(), self.arch);
        sig.patterns.reserve(optimized.len());
        for pat in optimized {
            sig.add_pattern(pat);
        }
        Ok(sig)
    }

    /// Generate statistics without producing a sig file.
    #[must_use]
    pub fn analyze(&self, samples: &[FunctionSample]) -> SigGenStats {
        let patterns = self.extractor.extract_batch(samples);
        let dup_groups = SigOptimizer::find_duplicates(&patterns);

        SigGenStats {
            input_samples: samples.len(),
            extracted_patterns: patterns.len(),
            duplicate_groups: dup_groups.len(),
            total_duplicates: dup_groups
                .iter()
                .map(std::vec::Vec::len)
                .sum::<usize>()
                .saturating_sub(dup_groups.len()),
            avg_initial_len: if patterns.is_empty() {
                0.0
            } else {
                patterns
                    .iter()
                    .map(|p| f64::from(u32::try_from(p.initial_bytes.len()).unwrap_or(u32::MAX)))
                    .sum::<f64>()
                    / f64::from(u32::try_from(patterns.len()).unwrap_or(u32::MAX))
            },
            avg_wildcard_ratio: if patterns.is_empty() {
                0.0
            } else {
                patterns
                    .iter()
                    .map(|p| f64::from(p.wildcard_ratio()))
                    .sum::<f64>()
                    / f64::from(u32::try_from(patterns.len()).unwrap_or(u32::MAX))
            },
            crc_covered: patterns.iter().filter(|p| p.crc_length > 0).count(),
        }
    }
}

/// Statistics from a sig generation run.
#[derive(Debug, Clone)]
pub struct SigGenStats {
    pub input_samples: usize,
    pub extracted_patterns: usize,
    pub duplicate_groups: usize,
    pub total_duplicates: usize,
    pub avg_initial_len: f64,
    pub avg_wildcard_ratio: f64,
    pub crc_covered: usize,
}

impl fmt::Display for SigGenStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SigGenStats: {} samples → {} patterns, dups={}, crc_covered={}, avg_wc={:.2}%",
            self.input_samples,
            self.extracted_patterns,
            self.total_duplicates,
            self.crc_covered,
            self.avg_wildcard_ratio * 100.0,
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_flirt::{FlirtArch, FlirtOs};

    fn make_sample(name: &str, bytes: &[u8]) -> FunctionSample {
        FunctionSample::new(name, bytes.to_vec())
    }

    fn make_generator() -> SigGenerator {
        SigGenerator::new("testlib", FlirtArch::X64, FlirtOs::Linux)
    }

    // ── FunctionSample ───────────────────────────────────────────────────

    #[test]
    fn function_sample_new() {
        let s = FunctionSample::new("main", vec![0x55, 0x48, 0x89, 0xE5]);
        assert_eq!(s.name, "main");
        assert_eq!(s.bytes.len(), 4);
    }

    #[test]
    fn function_sample_with_lib() {
        let s = FunctionSample::new("f", vec![]).with_lib("libc");
        assert_eq!(s.lib_name, "libc");
    }

    #[test]
    fn function_sample_with_reloc() {
        let s = FunctionSample::new("f", vec![0; 8]).with_reloc(4);
        assert_eq!(s.relocations.len(), 1);
        assert_eq!(s.relocations[0].offset, 4);
        assert_eq!(s.relocations[0].size, 4);
    }

    #[test]
    fn function_sample_with_reloc_sized() {
        let s = FunctionSample::new("f", vec![0; 8]).with_reloc_sized(2, 8);
        assert_eq!(s.relocations[0].size, 8);
    }

    #[test]
    fn function_sample_with_xref() {
        let s = FunctionSample::new("f", vec![]).with_xref(10, "callee");
        assert_eq!(s.xrefs.len(), 1);
        assert_eq!(s.xrefs[0].1, "callee");
    }

    // ── PatternExtractor ─────────────────────────────────────────────────

    #[test]
    fn extractor_extract_one_basic() {
        let e = PatternExtractor::new();
        let s = make_sample("foo", &[0x55, 0x48, 0x89, 0xE5, 0xC3]);
        let p = e.extract_one(&s).unwrap();
        assert_eq!(p.primary_name(), Some("foo"));
    }

    #[test]
    fn extractor_extract_one_too_short() {
        let e = PatternExtractor::new();
        let s = make_sample("f", &[0x55]);
        assert!(e.extract_one(&s).is_err());
    }

    #[test]
    fn extractor_extract_one_with_reloc() {
        let e = PatternExtractor::new();
        let s = FunctionSample::new("f", vec![0x55, 0x48, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3])
            .with_reloc(3);
        let p = e.extract_one(&s).unwrap();
        assert_eq!(p.initial_bytes[3], PatternByte::Wildcard);
    }

    #[test]
    fn extractor_extract_batch_no_variants() {
        let mut e = PatternExtractor::new();
        e.detect_variants = false;
        let samples = vec![
            make_sample("a", &[0x55, 0x48, 0x89, 0xE5]),
            make_sample("b", &[0x56, 0x48, 0x89, 0xE5]),
        ];
        let pats = e.extract_batch(&samples);
        assert_eq!(pats.len(), 2);
    }

    #[test]
    fn extractor_variant_detection_wildcards_differing_bytes() {
        let e = PatternExtractor::new();
        let samples = vec![
            FunctionSample::new("fn", vec![0x55, 0x48, 0x89, 0xE5, 0x01]),
            FunctionSample::new("fn", vec![0x55, 0x48, 0x89, 0xE5, 0x02]), // last byte differs
        ];
        let pats = e.extract_batch(&samples);
        assert_eq!(pats.len(), 1);
        // The differing byte at index 4 should be wildcarded.
        assert_eq!(pats[0].initial_bytes[4], PatternByte::Wildcard);
    }

    // ── CrcComputer ──────────────────────────────────────────────────────

    #[test]
    fn crc_computer_compute_basic() {
        let data = b"123456789";
        let (crc, len) = CrcComputer::compute(data, 0, 9);
        assert_eq!(crc, crc16_flirt(data));
        assert_eq!(len, 9);
    }

    #[test]
    fn crc_computer_compute_past_end() {
        let data = b"abc";
        let (_, len) = CrcComputer::compute(data, 0, 100);
        assert_eq!(len, 3);
    }

    #[test]
    fn crc_computer_verify_pass() {
        let data = b"test";
        let expected = crc16_flirt(data);
        assert!(CrcComputer::verify(data, 0, 4, expected));
    }

    #[test]
    fn crc_computer_verify_fail() {
        let data = b"test";
        assert!(!CrcComputer::verify(data, 0, 4, 0xDEAD));
    }

    #[test]
    fn crc_computer_stable() {
        let data = vec![0x55u8, 0x48, 0x89, 0xE5, 0xAA, 0xBB, 0xCC];
        let masked: HashSet<usize> = HashSet::new();
        let (crc, len) = CrcComputer::compute_stable(&data, 4, 3, &masked);
        assert_eq!(len, 3);
        assert_eq!(crc, crc16_flirt(&[0xAA, 0xBB, 0xCC]));
    }

    // ── SigOptimizer ─────────────────────────────────────────────────────

    #[test]
    fn optimizer_remove_duplicates() {
        let e = PatternExtractor::new();
        let s = make_sample("dup_fn", &[0x55, 0x48, 0x89, 0xE5, 0xC3]);
        let p1 = e.extract_one(&s).unwrap();
        let p2 = p1.clone();
        let opt = SigOptimizer::new();
        let result = opt.optimize(vec![p1, p2]);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn optimizer_min_exact_bytes_filter() {
        let opt = SigOptimizer {
            remove_duplicates: false,
            min_exact_bytes: 10,
        };
        // All wildcards: should be filtered out.
        let mut p = FlirtPattern::new(vec![PatternByte::Wildcard; 6]);
        p.names.push(FlirtName {
            name: "f".to_string(),
            offset: 0,
            is_public: true,
            is_local: false,
        });
        p.pattern_length = 6;
        let result = opt.optimize(vec![p]);
        assert!(result.is_empty());
    }

    #[test]
    fn optimizer_find_duplicates() {
        let e = PatternExtractor::new();
        let s = make_sample("f", &[0x55, 0x48, 0x89, 0xE5]);
        let p1 = e.extract_one(&s).unwrap();
        let p2 = p1.clone();
        let groups = SigOptimizer::find_duplicates(&[p1, p2]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].len(), 2);
    }

    // ── SigVerifier ──────────────────────────────────────────────────────

    #[test]
    fn verifier_verify_pattern_pass() {
        let e = PatternExtractor::new();
        let s = make_sample("f", &[0x55, 0x48, 0x89, 0xE5, 0xC3]);
        let p = e.extract_one(&s).unwrap();
        assert!(SigVerifier::verify_pattern(&p, &s));
    }

    #[test]
    fn verifier_validate_fields_empty() {
        let p = FlirtPattern::new(vec![]);
        let errors = SigVerifier::validate_fields(&p);
        assert!(errors.iter().any(|e| e.contains("empty")));
    }

    #[test]
    fn verifier_validate_fields_no_names() {
        let p = FlirtPattern::new(vec![PatternByte::Exact(0x55)]);
        let errors = SigVerifier::validate_fields(&p);
        assert!(errors.iter().any(|e| e.contains("names")));
    }

    // ── SigFile ──────────────────────────────────────────────────────────

    #[test]
    fn sig_file_new() {
        let sf = SigFile::new("mylib", FlirtArch::X64);
        assert_eq!(sf.library_name, "mylib");
        assert_eq!(sf.pattern_count(), 0);
    }

    #[test]
    fn sig_file_to_bytes_magic() {
        let sf = SigFile::new("lib", FlirtArch::X64);
        let bytes = sf.to_bytes();
        assert_eq!(&bytes[..6], b"IDASGN");
    }

    #[test]
    fn sig_file_display() {
        let sf = SigFile::new("mylib", FlirtArch::X86);
        let s = sf.to_string();
        assert!(s.contains("mylib"));
        assert!(s.contains("0 patterns"));
    }

    #[test]
    fn sig_file_write_creates_file() {
        let sf = SigFile::new("lib", FlirtArch::X64);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sig");
        sf.write(&path).unwrap();
        assert!(path.exists());
        let data = std::fs::read(&path).unwrap();
        assert_eq!(&data[..6], b"IDASGN");
    }

    // ── SigGenerator ─────────────────────────────────────────────────────

    #[test]
    fn sig_generator_empty_samples() {
        let g = make_generator();
        let sig = g.generate(&[]).unwrap();
        assert_eq!(sig.pattern_count(), 0);
    }

    #[test]
    fn sig_generator_single_sample() {
        let g = make_generator();
        let samples = vec![make_sample("main", &[0x55, 0x48, 0x89, 0xE5, 0xC3])];
        let sig = g.generate(&samples).unwrap();
        assert!(sig.pattern_count() <= 1);
    }

    #[test]
    fn sig_generator_analyze() {
        let g = make_generator();
        let samples = vec![
            make_sample("a", &[0x55, 0x48, 0x89, 0xE5]),
            make_sample("b", &[0x56, 0x48, 0x89, 0xE5]),
        ];
        let stats = g.analyze(&samples);
        assert_eq!(stats.input_samples, 2);
        assert!(stats.extracted_patterns <= 2);
    }

    #[test]
    fn sig_gen_stats_display() {
        let stats = SigGenStats {
            input_samples: 10,
            extracted_patterns: 8,
            duplicate_groups: 1,
            total_duplicates: 2,
            avg_initial_len: 16.0,
            avg_wildcard_ratio: 0.2,
            crc_covered: 7,
        };
        let s = stats.to_string();
        assert!(s.contains("10 samples"));
        assert!(s.contains("8 patterns"));
    }

    #[test]
    fn sig_generator_set_initial_length() {
        let mut g = make_generator();
        g.set_initial_length(16);
        assert_eq!(g.extractor.generator.initial_length, 16);
    }

    #[test]
    fn sig_generator_set_crc_length() {
        let mut g = make_generator();
        g.set_crc_length(8);
        assert_eq!(g.extractor.generator.crc_length, 8);
    }

    #[test]
    fn sig_generator_disable_variant_detection() {
        let mut g = make_generator();
        g.disable_variant_detection();
        assert!(!g.extractor.detect_variants);
    }

    #[test]
    fn sig_generator_disable_verification() {
        let mut g = make_generator();
        g.disable_verification();
        assert!(!g.verify);
    }

    #[test]
    fn sig_generator_with_xrefs() {
        let g = make_generator();
        let samples = vec![
            FunctionSample::new(
                "fn_with_call",
                vec![0x55u8, 0x48, 0x89, 0xE5, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3],
            )
            .with_reloc(5)
            .with_xref(5, "callee"),
        ];
        let sig = g.generate(&samples).unwrap();
        assert!(sig.pattern_count() <= 1);
    }
}
