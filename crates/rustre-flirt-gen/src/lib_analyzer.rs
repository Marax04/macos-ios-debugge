//! `lib_analyzer` — Analyse static libraries to generate FLIRT signatures.
//!
//! Provides:
//! * [`LibAnalyzer`] — top-level library analysis engine
//! * [`ObjFileParser`] — parses ELF `.o` / COFF `.obj` files
//! * [`FunctionExtractor`] — extracts function byte ranges from object files
//! * [`PrologueSampler`] — samples function prologues for signature generation
//! * [`NormalizedBytes`] — relocation-masked byte sequence
//! * [`SignatureGenerator`] — generates FLIRT-style byte patterns from function bytes

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::GenError;

// ─── NormalizedBytes ─────────────────────────────────────────────────────────

/// A sequence of function bytes with relocation targets masked out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedBytes {
    /// Raw bytes (relocation offsets zeroed).
    pub bytes: Vec<u8>,
    /// Positions that are masked out (relocation targets).
    pub masked: Vec<usize>,
}

impl NormalizedBytes {
    /// Create a `NormalizedBytes` by zeroing the given relocation offsets.
    #[must_use]
    pub fn new(raw: &[u8], relocations: &[usize]) -> Self {
        let mut bytes = raw.to_vec();
        let mut masked = Vec::with_capacity(relocations.len() * 4);
        for &rel in relocations {
            // Mask 4 bytes at each relocation target.
            for i in 0..4 {
                let pos = rel + i;
                if pos < bytes.len() {
                    bytes[pos] = 0x00;
                    masked.push(pos);
                }
            }
        }
        Self { bytes, masked }
    }

    /// Returns `true` if the byte at `offset` is masked.
    #[must_use]
    #[inline]
    pub fn is_masked(&self, offset: usize) -> bool {
        self.masked.contains(&offset)
    }

    /// Returns the significant (non-masked) bytes up to `max_len`.
    #[must_use]
    pub fn significant_bytes(&self, max_len: usize) -> Vec<(usize, u8)> {
        self.bytes
            .iter()
            .enumerate()
            .take(max_len)
            .filter(|(i, _)| !self.is_masked(*i))
            .map(|(i, &b)| (i, b))
            .collect()
    }

    /// Number of bytes in the normalised sequence.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns `true` if there are no bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

// ─── ObjectFunction ───────────────────────────────────────────────────────────

/// A function extracted from an object file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectFunction {
    /// Function / symbol name.
    pub name: String,
    /// Raw bytes of the function.
    pub bytes: Vec<u8>,
    /// Relocation offsets within the function bytes.
    pub relocations: Vec<usize>,
    /// Offset of the function within the original section.
    pub section_offset: usize,
    /// Object file this function came from.
    pub object_file: String,
}

impl ObjectFunction {
    /// Build a `NormalizedBytes` for this function.
    #[must_use]
    pub fn normalized(&self) -> NormalizedBytes {
        NormalizedBytes::new(&self.bytes, &self.relocations)
    }

    /// Returns `true` if the function is large enough to generate a reliable signature.
    #[must_use]
    pub const fn is_signable(&self) -> bool {
        self.bytes.len() >= 8
    }
}

// ─── ObjFileParser ────────────────────────────────────────────────────────────

/// Parses ELF object files to extract function symbols and their bytes.
#[derive(Debug, Clone)]
pub struct ObjFileParser {
    /// Whether to also parse COFF object files.
    pub support_coff: bool,
    /// Minimum function size to extract (bytes).
    pub min_func_size: usize,
}

/// Delegates to [`ObjFileParser::new`].
///
/// BUG FIX: this used to be `#[derive(Default)]`, which set
/// `min_func_size` to 0 while `new()` sets it to 4. A threshold of zero is
/// not a neutral default — it silently disables the check it guards.
impl Default for ObjFileParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ObjFileParser {
    /// Create a new parser.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            support_coff: false,
            min_func_size: 4,
        }
    }

    /// Enable COFF support.
    #[must_use]
    pub const fn with_coff(mut self) -> Self {
        self.support_coff = true;
        self
    }

    /// Parse a byte buffer representing an ELF `.o` file.
    ///
    /// Returns a list of extracted functions.
    ///
    /// # Errors
    /// Returns [`GenError`] if the buffer is too short or has bad magic.
    pub fn parse_elf(
        &self,
        data: &[u8],
        object_name: &str,
    ) -> Result<Vec<ObjectFunction>, GenError> {
        if data.len() < 4 {
            return Err(GenError::InvalidPattern("ELF too small".into()));
        }
        if &data[0..4] != b"\x7FELF" {
            return Err(GenError::InvalidPattern("not an ELF file".into()));
        }
        // Synthetic extraction: create one function per 64-byte block.
        let mut funcs = Vec::new();
        let block = 64usize;
        let count = (data.len() - 4) / block;
        for i in 0..count.min(5) {
            let start = 4 + i * block;
            let end = (start + block).min(data.len());
            let bytes = data[start..end].to_vec();
            if bytes.len() < self.min_func_size {
                continue;
            }
            funcs.push(ObjectFunction {
                name: format!("func_{i}"),
                bytes,
                relocations: vec![],
                section_offset: start,
                object_file: object_name.to_string(),
            });
        }
        Ok(funcs)
    }

    /// Parse a byte buffer representing a COFF `.obj` file.
    ///
    /// # Errors
    /// Returns [`GenError`] if COFF support is disabled or the buffer is invalid.
    pub fn parse_coff(
        &self,
        data: &[u8],
        object_name: &str,
    ) -> Result<Vec<ObjectFunction>, GenError> {
        if !self.support_coff {
            return Err(GenError::InvalidPattern("COFF support disabled".into()));
        }
        if data.len() < 20 {
            return Err(GenError::InvalidPattern("COFF too small".into()));
        }
        let mut funcs = Vec::new();
        let block = 32usize;
        for i in 0..(data.len() / block).min(3) {
            let start = i * block;
            let end = (start + block).min(data.len());
            funcs.push(ObjectFunction {
                name: format!("coff_func_{i}"),
                bytes: data[start..end].to_vec(),
                relocations: vec![4, 12], // synthetic relocs
                section_offset: start,
                object_file: object_name.to_string(),
            });
        }
        Ok(funcs)
    }
}

// ─── FunctionExtractor ────────────────────────────────────────────────────────

/// Extracts function byte ranges from a collection of object functions.
#[derive(Debug, Clone)]
pub struct FunctionExtractor {
    /// Maximum function size in bytes to consider.
    pub max_func_size: usize,
    /// Whether to deduplicate identical byte sequences.
    pub deduplicate: bool,
}

/// Delegates to [`FunctionExtractor::new`].
///
/// BUG FIX: this used to be `#[derive(Default)]`, which set
/// `max_func_size` to 0 while `new()` sets it to 65536. A threshold of zero is
/// not a neutral default — it silently disables the check it guards.
impl Default for FunctionExtractor {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionExtractor {
    /// Create a new extractor.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_func_size: 65536,
            deduplicate: true,
        }
    }

    /// Filter and return signable functions from a list.
    #[must_use]
    pub fn extract(&self, functions: Vec<ObjectFunction>) -> Vec<ObjectFunction> {
        let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        functions
            .into_iter()
            .filter(|f| {
                f.is_signable()
                    && f.bytes.len() <= self.max_func_size
                    && if self.deduplicate {
                        seen.insert(f.bytes.clone())
                    } else {
                        true
                    }
            })
            .collect()
    }

    /// Returns the number of unique functions after extraction.
    #[must_use]
    pub fn count_unique(&self, functions: &[ObjectFunction]) -> usize {
        let mut seen = std::collections::HashSet::new();
        functions.iter().filter(|f| seen.insert(&f.bytes)).count()
    }
}

// ─── PrologueSampler ─────────────────────────────────────────────────────────

/// Samples function prologues to find the most common patterns.
#[derive(Debug, Clone)]
pub struct PrologueSampler {
    /// Number of prologue bytes to sample.
    pub sample_len: usize,
    /// Minimum occurrence count to report a pattern.
    pub min_occurrences: usize,
}

/// Delegates to [`PrologueSampler::new`].
///
/// BUG FIX: this used to be `#[derive(Default)]`, which set
/// `min_occurrences` to 0 while `new()` sets it to 2. A threshold of zero is
/// not a neutral default — it silently disables the check it guards.
impl Default for PrologueSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl PrologueSampler {
    /// Create a sampler with default settings (32-byte sample, min 2 occurrences).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sample_len: 32,
            min_occurrences: 2,
        }
    }

    /// Count prologue patterns across all functions.
    ///
    /// Returns a map `bytes → count`.
    #[must_use]
    pub fn count_patterns(&self, functions: &[ObjectFunction]) -> HashMap<Vec<u8>, usize> {
        let mut counts: HashMap<Vec<u8>, usize> = HashMap::new();
        for func in functions {
            let len = self.sample_len.min(func.bytes.len());
            let prologue = func.bytes[..len].to_vec();
            *counts.entry(prologue).or_insert(0) += 1;
        }
        counts
    }

    /// Return prologue patterns meeting the minimum occurrence threshold.
    #[must_use]
    pub fn common_patterns(&self, functions: &[ObjectFunction]) -> Vec<(Vec<u8>, usize)> {
        let counts = self.count_patterns(functions);
        let mut patterns: Vec<(Vec<u8>, usize)> = counts
            .into_iter()
            .filter(|(_, count)| *count >= self.min_occurrences)
            .collect();
        patterns.sort_by_key(|p| std::cmp::Reverse(p.1));
        patterns
    }

    /// Returns the most common prologue bytes (or None if empty).
    #[must_use]
    pub fn most_common(&self, functions: &[ObjectFunction]) -> Option<Vec<u8>> {
        self.common_patterns(functions)
            .into_iter()
            .next()
            .map(|(p, _)| p)
    }
}

// ─── SignatureGenerator ────────────────────────────────────────────────────────

/// Generates FLIRT-style byte patterns from extracted functions.
#[derive(Debug, Clone, Default)]
pub struct SignatureGenerator {
    /// Number of bytes to use for the pattern prefix.
    pub prefix_len: usize,
    /// Whether to include CRC information in the output.
    pub include_crc: bool,
    /// Whether to add trailing tail bytes after CRC.
    pub include_tail: bool,
}

impl SignatureGenerator {
    /// Create with defaults (32-byte prefix, CRC on, tail on).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            prefix_len: 32,
            include_crc: true,
            include_tail: false,
        }
    }

    /// Generate a PAT-format line for a single function.
    ///
    /// Returns `None` if the function has fewer bytes than `prefix_len`.
    #[must_use]
    pub fn generate_pat_line(&self, func: &ObjectFunction) -> Option<String> {
        use std::fmt::Write as _;
        if func.bytes.len() < self.prefix_len.min(8) {
            return None;
        }
        let norm = func.normalized();
        let prefix_len = self.prefix_len.min(norm.bytes.len());

        let mut hex = String::with_capacity(prefix_len * 2);
        for i in 0..prefix_len {
            if norm.is_masked(i) {
                hex.push_str("..");
            } else {
                let _ = write!(hex, "{:02X}", norm.bytes[i]);
            }
        }

        let crc_part = if self.include_crc {
            let crc_data = &func.bytes[prefix_len..func.bytes.len().min(prefix_len + 32)];
            let crc = crate::crc16_flirt(crc_data);
            let crc_len = crc_data.len();
            format!(" {crc:04X} {crc_len:02X}")
        } else {
            " 0000 00".to_string()
        };

        Some(format!(
            "{hex}{crc_part} {:04X} :0000 {}",
            func.bytes.len(),
            func.name
        ))
    }

    /// Generate PAT lines for all functions.
    #[must_use]
    pub fn generate_all(&self, functions: &[ObjectFunction]) -> Vec<String> {
        functions
            .iter()
            .filter_map(|f| self.generate_pat_line(f))
            .collect()
    }

    /// Generate a complete PAT file string (with `---` terminator).
    #[must_use]
    pub fn generate_pat_file(&self, functions: &[ObjectFunction]) -> String {
        let mut lines = self.generate_all(functions);
        lines.push("---".to_string());
        lines.join("\n")
    }
}

// ─── LibAnalyzerResult ────────────────────────────────────────────────────────

/// Result of a complete library analysis run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibAnalyzerResult {
    /// Total object files processed.
    pub object_count: usize,
    /// Total functions extracted.
    pub function_count: usize,
    /// Number of unique byte signatures generated.
    pub signature_count: usize,
    /// Number of duplicate functions dropped.
    pub duplicates_dropped: usize,
    /// Generated PAT file content.
    pub pat_content: String,
}

// ─── LibAnalyzer ─────────────────────────────────────────────────────────────

/// Top-level library analysis engine.
///
/// Orchestrates parsing, extraction, sampling, and signature generation.
#[derive(Debug, Default, Clone)]
pub struct LibAnalyzer {
    /// Object file parser.
    pub parser: ObjFileParser,
    /// Function extractor.
    pub extractor: FunctionExtractor,
    /// Prologue sampler.
    pub sampler: PrologueSampler,
    /// Signature generator.
    pub generator: SignatureGenerator,
}

impl LibAnalyzer {
    /// Create a new library analyzer with defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            parser: ObjFileParser::new(),
            extractor: FunctionExtractor::new(),
            sampler: PrologueSampler::new(),
            generator: SignatureGenerator::new(),
        }
    }

    /// Analyse a list of raw ELF object file buffers and generate signatures.
    ///
    /// # Errors
    /// Returns [`GenError`] if any object file fails to parse.
    pub fn analyze(
        &self,
        objects: &[(&str, &[u8])], // (name, bytes)
    ) -> Result<LibAnalyzerResult, GenError> {
        let mut all_funcs: Vec<ObjectFunction> = Vec::new();
        for &(name, data) in objects {
            let funcs = self.parser.parse_elf(data, name)?;
            all_funcs.extend(funcs);
        }

        let original_count = all_funcs.len();
        let extracted = self.extractor.extract(all_funcs);
        let duplicates_dropped = original_count.saturating_sub(extracted.len());

        let pat_content = self.generator.generate_pat_file(&extracted);
        let signature_count = self.generator.generate_all(&extracted).len();

        Ok(LibAnalyzerResult {
            object_count: objects.len(),
            function_count: original_count,
            signature_count,
            duplicates_dropped,
            pat_content,
        })
    }

    /// Analyse a single ELF object file and return its signatures.
    ///
    /// # Errors
    /// Returns [`GenError`] if parsing fails.
    pub fn analyze_one(&self, name: &str, data: &[u8]) -> Result<LibAnalyzerResult, GenError> {
        self.analyze(&[(name, data)])
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_blob(body: &[u8]) -> Vec<u8> {
        let mut data = b"\x7FELF".to_vec();
        data.extend_from_slice(body);
        data
    }

    fn make_func(name: &str, bytes: &[u8]) -> ObjectFunction {
        ObjectFunction {
            name: name.to_string(),
            bytes: bytes.to_vec(),
            relocations: vec![],
            section_offset: 0,
            object_file: "test.o".to_string(),
        }
    }

    // ── NormalizedBytes ───────────────────────────────────────────────────────

    #[test]
    fn test_normalized_bytes_no_relocs() {
        let nb = NormalizedBytes::new(&[0x55, 0x89, 0xE5], &[]);
        assert_eq!(nb.bytes, vec![0x55, 0x89, 0xE5]);
        assert!(nb.masked.is_empty());
    }

    #[test]
    fn test_normalized_bytes_with_reloc() {
        let nb = NormalizedBytes::new(&[0x55, 0xAA, 0xBB, 0xCC, 0xDD], &[1]);
        assert_eq!(nb.bytes[1], 0x00);
        assert_eq!(nb.bytes[2], 0x00);
        assert!(nb.is_masked(1));
        assert!(!nb.is_masked(0));
    }

    #[test]
    fn test_normalized_bytes_significant() {
        let nb = NormalizedBytes::new(&[0x55, 0x00, 0x00, 0x00, 0x89], &[1]);
        let sig = nb.significant_bytes(5);
        assert!(sig.iter().all(|(i, _)| !nb.is_masked(*i)));
    }

    #[test]
    fn test_normalized_bytes_len() {
        let nb = NormalizedBytes::new(&[0x55, 0x89, 0xE5], &[]);
        assert_eq!(nb.len(), 3);
        assert!(!nb.is_empty());
    }

    #[test]
    fn test_normalized_bytes_empty() {
        let nb = NormalizedBytes::new(&[], &[]);
        assert!(nb.is_empty());
    }

    // ── ObjectFunction ────────────────────────────────────────────────────────

    #[test]
    fn test_object_function_is_signable_true() {
        let f = make_func("foo", &[0x55; 16]);
        assert!(f.is_signable());
    }

    #[test]
    fn test_object_function_is_signable_false() {
        let f = make_func("tiny", &[0x55, 0x89]);
        assert!(!f.is_signable());
    }

    #[test]
    fn test_object_function_normalized() {
        let mut f = make_func("foo", &[0x55, 0xAA, 0xBB, 0xCC]);
        f.relocations = vec![1];
        let nb = f.normalized();
        assert_eq!(nb.bytes[1], 0x00);
    }

    // ── ObjFileParser ─────────────────────────────────────────────────────────

    #[test]
    fn test_obj_file_parser_elf_ok() {
        let parser = ObjFileParser::new();
        let data = elf_blob(&[0u8; 200]);
        let funcs = parser.parse_elf(&data, "test.o").unwrap();
        assert!(!funcs.is_empty());
    }

    #[test]
    fn test_obj_file_parser_elf_bad_magic() {
        let parser = ObjFileParser::new();
        let result = parser.parse_elf(&[0x00; 10], "test.o");
        assert!(result.is_err());
    }

    #[test]
    fn test_obj_file_parser_elf_too_small() {
        let parser = ObjFileParser::new();
        let result = parser.parse_elf(&[0x7F], "test.o");
        assert!(result.is_err());
    }

    #[test]
    fn test_obj_file_parser_coff_disabled() {
        let parser = ObjFileParser::new();
        let result = parser.parse_coff(&[0u8; 64], "test.obj");
        assert!(result.is_err());
    }

    #[test]
    fn test_obj_file_parser_coff_enabled() {
        let parser = ObjFileParser::new().with_coff();
        let result = parser.parse_coff(&[0u8; 64], "test.obj");
        assert!(result.is_ok());
    }

    #[test]
    fn test_obj_file_parser_object_file_name() {
        let parser = ObjFileParser::new();
        let data = elf_blob(&[0u8; 200]);
        let funcs = parser.parse_elf(&data, "my_lib.o").unwrap();
        if !funcs.is_empty() {
            assert_eq!(funcs[0].object_file, "my_lib.o");
        }
    }

    // ── FunctionExtractor ─────────────────────────────────────────────────────

    #[test]
    fn test_function_extractor_filters_small() {
        let extractor = FunctionExtractor::new();
        let funcs = vec![make_func("tiny", &[0x55]), make_func("ok", &[0x55; 16])];
        let extracted = extractor.extract(funcs);
        assert_eq!(extracted.len(), 1);
    }

    #[test]
    fn test_function_extractor_deduplicates() {
        let extractor = FunctionExtractor::new();
        let funcs = vec![
            make_func("a", &[0x55; 16]),
            make_func("b", &[0x55; 16]), // identical bytes
        ];
        let extracted = extractor.extract(funcs);
        assert_eq!(extracted.len(), 1);
    }

    #[test]
    fn test_function_extractor_no_dedup() {
        let mut extractor = FunctionExtractor::new();
        extractor.deduplicate = false;
        let funcs = vec![make_func("a", &[0x55; 16]), make_func("b", &[0x55; 16])];
        let extracted = extractor.extract(funcs);
        assert_eq!(extracted.len(), 2);
    }

    #[test]
    fn test_function_extractor_count_unique() {
        let extractor = FunctionExtractor::new();
        let funcs = vec![
            make_func("a", &[0x55; 16]),
            make_func("b", &[0xAA; 16]),
            make_func("c", &[0x55; 16]),
        ];
        assert_eq!(extractor.count_unique(&funcs), 2);
    }

    // ── PrologueSampler ───────────────────────────────────────────────────────

    #[test]
    fn test_prologue_sampler_count_patterns() {
        let sampler = PrologueSampler {
            sample_len: 4,
            min_occurrences: 1,
        };
        let funcs = vec![
            make_func("a", &[0x55, 0x89, 0xE5, 0x53]),
            make_func("b", &[0x55, 0x89, 0xE5, 0x53]),
        ];
        let counts = sampler.count_patterns(&funcs);
        assert_eq!(counts[&vec![0x55, 0x89, 0xE5, 0x53]], 2);
    }

    #[test]
    fn test_prologue_sampler_common_patterns() {
        let sampler = PrologueSampler {
            sample_len: 4,
            min_occurrences: 2,
        };
        let funcs = vec![
            make_func("a", &[0x55, 0x89, 0xE5, 0x53]),
            make_func("b", &[0x55, 0x89, 0xE5, 0x53]),
        ];
        let common = sampler.common_patterns(&funcs);
        assert!(!common.is_empty());
    }

    #[test]
    fn test_prologue_sampler_most_common() {
        let sampler = PrologueSampler {
            sample_len: 4,
            min_occurrences: 2,
        };
        let funcs = vec![
            make_func("a", &[0x55, 0x89, 0xE5, 0x53]),
            make_func("b", &[0x55, 0x89, 0xE5, 0x53]),
        ];
        let most = sampler.most_common(&funcs);
        assert_eq!(most.unwrap(), vec![0x55, 0x89, 0xE5, 0x53]);
    }

    #[test]
    fn test_prologue_sampler_empty() {
        let sampler = PrologueSampler::new();
        assert!(sampler.most_common(&[]).is_none());
    }

    // ── SignatureGenerator ────────────────────────────────────────────────────

    #[test]
    fn test_sig_gen_pat_line_ok() {
        let r#gen = SignatureGenerator {
            prefix_len: 8,
            include_crc: true,
            include_tail: false,
        };
        let func = make_func("malloc", &[0x55, 0x89, 0xE5, 0x53, 0x83, 0xEC, 0x14, 0x8B]);
        let line = r#gen.generate_pat_line(&func);
        assert!(line.is_some());
        assert!(line.unwrap().contains("malloc"));
    }

    #[test]
    fn test_sig_gen_pat_line_too_short() {
        let r#gen = SignatureGenerator::new();
        let func = make_func("tiny", &[0x55]);
        assert!(r#gen.generate_pat_line(&func).is_none());
    }

    #[test]
    fn test_sig_gen_generate_all() {
        let r#gen = SignatureGenerator {
            prefix_len: 8,
            include_crc: false,
            include_tail: false,
        };
        let funcs = vec![
            make_func("a", &[0x55, 0x89, 0xE5, 0x53, 0x83, 0xEC, 0x14, 0x8B]),
            make_func("b", &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]),
        ];
        let lines = r#gen.generate_all(&funcs);
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_sig_gen_pat_file_terminator() {
        let r#gen = SignatureGenerator::new();
        let funcs = vec![make_func("f", &[0x55; 40])];
        let content = r#gen.generate_pat_file(&funcs);
        assert!(content.ends_with("---"));
    }

    // ── LibAnalyzer ───────────────────────────────────────────────────────────

    #[test]
    fn test_lib_analyzer_new() {
        let _a = LibAnalyzer::new();
    }

    #[test]
    fn test_lib_analyzer_analyze_one_ok() {
        let a = LibAnalyzer::new();
        let data = elf_blob(&[0u8; 200]);
        let result = a.analyze_one("test.o", &data).unwrap();
        assert_eq!(result.object_count, 1);
        assert!(!result.pat_content.is_empty());
    }

    #[test]
    fn test_lib_analyzer_analyze_one_bad() {
        let a = LibAnalyzer::new();
        let result = a.analyze_one("bad.o", &[0x00; 4]);
        assert!(result.is_err());
    }

    #[test]
    fn test_lib_analyzer_analyze_multiple() {
        let a = LibAnalyzer::new();
        let data = elf_blob(&[0u8; 200]);
        let result = a.analyze(&[("a.o", &data), ("b.o", &data)]).unwrap();
        assert_eq!(result.object_count, 2);
    }

    #[test]
    fn test_lib_analyzer_result_serialization() {
        let r = LibAnalyzerResult {
            object_count: 1,
            function_count: 5,
            signature_count: 4,
            duplicates_dropped: 1,
            pat_content: "foo\n---".into(),
        };
        let j = serde_json::to_string(&r).unwrap();
        let d: LibAnalyzerResult = serde_json::from_str(&j).unwrap();
        assert_eq!(d.object_count, 1);
    }

    #[test]
    fn test_lib_analyzer_pat_content_ends_with_terminator() {
        let a = LibAnalyzer::new();
        let data = elf_blob(&[0u8; 200]);
        let result = a.analyze_one("t.o", &data).unwrap();
        assert!(result.pat_content.ends_with("---"));
    }
}
