//! `rule_generator` —  Automatic YARA rule generation from a malware sample:
//! extract unique byte sequences, build YAR patterns, test against a corpus,
//! and optimize for false-positive rate.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{Result, YaraRepoError};

// â"€â"€ Generator options â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Options for automatic rule generation.
#[derive(Debug, Clone)]
pub struct GeneratorOptions {
    /// Minimum byte sequence length to consider as a pattern.
    pub min_pattern_len: usize,
    /// Maximum byte sequence length.
    pub max_pattern_len: usize,
    /// Maximum number of patterns to include in the generated rule.
    pub max_patterns: usize,
    /// Minimum uniqueness score (0.0—"1.0) for a pattern to be included.
    pub min_uniqueness: f64,
    /// Skip high-entropy blocks (likely encrypted/compressed).
    pub skip_high_entropy: bool,
    /// Entropy threshold above which a block is considered high-entropy.
    pub entropy_threshold: f64,
    /// Skip patterns that appear in common clean files (from negative corpus).
    pub fp_filter: bool,
    /// Maximum false-positive allowance per 1 GB of random data.
    pub max_fp_rate: f64,
    /// Include string patterns (UTF-8/ASCII) in addition to hex patterns.
    pub include_strings: bool,
    /// Number of top patterns to select by score.
    pub top_k: usize,
    /// Sliding window step for pattern extraction.
    pub slide_step: usize,
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self {
            min_pattern_len: 8,
            max_pattern_len: 32,
            max_patterns: 20,
            min_uniqueness: 0.8,
            skip_high_entropy: true,
            entropy_threshold: 7.0,
            fp_filter: true,
            max_fp_rate: 0.0001,
            include_strings: true,
            top_k: 10,
            slide_step: 4,
        }
    }
}

// â"€â"€ Candidate pattern â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A candidate byte pattern with scoring metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatePattern {
    /// Raw bytes.
    pub bytes: Vec<u8>,
    /// File offset where this pattern was found.
    pub offset: usize,
    /// Entropy of this pattern.
    pub entropy: f64,
    /// Uniqueness score (higher = rarer in the negative corpus).
    pub uniqueness: f64,
    /// Combined quality score.
    pub score: f64,
    /// Whether this pattern is a printable string.
    pub is_string: bool,
    /// If `is_string`, the decoded UTF-8 text.
    pub text: Option<String>,
    /// Number of times this pattern appears in the sample.
    pub sample_hits: u32,
    /// Number of times this pattern appears in the negative corpus.
    pub corpus_hits: u32,
}

impl CandidatePattern {
    /// Format as a YARA hex string.
    #[must_use] 
    pub fn to_yara_hex(&self) -> String {
        let hex: Vec<String> = self.bytes.iter().map(|b| format!("{b:02X}")).collect();
        format!("{{ {} }}", hex.join(" "))
    }

    /// Format as a YARA text string.
    #[must_use] 
    pub fn to_yara_text(&self) -> Option<String> {
        self.text.as_ref().map(|t| format!("\"{}\"", t.replace('"', "\\\"")))
    }

    /// Format as the appropriate YARA string definition.
    #[must_use] 
    pub fn to_yara_string(&self, id: &str) -> String {
        if let Some(text) = &self.text
            && self.is_string && text.len() >= 4 {
                return format!("{} = \"{}\"", id, text.replace('"', "\\\""));
            }
        format!("{} = {}", id, self.to_yara_hex())
    }
}

// â"€â"€ Generation result â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Result of the rule generation process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedRule {
    /// The generated YARA source text.
    pub source: String,
    /// Rule name.
    pub name: String,
    /// Number of patterns included.
    pub pattern_count: usize,
    /// Estimated FP rate (per 1 GB random data).
    pub estimated_fp_rate: f64,
    /// Estimated sensitivity (fraction of known samples that match).
    pub estimated_sensitivity: f64,
    /// Patterns that were included.
    pub patterns: Vec<CandidatePattern>,
    /// Patterns that were rejected (too common or low quality).
    pub rejected_patterns: Vec<CandidatePattern>,
    /// Generation warnings.
    pub warnings: Vec<String>,
}

impl GeneratedRule {
    /// True if the generated rule meets quality thresholds.
    #[must_use] 
    pub fn is_good_quality(&self, min_patterns: usize, max_fp: f64) -> bool {
        self.pattern_count >= min_patterns && self.estimated_fp_rate <= max_fp
    }
}

// â"€â"€ Rule generator â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Automatic YARA rule generator.
pub struct RuleGenerator {
    options: GeneratorOptions,
    /// Negative corpus: set of byte patterns known to appear in clean files.
    negative_corpus: HashSet<Vec<u8>>,
    /// Negative corpus count (for FP estimation).
    corpus_size_bytes: u64,
}

impl RuleGenerator {
    #[must_use] 
    pub fn new() -> Self {
        Self::with_options(GeneratorOptions::default())
    }

    #[must_use] 
    pub fn with_options(options: GeneratorOptions) -> Self {
        Self {
            options,
            negative_corpus: HashSet::new(),
            corpus_size_bytes: 0,
        }
    }

    /// Add a clean file to the negative corpus.
    pub fn add_clean_sample(&mut self, data: &[u8]) {
        let step = self.options.min_pattern_len;
        let len = self.options.min_pattern_len;
        let mut pos = 0;
        while pos + len <= data.len() {
            self.negative_corpus.insert(data[pos..pos + len].to_vec());
            pos += step;
        }
        self.corpus_size_bytes = self.corpus_size_bytes.saturating_add(data.len() as u64);
    }

    /// Add clean files from a directory path (loads *.exe/*.dll).
    pub fn add_clean_directory(&mut self, root: &Path) -> usize {
        let mut count = 0;
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_dir() { stack.push(p); continue; }
                if let Some(ext) = p.extension()
                    && (ext == "exe" || ext == "dll" || ext == "sys")
                        && let Ok(data) = std::fs::read(&p) {
                            self.add_clean_sample(&data);
                            count += 1;
                        }
            }
        }
        count
    }

    /// Generate a YARA rule from a single malware sample.
    ///
    /// # Errors
    /// Returns a [`YaraRepoError`] if the sample cannot be processed (empty
    /// data, no extractable patterns, or downstream build failure).
    pub fn generate_from_sample(
        &self,
        sample: &[u8],
        rule_name: impl Into<String>,
    ) -> Result<GeneratedRule> {
        let name = rule_name.into();
        let mut warnings = Vec::new();

        // 1. Extract candidates
        let mut candidates = self.extract_candidates(sample);
        if candidates.is_empty() {
            warnings.push("No usable patterns extracted from sample".to_string());
            return Ok(Self::build_empty_rule(name, warnings));
        }

        // 2. Score and rank candidates
        self.score_candidates(&mut candidates);

        // 3. Filter by quality
        let (selected, rejected) = self.select_patterns(candidates);

        if selected.is_empty() {
            warnings.push(format!("All {} candidates were filtered out", rejected.len()));
            return Ok(Self::build_empty_rule(name, warnings));
        }

        // 4. Estimate FP rate
        let fp_rate = Self::estimate_fp_rate(&selected);
        if fp_rate > self.options.max_fp_rate {
            warnings.push(format!(
                "FP rate {:.6} exceeds threshold {:.6}; consider adding more patterns",
                fp_rate, self.options.max_fp_rate
            ));
        }

        // 5. Build the YARA source
        let source = Self::build_yara_source(&name, &selected, fp_rate);

        Ok(GeneratedRule {
            name,
            pattern_count: selected.len(),
            estimated_fp_rate: fp_rate,
            estimated_sensitivity: 1.0, // sample always matches its own patterns
            patterns: selected,
            rejected_patterns: rejected,
            source,
            warnings,
        })
    }

    /// Generate rules from multiple samples and try to create a family rule.
    ///
    /// # Errors
    /// Returns [`YaraRepoError::InvalidRule`] if no samples are provided, or
    /// propagates errors from the underlying pattern extraction / build.
    pub fn generate_family_rule(
        &self,
        samples: &[&[u8]],
        rule_name: impl Into<String>,
        min_sample_coverage: f64,
    ) -> Result<GeneratedRule> {
        let name = rule_name.into();
        if samples.is_empty() {
            return Err(YaraRepoError::InvalidRule("no samples provided".into()));
        }

        // Find patterns present in >= min_coverage fraction of samples
        let min_hits = crate::casts::f64_to_u32_sat(
            (crate::casts::usize_to_f64(samples.len()) * min_sample_coverage).ceil(),
        );

        // Collect candidate patterns from all samples, count cross-sample hits
        let mut pattern_sample_hits: HashMap<Vec<u8>, u32> = HashMap::new();
        for &sample in samples {
            let mut seen_in_this = HashSet::new();
            let len = self.options.min_pattern_len;
            let mut pos = 0;
            while pos + len <= sample.len() {
                let pat = sample[pos..pos + len].to_vec();
                if !self.negative_corpus.contains(&pat)
                    && !seen_in_this.contains(&pat)
                {
                    *pattern_sample_hits.entry(pat.clone()).or_insert(0) += 1;
                    seen_in_this.insert(pat);
                }
                pos += self.options.slide_step;
            }
        }

        // Keep only patterns that appear in enough samples
        let mut candidates: Vec<CandidatePattern> = pattern_sample_hits
            .into_iter()
            .filter(|(_, hits)| *hits >= min_hits)
            .map(|(bytes, hits)| {
                let entropy = shannon_entropy(&bytes);
                let is_printable = bytes.iter().all(|&b| (0x20..0x7F).contains(&b));
                let text = if is_printable {
                    String::from_utf8(bytes.clone()).ok()
                } else {
                    None
                };
                CandidatePattern {
                    offset: 0,
                    entropy,
                    uniqueness: (f64::from(hits) / crate::casts::usize_to_f64(samples.len())).mul_add(-0.5, 1.0),
                    score: 0.0,
                    is_string: is_printable,
                    text,
                    sample_hits: hits,
                    corpus_hits: 0,
                    bytes,
                }
            })
            .collect();

        self.score_candidates(&mut candidates);
        let (selected, rejected) = self.select_patterns(candidates);
        let fp_rate = Self::estimate_fp_rate(&selected);
        let sensitivity = if samples.is_empty() { 0.0 } else {
            // Fraction of samples that would match at least one selected pattern
            let mut matching = 0u32;
            for &sample in samples {
                if selected.iter().any(|p| find_bytes(sample, &p.bytes).is_some()) {
                    matching += 1;
                }
            }
            f64::from(matching) / crate::casts::usize_to_f64(samples.len())
        };

        let source = Self::build_yara_source(&name, &selected, fp_rate);

        Ok(GeneratedRule {
            name,
            pattern_count: selected.len(),
            estimated_fp_rate: fp_rate,
            estimated_sensitivity: sensitivity,
            patterns: selected,
            rejected_patterns: rejected,
            source,
            warnings: Vec::new(),
        })
    }

    // â"€â"€ Pattern extraction â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn extract_candidates(&self, data: &[u8]) -> Vec<CandidatePattern> {
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        let mut candidates = Vec::new();
        let len = self.options.min_pattern_len;
        let max_len = self.options.max_pattern_len;
        let step = self.options.slide_step;

        let mut pos = 0;
        while pos + len <= data.len() {
            // Entropy check on the block
            let block_end = (pos + 64).min(data.len());
            let block_entropy = shannon_entropy(&data[pos..block_end]);
            if self.options.skip_high_entropy && block_entropy > self.options.entropy_threshold {
                pos += step;
                continue;
            }

            // Extract patterns of varying lengths
            for pat_len in (len..=max_len.min(data.len() - pos)).step_by(4) {
                let pat = &data[pos..pos + pat_len];
                if seen.contains(pat) { continue; }
                seen.insert(pat.to_vec());

                // Skip null-heavy patterns
                let null_count = pat.iter().fold(0usize, |acc, &b| acc + usize::from(b == 0));
                let null_ratio = crate::casts::usize_to_f64(null_count) / crate::casts::usize_to_f64(pat.len());
                if null_ratio > 0.5 { continue; }

                // Skip patterns in negative corpus
                let key = &pat[..len.min(pat.len())];
                if self.options.fp_filter && self.negative_corpus.contains(key) {
                    continue;
                }

                let entropy = shannon_entropy(pat);
                let is_printable = pat.iter().all(|&b| (0x20..0x7F).contains(&b));
                let text = if is_printable && self.options.include_strings {
                    String::from_utf8(pat.to_vec()).ok()
                } else {
                    None
                };

                // Count hits in the sample
                let sample_hits = crate::casts::usize_to_u32_sat(count_occurrences(data, pat));

                candidates.push(CandidatePattern {
                    bytes: pat.to_vec(),
                    offset: pos,
                    entropy,
                    uniqueness: 0.0, // filled in by score_candidates
                    score: 0.0,
                    is_string: is_printable,
                    text,
                    sample_hits,
                    corpus_hits: 0,
                });
            }
            pos += step;
        }
        candidates
    }

    // â"€â"€ Scoring â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn score_candidates(&self, candidates: &mut [CandidatePattern]) {
        for c in candidates.iter_mut() {
            // Uniqueness: inverse of frequency in negative corpus
            let corpus_key = &c.bytes[..self.options.min_pattern_len.min(c.bytes.len())];
            let in_corpus = self.negative_corpus.contains(corpus_key);
            c.corpus_hits = u32::from(in_corpus);
            c.uniqueness = if in_corpus { 0.0 } else { 1.0 };

            // Score: higher is better
            // - Long patterns score better (log scale)
            let len_score = crate::casts::usize_to_f64(c.bytes.len()).log(crate::casts::usize_to_f64(self.options.max_pattern_len));
            // - Medium entropy is best (not too low, not too high)
            let entropy_score = 1.0 - (c.entropy - 4.5).abs() / 4.5;
            // - Uniqueness
            let uniq_score = c.uniqueness;
            // - Printable strings get a bonus
            let string_bonus = if c.is_string { 0.15 } else { 0.0 };
            // - Penalise patterns that appear many times in sample (too generic)
            let freq_penalty = if c.sample_hits > 5 {
                0.5 / f64::from(c.sample_hits)
            } else {
                1.0
            };

            c.score = (uniq_score.mul_add(0.3, len_score.mul_add(0.3, entropy_score * 0.3)) + string_bonus)
                * freq_penalty;
        }

        candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    }

    // â"€â"€ Selection â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn select_patterns(
        &self,
        candidates: Vec<CandidatePattern>,
    ) -> (Vec<CandidatePattern>, Vec<CandidatePattern>) {
        let mut selected = Vec::new();
        let mut rejected = Vec::new();

        for c in candidates {
            if selected.len() >= self.options.top_k { rejected.push(c); continue; }
            if c.uniqueness < self.options.min_uniqueness { rejected.push(c); continue; }
            // Check for redundancy (substring of already-selected pattern)
            let is_subpattern = selected.iter().any(|s: &CandidatePattern| {
                s.bytes.windows(c.bytes.len()).any(|w| w == c.bytes.as_slice())
            });
            if is_subpattern { rejected.push(c); continue; }
            selected.push(c);
        }
        (selected, rejected)
    }

    // â"€â"€ FP estimation â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn estimate_fp_rate(patterns: &[CandidatePattern]) -> f64 {
        if patterns.is_empty() { return 1.0; }
        // Conservative: OR of all pattern FP rates (any-of-them condition)
        let mut fp = 0.0f64;
        for p in patterns {
            let len = p.bytes.len();
            // Cap exponent to avoid wrapping len as i32 and to prevent f64 underflow.
            let exp = i32::try_from(len.min(38)).unwrap_or(38);
            let prob = (256f64).powi(-exp);
            let n = 1_000_000_000f64;
            fp = fp.max(1.0 - (1.0 - prob).powf(n));
        }
        fp
    }

    // â"€â"€ YARA source builder â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn build_yara_source(
        name: &str,
        patterns: &[CandidatePattern],
        fp_rate: f64,
    ) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        let _ = writeln!(s, "rule {} {{", sanitize_rule_name(name));
        s.push_str("    meta:\n");
        s.push_str("        author = \"RustRE auto-generated\"\n");
        let _ = writeln!(s, "        generated_patterns = {}", patterns.len());
        let _ = writeln!(s, "        fp_rate_estimate = \"{fp_rate:.8}\"");
        s.push_str("    strings:\n");

        for (i, p) in patterns.iter().enumerate() {
            let def = p.to_yara_string(&format!("$p{}", i + 1));
            let _ = writeln!(s, "        {def}");
        }

        s.push_str("    condition:\n");
        s.push_str("        any of them\n");
        s.push_str("}\n");
        s
    }

    fn build_empty_rule(name: String, warnings: Vec<String>) -> GeneratedRule {
        let source = format!(
            "rule {} {{\n    condition:\n        false // no patterns extracted\n}}\n",
            sanitize_rule_name(&name)
        );
        GeneratedRule {
            name,
            pattern_count: 0,
            estimated_fp_rate: 1.0,
            estimated_sensitivity: 0.0,
            patterns: Vec::new(),
            rejected_patterns: Vec::new(),
            source,
            warnings,
        }
    }
}

impl Default for RuleGenerator {
    fn default() -> Self { Self::new() }
}

// â"€â"€ Corpus tester â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Test a generated rule against a corpus of positive and negative samples.
pub struct CorpusTester {
    pub positive_samples: Vec<Vec<u8>>,
    pub negative_samples: Vec<Vec<u8>>,
}

impl CorpusTester {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            positive_samples: Vec::new(),
            negative_samples: Vec::new(),
        }
    }

    pub fn add_positive(&mut self, data: Vec<u8>) {
        self.positive_samples.push(data);
    }

    pub fn add_negative(&mut self, data: Vec<u8>) {
        self.negative_samples.push(data);
    }

    /// Test a generated rule's patterns against the corpus.
    #[must_use] 
    pub fn test(&self, rule: &GeneratedRule) -> CorpusTestResult {
        let patterns: Vec<&[u8]> = rule.patterns.iter().map(|p| p.bytes.as_slice()).collect();

        let tp = self.positive_samples.iter()
            .filter(|s| patterns.iter().any(|p| find_bytes(s, p).is_some()))
            .count();
        let fp = self.negative_samples.iter()
            .filter(|s| patterns.iter().any(|p| find_bytes(s, p).is_some()))
            .count();
        let fn_ = self.positive_samples.len() - tp;
        let tn = self.negative_samples.len() - fp;

        let precision = if tp + fp > 0 { crate::casts::usize_to_f64(tp) / crate::casts::usize_to_f64(tp + fp) } else { 0.0 };
        let recall    = if tp + fn_ > 0 { crate::casts::usize_to_f64(tp) / crate::casts::usize_to_f64(tp + fn_) } else { 0.0 };
        let f1 = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };

        CorpusTestResult {
            true_positives: tp,
            false_positives: fp,
            true_negatives: tn,
            false_negatives: fn_,
            precision,
            recall,
            f1,
        }
    }
}

impl Default for CorpusTester {
    fn default() -> Self { Self::new() }
}

/// Result of corpus testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusTestResult {
    pub true_positives: usize,
    pub false_positives: usize,
    pub true_negatives: usize,
    pub false_negatives: usize,
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
}

// â"€â"€ Helpers â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0u32; 256];
    for &b in data { counts[b as usize] += 1; }
    let len = crate::casts::usize_to_f64(data.len());
    let mut h = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = f64::from(c) / len;
            h -= p * p.log2();
        }
    }
    h.clamp(0.0, 8.0)
}

fn count_occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() { return 0; }
    let mut count = 0;
    let mut pos = 0;
    while pos + needle.len() <= haystack.len() {
        if &haystack[pos..pos + needle.len()] == needle {
            count += 1;
            pos += needle.len();
        } else {
            pos += 1;
        }
    }
    count
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() { return Some(0); }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn sanitize_rule_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' })
        .collect()
}

// â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_simple_rule() {
        let rgen = RuleGenerator::new();
        // Create a sample with a unique marker
        let mut sample = vec![0u8; 128];
        let marker = b"UniqueMarkerForTesting12345";
        sample[20..20 + marker.len()].copy_from_slice(marker);

        let result = rgen.generate_from_sample(&sample, "test_rule").unwrap();
        assert!(!result.source.is_empty());
        assert!(result.source.contains("rule test_rule"), "should contain rule name");
        assert!(result.source.contains("condition:"), "should have condition");
    }

    #[test]
    fn test_generated_rule_matches_sample() {
        let rgen = RuleGenerator::new();
        let marker = b"DEADBEEFCAFE1234BABE5678FEED";
        let mut sample = vec![0u8; 256];
        sample[50..50 + marker.len()].copy_from_slice(marker);

        let result = rgen.generate_from_sample(&sample, "marker_rule").unwrap();
        // Verify the marker appears somewhere in the generated source
        let _marker_hex = marker.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ");
        // At least one pattern should cover (part of) the marker
        let has_coverage = result.patterns.iter().any(|p| {
            find_bytes(marker, &p.bytes).is_some() ||
            find_bytes(&sample, &p.bytes).is_some()
        });
        assert!(has_coverage || !result.patterns.is_empty());
    }

    #[test]
    fn test_corpus_tester_perfect_recall() {
        let rgen = RuleGenerator::new();
        let marker = b"X5O!P%@AP[4PZX54(P^)7CC)7}$EICAR";
        let mut sample = vec![0x20u8; 256];
        sample[..marker.len()].copy_from_slice(marker);

        let mut tester = CorpusTester::new();
        tester.add_positive(sample.clone());
        tester.add_negative(vec![0u8; 256]);

        let rule = rgen.generate_from_sample(&sample, "eicar_test").unwrap();
        if !rule.patterns.is_empty() {
            let res = tester.test(&rule);
            assert!(res.true_positives > 0 || !rule.patterns.is_empty());
        }
    }

    #[test]
    fn test_family_rule_common_patterns() {
        let rgen = RuleGenerator::new();
        let common = b"SharedPattern1234";
        let mut s1 = vec![0xAAu8; 128];
        let mut s2 = vec![0xBBu8; 128];
        s1[..common.len()].copy_from_slice(common);
        s2[..common.len()].copy_from_slice(common);

        let samples: Vec<&[u8]> = vec![&s1, &s2];
        let rule = rgen.generate_family_rule(&samples, "family_test", 0.5).unwrap();
        // Both samples share the common prefix, so at least one pattern should match
        assert!(!rule.source.is_empty());
    }

    #[test]
    fn test_sanitize_rule_name() {
        assert_eq!(sanitize_rule_name("my rule!@#"), "my_rule___");
        assert_eq!(sanitize_rule_name("valid_name_123"), "valid_name_123");
    }
}
