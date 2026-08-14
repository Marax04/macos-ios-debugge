//! Signature database builder.
//!
//! Groups raw function samples by name, runs variance analysis on each group,
//! and produces a deduplicated [`SignatureDatabase`] containing
//! [`rustre_flirt::FlirtPattern`]s ready for serialization.

use rustre_flirt::{FlirtName, FlirtPattern, PatternByte};

use crate::{
    GenError,
    library_scanner::FunctionSample,
    serializer::{PatDeserializer, PatSerializer, SerializeError},
    variance_analyzer::VarianceAnalyzer,
};

// ── BuilderConfig ─────────────────────────────────────────────────────────────

/// Configuration for [`DatabaseBuilder`].
#[derive(Debug, Clone)]
pub struct BuilderConfig {
    /// Minimum number of concrete bytes in the initial block.
    pub min_pattern_len: usize,
    /// Maximum total number of pattern bytes to consider.
    pub max_pattern_len: usize,
    /// Minimum number of samples required to generate a pattern for a function.
    pub min_samples: usize,
    /// Maximum allowed fraction of wildcard bytes (0.0–1.0).
    pub max_wildcard_ratio: f64,
    /// Entropy threshold forwarded to [`VarianceAnalyzer`].
    pub entropy_threshold: f64,
}

impl Default for BuilderConfig {
    fn default() -> Self {
        Self {
            min_pattern_len: 4,
            max_pattern_len: 64,
            min_samples: 2,
            max_wildcard_ratio: 0.8,
            entropy_threshold: 2.0,
        }
    }
}

// ── DbBuildStats ──────────────────────────────────────────────────────────────

/// Statistics collected during a [`DatabaseBuilder::build`] run.
#[derive(Debug, Clone, Default)]
pub struct DbBuildStats {
    /// Total number of function samples provided.
    pub input_samples: usize,
    /// Number of patterns successfully generated and kept.
    pub output_patterns: usize,
    /// Number of exact duplicate patterns that were removed.
    pub duplicates_removed: usize,
    /// Number of function groups skipped for being too short.
    pub too_short_skipped: usize,
    /// Number of patterns rejected for having too many wildcards.
    pub too_many_wildcards: usize,
    /// Wall-clock time in nanoseconds (set by the caller if desired).
    pub elapsed_ns: u64,
}

// ── SignatureDatabase ─────────────────────────────────────────────────────────

/// A complete, deduplicated collection of FLIRT patterns for one library.
#[derive(Debug)]
pub struct SignatureDatabase {
    /// Library name.
    pub lib_name: String,
    /// Library version string.
    pub version: String,
    /// The patterns.
    pub patterns: Vec<FlirtPattern>,
    /// Statistics from the last build that produced this database.
    pub stats: DbBuildStats,
}

impl SignatureDatabase {
    /// Create an empty database.
    #[must_use]
    pub fn new(lib_name: &str, version: &str) -> Self {
        Self {
            lib_name: lib_name.to_string(),
            version: version.to_string(),
            patterns: Vec::new(),
            stats: DbBuildStats::default(),
        }
    }

    /// Append a pattern to the database.
    pub fn add_pattern(&mut self, p: FlirtPattern) {
        self.patterns.push(p);
    }

    /// Remove exact duplicate patterns.
    ///
    /// Two patterns are considered duplicates when their hex-encoded initial
    /// bytes, CRC-16, and primary name all match.
    pub fn dedup(&mut self) {
        let before = self.patterns.len();
        let mut seen = std::collections::HashSet::new();
        self.patterns.retain(|p| {
            let hex: String = p
                .initial_bytes
                .iter()
                .map(|pb| match pb {
                    PatternByte::Exact(b) => format!("{b:02X}"),
                    PatternByte::Wildcard => "..".to_string(),
                })
                .collect();
            let key = format!("{}:{}:{}", hex, p.crc16, p.primary_name().unwrap_or(""));
            seen.insert(key)
        });
        let removed = before - self.patterns.len();
        self.stats.duplicates_removed += removed;
    }

    /// Serialize the database to a `.pat` text string.
    #[must_use]
    pub fn save_to_pat(&self) -> String {
        PatSerializer::to_pat(&self.patterns)
    }

    /// Deserialize a database from `.pat` text, tagging it with `lib_name`.
    ///
    /// # Errors
    ///
    /// Returns [`GenError`] on parse failure.
    pub fn load_from_pat(text: &str, lib_name: &str) -> Result<Self, GenError> {
        let patterns = PatDeserializer::from_pat(text)
            .map_err(|e: SerializeError| GenError::Parse(e.to_string()))?;
        let mut db = Self::new(lib_name, "");
        db.patterns = patterns;
        Ok(db)
    }
}

// ── DatabaseBuilder ───────────────────────────────────────────────────────────

/// Accumulates [`FunctionSample`]s and constructs a [`SignatureDatabase`].
pub struct DatabaseBuilder {
    config: BuilderConfig,
    samples: Vec<FunctionSample>,
    analyzer: VarianceAnalyzer,
}

impl DatabaseBuilder {
    /// Create a new builder with the given configuration.
    #[must_use]
    pub const fn new(config: BuilderConfig) -> Self {
        let analyzer = VarianceAnalyzer::new(config.entropy_threshold, 0.7);
        Self {
            config,
            samples: Vec::new(),
            analyzer,
        }
    }

    /// Add a single function sample.
    pub fn add_sample(&mut self, sample: FunctionSample) {
        self.samples.push(sample);
    }

    /// Build a [`SignatureDatabase`] from all accumulated samples.
    ///
    /// Steps:
    /// 1. Group samples by function name.
    /// 2. For groups with ≥ `min_samples`: run variance analysis, build pattern.
    /// 3. Filter patterns shorter than `min_pattern_len`.
    /// 4. Filter patterns with wildcard ratio > `max_wildcard_ratio`.
    /// 5. Deduplicate.
    #[must_use]
    pub fn build(&mut self, lib_name: &str, version: &str) -> SignatureDatabase {
        let mut db = SignatureDatabase::new(lib_name, version);
        let mut stats = DbBuildStats {
            input_samples: self.samples.len(),
            ..DbBuildStats::default()
        };

        // Group samples by name.
        // BTreeMap is used here instead of HashMap to avoid hash-collision DoS:
        // function names come from untrusted library files and an attacker could
        // craft many names with the same hash to cause O(n²) behaviour.
        let mut groups: std::collections::BTreeMap<&str, Vec<&[u8]>> =
            std::collections::BTreeMap::new();
        for sample in &self.samples {
            groups
                .entry(sample.name.as_str())
                .or_default()
                .push(sample.bytes.as_slice());
        }

        let max_len = self.config.max_pattern_len;
        let min_pattern_len = self.config.min_pattern_len;
        let max_wc = self.config.max_wildcard_ratio;
        let min_samples = self.config.min_samples;

        for (name, sample_slices) in &groups {
            if sample_slices.len() < min_samples {
                continue;
            }

            // Determine pattern length: min of all sample lengths, capped at max_len
            let max_sample_len = sample_slices.iter().map(|s| s.len()).min().unwrap_or(0);
            let pattern_len = max_sample_len.min(max_len);

            if pattern_len < min_pattern_len {
                stats.too_short_skipped += 1;
                continue;
            }

            let results = self.analyzer.analyze(sample_slices, pattern_len);
            let reference = sample_slices[0];
            let pattern_bytes = VarianceAnalyzer::build_pattern(&results, reference);

            // Convert Option<u8> to PatternByte
            let initial_bytes: Vec<PatternByte> = pattern_bytes
                .iter()
                .map(|b| b.as_ref().map_or(PatternByte::Wildcard, |v| PatternByte::Exact(*v)))
                .collect();

            // Quality checks
            let effective = VarianceAnalyzer::effective_length(&pattern_bytes);
            if effective < min_pattern_len {
                stats.too_short_skipped += 1;
                continue;
            }

            let wc_ratio = 1.0 - VarianceAnalyzer::quality_score(&pattern_bytes);
            if wc_ratio > max_wc {
                stats.too_many_wildcards += 1;
                continue;
            }

            let mut pat = FlirtPattern::new(initial_bytes);
            pat.pattern_length = u16::try_from(max_sample_len).unwrap_or(u16::MAX);
            pat.names.push(FlirtName {
                name: name.to_string(),
                offset: 0,
                is_public: true,
                is_local: false,
            });

            db.patterns.push(pat);
            stats.output_patterns += 1;
        }

        db.dedup();
        db.stats = stats;
        db
    }

    /// Estimate the quality of a set of patterns (average quality score).
    ///
    /// Returns 0.0 for an empty slice.
    #[must_use]
    pub fn estimate_quality(patterns: &[FlirtPattern]) -> f64 {
        if patterns.is_empty() {
            return 0.0;
        }
        let total: f64 = patterns
            .iter()
            .map(|p| {
                let opts: Vec<Option<u8>> = p
                    .initial_bytes
                    .iter()
                    .map(|pb| match pb {
                        PatternByte::Exact(b) => Some(*b),
                        PatternByte::Wildcard => None,
                    })
                    .collect();
                VarianceAnalyzer::quality_score(&opts)
            })
            .sum();
        total / f64::from(u32::try_from(patterns.len()).unwrap_or(u32::MAX))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(name: &str, bytes: &[u8]) -> FunctionSample {
        FunctionSample {
            name: name.to_string(),
            bytes: bytes.to_vec(),
            reloc_offsets: vec![],
        }
    }

    // ── SignatureDatabase ─────────────────────────────────────────────────────

    #[test]
    fn test_new_database_empty() {
        let db = SignatureDatabase::new("mylib", "1.0");
        assert_eq!(db.lib_name, "mylib");
        assert_eq!(db.version, "1.0");
        assert!(db.patterns.is_empty());
    }

    #[test]
    fn test_add_pattern() {
        let mut db = SignatureDatabase::new("lib", "0");
        let p = FlirtPattern::new(vec![PatternByte::Exact(0x55)]);
        db.add_pattern(p);
        assert_eq!(db.patterns.len(), 1);
    }

    #[test]
    fn test_dedup_removes_duplicates() {
        let mut db = SignatureDatabase::new("lib", "0");
        let mut p1 = FlirtPattern::new(vec![PatternByte::Exact(0x55)]);
        p1.names.push(FlirtName {
            name: "f".to_string(),
            offset: 0,
            is_public: true,
            is_local: false,
        });
        let p2 = p1.clone();
        db.add_pattern(p1);
        db.add_pattern(p2);
        let before = db.patterns.len();
        db.dedup();
        assert!(db.patterns.len() < before);
        assert_eq!(db.stats.duplicates_removed, 1);
    }

    #[test]
    fn test_dedup_no_duplicates() {
        let mut db = SignatureDatabase::new("lib", "0");
        let p1 = FlirtPattern::new(vec![PatternByte::Exact(0x55)]);
        let p2 = FlirtPattern::new(vec![PatternByte::Exact(0x8B)]);
        db.add_pattern(p1);
        db.add_pattern(p2);
        db.dedup();
        assert_eq!(db.patterns.len(), 2);
        assert_eq!(db.stats.duplicates_removed, 0);
    }

    #[test]
    fn test_save_to_pat_contains_separator() {
        let db = SignatureDatabase::new("lib", "0");
        let text = db.save_to_pat();
        assert!(text.contains("---"));
    }

    #[test]
    fn test_load_from_pat_roundtrip() {
        let mut db = SignatureDatabase::new("lib", "1.0");
        let mut p = FlirtPattern::new(vec![
            PatternByte::Exact(0x55),
            PatternByte::Exact(0x8B),
            PatternByte::Exact(0xEC),
        ]);
        p.pattern_length = 3;
        p.names.push(FlirtName {
            name: "my_fn".to_string(),
            offset: 0,
            is_public: true,
            is_local: false,
        });
        db.add_pattern(p);
        let text = db.save_to_pat();

        let db2 = SignatureDatabase::load_from_pat(&text, "lib").unwrap();
        assert_eq!(db2.patterns.len(), 1);
        assert_eq!(db2.patterns[0].names[0].name, "my_fn");
    }

    // ── DatabaseBuilder ───────────────────────────────────────────────────────

    #[test]
    fn test_builder_empty_returns_empty_db() {
        let mut builder = DatabaseBuilder::new(BuilderConfig::default());
        let db = builder.build("lib", "1.0");
        assert!(db.patterns.is_empty());
    }

    #[test]
    fn test_builder_insufficient_samples_skipped() {
        let mut builder = DatabaseBuilder::new(BuilderConfig {
            min_samples: 3,
            ..BuilderConfig::default()
        });
        // Only 2 samples — below min_samples
        builder.add_sample(sample("fn_a", &[0x55, 0x8B, 0xEC, 0x83]));
        builder.add_sample(sample("fn_a", &[0x55, 0x8B, 0xEC, 0x83]));
        let db = builder.build("lib", "1.0");
        assert!(db.patterns.is_empty());
    }

    #[test]
    fn test_builder_generates_pattern_from_identical_samples() {
        let mut builder = DatabaseBuilder::new(BuilderConfig::default());
        let bytes = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
        for _ in 0..5 {
            builder.add_sample(sample("my_func", &bytes));
        }
        let db = builder.build("lib", "1.0");
        assert!(
            !db.patterns.is_empty(),
            "should generate at least one pattern"
        );
        assert_eq!(db.patterns[0].primary_name(), Some("my_func"));
    }

    #[test]
    fn test_builder_wildcard_ratio_filter() {
        let mut builder = DatabaseBuilder::new(BuilderConfig {
            max_wildcard_ratio: 0.1, // very strict
            min_samples: 2,
            entropy_threshold: 0.01, // very strict → most bytes become wildcards
            ..BuilderConfig::default()
        });
        // Highly variable bytes
        let bytes: Vec<Vec<u8>> = (0u8..5).map(|i| vec![i, i, i, i, i, i, i, i]).collect();
        for b in &bytes {
            builder.add_sample(sample("var_fn", b));
        }
        let db = builder.build("lib", "1.0");
        // With extremely strict settings, pattern should be filtered out
        // (all wildcards → ratio = 1.0 > 0.1)
        assert!(db.stats.too_many_wildcards > 0 || db.patterns.is_empty());
    }

    #[test]
    fn test_builder_stats_input_samples() {
        let mut builder = DatabaseBuilder::new(BuilderConfig::default());
        for _ in 0..5 {
            builder.add_sample(sample("f", &[0x55; 8]));
        }
        let db = builder.build("lib", "1.0");
        assert_eq!(db.stats.input_samples, 5);
    }

    #[test]
    fn test_builder_dedup_via_build() {
        let mut builder = DatabaseBuilder::new(BuilderConfig {
            min_samples: 2,
            ..BuilderConfig::default()
        });
        let bytes = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
        // Same function name, same bytes → should produce one pattern after dedup
        for _ in 0..4 {
            builder.add_sample(sample("dup_fn", &bytes));
        }
        let db = builder.build("lib", "1.0");
        // Build groups samples by name, so there's one group → one pattern
        assert_eq!(db.patterns.len(), 1);
    }

    // ── estimate_quality ──────────────────────────────────────────────────────

    #[test]
    fn test_estimate_quality_all_concrete() {
        let pats = vec![FlirtPattern::new(vec![PatternByte::Exact(0x55); 8])];
        let q = DatabaseBuilder::estimate_quality(&pats);
        assert!((q - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_estimate_quality_all_wildcard() {
        let pats = vec![FlirtPattern::new(vec![PatternByte::Wildcard; 8])];
        let q = DatabaseBuilder::estimate_quality(&pats);
        assert_eq!(q, 0.0);
    }

    #[test]
    fn test_estimate_quality_empty() {
        let q = DatabaseBuilder::estimate_quality(&[]);
        assert_eq!(q, 0.0);
    }

    #[test]
    fn test_estimate_quality_mixed() {
        let pats = vec![FlirtPattern::new(vec![
            PatternByte::Exact(0x55),
            PatternByte::Wildcard,
            PatternByte::Exact(0x8B),
            PatternByte::Wildcard,
        ])];
        let q = DatabaseBuilder::estimate_quality(&pats);
        assert!((q - 0.5).abs() < 1e-9);
    }

    // ── BuilderConfig default ─────────────────────────────────────────────────

    #[test]
    fn test_builder_config_defaults() {
        let cfg = BuilderConfig::default();
        assert!(cfg.min_pattern_len >= 1);
        assert!(cfg.max_wildcard_ratio > 0.0);
        assert!(cfg.min_samples >= 1);
        assert!(cfg.entropy_threshold > 0.0);
    }

    // ── Multiple functions ────────────────────────────────────────────────────

    #[test]
    fn test_builder_multiple_functions() {
        let mut builder = DatabaseBuilder::new(BuilderConfig {
            min_samples: 2,
            ..BuilderConfig::default()
        });
        let fn_a = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xEC, 0x10];
        let fn_b = vec![0x48u8, 0x89, 0xE5, 0x48, 0x83, 0xEC];
        for _ in 0..3 {
            builder.add_sample(sample("fn_a", &fn_a));
            builder.add_sample(sample("fn_b", &fn_b));
        }
        let db = builder.build("lib", "1.0");
        assert_eq!(db.patterns.len(), 2, "should have two distinct patterns");
    }

    #[test]
    fn test_builder_too_short_skipped_stat() {
        let mut builder = DatabaseBuilder::new(BuilderConfig {
            min_pattern_len: 16,
            min_samples: 2,
            ..BuilderConfig::default()
        });
        let bytes = vec![0x55u8, 0x8B]; // only 2 bytes, below 16
        for _ in 0..3 {
            builder.add_sample(sample("short_fn", &bytes));
        }
        let db = builder.build("lib", "1.0");
        assert!(db.stats.too_short_skipped > 0);
    }
}
