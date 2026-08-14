//! Pattern application engine.
//!
//! Provides the [`ApplyEngine`] which scans binary buffers and function
//! boundaries against a collection of [`crate::FlirtPattern`]s.

use crate::{FlirtMatch, FlirtPattern};

// ── ApplyConfig ───────────────────────────────────────────────────────────────

/// Configuration for the [`ApplyEngine`].
#[derive(Debug, Clone)]
pub struct ApplyConfig {
    /// Maximum number of pattern candidates to evaluate per function offset.
    pub max_candidates_per_offset: usize,
    /// Whether to require a passing CRC-16 check before yielding a match.
    pub require_crc: bool,
    /// Whether to verify that the buffer is long enough to cover
    /// `crc_offset + crc_len` before checking CRC.
    pub verify_total_len: bool,
    /// Minimum number of bytes a pattern must have to be considered.
    pub min_pattern_length: usize,
}

impl Default for ApplyConfig {
    fn default() -> Self {
        Self {
            max_candidates_per_offset: 64,
            require_crc: false,
            verify_total_len: false,
            min_pattern_length: 4,
        }
    }
}

// ── MatchCandidate ────────────────────────────────────────────────────────────

/// An intermediate match candidate before CRC / total-len verification.
#[derive(Debug, Clone)]
pub struct MatchCandidate {
    /// Index of the matching pattern in the engine's pattern list.
    pub pattern_idx: usize,
    /// Byte offset within the scanned buffer.
    pub offset: usize,
    /// Primary name of the matched function.
    pub name: String,
    /// Whether the CRC check passed (or was skipped).
    pub crc_passed: bool,
    /// Total length field from the pattern.
    pub total_len: u16,
}

// ── ApplyStats ────────────────────────────────────────────────────────────────

/// Statistics collected by an [`ApplyEngine`] run.
#[derive(Debug, Clone, Default)]
pub struct ApplyStats {
    /// Number of function entry points evaluated.
    pub functions_scanned: usize,
    /// Total number of successful pattern matches.
    pub total_matches: usize,
    /// Number of candidates rejected by the CRC check.
    pub crc_failures: usize,
    /// Number of patterns loaded into the engine.
    pub pattern_count: usize,
    /// Total elapsed time in nanoseconds (set by callers that measure time).
    pub elapsed_ns: u64,
}

// CRC-16/MCRF4XX is provided by crate::crc16_flirt (lib.rs).
// Re-export it so internal users of this module can call crc16_flirt directly.
pub use crate::crc16_flirt;

// ── Pattern matching helpers ──────────────────────────────────────────────────

/// Returns `true` if `pattern` matches at `data[offset..]`.
///
/// Each `None` entry is a wildcard that matches any byte.
#[must_use]
pub fn match_pattern_at(pattern: &[Option<u8>], data: &[u8], offset: usize) -> bool {
    let slice = &data[offset..];
    if slice.len() < pattern.len() {
        return false;
    }
    pattern
        .iter()
        .zip(slice.iter())
        .all(|(pb, &b)| pb.is_none_or(|expected| expected == b))
}

// ── ApplyEngine ───────────────────────────────────────────────────────────────

/// Scans a binary buffer against a set of FLIRT patterns.
pub struct ApplyEngine {
    patterns: Vec<FlirtPattern>,
    config: ApplyConfig,
    stats: ApplyStats,
}

impl ApplyEngine {
    /// Create a new engine from a list of patterns and a configuration.
    #[must_use]
    pub fn new(patterns: Vec<FlirtPattern>, config: ApplyConfig) -> Self {
        let pattern_count = patterns.len();
        Self {
            patterns,
            config,
            stats: ApplyStats {
                pattern_count,
                ..ApplyStats::default()
            },
        }
    }

    /// Scan all provided function start addresses in `data`.
    ///
    /// `base_addr` is the virtual address of `data[0]`.
    /// `fn_starts` lists absolute function entry-point addresses.
    ///
    /// Returns all [`FlirtMatch`] records found.
    #[must_use]
    pub fn scan_buffer(
        &mut self,
        data: &[u8],
        base_addr: u64,
        fn_starts: &[u64],
    ) -> Vec<FlirtMatch> {
        let mut results = Vec::with_capacity(fn_starts.len());

        for &addr in fn_starts {
            if addr < base_addr {
                continue;
            }
            let Ok(offset) = usize::try_from(addr - base_addr) else { continue };
            if offset >= data.len() {
                continue;
            }

            self.stats.functions_scanned += 1;
            let candidates = self.scan_function(data, offset);

            for cand in candidates {
                self.stats.total_matches += 1;
                let pat = &self.patterns[cand.pattern_idx];
                results.push(FlirtMatch {
                    address: addr,
                    function_name: cand.name,
                    lib_name: pat.lib_name.clone(),
                    confidence: if cand.crc_passed { 95 } else { 70 },
                    pattern_length: pat.pattern_len(),
                });
            }
        }

        results
    }

    /// Scan at a single function start offset within `data`.
    ///
    /// Returns all pattern candidates that matched at that offset.
    #[must_use]
    pub fn scan_function(&mut self, data: &[u8], fn_offset: usize) -> Vec<MatchCandidate> {
        let mut candidates = Vec::new();

        for (idx, pat) in self.patterns.iter().enumerate() {
            if candidates.len() >= self.config.max_candidates_per_offset {
                break;
            }
            if pat.bytes.len() < self.config.min_pattern_length {
                continue;
            }
            if !match_pattern_at(&pat.bytes, data, fn_offset) {
                continue;
            }

            // CRC verification
            let crc_passed = if pat.crc_len > 0 {
                let crc_bounds = fn_offset
                    .checked_add(pat.bytes.len())
                    .and_then(|v| v.checked_add(pat.crc_offset as usize))
                    .and_then(|off| off.checked_add(pat.crc_len as usize).map(|end| (off, end)));
                let (crc_off, crc_end) = if let Some(v) = crc_bounds { v } else {
                    if self.config.require_crc {
                        continue;
                    }
                    (data.len() + 1, data.len() + 1)
                };
                if crc_end <= data.len() {
                    let computed = crc16_flirt(&data[crc_off..crc_end]);
                    let passed = computed == pat.crc;
                    if !passed {
                        self.stats.crc_failures += 1;
                        if self.config.require_crc {
                            continue;
                        }
                    }
                    passed
                } else {
                    if self.config.require_crc {
                        continue;
                    }
                    false
                }
            } else {
                true
            };

            candidates.push(MatchCandidate {
                pattern_idx: idx,
                offset: fn_offset,
                name: pat.name.clone(),
                crc_passed,
                total_len: u16::try_from(pat.pattern_len()).unwrap_or(u16::MAX),
            });
        }

        candidates
    }

    /// Verify the CRC-16 of a region within `data`.
    ///
    /// Returns `true` if the CRC of `data[fn_offset + crc_offset .. fn_offset + crc_offset + crc_len]`
    /// equals `expected`.
    #[must_use]
    pub fn verify_crc(
        &self,
        data: &[u8],
        fn_offset: usize,
        crc_offset: u16,
        crc_len: u8,
        expected: u16,
    ) -> bool {
        if crc_len == 0 {
            return true;
        }
        let start = fn_offset + crc_offset as usize;
        let end = start + crc_len as usize;
        if end > data.len() {
            return false;
        }
        crc16_flirt(&data[start..end]) == expected
    }

    /// Return a reference to the accumulated statistics.
    #[must_use]
    pub const fn stats(&self) -> &ApplyStats {
        &self.stats
    }

    /// Reset all accumulated statistics (does not clear patterns).
    pub fn reset_stats(&mut self) {
        let pattern_count = self.stats.pattern_count;
        self.stats = ApplyStats {
            pattern_count,
            ..ApplyStats::default()
        };
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── crc16_flirt ──────────────────────────────────────────────────────────

    #[test]
    fn test_crc16_empty() {
        // crc16_flirt matches IDA flair's crc16.cpp (poly 0x8408 reflected,
        // init 0xFFFF, no final XOR). Empty input returns the init value.
        assert_eq!(crc16_flirt(&[]), 0xFFFF);
    }

    #[test]
    fn test_crc16_single_zero() {
        // deterministic
        let v1 = crc16_flirt(&[0]);
        let v2 = crc16_flirt(&[0]);
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_crc16_known_vector_123456789() {
        // crc16_flirt is CRC-16/MCRF4XX (poly 0x8408 reflected, init 0xFFFF,
        // no final XOR) as used by IDA FLIRT. Standard check value for
        // "123456789" is 0x6F91.
        assert_eq!(crc16_flirt(b"123456789"), 0x6F91);
    }

    #[test]
    fn test_crc16_two_byte_sequence() {
        let a = crc16_flirt(&[0x55, 0xAA]);
        let b = crc16_flirt(&[0x55, 0xAA]);
        assert_eq!(a, b);
    }

    #[test]
    fn test_crc16_different_inputs_differ() {
        let a = crc16_flirt(b"hello");
        let b = crc16_flirt(b"world");
        assert_ne!(a, b);
    }

    // ── match_pattern_at ──────────────────────────────────────────────────────

    #[test]
    fn test_match_exact() {
        let pat = vec![Some(0x55u8), Some(0x8B), Some(0xEC)];
        let data = [0x55u8, 0x8B, 0xEC, 0x00];
        assert!(match_pattern_at(&pat, &data, 0));
    }

    #[test]
    fn test_match_mismatch() {
        let pat = vec![Some(0x55u8), Some(0x8B), Some(0xEC)];
        let data = [0x55u8, 0x8B, 0xED, 0x00];
        assert!(!match_pattern_at(&pat, &data, 0));
    }

    #[test]
    fn test_match_wildcard() {
        let pat = vec![Some(0x55u8), None, Some(0xEC)];
        assert!(match_pattern_at(&pat, &[0x55, 0xFF, 0xEC], 0));
        assert!(match_pattern_at(&pat, &[0x55, 0x00, 0xEC], 0));
    }

    #[test]
    fn test_match_at_offset() {
        let pat = vec![Some(0xAA), Some(0xBB)];
        let data = [0x00u8, 0x00, 0xAA, 0xBB];
        assert!(match_pattern_at(&pat, &data, 2));
        assert!(!match_pattern_at(&pat, &data, 0));
    }

    #[test]
    fn test_match_too_short() {
        let pat = vec![Some(0x55); 10];
        let data = [0x55u8; 5];
        assert!(!match_pattern_at(&pat, &data, 0));
    }

    #[test]
    fn test_match_empty_pattern() {
        // empty pattern always matches
        let pat: Vec<Option<u8>> = vec![];
        let data = [0xFFu8; 4];
        assert!(match_pattern_at(&pat, &data, 0));
    }

    // ── ApplyEngine ───────────────────────────────────────────────────────────

    fn make_pat(name: &str, bytes: &[Option<u8>]) -> FlirtPattern {
        FlirtPattern::new(name.to_string(), bytes.to_vec())
    }

    #[test]
    fn test_engine_new_sets_pattern_count() {
        let pats = vec![make_pat("f", &[Some(0x55)])];
        let eng = ApplyEngine::new(pats, ApplyConfig::default());
        assert_eq!(eng.stats().pattern_count, 1);
    }

    #[test]
    fn test_engine_scan_function_finds_match() {
        let pats = vec![make_pat(
            "myfunc",
            &[Some(0x55), Some(0x8B), Some(0xEC), Some(0x83)],
        )];
        let mut eng = ApplyEngine::new(pats, ApplyConfig::default());
        let data = [0x55u8, 0x8B, 0xEC, 0x83, 0x00];
        let cands = eng.scan_function(&data, 0);
        assert_eq!(cands.len(), 1);
        assert_eq!(cands[0].name, "myfunc");
    }

    #[test]
    fn test_engine_scan_function_no_match() {
        let pats = vec![make_pat("f", &[Some(0xAA), Some(0xBB)])];
        let mut eng = ApplyEngine::new(pats, ApplyConfig::default());
        let data = [0x55u8, 0x8B, 0xEC];
        let cands = eng.scan_function(&data, 0);
        assert!(cands.is_empty());
    }

    #[test]
    fn test_engine_scan_buffer_returns_matches() {
        let pats = vec![make_pat(
            "stub",
            &[Some(0x90), Some(0x90), Some(0x90), Some(0x90)],
        )];
        let mut eng = ApplyEngine::new(pats, ApplyConfig::default());
        let data = [0x90u8; 8];
        let matches = eng.scan_buffer(&data, 0x1000, &[0x1000, 0x1004]);
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_engine_scan_buffer_skips_below_base() {
        let pats = vec![make_pat("f", &[Some(0x55)])];
        let mut eng = ApplyEngine::new(pats, ApplyConfig::default());
        let data = [0x55u8; 4];
        let matches = eng.scan_buffer(&data, 0x1000, &[0x500]);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_engine_scan_buffer_skips_out_of_range() {
        let pats = vec![make_pat("f", &[Some(0x55)])];
        let mut eng = ApplyEngine::new(pats, ApplyConfig::default());
        let data = [0x55u8; 4];
        let matches = eng.scan_buffer(&data, 0x1000, &[0x9999]);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_engine_functions_scanned_stat() {
        let pats = vec![make_pat("f", &[Some(0x55)])];
        let mut eng = ApplyEngine::new(pats, ApplyConfig::default());
        let data = [0x55u8; 4];
        let _ = eng.scan_buffer(&data, 0, &[0, 1, 2]);
        assert_eq!(eng.stats().functions_scanned, 3);
    }

    #[test]
    fn test_engine_reset_stats() {
        let pats = vec![make_pat("f", &[Some(0x55)])];
        let mut eng = ApplyEngine::new(pats, ApplyConfig::default());
        let data = [0x55u8; 4];
        let _ = eng.scan_buffer(&data, 0, &[0]);
        assert!(eng.stats().functions_scanned > 0);
        eng.reset_stats();
        assert_eq!(eng.stats().functions_scanned, 0);
        assert_eq!(eng.stats().pattern_count, 1);
    }

    #[test]
    fn test_engine_min_pattern_length_filter() {
        let cfg = ApplyConfig {
            min_pattern_length: 8,
            ..ApplyConfig::default()
        };
        let pats = vec![make_pat("short", &[Some(0x55), Some(0x8B)])]; // only 2 bytes
        let mut eng = ApplyEngine::new(pats, cfg);
        let data = [0x55u8, 0x8B, 0xEC, 0x83];
        let cands = eng.scan_function(&data, 0);
        assert!(cands.is_empty(), "too-short pattern should be skipped");
    }

    #[test]
    fn test_engine_max_candidates_per_offset() {
        let cfg = ApplyConfig {
            max_candidates_per_offset: 2,
            ..ApplyConfig::default()
        };
        let pats: Vec<FlirtPattern> = (0..10u8)
            .map(|i| make_pat(&format!("f{i}"), &[Some(0x55), Some(0x8B), Some(0xEC)]))
            .collect();
        let mut eng = ApplyEngine::new(pats, cfg);
        let data = [0x55u8, 0x8B, 0xEC];
        let cands = eng.scan_function(&data, 0);
        assert!(cands.len() <= 2);
    }

    // ── verify_crc ────────────────────────────────────────────────────────────

    #[test]
    fn test_verify_crc_zero_len_always_true() {
        let eng = ApplyEngine::new(vec![], ApplyConfig::default());
        assert!(eng.verify_crc(&[0x55, 0x8B], 0, 0, 0, 0xFFFF));
    }

    #[test]
    fn test_verify_crc_correct() {
        let data = b"123456789";
        let expected = crc16_flirt(b"123456789");
        let eng = ApplyEngine::new(vec![], ApplyConfig::default());
        assert!(eng.verify_crc(data, 0, 0, 9, expected));
    }

    #[test]
    fn test_verify_crc_wrong_value() {
        let data = b"123456789";
        let eng = ApplyEngine::new(vec![], ApplyConfig::default());
        assert!(!eng.verify_crc(data, 0, 0, 9, 0xDEAD));
    }

    #[test]
    fn test_verify_crc_out_of_bounds() {
        let data = [0x55u8; 4];
        let eng = ApplyEngine::new(vec![], ApplyConfig::default());
        assert!(!eng.verify_crc(&data, 0, 0, 10, 0));
    }

    // ── ApplyConfig defaults ─────────────────────────────────────────────────

    #[test]
    fn test_apply_config_defaults() {
        let cfg = ApplyConfig::default();
        assert!(cfg.max_candidates_per_offset > 0);
        assert!(!cfg.require_crc);
        assert!(cfg.min_pattern_length >= 1);
    }
}
