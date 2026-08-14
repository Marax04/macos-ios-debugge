// sig_matcher.rs — Match FLIRT signatures against binary data

use std::collections::HashMap;
use ahash::AHashMap;
use serde::{Deserialize, Serialize};

use crate::pat_parser_v2::{crc16_ccitt, PatternEntry};

// ─── Name binding ─────────────────────────────────────────────────────────────

/// A resolved symbol name at a specific offset in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NameBinding {
    /// Virtual address (or file offset) of the matched function start.
    pub func_offset: u64,
    /// Symbol name.
    pub name: String,
    /// Byte offset of the name relative to `func_offset`
    /// (0 for the primary name; non-zero for trailing module refs).
    pub name_offset: u16,
    /// True if this binding is the primary function name.
    pub is_primary: bool,
    /// The CRC-16 value that confirmed the match (0 if not checked).
    pub confirmed_crc16: u16,
}

// ─── Match result ─────────────────────────────────────────────────────────────

/// One successful pattern match at a specific location in the binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    /// Offset in the binary buffer where the match starts.
    pub offset: u64,
    /// Total length of the matched function (from the pattern entry).
    pub total_len: u32,
    /// All name bindings produced by this match.
    pub bindings: Vec<NameBinding>,
    /// CRC-16 disambiguation was performed and passed.
    pub crc16_verified: bool,
    /// Pattern source line (for diagnostics).
    pub source_line: usize,
}

impl MatchResult {
    /// Primary name binding (the function name at offset 0).
    #[must_use] 
    pub fn primary_name(&self) -> Option<&str> {
        self.bindings
            .iter()
            .find(|b| b.is_primary)
            .map(|b| b.name.as_str())
    }

    /// All names produced by this match, with their virtual addresses.
    #[must_use] 
    pub fn all_names(&self) -> Vec<(u64, &str)> {
        self.bindings
            .iter()
            .map(|b| (self.offset + u64::from(b.name_offset), b.name.as_str()))
            .collect()
    }
}

// ─── Matcher configuration ────────────────────────────────────────────────────

/// Configuration for the signature matcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatcherConfig {
    /// Only match at these specific offsets (if non-empty).
    pub candidate_offsets: Vec<u64>,
    /// If true, scan every byte offset; otherwise scan only aligned candidates.
    pub sliding_window: bool,
    /// Alignment requirement for candidate offsets (1 = no alignment).
    pub alignment: u64,
    /// Maximum number of match results to return (0 = unlimited).
    pub max_results: usize,
    /// Require CRC-16 verification before emitting a match.
    pub require_crc16: bool,
    /// Minimum number of concrete (non-wild) bytes in a pattern before it is used.
    pub min_concrete_bytes: usize,
}

impl Default for MatcherConfig {
    fn default() -> Self {
        Self {
            candidate_offsets: vec![],
            sliding_window: true,
            alignment: 1,
            max_results: 0,
            require_crc16: true,
            min_concrete_bytes: 2,
        }
    }
}

// ─── Signature matcher ────────────────────────────────────────────────────────

/// Matches a set of FLIRT `PatternEntry` objects against a binary buffer.
pub struct SigMatcher<'a> {
    patterns: &'a [PatternEntry],
    config: MatcherConfig,
}

impl<'a> SigMatcher<'a> {
    #[must_use] 
    pub fn new(patterns: &'a [PatternEntry]) -> Self {
        Self {
            patterns,
            config: MatcherConfig::default(),
        }
    }

    #[must_use] 
    pub fn with_config(mut self, config: MatcherConfig) -> Self {
        self.config = config;
        self
    }

    /// Run the full scan against `binary` and return all matches.
    #[must_use] 
    pub fn scan(&self, binary: &[u8]) -> Vec<MatchResult> {
        let mut results: Vec<MatchResult> = Vec::new();

        // Pre-filter patterns.
        let usable: Vec<&PatternEntry> = self
            .patterns
            .iter()
            .filter(|p| p.concrete_bytes() >= self.config.min_concrete_bytes)
            .collect();

        if usable.is_empty() || binary.is_empty() {
            return results;
        }

        let candidates = self.candidate_offsets(binary.len() as u64);

        'outer: for offset in candidates {
            let offset_usize = match usize::try_from(offset) {
                Ok(v) if v <= binary.len() => v,
                _ => continue,
            };
            let slice = &binary[offset_usize..];
            for pat in &usable {
                if let Some(result) = self.try_match(pat, slice, offset, binary) {
                    results.push(result);
                    if self.config.max_results > 0 && results.len() >= self.config.max_results {
                        break 'outer;
                    }
                }
            }
        }

        results
    }

    /// Try to match a single pattern at `offset` within `binary`.
    #[must_use] 
    pub fn try_match(
        &self,
        pat: &PatternEntry,
        slice: &[u8],
        offset: u64,
        binary: &[u8],
    ) -> Option<MatchResult> {
        if slice.len() < pat.pattern.len() {
            return None;
        }

        // Step 1: test leading pattern bytes.
        for (i, pb) in pat.pattern.iter().enumerate() {
            if !pb.matches(slice[i]) {
                return None;
            }
        }

        // Step 2: CRC-16 verification over the next `crc16_len` bytes.
        let crc16_start = pat.pattern.len();

        let crc16_verified;
        if pat.crc16_len > 0 {
            let full_offset = usize::try_from(offset).unwrap_or(usize::MAX) + crc16_start;
            if full_offset + pat.crc16_len as usize > binary.len() {
                if self.config.require_crc16 {
                    return None;
                }
                crc16_verified = false;
            } else {
                let crc_data = &binary[full_offset..full_offset + pat.crc16_len as usize];
                let computed = crc16_ccitt(crc_data);
                if computed != pat.crc16 {
                    return None; // CRC mismatch — different function.
                }
                crc16_verified = true;
            }
        } else {
            crc16_verified = false;
        }

        // Step 3: build name bindings.
        let mut bindings: Vec<NameBinding> = Vec::new();
        for r in &pat.refs {
            bindings.push(NameBinding {
                func_offset: offset,
                name: r.name.clone(),
                name_offset: r.offset,
                is_primary: r.is_primary,
                confirmed_crc16: if crc16_verified { pat.crc16 } else { 0 },
            });
        }

        Some(MatchResult {
            offset,
            total_len: pat.total_len,
            bindings,
            crc16_verified,
            source_line: pat.source_line,
        })
    }

    fn candidate_offsets(&self, binary_len: u64) -> Vec<u64> {
        if !self.config.candidate_offsets.is_empty() {
            return self.config.candidate_offsets.clone();
        }
        let align = self.config.alignment.max(1);
        let mut offsets: Vec<u64> = Vec::new();
        let max_pat_len = self.patterns.iter().map(|p| p.pattern.len()).max().unwrap_or(0) as u64;
        let limit = binary_len.saturating_sub(max_pat_len);
        let mut off = 0u64;
        while off < limit {
            offsets.push(off);
            off += align;
        }
        offsets
    }
}

// ─── Match deduplication ──────────────────────────────────────────────────────

/// Deduplicates matches: if multiple patterns match the same offset, keep the
/// best one (most concrete bytes, then CRC-verified, then lowest source line).
#[must_use] 
pub fn deduplicate_matches(mut results: Vec<MatchResult>) -> Vec<MatchResult> {
    // Sort by offset, then concrete preference.
    results.sort_unstable_by(|a, b| {
        a.offset
            .cmp(&b.offset)
            .then_with(|| b.crc16_verified.cmp(&a.crc16_verified))
            .then_with(|| a.source_line.cmp(&b.source_line))
    });

    // Keep only the first match per offset.
    let mut seen: HashMap<u64, bool> = HashMap::new();
    results.retain(|r| seen.insert(r.offset, true).is_none());
    results
}

// ─── Batch scan ───────────────────────────────────────────────────────────────

/// Scan multiple binaries and return results keyed by an identifier.
#[must_use] 
pub fn batch_scan(
    patterns: &[PatternEntry],
    binaries: &[(String, &[u8])],
    config: &MatcherConfig,
) -> AHashMap<String, Vec<MatchResult>> {
    let mut out: AHashMap<String, Vec<MatchResult>> = AHashMap::new();
    for (name, data) in binaries {
        let matcher = SigMatcher::new(patterns).with_config(config.clone());
        let results = deduplicate_matches(matcher.scan(data));
        out.insert(name.clone(), results);
    }
    out
}

// ─── Summary statistics ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    pub total_matches: usize,
    pub crc16_verified: usize,
    pub unique_names: usize,
    pub offsets_matched: Vec<u64>,
}

impl ScanStats {
    #[must_use] 
    pub fn from(results: &[MatchResult]) -> Self {
        let total_matches = results.len();
        let crc16_verified = results.iter().filter(|r| r.crc16_verified).count();
        let mut names: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut offsets: Vec<u64> = Vec::new();
        for r in results {
            offsets.push(r.offset);
            for b in &r.bindings {
                names.insert(&b.name);
            }
        }
        Self {
            total_matches,
            crc16_verified,
            unique_names: names.len(),
            offsets_matched: offsets,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pat_parser_v2::{ModuleRef, ModuleRefKind, PatByte, PatternEntry};

    fn make_entry(pattern: Vec<PatByte>, crc16_len: u8, crc16: u16, name: &str) -> PatternEntry {
        PatternEntry {
            pattern,
            crc16_len,
            crc16,
            total_len: 16,
            refs: vec![ModuleRef {
                offset: 0,
                kind: ModuleRefKind::Public,
                delta: 0,
                name: name.to_string(),
                is_primary: true,
            }],
            source_line: 1,
        }
    }

    #[test]
    fn test_exact_pattern_matches() {
        let pat = make_entry(vec![PatByte::Exact(0x55), PatByte::Exact(0x8B)], 0, 0, "foo");
        let binary = vec![0x55u8, 0x8B, 0xEC, 0x83];
        let patterns = [pat];
        let matcher = SigMatcher::new(&patterns).with_config(MatcherConfig {
            require_crc16: false,
            ..Default::default()
        });
        let results = matcher.scan(&binary);
        assert!(!results.is_empty());
        assert_eq!(results[0].offset, 0);
        assert_eq!(results[0].primary_name(), Some("foo"));
    }

    #[test]
    fn test_wildcard_pattern_matches() {
        let pat = make_entry(
            vec![PatByte::Exact(0x55), PatByte::Wild, PatByte::Exact(0xEC)],
            0,
            0,
            "bar",
        );
        let binary = vec![0x55u8, 0xAB, 0xEC, 0x00];
        let patterns = [pat];
        let matcher = SigMatcher::new(&patterns).with_config(MatcherConfig {
            require_crc16: false,
            min_concrete_bytes: 2,
            ..Default::default()
        });
        let results = matcher.scan(&binary);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_pattern_does_not_match() {
        let pat = make_entry(vec![PatByte::Exact(0x55), PatByte::Exact(0x8B)], 0, 0, "foo");
        let binary = vec![0xCC, 0xCC, 0xCC];
        let patterns = [pat];
        let matcher = SigMatcher::new(&patterns).with_config(MatcherConfig {
            require_crc16: false,
            ..Default::default()
        });
        let results = matcher.scan(&binary);
        assert!(results.is_empty());
    }

    #[test]
    fn test_crc16_verification_pass() {
        let data = b"ABCDE";
        let crc = crc16_ccitt(&data[2..4]); // 2 bytes CRC region after 2-byte pattern.
        let pat = make_entry(
            vec![PatByte::Exact(data[0]), PatByte::Exact(data[1])],
            2,
            crc,
            "verified_func",
        );
        let patterns = [pat];
        let matcher = SigMatcher::new(&patterns).with_config(MatcherConfig {
            require_crc16: true,
            min_concrete_bytes: 1,
            ..Default::default()
        });
        let results = matcher.scan(data);
        assert!(results.iter().any(|r| r.crc16_verified));
    }

    #[test]
    fn test_crc16_verification_fail() {
        let pat = make_entry(
            vec![PatByte::Exact(0x55), PatByte::Exact(0x8B)],
            2,
            0xDEAD, // wrong CRC
            "ghost_func",
        );
        let binary = vec![0x55u8, 0x8B, 0x00, 0x00, 0x00];
        let patterns = [pat];
        let matcher = SigMatcher::new(&patterns).with_config(MatcherConfig {
            require_crc16: true,
            min_concrete_bytes: 1,
            ..Default::default()
        });
        let results = matcher.scan(&binary);
        assert!(results.is_empty());
    }

    #[test]
    fn test_scan_finds_match_at_non_zero_offset() {
        let pat = make_entry(vec![PatByte::Exact(0xCC)], 0, 0, "breakpoint");
        let binary = vec![0x00u8, 0x00, 0xCC, 0x00];
        let patterns = [pat];
        let matcher = SigMatcher::new(&patterns).with_config(MatcherConfig {
            require_crc16: false,
            min_concrete_bytes: 1,
            ..Default::default()
        });
        let results = matcher.scan(&binary);
        assert!(results.iter().any(|r| r.offset == 2));
    }

    #[test]
    fn test_max_results_limit() {
        let pat = make_entry(vec![PatByte::Exact(0x90)], 0, 0, "nop");
        let binary = vec![0x90u8; 100];
        let patterns = [pat];
        let matcher = SigMatcher::new(&patterns).with_config(MatcherConfig {
            require_crc16: false,
            min_concrete_bytes: 1,
            max_results: 5,
            ..Default::default()
        });
        let results = matcher.scan(&binary);
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_deduplicate_keeps_one_per_offset() {
        let results = vec![
            MatchResult {
                offset: 0,
                total_len: 8,
                bindings: vec![],
                crc16_verified: false,
                source_line: 1,
            },
            MatchResult {
                offset: 0,
                total_len: 8,
                bindings: vec![],
                crc16_verified: true,
                source_line: 2,
            },
        ];
        let dedup = deduplicate_matches(results);
        assert_eq!(dedup.len(), 1);
    }

    #[test]
    fn test_scan_stats() {
        let pat = make_entry(vec![PatByte::Exact(0x55)], 0, 0, "func");
        let binary = vec![0x55u8, 0xCC, 0x55, 0xCC];
        let patterns = [pat];
        let matcher = SigMatcher::new(&patterns).with_config(MatcherConfig {
            require_crc16: false,
            min_concrete_bytes: 1,
            ..Default::default()
        });
        let results = matcher.scan(&binary);
        let stats = ScanStats::from(&results);
        assert!(stats.total_matches >= 2);
    }

    #[test]
    fn test_candidate_offsets_alignment() {
        let pat = make_entry(vec![PatByte::Exact(0x55)], 0, 0, "aligned");
        let binary = vec![0x55u8; 100];
        let patterns = [pat];
        let matcher = SigMatcher::new(&patterns).with_config(MatcherConfig {
            require_crc16: false,
            min_concrete_bytes: 1,
            alignment: 4,
            ..Default::default()
        });
        let results = matcher.scan(&binary);
        // All match offsets should be multiples of 4.
        for r in &results {
            assert_eq!(r.offset % 4, 0, "offset {} not aligned to 4", r.offset);
        }
    }

    #[test]
    fn test_all_names_in_result() {
        let mut entry = make_entry(vec![PatByte::Exact(0xAA)], 0, 0, "primary");
        entry.refs.push(ModuleRef {
            offset: 4,
            kind: ModuleRefKind::Ref,
            delta: 0,
            name: "helper".to_string(),
            is_primary: false,
        });
        let binary = vec![0xAAu8; 16];
        let patterns = [entry];
        let matcher = SigMatcher::new(&patterns).with_config(MatcherConfig {
            require_crc16: false,
            min_concrete_bytes: 1,
            ..Default::default()
        });
        let results = matcher.scan(&binary);
        let names: Vec<_> = results[0].all_names();
        assert!(names.iter().any(|(_, n)| *n == "primary"));
        assert!(names.iter().any(|(_, n)| *n == "helper"));
    }

    #[test]
    fn test_empty_binary_returns_empty() {
        let pat = make_entry(vec![PatByte::Exact(0x55)], 0, 0, "func");
        let binary: &[u8] = &[];
        let patterns = [pat];
        let matcher = SigMatcher::new(&patterns);
        let results = matcher.scan(binary);
        assert!(results.is_empty());
    }

    #[test]
    fn test_batch_scan() {
        let pat = make_entry(vec![PatByte::Exact(0xBB)], 0, 0, "bb_func");
        let bin1 = vec![0xBBu8, 0x00];
        let bin2 = vec![0x00u8, 0x00];
        let binaries = vec![
            ("bin1".to_string(), bin1.as_slice()),
            ("bin2".to_string(), bin2.as_slice()),
        ];
        let results = batch_scan(
            &[pat],
            &binaries,
            &MatcherConfig {
                require_crc16: false,
                min_concrete_bytes: 1,
                ..Default::default()
            },
        );
        assert!(!results["bin1"].is_empty());
        assert!(results["bin2"].is_empty());
    }
}
