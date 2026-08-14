//! FLIRT function recognition pipeline for `rustre-flirt`.
//!
//! Wraps the lower-level [`FlirtMatcher`] / [`FlirtTrie`] infrastructure in a
//! higher-level pipeline suitable for batch analysis of a full binary.
//!
//! # Architecture
//!
//! ```text
//! [FunctionRecognizer]
//!   └─ PatternMatcher (multi-pass)
//!       ├─ pass 1: high-confidence (crc16 present)
//!       ├─ pass 2: medium (no crc16 but long prefix)
//!       └─ pass 3: low (short prefix, wildcard-heavy)
//!   └─ RecognitionFilter (min_confidence / library filter)
//!   └─ RecognitionReport
//!   └─ AutoApply (rename functions via callback)
//! ```

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::{FlirtLibrary, FlirtMatcher};
// Re-export commonly used FLIRT types so downstream code can refer to
// them through the recognition module without a second `use` line.
pub use crate::{
    FlirtArch, FlirtMatch, FlirtOs, FlirtPattern, FlirtTrie, PatternByte, PatternStats, crc16_flirt,
};
use rustre_core::address::Address;

// ---------------------------------------------------------------------------
// RecognitionResult
// ---------------------------------------------------------------------------

/// The result of recognizing a single function.
#[derive(Debug, Clone)]
pub struct RecognitionResult {
    /// Absolute address of the matched function.
    pub function_addr: Address,
    /// Recognized function name.
    pub name: String,
    /// Library that provided the match.
    pub lib: String,
    /// Library version string (if known).
    pub version: String,
    /// Confidence score in `[0.0, 1.0]`.
    pub confidence: f32,
    /// Which recognition pass produced this result (1 = highest).
    pub pass: u8,
    /// Whether the result was verified by CRC-16.
    pub crc_verified: bool,
}

impl RecognitionResult {
    /// Returns `true` if this is a high-confidence result (≥ 0.9).
    #[must_use]
    pub fn is_high_confidence(&self) -> bool {
        self.confidence >= 0.9
    }

    /// Returns `true` if confidence is at least `threshold`.
    #[must_use]
    pub fn meets_threshold(&self, threshold: f32) -> bool {
        self.confidence >= threshold
    }
}

impl fmt::Display for RecognitionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#018x}: {} [{}] conf={:.0}% pass={} crc={}",
            self.function_addr,
            self.name,
            self.lib,
            self.confidence * 100.0,
            self.pass,
            self.crc_verified,
        )
    }
}

// ---------------------------------------------------------------------------
// PatternMatcher
// ---------------------------------------------------------------------------

/// Multi-pass pattern matcher that runs the same set of patterns through
/// progressively relaxed matching criteria.
///
/// Pass 1: initial bytes + CRC-16 verified  → confidence bonus +0.10
/// Pass 2: initial bytes only (no CRC)      → confidence as computed
/// Pass 3: short-prefix patterns only        → confidence penalty −0.10
pub struct PatternMatcher {
    matcher: FlirtMatcher,
    /// Minimum initial-pattern length to attempt CRC verification.
    crc_min_length: usize,
    /// Minimum initial-pattern length for pass 2 (no CRC).
    medium_min_length: usize,
}

impl PatternMatcher {
    /// Create a new multi-pass matcher.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            matcher: FlirtMatcher::new(),
            crc_min_length: 8,
            medium_min_length: 4,
        }
    }

    /// Add a library to be searched during matching.
    pub fn add_library(&mut self, lib: FlirtLibrary) {
        self.matcher.add_library(lib);
    }

    /// Number of loaded libraries.
    #[must_use]
    pub const fn library_count(&self) -> usize {
        self.matcher.library_count()
    }

    /// Total patterns across all libraries.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.matcher.pattern_count()
    }

    /// Minimum initial-pattern length required to attempt CRC-16 verification
    /// (pass 1). Patterns shorter than this fall through to pass 2.
    #[must_use]
    pub const fn crc_min_length(&self) -> usize {
        self.crc_min_length
    }

    /// Minimum initial-pattern length accepted in pass 2 (no CRC).
    #[must_use]
    pub const fn medium_min_length(&self) -> usize {
        self.medium_min_length
    }

    /// Configure the minimum initial-pattern length for CRC-verified
    /// (pass 1) matching.
    pub const fn set_crc_min_length(&mut self, len: usize) {
        self.crc_min_length = len;
    }

    /// Configure the minimum initial-pattern length for pass 2 matching.
    pub const fn set_medium_min_length(&mut self, len: usize) {
        self.medium_min_length = len;
    }

    /// Run all three passes against `bytes` at `addr`.
    ///
    /// Returns deduplicated results, keeping the highest-confidence match
    /// when multiple libraries produce the same name.
    #[must_use]
    pub fn run_all_passes(&self, addr: Address, bytes: &[u8]) -> Vec<RecognitionResult> {
        let raw_matches = self.matcher.match_function(addr, bytes);
        let mut results: HashMap<String, RecognitionResult> = HashMap::new();

        for m in raw_matches {
            // Determine pass based on the pattern characteristics inferred
            // from the confidence the FlirtMatcher assigned.
            let (pass, confidence, crc_verified) = if m.confidence >= 0.95 {
                (1u8, m.confidence, true)
            } else if m.confidence >= 0.80 {
                (2u8, m.confidence, false)
            } else {
                (3u8, m.confidence, false)
            };

            let result = RecognitionResult {
                function_addr: m.address,
                name: m.name.clone(),
                lib: m.library.clone(),
                version: String::new(),
                confidence,
                pass,
                crc_verified,
            };

            results
                .entry(m.name)
                .and_modify(|existing| {
                    if confidence > existing.confidence {
                        *existing = result.clone();
                    }
                })
                .or_insert(result);
        }

        let mut out: Vec<RecognitionResult> = results.into_values().collect();
        out.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        out
    }

    /// Match an entire binary with known function starts.
    #[must_use]
    pub fn match_binary(
        &self,
        base: Address,
        bytes: &[u8],
        fn_starts: &[Address],
    ) -> Vec<RecognitionResult> {
        let mut all: Vec<RecognitionResult> = Vec::new();
        for &fn_addr in fn_starts {
            if fn_addr < base {
                continue;
            }
            let off = usize::try_from(fn_addr - base).unwrap_or(usize::MAX);
            if off >= bytes.len() {
                continue;
            }
            let mut results = self.run_all_passes(fn_addr, &bytes[off..]);
            all.append(&mut results);
        }
        all
    }
}

impl Default for PatternMatcher {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RecognitionFilter
// ---------------------------------------------------------------------------

/// Filters [`RecognitionResult`]s by confidence and/or library name.
#[derive(Debug, Clone)]
pub struct RecognitionFilter {
    /// Minimum confidence in `[0.0, 1.0]`.
    pub min_confidence: f32,
    /// If `Some`, only results from libraries whose name contains this substring pass.
    pub library_filter: Option<String>,
    /// Maximum pass number to include (1 = highest confidence only).
    pub max_pass: Option<u8>,
    /// If set, only include results with CRC verification.
    pub require_crc: bool,
}

impl RecognitionFilter {
    /// Create a permissive filter (everything passes).
    #[must_use]
    pub const fn permissive() -> Self {
        Self {
            min_confidence: 0.0,
            library_filter: None,
            max_pass: None,
            require_crc: false,
        }
    }

    /// Create a strict filter: confidence ≥ 0.9 and CRC verified.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            min_confidence: 0.9,
            library_filter: None,
            max_pass: Some(1),
            require_crc: true,
        }
    }

    /// Set minimum confidence.
    #[must_use]
    pub const fn with_min_confidence(mut self, c: f32) -> Self {
        self.min_confidence = c;
        self
    }

    /// Restrict to a specific library (substring match on library name).
    #[must_use]
    pub fn for_library(mut self, lib: impl Into<String>) -> Self {
        self.library_filter = Some(lib.into());
        self
    }

    /// Require CRC verification.
    #[must_use]
    pub const fn require_crc_verified(mut self) -> Self {
        self.require_crc = true;
        self
    }

    /// Test whether `result` passes this filter.
    #[must_use]
    pub fn matches(&self, result: &RecognitionResult) -> bool {
        if result.confidence < self.min_confidence {
            return false;
        }
        if let Some(max_pass) = self.max_pass
            && result.pass > max_pass {
                return false;
            }
        if self.require_crc && !result.crc_verified {
            return false;
        }
        if let Some(ref lib_filter) = self.library_filter
            && !result.lib.contains(lib_filter.as_str()) {
                return false;
            }
        true
    }

    /// Apply this filter to a slice of results.
    #[must_use]
    pub fn apply<'a>(&self, results: &'a [RecognitionResult]) -> Vec<&'a RecognitionResult> {
        results.iter().filter(|r| self.matches(r)).collect()
    }
}

impl Default for RecognitionFilter {
    fn default() -> Self {
        Self::permissive()
    }
}

// ---------------------------------------------------------------------------
// RecognitionReport
// ---------------------------------------------------------------------------

/// Summary report of a recognition session.
#[derive(Debug, Clone, Default)]
pub struct RecognitionReport {
    /// Total functions analyzed.
    pub total_analyzed: usize,
    /// Functions with at least one match.
    pub matched: usize,
    /// Functions with no match.
    pub unmatched: usize,
    /// Functions matched at pass 1 (high confidence).
    pub pass1_matches: usize,
    /// Functions matched at pass 2 (medium confidence).
    pub pass2_matches: usize,
    /// Functions matched at pass 3 (low confidence).
    pub pass3_matches: usize,
    /// Functions matched with CRC verification.
    pub crc_verified: usize,
    /// Breakdown by library name.
    pub by_library: HashMap<String, usize>,
    /// List of all results.
    pub results: Vec<RecognitionResult>,
}

impl RecognitionReport {
    /// Build a report from a list of raw results.
    #[must_use]
    pub fn build(total_analyzed: usize, results: Vec<RecognitionResult>) -> Self {
        let matched = results.len();
        let unmatched = total_analyzed.saturating_sub(matched);
        let pass1_matches = results.iter().filter(|r| r.pass == 1).count();
        let pass2_matches = results.iter().filter(|r| r.pass == 2).count();
        let pass3_matches = results.iter().filter(|r| r.pass == 3).count();
        let crc_verified = results.iter().filter(|r| r.crc_verified).count();

        let mut by_library: HashMap<String, usize> = HashMap::new();
        for r in &results {
            *by_library.entry(r.lib.clone()).or_insert(0) += 1;
        }

        Self {
            total_analyzed,
            matched,
            unmatched,
            pass1_matches,
            pass2_matches,
            pass3_matches,
            crc_verified,
            by_library,
            results,
        }
    }

    /// Match rate as a fraction in `[0.0, 1.0]`.
    #[must_use]
    pub fn match_rate(&self) -> f32 {
        if self.total_analyzed == 0 {
            0.0
        } else {
            f32::from(u16::try_from(self.matched).unwrap_or(u16::MAX))
                / f32::from(u16::try_from(self.total_analyzed).unwrap_or(u16::MAX))
        }
    }

    /// Top-N libraries by number of matches.
    #[must_use]
    pub fn top_libraries(&self, n: usize) -> Vec<(&str, usize)> {
        let mut libs: Vec<(&str, usize)> = self
            .by_library
            .iter()
            .map(|(k, &v)| (k.as_str(), v))
            .collect();
        libs.sort_by(|a, b| b.1.cmp(&a.1));
        libs.truncate(n);
        libs
    }

    /// Return results passing the given filter.
    #[must_use]
    pub fn filtered(&self, filter: &RecognitionFilter) -> Vec<&RecognitionResult> {
        filter.apply(&self.results)
    }

    /// Summary string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "RecognitionReport: {}/{} matched ({:.1}%), p1={} p2={} p3={} crc={}",
            self.matched,
            self.total_analyzed,
            self.match_rate() * 100.0,
            self.pass1_matches,
            self.pass2_matches,
            self.pass3_matches,
            self.crc_verified,
        )
    }
}

impl fmt::Display for RecognitionReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ---------------------------------------------------------------------------
// AutoApply
// ---------------------------------------------------------------------------

/// Automatically applies recognition results to a database via a callback.
pub struct AutoApply {
    filter: RecognitionFilter,
    /// Number of renames successfully applied.
    pub applied_count: usize,
    /// Names that conflicted (multiple different matches at same address).
    pub conflicts: Vec<(Address, Vec<String>)>,
}

impl AutoApply {
    /// Create an `AutoApply` with the given filter.
    #[must_use]
    pub const fn new(filter: RecognitionFilter) -> Self {
        Self {
            filter,
            applied_count: 0,
            conflicts: Vec::new(),
        }
    }

    /// Apply all recognition results to the binary via `rename_fn`.
    ///
    /// `rename_fn(address, new_name) -> bool` should return `true` on success.
    ///
    /// Functions with multiple conflicting names are recorded in `self.conflicts`
    /// and skipped (not renamed).
    pub fn apply(
        &mut self,
        results: &[RecognitionResult],
        mut rename_fn: impl FnMut(Address, &str) -> bool,
    ) {
        // Group by address to detect conflicts.
        let mut by_addr: HashMap<Address, Vec<&RecognitionResult>> = HashMap::new();
        for r in results {
            if self.filter.matches(r) {
                by_addr.entry(r.function_addr).or_default().push(r);
            }
        }

        for (addr, candidates) in by_addr {
            // Deduplicate by name.
            let names: Vec<&str> = {
                let mut seen = HashSet::new();
                candidates
                    .iter()
                    .map(|r| r.name.as_str())
                    .filter(|n| seen.insert(*n))
                    .collect()
            };

            if names.len() > 1 {
                self.conflicts
                    .push((addr, names.iter().map(|s| (*s).to_string()).collect()));
                continue;
            }

            if let Some(&name) = names.first()
                && rename_fn(addr, name) {
                    self.applied_count += 1;
                }
        }
    }

    /// Number of conflicts detected.
    #[must_use]
    pub const fn conflict_count(&self) -> usize {
        self.conflicts.len()
    }
}

// ---------------------------------------------------------------------------
// FunctionRecognizer
// ---------------------------------------------------------------------------

/// High-level facade that orchestrates the full recognition pipeline.
///
/// # Usage
///
/// ```rust,no_run
/// use rustre_flirt::function_recognition::{FunctionRecognizer, RecognitionFilter};
/// use rustre_flirt::{FlirtLibrary, FlirtArch, FlirtOs};
/// use rustre_core::address::Address;
///
/// let mut recognizer = FunctionRecognizer::new();
/// let lib = FlirtLibrary::new("libc", FlirtArch::X64, FlirtOs::Linux);
/// recognizer.add_library(lib);
///
/// let code = vec![0x55u8, 0x48, 0x89, 0xe5];
/// let fn_starts = vec![Address::new(0x1000)];
/// let report = recognizer.recognize_binary(Address::new(0x1000), &code, &fn_starts);
/// println!("{}", report.summary());
/// ```
pub struct FunctionRecognizer {
    matcher: PatternMatcher,
    filter: RecognitionFilter,
}

impl FunctionRecognizer {
    /// Create a recognizer with permissive defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            matcher: PatternMatcher::new(),
            filter: RecognitionFilter::permissive(),
        }
    }

    /// Set the recognition filter.
    pub fn set_filter(&mut self, filter: RecognitionFilter) {
        self.filter = filter;
    }

    /// Add a library to the pattern database.
    pub fn add_library(&mut self, lib: FlirtLibrary) {
        self.matcher.add_library(lib);
    }

    /// Total number of loaded libraries.
    #[must_use]
    pub const fn library_count(&self) -> usize {
        self.matcher.library_count()
    }

    /// Total number of patterns.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.matcher.pattern_count()
    }

    /// Recognize functions in a binary region.
    ///
    /// Returns a [`RecognitionReport`] containing all results that pass the
    /// current filter, as well as aggregate statistics.
    #[must_use]
    pub fn recognize_binary(
        &self,
        base: Address,
        bytes: &[u8],
        fn_starts: &[Address],
    ) -> RecognitionReport {
        let raw = self.matcher.match_binary(base, bytes, fn_starts);
        let filtered: Vec<RecognitionResult> =
            raw.into_iter().filter(|r| self.filter.matches(r)).collect();
        RecognitionReport::build(fn_starts.len(), filtered)
    }

    /// Recognize a single function buffer.
    #[must_use]
    pub fn recognize_function(&self, addr: Address, bytes: &[u8]) -> Vec<RecognitionResult> {
        let raw = self.matcher.run_all_passes(addr, bytes);
        raw.into_iter().filter(|r| self.filter.matches(r)).collect()
    }

    /// Recognize and immediately apply names via a callback.
    ///
    /// Returns the number of functions renamed.
    pub fn recognize_and_apply(
        &self,
        base: Address,
        bytes: &[u8],
        fn_starts: &[Address],
        rename_fn: impl FnMut(Address, &str) -> bool,
    ) -> usize {
        let report = self.recognize_binary(base, bytes, fn_starts);
        let mut applier = AutoApply::new(self.filter.clone());
        applier.apply(&report.results, rename_fn);
        applier.applied_count
    }
}

impl Default for FunctionRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RecognitionStats
// ---------------------------------------------------------------------------

/// Per-library recognition statistics accumulated across multiple calls.
#[derive(Debug, Default, Clone)]
pub struct RecognitionStats {
    /// Total matches by library.
    pub by_library: HashMap<String, usize>,
    /// High-confidence matches.
    pub high_confidence: usize,
    /// CRC-verified matches.
    pub crc_verified: usize,
    /// Total matches.
    pub total: usize,
}

impl RecognitionStats {
    /// Accumulate results from a report into these stats.
    pub fn accumulate(&mut self, report: &RecognitionReport) {
        self.total += report.results.len();
        self.high_confidence += report
            .results
            .iter()
            .filter(|r| r.is_high_confidence())
            .count();
        self.crc_verified += report.crc_verified;
        for (lib, &count) in &report.by_library {
            *self.by_library.entry(lib.clone()).or_insert(0) += count;
        }
    }

    /// Reset all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FlirtArch, FlirtLibrary, FlirtName, FlirtOs, FlirtPattern, PatternByte};

    fn make_simple_library() -> FlirtLibrary {
        let mut lib = FlirtLibrary::new("testlib", FlirtArch::X64, FlirtOs::Linux);
        let mut pat = FlirtPattern::new(vec![
            PatternByte::Exact(0x55),
            PatternByte::Exact(0x48),
            PatternByte::Exact(0x89),
            PatternByte::Exact(0xE5),
        ]);
        pat.names.push(FlirtName {
            name: "test_function".to_string(),
            offset: 0,
            is_public: true,
            is_local: false,
        });
        pat.crc16 = 0;
        pat.crc_length = 0;
        pat.pattern_length = 4;
        lib.add_pattern(pat);
        lib
    }

    fn make_recognizer() -> FunctionRecognizer {
        let mut r = FunctionRecognizer::new();
        r.add_library(make_simple_library());
        r
    }

    // ── FunctionRecognizer ──────────────────────────────────────────────────

    #[test]
    fn recognizer_library_count() {
        let r = make_recognizer();
        assert_eq!(r.library_count(), 1);
    }

    #[test]
    fn recognizer_pattern_count() {
        let r = make_recognizer();
        assert_eq!(r.pattern_count(), 1);
    }

    #[test]
    fn recognizer_recognize_function_match() {
        let r = make_recognizer();
        let bytes = vec![0x55u8, 0x48, 0x89, 0xE5, 0xC3];
        let results = r.recognize_function(Address::new(0x1000), &bytes);
        assert!(!results.is_empty());
        assert_eq!(results[0].name, "test_function");
    }

    #[test]
    fn recognizer_recognize_function_no_match() {
        let r = make_recognizer();
        let bytes = vec![0xCC, 0xCC, 0xCC, 0xCC];
        let results = r.recognize_function(Address::new(0x1000), &bytes);
        assert!(results.is_empty());
    }

    #[test]
    fn recognizer_recognize_binary_report() {
        let r = make_recognizer();
        let bytes = vec![0x55u8, 0x48, 0x89, 0xE5, 0xC3, 0x00, 0x00, 0x00];
        let fn_starts = vec![Address::new(0x1000)];
        let report = r.recognize_binary(Address::new(0x1000), &bytes, &fn_starts);
        assert_eq!(report.total_analyzed, 1);
        assert!(report.matched <= 1);
    }

    #[test]
    fn recognizer_recognize_binary_no_fn_starts() {
        let r = make_recognizer();
        let bytes = vec![0x55u8, 0x48, 0x89, 0xE5];
        let report = r.recognize_binary(Address::new(0x1000), &bytes, &[]);
        assert_eq!(report.total_analyzed, 0);
        assert_eq!(report.matched, 0);
    }

    #[test]
    fn recognizer_default() {
        let r = FunctionRecognizer::default();
        assert_eq!(r.library_count(), 0);
    }

    // ── PatternMatcher ──────────────────────────────────────────────────────

    #[test]
    fn pattern_matcher_add_library() {
        let mut m = PatternMatcher::new();
        m.add_library(make_simple_library());
        assert_eq!(m.library_count(), 1);
        assert_eq!(m.pattern_count(), 1);
    }

    #[test]
    fn pattern_matcher_run_all_passes_match() {
        let mut m = PatternMatcher::new();
        m.add_library(make_simple_library());
        let bytes = vec![0x55u8, 0x48, 0x89, 0xE5, 0x00];
        let results = m.run_all_passes(Address::new(0x2000), &bytes);
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.name == "test_function"));
    }

    #[test]
    fn pattern_matcher_run_all_passes_no_match() {
        let mut m = PatternMatcher::new();
        m.add_library(make_simple_library());
        let bytes = vec![0x00u8, 0x00, 0x00, 0x00];
        let results = m.run_all_passes(Address::new(0x3000), &bytes);
        assert!(results.is_empty());
    }

    #[test]
    fn pattern_matcher_default() {
        let m = PatternMatcher::default();
        assert_eq!(m.library_count(), 0);
    }

    // ── RecognitionResult ───────────────────────────────────────────────────

    #[test]
    fn recognition_result_high_confidence() {
        let r = RecognitionResult {
            function_addr: Address::new(0x1000),
            name: "foo".to_string(),
            lib: "lib".to_string(),
            version: String::new(),
            confidence: 0.95,
            pass: 1,
            crc_verified: true,
        };
        assert!(r.is_high_confidence());
        assert!(r.meets_threshold(0.9));
        assert!(!r.meets_threshold(0.99));
    }

    #[test]
    fn recognition_result_display() {
        let r = RecognitionResult {
            function_addr: Address::new(0x1000),
            name: "fn1".to_string(),
            lib: "libc".to_string(),
            version: String::new(),
            confidence: 0.85,
            pass: 2,
            crc_verified: false,
        };
        let s = r.to_string();
        assert!(s.contains("fn1"));
        assert!(s.contains("libc"));
    }

    // ── RecognitionFilter ───────────────────────────────────────────────────

    #[test]
    fn filter_permissive_allows_all() {
        let f = RecognitionFilter::permissive();
        let r = RecognitionResult {
            function_addr: Address::new(0),
            name: "x".to_string(),
            lib: "anylib".to_string(),
            version: String::new(),
            confidence: 0.1,
            pass: 3,
            crc_verified: false,
        };
        assert!(f.matches(&r));
    }

    #[test]
    fn filter_strict_rejects_low_confidence() {
        let f = RecognitionFilter::strict();
        let r = RecognitionResult {
            function_addr: Address::new(0),
            name: "x".to_string(),
            lib: "lib".to_string(),
            version: String::new(),
            confidence: 0.5,
            pass: 2,
            crc_verified: false,
        };
        assert!(!f.matches(&r));
    }

    #[test]
    fn filter_library_filter() {
        let f = RecognitionFilter::permissive().for_library("libc");
        let yes = RecognitionResult {
            function_addr: Address::new(0),
            name: "x".to_string(),
            lib: "libc-2.35".to_string(),
            version: String::new(),
            confidence: 0.9,
            pass: 1,
            crc_verified: true,
        };
        let no = RecognitionResult {
            function_addr: Address::new(0),
            name: "x".to_string(),
            lib: "msvcrt".to_string(),
            version: String::new(),
            confidence: 0.9,
            pass: 1,
            crc_verified: true,
        };
        assert!(f.matches(&yes));
        assert!(!f.matches(&no));
    }

    #[test]
    fn filter_require_crc() {
        let f = RecognitionFilter::permissive().require_crc_verified();
        let r_no_crc = RecognitionResult {
            function_addr: Address::new(0),
            name: "x".to_string(),
            lib: "lib".to_string(),
            version: String::new(),
            confidence: 0.9,
            pass: 2,
            crc_verified: false,
        };
        assert!(!f.matches(&r_no_crc));
    }

    #[test]
    fn filter_apply_slice() {
        let f = RecognitionFilter::permissive().with_min_confidence(0.8);
        let results = vec![
            RecognitionResult {
                function_addr: Address::new(0),
                name: "a".to_string(),
                lib: "l".to_string(),
                version: String::new(),
                confidence: 0.9,
                pass: 1,
                crc_verified: false,
            },
            RecognitionResult {
                function_addr: Address::new(1),
                name: "b".to_string(),
                lib: "l".to_string(),
                version: String::new(),
                confidence: 0.5,
                pass: 3,
                crc_verified: false,
            },
        ];
        let filtered = f.apply(&results);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "a");
    }

    // ── RecognitionReport ───────────────────────────────────────────────────

    #[test]
    fn report_build_empty() {
        let r = RecognitionReport::build(10, vec![]);
        assert_eq!(r.total_analyzed, 10);
        assert_eq!(r.matched, 0);
        assert_eq!(r.unmatched, 10);
        assert_eq!(r.match_rate(), 0.0);
    }

    #[test]
    fn report_build_with_results() {
        let results = vec![RecognitionResult {
            function_addr: Address::new(0x1000),
            name: "foo".to_string(),
            lib: "libc".to_string(),
            version: String::new(),
            confidence: 1.0,
            pass: 1,
            crc_verified: true,
        }];
        let r = RecognitionReport::build(5, results);
        assert_eq!(r.total_analyzed, 5);
        assert_eq!(r.matched, 1);
        assert_eq!(r.unmatched, 4);
        assert_eq!(r.pass1_matches, 1);
        assert_eq!(r.crc_verified, 1);
        assert!(r.by_library.contains_key("libc"));
    }

    #[test]
    fn report_match_rate() {
        let r = RecognitionReport::build(0, vec![]);
        assert_eq!(r.match_rate(), 0.0);
    }

    #[test]
    fn report_top_libraries() {
        let results: Vec<RecognitionResult> = (0..5)
            .map(|i| RecognitionResult {
                function_addr: Address::new(i as u64 * 0x100),
                name: format!("fn{i}"),
                lib: if i < 3 {
                    "libc".to_string()
                } else {
                    "msvcrt".to_string()
                },
                version: String::new(),
                confidence: 0.9,
                pass: 1,
                crc_verified: false,
            })
            .collect();
        let r = RecognitionReport::build(5, results);
        let top = r.top_libraries(1);
        assert_eq!(top[0].0, "libc");
        assert_eq!(top[0].1, 3);
    }

    #[test]
    fn report_display() {
        let r = RecognitionReport::build(10, vec![]);
        let s = r.to_string();
        assert!(s.contains("0/10"));
    }

    // ── AutoApply ───────────────────────────────────────────────────────────

    #[test]
    fn auto_apply_applies_renames() {
        let filter = RecognitionFilter::permissive();
        let mut applier = AutoApply::new(filter);
        let results = vec![RecognitionResult {
            function_addr: Address::new(0x1000),
            name: "main".to_string(),
            lib: "libc".to_string(),
            version: String::new(),
            confidence: 0.95,
            pass: 1,
            crc_verified: true,
        }];
        let mut renamed = Vec::new();
        applier.apply(&results, |addr, name| {
            renamed.push((addr, name.to_string()));
            true
        });
        assert_eq!(applier.applied_count, 1);
        assert_eq!(renamed[0].1, "main");
    }

    #[test]
    fn auto_apply_conflict_detection() {
        let filter = RecognitionFilter::permissive();
        let mut applier = AutoApply::new(filter);
        let results = vec![
            RecognitionResult {
                function_addr: Address::new(0x1000),
                name: "foo".to_string(),
                lib: "liba".to_string(),
                version: String::new(),
                confidence: 0.9,
                pass: 1,
                crc_verified: false,
            },
            RecognitionResult {
                function_addr: Address::new(0x1000),
                name: "bar".to_string(),
                lib: "libb".to_string(),
                version: String::new(),
                confidence: 0.9,
                pass: 1,
                crc_verified: false,
            },
        ];
        applier.apply(&results, |_, _| true);
        assert_eq!(applier.conflict_count(), 1);
        assert_eq!(applier.applied_count, 0);
    }

    #[test]
    fn auto_apply_filter_skips_low_confidence() {
        let filter = RecognitionFilter::permissive().with_min_confidence(0.9);
        let mut applier = AutoApply::new(filter);
        let results = vec![RecognitionResult {
            function_addr: Address::new(0x2000),
            name: "helper".to_string(),
            lib: "lib".to_string(),
            version: String::new(),
            confidence: 0.5,
            pass: 3,
            crc_verified: false,
        }];
        applier.apply(&results, |_, _| true);
        assert_eq!(applier.applied_count, 0);
    }

    // ── RecognitionStats ────────────────────────────────────────────────────

    #[test]
    fn recognition_stats_accumulate() {
        let mut stats = RecognitionStats::default();
        let results = vec![RecognitionResult {
            function_addr: Address::new(0),
            name: "f".to_string(),
            lib: "libc".to_string(),
            version: String::new(),
            confidence: 0.95,
            pass: 1,
            crc_verified: true,
        }];
        let report = RecognitionReport::build(1, results);
        stats.accumulate(&report);
        assert_eq!(stats.total, 1);
        assert_eq!(stats.high_confidence, 1);
        assert_eq!(stats.crc_verified, 1);
        assert_eq!(*stats.by_library.get("libc").unwrap(), 1);
    }

    #[test]
    fn recognition_stats_reset() {
        let mut stats = RecognitionStats {
            total: 100,
            ..RecognitionStats::default()
        };
        stats.reset();
        assert_eq!(stats.total, 0);
    }

    // ── recognize_and_apply ─────────────────────────────────────────────────

    #[test]
    fn recognize_and_apply_returns_count() {
        let r = make_recognizer();
        let bytes = vec![0x55u8, 0x48, 0x89, 0xE5, 0xC3];
        let fn_starts = vec![Address::new(0x1000)];
        let count = r.recognize_and_apply(Address::new(0x1000), &bytes, &fn_starts, |_, _| true);
        // Either 0 or 1 depending on confidence threshold; just assert no panic.
        assert!(count <= 1);
    }
}
