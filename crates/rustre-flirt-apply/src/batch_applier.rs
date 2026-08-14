//! Batch FLIRT signature application.
//!
//! Loads and applies multiple `.sig` / `.pat` files against a binary in one
//! pass, merges results using a configurable [`MergeStrategy`], and produces a
//! unified [`ApplyResult`].

// AHashMap (randomised) prevents hash-collision DoS from attacker-controlled
// function names/addresses from untrusted .sig/.pat files.
use ahash::AHashMap as HashMap;
use std::path::PathBuf;
use crate::casts::{f64_to_u8, u128_to_u64, usize_to_f64};

use serde::{Deserialize, Serialize};

use crate::{FlirtError, FlirtMatch, FlirtPattern};

// ---------------------------------------------------------------------------
// SigFile
// ---------------------------------------------------------------------------

/// Descriptor for a single signature file to be applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigFile {
    /// Path to the `.sig` or `.pat` file.
    pub path: PathBuf,
    /// Human-readable label (defaults to the file name).
    pub label: String,
    /// Priority (higher = preferred in conflict resolution).
    pub priority: i32,
    /// Whether to skip this file on error instead of aborting the batch.
    pub skip_on_error: bool,
}

impl SigFile {
    /// Create a descriptor for `path` with default settings.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let p: PathBuf = path.into();
        let label = p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        Self {
            path: p,
            label,
            priority: 0,
            skip_on_error: true,
        }
    }

    /// Override the label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// Set the priority.
    #[must_use]
    pub const fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Set `skip_on_error`.
    #[must_use]
    pub const fn skip_on_error(mut self, skip: bool) -> Self {
        self.skip_on_error = skip;
        self
    }
}

// ---------------------------------------------------------------------------
// MergeStrategy
// ---------------------------------------------------------------------------

/// Strategy for merging matches from multiple signature files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum MergeStrategy {
    /// Keep the match with the highest confidence for each address.
    #[default]
    HighestConfidence,
    /// Keep matches from higher-priority files; lower-priority files fill gaps.
    PriorityFirst,
    /// Accept all matches (may produce duplicates at the same address).
    AllMatches,
    /// Accept only matches that appear in at least `min_votes` files.
    Consensus { min_votes: usize },
}


// ---------------------------------------------------------------------------
// ApplyResult
// ---------------------------------------------------------------------------

/// Result of a batch signature application run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplyResult {
    /// Final merged matches (one per address when strategy removes duplicates).
    pub matches: Vec<FlirtMatch>,
    /// Per-file diagnostics: `(label, match_count, error)`.
    pub file_results: Vec<FileResult>,
    /// Number of address conflicts resolved.
    pub conflicts_resolved: usize,
    /// Number of files that were skipped due to errors.
    pub files_skipped: usize,
    /// Total wall-clock time consumed (milliseconds, approximate).
    pub elapsed_ms: u64,
}

impl ApplyResult {
    /// Total number of final matches.
    #[must_use]
    pub const fn match_count(&self) -> usize {
        self.matches.len()
    }

    /// Returns `true` if at least one file produced matches.
    #[must_use]
    pub const fn has_matches(&self) -> bool {
        !self.matches.is_empty()
    }

    /// Return only matches with `confidence >= threshold`.
    #[must_use]
    pub fn filter_confidence(&self, threshold: u8) -> Vec<&FlirtMatch> {
        self.matches
            .iter()
            .filter(|m| m.confidence >= threshold)
            .collect()
    }

    /// Return matches sorted by address.
    #[must_use]
    pub fn sorted_by_address(&self) -> Vec<&FlirtMatch> {
        let mut v: Vec<&FlirtMatch> = self.matches.iter().collect();
        v.sort_by_key(|m| m.address);
        v
    }

    /// Summarise the run as a human-readable string.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "BatchApplier: {} matches from {} processed ({} files skipped, {} conflicts, {}ms)",
            self.matches.len(),
            self.file_results.len(),
            self.files_skipped,
            self.conflicts_resolved,
            self.elapsed_ms,
        )
    }
}

/// Per-file result inside an [`ApplyResult`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileResult {
    /// Label of the corresponding [`SigFile`].
    pub label: String,
    /// Number of raw matches found before merging.
    pub raw_matches: usize,
    /// Error string if the file could not be processed.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// InMemorySigDb — lightweight in-process pattern database
// ---------------------------------------------------------------------------

/// An in-memory signature database built from parsed FLIRT patterns.
///
/// Unlike [`FlirtSigDb`] (which owns patterns), `InMemorySigDb` indexes the
/// patterns by their first concrete byte for faster scanning.
#[derive(Debug, Default)]
pub struct InMemorySigDb {
    patterns: Vec<FlirtPattern>,
    /// `first_byte` → indices into `patterns`
    index: HashMap<u8, Vec<usize>>,
    /// Wildcard patterns (first byte is None) stored separately.
    wildcard_patterns: Vec<usize>,
}

impl InMemorySigDb {
    /// Create an empty database.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a pattern.
    pub fn add(&mut self, pat: FlirtPattern) {
        let idx = self.patterns.len();
        match pat.bytes.first().copied().flatten() {
            Some(b) => {
                self.index.entry(b).or_default().push(idx);
            }
            None => {
                self.wildcard_patterns.push(idx);
            }
        }
        self.patterns.push(pat);
    }

    /// Number of patterns.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Returns `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// Scan `data` and return matches above `min_confidence`.
    #[must_use]
    pub fn scan(&self, data: &[u8], base_addr: u64, min_confidence: u8) -> Vec<FlirtMatch> {
        let mut results = Vec::new();

        for offset in 0..data.len() {
            let byte = data[offset];
            // Collect candidate pattern indices.
            let mut candidates: Vec<usize> = self
                .index
                .get(&byte)
                .map_or(&[][..], std::vec::Vec::as_slice)
                .to_vec();
            candidates.extend_from_slice(&self.wildcard_patterns);

            for idx in candidates {
                let pat = &self.patterns[idx];
                let slice = &data[offset..];
                if !pat.matches(slice) {
                    continue;
                }
                // CRC check.
                if pat.crc_len > 0 {
                    let crc_start = offset + pat.bytes.len() + pat.crc_offset as usize;
                    let crc_end = crc_start + pat.crc_len as usize;
                    if crc_end > data.len() {
                        continue;
                    }
                    let actual = crate::crc16_flirt(&data[crc_start..crc_end]);
                    if actual != pat.crc {
                        continue;
                    }
                }
                let conf = compute_confidence_inline(pat);
                if conf < min_confidence {
                    continue;
                }
                results.push(FlirtMatch {
                    address: base_addr + offset as u64,
                    function_name: pat.name.clone(),
                    lib_name: pat.lib_name.clone(),
                    confidence: conf,
                    pattern_length: pat.bytes.len(),
                });
            }
        }

        results
    }
}

fn compute_confidence_inline(pat: &FlirtPattern) -> u8 {
    let total = pat.bytes.len();
    if total == 0 {
        return 0;
    }
    let concrete = pat.bytes.iter().filter(|b| b.is_some()).count();
    let ratio = usize_to_f64(concrete) / usize_to_f64(total);
    let bonus = (usize_to_f64(total.min(16)) / 16.0) * 20.0;
    f64_to_u8(ratio.mul_add(80.0, bonus)).min(100)
}

// ---------------------------------------------------------------------------
// BatchApplier
// ---------------------------------------------------------------------------

/// Applies a list of [`SigFile`]s against a binary buffer in a single pass.
///
/// # Usage
///
/// ```rust,no_run
/// # use rustre_flirt_apply::batch_applier::{BatchApplier, SigFile, MergeStrategy};
/// let mut applier = BatchApplier::new();
/// applier.add_sig_file(SigFile::new("libcrt.sig"));
/// applier.add_sig_file(SigFile::new("libssl.pat"));
/// applier.set_merge_strategy(MergeStrategy::HighestConfidence);
/// let data = std::fs::read("binary.exe").unwrap();
/// let result = applier.apply(&data, 0x0040_0000);
/// println!("{}", result.summary());
/// ```
pub struct BatchApplier {
    sig_files: Vec<SigFile>,
    strategy: MergeStrategy,
    min_confidence: u8,
    base_addr: u64,
}

impl BatchApplier {
    /// Create a new applier with default settings.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            sig_files: Vec::new(),
            strategy: MergeStrategy::HighestConfidence,
            min_confidence: 60,
            base_addr: 0,
        }
    }

    /// Add a signature file descriptor.
    pub fn add_sig_file(&mut self, f: SigFile) {
        self.sig_files.push(f);
    }

    /// Add multiple signature file descriptors.
    pub fn add_sig_files(&mut self, files: impl IntoIterator<Item = SigFile>) {
        self.sig_files.extend(files);
    }

    /// Set the merge strategy.
    pub const fn set_merge_strategy(&mut self, s: MergeStrategy) {
        self.strategy = s;
    }

    /// Set the minimum confidence threshold (default 60).
    pub const fn set_min_confidence(&mut self, conf: u8) {
        self.min_confidence = conf;
    }

    /// Set the default base address used by [`Self::apply_default`].
    pub const fn set_base_addr(&mut self, addr: u64) {
        self.base_addr = addr;
    }

    /// Get the configured default base address.
    #[must_use]
    pub const fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// Apply using the configured default base address.
    #[must_use]
    pub fn apply_default(&self, data: &[u8]) -> ApplyResult {
        self.apply(data, self.base_addr)
    }

    /// Apply all registered signature files against `data`.
    ///
    /// Uses an in-process pattern scanner; does not write to disk.
    #[must_use]
    pub fn apply(&self, data: &[u8], base_addr: u64) -> ApplyResult {
        let start = std::time::Instant::now();
        let mut file_results: Vec<FileResult> = Vec::new();
        // address → Vec<(priority, FlirtMatch)>
        let mut raw: HashMap<u64, Vec<(i32, FlirtMatch)>> = HashMap::new();
        let mut files_skipped = 0usize;

        for sig_file in &self.sig_files {
            match self.apply_one_file(sig_file, data, base_addr) {
                Ok(matches) => {
                    let count = matches.len();
                    for m in matches {
                        raw.entry(m.address)
                            .or_default()
                            .push((sig_file.priority, m));
                    }
                    file_results.push(FileResult {
                        label: sig_file.label.clone(),
                        raw_matches: count,
                        error: None,
                    });
                }
                Err(e) => {
                    files_skipped += 1;
                    file_results.push(FileResult {
                        label: sig_file.label.clone(),
                        raw_matches: 0,
                        error: Some(e.to_string()),
                    });
                    if !sig_file.skip_on_error {
                        // Abort the batch.
                        break;
                    }
                }
            }
        }

        let (merged, conflicts_resolved) = self.merge(raw);
        let elapsed_ms = u128_to_u64(start.elapsed().as_millis());

        ApplyResult {
            matches: merged,
            file_results,
            conflicts_resolved,
            files_skipped,
            elapsed_ms,
        }
    }

    // Apply a single file and return raw matches.
    fn apply_one_file(
        &self,
        sig_file: &SigFile,
        data: &[u8],
        base_addr: u64,
    ) -> Result<Vec<FlirtMatch>, FlirtError> {
        let sigs = crate::load_auto(&sig_file.path)?;

        let mut db = InMemorySigDb::new();
        for sig in &sigs {
            let pat_bytes: Vec<Option<u8>> = sig
                .bytes
                .iter()
                .zip(sig.mask.iter())
                .map(|(&b, &m)| if m != 0 { Some(b) } else { None })
                .collect();
            let mut fp = FlirtPattern::new(sig.name.clone(), pat_bytes);
            fp.lib_name.clone_from(&sig.lib_name);
            fp.crc_offset = sig.crc_offset;
            fp.crc_len = sig.crc_len;
            fp.crc = sig.crc;
            db.add(fp);
        }

        Ok(db.scan(data, base_addr, self.min_confidence))
    }

    /// Merge raw per-address matches according to the strategy.
    fn merge(
        &self,
        raw: HashMap<u64, Vec<(i32, FlirtMatch)>>,
    ) -> (Vec<FlirtMatch>, usize) {
        let mut merged = Vec::new();
        let mut conflicts = 0usize;

        for (addr, mut candidates) in raw {
            let _ = addr;
            if candidates.len() > 1 {
                conflicts += 1;
            }
            match self.strategy {
                MergeStrategy::HighestConfidence => {
                    candidates.sort_by(|a, b| b.1.confidence.cmp(&a.1.confidence));
                    merged.push(candidates.remove(0).1);
                }
                MergeStrategy::PriorityFirst => {
                    candidates.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.confidence.cmp(&a.1.confidence)));
                    merged.push(candidates.remove(0).1);
                }
                MergeStrategy::AllMatches => {
                    for (_, m) in candidates {
                        merged.push(m);
                    }
                }
                MergeStrategy::Consensus { min_votes } => {
                    if candidates.len() >= min_votes {
                        // Pick the highest-confidence representative.
                        candidates.sort_by(|a, b| b.1.confidence.cmp(&a.1.confidence));
                        merged.push(candidates.remove(0).1);
                    }
                }
            }
        }

        merged.sort_by_key(|m| m.address);
        (merged, conflicts)
    }

    /// Number of registered signature files.
    #[must_use]
    pub const fn sig_file_count(&self) -> usize {
        self.sig_files.len()
    }

    /// Build a summary of all registered files (path + label + priority).
    #[must_use]
    pub fn file_list(&self) -> Vec<String> {
        self.sig_files
            .iter()
            .map(|f| format!("[{}] {} (prio={})", f.label, f.path.display(), f.priority))
            .collect()
    }
}

impl Default for BatchApplier {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sig_file_new() {
        let sf = SigFile::new("/tmp/test.sig");
        assert_eq!(sf.label, "test.sig");
        assert!(sf.skip_on_error);
    }

    #[test]
    fn test_sig_file_builder() {
        let sf = SigFile::new("/tmp/a.pat")
            .with_label("MyLib")
            .with_priority(10);
        assert_eq!(sf.label, "MyLib");
        assert_eq!(sf.priority, 10);
    }

    #[test]
    fn test_merge_strategy_default() {
        assert_eq!(MergeStrategy::default(), MergeStrategy::HighestConfidence);
    }

    #[test]
    fn test_apply_result_summary() {
        let r = ApplyResult {
            matches: vec![],
            file_results: vec![],
            conflicts_resolved: 0,
            files_skipped: 1,
            elapsed_ms: 42,
        };
        assert!(r.summary().contains("1 files"));
    }

    #[test]
    fn test_apply_result_filter_confidence() {
        let m = FlirtMatch {
            address: 0x1000,
            function_name: "f".to_string(),
            lib_name: "l".to_string(),
            confidence: 90,
            pattern_length: 8,
        };
        let r = ApplyResult {
            matches: vec![m],
            file_results: vec![],
            conflicts_resolved: 0,
            files_skipped: 0,
            elapsed_ms: 0,
        };
        assert_eq!(r.filter_confidence(80).len(), 1);
        assert_eq!(r.filter_confidence(95).len(), 0);
    }

    #[test]
    fn test_in_memory_sig_db_scan() {
        let mut db = InMemorySigDb::new();
        let pat =
            FlirtPattern::from_pattern_str("55 8B EC 83", "test_fn".to_string(), "lib".to_string()).unwrap();
        db.add(pat);
        let data = vec![0x55u8, 0x8B, 0xEC, 0x83, 0x00];
        let matches = db.scan(&data, 0x1000, 0);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].function_name, "test_fn");
    }

    #[test]
    fn test_in_memory_sig_db_scan_no_match() {
        let mut db = InMemorySigDb::new();
        let pat =
            FlirtPattern::from_pattern_str("AA BB CC DD", "absent".to_string(), "lib".to_string()).unwrap();
        db.add(pat);
        let data = vec![0x00u8; 32];
        let matches = db.scan(&data, 0, 0);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_batch_applier_no_files() {
        let applier = BatchApplier::new();
        let result = applier.apply(&[0u8; 64], 0x1000);
        assert_eq!(result.match_count(), 0);
        assert_eq!(result.files_skipped, 0);
    }

    #[test]
    fn test_batch_applier_missing_file_skipped() {
        let mut applier = BatchApplier::new();
        applier.add_sig_file(SigFile::new("nonexistent_xyz.sig").skip_on_error(true));
        let result = applier.apply(&[0u8; 64], 0x1000);
        assert_eq!(result.files_skipped, 1);
        assert!(result.file_results[0].error.is_some());
    }

    #[test]
    fn test_batch_applier_file_list() {
        let mut applier = BatchApplier::new();
        applier.add_sig_file(SigFile::new("/tmp/a.sig").with_priority(5));
        let list = applier.file_list();
        assert_eq!(list.len(), 1);
        assert!(list[0].contains("prio=5"));
    }

    #[test]
    fn test_apply_result_sorted_by_address() {
        let make = |addr| FlirtMatch {
            address: addr,
            function_name: "f".to_string(),
            lib_name: String::new(),
            confidence: 80,
            pattern_length: 4,
        };
        let r = ApplyResult {
            matches: vec![make(0x3000), make(0x1000), make(0x2000)],
            file_results: vec![],
            conflicts_resolved: 0,
            files_skipped: 0,
            elapsed_ms: 0,
        };
        let sorted = r.sorted_by_address();
        assert_eq!(sorted[0].address, 0x1000);
        assert_eq!(sorted[2].address, 0x3000);
    }

    #[test]
    fn test_consensus_strategy_needs_votes() {
        // Build a raw map with only one vote — should be excluded.
        let mut applier = BatchApplier::new();
        applier.set_merge_strategy(MergeStrategy::Consensus { min_votes: 2 });
        let m = FlirtMatch {
            address: 0x1000,
            function_name: "strlen".to_string(),
            lib_name: "msvcrt".to_string(),
            confidence: 90,
            pattern_length: 12,
        };
        let mut raw = HashMap::new();
        raw.insert(0x1000u64, vec![(0i32, m)]);
        let (merged, _) = applier.merge(raw);
        assert!(merged.is_empty());
    }

    #[test]
    fn test_sig_file_count() {
        let mut applier = BatchApplier::new();
        applier.add_sig_files([SigFile::new("a.sig"), SigFile::new("b.sig")]);
        assert_eq!(applier.sig_file_count(), 2);
    }
}
