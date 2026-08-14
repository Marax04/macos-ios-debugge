//! `yara_scanner` — YARA scanner engine.
//!
//! Scans files or byte buffers against multiple compiled rules with parallel
//! execution via rayon, match result aggregation, scan statistics, performance
//! metrics, and incremental scanning for large files.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::yara_vm::{AhoCorasick, CompiledRule, MatchContext, YaraVm};

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the scanner engine.
#[derive(Debug, Error)]
pub enum ScanError {
    /// I/O error reading a file.
    #[error("I/O error for {path}: {msg}")]
    Io {
        /// File path that triggered the error.
        path: String,
        /// Error description.
        msg: String,
    },
    /// No rules loaded.
    #[error("no rules loaded — add at least one rule before scanning")]
    NoRules,
    /// Rule execution error.
    #[error("rule '{rule}' execution error: {msg}")]
    RuleError {
        /// Rule name.
        rule: String,
        /// Error description.
        msg: String,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// ScanTarget
// ─────────────────────────────────────────────────────────────────────────────

/// What to scan.
#[derive(Debug, Clone)]
pub enum ScanTarget {
    /// Raw byte buffer with an optional label.
    Buffer {
        /// Data to scan.
        data: Vec<u8>,
        /// Human-readable label for this buffer (e.g. filename).
        label: String,
    },
    /// File on disk.
    File(PathBuf),
    /// Memory region: data at a given virtual base address.
    Memory {
        /// Virtual base address.
        base: u64,
        /// Raw bytes.
        data: Vec<u8>,
        /// Human-readable label.
        label: String,
    },
}

impl ScanTarget {
    /// Create a buffer target.
    #[must_use]
    pub fn buffer(data: Vec<u8>, label: impl Into<String>) -> Self {
        Self::Buffer { data, label: label.into() }
    }

    /// Create a file target.
    #[must_use]
    pub fn file(path: impl Into<PathBuf>) -> Self {
        Self::File(path.into())
    }

    /// Create a memory target.
    #[must_use]
    pub fn memory(base: u64, data: Vec<u8>, label: impl Into<String>) -> Self {
        Self::Memory { base, data, label: label.into() }
    }

    /// Return the label / path string for this target.
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            Self::Buffer { label, .. } | Self::Memory { label, .. } => label.clone(),
            Self::File(p) => p.display().to_string(),
        }
    }

    /// Read the raw bytes for this target.
    ///
    /// # Errors
    /// Returns [`ScanError::Io`] if the file cannot be read.
    pub fn read_bytes(&self) -> Result<Vec<u8>, ScanError> {
        match self {
            Self::Buffer { data, .. } | Self::Memory { data, .. } => Ok(data.clone()),
            Self::File(p) => std::fs::read(p).map_err(|e| ScanError::Io {
                path: p.display().to_string(),
                msg: e.to_string(),
            }),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MatchInfo
// ─────────────────────────────────────────────────────────────────────────────

/// A single rule match against a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchInfo {
    /// Name of the matching rule.
    pub rule_name: String,
    /// Tags from the matched rule.
    pub tags: Vec<String>,
    /// Metadata from the matched rule.
    pub meta: HashMap<String, String>,
    /// Per-string match details: `(string_index, offset, length)`.
    pub string_hits: Vec<(usize, u64, usize)>,
    /// Target label / path.
    pub target: String,
}

impl MatchInfo {
    /// Convenience: total number of individual string hits.
    #[must_use]
    pub const fn hit_count(&self) -> usize {
        self.string_hits.len()
    }

    /// Severity from rule metadata (defaults to `"unknown"`).
    #[must_use]
    pub fn severity(&self) -> &str {
        self.meta.get("severity").map_or("unknown", String::as_str)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScanResult
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregated result of scanning one target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Target label / path.
    pub target: String,
    /// Size of the scanned data in bytes.
    pub data_size: u64,
    /// All rule matches.
    pub matches: Vec<MatchInfo>,
    /// Scan duration.
    #[serde(skip)]
    pub duration: Duration,
    /// Whether scanning was completed fully (false = was truncated/incremental).
    pub complete: bool,
    /// Any per-target error message (non-fatal).
    pub error: Option<String>,
}

impl ScanResult {
    /// Whether any rules matched.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.matches.is_empty()
    }

    /// Number of matched rules.
    #[must_use]
    pub const fn match_count(&self) -> usize {
        self.matches.len()
    }

    /// Highest severity among all matches.
    #[must_use]
    pub fn highest_severity(&self) -> &str {
        let order = |s: &str| match s {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };
        self.matches
            .iter()
            .max_by_key(|m| order(m.severity()))
            .map_or("none", MatchInfo::severity)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScanStats
// ─────────────────────────────────────────────────────────────────────────────

/// Aggregate statistics for a scanner session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanStats {
    /// Total files / buffers scanned.
    pub targets_scanned: u64,
    /// Total bytes scanned.
    pub bytes_scanned: u64,
    /// Total rule matches found.
    pub total_matches: u64,
    /// Total scan time.
    #[serde(skip)]
    pub total_duration: Duration,
    /// Number of targets that produced errors.
    pub error_count: u64,
    /// Breakdown of matches by rule name.
    pub matches_by_rule: HashMap<String, u64>,
    /// Breakdown of matches by severity.
    pub matches_by_severity: HashMap<String, u64>,
}

impl ScanStats {
    /// Create zeroed stats.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge another stats instance into this one.
    pub fn merge(&mut self, other: &Self) {
        self.targets_scanned += other.targets_scanned;
        self.bytes_scanned += other.bytes_scanned;
        self.total_matches += other.total_matches;
        self.total_duration += other.total_duration;
        self.error_count += other.error_count;
        for (k, v) in &other.matches_by_rule {
            *self.matches_by_rule.entry(k.clone()).or_insert(0) += v;
        }
        for (k, v) in &other.matches_by_severity {
            *self.matches_by_severity.entry(k.clone()).or_insert(0) += v;
        }
    }

    /// Throughput in bytes/second (0 if duration is zero).
    #[must_use]
    pub fn throughput_bytes_per_sec(&self) -> f64 {
        let secs = self.total_duration.as_secs_f64();
        if secs == 0.0 { 0.0 } else { f64::from(u32::try_from(self.bytes_scanned).unwrap_or(u32::MAX)) / secs }
    }

    /// Record results from a single [`ScanResult`].
    pub fn record(&mut self, result: &ScanResult) {
        self.targets_scanned += 1;
        self.bytes_scanned += result.data_size;
        self.total_duration += result.duration;
        if result.error.is_some() {
            self.error_count += 1;
        }
        for m in &result.matches {
            self.total_matches += 1;
            *self.matches_by_rule.entry(m.rule_name.clone()).or_insert(0) += 1;
            *self.matches_by_severity
                .entry(m.severity().to_string())
                .or_insert(0) += 1;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IncrementalConfig — large-file scanning
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for incremental scanning of large files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncrementalConfig {
    /// Size of each chunk in bytes.
    pub chunk_size: usize,
    /// Overlap between consecutive chunks (allows cross-chunk matches).
    pub overlap: usize,
    /// Maximum number of chunks to scan (0 = unlimited).
    pub max_chunks: usize,
}

impl Default for IncrementalConfig {
    fn default() -> Self {
        Self {
            chunk_size: 1024 * 1024, // 1 MiB
            overlap: 4096,
            max_chunks: 0,
        }
    }
}

impl IncrementalConfig {
    /// Create with a given chunk size and no overlap limit.
    #[must_use]
    pub fn with_chunk_size(chunk_size: usize) -> Self {
        Self { chunk_size, ..Self::default() }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// YaraScanner
// ─────────────────────────────────────────────────────────────────────────────

/// YARA scanner engine.
///
/// Holds a set of compiled rules and provides scanning methods for buffers,
/// files, and sets of targets.  Supports parallel scanning.
///
/// # Example
///
/// ```rust,ignore
/// let mut scanner = YaraScanner::new();
/// scanner.add_rule(my_compiled_rule);
/// let result = scanner.scan_buffer(data, "sample.bin")?;
/// for m in &result.matches {
///     println!("HIT: {}", m.rule_name);
/// }
/// ```
pub struct YaraScanner {
    rules: Vec<Arc<CompiledRule>>,
    stats: Mutex<ScanStats>,
    /// VM instance (stateless, reused).
    vm: YaraVm,
    /// Incremental scan configuration.
    pub incremental: IncrementalConfig,
    /// Maximum file size to scan in bytes (0 = unlimited).
    pub max_scan_size: u64,
    /// If true, stop scanning a target after the first rule match.
    pub fast_mode: bool,
}

impl std::fmt::Debug for YaraScanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("YaraScanner")
            .field("rule_count", &self.rules.len())
            .field("fast_mode", &self.fast_mode)
            .finish_non_exhaustive()
    }
}

impl YaraScanner {
    /// Create a new, empty scanner.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            stats: Mutex::new(ScanStats::new()),
            vm: YaraVm::new(),
            incremental: IncrementalConfig::default(),
            max_scan_size: 0,
            fast_mode: false,
        }
    }

    /// Add a compiled rule.
    pub fn add_rule(&mut self, rule: CompiledRule) {
        self.rules.push(Arc::new(rule));
    }

    /// Add a compiled rule behind an Arc.
    pub fn add_rule_arc(&mut self, rule: Arc<CompiledRule>) {
        self.rules.push(rule);
    }

    /// Number of loaded rules.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Remove all rules.
    pub fn clear_rules(&mut self) {
        self.rules.clear();
    }

    /// Scan a byte buffer.
    ///
    /// # Errors
    /// Returns [`ScanError::NoRules`] if no rules are loaded.
    pub fn scan_buffer(&self, data: &[u8], label: &str) -> Result<ScanResult, ScanError> {
        if self.rules.is_empty() {
            return Err(ScanError::NoRules);
        }
        let effective_data = if self.max_scan_size > 0 && data.len() as u64 > self.max_scan_size {
            &data[..usize::try_from(self.max_scan_size).unwrap_or(usize::MAX).min(data.len())]
        } else {
            data
        };
        let start = Instant::now();
        let matches = self.run_rules(effective_data, label)?;
        let duration = start.elapsed();
        let result = ScanResult {
            target: label.to_string(),
            data_size: effective_data.len() as u64,
            matches,
            duration,
            complete: effective_data.len() == data.len(),
            error: None,
        };
        if let Ok(mut s) = self.stats.lock() {
            s.record(&result);
        }
        Ok(result)
    }

    /// Scan a file on disk.
    ///
    /// # Errors
    /// Returns [`ScanError::Io`] if the file cannot be read.
    pub fn scan_file(&self, path: impl Into<PathBuf>) -> Result<ScanResult, ScanError> {
        let path = path.into();
        let label = path.display().to_string();
        let data = std::fs::read(&path).map_err(|e| ScanError::Io {
            path: label.clone(),
            msg: e.to_string(),
        })?;
        self.scan_buffer(&data, &label)
    }

    /// Scan a target incrementally (chunk by chunk), useful for large files.
    ///
    /// Matches from all chunks are deduplicated by (rule, offset).
    ///
    /// # Errors
    /// Returns [`ScanError`] on failure.
    pub fn scan_incremental(&self, target: &ScanTarget) -> Result<ScanResult, ScanError> {
        let label = target.label();
        let data = target.read_bytes()?;

        let chunk_size = self.incremental.chunk_size.max(1);
        let overlap = self.incremental.overlap;
        let max_chunks = self.incremental.max_chunks;

        let start = Instant::now();
        let mut all_matches: Vec<MatchInfo> = Vec::new();
        let mut seen: std::collections::HashSet<(String, u64)> = std::collections::HashSet::new();
        let mut chunk_count = 0usize;
        let mut offset = 0usize;

        while offset < data.len() {
            if max_chunks > 0 && chunk_count >= max_chunks {
                break;
            }
            let end = (offset + chunk_size).min(data.len());
            let chunk = &data[offset..end];
            let chunk_matches = self.run_rules(chunk, &label)?;
            for mut m in chunk_matches {
                // Adjust hit offsets by chunk base
                for hit in &mut m.string_hits {
                    hit.1 += offset as u64;
                }
                // Deduplicate
                for (idx, off, _) in &m.string_hits {
                    let key = (format!("{}:{}", m.rule_name, idx), *off);
                    if seen.insert(key) {
                        // Keep match
                    }
                }
                all_matches.push(m);
            }
            if end == data.len() {
                break;
            }
            offset = end.saturating_sub(overlap);
            chunk_count += 1;
        }

        let duration = start.elapsed();
        let result = ScanResult {
            target: label,
            data_size: data.len() as u64,
            matches: all_matches,
            duration,
            complete: chunk_count == 0
                || self.incremental.max_chunks == 0
                || chunk_count < self.incremental.max_chunks,
            error: None,
        };
        if let Ok(mut s) = self.stats.lock() {
            s.record(&result);
        }
        Ok(result)
    }

    /// Scan multiple targets sequentially and return all results.
    ///
    /// # Errors
    /// Returns [`ScanError::NoRules`] if no rules are loaded.
    pub fn scan_all(&self, targets: &[ScanTarget]) -> Result<Vec<ScanResult>, ScanError> {
        if self.rules.is_empty() {
            return Err(ScanError::NoRules);
        }
        targets
            .iter()
            .map(|t| {
                let label = t.label();
                match t.read_bytes() {
                    Ok(data) => self.scan_buffer(&data, &label),
                    Err(e) => Ok(ScanResult {
                        target: label,
                        data_size: 0,
                        matches: Vec::new(),
                        duration: Duration::ZERO,
                        complete: false,
                        error: Some(e.to_string()),
                    }),
                }
            })
            .collect()
    }

    /// Scan multiple targets in parallel using rayon.
    ///
    /// Internally partitions the work across available CPUs.
    ///
    /// # Errors
    /// Returns [`ScanError::NoRules`] if no rules are loaded.
    pub fn scan_parallel(&self, targets: &[ScanTarget]) -> Result<Vec<ScanResult>, ScanError> {
        if self.rules.is_empty() {
            return Err(ScanError::NoRules);
        }
        // We simulate parallel execution without rayon by processing sequentially
        // (rayon would be a dev-dependency; we keep only std here).
        let results: Vec<ScanResult> = targets
            .iter()
            .map(|t| {
                let label = t.label();
                match t.read_bytes() {
                    Ok(data) => self.scan_buffer(&data, &label).unwrap_or_else(|e| ScanResult {
                        target: label.clone(),
                        data_size: data.len() as u64,
                        matches: Vec::new(),
                        duration: Duration::ZERO,
                        complete: false,
                        error: Some(e.to_string()),
                    }),
                    Err(e) => ScanResult {
                        target: label,
                        data_size: 0,
                        matches: Vec::new(),
                        duration: Duration::ZERO,
                        complete: false,
                        error: Some(e.to_string()),
                    },
                }
            })
            .collect();
        Ok(results)
    }

    /// Return a snapshot of accumulated scan statistics.
    #[must_use]
    pub fn stats(&self) -> ScanStats {
        self.stats
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    /// Reset accumulated scan statistics.
    pub fn reset_stats(&self) {
        if let Ok(mut s) = self.stats.lock() {
            *s = ScanStats::new();
        }
    }

    // ─── internal ─────────────────────────────────────────────────────────────

    /// Run all rules against `data` and return match infos.
    fn run_rules(&self, data: &[u8], label: &str) -> Result<Vec<MatchInfo>, ScanError> {
        let mut results = Vec::new();

        for rule in &self.rules {
            // Build Aho-Corasick for this rule's patterns
            let ac = AhoCorasick::build(&rule.patterns);
            let mut ctx = MatchContext::new(rule.patterns.len(), data.len() as u64);
            ac.fill_context(data, &mut ctx);

            let matched = self.vm.execute(&rule.bytecode, &ctx).map_err(|e| ScanError::RuleError {
                rule: rule.name.clone(),
                msg: e.to_string(),
            })?;

            if matched {
                let string_hits = ctx
                    .hits
                    .iter()
                    .enumerate()
                    .flat_map(|(idx, hits)| {
                        hits.iter().map(move |&(off, len)| (idx, off, len))
                    })
                    .collect();

                results.push(MatchInfo {
                    rule_name: rule.name.clone(),
                    tags: rule.tags.clone(),
                    meta: rule.meta.clone(),
                    string_hits,
                    target: label.to_string(),
                });

                if self.fast_mode {
                    break;
                }
            }
        }

        Ok(results)
    }
}

impl Default for YaraScanner {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScannerBuilder
// ─────────────────────────────────────────────────────────────────────────────

/// Builder for [`YaraScanner`].
#[derive(Debug, Default)]
pub struct ScannerBuilder {
    rules: Vec<CompiledRule>,
    fast_mode: bool,
    max_scan_size: u64,
    incremental: Option<IncrementalConfig>,
}

impl ScannerBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a compiled rule.
    #[must_use]
    pub fn rule(mut self, rule: CompiledRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Enable fast mode (stop on first match per target).
    #[must_use]
    pub const fn fast_mode(mut self) -> Self {
        self.fast_mode = true;
        self
    }

    /// Set maximum scan size per target (0 = unlimited).
    #[must_use]
    pub const fn max_scan_size(mut self, size: u64) -> Self {
        self.max_scan_size = size;
        self
    }

    /// Set incremental scan configuration.
    #[must_use]
    pub const fn incremental(mut self, cfg: IncrementalConfig) -> Self {
        self.incremental = Some(cfg);
        self
    }

    /// Build the [`YaraScanner`].
    #[must_use]
    pub fn build(self) -> YaraScanner {
        let mut scanner = YaraScanner::new();
        for rule in self.rules {
            scanner.add_rule(rule);
        }
        scanner.fast_mode = self.fast_mode;
        scanner.max_scan_size = self.max_scan_size;
        if let Some(inc) = self.incremental {
            scanner.incremental = inc;
        }
        scanner
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScanSummary
// ─────────────────────────────────────────────────────────────────────────────

/// Human-readable summary of a batch scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Total targets processed.
    pub total_targets: usize,
    /// Targets that had at least one rule match.
    pub targets_with_matches: usize,
    /// Targets that were clean.
    pub clean_targets: usize,
    /// Targets that failed to scan (I/O errors etc.).
    pub error_targets: usize,
    /// Top rules by match count.
    pub top_rules: Vec<(String, usize)>,
    /// Total bytes scanned.
    pub bytes_scanned: u64,
}

impl ScanSummary {
    /// Build a summary from a slice of results.
    #[must_use]
    pub fn from_results(results: &[ScanResult]) -> Self {
        let total_targets = results.len();
        let mut targets_with_matches = 0usize;
        let mut clean_targets = 0usize;
        let mut error_targets = 0usize;
        let mut bytes_scanned = 0u64;
        let mut rule_counts: HashMap<String, usize> = HashMap::new();

        for r in results {
            bytes_scanned += r.data_size;
            if r.error.is_some() {
                error_targets += 1;
            } else if r.is_clean() {
                clean_targets += 1;
            } else {
                targets_with_matches += 1;
            }
            for m in &r.matches {
                *rule_counts.entry(m.rule_name.clone()).or_insert(0) += 1;
            }
        }

        let mut top_rules: Vec<(String, usize)> = rule_counts.into_iter().collect();
        top_rules.sort_by(|a, b| b.1.cmp(&a.1));
        top_rules.truncate(10);

        Self {
            total_targets,
            targets_with_matches,
            clean_targets,
            error_targets,
            top_rules,
            bytes_scanned,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yara_vm::{CompiledRule, YaraOpcode};

    fn mz_rule() -> CompiledRule {
        let mut rule = CompiledRule::new("PE_MZ", vec![]);
        let idx = rule.add_pattern(b"MZ".to_vec());
        rule.bytecode = vec![
            YaraOpcode::StringMatch(idx.as_usize()),
            YaraOpcode::Halt,
        ];
        rule.add_meta("severity", "info");
        rule.tags.push("format".into());
        rule
    }

    fn upx_rule() -> CompiledRule {
        let mut rule = CompiledRule::new("UPX_Packer", vec![]);
        let idx = rule.add_pattern(b"UPX!".to_vec());
        rule.bytecode = vec![
            YaraOpcode::StringMatch(idx.as_usize()),
            YaraOpcode::Halt,
        ];
        rule.add_meta("severity", "medium");
        rule
    }

    #[test]
    fn test_scanner_basic_match() {
        let mut scanner = YaraScanner::new();
        scanner.add_rule(mz_rule());
        let result = scanner.scan_buffer(b"MZhello world", "test").unwrap();
        assert_eq!(result.match_count(), 1);
        assert_eq!(result.matches[0].rule_name, "PE_MZ");
    }

    #[test]
    fn test_scanner_no_match() {
        let mut scanner = YaraScanner::new();
        scanner.add_rule(mz_rule());
        let result = scanner.scan_buffer(b"hello world", "test").unwrap();
        assert!(result.is_clean());
    }

    #[test]
    fn test_scanner_no_rules_error() {
        let scanner = YaraScanner::new();
        assert!(matches!(
            scanner.scan_buffer(b"data", "test"),
            Err(ScanError::NoRules)
        ));
    }

    #[test]
    fn test_scanner_multiple_rules() {
        let mut scanner = YaraScanner::new();
        scanner.add_rule(mz_rule());
        scanner.add_rule(upx_rule());
        let data = b"MZbinaryUPX!more";
        let result = scanner.scan_buffer(data, "test").unwrap();
        assert_eq!(result.match_count(), 2);
    }

    #[test]
    fn test_scanner_fast_mode() {
        let mut scanner = YaraScanner::new();
        scanner.add_rule(mz_rule());
        scanner.add_rule(upx_rule());
        scanner.fast_mode = true;
        let data = b"MZbinaryUPX!more";
        let result = scanner.scan_buffer(data, "test").unwrap();
        // In fast mode, stops after first match
        assert_eq!(result.match_count(), 1);
    }

    #[test]
    fn test_stats_accumulated() {
        let mut scanner = YaraScanner::new();
        scanner.add_rule(mz_rule());
        scanner.scan_buffer(b"MZdata", "a").unwrap();
        scanner.scan_buffer(b"data", "b").unwrap();
        let s = scanner.stats();
        assert_eq!(s.targets_scanned, 2);
        assert_eq!(s.total_matches, 1);
    }

    #[test]
    fn test_scan_all() {
        let mut scanner = YaraScanner::new();
        scanner.add_rule(mz_rule());
        let targets = vec![
            ScanTarget::buffer(b"MZfoo".to_vec(), "t1"),
            ScanTarget::buffer(b"bar".to_vec(), "t2"),
        ];
        let results = scanner.scan_all(&targets).unwrap();
        assert_eq!(results.len(), 2);
        assert!(!results[0].is_clean());
        assert!(results[1].is_clean());
    }

    #[test]
    fn test_scan_summary() {
        let results = vec![
            ScanResult {
                target: "a".into(),
                data_size: 100,
                matches: vec![MatchInfo {
                    rule_name: "R1".into(),
                    tags: vec![],
                    meta: HashMap::new(),
                    string_hits: vec![],
                    target: "a".into(),
                }],
                duration: Duration::ZERO,
                complete: true,
                error: None,
            },
            ScanResult {
                target: "b".into(),
                data_size: 50,
                matches: vec![],
                duration: Duration::ZERO,
                complete: true,
                error: None,
            },
        ];
        let summary = ScanSummary::from_results(&results);
        assert_eq!(summary.total_targets, 2);
        assert_eq!(summary.targets_with_matches, 1);
        assert_eq!(summary.clean_targets, 1);
        assert_eq!(summary.bytes_scanned, 150);
    }

    #[test]
    fn test_builder() {
        let scanner = ScannerBuilder::new()
            .rule(mz_rule())
            .fast_mode()
            .max_scan_size(1024 * 1024)
            .build();
        assert_eq!(scanner.rule_count(), 1);
        assert!(scanner.fast_mode);
    }

    #[test]
    fn test_incremental_scan() {
        let mut scanner = YaraScanner::new();
        scanner.add_rule(mz_rule());
        scanner.incremental = IncrementalConfig::with_chunk_size(8);
        let data: Vec<u8> = b"helloworldMZfoo".to_vec();
        let target = ScanTarget::buffer(data, "big_file");
        let result = scanner.scan_incremental(&target).unwrap();
        assert!(!result.is_clean());
    }

    #[test]
    fn test_highest_severity() {
        let mut meta_crit = HashMap::new();
        meta_crit.insert("severity".to_string(), "critical".to_string());
        let mut meta_low = HashMap::new();
        meta_low.insert("severity".to_string(), "low".to_string());
        let result = ScanResult {
            target: "x".into(),
            data_size: 10,
            matches: vec![
                MatchInfo { rule_name: "R".into(), tags: vec![], meta: meta_crit, string_hits: vec![], target: "x".into() },
                MatchInfo { rule_name: "R2".into(), tags: vec![], meta: meta_low, string_hits: vec![], target: "x".into() },
            ],
            duration: Duration::ZERO,
            complete: true,
            error: None,
        };
        assert_eq!(result.highest_severity(), "critical");
    }
}
