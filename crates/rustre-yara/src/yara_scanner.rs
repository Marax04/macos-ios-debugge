//! `yara_scanner` — Complete YARA scanner.
//!
//! Provides `YaraScanner`, `ScanResult`, `ScanConfig`, `FileScanner`,
//! `MemoryScanner`, `ProcessScanner`, `RulesetStats`, `BatchScanner`.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the YARA scanner.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ScannerError {
    #[error("rule parse error: {0}")]
    ParseError(String),
    #[error("rule compile error: {0}")]
    CompileError(String),
    #[error("scan timeout")]
    Timeout,
    #[error("IO error: {0}")]
    Io(String),
    #[error("process error: {0}")]
    Process(String),
    #[error("no rules loaded")]
    NoRules,
    #[error("max matches exceeded")]
    MaxMatchesExceeded,
    #[error("invalid scan target: {0}")]
    InvalidTarget(String),
}

// ─── RuleMatch ────────────────────────────────────────────────────────────────

/// A single rule match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    /// Rule name.
    pub rule_name: String,
    /// Namespace.
    pub namespace: String,
    /// Tags.
    pub tags: Vec<String>,
    /// Metadata.
    pub meta: HashMap<String, String>,
    /// String matches: (identifier, offset, `matched_bytes`).
    pub string_matches: Vec<StringMatchEntry>,
}

/// One string match within a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringMatchEntry {
    pub identifier: String,
    pub offset: u64,
    pub length: usize,
    pub data: Vec<u8>,
    pub xor_key: Option<u8>,
}

impl StringMatchEntry {
    /// Create a match entry.
    #[must_use]
    pub fn new(identifier: impl Into<String>, offset: u64, data: Vec<u8>) -> Self {
        Self { identifier: identifier.into(), offset, length: data.len(), data, xor_key: None }
    }

    /// Return hex representation of the matched data (up to 16 bytes).
    #[must_use]
    pub fn hex_preview(&self) -> String {
        self.data.iter().take(16).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
    }
}

impl fmt::Display for RuleMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}] ({} strings)", self.rule_name, self.namespace, self.string_matches.len())
    }
}

// ─── ScanResult ───────────────────────────────────────────────────────────────

/// Result of scanning a single target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Target description (file path, PID, etc.).
    pub target: String,
    /// All matching rules.
    pub matches: Vec<RuleMatch>,
    /// Scan duration.
    pub elapsed_ms: u64,
    /// Whether the scan was aborted (timeout / max matches).
    pub aborted: bool,
    /// Bytes scanned.
    pub bytes_scanned: usize,
}

impl ScanResult {
    /// Create a clean (no matches) result.
    #[must_use]
    pub fn clean(target: impl Into<String>, elapsed_ms: u64, bytes_scanned: usize) -> Self {
        Self { target: target.into(), matches: vec![], elapsed_ms, aborted: false, bytes_scanned }
    }

    /// Return `true` if any rules matched.
    #[must_use]
    pub const fn is_match(&self) -> bool { !self.matches.is_empty() }

    /// Number of matching rules.
    #[must_use]
    pub const fn match_count(&self) -> usize { self.matches.len() }

    /// Rule names that matched.
    #[must_use]
    pub fn matched_rule_names(&self) -> Vec<&str> {
        self.matches.iter().map(|m| m.rule_name.as_str()).collect()
    }

    /// Return matches with a specific tag.
    #[must_use]
    pub fn matches_with_tag(&self, tag: &str) -> Vec<&RuleMatch> {
        self.matches.iter().filter(|m| m.tags.iter().any(|t| t == tag)).collect()
    }

    /// Serialise to JSON.
    ///
    /// # Errors
    /// Returns error string on failure.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }
}

impl fmt::Display for ScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ScanResult[{}] {} matches {}ms", self.target, self.matches.len(), self.elapsed_ms)
    }
}

// ─── ScanConfig ───────────────────────────────────────────────────────────────

/// Configuration for a scan operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Maximum time per file scan in milliseconds (0 = no limit).
    pub timeout_ms: u64,
    /// Maximum number of matches to return per scan (0 = no limit).
    pub max_matches: usize,
    /// Enable fast mode (stop at first match).
    pub fast_mode: bool,
    /// Scan recursively in directories.
    pub recursive: bool,
    /// File extensions to scan (empty = all).
    pub file_extensions: Vec<String>,
    /// Maximum file size to scan in bytes (0 = no limit).
    pub max_file_size: u64,
    /// Skip files that cannot be read.
    pub skip_unreadable: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30_000,
            max_matches: 1000,
            fast_mode: false,
            recursive: false,
            file_extensions: vec![],
            max_file_size: 100 * 1024 * 1024, // 100 MiB
            skip_unreadable: true,
        }
    }
}

impl ScanConfig {
    /// Create config with fast mode enabled.
    #[must_use]
    pub fn fast() -> Self { Self { fast_mode: true, ..Default::default() } }

    /// Create config with no limits.
    #[must_use]
    pub fn unlimited() -> Self {
        Self { timeout_ms: 0, max_matches: 0, max_file_size: 0, ..Default::default() }
    }

    /// Return `true` if the given file size is within limits.
    #[must_use]
    pub const fn within_size_limit(&self, size: u64) -> bool {
        self.max_file_size == 0 || size <= self.max_file_size
    }

    /// Return `true` if the extension matches the filter.
    #[must_use]
    pub fn extension_matches(&self, path: &Path) -> bool {
        if self.file_extensions.is_empty() { return true; }
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
        self.file_extensions.iter().any(|e| e.to_ascii_lowercase() == ext)
    }
}

// ─── Built-in rule representation (internal) ──────────────────────────────────

/// Internal representation of a compiled rule for the in-process scanner.
#[derive(Debug, Clone)]
struct InternalRule {
    name: String,
    namespace: String,
    tags: Vec<String>,
    meta: HashMap<String, String>,
    /// Byte patterns to search for: (identifier, bytes, nocase).
    patterns: Vec<(String, Vec<u8>, bool)>,
    /// For condition evaluation: require all patterns or any pattern.
    require_all: bool,
}

impl InternalRule {
    /// Test whether this rule matches the given data.
    fn matches(&self, data: &[u8]) -> Option<Vec<StringMatchEntry>> {
        let mut string_hits: Vec<StringMatchEntry> = Vec::new();
        for (ident, pattern, nocase) in &self.patterns {
            if pattern.is_empty() { continue; }
            let offsets = if *nocase {
                find_nocase(pattern, data)
            } else {
                find_bytes(pattern, data)
            };
            for off in offsets {
                let end = (off + pattern.len()).min(data.len());
                string_hits.push(StringMatchEntry::new(ident.clone(), off as u64, data[off..end].to_vec()));
            }
        }

        let matched = if self.require_all {
            let hit_ids: std::collections::HashSet<&str> =
                string_hits.iter().map(|h| h.identifier.as_str()).collect();
            self.patterns.iter().all(|(id, _, _)| hit_ids.contains(id.as_str()))
        } else {
            !string_hits.is_empty()
        };

        if matched { Some(string_hits) } else { None }
    }
}

fn find_bytes(needle: &[u8], haystack: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() { return vec![]; }
    let mut result = Vec::new();
    for start in 0..=(haystack.len() - needle.len()) {
        if haystack[start..start + needle.len()] == *needle { result.push(start); }
    }
    result
}

fn find_nocase(needle: &[u8], haystack: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() { return vec![]; }
    let needle_lc: Vec<u8> = needle.iter().map(u8::to_ascii_lowercase).collect();
    let mut result = Vec::new();
    for start in 0..=(haystack.len() - needle.len()) {
        if haystack[start..start + needle.len()].iter().zip(needle_lc.iter()).all(|(a, b)| a.to_ascii_lowercase() == *b) {
            result.push(start);
        }
    }
    result
}

// ─── YaraScanner ──────────────────────────────────────────────────────────────

/// Main YARA scanner that operates on byte buffers.
pub struct YaraScanner {
    rules: Vec<InternalRule>,
    pub config: ScanConfig,
}

impl YaraScanner {
    /// Create a new empty scanner.
    #[must_use]
    pub fn new() -> Self {
        Self { rules: vec![], config: ScanConfig::default() }
    }

    /// Create a scanner with a custom config.
    #[must_use]
    pub const fn with_config(config: ScanConfig) -> Self {
        Self { rules: vec![], config }
    }

    /// Add a rule by name with byte patterns.
    pub fn add_rule(
        &mut self,
        name: impl Into<String>,
        patterns: Vec<(String, Vec<u8>, bool)>,
        require_all: bool,
    ) {
        self.rules.push(InternalRule {
            name: name.into(), namespace: "default".into(),
            tags: vec![], meta: HashMap::new(), patterns, require_all,
        });
    }

    /// Add a rule from a text string (simplified parser).
    ///
    /// # Errors
    /// Returns `ScannerError::ParseError` if the text is invalid.
    pub fn add_rule_text(&mut self, text: &str) -> Result<(), ScannerError> {
        // Extract rule name
        let name = text.lines().find(|l| l.trim().starts_with("rule "))
            .and_then(|l| l.trim().strip_prefix("rule "))
            .and_then(|l| l.split_whitespace().next())
            .ok_or_else(|| ScannerError::ParseError("no rule name found".into()))?;

        // Extract string patterns (very simplified)
        let mut patterns = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('$')
                && let Some(eq) = line.find('=') {
                    let ident = line[..eq].trim().to_string();
                    let val_part = line[eq + 1..].trim();
                    if val_part.starts_with('"') && val_part.len() >= 2 {
                        let end = val_part[1..].find('"').unwrap_or(val_part.len() - 1) + 1;
                        let text_pattern = val_part.as_bytes()[1..end].to_vec();
                        let nocase = line.contains("nocase");
                        patterns.push((ident, text_pattern, nocase));
                    } else if val_part.starts_with('{') {
                        // Hex pattern
                        let close = val_part.find('}').unwrap_or(val_part.len());
                        let hex_content = &val_part[1..close];
                        let bytes: Vec<u8> = hex_content.split_whitespace()
                            .filter_map(|s| u8::from_str_radix(s, 16).ok())
                            .collect();
                        patterns.push((ident, bytes, false));
                    }
                }
        }

        let require_all = text.contains("all of them");
        let mut rule = InternalRule {
            name: name.to_string(), namespace: "default".into(),
            tags: vec![], meta: HashMap::new(), patterns, require_all,
        };

        // Extract tags
        if let Some(header) = text.lines().find(|l| l.trim().starts_with("rule "))
            && let Some(colon) = header.find(':')
                && let Some(brace) = header.find('{')
                    && colon < brace {
                        let tag_part = &header[colon + 1..brace];
                        rule.tags = tag_part.split_whitespace().map(str::to_string).collect();
                    }

        self.rules.push(rule);
        Ok(())
    }

    /// Scan byte data and return a `ScanResult`.
    #[must_use]
    pub fn scan_bytes(&self, data: &[u8], target: impl Into<String>) -> ScanResult {
        let target_s: String = target.into();
        let t0 = Instant::now();
        let mut matches = Vec::new();
        let mut match_count = 0usize;
        let mut aborted = false;

        for rule in &self.rules {
            if let Some(hits) = rule.matches(data) {
                match_count += 1;
                matches.push(RuleMatch {
                    rule_name: rule.name.clone(),
                    namespace: rule.namespace.clone(),
                    tags: rule.tags.clone(),
                    meta: rule.meta.clone(),
                    string_matches: hits,
                });
                if self.config.fast_mode { break; }
                if self.config.max_matches > 0 && match_count >= self.config.max_matches {
                    aborted = true;
                    break;
                }
            }
            // Timeout check (approximate)
            if self.config.timeout_ms > 0 && u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX) > self.config.timeout_ms {
                aborted = true;
                break;
            }
        }

        let elapsed = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
        ScanResult { target: target_s, matches, elapsed_ms: elapsed, aborted, bytes_scanned: data.len() }
    }

    /// Number of loaded rules.
    #[must_use]
    pub const fn rule_count(&self) -> usize { self.rules.len() }

    /// Return all rule names.
    #[must_use]
    pub fn rule_names(&self) -> Vec<&str> {
        self.rules.iter().map(|r| r.name.as_str()).collect()
    }
}

impl Default for YaraScanner {
    fn default() -> Self { Self::new() }
}

impl fmt::Debug for YaraScanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "YaraScanner({} rules)", self.rules.len())
    }
}

// ─── RulesetStats ─────────────────────────────────────────────────────────────

/// Statistics about a ruleset.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RulesetStats {
    pub rule_count: usize,
    pub string_count: usize,
    pub tagged_rule_count: usize,
    pub namespaces: Vec<String>,
    pub avg_strings_per_rule: f64,
}

impl RulesetStats {
    /// Compute stats from a scanner.
    #[must_use]
    pub fn compute(scanner: &YaraScanner) -> Self {
        let rule_count = scanner.rules.len();
        let string_count: usize = scanner.rules.iter().map(|r| r.patterns.len()).sum();
        let tagged = scanner.rules.iter().filter(|r| !r.tags.is_empty()).count();
        let ns: Vec<String> = {
            let mut seen = std::collections::HashSet::new();
            scanner.rules.iter().map(|r| r.namespace.clone()).filter(|n| seen.insert(n.clone())).collect()
        };
        let avg = if rule_count == 0 { 0.0 } else { f64::from(u32::try_from(string_count).unwrap_or(u32::MAX)) / f64::from(u32::try_from(rule_count).unwrap_or(u32::MAX)) };
        Self { rule_count, string_count, tagged_rule_count: tagged, namespaces: ns, avg_strings_per_rule: avg }
    }
}

// ─── FileScanner ──────────────────────────────────────────────────────────────

/// Scans files on disk.
pub struct FileScanner {
    scanner: YaraScanner,
    config: ScanConfig,
}

impl FileScanner {
    /// Create a new file scanner.
    #[must_use]
    pub const fn new(scanner: YaraScanner, config: ScanConfig) -> Self {
        Self { scanner, config }
    }

    /// Scan a single file.
    ///
    /// # Errors
    /// Returns `ScannerError::Io` on read failure, or `ScannerError::InvalidTarget` for directories.
    pub fn scan_file(&self, path: &Path) -> Result<ScanResult, ScannerError> {
        if path.is_dir() {
            return Err(ScannerError::InvalidTarget(format!("{} is a directory", path.display())));
        }
        if !self.config.extension_matches(path) {
            return Ok(ScanResult::clean(path.to_string_lossy(), 0, 0));
        }
        let meta = std::fs::metadata(path).map_err(|e| ScannerError::Io(e.to_string()))?;
        if !self.config.within_size_limit(meta.len()) {
            return Ok(ScanResult::clean(path.to_string_lossy(), 0, 0));
        }
        let data = std::fs::read(path).map_err(|e| ScannerError::Io(e.to_string()))?;
        let target = path.to_string_lossy().to_string();
        Ok(self.scanner.scan_bytes(&data, target))
    }

    /// Scan all files in a directory (optionally recursive).
    ///
    /// # Errors
    /// Returns `ScannerError::Io` on directory read failure.
    pub fn scan_directory(&self, dir: &Path) -> Result<Vec<ScanResult>, ScannerError> {
        let mut results = Vec::new();
        self.walk_dir(dir, &mut results)?;
        Ok(results)
    }

    fn walk_dir(&self, dir: &Path, results: &mut Vec<ScanResult>) -> Result<(), ScannerError> {
        let entries = std::fs::read_dir(dir).map_err(|e| ScannerError::Io(e.to_string()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                match self.scan_file(&path) {
                    Ok(r) => results.push(r),
                    Err(_) if self.config.skip_unreadable => {}
                    Err(e) => return Err(e),
                }
            } else if path.is_dir() && self.config.recursive {
                self.walk_dir(&path, results)?;
            }
        }
        Ok(())
    }
}

// ─── MemoryScanner ────────────────────────────────────────────────────────────

/// Scans arbitrary memory regions.
pub struct MemoryScanner {
    scanner: YaraScanner,
}

impl MemoryScanner {
    /// Create a new memory scanner.
    #[must_use]
    pub const fn new(scanner: YaraScanner) -> Self { Self { scanner } }

    /// Scan a memory region at base address `base`.
    #[must_use]
    pub fn scan_region(&self, data: &[u8], base: u64, label: impl Into<String>) -> ScanResult {
        let mut result = self.scanner.scan_bytes(data, label);
        // Adjust offsets to be absolute addresses
        for m in &mut result.matches {
            for s in &mut m.string_matches {
                s.offset += base;
            }
        }
        result
    }

    /// Scan multiple regions and return all results.
    #[must_use]
    pub fn scan_regions(&self, regions: &[(u64, Vec<u8>)]) -> Vec<ScanResult> {
        regions.iter().map(|(base, data)| {
            self.scan_region(data, *base, format!("mem@{base:#x}"))
        }).collect()
    }
}

// ─── ProcessScanner ──────────────────────────────────────────────────────────

/// Scans a process's virtual memory (stub implementation).
pub struct ProcessScanner {
    scanner: YaraScanner,
}

impl ProcessScanner {
    /// Create a new process scanner.
    #[must_use]
    pub const fn new(scanner: YaraScanner) -> Self { Self { scanner } }

    /// Scan a process by PID (stub — requires OS-specific memory access).
    ///
    /// # Errors
    /// Returns `ScannerError::Process` always (stub).
    pub fn scan_pid(&self, _pid: u32) -> Result<Vec<ScanResult>, ScannerError> {
        Err(ScannerError::Process("process scanning requires elevated privileges".into()))
    }

    /// Scan an in-memory representation of a process.
    #[must_use]
    pub fn scan_process_image(&self, pid: u32, regions: &[(u64, Vec<u8>)]) -> Vec<ScanResult> {
        let mem = MemoryScanner {
            scanner: YaraScanner {
                rules: self.scanner.rules.clone(),
                config: self.scanner.config.clone(),
            },
        };
        let mut results = mem.scan_regions(regions);
        for r in &mut results {
            r.target = format!("pid:{pid} {}", r.target);
        }
        results
    }
}

// ─── BatchScanner ─────────────────────────────────────────────────────────────

/// Parallel multi-file batch scanner.
pub struct BatchScanner {
    scanner: Arc<YaraScanner>,
    config: ScanConfig,
    results: Arc<Mutex<Vec<(PathBuf, ScanResult)>>>,
}

impl BatchScanner {
    /// Create a new batch scanner.
    #[must_use]
    pub fn new(scanner: YaraScanner, config: ScanConfig) -> Self {
        Self {
            scanner: Arc::new(scanner),
            config,
            results: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Scan a list of files (sequentially in this implementation).
    ///
    /// Results are also cached on `self.results` so subsequent calls to
    /// [`Self::cached_results`] return the most recent batch's outputs.
    #[must_use] 
    pub fn scan_files(&self, paths: &[PathBuf]) -> Vec<(PathBuf, ScanResult)> {
        let start = std::time::Instant::now();
        let budget: Duration = if self.config.timeout_ms > 0 {
            Duration::from_millis(self.config.timeout_ms)
        } else {
            Duration::from_secs(u64::MAX / 2)
        };
        let mut results = Vec::with_capacity(paths.len());
        for path in paths {
            if start.elapsed() > budget {
                break;
            }
            match std::fs::read(path) {
                Ok(data) => {
                    let result = self.scanner.scan_bytes(&data, path.to_string_lossy().as_ref());
                    results.push((path.clone(), result));
                }
                Err(e) if self.config.skip_unreadable => {
                    let mut r = ScanResult::clean(path.to_string_lossy(), 0, 0);
                    r.target = format!("{} (skipped: {})", r.target, e);
                    results.push((path.clone(), r));
                }
                Err(e) => {
                    // Record error as clean result with the IO error captured
                    // in the target field so callers can surface what failed.
                    let mut r = ScanResult::clean(path.to_string_lossy(), 0, 0);
                    r.aborted = true;
                    r.target = format!("{} (error: {})", r.target, e);
                    results.push((path.clone(), r));
                }
            }
        }
        // Cache the batch's results so callers can inspect the most recent
        // run via `cached_results()` without re-scanning.
        if let Ok(mut cache) = self.results.lock() {
            cache.clone_from(&results);
        }
        results
    }

    /// Return a clone of the results produced by the last `scan_files` call.
    /// Returns an empty vector if no batch has been run yet.
    #[must_use]
    pub fn cached_results(&self) -> Vec<(PathBuf, ScanResult)> {
        self.results.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Return the total number of scanned files.
    #[must_use]
    pub fn scan_bytes_batch(&self, targets: &[(&str, &[u8])]) -> Vec<ScanResult> {
        targets.iter().map(|(name, data)| {
            self.scanner.scan_bytes(data, *name)
        }).collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner_with_rules() -> YaraScanner {
        let mut s = YaraScanner::new();
        // Rule 1: detect "malware"
        s.add_rule("MalwareRule", vec![("$s".into(), b"malware".to_vec(), false)], false);
        // Rule 2: detect MZ header
        s.add_rule("MZHeader", vec![("$mz".into(), b"MZ".to_vec(), false)], false);
        // Rule 3: nocase
        s.add_rule("NocaseRule", vec![("$kw".into(), b"SUSPICIOUS".to_vec(), true)], false);
        // Rule 4: multi-string, require all
        s.add_rule("MultiRule", vec![
            ("$a".into(), b"aaa".to_vec(), false),
            ("$b".into(), b"bbb".to_vec(), false),
        ], true);
        s
    }

    // ── ScanConfig ────────────────────────────────────────────────────────────

    #[test]
    fn test_config_default() {
        let c = ScanConfig::default();
        assert!(c.timeout_ms > 0);
        assert!(c.skip_unreadable);
    }

    #[test]
    fn test_config_fast() {
        let c = ScanConfig::fast();
        assert!(c.fast_mode);
    }

    #[test]
    fn test_config_unlimited() {
        let c = ScanConfig::unlimited();
        assert_eq!(c.timeout_ms, 0);
        assert_eq!(c.max_matches, 0);
    }

    #[test]
    fn test_config_size_limit() {
        let c = ScanConfig { max_file_size: 100, ..Default::default() };
        assert!(c.within_size_limit(100));
        assert!(!c.within_size_limit(101));
    }

    #[test]
    fn test_config_extension_filter() {
        let c = ScanConfig { file_extensions: vec!["exe".into()], ..Default::default() };
        assert!(c.extension_matches(Path::new("test.exe")));
        assert!(!c.extension_matches(Path::new("test.txt")));
    }

    #[test]
    fn test_config_extension_empty_matches_all() {
        let c = ScanConfig::default();
        assert!(c.extension_matches(Path::new("anything.xyz")));
    }

    // ── YaraScanner ───────────────────────────────────────────────────────────

    #[test]
    fn test_scanner_rule_count() {
        let s = scanner_with_rules();
        assert_eq!(s.rule_count(), 4);
    }

    #[test]
    fn test_scanner_scan_match() {
        let s = scanner_with_rules();
        let result = s.scan_bytes(b"contains malware string", "test");
        assert!(result.is_match());
        assert!(result.matched_rule_names().contains(&"MalwareRule"));
    }

    #[test]
    fn test_scanner_scan_no_match() {
        let s = scanner_with_rules();
        let result = s.scan_bytes(b"nothing here", "test");
        // MZ, malware, suspicious, aaa+bbb are all absent
        assert!(!result.is_match());
    }

    #[test]
    fn test_scanner_mz_header() {
        let s = scanner_with_rules();
        let data = b"MZ\x90\x00\x03\x00\x00";
        let result = s.scan_bytes(data, "pe.exe");
        assert!(result.matched_rule_names().contains(&"MZHeader"));
    }

    #[test]
    fn test_scanner_nocase() {
        let s = scanner_with_rules();
        let result = s.scan_bytes(b"something suspicious here", "test");
        assert!(result.matched_rule_names().contains(&"NocaseRule"));
    }

    #[test]
    fn test_scanner_multi_string_all_required() {
        let s = scanner_with_rules();
        let both = s.scan_bytes(b"aaa bbb", "both");
        assert!(both.matched_rule_names().contains(&"MultiRule"));
        let only_a = s.scan_bytes(b"aaa only", "a_only");
        assert!(!only_a.matched_rule_names().contains(&"MultiRule"));
    }

    #[test]
    fn test_scanner_fast_mode_stops_early() {
        let mut s = scanner_with_rules();
        s.config.fast_mode = true;
        let data = b"malware MZ SUSPICIOUS aaa bbb";
        let result = s.scan_bytes(data, "fast");
        assert!(result.match_count() <= 1);
    }

    #[test]
    fn test_scanner_max_matches() {
        let mut s = YaraScanner::new();
        for i in 0..10 {
            s.add_rule(format!("rule_{i}"), vec![(format!("$s{i}"), b"match".to_vec(), false)], false);
        }
        s.config.max_matches = 3;
        let result = s.scan_bytes(b"match match match", "test");
        assert!(result.match_count() <= 3 || result.aborted);
    }

    #[test]
    fn test_scanner_add_rule_text() {
        let mut s = YaraScanner::new();
        s.add_rule_text(r#"rule TestRule {
    strings:
        $s = "hello"
    condition:
        $s
}"#).unwrap();
        assert_eq!(s.rule_count(), 1);
        let r = s.scan_bytes(b"say hello world", "t");
        assert!(r.is_match());
    }

    #[test]
    fn test_scanner_add_rule_hex() {
        let mut s = YaraScanner::new();
        s.add_rule_text(r"rule HexRule {
    strings:
        $h = { DE AD BE EF }
    condition:
        $h
}").unwrap();
        let data = &[0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        let r = s.scan_bytes(data, "t");
        assert!(r.is_match());
    }

    #[test]
    fn test_scanner_rule_names() {
        let s = scanner_with_rules();
        let names = s.rule_names();
        assert!(names.contains(&"MalwareRule"));
        assert!(names.contains(&"MZHeader"));
    }

    // ── ScanResult ────────────────────────────────────────────────────────────

    #[test]
    fn test_scan_result_clean() {
        let r = ScanResult::clean("target.exe", 5, 1024);
        assert!(!r.is_match());
        assert_eq!(r.match_count(), 0);
    }

    #[test]
    fn test_scan_result_matched_rule_names() {
        let s = scanner_with_rules();
        let r = s.scan_bytes(b"malware", "test");
        let names = r.matched_rule_names();
        assert!(names.contains(&"MalwareRule"));
    }

    #[test]
    fn test_scan_result_matches_with_tag() {
        let mut s = YaraScanner::new();
        let rule = InternalRule {
            name: "Tagged".into(), namespace: "default".into(),
            tags: vec!["ransom".into()], meta: HashMap::new(),
            patterns: vec![("$s".into(), b"pay".to_vec(), false)],
            require_all: false,
        };
        s.rules.push(rule);
        let r = s.scan_bytes(b"please pay now", "test");
        assert!(!r.matches_with_tag("ransom").is_empty());
        assert!(r.matches_with_tag("trojan").is_empty());
    }

    #[test]
    fn test_scan_result_to_json() {
        let r = ScanResult::clean("t", 0, 0);
        assert!(r.to_json().is_ok());
    }

    #[test]
    fn test_scan_result_display() {
        let r = ScanResult::clean("t.exe", 5, 100);
        assert!(r.to_string().contains("t.exe"));
    }

    // ── StringMatchEntry ──────────────────────────────────────────────────────

    #[test]
    fn test_string_match_hex_preview() {
        let m = StringMatchEntry::new("$s", 0, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(m.hex_preview(), "de ad be ef");
    }

    #[test]
    fn test_string_match_truncated_preview() {
        let m = StringMatchEntry::new("$s", 0, vec![0xFF; 20]);
        let preview = m.hex_preview();
        // Preview is at most 16 bytes = 47 chars (16*2 + 15 spaces)
        assert!(preview.len() <= 47);
    }

    // ── RulesetStats ──────────────────────────────────────────────────────────

    #[test]
    fn test_ruleset_stats() {
        let s = scanner_with_rules();
        let stats = RulesetStats::compute(&s);
        assert_eq!(stats.rule_count, 4);
        assert!(stats.string_count > 0);
        assert!(stats.avg_strings_per_rule > 0.0);
    }

    #[test]
    fn test_ruleset_stats_empty() {
        let s = YaraScanner::new();
        let stats = RulesetStats::compute(&s);
        assert_eq!(stats.rule_count, 0);
        assert_eq!(stats.avg_strings_per_rule, 0.0);
    }

    // ── MemoryScanner ─────────────────────────────────────────────────────────

    #[test]
    fn test_memory_scanner_region() {
        let s = scanner_with_rules();
        let ms = MemoryScanner::new(s);
        let r = ms.scan_region(b"malware data", 0x401000, "test_region");
        assert!(r.is_match());
        // Offsets should be adjusted
        let m = &r.matches[0].string_matches[0];
        assert!(m.offset >= 0x401000);
    }

    #[test]
    fn test_memory_scanner_multiple_regions() {
        let s = scanner_with_rules();
        let ms = MemoryScanner::new(s);
        let regions = vec![
            (0x1000u64, b"nothing here".to_vec()),
            (0x2000u64, b"MZ\x90 malware".to_vec()),
        ];
        let results = ms.scan_regions(&regions);
        assert_eq!(results.len(), 2);
        assert!(!results[0].is_match());
        assert!(results[1].is_match());
    }

    // ── ProcessScanner ────────────────────────────────────────────────────────

    #[test]
    fn test_process_scanner_pid_error() {
        let s = scanner_with_rules();
        let ps = ProcessScanner::new(s);
        assert!(ps.scan_pid(1234).is_err());
    }

    #[test]
    fn test_process_scanner_image() {
        let s = scanner_with_rules();
        let ps = ProcessScanner::new(s);
        let regions = vec![(0x401000u64, b"malware payload".to_vec())];
        let results = ps.scan_process_image(9999, &regions);
        assert!(!results.is_empty());
        assert!(results[0].target.contains("pid:9999"));
    }

    // ── BatchScanner ──────────────────────────────────────────────────────────

    #[test]
    fn test_batch_scanner_bytes() {
        let s = scanner_with_rules();
        let bs = BatchScanner::new(s, ScanConfig::default());
        let targets: Vec<(&str, &[u8])> = vec![
            ("target1", b"malware code"),
            ("target2", b"clean code"),
        ];
        let results = bs.scan_bytes_batch(&targets);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_match());
        assert!(!results[1].is_match());
    }
}
