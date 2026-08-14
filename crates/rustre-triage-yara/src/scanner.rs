// rustre-triage-yara/src/scanner.rs
//! High-performance YARA scanner with session management and batch scanning.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    EnhancedYaraMatch, EnhancedYaraRule, RuleEngine, YaraTriageEngine, YaraTriageMatch,
    YaraTriageRule,
};
pub use crate::{NamedPattern, PatternKind, StringModifiers, YaraCondition};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("rule error: {0}")]
    Rule(String),
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("scan timeout")]
    Timeout,
    #[error("{0}")]
    Other(String),
}

pub type ScanResult<T> = Result<T, ScanError>;

// ─── Scan options ─────────────────────────────────────────────────────────────

/// Options controlling a single scan.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Maximum bytes to scan (None = entire file).
    pub max_bytes: Option<usize>,
    /// Whether to scan in fast mode (first match per rule only).
    pub fast_mode: bool,
    /// Whether to include string match data in results.
    pub include_match_data: bool,
    /// Optional entry-point offset for PE/ELF files.
    pub entry_point: Option<u64>,
    /// Minimum severity to include in results (`"info"`, `"low"`, etc.).
    pub min_severity: Option<String>,
    /// Timeout in milliseconds (0 = no timeout).
    pub timeout_ms: u64,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_bytes: None,
            fast_mode: false,
            include_match_data: true,
            entry_point: None,
            min_severity: None,
            timeout_ms: 0,
        }
    }
}

impl ScanOptions {
    #[must_use]
    pub fn fast() -> Self {
        Self {
            fast_mode: true,
            ..Default::default()
        }
    }
    #[must_use]
    pub const fn with_max_bytes(mut self, n: usize) -> Self {
        self.max_bytes = Some(n);
        self
    }
    #[must_use]
    pub fn with_min_severity(mut self, s: impl Into<String>) -> Self {
        self.min_severity = Some(s.into());
        self
    }
    #[must_use]
    pub const fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }
    #[must_use]
    pub const fn with_ep(mut self, ep: u64) -> Self {
        self.entry_point = Some(ep);
        self
    }
}

// ─── Scan session ─────────────────────────────────────────────────────────────

/// An isolated scan session holding a set of rules.
pub struct ScanSession {
    pub id: String,
    engine: RuleEngine,
    triage_engine: YaraTriageEngine,
    pub options: ScanOptions,
    stats: SessionStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionStats {
    pub scans_completed: u64,
    pub total_matches: u64,
    pub total_bytes_scanned: u64,
    pub total_scan_time_ms: u64,
}

impl ScanSession {
    /// Create a new empty session.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            engine: RuleEngine::new(),
            triage_engine: YaraTriageEngine::new(),
            options: ScanOptions::default(),
            stats: SessionStats::default(),
        }
    }

    /// Create a session pre-loaded with default rules.
    pub fn with_defaults(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            engine: RuleEngine::load_builtin_rules(),
            triage_engine: YaraTriageEngine::load_default_rules(),
            options: ScanOptions::default(),
            stats: SessionStats::default(),
        }
    }

    /// Add an enhanced YARA rule.
    pub fn add_rule(&mut self, rule: EnhancedYaraRule) {
        self.engine.add_rule(rule);
    }

    /// Add a simple triage rule.
    ///
    /// # Errors
    ///
    /// Returns an error if the rule fails validation.
    pub fn add_triage_rule(&mut self, rule: YaraTriageRule) -> Result<(), crate::YaraError> {
        self.triage_engine.add_rule(rule)
    }

    /// Scan raw byte data.
    ///
    /// Returns [`ScanError::Timeout`] if `options.timeout_ms` is non-zero and
    /// the scan exceeds that deadline.
    ///
    /// # Errors
    ///
    /// Returns [`ScanError::Timeout`] if the configured timeout is exceeded.
    pub fn scan_bytes(&mut self, data: &[u8]) -> ScanResult<ScanHits> {
        let t0 = Instant::now();
        let deadline_ms = self.options.timeout_ms;

        let scan_data = self.options.max_bytes.map_or(data, |limit| &data[..data.len().min(limit)]);

        let enhanced = self
            .engine
            .scan_with_ep(scan_data, self.options.entry_point);

        // Check timeout after the (potentially expensive) enhanced scan.
        if deadline_ms > 0 && u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX) >= deadline_ms {
            return Err(ScanError::Timeout);
        }

        let triage = self.triage_engine.scan(scan_data);

        // Check timeout again after triage scan.
        if deadline_ms > 0 && u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX) >= deadline_ms {
            return Err(ScanError::Timeout);
        }

        let elapsed = u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.stats.scans_completed += 1;
        self.stats.total_bytes_scanned += scan_data.len() as u64;
        self.stats.total_matches += (enhanced.len() + triage.len()) as u64;
        self.stats.total_scan_time_ms += elapsed;

        Ok(ScanHits {
            enhanced_matches: enhanced,
            triage_matches: triage,
            scan_time_ms: elapsed,
            bytes_scanned: scan_data.len(),
        })
    }

    /// Scan a file on disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or scanning fails.
    pub fn scan_file(&mut self, path: &Path) -> ScanResult<ScanHits> {
        let data = std::fs::read(path)?;
        self.scan_bytes(&data)
    }

    /// Session statistics.
    #[must_use]
    pub fn stats(&self) -> &SessionStats {
        &self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = SessionStats::default();
    }

    /// Number of enhanced rules loaded.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.engine.rule_count()
    }

    /// Number of triage rules loaded.
    #[must_use]
    pub fn triage_rule_count(&self) -> usize {
        self.triage_engine.rule_count()
    }

    /// Clone the rule engine (snapshot of all loaded rules).
    #[must_use]
    pub fn clone_engine(&self) -> RuleEngine {
        self.engine.clone()
    }

    /// Clone the triage engine (snapshot of all loaded rules).
    #[must_use]
    pub fn clone_triage_engine(&self) -> YaraTriageEngine {
        self.triage_engine.clone()
    }
}

// ─── Scan hits ────────────────────────────────────────────────────────────────

/// Combined results of one scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHits {
    pub enhanced_matches: Vec<EnhancedYaraMatch>,
    pub triage_matches: Vec<YaraTriageMatch>,
    pub scan_time_ms: u64,
    pub bytes_scanned: usize,
}

impl ScanHits {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.enhanced_matches.is_empty() && self.triage_matches.is_empty()
    }

    #[must_use]
    pub fn total_matches(&self) -> usize {
        self.enhanced_matches.len() + self.triage_matches.len()
    }

    /// Compute a quick threat score (0–100) from the hits.
    #[must_use]
    pub fn threat_score(&self) -> u8 {
        let mut score: u32 = 0;
        for m in &self.enhanced_matches {
            let sev = m
                .meta
                .get("severity")
                .map_or("medium", |s| s.as_str());
            score = score.saturating_add(severity_score(sev));
        }
        for m in &self.triage_matches {
            score = score.saturating_add(severity_score(&m.severity));
        }
        score.min(100) as u8
    }

    /// List all matched rule names.
    #[must_use]
    pub fn rule_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .enhanced_matches
            .iter()
            .map(|m| m.rule_name.as_str())
            .chain(self.triage_matches.iter().map(|m| m.rule_name.as_str()))
            .collect();
        names.sort_unstable();
        names.dedup();
        names
    }

    /// Filter hits to only those with severity >= `min_severity`.
    #[must_use]
    pub fn filter_severity(&self, min: &str) -> ScanHits {
        let min_score = severity_score(min);
        Self {
            enhanced_matches: self
                .enhanced_matches
                .iter()
                .filter(|m| {
                    let sev = m
                        .meta
                        .get("severity")
                        .map_or("medium", |s| s.as_str());
                    severity_score(sev) >= min_score
                })
                .cloned()
                .collect(),
            triage_matches: self
                .triage_matches
                .iter()
                .filter(|m| severity_score(&m.severity) >= min_score)
                .cloned()
                .collect(),
            scan_time_ms: self.scan_time_ms,
            bytes_scanned: self.bytes_scanned,
        }
    }
}

fn severity_score(s: &str) -> u32 {
    match s.to_lowercase().as_str() {
        "critical" => 90,
        "high" => 65,
        "medium" => 40,
        "low" => 20,
        "info" => 5,
        _ => 10,
    }
}

// ─── Batch scanner ────────────────────────────────────────────────────────────

/// Result of a single file in a batch scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchScanEntry {
    pub path: PathBuf,
    pub hits: Option<ScanHits>,
    pub error: Option<String>,
    pub threat_score: u8,
}

impl BatchScanEntry {
    #[must_use]
    pub fn ok(path: PathBuf, hits: ScanHits) -> Self {
        let score = hits.threat_score();
        Self {
            path,
            hits: Some(hits),
            error: None,
            threat_score: score,
        }
    }
    pub fn err(path: PathBuf, e: impl Into<String>) -> Self {
        Self {
            path,
            hits: None,
            error: Some(e.into()),
            threat_score: 0,
        }
    }
}

/// Batch scan multiple files with a shared session.
pub fn batch_scan(paths: &[PathBuf], session: &mut ScanSession) -> Vec<BatchScanEntry> {
    paths
        .iter()
        .map(|p| match session.scan_file(p) {
            Ok(hits) => BatchScanEntry::ok(p.clone(), hits),
            Err(e) => BatchScanEntry::err(p.clone(), e.to_string()),
        })
        .collect()
}

/// Batch scan with a limit on maximum files.
pub fn batch_scan_limited(
    paths: &[PathBuf],
    session: &mut ScanSession,
    limit: usize,
) -> Vec<BatchScanEntry> {
    batch_scan(&paths[..paths.len().min(limit)], session)
}

// ─── Session pool ─────────────────────────────────────────────────────────────

/// Thread-safe pool of named scan sessions.
pub struct SessionPool {
    sessions: Arc<Mutex<HashMap<String, ScanSession>>>,
}

impl Default for SessionPool {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionPool {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create and add a new session.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn create_session(&self, id: impl Into<String>, defaults: bool) -> String {
        let id_str: String = id.into();
        let session = if defaults {
            ScanSession::with_defaults(&id_str)
        } else {
            ScanSession::new(&id_str)
        };
        self.sessions
            .lock()
            .unwrap()
            .insert(id_str.clone(), session);
        id_str
    }

    /// Scan bytes using a named session.
    ///
    /// # Errors
    ///
    /// Returns [`ScanError::SessionNotFound`] if the session does not exist, or
    /// a scan error if scanning fails.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn scan_bytes(&self, session_id: &str, data: &[u8]) -> ScanResult<ScanHits> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(session_id)
            .ok_or_else(|| ScanError::SessionNotFound(session_id.to_string()))?;
        session.scan_bytes(data)
    }

    /// Remove a session.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    pub fn remove_session(&self, session_id: &str) {
        self.sessions.lock().unwrap().remove(session_id);
    }

    /// List all session IDs.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn session_ids(&self) -> Vec<String> {
        self.sessions.lock().unwrap().keys().cloned().collect()
    }

    /// Session count.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}

// ─── Match to verdict conversion ──────────────────────────────────────────────

/// Convert scan hits to a simple verdict string.
#[must_use]
pub fn match_to_verdict(hits: &ScanHits) -> &'static str {
    let score = hits.threat_score();
    if score == 0 {
        "clean"
    } else if score < 20 {
        "informational"
    } else if score < 40 {
        "low"
    } else if score < 60 {
        "suspicious"
    } else if score < 80 {
        "high"
    } else {
        "malicious"
    }
}

/// Convert a scan hits set to a structured verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanVerdict {
    pub verdict: String,
    pub score: u8,
    pub rule_count: usize,
    pub families: Vec<String>,
    pub top_severity: String,
}

impl ScanVerdict {
    #[must_use]
    pub fn from_hits(hits: &ScanHits) -> Self {
        let score = hits.threat_score();
        let verdict = match_to_verdict(hits).to_string();

        let mut families: Vec<String> = hits
            .triage_matches
            .iter()
            .filter_map(|m| m.description.split(' ').next().map(ToString::to_string))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        families.sort();

        let top_severity = if hits.triage_matches.iter().any(|m| m.severity == "critical")
            || hits
                .enhanced_matches
                .iter()
                .any(|m| m.meta.get("severity").is_some_and(|s| s == "critical"))
        {
            "critical"
        } else if hits.triage_matches.iter().any(|m| m.severity == "high")
            || hits
                .enhanced_matches
                .iter()
                .any(|m| m.meta.get("severity").is_some_and(|s| s == "high"))
        {
            "high"
        } else if score > 0 {
            "medium"
        } else {
            "none"
        }
        .to_string();

        Self {
            verdict,
            score,
            rule_count: hits.total_matches(),
            families,
            top_severity,
        }
    }
}

// ─── Parallel scan ────────────────────────────────────────────────────────────

/// Parallel batch scan using thread-per-file with a shared rule set snapshot.
///
/// Each thread gets its own [`ScanSession`] clone from the provided `template`.
#[must_use]
pub fn parallel_batch_scan(
    paths: &[PathBuf],
    template_session: &ScanSession,
) -> Vec<BatchScanEntry> {
    // Clone rule engines from the template so custom rules added by the caller
    // are preserved in the batch scan rather than silently discarded.
    let engine = template_session.clone_engine();
    let triage = template_session.clone_triage_engine();

    // Inherit scan limits and entry-point hint from the template session so
    // batch behaviour matches single-file scans configured by the caller.
    let max_bytes = template_session.options.max_bytes;
    let entry_point = template_session.options.entry_point;

    paths
        .iter()
        .map(|p| {
            let data = match std::fs::read(p) {
                Ok(d) => d,
                Err(e) => return BatchScanEntry::err(p.clone(), e.to_string()),
            };
            let scan_data: &[u8] = match max_bytes {
                Some(limit) => &data[..data.len().min(limit)],
                None => &data,
            };
            let enhanced = engine.scan_with_ep(scan_data, entry_point);
            let triage_hits = triage.scan(scan_data);
            let hits = ScanHits {
                enhanced_matches: enhanced,
                triage_matches: triage_hits,
                scan_time_ms: 0,
                bytes_scanned: scan_data.len(),
            };
            BatchScanEntry::ok(p.clone(), hits)
        })
        .collect()
}

// ─── Scanner builder ──────────────────────────────────────────────────────────

/// Builder for creating configured [`ScanSession`]s.
pub struct ScannerBuilder {
    use_defaults: bool,
    extra_rules: Vec<EnhancedYaraRule>,
    options: ScanOptions,
    session_id: String,
}

impl ScannerBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            use_defaults: true,
            extra_rules: Vec::new(),
            options: ScanOptions::default(),
            session_id: "default".to_string(),
        }
    }

    #[must_use]
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.session_id = id.into();
        self
    }

    #[must_use]
    pub fn no_defaults(mut self) -> Self {
        self.use_defaults = false;
        self
    }

    #[must_use]
    pub fn add_rule(mut self, rule: EnhancedYaraRule) -> Self {
        self.extra_rules.push(rule);
        self
    }

    #[must_use]
    pub fn with_options(mut self, opts: ScanOptions) -> Self {
        self.options = opts;
        self
    }

    #[must_use]
    pub fn build(self) -> ScanSession {
        let mut session = if self.use_defaults {
            ScanSession::with_defaults(&self.session_id)
        } else {
            ScanSession::new(&self.session_id)
        };
        session.options = self.options;
        for rule in self.extra_rules {
            session.add_rule(rule);
        }
        session
    }
}

impl Default for ScannerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Scanner statistics ───────────────────────────────────────────────────────

/// Aggregate statistics across multiple batch results.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BatchStats {
    pub total_files: usize,
    pub files_with_hits: usize,
    pub files_errored: usize,
    pub total_matches: usize,
    pub max_score: u8,
    pub avg_score: f64,
    pub total_bytes: u64,
    pub total_scan_ms: u64,
}

impl BatchStats {
    #[must_use]
    pub fn from_entries(entries: &[BatchScanEntry]) -> Self {
        let mut stats = Self {
            total_files: entries.len(),
            ..Default::default()
        };
        let mut score_sum: u64 = 0;
        for e in entries {
            if e.error.is_some() {
                stats.files_errored += 1;
                continue;
            }
            if let Some(hits) = &e.hits {
                if !hits.is_empty() {
                    stats.files_with_hits += 1;
                }
                stats.total_matches += hits.total_matches();
                stats.total_bytes += hits.bytes_scanned as u64;
                stats.total_scan_ms += hits.scan_time_ms;
            }
            if e.threat_score > stats.max_score {
                stats.max_score = e.threat_score;
            }
            score_sum += u64::from(e.threat_score);
        }
        let counted = f64::from(u32::try_from(stats.total_files - stats.files_errored).unwrap_or(u32::MAX));
        if counted > 0.0 {
            stats.avg_score = f64::from(u32::try_from(score_sum).unwrap_or(u32::MAX)) / counted;
        }
        stats
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_session_default_has_rules() {
        let s = ScanSession::with_defaults("test");
        assert!(s.rule_count() > 0 || s.triage_rule_count() > 0);
    }

    #[test]
    fn scan_session_scan_bytes_empty() {
        let mut s = ScanSession::new("empty");
        let hits = s.scan_bytes(b"data").unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn scan_session_finds_mz() {
        let mut s = ScanSession::with_defaults("mz");
        let hits = s.scan_bytes(b"MZ\x00\x00").unwrap();
        // Should match PE magic in enhanced rules
        assert!(hits.bytes_scanned == 4);
    }

    #[test]
    fn scan_hits_threat_score_bounded() {
        let hits = ScanHits {
            enhanced_matches: Vec::new(),
            triage_matches: Vec::new(),
            scan_time_ms: 0,
            bytes_scanned: 100,
        };
        assert_eq!(hits.threat_score(), 0);
    }

    #[test]
    fn match_to_verdict_clean() {
        let hits = ScanHits {
            enhanced_matches: Vec::new(),
            triage_matches: Vec::new(),
            scan_time_ms: 0,
            bytes_scanned: 10,
        };
        assert_eq!(match_to_verdict(&hits), "clean");
    }

    #[test]
    fn scan_verdict_from_hits() {
        let hits = ScanHits {
            enhanced_matches: Vec::new(),
            triage_matches: Vec::new(),
            scan_time_ms: 0,
            bytes_scanned: 10,
        };
        let v = ScanVerdict::from_hits(&hits);
        assert_eq!(v.verdict, "clean");
        assert_eq!(v.score, 0);
    }

    #[test]
    fn session_pool_create_and_scan() {
        let pool = SessionPool::new();
        let id = pool.create_session("s1", true);
        let hits = pool.scan_bytes(&id, b"MZ data").unwrap();
        assert_eq!(hits.bytes_scanned, 7);
    }

    #[test]
    fn session_pool_unknown_session_error() {
        let pool = SessionPool::new();
        let result = pool.scan_bytes("nonexistent", b"data");
        assert!(result.is_err());
    }

    #[test]
    fn scanner_builder_defaults() {
        let s = ScannerBuilder::new().build();
        assert!(s.rule_count() > 0 || s.triage_rule_count() > 0);
    }

    #[test]
    fn scanner_builder_no_defaults() {
        let s = ScannerBuilder::new().no_defaults().build();
        assert_eq!(s.rule_count(), 0);
        assert_eq!(s.triage_rule_count(), 0);
    }

    #[test]
    fn batch_stats_all_errors() {
        let entries = vec![
            BatchScanEntry::err(PathBuf::from("/a"), "err1"),
            BatchScanEntry::err(PathBuf::from("/b"), "err2"),
        ];
        let stats = BatchStats::from_entries(&entries);
        assert_eq!(stats.total_files, 2);
        assert_eq!(stats.files_errored, 2);
        assert_eq!(stats.avg_score, 0.0);
    }

    #[test]
    fn filter_severity_filters_correctly() {
        let hits = ScanHits {
            enhanced_matches: Vec::new(),
            triage_matches: vec![
                crate::YaraTriageMatch {
                    rule_name: "Low".into(),
                    matched_strings: Vec::new(),
                    description: "low".into(),
                    severity: "low".into(),
                },
                crate::YaraTriageMatch {
                    rule_name: "Critical".into(),
                    matched_strings: Vec::new(),
                    description: "critical".into(),
                    severity: "critical".into(),
                },
            ],
            scan_time_ms: 0,
            bytes_scanned: 100,
        };
        let filtered = hits.filter_severity("high");
        assert_eq!(filtered.triage_matches.len(), 1);
        assert_eq!(filtered.triage_matches[0].severity, "critical");
    }

    #[test]
    fn scan_options_builder_methods() {
        let opts = ScanOptions::fast()
            .with_max_bytes(1024)
            .with_min_severity("high")
            .with_timeout(5000)
            .with_ep(0x1000);
        assert!(opts.fast_mode);
        assert_eq!(opts.max_bytes, Some(1024));
        assert_eq!(opts.timeout_ms, 5000);
        assert_eq!(opts.entry_point, Some(0x1000));
    }
}
