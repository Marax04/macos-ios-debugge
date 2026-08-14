//! `vt_hunting_notifier` — `VirusTotal` hunting notification handling.
//!
//! Models the two hunting systems exposed by VT v3:
//!
//! * **`LiveHunt`** — YARA rules uploaded to VT that trigger on newly submitted
//!   samples.  Results arrive as webhook callbacks or are polled via the API.
//! * **`RetroHunt`** — YARA rules run against VT's historical corpus.  Results
//!   are produced as a batch job.
//!
//! The [`VtHuntingNotifier`] receives [`HuntResult`]s, deduplicates them, and
//! dispatches them to registered callbacks.  It also maintains an in-memory
//! ring buffer of recent results for replay and audit.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

// ── LivehuntMatch ─────────────────────────────────────────────────────────────

/// A single file that matched a `LiveHunt` YARA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivehuntMatch {
    /// Internal match identifier.
    pub id: String,
    /// SHA-256 of the matching file.
    pub sha256: String,
    /// MD5 of the matching file.
    pub md5: Option<String>,
    /// File name (if known).
    pub file_name: Option<String>,
    /// File size in bytes.
    pub file_size: Option<u64>,
    /// File type (e.g., "PE32", "ELF").
    pub file_type: Option<String>,
    /// YARA rule names that matched.
    pub matching_rules: Vec<String>,
    /// Tags on the file.
    pub tags: Vec<String>,
    /// Number of detections at time of match.
    pub positives: u32,
    /// Detection ratio denominator.
    pub total_engines: u32,
    /// Timestamp of the match (Unix epoch seconds).
    pub timestamp: u64,
    /// Name of the ruleset that triggered.
    pub ruleset_name: String,
    /// VT permalink.
    pub permalink: Option<String>,
}

impl LivehuntMatch {
    /// Detection ratio as a percentage.
    #[must_use]
    pub fn detection_pct(&self) -> f64 {
        if self.total_engines == 0 {
            0.0
        } else {
            f64::from(self.positives) / f64::from(self.total_engines) * 100.0
        }
    }

    /// Return `true` if the file has at least one detection.
    #[must_use]
    pub const fn is_malicious(&self) -> bool {
        self.positives > 0
    }
}

impl fmt::Display for LivehuntMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LivehuntMatch {{ sha256={}, rules={:?}, det={}/{} }}",
            // Use char_indices to avoid slicing in the middle of a multibyte
            // codepoint.  SHA-256 hex is always ASCII in practice, but the
            // field is an unvalidated String so we must be defensive.
            &self.sha256[..self.sha256.char_indices().nth(8).map_or(self.sha256.len(), |(i, _)| i)],
            self.matching_rules,
            self.positives,
            self.total_engines,
        )
    }
}

// ── RetroHuntResult ───────────────────────────────────────────────────────────

/// The outcome of a completed `RetroHunt` job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetroHuntResult {
    /// `RetroHunt` job identifier.
    pub job_id: String,
    /// YARA rule text that was used.
    pub rule_text: String,
    /// Number of matching files.
    pub match_count: u64,
    /// Whether the job completed successfully.
    pub finished: bool,
    /// Error message if the job failed.
    pub error: Option<String>,
    /// Timestamp when the job completed.
    pub finished_at: Option<u64>,
    /// Top matching SHA-256 hashes.
    pub top_matches: Vec<String>,
    /// Number of files scanned.
    pub files_scanned: u64,
    /// Number of files that produced a timeout during scanning.
    pub timeout_files: u64,
}

impl RetroHuntResult {
    /// Return `true` if the job produced at least one match.
    #[must_use]
    pub const fn has_matches(&self) -> bool {
        self.match_count > 0
    }

    /// Return `true` if the job ended with an error.
    #[must_use]
    pub const fn has_error(&self) -> bool {
        self.error.is_some()
    }

    /// Match rate (matches / scanned).
    #[must_use]
    pub fn match_rate(&self) -> f64 {
        if self.files_scanned == 0 {
            0.0
        } else {
            self.match_count as f64 / self.files_scanned as f64
        }
    }
}

impl fmt::Display for RetroHuntResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RetroHunt job={} matches={} scanned={} finished={}",
            self.job_id, self.match_count, self.files_scanned, self.finished,
        )
    }
}

// ── HuntResult ────────────────────────────────────────────────────────────────

/// A hunting result — either a `LiveHunt` match or a completed `RetroHunt` job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HuntResult {
    /// A file matched a `LiveHunt` YARA rule.
    Livehunt(LivehuntMatch),
    /// A `RetroHunt` job completed.
    Retrohunt(RetroHuntResult),
}

impl HuntResult {
    /// Return the SHA-256 associated with the result, if any.
    #[must_use]
    pub fn sha256(&self) -> Option<&str> {
        match self {
            Self::Livehunt(m) => Some(&m.sha256),
            Self::Retrohunt(_) => None,
        }
    }

    /// Return a short human-readable type label.
    #[must_use]
    pub const fn kind_label(&self) -> &'static str {
        match self {
            Self::Livehunt(_) => "livehunt",
            Self::Retrohunt(_) => "retrohunt",
        }
    }

    /// Return the timestamp of the result.
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        match self {
            Self::Livehunt(m) => m.timestamp,
            Self::Retrohunt(r) => r.finished_at.unwrap_or(0),
        }
    }
}

impl fmt::Display for HuntResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Livehunt(m) => write!(f, "{m}"),
            Self::Retrohunt(r) => write!(f, "{r}"),
        }
    }
}

// ── NotificationCallback ──────────────────────────────────────────────────────

/// A callback invoked when a new [`HuntResult`] is received.
pub trait NotificationCallback: Send + Sync + fmt::Debug {
    /// Called with a reference to the new result.
    fn on_result(&self, result: &HuntResult);

    /// Human-readable name for this callback.
    fn name(&self) -> &str;
}

// ── NotifierConfig ────────────────────────────────────────────────────────────

/// Configuration for [`VtHuntingNotifier`].
#[derive(Debug, Clone)]
pub struct NotifierConfig {
    /// Maximum results to keep in the ring buffer.
    pub buffer_capacity: usize,
    /// Whether to deduplicate results by SHA-256 within the buffer.
    pub deduplicate: bool,
    /// Optional filter: only forward results matching these YARA rule names.
    pub rule_filter: Vec<String>,
}

impl Default for NotifierConfig {
    fn default() -> Self {
        Self {
            buffer_capacity: 1024,
            deduplicate: true,
            rule_filter: Vec::new(),
        }
    }
}

// ── NotifierStats ─────────────────────────────────────────────────────────────

/// Runtime statistics for a [`VtHuntingNotifier`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotifierStats {
    /// Total results received.
    pub total_received: u64,
    /// Results forwarded to callbacks (after deduplication/filtering).
    pub total_forwarded: u64,
    /// Results that were deduplicated (dropped as duplicates).
    pub total_deduplicated: u64,
    /// Results that were filtered out.
    pub total_filtered: u64,
    /// Number of livehunt results received.
    pub livehunt_count: u64,
    /// Number of retrohunt results received.
    pub retrohunt_count: u64,
}

// ── VtHuntingNotifier ─────────────────────────────────────────────────────────

/// Receives, deduplicates, filters, and dispatches `VirusTotal` hunting results.
///
/// # Example
///
/// ```
/// use rustre_ti_vt::vt_hunting_notifier::{
///     VtHuntingNotifier, NotifierConfig, HuntResult, LivehuntMatch,
///     NotificationCallback,
/// };
/// use std::sync::{Arc, Mutex};
///
/// #[derive(Debug)]
/// struct PrintCallback;
/// impl NotificationCallback for PrintCallback {
///     fn on_result(&self, r: &HuntResult) { println!("{r}"); }
///     fn name(&self) -> &str { "printer" }
/// }
///
/// let notifier = VtHuntingNotifier::new(NotifierConfig::default());
/// notifier.register_callback(Arc::new(PrintCallback));
/// ```
#[derive(Debug)]
pub struct VtHuntingNotifier {
    config: NotifierConfig,
    /// Ring buffer of recent results.
    buffer: RwLock<VecDeque<HuntResult>>,
    /// SHA-256 → sequence number, for deduplication of Livehunt results.
    seen_hashes: RwLock<HashMap<String, u64>>,
    /// Registered callbacks.
    callbacks: RwLock<Vec<std::sync::Arc<dyn NotificationCallback>>>,
    /// Monotonic sequence counter.
    seq: AtomicU64,
    /// Stats counters.
    total_received: AtomicU64,
    total_forwarded: AtomicU64,
    total_deduplicated: AtomicU64,
    total_filtered: AtomicU64,
    livehunt_count: AtomicU64,
    retrohunt_count: AtomicU64,
}

impl VtHuntingNotifier {
    /// Create a notifier with the given configuration.
    #[must_use]
    pub fn new(config: NotifierConfig) -> Self {
        let cap = config.buffer_capacity;
        Self {
            config,
            buffer: RwLock::new(VecDeque::with_capacity(cap)),
            seen_hashes: RwLock::new(HashMap::new()),
            callbacks: RwLock::new(Vec::new()),
            seq: AtomicU64::new(0),
            total_received: AtomicU64::new(0),
            total_forwarded: AtomicU64::new(0),
            total_deduplicated: AtomicU64::new(0),
            total_filtered: AtomicU64::new(0),
            livehunt_count: AtomicU64::new(0),
            retrohunt_count: AtomicU64::new(0),
        }
    }

    /// Create a notifier with default configuration.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(NotifierConfig::default())
    }

    /// Register a callback to receive forwarded results.
    pub fn register_callback(&self, cb: std::sync::Arc<dyn NotificationCallback>) {
        self.callbacks.write().push(cb);
    }

    /// Deregister callbacks by name.
    pub fn deregister_callback(&self, name: &str) {
        self.callbacks.write().retain(|cb| cb.name() != name);
    }

    /// Submit a [`HuntResult`] for processing.
    ///
    /// The result is deduplicated and filtered according to the notifier's
    /// configuration, then forwarded to all registered callbacks and stored
    /// in the ring buffer.
    pub fn notify(&self, result: HuntResult) {
        self.total_received.fetch_add(1, Ordering::Relaxed);

        match &result {
            HuntResult::Livehunt(_) => { self.livehunt_count.fetch_add(1, Ordering::Relaxed); }
            HuntResult::Retrohunt(_) => { self.retrohunt_count.fetch_add(1, Ordering::Relaxed); }
        }

        // Deduplication (Livehunt only).
        if self.config.deduplicate
            && let Some(sha) = result.sha256() {
                let seq = self.seq.fetch_add(1, Ordering::Relaxed);
                let mut seen = self.seen_hashes.write();
                if seen.contains_key(sha) {
                    self.total_deduplicated.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                seen.insert(sha.to_string(), seq);
            }

        // Rule filter.
        if !self.config.rule_filter.is_empty()
            && let HuntResult::Livehunt(m) = &result {
                let passes = m.matching_rules.iter().any(|r| self.config.rule_filter.contains(r));
                if !passes {
                    self.total_filtered.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }

        // Forward to callbacks.
        {
            let cbs = self.callbacks.read();
            for cb in cbs.iter() {
                cb.on_result(&result);
            }
        }
        self.total_forwarded.fetch_add(1, Ordering::Relaxed);

        // Store in ring buffer.
        {
            let mut buf = self.buffer.write();
            if buf.len() >= self.config.buffer_capacity {
                buf.pop_front();
            }
            buf.push_back(result);
        }
    }

    /// Return a snapshot of recent results (newest first).
    #[must_use]
    pub fn recent_results(&self, limit: usize) -> Vec<HuntResult> {
        let buf = self.buffer.read();
        buf.iter().rev().take(limit).cloned().collect()
    }

    /// Return all results in the buffer matching `sha256`.
    #[must_use]
    pub fn results_for_hash(&self, sha256: &str) -> Vec<HuntResult> {
        let buf = self.buffer.read();
        buf.iter()
            .filter(|r| r.sha256() == Some(sha256))
            .cloned()
            .collect()
    }

    /// Clear the ring buffer and deduplication state.
    pub fn clear(&self) {
        self.buffer.write().clear();
        self.seen_hashes.write().clear();
    }

    /// Number of results currently in the ring buffer.
    #[must_use]
    pub fn buffer_len(&self) -> usize {
        self.buffer.read().len()
    }

    /// Number of registered callbacks.
    #[must_use]
    pub fn callback_count(&self) -> usize {
        self.callbacks.read().len()
    }

    /// Collect current statistics.
    #[must_use]
    pub fn stats(&self) -> NotifierStats {
        NotifierStats {
            total_received: self.total_received.load(Ordering::Relaxed),
            total_forwarded: self.total_forwarded.load(Ordering::Relaxed),
            total_deduplicated: self.total_deduplicated.load(Ordering::Relaxed),
            total_filtered: self.total_filtered.load(Ordering::Relaxed),
            livehunt_count: self.livehunt_count.load(Ordering::Relaxed),
            retrohunt_count: self.retrohunt_count.load(Ordering::Relaxed),
        }
    }

    /// Parse a raw VT Livehunt notification JSON and submit it.
    pub fn notify_from_json(&self, json: &serde_json::Value) {
        let sha256 = json["sha256"].as_str().unwrap_or("").to_string();
        if sha256.is_empty() {
            return;
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
        let matching_rules: Vec<String> = json["matching_rule_names"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(std::string::ToString::to_string)).collect())
            .unwrap_or_default();
        let tags: Vec<String> = json["tags"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(std::string::ToString::to_string)).collect())
            .unwrap_or_default();

        let m = LivehuntMatch {
            id: json["id"].as_str().unwrap_or("").to_string(),
            sha256: sha256.clone(),
            md5: json["md5"].as_str().map(std::string::ToString::to_string),
            file_name: json["meaningful_name"].as_str().map(std::string::ToString::to_string),
            file_size: json["size"].as_u64(),
            file_type: json["type_description"].as_str().map(std::string::ToString::to_string),
            matching_rules,
            tags,
            positives: json["last_analysis_stats"]["malicious"].as_u64().unwrap_or(0) as u32,
            total_engines: json["last_analysis_stats"]["total"].as_u64().unwrap_or(0) as u32,
            timestamp: now,
            ruleset_name: json["ruleset_name"].as_str().unwrap_or("").to_string(),
            permalink: Some(format!("https://www.virustotal.com/gui/file/{sha256}")),
        };
        self.notify(HuntResult::Livehunt(m));
    }
}

// ── Built-in callbacks ────────────────────────────────────────────────────────

/// A callback that collects results into a `Vec` for testing.
#[derive(Debug, Default)]
pub struct CollectingCallback {
    results: parking_lot::Mutex<Vec<HuntResult>>,
    name: String,
}

impl CollectingCallback {
    /// Create a named collecting callback.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { results: parking_lot::Mutex::new(Vec::new()), name: name.into() }
    }

    /// Return all collected results (cloned).
    #[must_use]
    pub fn collected(&self) -> Vec<HuntResult> {
        self.results.lock().clone()
    }

    /// Number of collected results.
    #[must_use]
    pub fn len(&self) -> usize {
        self.results.lock().len()
    }

    /// Return `true` if no results have been collected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.results.lock().is_empty()
    }
}

impl NotificationCallback for CollectingCallback {
    fn on_result(&self, result: &HuntResult) {
        self.results.lock().push(result.clone());
    }

    fn name(&self) -> &str {
        &self.name
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn sample_livehunt(sha: &str, rules: &[&str]) -> HuntResult {
        HuntResult::Livehunt(LivehuntMatch {
            id: sha.to_string(),
            sha256: sha.to_string(),
            md5: None,
            file_name: None,
            file_size: None,
            file_type: None,
            matching_rules: rules.iter().map(std::string::ToString::to_string).collect(),
            tags: vec![],
            positives: 5,
            total_engines: 72,
            timestamp: 0,
            ruleset_name: "test_ruleset".to_string(),
            permalink: None,
        })
    }

    fn sample_retrohunt(job_id: &str, matches: u64) -> HuntResult {
        HuntResult::Retrohunt(RetroHuntResult {
            job_id: job_id.to_string(),
            rule_text: "rule test {}".to_string(),
            match_count: matches,
            finished: true,
            error: None,
            finished_at: Some(0),
            top_matches: vec![],
            files_scanned: 1000,
            timeout_files: 0,
        })
    }

    // ── HuntResult ────────────────────────────────────────────────────────────

    #[test]
    fn test_livehunt_is_malicious() {
        let r = sample_livehunt("abc", &["rule1"]);
        if let HuntResult::Livehunt(m) = &r {
            assert!(m.is_malicious());
        }
    }

    #[test]
    fn test_retrohunt_has_matches() {
        let r = sample_retrohunt("job1", 42);
        if let HuntResult::Retrohunt(rh) = &r {
            assert!(rh.has_matches());
        }
    }

    #[test]
    fn test_retrohunt_match_rate() {
        let r = sample_retrohunt("j1", 10);
        if let HuntResult::Retrohunt(rh) = &r {
            assert!((rh.match_rate() - 0.01).abs() < 1e-6);
        }
    }

    #[test]
    fn test_hunt_result_sha256_livehunt() {
        let r = sample_livehunt("deadbeef", &[]);
        assert_eq!(r.sha256(), Some("deadbeef"));
    }

    #[test]
    fn test_hunt_result_sha256_retrohunt() {
        let r = sample_retrohunt("j1", 0);
        assert_eq!(r.sha256(), None);
    }

    // ── VtHuntingNotifier ─────────────────────────────────────────────────────

    #[test]
    fn test_notify_increments_buffer() {
        let n = VtHuntingNotifier::with_defaults();
        n.notify(sample_livehunt("sha1", &["r1"]));
        assert_eq!(n.buffer_len(), 1);
    }

    #[test]
    fn test_deduplication() {
        let n = VtHuntingNotifier::with_defaults();
        n.notify(sample_livehunt("sha_dup", &["r1"]));
        n.notify(sample_livehunt("sha_dup", &["r1"])); // duplicate
        assert_eq!(n.buffer_len(), 1);
        assert_eq!(n.stats().total_deduplicated, 1);
    }

    #[test]
    fn test_no_dedup_retrohunt() {
        let n = VtHuntingNotifier::with_defaults();
        n.notify(sample_retrohunt("j1", 5));
        n.notify(sample_retrohunt("j2", 3));
        assert_eq!(n.buffer_len(), 2);
    }

    #[test]
    fn test_callback_called() {
        let cb = Arc::new(CollectingCallback::new("col"));
        let n = VtHuntingNotifier::with_defaults();
        n.register_callback(cb.clone());
        n.notify(sample_livehunt("sha_cb", &[]));
        assert_eq!(cb.len(), 1);
    }

    #[test]
    fn test_rule_filter_passes() {
        let config = NotifierConfig {
            rule_filter: vec!["allowed_rule".to_string()],
            ..Default::default()
        };
        let cb = Arc::new(CollectingCallback::new("col"));
        let n = VtHuntingNotifier::new(config);
        n.register_callback(cb.clone());
        n.notify(sample_livehunt("sha1", &["allowed_rule"]));
        assert_eq!(cb.len(), 1);
    }

    #[test]
    fn test_rule_filter_blocks() {
        let config = NotifierConfig {
            rule_filter: vec!["allowed_rule".to_string()],
            ..Default::default()
        };
        let cb = Arc::new(CollectingCallback::new("col"));
        let n = VtHuntingNotifier::new(config);
        n.register_callback(cb.clone());
        n.notify(sample_livehunt("sha1", &["other_rule"]));
        assert_eq!(cb.len(), 0);
        assert_eq!(n.stats().total_filtered, 1);
    }

    #[test]
    fn test_ring_buffer_eviction() {
        let config = NotifierConfig { buffer_capacity: 3, ..Default::default() };
        let n = VtHuntingNotifier::new(config);
        for i in 0u32..5 {
            n.notify(sample_livehunt(&format!("sha{i}"), &[]));
        }
        assert_eq!(n.buffer_len(), 3);
    }

    #[test]
    fn test_recent_results_order() {
        let n = VtHuntingNotifier::with_defaults();
        n.notify(sample_livehunt("sha_a", &[]));
        n.notify(sample_livehunt("sha_b", &[]));
        let recent = n.recent_results(2);
        // Newest first.
        assert_eq!(recent[0].sha256(), Some("sha_b"));
        assert_eq!(recent[1].sha256(), Some("sha_a"));
    }

    #[test]
    fn test_results_for_hash() {
        let n = VtHuntingNotifier::with_defaults();
        n.notify(sample_livehunt("target_hash", &[]));
        n.notify(sample_livehunt("other_hash", &[]));
        let found = n.results_for_hash("target_hash");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_clear() {
        let n = VtHuntingNotifier::with_defaults();
        n.notify(sample_livehunt("sha_c", &[]));
        n.clear();
        assert_eq!(n.buffer_len(), 0);
    }

    #[test]
    fn test_deregister_callback() {
        let cb = Arc::new(CollectingCallback::new("remove_me"));
        let n = VtHuntingNotifier::with_defaults();
        n.register_callback(cb);
        n.deregister_callback("remove_me");
        assert_eq!(n.callback_count(), 0);
    }

    #[test]
    fn test_stats_counts() {
        let n = VtHuntingNotifier::with_defaults();
        n.notify(sample_livehunt("sha_s1", &[]));
        n.notify(sample_retrohunt("jr1", 10));
        let s = n.stats();
        assert_eq!(s.total_received, 2);
        assert_eq!(s.livehunt_count, 1);
        assert_eq!(s.retrohunt_count, 1);
    }

    #[test]
    fn test_notify_from_json() {
        use serde_json::json;
        let n = VtHuntingNotifier::with_defaults();
        let j = json!({
            "sha256": "abcdef1234567890",
            "md5": "aabbcc",
            "matching_rule_names": ["detect_trojan"],
            "last_analysis_stats": {"malicious": 10, "total": 72},
            "ruleset_name": "my_rules"
        });
        n.notify_from_json(&j);
        assert_eq!(n.buffer_len(), 1);
    }

    #[test]
    fn test_notify_from_json_empty_sha() {
        use serde_json::json;
        let n = VtHuntingNotifier::with_defaults();
        n.notify_from_json(&json!({})); // no sha256
        assert_eq!(n.buffer_len(), 0);
    }

    #[test]
    fn test_detection_pct() {
        if let HuntResult::Livehunt(m) = sample_livehunt("x", &[]) {
            assert!((5.0_f64 / 72.0).mul_add(-100.0, m.detection_pct()).abs() < 1e-6);
        }
    }
}
