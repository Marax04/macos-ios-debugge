//! `VirusTotal` reputation subsystem.
//!
//! Provides `VtReputation`, `ReputationScore`, `VendorVote`, `CategoryScore`,
//! `ThreatLevel`, `ReputationDb`, and `ReputationHistory` for tracking,
//! aggregating, and querying community-sourced reputation data from VT.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ── ThreatLevel ───────────────────────────────────────────────────────────────

/// Overall threat classification derived from aggregated votes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ThreatLevel {
    /// No engines flagged the resource.
    Clean,
    /// A small number of engines flagged the resource.
    Suspicious,
    /// Many engines agree the resource is malicious.
    Malicious,
    /// Seen in relation to an active APT campaign.
    HighThreat,
    /// Critical infrastructure threat, immediate action required.
    Critical,
}

impl ThreatLevel {
    /// Return a numeric severity in `[0, 4]`.
    #[must_use]
    pub const fn severity(self) -> u8 {
        self as u8
    }

    /// Derive a threat level from a detection ratio (malicious/total, 0..=1.0).
    #[must_use]
    pub fn from_ratio(ratio: f32) -> Self {
        if ratio >= 0.75 {
            Self::Critical
        } else if ratio >= 0.5 {
            Self::HighThreat
        } else if ratio >= 0.15 {
            Self::Malicious
        } else if ratio > 0.0 {
            Self::Suspicious
        } else {
            Self::Clean
        }
    }

    /// Return a human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Suspicious => "suspicious",
            Self::Malicious => "malicious",
            Self::HighThreat => "high-threat",
            Self::Critical => "critical",
        }
    }

    /// Return `true` if the level warrants automated blocking.
    #[must_use]
    pub const fn should_block(self) -> bool {
        matches!(self, Self::Malicious | Self::HighThreat | Self::Critical)
    }
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// ── VendorVote ────────────────────────────────────────────────────────────────

/// A single vendor (AV engine or research team) vote on a resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorVote {
    /// Vendor name.
    pub vendor: String,
    /// Detection label, if any (e.g. `"Trojan.GenericKD.12345"`).
    pub detection: Option<String>,
    /// Vote weight; public engines default to 1.0; premium research teams may
    /// carry higher weight.
    pub weight: f32,
    /// Whether this vendor classified the resource as malicious.
    pub malicious: bool,
    /// Optional confidence in [0, 100].
    pub confidence: Option<u8>,
    /// Timestamp of the scan.
    pub scanned_at: u64,
    /// Engine version used.
    pub engine_version: Option<String>,
}

impl VendorVote {
    /// Create a malicious vote.
    #[must_use]
    pub fn malicious(vendor: impl Into<String>, detection: impl Into<String>) -> Self {
        Self {
            vendor: vendor.into(),
            detection: Some(detection.into()),
            weight: 1.0,
            malicious: true,
            confidence: Some(80),
            scanned_at: unix_now(),
            engine_version: None,
        }
    }

    /// Create a clean vote.
    #[must_use]
    pub fn clean(vendor: impl Into<String>) -> Self {
        Self {
            vendor: vendor.into(),
            detection: None,
            weight: 1.0,
            malicious: false,
            confidence: Some(95),
            scanned_at: unix_now(),
            engine_version: None,
        }
    }

    /// Create a weighted vote.
    #[must_use]
    pub const fn with_weight(mut self, weight: f32) -> Self {
        self.weight = weight;
        self
    }

    /// Return the effective malicious score contribution (weight if malicious,
    /// else 0).
    #[must_use]
    pub const fn score_contribution(&self) -> f32 {
        if self.malicious { self.weight } else { 0.0 }
    }
}

// ── CategoryScore ─────────────────────────────────────────────────────────────

/// Aggregated score for a malware category (e.g. "ransomware", "trojan").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryScore {
    /// Malware category name.
    pub category: String,
    /// Number of vendors reporting this category.
    pub vendor_count: u32,
    /// Normalised prevalence score [0.0, 1.0] among all votes.
    pub prevalence: f32,
    /// Most common detection family name.
    pub top_family: Option<String>,
}

impl CategoryScore {
    /// Create a new `CategoryScore`.
    #[must_use]
    pub fn new(category: impl Into<String>, vendor_count: u32, total_vendors: u32) -> Self {
        let prevalence = if total_vendors > 0 {
            vendor_count as f32 / total_vendors as f32
        } else {
            0.0
        };
        Self {
            category: category.into(),
            vendor_count,
            prevalence,
            top_family: None,
        }
    }

    /// Attach a top family label.
    #[must_use]
    pub fn with_top_family(mut self, family: impl Into<String>) -> Self {
        self.top_family = Some(family.into());
        self
    }

    /// Return `true` if this category is prevalent (>= 10% of votes).
    #[must_use]
    pub fn is_prevalent(&self) -> bool {
        self.prevalence >= 0.10
    }
}

// ── ReputationScore ───────────────────────────────────────────────────────────

/// Comprehensive reputation score for a single indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    /// Indicator value (hash, IP, domain, URL).
    pub indicator: String,
    /// Derived threat level.
    pub threat_level: ThreatLevel,
    /// Raw community reputation (-100..=100 from VT).
    pub community_score: i32,
    /// Weighted malicious vote total.
    pub weighted_malicious: f32,
    /// Weighted total votes.
    pub weighted_total: f32,
    /// Detection ratio (0.0..=1.0).
    pub detection_ratio: f32,
    /// Number of malicious votes.
    pub malicious_count: u32,
    /// Number of clean votes.
    pub clean_count: u32,
    /// Per-category breakdown.
    pub categories: Vec<CategoryScore>,
    /// Tags from the community.
    pub tags: Vec<String>,
    /// Timestamp this score was computed.
    pub computed_at: u64,
    /// Whether this score is stale (> 24 h old).
    pub is_stale: bool,
}

impl ReputationScore {
    /// Compute a score from a slice of vendor votes.
    #[must_use]
    pub fn from_votes(indicator: impl Into<String>, votes: &[VendorVote]) -> Self {
        let indicator = indicator.into();
        if votes.is_empty() {
            return Self {
                indicator,
                threat_level: ThreatLevel::Clean,
                community_score: 0,
                weighted_malicious: 0.0,
                weighted_total: 0.0,
                detection_ratio: 0.0,
                malicious_count: 0,
                clean_count: 0,
                categories: Vec::new(),
                tags: Vec::new(),
                computed_at: unix_now(),
                is_stale: false,
            };
        }

        let weighted_malicious: f32 = votes.iter().map(VendorVote::score_contribution).sum();
        let weighted_total: f32 = votes.iter().map(|v| v.weight).sum();
        let malicious_count = votes.iter().filter(|v| v.malicious).count() as u32;
        let clean_count = votes.iter().filter(|v| !v.malicious).count() as u32;
        let detection_ratio = if weighted_total > 0.0 {
            weighted_malicious / weighted_total
        } else {
            0.0
        };
        let threat_level = ThreatLevel::from_ratio(detection_ratio);
        let community_score = ((detection_ratio - 0.5) * -200.0) as i32;

        // Build category breakdown from detection labels.
        let mut category_counts: HashMap<String, u32> = HashMap::new();
        for v in votes.iter().filter(|v| v.malicious) {
            if let Some(det) = &v.detection {
                let cat = extract_category(det);
                *category_counts.entry(cat).or_insert(0) += 1;
            }
        }
        let total = votes.len() as u32;
        let categories: Vec<CategoryScore> = category_counts
            .into_iter()
            .map(|(cat, cnt)| CategoryScore::new(cat, cnt, total))
            .collect();

        Self {
            indicator,
            threat_level,
            community_score,
            weighted_malicious,
            weighted_total,
            detection_ratio,
            malicious_count,
            clean_count,
            categories,
            tags: Vec::new(),
            computed_at: unix_now(),
            is_stale: false,
        }
    }

    /// Return `true` if the indicator is considered malicious.
    #[must_use]
    pub const fn is_malicious(&self) -> bool {
        self.threat_level.should_block()
    }

    /// Human-readable detection ratio string e.g. `"32/72"`.
    #[must_use]
    pub fn ratio_string(&self) -> String {
        let total = self.malicious_count + self.clean_count;
        format!("{}/{total}", self.malicious_count)
    }

    /// Mark this score as stale if it is older than `max_age_secs`.
    pub fn update_staleness(&mut self, max_age_secs: u64) {
        let age = unix_now().saturating_sub(self.computed_at);
        // max_age_secs == 0 means "anything older than instant is stale";
        // use >= so a freshly computed score with max_age=0 is also stale.
        self.is_stale = age >= max_age_secs;
    }

    /// Return the dominant category (highest prevalence), if any.
    #[must_use]
    pub fn dominant_category(&self) -> Option<&CategoryScore> {
        self.categories.iter().max_by(|a, b| {
            a.prevalence
                .partial_cmp(&b.prevalence)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }
}

/// Rough category extraction from a detection string.
fn extract_category(detection: &str) -> String {
    let lower = detection.to_ascii_lowercase();
    for keyword in &[
        "ransomware",
        "trojan",
        "worm",
        "backdoor",
        "spyware",
        "adware",
        "rootkit",
        "dropper",
        "downloader",
        "exploit",
        "miner",
        "banker",
        "stealer",
        "rat",
        "loader",
    ] {
        if lower.contains(keyword) {
            return keyword.to_string();
        }
    }
    "other".to_string()
}

// ── VtReputation ──────────────────────────────────────────────────────────────

/// High-level reputation manager that combines vendor votes, community scores,
/// and historical data into a single `ReputationScore`.
#[derive(Debug, Default)]
pub struct VtReputation {
    /// Cache: indicator → `ReputationScore`.
    cache: HashMap<String, ReputationScore>,
    /// Stale threshold in seconds (default 86 400 = 24 h).
    stale_threshold_secs: u64,
}

impl VtReputation {
    /// Create a new reputation manager with a 24-hour stale threshold.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            stale_threshold_secs: 86_400,
        }
    }

    /// Override the stale threshold.
    #[must_use]
    pub const fn with_stale_threshold(mut self, secs: u64) -> Self {
        self.stale_threshold_secs = secs;
        self
    }

    /// Ingest vendor votes for an indicator and (re-)compute its score.
    pub fn ingest(&mut self, indicator: impl Into<String>, votes: Vec<VendorVote>) {
        let indicator = indicator.into();
        let mut score = ReputationScore::from_votes(&indicator, &votes);
        score.update_staleness(self.stale_threshold_secs);
        self.cache.insert(indicator, score);
    }

    /// Look up the current score for an indicator.
    #[must_use]
    pub fn get(&self, indicator: &str) -> Option<&ReputationScore> {
        self.cache.get(indicator)
    }

    /// Return all indicators at or above `min_level`.
    #[must_use]
    pub fn by_threat_level(&self, min_level: ThreatLevel) -> Vec<&ReputationScore> {
        self.cache
            .values()
            .filter(|s| s.threat_level >= min_level)
            .collect()
    }

    /// Return all stale scores.
    #[must_use]
    pub fn stale_scores(&self) -> Vec<&ReputationScore> {
        self.cache.values().filter(|s| s.is_stale).collect()
    }

    /// Evict a single indicator.
    pub fn evict(&mut self, indicator: &str) -> bool {
        self.cache.remove(indicator).is_some()
    }

    /// Clear all cached scores.
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Return the number of cached scores.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Return `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Bulk-update staleness for all cached entries.
    pub fn refresh_staleness(&mut self) {
        let threshold = self.stale_threshold_secs;
        for s in self.cache.values_mut() {
            s.update_staleness(threshold);
        }
    }

    /// Add a tag to an existing score.
    pub fn add_tag(&mut self, indicator: &str, tag: impl Into<String>) -> bool {
        if let Some(score) = self.cache.get_mut(indicator) {
            score.tags.push(tag.into());
            true
        } else {
            false
        }
    }
}

// ── ReputationHistory ─────────────────────────────────────────────────────────

/// A time-ordered snapshot of reputation scores for a single indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Unix timestamp.
    pub timestamp: u64,
    /// Detection ratio at this point in time.
    pub detection_ratio: f32,
    /// Threat level at this point in time.
    pub threat_level: ThreatLevel,
    /// Malicious vendor count.
    pub malicious_count: u32,
    /// Optional analyst note.
    pub note: Option<String>,
}

impl HistoryEntry {
    /// Create a snapshot from a `ReputationScore`.
    #[must_use]
    pub const fn from_score(score: &ReputationScore) -> Self {
        Self {
            timestamp: score.computed_at,
            detection_ratio: score.detection_ratio,
            threat_level: score.threat_level,
            malicious_count: score.malicious_count,
            note: None,
        }
    }

    /// Attach a note.
    #[must_use]
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }
}

/// Historical reputation timeline for a single indicator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationHistory {
    /// The indicator being tracked.
    pub indicator: String,
    /// Ordered snapshots (oldest first).
    pub entries: Vec<HistoryEntry>,
    /// Maximum number of entries to retain.
    pub max_entries: usize,
}

impl ReputationHistory {
    /// Create a new history with the given capacity.
    #[must_use]
    pub fn new(indicator: impl Into<String>, max_entries: usize) -> Self {
        Self {
            indicator: indicator.into(),
            entries: Vec::new(),
            max_entries: max_entries.max(1),
        }
    }

    /// Push a new snapshot, pruning old entries if necessary.
    pub fn push(&mut self, entry: HistoryEntry) {
        self.entries.push(entry);
        if self.entries.len() > self.max_entries {
            self.entries.remove(0);
        }
    }

    /// Push a snapshot derived from a `ReputationScore`.
    pub fn record(&mut self, score: &ReputationScore) {
        self.push(HistoryEntry::from_score(score));
    }

    /// Return the most recent entry.
    #[must_use]
    pub fn latest(&self) -> Option<&HistoryEntry> {
        self.entries.last()
    }

    /// Return the earliest entry.
    #[must_use]
    pub fn earliest(&self) -> Option<&HistoryEntry> {
        self.entries.first()
    }

    /// Compute the trend in detection ratio (latest - earliest).  Positive
    /// means worsening reputation; negative means improving.
    #[must_use]
    pub fn ratio_trend(&self) -> Option<f32> {
        let first = self.earliest()?;
        let last = self.latest()?;
        if std::ptr::eq(first, last) {
            return None;
        }
        Some(last.detection_ratio - first.detection_ratio)
    }

    /// Return `true` if the indicator's reputation is getting worse over time.
    #[must_use]
    pub fn is_worsening(&self) -> bool {
        self.ratio_trend().is_some_and(|t| t > 0.05)
    }

    /// Return `true` if the indicator's reputation is improving over time.
    #[must_use]
    pub fn is_improving(&self) -> bool {
        self.ratio_trend().is_some_and(|t| t < -0.05)
    }

    /// Number of stored snapshots.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if no snapshots are stored.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all entries in a given time window.
    #[must_use]
    pub fn window(&self, from: u64, to: u64) -> Vec<&HistoryEntry> {
        self.entries
            .iter()
            .filter(|e| e.timestamp >= from && e.timestamp <= to)
            .collect()
    }
}

// ── ReputationDb ──────────────────────────────────────────────────────────────

/// Thread-safe, in-memory reputation database that stores both current scores
/// and historical timelines.
#[derive(Debug, Clone)]
pub struct ReputationDb {
    inner: Arc<Mutex<ReputationDbInner>>,
}

#[derive(Debug, Default)]
struct ReputationDbInner {
    scores: HashMap<String, ReputationScore>,
    history: HashMap<String, ReputationHistory>,
    history_max: usize,
}

impl Default for ReputationDb {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationDb {
    /// Create a new database, retaining up to `history_max` entries per
    /// indicator.
    #[must_use]
    pub fn with_history_max(history_max: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ReputationDbInner {
                scores: HashMap::new(),
                history: HashMap::new(),
                history_max,
            })),
        }
    }

    /// Create a new database with the default history capacity (50).
    #[must_use]
    pub fn new() -> Self {
        Self::with_history_max(50)
    }

    /// Insert or update a score, automatically recording a history entry.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn upsert(&self, score: ReputationScore) {
        let indicator = score.indicator.clone();
        let mut guard = self.inner.lock().unwrap();
        let max = guard.history_max;
        let history = guard
            .history
            .entry(indicator.clone())
            .or_insert_with(|| ReputationHistory::new(&indicator, max));
        history.record(&score);
        guard.scores.insert(indicator, score);
    }

    /// Look up the current score for an indicator.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    #[must_use]
    pub fn get_score(&self, indicator: &str) -> Option<ReputationScore> {
        self.inner.lock().unwrap().scores.get(indicator).cloned()
    }

    /// Look up the full history for an indicator.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    #[must_use]
    pub fn get_history(&self, indicator: &str) -> Option<ReputationHistory> {
        self.inner.lock().unwrap().history.get(indicator).cloned()
    }

    /// Remove an indicator from the database.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    #[must_use] 
    pub fn remove(&self, indicator: &str) -> bool {
        let mut guard = self.inner.lock().unwrap();
        guard.history.remove(indicator);
        guard.scores.remove(indicator).is_some()
    }

    /// Return all indicators in the database.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    #[must_use]
    pub fn indicators(&self) -> Vec<String> {
        let mut keys: Vec<_> = self.inner.lock().unwrap().scores.keys().cloned().collect();
        keys.sort();
        keys
    }

    /// Return the number of indicators.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().scores.len()
    }

    /// Return `true` if the database is empty.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().scores.is_empty()
    }

    /// Return all scores at or above `min_level`.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    #[must_use]
    pub fn malicious_indicators(&self, min_level: ThreatLevel) -> Vec<ReputationScore> {
        self.inner
            .lock()
            .unwrap()
            .scores
            .values()
            .filter(|s| s.threat_level >= min_level)
            .cloned()
            .collect()
    }

    /// Clear all data from the database.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn clear(&self) {
        let mut guard = self.inner.lock().unwrap();
        guard.scores.clear();
        guard.history.clear();
    }

    /// Compute aggregate statistics across all stored scores.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    #[must_use]
    pub fn stats(&self) -> DbStats {
        let guard = self.inner.lock().unwrap();
        let total = guard.scores.len();
        let mut by_level = HashMap::new();
        for score in guard.scores.values() {
            *by_level.entry(score.threat_level).or_insert(0u32) += 1;
        }
        drop(guard);
        DbStats { total, by_level }
    }
}

/// Aggregate statistics returned by [`ReputationDb::stats`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbStats {
    /// Total number of tracked indicators.
    pub total: usize,
    /// Count per threat level.
    pub by_level: HashMap<ThreatLevel, u32>,
}

impl DbStats {
    /// Number of clean indicators.
    #[must_use]
    pub fn clean_count(&self) -> u32 {
        self.by_level.get(&ThreatLevel::Clean).copied().unwrap_or(0)
    }

    /// Number of indicators that should be blocked.
    #[must_use]
    pub fn blocked_count(&self) -> u32 {
        [
            ThreatLevel::Malicious,
            ThreatLevel::HighThreat,
            ThreatLevel::Critical,
        ]
        .iter()
        .filter_map(|l| self.by_level.get(l))
        .sum()
    }
}

// ── ReputationAggregator ──────────────────────────────────────────────────────

/// Aggregates reputation scores from multiple sources (VT engines, community,
/// sandbox verdicts) into a single consolidated score.
#[derive(Debug, Default)]
pub struct ReputationAggregator {
    /// Weight applied to AV engine votes.
    pub engine_weight: f32,
    /// Weight applied to community votes.
    pub community_weight: f32,
    /// Weight applied to sandbox verdicts.
    pub sandbox_weight: f32,
    /// Minimum number of votes before a score is considered reliable.
    pub min_votes: u32,
}

impl ReputationAggregator {
    /// Create a balanced aggregator (equal weights).
    #[must_use]
    pub const fn balanced() -> Self {
        Self {
            engine_weight: 0.5,
            community_weight: 0.3,
            sandbox_weight: 0.2,
            min_votes: 5,
        }
    }

    /// Create an engine-heavy aggregator.
    #[must_use]
    pub const fn engine_heavy() -> Self {
        Self {
            engine_weight: 0.7,
            community_weight: 0.2,
            sandbox_weight: 0.1,
            min_votes: 3,
        }
    }

    /// Aggregate engine votes, a community score, and an optional sandbox verdict.
    ///
    /// Returns the weighted composite score in [0.0, 1.0].
    #[must_use]
    pub fn aggregate(
        &self,
        engine_ratio: f32,
        community_score: i32,
        sandbox_malicious: Option<bool>,
    ) -> f32 {
        let engine_contrib = engine_ratio * self.engine_weight;

        // Normalise community score from [-100, 100] → [0.0, 1.0].
        let community_norm = (community_score.clamp(-100, 100) as f32 + 100.0) / 200.0;
        // Invert: lower community score → higher maliciousness.
        let community_contrib = (1.0 - community_norm) * self.community_weight;

        let sandbox_contrib = match sandbox_malicious {
            Some(true) => self.sandbox_weight,
            Some(false) => 0.0,
            None => self.sandbox_weight * 0.5,
        };

        (engine_contrib + community_contrib + sandbox_contrib).clamp(0.0, 1.0)
    }

    /// Return `true` if a score computed from `vote_count` votes is reliable.
    #[must_use]
    pub const fn is_reliable(&self, vote_count: u32) -> bool {
        vote_count >= self.min_votes
    }
}

// ── ReputationFilter ──────────────────────────────────────────────────────────

/// A filter for selecting reputation scores from a database.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReputationFilter {
    /// Minimum threat level.
    pub min_level: Option<ThreatLevel>,
    /// Maximum staleness in seconds (0 = any).
    pub max_age_secs: u64,
    /// Only include indicators with at least this many malicious votes.
    pub min_malicious_count: u32,
    /// Only include indicators with at least this detection ratio.
    pub min_detection_ratio: f32,
    /// Only include indicators tagged with all of these tags.
    pub required_tags: Vec<String>,
    /// Only include indicators not tagged with any of these tags.
    pub excluded_tags: Vec<String>,
}

impl ReputationFilter {
    /// Create a filter that matches everything.
    #[must_use]
    pub fn all() -> Self {
        Self::default()
    }

    /// Create a filter for malicious indicators.
    #[must_use]
    pub fn malicious_only() -> Self {
        Self {
            min_level: Some(ThreatLevel::Malicious),
            ..Default::default()
        }
    }

    /// Set minimum detection ratio.
    #[must_use]
    pub const fn with_min_ratio(mut self, ratio: f32) -> Self {
        self.min_detection_ratio = ratio;
        self
    }

    /// Apply this filter to a score.
    #[must_use]
    pub fn matches(&self, score: &ReputationScore) -> bool {
        if let Some(min) = self.min_level
            && score.threat_level < min {
                return false;
            }
        if score.malicious_count < self.min_malicious_count {
            return false;
        }
        if score.detection_ratio < self.min_detection_ratio {
            return false;
        }
        if self.max_age_secs > 0 {
            let age = unix_now().saturating_sub(score.computed_at);
            if age > self.max_age_secs {
                return false;
            }
        }
        for tag in &self.required_tags {
            if !score.tags.contains(tag) {
                return false;
            }
        }
        for tag in &self.excluded_tags {
            if score.tags.contains(tag) {
                return false;
            }
        }
        true
    }
}

// ── ReputationReport ──────────────────────────────────────────────────────────

/// A structured reputation analysis report for a set of indicators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationReport {
    /// Report title.
    pub title: String,
    /// Indicators analysed.
    pub indicators: Vec<String>,
    /// Scores for each indicator.
    pub scores: Vec<ReputationScore>,
    /// Summary statistics.
    pub summary: ReportSummary,
    /// Generated timestamp.
    pub generated_at: u64,
}

/// Summary statistics for a reputation report.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total: usize,
    pub malicious: usize,
    pub suspicious: usize,
    pub clean: usize,
    pub high_threat: usize,
    pub critical: usize,
    pub avg_detection_ratio: f32,
    pub max_detection_ratio: f32,
}

impl ReputationReport {
    /// Generate a report from a database using a filter.
    #[must_use]
    pub fn from_db(db: &ReputationDb, filter: &ReputationFilter, title: impl Into<String>) -> Self {
        

        let scores: Vec<ReputationScore> = db
            .indicators()
            .into_iter()
            .filter_map(|id| db.get_score(&id))
            .filter(|s| filter.matches(s))
            .collect();

        let total = scores.len();
        let malicious = scores
            .iter()
            .filter(|s| s.threat_level == ThreatLevel::Malicious)
            .count();
        let suspicious = scores
            .iter()
            .filter(|s| s.threat_level == ThreatLevel::Suspicious)
            .count();
        let clean = scores
            .iter()
            .filter(|s| s.threat_level == ThreatLevel::Clean)
            .count();
        let high_threat = scores
            .iter()
            .filter(|s| s.threat_level == ThreatLevel::HighThreat)
            .count();
        let critical = scores
            .iter()
            .filter(|s| s.threat_level == ThreatLevel::Critical)
            .count();

        let avg_ratio = if total > 0 {
            scores.iter().map(|s| s.detection_ratio).sum::<f32>() / total as f32
        } else {
            0.0
        };
        let max_ratio = scores
            .iter()
            .map(|s| s.detection_ratio)
            .fold(0.0_f32, f32::max);

        let indicators: Vec<String> = scores.iter().map(|s| s.indicator.clone()).collect();

        Self {
            title: title.into(),
            indicators,
            scores,
            summary: ReportSummary {
                total,
                malicious,
                suspicious,
                clean,
                high_threat,
                critical,
                avg_detection_ratio: avg_ratio,
                max_detection_ratio: max_ratio,
            },
            generated_at: unix_now(),
        }
    }

    /// Return indicators that should be blocked.
    #[must_use]
    pub fn blockable_indicators(&self) -> Vec<&str> {
        self.scores
            .iter()
            .filter(|s| s.threat_level.should_block())
            .map(|s| s.indicator.as_str())
            .collect()
    }

    /// Serialise to a JSON string.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_votes(malicious: usize, clean: usize) -> Vec<VendorVote> {
        let mut v = Vec::new();
        for i in 0..malicious {
            v.push(VendorVote::malicious(format!("AV{i}"), "Trojan.GenericKD"));
        }
        for i in 0..clean {
            v.push(VendorVote::clean(format!("AV_clean{i}")));
        }
        v
    }

    // ── ThreatLevel ──────────────────────────────────────────────────────────

    #[test]
    fn test_threat_level_from_ratio_clean() {
        assert_eq!(ThreatLevel::from_ratio(0.0), ThreatLevel::Clean);
    }

    #[test]
    fn test_threat_level_from_ratio_suspicious() {
        assert_eq!(ThreatLevel::from_ratio(0.05), ThreatLevel::Suspicious);
    }

    #[test]
    fn test_threat_level_from_ratio_malicious() {
        assert_eq!(ThreatLevel::from_ratio(0.3), ThreatLevel::Malicious);
    }

    #[test]
    fn test_threat_level_from_ratio_high() {
        assert_eq!(ThreatLevel::from_ratio(0.6), ThreatLevel::HighThreat);
    }

    #[test]
    fn test_threat_level_from_ratio_critical() {
        assert_eq!(ThreatLevel::from_ratio(0.9), ThreatLevel::Critical);
    }

    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::Critical > ThreatLevel::Clean);
        assert!(ThreatLevel::Malicious > ThreatLevel::Suspicious);
    }

    #[test]
    fn test_threat_level_should_block() {
        assert!(ThreatLevel::Malicious.should_block());
        assert!(!ThreatLevel::Clean.should_block());
        assert!(!ThreatLevel::Suspicious.should_block());
    }

    #[test]
    fn test_threat_level_label() {
        assert_eq!(ThreatLevel::Clean.label(), "clean");
        assert_eq!(ThreatLevel::Critical.label(), "critical");
    }

    #[test]
    fn test_threat_level_severity() {
        assert_eq!(ThreatLevel::Clean.severity(), 0);
        assert!(ThreatLevel::Critical.severity() > ThreatLevel::Malicious.severity());
    }

    // ── VendorVote ───────────────────────────────────────────────────────────

    #[test]
    fn test_vendor_vote_malicious() {
        let v = VendorVote::malicious("TestAV", "Trojan.Test");
        assert!(v.malicious);
        assert_eq!(v.detection.as_deref(), Some("Trojan.Test"));
    }

    #[test]
    fn test_vendor_vote_clean() {
        let v = VendorVote::clean("TestAV");
        assert!(!v.malicious);
        assert!(v.detection.is_none());
    }

    #[test]
    fn test_vendor_vote_weight() {
        let v = VendorVote::malicious("TestAV", "Ransomware").with_weight(2.0);
        assert_eq!(v.weight, 2.0);
        assert_eq!(v.score_contribution(), 2.0);
    }

    #[test]
    fn test_vendor_vote_clean_contribution_zero() {
        let v = VendorVote::clean("AV");
        assert_eq!(v.score_contribution(), 0.0);
    }

    // ── CategoryScore ────────────────────────────────────────────────────────

    #[test]
    fn test_category_score_prevalence() {
        let c = CategoryScore::new("trojan", 10, 100);
        assert!((c.prevalence - 0.1).abs() < f32::EPSILON);
    }

    #[test]
    fn test_category_score_prevalent() {
        let c = CategoryScore::new("ransomware", 20, 100);
        assert!(c.is_prevalent());
    }

    #[test]
    fn test_category_score_not_prevalent() {
        let c = CategoryScore::new("adware", 5, 100);
        assert!(!c.is_prevalent());
    }

    #[test]
    fn test_category_score_with_family() {
        let c = CategoryScore::new("trojan", 1, 1).with_top_family("Emotet");
        assert_eq!(c.top_family.as_deref(), Some("Emotet"));
    }

    // ── ReputationScore ──────────────────────────────────────────────────────

    #[test]
    fn test_reputation_score_empty_votes() {
        let s = ReputationScore::from_votes("safe_hash", &[]);
        assert_eq!(s.threat_level, ThreatLevel::Clean);
        assert_eq!(s.malicious_count, 0);
    }

    #[test]
    fn test_reputation_score_all_malicious() {
        let votes = make_votes(70, 0);
        let s = ReputationScore::from_votes("evil_hash", &votes);
        assert!(s.is_malicious());
        assert_eq!(s.malicious_count, 70);
    }

    #[test]
    fn test_reputation_score_all_clean() {
        let votes = make_votes(0, 72);
        let s = ReputationScore::from_votes("clean_hash", &votes);
        assert!(!s.is_malicious());
        assert_eq!(s.threat_level, ThreatLevel::Clean);
    }

    #[test]
    fn test_reputation_score_mixed() {
        let votes = make_votes(5, 67);
        let s = ReputationScore::from_votes("partial_hash", &votes);
        assert_eq!(s.malicious_count, 5);
        assert!(s.detection_ratio > 0.0);
    }

    #[test]
    fn test_reputation_score_ratio_string() {
        let votes = make_votes(10, 62);
        let s = ReputationScore::from_votes("hash", &votes);
        assert_eq!(s.ratio_string(), "10/72");
    }

    #[test]
    fn test_reputation_score_dominant_category() {
        let mut votes = make_votes(30, 42);
        votes[0] = VendorVote::malicious("AV0", "Ransomware.WannaCry");
        let s = ReputationScore::from_votes("hash", &votes);
        // At least one category should be present.
        assert!(!s.categories.is_empty());
    }

    #[test]
    fn test_reputation_score_staleness() {
        let votes = make_votes(5, 5);
        let mut s = ReputationScore::from_votes("stale_hash", &votes);
        // Force stale by using a max_age of 0.
        s.update_staleness(0);
        assert!(s.is_stale);
    }

    #[test]
    fn test_reputation_score_not_stale_fresh() {
        let votes = make_votes(1, 1);
        let mut s = ReputationScore::from_votes("fresh_hash", &votes);
        s.update_staleness(86_400);
        assert!(!s.is_stale);
    }

    // ── VtReputation ────────────────────────────────────────────────────────

    #[test]
    fn test_vt_reputation_ingest_and_get() {
        let mut rep = VtReputation::new();
        rep.ingest("evil_hash", make_votes(50, 22));
        let score = rep.get("evil_hash").unwrap();
        assert!(score.is_malicious());
    }

    #[test]
    fn test_vt_reputation_get_missing() {
        let rep = VtReputation::new();
        assert!(rep.get("missing").is_none());
    }

    #[test]
    fn test_vt_reputation_by_threat_level() {
        let mut rep = VtReputation::new();
        rep.ingest("bad", make_votes(50, 22));
        rep.ingest("good", make_votes(0, 72));
        let hits = rep.by_threat_level(ThreatLevel::Malicious);
        assert!(hits.iter().any(|s| s.indicator == "bad"));
        assert!(!hits.iter().any(|s| s.indicator == "good"));
    }

    #[test]
    fn test_vt_reputation_evict() {
        let mut rep = VtReputation::new();
        rep.ingest("hash", make_votes(5, 5));
        assert!(rep.evict("hash"));
        assert!(rep.get("hash").is_none());
    }

    #[test]
    fn test_vt_reputation_clear() {
        let mut rep = VtReputation::new();
        rep.ingest("a", make_votes(1, 1));
        rep.ingest("b", make_votes(1, 1));
        rep.clear();
        assert!(rep.is_empty());
    }

    #[test]
    fn test_vt_reputation_add_tag() {
        let mut rep = VtReputation::new();
        rep.ingest("hash", make_votes(1, 1));
        assert!(rep.add_tag("hash", "apt28"));
        let score = rep.get("hash").unwrap();
        assert!(score.tags.contains(&"apt28".to_string()));
    }

    #[test]
    fn test_vt_reputation_len() {
        let mut rep = VtReputation::new();
        assert_eq!(rep.len(), 0);
        rep.ingest("a", make_votes(1, 1));
        assert_eq!(rep.len(), 1);
    }

    // ── ReputationHistory ────────────────────────────────────────────────────

    #[test]
    fn test_reputation_history_push_and_len() {
        let mut h = ReputationHistory::new("hash", 10);
        let e = HistoryEntry {
            timestamp: unix_now(),
            detection_ratio: 0.5,
            threat_level: ThreatLevel::Malicious,
            malicious_count: 36,
            note: None,
        };
        h.push(e);
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn test_reputation_history_pruning() {
        let mut h = ReputationHistory::new("hash", 3);
        for i in 0..5u64 {
            h.push(HistoryEntry {
                timestamp: i,
                detection_ratio: 0.1 * i as f32,
                threat_level: ThreatLevel::Suspicious,
                malicious_count: i as u32,
                note: None,
            });
        }
        assert_eq!(h.len(), 3);
        assert_eq!(h.earliest().unwrap().timestamp, 2);
    }

    #[test]
    fn test_reputation_history_trend_worsening() {
        let mut h = ReputationHistory::new("hash", 10);
        h.push(HistoryEntry {
            timestamp: 1,
            detection_ratio: 0.1,
            threat_level: ThreatLevel::Suspicious,
            malicious_count: 7,
            note: None,
        });
        h.push(HistoryEntry {
            timestamp: 2,
            detection_ratio: 0.5,
            threat_level: ThreatLevel::Malicious,
            malicious_count: 36,
            note: None,
        });
        assert!(h.is_worsening());
        assert!(!h.is_improving());
    }

    #[test]
    fn test_reputation_history_trend_improving() {
        let mut h = ReputationHistory::new("hash", 10);
        h.push(HistoryEntry {
            timestamp: 1,
            detection_ratio: 0.8,
            threat_level: ThreatLevel::HighThreat,
            malicious_count: 58,
            note: None,
        });
        h.push(HistoryEntry {
            timestamp: 2,
            detection_ratio: 0.2,
            threat_level: ThreatLevel::Suspicious,
            malicious_count: 14,
            note: None,
        });
        assert!(h.is_improving());
    }

    #[test]
    fn test_reputation_history_window() {
        let mut h = ReputationHistory::new("hash", 20);
        for i in 0..10u64 {
            h.push(HistoryEntry {
                timestamp: i * 1000,
                detection_ratio: 0.0,
                threat_level: ThreatLevel::Clean,
                malicious_count: 0,
                note: None,
            });
        }
        let window = h.window(2000, 5000);
        assert_eq!(window.len(), 4);
    }

    #[test]
    fn test_history_entry_with_note() {
        let score = ReputationScore::from_votes("hash", &make_votes(5, 5));
        let entry = HistoryEntry::from_score(&score).with_note("initial scan");
        assert_eq!(entry.note.as_deref(), Some("initial scan"));
    }

    // ── ReputationDb ────────────────────────────────────────────────────────

    #[test]
    fn test_reputation_db_upsert_and_get() {
        let db = ReputationDb::new();
        let score = ReputationScore::from_votes("hash", &make_votes(10, 62));
        db.upsert(score);
        let fetched = db.get_score("hash").unwrap();
        assert_eq!(fetched.malicious_count, 10);
    }

    #[test]
    fn test_reputation_db_history_recorded() {
        let db = ReputationDb::new();
        let score = ReputationScore::from_votes("hash", &make_votes(5, 5));
        db.upsert(score);
        let h = db.get_history("hash").unwrap();
        assert_eq!(h.len(), 1);
    }

    #[test]
    fn test_reputation_db_remove() {
        let db = ReputationDb::new();
        db.upsert(ReputationScore::from_votes("h", &make_votes(1, 1)));
        assert!(db.remove("h"));
        assert!(db.get_score("h").is_none());
    }

    #[test]
    fn test_reputation_db_indicators() {
        let db = ReputationDb::new();
        db.upsert(ReputationScore::from_votes("a", &make_votes(1, 1)));
        db.upsert(ReputationScore::from_votes("b", &make_votes(1, 1)));
        let ids = db.indicators();
        assert!(ids.contains(&"a".to_string()));
        assert!(ids.contains(&"b".to_string()));
    }

    #[test]
    fn test_reputation_db_stats() {
        let db = ReputationDb::new();
        db.upsert(ReputationScore::from_votes("evil", &make_votes(50, 22)));
        db.upsert(ReputationScore::from_votes("safe", &make_votes(0, 72)));
        let stats = db.stats();
        assert_eq!(stats.total, 2);
        assert!(stats.blocked_count() >= 1);
        assert!(stats.clean_count() >= 1);
    }

    #[test]
    fn test_reputation_db_malicious_indicators() {
        let db = ReputationDb::new();
        db.upsert(ReputationScore::from_votes("evil", &make_votes(60, 12)));
        db.upsert(ReputationScore::from_votes("clean", &make_votes(0, 72)));
        let malicious = db.malicious_indicators(ThreatLevel::Malicious);
        assert!(malicious.iter().any(|s| s.indicator == "evil"));
        assert!(!malicious.iter().any(|s| s.indicator == "clean"));
    }

    #[test]
    fn test_reputation_db_clear() {
        let db = ReputationDb::new();
        db.upsert(ReputationScore::from_votes("x", &make_votes(1, 1)));
        db.clear();
        assert!(db.is_empty());
    }

    #[test]
    fn test_reputation_db_len() {
        let db = ReputationDb::new();
        assert_eq!(db.len(), 0);
        db.upsert(ReputationScore::from_votes("a", &[]));
        assert_eq!(db.len(), 1);
    }

    // ── ReputationAggregator ─────────────────────────────────────────────────

    #[test]
    fn test_aggregator_balanced_high_engine() {
        let agg = ReputationAggregator::balanced();
        let score = agg.aggregate(0.9, -80, Some(true));
        assert!(score > 0.7);
    }

    #[test]
    fn test_aggregator_all_clean() {
        let agg = ReputationAggregator::balanced();
        let score = agg.aggregate(0.0, 100, Some(false));
        assert!(score < 0.3);
    }

    #[test]
    fn test_aggregator_engine_heavy() {
        let agg = ReputationAggregator::engine_heavy();
        assert!((agg.engine_weight - 0.7).abs() < f32::EPSILON);
    }

    #[test]
    fn test_aggregator_no_sandbox() {
        let agg = ReputationAggregator::balanced();
        let score = agg.aggregate(0.5, 0, None);
        assert!(score > 0.0 && score < 1.0);
    }

    #[test]
    fn test_aggregator_is_reliable() {
        let agg = ReputationAggregator::balanced();
        assert!(!agg.is_reliable(4));
        assert!(agg.is_reliable(5));
    }

    #[test]
    fn test_aggregator_score_clamped() {
        let agg = ReputationAggregator {
            engine_weight: 2.0,
            community_weight: 2.0,
            sandbox_weight: 2.0,
            min_votes: 1,
        };
        let score = agg.aggregate(1.0, -100, Some(true));
        assert!(score <= 1.0);
    }

    // ── ReputationFilter ─────────────────────────────────────────────────────

    #[test]
    fn test_filter_malicious_only() {
        let filter = ReputationFilter::malicious_only();
        let score_clean = ReputationScore::from_votes("clean", &make_votes(0, 72));
        let score_bad = ReputationScore::from_votes("evil", &make_votes(50, 22));
        assert!(!filter.matches(&score_clean));
        assert!(filter.matches(&score_bad));
    }

    #[test]
    fn test_filter_all_passes_everything() {
        let filter = ReputationFilter::all();
        let score = ReputationScore::from_votes("x", &[]);
        assert!(filter.matches(&score));
    }

    #[test]
    fn test_filter_min_malicious_count() {
        let filter = ReputationFilter {
            min_malicious_count: 10,
            ..Default::default()
        };
        let score_low = ReputationScore::from_votes("x", &make_votes(5, 67));
        let score_high = ReputationScore::from_votes("y", &make_votes(15, 57));
        assert!(!filter.matches(&score_low));
        assert!(filter.matches(&score_high));
    }

    #[test]
    fn test_filter_min_ratio() {
        let filter = ReputationFilter::all().with_min_ratio(0.5);
        let score_low = ReputationScore::from_votes("x", &make_votes(10, 62));
        let score_high = ReputationScore::from_votes("y", &make_votes(50, 22));
        assert!(!filter.matches(&score_low));
        assert!(filter.matches(&score_high));
    }

    #[test]
    fn test_filter_required_tag() {
        let mut filter = ReputationFilter::default();
        filter.required_tags.push("apt28".into());
        let mut score = ReputationScore::from_votes("x", &make_votes(5, 5));
        assert!(!filter.matches(&score));
        score.tags.push("apt28".into());
        assert!(filter.matches(&score));
    }

    #[test]
    fn test_filter_excluded_tag() {
        let mut filter = ReputationFilter::default();
        filter.excluded_tags.push("false-positive".into());
        let mut score = ReputationScore::from_votes("x", &make_votes(5, 5));
        assert!(filter.matches(&score));
        score.tags.push("false-positive".into());
        assert!(!filter.matches(&score));
    }

    // ── ReputationReport ─────────────────────────────────────────────────────

    #[test]
    fn test_reputation_report_from_db() {
        let db = ReputationDb::new();
        db.upsert(ReputationScore::from_votes("evil", &make_votes(50, 22)));
        db.upsert(ReputationScore::from_votes("clean", &make_votes(0, 72)));
        let report = ReputationReport::from_db(&db, &ReputationFilter::all(), "Test Report");
        assert_eq!(report.summary.total, 2);
    }

    #[test]
    fn test_reputation_report_blockable() {
        let db = ReputationDb::new();
        db.upsert(ReputationScore::from_votes("evil", &make_votes(60, 12)));
        let report = ReputationReport::from_db(&db, &ReputationFilter::all(), "Report");
        assert!(report.blockable_indicators().contains(&"evil"));
    }

    #[test]
    fn test_reputation_report_to_json() {
        let db = ReputationDb::new();
        db.upsert(ReputationScore::from_votes("x", &make_votes(1, 1)));
        let report = ReputationReport::from_db(&db, &ReputationFilter::all(), "JSON Report");
        let json = report.to_json();
        assert!(json.contains("JSON Report"));
    }

    #[test]
    fn test_reputation_report_summary_stats() {
        let db = ReputationDb::new();
        db.upsert(ReputationScore::from_votes("c", &make_votes(0, 72)));
        db.upsert(ReputationScore::from_votes("s", &make_votes(5, 67)));
        db.upsert(ReputationScore::from_votes("m", &make_votes(30, 42)));
        let report = ReputationReport::from_db(&db, &ReputationFilter::all(), "Stats");
        assert_eq!(report.summary.total, 3);
        assert!(report.summary.avg_detection_ratio > 0.0);
    }
}
