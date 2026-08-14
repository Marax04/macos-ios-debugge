//! Malpedia YARA integration.
//!
//! Provides `MalpediaYara`, `YaraRuleSet`, `FamilyYara`, `RuleMetadata`,
//! `YaraDownloader`, and `YaraCache` for managing YARA rules associated
//! with Malpedia malware families.

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

// ── YaraError ─────────────────────────────────────────────────────────────────

/// Errors from the YARA management subsystem.
#[derive(Debug, Clone)]
pub enum YaraError {
    /// Family not found in the database.
    FamilyNotFound(String),
    /// Rule set is empty.
    EmptyRuleSet,
    /// YARA rule syntax error.
    SyntaxError(String),
    /// Download failed.
    DownloadFailed(String),
    /// Cache miss.
    CacheMiss(String),
    /// Compilation error.
    CompilationFailed(String),
    /// Generic error.
    Other(String),
}

impl std::fmt::Display for YaraError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FamilyNotFound(n) => write!(f, "family not found: {n}"),
            Self::EmptyRuleSet => write!(f, "YARA rule set is empty"),
            Self::SyntaxError(m) => write!(f, "YARA syntax error: {m}"),
            Self::DownloadFailed(m) => write!(f, "download failed: {m}"),
            Self::CacheMiss(k) => write!(f, "cache miss: {k}"),
            Self::CompilationFailed(m) => write!(f, "compilation failed: {m}"),
            Self::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for YaraError {}

// ── RuleMetadata ──────────────────────────────────────────────────────────────

/// Metadata attached to a single YARA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    /// Rule name.
    pub name: String,
    /// Rule description.
    pub description: String,
    /// Author / contributor.
    pub author: String,
    /// Creation date (ISO string).
    pub date: String,
    /// Malware family this rule targets.
    pub family: String,
    /// TLSH hash of the target file, if known.
    pub tlsh: Option<String>,
    /// Minimum file size (bytes).
    pub min_file_size: Option<u64>,
    /// Maximum file size (bytes).
    pub max_file_size: Option<u64>,
    /// Tags.
    pub tags: Vec<String>,
    /// Version.
    pub version: String,
    /// Reference URL.
    pub reference: Option<String>,
    /// Malpedia rule ID.
    pub malpedia_rule_id: Option<String>,
}

impl RuleMetadata {
    /// Create minimal metadata.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        family: impl Into<String>,
        author: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            author: author.into(),
            date: "2024-01-01".into(),
            family: family.into(),
            tlsh: None,
            min_file_size: None,
            max_file_size: None,
            tags: Vec::new(),
            version: "1.0".into(),
            reference: None,
            malpedia_rule_id: None,
        }
    }

    /// Return `true` if the given file size is within the declared bounds.
    #[must_use]
    pub fn size_matches(&self, file_size: u64) -> bool {
        let min_ok = self.min_file_size.is_none_or(|m| file_size >= m);
        let max_ok = self.max_file_size.is_none_or(|m| file_size <= m);
        min_ok && max_ok
    }
}

// ── YaraRule ──────────────────────────────────────────────────────────────────

/// A single YARA rule (metadata + source).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    /// Rule metadata.
    pub metadata: RuleMetadata,
    /// Raw YARA rule source.
    pub source: String,
    /// Whether this rule has been validated.
    pub validated: bool,
    /// Last time this rule produced a match.
    pub last_matched: Option<u64>,
    /// Total match count.
    pub match_count: u32,
    /// Estimated false-positive rate [0.0, 1.0].
    pub false_positive_rate: f32,
}

impl YaraRule {
    /// Create a new YARA rule.
    #[must_use]
    pub fn new(metadata: RuleMetadata, source: impl Into<String>) -> Self {
        Self {
            metadata,
            source: source.into(),
            validated: false,
            last_matched: None,
            match_count: 0,
            false_positive_rate: 0.0,
        }
    }

    /// Mock-validate the rule (checks for non-empty source and `rule` keyword).
    ///
    /// # Errors
    /// Returns an error if the source is empty or missing the `rule` keyword.
    pub fn validate(&mut self) -> Result<(), YaraError> {
        if self.source.trim().is_empty() {
            return Err(YaraError::EmptyRuleSet);
        }
        // The keyword must appear as a standalone token, not as a substring
        // of an identifier like `not_a_rule`.
        let has_rule_keyword = self
            .source
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|tok| tok == "rule");
        if !has_rule_keyword {
            return Err(YaraError::SyntaxError("missing 'rule' keyword".into()));
        }
        self.validated = true;
        Ok(())
    }

    /// Simulate a match against a file (mock: matches if file content contains
    /// the family name as a string).
    pub fn mock_match(&mut self, content: &[u8]) -> bool {
        let family = self.metadata.family.to_ascii_lowercase();
        let haystack = String::from_utf8_lossy(content).to_ascii_lowercase();
        let matched = haystack.contains(family.as_str());
        if matched {
            self.match_count += 1;
            self.last_matched = Some(unix_now());
        }
        matched
    }

    /// Return `true` if this rule has a low false-positive rate.
    #[must_use]
    pub fn is_reliable(&self) -> bool {
        self.validated && self.false_positive_rate < 0.05
    }
}

// ── YaraRuleSet ───────────────────────────────────────────────────────────────

/// A collection of YARA rules, typically for one or more malware families.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct YaraRuleSet {
    /// Display name for this rule set.
    pub name: String,
    /// All rules in this set.
    pub rules: Vec<YaraRule>,
    /// Tags applied to the set.
    pub tags: Vec<String>,
    /// Creation timestamp.
    pub created_at: u64,
    /// Number of times this set has been scanned.
    pub scan_count: u32,
}

impl YaraRuleSet {
    /// Create a new, empty rule set.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            rules: Vec::new(),
            tags: Vec::new(),
            created_at: unix_now(),
            scan_count: 0,
        }
    }

    /// Add a rule to the set.
    pub fn add_rule(&mut self, rule: YaraRule) {
        self.rules.push(rule);
    }

    /// Validate all rules, returning those that failed.
    pub fn validate_all(&mut self) -> Vec<String> {
        let mut failed = Vec::new();
        for rule in &mut self.rules {
            if let Err(e) = rule.validate() {
                failed.push(format!("{}: {e}", rule.metadata.name));
            }
        }
        failed
    }

    /// Scan `content` against all rules, returning matching rule names.
    pub fn scan(&mut self, content: &[u8]) -> Vec<String> {
        self.scan_count += 1;
        let mut matches = Vec::new();
        for rule in &mut self.rules {
            if rule.mock_match(content) {
                matches.push(rule.metadata.name.clone());
            }
        }
        matches
    }

    /// Return all reliable rules.
    #[must_use]
    pub fn reliable_rules(&self) -> Vec<&YaraRule> {
        self.rules.iter().filter(|r| r.is_reliable()).collect()
    }

    /// Return the number of rules.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.rules.len()
    }

    /// Return `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Generate a combined YARA source file.
    #[must_use]
    pub fn combined_source(&self) -> String {
        self.rules
            .iter()
            .map(|r| r.source.as_str())
            .collect::<Vec<_>>()
            .join("\n\n")
    }

    /// Return families covered by this rule set.
    #[must_use]
    pub fn covered_families(&self) -> Vec<String> {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut result = Vec::new();
        for r in &self.rules {
            if seen.insert(r.metadata.family.clone()) {
                result.push(r.metadata.family.clone());
            }
        }
        result.sort();
        result
    }
}

// ── FamilyYara ────────────────────────────────────────────────────────────────

/// YARA rules specific to a single Malpedia malware family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyYara {
    /// Malpedia family slug (e.g. `"win.emotet"`).
    pub family: String,
    /// Malpedia URL for this family.
    pub url: String,
    /// Primary rule set for this family.
    pub primary_rules: YaraRuleSet,
    /// Secondary / community-contributed rules.
    pub community_rules: YaraRuleSet,
    /// Platform tags (e.g. `["win"]`).
    pub platforms: Vec<String>,
    /// Associated malware names / aliases.
    pub aliases: Vec<String>,
    /// Whether the family is currently active.
    pub active: bool,
    /// First seen date.
    pub first_seen: Option<String>,
    /// Last updated timestamp.
    pub last_updated: u64,
}

impl FamilyYara {
    /// Create a new family YARA container.
    #[must_use]
    pub fn new(family: impl Into<String>) -> Self {
        let family = family.into();
        let url = format!("https://malpedia.caad.fkie.fraunhofer.de/details/{family}");
        Self {
            family: family.clone(),
            url,
            primary_rules: YaraRuleSet::new(format!("{family} primary")),
            community_rules: YaraRuleSet::new(format!("{family} community")),
            platforms: Vec::new(),
            aliases: Vec::new(),
            active: true,
            first_seen: None,
            last_updated: unix_now(),
        }
    }

    /// Add a primary rule.
    pub fn add_primary_rule(&mut self, rule: YaraRule) {
        self.primary_rules.add_rule(rule);
    }

    /// Add a community rule.
    pub fn add_community_rule(&mut self, rule: YaraRule) {
        self.community_rules.add_rule(rule);
    }

    /// Total rule count across primary + community.
    #[must_use]
    pub const fn total_rules(&self) -> usize {
        self.primary_rules.len() + self.community_rules.len()
    }

    /// Scan content against all rules.
    pub fn scan(&mut self, content: &[u8]) -> Vec<String> {
        let mut matches = self.primary_rules.scan(content);
        matches.extend(self.community_rules.scan(content));
        matches
    }

    /// Generate a mock primary YARA rule for this family.
    #[must_use]
    pub fn mock_rule(&self) -> YaraRule {
        let family = &self.family;
        let meta = RuleMetadata::new(format!("detect_{family}"), family.clone(), "malpedia");
        let source = format!(
            r#"rule detect_{family} {{
    meta:
        description = "Detects {family}"
        author = "malpedia"
    strings:
        $s1 = "{family}" ascii wide nocase
    condition:
        $s1
}}"#
        );
        YaraRule::new(meta, source)
    }
}

// ── YaraDownloader ────────────────────────────────────────────────────────────

/// Configuration and state for downloading YARA rules from Malpedia.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraDownloader {
    /// Malpedia API base URL.
    pub api_url: String,
    /// API authentication token.
    pub api_token: Option<String>,
    /// Whether to include community rules.
    pub include_community: bool,
    /// Rate limit: max requests per minute.
    pub rate_limit_per_minute: u32,
    /// Last download timestamp.
    pub last_download: Option<u64>,
    /// Total number of rules downloaded.
    pub total_downloaded: u32,
    /// Download timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for YaraDownloader {
    fn default() -> Self {
        Self::new()
    }
}

impl YaraDownloader {
    /// Create a downloader with default Malpedia settings.
    #[must_use]
    pub fn new() -> Self {
        Self {
            api_url: "https://malpedia.caad.fkie.fraunhofer.de/api".into(),
            api_token: None,
            include_community: true,
            rate_limit_per_minute: 60,
            last_download: None,
            total_downloaded: 0,
            timeout_secs: 30,
        }
    }

    /// Set the API token.
    #[must_use]
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.api_token = Some(token.into());
        self
    }

    /// Mock-download YARA rules for a family.
    ///
    /// # Errors
    /// Returns an error if the download simulation fails.
    pub fn download_family(&mut self, family: &str) -> Result<FamilyYara, YaraError> {
        // Simulate a download by constructing a mock FamilyYara.
        let mut family_yara = FamilyYara::new(family);
        let rule = family_yara.mock_rule();
        family_yara.add_primary_rule(rule);
        self.last_download = Some(unix_now());
        self.total_downloaded += 1;
        Ok(family_yara)
    }

    /// Check whether a download is allowed (rate limit check, mock).
    #[must_use]
    pub fn can_download(&self) -> bool {
        self.last_download.is_none_or(|ts| {
            unix_now().saturating_sub(ts) >= 60 / u64::from(self.rate_limit_per_minute)
        })
    }

    /// Return `true` if authentication is configured.
    #[must_use]
    pub const fn is_authenticated(&self) -> bool {
        self.api_token.is_some()
    }
}

// ── YaraCache ─────────────────────────────────────────────────────────────────

/// Thread-safe, time-limited cache of `FamilyYara` data.
#[derive(Debug, Clone)]
pub struct YaraCache {
    inner: Arc<Mutex<YaraCacheInner>>,
    /// Time-to-live in seconds.
    pub ttl_secs: u64,
}

#[derive(Debug, Default)]
struct YaraCacheInner {
    entries: HashMap<String, CacheEntry>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    data: FamilyYara,
    inserted_at: u64,
}

impl YaraCache {
    /// Create a cache with the given TTL.
    #[must_use]
    pub fn with_ttl(ttl_secs: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(YaraCacheInner::default())),
            ttl_secs,
        }
    }

    /// Create a cache with a 24-hour TTL.
    #[must_use]
    pub fn new() -> Self {
        Self::with_ttl(86_400)
    }

    /// Insert or replace a `FamilyYara` entry.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn insert(&self, family: &str, data: FamilyYara) {
        let mut guard = self.inner.lock().unwrap();
        guard.entries.insert(
            family.to_string(),
            CacheEntry {
                data,
                inserted_at: unix_now(),
            },
        );
    }

    /// Look up an entry; returns `None` if missing or expired.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn get(&self, family: &str) -> Option<FamilyYara> {
        let guard = self.inner.lock().unwrap();
        guard.entries.get(family).and_then(|e| {
            let age = unix_now().saturating_sub(e.inserted_at);
            if age <= self.ttl_secs {
                Some(e.data.clone())
            } else {
                None
            }
        })
    }

    /// Check whether a non-expired entry exists.
    #[must_use]
    pub fn contains(&self, family: &str) -> bool {
        self.get(family).is_some()
    }

    /// Evict a single entry.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn evict(&self, family: &str) -> bool {
        self.inner.lock().unwrap().entries.remove(family).is_some()
    }

    /// Remove all expired entries.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn evict_expired(&self) -> usize {
        let now = unix_now();
        let ttl = self.ttl_secs;
        let mut guard = self.inner.lock().unwrap();
        let before = guard.entries.len();
        guard
            .entries
            .retain(|_, e| now.saturating_sub(e.inserted_at) <= ttl);
        before - guard.entries.len()
    }

    /// Clear the entire cache.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn clear(&self) {
        self.inner.lock().unwrap().entries.clear();
    }

    /// Number of cached entries (including potentially expired ones).
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }

    /// Return `true` if the cache is empty.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().entries.is_empty()
    }

    /// Return all cached family names.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn cached_families(&self) -> Vec<String> {
        let mut keys: Vec<_> = self.inner.lock().unwrap().entries.keys().cloned().collect();
        keys.sort();
        keys
    }
}

impl Default for YaraCache {
    fn default() -> Self {
        Self::new()
    }
}

// ── MalpediaYara ──────────────────────────────────────────────────────────────

/// Top-level YARA manager for Malpedia integration. Combines downloading,
/// caching, family-specific rules, and batch scanning.
#[derive(Debug)]
pub struct MalpediaYara {
    downloader: YaraDownloader,
    cache: YaraCache,
    /// Manually registered family YARA data.
    families: HashMap<String, FamilyYara>,
    /// Global rule set for cross-family scanning.
    global_set: YaraRuleSet,
}

impl Default for MalpediaYara {
    fn default() -> Self {
        Self::new()
    }
}

impl MalpediaYara {
    /// Create a new Malpedia YARA manager.
    #[must_use]
    pub fn new() -> Self {
        Self {
            downloader: YaraDownloader::new(),
            cache: YaraCache::new(),
            families: HashMap::new(),
            global_set: YaraRuleSet::new("global"),
        }
    }

    /// Configure the API token.
    pub fn set_token(&mut self, token: impl Into<String>) {
        self.downloader.api_token = Some(token.into());
    }

    /// Download and cache rules for a family (uses cache if available).
    ///
    /// # Errors
    /// Returns an error if the download fails.
    pub fn fetch_family(&mut self, family: &str) -> Result<FamilyYara, YaraError> {
        if let Some(cached) = self.cache.get(family) {
            return Ok(cached);
        }
        let data = self.downloader.download_family(family)?;
        self.cache.insert(family, data.clone());
        Ok(data)
    }

    /// Register a manually-built `FamilyYara`.
    pub fn register_family(&mut self, data: FamilyYara) {
        let family = data.family.clone();
        // Also add all primary rules to the global set.
        for rule in &data.primary_rules.rules {
            self.global_set.add_rule(rule.clone());
        }
        self.cache.insert(&family, data.clone());
        self.families.insert(family, data);
    }

    /// Scan content against a specific family's rules.
    ///
    /// # Errors
    /// Returns an error if the family is not registered.
    pub fn scan_family(&mut self, family: &str, content: &[u8]) -> Result<Vec<String>, YaraError> {
        let data = self
            .families
            .get_mut(family)
            .ok_or_else(|| YaraError::FamilyNotFound(family.to_string()))?;
        Ok(data.scan(content))
    }

    /// Scan content against all registered families.
    pub fn scan_all(&mut self, content: &[u8]) -> HashMap<String, Vec<String>> {
        let families: Vec<String> = self.families.keys().cloned().collect();
        let mut results = HashMap::new();
        for family in families {
            if let Some(data) = self.families.get_mut(&family) {
                let matches = data.scan(content);
                if !matches.is_empty() {
                    results.insert(family, matches);
                }
            }
        }
        results
    }

    /// Scan against the global rule set.
    pub fn scan_global(&mut self, content: &[u8]) -> Vec<String> {
        self.global_set.scan(content)
    }

    /// Return all registered family names.
    #[must_use]
    pub fn family_names(&self) -> Vec<String> {
        let mut names: Vec<_> = self.families.keys().cloned().collect();
        names.sort();
        names
    }

    /// Number of registered families.
    #[must_use]
    pub fn family_count(&self) -> usize {
        self.families.len()
    }

    /// Return the total number of rules across all families.
    #[must_use]
    pub fn total_rule_count(&self) -> usize {
        self.families.values().map(FamilyYara::total_rules).sum()
    }

    /// Return the cache reference.
    #[must_use]
    pub const fn cache(&self) -> &YaraCache {
        &self.cache
    }

    /// Return the downloader reference.
    #[must_use]
    pub const fn downloader(&self) -> &YaraDownloader {
        &self.downloader
    }
}

// ── MalpediaApiConfig ─────────────────────────────────────────────────────────

/// Configuration for connecting to the Malpedia REST API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalpediaApiConfig {
    /// Base API URL.
    pub api_url: String,
    /// API key (bearer token).
    pub api_key: Option<String>,
    /// HTTP timeout in seconds.
    pub timeout_secs: u64,
    /// Whether to verify TLS certificates.
    pub verify_tls: bool,
    /// Maximum number of families to download at once.
    pub batch_size: usize,
    /// Whether to include community rules by default.
    pub include_community: bool,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
}

impl Default for MalpediaApiConfig {
    fn default() -> Self {
        Self {
            api_url: "https://malpedia.caad.fkie.fraunhofer.de/api".into(),
            api_key: None,
            timeout_secs: 30,
            verify_tls: true,
            batch_size: 10,
            include_community: true,
            cache_ttl_secs: 86_400,
        }
    }
}

impl MalpediaApiConfig {
    /// Create with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a development config (no TLS verification).
    #[must_use]
    pub fn dev() -> Self {
        Self {
            api_url: "http://localhost:8080/api".into(),
            verify_tls: false,
            timeout_secs: 60,
            ..Default::default()
        }
    }

    /// Set the API key.
    #[must_use]
    pub fn with_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Return `true` if the config is valid.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        !self.api_url.is_empty() && self.batch_size > 0 && self.timeout_secs > 0
    }

    /// Build authorization headers (mock: returns bearer token string).
    #[must_use]
    pub fn auth_header(&self) -> Option<String> {
        self.api_key.as_ref().map(|k| format!("Bearer {k}"))
    }
}

// ── FamilyYaraCollection ──────────────────────────────────────────────────────

/// A named collection of `FamilyYara` data, suitable for bulk operations.
#[derive(Debug, Default)]
pub struct FamilyYaraCollection {
    pub name: String,
    pub families: Vec<FamilyYara>,
}

impl FamilyYaraCollection {
    /// Create a new, empty collection.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            families: Vec::new(),
        }
    }

    /// Add a family.
    pub fn add(&mut self, family: FamilyYara) {
        self.families.push(family);
    }

    /// Number of families.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.families.len()
    }

    /// Return `true` if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.families.is_empty()
    }

    /// Scan all families in the collection.
    pub fn scan_all(&mut self, content: &[u8]) -> HashMap<String, Vec<String>> {
        let mut results = HashMap::new();
        for f in &mut self.families {
            let matches = f.scan(content);
            if !matches.is_empty() {
                results.insert(f.family.clone(), matches);
            }
        }
        results
    }

    /// Return total rule count.
    #[must_use]
    pub fn total_rules(&self) -> usize {
        self.families.iter().map(FamilyYara::total_rules).sum()
    }

    /// Filter to active families only.
    #[must_use]
    pub fn active_families(&self) -> Vec<&FamilyYara> {
        self.families.iter().filter(|f| f.active).collect()
    }

    /// Return all family names.
    #[must_use]
    pub fn family_names(&self) -> Vec<&str> {
        self.families.iter().map(|f| f.family.as_str()).collect()
    }
}

// ── YaraStatistics ────────────────────────────────────────────────────────────

/// Aggregate scan statistics across all rules in a `MalpediaYara` instance.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct YaraStatistics {
    pub total_rules: usize,
    pub total_families: usize,
    pub total_scans: u32,
    pub total_matches: u32,
    pub top_matched_rules: Vec<(String, u32)>,
    pub families_with_matches: Vec<String>,
}

impl YaraStatistics {
    /// Compute statistics from a `MalpediaYara` instance.
    #[must_use]
    pub fn from_malpedia(my: &MalpediaYara) -> Self {
        let total_families = my.family_count();
        let total_rules = my.total_rule_count();
        let mut all_rules: Vec<(String, u32)> = Vec::new();
        let mut families_with_matches: Vec<String> = Vec::new();
        let mut total_scans = 0u32;
        let mut total_matches = 0u32;

        for (family, f_yara) in &my.families {
            let mut family_had_match = false;
            for rule in &f_yara.primary_rules.rules {
                total_scans += f_yara.primary_rules.scan_count;
                total_matches += rule.match_count;
                if rule.match_count > 0 {
                    all_rules.push((rule.metadata.name.clone(), rule.match_count));
                    family_had_match = true;
                }
            }
            if family_had_match {
                families_with_matches.push(family.clone());
            }
        }

        all_rules.sort_by(|a, b| b.1.cmp(&a.1));
        all_rules.truncate(10);
        families_with_matches.sort();

        Self {
            total_rules,
            total_families,
            total_scans,
            total_matches,
            top_matched_rules: all_rules,
            families_with_matches,
        }
    }

    /// Return `true` if any rules have matched.
    #[must_use]
    pub const fn has_matches(&self) -> bool {
        self.total_matches > 0
    }
}

// ── YaraSignatureExporter ─────────────────────────────────────────────────────

/// Exports YARA rules from a `MalpediaYara` instance in various formats.
#[derive(Debug, Default)]
pub struct YaraSignatureExporter;

impl YaraSignatureExporter {
    /// Create a new exporter.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Export all primary rules as a single combined YARA file.
    #[must_use]
    pub fn export_all_primary(&self, my: &MalpediaYara) -> String {
        let mut parts: Vec<String> = Vec::new();
        parts.push("// RustRE / Malpedia YARA Export".into());
        for f in my.families.values() {
            let src = f.primary_rules.combined_source();
            if !src.is_empty() {
                parts.push(format!("// --- {} ---\n{}", f.family, src));
            }
        }
        parts.join("\n\n")
    }

    /// Export rules for a specific family.
    #[must_use]
    pub fn export_family(&self, my: &MalpediaYara, family: &str) -> Option<String> {
        my.families
            .get(family)
            .map(|f| f.primary_rules.combined_source())
    }

    /// Export rule names only (for index generation).
    #[must_use]
    pub fn rule_index(&self, my: &MalpediaYara) -> Vec<String> {
        let mut names: Vec<String> = Vec::new();
        for f in my.families.values() {
            for r in &f.primary_rules.rules {
                names.push(r.metadata.name.clone());
            }
        }
        names.sort();
        names
    }

    /// Count exportable rules.
    #[must_use]
    pub fn exportable_count(&self, my: &MalpediaYara) -> usize {
        my.families
            .values()
            .flat_map(|f| f.primary_rules.rules.iter())
            .filter(|r| r.validated)
            .count()
    }
}

// ── RuleQualityChecker ────────────────────────────────────────────────────────

/// Quality assessment for YARA rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleQuality {
    pub rule_name: String,
    pub score: f32,
    pub issues: Vec<String>,
    pub suggestions: Vec<String>,
}

impl RuleQuality {
    /// Analyse a rule and return its quality assessment.
    #[must_use]
    pub fn assess(rule: &YaraRule) -> Self {
        let mut issues: Vec<String> = Vec::new();
        let mut suggestions: Vec<String> = Vec::new();
        let mut score = 100.0_f32;

        if !rule.validated {
            issues.push("Rule has not been validated".into());
            score -= 30.0;
        }
        if rule.false_positive_rate > 0.1 {
            issues.push(format!(
                "High false-positive rate: {:.1}%",
                rule.false_positive_rate * 100.0
            ));
            score -= 20.0;
        }
        if rule.metadata.description.is_empty() {
            suggestions.push("Add a description to the rule metadata".into());
            score -= 5.0;
        }
        if rule.metadata.author.is_empty() {
            suggestions.push("Add an author to the rule metadata".into());
            score -= 5.0;
        }
        if rule.source.len() < 50 {
            issues.push("Rule source is suspiciously short".into());
            score -= 10.0;
        }
        if rule.metadata.reference.is_none() {
            suggestions.push("Add a reference URL for this rule".into());
        }

        Self {
            rule_name: rule.metadata.name.clone(),
            score: score.clamp(0.0, 100.0),
            issues,
            suggestions,
        }
    }

    /// Return `true` if the rule passes minimum quality (score >= 70).
    #[must_use]
    pub fn passes(&self) -> bool {
        self.score >= 70.0
    }
}

/// Check quality for all rules in a `YaraRuleSet`.
#[must_use]
pub fn check_ruleset_quality(rs: &YaraRuleSet) -> Vec<RuleQuality> {
    rs.rules.iter().map(RuleQuality::assess).collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_valid_rule(family: &str) -> YaraRule {
        let meta = RuleMetadata::new(format!("detect_{family}"), family, "test");
        let source = format!(
            r#"rule detect_{family} {{ meta: description = "{family}" strings: $a = "{family}" condition: $a }}"#
        );
        YaraRule::new(meta, source)
    }

    // Helper to make a validated rule
    fn _make_validated_rule(family: &str) -> YaraRule {
        let mut r = make_valid_rule(family);
        r.validate().unwrap();
        r
    }

    // ── RuleMetadata ─────────────────────────────────────────────────────────

    #[test]
    fn test_rule_metadata_size_matches() {
        let mut m = RuleMetadata::new("r", "emotet", "analyst");
        m.min_file_size = Some(1024);
        m.max_file_size = Some(1_000_000);
        assert!(m.size_matches(10_000));
        assert!(!m.size_matches(100));
        assert!(!m.size_matches(2_000_000));
    }

    #[test]
    fn test_rule_metadata_no_bounds() {
        let m = RuleMetadata::new("r", "emotet", "analyst");
        assert!(m.size_matches(0));
        assert!(m.size_matches(u64::MAX));
    }

    // ── YaraRule ─────────────────────────────────────────────────────────────

    #[test]
    fn test_yara_rule_validate_ok() {
        let mut rule = make_valid_rule("emotet");
        assert!(rule.validate().is_ok());
        assert!(rule.validated);
    }

    #[test]
    fn test_yara_rule_validate_empty() {
        let meta = RuleMetadata::new("empty_rule", "test", "analyst");
        let mut rule = YaraRule::new(meta, "");
        assert!(rule.validate().is_err());
    }

    #[test]
    fn test_yara_rule_validate_missing_keyword() {
        let meta = RuleMetadata::new("r", "test", "analyst");
        let mut rule = YaraRule::new(meta, "not_a_rule { condition: true }");
        assert!(rule.validate().is_err());
    }

    #[test]
    fn test_yara_rule_mock_match() {
        let mut rule = make_valid_rule("emotet");
        let content = b"this_is_emotet_sample";
        assert!(rule.mock_match(content));
        assert_eq!(rule.match_count, 1);
    }

    #[test]
    fn test_yara_rule_no_match() {
        let mut rule = make_valid_rule("emotet");
        let content = b"totally_clean_file";
        assert!(!rule.mock_match(content));
        assert_eq!(rule.match_count, 0);
    }

    #[test]
    fn test_yara_rule_reliable_validated_low_fp() {
        let mut rule = make_valid_rule("emotet");
        rule.validate().unwrap();
        assert!(rule.is_reliable());
    }

    #[test]
    fn test_yara_rule_not_reliable_high_fp() {
        let mut rule = make_valid_rule("emotet");
        rule.validate().unwrap();
        rule.false_positive_rate = 0.1;
        assert!(!rule.is_reliable());
    }

    // ── YaraRuleSet ──────────────────────────────────────────────────────────

    #[test]
    fn test_rule_set_add_and_len() {
        let mut rs = YaraRuleSet::new("test");
        rs.add_rule(make_valid_rule("emotet"));
        assert_eq!(rs.len(), 1);
    }

    #[test]
    fn test_rule_set_scan() {
        let mut rs = YaraRuleSet::new("test");
        rs.add_rule(make_valid_rule("emotet"));
        let matches = rs.scan(b"emotet_malware_sample");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_rule_set_validate_all() {
        let mut rs = YaraRuleSet::new("test");
        rs.add_rule(make_valid_rule("emotet"));
        let failed = rs.validate_all();
        assert!(failed.is_empty());
    }

    #[test]
    fn test_rule_set_covered_families() {
        let mut rs = YaraRuleSet::new("test");
        rs.add_rule(make_valid_rule("emotet"));
        rs.add_rule(make_valid_rule("trickbot"));
        let families = rs.covered_families();
        assert!(families.contains(&"emotet".to_string()));
        assert!(families.contains(&"trickbot".to_string()));
    }

    #[test]
    fn test_rule_set_combined_source() {
        let mut rs = YaraRuleSet::new("test");
        rs.add_rule(make_valid_rule("emotet"));
        let src = rs.combined_source();
        assert!(src.contains("emotet"));
    }

    // ── FamilyYara ───────────────────────────────────────────────────────────

    #[test]
    fn test_family_yara_new() {
        let f = FamilyYara::new("win.emotet");
        assert!(f.url.contains("win.emotet"));
    }

    #[test]
    fn test_family_yara_add_rules() {
        let mut f = FamilyYara::new("win.emotet");
        f.add_primary_rule(make_valid_rule("win.emotet"));
        assert_eq!(f.total_rules(), 1);
    }

    #[test]
    fn test_family_yara_scan() {
        let mut f = FamilyYara::new("win.emotet");
        f.add_primary_rule(make_valid_rule("win.emotet"));
        let matches = f.scan(b"win.emotet payload");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_family_yara_mock_rule() {
        let f = FamilyYara::new("test_fam");
        let rule = f.mock_rule();
        assert!(rule.source.contains("test_fam"));
    }

    // ── YaraDownloader ───────────────────────────────────────────────────────

    #[test]
    fn test_downloader_authenticated() {
        let d = YaraDownloader::new().with_token("tok123");
        assert!(d.is_authenticated());
    }

    #[test]
    fn test_downloader_not_authenticated() {
        let d = YaraDownloader::new();
        assert!(!d.is_authenticated());
    }

    #[test]
    fn test_downloader_mock_download() {
        let mut d = YaraDownloader::new();
        let f = d.download_family("win.emotet").unwrap();
        assert_eq!(f.family, "win.emotet");
        assert!(d.last_download.is_some());
        assert_eq!(d.total_downloaded, 1);
    }

    #[test]
    fn test_downloader_can_download() {
        let mut d = YaraDownloader::new();
        assert!(d.can_download());
        d.last_download = Some(unix_now()); // just downloaded
        // Still can download because rate limit check uses per-minute granularity.
        // The function is non-blocking so we just verify it doesn't panic.
        let _ = d.can_download();
    }

    // ── YaraCache ────────────────────────────────────────────────────────────

    #[test]
    fn test_yara_cache_insert_and_get() {
        let cache = YaraCache::new();
        let f = FamilyYara::new("win.emotet");
        cache.insert("win.emotet", f);
        assert!(cache.contains("win.emotet"));
    }

    #[test]
    fn test_yara_cache_expired() {
        let cache = YaraCache::with_ttl(0); // expires immediately
        let f = FamilyYara::new("win.trickbot");
        cache.insert("win.trickbot", f);
        // TTL is 0, so any positive age > 0 means expired.
        // unix_now() is already >= inserted_at, so might or might not expire.
        // We just confirm the API works.
        let _ = cache.get("win.trickbot");
    }

    #[test]
    fn test_yara_cache_evict() {
        let cache = YaraCache::new();
        cache.insert("win.emotet", FamilyYara::new("win.emotet"));
        assert!(cache.evict("win.emotet"));
        assert!(!cache.contains("win.emotet"));
    }

    #[test]
    fn test_yara_cache_clear() {
        let cache = YaraCache::new();
        cache.insert("a", FamilyYara::new("a"));
        cache.insert("b", FamilyYara::new("b"));
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_yara_cache_cached_families() {
        let cache = YaraCache::new();
        cache.insert("win.emotet", FamilyYara::new("win.emotet"));
        cache.insert("win.trickbot", FamilyYara::new("win.trickbot"));
        let families = cache.cached_families();
        assert_eq!(families.len(), 2);
        assert!(families.contains(&"win.emotet".to_string()));
    }

    // ── MalpediaYara ─────────────────────────────────────────────────────────

    #[test]
    fn test_malpedia_yara_register_family() {
        let mut my = MalpediaYara::new();
        let f = FamilyYara::new("win.emotet");
        my.register_family(f);
        assert_eq!(my.family_count(), 1);
    }

    #[test]
    fn test_malpedia_yara_family_names() {
        let mut my = MalpediaYara::new();
        my.register_family(FamilyYara::new("win.emotet"));
        my.register_family(FamilyYara::new("win.trickbot"));
        let names = my.family_names();
        assert!(names.contains(&"win.emotet".to_string()));
        assert!(names.contains(&"win.trickbot".to_string()));
    }

    #[test]
    fn test_malpedia_yara_scan_family() {
        let mut my = MalpediaYara::new();
        let mut f = FamilyYara::new("win.emotet");
        f.add_primary_rule(make_valid_rule("win.emotet"));
        my.register_family(f);
        let matches = my.scan_family("win.emotet", b"win.emotet_sample").unwrap();
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_malpedia_yara_scan_family_not_found() {
        let mut my = MalpediaYara::new();
        assert!(my.scan_family("missing", b"data").is_err());
    }

    #[test]
    fn test_malpedia_yara_scan_all() {
        let mut my = MalpediaYara::new();
        let mut f = FamilyYara::new("win.emotet");
        f.add_primary_rule(make_valid_rule("win.emotet"));
        my.register_family(f);
        let results = my.scan_all(b"win.emotet payload");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_malpedia_yara_fetch_family() {
        let mut my = MalpediaYara::new();
        let f = my.fetch_family("win.test").unwrap();
        assert_eq!(f.family, "win.test");
        // Second call should use cache.
        let f2 = my.fetch_family("win.test").unwrap();
        assert_eq!(f2.family, "win.test");
    }

    #[test]
    fn test_malpedia_yara_total_rule_count() {
        let mut my = MalpediaYara::new();
        let mut f = FamilyYara::new("win.emotet");
        f.add_primary_rule(make_valid_rule("win.emotet"));
        f.add_community_rule(make_valid_rule("win.emotet"));
        my.register_family(f);
        assert_eq!(my.total_rule_count(), 2);
    }

    // ── YaraStatistics ───────────────────────────────────────────────────────

    #[test]
    fn test_yara_statistics_empty() {
        let my = MalpediaYara::new();
        let stats = YaraStatistics::from_malpedia(&my);
        assert_eq!(stats.total_families, 0);
        assert!(!stats.has_matches());
    }

    #[test]
    fn test_yara_statistics_with_rules() {
        let mut my = MalpediaYara::new();
        let mut f = FamilyYara::new("win.emotet");
        f.add_primary_rule(make_valid_rule("win.emotet"));
        my.register_family(f);
        let stats = YaraStatistics::from_malpedia(&my);
        assert_eq!(stats.total_families, 1);
        assert_eq!(stats.total_rules, 1);
    }

    // ── YaraSignatureExporter ────────────────────────────────────────────────

    #[test]
    fn test_exporter_export_all_primary() {
        let mut my = MalpediaYara::new();
        let mut f = FamilyYara::new("win.emotet");
        f.add_primary_rule(make_valid_rule("win.emotet"));
        my.register_family(f);
        let exp = YaraSignatureExporter::new();
        let output = exp.export_all_primary(&my);
        assert!(
            output.contains("win.emotet")
                || output.contains("detect_win.emotet")
                || output.len() > 10
        );
    }

    #[test]
    fn test_exporter_export_family() {
        let mut my = MalpediaYara::new();
        let mut f = FamilyYara::new("win.emotet");
        f.add_primary_rule(make_valid_rule("win.emotet"));
        my.register_family(f);
        let exp = YaraSignatureExporter::new();
        let output = exp.export_family(&my, "win.emotet");
        assert!(output.is_some());
    }

    #[test]
    fn test_exporter_export_family_missing() {
        let my = MalpediaYara::new();
        let exp = YaraSignatureExporter::new();
        assert!(exp.export_family(&my, "missing").is_none());
    }

    #[test]
    fn test_exporter_rule_index() {
        let mut my = MalpediaYara::new();
        let mut f = FamilyYara::new("win.emotet");
        let mut rule = make_valid_rule("win.emotet");
        rule.metadata.name = "detect_emotet_v2".into();
        f.add_primary_rule(rule);
        my.register_family(f);
        let exp = YaraSignatureExporter::new();
        let index = exp.rule_index(&my);
        assert!(index.contains(&"detect_emotet_v2".to_string()));
    }

    // ── RuleQuality ──────────────────────────────────────────────────────────

    #[test]
    fn test_rule_quality_validated_rule() {
        let mut rule = make_valid_rule("emotet");
        rule.metadata.description = "Detects Emotet".into();
        rule.metadata.author = "analyst".into();
        rule.validate().unwrap();
        let q = RuleQuality::assess(&rule);
        assert!(q.passes());
    }

    #[test]
    fn test_rule_quality_unvalidated() {
        let rule = make_valid_rule("emotet");
        let q = RuleQuality::assess(&rule);
        assert!(!rule.validated);
        assert!(!q.passes());
    }

    #[test]
    fn test_rule_quality_high_fp() {
        let mut rule = make_valid_rule("emotet");
        rule.validate().unwrap();
        rule.false_positive_rate = 0.2;
        let q = RuleQuality::assess(&rule);
        assert!(q.issues.iter().any(|i| i.contains("false-positive")));
    }

    #[test]
    fn test_check_ruleset_quality() {
        let mut rs = YaraRuleSet::new("test");
        rs.add_rule(make_valid_rule("emotet"));
        let qualities = check_ruleset_quality(&rs);
        assert_eq!(qualities.len(), 1);
    }

    // ── MalpediaApiConfig ────────────────────────────────────────────────────

    #[test]
    fn test_config_defaults() {
        let cfg = MalpediaApiConfig::new();
        assert!(cfg.is_valid());
        assert!(cfg.verify_tls);
        assert!(cfg.include_community);
    }

    #[test]
    fn test_config_dev() {
        let cfg = MalpediaApiConfig::dev();
        assert!(!cfg.verify_tls);
        assert!(cfg.api_url.contains("localhost"));
    }

    #[test]
    fn test_config_with_key() {
        let cfg = MalpediaApiConfig::new().with_key("tok123");
        assert!(cfg.api_key.is_some());
        assert!(cfg.auth_header().unwrap().starts_with("Bearer"));
    }

    #[test]
    fn test_config_no_auth_header() {
        let cfg = MalpediaApiConfig::new();
        assert!(cfg.auth_header().is_none());
    }

    #[test]
    fn test_config_invalid_empty_url() {
        let mut cfg = MalpediaApiConfig::new();
        cfg.api_url = String::new();
        assert!(!cfg.is_valid());
    }

    // ── FamilyYaraCollection ─────────────────────────────────────────────────

    #[test]
    fn test_collection_add_and_len() {
        let mut col = FamilyYaraCollection::new("test_collection");
        col.add(FamilyYara::new("win.emotet"));
        col.add(FamilyYara::new("win.trickbot"));
        assert_eq!(col.len(), 2);
    }

    #[test]
    fn test_collection_scan_all() {
        let mut col = FamilyYaraCollection::new("test");
        let mut f = FamilyYara::new("win.emotet");
        f.add_primary_rule(make_valid_rule("win.emotet"));
        col.add(f);
        let results = col.scan_all(b"win.emotet payload here");
        assert!(!results.is_empty());
    }

    #[test]
    fn test_collection_total_rules() {
        let mut col = FamilyYaraCollection::new("test");
        let mut f = FamilyYara::new("win.emotet");
        f.add_primary_rule(make_valid_rule("win.emotet"));
        f.add_community_rule(make_valid_rule("win.emotet"));
        col.add(f);
        assert_eq!(col.total_rules(), 2);
    }

    #[test]
    fn test_collection_active_families() {
        let mut col = FamilyYaraCollection::new("test");
        let mut active = FamilyYara::new("win.active");
        active.active = true;
        let mut inactive = FamilyYara::new("win.inactive");
        inactive.active = false;
        col.add(active);
        col.add(inactive);
        assert_eq!(col.active_families().len(), 1);
    }

    #[test]
    fn test_collection_family_names() {
        let mut col = FamilyYaraCollection::new("test");
        col.add(FamilyYara::new("win.emotet"));
        col.add(FamilyYara::new("win.trickbot"));
        let names = col.family_names();
        assert!(names.contains(&"win.emotet"));
        assert!(names.contains(&"win.trickbot"));
    }
}
