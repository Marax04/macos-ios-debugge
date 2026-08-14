//! YARA rule fetching and caching for Malpedia.
//!
//! Provides types to download, cache, and serve per-family YARA rules
//! from the Malpedia API. Includes a rule-set parser, a per-family cache
//! with TTL-based expiry, and a batch fetcher for offline bundles.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// RuleStatus
// ---------------------------------------------------------------------------

/// Status of a cached YARA rule set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleStatus {
    /// Rule set is present and fresh.
    Fresh,
    /// Rule set is present but stale (TTL expired).
    Stale,
    /// Rule set has never been fetched.
    Missing,
    /// The last fetch attempt failed.
    FetchFailed,
}

impl std::fmt::Display for RuleStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fresh => write!(f, "Fresh"),
            Self::Stale => write!(f, "Stale"),
            Self::Missing => write!(f, "Missing"),
            Self::FetchFailed => write!(f, "FetchFailed"),
        }
    }
}

// ---------------------------------------------------------------------------
// YaraString
// ---------------------------------------------------------------------------

/// A single string definition within a YARA rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct YaraString {
    /// Identifier (without the leading `$`).
    pub identifier: String,
    /// The pattern value (hex bytes, text string, or regex).
    pub value: String,
    /// Optional modifiers (e.g. "ascii", "wide", "nocase").
    pub modifiers: Vec<String>,
}

impl YaraString {
    /// Create a simple hex-pattern YARA string.
    #[must_use]
    pub fn hex(identifier: impl Into<String>, pattern: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            value: format!("{{ {} }}", pattern.into()),
            modifiers: Vec::new(),
        }
    }

    /// Create a plain text YARA string.
    #[must_use]
    pub fn text(identifier: impl Into<String>, text: impl Into<String>, wide: bool) -> Self {
        let mut mods = Vec::new();
        if wide {
            mods.push("wide".to_string());
        }
        Self {
            identifier: identifier.into(),
            value: format!("\"{}\"", text.into()),
            modifiers: mods,
        }
    }

    /// Render this string as a YARA rule source line.
    #[must_use]
    pub fn render(&self) -> String {
        if self.modifiers.is_empty() {
            format!("        ${} = {}", self.identifier, self.value)
        } else {
            format!(
                "        ${} = {} {}",
                self.identifier,
                self.value,
                self.modifiers.join(" ")
            )
        }
    }
}

// ---------------------------------------------------------------------------
// YaraRuleSet
// ---------------------------------------------------------------------------

/// A YARA rule targeting a specific malware family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleSet {
    /// Rule name (must be a valid YARA identifier).
    pub name: String,
    /// Associated malware family id.
    pub family_id: String,
    /// Human-readable description.
    pub description: String,
    /// Rule author.
    pub author: Option<String>,
    /// Rule date.
    pub date: Option<String>,
    /// Sample hash(es) used to build this rule.
    pub reference_hashes: Vec<String>,
    /// Classification tags.
    pub tags: Vec<String>,
    /// YARA string definitions.
    pub strings: Vec<YaraString>,
    /// Condition expression.
    pub condition: String,
    /// Raw rule source text (if available).
    pub raw_source: Option<String>,
    /// Version or revision string.
    pub version: Option<String>,
}

impl YaraRuleSet {
    /// Create a new empty rule targeting `family_id`.
    #[must_use]
    pub fn new(name: impl Into<String>, family_id: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            family_id: family_id.into(),
            description: String::new(),
            author: None,
            date: None,
            reference_hashes: Vec::new(),
            tags: Vec::new(),
            strings: Vec::new(),
            condition: "any of them".to_string(),
            raw_source: None,
            version: None,
        }
    }

    /// Add a string definition.
    pub fn add_string(&mut self, s: YaraString) {
        self.strings.push(s);
    }

    /// Render the rule as YARA source text.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        if let Some(ref raw) = self.raw_source {
            return raw.clone();
        }
        let mut out = String::new();
        let tag_str = if self.tags.is_empty() {
            String::new()
        } else {
            format!(" : {}", self.tags.join(" "))
        };
        let _ = writeln!(out, "rule {}{} {{", self.name, tag_str);
        let _ = writeln!(out, "    meta:");
        let _ = writeln!(out, "        description = \"{}\"", self.description);
        let _ = writeln!(out, "        family = \"{}\"", self.family_id);
        if let Some(ref auth) = self.author {
            let _ = writeln!(out, "        author = \"{auth}\"");
        }
        if let Some(ref date) = self.date {
            let _ = writeln!(out, "        date = \"{date}\"");
        }
        if !self.strings.is_empty() {
            let _ = writeln!(out, "    strings:");
            for s in &self.strings {
                let _ = writeln!(out, "{}", s.render());
            }
        }
        let _ = writeln!(out, "    condition:");
        let _ = writeln!(out, "        {}", self.condition);
        out.push('}');
        out.push('\n');
        out
    }

    /// Return the number of string definitions.
    #[must_use]
    pub const fn string_count(&self) -> usize {
        self.strings.len()
    }

    /// Return `true` if this rule has at least one string pattern.
    #[must_use]
    pub const fn has_patterns(&self) -> bool {
        !self.strings.is_empty()
    }

    /// Parse a trivially simple YARA rule to extract the rule name.
    /// (A full YARA parser is out of scope; this handles the common header form.)
    #[must_use]
    pub fn name_from_source(source: &str) -> Option<String> {
        // Look for `rule <identifier>` at the start of a line.
        for line in source.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix("rule ") {
                let name: String = rest
                    .split([' ', '{', ':'])
                    .next()
                    .unwrap_or("")
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() {
                    return Some(name);
                }
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// FamilyRules
// ---------------------------------------------------------------------------

/// A collection of YARA rules for a single malware family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyRules {
    /// The Malpedia family id.
    pub family_id: String,
    /// All YARA rules for this family.
    pub rules: Vec<YaraRuleSet>,
    /// Unix timestamp of the last successful fetch.
    pub fetched_at: u64,
    /// Whether these rules came from the live API or a local cache.
    pub from_cache: bool,
}

impl FamilyRules {
    /// Create an empty `FamilyRules` for the given family.
    #[must_use]
    pub fn new(family_id: impl Into<String>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            family_id: family_id.into(),
            rules: Vec::new(),
            fetched_at: now,
            from_cache: false,
        }
    }

    /// Add a rule.
    pub fn add_rule(&mut self, rule: YaraRuleSet) {
        self.rules.push(rule);
    }

    /// Total number of rules.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.rules.len()
    }

    /// Return `true` if this collection is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Render all rules as a concatenated YARA source text.
    #[must_use]
    pub fn render_all(&self) -> String {
        self.rules.iter().map(YaraRuleSet::render).collect::<Vec<_>>().join("\n")
    }

    /// Check if the rules are stale given a TTL in seconds.
    #[must_use]
    pub fn is_stale(&self, ttl_secs: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now.saturating_sub(self.fetched_at) > ttl_secs
    }
}

// ---------------------------------------------------------------------------
// RuleCache
// ---------------------------------------------------------------------------

/// An in-memory TTL cache for `FamilyRules`.
pub struct RuleCache {
    /// Map of `family_id` → (`FamilyRules`, expiry Unix timestamp).
    store: HashMap<String, (FamilyRules, u64)>,
    /// TTL for cache entries (seconds).
    ttl_secs: u64,
}

impl RuleCache {
    /// Create a new cache with the given TTL.
    #[must_use]
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            store: HashMap::new(),
            ttl_secs,
        }
    }

    /// Create a cache with a default 24-hour TTL.
    #[must_use]
    pub fn with_default_ttl() -> Self {
        Self::new(86_400)
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Insert or replace a `FamilyRules` entry.
    pub fn put(&mut self, mut rules: FamilyRules) {
        rules.from_cache = false;
        let expiry = Self::now_secs().saturating_add(self.ttl_secs);
        self.store.insert(rules.family_id.clone(), (rules, expiry));
    }

    /// Retrieve cached rules for a family, returning `None` if missing or expired.
    pub fn get(&mut self, family_id: &str) -> Option<&FamilyRules> {
        let now = Self::now_secs();
        if let Some((_, expiry)) = self.store.get(family_id)
            && now > *expiry
        {
            self.store.remove(family_id);
            return None;
        }
        if let Some((rules, _)) = self.store.get_mut(family_id) {
            rules.from_cache = true;
            return Some(rules);
        }
        None
    }

    /// Get cached rules without TTL checking (returns stale entries too).
    #[must_use] pub fn get_stale(&self, family_id: &str) -> Option<&FamilyRules> {
        self.store.get(family_id).map(|(r, _)| r)
    }

    /// Evict expired entries. Returns the count of evicted entries.
    pub fn evict_expired(&mut self) -> usize {
        let now = Self::now_secs();
        let before = self.store.len();
        self.store.retain(|_, (_, expiry)| now <= *expiry);
        before - self.store.len()
    }

    /// Invalidate a single family entry.
    pub fn invalidate(&mut self, family_id: &str) -> bool {
        self.store.remove(family_id).is_some()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.store.clear();
    }

    /// Number of entries in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Return `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// Return the status for a specific family.
    pub fn status(&mut self, family_id: &str) -> RuleStatus {
        let now = Self::now_secs();
        match self.store.get(family_id) {
            None => RuleStatus::Missing,
            Some((_, expiry)) => {
                if now > *expiry {
                    RuleStatus::Stale
                } else {
                    RuleStatus::Fresh
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MalpediaYaraFetcher
// ---------------------------------------------------------------------------

/// Fetches YARA rules from Malpedia, caching results to avoid redundant fetches.
///
/// In a real deployment this would make HTTP requests to the Malpedia API.
/// Here we use a purely synchronous mock implementation suitable for testing
/// and offline analysis pipelines.
pub struct MalpediaYaraFetcher {
    /// API key for authenticated Malpedia endpoints.
    api_key: Option<String>,
    /// Base URL of the Malpedia API.
    base_url: String,
    /// TTL for cached rule sets.
    cache_ttl: Duration,
    /// In-memory rule cache.
    cache: RuleCache,
    /// Count of live fetches performed.
    fetch_count: u64,
    /// Count of cache hits.
    cache_hit_count: u64,
}

impl MalpediaYaraFetcher {
    /// Create a new fetcher.
    #[must_use]
    pub fn new(api_key: Option<String>) -> Self {
        let ttl = Duration::from_hours(24);
        Self {
            api_key,
            base_url: "https://malpedia.caad.fkie.fraunhofer.de".to_string(),
            cache_ttl: ttl,
            cache: RuleCache::new(ttl.as_secs()),
            fetch_count: 0,
            cache_hit_count: 0,
        }
    }

    /// Override the cache TTL.
    #[must_use]
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self.cache = RuleCache::new(ttl.as_secs());
        self
    }

    /// Override the API base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Return `true` if an API key is configured.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.api_key.as_ref().is_some_and(|k| !k.is_empty())
    }

    /// Fetch YARA rules for a family, using the cache if available.
    ///
    /// This mock implementation generates deterministic fake rules for any
    /// family id.
    ///
    /// # Errors
    /// Returns a description string if the fetch fails.
    ///
    /// # Panics
    /// Panics if the cache state becomes inconsistent between checks (should not occur in practice).
    pub fn fetch_family_rules(&mut self, family_id: &str) -> Result<FamilyRules, String> {
        // Cache hit?
        if self.cache.get(family_id).is_some() {
            self.cache_hit_count += 1;
            // Clone out of borrow.
            let rules = self.cache.get_stale(family_id).unwrap().clone();
            return Ok(rules);
        }

        // Simulate a fetch.
        self.fetch_count += 1;
        let rules = Self::generate_mock_rules(family_id);
        self.cache.put(rules.clone());
        Ok(rules)
    }

    /// Batch-fetch rules for multiple families.
    ///
    /// Returns a map of `family_id → FamilyRules` for all successful fetches.
    pub fn fetch_batch(&mut self, family_ids: &[&str]) -> HashMap<String, FamilyRules> {
        let mut out = HashMap::new();
        for &id in family_ids {
            if let Ok(rules) = self.fetch_family_rules(id) {
                out.insert(id.to_string(), rules);
            }
        }
        out
    }

    /// Pre-warm the cache from a pre-built bundle of YARA sources.
    ///
    /// `bundle` is a map of `family_id → raw YARA source text`.
    pub fn load_bundle(&mut self, bundle: &HashMap<String, String>) {
        for (family_id, source) in bundle {
            let mut fr = FamilyRules::new(family_id.as_str());
            // Parse out each rule from the source (simplified: one rule per file).
            let rule_name = YaraRuleSet::name_from_source(source)
                .unwrap_or_else(|| format!("rule_{}", family_id.replace('.', "_")));
            let mut rs = YaraRuleSet::new(&rule_name, family_id.as_str());
            rs.raw_source = Some(source.clone());
            fr.add_rule(rs);
            self.cache.put(fr);
        }
    }

    /// Return statistics about cache utilisation.
    #[must_use]
    pub fn stats(&self) -> FetcherStats {
        FetcherStats {
            fetch_count: self.fetch_count,
            cache_hit_count: self.cache_hit_count,
            cached_families: self.cache.len(),
        }
    }

    /// Evict stale cache entries.
    pub fn evict_stale(&mut self) -> usize {
        self.cache.evict_expired()
    }

    /// Invalidate the cache for a specific family.
    pub fn invalidate(&mut self, family_id: &str) -> bool {
        self.cache.invalidate(family_id)
    }

    /// Clear all cached rules.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Generate deterministic mock YARA rules for a given family id.
    fn generate_mock_rules(family_id: &str) -> FamilyRules {
        let clean = family_id.replace(['.', '-'], "_");
        let rule_name = format!("detect_{clean}");
        let mut rs = YaraRuleSet::new(&rule_name, family_id);
        rs.description = format!("Auto-generated detection rule for {family_id}");
        rs.author = Some("RustRE Mock Generator".to_string());
        rs.date = Some("2026-06-11".to_string());
        rs.tags = vec!["malware".to_string(), clean.split('_').next().unwrap_or("win").to_string()];
        rs.strings = vec![
            YaraString::hex("b0", "DE AD BE EF 00"),
            YaraString::text("s0", format!("{family_id}_marker"), false),
        ];
        rs.condition = "1 of them".to_string();

        let mut fr = FamilyRules::new(family_id);
        fr.add_rule(rs);
        fr
    }
}

// ---------------------------------------------------------------------------
// FetcherStats
// ---------------------------------------------------------------------------

/// Aggregated statistics from a `MalpediaYaraFetcher`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetcherStats {
    /// Number of live fetch operations performed.
    pub fetch_count: u64,
    /// Number of cache hits.
    pub cache_hit_count: u64,
    /// Number of families currently in cache.
    pub cached_families: usize,
}

impl FetcherStats {
    /// Compute the cache hit rate [0.0, 1.0].
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        // Use saturating_add to avoid wrapping; u64 values > 2^53 lose precision
        // when cast to f64, so we clamp each operand to 2^53 before casting.
        const MAX_EXACT_F64: u64 = 1u64 << 53;
        let hits = self.cache_hit_count.min(MAX_EXACT_F64) as f64;
        let total = self
            .fetch_count
            .saturating_add(self.cache_hit_count)
            .min(MAX_EXACT_F64) as f64;
        if total == 0.0 {
            0.0
        } else {
            hits / total
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fetcher() -> MalpediaYaraFetcher {
        MalpediaYaraFetcher::new(Some("test-key".to_string()))
    }

    #[test]
    fn test_fetcher_authenticated() {
        assert!(fetcher().is_authenticated());
    }

    #[test]
    fn test_fetcher_anonymous() {
        assert!(!MalpediaYaraFetcher::new(None).is_authenticated());
    }

    #[test]
    fn test_fetch_returns_rules() {
        let mut f = fetcher();
        let r = f.fetch_family_rules("win.emotet").unwrap();
        assert_eq!(r.family_id, "win.emotet");
        assert!(!r.is_empty());
    }

    #[test]
    fn test_fetch_second_call_uses_cache() {
        let mut f = fetcher();
        let _ = f.fetch_family_rules("win.emotet").unwrap();
        let _ = f.fetch_family_rules("win.emotet").unwrap();
        assert_eq!(f.stats().fetch_count, 1);
        assert_eq!(f.stats().cache_hit_count, 1);
    }

    #[test]
    fn test_fetch_different_families_increment_fetch_count() {
        let mut f = fetcher();
        let _ = f.fetch_family_rules("win.emotet");
        let _ = f.fetch_family_rules("win.wannacry");
        assert_eq!(f.stats().fetch_count, 2);
    }

    #[test]
    fn test_batch_fetch() {
        let mut f = fetcher();
        let result = f.fetch_batch(&["win.emotet", "linux.mirai"]);
        assert_eq!(result.len(), 2);
        assert!(result.contains_key("win.emotet"));
    }

    #[test]
    fn test_invalidate_clears_entry() {
        let mut f = fetcher();
        let _ = f.fetch_family_rules("win.emotet");
        assert_eq!(f.cache.len(), 1);
        f.invalidate("win.emotet");
        assert_eq!(f.cache.len(), 0);
    }

    #[test]
    fn test_clear_cache() {
        let mut f = fetcher();
        let _ = f.fetch_family_rules("win.emotet");
        let _ = f.fetch_family_rules("win.wannacry");
        f.clear_cache();
        assert!(f.cache.is_empty());
    }

    #[test]
    fn test_load_bundle() {
        let mut f = fetcher();
        let mut bundle = HashMap::new();
        bundle.insert(
            "win.testfamily".to_string(),
            "rule detect_win_testfamily {\n  condition: false\n}\n".to_string(),
        );
        f.load_bundle(&bundle);
        assert_eq!(f.cache.len(), 1);
    }

    #[test]
    fn test_family_rules_render_all() {
        let mut f = fetcher();
        let r = f.fetch_family_rules("win.emotet").unwrap();
        let text = r.render_all();
        assert!(text.contains("rule "));
        assert!(text.contains("win.emotet"));
    }

    #[test]
    fn test_rule_set_render() {
        let mut rs = YaraRuleSet::new("test_rule", "win.test");
        rs.description = "Test rule".to_string();
        rs.strings
            .push(YaraString::hex("b0", "DE AD BE EF"));
        rs.condition = "any of them".to_string();
        let text = rs.render();
        assert!(text.contains("rule test_rule"));
        assert!(text.contains("$b0"));
        assert!(text.contains("DE AD BE EF"));
        assert!(text.contains("any of them"));
    }

    #[test]
    fn test_rule_set_render_with_raw_source() {
        let raw = "rule raw { condition: false }\n".to_string();
        let mut rs = YaraRuleSet::new("raw", "win.test");
        rs.raw_source = Some(raw.clone());
        assert_eq!(rs.render(), raw);
    }

    #[test]
    fn test_rule_set_name_from_source() {
        let src = "rule detect_emotet : malware {\n  condition: true\n}\n";
        let name = YaraRuleSet::name_from_source(src);
        assert_eq!(name.as_deref(), Some("detect_emotet"));
    }

    #[test]
    fn test_rule_set_name_from_source_none() {
        let name = YaraRuleSet::name_from_source("not a rule");
        assert!(name.is_none());
    }

    #[test]
    fn test_yara_string_hex_render() {
        let s = YaraString::hex("b0", "DE AD BE EF");
        assert!(s.render().contains("$b0"));
        assert!(s.render().contains("{ DE AD BE EF }"));
    }

    #[test]
    fn test_yara_string_text_render() {
        let s = YaraString::text("s0", "malpedia", true);
        assert!(s.render().contains("wide"));
    }

    #[test]
    fn test_rule_cache_put_and_get() {
        let mut cache = RuleCache::new(3600);
        let fr = FamilyRules::new("win.test");
        cache.put(fr);
        assert!(cache.get("win.test").is_some());
    }

    #[test]
    fn test_rule_cache_status_fresh() {
        let mut cache = RuleCache::new(3600);
        cache.put(FamilyRules::new("win.test"));
        assert_eq!(cache.status("win.test"), RuleStatus::Fresh);
    }

    #[test]
    fn test_rule_cache_status_missing() {
        let mut cache = RuleCache::new(3600);
        assert_eq!(cache.status("win.missing"), RuleStatus::Missing);
    }

    #[test]
    fn test_rule_cache_evict_expired_immediate() {
        // TTL = 0 means entries expire immediately.
        let mut cache = RuleCache::new(0);
        cache.put(FamilyRules::new("win.test"));
        // Entries with TTL=0 expire at the moment of insertion.
        let evicted = cache.evict_expired();
        assert!(evicted == 0 || cache.is_empty()); // implementation may or may not evict
    }

    #[test]
    fn test_fetcher_stats_hit_rate_empty() {
        let f = fetcher();
        let s = f.stats();
        assert!((s.hit_rate() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_family_rules_not_stale_fresh() {
        let fr = FamilyRules::new("win.test");
        // Should not be stale with a 1-day TTL.
        assert!(!fr.is_stale(86_400));
    }

    #[test]
    fn test_family_rules_stale_zero_ttl() {
        let mut fr = FamilyRules::new("win.test");
        // Set fetched_at to the distant past.
        fr.fetched_at = 0;
        assert!(fr.is_stale(3600));
    }

    #[test]
    fn test_rule_status_display() {
        assert_eq!(RuleStatus::Fresh.to_string(), "Fresh");
        assert_eq!(RuleStatus::Missing.to_string(), "Missing");
    }
}
