//! Malpedia YARA download client — fetches, caches, and organises YARA rules
//! by malware family.
//!
//! Covers: `MalpediaClient::download_yara_rules`, `MalpediaYaraRule`,
//! `YaraRuleSet`, `FamilyProfile`, and a TTL-backed rule cache.

use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

// ---------------------------------------------------------------------------
// YaraRuleTag — classification tags for YARA rules
// ---------------------------------------------------------------------------

/// Classification tags that can be attached to a YARA rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum YaraRuleTag {
    Ransomware,
    Trojan,
    Backdoor,
    Dropper,
    Stealer,
    Worm,
    Rootkit,
    Rat,
    Banker,
    Cryptominer,
    Tool,
    Loader,
    Custom(String),
}

impl YaraRuleTag {
    /// Return the string representation.
    #[must_use]
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Ransomware => "ransomware",
            Self::Trojan => "trojan",
            Self::Backdoor => "backdoor",
            Self::Dropper => "dropper",
            Self::Stealer => "stealer",
            Self::Worm => "worm",
            Self::Rootkit => "rootkit",
            Self::Rat => "rat",
            Self::Banker => "banker",
            Self::Cryptominer => "cryptominer",
            Self::Tool => "tool",
            Self::Loader => "loader",
            Self::Custom(s) => s.as_str(),
        }
    }

}

impl std::str::FromStr for YaraRuleTag {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "ransomware" => Self::Ransomware,
            "trojan" => Self::Trojan,
            "backdoor" => Self::Backdoor,
            "dropper" => Self::Dropper,
            "stealer" => Self::Stealer,
            "worm" => Self::Worm,
            "rootkit" => Self::Rootkit,
            "rat" => Self::Rat,
            "banker" => Self::Banker,
            "cryptominer" | "miner" => Self::Cryptominer,
            "tool" => Self::Tool,
            "loader" => Self::Loader,
            other => Self::Custom(other.to_string()),
        })
    }
}

// ---------------------------------------------------------------------------
// MalpediaYaraRule (detailed, download-specific)
// ---------------------------------------------------------------------------

/// A YARA rule downloaded from Malpedia.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalpediaYaraRule {
    /// Rule name identifier.
    pub name: String,
    /// Associated malware family canonical name.
    pub family: String,
    /// Target platform (win, linux, android, osx, …).
    pub platform: String,
    /// Classification tags.
    pub tags: Vec<String>,
    /// Full rule source text.
    pub source: String,
    /// Author of the rule.
    pub author: Option<String>,
    /// Rule creation date.
    pub date: Option<String>,
    /// Description from rule metadata.
    pub description: Option<String>,
    /// Reference URL.
    pub reference: Option<String>,
    /// SHA-256 of the target sample this rule was written for.
    pub sample_sha256: Option<String>,
    /// Rule version.
    pub version: Option<String>,
}

impl MalpediaYaraRule {
    /// Create a minimal YARA rule.
    #[must_use]
    pub fn new(name: impl Into<String>, family: impl Into<String>) -> Self {
        let n: String = name.into();
        let f: String = family.into();
        let source = format!(
            "rule {n} {{\n  meta:\n    family = \"{f}\"\n  strings:\n    $s0 = \"placeholder\"\n  condition:\n    any of them\n}}\n"
        );
        Self {
            name: n,
            family: f,
            platform: "win".to_string(),
            tags: Vec::new(),
            source,
            author: None,
            date: None,
            description: None,
            reference: None,
            sample_sha256: None,
            version: None,
        }
    }

    /// Return `true` if this rule's source text passes minimal validation.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.source.contains("rule ")
            && self.source.contains("condition:")
            && self.source.contains('{')
            && self.source.contains('}')
    }

    /// Return the number of string definitions.
    #[must_use]
    pub fn string_count(&self) -> usize {
        self.source
            .lines()
            .filter(|l| {
                let t = l.trim();
                t.starts_with('$') && t.contains('=')
            })
            .count()
    }
}

// ---------------------------------------------------------------------------
// YaraRuleSet — rules grouped by family
// ---------------------------------------------------------------------------

/// A set of YARA rules for a single malware family.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRuleSet {
    /// Malpedia canonical family name (e.g. `win.emotet`).
    pub family: String,
    /// Platform (e.g. `win`, `linux`).
    pub platform: String,
    /// All rules in this set.
    pub rules: Vec<MalpediaYaraRule>,
    /// Timestamp when this rule set was last fetched (Unix seconds).
    pub fetched_at: u64,
}

impl YaraRuleSet {
    /// Create an empty rule set for a family.
    #[must_use]
    pub fn new(family: impl Into<String>, platform: impl Into<String>) -> Self {
        Self {
            family: family.into(),
            platform: platform.into(),
            rules: Vec::new(),
            fetched_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Number of rules in the set.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Return all rule names.
    #[must_use]
    pub fn rule_names(&self) -> Vec<&str> {
        self.rules.iter().map(|r| r.name.as_str()).collect()
    }

    /// Concatenate all rule sources into a single YARA file.
    #[must_use]
    pub fn to_combined_source(&self) -> String {
        self.rules
            .iter()
            .map(|r| r.source.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

// ---------------------------------------------------------------------------
// FamilyProfile — extended family description
// ---------------------------------------------------------------------------

/// Extended profile for a malware family including Malpedia metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FamilyProfile {
    /// Malpedia canonical name (e.g. `win.emotet`).
    pub name: String,
    /// Common human-readable name.
    pub description: String,
    /// Alternative names / aliases.
    pub aliases: Vec<String>,
    /// Associated threat actor names.
    pub actors: Vec<String>,
    /// Malpedia URL.
    pub url: Option<String>,
    /// Target platform.
    pub platform: String,
    /// Malware type string.
    pub malware_type: String,
    /// Country of suspected origin.
    pub country: Option<String>,
    /// YARA rule count available.
    pub yara_count: usize,
    /// Sample count in Malpedia.
    pub sample_count: usize,
    /// MITRE ATT&CK technique IDs.
    pub attack_techniques: Vec<String>,
    /// Last updated timestamp.
    pub last_updated: u64,
}

impl FamilyProfile {
    /// Build a mock profile.
    #[must_use]
    pub fn mock(name: &str, description: &str, malware_type: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            aliases: Vec::new(),
            actors: Vec::new(),
            url: Some(format!(
                "https://malpedia.caad.fkie.fraunhofer.de/details/{name}"
            )),
            platform: name.split('.').next().unwrap_or("win").to_string(),
            malware_type: malware_type.to_string(),
            country: None,
            yara_count: 0,
            sample_count: 0,
            attack_techniques: Vec::new(),
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

// ---------------------------------------------------------------------------
// YaraRuleCache — TTL-backed in-memory cache
// ---------------------------------------------------------------------------

/// Entry in the YARA rule cache.
#[derive(Debug, Clone)]
struct CacheEntry {
    rule_set: YaraRuleSet,
    inserted_at: u64,
}

/// Thread-safe TTL cache for downloaded YARA rule sets.
#[derive(Debug, Clone)]
pub struct YaraRuleCache {
    entries: Arc<Mutex<HashMap<String, CacheEntry>>>,
    ttl: Duration,
}

impl YaraRuleCache {
    /// Create a cache with the given TTL.
    #[must_use]
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            ttl,
        }
    }

    /// Store a rule set in the cache.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn put(&self, key: impl Into<String>, rule_set: YaraRuleSet) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.entries.lock().unwrap().insert(
            key.into(),
            CacheEntry {
                rule_set,
                inserted_at: now,
            },
        );
    }

    /// Retrieve a rule set if it exists and has not expired.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<YaraRuleSet> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let guard = self.entries.lock().unwrap();
        guard.get(key).and_then(|e| {
            if now.saturating_sub(e.inserted_at) < self.ttl.as_secs() {
                Some(e.rule_set.clone())
            } else {
                None
            }
        })
    }

    /// Remove all expired entries.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn evict_expired(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut guard = self.entries.lock().unwrap();
        guard.retain(|_, e| now.saturating_sub(e.inserted_at) < self.ttl.as_secs());
    }

    /// Number of cached entries.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Return `true` if the cache is empty.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.lock().unwrap().is_empty()
    }

    /// Clear all cache entries.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

// ---------------------------------------------------------------------------
// MalpediaYaraDownloader
// ---------------------------------------------------------------------------

/// Client that downloads YARA rules from Malpedia with caching.
pub struct MalpediaYaraDownloader {
    api_key: Option<String>,
    base_url: String,
    cache: YaraRuleCache,
}

impl MalpediaYaraDownloader {
    /// Create a new downloader.
    #[must_use]
    pub fn new(api_key: Option<String>, cache_ttl: Duration) -> Self {
        Self {
            api_key,
            base_url: "https://malpedia.caad.fkie.fraunhofer.de".to_string(),
            cache: YaraRuleCache::new(cache_ttl),
        }
    }

    /// Override the base URL (for testing).
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Whether the downloader is authenticated.
    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        self.api_key.as_ref().is_some_and(|k| !k.is_empty())
    }

    /// Download (or return cached) YARA rules for a specific family.
    ///
    /// Returns the `YaraRuleSet` for the family.
    ///
    /// # Errors
    /// Returns an error if the family name is empty.
    pub async fn download_yara_rules(&self, family: &str) -> Result<YaraRuleSet, String> {
        if family.is_empty() {
            return Err("family name must not be empty".to_string());
        }

        // Check cache first.
        if let Some(cached) = self.cache.get(family) {
            return Ok(cached);
        }

        // A cache miss is a miss.  This type has no HTTP transport, so rules
        // for an uncached family cannot be obtained without a network lookup;
        // it used to generate placeholder rules and cache them as real ones.
        Err(format!(
            "no YARA rules cached for '{family}': downloading them requires a network \
             lookup against {}{}",
            self.base_url,
            if self.is_authenticated() {
                ""
            } else {
                " and no API key is configured"
            }
        ))
    }

    /// Download rules for multiple families.
    ///
    /// # Errors
    /// Returns combined errors as a single string.
    pub async fn download_rules_for_families(
        &self,
        families: &[&str],
    ) -> Result<Vec<YaraRuleSet>, String> {
        let mut results = Vec::new();
        let mut errors = Vec::new();
        for &family in families {
            match self.download_yara_rules(family).await {
                Ok(rs) => results.push(rs),
                Err(e) => errors.push(format!("{family}: {e}")),
            }
        }
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        Ok(results)
    }

    /// Get the family profile for a given family name.
    ///
    /// # Errors
    /// Returns an error if the family name is empty.
    pub async fn get_family_profile(&self, family: &str) -> Result<FamilyProfile, String> {
        if family.is_empty() {
            return Err("family name must not be empty".to_string());
        }
        // The profile (description, malware type, aliases) is Malpedia's data.
        // It used to be answered from a five-entry hard-coded table, and with
        // "Unknown malware family"/"trojan" for everything else - a guess
        // presented as an attribution.
        Err(format!(
            "no profile for '{family}' available offline: this requires a network lookup \
             against {}",
            self.base_url
        ))
    }

    /// Get profiles for multiple families.
    ///
    /// # Errors
    /// Returns an error if any family name is empty.
    pub async fn get_all_profiles(&self, families: &[&str]) -> Result<Vec<FamilyProfile>, String> {
        let mut out = Vec::new();
        for &f in families {
            out.push(self.get_family_profile(f).await?);
        }
        Ok(out)
    }

    /// Return the underlying cache for inspection.
    #[must_use] 
    pub const fn cache(&self) -> &YaraRuleCache {
        &self.cache
    }

    // ---- Local template builders (never presented as Malpedia data) ----

    /// Build a LOCAL placeholder rule set for a family.
    ///
    /// Its strings are `mock_string_N` and match nothing real.  Exposed so a
    /// caller that wants a scaffold must ask for it by name.
    #[must_use]
    pub fn mock_rule_set(family: &str) -> YaraRuleSet {
        let platform = family.split('.').next().unwrap_or("win").to_string();
        let mut rs = YaraRuleSet::new(family, &platform);
        let rule_count = match family {
            "win.emotet" => 3,
            "win.wannacry" => 2,
            "win.trickbot" => 4,
            _ => 1,
        };
        for i in 0..rule_count {
            let safe_family = family.replace('.', "_");
            let rule_name = format!("detect_{safe_family}_{i}");
            let mut rule = MalpediaYaraRule::new(rule_name.clone(), family);
            rule.tags = vec![platform.clone()];
            rule.author = Some("Malpedia Team".to_string());
            rule.source = format!(
                "rule {rule_name} {{\n  meta:\n    family = \"{family}\"\n    author = \"Malpedia Team\"\n  strings:\n    $s{i} = \"mock_string_{i}\"\n  condition:\n    any of them\n}}\n"
            );
            rs.rules.push(rule);
        }
        rs
    }

    /// Build a LOCAL profile record from the small built-in example table.
    ///
    /// This is example data for tests, not a Malpedia lookup.
    #[must_use]
    pub fn mock_family_profile(family: &str) -> FamilyProfile {
        let descriptions: &[(&str, &str, &str)] = &[
            ("win.emotet", "Banking trojan / loader / botnet", "trojan"),
            (
                "win.wannacry",
                "Ransomware worm exploiting EternalBlue",
                "ransomware",
            ),
            ("win.trickbot", "Modular banking trojan", "trojan"),
            (
                "win.cobalt_strike",
                "Commercial post-exploitation framework",
                "tool",
            ),
            ("win.mimikatz", "Credential dumping tool", "tool"),
        ];
        let (desc, mt) = descriptions
            .iter()
            .find(|&&(n, _, _)| n == family)
            .map_or(("Unknown malware family", "trojan"), |&(_, d, mt)| (d, mt));
        FamilyProfile::mock(family, desc, mt)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A downloader whose cache has already been filled by the caller.
    ///
    /// Tests below exercise the cache / rule-set machinery, so they supply the
    /// rules themselves instead of relying on the downloader to invent any.
    fn downloader() -> MalpediaYaraDownloader {
        let d = bare_downloader();
        for f in [
            "win.emotet",
            "win.wannacry",
            "win.trickbot",
            "win.cobalt_strike",
            "win.mimikatz",
            "linux.mirai",
        ] {
            d.cache().put(f, MalpediaYaraDownloader::mock_rule_set(f));
        }
        d
    }

    /// A downloader configured the way production configures it: empty cache.
    fn bare_downloader() -> MalpediaYaraDownloader {
        MalpediaYaraDownloader::new(Some("test-api-key".to_string()), Duration::from_secs(3600))
    }

    #[tokio::test]
    async fn test_download_without_cache_reports_network_lookup() {
        let err = bare_downloader()
            .download_yara_rules("win.emotet")
            .await
            .unwrap_err();
        assert!(err.contains("no YARA rules cached"), "{err}");
        assert!(err.contains("network"), "{err}");
    }

    #[tokio::test]
    async fn test_family_profile_is_never_guessed() {
        // Previously answered "Unknown malware family"/"trojan" for anything
        // outside a five-entry table.
        let err = bare_downloader()
            .get_family_profile("win.some_unknown_family")
            .await
            .unwrap_err();
        assert!(err.contains("network lookup"), "{err}");
        assert!(
            downloader()
                .get_family_profile("win.emotet")
                .await
                .is_err()
        );
    }

    // ---- YaraRuleTag ----

    #[test]
    fn test_yara_tag_as_str() {
        assert_eq!(YaraRuleTag::Ransomware.as_str(), "ransomware");
        assert_eq!(YaraRuleTag::Trojan.as_str(), "trojan");
        assert_eq!(YaraRuleTag::Custom("x".to_string()).as_str(), "x");
    }

    #[test]
    fn test_yara_tag_from_str_known() {
        use std::str::FromStr;
        assert_eq!(YaraRuleTag::from_str("ransomware").unwrap(), YaraRuleTag::Ransomware);
        assert_eq!(YaraRuleTag::from_str("TROJAN").unwrap(), YaraRuleTag::Trojan);
        assert_eq!(YaraRuleTag::from_str("miner").unwrap(), YaraRuleTag::Cryptominer);
    }

    #[test]
    fn test_yara_tag_from_str_unknown() {
        use std::str::FromStr;
        assert_eq!(
            YaraRuleTag::from_str("spaceship").unwrap(),
            YaraRuleTag::Custom("spaceship".to_string())
        );
    }

    // ---- MalpediaYaraRule ----

    #[test]
    fn test_rule_new() {
        let r = MalpediaYaraRule::new("detect_emotet", "win.emotet");
        assert_eq!(r.family, "win.emotet");
        assert!(r.is_valid());
    }

    #[test]
    fn test_rule_string_count() {
        let r = MalpediaYaraRule::new("r", "f");
        assert!(r.string_count() >= 1);
    }

    #[test]
    fn test_rule_is_valid_bad_source() {
        let mut r = MalpediaYaraRule::new("r", "f");
        r.source = "not a valid rule".to_string();
        assert!(!r.is_valid());
    }

    // ---- YaraRuleSet ----

    #[test]
    fn test_rule_set_new() {
        let rs = YaraRuleSet::new("win.emotet", "win");
        assert_eq!(rs.family, "win.emotet");
        assert_eq!(rs.rule_count(), 0);
    }

    #[test]
    fn test_rule_set_combined_source() {
        let mut rs = YaraRuleSet::new("win.test", "win");
        rs.rules.push(MalpediaYaraRule::new("rule_a", "win.test"));
        rs.rules.push(MalpediaYaraRule::new("rule_b", "win.test"));
        let combined = rs.to_combined_source();
        assert!(combined.contains("rule_a"));
        assert!(combined.contains("rule_b"));
    }

    #[test]
    fn test_rule_set_rule_names() {
        let mut rs = YaraRuleSet::new("win.test", "win");
        rs.rules.push(MalpediaYaraRule::new("my_rule", "win.test"));
        assert!(rs.rule_names().contains(&"my_rule"));
    }

    // ---- FamilyProfile ----

    #[test]
    fn test_family_profile_mock() {
        let p = FamilyProfile::mock("win.emotet", "Banking trojan", "trojan");
        assert_eq!(p.name, "win.emotet");
        assert_eq!(p.malware_type, "trojan");
        assert!(p.url.is_some());
    }

    #[test]
    fn test_family_profile_platform_from_name() {
        let p = FamilyProfile::mock("linux.mirai", "IoT botnet", "botnet");
        assert_eq!(p.platform, "linux");
    }

    // ---- YaraRuleCache ----

    #[test]
    fn test_cache_put_and_get() {
        let cache = YaraRuleCache::new(Duration::from_secs(3600));
        let rs = YaraRuleSet::new("win.emotet", "win");
        cache.put("win.emotet", rs);
        let got = cache.get("win.emotet");
        assert!(got.is_some());
        assert_eq!(got.unwrap().family, "win.emotet");
    }

    #[test]
    fn test_cache_miss() {
        let cache = YaraRuleCache::new(Duration::from_secs(3600));
        assert!(cache.get("win.nonexistent").is_none());
    }

    #[test]
    fn test_cache_expired() {
        let cache = YaraRuleCache::new(Duration::from_secs(0));
        let rs = YaraRuleSet::new("win.test", "win");
        cache.put("win.test", rs);
        // TTL is 0 seconds — everything is immediately expired.
        assert!(cache.get("win.test").is_none());
    }

    #[test]
    fn test_cache_len() {
        let cache = YaraRuleCache::new(Duration::from_secs(3600));
        cache.put("win.a", YaraRuleSet::new("win.a", "win"));
        cache.put("win.b", YaraRuleSet::new("win.b", "win"));
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_cache_clear() {
        let cache = YaraRuleCache::new(Duration::from_secs(3600));
        cache.put("win.a", YaraRuleSet::new("win.a", "win"));
        cache.clear();
        assert!(cache.is_empty());
    }

    // ---- MalpediaYaraDownloader ----

    #[test]
    fn test_downloader_is_authenticated() {
        assert!(downloader().is_authenticated());
        let anon = MalpediaYaraDownloader::new(None, Duration::from_secs(3600));
        assert!(!anon.is_authenticated());
    }

    #[tokio::test]
    async fn test_download_yara_rules_emotet() {
        let rs = downloader()
            .download_yara_rules("win.emotet")
            .await
            .unwrap();
        assert_eq!(rs.family, "win.emotet");
        assert!(rs.rule_count() > 0);
    }

    #[tokio::test]
    async fn test_download_yara_rules_uses_cache() {
        let dl = downloader();
        let _ = dl.download_yara_rules("win.wannacry").await.unwrap();
        // Second call should hit cache.
        let _ = dl.download_yara_rules("win.wannacry").await.unwrap();
        assert_eq!(dl.cache().len(), 1);
    }

    #[tokio::test]
    async fn test_download_yara_rules_empty_family_err() {
        let result = downloader().download_yara_rules("").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_download_rules_for_families() {
        let families = ["win.emotet", "win.wannacry", "win.trickbot"];
        let results = downloader()
            .download_rules_for_families(&families)
            .await
            .unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn test_get_family_profile() {
        let p = MalpediaYaraDownloader::mock_family_profile("win.emotet");
        assert_eq!(p.name, "win.emotet");
        assert!(!p.description.is_empty());
    }

    #[tokio::test]
    async fn test_get_family_profile_empty_err() {
        let result = downloader().get_family_profile("").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_get_all_profiles() {
        let fams = ["win.emotet", "win.wannacry"];
        let profiles: Vec<_> = fams
            .iter()
            .map(|f| MalpediaYaraDownloader::mock_family_profile(f))
            .collect();
        assert_eq!(profiles.len(), 2);
    }

    #[tokio::test]
    async fn test_rules_all_valid() {
        let rs = downloader()
            .download_yara_rules("win.trickbot")
            .await
            .unwrap();
        for rule in &rs.rules {
            assert!(rule.is_valid(), "Rule {} should be valid", rule.name);
        }
    }

    // ---- FamilyProfile serde ----

    #[test]
    fn test_family_profile_serde() {
        let p = FamilyProfile::mock("win.emotet", "Banking trojan", "trojan");
        let json = serde_json::to_string(&p).unwrap();
        let p2: FamilyProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p2.name, "win.emotet");
        assert_eq!(p2.malware_type, "trojan");
    }

    // ---- YaraRuleSet serde ----

    #[test]
    fn test_yara_rule_set_serde() {
        let mut rs = YaraRuleSet::new("win.trickbot", "win");
        rs.rules
            .push(MalpediaYaraRule::new("detect_trickbot_0", "win.trickbot"));
        let json = serde_json::to_string(&rs).unwrap();
        let rs2: YaraRuleSet = serde_json::from_str(&json).unwrap();
        assert_eq!(rs2.rule_count(), 1);
    }

    // ---- MalpediaYaraRule serde ----

    #[test]
    fn test_yara_rule_serde() {
        let r = MalpediaYaraRule::new("detect_emotet_0", "win.emotet");
        let json = serde_json::to_string(&r).unwrap();
        let r2: MalpediaYaraRule = serde_json::from_str(&json).unwrap();
        assert_eq!(r2.name, "detect_emotet_0");
        assert_eq!(r2.family, "win.emotet");
    }

    // ---- Download caches per family independently ----

    #[tokio::test]
    async fn test_download_multiple_families_cached_independently() {
        let dl = downloader();
        let _ = dl.download_yara_rules("win.emotet").await.unwrap();
        let _ = dl.download_yara_rules("win.wannacry").await.unwrap();
        let _ = dl.download_yara_rules("win.trickbot").await.unwrap();
        assert_eq!(dl.cache().len(), 3);
    }

    // ---- Rule author / date fields ----

    #[tokio::test]
    async fn test_rule_has_author() {
        let rs = downloader()
            .download_yara_rules("win.emotet")
            .await
            .unwrap();
        for rule in &rs.rules {
            assert!(
                rule.author.is_some(),
                "rule {} should have author",
                rule.name
            );
        }
    }

    // ---- Combined source contains all rule names ----

    #[tokio::test]
    async fn test_combined_source_contains_all_rules() {
        let rs = downloader()
            .download_yara_rules("win.trickbot")
            .await
            .unwrap();
        let combined = rs.to_combined_source();
        for rule in &rs.rules {
            assert!(
                combined.contains(&rule.name),
                "combined should contain {}",
                rule.name
            );
        }
    }

    // ---- Platform derived from family name ----

    #[tokio::test]
    async fn test_linux_family_platform() {
        let rs = downloader()
            .download_yara_rules("linux.mirai")
            .await
            .unwrap();
        assert_eq!(rs.platform, "linux");
    }

    // ---- Cache eviction on zero TTL ----

    #[test]
    fn test_cache_evict_expired_removes_all_on_zero_ttl() {
        let cache = YaraRuleCache::new(Duration::from_secs(0));
        cache.put("win.a", YaraRuleSet::new("win.a", "win"));
        cache.put("win.b", YaraRuleSet::new("win.b", "win"));
        cache.evict_expired();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_evict_expired_keeps_fresh() {
        let cache = YaraRuleCache::new(Duration::from_secs(3600));
        cache.put("win.a", YaraRuleSet::new("win.a", "win"));
        cache.evict_expired();
        assert_eq!(cache.len(), 1);
    }

    // ---- download_rules_for_families with empty list ----

    #[tokio::test]
    async fn test_download_rules_empty_families_list() {
        let result = downloader().download_rules_for_families(&[]).await.unwrap();
        assert!(result.is_empty());
    }

    // ---- YaraRuleTag serde ----

    #[test]
    fn test_yara_tag_serde() {
        let tag = YaraRuleTag::Ransomware;
        let json = serde_json::to_string(&tag).unwrap();
        let tag2: YaraRuleTag = serde_json::from_str(&json).unwrap();
        assert_eq!(tag2, YaraRuleTag::Ransomware);
    }

    // ---- FamilyProfile actors and techniques ----

    #[test]
    fn test_family_profile_actors_empty_by_default() {
        let p = FamilyProfile::mock("win.test", "Test family", "trojan");
        assert!(p.actors.is_empty());
        assert!(p.attack_techniques.is_empty());
    }

    // ---- downloader base_url override ----

    #[test]
    fn test_downloader_with_base_url() {
        let dl = MalpediaYaraDownloader::new(None, Duration::from_secs(60))
            .with_base_url("http://localhost:9999");
        assert_eq!(dl.base_url, "http://localhost:9999");
    }

    // ---- YaraRuleSet fetched_at timestamp is recent ----

    #[tokio::test]
    async fn test_rule_set_fetched_at_recent() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let rs = downloader()
            .download_yara_rules("win.emotet")
            .await
            .unwrap();
        // fetched_at should be within the last 5 seconds.
        assert!(rs.fetched_at >= now.saturating_sub(5));
    }

    // ---- rule source contains family name ----

    #[tokio::test]
    async fn test_rule_source_contains_family() {
        let rs = downloader()
            .download_yara_rules("win.emotet")
            .await
            .unwrap();
        for rule in &rs.rules {
            assert!(
                rule.source.contains("win.emotet"),
                "rule source should mention family, got: {}",
                rule.source
            );
        }
    }

    // ---- download emotet has 3 rules ----

    #[tokio::test]
    async fn test_emotet_rule_count_3() {
        let rs = downloader()
            .download_yara_rules("win.emotet")
            .await
            .unwrap();
        assert_eq!(rs.rule_count(), 3);
    }

    // ---- download wannacry has 2 rules ----

    #[tokio::test]
    async fn test_wannacry_rule_count_2() {
        let rs = downloader()
            .download_yara_rules("win.wannacry")
            .await
            .unwrap();
        assert_eq!(rs.rule_count(), 2);
    }

    // ---- download trickbot has 4 rules ----

    #[tokio::test]
    async fn test_trickbot_rule_count_4() {
        let rs = downloader()
            .download_yara_rules("win.trickbot")
            .await
            .unwrap();
        assert_eq!(rs.rule_count(), 4);
    }

    // ---- rule_names non-empty ----

    #[tokio::test]
    async fn test_rule_names_non_empty() {
        let rs = downloader()
            .download_yara_rules("win.emotet")
            .await
            .unwrap();
        let names = rs.rule_names();
        assert!(!names.is_empty());
        // All names should be non-empty strings.
        assert!(names.iter().all(|n| !n.is_empty()));
    }

    // ---- YaraRuleSet platform field ----

    #[tokio::test]
    async fn test_rule_set_platform_win() {
        let rs = downloader()
            .download_yara_rules("win.cobalt_strike")
            .await
            .unwrap();
        assert_eq!(rs.platform, "win");
    }

    // ---- get_all_profiles returns all profiles ----

    #[tokio::test]
    async fn test_get_all_profiles_count() {
        let fams = [
            "win.emotet",
            "win.trickbot",
            "win.wannacry",
            "win.cobalt_strike",
        ];
        let profiles = downloader().get_all_profiles(&fams).await.unwrap();
        assert_eq!(profiles.len(), 4);
    }

    // ---- profile for cobalt_strike ----

    #[tokio::test]
    async fn test_cobalt_strike_profile() {
        let p = downloader()
            .get_family_profile("win.cobalt_strike")
            .await
            .unwrap();
        assert_eq!(p.name, "win.cobalt_strike");
        assert!(!p.description.is_empty());
        assert_eq!(p.malware_type, "tool");
    }

    // ---- MalpediaYaraRule tags field ----

    #[tokio::test]
    async fn test_rule_tags_contain_platform() {
        let rs = downloader()
            .download_yara_rules("win.emotet")
            .await
            .unwrap();
        for rule in &rs.rules {
            assert!(rule.tags.contains(&"win".to_string()));
        }
    }

    // ---- FamilyProfile last_updated is set ----

    #[tokio::test]
    async fn test_profile_last_updated_set() {
        let p = downloader()
            .get_family_profile("win.wannacry")
            .await
            .unwrap();
        assert!(p.last_updated > 0);
    }
}

// ---------------------------------------------------------------------------
// YaraRuleValidator — static analysis checks on YARA rule text
// ---------------------------------------------------------------------------

/// Severity level for a YARA validation finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationSeverity {
    Error,
    Warning,
    Info,
}

impl std::fmt::Display for ValidationSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error => write!(f, "ERROR"),
            Self::Warning => write!(f, "WARNING"),
            Self::Info => write!(f, "INFO"),
        }
    }
}

/// A single validation finding on a YARA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationFinding {
    /// Severity.
    pub severity: ValidationSeverity,
    /// Short code identifying the check.
    pub code: String,
    /// Human-readable message.
    pub message: String,
    /// Source line number if available.
    pub line: Option<usize>,
}

impl ValidationFinding {
    fn error(code: &str, msg: impl Into<String>) -> Self {
        Self {
            severity: ValidationSeverity::Error,
            code: code.to_string(),
            message: msg.into(),
            line: None,
        }
    }

    fn warning(code: &str, msg: impl Into<String>) -> Self {
        Self {
            severity: ValidationSeverity::Warning,
            code: code.to_string(),
            message: msg.into(),
            line: None,
        }
    }

    fn info(code: &str, msg: impl Into<String>) -> Self {
        Self {
            severity: ValidationSeverity::Info,
            code: code.to_string(),
            message: msg.into(),
            line: None,
        }
    }
}

/// Result of validating a YARA rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub rule_name: String,
    pub is_valid: bool,
    pub findings: Vec<ValidationFinding>,
}

impl ValidationResult {
    /// Return `true` if there are no error-level findings.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == ValidationSeverity::Error)
    }

    /// Return only error-level findings.
    #[must_use]
    pub fn errors(&self) -> Vec<&ValidationFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity == ValidationSeverity::Error)
            .collect()
    }

    /// Return only warning-level findings.
    #[must_use]
    pub fn warnings(&self) -> Vec<&ValidationFinding> {
        self.findings
            .iter()
            .filter(|f| f.severity == ValidationSeverity::Warning)
            .collect()
    }
}

/// Static YARA rule validator with multiple checks.
pub struct YaraRuleValidator;

impl YaraRuleValidator {
    /// Validate a `MalpediaYaraRule`, returning a `ValidationResult`.
    #[must_use]
    pub fn validate(rule: &MalpediaYaraRule) -> ValidationResult {
        let mut findings = Vec::new();
        let src = &rule.source;

        // E001: rule keyword present.
        if !src.contains("rule ") {
            findings.push(ValidationFinding::error("E001", "missing 'rule' keyword"));
        }

        // E002: balanced braces.
        let opens = src.chars().filter(|&c| c == '{').count();
        let closes = src.chars().filter(|&c| c == '}').count();
        if opens != closes {
            findings.push(ValidationFinding::error(
                "E002",
                format!("unbalanced braces: {opens} open, {closes} close"),
            ));
        }

        // E003: condition section.
        if !src.contains("condition:") {
            findings.push(ValidationFinding::error(
                "E003",
                "missing 'condition:' section",
            ));
        }

        // W001: no strings section.
        if !src.contains("strings:") {
            findings.push(ValidationFinding::warning(
                "W001",
                "no 'strings:' section — condition must not reference $variables",
            ));
        }

        // W002: empty rule name.
        if rule.name.is_empty() {
            findings.push(ValidationFinding::error("E004", "rule name is empty"));
        }

        // W003: rule name contains spaces.
        if rule.name.contains(' ') {
            findings.push(ValidationFinding::warning(
                "W003",
                "rule name contains spaces — may cause issues with some YARA parsers",
            ));
        }

        // I001: meta author present.
        if rule.author.is_none() {
            findings.push(ValidationFinding::info(
                "I001",
                "no author specified in metadata",
            ));
        }

        // I002: meta date present.
        if rule.date.is_none() {
            findings.push(ValidationFinding::info(
                "I002",
                "no date specified in metadata",
            ));
        }

        // I003: family set.
        if rule.family.is_empty() {
            findings.push(ValidationFinding::warning("W004", "family field is empty"));
        }

        let is_valid = !findings
            .iter()
            .any(|f| f.severity == ValidationSeverity::Error);

        ValidationResult {
            rule_name: rule.name.clone(),
            is_valid,
            findings,
        }
    }

    /// Validate all rules in a `YaraRuleSet`.
    #[must_use]
    pub fn validate_set(rule_set: &YaraRuleSet) -> Vec<ValidationResult> {
        rule_set.rules.iter().map(Self::validate).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests for YaraRuleValidator
// ---------------------------------------------------------------------------

#[cfg(test)]
mod validator_tests {
    use super::*;

    fn valid_rule() -> MalpediaYaraRule {
        let mut r = MalpediaYaraRule::new("detect_emotet_valid", "win.emotet");
        r.author = Some("analyst".to_string());
        r.date = Some("2024-01-01".to_string());
        r
    }

    #[test]
    fn test_validator_valid_rule() {
        let result = YaraRuleValidator::validate(&valid_rule());
        assert!(result.is_valid);
        assert!(!result.has_errors());
    }

    #[test]
    fn test_validator_missing_condition() {
        let mut r = valid_rule();
        r.source = "rule detect_x { strings: $s = \"x\" }".to_string();
        let result = YaraRuleValidator::validate(&r);
        assert!(!result.is_valid);
        assert!(result.errors().iter().any(|f| f.code == "E003"));
    }

    #[test]
    fn test_validator_missing_rule_keyword() {
        let mut r = valid_rule();
        r.source = "{ condition: true }".to_string();
        let result = YaraRuleValidator::validate(&r);
        assert!(!result.is_valid);
        assert!(result.errors().iter().any(|f| f.code == "E001"));
    }

    #[test]
    fn test_validator_unbalanced_braces() {
        let mut r = valid_rule();
        r.source = "rule bad { condition: true".to_string();
        let result = YaraRuleValidator::validate(&r);
        assert!(!result.is_valid);
        assert!(result.errors().iter().any(|f| f.code == "E002"));
    }

    #[test]
    fn test_validator_no_strings_warning() {
        let mut r = valid_rule();
        // Has condition but no strings section.
        r.source = "rule no_strings { condition: true }".to_string();
        let result = YaraRuleValidator::validate(&r);
        // Should be valid (no error), but has a warning.
        assert!(result.is_valid);
        assert!(result.warnings().iter().any(|f| f.code == "W001"));
    }

    #[test]
    fn test_validator_no_author_info() {
        let mut r = valid_rule();
        r.author = None;
        let result = YaraRuleValidator::validate(&r);
        assert!(result.findings.iter().any(|f| f.code == "I001"));
    }

    #[test]
    fn test_validator_validate_set() {
        let mut rs = YaraRuleSet::new("win.emotet", "win");
        rs.rules.push(valid_rule());
        rs.rules.push(valid_rule());
        let results = YaraRuleValidator::validate_set(&rs);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_valid));
    }

    #[test]
    fn test_validation_finding_serde() {
        let f = ValidationFinding::error("E001", "test error");
        let json = serde_json::to_string(&f).unwrap();
        let f2: ValidationFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(f2.severity, ValidationSeverity::Error);
        assert_eq!(f2.code, "E001");
    }

    #[test]
    fn test_validation_severity_display() {
        assert_eq!(ValidationSeverity::Error.to_string(), "ERROR");
        assert_eq!(ValidationSeverity::Warning.to_string(), "WARNING");
        assert_eq!(ValidationSeverity::Info.to_string(), "INFO");
    }

    #[test]
    fn test_validation_result_warnings_only() {
        let mut r = valid_rule();
        r.source = "rule only_condition { condition: true }".to_string();
        let result = YaraRuleValidator::validate(&r);
        // Warnings but no errors.
        assert!(result.is_valid);
        assert!(!result.warnings().is_empty());
        assert!(result.errors().is_empty());
    }
}
