//! `yara_integration` — High-level YARA integration: rule loading, scan
//! targeting, result types, and caching.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// YaraRule (integration-level, not the parser-level struct)
// ---------------------------------------------------------------------------

/// A compiled YARA rule ready for scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraRule {
    pub name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
    /// Pattern strings: `(identifier, bytes)`.
    pub patterns: Vec<(String, Vec<u8>)>,
    /// Minimum number of patterns that must match.
    pub min_matches: usize,
    pub is_private: bool,
    pub is_global: bool,
}

impl YaraRule {
    /// Create a minimal rule.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            namespace: "default".to_string(),
            tags: Vec::new(),
            meta: HashMap::new(),
            patterns: Vec::new(),
            min_matches: 1,
            is_private: false,
            is_global: false,
        }
    }

    /// Add a text pattern.
    pub fn add_text_pattern(&mut self, id: impl Into<String>, text: impl Into<String>) {
        self.patterns.push((id.into(), text.into().into_bytes()));
    }

    /// Add a hex pattern.
    pub fn add_hex_pattern(&mut self, id: impl Into<String>, bytes: Vec<u8>) {
        self.patterns.push((id.into(), bytes));
    }

    /// Add metadata.
    pub fn add_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.meta.insert(key.into(), value.into());
    }

    /// Returns `true` if the rule should fire for `data`.
    #[must_use]
    pub fn evaluate(&self, data: &[u8]) -> bool {
        if self.patterns.is_empty() {
            return true;
        }
        let matched = self
            .patterns
            .iter()
            .filter(|(_, pat)| {
                !pat.is_empty() && data.windows(pat.len()).any(|w| w == pat.as_slice())
            })
            .count();
        matched >= self.min_matches
    }
}

impl fmt::Display for YaraRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rule {}:{} [{} patterns]",
            self.namespace,
            self.name,
            self.patterns.len()
        )
    }
}

// ---------------------------------------------------------------------------
// YaraMatch
// ---------------------------------------------------------------------------

/// A string match within a scan result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraStringMatch {
    pub identifier: String,
    pub offset: u64,
    pub length: usize,
    pub data: Vec<u8>,
}

/// Full match result for a rule firing against a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    pub rule_name: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub meta: HashMap<String, String>,
    pub string_matches: Vec<YaraStringMatch>,
    pub scan_time_us: u64,
}

impl YaraMatch {
    /// Severity from meta (default "unknown").
    #[must_use]
    pub fn severity(&self) -> &str {
        self.meta
            .get("severity")
            .map_or("unknown", String::as_str)
    }

    /// Whether this match is considered critical.
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.severity() == "critical"
    }
}

impl fmt::Display for YaraMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MATCH {}:{} ({} strings matched)",
            self.namespace,
            self.rule_name,
            self.string_matches.len()
        )
    }
}

// ---------------------------------------------------------------------------
// YaraScanTarget
// ---------------------------------------------------------------------------

/// The kind of data being scanned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanTargetKind {
    File,
    MemoryRegion,
    NetworkPacket,
    ProcessMemory,
    Archive,
    Stream,
}

/// A scan target: raw bytes with metadata.
#[derive(Debug, Clone)]
pub struct YaraScanTarget {
    pub kind: ScanTargetKind,
    pub name: String,
    pub data: Vec<u8>,
    pub base_address: u64,
    pub tags: Vec<String>,
}

impl YaraScanTarget {
    /// Create a file scan target.
    #[must_use]
    pub fn file(name: impl Into<String>, data: Vec<u8>) -> Self {
        Self {
            kind: ScanTargetKind::File,
            name: name.into(),
            data,
            base_address: 0,
            tags: Vec::new(),
        }
    }

    /// Create a memory region scan target.
    #[must_use]
    pub fn memory(name: impl Into<String>, data: Vec<u8>, base: u64) -> Self {
        Self {
            kind: ScanTargetKind::MemoryRegion,
            name: name.into(),
            data,
            base_address: base,
            tags: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// YaraResult
// ---------------------------------------------------------------------------

/// The result of scanning a single target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraResult {
    pub target_name: String,
    pub target_kind: ScanTargetKind,
    pub matches: Vec<YaraMatch>,
    pub rules_evaluated: usize,
    pub scan_duration_ms: u64,
    pub errors: Vec<String>,
}

impl YaraResult {
    /// Whether any rule fired.
    #[must_use]
    pub const fn has_matches(&self) -> bool {
        !self.matches.is_empty()
    }

    /// Whether any critical match was found.
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.matches.iter().any(YaraMatch::is_critical)
    }

    /// All rule names that fired.
    #[must_use]
    pub fn matched_rule_names(&self) -> Vec<&str> {
        self.matches.iter().map(|m| m.rule_name.as_str()).collect()
    }
}

impl fmt::Display for YaraResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "YaraResult[{}] {} matches / {} rules in {}ms",
            self.target_name,
            self.matches.len(),
            self.rules_evaluated,
            self.scan_duration_ms
        )
    }
}

// ---------------------------------------------------------------------------
// YaraCache
// ---------------------------------------------------------------------------

/// Cache entry.
#[derive(Debug, Clone)]
struct CacheEntry {
    result: YaraResult,
    inserted_at: Instant,
    hits: u64,
}

/// A time-bounded LRU-like cache for YARA scan results.
pub struct YaraCache {
    entries: Arc<Mutex<HashMap<String, CacheEntry>>>,
    ttl: Duration,
    max_entries: usize,
}

impl YaraCache {
    /// Create a cache with the given TTL and capacity.
    #[must_use]
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            ttl,
            max_entries,
        }
    }

    /// Look up a result by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<YaraResult> {
        let mut entries = self.entries.lock().ok()?;
        let entry = entries.get_mut(key)?;
        if entry.inserted_at.elapsed() > self.ttl {
            entries.remove(key);
            drop(entries);
            return None;
        }
        entry.hits += 1;
        let result = entry.result.clone();
        drop(entries);
        Some(result)
    }

    /// Insert a result under the given key.
    pub fn insert(&self, key: impl Into<String>, result: YaraResult) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        let key = key.into();

        // Evict oldest if at capacity
        if entries.len() >= self.max_entries && !entries.contains_key(&key) {
            // `entries` is a HashMap and `inserted_at` ties easily, so without a
            // tie-break on the key the evicted rule-cache entry differs between
            // runs on identical input.
            let oldest = entries
                .iter()
                .min_by(|a, b| a.1.inserted_at.cmp(&b.1.inserted_at).then(a.0.cmp(b.0)))
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                entries.remove(&k);
            }
        }

        entries.insert(
            key,
            CacheEntry {
                result,
                inserted_at: Instant::now(),
                hits: 0,
            },
        );
    }

    /// Evict all expired entries and return the count removed.
    #[must_use] 
    pub fn evict_expired(&self) -> usize {
        let Ok(mut entries) = self.entries.lock() else {
            return 0;
        };
        let before = entries.len();
        let ttl = self.ttl;
        entries.retain(|_, e| e.inserted_at.elapsed() <= ttl);
        before - entries.len()
    }

    /// Current number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().map_or(0, |e| e.len())
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl fmt::Debug for YaraCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "YaraCache({} entries, ttl={:?})", self.len(), self.ttl)
    }
}

// ---------------------------------------------------------------------------
// YaraIntegration — the main facade
// ---------------------------------------------------------------------------

/// High-level YARA integration engine.
pub struct YaraIntegration {
    rules: Vec<YaraRule>,
    cache: Option<YaraCache>,
}

impl YaraIntegration {
    /// Create an empty integration engine.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rules: Vec::new(),
            cache: None,
        }
    }

    /// Create with built-in rules.
    #[must_use]
    pub fn with_builtins() -> Self {
        let mut yi = Self::new();
        yi.load_builtin_rules();
        yi
    }

    /// Enable caching with the given TTL and max entries.
    #[must_use] 
    pub fn with_cache(mut self, ttl: Duration, max_entries: usize) -> Self {
        self.cache = Some(YaraCache::new(ttl, max_entries));
        self
    }

    /// Add a rule.
    pub fn add_rule(&mut self, rule: YaraRule) {
        self.rules.push(rule);
    }

    /// Number of loaded rules.
    #[must_use]
    pub const fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Scan a target.
    #[must_use]
    pub fn scan(&self, target: &YaraScanTarget) -> YaraResult {
        // Cache lookup
        if let Some(cache) = &self.cache {
            let key = format!("{:?}:{}", target.kind, target.name);
            if let Some(cached) = cache.get(&key) {
                return cached;
            }
        }

        let t0 = Instant::now();
        let mut matches = Vec::new();

        for rule in &self.rules {
            if rule.is_private {
                continue;
            }
            let rule_t0 = Instant::now();
            if rule.evaluate(&target.data) {
                let string_matches: Vec<YaraStringMatch> = rule
                    .patterns
                    .iter()
                    .filter_map(|(id, pat)| {
                        if pat.is_empty() {
                            return None;
                        }
                        let offset = target
                            .data
                            .windows(pat.len())
                            .position(|w| w == pat.as_slice())?
                            as u64;
                        Some(YaraStringMatch {
                            identifier: id.clone(),
                            offset: target.base_address + offset,
                            length: pat.len(),
                            data: target.data[usize::try_from(offset).unwrap_or(usize::MAX)..usize::try_from(offset).unwrap_or(usize::MAX) + pat.len()]
                                .to_vec(),
                        })
                    })
                    .collect();

                matches.push(YaraMatch {
                    rule_name: rule.name.clone(),
                    namespace: rule.namespace.clone(),
                    tags: rule.tags.clone(),
                    meta: rule.meta.clone(),
                    string_matches,
                    scan_time_us: u64::try_from(rule_t0.elapsed().as_micros()).unwrap_or(u64::MAX),
                });
            }
        }

        let result = YaraResult {
            target_name: target.name.clone(),
            target_kind: target.kind.clone(),
            matches,
            rules_evaluated: self.rules.len(),
            scan_duration_ms: u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
            errors: Vec::new(),
        };

        if let Some(cache) = &self.cache {
            let key = format!("{:?}:{}", target.kind, target.name);
            cache.insert(key, result.clone());
        }

        result
    }

    fn load_builtin_rules(&mut self) {
        let mut r = YaraRule::new("UPX_Packer");
        r.add_text_pattern("$s0", "UPX0");
        r.add_text_pattern("$s1", "UPX1");
        r.min_matches = 1;
        r.meta.insert("severity".to_string(), "medium".to_string());
        r.tags.push("packer".to_string());
        self.add_rule(r);

        let mut r = YaraRule::new("Mimikatz");
        r.add_text_pattern("$s0", "mimikatz");
        r.add_text_pattern("$s1", "sekurlsa");
        r.min_matches = 1;
        r.meta
            .insert("severity".to_string(), "critical".to_string());
        r.tags.push("credential-theft".to_string());
        self.add_rule(r);

        let mut r = YaraRule::new("Meterpreter");
        r.add_text_pattern("$s0", "meterpreter");
        r.min_matches = 1;
        r.meta
            .insert("severity".to_string(), "critical".to_string());
        r.tags.push("rat".to_string());
        self.add_rule(r);

        let mut r = YaraRule::new("ProcessInjection");
        r.add_text_pattern("$va", "VirtualAllocEx");
        r.add_text_pattern("$wpm", "WriteProcessMemory");
        r.add_text_pattern("$crt", "CreateRemoteThread");
        r.min_matches = 2;
        r.meta.insert("severity".to_string(), "high".to_string());
        r.tags.push("injection".to_string());
        self.add_rule(r);

        let mut r = YaraRule::new("AntiDebug");
        r.add_text_pattern("$s0", "IsDebuggerPresent");
        r.min_matches = 1;
        r.meta.insert("severity".to_string(), "medium".to_string());
        self.add_rule(r);
    }
}

impl Default for YaraIntegration {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for YaraIntegration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "YaraIntegration({} rules)", self.rules.len())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_target(data: &[u8]) -> YaraScanTarget {
        YaraScanTarget::file("test.bin", data.to_vec())
    }

    #[test]
    fn test_yara_rule_new() {
        let r = YaraRule::new("TestRule");
        assert_eq!(r.name, "TestRule");
        assert!(r.patterns.is_empty());
    }

    #[test]
    fn test_yara_rule_evaluate_no_patterns() {
        let r = YaraRule::new("Empty");
        assert!(r.evaluate(b"anything"));
    }

    #[test]
    fn test_yara_rule_evaluate_match() {
        let mut r = YaraRule::new("Test");
        r.add_text_pattern("$s0", "sekurlsa");
        assert!(r.evaluate(b"sekurlsa embedded string"));
    }

    #[test]
    fn test_yara_rule_evaluate_no_match() {
        let mut r = YaraRule::new("Test");
        r.add_text_pattern("$s0", "notpresent");
        assert!(!r.evaluate(b"other data here"));
    }

    #[test]
    fn test_yara_rule_min_matches_two() {
        let mut r = YaraRule::new("Test");
        r.add_text_pattern("$a", "abc");
        r.add_text_pattern("$b", "def");
        r.min_matches = 2;
        assert!(r.evaluate(b"abcdef"));
        assert!(!r.evaluate(b"abc only"));
    }

    #[test]
    fn test_yara_rule_display() {
        let r = YaraRule::new("TestRule");
        let s = r.to_string();
        assert!(s.contains("TestRule"));
    }

    #[test]
    fn test_yara_rule_add_meta() {
        let mut r = YaraRule::new("R");
        r.add_meta("severity", "high");
        assert_eq!(r.meta["severity"], "high");
    }

    #[test]
    fn test_yara_scan_target_file() {
        let t = YaraScanTarget::file("foo.exe", vec![0x4D, 0x5A]);
        assert_eq!(t.kind, ScanTargetKind::File);
        assert_eq!(t.name, "foo.exe");
    }

    #[test]
    fn test_yara_scan_target_memory() {
        let t = YaraScanTarget::memory("region1", vec![0; 64], 0x140000000);
        assert_eq!(t.kind, ScanTargetKind::MemoryRegion);
        assert_eq!(t.base_address, 0x140000000);
    }

    #[test]
    fn test_yara_match_severity() {
        let mut meta = HashMap::new();
        meta.insert("severity".to_string(), "critical".to_string());
        let m = YaraMatch {
            rule_name: "R".to_string(),
            namespace: "n".to_string(),
            tags: vec![],
            meta,
            string_matches: vec![],
            scan_time_us: 0,
        };
        assert_eq!(m.severity(), "critical");
        assert!(m.is_critical());
    }

    #[test]
    fn test_yara_match_display() {
        let m = YaraMatch {
            rule_name: "UPX".to_string(),
            namespace: "default".to_string(),
            tags: vec![],
            meta: HashMap::new(),
            string_matches: vec![],
            scan_time_us: 0,
        };
        let s = m.to_string();
        assert!(s.contains("UPX"));
    }

    #[test]
    fn test_yara_result_has_matches() {
        let r = YaraResult {
            target_name: "t".to_string(),
            target_kind: ScanTargetKind::File,
            matches: vec![YaraMatch {
                rule_name: "R".to_string(),
                namespace: "n".to_string(),
                tags: vec![],
                meta: HashMap::new(),
                string_matches: vec![],
                scan_time_us: 0,
            }],
            rules_evaluated: 1,
            scan_duration_ms: 0,
            errors: vec![],
        };
        assert!(r.has_matches());
        assert!(!r.has_critical());
    }

    #[test]
    fn test_yara_result_display() {
        let r = YaraResult {
            target_name: "test.bin".to_string(),
            target_kind: ScanTargetKind::File,
            matches: vec![],
            rules_evaluated: 5,
            scan_duration_ms: 10,
            errors: vec![],
        };
        let s = r.to_string();
        assert!(s.contains("test.bin"));
    }

    #[test]
    fn test_yara_cache_insert_get() {
        let cache = YaraCache::new(Duration::from_secs(60), 10);
        let r = YaraResult {
            target_name: "t".to_string(),
            target_kind: ScanTargetKind::File,
            matches: vec![],
            rules_evaluated: 0,
            scan_duration_ms: 0,
            errors: vec![],
        };
        cache.insert("key1", r);
        assert_eq!(cache.len(), 1);
        let fetched = cache.get("key1");
        assert!(fetched.is_some());
    }

    #[test]
    fn test_yara_cache_miss() {
        let cache = YaraCache::new(Duration::from_secs(60), 10);
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn test_yara_cache_empty() {
        let cache = YaraCache::new(Duration::from_secs(60), 10);
        assert!(cache.is_empty());
    }

    #[test]
    fn test_yara_integration_builtin_rules() {
        let yi = YaraIntegration::with_builtins();
        assert!(yi.rule_count() >= 5);
    }

    #[test]
    fn test_yara_integration_scan_upx() {
        let yi = YaraIntegration::with_builtins();
        let target = make_target(b"UPX0 header data UPX1 end");
        let result = yi.scan(&target);
        assert!(result.matched_rule_names().contains(&"UPX_Packer"));
    }

    #[test]
    fn test_yara_integration_scan_mimikatz() {
        let yi = YaraIntegration::with_builtins();
        let target = make_target(b"sekurlsa module loaded");
        let result = yi.scan(&target);
        assert!(result.matched_rule_names().contains(&"Mimikatz"));
    }

    #[test]
    fn test_yara_integration_scan_injection() {
        let yi = YaraIntegration::with_builtins();
        let target = make_target(b"VirtualAllocEx WriteProcessMemory CreateRemoteThread");
        let result = yi.scan(&target);
        assert!(result.matched_rule_names().contains(&"ProcessInjection"));
    }

    #[test]
    fn test_yara_integration_scan_clean() {
        let yi = YaraIntegration::with_builtins();
        let target = make_target(b"nothing suspicious here just normal text");
        let result = yi.scan(&target);
        assert!(!result.has_matches());
    }

    #[test]
    fn test_yara_integration_with_cache() {
        let yi = YaraIntegration::with_builtins().with_cache(Duration::from_secs(60), 100);
        let target = make_target(b"mimikatz test data");
        let r1 = yi.scan(&target);
        let r2 = yi.scan(&target);
        assert_eq!(r1.matches.len(), r2.matches.len());
    }

    #[test]
    fn test_yara_integration_scan_string_offsets() {
        let yi = YaraIntegration::with_builtins();
        let target = make_target(b"PREFIX mimikatz SUFFIX");
        let result = yi.scan(&target);
        let m = result.matches.iter().find(|m| m.rule_name == "Mimikatz");
        assert!(m.is_some());
        let m = m.unwrap();
        assert!(!m.string_matches.is_empty());
        // "mimikatz" starts at offset 7
        assert_eq!(m.string_matches[0].offset, 7);
    }

    #[test]
    fn test_yara_integration_add_custom_rule() {
        let mut yi = YaraIntegration::new();
        let mut r = YaraRule::new("CustomRule");
        r.add_text_pattern("$p", "CUSTOM_PATTERN");
        yi.add_rule(r);
        let target = make_target(b"CUSTOM_PATTERN found");
        let result = yi.scan(&target);
        assert!(result.matched_rule_names().contains(&"CustomRule"));
    }
}
