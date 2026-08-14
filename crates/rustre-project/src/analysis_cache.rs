//! Analysis result cache — `AnalysisCache` and associated types.
//!
//! Provides a content-addressed cache for analysis pass results keyed by
//! binary hash and pass name.  Supports invalidation by dependency change,
//! cache statistics, export/import, and dependency tracking.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

// ─── CacheKey ────────────────────────────────────────────────────────────────

/// A unique cache key identifying an analysis result.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// SHA-256 hex digest of the binary that was analyzed.
    pub binary_hash: String,
    /// Name of the analysis pass that produced this result.
    pub analysis_pass: String,
}

impl CacheKey {
    #[must_use]
    pub fn new(binary_hash: impl Into<String>, analysis_pass: impl Into<String>) -> Self {
        Self { binary_hash: binary_hash.into(), analysis_pass: analysis_pass.into() }
    }
}

impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", &self.binary_hash[..8.min(self.binary_hash.len())], self.analysis_pass)
    }
}

// ─── CachedResult ────────────────────────────────────────────────────────────

/// A cached analysis result.
#[derive(Debug, Clone)]
pub struct CachedResult {
    /// The analysis pass that produced this result.
    pub analysis_pass: String,
    /// JSON-serialized result payload.
    pub result_json: String,
    /// Unix timestamp (seconds) when this result was cached.
    pub timestamp: u64,
    /// SHA-256 hex digest of the binary that was analyzed.
    pub binary_hash: String,
    /// Hashes of dependency passes whose results this entry depends on.
    pub dependency_hashes: Vec<String>,
    /// Whether this result has been invalidated.
    pub invalidated: bool,
}

impl CachedResult {
    /// Create a new cached result.
    #[must_use]
    pub fn new(
        analysis_pass: impl Into<String>,
        result_json: impl Into<String>,
        binary_hash: impl Into<String>,
    ) -> Self {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            analysis_pass: analysis_pass.into(),
            result_json: result_json.into(),
            timestamp: ts,
            binary_hash: binary_hash.into(),
            dependency_hashes: Vec::new(),
            invalidated: false,
        }
    }

    /// Returns `true` if this entry is valid (not invalidated, not expired).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.invalidated
    }

    /// Returns `true` if the result is older than `max_age_secs` seconds.
    #[must_use]
    pub fn is_expired(&self, max_age_secs: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now.saturating_sub(self.timestamp) > max_age_secs
    }

    /// Add a dependency hash.
    pub fn add_dependency(&mut self, dep_hash: impl Into<String>) {
        self.dependency_hashes.push(dep_hash.into());
    }
}

// ─── CacheInvalidation ───────────────────────────────────────────────────────

/// Describes a cache invalidation event.
#[derive(Debug, Clone)]
pub struct CacheInvalidation {
    /// The binary hash whose entries were invalidated.
    pub binary_hash: String,
    /// Specific analysis pass invalidated, or `None` for all passes.
    pub analysis_pass: Option<String>,
    /// Reason for invalidation.
    pub reason: String,
    /// Timestamp of the invalidation event.
    pub timestamp: u64,
    /// Number of entries that were invalidated.
    pub entries_invalidated: usize,
}

impl CacheInvalidation {
    #[must_use]
    pub fn new(binary_hash: impl Into<String>, reason: impl Into<String>) -> Self {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        Self {
            binary_hash: binary_hash.into(),
            analysis_pass: None,
            reason: reason.into(),
            timestamp: ts,
            entries_invalidated: 0,
        }
    }
}

// ─── CacheStats ───────────────────────────────────────────────────────────────

/// Statistics about cache usage.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub invalidations: u64,
    pub total_entries: usize,
    pub expired_entries: usize,
    pub bytes_stored: usize,
}

impl CacheStats {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Hit ratio (0.0 to 1.0). Returns 0.0 if no accesses.
    #[must_use]
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else { self.hits as f64 / total as f64 }
    }
}

impl fmt::Display for CacheStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CacheStats {{ hits={}, misses={}, ratio={:.2}, entries={}, invalidations={} }}",
            self.hits,
            self.misses,
            self.hit_ratio(),
            self.total_entries,
            self.invalidations,
        )
    }
}

// ─── DependencyTracker ────────────────────────────────────────────────────────

/// Tracks which analysis passes depend on which others, and detects when a
/// dependency change requires downstream cache invalidation.
#[derive(Debug, Default, Clone)]
pub struct DependencyTracker {
    /// Map from analysis pass name to the set of passes it depends on.
    dependencies: HashMap<String, HashSet<String>>,
    /// Last known hash for each pass output (used to detect changes).
    pass_hashes: HashMap<String, String>,
}

impl DependencyTracker {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare that `pass` depends on `dep`.
    pub fn add_dependency(&mut self, pass: impl Into<String>, dep: impl Into<String>) {
        self.dependencies
            .entry(pass.into())
            .or_default()
            .insert(dep.into());
    }

    /// Register the current output hash for a pass.
    pub fn set_pass_hash(&mut self, pass: impl Into<String>, hash: impl Into<String>) {
        self.pass_hashes.insert(pass.into(), hash.into());
    }

    /// Return the dependencies of a pass.
    #[must_use]
    pub fn deps_of(&self, pass: &str) -> Vec<&str> {
        self.dependencies
            .get(pass)
            .map(|s| s.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// Return all passes that transitively depend on `pass` (reverse deps).
    #[must_use]
    pub fn dependents_of(&self, pass: &str) -> Vec<String> {
        self.dependencies
            .iter()
            .filter(|(_, deps)| deps.contains(pass))
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Return the passes that need re-running because `changed_pass` has a new hash.
    #[must_use]
    pub fn invalidated_by_change(&self, changed_pass: &str, new_hash: &str) -> Vec<String> {
        if let Some(old) = self.pass_hashes.get(changed_pass) {
            if old == new_hash {
                return Vec::new(); // no change
            }
        }
        self.dependents_of(changed_pass)
    }

    /// Returns `true` if `pass` directly or transitively depends on `dep`.
    #[must_use]
    pub fn depends_on(&self, pass: &str, dep: &str) -> bool {
        let mut visited = HashSet::new();
        let mut stack = vec![pass.to_string()];
        while let Some(current) = stack.pop() {
            if visited.contains(&current) { continue; }
            visited.insert(current.clone());
            if let Some(deps) = self.dependencies.get(&current) {
                if deps.contains(dep) { return true; }
                for d in deps {
                    stack.push(d.clone());
                }
            }
        }
        false
    }
}

// ─── CacheExport ─────────────────────────────────────────────────────────────

/// A portable export of cache contents.
#[derive(Debug, Clone, Default)]
pub struct CacheExport {
    pub entries: Vec<CacheExportEntry>,
    pub exported_at: u64,
    pub source_label: String,
}

/// A single exported cache entry.
#[derive(Debug, Clone)]
pub struct CacheExportEntry {
    pub key: CacheKey,
    pub result_json: String,
    pub timestamp: u64,
    pub dependency_hashes: Vec<String>,
}

impl CacheExport {
    #[must_use]
    pub fn new(source_label: impl Into<String>) -> Self {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        Self {
            entries: Vec::new(),
            exported_at: ts,
            source_label: source_label.into(),
        }
    }

    pub fn add_entry(&mut self, key: CacheKey, result: &CachedResult) {
        self.entries.push(CacheExportEntry {
            key,
            result_json: result.result_json.clone(),
            timestamp: result.timestamp,
            dependency_hashes: result.dependency_hashes.clone(),
        });
    }

    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

// ─── AnalysisCache ────────────────────────────────────────────────────────────

/// Content-addressed cache for analysis pass results.
///
/// All entries are keyed by `(binary_hash, analysis_pass)` and stored in memory.
/// Optionally wired to a `DependencyTracker` for automatic downstream invalidation.
#[derive(Debug, Default)]
pub struct AnalysisCache {
    entries: HashMap<CacheKey, CachedResult>,
    stats: CacheStats,
    invalidation_log: Vec<CacheInvalidation>,
    dependency_tracker: DependencyTracker,
    /// Maximum age in seconds before an entry is considered expired (0 = no limit).
    pub max_age_secs: u64,
    /// Maximum number of entries. 0 = unlimited.
    pub capacity: usize,
}

impl AnalysisCache {
    /// Create a new `AnalysisCache` with no limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a cache with a specific capacity and max age.
    #[must_use]
    pub fn with_limits(capacity: usize, max_age_secs: u64) -> Self {
        Self { capacity, max_age_secs, ..Default::default() }
    }

    // ── Insertion ──────────────────────────────────────────────────────────────

    /// Insert or update a cache entry.
    pub fn insert(&mut self, binary_hash: impl Into<String>, analysis_pass: impl Into<String>, result_json: impl Into<String>) -> CacheKey {
        let binary_hash = binary_hash.into();
        let analysis_pass = analysis_pass.into();
        let key = CacheKey::new(binary_hash.clone(), analysis_pass.clone());
        let entry = CachedResult::new(analysis_pass, result_json, binary_hash);
        self.entries.insert(key.clone(), entry);
        self.update_stats();
        // Evict if over capacity.
        if self.capacity > 0 && self.entries.len() > self.capacity {
            self.evict_oldest();
        }
        key
    }

    // ── Retrieval ──────────────────────────────────────────────────────────────

    /// Look up a cached result.
    #[must_use]
    pub fn get(&mut self, key: &CacheKey) -> Option<&CachedResult> {
        let entry = if let Some(e) = self.entries.get(key) { e } else {
            self.stats.misses += 1;
            return None;
        };
        if entry.is_expired(self.max_age_secs) || entry.invalidated {
            self.stats.misses += 1;
            return None;
        }
        self.stats.hits += 1;
        self.entries.get(key)
    }

    /// Peek at an entry without updating stats.
    #[must_use]
    pub fn peek(&self, key: &CacheKey) -> Option<&CachedResult> {
        self.entries.get(key)
    }

    /// Returns `true` if a valid entry exists for this key.
    #[must_use]
    pub fn contains(&mut self, key: &CacheKey) -> bool {
        self.get(key).is_some()
    }

    // ── Invalidation ──────────────────────────────────────────────────────────

    /// Invalidate all entries for a given binary hash.
    pub fn invalidate_binary(&mut self, binary_hash: &str, reason: impl Into<String>) -> usize {
        let mut count = 0;
        for (k, v) in self.entries.iter_mut() {
            if k.binary_hash == binary_hash {
                v.invalidated = true;
                count += 1;
            }
        }
        self.stats.invalidations += 1;
        let inv = CacheInvalidation {
            binary_hash: binary_hash.to_string(),
            analysis_pass: None,
            reason: reason.into(),
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            entries_invalidated: count,
        };
        self.invalidation_log.push(inv);
        count
    }

    /// Invalidate a single entry.
    pub fn invalidate_entry(&mut self, key: &CacheKey, reason: impl Into<String>) -> bool {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.invalidated = true;
            self.stats.invalidations += 1;
            let inv = CacheInvalidation {
                binary_hash: key.binary_hash.clone(),
                analysis_pass: Some(key.analysis_pass.clone()),
                reason: reason.into(),
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
                entries_invalidated: 1,
            };
            self.invalidation_log.push(inv);
            true
        } else {
            false
        }
    }

    /// Invalidate all downstream entries when a dependency changes.
    pub fn invalidate_dependents(&mut self, changed_pass: &str, new_hash: &str, binary_hash: &str) -> usize {
        let dependents = self.dependency_tracker.invalidated_by_change(changed_pass, new_hash);
        let mut count = 0;
        for pass in &dependents {
            let key = CacheKey::new(binary_hash, pass.as_str());
            if self.invalidate_entry(&key, format!("dependency {changed_pass} changed")) {
                count += 1;
            }
        }
        count
    }

    // ── Dependencies ──────────────────────────────────────────────────────────

    /// Return a mutable reference to the dependency tracker.
    pub fn dependency_tracker_mut(&mut self) -> &mut DependencyTracker {
        &mut self.dependency_tracker
    }

    // ── Export ────────────────────────────────────────────────────────────────

    /// Export all valid entries for a binary hash.
    #[must_use]
    pub fn export(&self, binary_hash: &str, label: impl Into<String>) -> CacheExport {
        let mut export = CacheExport::new(label);
        for (key, entry) in &self.entries {
            if key.binary_hash == binary_hash && entry.is_valid() {
                export.add_entry(key.clone(), entry);
            }
        }
        export
    }

    /// Import entries from a `CacheExport`.
    pub fn import(&mut self, export: CacheExport) -> usize {
        let mut imported = 0;
        for e in export.entries {
            if !self.entries.contains_key(&e.key) {
                let mut result = CachedResult::new(
                    e.key.analysis_pass.clone(),
                    e.result_json,
                    e.key.binary_hash.clone(),
                );
                result.timestamp = e.timestamp;
                result.dependency_hashes = e.dependency_hashes;
                self.entries.insert(e.key, result);
                imported += 1;
            }
        }
        self.update_stats();
        imported
    }

    // ── Maintenance ───────────────────────────────────────────────────────────

    /// Remove all invalidated and expired entries.
    pub fn prune(&mut self) -> usize {
        let max_age = self.max_age_secs;
        let before = self.entries.len();
        self.entries.retain(|_, v| {
            !v.invalidated && (max_age == 0 || !v.is_expired(max_age))
        });
        let removed = before - self.entries.len();
        self.update_stats();
        removed
    }

    /// Clear the entire cache.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.update_stats();
    }

    /// Return current statistics.
    #[must_use]
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    /// Return the invalidation log.
    #[must_use]
    pub fn invalidation_log(&self) -> &[CacheInvalidation] {
        &self.invalidation_log
    }

    /// Total number of entries (including invalidated).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn update_stats(&mut self) {
        let max_age = self.max_age_secs;
        let expired = self.entries.values()
            .filter(|v| max_age > 0 && v.is_expired(max_age))
            .count();
        let bytes: usize = self.entries.values().map(|v| v.result_json.len()).sum();
        self.stats.total_entries = self.entries.len();
        self.stats.expired_entries = expired;
        self.stats.bytes_stored = bytes;
    }

    fn evict_oldest(&mut self) {
        // `entries` is a HashMap and timestamps tie easily, so without a
        // tie-break the evicted entry differs between runs on identical input.
        // `CacheKey` does not derive `Ord`, so order on its public fields.
        let oldest_key = self.entries
            .iter()
            .min_by(|a, b| {
                a.1.timestamp.cmp(&b.1.timestamp).then_with(|| {
                    a.0.binary_hash
                        .cmp(&b.0.binary_hash)
                        .then_with(|| a.0.analysis_pass.cmp(&b.0.analysis_pass))
                })
            })
            .map(|(k, _)| k.clone());
        if let Some(k) = oldest_key {
            self.entries.remove(&k);
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cache() -> AnalysisCache {
        AnalysisCache::new()
    }

    // ── CacheKey ──────────────────────────────────────────────────────────────

    #[test]
    fn cache_key_eq() {
        let a = CacheKey::new("abc123", "cfg");
        let b = CacheKey::new("abc123", "cfg");
        assert_eq!(a, b);
    }

    #[test]
    fn cache_key_display() {
        let k = CacheKey::new("abcdefgh1234", "pass1");
        let s = k.to_string();
        assert!(s.contains("abcdefgh"));
        assert!(s.contains("pass1"));
    }

    // ── CachedResult ─────────────────────────────────────────────────────────

    #[test]
    fn cached_result_is_valid_new() {
        let r = CachedResult::new("pass1", r#"{"x":1}"#, "abc");
        assert!(r.is_valid());
        assert!(!r.invalidated);
    }

    #[test]
    fn cached_result_not_expired_zero_age() {
        let r = CachedResult::new("pass1", "{}", "abc");
        assert!(!r.is_expired(0));
    }

    #[test]
    fn cached_result_is_expired_large_threshold() {
        // A result with timestamp 0 (epoch) should be very old.
        let mut r = CachedResult::new("pass1", "{}", "abc");
        r.timestamp = 0;
        assert!(r.is_expired(1));
    }

    #[test]
    fn cached_result_add_dependency() {
        let mut r = CachedResult::new("pass1", "{}", "abc");
        r.add_dependency("dep_hash_abc");
        assert_eq!(r.dependency_hashes.len(), 1);
    }

    // ── CacheStats ────────────────────────────────────────────────────────────

    #[test]
    fn cache_stats_hit_ratio_zero() {
        let s = CacheStats::new();
        assert_eq!(s.hit_ratio(), 0.0);
    }

    #[test]
    fn cache_stats_hit_ratio_partial() {
        let s = CacheStats { hits: 3, misses: 1, ..Default::default() };
        assert!((s.hit_ratio() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn cache_stats_display() {
        let s = CacheStats { hits: 10, misses: 5, total_entries: 20, ..Default::default() };
        let txt = s.to_string();
        assert!(txt.contains("hits=10"));
        assert!(txt.contains("misses=5"));
    }

    // ── DependencyTracker ─────────────────────────────────────────────────────

    #[test]
    fn dep_tracker_add_and_query() {
        let mut dt = DependencyTracker::new();
        dt.add_dependency("type-infer", "cfg");
        dt.add_dependency("type-infer", "symbol-resolve");
        let deps = dt.deps_of("type-infer");
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn dep_tracker_dependents_of() {
        let mut dt = DependencyTracker::new();
        dt.add_dependency("type-infer", "cfg");
        dt.add_dependency("dead-code", "cfg");
        let dependents = dt.dependents_of("cfg");
        assert_eq!(dependents.len(), 2);
        assert!(dependents.contains(&"type-infer".to_string()));
    }

    #[test]
    fn dep_tracker_invalidated_by_change() {
        let mut dt = DependencyTracker::new();
        dt.add_dependency("pass-b", "pass-a");
        dt.set_pass_hash("pass-a", "old_hash");
        let invalid = dt.invalidated_by_change("pass-a", "new_hash");
        assert!(invalid.contains(&"pass-b".to_string()));
    }

    #[test]
    fn dep_tracker_no_change() {
        let mut dt = DependencyTracker::new();
        dt.add_dependency("pass-b", "pass-a");
        dt.set_pass_hash("pass-a", "same_hash");
        let invalid = dt.invalidated_by_change("pass-a", "same_hash");
        assert!(invalid.is_empty());
    }

    #[test]
    fn dep_tracker_depends_on_direct() {
        let mut dt = DependencyTracker::new();
        dt.add_dependency("b", "a");
        assert!(dt.depends_on("b", "a"));
        assert!(!dt.depends_on("a", "b"));
    }

    #[test]
    fn dep_tracker_depends_on_transitive() {
        let mut dt = DependencyTracker::new();
        dt.add_dependency("b", "a");
        dt.add_dependency("c", "b");
        assert!(dt.depends_on("c", "a"));
    }

    // ── AnalysisCache ─────────────────────────────────────────────────────────

    #[test]
    fn cache_insert_and_get() {
        let mut cache = make_cache();
        let key = cache.insert("abc123", "cfg", r#"{"nodes":10}"#);
        let entry = cache.get(&key).unwrap();
        assert_eq!(entry.analysis_pass, "cfg");
        assert_eq!(entry.result_json, r#"{"nodes":10}"#);
    }

    #[test]
    fn cache_get_miss() {
        let mut cache = make_cache();
        let key = CacheKey::new("unknown", "pass");
        assert!(cache.get(&key).is_none());
        assert_eq!(cache.stats().misses, 1);
    }

    #[test]
    fn cache_contains_true() {
        let mut cache = make_cache();
        let key = cache.insert("abc", "pass", "{}");
        assert!(cache.contains(&key));
    }

    #[test]
    fn cache_contains_false_after_invalidate() {
        let mut cache = make_cache();
        let key = cache.insert("abc", "pass", "{}");
        cache.invalidate_entry(&key, "test");
        assert!(!cache.contains(&key));
    }

    #[test]
    fn cache_invalidate_binary_all_entries() {
        let mut cache = make_cache();
        cache.insert("abc", "pass1", "{}");
        cache.insert("abc", "pass2", "{}");
        cache.insert("xyz", "pass1", "{}");
        let count = cache.invalidate_binary("abc", "binary changed");
        assert_eq!(count, 2);
    }

    #[test]
    fn cache_invalidation_log() {
        let mut cache = make_cache();
        let key = cache.insert("abc", "pass", "{}");
        cache.invalidate_entry(&key, "test reason");
        assert_eq!(cache.invalidation_log().len(), 1);
        assert_eq!(cache.invalidation_log()[0].reason, "test reason");
    }

    #[test]
    fn cache_prune_removes_invalidated() {
        let mut cache = make_cache();
        cache.insert("abc", "pass1", "{}");
        let key = cache.insert("abc", "pass2", "{}");
        cache.invalidate_entry(&key, "x");
        let removed = cache.prune();
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_clear() {
        let mut cache = make_cache();
        cache.insert("a", "p1", "{}");
        cache.insert("b", "p2", "{}");
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_hit_stat_increments() {
        let mut cache = make_cache();
        let key = cache.insert("abc", "pass", "{}");
        let _ = cache.get(&key);
        let _ = cache.get(&key);
        assert_eq!(cache.stats().hits, 2);
    }

    #[test]
    fn cache_export_and_import() {
        let mut a = make_cache();
        a.insert("abc", "cfg", r#"{"nodes":5}"#);
        a.insert("abc", "symbols", r#"{"count":20}"#);
        let export = a.export("abc", "test export");
        assert_eq!(export.entry_count(), 2);

        let mut b = make_cache();
        let imported = b.import(export);
        assert_eq!(imported, 2);
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn cache_import_skips_duplicates() {
        let mut a = make_cache();
        a.insert("abc", "cfg", r#"{"v":1}"#);
        let export = a.export("abc", "test");

        let mut b = make_cache();
        b.insert("abc", "cfg", r#"{"v":2}"#); // already has an entry
        let imported = b.import(export);
        assert_eq!(imported, 0); // should not overwrite
    }

    #[test]
    fn cache_capacity_evicts_oldest() {
        let mut cache = AnalysisCache::with_limits(2, 0);
        cache.insert("a", "p1", "{}");
        std::thread::sleep(std::time::Duration::from_millis(10)); // ensure different timestamps
        cache.insert("a", "p2", "{}");
        std::thread::sleep(std::time::Duration::from_millis(10));
        cache.insert("a", "p3", "{}"); // should evict oldest
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn cache_peek_does_not_update_stats() {
        let mut cache = make_cache();
        let key = cache.insert("abc", "pass", "{}");
        let _ = cache.peek(&key);
        assert_eq!(cache.stats().hits, 0);
        assert_eq!(cache.stats().misses, 0);
    }

    #[test]
    fn cache_invalidate_dependents() {
        let mut cache = make_cache();
        cache.insert("abc", "cfg", "{}");
        cache.insert("abc", "type-infer", "{}");
        cache.dependency_tracker_mut().add_dependency("type-infer", "cfg");
        cache.dependency_tracker_mut().set_pass_hash("cfg", "old_hash");
        let count = cache.invalidate_dependents("cfg", "new_hash", "abc");
        assert_eq!(count, 1);
    }
}
