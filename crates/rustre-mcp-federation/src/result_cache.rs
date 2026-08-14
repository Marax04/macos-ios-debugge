//! `result_cache` — Tool-result caching with LRU eviction and file-change invalidation.
//!
//! Cache keyed by `(tool_name, input_hash)`, with TTL, persistent cross-session
//! serialisation, LRU eviction, and optional file-watching invalidation.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ─────────────────────────────────────────────────────────────────────────────
// CacheKey
// ─────────────────────────────────────────────────────────────────────────────

/// Deterministic cache key: FNV-1a hash over `"tool_name|params_json"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CacheKey {
    pub tool_name: String,
    pub input_hash: u64,
}

impl CacheKey {
    /// Compute a cache key for the given tool name and params.
    #[must_use]
    pub fn compute(tool_name: &str, params: &Value) -> Self {
        let raw = format!("{tool_name}|{params}");
        let mut h: u64 = 14_695_981_039_346_656_037;
        for b in raw.bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(1_099_511_628_211);
        }
        Self { tool_name: tool_name.to_string(), input_hash: h }
    }
}

impl std::fmt::Display for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{:016x}", self.tool_name, self.input_hash)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CacheEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single cache entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub key: CacheKey,
    pub value: Value,
    /// Unix timestamp (seconds) when this entry was inserted.
    pub inserted_at: u64,
    /// TTL in seconds.
    pub ttl_secs: u64,
    /// Number of times this entry has been served from cache.
    pub hit_count: u64,
    /// LRU sequence number (higher = more recently used).
    pub lru_seq: u64,
    /// Files this result is associated with (for invalidation).
    pub associated_files: Vec<PathBuf>,
    /// Modification time of associated files at cache time (for change detection).
    pub file_mtimes: HashMap<PathBuf, u64>,
}

impl CacheEntry {
    #[must_use]
    pub fn new(key: CacheKey, value: Value, ttl_secs: u64, lru_seq: u64) -> Self {
        Self {
            key,
            value,
            inserted_at: now_secs(),
            ttl_secs,
            hit_count: 0,
            lru_seq,
            associated_files: Vec::new(),
            file_mtimes: HashMap::new(),
        }
    }

    /// Returns `true` when this entry has exceeded its TTL.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        // Use saturating_add to prevent u64 overflow when ttl_secs is very large.
        now_secs() > self.inserted_at.saturating_add(self.ttl_secs)
    }

    /// Age of this entry in seconds.
    #[must_use]
    pub fn age_secs(&self) -> u64 {
        now_secs().saturating_sub(self.inserted_at)
    }

    /// Associate a file with this entry, recording its current mtime.
    pub fn watch_file(&mut self, path: impl Into<PathBuf>) {
        let p: PathBuf = path.into();
        let mtime = file_mtime(&p).unwrap_or(0);
        self.file_mtimes.insert(p.clone(), mtime);
        if !self.associated_files.contains(&p) {
            self.associated_files.push(p);
        }
    }

    /// Returns `true` when any associated file has been modified since cache insertion.
    #[must_use]
    pub fn files_changed(&self) -> bool {
        for path in &self.associated_files {
            let current = file_mtime(path).unwrap_or(0);
            let stored = self.file_mtimes.get(path).copied().unwrap_or(0);
            if current != stored {
                return true;
            }
        }
        false
    }

    /// Returns `true` when this entry should be evicted (expired OR files changed).
    #[must_use]
    pub fn should_evict(&self) -> bool {
        self.is_expired() || self.files_changed()
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn file_mtime(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
}

// ─────────────────────────────────────────────────────────────────────────────
// CacheStats
// ─────────────────────────────────────────────────────────────────────────────

/// Cache performance statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub invalidations: u64,
    pub total_entries: usize,
    pub expired_entries: usize,
    pub size_bytes_approx: usize,
}

impl CacheStats {
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else { self.hits as f64 / total as f64 }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ResultCache
// ─────────────────────────────────────────────────────────────────────────────

/// LRU cache for tool results with TTL and file-change invalidation.
pub struct ResultCache {
    /// The actual entries.
    entries: HashMap<CacheKey, CacheEntry>,
    /// LRU order: lru_seq → CacheKey.  Lower seq = least recently used.
    lru_order: BTreeMap<u64, CacheKey>,
    /// Next LRU sequence number.
    lru_seq: u64,
    /// Maximum number of entries.
    capacity: usize,
    /// Default TTL for new entries.
    default_ttl: Duration,
    /// Accumulated stats.
    stats: CacheStats,
}

impl ResultCache {
    #[must_use]
    pub fn new(capacity: usize, default_ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            lru_order: BTreeMap::new(),
            lru_seq: 0,
            capacity,
            default_ttl,
            stats: CacheStats::default(),
        }
    }

    // ── Insert ──────────────────────────────────────────────────────────────

    /// Insert a result with the default TTL.
    pub fn insert(&mut self, key: CacheKey, value: Value) {
        self.insert_with_ttl(key, value, self.default_ttl);
    }

    /// Insert a result with a custom TTL.
    pub fn insert_with_ttl(&mut self, key: CacheKey, value: Value, ttl: Duration) {
        // Remove old entry if exists
        if let Some(old) = self.entries.remove(&key) {
            self.lru_order.remove(&old.lru_seq);
        }
        // Evict if at capacity
        if self.entries.len() >= self.capacity {
            self.evict_lru();
        }
        let seq = self.next_seq();
        let entry = CacheEntry::new(key.clone(), value, ttl.as_secs(), seq);
        self.lru_order.insert(seq, key.clone());
        self.entries.insert(key, entry);
        self.stats.total_entries = self.entries.len();
    }

    /// Insert and associate a file for invalidation.
    pub fn insert_with_file(
        &mut self,
        key: CacheKey,
        value: Value,
        ttl: Duration,
        file: impl Into<PathBuf>,
    ) {
        self.insert_with_ttl(key.clone(), value, ttl);
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.watch_file(file);
        }
    }

    // ── Lookup ──────────────────────────────────────────────────────────────

    /// Look up a cached result.  Returns `None` on miss, expiry, or file change.
    pub fn get(&mut self, key: &CacheKey) -> Option<Value> {
        // Evict if needed
        let should_evict = self
            .entries
            .get(key)
            .map(|e| e.should_evict())
            .unwrap_or(false);
        if should_evict {
            self.remove_entry(key);
            self.stats.misses += 1;
            return None;
        }
        if let Some(entry) = self.entries.get_mut(key) {
            entry.hit_count += 1;
            // Promote in LRU
            let old_seq = entry.lru_seq;
            let new_seq = self.lru_seq + 1;
            self.lru_seq = new_seq;
            entry.lru_seq = new_seq;
            self.lru_order.remove(&old_seq);
            self.lru_order.insert(new_seq, key.clone());
            self.stats.hits += 1;
            Some(entry.value.clone())
        } else {
            self.stats.misses += 1;
            None
        }
    }

    /// Peek at a cached value without updating LRU order or hit count.
    #[must_use]
    pub fn peek(&self, key: &CacheKey) -> Option<&Value> {
        self.entries.get(key).filter(|e| !e.should_evict()).map(|e| &e.value)
    }

    // ── Invalidation ────────────────────────────────────────────────────────

    /// Explicitly remove an entry by key.
    pub fn invalidate(&mut self, key: &CacheKey) {
        if self.remove_entry(key) {
            self.stats.invalidations += 1;
        }
    }

    /// Invalidate all entries associated with the given file path.
    pub fn invalidate_file(&mut self, path: &Path) {
        let to_remove: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|(_, e)| e.associated_files.iter().any(|p| p == path))
            .map(|(k, _)| k.clone())
            .collect();
        for key in to_remove {
            self.remove_entry(&key);
            self.stats.invalidations += 1;
        }
    }

    /// Invalidate all entries for a given tool name.
    pub fn invalidate_tool(&mut self, tool_name: &str) {
        let to_remove: Vec<CacheKey> = self
            .entries
            .keys()
            .filter(|k| k.tool_name == tool_name)
            .cloned()
            .collect();
        for key in to_remove {
            self.remove_entry(&key);
            self.stats.invalidations += 1;
        }
    }

    // ── Maintenance ─────────────────────────────────────────────────────────

    /// Remove all expired and file-changed entries.
    pub fn evict_expired(&mut self) -> usize {
        let to_remove: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|(_, e)| e.should_evict())
            .map(|(k, _)| k.clone())
            .collect();
        let count = to_remove.len();
        for key in to_remove {
            self.remove_entry(&key);
            self.stats.evictions += 1;
        }
        self.stats.total_entries = self.entries.len();
        count
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.lru_order.clear();
        self.stats.total_entries = 0;
    }

    // ── Persistence ─────────────────────────────────────────────────────────

    /// Serialise the cache to a JSON string (for cross-session persistence).
    #[must_use]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let entries: Vec<&CacheEntry> = self.entries.values().filter(|e| !e.should_evict()).collect();
        serde_json::to_string(&entries)
    }

    /// Load entries from a persisted JSON string.
    pub fn load_json(&mut self, json: &str) -> Result<usize, serde_json::Error> {
        let entries: Vec<CacheEntry> = serde_json::from_str(json)?;
        let mut loaded = 0;
        for entry in entries {
            if !entry.should_evict() {
                let key = entry.key.clone();
                let seq = self.next_seq();
                let mut e = entry;
                e.lru_seq = seq;
                self.lru_order.insert(seq, key.clone());
                self.entries.insert(key, e);
                loaded += 1;
            }
        }
        self.stats.total_entries = self.entries.len();
        Ok(loaded)
    }

    // ── Stats / Info ────────────────────────────────────────────────────────

    #[must_use]
    pub fn stats(&self) -> &CacheStats {
        &self.stats
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total hit count across all entries.
    #[must_use]
    pub fn total_hits(&self) -> u64 {
        self.entries.values().map(|e| e.hit_count).sum()
    }

    /// List all cached tool names.
    #[must_use]
    pub fn cached_tools(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.entries.keys().map(|k| k.tool_name.as_str()).collect();
        names.sort();
        names.dedup();
        names
    }

    /// Return a list of the N most-recently-used keys.
    #[must_use]
    pub fn mru_keys(&self, n: usize) -> Vec<&CacheKey> {
        self.lru_order
            .values()
            .rev()
            .take(n)
            .filter_map(|k| self.entries.get(k).map(|e| &e.key))
            .collect()
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    fn next_seq(&mut self) -> u64 {
        self.lru_seq += 1;
        self.lru_seq
    }

    fn evict_lru(&mut self) {
        if let Some((&seq, key)) = self.lru_order.iter().next() {
            let key = key.clone();
            self.lru_order.remove(&seq);
            self.entries.remove(&key);
            self.stats.evictions += 1;
        }
    }

    fn remove_entry(&mut self, key: &CacheKey) -> bool {
        if let Some(e) = self.entries.remove(key) {
            self.lru_order.remove(&e.lru_seq);
            self.stats.total_entries = self.entries.len();
            true
        } else {
            false
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CachedCall helper
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of a cache-assisted tool call.
#[derive(Debug, Clone)]
pub enum CachedCallOutcome {
    Hit { value: Value },
    Miss,
}

impl CachedCallOutcome {
    #[must_use]
    pub fn is_hit(&self) -> bool {
        matches!(self, Self::Hit { .. })
    }

    #[must_use]
    pub fn into_value(self) -> Option<Value> {
        match self {
            Self::Hit { value } => Some(value),
            Self::Miss => None,
        }
    }
}

/// Try the cache first; on miss call `f`, insert result.
pub fn with_cache<F>(
    cache: &mut ResultCache,
    tool_name: &str,
    params: &Value,
    ttl: Duration,
    f: F,
) -> Result<Value, String>
where
    F: FnOnce() -> Result<Value, String>,
{
    let key = CacheKey::compute(tool_name, params);
    if let Some(cached) = cache.get(&key) {
        return Ok(cached);
    }
    let result = f()?;
    cache.insert_with_ttl(key, result.clone(), ttl);
    Ok(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(cap: usize) -> ResultCache {
        ResultCache::new(cap, Duration::from_secs(60))
    }

    #[test]
    fn test_insert_and_get() {
        let mut c = cache(10);
        let key = CacheKey::compute("decompile", &serde_json::json!({"addr": "0x1000"}));
        c.insert(key.clone(), serde_json::json!({"code": "void foo(){}"}));
        let val = c.get(&key).unwrap();
        assert_eq!(val["code"], "void foo(){}");
    }

    #[test]
    fn test_miss() {
        let mut c = cache(10);
        let key = CacheKey::compute("missing", &serde_json::json!({}));
        assert!(c.get(&key).is_none());
    }

    #[test]
    fn test_invalidate() {
        let mut c = cache(10);
        let key = CacheKey::compute("tool", &serde_json::json!({}));
        c.insert(key.clone(), serde_json::json!(1));
        c.invalidate(&key);
        assert!(c.get(&key).is_none());
    }

    #[test]
    fn test_invalidate_tool() {
        let mut c = cache(10);
        let k1 = CacheKey::compute("disasm", &serde_json::json!({"a": 1}));
        let k2 = CacheKey::compute("disasm", &serde_json::json!({"a": 2}));
        let k3 = CacheKey::compute("decompile", &serde_json::json!({}));
        c.insert(k1.clone(), serde_json::json!(1));
        c.insert(k2.clone(), serde_json::json!(2));
        c.insert(k3.clone(), serde_json::json!(3));
        c.invalidate_tool("disasm");
        assert!(c.get(&k1).is_none());
        assert!(c.get(&k2).is_none());
        assert!(c.get(&k3).is_some());
    }

    #[test]
    fn test_lru_eviction() {
        let mut c = cache(3);
        for i in 0u32..4 {
            let k = CacheKey::compute(&format!("t{i}"), &serde_json::json!({}));
            c.insert(k, serde_json::json!(i));
        }
        // After 4 inserts with capacity 3, the LRU entry should be gone
        assert_eq!(c.len(), 3);
    }

    #[test]
    fn test_ttl_expiry() {
        let mut c = ResultCache::new(10, Duration::from_nanos(1));
        let key = CacheKey::compute("t", &serde_json::json!({}));
        c.insert_with_ttl(key.clone(), serde_json::json!(1), Duration::from_nanos(1));
        std::thread::sleep(Duration::from_millis(5));
        assert!(c.get(&key).is_none());
    }

    #[test]
    fn test_hit_rate() {
        let mut c = cache(10);
        let k = CacheKey::compute("t", &serde_json::json!({}));
        c.insert(k.clone(), serde_json::json!(1));
        c.get(&k);
        c.get(&k);
        let miss_k = CacheKey::compute("other", &serde_json::json!({}));
        c.get(&miss_k);
        assert!((c.stats().hit_rate() - 2.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_total_hits() {
        let mut c = cache(10);
        let k = CacheKey::compute("t", &serde_json::json!({}));
        c.insert(k.clone(), serde_json::json!(1));
        c.get(&k);
        c.get(&k);
        assert_eq!(c.total_hits(), 2);
    }

    #[test]
    fn test_persist_roundtrip() {
        let mut c = cache(10);
        let k = CacheKey::compute("tool", &serde_json::json!({"x": 1}));
        c.insert(k.clone(), serde_json::json!("result"));
        let json = c.to_json().unwrap();

        let mut c2 = cache(10);
        let loaded = c2.load_json(&json).unwrap();
        assert_eq!(loaded, 1);
        assert!(c2.peek(&k).is_some());
    }

    #[test]
    fn test_cache_key_display() {
        let k = CacheKey::compute("disasm", &serde_json::json!({}));
        let s = k.to_string();
        assert!(s.starts_with("disasm@"));
    }

    #[test]
    fn test_cached_tools() {
        let mut c = cache(10);
        c.insert(CacheKey::compute("a", &serde_json::json!({})), serde_json::json!(1));
        c.insert(CacheKey::compute("a", &serde_json::json!({"x": 1})), serde_json::json!(2));
        c.insert(CacheKey::compute("b", &serde_json::json!({})), serde_json::json!(3));
        let tools = c.cached_tools();
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn test_with_cache_helper() {
        let mut c = cache(10);
        let params = serde_json::json!({"addr": "0x1000"});
        let v1 = with_cache(&mut c, "decompile", &params, Duration::from_secs(60), || {
            Ok(serde_json::json!({"code": "int main(){}"}))
        })
        .unwrap();
        assert_eq!(v1["code"], "int main(){}");
        // Second call should be a cache hit
        let v2 = with_cache(&mut c, "decompile", &params, Duration::from_secs(60), || {
            panic!("should not be called on cache hit")
        })
        .unwrap();
        assert_eq!(v1, v2);
    }
}
