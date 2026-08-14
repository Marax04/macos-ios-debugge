//! MCP federation response cache: `FederationCache`, `CacheEntry`,
//! `CachePolicy`, `get_cached()`.
//!
//! Provides a TTL-based, LRU-evicted in-memory cache for MCP tool call
//! responses.  Caching is opt-in per-tool via `CachePolicy`.

use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── CachePolicy ───────────────────────────────────────────────────────────────

/// Policy governing when (and whether) a tool call result is cached.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachePolicy {
    /// Whether caching is enabled for this tool.
    pub enabled: bool,
    /// Maximum time-to-live for a cached entry (seconds).
    pub ttl_secs: u64,
    /// Maximum number of bytes to cache for a single response.
    /// Responses larger than this limit are not cached.
    pub max_response_bytes: usize,
    /// Whether to cache error responses.
    pub cache_errors: bool,
    /// If `Some`, only cache when the tool arguments match this pattern
    /// (treated as a JSON path prefix for the first key in the args object).
    pub key_prefix_filter: Option<String>,
    /// Maximum number of distinct argument hashes to keep for this tool.
    pub max_variants: usize,
}

impl CachePolicy {
    /// Default policy: 60-second TTL, 64 KiB limit, no error caching.
    #[must_use]
    pub fn default_ttl(secs: u64) -> Self {
        Self {
            enabled: true,
            ttl_secs: secs,
            max_response_bytes: 65_536,
            cache_errors: false,
            key_prefix_filter: None,
            max_variants: 128,
        }
    }

    /// A policy that disables caching entirely.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ttl_secs: 0,
            max_response_bytes: 0,
            cache_errors: false,
            key_prefix_filter: None,
            max_variants: 0,
        }
    }

    /// Return `true` if a response of `byte_size` bytes should be stored.
    #[must_use]
    pub const fn should_cache_response(&self, byte_size: usize) -> bool {
        self.enabled && byte_size <= self.max_response_bytes
    }
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self::default_ttl(60)
    }
}

// ── CacheKey ──────────────────────────────────────────────────────────────────

/// A cache key combining the tool name and a hash of its arguments.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CacheKey {
    pub tool_name: String,
    pub args_hash: u64,
}

impl CacheKey {
    /// Compute a cache key from a tool name and its JSON arguments.
    #[must_use]
    pub fn from_args(tool_name: impl Into<String>, args: &Value) -> Self {
        let args_hash = fnv1a_value(args);
        Self { tool_name: tool_name.into(), args_hash }
    }
}


impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{:016x}", self.tool_name, self.args_hash)
    }
}

/// Streaming FNV-1a [`Hasher`] used for cache-key fingerprinting.
///
/// Exposed so callers can hash custom types into the same 64-bit space as
/// [`CacheKey::from_args`].
#[derive(Debug, Clone)]
pub struct Fnv1aHasher(u64);

impl Default for Fnv1aHasher {
    fn default() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

impl Hasher for Fnv1aHasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= b as u64;
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01B3);
        }
    }
}

/// Fold a `Hash`-able value into a 64-bit fingerprint using [`Fnv1aHasher`].
/// Symmetric with [`fnv1a_value`] but works for any `H: Hash`.
pub fn fnv1a_hashable<H: Hash + ?Sized>(value: &H) -> u64 {
    let mut h = Fnv1aHasher::default();
    value.hash(&mut h);
    h.finish()
}

fn fnv1a_value(v: &Value) -> u64 {
    let s = v.to_string();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

// ── CacheEntry ────────────────────────────────────────────────────────────────

/// A single cached tool-call response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// The cache key this entry corresponds to.
    pub key: CacheKey,
    /// The cached response value.
    pub value: Value,
    /// Unix timestamp (seconds) when this entry was inserted.
    pub inserted_at: u64,
    /// Unix timestamp (seconds) when this entry expires.
    pub expires_at: u64,
    /// Number of times this entry has been returned as a cache hit.
    pub hit_count: u64,
    /// Approximate response size in bytes.
    pub size_bytes: usize,
    /// Whether this is a cached error response.
    pub is_error: bool,
}

impl CacheEntry {
    /// Construct a new cache entry.
    #[must_use]
    pub fn new(key: CacheKey, value: Value, ttl_secs: u64, is_error: bool) -> Self {
        let now = unix_now();
        let size_bytes = value.to_string().len();
        Self {
            key,
            value,
            inserted_at: now,
            expires_at: now.saturating_add(ttl_secs),
            hit_count: 0,
            size_bytes,
            is_error,
        }
    }

    /// Return `true` if this entry is still valid.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        unix_now() < self.expires_at
    }

    /// Return remaining TTL in seconds (0 if expired).
    #[must_use]
    pub fn remaining_ttl(&self) -> u64 {
        let now = unix_now();
        if now >= self.expires_at { 0 } else { self.expires_at - now }
    }

    /// Record a cache hit.
    pub fn record_hit(&mut self) {
        self.hit_count += 1;
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs()
}

impl fmt::Display for CacheEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ttl={}s hits={} size={}B",
            self.key, self.remaining_ttl(), self.hit_count, self.size_bytes
        )
    }
}

// ── CacheStats ────────────────────────────────────────────────────────────────

/// Aggregate statistics for the federation cache.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub total_hits: u64,
    pub total_misses: u64,
    pub total_inserts: u64,
    pub total_evictions: u64,
    pub total_expirations: u64,
    pub current_entries: usize,
    pub current_size_bytes: usize,
}

impl CacheStats {
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.total_hits + self.total_misses;
        if total == 0 { 0.0 } else { self.total_hits as f64 / total as f64 }
    }
}

// ── FederationCache ───────────────────────────────────────────────────────────

/// In-memory LRU-ish TTL cache for MCP tool call responses.
///
/// Policies are registered per tool name.  Tools without a registered policy
/// use a conservative default.
#[derive(Debug)]
pub struct FederationCache {
    inner: Arc<Mutex<CacheInner>>,
}

#[derive(Debug)]
struct CacheInner {
    /// The cached entries, keyed by `CacheKey`.
    entries: HashMap<CacheKey, CacheEntry>,
    /// Access order for LRU eviction (oldest first).
    access_order: Vec<CacheKey>,
    /// Per-tool policies.
    policies: HashMap<String, CachePolicy>,
    /// Default policy for tools without an explicit policy.
    default_policy: CachePolicy,
    /// Maximum total number of entries.
    max_entries: usize,
    /// Maximum total cache size in bytes.
    max_size_bytes: usize,
    /// Statistics.
    stats: CacheStats,
}

impl CacheInner {
    fn evict_lru(&mut self) {
        // Remove the least-recently-used entry.
        if let Some(key) = self.access_order.first().cloned() {
            self.access_order.remove(0);
            if let Some(e) = self.entries.remove(&key) {
                self.stats.current_entries -= 1;
                self.stats.current_size_bytes = self.stats.current_size_bytes.saturating_sub(e.size_bytes);
                self.stats.total_evictions += 1;
            }
        }
    }

    fn evict_expired(&mut self) {
        let now = unix_now();
        let expired: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|(_, e)| e.expires_at <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            self.access_order.retain(|k| k != &key);
            if let Some(e) = self.entries.remove(&key) {
                self.stats.current_entries -= 1;
                self.stats.current_size_bytes = self.stats.current_size_bytes.saturating_sub(e.size_bytes);
                self.stats.total_expirations += 1;
            }
        }
    }

    fn touch(&mut self, key: &CacheKey) {
        self.access_order.retain(|k| k != key);
        self.access_order.push(key.clone());
    }

    fn policy_for(&self, tool_name: &str) -> &CachePolicy {
        self.policies.get(tool_name).unwrap_or(&self.default_policy)
    }
}

impl FederationCache {
    /// Construct a new cache.
    ///
    /// # Parameters
    /// - `max_entries`: Hard cap on the number of cached responses.
    /// - `max_size_bytes`: Soft cap on the total byte size of cached values.
    #[must_use]
    pub fn new(max_entries: usize, max_size_bytes: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CacheInner {
                entries: HashMap::new(),
                access_order: Vec::new(),
                policies: HashMap::new(),
                default_policy: CachePolicy::default_ttl(60),
                max_entries,
                max_size_bytes,
                stats: CacheStats::default(),
            })),
        }
    }

    /// Register a caching policy for a tool.
    pub fn set_policy(&self, tool_name: impl Into<String>, policy: CachePolicy) {
        self.inner.lock().policies.insert(tool_name.into(), policy);
    }

    /// Set the default policy for tools without an explicit policy.
    pub fn set_default_policy(&self, policy: CachePolicy) {
        self.inner.lock().default_policy = policy;
    }

    /// Return the number of current entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().entries.len()
    }

    /// Return `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().entries.is_empty()
    }

    /// Return a snapshot of the current statistics.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        self.inner.lock().stats.clone()
    }

    /// Evict all expired entries.
    pub fn evict_expired(&self) {
        self.inner.lock().evict_expired();
    }

    /// Clear all cached entries.
    pub fn clear(&self) {
        let mut g = self.inner.lock();
        g.entries.clear();
        g.access_order.clear();
        g.stats.current_entries = 0;
        g.stats.current_size_bytes = 0;
    }

    /// Invalidate all entries for a given tool.
    pub fn invalidate_tool(&self, tool_name: &str) {
        let mut g = self.inner.lock();
        let to_remove: Vec<CacheKey> = g
            .entries
            .keys()
            .filter(|k| k.tool_name == tool_name)
            .cloned()
            .collect();
        for key in to_remove {
            g.access_order.retain(|k| k != &key);
            if let Some(e) = g.entries.remove(&key) {
                g.stats.current_entries -= 1;
                g.stats.current_size_bytes = g.stats.current_size_bytes.saturating_sub(e.size_bytes);
            }
        }
    }

    /// Store a tool call result in the cache.
    ///
    /// Returns `true` if the entry was actually stored (policy allows it).
    pub fn put(
        &self,
        tool_name: &str,
        args: &Value,
        response: Value,
        is_error: bool,
    ) -> bool {
        let mut g = self.inner.lock();

        let policy = g.policy_for(tool_name).clone();
        if !policy.enabled { return false; }
        if is_error && !policy.cache_errors { return false; }

        let size = response.to_string().len();
        if !policy.should_cache_response(size) { return false; }

        // Check variant count for this tool.
        let variant_count = g.entries.keys().filter(|k| k.tool_name == tool_name).count();
        if variant_count >= policy.max_variants {
            // Evict the oldest variant for this tool.
            let oldest = g.access_order.iter()
                .find(|k| k.tool_name == tool_name)
                .cloned();
            if let Some(key) = oldest {
                g.access_order.retain(|k| k != &key);
                if let Some(e) = g.entries.remove(&key) {
                    g.stats.current_entries -= 1;
                    g.stats.current_size_bytes = g.stats.current_size_bytes.saturating_sub(e.size_bytes);
                    g.stats.total_evictions += 1;
                }
            }
        }

        // Evict expired before inserting.
        let now = unix_now();
        let expired: Vec<CacheKey> = g.entries.iter()
            .filter(|(_, e)| e.expires_at <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            g.access_order.retain(|k| k != &key);
            if let Some(e) = g.entries.remove(&key) {
                g.stats.current_entries -= 1;
                g.stats.current_size_bytes = g.stats.current_size_bytes.saturating_sub(e.size_bytes);
                g.stats.total_expirations += 1;
            }
        }

        // Evict LRU if at capacity.
        while g.entries.len() >= g.max_entries || g.stats.current_size_bytes + size > g.max_size_bytes {
            if g.access_order.is_empty() { break; }
            g.evict_lru();
        }

        let key = CacheKey::from_args(tool_name, args);
        let entry = CacheEntry::new(key.clone(), response, policy.ttl_secs, is_error);
        g.stats.current_size_bytes += entry.size_bytes;
        g.entries.insert(key.clone(), entry);
        g.access_order.push(key);
        g.stats.current_entries += 1;
        g.stats.total_inserts += 1;
        true
    }
}

// ── get_cached ────────────────────────────────────────────────────────────────

/// Look up a cached response for `(tool_name, args)`.
///
/// Returns a clone of the cached [`CacheEntry`] on a hit (and advances its
/// LRU position), or `None` on a miss or expired entry.
/// Like [`get_cached`], but also returns the monotonic wall time taken by
/// the lookup (using [`Instant`]). Useful for cache-perf dashboards.
pub fn get_cached_timed(
    cache: &FederationCache,
    tool_name: &str,
    args: &Value,
) -> (Option<CacheEntry>, Duration) {
    let started = Instant::now();
    let entry = get_cached(cache, tool_name, args);
    (entry, started.elapsed())
}

pub fn get_cached(
    cache: &FederationCache,
    tool_name: &str,
    args: &Value,
) -> Option<CacheEntry> {
    let mut g = cache.inner.lock();
    let key = CacheKey::from_args(tool_name, args);

    if let Some(entry) = g.entries.get_mut(&key) {
        if entry.is_valid() {
            entry.record_hit();
            g.stats.total_hits += 1;
            let entry_clone = g.entries[&key].clone();
            g.touch(&key);
            return Some(entry_clone);
        } else {
            // Expired — remove.
            g.access_order.retain(|k| k != &key);
            if let Some(e) = g.entries.remove(&key) {
                g.stats.current_entries -= 1;
                g.stats.current_size_bytes = g.stats.current_size_bytes.saturating_sub(e.size_bytes);
                g.stats.total_expirations += 1;
            }
        }
    }

    g.stats.total_misses += 1;
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_put_and_get() {
        let cache = FederationCache::new(100, 1_000_000);
        let args = json!({"path": "/tmp/foo"});
        let resp = json!({"content": "hello"});
        cache.put("file_read", &args, resp.clone(), false);
        let hit = get_cached(&cache, "file_read", &args).unwrap();
        assert_eq!(hit.value, resp);
    }

    #[test]
    fn test_miss_returns_none() {
        let cache = FederationCache::new(100, 1_000_000);
        let args = json!({"path": "/tmp/bar"});
        assert!(get_cached(&cache, "file_read", &args).is_none());
    }

    #[test]
    fn test_hit_count_incremented() {
        let cache = FederationCache::new(100, 1_000_000);
        let args = json!({"x": 1});
        cache.put("tool", &args, json!("result"), false);
        get_cached(&cache, "tool", &args);
        get_cached(&cache, "tool", &args);
        let stats = cache.stats();
        assert_eq!(stats.total_hits, 2);
    }

    #[test]
    fn test_policy_disabled_no_cache() {
        let cache = FederationCache::new(100, 1_000_000);
        cache.set_policy("no_cache_tool", CachePolicy::disabled());
        cache.put("no_cache_tool", &json!({}), json!("x"), false);
        assert!(get_cached(&cache, "no_cache_tool", &json!({})).is_none());
    }

    #[test]
    fn test_invalidate_tool() {
        let cache = FederationCache::new(100, 1_000_000);
        cache.put("tool_a", &json!({"k": 1}), json!("v1"), false);
        cache.put("tool_a", &json!({"k": 2}), json!("v2"), false);
        cache.put("tool_b", &json!({}), json!("bv"), false);
        cache.invalidate_tool("tool_a");
        assert!(get_cached(&cache, "tool_a", &json!({"k": 1})).is_none());
        assert!(get_cached(&cache, "tool_b", &json!({})).is_some());
    }

    #[test]
    fn test_clear() {
        let cache = FederationCache::new(100, 1_000_000);
        cache.put("t", &json!({}), json!("x"), false);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_error_not_cached_by_default() {
        let cache = FederationCache::new(100, 1_000_000);
        cache.put("t", &json!({}), json!({"error": "oops"}), true);
        assert!(get_cached(&cache, "t", &json!({})).is_none());
    }

    #[test]
    fn test_cache_key_display() {
        let k = CacheKey::from_args("tool", &json!({"a": 1}));
        let s = format!("{k}");
        assert!(s.starts_with("tool:"));
    }

    #[test]
    fn test_lru_eviction_at_capacity() {
        let cache = FederationCache::new(2, 1_000_000);
        cache.put("t", &json!(1), json!("a"), false);
        cache.put("t", &json!(2), json!("b"), false);
        cache.put("t", &json!(3), json!("c"), false); // triggers eviction of entry 1
        // Entry 1 should have been evicted.
        assert!(get_cached(&cache, "t", &json!(1)).is_none());
        assert!(get_cached(&cache, "t", &json!(2)).is_some() || get_cached(&cache, "t", &json!(3)).is_some());
    }

    #[test]
    fn test_stats_miss_count() {
        let cache = FederationCache::new(100, 1_000_000);
        get_cached(&cache, "t", &json!({}));
        get_cached(&cache, "t", &json!({}));
        assert_eq!(cache.stats().total_misses, 2);
    }

    #[test]
    fn test_hit_rate_zero_when_no_requests() {
        let stats = CacheStats::default();
        assert_eq!(stats.hit_rate(), 0.0);
    }

    #[test]
    fn test_cache_entry_display() {
        let key = CacheKey::from_args("tool", &json!({}));
        let entry = CacheEntry::new(key, json!("val"), 60, false);
        let s = format!("{entry}");
        assert!(s.contains("tool:"));
    }
}
