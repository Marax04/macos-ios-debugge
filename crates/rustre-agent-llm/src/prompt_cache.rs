//! LLM prompt/response cache with TTL-based eviction.
//!
//! Caches LLM prompts and their responses by a content hash of the prompt,
//! so repeated identical prompts hit the cache instead of making network calls.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rustre_agent::casts::u64_to_f64;

// ── CacheKey ──────────────────────────────────────────────────────────────────

/// Content-hash key for a cached prompt.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey(pub u64);

impl CacheKey {
    /// Compute a key from an arbitrary prompt string using FNV-1a.
    #[must_use]
    pub fn from_prompt(prompt: &str) -> Self {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in prompt.bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
        }
        Self(hash)
    }

    /// Compute a key from prompt + model identifier.
    #[must_use]
    pub fn from_prompt_and_model(prompt: &str, model: &str) -> Self {
        let combined = format!("{model}::{prompt}");
        Self::from_prompt(&combined)
    }
}

impl std::fmt::Display for CacheKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CacheKey({:#018x})", self.0)
    }
}

// ── CacheEntry ────────────────────────────────────────────────────────────────

/// A single cached LLM exchange.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The original prompt text.
    pub prompt: String,
    /// The LLM response text.
    pub response: String,
    /// Number of prompt tokens reported by the model.
    pub prompt_tokens: u32,
    /// Number of completion tokens reported by the model.
    pub completion_tokens: u32,
    /// Model identifier (e.g. `"gpt-4o"`).
    pub model: String,
    /// Wall-clock time when the entry was inserted.
    pub created_at: Instant,
    /// Number of times this entry has been retrieved from the cache.
    pub hit_count: u64,
}

impl CacheEntry {
    /// Create a new entry.
    #[must_use]
    pub fn new(
        prompt: impl Into<String>,
        response: impl Into<String>,
        prompt_tokens: u32,
        completion_tokens: u32,
        model: impl Into<String>,
    ) -> Self {
        Self {
            prompt: prompt.into(),
            response: response.into(),
            prompt_tokens,
            completion_tokens,
            model: model.into(),
            created_at: Instant::now(),
            hit_count: 0,
        }
    }

    /// Total tokens used.
    #[must_use]
    pub const fn total_tokens(&self) -> u32 {
        self.prompt_tokens + self.completion_tokens
    }

    /// Return `true` if this entry has expired given the TTL.
    #[must_use]
    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed() >= ttl
    }

    /// Age of the entry.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }
}

// ── CacheStats ────────────────────────────────────────────────────────────────

/// Aggregate statistics for a [`PromptCache`] instance.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Total cache lookup attempts.
    pub lookups: u64,
    /// Successful cache hits.
    pub hits: u64,
    /// Cache misses.
    pub misses: u64,
    /// Number of entries evicted due to TTL expiry.
    pub evictions: u64,
    /// Total prompt tokens served from cache (not re-generated).
    pub saved_prompt_tokens: u64,
    /// Total completion tokens served from cache.
    pub saved_completion_tokens: u64,
}

impl CacheStats {
    /// Hit ratio in [0, 1].
    #[must_use]
    pub fn hit_ratio(&self) -> f64 {
        if self.lookups == 0 {
            0.0
        } else {
            u64_to_f64(self.hits) / u64_to_f64(self.lookups)
        }
    }

    /// Total tokens saved by cache hits.
    #[must_use]
    pub const fn total_saved_tokens(&self) -> u64 {
        self.saved_prompt_tokens + self.saved_completion_tokens
    }
}

impl std::fmt::Display for CacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CacheStats(lookups={} hits={} misses={} evictions={} saved_tokens={} hit_ratio={:.1}%)",
            self.lookups,
            self.hits,
            self.misses,
            self.evictions,
            self.total_saved_tokens(),
            self.hit_ratio() * 100.0,
        )
    }
}

// ── PromptCache ───────────────────────────────────────────────────────────────

/// Cache LLM prompts and their responses, with TTL-based eviction.
pub struct PromptCache {
    entries: HashMap<CacheKey, CacheEntry>,
    /// Maximum number of entries before evicting the oldest.
    pub max_entries: usize,
    /// Time-to-live for each entry.
    pub ttl: Duration,
    /// Running statistics.
    pub stats: CacheStats,
}

impl PromptCache {
    /// Create a new cache with the given capacity and TTL.
    #[must_use]
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            ttl,
            stats: CacheStats::default(),
        }
    }

    /// Create with a 1-hour TTL and 1 000 entry limit.
    #[must_use]
    pub fn default_cache() -> Self {
        Self::new(1000, Duration::from_hours(1))
    }

    /// Insert a new cache entry.  If the cache is full the oldest entry is evicted.
    pub fn insert(&mut self, key: CacheKey, entry: CacheEntry) {
        // Evict expired entries first.
        self.evict_expired();
        // If still full, evict the oldest insertion.
        if self.entries.len() >= self.max_entries
            && let Some(oldest_key) = self
                .entries
                .iter()
                // `entries` is a HashMap and timestamps collide easily (coarse
                // clock, rapid inserts), so without a tie-break on the key the
                // victim of an eviction differs between runs on identical input.
                .min_by(|a, b| a.1.created_at.cmp(&b.1.created_at).then(a.0.0.cmp(&b.0.0)))
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest_key);
                self.stats.evictions += 1;
            }
        self.entries.insert(key, entry);
    }

    /// Look up a cached response.  Marks a hit or miss and increments the entry
    /// hit counter.  Returns `None` if not found or if the entry has expired.
    pub fn get(&mut self, key: &CacheKey) -> Option<&CacheEntry> {
        self.stats.lookups += 1;
        // Evict if expired
        let expired = self
            .entries
            .get(key)
            .is_some_and(|e| e.is_expired(self.ttl));
        if expired {
            self.entries.remove(key);
            self.stats.misses += 1;
            self.stats.evictions += 1;
            return None;
        }
        if let Some(entry) = self.entries.get_mut(key) {
            self.stats.hits += 1;
            self.stats.saved_prompt_tokens += u64::from(entry.prompt_tokens);
            self.stats.saved_completion_tokens += u64::from(entry.completion_tokens);
            entry.hit_count += 1;
            // Re-borrow immutably for return
            return self.entries.get(key);
        }
        self.stats.misses += 1;
        None
    }

    /// Remove all entries whose TTL has elapsed.
    pub fn evict_expired(&mut self) {
        let ttl = self.ttl;
        let before = self.entries.len();
        self.entries.retain(|_, e| !e.is_expired(ttl));
        let evicted = before.saturating_sub(self.entries.len());
        self.stats.evictions += evicted as u64;
    }

    /// Remove all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Return the number of live entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the cache has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return whether `key` is present (and not expired).
    #[must_use]
    pub fn contains(&self, key: &CacheKey) -> bool {
        self.entries
            .get(key)
            .is_some_and(|e| !e.is_expired(self.ttl))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(prompt: &str, response: &str) -> CacheEntry {
        CacheEntry::new(prompt, response, 10, 20, "gpt-4o")
    }

    #[test]
    fn test_cache_key_from_prompt_deterministic() {
        let k1 = CacheKey::from_prompt("hello world");
        let k2 = CacheKey::from_prompt("hello world");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_cache_key_different_prompts_differ() {
        let k1 = CacheKey::from_prompt("foo");
        let k2 = CacheKey::from_prompt("bar");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_cache_key_includes_model() {
        let k1 = CacheKey::from_prompt_and_model("q", "gpt-4o");
        let k2 = CacheKey::from_prompt_and_model("q", "claude-3");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_cache_entry_total_tokens() {
        let e = make_entry("p", "r");
        assert_eq!(e.total_tokens(), 30);
    }

    #[test]
    fn test_cache_insert_and_get() {
        let mut cache = PromptCache::new(10, Duration::from_secs(60));
        let key = CacheKey::from_prompt("what is 2+2?");
        cache.insert(key.clone(), make_entry("what is 2+2?", "4"));
        let entry = cache.get(&key).unwrap();
        assert_eq!(entry.response, "4");
    }

    #[test]
    fn test_cache_miss_returns_none() {
        let mut cache = PromptCache::default_cache();
        let key = CacheKey::from_prompt("not in cache");
        assert!(cache.get(&key).is_none());
        assert_eq!(cache.stats.misses, 1);
    }

    #[test]
    fn test_cache_hit_increments_stats() {
        let mut cache = PromptCache::new(10, Duration::from_secs(60));
        let key = CacheKey::from_prompt("test");
        cache.insert(key.clone(), make_entry("test", "resp"));
        cache.get(&key);
        assert_eq!(cache.stats.hits, 1);
        assert_eq!(cache.stats.saved_prompt_tokens, 10);
    }

    #[test]
    fn test_cache_evicts_when_full() {
        let mut cache = PromptCache::new(2, Duration::from_secs(60));
        for i in 0..3u64 {
            let key = CacheKey(i);
            cache.insert(key, make_entry("p", "r"));
        }
        assert_eq!(cache.len(), 2);
        assert!(cache.stats.evictions >= 1);
    }

    #[test]
    fn test_cache_clear() {
        let mut cache = PromptCache::new(10, Duration::from_secs(60));
        cache.insert(CacheKey::from_prompt("a"), make_entry("a", "b"));
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_stats_hit_ratio() {
        let stats = CacheStats {
            lookups: 10,
            hits: 7,
            ..CacheStats::default()
        };
        let ratio = stats.hit_ratio();
        assert!((ratio - 0.7).abs() < 1e-9);
        let s = stats.to_string();
        assert!(s.contains("lookups=10"));
    }

    #[test]
    fn test_cache_expired_entry_is_miss() {
        let mut cache = PromptCache::new(10, Duration::from_nanos(1)); // instant TTL
        let key = CacheKey::from_prompt("stale");
        cache.insert(key.clone(), make_entry("stale", "old"));
        std::thread::sleep(Duration::from_millis(2));
        let result = cache.get(&key);
        assert!(result.is_none());
    }
}
