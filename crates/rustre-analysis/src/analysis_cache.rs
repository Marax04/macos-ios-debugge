//! Analysis result cache.
//!
//! [`AnalysisCache`] stores the results of completed analysis passes keyed by
//! a [`CacheKey`] so that re-analysis can be skipped when the binary has not
//! changed.
//!
//! The cache supports:
//! - Keying by pass name + binary URI + content hash.
//! - TTL-based expiry (optional).
//! - Targeted invalidation by function address, pass name, or URI.
//! - Eviction by LRU when the entry count exceeds a configurable cap.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────────────────────
// CacheKey
// ─────────────────────────────────────────────────────────────────────────────

/// The key that uniquely identifies a cached analysis result.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// The analysis pass that produced this result.
    pub pass_name: String,
    /// The binary URI.
    pub uri: String,
    /// A hash of the binary content at the time of analysis.
    pub content_hash: u64,
}

impl CacheKey {
    /// Create a new [`CacheKey`].
    #[must_use]
    pub fn new(pass_name: impl Into<String>, uri: impl Into<String>, content_hash: u64) -> Self {
        Self {
            pass_name: pass_name.into(),
            uri: uri.into(),
            content_hash,
        }
    }

    /// Create a key with a content hash derived from the length of `data`.
    ///
    /// For production use, replace this with a proper hash (e.g. xxHash).
    #[must_use]
    pub fn from_data(pass_name: &str, uri: &str, data: &[u8]) -> Self {
        Self::new(pass_name, uri, compute_hash(data))
    }
}

impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{:#016x}",
            self.pass_name, self.uri, self.content_hash
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CacheEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single entry in the [`AnalysisCache`].
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The cache key.
    pub key: CacheKey,
    /// JSON-serialised analysis result payload.
    pub payload: String,
    /// When the entry was inserted.
    pub inserted_at: Instant,
    /// Optional TTL; the entry expires `ttl` after insertion.
    pub ttl: Option<Duration>,
    /// Access counter for LRU bookkeeping.
    pub access_count: u64,
    /// Time of last access.
    pub last_accessed: Instant,
    /// Pass-specific tags for targeted invalidation.
    pub tags: Vec<String>,
    /// Virtual address of the function this result covers, if applicable.
    pub function_address: Option<u64>,
}

impl CacheEntry {
    /// Create a new entry.
    #[must_use]
    pub fn new(key: CacheKey, payload: impl Into<String>) -> Self {
        let now = Instant::now();
        Self {
            key,
            payload: payload.into(),
            inserted_at: now,
            ttl: None,
            access_count: 0,
            last_accessed: now,
            tags: Vec::new(),
            function_address: None,
        }
    }

    /// Set the TTL.
    #[must_use]
    pub const fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Associate the entry with a function at `address`.
    #[must_use]
    pub const fn for_function(mut self, address: u64) -> Self {
        self.function_address = Some(address);
        self
    }

    /// Add a tag for targeted invalidation.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        self.tags.push(tag.into());
    }

    /// Return `true` if the entry has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.ttl.is_some_and(|ttl| self.inserted_at.elapsed() > ttl)
    }

    /// Age of the entry.
    #[must_use]
    pub fn age(&self) -> Duration {
        self.inserted_at.elapsed()
    }

    /// Record an access: increment counter and update `last_accessed`.
    fn touch(&mut self) {
        self.access_count += 1;
        self.last_accessed = Instant::now();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CacheStats
// ─────────────────────────────────────────────────────────────────────────────

/// Runtime statistics for the cache.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Successful lookups.
    pub hits: u64,
    /// Failed lookups.
    pub misses: u64,
    /// Entries evicted by LRU.
    pub evictions: u64,
    /// Entries invalidated explicitly.
    pub invalidations: u64,
    /// Entries that expired by TTL.
    pub expirations: u64,
    /// Total insertions.
    pub insertions: u64,
}

impl CacheStats {
    /// Hit rate 0.0–1.0.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.hits).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
        }
    }
}

impl fmt::Display for CacheStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CacheStats {{ hits={}, misses={}, evictions={}, invalidations={}, hit_rate={:.1}% }}",
            self.hits,
            self.misses,
            self.evictions,
            self.invalidations,
            self.hit_rate() * 100.0
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisCache
// ─────────────────────────────────────────────────────────────────────────────

/// An in-process LRU cache for analysis pass results.
///
/// Entries are keyed by [`CacheKey`] and stored as JSON-serialised strings.
/// The cache evicts the least-recently-used entries when `max_entries` is
/// exceeded.
pub struct AnalysisCache {
    entries: HashMap<CacheKey, CacheEntry>,
    /// Maximum number of entries before LRU eviction.
    max_entries: usize,
    /// Default TTL for new entries.
    default_ttl: Option<Duration>,
    /// Runtime statistics.
    pub stats: CacheStats,
}

impl fmt::Debug for AnalysisCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AnalysisCache")
            .field("entry_count", &self.entries.len())
            .field("max_entries", &self.max_entries)
            .finish_non_exhaustive()
    }
}

impl AnalysisCache {
    /// Create a new cache with the given capacity.
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            default_ttl: None,
            stats: CacheStats::default(),
        }
    }

    /// Set the default TTL applied to all new entries.
    #[must_use]
    pub const fn with_default_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = Some(ttl);
        self
    }

    // ── Insertion ─────────────────────────────────────────────────────────────

    /// Insert a new entry.  Returns the evicted entry's key if LRU eviction
    /// occurred.
    pub fn insert(&mut self, mut entry: CacheEntry) -> Option<CacheKey> {
        // Apply default TTL if the entry doesn't have its own
        if entry.ttl.is_none() {
            entry.ttl = self.default_ttl;
        }

        // If the entry already exists, replace it.
        if self.entries.contains_key(&entry.key) {
            self.entries.insert(entry.key.clone(), entry);
            self.stats.insertions += 1;
            return None;
        }

        // Evict LRU if at capacity
        let evicted = if self.entries.len() >= self.max_entries {
            self.evict_lru()
        } else {
            None
        };

        self.entries.insert(entry.key.clone(), entry);
        self.stats.insertions += 1;
        evicted
    }

    /// Insert a raw payload string directly.
    pub fn put(&mut self, key: CacheKey, payload: impl Into<String>) -> Option<CacheKey> {
        self.insert(CacheEntry::new(key, payload))
    }

    // ── Retrieval ─────────────────────────────────────────────────────────────

    /// Look up an entry by key.
    ///
    /// Returns `None` if the entry does not exist or has expired.
    pub fn get(&mut self, key: &CacheKey) -> Option<&CacheEntry> {
        // Check for expiry first.
        if let Some(entry) = self.entries.get(key)
            && entry.is_expired() {
                self.entries.remove(key);
                self.stats.misses += 1;
                self.stats.expirations += 1;
                return None;
            }

        if let Some(entry) = self.entries.get_mut(key) {
            entry.touch();
            self.stats.hits += 1;
            Some(entry)
        } else {
            self.stats.misses += 1;
            None
        }
    }

    /// Peek at an entry without updating access metadata.
    #[must_use]
    pub fn peek(&self, key: &CacheKey) -> Option<&CacheEntry> {
        let entry = self.entries.get(key)?;
        if entry.is_expired() {
            None
        } else {
            Some(entry)
        }
    }

    /// Return `true` if the cache contains a non-expired entry for `key`.
    #[must_use]
    pub fn contains(&self, key: &CacheKey) -> bool {
        self.peek(key).is_some()
    }

    // ── Invalidation ─────────────────────────────────────────────────────────

    /// Remove the entry for `key`. Returns `true` if it existed.
    pub fn invalidate(&mut self, key: &CacheKey) -> bool {
        let removed = self.entries.remove(key).is_some();
        if removed {
            self.stats.invalidations += 1;
        }
        removed
    }

    /// Invalidate all entries for a given URI.
    pub fn invalidate_for_uri(&mut self, uri: &str) -> usize {
        let keys: Vec<CacheKey> = self
            .entries
            .keys()
            .filter(|k| k.uri == uri)
            .cloned()
            .collect();
        let count = keys.len();
        for k in keys {
            self.entries.remove(&k);
        }
        self.stats.invalidations += count as u64;
        count
    }

    /// Invalidate all entries produced by `pass_name`.
    pub fn invalidate_for_pass(&mut self, pass_name: &str) -> usize {
        let keys: Vec<CacheKey> = self
            .entries
            .keys()
            .filter(|k| k.pass_name == pass_name)
            .cloned()
            .collect();
        let count = keys.len();
        for k in keys {
            self.entries.remove(&k);
        }
        self.stats.invalidations += count as u64;
        count
    }

    /// Invalidate all entries associated with a specific function address.
    pub fn invalidate_for_function(&mut self, address: u64) -> usize {
        let keys: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|(_, e)| e.function_address == Some(address))
            .map(|(k, _)| k.clone())
            .collect();
        let count = keys.len();
        for k in keys {
            self.entries.remove(&k);
        }
        self.stats.invalidations += count as u64;
        count
    }

    /// Invalidate all entries carrying `tag`.
    pub fn invalidate_by_tag(&mut self, tag: &str) -> usize {
        let keys: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|(_, e)| e.tags.iter().any(|t| t == tag))
            .map(|(k, _)| k.clone())
            .collect();
        let count = keys.len();
        for k in keys {
            self.entries.remove(&k);
        }
        self.stats.invalidations += count as u64;
        count
    }

    /// Remove all expired entries. Returns the number removed.
    pub fn evict_expired(&mut self) -> usize {
        let keys: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|(_, e)| e.is_expired())
            .map(|(k, _)| k.clone())
            .collect();
        let count = keys.len();
        for k in keys {
            self.entries.remove(&k);
        }
        self.stats.expirations += count as u64;
        count
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        let count = self.entries.len() as u64;
        self.entries.clear();
        self.stats.invalidations += count;
    }

    // ── LRU eviction ─────────────────────────────────────────────────────────

    fn evict_lru(&mut self) -> Option<CacheKey> {
        // Find the entry with the smallest access_count (then oldest last_accessed)
        // `entries` is a HashMap, and BOTH parts of the key tie easily: access
        // counts are small integers and `last_accessed` is coarse. Without a
        // tie-break on the key itself the evicted entry differs between runs on
        // identical input. `CacheKey` does not derive `Ord`, so order on its
        // public fields.
        let lru_key = self
            .entries
            .iter()
            .min_by(|a, b| {
                (a.1.access_count, a.1.last_accessed)
                    .cmp(&(b.1.access_count, b.1.last_accessed))
                    .then_with(|| a.0.content_hash.cmp(&b.0.content_hash))
                    .then_with(|| a.0.pass_name.cmp(&b.0.pass_name))
                    .then_with(|| a.0.uri.cmp(&b.0.uri))
            })
            .map(|(k, _)| k.clone())?;
        self.entries.remove(&lru_key);
        self.stats.evictions += 1;
        Some(lru_key)
    }

    // ── Metrics ───────────────────────────────────────────────────────────────

    /// Number of entries currently in the cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Return `true` if the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Maximum capacity.
    #[must_use]
    pub const fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Return the current fill ratio (0.0–1.0).
    #[must_use]
    pub fn fill_ratio(&self) -> f64 {
        if self.max_entries == 0 {
            return 1.0;
        }
        f64::from(u32::try_from(self.entries.len()).unwrap_or(u32::MAX))
            / f64::from(u32::try_from(self.max_entries).unwrap_or(u32::MAX))
    }

    /// Return all keys currently in the cache.
    #[must_use]
    pub fn keys(&self) -> Vec<&CacheKey> {
        self.entries.keys().collect()
    }
}

impl Default for AnalysisCache {
    fn default() -> Self {
        Self::new(1024)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// compute_hash — simple FNV-1a hash
// ─────────────────────────────────────────────────────────────────────────────

/// Compute a 64-bit FNV-1a hash of `data`.
///
/// Used for content-based cache keying.  Not cryptographically secure.
#[must_use]
pub fn compute_hash(data: &[u8]) -> u64 {
    const OFFSET: u64 = 14_695_981_039_346_656_037;
    const PRIME: u64 = 1_099_511_628_211;
    let mut hash = OFFSET;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(pass: &str) -> CacheKey {
        CacheKey::new(pass, "file.bin", 0xDEAD_BEEF)
    }

    #[test]
    fn test_insert_and_get() {
        let mut cache = AnalysisCache::new(10);
        let key = make_key("linear_sweep");
        cache.put(key.clone(), r#"{"functions":5}"#);
        let entry = cache.get(&key).unwrap();
        assert_eq!(entry.payload, r#"{"functions":5}"#);
    }

    #[test]
    fn test_miss_increments_stat() {
        let mut cache = AnalysisCache::new(10);
        let key = make_key("ghost");
        assert!(cache.get(&key).is_none());
        assert_eq!(cache.stats.misses, 1);
    }

    #[test]
    fn test_hit_increments_stat() {
        let mut cache = AnalysisCache::new(10);
        let key = make_key("pass");
        cache.put(key.clone(), "data");
        cache.get(&key);
        assert_eq!(cache.stats.hits, 1);
    }

    #[test]
    fn test_ttl_expiry() {
        let mut cache = AnalysisCache::new(10);
        let key = make_key("ttl_pass");
        let entry = CacheEntry::new(key.clone(), "payload").with_ttl(Duration::from_nanos(1));
        cache.insert(entry);
        // Wait a tiny bit so the entry expires (1 ns TTL)
        std::thread::sleep(Duration::from_millis(1));
        assert!(cache.get(&key).is_none());
        assert_eq!(cache.stats.expirations, 1);
    }

    #[test]
    fn test_lru_eviction() {
        let mut cache = AnalysisCache::new(2);
        cache.put(make_key("A"), "a");
        cache.put(make_key("B"), "b");
        // Access A to make it more recently used
        cache.get(&make_key("A"));
        // Insert C — should evict B (LRU)
        cache.put(make_key("C"), "c");
        assert_eq!(cache.len(), 2);
        assert!(cache.contains(&make_key("A")));
        assert!(!cache.contains(&make_key("B")));
        assert!(cache.contains(&make_key("C")));
        assert_eq!(cache.stats.evictions, 1);
    }

    #[test]
    fn test_invalidate_by_key() {
        let mut cache = AnalysisCache::new(10);
        let key = make_key("P");
        cache.put(key.clone(), "data");
        assert!(cache.invalidate(&key));
        assert!(cache.get(&key).is_none());
        assert_eq!(cache.stats.invalidations, 1);
    }

    #[test]
    fn test_invalidate_for_uri() {
        let mut cache = AnalysisCache::new(10);
        cache.put(CacheKey::new("P1", "file.bin", 1), "a");
        cache.put(CacheKey::new("P2", "file.bin", 1), "b");
        cache.put(CacheKey::new("P3", "other.bin", 1), "c");
        let n = cache.invalidate_for_uri("file.bin");
        assert_eq!(n, 2);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_invalidate_for_pass() {
        let mut cache = AnalysisCache::new(10);
        cache.put(CacheKey::new("sweep", "a.bin", 1), "x");
        cache.put(CacheKey::new("sweep", "b.bin", 1), "y");
        cache.put(CacheKey::new("xref", "a.bin", 1), "z");
        let n = cache.invalidate_for_pass("sweep");
        assert_eq!(n, 2);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_invalidate_for_function() {
        let mut cache = AnalysisCache::new(10);
        let key = make_key("type_recovery");
        let entry = CacheEntry::new(key.clone(), "payload").for_function(0x4000);
        cache.insert(entry);
        let n = cache.invalidate_for_function(0x4000);
        assert_eq!(n, 1);
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn test_invalidate_by_tag() {
        let mut cache = AnalysisCache::new(10);
        let mut entry = CacheEntry::new(make_key("P"), "data");
        entry.add_tag("incremental");
        cache.insert(entry);
        cache.put(make_key("Q"), "no-tag");
        let n = cache.invalidate_by_tag("incremental");
        assert_eq!(n, 1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_evict_expired() {
        let mut cache = AnalysisCache::new(10);
        let entry =
            CacheEntry::new(make_key("old"), "data").with_ttl(Duration::from_nanos(1));
        cache.insert(entry);
        cache.put(make_key("fresh"), "data2");
        std::thread::sleep(Duration::from_millis(1));
        let removed = cache.evict_expired();
        assert_eq!(removed, 1);
        assert!(cache.contains(&make_key("fresh")));
    }

    #[test]
    fn test_fill_ratio() {
        let mut cache = AnalysisCache::new(4);
        cache.put(make_key("A"), "a");
        cache.put(make_key("B"), "b");
        assert!((cache.fill_ratio() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_compute_hash_deterministic() {
        let h1 = compute_hash(b"hello");
        let h2 = compute_hash(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_hash_different_data() {
        let h1 = compute_hash(b"hello");
        let h2 = compute_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_contains_no_expired() {
        let mut cache = AnalysisCache::new(10);
        let entry = CacheEntry::new(make_key("E"), "d").with_ttl(Duration::from_nanos(1));
        cache.insert(entry);
        std::thread::sleep(Duration::from_millis(1));
        assert!(!cache.contains(&make_key("E")));
    }

    #[test]
    fn test_clear() {
        let mut cache = AnalysisCache::new(10);
        cache.put(make_key("A"), "a");
        cache.put(make_key("B"), "b");
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_stats_hit_rate() {
        let mut stats = CacheStats::default();
        stats.hits = 3;
        stats.misses = 1;
        assert!((stats.hit_rate() - 0.75).abs() < 1e-9);
    }

    #[test]
    fn test_peek_no_side_effects() {
        let mut cache = AnalysisCache::new(10);
        cache.put(make_key("P"), "data");
        let before_hits = cache.stats.hits;
        let _ = cache.peek(&make_key("P"));
        assert_eq!(cache.stats.hits, before_hits);
    }
}
