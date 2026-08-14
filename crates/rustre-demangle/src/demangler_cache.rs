//! LRU cache for demangled names, batch demangling with rayon,
//! statistics, and TTL-based eviction.

use ahash::AHashMap;
use anyhow::Result;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

// ── Generic LRU core ──────────────────────────────────────────────────────────

/// The one shared LRU engine: a map plus a lazily-compacted recency queue.
///
/// Each access stamps its entry with a monotonically increasing tick and pushes
/// `(key, tick)` onto the front of the queue; queue records whose tick no longer
/// matches the map are stale and are discarded during eviction or compaction.
/// This makes hits and inserts amortized O(1), where a strict
/// "remove-from-middle" recency list would cost O(n) per hit.
///
/// Callers that never promote (i.e. only ever use [`LruCore::peek`] and
/// [`LruCore::insert_keep_order`]) get plain insertion-order (FIFO) eviction,
/// because ticks then increase in insertion order.
pub(crate) struct LruCore<V> {
    capacity: usize,
    // AHashMap: keys are untrusted mangled symbols; dos-hash-collision guard.
    map: AHashMap<String, (V, u64)>,
    /// Recency queue: front = most recent. May contain stale `(key, tick)` pairs.
    order: VecDeque<(String, u64)>,
    tick: u64,
}

impl<V> LruCore<V> {
    /// Create an empty core holding at most `capacity` entries.
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            map: AHashMap::with_capacity(capacity.min(1024)),
            order: VecDeque::with_capacity(capacity.min(1024)),
            tick: 0,
        }
    }

    /// Look up `key` without altering recency.
    pub(crate) fn peek(&self, key: &str) -> Option<&V> {
        self.map.get(key).map(|(v, _)| v)
    }

    /// Look up `key` mutably, promoting it to most-recently-used on a hit.
    pub(crate) fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        if !self.map.contains_key(key) {
            return None;
        }
        self.promote(key);
        self.map.get_mut(key).map(|(v, _)| v)
    }

    /// Insert or update `key`, promoting it and evicting the true-LRU entry
    /// (skipping stale queue records) once at capacity.
    pub(crate) fn insert(&mut self, key: String, value: V) {
        if let Some(slot) = self.map.get_mut(&key) {
            slot.0 = value;
            self.promote(&key);
            return;
        }
        self.evict_to_fit();
        self.tick += 1;
        self.order.push_front((key.clone(), self.tick));
        self.map.insert(key, (value, self.tick));
    }

    /// Insert or update `key` **without** changing its recency position.
    ///
    /// Used by the caches whose documented contract is insertion-order eviction.
    pub(crate) fn insert_keep_order(&mut self, key: String, value: V) {
        if let Some(slot) = self.map.get_mut(&key) {
            slot.0 = value;
            return;
        }
        self.evict_to_fit();
        self.tick += 1;
        self.order.push_front((key.clone(), self.tick));
        self.map.insert(key, (value, self.tick));
    }

    /// Drop true-LRU entries until there is room for one more.
    fn evict_to_fit(&mut self) {
        while self.map.len() >= self.capacity {
            match self.order.pop_back() {
                Some((lru_key, tick)) => {
                    if self.map.get(&lru_key).is_some_and(|&(_, t)| t == tick) {
                        self.map.remove(&lru_key);
                    }
                    // else: stale record for a since-promoted key; skip.
                }
                None => break,
            }
        }
    }

    /// Stamp `key` as most-recent (amortized O(1); stale queue records are
    /// discarded lazily by eviction or by the compaction below).
    fn promote(&mut self, key: &str) {
        self.tick += 1;
        let tick = self.tick;
        if let Some(slot) = self.map.get_mut(key) {
            slot.1 = tick;
        }
        self.order.push_front((key.to_owned(), tick));
        // Bound queue growth: compact once stale records dominate.
        if self.order.len() > self.capacity.saturating_mul(2) + 16 {
            let map = &self.map;
            self.order
                .retain(|(k, t)| map.get(k).is_some_and(|&(_, mt)| mt == *t));
        }
    }

    /// Remove `key`, returning its value if present.
    pub(crate) fn remove(&mut self, key: &str) -> Option<V> {
        let removed = self.map.remove(key).map(|(v, _)| v);
        if removed.is_some() {
            self.order.retain(|(k, _)| k != key);
        }
        removed
    }

    /// Iterate over live `(key, value)` pairs in unspecified order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&String, &V)> {
        self.map.iter().map(|(k, (v, _))| (k, v))
    }

    /// Number of live entries.
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns `true` if the core holds no entries.
    pub(crate) fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Remove all entries and recency records.
    pub(crate) fn clear(&mut self) {
        self.map.clear();
        self.order.clear();
    }
}

// ── Cache Entry ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CacheEntry {
    demangled: String,
    hits: u64,
    inserted_at: Instant,
    last_accessed: Instant,
}

impl CacheEntry {
    fn new(demangled: String) -> Self {
        let now = Instant::now();
        Self {
            demangled,
            hits: 1,
            inserted_at: now,
            last_accessed: now,
        }
    }

    fn access(&mut self) -> &str {
        self.hits += 1;
        self.last_accessed = Instant::now();
        &self.demangled
    }

    fn age(&self) -> Duration {
        self.inserted_at.elapsed()
    }
}

// ── LRU Cache ─────────────────────────────────────────────────────────────────

/// An LRU cache backed by a `HashMap` plus a lazily-compacted recency queue.
///
/// Each access stamps the entry with a monotonically increasing tick and
/// pushes `(key, tick)` on the queue; stale queue entries (whose tick no
/// longer matches the map) are discarded during eviction/compaction. This
/// makes both hits and inserts amortized O(1), where a strict
/// "remove-from-middle" queue would cost O(n) per hit.
pub struct LruCache {
    core: LruCore<CacheEntry>,
    ttl: Option<Duration>,
}

impl LruCache {
    /// Create an empty cache holding at most `capacity` entries, with no TTL.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            core: LruCore::new(capacity),
            ttl: None,
        }
    }

    /// Builder: set a time-to-live after which entries are treated as expired.
    #[must_use]
    pub const fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Look up `key`, promoting it to most-recently-used on a hit.
    ///
    /// Expired entries (past the TTL) are removed and reported as a miss.
    /// Amortized O(1): promotion pushes a fresh tick instead of removing
    /// the old queue record.
    pub fn get(&mut self, key: &str) -> Option<&str> {
        // Check TTL
        if let Some(ttl) = self.ttl
            && let Some(entry) = self.core.peek(key)
            && entry.age() > ttl {
            self.core.remove(key);
            return None;
        }

        self.core.get_mut(key).map(CacheEntry::access)
    }

    /// Insert or update `key`, evicting true-LRU entries once at capacity.
    ///
    /// Amortized O(1): eviction skips stale queue records left behind by
    /// promotions rather than searching the queue.
    pub fn insert(&mut self, key: String, value: String) {
        if let Some(entry) = self.core.get_mut(&key) {
            entry.demangled = value;
            return;
        }
        self.core.insert(key, CacheEntry::new(value));
    }

    /// Number of live entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.core.len()
    }

    /// Returns `true` if the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.core.is_empty()
    }

    /// Remove all entries and recency records.
    pub fn clear(&mut self) {
        self.core.clear();
    }

    /// Evict all entries older than `ttl`.
    pub fn evict_expired(&mut self) {
        if let Some(ttl) = self.ttl {
            let expired: Vec<String> = self
                .core
                .iter()
                .filter(|(_, e)| e.age() > ttl)
                .map(|(k, _)| k.clone())
                .collect();
            for key in expired {
                self.core.remove(&key);
            }
        }
    }

    /// Top N most-hit entries.
    #[must_use]
    pub fn top_entries(&self, n: usize) -> Vec<(String, u64)> {
        let mut pairs: Vec<(String, u64)> = self
            .core
            .iter()
            .map(|(k, e)| (k.clone(), e.hits))
            .collect();
        pairs.sort_unstable_by_key(|&(_, hits)| std::cmp::Reverse(hits));
        pairs.truncate(n);
        pairs
    }
}

// ── Cache Statistics ──────────────────────────────────────────────────────────

/// Counters describing cache effectiveness.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CacheStats {
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Number of insertions performed.
    pub inserts: u64,
    /// Number of entries evicted.
    pub evictions: u64,
    /// Configured maximum entry count.
    pub capacity: usize,
    /// Current number of live entries.
    pub current_size: usize,
    /// Hit rate as a percentage of all lookups (0-100).
    pub hit_rate_pct: f64,
}

impl CacheStats {
    fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            f64::from(u32::try_from(self.hits).unwrap_or(u32::MAX))
                / f64::from(u32::try_from(total).unwrap_or(u32::MAX))
                * 100.0
        }
    }

    fn update_rate(&mut self) {
        self.hit_rate_pct = self.hit_rate();
    }
}

// ── Demangler function type ───────────────────────────────────────────────────

/// Shared demangling function: maps a mangled symbol to its demangled form,
/// or an error if the symbol cannot be decoded.
pub type DemanglerFn = Arc<dyn Fn(&str) -> Result<String> + Send + Sync>;

// ── Thread-safe Demangler Cache ───────────────────────────────────────────────

/// Thread-safe demangling cache: wraps a [`DemanglerFn`] (plus optional
/// fallback) behind a mutex-guarded [`LruCache`] with hit/miss statistics.
pub struct DemanglerCache {
    lru: Mutex<LruCache>,
    stats: Mutex<CacheStats>,
    demangle_fn: DemanglerFn,
    fallback: Option<DemanglerFn>,
}

impl DemanglerCache {
    /// Create a cache of at most `capacity` entries backed by `demangle_fn`.
    #[must_use]
    pub fn new(capacity: usize, demangle_fn: DemanglerFn) -> Self {
        let stats = CacheStats { capacity, ..Default::default() };
        Self {
            lru: Mutex::new(LruCache::new(capacity)),
            stats: Mutex::new(stats),
            demangle_fn,
            fallback: None,
        }
    }

    /// Builder: set a fallback demangler tried when the primary one fails.
    #[must_use]
    pub fn with_fallback(mut self, fallback: DemanglerFn) -> Self {
        self.fallback = Some(fallback);
        self
    }

    /// Builder: set a time-to-live on the underlying [`LruCache`].
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn with_ttl(self, ttl: Duration) -> Self {
        {
            let mut lru = self.lru.lock().unwrap();
            lru.ttl = Some(ttl);
        }
        self
    }

    /// Demangle `symbol`, using cached result if available.
    ///
    /// # Panics
    /// Panics if an internal mutex is poisoned.
    pub fn demangle(&self, symbol: &str) -> String {
        // Try cache
        {
            let mut lru = self.lru.lock().unwrap();
            if let Some(cached) = lru.get(symbol) {
                let s = cached.to_owned();
                drop(lru);
                let mut stats = self.stats.lock().unwrap();
                stats.hits += 1;
                stats.update_rate();
                drop(stats);
                return s;
            }
        }

        // Cache miss — call demangler
        {
            let mut stats = self.stats.lock().unwrap();
            stats.misses += 1;
        }

        let result = (self.demangle_fn)(symbol)
            .or_else(|_| {
                self.fallback.as_ref().map_or_else(
                    || Err(anyhow::anyhow!("No fallback")),
                    |fb| (fb)(symbol),
                )
            })
            .unwrap_or_else(|_| symbol.to_owned());

        {
            // Always acquire locks in the order stats → lru to match the
            // ordering in stats() and prevent potential deadlock.
            let mut stats = self.stats.lock().unwrap();
            let mut lru = self.lru.lock().unwrap();
            lru.insert(symbol.to_owned(), result.clone());
            stats.inserts += 1;
            stats.current_size = lru.len();
        }

        result
    }

    /// Snapshot of the current [`CacheStats`] (hit rate recomputed).
    ///
    /// # Panics
    /// Panics if an internal mutex is poisoned.
    pub fn stats(&self) -> CacheStats {
        // Acquire in order stats → lru (same as demangle()).
        let mut s = self.stats.lock().unwrap().clone();
        let size = self.lru.lock().unwrap().len();
        s.current_size = size;
        s.update_rate();
        s
    }

    /// Remove all cached entries and reset the current-size counter.
    ///
    /// # Panics
    /// Panics if an internal mutex is poisoned.
    pub fn clear(&self) {
        // Acquire in order stats → lru (consistent with demangle/stats).
        let mut stats = self.stats.lock().unwrap();
        self.lru.lock().unwrap().clear();
        stats.current_size = 0;
    }

    /// Evict all entries older than the configured TTL (no-op without a TTL).
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn evict_expired(&self) {
        self.lru.lock().unwrap().evict_expired();
    }

    /// Top `n` most-hit `(symbol, hits)` entries.
    ///
    /// # Panics
    /// Panics if the internal mutex is poisoned.
    pub fn top_entries(&self, n: usize) -> Vec<(String, u64)> {
        self.lru.lock().unwrap().top_entries(n)
    }
}

// ── Shared cache (Arc wrapper) ────────────────────────────────────────────────

/// A [`DemanglerCache`] shared across threads via [`Arc`].
pub type SharedDemanglerCache = Arc<DemanglerCache>;

/// Create a new [`SharedDemanglerCache`] with the given capacity and demangler.
pub fn new_shared_cache(capacity: usize, demangle_fn: DemanglerFn) -> SharedDemanglerCache {
    Arc::new(DemanglerCache::new(capacity, demangle_fn))
}

// ── Batch demangler ───────────────────────────────────────────────────────────

/// Outcome of demangling one symbol within [`batch_demangle`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResult {
    /// The original mangled symbol.
    pub symbol: String,
    /// The demangled form (equal to `symbol` when demangling failed).
    pub demangled: String,
    /// Whether the result was served from the cache.
    pub was_cached: bool,
    /// Whether demangling succeeded.
    pub succeeded: bool,
}

/// Demangle a batch of symbols in parallel using rayon.
/// Each symbol is first looked up in `cache` (write-locked per batch),
/// misses are demangled in parallel then inserted.
///
/// # Panics
/// Panics if the cache's internal mutex is poisoned.
pub fn batch_demangle(
    symbols: &[String],
    demangle_fn: &DemanglerFn,
    cache: Option<&SharedDemanglerCache>,
) -> Vec<BatchResult> {
    cache.map_or_else(
        || {
            // Pure parallel, no cache
            symbols
                .par_iter()
                .map(|sym| {
                    let (demangled, ok) = (demangle_fn)(sym)
                        .map_or_else(|_| (sym.clone(), false), |d| (d, true));
                    BatchResult {
                        symbol: sym.clone(),
                        demangled,
                        was_cached: false,
                        succeeded: ok,
                    }
                })
                .collect()
        },
        |c| {
            // Two-pass: check cache first (sequential), then demangle misses (parallel)
            let mut results: Vec<Option<BatchResult>> = vec![None; symbols.len()];
            let mut miss_indices: Vec<usize> = Vec::new();

            for (i, sym) in symbols.iter().enumerate() {
                let mut lru = c.lru.lock().unwrap();
                if let Some(demangled) = lru.get(sym) {
                    results[i] = Some(BatchResult {
                        symbol: sym.clone(),
                        demangled: demangled.to_owned(),
                        was_cached: true,
                        succeeded: true,
                    });
                } else {
                    miss_indices.push(i);
                }
            }

            // Parallel demangle of misses
            let miss_symbols: Vec<&str> =
                miss_indices.iter().map(|&i| symbols[i].as_str()).collect();
            let miss_results: Vec<BatchResult> = miss_symbols
                .par_iter()
                .map(|&sym| {
                    let (demangled, ok) = (demangle_fn)(sym)
                        .map_or_else(|_| (sym.to_owned(), false), |d| (d, true));
                    BatchResult {
                        symbol: sym.to_owned(),
                        demangled,
                        was_cached: false,
                        succeeded: ok,
                    }
                })
                .collect();

            // Insert misses into cache
            for result in &miss_results {
                let mut lru = c.lru.lock().unwrap();
                lru.insert(result.symbol.clone(), result.demangled.clone());
            }

            // Assemble final results
            let mut miss_iter = miss_results.into_iter();
            for i in &miss_indices {
                results[*i] = miss_iter.next();
            }

            results.into_iter().flatten().collect()
        },
    )
}

// ── Multi-ABI cache ───────────────────────────────────────────────────────────

/// A cache that tries multiple ABI demangling strategies in priority order.
pub struct MultiAbiCache {
    inner: DemanglerCache,
    abi_stats: Arc<RwLock<HashMap<String, u64>>>,
}

impl MultiAbiCache {
    /// Create a cache trying each `(abi_name, demangler)` strategy in order;
    /// the first success wins and increments that ABI's hit counter.
    #[must_use]
    pub fn new(capacity: usize, strategies: Vec<(&'static str, DemanglerFn)>) -> Self {
        let abi_names: Vec<String> = strategies.iter().map(|(n, _)| n.to_string()).collect();
        let strategy_arc: Vec<(String, DemanglerFn)> = strategies
            .into_iter()
            .map(|(n, f)| (n.to_string(), f))
            .collect();
        let strategy_arc = Arc::new(strategy_arc);

        let mut abi_stats_map = HashMap::new();
        for name in abi_names {
            abi_stats_map.insert(name, 0u64);
        }
        let abi_stats = Arc::new(RwLock::new(abi_stats_map));

        let stats_for_fn = Arc::clone(&abi_stats);
        let demangle_fn: DemanglerFn = Arc::new(move |sym: &str| -> Result<String> {
            for (name, strategy) in strategy_arc.as_ref() {
                if let Ok(result) = strategy(sym) {
                    if let Ok(mut stats) = stats_for_fn.write() {
                        *stats.entry(name.clone()).or_insert(0) += 1;
                    }
                    return Ok(result);
                }
            }
            anyhow::bail!("No ABI could demangle: {sym}")
        });

        Self {
            inner: DemanglerCache::new(capacity, demangle_fn),
            abi_stats,
        }
    }

    /// Demangle `symbol` through the cached multi-ABI strategy chain,
    /// returning the original string if every ABI fails.
    pub fn demangle(&self, symbol: &str) -> String {
        self.inner.demangle(symbol)
    }

    /// Snapshot of the inner cache's [`CacheStats`].
    pub fn stats(&self) -> CacheStats {
        self.inner.stats()
    }

    /// # Panics
    /// Panics if the internal `RwLock` is poisoned.
    pub fn abi_stats(&self) -> HashMap<String, u64> {
        self.abi_stats.read().unwrap().clone()
    }
}

// ── Persistent cache (JSON-backed) ────────────────────────────────────────────

/// One serialized cache entry inside a [`PersistentCache`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentEntry {
    /// The mangled symbol (cache key).
    pub symbol: String,
    /// The cached demangled form.
    pub demangled: String,
    /// Hit count recorded at save time.
    pub hits: u64,
}

/// JSON-serializable snapshot of an [`LruCache`] for persistence across runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentCache {
    /// Saved cache entries.
    pub entries: Vec<PersistentEntry>,
    /// Format version (currently 1).
    pub version: u32,
    /// Creation time as seconds since the Unix epoch.
    pub created_at_unix: u64,
}

impl PersistentCache {
    /// Create an empty snapshot stamped with the current time.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            version: 1,
            created_at_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        }
    }

    /// Snapshot every live entry of `lru` (order is not preserved).
    #[must_use]
    pub fn from_lru_cache(lru: &LruCache) -> Self {
        let entries = lru
            .core
            .iter()
            .map(|(k, v)| PersistentEntry {
                symbol: k.clone(),
                demangled: v.demangled.clone(),
                hits: v.hits,
            })
            .collect();
        let mut pc = Self::new();
        pc.entries = entries;
        pc
    }

    /// # Errors
    /// Returns an error if JSON serialization fails.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// # Errors
    /// Returns an error if JSON deserialization fails.
    pub fn from_json(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }

    /// Rebuild an [`LruCache`] from this snapshot, growing `capacity` if
    /// needed so no saved entry is dropped.
    #[must_use]
    pub fn into_lru_cache(self, capacity: usize) -> LruCache {
        let mut lru = LruCache::new(capacity.max(self.entries.len()));
        for entry in self.entries {
            lru.insert(entry.symbol, entry.demangled);
        }
        lru
    }
}

impl Default for PersistentCache {
    fn default() -> Self {
        Self::new()
    }
}

// ── Deduplication helper ──────────────────────────────────────────────────────

/// Given a list of symbols (possibly with duplicates), deduplicate then demangle,
/// returning a map from original symbol → demangled string.
pub fn dedup_demangle(
    symbols: &[String],
    demangle_fn: &DemanglerFn,
) -> HashMap<String, String> {
    let unique: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        symbols
            .iter()
            .filter(|s| seen.insert(s.as_str()))
            .cloned()
            .collect()
    };

    let results: Vec<(String, String)> = unique
        .par_iter()
        .map(|sym| {
            let d = (demangle_fn)(sym).unwrap_or_else(|_| sym.clone());
            (sym.clone(), d)
        })
        .collect();

    results.into_iter().collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_cache(cap: usize) -> DemanglerCache {
        DemanglerCache::new(cap, Arc::new(|s: &str| Ok(s.to_uppercase())))
    }

    #[test]
    fn test_lru_basic_insert_get() {
        let mut cache = LruCache::new(3);
        cache.insert("a".to_owned(), "A".to_owned());
        cache.insert("b".to_owned(), "B".to_owned());
        assert_eq!(cache.get("a"), Some("A"));
        assert_eq!(cache.get("b"), Some("B"));
        assert_eq!(cache.get("c"), None);
    }

    #[test]
    fn test_lru_eviction() {
        let mut cache = LruCache::new(2);
        cache.insert("a".to_owned(), "A".to_owned());
        cache.insert("b".to_owned(), "B".to_owned());
        cache.insert("c".to_owned(), "C".to_owned()); // evicts LRU (a)
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get("a"), None);
        assert_eq!(cache.get("c"), Some("C"));
    }

    #[test]
    fn test_demangler_cache_hit() {
        let cache = make_cache(10);
        let r1 = cache.demangle("hello");
        let r2 = cache.demangle("hello");
        assert_eq!(r1, "HELLO");
        assert_eq!(r2, "HELLO");
        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_demangler_cache_clear() {
        let cache = make_cache(10);
        cache.demangle("x");
        cache.clear();
        assert_eq!(cache.stats().current_size, 0);
    }

    #[test]
    fn test_batch_demangle_no_cache() {
        let syms: Vec<String> = vec!["foo".to_owned(), "bar".to_owned(), "baz".to_owned()];
        let fn_: DemanglerFn = Arc::new(|s: &str| Ok(s.to_uppercase()));
        let results = batch_demangle(&syms, &fn_, None);
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|r| r.succeeded));
        assert_eq!(results[0].demangled, "FOO");
    }

    #[test]
    fn test_persistent_cache_roundtrip() {
        let mut lru = LruCache::new(10);
        lru.insert("_Zfoo".to_owned(), "foo()".to_owned());
        let pc = PersistentCache::from_lru_cache(&lru);
        let json = pc.to_json().unwrap();
        let pc2 = PersistentCache::from_json(&json).unwrap();
        assert_eq!(pc2.entries.len(), 1);
        assert_eq!(pc2.entries[0].symbol, "_Zfoo");
    }

    #[test]
    fn test_dedup_demangle() {
        let syms: Vec<String> = vec!["a".to_owned(), "b".to_owned(), "a".to_owned()];
        let fn_: DemanglerFn = Arc::new(|s: &str| Ok(s.to_uppercase()));
        let map = dedup_demangle(&syms, &fn_);
        assert_eq!(map.len(), 2);
        assert_eq!(map.get("a"), Some(&"A".to_owned()));
    }

    #[test]
    fn test_top_entries() {
        let mut lru = LruCache::new(10);
        lru.insert("a".to_owned(), "A".to_owned());
        lru.insert("b".to_owned(), "B".to_owned());
        lru.get("a");
        lru.get("a");
        let top = lru.top_entries(1);
        assert_eq!(top[0].0, "a");
    }

    #[test]
    fn test_cache_stats_rate() {
        let mut s = CacheStats { hits: 3, misses: 1, ..Default::default() };
        s.update_rate();
        assert!((s.hit_rate_pct - 75.0).abs() < 0.01);
    }
}
