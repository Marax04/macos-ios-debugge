//! `decompiler_cache.rs` — Persistent LRU decompilation cache.
//!
//! Cache key: (`function_address`, `binary_hash`, `decompiler_version`)
//! Backend: in-memory LRU with optional persistent `SQLite` backend.
//! Invalidation: on patch, rename, or retype events.

use crate::DecompiledFunction;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ─────────────────────────────────────────────────────────────────────────────
// CacheKey — composite cache key
// ─────────────────────────────────────────────────────────────────────────────

/// Uniquely identifies a cached decompilation result.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CacheKey {
    /// Address of the function in the binary.
    pub function_address: u64,
    /// SHA-256 hash (truncated to 64 bits) of the binary image.
    pub binary_hash: u64,
    /// Decompiler version string (e.g., "rustre-0.4.2").
    pub decompiler_version: String,
    /// Options fingerprint (hash of the `DecompOptions` struct).
    pub options_hash: u64,
}

impl CacheKey {
    pub fn new(
        function_address: u64,
        binary_hash: u64,
        decompiler_version: impl Into<String>,
        options_hash: u64,
    ) -> Self {
        Self {
            function_address,
            binary_hash,
            decompiler_version: decompiler_version.into(),
            options_hash,
        }
    }

    /// Compute a u64 hash of this key for stable, deterministic indexing.
    ///
    /// Uses FNV-1a (64-bit), which is deterministic across Rust versions and
    /// process restarts — unlike `DefaultHasher`, which is explicitly
    /// non-deterministic and must not be used for persistent cache keys.
    #[must_use] 
    pub fn hash64(&self) -> u64 {
        const FNV_OFFSET: u64 = 14_695_981_039_346_656_037;
        const FNV_PRIME: u64 = 1_099_511_628_211;

        fn fnv1a_bytes(mut h: u64, bytes: &[u8]) -> u64 {
            for &b in bytes {
                h ^= u64::from(b);
                h = h.wrapping_mul(FNV_PRIME);
            }
            h
        }

        let mut h = FNV_OFFSET;
        h = fnv1a_bytes(h, &self.function_address.to_le_bytes());
        h = fnv1a_bytes(h, &self.binary_hash.to_le_bytes());
        h = fnv1a_bytes(h, self.decompiler_version.as_bytes());
        h = fnv1a_bytes(h, &self.options_hash.to_le_bytes());
        h
    }
}

impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "addr={:#x} bin={:#x} ver={} opts={:#x}",
            self.function_address,
            self.binary_hash,
            self.decompiler_version,
            self.options_hash,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CacheEntry — a single cached item with metadata
// ─────────────────────────────────────────────────────────────────────────────

/// A single entry in the decompiler cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// The cached key.
    pub key: CacheKey,
    /// The cached decompiled function.
    pub function: DecompiledFunction,
    /// Unix timestamp (seconds) when this entry was created.
    pub created_at: u64,
    /// Unix timestamp (seconds) of last access.
    pub last_accessed: u64,
    /// Number of times this entry has been accessed.
    pub access_count: u64,
    /// Size of the pseudo-code in bytes (for eviction scoring).
    pub size_bytes: usize,
    /// Whether this entry has been invalidated.
    pub invalidated: bool,
}

impl CacheEntry {
    #[must_use] 
    pub fn new(key: CacheKey, function: DecompiledFunction) -> Self {
        let now = unix_now();
        let size_bytes = function.pseudo_code.len() + function.name.len();
        Self {
            key,
            function,
            created_at: now,
            last_accessed: now,
            access_count: 0,
            size_bytes,
            invalidated: false,
        }
    }

    pub fn touch(&mut self) {
        self.last_accessed = unix_now();
        self.access_count += 1;
    }

    /// LRU score: higher score → evict first.
    #[must_use] 
    pub fn eviction_score(&self) -> u64 {
        // Evict entries that are old and infrequently accessed.
        let age = unix_now().saturating_sub(self.last_accessed);
        age / (self.access_count + 1).max(1)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

// ─────────────────────────────────────────────────────────────────────────────
// InvalidationReason — why a cache entry was invalidated
// ─────────────────────────────────────────────────────────────────────────────

/// The reason a cache entry was invalidated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidationReason {
    /// A patch was applied to the binary near the function.
    BinaryPatch,
    /// The function was renamed.
    Renamed,
    /// The function or a variable's type was changed.
    Retyped,
    /// The decompiler version changed.
    VersionUpgrade,
    /// Explicit manual invalidation.
    ManualInvalidation,
    /// The binary hash changed (different binary).
    BinaryChanged,
}

impl fmt::Display for InvalidationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BinaryPatch => write!(f, "binary_patch"),
            Self::Renamed => write!(f, "renamed"),
            Self::Retyped => write!(f, "retyped"),
            Self::VersionUpgrade => write!(f, "version_upgrade"),
            Self::ManualInvalidation => write!(f, "manual"),
            Self::BinaryChanged => write!(f, "binary_changed"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CacheStats — hit/miss/eviction counters
// ─────────────────────────────────────────────────────────────────────────────

/// Statistics for the decompiler cache.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub invalidations: u64,
    pub inserts: u64,
    pub persistent_reads: u64,
    pub persistent_writes: u64,
}

impl CacheStats {
    #[must_use] 
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else {
            let h = f64::from(u32::try_from(self.hits).unwrap_or(u32::MAX));
            let t = f64::from(u32::try_from(total).unwrap_or(u32::MAX));
            h / t
        }
    }

    #[must_use] 
    pub const fn total_lookups(&self) -> u64 {
        self.hits + self.misses
    }
}

impl fmt::Display for CacheStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hits={} misses={} evictions={} invalidations={} hit_rate={:.1}%",
            self.hits,
            self.misses,
            self.evictions,
            self.invalidations,
            self.hit_rate() * 100.0,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LruIndex — ordered access tracking for LRU eviction
// ─────────────────────────────────────────────────────────────────────────────

/// Minimal LRU tracker: maps key → insertion counter, plus an ordered
/// counter → key index so the eviction candidate is found in O(log n)
/// instead of an O(n) scan.
struct LruIndex {
    order: HashMap<u64, u64>,
    by_counter: BTreeMap<u64, u64>,
    counter: u64,
}

impl LruIndex {
    fn new() -> Self {
        Self {
            order: HashMap::new(),
            by_counter: BTreeMap::new(),
            counter: 0,
        }
    }

    fn touch(&mut self, key_hash: u64) {
        self.counter += 1;
        if let Some(old) = self.order.insert(key_hash, self.counter) {
            self.by_counter.remove(&old);
        }
        self.by_counter.insert(self.counter, key_hash);
    }

    fn evict_candidate(&self) -> Option<u64> {
        self.by_counter.iter().next().map(|(_, &k)| k)
    }

    fn remove(&mut self, key_hash: u64) {
        if let Some(c) = self.order.remove(&key_hash) {
            self.by_counter.remove(&c);
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PersistentBackend — SQLite-style interface (in-memory simulation)
// ─────────────────────────────────────────────────────────────────────────────

/// Trait for a persistent backing store.
pub trait PersistentBackend: fmt::Debug + Send + Sync {
    /// Load an entry by key hash.
    fn load(&self, key_hash: u64) -> Option<CacheEntry>;
    /// Save an entry.
    fn save(&mut self, entry: &CacheEntry);
    /// Delete an entry by key hash.
    fn delete(&mut self, key_hash: u64);
    /// Return the number of entries in the store.
    fn entry_count(&self) -> usize;
    /// Flush all pending writes.
    fn flush(&mut self);
}

/// A simple in-memory persistent backend (production would use `SQLite`).
#[derive(Debug, Default)]
pub struct InMemoryBackend {
    store: HashMap<u64, CacheEntry>,
}

impl InMemoryBackend {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }
}

impl PersistentBackend for InMemoryBackend {
    fn load(&self, key_hash: u64) -> Option<CacheEntry> {
        self.store.get(&key_hash).cloned()
    }

    fn save(&mut self, entry: &CacheEntry) {
        self.store.insert(entry.key.hash64(), entry.clone());
    }

    fn delete(&mut self, key_hash: u64) {
        self.store.remove(&key_hash);
    }

    fn entry_count(&self) -> usize {
        self.store.len()
    }

    fn flush(&mut self) {
        // No-op for in-memory.
    }
}

/// A file-path-based backend stub (would use `SQLite` in production).
#[derive(Debug)]
pub struct FileBackend {
    pub path: PathBuf,
    /// In-memory buffer (flushed to disk on `flush()`).
    buffer: HashMap<u64, CacheEntry>,
}

impl FileBackend {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            buffer: HashMap::new(),
        }
    }
}

impl PersistentBackend for FileBackend {
    fn load(&self, key_hash: u64) -> Option<CacheEntry> {
        self.buffer.get(&key_hash).cloned()
    }

    fn save(&mut self, entry: &CacheEntry) {
        self.buffer.insert(entry.key.hash64(), entry.clone());
    }

    fn delete(&mut self, key_hash: u64) {
        self.buffer.remove(&key_hash);
    }

    fn entry_count(&self) -> usize {
        self.buffer.len()
    }

    fn flush(&mut self) {
        // In a real implementation: serialize `self.buffer` to SQLite at `self.path`.
        // Here we just log the path.
        let _ = &self.path;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DecompilerCacheV2 — the main cache implementation
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for `DecompilerCacheV2`.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries in the in-memory LRU.
    pub capacity: usize,
    /// Maximum total size of pseudo-code in the in-memory cache (bytes).
    pub max_size_bytes: usize,
    /// Whether to use the persistent backend.
    pub use_persistent: bool,
    /// Whether to verify entry integrity on load.
    pub verify_on_load: bool,
    /// TTL for entries in seconds (0 = never expire).
    pub ttl_secs: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            capacity: 4096,
            max_size_bytes: 256 * 1024 * 1024, // 256 MiB
            use_persistent: true,
            verify_on_load: true,
            ttl_secs: 0,
        }
    }
}

/// A full-featured decompiler cache with LRU eviction and persistent backend.
pub struct DecompilerCacheV2 {
    config: CacheConfig,
    /// In-memory LRU map: `key_hash` → `CacheEntry`.
    memory: HashMap<u64, CacheEntry>,
    /// LRU order tracker.
    lru: LruIndex,
    /// Current total pseudo-code size in memory.
    current_size: usize,
    /// Optional persistent backend.
    backend: Option<Box<dyn PersistentBackend>>,
    /// Statistics.
    pub stats: CacheStats,
    /// Invalidation log.
    pub invalidation_log: Vec<(CacheKey, InvalidationReason, u64)>,
}

impl DecompilerCacheV2 {
    /// Create an in-memory-only cache.
    #[must_use] 
    pub fn new_in_memory(capacity: usize) -> Self {
        Self {
            config: CacheConfig { capacity, use_persistent: false, ..Default::default() },
            memory: HashMap::new(),
            lru: LruIndex::new(),
            current_size: 0,
            backend: None,
            stats: CacheStats::default(),
            invalidation_log: Vec::new(),
        }
    }

    /// Create with a persistent backend.
    #[must_use] 
    pub fn with_backend(config: CacheConfig, backend: Box<dyn PersistentBackend>) -> Self {
        Self {
            config,
            memory: HashMap::new(),
            lru: LruIndex::new(),
            current_size: 0,
            backend: Some(backend),
            stats: CacheStats::default(),
            invalidation_log: Vec::new(),
        }
    }

    /// Create with the default SQLite-style file backend.
    pub fn with_file_backend(path: impl AsRef<Path>, capacity: usize) -> Self {
        let config = CacheConfig { capacity, use_persistent: true, ..Default::default() };
        let backend: Box<dyn PersistentBackend> = Box::new(FileBackend::new(path));
        Self::with_backend(config, backend)
    }

    /// Look up a cached result by key.
    ///
    /// Checks memory first, then the persistent backend.
    pub fn get(&mut self, key: &CacheKey) -> Option<&DecompiledFunction> {
        let h = key.hash64();
        let ttl = self.config.ttl_secs;

        // Single in-memory probe: handles invalidation, TTL, and hits.
        if let Some(entry) = self.memory.get_mut(&h) {
            if entry.invalidated {
                self.stats.misses += 1;
                return None;
            }
            let expired = ttl != 0 && unix_now().saturating_sub(entry.created_at) > ttl;
            if expired {
                self.evict_by_hash(h);
                self.stats.misses += 1;
                return None;
            }
            entry.touch();
            self.lru.touch(h);
            self.stats.hits += 1;
            return self.memory.get(&h).map(|e| &e.function);
        }

        // Persistent backend miss.
        if self.config.use_persistent
            && let Some(ref backend) = self.backend
                && let Some(mut entry) = backend.load(h) {
                    self.stats.persistent_reads += 1;
                    if self.config.verify_on_load && entry.key != *key {
                        self.stats.misses += 1;
                        return None;
                    }
                    if self.is_expired(&entry) {
                        self.stats.misses += 1;
                        return None;
                    }
                    entry.touch();
                    self.insert_to_memory(h, entry);
                    self.stats.hits += 1;
                    return self.memory.get(&h).map(|e| &e.function);
                }

        self.stats.misses += 1;
        None
    }

    /// Insert a result into the cache.
    pub fn put(&mut self, key: CacheKey, function: DecompiledFunction) {
        let entry = CacheEntry::new(key, function);
        let h = entry.key.hash64();

        // Write to persistent backend first.
        if self.config.use_persistent
            && let Some(ref mut backend) = self.backend {
                backend.save(&entry);
                self.stats.persistent_writes += 1;
            }

        self.insert_to_memory(h, entry);
        self.stats.inserts += 1;
    }

    /// Invalidate a specific function by address and binary hash.
    pub fn invalidate_function(
        &mut self,
        addr: u64,
        binary_hash: u64,
        reason: InvalidationReason,
    ) {
        let to_remove: Vec<u64> = self
            .memory
            .iter()
            .filter(|(_, e)| e.key.function_address == addr && e.key.binary_hash == binary_hash)
            .map(|(&h, _)| h)
            .collect();

        for h in &to_remove {
            self.lru.remove(*h);
            if let Some(entry) = self.memory.remove(h) {
                self.current_size = self.current_size.saturating_sub(entry.size_bytes);
                self.invalidation_log.push((entry.key, reason, unix_now()));
            }
            if let Some(ref mut backend) = self.backend {
                backend.delete(*h);
            }
        }
        self.stats.invalidations += to_remove.len() as u64;
    }

    /// Invalidate all entries for a changed binary hash.
    pub fn invalidate_binary(&mut self, binary_hash: u64, reason: InvalidationReason) {
        let to_remove: Vec<u64> = self
            .memory
            .iter()
            .filter(|(_, e)| e.key.binary_hash == binary_hash)
            .map(|(&h, _)| h)
            .collect();

        for h in &to_remove {
            self.lru.remove(*h);
            if let Some(entry) = self.memory.remove(h) {
                self.current_size = self.current_size.saturating_sub(entry.size_bytes);
                self.invalidation_log.push((entry.key, reason, unix_now()));
            }
            if let Some(ref mut backend) = self.backend {
                backend.delete(*h);
            }
        }
        self.stats.invalidations += to_remove.len() as u64;
    }

    /// Invalidate all entries where the decompiler version doesn't match `current_version`.
    pub fn invalidate_old_versions(&mut self, current_version: &str) {
        let to_remove: Vec<u64> = self
            .memory
            .iter()
            .filter(|(_, e)| e.key.decompiler_version != current_version)
            .map(|(&h, _)| h)
            .collect();

        for h in &to_remove {
            self.lru.remove(*h);
            if let Some(entry) = self.memory.remove(h) {
                self.current_size = self.current_size.saturating_sub(entry.size_bytes);
                self.invalidation_log.push((
                    entry.key,
                    InvalidationReason::VersionUpgrade,
                    unix_now(),
                ));
            }
            if let Some(ref mut backend) = self.backend {
                backend.delete(*h);
            }
        }
        self.stats.invalidations += to_remove.len() as u64;
    }

    /// Evict the least recently used entry.
    fn evict_one(&mut self) {
        if let Some(h) = self.lru.evict_candidate() {
            self.evict_by_hash(h);
        }
    }

    fn evict_by_hash(&mut self, h: u64) {
        self.lru.remove(h);
        if let Some(entry) = self.memory.remove(&h) {
            self.current_size = self.current_size.saturating_sub(entry.size_bytes);
        }
        self.stats.evictions += 1;
    }

    fn insert_to_memory(&mut self, h: u64, entry: CacheEntry) {
        // Evict until there is capacity.
        while self.memory.len() >= self.config.capacity
            || self.current_size + entry.size_bytes > self.config.max_size_bytes
        {
            if self.memory.is_empty() {
                break;
            }
            self.evict_one();
        }
        self.current_size += entry.size_bytes;
        self.lru.touch(h);
        self.memory.insert(h, entry);
    }

    fn is_expired(&self, entry: &CacheEntry) -> bool {
        if self.config.ttl_secs == 0 {
            return false;
        }
        let age = unix_now().saturating_sub(entry.created_at);
        age > self.config.ttl_secs
    }

    /// Flush the persistent backend.
    pub fn flush(&mut self) {
        if let Some(ref mut backend) = self.backend {
            backend.flush();
        }
    }

    /// Number of entries in memory.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.memory.len()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.memory.is_empty()
    }

    /// Current in-memory size in bytes.
    #[must_use] 
    pub const fn size_bytes(&self) -> usize {
        self.current_size
    }

    /// Clear all in-memory entries (does not clear the persistent backend).
    pub fn clear_memory(&mut self) {
        self.memory.clear();
        self.lru = LruIndex::new();
        self.current_size = 0;
    }

    /// Return all cached function addresses.
    #[must_use] 
    pub fn cached_addresses(&self) -> Vec<u64> {
        self.memory.values().map(|e| e.key.function_address).collect()
    }

    /// Return the most recently accessed `n` functions.
    #[must_use] 
    pub fn most_recent(&self, n: usize) -> Vec<&DecompiledFunction> {
        let mut entries: Vec<&CacheEntry> = self.memory.values().collect();
        entries.sort_by(|a, b| b.last_accessed.cmp(&a.last_accessed));
        entries.truncate(n);
        entries.iter().map(|e| &e.function).collect()
    }

    /// Find all cached results for a given function address.
    #[must_use] 
    pub fn find_by_address(&self, addr: u64) -> Vec<&DecompiledFunction> {
        self.memory
            .values()
            .filter(|e| e.key.function_address == addr)
            .map(|e| &e.function)
            .collect()
    }
}

impl fmt::Debug for DecompilerCacheV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DecompilerCacheV2 {{ len: {}, size: {}B, stats: {} }}",
            self.memory.len(),
            self.current_size,
            self.stats,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CacheKeyBuilder — convenience builder
// ─────────────────────────────────────────────────────────────────────────────

/// Builds cache keys with a consistent options fingerprint.
pub struct CacheKeyBuilder {
    binary_hash: u64,
    version: String,
    options_hash: u64,
}

impl CacheKeyBuilder {
    pub fn new(binary_hash: u64, version: impl Into<String>) -> Self {
        Self {
            binary_hash,
            version: version.into(),
            options_hash: 0,
        }
    }

    #[must_use] 
    pub const fn with_options_hash(mut self, h: u64) -> Self {
        self.options_hash = h;
        self
    }

    #[must_use] 
    pub fn key_for(&self, function_address: u64) -> CacheKey {
        CacheKey::new(
            function_address,
            self.binary_hash,
            &self.version,
            self.options_hash,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func(addr: u64) -> DecompiledFunction {
        DecompiledFunction::new(addr, format!("func_{addr:#x}"), format!("void func_{addr:#x}() {{}}"))
    }

    fn make_key(addr: u64) -> CacheKey {
        CacheKey::new(addr, 0xDEADBEEF, "test-0.1", 0)
    }

    #[test]
    fn basic_put_get() {
        let mut cache = DecompilerCacheV2::new_in_memory(100);
        let key = make_key(0x1000);
        cache.put(key.clone(), make_func(0x1000));
        let result = cache.get(&key);
        assert!(result.is_some());
        assert_eq!(result.unwrap().address, 0x1000);
    }

    #[test]
    fn cache_miss_returns_none() {
        let mut cache = DecompilerCacheV2::new_in_memory(100);
        let key = make_key(0x2000);
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn lru_eviction() {
        let mut cache = DecompilerCacheV2::new_in_memory(2);
        let k1 = make_key(0x1000);
        let k2 = make_key(0x2000);
        let k3 = make_key(0x3000);
        cache.put(k1.clone(), make_func(0x1000));
        cache.put(k2.clone(), make_func(0x2000));
        // Touch k1 to make k2 the LRU.
        let _ = cache.get(&k1);
        // Insert k3; should evict k2 (LRU).
        cache.put(k3.clone(), make_func(0x3000));
        assert_eq!(cache.len(), 2);
        assert!(cache.stats.evictions >= 1);
    }

    #[test]
    fn invalidate_function() {
        let mut cache = DecompilerCacheV2::new_in_memory(100);
        let key = make_key(0x4000);
        cache.put(key.clone(), make_func(0x4000));
        cache.invalidate_function(0x4000, 0xDEADBEEF, InvalidationReason::BinaryPatch);
        assert!(cache.get(&key).is_none());
        assert_eq!(cache.stats.invalidations, 1);
    }

    #[test]
    fn invalidate_old_versions() {
        let mut cache = DecompilerCacheV2::new_in_memory(100);
        let key = CacheKey::new(0x5000, 0xABCD, "old-0.1", 0);
        cache.put(key, make_func(0x5000));
        cache.invalidate_old_versions("new-0.2");
        assert!(cache.is_empty());
        assert_eq!(cache.stats.invalidations, 1);
    }

    #[test]
    fn cache_stats() {
        let mut cache = DecompilerCacheV2::new_in_memory(100);
        let key = make_key(0x6000);
        let _ = cache.get(&key); // miss
        cache.put(key.clone(), make_func(0x6000));
        let _ = cache.get(&key); // hit
        let _ = cache.get(&key); // hit
        assert_eq!(cache.stats.hits, 2);
        assert_eq!(cache.stats.misses, 1);
        assert!((cache.stats.hit_rate() - 2.0 / 3.0).abs() < 0.001);
    }

    #[test]
    fn most_recent() {
        let mut cache = DecompilerCacheV2::new_in_memory(100);
        for addr in [0x1000u64, 0x2000, 0x3000] {
            let key = make_key(addr);
            cache.put(key.clone(), make_func(addr));
        }
        let recent = cache.most_recent(2);
        assert_eq!(recent.len(), 2);
    }

    #[test]
    fn cache_key_builder() {
        let builder = CacheKeyBuilder::new(0xCAFE, "v1").with_options_hash(42);
        let key = builder.key_for(0x7000);
        assert_eq!(key.function_address, 0x7000);
        assert_eq!(key.binary_hash, 0xCAFE);
        assert_eq!(key.options_hash, 42);
    }

    #[test]
    fn in_memory_backend() {
        let mut backend = InMemoryBackend::new();
        let key = make_key(0x8000);
        let entry = CacheEntry::new(key, make_func(0x8000));
        let h = entry.key.hash64();
        backend.save(&entry);
        assert_eq!(backend.entry_count(), 1);
        let loaded = backend.load(h);
        assert!(loaded.is_some());
        backend.delete(h);
        assert_eq!(backend.entry_count(), 0);
    }
}
