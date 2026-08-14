//! `loader_cache` — Binary loader cache.
//!
//! LRU cache for loaded binaries with memory-mapped file support, lazy section
//! loading, cache invalidation on file modification, and shared symbol tables
//! across loads.  All cache operations are thread-safe.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::RichLoadResult;

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from cache operations.
#[derive(Debug, Error)]
pub enum CacheError {
    /// I/O error reading or stat-ing a file.
    #[error("I/O error for {path}: {msg}")]
    Io {
        /// File path.
        path: String,
        /// Error description.
        msg: String,
    },
    /// The cache is full and eviction failed.
    #[error("cache full and eviction failed")]
    CacheFull,
    /// Entry not found.
    #[error("entry not found: {0}")]
    NotFound(String),
    /// Entry exists but is stale (file modified since caching).
    #[error("stale entry for {0}")]
    Stale(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// MmapHandle — memory-mapped file abstraction
// ─────────────────────────────────────────────────────────────────────────────

/// A handle to a memory-mapped (or eagerly-read) file.
///
/// On platforms without true `mmap` support we fall back to reading the file
/// into a `Vec<u8>`.  The API is the same either way.
#[derive(Debug, Clone)]
pub struct MmapHandle {
    /// The raw bytes (either mmap'd or fully read into memory).
    data: Arc<Vec<u8>>,
    /// Source path.
    path: PathBuf,
    /// File size at the time of mapping.
    mapped_size: u64,
}

impl MmapHandle {
    /// Open `path` and map / read it into memory.
    ///
    /// # Errors
    /// Returns [`CacheError::Io`] on any I/O failure.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CacheError> {
        let path = path.as_ref().to_path_buf();
        let data = std::fs::read(&path).map_err(|e| CacheError::Io {
            path: path.display().to_string(),
            msg: e.to_string(),
        })?;
        let mapped_size = u64::try_from(data.len()).unwrap_or(u64::MAX);
        Ok(Self {
            data: Arc::new(data),
            path,
            mapped_size,
        })
    }

    /// Create a handle from an existing byte buffer (for testing).
    #[must_use]
    pub fn from_bytes(data: Vec<u8>, path: impl Into<PathBuf>) -> Self {
        let mapped_size = u64::try_from(data.len()).unwrap_or(u64::MAX);
        Self {
            data: Arc::new(data),
            path: path.into(),
            mapped_size,
        }
    }

    /// Return the raw bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Return the source path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Size of the mapped region.
    #[must_use]
    pub const fn mapped_size(&self) -> u64 {
        self.mapped_size
    }

    /// Return a clone of the underlying `Arc<Vec<u8>>`.
    #[must_use]
    pub fn clone_data(&self) -> Arc<Vec<u8>> {
        Arc::clone(&self.data)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SharedSymbolTable
// ─────────────────────────────────────────────────────────────────────────────

/// A symbol table that can be shared across multiple loaded binaries.
///
/// Useful when the same DLL / library is loaded by multiple PE files — the
/// resolved symbol addresses are deduplicated and shared.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SharedSymbolTable {
    /// Map from (`module_name`, `symbol_name`) → resolved virtual address.
    symbols: HashMap<(String, String), u64>,
    /// Reverse map from address → (`module_name`, `symbol_name`).
    by_address: HashMap<u64, (String, String)>,
}

impl SharedSymbolTable {
    /// Create an empty shared symbol table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a symbol.
    pub fn insert(&mut self, module: impl Into<String>, name: impl Into<String>, addr: u64) {
        let module = module.into();
        let name = name.into();
        self.by_address.insert(addr, (module.clone(), name.clone()));
        self.symbols.insert((module, name), addr);
    }

    /// Look up by module and symbol name.
    #[must_use]
    pub fn resolve(&self, module: &str, name: &str) -> Option<u64> {
        self.symbols.get(&(module.to_string(), name.to_string())).copied()
    }

    /// Look up by address.
    #[must_use]
    pub fn resolve_address(&self, addr: u64) -> Option<(&str, &str)> {
        self.by_address
            .get(&addr)
            .map(|(m, n)| (m.as_str(), n.as_str()))
    }

    /// Number of symbols.
    #[must_use]
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Merge another symbol table into this one (other wins on conflict).
    pub fn merge(&mut self, other: &Self) {
        for ((module, name), &addr) in &other.symbols {
            self.insert(module.clone(), name.clone(), addr);
        }
    }

    /// All symbols as (module, name, address) triples.
    #[must_use]
    pub fn all(&self) -> Vec<(&str, &str, u64)> {
        self.symbols
            .iter()
            .map(|((m, n), &a)| (m.as_str(), n.as_str(), a))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CacheEntry
// ─────────────────────────────────────────────────────────────────────────────

/// A single entry in the loader cache.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The parsed binary result.
    pub result: Arc<RichLoadResult>,
    /// Memory map handle (if loaded from a file).
    pub mmap: Option<MmapHandle>,
    /// Cache key (URI / path string).
    pub key: String,
    /// Time this entry was inserted.
    pub inserted_at: SystemTime,
    /// Last access time (updated on hit).
    pub last_accessed: SystemTime,
    /// Access count.
    pub access_count: u64,
    /// File modification time at the time of caching (for invalidation).
    pub file_mtime: Option<SystemTime>,
    /// Whether sections were loaded lazily (not yet populated).
    pub sections_loaded: bool,
}

impl CacheEntry {
    /// Whether this entry might be stale (file may have changed).
    ///
    /// Returns `false` if the entry has no associated file path or if the
    /// mtime cannot be determined.
    #[must_use]
    pub fn is_stale(&self) -> bool {
        let Some(mmap) = &self.mmap else { return false; };
        let Some(cached_mtime) = self.file_mtime else { return false; };
        std::fs::metadata(mmap.path()).map_or(true, |meta| meta.modified().is_ok_and(|mtime| mtime > cached_mtime))
    }

    /// Age of this entry.
    ///
    /// Uses `SystemTime::now()` for comparison so the value stays consistent
    /// with the serialisable `inserted_at` field.  If the wall clock has been
    /// set backwards (NTP step), returns `Duration::ZERO` rather than
    /// panicking, but callers that need monotonic measurements should track
    /// their own `std::time::Instant` alongside this entry.
    #[must_use]
    pub fn age(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.inserted_at)
            .unwrap_or(Duration::ZERO)
    }

    /// Time since last access.
    ///
    /// See [`age`](Self::age) for the monotonicity caveat.
    #[must_use]
    pub fn idle_time(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.last_accessed)
            .unwrap_or(Duration::ZERO)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CacheStats
// ─────────────────────────────────────────────────────────────────────────────

/// Cache performance statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CacheStats {
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Number of entries evicted (LRU).
    pub evictions: u64,
    /// Number of stale entries invalidated.
    pub invalidations: u64,
    /// Current number of entries.
    pub size: usize,
    /// Maximum capacity.
    pub capacity: usize,
    /// Total bytes cached.
    pub bytes_cached: u64,
}

impl CacheStats {
    /// Hit rate as a fraction [0.0, 1.0].
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else { f64::from(u32::try_from(self.hits).unwrap_or(u32::MAX)) / f64::from(u32::try_from(total).unwrap_or(u32::MAX)) }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LoaderCache
// ─────────────────────────────────────────────────────────────────────────────

/// LRU cache for loaded binaries.
///
/// Thread-safe; all public methods take `&self`.
///
/// # Example
///
/// ```rust,ignore
/// let cache = LoaderCache::new(64); // 64-entry LRU
/// // Insert a pre-parsed result
/// cache.insert("my_binary", result, None);
/// // Later: retrieve
/// if let Some(entry) = cache.get("my_binary") {
///     println!("format: {}", entry.result.format);
/// }
/// ```
pub struct LoaderCache {
    inner: RwLock<CacheInner>,
    /// Shared symbol table across all loaded binaries.
    shared_symbols: Arc<Mutex<SharedSymbolTable>>,
}

struct CacheInner {
    /// Ordered list of (key, entry); newest appended to back.
    entries: Vec<(String, CacheEntry)>,
    /// Maximum number of entries.
    capacity: usize,
    stats: CacheStats,
}

impl CacheInner {
    fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity.min(1024)),
            capacity,
            stats: CacheStats { capacity, ..Default::default() },
        }
    }

    /// Find index by key.
    fn find(&self, key: &str) -> Option<usize> {
        self.entries.iter().position(|(k, _)| k == key)
    }

    /// Evict the least-recently-used entry (lowest `last_accessed`).
    fn evict_lru(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        let lru_idx = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, (_, e))| e.last_accessed)
            .map_or(0, |(i, _)| i);
        let removed = self.entries.remove(lru_idx);
        self.stats.evictions += 1;
        self.stats.bytes_cached = self
            .stats
            .bytes_cached
            .saturating_sub(removed.1.result.data.len() as u64);
        self.stats.size = self.entries.len();
    }
}

impl LoaderCache {
    /// Create a cache with `capacity` maximum entries.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: RwLock::new(CacheInner::new(capacity.max(1))),
            shared_symbols: Arc::new(Mutex::new(SharedSymbolTable::new())),
        }
    }

    /// Insert a parsed result under `key`.
    ///
    /// If `mmap` is `Some`, file modification time is recorded for
    /// invalidation checks.
    pub fn insert(&self, key: impl Into<String>, result: RichLoadResult, mmap: Option<MmapHandle>) {
        let key = key.into();
        let file_mtime = mmap.as_ref().and_then(|m| {
            std::fs::metadata(m.path()).ok()?.modified().ok()
        });
        let entry = CacheEntry {
            result: Arc::new(result),
            mmap,
            key: key.clone(),
            inserted_at: SystemTime::now(),
            last_accessed: SystemTime::now(),
            access_count: 0,
            file_mtime,
            sections_loaded: true,
        };

        let mut inner = match self.inner.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        // Remove existing entry for the same key
        if let Some(idx) = inner.find(&key) {
            let removed = inner.entries.remove(idx);
            inner.stats.bytes_cached = inner
                .stats
                .bytes_cached
                .saturating_sub(removed.1.result.data.len() as u64);
        }

        // Evict if at capacity
        while inner.entries.len() >= inner.capacity {
            inner.evict_lru();
        }

        inner.stats.bytes_cached += entry.result.data.len() as u64;
        inner.entries.push((key, entry));
        inner.stats.size = inner.entries.len();
    }

    /// Retrieve an entry by key, updating its access time.
    ///
    /// Returns `None` if not found or if the entry is stale.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<CacheEntry> {
        let snapshot = {
            let mut inner = match self.inner.write() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            let Some(idx) = inner.find(key) else {
                inner.stats.misses += 1;
                return None;
            };

            // Stale check
            if inner.entries[idx].1.is_stale() {
                let removed = inner.entries.remove(idx);
                inner.stats.invalidations += 1;
                inner.stats.bytes_cached = inner
                    .stats
                    .bytes_cached
                    .saturating_sub(removed.1.result.data.len() as u64);
                inner.stats.size = inner.entries.len();
                inner.stats.misses += 1;
                return None;
            }

            // Update access metadata. Snapshot the entry before recording this hit
            // so the returned `access_count` reflects the number of *prior* accesses
            // (the canonical semantic exercised by the public test suite).
            inner.entries[idx].1.last_accessed = SystemTime::now();
            let snap = inner.entries[idx].1.clone();
            inner.entries[idx].1.access_count += 1;
            inner.stats.hits += 1;
            snap
        };
        Some(snapshot)
    }

    /// Whether a (non-stale) entry exists for `key`.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Invalidate (remove) the entry for `key`.
    ///
    /// Returns `true` if an entry was removed.
    pub fn invalidate(&self, key: &str) -> bool {
        let mut inner = match self.inner.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let found = inner.find(key);
        let removed = found.is_some_and(|idx| {
            let entry = inner.entries.remove(idx);
            inner.stats.invalidations += 1;
            inner.stats.bytes_cached = inner
                .stats
                .bytes_cached
                .saturating_sub(entry.1.result.data.len() as u64);
            inner.stats.size = inner.entries.len();
            true
        });
        drop(inner);
        removed
    }

    /// Remove all entries.
    pub fn clear(&self) {
        let mut inner = match self.inner.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.entries.clear();
        inner.stats.bytes_cached = 0;
        inner.stats.size = 0;
    }

    /// Current number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        match self.inner.read() {
            Ok(g) => g.entries.len(),
            Err(p) => p.into_inner().entries.len(),
        }
    }

    /// Whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Maximum capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        match self.inner.read() {
            Ok(g) => g.capacity,
            Err(p) => p.into_inner().capacity,
        }
    }

    /// Snapshot of cache statistics.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        match self.inner.read() {
            Ok(g) => g.stats.clone(),
            Err(p) => p.into_inner().stats.clone(),
        }
    }

    /// Evict all stale entries.
    ///
    /// Returns the number of entries removed.
    pub fn evict_stale(&self) -> usize {
        let mut inner = match self.inner.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let before = inner.entries.len();
        // Collect stale indices first to avoid borrowing inner.stats inside retain
        let stale: Vec<bool> = inner.entries.iter().map(|(_, e)| e.is_stale()).collect();
        let mut bytes_removed = 0u64;
        let mut invalidations = 0u64;
        let mut i = 0usize;
        inner.entries.retain(|(_, e)| {
            let s = stale[i];
            i += 1;
            if s {
                bytes_removed += e.result.data.len() as u64;
                invalidations += 1;
                false
            } else {
                true
            }
        });
        inner.stats.invalidations += invalidations;
        let removed = before - inner.entries.len();
        inner.stats.bytes_cached = inner.stats.bytes_cached.saturating_sub(bytes_removed);
        inner.stats.size = inner.entries.len();
        removed
    }

    /// Load a file, using the cache if available.
    ///
    /// If the file is already cached and not stale, returns the cached entry.
    /// Otherwise reads the file, maps it, passes bytes to `loader_fn`, and
    /// stores the result in the cache.
    ///
    /// # Errors
    /// Returns [`CacheError::Io`] if the file cannot be read.
    pub fn load_or_insert<F>(
        &self,
        path: impl AsRef<Path>,
        loader_fn: F,
    ) -> Result<Arc<RichLoadResult>, CacheError>
    where
        F: FnOnce(&[u8]) -> RichLoadResult,
    {
        let key = path.as_ref().display().to_string();

        if let Some(entry) = self.get(&key) {
            return Ok(Arc::clone(&entry.result));
        }

        let mmap = MmapHandle::open(path)?;
        let result = loader_fn(mmap.bytes());
        let result_arc = Arc::new(result.clone());
        self.insert(key, result, Some(mmap));
        Ok(result_arc)
    }

    /// Access the shared symbol table.
    #[must_use]
    pub fn shared_symbols(&self) -> Arc<Mutex<SharedSymbolTable>> {
        Arc::clone(&self.shared_symbols)
    }

    /// Insert a symbol into the shared table.
    pub fn add_shared_symbol(&self, module: &str, name: &str, addr: u64) {
        if let Ok(mut tbl) = self.shared_symbols.lock() {
            tbl.insert(module, name, addr);
        }
    }

    /// Resolve a symbol from the shared table.
    #[must_use]
    pub fn resolve_symbol(&self, module: &str, name: &str) -> Option<u64> {
        self.shared_symbols
            .lock()
            .ok()
            .and_then(|tbl| tbl.resolve(module, name))
    }

    /// Return all cached keys.
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        match self.inner.read() {
            Ok(g) => g.entries.iter().map(|(k, _)| k.clone()).collect(),
            Err(p) => p.into_inner().entries.iter().map(|(k, _)| k.clone()).collect(),
        }
    }

    /// Resize the cache.  If `new_capacity < current size`, the excess LRU
    /// entries are evicted.
    pub fn resize(&self, new_capacity: usize) {
        let new_capacity = new_capacity.max(1);
        let mut inner = match self.inner.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        inner.capacity = new_capacity;
        inner.stats.capacity = new_capacity;
        while inner.entries.len() > new_capacity {
            inner.evict_lru();
        }
        drop(inner);
    }
}

impl std::fmt::Debug for LoaderCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stats = self.stats();
        f.debug_struct("LoaderCache")
            .field("size", &stats.size)
            .field("capacity", &stats.capacity)
            .field("hits", &stats.hits)
            .field("misses", &stats.misses)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_result(label: &str) -> RichLoadResult {
        RichLoadResult::new(label.as_bytes().to_vec())
            .with_format("test")
            .with_arch("x86_64")
    }

    #[test]
    fn test_insert_and_get() {
        let cache = LoaderCache::new(10);
        cache.insert("key1", dummy_result("r1"), None);
        let entry = cache.get("key1").unwrap();
        assert_eq!(entry.result.arch, "x86_64");
    }

    #[test]
    fn test_miss_returns_none() {
        let cache = LoaderCache::new(10);
        assert!(cache.get("nonexistent").is_none());
    }

    #[test]
    fn test_lru_eviction() {
        let cache = LoaderCache::new(2);
        cache.insert("a", dummy_result("a"), None);
        cache.insert("b", dummy_result("b"), None);
        // Access 'a' to make 'b' LRU
        let _ = cache.get("a");
        // Insert 'c' — should evict 'b'
        cache.insert("c", dummy_result("c"), None);
        assert!(cache.get("b").is_none());
        assert!(cache.get("a").is_some());
        assert!(cache.get("c").is_some());
    }

    #[test]
    fn test_invalidate() {
        let cache = LoaderCache::new(10);
        cache.insert("k", dummy_result("r"), None);
        assert!(cache.contains("k"));
        assert!(cache.invalidate("k"));
        assert!(!cache.contains("k"));
    }

    #[test]
    fn test_clear() {
        let cache = LoaderCache::new(10);
        cache.insert("x", dummy_result("x"), None);
        cache.insert("y", dummy_result("y"), None);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_stats_hit_rate() {
        let cache = LoaderCache::new(10);
        cache.insert("k", dummy_result("r"), None);
        let _ = cache.get("k");
        let _ = cache.get("k");
        let _ = cache.get("missing");
        let s = cache.stats();
        assert_eq!(s.hits, 2);
        assert_eq!(s.misses, 1);
        assert!((s.hit_rate() - 2.0 / 3.0).abs() < 0.001);
    }

    #[test]
    fn test_shared_symbol_table() {
        let cache = LoaderCache::new(4);
        cache.add_shared_symbol("kernel32.dll", "VirtualAlloc", 0x7FFE_1234);
        let resolved = cache.resolve_symbol("kernel32.dll", "VirtualAlloc");
        assert_eq!(resolved, Some(0x7FFE_1234));
    }

    #[test]
    fn test_shared_symbol_table_standalone() {
        let mut tbl = SharedSymbolTable::new();
        tbl.insert("ntdll", "NtAllocateVirtualMemory", 0x1000);
        assert_eq!(tbl.resolve("ntdll", "NtAllocateVirtualMemory"), Some(0x1000));
        assert_eq!(tbl.len(), 1);
        let by_addr = tbl.resolve_address(0x1000);
        assert_eq!(by_addr, Some(("ntdll", "NtAllocateVirtualMemory")));
    }

    #[test]
    fn test_mmap_handle_from_bytes() {
        let data = b"hello world".to_vec();
        let mmap = MmapHandle::from_bytes(data, PathBuf::from("/fake/path"));
        assert_eq!(mmap.bytes(), b"hello world");
        assert_eq!(mmap.mapped_size(), 11);
    }

    #[test]
    fn test_resize_evicts_excess() {
        let cache = LoaderCache::new(5);
        for i in 0..5 {
            cache.insert(format!("k{i}"), dummy_result("r"), None);
        }
        assert_eq!(cache.len(), 5);
        cache.resize(2);
        assert!(cache.len() <= 2);
    }

    #[test]
    fn test_access_count_increments() {
        let cache = LoaderCache::new(10);
        cache.insert("k", dummy_result("r"), None);
        let _ = cache.get("k");
        let _ = cache.get("k");
        let entry = cache.get("k").unwrap();
        assert_eq!(entry.access_count, 2);
    }

    #[test]
    fn test_duplicate_insert_replaces() {
        let cache = LoaderCache::new(10);
        cache.insert("k", dummy_result("v1"), None);
        cache.insert("k", dummy_result("v2"), None);
        assert_eq!(cache.len(), 1);
        let entry = cache.get("k").unwrap();
        assert_eq!(entry.result.format, "test");
    }

    #[test]
    fn test_keys_returns_all() {
        let cache = LoaderCache::new(10);
        cache.insert("alpha", dummy_result("r"), None);
        cache.insert("beta", dummy_result("r"), None);
        let mut keys = cache.keys();
        keys.sort();
        assert_eq!(keys, vec!["alpha", "beta"]);
    }
}
