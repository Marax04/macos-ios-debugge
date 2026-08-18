//! LRU cache layer over any [`MemoryProvider`].
//!
//! Provides [`CacheLayer`], [`PageCache`], [`CacheStats`],
//! [`CacheEviction`], [`WriteThrough`], and [`CacheInvalidation`].


use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
pub use std::time::Duration;
use std::time::Instant;

use parking_lot::Mutex;
use thiserror::Error;

pub use crate::memory_provider::MemoryRegion;
use crate::memory_provider::{MemError, MemoryProvider};

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CacheError {
    #[error("underlying memory error: {0}")]
    Memory(String),

    #[error("invalid page size {0}: must be a power of 2")]
    InvalidPageSize(usize),

    #[error("address 0x{0:x} out of range")]
    OutOfRange(u64),

    #[error("cache capacity must be >= 1")]
    ZeroCapacity,
}

pub type CacheResult<T> = std::result::Result<T, CacheError>;

impl From<MemError> for CacheError {
    fn from(e: MemError) -> Self {
        Self::Memory(e.to_string())
    }
}

// ── CacheStats ────────────────────────────────────────────────────────────────

/// Accumulated statistics for a [`CacheLayer`].
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub write_throughs: u64,
    pub invalidations: u64,
    pub reads: u64,
    pub writes: u64,
}

impl CacheStats {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Cache hit ratio (0.0 – 1.0). Returns 0.0 if no accesses yet.
    #[must_use]
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

impl std::fmt::Display for CacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "hits={} misses={} ratio={:.2} evictions={} wt={} inv={}",
            self.hits,
            self.misses,
            self.hit_ratio(),
            self.evictions,
            self.write_throughs,
            self.invalidations,
        )
    }
}

// ── CacheEviction ─────────────────────────────────────────────────────────────

/// Eviction policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheEviction {
    /// Least-recently-used.
    Lru,
    /// First-in, first-out.
    Fifo,
}

// ── WriteThrough ──────────────────────────────────────────────────────────────

/// Write policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteThrough {
    /// Writes go to both cache and backing store immediately.
    Enabled,
    /// Writes update only the cache; backing store is written on eviction.
    Disabled,
}

// ── CacheInvalidation ─────────────────────────────────────────────────────────

/// A record of a cache line that was invalidated.
#[derive(Debug, Clone)]
pub struct InvalidationRecord {
    pub page_addr: u64,
    pub reason: String,
    pub at: Instant,
}

/// Tracks cache invalidation events.
pub struct CacheInvalidation {
    records: Mutex<Vec<InvalidationRecord>>,
    max_records: usize,
}

impl CacheInvalidation {
    #[must_use] 
    pub fn new(max_records: usize) -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            max_records: max_records.max(1),
        }
    }

    pub fn record(&self, page_addr: u64, reason: impl Into<String>) {
        let mut recs = self.records.lock();
        if recs.len() >= self.max_records {
            recs.remove(0);
        }
        recs.push(InvalidationRecord {
            page_addr,
            reason: reason.into(),
            at: Instant::now(),
        });
    }

    pub fn records(&self) -> Vec<InvalidationRecord> {
        self.records.lock().clone()
    }

    pub fn count(&self) -> usize {
        self.records.lock().len()
    }

    pub fn clear(&self) {
        self.records.lock().clear();
    }
}

// ── PageCache ─────────────────────────────────────────────────────────────────

/// A single cached page (aligned block of memory).
#[derive(Clone)]
pub struct CachePage {
    /// Base address (page-aligned).
    pub addr: u64,
    /// Cached bytes.
    pub data: Vec<u8>,
    /// Whether this page has been written to but not yet flushed to the backing store.
    pub dirty: bool,
}

/// LRU page cache.
pub struct PageCache {
    pages: HashMap<u64, CachePage>,
    order: VecDeque<u64>,
    capacity: usize,
    page_size: usize,
    eviction: CacheEviction,
}

impl PageCache {
    /// Create a new page cache.
    ///
    /// # Errors
    /// Returns [`CacheError::InvalidPageSize`] if `page_size` is not a power of 2.
    /// Returns [`CacheError::ZeroCapacity`] if `capacity` is zero.
    pub fn new(capacity: usize, page_size: usize, eviction: CacheEviction) -> CacheResult<Self> {
        if capacity == 0 {
            return Err(CacheError::ZeroCapacity);
        }
        if !page_size.is_power_of_two() {
            return Err(CacheError::InvalidPageSize(page_size));
        }
        Ok(Self {
            pages: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
            page_size,
            eviction,
        })
    }

    /// Align address down to the page boundary.
    #[must_use]
    pub const fn page_base(&self, addr: u64) -> u64 {
        addr & !(self.page_size as u64 - 1)
    }

    /// Returns `true` if the given page base address is cached.
    #[must_use]
    pub fn contains(&self, page_addr: u64) -> bool {
        self.pages.contains_key(&page_addr)
    }

    /// Look up a page, promoting it in the LRU order.
    pub fn get_mut(&mut self, page_addr: u64) -> Option<&mut CachePage> {
        if !self.pages.contains_key(&page_addr) {
            return None;
        }
        if self.eviction == CacheEviction::Lru {
            self.order.retain(|&a| a != page_addr);
            self.order.push_back(page_addr);
        }
        self.pages.get_mut(&page_addr)
    }

    /// Insert a page, evicting if necessary. Returns the evicted page if any.
    pub fn insert(&mut self, addr: u64, data: Vec<u8>) -> Option<CachePage> {
        let page_addr = self.page_base(addr);
        let mut evicted = None;
        if self.pages.len() >= self.capacity && !self.pages.contains_key(&page_addr) {
            let victim = self.order.pop_front();
            if let Some(v) = victim {
                evicted = self.pages.remove(&v);
            }
        }
        self.pages.insert(
            page_addr,
            CachePage {
                addr: page_addr,
                data,
                dirty: false,
            },
        );
        self.order.retain(|&a| a != page_addr);
        self.order.push_back(page_addr);
        evicted
    }

    /// Invalidate (remove) a specific page. Returns the removed page if present.
    pub fn invalidate(&mut self, page_addr: u64) -> Option<CachePage> {
        self.order.retain(|&a| a != page_addr);
        self.pages.remove(&page_addr)
    }

    /// Invalidate all pages in the range [addr, addr+len).
    pub fn invalidate_range(&mut self, addr: u64, len: u64) -> Vec<u64> {
        let mut invalidated = Vec::new();
        let start = self.page_base(addr);
        let end = self.page_base(addr + len.saturating_sub(1));
        let mut p = start;
        while p <= end {
            if self.invalidate(p).is_some() {
                invalidated.push(p);
            }
            p = p.wrapping_add(self.page_size as u64);
        }
        invalidated
    }

    /// Mark a page dirty (write-back mode).
    pub fn mark_dirty(&mut self, page_addr: u64) {
        if let Some(page) = self.pages.get_mut(&page_addr) {
            page.dirty = true;
        }
    }

    /// Collect all dirty pages.
    #[must_use] 
    pub fn dirty_pages(&self) -> Vec<&CachePage> {
        self.pages.values().filter(|p| p.dirty).collect()
    }

    /// Clear all pages.
    pub fn clear(&mut self) {
        self.pages.clear();
        self.order.clear();
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.pages.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pages.is_empty()
    }

    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    #[must_use]
    pub const fn page_size(&self) -> usize {
        self.page_size
    }
}

// ── CacheLayer ────────────────────────────────────────────────────────────────

/// LRU cache layered over an arbitrary [`MemoryProvider`].
///
/// Page-granularity caching; supports write-through and write-back.
pub struct CacheLayer<P: MemoryProvider> {
    inner: P,
    cache: Mutex<PageCache>,
    stats: Mutex<CacheStats>,
    write_policy: WriteThrough,
    invalidation_log: Arc<CacheInvalidation>,
}

impl<P: MemoryProvider> CacheLayer<P> {
    // ── Constructor ───────────────────────────────────────────────────────────

    /// Create a new cache layer.
    ///
    /// # Errors
    /// Propagates [`PageCache::new`] errors.
    pub fn new(
        inner: P,
        capacity: usize,
        page_size: usize,
        write_policy: WriteThrough,
        eviction: CacheEviction,
    ) -> CacheResult<Self> {
        let cache = PageCache::new(capacity, page_size, eviction)?;
        Ok(Self {
            inner,
            cache: Mutex::new(cache),
            stats: Mutex::new(CacheStats::new()),
            write_policy,
            invalidation_log: Arc::new(CacheInvalidation::new(1024)),
        })
    }

    /// Convenience: create with LRU eviction and write-through policy.
    pub fn new_lru(inner: P, capacity: usize, page_size: usize) -> CacheResult<Self> {
        Self::new(
            inner,
            capacity,
            page_size,
            WriteThrough::Enabled,
            CacheEviction::Lru,
        )
    }

    // ── Read ──────────────────────────────────────────────────────────────────

    /// Read `len` bytes from `addr` using the cache.
    pub fn read(&self, addr: u64, len: usize) -> CacheResult<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }

        let mut stats = self.stats.lock();
        stats.reads += 1;

        let mut cache = self.cache.lock();
        let page_size = cache.page_size();
        let page_addr = cache.page_base(addr);

        if let Some(page) = cache.get_mut(page_addr) {
            let offset = (addr - page_addr) as usize;
            if offset + len <= page.data.len() {
                stats.hits += 1;
                return Ok(page.data[offset..offset + len].to_vec());
            }
        }

        // Cache miss: fetch from backing store.
        stats.misses += 1;
        drop(stats);
        drop(cache);

        // Fetch an aligned page.
        let page_data = self
            .inner
            .read(rustre_core::address::Address::new(page_addr), page_size)
            .map_err(CacheError::from)?;

        let mut cache = self.cache.lock();
        cache.insert(page_addr, page_data);

        let page = cache.get_mut(page_addr).unwrap();
        let offset = (addr - page_addr) as usize;
        let end = (offset + len).min(page.data.len());
        Ok(page.data[offset..end].to_vec())
    }

    // ── Write ─────────────────────────────────────────────────────────────────

    /// Write `data` to `addr`, respecting the write policy.
    pub fn write(&mut self, addr: u64, data: &[u8]) -> CacheResult<()> {
        let mut stats = self.stats.lock();
        stats.writes += 1;

        if data.is_empty() {
            return Ok(());
        }

        match self.write_policy {
            WriteThrough::Enabled => {
                stats.write_throughs += 1;
                drop(stats);
                // Write to backing store first.
                self.inner
                    .write(rustre_core::address::Address::new(addr), data)
                    .map_err(CacheError::from)?;
                // Invalidate cached pages covering this range.
                let invalidated = self.cache.lock().invalidate_range(addr, data.len() as u64);
                let mut s = self.stats.lock();
                s.invalidations += invalidated.len() as u64;
                for page_addr in invalidated {
                    self.invalidation_log
                        .record(page_addr, "write-through invalidation");
                }
            }
            WriteThrough::Disabled => {
                drop(stats);
                // Write to cache only; mark dirty.
                let mut cache = self.cache.lock();
                let page_size = cache.page_size();
                let page_addr = cache.page_base(addr);

                if cache.contains(page_addr) {
                    let page = cache.get_mut(page_addr).unwrap();
                    let offset = (addr - page_addr) as usize;
                    let end = (offset + data.len()).min(page.data.len());
                    page.data[offset..end].copy_from_slice(&data[..end - offset]);
                    page.dirty = true;
                } else {
                    // Load the page first.
                    drop(cache);
                    let page_data = self
                        .inner
                        .read(rustre_core::address::Address::new(page_addr), page_size)
                        .map_err(CacheError::from)?;
                    let mut cache = self.cache.lock();
                    cache.insert(page_addr, page_data);
                    let page = cache.get_mut(page_addr).unwrap();
                    let offset = (addr - page_addr) as usize;
                    let end = (offset + data.len()).min(page.data.len());
                    page.data[offset..end].copy_from_slice(&data[..end - offset]);
                    page.dirty = true;
                }
            }
        }
        Ok(())
    }

    // ── Flush ─────────────────────────────────────────────────────────────────

    /// Flush all dirty pages to the backing store (write-back mode).
    pub fn flush_dirty(&mut self) -> CacheResult<usize> {
        let cache = self.cache.lock();
        let dirty: Vec<_> = cache
            .dirty_pages()
            .iter()
            .map(|p| (p.addr, p.data.clone()))
            .collect();
        let count = dirty.len();
        drop(cache);
        for (page_addr, data) in dirty {
            self.inner
                .write(rustre_core::address::Address::new(page_addr), &data)
                .map_err(CacheError::from)?;
            let mut cache = self.cache.lock();
            if let Some(page) = cache.get_mut(page_addr) {
                page.dirty = false;
            }
        }
        Ok(count)
    }

    // ── Invalidation ─────────────────────────────────────────────────────────

    /// Invalidate all cached pages covering [addr, addr+len).
    pub fn invalidate_range(&self, addr: u64, len: u64) -> usize {
        let invalidated = self.cache.lock().invalidate_range(addr, len);
        let count = invalidated.len();
        let mut stats = self.stats.lock();
        stats.invalidations += count as u64;
        for page_addr in invalidated {
            self.invalidation_log
                .record(page_addr, "explicit invalidation");
        }
        count
    }

    /// Invalidate the entire cache.
    pub fn invalidate_all(&self) {
        self.cache.lock().clear();
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// Get a snapshot of the current cache statistics.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        self.stats.lock().clone()
    }

    /// Reset statistics.
    pub fn reset_stats(&self) {
        self.stats.lock().reset();
    }

    /// Number of pages currently held in the cache.
    #[must_use]
    pub fn cached_pages(&self) -> usize {
        self.cache.lock().len()
    }

    /// The cache capacity in pages.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.cache.lock().capacity()
    }

    /// The page size in bytes.
    #[must_use]
    pub fn page_size(&self) -> usize {
        self.cache.lock().page_size()
    }

    /// The write policy.
    #[must_use]
    pub const fn write_policy(&self) -> WriteThrough {
        self.write_policy
    }

    /// A reference to the invalidation log.
    pub fn invalidation_log(&self) -> Arc<CacheInvalidation> {
        Arc::clone(&self.invalidation_log)
    }

    /// Access the underlying provider (immutable).
    #[must_use]
    pub const fn inner(&self) -> &P {
        &self.inner
    }

    /// Access the underlying provider mutably.
    pub const fn inner_mut(&mut self) -> &mut P {
        &mut self.inner
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use async_trait::async_trait;
    use rustre_core::address::Address;

    // ── Stub MemoryProvider ───────────────────────────────────────────────────

    #[derive(Clone)]
    pub(crate) struct FlatMemory {
        data: Arc<Mutex<Vec<u8>>>,
    }

    impl FlatMemory {
        pub(crate) fn new(size: usize) -> Self {
            Self {
                data: Arc::new(Mutex::new(vec![0u8; size])),
            }
        }
        pub(crate) fn fill(&self, byte: u8) {
            self.data.lock().iter_mut().for_each(|b| *b = byte);
        }
    }

    #[async_trait]
    impl MemoryProvider for FlatMemory {
        fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
            let data = self.data.lock();
            let a = addr.as_u64() as usize;
            if a + len > data.len() {
                return Err(MemError::OutOfBounds(addr, len));
            }
            Ok(data[a..a + len].to_vec())
        }
        fn write(&mut self, addr: Address, buf: &[u8]) -> Result<(), MemError> {
            let mut data = self.data.lock();
            let a = addr.as_u64() as usize;
            if a + buf.len() > data.len() {
                return Err(MemError::OutOfBounds(addr, buf.len()));
            }
            data[a..a + buf.len()].copy_from_slice(buf);
            Ok(())
        }
        fn regions(&self) -> Vec<MemoryRegion> {
            vec![]
        }
    }

    fn make_layer(cap: usize) -> CacheLayer<FlatMemory> {
        let mem = FlatMemory::new(65536);
        CacheLayer::new_lru(mem, cap, 256).unwrap()
    }

    /// Same, but also hands back a handle to the backing store so a test can
    /// change the bytes *behind* the cache.
    ///
    /// ⚠ `FlatMemory::fill` existed and had no caller: every cache test read
    /// through a backing store that never changed, so nothing ever exercised
    /// the one behaviour a cache can get wrong — serving a stale page after the
    /// source moved. `FlatMemory` is `Clone` over an `Arc`, so the handle and
    /// the store inside the layer are the same memory.
    pub(crate) fn make_layer_with_backing(cap: usize) -> (CacheLayer<FlatMemory>, FlatMemory) {
        let mem = FlatMemory::new(65536);
        let handle = mem.clone();
        (CacheLayer::new_lru(mem, cap, 256).unwrap(), handle)
    }

    // ── PageCache ─────────────────────────────────────────────────────────────

    #[test]
    fn test_page_cache_invalid_page_size() {
        let err = PageCache::new(4, 300, CacheEviction::Lru);
        assert!(matches!(err, Err(CacheError::InvalidPageSize(300))));
    }

    #[test]
    fn test_page_cache_zero_capacity() {
        let err = PageCache::new(0, 256, CacheEviction::Lru);
        assert!(matches!(err, Err(CacheError::ZeroCapacity)));
    }

    #[test]
    fn test_page_cache_insert_and_contains() {
        let mut pc = PageCache::new(4, 256, CacheEviction::Lru).unwrap();
        let data = vec![0u8; 256];
        pc.insert(0, data);
        assert!(pc.contains(0));
        assert!(!pc.contains(256));
    }

    #[test]
    fn test_page_cache_eviction_lru() {
        let mut pc = PageCache::new(2, 256, CacheEviction::Lru).unwrap();
        pc.insert(0, vec![1u8; 256]);
        pc.insert(256, vec![2u8; 256]);
        // Access page 0 to make it recently used.
        pc.get_mut(0);
        // Insert a third page — should evict page 256 (LRU).
        pc.insert(512, vec![3u8; 256]);
        assert!(pc.contains(0));
        assert!(!pc.contains(256));
        assert!(pc.contains(512));
    }

    #[test]
    fn test_page_cache_invalidate() {
        let mut pc = PageCache::new(4, 256, CacheEviction::Lru).unwrap();
        pc.insert(0, vec![0u8; 256]);
        pc.invalidate(0);
        assert!(!pc.contains(0));
    }

    #[test]
    fn test_page_cache_invalidate_range() {
        let mut pc = PageCache::new(8, 256, CacheEviction::Lru).unwrap();
        pc.insert(0, vec![0u8; 256]);
        pc.insert(256, vec![0u8; 256]);
        pc.insert(512, vec![0u8; 256]);
        let removed = pc.invalidate_range(0, 512);
        assert_eq!(removed.len(), 2);
        assert!(!pc.contains(0));
        assert!(!pc.contains(256));
        assert!(pc.contains(512));
    }

    #[test]
    fn test_page_cache_dirty() {
        let mut pc = PageCache::new(4, 256, CacheEviction::Lru).unwrap();
        pc.insert(0, vec![0u8; 256]);
        assert!(pc.dirty_pages().is_empty());
        pc.mark_dirty(0);
        assert_eq!(pc.dirty_pages().len(), 1);
    }

    #[test]
    fn test_page_cache_clear() {
        let mut pc = PageCache::new(4, 256, CacheEviction::Lru).unwrap();
        pc.insert(0, vec![0u8; 256]);
        pc.insert(256, vec![0u8; 256]);
        pc.clear();
        assert!(pc.is_empty());
    }

    #[test]
    fn test_page_base() {
        let pc = PageCache::new(4, 256, CacheEviction::Lru).unwrap();
        assert_eq!(pc.page_base(0), 0);
        assert_eq!(pc.page_base(255), 0);
        assert_eq!(pc.page_base(256), 256);
        assert_eq!(pc.page_base(511), 256);
        assert_eq!(pc.page_base(512), 512);
    }

    // ── CacheLayer reads ──────────────────────────────────────────────────────

    #[test]
    fn test_cache_layer_read_miss_then_hit() {
        let layer = make_layer(4);
        // First read — miss.
        let data = layer.read(0, 10).unwrap();
        assert_eq!(data.len(), 10);
        let stats = layer.stats();
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, 0);

        // Second read from same page — hit.
        let _data2 = layer.read(0, 10).unwrap();
        let stats = layer.stats();
        assert_eq!(stats.hits, 1);
    }

    #[test]
    fn test_cache_layer_read_correct_data() {
        let mut layer = make_layer(4);
        layer.inner_mut().write(Address::new(0), &[1, 2, 3, 4, 5]).unwrap();
        let data = layer.read(0, 5).unwrap();
        assert_eq!(data, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_cache_layer_empty_read() {
        let layer = make_layer(4);
        let data = layer.read(0, 0).unwrap();
        assert!(data.is_empty());
    }

    // ── CacheLayer writes (write-through) ────────────────────────────────────

    #[test]
    fn test_cache_write_through_reaches_backing() {
        let mut layer = make_layer(4);
        layer.write(0, &[0xAB, 0xCD]).unwrap();
        let raw = layer.inner().read(Address::new(0), 2).unwrap();
        assert_eq!(raw, vec![0xAB, 0xCD]);
    }

    #[test]
    fn test_cache_write_through_invalidates_page() {
        let mut layer = make_layer(4);
        // Load page 0 into cache.
        let _ = layer.read(0, 10).unwrap();
        assert_eq!(layer.cached_pages(), 1);
        // Write-through write should invalidate the cached page.
        layer.write(0, &[0xFF]).unwrap();
        assert_eq!(layer.cached_pages(), 0);
    }

    // ── CacheLayer writes (write-back) ────────────────────────────────────────

    #[test]
    fn test_cache_write_back_not_immediate() {
        let mem = FlatMemory::new(65536);
        let mut layer = CacheLayer::new(
            mem.clone(),
            4,
            256,
            WriteThrough::Disabled,
            CacheEviction::Lru,
        )
        .unwrap();
        layer.write(0, &[0xBB]).unwrap();
        // Backing store should still have 0.
        let raw = mem.read(Address::new(0), 1).unwrap();
        assert_eq!(raw, vec![0]);
    }

    #[test]
    fn test_cache_write_back_flush() {
        let mem = FlatMemory::new(65536);
        let mut layer = CacheLayer::new(
            mem.clone(),
            4,
            256,
            WriteThrough::Disabled,
            CacheEviction::Lru,
        )
        .unwrap();
        layer.write(0, &[0xCC]).unwrap();
        let flushed = layer.flush_dirty().unwrap();
        assert_eq!(flushed, 1);
        let raw = mem.read(Address::new(0), 1).unwrap();
        assert_eq!(raw, vec![0xCC]);
    }

    // ── Invalidation ─────────────────────────────────────────────────────────

    #[test]
    fn test_invalidate_range() {
        let layer = make_layer(8);
        let _ = layer.read(0, 10).unwrap();
        let _ = layer.read(256, 10).unwrap();
        assert_eq!(layer.cached_pages(), 2);
        let n = layer.invalidate_range(0, 512);
        assert_eq!(n, 2);
        assert_eq!(layer.cached_pages(), 0);
    }

    #[test]
    fn test_invalidate_all() {
        let layer = make_layer(8);
        let _ = layer.read(0, 10).unwrap();
        let _ = layer.read(256, 10).unwrap();
        layer.invalidate_all();
        assert_eq!(layer.cached_pages(), 0);
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_stats_hit_ratio_zero_accesses() {
        let stats = CacheStats::new();
        assert_eq!(stats.hit_ratio(), 0.0);
    }

    #[test]
    fn test_stats_hit_ratio_all_hits() {
        let mut stats = CacheStats::new();
        stats.hits = 10;
        assert_eq!(stats.hit_ratio(), 1.0);
    }

    #[test]
    fn test_stats_reset() {
        let mut stats = CacheStats::new();
        stats.hits = 100;
        stats.misses = 50;
        stats.reset();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
    }

    #[test]
    fn test_cache_layer_reset_stats() {
        let layer = make_layer(4);
        let _ = layer.read(0, 10).unwrap();
        layer.reset_stats();
        assert_eq!(layer.stats().reads, 0);
    }

    // ── CacheInvalidation ─────────────────────────────────────────────────────

    #[test]
    fn test_cache_invalidation_record() {
        let ci = CacheInvalidation::new(10);
        ci.record(0x1000, "test");
        assert_eq!(ci.count(), 1);
    }

    #[test]
    fn test_cache_invalidation_overflow_evicts() {
        let ci = CacheInvalidation::new(3);
        ci.record(0x1000, "a");
        ci.record(0x2000, "b");
        ci.record(0x3000, "c");
        ci.record(0x4000, "d"); // evicts oldest
        assert_eq!(ci.count(), 3);
        let recs = ci.records();
        assert_eq!(recs[0].page_addr, 0x2000);
    }

    #[test]
    fn test_cache_invalidation_clear() {
        let ci = CacheInvalidation::new(10);
        ci.record(0, "x");
        ci.clear();
        assert_eq!(ci.count(), 0);
    }

    // ── write_policy accessor ─────────────────────────────────────────────────

    #[test]
    fn test_write_policy_through() {
        let layer = make_layer(4);
        assert_eq!(layer.write_policy(), WriteThrough::Enabled);
    }

    #[test]
    fn test_write_policy_back() {
        let mem = FlatMemory::new(65536);
        let layer_imm =
            CacheLayer::new(mem, 4, 256, WriteThrough::Disabled, CacheEviction::Lru).unwrap();
        assert_eq!(layer_imm.write_policy(), WriteThrough::Disabled);
    }

    // ── capacity/page_size ────────────────────────────────────────────────────

    #[test]
    fn test_capacity_and_page_size() {
        let layer = make_layer(8);
        assert_eq!(layer.capacity(), 8);
        assert_eq!(layer.page_size(), 256);
    }

    // ── stats display ─────────────────────────────────────────────────────────

    #[test]
    fn test_stats_display() {
        let mut s = CacheStats::new();
        s.hits = 5;
        s.misses = 5;
        let display = format!("{}", s);
        assert!(display.contains("hits=5"));
        assert!(display.contains("misses=5"));
        assert!(display.contains("ratio=0.50"));
    }

    // ── FIFO eviction ─────────────────────────────────────────────────────────

    #[test]
    fn test_fifo_eviction_order() {
        let mut pc = PageCache::new(2, 256, CacheEviction::Fifo).unwrap();
        pc.insert(0, vec![1u8; 256]);
        pc.insert(256, vec![2u8; 256]);
        // Access page 0 — in FIFO, access order doesn't matter.
        pc.get_mut(0);
        pc.insert(512, vec![3u8; 256]);
        // FIFO evicts oldest insert: page 0.
        assert!(!pc.contains(0));
        assert!(pc.contains(256));
        assert!(pc.contains(512));
    }

    // ── multi-page read (cross-boundary) ─────────────────────────────────────

    #[test]
    fn test_stats_incremented_on_reads() {
        let layer = make_layer(4);
        let _ = layer.read(0, 5).unwrap();
        let _ = layer.read(0, 5).unwrap();
        let stats = layer.stats();
        assert_eq!(stats.reads, 2);
        assert_eq!(stats.hits + stats.misses, 2);
    }

    #[test]
    fn test_write_increments_stats() {
        let mut layer = make_layer(4);
        layer.write(0, &[1]).unwrap();
        assert_eq!(layer.stats().writes, 1);
    }

    #[test]
    fn test_cache_inner_accessor() {
        let layer = make_layer(4);
        // inner() returns the underlying memory provider
        let _ = layer.inner();
    }

    #[test]
    fn test_cache_invalidation_log_accessible() {
        let layer = make_layer(4);
        let log = layer.invalidation_log();
        assert_eq!(log.count(), 0);
    }

    #[test]
    fn test_write_through_increments_write_throughs() {
        let mut layer = make_layer(4);
        layer.write(0, &[0xAB]).unwrap();
        assert_eq!(layer.stats().write_throughs, 1);
    }

    #[test]
    fn test_page_cache_fifo_basic() {
        let mut pc = PageCache::new(4, 256, CacheEviction::Fifo).unwrap();
        pc.insert(0, vec![1u8; 256]);
        assert!(pc.contains(0));
        assert_eq!(pc.len(), 1);
    }

    #[test]
    fn test_cache_empty_write_is_noop() {
        let mut layer = make_layer(4);
        layer.write(0, &[]).unwrap();
        assert_eq!(layer.stats().writes, 1); // call counted even if no-op
    }

    #[test]
    fn test_cache_stats_default() {
        let s = CacheStats::default();
        assert_eq!(s.hits, 0);
        assert_eq!(s.misses, 0);
    }

    #[test]
    fn test_flush_dirty_empty() {
        let mem = FlatMemory::new(65536);
        let mut layer =
            CacheLayer::new(mem, 4, 256, WriteThrough::Disabled, CacheEviction::Lru).unwrap();
        let flushed = layer.flush_dirty().unwrap();
        assert_eq!(flushed, 0);
    }

    #[test]
    fn test_invalidation_record_page_addr() {
        let ci = CacheInvalidation::new(10);
        ci.record(0xDEAD, "test reason");
        let recs = ci.records();
        assert_eq!(recs[0].page_addr, 0xDEAD);
        assert_eq!(recs[0].reason, "test reason");
    }

    #[test]
    fn test_cache_write_through_increments_invalidations() {
        let mut layer = make_layer(4);
        // Load page.
        let _ = layer.read(0, 10).unwrap();
        // Write invalidates the page.
        layer.write(0, &[1]).unwrap();
        assert!(layer.stats().invalidations >= 1);
    }

    #[test]
    fn test_page_cache_mark_and_clear() {
        let mut pc = PageCache::new(4, 256, CacheEviction::Lru).unwrap();
        pc.insert(0, vec![0u8; 256]);
        pc.mark_dirty(0);
        assert_eq!(pc.dirty_pages().len(), 1);
        pc.clear();
        assert!(pc.is_empty());
    }

    #[test]
    fn test_cache_layer_new_lru_valid_params() {
        let mem = FlatMemory::new(4096);
        assert!(CacheLayer::new_lru(mem, 4, 256).is_ok());
    }

    #[test]
    fn test_cache_layer_invalid_page_size() {
        let mem = FlatMemory::new(4096);
        let r = CacheLayer::new(mem, 4, 300, WriteThrough::Enabled, CacheEviction::Lru);
        assert!(matches!(r, Err(CacheError::InvalidPageSize(300))));
    }

    #[test]
    fn test_cache_error_from_mem_error() {
        let e = MemError::OutOfBounds(rustre_core::address::Address::new(0), 1);
        let ce: CacheError = e.into();
        assert!(matches!(ce, CacheError::Memory(_)));
    }

    #[test]
    fn test_page_cache_len_after_inserts() {
        let mut pc = PageCache::new(8, 256, CacheEviction::Lru).unwrap();
        pc.insert(0, vec![0u8; 256]);
        pc.insert(256, vec![0u8; 256]);
        assert_eq!(pc.len(), 2);
    }

    #[test]
    fn test_cache_stats_write_through_count() {
        let mut layer = make_layer(4);
        layer.write(0, &[1]).unwrap();
        layer.write(256, &[2]).unwrap();
        assert_eq!(layer.stats().write_throughs, 2);
    }
}

#[cfg(test)]
mod staleness_tests {
    //! The behaviour a cache exists to optimise is also the one it can get
    //! wrong: after the backing store changes, a cached page is stale until it
    //! is invalidated. No test covered this, because the fixture that mutates
    //! the backing store (`FlatMemory::fill`) had no caller.

    use super::tests::*;

    /// A page read once is served from the cache afterwards, so a change made
    /// behind the layer is NOT visible until invalidation. This pins the
    /// current contract; if the layer ever starts revalidating, this test is
    /// the one that must be updated deliberately.
    #[test]
    fn a_cached_page_hides_a_later_backing_write() {
        let (layer, backing) = make_layer_with_backing(4);

        let first = layer.read(0, 8).expect("first read populates the cache");
        assert_eq!(first, vec![0u8; 8], "the store starts zeroed");

        backing.fill(0xAB);

        let cached = layer.read(0, 8).expect("second read is served from cache");
        assert_eq!(cached, vec![0u8; 8], "still the cached page, by design");
    }

    /// After invalidating the range, the same read must observe the new bytes.
    /// This is the half that proves the staleness above is a cache effect and
    /// not a broken backing store.
    #[test]
    fn invalidation_makes_the_backing_write_visible() {
        let (layer, backing) = make_layer_with_backing(4);

        let _ = layer.read(0, 8).expect("populate");
        backing.fill(0xAB);
        let dropped = layer.invalidate_range(0, 8);
        assert!(dropped > 0, "the page holding [0,8) must be dropped");

        let fresh = layer.read(0, 8).expect("re-read after invalidation");
        assert_eq!(fresh, vec![0xABu8; 8], "the new bytes must be visible now");
    }

    /// `invalidate_all` must have the same effect as invalidating the range.
    #[test]
    fn invalidate_all_also_refreshes() {
        let (layer, backing) = make_layer_with_backing(4);

        let _ = layer.read(1024, 4).expect("populate");
        backing.fill(0x5A);
        layer.invalidate_all();

        assert_eq!(layer.read(1024, 4).unwrap(), vec![0x5Au8; 4]);
    }
}
