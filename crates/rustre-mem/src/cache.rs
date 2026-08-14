/// Page-granular read cache for slow `MemoryProvider` implementations.
///
/// `PageCache` divides the address space into fixed-size pages (default 4 KiB)
/// and caches entire pages after the first read.  Subsequent reads that fall
/// within a cached page are served entirely from RAM without touching the
/// underlying provider.  This is critical for `ProcessMemoryProvider` and
/// `TraceMemoryProvider` where every read requires a syscall or IPC call.
///
/// # Design notes
/// - Cache entries track a "dirty" flag so that writes can invalidate the
///   corresponding page.
/// - A configurable capacity (in pages) evicts the least-recently-used entry
///   when full, using a simple timestamp counter as a proxy for recency.
/// - The cache is **not** thread-safe; synchronisation is the caller's
///   responsibility (typically `parking_lot::RwLock` in the provider).
use rustre_core::address::{Address, AddressRange};
use std::collections::HashMap;

// ─────────────────────────────────────────────────────────────────────────────
// CachedPage
// ─────────────────────────────────────────────────────────────────────────────

/// A single cached page.
#[derive(Debug, Clone)]
struct CachedPage {
    /// The cached bytes (length == `page_size`).
    data: Vec<u8>,
    /// Logical "last access" timestamp (monotonically increasing counter).
    last_access: u64,
    /// `true` if the page has been written-to and needs to be flushed.
    dirty: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// CacheStats
// ─────────────────────────────────────────────────────────────────────────────

/// Counters gathered by the cache for diagnostic purposes.
#[derive(Debug, Clone, Copy, Default)]
pub struct CacheStats {
    /// Number of read operations served entirely from cache (no provider call).
    pub read_hits: u64,
    /// Number of read operations that required loading a new page from the provider.
    pub read_misses: u64,
    /// Number of page evictions due to capacity constraints.
    pub evictions: u64,
    /// Number of invalidations triggered by write operations.
    pub invalidations: u64,
}

impl CacheStats {
    /// Hit rate as a value in `[0.0, 1.0]`, or `0.0` if no reads have occurred.
    #[must_use]
    pub fn hit_rate(&self) -> f64 {
        let total = self.read_hits + self.read_misses;
        if total == 0 {
            0.0
        } else {
            self.read_hits as f64 / total as f64
        }
    }

    /// Total number of reads.
    #[must_use]
    pub const fn total_reads(&self) -> u64 {
        self.read_hits + self.read_misses
    }
}

impl std::fmt::Display for CacheStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PageCache hits={} misses={} evictions={} invalidations={} hit_rate={:.1}%",
            self.read_hits,
            self.read_misses,
            self.evictions,
            self.invalidations,
            self.hit_rate() * 100.0,
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PageCache
// ─────────────────────────────────────────────────────────────────────────────

/// Page-granular LRU read cache.
///
/// # Type parameter
/// `PageCache` is generic over `F`, a callable `(Address, usize) -> Vec<u8>` that
/// fetches a page from the underlying provider.  In practice callers pass a
/// closure capturing the provider.
pub struct PageCache {
    /// `page_index → CachedPage`.
    pages: HashMap<u64, CachedPage>,
    /// Page size in bytes.  Must be a power of two.
    page_size: u64,
    /// Maximum number of pages to keep in cache (0 = unlimited).
    capacity: usize,
    /// Monotonically increasing logical clock for LRU tracking.
    clock: u64,
    /// Accumulated statistics.
    pub stats: CacheStats,
}

impl PageCache {
    /// Create a cache with the given `page_size` and `capacity` (in pages).
    ///
    /// `capacity = 0` means unlimited.
    ///
    /// # Panics
    /// Panics if `page_size` is not a power of two or is zero.
    #[must_use]
    pub fn new(page_size: u64, capacity: usize) -> Self {
        assert!(
            page_size.is_power_of_two() && page_size > 0,
            "page_size must be a non-zero power of two"
        );
        Self {
            pages: if capacity > 0 {
                HashMap::with_capacity(capacity.min(1024))
            } else {
                HashMap::new()
            },
            page_size,
            capacity,
            clock: 0,
            stats: CacheStats::default(),
        }
    }

    /// Create a cache with 4 KiB pages and capacity for 1024 pages (4 MiB).
    #[must_use]
    pub fn default_4k() -> Self {
        Self::new(0x1000, 1024)
    }

    /// The configured page size in bytes.
    #[must_use]
    pub const fn page_size(&self) -> u64 {
        self.page_size
    }

    /// Number of pages currently held in cache.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pages.len()
    }

    /// Return `true` if no pages are cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pages.is_empty()
    }

    /// Flush all cached pages.
    pub fn invalidate_all(&mut self) {
        self.stats.invalidations += self.pages.len() as u64;
        self.pages.clear();
    }

    /// Invalidate all pages that overlap with `range`.
    ///
    /// This must be called after any write to ensure subsequent reads return the
    /// freshly-written data.
    pub fn invalidate_range(&mut self, range: AddressRange) {
        if range.is_empty() {
            return;
        }
        let first_page = range.start.as_u64() / self.page_size;
        let last_page = (range.end.as_u64().saturating_sub(1)) / self.page_size;
        let count_before = self.pages.len() as u64;
        for page_idx in first_page..=last_page {
            self.pages.remove(&page_idx);
        }
        let removed = count_before - self.pages.len() as u64;
        self.stats.invalidations += removed;
    }

    /// Invalidate the single page that contains `addr`.
    pub fn invalidate_page(&mut self, addr: Address) {
        let page_idx = addr.as_u64() / self.page_size;
        if self.pages.remove(&page_idx).is_some() {
            self.stats.invalidations += 1;
        }
    }

    /// Read `len` bytes starting at `addr`, using `fetch_page` to load cache
    /// misses.
    ///
    /// `fetch_page(page_start: Address, page_size: usize) -> Result<Vec<u8>, E>`
    /// is called at most once per missing page.  The returned `Vec` must have
    /// exactly `page_size` bytes; if it is shorter the rest is zero-padded, if
    /// it is longer it is truncated.
    ///
    /// # Errors
    /// Propagates any error returned by `fetch_page`.
    pub fn read<E, F>(&mut self, addr: Address, len: usize, mut fetch_page: F) -> Result<Vec<u8>, E>
    where
        F: FnMut(Address, usize) -> Result<Vec<u8>, E>,
    {
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut result = Vec::with_capacity(len);
        let page_mask = self.page_size - 1;
        let mut remaining = len;
        let mut current = addr.as_u64();

        while remaining > 0 {
            let page_idx = current / self.page_size;
            let page_start = page_idx * self.page_size;
            let offset_in_page = (current - page_start) as usize;
            let bytes_from_this_page = ((self.page_size as usize - offset_in_page).min(remaining))
                .min(self.page_size as usize);

            // Look up or fetch the page.
            if self.pages.contains_key(&page_idx) {
                self.stats.read_hits += 1;
            } else {
                // Cache miss.
                self.stats.read_misses += 1;
                let ps = self.page_size as usize;
                let mut data = fetch_page(Address::new(page_start), ps)?;
                // Normalise length.
                if data.len() < ps {
                    data.resize(ps, 0u8);
                } else if data.len() > ps {
                    data.truncate(ps);
                }
                self.clock += 1;
                let entry = CachedPage {
                    data,
                    last_access: self.clock,
                    dirty: false,
                };
                // Evict if at capacity.
                if self.capacity > 0 && self.pages.len() >= self.capacity {
                    self.evict_lru();
                }
                self.pages.insert(page_idx, entry);
            }

            let page = self.pages.get_mut(&page_idx).expect("just inserted");
            self.clock += 1;
            page.last_access = self.clock;
            let end = offset_in_page + bytes_from_this_page;
            result.extend_from_slice(&page.data[offset_in_page..end]);
            current = current.saturating_add(bytes_from_this_page as u64);
            remaining -= bytes_from_this_page;
        }

        let _ = page_mask; // suppress unused warning
        Ok(result)
    }

    /// Store `data` into the cache without writing to the underlying provider.
    ///
    /// This is used by `EmulatedMemoryProvider` where the cache *is* the
    /// backing store — writes go directly into cached pages.
    ///
    /// Pages that do not yet exist are created on demand (filled with zeros
    /// first).
    pub fn write_into_cache(&mut self, addr: Address, data: &[u8]) {
        let mut remaining = data.len();
        let mut src_offset = 0usize;
        let mut current = addr.as_u64();

        while remaining > 0 {
            let page_idx = current / self.page_size;
            let page_start = page_idx * self.page_size;
            let offset_in_page = (current - page_start) as usize;
            let bytes_this_page = (self.page_size as usize - offset_in_page).min(remaining);

            let ps = self.page_size as usize;
            let entry = self.pages.entry(page_idx).or_insert_with(|| CachedPage {
                data: vec![0u8; ps],
                last_access: 0,
                dirty: false,
            });
            self.clock += 1;
            entry.last_access = self.clock;
            entry.dirty = true;
            let end_in_page = offset_in_page + bytes_this_page;
            entry.data[offset_in_page..end_in_page]
                .copy_from_slice(&data[src_offset..src_offset + bytes_this_page]);

            current += bytes_this_page as u64;
            src_offset += bytes_this_page;
            remaining -= bytes_this_page;
        }
    }

    /// Return `true` if the page containing `addr` is currently cached.
    #[must_use]
    pub fn is_cached(&self, addr: Address) -> bool {
        let page_idx = addr.as_u64() / self.page_size;
        self.pages.contains_key(&page_idx)
    }

    /// Pre-populate the cache with `data` starting at `base_addr`.
    ///
    /// This is useful during `EmulatedMemoryProvider` initialization, where we
    /// want to seed the cache with the entire binary image rather than loading
    /// pages on demand.
    pub fn seed(&mut self, base_addr: Address, data: &[u8]) {
        self.write_into_cache(base_addr, data);
    }

    /// Return the address range covered by the cache (smallest start to largest end).
    /// Returns `None` if the cache is empty.
    #[must_use]
    pub fn covered_range(&self) -> Option<AddressRange> {
        if self.pages.is_empty() {
            return None;
        }
        let min_page = *self.pages.keys().min().unwrap();
        let max_page = *self.pages.keys().max().unwrap();
        Some(AddressRange::new(
            Address::new(min_page * self.page_size),
            Address::new((max_page + 1) * self.page_size),
        ))
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    /// Evict the least-recently-used page.
    fn evict_lru(&mut self) {
        if self.pages.is_empty() {
            return;
        }
        // `pages` is a HashMap and `last_access` ties easily (coarse clock,
        // bursts of accesses), so without a tie-break on the page index the
        // victim of an eviction differs between runs on identical input.
        let (&lru_idx, _) = self
            .pages
            .iter()
            .min_by(|a, b| a.1.last_access.cmp(&b.1.last_access).then(a.0.cmp(b.0)))
            .unwrap();
        self.pages.remove(&lru_idx);
        self.stats.evictions += 1;
    }
}

impl std::fmt::Debug for PageCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PageCache")
            .field("page_size", &self.page_size)
            .field("capacity", &self.capacity)
            .field("cached_pages", &self.pages.len())
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a simple "memory" as a flat Vec<u8> and produce a fetch_page closure.
    fn make_memory(size: usize) -> Vec<u8> {
        (0..size).map(|i| (i & 0xFF) as u8).collect()
    }

    fn fetch_page_for(
        memory: &[u8],
        page_start: Address,
        page_size: usize,
    ) -> Result<Vec<u8>, String> {
        let start = page_start.as_u64() as usize;
        if start >= memory.len() {
            return Ok(vec![0u8; page_size]);
        }
        let end = (start + page_size).min(memory.len());
        let mut data = memory[start..end].to_vec();
        data.resize(page_size, 0u8);
        Ok(data)
    }

    #[test]
    fn basic_read_miss_then_hit() {
        let memory = make_memory(0x2000);
        let mut cache = PageCache::new(0x1000, 16);

        let result = cache
            .read(Address::new(0), 4, |pa, ps| fetch_page_for(&memory, pa, ps))
            .unwrap();
        assert_eq!(result, [0, 1, 2, 3]);
        assert_eq!(cache.stats.read_misses, 1);
        assert_eq!(cache.stats.read_hits, 0);

        // Second read from same page — hit.
        let result2 = cache
            .read(Address::new(0), 4, |pa, ps| fetch_page_for(&memory, pa, ps))
            .unwrap();
        assert_eq!(result2, [0, 1, 2, 3]);
        assert_eq!(cache.stats.read_hits, 1);
    }

    #[test]
    fn cross_page_read() {
        let memory = make_memory(0x3000);
        let mut cache = PageCache::new(0x1000, 16);

        // Read 8 bytes straddling the boundary at 0x1000.
        let result = cache
            .read(Address::new(0xFFE), 8, |pa, ps| {
                fetch_page_for(&memory, pa, ps)
            })
            .unwrap();
        assert_eq!(result.len(), 8);
        // First 2 bytes from page 0, next 6 from page 1.
        assert_eq!(result[0], 0xFE);
        assert_eq!(result[1], 0xFF);
        assert_eq!(result[2], 0x00); // offset 0x1000 → 0x00 (index.is_multiple_of(256))
    }

    #[test]
    fn invalidate_range_clears_pages() {
        let memory = make_memory(0x4000);
        let mut cache = PageCache::new(0x1000, 16);

        // Load pages 0, 1, 2.
        cache
            .read(Address::new(0), 1, |pa, ps| fetch_page_for(&memory, pa, ps))
            .unwrap();
        cache
            .read(Address::new(0x1000), 1, |pa, ps| {
                fetch_page_for(&memory, pa, ps)
            })
            .unwrap();
        cache
            .read(Address::new(0x2000), 1, |pa, ps| {
                fetch_page_for(&memory, pa, ps)
            })
            .unwrap();
        assert_eq!(cache.len(), 3);

        // Invalidate range covering pages 0 and 1.
        cache.invalidate_range(AddressRange::new(Address::new(0), Address::new(0x2000)));
        assert_eq!(cache.len(), 1); // page 2 survives
        assert!(cache.is_cached(Address::new(0x2000)));
        assert!(!cache.is_cached(Address::new(0)));
    }

    #[test]
    fn lru_eviction() {
        let memory = make_memory(0x5000);
        let mut cache = PageCache::new(0x1000, 3);

        // Fill cache to capacity (3 pages).
        cache
            .read(Address::new(0), 1, |pa, ps| fetch_page_for(&memory, pa, ps))
            .unwrap();
        cache
            .read(Address::new(0x1000), 1, |pa, ps| {
                fetch_page_for(&memory, pa, ps)
            })
            .unwrap();
        cache
            .read(Address::new(0x2000), 1, |pa, ps| {
                fetch_page_for(&memory, pa, ps)
            })
            .unwrap();
        assert_eq!(cache.len(), 3);

        // Access page 0 to make it "recently used".
        cache
            .read(Address::new(0), 1, |pa, ps| fetch_page_for(&memory, pa, ps))
            .unwrap();

        // Adding page 3 must evict the LRU (page 1 or 2, whichever was least recently used).
        cache
            .read(Address::new(0x3000), 1, |pa, ps| {
                fetch_page_for(&memory, pa, ps)
            })
            .unwrap();
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.stats.evictions, 1);

        // Page 0 must still be present.
        assert!(cache.is_cached(Address::new(0)));
    }

    #[test]
    fn write_into_cache_and_read_back() {
        let mut cache = PageCache::new(0x1000, 16);
        cache.write_into_cache(Address::new(0x1000), &[0xDE, 0xAD, 0xBE, 0xEF]);

        // Read back without needing a fetch_page since the page is already cached.
        let result = cache
            .read(Address::new(0x1000), 4, |_pa, _ps| -> Result<Vec<u8>, ()> {
                panic!("fetch_page should not be called for already-cached page")
            })
            .unwrap();
        assert_eq!(result, [0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn seed_preloads_data() {
        let data: Vec<u8> = (0u8..16).collect();
        let mut cache = PageCache::new(0x1000, 16);
        cache.seed(Address::new(0x2000), &data);

        let result = cache
            .read(Address::new(0x2000), 8, |_pa, _ps| -> Result<Vec<u8>, ()> {
                panic!("should hit cache")
            })
            .unwrap();
        assert_eq!(result, data[..8]);
    }

    #[test]
    fn covered_range() {
        let mut cache = PageCache::new(0x1000, 16);
        assert!(cache.covered_range().is_none());
        cache.write_into_cache(Address::new(0x1000), &[0u8; 4]);
        cache.write_into_cache(Address::new(0x5000), &[0u8; 4]);
        let r = cache.covered_range().unwrap();
        assert_eq!(r.start, Address::new(0x1000));
        assert_eq!(r.end, Address::new(0x6000));
    }

    #[test]
    fn stats_hit_rate_empty() {
        let cache = PageCache::new(0x1000, 16);
        assert_eq!(cache.stats.hit_rate(), 0.0);
        assert_eq!(cache.stats.total_reads(), 0);
    }

    #[test]
    fn invalidate_all_clears_cache() {
        let mut cache = PageCache::new(0x1000, 16);
        cache.write_into_cache(Address::new(0x0), &[0u8; 16]);
        cache.write_into_cache(Address::new(0x1000), &[0u8; 16]);
        assert_eq!(cache.len(), 2);
        cache.invalidate_all();
        assert!(cache.is_empty());
    }
}
