//! Sparse memory provider: stores only the bytes that have been explicitly
//! written.  Reads from unmapped addresses return a configurable fill byte
//! (default 0x00) rather than an error.

use crate::memory_provider::{MemError, MemoryProvider, MemoryRegion, RegionSource, SnapshotId};
use async_trait::async_trait;
use parking_lot::Mutex;
use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;
use std::collections::BTreeMap;

// ─────────────────────────────────────────────────────────────────────────────
// SparseMemoryProvider
// ─────────────────────────────────────────────────────────────────────────────

/// A memory provider backed by a sorted sparse byte map.
///
/// Bytes that have never been written are served as the `fill_byte` (default
/// `0x00`).  The provider accepts writes to any 64-bit address.
pub struct SparseMemoryProvider {
    /// Sorted map from address to byte.
    data: BTreeMap<u64, u8>,
    /// Byte returned for unwritten addresses.
    fill_byte: u8,
    /// Permissions reported for synthesized regions.
    perms: Permissions,
    /// Optional hard limit on the total number of bytes that may be stored.
    /// `None` = unlimited.
    capacity: Option<usize>,
}

impl SparseMemoryProvider {
    /// Create a new provider with zero fill and read+write permissions.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: BTreeMap::new(),
            fill_byte: 0,
            perms: Permissions::READ | Permissions::WRITE,
            capacity: None,
        }
    }

    /// Set the byte returned for unmapped addresses.
    #[must_use]
    pub const fn with_fill(mut self, fill: u8) -> Self {
        self.fill_byte = fill;
        self
    }

    /// Set the permissions reported by `regions()`.
    #[must_use]
    pub const fn with_permissions(mut self, perms: Permissions) -> Self {
        self.perms = perms;
        self
    }

    /// Set the capacity (maximum number of stored bytes).
    #[must_use]
    pub const fn with_capacity(mut self, cap: usize) -> Self {
        self.capacity = Some(cap);
        self
    }

    /// Number of bytes currently stored.
    #[must_use]
    pub fn stored_bytes(&self) -> usize {
        self.data.len()
    }

    /// Return `true` if no bytes have been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Wipe all stored bytes.
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Iterate over all (address, byte) pairs in ascending address order.
    pub fn iter(&self) -> impl Iterator<Item = (Address, u8)> + '_ {
        self.data.iter().map(|(&k, &v)| (Address::new(k), v))
    }

    /// Pre-populate a range with `value`, potentially using much less memory
    /// than writing the range byte-by-byte when the range is large.
    ///
    /// This implementation stores every byte individually; a production
    /// implementation could use a run-length encoding.
    ///
    /// # Errors
    /// Returns `Err` if the write would exceed the capacity limit.
    pub fn fill_range(&mut self, start: Address, len: usize, value: u8) -> Result<(), MemError> {
        for i in 0..len as u64 {
            if let Some(cap) = self.capacity
                && self.data.len() >= cap {
                    return Err(MemError::Other("sparse capacity exceeded".into()));
                }
            let key = start.0.checked_add(i).ok_or({
                MemError::OutOfBounds(start, len)
            })?;
            self.data.insert(key, value);
        }
        Ok(())
    }

    /// Find contiguous ranges of stored bytes and return them as `AddressRange`s.
    #[must_use]
    pub fn contiguous_ranges(&self) -> Vec<AddressRange> {
        let mut ranges = Vec::new();
        let mut keys: Vec<u64> = self.data.keys().copied().collect();
        keys.sort_unstable();

        let mut i = 0;
        while i < keys.len() {
            let start = keys[i];
            let mut end = start + 1;
            while i + 1 < keys.len() && keys[i + 1] == end {
                i += 1;
                end += 1;
            }
            ranges.push(AddressRange::new(Address::new(start), Address::new(end)));
            i += 1;
        }
        ranges
    }

    /// Compute total stored byte count and the span (min..max+1).
    #[must_use]
    pub fn span(&self) -> Option<AddressRange> {
        let min = self.data.keys().next().copied()?;
        let max = self.data.keys().next_back().copied()?;
        Some(AddressRange::new(Address::new(min), Address::new(max.saturating_add(1))))
    }
}

impl Default for SparseMemoryProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SparseMemoryProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SparseMemoryProvider")
            .field("stored_bytes", &self.data.len())
            .field("fill_byte", &self.fill_byte)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl MemoryProvider for SparseMemoryProvider {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        let mut result = Vec::with_capacity(len);
        for i in 0..len as u64 {
            let key = addr.0.checked_add(i).ok_or(MemError::OutOfBounds(addr, len))?;
            let byte = self
                .data
                .get(&key)
                .copied()
                .unwrap_or(self.fill_byte);
            result.push(byte);
        }
        Ok(result)
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        for (i, &byte) in data.iter().enumerate() {
            let key = addr.0.checked_add(i as u64).ok_or(MemError::OutOfBounds(addr, data.len()))?;
            if let Some(cap) = self.capacity
                && !self.data.contains_key(&key) && self.data.len() >= cap {
                    return Err(MemError::Other("sparse capacity exceeded".into()));
                }
            self.data.insert(key, byte);
        }
        Ok(())
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        self.contiguous_ranges()
            .into_iter()
            .map(|r| MemoryRegion {
                range: r,
                perms: self.perms,
                name: Some("sparse".to_string()),
                source: RegionSource::Anonymous,
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LargeWindowProvider
// ─────────────────────────────────────────────────────────────────────────────

/// Interior-mutable cache state for `LargeWindowProvider`.
struct WindowCache {
    cached_base: Option<Address>,
    cache: Vec<u8>,
    hits: u64,
    misses: u64,
}

impl WindowCache {
    const fn new() -> Self {
        Self {
            cached_base: None,
            cache: Vec::new(),
            hits: 0,
            misses: 0,
        }
    }

    fn invalidate(&mut self) {
        self.cached_base = None;
        self.cache.clear();
    }

    const fn is_cached(&self, addr: Address, len: usize) -> bool {
        if let Some(base) = self.cached_base {
            let offset = addr.0.wrapping_sub(base.0) as usize;
            offset + len <= self.cache.len() && addr.0 >= base.0
        } else {
            false
        }
    }
}

/// A large-window memory view over a base provider.
///
/// Caches the last-read window (of size `window_size`) to amortise the cost of
/// repeated reads to the same region.  The cached window is invalidated on
/// any write.
pub struct LargeWindowProvider<P: MemoryProvider> {
    inner: P,
    window_size: usize,
    cache: Mutex<WindowCache>,
}

impl<P: MemoryProvider> LargeWindowProvider<P> {
    /// Wrap `provider` with a `window_size`-byte cache window.
    ///
    /// # Panics
    /// Panics if `window_size` is zero.
    #[must_use]
    pub fn new(provider: P, window_size: usize) -> Self {
        assert!(window_size > 0, "window_size must be > 0");
        Self {
            inner: provider,
            window_size,
            cache: Mutex::new(WindowCache::new()),
        }
    }

    /// Cache hit count.
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.cache.lock().hits
    }

    /// Cache miss count.
    #[must_use]
    pub fn misses(&self) -> u64 {
        self.cache.lock().misses
    }

    /// Whether the cache is currently populated.
    #[must_use]
    pub fn is_cache_populated(&self) -> bool {
        self.cache.lock().cached_base.is_some()
    }

    /// Invalidate the cache.
    pub fn invalidate(&mut self) {
        self.cache.lock().invalidate();
    }
}

impl<P: MemoryProvider + Send + Sync> std::fmt::Debug for LargeWindowProvider<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let c = self.cache.lock();
        f.debug_struct("LargeWindowProvider")
            .field("window_size", &self.window_size)
            .field("cached", &c.cached_base.is_some())
            .field("hits", &c.hits)
            .field("misses", &c.misses)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<P: MemoryProvider + Send + Sync> MemoryProvider for LargeWindowProvider<P> {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        {
            let mut c = self.cache.lock();
            if c.is_cached(addr, len) {
                c.hits += 1;
                let offset = (addr.0 - c.cached_base.unwrap().0) as usize;
                return Ok(c.cache[offset..offset + len].to_vec());
            }
            c.misses += 1;
        }
        // For requests larger than the window, bypass the cache and read directly.
        if len > self.window_size {
            return self.inner.read(addr, len);
        }
        // Load a full window starting at `addr` (lock released).
        let window_data = self.inner.read(addr, self.window_size)?;
        let actual_len = len.min(window_data.len());
        if actual_len < len {
            return Err(MemError::Other(format!(
                "read at {addr:?}: requested {len} bytes but provider returned only {actual_len}"
            )));
        }
        let result = window_data[..actual_len].to_vec();
        {
            let mut c = self.cache.lock();
            c.cached_base = Some(addr);
            c.cache = window_data;
        }
        Ok(result)
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        self.cache.lock().invalidate();
        self.inner.write(addr, data)
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        self.inner.regions()
    }

    fn is_live(&self) -> bool {
        self.inner.is_live()
    }

    async fn refresh(&mut self) -> Result<(), MemError> {
        self.cache.lock().invalidate();
        self.inner.refresh().await
    }

    async fn snapshot(&mut self) -> Result<SnapshotId, MemError> {
        self.inner.snapshot().await
    }

    async fn restore(&mut self, id: SnapshotId) -> Result<(), MemError> {
        self.cache.lock().invalidate();
        self.inner.restore(id).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparse_read_fill() {
        let sp = SparseMemoryProvider::new();
        let bytes = sp.read(Address::new(0xDEAD), 4).unwrap();
        assert_eq!(bytes, [0, 0, 0, 0]);
    }

    #[test]
    fn test_sparse_write_read() {
        let mut sp = SparseMemoryProvider::new();
        sp.write(Address::new(0x100), &[1, 2, 3, 4]).unwrap();
        let bytes = sp.read(Address::new(0x100), 4).unwrap();
        assert_eq!(bytes, [1, 2, 3, 4]);
    }

    #[test]
    fn test_sparse_fill_byte() {
        let sp = SparseMemoryProvider::new().with_fill(0xFF);
        let bytes = sp.read(Address::new(0), 4).unwrap();
        assert_eq!(bytes, [0xFF; 4]);
    }

    #[test]
    fn test_sparse_mixed_read() {
        let mut sp = SparseMemoryProvider::new();
        sp.write(Address::new(2), &[0xAB]).unwrap();
        let bytes = sp.read(Address::new(0), 4).unwrap();
        assert_eq!(bytes, [0, 0, 0xAB, 0]);
    }

    #[test]
    fn test_sparse_stored_bytes() {
        let mut sp = SparseMemoryProvider::new();
        assert_eq!(sp.stored_bytes(), 0);
        sp.write(Address::new(0), &[1, 2, 3]).unwrap();
        assert_eq!(sp.stored_bytes(), 3);
    }

    #[test]
    fn test_sparse_clear() {
        let mut sp = SparseMemoryProvider::new();
        sp.write(Address::new(0), &[1, 2]).unwrap();
        sp.clear();
        assert!(sp.is_empty());
    }

    #[test]
    fn test_sparse_contiguous_ranges() {
        let mut sp = SparseMemoryProvider::new();
        sp.write(Address::new(0), &[1, 2, 3]).unwrap(); // range 0..3
        sp.write(Address::new(5), &[4, 5]).unwrap(); // range 5..7
        let ranges = sp.contiguous_ranges();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, Address::new(0));
        assert_eq!(ranges[0].end, Address::new(3));
        assert_eq!(ranges[1].start, Address::new(5));
        assert_eq!(ranges[1].end, Address::new(7));
    }

    #[test]
    fn test_sparse_span() {
        let mut sp = SparseMemoryProvider::new();
        assert!(sp.span().is_none());
        sp.write(Address::new(0x100), &[1]).unwrap();
        sp.write(Address::new(0x200), &[2]).unwrap();
        let span = sp.span().unwrap();
        assert_eq!(span.start, Address::new(0x100));
        assert_eq!(span.end, Address::new(0x201));
    }

    #[test]
    fn test_sparse_capacity_limit() {
        let mut sp = SparseMemoryProvider::new().with_capacity(2);
        sp.write(Address::new(0), &[1, 2]).unwrap();
        let result = sp.write(Address::new(2), &[3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_sparse_regions() {
        let mut sp = SparseMemoryProvider::new();
        sp.write(Address::new(0x1000), &[1, 2]).unwrap();
        let regions = sp.regions();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].range.start, Address::new(0x1000));
    }

    #[test]
    fn test_large_window_cache_hit() {
        use crate::file_memory::FileMemoryProvider;
        let base =
            FileMemoryProvider::from_bytes(vec![0xAB; 0x2000], Address::new(0), Permissions::READ);
        let wnd = LargeWindowProvider::new(base, 0x1000);
        // First read fills the cache.
        wnd.read(Address::new(0), 4).unwrap();
        assert_eq!(wnd.misses(), 1);
        // Second read within the window is a hit.
        wnd.read(Address::new(4), 4).unwrap();
        assert_eq!(wnd.hits(), 1);
    }

    #[test]
    fn test_large_window_write_invalidates() {
        use crate::file_memory::FileMemoryProvider;
        let base = FileMemoryProvider::from_bytes(
            vec![0u8; 0x2000],
            Address::new(0),
            Permissions::READ | Permissions::WRITE,
        );
        let mut wnd = LargeWindowProvider::new(base, 0x1000);
        wnd.read(Address::new(0), 4).unwrap();
        assert!(wnd.is_cache_populated());
        wnd.write(Address::new(0), &[1]).unwrap();
        assert!(!wnd.is_cache_populated());
    }

    #[test]
    fn test_large_window_miss_on_different_window() {
        use crate::file_memory::FileMemoryProvider;
        let base =
            FileMemoryProvider::from_bytes(vec![0u8; 0x4000], Address::new(0), Permissions::READ);
        let wnd = LargeWindowProvider::new(base, 0x100);
        wnd.read(Address::new(0), 4).unwrap();
        // 0x200 is outside the 0x100-byte window starting at 0.
        wnd.read(Address::new(0x200), 4).unwrap();
        assert_eq!(wnd.misses(), 2);
    }

    #[test]
    fn test_sparse_fill_range() {
        let mut sp = SparseMemoryProvider::new();
        sp.fill_range(Address::new(0x100), 4, 0xCC).unwrap();
        let bytes = sp.read(Address::new(0x100), 4).unwrap();
        assert_eq!(bytes, [0xCC; 4]);
    }
}
