//! `ttd_memory_provider` — memory provider backed by a TTD trace.
//!
//! Implements the [`MemoryProvider`] trait by reconstructing memory state at
//! an arbitrary trace position (tick) through snapshot restoration and
//! incremental application of [`TraceEvent::SyscallExit`] write records.
//!
//! # Design
//!
//! Memory reconstruction is handled by a two-step algorithm:
//!
//! 1. Locate the nearest [`TraceSnapshot`] at or before `tick` in the trace.
//! 2. Apply all [`MemWriteRecord`]s carried by `SyscallExit` events in the
//!    range `[snapshot_tick, tick]`.
//!
//! Results are cached in a per-tick [`MemoryCache`] keyed by `(tick, addr,
//! size)` to avoid redundant reconstruction during burst queries.
//!
//! [`MemoryProvider`] is a trait defined in this module; it has no
//! dependency on anything outside `rustre-ttd-replayer`.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ReplayState, TraceEvent, TtdTrace, REPLAY_PAGE_SIZE};

// ── MemoryProvider trait ──────────────────────────────────────────────────────

/// Abstraction over a source that can supply memory bytes at a trace position.
pub trait MemoryProvider: fmt::Debug {
    /// Read `size` bytes from virtual address `addr` at the given trace tick.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError`] if the address is not mapped or the tick is
    /// out of range.
    fn read(&self, tick: u64, addr: u64, size: usize) -> Result<Vec<u8>, ProviderError>;

    /// Return `true` if `addr` is mapped at `tick`.
    fn is_mapped(&self, tick: u64, addr: u64) -> bool {
        self.read(tick, addr, 1).is_ok()
    }

    /// Return the first tick in this provider's range.
    fn min_tick(&self) -> u64;

    /// Return the last tick in this provider's range.
    fn max_tick(&self) -> u64;
}

// ── ProviderError ─────────────────────────────────────────────────────────────

/// Errors produced by [`TtdMemoryProvider`].
#[derive(Debug, Error)]
pub enum ProviderError {
    /// The requested tick is outside the trace.
    #[error("tick {tick} out of range (trace spans {min}..{max})")]
    TickOutOfRange { tick: u64, min: u64, max: u64 },

    /// The virtual address is not mapped at the requested tick.
    #[error("address {addr:#x} not mapped at tick {tick}")]
    NotMapped { addr: u64, tick: u64 },

    /// A read would extend beyond a mapped page.
    #[error("read of {size} bytes at {addr:#x} overflows mapped region at tick {tick}")]
    ReadOverflow { addr: u64, size: usize, tick: u64 },

    /// The trace contains no snapshots, making reconstruction impossible.
    #[error("trace has no snapshots; memory reconstruction requires at least one snapshot")]
    NoSnapshots,
}

// ── MemoryCache ───────────────────────────────────────────────────────────────

/// Cache key for reconstructed memory reads.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    tick: u64,
    addr: u64,
    size: usize,
}

/// LRU-like cache for reconstructed memory reads.
///
/// Simple bounded map: evicts all entries when capacity is exceeded.
#[derive(Debug)]
struct MemoryCache {
    entries: HashMap<CacheKey, Vec<u8>>,
    capacity: usize,
}

impl MemoryCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            capacity,
        }
    }

    fn get(&self, key: &CacheKey) -> Option<&Vec<u8>> {
        self.entries.get(key)
    }

    fn insert(&mut self, key: CacheKey, value: Vec<u8>) {
        if self.entries.len() >= self.capacity {
            self.entries.clear();
        }
        self.entries.insert(key, value);
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn clear(&mut self) {
        self.entries.clear();
    }
}

// ── ProviderConfig ────────────────────────────────────────────────────────────

/// Configuration for a [`TtdMemoryProvider`].
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    /// Maximum number of cached reconstruction results.
    pub cache_capacity: usize,
    /// Whether to include writes from the exact `tick` in the reconstruction.
    /// When `true`, writes at `tick` are included; when `false`, only writes
    /// strictly before `tick` are applied.
    pub include_tick: bool,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            cache_capacity: 1024,
            include_tick: true,
        }
    }
}

// ── TtdMemoryProvider ─────────────────────────────────────────────────────────

/// A [`MemoryProvider`] that reconstructs memory state from a TTD trace.
///
/// Thread-safe: the cache is protected by a `RwLock`.
///
/// # Example
///
/// ```no_run
/// use rustre_ttd_replayer::{TtdTrace, TraceEvent};
/// use rustre_ttd_replayer::ttd_memory_provider::{
///     TtdMemoryProvider, MemoryProvider, ProviderConfig,
/// };
/// use std::sync::Arc;
///
/// let trace = TtdTrace::new();
/// let provider = TtdMemoryProvider::new(Arc::new(trace), ProviderConfig::default());
/// ```
#[derive(Debug)]
pub struct TtdMemoryProvider {
    /// The trace this provider reads from.
    trace: Arc<TtdTrace>,
    /// Configuration.
    config: ProviderConfig,
    /// Reconstruction cache.
    cache: RwLock<MemoryCache>,
}

impl TtdMemoryProvider {
    /// Create a new provider backed by `trace`.
    #[must_use]
    pub fn new(trace: Arc<TtdTrace>, config: ProviderConfig) -> Self {
        let capacity = config.cache_capacity;
        Self {
            trace,
            config,
            cache: RwLock::new(MemoryCache::new(capacity)),
        }
    }

    /// Create a provider with default configuration.
    #[must_use]
    pub fn with_defaults(trace: Arc<TtdTrace>) -> Self {
        Self::new(trace, ProviderConfig::default())
    }

    /// Read `size` bytes from `addr` at the given tick.
    ///
    /// This is the core operation: locate the nearest snapshot, replay forward,
    /// and extract the bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError`] if the tick or address is invalid.
    pub fn memory_at_position(
        &self,
        tick: u64,
        addr: u64,
        size: usize,
    ) -> Result<Vec<u8>, ProviderError> {
        let min = self.trace.min_tick();
        let max = self.trace.max_tick();

        if tick > max || (tick < min && !self.trace.is_empty()) {
            return Err(ProviderError::TickOutOfRange { tick, min, max });
        }

        // Fast path: check cache.
        let key = CacheKey { tick, addr, size };
        {
            let cache = self.cache.read();
            if let Some(cached) = cache.get(&key) {
                return Ok(cached.clone());
            }
        }

        // Reconstruct state.
        let state = self.reconstruct_at(tick);

        // Read from reconstructed state.
        let bytes = state
            .read(addr, size)
            .ok_or(ProviderError::NotMapped { addr, tick })?;

        // Store in cache.
        {
            let mut cache = self.cache.write();
            cache.insert(key, bytes.clone());
        }

        Ok(bytes)
    }

    /// Return the number of entries currently in the reconstruction cache.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.read().len()
    }

    /// Clear the reconstruction cache.
    pub fn clear_cache(&self) {
        self.cache.write().clear();
    }

    /// Reconstruct the full memory state at `tick` by:
    /// 1. Loading the nearest snapshot before `tick`.
    /// 2. Applying all `SyscallExit` writes up to (and optionally including) `tick`.
    fn reconstruct_at(&self, tick: u64) -> ReplayState {
        let mut state = ReplayState::new();

        // Load nearest snapshot.
        let snap_tick = self.trace.nearest_snapshot_before(tick).map_or(0, |snap| {
            state.load_snapshot(snap);
            snap.tick
        });

        // Apply writes from [snap_tick, tick].
        let end_tick = if self.config.include_tick { tick } else { tick.saturating_sub(1) };

        for ev in self.trace.events_in_range(snap_tick, end_tick) {
            if let TraceEvent::SyscallExit { mem_writes, .. } = ev {
                for wr in mem_writes {
                    state.apply_write(wr);
                }
            }
        }

        state
    }

    /// Return the full reconstructed [`ReplayState`] at `tick`.
    ///
    /// This is more expensive than `memory_at_position` but gives access to
    /// registers and the entire page map.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError`] if the tick is out of range.
    pub fn state_at(&self, tick: u64) -> Result<ReplayState, ProviderError> {
        let min = self.trace.min_tick();
        let max = self.trace.max_tick();
        if tick > max && !self.trace.is_empty() {
            return Err(ProviderError::TickOutOfRange { tick, min, max });
        }
        Ok(self.reconstruct_at(tick))
    }

    /// Return all addresses that were written between `from_tick` and `to_tick`.
    #[must_use]
    pub fn written_addresses_in_range(&self, from_tick: u64, to_tick: u64) -> Vec<u64> {
        let mut addrs: Vec<u64> = self
            .trace
            .events_in_range(from_tick, to_tick)
            .filter_map(|ev| {
                if let TraceEvent::SyscallExit { mem_writes, .. } = ev {
                    Some(mem_writes.iter().map(|wr| wr.addr).collect::<Vec<_>>())
                } else {
                    None
                }
            })
            .flatten()
            .collect();
        addrs.sort_unstable();
        addrs.dedup();
        addrs
    }

    /// Return how many bytes were written at or before `tick`.
    #[must_use]
    pub fn bytes_written_before(&self, tick: u64) -> usize {
        self.trace
            .events_in_range(0, tick)
            .filter_map(|ev| {
                if let TraceEvent::SyscallExit { mem_writes, .. } = ev {
                    Some(mem_writes.iter().map(|wr| wr.data.len()).sum::<usize>())
                } else {
                    None
                }
            })
            .sum()
    }
}

impl MemoryProvider for TtdMemoryProvider {
    fn read(&self, tick: u64, addr: u64, size: usize) -> Result<Vec<u8>, ProviderError> {
        self.memory_at_position(tick, addr, size)
    }

    fn min_tick(&self) -> u64 {
        self.trace.min_tick()
    }

    fn max_tick(&self) -> u64 {
        self.trace.max_tick()
    }
}

// ── StaticMemoryProvider ──────────────────────────────────────────────────────

/// A [`MemoryProvider`] that holds a fixed memory image regardless of tick.
///
/// Useful for testing or for mapping static ROM / firmware blobs.
#[derive(Debug)]
pub struct StaticMemoryProvider {
    /// Page map: page-aligned base → 4 KiB page bytes.
    pages: HashMap<u64, Vec<u8>>,
    /// Synthetic tick range.
    tick_range: (u64, u64),
}

impl StaticMemoryProvider {
    /// Create an empty static provider with the given tick range.
    #[must_use]
    pub fn new(min_tick: u64, max_tick: u64) -> Self {
        Self {
            pages: HashMap::new(),
            tick_range: (min_tick, max_tick),
        }
    }

    /// Write `data` starting at virtual address `addr` into the static image.
    pub fn write(&mut self, addr: u64, data: &[u8]) {
        let mut cursor = addr;
        let mut remaining = data;
        while !remaining.is_empty() {
            let base = cursor & !(REPLAY_PAGE_SIZE as u64 - 1);
            let off = (cursor - base) as usize;
            let page = self.pages.entry(base).or_insert_with(|| vec![0u8; REPLAY_PAGE_SIZE]);
            let space = REPLAY_PAGE_SIZE - off;
            let chunk = remaining.len().min(space);
            page[off..off + chunk].copy_from_slice(&remaining[..chunk]);
            cursor += chunk as u64;
            remaining = &remaining[chunk..];
        }
    }

    /// Number of 4 KiB pages in this provider.
    #[must_use]
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }
}

impl MemoryProvider for StaticMemoryProvider {
    fn read(&self, tick: u64, addr: u64, size: usize) -> Result<Vec<u8>, ProviderError> {
        let _ = tick; // static: same image at all ticks
        let mut out = Vec::with_capacity(size);
        let mut cursor = addr;
        let mut remaining = size;
        while remaining > 0 {
            let base = cursor & !(REPLAY_PAGE_SIZE as u64 - 1);
            let off = (cursor - base) as usize;
            let page = self
                .pages
                .get(&base)
                .ok_or(ProviderError::NotMapped { addr: cursor, tick })?;
            let chunk = remaining.min(REPLAY_PAGE_SIZE - off);
            out.extend_from_slice(&page[off..off + chunk]);
            cursor += chunk as u64;
            remaining -= chunk;
        }
        Ok(out)
    }

    fn min_tick(&self) -> u64 {
        self.tick_range.0
    }

    fn max_tick(&self) -> u64 {
        self.tick_range.1
    }
}

impl fmt::Display for StaticMemoryProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StaticMemoryProvider(pages={})", self.pages.len())
    }
}

// ── OverlayMemoryProvider ─────────────────────────────────────────────────────

/// A [`MemoryProvider`] that layers a writable overlay on top of a base
/// provider.  Reads first check the overlay; on a miss they fall through to
/// the base.
///
/// Useful for patching memory without modifying the underlying trace.
pub struct OverlayMemoryProvider {
    base: Box<dyn MemoryProvider + Send + Sync>,
    overlay: HashMap<u64, Vec<u8>>,
}

impl fmt::Debug for OverlayMemoryProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OverlayMemoryProvider")
            .field("overlay_bytes", &self.overlay.values().map(std::vec::Vec::len).sum::<usize>())
            .finish()
    }
}

impl OverlayMemoryProvider {
    /// Create an overlay provider wrapping `base`.
    #[must_use] 
    pub fn new(base: Box<dyn MemoryProvider + Send + Sync>) -> Self {
        Self { base, overlay: HashMap::new() }
    }

    /// Write `data` at `addr` in the overlay.  Does not modify the base.
    pub fn patch(&mut self, addr: u64, data: Vec<u8>) {
        self.overlay.insert(addr, data);
    }

    /// Remove a patch from the overlay.
    pub fn remove_patch(&mut self, addr: u64) {
        self.overlay.remove(&addr);
    }

    /// Number of patches in the overlay.
    #[must_use]
    pub fn patch_count(&self) -> usize {
        self.overlay.len()
    }
}

impl MemoryProvider for OverlayMemoryProvider {
    fn read(&self, tick: u64, addr: u64, size: usize) -> Result<Vec<u8>, ProviderError> {
        // Check for a single-address patch.
        if let Some(patched) = self.overlay.get(&addr)
            && patched.len() >= size {
                return Ok(patched[..size].to_vec());
            }
        self.base.read(tick, addr, size)
    }

    fn min_tick(&self) -> u64 {
        self.base.min_tick()
    }

    fn max_tick(&self) -> u64 {
        self.base.max_tick()
    }
}

// ── MemoryProviderStats ───────────────────────────────────────────────────────

/// Runtime statistics for a [`TtdMemoryProvider`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProviderStats {
    /// Total bytes written in the trace.
    pub total_bytes_written: usize,
    /// Number of unique write addresses.
    pub unique_write_addrs: usize,
    /// Tick range of the trace.
    pub tick_range: (u64, u64),
    /// Number of snapshots.
    pub snapshot_count: usize,
    /// Current cache size.
    pub cache_size: usize,
}

impl TtdMemoryProvider {
    /// Collect runtime statistics for this provider.
    #[must_use]
    pub fn stats(&self) -> MemoryProviderStats {
        let mut total_bytes = 0usize;
        let mut addrs = std::collections::HashSet::new();

        for ev in &self.trace.events {
            if let TraceEvent::SyscallExit { mem_writes, .. } = ev {
                for wr in mem_writes {
                    total_bytes += wr.data.len();
                    addrs.insert(wr.addr);
                }
            }
        }

        MemoryProviderStats {
            total_bytes_written: total_bytes,
            unique_write_addrs: addrs.len(),
            tick_range: (self.trace.min_tick(), self.trace.max_tick()),
            snapshot_count: self.trace.snapshots.len(),
            cache_size: self.cache_size(),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemWriteRecord, TraceBuilder, TraceSnapshot};

    fn make_trace_with_write(addr: u64, data: Vec<u8>, write_tick: u64) -> Arc<TtdTrace> {
        let mut builder = TraceBuilder::new(512);
        builder.syscall_entry(1, [0; 6]);
        builder.syscall_exit(0, vec![MemWriteRecord::new(addr, data.clone())]);
        // Force the tick to match write_tick by building and patching.
        // Instead, build a trace manually.
        let _ = builder; // drop

        let mut trace = TtdTrace::new();
        let mut snap = TraceSnapshot::new(0);
        snap.set_reg("rip", 0);
        trace.push_snapshot(snap);
        trace.push_event(TraceEvent::SyscallEntry { tick: 1, nr: 1, args: [0; 6] });
        trace.push_event(TraceEvent::SyscallExit {
            tick: write_tick,
            retval: 0,
            mem_writes: vec![MemWriteRecord::new(addr, data)],
        });
        Arc::new(trace)
    }

    // ── TtdMemoryProvider ─────────────────────────────────────────────────────

    #[test]
    fn test_read_after_write() {
        let addr = 0x1000u64;
        let data = vec![0x41u8; 16];
        let trace = make_trace_with_write(addr, data.clone(), 5);
        let provider = TtdMemoryProvider::with_defaults(trace);
        let got = provider.memory_at_position(5, addr, 16).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn test_not_mapped_before_write() {
        let trace = Arc::new(TtdTrace::new());
        let provider = TtdMemoryProvider::with_defaults(trace);
        // Empty trace: any read should return NotMapped.
        assert!(matches!(
            provider.memory_at_position(0, 0x1000, 4),
            Err(ProviderError::NotMapped { .. })
        ));
    }

    #[test]
    fn test_tick_out_of_range() {
        let addr = 0x1000u64;
        let trace = make_trace_with_write(addr, vec![1, 2, 3, 4], 2);
        let provider = TtdMemoryProvider::with_defaults(Arc::clone(&trace));
        assert!(matches!(
            provider.memory_at_position(9999, addr, 4),
            Err(ProviderError::TickOutOfRange { .. })
        ));
    }

    #[test]
    fn test_cache_populated_on_read() {
        let addr = 0x2000u64;
        let data = vec![0xBBu8; 8];
        let trace = make_trace_with_write(addr, data, 3);
        let provider = TtdMemoryProvider::with_defaults(trace);
        assert_eq!(provider.cache_size(), 0);
        let _ = provider.memory_at_position(3, addr, 8).unwrap();
        assert!(provider.cache_size() > 0);
    }

    #[test]
    fn test_cache_clear() {
        let addr = 0x3000u64;
        let trace = make_trace_with_write(addr, vec![1; 4], 1);
        let provider = TtdMemoryProvider::with_defaults(trace);
        let _ = provider.memory_at_position(1, addr, 4);
        provider.clear_cache();
        assert_eq!(provider.cache_size(), 0);
    }

    #[test]
    fn test_min_max_tick() {
        let trace = make_trace_with_write(0x1000, vec![1, 2], 10);
        let provider = TtdMemoryProvider::with_defaults(trace);
        assert!(provider.min_tick() <= provider.max_tick());
    }

    #[test]
    fn test_written_addresses_in_range() {
        let mut trace = TtdTrace::new();
        trace.push_snapshot(TraceSnapshot::new(0));
        trace.push_event(TraceEvent::SyscallExit {
            tick: 5,
            retval: 0,
            mem_writes: vec![
                MemWriteRecord::new(0x1000, vec![1, 2]),
                MemWriteRecord::new(0x2000, vec![3, 4]),
            ],
        });
        let provider = TtdMemoryProvider::with_defaults(Arc::new(trace));
        let addrs = provider.written_addresses_in_range(0, 10);
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&0x1000));
        assert!(addrs.contains(&0x2000));
    }

    #[test]
    fn test_bytes_written_before() {
        let addr = 0x1000u64;
        let trace = make_trace_with_write(addr, vec![0u8; 64], 8);
        let provider = TtdMemoryProvider::with_defaults(trace);
        assert_eq!(provider.bytes_written_before(8), 64);
        assert_eq!(provider.bytes_written_before(7), 0);
    }

    #[test]
    fn test_stats() {
        let addr = 0x1000u64;
        let trace = make_trace_with_write(addr, vec![1u8; 32], 4);
        let provider = TtdMemoryProvider::with_defaults(trace);
        let _ = provider.memory_at_position(4, addr, 8);
        let stats = provider.stats();
        assert_eq!(stats.total_bytes_written, 32);
        assert!(stats.cache_size > 0);
    }

    #[test]
    fn test_is_mapped_trait() {
        let addr = 0x1000u64;
        let trace = make_trace_with_write(addr, vec![0xFFu8; 16], 1);
        let provider = TtdMemoryProvider::with_defaults(trace);
        assert!(provider.is_mapped(1, addr));
        assert!(!provider.is_mapped(0, addr));
    }

    // ── StaticMemoryProvider ──────────────────────────────────────────────────

    #[test]
    fn test_static_provider_read() {
        let mut p = StaticMemoryProvider::new(0, 100);
        p.write(0x5000, &[1, 2, 3, 4]);
        let bytes = p.read(0, 0x5000, 4).unwrap();
        assert_eq!(bytes, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_static_provider_not_mapped() {
        let p = StaticMemoryProvider::new(0, 100);
        assert!(matches!(p.read(0, 0x9000, 4), Err(ProviderError::NotMapped { .. })));
    }

    #[test]
    fn test_static_provider_page_count() {
        let mut p = StaticMemoryProvider::new(0, 100);
        assert_eq!(p.page_count(), 0);
        p.write(0x1000, &[0u8; 8]);
        assert_eq!(p.page_count(), 1);
    }

    #[test]
    fn test_static_provider_cross_page() {
        let mut p = StaticMemoryProvider::new(0, 100);
        let data = vec![0xAAu8; REPLAY_PAGE_SIZE];
        p.write(0x0FF0, &data); // spans page 0 and page 1
        assert_eq!(p.page_count(), 2);
    }

    // ── OverlayMemoryProvider ─────────────────────────────────────────────────

    #[test]
    fn test_overlay_patch_applied() {
        let mut base = StaticMemoryProvider::new(0, 100);
        base.write(0x8000, &[0x00u8; 4]);
        let mut overlay = OverlayMemoryProvider::new(Box::new(base));
        overlay.patch(0x8000, vec![0xFF, 0xFE, 0xFD, 0xFC]);
        let bytes = overlay.read(0, 0x8000, 4).unwrap();
        assert_eq!(bytes, vec![0xFF, 0xFE, 0xFD, 0xFC]);
    }

    #[test]
    fn test_overlay_fallthrough_to_base() {
        let mut base = StaticMemoryProvider::new(0, 100);
        base.write(0x8000, &[0x12u8; 4]);
        let overlay = OverlayMemoryProvider::new(Box::new(base));
        // No patch for 0x8000: falls through to base.
        let bytes = overlay.read(0, 0x8000, 4).unwrap();
        assert_eq!(bytes, vec![0x12; 4]);
    }

    #[test]
    fn test_overlay_remove_patch() {
        let mut base = StaticMemoryProvider::new(0, 100);
        base.write(0x8000, &[0xAAu8; 4]);
        let mut overlay = OverlayMemoryProvider::new(Box::new(base));
        overlay.patch(0x8000, vec![0xBB; 4]);
        overlay.remove_patch(0x8000);
        // After removal, base data is returned.
        let bytes = overlay.read(0, 0x8000, 4).unwrap();
        assert_eq!(bytes, vec![0xAAu8; 4]);
    }

    #[test]
    fn test_overlay_patch_count() {
        let base = StaticMemoryProvider::new(0, 100);
        let mut overlay = OverlayMemoryProvider::new(Box::new(base));
        assert_eq!(overlay.patch_count(), 0);
        overlay.patch(0x1000, vec![1, 2]);
        overlay.patch(0x2000, vec![3, 4]);
        assert_eq!(overlay.patch_count(), 2);
    }

    // ── ProviderError display ─────────────────────────────────────────────────

    #[test]
    fn test_error_display_tick_out_of_range() {
        let e = ProviderError::TickOutOfRange { tick: 999, min: 0, max: 100 };
        assert!(e.to_string().contains("999"));
    }

    #[test]
    fn test_error_display_not_mapped() {
        let e = ProviderError::NotMapped { addr: 0xDEAD_BEEF, tick: 42 };
        assert!(e.to_string().contains("0xdeadbeef") || e.to_string().contains("0xDEADBEEF") || e.to_string().to_lowercase().contains("dead"));
    }
}
