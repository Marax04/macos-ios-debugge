//! Simple priority-ordered composite memory provider.
//!
//! Provides a lightweight [`CompositeMemoryProvider`] that tries each inner
//! provider in descending priority order and returns the first successful result.
//!
//! # Distinction from `composite_provider`
//!
//! [`crate::composite_provider`] is the *enhanced* composite with explicit
//! [`crate::composite_provider::WriteStrategy`], copy-on-write overlay support,
//! region merging, and named layers.  Use `composite_memory` when you only need
//! simple fallthrough reads; use `composite_provider` for production layered
//! analysis pipelines.

use crate::memory_provider::{MemError, MemoryProvider, MemoryRegion, SnapshotId};
use async_trait::async_trait;
use rustre_core::address::{Address, AddressRange};

// ---------------------------------------------------------------------------
// CompositeMemoryProvider
// ---------------------------------------------------------------------------

/// Merges several `MemoryProvider` instances into one by forwarding each
/// operation to the first provider (in priority order) that can satisfy it.
///
/// Providers with a higher `priority` value are tried before those with a
/// lower value.  Ties are broken by insertion order (latest wins).
pub struct CompositeMemoryProvider {
    /// Stored as `(priority, provider)` pairs.
    providers: Vec<(u32, Box<dyn MemoryProvider>)>,
}

impl CompositeMemoryProvider {
    /// Create an empty composite provider.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Append a provider with the given `priority`.  Higher priority providers
    /// are tried first for reads.
    pub fn add_provider(&mut self, provider: Box<dyn MemoryProvider>, priority: u32) {
        self.providers.push((priority, provider));
        // Sort descending so index 0 has the highest priority.
        self.providers.sort_by(|a, b| b.0.cmp(&a.0));
    }

    /// Remove and return the provider at logical `index` (0 = highest priority).
    /// Returns `None` if the index is out of range.
    pub fn remove_provider_at(&mut self, index: usize) -> Option<Box<dyn MemoryProvider>> {
        if index < self.providers.len() {
            Some(self.providers.remove(index).1)
        } else {
            None
        }
    }

    /// Number of registered providers.
    #[must_use] 
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Iterate providers in priority order (immutable).
    fn iter_by_priority(&self) -> impl Iterator<Item = &dyn MemoryProvider> {
        self.providers.iter().map(|(_, p)| p.as_ref())
    }
}

impl Default for CompositeMemoryProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MemoryProvider for CompositeMemoryProvider {
    /// Try each provider in priority order; return the first successful result.
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        let mut last_err = MemError::NotMapped(addr);
        for provider in self.iter_by_priority() {
            match provider.read(addr, len) {
                Ok(data) => return Ok(data),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    /// Write to all providers that map the target address (best-effort).
    /// Returns the first error encountered; continues writing to remaining
    /// providers regardless.
    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        let mut first_err: Option<MemError> = None;
        let mut wrote_any = false;

        for (_, provider) in &mut self.providers {
            match provider.write(addr, data) {
                Ok(()) => wrote_any = true,
                Err(MemError::NotMapped(_) | MemError::OutOfBounds(_, _)) => {
                    // Provider doesn't cover this address — skip silently.
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }

        if let Some(err) = first_err {
            Err(err)
        } else if wrote_any {
            Ok(())
        } else {
            Err(MemError::NotMapped(addr))
        }
    }

    /// Collect regions from all providers (duplicates allowed — callers can
    /// deduplicate if needed).
    fn regions(&self) -> Vec<MemoryRegion> {
        self.providers
            .iter()
            .flat_map(|(_, p)| p.regions())
            .collect()
    }

    /// True if any inner provider is live.
    fn is_live(&self) -> bool {
        self.providers.iter().any(|(_, p)| p.is_live())
    }

    /// Refresh all providers; return the first error (if any).
    async fn refresh(&mut self) -> Result<(), MemError> {
        let mut first_err: Option<MemError> = None;
        for index in 0..self.providers.len() {
            if let (Err(e), true) = (self.providers[index].1.refresh().await, first_err.is_none()) {
                first_err = Some(e);
            }
        }
        if let Some(e) = first_err {
            Err(e)
        } else {
            Ok(())
        }
    }

    /// Snapshot is unsupported for composite providers (use inner snapshots
    /// individually).
    async fn snapshot(&mut self) -> Result<SnapshotId, MemError> {
        Err(MemError::Unsupported)
    }

    async fn restore(&mut self, _id: SnapshotId) -> Result<(), MemError> {
        Err(MemError::Unsupported)
    }
}

// ---------------------------------------------------------------------------
// RangeRoutingProvider — routes reads/writes to a specific provider by range
// ---------------------------------------------------------------------------

/// A memory provider that routes accesses to different sub-providers based on
/// the virtual address range being accessed.
///
/// Unlike `CompositeMemoryProvider`, which tries all providers in priority
/// order, `RangeRoutingProvider` maps disjoint address ranges to specific
/// providers. Accesses to unmapped ranges return `MemError::NotMapped`.
pub struct RangeRoutingProvider {
    /// Sorted list of `(range, provider)` entries.
    routes: Vec<(AddressRange, Box<dyn MemoryProvider>)>,
}

impl RangeRoutingProvider {
    /// Create an empty routing provider.
    #[must_use]
    pub fn new() -> Self {
        Self { routes: Vec::new() }
    }

    /// Add a route mapping `range` to `provider`.
    ///
    /// Panics in debug if the range overlaps with an existing route.
    pub fn add_route(&mut self, range: AddressRange, provider: Box<dyn MemoryProvider>) {
        self.routes.push((range, provider));
        // Keep sorted by start address for deterministic iteration.
        self.routes.sort_by_key(|(r, _)| r.start);
    }

    /// Remove the route whose range starts at exactly `start`.
    /// Returns `true` if a route was found and removed.
    pub fn remove_route_at(&mut self, start: Address) -> bool {
        let before = self.routes.len();
        self.routes.retain(|(r, _)| r.start != start);
        self.routes.len() < before
    }

    /// Number of registered routes.
    #[must_use]
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Find the provider responsible for `addr`, if any.
    fn find_provider_for(&self, addr: Address) -> Option<&dyn MemoryProvider> {
        for (range, provider) in &self.routes {
            if range.contains(addr) {
                return Some(provider.as_ref());
            }
        }
        None
    }

    /// Mutable version — find the provider responsible for `addr`.
    fn find_provider_for_mut(&mut self, addr: Address) -> Option<&mut dyn MemoryProvider> {
        for (range, provider) in &mut self.routes {
            if range.contains(addr) {
                return Some(provider.as_mut());
            }
        }
        None
    }
}

impl Default for RangeRoutingProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RangeRoutingProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RangeRoutingProvider")
            .field("routes", &self.routes.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl MemoryProvider for RangeRoutingProvider {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        match self.find_provider_for(addr) {
            Some(p) => p.read(addr, len),
            None => Err(MemError::NotMapped(addr)),
        }
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        match self.find_provider_for_mut(addr) {
            Some(p) => p.write(addr, data),
            None => Err(MemError::NotMapped(addr)),
        }
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        self.routes.iter().flat_map(|(_, p)| p.regions()).collect()
    }

    fn is_live(&self) -> bool {
        self.routes.iter().any(|(_, p)| p.is_live())
    }

    async fn refresh(&mut self) -> Result<(), MemError> {
        let mut first_err: Option<MemError> = None;
        for (_, provider) in &mut self.routes {
            if let Err(e) = provider.refresh().await
                && first_err.is_none() {
                    first_err = Some(e);
                }
        }
        if let Some(e) = first_err {
            Err(e)
        } else {
            Ok(())
        }
    }

    async fn snapshot(&mut self) -> Result<SnapshotId, MemError> {
        Err(MemError::Unsupported)
    }

    async fn restore(&mut self, _id: SnapshotId) -> Result<(), MemError> {
        Err(MemError::Unsupported)
    }
}

// ---------------------------------------------------------------------------
// FallbackChain — tries providers in order until one succeeds
// ---------------------------------------------------------------------------

/// A simple ordered fallback chain: attempts each provider in sequence and
/// returns the first successful result.  Unlike `CompositeMemoryProvider`,
/// there is no priority sorting — providers are tried in insertion order.
pub struct FallbackChain {
    providers: Vec<Box<dyn MemoryProvider>>,
}

impl FallbackChain {
    /// Create an empty fallback chain.
    #[must_use]
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Append a provider at the end of the chain (lowest precedence).
    pub fn push(&mut self, provider: Box<dyn MemoryProvider>) {
        self.providers.push(provider);
    }

    /// Remove the provider at `index`. Returns `None` if out of range.
    pub fn remove(&mut self, index: usize) -> Option<Box<dyn MemoryProvider>> {
        if index < self.providers.len() {
            Some(self.providers.remove(index))
        } else {
            None
        }
    }

    /// Number of providers in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    /// Returns `true` if no providers are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

impl Default for FallbackChain {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for FallbackChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FallbackChain")
            .field("providers", &self.providers.len())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl MemoryProvider for FallbackChain {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        let mut last_err = MemError::NotMapped(addr);
        for p in &self.providers {
            match p.read(addr, len) {
                Ok(d) => return Ok(d),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        let mut last_err = MemError::NotMapped(addr);
        for p in &mut self.providers {
            match p.write(addr, data) {
                Ok(()) => return Ok(()),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        self.providers.iter().flat_map(|p| p.regions()).collect()
    }

    fn is_live(&self) -> bool {
        self.providers.iter().any(|p| p.is_live())
    }

    async fn refresh(&mut self) -> Result<(), MemError> {
        let mut first_err: Option<MemError> = None;
        for p in &mut self.providers {
            if let Err(e) = p.refresh().await
                && first_err.is_none() {
                    first_err = Some(e);
                }
        }
        if let Some(e) = first_err {
            Err(e)
        } else {
            Ok(())
        }
    }

    async fn snapshot(&mut self) -> Result<SnapshotId, MemError> {
        Err(MemError::Unsupported)
    }

    async fn restore(&mut self, _id: SnapshotId) -> Result<(), MemError> {
        Err(MemError::Unsupported)
    }
}

// ---------------------------------------------------------------------------
// BroadcastWriteProvider — writes to all providers simultaneously
// ---------------------------------------------------------------------------

/// Mirrors all writes to every registered provider and serves reads from the
/// first provider that returns a successful result.  Useful for keeping
/// multiple memory images in sync (e.g., a `CoW` overlay and a raw image).
pub struct BroadcastWriteProvider {
    providers: Vec<Box<dyn MemoryProvider>>,
}

impl BroadcastWriteProvider {
    /// Create an empty broadcast provider.
    #[must_use]
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    /// Append a provider.
    pub fn add(&mut self, provider: Box<dyn MemoryProvider>) {
        self.providers.push(provider);
    }

    /// Number of registered providers.
    #[must_use]
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }
}

impl Default for BroadcastWriteProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MemoryProvider for BroadcastWriteProvider {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        let mut last_err = MemError::NotMapped(addr);
        for p in &self.providers {
            match p.read(addr, len) {
                Ok(d) => return Ok(d),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        let mut first_err: Option<MemError> = None;
        for p in &mut self.providers {
            if let Err(e) = p.write(addr, data)
                && first_err.is_none() {
                    first_err = Some(e);
                }
        }
        if let Some(e) = first_err {
            Err(e)
        } else {
            Ok(())
        }
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        self.providers.iter().flat_map(|p| p.regions()).collect()
    }

    fn is_live(&self) -> bool {
        self.providers.iter().any(|p| p.is_live())
    }

    async fn refresh(&mut self) -> Result<(), MemError> {
        let mut first_err: Option<MemError> = None;
        for p in &mut self.providers {
            if let Err(e) = p.refresh().await
                && first_err.is_none() {
                    first_err = Some(e);
                }
        }
        if let Some(e) = first_err {
            Err(e)
        } else {
            Ok(())
        }
    }

    async fn snapshot(&mut self) -> Result<SnapshotId, MemError> {
        Err(MemError::Unsupported)
    }

    async fn restore(&mut self, _id: SnapshotId) -> Result<(), MemError> {
        Err(MemError::Unsupported)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_memory::FileMemoryProvider;
    use crate::null_memory::NullMemoryProvider;
    use rustre_core::address::{Address, AddressRange};
    use rustre_core::permissions::Permissions;

    fn file_provider(base: u64, data: Vec<u8>) -> Box<dyn MemoryProvider> {
        Box::new(FileMemoryProvider::from_bytes(
            data,
            Address::new(base),
            Permissions::READ | Permissions::WRITE,
        ))
    }

    #[test]
    fn read_from_first_matching_provider() {
        let mut c = CompositeMemoryProvider::new();
        c.add_provider(file_provider(0x2000, vec![0xBB; 4]), 10);
        c.add_provider(file_provider(0x1000, vec![0xAA; 4]), 20);

        // Address 0x1000 is covered by priority-20 provider.
        let data = c.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xAA; 4]);

        // Address 0x2000 is covered by priority-10 provider.
        let data = c.read(Address::new(0x2000), 4).unwrap();
        assert_eq!(data, [0xBB; 4]);
    }

    #[test]
    fn read_unmapped_returns_error() {
        let mut c = CompositeMemoryProvider::new();
        c.add_provider(file_provider(0x1000, vec![0; 4]), 10);
        assert!(c.read(Address::new(0x9999), 4).is_err());
    }

    #[test]
    fn write_to_covering_provider() {
        let mut c = CompositeMemoryProvider::new();
        c.add_provider(file_provider(0x1000, vec![0xAA; 8]), 10);
        c.write(Address::new(0x1000), &[0x11, 0x22]).unwrap();
        let data = c.read(Address::new(0x1000), 2).unwrap();
        assert_eq!(data, [0x11, 0x22]);
    }

    #[test]
    fn provider_count_and_remove() {
        let mut c = CompositeMemoryProvider::new();
        c.add_provider(file_provider(0, vec![0; 4]), 5);
        c.add_provider(file_provider(0x1000, vec![0; 4]), 10);
        assert_eq!(c.provider_count(), 2);

        let removed = c.remove_provider_at(0);
        assert!(removed.is_some());
        assert_eq!(c.provider_count(), 1);

        assert!(c.remove_provider_at(99).is_none());
    }

    #[test]
    fn priority_ordering_higher_wins() {
        // Two providers cover the same range; higher priority should win.
        let mut c = CompositeMemoryProvider::new();
        c.add_provider(file_provider(0, vec![0xAA; 4]), 1);
        c.add_provider(file_provider(0, vec![0xBB; 4]), 100);
        let data = c.read(Address::new(0), 4).unwrap();
        assert_eq!(data, [0xBB; 4]);
    }

    #[test]
    fn regions_aggregates_all() {
        let mut c = CompositeMemoryProvider::new();
        c.add_provider(file_provider(0x1000, vec![0; 4]), 10);
        c.add_provider(file_provider(0x2000, vec![0; 4]), 20);
        assert_eq!(c.regions().len(), 2);
    }

    #[test]
    fn default_is_empty() {
        let c = CompositeMemoryProvider::default();
        assert_eq!(c.provider_count(), 0);
    }

    #[test]
    fn is_live_true_if_any_live() {
        let mut c = CompositeMemoryProvider::new();
        let mut null = NullMemoryProvider::new();
        null.add_null_region(
            AddressRange::new(Address::new(0), Address::new(0x1000)),
            Permissions::READ,
        );
        c.add_provider(Box::new(null), 1);
        // NullMemoryProvider::is_live() returns false.
        assert!(!c.is_live());
    }

    // ── RangeRoutingProvider tests ───────────────────────────────────────────

    #[test]
    fn range_routing_routes_to_correct_provider() {
        let mut router = RangeRoutingProvider::new();
        router.add_route(
            AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
            file_provider(0x1000, vec![0xAA; 0x1000]),
        );
        router.add_route(
            AddressRange::new(Address::new(0x3000), Address::new(0x4000)),
            file_provider(0x3000, vec![0xBB; 0x1000]),
        );
        let data = router.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xAA; 4]);
        let data = router.read(Address::new(0x3000), 4).unwrap();
        assert_eq!(data, [0xBB; 4]);
    }

    #[test]
    fn range_routing_unmapped_returns_error() {
        let router = RangeRoutingProvider::new();
        assert!(router.read(Address::new(0x5000), 4).is_err());
    }

    #[test]
    fn range_routing_write_to_correct_provider() {
        let mut router = RangeRoutingProvider::new();
        router.add_route(
            AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
            file_provider(0x1000, vec![0x00; 0x1000]),
        );
        router.write(Address::new(0x1000), &[0x42, 0x43]).unwrap();
        let data = router.read(Address::new(0x1000), 2).unwrap();
        assert_eq!(data, [0x42, 0x43]);
    }

    #[test]
    fn range_routing_remove_route() {
        let mut router = RangeRoutingProvider::new();
        router.add_route(
            AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
            file_provider(0x1000, vec![0xAA; 0x1000]),
        );
        assert_eq!(router.route_count(), 1);
        assert!(router.remove_route_at(Address::new(0x1000)));
        assert_eq!(router.route_count(), 0);
        assert!(!router.remove_route_at(Address::new(0xDEAD)));
    }

    #[test]
    fn range_routing_regions_aggregates() {
        let mut router = RangeRoutingProvider::new();
        router.add_route(
            AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
            file_provider(0x1000, vec![0xAA; 0x1000]),
        );
        router.add_route(
            AddressRange::new(Address::new(0x3000), Address::new(0x4000)),
            file_provider(0x3000, vec![0xBB; 0x1000]),
        );
        assert_eq!(router.regions().len(), 2);
    }

    // ── FallbackChain tests ──────────────────────────────────────────────────

    #[test]
    fn fallback_chain_first_success_wins() {
        let mut chain = FallbackChain::new();
        chain.push(file_provider(0x1000, vec![0xAA; 4]));
        chain.push(file_provider(0x1000, vec![0xBB; 4]));
        let data = chain.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xAA; 4]);
    }

    #[test]
    fn fallback_chain_falls_through_to_second() {
        let mut chain = FallbackChain::new();
        chain.push(file_provider(0x2000, vec![0xAA; 4])); // only at 0x2000
        chain.push(file_provider(0x1000, vec![0xBB; 4])); // at 0x1000
        let data = chain.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xBB; 4]);
    }

    #[test]
    fn fallback_chain_all_fail() {
        let mut chain = FallbackChain::new();
        chain.push(file_provider(0x2000, vec![0xAA; 4]));
        assert!(chain.read(Address::new(0xDEAD), 4).is_err());
    }

    #[test]
    fn fallback_chain_write_first_success() {
        let mut chain = FallbackChain::new();
        chain.push(file_provider(0x1000, vec![0x00; 4]));
        chain.push(file_provider(0x2000, vec![0x00; 4])); // shouldn't be reached
        chain.write(Address::new(0x1000), &[0x99]).unwrap();
        let data = chain.read(Address::new(0x1000), 1).unwrap();
        assert_eq!(data, [0x99]);
    }

    #[test]
    fn fallback_chain_len_and_is_empty() {
        let mut chain = FallbackChain::new();
        assert!(chain.is_empty());
        chain.push(file_provider(0, vec![0; 4]));
        assert_eq!(chain.len(), 1);
        chain.remove(0);
        assert!(chain.is_empty());
    }

    // ── BroadcastWriteProvider tests ─────────────────────────────────────────

    #[test]
    fn broadcast_write_mirrors_to_all() {
        use crate::file_memory::FileMemoryProvider;
        let p1 = FileMemoryProvider::from_bytes(
            vec![0u8; 4],
            Address::new(0x1000),
            Permissions::READ | Permissions::WRITE,
        );
        let p2 = FileMemoryProvider::from_bytes(
            vec![0u8; 4],
            Address::new(0x1000),
            Permissions::READ | Permissions::WRITE,
        );
        let mut bcast = BroadcastWriteProvider::new();
        bcast.add(Box::new(p1));
        bcast.add(Box::new(p2));
        bcast.write(Address::new(0x1000), &[0xAB, 0xCD]).unwrap();
        // Both providers should reflect the write.
        let data = bcast.read(Address::new(0x1000), 2).unwrap();
        assert_eq!(data, [0xAB, 0xCD]);
    }

    #[test]
    fn broadcast_provider_count() {
        let mut b = BroadcastWriteProvider::new();
        assert_eq!(b.provider_count(), 0);
        b.add(file_provider(0, vec![0; 4]));
        assert_eq!(b.provider_count(), 1);
    }

    #[test]
    fn broadcast_read_falls_through_on_miss() {
        let mut b = BroadcastWriteProvider::new();
        b.add(file_provider(0x2000, vec![0xCC; 4]));
        b.add(file_provider(0x1000, vec![0xDD; 4]));
        let data = b.read(Address::new(0x1000), 4).unwrap();
        assert_eq!(data, [0xDD; 4]);
    }
}
