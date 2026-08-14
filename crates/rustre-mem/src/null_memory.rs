use crate::memory_provider::{MemError, MemoryProvider, MemoryRegion, RegionSource, SnapshotId};
use async_trait::async_trait;
use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;

// ---------------------------------------------------------------------------
// NullMemoryProvider
// ---------------------------------------------------------------------------

/// A memory provider that returns zeros for all reads and silently accepts
/// writes. Useful as a placeholder or for testing.
pub struct NullMemoryProvider {
    regions: Vec<MemoryRegion>,
}

impl NullMemoryProvider {
    /// Create a provider with no regions. Reads against unmapped addresses
    /// will still return an error; use [`with_regions`] or
    /// [`add_null_region`] to register address ranges.
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    /// Create a provider from a pre-populated region list.
    #[must_use] 
    pub const fn with_regions(regions: Vec<MemoryRegion>) -> Self {
        Self { regions }
    }

    /// Register a new zero-filled region spanning `range` with `perms`.
    pub fn add_null_region(&mut self, range: AddressRange, perms: Permissions) {
        self.regions.push(MemoryRegion {
            range,
            perms,
            name: None,
            source: RegionSource::Anonymous,
        });
    }

    /// Find the region that fully contains `[addr, addr+len)`, if any.
    fn find_region(&self, addr: Address, len: usize) -> Option<&MemoryRegion> {
        let end = addr + len as u64;
        self.regions
            .iter()
            .find(|r| r.range.contains(addr) && (len == 0 || r.range.contains(end - 1u64)))
    }
}

impl Default for NullMemoryProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MemoryProvider for NullMemoryProvider {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        match self.find_region(addr, len) {
            Some(region) => {
                if !region.perms.is_readable() {
                    return Err(MemError::PermissionDenied(addr));
                }
                Ok(vec![0u8; len])
            }
            None => Err(MemError::NotMapped(addr)),
        }
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        match self.find_region(addr, data.len()) {
            Some(region) => {
                if !region.perms.is_writable() {
                    return Err(MemError::PermissionDenied(addr));
                }
                // Null provider discards the written data.
                Ok(())
            }
            None => Err(MemError::NotMapped(addr)),
        }
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        self.regions.clone()
    }

    fn is_live(&self) -> bool {
        false
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

    fn provider_with_rw_region() -> NullMemoryProvider {
        let mut p = NullMemoryProvider::new();
        p.add_null_region(
            AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
            Permissions::READ | Permissions::WRITE,
        );
        p
    }

    #[test]
    fn read_mapped_region_returns_zeros() {
        let p = provider_with_rw_region();
        let data = p.read(Address::new(0x1000), 8).unwrap();
        assert_eq!(data, vec![0u8; 8]);
    }

    #[test]
    fn read_unmapped_returns_error() {
        let p = provider_with_rw_region();
        assert!(p.read(Address::new(0x3000), 4).is_err());
    }

    #[test]
    fn write_mapped_region_succeeds() {
        let mut p = provider_with_rw_region();
        p.write(Address::new(0x1000), &[1, 2, 3]).unwrap();
        // Data is discarded; subsequent read still returns zeros.
        let data = p.read(Address::new(0x1000), 3).unwrap();
        assert_eq!(data, vec![0u8; 3]);
    }

    #[test]
    fn write_unmapped_returns_error() {
        let mut p = provider_with_rw_region();
        assert!(p.write(Address::new(0x5000), &[1]).is_err());
    }

    #[test]
    fn write_readonly_region_denied() {
        let mut p = NullMemoryProvider::new();
        p.add_null_region(
            AddressRange::new(Address::new(0), Address::new(0x1000)),
            Permissions::READ,
        );
        assert!(p.write(Address::new(0), &[1]).is_err());
    }

    #[test]
    fn regions_returns_all_added() {
        let mut p = NullMemoryProvider::new();
        p.add_null_region(
            AddressRange::new(Address::new(0), Address::new(0x1000)),
            Permissions::READ,
        );
        p.add_null_region(
            AddressRange::new(Address::new(0x2000), Address::new(0x3000)),
            Permissions::READ | Permissions::WRITE,
        );
        assert_eq!(p.regions().len(), 2);
    }

    #[test]
    fn default_has_no_regions() {
        let p = NullMemoryProvider::default();
        assert!(p.regions().is_empty());
    }

    #[test]
    fn with_regions_constructor() {
        let regions = vec![MemoryRegion {
            range: AddressRange::new(Address::new(0), Address::new(0x100)),
            perms: Permissions::READ,
            name: Some("test".into()),
            source: RegionSource::Anonymous,
        }];
        let p = NullMemoryProvider::with_regions(regions);
        assert_eq!(p.regions().len(), 1);
    }
}
