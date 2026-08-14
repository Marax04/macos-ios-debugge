//! Copy-on-write (`CoW`) memory provider.
//!
//! `CowMemoryProvider` wraps an immutable base provider and accumulates writes
//! into a dirty-page overlay.  Reads are served from the overlay when a
//! page has been dirtied; otherwise they fall through to the base.

use crate::memory_provider::{MemError, MemoryProvider, MemoryRegion, SnapshotId};
use async_trait::async_trait;
use rustre_core::address::Address;
use std::collections::BTreeMap;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default `CoW` page size in bytes (4 KiB).
pub const COW_PAGE_SIZE: u64 = 0x1000;

// ─────────────────────────────────────────────────────────────────────────────
// CowMemoryProvider
// ─────────────────────────────────────────────────────────────────────────────

/// A copy-on-write memory provider.
///
/// Pages are copied into a private overlay on first write.  All subsequent
/// reads and writes for that page are served from the overlay.
pub struct CowMemoryProvider<B: MemoryProvider> {
    base: B,
    /// Dirty page table: `page_base_address` → page bytes.
    dirty: BTreeMap<u64, Vec<u8>>,
    /// Page size (must be a power of two).
    page_size: u64,
}

impl<B: MemoryProvider> CowMemoryProvider<B> {
    /// Wrap `base` with 4 KiB `CoW` pages.
    #[must_use]
    pub fn new(base: B) -> Self {
        Self::with_page_size(base, COW_PAGE_SIZE)
    }

    /// Wrap `base` with a custom page size.
    ///
    /// # Panics
    /// Panics if `page_size` is zero or not a power of two.
    #[must_use]
    pub fn with_page_size(base: B, page_size: u64) -> Self {
        assert!(
            page_size > 0 && page_size.is_power_of_two(),
            "page_size must be a power of two"
        );
        Self {
            base,
            dirty: BTreeMap::new(),
            page_size,
        }
    }

    /// Return the number of currently dirtied pages.
    #[must_use]
    pub fn dirty_page_count(&self) -> usize {
        self.dirty.len()
    }

    /// Discard all dirty pages, reverting to the base provider state.
    pub fn revert_all(&mut self) {
        self.dirty.clear();
    }

    /// Base address of the page containing `addr`.
    #[must_use]
    const fn page_base(&self, addr: Address) -> u64 {
        (addr.0 / self.page_size) * self.page_size
    }

    /// Ensure that the page containing `addr` is present in the dirty table.
    /// If not already dirty, reads it from `base` and inserts it.
    fn ensure_dirty(&mut self, addr: Address) -> Result<(), MemError> {
        let base = self.page_base(addr);
        if !self.dirty.contains_key(&base) {
            let page_data = match self.base.read(Address::new(base), self.page_size as usize) {
                Ok(d) => d,
                Err(MemError::NotMapped(_) | MemError::OutOfBounds(_, _)) => {
                    // Base doesn't have this page; create a zero page.
                    vec![0u8; self.page_size as usize]
                }
                Err(e) => return Err(e),
            };
            self.dirty.insert(base, page_data);
        }
        Ok(())
    }

    /// Return a reference to the dirty page for `addr` if it exists.
    #[must_use]
    fn get_dirty_page(&self, page_base: u64) -> Option<&Vec<u8>> {
        self.dirty.get(&page_base)
    }

    /// Dirty page count as reported per-region.
    #[must_use]
    pub fn dirty_addresses(&self) -> Vec<Address> {
        self.dirty.keys().map(|&k| Address::new(k)).collect()
    }
}

impl<B: MemoryProvider + Send + Sync> std::fmt::Debug for CowMemoryProvider<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CowMemoryProvider")
            .field("dirty_pages", &self.dirty.len())
            .field("page_size", &self.page_size)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<B: MemoryProvider + Send + Sync> MemoryProvider for CowMemoryProvider<B> {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        if len == 0 {
            return Ok(Vec::new());
        }
        let mut result = vec![0u8; len];
        let mut written = 0usize;
        let mut cur_addr = addr;

        while written < len {
            let page_base = self.page_base(cur_addr);
            let page_offset = (cur_addr.0 - page_base) as usize;
            let bytes_in_page = (self.page_size as usize - page_offset).min(len - written);

            if let Some(page) = self.get_dirty_page(page_base) {
                // Serve from dirty overlay.
                let end = page_offset + bytes_in_page;
                if end > page.len() {
                    return Err(MemError::OutOfBounds(cur_addr, bytes_in_page));
                }
                result[written..written + bytes_in_page].copy_from_slice(&page[page_offset..end]);
            } else {
                // Fall through to base.
                let chunk = self.base.read(cur_addr, bytes_in_page)?;
                result[written..written + bytes_in_page].copy_from_slice(&chunk);
            }

            written += bytes_in_page;
            cur_addr = Address::new(cur_addr.0 + bytes_in_page as u64);
        }
        Ok(result)
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        if data.is_empty() {
            return Ok(());
        }
        let mut written = 0usize;
        let mut cur_addr = addr;

        while written < data.len() {
            let page_base = self.page_base(cur_addr);
            let page_offset = (cur_addr.0 - page_base) as usize;
            let bytes_in_page = (self.page_size as usize - page_offset).min(data.len() - written);

            self.ensure_dirty(cur_addr)?;
            let page = self.dirty.get_mut(&page_base).unwrap();
            page[page_offset..page_offset + bytes_in_page]
                .copy_from_slice(&data[written..written + bytes_in_page]);

            written += bytes_in_page;
            cur_addr = Address::new(cur_addr.0 + bytes_in_page as u64);
        }
        Ok(())
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        self.base.regions()
    }

    fn is_live(&self) -> bool {
        self.base.is_live()
    }

    async fn refresh(&mut self) -> Result<(), MemError> {
        self.base.refresh().await
    }

    async fn snapshot(&mut self) -> Result<SnapshotId, MemError> {
        self.base.snapshot().await
    }

    async fn restore(&mut self, id: SnapshotId) -> Result<(), MemError> {
        self.base.restore(id).await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::file_memory::FileMemoryProvider;
    use rustre_core::permissions::Permissions;

    fn make_base(data: Vec<u8>) -> FileMemoryProvider {
        FileMemoryProvider::from_bytes(
            data,
            Address::new(0),
            Permissions::READ | Permissions::WRITE,
        )
    }

    #[test]
    fn test_cow_read_falls_through_to_base() {
        let base = make_base(vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let cow = CowMemoryProvider::new(base);
        let bytes = cow.read(Address::new(0), 4).unwrap();
        assert_eq!(bytes, [0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_cow_write_creates_dirty_page() {
        let base = make_base(vec![0u8; 0x1000]);
        let mut cow = CowMemoryProvider::new(base);
        assert_eq!(cow.dirty_page_count(), 0);
        cow.write(Address::new(0), &[0xFF]).unwrap();
        assert_eq!(cow.dirty_page_count(), 1);
    }

    #[test]
    fn test_cow_write_read_roundtrip() {
        let base = make_base(vec![0u8; 0x2000]);
        let mut cow = CowMemoryProvider::new(base);
        cow.write(Address::new(0x100), &[1, 2, 3, 4]).unwrap();
        let bytes = cow.read(Address::new(0x100), 4).unwrap();
        assert_eq!(bytes, [1, 2, 3, 4]);
    }

    #[test]
    fn test_cow_base_unmodified() {
        let base = make_base(vec![0xAB; 0x1000]);
        let mut cow = CowMemoryProvider::new(base);
        cow.write(Address::new(0), &[0xFF]).unwrap();
        // Base (accessed through inner field) still has 0xAB at offset 0.
        let from_dirty = cow.dirty.get(&0).unwrap();
        assert_eq!(from_dirty[0], 0xFF);
        assert_eq!(from_dirty[1], 0xAB); // rest is CoW copy of base
    }

    #[test]
    fn test_cow_revert_all() {
        let base = make_base(vec![0u8; 0x1000]);
        let mut cow = CowMemoryProvider::new(base);
        cow.write(Address::new(0), &[1, 2, 3]).unwrap();
        assert_eq!(cow.dirty_page_count(), 1);
        cow.revert_all();
        assert_eq!(cow.dirty_page_count(), 0);
        // Read again — should return base values.
        let bytes = cow.read(Address::new(0), 3).unwrap();
        assert_eq!(bytes, [0u8; 3]);
    }

    #[test]
    fn test_cow_cross_page_write() {
        let base = make_base(vec![0u8; 0x3000]);
        let mut cow = CowMemoryProvider::new(base);
        // Write 8 bytes that straddle a 4 KiB boundary (0x0FFE..0x1006).
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
        cow.write(Address::new(0x0FFE), &data).unwrap();
        assert_eq!(cow.dirty_page_count(), 2);
        let back = cow.read(Address::new(0x0FFE), 8).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn test_cow_write_empty_noop() {
        let base = make_base(vec![0u8; 0x1000]);
        let mut cow = CowMemoryProvider::new(base);
        cow.write(Address::new(0), &[]).unwrap();
        assert_eq!(cow.dirty_page_count(), 0);
    }

    #[test]
    fn test_cow_regions_delegate_to_base() {
        let base = make_base(vec![0u8; 0x1000]);
        let cow = CowMemoryProvider::new(base);
        let regs = cow.regions();
        assert_eq!(regs.len(), 1);
    }

    #[test]
    fn test_cow_dirty_addresses() {
        let base = make_base(vec![0u8; 0x4000]);
        let mut cow = CowMemoryProvider::new(base);
        cow.write(Address::new(0), &[1]).unwrap();
        cow.write(Address::new(0x1000), &[2]).unwrap();
        let addrs = cow.dirty_addresses();
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn test_cow_page_size_custom() {
        let base = make_base(vec![0u8; 0x200]);
        let mut cow = CowMemoryProvider::with_page_size(base, 0x100);
        cow.write(Address::new(0), &[0xAA]).unwrap();
        cow.write(Address::new(0x100), &[0xBB]).unwrap();
        assert_eq!(cow.dirty_page_count(), 2);
    }

    #[test]
    fn test_cow_is_live_delegates() {
        let base = make_base(vec![0u8; 0x100]);
        let cow = CowMemoryProvider::new(base);
        assert!(!cow.is_live());
    }

    #[test]
    fn test_cow_zero_len_read() {
        let base = make_base(vec![0u8; 0x100]);
        let cow = CowMemoryProvider::new(base);
        let bytes = cow.read(Address::new(0), 0).unwrap();
        assert!(bytes.is_empty());
    }
}
