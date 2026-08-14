use crate::memory_provider::{MemError, MemoryProvider, MemoryRegion, RegionSource, SnapshotId};
use async_trait::async_trait;
use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// FileMemoryProvider
// ---------------------------------------------------------------------------

/// Maps a binary file (or arbitrary byte slice) into a contiguous virtual
/// address range. All reads are served from an in-memory `Vec<u8>`; writes are
/// only permitted when the region includes `Permissions::WRITE`.
pub struct FileMemoryProvider {
    data: Vec<u8>,
    base_addr: Address,
    perms: Permissions,
    path: PathBuf,
}

impl FileMemoryProvider {
    /// Open `path`, read it entirely into memory, and map it starting at
    /// `base_addr` with the given `perms`.
    pub fn open(path: &Path, base_addr: Address, perms: Permissions) -> Result<Self, MemError> {
        let data = std::fs::read(path).map_err(MemError::from)?;
        Ok(Self {
            data,
            base_addr,
            perms,
            path: path.to_owned(),
        })
    }

    /// Construct directly from a byte vector.
    #[must_use] 
    pub const fn from_bytes(data: Vec<u8>, base_addr: Address, perms: Permissions) -> Self {
        Self {
            data,
            base_addr,
            perms,
            path: PathBuf::new(),
        }
    }

    /// Return the path that was used to open this provider (empty for `from_bytes`).
    #[must_use] 
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Length of the mapped data in bytes.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if the data buffer is empty.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Return a view of the underlying raw bytes.
    #[must_use] 
    pub fn raw_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Compute the virtual end address (exclusive).
    fn end_addr(&self) -> Address {
        self.base_addr + self.data.len() as u64
    }

    /// Convert a virtual address to a byte offset, checking bounds.
    fn offset_of(&self, addr: Address, len: usize) -> Result<usize, MemError> {
        if addr.as_u64() < self.base_addr.as_u64() {
            return Err(MemError::NotMapped(addr));
        }
        let offset = usize::try_from(addr.as_u64() - self.base_addr.as_u64())
            .map_err(|_| MemError::OutOfBounds(addr, len))?;
        if offset.saturating_add(len) > self.data.len() {
            return Err(MemError::OutOfBounds(addr, len));
        }
        Ok(offset)
    }
}

#[async_trait]
impl MemoryProvider for FileMemoryProvider {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        if !self.perms.is_readable() {
            return Err(MemError::PermissionDenied(addr));
        }
        let offset = self.offset_of(addr, len)?;
        Ok(self.data[offset..offset + len].to_vec())
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        if !self.perms.is_writable() {
            return Err(MemError::PermissionDenied(addr));
        }
        let offset = self.offset_of(addr, data.len())?;
        self.data[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        vec![MemoryRegion {
            range: AddressRange::new(self.base_addr, self.end_addr()),
            perms: self.perms,
            name: if self.path.as_os_str().is_empty() {
                None
            } else {
                Some(self.path.to_string_lossy().into_owned())
            },
            source: if self.path.as_os_str().is_empty() {
                RegionSource::Anonymous
            } else {
                RegionSource::FileSection {
                    file: self.path.clone(),
                    section: String::from("raw"),
                    file_offset: 0,
                }
            },
        }]
    }

    fn is_live(&self) -> bool {
        false
    }

    async fn refresh(&mut self) -> Result<(), MemError> {
        if self.path.as_os_str().is_empty() {
            return Ok(());
        }
        self.data = std::fs::read(&self.path).map_err(MemError::from)?;
        Ok(())
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
    use rustre_core::permissions::Permissions;

    fn make_provider() -> FileMemoryProvider {
        FileMemoryProvider::from_bytes(
            vec![0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80],
            Address::new(0x8000),
            Permissions::READ | Permissions::WRITE,
        )
    }

    #[test]
    fn read_in_bounds() {
        let p = make_provider();
        assert_eq!(
            p.read(Address::new(0x8000), 4).unwrap(),
            [0x10, 0x20, 0x30, 0x40]
        );
        assert_eq!(p.read(Address::new(0x8002), 2).unwrap(), [0x30, 0x40]);
    }

    #[test]
    fn read_out_of_bounds_returns_error() {
        let p = make_provider();
        assert!(p.read(Address::new(0x8000), 9).is_err());
    }

    #[test]
    fn read_unmapped_returns_error() {
        let p = make_provider();
        assert!(p.read(Address::new(0x1000), 4).is_err());
    }

    #[test]
    fn write_in_bounds() {
        let mut p = make_provider();
        p.write(Address::new(0x8000), &[0xAA, 0xBB]).unwrap();
        assert_eq!(p.read(Address::new(0x8000), 2).unwrap(), [0xAA, 0xBB]);
    }

    #[test]
    fn write_denied_on_readonly() {
        let mut p =
            FileMemoryProvider::from_bytes(vec![0u8; 8], Address::new(0), Permissions::READ);
        assert!(p.write(Address::new(0), &[1]).is_err());
    }

    #[test]
    fn regions_returns_full_range() {
        let p = make_provider();
        let regions = p.regions();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].range.start, Address::new(0x8000));
        assert_eq!(regions[0].range.end, Address::new(0x8008));
    }

    #[test]
    fn len_and_is_empty() {
        let p = make_provider();
        assert_eq!(p.len(), 8);
        assert!(!p.is_empty());

        let empty = FileMemoryProvider::from_bytes(vec![], Address::new(0), Permissions::READ);
        assert!(empty.is_empty());
    }

    #[test]
    fn from_bytes_raw_bytes() {
        let data = vec![1u8, 2, 3];
        let p = FileMemoryProvider::from_bytes(data.clone(), Address::new(0), Permissions::READ);
        assert_eq!(p.raw_bytes(), &data[..]);
    }
}
