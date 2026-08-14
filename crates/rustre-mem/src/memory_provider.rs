use async_trait::async_trait;
use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum MemError {
    #[error("address not mapped: {0}")]
    NotMapped(Address),
    #[error("write protection violation at {0}")]
    PermissionDenied(Address),
    #[error("read out of bounds at {0} len {1}")]
    OutOfBounds(Address, usize),
    #[error("operation unsupported")]
    Unsupported,
    #[error("io error: {0}")]
    Io(String),
    #[error("other error: {0}")]
    Other(String),
}

impl From<std::io::Error> for MemError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SnapshotId(pub u64);

#[async_trait]
pub trait MemoryProvider: Send + Sync {
    /// Read memory range synchronously. Returns error if not mapped.
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError>;

    /// Write memory range synchronously. Returns error if readonly or not mapped.
    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError>;

    /// List of memory regions mapped at query time.
    fn regions(&self) -> Vec<MemoryRegion>;

    /// Read a single byte at `addr`. Returns `None` if the address is not mapped.
    fn read_u8(&self, addr: Address) -> Option<u8> {
        self.read(addr, 1).ok().map(|b| b[0])
    }

    /// Read a little-endian u16 at `addr`. Returns `None` if not mapped.
    fn read_u16_le(&self, addr: Address) -> Option<u16> {
        let b = self.read(addr, 2).ok()?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }

    /// Read a little-endian u32 at `addr`. Returns `None` if not mapped.
    fn read_u32_le(&self, addr: Address) -> Option<u32> {
        let b = self.read(addr, 4).ok()?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a little-endian u64 at `addr`. Returns `None` if not mapped.
    fn read_u64_le(&self, addr: Address) -> Option<u64> {
        let b = self.read(addr, 8).ok()?;
        Some(u64::from_le_bytes(b[..8].try_into().ok()?))
    }

    /// Scan all readable regions for the first occurrence of `pattern` at or
    /// after `start`. Returns the address of the first match, or `None`.
    fn find_bytes(&self, pattern: &[u8], start: Address) -> Option<Address> {
        if pattern.is_empty() {
            return None;
        }
        for region in self.regions() {
            if !region.perms.is_readable() {
                continue;
            }
            // Skip regions that end before `start`.
            if region.range.end <= start {
                continue;
            }
            // Clamp the scan start to `start` when inside this region.
            let scan_start = if region.range.start >= start {
                region.range.start
            } else {
                start
            };
            let scan_len = (region
                .range
                .end
                .as_u64()
                .saturating_sub(scan_start.as_u64())) as usize;
            if scan_len < pattern.len() {
                continue;
            }
            if let Ok(data) = self.read(scan_start, scan_len) {
                let pat_len = pattern.len();
                'search: for i in 0..=(data.len().saturating_sub(pat_len)) {
                    for j in 0..pat_len {
                        if data[i + j] != pattern[j] {
                            continue 'search;
                        }
                    }
                    return Some(Address::new(scan_start.as_u64() + i as u64));
                }
            }
        }
        None
    }

    /// Return aggregate byte-count statistics for this provider's mapped regions.
    fn stats(&self) -> MemoryStats {
        let mut s = MemoryStats::default();
        for region in self.regions() {
            let len = region.range.len();
            s.total_mapped += len;
            if region.perms.is_readable() {
                s.readable_bytes += len;
            }
            if region.perms.is_writable() {
                s.writable_bytes += len;
            }
            if region.perms.is_executable() {
                s.executable_bytes += len;
            }
        }
        s
    }

    /// Read a UTF-8 string (stopping at NUL or `max_len` bytes) at `addr`.
    /// Returns `None` if the address is unmapped or the bytes are invalid UTF-8.
    fn read_string(&self, addr: Address, max_len: usize) -> Option<String>
    where
        Self: Sized,
    {
        read_cstring(self, addr, max_len).ok()
    }

    /// True if the provider represents a live, mutable runtime state (process, emulator).
    fn is_live(&self) -> bool {
        false
    }

    /// For live providers: invalidate caches, refresh mapped regions.
    async fn refresh(&mut self) -> Result<(), MemError> {
        Ok(())
    }

    /// Snapshot provider state if supported (TTD, emulator).
    async fn snapshot(&mut self) -> Result<SnapshotId, MemError> {
        Err(MemError::Unsupported)
    }

    /// Restore provider state to a snapshot.
    async fn restore(&mut self, _id: SnapshotId) -> Result<(), MemError> {
        Err(MemError::Unsupported)
    }
}

#[derive(Clone, Debug)]
pub struct MemoryRegion {
    pub range: AddressRange,
    pub perms: Permissions,
    pub name: Option<String>,
    pub source: RegionSource,
}

impl MemoryRegion {
    /// Create a new named region with given permissions.
    #[must_use] 
    pub const fn new(
        range: AddressRange,
        perms: Permissions,
        name: Option<String>,
        source: RegionSource,
    ) -> Self {
        Self {
            range,
            perms,
            name,
            source,
        }
    }
}

#[derive(Clone, Debug)]
pub enum RegionSource {
    FileSection {
        file: PathBuf,
        section: String,
        file_offset: u64,
    },
    ProcessModule {
        module: String,
        pid: u32,
    },
    Anonymous,
    Heap,
    Stack,
    Emulated,
    Reconstructed,
}

// ---------------------------------------------------------------------------
// ReadOnlyWrapper
// ---------------------------------------------------------------------------

/// Wraps a `MemoryProvider` and denies all writes.
pub struct ReadOnlyWrapper<P: MemoryProvider>(pub P);

#[async_trait]
impl<P: MemoryProvider + Send + Sync> MemoryProvider for ReadOnlyWrapper<P> {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        self.0.read(addr, len)
    }

    fn write(&mut self, addr: Address, _data: &[u8]) -> Result<(), MemError> {
        Err(MemError::PermissionDenied(addr))
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        self.0.regions()
    }

    fn is_live(&self) -> bool {
        self.0.is_live()
    }

    async fn refresh(&mut self) -> Result<(), MemError> {
        self.0.refresh().await
    }

    async fn snapshot(&mut self) -> Result<SnapshotId, MemError> {
        self.0.snapshot().await
    }

    async fn restore(&mut self, id: SnapshotId) -> Result<(), MemError> {
        self.0.restore(id).await
    }
}

// ---------------------------------------------------------------------------
// Utility read functions (synchronous, work on any MemoryProvider)
// ---------------------------------------------------------------------------

/// Read a little-endian u16.
pub fn read_u16_le<P: MemoryProvider>(provider: &P, addr: Address) -> Result<u16, MemError> {
    let bytes = provider.read(addr, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Read a little-endian u32.
pub fn read_u32_le<P: MemoryProvider>(provider: &P, addr: Address) -> Result<u32, MemError> {
    let bytes = provider.read(addr, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a little-endian u64.
pub fn read_u64_le<P: MemoryProvider>(provider: &P, addr: Address) -> Result<u64, MemError> {
    let bytes = provider.read(addr, 8)?;
    Ok(u64::from_le_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| MemError::OutOfBounds(addr, 8))?,
    ))
}

/// Read a big-endian u32.
pub fn read_u32_be<P: MemoryProvider>(provider: &P, addr: Address) -> Result<u32, MemError> {
    let bytes = provider.read(addr, 4)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a big-endian u64.
pub fn read_u64_be<P: MemoryProvider>(provider: &P, addr: Address) -> Result<u64, MemError> {
    let bytes = provider.read(addr, 8)?;
    Ok(u64::from_be_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| MemError::OutOfBounds(addr, 8))?,
    ))
}

/// Read a NUL-terminated C string up to `max_len` bytes.
///
/// Bytes are read one at a time so that the read does not exceed the mapped
/// region. This is less efficient than a bulk read but works correctly even
/// when the NUL terminator falls within a region boundary.
pub fn read_cstring<P: MemoryProvider>(
    provider: &P,
    addr: Address,
    max_len: usize,
) -> Result<String, MemError> {
    let mut result = Vec::with_capacity(max_len.min(256));
    for i in 0..max_len {
        match provider.read(addr + i as u64, 1) {
            Ok(b) => {
                if b[0] == 0 {
                    break;
                }
                result.push(b[0]);
            }
            Err(MemError::OutOfBounds(_, _) | MemError::NotMapped(_)) => break,
            Err(e) => return Err(e),
        }
    }
    String::from_utf8(result).map_err(|e| MemError::Other(format!("invalid utf-8 in cstring: {e}")))
}

/// Scan `region` for all occurrences of `pattern`, respecting an optional `mask`
/// (mask byte 0x00 = wildcard, 0xFF = exact match). Returns starting addresses.
pub fn find_bytes<P: MemoryProvider>(
    provider: &P,
    pattern: &[u8],
    mask: Option<&[u8]>,
    region: AddressRange,
) -> Vec<Address> {
    if pattern.is_empty() || region.is_empty() {
        return Vec::new();
    }
    let len = region.len() as usize;
    let data = match provider.read(region.start, len) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };

    let pat_len = pattern.len();
    if pat_len > data.len() {
        return Vec::new();
    }

    let mut results = Vec::new();
    'outer: for i in 0..=(data.len() - pat_len) {
        for j in 0..pat_len {
            let mask_byte = mask.map_or(0xFF, |m| if j < m.len() { m[j] } else { 0xFF });
            if (data[i + j] & mask_byte) != (pattern[j] & mask_byte) {
                continue 'outer;
            }
        }
        results.push(region.start + i as u64);
    }
    results
}

// ---------------------------------------------------------------------------
// Additional utility read functions
// ---------------------------------------------------------------------------

/// Read a little-endian u8.
pub fn read_u8<P: MemoryProvider>(provider: &P, addr: Address) -> Result<u8, MemError> {
    let bytes = provider.read(addr, 1)?;
    Ok(bytes[0])
}

/// Read a big-endian u16.
pub fn read_u16_be<P: MemoryProvider>(provider: &P, addr: Address) -> Result<u16, MemError> {
    let bytes = provider.read(addr, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Read a little-endian i8.
pub fn read_i8<P: MemoryProvider>(provider: &P, addr: Address) -> Result<i8, MemError> {
    Ok(read_u8(provider, addr)? as i8)
}

/// Read a little-endian i16.
pub fn read_i16_le<P: MemoryProvider>(provider: &P, addr: Address) -> Result<i16, MemError> {
    let bytes = provider.read(addr, 2)?;
    Ok(i16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Read a big-endian i16.
pub fn read_i16_be<P: MemoryProvider>(provider: &P, addr: Address) -> Result<i16, MemError> {
    let bytes = provider.read(addr, 2)?;
    Ok(i16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Read a little-endian i32.
pub fn read_i32_le<P: MemoryProvider>(provider: &P, addr: Address) -> Result<i32, MemError> {
    let bytes = provider.read(addr, 4)?;
    Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a big-endian i32.
pub fn read_i32_be<P: MemoryProvider>(provider: &P, addr: Address) -> Result<i32, MemError> {
    let bytes = provider.read(addr, 4)?;
    Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Read a little-endian i64.
pub fn read_i64_le<P: MemoryProvider>(provider: &P, addr: Address) -> Result<i64, MemError> {
    let bytes = provider.read(addr, 8)?;
    Ok(i64::from_le_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| MemError::OutOfBounds(addr, 8))?,
    ))
}

/// Read a big-endian i64.
pub fn read_i64_be<P: MemoryProvider>(provider: &P, addr: Address) -> Result<i64, MemError> {
    let bytes = provider.read(addr, 8)?;
    Ok(i64::from_be_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| MemError::OutOfBounds(addr, 8))?,
    ))
}

/// Read a little-endian f32 (IEEE 754).
pub fn read_f32_le<P: MemoryProvider>(provider: &P, addr: Address) -> Result<f32, MemError> {
    let bytes = provider.read(addr, 4)?;
    let bits = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    Ok(f32::from_bits(bits))
}

/// Read a big-endian f32 (IEEE 754).
pub fn read_f32_be<P: MemoryProvider>(provider: &P, addr: Address) -> Result<f32, MemError> {
    let bytes = provider.read(addr, 4)?;
    let bits = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    Ok(f32::from_bits(bits))
}

/// Read a little-endian f64 (IEEE 754).
pub fn read_f64_le<P: MemoryProvider>(provider: &P, addr: Address) -> Result<f64, MemError> {
    let bytes = provider.read(addr, 8)?;
    let bits = u64::from_le_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| MemError::OutOfBounds(addr, 8))?,
    );
    Ok(f64::from_bits(bits))
}

/// Read a big-endian f64 (IEEE 754).
pub fn read_f64_be<P: MemoryProvider>(provider: &P, addr: Address) -> Result<f64, MemError> {
    let bytes = provider.read(addr, 8)?;
    let bits = u64::from_be_bytes(
        bytes[..8]
            .try_into()
            .map_err(|_| MemError::OutOfBounds(addr, 8))?,
    );
    Ok(f64::from_bits(bits))
}

/// Read a fixed-size array of `N` bytes from `addr`.
pub fn read_array<P: MemoryProvider, const N: usize>(
    provider: &P,
    addr: Address,
) -> Result<[u8; N], MemError> {
    let bytes = provider.read(addr, N)?;
    bytes[..N]
        .try_into()
        .map_err(|_| MemError::OutOfBounds(addr, N))
}

/// Write a little-endian u16 to `addr`.
pub fn write_u16_le<P: MemoryProvider>(
    provider: &mut P,
    addr: Address,
    value: u16,
) -> Result<(), MemError> {
    provider.write(addr, &value.to_le_bytes())
}

/// Write a big-endian u16 to `addr`.
pub fn write_u16_be<P: MemoryProvider>(
    provider: &mut P,
    addr: Address,
    value: u16,
) -> Result<(), MemError> {
    provider.write(addr, &value.to_be_bytes())
}

/// Write a little-endian u32 to `addr`.
pub fn write_u32_le<P: MemoryProvider>(
    provider: &mut P,
    addr: Address,
    value: u32,
) -> Result<(), MemError> {
    provider.write(addr, &value.to_le_bytes())
}

/// Write a big-endian u32 to `addr`.
pub fn write_u32_be<P: MemoryProvider>(
    provider: &mut P,
    addr: Address,
    value: u32,
) -> Result<(), MemError> {
    provider.write(addr, &value.to_be_bytes())
}

/// Write a little-endian u64 to `addr`.
pub fn write_u64_le<P: MemoryProvider>(
    provider: &mut P,
    addr: Address,
    value: u64,
) -> Result<(), MemError> {
    provider.write(addr, &value.to_le_bytes())
}

/// Write a big-endian u64 to `addr`.
pub fn write_u64_be<P: MemoryProvider>(
    provider: &mut P,
    addr: Address,
    value: u64,
) -> Result<(), MemError> {
    provider.write(addr, &value.to_be_bytes())
}

/// Read a NUL-terminated wide (UTF-16LE) string up to `max_chars` characters.
pub fn read_wstring<P: MemoryProvider>(
    provider: &P,
    addr: Address,
    max_chars: usize,
) -> Result<String, MemError> {
    let mut chars = Vec::with_capacity(max_chars.min(128));
    for i in 0..max_chars {
        let byte_offset = (i * 2) as u64;
        match provider.read(addr + byte_offset, 2) {
            Ok(bytes) => {
                let wc = u16::from_le_bytes([bytes[0], bytes[1]]);
                if wc == 0 {
                    break;
                }
                chars.push(wc);
            }
            Err(MemError::OutOfBounds(_, _) | MemError::NotMapped(_)) => break,
            Err(e) => return Err(e),
        }
    }
    String::from_utf16(&chars).map_err(|e| MemError::Other(format!("invalid utf-16: {e}")))
}

/// Fill `len` bytes starting at `addr` with `fill_byte`.
pub fn fill_memory<P: MemoryProvider>(
    provider: &mut P,
    addr: Address,
    len: usize,
    fill_byte: u8,
) -> Result<(), MemError> {
    let data = vec![fill_byte; len];
    provider.write(addr, &data)
}

/// Copy `len` bytes from `src_addr` to `dst_addr` within the same provider.
pub fn copy_memory<P: MemoryProvider>(
    provider: &mut P,
    src_addr: Address,
    dst_addr: Address,
    len: usize,
) -> Result<(), MemError> {
    let data = provider.read(src_addr, len)?;
    provider.write(dst_addr, &data)
}

/// Read all mapped regions and return a `HashMap<AddressRange, Vec<u8>>`.
pub fn dump_all_regions<P: MemoryProvider>(provider: &P) -> HashMap<AddressRange, Vec<u8>> {
    let mut result = HashMap::new();
    for region in provider.regions() {
        if !region.perms.is_readable() {
            continue;
        }
        let len = region.range.len() as usize;
        if let Ok(data) = provider.read(region.range.start, len) {
            result.insert(region.range, data);
        }
    }
    result
}

/// Search all readable mapped regions for the first occurrence of `needle`.
/// Returns `(region, address)` on success.
pub fn find_first_in_all_regions<P: MemoryProvider>(
    provider: &P,
    needle: &[u8],
) -> Option<(MemoryRegion, Address)> {
    if needle.is_empty() {
        return None;
    }
    for region in provider.regions() {
        if !region.perms.is_readable() {
            continue;
        }
        let hits = find_bytes(provider, needle, None, region.range);
        if let Some(&hit) = hits.first() {
            return Some((region, hit));
        }
    }
    None
}

/// Check whether an address is within any mapped region.
pub fn is_mapped<P: MemoryProvider>(provider: &P, addr: Address) -> bool {
    provider.regions().iter().any(|r| r.range.contains(addr))
}

/// Return the region that contains `addr`, if any.
pub fn region_at<P: MemoryProvider>(provider: &P, addr: Address) -> Option<MemoryRegion> {
    provider
        .regions()
        .into_iter()
        .find(|r| r.range.contains(addr))
}

/// Return all regions that are both readable and executable.
pub fn executable_regions<P: MemoryProvider>(provider: &P) -> Vec<MemoryRegion> {
    provider
        .regions()
        .into_iter()
        .filter(|r| r.perms.is_readable() && r.perms.is_executable())
        .collect()
}

/// Return all regions that are writable.
pub fn writable_regions<P: MemoryProvider>(provider: &P) -> Vec<MemoryRegion> {
    provider
        .regions()
        .into_iter()
        .filter(|r| r.perms.is_writable())
        .collect()
}

/// Compute the total number of mapped bytes across all regions.
pub fn total_mapped_bytes<P: MemoryProvider>(provider: &P) -> u64 {
    provider.regions().iter().map(|r| r.range.len()).sum()
}

// ---------------------------------------------------------------------------
// MemoryStats — aggregate statistics about a provider's mapped regions
// ---------------------------------------------------------------------------

/// Aggregate byte-count statistics derived from a provider's mapped regions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemoryStats {
    /// Total bytes covered by all mapped regions.
    pub total_mapped: u64,
    /// Bytes in regions that are readable.
    pub readable_bytes: u64,
    /// Bytes in regions that are writable.
    pub writable_bytes: u64,
    /// Bytes in regions that are executable.
    pub executable_bytes: u64,
}

// ---------------------------------------------------------------------------
// MemoryProviderExt — extension trait for ergonomic typed reads
// ---------------------------------------------------------------------------

/// Extension methods for any `MemoryProvider`, providing fallible typed reads
/// (returning `Result<T, MemError>`) and other ergonomic helpers.
///
/// The `MemoryProvider` trait itself exposes infallible `Option`-returning
/// variants of the common scalar reads. This extension trait provides the
/// corresponding `Result`-returning versions plus additional helpers.
pub trait MemoryProviderExt: MemoryProvider {
    /// Read a u8 at `addr`, returning a `Result`.
    fn read_u8_result(&self, addr: Address) -> Result<u8, MemError>
    where
        Self: Sized,
    {
        read_u8(self, addr)
    }

    /// Read a little-endian u16 at `addr`, returning a `Result`.
    fn read_u16_le_result(&self, addr: Address) -> Result<u16, MemError>
    where
        Self: Sized,
    {
        read_u16_le(self, addr)
    }

    /// Read a big-endian u16 at `addr`.
    fn read_u16_be(&self, addr: Address) -> Result<u16, MemError>
    where
        Self: Sized,
    {
        read_u16_be(self, addr)
    }

    /// Read a little-endian u32 at `addr`, returning a `Result`.
    fn read_u32_le_result(&self, addr: Address) -> Result<u32, MemError>
    where
        Self: Sized,
    {
        read_u32_le(self, addr)
    }

    /// Read a big-endian u32 at `addr`.
    fn read_u32_be(&self, addr: Address) -> Result<u32, MemError>
    where
        Self: Sized,
    {
        read_u32_be(self, addr)
    }

    /// Read a little-endian u64 at `addr`, returning a `Result`.
    fn read_u64_le_result(&self, addr: Address) -> Result<u64, MemError>
    where
        Self: Sized,
    {
        read_u64_le(self, addr)
    }

    /// Read a big-endian u64 at `addr`.
    fn read_u64_be(&self, addr: Address) -> Result<u64, MemError>
    where
        Self: Sized,
    {
        read_u64_be(self, addr)
    }

    /// Read a NUL-terminated C string, returning a `Result`.
    fn read_cstring(&self, addr: Address, max_len: usize) -> Result<String, MemError>
    where
        Self: Sized,
    {
        read_cstring(self, addr, max_len)
    }

    /// Read a NUL-terminated UTF-16LE string.
    fn read_wstring(&self, addr: Address, max_chars: usize) -> Result<String, MemError>
    where
        Self: Sized,
    {
        read_wstring(self, addr, max_chars)
    }

    /// Check whether `addr` is covered by any mapped region.
    fn is_mapped(&self, addr: Address) -> bool
    where
        Self: Sized,
    {
        is_mapped(self, addr)
    }

    /// Return the region covering `addr`, if any.
    fn region_at(&self, addr: Address) -> Option<MemoryRegion>
    where
        Self: Sized,
    {
        region_at(self, addr)
    }
}

/// Blanket implementation — every `MemoryProvider` gets the extension methods.
impl<T: MemoryProvider> MemoryProviderExt for T {}

// ---------------------------------------------------------------------------
// RegionFilter — convenience struct to filter regions by various criteria
// ---------------------------------------------------------------------------

/// Builder for filtering a list of `MemoryRegion`s.
#[derive(Debug, Default)]
pub struct RegionFilter {
    require_read: bool,
    require_write: bool,
    require_exec: bool,
    name_contains: Option<String>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    source_is_file: bool,
}

impl RegionFilter {
    /// Create a new, unconfigured filter.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Only pass regions with read permission.
    #[must_use]
    pub const fn readable(mut self) -> Self {
        self.require_read = true;
        self
    }

    /// Only pass regions with write permission.
    #[must_use]
    pub const fn writable(mut self) -> Self {
        self.require_write = true;
        self
    }

    /// Only pass regions with execute permission.
    #[must_use]
    pub const fn executable(mut self) -> Self {
        self.require_exec = true;
        self
    }

    /// Only pass regions whose name contains `s` (case-sensitive).
    #[must_use]
    pub fn named_contains(mut self, s: impl Into<String>) -> Self {
        self.name_contains = Some(s.into());
        self
    }

    /// Only pass regions of at least `bytes` bytes.
    #[must_use]
    pub const fn at_least(mut self, bytes: u64) -> Self {
        self.min_size = Some(bytes);
        self
    }

    /// Only pass regions of at most `bytes` bytes.
    #[must_use]
    pub const fn at_most(mut self, bytes: u64) -> Self {
        self.max_size = Some(bytes);
        self
    }

    /// Only pass file-backed regions.
    #[must_use]
    pub const fn file_backed(mut self) -> Self {
        self.source_is_file = true;
        self
    }

    /// Apply the filter to a list of regions.
    #[must_use]
    pub fn apply(&self, regions: Vec<MemoryRegion>) -> Vec<MemoryRegion> {
        regions
            .into_iter()
            .filter(|r| {
                if self.require_read && !r.perms.is_readable() {
                    return false;
                }
                if self.require_write && !r.perms.is_writable() {
                    return false;
                }
                if self.require_exec && !r.perms.is_executable() {
                    return false;
                }
                if let Some(ref s) = self.name_contains {
                    match &r.name {
                        Some(n) if n.contains(s.as_str()) => {}
                        _ => return false,
                    }
                }
                let size = r.range.len();
                if let Some(min) = self.min_size
                    && size < min {
                        return false;
                    }
                if let Some(max) = self.max_size
                    && size > max {
                        return false;
                    }
                if self.source_is_file
                    && !matches!(r.source, RegionSource::FileSection { .. }) {
                        return false;
                    }
                true
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// MemoryCursor — a positioned reader over a MemoryProvider
// ---------------------------------------------------------------------------

/// A stateful cursor that reads sequentially through a `MemoryProvider`.
pub struct MemoryCursor<'p, P: MemoryProvider> {
    provider: &'p P,
    pos: Address,
}

impl<'p, P: MemoryProvider + Send + Sync> MemoryCursor<'p, P> {
    /// Create a cursor positioned at `addr`.
    #[must_use]
    pub const fn new(provider: &'p P, addr: Address) -> Self {
        Self {
            provider,
            pos: addr,
        }
    }

    /// Current position.
    #[must_use]
    pub const fn position(&self) -> Address {
        self.pos
    }

    /// Seek to an absolute address.
    pub const fn seek(&mut self, addr: Address) {
        self.pos = addr;
    }

    /// Advance the cursor by `n` bytes without reading.
    pub const fn skip(&mut self, n: u64) {
        self.pos = Address::new(self.pos.0.saturating_add(n));
    }

    /// Read `len` bytes at the current position and advance.
    pub fn read(&mut self, len: usize) -> Result<Vec<u8>, MemError> {
        let data = self.provider.read(self.pos, len)?;
        self.pos = Address::new(self.pos.0 + len as u64);
        Ok(data)
    }

    /// Read a u8 and advance.
    pub fn read_u8(&mut self) -> Result<u8, MemError> {
        let b = read_u8(self.provider, self.pos)?;
        self.pos = Address::new(self.pos.0 + 1);
        Ok(b)
    }

    /// Read a little-endian u16 and advance.
    pub fn read_u16_le(&mut self) -> Result<u16, MemError> {
        let v = read_u16_le(self.provider, self.pos)?;
        self.pos = Address::new(self.pos.0 + 2);
        Ok(v)
    }

    /// Read a little-endian u32 and advance.
    pub fn read_u32_le(&mut self) -> Result<u32, MemError> {
        let v = read_u32_le(self.provider, self.pos)?;
        self.pos = Address::new(self.pos.0 + 4);
        Ok(v)
    }

    /// Read a little-endian u64 and advance.
    pub fn read_u64_le(&mut self) -> Result<u64, MemError> {
        let v = read_u64_le(self.provider, self.pos)?;
        self.pos = Address::new(self.pos.0 + 8);
        Ok(v)
    }

    /// Read a big-endian u32 and advance.
    pub fn read_u32_be(&mut self) -> Result<u32, MemError> {
        let v = read_u32_be(self.provider, self.pos)?;
        self.pos = Address::new(self.pos.0 + 4);
        Ok(v)
    }

    /// Read a big-endian u64 and advance.
    pub fn read_u64_be(&mut self) -> Result<u64, MemError> {
        let v = read_u64_be(self.provider, self.pos)?;
        self.pos = Address::new(self.pos.0 + 8);
        Ok(v)
    }

    /// Read a NUL-terminated C string at the current position and advance
    /// past the NUL terminator.
    pub fn read_cstring(&mut self, max_len: usize) -> Result<String, MemError> {
        let s = read_cstring(self.provider, self.pos, max_len)?;
        self.pos = Address::new(self.pos.0 + s.len() as u64 + 1); // +1 for NUL
        Ok(s)
    }

    /// Peek `len` bytes at the current position *without* advancing.
    pub fn peek(&self, len: usize) -> Result<Vec<u8>, MemError> {
        self.provider.read(self.pos, len)
    }

    /// Peek a u8 at the current position without advancing.
    pub fn peek_u8(&self) -> Result<u8, MemError> {
        read_u8(self.provider, self.pos)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::null_memory::NullMemoryProvider;

    #[test]
    fn read_only_wrapper_blocks_write() {
        let inner = NullMemoryProvider::new();
        let mut ro = ReadOnlyWrapper(inner);
        assert!(ro.write(Address::new(0), &[1, 2, 3]).is_err());
    }

    #[test]
    fn read_only_wrapper_allows_read() {
        let mut inner = NullMemoryProvider::new();
        inner.add_null_region(
            AddressRange::new(Address::new(0), Address::new(0x1000)),
            Permissions::READ,
        );
        let ro = ReadOnlyWrapper(inner);
        let data = ro.read(Address::new(0), 4).unwrap();
        assert_eq!(data, [0u8; 4]);
    }

    #[test]
    fn read_u32_le_from_provider() {
        use crate::file_memory::FileMemoryProvider;
        let data = vec![0x01u8, 0x02, 0x03, 0x04];
        let p = FileMemoryProvider::from_bytes(data, Address::new(0), Permissions::READ);
        let val = read_u32_le(&p, Address::new(0)).unwrap();
        assert_eq!(val, 0x0403_0201);
    }

    #[test]
    fn read_u32_be_from_provider() {
        use crate::file_memory::FileMemoryProvider;
        let data = vec![0x01u8, 0x02, 0x03, 0x04];
        let p = FileMemoryProvider::from_bytes(data, Address::new(0), Permissions::READ);
        let val = read_u32_be(&p, Address::new(0)).unwrap();
        assert_eq!(val, 0x0102_0304);
    }

    #[test]
    fn read_cstring_finds_null_terminator() {
        use crate::file_memory::FileMemoryProvider;
        let data = b"hello\0world".to_vec();
        let p = FileMemoryProvider::from_bytes(data, Address::new(0), Permissions::READ);
        let s = read_cstring(&p, Address::new(0), 64).unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn find_bytes_locates_pattern() {
        use crate::file_memory::FileMemoryProvider;
        let data = vec![0x00u8, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        let p = FileMemoryProvider::from_bytes(data, Address::new(0x1000), Permissions::READ);
        let region = AddressRange::new(Address::new(0x1000), Address::new(0x1006));
        let found = find_bytes(&p, &[0xDE, 0xAD, 0xBE, 0xEF], None, region);
        assert_eq!(found, vec![Address::new(0x1001)]);
    }

    #[test]
    fn find_bytes_wildcard_mask() {
        use crate::file_memory::FileMemoryProvider;
        let data = vec![0xAA, 0xBB, 0xCC, 0xAA, 0xFF, 0xCC];
        let p = FileMemoryProvider::from_bytes(data, Address::new(0), Permissions::READ);
        let region = AddressRange::new(Address::new(0), Address::new(6));
        // pattern: 0xAA ?? 0xCC  (mask 0xFF 0x00 0xFF)
        let found = find_bytes(&p, &[0xAA, 0x00, 0xCC], Some(&[0xFF, 0x00, 0xFF]), region);
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn read_u8_works() {
        use crate::file_memory::FileMemoryProvider;
        let data = vec![0xABu8];
        let p = FileMemoryProvider::from_bytes(data, Address::new(0), Permissions::READ);
        assert_eq!(read_u8(&p, Address::new(0)).unwrap(), 0xAB);
    }

    #[test]
    fn read_u16_be_works() {
        use crate::file_memory::FileMemoryProvider;
        let data = vec![0x01u8, 0x02];
        let p = FileMemoryProvider::from_bytes(data, Address::new(0), Permissions::READ);
        assert_eq!(read_u16_be(&p, Address::new(0)).unwrap(), 0x0102);
    }

    #[test]
    fn read_i8_positive() {
        use crate::file_memory::FileMemoryProvider;
        let p = FileMemoryProvider::from_bytes(vec![42u8], Address::new(0), Permissions::READ);
        assert_eq!(read_i8(&p, Address::new(0)).unwrap(), 42i8);
    }

    #[test]
    fn read_i8_negative() {
        use crate::file_memory::FileMemoryProvider;
        let p = FileMemoryProvider::from_bytes(vec![0xFFu8], Address::new(0), Permissions::READ);
        assert_eq!(read_i8(&p, Address::new(0)).unwrap(), -1i8);
    }

    #[test]
    fn read_i16_le_roundtrip() {
        use crate::file_memory::FileMemoryProvider;
        let val: i16 = -1234;
        let p = FileMemoryProvider::from_bytes(
            val.to_le_bytes().to_vec(),
            Address::new(0),
            Permissions::READ,
        );
        assert_eq!(read_i16_le(&p, Address::new(0)).unwrap(), val);
    }

    #[test]
    fn read_i16_be_roundtrip() {
        use crate::file_memory::FileMemoryProvider;
        let val: i16 = 5678;
        let p = FileMemoryProvider::from_bytes(
            val.to_be_bytes().to_vec(),
            Address::new(0),
            Permissions::READ,
        );
        assert_eq!(read_i16_be(&p, Address::new(0)).unwrap(), val);
    }

    #[test]
    fn read_i32_le_roundtrip() {
        use crate::file_memory::FileMemoryProvider;
        let val: i32 = -987654321;
        let p = FileMemoryProvider::from_bytes(
            val.to_le_bytes().to_vec(),
            Address::new(0),
            Permissions::READ,
        );
        assert_eq!(read_i32_le(&p, Address::new(0)).unwrap(), val);
    }

    #[test]
    fn read_i32_be_roundtrip() {
        use crate::file_memory::FileMemoryProvider;
        let val: i32 = 123456789;
        let p = FileMemoryProvider::from_bytes(
            val.to_be_bytes().to_vec(),
            Address::new(0),
            Permissions::READ,
        );
        assert_eq!(read_i32_be(&p, Address::new(0)).unwrap(), val);
    }

    #[test]
    fn read_i64_le_roundtrip() {
        use crate::file_memory::FileMemoryProvider;
        let val: i64 = -1_234_567_890_123_456;
        let p = FileMemoryProvider::from_bytes(
            val.to_le_bytes().to_vec(),
            Address::new(0),
            Permissions::READ,
        );
        assert_eq!(read_i64_le(&p, Address::new(0)).unwrap(), val);
    }

    #[test]
    fn read_i64_be_roundtrip() {
        use crate::file_memory::FileMemoryProvider;
        let val: i64 = 9_876_543_210_987_654;
        let p = FileMemoryProvider::from_bytes(
            val.to_be_bytes().to_vec(),
            Address::new(0),
            Permissions::READ,
        );
        assert_eq!(read_i64_be(&p, Address::new(0)).unwrap(), val);
    }

    #[test]
    fn read_f32_le_roundtrip() {
        use crate::file_memory::FileMemoryProvider;
        let val: f32 = std::f32::consts::PI;
        let p = FileMemoryProvider::from_bytes(
            val.to_le_bytes().to_vec(),
            Address::new(0),
            Permissions::READ,
        );
        assert!((read_f32_le(&p, Address::new(0)).unwrap() - val).abs() < 1e-6);
    }

    #[test]
    fn read_f64_le_roundtrip() {
        use crate::file_memory::FileMemoryProvider;
        let val: f64 = std::f64::consts::PI;
        let p = FileMemoryProvider::from_bytes(
            val.to_le_bytes().to_vec(),
            Address::new(0),
            Permissions::READ,
        );
        assert!((read_f64_le(&p, Address::new(0)).unwrap() - val).abs() < 1e-12);
    }

    #[test]
    fn read_f32_be_roundtrip() {
        use crate::file_memory::FileMemoryProvider;
        let val: f32 = 1.5f32;
        let p = FileMemoryProvider::from_bytes(
            val.to_be_bytes().to_vec(),
            Address::new(0),
            Permissions::READ,
        );
        assert!((read_f32_be(&p, Address::new(0)).unwrap() - val).abs() < 1e-6);
    }

    #[test]
    fn read_f64_be_roundtrip() {
        use crate::file_memory::FileMemoryProvider;
        let val: f64 = std::f64::consts::E;
        let p = FileMemoryProvider::from_bytes(
            val.to_be_bytes().to_vec(),
            Address::new(0),
            Permissions::READ,
        );
        assert!((read_f64_be(&p, Address::new(0)).unwrap() - val).abs() < 1e-9);
    }

    #[test]
    fn read_array_works() {
        use crate::file_memory::FileMemoryProvider;
        let data = vec![0x01u8, 0x02, 0x03, 0x04, 0x05];
        let p = FileMemoryProvider::from_bytes(data, Address::new(0), Permissions::READ);
        let arr: [u8; 5] = read_array(&p, Address::new(0)).unwrap();
        assert_eq!(arr, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn write_u16_le_roundtrip() {
        use crate::file_memory::FileMemoryProvider;
        let mut p = FileMemoryProvider::from_bytes(
            vec![0u8; 4],
            Address::new(0),
            Permissions::READ | Permissions::WRITE,
        );
        write_u16_le(&mut p, Address::new(0), 0xBEEF).unwrap();
        assert_eq!(read_u16_le(&p, Address::new(0)).unwrap(), 0xBEEF);
    }

    #[test]
    fn write_u32_le_roundtrip() {
        use crate::file_memory::FileMemoryProvider;
        let mut p = FileMemoryProvider::from_bytes(
            vec![0u8; 8],
            Address::new(0),
            Permissions::READ | Permissions::WRITE,
        );
        write_u32_le(&mut p, Address::new(0), 0xDEAD_BEEF).unwrap();
        assert_eq!(read_u32_le(&p, Address::new(0)).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn write_u64_le_roundtrip() {
        use crate::file_memory::FileMemoryProvider;
        let mut p = FileMemoryProvider::from_bytes(
            vec![0u8; 16],
            Address::new(0),
            Permissions::READ | Permissions::WRITE,
        );
        write_u64_le(&mut p, Address::new(0), 0xCAFE_BABE_DEAD_BEEF).unwrap();
        assert_eq!(
            read_u64_le(&p, Address::new(0)).unwrap(),
            0xCAFE_BABE_DEAD_BEEF
        );
    }

    #[test]
    fn write_u64_be_roundtrip() {
        use crate::file_memory::FileMemoryProvider;
        let mut p = FileMemoryProvider::from_bytes(
            vec![0u8; 16],
            Address::new(0),
            Permissions::READ | Permissions::WRITE,
        );
        write_u64_be(&mut p, Address::new(0), 0x1234_5678_9ABC_DEF0).unwrap();
        assert_eq!(
            read_u64_be(&p, Address::new(0)).unwrap(),
            0x1234_5678_9ABC_DEF0
        );
    }

    #[test]
    fn write_u32_be_roundtrip() {
        use crate::file_memory::FileMemoryProvider;
        let mut p = FileMemoryProvider::from_bytes(
            vec![0u8; 8],
            Address::new(0),
            Permissions::READ | Permissions::WRITE,
        );
        write_u32_be(&mut p, Address::new(0), 0x1234_5678).unwrap();
        assert_eq!(read_u32_be(&p, Address::new(0)).unwrap(), 0x1234_5678);
    }

    #[test]
    fn read_wstring_works() {
        use crate::file_memory::FileMemoryProvider;
        // "hi\0" in UTF-16LE
        let data: Vec<u8> = vec![0x68, 0x00, 0x69, 0x00, 0x00, 0x00];
        let p = FileMemoryProvider::from_bytes(data, Address::new(0), Permissions::READ);
        let s = read_wstring(&p, Address::new(0), 64).unwrap();
        assert_eq!(s, "hi");
    }

    #[test]
    fn fill_memory_works() {
        use crate::file_memory::FileMemoryProvider;
        let mut p = FileMemoryProvider::from_bytes(
            vec![0u8; 8],
            Address::new(0),
            Permissions::READ | Permissions::WRITE,
        );
        fill_memory(&mut p, Address::new(0), 8, 0xCC).unwrap();
        let data = p.read(Address::new(0), 8).unwrap();
        assert!(data.iter().all(|&b| b == 0xCC));
    }

    #[test]
    fn copy_memory_works() {
        use crate::file_memory::FileMemoryProvider;
        let mut p = FileMemoryProvider::from_bytes(
            vec![0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x00],
            Address::new(0),
            Permissions::READ | Permissions::WRITE,
        );
        copy_memory(&mut p, Address::new(0), Address::new(3), 3).unwrap();
        let data = p.read(Address::new(3), 3).unwrap();
        assert_eq!(data, [0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn is_mapped_returns_correct_result() {
        use crate::null_memory::NullMemoryProvider;
        let mut null = NullMemoryProvider::new();
        null.add_null_region(
            AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
            Permissions::READ,
        );
        assert!(is_mapped(&null, Address::new(0x1500)));
        assert!(!is_mapped(&null, Address::new(0x5000)));
    }

    #[test]
    fn region_at_finds_correct_region() {
        use crate::null_memory::NullMemoryProvider;
        let mut null = NullMemoryProvider::new();
        null.add_null_region(
            AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
            Permissions::READ,
        );
        let r = region_at(&null, Address::new(0x1500));
        assert!(r.is_some());
        assert_eq!(r.unwrap().range.start, Address::new(0x1000));
    }

    #[test]
    fn total_mapped_bytes_sums_correctly() {
        use crate::null_memory::NullMemoryProvider;
        let mut null = NullMemoryProvider::new();
        null.add_null_region(
            AddressRange::new(Address::new(0), Address::new(0x1000)),
            Permissions::READ,
        );
        null.add_null_region(
            AddressRange::new(Address::new(0x2000), Address::new(0x4000)),
            Permissions::READ,
        );
        assert_eq!(total_mapped_bytes(&null), 0x3000);
    }

    #[test]
    fn region_filter_by_name() {
        use crate::memory_provider::RegionSource;
        use crate::null_memory::NullMemoryProvider;
        let mut null = NullMemoryProvider::new();
        null.add_null_region(
            AddressRange::new(Address::new(0), Address::new(0x1000)),
            Permissions::READ,
        );
        // Manually craft a region with a name to test the filter.
        let regions = vec![
            crate::memory_provider::MemoryRegion {
                range: AddressRange::new(Address::new(0), Address::new(0x1000)),
                perms: Permissions::READ,
                name: Some("libc.so".to_string()),
                source: RegionSource::Anonymous,
            },
            crate::memory_provider::MemoryRegion {
                range: AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
                perms: Permissions::READ | Permissions::WRITE,
                name: Some("heap".to_string()),
                source: RegionSource::Anonymous,
            },
        ];
        let filter = RegionFilter::new().named_contains("libc");
        let result = filter.apply(regions);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name.as_deref(), Some("libc.so"));
    }

    #[test]
    fn region_filter_by_size() {
        use crate::memory_provider::RegionSource;
        let regions = vec![
            crate::memory_provider::MemoryRegion {
                range: AddressRange::new(Address::new(0), Address::new(0x100)),
                perms: Permissions::READ,
                name: None,
                source: RegionSource::Anonymous,
            },
            crate::memory_provider::MemoryRegion {
                range: AddressRange::new(Address::new(0x1000), Address::new(0x3000)),
                perms: Permissions::READ,
                name: None,
                source: RegionSource::Anonymous,
            },
        ];
        let filter = RegionFilter::new().at_least(0x1000);
        let result = filter.apply(regions);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].range.len(), 0x2000);
    }

    #[test]
    fn memory_cursor_sequential_reads() {
        use crate::file_memory::FileMemoryProvider;
        let data: Vec<u8> = vec![
            0x01, 0x02, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];
        let p = FileMemoryProvider::from_bytes(data, Address::new(0), Permissions::READ);
        let mut cursor = MemoryCursor::new(&p, Address::new(0));
        assert_eq!(cursor.read_u8().unwrap(), 0x01);
        assert_eq!(cursor.read_u8().unwrap(), 0x02);
        assert_eq!(cursor.read_u16_le().unwrap(), 0x0003);
        assert_eq!(cursor.read_u32_le().unwrap(), 0x0000_0004);
        assert_eq!(cursor.read_u64_le().unwrap(), 0x0000_0000_0000_0005);
    }

    #[test]
    fn memory_cursor_peek_no_advance() {
        use crate::file_memory::FileMemoryProvider;
        let p = FileMemoryProvider::from_bytes(vec![0xABu8; 8], Address::new(0), Permissions::READ);
        let cursor = MemoryCursor::new(&p, Address::new(0));
        let _ = cursor.peek(4).unwrap();
        assert_eq!(cursor.position(), Address::new(0));
    }

    #[test]
    fn memory_cursor_seek_and_skip() {
        use crate::file_memory::FileMemoryProvider;
        let p = FileMemoryProvider::from_bytes(vec![0u8; 64], Address::new(0), Permissions::READ);
        let mut cursor = MemoryCursor::new(&p, Address::new(0));
        cursor.seek(Address::new(16));
        assert_eq!(cursor.position(), Address::new(16));
        cursor.skip(8);
        assert_eq!(cursor.position(), Address::new(24));
    }

    #[test]
    fn memory_provider_ext_read_u32_le() {
        use crate::file_memory::FileMemoryProvider;
        let data = vec![0x78u8, 0x56, 0x34, 0x12];
        let p = FileMemoryProvider::from_bytes(data, Address::new(0), Permissions::READ);
        assert_eq!(p.read_u32_le(Address::new(0)).unwrap(), 0x1234_5678);
    }

    #[test]
    fn dump_all_regions_collects_data() {
        use crate::file_memory::FileMemoryProvider;
        let data = vec![0xAAu8; 8];
        let p = FileMemoryProvider::from_bytes(data, Address::new(0x1000), Permissions::READ);
        let dump = dump_all_regions(&p);
        assert_eq!(dump.len(), 1);
        let (_, bytes) = dump.iter().next().unwrap();
        assert_eq!(bytes.len(), 8);
        assert!(bytes.iter().all(|&b| b == 0xAA));
    }

    #[test]
    fn find_first_in_all_regions_finds_pattern() {
        use crate::file_memory::FileMemoryProvider;
        let data = vec![0x00u8, 0xDE, 0xAD, 0x00, 0x00, 0x00, 0x00, 0x00];
        let p = FileMemoryProvider::from_bytes(data, Address::new(0x1000), Permissions::READ);
        let result = find_first_in_all_regions(&p, &[0xDE, 0xAD]);
        assert!(result.is_some());
        assert_eq!(result.unwrap().1, Address::new(0x1001));
    }

    #[test]
    fn executable_regions_filters_correctly() {
        use crate::null_memory::NullMemoryProvider;
        let mut null = NullMemoryProvider::new();
        null.add_null_region(
            AddressRange::new(Address::new(0), Address::new(0x1000)),
            Permissions::READ | Permissions::EXECUTE,
        );
        null.add_null_region(
            AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
            Permissions::READ | Permissions::WRITE,
        );
        let exec = executable_regions(&null);
        assert_eq!(exec.len(), 1);
        assert!(exec[0].perms.is_executable());
    }

    #[test]
    fn writable_regions_filters_correctly() {
        use crate::null_memory::NullMemoryProvider;
        let mut null = NullMemoryProvider::new();
        null.add_null_region(
            AddressRange::new(Address::new(0), Address::new(0x1000)),
            Permissions::READ,
        );
        null.add_null_region(
            AddressRange::new(Address::new(0x1000), Address::new(0x2000)),
            Permissions::READ | Permissions::WRITE,
        );
        let writable = writable_regions(&null);
        assert_eq!(writable.len(), 1);
        assert!(writable[0].perms.is_writable());
    }

    #[test]
    fn write_u16_be_roundtrip() {
        use crate::file_memory::FileMemoryProvider;
        let mut p = FileMemoryProvider::from_bytes(
            vec![0u8; 4],
            Address::new(0),
            Permissions::READ | Permissions::WRITE,
        );
        write_u16_be(&mut p, Address::new(0), 0xBEEF).unwrap();
        assert_eq!(read_u16_be(&p, Address::new(0)).unwrap(), 0xBEEF);
    }
}
