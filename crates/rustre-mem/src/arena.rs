//! Memory arena allocator for reverse-engineering use cases.
//!
//! Provides a bump-pointer arena that allocates from a flat byte buffer.
//! Supports alignment requirements, guard bytes, undo (pop) to a saved mark,
//! and optional canary bytes for overflow detection.

use crate::memory_provider::{MemError, MemoryProvider, MemoryRegion, RegionSource, SnapshotId};
use async_trait::async_trait;
use rustre_core::address::{Address, AddressRange};
use rustre_core::permissions::Permissions;

// ─────────────────────────────────────────────────────────────────────────────
// ArenaError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from `MemoryArena` operations.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ArenaError {
    /// Not enough contiguous space in the arena.
    #[error("arena out of memory: requested {requested}, available {available}")]
    OutOfMemory { requested: usize, available: usize },
    /// Requested alignment is not a power of two.
    #[error("invalid alignment: {align} (must be a power of two)")]
    InvalidAlignment { align: usize },
    /// A free / dealloc of an address outside the arena.
    #[error("address 0x{addr:x} not in arena")]
    OutOfBounds { addr: u64 },
    /// Canary bytes were overwritten — heap corruption detected.
    #[error("canary corrupted at arena offset {offset}")]
    CanaryCorrupted { offset: usize },
}

// ─────────────────────────────────────────────────────────────────────────────
// ArenaAlloc — metadata for one allocation
// ─────────────────────────────────────────────────────────────────────────────

/// Metadata about a single allocation within the arena.
#[derive(Debug, Clone)]
pub struct ArenaAlloc {
    /// Byte offset from the arena base.
    pub offset: usize,
    /// Aligned allocation size in bytes (not including canary).
    pub size: usize,
    /// The alignment that was requested.
    pub align: usize,
    /// Optional tag for debugging (e.g., type name or purpose).
    pub tag: Option<String>,
}

impl ArenaAlloc {
    /// Virtual address of this allocation when the arena is mapped at `base`.
    #[must_use]
    pub const fn address(&self, base: Address) -> Address {
        Address::new(base.0 + self.offset as u64)
    }

    /// End offset (exclusive) of this allocation.
    #[must_use]
    pub const fn end_offset(&self) -> usize {
        self.offset + self.size
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArenaStats
// ─────────────────────────────────────────────────────────────────────────────

/// Usage statistics for a `MemoryArena`.
#[derive(Debug, Clone, Default)]
pub struct ArenaStats {
    /// Total capacity of the arena in bytes.
    pub capacity: usize,
    /// Number of bytes currently allocated.
    pub used: usize,
    /// Number of bytes still free.
    pub free: usize,
    /// Total number of allocations performed (includes freed ones).
    pub total_allocations: u64,
    /// Number of live allocations.
    pub live_allocations: usize,
    /// Total bytes wasted to alignment padding.
    pub alignment_waste: usize,
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryArena
// ─────────────────────────────────────────────────────────────────────────────

/// A bump-pointer arena allocator backed by a contiguous byte buffer.
///
/// Allocations are sequential and cannot be individually freed.  The entire
/// arena can be reset or a saved "mark" can be restored.
///
/// When `canary_enabled == true`, each allocation is followed by 4 canary
/// bytes (`0xDE 0xAD 0xC0 0xDE`), and [`MemoryArena::check_canaries`] can
/// verify none have been overwritten.
pub struct MemoryArena {
    /// Backing buffer.
    buf: Vec<u8>,
    /// Bump pointer — next free byte offset.
    cursor: usize,
    /// Base virtual address for the arena (used when acting as a provider).
    base: Address,
    /// Whether canary bytes are appended to each allocation.
    canary_enabled: bool,
    /// Allocation metadata (in order of allocation).
    allocs: Vec<ArenaAlloc>,
    /// Total allocations ever performed.
    total_allocs: u64,
    /// Total alignment waste.
    alignment_waste: usize,
    /// Monotonically increasing generation counter, incremented on every
    /// `reset()`.  Marks from a prior generation are stale and must not be
    /// applied.
    generation: u64,
}

/// The 4-byte canary value appended to each allocation when canaries are on.
const CANARY: [u8; 4] = [0xDE, 0xAD, 0xC0, 0xDE];
/// Size of the canary in bytes.
const CANARY_SIZE: usize = 4;

impl MemoryArena {
    /// Create a new arena of `capacity` bytes, mapped at virtual address `base`.
    #[must_use]
    pub fn new(capacity: usize, base: Address) -> Self {
        Self {
            buf: vec![0u8; capacity],
            cursor: 0,
            base,
            canary_enabled: false,
            allocs: Vec::new(),
            total_allocs: 0,
            alignment_waste: 0,
            generation: 0,
        }
    }

    /// Enable or disable canary bytes after each allocation.
    pub const fn set_canary_enabled(&mut self, enabled: bool) {
        self.canary_enabled = enabled;
    }

    /// Total capacity of the arena in bytes.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Number of bytes currently used (including canaries).
    #[must_use]
    pub const fn used(&self) -> usize {
        self.cursor
    }

    /// Number of bytes still available.
    #[must_use]
    pub const fn available(&self) -> usize {
        self.capacity() - self.cursor
    }

    /// Base virtual address of the arena.
    #[must_use]
    pub const fn base(&self) -> Address {
        self.base
    }

    /// Compute statistics.
    #[must_use]
    pub const fn stats(&self) -> ArenaStats {
        ArenaStats {
            capacity: self.capacity(),
            used: self.cursor,
            free: self.available(),
            total_allocations: self.total_allocs,
            live_allocations: self.allocs.len(),
            alignment_waste: self.alignment_waste,
        }
    }

    /// Save the current bump pointer as a mark.  The mark can be restored with
    /// [`pop_mark`].
    ///
    /// The returned mark becomes invalid after [`reset`] is called.
    #[must_use]
    pub const fn save_mark(&self) -> ArenaMark {
        ArenaMark {
            cursor: self.cursor,
            alloc_count: self.allocs.len(),
            generation: self.generation,
        }
    }

    /// Restore the arena to a saved mark, freeing all allocations made since
    /// the mark was saved.
    ///
    /// # Errors
    /// Returns [`ArenaError::OutOfBounds`] if `mark` is stale (it was created
    /// before a call to [`reset`]).
    pub fn pop_mark(&mut self, mark: ArenaMark) -> Result<(), ArenaError> {
        if mark.generation != self.generation {
            return Err(ArenaError::OutOfBounds {
                addr: mark.cursor as u64,
            });
        }
        if mark.cursor < self.cursor {
            self.buf[mark.cursor..self.cursor].fill(0);
        }
        self.cursor = mark.cursor;
        self.allocs.truncate(mark.alloc_count);
        Ok(())
    }

    /// Reset the entire arena to empty, zeroing the buffer.
    ///
    /// All outstanding [`ArenaMark`]s are invalidated by this call.
    pub fn reset(&mut self) {
        self.buf.fill(0);
        self.cursor = 0;
        self.allocs.clear();
        self.generation = self.generation.wrapping_add(1);
    }

    /// Allocate `size` bytes with `align`-byte alignment, writing `fill` into
    /// each byte.  Returns the virtual address and the arena allocation record.
    ///
    /// # Errors
    /// Returns [`ArenaError::OutOfMemory`] if not enough space is available.
    /// Returns [`ArenaError::InvalidAlignment`] if `align` is not a power of two.
    pub fn alloc_fill(
        &mut self,
        size: usize,
        align: usize,
        fill: u8,
        tag: Option<String>,
    ) -> Result<ArenaAlloc, ArenaError> {
        if align == 0 || !align.is_power_of_two() {
            return Err(ArenaError::InvalidAlignment { align });
        }
        // Align the cursor up to `align`.
        let padding = (align - (self.cursor % align)) % align;
        let aligned_offset = self.cursor.checked_add(padding).ok_or(ArenaError::OutOfMemory {
            requested: size,
            available: 0,
        })?;
        let canary_extra = if self.canary_enabled { CANARY_SIZE } else { 0 };
        let total_needed = aligned_offset
            .checked_add(size)
            .and_then(|v| v.checked_add(canary_extra))
            .ok_or(ArenaError::OutOfMemory {
                requested: size,
                available: self.capacity().saturating_sub(aligned_offset),
            })?;

        if total_needed > self.capacity() {
            return Err(ArenaError::OutOfMemory {
                requested: size,
                available: self.capacity().saturating_sub(aligned_offset),
            });
        }

        // Advance cursor past padding + allocation + optional canary.
        self.alignment_waste += padding;
        self.cursor = aligned_offset;

        // Write fill bytes.
        self.buf[self.cursor..self.cursor + size].fill(fill);
        self.cursor += size;

        // Write canary.
        if self.canary_enabled {
            self.buf[self.cursor..self.cursor + CANARY_SIZE].copy_from_slice(&CANARY);
            self.cursor += CANARY_SIZE;
        }

        let a = ArenaAlloc {
            offset: aligned_offset,
            size,
            align,
            tag,
        };
        self.allocs.push(a.clone());
        self.total_allocs += 1;
        Ok(a)
    }

    /// Allocate `size` zero-filled bytes with `align`-byte alignment.
    ///
    /// # Errors
    /// See [`alloc_fill`].
    pub fn alloc_zeroed(&mut self, size: usize, align: usize) -> Result<ArenaAlloc, ArenaError> {
        self.alloc_fill(size, align, 0, None)
    }

    /// Allocate `size` bytes with 1-byte alignment and write `data` into them.
    ///
    /// # Errors
    /// See [`alloc_fill`].  Returns `Err` if `data.len() != size`.
    pub fn alloc_bytes(&mut self, data: &[u8], align: usize) -> Result<ArenaAlloc, ArenaError> {
        let a = self.alloc_fill(data.len(), align, 0, None)?;
        self.buf[a.offset..a.offset + data.len()].copy_from_slice(data);
        Ok(a)
    }

    /// Read `len` bytes from the arena at virtual `addr`.
    ///
    /// # Errors
    /// Returns `ArenaError::OutOfBounds` if the range is outside the arena.
    pub fn read_at(&self, addr: Address, len: usize) -> Result<Vec<u8>, ArenaError> {
        let offset_u64 = addr
            .0
            .checked_sub(self.base.0)
            .ok_or(ArenaError::OutOfBounds { addr: addr.0 })?;
        let offset = usize::try_from(offset_u64)
            .map_err(|_| ArenaError::OutOfBounds { addr: addr.0 })?;
        let end = offset.checked_add(len).ok_or(ArenaError::OutOfBounds { addr: addr.0 })?;
        if end > self.buf.len() {
            return Err(ArenaError::OutOfBounds { addr: addr.0 });
        }
        Ok(self.buf[offset..end].to_vec())
    }

    /// Write `data` bytes into the arena at virtual `addr`.
    ///
    /// # Errors
    /// Returns `ArenaError::OutOfBounds` if the range is outside the arena.
    pub fn write_at(&mut self, addr: Address, data: &[u8]) -> Result<(), ArenaError> {
        let offset_u64 = addr
            .0
            .checked_sub(self.base.0)
            .ok_or(ArenaError::OutOfBounds { addr: addr.0 })?;
        let offset = usize::try_from(offset_u64)
            .map_err(|_| ArenaError::OutOfBounds { addr: addr.0 })?;
        let end = offset
            .checked_add(data.len())
            .ok_or(ArenaError::OutOfBounds { addr: addr.0 })?;
        if end > self.buf.len() {
            return Err(ArenaError::OutOfBounds { addr: addr.0 });
        }
        self.buf[offset..end].copy_from_slice(data);
        Ok(())
    }

    /// Verify all canaries are intact.  Returns `Ok(())` if all pass or the
    /// first `ArenaError::CanaryCorrupted` found.
    ///
    /// # Errors
    /// Returns [`ArenaError::CanaryCorrupted`] if any canary is overwritten.
    pub fn check_canaries(&self) -> Result<(), ArenaError> {
        if !self.canary_enabled {
            return Ok(());
        }
        for a in &self.allocs {
            let canary_off = a.offset + a.size;
            if canary_off + CANARY_SIZE > self.buf.len() {
                continue;
            }
            if self.buf[canary_off..canary_off + CANARY_SIZE] != CANARY {
                return Err(ArenaError::CanaryCorrupted { offset: canary_off });
            }
        }
        Ok(())
    }

    /// Immutable view of all live allocations.
    #[must_use]
    pub fn allocations(&self) -> &[ArenaAlloc] {
        &self.allocs
    }

    /// Find the allocation that covers virtual address `addr`, if any.
    #[must_use]
    pub fn find_alloc(&self, addr: Address) -> Option<&ArenaAlloc> {
        let offset = addr.0.checked_sub(self.base.0)? as usize;
        self.allocs
            .iter()
            .find(|a| offset >= a.offset && offset < a.offset + a.size)
    }

    /// View the raw arena bytes.
    #[must_use]
    pub fn raw_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Copy the used portion of the arena into a `Vec<u8>`.
    #[must_use]
    pub fn dump(&self) -> Vec<u8> {
        self.buf[..self.cursor].to_vec()
    }
}

impl std::fmt::Debug for MemoryArena {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryArena")
            .field("capacity", &self.capacity())
            .field("used", &self.cursor)
            .field("base", &self.base)
            .field("canary_enabled", &self.canary_enabled)
            .field("alloc_count", &self.allocs.len())
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ArenaMark
// ─────────────────────────────────────────────────────────────────────────────

/// A saved position in the arena, created by [`MemoryArena::save_mark`].
///
/// A mark is invalidated whenever [`MemoryArena::reset`] is called.  Passing
/// a stale mark (from a previous generation) to [`MemoryArena::pop_mark`]
/// returns an error rather than silently corrupting arena state.
#[derive(Debug, Clone, Copy)]
pub struct ArenaMark {
    cursor: usize,
    alloc_count: usize,
    /// Generation of the arena at the time the mark was saved.
    generation: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// MemoryArena as MemoryProvider
// ─────────────────────────────────────────────────────────────────────────────

/// The arena can act as a `MemoryProvider`, serving reads from its buffer and
/// writes back into it.
#[async_trait]
impl MemoryProvider for MemoryArena {
    fn read(&self, addr: Address, len: usize) -> Result<Vec<u8>, MemError> {
        self.read_at(addr, len)
            .map_err(|_| MemError::OutOfBounds(addr, len))
    }

    fn write(&mut self, addr: Address, data: &[u8]) -> Result<(), MemError> {
        self.write_at(addr, data)
            .map_err(|_| MemError::OutOfBounds(addr, data.len()))
    }

    fn regions(&self) -> Vec<MemoryRegion> {
        vec![MemoryRegion {
            range: AddressRange::new(
                self.base,
                Address::new(self.base.0 + self.capacity() as u64),
            ),
            perms: Permissions::READ | Permissions::WRITE,
            name: Some("arena".to_string()),
            source: RegionSource::Anonymous,
        }]
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

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn arena(capacity: usize) -> MemoryArena {
        MemoryArena::new(capacity, Address::new(0x1000_0000))
    }

    // ── Basic alloc / read ───────────────────────────────────────────────────

    #[test]
    fn test_alloc_zeroed() {
        let mut a = arena(0x1000);
        let alloc = a.alloc_zeroed(16, 1).unwrap();
        assert_eq!(alloc.size, 16);
        assert_eq!(alloc.offset, 0);
        let data = a.read_at(alloc.address(a.base()), 16).unwrap();
        assert_eq!(data, vec![0u8; 16]);
    }

    #[test]
    fn test_alloc_bytes() {
        let mut a = arena(0x1000);
        let payload = b"hello";
        let alloc = a.alloc_bytes(payload, 1).unwrap();
        let data = a.read_at(alloc.address(a.base()), 5).unwrap();
        assert_eq!(data, payload);
    }

    #[test]
    fn test_alloc_fill() {
        let mut a = arena(0x1000);
        let alloc = a.alloc_fill(8, 1, 0xCC, Some("test".into())).unwrap();
        let data = a.read_at(alloc.address(a.base()), 8).unwrap();
        assert_eq!(data, vec![0xCCu8; 8]);
        assert_eq!(alloc.tag.as_deref(), Some("test"));
    }

    // ── Alignment ────────────────────────────────────────────────────────────

    #[test]
    fn test_alloc_alignment() {
        let mut a = arena(0x1000);
        // Allocate 1 byte, then 4-byte aligned → padding of 3 bytes
        a.alloc_zeroed(1, 1).unwrap();
        let alloc = a.alloc_zeroed(4, 4).unwrap();
        assert_eq!(alloc.offset % 4, 0, "offset must be 4-aligned");
    }

    #[test]
    fn test_alloc_invalid_alignment() {
        let mut a = arena(0x1000);
        let err = a.alloc_zeroed(4, 3).unwrap_err();
        assert!(matches!(err, ArenaError::InvalidAlignment { .. }));
    }

    #[test]
    fn test_alloc_zero_alignment_invalid() {
        let mut a = arena(0x1000);
        assert!(a.alloc_zeroed(4, 0).is_err());
    }

    // ── Out-of-memory ────────────────────────────────────────────────────────

    #[test]
    fn test_alloc_oom() {
        let mut a = arena(8);
        let err = a.alloc_zeroed(16, 1).unwrap_err();
        assert!(matches!(err, ArenaError::OutOfMemory { .. }));
    }

    #[test]
    fn test_alloc_exactly_full() {
        let mut a = arena(8);
        a.alloc_zeroed(8, 1).unwrap();
        assert_eq!(a.available(), 0);
        assert!(a.alloc_zeroed(1, 1).is_err());
    }

    // ── Reset / marks ────────────────────────────────────────────────────────

    #[test]
    fn test_reset_clears_arena() {
        let mut a = arena(0x1000);
        a.alloc_bytes(b"data", 1).unwrap();
        a.reset();
        assert_eq!(a.used(), 0);
        assert!(a.allocations().is_empty());
    }

    #[test]
    fn test_save_pop_mark() {
        let mut a = arena(0x1000);
        a.alloc_zeroed(64, 1).unwrap();
        let mark = a.save_mark();
        a.alloc_zeroed(128, 1).unwrap();
        assert_eq!(a.allocations().len(), 2);
        a.pop_mark(mark).unwrap();
        assert_eq!(a.allocations().len(), 1);
        assert_eq!(a.used(), 64);
    }

    // ── Canaries ─────────────────────────────────────────────────────────────

    #[test]
    fn test_canaries_intact() {
        let mut a = arena(0x1000);
        a.set_canary_enabled(true);
        a.alloc_zeroed(16, 1).unwrap();
        a.alloc_zeroed(8, 1).unwrap();
        assert!(a.check_canaries().is_ok());
    }

    #[test]
    fn test_canary_corruption_detected() {
        let mut a = arena(0x1000);
        a.set_canary_enabled(true);
        let alloc = a.alloc_zeroed(16, 1).unwrap();
        // Overwrite the canary bytes directly.
        let canary_addr = Address::new(a.base().0 + (alloc.offset + 16) as u64);
        a.write_at(canary_addr, &[0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
        assert!(matches!(
            a.check_canaries(),
            Err(ArenaError::CanaryCorrupted { .. })
        ));
    }

    // ── find_alloc ────────────────────────────────────────────────────────────

    #[test]
    fn test_find_alloc_hit() {
        let mut a = arena(0x1000);
        let alloc = a.alloc_zeroed(32, 8).unwrap();
        let mid = Address::new(a.base().0 + alloc.offset as u64 + 10);
        assert!(a.find_alloc(mid).is_some());
    }

    #[test]
    fn test_find_alloc_miss() {
        let mut a = arena(0x1000);
        a.alloc_zeroed(32, 1).unwrap();
        // Address well outside the arena
        let far = Address::new(0xDEAD_BEEF);
        assert!(a.find_alloc(far).is_none());
    }

    // ── MemoryProvider impl ───────────────────────────────────────────────────

    #[test]
    fn test_arena_as_provider_read_write() {
        let mut a = arena(0x1000);
        a.alloc_zeroed(64, 1).unwrap();
        a.write(a.base(), &[1, 2, 3, 4]).unwrap();
        let data = a.read(a.base(), 4).unwrap();
        assert_eq!(data, [1, 2, 3, 4]);
    }

    #[test]
    fn test_arena_as_provider_regions() {
        let a = arena(0x200);
        let regions = a.regions();
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].range.start.0, 0x1000_0000);
        assert_eq!(regions[0].range.end.0, 0x1000_0200);
    }

    #[test]
    fn test_arena_read_out_of_bounds() {
        let a = arena(0x100);
        // Try reading beyond the arena capacity.
        let result = a.read(Address::new(0x1000_0200), 4);
        assert!(result.is_err());
    }

    // ── Stats ─────────────────────────────────────────────────────────────────

    #[test]
    fn test_arena_stats() {
        let mut a = arena(0x1000);
        a.alloc_zeroed(64, 8).unwrap();
        let s = a.stats();
        assert_eq!(s.capacity, 0x1000);
        assert_eq!(s.live_allocations, 1);
        assert_eq!(s.total_allocations, 1);
    }

    #[test]
    fn test_arena_stats_alignment_waste() {
        let mut a = arena(0x1000);
        a.alloc_zeroed(3, 1).unwrap(); // cursor = 3
        a.alloc_zeroed(4, 8).unwrap(); // pads 5 bytes to reach offset 8
        assert_eq!(a.stats().alignment_waste, 5);
    }

    // ── Dump ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_arena_dump() {
        let mut a = arena(0x1000);
        a.alloc_bytes(b"ABC", 1).unwrap();
        let dump = a.dump();
        assert_eq!(dump.len(), 3);
        assert_eq!(&dump, b"ABC");
    }

    // ── ArenaMark cursor position ─────────────────────────────────────────────

    #[test]
    fn test_arena_mark_cursor_position() {
        let mut a = arena(0x1000);
        a.alloc_zeroed(10, 1).unwrap();
        let mark = a.save_mark();
        a.alloc_zeroed(20, 1).unwrap();
        a.pop_mark(mark).unwrap();
        // Buffer at offset 10..30 should be zeroed out
        let data = a.read_at(Address::new(a.base().0 + 10), 20).unwrap();
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_arena_alloc_address() {
        let mut a = arena(0x1000);
        let alloc = a.alloc_zeroed(8, 1).unwrap();
        let expected = Address::new(a.base().0 + alloc.offset as u64);
        assert_eq!(alloc.address(a.base()), expected);
    }

    #[test]
    fn test_arena_write_out_of_bounds() {
        let mut a = arena(0x10);
        let result = a.write_at(Address::new(a.base().0 + 0x20), &[1, 2, 3]);
        assert!(matches!(result, Err(ArenaError::OutOfBounds { .. })));
    }
}
