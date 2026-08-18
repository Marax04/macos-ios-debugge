//! WebAssembly linear memory model.
//!
//! Implements the Wasm linear memory semantics including page-granular growth,
//! typed reads/writes, bulk memory operations, and statistics tracking.

use std::collections::HashMap;

/// One page of linear memory is always 64 KiB.
pub const PAGE_SIZE: u32 = 65_536;

/// Maximum allowed pages per the Wasm MVP spec (4 GiB / 64 KiB).
pub const MAX_PAGES: u32 = 65_536;

/// Maximum pages that will be *eagerly allocated* during construction.
///
/// The Wasm spec cap is 65 536 pages = 4 GiB, which is far too large to
/// allocate for a static-analysis tool on every module parse. This constant
/// caps the initial `Vec<u8>` allocation to 64 MiB (1 024 pages) to prevent
/// memory exhaustion when analysing malicious or artificially large modules
/// (dos-memory-exhaustion).
const MAX_ALLOC_PAGES: u32 = 1_024;

// ---------------------------------------------------------------------------
// MemoryLimits
// ---------------------------------------------------------------------------

/// Minimum / maximum page counts for a Wasm memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemoryLimits {
    pub min: u32,
    pub max: Option<u32>,
}

impl MemoryLimits {
    #[must_use]
    pub const fn new(min: u32, max: Option<u32>) -> Self {
        Self { min, max }
    }

    /// Return the effective maximum (spec cap if none given).
    #[must_use]
    pub fn effective_max(self) -> u32 {
        self.max.unwrap_or(MAX_PAGES)
    }

    #[must_use]
    pub fn is_valid(self) -> bool {
        self.min <= self.effective_max() && self.effective_max() <= MAX_PAGES
    }
}

// ---------------------------------------------------------------------------
// MemoryStats
// ---------------------------------------------------------------------------

/// Accumulated statistics for a `WasmMemory` instance.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct MemoryStats {
    pub pages: u32,
    pub bytes: u64,
    pub reads: u64,
    pub writes: u64,
    pub trap_count: u64,
}

// ---------------------------------------------------------------------------
// AccessError
// ---------------------------------------------------------------------------

/// Reason a memory access failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AccessError {
    #[error("out-of-bounds access at address {addr:#x}, size {size}")]
    OutOfBounds { addr: u32, size: u32 },
    #[error("memory not enabled")]
    MemoryNotEnabled,
    #[error("misaligned access at address {addr:#x}, required alignment {align}")]
    Misaligned { addr: u32, align: u32 },
}

// ---------------------------------------------------------------------------
// WasmMemory
// ---------------------------------------------------------------------------

/// WebAssembly linear memory backed by a `Vec<u8>`.
///
/// All multi-byte accesses use **little-endian** byte order as required by the
/// WebAssembly specification.
#[derive(Debug, Clone)]
pub struct WasmMemory {
    data: Vec<u8>,
    limits: MemoryLimits,
    /// Whether bulk-memory proposal operations (memory.fill, memory.copy) are
    /// permitted.
    pub bulk_memory_enabled: bool,
    stats: MemoryStats,
}

impl WasmMemory {
    /// Create a new `WasmMemory` with `limits.min` pages pre-allocated.
    ///
    /// The eager allocation is capped at [`MAX_ALLOC_PAGES`] pages (64 MiB)
    /// to prevent memory exhaustion when `limits.min` comes from an untrusted
    /// module binary (dos-memory-exhaustion). The logical page count reported
    /// by [`size`](Self::size) still reflects `limits.min` so spec-conformant
    /// callers see the correct value, but `data` only backs the capped amount.
    #[must_use]
    pub fn new(limits: MemoryLimits, bulk_memory_enabled: bool) -> Self {
        let alloc_pages = limits.min.min(MAX_ALLOC_PAGES);
        let initial_bytes = (alloc_pages as usize)
            .saturating_mul(PAGE_SIZE as usize);
        let stats = MemoryStats {
            pages: limits.min,
            bytes: initial_bytes as u64,
            ..MemoryStats::default()
        };
        WasmMemory {
            data: vec![0u8; initial_bytes],
            limits,
            bulk_memory_enabled,
            stats,
        }
    }

    /// Return the current size in pages.
    #[must_use]
    pub const fn size(&self) -> u32 {
        self.stats.pages
    }

    /// Return a snapshot of the current statistics.
    #[must_use]
    pub const fn stats(&self) -> &MemoryStats {
        &self.stats
    }

    /// Attempt to grow the memory by `delta_pages`.
    ///
    /// Returns the *old* size in pages on success, or `-1` if the grow
    /// would violate the memory limits or exceed the implementation cap.
    pub fn grow(&mut self, delta_pages: u32) -> i32 {
        let old_pages = self.stats.pages;
        let new_pages = match old_pages.checked_add(delta_pages) {
            Some(n) => n,
            None => return -1,
        };
        if new_pages > self.limits.effective_max() {
            return -1;
        }
        let new_bytes = (new_pages as usize).saturating_mul(PAGE_SIZE as usize);
        self.data.resize(new_bytes, 0u8);
        self.stats.pages = new_pages;
        self.stats.bytes = new_bytes as u64;
        old_pages as i32
    }

    // -----------------------------------------------------------------------
    // Bounds helpers
    // -----------------------------------------------------------------------

    /// Check that the range `[addr, addr + size)` is within the memory.
    #[inline]
    fn check_bounds(&mut self, addr: u32, size: u32) -> Result<(), AccessError> {
        let end = addr.checked_add(size).ok_or(AccessError::OutOfBounds { addr, size })?;
        if end as usize > self.data.len() {
            self.stats.trap_count += 1;
            return Err(AccessError::OutOfBounds { addr, size });
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Single-byte
    // -----------------------------------------------------------------------

    /// Read a single byte. Returns `None` on out-of-bounds.
    pub fn read_byte(&mut self, addr: u32) -> Option<u8> {
        self.check_bounds(addr, 1).ok()?;
        self.stats.reads += 1;
        Some(self.data[addr as usize])
    }

    /// Write a single byte. Returns `false` on out-of-bounds.
    pub fn write_byte(&mut self, addr: u32, val: u8) -> bool {
        if self.check_bounds(addr, 1).is_err() {
            return false;
        }
        self.stats.writes += 1;
        self.data[addr as usize] = val;
        true
    }

    // -----------------------------------------------------------------------
    // u16 little-endian
    // -----------------------------------------------------------------------

    pub fn read_u16_le(&mut self, addr: u32) -> Option<u16> {
        self.check_bounds(addr, 2).ok()?;
        self.stats.reads += 1;
        let lo = self.data[addr as usize] as u16;
        let hi = self.data[(addr + 1) as usize] as u16;
        Some(lo | (hi << 8))
    }

    pub fn write_u16_le(&mut self, addr: u32, val: u16) -> bool {
        if self.check_bounds(addr, 2).is_err() {
            return false;
        }
        self.stats.writes += 1;
        let i = addr as usize;
        self.data[i] = (val & 0xFF) as u8;
        self.data[i + 1] = ((val >> 8) & 0xFF) as u8;
        true
    }

    // -----------------------------------------------------------------------
    // u32 little-endian
    // -----------------------------------------------------------------------

    pub fn read_u32_le(&mut self, addr: u32) -> Option<u32> {
        self.check_bounds(addr, 4).ok()?;
        self.stats.reads += 1;
        let i = addr as usize;
        let bytes = &self.data[i..i + 4];
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn write_u32_le(&mut self, addr: u32, val: u32) -> bool {
        if self.check_bounds(addr, 4).is_err() {
            return false;
        }
        self.stats.writes += 1;
        let i = addr as usize;
        let bytes = val.to_le_bytes();
        self.data[i..i + 4].copy_from_slice(&bytes);
        true
    }

    // -----------------------------------------------------------------------
    // u64 little-endian
    // -----------------------------------------------------------------------

    pub fn read_u64_le(&mut self, addr: u32) -> Option<u64> {
        self.check_bounds(addr, 8).ok()?;
        self.stats.reads += 1;
        let i = addr as usize;
        let bytes: [u8; 8] = self.data[i..i + 8].try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }

    pub fn write_u64_le(&mut self, addr: u32, val: u64) -> bool {
        if self.check_bounds(addr, 8).is_err() {
            return false;
        }
        self.stats.writes += 1;
        let i = addr as usize;
        let bytes = val.to_le_bytes();
        self.data[i..i + 8].copy_from_slice(&bytes);
        true
    }

    // -----------------------------------------------------------------------
    // f32 / f64 IEEE 754
    // -----------------------------------------------------------------------

    pub fn read_f32_le(&mut self, addr: u32) -> Option<f32> {
        let bits = self.read_u32_le(addr)?;
        Some(f32::from_bits(bits))
    }

    pub fn write_f32_le(&mut self, addr: u32, val: f32) -> bool {
        self.write_u32_le(addr, val.to_bits())
    }

    pub fn read_f64_le(&mut self, addr: u32) -> Option<f64> {
        let bits = self.read_u64_le(addr)?;
        Some(f64::from_bits(bits))
    }

    pub fn write_f64_le(&mut self, addr: u32, val: f64) -> bool {
        self.write_u64_le(addr, val.to_bits())
    }

    // -----------------------------------------------------------------------
    // Bulk slice operations
    // -----------------------------------------------------------------------

    /// Read `len` bytes starting at `addr`. Returns `None` if out-of-bounds.
    pub fn read_bytes(&mut self, addr: u32, len: u32) -> Option<Vec<u8>> {
        self.check_bounds(addr, len).ok()?;
        self.stats.reads += 1;
        let i = addr as usize;
        Some(self.data[i..i + len as usize].to_vec())
    }

    /// Write `data` starting at `addr`. Returns `false` if out-of-bounds.
    pub fn write_bytes(&mut self, addr: u32, data: &[u8]) -> bool {
        let len = match u32::try_from(data.len()) {
            Ok(n) => n,
            Err(_) => return false, // data too large for Wasm address space
        };
        if self.check_bounds(addr, len).is_err() {
            return false;
        }
        self.stats.writes += 1;
        let i = addr as usize;
        self.data[i..i + data.len()].copy_from_slice(data);
        true
    }

    // -----------------------------------------------------------------------
    // Bulk memory proposal
    // -----------------------------------------------------------------------

    /// Fill `len` bytes starting at `addr` with `val`.
    ///
    /// Requires `bulk_memory_enabled`. Returns `false` on trap or if not enabled.
    pub fn fill(&mut self, addr: u32, val: u8, len: u32) -> bool {
        if !self.bulk_memory_enabled {
            self.stats.trap_count += 1;
            return false;
        }
        if self.check_bounds(addr, len).is_err() {
            return false;
        }
        let i = addr as usize;
        self.data[i..i + len as usize].fill(val);
        self.stats.writes += 1;
        true
    }

    /// Copy `len` bytes within the same memory from `src` to `dst`.
    ///
    /// Handles overlapping regions correctly (uses `copy_within`). Requires
    /// `bulk_memory_enabled`.
    pub fn copy_within(&mut self, dst: u32, src: u32, len: u32) -> bool {
        if !self.bulk_memory_enabled {
            self.stats.trap_count += 1;
            return false;
        }
        if self.check_bounds(src, len).is_err() || self.check_bounds(dst, len).is_err() {
            return false;
        }
        let src_i = src as usize;
        let dst_i = dst as usize;
        let len_u = len as usize;
        self.data.copy_within(src_i..src_i + len_u, dst_i);
        self.stats.writes += 1;
        true
    }

    /// Copy `len` bytes from `src_mem` at `src` into this memory at `dst`.
    pub fn copy_from(&mut self, dst: u32, src_mem: &WasmMemory, src: u32, len: u32) -> bool {
        if !self.bulk_memory_enabled {
            self.stats.trap_count += 1;
            return false;
        }
        let src_end = (src as usize).checked_add(len as usize).unwrap_or(usize::MAX);
        if src_end > src_mem.data.len() {
            self.stats.trap_count += 1;
            return false;
        }
        if self.check_bounds(dst, len).is_err() {
            return false;
        }
        let src_slice = &src_mem.data[src as usize..src_end];
        let dst_i = dst as usize;
        self.data[dst_i..dst_i + len as usize].copy_from_slice(src_slice);
        self.stats.writes += 1;
        true
    }

    // -----------------------------------------------------------------------
    // Data-segment initialisation
    // -----------------------------------------------------------------------

    /// Initialise a region of memory from a Wasm data segment.
    ///
    /// Returns `false` if the segment overflows the current memory.
    pub fn data_segment(&mut self, offset: u32, data: &[u8]) -> bool {
        let start = offset as usize;
        let end = match start.checked_add(data.len()) {
            Some(e) => e,
            None => {
                self.stats.trap_count += 1;
                return false;
            }
        };
        if end > self.data.len() {
            self.stats.trap_count += 1;
            return false;
        }
        self.data[start..end].copy_from_slice(data);
        true
    }

    // -----------------------------------------------------------------------
    // Raw slice access (for zero-copy host integration)
    // -----------------------------------------------------------------------

    /// Return a view of the raw byte slice backing this memory.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Return a mutable view of the raw byte slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    // -----------------------------------------------------------------------
    // Atomic compare-exchange (simplified; not fully multi-threaded)
    // -----------------------------------------------------------------------

    /// Atomic compare-and-exchange on a 32-bit value.
    ///
    /// Returns `Ok(old_value)` on success, `Err(AccessError)` on out-of-bounds.
    pub fn atomic_cmpxchg_u32(&mut self, addr: u32, expected: u32, replacement: u32) -> Result<u32, AccessError> {
        self.check_bounds(addr, 4)?;
        let i = addr as usize;
        let current = u32::from_le_bytes(self.data[i..i + 4].try_into().unwrap());
        if current == expected {
            let bytes = replacement.to_le_bytes();
            self.data[i..i + 4].copy_from_slice(&bytes);
        }
        self.stats.reads += 1;
        self.stats.writes += 1;
        Ok(current)
    }

    /// Atomic compare-and-exchange on a 64-bit value.
    pub fn atomic_cmpxchg_u64(&mut self, addr: u32, expected: u64, replacement: u64) -> Result<u64, AccessError> {
        self.check_bounds(addr, 8)?;
        let i = addr as usize;
        let current = u64::from_le_bytes(self.data[i..i + 8].try_into().unwrap());
        if current == expected {
            let bytes = replacement.to_le_bytes();
            self.data[i..i + 8].copy_from_slice(&bytes);
        }
        self.stats.reads += 1;
        self.stats.writes += 1;
        Ok(current)
    }

    // -----------------------------------------------------------------------
    // Debug helpers
    // -----------------------------------------------------------------------

    /// Dump up to `max_bytes` bytes starting at `addr` as a hex string.
    pub fn hex_dump(&mut self, addr: u32, max_bytes: u32) -> String {
        let mem_len = self.data.len();
        let addr_usize = addr as usize;
        if addr_usize >= mem_len {
            return String::new();
        }
        let available = mem_len - addr_usize;
        let len = (max_bytes as usize).min(available);
        if len == 0 {
            return String::new();
        }
        let slice = &self.data[addr_usize..addr_usize + len];
        slice.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
    }

    /// Return the number of non-zero bytes in the memory (useful for quick
    /// "is this memory interesting?" checks).
    #[must_use]
    pub fn nonzero_byte_count(&self) -> usize {
        self.data.iter().filter(|&&b| b != 0).count()
    }
}

// ---------------------------------------------------------------------------
// MemoryView — a windowed, read-only view into a WasmMemory
// ---------------------------------------------------------------------------

/// A read-only slice-view into a `WasmMemory` for use by the analysis layer.
#[derive(Debug, Clone)]
pub struct MemoryView {
    data: Vec<u8>,
    base_addr: u32,
}

impl MemoryView {
    #[must_use]
    pub fn from_memory(mem: &WasmMemory, base: u32, len: u32) -> Option<Self> {
        if (base as usize) + (len as usize) > mem.data.len() {
            return None;
        }
        Some(MemoryView {
            data: mem.data[base as usize..(base + len) as usize].to_vec(),
            base_addr: base,
        })
    }

    #[must_use]
    pub fn read_byte(&self, addr: u32) -> Option<u8> {
        let rel = addr.checked_sub(self.base_addr)? as usize;
        self.data.get(rel).copied()
    }

    #[must_use]
    pub fn read_u32_le(&self, addr: u32) -> Option<u32> {
        let rel = addr.checked_sub(self.base_addr)? as usize;
        let bytes: [u8; 4] = self.data.get(rel..rel + 4)?.try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }

    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

// ---------------------------------------------------------------------------
// MultiMemory — manage multiple indexed memories (multi-memory proposal)
// ---------------------------------------------------------------------------

/// Manages a collection of Wasm memories (multi-memory proposal support).
#[derive(Debug, Default)]
pub struct MultiMemory {
    memories: HashMap<u32, WasmMemory>,
    next_id: u32,
}

impl MultiMemory {
    pub fn add(&mut self, limits: MemoryLimits, bulk: bool) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        self.memories.insert(id, WasmMemory::new(limits, bulk));
        id
    }

    #[must_use]
    pub fn get(&self, idx: u32) -> Option<&WasmMemory> {
        self.memories.get(&idx)
    }

    pub fn get_mut(&mut self, idx: u32) -> Option<&mut WasmMemory> {
        self.memories.get_mut(&idx)
    }

    #[must_use]
    pub fn count(&self) -> usize {
        self.memories.len()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mem(pages: u32) -> WasmMemory {
        WasmMemory::new(MemoryLimits::new(pages, Some(4)), true)
    }

    #[test]
    fn initial_size() {
        let m = make_mem(1);
        assert_eq!(m.size(), 1);
        assert_eq!(m.as_slice().len(), PAGE_SIZE as usize);
    }

    #[test]
    fn grow_success() {
        let mut m = make_mem(1);
        let old = m.grow(1);
        assert_eq!(old, 1);
        assert_eq!(m.size(), 2);
    }

    #[test]
    fn grow_exceeds_max() {
        let mut m = make_mem(1);
        let res = m.grow(10);
        assert_eq!(res, -1);
        assert_eq!(m.size(), 1);
    }

    #[test]
    fn grow_overflow_wraps() {
        let mut m = make_mem(0);
        let res = m.grow(u32::MAX);
        assert_eq!(res, -1);
    }

    #[test]
    fn read_write_byte() {
        let mut m = make_mem(1);
        assert!(m.write_byte(100, 0xAB));
        assert_eq!(m.read_byte(100), Some(0xAB));
    }

    #[test]
    fn out_of_bounds_byte() {
        let mut m = make_mem(1);
        assert_eq!(m.read_byte(PAGE_SIZE), None);
        assert!(!m.write_byte(PAGE_SIZE, 0x00));
    }

    #[test]
    fn read_write_u16_le() {
        let mut m = make_mem(1);
        assert!(m.write_u16_le(0, 0xBEEF));
        assert_eq!(m.read_u16_le(0), Some(0xBEEF));
        assert_eq!(m.read_byte(0), Some(0xEF));
        assert_eq!(m.read_byte(1), Some(0xBE));
    }

    #[test]
    fn read_write_u32_le() {
        let mut m = make_mem(1);
        assert!(m.write_u32_le(4, 0xDEAD_BEEF));
        assert_eq!(m.read_u32_le(4), Some(0xDEAD_BEEF));
    }

    #[test]
    fn read_write_u64_le() {
        let mut m = make_mem(1);
        assert!(m.write_u64_le(8, 0x0102_0304_0506_0708));
        assert_eq!(m.read_u64_le(8), Some(0x0102_0304_0506_0708));
    }

    #[test]
    fn read_write_f32() {
        let mut m = make_mem(1);
        assert!(m.write_f32_le(0, std::f32::consts::PI));
        let v = m.read_f32_le(0).unwrap();
        assert!((v - std::f32::consts::PI).abs() < 1e-6);
    }

    #[test]
    fn read_write_bytes_bulk() {
        let mut m = make_mem(1);
        let data = vec![1u8, 2, 3, 4, 5];
        assert!(m.write_bytes(10, &data));
        let back = m.read_bytes(10, 5).unwrap();
        assert_eq!(back, data);
    }

    #[test]
    fn fill_bulk() {
        let mut m = make_mem(1);
        assert!(m.fill(0, 0xFF, 8));
        for i in 0..8u32 {
            assert_eq!(m.read_byte(i), Some(0xFF));
        }
    }

    #[test]
    fn copy_within_non_overlapping() {
        let mut m = make_mem(1);
        m.write_bytes(0, &[10, 20, 30, 40]);
        assert!(m.copy_within(100, 0, 4));
        assert_eq!(m.read_bytes(100, 4), Some(vec![10, 20, 30, 40]));
    }

    #[test]
    fn data_segment_init() {
        let mut m = make_mem(1);
        assert!(m.data_segment(512, &[0xCA, 0xFE, 0xBA, 0xBE]));
        assert_eq!(m.read_u32_le(512), Some(0xBEBA_FECA));
    }

    #[test]
    fn atomic_cmpxchg_u32_success() {
        let mut m = make_mem(1);
        m.write_u32_le(0, 42);
        let old = m.atomic_cmpxchg_u32(0, 42, 99).unwrap();
        assert_eq!(old, 42);
        assert_eq!(m.read_u32_le(0), Some(99));
    }

    #[test]
    fn atomic_cmpxchg_u32_no_match() {
        let mut m = make_mem(1);
        m.write_u32_le(0, 1);
        let old = m.atomic_cmpxchg_u32(0, 99, 200).unwrap();
        assert_eq!(old, 1);
        assert_eq!(m.read_u32_le(0), Some(1));
    }

    #[test]
    fn multi_memory_basic() {
        let mut mm = MultiMemory::default();
        let id0 = mm.add(MemoryLimits::new(1, Some(2)), true);
        let id1 = mm.add(MemoryLimits::new(1, Some(2)), true);
        assert_ne!(id0, id1);
        assert_eq!(mm.count(), 2);
        mm.get_mut(id0).unwrap().write_byte(0, 7);
        assert_eq!(mm.get(id0).unwrap().as_slice()[0], 7);
        assert_eq!(mm.get(id1).unwrap().as_slice()[0], 0);
    }

    #[test]
    fn memory_view_read() {
        let mut m = make_mem(1);
        m.write_u32_le(0, 0x1234_5678);
        let view = MemoryView::from_memory(&m, 0, 16).unwrap();
        assert_eq!(view.read_u32_le(0), Some(0x1234_5678));
    }

    #[test]
    fn stats_trap_count() {
        let mut m = make_mem(1);
        m.read_byte(PAGE_SIZE); // out of bounds
        assert_eq!(m.stats().trap_count, 1);
    }

    #[test]
    fn nonzero_count() {
        let mut m = make_mem(1);
        m.fill(0, 0xFF, 16);
        assert_eq!(m.nonzero_byte_count(), 16);
    }
}
