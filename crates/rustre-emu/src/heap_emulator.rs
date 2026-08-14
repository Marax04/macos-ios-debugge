//! `heap_emulator` — dlmalloc-compatible heap emulator for use inside the emulator.
//!
//! Implements malloc/free/realloc/calloc in Rust, hooks calls from emulated code
//! to these functions, tracks all live allocations, and detects heap corruptions
//! (double-free, use-after-free, buffer overflow via canary words).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

// ─── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum HeapError {
    #[error("out of memory: requested {0:#x} bytes")]
    OutOfMemory(u64),
    #[error("double-free at address {0:#x}")]
    DoubleFree(u64),
    #[error("use-after-free at address {0:#x}")]
    UseAfterFree(u64),
    #[error("buffer overflow detected at {0:#x}: canary corrupted")]
    BufferOverflow(u64),
    #[error("invalid free of untracked address {0:#x}")]
    InvalidFree(u64),
    #[error("heap corruption at {0:#x}: {1}")]
    Corruption(u64, String),
    #[error("realloc of freed block at {0:#x}")]
    ReallocFreed(u64),
    #[error("size too large: {0:#x}")]
    SizeTooLarge(u64),
}

// ─── Canary ───────────────────────────────────────────────────────────────────

/// Canary value placed at start and end of each allocation's metadata.
const CANARY_MAGIC: u64 = 0xDEAD_BEEF_CAFE_BABE;
const HEADER_CANARY_OFFSET: usize = 0;
const MAX_ALLOC_SIZE: u64 = 1 << 30; // 1 GiB sanity limit

// ─── Heap Block ───────────────────────────────────────────────────────────────

/// State of a heap block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockState {
    Free,
    Allocated,
    Freed, // Was allocated, then freed (helps UAF detection)
}

/// Metadata for a single heap allocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapBlock {
    /// User-visible pointer (base of user data, after header).
    pub user_ptr: u64,
    /// Total chunk size including header and footer canaries.
    pub chunk_size: u64,
    /// Requested size (what `malloc()` was called with).
    pub requested_size: u64,
    pub state: BlockState,
    /// Stack trace at allocation time (simulated as instruction addresses).
    pub alloc_trace: Vec<u64>,
    /// Stack trace at free time (if freed).
    pub free_trace: Vec<u64>,
    /// Header canary value (should equal `CANARY_MAGIC`).
    pub header_canary: u64,
    /// Footer canary value.
    pub footer_canary: u64,
    /// Allocation sequence number.
    pub alloc_id: u64,
    /// Free sequence number (None if not freed).
    pub free_id: Option<u64>,
}

impl HeapBlock {
    #[must_use] 
    pub const fn is_overflowed(&self) -> bool {
        self.footer_canary != CANARY_MAGIC
    }

    #[must_use] 
    pub const fn is_header_corrupted(&self) -> bool {
        self.header_canary != CANARY_MAGIC
    }
}

// ─── Heap Event ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapEvent {
    pub id: u64,
    pub event_type: HeapEventType,
    pub address: u64,
    pub size: u64,
    pub call_address: u64, // RIP when the malloc/free was called
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeapEventType {
    Malloc,
    Calloc,
    Realloc,
    Free,
    Error(HeapErrorKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeapErrorKind {
    DoubleFree,
    UseAfterFree,
    BufferOverflow,
    InvalidFree,
}

// ─── Heap State ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapState {
    pub total_allocated: u64,
    pub total_freed: u64,
    pub live_allocations: usize,
    pub peak_allocations: usize,
    pub allocation_count: u64,
    pub free_count: u64,
}

// ─── Heap Emulator ────────────────────────────────────────────────────────────

/// dlmalloc-compatible heap allocator running purely in Rust.
///
/// Manages a simulated address space starting at `base`. Does not touch
/// real process memory — all addresses are virtual handles used by the emulator.
#[derive(Debug)]
pub struct HeapEmulator {
    /// Base address of the simulated heap region.
    base: u64,
    /// Current top-of-heap pointer.
    top: u64,
    /// Maximum heap size.
    max_size: u64,
    /// Live + freed blocks indexed by user pointer.
    blocks: HashMap<u64, HeapBlock>,
    /// Ordered free list (`user_ptr` → size) for reuse.
    free_list: Vec<(u64, u64)>,
    /// All heap events (malloc, free, realloc, errors).
    events: Vec<HeapEvent>,
    next_alloc_id: u64,
    next_free_id: u64,
    next_event_id: u64,
    /// Alignment for all allocations (must be power of 2).
    alignment: u64,
    /// Size of the canary header/footer in the simulated address space.
    canary_size: u64,
    /// Statistics.
    peak_live: usize,
    live_count: usize,
}

impl HeapEmulator {
    pub const DEFAULT_BASE: u64 = 0x0000_0001_0000_0000;
    pub const DEFAULT_MAX: u64 = 256 * 1024 * 1024; // 256 MiB
    pub const ALIGNMENT: u64 = 16;
    pub const CANARY_SIZE: u64 = 8;
    pub const OVERHEAD: u64 = 16; // header_canary(8) + footer_canary(8)

    #[must_use] 
    pub fn new(base: u64, max_size: u64) -> Self {
        Self {
            base,
            top: base,
            max_size,
            blocks: HashMap::new(),
            free_list: Vec::new(),
            events: Vec::new(),
            next_alloc_id: 0,
            next_free_id: 0,
            next_event_id: 0,
            alignment: Self::ALIGNMENT,
            canary_size: Self::CANARY_SIZE,
            peak_live: 0,
            live_count: 0,
        }
    }

    #[must_use] 
    pub fn with_defaults() -> Self {
        Self::new(Self::DEFAULT_BASE, Self::DEFAULT_MAX)
    }

    const fn align_up(size: u64, align: u64) -> u64 {
        (size + align - 1) & !(align - 1)
    }

    /// Per-block canary header/footer size, in bytes of the simulated address space.
    /// Exposed so callers can size their own scratch buffers consistently with the
    /// emulator's overhead accounting (`OVERHEAD = 2 * canary_size`).
    #[must_use] 
    pub const fn canary_size(&self) -> u64 {
        self.canary_size
    }

    /// Total per-allocation canary overhead (header + footer) in bytes.
    #[must_use] 
    pub const fn canary_overhead(&self) -> u64 {
        self.canary_size.saturating_mul(2)
    }

    const fn next_event_id(&mut self) -> u64 {
        let id = self.next_event_id;
        self.next_event_id += 1;
        id
    }

    const fn next_alloc_id(&mut self) -> u64 {
        let id = self.next_alloc_id;
        self.next_alloc_id += 1;
        id
    }

    const fn next_free_id(&mut self) -> u64 {
        let id = self.next_free_id;
        self.next_free_id += 1;
        id
    }

    fn push_event(&mut self, event_type: HeapEventType, address: u64, size: u64, call_address: u64) {
        let id = self.next_event_id();
        self.events.push(HeapEvent { id, event_type, address, size, call_address });
    }

    // ── Allocate ──────────────────────────────────────────────────────────────

    /// Core allocation routine. Returns the user-visible pointer.
    ///
    /// # Errors
    /// Returns `HeapError::SizeTooLarge` if `size` exceeds `MAX_ALLOC_SIZE`, or
    /// `HeapError::OutOfMemory` if the heap is exhausted.
    pub fn malloc(&mut self, size: u64, call_address: u64) -> Result<u64, HeapError> {
        if size == 0 {
            return Ok(0); // POSIX: malloc(0) may return non-NULL
        }
        if size > MAX_ALLOC_SIZE {
            return Err(HeapError::SizeTooLarge(size));
        }

        let aligned_size = Self::align_up(size, self.alignment);
        let total_chunk = Self::OVERHEAD + aligned_size;

        // Try to find a suitable block in the free list
        if let Some(idx) = self.free_list.iter().position(|(_, s)| *s >= total_chunk) {
            let (user_ptr, _chunk_size) = self.free_list.remove(idx);
            let new_alloc_id = self.next_alloc_id();
            if let Some(block) = self.blocks.get_mut(&user_ptr) {
                block.state = BlockState::Allocated;
                block.header_canary = CANARY_MAGIC;
                block.footer_canary = CANARY_MAGIC;
                block.alloc_id = new_alloc_id;
                block.free_id = None;
                block.requested_size = size;
            }
            self.live_count += 1;
            if self.live_count > self.peak_live { self.peak_live = self.live_count; }
            self.push_event(HeapEventType::Malloc, user_ptr, size, call_address);
            return Ok(user_ptr);
        }

        // Allocate from top of heap
        let chunk_start = self.top;
        if chunk_start + total_chunk > self.base + self.max_size {
            return Err(HeapError::OutOfMemory(size));
        }

        // user_ptr points after the header canary (header canary is at chunk_start + HEADER_CANARY_OFFSET)
        let user_ptr = chunk_start + HEADER_CANARY_OFFSET as u64 + Self::CANARY_SIZE;
        self.top = chunk_start + total_chunk;

        let alloc_id = self.next_alloc_id();
        self.blocks.insert(user_ptr, HeapBlock {
            user_ptr,
            chunk_size: total_chunk,
            requested_size: size,
            state: BlockState::Allocated,
            alloc_trace: vec![call_address],
            free_trace: Vec::new(),
            header_canary: CANARY_MAGIC,
            footer_canary: CANARY_MAGIC,
            alloc_id,
            free_id: None,
        });

        self.live_count += 1;
        if self.live_count > self.peak_live { self.peak_live = self.live_count; }
        self.push_event(HeapEventType::Malloc, user_ptr, size, call_address);
        Ok(user_ptr)
    }

    /// calloc: allocate and zero-initialise (simulated — returns pointer only).
    ///
    /// # Errors
    /// Returns `HeapError::SizeTooLarge` if `nmemb * size` overflows or exceeds
    /// `MAX_ALLOC_SIZE`, or `HeapError::OutOfMemory` if the heap is exhausted.
    pub fn calloc(&mut self, nmemb: u64, size: u64, call_address: u64) -> Result<u64, HeapError> {
        let total = nmemb.checked_mul(size).ok_or(HeapError::SizeTooLarge(u64::MAX))?;
        let ptr = self.malloc(total, call_address)?;
        // In a real emulator we'd zero out the memory range
        if let Some(ev) = self.events.last_mut() {
            ev.event_type = HeapEventType::Calloc;
        }
        Ok(ptr)
    }

    /// realloc: resize a live allocation.
    ///
    /// # Errors
    /// Returns `HeapError::InvalidFree` if `ptr` was never allocated,
    /// `HeapError::ReallocFreed` if the block was already freed, or any error
    /// raised by the inner `malloc` / `free` calls.
    pub fn realloc(
        &mut self,
        ptr: u64,
        new_size: u64,
        call_address: u64,
    ) -> Result<u64, HeapError> {
        if ptr == 0 {
            return self.malloc(new_size, call_address);
        }
        if new_size == 0 {
            self.free(ptr, call_address)?;
            return Ok(0);
        }

        // Check state
        match self.blocks.get(&ptr) {
            None => return Err(HeapError::InvalidFree(ptr)),
            Some(b) if b.state == BlockState::Freed => return Err(HeapError::ReallocFreed(ptr)),
            _ => {}
        }

        // NOTE: This virtual heap tracks allocation metadata only; there is no
        // byte-level backing store.  A real realloc would copy
        // min(old_requested_size, new_size) bytes from the old region to the new
        // one before freeing the old block.  Emulated code that reads from the
        // new pointer expecting to see prior data will observe whatever the
        // underlying emulator's memory contains — this layer cannot copy it.
        let old_requested_size = self.blocks[&ptr].requested_size;
        let new_ptr = self.malloc(new_size, call_address)?;
        // Store the logically-copied byte count in the new block's alloc_trace
        // slot so analysis tools can report the valid data range after realloc.
        if let Some(new_block) = self.blocks.get_mut(&new_ptr) {
            let copy_len = old_requested_size.min(new_size);
            // alloc_trace[0] is the call site; push copy_len as a sentinel.
            new_block.alloc_trace.push(copy_len);
        }
        self.free(ptr, call_address)?;

        if let Some(ev) = self.events.last_mut() {
            ev.event_type = HeapEventType::Realloc;
        }
        Ok(new_ptr)
    }

    // ── Free ──────────────────────────────────────────────────────────────────

    /// Free a previously allocated pointer.
    ///
    /// # Errors
    /// Returns `HeapError::InvalidFree`, `HeapError::DoubleFree`, or
    /// `HeapError::BufferOverflow` depending on the block state and canary
    /// integrity checks.
    ///
    /// # Panics
    /// Panics if internal block bookkeeping is inconsistent (the block was
    /// fetched immutably moments earlier but is now missing from `self.blocks`).
    pub fn free(&mut self, ptr: u64, call_address: u64) -> Result<(), HeapError> {
        if ptr == 0 {
            return Ok(()); // free(NULL) is a no-op
        }

        let block = self.blocks.get(&ptr).ok_or(HeapError::InvalidFree(ptr))?;

        match block.state {
            BlockState::Freed => {
                self.push_event(HeapEventType::Error(HeapErrorKind::DoubleFree), ptr, block.requested_size, call_address);
                return Err(HeapError::DoubleFree(ptr));
            }
            BlockState::Free => {
                self.push_event(HeapEventType::Error(HeapErrorKind::InvalidFree), ptr, 0, call_address);
                return Err(HeapError::InvalidFree(ptr));
            }
            BlockState::Allocated => {}
        }

        // Check canaries
        if block.footer_canary != CANARY_MAGIC {
            self.push_event(HeapEventType::Error(HeapErrorKind::BufferOverflow), ptr, block.requested_size, call_address);
            return Err(HeapError::BufferOverflow(ptr));
        }
        if block.header_canary != CANARY_MAGIC {
            self.push_event(HeapEventType::Error(HeapErrorKind::BufferOverflow), ptr, block.requested_size, call_address);
            return Err(HeapError::BufferOverflow(ptr));
        }

        let chunk_size = block.chunk_size;
        let requested_size = block.requested_size;
        let free_id = self.next_free_id();

        let block = self.blocks.get_mut(&ptr).unwrap();
        block.state = BlockState::Freed;
        block.free_trace = vec![call_address];
        block.free_id = Some(free_id);

        self.live_count = self.live_count.saturating_sub(1);
        self.free_list.push((ptr, chunk_size));
        self.push_event(HeapEventType::Free, ptr, requested_size, call_address);
        Ok(())
    }

    // ── Read/Write Access Checking ────────────────────────────────────────────

    /// Check if a read/write access at `addr` of `size` bytes is valid.
    /// Used to detect use-after-free.
    ///
    /// # Errors
    /// Returns `HeapError::UseAfterFree` if the address falls inside a freed
    /// block, or `HeapError::BufferOverflow` if the access spans past the
    /// requested allocation size.
    pub fn check_access(
        &self,
        addr: u64,
        size: u64,
        _write: bool,
        _call_address: u64,
    ) -> Result<(), HeapError> {
        // An access is the INTERVAL `[addr, addr + size)`, not the point
        // `addr`. Locating the block by "does addr fall inside the user area"
        // missed the single most common heap bug there is: a write that begins
        // exactly AT the end of the buffer is inside no user area at all, so it
        // fell through to "not a heap address — allow". One byte past a 16-byte
        // buffer was reported as fine.
        //
        // Each block is therefore checked against its full extent, guard region
        // included, and the access is compared as an interval.
        let access_end = addr.saturating_add(size.max(1));
        for block in self.blocks.values() {
            let user_start = block.user_ptr;
            let user_end = user_start + block.requested_size;
            // The guard/footer region that follows the user data. An access
            // landing here is an overflow, not an unrelated address.
            let guarded_end = user_end.saturating_add(Self::CANARY_SIZE);

            let touches_user = addr < user_end && access_end > user_start;
            let touches_guard = addr < guarded_end && access_end > user_end;

            if touches_user {
                if block.state == BlockState::Freed {
                    return Err(HeapError::UseAfterFree(addr));
                }
                if access_end > user_end {
                    return Err(HeapError::BufferOverflow(block.user_ptr));
                }
                return Ok(());
            }
            if touches_guard {
                if block.state == BlockState::Freed {
                    return Err(HeapError::UseAfterFree(addr));
                }
                return Err(HeapError::BufferOverflow(block.user_ptr));
            }
        }
        Ok(()) // not a heap address — allow
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    #[must_use] 
    pub fn state(&self) -> HeapState {
        let total_allocated: u64 = self.blocks.values()
            .filter(|b| b.state == BlockState::Allocated)
            .map(|b| b.requested_size)
            .sum();
        let total_freed: u64 = self.blocks.values()
            .filter(|b| b.state == BlockState::Freed)
            .map(|b| b.requested_size)
            .sum();
        HeapState {
            total_allocated,
            total_freed,
            live_allocations: self.live_count,
            peak_allocations: self.peak_live,
            allocation_count: self.next_alloc_id,
            free_count: self.next_free_id,
        }
    }

    #[must_use] 
    pub fn live_blocks(&self) -> Vec<&HeapBlock> {
        self.blocks.values()
            .filter(|b| b.state == BlockState::Allocated)
            .collect()
    }

    #[must_use] 
    pub fn freed_blocks(&self) -> Vec<&HeapBlock> {
        self.blocks.values()
            .filter(|b| b.state == BlockState::Freed)
            .collect()
    }

    #[must_use] 
    pub fn events(&self) -> &[HeapEvent] {
        &self.events
    }

    #[must_use] 
    pub fn error_events(&self) -> Vec<&HeapEvent> {
        self.events.iter()
            .filter(|e| matches!(e.event_type, HeapEventType::Error(_)))
            .collect()
    }

    #[must_use] 
    pub fn error_count(&self) -> usize {
        self.error_events().len()
    }

    #[must_use] 
    pub const fn top_of_heap(&self) -> u64 {
        self.top
    }

    #[must_use] 
    pub const fn heap_used(&self) -> u64 {
        self.top.saturating_sub(self.base)
    }

    // ── Hook Integration ──────────────────────────────────────────────────────

    /// Given a function name from the emulated process (hooked via library stubs),
    /// dispatch to the correct heap operation. Returns the new rax value.
    pub fn hook_function_call(
        &mut self,
        function: &str,
        rdi: u64,
        rsi: u64,
        _rdx: u64,
        call_rip: u64,
    ) -> i64 {
        match function {
            "malloc" | "__libc_malloc" => self
                .malloc(rdi, call_rip)
                .map_or(0, u64::cast_signed),
            "calloc" | "__libc_calloc" => self
                .calloc(rdi, rsi, call_rip)
                .map_or(0, u64::cast_signed),
            "realloc" | "__libc_realloc" => self
                .realloc(rdi, rsi, call_rip)
                .map_or(0, u64::cast_signed),
            "free" | "__libc_free" | "cfree" => {
                let _ = self.free(rdi, call_rip);
                0
            }
            "malloc_usable_size" => self
                .blocks
                .get(&rdi)
                .map_or(0, |b| b.requested_size.cast_signed()),
            _ => -1,
        }
    }

    // ── Vulnerability Report ──────────────────────────────────────────────────

    #[must_use] 
    pub fn vulnerability_report(&self) -> HeapVulnerabilityReport {
        let err_cap = self.events.iter().filter(|e| matches!(e.event_type, HeapEventType::Error(_))).count();
        let mut double_frees = Vec::with_capacity(err_cap);
        let mut buffer_overflows = Vec::with_capacity(err_cap);
        let mut use_after_frees = Vec::with_capacity(err_cap);
        let leak_cap = self.blocks.values().filter(|b| b.state == BlockState::Allocated).count();
        let mut memory_leaks = Vec::with_capacity(leak_cap);

        for ev in &self.events {
            match ev.event_type {
                HeapEventType::Error(HeapErrorKind::DoubleFree) => double_frees.push(ev.address),
                HeapEventType::Error(HeapErrorKind::BufferOverflow) => buffer_overflows.push(ev.address),
                HeapEventType::Error(HeapErrorKind::UseAfterFree) => use_after_frees.push(ev.address),
                _ => {}
            }
        }

        // Memory leaks: blocks allocated but never freed when we expect them to be
        for block in self.blocks.values() {
            if block.state == BlockState::Allocated && block.requested_size > 0 {
                memory_leaks.push((block.user_ptr, block.requested_size));
            }
        }

        HeapVulnerabilityReport {
            double_frees,
            buffer_overflows,
            use_after_frees,
            memory_leaks,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeapVulnerabilityReport {
    pub double_frees: Vec<u64>,
    pub buffer_overflows: Vec<u64>,
    pub use_after_frees: Vec<u64>,
    pub memory_leaks: Vec<(u64, u64)>, // (ptr, size)
}

impl HeapVulnerabilityReport {
    #[must_use] 
    pub const fn has_vulnerabilities(&self) -> bool {
        !self.double_frees.is_empty()
            || !self.buffer_overflows.is_empty()
            || !self.use_after_frees.is_empty()
    }

    #[must_use] 
    pub fn total_leaked_bytes(&self) -> u64 {
        self.memory_leaks.iter().map(|(_, s)| *s).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malloc_and_free() {
        let mut heap = HeapEmulator::with_defaults();
        let p = heap.malloc(64, 0x0040_0000).unwrap();
        assert!(p >= HeapEmulator::DEFAULT_BASE);
        let state = heap.state();
        assert_eq!(state.live_allocations, 1);
        heap.free(p, 0x0040_0010).unwrap();
        let state = heap.state();
        assert_eq!(state.live_allocations, 0);
    }

    #[test]
    fn test_double_free_detection() {
        let mut heap = HeapEmulator::with_defaults();
        let p = heap.malloc(32, 0x0040_1000).unwrap();
        heap.free(p, 0x0040_1010).unwrap();
        let result = heap.free(p, 0x0040_1020);
        assert!(matches!(result, Err(HeapError::DoubleFree(_))));
    }

    #[test]
    fn test_invalid_free() {
        let mut heap = HeapEmulator::with_defaults();
        let result = heap.free(0xDEAD_BEEF, 0x0);
        assert!(matches!(result, Err(HeapError::InvalidFree(_))));
    }

    #[test]
    fn test_calloc() {
        let mut heap = HeapEmulator::with_defaults();
        let p = heap.calloc(10, 4, 0x0040_0000).unwrap();
        assert!(p > 0);
        let state = heap.state();
        assert_eq!(state.live_allocations, 1);
        assert_eq!(heap.blocks[&p].requested_size, 40);
    }

    #[test]
    fn test_realloc_grow() {
        let mut heap = HeapEmulator::with_defaults();
        let p = heap.malloc(16, 0x0040_0000).unwrap();
        let p2 = heap.realloc(p, 128, 0x0040_0010).unwrap();
        assert!(p2 > 0);
        assert_eq!(heap.live_blocks().len(), 1);
        assert_eq!(heap.live_blocks()[0].requested_size, 128);
    }

    #[test]
    fn test_realloc_null_is_malloc() {
        let mut heap = HeapEmulator::with_defaults();
        let p = heap.realloc(0, 64, 0x0040_0000).unwrap();
        assert!(p > 0);
    }

    #[test]
    fn test_free_reuse() {
        let mut heap = HeapEmulator::with_defaults();
        let p1 = heap.malloc(64, 0x0).unwrap();
        heap.free(p1, 0x0).unwrap();
        let p2 = heap.malloc(64, 0x0).unwrap();
        // Should reuse the freed block
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_vulnerability_report_clean() {
        let mut heap = HeapEmulator::with_defaults();
        let p = heap.malloc(32, 0x0).unwrap();
        heap.free(p, 0x0).unwrap();
        let report = heap.vulnerability_report();
        assert!(!report.has_vulnerabilities());
    }

    #[test]
    fn test_hook_function_call() {
        let mut heap = HeapEmulator::with_defaults();
        let ptr = heap.hook_function_call("malloc", 128, 0, 0, 0x0040_1000);
        assert!(ptr > 0);
        let _ = heap.hook_function_call("free", ptr.cast_unsigned(), 0, 0, 0x0040_1010);
        assert_eq!(heap.live_blocks().len(), 0);
    }

    #[test]
    fn test_size_too_large() {
        let mut heap = HeapEmulator::with_defaults();
        let result = heap.malloc(u64::MAX, 0x0);
        assert!(matches!(result, Err(HeapError::SizeTooLarge(_))));
    }

    #[test]
    fn test_heap_state_counters() {
        let mut heap = HeapEmulator::with_defaults();
        for i in 0..5 {
            heap.malloc(16 * u64::try_from(i + 1).unwrap_or(0), 0x0).unwrap();
        }
        let state = heap.state();
        assert_eq!(state.allocation_count, 5);
        assert_eq!(state.live_allocations, 5);
        assert_eq!(state.peak_allocations, 5);
    }
}

// ─── Heap Visualiser ──────────────────────────────────────────────────────────

/// ASCII-art visualisation of the heap layout.
#[must_use] 
pub fn visualise_heap(emulator: &HeapEmulator, width: usize) -> String {
    let start = emulator.base;
    let end = emulator.top;
    let total = (end - start).max(1);
    let mut cells = vec!['.'; width];

    let width_u64 = width as u64;
    for block in emulator.blocks.values() {
        // Integer math: col = rel * width = (offset * width) / total
        let off_start = block.user_ptr.saturating_sub(start);
        let off_end = (block.user_ptr + block.requested_size).saturating_sub(start);
        let col_start_u64 = off_start.saturating_mul(width_u64) / total;
        let col_end_u64 = off_end.saturating_mul(width_u64) / total;
        let col_start = usize::try_from(col_start_u64).unwrap_or(width).min(width);
        let col_end = usize::try_from(col_end_u64).unwrap_or(width).min(width);
        let symbol = match block.state {
            BlockState::Allocated => 'A',
            BlockState::Freed => 'F',
            BlockState::Free => '_',
        };
        for c in &mut cells[col_start..col_end] {
            *c = symbol;
        }
    }

    format!(
        "[{}]\n  base={:#x}  top={:#x}  used={:#x}  blocks={}\n  A=allocated F=freed .=unallocated",
        cells.into_iter().collect::<String>(),
        start,
        end,
        total,
        emulator.blocks.len(),
    )
}

// ─── Chunk Allocator ──────────────────────────────────────────────────────────

/// A fixed-size chunk allocator for homogeneous objects (arena-style).
/// Much faster than general malloc for same-size allocations.
#[derive(Debug)]
pub struct ChunkAllocator {
    /// Size of each chunk (user data only).
    chunk_size: u64,
    base: u64,
    top: u64,
    max_size: u64,
    free_chunks: Vec<u64>, // stack of free chunk pointers
    total_allocated: u64,
    total_freed: u64,
}

impl ChunkAllocator {
    /// Create a new chunk allocator.
    ///
    /// # Panics
    /// Panics if `chunk_size < 8` or if `max_size < chunk_size`.
    #[must_use]
    pub fn new(base: u64, max_size: u64, chunk_size: u64) -> Self {
        assert!(chunk_size >= 8, "chunk_size must be >= 8");
        assert!(max_size >= chunk_size, "max_size must be >= chunk_size");
        Self {
            chunk_size: HeapEmulator::align_up(chunk_size, HeapEmulator::ALIGNMENT),
            base,
            top: base,
            max_size,
            free_chunks: Vec::new(),
            total_allocated: 0,
            total_freed: 0,
        }
    }

    pub fn alloc(&mut self) -> Option<u64> {
        // Try free list first
        if let Some(ptr) = self.free_chunks.pop() {
            self.total_allocated += 1;
            return Some(ptr);
        }
        // Bump pointer
        if self.top + self.chunk_size > self.base + self.max_size {
            return None;
        }
        let ptr = self.top;
        self.top += self.chunk_size;
        self.total_allocated += 1;
        Some(ptr)
    }

    pub fn free(&mut self, ptr: u64) {
        // Basic bounds check
        if ptr >= self.base && ptr < self.top {
            self.free_chunks.push(ptr);
            self.total_freed += 1;
        }
    }

    #[must_use] 
    pub const fn live_count(&self) -> u64 {
        self.total_allocated - self.total_freed
    }

    #[must_use] 
    pub const fn capacity(&self) -> u64 {
        self.max_size / self.chunk_size
    }

    #[must_use]
    pub fn utilisation(&self) -> f64 {
        let cap = self.capacity();
        if cap == 0 {
            0.0
        } else {
            // Use u32 conversions (lossless to f64) by clamping; fine for ratios.
            let live = u32::try_from(self.live_count().min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
            let cap32 = u32::try_from(cap.min(u64::from(u32::MAX))).unwrap_or(u32::MAX);
            f64::from(live) / f64::from(cap32)
        }
    }
}

// ─── Canary Manager ───────────────────────────────────────────────────────────

/// Manages heap canary verification across all live blocks.
#[derive(Debug, Default)]
pub struct CanaryManager {
    /// Maps `user_ptr` → expected canary values (header, footer).
    canaries: std::collections::HashMap<u64, (u64, u64)>,
}

impl CanaryManager {
    pub fn register(&mut self, ptr: u64) {
        self.canaries.insert(ptr, (CANARY_MAGIC, CANARY_MAGIC));
    }

    pub fn unregister(&mut self, ptr: u64) {
        self.canaries.remove(&ptr);
    }

    /// Verify all canaries against the emulator's block table.
    #[must_use] 
    pub fn verify_all(&self, emulator: &HeapEmulator) -> Vec<CanaryViolation> {
        let mut violations = Vec::new();
        for block in emulator.blocks.values() {
            if block.state != BlockState::Allocated {
                continue;
            }
            if block.header_canary != CANARY_MAGIC {
                violations.push(CanaryViolation {
                    ptr: block.user_ptr,
                    kind: CanaryKind::Header,
                    expected: CANARY_MAGIC,
                    found: block.header_canary,
                });
            }
            if block.footer_canary != CANARY_MAGIC {
                violations.push(CanaryViolation {
                    ptr: block.user_ptr,
                    kind: CanaryKind::Footer,
                    expected: CANARY_MAGIC,
                    found: block.footer_canary,
                });
            }
        }
        violations
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryViolation {
    pub ptr: u64,
    pub kind: CanaryKind,
    pub expected: u64,
    pub found: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanaryKind {
    Header,
    Footer,
}

#[cfg(test)]
mod extra_tests {
    use super::*;

    #[test]
    fn test_chunk_allocator_basic() {
        let mut ca = ChunkAllocator::new(0x1000_0000, 0x10000, 32);
        let p1 = ca.alloc().unwrap();
        let p2 = ca.alloc().unwrap();
        assert_ne!(p1, p2);
        assert_eq!(ca.live_count(), 2);
        ca.free(p1);
        let p3 = ca.alloc().unwrap();
        assert_eq!(p3, p1); // reused from free list
    }

    #[test]
    fn test_chunk_allocator_capacity() {
        let ca = ChunkAllocator::new(0x0, 512, 16);
        assert!(ca.capacity() >= 16); // 512/16 = 32 chunks
    }

    #[test]
    fn test_visualise_heap() {
        let mut heap = HeapEmulator::with_defaults();
        heap.malloc(64, 0x0).unwrap();
        let vis = visualise_heap(&heap, 40);
        assert!(vis.contains('A'));
    }

    #[test]
    fn test_canary_manager_clean() {
        let mut heap = HeapEmulator::with_defaults();
        heap.malloc(32, 0x0).unwrap();
        let mgr = CanaryManager::default();
        let violations = mgr.verify_all(&heap);
        assert!(violations.is_empty());
    }

    #[test]
    fn test_heap_used() {
        let mut heap = HeapEmulator::with_defaults();
        assert_eq!(heap.heap_used(), 0);
        heap.malloc(100, 0x0).unwrap();
        assert!(heap.heap_used() > 0);
    }
}
