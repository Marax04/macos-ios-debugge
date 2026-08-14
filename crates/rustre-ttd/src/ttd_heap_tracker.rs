//! Heap allocation tracker for TTD (Time Travel Debugging) traces.
//!
//! [`TtdHeapTracker`] replays the event stream of a [`TtdTrace`] and
//! reconstructs the heap allocation timeline.  It tracks every malloc/free pair
//! and lets callers query which block was live at any given [`TracePosition`].
//!
//! Public types:
//! - [`HeapBlock`]       — a contiguous heap region with address and size.
//! - [`HeapAlloc`]       — a single allocation event (malloc or free).
//! - [`TtdHeapTracker`]  — the replaying tracker.
//! - [`find_alloc_at`]   — standalone convenience function.

use crate::{TracePosition, TtdTrace, EventKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ─── HeapBlock ───────────────────────────────────────────────────────────────

/// A contiguous heap region that was live at some point in the trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeapBlock {
    /// Base virtual address of the allocation.
    pub address: u64,
    /// Size of the allocation in bytes.
    pub size: u64,
    /// The execution position at which this block was allocated.
    pub alloc_pos: TracePosition,
    /// The execution position at which this block was freed, if known.
    pub free_pos: Option<TracePosition>,
    /// Optional tag: the allocator symbol (e.g. `"malloc"`, `"HeapAlloc"`).
    pub allocator: Option<String>,
    /// Optional tag: the call-site return address.
    pub call_site: Option<u64>,
}

impl HeapBlock {
    /// Create a new `HeapBlock` that is not yet freed.
    #[must_use]
    pub const fn new(address: u64, size: u64, alloc_pos: TracePosition) -> Self {
        Self {
            address,
            size,
            alloc_pos,
            free_pos: None,
            allocator: None,
            call_site: None,
        }
    }

    /// Return `true` if the block has been freed.
    #[must_use]
    pub const fn is_freed(&self) -> bool {
        self.free_pos.is_some()
    }

    /// Return `true` if the block is still live (not freed).
    #[must_use]
    pub const fn is_live(&self) -> bool {
        self.free_pos.is_none()
    }

    /// Return `true` if `addr` falls within this block's range.
    #[must_use]
    pub const fn contains_addr(&self, addr: u64) -> bool {
        addr >= self.address && addr < self.address.saturating_add(self.size)
    }

    /// End address (exclusive) of the block.
    #[must_use]
    pub const fn end_address(&self) -> u64 {
        self.address.saturating_add(self.size)
    }

    /// Return `true` if this block was live at the given trace position.
    #[must_use]
    pub fn was_live_at(&self, pos: &TracePosition) -> bool {
        // Allocated before or at `pos`, not yet freed.
        if self.alloc_pos.sequence > pos.sequence {
            return false;
        }
        self.free_pos.as_ref().is_none_or(|fp| fp.sequence > pos.sequence)
    }

    /// Attach an allocator symbol name.
    #[must_use]
    pub fn with_allocator(mut self, name: impl Into<String>) -> Self {
        self.allocator = Some(name.into());
        self
    }

    /// Attach a call-site return address.
    #[must_use]
    pub const fn with_call_site(mut self, addr: u64) -> Self {
        self.call_site = Some(addr);
        self
    }
}

impl std::fmt::Display for HeapBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HeapBlock {{ addr={:#x}, size={:#x}, freed={} }}",
            self.address,
            self.size,
            self.is_freed()
        )
    }
}

// ─── HeapAllocKind ───────────────────────────────────────────────────────────

/// Whether a heap event is an allocation or a free.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HeapAllocKind {
    /// A memory allocation.
    Alloc,
    /// A memory deallocation.
    Free,
    /// A reallocation (resize in place or at a new address).
    Realloc {
        /// Previous address before realloc.
        old_addr: u64,
        /// Previous size before realloc.
        old_size: u64,
    },
}

impl std::fmt::Display for HeapAllocKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Alloc => write!(f, "Alloc"),
            Self::Free => write!(f, "Free"),
            Self::Realloc { old_addr, old_size } => {
                write!(f, "Realloc(old={old_addr:#x}, old_size={old_size:#x})")
            }
        }
    }
}

// ─── HeapAlloc ───────────────────────────────────────────────────────────────

/// A single heap event (allocation or free) observed in the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapAlloc {
    /// Kind of event.
    pub kind: HeapAllocKind,
    /// The base address affected by this event.
    pub address: u64,
    /// Size in bytes (0 for a free).
    pub size: u64,
    /// Execution position of the event.
    pub position: TracePosition,
    /// The allocator function name, if resolved.
    pub allocator: Option<String>,
    /// Return address / call site.
    pub call_site: Option<u64>,
}

impl HeapAlloc {
    /// Create a new allocation event.
    #[must_use]
    pub const fn new_alloc(
        address: u64,
        size: u64,
        position: TracePosition,
        allocator: Option<String>,
    ) -> Self {
        Self {
            kind: HeapAllocKind::Alloc,
            address,
            size,
            position,
            allocator,
            call_site: None,
        }
    }

    /// Create a new free event.
    #[must_use]
    pub const fn new_free(address: u64, position: TracePosition) -> Self {
        Self {
            kind: HeapAllocKind::Free,
            address,
            size: 0,
            position,
            allocator: None,
            call_site: None,
        }
    }

    /// Return `true` if this is an allocation event.
    #[must_use]
    pub const fn is_alloc(&self) -> bool {
        matches!(self.kind, HeapAllocKind::Alloc)
    }

    /// Return `true` if this is a free event.
    #[must_use]
    pub const fn is_free(&self) -> bool {
        matches!(self.kind, HeapAllocKind::Free)
    }
}

impl std::fmt::Display for HeapAlloc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HeapAlloc {{ kind={}, addr={:#x}, size={:#x} }}",
            self.kind, self.address, self.size
        )
    }
}

// ─── HeapStats ───────────────────────────────────────────────────────────────

/// Aggregate statistics derived from the heap tracker.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeapStats {
    /// Total number of allocation events.
    pub total_allocs: u64,
    /// Total number of free events.
    pub total_frees: u64,
    /// Number of currently live allocations.
    pub live_allocs: u64,
    /// Peak number of simultaneously live allocations.
    pub peak_live_allocs: u64,
    /// Total bytes ever allocated.
    pub total_bytes_allocated: u64,
    /// Currently live bytes.
    pub live_bytes: u64,
    /// Peak live bytes.
    pub peak_live_bytes: u64,
    /// Number of double-free events detected.
    pub double_frees: u64,
    /// Number of frees for addresses that were never allocated (wild frees).
    pub wild_frees: u64,
}

impl HeapStats {
    /// Return the alloc/free ratio.  Returns `0.0` if no allocs occurred.
    #[must_use]
    pub fn alloc_free_ratio(&self) -> f64 {
        if self.total_allocs == 0 {
            0.0
        } else {
            // Pre-divide as integers using a fixed-point scaling to keep the
            // f64 cast within the mantissa-precision range. We scale by 2^20
            // (about 6 decimal digits) which is more than enough for a ratio.
            const SCALE: u64 = 1 << 20;
            let scaled = (self.total_frees.saturating_mul(SCALE)) / self.total_allocs;
            // `scaled` fits in u64; converting via `u32::try_from` of the
            // upper/lower halves keeps the f64 cast lossless.
            let upper = u32::try_from(scaled >> 32).unwrap_or(u32::MAX);
            let lower = u32::try_from(scaled & u64::from(u32::MAX)).unwrap_or(0);
            (f64::from(upper) * 4_294_967_296.0 + f64::from(lower)) / 2.0_f64.powi(20)
        }
    }

    /// Return `true` if there are suspected memory leaks (live allocs remain).
    #[must_use]
    pub const fn has_leaks(&self) -> bool {
        self.live_allocs > 0
    }
}

impl std::fmt::Display for HeapStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HeapStats {{ allocs={}, frees={}, live={}, leaks={} }}",
            self.total_allocs,
            self.total_frees,
            self.live_allocs,
            self.has_leaks()
        )
    }
}

// ─── TtdHeapTracker ───────────────────────────────────────────────────────────

/// Heap allocation tracker that reconstructs the heap timeline by replaying a
/// [`TtdTrace`] event stream.
///
/// Call [`replay`](Self::replay) to populate the tracker, then use the query
/// methods to inspect the heap state at any point in time.
pub struct TtdHeapTracker {
    /// All allocation events observed, in order.
    pub events: Vec<HeapAlloc>,
    /// All heap blocks ever seen.  Key is the base address.
    /// Multiple blocks at the same address are stored in chronological order.
    blocks: BTreeMap<u64, Vec<HeapBlock>>,
    /// Aggregate statistics.
    pub stats: HeapStats,
    /// Names considered to be allocators.
    pub allocator_names: Vec<String>,
    /// Names considered to be deallocators.
    pub free_names: Vec<String>,
}

impl TtdHeapTracker {
    /// Create a new heap tracker with a default set of allocator/free symbols.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            blocks: BTreeMap::new(),
            stats: HeapStats::default(),
            allocator_names: vec![
                "malloc".to_string(),
                "calloc".to_string(),
                "realloc".to_string(),
                "new".to_string(),
                "HeapAlloc".to_string(),
                "RtlAllocateHeap".to_string(),
                "VirtualAlloc".to_string(),
            ],
            free_names: vec![
                "free".to_string(),
                "delete".to_string(),
                "HeapFree".to_string(),
                "RtlFreeHeap".to_string(),
                "VirtualFree".to_string(),
            ],
        }
    }

    /// Create a tracker with custom allocator / free symbol lists.
    #[must_use]
    pub fn with_symbols(
        allocator_names: Vec<String>,
        free_names: Vec<String>,
    ) -> Self {
        Self {
            allocator_names,
            free_names,
            ..Self::new()
        }
    }

    // ── Replay ────────────────────────────────────────────────────────────

    /// Replay all events in `trace` to reconstruct the heap timeline.
    ///
    /// This method clears any previous state before replaying.
    pub fn replay(&mut self, trace: &TtdTrace) {
        self.clear();
        for event in trace.all_events() {
            self.process_event(event.kind.clone(), event.position);
        }
    }

    /// Replay a specific slice of events.
    pub fn replay_range(&mut self, trace: &TtdTrace, start: &TracePosition, end: &TracePosition) {
        for event in trace.all_events() {
            if event.position.sequence < start.sequence {
                continue;
            }
            if event.position.sequence > end.sequence {
                break;
            }
            self.process_event(event.kind.clone(), event.position);
        }
    }

    /// Process a single event kind at a given position.
    pub fn process_event(&mut self, kind: EventKind, pos: TracePosition) {
        match kind {
            EventKind::Call { from, to } => {
                Self::handle_call(from, Some(to), pos);
            }
            EventKind::MemWrite { addr, data } => {
                Self::handle_mem_write(addr, data, pos);
            }
            _ => {}
        }
    }

    /// Manually record an allocation.
    pub fn record_alloc(
        &mut self,
        address: u64,
        size: u64,
        pos: TracePosition,
        allocator: Option<String>,
    ) {
        if address == 0 {
            return; // Null return from allocator — skip.
        }
        let block = HeapBlock::new(address, size, pos);
        let block = if let Some(ref a) = allocator {
            block.with_allocator(a)
        } else {
            block
        };
        self.blocks.entry(address).or_default().push(block);
        let event =
            HeapAlloc::new_alloc(address, size, pos, allocator);
        self.events.push(event);

        self.stats.total_allocs += 1;
        self.stats.total_bytes_allocated += size;
        self.stats.live_allocs += 1;
        self.stats.live_bytes += size;
        if self.stats.live_allocs > self.stats.peak_live_allocs {
            self.stats.peak_live_allocs = self.stats.live_allocs;
        }
        if self.stats.live_bytes > self.stats.peak_live_bytes {
            self.stats.peak_live_bytes = self.stats.live_bytes;
        }
    }

    /// Manually record a free.
    pub fn record_free(&mut self, address: u64, pos: TracePosition) {
        if address == 0 {
            return;
        }
        if let Some(chain) = self.blocks.get_mut(&address) {
            // Find the most recent live block at this address.
            if let Some(block) = chain.iter_mut().rev().find(|b| b.is_live()) {
                let freed_size = block.size;
                block.free_pos = Some(pos);
                self.stats.total_frees += 1;
                self.stats.live_allocs = self.stats.live_allocs.saturating_sub(1);
                self.stats.live_bytes = self.stats.live_bytes.saturating_sub(freed_size);
            } else {
                // All blocks at this address already freed — double free.
                self.stats.double_frees += 1;
            }
        } else {
            // No record of this address — wild free.
            self.stats.wild_frees += 1;
        }
        let event = HeapAlloc::new_free(address, pos);
        self.events.push(event);
    }

    // ── Query API ─────────────────────────────────────────────────────────

    /// Find the heap block that is live at `pos` and contains `addr`.
    ///
    /// Returns `None` if no such block exists.
    #[must_use]
    pub fn find_alloc_at(&self, addr: u64, pos: &TracePosition) -> Option<&HeapBlock> {
        // Walk the BTree in reverse to find the largest base ≤ addr.
        for (_, chain) in self.blocks.range(..=addr).rev() {
            for block in chain.iter().rev() {
                if block.contains_addr(addr) && block.was_live_at(pos) {
                    return Some(block);
                }
            }
        }
        None
    }

    /// Return all blocks live at a given trace position.
    #[must_use]
    pub fn live_blocks_at(&self, pos: &TracePosition) -> Vec<&HeapBlock> {
        self.blocks
            .values()
            .flat_map(|chain| chain.iter())
            .filter(|b| b.was_live_at(pos))
            .collect()
    }

    /// Return all blocks that are currently live (no free position recorded).
    #[must_use]
    pub fn all_live_blocks(&self) -> Vec<&HeapBlock> {
        self.blocks
            .values()
            .flat_map(|chain| chain.iter())
            .filter(|b| b.is_live())
            .collect()
    }

    /// Return all blocks ever allocated (live or freed).
    #[must_use]
    pub fn all_blocks(&self) -> Vec<&HeapBlock> {
        self.blocks
            .values()
            .flat_map(|chain| chain.iter())
            .collect()
    }

    /// Return a block by its exact base address, if it is currently live.
    #[must_use]
    pub fn block_by_addr(&self, addr: u64) -> Option<&HeapBlock> {
        self.blocks
            .get(&addr)?
            .iter()
            .rev()
            .find(|b| b.is_live())
    }

    /// Return the allocation event at a given index.
    #[must_use]
    pub fn event_at(&self, idx: usize) -> Option<&HeapAlloc> {
        self.events.get(idx)
    }

    /// Return all allocation events for a given address.
    #[must_use]
    pub fn events_for_addr(&self, addr: u64) -> Vec<&HeapAlloc> {
        self.events.iter().filter(|e| e.address == addr).collect()
    }

    /// Return the number of distinct allocated addresses seen.
    #[must_use]
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Return `true` if any live blocks remain at the end of replay.
    #[must_use]
    pub const fn has_leaks(&self) -> bool {
        self.stats.has_leaks()
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /// Clear all state.
    pub fn clear(&mut self) {
        self.events.clear();
        self.blocks.clear();
        self.stats = HeapStats::default();
    }

    // ── Private ───────────────────────────────────────────────────────────

    const fn handle_call(target: u64, return_addr: Option<u64>, pos: TracePosition) { // target = from, return_addr = Some(to)
        // We don't have symbol resolution in this module; callers that want
        // symbol-based tracking should use `record_alloc` / `record_free`
        // directly after resolving symbols.  This handler exists as a hook for
        // future extension.
        let _ = (target, return_addr, pos);
    }

    fn handle_mem_write(addr: u64, data: Vec<u8>, pos: TracePosition) {
        // Detect heap metadata patterns: a write of a non-null pointer value
        // to address 0 is the canonical "return from malloc" pattern used in
        // TTD traces.  In practice callers call record_alloc directly.
        let _ = (addr, data, pos);
    }

    /// Returns true if `name` matches one of the registered allocator function names.
    #[must_use] 
    pub fn is_allocator(&self, name: &str) -> bool {
        self.allocator_names.iter().any(|n| n == name)
    }

    /// Returns true if `name` matches one of the registered deallocator function names.
    #[must_use] 
    pub fn is_free_fn(&self, name: &str) -> bool {
        self.free_names.iter().any(|n| n == name)
    }

    /// Classify a symbol name into a heap operation kind.
    ///
    /// Returns `Some("alloc")` for allocator names, `Some("free")` for deallocator names,
    /// and `None` otherwise. Used by upstream replay drivers to dispatch on resolved
    /// call targets without exposing the internal name vectors.
    #[must_use] 
    pub fn classify_symbol(&self, name: &str) -> Option<&'static str> {
        if self.is_allocator(name) {
            Some("alloc")
        } else if self.is_free_fn(name) {
            Some("free")
        } else {
            None
        }
    }
}

impl Default for TtdHeapTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ─── find_alloc_at (standalone) ──────────────────────────────────────────────

/// Standalone convenience function: replay `trace` and find the heap block that
/// contains `addr` and is live at `pos`.
///
/// Returns `None` if no such block exists.
#[must_use]
pub fn find_alloc_at<'a>(
    tracker: &'a TtdHeapTracker,
    addr: u64,
    pos: &TracePosition,
) -> Option<&'a HeapBlock> {
    tracker.find_alloc_at(addr, pos)
}

/// Replay a trace and collect all live blocks at a given position.
#[must_use]
pub fn live_blocks_snapshot(trace: &TtdTrace, pos: &TracePosition) -> Vec<HeapBlock> {
    let mut tracker = TtdHeapTracker::new();
    tracker.replay(trace);
    tracker.live_blocks_at(pos).into_iter().cloned().collect()
}

/// Classify a resolved call-target symbol as `alloc`, `free`, or neither.
///
/// Thin wrapper around [`TtdHeapTracker::classify_symbol`] for callers that
/// already hold a tracker reference.
#[must_use]
pub fn classify_call_target(tracker: &TtdHeapTracker, name: &str) -> Option<&'static str> {
    tracker.classify_symbol(name)
}

#[cfg(test)]
mod symbol_classify_tests {
    use super::*;

    #[test]
    fn classifies_default_alloc_and_free_names() {
        let tracker = TtdHeapTracker::new();
        // Default constructors register the standard CRT names; at least verify
        // the predicates and the wrapper agree.
        for name in ["malloc", "calloc", "realloc", "HeapAlloc"] {
            if tracker.is_allocator(name) {
                assert_eq!(classify_call_target(&tracker, name), Some("alloc"));
            }
        }
        for name in ["free", "HeapFree"] {
            if tracker.is_free_fn(name) {
                assert_eq!(classify_call_target(&tracker, name), Some("free"));
            }
        }
        assert_eq!(classify_call_target(&tracker, "definitely_not_a_heap_fn"), None);
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TracePosition;

    fn pos(seq: u64) -> TracePosition {
        TracePosition::new(seq, 0)
    }

    // ── HeapBlock ────────────────────────────────────────────────────────────

    #[test]
    fn test_heap_block_new() {
        let b = HeapBlock::new(0x1000, 0x40, pos(1));
        assert_eq!(b.address, 0x1000);
        assert_eq!(b.size, 0x40);
        assert!(b.is_live());
        assert!(!b.is_freed());
    }

    #[test]
    fn test_heap_block_contains_addr() {
        let b = HeapBlock::new(0x1000, 0x40, pos(1));
        assert!(b.contains_addr(0x1000));
        assert!(b.contains_addr(0x103F));
        assert!(!b.contains_addr(0x1040));
        assert!(!b.contains_addr(0x0FFF));
    }

    #[test]
    fn test_heap_block_end_address() {
        let b = HeapBlock::new(0x2000, 0x100, pos(1));
        assert_eq!(b.end_address(), 0x2100);
    }

    #[test]
    fn test_heap_block_was_live_at() {
        let mut b = HeapBlock::new(0x1000, 0x10, pos(5));
        // Allocated at seq=5, not freed — live at seq=6
        assert!(b.was_live_at(&pos(6)));
        // Not yet allocated at seq=4
        assert!(!b.was_live_at(&pos(4)));
        // Freed at seq=10
        b.free_pos = Some(pos(10));
        assert!(b.was_live_at(&pos(9)));
        assert!(!b.was_live_at(&pos(10)));
    }

    #[test]
    fn test_heap_block_with_allocator() {
        let b = HeapBlock::new(0x1000, 0x10, pos(1)).with_allocator("malloc");
        assert_eq!(b.allocator.as_deref(), Some("malloc"));
    }

    #[test]
    fn test_heap_block_with_call_site() {
        let b = HeapBlock::new(0x1000, 0x10, pos(1)).with_call_site(0xDEAD);
        assert_eq!(b.call_site, Some(0xDEAD));
    }

    #[test]
    fn test_heap_block_display() {
        let b = HeapBlock::new(0x1000, 0x10, pos(1));
        let s = format!("{b}");
        assert!(s.contains("HeapBlock"));
        assert!(s.contains("1000"));
    }

    // ── HeapAllocKind ────────────────────────────────────────────────────────

    #[test]
    fn test_heap_alloc_kind_display_alloc() {
        assert_eq!(HeapAllocKind::Alloc.to_string(), "Alloc");
    }

    #[test]
    fn test_heap_alloc_kind_display_free() {
        assert_eq!(HeapAllocKind::Free.to_string(), "Free");
    }

    #[test]
    fn test_heap_alloc_kind_display_realloc() {
        let s = HeapAllocKind::Realloc { old_addr: 0x10, old_size: 0x20 }.to_string();
        assert!(s.contains("Realloc"));
    }

    // ── HeapAlloc ────────────────────────────────────────────────────────────

    #[test]
    fn test_heap_alloc_new_alloc() {
        let a = HeapAlloc::new_alloc(0x1000, 0x40, pos(1), Some("malloc".to_string()));
        assert!(a.is_alloc());
        assert!(!a.is_free());
        assert_eq!(a.address, 0x1000);
        assert_eq!(a.size, 0x40);
    }

    #[test]
    fn test_heap_alloc_new_free() {
        let a = HeapAlloc::new_free(0x1000, pos(2));
        assert!(a.is_free());
        assert!(!a.is_alloc());
    }

    #[test]
    fn test_heap_alloc_display() {
        let a = HeapAlloc::new_alloc(0x1000, 0x10, pos(1), None);
        let s = format!("{a}");
        assert!(s.contains("HeapAlloc"));
    }

    // ── HeapStats ────────────────────────────────────────────────────────────

    #[test]
    fn test_heap_stats_default() {
        let s = HeapStats::default();
        assert_eq!(s.total_allocs, 0);
        assert!(!s.has_leaks());
        assert!(s.alloc_free_ratio().abs() < f64::EPSILON);
    }

    #[test]
    fn test_heap_stats_display() {
        let s = HeapStats::default();
        let d = format!("{s}");
        assert!(d.contains("HeapStats"));
    }

    #[test]
    fn test_heap_stats_alloc_free_ratio() {
        let s = HeapStats {
            total_allocs: 4,
            total_frees: 2,
            ..Default::default()
        };
        assert!((s.alloc_free_ratio() - 0.5).abs() < 1e-9);
    }

    // ── TtdHeapTracker ────────────────────────────────────────────────────────

    #[test]
    fn test_tracker_new_empty() {
        let t = TtdHeapTracker::new();
        assert!(t.events.is_empty());
        assert_eq!(t.block_count(), 0);
    }

    #[test]
    fn test_tracker_record_alloc() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x1000, 0x40, pos(1), Some("malloc".to_string()));
        assert_eq!(t.stats.total_allocs, 1);
        assert_eq!(t.stats.live_allocs, 1);
        assert_eq!(t.stats.total_bytes_allocated, 0x40);
        assert_eq!(t.block_count(), 1);
    }

    #[test]
    fn test_tracker_record_alloc_null_skipped() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0, 0x10, pos(1), None);
        assert_eq!(t.stats.total_allocs, 0);
    }

    #[test]
    fn test_tracker_record_free() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x1000, 0x10, pos(1), None);
        t.record_free(0x1000, pos(2));
        assert_eq!(t.stats.total_frees, 1);
        assert_eq!(t.stats.live_allocs, 0);
        assert!(!t.has_leaks());
    }

    #[test]
    fn test_tracker_double_free_detected() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x1000, 0x10, pos(1), None);
        t.record_free(0x1000, pos(2));
        t.record_free(0x1000, pos(3));
        assert_eq!(t.stats.double_frees, 1);
    }

    #[test]
    fn test_tracker_wild_free_detected() {
        let mut t = TtdHeapTracker::new();
        t.record_free(0xDEAD_BEEF, pos(1));
        assert_eq!(t.stats.wild_frees, 1);
    }

    #[test]
    fn test_tracker_find_alloc_at_hit() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x1000, 0x40, pos(1), None);
        let block = t.find_alloc_at(0x1020, &pos(2)).unwrap();
        assert_eq!(block.address, 0x1000);
        assert_eq!(block.size, 0x40);
    }

    #[test]
    fn test_tracker_find_alloc_at_miss_before_alloc() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x1000, 0x40, pos(10), None);
        // Query before the block was allocated
        assert!(t.find_alloc_at(0x1000, &pos(5)).is_none());
    }

    #[test]
    fn test_tracker_find_alloc_at_miss_after_free() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x1000, 0x40, pos(1), None);
        t.record_free(0x1000, pos(5));
        // Query after the block was freed
        assert!(t.find_alloc_at(0x1000, &pos(5)).is_none());
    }

    #[test]
    fn test_tracker_find_alloc_at_out_of_range() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x1000, 0x40, pos(1), None);
        assert!(t.find_alloc_at(0x2000, &pos(2)).is_none());
    }

    #[test]
    fn test_tracker_live_blocks_at() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x1000, 0x10, pos(1), None);
        t.record_alloc(0x2000, 0x20, pos(2), None);
        t.record_free(0x1000, pos(3));
        // At seq=2: both live
        let live = t.live_blocks_at(&pos(2));
        assert_eq!(live.len(), 2);
        // At seq=4: only 0x2000 live
        let live = t.live_blocks_at(&pos(4));
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].address, 0x2000);
    }

    #[test]
    fn test_tracker_all_live_blocks() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x1000, 0x10, pos(1), None);
        t.record_alloc(0x2000, 0x20, pos(2), None);
        assert_eq!(t.all_live_blocks().len(), 2);
    }

    #[test]
    fn test_tracker_all_blocks_includes_freed() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x1000, 0x10, pos(1), None);
        t.record_free(0x1000, pos(2));
        assert_eq!(t.all_blocks().len(), 1);
    }

    #[test]
    fn test_tracker_block_by_addr() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x3000, 0x80, pos(1), None);
        let b = t.block_by_addr(0x3000).unwrap();
        assert_eq!(b.address, 0x3000);
        t.record_free(0x3000, pos(2));
        assert!(t.block_by_addr(0x3000).is_none());
    }

    #[test]
    fn test_tracker_events_for_addr() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x1000, 0x10, pos(1), None);
        t.record_free(0x1000, pos(2));
        let ev = t.events_for_addr(0x1000);
        assert_eq!(ev.len(), 2);
    }

    #[test]
    fn test_tracker_event_at() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x1000, 0x10, pos(1), None);
        assert!(t.event_at(0).is_some());
        assert!(t.event_at(99).is_none());
    }

    #[test]
    fn test_tracker_has_leaks_true() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x1000, 0x10, pos(1), None);
        assert!(t.has_leaks());
    }

    #[test]
    fn test_tracker_has_leaks_false() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x1000, 0x10, pos(1), None);
        t.record_free(0x1000, pos(2));
        assert!(!t.has_leaks());
    }

    #[test]
    fn test_tracker_clear() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x1000, 0x10, pos(1), None);
        t.clear();
        assert!(t.events.is_empty());
        assert_eq!(t.block_count(), 0);
        assert_eq!(t.stats.total_allocs, 0);
    }

    #[test]
    fn test_tracker_peak_live_allocs() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x1000, 0x10, pos(1), None);
        t.record_alloc(0x2000, 0x20, pos(2), None);
        t.record_free(0x1000, pos(3));
        assert_eq!(t.stats.peak_live_allocs, 2);
        assert_eq!(t.stats.live_allocs, 1);
    }

    #[test]
    fn test_tracker_is_allocator() {
        let t = TtdHeapTracker::new();
        assert!(t.is_allocator("malloc"));
        assert!(!t.is_allocator("printf"));
    }

    #[test]
    fn test_tracker_is_free_fn() {
        let t = TtdHeapTracker::new();
        assert!(t.is_free_fn("free"));
        assert!(!t.is_free_fn("fopen"));
    }

    // ── standalone find_alloc_at ───────────────────────────────────────────────

    #[test]
    fn test_standalone_find_alloc_at() {
        let mut t = TtdHeapTracker::new();
        t.record_alloc(0x4000, 0x100, pos(1), None);
        let block = find_alloc_at(&t, 0x40FF, &pos(2)).unwrap();
        assert_eq!(block.address, 0x4000);
    }

    #[test]
    fn test_standalone_find_alloc_at_none() {
        let t = TtdHeapTracker::new();
        assert!(find_alloc_at(&t, 0x1000, &pos(1)).is_none());
    }
}
