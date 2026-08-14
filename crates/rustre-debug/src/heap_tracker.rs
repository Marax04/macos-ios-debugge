//! `heap_tracker` — Windows heap allocation tracker via breakpoint instrumentation.
//!
//! Instruments `RtlAllocateHeap`, `RtlFreeHeap`, and `RtlReAllocateHeap` by
//! setting software breakpoints at their entry and return points.  At each hit
//! it records the arguments and the return value (allocation address) together
//! with a call-stack snapshot, building a live allocation map.
//!
//! ## vs WinDbg / x64dbg
//! WinDbg's `!heap -s` / `!heap -p -a <addr>` interrogate the NT heap manager
//! state from a live or dump session, but only after the fact.  x64dbg's heap
//! view is similarly post-hoc.  This module instruments allocations
//! *as they happen* so callers get a chronological log usable for leak
//! detection and pattern analysis from an LLM tool-call without a WinDbg
//! extension.  Equivalent to `windbg -c "bp RtlAllocateHeap …"` scripted with
//! `dx @$scriptContents.Invoke()`, but available to any `Debugger` backend.
//!
//! The tracker is backend-agnostic: it drives the abstract [`Debugger`] trait
//! and therefore works equally well over the live Win32 backend,
//! a WinDbg adapter, or a replay backend.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// Errors produced by the heap tracker.
#[derive(Debug, Error)]
pub enum HeapTrackerError {
    #[error("debugger error: {0}")]
    Debugger(String),
    #[error("symbol not found: {0}")]
    SymbolNotFound(String),
    #[error("tracker not started")]
    NotStarted,
}

// ── allocation record ─────────────────────────────────────────────────────────

/// The kind of heap operation that produced this record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HeapOpKind {
    /// `RtlAllocateHeap(heap, flags, size)` → returned `ptr`.
    Allocate,
    /// `RtlFreeHeap(heap, flags, ptr)`.
    Free,
    /// `RtlReAllocateHeap(heap, flags, ptr, size)` → returned `new_ptr`.
    Reallocate,
}

impl std::fmt::Display for HeapOpKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allocate => write!(f, "alloc"),
            Self::Free => write!(f, "free"),
            Self::Reallocate => write!(f, "realloc"),
        }
    }
}

/// One captured heap operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HeapRecord {
    /// Sequential event number (monotonically increasing per session).
    pub seq: u64,
    /// Operation kind.
    pub kind: HeapOpKind,
    /// NT heap handle (first argument to Rtl*Heap).
    pub heap_handle: u64,
    /// Allocation flags (second argument).
    pub flags: u32,
    /// Requested size in bytes (third argument for Alloc/ReAlloc; 0 for Free).
    pub size: u64,
    /// The pointer being freed or reallocated (0 for Alloc; filled for Free/ReAlloc).
    pub old_ptr: u64,
    /// Returned pointer (0 until return breakpoint fires).
    pub returned_ptr: u64,
    /// Call stack PCs at the time of the call (innermost first).
    pub call_stack: Vec<u64>,
    /// Whether this block has been freed.
    pub freed: bool,
}

impl HeapRecord {
    /// Return `true` if this is a live allocation (allocated but not freed).
    ///
    /// `Reallocate` counts: `RtlReAllocateHeap` marks the OLD record freed and
    /// brings a new pointer live, so a realloc'd-then-leaked buffer survives
    /// only as a `Reallocate` record. Restricting this to `Allocate` made the
    /// predicate — and `leak_report`, which is built on it — silently blind to
    /// that entire class of leak.
    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(self.kind, HeapOpKind::Allocate | HeapOpKind::Reallocate)
            && !self.freed
            && self.returned_ptr != 0
    }
}

// ── tracker state ─────────────────────────────────────────────────────────────

/// In-memory state for an active heap-tracking session.
///
/// Thread-safe via `Arc<Mutex<…>>` so multiple event-loop threads can post
/// records concurrently.
#[derive(Debug, Default)]
pub struct HeapTrackerState {
    /// Chronological log of all heap events.
    pub log: Vec<HeapRecord>,
    /// Live allocations keyed by pointer value.
    pub live: HashMap<u64, usize>, // ptr → index into `log`
    /// Next sequence number.
    next_seq: u64,
    /// Pending "call" records awaiting their return-address breakpoint hit,
    /// keyed by thread ID.
    pending: HashMap<u32, usize>, // tid → log index
    /// Pointers that have been freed: ptr → index of the allocation record.
    ///
    /// Kept after the free so a SECOND free of the same pointer is
    /// recognisable. Without it a double free and a free of memory allocated
    /// before tracking started were the same event: nothing.
    freed_ptrs: HashMap<u64, usize>,
    /// Insertion order of `freed_ptrs`, so the oldest can be evicted.
    freed_order: std::collections::VecDeque<u64>,
    /// Frees the tracker has forgotten to stay within [`Self::FREED_MEMORY`].
    ///
    /// Published because forgetting changes what a later double free LOOKS
    /// like: a second free of an evicted pointer is reported as `Untracked`
    /// rather than `DoubleFree`. That is a weaker answer, not a wrong one, but
    /// a caller reading `double_frees()` deserves to know the count is a floor.
    forgotten_frees: u64,
    /// Frees of a pointer this tracker never saw allocated.
    untracked_frees: u64,
    /// Frees of a pointer that had already been freed.
    double_frees: u64,
    /// Calls whose return was never observed, so their result is unknown.
    abandoned_calls: u64,
}

/// What a call to [`HeapTrackerState::on_free`] turned out to be.
///
/// Returned rather than merely counted so a caller driving the breakpoints can
/// react the moment it happens — a double free is the single most valuable
/// thing a heap tracker can report, and it used to be discarded in silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreeOutcome {
    /// The pointer was live and is now freed.
    Matched,
    /// The pointer had already been freed: a double free.
    DoubleFree,
    /// The pointer was never seen allocated — either a genuine invalid free,
    /// or an allocation made before tracking started. The tracker cannot tell
    /// those apart and does not pretend to.
    Untracked,
    /// A null pointer, which is a no-op by contract in every allocator here.
    Null,
}

impl HeapTrackerState {
    /// Create an empty tracker state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a call-site hit (arguments captured; return value not yet known).
    pub fn on_call(
        &mut self,
        tid: u32,
        kind: HeapOpKind,
        heap_handle: u64,
        flags: u32,
        size: u64,
        old_ptr: u64,
        call_stack: Vec<u64>,
    ) {
        let seq = self.next_seq;
        self.next_seq += 1;
        let idx = self.log.len();
        // A thread can only be inside one tracked heap call at a time, so an
        // entry already pending for this tid means the previous call's return
        // was never observed — a missed breakpoint, a killed target, or a
        // nested call this tracker cannot follow. Its `returned_ptr` stays 0,
        // so that allocation never reaches `live` and never appears in the leak
        // report: the report is INCOMPLETE, and this counter is what says so.
        if self.pending.contains_key(&tid) {
            self.abandoned_calls += 1;
        }
        self.log.push(HeapRecord {
            seq,
            kind,
            heap_handle,
            flags,
            size,
            old_ptr,
            returned_ptr: 0,
            call_stack,
            freed: false,
        });
        self.pending.insert(tid, idx);
    }

    /// Record the return-address hit: fill in `returned_ptr` and update the
    /// live-allocation map.
    pub fn on_return(&mut self, tid: u32, returned_ptr: u64) {
        let Some(&idx) = self.pending.get(&tid) else {
            return;
        };
        self.pending.remove(&tid);
        // Read fields before taking a mutable borrow.
        let kind = self.log[idx].kind;
        let old_ptr = self.log[idx].old_ptr;
        self.log[idx].returned_ptr = returned_ptr;
        match kind {
            HeapOpKind::Allocate => {
                if returned_ptr != 0 {
                    self.live.insert(returned_ptr, idx);
                }
            }
            HeapOpKind::Reallocate => {
                if old_ptr != 0 {
                    if let Some(&old_idx) = self.live.get(&old_ptr) {
                        self.log[old_idx].freed = true;
                    }
                    self.live.remove(&old_ptr);
                }
                if returned_ptr != 0 {
                    self.live.insert(returned_ptr, idx);
                }
            }
            HeapOpKind::Free => {} // handled below
        }
    }

    /// Record a free call (called when a `RtlFreeHeap` call-site hits).
    ///
    /// Returns what the free actually was. A pointer that is not live used to
    /// be dropped without a trace, which merged two very different events into
    /// "nothing happened": a **double free** — the defect a heap tracker exists
    /// to catch — and a free of memory allocated before tracking started, which
    /// is ordinary and expected. Neither was reported, and a caller reading
    /// `total_frees` could not tell that anything had been ignored.
    /// How many freed pointers are remembered for double-free detection.
    ///
    /// The set of freed pointers is the one piece of this tracker's state that
    /// grows with the PROGRAM's behaviour rather than with the debugger's: a
    /// process that allocates and frees in a loop adds an entry for every
    /// distinct address it ever returns, and a debugger attached for hours is
    /// exactly the case this tracker exists for. Unbounded there means the
    /// tracker degrades the session it is meant to diagnose.
    ///
    /// Bounded FIFO rather than "clear when large": the useful window is the
    /// RECENT past, because a double free almost always follows its first free
    /// closely, and evicting the oldest keeps precisely that window.
    pub const FREED_MEMORY: usize = 65_536;

    /// Record a freed pointer, evicting the oldest if the window is full.
    fn remember_freed(&mut self, ptr: u64, alloc_idx: usize) {
        if self.freed_ptrs.insert(ptr, alloc_idx).is_none() {
            self.freed_order.push_back(ptr);
        }
        while self.freed_order.len() > Self::FREED_MEMORY {
            if let Some(old) = self.freed_order.pop_front() {
                self.freed_ptrs.remove(&old);
                self.forgotten_frees += 1;
            }
        }
    }

    /// How many freed pointers were dropped to stay inside [`Self::FREED_MEMORY`].
    ///
    /// Non-zero means [`Self::double_frees`] is a floor: a second free of a
    /// forgotten pointer counts as `Untracked` instead.
    #[must_use]
    pub const fn forgotten_frees(&self) -> u64 {
        self.forgotten_frees
    }

    pub fn on_free(&mut self, ptr: u64) -> FreeOutcome {
        if ptr == 0 {
            return FreeOutcome::Null;
        }
        if let Some(alloc_idx) = self.live.remove(&ptr) {
            self.log[alloc_idx].freed = true;
            self.remember_freed(ptr, alloc_idx);
            return FreeOutcome::Matched;
        }
        if self.freed_ptrs.contains_key(&ptr) {
            self.double_frees += 1;
            return FreeOutcome::DoubleFree;
        }
        self.untracked_frees += 1;
        FreeOutcome::Untracked
    }

    /// How many frees named a pointer that had already been freed.
    #[must_use]
    pub const fn double_frees(&self) -> u64 {
        self.double_frees
    }

    /// How many frees named a pointer this tracker never saw allocated.
    #[must_use]
    pub const fn untracked_frees(&self) -> u64 {
        self.untracked_frees
    }

    /// How many tracked calls never had their return observed.
    ///
    /// Every one of them is an allocation whose result is unknown, so
    /// [`Self::leak_report`] is missing at least that many entries. Non-zero
    /// means the report is a floor, not a total.
    #[must_use]
    pub const fn abandoned_calls(&self) -> u64 {
        self.abandoned_calls
    }

    /// Whether the leak report can be read as complete.
    #[must_use]
    pub const fn report_is_complete(&self) -> bool {
        self.abandoned_calls == 0
    }

    /// All live (not-freed) allocations.
    ///
    /// Entries in `self.live` are already known-live (inserted on
    /// alloc/realloc, removed on free), so this only re-checks `freed` /
    /// `returned_ptr` rather than calling [`HeapRecord::is_live`]. That
    /// predicate used to exclude `Reallocate`, which is why this method
    /// bypassed it; `is_live` now accepts `Reallocate` too, so the two agree
    /// — but going through the `live` map stays the cheaper path here.
    #[must_use]
    pub fn live_allocations(&self) -> Vec<&HeapRecord> {
        self.live
            .values()
            .map(|&idx| &self.log[idx])
            .filter(|r| !r.freed && r.returned_ptr != 0)
            .collect()
    }

    /// Total bytes currently live (sum of `size` across live records).
    #[must_use]
    pub fn live_bytes(&self) -> u64 {
        // Saturating: a corrupt or misread size must not wrap the total into a
        // small, believable number.
        self.live_allocations()
            .iter()
            .fold(0u64, |acc, r| acc.saturating_add(r.size))
    }

    /// Number of distinct allocations seen since start.
    #[must_use]
    pub fn total_allocs(&self) -> usize {
        self.log
            .iter()
            .filter(|r| r.kind == HeapOpKind::Allocate)
            .count()
    }

    /// Number of free operations seen.
    #[must_use]
    pub fn total_frees(&self) -> usize {
        self.log
            .iter()
            .filter(|r| r.kind == HeapOpKind::Free)
            .count()
    }

    /// Return all allocations whose call stack contains a PC in the given range
    /// `[lo, hi)` — useful for finding all allocs originating from a module.
    #[must_use]
    pub fn allocations_from_range(&self, lo: u64, hi: u64) -> Vec<&HeapRecord> {
        self.log
            .iter()
            .filter(|r| {
                r.kind == HeapOpKind::Allocate
                    && r.call_stack.iter().any(|&pc| pc >= lo && pc < hi)
            })
            .collect()
    }

    /// Leak report: all allocations that were never freed.
    ///
    /// `Reallocate` counts as an allocation here, for the same reason
    /// [`live_allocations`](Self::live_allocations) skips its `kind` check:
    /// `RtlReAllocateHeap` brings a NEW pointer live and marks the old
    /// record freed, so a buffer that was realloc'd and then leaked survives
    /// only as a `Reallocate` record. Filtering on `Allocate` alone made this
    /// method report "no leaks" while `live_allocations()` — reading the same
    /// state — reported the leaked buffer.
    #[must_use]
    pub fn leak_report(&self) -> Vec<&HeapRecord> {
        self.log
            .iter()
            .filter(|r| r.is_live())
            .collect()
    }
}

// ── breakpoint address resolver ───────────────────────────────────────────────

/// Known Windows heap function RVAs relative to ntdll.dll.
///
/// These are stable across Windows 10/11 builds for the x64 ABI.  The
/// symbol-server path is the preferred resolution; these constants are a
/// fallback for offline analysis.
pub mod rtl_rvas {
    /// Approximate RVA of `RtlAllocateHeap` in ntdll.dll on Windows 10 x64.
    /// Exact offset varies by build; use symbol resolution when possible.
    pub const ALLOC: u32 = 0x0002_B420;
    /// Approximate RVA of `RtlFreeHeap`.
    pub const FREE: u32 = 0x0002_D300;
    /// Approximate RVA of `RtlReAllocateHeap`.
    pub const REALLOC: u32 = 0x0002_E100;
}

/// Addresses at which to set breakpoints for heap tracking.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HeapBreakpointSet {
    /// Entry breakpoint for `RtlAllocateHeap`.
    pub alloc_entry: u64,
    /// Entry breakpoint for `RtlFreeHeap`.
    pub free_entry: u64,
    /// Entry breakpoint for `RtlReAllocateHeap`.
    pub realloc_entry: u64,
}

impl HeapBreakpointSet {
    /// Compute breakpoint addresses given the load base of `ntdll.dll`.
    #[must_use]
    pub fn from_ntdll_base(ntdll_base: u64) -> Self {
        Self {
            alloc_entry: ntdll_base + u64::from(rtl_rvas::ALLOC),
            free_entry: ntdll_base + u64::from(rtl_rvas::FREE),
            realloc_entry: ntdll_base + u64::from(rtl_rvas::REALLOC),
        }
    }
}

/// Shared handle to a heap tracker session.
pub type HeapTrackerHandle = Arc<Mutex<HeapTrackerState>>;

/// Create a new shared heap tracker.
#[must_use]
pub fn new_tracker() -> HeapTrackerHandle {
    Arc::new(Mutex::new(HeapTrackerState::new()))
}

// ── calling convention helpers (x64 Windows) ─────────────────────────────────

/// Which calling convention a register snapshot follows.
///
/// This crate debugs both x64 and ARM64 targets (the Apple backend is ARM64),
/// and a register snapshot carries no self-description: `{"x0": …}` and
/// `{"rcx": …}` are the same Rust type. Naming the ABI at the call site is what
/// keeps one from being read as the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapAbi {
    /// x64 Windows: integer arguments in RCX, RDX, R8, R9; return in RAX.
    Win64,
    /// AAPCS64 (ARM64): integer arguments in X0-X3; return in X0.
    Aapcs64,
}

impl HeapAbi {
    /// The first four integer-argument registers, in order.
    #[must_use]
    pub fn arg_regs(self) -> [&'static str; 4] {
        match self {
            Self::Win64 => ["rcx", "rdx", "r8", "r9"],
            // Taken from `ios::arm64::aapcs64`, which is the crate's single
            // source of truth for this ABI, rather than respelled here.
            Self::Aapcs64 => {
                let a = crate::ios::arm64::aapcs64::INT_ARG_REGS;
                [a[0], a[1], a[2], a[3]]
            }
        }
    }

    /// The integer return-value register.
    #[must_use]
    pub fn return_reg(self) -> &'static str {
        match self {
            Self::Win64 => "rax",
            Self::Aapcs64 => crate::ios::arm64::aapcs64::INT_RETURN_REG,
        }
    }
}

/// Read the first `n` argument registers, or `None` if any of them is absent.
///
/// All-or-nothing on purpose. Filling a missing register with 0 produces a
/// value that looks like a real one — heap handle 0, size 0 — and the tracker
/// has no way to tell it apart from a genuine reading.
fn args<const N: usize>(
    regs: &std::collections::HashMap<String, u64>,
    abi: HeapAbi,
) -> Option<[u64; N]> {
    let names = abi.arg_regs();
    let mut out = [0_u64; N];
    for (slot, name) in out.iter_mut().zip(names.iter()) {
        *slot = regs.get(*name).copied()?;
    }
    Some(out)
}

/// Extract `RtlAllocateHeap` arguments from an x64 register snapshot.
///
/// - RCX = HeapHandle, RDX = Flags, R8 = Size
///
/// Returns `None` if the snapshot does not carry all three — see
/// [`alloc_args_with_abi`] for a non-x64 target.
#[must_use]
pub fn alloc_args_from_regs(regs: &std::collections::HashMap<String, u64>) -> Option<(u64, u32, u64)> {
    alloc_args_with_abi(regs, HeapAbi::Win64)
}

/// Extract `RtlAllocateHeap` arguments under an explicit ABI.
#[must_use]
pub fn alloc_args_with_abi(
    regs: &std::collections::HashMap<String, u64>,
    abi: HeapAbi,
) -> Option<(u64, u32, u64)> {
    let [heap, flags, size] = args::<3>(regs, abi)?;
    Some((heap, flags as u32, size))
}

/// Extract `RtlFreeHeap` arguments from an x64 register snapshot.
///
/// - RCX = HeapHandle, RDX = Flags, R8 = HeapBase (ptr to free)
#[must_use]
pub fn free_args_from_regs(regs: &std::collections::HashMap<String, u64>) -> Option<(u64, u32, u64)> {
    free_args_with_abi(regs, HeapAbi::Win64)
}

/// Extract `RtlFreeHeap` arguments under an explicit ABI.
#[must_use]
pub fn free_args_with_abi(
    regs: &std::collections::HashMap<String, u64>,
    abi: HeapAbi,
) -> Option<(u64, u32, u64)> {
    let [heap, flags, ptr] = args::<3>(regs, abi)?;
    Some((heap, flags as u32, ptr))
}

/// Extract `RtlReAllocateHeap` arguments from an x64 register snapshot.
///
/// - RCX = HeapHandle, RDX = Flags, R8 = MemoryPointer (old ptr), R9 = Size
#[must_use]
pub fn realloc_args_from_regs(
    regs: &std::collections::HashMap<String, u64>,
) -> Option<(u64, u32, u64, u64)> {
    realloc_args_with_abi(regs, HeapAbi::Win64)
}

/// Extract `RtlReAllocateHeap` arguments under an explicit ABI.
#[must_use]
pub fn realloc_args_with_abi(
    regs: &std::collections::HashMap<String, u64>,
    abi: HeapAbi,
) -> Option<(u64, u32, u64, u64)> {
    let [heap, flags, old_ptr, size] = args::<4>(regs, abi)?;
    Some((heap, flags as u32, old_ptr, size))
}

/// Extract the return value (allocated pointer) from an x64 register snapshot.
///
/// `None` when the register is absent: a returned null pointer means "the
/// allocation failed", so it must not double as "the register was missing".
#[must_use]
pub fn return_value_from_regs(regs: &std::collections::HashMap<String, u64>) -> Option<u64> {
    return_value_with_abi(regs, HeapAbi::Win64)
}

/// Extract the return value under an explicit ABI.
#[must_use]
pub fn return_value_with_abi(
    regs: &std::collections::HashMap<String, u64>,
    abi: HeapAbi,
) -> Option<u64> {
    regs.get(abi.return_reg()).copied()
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    /// The freed-pointer set must not grow with the PROGRAM.
    ///
    /// It is the one part of this tracker that scales with how much the target
    /// allocates rather than with how long the debugger runs, and a process
    /// that allocates in a loop adds an entry for every distinct address it
    /// ever returns. A debugger attached for hours is exactly the case this
    /// tracker exists for, so unbounded there means degrading the session it is
    /// meant to diagnose.
    ///
    /// Forgetting is not free and the test says so: a double free of an evicted
    /// pointer is reported as `Untracked`, a weaker answer, and
    /// `forgotten_frees()` is what tells a caller that `double_frees()` has
    /// become a floor.
    #[test]
    fn the_freed_pointer_window_is_bounded_and_says_when_it_forgot() {
        let mut t = HeapTrackerState::default();
        let cap = HeapTrackerState::FREED_MEMORY;

        // Allocate and free one more distinct pointer than the window holds.
        for i in 0..=cap as u64 {
            let ptr = 0x1_0000 + i * 16;
            t.on_call(1, HeapOpKind::Allocate, 0x100, 0, 16, 0, Vec::new());
            t.on_return(1, ptr);
            assert_eq!(t.on_free(ptr), FreeOutcome::Matched);
        }

        assert_eq!(t.forgotten_frees(), 1, "exactly one pointer should have aged out");

        // The OLDEST is forgotten: freeing it again is no longer recognised as
        // a double free, and the tracker says so through the counter above
        // rather than pretending.
        assert_eq!(t.on_free(0x1_0000), FreeOutcome::Untracked);

        // The most recent is still remembered, which is the window that matters.
        let newest = 0x1_0000 + cap as u64 * 16;
        assert_eq!(t.on_free(newest), FreeOutcome::DoubleFree);
    }

    use super::*;

    #[test]
    fn basic_alloc_free_cycle() {
        let mut state = HeapTrackerState::new();

        // Simulate RtlAllocateHeap call on thread 1
        state.on_call(
            1,
            HeapOpKind::Allocate,
            0xDEAD_0000,
            0,
            128,
            0,
            vec![0x1000, 0x2000],
        );
        // Return: ptr = 0xABC0_0000
        state.on_return(1, 0xABC0_0000);

        assert_eq!(state.total_allocs(), 1);
        assert_eq!(state.live_allocations().len(), 1);
        assert_eq!(state.live_bytes(), 128);

        // Free it
        state.on_call(2, HeapOpKind::Free, 0xDEAD_0000, 0, 0, 0xABC0_0000, vec![0x3000]);
        state.on_free(0xABC0_0000);

        assert_eq!(state.live_allocations().len(), 0);
        assert_eq!(state.live_bytes(), 0);
        assert_eq!(state.leak_report().len(), 0);
    }

    #[test]
    fn leak_detection() {
        let mut state = HeapTrackerState::new();
        state.on_call(1, HeapOpKind::Allocate, 0x1, 0, 64, 0, vec![0x100]);
        state.on_return(1, 0xCAFE_0000);
        // No free — should appear in leak report
        assert_eq!(state.leak_report().len(), 1);
        assert_eq!(state.leak_report()[0].returned_ptr, 0xCAFE_0000);
    }

    /// A buffer that was `RtlReAllocateHeap`d and then never freed IS a leak,
    /// and `live_allocations()` correctly reports it — but `leak_report()`
    /// filtered on `kind == Allocate` and so returned nothing, because the
    /// surviving record has kind `Reallocate` (the original `Allocate` record
    /// was marked `freed` by the realloc path).
    ///
    /// The two methods contradicted each other on the same state, and
    /// `live_allocations()` even carries a comment explaining exactly why the
    /// `kind` check must be skipped — the reasoning was simply never applied
    /// to its twin. A leak-detector that answers "no leaks" while a real leak
    /// is live is the confidently-wrong failure mode, not a missing feature.
    #[test]
    fn a_reallocated_buffer_that_is_never_freed_is_reported_as_a_leak() {
        let mut state = HeapTrackerState::new();
        state.on_call(1, HeapOpKind::Allocate, 0x1, 0, 32, 0, vec![0x100]);
        state.on_return(1, 0x1000_0000);
        state.on_call(1, HeapOpKind::Reallocate, 0x1, 0, 64, 0x1000_0000, vec![0x200]);
        state.on_return(1, 0x2000_0000);

        // Both views must agree: exactly one live, leaked buffer.
        assert_eq!(state.live_allocations().len(), 1);
        let leaks = state.leak_report();
        assert_eq!(leaks.len(), 1, "the realloc'd buffer is leaked");
        assert_eq!(leaks[0].returned_ptr, 0x2000_0000);
        assert_eq!(leaks[0].size, 64);

        // ...and freeing it must clear the report, so the fix cannot be
        // "always report reallocs".
        state.on_free(0x2000_0000);
        assert!(state.leak_report().is_empty(), "freed buffer is not a leak");
        assert!(state.live_allocations().is_empty());
    }

    #[test]
    fn realloc_replaces_live() {
        let mut state = HeapTrackerState::new();
        // Initial alloc
        state.on_call(1, HeapOpKind::Allocate, 0x1, 0, 32, 0, vec![0x100]);
        state.on_return(1, 0x1000_0000);
        assert_eq!(state.live_allocations().len(), 1);

        // Realloc
        state.on_call(
            1,
            HeapOpKind::Reallocate,
            0x1,
            0,
            64,
            0x1000_0000,
            vec![0x200],
        );
        state.on_return(1, 0x2000_0000);

        // Old pointer gone, new one live
        assert_eq!(state.live_allocations().len(), 1);
        assert_eq!(state.live_allocations()[0].returned_ptr, 0x2000_0000);
        assert_eq!(state.live_bytes(), 64);
    }

    #[test]
    fn allocations_from_range() {
        let mut state = HeapTrackerState::new();
        state.on_call(1, HeapOpKind::Allocate, 0x1, 0, 16, 0, vec![0x4000, 0x5000]);
        state.on_return(1, 0xAA00);
        state.on_call(2, HeapOpKind::Allocate, 0x1, 0, 32, 0, vec![0x9000]);
        state.on_return(2, 0xBB00);

        let in_range = state.allocations_from_range(0x4000, 0x6000);
        assert_eq!(in_range.len(), 1);
        assert_eq!(in_range[0].returned_ptr, 0xAA00);
    }

    #[test]
    fn breakpoint_set_from_ntdll_base() {
        let bp = HeapBreakpointSet::from_ntdll_base(0x7FF8_0000_0000);
        assert_eq!(bp.alloc_entry, 0x7FF8_0000_0000 + u64::from(rtl_rvas::ALLOC));
        assert_eq!(bp.free_entry, 0x7FF8_0000_0000 + u64::from(rtl_rvas::FREE));
    }

    #[test]
    fn arg_extraction_from_regs() {
        let mut regs = std::collections::HashMap::new();
        regs.insert("rcx".into(), 0xDEAD_BEEF_u64);
        regs.insert("rdx".into(), 0x8_u64);
        regs.insert("r8".into(), 256_u64);
        let (heap, flags, size) = alloc_args_from_regs(&regs).expect("all three regs present");
        assert_eq!(heap, 0xDEAD_BEEF);
        assert_eq!(flags, 8);
        assert_eq!(size, 256);
    }

    /// A register snapshot from the ARM64 backend must not be silently read as
    /// an x64 one.
    ///
    /// `rcx`/`rdx`/`r8` do not exist on ARM64; the arguments live in `x0`-`x3`.
    /// The x64 extractors used to answer `(0, 0, 0)` for such a snapshot, which
    /// the tracker then recorded as a real zero-byte allocation from heap 0 —
    /// a fabricated event, not a failure. Absence of the registers must be
    /// reported, and the AAPCS64 snapshot must be readable with the matching
    /// ABI.
    #[test]
    fn arm64_snapshot_is_not_silently_read_as_x64() {
        let mut regs = std::collections::HashMap::new();
        regs.insert("x0".into(), 0xDEAD_BEEF_u64);
        regs.insert("x1".into(), 0x8_u64);
        regs.insert("x2".into(), 256_u64);

        assert_eq!(
            alloc_args_from_regs(&regs),
            None,
            "an ARM64 snapshot has no rcx/rdx/r8: reading it as x64 fabricates a zero-byte alloc"
        );
        assert_eq!(
            alloc_args_with_abi(&regs, HeapAbi::Aapcs64),
            Some((0xDEAD_BEEF, 8, 256))
        );

        // A partial x64 snapshot is just as wrong as a foreign one: `size` is
        // the field a missing register silently zeroes, and a zero size is a
        // plausible-looking value, not an obvious one.
        let mut partial = std::collections::HashMap::new();
        partial.insert("rcx".into(), 0xDEAD_BEEF_u64);
        partial.insert("rdx".into(), 0x8_u64);
        assert_eq!(alloc_args_from_regs(&partial), None, "missing r8 must not read as size 0");
    }

    #[test]
    fn heap_op_kind_display() {
        assert_eq!(HeapOpKind::Allocate.to_string(), "alloc");
        assert_eq!(HeapOpKind::Free.to_string(), "free");
        assert_eq!(HeapOpKind::Reallocate.to_string(), "realloc");
    }

    /// A double free must be REPORTED, not silently ignored.
    ///
    /// `on_free` used to drop any pointer that was not live. That merged two
    /// very different events into "nothing happened": a double free - the
    /// defect this tracker exists to catch - and a free of memory allocated
    /// before tracking started, which is ordinary. Neither reached the caller.
    #[test]
    fn a_double_free_is_distinguished_from_a_free_of_untracked_memory() {
        let mut t = HeapTrackerState::new();
        t.on_call(1, HeapOpKind::Allocate, 0x100, 0, 64, 0, vec![0x401000]);
        t.on_return(1, 0xAAAA);
        assert_eq!(t.live_bytes(), 64);

        assert_eq!(t.on_free(0xAAAA), FreeOutcome::Matched);
        assert_eq!(t.live_bytes(), 0);

        // The same pointer again: a double free, not a no-op.
        assert_eq!(t.on_free(0xAAAA), FreeOutcome::DoubleFree);
        assert_eq!(t.double_frees(), 1);

        // A pointer this tracker never saw: honestly reported as unknown
        // rather than as a double free, because the allocation may simply
        // predate tracking.
        assert_eq!(t.on_free(0xBBBB), FreeOutcome::Untracked);
        assert_eq!(t.untracked_frees(), 1);
        assert_eq!(t.double_frees(), 1, "an untracked free is not a double free");

        // NULL is a no-op by contract in every allocator here.
        assert_eq!(t.on_free(0), FreeOutcome::Null);
        assert_eq!(t.untracked_frees(), 1);
    }

    /// A call whose return was never seen makes the leak report a FLOOR, and
    /// the tracker must say so.
    ///
    /// The allocation stays with `returned_ptr == 0`, so it never enters the
    /// live map and never appears in the leak report. A caller reading zero
    /// leaks would conclude the target leaks nothing, when the truth is that
    /// the tracker lost sight of an allocation.
    #[test]
    fn an_abandoned_call_marks_the_leak_report_as_incomplete() {
        let mut t = HeapTrackerState::new();
        assert!(t.report_is_complete(), "a fresh tracker has seen nothing to lose");

        // Thread 7 enters an allocation and its return is never observed,
        // then the same thread enters another one.
        t.on_call(7, HeapOpKind::Allocate, 0x100, 0, 32, 0, vec![0x401000]);
        t.on_call(7, HeapOpKind::Allocate, 0x100, 0, 48, 0, vec![0x401020]);
        t.on_return(7, 0xCCCC);

        assert_eq!(t.abandoned_calls(), 1);
        assert!(!t.report_is_complete(), "one allocation was lost, so the report is a floor");
        // Only the second allocation is visible.
        assert_eq!(t.live_bytes(), 48);
        assert_eq!(t.leak_report().len(), 1);
    }

}
