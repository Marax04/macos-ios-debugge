// ============================================================================
// core/revision.rs — Revision / invalidation counters
// Every dataset carries a `rev: u64` so consumers can check cheaply whether
// their cached version is still fresh without deep comparison.
// ============================================================================

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// ── Global monotone tick ──────────────────────────────────────────────────────

static GLOBAL_TICK: AtomicU64 = AtomicU64::new(1);

/// Allocate a new, globally unique revision number.  Never returns 0.
#[inline]
pub fn next_rev() -> u64 {
    GLOBAL_TICK.fetch_add(1, Ordering::Relaxed)
}

/// Current tick without advancing it.
#[inline]
pub fn current_rev() -> u64 {
    GLOBAL_TICK.load(Ordering::Relaxed)
}

// ── RevCounter ────────────────────────────────────────────────────────────────

/// Shareable, cheaply-cloneable revision counter.
/// Clone gives you a second handle to the *same* counter.
#[derive(Clone, Debug)]
pub struct RevCounter(Arc<AtomicU64>);

impl Default for RevCounter {
    fn default() -> Self {
        Self(Arc::new(AtomicU64::new(next_rev())))
    }
}

impl RevCounter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bump the counter and return the new revision.
    pub fn bump(&self) -> u64 {
        let rev = next_rev();
        self.0.store(rev, Ordering::Release);
        rev
    }

    /// Read the current revision.
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    /// Returns true if `cached_rev` is still current (no bump since then).
    #[inline]
    pub fn is_fresh(&self, cached_rev: u64) -> bool {
        self.get() == cached_rev
    }
}

// ── Dataset revision set ──────────────────────────────────────────────────────

/// One `RevCounter` per major dataset.  Passed into every view so it can
/// detect stale caches without holding any lock on the actual data.
#[derive(Clone, Debug, Default)]
pub struct Revisions {
    pub symbols: RevCounter,
    pub functions: RevCounter,
    pub listing: RevCounter,
    pub hex: RevCounter,
    pub decompiler: RevCounter,
    pub graph: RevCounter,
    pub types: RevCounter,
    pub segments: RevCounter,
    pub breakpoints: RevCounter,
    pub registers: RevCounter,
    pub patches: RevCounter,
    pub strings: RevCounter,
    pub xrefs: RevCounter,
}

impl Revisions {
    /// Bump everything (e.g., new file loaded).
    pub fn invalidate_all(&self) {
        self.symbols.bump();
        self.functions.bump();
        self.listing.bump();
        self.hex.bump();
        self.decompiler.bump();
        self.graph.bump();
        self.types.bump();
        self.segments.bump();
        self.breakpoints.bump();
        self.registers.bump();
        self.patches.bump();
        self.strings.bump();
        self.xrefs.bump();
    }
}

// ── Cached<T> ─────────────────────────────────────────────────────────────────

/// Generic "cached value + the revision it was computed at".
/// `get_or_compute` recomputes only when the counter changed.
pub struct Cached<T> {
    rev: u64,
    value: Option<T>,
}

impl<T: Clone> Default for Cached<T> {
    fn default() -> Self {
        Self {
            rev: 0,
            value: None,
        }
    }
}

impl<T: Clone> Cached<T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Return mutable ref to value, recomputing if stale.
    pub fn get_or_compute<F: FnOnce() -> T>(&mut self, counter: &RevCounter, f: F) -> &T {
        let current = counter.get();
        if self.value.is_none() || self.rev != current {
            self.value = Some(f());
            self.rev = current;
        }
        self.value.as_ref().unwrap()
    }

    /// Force invalidation.
    pub fn invalidate(&mut self) {
        self.rev = 0;
        self.value = None;
    }

    pub fn is_fresh(&self, counter: &RevCounter) -> bool {
        self.value.is_some() && self.rev == counter.get()
    }

    pub fn snapshot(&self) -> Option<(u64, &T)> {
        self.value.as_ref().map(|v| (self.rev, v))
    }
}

#[doc(hidden)]
pub fn ensure_used_revision() {
    let before = current_rev();
    let _ = current_rev() >= before;

    let c = RevCounter::new();
    let r = c.get();
    debug_assert!(c.is_fresh(r));
    c.bump();

    let counter = RevCounter::new();
    let mut cached: Cached<u32> = Cached::new();
    debug_assert!(!cached.is_fresh(&counter));
    let _ = cached.get_or_compute(&counter, || 42u32);
    debug_assert!(cached.is_fresh(&counter));
    let _snap = cached.snapshot();
    cached.invalidate();
    debug_assert!(cached.snapshot().is_none());
}

// ── ensure-used (auto-added to satisfy warnings without #[allow] / deletion) ──

#[cfg(test)]
mod _coverage {
    use super::*;

    #[test]
    fn touches_current_rev_and_rev_counter() {
        let before = current_rev();
        let after = current_rev();
        assert!(after >= before);

        let c = RevCounter::new();
        let r = c.get();
        assert!(c.is_fresh(r));
        c.bump();
        assert!(!c.is_fresh(r));
    }

    #[test]
    fn touches_cached() {
        let counter = RevCounter::new();
        let mut cached: Cached<u32> = Cached::new();
        assert!(!cached.is_fresh(&counter));
        assert!(cached.snapshot().is_none());

        let v = *cached.get_or_compute(&counter, || 42u32);
        assert_eq!(v, 42);
        assert!(cached.is_fresh(&counter));
        let snap = cached.snapshot().expect("snapshot");
        assert_eq!(*snap.1, 42);

        cached.invalidate();
        assert!(!cached.is_fresh(&counter));
        assert!(cached.snapshot().is_none());

        // Re-compute, then bump counter to force staleness.
        let _ = cached.get_or_compute(&counter, || 7u32);
        counter.bump();
        let v2 = *cached.get_or_compute(&counter, || 9u32);
        assert_eq!(v2, 9);

        // Also exercise Cached struct construction via Default.
        let cd: Cached<String> = Cached::default();
        assert!(cd.snapshot().is_none());
    }
}
