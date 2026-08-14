//! `MSan` tracking: uninitialized memory shadow, propagation through operations,
//! branch checks, and origin tracking.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicU64, Ordering};
use parking_lot::Mutex;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum MsanError {
    #[error("use of uninitialized value at {addr:#x} (origin: {origin})")]
    UseOfUninit { addr: u64, origin: OriginId },

    #[error("uninitialized branch condition at PC {pc:#x} (origin: {origin})")]
    UninitBranch { pc: u64, origin: OriginId },

    #[error("uninitialized value passed to system call at PC {pc:#x}")]
    UninitSyscall { pc: u64 },

    #[error("uninitialized value in comparison at PC {pc:#x}")]
    UninitComparison { pc: u64 },

    #[error("shadow memory not initialised for address {0:#x}")]
    ShadowUninitialised(u64),
}

pub type MsanResult<T> = Result<T, MsanError>;

// ─── origin tracking ─────────────────────────────────────────────────────────

/// An origin ID uniquely identifies where an uninitialized value was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OriginId(pub u32);

impl OriginId {
    pub const UNKNOWN: Self = Self(0);

    #[must_use]
    pub const fn is_unknown(self) -> bool {
        self.0 == 0
    }
}

impl std::fmt::Display for OriginId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_unknown() {
            write!(f, "<unknown-origin>")
        } else {
            write!(f, "origin#{}", self.0)
        }
    }
}

/// A description of an origin: allocation site stack trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Origin {
    pub id: OriginId,
    /// Program counters of the allocation stack trace.
    pub stack_trace: Vec<u64>,
    /// Human-readable label (e.g. "heap allocation", "stack variable").
    pub label: String,
}

/// Allocator for unique origin IDs.
#[derive(Debug, Default)]
pub struct OriginStore {
    next_id: AtomicU64,
    origins: Mutex<HashMap<u32, Origin>>,
}

impl OriginStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_origin(&self, stack_trace: Vec<u64>, label: impl Into<String>) -> OriginId {
        let id = crate::cast::u64_to_u32(self.next_id.fetch_add(1, Ordering::Relaxed)) + 1;
        let origin = Origin { id: OriginId(id), stack_trace, label: label.into() };
        self.origins.lock().insert(id, origin);
        OriginId(id)
    }

    #[must_use]
    pub fn get(&self, id: OriginId) -> Option<Origin> {
        self.origins.lock().get(&id.0).cloned()
    }
}

// ─── shadow memory ────────────────────────────────────────────────────────────

/// Uninitialized shadow: 1 byte per application byte.
/// Shadow 0 = initialized; shadow 0xFF = fully uninitialized.
/// Partial initialisation: bitmask where 1 = uninitialized bit.
#[derive(Debug, Default)]
pub struct MsanShadow {
    /// Shadow bytes.  Missing entries are treated as fully initialized (0).
    shadow: RwLock<HashMap<u64, u8>>,
    /// Origin per 8-byte granule.
    origins: RwLock<HashMap<u64, OriginId>>,
}

impl MsanShadow {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    const fn origin_key(addr: u64) -> u64 {
        addr & !7
    }

    /// Read the shadow byte for `addr`.
    ///
    /// # Panics
    /// Documented for clippy.
    #[must_use]
    pub fn read_shadow(&self, addr: u64) -> u8 {
        self.shadow.read().unwrap().get(&addr).copied().unwrap_or(0)
    }

    /// Write a shadow byte.
    ///
    /// # Panics
    /// Documented for clippy.
    pub fn write_shadow(&self, addr: u64, value: u8) {
        let mut s = self.shadow.write().unwrap();
        if value == 0 {
            s.remove(&addr);
        } else {
            s.insert(addr, value);
        }
    }

    /// Mark `size` bytes at `addr` as uninitialized with a given origin.
    ///
    /// # Panics
    /// Documented for clippy.
    pub fn mark_uninit(&self, addr: u64, size: usize, origin: OriginId) {
        for i in 0..size as u64 {
            self.write_shadow(addr.saturating_add(i), 0xFF);
        }
        let key = Self::origin_key(addr);
        self.origins.write().unwrap().insert(key, origin);
    }

    /// Mark `size` bytes at `addr` as initialized.
    pub fn mark_init(&self, addr: u64, size: usize) {
        for i in 0..size as u64 {
            self.write_shadow(addr.saturating_add(i), 0);
        }
    }

    /// Check whether any byte in `[addr, addr+size)` is uninitialized.
    ///
    /// Lock order: always acquire `shadow` before `origins` to prevent livelock.
    /// The shadow guard is released before acquiring the origins guard.
    ///
    /// # Panics
    /// Documented for clippy.
    #[must_use]
    pub fn is_uninit(&self, addr: u64, size: usize) -> Option<(u64, OriginId)> {
        // Phase 1: find the first uninit byte under the shadow read-lock.
        let uninit_addr = {
            let s = self.shadow.read().unwrap();
            let mut found = None;
            for i in 0..size as u64 {
                if s.get(&addr.saturating_add(i)).copied().unwrap_or(0) != 0 {
                    found = Some(addr.saturating_add(i));
                    break;
                }
            }
            found
            // shadow read-lock is released here
        };

        // Phase 2: look up origin under a separate origins read-lock (no shadow held).
        uninit_addr.map(|bad_addr| {
            let key = Self::origin_key(bad_addr);
            let origin = self
                .origins
                .read()
                .unwrap()
                .get(&key)
                .copied()
                .unwrap_or(OriginId::UNKNOWN);
            (bad_addr, origin)
        })
    }

    /// Get the origin for a given address.
    ///
    /// # Panics
    /// Documented for clippy.
    #[must_use]
    pub fn origin_for(&self, addr: u64) -> OriginId {
        let key = Self::origin_key(addr);
        self.origins.read().unwrap().get(&key).copied().unwrap_or(OriginId::UNKNOWN)
    }

    /// Copy shadow bytes from `src` to `dst` (models `memcpy` propagation).
    ///
    /// # Panics
    /// Documented for clippy.
    pub fn propagate_copy(&self, dst: u64, src: u64, size: usize) {
        let shadows: Vec<u8> = (0..size as u64)
            .map(|i| self.read_shadow(src.saturating_add(i)))
            .collect();
        let origins: Vec<OriginId> = (0..size as u64)
            .map(|i| self.origin_for(src.saturating_add(i)))
            .collect();
        for (i, (&sh, &orig)) in shadows.iter().zip(origins.iter()).enumerate() {
            self.write_shadow(dst.saturating_add(i as u64), sh);
            if sh != 0 {
                self.origins.write().unwrap().insert(Self::origin_key(dst.saturating_add(i as u64)), orig);
            }
        }
    }

    /// Propagate through a binary operation: shadow of result = `shadow_a` | `shadow_b`.
    #[must_use]
    pub fn propagate_binop(&self, a: u64, b: u64, size: usize) -> Vec<u8> {
        (0..size as u64)
            .map(|i| self.read_shadow(a.saturating_add(i)) | self.read_shadow(b.saturating_add(i)))
            .collect()
    }

    /// Total number of uninitialized bytes tracked.
    ///
    /// # Panics
    /// Documented for clippy.
    #[must_use]
    pub fn uninit_byte_count(&self) -> usize {
        self.shadow.read().unwrap().values().filter(|&&b| b != 0).count()
    }
}

// ─── MSan violation record ───────────────────────────────────────────────────

/// A recorded `MSan` violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsanViolation {
    pub kind: MsanViolationKind,
    pub pc: u64,
    pub address: u64,
    pub origin: OriginId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MsanViolationKind {
    UseOfUninitValue,
    UninitBranchCondition,
    UninitSystemCall,
    UninitComparison,
    UninitMemcpy,
}

impl std::fmt::Display for MsanViolationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UseOfUninitValue => write!(f, "use-of-uninitialized-value"),
            Self::UninitBranchCondition => write!(f, "uninitialized-branch-condition"),
            Self::UninitSystemCall => write!(f, "uninitialized-syscall-argument"),
            Self::UninitComparison => write!(f, "uninitialized-comparison"),
            Self::UninitMemcpy => write!(f, "uninitialized-memcpy-source"),
        }
    }
}

// ─── MSan runtime ─────────────────────────────────────────────────────────────

/// Central `MSan` runtime: shadow memory + violation log + origin store.
#[derive(Debug)]
pub struct MsanRuntime {
    pub shadow: Arc<MsanShadow>,
    pub origins: Arc<OriginStore>,
    violations: Mutex<Vec<MsanViolation>>,
    halt_on_first: bool,
}

impl MsanRuntime {
    #[must_use]
    pub fn new(halt_on_first: bool) -> Self {
        Self {
            shadow: Arc::new(MsanShadow::new()),
            origins: Arc::new(OriginStore::new()),
            violations: Mutex::new(Vec::new()),
            halt_on_first,
        }
    }

    fn record(&self, v: MsanViolation) {
        assert!(!self.halt_on_first, "MSan: {} at {:#x} (origin: {})", v.kind, v.address, v.origin);
        self.violations.lock().push(v);
    }

    /// Called when a value at `addr` of `size` bytes is used.
    pub fn check_use(&self, pc: u64, addr: u64, size: usize) {
        if let Some((bad_addr, origin)) = self.shadow.is_uninit(addr, size) {
            self.record(MsanViolation {
                kind: MsanViolationKind::UseOfUninitValue,
                pc,
                address: bad_addr,
                origin,
            });
        }
    }

    /// Called on a conditional branch where the condition variable lives at `addr`.
    pub fn check_branch_condition(&self, pc: u64, cond_addr: u64, size: usize) {
        if let Some((bad_addr, origin)) = self.shadow.is_uninit(cond_addr, size) {
            self.record(MsanViolation {
                kind: MsanViolationKind::UninitBranchCondition,
                pc,
                address: bad_addr,
                origin,
            });
        }
    }

    /// Called when a value is passed to a syscall.
    pub fn check_syscall_arg(&self, pc: u64, addr: u64, size: usize) {
        if let Some((bad_addr, origin)) = self.shadow.is_uninit(addr, size) {
            self.record(MsanViolation {
                kind: MsanViolationKind::UninitSystemCall,
                pc,
                address: bad_addr,
                origin,
            });
        }
    }

    /// Called on comparison instructions.
    pub fn check_comparison(&self, pc: u64, lhs_addr: u64, rhs_addr: u64, size: usize) {
        if let Some((bad_addr, origin)) = self
            .shadow
            .is_uninit(lhs_addr, size)
            .or_else(|| self.shadow.is_uninit(rhs_addr, size))
        {
            self.record(MsanViolation {
                kind: MsanViolationKind::UninitComparison,
                pc,
                address: bad_addr,
                origin,
            });
        }
    }

    // ── instrumentation helpers ──────────────────────────────────────────────

    /// Record a heap allocation as uninitialized (models `malloc`).
    pub fn on_malloc(&self, addr: u64, size: usize, stack_trace: Vec<u64>) {
        let origin = self.origins.new_origin(stack_trace, "heap-malloc");
        self.shadow.mark_uninit(addr, size, origin);
    }

    /// Record a calloc allocation as initialized (calloc zeroes memory).
    pub fn on_calloc(&self, addr: u64, size: usize) {
        self.shadow.mark_init(addr, size);
    }

    /// Record a realloc: preserve shadow for min(old, new) bytes, mark rest uninit.
    pub fn on_realloc(&self, new_addr: u64, old_addr: u64, old_size: usize, new_size: usize, trace: Vec<u64>) {
        self.shadow.propagate_copy(new_addr, old_addr, old_size.min(new_size));
        if new_size > old_size {
            let origin = self.origins.new_origin(trace, "heap-realloc");
            self.shadow.mark_uninit(new_addr.saturating_add(old_size as u64), new_size - old_size, origin);
        }
    }

    /// Record a free (mark as initialized to suppress further reports).
    pub fn on_free(&self, addr: u64, size: usize) {
        self.shadow.mark_init(addr, size);
    }

    /// Model `memcpy(dst, src, size)`.
    pub fn on_memcpy(&self, pc: u64, dst: u64, src: u64, size: usize) {
        // Check source is initialized before copying.
        if let Some((bad, origin)) = self.shadow.is_uninit(src, size) {
            self.record(MsanViolation {
                kind: MsanViolationKind::UninitMemcpy,
                pc,
                address: bad,
                origin,
            });
        }
        self.shadow.propagate_copy(dst, src, size);
    }

    /// Model `memset(addr, value, size)`: marks initialized.
    pub fn on_memset(&self, addr: u64, size: usize) {
        self.shadow.mark_init(addr, size);
    }

    /// Model a store of a compile-time constant: marks initialized.
    pub fn on_store_constant(&self, addr: u64, size: usize) {
        self.shadow.mark_init(addr, size);
    }

    /// Model a load: propagates shadow from memory address to a virtual register.
    /// Returns the shadow byte for the register.
    #[must_use]
    pub fn on_load_shadow(&self, addr: u64, size: usize) -> u8 {
        (0..size as u64).fold(0u8, |acc, i| acc | self.shadow.read_shadow(addr.saturating_add(i)))
    }

    // ── stats ────────────────────────────────────────────────────────────────

    #[must_use]
    pub fn violation_count(&self) -> usize {
        self.violations.lock().len()
    }

    #[must_use]
    pub fn violations(&self) -> Vec<MsanViolation> {
        self.violations.lock().clone()
    }

    pub fn reset_violations(&self) {
        self.violations.lock().clear();
    }

    #[must_use]
    pub fn uninit_byte_count(&self) -> usize {
        self.shadow.uninit_byte_count()
    }

    #[must_use]
    pub fn summary(&self) -> MsanSummary {
        let violations = self.violations.lock();
        MsanSummary {
            total: violations.len(),
            use_of_uninit: violations.iter().filter(|v| v.kind == MsanViolationKind::UseOfUninitValue).count(),
            uninit_branch: violations.iter().filter(|v| v.kind == MsanViolationKind::UninitBranchCondition).count(),
            uninit_syscall: violations.iter().filter(|v| v.kind == MsanViolationKind::UninitSystemCall).count(),
            uninit_comparison: violations.iter().filter(|v| v.kind == MsanViolationKind::UninitComparison).count(),
            uninit_memcpy: violations.iter().filter(|v| v.kind == MsanViolationKind::UninitMemcpy).count(),
            uninit_bytes: self.shadow.uninit_byte_count(),
        }
    }
}

/// `MSan` session summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsanSummary {
    pub total: usize,
    pub use_of_uninit: usize,
    pub uninit_branch: usize,
    pub uninit_syscall: usize,
    pub uninit_comparison: usize,
    pub uninit_memcpy: usize,
    pub uninit_bytes: usize,
}

// ─── propagation helpers ──────────────────────────────────────────────────────

/// Compute the shadow byte for an arithmetic result given input shadows.
/// Any uninitialized input bit taints the entire output.
#[must_use]
pub const fn propagate_arith(shadow_a: u8, shadow_b: u8) -> u8 {
    if shadow_a != 0 || shadow_b != 0 { 0xFF } else { 0 }
}

/// Propagate shadow through a bitwise AND:
///   result is uninit only if the bit can actually affect the outcome.
///   (Simplified model: any uninit input → uninit output.)
#[must_use]
pub const fn propagate_and(shadow_a: u8, val_a: u8, shadow_b: u8, val_b: u8) -> u8 {
    // If a known-zero operand masks out all uninit bits, the result is init.
    let a_forces_zero = !shadow_a & !val_a;
    let b_forces_zero = !shadow_b & !val_b;
    if a_forces_zero == 0xFF || b_forces_zero == 0xFF {
        0
    } else {
        shadow_a | shadow_b
    }
}

/// Propagate shadow through a bitwise OR.
#[must_use]
pub const fn propagate_or(shadow_a: u8, val_a: u8, shadow_b: u8, val_b: u8) -> u8 {
    // If a known-one operand forces all bits to 1, result is init.
    let a_forces_one = !shadow_a & val_a;
    let b_forces_one = !shadow_b & val_b;
    if a_forces_one == 0xFF || b_forces_one == 0xFF {
        0
    } else {
        shadow_a | shadow_b
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_and_detect_uninit() {
        let rt = MsanRuntime::new(false);
        rt.on_malloc(0x1000, 8, vec![0xdead]);
        rt.check_use(0x100, 0x1000, 8);
        assert_eq!(rt.violation_count(), 1);
    }

    #[test]
    fn calloc_is_initialized() {
        let rt = MsanRuntime::new(false);
        rt.on_calloc(0x2000, 16);
        rt.check_use(0x100, 0x2000, 8);
        assert_eq!(rt.violation_count(), 0);
    }

    #[test]
    fn mark_init_clears_uninit() {
        let rt = MsanRuntime::new(false);
        rt.on_malloc(0x3000, 4, vec![]);
        rt.shadow.mark_init(0x3000, 4);
        rt.check_use(0x100, 0x3000, 4);
        assert_eq!(rt.violation_count(), 0);
    }

    #[test]
    fn memcpy_propagates_uninit() {
        let rt = MsanRuntime::new(false);
        rt.on_malloc(0x4000, 8, vec![]);
        rt.on_memcpy(0x200, 0x5000, 0x4000, 8);
        assert_eq!(rt.violation_count(), 1);
        assert_eq!(rt.violations()[0].kind, MsanViolationKind::UninitMemcpy);
        // Destination should have uninit shadow copied.
        assert_ne!(rt.shadow.read_shadow(0x5000), 0);
    }

    #[test]
    fn branch_condition_check() {
        let rt = MsanRuntime::new(false);
        rt.on_malloc(0x6000, 1, vec![]);
        rt.check_branch_condition(0x300, 0x6000, 1);
        assert_eq!(rt.violations()[0].kind, MsanViolationKind::UninitBranchCondition);
    }

    #[test]
    fn propagate_arith_taint() {
        assert_eq!(propagate_arith(0xFF, 0), 0xFF);
        assert_eq!(propagate_arith(0, 0), 0);
    }

    #[test]
    fn origin_tracking() {
        let rt = MsanRuntime::new(false);
        rt.on_malloc(0x7000, 8, vec![0xABCD]);
        let origin = rt.shadow.origin_for(0x7000);
        assert!(!origin.is_unknown());
        let info = rt.origins.get(origin).unwrap();
        assert_eq!(info.stack_trace, vec![0xABCD]);
    }

    #[test]
    fn summary_fields() {
        let rt = MsanRuntime::new(false);
        rt.on_malloc(0x8000, 4, vec![]);
        rt.check_use(0, 0x8000, 4);
        rt.check_branch_condition(0, 0x8000, 4);
        let s = rt.summary();
        assert_eq!(s.total, 2);
        assert_eq!(s.use_of_uninit, 1);
        assert_eq!(s.uninit_branch, 1);
    }
}
