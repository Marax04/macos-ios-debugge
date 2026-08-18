//! `rustre-fuzz-sanitizers`
//!
//! Pure-Rust sanitizer framework providing logic equivalents to `ASan`, `MSan`,
//! and `UBSan`.  No actual LLVM sanitizer infrastructure is used; instead, this
//! crate tracks heap allocations, shadow memory, and arithmetic operations in
//! software.

pub mod cast;
pub mod asan_analyzer;
pub mod asan_runtime;
pub mod coverage_guided_fuzzer;
pub mod crash_deduplicator;
pub mod msan_model;
pub mod msan_tracker;
pub mod sanitizer_runtime;
pub mod shadow_memory;
pub mod tsan_model;
pub mod ubsan_checks;
pub mod asan_report_parser;
pub mod ubsan_report_parser;
pub mod sanitizer_crash_deduplicator;
pub mod msan_report_parser;
pub mod tsan_report_parser;
pub mod sanitizer_dashboard;

use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

// ── SanitizerKind ─────────────────────────────────────────────────────────────

/// Category of sanitizer violation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SanitizerKind {
    /// Read from uninitialised memory.
    MemoryUninit,
    /// Write or read past the end of a heap allocation.
    HeapOverflow,
    /// Access to memory after it has been freed.
    UseAfterFree,
    /// Double-free of a heap allocation.
    DoubleFree,
    /// Null-pointer dereference.
    NullDeref,
    /// Signed integer overflow.
    IntOverflow,
    /// Misaligned memory access.
    Misaligned,
    /// Division by zero.
    DivByZero,
    /// Heap underflow (access before allocation start).
    HeapUnderflow,
}

impl std::fmt::Display for SanitizerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MemoryUninit => write!(f, "MemoryUninit"),
            Self::HeapOverflow => write!(f, "HeapOverflow"),
            Self::UseAfterFree => write!(f, "UseAfterFree"),
            Self::DoubleFree => write!(f, "DoubleFree"),
            Self::NullDeref => write!(f, "NullDeref"),
            Self::IntOverflow => write!(f, "IntOverflow"),
            Self::Misaligned => write!(f, "Misaligned"),
            Self::DivByZero => write!(f, "DivByZero"),
            Self::HeapUnderflow => write!(f, "HeapUnderflow"),
        }
    }
}

// ── SanitizerReport ───────────────────────────────────────────────────────────

/// A sanitizer violation report.
#[derive(Debug, Clone)]
pub struct SanitizerReport {
    /// Category of the violation.
    pub kind: SanitizerKind,
    /// Human-readable description.
    pub message: String,
    /// Simulated stack trace (list of return addresses).
    pub stack_trace: Vec<u64>,
}

impl SanitizerReport {
    /// Create a new report.
    #[must_use]
    pub fn new(kind: SanitizerKind, message: impl Into<String>, stack_trace: Vec<u64>) -> Self {
        Self {
            kind,
            message: message.into(),
            stack_trace,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Memory Sanitizer (MSan)
// ─────────────────────────────────────────────────────────────────────────────

/// Shadow memory: tracks which bytes are initialised (defined) vs
/// uninitialised (undefined).
///
/// Internally a `HashMap` maps the base address of 256-byte pages to a
/// 256-bit (32-byte) bitmap.  Bit 1 ⇒ defined, 0 ⇒ undefined.
#[derive(Debug, Default)]
pub struct ShadowMemory {
    /// Page map: page-base → 32-byte bitmap (1 bit per byte).
    pub bits: HashMap<u64, Vec<u8>>,
}

const PAGE_SIZE: u64 = 256;
const BITMAP_BYTES: usize = 32; // 256 bits / 8

impl ShadowMemory {
    /// Create an empty shadow memory (all bytes undefined).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    const fn page_base(addr: u64) -> u64 {
        (addr / PAGE_SIZE) * PAGE_SIZE
    }

    const fn bit_index(addr: u64) -> (usize, u8) {
        let offset = (addr % PAGE_SIZE) as usize;
        (offset / 8, 1 << (offset % 8))
    }

    /// Mark `len` bytes starting at `addr` as defined (initialised).
    pub fn mark_defined(&mut self, addr: u64, len: usize) {
        for i in 0..len as u64 {
            let a = addr.saturating_add(i);
            let page = Self::page_base(a);
            let bitmap = self
                .bits
                .entry(page)
                .or_insert_with(|| vec![0u8; BITMAP_BYTES]);
            let (byte_idx, bit) = Self::bit_index(a);
            bitmap[byte_idx] |= bit;
        }
    }

    /// Mark `len` bytes starting at `addr` as undefined (uninitialised).
    pub fn mark_undefined(&mut self, addr: u64, len: usize) {
        for i in 0..len as u64 {
            let a = addr.saturating_add(i);
            let page = Self::page_base(a);
            let bitmap = self
                .bits
                .entry(page)
                .or_insert_with(|| vec![0u8; BITMAP_BYTES]);
            let (byte_idx, bit) = Self::bit_index(a);
            bitmap[byte_idx] &= !bit;
        }
    }

    /// Returns `true` when all `len` bytes starting at `addr` are defined.
    #[must_use]
    pub fn check_defined(&self, addr: u64, len: usize) -> bool {
        for i in 0..len as u64 {
            let a = addr.saturating_add(i);
            let page = Self::page_base(a);
            if let Some(bitmap) = self.bits.get(&page) {
                let (byte_idx, bit) = Self::bit_index(a);
                if bitmap[byte_idx] & bit == 0 {
                    return false;
                }
            } else {
                // Page not in map → all undefined
                return false;
            }
        }
        true
    }
}

/// The Memory Sanitizer; wraps a [`ShadowMemory`] and surfaces violations as
/// [`SanitizerReport`]s.
#[derive(Debug, Default)]
pub struct MemorySanitizer {
    /// The underlying shadow memory.
    pub shadow: ShadowMemory,
}

impl MemorySanitizer {
    /// Create a new sanitizer with empty shadow memory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark bytes as defined.
    pub fn mark_defined(&mut self, addr: u64, len: usize) {
        self.shadow.mark_defined(addr, len);
    }

    /// Mark bytes as undefined.
    pub fn mark_undefined(&mut self, addr: u64, len: usize) {
        self.shadow.mark_undefined(addr, len);
    }

    /// Check that `len` bytes at `addr` are all defined.
    ///
    /// Returns `Ok(())` on success, or `Err(SanitizerReport)` on violation.
    ///
    /// # Errors
    /// Returns a [`SanitizerReport`] describing the uninitialised access.
    pub fn check(&self, addr: u64, len: usize) -> Result<(), SanitizerReport> {
        if self.shadow.check_defined(addr, len) {
            Ok(())
        } else {
            Err(SanitizerReport::new(
                SanitizerKind::MemoryUninit,
                format!("read of {len} uninitialised bytes at 0x{addr:x}"),
                vec![],
            ))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Address Sanitizer (ASan) — logic only
// ─────────────────────────────────────────────────────────────────────────────

/// Result of a heap-access check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SanitizerResult {
    /// The access is safe.
    Clean,
    /// Write or read past the end of an allocation.
    HeapOverflow {
        /// Address of the access.
        addr: u64,
        /// Number of bytes accessed.
        size: usize,
        /// Base address of the allocation.
        alloc_base: u64,
        /// Size of the allocation.
        alloc_size: usize,
    },
    /// Access to freed memory.
    UseAfterFree {
        /// Address of the access.
        addr: u64,
        /// When the memory was freed.
        freed_at: Option<SystemTime>,
    },
    /// Double-free of a pointer.
    DoubleFree {
        /// The pointer that was freed twice.
        addr: u64,
    },
    /// Write or read before the start of an allocation.
    HeapUnderflow {
        /// Address of the access.
        addr: u64,
    },
}

/// Metadata for a single heap allocation.
#[derive(Debug, Clone)]
pub struct Allocation {
    /// Base address of the allocation.
    pub addr: u64,
    /// Size in bytes.
    pub size: usize,
    /// Whether this allocation has been freed.
    pub freed: bool,
    /// When this allocation was freed, if applicable.
    pub freed_at: Option<SystemTime>,
}

/// Tracks heap allocations for ASan-style checking.
#[derive(Debug, Default)]
pub struct HeapTracking {
    /// Live and recently-freed allocations.
    pub allocations: HashMap<u64, Allocation>,
    /// Set of freed addresses (for fast double-free detection).
    pub freed: HashSet<u64>,
    /// Quarantine queue: freed addresses pending final cleanup.
    pub quarantine: Vec<u64>,
}

impl HeapTracking {
    /// Create new heap tracking state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a new allocation at `addr` of `size` bytes.
    pub fn track_alloc(&mut self, addr: u64, size: usize) {
        // If addr was in quarantine/freed, remove it (reuse after free is a
        // separate violation — here we just model the allocator)
        self.freed.remove(&addr);
        self.quarantine.retain(|&a| a != addr);
        self.allocations.insert(
            addr,
            Allocation {
                addr,
                size,
                freed: false,
                freed_at: None,
            },
        );
    }

    /// Record a free of `addr`.
    ///
    /// Returns [`SanitizerResult::DoubleFree`] when `addr` was already freed,
    /// [`SanitizerResult::Clean`] otherwise.
    pub fn track_free(&mut self, addr: u64) -> SanitizerResult {
        if self.freed.contains(&addr) {
            return SanitizerResult::DoubleFree { addr };
        }
        if let Some(alloc) = self.allocations.get_mut(&addr) {
            alloc.freed = true;
            alloc.freed_at = Some(SystemTime::now());
            self.freed.insert(addr);
            self.quarantine.push(addr);
        }
        SanitizerResult::Clean
    }

    /// Check whether a `size`-byte access at `addr` is valid.
    ///
    /// UAF detection covers interior bytes of freed allocations by scanning the
    /// full allocation range rather than only comparing base addresses.
    #[must_use]
    pub fn check_heap_access(&self, addr: u64, size: usize) -> SanitizerResult {
        // Scan all allocations. UAF detection is performed inside the loop so
        // that interior-byte accesses (base + N) into freed ranges are caught.
        for alloc in self.allocations.values() {
            let alloc_end = alloc.addr.saturating_add(alloc.size as u64);
            if alloc.freed {
                // Check UAF: any byte of [addr, addr+size) overlaps the freed range.
                let access_end = addr.saturating_add(size as u64);
                if addr < alloc_end && access_end > alloc.addr {
                    return SanitizerResult::UseAfterFree {
                        addr,
                        freed_at: alloc.freed_at,
                    };
                }
                continue;
            }
            if addr < alloc.addr {
                // Underflow: access before start that reaches into the allocation
                if addr.saturating_add(size as u64) > alloc.addr {
                    return SanitizerResult::HeapUnderflow { addr };
                }
                continue;
            }
            if addr >= alloc.addr && addr < alloc_end {
                // Inside this allocation — check for overflow
                let end = addr.saturating_add(size as u64);
                if end > alloc_end {
                    return SanitizerResult::HeapOverflow {
                        addr,
                        size,
                        alloc_base: alloc.addr,
                        alloc_size: alloc.size,
                    };
                }
                return SanitizerResult::Clean;
            }
        }

        // No matching allocation — treat as clean (untracked memory)
        SanitizerResult::Clean
    }
}

/// The Address Sanitizer; wraps [`HeapTracking`] and surfaces violations.
#[derive(Debug, Default)]
pub struct AddressSanitizer {
    /// Heap tracking state.
    pub heap: HeapTracking,
}

impl AddressSanitizer {
    /// Create a new sanitizer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an allocation.
    pub fn track_alloc(&mut self, addr: u64, size: usize) {
        self.heap.track_alloc(addr, size);
    }

    /// Record a free.
    pub fn track_free(&mut self, addr: u64) -> SanitizerResult {
        self.heap.track_free(addr)
    }

    /// Check a heap access and convert to a [`SanitizerReport`] on violation.
    ///
    /// # Errors
    /// Returns a [`SanitizerReport`] describing the violation.
    pub fn check(&self, addr: u64, size: usize) -> Result<(), SanitizerReport> {
        match self.heap.check_heap_access(addr, size) {
            SanitizerResult::Clean => Ok(()),
            SanitizerResult::HeapOverflow {
                addr,
                size,
                alloc_base,
                alloc_size,
            } => Err(SanitizerReport::new(
                SanitizerKind::HeapOverflow,
                format!(
                    "heap overflow: access {size} bytes at 0x{addr:x}, \
                     alloc=[0x{alloc_base:x}, 0x{:x})",
                    alloc_base.saturating_add(alloc_size as u64)
                ),
                vec![],
            )),
            SanitizerResult::UseAfterFree { addr, .. } => Err(SanitizerReport::new(
                SanitizerKind::UseAfterFree,
                format!("use-after-free at 0x{addr:x}"),
                vec![],
            )),
            SanitizerResult::DoubleFree { addr } => Err(SanitizerReport::new(
                SanitizerKind::DoubleFree,
                format!("double-free at 0x{addr:x}"),
                vec![],
            )),
            SanitizerResult::HeapUnderflow { addr } => Err(SanitizerReport::new(
                SanitizerKind::HeapUnderflow,
                format!("heap underflow at 0x{addr:x}"),
                vec![],
            )),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UB Sanitizer
// ─────────────────────────────────────────────────────────────────────────────

/// Arithmetic operations checked by [`UbSanitizer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    /// Addition.
    Add,
    /// Subtraction.
    Sub,
    /// Multiplication.
    Mul,
}

/// Logic-equivalent Undefined Behaviour Sanitizer.
#[derive(Debug, Default)]
pub struct UbSanitizer;

impl UbSanitizer {
    /// Create a new `UBSan` instance.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns `true` when the signed operation `a op b` would overflow.
    #[must_use]
    pub const fn check_signed_overflow(a: i64, b: i64, op: ArithOp) -> bool {
        match op {
            ArithOp::Add => a.checked_add(b).is_none(),
            ArithOp::Sub => a.checked_sub(b).is_none(),
            ArithOp::Mul => a.checked_mul(b).is_none(),
        }
    }

    /// Returns `true` when `ptr` is a null pointer (== 0).
    #[must_use]
    pub const fn check_null_deref(ptr: u64) -> bool {
        ptr == 0
    }

    /// Returns `true` when `addr` is not aligned to `alignment`.
    ///
    /// `alignment` must be a power of two; non-power-of-two values are treated
    /// as 1 (always aligned).
    #[must_use]
    pub const fn check_misaligned(addr: u64, alignment: usize) -> bool {
        if alignment == 0 || (alignment & (alignment - 1)) != 0 {
            // Not a power of two: every address is "aligned"
            return false;
        }
        !(addr).is_multiple_of(alignment as u64)
    }

    /// Returns `true` when `divisor` is zero.
    #[must_use]
    pub const fn check_division(divisor: i64) -> bool {
        divisor == 0
    }

    /// Check a signed add and produce a [`SanitizerReport`] on overflow.
    ///
    /// # Errors
    /// Returns a report on overflow.
    pub fn checked_add(a: i64, b: i64) -> Result<i64, SanitizerReport> {
        a.checked_add(b).ok_or_else(|| {
            SanitizerReport::new(
                SanitizerKind::IntOverflow,
                format!("signed overflow: {a} + {b}"),
                vec![],
            )
        })
    }

    /// Check a signed multiply and produce a [`SanitizerReport`] on overflow.
    ///
    /// # Errors
    /// Returns a report on overflow.
    pub fn checked_mul(a: i64, b: i64) -> Result<i64, SanitizerReport> {
        a.checked_mul(b).ok_or_else(|| {
            SanitizerReport::new(
                SanitizerKind::IntOverflow,
                format!("signed overflow: {a} * {b}"),
                vec![],
            )
        })
    }

    /// Perform all common UB checks on a memory access and return the first
    /// violation found.
    ///
    /// # Errors
    /// Returns the first [`SanitizerReport`] found.
    pub fn check_access(ptr: u64, alignment: usize) -> Result<(), SanitizerReport> {
        if Self::check_null_deref(ptr) {
            return Err(SanitizerReport::new(
                SanitizerKind::NullDeref,
                "null pointer dereference",
                vec![],
            ));
        }
        if Self::check_misaligned(ptr, alignment) {
            return Err(SanitizerReport::new(
                SanitizerKind::Misaligned,
                format!("misaligned access: address 0x{ptr:x} not aligned to {alignment}"),
                vec![],
            ));
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── ShadowMemory ──────────────────────────────────────────────────────────

    #[test]
    fn shadow_memory_undefined_by_default() {
        let sm = ShadowMemory::new();
        assert!(!sm.check_defined(0x1000, 4));
    }

    #[test]
    fn shadow_memory_mark_defined() {
        let mut sm = ShadowMemory::new();
        sm.mark_defined(0x1000, 4);
        assert!(sm.check_defined(0x1000, 4));
    }

    #[test]
    fn shadow_memory_partial_undefined() {
        let mut sm = ShadowMemory::new();
        sm.mark_defined(0x1000, 3);
        // byte at 0x1003 is undefined
        assert!(!sm.check_defined(0x1000, 4));
    }

    #[test]
    fn shadow_memory_mark_then_undefine() {
        let mut sm = ShadowMemory::new();
        sm.mark_defined(0x2000, 8);
        sm.mark_undefined(0x2004, 4);
        assert!(sm.check_defined(0x2000, 4));
        assert!(!sm.check_defined(0x2000, 8));
    }

    #[test]
    fn shadow_memory_cross_page() {
        let mut sm = ShadowMemory::new();
        // Write across the 256-byte page boundary
        sm.mark_defined(250, 10);
        assert!(sm.check_defined(250, 10));
    }

    // ── MemorySanitizer ───────────────────────────────────────────────────────

    #[test]
    fn msan_clean_after_mark() {
        let mut msan = MemorySanitizer::new();
        msan.mark_defined(0x100, 8);
        assert!(msan.check(0x100, 8).is_ok());
    }

    #[test]
    fn msan_violation_uninit() {
        let msan = MemorySanitizer::new();
        let result = msan.check(0x100, 4);
        assert!(result.is_err());
        let report = result.unwrap_err();
        assert_eq!(report.kind, SanitizerKind::MemoryUninit);
    }

    #[test]
    fn msan_mark_undefined_after_define() {
        let mut msan = MemorySanitizer::new();
        msan.mark_defined(0x200, 8);
        msan.mark_undefined(0x204, 4);
        assert!(msan.check(0x200, 4).is_ok());
        assert!(msan.check(0x204, 4).is_err());
    }

    // ── HeapTracking / AddressSanitizer ───────────────────────────────────────

    #[test]
    fn asan_clean_access_within_bounds() {
        let mut asan = AddressSanitizer::new();
        asan.track_alloc(0x1000, 64);
        assert!(asan.check(0x1000, 16).is_ok());
    }

    #[test]
    fn asan_heap_overflow() {
        let mut asan = AddressSanitizer::new();
        asan.track_alloc(0x1000, 8);
        let result = asan.check(0x1000, 16); // 16 > 8
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, SanitizerKind::HeapOverflow);
    }

    #[test]
    fn asan_use_after_free() {
        let mut asan = AddressSanitizer::new();
        asan.track_alloc(0x2000, 32);
        asan.track_free(0x2000);
        let result = asan.check(0x2000, 4);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, SanitizerKind::UseAfterFree);
    }

    #[test]
    fn asan_double_free() {
        let mut asan = AddressSanitizer::new();
        asan.track_alloc(0x3000, 16);
        assert_eq!(asan.track_free(0x3000), SanitizerResult::Clean);
        let result = asan.track_free(0x3000);
        assert_eq!(result, SanitizerResult::DoubleFree { addr: 0x3000 });
    }

    #[test]
    fn asan_heap_underflow() {
        let mut ht = HeapTracking::new();
        ht.track_alloc(0x1010, 16);
        // Access at 0x1000 with size 20 reaches into the allocation
        let result = ht.check_heap_access(0x1000, 20);
        assert_eq!(result, SanitizerResult::HeapUnderflow { addr: 0x1000 });
    }

    #[test]
    fn asan_clean_untracked_memory() {
        let asan = AddressSanitizer::new();
        // Untracked addresses are treated as clean
        assert!(asan.check(0xdead_beef, 4).is_ok());
    }

    #[test]
    fn asan_free_and_realloc() {
        let mut asan = AddressSanitizer::new();
        asan.track_alloc(0x4000, 8);
        asan.track_free(0x4000);
        // Re-alloc at same address should clear freed state
        asan.track_alloc(0x4000, 8);
        assert!(asan.check(0x4000, 8).is_ok());
    }

    // ── UbSanitizer ───────────────────────────────────────────────────────────

    #[test]
    fn ubsan_no_overflow() {
        assert!(!UbSanitizer::check_signed_overflow(1, 2, ArithOp::Add));
    }

    #[test]
    fn ubsan_add_overflow() {
        assert!(UbSanitizer::check_signed_overflow(
            i64::MAX,
            1,
            ArithOp::Add
        ));
    }

    #[test]
    fn ubsan_sub_overflow() {
        assert!(UbSanitizer::check_signed_overflow(
            i64::MIN,
            1,
            ArithOp::Sub
        ));
    }

    #[test]
    fn ubsan_mul_overflow() {
        assert!(UbSanitizer::check_signed_overflow(
            i64::MAX,
            2,
            ArithOp::Mul
        ));
    }

    #[test]
    fn ubsan_null_deref_zero() {
        assert!(UbSanitizer::check_null_deref(0));
    }

    #[test]
    fn ubsan_null_deref_nonzero() {
        assert!(!UbSanitizer::check_null_deref(0x1000));
    }

    #[test]
    fn ubsan_misaligned_odd_address() {
        assert!(UbSanitizer::check_misaligned(0x1001, 4));
    }

    #[test]
    fn ubsan_aligned_address() {
        assert!(!UbSanitizer::check_misaligned(0x1000, 4));
    }

    #[test]
    fn ubsan_misaligned_non_power_of_two() {
        // alignment = 3 is not a power of two → treat as always aligned
        assert!(!UbSanitizer::check_misaligned(0x1001, 3));
    }

    #[test]
    fn ubsan_division_by_zero() {
        assert!(UbSanitizer::check_division(0));
    }

    #[test]
    fn ubsan_division_nonzero() {
        assert!(!UbSanitizer::check_division(5));
    }

    #[test]
    fn ubsan_checked_add_ok() {
        assert_eq!(UbSanitizer::checked_add(10, 20).unwrap(), 30);
    }

    #[test]
    fn ubsan_checked_add_overflow() {
        let r = UbSanitizer::checked_add(i64::MAX, 1);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind, SanitizerKind::IntOverflow);
    }

    #[test]
    fn ubsan_check_access_null() {
        let r = UbSanitizer::check_access(0, 8);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind, SanitizerKind::NullDeref);
    }

    #[test]
    fn ubsan_check_access_misaligned() {
        let r = UbSanitizer::check_access(0x1001, 8);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err().kind, SanitizerKind::Misaligned);
    }

    #[test]
    fn ubsan_check_access_ok() {
        assert!(UbSanitizer::check_access(0x1000, 8).is_ok());
    }

    // ── SanitizerReport ───────────────────────────────────────────────────────

    #[test]
    fn sanitizer_report_fields() {
        let r = SanitizerReport::new(
            SanitizerKind::HeapOverflow,
            "overflow!",
            vec![0xdead, 0xbeef],
        );
        assert_eq!(r.kind, SanitizerKind::HeapOverflow);
        assert_eq!(r.message, "overflow!");
        assert_eq!(r.stack_trace.len(), 2);
    }

    #[test]
    fn sanitizer_kind_display() {
        assert_eq!(SanitizerKind::DivByZero.to_string(), "DivByZero");
        assert_eq!(SanitizerKind::MemoryUninit.to_string(), "MemoryUninit");
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Sanitizer log text parser  (ASAN / MSAN / UBSAN / TSAN / LSAN)
// ═════════════════════════════════════════════════════════════════════════════

use serde::{Deserialize, Serialize};

/// Which sanitizer tool produced a crash report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SanitizerTool {
    /// `AddressSanitizer`
    ASan,
    /// `MemorySanitizer`
    MSan,
    /// `UndefinedBehaviorSanitizer`
    UBSan,
    /// `LeakSanitizer`
    LSan,
    /// `ThreadSanitizer`
    TSan,
    /// Unrecognised / unknown tool
    Unknown,
}

impl std::fmt::Display for SanitizerTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ASan => write!(f, "AddressSanitizer"),
            Self::MSan => write!(f, "MemorySanitizer"),
            Self::UBSan => write!(f, "UndefinedBehaviorSanitizer"),
            Self::LSan => write!(f, "LeakSanitizer"),
            Self::TSan => write!(f, "ThreadSanitizer"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Direction of a memory access that triggered a sanitizer violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessType {
    /// Memory read.
    Read,
    /// Memory write.
    Write,
}

impl std::fmt::Display for AccessType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => write!(f, "READ"),
            Self::Write => write!(f, "WRITE"),
        }
    }
}

/// Crash severity classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CrashSeverity {
    /// Informational (e.g. memory leaks).
    Info,
    /// Low impact.
    Low,
    /// Medium impact (e.g. null dereference).
    Medium,
    /// High impact (e.g. heap/stack overflow, double-free).
    High,
    /// Critical exploitability (e.g. use-after-free).
    Critical,
}

impl std::fmt::Display for CrashSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single frame parsed from a sanitizer stack trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedStackFrame {
    /// Frame index (0-based).
    pub index: usize,
    /// Instruction pointer / PC if available.
    pub address: Option<u64>,
    /// Demangled or raw function name.
    pub function: Option<String>,
    /// Source file path.
    pub file: Option<String>,
    /// Source line number.
    pub line: Option<u32>,
    /// Column within the line.
    pub column: Option<u32>,
}

impl ParsedStackFrame {
    /// Create a frame with only an index.
    #[must_use]
    pub const fn empty(index: usize) -> Self {
        Self {
            index,
            address: None,
            function: None,
            file: None,
            line: None,
            column: None,
        }
    }

    /// Return a human-readable one-liner for this frame.
    #[must_use]
    pub fn display(&self) -> String {
        let addr = self
            .address
            .map_or_else(|| "???".to_owned(), |a| format!("0x{a:x}"));
        let func = self.function.as_deref().unwrap_or("<unknown>");
        let loc = match (&self.file, self.line) {
            (Some(f), Some(l)) => format!(" {f}:{l}"),
            (Some(f), None) => format!(" {f}"),
            _ => String::new(),
        };
        format!("#{} {} in {}{}", self.index, addr, func, loc)
    }
}

/// A fully-parsed sanitizer crash report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedCrashReport {
    /// Which sanitizer produced the report.
    pub tool: SanitizerTool,
    /// Short error type string: `"heap-buffer-overflow"`, `"use-after-free"`, etc.
    pub error_type: String,
    /// Whether the triggering access was a read or write.
    pub access_type: Option<AccessType>,
    /// Number of bytes involved in the access.
    pub access_size: Option<usize>,
    /// The memory address involved.
    pub address: Option<u64>,
    /// Thread index that triggered the error.
    pub thread: Option<u32>,
    /// Stack frames at the point of the violation.
    pub stack_frames: Vec<ParsedStackFrame>,
    /// Stack frames showing where the memory was allocated.
    pub allocation_frames: Vec<ParsedStackFrame>,
    /// Stack frames showing where the memory was previously freed.
    pub deallocation_frames: Vec<ParsedStackFrame>,
    /// The complete raw text of this report.
    pub raw_text: String,
    /// Computed severity level.
    pub severity: CrashSeverity,
}

impl ParsedCrashReport {
    /// Summarise the report in a single line.
    #[must_use]
    pub fn summary(&self) -> String {
        let addr = self
            .address
            .map_or_else(|| "?".to_owned(), |a| format!("0x{a:x}"));
        format!(
            "[{}] {} at {} ({} frames)",
            self.severity,
            self.error_type,
            addr,
            self.stack_frames.len()
        )
    }

    /// The top function name from the crash stack, if any.
    #[must_use]
    pub fn top_function(&self) -> Option<&str> {
        self.stack_frames
            .first()
            .and_then(|f| f.function.as_deref())
    }
}

// ── Parser internals ──────────────────────────────────────────────────────────

/// Stateless parser for `ASAN`, `MSAN`, `UBSAN`, and `TSAN` text logs.
pub struct SanitizerLogParser;

impl SanitizerLogParser {
    /// Parse the first crash report found in `text`.
    ///
    /// Returns a [`ParsedCrashReport`] with `tool == Unknown` and an empty
    /// `error_type` when no recognisable report is found.
    #[must_use]
    pub fn parse(text: &str) -> ParsedCrashReport {
        let mut reports = Self::parse_all(text);
        if reports.is_empty() {
            ParsedCrashReport {
                tool: SanitizerTool::Unknown,
                error_type: String::new(),
                access_type: None,
                access_size: None,
                address: None,
                thread: None,
                stack_frames: Vec::new(),
                allocation_frames: Vec::new(),
                deallocation_frames: Vec::new(),
                raw_text: text.to_owned(),
                severity: CrashSeverity::Info,
            }
        } else {
            reports.remove(0)
        }
    }

    /// Parse *all* crash reports embedded in `text`.
    ///
    /// Maximum number of lines processed per `parse_all` call to prevent
    /// memory exhaustion on attacker-controlled input.
    const MAX_LINES: usize = 1_000_000;

    /// Parse *all* crash reports embedded in `text`.
    ///
    /// Sanitizer logs can contain several `==PID==ERROR: …` blocks; this
    /// function splits the text on those headers and parses each block.
    #[must_use]
    pub fn parse_all(text: &str) -> Vec<ParsedCrashReport> {
        // Collect line indices where a new ERROR block starts.
        // Cap the number of lines processed to avoid memory exhaustion on
        // attacker-controlled input (dos-memory-exhaustion).
        let lines: Vec<&str> = text.lines().take(Self::MAX_LINES).collect();
        let mut block_starts: Vec<usize> = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if Self::is_error_header(line) {
                block_starts.push(i);
            }
        }
        if block_starts.is_empty() {
            return Vec::new();
        }
        let mut reports = Vec::new();
        for (idx, &start) in block_starts.iter().enumerate() {
            let end = if idx + 1 < block_starts.len() {
                block_starts[idx + 1]
            } else {
                lines.len()
            };
            let block_text = lines[start..end].join("\n");
            reports.push(Self::parse_block(&block_text));
        }
        reports
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn is_error_header(line: &str) -> bool {
        // "==PID==ERROR: SanitizerName: …"
        line.contains("==ERROR:") && line.contains("Sanitizer")
    }

    fn parse_block(block: &str) -> ParsedCrashReport {
        let tool = Self::detect_tool(block);
        let error_type = Self::extract_error_type(block);
        let (access_type, access_size, address) = Self::extract_access(block);
        let thread = Self::extract_thread(block);
        let stack_frames = Self::parse_frames_section(block, None);
        let allocation_frames = Self::parse_frames_section(block, Some("allocated by thread"));
        let deallocation_frames = Self::parse_frames_section(block, Some("freed by thread"));
        let severity = classify_crash_severity(&error_type);
        ParsedCrashReport {
            tool,
            error_type,
            access_type,
            access_size,
            address,
            thread,
            stack_frames,
            allocation_frames,
            deallocation_frames,
            raw_text: block.to_owned(),
            severity,
        }
    }

    fn detect_tool(text: &str) -> SanitizerTool {
        if text.contains("AddressSanitizer") {
            SanitizerTool::ASan
        } else if text.contains("MemorySanitizer") {
            SanitizerTool::MSan
        } else if text.contains("UndefinedBehaviorSanitizer")
            || text.contains("UBSanitizer")
            || text.contains("runtime error:")
        {
            SanitizerTool::UBSan
        } else if text.contains("ThreadSanitizer") {
            SanitizerTool::TSan
        } else if text.contains("LeakSanitizer") {
            SanitizerTool::LSan
        } else {
            SanitizerTool::Unknown
        }
    }

    /// Extract the short error type from a line like:
    /// `==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address …`
    fn extract_error_type(text: &str) -> String {
        for line in text.lines() {
            if let Some(rest) = Self::after_sanitizer_colon(line) {
                // `rest` is "heap-buffer-overflow on address …" or "use-after-free …"
                let error = rest
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_end_matches(':')
                    .to_owned();
                if !error.is_empty() {
                    return error;
                }
            }
        }
        String::from("unknown")
    }

    /// Given `==PID==ERROR: AddressSanitizer: <rest>` return `<rest>`.
    fn after_sanitizer_colon(line: &str) -> Option<&str> {
        // Pattern: "ERROR: SanitizerName: <rest>"
        let idx = line.find("ERROR:")?;
        let after_error = &line[idx + 6..]; // skip "ERROR:"
        // skip optional whitespace + tool name + colon
        let colon = after_error.find(':')?;
        let rest = after_error[colon + 1..].trim_start();
        Some(rest)
    }

    /// Parse: "READ of size 4 at 0x6020000000b0 thread T0"
    ///  or    "WRITE of size 8 at 0x…"
    fn extract_access(text: &str) -> (Option<AccessType>, Option<usize>, Option<u64>) {
        for line in text.lines() {
            let trimmed = line.trim();
            let (access_type, rest) = if let Some(r) = trimmed.strip_prefix("READ ") {
                (AccessType::Read, r)
            } else if let Some(r) = trimmed.strip_prefix("WRITE ") {
                (AccessType::Write, r)
            } else {
                continue;
            };
            // "of size N at 0xADDR …"
            let size = Self::parse_kv(rest, "of size").and_then(|s| s.parse::<usize>().ok());
            let addr = Self::parse_hex_after(rest, "at ");
            return (Some(access_type), size, addr);
        }
        // Fallback: try the header line for an address
        let addr = Self::extract_on_address(text);
        (None, None, addr)
    }

    fn extract_on_address(text: &str) -> Option<u64> {
        for line in text.lines() {
            if let Some(idx) = line.find("on address ") {
                let rest = &line[idx + 11..];
                let hex = rest.split_whitespace().next()?;
                return parse_hex_u64(hex);
            }
        }
        None
    }

    fn extract_thread(text: &str) -> Option<u32> {
        for line in text.lines() {
            // "… thread T3" or "thread T0"
            if let Some(idx) = line.find(" thread T") {
                let rest = &line[idx + 9..];
                let num: String = rest.chars().take_while(char::is_ascii_digit).collect();
                if let Ok(n) = num.parse::<u32>() {
                    return Some(n);
                }
            }
        }
        None
    }

    /// Parse stack frames starting after an optional anchor line.
    ///
    /// When `anchor` is `None` the frames start right after the ERROR header.
    fn parse_frames_section(text: &str, anchor: Option<&str>) -> Vec<ParsedStackFrame> {
        let lines: Vec<&str> = text.lines().collect();
        let start_idx = anchor.map_or_else(
            || {
                // Skip the ERROR header line
                lines
                    .iter()
                    .position(|l| l.contains("==ERROR:"))
                    .map_or(0, |i| i + 1)
            },
            |a| {
                lines
                    .iter()
                    .position(|l| l.to_ascii_lowercase().contains(a))
                    .map_or(lines.len(), |i| i + 1)
            },
        );

        let mut frames = Vec::new();
        for line in &lines[start_idx..] {
            let trimmed = line.trim();
            // Frame lines look like "    #N 0xADDR in FUNC FILE:LINE:COL"
            if let Some(frame) = Self::try_parse_frame(trimmed) {
                frames.push(frame);
            } else if !frames.is_empty() {
                // Non-frame line after we started collecting → stop for this section
                // (but only if it's not blank or a continuation)
                if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with("0x") {
                    break;
                }
            }
        }
        frames
    }

    /// Try to parse a single frame line.
    ///
    /// Expected format: `#N 0xADDR in FUNC_NAME /path/to/file.c:LINE:COL`
    /// or               `#N 0xADDR in FUNC_NAME`
    fn try_parse_frame(s: &str) -> Option<ParsedStackFrame> {
        // Must start with "#N"
        let s = s.trim();
        if !s.starts_with('#') {
            return None;
        }
        let s = &s[1..]; // drop '#'
        let mut parts = s.splitn(2, ' ');
        let idx_str = parts.next()?;
        let index: usize = idx_str.trim().parse().ok()?;
        let rest = parts.next().unwrap_or("").trim();

        // Optional address
        let (address, rest) = if rest.starts_with("0x") || rest.starts_with("0X") {
            let end = rest.find(' ').unwrap_or(rest.len());
            let addr = parse_hex_u64(&rest[..end]);
            (addr, rest[end..].trim())
        } else {
            (None, rest)
        };

        // "in FUNC_NAME [FILE:LINE:COL]"
        let (function, file, line, column) = rest.strip_prefix("in ").map_or_else(
            || {
                // No "in" keyword — whole rest is function name (rare)
                let func = if rest.is_empty() {
                    None
                } else {
                    Some(rest.to_owned())
                };
                (func, None, None, None)
            },
            |after_in| {
                // Split on whitespace: first token is function name, rest is location
                let mut it = after_in.splitn(2, ' ');
                let func = it.next().map(str::to_owned);
                let loc = it.next().unwrap_or("").trim();
                let (file, ln, col) = Self::parse_location(loc);
                (func, file, ln, col)
            },
        );

        Some(ParsedStackFrame {
            index,
            address,
            function,
            file,
            line,
            column,
        })
    }

    /// Parse `"/path/to/file.c:42:5"` into `(file, line, col)`.
    fn parse_location(s: &str) -> (Option<String>, Option<u32>, Option<u32>) {
        if s.is_empty() {
            return (None, None, None);
        }
        // Split from the right to find line/col numbers
        let parts: Vec<&str> = s.rsplitn(3, ':').collect();
        // rsplitn(3) gives [col, line, file_with_drive_letter_on_windows]
        match parts.as_slice() {
            [col_s, line_s, file] => {
                let col = col_s.parse::<u32>().ok();
                if let Ok(ln) = line_s.parse::<u32>() {
                    return (Some((*file).to_owned()), Some(ln), col);
                }
                // col parse failed — try [line, file]
                if let Ok(ln) = col_s.parse::<u32>() {
                    let file_part = format!("{file}:{line_s}");
                    return (Some(file_part), Some(ln), None);
                }
                (Some(s.to_owned()), None, None)
            }
            [line_s, file] => {
                let ln = line_s.parse::<u32>().ok();
                (Some((*file).to_owned()), ln, None)
            }
            [file] => (Some((*file).to_owned()), None, None),
            _ => (Some(s.to_owned()), None, None),
        }
    }

    /// Extract the value after a keyword in a string.
    ///
    /// e.g. `parse_kv("of size 4 at …", "of size")` → `Some("4")`
    fn parse_kv<'a>(s: &'a str, key: &str) -> Option<&'a str> {
        let idx = s.find(key)?;
        let rest = s[idx + key.len()..].trim_start();
        Some(rest.split_whitespace().next().unwrap_or(""))
    }

    /// Extract a hex `u64` that appears immediately after `needle` in `s`.
    fn parse_hex_after(s: &str, needle: &str) -> Option<u64> {
        let idx = s.find(needle)?;
        let rest = s[idx + needle.len()..].trim_start();
        let hex = rest.split_whitespace().next()?;
        parse_hex_u64(hex)
    }
}

/// Parse a `0x…` or `0X…` prefixed hexadecimal string into a `u64`.
///
/// Returns `None` for malformed input.
#[must_use]
pub fn parse_hex_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    // strip any trailing non-hex characters (punctuation, etc.)
    let clean: String = hex.chars().take_while(char::is_ascii_hexdigit).collect();
    u64::from_str_radix(&clean, 16).ok()
}

// ═════════════════════════════════════════════════════════════════════════════
// Severity classifier
// ═════════════════════════════════════════════════════════════════════════════

/// Map an error-type string to a [`CrashSeverity`].
///
/// This is a stand-alone function so that callers can re-classify reports
/// after post-processing.
#[must_use]
pub fn classify_crash_severity(error_type: &str) -> CrashSeverity {
    match error_type {
        "heap-buffer-overflow"
        | "global-buffer-overflow"
        | "stack-buffer-overflow"
        | "double-free"
        | "stack-overflow"
        | "bad-free"
        | "alloc-dealloc-mismatch" => CrashSeverity::High,
        "use-after-free" | "heap-use-after-free" => CrashSeverity::Critical,
        "integer-overflow"
        | "undefined-behavior"
        | "initialization-order-fiasco"
        | "odr-violation" => CrashSeverity::Low,
        "memory-leak" | "leak" => CrashSeverity::Info,
        // Known Medium-severity categories: use-after-return, use-after-scope,
        // null-deref, null-dereference, container-overflow — and any unknown
        // error type defaults to Medium so reports stay actionable.
        _ => CrashSeverity::Medium,
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Crash deduplication engine
// ═════════════════════════════════════════════════════════════════════════════

/// Configuration for the crash deduplication engine.
#[derive(Debug, Clone)]
pub struct CrashDeduplicator {
    /// How many top stack frames to use for the dedup key.
    pub stack_depth: usize,
    /// Ignore raw PC addresses when comparing frames (use function names only).
    pub ignore_addresses: bool,
    /// Strip `+0x…` offsets from function names before comparison.
    pub ignore_offsets: bool,
}

impl Default for CrashDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

impl CrashDeduplicator {
    /// Create a deduplicator with sensible defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            stack_depth: 5,
            ignore_addresses: true,
            ignore_offsets: true,
        }
    }

    /// Compute a string key that uniquely identifies a crash signature.
    ///
    /// Two crashes with the same key are considered duplicates.
    #[must_use]
    pub fn dedup_key(&self, report: &ParsedCrashReport) -> String {
        let mut key = report.error_type.clone();
        if let Some(at) = report.access_type {
            key.push('|');
            key.push_str(&at.to_string());
        }
        for frame in report.stack_frames.iter().take(self.stack_depth) {
            key.push('|');
            if let Some(func) = &frame.function {
                let f = if self.ignore_offsets {
                    func.split('+').next().unwrap_or(func).trim()
                } else {
                    func.as_str()
                };
                key.push_str(f);
            } else if !self.ignore_addresses {
                if let Some(addr) = frame.address {
                    use std::fmt::Write as _;
                    let _ = write!(key, "0x{addr:x}");
                } else {
                    key.push('?');
                }
            } else {
                key.push('?');
            }
        }
        key
    }

    /// Return `true` when two crash reports are considered duplicates.
    #[must_use]
    pub fn are_duplicates(&self, a: &ParsedCrashReport, b: &ParsedCrashReport) -> bool {
        self.dedup_key(a) == self.dedup_key(b)
    }

    /// Group a list of crash reports, keeping one representative per unique key.
    ///
    /// Insertion order of unique crashes is preserved.
    #[must_use]
    pub fn deduplicate(&self, reports: Vec<ParsedCrashReport>) -> Vec<DeduplicatedCrash> {
        let mut key_to_idx: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut result: Vec<DeduplicatedCrash> = Vec::new();

        for report in reports {
            let key = self.dedup_key(&report);
            if let Some(&idx) = key_to_idx.get(&key) {
                result[idx].duplicate_count += 1;
                if let Some(addr) = report.address {
                    result[idx].all_addresses.push(addr);
                }
            } else {
                let idx = result.len();
                key_to_idx.insert(key, idx);
                let addr = report.address;
                result.push(DeduplicatedCrash {
                    representative: report,
                    duplicate_count: 1,
                    all_addresses: addr.into_iter().collect(),
                });
            }
        }
        result
    }
}

/// A deduplicated crash group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeduplicatedCrash {
    /// The representative report for this group.
    pub representative: ParsedCrashReport,
    /// Total number of crashes in this group (including the representative).
    pub duplicate_count: usize,
    /// All unique addresses seen across all duplicates.
    pub all_addresses: Vec<u64>,
}

impl DeduplicatedCrash {
    /// Whether this group has been seen more than once.
    #[must_use]
    pub const fn is_recurring(&self) -> bool {
        self.duplicate_count > 1
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Coverage tracking
// ═════════════════════════════════════════════════════════════════════════════

/// A map of edge and basic-block coverage data from a single fuzz run.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct CoverageMap {
    /// Edge coverage: (`from_pc`, `to_pc`) -> hit count.
    pub edges: HashMap<(u64, u64), u64>,
    /// Block coverage: `pc` -> hit count.
    pub blocks: HashMap<u64, u64>,
}

impl CoverageMap {
    /// Create an empty coverage map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a taken edge from `from` to `to`.
    pub fn record_edge(&mut self, from: u64, to: u64) {
        *self.edges.entry((from, to)).or_insert(0) += 1;
        self.record_block(from);
        self.record_block(to);
    }

    /// Record execution of the basic block at `pc`.
    pub fn record_block(&mut self, pc: u64) {
        *self.blocks.entry(pc).or_insert(0) += 1;
    }

    /// Merge another coverage map into this one (accumulate counts).
    pub fn merge(&mut self, other: &Self) {
        for (&edge, &count) in &other.edges {
            *self.edges.entry(edge).or_insert(0) += count;
        }
        for (&block, &count) in &other.blocks {
            *self.blocks.entry(block).or_insert(0) += count;
        }
    }

    /// Total number of unique edges seen.
    #[must_use]
    pub fn total_edges(&self) -> usize {
        self.edges.len()
    }

    /// Total number of unique basic blocks seen.
    #[must_use]
    pub fn total_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Count edges present in `self` but *not* in `baseline`.
    #[must_use]
    pub fn new_edges_since(&self, baseline: &Self) -> usize {
        self.edges
            .keys()
            .filter(|e| !baseline.edges.contains_key(e))
            .count()
    }

    /// Return edge coverage ratio relative to `total_known` total edges.
    ///
    /// Clamps to `[0.0, 1.0]`.
    #[must_use]
    pub fn coverage_ratio(&self, total_known: usize) -> f64 {
        if total_known == 0 {
            return 0.0;
        }
        let edges = u32::try_from(self.total_edges()).unwrap_or(u32::MAX);
        let total = u32::try_from(total_known).unwrap_or(u32::MAX);
        (f64::from(edges) / f64::from(total)).min(1.0)
    }

    /// Return `true` when this map has at least one edge not in `other`.
    #[must_use]
    pub fn has_new_coverage(&self, other: &Self) -> bool {
        self.edges.keys().any(|e| !other.edges.contains_key(e))
    }
}

/// Aggregated coverage statistics for a fuzzing campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageStats {
    /// Total unique edges seen across all corpus entries.
    pub total_edges: usize,
    /// Total unique basic blocks seen.
    pub total_blocks: usize,
    /// Number of corpus entries.
    pub corpus_size: usize,
    /// Edge coverage ratio (0..1) relative to `total_known_edges`.
    pub coverage_ratio: f64,
    /// Rolling average of new edges discovered per run.
    pub new_edges_per_run: f64,
}

impl Default for CoverageStats {
    fn default() -> Self {
        Self {
            total_edges: 0,
            total_blocks: 0,
            corpus_size: 0,
            coverage_ratio: 0.0,
            new_edges_per_run: 0.0,
        }
    }
}

/// Tracks cumulative edge/block coverage across all fuzz runs.
#[derive(Debug, Clone)]
pub struct CoverageTracker {
    /// Accumulated map of all coverage seen so far.
    pub current: CoverageMap,
    /// Snapshot taken at the start of this tracking session.
    pub baseline: CoverageMap,
    /// Per-corpus-entry coverage maps (only those that added new coverage).
    pub corpus_maps: Vec<CoverageMap>,
    /// How many known total edges exist in the binary (0 = unknown).
    pub total_known_edges: usize,
    /// Cumulative new-edges count for rolling-average computation.
    cumulative_new_edges: u64,
    /// Total number of runs recorded.
    run_count: u64,
}

impl Default for CoverageTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl CoverageTracker {
    /// Create a new tracker with an empty baseline.
    #[must_use]
    pub fn new() -> Self {
        Self {
            current: CoverageMap::new(),
            baseline: CoverageMap::new(),
            corpus_maps: Vec::new(),
            total_known_edges: 0,
            cumulative_new_edges: 0,
            run_count: 0,
        }
    }

    /// Record coverage from one fuzz run.
    ///
    /// Returns `true` when the run discovered at least one new edge.
    pub fn record_run(&mut self, map: &CoverageMap) -> bool {
        self.run_count += 1;
        let new_count = map.new_edges_since(&self.current) as u64;
        let has_new = new_count > 0;
        if has_new {
            self.cumulative_new_edges += new_count;
            self.corpus_maps.push(map.clone());
        }
        self.current.merge(map);
        has_new
    }

    /// Total unique edges accumulated so far.
    #[must_use]
    pub fn total_unique_edges(&self) -> usize {
        self.current.total_edges()
    }

    /// Number of corpus entries that contributed new coverage.
    #[must_use]
    pub const fn seeds_with_new_coverage(&self) -> usize {
        self.corpus_maps.len()
    }

    /// Snapshot the current coverage as the new baseline.
    pub fn commit_baseline(&mut self) {
        self.baseline = self.current.clone();
    }

    /// Build a [`CoverageStats`] summary.
    #[must_use]
    pub fn stats(&self) -> CoverageStats {
        let total_edges = self.current.total_edges();
        let total_blocks = self.current.total_blocks();
        let corpus_size = self.corpus_maps.len();
        let coverage_ratio = if self.total_known_edges > 0 {
            self.current.coverage_ratio(self.total_known_edges)
        } else {
            0.0
        };
        let new_edges_per_run = if self.run_count == 0 {
            0.0
        } else {
            let num = u32::try_from(self.cumulative_new_edges).unwrap_or(u32::MAX);
            let den = u32::try_from(self.run_count).unwrap_or(u32::MAX);
            f64::from(num) / f64::from(den)
        };
        CoverageStats {
            total_edges,
            total_blocks,
            corpus_size,
            coverage_ratio,
            new_edges_per_run,
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// LibFuzzer log parser
// ═════════════════════════════════════════════════════════════════════════════

/// A single `NEW` coverage event from a `LibFuzzer` log line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageEvent {
    /// Run (iteration) number.
    pub run_number: u64,
    /// Edge coverage count at this point.
    pub coverage: u64,
    /// Feature count at this point.
    pub features: u64,
    /// Size of the triggering input.
    pub input_size: u64,
}

/// Aggregate statistics extracted from a `LibFuzzer` log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibFuzzerStats {
    /// Total number of executions recorded.
    pub total_runs: u64,
    /// Edge coverage at the final log entry.
    pub coverage_edges: u64,
    /// Feature count at the final log entry.
    pub features: u64,
    /// Corpus size (number of inputs) at the final log entry.
    pub corpus_size: u64,
    /// Total corpus size in bytes at the final log entry.
    pub corpus_bytes: u64,
    /// Executions per second at the final log entry.
    pub exec_per_second: f64,
    /// `RSS` memory usage in `MiB` at the final log entry.
    pub rss_mb: u64,
    /// All events where new coverage was discovered.
    pub new_coverage_events: Vec<CoverageEvent>,
    /// Raw crash/error lines found in the log.
    pub crashes: Vec<String>,
}

impl Default for LibFuzzerStats {
    fn default() -> Self {
        Self {
            total_runs: 0,
            coverage_edges: 0,
            features: 0,
            corpus_size: 0,
            corpus_bytes: 0,
            exec_per_second: 0.0,
            rss_mb: 0,
            new_coverage_events: Vec::new(),
            crashes: Vec::new(),
        }
    }
}

/// Stateless parser for `LibFuzzer` stdout/stderr logs.
pub struct LibFuzzerLogParser;

impl LibFuzzerLogParser {
    /// Parse a complete `LibFuzzer` log string and return aggregated statistics.
    #[must_use]
    pub fn parse(text: &str) -> LibFuzzerStats {
        let mut stats = LibFuzzerStats::default();

        for line in text.lines() {
            // LibFuzzer status lines: "#N  INITED ..." / "#N  NEW ..." / "#N  pulse ..."
            if line.starts_with('#')
                && let Some(entry) = Self::parse_status_line(line)
            {
                // Always update the aggregate state from the latest entry
                stats.total_runs = entry.run_number;
                if entry.coverage > 0 {
                    stats.coverage_edges = entry.coverage;
                }
                if entry.features > 0 {
                    stats.features = entry.features;
                }
                // Detect NEW coverage events by the keyword
                if line.contains("NEW") {
                    stats.new_coverage_events.push(entry);
                }
            }

            // Parse extra fields that appear on status lines
            if line.starts_with('#') {
                if let Some(v) = Self::field_u64(line, "corp:") {
                    stats.corpus_size = v;
                }
                if let Some(v) = Self::field_bytes(line, "corp:") {
                    stats.corpus_bytes = v;
                }
                if let Some(v) = Self::field_f64(line, "exec/s:") {
                    stats.exec_per_second = v;
                }
                if let Some(v) = Self::field_mb(line, "rss:") {
                    stats.rss_mb = v;
                }
            }

            // Crash / error lines
            if line.contains("==ERROR:") || line.contains("SUMMARY:") {
                stats.crashes.push(line.to_owned());
            }
        }
        stats
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Parse a `LibFuzzer` status line into a `CoverageEvent`.
    ///
    /// Format: `#2 INITED cov: 123 ft: 456 corp: 1/1b exec/s: 0 rss: 25Mb`
    fn parse_status_line(line: &str) -> Option<CoverageEvent> {
        // Run number is after '#'
        let rest = line.strip_prefix('#')?;
        let mut it = rest.split_whitespace();
        let run_str = it.next()?;
        let run_number: u64 = run_str.parse().ok()?;

        let coverage = Self::field_u64(line, "cov:").unwrap_or(0);
        let features = Self::field_u64(line, "ft:").unwrap_or(0);
        let input_size = Self::field_bytes_after_slash(line, "corp:");

        Some(CoverageEvent {
            run_number,
            coverage,
            features,
            input_size,
        })
    }

    /// Extract `u64` from `KEY: VALUE` in the line.
    fn field_u64(line: &str, key: &str) -> Option<u64> {
        let idx = line.find(key)?;
        let rest = line[idx + key.len()..].trim_start();
        let tok: String = rest.chars().take_while(char::is_ascii_digit).collect();
        tok.parse().ok()
    }

    /// Extract `f64` from `KEY: VALUE` in the line.
    fn field_f64(line: &str, key: &str) -> Option<f64> {
        let idx = line.find(key)?;
        let rest = line[idx + key.len()..].trim_start();
        let tok: String = rest
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        tok.parse().ok()
    }

    /// Extract `MB` value from `rss: 25Mb` patterns.
    fn field_mb(line: &str, key: &str) -> Option<u64> {
        let idx = line.find(key)?;
        let rest = line[idx + key.len()..].trim_start();
        let tok: String = rest.chars().take_while(char::is_ascii_digit).collect();
        tok.parse().ok()
    }

    /// Extract the byte count from `corp: N/Xb` patterns.
    fn field_bytes(line: &str, key: &str) -> Option<u64> {
        let idx = line.find(key)?;
        let rest = line[idx + key.len()..].trim_start();
        // format is "N/Xb"
        let slash = rest.find('/')?;
        let bytes_part = &rest[slash + 1..];
        let num: String = bytes_part
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        num.parse().ok()
    }

    /// Extract the input size from the second part of "corp: N/Xb" — i.e. X.
    fn field_bytes_after_slash(line: &str, key: &str) -> u64 {
        Self::field_bytes(line, key).unwrap_or(0)
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// FuzzingCampaign
// ═════════════════════════════════════════════════════════════════════════════

/// All data for a running or completed fuzzing campaign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzingCampaign {
    /// Human-readable campaign name.
    pub name: String,
    /// Name or path of the fuzzing target.
    pub target: String,
    /// Unix timestamp (seconds since epoch) when the campaign started.
    pub start_time: u64,
    /// Total number of inputs executed so far.
    pub total_executions: u64,
    /// All crash reports collected.
    pub crashes: Vec<ParsedCrashReport>,
    /// Deduplicated crash groups.
    pub unique_crashes: Vec<DeduplicatedCrash>,
    /// Coverage summary.
    pub coverage: CoverageStats,
    /// Measured executions per second.
    pub exec_per_second: f64,
    /// Number of inputs that timed out.
    pub timeout_count: u64,
    /// Number of inputs that caused OOM.
    pub oom_count: u64,
    /// Unix timestamp of when new coverage was last discovered.
    pub last_new_coverage: u64,
    /// Monotonic instant when new coverage was last discovered.
    /// Used by `is_stuck` to avoid sensitivity to wall-clock jumps
    /// (time-monotonic-vs-system).
    #[serde(skip)]
    pub last_coverage_instant: Option<std::time::Instant>,
    /// Monotonic instant when the campaign started.
    #[serde(skip)]
    pub start_instant: Option<std::time::Instant>,
}

impl FuzzingCampaign {
    /// Create a new campaign.
    #[must_use]
    pub fn new(name: String, target: String) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let instant = std::time::Instant::now();
        Self {
            name,
            target,
            start_time: now,
            total_executions: 0,
            crashes: Vec::new(),
            unique_crashes: Vec::new(),
            coverage: CoverageStats::default(),
            exec_per_second: 0.0,
            timeout_count: 0,
            oom_count: 0,
            last_new_coverage: now,
            last_coverage_instant: Some(instant),
            start_instant: Some(instant),
        }
    }

    /// Add a crash report, immediately deduplicating against existing crashes.
    pub fn add_crash(&mut self, report: ParsedCrashReport, dedup: &CrashDeduplicator) {
        let key = dedup.dedup_key(&report);
        // Check existing unique crashes
        for dc in &mut self.unique_crashes {
            if dedup.dedup_key(&dc.representative) == key {
                dc.duplicate_count += 1;
                if let Some(addr) = report.address {
                    dc.all_addresses.push(addr);
                }
                self.crashes.push(report);
                return;
            }
        }
        // New unique crash
        let addr = report.address;
        self.unique_crashes.push(DeduplicatedCrash {
            representative: report.clone(),
            duplicate_count: 1,
            all_addresses: addr.into_iter().collect(),
        });
        self.crashes.push(report);
    }

    /// Update execution statistics.
    pub fn update_stats(&mut self, execs: u64, time_secs: f64) {
        self.total_executions = execs;
        if time_secs > 0.0 {
            let execs_f = f64::from(u32::try_from(execs).unwrap_or(u32::MAX));
            self.exec_per_second = execs_f / time_secs;
        }
    }

    /// Return `true` when no new coverage has been found for `threshold_secs`.
    ///
    /// Uses a monotonic [`std::time::Instant`] when available (set by
    /// [`FuzzingCampaign::new`] or [`touch_coverage`]) so that wall-clock
    /// jumps cannot produce a false "not stuck" result
    /// (time-monotonic-vs-system fix).
    #[must_use]
    pub fn is_stuck(&self, threshold_secs: u64) -> bool {
        self.last_coverage_instant.map_or_else(|| {
            // Fallback when instant is unavailable (e.g. after deserialization).
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            now.saturating_sub(self.last_new_coverage) >= threshold_secs
        }, |last| last.elapsed().as_secs() >= threshold_secs)
    }

    /// Notify the campaign that new coverage was just discovered.
    pub fn touch_coverage(&mut self) {
        self.last_coverage_instant = Some(std::time::Instant::now());
        self.last_new_coverage = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
    }

    /// Return a multi-line human-readable summary.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Campaign: {} → {}\n\
             Executions : {}\n\
             Exec/s     : {:.1}\n\
             Total crashes  : {}\n\
             Unique crashes : {}\n\
             Timeouts   : {}\n\
             OOM        : {}\n\
             Coverage edges : {}\n\
             Corpus size    : {}",
            self.name,
            self.target,
            self.total_executions,
            self.exec_per_second,
            self.crashes.len(),
            self.unique_crashes.len(),
            self.timeout_count,
            self.oom_count,
            self.coverage.total_edges,
            self.coverage.corpus_size,
        )
    }

    /// Serialise this campaign to a JSON string.
    ///
    /// # Errors
    /// Returns a [`serde_json::Error`] when serialisation fails.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SanitizerHarness: combined runtime instrumentation model
// ═════════════════════════════════════════════════════════════════════════════

/// A combined `ASan` + `MSan` + `UBSan` harness that tracks all sanitizer state
/// in a single object.
#[derive(Debug, Default)]
pub struct SanitizerHarness {
    /// Address sanitizer component.
    pub asan: AddressSanitizer,
    /// Memory sanitizer component.
    pub msan: MemorySanitizer,
    /// UB sanitizer component.
    pub ubsan: UbSanitizer,
    /// All violation reports collected so far.
    pub reports: Vec<SanitizerReport>,
    /// Simulated call stack (return addresses).
    pub call_stack: Vec<u64>,
}

impl SanitizerHarness {
    /// Create a new, empty harness.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a return address onto the simulated call stack.
    pub fn push_frame(&mut self, return_addr: u64) {
        self.call_stack.push(return_addr);
    }

    /// Pop the top frame from the simulated call stack.
    pub fn pop_frame(&mut self) {
        self.call_stack.pop();
    }

    /// Record a `malloc`-style allocation.
    pub fn malloc(&mut self, addr: u64, size: usize) {
        self.asan.track_alloc(addr, size);
        // Mark the newly allocated bytes as uninitialised.
        self.msan.mark_undefined(addr, size);
    }

    /// Record a `free`-style deallocation.
    pub fn free(&mut self, addr: u64) {
        let result = self.asan.track_free(addr);
        if let SanitizerResult::DoubleFree { addr: a } = &result {
            self.reports.push(SanitizerReport::new(
                SanitizerKind::DoubleFree,
                format!("double-free at 0x{a:x}"),
                self.call_stack.clone(),
            ));
        }
        // Mark freed bytes as undefined for MSan.
        if let Some(alloc) = self.asan.heap.allocations.get(&addr) {
            let size = alloc.size;
            self.msan.mark_undefined(addr, size);
        }
    }

    /// Record a `memset` or bulk-initialise operation.
    pub fn memset(&mut self, addr: u64, size: usize) {
        self.msan.mark_defined(addr, size);
    }

    /// Record a memory read and check all sanitizers.
    pub fn read(&mut self, addr: u64, size: usize, alignment: usize) {
        // UBSan checks
        if let Err(r) = UbSanitizer::check_access(addr, alignment) {
            self.reports.push(SanitizerReport::new(
                r.kind,
                r.message,
                self.call_stack.clone(),
            ));
        }
        // ASan check
        if let Err(r) = self.asan.check(addr, size) {
            self.reports.push(SanitizerReport::new(
                r.kind,
                r.message,
                self.call_stack.clone(),
            ));
        }
        // MSan check
        if let Err(r) = self.msan.check(addr, size) {
            self.reports.push(SanitizerReport::new(
                r.kind,
                r.message,
                self.call_stack.clone(),
            ));
        }
    }

    /// Record a memory write and check all sanitizers.
    pub fn write(&mut self, addr: u64, size: usize, alignment: usize) {
        // UBSan checks
        if let Err(r) = UbSanitizer::check_access(addr, alignment) {
            self.reports.push(SanitizerReport::new(
                r.kind,
                r.message,
                self.call_stack.clone(),
            ));
        }
        // ASan check
        if let Err(r) = self.asan.check(addr, size) {
            self.reports.push(SanitizerReport::new(
                r.kind,
                r.message,
                self.call_stack.clone(),
            ));
        }
        // After a successful write, mark the memory as defined for MSan.
        if self.asan.check(addr, size).is_ok() {
            self.msan.mark_defined(addr, size);
        }
    }

    /// Perform a checked signed add, recording overflow if it occurs.
    pub fn checked_sadd(&mut self, a: i64, b: i64) -> Option<i64> {
        match UbSanitizer::checked_add(a, b) {
            Ok(v) => Some(v),
            Err(r) => {
                self.reports.push(SanitizerReport::new(
                    r.kind,
                    r.message,
                    self.call_stack.clone(),
                ));
                None
            }
        }
    }

    /// Perform a checked signed multiply, recording overflow if it occurs.
    pub fn checked_smul(&mut self, a: i64, b: i64) -> Option<i64> {
        match UbSanitizer::checked_mul(a, b) {
            Ok(v) => Some(v),
            Err(r) => {
                self.reports.push(SanitizerReport::new(
                    r.kind,
                    r.message,
                    self.call_stack.clone(),
                ));
                None
            }
        }
    }

    /// Perform a checked integer divide, recording division-by-zero.
    pub fn divide(&mut self, dividend: i64, divisor: i64) -> Option<i64> {
        if UbSanitizer::check_division(divisor) {
            self.reports.push(SanitizerReport::new(
                SanitizerKind::DivByZero,
                format!("division by zero: {dividend} / 0"),
                self.call_stack.clone(),
            ));
            return None;
        }
        Some(dividend / divisor)
    }

    /// Return `true` when any violation has been recorded.
    #[must_use]
    pub const fn has_violations(&self) -> bool {
        !self.reports.is_empty()
    }

    /// Return a slice of all recorded violation reports.
    #[must_use]
    pub fn violations(&self) -> &[SanitizerReport] {
        &self.reports
    }

    /// Clear all recorded reports (but preserve allocation state).
    pub fn clear(&mut self) {
        self.reports.clear();
    }

    /// Reset the entire harness to a fresh state.
    pub fn reset(&mut self) {
        *self = Self::new();
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Corpus management helpers
// ═════════════════════════════════════════════════════════════════════════════

/// A single seed in a fuzzer corpus.
#[derive(Debug, Clone)]
pub struct CorpusEntry {
    /// Unique identifier for this seed.
    pub id: u64,
    /// Raw bytes of the seed.
    pub data: Vec<u8>,
    /// Coverage map produced by executing this seed.
    pub coverage: CoverageMap,
    /// Whether this seed triggered a crash.
    pub is_crash: bool,
    /// Execution time in microseconds.
    pub exec_time_us: u64,
}

impl CorpusEntry {
    /// Create a new corpus entry.
    #[must_use]
    pub fn new(id: u64, data: Vec<u8>) -> Self {
        Self {
            id,
            data,
            coverage: CoverageMap::new(),
            is_crash: false,
            exec_time_us: 0,
        }
    }

    /// Length of the seed data.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the seed data is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// A managed collection of fuzzer seeds.
#[derive(Debug, Default)]
pub struct FuzzCorpus {
    /// All seeds, including those superseded by better seeds.
    pub entries: Vec<CorpusEntry>,
    /// Index of seeds that provide unique coverage.
    pub minimised: Vec<usize>,
    /// Combined coverage of the whole corpus.
    pub total_coverage: CoverageMap,
    /// Next seed ID to assign.
    next_id: u64,
}

impl FuzzCorpus {
    /// Create a new, empty corpus.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a seed to the corpus.
    ///
    /// Returns `true` when the seed contributes new coverage.
    pub fn add(&mut self, data: Vec<u8>, coverage: &CoverageMap) -> bool {
        let has_new = coverage.has_new_coverage(&self.total_coverage);
        let id = self.next_id;
        self.next_id += 1;
        let mut entry = CorpusEntry::new(id, data);
        entry.coverage = coverage.clone();
        if has_new {
            let idx = self.entries.len();
            self.minimised.push(idx);
            self.total_coverage.merge(coverage);
        }
        self.entries.push(entry);
        has_new
    }

    /// Total number of seeds (including non-coverage-increasing ones).
    #[must_use]
    pub const fn size(&self) -> usize {
        self.entries.len()
    }

    /// Number of minimised (coverage-increasing) seeds.
    #[must_use]
    pub const fn minimised_size(&self) -> usize {
        self.minimised.len()
    }

    /// Return references to the minimised seeds.
    #[must_use]
    pub fn minimised_entries(&self) -> Vec<&CorpusEntry> {
        self.minimised
            .iter()
            .filter_map(|&i| self.entries.get(i))
            .collect()
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Mutation engine skeleton
// ═════════════════════════════════════════════════════════════════════════════

/// A primitive pseudo-random number generator (xorshift64) for deterministic
/// mutation.  Not cryptographic — purely for fuzzing heuristics.
#[derive(Debug, Clone)]
pub struct FuzzRng {
    state: u64,
}

impl FuzzRng {
    /// Create a new RNG seeded with `seed`.  If `seed` is 0, uses 1 instead.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    /// Generate the next pseudo-random `u64`.
    pub const fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// Generate a pseudo-random `usize` in `[0, bound)`.
    ///
    /// # Panics
    ///
    /// Panics if `bound == 0`.
    pub fn next_usize(&mut self, bound: usize) -> usize {
        assert!(bound > 0, "bound must be > 0");
        // Reduce in u128 space then convert back: the modulo result is always
        // strictly less than `bound`, which is itself a `usize`, so the
        // `try_from` never fails.
        let raw = u128::from(self.next_u64());
        let reduced = raw % u128::try_from(bound).expect("usize fits in u128");
        usize::try_from(reduced).expect("reduced < bound (usize); fits in usize")
    }

    /// Generate a pseudo-random byte.
    pub const fn next_byte(&mut self) -> u8 {
        (self.next_u64() & 0xff) as u8
    }
}

/// Supported mutation strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationStrategy {
    /// Flip a single random bit.
    BitFlip,
    /// Set a random byte to a random value.
    ByteSet,
    /// Insert a random byte at a random position.
    ByteInsert,
    /// Delete a random byte.
    ByteDelete,
    /// Replace a random byte with an "interesting" value (0, 255, 127, etc.).
    InterestingByte,
    /// Swap two random bytes.
    ByteSwap,
    /// Repeat a random slice at a random position.
    ChunkRepeat,
}

impl MutationStrategy {
    /// All available strategies, in order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::BitFlip,
            Self::ByteSet,
            Self::ByteInsert,
            Self::ByteDelete,
            Self::InterestingByte,
            Self::ByteSwap,
            Self::ChunkRepeat,
        ]
    }
}

/// Applies mutations to byte buffers.
pub struct Mutator {
    rng: FuzzRng,
    /// Interesting byte values for the `InterestingByte` strategy.
    interesting: Vec<u8>,
}

impl Mutator {
    /// Create a new mutator with the given seed.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            rng: FuzzRng::new(seed),
            interesting: vec![0, 1, 0x7f, 0x80, 0xfe, 0xff],
        }
    }

    /// Apply a single mutation to `data` using the specified strategy.
    ///
    /// Returns `false` when the input is too short to apply the strategy.
    pub fn mutate(&mut self, data: &mut Vec<u8>, strategy: MutationStrategy) -> bool {
        if data.is_empty() {
            // Add a single byte so we can work with it
            data.push(self.rng.next_byte());
            return true;
        }
        match strategy {
            MutationStrategy::BitFlip => {
                let idx = self.rng.next_usize(data.len());
                let bit = 1u8 << (self.rng.next_u64() % 8);
                data[idx] ^= bit;
                true
            }
            MutationStrategy::ByteSet => {
                let idx = self.rng.next_usize(data.len());
                data[idx] = self.rng.next_byte();
                true
            }
            MutationStrategy::ByteInsert => {
                let idx = self.rng.next_usize(data.len());
                data.insert(idx, self.rng.next_byte());
                true
            }
            MutationStrategy::ByteDelete => {
                if data.len() <= 1 {
                    return false;
                }
                let idx = self.rng.next_usize(data.len());
                data.remove(idx);
                true
            }
            MutationStrategy::InterestingByte => {
                let pos = self.rng.next_usize(data.len());
                let pick = self.rng.next_usize(self.interesting.len());
                data[pos] = self.interesting[pick];
                true
            }
            MutationStrategy::ByteSwap => {
                if data.len() < 2 {
                    return false;
                }
                let a = self.rng.next_usize(data.len());
                let b = self.rng.next_usize(data.len());
                data.swap(a, b);
                true
            }
            MutationStrategy::ChunkRepeat => {
                if data.len() < 2 {
                    return false;
                }
                let src = self.rng.next_usize(data.len());
                let len = 1 + self.rng.next_usize(data.len() - src);
                let chunk: Vec<u8> = data[src..src + len].to_vec();
                let dst = self.rng.next_usize(data.len());
                for (i, &b) in chunk.iter().enumerate() {
                    let pos = (dst + i) % data.len();
                    data[pos] = b;
                }
                true
            }
        }
    }

    /// Apply `count` random mutations chosen uniformly from all strategies.
    pub fn mutate_random(&mut self, data: &mut Vec<u8>, count: usize) {
        let strategies = MutationStrategy::all();
        for _ in 0..count {
            let idx = self.rng.next_usize(strategies.len());
            self.mutate(data, strategies[idx]);
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Triage helpers
// ═════════════════════════════════════════════════════════════════════════════

/// A triage decision for a crash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TriageVerdict {
    /// Definitely exploitable.
    Exploitable,
    /// Likely exploitable but not confirmed.
    LikelyExploitable,
    /// Unlikely to be exploitable.
    NotExploitable,
    /// Not enough information to decide.
    Unknown,
}

impl std::fmt::Display for TriageVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exploitable => write!(f, "EXPLOITABLE"),
            Self::LikelyExploitable => write!(f, "LIKELY_EXPLOITABLE"),
            Self::NotExploitable => write!(f, "NOT_EXPLOITABLE"),
            Self::Unknown => write!(f, "UNKNOWN"),
        }
    }
}

/// Simple rule-based triage engine for crash reports.
pub struct CrashTriager;

impl CrashTriager {
    /// Triage a crash report based on error type and severity.
    #[must_use]
    pub const fn triage(report: &ParsedCrashReport) -> TriageVerdict {
        match report.severity {
            CrashSeverity::Critical => TriageVerdict::Exploitable,
            CrashSeverity::High => TriageVerdict::LikelyExploitable,
            CrashSeverity::Medium | CrashSeverity::Low | CrashSeverity::Info => {
                TriageVerdict::NotExploitable
            }
        }
    }

    /// Batch triage a slice of crash reports.
    #[must_use]
    pub fn triage_all(reports: &[ParsedCrashReport]) -> Vec<(TriageVerdict, &ParsedCrashReport)> {
        reports.iter().map(|r| (Self::triage(r), r)).collect()
    }

    /// Filter only exploitable or likely-exploitable crashes.
    #[must_use]
    pub fn exploitable_only(reports: &[ParsedCrashReport]) -> Vec<&ParsedCrashReport> {
        reports
            .iter()
            .filter(|r| {
                matches!(
                    Self::triage(r),
                    TriageVerdict::Exploitable | TriageVerdict::LikelyExploitable
                )
            })
            .collect()
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod extended_tests {
    use super::*;

    // ── SanitizerLogParser ────────────────────────────────────────────────────

    fn sample_asan_log() -> &'static str {
        r"==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6020000000b0 at pc 0x401234 bp 0x7ffe1234 sp 0x7ffe1230
WRITE of size 4 at 0x6020000000b0 thread T0
    #0 0x401234 in foo /home/user/src/foo.c:42:5
    #1 0x401456 in bar /home/user/src/bar.c:17:3
    #2 0x401678 in main /home/user/src/main.c:5:1
0x6020000000b0 is located 0 bytes to the right of 4-byte region [0x6020000000a0,0x6020000000a4)
allocated by thread T0 here:
    #0 0x7f1234 in malloc (/lib/libasan.so+0x12345)
    #1 0x401200 in setup /home/user/src/foo.c:10:3
freed by thread T0 here:
    #0 0x7f5678 in free (/lib/libasan.so+0x23456)
"
    }

    #[test]
    fn parser_detects_asan_tool() {
        let report = SanitizerLogParser::parse(sample_asan_log());
        assert_eq!(report.tool, SanitizerTool::ASan);
    }

    #[test]
    fn parser_extracts_error_type() {
        let report = SanitizerLogParser::parse(sample_asan_log());
        assert_eq!(report.error_type, "heap-buffer-overflow");
    }

    #[test]
    fn parser_extracts_write_access_type() {
        let report = SanitizerLogParser::parse(sample_asan_log());
        assert_eq!(report.access_type, Some(AccessType::Write));
    }

    #[test]
    fn parser_extracts_access_size() {
        let report = SanitizerLogParser::parse(sample_asan_log());
        assert_eq!(report.access_size, Some(4));
    }

    #[test]
    fn parser_extracts_address() {
        let report = SanitizerLogParser::parse(sample_asan_log());
        assert_eq!(report.address, Some(0x6020_0000_00b0));
    }

    #[test]
    fn parser_extracts_thread() {
        let report = SanitizerLogParser::parse(sample_asan_log());
        assert_eq!(report.thread, Some(0));
    }

    #[test]
    fn parser_extracts_stack_frames() {
        let report = SanitizerLogParser::parse(sample_asan_log());
        assert_eq!(report.stack_frames.len(), 3);
        assert_eq!(report.stack_frames[0].function.as_deref(), Some("foo"));
        assert_eq!(report.stack_frames[0].line, Some(42));
        assert_eq!(report.stack_frames[0].column, Some(5));
    }

    #[test]
    fn parser_extracts_allocation_frames() {
        let report = SanitizerLogParser::parse(sample_asan_log());
        assert!(!report.allocation_frames.is_empty());
    }

    #[test]
    fn parser_assigns_high_severity_to_heap_overflow() {
        let report = SanitizerLogParser::parse(sample_asan_log());
        assert_eq!(report.severity, CrashSeverity::High);
    }

    #[test]
    fn parser_raw_text_preserved() {
        let text = sample_asan_log();
        let report = SanitizerLogParser::parse(text);
        assert!(!report.raw_text.is_empty());
    }

    #[test]
    fn parser_parse_all_finds_one_block() {
        let reports = SanitizerLogParser::parse_all(sample_asan_log());
        assert_eq!(reports.len(), 1);
    }

    fn sample_uaf_log() -> &'static str {
        r"==99999==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc 0x402000 bp 0x7fff0000 sp 0x7ffefffc
READ of size 4 at 0x602000000010 thread T0
    #0 0x402000 in read_fn /src/vuln.c:30:1
    #1 0x403000 in caller /src/vuln.c:50:1
"
    }

    #[test]
    fn parser_uaf_is_critical() {
        let report = SanitizerLogParser::parse(sample_uaf_log());
        assert_eq!(report.severity, CrashSeverity::Critical);
    }

    #[test]
    fn parser_uaf_read_access() {
        let report = SanitizerLogParser::parse(sample_uaf_log());
        assert_eq!(report.access_type, Some(AccessType::Read));
    }

    #[test]
    fn parser_parse_all_multiple_blocks() {
        let combined = format!("{}\n{}", sample_asan_log(), sample_uaf_log());
        let reports = SanitizerLogParser::parse_all(&combined);
        assert_eq!(reports.len(), 2);
    }

    #[test]
    fn parser_empty_input_gives_unknown() {
        let report = SanitizerLogParser::parse("");
        assert_eq!(report.tool, SanitizerTool::Unknown);
        assert!(report.error_type.is_empty());
    }

    #[test]
    fn parsed_stack_frame_display() {
        let f = ParsedStackFrame {
            index: 0,
            address: Some(0x0040_1234),
            function: Some("foo".to_owned()),
            file: Some("/src/foo.c".to_owned()),
            line: Some(42),
            column: None,
        };
        let d = f.display();
        assert!(d.contains("foo"));
        assert!(d.contains("0x401234"));
    }

    #[test]
    fn parse_hex_u64_with_prefix() {
        assert_eq!(parse_hex_u64("0x1234abcd"), Some(0x1234_abcd));
    }

    #[test]
    fn parse_hex_u64_without_prefix() {
        assert_eq!(parse_hex_u64("deadbeef"), Some(0xdead_beef));
    }

    #[test]
    fn parse_hex_u64_with_trailing_garbage() {
        assert_eq!(parse_hex_u64("0x100,"), Some(0x100));
    }

    // ── CrashSeverity ordering ────────────────────────────────────────────────

    #[test]
    fn severity_ordering_correct() {
        assert!(CrashSeverity::Critical > CrashSeverity::High);
        assert!(CrashSeverity::High > CrashSeverity::Medium);
        assert!(CrashSeverity::Medium > CrashSeverity::Low);
        assert!(CrashSeverity::Low > CrashSeverity::Info);
    }

    // ── classify_crash_severity ───────────────────────────────────────────────

    #[test]
    fn severity_uaf_critical() {
        assert_eq!(
            classify_crash_severity("use-after-free"),
            CrashSeverity::Critical
        );
        assert_eq!(
            classify_crash_severity("heap-use-after-free"),
            CrashSeverity::Critical
        );
    }

    #[test]
    fn severity_heap_overflow_high() {
        assert_eq!(
            classify_crash_severity("heap-buffer-overflow"),
            CrashSeverity::High
        );
    }

    #[test]
    fn severity_integer_overflow_low() {
        assert_eq!(
            classify_crash_severity("integer-overflow"),
            CrashSeverity::Low
        );
    }

    #[test]
    fn severity_memory_leak_info() {
        assert_eq!(classify_crash_severity("memory-leak"), CrashSeverity::Info);
    }

    #[test]
    fn severity_unknown_medium() {
        assert_eq!(
            classify_crash_severity("some-unknown-error"),
            CrashSeverity::Medium
        );
    }

    // ── CrashDeduplicator ─────────────────────────────────────────────────────

    fn make_report(error: &str, funcs: &[&str]) -> ParsedCrashReport {
        let frames: Vec<ParsedStackFrame> = funcs
            .iter()
            .enumerate()
            .map(|(i, f)| ParsedStackFrame {
                index: i,
                address: Some(0x1000 + i as u64),
                function: Some((*f).to_owned()),
                file: None,
                line: None,
                column: None,
            })
            .collect();
        ParsedCrashReport {
            tool: SanitizerTool::ASan,
            error_type: error.to_owned(),
            access_type: Some(AccessType::Write),
            access_size: Some(4),
            address: Some(0x6020),
            thread: Some(0),
            stack_frames: frames,
            allocation_frames: Vec::new(),
            deallocation_frames: Vec::new(),
            raw_text: String::new(),
            severity: classify_crash_severity(error),
        }
    }

    #[test]
    fn dedup_same_key_same_crash() {
        let d = CrashDeduplicator::new();
        let a = make_report("heap-buffer-overflow", &["foo", "bar"]);
        let b = make_report("heap-buffer-overflow", &["foo", "bar"]);
        assert!(d.are_duplicates(&a, &b));
    }

    #[test]
    fn dedup_different_error_type_not_duplicate() {
        let d = CrashDeduplicator::new();
        let a = make_report("heap-buffer-overflow", &["foo", "bar"]);
        let b = make_report("use-after-free", &["foo", "bar"]);
        assert!(!d.are_duplicates(&a, &b));
    }

    #[test]
    fn dedup_different_stack_not_duplicate() {
        let d = CrashDeduplicator::new();
        let a = make_report("heap-buffer-overflow", &["foo", "bar"]);
        let b = make_report("heap-buffer-overflow", &["baz", "qux"]);
        assert!(!d.are_duplicates(&a, &b));
    }

    #[test]
    fn dedup_deduplicate_collapses_duplicates() {
        let d = CrashDeduplicator::new();
        let reports = vec![
            make_report("heap-buffer-overflow", &["foo", "bar"]),
            make_report("heap-buffer-overflow", &["foo", "bar"]),
            make_report("use-after-free", &["baz"]),
        ];
        let unique = d.deduplicate(reports);
        assert_eq!(unique.len(), 2);
        let hbo = unique
            .iter()
            .find(|u| u.representative.error_type == "heap-buffer-overflow")
            .unwrap();
        assert_eq!(hbo.duplicate_count, 2);
    }

    #[test]
    fn dedup_key_ignores_addresses_by_default() {
        let d = CrashDeduplicator::new();
        let mut a = make_report("heap-buffer-overflow", &["foo"]);
        let mut b = make_report("heap-buffer-overflow", &["foo"]);
        a.stack_frames[0].address = Some(0x1111);
        b.stack_frames[0].address = Some(0x2222);
        assert!(d.are_duplicates(&a, &b));
    }

    #[test]
    fn dedup_is_recurring_true_for_two() {
        let d = CrashDeduplicator::new();
        let reports = vec![
            make_report("double-free", &["x"]),
            make_report("double-free", &["x"]),
        ];
        let unique = d.deduplicate(reports);
        assert!(unique[0].is_recurring());
    }

    // ── CoverageMap ───────────────────────────────────────────────────────────

    #[test]
    fn coverage_map_record_edge_increments() {
        let mut m = CoverageMap::new();
        m.record_edge(0x1000, 0x2000);
        m.record_edge(0x1000, 0x2000);
        assert_eq!(*m.edges.get(&(0x1000, 0x2000)).unwrap(), 2);
    }

    #[test]
    fn coverage_map_total_edges() {
        let mut m = CoverageMap::new();
        m.record_edge(1, 2);
        m.record_edge(3, 4);
        assert_eq!(m.total_edges(), 2);
    }

    #[test]
    fn coverage_map_total_blocks_includes_both_endpoints() {
        let mut m = CoverageMap::new();
        m.record_edge(0xA, 0xB);
        assert!(m.total_blocks() >= 2);
    }

    #[test]
    fn coverage_map_merge_accumulates() {
        let mut a = CoverageMap::new();
        a.record_edge(1, 2);
        let mut b = CoverageMap::new();
        b.record_edge(3, 4);
        a.merge(&b);
        assert_eq!(a.total_edges(), 2);
    }

    #[test]
    fn coverage_map_new_edges_since() {
        let mut baseline = CoverageMap::new();
        baseline.record_edge(1, 2);
        let mut new_map = CoverageMap::new();
        new_map.record_edge(1, 2);
        new_map.record_edge(3, 4);
        assert_eq!(new_map.new_edges_since(&baseline), 1);
    }

    #[test]
    fn coverage_map_coverage_ratio() {
        let mut m = CoverageMap::new();
        m.record_edge(1, 2);
        m.record_edge(3, 4);
        let ratio = m.coverage_ratio(4);
        assert!((ratio - 0.5).abs() < 1e-9);
    }

    #[test]
    fn coverage_map_coverage_ratio_zero_total() {
        let m = CoverageMap::new();
        assert!((m.coverage_ratio(0)).abs() < f64::EPSILON);
    }

    // ── CoverageTracker ───────────────────────────────────────────────────────

    #[test]
    fn coverage_tracker_record_run_new_coverage() {
        let mut tracker = CoverageTracker::new();
        let mut m = CoverageMap::new();
        m.record_edge(1, 2);
        assert!(tracker.record_run(&m));
    }

    #[test]
    fn coverage_tracker_record_run_no_new_coverage() {
        let mut tracker = CoverageTracker::new();
        let mut m = CoverageMap::new();
        m.record_edge(1, 2);
        tracker.record_run(&m);
        // Same coverage again: no new edges
        assert!(!tracker.record_run(&m));
    }

    #[test]
    fn coverage_tracker_seeds_with_new_coverage() {
        let mut tracker = CoverageTracker::new();
        let mut m1 = CoverageMap::new();
        m1.record_edge(1, 2);
        let mut m2 = CoverageMap::new();
        m2.record_edge(3, 4);
        tracker.record_run(&m1);
        tracker.record_run(&m2);
        assert_eq!(tracker.seeds_with_new_coverage(), 2);
    }

    #[test]
    fn coverage_tracker_stats_has_correct_corpus_size() {
        let mut tracker = CoverageTracker::new();
        let mut m = CoverageMap::new();
        m.record_edge(10, 20);
        tracker.record_run(&m);
        let stats = tracker.stats();
        assert_eq!(stats.corpus_size, 1);
    }

    #[test]
    fn coverage_tracker_commit_baseline() {
        let mut tracker = CoverageTracker::new();
        let mut m = CoverageMap::new();
        m.record_edge(1, 2);
        tracker.record_run(&m);
        tracker.commit_baseline();
        assert_eq!(tracker.baseline.total_edges(), 1);
    }

    // ── LibFuzzerLogParser ────────────────────────────────────────────────────

    fn sample_libfuzzer_log() -> &'static str {
        "#2\tINITED cov: 123 ft: 456 corp: 1/1b exec/s: 0 rss: 25Mb\n\
         #3\tNEW    cov: 124 ft: 458 corp: 2/3b exec/s: 0 rss: 25Mb L: 2/2 MS: 1 ChangeByte-\n\
         #10\tpulse  cov: 124 ft: 458 corp: 2/3b exec/s: 100 rss: 26Mb\n\
         #100\tNEW    cov: 130 ft: 470 corp: 3/5b exec/s: 200 rss: 27Mb L: 2/2 MS: 1 FlipBit-\n"
    }

    #[test]
    fn libfuzzer_parser_total_runs() {
        let stats = LibFuzzerLogParser::parse(sample_libfuzzer_log());
        assert_eq!(stats.total_runs, 100);
    }

    #[test]
    fn libfuzzer_parser_coverage_edges() {
        let stats = LibFuzzerLogParser::parse(sample_libfuzzer_log());
        assert_eq!(stats.coverage_edges, 130);
    }

    #[test]
    fn libfuzzer_parser_new_coverage_events_count() {
        let stats = LibFuzzerLogParser::parse(sample_libfuzzer_log());
        assert_eq!(stats.new_coverage_events.len(), 2);
    }

    #[test]
    fn libfuzzer_parser_exec_per_second() {
        let stats = LibFuzzerLogParser::parse(sample_libfuzzer_log());
        assert!(stats.exec_per_second >= 200.0);
    }

    #[test]
    fn libfuzzer_parser_rss_mb() {
        let stats = LibFuzzerLogParser::parse(sample_libfuzzer_log());
        assert_eq!(stats.rss_mb, 27);
    }

    #[test]
    fn libfuzzer_parser_no_crashes_in_clean_log() {
        let stats = LibFuzzerLogParser::parse(sample_libfuzzer_log());
        assert!(stats.crashes.is_empty());
    }

    #[test]
    fn libfuzzer_parser_detects_crash_line() {
        let log = format!(
            "{}\n==1234==ERROR: AddressSanitizer: heap-buffer-overflow\n",
            sample_libfuzzer_log()
        );
        let stats = LibFuzzerLogParser::parse(&log);
        assert_eq!(stats.crashes.len(), 1);
    }

    // ── FuzzingCampaign ───────────────────────────────────────────────────────

    #[test]
    fn campaign_new_sets_name_target() {
        let c = FuzzingCampaign::new("test-campaign".into(), "target-binary".into());
        assert_eq!(c.name, "test-campaign");
        assert_eq!(c.target, "target-binary");
    }

    #[test]
    fn campaign_add_crash_increments_total() {
        let mut c = FuzzingCampaign::new("c".into(), "t".into());
        let dedup = CrashDeduplicator::new();
        let r = make_report("heap-buffer-overflow", &["foo"]);
        c.add_crash(r, &dedup);
        assert_eq!(c.crashes.len(), 1);
        assert_eq!(c.unique_crashes.len(), 1);
    }

    #[test]
    fn campaign_add_duplicate_crash_does_not_increase_unique() {
        let mut c = FuzzingCampaign::new("c".into(), "t".into());
        let dedup = CrashDeduplicator::new();
        let r1 = make_report("heap-buffer-overflow", &["foo"]);
        let r2 = make_report("heap-buffer-overflow", &["foo"]);
        c.add_crash(r1, &dedup);
        c.add_crash(r2, &dedup);
        assert_eq!(c.crashes.len(), 2);
        assert_eq!(c.unique_crashes.len(), 1);
        assert_eq!(c.unique_crashes[0].duplicate_count, 2);
    }

    #[test]
    fn campaign_update_stats() {
        let mut c = FuzzingCampaign::new("c".into(), "t".into());
        c.update_stats(10_000, 10.0);
        assert_eq!(c.total_executions, 10_000);
        assert!((c.exec_per_second - 1000.0).abs() < 1e-6);
    }

    #[test]
    fn campaign_to_json_round_trips() {
        let mut c = FuzzingCampaign::new("json-test".into(), "bin".into());
        c.update_stats(1000, 1.0);
        let json = c.to_json().unwrap();
        assert!(json.contains("json-test"));
        assert!(json.contains("total_executions"));
    }

    #[test]
    fn campaign_summary_contains_key_fields() {
        let c = FuzzingCampaign::new("s".into(), "b".into());
        let s = c.summary();
        assert!(s.contains("Campaign"));
        assert!(s.contains("Executions"));
    }

    // ── SanitizerHarness ──────────────────────────────────────────────────────

    #[test]
    fn harness_malloc_write_clean() {
        let mut h = SanitizerHarness::new();
        h.malloc(0x1000, 64);
        h.write(0x1000, 8, 8);
        assert!(!h.has_violations());
    }

    #[test]
    fn harness_use_after_free_detected() {
        let mut h = SanitizerHarness::new();
        h.malloc(0x2000, 16);
        h.free(0x2000);
        h.read(0x2000, 4, 1);
        assert!(h.has_violations());
        let v = h.violations();
        assert!(v.iter().any(|r| r.kind == SanitizerKind::UseAfterFree));
    }

    #[test]
    fn harness_double_free_detected() {
        let mut h = SanitizerHarness::new();
        h.malloc(0x3000, 8);
        h.free(0x3000);
        h.free(0x3000);
        assert!(h.has_violations());
        assert!(
            h.violations()
                .iter()
                .any(|r| r.kind == SanitizerKind::DoubleFree)
        );
    }

    #[test]
    fn harness_heap_overflow_on_write() {
        let mut h = SanitizerHarness::new();
        h.malloc(0x4000, 4);
        h.write(0x4000, 8, 1); // 8 > 4
        assert!(h.has_violations());
        assert!(
            h.violations()
                .iter()
                .any(|r| r.kind == SanitizerKind::HeapOverflow)
        );
    }

    #[test]
    fn harness_null_deref_read() {
        let mut h = SanitizerHarness::new();
        h.read(0, 4, 4);
        assert!(h.has_violations());
        assert!(
            h.violations()
                .iter()
                .any(|r| r.kind == SanitizerKind::NullDeref)
        );
    }

    #[test]
    fn harness_misaligned_access() {
        let mut h = SanitizerHarness::new();
        h.malloc(0x5000, 64);
        h.read(0x5001, 4, 4); // misaligned
        assert!(h.has_violations());
        assert!(
            h.violations()
                .iter()
                .any(|r| r.kind == SanitizerKind::Misaligned)
        );
    }

    #[test]
    fn harness_int_overflow_sadd() {
        let mut h = SanitizerHarness::new();
        let result = h.checked_sadd(i64::MAX, 1);
        assert!(result.is_none());
        assert!(
            h.violations()
                .iter()
                .any(|r| r.kind == SanitizerKind::IntOverflow)
        );
    }

    #[test]
    fn harness_int_overflow_smul() {
        let mut h = SanitizerHarness::new();
        let result = h.checked_smul(i64::MAX, 2);
        assert!(result.is_none());
        assert!(
            h.violations()
                .iter()
                .any(|r| r.kind == SanitizerKind::IntOverflow)
        );
    }

    #[test]
    fn harness_divide_by_zero() {
        let mut h = SanitizerHarness::new();
        let result = h.divide(100, 0);
        assert!(result.is_none());
        assert!(
            h.violations()
                .iter()
                .any(|r| r.kind == SanitizerKind::DivByZero)
        );
    }

    #[test]
    fn harness_clear_removes_reports() {
        let mut h = SanitizerHarness::new();
        h.divide(1, 0);
        assert!(h.has_violations());
        h.clear();
        assert!(!h.has_violations());
    }

    #[test]
    fn harness_push_pop_frame() {
        let mut h = SanitizerHarness::new();
        h.push_frame(0xdead_beef);
        assert_eq!(h.call_stack.len(), 1);
        h.pop_frame();
        assert!(h.call_stack.is_empty());
    }

    #[test]
    fn harness_memset_marks_defined() {
        let mut h = SanitizerHarness::new();
        h.malloc(0x6000, 32);
        h.memset(0x6000, 32);
        // After memset, reading should not trigger MSan uninit
        h.read(0x6000, 8, 1);
        // Should have no MSan violations (heap access is within bounds)
        let msan_violations = h
            .violations()
            .iter()
            .filter(|r| r.kind == SanitizerKind::MemoryUninit)
            .count();
        assert_eq!(msan_violations, 0);
    }

    #[test]
    fn harness_divide_ok() {
        let mut h = SanitizerHarness::new();
        let result = h.divide(10, 2);
        assert_eq!(result, Some(5));
        assert!(!h.has_violations());
    }

    // ── FuzzRng ───────────────────────────────────────────────────────────────

    #[test]
    fn fuzz_rng_deterministic() {
        let mut a = FuzzRng::new(42);
        let mut b = FuzzRng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn fuzz_rng_zero_seed_not_stuck() {
        let mut r = FuzzRng::new(0);
        let v = r.next_u64();
        assert_ne!(v, 0);
    }

    #[test]
    fn fuzz_rng_next_usize_in_range() {
        let mut r = FuzzRng::new(1234);
        for _ in 0..1000 {
            let v = r.next_usize(10);
            assert!(v < 10);
        }
    }

    // ── Mutator ───────────────────────────────────────────────────────────────

    #[test]
    fn mutator_bit_flip_changes_data() {
        let mut m = Mutator::new(1);
        let original = vec![0u8; 16];
        let mut data = original.clone();
        m.mutate(&mut data, MutationStrategy::BitFlip);
        assert_ne!(data, original);
    }

    #[test]
    fn mutator_byte_insert_increases_length() {
        let mut m = Mutator::new(2);
        let mut data = vec![1u8, 2, 3, 4];
        m.mutate(&mut data, MutationStrategy::ByteInsert);
        assert_eq!(data.len(), 5);
    }

    #[test]
    fn mutator_byte_delete_decreases_length() {
        let mut m = Mutator::new(3);
        let mut data = vec![1u8, 2, 3, 4];
        m.mutate(&mut data, MutationStrategy::ByteDelete);
        assert_eq!(data.len(), 3);
    }

    #[test]
    fn mutator_byte_delete_on_single_byte_returns_false() {
        let mut m = Mutator::new(4);
        let mut data = vec![0xffu8];
        let ok = m.mutate(&mut data, MutationStrategy::ByteDelete);
        assert!(!ok);
    }

    #[test]
    fn mutator_interesting_byte_uses_predefined_values() {
        let mut m = Mutator::new(5);
        let mut data = vec![0x42u8; 256];
        for _ in 0..100 {
            m.mutate(&mut data, MutationStrategy::InterestingByte);
        }
        // At least one interesting byte should appear in the buffer.
        let interesting = [0u8, 1, 0x7f, 0x80, 0xfe, 0xff];
        assert!(data.iter().any(|b| interesting.contains(b)));
    }

    #[test]
    fn mutator_random_does_not_panic_on_empty() {
        let mut m = Mutator::new(99);
        let mut data: Vec<u8> = Vec::new();
        m.mutate_random(&mut data, 10);
        // After mutations, at least one byte should exist
        assert!(!data.is_empty());
    }

    // ── FuzzCorpus ────────────────────────────────────────────────────────────

    #[test]
    fn fuzz_corpus_add_returns_true_for_new_coverage() {
        let mut corpus = FuzzCorpus::new();
        let mut m = CoverageMap::new();
        m.record_edge(1, 2);
        assert!(corpus.add(vec![1, 2, 3], &m));
    }

    #[test]
    fn fuzz_corpus_add_returns_false_for_duplicate_coverage() {
        let mut corpus = FuzzCorpus::new();
        let mut m = CoverageMap::new();
        m.record_edge(1, 2);
        corpus.add(vec![1], &m);
        assert!(!corpus.add(vec![2], &m));
    }

    #[test]
    fn fuzz_corpus_size_tracks_all_entries() {
        let mut corpus = FuzzCorpus::new();
        corpus.add(vec![1], &CoverageMap::new());
        corpus.add(vec![2], &CoverageMap::new());
        assert_eq!(corpus.size(), 2);
    }

    #[test]
    fn fuzz_corpus_minimised_size_only_counts_new_coverage() {
        let mut corpus = FuzzCorpus::new();
        let mut m1 = CoverageMap::new();
        m1.record_edge(1, 2);
        corpus.add(vec![1], &m1);
        corpus.add(vec![2], &CoverageMap::new()); // no new coverage
        assert_eq!(corpus.minimised_size(), 1);
    }

    // ── CrashTriager ─────────────────────────────────────────────────────────

    #[test]
    fn triager_uaf_is_exploitable() {
        let r = make_report("use-after-free", &["foo"]);
        assert_eq!(CrashTriager::triage(&r), TriageVerdict::Exploitable);
    }

    #[test]
    fn triager_heap_overflow_likely_exploitable() {
        let r = make_report("heap-buffer-overflow", &["bar"]);
        assert_eq!(CrashTriager::triage(&r), TriageVerdict::LikelyExploitable);
    }

    #[test]
    fn triager_info_not_exploitable() {
        let r = make_report("memory-leak", &["baz"]);
        assert_eq!(CrashTriager::triage(&r), TriageVerdict::NotExploitable);
    }

    #[test]
    fn triager_exploitable_only_filters_correctly() {
        let reports = vec![
            make_report("use-after-free", &["a"]),
            make_report("memory-leak", &["b"]),
            make_report("heap-buffer-overflow", &["c"]),
        ];
        let exploitable = CrashTriager::exploitable_only(&reports);
        assert_eq!(exploitable.len(), 2);
    }

    #[test]
    fn triager_triage_all_has_same_length() {
        let reports = vec![
            make_report("use-after-free", &["a"]),
            make_report("memory-leak", &["b"]),
        ];
        let triaged = CrashTriager::triage_all(&reports);
        assert_eq!(triaged.len(), 2);
    }

    // ── SanitizerTool / AccessType display ───────────────────────────────────

    #[test]
    fn sanitizer_tool_display() {
        assert_eq!(SanitizerTool::ASan.to_string(), "AddressSanitizer");
        assert_eq!(SanitizerTool::MSan.to_string(), "MemorySanitizer");
        assert_eq!(SanitizerTool::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn access_type_display() {
        assert_eq!(AccessType::Read.to_string(), "READ");
        assert_eq!(AccessType::Write.to_string(), "WRITE");
    }

    #[test]
    fn crash_severity_display() {
        assert_eq!(CrashSeverity::Critical.to_string(), "CRITICAL");
        assert_eq!(CrashSeverity::Info.to_string(), "INFO");
    }

    // ── CorpusEntry ───────────────────────────────────────────────────────────

    #[test]
    fn corpus_entry_len() {
        let e = CorpusEntry::new(0, vec![1, 2, 3]);
        assert_eq!(e.len(), 3);
        assert!(!e.is_empty());
    }

    #[test]
    fn corpus_entry_empty() {
        let e = CorpusEntry::new(0, vec![]);
        assert!(e.is_empty());
    }

    // ── ParsedCrashReport helpers ─────────────────────────────────────────────

    #[test]
    fn crash_report_summary_contains_error_type() {
        let r = make_report("heap-buffer-overflow", &["foo"]);
        let s = r.summary();
        assert!(s.contains("heap-buffer-overflow"));
    }

    #[test]
    fn crash_report_top_function() {
        let r = make_report("heap-buffer-overflow", &["my_func", "caller"]);
        assert_eq!(r.top_function(), Some("my_func"));
    }

    #[test]
    fn crash_report_top_function_empty_stack() {
        let mut r = make_report("heap-buffer-overflow", &[]);
        r.stack_frames.clear();
        assert_eq!(r.top_function(), None);
    }
}

// ── AddressSanitizerReport ─────────────────────────────────────────────────────

/// A single stack frame parsed from an ASAN report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackFrame {
    /// Frame index (0 = innermost).
    pub index: usize,
    /// Hexadecimal program-counter value, if present.
    pub address: Option<u64>,
    /// Symbol / function name, if present.
    pub symbol: Option<String>,
    /// Source file and line, if present.
    pub location: Option<String>,
}

/// A parsed `AddressSanitizer` report.
#[derive(Debug, Clone)]
pub struct AsanReport {
    /// Error type string, e.g. `"heap-buffer-overflow"`.
    pub error_type: String,
    /// Address involved in the violation (may be 0 when not reported).
    pub address: u64,
    /// Parsed stack frames from the first (most relevant) stack in the report.
    pub stack_trace: Vec<StackFrame>,
}

impl AsanReport {
    /// Return a one-line summary of this report.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "ASAN: {} @ 0x{:x} ({} frames)",
            self.error_type,
            self.address,
            self.stack_trace.len()
        )
    }
}

/// Parse a textual ASAN report (as written to stderr by the runtime) into an
/// [`AsanReport`].
///
/// Returns `None` if the text does not look like an ASAN report.
///
/// # Format assumed
/// ```text
/// ==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
///     #0 0x4a1234 in my_func /home/user/src/foo.c:42
///     #1 0x4a5678 in main /home/user/src/foo.c:100
/// ```
#[must_use]
pub fn parse_asan_report(text: &str) -> Option<AsanReport> {
    // Locate the "ERROR: AddressSanitizer:" header line.
    let header = text.lines().find(|l| l.contains("AddressSanitizer:"))?;

    // Extract the error type: the word(s) after "AddressSanitizer: " up to
    // " on address" or end-of-line.
    let after_colon = header
        .find("AddressSanitizer:")
        .map(|pos| header[pos + "AddressSanitizer:".len()..].trim())?;

    let error_type = after_colon.find(" on address").map_or_else(
        || {
            after_colon.find(" at ").map_or_else(
                || {
                    let end = after_colon.find('(').unwrap_or(after_colon.len());
                    after_colon[..end].trim().to_string()
                },
                |idx| after_colon[..idx].trim().to_string(),
            )
        },
        |idx| after_colon[..idx].trim().to_string(),
    );

    // Extract the address from "on address 0x..." if present.
    let address = header.find("on address 0x").map_or(0, |addr_pos| {
        let addr_str = &header[addr_pos + "on address 0x".len()..];
        let end = addr_str
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(addr_str.len());
        u64::from_str_radix(&addr_str[..end], 16).unwrap_or(0)
    });

    // Parse stack frames: lines that match "    #N 0xADDR in SYMBOL LOCATION"
    let mut stack_trace = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('#') {
            continue;
        }
        // "#0 0x4a1234 in my_func /home/..."
        let mut parts = trimmed.splitn(2, ' ');
        let index_str = parts.next().unwrap_or("").trim_start_matches('#');
        let rest = parts.next().unwrap_or("").trim();
        let index: usize = index_str.parse().unwrap_or(stack_trace.len());

        let (frame_addr, after_addr) = if rest.starts_with("0x") {
            let end = rest
                .find(|c: char| !c.is_ascii_hexdigit() && c != 'x' && c != 'X')
                .unwrap_or(rest.len());
            let hex = rest[2..end.max(2)].to_string();
            let addr = u64::from_str_radix(&hex, 16).ok();
            (addr, rest[end..].trim())
        } else {
            (None, rest)
        };

        // `after_addr` may be "in foo /path..." (no leading space, already
        // trimmed) or " in foo /path..." (space preserved).  Handle both.
        let sym_and_loc_opt: Option<&str> = after_addr.strip_prefix("in ").or_else(|| {
            after_addr
                .find(" in ")
                .map(|pos| &after_addr[pos + " in ".len()..])
        });

        let (symbol, location) = sym_and_loc_opt.map_or((None, None), |sym_and_loc| {
            sym_and_loc.find(' ').map_or_else(
                || (Some(sym_and_loc.trim().to_string()), None),
                |sp| {
                    (
                        Some(sym_and_loc[..sp].to_string()),
                        Some(sym_and_loc[sp + 1..].trim().to_string()),
                    )
                },
            )
        });

        stack_trace.push(StackFrame {
            index,
            address: frame_addr,
            symbol,
            location,
        });
    }

    Some(AsanReport {
        error_type,
        address,
        stack_trace,
    })
}

// ── SanitizerConfig ───────────────────────────────────────────────────────────

/// The set of sanitizer kinds that [`SanitizerConfig`] understands.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SanitizerFlag {
    /// `AddressSanitizer`.
    ASan,
    /// `UndefinedBehaviorSanitizer`.
    UBSan,
    /// `MemorySanitizer`.
    MSan,
    /// `ThreadSanitizer`.
    TSan,
    /// `LeakSanitizer`.
    LSan,
}

impl std::fmt::Display for SanitizerFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ASan => write!(f, "asan"),
            Self::UBSan => write!(f, "ubsan"),
            Self::MSan => write!(f, "msan"),
            Self::TSan => write!(f, "tsan"),
            Self::LSan => write!(f, "lsan"),
        }
    }
}

/// Configuration for which sanitizers are active and how to enable them.
///
/// # Examples
/// ```
/// # use rustre_fuzz_sanitizers::{SanitizerConfig, SanitizerFlag};
/// let mut cfg = SanitizerConfig::new();
/// cfg.enable(SanitizerFlag::ASan);
/// cfg.enable(SanitizerFlag::UBSan);
/// let flags = cfg.cmdline_flags();
/// assert!(flags.iter().any(|f| f.contains("address")));
/// ```
#[derive(Debug, Clone, Default)]
pub struct SanitizerConfig {
    /// The set of enabled sanitizer kinds.
    pub enabled: HashSet<SanitizerFlag>,
}

impl SanitizerConfig {
    /// Create a configuration with no sanitizers enabled.
    #[must_use]
    pub fn new() -> Self {
        Self {
            enabled: HashSet::new(),
        }
    }

    /// Enable a sanitizer.
    pub fn enable(&mut self, kind: SanitizerFlag) {
        self.enabled.insert(kind);
    }

    /// Disable a sanitizer.
    pub fn disable(&mut self, kind: &SanitizerFlag) {
        self.enabled.remove(kind);
    }

    /// Return a list of `(name, value)` environment variables that should be
    /// set when running an instrumented binary.
    #[must_use]
    pub fn env_vars(&self) -> Vec<(String, String)> {
        let mut vars = Vec::new();
        if self.enabled.contains(&SanitizerFlag::ASan) {
            vars.push((
                "ASAN_OPTIONS".into(),
                "abort_on_error=1:detect_leaks=0".into(),
            ));
        }
        if self.enabled.contains(&SanitizerFlag::LSan) {
            vars.push(("LSAN_OPTIONS".into(), "verbosity=1".into()));
        }
        if self.enabled.contains(&SanitizerFlag::UBSan) {
            vars.push((
                "UBSAN_OPTIONS".into(),
                "print_stacktrace=1:halt_on_error=1".into(),
            ));
        }
        if self.enabled.contains(&SanitizerFlag::MSan) {
            vars.push(("MSAN_OPTIONS".into(), "poison_in_dtor=1".into()));
        }
        if self.enabled.contains(&SanitizerFlag::TSan) {
            vars.push(("TSAN_OPTIONS".into(), "halt_on_error=1".into()));
        }
        vars
    }

    /// Return the compiler flags (e.g. `-fsanitize=address,undefined`) that
    /// enable the configured sanitizers.
    #[must_use]
    pub fn cmdline_flags(&self) -> Vec<String> {
        if self.enabled.is_empty() {
            return Vec::new();
        }
        // Collect the sanitizer names that go into `-fsanitize=`.
        let mut names: Vec<&str> = Vec::new();
        if self.enabled.contains(&SanitizerFlag::ASan) {
            names.push("address");
        }
        if self.enabled.contains(&SanitizerFlag::UBSan) {
            names.push("undefined");
        }
        if self.enabled.contains(&SanitizerFlag::MSan) {
            names.push("memory");
        }
        if self.enabled.contains(&SanitizerFlag::TSan) {
            names.push("thread");
        }
        if self.enabled.contains(&SanitizerFlag::LSan) {
            names.push("leak");
        }

        let mut flags = vec![format!("-fsanitize={}", names.join(","))];
        // Useful companion flags.
        flags.push("-fno-omit-frame-pointer".into());
        if self.enabled.contains(&SanitizerFlag::ASan)
            || self.enabled.contains(&SanitizerFlag::MSan)
        {
            flags.push("-fno-optimize-sibling-calls".into());
        }
        flags
    }
}

// ── FuzzReproducer ────────────────────────────────────────────────────────────

/// Utilities for generating crash-reproduction artifacts.
pub struct FuzzReproducer;

impl FuzzReproducer {
    /// Generate a shell script that:
    /// 1. Writes `crash` bytes to a temporary file.
    /// 2. Runs `target_cmd` with that file as its first argument.
    ///
    /// The script is written to `output_path` (created/overwritten) and the
    /// text is also returned so callers can inspect it without re-reading the
    /// file.
    ///
    /// # Arguments
    /// * `crash`       — Raw crash bytes to reproduce.
    /// * `target_cmd`  — Path or command to the fuzz target binary.
    /// * `output_path` — Where to write the shell script.
    #[must_use]
    pub fn generate_repro_script(crash: &[u8], target_cmd: &str, output_path: &str) -> String {
        // Encode crash bytes as a hex string so the script is self-contained.
        let hex: String = crash.iter().fold(String::new(), |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        });

        let script = format!(
            r#"#!/usr/bin/env bash
# Auto-generated crash reproducer
# Target : {target_cmd}
# Crash  : {byte_count} bytes

set -euo pipefail

CRASH_FILE="$(mktemp /tmp/rustre_crash_XXXXXX.bin)"
trap 'rm -f "$CRASH_FILE"' EXIT

# Decode hex crash bytes
python3 - <<'PYEOF'
import binascii, sys
data = binascii.unhexlify("{hex}")
sys.stdout.buffer.write(data)
PYEOF > "$CRASH_FILE"

echo "Crash file written to: $CRASH_FILE  ({byte_count} bytes)"
echo "Running: {target_cmd} $CRASH_FILE"
exec {target_cmd} "$CRASH_FILE"
"#,
            target_cmd = target_cmd,
            byte_count = crash.len(),
            hex = hex,
        );

        // Best-effort write; callers can check the returned string even if the
        // write fails in sandboxed environments.
        let _ = (|| -> std::io::Result<()> {
            use std::io::Write;
            let mut f = std::fs::File::create(output_path)?;
            f.write_all(script.as_bytes())?;
            // Make the script executable on Unix.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o755))?;
            }
            Ok(())
        })();

        script
    }
}

// ── Tests for new sanitizer types ─────────────────────────────────────────────

#[cfg(test)]
mod sanitizer_new_tests {
    use super::*;

    // parse_asan_report

    #[test]
    fn asan_report_parse_heap_buffer_overflow() {
        let text = "==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef\n    #0 0x400abc in foo /src/foo.c:10\n    #1 0x400def in main /src/foo.c:30\n";
        let report = parse_asan_report(text).expect("should parse");
        assert_eq!(report.error_type, "heap-buffer-overflow");
        assert_eq!(report.address, 0xdead_beef);
        assert_eq!(report.stack_trace.len(), 2);
        assert_eq!(report.stack_trace[0].symbol.as_deref(), Some("foo"));
    }

    #[test]
    fn asan_report_parse_use_after_free() {
        let text = "==99==ERROR: AddressSanitizer: use-after-free on address 0x1000\n    #0 0xabcd in bar /src/bar.c:5\n";
        let report = parse_asan_report(text).unwrap();
        assert_eq!(report.error_type, "use-after-free");
        assert_eq!(report.address, 0x1000);
    }

    #[test]
    fn asan_report_parse_double_free() {
        let text = "==55==ERROR: AddressSanitizer: double-free on address 0x2000\n";
        let report = parse_asan_report(text).unwrap();
        assert_eq!(report.error_type, "double-free");
    }

    #[test]
    fn asan_report_parse_stack_buffer_overflow() {
        let text = "==77==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x3000\n    #0 0x1111 in baz /src/baz.c:1\n";
        let report = parse_asan_report(text).unwrap();
        assert_eq!(report.error_type, "stack-buffer-overflow");
        assert_eq!(report.stack_trace[0].index, 0);
    }

    #[test]
    fn asan_report_parse_returns_none_for_non_asan_text() {
        let text = "This is not an ASAN report at all.\n";
        assert!(parse_asan_report(text).is_none());
    }

    #[test]
    fn asan_report_summary_contains_error_type() {
        let text = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x10\n";
        let r = parse_asan_report(text).unwrap();
        let s = r.summary();
        assert!(s.contains("heap-buffer-overflow"));
    }

    // SanitizerConfig

    #[test]
    fn sanitizer_config_empty_produces_no_flags() {
        let cfg = SanitizerConfig::new();
        assert!(cfg.cmdline_flags().is_empty());
        assert!(cfg.env_vars().is_empty());
    }

    #[test]
    fn sanitizer_config_asan_produces_flag() {
        let mut cfg = SanitizerConfig::new();
        cfg.enable(SanitizerFlag::ASan);
        let flags = cfg.cmdline_flags();
        assert!(flags.iter().any(|f| f.contains("address")));
    }

    #[test]
    fn sanitizer_config_ubsan_in_fsanitize() {
        let mut cfg = SanitizerConfig::new();
        cfg.enable(SanitizerFlag::UBSan);
        let flags = cfg.cmdline_flags();
        assert!(flags.iter().any(|f| f.contains("undefined")));
    }

    #[test]
    fn sanitizer_config_env_vars_asan() {
        let mut cfg = SanitizerConfig::new();
        cfg.enable(SanitizerFlag::ASan);
        let vars = cfg.env_vars();
        assert!(vars.iter().any(|(k, _)| k == "ASAN_OPTIONS"));
    }

    #[test]
    fn sanitizer_config_env_vars_ubsan() {
        let mut cfg = SanitizerConfig::new();
        cfg.enable(SanitizerFlag::UBSan);
        let vars = cfg.env_vars();
        assert!(vars.iter().any(|(k, _)| k == "UBSAN_OPTIONS"));
    }

    #[test]
    fn sanitizer_config_multiple_sanitizers_combined_flag() {
        let mut cfg = SanitizerConfig::new();
        cfg.enable(SanitizerFlag::ASan);
        cfg.enable(SanitizerFlag::UBSan);
        let flags = cfg.cmdline_flags();
        let fsanitize = flags.iter().find(|f| f.starts_with("-fsanitize=")).unwrap();
        assert!(fsanitize.contains("address"));
        assert!(fsanitize.contains("undefined"));
    }

    #[test]
    fn sanitizer_config_disable_removes_flag() {
        let mut cfg = SanitizerConfig::new();
        cfg.enable(SanitizerFlag::ASan);
        cfg.disable(&SanitizerFlag::ASan);
        assert!(cfg.cmdline_flags().is_empty());
    }

    // FuzzReproducer

    #[test]
    fn repro_script_contains_target_cmd() {
        let crash = vec![0xCAu8, 0xFEu8, 0xBAu8, 0xBEu8];
        let script =
            FuzzReproducer::generate_repro_script(&crash, "/usr/bin/my_target", "/dev/null");
        assert!(script.contains("/usr/bin/my_target"));
    }

    #[test]
    fn repro_script_contains_hex_encoded_crash() {
        let crash = vec![0xDEu8, 0xADu8];
        let script = FuzzReproducer::generate_repro_script(&crash, "target", "/dev/null");
        assert!(script.contains("dead"));
    }

    #[test]
    fn repro_script_contains_byte_count() {
        let crash = vec![0u8; 42];
        let script = FuzzReproducer::generate_repro_script(&crash, "t", "/dev/null");
        assert!(script.contains("42"));
    }

    #[test]
    fn repro_script_is_valid_bash_shebang() {
        let script = FuzzReproducer::generate_repro_script(&[1, 2, 3], "t", "/dev/null");
        assert!(script.starts_with("#!/usr/bin/env bash"));
    }
}

// =============================================================================
// ASan Shadow Memory
// =============================================================================

/// The type of an `AddressSanitizer` error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsanErrorType {
    /// Read or write past the end of a heap allocation.
    HeapBufferOverflow,
    /// Access to memory that has already been freed.
    UseAfterFree,
    /// Stack buffer overflow detected via red-zones.
    StackOverflow,
    /// Attempt to free memory that was already freed.
    DoubleFree,
    /// Access to memory before the allocation start (underflow).
    HeapBufferUnderflow,
    /// Use of stack memory after the enclosing scope has returned.
    UseAfterReturn,
    /// Access to a global variable outside its bounds.
    GlobalBufferOverflow,
}

impl std::fmt::Display for AsanErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeapBufferOverflow => write!(f, "heap-buffer-overflow"),
            Self::UseAfterFree => write!(f, "heap-use-after-free"),
            Self::StackOverflow => write!(f, "stack-buffer-overflow"),
            Self::DoubleFree => write!(f, "double-free"),
            Self::HeapBufferUnderflow => write!(f, "heap-buffer-underflow"),
            Self::UseAfterReturn => write!(f, "stack-use-after-return"),
            Self::GlobalBufferOverflow => write!(f, "global-buffer-overflow"),
        }
    }
}

/// An `AddressSanitizer` error together with context information.
#[derive(Debug, Clone)]
pub struct AsanError {
    /// The category of the violation.
    pub error_type: AsanErrorType,
    /// Faulting address.
    pub address: u64,
    /// Number of bytes the access attempted to touch.
    pub access_size: usize,
    /// Shadow byte value that triggered the error (for diagnostics).
    pub shadow_byte: u8,
    /// Human-readable description.
    pub description: String,
}

impl AsanError {
    /// Create a new [`AsanError`].
    #[must_use]
    pub fn new(
        error_type: AsanErrorType,
        address: u64,
        access_size: usize,
        shadow_byte: u8,
    ) -> Self {
        let description = format!(
            "{error_type} at {address:#018x} (size={access_size}, shadow={shadow_byte:#04x})"
        );
        Self {
            error_type,
            address,
            access_size,
            shadow_byte,
            description,
        }
    }
}

impl std::fmt::Display for AsanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description)
    }
}

// ── Shadow byte constants ──────────────────────────────────────────────────────

/// Shadow value for fully-accessible bytes (8 of 8 accessible).
pub const ASAN_SHADOW_ACCESSIBLE: u8 = 0x00;
/// Shadow value for a freed heap chunk.
pub const ASAN_SHADOW_FREED: u8 = 0xfd;
/// Shadow value for a heap left red-zone.
pub const ASAN_SHADOW_HEAP_LEFT: u8 = 0xfa;
/// Shadow value for a heap right red-zone.
pub const ASAN_SHADOW_HEAP_RIGHT: u8 = 0xfb;
/// Shadow value for a stack left red-zone.
pub const ASAN_SHADOW_STACK_LEFT: u8 = 0xf1;
/// Shadow value for a stack mid red-zone.
pub const ASAN_SHADOW_STACK_MID: u8 = 0xf2;
/// Shadow value for a stack right red-zone.
pub const ASAN_SHADOW_STACK_RIGHT: u8 = 0xf3;
/// Shadow value for a global variable red-zone.
pub const ASAN_SHADOW_GLOBAL: u8 = 0xf9;
/// Shadow value for a use-after-return region.
pub const ASAN_SHADOW_USE_AFTER_RETURN: u8 = 0xf5;

/// Number of application bytes represented by one shadow byte.
pub const ASAN_SHADOW_GRANULARITY: u64 = 8;

/// `ASan` shadow memory: one shadow byte covers 8 application bytes.
///
/// A shadow value of `0x00` means all 8 bytes are accessible.
/// Values `0x01..=0x07` mean that only the first N bytes are accessible
/// (partial last word).  Values `0x80..=0xff` represent various kinds of
/// poisoned / red-zone regions (see the `ASAN_SHADOW_*` constants).
#[derive(Debug)]
pub struct AsanShadow {
    /// Raw shadow bytes.  Index `i` covers application bytes
    /// `[offset + i*8 .. offset + i*8 + 8)`.
    pub shadow: Vec<u8>,
    /// The application address corresponding to shadow index 0.
    pub offset: u64,
}

impl AsanShadow {
    /// Create a new shadow memory region covering `app_size` application bytes
    /// starting at `app_base`.  All bytes start out accessible (`0x00`).
    ///
    /// # Panics
    ///
    /// Panics on the (unsupported) targets where `ASAN_SHADOW_GRANULARITY`
    /// does not fit in `usize`.
    #[must_use]
    pub fn new(app_base: u64, app_size: usize) -> Self {
        let shadow_len = app_size
            .div_ceil(usize::try_from(ASAN_SHADOW_GRANULARITY).expect("granularity fits in usize"));
        Self {
            shadow: vec![ASAN_SHADOW_ACCESSIBLE; shadow_len],
            offset: app_base,
        }
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    /// One past the last application address this shadow covers.
    ///
    /// Marking loops clamp to this: without it, a caller-supplied `size` large
    /// enough to run off the end of the tracked window would keep the loop
    /// stepping one granule at a time across the whole address space, doing
    /// nothing on every iteration.
    const fn tracked_end(&self) -> u64 {
        self.offset
            .saturating_add((self.shadow.len() as u64).saturating_mul(ASAN_SHADOW_GRANULARITY))
    }

    /// Convert an application address to a shadow index.
    /// Returns `None` if the address is outside the tracked range.
    const fn shadow_index(&self, addr: u64) -> Option<usize> {
        if addr < self.offset {
            return None;
        }
        let idx = ((addr - self.offset) / ASAN_SHADOW_GRANULARITY) as usize;
        if idx < self.shadow.len() {
            Some(idx)
        } else {
            None
        }
    }

    /// Return the shadow byte covering application address `addr`, or `None`
    /// when `addr` is out of range.
    #[must_use]
    pub fn shadow_byte_for(&self, addr: u64) -> Option<u8> {
        self.shadow_index(addr).map(|i| self.shadow[i])
    }

    // ── Public API ──────────────────────────────────────────────────────────

    /// Mark `size` application bytes starting at `addr` as fully accessible.
    ///
    /// Bytes that only partially fill a shadow granule are marked with a
    /// partial-accessible value (`1..=7`).
    ///
    /// # Panics
    ///
    /// Panics only if the internal partial-granule offset (always `<` 8) fails
    /// to fit in a `u8` — an invariant of the shadow-memory layout.
    pub fn mark_accessible(&mut self, addr: u64, size: usize) {
        if size == 0 {
            return;
        }
        // Caller-supplied: the sum can overflow, and an oversized range would
        // otherwise walk the whole address space one granule at a time.
        let end = addr.saturating_add(size as u64).min(self.tracked_end());
        let mut cur = addr.max(self.offset);
        while cur < end {
            if let Some(idx) = self.shadow_index(cur) {
                let granule_start = self.offset + idx as u64 * ASAN_SHADOW_GRANULARITY;
                let granule_end = granule_start + ASAN_SHADOW_GRANULARITY;
                if end >= granule_end {
                    // Whole granule is accessible.
                    self.shadow[idx] = ASAN_SHADOW_ACCESSIBLE;
                } else {
                    // Partial last granule — record how many bytes are OK.
                    let accessible =
                        u8::try_from(end - granule_start).expect("granule offset < 8 fits in u8");
                    self.shadow[idx] = accessible; // 1..=7
                }
            }
            cur = (cur / ASAN_SHADOW_GRANULARITY + 1) * ASAN_SHADOW_GRANULARITY;
        }
    }

    /// Poison `size` application bytes starting at `addr` with the given
    /// shadow `tag` (e.g. `ASAN_SHADOW_FREED`, `ASAN_SHADOW_HEAP_RIGHT`, …).
    pub fn mark_poisoned(&mut self, addr: u64, size: usize, tag: u8) {
        if size == 0 {
            return;
        }
        // Caller-supplied: the sum can overflow, and an oversized range would
        // otherwise walk the whole address space one granule at a time.
        let end = addr.saturating_add(size as u64).min(self.tracked_end());
        let mut cur = addr.max(self.offset);
        while cur < end {
            if let Some(idx) = self.shadow_index(cur) {
                self.shadow[idx] = tag;
            }
            cur = (cur / ASAN_SHADOW_GRANULARITY + 1) * ASAN_SHADOW_GRANULARITY;
        }
    }

    /// Check whether accessing `size` bytes at `addr` would be legal.
    ///
    /// Returns `Some(AsanError)` when the access would be illegal, `None`
    /// when the access is safe.
    #[must_use]
    pub fn check_access(&self, addr: u64, size: usize) -> Option<AsanError> {
        if size == 0 {
            return None;
        }
        let end = addr.saturating_add(size as u64);
        let mut cur = addr;
        while cur < end {
            match self.shadow_index(cur) {
                None => {
                    // Address is completely outside the tracked region.
                    return Some(AsanError::new(
                        AsanErrorType::HeapBufferOverflow,
                        cur,
                        size,
                        0xff,
                    ));
                }
                Some(idx) => {
                    let shadow_val = self.shadow[idx];
                    let error_type = match shadow_val {
                        ASAN_SHADOW_ACCESSIBLE => {
                            cur = (cur / ASAN_SHADOW_GRANULARITY + 1) * ASAN_SHADOW_GRANULARITY;
                            continue;
                        }
                        1..=7 => {
                            // Partial granule — check if access overruns the
                            // valid prefix.
                            let granule_start = self.offset + idx as u64 * ASAN_SHADOW_GRANULARITY;
                            let valid_end = granule_start + u64::from(shadow_val);
                            if end > valid_end {
                                AsanErrorType::HeapBufferOverflow
                            } else {
                                cur = (cur / ASAN_SHADOW_GRANULARITY + 1) * ASAN_SHADOW_GRANULARITY;
                                continue;
                            }
                        }
                        ASAN_SHADOW_FREED => AsanErrorType::UseAfterFree,
                        ASAN_SHADOW_STACK_LEFT
                        | ASAN_SHADOW_STACK_MID
                        | ASAN_SHADOW_STACK_RIGHT => AsanErrorType::StackOverflow,
                        ASAN_SHADOW_HEAP_LEFT | ASAN_SHADOW_HEAP_RIGHT => {
                            AsanErrorType::HeapBufferOverflow
                        }
                        ASAN_SHADOW_USE_AFTER_RETURN => AsanErrorType::UseAfterReturn,
                        ASAN_SHADOW_GLOBAL => AsanErrorType::GlobalBufferOverflow,
                        _ => AsanErrorType::HeapBufferOverflow,
                    };
                    return Some(AsanError::new(error_type, cur, size, shadow_val));
                }
            }
        }
        None
    }

    /// Dump the shadow map as a human-readable multi-line string for debugging.
    #[must_use]
    pub fn dump(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        for (i, &byte) in self.shadow.iter().enumerate() {
            if i.is_multiple_of(16) {
                if i > 0 {
                    out.push('\n');
                }
                let app_addr = self.offset + i as u64 * ASAN_SHADOW_GRANULARITY;
                let _ = write!(out, "{app_addr:#018x}: ");
            }
            let _ = write!(out, "{byte:02x} ");
        }
        out
    }

    /// Total number of shadow bytes tracked.
    #[must_use]
    pub const fn shadow_len(&self) -> usize {
        self.shadow.len()
    }

    /// Return the application address range covered by this shadow.
    #[must_use]
    pub const fn app_range(&self) -> std::ops::Range<u64> {
        self.offset..self.offset + self.shadow.len() as u64 * ASAN_SHADOW_GRANULARITY
    }
}

// =============================================================================
// UBSan checker
// =============================================================================

/// Result of a `UBSan` check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UbsanViolation {
    /// Signed integer overflow.
    SignedOverflow {
        /// Left-hand operand.
        lhs: i64,
        /// Right-hand operand.
        rhs: i64,
        /// The overflowed result (wrapping).
        wrapped: i64,
    },
    /// Null-pointer dereference.
    NullDeref {
        /// The address that was dereferenced (0 for a true null).
        ptr: u64,
    },
    /// Division or modulo by zero.
    DivByZero {
        /// The divisor that was zero.
        divisor: i64,
    },
    /// Shift amount out of range for the underlying type width.
    ShiftOutOfRange {
        /// The shift amount.
        amount: u32,
        /// The bit-width of the type being shifted.
        type_width: u32,
    },
    /// Integer conversion that loses information.
    IntegerTruncation {
        /// Original value before truncation.
        original: i64,
        /// Value after truncation.
        truncated: i64,
    },
    /// Array index out of bounds.
    ArrayBoundsViolation {
        /// The offending index.
        index: i64,
        /// The declared array length.
        length: i64,
    },
}

impl std::fmt::Display for UbsanViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignedOverflow { lhs, rhs, wrapped } => write!(
                f,
                "signed-integer-overflow: {lhs} op {rhs} -> {wrapped} (wrapped)"
            ),
            Self::NullDeref { ptr } => write!(f, "null-deref at {ptr:#x}"),
            Self::DivByZero { divisor } => write!(f, "division-by-zero: divisor={divisor}"),
            Self::ShiftOutOfRange { amount, type_width } => write!(
                f,
                "shift-out-of-range: shift {amount} for {type_width}-bit type"
            ),
            Self::IntegerTruncation {
                original,
                truncated,
            } => write!(f, "integer-truncation: {original} -> {truncated}"),
            Self::ArrayBoundsViolation { index, length } => write!(
                f,
                "array-bounds-violation: index {index} out of [0,{length})"
            ),
        }
    }
}

/// Undefined-behaviour sanitizer checker.
///
/// All methods return `Ok(())` when no UB is detected, or
/// `Err(UbsanViolation)` when a violation is found.
#[derive(Debug, Default, Clone)]
pub struct UbsanChecker {
    /// Accumulated violations (non-fatal mode).
    pub violations: Vec<UbsanViolation>,
    /// When `true`, the checker records violations instead of returning them.
    pub non_fatal: bool,
}

impl UbsanChecker {
    /// Create a new [`UbsanChecker`] in fatal mode (returns errors immediately).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            violations: Vec::new(),
            non_fatal: false,
        }
    }

    /// Create a new [`UbsanChecker`] in non-fatal mode (collects all violations).
    #[must_use]
    pub const fn non_fatal() -> Self {
        Self {
            violations: Vec::new(),
            non_fatal: true,
        }
    }

    fn report(&mut self, v: UbsanViolation) -> Result<(), UbsanViolation> {
        if self.non_fatal {
            self.violations.push(v);
            Ok(())
        } else {
            Err(v)
        }
    }

    // ── Arithmetic checks ────────────────────────────────────────────────────

    /// Check whether `a + b` overflows signed 64-bit arithmetic.
    ///
    /// # Errors
    ///
    /// Returns a [`UbsanViolation::SignedOverflow`] in fatal mode when the
    /// addition wraps around.
    pub fn check_signed_overflow(&mut self, a: i64, b: i64) -> Result<i64, UbsanViolation> {
        if let Some(result) = a.checked_add(b) {
            Ok(result)
        } else {
            let wrapped = a.wrapping_add(b);
            self.report(UbsanViolation::SignedOverflow {
                lhs: a,
                rhs: b,
                wrapped,
            })?;
            Ok(wrapped)
        }
    }

    /// Check whether `a - b` overflows signed 64-bit arithmetic.
    ///
    /// # Errors
    ///
    /// Returns a [`UbsanViolation::SignedOverflow`] in fatal mode when the
    /// subtraction wraps around.
    pub fn check_signed_sub_overflow(&mut self, a: i64, b: i64) -> Result<i64, UbsanViolation> {
        if let Some(result) = a.checked_sub(b) {
            Ok(result)
        } else {
            let wrapped = a.wrapping_sub(b);
            self.report(UbsanViolation::SignedOverflow {
                lhs: a,
                rhs: b,
                wrapped,
            })?;
            Ok(wrapped)
        }
    }

    /// Check whether `a * b` overflows signed 64-bit arithmetic.
    ///
    /// # Errors
    ///
    /// Returns a [`UbsanViolation::SignedOverflow`] in fatal mode when the
    /// multiplication wraps around.
    pub fn check_signed_mul_overflow(&mut self, a: i64, b: i64) -> Result<i64, UbsanViolation> {
        if let Some(result) = a.checked_mul(b) {
            Ok(result)
        } else {
            let wrapped = a.wrapping_mul(b);
            self.report(UbsanViolation::SignedOverflow {
                lhs: a,
                rhs: b,
                wrapped,
            })?;
            Ok(wrapped)
        }
    }

    // ── Pointer checks ───────────────────────────────────────────────────────

    /// Check that `ptr` is not null (zero).
    ///
    /// # Errors
    ///
    /// Returns a [`UbsanViolation::NullDeref`] in fatal mode when `ptr == 0`.
    pub fn check_null_deref(&mut self, ptr: u64) -> Result<(), UbsanViolation> {
        if ptr == 0 {
            self.report(UbsanViolation::NullDeref { ptr })?;
        }
        Ok(())
    }

    /// Check that `ptr` is not null and is naturally aligned to `align` bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`UbsanViolation::NullDeref`] in fatal mode when `ptr == 0`
    /// or `ptr` is not a multiple of `align`.
    pub fn check_aligned_deref(&mut self, ptr: u64, align: u64) -> Result<(), UbsanViolation> {
        self.check_null_deref(ptr)?;
        if !ptr.is_multiple_of(align) {
            // Misalignment — map it through NullDeref for now (callers can
            // distinguish by ptr != 0 and using UbsanViolation::NullDeref).
            self.report(UbsanViolation::NullDeref { ptr })?;
        }
        Ok(())
    }

    // ── Division checks ──────────────────────────────────────────────────────

    /// Check that `divisor` is non-zero before performing integer division.
    ///
    /// # Errors
    ///
    /// Returns a [`UbsanViolation::DivByZero`] in fatal mode when `divisor == 0`.
    pub fn check_div_by_zero(&mut self, divisor: i64) -> Result<(), UbsanViolation> {
        if divisor == 0 {
            self.report(UbsanViolation::DivByZero { divisor })?;
        }
        Ok(())
    }

    /// Safe integer division: checks for zero and overflow (`i64::MIN` / -1).
    ///
    /// # Errors
    ///
    /// Returns a [`UbsanViolation::DivByZero`] when `rhs == 0`, or a
    /// [`UbsanViolation::SignedOverflow`] when the division would overflow.
    pub fn safe_div(&mut self, lhs: i64, rhs: i64) -> Result<i64, UbsanViolation> {
        self.check_div_by_zero(rhs)?;
        // In non-fatal mode, `check_div_by_zero` records the violation but
        // returns Ok; guard the actual divide so we do not panic.
        if rhs == 0 {
            return Ok(0);
        }
        if lhs == i64::MIN && rhs == -1 {
            self.report(UbsanViolation::SignedOverflow {
                lhs,
                rhs,
                wrapped: i64::MIN,
            })?;
            return Ok(i64::MIN);
        }
        Ok(lhs / rhs)
    }

    // ── Shift checks ─────────────────────────────────────────────────────────

    /// Check that a shift amount is in `[0, type_width)`.
    ///
    /// # Errors
    ///
    /// Returns a [`UbsanViolation::ShiftOutOfRange`] in fatal mode when
    /// `amount >= type_width`.
    pub fn check_shift(&mut self, amount: u32, type_width: u32) -> Result<(), UbsanViolation> {
        if amount >= type_width {
            self.report(UbsanViolation::ShiftOutOfRange { amount, type_width })?;
        }
        Ok(())
    }

    // ── Bounds checks ────────────────────────────────────────────────────────

    /// Check that `index` is in `[0, length)`.
    ///
    /// # Errors
    ///
    /// Returns a [`UbsanViolation::ArrayBoundsViolation`] in fatal mode when
    /// the index is negative or greater than or equal to `length`.
    pub fn check_bounds(&mut self, index: i64, length: i64) -> Result<(), UbsanViolation> {
        if index < 0 || index >= length {
            self.report(UbsanViolation::ArrayBoundsViolation { index, length })?;
        }
        Ok(())
    }

    // ── Truncation checks ────────────────────────────────────────────────────

    /// Check that casting `value` to an `i32` does not lose information.
    ///
    /// # Errors
    ///
    /// Returns the truncation violation in fatal mode when the low 32 bits of
    /// `value` differ from the full 64-bit value.
    pub fn check_i64_to_i32_truncation(&mut self, value: i64) -> Result<i32, UbsanViolation> {
        // Bit-level truncate by taking the low four bytes — same semantics as
        // `value as i32` but expressed without an `as` truncation cast.
        let bytes = value.to_le_bytes();
        let truncated = i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if i64::from(truncated) != value {
            self.report(UbsanViolation::IntegerTruncation {
                original: value,
                truncated: i64::from(truncated),
            })?;
        }
        Ok(truncated)
    }

    /// Check that casting `value` to a `u8` does not lose information.
    ///
    /// # Errors
    ///
    /// Returns the truncation violation in fatal mode when the low byte of
    /// `value` differs from the full 64-bit value.
    pub fn check_i64_to_u8_truncation(&mut self, value: i64) -> Result<u8, UbsanViolation> {
        // Bit-level truncate by taking the low byte — same semantics as
        // `value as u8` but expressed without an `as` truncation cast.
        let truncated = value.to_le_bytes()[0];
        if i64::from(truncated) != value {
            self.report(UbsanViolation::IntegerTruncation {
                original: value,
                truncated: i64::from(truncated),
            })?;
        }
        Ok(truncated)
    }

    /// Drain and return all accumulated violations (non-fatal mode).
    pub fn drain_violations(&mut self) -> Vec<UbsanViolation> {
        std::mem::take(&mut self.violations)
    }

    /// Return `true` if any violations have been accumulated.
    #[must_use]
    pub const fn has_violations(&self) -> bool {
        !self.violations.is_empty()
    }
}

// =============================================================================
// ASan report parser
// =============================================================================

/// A parsed ASAN error report.
#[derive(Debug, Clone)]
pub struct AsanReportV2 {
    /// The error type string as reported by `ASan` (e.g. `"heap-buffer-overflow"`).
    pub error_type: String,
    /// The faulting application address.
    pub address: Option<u64>,
    /// Size of the illegal access in bytes.
    pub access_size: Option<usize>,
    /// Whether the access was a read (`true`) or write (`false`).
    pub is_read: Option<bool>,
    /// Parsed stack frames from the error trace.
    pub stack_frames: Vec<AsanStackFrame>,
    /// Shadow memory context lines extracted from the report.
    pub shadow_dump: Vec<String>,
    /// Raw lines of the original report.
    pub raw_lines: Vec<String>,
    /// Allocation stack frames (where the memory was allocated).
    pub alloc_stack: Vec<AsanStackFrame>,
    /// Free stack frames (where the memory was freed, if applicable).
    pub free_stack: Vec<AsanStackFrame>,
    /// Thread id that caused the error.
    pub thread_id: Option<u32>,
}

/// A single parsed stack frame from an `ASan` report.
#[derive(Debug, Clone)]
pub struct AsanStackFrame {
    /// Frame number (0-based).
    pub frame: usize,
    /// Program counter / instruction pointer.
    pub pc: u64,
    /// Symbol name, if present.
    pub symbol: Option<String>,
    /// Source file, if present.
    pub file: Option<String>,
    /// Line number in the source file.
    pub line: Option<u32>,
    /// Column number in the source file.
    pub column: Option<u32>,
    /// Shared library or module name.
    pub module: Option<String>,
    /// Offset within the module.
    pub module_offset: Option<u64>,
}

/// Parser for the text output of LLVM's `AddressSanitizer`.
pub struct AsanReportParser;

impl AsanReportParser {
    /// Parse an `ASan` error report from its text representation.
    ///
    /// Returns `Some(AsanReportV2)` when a recognisable error header is found,
    /// `None` when the text does not look like an `ASan` report.
    #[must_use]
    pub fn parse(text: &str) -> Option<AsanReportV2> {
        let lines: Vec<&str> = text.lines().collect();
        let raw_lines: Vec<String> = lines.iter().map(std::string::ToString::to_string).collect();

        // Find the primary error line: "==NNN==ERROR: AddressSanitizer: ..."
        let header_idx = lines.iter().position(|l| {
            l.contains("ERROR: AddressSanitizer:") || l.contains("ERROR: LeakSanitizer:")
        })?;

        let header = lines[header_idx];

        // Extract error type token after the last colon in the header.
        let error_type = Self::extract_error_type(header);
        let address = Self::extract_address(header);
        // Access size and direction (READ/WRITE) usually appear on the line
        // immediately following the ERROR header, not on the header itself.
        let access_size = Self::extract_access_size(header)
            .or_else(|| lines.get(header_idx + 1).and_then(|l| Self::extract_access_size(l)));
        let is_read = Self::extract_is_read(header)
            .or_else(|| lines.get(header_idx + 1).and_then(|l| Self::extract_is_read(l)));
        let thread_id = Self::extract_thread_id(header);

        // Collect stack frames, shadow dump, alloc/free stacks.
        let mut stack_frames = Vec::new();
        let mut shadow_dump = Vec::new();
        let mut alloc_stack = Vec::new();
        let mut free_stack = Vec::new();

        let mut section = Section::ErrorTrace;

        for line in &lines[header_idx + 1..] {
            // Section transitions.
            if line.contains("allocated by thread") || line.contains("Hint: address points") {
                section = Section::AllocTrace;
                continue;
            }
            if line.contains("freed by thread") {
                section = Section::FreeTrace;
                continue;
            }
            if line.contains("Shadow bytes around the buggy address") {
                section = Section::ShadowDump;
                continue;
            }
            if line.starts_with("SUMMARY:") {
                break;
            }

            match section {
                Section::ErrorTrace => {
                    if let Some(frame) = Self::parse_stack_frame(line) {
                        stack_frames.push(frame);
                    }
                }
                Section::AllocTrace => {
                    if let Some(frame) = Self::parse_stack_frame(line) {
                        alloc_stack.push(frame);
                    }
                }
                Section::FreeTrace => {
                    if let Some(frame) = Self::parse_stack_frame(line) {
                        free_stack.push(frame);
                    }
                }
                Section::ShadowDump => {
                    if !line.trim().is_empty() {
                        shadow_dump.push(line.to_string());
                    }
                }
            }
        }

        Some(AsanReportV2 {
            error_type,
            address,
            access_size,
            is_read,
            stack_frames,
            shadow_dump,
            raw_lines,
            alloc_stack,
            free_stack,
            thread_id,
        })
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn extract_error_type(header: &str) -> String {
        // Pattern: "AddressSanitizer: <error-type> on ..."
        //       or "AddressSanitizer: <error-type>\n"
        if let Some(after) = header
            .split("AddressSanitizer:")
            .nth(1)
            .or_else(|| header.split("LeakSanitizer:").nth(1))
        {
            let trimmed = after.trim();
            // Take up to the first " on " or end-of-token.
            let end = trimmed
                .find(" on address")
                .or_else(|| trimmed.find(" of size"))
                .unwrap_or(trimmed.len());
            return trimmed[..end].trim().to_string();
        }
        "unknown".to_string()
    }

    fn extract_address(line: &str) -> Option<u64> {
        // "on address 0x..." or "address 0x..."
        let marker = "address 0x";
        let idx = line.find(marker)?;
        let hex_str = line[idx + marker.len()..]
            .split(|c: char| !c.is_ascii_hexdigit())
            .next()?;
        u64::from_str_radix(hex_str, 16).ok()
    }

    fn extract_access_size(line: &str) -> Option<usize> {
        // "of size N"
        let marker = "of size ";
        let idx = line.find(marker)?;
        let num_str = line[idx + marker.len()..]
            .split(|c: char| !c.is_ascii_digit())
            .next()?;
        num_str.parse().ok()
    }

    fn extract_is_read(line: &str) -> Option<bool> {
        if line.contains("READ of size") || line.contains("read of size") {
            Some(true)
        } else if line.contains("WRITE of size") || line.contains("write of size") {
            Some(false)
        } else {
            None
        }
    }

    fn extract_thread_id(line: &str) -> Option<u32> {
        // "T0" or "T123"
        let idx = line.rfind(" T")?;
        let after = &line[idx + 2..];
        let num_str = after.split(|c: char| !c.is_ascii_digit()).next()?;
        if num_str.is_empty() {
            None
        } else {
            num_str.parse().ok()
        }
    }

    /// Parse a single stack frame line.
    ///
    /// Handles both of the common formats:
    /// ```text
    ///     #0 0xdead_beef in some_function /path/to/file.c:42:5
    ///     #0 0xdead_beef (libfoo.so+0x1234)
    /// ```
    fn parse_stack_frame(line: &str) -> Option<AsanStackFrame> {
        let trimmed = line.trim();
        // Must start with '#' followed by a digit.
        if !trimmed.starts_with('#') {
            return None;
        }
        let rest = &trimmed[1..];
        let sp = rest.find(' ')?;
        let frame: usize = rest[..sp].parse().ok()?;
        let rest = rest[sp..].trim();

        // Extract the PC hex value.
        let pc_str = rest.split_whitespace().next()?;
        let pc = u64::from_str_radix(pc_str.trim_start_matches("0x"), 16).ok()?;

        let after_pc = rest[pc_str.len()..].trim();

        // Two formats to detect: "in <symbol> <file>:<line>:<col>" vs
        // "(<module>+0x<offset>)".
        let mut symbol = None;
        let mut file = None;
        let mut line_no = None;
        let mut col_no = None;
        let mut module = None;
        let mut mod_offset = None;

        if let Some(in_idx) = after_pc.strip_prefix("in ") {
            // Symbol + optional file location.
            let parts: Vec<&str> = in_idx.splitn(2, ' ').collect();
            symbol = Some(parts[0].to_string());
            if parts.len() > 1 {
                let loc = parts[1].trim();
                // loc = "/path/file.c:42:5" or just "/path/file.c"
                let mut loc_parts = loc.rsplitn(3, ':');
                if let (Some(col_s), Some(line_s), Some(file_s)) =
                    (loc_parts.next(), loc_parts.next(), loc_parts.next())
                {
                    if let (Ok(c), Ok(l)) = (col_s.parse::<u32>(), line_s.parse::<u32>()) {
                        col_no = Some(c);
                        line_no = Some(l);
                        file = Some(file_s.to_string());
                    } else {
                        // Only two components; treat as file:line.
                        let mut lp = loc.rsplitn(2, ':');
                        if let (Some(ln_s), Some(fs)) = (lp.next(), lp.next()) {
                            line_no = ln_s.parse().ok();
                            file = Some(fs.to_string());
                        } else {
                            file = Some(loc.to_string());
                        }
                    }
                } else {
                    file = Some(loc.to_string());
                }
            }
        } else if after_pc.starts_with('(') {
            // Module+offset format: (libfoo.so+0x1234)
            let inner = after_pc.trim_start_matches('(').trim_end_matches(')');
            let mut it = inner.splitn(2, '+');
            if let Some(m) = it.next() {
                module = Some(m.to_string());
            }
            if let Some(off) = it.next() {
                mod_offset = u64::from_str_radix(off.trim_start_matches("0x"), 16).ok();
            }
        }

        Some(AsanStackFrame {
            frame,
            pc,
            symbol,
            file,
            line: line_no,
            column: col_no,
            module,
            module_offset: mod_offset,
        })
    }
}

/// Internal section tracker used during report parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    ErrorTrace,
    AllocTrace,
    FreeTrace,
    ShadowDump,
}

// =============================================================================
// AsanShadow + UbsanChecker integration: SanitizerHarness
// =============================================================================

/// A combined sanitizer harness that manages `ASan` shadow memory, `UBSan`
/// checking, and an allocation registry for a simulated process.
#[derive(Debug)]
pub struct SanitizerHarnessV2 {
    /// Shadow memory.
    pub shadow: AsanShadow,
    /// `UBSan` checker (non-fatal by default in the harness).
    pub ubsan: UbsanChecker,
    /// Live allocations: base address → (size, allocation id).
    pub allocations: HashMap<u64, (usize, u64)>,
    /// Freed addresses (tracked for double-free and UAF detection).
    pub freed: HashSet<u64>,
    /// Monotonically increasing allocation counter.
    next_alloc_id: u64,
}

impl SanitizerHarnessV2 {
    /// Create a harness that shadows the address range `[app_base, app_base+app_size)`.
    #[must_use]
    pub fn new(app_base: u64, app_size: usize) -> Self {
        Self {
            shadow: AsanShadow::new(app_base, app_size),
            ubsan: UbsanChecker::non_fatal(),
            allocations: HashMap::new(),
            freed: HashSet::new(),
            next_alloc_id: 0,
        }
    }

    /// Record a new heap allocation at `base` of `size` bytes and mark the
    /// region accessible in the shadow map.  Returns the allocation id.
    pub fn record_alloc(&mut self, base: u64, size: usize) -> u64 {
        let id = self.next_alloc_id;
        self.next_alloc_id += 1;
        self.allocations.insert(base, (size, id));
        self.freed.remove(&base);
        // Mark interior accessible; surround with red-zones if possible.
        let rz_bytes: usize = 8;
        let rz_u64 = rz_bytes as u64;
        if base >= rz_u64 {
            self.shadow
                .mark_poisoned(base - rz_u64, rz_bytes, ASAN_SHADOW_HEAP_LEFT);
        }
        self.shadow.mark_accessible(base, size);
        let after = base.saturating_add(size as u64);
        self.shadow
            .mark_poisoned(after, rz_bytes, ASAN_SHADOW_HEAP_RIGHT);
        id
    }

    /// Record a heap free at `base`.  Returns an [`AsanError`] if this is a
    /// double-free or if the address was never allocated.
    pub fn record_free(&mut self, base: u64) -> Option<AsanError> {
        if self.freed.contains(&base) {
            return Some(AsanError::new(
                AsanErrorType::DoubleFree,
                base,
                0,
                ASAN_SHADOW_FREED,
            ));
        }
        match self.allocations.remove(&base) {
            None => {
                // Unknown pointer — not necessarily an error (could be mid-alloc
                // pointer, or outside our range), return nothing by default.
                None
            }
            Some((size, _id)) => {
                self.freed.insert(base);
                // Poison the freed region.
                self.shadow.mark_poisoned(base, size, ASAN_SHADOW_FREED);
                None
            }
        }
    }

    /// Check an access at `addr` of `size` bytes.
    #[must_use]
    pub fn check_access(&self, addr: u64, size: usize) -> Option<AsanError> {
        self.shadow.check_access(addr, size)
    }

    /// Run a signed add with `UBSan` checking.
    pub fn safe_add(&mut self, a: i64, b: i64) -> i64 {
        self.ubsan
            .check_signed_overflow(a, b)
            .unwrap_or_else(|_| a.wrapping_add(b))
    }

    /// Run a signed divide with `UBSan` checking.
    pub fn safe_div(&mut self, a: i64, b: i64) -> i64 {
        self.ubsan.safe_div(a, b).unwrap_or(0)
    }

    /// Drain all `UBSan` violations collected so far.
    pub fn drain_ubsan_violations(&mut self) -> Vec<UbsanViolation> {
        self.ubsan.drain_violations()
    }
}

// =============================================================================
// Unit tests — ASan / UBSan additions
// =============================================================================

#[cfg(test)]
mod asan_ubsan_tests {
    use super::*;

    // ── AsanShadow ────────────────────────────────────────────────────────────

    #[test]
    fn asan_shadow_initial_accessible() {
        let shadow = AsanShadow::new(0x1000, 64);
        // Every byte should be accessible initially.
        assert!(shadow.check_access(0x1000, 64).is_none());
    }

    #[test]
    fn asan_shadow_poison_and_detect() {
        let mut shadow = AsanShadow::new(0x1000, 128);
        shadow.mark_poisoned(0x1040, 8, ASAN_SHADOW_FREED);
        let err = shadow.check_access(0x1040, 1);
        assert!(err.is_some());
        let e = err.unwrap();
        assert_eq!(e.error_type, AsanErrorType::UseAfterFree);
    }

    #[test]
    fn asan_shadow_partial_granule() {
        let mut shadow = AsanShadow::new(0x2000, 64);
        // Mark only 3 bytes in the first granule accessible.
        shadow.mark_poisoned(0x2000, 64, ASAN_SHADOW_HEAP_RIGHT);
        shadow.mark_accessible(0x2000, 3);
        // Access within the 3-byte region is fine.
        assert!(shadow.check_access(0x2000, 3).is_none());
        // Access of 4 bytes should fail.
        let err = shadow.check_access(0x2000, 4);
        assert!(err.is_some());
    }

    #[test]
    fn asan_shadow_out_of_range() {
        let shadow = AsanShadow::new(0x3000, 32);
        let err = shadow.check_access(0x5000, 1);
        assert!(err.is_some());
        assert_eq!(err.unwrap().error_type, AsanErrorType::HeapBufferOverflow);
    }

    #[test]
    fn asan_shadow_stack_overflow_tag() {
        let mut shadow = AsanShadow::new(0x4000, 64);
        shadow.mark_poisoned(0x4038, 8, ASAN_SHADOW_STACK_RIGHT);
        let err = shadow.check_access(0x4038, 1).unwrap();
        assert_eq!(err.error_type, AsanErrorType::StackOverflow);
    }

    #[test]
    fn asan_shadow_dump_non_empty() {
        let shadow = AsanShadow::new(0x1000, 64);
        let dump = shadow.dump();
        assert!(dump.contains("0x0000000000001000"));
    }

    // ── UbsanChecker ─────────────────────────────────────────────────────────

    #[test]
    fn ubsan_no_overflow() {
        let mut c = UbsanChecker::new();
        assert_eq!(c.check_signed_overflow(100, 200).unwrap(), 300);
    }

    #[test]
    fn ubsan_signed_overflow_fatal() {
        let mut c = UbsanChecker::new();
        let r = c.check_signed_overflow(i64::MAX, 1);
        assert!(r.is_err());
        if let Err(UbsanViolation::SignedOverflow { lhs, rhs, wrapped }) = r {
            assert_eq!(lhs, i64::MAX);
            assert_eq!(rhs, 1);
            let _ = wrapped; // just check it exists
        }
    }

    #[test]
    fn ubsan_signed_overflow_nonfatal_accumulates() {
        let mut c = UbsanChecker::non_fatal();
        let _ = c.check_signed_overflow(i64::MAX, 1);
        let _ = c.check_signed_overflow(i64::MAX, 2);
        assert_eq!(c.violations.len(), 2);
    }

    #[test]
    fn ubsan_null_deref_detected() {
        let mut c = UbsanChecker::new();
        let r = c.check_null_deref(0);
        assert!(r.is_err());
    }

    #[test]
    fn ubsan_non_null_passes() {
        let mut c = UbsanChecker::new();
        assert!(c.check_null_deref(0xdead_beef).is_ok());
    }

    #[test]
    fn ubsan_div_by_zero_detected() {
        let mut c = UbsanChecker::new();
        assert!(c.check_div_by_zero(0).is_err());
    }

    #[test]
    fn ubsan_div_by_zero_nonzero_passes() {
        let mut c = UbsanChecker::new();
        assert!(c.check_div_by_zero(42).is_ok());
    }

    #[test]
    fn ubsan_safe_div_normal() {
        let mut c = UbsanChecker::new();
        assert_eq!(c.safe_div(10, 3).unwrap(), 3);
    }

    #[test]
    fn ubsan_safe_div_min_over_minus_one() {
        let mut c = UbsanChecker::non_fatal();
        let _ = c.safe_div(i64::MIN, -1);
        assert!(c.has_violations());
    }

    #[test]
    fn ubsan_bounds_check_ok() {
        let mut c = UbsanChecker::new();
        assert!(c.check_bounds(0, 10).is_ok());
        assert!(c.check_bounds(9, 10).is_ok());
    }

    #[test]
    fn ubsan_bounds_check_fail() {
        let mut c = UbsanChecker::new();
        assert!(c.check_bounds(10, 10).is_err());
        assert!(c.check_bounds(-1, 10).is_err());
    }

    #[test]
    fn ubsan_shift_check() {
        let mut c = UbsanChecker::new();
        assert!(c.check_shift(63, 64).is_ok());
        assert!(c.check_shift(64, 64).is_err());
    }

    // ── AsanReportParser ─────────────────────────────────────────────────────

    const SAMPLE_ASAN_REPORT: &str = r"
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000eff0 at pc 0x000000500001 bp 0x7ffe000000e0 sp 0x7ffe000000d8
READ of size 1 at 0x60200000eff0 thread T0
    #0 0x500000 in vulnerable_func /home/user/test.c:42:5
    #1 0x500100 in main /home/user/test.c:88:3
    #2 0x7f1234567890 (/lib/libc.so.6+0xabcdef)
0x60200000eff0 is located 0 bytes to the right of 8-byte region [0x60200000efe8,0x60200000eff0)
allocated by thread T0 here:
    #0 0x499abc in malloc (/usr/lib/libasan.so.5+0x111111)
    #1 0x500000 in vulnerable_func /home/user/test.c:40:3
Shadow bytes around the buggy address:
  0x0c047fff9df0: fa fa 00 fa fa fa 00 fa
=>0x0c047fff9df0:[fb]fa 00 fa fa fa 00 fa
SUMMARY: AddressSanitizer: heap-buffer-overflow /home/user/test.c:42:5 in vulnerable_func
";

    #[test]
    fn asan_parser_detects_heap_overflow() {
        let report = AsanReportParser::parse(SAMPLE_ASAN_REPORT).unwrap();
        assert!(report.error_type.contains("heap-buffer-overflow"));
    }

    #[test]
    fn asan_parser_extracts_address() {
        let report = AsanReportParser::parse(SAMPLE_ASAN_REPORT).unwrap();
        assert_eq!(report.address, Some(0x6020_0000_eff0));
    }

    #[test]
    fn asan_parser_extracts_access_size() {
        let report = AsanReportParser::parse(SAMPLE_ASAN_REPORT).unwrap();
        assert_eq!(report.access_size, Some(1));
    }

    #[test]
    fn asan_parser_is_read() {
        let report = AsanReportParser::parse(SAMPLE_ASAN_REPORT).unwrap();
        assert_eq!(report.is_read, Some(true));
    }

    #[test]
    fn asan_parser_stack_frames() {
        let report = AsanReportParser::parse(SAMPLE_ASAN_REPORT).unwrap();
        assert!(!report.stack_frames.is_empty());
        let f0 = &report.stack_frames[0];
        assert_eq!(f0.frame, 0);
        assert_eq!(f0.pc, 0x0050_0000);
        assert_eq!(f0.symbol.as_deref(), Some("vulnerable_func"));
        assert_eq!(f0.line, Some(42));
        assert_eq!(f0.column, Some(5));
    }

    #[test]
    fn asan_parser_alloc_stack() {
        let report = AsanReportParser::parse(SAMPLE_ASAN_REPORT).unwrap();
        assert!(!report.alloc_stack.is_empty());
    }

    #[test]
    fn asan_parser_shadow_dump() {
        let report = AsanReportParser::parse(SAMPLE_ASAN_REPORT).unwrap();
        assert!(!report.shadow_dump.is_empty());
    }

    #[test]
    fn asan_parser_no_match_returns_none() {
        let r = AsanReportParser::parse("hello world, nothing to see here");
        assert!(r.is_none());
    }

    #[test]
    fn asan_parser_module_offset_frame() {
        let report = AsanReportParser::parse(SAMPLE_ASAN_REPORT).unwrap();
        let f2 = &report.stack_frames[2];
        assert_eq!(f2.module.as_deref(), Some("/lib/libc.so.6"));
        assert_eq!(f2.module_offset, Some(0x00ab_cdef));
    }

    // ── SanitizerHarness ─────────────────────────────────────────────────────

    #[test]
    fn harness_alloc_and_access() {
        let mut h = SanitizerHarnessV2::new(0x10000, 1024);
        h.record_alloc(0x10010, 16);
        assert!(h.check_access(0x10010, 16).is_none());
    }

    #[test]
    fn harness_free_poisons_region() {
        let mut h = SanitizerHarnessV2::new(0x10000, 1024);
        h.record_alloc(0x10010, 16);
        h.record_free(0x10010);
        let err = h.check_access(0x10010, 1);
        assert!(err.is_some());
        assert_eq!(err.unwrap().error_type, AsanErrorType::UseAfterFree);
    }

    #[test]
    fn harness_double_free_detected() {
        let mut h = SanitizerHarnessV2::new(0x10000, 1024);
        h.record_alloc(0x10010, 16);
        assert!(h.record_free(0x10010).is_none());
        let err = h.record_free(0x10010);
        assert!(err.is_some());
        assert_eq!(err.unwrap().error_type, AsanErrorType::DoubleFree);
    }

    #[test]
    fn harness_ubsan_overflow_collected() {
        let mut h = SanitizerHarnessV2::new(0x10000, 1024);
        h.safe_add(i64::MAX, 1);
        let violations = h.drain_ubsan_violations();
        assert!(!violations.is_empty());
    }

    #[test]
    fn harness_safe_div() {
        let mut h = SanitizerHarnessV2::new(0x10000, 1024);
        assert_eq!(h.safe_div(10, 2), 5);
        assert_eq!(h.safe_div(7, 0), 0); // div-by-zero handled
    }
}
