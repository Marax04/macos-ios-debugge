//! Heap object taint tracking.
//!
//! Tracks taint propagation through heap allocations (`malloc`/`new`),
//! copies (`memcpy`), and deallocations (`free`/`delete`). Detects
//! use-after-free patterns and heap spray signatures.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use thiserror::Error;

/// Re-exports of additional standard collections useful for heap-state
/// snapshots taken by callers of this module.
pub use std::collections::{HashSet, VecDeque};

use crate::{FindingType, TaintFinding, TaintId, taint_bits};

/// Re-export of [`TaintedValue`] so heap snapshots can be constructed by
/// downstream modules without importing the crate root.
pub use crate::TaintedValue;

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum HeapTaintError {
    #[error("double-free detected at address {0:#x}")]
    DoubleFree(u64),
    #[error("use-after-free: access to freed pointer {0:#x}")]
    UseAfterFree(u64),
    #[error("heap object not found at {0:#x}")]
    ObjectNotFound(u64),
    #[error("invalid allocation: zero-size at {0:#x}")]
    ZeroSizeAlloc(u64),
    #[error("heap error: {0}")]
    Other(String),
}

// ─── AllocationSite ───────────────────────────────────────────────────────────

/// The site in the program where an allocation was made.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AllocationSite {
    /// Instruction address of the `malloc`/`new` call.
    pub call_addr: u64,
    /// Name of the allocator function.
    pub allocator: String,
}

impl AllocationSite {
    #[must_use]
    pub fn new(call_addr: u64, allocator: impl Into<String>) -> Self {
        Self {
            call_addr,
            allocator: allocator.into(),
        }
    }

    #[must_use]
    pub fn malloc(call_addr: u64) -> Self {
        Self::new(call_addr, "malloc")
    }
    #[must_use]
    pub fn calloc(call_addr: u64) -> Self {
        Self::new(call_addr, "calloc")
    }
    #[must_use]
    pub fn new_op(call_addr: u64) -> Self {
        Self::new(call_addr, "operator new")
    }
    #[must_use]
    pub fn new_array(call_addr: u64) -> Self {
        Self::new(call_addr, "operator new[]")
    }
}

impl fmt::Display for AllocationSite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{:#x}", self.allocator, self.call_addr)
    }
}

// ─── HeapObject ───────────────────────────────────────────────────────────────

/// A heap-allocated object with byte-granular taint tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapObject {
    /// Base pointer returned by the allocator.
    pub base_ptr: u64,
    /// Allocation size in bytes.
    pub size: usize,
    /// Where this object was allocated.
    pub site: AllocationSite,
    /// Per-byte taint map (offset → `TaintId`).
    /// Bytes not present are clean.
    pub byte_taints: BTreeMap<usize, TaintId>,
    /// Whether this object has been freed.
    pub freed: bool,
    /// Address where this object was freed (if freed).
    pub free_addr: Option<u64>,
    /// Taint on the pointer itself (affects where data flows).
    pub ptr_taint: TaintId,
}

impl HeapObject {
    /// Create a new clean heap object.
    #[must_use]
    pub fn new(base_ptr: u64, size: usize, alloc_site: AllocationSite) -> Self {
        Self {
            base_ptr,
            size,
            site: alloc_site,
            byte_taints: BTreeMap::new(),
            freed: false,
            free_addr: None,
            ptr_taint: taint_bits::NONE,
        }
    }

    /// Mark a byte range as tainted.
    pub fn taint_range(&mut self, offset: usize, len: usize, taint: TaintId) {
        // Use saturating_add to prevent offset+len from overflowing usize.
        for i in offset..offset.saturating_add(len).min(self.size) {
            let entry = self.byte_taints.entry(i).or_insert(taint_bits::NONE);
            *entry |= taint;
        }
    }

    /// Clear taint from a byte range (sanitise).
    pub fn sanitize_range(&mut self, offset: usize, len: usize) {
        for i in offset..offset.saturating_add(len).min(self.size) {
            self.byte_taints.remove(&i);
        }
    }

    /// Get the combined taint of a byte range.
    #[must_use]
    pub fn range_taint(&self, offset: usize, len: usize) -> TaintId {
        let mut combined = taint_bits::NONE;
        for i in offset..offset.saturating_add(len).min(self.size) {
            combined |= self
                .byte_taints
                .get(&i)
                .copied()
                .unwrap_or(taint_bits::NONE);
        }
        combined
    }

    /// Get the taint of the entire object.
    #[must_use]
    pub fn total_taint(&self) -> TaintId {
        self.byte_taints
            .values()
            .fold(taint_bits::NONE, |acc, &t| acc | t)
    }

    /// Return `true` if any byte is tainted.
    #[must_use]
    pub fn is_tainted(&self) -> bool {
        !self.byte_taints.is_empty() || taint_bits::is_tainted(self.ptr_taint)
    }

    /// Return `true` if this object has been freed.
    #[must_use]
    pub const fn is_freed(&self) -> bool {
        self.freed
    }

    /// Mark the object as freed.
    pub fn mark_freed(&mut self, free_addr: u64) {
        self.freed = true;
        self.free_addr = Some(free_addr);
    }

    /// Return the number of tainted bytes.
    #[must_use]
    pub fn tainted_byte_count(&self) -> usize {
        self.byte_taints
            .values()
            .filter(|&&t| taint_bits::is_tainted(t))
            .count()
    }

    /// Proportion of the object that is tainted (0.0–1.0).
    #[must_use]
    pub fn taint_coverage(&self) -> f64 {
        if self.size == 0 {
            return 0.0;
        }
        usize_as_f64(self.tainted_byte_count()) / usize_as_f64(self.size)
    }
}

/// Lossily cast `usize` to `f64` (acceptable for ratio calculations).
fn usize_as_f64(n: usize) -> f64 {
    n as f64
}

// ─── HeapCopyRecord ───────────────────────────────────────────────────────────

/// Records a `memcpy`/`memmove` between two heap objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeapCopyRecord {
    pub src_ptr: u64,
    pub dst_ptr: u64,
    pub src_offset: usize,
    pub dst_offset: usize,
    pub len: usize,
    pub instr_addr: u64,
    pub taint_transferred: TaintId,
}

// ─── FreeRecord ───────────────────────────────────────────────────────────────

/// Records that a pointer was freed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreeRecord {
    pub ptr: u64,
    pub free_addr: u64,
    pub taint_at_free: TaintId,
}

// ─── UseAfterFreeTaintCheck ───────────────────────────────────────────────────

/// Detects use-after-free: any access to a freed pointer that was tainted.
pub struct UseAfterFreeTaintCheck;

impl UseAfterFreeTaintCheck {
    /// Check if `ptr` is a freed (and tainted) pointer.
    ///
    /// Returns a `TaintFinding` if use-after-free is detected.
    #[must_use]
    pub fn check(tracker: &HeapTaintTracker, ptr: u64, access_addr: u64) -> Option<TaintFinding> {
        if let Some(obj) = tracker.get_object(ptr) && obj.is_freed() && obj.is_tainted() {
            return Some(TaintFinding::new(
                FindingType::UseAfterFree,
                access_addr,
                obj.total_taint(),
                format!(
                    "Use-after-free: tainted pointer {ptr:#x} (freed at {:#x}) accessed at {access_addr:#x}",
                    obj.free_addr.unwrap_or(0)
                ),
            ));
        }
        None
    }

    /// Scan all freed objects for any that are still tainted.
    #[must_use]
    pub fn scan_freed_objects(tracker: &HeapTaintTracker) -> Vec<TaintFinding> {
        tracker
            .freed_objects
            .iter()
            .filter(|(_, obj)| obj.is_tainted())
            .map(|(&ptr, obj)| {
                TaintFinding::new(
                    FindingType::UseAfterFree,
                    obj.free_addr.unwrap_or(0),
                    obj.total_taint(),
                    format!("Freed object at {ptr:#x} contains taint"),
                )
            })
            .collect()
    }
}

// ─── HeapSpray ────────────────────────────────────────────────────────────────

/// Detects heap spray patterns: many allocations with similar tainted content.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HeapSprayDetector {
    /// Minimum number of allocations with tainted data to flag a spray.
    pub min_tainted_allocs: usize,
    /// Whether to require all sprayed objects to be the same size.
    pub require_same_size: bool,
}

impl HeapSprayDetector {
    #[must_use]
    pub fn new(min_tainted_allocs: usize, require_same_size: bool) -> Self {
        Self {
            min_tainted_allocs,
            require_same_size,
        }
    }

    /// Return `true` if the current heap state looks like a spray.
    #[must_use]
    pub fn detect(&self, tracker: &HeapTaintTracker) -> bool {
        let tainted_allocs: Vec<&HeapObject> = tracker
            .live_objects
            .values()
            .filter(|o| o.is_tainted())
            .collect();

        if tainted_allocs.len() < self.min_tainted_allocs {
            return false;
        }

        if self.require_same_size {
            let first_size = tainted_allocs[0].size;
            tainted_allocs.iter().all(|o| o.size == first_size)
        } else {
            true
        }
    }

    /// Return details about detected spray groups (grouped by allocation size).
    #[must_use]
    pub fn spray_groups(&self, tracker: &HeapTaintTracker) -> HashMap<usize, Vec<u64>> {
        let mut groups: HashMap<usize, Vec<u64>> = HashMap::new();
        for obj in tracker.live_objects.values() {
            if obj.is_tainted() {
                groups.entry(obj.size).or_default().push(obj.base_ptr);
            }
        }
        groups.retain(|_, ptrs| ptrs.len() >= self.min_tainted_allocs);
        groups
    }
}

// ─── HeapTaintTracker ────────────────────────────────────────────────────────

/// Tracks all heap objects, their taint state, and copies between them.
///
/// Keyed by allocation base address.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HeapTaintTracker {
    /// Live (not yet freed) objects.
    pub live_objects: HashMap<u64, HeapObject>,
    /// Objects that have been freed (retained for UAF detection).
    pub freed_objects: HashMap<u64, HeapObject>,
    /// History of memcpy/memmove operations.
    pub copy_records: Vec<HeapCopyRecord>,
    /// History of free operations.
    pub free_records: Vec<FreeRecord>,
    /// Total number of allocations tracked.
    pub total_allocs: u64,
    /// Total number of frees tracked.
    pub total_frees: u64,
}

impl HeapTaintTracker {
    /// Create a new empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Allocation ────────────────────────────────────────────────────────────

    /// Record a new heap allocation. Returns an error for zero-size.
    ///
    /// # Errors
    /// Returns [`HeapTaintError::ZeroSizeAlloc`] if `size` is zero.
    pub fn alloc(
        &mut self,
        ptr: u64,
        size: usize,
        alloc_site: AllocationSite,
    ) -> Result<(), HeapTaintError> {
        if size == 0 {
            return Err(HeapTaintError::ZeroSizeAlloc(ptr));
        }
        let obj = HeapObject::new(ptr, size, alloc_site);
        self.live_objects.insert(ptr, obj);
        self.total_allocs += 1;
        Ok(())
    }

    /// Record a free operation. Returns error on double-free.
    ///
    /// # Errors
    /// Returns [`HeapTaintError::DoubleFree`] if `ptr` was already freed.
    pub fn free(
        &mut self,
        ptr: u64,
        free_addr: u64,
    ) -> Result<Option<TaintFinding>, HeapTaintError> {
        if self.freed_objects.contains_key(&ptr) {
            return Err(HeapTaintError::DoubleFree(ptr));
        }
        if let Some(mut obj) = self.live_objects.remove(&ptr) {
            let taint_at_free = obj.total_taint();
            obj.mark_freed(free_addr);
            self.free_records.push(FreeRecord {
                ptr,
                free_addr,
                taint_at_free,
            });
            self.freed_objects.insert(ptr, obj);
        }
        // Also counts freeing unknown pointers (stack/external).
        self.total_frees += 1;
        Ok(None)
    }

    // ── Taint operations ──────────────────────────────────────────────────────

    /// Taint a range of bytes in a live heap object.
    ///
    /// # Errors
    /// Returns [`HeapTaintError::ObjectNotFound`] if `ptr` is not a live object.
    pub fn taint_range(
        &mut self,
        ptr: u64,
        offset: usize,
        len: usize,
        taint: TaintId,
    ) -> Result<(), HeapTaintError> {
        let obj = self
            .live_objects
            .get_mut(&ptr)
            .ok_or(HeapTaintError::ObjectNotFound(ptr))?;
        obj.taint_range(offset, len, taint);
        Ok(())
    }

    /// Taint the pointer value itself.
    ///
    /// # Errors
    /// Returns [`HeapTaintError::ObjectNotFound`] if `ptr` is not a live object.
    pub fn taint_ptr(&mut self, ptr: u64, taint: TaintId) -> Result<(), HeapTaintError> {
        let obj = self
            .live_objects
            .get_mut(&ptr)
            .ok_or(HeapTaintError::ObjectNotFound(ptr))?;
        obj.ptr_taint |= taint;
        Ok(())
    }

    /// Sanitise a range of bytes in a live heap object.
    ///
    /// # Errors
    /// Returns [`HeapTaintError::ObjectNotFound`] if `ptr` is not a live object.
    pub fn sanitize_range(
        &mut self,
        ptr: u64,
        offset: usize,
        len: usize,
    ) -> Result<(), HeapTaintError> {
        let obj = self
            .live_objects
            .get_mut(&ptr)
            .ok_or(HeapTaintError::ObjectNotFound(ptr))?;
        obj.sanitize_range(offset, len);
        Ok(())
    }

    // ── Copy propagation ──────────────────────────────────────────────────────

    /// Propagate taint from a `memcpy(dst+dst_off, src+src_off, len)` call.
    ///
    /// Returns a `TaintFinding` if the copy brings tainted data into a
    /// security-sensitive context (e.g., the destination is a code region).
    ///
    /// # Errors
    /// Currently always returns `Ok`; reserved for future validation.
    pub fn propagate_copy(
        &mut self,
        src_ptr: u64,
        src_offset: usize,
        dst_ptr: u64,
        dst_offset: usize,
        len: usize,
        instr_addr: u64,
    ) -> Result<Option<TaintFinding>, HeapTaintError> {
        // Read source taint.
        let src_taint = self.live_objects.get(&src_ptr)
            .map_or(taint_bits::NONE, |src| src.range_taint(src_offset, len));

        // Apply to destination.
        if taint_bits::is_tainted(src_taint) && let Some(dst) = self.live_objects.get_mut(&dst_ptr) {
            dst.taint_range(dst_offset, len, src_taint);
        }

        let record = HeapCopyRecord {
            src_ptr,
            dst_ptr,
            src_offset,
            dst_offset,
            len,
            instr_addr,
            taint_transferred: src_taint,
        };
        self.copy_records.push(record);

        Ok(None)
    }

    // ── Query ──────────────────────────────────────────────────────────────────

    /// Look up a live object by base pointer.
    #[must_use]
    pub fn get_object(&self, ptr: u64) -> Option<&HeapObject> {
        self.live_objects
            .get(&ptr)
            .or_else(|| self.freed_objects.get(&ptr))
    }

    /// Look up a live object mutably.
    #[must_use]
    pub fn get_object_mut(&mut self, ptr: u64) -> Option<&mut HeapObject> {
        self.live_objects.get_mut(&ptr)
    }

    /// Return the combined taint of a byte range in a (possibly freed) object.
    #[must_use]
    pub fn query_taint(&self, ptr: u64, offset: usize, len: usize) -> TaintId {
        self.get_object(ptr)
            .map_or(taint_bits::NONE, |o| o.range_taint(offset, len))
    }

    /// Return all live tainted pointers.
    #[must_use]
    pub fn tainted_ptrs(&self) -> Vec<u64> {
        self.live_objects
            .iter()
            .filter(|(_, obj)| obj.is_tainted())
            .map(|(&ptr, _)| ptr)
            .collect()
    }

    /// Return all allocation sites that produced tainted objects.
    #[must_use]
    pub fn tainted_sites(&self) -> Vec<&AllocationSite> {
        self.live_objects
            .values()
            .filter(|o| o.is_tainted())
            .map(|o| &o.site)
            .collect()
    }

    /// Total live objects.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.live_objects.len()
    }

    /// Total freed objects retained for UAF detection.
    #[must_use]
    pub fn freed_count(&self) -> usize {
        self.freed_objects.len()
    }

    // ── UAF scanning ─────────────────────────────────────────────────────────

    /// Scan for use-after-free accesses given a set of pointer accesses.
    ///
    /// `accesses`: list of `(ptr, instr_addr)` pairs.
    #[must_use]
    pub fn check_accesses(&self, accesses: &[(u64, u64)]) -> Vec<TaintFinding> {
        let mut findings = Vec::new();
        for &(ptr, access_addr) in accesses {
            if let Some(f) = UseAfterFreeTaintCheck::check(self, ptr, access_addr) {
                findings.push(f);
            }
        }
        findings
    }

    /// Run a full UAF scan over all freed objects.
    #[must_use]
    pub fn uaf_scan(&self) -> Vec<TaintFinding> {
        UseAfterFreeTaintCheck::scan_freed_objects(self)
    }

    // ── Heap spray detection ─────────────────────────────────────────────────

    /// Check for a heap spray pattern (≥ `min_allocs` tainted live allocations).
    #[must_use]
    pub fn detect_spray(&self, min_allocs: usize) -> bool {
        let detector = HeapSprayDetector::new(min_allocs, false);
        detector.detect(self)
    }

    /// Group spray candidates by size.
    #[must_use]
    pub fn spray_groups(&self, min_allocs: usize) -> HashMap<usize, Vec<u64>> {
        let detector = HeapSprayDetector::new(min_allocs, false);
        detector.spray_groups(self)
    }
}

// ─── HeapTaintPass ─────────────────────────────────────────────────────────────

/// High-level wrapper that models malloc/free/memcpy from call sites.
///
/// Callers feed in `HeapEvent` values in program order; this pass maintains
/// the `HeapTaintTracker` and emits `TaintFinding` values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HeapEvent {
    /// `malloc(size)` returned `ptr` at `call_addr`.
    Alloc {
        ptr: u64,
        size: usize,
        call_addr: u64,
        allocator: String,
    },
    /// `free(ptr)` called at `call_addr`.
    Free { ptr: u64, call_addr: u64 },
    /// `memcpy(dst, src, len)` called at `call_addr`.
    Copy {
        src: u64,
        dst: u64,
        len: usize,
        call_addr: u64,
    },
    /// External taint source writes into `ptr` at `offset` for `len` bytes.
    TaintWrite {
        ptr: u64,
        offset: usize,
        len: usize,
        taint: TaintId,
        call_addr: u64,
    },
    /// Read from `ptr` at `call_addr`.
    Read { ptr: u64, call_addr: u64 },
}

/// Result of running the heap taint pass.
#[derive(Debug, Default)]
pub struct HeapPassResult {
    pub findings: Vec<TaintFinding>,
    pub errors: Vec<HeapTaintError>,
    pub tracker: HeapTaintTracker,
}

/// Runs a sequence of `HeapEvent` through the `HeapTaintTracker`.
pub struct HeapTaintPass;

impl HeapTaintPass {
    #[must_use]
    pub fn run(events: Vec<HeapEvent>) -> HeapPassResult {
        let mut result = HeapPassResult::default();
        for event in events {
            match event {
                HeapEvent::Alloc {
                    ptr,
                    size,
                    call_addr,
                    allocator,
                } => {
                    let site = AllocationSite::new(call_addr, allocator);
                    if let Err(e) = result.tracker.alloc(ptr, size, site) {
                        result.errors.push(e);
                    }
                }
                HeapEvent::Free { ptr, call_addr } => match result.tracker.free(ptr, call_addr) {
                    Ok(Some(f)) => result.findings.push(f),
                    Ok(None) => {}
                    Err(HeapTaintError::DoubleFree(p)) => {
                        // Retrieve the size of the freed object to avoid passing
                        // usize::MAX as the length (which silently underflows in
                        // the range_taint arithmetic).
                        let obj_size = result
                            .tracker
                            .freed_objects
                            .get(&p)
                            .map_or(0, |o| o.size);
                        result.findings.push(TaintFinding::new(
                            FindingType::UseAfterFree,
                            call_addr,
                            result.tracker.query_taint(p, 0, obj_size),
                            format!("Double-free of pointer {p:#x} at {call_addr:#x}"),
                        ));
                    }
                    Err(e) => result.errors.push(e),
                },
                HeapEvent::Copy {
                    src,
                    dst,
                    len,
                    call_addr,
                } => {
                    match result
                        .tracker
                        .propagate_copy(src, 0, dst, 0, len, call_addr)
                    {
                        Ok(Some(f)) => result.findings.push(f),
                        Ok(None) => {}
                        Err(e) => result.errors.push(e),
                    }
                }
                HeapEvent::TaintWrite {
                    ptr,
                    offset,
                    len,
                    taint,
                    call_addr: _,
                } => {
                    if let Err(e) = result.tracker.taint_range(ptr, offset, len, taint) {
                        result.errors.push(e);
                    }
                }
                HeapEvent::Read { ptr, call_addr } => {
                    if let Some(f) = UseAfterFreeTaintCheck::check(&result.tracker, ptr, call_addr)
                    {
                        result.findings.push(f);
                    }
                }
            }
        }
        // Final UAF scan over all freed objects.
        result.findings.extend(result.tracker.uaf_scan());
        result
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taint_bits;

    // ── HeapObject tests ──────────────────────────────────────────────────────

    #[test]
    fn heap_object_new_is_clean() {
        let site = AllocationSite::malloc(0x1000);
        let obj = HeapObject::new(0x2000, 64, site);
        assert!(!obj.is_tainted());
        assert!(!obj.is_freed());
        assert_eq!(obj.total_taint(), taint_bits::NONE);
    }

    #[test]
    fn heap_object_taint_range() {
        let site = AllocationSite::malloc(0x1000);
        let mut obj = HeapObject::new(0x2000, 64, site);
        obj.taint_range(0, 8, taint_bits::NETWORK);
        assert!(obj.is_tainted());
        assert_eq!(obj.range_taint(0, 8), taint_bits::NETWORK);
        assert_eq!(obj.range_taint(8, 8), taint_bits::NONE);
    }

    #[test]
    fn heap_object_sanitize_range() {
        let site = AllocationSite::malloc(0x1000);
        let mut obj = HeapObject::new(0x2000, 64, site);
        obj.taint_range(0, 16, taint_bits::USER_INPUT);
        obj.sanitize_range(0, 8);
        assert_eq!(obj.range_taint(0, 8), taint_bits::NONE);
        assert_eq!(obj.range_taint(8, 8), taint_bits::USER_INPUT);
    }

    #[test]
    fn heap_object_total_taint_unions_all_bytes() {
        let site = AllocationSite::malloc(0x1000);
        let mut obj = HeapObject::new(0x2000, 64, site);
        obj.taint_range(0, 4, taint_bits::USER_INPUT);
        obj.taint_range(4, 4, taint_bits::NETWORK);
        assert_eq!(
            obj.total_taint(),
            taint_bits::USER_INPUT | taint_bits::NETWORK
        );
    }

    #[test]
    fn heap_object_mark_freed() {
        let site = AllocationSite::malloc(0x1000);
        let mut obj = HeapObject::new(0x2000, 64, site);
        obj.mark_freed(0x5000);
        assert!(obj.is_freed());
        assert_eq!(obj.free_addr, Some(0x5000));
    }

    #[test]
    fn heap_object_taint_coverage() {
        let site = AllocationSite::malloc(0x1000);
        let mut obj = HeapObject::new(0x2000, 100, site);
        obj.taint_range(0, 50, taint_bits::FILE);
        let coverage = obj.taint_coverage();
        assert!((coverage - 0.5).abs() < 1e-9);
    }

    #[test]
    fn heap_object_range_capped_at_size() {
        let site = AllocationSite::malloc(0x1000);
        let mut obj = HeapObject::new(0x2000, 8, site);
        // Taint past end — should not panic, just cap.
        obj.taint_range(4, 100, taint_bits::ENVIRONMENT);
        assert_eq!(obj.tainted_byte_count(), 4); // only bytes 4..8
    }

    // ── AllocationSite tests ──────────────────────────────────────────────────

    #[test]
    fn allocation_site_display() {
        let site = AllocationSite::malloc(0xDEAD);
        assert!(format!("{site}").contains("malloc"));
    }

    #[test]
    fn allocation_site_constructors() {
        let s1 = AllocationSite::calloc(0x100);
        assert_eq!(s1.allocator, "calloc");
        let s2 = AllocationSite::new_op(0x200);
        assert_eq!(s2.allocator, "operator new");
        let s3 = AllocationSite::new_array(0x300);
        assert_eq!(s3.allocator, "operator new[]");
    }

    // ── HeapTaintTracker tests ────────────────────────────────────────────────

    #[test]
    fn tracker_alloc_and_taint() {
        let mut tracker = HeapTaintTracker::new();
        tracker
            .alloc(0x1000, 32, AllocationSite::malloc(0x500))
            .unwrap();
        tracker
            .taint_range(0x1000, 0, 8, taint_bits::USER_INPUT)
            .unwrap();
        assert_eq!(tracker.query_taint(0x1000, 0, 8), taint_bits::USER_INPUT);
        assert_eq!(tracker.query_taint(0x1000, 8, 8), taint_bits::NONE);
    }

    #[test]
    fn tracker_zero_size_alloc_error() {
        let mut tracker = HeapTaintTracker::new();
        let r = tracker.alloc(0x1000, 0, AllocationSite::malloc(0x500));
        assert!(matches!(r, Err(HeapTaintError::ZeroSizeAlloc(_))));
    }

    #[test]
    fn tracker_free_moves_to_freed() {
        let mut tracker = HeapTaintTracker::new();
        tracker
            .alloc(0x1000, 32, AllocationSite::malloc(0x500))
            .unwrap();
        tracker
            .taint_range(0x1000, 0, 4, taint_bits::NETWORK)
            .unwrap();
        tracker.free(0x1000, 0x600).unwrap();
        assert_eq!(tracker.live_count(), 0);
        assert_eq!(tracker.freed_count(), 1);
    }

    #[test]
    fn tracker_double_free_error() {
        let mut tracker = HeapTaintTracker::new();
        tracker
            .alloc(0x1000, 32, AllocationSite::malloc(0x500))
            .unwrap();
        tracker.free(0x1000, 0x600).unwrap();
        let r = tracker.free(0x1000, 0x700);
        assert!(matches!(r, Err(HeapTaintError::DoubleFree(_))));
    }

    #[test]
    fn tracker_propagate_copy_transfers_taint() {
        let mut tracker = HeapTaintTracker::new();
        tracker
            .alloc(0x1000, 64, AllocationSite::malloc(0x500))
            .unwrap();
        tracker
            .alloc(0x2000, 64, AllocationSite::malloc(0x510))
            .unwrap();
        tracker
            .taint_range(0x1000, 0, 16, taint_bits::FILE)
            .unwrap();
        tracker
            .propagate_copy(0x1000, 0, 0x2000, 0, 16, 0x600)
            .unwrap();
        assert_eq!(tracker.query_taint(0x2000, 0, 16), taint_bits::FILE);
    }

    #[test]
    fn tracker_propagate_copy_no_taint_does_nothing() {
        let mut tracker = HeapTaintTracker::new();
        tracker
            .alloc(0x1000, 64, AllocationSite::malloc(0x500))
            .unwrap();
        tracker
            .alloc(0x2000, 64, AllocationSite::malloc(0x510))
            .unwrap();
        // Source is clean.
        tracker
            .propagate_copy(0x1000, 0, 0x2000, 0, 16, 0x600)
            .unwrap();
        assert_eq!(tracker.query_taint(0x2000, 0, 16), taint_bits::NONE);
    }

    #[test]
    fn tracker_taint_ptr() {
        let mut tracker = HeapTaintTracker::new();
        tracker
            .alloc(0x1000, 32, AllocationSite::malloc(0x500))
            .unwrap();
        tracker.taint_ptr(0x1000, taint_bits::REGISTRY).unwrap();
        let obj = tracker.get_object(0x1000).unwrap();
        assert_eq!(obj.ptr_taint, taint_bits::REGISTRY);
    }

    #[test]
    fn tracker_tainted_ptrs_list() {
        let mut tracker = HeapTaintTracker::new();
        tracker
            .alloc(0x1000, 32, AllocationSite::malloc(0x500))
            .unwrap();
        tracker
            .alloc(0x2000, 32, AllocationSite::malloc(0x510))
            .unwrap();
        tracker
            .taint_range(0x1000, 0, 4, taint_bits::USER_INPUT)
            .unwrap();
        let ptrs = tracker.tainted_ptrs();
        assert_eq!(ptrs.len(), 1);
        assert!(ptrs.contains(&0x1000));
    }

    #[test]
    fn tracker_uaf_scan_detects_freed_tainted() {
        let mut tracker = HeapTaintTracker::new();
        tracker
            .alloc(0x1000, 32, AllocationSite::malloc(0x500))
            .unwrap();
        tracker
            .taint_range(0x1000, 0, 4, taint_bits::NETWORK)
            .unwrap();
        tracker.free(0x1000, 0x600).unwrap();
        let findings = tracker.uaf_scan();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].finding_type, FindingType::UseAfterFree);
    }

    #[test]
    fn tracker_uaf_scan_clean_freed_no_finding() {
        let mut tracker = HeapTaintTracker::new();
        tracker
            .alloc(0x1000, 32, AllocationSite::malloc(0x500))
            .unwrap();
        // Don't taint, then free.
        tracker.free(0x1000, 0x600).unwrap();
        let findings = tracker.uaf_scan();
        assert!(findings.is_empty());
    }

    // ── UseAfterFreeTaintCheck tests ──────────────────────────────────────────

    #[test]
    fn uaf_check_live_object_no_finding() {
        let mut tracker = HeapTaintTracker::new();
        tracker
            .alloc(0x1000, 32, AllocationSite::malloc(0x500))
            .unwrap();
        tracker
            .taint_range(0x1000, 0, 4, taint_bits::USER_INPUT)
            .unwrap();
        // Not freed yet.
        let f = UseAfterFreeTaintCheck::check(&tracker, 0x1000, 0x700);
        assert!(f.is_none());
    }

    #[test]
    fn uaf_check_freed_tainted_object_finding() {
        let mut tracker = HeapTaintTracker::new();
        tracker
            .alloc(0x1000, 32, AllocationSite::malloc(0x500))
            .unwrap();
        tracker.taint_range(0x1000, 0, 4, taint_bits::FILE).unwrap();
        tracker.free(0x1000, 0x600).unwrap();
        let f = UseAfterFreeTaintCheck::check(&tracker, 0x1000, 0x700);
        assert!(f.is_some());
        assert_eq!(f.unwrap().finding_type, FindingType::UseAfterFree);
    }

    // ── HeapSprayDetector tests ───────────────────────────────────────────────

    #[test]
    fn spray_detector_below_threshold_no_spray() {
        let mut tracker = HeapTaintTracker::new();
        for i in 0u64..3 {
            tracker
                .alloc(0x1000 + i * 64, 64, AllocationSite::malloc(0x500))
                .unwrap();
            tracker
                .taint_range(0x1000 + i * 64, 0, 64, taint_bits::USER_INPUT)
                .unwrap();
        }
        assert!(!tracker.detect_spray(5));
    }

    #[test]
    fn spray_detector_above_threshold_is_spray() {
        let mut tracker = HeapTaintTracker::new();
        for i in 0u64..10 {
            tracker
                .alloc(0x1000 + i * 64, 64, AllocationSite::malloc(0x500))
                .unwrap();
            tracker
                .taint_range(0x1000 + i * 64, 0, 64, taint_bits::NETWORK)
                .unwrap();
        }
        assert!(tracker.detect_spray(5));
    }

    #[test]
    fn spray_groups_by_size() {
        let mut tracker = HeapTaintTracker::new();
        for i in 0u64..5 {
            tracker
                .alloc(0x1000 + i * 64, 64, AllocationSite::malloc(0x500))
                .unwrap();
            tracker
                .taint_range(0x1000 + i * 64, 0, 64, taint_bits::FILE)
                .unwrap();
        }
        for i in 0u64..3 {
            tracker
                .alloc(0x5000 + i * 32, 32, AllocationSite::malloc(0x600))
                .unwrap();
            tracker
                .taint_range(0x5000 + i * 32, 0, 32, taint_bits::FILE)
                .unwrap();
        }
        let groups = tracker.spray_groups(3);
        assert!(groups.contains_key(&64));
        assert!(groups.contains_key(&32));
    }

    // ── HeapTaintPass tests ───────────────────────────────────────────────────

    #[test]
    fn heap_pass_alloc_then_taint_then_free_uaf() {
        let events = vec![
            HeapEvent::Alloc {
                ptr: 0x1000,
                size: 64,
                call_addr: 0x100,
                allocator: "malloc".into(),
            },
            HeapEvent::TaintWrite {
                ptr: 0x1000,
                offset: 0,
                len: 8,
                taint: taint_bits::USER_INPUT,
                call_addr: 0x110,
            },
            HeapEvent::Free {
                ptr: 0x1000,
                call_addr: 0x120,
            },
        ];
        let result = HeapTaintPass::run(events);
        // UAF scan on freed tainted object should produce a finding.
        assert!(!result.findings.is_empty());
    }

    #[test]
    fn heap_pass_copy_propagates_taint() {
        let events = vec![
            HeapEvent::Alloc {
                ptr: 0x1000,
                size: 64,
                call_addr: 0x100,
                allocator: "malloc".into(),
            },
            HeapEvent::Alloc {
                ptr: 0x2000,
                size: 64,
                call_addr: 0x110,
                allocator: "malloc".into(),
            },
            HeapEvent::TaintWrite {
                ptr: 0x1000,
                offset: 0,
                len: 16,
                taint: taint_bits::NETWORK,
                call_addr: 0x120,
            },
            HeapEvent::Copy {
                src: 0x1000,
                dst: 0x2000,
                len: 16,
                call_addr: 0x130,
            },
        ];
        let result = HeapTaintPass::run(events);
        assert_eq!(
            result.tracker.query_taint(0x2000, 0, 16),
            taint_bits::NETWORK
        );
    }

    #[test]
    fn heap_pass_double_free_emits_finding() {
        let events = vec![
            HeapEvent::Alloc {
                ptr: 0x3000,
                size: 32,
                call_addr: 0x200,
                allocator: "malloc".into(),
            },
            HeapEvent::Free {
                ptr: 0x3000,
                call_addr: 0x210,
            },
            HeapEvent::Free {
                ptr: 0x3000,
                call_addr: 0x220,
            },
        ];
        let result = HeapTaintPass::run(events);
        assert!(!result.findings.is_empty());
        assert_eq!(result.findings[0].finding_type, FindingType::UseAfterFree);
    }

    #[test]
    fn heap_pass_read_after_free_tainted() {
        let events = vec![
            HeapEvent::Alloc {
                ptr: 0x4000,
                size: 32,
                call_addr: 0x300,
                allocator: "malloc".into(),
            },
            HeapEvent::TaintWrite {
                ptr: 0x4000,
                offset: 0,
                len: 4,
                taint: taint_bits::FILE,
                call_addr: 0x310,
            },
            HeapEvent::Free {
                ptr: 0x4000,
                call_addr: 0x320,
            },
            HeapEvent::Read {
                ptr: 0x4000,
                call_addr: 0x330,
            },
        ];
        let result = HeapTaintPass::run(events);
        // Read after free of tainted pointer should produce a finding.
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.finding_type == FindingType::UseAfterFree)
        );
    }

    #[test]
    fn heap_tracker_sanitize_range() {
        let mut tracker = HeapTaintTracker::new();
        tracker
            .alloc(0x1000, 64, AllocationSite::malloc(0x500))
            .unwrap();
        tracker
            .taint_range(0x1000, 0, 16, taint_bits::USER_INPUT)
            .unwrap();
        tracker.sanitize_range(0x1000, 0, 16).unwrap();
        assert_eq!(tracker.query_taint(0x1000, 0, 16), taint_bits::NONE);
    }

    #[test]
    fn heap_tracker_query_unknown_ptr_returns_none() {
        let tracker = HeapTaintTracker::new();
        assert_eq!(tracker.query_taint(0xDEAD, 0, 8), taint_bits::NONE);
    }
}
