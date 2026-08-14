//! `MSan`-style uninitialized memory detection model.
//!
//! # Structs
//! - [`UninitByte`]      — a single uninitialized byte with provenance
//! - [`UninitRegion`]    — a contiguous region of uninitialised bytes
//! - [`UninitPropagation`] — propagation rules for taint
//! - [`MsanReport`]      — report of a detected violation
//! - [`ShadowMap`]       — per-byte shadow memory (`init`/`uninit` tracking)
//! - [`MsanModel`]       — top-level `MSan` model coordinator

use std::collections::HashMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the `MSan` model.
#[derive(Debug, Error)]
pub enum MsanError {
    /// An uninitialised read at the given address and access size.
    #[error("uninitialised read at {0:#x} of {1} bytes")]
    UninitRead(u64, usize),
    /// The given address is not tracked by the shadow map.
    #[error("address {0:#x} not tracked")]
    Untracked(u64),
    /// A range computation failed.
    #[error("range error: {0}")]
    Range(String),
    /// A taint-propagation step failed.
    #[error("taint propagation error: {0}")]
    Propagation(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// UninitSource
// ─────────────────────────────────────────────────────────────────────────────

/// Where an uninitialised byte originated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UninitSource {
    /// Stack allocation.
    StackAlloc { sp: u64, frame: String },
    /// Heap allocation.
    HeapAlloc { addr: u64 },
    /// Returned from an external function.
    ExternalCall { function: String },
    /// Loaded from a memory-mapped region.
    MmapRegion { addr: u64 },
    /// Derived via bitwise or arithmetic propagation.
    Propagated { from_addr: u64, operation: String },
    /// Unknown origin.
    Unknown,
}

impl std::fmt::Display for UninitSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StackAlloc { frame, .. } => write!(f, "stack({frame})"),
            Self::HeapAlloc { addr } => write!(f, "heap({addr:#x})"),
            Self::ExternalCall { function } => write!(f, "extern({function})"),
            Self::MmapRegion { addr } => write!(f, "mmap({addr:#x})"),
            Self::Propagated { operation, .. } => write!(f, "propagated({operation})"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UninitByte
// ─────────────────────────────────────────────────────────────────────────────

/// A single byte tracked as potentially uninitialised.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UninitByte {
    /// Virtual address of this byte.
    pub addr: u64,
    /// Where the uninitialised byte originated.
    pub source: UninitSource,
    /// Call-site program counter at allocation time.
    pub alloc_pc: u64,
    /// Taint label (used for inter-variable tracking).
    pub taint_label: u32,
}

impl UninitByte {
    /// Construct a new uninitialised byte record.
    #[must_use]
    pub const fn new(addr: u64, source: UninitSource, alloc_pc: u64) -> Self {
        Self {
            addr,
            source,
            alloc_pc,
            taint_label: 0,
        }
    }

    /// Attach a taint label.
    #[must_use]
    pub const fn with_taint(mut self, label: u32) -> Self {
        self.taint_label = label;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UninitRegion
// ─────────────────────────────────────────────────────────────────────────────

/// A contiguous range of uninitialised bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UninitRegion {
    /// Base address.
    pub base: u64,
    /// Length in bytes.
    pub len: usize,
    /// Source of uninitialisation.
    pub source: UninitSource,
    /// When this region was allocated.
    pub alloc_time: SystemTime,
    /// PC at allocation.
    pub alloc_pc: u64,
    /// Description.
    pub description: String,
}

impl UninitRegion {
    /// Construct a new uninitialised region record.
    #[must_use]
    pub fn new(base: u64, len: usize, source: UninitSource, alloc_pc: u64) -> Self {
        let description = format!("uninit[{base:#x}..{base:#x}+{len}] from {source}");
        Self {
            base,
            len,
            source,
            alloc_time: SystemTime::now(),
            alloc_pc,
            description,
        }
    }

    /// Returns `true` if `addr` falls within this region.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + self.len as u64
    }

    /// Returns `true` if this region overlaps `[addr, addr+size)`.
    #[must_use]
    pub const fn overlaps(&self, addr: u64, size: usize) -> bool {
        let end = self.base + self.len as u64;
        let other_end = addr.saturating_add(size as u64);
        self.base < other_end && addr < end
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PropagationRule
// ─────────────────────────────────────────────────────────────────────────────

/// A single taint-propagation rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropagationRule {
    /// If any source byte is tainted, the destination is tainted.
    AnyTaintsResult,
    /// Only if all source bytes are tainted is the destination tainted.
    AllTaintResult,
    /// Taint always propagates (unconditional).
    Unconditional,
    /// Taint never propagates (e.g. constant mask that zeroes out bits).
    Never,
}

impl std::fmt::Display for PropagationRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AnyTaintsResult => write!(f, "any-taints-result"),
            Self::AllTaintResult => write!(f, "all-taint-result"),
            Self::Unconditional => write!(f, "unconditional"),
            Self::Never => write!(f, "never"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UninitPropagation
// ─────────────────────────────────────────────────────────────────────────────

/// Propagation rules and history for `MSan`-style taint tracking.
#[derive(Debug)]
pub struct UninitPropagation {
    /// Default propagation rule.
    pub default_rule: PropagationRule,
    /// Per-opcode overrides: opcode string → rule.
    pub opcode_rules: HashMap<String, PropagationRule>,
    /// Propagation events: (`dest_addr`, `src_addrs`, `rule`).
    pub events: Vec<PropagationEvent>,
    /// Maximum events to retain.
    pub max_events: usize,
}

/// One recorded propagation event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationEvent {
    pub pc: u64,
    pub opcode: String,
    pub src_addrs: Vec<u64>,
    pub dst_addr: u64,
    pub tainted: bool,
    pub rule: PropagationRule,
}

impl UninitPropagation {
    #[must_use]
    pub fn new() -> Self {
        Self {
            default_rule: PropagationRule::AnyTaintsResult,
            opcode_rules: HashMap::new(),
            events: Vec::new(),
            max_events: 10_000,
        }
    }

    /// Register a per-opcode propagation rule.
    pub fn add_rule(&mut self, opcode: impl Into<String>, rule: PropagationRule) {
        self.opcode_rules.insert(opcode.into(), rule);
    }

    /// Determine the propagation rule for `opcode`.
    #[must_use]
    pub fn rule_for(&self, opcode: &str) -> &PropagationRule {
        self.opcode_rules.get(opcode).unwrap_or(&self.default_rule)
    }

    /// Evaluate whether `dst_addr` becomes tainted given source taint states.
    ///
    /// `src_tainted`: list of (`addr`, `is_tainted`) for each source operand.
    #[must_use]
    pub fn evaluate(&self, opcode: &str, src_tainted: &[(u64, bool)]) -> bool {
        let rule = self.rule_for(opcode);
        match rule {
            PropagationRule::Unconditional => true,
            PropagationRule::Never => false,
            PropagationRule::AnyTaintsResult => src_tainted.iter().any(|(_, t)| *t),
            PropagationRule::AllTaintResult => {
                !src_tainted.is_empty() && src_tainted.iter().all(|(_, t)| *t)
            }
        }
    }

    /// Record a propagation event.
    pub fn record(
        &mut self,
        pc: u64,
        opcode: &str,
        src_addrs: Vec<u64>,
        dst_addr: u64,
        tainted: bool,
    ) {
        if self.events.len() >= self.max_events {
            self.events.remove(0);
        }
        self.events.push(PropagationEvent {
            pc,
            opcode: opcode.to_string(),
            src_addrs,
            dst_addr,
            tainted,
            rule: self.rule_for(opcode).clone(),
        });
    }

    /// Number of taint-propagating events.
    #[must_use]
    pub fn tainted_event_count(&self) -> usize {
        self.events.iter().filter(|e| e.tainted).count()
    }

    /// Unique destination addresses that received taint.
    #[must_use]
    pub fn tainted_destinations(&self) -> Vec<u64> {
        let mut addrs: Vec<u64> = self
            .events
            .iter()
            .filter(|e| e.tainted)
            .map(|e| e.dst_addr)
            .collect();
        addrs.sort_unstable();
        addrs.dedup();
        addrs
    }
}

impl Default for UninitPropagation {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MsanReport
// ─────────────────────────────────────────────────────────────────────────────

/// A detected `MSan` violation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsanReport {
    /// The address that was accessed uninitialised.
    pub access_addr: u64,
    /// Size of the access in bytes.
    pub access_size: usize,
    /// Program counter at the point of the violation.
    pub access_pc: u64,
    /// The uninitialised region responsible.
    pub region: Option<UninitRegion>,
    /// Taint labels involved.
    pub taint_labels: Vec<u32>,
    /// Backtrace program counters.
    pub backtrace: Vec<u64>,
    /// When this violation was detected.
    pub detected_at: SystemTime,
    /// Whether this was a conditional branch (especially dangerous).
    pub is_branch: bool,
    /// Human-readable summary.
    pub summary: String,
}

impl MsanReport {
    #[must_use]
    pub fn new(access_addr: u64, access_size: usize, access_pc: u64) -> Self {
        let summary = format!(
            "MSan: uninit read of {access_size} bytes at {access_addr:#x} (pc={access_pc:#x})"
        );
        Self {
            access_addr,
            access_size,
            access_pc,
            region: None,
            taint_labels: Vec::new(),
            backtrace: Vec::new(),
            detected_at: SystemTime::now(),
            is_branch: false,
            summary,
        }
    }

    #[must_use]
    pub fn with_region(mut self, region: UninitRegion) -> Self {
        self.region = Some(region);
        self
    }

    #[must_use]
    pub fn with_backtrace(mut self, bt: Vec<u64>) -> Self {
        self.backtrace = bt;
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ShadowMap
// ─────────────────────────────────────────────────────────────────────────────

/// Per-byte shadow memory: tracks initialisation state.
///
/// Shadow layout: 1 bit per byte. `1` = initialised, `0` = uninitialised.
/// Pages are 256 bytes wide; each page is stored as a 32-byte bitmap.
#[derive(Debug, Default)]
pub struct ShadowMap {
    /// `page_base` -> 32-byte bitmap (256 bits).
    pages: HashMap<u64, Vec<u8>>,
    /// Taint labels: `addr` -> `label`.
    taint_labels: HashMap<u64, u32>,
    /// Total bytes tracked.
    pub total_tracked: u64,
    /// Total uninit reads detected.
    pub total_uninit_reads: u64,
}

const SHADOW_PAGE_SIZE: u64 = 256;
const SHADOW_BITMAP_BYTES: usize = 32;

impl ShadowMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    const fn page_base(addr: u64) -> u64 {
        (addr / SHADOW_PAGE_SIZE) * SHADOW_PAGE_SIZE
    }
    const fn bit_index(addr: u64) -> (usize, u8) {
        let off = (addr % SHADOW_PAGE_SIZE) as usize;
        (off / 8, 1 << (off % 8))
    }

    /// Mark `len` bytes at `addr` as initialised.
    pub fn mark_init(&mut self, addr: u64, len: usize) {
        for i in 0..len as u64 {
            let a = addr + i;
            let page = Self::page_base(a);
            let bm = self
                .pages
                .entry(page)
                .or_insert_with(|| vec![0u8; SHADOW_BITMAP_BYTES]);
            let (byte_idx, bit) = Self::bit_index(a);
            if bm[byte_idx] & bit == 0 {
                bm[byte_idx] |= bit;
                self.total_tracked += 1;
            }
        }
    }

    /// Mark `len` bytes at `addr` as uninitialised.
    pub fn mark_uninit(&mut self, addr: u64, len: usize) {
        for i in 0..len as u64 {
            let a = addr + i;
            let page = Self::page_base(a);
            let bm = self
                .pages
                .entry(page)
                .or_insert_with(|| vec![0u8; SHADOW_BITMAP_BYTES]);
            let (byte_idx, bit) = Self::bit_index(a);
            bm[byte_idx] &= !bit;
        }
    }

    /// Returns `true` if all bytes in `[addr, addr+len)` are initialised.
    #[must_use]
    pub fn is_init(&self, addr: u64, len: usize) -> bool {
        for i in 0..len as u64 {
            let a = addr + i;
            let page = Self::page_base(a);
            match self.pages.get(&page) {
                Some(bm) => {
                    let (byte_idx, bit) = Self::bit_index(a);
                    if bm[byte_idx] & bit == 0 {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }

    /// Check whether an access is safe.  Records the event.
    ///
    /// Returns `Ok(())` if initialised, `Err(MsanError::UninitRead)` otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`MsanError::UninitRead`] if any byte in `[addr, addr+len)` is
    /// not currently marked initialised.
    pub fn check_access(&mut self, addr: u64, len: usize) -> Result<(), MsanError> {
        if self.is_init(addr, len) {
            Ok(())
        } else {
            self.total_uninit_reads += 1;
            Err(MsanError::UninitRead(addr, len))
        }
    }

    /// Set the taint label for a byte.
    pub fn set_taint(&mut self, addr: u64, label: u32) {
        self.taint_labels.insert(addr, label);
    }

    /// Get the taint label for a byte (0 if none).
    #[must_use]
    pub fn taint_label(&self, addr: u64) -> u32 {
        self.taint_labels.get(&addr).copied().unwrap_or(0)
    }

    /// Collect all taint labels covering `[addr, addr+len)`.
    #[must_use]
    pub fn taint_labels_for(&self, addr: u64, len: usize) -> Vec<u32> {
        (0..len as u64)
            .filter_map(|i| self.taint_labels.get(&(addr + i)).copied())
            .filter(|&l| l != 0)
            .collect()
    }

    /// Number of known pages.
    #[must_use]
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// Reset all shadow state.
    pub fn reset(&mut self) {
        self.pages.clear();
        self.taint_labels.clear();
        self.total_tracked = 0;
        self.total_uninit_reads = 0;
    }

    /// Count the total number of initialised bytes across all pages.
    #[must_use]
    pub fn init_byte_count(&self) -> u64 {
        self.pages
            .values()
            .map(|bm| bm.iter().map(|b| u64::from(b.count_ones())).sum::<u64>())
            .sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AllocRecord
// ─────────────────────────────────────────────────────────────────────────────

/// A heap allocation tracked by the `MSan` model.
#[derive(Debug, Clone)]
pub struct AllocRecord {
    pub base: u64,
    pub size: usize,
    pub init: bool,
    pub source: UninitSource,
    pub alloc_pc: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// MsanModel
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level `MSan`-style uninitialized-memory detection model.
///
/// Tracks allocations, initialisation state, and taint propagation.
/// Detects reads from uninitialised memory.
pub struct MsanModel {
    /// Shadow memory.
    pub shadow: ShadowMap,
    /// Known heap allocations.
    pub allocations: HashMap<u64, AllocRecord>,
    /// Known uninitialised regions.
    pub uninit_regions: Vec<UninitRegion>,
    /// Violation reports.
    pub reports: Vec<MsanReport>,
    /// Propagation engine.
    pub propagation: UninitPropagation,
    /// Whether to generate detailed reports.
    pub verbose: bool,
}

impl MsanModel {
    /// Create a new model.
    #[must_use]
    pub fn new() -> Self {
        Self {
            shadow: ShadowMap::new(),
            allocations: HashMap::new(),
            uninit_regions: Vec::new(),
            reports: Vec::new(),
            propagation: UninitPropagation::new(),
            verbose: false,
        }
    }

    /// Track a new heap allocation (initially uninitialised).
    pub fn alloc(&mut self, base: u64, size: usize, alloc_pc: u64) {
        let source = UninitSource::HeapAlloc { addr: base };
        self.shadow.mark_uninit(base, size);
        self.allocations.insert(
            base,
            AllocRecord {
                base,
                size,
                init: false,
                source: source.clone(),
                alloc_pc,
            },
        );
        self.uninit_regions
            .push(UninitRegion::new(base, size, source, alloc_pc));
    }

    /// Track a stack frame allocation (initially uninitialised).
    pub fn stack_alloc(&mut self, base: u64, size: usize, alloc_pc: u64, frame: impl Into<String>) {
        let frame = frame.into();
        let source = UninitSource::StackAlloc { sp: base, frame };
        self.shadow.mark_uninit(base, size);
        self.uninit_regions
            .push(UninitRegion::new(base, size, source, alloc_pc));
    }

    /// Initialise `size` bytes at `addr` (e.g. after a write).
    pub fn init_bytes(&mut self, addr: u64, size: usize) {
        self.shadow.mark_init(addr, size);
        // Remove overlapping uninit regions.
        self.uninit_regions.retain(|r| !r.overlaps(addr, size));
    }

    /// Check a read access.  Generates a report on violation.
    ///
    /// Returns `Ok(())` if all bytes are initialised.
    ///
    /// # Errors
    /// Returns [`MsanError::UninitRead`] on violation.
    pub fn check_read(&mut self, addr: u64, size: usize, pc: u64) -> Result<(), MsanError> {
        match self.shadow.check_access(addr, size) {
            Ok(()) => Ok(()),
            Err(e) => {
                let region = self
                    .uninit_regions
                    .iter()
                    .find(|r| r.overlaps(addr, size))
                    .cloned();
                let labels = self.shadow.taint_labels_for(addr, size);
                let mut report = MsanReport::new(addr, size, pc);
                report.region = region;
                report.taint_labels = labels;
                self.reports.push(report);
                Err(e)
            }
        }
    }

    /// Simulate a copy: init/uninit state of `src` is propagated to `dst`.
    pub fn copy(&mut self, src: u64, dst: u64, size: usize) {
        if self.shadow.is_init(src, size) {
            self.shadow.mark_init(dst, size);
        } else {
            self.shadow.mark_uninit(dst, size);
        }
    }

    /// Record a taint propagation event.
    pub fn propagate(&mut self, pc: u64, opcode: &str, src_addrs: &[u64], dst_addr: u64) {
        let src_tainted: Vec<(u64, bool)> = src_addrs
            .iter()
            .map(|&a| (a, !self.shadow.is_init(a, 1)))
            .collect();
        let tainted = self.propagation.evaluate(opcode, &src_tainted);
        self.propagation
            .record(pc, opcode, src_addrs.to_vec(), dst_addr, tainted);
        if tainted {
            self.shadow.mark_uninit(dst_addr, 1);
        } else {
            self.shadow.mark_init(dst_addr, 1);
        }
    }

    /// Number of violations detected.
    #[must_use]
    pub const fn violation_count(&self) -> usize {
        self.reports.len()
    }

    /// Latest report.
    #[must_use]
    pub fn latest_report(&self) -> Option<&MsanReport> {
        self.reports.last()
    }

    /// Reports involving branch instructions (most dangerous).
    #[must_use]
    pub fn branch_violations(&self) -> Vec<&MsanReport> {
        self.reports.iter().filter(|r| r.is_branch).collect()
    }

    /// Reset model (clear shadow, allocations, reports).
    pub fn reset(&mut self) {
        self.shadow.reset();
        self.allocations.clear();
        self.uninit_regions.clear();
        self.reports.clear();
    }
}

impl Default for MsanModel {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── UninitSource ──────────────────────────────────────────────────────────

    #[test]
    fn uninit_source_display() {
        let s = UninitSource::HeapAlloc { addr: 0x1000 };
        assert!(s.to_string().contains("heap"));
        let s2 = UninitSource::ExternalCall {
            function: "memset".into(),
        };
        assert!(s2.to_string().contains("memset"));
    }

    // ── UninitByte ────────────────────────────────────────────────────────────

    #[test]
    fn uninit_byte_new() {
        let b = UninitByte::new(0x1000, UninitSource::Unknown, 0x0040_0560);
        assert_eq!(b.addr, 0x1000);
        assert_eq!(b.taint_label, 0);
    }

    #[test]
    fn uninit_byte_with_taint() {
        let b = UninitByte::new(0x1000, UninitSource::Unknown, 0).with_taint(42);
        assert_eq!(b.taint_label, 42);
    }

    // ── UninitRegion ──────────────────────────────────────────────────────────

    #[test]
    fn uninit_region_contains() {
        let r = UninitRegion::new(0x1000, 16, UninitSource::Unknown, 0);
        assert!(r.contains(0x1000));
        assert!(r.contains(0x100F));
        assert!(!r.contains(0x1010));
    }

    #[test]
    fn uninit_region_overlaps() {
        let r = UninitRegion::new(0x1000, 16, UninitSource::Unknown, 0);
        assert!(r.overlaps(0x100C, 8)); // overlaps the last 4 bytes
        assert!(!r.overlaps(0x1010, 4)); // after the region
        assert!(!r.overlaps(0x0FF0, 4)); // before
    }

    // ── PropagationRule ───────────────────────────────────────────────────────

    #[test]
    fn propagation_rule_display() {
        assert_eq!(
            PropagationRule::AnyTaintsResult.to_string(),
            "any-taints-result"
        );
        assert_eq!(PropagationRule::Never.to_string(), "never");
    }

    // ── UninitPropagation ─────────────────────────────────────────────────────

    #[test]
    fn propagation_any_rule_tainted_if_any_src() {
        let p = UninitPropagation::new();
        let src = vec![(0x1000, true), (0x1001, false)];
        assert!(p.evaluate("add", &src));
    }

    #[test]
    fn propagation_any_rule_clean_if_all_clean() {
        let p = UninitPropagation::new();
        let src = vec![(0x1000, false), (0x1001, false)];
        assert!(!p.evaluate("add", &src));
    }

    #[test]
    fn propagation_unconditional_always_tainted() {
        let mut p = UninitPropagation::new();
        p.add_rule("mov", PropagationRule::Unconditional);
        let src = vec![(0x1000, false)];
        assert!(p.evaluate("mov", &src));
    }

    #[test]
    fn propagation_never_never_tainted() {
        let mut p = UninitPropagation::new();
        p.add_rule("and_zero", PropagationRule::Never);
        let src = vec![(0x1000, true)];
        assert!(!p.evaluate("and_zero", &src));
    }

    #[test]
    fn propagation_all_rule() {
        let mut p = UninitPropagation::new();
        p.add_rule("mul", PropagationRule::AllTaintResult);
        // Only one tainted → not all → not tainted
        assert!(!p.evaluate("mul", &[(0x1000, true), (0x1001, false)]));
        // All tainted → tainted
        assert!(p.evaluate("mul", &[(0x1000, true), (0x1001, true)]));
    }

    #[test]
    fn propagation_record_and_count() {
        let mut p = UninitPropagation::new();
        p.record(0x400, "add", vec![0x1000, 0x1001], 0x2000, true);
        p.record(0x404, "add", vec![0x1002], 0x2001, false);
        assert_eq!(p.tainted_event_count(), 1);
    }

    #[test]
    fn propagation_tainted_destinations() {
        let mut p = UninitPropagation::new();
        p.record(0x400, "add", vec![], 0xAAAA, true);
        p.record(0x404, "add", vec![], 0xBBBB, true);
        let dests = p.tainted_destinations();
        assert_eq!(dests.len(), 2);
    }

    // ── ShadowMap ─────────────────────────────────────────────────────────────

    #[test]
    fn shadow_initially_uninit() {
        let sm = ShadowMap::new();
        assert!(!sm.is_init(0x1000, 4));
    }

    #[test]
    fn shadow_mark_init() {
        let mut sm = ShadowMap::new();
        sm.mark_init(0x1000, 8);
        assert!(sm.is_init(0x1000, 8));
    }

    #[test]
    fn shadow_partial_init() {
        let mut sm = ShadowMap::new();
        sm.mark_init(0x1000, 4);
        assert!(!sm.is_init(0x1000, 8)); // last 4 bytes uninit
    }

    #[test]
    fn shadow_mark_uninit_after_init() {
        let mut sm = ShadowMap::new();
        sm.mark_init(0x1000, 8);
        sm.mark_uninit(0x1004, 4);
        assert!(sm.is_init(0x1000, 4));
        assert!(!sm.is_init(0x1004, 4));
    }

    #[test]
    fn shadow_check_access_ok() {
        let mut sm = ShadowMap::new();
        sm.mark_init(0x1000, 4);
        assert!(sm.check_access(0x1000, 4).is_ok());
    }

    #[test]
    fn shadow_check_access_uninit() {
        let mut sm = ShadowMap::new();
        let result = sm.check_access(0x1000, 4);
        assert!(result.is_err());
        assert_eq!(sm.total_uninit_reads, 1);
    }

    #[test]
    fn shadow_taint_label() {
        let mut sm = ShadowMap::new();
        sm.set_taint(0x1000, 7);
        assert_eq!(sm.taint_label(0x1000), 7);
        assert_eq!(sm.taint_label(0x2000), 0); // unknown → 0
    }

    #[test]
    fn shadow_taint_labels_for() {
        let mut sm = ShadowMap::new();
        sm.set_taint(0x1000, 1);
        sm.set_taint(0x1001, 2);
        let labels = sm.taint_labels_for(0x1000, 2);
        assert_eq!(labels.len(), 2);
    }

    #[test]
    fn shadow_reset() {
        let mut sm = ShadowMap::new();
        sm.mark_init(0x1000, 8);
        sm.reset();
        assert!(!sm.is_init(0x1000, 8));
        assert_eq!(sm.total_tracked, 0);
    }

    #[test]
    fn shadow_init_byte_count() {
        let mut sm = ShadowMap::new();
        sm.mark_init(0x1000, 4);
        assert_eq!(sm.init_byte_count(), 4);
    }

    #[test]
    fn shadow_cross_page_boundary() {
        let mut sm = ShadowMap::new();
        sm.mark_init(250, 10); // crosses 256-byte page boundary
        assert!(sm.is_init(250, 10));
    }

    // ── MsanReport ────────────────────────────────────────────────────────────

    #[test]
    fn msan_report_new() {
        let r = MsanReport::new(0x1000, 4, 0x0040_0560);
        assert_eq!(r.access_addr, 0x1000);
        assert_eq!(r.access_size, 4);
        assert!(!r.is_branch);
        assert!(r.summary.contains("uninit"));
    }

    // ── MsanModel ─────────────────────────────────────────────────────────────

    #[test]
    fn msan_alloc_marks_uninit() {
        let mut m = MsanModel::new();
        m.alloc(0x1000, 64, 0x4000);
        assert!(!m.shadow.is_init(0x1000, 64));
    }

    #[test]
    fn msan_init_bytes_clears_uninit() {
        let mut m = MsanModel::new();
        m.alloc(0x1000, 64, 0x4000);
        m.init_bytes(0x1000, 64);
        assert!(m.shadow.is_init(0x1000, 64));
    }

    #[test]
    fn msan_check_read_uninit_generates_report() {
        let mut m = MsanModel::new();
        m.alloc(0x1000, 8, 0x4000);
        let result = m.check_read(0x1000, 4, 0x4010);
        assert!(result.is_err());
        assert_eq!(m.violation_count(), 1);
    }

    #[test]
    fn msan_check_read_init_ok() {
        let mut m = MsanModel::new();
        m.alloc(0x1000, 8, 0x4000);
        m.init_bytes(0x1000, 8);
        assert!(m.check_read(0x1000, 8, 0x4010).is_ok());
    }

    #[test]
    fn msan_copy_propagates_uninit() {
        let mut m = MsanModel::new();
        m.alloc(0x1000, 4, 0x4000);
        m.copy(0x1000, 0x2000, 4);
        assert!(!m.shadow.is_init(0x2000, 4));
    }

    #[test]
    fn msan_copy_propagates_init() {
        let mut m = MsanModel::new();
        m.alloc(0x1000, 4, 0x4000);
        m.init_bytes(0x1000, 4);
        m.copy(0x1000, 0x2000, 4);
        assert!(m.shadow.is_init(0x2000, 4));
    }

    #[test]
    fn msan_propagate_taint() {
        let mut m = MsanModel::new();
        m.alloc(0x1000, 4, 0x4000); // uninit
        m.propagate(0x4020, "add", &[0x1000], 0x3000);
        // src is uninit → dst becomes uninit
        assert!(!m.shadow.is_init(0x3000, 1));
    }

    #[test]
    fn msan_stack_alloc() {
        let mut m = MsanModel::new();
        m.stack_alloc(0x7FFF_0000, 128, 0x4000, "main");
        assert!(!m.shadow.is_init(0x7FFF_0000, 128));
    }

    #[test]
    fn msan_reset() {
        let mut m = MsanModel::new();
        m.alloc(0x1000, 8, 0x4000);
        m.check_read(0x1000, 4, 0x4010).ok();
        m.reset();
        assert_eq!(m.violation_count(), 0);
        assert!(m.allocations.is_empty());
    }

    #[test]
    fn msan_latest_report() {
        let mut m = MsanModel::new();
        m.alloc(0x1000, 4, 0x4000);
        m.check_read(0x1000, 4, 0x4010).ok();
        assert!(m.latest_report().is_some());
    }
}
