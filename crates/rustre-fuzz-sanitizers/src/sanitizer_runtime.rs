//! Sanitizer runtime model for `rustre-fuzz-sanitizers`.
//!
//! Pure-Rust simulation of sanitizer behaviour used during fuzz testing:
//! - [`MemoryModel`]: tracks allocated/freed/accessible regions.
//! - [`AliasAnalysis`]: simple may-alias tracking.
//! - [`StrictAsan`]: validates every memory access against the memory model.
//! - [`StackProtector`]: canary-based stack overflow detection.
//! - [`SafeStack`]: shadow stack tracking.
//! - [`FortifySource`]: detects buffer overflows in string/memory functions.
//! - [`SanitizerReport`]: collects all findings.
//! - [`SanitizerRuntime`]: orchestrates all sanitizer components.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SanitizerKind
// ---------------------------------------------------------------------------

/// The type of sanitizer that produced a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SanitizerKind {
    Asan,
    Msan,
    Ubsan,
    Tsan,
    Lsan,
    StackProtector,
    SafeStack,
    FortifySource,
}

impl fmt::Display for SanitizerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Asan => "ASan",
            Self::Msan => "MSan",
            Self::Ubsan => "UBSan",
            Self::Tsan => "TSan",
            Self::Lsan => "LSan",
            Self::StackProtector => "StackProtector",
            Self::SafeStack => "SafeStack",
            Self::FortifySource => "FortifySource",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// SanitizerFinding
// ---------------------------------------------------------------------------

/// Severity of a sanitizer finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
    Fatal,
}

impl fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Info => "INFO",
            Self::Warning => "WARNING",
            Self::Error => "ERROR",
            Self::Fatal => "FATAL",
        };
        write!(f, "{s}")
    }
}

/// A single sanitizer finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizerFinding {
    pub kind: SanitizerKind,
    pub severity: FindingSeverity,
    pub address: u64,
    pub description: String,
    pub backtrace: Vec<u64>,
}

impl SanitizerFinding {
    #[must_use]
    pub fn new(
        kind: SanitizerKind,
        severity: FindingSeverity,
        address: u64,
        description: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            severity,
            address,
            description: description.into(),
            backtrace: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_backtrace(mut self, bt: Vec<u64>) -> Self {
        self.backtrace = bt;
        self
    }
}

impl fmt::Display for SanitizerFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} @ {:#018x}: {}",
            self.severity, self.kind, self.address, self.description
        )
    }
}

// ---------------------------------------------------------------------------
// MemoryModel
// ---------------------------------------------------------------------------

/// State of a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegionState {
    /// Allocated and accessible.
    Allocated,
    /// Freed (dangling pointer territory).
    Freed,
    /// Stack memory (may overlap with heap).
    Stack,
    /// Global/static memory.
    Global,
}

/// A tracked memory region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRegion {
    pub base: u64,
    pub size: usize,
    pub state: RegionState,
    /// Allocation site (caller address).
    pub alloc_site: Option<u64>,
    /// Free site (caller address).
    pub free_site: Option<u64>,
}

impl MemoryRegion {
    /// End address (exclusive).
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.base.saturating_add(self.size as u64)
    }

    /// Returns `true` if `addr` falls within this region.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }

    /// Returns `true` if the region is currently accessible.
    #[must_use]
    pub const fn is_accessible(&self) -> bool {
        matches!(
            self.state,
            RegionState::Allocated | RegionState::Stack | RegionState::Global
        )
    }
}

/// Tracks the live memory model.
#[derive(Debug, Default)]
pub struct MemoryModel {
    regions: Vec<MemoryRegion>,
    next_id: u64,
}

impl MemoryModel {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a heap allocation.
    pub fn allocate(&mut self, base: u64, size: usize, caller: Option<u64>) {
        self.regions.push(MemoryRegion {
            base,
            size,
            state: RegionState::Allocated,
            alloc_site: caller,
            free_site: None,
        });
        self.next_id += 1;
    }

    /// Mark a heap allocation as freed.
    pub fn free(&mut self, base: u64, caller: Option<u64>) {
        for region in &mut self.regions {
            if region.base == base && region.state == RegionState::Allocated {
                region.state = RegionState::Freed;
                region.free_site = caller;
                return;
            }
        }
    }

    /// Add a stack region.
    pub fn add_stack(&mut self, base: u64, size: usize) {
        self.regions.push(MemoryRegion {
            base,
            size,
            state: RegionState::Stack,
            alloc_site: None,
            free_site: None,
        });
    }

    /// Add a global region.
    pub fn add_global(&mut self, base: u64, size: usize) {
        self.regions.push(MemoryRegion {
            base,
            size,
            state: RegionState::Global,
            alloc_site: None,
            free_site: None,
        });
    }

    /// Find the region containing `addr`.
    #[must_use]
    pub fn find(&self, addr: u64) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| r.contains(addr))
    }

    /// Check whether `addr` is accessible.
    #[must_use]
    pub fn is_accessible(&self, addr: u64) -> bool {
        self.find(addr).is_some_and(MemoryRegion::is_accessible)
    }

    /// Check whether `addr` is a use-after-free.
    #[must_use]
    pub fn is_use_after_free(&self, addr: u64) -> bool {
        self.regions
            .iter()
            .any(|r| r.contains(addr) && r.state == RegionState::Freed)
    }

    /// Number of live allocations.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.regions
            .iter()
            .filter(|r| r.state == RegionState::Allocated)
            .count()
    }

    /// Leaked allocations (allocated but not freed).
    #[must_use]
    pub fn leaks(&self) -> Vec<&MemoryRegion> {
        self.regions
            .iter()
            .filter(|r| r.state == RegionState::Allocated)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// AliasAnalysis
// ---------------------------------------------------------------------------

/// May-alias set for a pointer.
#[derive(Debug, Clone, Default)]
pub struct AliasSet {
    pub pointers: Vec<u64>,
}

impl AliasSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, ptr: u64) {
        if !self.pointers.contains(&ptr) {
            self.pointers.push(ptr);
        }
    }

    /// Returns `true` if `ptr` may alias another pointer in this set.
    #[must_use]
    pub fn may_alias(&self, ptr: u64) -> bool {
        self.pointers.contains(&ptr)
    }

    /// Number of pointers in this alias set.
    #[must_use]
    pub const fn alias_count(&self) -> usize {
        self.pointers.len()
    }
}

/// Simple may-alias tracker.
#[derive(Debug, Default)]
pub struct AliasAnalysis {
    /// Maps canonical address → alias set.
    sets: HashMap<u64, AliasSet>,
}

impl AliasAnalysis {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `ptr_a` and `ptr_b` may alias (point to overlapping memory).
    pub fn record_alias(&mut self, ptr_a: u64, ptr_b: u64) {
        // Aliasing is an equivalence relation: if `a` aliases `b` and `b`
        // aliases `c`, then `a` may alias `c`. Keying a set by `min(a, b)`
        // alone does not merge those two records — `record_alias(10, 20)` and
        // `record_alias(20, 30)` would leave 20 sitting in two different sets
        // at once. That contradicts `alias_set_for`, which promises to return
        // *the* set containing a pointer, and made its answer depend on
        // `HashMap` iteration order (unspecified, and re-seeded every process).
        // Merging every set that already holds either pointer keeps the sets
        // disjoint, so each pointer has exactly one set and the lookup is both
        // complete and reproducible.
        let touched: Vec<u64> = self
            .sets
            .iter()
            .filter(|(_, s)| s.may_alias(ptr_a) || s.may_alias(ptr_b))
            .map(|(&k, _)| k)
            .collect();

        let mut merged: Vec<u64> = vec![ptr_a, ptr_b];
        for k in touched {
            if let Some(s) = self.sets.remove(&k) {
                merged.extend(s.pointers);
            }
        }
        merged.sort_unstable();
        merged.dedup();

        // The smallest pointer in the class is a stable, unique key.
        let key = merged[0];
        let mut set = AliasSet::new();
        for p in merged {
            set.add(p);
        }
        self.sets.insert(key, set);
    }

    /// Check if `ptr` is in any alias set.
    #[must_use]
    pub fn has_aliases(&self, ptr: u64) -> bool {
        self.sets.values().any(|s| s.may_alias(ptr))
    }

    /// Return the alias set containing `ptr`, if any.
    #[must_use]
    pub fn alias_set_for(&self, ptr: u64) -> Option<&AliasSet> {
        self.sets.values().find(|s| s.may_alias(ptr))
    }
}

// ---------------------------------------------------------------------------
// StrictAsan
// ---------------------------------------------------------------------------

/// Validates every memory access against the [`MemoryModel`].
#[derive(Debug, Default)]
pub struct StrictAsan {
    pub findings: Vec<SanitizerFinding>,
}

impl StrictAsan {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate a read access to `addr`.
    pub fn check_read(&mut self, model: &MemoryModel, addr: u64, size: usize) {
        self.check_access(model, addr, size, "read");
    }

    /// Validate a write access to `addr`.
    pub fn check_write(&mut self, model: &MemoryModel, addr: u64, size: usize) {
        self.check_access(model, addr, size, "write");
    }

    fn check_access(&mut self, model: &MemoryModel, addr: u64, size: usize, op: &str) {
        if model.is_use_after_free(addr) {
            self.findings.push(SanitizerFinding::new(
                SanitizerKind::Asan,
                FindingSeverity::Fatal,
                addr,
                format!("heap-use-after-free on {op} of size {size}"),
            ));
        } else if !model.is_accessible(addr) {
            self.findings.push(SanitizerFinding::new(
                SanitizerKind::Asan,
                FindingSeverity::Error,
                addr,
                format!("heap-buffer-overflow on {op} of size {size}"),
            ));
        }
        // Check end of access.
        let end = addr.saturating_add(size as u64);
        if size > 1 && !model.is_accessible(end - 1) {
            self.findings.push(SanitizerFinding::new(
                SanitizerKind::Asan,
                FindingSeverity::Error,
                end - 1,
                format!("heap-buffer-overflow (end) on {op}"),
            ));
        }
    }

    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity >= FindingSeverity::Error)
    }
}

// ---------------------------------------------------------------------------
// StackProtector
// ---------------------------------------------------------------------------

/// Stack canary state.
#[derive(Debug, Clone)]
pub struct StackCanary {
    pub frame_id: u64,
    pub canary_addr: u64,
    pub canary_value: u64,
}

/// Monitors stack canaries for corruption.
#[derive(Debug, Default)]
pub struct StackProtector {
    canaries: Vec<StackCanary>,
    pub findings: Vec<SanitizerFinding>,
    next_frame: u64,
}

impl StackProtector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Place a canary at `canary_addr` for a new stack frame.
    pub fn enter_frame(&mut self, canary_addr: u64, canary_value: u64) -> u64 {
        let frame_id = self.next_frame;
        self.next_frame += 1;
        self.canaries.push(StackCanary {
            frame_id,
            canary_addr,
            canary_value,
        });
        frame_id
    }

    /// Validate the canary for the given frame.
    pub fn exit_frame(&mut self, frame_id: u64, actual_value: u64) {
        if let Some(pos) = self.canaries.iter().position(|c| c.frame_id == frame_id) {
            let canary = self.canaries.remove(pos);
            if canary.canary_value != actual_value {
                self.findings.push(SanitizerFinding::new(
                    SanitizerKind::StackProtector,
                    FindingSeverity::Fatal,
                    canary.canary_addr,
                    format!("stack-smashing detected (frame {frame_id}): expected 0x{:016x}, got 0x{actual_value:016x}", canary.canary_value),
                ));
            }
        }
    }

    /// Number of frames currently being protected.
    #[must_use]
    pub const fn active_frames(&self) -> usize {
        self.canaries.len()
    }
}

// ---------------------------------------------------------------------------
// SafeStack
// ---------------------------------------------------------------------------

/// Models an unsafe-stack entry.
#[derive(Debug, Clone)]
pub struct SafeStackEntry {
    pub return_addr: u64,
    pub frame_size: usize,
}

/// Tracks a shadow stack for return-address protection.
#[derive(Debug, Default)]
pub struct SafeStack {
    stack: Vec<SafeStackEntry>,
    pub findings: Vec<SanitizerFinding>,
}

impl SafeStack {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a return address onto the shadow stack.
    pub fn push(&mut self, return_addr: u64, frame_size: usize) {
        self.stack.push(SafeStackEntry {
            return_addr,
            frame_size,
        });
    }

    /// Pop and validate the return address.
    pub fn pop(&mut self, actual_return: u64) {
        if let Some(entry) = self.stack.pop()
            && entry.return_addr != actual_return
        {
            self.findings.push(SanitizerFinding::new(
                SanitizerKind::SafeStack,
                FindingSeverity::Fatal,
                actual_return,
                format!(
                    "return-address mismatch: expected {:#018x}",
                    entry.return_addr
                ),
            ));
        }
    }

    /// Current shadow-stack depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.stack.len()
    }
}

// ---------------------------------------------------------------------------
// FortifySource
// ---------------------------------------------------------------------------

/// Detects buffer overflows in string/memory function calls.
#[derive(Debug, Default)]
pub struct FortifySource {
    pub findings: Vec<SanitizerFinding>,
}

impl FortifySource {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Simulate a `memcpy(dst, src, n)` call and check for overflow.
    pub fn check_memcpy(&mut self, model: &MemoryModel, dst: u64, src: u64, n: usize) {
        let _ = src;
        if !model.is_accessible(dst) || !model.is_accessible(dst + n as u64 - 1) {
            self.findings.push(SanitizerFinding::new(
                SanitizerKind::FortifySource,
                FindingSeverity::Error,
                dst,
                format!("memcpy: destination overflow (dst={dst:#x}, n={n})"),
            ));
        }
    }

    /// Simulate a `strcpy` and check null termination within `max_size`.
    pub fn check_strcpy(&mut self, model: &MemoryModel, dst: u64, src_len: usize, dst_size: usize) {
        if src_len + 1 > dst_size {
            self.findings.push(SanitizerFinding::new(
                SanitizerKind::FortifySource,
                FindingSeverity::Error,
                dst,
                format!("strcpy: source length {src_len} exceeds destination size {dst_size}"),
            ));
        }
        let _ = model;
    }

    /// Simulate `sprintf` with a format string length check.
    pub fn check_sprintf(&mut self, dst: u64, dst_size: usize, formatted_len: usize) {
        if formatted_len >= dst_size {
            self.findings.push(SanitizerFinding::new(
                SanitizerKind::FortifySource,
                FindingSeverity::Error,
                dst,
                format!("sprintf: formatted length {formatted_len} >= buffer size {dst_size}"),
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// SanitizerReport
// ---------------------------------------------------------------------------

/// Aggregated sanitizer findings.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SanitizerReport {
    pub findings: Vec<SanitizerFinding>,
}

impl SanitizerReport {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, finding: SanitizerFinding) {
        self.findings.push(finding);
    }

    pub fn extend(&mut self, findings: &[SanitizerFinding]) {
        self.findings.extend_from_slice(findings);
    }

    /// Total number of findings.
    #[must_use]
    pub const fn total(&self) -> usize {
        self.findings.len()
    }

    #[must_use]
    pub fn by_kind(&self, kind: SanitizerKind) -> Vec<&SanitizerFinding> {
        self.findings.iter().filter(|f| f.kind == kind).collect()
    }

    #[must_use]
    pub fn fatal_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == FindingSeverity::Fatal)
            .count()
    }

    #[must_use]
    pub fn has_fatals(&self) -> bool {
        self.fatal_count() > 0
    }

    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "SanitizerReport: {} findings ({} fatal, {} error)",
            self.total(),
            self.fatal_count(),
            self.findings
                .iter()
                .filter(|f| f.severity == FindingSeverity::Error)
                .count(),
        )
    }
}

impl fmt::Display for SanitizerReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ---------------------------------------------------------------------------
// SanitizerRuntime
// ---------------------------------------------------------------------------

/// Orchestrates all sanitizer components.
pub struct SanitizerRuntime {
    pub memory: MemoryModel,
    pub alias: AliasAnalysis,
    pub asan: StrictAsan,
    pub stack_protector: StackProtector,
    pub safe_stack: SafeStack,
    pub fortify: FortifySource,
}

impl SanitizerRuntime {
    #[must_use]
    pub fn new() -> Self {
        Self {
            memory: MemoryModel::new(),
            alias: AliasAnalysis::new(),
            asan: StrictAsan::new(),
            stack_protector: StackProtector::new(),
            safe_stack: SafeStack::new(),
            fortify: FortifySource::new(),
        }
    }

    /// Aggregate all findings into a [`SanitizerReport`].
    #[must_use]
    pub fn report(&self) -> SanitizerReport {
        let mut report = SanitizerReport::new();
        report.extend(&self.asan.findings);
        report.extend(&self.stack_protector.findings);
        report.extend(&self.safe_stack.findings);
        report.extend(&self.fortify.findings);
        // Leak detection.
        for leak in self.memory.leaks() {
            report.add(SanitizerFinding::new(
                SanitizerKind::Lsan,
                FindingSeverity::Warning,
                leak.base,
                format!("memory leak: {} bytes at {:#x}", leak.size, leak.base),
            ));
        }
        report
    }

    /// Returns `true` if any fatal finding has been recorded.
    #[must_use]
    pub fn has_fatal(&self) -> bool {
        self.report().has_fatals()
    }
}

impl Default for SanitizerRuntime {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── MemoryModel ────────────────────────────────────────────────────────

    #[test]
    fn memory_model_allocate_and_accessible() {
        let mut m = MemoryModel::new();
        m.allocate(0x1000, 64, None);
        assert!(m.is_accessible(0x1000));
        assert!(m.is_accessible(0x103F));
        assert!(!m.is_accessible(0x1040));
    }

    #[test]
    fn memory_model_free_makes_uaf() {
        let mut m = MemoryModel::new();
        m.allocate(0x1000, 64, None);
        m.free(0x1000, None);
        assert!(m.is_use_after_free(0x1000));
        assert!(!m.is_accessible(0x1000));
    }

    #[test]
    fn memory_model_live_count() {
        let mut m = MemoryModel::new();
        m.allocate(0x1000, 32, None);
        m.allocate(0x2000, 32, None);
        assert_eq!(m.live_count(), 2);
        m.free(0x1000, None);
        assert_eq!(m.live_count(), 1);
    }

    #[test]
    fn memory_model_leaks() {
        let mut m = MemoryModel::new();
        m.allocate(0x1000, 16, None);
        let leaks = m.leaks();
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].base, 0x1000);
    }

    #[test]
    fn memory_model_stack_accessible() {
        let mut m = MemoryModel::new();
        m.add_stack(0x7FFF_0000, 4096);
        assert!(m.is_accessible(0x7FFF_0000));
        assert!(m.is_accessible(0x7FFF_0FFF));
    }

    // ── AliasAnalysis ──────────────────────────────────────────────────────

    #[test]
    fn alias_analysis_record_and_check() {
        let mut aa = AliasAnalysis::new();
        aa.record_alias(0x1000, 0x1010);
        assert!(aa.has_aliases(0x1000));
        assert!(aa.has_aliases(0x1010));
        assert!(!aa.has_aliases(0x9999));
    }

    #[test]
    fn alias_analysis_alias_set_for() {
        let mut aa = AliasAnalysis::new();
        aa.record_alias(0x1000, 0x1000); // self-alias
        let set = aa.alias_set_for(0x1000);
        assert!(set.is_some());
    }

    // ── StrictAsan ────────────────────────────────────────────────────────

    #[test]
    fn asan_valid_access_no_finding() {
        let mut m = MemoryModel::new();
        m.allocate(0x1000, 64, None);
        let mut asan = StrictAsan::new();
        asan.check_read(&m, 0x1000, 4);
        assert!(!asan.has_errors());
    }

    #[test]
    fn asan_heap_overflow_detected() {
        let mut m = MemoryModel::new();
        m.allocate(0x1000, 4, None);
        let mut asan = StrictAsan::new();
        asan.check_read(&m, 0x1010, 4); // beyond allocation
        assert!(asan.has_errors());
    }

    #[test]
    fn asan_use_after_free_detected() {
        let mut m = MemoryModel::new();
        m.allocate(0x1000, 64, None);
        m.free(0x1000, None);
        let mut asan = StrictAsan::new();
        asan.check_write(&m, 0x1000, 4);
        assert!(
            asan.findings
                .iter()
                .any(|f| f.description.contains("use-after-free"))
        );
    }

    // ── StackProtector ────────────────────────────────────────────────────

    #[test]
    fn stack_protector_no_corruption() {
        let mut sp = StackProtector::new();
        let id = sp.enter_frame(0x7FFF_0000, 0xDEAD_BEEF_CAFE_BABE);
        sp.exit_frame(id, 0xDEAD_BEEF_CAFE_BABE);
        assert!(sp.findings.is_empty());
    }

    #[test]
    fn stack_protector_corruption_detected() {
        let mut sp = StackProtector::new();
        let id = sp.enter_frame(0x7FFF_0000, 0xDEAD_BEEF_CAFE_BABE);
        sp.exit_frame(id, 0x0000_0000_0000_0000); // wrong value
        assert!(!sp.findings.is_empty());
        assert_eq!(sp.findings[0].severity, FindingSeverity::Fatal);
    }

    #[test]
    fn stack_protector_active_frames() {
        let mut sp = StackProtector::new();
        sp.enter_frame(0, 0);
        sp.enter_frame(1, 0);
        assert_eq!(sp.active_frames(), 2);
    }

    // ── SafeStack ─────────────────────────────────────────────────────────

    #[test]
    fn safe_stack_valid_return() {
        let mut ss = SafeStack::new();
        ss.push(0x0040_1000, 64);
        ss.pop(0x0040_1000);
        assert!(ss.findings.is_empty());
    }

    #[test]
    fn safe_stack_hijacked_return() {
        let mut ss = SafeStack::new();
        ss.push(0x0040_1000, 64);
        ss.pop(0xDEAD_BEEF); // wrong return address
        assert!(!ss.findings.is_empty());
    }

    #[test]
    fn safe_stack_depth() {
        let mut ss = SafeStack::new();
        ss.push(0, 0);
        ss.push(0, 0);
        assert_eq!(ss.depth(), 2);
    }

    // ── FortifySource ─────────────────────────────────────────────────────

    #[test]
    fn fortify_memcpy_ok() {
        let mut m = MemoryModel::new();
        m.allocate(0x2000, 64, None);
        let mut fs = FortifySource::new();
        fs.check_memcpy(&m, 0x2000, 0x1000, 64);
        assert!(fs.findings.is_empty());
    }

    #[test]
    fn fortify_memcpy_overflow() {
        let mut m = MemoryModel::new();
        m.allocate(0x2000, 4, None);
        let mut fs = FortifySource::new();
        fs.check_memcpy(&m, 0x2000, 0x1000, 100); // 100 > 4
        assert!(!fs.findings.is_empty());
    }

    #[test]
    fn fortify_strcpy_overflow() {
        let m = MemoryModel::new();
        let mut fs = FortifySource::new();
        fs.check_strcpy(&m, 0x3000, 128, 64);
        assert!(!fs.findings.is_empty());
    }

    #[test]
    fn fortify_sprintf_overflow() {
        let mut fs = FortifySource::new();
        fs.check_sprintf(0x4000, 32, 50);
        assert!(!fs.findings.is_empty());
    }

    // ── SanitizerReport ───────────────────────────────────────────────────

    #[test]
    fn report_empty() {
        let r = SanitizerReport::new();
        assert_eq!(r.total(), 0);
        assert!(!r.has_fatals());
    }

    #[test]
    fn report_add_finding() {
        let mut r = SanitizerReport::new();
        r.add(SanitizerFinding::new(
            SanitizerKind::Asan,
            FindingSeverity::Fatal,
            0,
            "boom",
        ));
        assert_eq!(r.total(), 1);
        assert!(r.has_fatals());
    }

    #[test]
    fn report_by_kind() {
        let mut r = SanitizerReport::new();
        r.add(SanitizerFinding::new(
            SanitizerKind::Asan,
            FindingSeverity::Error,
            0,
            "heap-overflow",
        ));
        r.add(SanitizerFinding::new(
            SanitizerKind::Lsan,
            FindingSeverity::Warning,
            0,
            "leak",
        ));
        assert_eq!(r.by_kind(SanitizerKind::Asan).len(), 1);
    }

    #[test]
    fn report_display() {
        let r = SanitizerReport::new();
        let s = r.to_string();
        assert!(s.contains("SanitizerReport"));
    }

    // ── SanitizerRuntime ──────────────────────────────────────────────────

    #[test]
    fn runtime_no_findings_clean() {
        let mut rt = SanitizerRuntime::new();
        rt.memory.allocate(0x1000, 64, None);
        rt.memory.free(0x1000, None);
        let report = rt.report();
        // No leaks (freed), but UAF checks need explicit access calls.
        assert_eq!(report.by_kind(SanitizerKind::Lsan).len(), 0);
    }

    #[test]
    fn runtime_leak_detected() {
        let mut rt = SanitizerRuntime::new();
        rt.memory.allocate(0x1000, 64, None); // never freed
        let report = rt.report();
        assert_eq!(report.by_kind(SanitizerKind::Lsan).len(), 1);
    }

    #[test]
    fn runtime_asan_fatal() {
        let mut rt = SanitizerRuntime::new();
        rt.memory.allocate(0x1000, 8, None);
        rt.memory.free(0x1000, None);
        rt.asan.check_read(&rt.memory, 0x1000, 4);
        assert!(rt.has_fatal());
    }

    // ── SanitizerFinding display ──────────────────────────────────────────

    #[test]
    fn finding_display() {
        let f = SanitizerFinding::new(
            SanitizerKind::Asan,
            FindingSeverity::Error,
            0x1000,
            "overflow",
        );
        let s = f.to_string();
        assert!(s.contains("ASan"));
        assert!(s.contains("overflow"));
    }

    // ── AliasSet ──────────────────────────────────────────────────────────

    #[test]
    fn alias_set_deduplication() {
        let mut set = AliasSet::new();
        set.add(0x1000);
        set.add(0x1000);
        assert_eq!(set.alias_count(), 1);
    }
}
