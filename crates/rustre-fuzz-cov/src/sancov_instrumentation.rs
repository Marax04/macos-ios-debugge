//! `SanitizerCoverage` instrumentation: PC table, counter maps, trace callbacks.
//!
//! Implements the LLVM `SanitizerCoverage` ABI so that instrumented binaries can
//! report coverage back to the fuzzer engine without requiring an actual LLVM
//! runtime to be linked.  All callbacks mirror the symbols emitted by
//! `-fsanitize-coverage=trace-pc-guard,trace-cmp,trace-div,trace-gep,
//! indirect-calls,pc-table,inline-8bit-counters,inline-bool-flag`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── errors ──────────────────────────────────────────────────────────────────

/// Errors produced by the `SanitizerCoverage` instrumentation layer.
#[derive(Debug, Error)]
pub enum SanCovError {
    #[error("PC table size mismatch: got {got}, expected {expected}")]
    PcTableSizeMismatch { got: usize, expected: usize },

    #[error("Counter map not initialised")]
    CounterMapUninitialised,

    #[error("Bool map not initialised")]
    BoolMapUninitialised,

    #[error("Duplicate module registration for base {0:#x}")]
    DuplicateModule(u64),

    #[error("Module not found for guard at {0:#x}")]
    ModuleNotFound(u64),

    #[error("Index out of range: {index} >= {len}")]
    IndexOutOfRange { index: usize, len: usize },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type SanCovResult<T> = Result<T, SanCovError>;

// ─── PC table ────────────────────────────────────────────────────────────────

/// Flags stored alongside each PC in the PC table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcFlags(pub u64);

impl PcFlags {
    /// The entry represents a function (as opposed to a basic block).
    pub const FUNC: u64 = 1;

    #[must_use]
    pub const fn is_func(self) -> bool {
        self.0 & Self::FUNC != 0
    }

    #[must_use]
    pub const fn is_block(self) -> bool {
        !self.is_func()
    }
}

/// A single entry in the PC table: `(program_counter, flags)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcEntry {
    pub pc: u64,
    pub flags: PcFlags,
}

impl PcEntry {
    #[must_use]
    pub const fn new(pc: u64, flags: u64) -> Self {
        Self { pc, flags: PcFlags(flags) }
    }
}

/// The full PC table for one loaded module.
#[derive(Debug, Clone, Serialize)]
pub struct PcTable {
    pub module_base: u64,
    pub entries: Vec<PcEntry>,
}

// Manual Deserialize impl: the derived one triggers `unsafe_derive_deserialize`
// because this module exposes unsafe extern "C" trampolines (which are
// unrelated to deserialization but the lint can't tell). Hand-rolling the
// impl preserves behavior while satisfying clippy::pedantic.
impl<'de> serde::Deserialize<'de> for PcTable {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            module_base: u64,
            entries: Vec<PcEntry>,
        }
        let h = Helper::deserialize(d)?;
        Ok(Self { module_base: h.module_base, entries: h.entries })
    }
}

impl PcTable {
    /// Build a `PcTable` from a raw `(pc, flags)` pointer pair as provided by
    /// `__sanitizer_cov_pcs_init`.
    ///
    /// # Safety
    /// `pcs_beg` must point to a valid array of `(u64, u64)` pairs with at
    /// least `len` elements, alive for the duration of the call.
    #[must_use] 
    pub unsafe fn from_raw(pcs_beg: *const u64, len: usize, module_base: u64) -> Self { unsafe {
        let mut entries = Vec::with_capacity(len);
        for i in 0..len {
            let pc = *pcs_beg.add(i * 2);
            let flags = *pcs_beg.add(i * 2 + 1);
            entries.push(PcEntry::new(pc, flags));
        }
        Self { module_base, entries }
    }}

    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return all function-entry PCs.
    #[must_use]
    pub fn function_pcs(&self) -> Vec<u64> {
        self.entries.iter().filter(|e| e.flags.is_func()).map(|e| e.pc).collect()
    }

    /// Return all basic-block PCs (non-function).
    #[must_use]
    pub fn block_pcs(&self) -> Vec<u64> {
        self.entries.iter().filter(|e| e.flags.is_block()).map(|e| e.pc).collect()
    }
}

// ─── 8-bit counter map ───────────────────────────────────────────────────────

/// Inline 8-bit counter map.  One counter per basic block.  The LLVM
/// instrumentation increments these directly without calling a function.
#[derive(Debug)]
pub struct CounterMap {
    pub counters: Vec<AtomicU8>,
    pub module_base: u64,
}

impl CounterMap {
    #[must_use]
    pub fn new(len: usize, module_base: u64) -> Self {
        let counters = (0..len).map(|_| AtomicU8::new(0)).collect();
        Self { counters, module_base }
    }

    /// Reset every counter to zero.
    pub fn reset(&self) {
        for c in &self.counters {
            c.store(0, Ordering::Relaxed);
        }
    }

    /// Read counter at `index`.  Returns 0 if `index` is out of range.
    #[must_use]
    pub fn get(&self, index: usize) -> u8 {
        self.counters.get(index).map_or(0, |c| c.load(Ordering::Relaxed))
    }

    /// Increment counter at `index` (saturating at 255).  No-op if out of range.
    pub fn increment(&self, index: usize) {
        if let Some(c) = self.counters.get(index) {
            let _ = c.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Number of non-zero counters (= edges hit).
    #[must_use]
    pub fn hit_count(&self) -> usize {
        self.counters.iter().filter(|c| c.load(Ordering::Relaxed) != 0).count()
    }

    /// Collect a snapshot as a plain `Vec<u8>`.
    #[must_use]
    pub fn snapshot(&self) -> Vec<u8> {
        self.counters.iter().map(|c| c.load(Ordering::Relaxed)).collect()
    }

    /// Merge (OR-max) another snapshot into self.
    pub fn merge_snapshot(&self, other: &[u8]) {
        for (c, &v) in self.counters.iter().zip(other.iter()) {
            let cur = c.load(Ordering::Relaxed);
            if v > cur {
                c.store(v, Ordering::Relaxed);
            }
        }
    }
}

// ─── boolean map ─────────────────────────────────────────────────────────────

/// Inline 8-bit boolean flag map.  One byte per basic block; set to 1 on first
/// visit, never decremented.  Mirrors `-fsanitize-coverage=inline-bool-flag`.
#[derive(Debug)]
pub struct BoolMap {
    pub flags: Vec<AtomicU8>,
    pub module_base: u64,
}

impl BoolMap {
    #[must_use]
    pub fn new(len: usize, module_base: u64) -> Self {
        let flags = (0..len).map(|_| AtomicU8::new(0)).collect();
        Self { flags, module_base }
    }

    /// Set flag at `index`.  No-op if `index` is out of range.
    pub fn set(&self, index: usize) {
        if let Some(f) = self.flags.get(index) {
            f.store(1, Ordering::Relaxed);
        }
    }

    /// Get flag at `index`.  Returns `false` if `index` is out of range.
    #[must_use]
    pub fn get(&self, index: usize) -> bool {
        self.flags.get(index).is_some_and(|f| f.load(Ordering::Relaxed) != 0)
    }

    pub fn reset(&self) {
        for f in &self.flags {
            f.store(0, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn coverage_fraction(&self) -> f64 {
        let total = self.flags.len();
        if total == 0 {
            return 0.0;
        }
        let hit = self.flags.iter().filter(|f| f.load(Ordering::Relaxed) != 0).count();
        crate::casts::usize_to_f64(hit) / crate::casts::usize_to_f64(total)
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<bool> {
        self.flags.iter().map(|f| f.load(Ordering::Relaxed) != 0).collect()
    }
}

// ─── trace-pc-guard ──────────────────────────────────────────────────────────

/// Guard word written by `__sanitizer_cov_trace_pc_guard_init`.
/// The fuzzer sets each guard to a non-zero index; the instrumentation
/// then calls `__sanitizer_cov_trace_pc_guard(guard)` on every edge.
#[derive(Debug)]
pub struct GuardMap {
    pub guards: Vec<AtomicU64>,
    pub module_base: u64,
}

impl GuardMap {
    #[must_use]
    pub fn new(len: usize, module_base: u64) -> Self {
        let guards = (0..len).map(|i| AtomicU64::new(i as u64 + 1)).collect();
        Self { guards, module_base }
    }

    /// Called by the LLVM-generated `__sanitizer_cov_trace_pc_guard` stub.
    pub fn on_guard_hit(&self, guard_index: usize, hit_map: &CounterMap) {
        if guard_index < hit_map.counters.len() {
            hit_map.increment(guard_index);
        }
    }

    /// Zero out all guards to disable further tracing for this module.
    pub fn disable(&self) {
        for g in &self.guards {
            g.store(0, Ordering::Relaxed);
        }
    }
}

// ─── trace-cmp callbacks ─────────────────────────────────────────────────────

/// A single comparison observation recorded by a trace-cmp callback.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CmpObservation {
    /// Program counter of the compare instruction.
    pub pc: u64,
    /// Bit-width: 8, 16, 32, or 64.
    pub width: u8,
    /// Left-hand side operand.
    pub arg1: u64,
    /// Right-hand side operand.
    pub arg2: u64,
    /// True when the second operand is a compile-time constant.
    pub is_const: bool,
}

impl CmpObservation {
    #[must_use]
    pub const fn new(pc: u64, width: u8, arg1: u64, arg2: u64, is_const: bool) -> Self {
        Self { pc, width, arg1, arg2, is_const }
    }

    /// How many bits differ between the two operands.
    #[must_use]
    pub const fn hamming_distance(&self) -> u32 {
        (self.arg1 ^ self.arg2).count_ones()
    }

    /// Absolute numeric distance (saturating).
    #[must_use]
    pub const fn numeric_distance(&self) -> u64 {
        self.arg1.abs_diff(self.arg2)
    }
}

/// Ring-buffer storage for `CmpObservation` entries.
#[derive(Debug)]
pub struct CmpLog {
    capacity: usize,
    buf: Mutex<Vec<CmpObservation>>,
    write_pos: AtomicU64,
}

impl CmpLog {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            buf: Mutex::new(vec![
                CmpObservation::new(0, 8, 0, 0, false);
                capacity
            ]),
            write_pos: AtomicU64::new(0),
        }
    }

    pub fn record(&self, obs: CmpObservation) {
        if self.capacity == 0 {
            return;
        }
        let pos = crate::casts::u64_to_usize(self.write_pos.fetch_add(1, Ordering::Relaxed)) % self.capacity;
        if let Ok(mut buf) = self.buf.lock() {
            buf[pos] = obs;
        }
    }

    /// Drain a snapshot of all observations.
    #[must_use]
    pub fn drain(&self) -> Vec<CmpObservation> {
        self.buf.lock().map_or_else(|_| Vec::new(), |buf| buf.clone())
    }

    pub fn reset(&self) {
        self.write_pos.store(0, Ordering::Relaxed);
        if let Ok(mut buf) = self.buf.lock() {
            for e in buf.iter_mut() {
                *e = CmpObservation::new(0, 8, 0, 0, false);
            }
        }
    }
}

// ─── trace-div callbacks ─────────────────────────────────────────────────────

/// Observation from a `__sanitizer_cov_trace_div` callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DivObservation {
    pub pc: u64,
    pub divisor: u64,
    pub is_64bit: bool,
}

/// Log for division operands.
#[derive(Debug, Default)]
pub struct DivLog {
    entries: Mutex<Vec<DivObservation>>,
}

impl DivLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, pc: u64, divisor: u64, is_64bit: bool) {
        if let Ok(mut v) = self.entries.lock() {
            v.push(DivObservation { pc, divisor, is_64bit });
        }
    }

    pub fn reset(&self) {
        if let Ok(mut v) = self.entries.lock() {
            v.clear();
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<DivObservation> {
        self.entries.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

// ─── trace-gep callbacks ─────────────────────────────────────────────────────

/// Observation from a `__sanitizer_cov_trace_gep` callback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GepObservation {
    pub pc: u64,
    /// Index value passed to `getelementptr`.
    pub index: u64,
}

/// Log for GEP index values.
#[derive(Debug, Default)]
pub struct GepLog {
    entries: Mutex<Vec<GepObservation>>,
}

impl GepLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, pc: u64, index: u64) {
        if let Ok(mut v) = self.entries.lock() {
            v.push(GepObservation { pc, index });
        }
    }

    pub fn reset(&self) {
        if let Ok(mut v) = self.entries.lock() {
            v.clear();
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<GepObservation> {
        self.entries.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

// ─── indirect-call tracing ───────────────────────────────────────────────────

/// A single indirect-call observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndirectCallObservation {
    pub caller_pc: u64,
    pub target_pc: u64,
}

/// Log for indirect calls.
#[derive(Debug, Default)]
pub struct IndirectCallLog {
    entries: Mutex<Vec<IndirectCallObservation>>,
    /// Unique `(caller, callee)` pairs seen so far.
    unique: Mutex<HashMap<(u64, u64), usize>>,
}

impl IndirectCallLog {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, caller_pc: u64, target_pc: u64) {
        if let Ok(mut v) = self.entries.lock() {
            v.push(IndirectCallObservation { caller_pc, target_pc });
        }
        if let Ok(mut u) = self.unique.lock() {
            *u.entry((caller_pc, target_pc)).or_insert(0) += 1;
        }
    }

    #[must_use]
    pub fn unique_pairs(&self) -> usize {
        self.unique.lock().map_or(0, |u| u.len())
    }

    pub fn reset(&self) {
        if let Ok(mut v) = self.entries.lock() {
            v.clear();
        }
        if let Ok(mut u) = self.unique.lock() {
            u.clear();
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<IndirectCallObservation> {
        self.entries.lock().map(|v| v.clone()).unwrap_or_default()
    }
}

// ─── module registration ─────────────────────────────────────────────────────

/// All instrumentation data for a single loaded module.
#[derive(Debug)]
pub struct ModuleInstrumentation {
    pub pc_table: PcTable,
    pub counters: Arc<CounterMap>,
    pub bool_map: Arc<BoolMap>,
    pub guards: Arc<GuardMap>,
    pub name: String,
}

impl ModuleInstrumentation {
    #[must_use]
    pub fn new(name: String, pc_table: PcTable) -> Self {
        let len = pc_table.len();
        let base = pc_table.module_base;
        Self {
            counters: Arc::new(CounterMap::new(len, base)),
            bool_map: Arc::new(BoolMap::new(len, base)),
            guards: Arc::new(GuardMap::new(len, base)),
            pc_table,
            name,
        }
    }

    /// Reset all per-run state (counters, bool flags) but keep PC table.
    pub fn reset_run(&self) {
        self.counters.reset();
        self.bool_map.reset();
    }

    #[must_use]
    pub fn coverage_fraction(&self) -> f64 {
        self.bool_map.coverage_fraction()
    }

    #[must_use]
    pub fn hit_edges(&self) -> usize {
        self.counters.hit_count()
    }

    #[must_use]
    pub const fn total_edges(&self) -> usize {
        self.pc_table.len()
    }
}

// ─── SanCovRuntime ───────────────────────────────────────────────────────────

/// Central runtime that aggregates all instrumentation for the current process.
#[derive(Debug)]
pub struct SanCovRuntime {
    modules: RwLock<HashMap<u64, ModuleInstrumentation>>,
    pub cmp_log: Arc<CmpLog>,
    pub div_log: Arc<DivLog>,
    pub gep_log: Arc<GepLog>,
    pub indirect_calls: Arc<IndirectCallLog>,
}

impl SanCovRuntime {
    #[must_use]
    pub fn new(cmp_capacity: usize) -> Self {
        Self {
            modules: RwLock::new(HashMap::new()),
            cmp_log: Arc::new(CmpLog::new(cmp_capacity)),
            div_log: Arc::new(DivLog::new()),
            gep_log: Arc::new(GepLog::new()),
            indirect_calls: Arc::new(IndirectCallLog::new()),
        }
    }

    /// Register a module.  Called from `__sanitizer_cov_pcs_init` shim.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    pub fn register_module(
        &self,
        name: impl Into<String>,
        pc_table: PcTable,
    ) -> SanCovResult<()> {
        let base = pc_table.module_base;
        let mut modules = self.modules.write().unwrap();
        if modules.contains_key(&base) {
            return Err(SanCovError::DuplicateModule(base));
        }
        modules.insert(base, ModuleInstrumentation::new(name.into(), pc_table));
        drop(modules);
        Ok(())
    }

    /// Deregister a module (e.g. on dlclose).
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn deregister_module(&self, base: u64) {
        let mut modules = self.modules.write().unwrap();
        modules.remove(&base);
    }

    /// Handle `__sanitizer_cov_trace_pc_guard` for a given module base and
    /// guard index.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn on_trace_pc_guard(&self, module_base: u64, guard_index: usize) {
        let modules = self.modules.read().unwrap();
        if let Some(m) = modules.get(&module_base) {
            m.counters.increment(guard_index);
            if guard_index < m.bool_map.flags.len() {
                m.bool_map.set(guard_index);
            }
        }
    }

    /// Handle all `__sanitizer_cov_trace_cmpN` callbacks.
    pub fn on_trace_cmp(&self, pc: u64, width: u8, arg1: u64, arg2: u64, is_const: bool) {
        self.cmp_log.record(CmpObservation::new(pc, width, arg1, arg2, is_const));
    }

    /// Handle `__sanitizer_cov_trace_div4` / `trace_div8`.
    pub fn on_trace_div(&self, pc: u64, divisor: u64, is_64bit: bool) {
        self.div_log.record(pc, divisor, is_64bit);
    }

    /// Handle `__sanitizer_cov_trace_gep`.
    pub fn on_trace_gep(&self, pc: u64, index: u64) {
        self.gep_log.record(pc, index);
    }

    /// Handle `__sanitizer_cov_indirect_call`.
    pub fn on_indirect_call(&self, caller_pc: u64, target_pc: u64) {
        self.indirect_calls.record(caller_pc, target_pc);
    }

    /// Reset all per-run instrumentation state.
    ///
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn reset_run(&self) {
        let modules = self.modules.read().unwrap();
        for m in modules.values() {
            m.reset_run();
        }
        drop(modules);
        self.cmp_log.reset();
        self.div_log.reset();
        self.gep_log.reset();
        self.indirect_calls.reset();
    }

    /// Aggregate coverage across all registered modules.
    #[must_use]
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn global_coverage(&self) -> GlobalCoverage {
        let modules = self.modules.read().unwrap();
        let mut total = 0usize;
        let mut hit = 0usize;
        for m in modules.values() {
            total += m.total_edges();
            hit += m.hit_edges();
        }
        drop(modules);
        GlobalCoverage {
            total_edges: total,
            hit_edges: hit,
            unique_indirect_calls: self.indirect_calls.unique_pairs(),
            cmp_observations: self.cmp_log.drain().len(),
        }
    }

    /// Find which module owns a given PC.
    #[must_use]
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn module_for_pc(&self, pc: u64) -> Option<u64> {
        let modules = self.modules.read().unwrap();
        for (&base, m) in modules.iter() {
            let end = base + m.total_edges() as u64 * 16; // rough estimate
            if pc >= base && pc < end {
                return Some(base);
            }
        }
        drop(modules);
        None
    }

    /// Return names of all registered modules.
    #[must_use]
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn module_names(&self) -> Vec<String> {
        let modules = self.modules.read().unwrap();
        modules.values().map(|m| m.name.clone()).collect()
    }
}

// ─── aggregated coverage snapshot ────────────────────────────────────────────

/// Summary of coverage across all registered modules for one fuzz run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalCoverage {
    pub total_edges: usize,
    pub hit_edges: usize,
    pub unique_indirect_calls: usize,
    pub cmp_observations: usize,
}

impl GlobalCoverage {
    #[must_use]
    pub fn coverage_percent(&self) -> f64 {
        if self.total_edges == 0 {
            return 0.0;
        }
        crate::casts::usize_to_f64(self.hit_edges) / crate::casts::usize_to_f64(self.total_edges) * 100.0
    }
}

// ─── SanCov ABI shims ────────────────────────────────────────────────────────

// Thin wrappers that match the exact C ABI exported by the LLVM `SanitizerCoverage`
// runtime. Link these as `#[no_mangle] extern "C"` functions in the harness.

/// Equivalent of `__sanitizer_cov_trace_pc_guard_init`.
///
/// # Safety
/// Pointers must be valid for the lifetime of the module.
pub unsafe fn sanitizer_cov_trace_pc_guard_init(
    start: *mut u32,
    stop: *mut u32,
    module_base: u64,
    runtime: &SanCovRuntime,
) { unsafe {
    // Guard against inverted or equal pointers before calling offset_from.
    if start.is_null() || stop.is_null() || stop <= start {
        return;
    }
    let len = usize::try_from(stop.offset_from(start)).unwrap_or(0);
    // Assign sequential guard indices.  Cap to avoid u32 overflow (i+1 as u32).
    let len = len.min(u32::MAX as usize);
    for i in 0..len {
        *start.add(i) = crate::casts::usize_to_u32(i + 1);
    }
    // Build a synthetic PC table (no real pcs in this path).
    let entries: Vec<PcEntry> = (0..len)
        .map(|i| PcEntry::new(module_base + i as u64, 0))
        .collect();
    let pc_table = PcTable { module_base, entries };
    let _ = runtime.register_module(format!("module_{module_base:#x}"), pc_table);
}}

/// Equivalent of `__sanitizer_cov_trace_pc_guard`.
///
/// # Safety
/// `guard` must be a valid pointer into the guard array.
pub unsafe fn sanitizer_cov_trace_pc_guard(
    guard: *mut u32,
    module_base: u64,
    runtime: &SanCovRuntime,
) { unsafe {
    if guard.is_null() || *guard == 0 {
        return;
    }
    let index = (*guard - 1) as usize;
    runtime.on_trace_pc_guard(module_base, index);
}}

/// `__sanitizer_cov_trace_cmp1`
pub fn sanitizer_cov_trace_cmp1(pc: u64, arg1: u8, arg2: u8, rt: &SanCovRuntime) {
    rt.on_trace_cmp(pc, 8, u64::from(arg1), u64::from(arg2), false);
}

/// `__sanitizer_cov_trace_cmp2`
pub fn sanitizer_cov_trace_cmp2(pc: u64, arg1: u16, arg2: u16, rt: &SanCovRuntime) {
    rt.on_trace_cmp(pc, 16, u64::from(arg1), u64::from(arg2), false);
}

/// `__sanitizer_cov_trace_cmp4`
pub fn sanitizer_cov_trace_cmp4(pc: u64, arg1: u32, arg2: u32, rt: &SanCovRuntime) {
    rt.on_trace_cmp(pc, 32, u64::from(arg1), u64::from(arg2), false);
}

/// `__sanitizer_cov_trace_cmp8`
pub fn sanitizer_cov_trace_cmp8(pc: u64, arg1: u64, arg2: u64, rt: &SanCovRuntime) {
    rt.on_trace_cmp(pc, 64, arg1, arg2, false);
}

/// `__sanitizer_cov_trace_const_cmp1`
pub fn sanitizer_cov_trace_const_cmp1(pc: u64, arg1: u8, arg2: u8, rt: &SanCovRuntime) {
    rt.on_trace_cmp(pc, 8, u64::from(arg1), u64::from(arg2), true);
}

/// `__sanitizer_cov_trace_const_cmp2`
pub fn sanitizer_cov_trace_const_cmp2(pc: u64, arg1: u16, arg2: u16, rt: &SanCovRuntime) {
    rt.on_trace_cmp(pc, 16, u64::from(arg1), u64::from(arg2), true);
}

/// `__sanitizer_cov_trace_const_cmp4`
pub fn sanitizer_cov_trace_const_cmp4(pc: u64, arg1: u32, arg2: u32, rt: &SanCovRuntime) {
    rt.on_trace_cmp(pc, 32, u64::from(arg1), u64::from(arg2), true);
}

/// `__sanitizer_cov_trace_const_cmp8`
pub fn sanitizer_cov_trace_const_cmp8(pc: u64, arg1: u64, arg2: u64, rt: &SanCovRuntime) {
    rt.on_trace_cmp(pc, 64, arg1, arg2, true);
}

/// `__sanitizer_cov_trace_div4`
pub fn sanitizer_cov_trace_div4(pc: u64, val: u32, rt: &SanCovRuntime) {
    rt.on_trace_div(pc, u64::from(val), false);
}

/// `__sanitizer_cov_trace_div8`
pub fn sanitizer_cov_trace_div8(pc: u64, val: u64, rt: &SanCovRuntime) {
    rt.on_trace_div(pc, val, true);
}

/// `__sanitizer_cov_trace_gep`
pub fn sanitizer_cov_trace_gep(pc: u64, index: u64, rt: &SanCovRuntime) {
    rt.on_trace_gep(pc, index);
}

/// `__sanitizer_cov_indirect_call`
pub fn sanitizer_cov_indirect_call(caller: u64, target: u64, rt: &SanCovRuntime) {
    rt.on_indirect_call(caller, target);
}

// ─── CoverageSnapshot ────────────────────────────────────────────────────────

/// Full coverage snapshot that can be persisted or compared between runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSnapshot {
    pub module_base: u64,
    pub module_name: String,
    /// Snapshot of the 8-bit counter map.
    pub counters: Vec<u8>,
    /// Snapshot of the bool flag map.
    pub bool_flags: Vec<bool>,
    /// New CMP observations seen in this run.
    pub cmp_observations: Vec<CmpObservation>,
    /// GEP observations seen in this run.
    pub gep_observations: Vec<GepObservation>,
    /// Div observations seen in this run.
    pub div_observations: Vec<DivObservation>,
    /// Unique indirect call count.
    pub indirect_call_pairs: usize,
}

impl SanCovRuntime {
    /// Take a full snapshot of all instrumentation state.
    #[must_use]
    /// # Panics
    ///
    /// Panics if invariants are violated.
    pub fn snapshot(&self) -> Vec<CoverageSnapshot> {
        let modules = self.modules.read().unwrap();
        let cmp_obs = self.cmp_log.drain();
        let gep_obs = self.gep_log.snapshot();
        let div_obs = self.div_log.snapshot();
        let indirect = self.indirect_calls.unique_pairs();

        modules
            .values()
            .map(|m| CoverageSnapshot {
                module_base: m.pc_table.module_base,
                module_name: m.name.clone(),
                counters: m.counters.snapshot(),
                bool_flags: m.bool_map.snapshot(),
                cmp_observations: cmp_obs.clone(),
                gep_observations: gep_obs.clone(),
                div_observations: div_obs.clone(),
                indirect_call_pairs: indirect,
            })
            .collect()
    }

    /// Compute which new edges appear in `new_snap` vs `baseline`.
    #[must_use]
    pub fn new_edges(baseline: &[bool], new_snap: &[bool]) -> Vec<usize> {
        new_snap
            .iter()
            .enumerate()
            .filter(|&(i, &b)| b && !baseline.get(i).copied().unwrap_or(false))
            .map(|(i, _)| i)
            .collect()
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pc_table(len: usize) -> PcTable {
        let entries = (0..len).map(|i| PcEntry::new(0x1000 + i as u64 * 4, 0)).collect();
        PcTable { module_base: 0x1000, entries }
    }

    #[test]
    fn counter_map_increment() {
        let cm = CounterMap::new(8, 0x1000);
        cm.increment(0);
        cm.increment(0);
        cm.increment(3);
        assert_eq!(cm.get(0), 2);
        assert_eq!(cm.get(3), 1);
        assert_eq!(cm.hit_count(), 2);
    }

    #[test]
    fn bool_map_set_and_fraction() {
        let bm = BoolMap::new(4, 0x2000);
        bm.set(0);
        bm.set(2);
        let f = bm.coverage_fraction();
        assert!((f - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn cmp_log_ring() {
        let log = CmpLog::new(4);
        for i in 0..6u64 {
            log.record(CmpObservation::new(0x100 + i, 8, i, i + 1, false));
        }
        let snap = log.drain();
        assert_eq!(snap.len(), 4); // ring capacity
    }

    #[test]
    fn runtime_register_and_coverage() {
        let rt = SanCovRuntime::new(16);
        let pt = make_pc_table(4);
        rt.register_module("test", pt).unwrap();
        rt.on_trace_pc_guard(0x1000, 0);
        rt.on_trace_pc_guard(0x1000, 2);
        let gc = rt.global_coverage();
        assert_eq!(gc.hit_edges, 2);
        assert_eq!(gc.total_edges, 4);
    }

    #[test]
    fn cmp_hamming_distance() {
        let obs = CmpObservation::new(0, 32, 0b1010u64, 0b0101u64, false);
        assert_eq!(obs.hamming_distance(), 4);
    }

    #[test]
    fn indirect_call_unique_pairs() {
        let log = IndirectCallLog::new();
        log.record(0x100, 0x200);
        log.record(0x100, 0x200); // duplicate
        log.record(0x100, 0x300);
        assert_eq!(log.unique_pairs(), 2);
    }

    #[test]
    fn new_edges_detection() {
        let baseline = vec![true, false, true, false];
        let new_snap = vec![true, true, true, true];
        let new = SanCovRuntime::new_edges(&baseline, &new_snap);
        assert_eq!(new, vec![1, 3]);
    }

    #[test]
    fn pc_flags() {
        let f = PcFlags(PcFlags::FUNC);
        assert!(f.is_func());
        assert!(!f.is_block());
        let b = PcFlags(0);
        assert!(b.is_block());
    }
}
