//! TTD exception queries: `TtdExceptionQuery`, `ExceptionRecord`,
//! `ExceptionKind`, `find_exceptions()`.
//!
//! Queries a TTD trace for exception / fault events, with filtering,
//! classification, and aggregation.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use parking_lot::RwLock;
use rustre_ttd::{EventKind, TtdTrace};
use serde::{Deserialize, Serialize};

// ── ExceptionKind ─────────────────────────────────────────────────────────────

/// Classification of a Windows / x64 exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExceptionKind {
    /// Access violation (0xC0000005).
    AccessViolation,
    /// Stack overflow (0xC00000FD).
    StackOverflow,
    /// Integer divide-by-zero (0xC0000094).
    DivideByZero,
    /// Breakpoint (0x80000003).
    Breakpoint,
    /// Single-step / trap flag (0x80000004).
    SingleStep,
    /// Illegal instruction (0xC000001D).
    IllegalInstruction,
    /// Guard-page violation (0x80000001).
    GuardPage,
    /// Heap corruption / invalid heap access (0xC0000374).
    HeapCorruption,
    /// CLR / managed exception (0xE0434352).
    ManagedCode,
    /// C++ exception (0xE06D7363 = `msc`).
    CppException,
    /// Any other exception code.
    Other(u32),
}

impl ExceptionKind {
    /// Parse an exception kind from a Windows exception code.
    #[must_use]
    pub const fn from_code(code: u32) -> Self {
        match code {
            0xC000_0005 => Self::AccessViolation,
            0xC000_00FD => Self::StackOverflow,
            0xC000_0094 => Self::DivideByZero,
            0x8000_0003 => Self::Breakpoint,
            0x8000_0004 => Self::SingleStep,
            0xC000_001D => Self::IllegalInstruction,
            0x8000_0001 => Self::GuardPage,
            0xC000_0374 => Self::HeapCorruption,
            0xE043_4352 => Self::ManagedCode,
            0xE06D_7363 => Self::CppException,
            other => Self::Other(other),
        }
    }

    /// Return the Windows exception code for this kind.
    #[must_use]
    pub const fn code(self) -> u32 {
        match self {
            Self::AccessViolation => 0xC000_0005,
            Self::StackOverflow => 0xC000_00FD,
            Self::DivideByZero => 0xC000_0094,
            Self::Breakpoint => 0x8000_0003,
            Self::SingleStep => 0x8000_0004,
            Self::IllegalInstruction => 0xC000_001D,
            Self::GuardPage => 0x8000_0001,
            Self::HeapCorruption => 0xC000_0374,
            Self::ManagedCode => 0xE043_4352,
            Self::CppException => 0xE06D_7363,
            Self::Other(c) => c,
        }
    }

    /// Return `true` if this is a fatal / non-continuable exception.
    #[must_use]
    pub const fn is_fatal(self) -> bool {
        matches!(
            self,
            Self::AccessViolation
                | Self::StackOverflow
                | Self::DivideByZero
                | Self::IllegalInstruction
                | Self::HeapCorruption
        )
    }

    /// Return `true` if this is a debug-only exception (breakpoint / single-step).
    #[must_use]
    pub const fn is_debug(self) -> bool {
        matches!(self, Self::Breakpoint | Self::SingleStep)
    }

    /// Return a human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AccessViolation => "ACCESS_VIOLATION",
            Self::StackOverflow => "STACK_OVERFLOW",
            Self::DivideByZero => "INT_DIVIDE_BY_ZERO",
            Self::Breakpoint => "BREAKPOINT",
            Self::SingleStep => "SINGLE_STEP",
            Self::IllegalInstruction => "ILLEGAL_INSTRUCTION",
            Self::GuardPage => "GUARD_PAGE",
            Self::HeapCorruption => "HEAP_CORRUPTION",
            Self::ManagedCode => "CLR_EXCEPTION",
            Self::CppException => "CPP_EXCEPTION",
            Self::Other(_) => "UNKNOWN",
        }
    }
}

impl fmt::Display for ExceptionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(c) => write!(f, "EXCEPTION_{c:#010X}"),
            other => write!(f, "{}", other.name()),
        }
    }
}

// ── ExceptionRecord ───────────────────────────────────────────────────────────

/// A single exception event in a TTD trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionRecord {
    /// Trace sequence number.
    pub sequence: u64,
    /// Position in the trace.
    pub position: u64,
    /// Exception code.
    pub code: u32,
    /// Parsed exception kind.
    pub kind: ExceptionKind,
    /// Program counter at the time of the exception.
    pub fault_address: u64,
    /// For access violations: the address that was read/written.
    pub access_address: Option<u64>,
    /// Whether the access was a write (`true`) or a read (`false`), for AV.
    pub is_write_access: Option<bool>,
    /// Thread ID.
    pub thread_id: u32,
    /// Module containing `fault_address`, if known.
    pub module: Option<String>,
    /// Symbol at `fault_address`, if resolved.
    pub symbol: Option<String>,
    /// Whether a first-chance handler was invoked.
    pub first_chance: bool,
    /// Whether the exception was handled (did not crash the process).
    pub was_handled: bool,
    /// Number of exception parameters in the record.
    pub parameter_count: u32,
    /// Exception parameters (up to 15).
    pub parameters: Vec<u64>,
}

impl ExceptionRecord {
    /// Return `true` if this is an access violation where the fault address and
    /// access address are the same (typical null-deref).
    #[must_use]
    pub fn is_null_deref(&self) -> bool {
        if self.kind != ExceptionKind::AccessViolation { return false; }
        match self.access_address {
            Some(a) => a < 0x10000,
            None => false,
        }
    }

    /// Return a short one-line summary.
    #[must_use]
    pub fn summary(&self) -> String {
        let handled = if self.was_handled { "handled" } else { "unhandled" };
        format!(
            "{} at {:#x} (tid={} {})",
            self.kind,
            self.fault_address,
            self.thread_id,
            handled
        )
    }
}

impl fmt::Display for ExceptionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:010}] {}", self.sequence, self.summary())
    }
}

// ── ExceptionFilter ───────────────────────────────────────────────────────────

/// Declarative filter for exception records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExceptionFilter {
    /// If set, only match exceptions with this kind.
    pub kind: Option<ExceptionKind>,
    /// If set, only match exceptions with this exact code.
    pub code: Option<u32>,
    /// If set, only match exceptions in this thread.
    pub thread_id: Option<u32>,
    /// If set, only include unhandled exceptions.
    pub unhandled_only: bool,
    /// If set, only include fatal exceptions.
    pub fatal_only: bool,
    /// If set, only include first-chance exceptions.
    pub first_chance_only: bool,
    /// If set, only include exceptions in this module (case-insensitive substring).
    pub module_name: Option<String>,
    /// Minimum sequence number.
    pub after_sequence: Option<u64>,
    /// Maximum sequence number.
    pub before_sequence: Option<u64>,
    /// Maximum number of results.
    pub limit: Option<usize>,
}

impl ExceptionFilter {
    #[must_use]
    pub fn all() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn of_kind(kind: ExceptionKind) -> Self {
        Self { kind: Some(kind), ..Default::default() }
    }

    #[must_use]
    pub const fn unhandled(mut self) -> Self {
        self.unhandled_only = true;
        self
    }

    #[must_use]
    pub const fn fatal(mut self) -> Self {
        self.fatal_only = true;
        self
    }

    #[must_use]
    pub const fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// Return `true` if `rec` matches this filter.
    #[must_use]
    pub fn matches(&self, rec: &ExceptionRecord) -> bool {
        if let Some(k) = self.kind
            && rec.kind != k { return false; }
        if let Some(c) = self.code
            && rec.code != c { return false; }
        if let Some(tid) = self.thread_id
            && rec.thread_id != tid { return false; }
        if self.unhandled_only && rec.was_handled { return false; }
        if self.fatal_only && !rec.kind.is_fatal() { return false; }
        if self.first_chance_only && !rec.first_chance { return false; }
        if let Some(ref m) = self.module_name {
            let m_lower = m.to_ascii_lowercase();
            let rec_m = rec.module.as_deref().unwrap_or("").to_ascii_lowercase();
            if !rec_m.contains(&m_lower) { return false; }
        }
        if let Some(after) = self.after_sequence
            && rec.sequence <= after { return false; }
        if let Some(before) = self.before_sequence
            && rec.sequence >= before { return false; }
        true
    }
}

// ── ExceptionStats ────────────────────────────────────────────────────────────

/// Aggregate statistics over a set of exception records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExceptionStats {
    pub total: usize,
    pub unhandled: usize,
    pub fatal: usize,
    pub first_chance: usize,
    pub by_kind: HashMap<String, usize>,
    pub by_thread: HashMap<u32, usize>,
}

impl ExceptionStats {
    #[must_use]
    pub fn compute(records: &[ExceptionRecord]) -> Self {
        let mut stats = Self::default();
        stats.total = records.len();
        for r in records {
            if !r.was_handled { stats.unhandled += 1; }
            if r.kind.is_fatal() { stats.fatal += 1; }
            if r.first_chance { stats.first_chance += 1; }
            *stats.by_kind.entry(r.kind.to_string()).or_default() += 1;
            *stats.by_thread.entry(r.thread_id).or_default() += 1;
        }
        stats
    }
}

// ── TtdExceptionQuery ─────────────────────────────────────────────────────────

/// Queries TTD traces for exception events.
#[derive(Debug)]
pub struct TtdExceptionQuery {
    trace: Arc<RwLock<TtdTrace>>,
    cache: Arc<RwLock<Vec<ExceptionRecord>>>,
    cache_valid: Arc<RwLock<bool>>,
}

impl TtdExceptionQuery {
    /// Construct a new query engine backed by `trace`.
    #[must_use]
    pub fn new(trace: TtdTrace) -> Self {
        Self {
            trace: Arc::new(RwLock::new(trace)),
            cache: Arc::new(RwLock::new(Vec::new())),
            cache_valid: Arc::new(RwLock::new(false)),
        }
    }

    /// Invalidate the internal cache.
    pub fn invalidate_cache(&self) {
        *self.cache_valid.write() = false;
    }

    /// Build the exception record cache from the trace.
    pub fn build_cache(&self) {
        let trace = self.trace.read();
        let events = trace.all_events();
        let mut records: Vec<ExceptionRecord> = Vec::new();

        for event in &events {
            if let EventKind::Exception { code, addr } = &event.kind {
                let code = *code;
                let kind = ExceptionKind::from_code(code);
                // rustre_ttd::EventKind::Exception does not carry extended info;
                // access_address and is_write_access are not available.
                records.push(ExceptionRecord {
                    sequence: event.position.sequence,
                    position: event.position.as_u128() as u64,
                    code,
                    kind,
                    fault_address: *addr,
                    access_address: None,
                    is_write_access: None,
                    thread_id: event.thread_id,
                    module: None,
                    symbol: None,
                    first_chance: true,
                    was_handled: false,
                    parameter_count: 0,
                    parameters: vec![],
                });
            }
        }

        let mut c = self.cache.write();
        *c = records;
        *self.cache_valid.write() = true;
    }

    fn ensure_cache(&self) {
        if !*self.cache_valid.read() {
            self.build_cache();
        }
    }

    /// Execute an `ExceptionFilter` and return matching records.
    #[must_use]
    pub fn execute(&self, filter: &ExceptionFilter) -> Vec<ExceptionRecord> {
        self.ensure_cache();
        let cache = self.cache.read();
        let mut results: Vec<ExceptionRecord> = cache.iter().filter(|r| filter.matches(r)).cloned().collect();
        if let Some(limit) = filter.limit {
            results.truncate(limit);
        }
        results
    }

    /// Return statistics for the filtered exception set.
    #[must_use]
    pub fn stats(&self, filter: &ExceptionFilter) -> ExceptionStats {
        ExceptionStats::compute(&self.execute(filter))
    }

    /// Return the total number of exception events in the trace.
    #[must_use]
    pub fn total_exceptions(&self) -> usize {
        self.ensure_cache();
        self.cache.read().len()
    }

    /// Return the first unhandled exception in the trace, if any.
    #[must_use]
    pub fn first_crash(&self) -> Option<ExceptionRecord> {
        self.ensure_cache();
        self.cache.read().iter().find(|r| !r.was_handled && r.kind.is_fatal()).cloned()
    }

    /// Return all access violations in the trace.
    #[must_use]
    pub fn access_violations(&self) -> Vec<ExceptionRecord> {
        self.execute(&ExceptionFilter::of_kind(ExceptionKind::AccessViolation))
    }
}

// ── find_exceptions ───────────────────────────────────────────────────────────

/// Return all exception records from `engine` matching `filter`.
///
/// Convenience wrapper around `TtdExceptionQuery::execute`.
#[must_use]
pub fn find_exceptions(engine: &TtdExceptionQuery, filter: &ExceptionFilter) -> Vec<ExceptionRecord> {
    engine.execute(filter)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exception(seq: u64, code: u32, tid: u32, handled: bool, fatal_addr: u64) -> ExceptionRecord {
        let kind = ExceptionKind::from_code(code);
        ExceptionRecord {
            sequence: seq,
            position: seq,
            code,
            kind,
            fault_address: fatal_addr,
            access_address: if kind == ExceptionKind::AccessViolation { Some(fatal_addr) } else { None },
            is_write_access: if kind == ExceptionKind::AccessViolation { Some(false) } else { None },
            thread_id: tid,
            module: Some("ntdll.dll".to_string()),
            symbol: None,
            first_chance: true,
            was_handled: handled,
            parameter_count: 0,
            parameters: vec![],
        }
    }

    #[test]
    fn test_exception_kind_from_code() {
        assert_eq!(ExceptionKind::from_code(0xC000_0005), ExceptionKind::AccessViolation);
        assert_eq!(ExceptionKind::from_code(0xDEAD_BEEF), ExceptionKind::Other(0xDEAD_BEEF));
    }

    #[test]
    fn test_exception_kind_is_fatal() {
        assert!(ExceptionKind::AccessViolation.is_fatal());
        assert!(!ExceptionKind::Breakpoint.is_fatal());
    }

    #[test]
    fn test_exception_kind_is_debug() {
        assert!(ExceptionKind::Breakpoint.is_debug());
        assert!(ExceptionKind::SingleStep.is_debug());
        assert!(!ExceptionKind::AccessViolation.is_debug());
    }

    #[test]
    fn test_exception_record_is_null_deref() {
        let r = make_exception(1, 0xC000_0005, 1, false, 0x4);
        // access_address = Some(0x4) < 0x10000 → null-deref.
        assert!(r.is_null_deref());
    }

    #[test]
    fn test_exception_record_not_null_deref_for_non_av() {
        let r = make_exception(1, 0xC000_00FD, 1, false, 0x4);
        assert!(!r.is_null_deref());
    }

    #[test]
    fn test_exception_filter_kind() {
        let f = ExceptionFilter::of_kind(ExceptionKind::AccessViolation);
        let av = make_exception(1, 0xC000_0005, 1, false, 0x100);
        let bp = make_exception(2, 0x8000_0003, 1, true, 0x200);
        assert!(f.matches(&av));
        assert!(!f.matches(&bp));
    }

    #[test]
    fn test_exception_filter_unhandled() {
        let f = ExceptionFilter::all().unhandled();
        let r_handled = make_exception(1, 0xC000_0005, 1, true, 0x100);
        let r_unhandled = make_exception(2, 0xC000_0005, 1, false, 0x100);
        assert!(!f.matches(&r_handled));
        assert!(f.matches(&r_unhandled));
    }

    #[test]
    fn test_exception_filter_fatal() {
        let f = ExceptionFilter::all().fatal();
        let av = make_exception(1, 0xC000_0005, 1, false, 0x100); // fatal
        let bp = make_exception(2, 0x8000_0003, 1, true, 0x100); // not fatal
        assert!(f.matches(&av));
        assert!(!f.matches(&bp));
    }

    #[test]
    fn test_exception_filter_sequence_range() {
        let f = ExceptionFilter { after_sequence: Some(10), before_sequence: Some(100), ..Default::default() };
        let r_in = make_exception(50, 0xC000_0005, 1, false, 0x100);
        let r_out = make_exception(150, 0xC000_0005, 1, false, 0x100);
        assert!(f.matches(&r_in));
        assert!(!f.matches(&r_out));
    }

    #[test]
    fn test_exception_stats_compute() {
        let records = vec![
            make_exception(1, 0xC000_0005, 1, false, 0x100),
            make_exception(2, 0xC000_0005, 2, true, 0x200),
            make_exception(3, 0x8000_0003, 1, true, 0x300),
        ];
        let stats = ExceptionStats::compute(&records);
        assert_eq!(stats.total, 3);
        assert_eq!(stats.unhandled, 1);
        assert_eq!(stats.fatal, 2); // two AV records
    }

    #[test]
    fn test_exception_kind_display() {
        let s = format!("{}", ExceptionKind::AccessViolation);
        assert_eq!(s, "ACCESS_VIOLATION");
        let s2 = format!("{}", ExceptionKind::Other(0xDEAD));
        assert!(s2.contains("0x0000DEAD") || s2.contains("DEAD"));
    }

    #[test]
    fn test_exception_record_display() {
        let r = make_exception(42, 0xC000_0005, 3, false, 0xDEAD);
        let s = format!("{r}");
        assert!(s.contains("ACCESS_VIOLATION"));
    }

    #[test]
    fn test_exception_kind_code_roundtrip() {
        for code in [0xC000_0005u32, 0x8000_0003, 0xE06D_7363] {
            assert_eq!(ExceptionKind::from_code(code).code(), code);
        }
    }
}
