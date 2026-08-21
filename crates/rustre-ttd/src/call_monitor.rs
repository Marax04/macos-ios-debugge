//! `rustre-ttd::call_monitor`
//!
//! Monitors function calls during TTD replay. Records every call event with
//! its arguments, return value, and timing, and provides filtering and
//! aggregation utilities.

use std::collections::HashMap;
use std::fmt;
use std::ops::Not;
use std::time::Duration;

use serde::{Deserialize, Serialize};

// ─── CallRecord ───────────────────────────────────────────────────────────────

/// A single function-call event captured during TTD replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallRecord {
    /// Sequential position in the trace (sequence:step).
    pub seq_pos: (u64, u64),
    /// Virtual address of the called function.
    pub fn_addr: u64,
    /// Symbolic name of the function, if available.
    pub fn_name: Option<String>,
    /// Arguments captured at the call site (up to 6 integer registers).
    pub args: Vec<u64>,
    /// Return value placed in rax/eax after the call completes.
    pub ret_val: Option<u64>,
    /// Wall-clock duration of the call (from enter to return).
    pub duration: Duration,
    /// Thread that made the call.
    pub thread_id: u32,
    /// Call depth at the time this call was made.
    pub call_depth: u32,
}

impl CallRecord {
    /// Create a new `CallRecord` at the given position.
    #[must_use]
    pub const fn new(seq_pos: (u64, u64), fn_addr: u64, thread_id: u32) -> Self {
        Self {
            seq_pos,
            fn_addr,
            fn_name: None,
            args: Vec::new(),
            ret_val: None,
            duration: Duration::ZERO,
            thread_id,
            call_depth: 0,
        }
    }

    /// Attach a symbolic name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.fn_name = Some(name.into());
        self
    }

    /// Set argument registers.
    #[must_use]
    pub fn with_args(mut self, args: Vec<u64>) -> Self {
        self.args = args;
        self
    }

    /// Set the return value.
    #[must_use]
    pub const fn with_ret(mut self, ret: u64) -> Self {
        self.ret_val = Some(ret);
        self
    }

    /// Set the call duration.
    #[must_use]
    pub const fn with_duration(mut self, d: Duration) -> Self {
        self.duration = d;
        self
    }

    /// Display name: symbolic name or hex address.
    #[must_use]
    pub fn display_name(&self) -> String {
        self.fn_name
            .clone()
            .unwrap_or_else(|| format!("{:#x}", self.fn_addr))
    }

    /// Return `true` if this call has a symbolic name.
    #[must_use]
    pub const fn is_named(&self) -> bool {
        self.fn_name.is_some()
    }

    /// Return the first argument, or `0` if none.
    #[must_use]
    pub fn arg0(&self) -> u64 {
        self.args.first().copied().unwrap_or(0)
    }

    /// Return the nth argument, or `0` if out of bounds.
    #[must_use]
    pub fn arg(&self, n: usize) -> u64 {
        self.args.get(n).copied().unwrap_or(0)
    }
}

impl fmt::Display for CallRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} {}({}) -> {:?}  [{:.3}ms]",
            self.seq_pos.0,
            self.seq_pos.1,
            self.display_name(),
            self.args
                .iter()
                .map(|a| format!("{a:#x}"))
                .collect::<Vec<_>>()
                .join(", "),
            self.ret_val,
            self.duration.as_secs_f64() * 1000.0,
        )
    }
}

// ─── CallFilter ───────────────────────────────────────────────────────────────

/// Composable predicate for filtering [`CallRecord`]s.
#[derive(Debug, Clone)]
pub enum CallFilter {
    /// Match records from a specific module prefix (name starts with prefix).
    ByModule(String),
    /// Match records whose name contains the given substring.
    ByName(String),
    /// Match records at an exact virtual address.
    ByAddress(u64),
    /// Match records whose return value equals `val`.
    ByReturnValue(u64),
    /// Match records on a specific thread.
    ByThread(u32),
    /// Match records at call depth <= max.
    ByMaxDepth(u32),
    /// Match records at call depth >= min.
    ByMinDepth(u32),
    /// Logical AND.
    And(Box<Self>, Box<Self>),
    /// Logical OR.
    Or(Box<Self>, Box<Self>),
    /// Logical NOT.
    Not(Box<Self>),
    /// Accept everything.
    Any,
}

impl CallFilter {
    /// Return `true` if `record` matches this filter.
    #[must_use]
    pub fn matches(&self, record: &CallRecord) -> bool {
        match self {
            Self::ByModule(prefix) => record
                .fn_name
                .as_deref()
                .is_some_and(|n| n.starts_with(prefix.as_str())),
            Self::ByName(sub) => record
                .fn_name
                .as_deref()
                .is_some_and(|n| n.contains(sub.as_str())),
            Self::ByAddress(addr) => record.fn_addr == *addr,
            Self::ByReturnValue(val) => record.ret_val == Some(*val),
            Self::ByThread(tid) => record.thread_id == *tid,
            Self::ByMaxDepth(max) => record.call_depth <= *max,
            Self::ByMinDepth(min) => record.call_depth >= *min,
            Self::And(a, b) => a.matches(record) && b.matches(record),
            Self::Or(a, b) => a.matches(record) || b.matches(record),
            Self::Not(inner) => !inner.matches(record),
            Self::Any => true,
        }
    }

    /// Apply this filter to a slice of records.
    #[must_use]
    pub fn apply<'a>(&self, records: &'a [CallRecord]) -> Vec<&'a CallRecord> {
        records.iter().filter(|r| self.matches(r)).collect()
    }

    /// Convenience: `self AND other`.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        Self::And(Box::new(self), Box::new(other))
    }

    /// Convenience: `self OR other`.
    #[must_use]
    pub fn or(self, other: Self) -> Self {
        Self::Or(Box::new(self), Box::new(other))
    }

}

impl Not for CallFilter {
    type Output = Self;
    /// Convenience: `NOT self`.
    fn not(self) -> Self {
        Self::Not(Box::new(self))
    }
}

// ─── CallFrequencyMap ─────────────────────────────────────────────────────────

/// Maps function names (or addresses) to call counts.
#[derive(Debug, Clone, Default)]
pub struct CallFrequencyMap {
    by_name: HashMap<String, u64>,
    by_addr: HashMap<u64, u64>,
}

impl CallFrequencyMap {
    /// Create an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a frequency map from a slice of records.
    #[must_use]
    pub fn from_records(records: &[CallRecord]) -> Self {
        let mut m = Self::new();
        for r in records {
            m.record(r);
        }
        m
    }

    /// Record a single call.
    pub fn record(&mut self, record: &CallRecord) {
        let key = record.display_name();
        *self.by_name.entry(key).or_insert(0) += 1;
        *self.by_addr.entry(record.fn_addr).or_insert(0) += 1;
    }

    /// Return the count for a function by name.
    #[must_use]
    pub fn count_by_name(&self, name: &str) -> u64 {
        self.by_name.get(name).copied().unwrap_or(0)
    }

    /// Return the count for a function by address.
    #[must_use]
    pub fn count_by_addr(&self, addr: u64) -> u64 {
        self.by_addr.get(&addr).copied().unwrap_or(0)
    }

    /// Return all (name, count) pairs sorted by count descending.
    #[must_use]
    pub fn top_by_name(&self, limit: usize) -> Vec<(&str, u64)> {
        let mut v: Vec<(&str, u64)> = self.by_name.iter().map(|(k, &v)| (k.as_str(), v)).collect();
        v.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
        v.truncate(limit);
        v
    }

    /// Return all (address, count) pairs sorted by count descending.
    #[must_use]
    pub fn top_by_addr(&self, limit: usize) -> Vec<(u64, u64)> {
        let mut v: Vec<(u64, u64)> = self.by_addr.iter().map(|(&k, &v)| (k, v)).collect();
        v.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
        v.truncate(limit);
        v
    }

    /// Total number of recorded calls.
    #[must_use]
    pub fn total_calls(&self) -> u64 {
        self.by_name.values().sum()
    }

    /// Number of distinct function names seen.
    #[must_use]
    pub fn distinct_functions(&self) -> usize {
        self.by_name.len()
    }

    /// Merge another `CallFrequencyMap` into this one.
    pub fn merge(&mut self, other: &Self) {
        for (k, &v) in &other.by_name {
            *self.by_name.entry(k.clone()).or_insert(0) += v;
        }
        for (&k, &v) in &other.by_addr {
            *self.by_addr.entry(k).or_insert(0) += v;
        }
    }
}

// ─── CallChain ────────────────────────────────────────────────────────────────

/// An ordered sequence of call records representing a call path.
#[derive(Debug, Clone, Default)]
pub struct CallChain {
    /// The frames, ordered from outermost to innermost.
    pub frames: Vec<CallRecord>,
}

impl CallChain {
    /// Create an empty chain.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a call record onto the chain.
    pub fn push(&mut self, record: CallRecord) {
        self.frames.push(record);
    }

    /// Pop the innermost call record.
    pub fn pop(&mut self) -> Option<CallRecord> {
        self.frames.pop()
    }

    /// Return the current depth.
    #[must_use]
    pub const fn depth(&self) -> usize {
        self.frames.len()
    }

    /// Return the innermost frame, if any.
    #[must_use]
    pub fn top(&self) -> Option<&CallRecord> {
        self.frames.last()
    }

    /// Return all frames.
    #[must_use]
    pub fn frames(&self) -> &[CallRecord] {
        &self.frames
    }

    /// Format the chain as a human-readable call path.
    #[must_use]
    pub fn path_string(&self) -> String {
        self.frames
            .iter()
            .map(CallRecord::display_name)
            .collect::<Vec<_>>()
            .join(" -> ")
    }

    /// Check whether any frame matches `filter`.
    #[must_use]
    pub fn any_matches(&self, filter: &CallFilter) -> bool {
        self.frames.iter().any(|r| filter.matches(r))
    }

    /// Return `true` if the chain contains a call to a function with the given name.
    #[must_use]
    pub fn contains_name(&self, name: &str) -> bool {
        self.frames
            .iter()
            .any(|r| r.fn_name.as_deref() == Some(name))
    }

    /// Build a `CallChain` from a flat slice of `CallRecord`s filtered by thread.
    #[must_use]
    pub fn from_records_for_thread(records: &[CallRecord], tid: u32) -> Self {
        let mut chain = Self::new();
        for r in records {
            if r.thread_id == tid {
                chain.push(r.clone());
            }
        }
        chain
    }
}

impl fmt::Display for CallChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path_string())
    }
}

// ─── MonitorConfig ────────────────────────────────────────────────────────────

/// Configuration for a [`CallMonitor`].
#[derive(Debug, Clone)]
pub struct MonitorConfig {
    /// Maximum number of call records to keep in memory (0 = unlimited).
    pub max_records: usize,
    /// Record arguments on each call.
    pub record_args: bool,
    /// Record return values on each call.
    pub record_ret_vals: bool,
    /// Record call timing.
    pub record_timing: bool,
    /// Only record calls that pass this filter (None = record all).
    pub filter: Option<CallFilter>,
    /// Maximum call depth to record (0 = unlimited).
    pub max_depth: u32,
}

impl MonitorConfig {
    /// Create a permissive default config.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_records: 0,
            record_args: true,
            record_ret_vals: true,
            record_timing: true,
            filter: None,
            max_depth: 0,
        }
    }

    /// Limit recording to `max` call records.
    #[must_use]
    pub const fn with_max_records(mut self, max: usize) -> Self {
        self.max_records = max;
        self
    }

    /// Set the call filter.
    #[must_use]
    pub fn with_filter(mut self, filter: CallFilter) -> Self {
        self.filter = Some(filter);
        self
    }

    /// Disable argument recording.
    #[must_use]
    pub const fn without_args(mut self) -> Self {
        self.record_args = false;
        self
    }

    /// Set the maximum depth.
    #[must_use]
    pub const fn with_max_depth(mut self, depth: u32) -> Self {
        self.max_depth = depth;
        self
    }
}

impl Default for MonitorConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ─── CallMonitor ──────────────────────────────────────────────────────────────

/// Monitors and records function calls during TTD replay.
///
/// Feed [`CallRecord`]s via [`CallMonitor::record`].  The monitor applies the
/// configured [`CallFilter`] and enforces the `max_records` cap.  Use
/// [`CallMonitor::frequency_map`] and [`CallMonitor::filter_records`] for
/// analysis.
#[derive(Debug, Default)]
pub struct CallMonitor {
    /// All recorded call records.
    pub records: Vec<CallRecord>,
    /// Configuration.
    pub config: MonitorConfig,
    /// Per-thread current call depth.
    depths: HashMap<u32, u32>,
    /// Total calls seen (including those filtered out).
    pub total_seen: u64,
    /// Total calls that passed the filter and were recorded.
    pub total_recorded: u64,
}

impl CallMonitor {
    /// Create a new monitor with default config.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a monitor with a custom config.
    #[must_use]
    pub fn with_config(config: MonitorConfig) -> Self {
        Self {
            config,
            ..Self::default()
        }
    }

    /// Record a call. Returns `true` if the record was accepted.
    pub fn record(&mut self, mut rec: CallRecord) -> bool {
        self.total_seen += 1;

        // Compute and update call depth.
        let depth = self.depths.entry(rec.thread_id).or_insert(0);
        rec.call_depth = *depth;
        *depth = depth.saturating_add(1);

        // Depth filter.
        if self.config.max_depth > 0 && rec.call_depth > self.config.max_depth {
            return false;
        }

        // Custom filter.
        if let Some(ref f) = self.config.filter
            && !f.matches(&rec)
        {
            return false;
        }

        // Capacity check.
        if self.config.max_records > 0 && self.records.len() >= self.config.max_records {
            return false;
        }

        self.records.push(rec);
        self.total_recorded += 1;
        true
    }

    /// Notify the monitor that a return event occurred (decrements depth).
    pub fn notify_return(&mut self, thread_id: u32) {
        let depth = self.depths.entry(thread_id).or_insert(0);
        if *depth > 0 {
            *depth -= 1;
        }
    }

    /// Build a `CallFrequencyMap` from recorded calls.
    #[must_use]
    pub fn frequency_map(&self) -> CallFrequencyMap {
        CallFrequencyMap::from_records(&self.records)
    }

    /// Return all records matching `filter`.
    #[must_use]
    pub fn filter_records(&self, filter: &CallFilter) -> Vec<&CallRecord> {
        filter.apply(&self.records)
    }

    /// Return all records for thread `tid`.
    #[must_use]
    pub fn records_for_thread(&self, tid: u32) -> Vec<&CallRecord> {
        self.records.iter().filter(|r| r.thread_id == tid).collect()
    }

    /// Return all records matching a function name substring.
    #[must_use]
    pub fn find_by_name(&self, sub: &str) -> Vec<&CallRecord> {
        let f = CallFilter::ByName(sub.to_string());
        f.apply(&self.records)
    }

    /// Return the record at position `idx`, or `None`.
    #[must_use]
    pub fn get(&self, idx: usize) -> Option<&CallRecord> {
        self.records.get(idx)
    }

    /// Number of recorded calls.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if no calls have been recorded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Clear all recorded calls and reset counters.
    pub fn clear(&mut self) {
        self.records.clear();
        self.depths.clear();
        self.total_seen = 0;
        self.total_recorded = 0;
    }

    /// Return the top `n` most-called functions by name.
    #[must_use]
    pub fn top_functions(&self, n: usize) -> Vec<(String, u64)> {
        let freq = self.frequency_map();
        freq.top_by_name(n)
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect()
    }

    /// Build a `CallChain` for thread `tid`.
    #[must_use]
    pub fn chain_for_thread(&self, tid: u32) -> CallChain {
        CallChain::from_records_for_thread(&self.records, tid)
    }

    /// Return the total wall-clock time spent inside calls to `fn_name`.
    #[must_use]
    pub fn total_time_in(&self, fn_name: &str) -> Duration {
        self.records
            .iter()
            .filter(|r| r.fn_name.as_deref() == Some(fn_name))
            .map(|r| r.duration)
            .fold(Duration::ZERO, |acc, d| acc + d)
    }

    /// Return calls that returned a non-zero value.
    #[must_use]
    pub fn calls_with_nonzero_return(&self) -> Vec<&CallRecord> {
        self.records
            .iter()
            .filter(|r| r.ret_val.is_some_and(|v| v != 0))
            .collect()
    }

    /// Compute per-function average duration.
    #[must_use]
    pub fn average_durations(&self) -> HashMap<String, Duration> {
        let mut totals: HashMap<String, (Duration, u64)> = HashMap::new();
        for r in &self.records {
            let e = totals
                .entry(r.display_name())
                .or_insert((Duration::ZERO, 0));
            e.0 += r.duration;
            e.1 += 1;
        }
        totals
            .into_iter()
            .map(|(k, (total, count))| {
                let avg = if count == 0 {
                    Duration::ZERO
                } else {
                    total / u32::try_from(count).unwrap_or(u32::MAX)
                };
                (k, avg)
            })
            .collect()
    }
}

impl fmt::Display for CallMonitor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CallMonitor {{ recorded={}/{}, distinct={} }}",
            self.total_recorded,
            self.total_seen,
            self.frequency_map().distinct_functions(),
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(addr: u64, name: &str, tid: u32) -> CallRecord {
        CallRecord::new((1, 0), addr, tid).with_name(name)
    }

    fn make_record_with_ret(addr: u64, name: &str, ret: u64) -> CallRecord {
        CallRecord::new((1, 0), addr, 1)
            .with_name(name)
            .with_ret(ret)
    }

    // ── CallRecord ────────────────────────────────────────────────────────────

    #[test]
    fn call_record_display_name_symbolic() {
        let r = make_record(0x1000, "malloc", 1);
        assert_eq!(r.display_name(), "malloc");
    }

    #[test]
    fn call_record_display_name_hex_fallback() {
        let r = CallRecord::new((0, 0), 0xdead_beef, 1);
        assert_eq!(r.display_name(), "0xdeadbeef");
    }

    #[test]
    fn call_record_is_named() {
        let named = make_record(0, "foo", 1);
        let unnamed = CallRecord::new((0, 0), 0, 1);
        assert!(named.is_named());
        assert!(!unnamed.is_named());
    }

    #[test]
    fn call_record_arg_accessors() {
        let r = CallRecord::new((0, 0), 0, 1).with_args(vec![1, 2, 3]);
        assert_eq!(r.arg0(), 1);
        assert_eq!(r.arg(1), 2);
        assert_eq!(r.arg(10), 0); // out of bounds
    }

    #[test]
    fn call_record_with_ret() {
        let r = make_record_with_ret(0x1000, "VirtualAlloc", 0x0020_0000);
        assert_eq!(r.ret_val, Some(0x0020_0000));
    }

    #[test]
    fn call_record_display_format() {
        let r = CallRecord::new((5, 3), 0x4000, 2)
            .with_name("free")
            .with_args(vec![0xdead_beef]);
        let s = r.to_string();
        assert!(s.contains("5:3"));
        assert!(s.contains("free"));
    }

    // ── CallFilter ────────────────────────────────────────────────────────────

    #[test]
    fn filter_by_name_match() {
        let r = make_record(0, "LoadLibraryA", 1);
        assert!(CallFilter::ByName("LoadLibrary".to_string()).matches(&r));
    }

    #[test]
    fn filter_by_name_no_match() {
        let r = make_record(0, "VirtualAlloc", 1);
        assert!(!CallFilter::ByName("LoadLibrary".to_string()).matches(&r));
    }

    #[test]
    fn filter_by_address() {
        let r = make_record(0x7000, "f", 1);
        assert!(CallFilter::ByAddress(0x7000).matches(&r));
        assert!(!CallFilter::ByAddress(0x8000).matches(&r));
    }

    #[test]
    fn filter_by_return_value() {
        let r = make_record_with_ret(0, "fn", 42);
        assert!(CallFilter::ByReturnValue(42).matches(&r));
        assert!(!CallFilter::ByReturnValue(0).matches(&r));
    }

    #[test]
    fn filter_by_thread() {
        let r = make_record(0, "fn", 3);
        assert!(CallFilter::ByThread(3).matches(&r));
        assert!(!CallFilter::ByThread(4).matches(&r));
    }

    #[test]
    fn filter_by_module_prefix() {
        let r = make_record(0, "kernel32!LoadLibrary", 1);
        assert!(CallFilter::ByModule("kernel32".to_string()).matches(&r));
        assert!(!CallFilter::ByModule("ntdll".to_string()).matches(&r));
    }

    #[test]
    fn filter_and_both_true() {
        let r = make_record(0x1000, "VirtualAlloc", 1);
        let f = CallFilter::ByAddress(0x1000).and(CallFilter::ByName("Virtual".to_string()));
        assert!(f.matches(&r));
    }

    #[test]
    fn filter_and_one_false() {
        let r = make_record(0x1000, "VirtualAlloc", 1);
        let f = CallFilter::ByAddress(0x9999).and(CallFilter::ByName("Virtual".to_string()));
        assert!(!f.matches(&r));
    }

    #[test]
    fn filter_or() {
        let r = make_record(0x1000, "foo", 1);
        let f = CallFilter::ByAddress(0x1000).or(CallFilter::ByName("bar".to_string()));
        assert!(f.matches(&r));
    }

    #[test]
    fn filter_not() {
        let r = make_record(0, "malloc", 1);
        let f = CallFilter::ByName("malloc".to_string()).not();
        assert!(!f.matches(&r));
    }

    #[test]
    fn filter_any() {
        let r = make_record(0, "anything", 99);
        assert!(CallFilter::Any.matches(&r));
    }

    #[test]
    fn filter_apply_returns_subset() {
        let records = vec![
            make_record(0x1000, "malloc", 1),
            make_record(0x2000, "free", 1),
            make_record(0x1000, "malloc", 2),
        ];
        let hits = CallFilter::ByAddress(0x1000).apply(&records);
        assert_eq!(hits.len(), 2);
    }

    // ── CallFrequencyMap ──────────────────────────────────────────────────────

    #[test]
    fn freq_map_count_by_name() {
        let records = vec![
            make_record(0, "malloc", 1),
            make_record(0, "malloc", 1),
            make_record(0, "free", 1),
        ];
        let m = CallFrequencyMap::from_records(&records);
        assert_eq!(m.count_by_name("malloc"), 2);
        assert_eq!(m.count_by_name("free"), 1);
        assert_eq!(m.count_by_name("realloc"), 0);
    }

    #[test]
    fn freq_map_total_calls() {
        let records = vec![make_record(0, "a", 1), make_record(0, "b", 1)];
        let m = CallFrequencyMap::from_records(&records);
        assert_eq!(m.total_calls(), 2);
    }

    #[test]
    fn freq_map_top_by_name_sorted() {
        let records = vec![
            make_record(0, "a", 1),
            make_record(0, "b", 1),
            make_record(0, "b", 1),
            make_record(0, "c", 1),
            make_record(0, "c", 1),
            make_record(0, "c", 1),
        ];
        let m = CallFrequencyMap::from_records(&records);
        let top = m.top_by_name(3);
        assert_eq!(top[0].1, 3); // c
        assert_eq!(top[1].1, 2); // b
        assert_eq!(top[2].1, 1); // a
    }

    #[test]
    fn freq_map_distinct_functions() {
        let records = vec![
            make_record(0, "x", 1),
            make_record(0, "y", 1),
            make_record(0, "x", 2),
        ];
        let m = CallFrequencyMap::from_records(&records);
        assert_eq!(m.distinct_functions(), 2);
    }

    #[test]
    fn freq_map_merge() {
        let r1 = vec![make_record(0, "a", 1)];
        let r2 = vec![make_record(0, "a", 1), make_record(0, "b", 1)];
        let mut m1 = CallFrequencyMap::from_records(&r1);
        let m2 = CallFrequencyMap::from_records(&r2);
        m1.merge(&m2);
        assert_eq!(m1.count_by_name("a"), 2);
        assert_eq!(m1.count_by_name("b"), 1);
    }

    // ── CallChain ─────────────────────────────────────────────────────────────

    #[test]
    fn call_chain_push_pop() {
        let mut chain = CallChain::new();
        chain.push(make_record(0, "a", 1));
        chain.push(make_record(0, "b", 1));
        assert_eq!(chain.depth(), 2);
        let top = chain.pop().unwrap();
        assert_eq!(top.display_name(), "b");
    }

    #[test]
    fn call_chain_path_string() {
        let mut chain = CallChain::new();
        chain.push(make_record(0, "main", 1));
        chain.push(make_record(0, "foo", 1));
        chain.push(make_record(0, "bar", 1));
        assert_eq!(chain.path_string(), "main -> foo -> bar");
    }

    #[test]
    fn call_chain_contains_name() {
        let mut chain = CallChain::new();
        chain.push(make_record(0, "malloc", 1));
        chain.push(make_record(0, "free", 1));
        assert!(chain.contains_name("malloc"));
        assert!(!chain.contains_name("realloc"));
    }

    #[test]
    fn call_chain_any_matches() {
        let mut chain = CallChain::new();
        chain.push(make_record(0x1000, "VirtualAlloc", 1));
        chain.push(make_record(0x2000, "CreateThread", 1));
        let f = CallFilter::ByAddress(0x1000);
        assert!(chain.any_matches(&f));
    }

    #[test]
    fn call_chain_from_records_for_thread() {
        let records = vec![
            make_record(0, "a", 1),
            make_record(0, "b", 2),
            make_record(0, "c", 1),
        ];
        let chain = CallChain::from_records_for_thread(&records, 1);
        assert_eq!(chain.depth(), 2);
    }

    // ── CallMonitor ───────────────────────────────────────────────────────────

    #[test]
    fn monitor_records_calls() {
        let mut m = CallMonitor::new();
        m.record(make_record(0, "malloc", 1));
        m.record(make_record(0, "free", 1));
        assert_eq!(m.len(), 2);
        assert_eq!(m.total_seen, 2);
        assert_eq!(m.total_recorded, 2);
    }

    #[test]
    fn monitor_is_empty_initially() {
        let m = CallMonitor::new();
        assert!(m.is_empty());
    }

    #[test]
    fn monitor_max_records_cap() {
        let cfg = MonitorConfig::new().with_max_records(3);
        let mut m = CallMonitor::with_config(cfg);
        for i in 0..10u64 {
            m.record(CallRecord::new((i, 0), i, 1));
        }
        assert_eq!(m.len(), 3);
        assert_eq!(m.total_seen, 10);
    }

    #[test]
    fn monitor_filter_by_name() {
        let mut m = CallMonitor::new();
        m.record(make_record(0, "LoadLibraryA", 1));
        m.record(make_record(0, "GetProcAddress", 1));
        m.record(make_record(0, "LoadLibraryW", 1));
        let hits = m.find_by_name("LoadLibrary");
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn monitor_records_for_thread() {
        let mut m = CallMonitor::new();
        m.record(make_record(0, "a", 1));
        m.record(make_record(0, "b", 2));
        m.record(make_record(0, "c", 1));
        assert_eq!(m.records_for_thread(1).len(), 2);
        assert_eq!(m.records_for_thread(2).len(), 1);
        assert_eq!(m.records_for_thread(3).len(), 0);
    }

    #[test]
    fn monitor_top_functions() {
        let mut m = CallMonitor::new();
        for _ in 0..5 {
            m.record(make_record(0, "malloc", 1));
        }
        for _ in 0..2 {
            m.record(make_record(0, "free", 1));
        }
        let top = m.top_functions(2);
        assert_eq!(top[0].0, "malloc");
        assert_eq!(top[0].1, 5);
    }

    #[test]
    fn monitor_clear_resets_state() {
        let mut m = CallMonitor::new();
        m.record(make_record(0, "fn", 1));
        m.clear();
        assert!(m.is_empty());
        assert_eq!(m.total_seen, 0);
        assert_eq!(m.total_recorded, 0);
    }

    #[test]
    fn monitor_calls_with_nonzero_return() {
        let mut m = CallMonitor::new();
        m.record(make_record_with_ret(0, "f", 0));
        m.record(make_record_with_ret(0, "g", 1));
        m.record(make_record_with_ret(0, "h", 42));
        let nz = m.calls_with_nonzero_return();
        assert_eq!(nz.len(), 2);
    }

    #[test]
    fn monitor_total_time_in() {
        let mut m = CallMonitor::new();
        let r1 = make_record(0, "sleep", 1).with_duration(Duration::from_millis(100));
        let r2 = make_record(0, "sleep", 1).with_duration(Duration::from_millis(200));
        m.record(r1);
        m.record(r2);
        let total = m.total_time_in("sleep");
        assert_eq!(total.as_millis(), 300);
    }

    #[test]
    fn monitor_custom_filter_applied() {
        let cfg = MonitorConfig::new().with_filter(CallFilter::ByName("Virtual".to_string()));
        let mut m = CallMonitor::with_config(cfg);
        m.record(make_record(0, "VirtualAlloc", 1));
        m.record(make_record(0, "malloc", 1));
        assert_eq!(m.len(), 1);
        assert_eq!(m.records[0].display_name(), "VirtualAlloc");
    }

    #[test]
    fn monitor_depth_tracking() {
        let mut m = CallMonitor::new();
        m.record(make_record(0, "outer", 1));
        m.record(make_record(0, "inner", 1));
        assert_eq!(m.records[0].call_depth, 0);
        assert_eq!(m.records[1].call_depth, 1);
        m.notify_return(1);
        m.record(make_record(0, "after_return", 1));
        assert_eq!(m.records[2].call_depth, 1);
    }

    #[test]
    fn monitor_display_format() {
        let mut m = CallMonitor::new();
        m.record(make_record(0, "f", 1));
        let s = m.to_string();
        assert!(s.contains("CallMonitor"));
        assert!(s.contains("1/1"));
    }

    #[test]
    fn monitor_average_durations() {
        let mut m = CallMonitor::new();
        m.record(make_record(0, "f", 1).with_duration(Duration::from_millis(100)));
        m.record(make_record(0, "f", 1).with_duration(Duration::from_millis(200)));
        let avgs = m.average_durations();
        assert_eq!(avgs["f"].as_millis(), 150);
    }

    #[test]
    fn call_chain_display_empty() {
        let chain = CallChain::new();
        assert_eq!(chain.path_string(), "");
    }

    #[test]
    fn monitor_get_record_by_index() {
        let mut m = CallMonitor::new();
        m.record(make_record(0, "target", 1));
        assert!(m.get(0).is_some());
        assert!(m.get(1).is_none());
    }
}
