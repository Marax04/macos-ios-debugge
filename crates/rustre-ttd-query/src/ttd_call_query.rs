//! TTD call-trace queries: `TtdCallQuery`, `CallQuery`, `CallRecord`,
//! `find_calls_to()`.
//!
//! Queries a TTD (Time Travel Debugging) `SQLite` trace database for function
//! call / return events and provides rich filtering, aggregation, and export.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use parking_lot::RwLock;
use rustre_ttd::{EventKind, TtdTrace};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── CallQueryError ────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CallQueryError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("invalid address: {0:#x}")]
    InvalidAddress(u64),
    #[error("no trace loaded")]
    NoTrace,
    #[error("query timeout")]
    Timeout,
}

// ── CallRecord ────────────────────────────────────────────────────────────────

/// A single function call event captured in the TTD trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallRecord {
    /// Trace sequence number of the call event.
    pub sequence: u64,
    /// Position in the trace (major:minor clock).
    pub position: u64,
    /// Address of the called function (callee).
    pub callee_address: u64,
    /// Symbolic name of the callee, if resolved.
    pub callee_name: Option<String>,
    /// Address of the call instruction (caller).
    pub call_site: u64,
    /// Module that contains the callee, if known.
    pub callee_module: Option<String>,
    /// Thread ID.
    pub thread_id: u32,
    /// Depth of the call stack at the time of the call.
    pub call_depth: u32,
    /// Sequence number of the matching RETURN event (if paired).
    pub return_sequence: Option<u64>,
    /// Return address (top of stack at call time).
    pub return_address: u64,
    /// Value of RCX / R0 (first argument) at the time of the call.
    pub arg0: Option<u64>,
    /// Value of RDX / R1 (second argument) at the time of the call.
    pub arg1: Option<u64>,
    /// Value of R8 / R2 (third argument) at the time of the call.
    pub arg2: Option<u64>,
    /// Value of R9 / R3 (fourth argument) at the time of the call.
    pub arg3: Option<u64>,
    /// Return value (RAX / R0) captured from the matching RETURN event.
    pub return_value: Option<u64>,
}

impl CallRecord {
    /// Return `true` if this call has a matched return event.
    #[must_use]
    pub const fn is_paired(&self) -> bool {
        self.return_sequence.is_some()
    }

    /// Return the duration in trace-ticks between call and return, if paired.
    #[must_use]
    pub const fn duration_ticks(&self) -> Option<u64> {
        match self.return_sequence {
            Some(ret) => Some(ret.saturating_sub(self.sequence)),
            None => None,
        }
    }

    /// Return the callee name or a hex string.
    #[must_use]
    pub fn callee_display(&self) -> String {
        match &self.callee_name {
            Some(n) => n.clone(),
            None => format!("{:#x}", self.callee_address),
        }
    }
}

impl fmt::Display for CallRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{:010}] call {} from {:#x} (tid={} depth={})",
            self.sequence,
            self.callee_display(),
            self.call_site,
            self.thread_id,
            self.call_depth,
        )
    }
}

// ── CallQuery ─────────────────────────────────────────────────────────────────

/// Declarative query for call records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallQuery {
    /// If set, only return calls to this exact address.
    pub callee_address: Option<u64>,
    /// If set, filter by callee name (substring, case-insensitive).
    pub callee_name_contains: Option<String>,
    /// If set, only return calls from this call site.
    pub call_site: Option<u64>,
    /// If set, filter by module name (case-insensitive).
    pub module_name: Option<String>,
    /// If set, filter to a specific thread ID.
    pub thread_id: Option<u32>,
    /// If set, return only calls at or above this stack depth.
    pub min_depth: Option<u32>,
    /// If set, return only calls at or below this stack depth.
    pub max_depth: Option<u32>,
    /// Only include calls that have a matched return event.
    pub paired_only: bool,
    /// If set, return only calls with the return value equal to this.
    pub return_value: Option<u64>,
    /// Maximum trace sequence number.
    pub before_sequence: Option<u64>,
    /// Minimum trace sequence number.
    pub after_sequence: Option<u64>,
    /// Maximum number of results to return.
    pub limit: Option<usize>,
    /// If set, only include calls whose first argument matches.
    pub arg0_filter: Option<u64>,
}

impl CallQuery {
    /// Construct an empty query (matches all calls).
    #[must_use]
    pub fn all() -> Self {
        Self::default()
    }

    /// Restrict to a specific callee address.
    #[must_use]
    pub const fn to_address(mut self, addr: u64) -> Self {
        self.callee_address = Some(addr);
        self
    }

    /// Restrict to calls whose callee name contains `s`.
    #[must_use]
    pub fn to_name(mut self, s: impl Into<String>) -> Self {
        self.callee_name_contains = Some(s.into());
        self
    }

    /// Restrict to a specific thread.
    #[must_use]
    pub const fn on_thread(mut self, tid: u32) -> Self {
        self.thread_id = Some(tid);
        self
    }

    /// Only include paired calls (with return event).
    #[must_use]
    pub const fn paired(mut self) -> Self {
        self.paired_only = true;
        self
    }

    /// Set a result limit.
    #[must_use]
    pub const fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// Check whether a `CallRecord` satisfies this query.
    #[must_use]
    pub fn matches(&self, rec: &CallRecord) -> bool {
        if let Some(addr) = self.callee_address
            && rec.callee_address != addr { return false; }
        if let Some(ref pat) = self.callee_name_contains {
            let pat_lower = pat.to_ascii_lowercase();
            let name_lower = rec.callee_name.as_deref().unwrap_or("").to_ascii_lowercase();
            if !name_lower.contains(&pat_lower) { return false; }
        }
        if let Some(site) = self.call_site
            && rec.call_site != site { return false; }
        if let Some(ref m) = self.module_name {
            let m_lower = m.to_ascii_lowercase();
            let mod_lower = rec.callee_module.as_deref().unwrap_or("").to_ascii_lowercase();
            if !mod_lower.contains(&m_lower) { return false; }
        }
        if let Some(tid) = self.thread_id
            && rec.thread_id != tid { return false; }
        if let Some(min_d) = self.min_depth
            && rec.call_depth < min_d { return false; }
        if let Some(max_d) = self.max_depth
            && rec.call_depth > max_d { return false; }
        if self.paired_only && !rec.is_paired() { return false; }
        if let Some(rv) = self.return_value
            && rec.return_value != Some(rv) { return false; }
        if let Some(before) = self.before_sequence
            && rec.sequence >= before { return false; }
        if let Some(after) = self.after_sequence
            && rec.sequence <= after { return false; }
        if let Some(a0) = self.arg0_filter
            && rec.arg0 != Some(a0) { return false; }
        true
    }
}

// ── CallStats ─────────────────────────────────────────────────────────────────

/// Aggregate statistics for a set of call records.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CallStats {
    pub total_calls: usize,
    pub paired_calls: usize,
    pub unique_callees: usize,
    pub unique_call_sites: usize,
    pub max_depth_seen: u32,
    pub min_duration_ticks: Option<u64>,
    pub max_duration_ticks: Option<u64>,
    pub avg_duration_ticks: Option<f64>,
    /// Callee address → call count.
    pub call_counts: HashMap<u64, usize>,
}

impl CallStats {
    /// Compute statistics from a slice of call records.
    #[must_use]
    pub fn compute(records: &[CallRecord]) -> Self {
        let mut stats = Self::default();
        stats.total_calls = records.len();
        let mut callees = std::collections::HashSet::new();
        let mut sites = std::collections::HashSet::new();
        let mut total_ticks: u64 = 0;
        let mut paired_count = 0;

        for r in records {
            callees.insert(r.callee_address);
            sites.insert(r.call_site);
            if r.call_depth > stats.max_depth_seen {
                stats.max_depth_seen = r.call_depth;
            }
            *stats.call_counts.entry(r.callee_address).or_default() += 1;
            if let Some(d) = r.duration_ticks() {
                paired_count += 1;
                total_ticks += d;
                stats.min_duration_ticks = Some(match stats.min_duration_ticks {
                    None => d,
                    Some(prev) => prev.min(d),
                });
                stats.max_duration_ticks = Some(match stats.max_duration_ticks {
                    None => d,
                    Some(prev) => prev.max(d),
                });
            }
        }

        stats.paired_calls = paired_count;
        stats.unique_callees = callees.len();
        stats.unique_call_sites = sites.len();
        if paired_count > 0 {
            stats.avg_duration_ticks = Some(total_ticks as f64 / paired_count as f64);
        }
        stats
    }

    /// Return the top-N most frequently called addresses.
    #[must_use]
    pub fn top_callees(&self, n: usize) -> Vec<(u64, usize)> {
        let mut v: Vec<(u64, usize)> = self.call_counts.iter().map(|(&a, &c)| (a, c)).collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.1));
        v.truncate(n);
        v
    }
}

// ── TtdCallQuery ─────────────────────────────────────────────────────────────

/// Queries TTD traces for call/return events.
///
/// Wraps a `TtdTrace` and provides structured query methods.
#[derive(Debug)]
pub struct TtdCallQuery {
    trace: Arc<RwLock<TtdTrace>>,
    /// Cached call records from the last full scan.
    cache: Arc<RwLock<Vec<CallRecord>>>,
    /// Whether the cache is valid.
    cache_valid: Arc<RwLock<bool>>,
}

impl TtdCallQuery {
    /// Construct a new `TtdCallQuery` backed by `trace`.
    #[must_use]
    pub fn new(trace: TtdTrace) -> Self {
        Self {
            trace: Arc::new(RwLock::new(trace)),
            cache: Arc::new(RwLock::new(Vec::new())),
            cache_valid: Arc::new(RwLock::new(false)),
        }
    }

    /// Invalidate the internal call record cache.
    pub fn invalidate_cache(&self) {
        *self.cache_valid.write() = false;
    }

    /// Scan the trace and build the call-record cache.
    ///
    /// This walks all trace events and pairs calls with returns.
    pub fn build_cache(&self) {
        let trace = self.trace.read();
        let events = trace.all_events();
        let mut records: Vec<CallRecord> = Vec::new();
        // ONE stack PER THREAD. A time-travel trace interleaves every thread
        // into a single event stream, so a global stack let a return on one
        // thread pop a call made on another: the wrong record got the return
        // (and its duration), the right one stayed unpaired forever, and
        // `call_depth` measured the interleaving rather than the program.
        let mut stacks: HashMap<u32, Vec<usize>> = HashMap::new();

        for event in &events {
            match &event.kind {
                EventKind::Call { from, to } => {
                    let idx = records.len();
                    let stack = stacks.entry(event.thread_id).or_default();
                    records.push(CallRecord {
                        sequence: event.position.sequence,
                        // `as_u128` packs the sequence in the HIGH 64 bits, so
                        // `as u64` kept only the step and every record of a
                        // step-0 trace reported position 0. Pack both into the
                        // u64 the field actually is.
                        position: (event.position.sequence << 32)
                            | (event.position.step & 0xFFFF_FFFF),
                        callee_address: *to,
                        callee_name: None,
                        call_site: *from,
                        callee_module: None,
                        thread_id: event.thread_id,
                        call_depth: stack.len() as u32,
                        return_sequence: None,
                        return_address: 0,
                        arg0: None,
                        arg1: None,
                        arg2: None,
                        arg3: None,
                        return_value: None,
                    });
                    stack.push(idx);
                }
                EventKind::Return { to, .. } => {
                    if let Some(call_idx) = stacks
                        .get_mut(&event.thread_id)
                        .and_then(std::vec::Vec::pop)
                        && let Some(rec) = records.get_mut(call_idx) {
                            rec.return_sequence = Some(event.position.sequence);
                            rec.return_value = Some(*to);
                        }
                }
                _ => {}
            }
        }

        let mut c = self.cache.write();
        *c = records;
        *self.cache_valid.write() = true;
    }

    /// Ensure the cache is built.
    fn ensure_cache(&self) {
        if !*self.cache_valid.read() {
            self.build_cache();
        }
    }

    /// Execute a `CallQuery` and return matching records.
    #[must_use]
    pub fn execute(&self, query: &CallQuery) -> Vec<CallRecord> {
        self.ensure_cache();
        let cache = self.cache.read();
        let mut results: Vec<CallRecord> = cache.iter().filter(|r| query.matches(r)).cloned().collect();
        if let Some(limit) = query.limit {
            results.truncate(limit);
        }
        results
    }

    /// Return aggregate statistics for all call records matching `query`.
    #[must_use]
    pub fn stats(&self, query: &CallQuery) -> CallStats {
        let records = self.execute(query);
        CallStats::compute(&records)
    }

    /// Return the total number of call events in the trace.
    #[must_use]
    pub fn total_calls(&self) -> usize {
        self.ensure_cache();
        self.cache.read().len()
    }
}

// ── find_calls_to ─────────────────────────────────────────────────────────────

/// Find all call records targeting `callee_address` in the given query engine.
///
/// Equivalent to `engine.execute(&CallQuery::all().to_address(callee_address))`.
#[must_use]
pub fn find_calls_to(engine: &TtdCallQuery, callee_address: u64) -> Vec<CallRecord> {
    engine.execute(&CallQuery::all().to_address(callee_address))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(seq: u64, callee: u64, name: Option<&str>, site: u64, tid: u32, depth: u32) -> CallRecord {
        CallRecord {
            sequence: seq,
            position: seq,
            callee_address: callee,
            callee_name: name.map(str::to_string),
            call_site: site,
            callee_module: Some("ntdll.dll".to_string()),
            thread_id: tid,
            call_depth: depth,
            return_sequence: Some(seq + 100),
            return_address: site + 5,
            arg0: Some(0x1234),
            arg1: None,
            arg2: None,
            arg3: None,
            return_value: Some(0),
        }
    }

    #[test]
    fn test_call_query_address_filter() {
        let q = CallQuery::all().to_address(0x1000);
        let r1 = make_record(1, 0x1000, Some("NtCreateFile"), 0x500, 1, 0);
        let r2 = make_record(2, 0x2000, Some("NtReadFile"), 0x501, 1, 0);
        assert!(q.matches(&r1));
        assert!(!q.matches(&r2));
    }

    #[test]
    fn test_call_query_name_filter() {
        let q = CallQuery::all().to_name("ntread");
        let r = make_record(1, 0x2000, Some("NtReadFile"), 0x500, 1, 0);
        assert!(q.matches(&r));
    }

    #[test]
    fn test_call_query_thread_filter() {
        let q = CallQuery::all().on_thread(2);
        let r1 = make_record(1, 0x1000, None, 0x500, 1, 0);
        let r2 = make_record(2, 0x1000, None, 0x500, 2, 0);
        assert!(!q.matches(&r1));
        assert!(q.matches(&r2));
    }

    #[test]
    fn test_call_query_paired_only() {
        let q = CallQuery::all().paired();
        let mut r = make_record(1, 0x1000, None, 0x500, 1, 0);
        assert!(q.matches(&r));
        r.return_sequence = None;
        assert!(!q.matches(&r));
    }

    #[test]
    fn test_call_query_sequence_range() {
        let q = CallQuery { after_sequence: Some(100), before_sequence: Some(200), ..Default::default() };
        let r_in = make_record(150, 0x1000, None, 0x500, 1, 0);
        let r_out = make_record(250, 0x1000, None, 0x500, 1, 0);
        assert!(q.matches(&r_in));
        assert!(!q.matches(&r_out));
    }

    #[test]
    fn test_call_record_duration_ticks() {
        let r = make_record(100, 0x1000, None, 0x500, 1, 0);
        assert_eq!(r.duration_ticks(), Some(100));
    }

    #[test]
    fn test_call_record_unpaired_duration() {
        let mut r = make_record(100, 0x1000, None, 0x500, 1, 0);
        r.return_sequence = None;
        assert_eq!(r.duration_ticks(), None);
    }

    #[test]
    fn test_call_stats_compute() {
        let records = vec![
            make_record(1, 0x1000, None, 0x500, 1, 0),
            make_record(2, 0x1000, None, 0x501, 1, 1),
            make_record(3, 0x2000, None, 0x502, 1, 0),
        ];
        let stats = CallStats::compute(&records);
        assert_eq!(stats.total_calls, 3);
        assert_eq!(stats.unique_callees, 2);
        assert_eq!(stats.max_depth_seen, 1);
    }

    #[test]
    fn test_call_stats_top_callees() {
        let records = vec![
            make_record(1, 0x1000, None, 0x500, 1, 0),
            make_record(2, 0x1000, None, 0x501, 1, 0),
            make_record(3, 0x2000, None, 0x502, 1, 0),
        ];
        let stats = CallStats::compute(&records);
        let top = stats.top_callees(1);
        assert_eq!(top[0], (0x1000, 2));
    }

    #[test]
    fn test_call_record_display() {
        let r = make_record(42, 0x1000, Some("Foo"), 0x500, 3, 2);
        let s = format!("{r}");
        assert!(s.contains("Foo"));
        assert!(s.contains("tid=3"));
    }

    #[test]
    fn test_call_query_limit() {
        let records = [make_record(1, 0x1000, None, 0x500, 1, 0),
            make_record(2, 0x1000, None, 0x501, 1, 0),
            make_record(3, 0x1000, None, 0x502, 1, 0)];
        let q = CallQuery::all().to_address(0x1000).limit(2);
        let filtered: Vec<_> = records.iter().filter(|r| q.matches(r)).cloned().collect();
        // limit is enforced by execute(), not matches(); just check matches works.
        assert_eq!(filtered.len(), 3);
    }
}
