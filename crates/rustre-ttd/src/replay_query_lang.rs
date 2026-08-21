//! `replay_query_lang` — SQL-like query language for TTD traces.
//!
//! Provides a mini-language for filtering and sorting TTD trace events:
//!
//! * [`TtdQuery`] — parsed query tree.
//! * [`QueryClause`] — WHERE / ORDER BY / LIMIT / OFFSET clauses.
//! * [`QueryExecutor`] — evaluates a query against a live `TtdTrace`.
//! * [`PositionFilter`] — filter by trace position range.
//! * [`MemoryFilter`] — filter by memory address / size.
//! * [`CallFilter`] — filter by call source/target addresses.
//! * [`ThreadFilter`] — filter by thread ID.

use std::fmt;
use std::ops::Not;

use serde::{Deserialize, Serialize};

use crate::{EventKind, TraceEvent, TracePosition, TtdTrace};

// ─── Predicate leaf types ─────────────────────────────────────────────────────

/// Filter by trace position range `[start, end)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PositionFilter {
    /// Inclusive start position.  `None` means "from the beginning".
    pub start: Option<TracePosition>,
    /// Exclusive end position.  `None` means "to the end".
    pub end: Option<TracePosition>,
}

impl PositionFilter {
    /// Create a new `PositionFilter`.
    #[must_use]
    pub const fn new(start: Option<TracePosition>, end: Option<TracePosition>) -> Self {
        Self { start, end }
    }

    /// Accept all positions.
    #[must_use]
    pub const fn any() -> Self {
        Self {
            start: None,
            end: None,
        }
    }

    /// Accept only positions ≥ `start`.
    #[must_use]
    pub const fn from(start: TracePosition) -> Self {
        Self {
            start: Some(start),
            end: None,
        }
    }

    /// Accept only positions < `end`.
    #[must_use]
    pub const fn until(end: TracePosition) -> Self {
        Self {
            start: None,
            end: Some(end),
        }
    }

    /// Test whether `pos` passes this filter.
    #[must_use]
    pub fn matches(&self, pos: TracePosition) -> bool {
        if let Some(start) = self.start
            && pos < start {
                return false;
            }
        if let Some(end) = self.end
            && pos >= end {
                return false;
            }
        true
    }
}

/// Filter by memory address range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryFilter {
    /// Inclusive lower address bound.  `None` = no lower bound.
    pub addr_lo: Option<u64>,
    /// Exclusive upper address bound.  `None` = no upper bound.
    pub addr_hi: Option<u64>,
    /// Minimum number of bytes accessed.  `None` = no minimum.
    pub min_size: Option<usize>,
    /// Whether to match reads, writes, or both.
    pub access_kind: MemAccessKind,
}

/// Which direction of memory access to match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemAccessKind {
    /// Match only memory reads.
    Read,
    /// Match only memory writes.
    Write,
    /// Match both reads and writes.
    Any,
}

impl MemoryFilter {
    /// Create a filter that accepts any memory access.
    #[must_use]
    pub const fn any() -> Self {
        Self {
            addr_lo: None,
            addr_hi: None,
            min_size: None,
            access_kind: MemAccessKind::Any,
        }
    }

    /// Create a filter for writes to a specific address range.
    #[must_use]
    pub const fn write_range(lo: u64, hi: u64) -> Self {
        Self {
            addr_lo: Some(lo),
            addr_hi: Some(hi),
            min_size: None,
            access_kind: MemAccessKind::Write,
        }
    }

    /// Create a filter for reads from a specific address range.
    #[must_use]
    pub const fn read_range(lo: u64, hi: u64) -> Self {
        Self {
            addr_lo: Some(lo),
            addr_hi: Some(hi),
            min_size: None,
            access_kind: MemAccessKind::Read,
        }
    }

    /// Test whether an event passes this filter.
    #[must_use]
    pub fn matches(&self, event: &TraceEvent) -> bool {
        match &event.kind {
            EventKind::MemRead { addr, len } => {
                if self.access_kind == MemAccessKind::Write {
                    return false;
                }
                self.addr_matches(*addr) && self.size_ok(*len)
            }
            EventKind::MemWrite { addr, data } => {
                if self.access_kind == MemAccessKind::Read {
                    return false;
                }
                self.addr_matches(*addr) && self.size_ok(data.len())
            }
            _ => false,
        }
    }

    const fn addr_matches(&self, addr: u64) -> bool {
        if let Some(lo) = self.addr_lo
            && addr < lo {
                return false;
            }
        if let Some(hi) = self.addr_hi
            && addr >= hi {
                return false;
            }
        true
    }

    fn size_ok(&self, size: usize) -> bool {
        self.min_size.is_none_or(|ms| size >= ms)
    }
}

/// Filter by call instruction source/target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallFilter {
    /// Required caller address.  `None` = any.
    pub from: Option<u64>,
    /// Required callee address.  `None` = any.
    pub to: Option<u64>,
    /// Whether to also match Return events.
    pub include_returns: bool,
}

impl CallFilter {
    /// Create a filter that accepts any call.
    #[must_use]
    pub const fn any() -> Self {
        Self {
            from: None,
            to: None,
            include_returns: false,
        }
    }

    /// Create a filter that matches calls to a specific target.
    #[must_use]
    pub const fn to_target(target: u64) -> Self {
        Self {
            from: None,
            to: Some(target),
            include_returns: false,
        }
    }

    /// Create a filter that matches calls from a specific site.
    #[must_use]
    pub const fn from_site(site: u64) -> Self {
        Self {
            from: Some(site),
            to: None,
            include_returns: false,
        }
    }

    /// Test whether `event` passes this filter.
    #[must_use]
    pub fn matches(&self, event: &TraceEvent) -> bool {
        match &event.kind {
            EventKind::Call { from, to } => {
                let from_ok = self.from.is_none_or(|f| f == *from);
                let to_ok = self.to.is_none_or(|t| t == *to);
                from_ok && to_ok
            }
            EventKind::Return { from, to } if self.include_returns => {
                let from_ok = self.from.is_none_or(|f| f == *from);
                let to_ok = self.to.is_none_or(|t| t == *to);
                from_ok && to_ok
            }
            _ => false,
        }
    }
}

/// Filter by OS thread identifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadFilter {
    /// The exact TID to match.  `None` = any thread.
    pub tid: Option<u32>,
    /// If `true`, the filter is negated (match all threads *except* `tid`).
    pub negate: bool,
}

impl ThreadFilter {
    /// Accept events from any thread.
    #[must_use]
    pub const fn any() -> Self {
        Self {
            tid: None,
            negate: false,
        }
    }

    /// Accept events from `tid` only.
    #[must_use]
    pub const fn only(tid: u32) -> Self {
        Self {
            tid: Some(tid),
            negate: false,
        }
    }

    /// Reject events from `tid`, accept all others.
    #[must_use]
    pub const fn exclude(tid: u32) -> Self {
        Self {
            tid: Some(tid),
            negate: true,
        }
    }

    /// Test whether `event` passes this filter.
    #[must_use]
    pub fn matches(&self, event: &TraceEvent) -> bool {
        self.tid.map_or(!self.negate, |tid| {
                let matched = event.thread_id == tid;
                if self.negate { !matched } else { matched }
            })
    }
}

// ─── EventTypeFilter ─────────────────────────────────────────────────────────

/// Filter events by their discriminant (kind name).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventTypeFilter {
    /// Kind names to accept (e.g. `"Call"`, `"MemWrite"`).
    pub kind_names: Vec<String>,
}

impl EventTypeFilter {
    /// Accept events of any kind.
    #[must_use]
    pub const fn any() -> Self {
        Self {
            kind_names: Vec::new(),
        }
    }

    /// Accept only events whose kind matches one of `names`.
    #[must_use]
    pub fn of_kinds(names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            kind_names: names.into_iter().map(Into::into).collect(),
        }
    }

    /// Test whether `event` passes this filter.
    #[must_use]
    pub fn matches(&self, event: &TraceEvent) -> bool {
        if self.kind_names.is_empty() {
            return true;
        }
        let name = event_kind_name(&event.kind);
        self.kind_names.iter().any(|k| k.as_str() == name)
    }
}

const fn event_kind_name(kind: &EventKind) -> &'static str {
    match kind {
        EventKind::MemRead { .. } => "MemRead",
        EventKind::MemWrite { .. } => "MemWrite",
        EventKind::Call { .. } => "Call",
        EventKind::Return { .. } => "Return",
        EventKind::SyscallEnter { .. } => "SyscallEnter",
        EventKind::SyscallExit { .. } => "SyscallExit",
        EventKind::Exception { .. } => "Exception",
        EventKind::ThreadCreate { .. } => "ThreadCreate",
        EventKind::ThreadExit { .. } => "ThreadExit",
        EventKind::Breakpoint { .. } => "Breakpoint",
    }
}

// ─── QueryClause ─────────────────────────────────────────────────────────────

/// A single clause that can appear in a [`TtdQuery`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryClause {
    /// `WHERE position IN [start, end)`
    WherePosition(PositionFilter),
    /// `WHERE memory <op> addr_range`
    WhereMemory(MemoryFilter),
    /// `WHERE call from/to target`
    WhereCall(CallFilter),
    /// `WHERE thread = tid`
    WhereThread(ThreadFilter),
    /// `WHERE event_kind IN [...]`
    WhereEventType(EventTypeFilter),
    /// `ORDER BY position ASC/DESC`
    OrderByPosition { descending: bool },
    /// `LIMIT n`
    Limit(usize),
    /// `OFFSET n`
    Offset(usize),
    /// Logical AND of two sub-clauses (applied to WHERE predicates only).
    And(Box<Self>, Box<Self>),
    /// Logical OR of two sub-clauses (applied to WHERE predicates only).
    Or(Box<Self>, Box<Self>),
    /// Logical NOT of a sub-clause.
    Not(Box<Self>),
}

impl QueryClause {
    /// Return `true` if this clause is a WHERE predicate that can be evaluated
    /// per-event.
    #[must_use]
    pub const fn is_predicate(&self) -> bool {
        matches!(
            self,
            Self::WherePosition(_)
                | Self::WhereMemory(_)
                | Self::WhereCall(_)
                | Self::WhereThread(_)
                | Self::WhereEventType(_)
                | Self::And(_, _)
                | Self::Or(_, _)
                | Self::Not(_)
        )
    }

    /// Evaluate this clause as a per-event predicate.
    ///
    /// Returns `true` if the event passes, `false` otherwise.
    /// Non-predicate clauses (LIMIT, OFFSET, ORDER BY) always return `true`.
    #[must_use]
    pub fn eval(&self, event: &TraceEvent) -> bool {
        match self {
            Self::WherePosition(f) => f.matches(event.position),
            Self::WhereMemory(f) => f.matches(event),
            Self::WhereCall(f) => f.matches(event),
            Self::WhereThread(f) => f.matches(event),
            Self::WhereEventType(f) => f.matches(event),
            Self::And(a, b) => a.eval(event) && b.eval(event),
            Self::Or(a, b) => a.eval(event) || b.eval(event),
            Self::Not(inner) => !inner.eval(event),
            _ => true, // non-predicate clauses don't filter
        }
    }

    /// Convenience builder: `self AND other`.
    #[must_use]
    pub fn and(self, other: Self) -> Self {
        Self::And(Box::new(self), Box::new(other))
    }

    /// Convenience builder: `self OR other`.
    #[must_use]
    pub fn or(self, other: Self) -> Self {
        Self::Or(Box::new(self), Box::new(other))
    }

}

impl Not for QueryClause {
    type Output = Self;
    /// Convenience builder: `NOT self`.
    fn not(self) -> Self {
        Self::Not(Box::new(self))
    }
}

impl fmt::Display for QueryClause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WherePosition(_) => write!(f, "WHERE position"),
            Self::WhereMemory(_) => write!(f, "WHERE memory"),
            Self::WhereCall(_) => write!(f, "WHERE call"),
            Self::WhereThread(_) => write!(f, "WHERE thread"),
            Self::WhereEventType(_) => write!(f, "WHERE event_type"),
            Self::OrderByPosition { descending } => {
                write!(
                    f,
                    "ORDER BY position {}",
                    if *descending { "DESC" } else { "ASC" }
                )
            }
            Self::Limit(n) => write!(f, "LIMIT {n}"),
            Self::Offset(n) => write!(f, "OFFSET {n}"),
            Self::And(_, _) => write!(f, "AND"),
            Self::Or(_, _) => write!(f, "OR"),
            Self::Not(_) => write!(f, "NOT"),
        }
    }
}

// ─── TtdQuery ─────────────────────────────────────────────────────────────────

/// A complete query over a TTD trace.
///
/// Queries are built by chaining clauses using the builder API, then executed
/// via [`QueryExecutor`].
///
/// ```text
/// TtdQuery::new()
///     .where_position(start, end)
///     .where_thread(1)
///     .where_event_kinds(["Call", "Return"])
///     .order_desc()
///     .limit(100)
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TtdQuery {
    /// All clauses in the order they were added.
    clauses: Vec<QueryClause>,
    /// Cached LIMIT value extracted from clauses.
    limit: Option<usize>,
    /// Cached OFFSET value extracted from clauses.
    offset: Option<usize>,
    /// Cached ORDER BY descending flag.
    order_desc: bool,
}

impl TtdQuery {
    /// Create an empty query that matches all events.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a position range predicate.
    #[must_use]
    pub fn where_position(mut self, start: TracePosition, end: TracePosition) -> Self {
        self.clauses
            .push(QueryClause::WherePosition(PositionFilter::new(
                Some(start),
                Some(end),
            )));
        self
    }

    /// Add a lower-bound position predicate (`position >= start`).
    #[must_use]
    pub fn where_position_from(mut self, start: TracePosition) -> Self {
        self.clauses
            .push(QueryClause::WherePosition(PositionFilter::from(start)));
        self
    }

    /// Add an upper-bound position predicate (`position < end`).
    #[must_use]
    pub fn where_position_until(mut self, end: TracePosition) -> Self {
        self.clauses
            .push(QueryClause::WherePosition(PositionFilter::until(end)));
        self
    }

    /// Add a memory filter.
    #[must_use]
    pub fn where_memory(mut self, filter: MemoryFilter) -> Self {
        self.clauses.push(QueryClause::WhereMemory(filter));
        self
    }

    /// Add a call filter.
    #[must_use]
    pub fn where_call(mut self, filter: CallFilter) -> Self {
        self.clauses.push(QueryClause::WhereCall(filter));
        self
    }

    /// Add a thread filter by TID.
    #[must_use]
    pub fn where_thread(mut self, tid: u32) -> Self {
        self.clauses
            .push(QueryClause::WhereThread(ThreadFilter::only(tid)));
        self
    }

    /// Add an event-type filter.
    #[must_use]
    pub fn where_event_kinds(mut self, kinds: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.clauses
            .push(QueryClause::WhereEventType(EventTypeFilter::of_kinds(
                kinds,
            )));
        self
    }

    /// Add an arbitrary clause.
    #[must_use]
    pub fn with_clause(mut self, clause: QueryClause) -> Self {
        match &clause {
            QueryClause::Limit(n) => self.limit = Some(*n),
            QueryClause::Offset(n) => self.offset = Some(*n),
            QueryClause::OrderByPosition { descending } => self.order_desc = *descending,
            _ => {}
        }
        self.clauses.push(clause);
        self
    }

    /// Sort results in ascending position order (default).
    #[must_use]
    pub fn order_asc(mut self) -> Self {
        self.order_desc = false;
        self.clauses
            .retain(|c| !matches!(c, QueryClause::OrderByPosition { .. }));
        self.clauses
            .push(QueryClause::OrderByPosition { descending: false });
        self
    }

    /// Sort results in descending position order.
    #[must_use]
    pub fn order_desc(mut self) -> Self {
        self.order_desc = true;
        self.clauses
            .retain(|c| !matches!(c, QueryClause::OrderByPosition { .. }));
        self.clauses
            .push(QueryClause::OrderByPosition { descending: true });
        self
    }

    /// Set a result limit.
    #[must_use]
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self.clauses.retain(|c| !matches!(c, QueryClause::Limit(_)));
        self.clauses.push(QueryClause::Limit(n));
        self
    }

    /// Set a result offset.
    #[must_use]
    pub fn offset(mut self, n: usize) -> Self {
        self.offset = Some(n);
        self.clauses
            .retain(|c| !matches!(c, QueryClause::Offset(_)));
        self.clauses.push(QueryClause::Offset(n));
        self
    }

    /// Return all clauses in this query.
    #[must_use]
    pub fn clauses(&self) -> &[QueryClause] {
        &self.clauses
    }

    /// Return `true` if the query has no predicates (matches everything).
    #[must_use]
    pub fn is_match_all(&self) -> bool {
        !self.clauses.iter().any(QueryClause::is_predicate)
    }

    /// Return the effective limit, if set.
    #[must_use]
    pub const fn get_limit(&self) -> Option<usize> {
        self.limit
    }

    /// Return the effective offset, if set.
    #[must_use]
    pub const fn get_offset(&self) -> Option<usize> {
        self.offset
    }

    /// Return `true` if results should be sorted descending.
    #[must_use]
    pub const fn is_order_desc(&self) -> bool {
        self.order_desc
    }
}

impl fmt::Display for TtdQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TtdQuery {{")?;
        for (i, c) in self.clauses.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{c}")?;
        }
        write!(f, "}}")
    }
}

// ─── QueryResult ─────────────────────────────────────────────────────────────

/// The result of executing a [`TtdQuery`].
#[derive(Debug, Clone, Default)]
pub struct QueryResult {
    /// Matched events.
    pub events: Vec<TraceEvent>,
    /// Total number of events that passed the WHERE predicates (before
    /// LIMIT/OFFSET).
    pub total_matched: usize,
    /// Number of events scanned.
    pub scanned: usize,
}

impl QueryResult {
    /// Create an empty result.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return the number of events in the result set.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    /// Return `true` if the result set is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Return the first event in the result, if any.
    #[must_use]
    pub fn first(&self) -> Option<&TraceEvent> {
        self.events.first()
    }

    /// Return the last event in the result, if any.
    #[must_use]
    pub fn last(&self) -> Option<&TraceEvent> {
        self.events.last()
    }
}

// ─── QueryExecutor ────────────────────────────────────────────────────────────

/// Executes a [`TtdQuery`] against a live [`TtdTrace`].
///
/// The executor:
/// 1. Scans all events in the trace.
/// 2. Applies WHERE predicates (all clauses that are predicates must pass).
/// 3. Applies ORDER BY.
/// 4. Applies OFFSET then LIMIT.
pub struct QueryExecutor<'a> {
    trace: &'a TtdTrace,
}

impl<'a> QueryExecutor<'a> {
    /// Create a new executor bound to `trace`.
    #[must_use]
    pub const fn new(trace: &'a TtdTrace) -> Self {
        Self { trace }
    }

    /// Execute `query` and return a [`QueryResult`].
    #[must_use]
    pub fn execute(&self, query: &TtdQuery) -> QueryResult {
        let all_events = self.trace.all_events();
        let scanned = all_events.len();

        // Collect predicate clauses.
        let predicates: Vec<&QueryClause> = query
            .clauses()
            .iter()
            .filter(|c| c.is_predicate())
            .collect();

        // Filter.
        let mut matched: Vec<TraceEvent> = all_events
            .into_iter()
            .filter(|e| predicates.iter().all(|p| p.eval(e)))
            .collect();

        let total_matched = matched.len();

        // Sort.
        if query.is_order_desc() {
            matched.sort_unstable_by_key(|b| std::cmp::Reverse(b.position));
        } else {
            matched.sort_unstable_by_key(|e| e.position);
        }

        // Offset.
        let offset = query.get_offset().unwrap_or(0);
        if offset > 0 && offset < matched.len() {
            matched = matched.into_iter().skip(offset).collect();
        } else if offset >= matched.len() {
            matched.clear();
        }

        // Limit.
        if let Some(limit) = query.get_limit() {
            matched.truncate(limit);
        }

        QueryResult {
            events: matched,
            total_matched,
            scanned,
        }
    }

    /// Execute multiple queries and return their results in order.
    #[must_use]
    pub fn execute_batch(&self, queries: &[TtdQuery]) -> Vec<QueryResult> {
        queries.iter().map(|q| self.execute(q)).collect()
    }

    /// Count events that match `query` without materializing the result.
    #[must_use]
    pub fn count(&self, query: &TtdQuery) -> usize {
        let all_events = self.trace.all_events();
        let predicates: Vec<&QueryClause> = query
            .clauses()
            .iter()
            .filter(|c| c.is_predicate())
            .collect();
        all_events
            .iter()
            .filter(|e| predicates.iter().all(|p| p.eval(e)))
            .count()
    }

    /// Return the first event matching `query`, if any.
    #[must_use]
    pub fn find_first(&self, query: &TtdQuery) -> Option<TraceEvent> {
        let predicates: Vec<&QueryClause> = query
            .clauses()
            .iter()
            .filter(|c| c.is_predicate())
            .collect();
        self.trace
            .all_events()
            .into_iter()
            .find(|e| predicates.iter().all(|p| p.eval(e)))
    }

    /// Return the last event matching `query`, if any.
    #[must_use]
    pub fn find_last(&self, query: &TtdQuery) -> Option<TraceEvent> {
        let predicates: Vec<&QueryClause> = query
            .clauses()
            .iter()
            .filter(|c| c.is_predicate())
            .collect();
        self.trace
            .all_events()
            .into_iter().rfind(|e| predicates.iter().all(|p| p.eval(e)))
    }

    /// Test whether any event in the trace matches `query`.
    #[must_use]
    pub fn any_matches(&self, query: &TtdQuery) -> bool {
        self.find_first(query).is_some()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TraceEvent, TracePosition, build_multi_thread_trace, build_test_trace};

    fn call_pos(seq: u64) -> TraceEvent {
        TraceEvent {
            position: TracePosition::new(seq, 0),
            thread_id: 1,
            kind: EventKind::Call {
                from: 0x1000,
                to: 0x2000 + seq,
            },
        }
    }

    fn mem_write_pos(seq: u64, tid: u32) -> TraceEvent {
        TraceEvent {
            position: TracePosition::new(seq, 0),
            thread_id: tid,
            kind: EventKind::MemWrite {
                addr: 0x3000 + seq,
                data: vec![0xAA, 0xBB],
            },
        }
    }

    // ── PositionFilter ───────────────────────────────────────────────────

    #[test]
    fn test_position_filter_any() {
        let f = PositionFilter::any();
        assert!(f.matches(TracePosition::new(999, 999)));
    }

    #[test]
    fn test_position_filter_range() {
        let f = PositionFilter::new(
            Some(TracePosition::new(5, 0)),
            Some(TracePosition::new(10, 0)),
        );
        assert!(f.matches(TracePosition::new(7, 0)));
        assert!(!f.matches(TracePosition::new(4, 0)));
        assert!(!f.matches(TracePosition::new(10, 0))); // exclusive end
    }

    #[test]
    fn test_position_filter_from() {
        let f = PositionFilter::from(TracePosition::new(50, 0));
        assert!(f.matches(TracePosition::new(50, 0)));
        assert!(!f.matches(TracePosition::new(49, 0)));
    }

    #[test]
    fn test_position_filter_until() {
        let f = PositionFilter::until(TracePosition::new(10, 0));
        assert!(f.matches(TracePosition::new(9, 9)));
        assert!(!f.matches(TracePosition::new(10, 0)));
    }

    // ── MemoryFilter ─────────────────────────────────────────────────────

    #[test]
    fn test_memory_filter_write_range_match() {
        let f = MemoryFilter::write_range(0x1000, 0x2000);
        let event = mem_write_pos(0, 1);
        // addr 0x3000 is outside [0x1000, 0x2000)
        assert!(!f.matches(&event));
    }

    #[test]
    fn test_memory_filter_write_in_range() {
        let f = MemoryFilter::write_range(0x3000, 0x4000);
        let event = mem_write_pos(0, 1); // addr 0x3000
        assert!(f.matches(&event));
    }

    #[test]
    fn test_memory_filter_read_only_rejects_write() {
        let f = MemoryFilter::read_range(0x3000, 0x4000);
        let event = mem_write_pos(0, 1);
        assert!(!f.matches(&event));
    }

    #[test]
    fn test_memory_filter_any() {
        let f = MemoryFilter::any();
        let event = mem_write_pos(5, 1);
        assert!(f.matches(&event));
    }

    // ── CallFilter ───────────────────────────────────────────────────────

    #[test]
    fn test_call_filter_to_target() {
        let f = CallFilter::to_target(0x2005);
        let event = call_pos(5); // to = 0x2005
        assert!(f.matches(&event));
    }

    #[test]
    fn test_call_filter_to_target_miss() {
        let f = CallFilter::to_target(0x9999);
        let event = call_pos(5);
        assert!(!f.matches(&event));
    }

    #[test]
    fn test_call_filter_from_site() {
        let f = CallFilter::from_site(0x1000);
        let event = call_pos(1);
        assert!(f.matches(&event));
    }

    #[test]
    fn test_call_filter_any_matches_call() {
        let f = CallFilter::any();
        let event = call_pos(1);
        assert!(f.matches(&event));
    }

    // ── ThreadFilter ─────────────────────────────────────────────────────

    #[test]
    fn test_thread_filter_only() {
        let f = ThreadFilter::only(1);
        let event = call_pos(1);
        assert!(f.matches(&event));
    }

    #[test]
    fn test_thread_filter_only_miss() {
        let f = ThreadFilter::only(99);
        let event = call_pos(1);
        assert!(!f.matches(&event));
    }

    #[test]
    fn test_thread_filter_exclude() {
        let f = ThreadFilter::exclude(1);
        let event = call_pos(1);
        assert!(!f.matches(&event));
        let event2 = mem_write_pos(0, 2);
        assert!(f.matches(&event2));
    }

    // ── QueryClause ──────────────────────────────────────────────────────

    #[test]
    fn test_clause_and_short_circuits() {
        let c = QueryClause::WhereThread(ThreadFilter::only(99)).and(QueryClause::WhereEventType(
            EventTypeFilter::of_kinds(["Call"]),
        ));
        let event = call_pos(1); // tid=1, kind=Call
        assert!(!c.eval(&event)); // thread 99 fails
    }

    #[test]
    fn test_clause_or() {
        let c = QueryClause::WhereThread(ThreadFilter::only(99)).or(QueryClause::WhereEventType(
            EventTypeFilter::of_kinds(["Call"]),
        ));
        let event = call_pos(1); // tid=1, kind=Call — passes via OR right side
        assert!(c.eval(&event));
    }

    #[test]
    fn test_clause_not() {
        let c = QueryClause::WhereThread(ThreadFilter::only(1)).not();
        let event = call_pos(1); // tid=1 — normally passes; NOT inverts
        assert!(!c.eval(&event));
    }

    // ── TtdQuery ─────────────────────────────────────────────────────────

    #[test]
    fn test_query_builder_fluent() {
        let q = TtdQuery::new()
            .where_thread(1)
            .where_event_kinds(["Call"])
            .limit(50)
            .offset(5)
            .order_desc();
        assert_eq!(q.get_limit(), Some(50));
        assert_eq!(q.get_offset(), Some(5));
        assert!(q.is_order_desc());
    }

    #[test]
    fn test_query_is_match_all() {
        let q = TtdQuery::new().limit(100).order_asc();
        assert!(q.is_match_all());
    }

    #[test]
    fn test_query_not_match_all_with_predicate() {
        let q = TtdQuery::new().where_thread(1);
        assert!(!q.is_match_all());
    }

    // ── QueryExecutor ────────────────────────────────────────────────────

    #[test]
    fn test_executor_match_all() {
        let trace = build_test_trace(20);
        let ex = QueryExecutor::new(&trace);
        let result = ex.execute(&TtdQuery::new());
        assert_eq!(result.len(), 20);
        assert_eq!(result.total_matched, 20);
        assert_eq!(result.scanned, 20);
    }

    #[test]
    fn test_executor_where_position() {
        let trace = build_test_trace(20);
        let ex = QueryExecutor::new(&trace);
        let q = TtdQuery::new().where_position(TracePosition::new(5, 0), TracePosition::new(10, 0));
        let result = ex.execute(&q);
        assert_eq!(result.len(), 5); // seq 5,6,7,8,9
        assert!(
            result
                .events
                .iter()
                .all(|e| e.position.sequence >= 5 && e.position.sequence < 10)
        );
    }

    #[test]
    fn test_executor_where_thread() {
        let trace = build_multi_thread_trace(20);
        let ex = QueryExecutor::new(&trace);
        let q = TtdQuery::new().where_thread(1);
        let result = ex.execute(&q);
        assert!(result.events.iter().all(|e| e.thread_id == 1));
    }

    #[test]
    fn test_executor_where_event_kind_mem_write() {
        let trace = build_test_trace(10);
        let ex = QueryExecutor::new(&trace);
        let q = TtdQuery::new().where_event_kinds(["MemWrite"]);
        let result = ex.execute(&q);
        assert!(
            result
                .events
                .iter()
                .all(|e| matches!(e.kind, EventKind::MemWrite { .. }))
        );
    }

    #[test]
    fn test_executor_limit() {
        let trace = build_test_trace(50);
        let ex = QueryExecutor::new(&trace);
        let q = TtdQuery::new().limit(10);
        let result = ex.execute(&q);
        assert_eq!(result.len(), 10);
        assert_eq!(result.total_matched, 50);
    }

    #[test]
    fn test_executor_offset() {
        let trace = build_test_trace(20);
        let ex = QueryExecutor::new(&trace);
        let q = TtdQuery::new().offset(15);
        let result = ex.execute(&q);
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn test_executor_order_desc() {
        let trace = build_test_trace(5);
        let ex = QueryExecutor::new(&trace);
        let q = TtdQuery::new().order_desc();
        let result = ex.execute(&q);
        // Events should be in descending order.
        for w in result.events.windows(2) {
            assert!(w[0].position >= w[1].position);
        }
    }

    #[test]
    fn test_executor_count() {
        let trace = build_test_trace(20);
        let ex = QueryExecutor::new(&trace);
        let q = TtdQuery::new().where_event_kinds(["MemRead"]);
        let c = ex.count(&q);
        assert!(c > 0 && c <= 20);
    }

    #[test]
    fn test_executor_find_first_last() {
        let trace = build_test_trace(10);
        let ex = QueryExecutor::new(&trace);
        let q = TtdQuery::new().where_event_kinds(["MemRead"]);
        let first = ex.find_first(&q);
        let last = ex.find_last(&q);
        assert!(first.is_some());
        assert!(last.is_some());
        let first = first.unwrap();
        let last = last.unwrap();
        assert!(first.position <= last.position);
    }

    #[test]
    fn test_executor_any_matches() {
        let trace = build_test_trace(5);
        let ex = QueryExecutor::new(&trace);
        assert!(ex.any_matches(&TtdQuery::new().where_event_kinds(["MemRead"])));
        assert!(!ex.any_matches(&TtdQuery::new().where_call(CallFilter::to_target(0))));
    }

    #[test]
    fn test_executor_batch() {
        let trace = build_test_trace(10);
        let ex = QueryExecutor::new(&trace);
        let q1 = TtdQuery::new().where_event_kinds(["MemRead"]);
        let q2 = TtdQuery::new().where_event_kinds(["MemWrite"]);
        let results = ex.execute_batch(&[q1, q2]);
        assert_eq!(results.len(), 2);
        assert!(results[0].total_matched > 0);
        assert!(results[1].total_matched > 0);
    }

    #[test]
    fn test_memory_filter_min_size() {
        let mut f = MemoryFilter::any();
        f.min_size = Some(3);
        // data len = 2 — should fail
        let event = mem_write_pos(0, 1);
        assert!(!f.matches(&event));
        // data len = 3
        let event2 = TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::MemWrite {
                addr: 0x1000,
                data: vec![1, 2, 3],
            },
        };
        assert!(f.matches(&event2));
    }

    #[test]
    fn test_call_filter_include_returns() {
        let f = CallFilter {
            from: None,
            to: None,
            include_returns: true,
        };
        let ret_event = TraceEvent {
            position: TracePosition::new(5, 0),
            thread_id: 1,
            kind: EventKind::Return {
                from: 0x2000,
                to: 0x1000,
            },
        };
        assert!(f.matches(&ret_event));
    }

    #[test]
    fn test_event_type_filter_multiple_kinds() {
        let f = EventTypeFilter::of_kinds(["Call", "Return"]);
        let call_ev = call_pos(1);
        let ret_ev = TraceEvent {
            position: TracePosition::new(2, 0),
            thread_id: 1,
            kind: EventKind::Return {
                from: 0x2000,
                to: 0x1000,
            },
        };
        assert!(f.matches(&call_ev));
        assert!(f.matches(&ret_ev));
        let mem_ev = mem_write_pos(3, 1);
        assert!(!f.matches(&mem_ev));
    }

    #[test]
    fn test_query_display() {
        let q = TtdQuery::new().where_thread(1).limit(5);
        let s = q.to_string();
        assert!(s.contains("WHERE thread"));
        assert!(s.contains("LIMIT"));
    }
}
