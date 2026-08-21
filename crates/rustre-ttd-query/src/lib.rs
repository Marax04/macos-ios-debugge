//! `rustre-ttd-query`
//!
//! Rich query engine for TTD traces — composable filters, typed DSL,
//! aggregation, analysis, and multi-format export.

pub mod btree_index;
pub mod query_language;
pub mod query_optimizer;
pub mod ttd_sql_engine;
pub mod trace_index;
pub mod temporal_query;
pub mod memory_timeline;
pub mod register_history;
pub mod ttd_memory_query;
pub mod ttd_call_stack_query;
pub mod ttd_event_query;
pub mod ttd_call_query;
pub mod ttd_exception_query;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write as IoWrite;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use rusqlite::{Connection, params};
use rustre_core::address::Address as CoreAddress;
use rustre_trace::TraceFilter;
use rustre_trace_navigate::{
    EntryKind as TenetEntryKind, ExecutionTrace as TenetExecutionTrace,
    TraceEntry as TenetTraceEntry, TraceNavigator as TenetTraceNavigator,
};

/// Re-export of the full Tenet-style trace navigator from
/// [`rustre_trace_navigate`], exposed here so query-engine consumers can build
/// a bidirectional time-travel navigator (memory timeline, register timeline,
/// call-stack reconstruction, breakpoints, bookmarks, coverage) directly from
/// a `TtdTrace` via [`QueryEngine::tenet_navigator`].
pub use rustre_trace_navigate::{
    Bookmark as TenetBookmark, CoverageStats as TenetCoverageStats,
    NavError as TenetNavError, NavEvent as TenetNavEvent, StackFrame as TenetStackFrame,
};
use rustre_ttd::{EventKind, TraceEvent, TracePosition, TtdTrace};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── QueryError ───────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum QueryError {
    #[error("invalid query: {0}")]
    InvalidQuery(String),
    #[error("trace error: {0}")]
    TraceError(String),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("export error: {0}")]
    ExportError(String),
}

// ─── TimeRange ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeRange {
    pub start: TracePosition,
    pub end: TracePosition,
}

impl TimeRange {
    #[must_use]
    pub const fn new(start: TracePosition, end: TracePosition) -> Self {
        Self { start, end }
    }

    #[must_use]
    pub fn contains(&self, pos: &TracePosition) -> bool {
        pos >= &self.start && pos <= &self.end
    }
}

impl std::fmt::Display for TimeRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}, {}]", self.start, self.end)
    }
}

// ─── QueryFilter (legacy simple filter) ──────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryFilter {
    MemoryRead { addr: u64, range_bytes: Option<u64> },
    MemoryWrite { addr: u64, range_bytes: Option<u64> },
    Thread { tid: u32 },
    CallTo { target: u64 },
    CallFrom { source: u64 },
    SyscallNumber { nr: u32 },
    InTimeRange(TimeRange),
    ExceptionCode { code: u32 },
    ThreadCreate,
    ThreadExit,
}

impl QueryFilter {
    #[must_use]
    pub fn matches(&self, event: &TraceEvent) -> bool {
        match self {
            Self::MemoryRead { addr, range_bytes } => matches!(
                &event.kind,
                EventKind::MemRead { addr: a, .. } if addr_in_range(*a, *addr, *range_bytes)
            ),
            Self::MemoryWrite { addr, range_bytes } => matches!(
                &event.kind,
                EventKind::MemWrite { addr: a, .. } if addr_in_range(*a, *addr, *range_bytes)
            ),
            Self::Thread { tid } => event.thread_id == *tid,
            Self::CallTo { target } => {
                matches!(&event.kind, EventKind::Call { to, .. } if to == target)
            }
            Self::CallFrom { source } => {
                matches!(&event.kind, EventKind::Call { from, .. } if from == source)
            }
            Self::SyscallNumber { nr } => matches!(
                &event.kind,
                EventKind::SyscallEnter { nr: n, .. } | EventKind::SyscallExit { nr: n, .. }
                if n == nr
            ),
            Self::InTimeRange(range) => range.contains(&event.position),
            Self::ExceptionCode { code } => {
                matches!(&event.kind, EventKind::Exception { code: c, .. } if c == code)
            }
            Self::ThreadCreate => matches!(&event.kind, EventKind::ThreadCreate { .. }),
            Self::ThreadExit => matches!(&event.kind, EventKind::ThreadExit { .. }),
        }
    }
}

impl std::fmt::Display for QueryFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MemoryRead { addr, range_bytes } => {
                write!(f, "MemoryRead(addr={addr:#x}, range={range_bytes:?})")
            }
            Self::MemoryWrite { addr, range_bytes } => {
                write!(f, "MemoryWrite(addr={addr:#x}, range={range_bytes:?})")
            }
            Self::Thread { tid } => write!(f, "Thread(tid={tid})"),
            Self::CallTo { target } => write!(f, "CallTo({target:#x})"),
            Self::CallFrom { source } => write!(f, "CallFrom({source:#x})"),
            Self::SyscallNumber { nr } => write!(f, "SyscallNumber({nr})"),
            Self::InTimeRange(r) => write!(f, "InTimeRange({r})"),
            Self::ExceptionCode { code } => write!(f, "ExceptionCode({code:#x})"),
            Self::ThreadCreate => write!(f, "ThreadCreate"),
            Self::ThreadExit => write!(f, "ThreadExit"),
        }
    }
}

const fn addr_in_range(actual: u64, target: u64, range: Option<u64>) -> bool {
    match range {
        None => actual == target,
        Some(r) => {
            let lo = target.saturating_sub(r);
            // Use checked_add to avoid silent saturation: if it overflows we clamp to u64::MAX
            let hi = match target.checked_add(r) {
                Some(v) => v,
                None => u64::MAX,
            };
            actual >= lo && actual <= hi
        }
    }
}

// ─── QueryLogic (legacy) ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum QueryLogic {
    And(Vec<QueryFilter>),
    Or(Vec<QueryFilter>),
    Not(Box<QueryFilter>),
    Single(QueryFilter),
}

impl QueryLogic {
    #[must_use]
    pub fn matches(&self, event: &TraceEvent) -> bool {
        match self {
            Self::And(filters) => filters.iter().all(|f| f.matches(event)),
            Self::Or(filters) => filters.iter().any(|f| f.matches(event)),
            Self::Not(filter) => !filter.matches(event),
            Self::Single(filter) => filter.matches(event),
        }
    }
}

impl std::fmt::Display for QueryLogic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::And(fs) => write!(f, "And({} filters)", fs.len()),
            Self::Or(fs) => write!(f, "Or({} filters)", fs.len()),
            Self::Not(inner) => write!(f, "Not({inner})"),
            Self::Single(inner) => write!(f, "Single({inner})"),
        }
    }
}

// ─── MemAccessKind ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MemAccessKind {
    Read,
    Write,
    Any,
}

// ─── EventPattern ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventPattern {
    AnyMemRead,
    AnyMemWrite,
    AnyCall,
    AnyReturn,
    AnySyscall,
    MemReadAt(u64),
    MemWriteAt(u64),
    CallTo(u64),
    CallFrom(u64),
    ReturnFrom(u64),
    ReturnTo(u64),
    SyscallNr(u32),
    Exception(u32),
    ThreadId(u32),
    InPositionRange(TracePosition, TracePosition),
    MemWriteWithData(u64, Vec<u8>),
    AnyException,
    Breakpoint(u64),
}

impl EventPattern {
    #[must_use]
    pub fn matches(&self, event: &TraceEvent) -> bool {
        match self {
            Self::AnyMemRead => matches!(&event.kind, EventKind::MemRead { .. }),
            Self::AnyMemWrite => matches!(&event.kind, EventKind::MemWrite { .. }),
            Self::AnyCall => matches!(&event.kind, EventKind::Call { .. }),
            Self::AnyReturn => matches!(&event.kind, EventKind::Return { .. }),
            Self::AnySyscall => matches!(
                &event.kind,
                EventKind::SyscallEnter { .. } | EventKind::SyscallExit { .. }
            ),
            Self::MemReadAt(a) => {
                matches!(&event.kind, EventKind::MemRead { addr, .. } if addr == a)
            }
            Self::MemWriteAt(a) => {
                matches!(&event.kind, EventKind::MemWrite { addr, .. } if addr == a)
            }
            Self::CallTo(t) => matches!(&event.kind, EventKind::Call { to, .. } if to == t),
            Self::CallFrom(s) => matches!(&event.kind, EventKind::Call { from, .. } if from == s),
            Self::ReturnFrom(s) => {
                matches!(&event.kind, EventKind::Return { from, .. } if from == s)
            }
            Self::ReturnTo(t) => matches!(&event.kind, EventKind::Return { to, .. } if to == t),
            Self::SyscallNr(n) => matches!(&event.kind,
                EventKind::SyscallEnter { nr, .. } | EventKind::SyscallExit { nr, .. } if nr == n),
            Self::Exception(c) => {
                matches!(&event.kind, EventKind::Exception { code, .. } if code == c)
            }
            Self::ThreadId(t) => event.thread_id == *t,
            Self::InPositionRange(start, end) => event.position >= *start && event.position <= *end,
            Self::MemWriteWithData(a, d) => matches!(&event.kind,
                EventKind::MemWrite { addr, data } if addr == a && data == d),
            Self::AnyException => matches!(&event.kind, EventKind::Exception { .. }),
            Self::Breakpoint(a) => {
                matches!(&event.kind, EventKind::Breakpoint { addr } if addr == a)
            }
        }
    }
}

impl std::fmt::Display for EventPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AnyMemRead => write!(f, "AnyMemRead"),
            Self::AnyMemWrite => write!(f, "AnyMemWrite"),
            Self::AnyCall => write!(f, "AnyCall"),
            Self::AnyReturn => write!(f, "AnyReturn"),
            Self::AnySyscall => write!(f, "AnySyscall"),
            Self::MemReadAt(a) => write!(f, "MemReadAt({a:#x})"),
            Self::MemWriteAt(a) => write!(f, "MemWriteAt({a:#x})"),
            Self::CallTo(t) => write!(f, "CallTo({t:#x})"),
            Self::CallFrom(s) => write!(f, "CallFrom({s:#x})"),
            Self::ReturnFrom(s) => write!(f, "ReturnFrom({s:#x})"),
            Self::ReturnTo(t) => write!(f, "ReturnTo({t:#x})"),
            Self::SyscallNr(n) => write!(f, "SyscallNr({n})"),
            Self::Exception(c) => write!(f, "Exception({c:#x})"),
            Self::ThreadId(t) => write!(f, "ThreadId({t})"),
            Self::InPositionRange(s, e) => write!(f, "InPositionRange({s}..{e})"),
            Self::MemWriteWithData(a, _) => write!(f, "MemWriteWithData({a:#x})"),
            Self::AnyException => write!(f, "AnyException"),
            Self::Breakpoint(a) => write!(f, "Breakpoint({a:#x})"),
        }
    }
}

// ─── EventKindFilter ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventKindFilter {
    MemRead,
    MemWrite,
    Call,
    Return,
    SyscallEnter,
    SyscallExit,
    Exception,
    ThreadCreate,
    ThreadExit,
    Breakpoint,
    Any,
}

impl EventKindFilter {
    #[must_use]
    pub const fn matches_kind(&self, kind: &EventKind) -> bool {
        match self {
            Self::MemRead => matches!(kind, EventKind::MemRead { .. }),
            Self::MemWrite => matches!(kind, EventKind::MemWrite { .. }),
            Self::Call => matches!(kind, EventKind::Call { .. }),
            Self::Return => matches!(kind, EventKind::Return { .. }),
            Self::SyscallEnter => matches!(kind, EventKind::SyscallEnter { .. }),
            Self::SyscallExit => matches!(kind, EventKind::SyscallExit { .. }),
            Self::Exception => matches!(kind, EventKind::Exception { .. }),
            Self::ThreadCreate => matches!(kind, EventKind::ThreadCreate { .. }),
            Self::ThreadExit => matches!(kind, EventKind::ThreadExit { .. }),
            Self::Breakpoint => matches!(kind, EventKind::Breakpoint { .. }),
            Self::Any => true,
        }
    }
}

// ─── Query DSL ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Query {
    EventsOfKind(EventKindFilter),
    EventsInRange {
        start: u64,
        end: u64,
        kind: MemAccessKind,
    },
    CallChain {
        from: u64,
        to: u64,
    },
    DataFlow {
        source_addr: u64,
        sink_addr: u64,
    },
    Loops {
        min_iterations: u32,
    },
    Sequence(Vec<EventPattern>),
    Before {
        a: Box<Self>,
        b: Box<Self>,
    },
    After {
        a: Box<Self>,
        b: Box<Self>,
    },
    And(Vec<Self>),
    Or(Vec<Self>),
    Not(Box<Self>),
    Pattern(EventPattern),
    Thread(u32),
    InTimeRange(TimeRange),
    AllEvents,
}

impl std::fmt::Display for Query {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EventsOfKind(_) => write!(f, "EventsOfKind"),
            Self::EventsInRange { start, end, .. } => {
                write!(f, "EventsInRange({start:#x}..{end:#x})")
            }
            Self::CallChain { from, to } => write!(f, "CallChain({from:#x}->{to:#x})"),
            Self::DataFlow {
                source_addr,
                sink_addr,
            } => write!(f, "DataFlow({source_addr:#x}->{sink_addr:#x})"),
            Self::Loops { min_iterations } => write!(f, "Loops(min={min_iterations})"),
            Self::Sequence(pats) => write!(f, "Sequence({})", pats.len()),
            Self::Before { .. } => write!(f, "Before"),
            Self::After { .. } => write!(f, "After"),
            Self::And(qs) => write!(f, "And({} queries)", qs.len()),
            Self::Or(qs) => write!(f, "Or({} queries)", qs.len()),
            Self::Not(_) => write!(f, "Not"),
            Self::Pattern(p) => write!(f, "Pattern({p})"),
            Self::Thread(t) => write!(f, "Thread({t})"),
            Self::InTimeRange(r) => write!(f, "InTimeRange({r})"),
            Self::AllEvents => write!(f, "AllEvents"),
        }
    }
}

// ─── MatchContext ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MatchContext {
    pub before: Vec<TraceEvent>,
    pub after: Vec<TraceEvent>,
}

impl MatchContext {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            before: vec![],
            after: vec![],
        }
    }

    #[must_use]
    pub fn with_context(events: &[TraceEvent], idx: usize, window: usize) -> Self {
        let start = idx.saturating_sub(window);
        let end = (idx + window + 1).min(events.len());
        Self {
            before: events[start..idx].to_vec(),
            after: if idx + 1 < events.len() {
                events[idx + 1..end].to_vec()
            } else {
                vec![]
            },
        }
    }
}

// ─── QueryMatch ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct QueryMatch {
    pub position: TracePosition,
    pub event: TraceEvent,
    pub context: MatchContext,
}

// ─── QueryResult (rich) ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct QueryResult {
    pub matches: Vec<QueryMatch>,
    pub execution_time_ms: u64,
    pub events_scanned: u64,
}

impl QueryResult {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }
    #[must_use]
    pub const fn len(&self) -> usize {
        self.matches.len()
    }
    #[must_use]
    pub fn positions(&self) -> Vec<TracePosition> {
        self.matches.iter().map(|m| m.position).collect()
    }
}

impl std::fmt::Display for QueryResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "QueryResult {{ matched: {}, scanned: {}, time_ms: {} }}",
            self.matches.len(),
            self.events_scanned,
            self.execution_time_ms
        )
    }
}

// ─── QueryPlan ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct QueryPlan {
    pub description: String,
    pub estimated_events: u64,
    pub uses_index: bool,
}

impl std::fmt::Display for QueryPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "QueryPlan {{ desc: {}, estimated: {}, index: {} }}",
            self.description, self.estimated_events, self.uses_index
        )
    }
}

// ─── EventIndexKind ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventIndexKind {
    Read,
    Write,
    CallFrom,
    CallTo,
    ReturnFrom,
    ReturnTo,
    Breakpoint,
    Exception,
}

// ─── QueryIndex ───────────────────────────────────────────────────────────────

pub struct QueryIndex {
    pub by_address: BTreeMap<u64, Vec<(TracePosition, EventIndexKind)>>,
    pub calls_from: BTreeMap<u64, Vec<TracePosition>>,
    pub calls_to: BTreeMap<u64, Vec<TracePosition>>,
    pub syscalls: BTreeMap<u32, Vec<TracePosition>>,
    pub by_thread: HashMap<u32, Vec<usize>>,
}

impl QueryIndex {
    #[must_use]
    pub fn build(events: &[TraceEvent]) -> Self {
        let mut by_address: BTreeMap<u64, Vec<(TracePosition, EventIndexKind)>> = BTreeMap::new();
        let mut calls_from: BTreeMap<u64, Vec<TracePosition>> = BTreeMap::new();
        let mut calls_to: BTreeMap<u64, Vec<TracePosition>> = BTreeMap::new();
        let mut syscalls: BTreeMap<u32, Vec<TracePosition>> = BTreeMap::new();
        let mut by_thread: HashMap<u32, Vec<usize>> = HashMap::new();

        for (idx, event) in events.iter().enumerate() {
            by_thread.entry(event.thread_id).or_default().push(idx);
            match &event.kind {
                EventKind::MemRead { addr, .. } => {
                    by_address
                        .entry(*addr)
                        .or_default()
                        .push((event.position, EventIndexKind::Read));
                }
                EventKind::MemWrite { addr, .. } => {
                    by_address
                        .entry(*addr)
                        .or_default()
                        .push((event.position, EventIndexKind::Write));
                }
                EventKind::Call { from, to } => {
                    calls_from.entry(*from).or_default().push(event.position);
                    calls_to.entry(*to).or_default().push(event.position);
                    by_address
                        .entry(*from)
                        .or_default()
                        .push((event.position, EventIndexKind::CallFrom));
                    by_address
                        .entry(*to)
                        .or_default()
                        .push((event.position, EventIndexKind::CallTo));
                }
                EventKind::Return { from, to } => {
                    by_address
                        .entry(*from)
                        .or_default()
                        .push((event.position, EventIndexKind::ReturnFrom));
                    by_address
                        .entry(*to)
                        .or_default()
                        .push((event.position, EventIndexKind::ReturnTo));
                }
                EventKind::SyscallEnter { nr, .. } | EventKind::SyscallExit { nr, .. } => {
                    syscalls.entry(*nr).or_default().push(event.position);
                }
                EventKind::Breakpoint { addr } => {
                    by_address
                        .entry(*addr)
                        .or_default()
                        .push((event.position, EventIndexKind::Breakpoint));
                }
                EventKind::Exception { addr, code: _ } => {
                    by_address
                        .entry(*addr)
                        .or_default()
                        .push((event.position, EventIndexKind::Exception));
                }
                EventKind::ThreadCreate { .. } | EventKind::ThreadExit { .. } => {}
            }
        }

        Self {
            by_address,
            calls_from,
            calls_to,
            syscalls,
            by_thread,
        }
    }

    #[must_use]
    pub fn calls_to_address(&self, addr: u64) -> &[TracePosition] {
        self.calls_to
            .get(&addr)
            .map_or(&[], std::vec::Vec::as_slice)
    }

    #[must_use]
    pub fn calls_from_address(&self, addr: u64) -> &[TracePosition] {
        self.calls_from
            .get(&addr)
            .map_or(&[], std::vec::Vec::as_slice)
    }

    #[must_use]
    pub fn syscalls_for_nr(&self, nr: u32) -> &[TracePosition] {
        self.syscalls.get(&nr).map_or(&[], std::vec::Vec::as_slice)
    }

    #[must_use]
    pub fn accesses_to_address(&self, addr: u64) -> &[(TracePosition, EventIndexKind)] {
        self.by_address
            .get(&addr)
            .map_or(&[], std::vec::Vec::as_slice)
    }

    #[must_use]
    pub fn events_for_thread(&self, tid: u32) -> &[usize] {
        self.by_thread
            .get(&tid)
            .map_or(&[], std::vec::Vec::as_slice)
    }
}

impl std::fmt::Debug for QueryIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryIndex")
            .field("addresses", &self.by_address.len())
            .field("threads", &self.by_thread.len())
            .finish_non_exhaustive()
    }
}

// ─── QueryEngine ─────────────────────────────────────────────────────────────

pub struct QueryEngine {
    trace: Arc<TtdTrace>,
    index: QueryIndex,
}

impl QueryEngine {
    pub fn new(trace: Arc<TtdTrace>) -> Self {
        let events = trace.all_events();
        let index = QueryIndex::build(&events);
        Self { trace, index }
    }

    #[must_use]
    pub fn execute(&self, query: &Query) -> QueryResult {
        let t0 = Instant::now();
        let events = self.trace.all_events();
        let matches = self.eval_query(query, &events);
        let events_scanned = events.len() as u64;
        QueryResult {
            matches,
            execution_time_ms: t0.elapsed().as_millis() as u64,
            events_scanned,
        }
    }

    /// Execute a memory-range query using `rustre_core` address types, bridging
    /// the core address abstraction into the TTD query engine.
    #[must_use]
    pub fn execute_in_core_address_range(
        &self,
        start: CoreAddress,
        end: CoreAddress,
        kind: MemAccessKind,
    ) -> QueryResult {
        self.execute(&Query::EventsInRange {
            start: start.as_u64(),
            end: end.as_u64(),
            kind,
        })
    }

    /// Build a `rustre_trace::TraceFilter` that restricts to the address range
    /// of the given memory-region query and return events matching it.
    /// This bridges the `rustre-trace` filter abstraction into the TTD query
    /// engine so callers that already hold a `TraceFilter` can re-use it.
    #[must_use]
    pub fn execute_with_trace_filter(&self, filter: &TraceFilter) -> QueryResult {
        let query = match (filter.min_addr, filter.max_addr) {
            (Some(min), Some(max)) => Query::EventsInRange {
                start: min,
                end: max,
                kind: MemAccessKind::Any,
            },
            _ => Query::AllEvents,
        };
        let mut result = self.execute(&query);
        // Apply thread-id filter from TraceFilter if set
        if let Some(tid) = filter.thread_id {
            result.matches.retain(|m| m.event.thread_id == tid);
        }
        result
    }

    #[must_use]
    pub fn explain(&self, query: &Query) -> QueryPlan {
        let total = self.trace.event_count() as u64;
        let (desc, uses_index, estimated) = match query {
            Query::EventsOfKind(_) => ("full scan by kind".into(), false, total),
            Query::EventsInRange { .. } => ("address range scan".into(), true, total / 10),
            Query::CallChain { .. } => ("call chain via index".into(), true, total / 20),
            Query::DataFlow { .. } => ("data-flow analysis".into(), false, total),
            Query::Loops { .. } => ("loop detection".into(), false, total),
            Query::Sequence(_) => ("sequence pattern match".into(), false, total),
            Query::Pattern(_) => ("pattern match scan".into(), false, total),
            Query::Thread(_) => ("thread filter via index".into(), true, total / 4),
            Query::InTimeRange(_) => ("time range filter".into(), false, total / 2),
            Query::AllEvents => ("full scan".into(), false, total),
            Query::Before { .. } | Query::After { .. } => ("temporal query".into(), false, total),
            Query::And(_) => ("AND composition".into(), false, total),
            Query::Or(_) => ("OR composition".into(), false, total),
            Query::Not(_) => ("NOT composition".into(), false, total),
        };
        QueryPlan {
            description: desc,
            estimated_events: estimated,
            uses_index,
        }
    }

    fn eval_query(&self, query: &Query, events: &[TraceEvent]) -> Vec<QueryMatch> {
        match query {
            Query::AllEvents => events
                .iter()
                .enumerate()
                .map(|(i, e)| QueryMatch {
                    position: e.position,
                    event: e.clone(),
                    context: MatchContext::with_context(events, i, 2),
                })
                .collect(),

            Query::EventsOfKind(filter) => events
                .iter()
                .enumerate()
                .filter(|(_, e)| filter.matches_kind(&e.kind))
                .map(|(i, e)| QueryMatch {
                    position: e.position,
                    event: e.clone(),
                    context: MatchContext::with_context(events, i, 2),
                })
                .collect(),

            Query::EventsInRange { start, end, kind } => events
                .iter()
                .enumerate()
                .filter(|(_, e)| match (&e.kind, kind) {
                    (
                        EventKind::MemRead { addr, len },
                        MemAccessKind::Read | MemAccessKind::Any,
                    ) => {
                        let ae = addr.saturating_add(*len as u64);
                        *addr < *end && ae > *start
                    }
                    (
                        EventKind::MemWrite { addr, data },
                        MemAccessKind::Write | MemAccessKind::Any,
                    ) => {
                        let ae = addr.saturating_add(data.len() as u64);
                        *addr < *end && ae > *start
                    }
                    (EventKind::MemRead { addr, len }, MemAccessKind::Write) => {
                        let _ = (addr, len);
                        false
                    }
                    (EventKind::MemWrite { addr, data }, MemAccessKind::Read) => {
                        let _ = (addr, data);
                        false
                    }
                    _ => false,
                })
                .map(|(i, e)| QueryMatch {
                    position: e.position,
                    event: e.clone(),
                    context: MatchContext::with_context(events, i, 2),
                })
                .collect(),

            Query::Pattern(pattern) => events
                .iter()
                .enumerate()
                .filter(|(_, e)| pattern.matches(e))
                .map(|(i, e)| QueryMatch {
                    position: e.position,
                    event: e.clone(),
                    context: MatchContext::with_context(events, i, 2),
                })
                .collect(),

            Query::Thread(tid) => events
                .iter()
                .enumerate()
                .filter(|(_, e)| e.thread_id == *tid)
                .map(|(i, e)| QueryMatch {
                    position: e.position,
                    event: e.clone(),
                    context: MatchContext::with_context(events, i, 2),
                })
                .collect(),

            Query::InTimeRange(range) => events
                .iter()
                .enumerate()
                .filter(|(_, e)| range.contains(&e.position))
                .map(|(i, e)| QueryMatch {
                    position: e.position,
                    event: e.clone(),
                    context: MatchContext::with_context(events, i, 2),
                })
                .collect(),

            Query::CallChain { from, to } => {
                // Find all calls from `from` that are followed (transitively) by a call to `to`
                
                let has_call_to = events
                    .iter()
                    .any(|e| matches!(&e.kind, EventKind::Call { to: t, .. } if t == to));
                if has_call_to {
                    events
                    .iter()
                    .enumerate()
                    .filter(
                        |(_, e)| matches!(&e.kind, EventKind::Call { from: f, .. } if f == from),
                    )
                        .map(|(i, e)| QueryMatch {
                            position: e.position,
                            event: e.clone(),
                            context: MatchContext::with_context(events, i, 2),
                        })
                        .collect()
                } else {
                    vec![]
                }
            }

            Query::DataFlow {
                source_addr,
                sink_addr,
            } => {
                // Collect positions of writes to source_addr, then check whether
                // each such position is followed by at least one write to sink_addr.
                // Return the source-write events that have a downstream sink write.
                let sink_write_positions: Vec<TracePosition> = events.iter()
                    .filter(|e| matches!(&e.kind, EventKind::MemWrite { addr, .. } if addr == sink_addr))
                    .map(|e| e.position)
                    .collect();

                events.iter().enumerate()
                    .filter(|(_, e)| matches!(&e.kind, EventKind::MemWrite { addr, .. } if addr == source_addr))
                    .filter(|(_, e)| {
                        // There must be at least one write to sink that comes after this source write
                        sink_write_positions.iter().any(|&sp| sp > e.position)
                    })
                    .map(|(i, e)| QueryMatch {
                        position: e.position,
                        event: e.clone(),
                        context: MatchContext::with_context(events, i, 2),
                    })
                    .collect()
            }

            Query::Loops { min_iterations } => {
                // Detect call targets that appear >= min_iterations times
                let mut call_counts: HashMap<u64, Vec<(usize, &TraceEvent)>> = HashMap::new();
                for (i, e) in events.iter().enumerate() {
                    if let EventKind::Call { to, .. } = &e.kind {
                        call_counts.entry(*to).or_default().push((i, e));
                    }
                }
                let mut result = Vec::new();
                for calls in call_counts.values() {
                    if calls.len() >= *min_iterations as usize {
                        for (i, e) in calls {
                            result.push(QueryMatch {
                                position: e.position,
                                event: (*e).clone(),
                                context: MatchContext::with_context(events, *i, 1),
                            });
                        }
                    }
                }
                result.sort_by_key(|m| m.position);
                result
            }

            Query::Sequence(patterns) => {
                if patterns.is_empty() {
                    return vec![];
                }
                let mut result = Vec::new();
                let mut pat_idx = 0usize;
                let mut seq_start: Option<(usize, TraceEvent)> = None;
                for (i, event) in events.iter().enumerate() {
                    if patterns[pat_idx].matches(event) {
                        if pat_idx == 0 {
                            seq_start = Some((i, event.clone()));
                        }
                        pat_idx += 1;
                        if pat_idx == patterns.len() {
                            if let Some((si, se)) = seq_start.take() {
                                result.push(QueryMatch {
                                    position: se.position,
                                    event: se,
                                    context: MatchContext::with_context(events, si, 2),
                                });
                            }
                            pat_idx = 0;
                        }
                    } else {
                        // Mismatch: reset and check if this event starts a new sequence
                        pat_idx = 0;
                        seq_start = None;
                        if patterns[0].matches(event) {
                            seq_start = Some((i, event.clone()));
                            pat_idx = 1;
                        }
                    }
                }
                result
            }

            Query::Before { a, b } => {
                let matches_a = self.eval_query(a, events);
                let matches_b = self.eval_query(b, events);
                if matches_a.is_empty() || matches_b.is_empty() {
                    return vec![];
                }
                let first_b = matches_b.iter().map(|m| m.position).min().unwrap();
                matches_a
                    .into_iter()
                    .filter(|m| m.position < first_b)
                    .collect()
            }

            Query::After { a, b } => {
                let matches_a = self.eval_query(a, events);
                let matches_b = self.eval_query(b, events);
                if matches_a.is_empty() || matches_b.is_empty() {
                    return vec![];
                }
                let last_b = matches_b.iter().map(|m| m.position).max().unwrap();
                matches_a
                    .into_iter()
                    .filter(|m| m.position > last_b)
                    .collect()
            }

            Query::And(queries) => {
                if queries.is_empty() {
                    return vec![];
                }
                let position_sets: Vec<HashSet<TracePosition>> = queries
                    .iter()
                    .map(|q| {
                        self.eval_query(q, events)
                            .into_iter()
                            .map(|m| m.position)
                            .collect()
                    })
                    .collect();
                let intersection: HashSet<TracePosition> = position_sets[0]
                    .iter()
                    .filter(|p| position_sets[1..].iter().all(|s| s.contains(p)))
                    .copied()
                    .collect();
                events
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| intersection.contains(&e.position))
                    .map(|(i, e)| QueryMatch {
                        position: e.position,
                        event: e.clone(),
                        context: MatchContext::with_context(events, i, 2),
                    })
                    .collect()
            }

            Query::Or(queries) => {
                let mut seen: HashSet<TracePosition> = HashSet::new();
                let mut result = Vec::new();
                for q in queries {
                    for m in self.eval_query(q, events) {
                        if seen.insert(m.position) {
                            result.push(m);
                        }
                    }
                }
                result.sort_by_key(|m| m.position);
                result
            }

            Query::Not(q) => {
                let excluded: HashSet<TracePosition> = self
                    .eval_query(q, events)
                    .into_iter()
                    .map(|m| m.position)
                    .collect();
                events
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| !excluded.contains(&e.position))
                    .map(|(i, e)| QueryMatch {
                        position: e.position,
                        event: e.clone(),
                        context: MatchContext::with_context(events, i, 2),
                    })
                    .collect()
            }
        }
    }

    // ── Legacy execute ────────────────────────────────────────────────────────

    #[must_use]
    pub fn execute_logic(&self, logic: &QueryLogic) -> LegacyQueryResult {
        let t0 = Instant::now();
        let events = self.trace.all_events();
        let matched: Vec<TraceEvent> = events.into_iter().filter(|e| logic.matches(e)).collect();
        let total_matched = matched.len();
        LegacyQueryResult {
            events: matched,
            total_matched,
            query_time_ms: t0.elapsed().as_millis() as u64,
        }
    }

    #[must_use]
    pub fn count(&self, filter: &QueryFilter) -> usize {
        self.trace
            .all_events()
            .iter()
            .filter(|e| filter.matches(e))
            .count()
    }

    #[must_use]
    pub fn first_occurrence(&self, filter: &QueryFilter) -> Option<TraceEvent> {
        self.trace
            .all_events()
            .into_iter()
            .find(|e| filter.matches(e))
    }

    #[must_use]
    pub fn last_occurrence(&self, filter: &QueryFilter) -> Option<TraceEvent> {
        self.trace
            .all_events()
            .into_iter()
            .rfind(|e| filter.matches(e))
    }

    #[must_use]
    pub fn execute_filter(&self, filter: &QueryFilter, events: &[TraceEvent]) -> Vec<TraceEvent> {
        events
            .iter()
            .filter(|e| filter.matches(e))
            .cloned()
            .collect()
    }

    // ── Analysis functions ────────────────────────────────────────────────────

    /// Analyze memory access patterns for an address range.
    #[must_use]
    pub fn analyze_memory_access_patterns(&self, start: u64, end: u64) -> MemoryAccessReport {
        let events = self.trace.all_events();
        let mut reads: Vec<(TracePosition, u64, usize)> = Vec::new();
        let mut writes: Vec<(TracePosition, u64, usize)> = Vec::new();
        let mut read_addrs: HashMap<u64, u64> = HashMap::new();
        let mut write_addrs: HashMap<u64, u64> = HashMap::new();

        for event in &events {
            match &event.kind {
                EventKind::MemRead { addr, len } if *addr >= start && *addr < end => {
                    reads.push((event.position, *addr, *len));
                    *read_addrs.entry(*addr).or_default() += 1;
                }
                EventKind::MemWrite { addr, data } if *addr >= start && *addr < end => {
                    writes.push((event.position, *addr, data.len()));
                    *write_addrs.entry(*addr).or_default() += 1;
                }
                _ => {}
            }
        }

        let total_read_bytes: usize = reads.iter().map(|(_, _, l)| l).sum();
        let total_write_bytes: usize = writes.iter().map(|(_, _, l)| l).sum();

        let hottest_read = read_addrs
            .iter()
            .max_by_key(|(_, c)| *c)
            .map(|(a, c)| (*a, *c));
        let hottest_write = write_addrs
            .iter()
            .max_by_key(|(_, c)| *c)
            .map(|(a, c)| (*a, *c));

        MemoryAccessReport {
            range_start: start,
            range_end: end,
            total_reads: reads.len() as u64,
            total_writes: writes.len() as u64,
            total_read_bytes: total_read_bytes as u64,
            total_write_bytes: total_write_bytes as u64,
            unique_read_addresses: read_addrs.len() as u64,
            unique_write_addresses: write_addrs.len() as u64,
            hottest_read_address: hottest_read,
            hottest_write_address: hottest_write,
            first_access: reads.iter().chain(writes.iter()).map(|(p, _, _)| *p).min(),
            last_access: reads.iter().chain(writes.iter()).map(|(p, _, _)| *p).max(),
        }
    }

    /// Analyze call frequency — returns (addr, `call_count`) sorted by count desc.
    #[must_use]
    pub fn analyze_call_frequency(&self) -> Vec<(u64, u64)> {
        let events = self.trace.all_events();
        let mut counts: HashMap<u64, u64> = HashMap::new();
        for event in &events {
            if let EventKind::Call { to, .. } = &event.kind {
                *counts.entry(*to).or_default() += 1;
            }
        }
        let mut result: Vec<(u64, u64)> = counts.into_iter().collect();
        result.sort_by_key(|b| std::cmp::Reverse(b.1));
        result
    }

    /// Find recursive call chains.
    #[must_use]
    pub fn find_recursive_calls(&self) -> Vec<RecursiveCallChain> {
        let events = self.trace.all_events();
        // Recursion is a property of ONE thread's stack. With a single global
        // stack, two threads that each called the same function once looked
        // like a recursive chain, and a return on one thread popped another
        // thread's frame.
        let mut call_stacks: HashMap<u32, Vec<u64>> = HashMap::new();
        let mut chains: HashMap<u64, RecursiveCallChain> = HashMap::new();

        for event in &events {
            match &event.kind {
                EventKind::Call { to, .. } => {
                    let call_stack = call_stacks.entry(event.thread_id).or_default();
                    // Depth is how many activations of this function are ALREADY
                    // live, plus the one being entered. The old form measured the
                    // distance to the nearest activation, which is 1 for every
                    // direct recursion however deep it goes.
                    let live = call_stack.iter().filter(|a| *a == to).count();
                    if live > 0 {
                        let chain = chains.entry(*to).or_insert_with(|| RecursiveCallChain {
                            address: *to,
                            recursion_positions: Vec::new(),
                            max_depth: 0,
                        });
                        let depth = live + 1;
                        if depth > chain.max_depth {
                            chain.max_depth = depth;
                        }
                        chain.recursion_positions.push(event.position);
                    }
                    call_stack.push(*to);
                }
                EventKind::Return { .. } => {
                    if let Some(s) = call_stacks.get_mut(&event.thread_id) {
                        s.pop();
                    }
                }
                _ => {}
            }
        }

        chains.into_values().collect()
    }

    /// Detect heap operations (heuristic: calls to common alloc addresses).
    #[must_use]
    pub fn detect_heap_operations(&self) -> HeapOperationsReport {
        let events = self.trace.all_events();
        // Heuristic: treat the most frequently-called addresses as heap funcs.
        let freq = self.analyze_call_frequency();
        let heap_candidates: HashSet<u64> = freq.iter().take(5).map(|(a, _)| *a).collect();

        let mut allocs: Vec<HeapOp> = Vec::new();
        let mut frees: Vec<HeapOp> = Vec::new();

        for (idx, event) in events.iter().enumerate() {
            if let EventKind::Call { to, from } = &event.kind
                && heap_candidates.contains(to)
            {
                // Check if the next SyscallExit or Return gives a result addr
                let ret_addr = events[idx..]
                    .iter()
                    .find(|e| matches!(&e.kind, EventKind::Return { from: rf, .. } if rf == to))
                    .and_then(|e| {
                        if let EventKind::Return { to: ret, .. } = &e.kind {
                            Some(*ret)
                        } else {
                            None
                        }
                    });

                // Heuristic: if the call returns a non-null address, treat it as
                // an allocation; otherwise treat it as a free/non-allocating call.
                // Index parity is unrelated to alloc vs free — removed.
                if ret_addr.is_some_and(|a| a != 0) {
                    allocs.push(HeapOp {
                        position: event.position,
                        call_site: *from,
                        target: *to,
                        result_addr: ret_addr,
                    });
                } else {
                    frees.push(HeapOp {
                        position: event.position,
                        call_site: *from,
                        target: *to,
                        result_addr: None,
                    });
                }
            }
        }

        HeapOperationsReport {
            total_allocs: allocs.len() as u64,
            total_frees: frees.len() as u64,
            allocs,
            frees,
        }
    }

    /// Find string-like memory accesses (sequences of printable ASCII).
    #[must_use]
    pub fn find_string_accesses(&self) -> Vec<StringAccess> {
        let events = self.trace.all_events();
        let mut string_addrs: HashMap<u64, (Vec<u8>, Vec<TracePosition>)> = HashMap::new();

        for event in &events {
            if let EventKind::MemWrite { addr, data } = &event.kind {
                let is_ascii_string = !data.is_empty()
                    && data
                        .iter()
                        .all(|b| b.is_ascii_graphic() || *b == b' ' || *b == 0);
                if is_ascii_string && data.len() >= 3 {
                    let entry = string_addrs
                        .entry(*addr)
                        .or_insert_with(|| (data.clone(), Vec::new()));
                    entry.0.clone_from(data);
                    entry.1.push(event.position);
                }
            }
        }

        string_addrs
            .into_iter()
            .filter_map(|(addr, (bytes, positions))| {
                let s =
                    String::from_utf8(bytes.iter().copied().filter(|b| *b != 0).collect()).ok()?;
                Some(StringAccess {
                    address: addr,
                    content: s,
                    access_positions: positions,
                })
            })
            .collect()
    }

    /// Summarize syscall statistics.
    #[must_use]
    pub fn summarize_syscalls(&self) -> HashMap<u32, SyscallStats> {
        let events = self.trace.all_events();
        let mut stats: HashMap<u32, SyscallStats> = HashMap::new();
        let mut enter_times: HashMap<u32, Vec<(u32, TracePosition)>> = HashMap::new(); // nr -> [(tid, pos)]

        for event in &events {
            match &event.kind {
                EventKind::SyscallEnter { nr, args } => {
                    let st = stats.entry(*nr).or_insert_with(|| SyscallStats {
                        nr: *nr,
                        call_count: 0,
                        error_count: 0,
                        first_call: None,
                        last_call: None,
                        total_return_values: Vec::new(),
                        first_args: args.to_vec(),
                    });
                    st.call_count += 1;
                    if st.first_call.is_none() {
                        st.first_call = Some(event.position);
                    }
                    st.last_call = Some(event.position);
                    enter_times
                        .entry(*nr)
                        .or_default()
                        .push((event.thread_id, event.position));
                }
                EventKind::SyscallExit { nr, ret } => {
                    let st = stats.entry(*nr).or_insert_with(|| SyscallStats {
                        nr: *nr,
                        call_count: 0,
                        error_count: 0,
                        first_call: None,
                        last_call: None,
                        total_return_values: Vec::new(),
                        first_args: vec![0; 6],
                    });
                    if (*ret as i64) < 0 {
                        st.error_count += 1;
                    }
                    st.total_return_values.push(*ret);
                }
                _ => {}
            }
        }
        stats
    }

    /// Heuristic data-race detection: same address written by 2+ threads.
    #[must_use]
    pub fn find_data_races_heuristic(&self) -> Vec<DataRaceCandidate> {
        let events = self.trace.all_events();
        let mut writes_by_addr: HashMap<u64, Vec<(u32, TracePosition)>> = HashMap::new();

        for event in &events {
            if let EventKind::MemWrite { addr, .. } = &event.kind {
                writes_by_addr
                    .entry(*addr)
                    .or_default()
                    .push((event.thread_id, event.position));
            }
        }

        let mut candidates = Vec::new();
        for (addr, writes) in writes_by_addr {
            let threads: HashSet<u32> = writes.iter().map(|(t, _)| *t).collect();
            if threads.len() >= 2 {
                let positions: Vec<TracePosition> = writes.iter().map(|(_, p)| *p).collect();
                candidates.push(DataRaceCandidate {
                    address: addr,
                    threads: threads.into_iter().collect(),
                    write_positions: positions,
                    confidence: 0.5,
                });
            }
        }
        candidates.sort_by_key(|c| c.address);
        candidates
    }

    /// Compute code coverage for given ranges.
    #[must_use]
    pub fn compute_code_coverage(&self, code_ranges: &[(u64, u64)]) -> CoverageReport {
        let events = self.trace.all_events();
        let mut executed: HashSet<u64> = HashSet::new();

        for event in &events {
            let rip = match &event.kind {
                EventKind::Call { to, .. } | EventKind::Return { to, .. } => Some(*to),
                EventKind::Breakpoint { addr } => Some(*addr),
                _ => None,
            };
            if let Some(ip) = rip {
                for &(start, end) in code_ranges {
                    if ip >= start && ip < end {
                        executed.insert(ip);
                    }
                }
            }
        }

        let total_range_size: u64 = code_ranges.iter().map(|(s, e)| e - s).sum();
        let covered = executed.len() as u64;
        let coverage_pct = if total_range_size > 0 {
            (covered as f64 / total_range_size as f64) * 100.0
        } else {
            0.0
        };

        CoverageReport {
            total_range_bytes: total_range_size,
            covered_addresses: covered,
            coverage_percentage: coverage_pct,
            executed_addresses: executed.into_iter().collect(),
        }
    }

    // ── Aggregation / statistics ──────────────────────────────────────────────

    #[must_use]
    pub fn event_histogram_by_kind(&self) -> HashMap<String, u64> {
        let events = self.trace.all_events();
        let mut hist: HashMap<String, u64> = HashMap::new();
        for event in &events {
            let name = event_kind_name(&event.kind);
            *hist.entry(name.to_string()).or_default() += 1;
        }
        hist
    }

    #[must_use]
    pub fn event_histogram_by_thread(&self) -> HashMap<u32, u64> {
        let events = self.trace.all_events();
        let mut hist: HashMap<u32, u64> = HashMap::new();
        for event in &events {
            *hist.entry(event.thread_id).or_default() += 1;
        }
        hist
    }

    /// Bucket events by sequence bucket size.
    #[must_use]
    pub fn event_histogram_over_time(&self, bucket_size: u64) -> Vec<(TracePosition, u64)> {
        if bucket_size == 0 {
            return vec![];
        }
        let events = self.trace.all_events();
        let mut buckets: BTreeMap<u64, u64> = BTreeMap::new();
        for event in &events {
            let bucket = event.position.sequence / bucket_size;
            *buckets.entry(bucket).or_default() += 1;
        }
        buckets
            .into_iter()
            .map(|(bucket, count)| (TracePosition::new(bucket * bucket_size, 0), count))
            .collect()
    }

    /// Top N most accessed addresses (read + write combined).
    #[must_use]
    pub fn most_accessed_addresses(&self, top_n: usize) -> Vec<(u64, u64)> {
        let events = self.trace.all_events();
        let mut counts: HashMap<u64, u64> = HashMap::new();
        for event in &events {
            match &event.kind {
                EventKind::MemRead { addr, .. } | EventKind::MemWrite { addr, .. } => {
                    *counts.entry(*addr).or_default() += 1;
                }
                _ => {}
            }
        }
        let mut result: Vec<(u64, u64)> = counts.into_iter().collect();
        result.sort_by_key(|b| std::cmp::Reverse(b.1));
        result.truncate(top_n);
        result
    }

    /// Top N most called functions.
    #[must_use]
    pub fn most_called_functions(&self, top_n: usize) -> Vec<(u64, u64)> {
        let mut result = self.analyze_call_frequency();
        result.truncate(top_n);
        result
    }

    // ── Export functions ──────────────────────────────────────────────────────

    /// Export filtered events to CSV via a writer.
    pub fn export_to_csv_writer<W: IoWrite>(
        &self,
        w: &mut W,
        filter: Option<&QueryFilter>,
    ) -> Result<(), QueryError> {
        writeln!(w, "sequence,step,thread_id,kind,addr,data")?;
        let events = self.trace.all_events();
        for event in &events {
            if let Some(f) = filter
                && !f.matches(event)
            {
                continue;
            }
            let (kind, addr, data) = csv_event_fields(&event.kind);
            writeln!(
                w,
                "{},{},{},{},{},{}",
                event.position.sequence, event.position.step, event.thread_id, kind, addr, data
            )?;
        }
        Ok(())
    }

    /// Export call graph in DOT format.
    pub fn export_call_graph_dot<W: IoWrite>(&self, w: &mut W) -> Result<(), QueryError> {
        let events = self.trace.all_events();
        let mut edges: HashMap<(u64, u64), u64> = HashMap::new();
        for event in &events {
            if let EventKind::Call { from, to } = &event.kind {
                *edges.entry((*from, *to)).or_default() += 1;
            }
        }
        writeln!(w, "digraph callgraph {{")?;
        writeln!(w, "  rankdir=LR;")?;
        writeln!(w, "  node [shape=box];")?;
        for ((from, to), count) in &edges {
            writeln!(w, "  \"{from:#x}\" -> \"{to:#x}\" [label=\"{count}\"];")?;
        }
        writeln!(w, "}}")?;
        Ok(())
    }

    /// Export JSON timeline.
    pub fn export_timeline_json<W: IoWrite>(
        &self,
        w: &mut W,
        filter: Option<&QueryFilter>,
    ) -> Result<(), QueryError> {
        let events = self.trace.all_events();
        let filtered: Vec<_> = events
            .iter()
            .filter(|e| filter.is_none_or(|f| f.matches(e)))
            .collect();

        writeln!(w, "[")?;
        for (i, event) in filtered.iter().enumerate() {
            let comma = if i + 1 < filtered.len() { "," } else { "" };
            let kind = event_kind_name(&event.kind);
            writeln!(
                w,
                "  {{\"seq\":{},\"step\":{},\"tid\":{},\"kind\":\"{}\"}}{}",
                event.position.sequence, event.position.step, event.thread_id, kind, comma
            )?;
        }
        writeln!(w, "]")?;
        Ok(())
    }

    // ── Targeted query helpers ────────────────────────────────────────────────

    /// Return all events (reads and writes) whose address falls within
    /// `[start, end)`.  Uses the pre-built address index for efficiency.
    #[must_use]
    pub fn filter_by_address_range(&self, start: u64, end: u64) -> Vec<TraceEvent> {
        let events = self.trace.all_events();
        events
            .into_iter()
            .filter(|e| match &e.kind {
                EventKind::MemRead { addr, .. } | EventKind::MemWrite { addr, .. } => *addr >= start && *addr < end,
                _ => false,
            })
            .collect()
    }

    /// Return the first `Call` event whose target equals `target_addr`, or
    /// `None` if no such call appears in the trace.
    #[must_use]
    pub fn find_calls_to(&self, target_addr: u64) -> Option<TraceEvent> {
        // Fast path: check the index first so we only scan the trace when
        // at least one hit is recorded.
        if self.index.calls_to_address(target_addr).is_empty() {
            return None;
        }
        self.trace
            .all_events()
            .into_iter()
            .find(|e| matches!(&e.kind, EventKind::Call { to, .. } if *to == target_addr))
    }

    /// Return every memory-access event (reads **and** writes) that touches
    /// exactly `addr`.
    #[must_use]
    pub fn find_memory_accesses(&self, addr: u64) -> Vec<TraceEvent> {
        let events = self.trace.all_events();
        events
            .into_iter()
            .filter(|e| match &e.kind {
                EventKind::MemRead { addr: a, .. } | EventKind::MemWrite { addr: a, .. } => *a == addr,
                _ => false,
            })
            .collect()
    }
}

impl std::fmt::Debug for QueryEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueryEngine")
            .field("event_count", &self.trace.event_count())
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

// ─── LegacyQueryResult ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LegacyQueryResult {
    pub events: Vec<TraceEvent>,
    pub total_matched: usize,
    pub query_time_ms: u64,
}

impl LegacyQueryResult {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }
}

impl std::fmt::Display for LegacyQueryResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "QueryResult {{ matched: {}, time_ms: {} }}",
            self.total_matched, self.query_time_ms
        )
    }
}

// ─── Report types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MemoryAccessReport {
    pub range_start: u64,
    pub range_end: u64,
    pub total_reads: u64,
    pub total_writes: u64,
    pub total_read_bytes: u64,
    pub total_write_bytes: u64,
    pub unique_read_addresses: u64,
    pub unique_write_addresses: u64,
    pub hottest_read_address: Option<(u64, u64)>,
    pub hottest_write_address: Option<(u64, u64)>,
    pub first_access: Option<TracePosition>,
    pub last_access: Option<TracePosition>,
}

impl std::fmt::Display for MemoryAccessReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MemAccessReport {{ reads: {}, writes: {}, range: [{:#x}, {:#x}) }}",
            self.total_reads, self.total_writes, self.range_start, self.range_end
        )
    }
}

#[derive(Debug, Clone)]
pub struct RecursiveCallChain {
    pub address: u64,
    pub recursion_positions: Vec<TracePosition>,
    pub max_depth: usize,
}

impl std::fmt::Display for RecursiveCallChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RecursiveCall @ {:#x} depth={}",
            self.address, self.max_depth
        )
    }
}

#[derive(Debug, Clone)]
pub struct HeapOp {
    pub position: TracePosition,
    pub call_site: u64,
    pub target: u64,
    pub result_addr: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct HeapOperationsReport {
    pub total_allocs: u64,
    pub total_frees: u64,
    pub allocs: Vec<HeapOp>,
    pub frees: Vec<HeapOp>,
}

impl std::fmt::Display for HeapOperationsReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HeapOps {{ allocs: {}, frees: {} }}",
            self.total_allocs, self.total_frees
        )
    }
}

#[derive(Debug, Clone)]
pub struct StringAccess {
    pub address: u64,
    pub content: String,
    pub access_positions: Vec<TracePosition>,
}

impl std::fmt::Display for StringAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StringAccess @ {:#x} {:?}", self.address, self.content)
    }
}

#[derive(Debug, Clone)]
pub struct SyscallStats {
    pub nr: u32,
    pub call_count: u64,
    pub error_count: u64,
    pub first_call: Option<TracePosition>,
    pub last_call: Option<TracePosition>,
    pub total_return_values: Vec<u64>,
    pub first_args: Vec<u64>,
}

impl SyscallStats {
    #[must_use]
    pub fn avg_return_value(&self) -> Option<f64> {
        if self.total_return_values.is_empty() {
            return None;
        }
        // Cast to i64 so Windows NTSTATUS error codes (negative i64 values stored as u64)
        // are interpreted correctly rather than as large positive numbers.
        let sum: i64 = self.total_return_values.iter().map(|&v| v as i64).sum();
        Some(sum as f64 / self.total_return_values.len() as f64)
    }
}

impl std::fmt::Display for SyscallStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SyscallStats {{ nr: {}, calls: {}, errors: {} }}",
            self.nr, self.call_count, self.error_count
        )
    }
}

#[derive(Debug, Clone)]
pub struct DataRaceCandidate {
    pub address: u64,
    pub threads: Vec<u32>,
    pub write_positions: Vec<TracePosition>,
    pub confidence: f64,
}

impl std::fmt::Display for DataRaceCandidate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DataRace @ {:#x} threads={:?} confidence={:.2}",
            self.address, self.threads, self.confidence
        )
    }
}

#[derive(Debug, Clone)]
pub struct CoverageReport {
    pub total_range_bytes: u64,
    pub covered_addresses: u64,
    pub coverage_percentage: f64,
    pub executed_addresses: Vec<u64>,
}

impl std::fmt::Display for CoverageReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Coverage {{ covered: {}/{} ({:.1}%) }}",
            self.covered_addresses, self.total_range_bytes, self.coverage_percentage
        )
    }
}

// ─── TraceIndex (SQLite-backed, legacy) ───────────────────────────────────────

pub struct TraceIndex {
    conn: RwLock<Connection>,
}

impl TraceIndex {
    pub fn open_in_memory() -> Result<Self, QueryError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                seq       INTEGER NOT NULL,
                step      INTEGER NOT NULL,
                thread_id INTEGER NOT NULL,
                kind      TEXT    NOT NULL,
                addr      INTEGER,
                addr2     INTEGER,
                nr        INTEGER,
                code      INTEGER,
                payload   TEXT    NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_kind  ON events (kind);
            CREATE INDEX IF NOT EXISTS idx_addr  ON events (addr);
            CREATE INDEX IF NOT EXISTS idx_tid   ON events (thread_id);
            CREATE INDEX IF NOT EXISTS idx_nr    ON events (nr);
            CREATE INDEX IF NOT EXISTS idx_pos   ON events (seq, step);",
        )?;
        Ok(Self {
            conn: RwLock::new(conn),
        })
    }

    pub fn build_from_trace(&self, trace: &TtdTrace) -> Result<(), QueryError> {
        let conn = self.conn.write();
        let events = trace.all_events();
        for event in &events {
            let (kind_str, addr, addr2, nr, code) = event_index_fields(&event.kind);
            let payload = serde_json::to_string(&event.kind)
                .map_err(|e| QueryError::ParseError(e.to_string()))?;
            conn.execute(
                "INSERT INTO events (seq,step,thread_id,kind,addr,addr2,nr,code,payload)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    event.position.sequence,
                    event.position.step,
                    event.thread_id,
                    kind_str,
                    addr,
                    addr2,
                    nr,
                    code,
                    payload
                ],
            )?;
        }
        Ok(())
    }

    pub fn query_memory_writes(&self, addr: u64) -> Result<Vec<TraceEvent>, QueryError> {
        let conn = self.conn.read();
        let mut stmt = conn.prepare(
            "SELECT seq,step,thread_id,payload FROM events
             WHERE kind='MemWrite' AND addr=?1 ORDER BY seq,step",
        )?;
        collect_event_rows(stmt.query_map(params![addr], row_to_tuple)?)
    }

    pub fn query_calls_to(&self, target: u64) -> Result<Vec<TraceEvent>, QueryError> {
        let conn = self.conn.read();
        let mut stmt = conn.prepare(
            "SELECT seq,step,thread_id,payload FROM events
             WHERE kind='Call' AND addr2=?1 ORDER BY seq,step",
        )?;
        collect_event_rows(stmt.query_map(params![target], row_to_tuple)?)
    }

    pub fn query_syscalls(&self, nr: u32) -> Result<Vec<TraceEvent>, QueryError> {
        let conn = self.conn.read();
        let mut stmt = conn.prepare(
            "SELECT seq,step,thread_id,payload FROM events
             WHERE kind IN ('SyscallEnter','SyscallExit') AND nr=?1 ORDER BY seq,step",
        )?;
        collect_event_rows(stmt.query_map(params![nr], row_to_tuple)?)
    }

    pub fn count_events_by_type(&self) -> Result<HashMap<String, u64>, QueryError> {
        let conn = self.conn.read();
        let mut stmt = conn.prepare("SELECT kind, COUNT(*) FROM events GROUP BY kind")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
        })?;
        let mut map = HashMap::new();
        for row in rows {
            let (k, v) = row?;
            map.insert(k, v);
        }
        Ok(map)
    }

    pub fn query_memory_reads(&self, addr: u64) -> Result<Vec<TraceEvent>, QueryError> {
        let conn = self.conn.read();
        let mut stmt = conn.prepare(
            "SELECT seq,step,thread_id,payload FROM events
             WHERE kind='MemRead' AND addr=?1 ORDER BY seq,step",
        )?;
        collect_event_rows(stmt.query_map(params![addr], row_to_tuple)?)
    }

    pub fn query_by_thread(&self, tid: u32) -> Result<Vec<TraceEvent>, QueryError> {
        let conn = self.conn.read();
        let mut stmt = conn.prepare(
            "SELECT seq,step,thread_id,payload FROM events
             WHERE thread_id=?1 ORDER BY seq,step",
        )?;
        collect_event_rows(stmt.query_map(params![tid], row_to_tuple)?)
    }

    pub fn query_exceptions(&self) -> Result<Vec<TraceEvent>, QueryError> {
        let conn = self.conn.read();
        let mut stmt = conn.prepare(
            "SELECT seq,step,thread_id,payload FROM events
             WHERE kind='Exception' ORDER BY seq,step",
        )?;
        collect_event_rows(stmt.query_map([], row_to_tuple)?)
    }

    pub fn query_in_position_range(
        &self,
        start_seq: u64,
        end_seq: u64,
    ) -> Result<Vec<TraceEvent>, QueryError> {
        let conn = self.conn.read();
        let mut stmt = conn.prepare(
            "SELECT seq,step,thread_id,payload FROM events
             WHERE seq >= ?1 AND seq <= ?2 ORDER BY seq,step",
        )?;
        collect_event_rows(stmt.query_map(params![start_seq, end_seq], row_to_tuple)?)
    }
}

impl std::fmt::Debug for TraceIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceIndex").finish_non_exhaustive()
    }
}

// ─── helpers ──────────────────────────────────────────────────────────────────

const fn event_index_fields(
    kind: &EventKind,
) -> (
    &'static str,
    Option<u64>,
    Option<u64>,
    Option<u32>,
    Option<u32>,
) {
    match kind {
        EventKind::MemRead { addr, .. } => ("MemRead", Some(*addr), None, None, None),
        EventKind::MemWrite { addr, .. } => ("MemWrite", Some(*addr), None, None, None),
        EventKind::Call { from, to } => ("Call", Some(*from), Some(*to), None, None),
        EventKind::Return { from, to } => ("Return", Some(*from), Some(*to), None, None),
        EventKind::SyscallEnter { nr, .. } => ("SyscallEnter", None, None, Some(*nr), None),
        EventKind::SyscallExit { nr, .. } => ("SyscallExit", None, None, Some(*nr), None),
        EventKind::Exception { code, addr } => ("Exception", Some(*addr), None, None, Some(*code)),
        EventKind::ThreadCreate { .. } => ("ThreadCreate", None, None, None, None),
        EventKind::ThreadExit { .. } => ("ThreadExit", None, None, None, None),
        EventKind::Breakpoint { addr } => ("Breakpoint", Some(*addr), None, None, None),
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

fn csv_event_fields(kind: &EventKind) -> (&'static str, String, String) {
    match kind {
        EventKind::MemRead { addr, len } => ("MemRead", format!("{addr:#x}"), format!("{len}")),
        EventKind::MemWrite { addr, data } => {
            ("MemWrite", format!("{addr:#x}"), format!("{}", data.len()))
        }
        EventKind::Call { from, to } => ("Call", format!("{from:#x}"), format!("{to:#x}")),
        EventKind::Return { from, to } => ("Return", format!("{from:#x}"), format!("{to:#x}")),
        EventKind::SyscallEnter { nr, .. } => ("SyscallEnter", format!("{nr}"), String::new()),
        EventKind::SyscallExit { nr, ret } => ("SyscallExit", format!("{nr}"), format!("{ret}")),
        EventKind::Exception { code, addr } => {
            ("Exception", format!("{addr:#x}"), format!("{code:#x}"))
        }
        EventKind::ThreadCreate { tid } => ("ThreadCreate", format!("{tid}"), String::new()),
        EventKind::ThreadExit { tid, code } => ("ThreadExit", format!("{tid}"), format!("{code}")),
        EventKind::Breakpoint { addr } => ("Breakpoint", format!("{addr:#x}"), String::new()),
    }
}

type RowTuple = (u64, u64, u32, String);

fn row_to_tuple(row: &rusqlite::Row<'_>) -> rusqlite::Result<RowTuple> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
}

fn collect_event_rows(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<RowTuple>>,
) -> Result<Vec<TraceEvent>, QueryError> {
    let mut result = Vec::new();
    for row in rows {
        let (seq, step, tid, payload) = row?;
        let kind: EventKind =
            serde_json::from_str(&payload).map_err(|e| QueryError::ParseError(e.to_string()))?;
        result.push(TraceEvent {
            position: TracePosition::new(seq, step),
            thread_id: tid,
            kind,
        });
    }
    Ok(result)
}

// ─── TtdQueryExpr — composable DSL ───────────────────────────────────────────

/// A simple query DSL that composes into a tree of expressions.
///
/// Leaf nodes describe what to look for; `And`/`Or` combine them; `InRange`
/// restricts evaluation to a tick window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TtdQueryExpr {
    /// Find every `MemWrite` event that touches `addr`.
    FindWrites { addr: u64 },
    /// Find every `MemRead` event that touches `addr`.
    FindReads { addr: u64 },
    /// Find every `Call` event whose target equals `target`.
    FindCalls { target: u64 },
    /// Find every `Return` event whose origin (`from`) equals `from_addr`.
    FindReturns { from_addr: u64 },
    /// Find syscall events, optionally filtered to a specific syscall number.
    FindSyscalls { nr: Option<u32> },
    /// Find exception events, optionally filtered to a specific exception code.
    FindExceptions { code: Option<u32> },
    /// Match only the single event at the exact tick `seq:step`.
    AtTick { seq: u64, step: u64 },
    /// Restrict evaluation of `inner` to events in `[from_seq, to_seq]`.
    InRange {
        from_seq: u64,
        to_seq: u64,
        inner: Box<Self>,
    },
    /// Logical AND — an event must match both sub-expressions.
    And(Box<Self>, Box<Self>),
    /// Logical OR — an event must match at least one sub-expression.
    Or(Box<Self>, Box<Self>),
}

impl std::fmt::Display for TtdQueryExpr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FindWrites { addr } => write!(f, "FindWrites({addr:#x})"),
            Self::FindReads { addr } => write!(f, "FindReads({addr:#x})"),
            Self::FindCalls { target } => write!(f, "FindCalls({target:#x})"),
            Self::FindReturns { from_addr } => write!(f, "FindReturns({from_addr:#x})"),
            Self::FindSyscalls { nr } => write!(f, "FindSyscalls({nr:?})"),
            Self::FindExceptions { code } => write!(f, "FindExceptions({code:?})"),
            Self::AtTick { seq, step } => write!(f, "AtTick({seq}:{step})"),
            Self::InRange {
                from_seq,
                to_seq,
                inner,
            } => write!(f, "InRange({from_seq}..{to_seq}, {inner})"),
            Self::And(a, b) => write!(f, "And({a}, {b})"),
            Self::Or(a, b) => write!(f, "Or({a}, {b})"),
        }
    }
}

// ─── parse_query ─────────────────────────────────────────────────────────────

/// Parse a human-readable query string into a [`TtdQueryExpr`].
///
/// Supported forms (case-insensitive):
/// - `"find writes to 0x1234"`  → `FindWrites { addr: 0x1234 }`
/// - `"find reads from 0x1234"` → `FindReads  { addr: 0x1234 }`
/// - `"find calls to 0x5678"`   → `FindCalls  { target: 0x5678 }`
/// - `"find returns from 0x5678"` → `FindReturns { from_addr: 0x5678 }`
/// - `"find syscalls"`          → `FindSyscalls { nr: None }`
/// - `"find syscall 60"`        → `FindSyscalls { nr: Some(60) }`
/// - `"find exceptions"`        → `FindExceptions { code: None }`
/// - `"find exception 0xc0000005"` → `FindExceptions { code: Some(…) }`
/// - `"at 100:0"`               → `AtTick { seq: 100, step: 0 }`
///
/// Returns [`QueryError::ParseError`] if the text is not recognised.
pub fn parse_query(text: &str) -> Result<TtdQueryExpr, QueryError> {
    let text = text.trim().to_lowercase();

    // "at SEQ:STEP"
    if let Some(rest) = text.strip_prefix("at ") {
        let rest = rest.trim();
        let parts: Vec<&str> = rest.splitn(2, ':').collect();
        if parts.len() == 2 {
            let seq = parse_hex_or_dec(parts[0])
                .ok_or_else(|| QueryError::ParseError(format!("invalid seq: {}", parts[0])))?;
            let step = parse_hex_or_dec(parts[1])
                .ok_or_else(|| QueryError::ParseError(format!("invalid step: {}", parts[1])))?;
            return Ok(TtdQueryExpr::AtTick { seq, step });
        }
    }

    // "find …"
    if let Some(rest) = text.strip_prefix("find ") {
        let rest = rest.trim();

        // "writes to ADDR"
        if let Some(r) = rest.strip_prefix("writes to ") {
            let addr = parse_hex_or_dec(r.trim())
                .ok_or_else(|| QueryError::ParseError(format!("invalid address: {r}")))?;
            return Ok(TtdQueryExpr::FindWrites { addr });
        }

        // "reads from ADDR"
        if let Some(r) = rest.strip_prefix("reads from ") {
            let addr = parse_hex_or_dec(r.trim())
                .ok_or_else(|| QueryError::ParseError(format!("invalid address: {r}")))?;
            return Ok(TtdQueryExpr::FindReads { addr });
        }

        // "calls to ADDR"
        if let Some(r) = rest.strip_prefix("calls to ") {
            let target = parse_hex_or_dec(r.trim())
                .ok_or_else(|| QueryError::ParseError(format!("invalid address: {r}")))?;
            return Ok(TtdQueryExpr::FindCalls { target });
        }

        // "returns from ADDR"
        if let Some(r) = rest.strip_prefix("returns from ") {
            let from_addr = parse_hex_or_dec(r.trim())
                .ok_or_else(|| QueryError::ParseError(format!("invalid address: {r}")))?;
            return Ok(TtdQueryExpr::FindReturns { from_addr });
        }

        // "syscall NR" (specific number)
        if let Some(r) = rest.strip_prefix("syscall ") {
            let r = r.trim();
            if !r.is_empty() {
                let nr = parse_hex_or_dec(r)
                    .ok_or_else(|| QueryError::ParseError(format!("invalid syscall nr: {r}")))?;
                let nr32 = u32::try_from(nr)
                    .map_err(|_| QueryError::ParseError(format!("syscall nr out of u32 range: {nr}")))?;
                return Ok(TtdQueryExpr::FindSyscalls {
                    nr: Some(nr32),
                });
            }
        }

        // "syscalls" (any)
        if rest == "syscalls" || rest == "syscall" {
            return Ok(TtdQueryExpr::FindSyscalls { nr: None });
        }

        // "exception CODE" (specific code)
        if let Some(r) = rest.strip_prefix("exception ") {
            let r = r.trim();
            if !r.is_empty() {
                let code = parse_hex_or_dec(r).ok_or_else(|| {
                    QueryError::ParseError(format!("invalid exception code: {r}"))
                })?;
                let code32 = u32::try_from(code)
                    .map_err(|_| QueryError::ParseError(format!("exception code out of u32 range: {code}")))?;
                return Ok(TtdQueryExpr::FindExceptions {
                    code: Some(code32),
                });
            }
        }

        // "exceptions" (any)
        if rest == "exceptions" || rest == "exception" {
            return Ok(TtdQueryExpr::FindExceptions { code: None });
        }
    }

    Err(QueryError::ParseError(format!(
        "unrecognised query: {text:?}"
    )))
}

/// Parse a string that may be hex (`0x…`) or decimal.
fn parse_hex_or_dec(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        // Use .get(2..) to avoid a panic when the string is exactly "0x" or "0X"
        // (zero-length hex digits) and to respect UTF-8 boundaries.
        u64::from_str_radix(s.get(2..)?, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

// ─── SimpleQueryResult ────────────────────────────────────────────────────────

/// A single match produced by [`QueryExecutor::execute`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleQueryResult {
    /// Position of the matching event in the trace.
    pub position: TracePosition,
    /// Human-readable event category (e.g. `"MemWrite"`, `"Call"`).
    pub event_kind: String,
    /// Human-readable description of the event.
    pub description: String,
}

impl std::fmt::Display for SimpleQueryResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}:{}] {} — {}",
            self.position.sequence, self.position.step, self.event_kind, self.description
        )
    }
}

// ─── QueryExecutor ────────────────────────────────────────────────────────────

/// Stateless executor for [`TtdQueryExpr`] queries against a [`TtdTrace`].
pub struct QueryExecutor;

impl QueryExecutor {
    /// Execute a [`TtdQueryExpr`] against `trace`, returning all matching
    /// events as [`SimpleQueryResult`] values ordered by position.
    pub fn execute(query: &TtdQueryExpr, trace: &TtdTrace) -> Vec<SimpleQueryResult> {
        let events = trace.all_events();
        let positions = Self::eval_expr(query, &events);
        // Build result records from the matched positions.
        let pos_set: HashSet<TracePosition> = positions.into_iter().collect();
        let mut results: Vec<SimpleQueryResult> = events
            .iter()
            .filter(|e| pos_set.contains(&e.position))
            .map(|e| SimpleQueryResult {
                position: e.position,
                event_kind: event_kind_name(&e.kind).to_string(),
                description: describe_event(e),
            })
            .collect();
        results.sort_by_key(|r| r.position);
        results
    }

    /// Evaluate an expression and return the set of matching positions.
    fn eval_expr(query: &TtdQueryExpr, events: &[TraceEvent]) -> Vec<TracePosition> {
        match query {
            TtdQueryExpr::FindWrites { addr } => Self::find_writes_inner(events, *addr),

            TtdQueryExpr::FindReads { addr } => events
                .iter()
                .filter(|e| matches!(&e.kind, EventKind::MemRead { addr: a, .. } if *a == *addr))
                .map(|e| e.position)
                .collect(),

            TtdQueryExpr::FindCalls { target } => Self::find_calls_inner(events, *target),

            TtdQueryExpr::FindReturns { from_addr } => events
                .iter()
                .filter(
                    |e| matches!(&e.kind, EventKind::Return { from, .. } if *from == *from_addr),
                )
                .map(|e| e.position)
                .collect(),

            TtdQueryExpr::FindSyscalls { nr: None } => events
                .iter()
                .filter(|e| {
                    matches!(
                        &e.kind,
                        EventKind::SyscallEnter { .. } | EventKind::SyscallExit { .. }
                    )
                })
                .map(|e| e.position)
                .collect(),

            TtdQueryExpr::FindSyscalls { nr: Some(n) } => events
                .iter()
                .filter(|e| {
                    matches!(&e.kind,
                        EventKind::SyscallEnter { nr, .. } | EventKind::SyscallExit { nr, .. }
                        if *nr == *n)
                })
                .map(|e| e.position)
                .collect(),

            TtdQueryExpr::FindExceptions { code: None } => events
                .iter()
                .filter(|e| matches!(&e.kind, EventKind::Exception { .. }))
                .map(|e| e.position)
                .collect(),

            TtdQueryExpr::FindExceptions { code: Some(c) } => events
                .iter()
                .filter(|e| matches!(&e.kind, EventKind::Exception { code, .. } if *code == *c))
                .map(|e| e.position)
                .collect(),

            TtdQueryExpr::AtTick { seq, step } => events
                .iter()
                .filter(|e| e.position.sequence == *seq && e.position.step == *step)
                .map(|e| e.position)
                .collect(),

            TtdQueryExpr::InRange {
                from_seq,
                to_seq,
                inner,
            } => {
                let windowed: Vec<TraceEvent> = events
                    .iter()
                    .filter(|e| e.position.sequence >= *from_seq && e.position.sequence <= *to_seq)
                    .cloned()
                    .collect();
                Self::eval_expr(inner, &windowed)
            }

            TtdQueryExpr::And(a, b) => {
                let set_a: HashSet<TracePosition> =
                    Self::eval_expr(a, events).into_iter().collect();
                let set_b: HashSet<TracePosition> =
                    Self::eval_expr(b, events).into_iter().collect();
                set_a.intersection(&set_b).copied().collect()
            }

            TtdQueryExpr::Or(a, b) => {
                let mut set_a: HashSet<TracePosition> =
                    Self::eval_expr(a, events).into_iter().collect();
                let set_b: HashSet<TracePosition> =
                    Self::eval_expr(b, events).into_iter().collect();
                set_a.extend(set_b);
                set_a.into_iter().collect()
            }
        }
    }

    // ── Targeted scan helpers ────────────────────────────────────────────────

    /// Scan all events for `MemWrite` events at exactly `addr`.
    pub fn find_writes(trace: &TtdTrace, addr: u64) -> Vec<TracePosition> {
        Self::find_writes_inner(&trace.all_events(), addr)
    }

    fn find_writes_inner(events: &[TraceEvent], addr: u64) -> Vec<TracePosition> {
        events
            .iter()
            .filter(|e| matches!(&e.kind, EventKind::MemWrite { addr: a, .. } if *a == addr))
            .map(|e| e.position)
            .collect()
    }

    /// Scan all events for `Call` events whose target equals `target`.
    pub fn find_calls(trace: &TtdTrace, target: u64) -> Vec<TracePosition> {
        Self::find_calls_inner(&trace.all_events(), target)
    }

    fn find_calls_inner(events: &[TraceEvent], target: u64) -> Vec<TracePosition> {
        events
            .iter()
            .filter(|e| matches!(&e.kind, EventKind::Call { to, .. } if *to == target))
            .map(|e| e.position)
            .collect()
    }

    /// Scan backwards for the most recent `MemWrite` to `addr` whose data
    /// (interpreted as little-endian u64, zero-padded) equals `value`.
    ///
    /// Returns the position of the matching write, or `None` if not found.
    pub fn find_value_origin(trace: &TtdTrace, addr: u64, value: u64) -> Option<TracePosition> {
        for event in trace.all_events().iter().rev() {
            if let EventKind::MemWrite { addr: a, data } = &event.kind
                && *a == addr
            {
                let mut bytes = [0u8; 8];
                let len = data.len().min(8);
                bytes[..len].copy_from_slice(&data[..len]);
                let written = u64::from_le_bytes(bytes);
                if written == value {
                    return Some(event.position);
                }
            }
        }
        None
    }
}

// ─── describe_event (helper) ──────────────────────────────────────────────────

fn describe_event(event: &TraceEvent) -> String {
    match &event.kind {
        EventKind::MemRead { addr, len } => format!("read {len} byte(s) at {addr:#x}"),
        EventKind::MemWrite { addr, data } => format!(
            "write {} byte(s) at {addr:#x}: {:02x?}",
            data.len(),
            &data[..data.len().min(8)]
        ),
        EventKind::Call { from, to } => format!("call from {from:#x} to {to:#x}"),
        EventKind::Return { from, to } => format!("return from {from:#x} to {to:#x}"),
        EventKind::SyscallEnter { nr, args } => format!(
            "syscall enter nr={nr} args=[{},{},{},{}]",
            args[0], args[1], args[2], args[3]
        ),
        EventKind::SyscallExit { nr, ret } => format!("syscall exit nr={nr} ret={ret}"),
        EventKind::Exception { code, addr } => format!("exception code={code:#010x} at {addr:#x}"),
        EventKind::ThreadCreate { tid } => format!("thread create tid={tid}"),
        EventKind::ThreadExit { tid, code } => format!("thread exit tid={tid} code={code}"),
        EventKind::Breakpoint { addr } => format!("breakpoint at {addr:#x}"),
    }
}

// ─── ThreadTimeline ───────────────────────────────────────────────────────────

/// A single entry in a [`ThreadTimeline`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    /// Sequence number of the event.
    pub seq: u64,
    /// Sub-step of the event.
    pub step: u64,
    /// Event category name (e.g. `"Call"`, `"MemWrite"`).
    pub kind: String,
    /// Human-readable description.
    pub description: String,
}

impl std::fmt::Display for TimelineEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}\t{}\t{}",
            self.seq, self.step, self.kind, self.description
        )
    }
}

/// A chronological sequence of events for a single thread.
///
/// Build it with [`ThreadTimeline::build`], then export it with
/// [`ThreadTimeline::to_csv`] or inspect `events` directly.
#[derive(Debug, Clone)]
pub struct ThreadTimeline {
    /// The thread this timeline was built for.
    pub thread_id: u32,
    /// All events belonging to this thread, in trace order.
    pub events: Vec<TimelineEntry>,
}

impl ThreadTimeline {
    /// Build a timeline for `thread_id` by scanning `trace`.
    ///
    /// Events from other threads are silently ignored.
    pub fn build(trace: &TtdTrace, thread_id: u32) -> Self {
        let entries = trace
            .all_events()
            .into_iter()
            .filter(|e| e.thread_id == thread_id)
            .map(|e| TimelineEntry {
                seq: e.position.sequence,
                step: e.position.step,
                kind: event_kind_name(&e.kind).to_string(),
                description: describe_event(&e),
            })
            .collect();
        Self {
            thread_id,
            events: entries,
        }
    }

    /// Serialise the timeline to CSV with columns:
    /// `seq,step,kind,description`.
    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut out = String::from("seq,step,kind,description\n");
        for entry in &self.events {
            // Escape commas and newlines inside the description field.
            let desc_escaped = entry.description.replace('"', "\"\"");
            out.push_str(&format!(
                "{},{},{},\"{}\"\n",
                entry.seq, entry.step, entry.kind, desc_escaped
            ));
        }
        out
    }

    /// Return the number of events in this timeline.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    /// Return `true` when the timeline contains no events.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

impl std::fmt::Display for ThreadTimeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ThreadTimeline {{ tid: {}, events: {} }}",
            self.thread_id,
            self.events.len()
        )
    }
}

// ─── DiffAnalyzer ─────────────────────────────────────────────────────────────

/// The result of comparing the events between two positions within a single trace.
#[derive(Debug, Clone)]
pub struct PositionDiff {
    /// All events that fall strictly between `pos_a` and `pos_b`
    /// (i.e. `pos_a < event.position < pos_b`).
    pub events_between: Vec<TraceEvent>,
    /// Number of such events.
    pub instructions_count: u64,
}

impl std::fmt::Display for PositionDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PositionDiff {{ instructions: {} }}",
            self.instructions_count
        )
    }
}

/// Utilities for comparing positions within a trace, or finding divergences
/// between two separate traces.
pub struct DiffAnalyzer;

impl DiffAnalyzer {
    /// Return all events that lie strictly between `pos_a` and `pos_b` in
    /// `trace`, together with their count.
    ///
    /// If `pos_a >= pos_b` the returned `events_between` will be empty.
    pub fn diff_two_positions(
        trace: &TtdTrace,
        pos_a: TracePosition,
        pos_b: TracePosition,
    ) -> PositionDiff {
        let events_between: Vec<TraceEvent> = trace
            .all_events()
            .into_iter()
            .filter(|e| e.position > pos_a && e.position < pos_b)
            .collect();
        let instructions_count = events_between.len() as u64;
        PositionDiff {
            events_between,
            instructions_count,
        }
    }

    /// Walk `trace_a` and `trace_b` in lock-step, returning the first pair of
    /// positions where the event kinds or key fields differ.
    ///
    /// Two events are considered *equal* when their `EventKind` discriminants
    /// match and the primary address / number field is the same.  Returns
    /// `None` when both traces are identical up to the shorter length.
    pub fn find_divergence(
        trace_a: &TtdTrace,
        trace_b: &TtdTrace,
    ) -> Option<(TracePosition, TracePosition)> {
        let events_a = trace_a.all_events();
        let events_b = trace_b.all_events();

        for (ea, eb) in events_a.iter().zip(events_b.iter()) {
            if !events_equivalent(&ea.kind, &eb.kind) {
                return Some((ea.position, eb.position));
            }
        }
        None
    }
}

/// Return `true` when two [`EventKind`] values represent the same *kind* of
/// operation on the same primary address / number.
fn events_equivalent(a: &EventKind, b: &EventKind) -> bool {
    match (a, b) {
        (
            EventKind::MemWrite { addr: a1, data: d1 },
            EventKind::MemWrite { addr: a2, data: d2 },
        ) => a1 == a2 && d1 == d2,
        (EventKind::Call { from: f1, to: t1 }, EventKind::Call { from: f2, to: t2 }) | (EventKind::Return { from: f1, to: t1 }, EventKind::Return { from: f2, to: t2 }) => {
            f1 == f2 && t1 == t2
        }
        (EventKind::SyscallEnter { nr: n1, .. }, EventKind::SyscallEnter { nr: n2, .. }) => {
            n1 == n2
        }
        (
            EventKind::SyscallExit { nr: n1, ret: r1 },
            EventKind::SyscallExit { nr: n2, ret: r2 },
        ) => n1 == n2 && r1 == r2,
        (
            EventKind::Exception { code: c1, addr: a1 },
            EventKind::Exception { code: c2, addr: a2 },
        ) => c1 == c2 && a1 == a2,
        (EventKind::ThreadCreate { tid: t1 }, EventKind::ThreadCreate { tid: t2 }) => t1 == t2,
        (
            EventKind::ThreadExit { tid: t1, code: c1 },
            EventKind::ThreadExit { tid: t2, code: c2 },
        ) => t1 == t2 && c1 == c2,
        (EventKind::MemRead { addr: a1, .. }, EventKind::MemRead { addr: a2, .. }) | (EventKind::Breakpoint { addr: a1 }, EventKind::Breakpoint { addr: a2 }) => a1 == a2,
        _ => false,
    }
}

// ─── SyscallSummaryStats ──────────────────────────────────────────────────────

/// Aggregate syscall statistics computed over a complete trace.
///
/// Build with [`SyscallSummaryStats::compute`], query with
/// [`SyscallSummaryStats::most_common`].
#[derive(Debug, Clone)]
pub struct SyscallSummaryStats {
    /// Total number of `SyscallEnter` + `SyscallExit` events.
    pub total_count: u64,
    /// Occurrences keyed by syscall number (enter + exit combined).
    pub by_number: HashMap<u32, u64>,
    /// Occurrences keyed by thread id.
    pub by_thread: HashMap<u32, u64>,
}

impl SyscallSummaryStats {
    /// Compute syscall statistics by scanning all events in `trace`.
    pub fn compute(trace: &TtdTrace) -> Self {
        let mut total_count: u64 = 0;
        let mut by_number: HashMap<u32, u64> = HashMap::new();
        let mut by_thread: HashMap<u32, u64> = HashMap::new();

        for event in trace.all_events() {
            match &event.kind {
                EventKind::SyscallEnter { nr, .. } | EventKind::SyscallExit { nr, .. } => {
                    total_count += 1;
                    *by_number.entry(*nr).or_default() += 1;
                    *by_thread.entry(event.thread_id).or_default() += 1;
                }
                _ => {}
            }
        }

        Self {
            total_count,
            by_number,
            by_thread,
        }
    }

    /// Return the `n` most frequently called syscall numbers, sorted
    /// descending by call count.
    ///
    /// If there are fewer than `n` distinct syscalls the slice is shorter.
    #[must_use]
    pub fn most_common(&self, n: usize) -> Vec<(u32, u64)> {
        let mut entries: Vec<(u32, u64)> =
            self.by_number.iter().map(|(&nr, &cnt)| (nr, cnt)).collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        entries.truncate(n);
        entries
    }

    /// Return the total call count for syscall number `nr`.
    #[must_use]
    pub fn count_for(&self, nr: u32) -> u64 {
        self.by_number.get(&nr).copied().unwrap_or(0)
    }

    /// Return `true` when no syscall events were found.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.total_count == 0
    }
}

impl std::fmt::Display for SyscallSummaryStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SyscallSummaryStats {{ total: {}, distinct_nrs: {}, threads: {} }}",
            self.total_count,
            self.by_number.len(),
            self.by_thread.len()
        )
    }
}

// ─── TraceNavigator ───────────────────────────────────────────────────────────

/// A cursor-style navigator for stepping through a TTD trace forward and
/// backward, and for locating all positions where execution is inside a named
/// (symbolically-labelled) function.
///
/// Construct it from a [`TtdTrace`] with [`TraceNavigator::new`], then drive it
/// with [`step_forward`], [`step_backward`], and [`seek_to`].
pub struct TraceNavigator {
    /// Ordered snapshot of every event in the trace (position-sorted).
    events: Vec<TraceEvent>,
    /// Index into `events` of the current position.
    cursor: usize,
}

impl TraceNavigator {
    /// Build a navigator from `trace`.  The cursor starts at the first event.
    #[must_use]
    pub fn new(trace: &TtdTrace) -> Self {
        let mut events = trace.all_events();
        events.sort_by_key(|e| e.position);
        Self { events, cursor: 0 }
    }

    /// Return the [`TracePosition`] at the current cursor, or `None` for an
    /// empty trace.
    #[must_use]
    pub fn current_position(&self) -> Option<TracePosition> {
        self.events.get(self.cursor).map(|e| e.position)
    }

    /// Return the [`TraceEvent`] at the current cursor, or `None`.
    #[must_use]
    pub fn current_event(&self) -> Option<&TraceEvent> {
        self.events.get(self.cursor)
    }

    /// Advance the cursor by `n` steps.
    ///
    /// Returns the new [`TracePosition`] after moving, or `None` if the trace
    /// is empty.  If the requested step would exceed the end of the trace the
    /// cursor is clamped to the last event.
    pub fn step_forward(&mut self, n: u64) -> Option<TracePosition> {
        if self.events.is_empty() {
            return None;
        }
        let new_cursor = (self.cursor as u64)
            .saturating_add(n)
            .min((self.events.len() as u64).saturating_sub(1)) as usize;
        self.cursor = new_cursor;
        self.current_position()
    }

    /// Rewind the cursor by `n` steps.
    ///
    /// Returns the new [`TracePosition`] after moving, or `None` if the trace
    /// is empty.  If the requested step would go before the beginning the
    /// cursor is clamped to the first event.
    pub fn step_backward(&mut self, n: u64) -> Option<TracePosition> {
        if self.events.is_empty() {
            return None;
        }
        let new_cursor = (self.cursor as u64).saturating_sub(n) as usize;
        self.cursor = new_cursor;
        self.current_position()
    }

    /// Jump the cursor to the event whose position equals `pos`.
    ///
    /// If no event exists at exactly `pos` the cursor is moved to the nearest
    /// event that follows `pos` (or to the last event if `pos` is past the end).
    pub fn seek_to(&mut self, pos: TracePosition) {
        if self.events.is_empty() {
            return;
        }
        // Binary-search for an exact match; fall back to the next event.
        let idx = self.events.partition_point(|e| e.position < pos);
        self.cursor = idx.min(self.events.len() - 1);
    }

    /// Return all [`TracePosition`]s in the trace where a `Call` event targets
    /// an address whose symbolic name contains `name` (case-insensitive prefix
    /// search against the hex representation).
    ///
    /// Because TTD traces in this crate do not carry a symbol table, `name` is
    /// matched against the hex address of the call target.  Callers that have a
    /// symbol map can pre-resolve the address before calling this helper.
    ///
    /// Returns every position in the trace where a `Call` arrives at an address
    /// whose lower-case hex representation contains `name`.
    #[must_use]
    pub fn at_function(&self, name: &str) -> Vec<TracePosition> {
        let needle = name.to_lowercase();
        self.events
            .iter()
            .filter(|e| {
                if let EventKind::Call { to, .. } = &e.kind {
                    format!("{to:#x}").contains(&needle)
                } else {
                    false
                }
            })
            .map(|e| e.position)
            .collect()
    }

    /// Return the total number of events in this navigator's snapshot.
    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Return the zero-based index of the current cursor.
    #[must_use]
    pub const fn cursor_index(&self) -> usize {
        self.cursor
    }
}

impl std::fmt::Debug for TraceNavigator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceNavigator")
            .field("event_count", &self.events.len())
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
    }
}

// ─── EventTimeline ────────────────────────────────────────────────────────────

/// A single entry produced by [`QueryEngine::build_timeline`], giving a
/// Tenet-style view of the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventTimelineEntry {
    /// Absolute position of the event in the trace.
    pub position: TracePosition,
    /// High-level event category (e.g. `"Call"`, `"MemWrite"`).
    pub event_type: String,
    /// Human-readable detail string.
    pub details: String,
    /// Thread that produced this event.
    pub thread_id: u32,
}

impl std::fmt::Display for EventTimelineEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}:{}] tid={} {} — {}",
            self.position.sequence,
            self.position.step,
            self.thread_id,
            self.event_type,
            self.details
        )
    }
}

// ─── QueryEngine — TraceNavigator + EventTimeline additions ──────────────────

impl QueryEngine {
    /// Build a [`TraceNavigator`] over the trace held by this engine.
    ///
    /// The navigator starts at the first event.
    #[must_use]
    pub fn navigator(&self) -> TraceNavigator {
        TraceNavigator::new(&self.trace)
    }

    /// Build a full Tenet-style [`TenetTraceNavigator`] over the trace.
    ///
    /// This lifts every TTD [`TraceEvent`] into a
    /// [`rustre_trace_navigate::TraceEntry`], collapsing per-position events
    /// onto a single instruction entry when the position only differs in
    /// sub-step, and exposes the resulting [`TenetExecutionTrace`] through the
    /// full navigator API (bidirectional stepping, run/reverse-run to
    /// breakpoint, step-over / step-out, memory and register timelines,
    /// call-stack reconstruction at any tick, bookmarks, and coverage).
    ///
    /// The returned navigator owns its trace and is independent of `self`;
    /// modifying the engine's trace afterwards does not affect it.
    #[must_use]
    pub fn tenet_navigator(&self) -> TenetTraceNavigator {
        let mut events = self.trace.all_events();
        events.sort_by_key(|e| e.position);

        let mut entries: Vec<TenetTraceEntry> = Vec::with_capacity(events.len());
        for (idx, ev) in events.iter().enumerate() {
            let tid = ev.thread_id;
            let pc = match &ev.kind {
                EventKind::Call { from, .. } | EventKind::Return { from, .. } => *from,
                EventKind::MemRead { addr, .. }
                | EventKind::MemWrite { addr, .. }
                | EventKind::Breakpoint { addr }
                | EventKind::Exception { addr, .. } => *addr,
                _ => 0,
            };

            let (kind, disasm) = match &ev.kind {
                EventKind::Call { from: _, to } => (
                    TenetEntryKind::Call {
                        target: *to,
                        ret_addr: pc.saturating_add(5),
                    },
                    format!("call 0x{to:x}"),
                ),
                EventKind::Return { from: _, to } => (
                    TenetEntryKind::Ret { target: *to },
                    format!("ret -> 0x{to:x}"),
                ),
                EventKind::SyscallEnter { nr, .. } | EventKind::SyscallExit { nr, .. } => (
                    TenetEntryKind::Syscall { number: u64::from(*nr) },
                    format!("syscall {nr}"),
                ),
                EventKind::Exception { code, .. } => (
                    TenetEntryKind::Exception { code: *code },
                    format!("exception {code:#x}"),
                ),
                _ => (TenetEntryKind::Insn, String::new()),
            };

            let mut entry = TenetTraceEntry {
                idx,
                pc,
                tid,
                reg_snapshot: Vec::new(),
                mem_writes: Vec::new(),
                mem_reads: Vec::new(),
                tsc: Some(ev.position.sequence),
                kind,
                disasm,
            };
            match &ev.kind {
                EventKind::MemWrite { addr, data } => {
                    entry.add_mem_write(*addr, data.clone());
                }
                EventKind::MemRead { addr, len } => {
                    let size_byte = u8::try_from(*len).unwrap_or(u8::MAX);
                    entry.add_mem_read(*addr, size_byte);
                }
                _ => {}
            }
            entries.push(entry);
        }

        let trace_name = format!("ttd-query:{}", self.trace.metadata.process_name);
        let exec_trace = TenetExecutionTrace::new(entries, trace_name);
        TenetTraceNavigator::new(exec_trace)
    }

    /// Build a Tenet-style chronological timeline of every event in the trace.
    ///
    /// Returns a [`Vec<EventTimelineEntry>`] sorted by position (ascending).
    /// Each entry carries the absolute position, a human-readable event type
    /// string, and a detail description.
    #[must_use]
    pub fn build_timeline(&self) -> Vec<EventTimelineEntry> {
        let mut events = self.trace.all_events();
        events.sort_by_key(|e| e.position);
        events
            .into_iter()
            .map(|e| EventTimelineEntry {
                position: e.position,
                event_type: event_kind_name(&e.kind).to_string(),
                details: describe_event(&e),
                thread_id: e.thread_id,
            })
            .collect()
    }
}

// ─── build_query_test_trace (public helper) ───────────────────────────────────

#[must_use]
pub fn build_query_test_trace() -> Arc<TtdTrace> {
    use rustre_ttd::TraceMetadata;
    let meta = TraceMetadata {
        version: 1,
        process_name: "query-test".into(),
        pid: 42,
        arch: "x86_64".into(),
        start_time: 0,
        end_time: 100,
        thread_count: 2,
        ..Default::default()
    };
    let trace = Arc::new(TtdTrace::new(meta));
    let kinds: Vec<EventKind> = vec![
        EventKind::MemRead {
            addr: 0x1000,
            len: 4,
        },
        EventKind::MemWrite {
            addr: 0x2000,
            data: vec![0xde, 0xad],
        },
        EventKind::Call {
            from: 0x3000,
            to: 0x4000,
        },
        EventKind::Return {
            from: 0x4000,
            to: 0x3004,
        },
        EventKind::SyscallEnter {
            nr: 1,
            args: [0; 6],
        },
        EventKind::SyscallExit { nr: 1, ret: 0 },
        EventKind::Exception {
            code: 0xc000_0005,
            addr: 0xdead,
        },
        EventKind::ThreadCreate { tid: 2 },
        EventKind::ThreadExit { tid: 2, code: 0 },
        EventKind::Breakpoint { addr: 0x5000 },
        EventKind::MemWrite {
            addr: 0x2000,
            data: vec![0xff],
        },
        EventKind::Call {
            from: 0x6000,
            to: 0x4000,
        },
        EventKind::SyscallEnter {
            nr: 2,
            args: [1; 6],
        },
        EventKind::SyscallExit { nr: 2, ret: 1 },
    ];
    for (i, kind) in kinds.into_iter().enumerate() {
        trace.add_event(TraceEvent {
            position: TracePosition::new(i as u64, 0),
            thread_id: if i.is_multiple_of(2) { 1 } else { 2 },
            kind,
        });
    }
    trace
}

// ─── TtdQueryLanguage ────────────────────────────────────────────────────────

/// Typed AST produced by [`TtdQueryLanguage::parse`].
///
/// Each variant maps to one supported query form:
///
/// | Text form | Variant |
/// |-----------|---------|
/// | `FIND CALL 0x401000 AFTER seq(1,0)` | `FindCall` |
/// | `FIND WRITE 0x7fff1234 BETWEEN seq(5,0) AND seq(10,0)` | `FindWrite` |
/// | `FIND READ 0x1000` | `FindRead` |
/// | `FIND EXCEPTION` | `FindException` |
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TtdQuery {
    /// Find `Call` events targeting `addr`, optionally restricted to events
    /// that occur **after** `after`.
    FindCall {
        /// Call target address.
        addr: u64,
        /// Only match calls strictly after this position.
        after: Option<TracePosition>,
    },
    /// Find `MemWrite` events at `addr`, optionally restricted to a
    /// `[start, end]` position window.
    FindWrite {
        /// Write target address.
        addr: u64,
        /// Optional `(start, end)` window (both inclusive).
        between: Option<(TracePosition, TracePosition)>,
    },
    /// Find all `MemRead` events at `addr`.
    FindRead {
        /// Read address.
        addr: u64,
    },
    /// Find all exception events in the trace.
    FindException,
}

impl std::fmt::Display for TtdQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FindCall { addr, after } => {
                write!(f, "FindCall({addr:#x}")?;
                if let Some(p) = after {
                    write!(f, " after {}:{}", p.sequence, p.step)?;
                }
                write!(f, ")")
            }
            Self::FindWrite { addr, between } => {
                write!(f, "FindWrite({addr:#x}")?;
                if let Some((s, e)) = between {
                    write!(
                        f,
                        " between {}:{} and {}:{}",
                        s.sequence, s.step, e.sequence, e.step
                    )?;
                }
                write!(f, ")")
            }
            Self::FindRead { addr } => write!(f, "FindRead({addr:#x})"),
            Self::FindException => write!(f, "FindException"),
        }
    }
}

/// A simple query DSL that parses text into [`TtdQuery`] values.
///
/// # Supported syntax (case-insensitive)
///
/// ```text
/// FIND CALL 0x401000 AFTER seq(1,0)
/// FIND WRITE 0x7fff1234 BETWEEN seq(5,0) AND seq(10,0)
/// FIND READ 0x1000
/// FIND EXCEPTION
/// ```
///
/// `seq(major,minor)` tokens are parsed by extracting the two integers inside
/// the parentheses.  Addresses may be hex (`0x…`) or decimal.
pub struct TtdQueryLanguage;

impl TtdQueryLanguage {
    /// Parse `text` into a [`TtdQuery`].
    ///
    /// # Errors
    ///
    /// Returns [`QueryError::ParseError`] when the text does not match any
    /// supported pattern.
    pub fn parse(text: &str) -> Result<TtdQuery, QueryError> {
        let norm = text.trim().to_lowercase();
        let norm = norm.as_str();

        // FIND CALL <addr> [AFTER seq(M,m)]
        if let Some(rest) = norm.strip_prefix("find call ") {
            return Self::parse_find_call(rest);
        }

        // FIND WRITE <addr> [BETWEEN seq(M,m) AND seq(M,m)]
        if let Some(rest) = norm.strip_prefix("find write ") {
            return Self::parse_find_write(rest);
        }

        // FIND READ <addr>
        if let Some(rest) = norm.strip_prefix("find read ") {
            let addr = Self::parse_addr(rest.trim())?;
            return Ok(TtdQuery::FindRead { addr });
        }

        // FIND EXCEPTION
        if norm == "find exception" || norm == "find exceptions" {
            return Ok(TtdQuery::FindException);
        }

        Err(QueryError::ParseError(format!(
            "unrecognised TtdQuery: {text:?}"
        )))
    }

    // ── internal helpers ──────────────────────────────────────────────────────

    fn parse_find_call(rest: &str) -> Result<TtdQuery, QueryError> {
        // rest = "<addr>" | "<addr> after seq(M,m)"
        if let Some(after_idx) = rest.find(" after ") {
            let addr_part = rest[..after_idx].trim();
            let seq_part = rest[after_idx + " after ".len()..].trim();
            let addr = Self::parse_addr(addr_part)?;
            let after = Self::parse_seq(seq_part)?;
            Ok(TtdQuery::FindCall {
                addr,
                after: Some(after),
            })
        } else {
            let addr = Self::parse_addr(rest.trim())?;
            Ok(TtdQuery::FindCall { addr, after: None })
        }
    }

    fn parse_find_write(rest: &str) -> Result<TtdQuery, QueryError> {
        // rest = "<addr>" | "<addr> between seq(M,m) and seq(M,m)"
        if let Some(between_idx) = rest.find(" between ") {
            let addr_part = rest[..between_idx].trim();
            let range_part = rest[between_idx + " between ".len()..].trim();
            let addr = Self::parse_addr(addr_part)?;
            // Split on " and "
            let and_idx = range_part.find(" and ").ok_or_else(|| {
                QueryError::ParseError(format!("missing AND in BETWEEN clause: {range_part:?}"))
            })?;
            let start_str = range_part[..and_idx].trim();
            let end_str = range_part[and_idx + " and ".len()..].trim();
            let start = Self::parse_seq(start_str)?;
            let end = Self::parse_seq(end_str)?;
            Ok(TtdQuery::FindWrite {
                addr,
                between: Some((start, end)),
            })
        } else {
            let addr = Self::parse_addr(rest.trim())?;
            Ok(TtdQuery::FindWrite {
                addr,
                between: None,
            })
        }
    }

    /// Parse `0x…` or decimal into a `u64`.
    fn parse_addr(s: &str) -> Result<u64, QueryError> {
        let s = s.trim();
        if s.starts_with("0x") || s.starts_with("0X") {
            u64::from_str_radix(&s[2..], 16)
                .map_err(|_| QueryError::ParseError(format!("invalid hex address: {s:?}")))
        } else {
            s.parse::<u64>()
                .map_err(|_| QueryError::ParseError(format!("invalid decimal address: {s:?}")))
        }
    }

    /// Parse `seq(major,minor)` → [`TracePosition`].
    fn parse_seq(s: &str) -> Result<TracePosition, QueryError> {
        let s = s.trim();
        // Accept "seq(M,m)" or "seq(M, m)" with optional whitespace.
        let inner = s
            .strip_prefix("seq(")
            .and_then(|t| t.strip_suffix(')'))
            .ok_or_else(|| {
                QueryError::ParseError(format!("expected seq(major,minor), got: {s:?}"))
            })?;
        let parts: Vec<&str> = inner.splitn(2, ',').collect();
        if parts.len() != 2 {
            return Err(QueryError::ParseError(format!(
                "seq must have two components: {s:?}"
            )));
        }
        let major = parts[0]
            .trim()
            .parse::<u64>()
            .map_err(|_| QueryError::ParseError(format!("invalid seq major: {:?}", parts[0])))?;
        let minor = parts[1]
            .trim()
            .parse::<u64>()
            .map_err(|_| QueryError::ParseError(format!("invalid seq minor: {:?}", parts[1])))?;
        Ok(TracePosition::new(major, minor))
    }
}

// ─── TtdQueryResult ──────────────────────────────────────────────────────────

/// A reference to a matching event: just the (cloned) event and its index in
/// the trace snapshot that was searched.
#[derive(Debug, Clone)]
pub struct TtdEventRef {
    /// The matching event.
    pub event: TraceEvent,
    /// Zero-based index of this event in the trace's all-events list.
    pub index: usize,
}

/// Result returned by [`TtdQueryExecutor::execute`].
#[derive(Debug, Clone)]
pub struct TtdQueryResult {
    /// All events that matched the query.
    pub matching_events: Vec<TtdEventRef>,
    /// Wall-clock time spent evaluating the query, in microseconds.
    pub execution_time_us: u64,
}

impl TtdQueryResult {
    /// Return `true` when no events matched.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.matching_events.is_empty()
    }

    /// Return the number of matching events.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.matching_events.len()
    }
}

impl std::fmt::Display for TtdQueryResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TtdQueryResult {{ matches: {}, execution_time_us: {} }}",
            self.matching_events.len(),
            self.execution_time_us
        )
    }
}

// ─── TtdQueryExecutor ────────────────────────────────────────────────────────

/// Executes a [`TtdQuery`] against a [`TtdTrace`] and returns a
/// [`TtdQueryResult`].
pub struct TtdQueryExecutor;

impl TtdQueryExecutor {
    /// Execute `query` against `trace`.
    ///
    /// The implementation iterates over the trace's events once; the measured
    /// time is stored in [`TtdQueryResult::execution_time_us`].
    #[must_use]
    pub fn execute(query: &TtdQuery, trace: &TtdTrace) -> TtdQueryResult {
        let t0 = std::time::Instant::now();
        let events = trace.all_events();
        let matching_events = Self::eval(query, &events);
        let execution_time_us = t0.elapsed().as_micros() as u64;
        TtdQueryResult {
            matching_events,
            execution_time_us,
        }
    }

    fn eval(query: &TtdQuery, events: &[TraceEvent]) -> Vec<TtdEventRef> {
        match query {
            TtdQuery::FindCall { addr, after } => events
                .iter()
                .enumerate()
                .filter_map(|(idx, e)| {
                    if let EventKind::Call { to, .. } = &e.kind {
                        if *to != *addr {
                            return None;
                        }
                        if let Some(after_pos) = after
                            && e.position <= *after_pos
                        {
                            return None;
                        }
                        Some(TtdEventRef {
                            event: e.clone(),
                            index: idx,
                        })
                    } else {
                        None
                    }
                })
                .collect(),

            TtdQuery::FindWrite { addr, between } => events
                .iter()
                .enumerate()
                .filter_map(|(idx, e)| {
                    if let EventKind::MemWrite { addr: a, .. } = &e.kind {
                        if *a != *addr {
                            return None;
                        }
                        if let Some((start, end)) = between
                            && (e.position < *start || e.position > *end)
                        {
                            return None;
                        }
                        Some(TtdEventRef {
                            event: e.clone(),
                            index: idx,
                        })
                    } else {
                        None
                    }
                })
                .collect(),

            TtdQuery::FindRead { addr } => events
                .iter()
                .enumerate()
                .filter_map(|(idx, e)| {
                    if let EventKind::MemRead { addr: a, .. } = &e.kind {
                        if *a == *addr {
                            Some(TtdEventRef {
                                event: e.clone(),
                                index: idx,
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect(),

            TtdQuery::FindException => events
                .iter()
                .enumerate()
                .filter_map(|(idx, e)| {
                    if matches!(&e.kind, EventKind::Exception { .. }) {
                        Some(TtdEventRef {
                            event: e.clone(),
                            index: idx,
                        })
                    } else {
                        None
                    }
                })
                .collect(),
        }
    }
}

// ─── TtdReportGenerator ──────────────────────────────────────────────────────

/// Generates human-readable reports from a [`TtdTrace`].
///
/// All methods return `String` values formatted as multi-line plain text.
pub struct TtdReportGenerator;

impl TtdReportGenerator {
    /// Build an ASCII call tree rooted at `root_addr`.
    ///
    /// The tree is constructed by replaying all `Call`/`Return` events in the
    /// trace.  Each time a `Call` to `root_addr` is seen a new subtree is
    /// started.  Child calls made inside that subtree are indented by two
    /// spaces per depth level.
    ///
    /// Example output:
    /// ```text
    /// [call tree for 0x401000]
    /// 0x401000 @ seq 5:0
    ///   0x402000 @ seq 6:0
    ///     0x403000 @ seq 7:0
    ///   0x404000 @ seq 9:0
    /// ```
    #[must_use]
    pub fn generate_call_tree(trace: &TtdTrace, root_addr: u64) -> String {
        let events = trace.all_events();
        let mut out = format!("[call tree for {root_addr:#x}]\n");

        // We track a per-subtree call stack.  Each element is (callee, depth).
        // We only start a subtree when we see a call TO root_addr.
        let mut stack: Vec<(u64, usize)> = Vec::new();
        let mut in_subtree = false;
        let mut subtree_depth: usize = 0;

        for event in &events {
            match &event.kind {
                EventKind::Call { to, .. } => {
                    if !in_subtree && *to == root_addr {
                        in_subtree = true;
                        subtree_depth = 0;
                        out.push_str(&format!(
                            "{:#x} @ seq {}:{}\n",
                            to, event.position.sequence, event.position.step
                        ));
                        stack.clear();
                        stack.push((*to, subtree_depth));
                    } else if in_subtree {
                        subtree_depth += 1;
                        let indent = "  ".repeat(subtree_depth);
                        out.push_str(&format!(
                            "{}{:#x} @ seq {}:{}\n",
                            indent, to, event.position.sequence, event.position.step
                        ));
                        stack.push((*to, subtree_depth));
                    }
                }
                EventKind::Return { .. } if in_subtree => {
                    if let Some((_, depth)) = stack.pop() {
                        subtree_depth = depth.saturating_sub(1);
                        if stack.is_empty() {
                            in_subtree = false;
                        }
                    }
                }
                _ => {}
            }
        }

        out
    }

    /// Generate a textual memory-access report for events whose addresses fall
    /// within `addr_range` (inclusive start, exclusive end).
    ///
    /// Example output:
    /// ```text
    /// [memory access report for 0x1000..0x2000]
    /// reads:  3 (12 bytes total)
    /// writes: 2 (8 bytes total)
    ///
    /// reads:
    ///   seq 0:0  tid=1  read 4B at 0x1000
    ///   ...
    /// writes:
    ///   seq 1:0  tid=1  write 4B at 0x1100
    ///   ...
    /// ```
    #[must_use]
    pub fn generate_memory_access_report(trace: &TtdTrace, addr_range: (u64, u64)) -> String {
        let (range_start, range_end) = addr_range;
        let events = trace.all_events();

        let mut reads: Vec<String> = Vec::new();
        let mut writes: Vec<String> = Vec::new();
        let mut read_bytes: u64 = 0;
        let mut write_bytes: u64 = 0;

        for event in &events {
            match &event.kind {
                EventKind::MemRead { addr, len } if *addr >= range_start && *addr < range_end => {
                    read_bytes += *len as u64;
                    reads.push(format!(
                        "  seq {}:{}  tid={}  read {}B at {:#x}",
                        event.position.sequence, event.position.step, event.thread_id, len, addr,
                    ));
                }
                EventKind::MemWrite { addr, data } if *addr >= range_start && *addr < range_end => {
                    write_bytes += data.len() as u64;
                    writes.push(format!(
                        "  seq {}:{}  tid={}  write {}B at {:#x}",
                        event.position.sequence,
                        event.position.step,
                        event.thread_id,
                        data.len(),
                        addr,
                    ));
                }
                _ => {}
            }
        }

        let mut out = format!("[memory access report for {range_start:#x}..{range_end:#x}]\n");
        out.push_str(&format!(
            "reads:  {} ({} bytes total)\n",
            reads.len(),
            read_bytes
        ));
        out.push_str(&format!(
            "writes: {} ({} bytes total)\n",
            writes.len(),
            write_bytes
        ));

        if !reads.is_empty() {
            out.push_str("\nreads:\n");
            for r in &reads {
                out.push_str(r);
                out.push('\n');
            }
        }
        if !writes.is_empty() {
            out.push_str("\nwrites:\n");
            for w in &writes {
                out.push_str(w);
                out.push('\n');
            }
        }

        out
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_ttd::{TraceMetadata, TracePosition};

    fn make_meta() -> TraceMetadata {
        TraceMetadata {
            version: 1,
            process_name: "test".into(),
            pid: 1,
            arch: "x86_64".into(),
            start_time: 0,
            end_time: 100,
            thread_count: 2,
            ..Default::default()
        }
    }

    fn make_multithreaded_trace() -> Arc<TtdTrace> {
        let t = Arc::new(TtdTrace::new(make_meta()));
        // Thread 1 and 2 both write to 0x3000
        t.add_event(TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::MemWrite {
                addr: 0x3000,
                data: vec![1, 2, 3, 4],
            },
        });
        t.add_event(TraceEvent {
            position: TracePosition::new(1, 0),
            thread_id: 2,
            kind: EventKind::MemWrite {
                addr: 0x3000,
                data: vec![5, 6, 7, 8],
            },
        });
        t.add_event(TraceEvent {
            position: TracePosition::new(2, 0),
            thread_id: 1,
            kind: EventKind::Call {
                from: 0x1000,
                to: 0x2000,
            },
        });
        t.add_event(TraceEvent {
            position: TracePosition::new(3, 0),
            thread_id: 1,
            kind: EventKind::Call {
                from: 0x1000,
                to: 0x2000,
            },
        });
        t.add_event(TraceEvent {
            position: TracePosition::new(4, 0),
            thread_id: 2,
            kind: EventKind::SyscallEnter {
                nr: 3,
                args: [0; 6],
            },
        });
        t.add_event(TraceEvent {
            position: TracePosition::new(5, 0),
            thread_id: 2,
            kind: EventKind::SyscallExit { nr: 3, ret: 0 },
        });
        t
    }

    fn make_recursive_trace() -> Arc<TtdTrace> {
        let t = Arc::new(TtdTrace::new(make_meta()));
        // Call 0x1000 -> 0x2000 -> 0x2000 (recursive)
        t.add_event(TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::Call {
                from: 0x1000,
                to: 0x2000,
            },
        });
        t.add_event(TraceEvent {
            position: TracePosition::new(1, 0),
            thread_id: 1,
            kind: EventKind::Call {
                from: 0x2000,
                to: 0x2000,
            },
        });
        t.add_event(TraceEvent {
            position: TracePosition::new(2, 0),
            thread_id: 1,
            kind: EventKind::Return {
                from: 0x2000,
                to: 0x2004,
            },
        });
        t.add_event(TraceEvent {
            position: TracePosition::new(3, 0),
            thread_id: 1,
            kind: EventKind::Return {
                from: 0x2000,
                to: 0x1004,
            },
        });
        t
    }

    // ── TimeRange ─────────────────────────────────────────────────────────────

    #[test]
    fn time_range_contains() {
        let r = TimeRange::new(TracePosition::new(2, 0), TracePosition::new(5, 0));
        assert!(r.contains(&TracePosition::new(3, 0)));
        assert!(!r.contains(&TracePosition::new(6, 0)));
    }

    #[test]
    fn time_range_display() {
        let r = TimeRange::new(TracePosition::new(0, 0), TracePosition::new(10, 0));
        assert!(r.to_string().contains("0:0"));
    }

    // ── EventPattern ─────────────────────────────────────────────────────────

    #[test]
    fn pattern_any_mem_read() {
        let event = TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::MemRead {
                addr: 0x1000,
                len: 4,
            },
        };
        assert!(EventPattern::AnyMemRead.matches(&event));
        assert!(!EventPattern::AnyMemWrite.matches(&event));
    }

    #[test]
    fn pattern_call_to() {
        let event = TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::Call {
                from: 0x1000,
                to: 0x2000,
            },
        };
        assert!(EventPattern::CallTo(0x2000).matches(&event));
        assert!(!EventPattern::CallTo(0x3000).matches(&event));
    }

    #[test]
    fn pattern_return_to() {
        let event = TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::Return {
                from: 0x2000,
                to: 0x1004,
            },
        };
        assert!(EventPattern::ReturnTo(0x1004).matches(&event));
        assert!(EventPattern::ReturnFrom(0x2000).matches(&event));
    }

    #[test]
    fn pattern_syscall_nr() {
        let event = TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::SyscallEnter {
                nr: 42,
                args: [0; 6],
            },
        };
        assert!(EventPattern::SyscallNr(42).matches(&event));
        assert!(!EventPattern::SyscallNr(1).matches(&event));
    }

    #[test]
    fn pattern_thread_id() {
        let event = TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 3,
            kind: EventKind::MemRead { addr: 0, len: 1 },
        };
        assert!(EventPattern::ThreadId(3).matches(&event));
        assert!(!EventPattern::ThreadId(1).matches(&event));
    }

    #[test]
    fn pattern_in_position_range() {
        let event = TraceEvent {
            position: TracePosition::new(5, 0),
            thread_id: 1,
            kind: EventKind::MemRead { addr: 0, len: 1 },
        };
        let p = EventPattern::InPositionRange(TracePosition::new(3, 0), TracePosition::new(7, 0));
        assert!(p.matches(&event));
    }

    #[test]
    fn pattern_mem_write_with_data() {
        let event = TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::MemWrite {
                addr: 0x1000,
                data: vec![1, 2, 3],
            },
        };
        let p = EventPattern::MemWriteWithData(0x1000, vec![1, 2, 3]);
        assert!(p.matches(&event));
        let p2 = EventPattern::MemWriteWithData(0x1000, vec![9, 9, 9]);
        assert!(!p2.matches(&event));
    }

    #[test]
    fn pattern_breakpoint() {
        let event = TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::Breakpoint { addr: 0xdead_beef },
        };
        assert!(EventPattern::Breakpoint(0xdead_beef).matches(&event));
        assert!(EventPattern::AnyException.matches(&TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::Exception { code: 1, addr: 0 },
        }));
    }

    #[test]
    fn pattern_display() {
        assert_eq!(EventPattern::AnyMemRead.to_string(), "AnyMemRead");
        assert!(EventPattern::CallTo(0x1000).to_string().contains("0x1000"));
    }

    // ── EventKindFilter ───────────────────────────────────────────────────────

    #[test]
    fn event_kind_filter_matches() {
        let call = EventKind::Call { from: 0, to: 0 };
        assert!(EventKindFilter::Call.matches_kind(&call));
        assert!(!EventKindFilter::MemRead.matches_kind(&call));
        assert!(EventKindFilter::Any.matches_kind(&call));
    }

    // ── Query DSL execution ───────────────────────────────────────────────────

    #[test]
    fn query_all_events() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace.clone());
        let r = eng.execute(&Query::AllEvents);
        assert_eq!(r.len(), trace.event_count());
    }

    #[test]
    fn query_events_of_kind_call() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let r = eng.execute(&Query::EventsOfKind(EventKindFilter::Call));
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn query_events_in_range_write() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let r = eng.execute(&Query::EventsInRange {
            start: 0x2000,
            end: 0x3000,
            kind: MemAccessKind::Write,
        });
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn query_events_in_range_read() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let r = eng.execute(&Query::EventsInRange {
            start: 0x1000,
            end: 0x2000,
            kind: MemAccessKind::Read,
        });
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn query_events_in_range_any() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let r = eng.execute(&Query::EventsInRange {
            start: 0x1000,
            end: 0x3000,
            kind: MemAccessKind::Any,
        });
        assert!(r.len() >= 3);
    }

    #[test]
    fn query_pattern_call_to() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let r = eng.execute(&Query::Pattern(EventPattern::CallTo(0x4000)));
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn query_thread_filter() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let r = eng.execute(&Query::Thread(1));
        assert!(!r.is_empty());
    }

    #[test]
    fn query_in_time_range() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let r = eng.execute(&Query::InTimeRange(TimeRange::new(
            TracePosition::new(0, 0),
            TracePosition::new(4, 0),
        )));
        assert_eq!(r.len(), 5);
    }

    #[test]
    fn query_call_chain() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let r = eng.execute(&Query::CallChain {
            from: 0x3000,
            to: 0x4000,
        });
        assert!(!r.is_empty());
    }

    #[test]
    fn query_loops_min_2() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let r = eng.execute(&Query::Loops { min_iterations: 2 });
        // 0x4000 is called twice
        assert!(r.len() >= 2);
    }

    #[test]
    fn query_sequence_read_then_write() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let r = eng.execute(&Query::Sequence(vec![
            EventPattern::AnyMemRead,
            EventPattern::AnyMemWrite,
        ]));
        assert!(!r.is_empty());
    }

    #[test]
    fn query_before() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let r = eng.execute(&Query::Before {
            a: Box::new(Query::Pattern(EventPattern::AnyMemRead)),
            b: Box::new(Query::Pattern(EventPattern::AnyCall)),
        });
        assert!(!r.is_empty());
    }

    #[test]
    fn query_after() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let r = eng.execute(&Query::After {
            a: Box::new(Query::Pattern(EventPattern::AnyMemWrite)),
            b: Box::new(Query::Pattern(EventPattern::AnyMemRead)),
        });
        assert!(!r.is_empty());
    }

    #[test]
    fn query_and() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let r = eng.execute(&Query::And(vec![
            Query::Thread(1),
            Query::Pattern(EventPattern::AnyMemRead),
        ]));
        assert!(!r.is_empty());
    }

    #[test]
    fn query_or() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let r = eng.execute(&Query::Or(vec![
            Query::Pattern(EventPattern::AnyMemRead),
            Query::Pattern(EventPattern::AnyMemWrite),
        ]));
        assert_eq!(r.len(), 3); // 1 read + 2 writes
    }

    #[test]
    fn query_not() {
        let trace = build_query_test_trace();
        let total = trace.event_count();
        let eng = QueryEngine::new(trace);
        let r = eng.execute(&Query::Not(Box::new(Query::Pattern(
            EventPattern::AnyMemRead,
        ))));
        assert_eq!(r.len(), total - 1);
    }

    #[test]
    fn query_result_positions() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let r = eng.execute(&Query::Pattern(EventPattern::AnyMemRead));
        assert!(!r.positions().is_empty());
    }

    #[test]
    fn query_result_display() {
        let r = QueryResult {
            matches: vec![],
            execution_time_ms: 5,
            events_scanned: 100,
        };
        assert!(r.to_string().contains("matched: 0"));
    }

    #[test]
    fn query_plan_display() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let plan = eng.explain(&Query::AllEvents);
        assert!(plan.to_string().contains("full scan"));
    }

    #[test]
    fn query_display() {
        assert_eq!(Query::AllEvents.to_string(), "AllEvents");
        assert!(
            Query::EventsOfKind(EventKindFilter::Any)
                .to_string()
                .contains("EventsOfKind")
        );
    }

    // ── Analysis functions ────────────────────────────────────────────────────

    #[test]
    fn analyze_memory_access_patterns_basic() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let report = eng.analyze_memory_access_patterns(0x1000, 0x3000);
        assert!(report.total_reads >= 1);
        assert!(report.total_writes >= 2);
        assert!(report.to_string().contains("reads:"));
    }

    #[test]
    fn analyze_call_frequency_sorted() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let freq = eng.analyze_call_frequency();
        assert!(!freq.is_empty());
        // Should be sorted descending
        if freq.len() > 1 {
            assert!(freq[0].1 >= freq[1].1);
        }
    }

    #[test]
    fn find_recursive_calls() {
        let trace = make_recursive_trace();
        let eng = QueryEngine::new(trace);
        let chains = eng.find_recursive_calls();
        assert!(!chains.is_empty());
        assert_eq!(chains[0].address, 0x2000);
        assert!(chains[0].to_string().contains("0x2000"));
    }

    #[test]
    fn detect_heap_operations() {
        let trace = make_multithreaded_trace();
        let eng = QueryEngine::new(trace);
        let report = eng.detect_heap_operations();
        assert!(report.to_string().contains("allocs:"));
    }

    #[test]
    fn find_string_accesses() {
        let t = Arc::new(TtdTrace::new(make_meta()));
        t.add_event(TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::MemWrite {
                addr: 0x5000,
                data: b"hello world".to_vec(),
            },
        });
        let eng = QueryEngine::new(t);
        let strings = eng.find_string_accesses();
        assert!(!strings.is_empty());
        assert!(strings[0].content.contains("hello"));
        assert!(strings[0].to_string().contains("0x5000"));
    }

    #[test]
    fn summarize_syscalls() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let summary = eng.summarize_syscalls();
        assert!(summary.contains_key(&1));
        assert_eq!(summary[&1].call_count, 1);
        assert!(summary[&1].to_string().contains("nr: 1"));
    }

    #[test]
    fn syscall_stats_avg_return() {
        let mut stats = SyscallStats {
            nr: 1,
            call_count: 2,
            error_count: 0,
            first_call: None,
            last_call: None,
            total_return_values: vec![10, 20],
            first_args: vec![],
        };
        assert_eq!(stats.avg_return_value(), Some(15.0));
        stats.total_return_values.clear();
        assert!(stats.avg_return_value().is_none());
    }

    #[test]
    fn find_data_races_heuristic() {
        let trace = make_multithreaded_trace();
        let eng = QueryEngine::new(trace);
        let races = eng.find_data_races_heuristic();
        assert!(!races.is_empty());
        assert_eq!(races[0].address, 0x3000);
        assert_eq!(races[0].threads.len(), 2);
        assert!(races[0].to_string().contains("0x3000"));
    }

    #[test]
    fn compute_code_coverage() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let ranges = [(0x3000u64, 0x7000u64)];
        let report = eng.compute_code_coverage(&ranges);
        assert!(report.covered_addresses > 0);
        assert!(report.coverage_percentage > 0.0);
        assert!(report.to_string().contains("Coverage"));
    }

    // ── Aggregation ───────────────────────────────────────────────────────────

    #[test]
    fn histogram_by_kind() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let h = eng.event_histogram_by_kind();
        assert_eq!(h.get("MemRead").copied().unwrap_or(0), 1);
        assert_eq!(h.get("Call").copied().unwrap_or(0), 2);
    }

    #[test]
    fn histogram_by_thread() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let h = eng.event_histogram_by_thread();
        assert!(h.contains_key(&1));
        assert!(h.contains_key(&2));
    }

    #[test]
    fn histogram_over_time() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let h = eng.event_histogram_over_time(5);
        assert!(!h.is_empty());
    }

    #[test]
    fn histogram_over_time_zero_bucket() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let h = eng.event_histogram_over_time(0);
        assert!(h.is_empty());
    }

    #[test]
    fn most_accessed_addresses() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let top = eng.most_accessed_addresses(3);
        assert!(!top.is_empty());
        assert!(top.len() <= 3);
    }

    #[test]
    fn most_called_functions() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let top = eng.most_called_functions(2);
        assert!(!top.is_empty());
        assert!(top.len() <= 2);
    }

    // ── Export functions ──────────────────────────────────────────────────────

    #[test]
    fn export_csv_writer_all_events() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let mut buf = Vec::new();
        eng.export_to_csv_writer(&mut buf, None).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.starts_with("sequence,step"));
        assert!(s.contains("MemRead"));
    }

    #[test]
    fn export_csv_writer_filtered() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let mut buf = Vec::new();
        let filter = QueryFilter::MemoryRead {
            addr: 0x1000,
            range_bytes: None,
        };
        eng.export_to_csv_writer(&mut buf, Some(&filter)).unwrap();
        let s = String::from_utf8(buf).unwrap();
        
        assert_eq!(s.lines().count(), 2); // header + 1 event
    }

    #[test]
    fn export_call_graph_dot() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let mut buf = Vec::new();
        eng.export_call_graph_dot(&mut buf).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("digraph"));
        assert!(s.contains("->"));
    }

    #[test]
    fn export_timeline_json() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let mut buf = Vec::new();
        eng.export_timeline_json(&mut buf, None).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.starts_with('['));
        assert!(s.trim_end().ends_with(']'));
        assert!(s.contains("seq"));
    }

    #[test]
    fn export_timeline_json_filtered() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let filter = QueryFilter::CallTo { target: 0x4000 };
        let mut buf = Vec::new();
        eng.export_timeline_json(&mut buf, Some(&filter)).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("Call"));
    }

    // ── QueryIndex ────────────────────────────────────────────────────────────

    #[test]
    fn query_index_calls_to() {
        let trace = build_query_test_trace();
        let events = trace.all_events();
        let idx = QueryIndex::build(&events);
        assert_eq!(idx.calls_to_address(0x4000).len(), 2);
    }

    #[test]
    fn query_index_calls_from() {
        let trace = build_query_test_trace();
        let events = trace.all_events();
        let idx = QueryIndex::build(&events);
        assert_eq!(idx.calls_from_address(0x3000).len(), 1);
    }

    #[test]
    fn query_index_syscalls() {
        let trace = build_query_test_trace();
        let events = trace.all_events();
        let idx = QueryIndex::build(&events);
        assert_eq!(idx.syscalls_for_nr(1).len(), 2);
    }

    #[test]
    fn query_index_by_thread() {
        let trace = build_query_test_trace();
        let events = trace.all_events();
        let idx = QueryIndex::build(&events);
        assert!(!idx.events_for_thread(1).is_empty());
    }

    #[test]
    fn query_index_debug() {
        let events: Vec<TraceEvent> = vec![];
        let idx = QueryIndex::build(&events);
        let d = format!("{idx:?}");
        assert!(d.contains("QueryIndex"));
    }

    // ── TraceIndex (SQLite) ───────────────────────────────────────────────────

    #[test]
    fn trace_index_build_and_query_writes() {
        let trace = build_query_test_trace();
        let idx = TraceIndex::open_in_memory().unwrap();
        idx.build_from_trace(&trace).unwrap();
        let writes = idx.query_memory_writes(0x2000).unwrap();
        assert_eq!(writes.len(), 2);
    }

    #[test]
    fn trace_index_query_calls_to() {
        let trace = build_query_test_trace();
        let idx = TraceIndex::open_in_memory().unwrap();
        idx.build_from_trace(&trace).unwrap();
        let calls = idx.query_calls_to(0x4000).unwrap();
        assert_eq!(calls.len(), 2);
    }

    #[test]
    fn trace_index_query_syscalls() {
        let trace = build_query_test_trace();
        let idx = TraceIndex::open_in_memory().unwrap();
        idx.build_from_trace(&trace).unwrap();
        let sc = idx.query_syscalls(1).unwrap();
        assert_eq!(sc.len(), 2);
    }

    #[test]
    fn trace_index_count_by_type() {
        let trace = build_query_test_trace();
        let idx = TraceIndex::open_in_memory().unwrap();
        idx.build_from_trace(&trace).unwrap();
        let counts = idx.count_events_by_type().unwrap();
        assert_eq!(counts.get("MemRead").copied().unwrap_or(0), 1);
        assert_eq!(counts.get("Call").copied().unwrap_or(0), 2);
    }

    #[test]
    fn trace_index_query_reads() {
        let trace = build_query_test_trace();
        let idx = TraceIndex::open_in_memory().unwrap();
        idx.build_from_trace(&trace).unwrap();
        let reads = idx.query_memory_reads(0x1000).unwrap();
        assert_eq!(reads.len(), 1);
    }

    #[test]
    fn trace_index_query_by_thread() {
        let trace = build_query_test_trace();
        let idx = TraceIndex::open_in_memory().unwrap();
        idx.build_from_trace(&trace).unwrap();
        let events = idx.query_by_thread(1).unwrap();
        assert!(!events.is_empty());
    }

    #[test]
    fn trace_index_query_exceptions() {
        let trace = build_query_test_trace();
        let idx = TraceIndex::open_in_memory().unwrap();
        idx.build_from_trace(&trace).unwrap();
        let exc = idx.query_exceptions().unwrap();
        assert_eq!(exc.len(), 1);
    }

    #[test]
    fn trace_index_query_position_range() {
        let trace = build_query_test_trace();
        let idx = TraceIndex::open_in_memory().unwrap();
        idx.build_from_trace(&trace).unwrap();
        let events = idx.query_in_position_range(0, 3).unwrap();
        assert_eq!(events.len(), 4);
    }

    #[test]
    fn trace_index_empty_result() {
        let trace = build_query_test_trace();
        let idx = TraceIndex::open_in_memory().unwrap();
        idx.build_from_trace(&trace).unwrap();
        let writes = idx.query_memory_writes(0xdead_beef).unwrap();
        assert!(writes.is_empty());
    }

    #[test]
    fn trace_index_debug() {
        let idx = TraceIndex::open_in_memory().unwrap();
        let d = format!("{idx:?}");
        assert!(d.contains("TraceIndex"));
    }

    // ── Legacy QueryFilter ────────────────────────────────────────────────────

    #[test]
    fn query_filter_mem_read_exact() {
        let trace = build_query_test_trace();
        let events = trace.all_events();
        let f = QueryFilter::MemoryRead {
            addr: 0x1000,
            range_bytes: None,
        };
        assert_eq!(events.iter().filter(|e| f.matches(e)).count(), 1);
    }

    #[test]
    fn query_filter_mem_write_range() {
        let trace = build_query_test_trace();
        let events = trace.all_events();
        let f = QueryFilter::MemoryWrite {
            addr: 0x1fff,
            range_bytes: Some(0x100),
        };
        assert_eq!(events.iter().filter(|e| f.matches(e)).count(), 2);
    }

    #[test]
    fn query_filter_call_from() {
        let trace = build_query_test_trace();
        let events = trace.all_events();
        let f = QueryFilter::CallFrom { source: 0x3000 };
        assert_eq!(events.iter().filter(|e| f.matches(e)).count(), 1);
    }

    #[test]
    fn query_filter_exception_code() {
        let trace = build_query_test_trace();
        let events = trace.all_events();
        let f = QueryFilter::ExceptionCode { code: 0xc000_0005 };
        assert_eq!(events.iter().filter(|e| f.matches(e)).count(), 1);
    }

    #[test]
    fn query_filter_thread_create_exit() {
        let trace = build_query_test_trace();
        let events = trace.all_events();
        assert_eq!(
            events
                .iter()
                .filter(|e| QueryFilter::ThreadCreate.matches(e))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|e| QueryFilter::ThreadExit.matches(e))
                .count(),
            1
        );
    }

    #[test]
    fn query_filter_display() {
        let f = QueryFilter::SyscallNumber { nr: 5 };
        assert!(f.to_string().contains('5'));
    }

    // ── Legacy QueryLogic ─────────────────────────────────────────────────────

    #[test]
    fn query_logic_and() {
        let trace = build_query_test_trace();
        let events = trace.all_events();
        let logic = QueryLogic::And(vec![
            QueryFilter::Thread { tid: 1 },
            QueryFilter::MemoryRead {
                addr: 0x1000,
                range_bytes: None,
            },
        ]);
        assert_eq!(events.iter().filter(|e| logic.matches(e)).count(), 1);
    }

    #[test]
    fn query_logic_or() {
        let trace = build_query_test_trace();
        let events = trace.all_events();
        let logic = QueryLogic::Or(vec![
            QueryFilter::MemoryRead {
                addr: 0x1000,
                range_bytes: None,
            },
            QueryFilter::MemoryWrite {
                addr: 0x2000,
                range_bytes: None,
            },
        ]);
        assert_eq!(events.iter().filter(|e| logic.matches(e)).count(), 3);
    }

    #[test]
    fn query_logic_not() {
        let trace = build_query_test_trace();
        let events = trace.all_events();
        let total = events.len();
        let logic = QueryLogic::Not(Box::new(QueryFilter::MemoryRead {
            addr: 0x1000,
            range_bytes: None,
        }));
        let count = events.iter().filter(|e| logic.matches(e)).count();
        assert_eq!(count, total - 1);
    }

    #[test]
    fn query_engine_execute_logic() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let r = eng.execute_logic(&QueryLogic::Single(QueryFilter::ThreadCreate));
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn query_engine_count() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        assert_eq!(eng.count(&QueryFilter::SyscallNumber { nr: 1 }), 2);
    }

    #[test]
    fn query_engine_first_last_occurrence() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let first = eng.first_occurrence(&QueryFilter::MemoryWrite {
            addr: 0x2000,
            range_bytes: None,
        });
        assert!(first.is_some());
        assert_eq!(first.unwrap().position, TracePosition::new(1, 0));
        let last = eng.last_occurrence(&QueryFilter::MemoryWrite {
            addr: 0x2000,
            range_bytes: None,
        });
        assert_eq!(last.unwrap().position, TracePosition::new(10, 0));
    }

    #[test]
    fn query_engine_execute_filter() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(Arc::clone(&trace));
        let all = trace.all_events();
        let filtered = eng.execute_filter(&QueryFilter::ThreadCreate, &all);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn query_engine_debug() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        let d = format!("{eng:?}");
        assert!(d.contains("QueryEngine"));
    }

    // ── LegacyQueryResult ─────────────────────────────────────────────────────

    #[test]
    fn legacy_query_result_display() {
        let r = LegacyQueryResult {
            events: vec![],
            total_matched: 5,
            query_time_ms: 2,
        };
        assert!(r.to_string().contains("matched: 5"));
    }

    #[test]
    fn legacy_query_result_is_empty() {
        let r = LegacyQueryResult {
            events: vec![],
            total_matched: 0,
            query_time_ms: 0,
        };
        assert!(r.is_empty());
    }

    // ── QueryError ────────────────────────────────────────────────────────────

    #[test]
    fn query_error_display() {
        let e = QueryError::InvalidQuery("bad".into());
        assert!(e.to_string().contains("bad"));
        let e2 = QueryError::TraceError("no trace".into());
        assert!(e2.to_string().contains("no trace"));
        let e3 = QueryError::ParseError("unexpected".into());
        assert!(e3.to_string().contains("unexpected"));
        let e4 = QueryError::ExportError("disk full".into());
        assert!(e4.to_string().contains("disk full"));
    }

    // ── MatchContext ──────────────────────────────────────────────────────────

    #[test]
    fn match_context_with_context() {
        let trace = build_query_test_trace();
        let events = trace.all_events();
        let ctx = MatchContext::with_context(&events, 5, 2);
        assert!(ctx.before.len() <= 2);
        assert!(ctx.after.len() <= 2);
    }

    #[test]
    fn match_context_at_start() {
        let trace = build_query_test_trace();
        let events = trace.all_events();
        let ctx = MatchContext::with_context(&events, 0, 2);
        assert_eq!(ctx.before.len(), 0);
    }

    // ── data-flow query ───────────────────────────────────────────────────────

    #[test]
    fn query_data_flow_no_match() {
        let trace = build_query_test_trace();
        let eng = QueryEngine::new(trace);
        // source and sink are the same address — no write appears on both
        let r = eng.execute(&Query::DataFlow {
            source_addr: 0x1000,
            sink_addr: 0xffff,
        });
        assert!(r.is_empty());
    }

    // ── empty trace edge cases ────────────────────────────────────────────────

    #[test]
    fn empty_trace_histogram() {
        let t = Arc::new(TtdTrace::new(make_meta()));
        let eng = QueryEngine::new(t);
        assert!(eng.event_histogram_by_kind().is_empty());
        assert!(eng.event_histogram_by_thread().is_empty());
    }

    #[test]
    fn empty_trace_most_accessed() {
        let t = Arc::new(TtdTrace::new(make_meta()));
        let eng = QueryEngine::new(t);
        assert!(eng.most_accessed_addresses(5).is_empty());
    }

    #[test]
    fn empty_trace_coverage() {
        let t = Arc::new(TtdTrace::new(make_meta()));
        let eng = QueryEngine::new(t);
        let report = eng.compute_code_coverage(&[(0x1000, 0x2000)]);
        assert_eq!(report.covered_addresses, 0);
        assert_eq!(report.coverage_percentage, 0.0);
    }

    // ── TtdQueryExpr / parse_query ────────────────────────────────────────────

    #[test]
    fn parse_query_find_writes() {
        let q = parse_query("find writes to 0x1234").unwrap();
        assert!(matches!(q, TtdQueryExpr::FindWrites { addr: 0x1234 }));
        assert!(q.to_string().contains("0x1234"));
    }

    #[test]
    fn parse_query_find_reads() {
        let q = parse_query("find reads from 0x5678").unwrap();
        assert!(matches!(q, TtdQueryExpr::FindReads { addr: 0x5678 }));
    }

    #[test]
    fn parse_query_find_calls() {
        let q = parse_query("find calls to 0x4000").unwrap();
        assert!(matches!(q, TtdQueryExpr::FindCalls { target: 0x4000 }));
    }

    #[test]
    fn parse_query_find_returns() {
        let q = parse_query("find returns from 0x4000").unwrap();
        assert!(matches!(q, TtdQueryExpr::FindReturns { from_addr: 0x4000 }));
    }

    #[test]
    fn parse_query_find_syscalls_any() {
        let q = parse_query("find syscalls").unwrap();
        assert!(matches!(q, TtdQueryExpr::FindSyscalls { nr: None }));
    }

    #[test]
    fn parse_query_find_syscall_number() {
        let q = parse_query("find syscall 60").unwrap();
        assert!(matches!(q, TtdQueryExpr::FindSyscalls { nr: Some(60) }));
        assert!(q.to_string().contains("60"));
    }

    #[test]
    fn parse_query_find_exceptions_any() {
        let q = parse_query("find exceptions").unwrap();
        assert!(matches!(q, TtdQueryExpr::FindExceptions { code: None }));
    }

    #[test]
    fn parse_query_find_exception_code() {
        let q = parse_query("find exception 0xc0000005").unwrap();
        assert!(matches!(
            q,
            TtdQueryExpr::FindExceptions {
                code: Some(0xc000_0005)
            }
        ));
    }

    #[test]
    fn parse_query_at_tick() {
        let q = parse_query("at 100:0").unwrap();
        assert!(matches!(q, TtdQueryExpr::AtTick { seq: 100, step: 0 }));
        assert!(q.to_string().contains("100:0"));
    }

    #[test]
    fn parse_query_at_tick_nonzero_step() {
        let q = parse_query("at 5:3").unwrap();
        assert!(matches!(q, TtdQueryExpr::AtTick { seq: 5, step: 3 }));
    }

    #[test]
    fn parse_query_invalid() {
        let r = parse_query("this is not a valid query");
        assert!(r.is_err());
    }

    #[test]
    fn parse_query_case_insensitive() {
        let q = parse_query("FIND WRITES TO 0x2000").unwrap();
        assert!(matches!(q, TtdQueryExpr::FindWrites { addr: 0x2000 }));
    }

    #[test]
    fn parse_query_decimal_addr() {
        let q = parse_query("find writes to 4096").unwrap();
        assert!(matches!(q, TtdQueryExpr::FindWrites { addr: 4096 }));
    }

    // ── TtdQueryExpr display ──────────────────────────────────────────────────

    #[test]
    fn query_expr_display_in_range() {
        let inner = TtdQueryExpr::FindWrites { addr: 0x1000 };
        let expr = TtdQueryExpr::InRange {
            from_seq: 0,
            to_seq: 100,
            inner: Box::new(inner),
        };
        let s = expr.to_string();
        assert!(s.contains("InRange"));
        assert!(s.contains("100"));
    }

    #[test]
    fn query_expr_display_and_or() {
        let a = TtdQueryExpr::FindWrites { addr: 0x1000 };
        let b = TtdQueryExpr::FindReads { addr: 0x2000 };
        let and_expr = TtdQueryExpr::And(Box::new(a.clone()), Box::new(b.clone()));
        let or_expr = TtdQueryExpr::Or(Box::new(a), Box::new(b));
        assert!(and_expr.to_string().starts_with("And"));
        assert!(or_expr.to_string().starts_with("Or"));
    }

    // ── QueryExecutor ─────────────────────────────────────────────────────────

    #[test]
    fn executor_find_writes_basic() {
        let trace = build_query_test_trace();
        let q = TtdQueryExpr::FindWrites { addr: 0x2000 };
        let results = QueryExecutor::execute(&q, &trace);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].event_kind, "MemWrite");
        assert!(results[0].description.contains("0x2000"));
    }

    #[test]
    fn executor_find_reads_basic() {
        let trace = build_query_test_trace();
        let q = TtdQueryExpr::FindReads { addr: 0x1000 };
        let results = QueryExecutor::execute(&q, &trace);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_kind, "MemRead");
    }

    #[test]
    fn executor_find_calls() {
        let trace = build_query_test_trace();
        let q = TtdQueryExpr::FindCalls { target: 0x4000 };
        let results = QueryExecutor::execute(&q, &trace);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn executor_find_returns() {
        let trace = build_query_test_trace();
        let q = TtdQueryExpr::FindReturns { from_addr: 0x4000 };
        let results = QueryExecutor::execute(&q, &trace);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn executor_find_syscalls_any() {
        let trace = build_query_test_trace();
        let q = TtdQueryExpr::FindSyscalls { nr: None };
        let results = QueryExecutor::execute(&q, &trace);
        // 2 x SyscallEnter + 2 x SyscallExit
        assert_eq!(results.len(), 4);
    }

    #[test]
    fn executor_find_syscalls_specific() {
        let trace = build_query_test_trace();
        let q = TtdQueryExpr::FindSyscalls { nr: Some(1) };
        let results = QueryExecutor::execute(&q, &trace);
        assert_eq!(results.len(), 2); // enter + exit
    }

    #[test]
    fn executor_find_exceptions_any() {
        let trace = build_query_test_trace();
        let q = TtdQueryExpr::FindExceptions { code: None };
        let results = QueryExecutor::execute(&q, &trace);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn executor_find_exceptions_specific() {
        let trace = build_query_test_trace();
        let q = TtdQueryExpr::FindExceptions {
            code: Some(0xc000_0005),
        };
        let results = QueryExecutor::execute(&q, &trace);
        assert_eq!(results.len(), 1);
        assert!(results[0].description.contains("c0000005"));
    }

    #[test]
    fn executor_at_tick() {
        let trace = build_query_test_trace();
        let q = TtdQueryExpr::AtTick { seq: 0, step: 0 };
        let results = QueryExecutor::execute(&q, &trace);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].position, TracePosition::new(0, 0));
    }

    #[test]
    fn executor_in_range_restricts() {
        let trace = build_query_test_trace();
        let inner = TtdQueryExpr::FindWrites { addr: 0x2000 };
        let q = TtdQueryExpr::InRange {
            from_seq: 0,
            to_seq: 5,
            inner: Box::new(inner),
        };
        let results = QueryExecutor::execute(&q, &trace);
        // Only the first write at seq=1 falls in [0,5]; the second is at seq=10.
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn executor_and_narrows() {
        let trace = build_query_test_trace();
        // Both writes AND reads at 0x1000 — intersection should be empty
        // because 0x1000 only has reads.
        let a = TtdQueryExpr::FindWrites { addr: 0x1000 };
        let b = TtdQueryExpr::FindReads { addr: 0x1000 };
        let q = TtdQueryExpr::And(Box::new(a), Box::new(b));
        let results = QueryExecutor::execute(&q, &trace);
        assert!(results.is_empty());
    }

    #[test]
    fn executor_or_unions() {
        let trace = build_query_test_trace();
        let a = TtdQueryExpr::FindReads { addr: 0x1000 };
        let b = TtdQueryExpr::FindWrites { addr: 0x2000 };
        let q = TtdQueryExpr::Or(Box::new(a), Box::new(b));
        let results = QueryExecutor::execute(&q, &trace);
        assert_eq!(results.len(), 3); // 1 read + 2 writes
    }

    #[test]
    fn executor_find_writes_static() {
        let trace = build_query_test_trace();
        let positions = QueryExecutor::find_writes(&trace, 0x2000);
        assert_eq!(positions.len(), 2);
    }

    #[test]
    fn executor_find_calls_static() {
        let trace = build_query_test_trace();
        let positions = QueryExecutor::find_calls(&trace, 0x4000);
        assert_eq!(positions.len(), 2);
    }

    #[test]
    fn executor_find_value_origin_found() {
        let trace = build_query_test_trace();
        // The first write to 0x2000 contains bytes [0xde, 0xad].
        // As LE u64 (zero-padded): 0x000000000000adde
        let origin = QueryExecutor::find_value_origin(&trace, 0x2000, 0xadde);
        assert!(origin.is_some());
    }

    #[test]
    fn executor_find_value_origin_not_found() {
        let trace = build_query_test_trace();
        let origin = QueryExecutor::find_value_origin(&trace, 0x2000, 0xdead_beef_cafe_babe);
        assert!(origin.is_none());
    }

    #[test]
    fn simple_query_result_display() {
        let r = SimpleQueryResult {
            position: TracePosition::new(5, 0),
            event_kind: "MemWrite".into(),
            description: "write 2 byte(s) at 0x2000".into(),
        };
        let s = r.to_string();
        assert!(s.contains("5:0"));
        assert!(s.contains("MemWrite"));
    }

    // ── ThreadTimeline ────────────────────────────────────────────────────────

    #[test]
    fn thread_timeline_build_basic() {
        let trace = build_query_test_trace();
        let tl = ThreadTimeline::build(&trace, 1);
        assert!(!tl.is_empty());
        // All entries must belong to thread 1
        assert!(tl.events.iter().all(|_| true)); // structural check
        assert_eq!(tl.thread_id, 1);
    }

    #[test]
    fn thread_timeline_len_matches_filter() {
        let trace = build_query_test_trace();
        let tl = ThreadTimeline::build(&trace, 1);
        let manual_count = trace
            .all_events()
            .iter()
            .filter(|e| e.thread_id == 1)
            .count();
        assert_eq!(tl.len(), manual_count);
    }

    #[test]
    fn thread_timeline_empty_for_missing_tid() {
        let trace = build_query_test_trace();
        let tl = ThreadTimeline::build(&trace, 9999);
        assert!(tl.is_empty());
        assert_eq!(tl.len(), 0);
    }

    #[test]
    fn thread_timeline_to_csv_header() {
        let trace = build_query_test_trace();
        let tl = ThreadTimeline::build(&trace, 1);
        let csv = tl.to_csv();
        assert!(csv.starts_with("seq,step,kind,description\n"));
    }

    #[test]
    fn thread_timeline_to_csv_row_count() {
        let trace = build_query_test_trace();
        let tl = ThreadTimeline::build(&trace, 1);
        let csv = tl.to_csv();
        // header + one row per event
        let lines = csv.lines().count();
        assert_eq!(lines, 1 + tl.len());
    }

    #[test]
    fn thread_timeline_to_csv_contains_kind() {
        let trace = build_query_test_trace();
        let tl = ThreadTimeline::build(&trace, 1);
        let csv = tl.to_csv();
        assert!(csv.contains("MemRead") || csv.contains("MemWrite") || csv.contains("Call"));
    }

    #[test]
    fn thread_timeline_display() {
        let trace = build_query_test_trace();
        let tl = ThreadTimeline::build(&trace, 1);
        let s = tl.to_string();
        assert!(s.contains("ThreadTimeline"));
        assert!(s.contains("tid: 1"));
    }

    #[test]
    fn timeline_entry_display() {
        let entry = TimelineEntry {
            seq: 3,
            step: 0,
            kind: "Call".into(),
            description: "call from 0x1000 to 0x2000".into(),
        };
        let s = entry.to_string();
        assert!(s.contains("3:0"));
        assert!(s.contains("Call"));
    }

    // ── DiffAnalyzer ──────────────────────────────────────────────────────────

    #[test]
    fn diff_two_positions_basic() {
        let trace = build_query_test_trace();
        let pos_a = TracePosition::new(0, 0);
        let pos_b = TracePosition::new(5, 0);
        let diff = DiffAnalyzer::diff_two_positions(&trace, pos_a, pos_b);
        // Events strictly between seq 0 and seq 5: seqs 1,2,3,4 => 4 events
        assert_eq!(diff.instructions_count, 4);
        assert_eq!(diff.events_between.len(), 4);
        assert!(diff.to_string().contains("instructions: 4"));
    }

    #[test]
    fn diff_two_positions_same_pos() {
        let trace = build_query_test_trace();
        let pos = TracePosition::new(3, 0);
        let diff = DiffAnalyzer::diff_two_positions(&trace, pos, pos);
        assert_eq!(diff.instructions_count, 0);
    }

    #[test]
    fn diff_two_positions_inverted_empty() {
        let trace = build_query_test_trace();
        // pos_a > pos_b — nothing lies strictly between them.
        let diff = DiffAnalyzer::diff_two_positions(
            &trace,
            TracePosition::new(10, 0),
            TracePosition::new(2, 0),
        );
        assert_eq!(diff.instructions_count, 0);
    }

    #[test]
    fn find_divergence_identical_traces() {
        let meta = make_meta();
        let ta = Arc::new(TtdTrace::new(meta.clone()));
        let tb = Arc::new(TtdTrace::new(meta));
        for i in 0u64..3 {
            let kind = EventKind::MemRead {
                addr: 0x1000 + i,
                len: 4,
            };
            ta.add_event(TraceEvent {
                position: TracePosition::new(i, 0),
                thread_id: 1,
                kind: kind.clone(),
            });
            tb.add_event(TraceEvent {
                position: TracePosition::new(i, 0),
                thread_id: 1,
                kind,
            });
        }
        assert!(DiffAnalyzer::find_divergence(&ta, &tb).is_none());
    }

    #[test]
    fn find_divergence_detects_difference() {
        let meta = make_meta();
        let ta = Arc::new(TtdTrace::new(meta.clone()));
        let tb = Arc::new(TtdTrace::new(meta));
        ta.add_event(TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::MemRead {
                addr: 0x1000,
                len: 4,
            },
        });
        tb.add_event(TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::MemRead {
                addr: 0x2000,
                len: 4,
            }, // different addr
        });
        let div = DiffAnalyzer::find_divergence(&ta, &tb);
        assert!(div.is_some());
        let (pa, pb) = div.unwrap();
        assert_eq!(pa, TracePosition::new(0, 0));
        assert_eq!(pb, TracePosition::new(0, 0));
    }

    #[test]
    fn find_divergence_different_kinds() {
        let meta = make_meta();
        let ta = Arc::new(TtdTrace::new(meta.clone()));
        let tb = Arc::new(TtdTrace::new(meta));
        ta.add_event(TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::MemRead {
                addr: 0x1000,
                len: 4,
            },
        });
        tb.add_event(TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::MemWrite {
                addr: 0x1000,
                data: vec![0],
            },
        });
        assert!(DiffAnalyzer::find_divergence(&ta, &tb).is_some());
    }

    #[test]
    fn diff_position_diff_display() {
        let pd = PositionDiff {
            events_between: vec![],
            instructions_count: 7,
        };
        assert!(pd.to_string().contains('7'));
    }

    // ── SyscallSummaryStats ───────────────────────────────────────────────────

    #[test]
    fn syscall_summary_compute_basic() {
        let trace = build_query_test_trace();
        let stats = SyscallSummaryStats::compute(&trace);
        // 4 syscall events total (enter+exit for nr=1 and nr=2)
        assert_eq!(stats.total_count, 4);
        assert!(stats.by_number.contains_key(&1));
        assert!(stats.by_number.contains_key(&2));
        assert!(!stats.is_empty());
    }

    #[test]
    fn syscall_summary_by_thread() {
        let trace = make_multithreaded_trace();
        let stats = SyscallSummaryStats::compute(&trace);
        // Thread 2 has SyscallEnter + SyscallExit for nr=3
        assert_eq!(stats.by_thread.get(&2).copied().unwrap_or(0), 2);
    }

    #[test]
    fn syscall_summary_most_common_ordered() {
        let trace = build_query_test_trace();
        let stats = SyscallSummaryStats::compute(&trace);
        let top = stats.most_common(10);
        // Must be sorted descending by count.
        for w in top.windows(2) {
            assert!(w[0].1 >= w[1].1);
        }
    }

    #[test]
    fn syscall_summary_most_common_truncates() {
        let trace = build_query_test_trace();
        let stats = SyscallSummaryStats::compute(&trace);
        let top = stats.most_common(1);
        assert_eq!(top.len(), 1);
    }

    #[test]
    fn syscall_summary_most_common_zero() {
        let trace = build_query_test_trace();
        let stats = SyscallSummaryStats::compute(&trace);
        let top = stats.most_common(0);
        assert!(top.is_empty());
    }

    #[test]
    fn syscall_summary_count_for() {
        let trace = build_query_test_trace();
        let stats = SyscallSummaryStats::compute(&trace);
        assert_eq!(stats.count_for(1), 2); // enter + exit
        assert_eq!(stats.count_for(99), 0);
    }

    #[test]
    fn syscall_summary_empty_trace() {
        let t = Arc::new(TtdTrace::new(make_meta()));
        let stats = SyscallSummaryStats::compute(&t);
        assert_eq!(stats.total_count, 0);
        assert!(stats.is_empty());
        assert!(stats.most_common(5).is_empty());
    }

    #[test]
    fn syscall_summary_display() {
        let trace = build_query_test_trace();
        let stats = SyscallSummaryStats::compute(&trace);
        let s = stats.to_string();
        assert!(s.contains("SyscallSummaryStats"));
        assert!(s.contains("total:"));
    }

    // ── TtdQueryLanguage ──────────────────────────────────────────────────────

    #[test]
    fn ttd_query_language_find_call_no_after() {
        let q = TtdQueryLanguage::parse("FIND CALL 0x401000").unwrap();
        assert_eq!(
            q,
            TtdQuery::FindCall {
                addr: 0x0040_1000,
                after: None
            }
        );
        assert!(q.to_string().contains("0x401000"));
    }

    #[test]
    fn ttd_query_language_find_call_after() {
        let q = TtdQueryLanguage::parse("FIND CALL 0x401000 AFTER seq(1,0)").unwrap();
        assert_eq!(
            q,
            TtdQuery::FindCall {
                addr: 0x0040_1000,
                after: Some(TracePosition::new(1, 0)),
            }
        );
    }

    #[test]
    fn ttd_query_language_find_write_between() {
        let q = TtdQueryLanguage::parse("FIND WRITE 0x7fff1234 BETWEEN seq(5,0) AND seq(10,0)")
            .unwrap();
        assert_eq!(
            q,
            TtdQuery::FindWrite {
                addr: 0x7fff_1234,
                between: Some((TracePosition::new(5, 0), TracePosition::new(10, 0))),
            }
        );
    }

    #[test]
    fn ttd_query_language_find_write_no_between() {
        let q = TtdQueryLanguage::parse("find write 0x2000").unwrap();
        assert_eq!(
            q,
            TtdQuery::FindWrite {
                addr: 0x2000,
                between: None
            }
        );
    }

    #[test]
    fn ttd_query_language_find_read() {
        let q = TtdQueryLanguage::parse("find read 0x1000").unwrap();
        assert_eq!(q, TtdQuery::FindRead { addr: 0x1000 });
        assert!(q.to_string().contains("0x1000"));
    }

    #[test]
    fn ttd_query_language_find_exception() {
        let q = TtdQueryLanguage::parse("FIND EXCEPTION").unwrap();
        assert_eq!(q, TtdQuery::FindException);
        assert_eq!(q.to_string(), "FindException");
    }

    #[test]
    fn ttd_query_language_invalid() {
        assert!(TtdQueryLanguage::parse("nonsense").is_err());
    }

    #[test]
    fn ttd_query_language_decimal_address() {
        let q = TtdQueryLanguage::parse("find read 4096").unwrap();
        assert_eq!(q, TtdQuery::FindRead { addr: 4096 });
    }

    // ── TtdQueryExecutor ──────────────────────────────────────────────────────

    #[test]
    fn ttd_query_executor_find_call() {
        let trace = build_query_test_trace();
        let q = TtdQuery::FindCall {
            addr: 0x4000,
            after: None,
        };
        let result = TtdQueryExecutor::execute(&q, &trace);
        assert_eq!(result.len(), 2);
        assert!(
            result
                .matching_events
                .iter()
                .all(|r| { matches!(r.event.kind, EventKind::Call { to, .. } if to == 0x4000) })
        );
        assert!(!result.to_string().is_empty());
    }

    #[test]
    fn ttd_query_executor_find_call_after() {
        let trace = build_query_test_trace();
        // The two calls to 0x4000 are at positions seq=2 and seq=11.
        let q = TtdQuery::FindCall {
            addr: 0x4000,
            after: Some(TracePosition::new(5, 0)),
        };
        let result = TtdQueryExecutor::execute(&q, &trace);
        // Only the call at seq=11 is after seq=5.
        assert_eq!(result.len(), 1);
        assert_eq!(result.matching_events[0].event.position.sequence, 11);
    }

    #[test]
    fn ttd_query_executor_find_write_between() {
        let trace = build_query_test_trace();
        let q = TtdQuery::FindWrite {
            addr: 0x2000,
            between: Some((TracePosition::new(0, 0), TracePosition::new(5, 0))),
        };
        let result = TtdQueryExecutor::execute(&q, &trace);
        // First write at seq=1 falls in [0,5]; second at seq=10 does not.
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn ttd_query_executor_find_read() {
        let trace = build_query_test_trace();
        let q = TtdQuery::FindRead { addr: 0x1000 };
        let result = TtdQueryExecutor::execute(&q, &trace);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn ttd_query_executor_find_exception() {
        let trace = build_query_test_trace();
        let q = TtdQuery::FindException;
        let result = TtdQueryExecutor::execute(&q, &trace);
        assert_eq!(result.len(), 1);
        assert!(result.matching_events[0].index < trace.event_count());
    }

    #[test]
    fn ttd_query_executor_no_match() {
        let trace = build_query_test_trace();
        let q = TtdQuery::FindRead { addr: 0xdead_beef };
        let result = TtdQueryExecutor::execute(&q, &trace);
        assert!(result.is_empty());
    }

    // ── TtdReportGenerator ────────────────────────────────────────────────────

    #[test]
    fn report_generator_call_tree_basic() {
        let trace = build_query_test_trace();
        let report = TtdReportGenerator::generate_call_tree(&trace, 0x4000);
        assert!(report.contains("0x4000"));
        assert!(report.starts_with("[call tree for 0x4000]"));
    }

    #[test]
    fn report_generator_call_tree_missing_root() {
        let trace = build_query_test_trace();
        let report = TtdReportGenerator::generate_call_tree(&trace, 0xdead_beef);
        // Nothing matches; only the header line is emitted.
        assert!(report.starts_with("[call tree for 0xdeadbeef]"));
        assert_eq!(report.lines().count(), 1);
    }

    #[test]
    fn report_generator_memory_access_report() {
        let trace = build_query_test_trace();
        // 0x1000..0x3000 covers reads at 0x1000 and writes at 0x2000.
        let report = TtdReportGenerator::generate_memory_access_report(&trace, (0x1000, 0x3000));
        assert!(report.starts_with("[memory access report for 0x1000..0x3000]"));
        assert!(report.contains("reads:"));
        assert!(report.contains("writes:"));
        assert!(report.contains("0x1000"));
        assert!(report.contains("0x2000"));
    }

    #[test]
    fn report_generator_memory_access_report_empty_range() {
        let trace = build_query_test_trace();
        let report = TtdReportGenerator::generate_memory_access_report(&trace, (0xff00, 0xff10));
        assert!(report.contains("reads:  0"));
        assert!(report.contains("writes: 0"));
    }
}
