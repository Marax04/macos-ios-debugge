//! Time-travel query engine for TTD traces.
//!
//! Provides high-level queries over a full execution trace:
//! * When did register R hold value V?
//! * When was address A written value V?
//! * All invocations of function F.
//! * Which instruction last wrote to memory address M?

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use rustre_ttd::{EventKind, TraceEvent, TracePosition, TtdTrace};

// ─── RegisterQuery ────────────────────────────────────────────────────────────

/// Query: find all trace positions where `register` equals `value`.
#[derive(Debug, Clone)]
pub struct RegisterQuery {
    pub register: String,
    pub value: u64,
    pub thread_id: Option<u32>,
}

impl RegisterQuery {
    #[must_use]
    pub fn new(register: impl Into<String>, value: u64) -> Self {
        Self {
            register: register.into(),
            value,
            thread_id: None,
        }
    }

    #[must_use]
    pub const fn for_thread(mut self, tid: u32) -> Self {
        self.thread_id = Some(tid);
        self
    }
}

impl fmt::Display for RegisterQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RegisterQuery {{ reg={}, value={:#x}, tid={:?} }}",
            self.register, self.value, self.thread_id
        )
    }
}

// ─── MemoryQuery ──────────────────────────────────────────────────────────────

/// Query: find all trace positions where address `addr` held value `value`.
#[derive(Debug, Clone)]
pub struct MemoryQuery {
    pub address: u64,
    pub value: Vec<u8>,
    pub match_kind: MemMatchKind,
}

/// How to match a memory value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemMatchKind {
    /// Exact byte sequence match.
    Exact,
    /// Match only the first `n` bytes of the stored value against the pattern.
    Prefix,
    /// Match if the stored bytes contain the pattern anywhere.
    Contains,
}

impl MemoryQuery {
    #[must_use]
    pub const fn exact(address: u64, value: Vec<u8>) -> Self {
        Self {
            address,
            value,
            match_kind: MemMatchKind::Exact,
        }
    }

    #[must_use]
    pub const fn contains(address: u64, pattern: Vec<u8>) -> Self {
        Self {
            address,
            value: pattern,
            match_kind: MemMatchKind::Contains,
        }
    }

    /// Check whether `data` matches this query.
    #[must_use]
    pub fn matches_bytes(&self, data: &[u8]) -> bool {
        match self.match_kind {
            MemMatchKind::Exact => data == self.value.as_slice(),
            MemMatchKind::Prefix => {
                data.len() >= self.value.len() && data.starts_with(&self.value)
            }
            MemMatchKind::Contains => data
                .windows(self.value.len())
                .any(|w| w == self.value.as_slice()),
        }
    }
}

impl fmt::Display for MemoryQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemoryQuery {{ addr={:#x}, len={}, kind={:?} }}",
            self.address,
            self.value.len(),
            self.match_kind
        )
    }
}

// ─── CallQuery ────────────────────────────────────────────────────────────────

/// Query: find all calls to / from a given address.
#[derive(Debug, Clone)]
pub struct CallQuery {
    pub target: Option<u64>,
    pub caller: Option<u64>,
    pub thread_id: Option<u32>,
}

impl CallQuery {
    #[must_use]
    pub const fn to_target(target: u64) -> Self {
        Self {
            target: Some(target),
            caller: None,
            thread_id: None,
        }
    }

    #[must_use]
    pub const fn from_caller(caller: u64) -> Self {
        Self {
            target: None,
            caller: Some(caller),
            thread_id: None,
        }
    }

    #[must_use]
    pub const fn for_thread(mut self, tid: u32) -> Self {
        self.thread_id = Some(tid);
        self
    }
}

impl fmt::Display for CallQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CallQuery {{ target={:?}, caller={:?}, tid={:?} }}",
            self.target.map(|a| format!("{a:#x}")),
            self.caller.map(|a| format!("{a:#x}")),
            self.thread_id
        )
    }
}

// ─── TtQuery ──────────────────────────────────────────────────────────────────

/// A time-travel query — either a register, memory, or call query.
#[derive(Debug, Clone)]
pub enum TtQuery {
    Register(RegisterQuery),
    Memory(MemoryQuery),
    Call(CallQuery),
    /// Find all events where a syscall with number `nr` was entered.
    SyscallEnter(u32),
    /// Find all events where a syscall with number `nr` returned.
    SyscallExit(u32),
    /// Find all thread creation events.
    ThreadCreate,
    /// Find all exception events.
    Exception,
}

impl fmt::Display for TtQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Register(q) => write!(f, "TtQuery::Register({q})"),
            Self::Memory(q) => write!(f, "TtQuery::Memory({q})"),
            Self::Call(q) => write!(f, "TtQuery::Call({q})"),
            Self::SyscallEnter(nr) => write!(f, "TtQuery::SyscallEnter({nr})"),
            Self::SyscallExit(nr) => write!(f, "TtQuery::SyscallExit({nr})"),
            Self::ThreadCreate => write!(f, "TtQuery::ThreadCreate"),
            Self::Exception => write!(f, "TtQuery::Exception"),
        }
    }
}

// ─── QueryMatch ───────────────────────────────────────────────────────────────

/// A single match returned by a query.
#[derive(Debug, Clone)]
pub struct QueryMatch {
    pub position: TracePosition,
    pub thread_id: u32,
    pub event_index: usize,
    pub detail: QueryMatchDetail,
}

/// Detail data about a specific query match.
#[derive(Debug, Clone)]
pub enum QueryMatchDetail {
    /// Register had the queried value at this position.
    Register {
        reg: String,
        value: u64,
    },
    /// Memory address was written with the queried value.
    Memory {
        address: u64,
        bytes: Vec<u8>,
    },
    /// A function call occurred with the matching properties.
    Call {
        from: u64,
        to: u64,
    },
    /// A syscall was entered/exited.
    Syscall {
        nr: u32,
        args: Option<[u64; 6]>,
        ret: Option<u64>,
    },
    /// A new thread was created.
    Thread {
        tid: u32,
    },
    /// An exception occurred.
    Exception {
        code: u32,
        address: u64,
    },
}

impl fmt::Display for QueryMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "QueryMatch {{ pos={}, tid={}, idx={} }}",
            self.position, self.thread_id, self.event_index
        )
    }
}

// ─── QueryResult ─────────────────────────────────────────────────────────────

/// The full result set of a time-travel query.
#[derive(Debug, Clone)]
pub struct QueryResult {
    pub query: String,
    pub matches: Vec<QueryMatch>,
    pub total_events_scanned: usize,
    pub duration_us: u64,
}

impl QueryResult {
    #[must_use]
    pub fn empty(query: impl Into<String>, scanned: usize) -> Self {
        Self {
            query: query.into(),
            matches: Vec::new(),
            total_events_scanned: scanned,
            duration_us: 0,
        }
    }

    #[must_use]
    pub const fn hit_count(&self) -> usize {
        self.matches.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.matches.is_empty()
    }

    /// Return the first match position if any.
    #[must_use]
    pub fn first_position(&self) -> Option<TracePosition> {
        self.matches.first().map(|m| m.position)
    }

    /// Return the last match position if any.
    #[must_use]
    pub fn last_position(&self) -> Option<TracePosition> {
        self.matches.last().map(|m| m.position)
    }

    /// Filter matches to a specific thread.
    #[must_use]
    pub fn for_thread(&self, tid: u32) -> Vec<&QueryMatch> {
        self.matches.iter().filter(|m| m.thread_id == tid).collect()
    }

    /// Return all positions as a flat vec.
    #[must_use]
    pub fn positions(&self) -> Vec<TracePosition> {
        self.matches.iter().map(|m| m.position).collect()
    }
}

impl fmt::Display for QueryResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "QueryResult {{ query=\"{}\", hits={}, scanned={} }}",
            self.query, self.matches.len(), self.total_events_scanned
        )
    }
}

// ─── MemoryStateTracker ───────────────────────────────────────────────────────

/// Lightweight memory state tracker that only keeps track of written bytes.
struct MemoryStateTracker {
    pages: HashMap<u64, Vec<u8>>,
}

impl MemoryStateTracker {
    const PAGE_SIZE: u64 = 4096;

    fn new() -> Self {
        Self {
            pages: HashMap::new(),
        }
    }

    const fn page_base(addr: u64) -> u64 {
        addr & !(Self::PAGE_SIZE - 1)
    }

    fn apply_write(&mut self, addr: u64, data: &[u8]) {
        let mut offset = 0usize;
        let mut cur = addr;
        while offset < data.len() {
            let base = Self::page_base(cur);
            let page = self
                .pages
                .entry(base)
                .or_insert_with(|| vec![0u8; usize::try_from(Self::PAGE_SIZE).unwrap_or(usize::MAX)]);
            let page_off = usize::try_from(cur - base).unwrap_or(usize::MAX);
            let can = usize::try_from(Self::PAGE_SIZE).unwrap_or(usize::MAX) - page_off;
            let to = (data.len() - offset).min(can);
            page[page_off..page_off + to].copy_from_slice(&data[offset..offset + to]);
            offset += to;
            cur += to as u64;
        }
    }

    fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(vec![]);
        }
        let mut out = Vec::with_capacity(len);
        let mut offset = 0usize;
        let mut cur = addr;
        while offset < len {
            let base = Self::page_base(cur);
            let page = self.pages.get(&base)?;
            let page_off = usize::try_from(cur - base).unwrap_or(usize::MAX);
            let can = usize::try_from(Self::PAGE_SIZE).unwrap_or(usize::MAX) - page_off;
            let to = (len - offset).min(can);
            out.extend_from_slice(&page[page_off..page_off + to]);
            offset += to;
            cur += to as u64;
        }
        Some(out)
    }
}

// ─── RegisterStateTracker ─────────────────────────────────────────────────────

/// Track per-thread register state as we scan events.
struct RegisterStateTracker {
    regs: HashMap<u32, HashMap<String, u64>>,
}

impl RegisterStateTracker {
    fn new() -> Self {
        Self {
            regs: HashMap::new(),
        }
    }

    fn apply(&mut self, event: &TraceEvent) {
        let r = self.regs.entry(event.thread_id).or_default();
        match &event.kind {
            EventKind::Call { to, .. } | EventKind::Return { to, .. } => {
                r.insert("rip".into(), *to);
            }
            EventKind::SyscallEnter { nr, args } => {
                r.insert("rax".into(), u64::from(*nr));
                for (i, &v) in args.iter().enumerate() {
                    let name = match i {
                        0 => "rdi",
                        1 => "rsi",
                        2 => "rdx",
                        3 => "r10",
                        4 => "r8",
                        _ => "r9",
                    };
                    r.insert(name.to_string(), v);
                }
            }
            EventKind::SyscallExit { ret, .. } => {
                r.insert("rax".into(), *ret);
            }
            _ => {}
        }
    }

    fn get(&self, tid: u32, reg: &str) -> Option<u64> {
        self.regs.get(&tid)?.get(reg).copied()
    }
}

// ─── TimeTravelQueryEngine ────────────────────────────────────────────────────

/// Engine that executes time-travel queries against a TTD trace.
pub struct TimeTravelQueryEngine {
    trace: Arc<TtdTrace>,
}

impl TimeTravelQueryEngine {
    /// Create a new query engine for the given trace.
    #[must_use]
    pub const fn new(trace: Arc<TtdTrace>) -> Self {
        Self { trace }
    }

    /// Execute a query over the full trace and return matches.
    #[must_use] 
    pub fn execute(&self, query: &TtQuery) -> QueryResult {
        let events = self.trace.all_events();
        let scanned = events.len();
        let label = format!("{query}");

        let matches = match query {
            TtQuery::Register(rq) => Self::exec_register(rq, &events),
            TtQuery::Memory(mq) => Self::exec_memory(mq, &events),
            TtQuery::Call(cq) => Self::exec_call(cq, &events),
            TtQuery::SyscallEnter(nr) => Self::exec_syscall_enter(*nr, &events),
            TtQuery::SyscallExit(nr) => Self::exec_syscall_exit(*nr, &events),
            TtQuery::ThreadCreate => Self::exec_thread_create(&events),
            TtQuery::Exception => Self::exec_exception(&events),
        };

        QueryResult {
            query: label,
            matches,
            total_events_scanned: scanned,
            duration_us: 0,
        }
    }

    // ── Register query ───────────────────────────────────────────────────────

    fn exec_register(
        rq: &RegisterQuery,
        events: &[TraceEvent],
    ) -> Vec<QueryMatch> {
        let mut tracker = RegisterStateTracker::new();
        let mut matches = Vec::new();

        for (idx, event) in events.iter().enumerate() {
            tracker.apply(event);

            if let Some(tid_filter) = rq.thread_id
                && event.thread_id != tid_filter {
                    continue;
                }

            if let Some(val) = tracker.get(event.thread_id, &rq.register)
                && val == rq.value {
                    matches.push(QueryMatch {
                        position: event.position,
                        thread_id: event.thread_id,
                        event_index: idx,
                        detail: QueryMatchDetail::Register {
                            reg: rq.register.clone(),
                            value: val,
                        },
                    });
                }
        }
        matches
    }

    // ── Memory query ─────────────────────────────────────────────────────────

    fn exec_memory(
        mq: &MemoryQuery,
        events: &[TraceEvent],
    ) -> Vec<QueryMatch> {
        let mut mem = MemoryStateTracker::new();
        let mut matches = Vec::new();

        for (idx, event) in events.iter().enumerate() {
            if let EventKind::MemWrite { addr, data } = &event.kind {
                mem.apply_write(*addr, data);

                // Check if the affected range overlaps with our query address.
                let write_end = addr.saturating_add(data.len() as u64);
                if *addr <= mq.address && mq.address < write_end {
                    // Read exactly as many bytes as the query asks about. Using
                    // `max(query, write)` compared the FULL stored value to a
                    // shorter pattern, so asking "was the byte at 0x1000
                    // written 0xAA?" never matched a wider write that did
                    // exactly that.
                    let len = mq.value.len().max(1);
                    if let Some(current) = mem.read(mq.address, len)
                        && mq.matches_bytes(&current) {
                            matches.push(QueryMatch {
                                position: event.position,
                                thread_id: event.thread_id,
                                event_index: idx,
                                detail: QueryMatchDetail::Memory {
                                    address: mq.address,
                                    bytes: current,
                                },
                            });
                        }
                }
            }
        }
        matches
    }

    // ── Call query ────────────────────────────────────────────────────────────

    fn exec_call(cq: &CallQuery, events: &[TraceEvent]) -> Vec<QueryMatch> {
        let mut matches = Vec::new();
        for (idx, event) in events.iter().enumerate() {
            if let Some(tid_filter) = cq.thread_id
                && event.thread_id != tid_filter {
                    continue;
                }
            if let EventKind::Call { from, to } = &event.kind {
                let target_match = cq.target.is_none_or(|t| t == *to);
                let caller_match = cq.caller.is_none_or(|c| c == *from);
                if target_match && caller_match {
                    matches.push(QueryMatch {
                        position: event.position,
                        thread_id: event.thread_id,
                        event_index: idx,
                        detail: QueryMatchDetail::Call {
                            from: *from,
                            to: *to,
                        },
                    });
                }
            }
        }
        matches
    }

    // ── SyscallEnter query ────────────────────────────────────────────────────

    fn exec_syscall_enter(nr: u32, events: &[TraceEvent]) -> Vec<QueryMatch> {
        let mut matches = Vec::new();
        for (idx, event) in events.iter().enumerate() {
            if let EventKind::SyscallEnter {
                nr: snr,
                args,
            } = &event.kind
                && *snr == nr {
                    matches.push(QueryMatch {
                        position: event.position,
                        thread_id: event.thread_id,
                        event_index: idx,
                        detail: QueryMatchDetail::Syscall {
                            nr,
                            args: Some(*args),
                            ret: None,
                        },
                    });
                }
        }
        matches
    }

    // ── SyscallExit query ─────────────────────────────────────────────────────

    fn exec_syscall_exit(nr: u32, events: &[TraceEvent]) -> Vec<QueryMatch> {
        let mut matches = Vec::new();
        for (idx, event) in events.iter().enumerate() {
            if let EventKind::SyscallExit { nr: snr, ret } = &event.kind
                && *snr == nr {
                    matches.push(QueryMatch {
                        position: event.position,
                        thread_id: event.thread_id,
                        event_index: idx,
                        detail: QueryMatchDetail::Syscall {
                            nr,
                            args: None,
                            ret: Some(*ret),
                        },
                    });
                }
        }
        matches
    }

    // ── Thread create query ────────────────────────────────────────────────────

    fn exec_thread_create(events: &[TraceEvent]) -> Vec<QueryMatch> {
        let mut matches = Vec::new();
        for (idx, event) in events.iter().enumerate() {
            if let EventKind::ThreadCreate { tid } = &event.kind {
                matches.push(QueryMatch {
                    position: event.position,
                    thread_id: event.thread_id,
                    event_index: idx,
                    detail: QueryMatchDetail::Thread { tid: *tid },
                });
            }
        }
        matches
    }

    // ── Exception query ───────────────────────────────────────────────────────

    fn exec_exception(events: &[TraceEvent]) -> Vec<QueryMatch> {
        let mut matches = Vec::new();
        for (idx, event) in events.iter().enumerate() {
            if let EventKind::Exception { code, addr } = &event.kind {
                matches.push(QueryMatch {
                    position: event.position,
                    thread_id: event.thread_id,
                    event_index: idx,
                    detail: QueryMatchDetail::Exception {
                        code: *code,
                        address: *addr,
                    },
                });
            }
        }
        matches
    }

    // ── Convenience query helpers ─────────────────────────────────────────────

    /// Find all positions where `reg` (in `tid`) equals `value`.
    #[must_use]
    pub fn find_register_value(&self, reg: &str, value: u64, tid: Option<u32>) -> QueryResult {
        let mut q = RegisterQuery::new(reg, value);
        if let Some(t) = tid {
            q = q.for_thread(t);
        }
        self.execute(&TtQuery::Register(q))
    }

    /// Find all positions where `address` was written with `value`.
    #[must_use]
    pub fn find_memory_write(&self, address: u64, value: Vec<u8>) -> QueryResult {
        self.execute(&TtQuery::Memory(MemoryQuery::exact(address, value)))
    }

    /// Find all positions where function `target` was called.
    #[must_use]
    pub fn find_calls_to(&self, target: u64) -> QueryResult {
        self.execute(&TtQuery::Call(CallQuery::to_target(target)))
    }

    /// Find all positions where calls originated from `caller`.
    #[must_use]
    pub fn find_calls_from(&self, caller: u64) -> QueryResult {
        self.execute(&TtQuery::Call(CallQuery::from_caller(caller)))
    }

    /// Find which event last wrote to `address` before `pos`.
    #[must_use]
    pub fn find_last_writer_before(&self, address: u64, pos: TracePosition) -> Option<QueryMatch> {
        let events = self.trace.all_events();
        let mut last: Option<QueryMatch> = None;

        for (idx, event) in events.iter().enumerate() {
            if event.position > pos {
                break;
            }
            if let EventKind::MemWrite { addr, data } = &event.kind {
                let end = addr.saturating_add(data.len() as u64);
                if *addr <= address && address < end {
                    last = Some(QueryMatch {
                        position: event.position,
                        thread_id: event.thread_id,
                        event_index: idx,
                        detail: QueryMatchDetail::Memory {
                            address,
                            bytes: data.clone(),
                        },
                    });
                }
            }
        }
        last
    }

    /// Find the first time `reg` (tid 1) became non-zero.
    #[must_use]
    pub fn find_first_nonzero(&self, reg: &str, tid: u32) -> Option<QueryMatch> {
        let events = self.trace.all_events();
        let mut tracker = RegisterStateTracker::new();

        for (idx, event) in events.iter().enumerate() {
            tracker.apply(event);
            if event.thread_id != tid {
                continue;
            }
            if let Some(val) = tracker.get(tid, reg)
                && val != 0 {
                    return Some(QueryMatch {
                        position: event.position,
                        thread_id: event.thread_id,
                        event_index: idx,
                        detail: QueryMatchDetail::Register {
                            reg: reg.to_string(),
                            value: val,
                        },
                    });
                }
        }
        None
    }

    /// Summarise how many times each syscall number was called.
    #[must_use]
    pub fn syscall_frequency(&self) -> Vec<(u32, usize)> {
        let events = self.trace.all_events();
        let mut freq: HashMap<u32, usize> = HashMap::new();
        for event in &events {
            if let EventKind::SyscallEnter { nr, .. } = &event.kind {
                *freq.entry(*nr).or_insert(0) += 1;
            }
        }
        let mut pairs: Vec<(u32, usize)> = freq.into_iter().collect();
        pairs.sort_by_key(|b| std::cmp::Reverse(b.1));
        pairs
    }

    /// Return all (caller, target, count) call triples.
    #[must_use]
    pub fn call_frequency(&self) -> Vec<(u64, u64, usize)> {
        let events = self.trace.all_events();
        let mut freq: HashMap<(u64, u64), usize> = HashMap::new();
        for event in &events {
            if let EventKind::Call { from, to } = &event.kind {
                *freq.entry((*from, *to)).or_insert(0) += 1;
            }
        }
        let mut triples: Vec<(u64, u64, usize)> = freq
            .into_iter()
            .map(|((f, t), c)| (f, t, c))
            .collect();
        triples.sort_by_key(|b| std::cmp::Reverse(b.2));
        triples
    }

    /// Return all (address, count) write-frequency pairs.
    #[must_use]
    pub fn write_frequency(&self) -> Vec<(u64, usize)> {
        let events = self.trace.all_events();
        let mut freq: HashMap<u64, usize> = HashMap::new();
        for event in &events {
            if let EventKind::MemWrite { addr, .. } = &event.kind {
                *freq.entry(*addr).or_insert(0) += 1;
            }
        }
        let mut pairs: Vec<(u64, usize)> = freq.into_iter().collect();
        pairs.sort_by_key(|b| std::cmp::Reverse(b.1));
        pairs
    }

    /// Execute multiple queries in sequence and collect results.
    #[must_use]
    pub fn batch_execute(&self, queries: &[TtQuery]) -> Vec<QueryResult> {
        queries.iter().map(|q| self.execute(q)).collect()
    }

    /// Find all times the value at `addr` changed.
    #[must_use]
    pub fn find_value_changes(&self, addr: u64, size: usize) -> Vec<(TracePosition, Vec<u8>, Vec<u8>)> {
        let events = self.trace.all_events();
        let mut mem = MemoryStateTracker::new();
        let mut result = Vec::new();
        let mut prev: Option<Vec<u8>> = None;

        for event in &events {
            if let EventKind::MemWrite { addr: wa, data } = &event.kind {
                let write_end = wa.saturating_add(data.len() as u64);
                if *wa <= addr + size as u64 && addr <= write_end {
                    let before = mem.read(addr, size).unwrap_or_default();
                    mem.apply_write(*wa, data);
                    let after = mem.read(addr, size).unwrap_or_default();
                    if Some(&after) != prev.as_ref() {
                        result.push((event.position, before, after.clone()));
                        prev = Some(after);
                    }
                } else {
                    mem.apply_write(*wa, data);
                }
            }
        }
        result
    }

    /// Find all positions where a specific byte pattern appears in memory writes.
    #[must_use]
    pub fn find_pattern_in_writes(&self, pattern: &[u8]) -> Vec<QueryMatch> {
        let events = self.trace.all_events();
        let mut matches = Vec::new();
        for (idx, event) in events.iter().enumerate() {
            if let EventKind::MemWrite { addr, data } = &event.kind
                && data.windows(pattern.len()).any(|w| w == pattern) {
                    matches.push(QueryMatch {
                        position: event.position,
                        thread_id: event.thread_id,
                        event_index: idx,
                        detail: QueryMatchDetail::Memory {
                            address: *addr,
                            bytes: data.clone(),
                        },
                    });
                }
        }
        matches
    }
}

impl fmt::Debug for TimeTravelQueryEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeTravelQueryEngine")
            .field("events", &self.trace.all_events().len())
            .finish_non_exhaustive()
    }
}

// ─── MemWriteRecord ───────────────────────────────────────────────────────────

/// A compact record of a memory write event.
#[derive(Debug, Clone)]
pub struct MemWriteRecord {
    pub position: TracePosition,
    pub thread_id: u32,
    pub address: u64,
    pub data: Vec<u8>,
    pub event_index: usize,
}

impl fmt::Display for MemWriteRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemWriteRecord {{ pos={}, addr={:#x}, len={} }}",
            self.position,
            self.address,
            self.data.len()
        )
    }
}

/// Index all memory writes in a trace for fast lookup.
#[must_use]
pub fn build_write_index(trace: &TtdTrace) -> Vec<MemWriteRecord> {
    trace
        .all_events()
        .into_iter()
        .enumerate()
        .filter_map(|(i, event)| {
            if let EventKind::MemWrite { addr, data } = event.kind {
                Some(MemWriteRecord {
                    position: event.position,
                    thread_id: event.thread_id,
                    address: addr,
                    data,
                    event_index: i,
                })
            } else {
                None
            }
        })
        .collect()
}

/// Return all write records that overlap with the address range [start, end).
#[must_use]
pub fn writes_in_range(
    index: &[MemWriteRecord],
    start: u64,
    end: u64,
) -> Vec<&MemWriteRecord> {
    index
        .iter()
        .filter(|r| {
            let wend = r.address.saturating_add(r.data.len() as u64);
            r.address < end && wend > start
        })
        .collect()
}

// ─── QueryStats ───────────────────────────────────────────────────────────────

/// Statistics aggregated from a batch of query results.
#[derive(Debug, Clone, Default)]
pub struct QueryStats {
    pub total_queries: usize,
    pub total_matches: usize,
    pub queries_with_zero_matches: usize,
    pub max_matches: usize,
    pub min_matches: usize,
}

impl QueryStats {
    #[must_use]
    pub fn compute(results: &[QueryResult]) -> Self {
        if results.is_empty() {
            return Self::default();
        }
        let total_queries = results.len();
        let total_matches: usize = results.iter().map(QueryResult::hit_count).sum();
        let queries_with_zero_matches = results.iter().filter(|r| r.is_empty()).count();
        let max_matches = results.iter().map(QueryResult::hit_count).max().unwrap_or(0);
        let min_matches = results.iter().map(QueryResult::hit_count).min().unwrap_or(0);
        Self {
            total_queries,
            total_matches,
            queries_with_zero_matches,
            max_matches,
            min_matches,
        }
    }

    #[must_use]
    pub fn average_matches(&self) -> f64 {
        if self.total_queries == 0 {
            0.0
        } else {
            self.total_matches as f64 / self.total_queries as f64
        }
    }
}

impl fmt::Display for QueryStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "QueryStats {{ queries={}, total_matches={}, avg={:.1}, max={}, min={} }}",
            self.total_queries,
            self.total_matches,
            self.average_matches(),
            self.max_matches,
            self.min_matches
        )
    }
}
