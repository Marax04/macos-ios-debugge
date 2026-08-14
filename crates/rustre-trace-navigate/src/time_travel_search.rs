//! Time-travel search over execution traces.
//!
//! Provides specialised searchers that find specific events by navigating the
//! trace both forwards and backwards in time.
//!
//! # Structs
//! - [`SearchResult`]           — the outcome of a search (seq + metadata)
//! - [`SearchForMemWrite`]      — find the last write to a given address
//! - [`SearchForApiCall`]       — find calls to a syscall / API number
//! - [`SearchForException`]     — find hardware exceptions
//! - [`SearchForValue`]         — find when a register or memory held a value
//! - [`SearchForInstruction`]   — find by instruction PC or disassembly substring
//! - [`TimeTravelSearch`]       — composite search coordinator

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{EntryKind, ExecutionTrace, TraceEntry};

/// Re-exports of the per-address and per-register timeline indexes used by
/// [`TimeTravelSearch`] consumers that want direct timeline access.
pub use crate::{MemAccessIndex, RegTimeline};

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the time-travel search subsystem.
#[derive(Debug, Error)]
pub enum SearchError {
    #[error("no match found")]
    NoMatch,
    #[error("trace is empty")]
    EmptyTrace,
    #[error("start index {start} > end index {end}")]
    InvalidRange { start: usize, end: usize },
    #[error("search limit exceeded after {0} steps")]
    LimitExceeded(usize),
    #[error("invalid query: {0}")]
    InvalidQuery(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchDirection
// ─────────────────────────────────────────────────────────────────────────────

/// Which direction to scan the trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SearchDirection {
    /// Scan forward (increasing index).
    Forward,
    /// Scan backward (decreasing index).
    Backward,
}

impl std::fmt::Display for SearchDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Forward => write!(f, "forward"),
            Self::Backward => write!(f, "backward"),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchResult
// ─────────────────────────────────────────────────────────────────────────────

/// The outcome of a successful search.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// Trace index of the matching entry.
    pub idx: usize,
    /// Program counter at the match.
    pub pc: u64,
    /// Thread ID of the matching entry.
    pub tid: u32,
    /// Human-readable description of what was found.
    pub description: String,
    /// Free-form metadata.
    pub metadata: HashMap<String, String>,
    /// Number of entries scanned to find this result.
    pub steps_taken: usize,
    /// Search direction.
    pub direction: SearchDirection,
}

impl SearchResult {
    #[must_use]
    pub fn new(
        idx: usize,
        pc: u64,
        tid: u32,
        description: impl Into<String>,
        direction: SearchDirection,
        steps: usize,
    ) -> Self {
        Self {
            idx,
            pc,
            tid,
            description: description.into(),
            metadata: HashMap::new(),
            steps_taken: steps,
            direction,
        }
    }

    /// Attach metadata.
    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), val.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchRange
// ─────────────────────────────────────────────────────────────────────────────

/// Range of trace indices to search.
#[derive(Debug, Clone, Copy)]
pub struct SearchRange {
    /// Inclusive start (in forward) / inclusive end (in backward).
    pub start: usize,
    /// Inclusive end (in forward) / inclusive start (in backward).
    pub end: usize,
}

impl SearchRange {
    /// Whole trace.
    #[must_use]
    pub const fn all(len: usize) -> Self {
        Self {
            start: 0,
            end: len.saturating_sub(1),
        }
    }

    /// From `start` to end.
    #[must_use]
    pub const fn from(start: usize, len: usize) -> Self {
        Self {
            start,
            end: len.saturating_sub(1),
        }
    }

    /// From 0 to `end`.
    #[must_use]
    pub const fn up_to(end: usize) -> Self {
        Self { start: 0, end }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchForMemWrite
// ─────────────────────────────────────────────────────────────────────────────

/// Finds memory write events to a specific address, optionally filtered by value.
#[derive(Debug, Clone)]
pub struct SearchForMemWrite {
    /// Target memory address.
    pub target_addr: u64,
    /// If `Some`, only match writes of this exact value.
    pub target_value: Option<u64>,
    /// Maximum number of matches to collect.
    pub max_results: usize,
    /// Step limit.
    pub step_limit: usize,
}

impl SearchForMemWrite {
    /// Create a new write searcher for `addr`.
    #[must_use]
    pub const fn new(addr: u64) -> Self {
        Self {
            target_addr: addr,
            target_value: None,
            max_results: 16,
            step_limit: usize::MAX,
        }
    }

    /// Only match writes of `value`.
    #[must_use]
    pub const fn with_value(mut self, v: u64) -> Self {
        self.target_value = Some(v);
        self
    }

    /// Set maximum results.
    #[must_use]
    pub const fn max_results(mut self, n: usize) -> Self {
        self.max_results = n;
        self
    }

    /// Search forward from `start_idx`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn search_forward(
        &self,
        trace: &ExecutionTrace,
        start_idx: usize,
    ) -> Result<Vec<SearchResult>, SearchError> {
        if trace.is_empty() {
            return Err(SearchError::EmptyTrace);
        }
        let mut results = Vec::new();
        let safe_start = start_idx.min(trace.entries.len());
        for (step, entry) in trace.entries[safe_start..].iter().enumerate() {
            if results.len() >= self.max_results {
                break;
            }
            if step >= self.step_limit {
                return Err(SearchError::LimitExceeded(step));
            }
            for (addr, bytes) in &entry.mem_writes {
                if *addr == self.target_addr {
                    let val = crate::bytes_to_u64(bytes);
                    if self.target_value.is_none_or(|v| v == val) {
                        results.push(
                            SearchResult::new(
                                entry.idx,
                                entry.pc,
                                entry.tid,
                                format!("write {val:#x} to {addr:#x}"),
                                SearchDirection::Forward,
                                step + 1,
                            )
                            .with_meta("value", format!("{val:#x}")),
                        );
                    }
                }
            }
        }
        if results.is_empty() {
            Err(SearchError::NoMatch)
        } else {
            Ok(results)
        }
    }

    /// Search backward from `start_idx`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn search_backward(
        &self,
        trace: &ExecutionTrace,
        start_idx: usize,
    ) -> Result<Vec<SearchResult>, SearchError> {
        if trace.is_empty() {
            return Err(SearchError::EmptyTrace);
        }
        let mut results = Vec::new();
        let end = start_idx.min(trace.len().saturating_sub(1));
        for (step, entry) in trace.entries[..=end].iter().rev().enumerate() {
            if results.len() >= self.max_results {
                break;
            }
            if step >= self.step_limit {
                return Err(SearchError::LimitExceeded(step));
            }
            for (addr, bytes) in &entry.mem_writes {
                if *addr == self.target_addr {
                    let val = crate::bytes_to_u64(bytes);
                    if self.target_value.is_none_or(|v| v == val) {
                        results.push(
                            SearchResult::new(
                                entry.idx,
                                entry.pc,
                                entry.tid,
                                format!("write {val:#x} to {addr:#x}"),
                                SearchDirection::Backward,
                                step + 1,
                            )
                            .with_meta("value", format!("{val:#x}")),
                        );
                    }
                }
            }
        }
        if results.is_empty() {
            Err(SearchError::NoMatch)
        } else {
            Ok(results)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchForApiCall
// ─────────────────────────────────────────────────────────────────────────────

/// Finds CALL entries targeting a specific callee address or matching a
/// function name substring.
#[derive(Debug, Clone)]
pub struct SearchForApiCall {
    /// Callee address to match (None = wildcard).
    pub target_addr: Option<u64>,
    /// Function name substring to match (None = wildcard).
    pub name_substr: Option<String>,
    pub max_results: usize,
    pub step_limit: usize,
}

impl SearchForApiCall {
    #[must_use]
    pub const fn by_addr(addr: u64) -> Self {
        Self {
            target_addr: Some(addr),
            name_substr: None,
            max_results: 16,
            step_limit: usize::MAX,
        }
    }

    #[must_use]
    pub fn by_name(name: impl Into<String>) -> Self {
        Self {
            target_addr: None,
            name_substr: Some(name.into()),
            max_results: 16,
            step_limit: usize::MAX,
        }
    }

    fn matches(&self, entry: &TraceEntry) -> bool {
        match &entry.kind {
            EntryKind::Call { target, .. } => {
                let addr_ok = self.target_addr.is_none_or(|a| *target == a);
                let name_ok = self.name_substr.as_ref().is_none_or(|sub| {
                    entry
                        .disasm
                        .to_ascii_lowercase()
                        .contains(&sub.to_ascii_lowercase())
                });
                addr_ok && name_ok
            }
            _ => false,
        }
    }

    /// # Errors
    /// Returns an error if the operation fails.
    pub fn search(
        &self,
        trace: &ExecutionTrace,
        start_idx: usize,
        direction: SearchDirection,
    ) -> Result<Vec<SearchResult>, SearchError> {
        if trace.is_empty() {
            return Err(SearchError::EmptyTrace);
        }
        let mut results = Vec::new();
        let entries: Vec<&TraceEntry> = match direction {
            SearchDirection::Forward => trace.entries[start_idx.min(trace.entries.len())..].iter().collect(),
            SearchDirection::Backward => trace.entries[..=start_idx.min(trace.len() - 1)]
                .iter()
                .rev()
                .collect(),
        };
        for (step, entry) in entries.iter().enumerate() {
            if results.len() >= self.max_results {
                break;
            }
            if step >= self.step_limit {
                return Err(SearchError::LimitExceeded(step));
            }
            if self.matches(entry) {
                results.push(SearchResult::new(
                    entry.idx,
                    entry.pc,
                    entry.tid,
                    format!("call at {:#x}: {}", entry.pc, entry.disasm),
                    direction,
                    step + 1,
                ));
            }
        }
        if results.is_empty() {
            Err(SearchError::NoMatch)
        } else {
            Ok(results)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchForException
// ─────────────────────────────────────────────────────────────────────────────

/// Finds entries with `Exception` kind, optionally filtered by code.
#[derive(Debug, Clone)]
pub struct SearchForException {
    pub target_code: Option<u32>,
    pub max_results: usize,
    pub step_limit: usize,
}

impl SearchForException {
    #[must_use]
    pub const fn any() -> Self {
        Self {
            target_code: None,
            max_results: 16,
            step_limit: usize::MAX,
        }
    }

    #[must_use]
    pub const fn with_code(code: u32) -> Self {
        Self {
            target_code: Some(code),
            max_results: 16,
            step_limit: usize::MAX,
        }
    }

    fn matches(&self, entry: &TraceEntry) -> bool {
        match &entry.kind {
            EntryKind::Exception { code } => self.target_code.is_none_or(|c| c == *code),
            _ => false,
        }
    }

    /// # Errors
    /// Returns an error if the operation fails.
    pub fn search(
        &self,
        trace: &ExecutionTrace,
        start_idx: usize,
        direction: SearchDirection,
    ) -> Result<Vec<SearchResult>, SearchError> {
        if trace.is_empty() {
            return Err(SearchError::EmptyTrace);
        }
        let mut results = Vec::new();
        let entries: Vec<&TraceEntry> = match direction {
            SearchDirection::Forward => trace.entries[start_idx.min(trace.entries.len())..].iter().collect(),
            SearchDirection::Backward => trace.entries[..=start_idx.min(trace.len() - 1)]
                .iter()
                .rev()
                .collect(),
        };
        for (step, entry) in entries.iter().enumerate() {
            if results.len() >= self.max_results {
                break;
            }
            if step >= self.step_limit {
                return Err(SearchError::LimitExceeded(step));
            }
            if self.matches(entry) {
                let code = if let EntryKind::Exception { code } = entry.kind {
                    code
                } else {
                    0
                };
                results.push(
                    SearchResult::new(
                        entry.idx,
                        entry.pc,
                        entry.tid,
                        format!("exception code={code:#x} at {:#x}", entry.pc),
                        direction,
                        step + 1,
                    )
                    .with_meta("code", format!("{code:#x}")),
                );
            }
        }
        if results.is_empty() {
            Err(SearchError::NoMatch)
        } else {
            Ok(results)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchForValue
// ─────────────────────────────────────────────────────────────────────────────

/// Finds trace entries where a specific register held a given value.
#[derive(Debug, Clone)]
pub struct SearchForValue {
    /// Register id to inspect.
    pub reg_id: u32,
    /// Target value.
    pub value: u64,
    pub max_results: usize,
    pub step_limit: usize,
}

impl SearchForValue {
    #[must_use]
    pub const fn in_register(reg_id: u32, value: u64) -> Self {
        Self {
            reg_id,
            value,
            max_results: 16,
            step_limit: usize::MAX,
        }
    }

    /// # Errors
    /// Returns an error if the operation fails.
    pub fn search(
        &self,
        trace: &ExecutionTrace,
        start_idx: usize,
        direction: SearchDirection,
    ) -> Result<Vec<SearchResult>, SearchError> {
        if trace.is_empty() {
            return Err(SearchError::EmptyTrace);
        }
        let mut results = Vec::new();
        let entries: Vec<&TraceEntry> = match direction {
            SearchDirection::Forward => trace.entries[start_idx.min(trace.entries.len())..].iter().collect(),
            SearchDirection::Backward => trace.entries[..=start_idx.min(trace.len() - 1)]
                .iter()
                .rev()
                .collect(),
        };
        for (step, entry) in entries.iter().enumerate() {
            if results.len() >= self.max_results {
                break;
            }
            if step >= self.step_limit {
                return Err(SearchError::LimitExceeded(step));
            }
            if let Some(v) = entry.reg_value(self.reg_id)
                && v == self.value {
                    results.push(
                        SearchResult::new(
                            entry.idx,
                            entry.pc,
                            entry.tid,
                            format!("reg[{}]={:#x} at {:#x}", self.reg_id, self.value, entry.pc),
                            direction,
                            step + 1,
                        )
                        .with_meta("reg_value", format!("{:#x}", self.value)),
                    );
                }
        }
        if results.is_empty() {
            Err(SearchError::NoMatch)
        } else {
            Ok(results)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchForInstruction
// ─────────────────────────────────────────────────────────────────────────────

/// Finds trace entries by PC address or disassembly substring.
#[derive(Debug, Clone)]
pub struct SearchForInstruction {
    /// Exact PC to match (None = wildcard).
    pub target_pc: Option<u64>,
    /// Disassembly substring to match (None = wildcard).
    pub disasm_substr: Option<String>,
    /// Thread filter (None = all threads).
    pub thread_filter: Option<u32>,
    pub max_results: usize,
    pub step_limit: usize,
}

impl SearchForInstruction {
    #[must_use]
    pub const fn by_pc(pc: u64) -> Self {
        Self {
            target_pc: Some(pc),
            disasm_substr: None,
            thread_filter: None,
            max_results: 16,
            step_limit: usize::MAX,
        }
    }

    #[must_use]
    pub fn by_disasm(substr: impl Into<String>) -> Self {
        Self {
            target_pc: None,
            disasm_substr: Some(substr.into()),
            thread_filter: None,
            max_results: 16,
            step_limit: usize::MAX,
        }
    }

    #[must_use]
    pub const fn for_thread(mut self, tid: u32) -> Self {
        self.thread_filter = Some(tid);
        self
    }

    fn matches(&self, entry: &TraceEntry) -> bool {
        if let Some(tid) = self.thread_filter
            && entry.tid != tid {
                return false;
            }
        let pc_ok = self.target_pc.is_none_or(|pc| entry.pc == pc);
        let dis_ok = self.disasm_substr.as_ref().is_none_or(|sub| {
            entry
                .disasm
                .to_ascii_lowercase()
                .contains(&sub.to_ascii_lowercase())
        });
        pc_ok && dis_ok
    }

    /// # Errors
    /// Returns an error if the operation fails.
    pub fn search(
        &self,
        trace: &ExecutionTrace,
        start_idx: usize,
        direction: SearchDirection,
    ) -> Result<Vec<SearchResult>, SearchError> {
        if trace.is_empty() {
            return Err(SearchError::EmptyTrace);
        }
        let mut results = Vec::new();
        let entries: Vec<&TraceEntry> = match direction {
            SearchDirection::Forward => trace.entries[start_idx.min(trace.entries.len())..].iter().collect(),
            SearchDirection::Backward => trace.entries[..=start_idx.min(trace.len() - 1)]
                .iter()
                .rev()
                .collect(),
        };
        for (step, entry) in entries.iter().enumerate() {
            if results.len() >= self.max_results {
                break;
            }
            if step >= self.step_limit {
                return Err(SearchError::LimitExceeded(step));
            }
            if self.matches(entry) {
                results.push(SearchResult::new(
                    entry.idx,
                    entry.pc,
                    entry.tid,
                    format!("insn at {:#x}: {}", entry.pc, entry.disasm),
                    direction,
                    step + 1,
                ));
            }
        }
        if results.is_empty() {
            Err(SearchError::NoMatch)
        } else {
            Ok(results)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SearchQuery
// ─────────────────────────────────────────────────────────────────────────────

/// A unified search query type.
#[derive(Debug, Clone)]
pub enum SearchQuery {
    MemWrite {
        addr: u64,
        value: Option<u64>,
    },
    ApiCall {
        addr: Option<u64>,
        name_substr: Option<String>,
    },
    Exception {
        code: Option<u32>,
    },
    Register {
        reg_id: u32,
        value: u64,
    },
    Instruction {
        pc: Option<u64>,
        disasm: Option<String>,
        tid: Option<u32>,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// TimeTravelSearch
// ─────────────────────────────────────────────────────────────────────────────

/// Composite time-travel search coordinator.
///
/// Owns a reference to an [`ExecutionTrace`] and provides a unified interface
/// for all five searcher types, as well as batch and chained searches.
pub struct TimeTravelSearch<'t> {
    /// The trace to search.
    pub trace: &'t ExecutionTrace,
    /// Current cursor position.
    pub cursor: usize,
    /// Default search direction.
    pub direction: SearchDirection,
    /// Default step limit.
    pub step_limit: usize,
    /// History of search results.
    pub history: Vec<SearchResult>,
}

impl<'t> TimeTravelSearch<'t> {
    /// Create a search coordinator for `trace`.
    #[must_use]
    pub const fn new(trace: &'t ExecutionTrace) -> Self {
        Self {
            trace,
            cursor: 0,
            direction: SearchDirection::Forward,
            step_limit: usize::MAX,
            history: Vec::new(),
        }
    }

    /// Set the cursor to `idx`.
    pub fn seek(&mut self, idx: usize) {
        self.cursor = idx.min(self.trace.len().saturating_sub(1));
    }

    /// Move cursor to the beginning.
    pub const fn rewind(&mut self) {
        self.cursor = 0;
    }

    /// Move cursor to the end.
    pub const fn fast_forward(&mut self) {
        self.cursor = self.trace.len().saturating_sub(1);
    }

    // ── Memory write search ───────────────────────────────────────────────────

    /// Find the next (or previous) write to `addr`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn find_mem_write(&mut self, addr: u64) -> Result<SearchResult, SearchError> {
        let s = SearchForMemWrite::new(addr);
        let results = match self.direction {
            SearchDirection::Forward => s.search_forward(self.trace, self.cursor)?,
            SearchDirection::Backward => s.search_backward(self.trace, self.cursor)?,
        };
        let r = results.into_iter().next().ok_or(SearchError::NoMatch)?;
        self.cursor = r.idx;
        self.history.push(r.clone());
        Ok(r)
    }

    /// Find a write to `addr` with specific `value`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn find_mem_write_value(
        &mut self,
        addr: u64,
        value: u64,
    ) -> Result<SearchResult, SearchError> {
        let s = SearchForMemWrite::new(addr).with_value(value);
        let results = match self.direction {
            SearchDirection::Forward => s.search_forward(self.trace, self.cursor)?,
            SearchDirection::Backward => s.search_backward(self.trace, self.cursor)?,
        };
        let r = results.into_iter().next().ok_or(SearchError::NoMatch)?;
        self.cursor = r.idx;
        self.history.push(r.clone());
        Ok(r)
    }

    // ── API / call search ─────────────────────────────────────────────────────

    /// Find a call to `target_addr`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn find_call(&mut self, target_addr: u64) -> Result<SearchResult, SearchError> {
        let s = SearchForApiCall::by_addr(target_addr);
        let results = s.search(self.trace, self.cursor, self.direction)?;
        let r = results.into_iter().next().ok_or(SearchError::NoMatch)?;
        self.cursor = r.idx;
        self.history.push(r.clone());
        Ok(r)
    }

    /// Find a call whose disassembly contains `name_substr`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn find_call_by_name(&mut self, name_substr: &str) -> Result<SearchResult, SearchError> {
        let s = SearchForApiCall::by_name(name_substr);
        let results = s.search(self.trace, self.cursor, self.direction)?;
        let r = results.into_iter().next().ok_or(SearchError::NoMatch)?;
        self.cursor = r.idx;
        self.history.push(r.clone());
        Ok(r)
    }

    // ── Exception search ──────────────────────────────────────────────────────

    /// Find the next exception.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn find_exception(&mut self) -> Result<SearchResult, SearchError> {
        let s = SearchForException::any();
        let results = s.search(self.trace, self.cursor, self.direction)?;
        let r = results.into_iter().next().ok_or(SearchError::NoMatch)?;
        self.cursor = r.idx;
        self.history.push(r.clone());
        Ok(r)
    }

    /// Find an exception with a specific code.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn find_exception_code(&mut self, code: u32) -> Result<SearchResult, SearchError> {
        let s = SearchForException::with_code(code);
        let results = s.search(self.trace, self.cursor, self.direction)?;
        let r = results.into_iter().next().ok_or(SearchError::NoMatch)?;
        self.cursor = r.idx;
        self.history.push(r.clone());
        Ok(r)
    }

    // ── Register value search ─────────────────────────────────────────────────

    /// Find an entry where `reg_id` == `value`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn find_reg_value(&mut self, reg_id: u32, value: u64) -> Result<SearchResult, SearchError> {
        let s = SearchForValue::in_register(reg_id, value);
        let results = s.search(self.trace, self.cursor, self.direction)?;
        let r = results.into_iter().next().ok_or(SearchError::NoMatch)?;
        self.cursor = r.idx;
        self.history.push(r.clone());
        Ok(r)
    }

    // ── Instruction search ────────────────────────────────────────────────────

    /// Find an entry at `pc`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn find_pc(&mut self, pc: u64) -> Result<SearchResult, SearchError> {
        let s = SearchForInstruction::by_pc(pc);
        let results = s.search(self.trace, self.cursor, self.direction)?;
        let r = results.into_iter().next().ok_or(SearchError::NoMatch)?;
        self.cursor = r.idx;
        self.history.push(r.clone());
        Ok(r)
    }

    /// Find an entry whose disassembly contains `substr`.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn find_disasm(&mut self, substr: &str) -> Result<SearchResult, SearchError> {
        let s = SearchForInstruction::by_disasm(substr);
        let results = s.search(self.trace, self.cursor, self.direction)?;
        let r = results.into_iter().next().ok_or(SearchError::NoMatch)?;
        self.cursor = r.idx;
        self.history.push(r.clone());
        Ok(r)
    }

    // ── Batch search ──────────────────────────────────────────────────────────

    /// Collect up to `n` results for `query` starting at the cursor.
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn collect(&self, query: SearchQuery, n: usize) -> Result<Vec<SearchResult>, SearchError> {
        match query {
            SearchQuery::MemWrite { addr, value } => {
                let mut s = SearchForMemWrite::new(addr).max_results(n);
                if let Some(v) = value {
                    s = s.with_value(v);
                }
                match self.direction {
                    SearchDirection::Forward => s.search_forward(self.trace, self.cursor),
                    SearchDirection::Backward => s.search_backward(self.trace, self.cursor),
                }
            }
            SearchQuery::ApiCall { addr, name_substr } => {
                let s = match (addr, name_substr) {
                    (Some(a), _) => {
                        let mut s = SearchForApiCall::by_addr(a);
                        s.max_results = n;
                        s
                    }
                    (None, Some(n_sub)) => {
                        let mut s = SearchForApiCall::by_name(n_sub);
                        s.max_results = n;
                        s
                    }
                    _ => {
                        return Err(SearchError::InvalidQuery(
                            "ApiCall needs addr or name".into(),
                        ));
                    }
                };
                s.search(self.trace, self.cursor, self.direction)
            }
            SearchQuery::Exception { code } => {
                let mut s = code.map_or_else(SearchForException::any, SearchForException::with_code);
                s.max_results = n;
                s.search(self.trace, self.cursor, self.direction)
            }
            SearchQuery::Register { reg_id, value } => {
                let mut s = SearchForValue::in_register(reg_id, value);
                s.max_results = n;
                s.search(self.trace, self.cursor, self.direction)
            }
            SearchQuery::Instruction { pc, disasm, tid } => {
                let s = SearchForInstruction {
                    target_pc: pc,
                    disasm_substr: disasm,
                    thread_filter: tid,
                    max_results: n,
                    step_limit: usize::MAX,
                };
                s.search(self.trace, self.cursor, self.direction)
            }
        }
    }

    /// Count how many times `query` matches in the entire trace.
    #[must_use] 
    pub fn count_all(&self, query: SearchQuery) -> usize {
        let mut ts = TimeTravelSearch::new(self.trace);
        ts.direction = SearchDirection::Forward;
        ts.collect(query, usize::MAX).map_or(0, |results| results.len())
    }

    // ── History ───────────────────────────────────────────────────────────────

    /// Undo the last search (restore cursor to previous position).
    pub fn undo(&mut self) -> Option<usize> {
        // Undo the LAST search: drop its result and go back to where the cursor
        // was before it ran — which is where the PREVIOUS search left it, or
        // the start of the trace if this was the first.
        //
        // Setting the cursor to the popped result's own index put it exactly
        // where the search had LANDED, so undoing a search that moved the
        // cursor from 0 to 3 left it at 3: the call reported success and
        // changed nothing.
        self.history.pop()?;
        let restored = self.history.last().map_or(0, |r| r.idx);
        self.cursor = restored;
        Some(restored)
    }

    /// Clear search history.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExecutionTrace, TraceBuilder};

    fn make_trace() -> ExecutionTrace {
        let mut b = TraceBuilder::new("test.exe");
        // insn at 0x1000
        b.insn(0x1000, 1, "nop");
        // insn at 0x1001
        b.insn(0x1001, 1, "push rbx");
        // call to 0x2000
        b.call(0x1005, 1, 0x2000, 0x100A);
        // insn at 0x2000
        b.insn(0x2000, 1, "mov eax, 0");
        // ret from 0x2000
        b.ret(0x200F, 1, 0x100A);
        // insn at 0x100A
        b.insn(0x100A, 1, "add rsp, 8");
        // memory write at 0x4000
        {
            b.insn(0x100E, 1, "mov [0x4000], rax");
            b.mem_write(0x4000, vec![0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0]);
        }
        // add register snapshot
        b.regs(vec![(0, 0xDEAD_BEEF), (1, 0x4000)]);
        b.build()
    }

    fn make_trace_with_exception() -> ExecutionTrace {
        let mut b = TraceBuilder::new("crash.exe");
        b.insn(0x1000, 1, "nop");
        // exception
        {
            let idx = b.len();
            let mut e = crate::TraceEntry::insn(idx, 0x1010, 1, "fault");
            e.kind = EntryKind::Exception { code: 0xC000_0005 };
            b.entries.push(e);
            b.next_idx += 1;
        }
        b.insn(0x1020, 1, "nop");
        b.build()
    }

    // ── SearchResult ──────────────────────────────────────────────────────────

    #[test]
    fn search_result_new() {
        let r = SearchResult::new(
            5,
            0x1000,
            1,
            "found something",
            SearchDirection::Forward,
            10,
        );
        assert_eq!(r.idx, 5);
        assert_eq!(r.steps_taken, 10);
        assert_eq!(r.direction, SearchDirection::Forward);
    }

    #[test]
    fn search_result_with_meta() {
        let r =
            SearchResult::new(0, 0, 0, "x", SearchDirection::Forward, 1).with_meta("key", "val");
        assert_eq!(r.metadata.get("key"), Some(&"val".to_string()));
    }

    // ── SearchForMemWrite ─────────────────────────────────────────────────────

    #[test]
    fn mem_write_search_forward_finds_write() {
        let trace = make_trace();
        let s = SearchForMemWrite::new(0x4000);
        let results = s.search_forward(&trace, 0).unwrap();
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.description.contains("0x4000")));
    }

    #[test]
    fn mem_write_search_backward_finds_write() {
        let trace = make_trace();
        let s = SearchForMemWrite::new(0x4000);
        let results = s.search_backward(&trace, trace.len() - 1).unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn mem_write_search_with_value_match() {
        let trace = make_trace();
        let val = u64::from_le_bytes([0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0]);
        let s = SearchForMemWrite::new(0x4000).with_value(val);
        let results = s.search_forward(&trace, 0).unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn mem_write_search_no_match_wrong_value() {
        let trace = make_trace();
        let s = SearchForMemWrite::new(0x4000).with_value(0x1234_5678);
        let err = s.search_forward(&trace, 0).unwrap_err();
        assert!(matches!(err, SearchError::NoMatch));
    }

    #[test]
    fn mem_write_search_empty_trace_error() {
        let trace = TraceBuilder::new("empty").build();
        let s = SearchForMemWrite::new(0x1000);
        assert!(matches!(
            s.search_forward(&trace, 0).unwrap_err(),
            SearchError::EmptyTrace
        ));
    }

    // ── SearchForApiCall ──────────────────────────────────────────────────────

    #[test]
    fn api_call_search_by_addr() {
        let trace = make_trace();
        let s = SearchForApiCall::by_addr(0x2000);
        let results = s.search(&trace, 0, SearchDirection::Forward).unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn api_call_search_by_name() {
        let trace = make_trace();
        let s = SearchForApiCall::by_name("call 0x2000");
        let results = s.search(&trace, 0, SearchDirection::Forward).unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn api_call_search_no_match() {
        let trace = make_trace();
        let s = SearchForApiCall::by_addr(0xDEAD_BEEF);
        assert!(matches!(
            s.search(&trace, 0, SearchDirection::Forward).unwrap_err(),
            SearchError::NoMatch
        ));
    }

    #[test]
    fn api_call_search_backward() {
        let trace = make_trace();
        let s = SearchForApiCall::by_addr(0x2000);
        let results = s
            .search(&trace, trace.len() - 1, SearchDirection::Backward)
            .unwrap();
        assert!(!results.is_empty());
    }

    // ── SearchForException ────────────────────────────────────────────────────

    #[test]
    fn exception_search_finds_any() {
        let trace = make_trace_with_exception();
        let s = SearchForException::any();
        let results = s.search(&trace, 0, SearchDirection::Forward).unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn exception_search_by_code() {
        let trace = make_trace_with_exception();
        let s = SearchForException::with_code(0xC000_0005);
        let results = s.search(&trace, 0, SearchDirection::Forward).unwrap();
        assert!(!results.is_empty());
        assert!(
            results[0]
                .metadata
                .get("code")
                .is_some_and(|s| s.contains("0xc0000005"))
        );
    }

    #[test]
    fn exception_search_wrong_code_no_match() {
        let trace = make_trace_with_exception();
        let s = SearchForException::with_code(0x1234);
        assert!(matches!(
            s.search(&trace, 0, SearchDirection::Forward).unwrap_err(),
            SearchError::NoMatch
        ));
    }

    #[test]
    fn exception_search_no_exception_trace() {
        let trace = make_trace();
        let s = SearchForException::any();
        assert!(matches!(
            s.search(&trace, 0, SearchDirection::Forward).unwrap_err(),
            SearchError::NoMatch
        ));
    }

    // ── SearchForValue ────────────────────────────────────────────────────────

    #[test]
    fn value_search_finds_register() {
        let trace = make_trace();
        let s = SearchForValue::in_register(0, 0xDEAD_BEEF);
        let results = s.search(&trace, 0, SearchDirection::Forward).unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn value_search_no_match() {
        let trace = make_trace();
        let s = SearchForValue::in_register(0, 0x1234_5678_9ABC);
        assert!(matches!(
            s.search(&trace, 0, SearchDirection::Forward).unwrap_err(),
            SearchError::NoMatch
        ));
    }

    #[test]
    fn value_search_backward() {
        let trace = make_trace();
        let s = SearchForValue::in_register(0, 0xDEAD_BEEF);
        let results = s
            .search(&trace, trace.len() - 1, SearchDirection::Backward)
            .unwrap();
        assert!(!results.is_empty());
    }

    // ── SearchForInstruction ──────────────────────────────────────────────────

    #[test]
    fn insn_search_by_pc() {
        let trace = make_trace();
        let s = SearchForInstruction::by_pc(0x1000);
        let results = s.search(&trace, 0, SearchDirection::Forward).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].pc, 0x1000);
    }

    #[test]
    fn insn_search_by_disasm() {
        let trace = make_trace();
        let s = SearchForInstruction::by_disasm("push");
        let results = s.search(&trace, 0, SearchDirection::Forward).unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn insn_search_thread_filter() {
        let trace = make_trace();
        let s = SearchForInstruction::by_pc(0x1000).for_thread(99);
        // thread 99 doesn't exist
        assert!(matches!(
            s.search(&trace, 0, SearchDirection::Forward).unwrap_err(),
            SearchError::NoMatch
        ));
    }

    #[test]
    fn insn_search_backward() {
        let trace = make_trace();
        let s = SearchForInstruction::by_pc(0x1000);
        let results = s
            .search(&trace, trace.len() - 1, SearchDirection::Backward)
            .unwrap();
        assert!(!results.is_empty());
    }

    // ── TimeTravelSearch ──────────────────────────────────────────────────────

    #[test]
    fn tts_find_pc() {
        let trace = make_trace();
        let mut tts = TimeTravelSearch::new(&trace);
        let r = tts.find_pc(0x1000).unwrap();
        assert_eq!(r.pc, 0x1000);
        assert_eq!(tts.cursor, r.idx);
    }

    #[test]
    fn tts_find_call() {
        let trace = make_trace();
        let mut tts = TimeTravelSearch::new(&trace);
        let r = tts.find_call(0x2000).unwrap();
        assert!(r.description.contains("call"));
    }

    #[test]
    fn tts_find_mem_write() {
        let trace = make_trace();
        let mut tts = TimeTravelSearch::new(&trace);
        let r = tts.find_mem_write(0x4000).unwrap();
        assert_eq!(tts.cursor, r.idx);
    }

    #[test]
    fn tts_find_exception() {
        let trace = make_trace_with_exception();
        let mut tts = TimeTravelSearch::new(&trace);
        let r = tts.find_exception().unwrap();
        assert!(r.description.contains("exception"));
    }

    #[test]
    fn tts_find_reg_value() {
        let trace = make_trace();
        let mut tts = TimeTravelSearch::new(&trace);
        let r = tts.find_reg_value(0, 0xDEAD_BEEF).unwrap();
        assert!(r.description.contains("reg[0]"));
    }

    #[test]
    fn tts_direction_backward() {
        let trace = make_trace();
        let mut tts = TimeTravelSearch::new(&trace);
        tts.direction = SearchDirection::Backward;
        tts.fast_forward();
        let r = tts.find_pc(0x1000).unwrap();
        assert_eq!(r.direction, SearchDirection::Backward);
    }

    #[test]
    fn tts_history_and_undo() {
        let trace = make_trace();
        let mut tts = TimeTravelSearch::new(&trace);
        tts.find_pc(0x1000).unwrap();
        tts.find_disasm("push").unwrap();
        assert_eq!(tts.history.len(), 2);
        tts.undo();
        assert_eq!(tts.history.len(), 1);
    }

    #[test]
    fn tts_collect() {
        let trace = make_trace();
        let tts = TimeTravelSearch::new(&trace);
        let results = tts
            .collect(
                SearchQuery::Instruction {
                    pc: None,
                    disasm: Some("nop".into()),
                    tid: None,
                },
                10,
            )
            .unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn tts_count_all() {
        let trace = make_trace();
        let tts = TimeTravelSearch::new(&trace);
        let count = tts.count_all(SearchQuery::Instruction {
            pc: Some(0x1000),
            disasm: None,
            tid: None,
        });
        assert_eq!(count, 1);
    }

    #[test]
    fn tts_seek_and_rewind() {
        let trace = make_trace();
        let mut tts = TimeTravelSearch::new(&trace);
        tts.seek(5);
        assert_eq!(tts.cursor, 5);
        tts.rewind();
        assert_eq!(tts.cursor, 0);
    }
}
