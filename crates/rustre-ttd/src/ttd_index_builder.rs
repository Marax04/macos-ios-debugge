//! `ttd_index_builder` — Build a multi-layered index over a TTD trace.
//!
//! Provides:
//! * [`TtdIndexBuilder`]    — main builder that assembles all sub-indexes
//! * [`PositionIndex`]      — fast position → event-index lookup
//! * [`CallIndex`]          — call/return graph index
//! * [`MemoryWriteIndex`]   — address → write records
//! * [`ExceptionIndex`]     — exception events indexed by code and thread
//! * [`ApiCallIndex`]       — API calls extracted from syscall events

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{EventKind, TraceEvent, TracePosition, TtdTrace};

// ─── errors ──────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum IndexError {
    EmptyTrace,
    DuplicatePosition(TracePosition),
    InvalidRange(String),
    Custom(String),
}

impl fmt::Display for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyTrace => write!(f, "trace is empty: no events"),
            Self::DuplicatePosition(p) => write!(f, "duplicate position: {p}"),
            Self::InvalidRange(s) => write!(f, "invalid range: {s}"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for IndexError {}

// ─── PositionIndex ───────────────────────────────────────────────────────────

/// Maps every `TracePosition` to the index of its event in the flat event list.
#[derive(Debug, Clone, Default)]
pub struct PositionIndex {
    pub map: BTreeMap<TracePosition, usize>,
}

impl PositionIndex {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a `PositionIndex` from a slice of trace events.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError::DuplicatePosition`] if two events share the same
    /// [`TracePosition`].
    pub fn build(events: &[TraceEvent]) -> Result<Self, IndexError> {
        let mut index = Self::new();
        for (i, ev) in events.iter().enumerate() {
            if index.map.contains_key(&ev.position) {
                return Err(IndexError::DuplicatePosition(ev.position));
            }
            index.map.insert(ev.position, i);
        }
        Ok(index)
    }

    #[must_use] 
    pub fn get(&self, pos: TracePosition) -> Option<usize> {
        self.map.get(&pos).copied()
    }

    /// Return all positions in [from, to].
    #[must_use] 
    pub fn range_indices(&self, from: TracePosition, to: TracePosition) -> Vec<usize> {
        self.map.range(from..=to).map(|(_, i)| *i).collect()
    }

    #[must_use] 
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    #[must_use] 
    pub fn first_position(&self) -> Option<TracePosition> {
        self.map.keys().next().copied()
    }

    #[must_use] 
    pub fn last_position(&self) -> Option<TracePosition> {
        self.map.keys().next_back().copied()
    }
}

impl fmt::Display for PositionIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PositionIndex {{ entries={} }}", self.map.len())
    }
}

// ─── CallRecord ──────────────────────────────────────────────────────────────

/// A single call/return pair from the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallRecord {
    pub caller: u64,
    pub callee: u64,
    pub call_position: TracePosition,
    pub return_position: Option<TracePosition>,
    pub thread_id: u32,
    pub depth: usize,
}

impl CallRecord {
    #[must_use] 
    pub const fn is_resolved(&self) -> bool {
        self.return_position.is_some()
    }
}

impl fmt::Display for CallRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Call {:#x}->{:#x} tid={} depth={}",
            self.caller, self.callee, self.thread_id, self.depth
        )
    }
}

// ─── CallIndex ───────────────────────────────────────────────────────────────

/// Indexes all call/return pairs by callee address and thread.
#[derive(Debug, Clone, Default)]
pub struct CallIndex {
    /// callee address → list of call records
    pub by_callee: HashMap<u64, Vec<CallRecord>>,
    /// caller address → list of call records
    pub by_caller: HashMap<u64, Vec<CallRecord>>,
    /// flat ordered list of all calls
    pub all_calls: Vec<CallRecord>,
    pub max_depth: usize,
}

impl CallIndex {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn build(events: &[TraceEvent]) -> Self {
        let mut index = Self::new();
        // Per-thread stacks of (call_record_idx, depth)
        let mut stacks: HashMap<u32, Vec<(usize, usize)>> = HashMap::new();
        let mut depths: HashMap<u32, usize> = HashMap::new();

        for ev in events {
            match &ev.kind {
                EventKind::Call { from, to } => {
                    let tid = ev.thread_id;
                    let depth = *depths.entry(tid).or_insert(0);
                    if depth > index.max_depth {
                        index.max_depth = depth;
                    }
                    let rec = CallRecord {
                        caller: *from,
                        callee: *to,
                        call_position: ev.position,
                        return_position: None,
                        thread_id: tid,
                        depth,
                    };
                    let idx = index.all_calls.len();
                    index.all_calls.push(rec);
                    stacks.entry(tid).or_default().push((idx, depth));
                    *depths.entry(tid).or_insert(0) += 1;
                }
                EventKind::Return { to, .. } => {
                    let tid = ev.thread_id;
                    if let Some(stack) = stacks.get_mut(&tid)
                        && let Some((call_idx, _)) = stack.pop() {
                            index.all_calls[call_idx].return_position = Some(ev.position);
                        }
                    let d = depths.entry(ev.thread_id).or_insert(0);
                    *d = d.saturating_sub(1);
                    let _ = to;
                }
                _ => {}
            }
        }

        // Build lookup maps
        for rec in &index.all_calls {
            index
                .by_callee
                .entry(rec.callee)
                .or_default()
                .push(rec.clone());
            index
                .by_caller
                .entry(rec.caller)
                .or_default()
                .push(rec.clone());
        }

        index
    }

    pub fn calls_to(&self, callee: u64) -> &[CallRecord] {
        self.by_callee
            .get(&callee)
            .map_or(&[], Vec::as_slice)
    }

    pub fn calls_from(&self, caller: u64) -> &[CallRecord] {
        self.by_caller
            .get(&caller)
            .map_or(&[], Vec::as_slice)
    }

    #[must_use] 
    pub fn unique_callees(&self) -> HashSet<u64> {
        self.by_callee.keys().copied().collect()
    }

    #[must_use] 
    pub const fn total_calls(&self) -> usize {
        self.all_calls.len()
    }

    #[must_use] 
    pub fn resolved_calls(&self) -> usize {
        self.all_calls.iter().filter(|r| r.is_resolved()).count()
    }
}

impl fmt::Display for CallIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CallIndex {{ calls={}, unique_callees={}, max_depth={} }}",
            self.all_calls.len(),
            self.by_callee.len(),
            self.max_depth
        )
    }
}

// ─── MemoryWriteRecord ───────────────────────────────────────────────────────

/// A single memory write captured from the trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryWriteRecord {
    pub address: u64,
    pub data: Vec<u8>,
    pub position: TracePosition,
    pub thread_id: u32,
}

impl MemoryWriteRecord {
    #[must_use] 
    pub const fn size(&self) -> usize {
        self.data.len()
    }
}

impl fmt::Display for MemoryWriteRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemWrite @ {:#x} len={} pos={}",
            self.address,
            self.data.len(),
            self.position
        )
    }
}

// ─── MemoryWriteIndex ────────────────────────────────────────────────────────

/// Indexes memory write events by address (page-granular) and exact address.
#[derive(Debug, Clone, Default)]
pub struct MemoryWriteIndex {
    /// exact address → write records
    pub by_address: BTreeMap<u64, Vec<MemoryWriteRecord>>,
    /// page (4 KiB) → write records
    pub by_page: BTreeMap<u64, Vec<MemoryWriteRecord>>,
    pub total_writes: u64,
    pub total_bytes_written: u64,
}

impl MemoryWriteIndex {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    const PAGE_SIZE: u64 = 4096;

    const fn page_of(addr: u64) -> u64 {
        addr & !(Self::PAGE_SIZE - 1)
    }

    #[must_use] 
    pub fn build(events: &[TraceEvent]) -> Self {
        let mut index = Self::new();
        for ev in events {
            if let EventKind::MemWrite { addr, data } = &ev.kind {
                let rec = MemoryWriteRecord {
                    address: *addr,
                    data: data.clone(),
                    position: ev.position,
                    thread_id: ev.thread_id,
                };
                index.total_writes += 1;
                index.total_bytes_written += data.len() as u64;
                index.by_address.entry(*addr).or_default().push(rec.clone());
                let page = Self::page_of(*addr);
                index.by_page.entry(page).or_default().push(rec);
            }
        }
        index
    }

    pub fn writes_to(&self, addr: u64) -> &[MemoryWriteRecord] {
        self.by_address.get(&addr).map_or(&[], Vec::as_slice)
    }

    pub fn writes_to_page(&self, addr: u64) -> &[MemoryWriteRecord] {
        let page = Self::page_of(addr);
        self.by_page.get(&page).map_or(&[], Vec::as_slice)
    }

    #[must_use] 
    pub fn addresses_written(&self) -> Vec<u64> {
        self.by_address.keys().copied().collect()
    }

    #[must_use] 
    pub fn pages_written(&self) -> Vec<u64> {
        self.by_page.keys().copied().collect()
    }

    #[must_use] 
    pub fn writes_in_range(&self, start: u64, end: u64) -> Vec<&MemoryWriteRecord> {
        self.by_address
            .range(start..end)
            .flat_map(|(_, v)| v.iter())
            .collect()
    }
}

impl fmt::Display for MemoryWriteIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MemoryWriteIndex {{ writes={}, addrs={}, pages={} }}",
            self.total_writes,
            self.by_address.len(),
            self.by_page.len()
        )
    }
}

// ─── ExceptionRecord ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExceptionRecord {
    pub code: u32,
    pub address: u64,
    pub position: TracePosition,
    pub thread_id: u32,
}

impl fmt::Display for ExceptionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Exception {:#010x} @ {:#x} pos={} tid={}",
            self.code, self.address, self.position, self.thread_id
        )
    }
}

// ─── ExceptionIndex ──────────────────────────────────────────────────────────

/// Indexes exception events by code and by thread.
#[derive(Debug, Clone, Default)]
pub struct ExceptionIndex {
    /// exception code → records
    pub by_code: HashMap<u32, Vec<ExceptionRecord>>,
    /// thread id → records
    pub by_thread: HashMap<u32, Vec<ExceptionRecord>>,
    pub all_exceptions: Vec<ExceptionRecord>,
}

impl ExceptionIndex {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn build(events: &[TraceEvent]) -> Self {
        let mut index = Self::new();
        for ev in events {
            if let EventKind::Exception {
                code,
                addr: address,
            } = &ev.kind
            {
                let rec = ExceptionRecord {
                    code: *code,
                    address: *address,
                    position: ev.position,
                    thread_id: ev.thread_id,
                };
                index.by_code.entry(*code).or_default().push(rec.clone());
                index
                    .by_thread
                    .entry(ev.thread_id)
                    .or_default()
                    .push(rec.clone());
                index.all_exceptions.push(rec);
            }
        }
        index
    }

    pub fn exceptions_of_code(&self, code: u32) -> &[ExceptionRecord] {
        self.by_code.get(&code).map_or(&[], Vec::as_slice)
    }

    pub fn exceptions_on_thread(&self, tid: u32) -> &[ExceptionRecord] {
        self.by_thread.get(&tid).map_or(&[], Vec::as_slice)
    }

    #[must_use] 
    pub fn unique_codes(&self) -> HashSet<u32> {
        self.by_code.keys().copied().collect()
    }

    #[must_use] 
    pub fn has_access_violations(&self) -> bool {
        self.by_code.contains_key(&0xC000_0005)
    }

    #[must_use] 
    pub const fn total_exceptions(&self) -> usize {
        self.all_exceptions.len()
    }
}

impl fmt::Display for ExceptionIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExceptionIndex {{ total={}, unique_codes={} }}",
            self.all_exceptions.len(),
            self.by_code.len()
        )
    }
}

// ─── ApiCallRecord ───────────────────────────────────────────────────────────

/// An API-level call inferred from a syscall event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCallRecord {
    pub syscall_nr: u32,
    pub args: Vec<u64>,
    pub return_value: Option<u64>,
    pub enter_position: TracePosition,
    pub exit_position: Option<TracePosition>,
    pub thread_id: u32,
}

impl ApiCallRecord {
    #[must_use] 
    pub const fn is_complete(&self) -> bool {
        self.exit_position.is_some()
    }
}

impl fmt::Display for ApiCallRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ApiCall nr={} tid={} ret={:?}",
            self.syscall_nr, self.thread_id, self.return_value
        )
    }
}

// ─── ApiCallIndex ────────────────────────────────────────────────────────────

/// Indexes API calls (via syscalls) by number and thread.
#[derive(Debug, Clone, Default)]
pub struct ApiCallIndex {
    /// syscall nr → records
    pub by_nr: HashMap<u32, Vec<ApiCallRecord>>,
    /// thread id → records
    pub by_thread: HashMap<u32, Vec<ApiCallRecord>>,
    pub all_calls: Vec<ApiCallRecord>,
}

impl ApiCallIndex {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use] 
    pub fn build(events: &[TraceEvent]) -> Self {
        let mut index = Self::new();
        // pending enter keyed by tid
        let mut pending: HashMap<u32, usize> = HashMap::new();

        for ev in events {
            match &ev.kind {
                EventKind::SyscallEnter { nr, args } => {
                    let rec = ApiCallRecord {
                        syscall_nr: *nr,
                        args: args.to_vec(),
                        return_value: None,
                        enter_position: ev.position,
                        exit_position: None,
                        thread_id: ev.thread_id,
                    };
                    let idx = index.all_calls.len();
                    index.all_calls.push(rec);
                    pending.insert(ev.thread_id, idx);
                }
                EventKind::SyscallExit { ret, .. } => {
                    if let Some(&idx) = pending.get(&ev.thread_id) {
                        index.all_calls[idx].return_value = Some(*ret);
                        index.all_calls[idx].exit_position = Some(ev.position);
                        pending.remove(&ev.thread_id);
                    }
                }
                _ => {}
            }
        }

        // Build lookup maps
        for rec in &index.all_calls {
            index
                .by_nr
                .entry(rec.syscall_nr)
                .or_default()
                .push(rec.clone());
            index
                .by_thread
                .entry(rec.thread_id)
                .or_default()
                .push(rec.clone());
        }

        index
    }

    pub fn calls_of_nr(&self, nr: u32) -> &[ApiCallRecord] {
        self.by_nr.get(&nr).map_or(&[], Vec::as_slice)
    }

    pub fn calls_on_thread(&self, tid: u32) -> &[ApiCallRecord] {
        self.by_thread.get(&tid).map_or(&[], Vec::as_slice)
    }

    #[must_use] 
    pub fn unique_syscalls(&self) -> HashSet<u32> {
        self.by_nr.keys().copied().collect()
    }

    #[must_use] 
    pub const fn total_calls(&self) -> usize {
        self.all_calls.len()
    }

    #[must_use] 
    pub fn completed_calls(&self) -> usize {
        self.all_calls.iter().filter(|c| c.is_complete()).count()
    }
}

impl fmt::Display for ApiCallIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ApiCallIndex {{ total={}, unique_nrs={} }}",
            self.all_calls.len(),
            self.by_nr.len()
        )
    }
}

// ─── TtdIndex ────────────────────────────────────────────────────────────────

/// The assembled multi-index over a TTD trace.
pub struct TtdIndex {
    pub positions: PositionIndex,
    pub calls: CallIndex,
    pub memory_writes: MemoryWriteIndex,
    pub exceptions: ExceptionIndex,
    pub api_calls: ApiCallIndex,
    pub event_count: usize,
}

impl TtdIndex {
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.event_count == 0
    }
}

impl fmt::Display for TtdIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TtdIndex {{ events={}, {} {} {} {} }}",
            self.event_count, self.positions, self.calls, self.memory_writes, self.exceptions,
        )
    }
}

// ─── TtdIndexBuilder ─────────────────────────────────────────────────────────

/// Builds a full [`TtdIndex`] from a [`TtdTrace`].
pub struct TtdIndexBuilder {
    pub allow_duplicate_positions: bool,
}

impl TtdIndexBuilder {
    #[must_use] 
    pub const fn new() -> Self {
        Self {
            allow_duplicate_positions: false,
        }
    }

    #[must_use] 
    pub const fn allow_duplicate_positions(mut self) -> Self {
        self.allow_duplicate_positions = true;
        self
    }

    /// Build a [`TtdIndex`] from `trace` according to the builder's options.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError::EmptyTrace`] if `trace` has no events, or
    /// [`IndexError::DuplicatePosition`] if duplicate positions are not
    /// allowed and the trace contains one.
    pub fn build(&self, trace: &TtdTrace) -> Result<TtdIndex, IndexError> {
        let events = trace.all_events();
        if events.is_empty() {
            return Err(IndexError::EmptyTrace);
        }

        let positions = if self.allow_duplicate_positions {
            let mut idx = PositionIndex::new();
            for (i, ev) in events.iter().enumerate() {
                idx.map.entry(ev.position).or_insert(i);
            }
            idx
        } else {
            PositionIndex::build(&events)?
        };

        Ok(TtdIndex {
            positions,
            calls: CallIndex::build(&events),
            memory_writes: MemoryWriteIndex::build(&events),
            exceptions: ExceptionIndex::build(&events),
            api_calls: ApiCallIndex::build(&events),
            event_count: events.len(),
        })
    }
}

impl Default for TtdIndexBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventKind, TraceEvent, TraceMetadata, TracePosition, TtdTrace};

    fn pos(seq: u64) -> TracePosition {
        TracePosition {
            sequence: seq,
            step: 0,
        }
    }

    fn ev_call(from: u64, to: u64, seq: u64) -> TraceEvent {
        TraceEvent {
            position: pos(seq),
            thread_id: 1,
            kind: EventKind::Call { from, to },
        }
    }

    fn ev_ret(from: u64, to: u64, seq: u64) -> TraceEvent {
        TraceEvent {
            position: pos(seq),
            thread_id: 1,
            kind: EventKind::Return { from, to },
        }
    }

    fn ev_write(addr: u64, data: Vec<u8>, seq: u64) -> TraceEvent {
        TraceEvent {
            position: pos(seq),
            thread_id: 1,
            kind: EventKind::MemWrite { addr, data },
        }
    }

    fn ev_exc(code: u32, address: u64, seq: u64) -> TraceEvent {
        TraceEvent {
            position: pos(seq),
            thread_id: 1,
            kind: EventKind::Exception { code, addr: address },
        }
    }

    fn ev_syscall_enter(nr: u32, seq: u64) -> TraceEvent {
        TraceEvent {
            position: pos(seq),
            thread_id: 1,
            kind: EventKind::SyscallEnter {
                nr,
                args: [1, 2, 3, 4, 5, 6],
            },
        }
    }

    fn ev_syscall_exit(ret: u64, seq: u64) -> TraceEvent {
        TraceEvent {
            position: pos(seq),
            thread_id: 1,
            kind: EventKind::SyscallExit { nr: 0, ret },
        }
    }

    fn build_trace(events: Vec<TraceEvent>) -> TtdTrace {
        let last = events
            .last().map_or_else(TracePosition::start, |e| e.position);
        let mut t = TtdTrace::new(TraceMetadata {
            pid: 1,
            process_name: "test".into(),
            start_position: TracePosition::start(),
            end_position: last,
            thread_ids: vec![1],
            ..Default::default()
        });
        for ev in events {
            t.push_event(ev);
        }
        t
    }

    // ── PositionIndex ────────────────────────────────────────────────────────

    #[test]
    fn test_position_index_build() {
        let events = vec![ev_call(0x1000, 0x2000, 1), ev_ret(0x2000, 0x1004, 2)];
        let idx = PositionIndex::build(&events).unwrap();
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.get(pos(1)), Some(0));
        assert_eq!(idx.get(pos(2)), Some(1));
    }

    #[test]
    fn test_position_index_range() {
        let events: Vec<TraceEvent> = (1..=5).map(|i| ev_call(0, 0, i)).collect();
        let idx = PositionIndex::build(&events).unwrap();
        let range = idx.range_indices(pos(2), pos(4));
        assert_eq!(range, vec![1, 2, 3]);
    }

    #[test]
    fn test_position_index_first_last() {
        let events = vec![ev_call(0, 0, 10), ev_call(0, 0, 20)];
        let idx = PositionIndex::build(&events).unwrap();
        assert_eq!(idx.first_position(), Some(pos(10)));
        assert_eq!(idx.last_position(), Some(pos(20)));
    }

    #[test]
    fn test_position_index_duplicate_error() {
        let events = vec![ev_call(0, 0, 1), ev_call(0, 0, 1)];
        assert!(matches!(
            PositionIndex::build(&events),
            Err(IndexError::DuplicatePosition(_))
        ));
    }

    #[test]
    fn test_position_index_empty() {
        let idx = PositionIndex::build(&[]).unwrap();
        assert!(idx.is_empty());
    }

    // ── CallIndex ────────────────────────────────────────────────────────────

    #[test]
    fn test_call_index_basic() {
        let events = vec![ev_call(0x1000, 0x2000, 1), ev_ret(0x2000, 0x1004, 2)];
        let idx = CallIndex::build(&events);
        assert_eq!(idx.total_calls(), 1);
        assert_eq!(idx.resolved_calls(), 1);
    }

    #[test]
    fn test_call_index_calls_to() {
        let events = vec![ev_call(0x1000, 0x2000, 1), ev_call(0x3000, 0x2000, 2)];
        let idx = CallIndex::build(&events);
        assert_eq!(idx.calls_to(0x2000).len(), 2);
    }

    #[test]
    fn test_call_index_unique_callees() {
        let events = vec![
            ev_call(0, 0x2000, 1),
            ev_call(0, 0x3000, 2),
            ev_call(0, 0x2000, 3),
        ];
        let idx = CallIndex::build(&events);
        assert_eq!(idx.unique_callees().len(), 2);
    }

    #[test]
    fn test_call_index_max_depth() {
        let events = vec![
            ev_call(0, 0x1000, 1),
            ev_call(0, 0x2000, 2),
            ev_call(0, 0x3000, 3),
        ];
        let idx = CallIndex::build(&events);
        assert!(idx.max_depth >= 2);
    }

    // ── MemoryWriteIndex ─────────────────────────────────────────────────────

    #[test]
    fn test_mem_write_index_build() {
        let events = vec![
            ev_write(0x1000, vec![1, 2], 1),
            ev_write(0x1000, vec![3, 4], 2),
        ];
        let idx = MemoryWriteIndex::build(&events);
        assert_eq!(idx.total_writes, 2);
        assert_eq!(idx.writes_to(0x1000).len(), 2);
    }

    #[test]
    fn test_mem_write_index_range() {
        let events = vec![
            ev_write(0x1000, vec![1], 1),
            ev_write(0x2000, vec![2], 2),
            ev_write(0x5000, vec![3], 3),
        ];
        let idx = MemoryWriteIndex::build(&events);
        let r = idx.writes_in_range(0x0000, 0x3000);
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn test_mem_write_index_pages() {
        let events = vec![ev_write(0x1000, vec![1], 1), ev_write(0x1500, vec![2], 2)];
        let idx = MemoryWriteIndex::build(&events);
        // Both in page 0x1000
        assert_eq!(idx.writes_to_page(0x1000).len(), 2);
    }

    #[test]
    fn test_mem_write_index_total_bytes() {
        let events = vec![
            ev_write(0x1000, vec![0u8; 8], 1),
            ev_write(0x2000, vec![0u8; 16], 2),
        ];
        let idx = MemoryWriteIndex::build(&events);
        assert_eq!(idx.total_bytes_written, 24);
    }

    // ── ExceptionIndex ───────────────────────────────────────────────────────

    #[test]
    fn test_exception_index_build() {
        let events = vec![
            ev_exc(0xC000_0005, 0x1000, 1),
            ev_exc(0xC000_0005, 0x2000, 2),
            ev_exc(0xC000_001D, 0x3000, 3),
        ];
        let idx = ExceptionIndex::build(&events);
        assert_eq!(idx.total_exceptions(), 3);
        assert_eq!(idx.exceptions_of_code(0xC000_0005).len(), 2);
    }

    #[test]
    fn test_exception_index_has_av() {
        let events = vec![ev_exc(0xC000_0005, 0x1000, 1)];
        let idx = ExceptionIndex::build(&events);
        assert!(idx.has_access_violations());
    }

    #[test]
    fn test_exception_index_by_thread() {
        let mut events = vec![ev_exc(0xC000_0005, 0x1000, 1)];
        events[0].thread_id = 2;
        let idx = ExceptionIndex::build(&events);
        assert_eq!(idx.exceptions_on_thread(2).len(), 1);
        assert_eq!(idx.exceptions_on_thread(1).len(), 0);
    }

    #[test]
    fn test_exception_index_unique_codes() {
        let events = vec![ev_exc(0xC000_0005, 0x1000, 1), ev_exc(0xC000_001D, 0x2000, 2)];
        let idx = ExceptionIndex::build(&events);
        assert_eq!(idx.unique_codes().len(), 2);
    }

    // ── ApiCallIndex ─────────────────────────────────────────────────────────

    #[test]
    fn test_api_call_index_build() {
        let events = vec![ev_syscall_enter(1, 1), ev_syscall_exit(0, 2)];
        let idx = ApiCallIndex::build(&events);
        assert_eq!(idx.total_calls(), 1);
        assert_eq!(idx.completed_calls(), 1);
    }

    #[test]
    fn test_api_call_index_by_nr() {
        let events = vec![
            ev_syscall_enter(1, 1),
            ev_syscall_exit(0, 2),
            ev_syscall_enter(1, 3),
            ev_syscall_exit(0, 4),
        ];
        let idx = ApiCallIndex::build(&events);
        assert_eq!(idx.calls_of_nr(1).len(), 2);
    }

    #[test]
    fn test_api_call_index_incomplete() {
        let events = vec![ev_syscall_enter(1, 1)]; // no exit
        let idx = ApiCallIndex::build(&events);
        assert_eq!(idx.total_calls(), 1);
        assert_eq!(idx.completed_calls(), 0);
    }

    #[test]
    fn test_api_call_index_return_value() {
        let events = vec![ev_syscall_enter(5, 1), ev_syscall_exit(0xDEAD_BEEF, 2)];
        let idx = ApiCallIndex::build(&events);
        assert_eq!(idx.all_calls[0].return_value, Some(0xDEAD_BEEF));
    }

    // ── TtdIndexBuilder ──────────────────────────────────────────────────────

    #[test]
    fn test_builder_empty_trace_error() {
        let t = build_trace(vec![]);
        let err = TtdIndexBuilder::new().build(&t);
        assert!(matches!(err, Err(IndexError::EmptyTrace)));
    }

    #[test]
    fn test_builder_full_index() {
        let trace = build_trace(vec![
            ev_call(0x1000, 0x2000, 1),
            ev_write(0x5000, vec![0xAA], 2),
            ev_exc(0xC000_0005, 0x6000, 3),
            ev_syscall_enter(1, 4),
            ev_syscall_exit(0, 5),
        ]);
        let idx = TtdIndexBuilder::new().build(&trace).unwrap();
        assert_eq!(idx.event_count, 5);
        assert_eq!(idx.calls.total_calls(), 1);
        assert_eq!(idx.memory_writes.total_writes, 1);
        assert_eq!(idx.exceptions.total_exceptions(), 1);
        assert_eq!(idx.api_calls.total_calls(), 1);
    }

    #[test]
    fn test_builder_allow_duplicate_positions() {
        let events = vec![ev_call(0, 0, 1), ev_call(0, 0, 1)];
        let t = build_trace(events);
        // should succeed with allow_duplicate_positions
        assert!(
            TtdIndexBuilder::new()
                .allow_duplicate_positions()
                .build(&t)
                .is_ok()
        );
        // should fail without it (duplicate position error)
        assert!(TtdIndexBuilder::new().build(&t).is_err());
    }

    #[test]
    fn test_position_index_get_missing() {
        let events = vec![ev_call(0, 0, 1)];
        let idx = PositionIndex::build(&events).unwrap();
        assert_eq!(idx.get(pos(999)), None);
    }

    #[test]
    fn test_call_index_unresolved() {
        let events = vec![ev_call(0, 0x1000, 1)]; // no return
        let idx = CallIndex::build(&events);
        assert_eq!(idx.resolved_calls(), 0);
        assert_eq!(idx.total_calls(), 1);
    }

    #[test]
    fn test_position_index_range_empty() {
        let events = vec![ev_call(0, 0, 1), ev_call(0, 0, 10)];
        let idx = PositionIndex::build(&events).unwrap();
        let r = idx.range_indices(pos(5), pos(9));
        assert!(r.is_empty());
    }

    #[test]
    fn test_call_index_calls_from() {
        let events = vec![ev_call(0x1000, 0x2000, 1), ev_call(0x1000, 0x3000, 2)];
        let idx = CallIndex::build(&events);
        assert_eq!(idx.calls_from(0x1000).len(), 2);
    }

    #[test]
    fn test_call_index_empty() {
        let events = vec![ev_write(0x1000, vec![1], 1)];
        let idx = CallIndex::build(&events);
        assert_eq!(idx.total_calls(), 0);
    }

    #[test]
    fn test_api_call_index_by_thread() {
        let mut events = vec![ev_syscall_enter(7, 1), ev_syscall_exit(0, 2)];
        events[0].thread_id = 5;
        events[1].thread_id = 5;
        let idx = ApiCallIndex::build(&events);
        assert_eq!(idx.calls_on_thread(5).len(), 1);
        assert_eq!(idx.calls_on_thread(1).len(), 0);
    }

    #[test]
    fn test_api_call_index_unique_syscalls() {
        let events = vec![
            ev_syscall_enter(1, 1),
            ev_syscall_exit(0, 2),
            ev_syscall_enter(2, 3),
            ev_syscall_exit(0, 4),
            ev_syscall_enter(1, 5),
            ev_syscall_exit(0, 6),
        ];
        let idx = ApiCallIndex::build(&events);
        assert_eq!(idx.unique_syscalls().len(), 2);
    }

    #[test]
    fn test_exception_index_no_av() {
        let events = vec![ev_exc(0xC000_001D, 0x1000, 1)];
        let idx = ExceptionIndex::build(&events);
        assert!(!idx.has_access_violations());
    }

    #[test]
    fn test_mem_write_record_size() {
        let rec = MemoryWriteRecord {
            address: 0x1000,
            data: vec![1, 2, 3, 4],
            position: pos(1),
            thread_id: 1,
        };
        assert_eq!(rec.size(), 4);
    }

    #[test]
    fn test_call_record_is_resolved() {
        let mut rec = CallRecord {
            caller: 0,
            callee: 0x1000,
            call_position: pos(1),
            return_position: None,
            thread_id: 1,
            depth: 0,
        };
        assert!(!rec.is_resolved());
        rec.return_position = Some(pos(5));
        assert!(rec.is_resolved());
    }

    #[test]
    fn test_ttd_index_is_empty() {
        // An empty trace gives an error, so we just check the is_empty method
        // by constructing a minimal index
        let trace = build_trace(vec![ev_call(0, 0, 1)]);
        let idx = TtdIndexBuilder::new().build(&trace).unwrap();
        assert!(!idx.is_empty());
    }

    #[test]
    fn test_position_index_display() {
        let events = vec![ev_call(0, 0, 1)];
        let idx = PositionIndex::build(&events).unwrap();
        let s = format!("{idx}");
        assert!(s.contains("entries=1"));
    }

    #[test]
    fn test_call_index_display() {
        let events = vec![ev_call(0, 0x1000, 1)];
        let idx = CallIndex::build(&events);
        let s = format!("{idx}");
        assert!(s.contains("calls=1"));
    }

    #[test]
    fn test_exception_index_display() {
        let events = vec![ev_exc(0xC000_0005, 0x1000, 1)];
        let idx = ExceptionIndex::build(&events);
        let s = format!("{idx}");
        assert!(s.contains("total=1"));
    }

    #[test]
    fn test_memory_write_index_display() {
        let events = vec![ev_write(0x1000, vec![1, 2], 1)];
        let idx = MemoryWriteIndex::build(&events);
        let s = format!("{idx}");
        assert!(s.contains("writes=1"));
    }

    #[test]
    fn test_api_call_index_display() {
        let events = vec![ev_syscall_enter(1, 1), ev_syscall_exit(0, 2)];
        let idx = ApiCallIndex::build(&events);
        let s = format!("{idx}");
        assert!(s.contains("total=1"));
    }

    #[test]
    fn test_mem_write_record_display() {
        let r = MemoryWriteRecord {
            address: 0x1000,
            data: vec![1, 2, 3],
            position: pos(1),
            thread_id: 1,
        };
        let s = format!("{r}");
        assert!(s.contains("0x1000"));
    }

    #[test]
    fn test_exception_record_display() {
        let r = ExceptionRecord {
            code: 0xC000_0005,
            address: 0x2000,
            position: pos(1),
            thread_id: 1,
        };
        let s = format!("{r}");
        assert!(s.contains("0xc0000005") || s.contains("0xC0000005"));
    }

    #[test]
    fn test_api_call_record_display() {
        let r = ApiCallRecord {
            syscall_nr: 5,
            args: vec![1, 2, 3, 4, 5, 6],
            return_value: Some(0),
            enter_position: pos(1),
            exit_position: Some(pos(2)),
            thread_id: 1,
        };
        let s = format!("{r}");
        assert!(s.contains("nr=5"));
    }

    #[test]
    fn test_index_error_display() {
        let e = IndexError::EmptyTrace;
        assert!(format!("{e}").contains("empty"));
        let e2 = IndexError::DuplicatePosition(pos(5));
        assert!(format!("{e2}").contains("duplicate"));
    }

    #[test]
    fn test_ttd_index_display() {
        let trace = build_trace(vec![ev_call(0, 0x1000, 1)]);
        let idx = TtdIndexBuilder::new().build(&trace).unwrap();
        let s = format!("{idx}");
        assert!(s.contains("TtdIndex"));
    }

    #[test]
    fn test_position_index_is_not_empty() {
        let events = vec![ev_call(0, 0, 1)];
        let idx = PositionIndex::build(&events).unwrap();
        assert!(!idx.is_empty());
    }
}
