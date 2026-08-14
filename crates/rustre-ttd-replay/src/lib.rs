//! `rustre-ttd-replay`
//!
//! Deterministic replay engine — restore process state at any position in a
//! TTD trace.  Analogous to `WinDbg` TTD backward-stepping or Mozilla rr replay.
//!
//! # Modules
//! * [`ttd_format`] — Binary TTD file format parser (`.run`, `.idx`, records).
//! * [`replay_engine`] — Trait + in-process replay engine implementation.
//! * [`memory_snapshot`] — Page-granular memory snapshot diffing.
//! * [`call_stack`] — Call-stack reconstruction at any replay position.
//! * [`watchpoints`] — Data-breakpoint / memory watchpoint system.
//! * [`thread_replay`] — Per-thread state, register files, context switches.

pub mod call_stack;
pub mod execution_graph;
pub mod memory_snapshot;
pub mod replay_analysis;
pub mod replay_engine;
pub mod thread_replay;
pub mod time_travel_queries;
pub mod ttd_format;
pub mod watchpoints;
pub mod forward_stepper;
pub mod backward_stepper;
pub mod replay_state_manager;
pub mod ttd_replay_engine;
pub mod ttd_breakpoint_manager;
pub mod ttd_watchpoint_manager;

use std::collections::{BTreeMap, HashMap};
use std::io::{Read as IoRead, Write as IoWrite};
use std::sync::Arc;

use rusqlite::{Connection, params};
use rustre_ttd::{EventKind, TraceEvent, TraceMetadata, TracePosition, TtdTrace};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── PAGE_SIZE ────────────────────────────────────────────────────────────────

const PAGE_SIZE: usize = 4096;

// ─── ReplayError ─────────────────────────────────────────────────────────────

/// Errors produced by the replay engine.
#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("invalid trace: {0}")]
    InvalidTrace(String),
    #[error("position not found: {0}")]
    PositionNotFound(TracePosition),
    #[error("state restore error: {0}")]
    StateRestoreError(String),
    #[error("emulation error: {0}")]
    EmulationError(String),
    #[error("database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

// ─── ReplayStopReason ─────────────────────────────────────────────────────────

/// Reason the replay engine stopped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplayStopReason {
    BreakpointHit {
        bp_id: u32,
        position: TracePosition,
    },
    WatchpointHit {
        wp_id: u32,
        position: TracePosition,
        old_value: Vec<u8>,
        new_value: Vec<u8>,
    },
    End,
    Start,
    StepComplete {
        position: TracePosition,
    },
    ConditionMet {
        position: TracePosition,
    },
    EventKindMatch {
        position: TracePosition,
    },
}

impl std::fmt::Display for ReplayStopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BreakpointHit { bp_id, position } => {
                write!(f, "BreakpointHit(id={bp_id}, pos={position})")
            }
            Self::WatchpointHit {
                wp_id, position, ..
            } => write!(f, "WatchpointHit(id={wp_id}, pos={position})"),
            Self::End => write!(f, "End"),
            Self::Start => write!(f, "Start"),
            Self::StepComplete { position } => write!(f, "StepComplete({position})"),
            Self::ConditionMet { position } => write!(f, "ConditionMet({position})"),
            Self::EventKindMatch { position } => write!(f, "EventKindMatch({position})"),
        }
    }
}

// ─── BreakpointCondition ──────────────────────────────────────────────────────

/// Optional condition attached to a breakpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BreakpointCondition {
    Always,
    RegisterEquals { reg: String, value: u64 },
    MemoryEquals { addr: u64, value: Vec<u8> },
    HitCountMultiple(u64),
}

// ─── ReplayBreakpoint ─────────────────────────────────────────────────────────

/// An address breakpoint that can halt replay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayBreakpoint {
    pub id: u32,
    pub address: u64,
    pub condition: Option<BreakpointCondition>,
    pub enabled: bool,
    pub hit_count: u64,
}

impl ReplayBreakpoint {
    #[must_use]
    pub const fn new(id: u32, address: u64) -> Self {
        Self {
            id,
            address,
            condition: None,
            enabled: true,
            hit_count: 0,
        }
    }

    #[must_use]
    pub fn with_condition(mut self, cond: BreakpointCondition) -> Self {
        self.condition = Some(cond);
        self
    }

    /// Check whether this breakpoint fires given current execution context.
    #[must_use]
    pub fn fires(&self, rip: u64, registers: &HashMap<String, u64>, mem: &MemoryState) -> bool {
        if !self.enabled {
            return false;
        }
        if rip != self.address {
            return false;
        }
        match &self.condition {
            None | Some(BreakpointCondition::Always) => true,
            Some(BreakpointCondition::RegisterEquals { reg, value }) => {
                registers.get(reg).copied() == Some(*value)
            }
            Some(BreakpointCondition::MemoryEquals { addr, value }) => {
                mem.read(*addr, value.len()).as_deref() == Some(value.as_slice())
            }
            Some(BreakpointCondition::HitCountMultiple(n)) => {
                *n > 0 && (self.hit_count + 1).is_multiple_of(*n)
            }
        }
    }
}

impl std::fmt::Display for ReplayBreakpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BP#{} @ {:#x} enabled={}",
            self.id, self.address, self.enabled
        )
    }
}

// ─── WatchpointKind ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WatchpointKind {
    Read,
    Write,
    ReadWrite,
}

// ─── Watchpoint ───────────────────────────────────────────────────────────────

/// A memory watchpoint that fires on read, write, or both.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Watchpoint {
    pub id: u32,
    pub address: u64,
    pub size: usize,
    pub kind: WatchpointKind,
    pub enabled: bool,
}

impl Watchpoint {
    #[must_use]
    pub const fn new(id: u32, address: u64, size: usize, kind: WatchpointKind) -> Self {
        Self {
            id,
            address,
            size,
            kind,
            enabled: true,
        }
    }

    #[must_use]
    pub const fn overlaps(&self, addr: u64, len: usize) -> bool {
        let wp_end = self.address.saturating_add(self.size as u64);
        let acc_end = addr.saturating_add(len as u64);
        self.address < acc_end && addr < wp_end
    }
}

impl std::fmt::Display for Watchpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WP#{} @ {:#x}+{} {:?}",
            self.id, self.address, self.size, self.kind
        )
    }
}

// ─── MemDiff ──────────────────────────────────────────────────────────────────

/// A difference between two memory states.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemDiff {
    pub address: u64,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

impl std::fmt::Display for MemDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MemDiff @ {:#x} len={}", self.address, self.after.len())
    }
}

// ─── MemPage ──────────────────────────────────────────────────────────────────

/// A single 4 KiB memory page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemPage {
    pub base: u64,
    pub data: Vec<u8>,
    pub dirty: bool,
}

impl MemPage {
    #[must_use]
    pub fn new(base: u64) -> Self {
        Self {
            base,
            data: vec![0u8; PAGE_SIZE],
            dirty: false,
        }
    }

    fn page_offset(addr: u64, base: u64) -> usize {
        usize::try_from(addr - base).unwrap_or(usize::MAX)
    }
}

// ─── MemoryState ─────────────────────────────────────────────────────────────

/// The reconstructed memory state at a given replay position.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryState {
    pub pages: BTreeMap<u64, MemPage>,
}

impl MemoryState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    const fn page_base(addr: u64) -> u64 {
        addr & !(PAGE_SIZE as u64 - 1)
    }

    /// Apply a write of `data` bytes starting at `addr`.
    pub fn apply_write(&mut self, addr: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let mut offset = 0usize;
        let mut cur_addr = addr;
        while offset < data.len() {
            let base = Self::page_base(cur_addr);
            let page = self.pages.entry(base).or_insert_with(|| MemPage::new(base));
            let page_off = MemPage::page_offset(cur_addr, base);
            let can_write = PAGE_SIZE - page_off;
            let to_write = (data.len() - offset).min(can_write);
            page.data[page_off..page_off + to_write]
                .copy_from_slice(&data[offset..offset + to_write]);
            page.dirty = true;
            offset += to_write;
            cur_addr += to_write as u64;
        }
    }

    /// Read `len` bytes from `addr`. Returns `None` if any byte is unmapped.
    #[must_use]
    pub fn read(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(vec![]);
        }
        let mut result = Vec::with_capacity(len);
        let mut offset = 0usize;
        let mut cur_addr = addr;
        while offset < len {
            let base = Self::page_base(cur_addr);
            let page = self.pages.get(&base)?;
            let page_off = MemPage::page_offset(cur_addr, base);
            let can_read = PAGE_SIZE - page_off;
            let to_read = (len - offset).min(can_read);
            result.extend_from_slice(&page.data[page_off..page_off + to_read]);
            offset += to_read;
            cur_addr += to_read as u64;
        }
        Some(result)
    }

    /// Compute page-level diffs between `self` and `other`.
    #[must_use]
    pub fn diff(&self, other: &Self) -> Vec<MemDiff> {
        let mut diffs = Vec::new();
        let all_bases: std::collections::BTreeSet<u64> = self
            .pages
            .keys()
            .chain(other.pages.keys())
            .copied()
            .collect();
        for base in all_bases {
            let before: &[u8] = self.pages.get(&base).map_or(&[][..], |p| p.data.as_slice());
            let after: &[u8] = other
                .pages
                .get(&base)
                .map_or(&[][..], |p| p.data.as_slice());
            if before != after {
                diffs.push(MemDiff {
                    address: base,
                    before: before.to_vec(),
                    after: after.to_vec(),
                });
            }
        }
        diffs
    }

    /// Count mapped pages.
    #[must_use]
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }
}

// ─── Snapshot ─────────────────────────────────────────────────────────────────

/// A full state snapshot at a trace position (for backward stepping).
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub position: TracePosition,
    pub memory: MemoryState,
    pub registers: HashMap<u32, HashMap<String, u64>>,
}

impl Snapshot {
    #[must_use]
    pub const fn new(
        position: TracePosition,
        memory: MemoryState,
        registers: HashMap<u32, HashMap<String, u64>>,
    ) -> Self {
        Self {
            position,
            memory,
            registers,
        }
    }
}

// ─── SnapshotCache ────────────────────────────────────────────────────────────

/// Cache of periodic snapshots enabling efficient backward replay.
pub struct SnapshotCache {
    pub interval: u64,
    snapshots: BTreeMap<TracePosition, Snapshot>,
}

impl SnapshotCache {
    #[must_use]
    pub const fn new(interval: u64) -> Self {
        Self {
            interval,
            snapshots: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, snapshot: Snapshot) {
        self.snapshots.insert(snapshot.position, snapshot);
    }

    /// Return the nearest snapshot whose position is <= `pos`.
    #[must_use]
    pub fn nearest_before(&self, pos: TracePosition) -> Option<&Snapshot> {
        self.snapshots.range(..=pos).next_back().map(|(_, s)| s)
    }

    #[must_use]
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    pub fn clear(&mut self) {
        self.snapshots.clear();
    }

    #[must_use]
    pub fn contains(&self, pos: TracePosition) -> bool {
        self.snapshots.contains_key(&pos)
    }
}

impl std::fmt::Debug for SnapshotCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotCache")
            .field("interval", &self.interval)
            .field("count", &self.snapshots.len())
            .finish_non_exhaustive()
    }
}

// ─── ReplayState (legacy) ─────────────────────────────────────────────────────

/// Simple flattened state for a single thread — kept for compat.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayState {
    pub position: TracePosition,
    pub registers: HashMap<String, u64>,
    pub memory_pages: HashMap<u64, Vec<u8>>,
    pub thread_id: u32,
}

impl Default for ReplayState {
    fn default() -> Self {
        let mut registers = HashMap::new();
        for name in &[
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13",
            "r14", "r15",
        ] {
            registers.insert(name.to_string(), 0u64);
        }
        registers.insert("rsp".to_string(), 0x7fff_0000u64);
        registers.insert("rbp".to_string(), 0x7fff_0000u64);
        registers.insert("rip".to_string(), 0u64);
        Self {
            position: TracePosition::start(),
            registers,
            memory_pages: HashMap::new(),
            thread_id: 0,
        }
    }
}

impl std::fmt::Display for ReplayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ReplayState {{ position: {}, tid: {}, regs: {}, pages: {} }}",
            self.position,
            self.thread_id,
            self.registers.len(),
            self.memory_pages.len()
        )
    }
}

// ─── MemoryDelta ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDelta {
    pub address: u64,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

impl std::fmt::Display for MemoryDelta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MemoryDelta {{ addr: {:#x}, len: {} }}",
            self.address,
            self.after.len()
        )
    }
}

// ─── ReplayCheckpoint ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ReplayCheckpoint {
    pub position: TracePosition,
    pub state: ReplayState,
}

impl std::fmt::Display for ReplayCheckpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReplayCheckpoint {{ position: {} }}", self.position)
    }
}

// ─── WatchAddress / WatchpointSet (legacy) ────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchAddress {
    pub addr: u64,
    pub size: usize,
}

impl std::fmt::Display for WatchAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WatchAddress {{ addr: {:#x}, size: {} }}",
            self.addr, self.size
        )
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WatchpointSet {
    pub watchpoints: Vec<WatchAddress>,
}

impl WatchpointSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, addr: u64, size: usize) {
        self.watchpoints.push(WatchAddress { addr, size });
    }

    pub fn remove(&mut self, addr: u64) -> bool {
        if let Some(pos) = self.watchpoints.iter().position(|w| w.addr == addr) {
            self.watchpoints.remove(pos);
            true
        } else {
            false
        }
    }

    #[must_use]
    pub fn matches(&self, addr: u64, size: usize) -> bool {
        self.watchpoints.iter().any(|w| {
            let w_end = w.addr.saturating_add(w.size as u64);
            let a_end = addr.saturating_add(size as u64);
            w.addr < a_end && addr < w_end
        })
    }
}

impl std::fmt::Display for WatchpointSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WatchpointSet {{ count: {} }}", self.watchpoints.len())
    }
}

// ─── DeltaCompressor ──────────────────────────────────────────────────────────

pub struct DeltaCompressor;

impl DeltaCompressor {
    #[must_use]
    pub fn compute_delta(address: u64, before: &[u8], after: &[u8]) -> MemoryDelta {
        MemoryDelta {
            address,
            before: before.to_vec(),
            after: after.to_vec(),
        }
    }

    #[must_use]
    pub fn apply_delta(base: &[u8], delta: &MemoryDelta) -> Vec<u8> {
        let mut result = base.to_vec();
        if result.len() < delta.after.len() {
            result.resize(delta.after.len(), 0);
        }
        result[..delta.after.len()].copy_from_slice(&delta.after);
        result
    }
}

// ─── ReplayEngine ─────────────────────────────────────────────────────────────

/// Full deterministic replay engine.
pub struct ReplayEngine {
    trace: Arc<TtdTrace>,
    current_pos: TracePosition,
    event_index: usize,
    memory_state: MemoryState,
    register_state: HashMap<u32, HashMap<String, u64>>,
    breakpoints: Vec<ReplayBreakpoint>,
    watchpoints: Vec<Watchpoint>,
    history: Vec<TracePosition>,
    snapshot_cache: SnapshotCache,
    next_bp_id: u32,
    next_wp_id: u32,
}

impl ReplayEngine {
    /// Create a new engine at the start of the trace.
    pub fn new(trace: Arc<TtdTrace>) -> Self {
        Self {
            trace,
            current_pos: TracePosition::start(),
            event_index: 0,
            memory_state: MemoryState::new(),
            register_state: HashMap::new(),
            breakpoints: Vec::new(),
            watchpoints: Vec::new(),
            history: Vec::new(),
            snapshot_cache: SnapshotCache::new(1000),
            next_bp_id: 1,
            next_wp_id: 1,
        }
    }

    /// Create engine with custom snapshot interval.
    pub fn with_snapshot_interval(trace: Arc<TtdTrace>, interval: u64) -> Self {
        let mut eng = Self::new(trace);
        eng.snapshot_cache = SnapshotCache::new(interval);
        eng
    }

    #[must_use]
    pub const fn current_position(&self) -> TracePosition {
        self.current_pos
    }
    #[must_use]
    pub const fn memory_state(&self) -> &MemoryState {
        &self.memory_state
    }
    #[must_use]
    pub const fn register_state(&self) -> &HashMap<u32, HashMap<String, u64>> {
        &self.register_state
    }
    #[must_use]
    pub fn breakpoints(&self) -> &[ReplayBreakpoint] {
        &self.breakpoints
    }
    #[must_use]
    pub fn watchpoints(&self) -> &[Watchpoint] {
        &self.watchpoints
    }
    #[must_use]
    pub fn history(&self) -> &[TracePosition] {
        &self.history
    }
    #[must_use]
    pub const fn snapshot_cache(&self) -> &SnapshotCache {
        &self.snapshot_cache
    }

    // ── Breakpoint management ────────────────────────────────────────────────

    pub fn add_breakpoint(&mut self, address: u64) -> u32 {
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        self.breakpoints.push(ReplayBreakpoint::new(id, address));
        id
    }

    pub fn add_breakpoint_with_condition(
        &mut self,
        address: u64,
        cond: BreakpointCondition,
    ) -> u32 {
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        self.breakpoints
            .push(ReplayBreakpoint::new(id, address).with_condition(cond));
        id
    }

    pub fn remove_breakpoint(&mut self, id: u32) -> bool {
        if let Some(pos) = self.breakpoints.iter().position(|b| b.id == id) {
            self.breakpoints.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn enable_breakpoint(&mut self, id: u32) -> bool {
        if let Some(bp) = self.breakpoints.iter_mut().find(|b| b.id == id) {
            bp.enabled = true;
            true
        } else {
            false
        }
    }

    pub fn disable_breakpoint(&mut self, id: u32) -> bool {
        if let Some(bp) = self.breakpoints.iter_mut().find(|b| b.id == id) {
            bp.enabled = false;
            true
        } else {
            false
        }
    }

    // ── Watchpoint management ────────────────────────────────────────────────

    pub fn add_watchpoint(&mut self, address: u64, size: usize, kind: WatchpointKind) -> u32 {
        let id = self.next_wp_id;
        self.next_wp_id += 1;
        self.watchpoints
            .push(Watchpoint::new(id, address, size, kind));
        id
    }

    pub fn remove_watchpoint(&mut self, id: u32) -> bool {
        if let Some(pos) = self.watchpoints.iter().position(|w| w.id == id) {
            self.watchpoints.remove(pos);
            true
        } else {
            false
        }
    }

    // ── Internal state application ───────────────────────────────────────────

    fn apply_event(&mut self, event: &TraceEvent) {
        self.current_pos = event.position;
        let regs = self.register_state.entry(event.thread_id).or_default();
        match &event.kind {
            EventKind::MemWrite { addr, data } => {
                self.memory_state.apply_write(*addr, data);
            }
            EventKind::Call { to, .. } | EventKind::Return { to, .. } => {
                regs.insert("rip".into(), *to);
            }
            EventKind::SyscallEnter { nr, args } => {
                regs.insert("rax".into(), u64::from(*nr));
                regs.insert("rdi".into(), args[0]);
                regs.insert("rsi".into(), args[1]);
                regs.insert("rdx".into(), args[2]);
                regs.insert("r10".into(), args[3]);
                regs.insert("r8".into(), args[4]);
                regs.insert("r9".into(), args[5]);
            }
            EventKind::SyscallExit { ret, .. } => {
                regs.insert("rax".into(), *ret);
            }
            EventKind::ThreadCreate { tid } => {
                self.register_state.entry(*tid).or_default();
            }
            EventKind::ThreadExit { .. }
            | EventKind::MemRead { .. }
            | EventKind::Exception { .. }
            | EventKind::Breakpoint { .. } => {}
        }
    }

    fn maybe_take_snapshot(&mut self, event_idx: usize) {
        let interval = self.snapshot_cache.interval;
        if interval == 0 {
            return;
        }
        if (event_idx as u64).is_multiple_of(interval)
            && !self.snapshot_cache.contains(self.current_pos)
        {
            let snap = Snapshot::new(
                self.current_pos,
                self.memory_state.clone(),
                self.register_state.clone(),
            );
            self.snapshot_cache.insert(snap);
        }
    }

    fn restore_from_snapshot(&mut self, snap: &Snapshot) {
        self.current_pos = snap.position;
        self.memory_state.clone_from(&snap.memory);
        self.register_state.clone_from(&snap.registers);
    }

    fn index_of_position(&self, pos: TracePosition) -> Option<usize> {
        let events = self.trace.all_events();
        events.iter().position(|e| e.position == pos)
    }

    fn replay_from_index(&mut self, from_idx: usize, to_idx: usize, events: &[TraceEvent]) {
        let mut i = from_idx;
        while i <= to_idx && i < events.len() {
            self.apply_event(&events[i]);
            self.maybe_take_snapshot(i);
            i += 1;
        }
        self.event_index = i;
    }

    fn check_breakpoints_at_event(&mut self, event: &TraceEvent) -> Option<u32> {
        let rip = match &event.kind {
            EventKind::Call { to, .. } | EventKind::Return { to, .. } => *to,
            EventKind::Breakpoint { addr } => *addr,
            _ => return None,
        };
        let regs = self
            .register_state
            .get(&event.thread_id)
            .cloned()
            .unwrap_or_default();
        for bp in &mut self.breakpoints {
            if bp.fires(rip, &regs, &self.memory_state) {
                let id = bp.id;
                bp.hit_count += 1;
                return Some(id);
            }
        }
        None
    }

    fn check_watchpoints_write(&self, addr: u64, data: &[u8]) -> Option<(u32, Vec<u8>, Vec<u8>)> {
        for wp in &self.watchpoints {
            if !wp.enabled {
                continue;
            }
            if wp.kind == WatchpointKind::Read {
                continue;
            }
            if wp.overlaps(addr, data.len()) {
                let old = self
                    .memory_state
                    .read(wp.address, wp.size)
                    .unwrap_or_default();
                return Some((wp.id, old, data.to_vec()));
            }
        }
        None
    }

    fn check_watchpoints_read(&self, addr: u64, len: usize) -> Option<u32> {
        for wp in &self.watchpoints {
            if !wp.enabled {
                continue;
            }
            if wp.kind == WatchpointKind::Write {
                continue;
            }
            if wp.overlaps(addr, len) {
                return Some(wp.id);
            }
        }
        None
    }

    // ── Navigation ────────────────────────────────────────────────────────────

    /// Step one event forward.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn step_forward(&mut self) -> Result<ReplayStopReason, ReplayError> {
        let events = self.trace.all_events();
        if self.event_index >= events.len() {
            return Ok(ReplayStopReason::End);
        }
        let event = events[self.event_index].clone();

        // Check watchpoints before applying the event
        if let EventKind::MemWrite { addr, data } = &event.kind
            && let Some((wp_id, old, new_val)) = self.check_watchpoints_write(*addr, data)
        {
            self.history.push(self.current_pos);
            self.apply_event(&event);
            self.maybe_take_snapshot(self.event_index);
            self.event_index += 1;
            return Ok(ReplayStopReason::WatchpointHit {
                wp_id,
                position: self.current_pos,
                old_value: old,
                new_value: new_val,
            });
        }
        if let EventKind::MemRead { addr, len } = &event.kind
            && let Some(wp_id) = self.check_watchpoints_read(*addr, *len)
        {
            self.history.push(self.current_pos);
            self.apply_event(&event);
            self.maybe_take_snapshot(self.event_index);
            self.event_index += 1;
            return Ok(ReplayStopReason::WatchpointHit {
                wp_id,
                position: self.current_pos,
                old_value: vec![],
                new_value: vec![],
            });
        }

        self.history.push(self.current_pos);
        self.apply_event(&event);
        self.maybe_take_snapshot(self.event_index);
        self.event_index += 1;

        if let Some(bp_id) = self.check_breakpoints_at_event(&event) {
            return Ok(ReplayStopReason::BreakpointHit {
                bp_id,
                position: self.current_pos,
            });
        }

        Ok(ReplayStopReason::StepComplete {
            position: self.current_pos,
        })
    }

    /// Step one event backward using snapshot cache.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn step_backward(&mut self) -> Result<ReplayStopReason, ReplayError> {
        if self.event_index == 0 {
            return Ok(ReplayStopReason::Start);
        }

        // Target: state after event at (event_index - 2)
        let target_event_idx = self.event_index.saturating_sub(2);
        let at_beginning = self.event_index == 1;

        let events = self.trace.all_events();

        if at_beginning {
            self.current_pos = TracePosition::start();
            self.memory_state = MemoryState::new();
            self.register_state = HashMap::new();
            self.event_index = 0;
            return Ok(ReplayStopReason::Start);
        }

        // Find the nearest snapshot at or before target
        let target_pos = events[target_event_idx].position;
        if let Some(snap) = self.snapshot_cache.nearest_before(target_pos).cloned() {
            let snap_idx = self
                .index_of_position(snap.position)
                .ok_or_else(|| ReplayError::InvalidTrace("snapshot position lost".into()))?;
            self.restore_from_snapshot(&snap);
            self.event_index = snap_idx + 1;
            // Replay forward to target
            if self.event_index <= target_event_idx {
                self.replay_from_index(self.event_index, target_event_idx, &events);
            } else {
                self.event_index = snap_idx + 1;
            }
        } else {
            // Replay from scratch
            self.current_pos = TracePosition::start();
            self.memory_state = MemoryState::new();
            self.register_state = HashMap::new();
            self.event_index = 0;
            self.replay_from_index(0, target_event_idx, &events);
        }

        Ok(ReplayStopReason::StepComplete {
            position: self.current_pos,
        })
    }

    /// Fast-forward to a specific position.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn run_forward_to_position(
        &mut self,
        pos: TracePosition,
    ) -> Result<ReplayStopReason, ReplayError> {
        let events = self.trace.all_events();
        let target_idx = events
            .iter()
            .position(|e| e.position == pos)
            .ok_or(ReplayError::PositionNotFound(pos))?;

        if target_idx < self.event_index.saturating_sub(1) {
            return Err(ReplayError::PositionNotFound(pos));
        }

        while self.event_index <= target_idx {
            let event = events[self.event_index].clone();
            self.apply_event(&event);
            self.maybe_take_snapshot(self.event_index);
            self.event_index += 1;
        }
        Ok(ReplayStopReason::StepComplete {
            position: self.current_pos,
        })
    }

    /// Reverse replay to a specific position.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn run_backward_to_position(
        &mut self,
        pos: TracePosition,
    ) -> Result<ReplayStopReason, ReplayError> {
        let events = self.trace.all_events();
        let target_idx = events
            .iter()
            .position(|e| e.position == pos)
            .ok_or(ReplayError::PositionNotFound(pos))?;

        if target_idx >= self.event_index {
            return Err(ReplayError::PositionNotFound(pos));
        }

        // Use nearest snapshot before target
        if let Some(snap) = self.snapshot_cache.nearest_before(pos).cloned() {
            let snap_idx = self
                .index_of_position(snap.position)
                .ok_or_else(|| ReplayError::InvalidTrace("snapshot lost".into()))?;
            self.restore_from_snapshot(&snap);
            self.event_index = snap_idx + 1;
            if self.event_index <= target_idx {
                self.replay_from_index(self.event_index, target_idx, &events);
            }
        } else {
            self.current_pos = TracePosition::start();
            self.memory_state = MemoryState::new();
            self.register_state = HashMap::new();
            self.event_index = 0;
            self.replay_from_index(0, target_idx, &events);
        }
        Ok(ReplayStopReason::StepComplete {
            position: self.current_pos,
        })
    }

    /// Continue forward until a breakpoint is hit.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn run_to_breakpoint_forward(&mut self) -> Result<ReplayStopReason, ReplayError> {
        let events = self.trace.all_events();
        while self.event_index < events.len() {
            let event = events[self.event_index].clone();

            if let EventKind::MemWrite { addr, data } = &event.kind
                && let Some((wp_id, old, new_val)) = self.check_watchpoints_write(*addr, data)
            {
                self.apply_event(&event);
                self.maybe_take_snapshot(self.event_index);
                self.event_index += 1;
                return Ok(ReplayStopReason::WatchpointHit {
                    wp_id,
                    position: self.current_pos,
                    old_value: old,
                    new_value: new_val,
                });
            }

            self.apply_event(&event);
            self.maybe_take_snapshot(self.event_index);
            self.event_index += 1;

            if let Some(bp_id) = self.check_breakpoints_at_event(&event) {
                return Ok(ReplayStopReason::BreakpointHit {
                    bp_id,
                    position: self.current_pos,
                });
            }
        }
        Ok(ReplayStopReason::End)
    }

    /// Continue backward until a breakpoint is hit.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn run_to_breakpoint_backward(&mut self) -> Result<ReplayStopReason, ReplayError> {
        if self.event_index == 0 {
            return Ok(ReplayStopReason::Start);
        }
        let events = self.trace.all_events();
        let start_idx = self.event_index.saturating_sub(1);
        // Scan backward for first breakpoint — collect (bp_id, pos) without holding borrow
        let mut found: Option<(u32, TracePosition)> = None;
        'outer: for scan_idx in (0..=start_idx).rev() {
            let event = &events[scan_idx];
            let rip = match &event.kind {
                EventKind::Call { to, .. } | EventKind::Return { to, .. } => *to,
                EventKind::Breakpoint { addr } => *addr,
                _ => continue,
            };
            for bp in &self.breakpoints {
                if bp.enabled && bp.address == rip {
                    found = Some((bp.id, event.position));
                    break 'outer;
                }
            }
        }
        if let Some((bp_id, pos)) = found {
            self.run_backward_to_position(pos)?;
            return Ok(ReplayStopReason::BreakpointHit {
                bp_id,
                position: pos,
            });
        }
        self.go_to_start()?;
        Ok(ReplayStopReason::Start)
    }

    /// Skip forward to the next event of a matching kind.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn run_to_next_event_of_kind(
        &mut self,
        kind_filter: &dyn Fn(&EventKind) -> bool,
    ) -> Result<ReplayStopReason, ReplayError> {
        let events = self.trace.all_events();
        while self.event_index < events.len() {
            let event = events[self.event_index].clone();
            self.apply_event(&event);
            self.maybe_take_snapshot(self.event_index);
            self.event_index += 1;
            if kind_filter(&event.kind) {
                return Ok(ReplayStopReason::EventKindMatch {
                    position: self.current_pos,
                });
            }
        }
        Ok(ReplayStopReason::End)
    }

    /// Rewind to the beginning of the trace.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn go_to_start(&mut self) -> Result<ReplayStopReason, ReplayError> {
        self.current_pos = TracePosition::start();
        self.memory_state = MemoryState::new();
        self.register_state = HashMap::new();
        self.event_index = 0;
        self.history.clear();
        Ok(ReplayStopReason::Start)
    }

    /// Fast-forward to the last event in the trace.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn go_to_end(&mut self) -> Result<ReplayStopReason, ReplayError> {
        let events = self.trace.all_events();
        if events.is_empty() {
            return Ok(ReplayStopReason::End);
        }
        // Build all snapshots as we go
        while self.event_index < events.len() {
            let event = events[self.event_index].clone();
            self.apply_event(&event);
            self.maybe_take_snapshot(self.event_index);
            self.event_index += 1;
        }
        Ok(ReplayStopReason::End)
    }

    // ── Query APIs ────────────────────────────────────────────────────────────

    /// Find the first memory write to `addr`.
    #[must_use]
    pub fn find_first_write_to(&self, addr: u64) -> Option<TracePosition> {
        let events = self.trace.all_events();
        for event in &events {
            if let EventKind::MemWrite { addr: wa, .. } = &event.kind
                && *wa == addr
            {
                return Some(event.position);
            }
        }
        None
    }

    /// Find the last memory write to `addr`.
    #[must_use]
    pub fn find_last_write_to(&self, addr: u64) -> Option<TracePosition> {
        let events = self.trace.all_events();
        let mut last = None;
        for event in &events {
            if let EventKind::MemWrite { addr: wa, .. } = &event.kind
                && *wa == addr
            {
                last = Some(event.position);
            }
        }
        last
    }

    /// Return all (position, data) pairs for writes to `addr`.
    #[must_use]
    pub fn find_all_writes_to(&self, addr: u64) -> Vec<(TracePosition, Vec<u8>)> {
        // `all_events` returns an owned Vec; consume it so we can move
        // `data` out of each matching event instead of cloning.
        self.trace
            .all_events()
            .into_iter()
            .filter_map(|event| match event.kind {
                EventKind::MemWrite { addr: wa, data } if wa == addr => {
                    Some((event.position, data))
                }
                _ => None,
            })
            .collect()
    }

    /// Return all positions of memory reads from `addr`.
    #[must_use]
    pub fn find_all_reads_from(&self, addr: u64) -> Vec<TracePosition> {
        let events = self.trace.all_events();
        events
            .iter()
            .filter_map(|e| {
                if let EventKind::MemRead { addr: ra, .. } = &e.kind {
                    if *ra == addr { Some(e.position) } else { None }
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return all positions of calls to `target`.
    #[must_use]
    pub fn find_all_calls_to(&self, target: u64) -> Vec<TracePosition> {
        let events = self.trace.all_events();
        events
            .iter()
            .filter_map(|e| {
                if let EventKind::Call { to, .. } = &e.kind {
                    if *to == target {
                        Some(e.position)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    /// Return all positions of calls from `site`.
    #[must_use]
    pub fn find_all_calls_from(&self, site: u64) -> Vec<TracePosition> {
        let events = self.trace.all_events();
        events
            .iter()
            .filter_map(|e| {
                if let EventKind::Call { from, .. } = &e.kind {
                    if *from == site {
                        Some(e.position)
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    /// Find all positions where `addr` contains `value`.
    #[must_use]
    pub fn find_value_at(&self, addr: u64, value: &[u8]) -> Vec<TracePosition> {
        let events = self.trace.all_events();
        let mut mem = MemoryState::new();
        let mut result = Vec::new();
        for event in &events {
            if let EventKind::MemWrite { addr: wa, data } = &event.kind {
                mem.apply_write(*wa, data);
                if *wa == addr
                    && let Some(current) = mem.read(addr, value.len())
                    && current.as_slice() == value
                {
                    result.push(event.position);
                }
            }
        }
        result
    }

    /// Return the memory bytes at `addr` for length `len` as it was at `pos`.
    #[must_use]
    pub fn get_memory_at(&self, pos: TracePosition, addr: u64, len: usize) -> Option<Vec<u8>> {
        let events = self.trace.all_events();
        let target_idx = events.iter().position(|e| e.position == pos)?;
        let mut mem = MemoryState::new();
        for event in events.iter().take(target_idx + 1) {
            if let EventKind::MemWrite { addr: wa, data } = &event.kind {
                mem.apply_write(*wa, data);
            }
        }
        mem.read(addr, len)
    }

    /// Return the register value for thread `tid` register `reg` at `pos`.
    #[must_use]
    pub fn get_register_at(&self, pos: TracePosition, tid: u32, reg: &str) -> Option<u64> {
        let events = self.trace.all_events();
        let target_idx = events.iter().position(|e| e.position == pos)?;
        let mut regs: HashMap<u32, HashMap<String, u64>> = HashMap::new();
        for event in events.iter().take(target_idx + 1) {
            let r = regs.entry(event.thread_id).or_default();
            match &event.kind {
                EventKind::Call { to, .. } | EventKind::Return { to, .. } => {
                    r.insert("rip".into(), *to);
                }
                EventKind::SyscallEnter { nr, args } => {
                    r.insert("rax".into(), u64::from(*nr));
                    r.insert("rdi".into(), args[0]);
                    r.insert("rsi".into(), args[1]);
                    r.insert("rdx".into(), args[2]);
                }
                EventKind::SyscallExit { ret, .. } => {
                    r.insert("rax".into(), *ret);
                }
                _ => {}
            }
        }
        regs.get(&tid)?.get(reg).copied()
    }

    // ── Bulk index building ───────────────────────────────────────────────────

    /// Pre-build all snapshots by replaying the entire trace.
    pub fn build_snapshot_index(&mut self) {
        let events = self.trace.all_events();
        let interval = self.snapshot_cache.interval;
        if interval == 0 {
            return;
        }
        let saved_idx = self.event_index;
        let saved_pos = self.current_pos;
        let saved_mem = self.memory_state.clone();
        let saved_regs = self.register_state.clone();

        self.current_pos = TracePosition::start();
        self.memory_state = MemoryState::new();
        self.register_state = HashMap::new();
        self.event_index = 0;

        for (i, event) in events.iter().enumerate() {
            self.apply_event(event);
            if (i as u64 + 1).is_multiple_of(interval) {
                let snap = Snapshot::new(
                    self.current_pos,
                    self.memory_state.clone(),
                    self.register_state.clone(),
                );
                self.snapshot_cache.insert(snap);
            }
            self.event_index = i + 1;
        }

        // Restore original state
        self.event_index = saved_idx;
        self.current_pos = saved_pos;
        self.memory_state = saved_mem;
        self.register_state = saved_regs;
    }

    // ── Legacy state API ─────────────────────────────────────────────────────

    /// Return a `ReplayState` snapshot of the current position (legacy API).
    #[must_use]
    pub fn current_state(&self) -> ReplayState {
        let mut rs = ReplayState {
            position: self.current_pos,
            ..ReplayState::default()
        };
        // Use thread 1 as the "current" thread for legacy compat
        if let Some(regs) = self.register_state.get(&1) {
            rs.registers.clone_from(regs);
        }
        for (base, page) in &self.memory_state.pages {
            rs.memory_pages.insert(*base, page.data.clone());
        }
        rs
    }

    /// Legacy `step_forward` returning `ReplayState`.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn step_forward_state(&mut self) -> Result<ReplayState, ReplayError> {
        self.step_forward()?;
        Ok(self.current_state())
    }

    /// Legacy `step_backward` returning `ReplayState`.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn step_backward_state(&mut self) -> Result<ReplayState, ReplayError> {
        self.step_backward()?;
        Ok(self.current_state())
    }

    /// Legacy goto.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn goto(&mut self, pos: TracePosition) -> Result<ReplayState, ReplayError> {
        let events = self.trace.all_events();
        let target_idx = events
            .iter()
            .position(|e| e.position == pos)
            .ok_or(ReplayError::PositionNotFound(pos))?;
        self.current_pos = TracePosition::start();
        self.memory_state = MemoryState::new();
        self.register_state = HashMap::new();
        self.event_index = 0;
        while self.event_index <= target_idx {
            let e = events[self.event_index].clone();
            self.apply_event(&e);
            self.event_index += 1;
        }
        Ok(self.current_state())
    }

    #[must_use]
    pub fn save_checkpoint(&self) -> ReplayCheckpoint {
        ReplayCheckpoint {
            position: self.current_pos,
            state: self.current_state(),
        }
    }

    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn restore_checkpoint(&mut self, cp: &ReplayCheckpoint) -> Result<(), ReplayError> {
        let events = self.trace.all_events();
        let idx = events
            .iter()
            .position(|e| e.position == cp.position)
            .ok_or_else(|| {
                ReplayError::StateRestoreError(format!(
                    "checkpoint position {} not found",
                    cp.position
                ))
            })?;
        self.current_pos = cp.position;
        self.event_index = idx + 1;
        Ok(())
    }

    pub fn set_watchpoints(&mut self, ws: WatchpointSet) {
        self.watchpoints.clear();
        for w in ws.watchpoints {
            let id = self.next_wp_id;
            self.next_wp_id += 1;
            self.watchpoints
                .push(Watchpoint::new(id, w.addr, w.size, WatchpointKind::Write));
        }
    }

    pub fn apply_event_to_state(state: &mut ReplayState, event: &TraceEvent) {
        state.position = event.position;
        state.thread_id = event.thread_id;
        match &event.kind {
            EventKind::MemWrite { addr, data } => {
                // Key by page-aligned base and write at the correct intra-page offset,
                // consistent with MemoryState::apply_write.
                let page_size: u64 = 0x1000;
                let mut offset = 0usize;
                let mut cur_addr = *addr;
                while offset < data.len() {
                    let base = cur_addr & !(page_size - 1);
                    let page_off = usize::try_from(cur_addr - base).unwrap_or(usize::MAX);
                    let can_write = (usize::try_from(page_size).unwrap_or(usize::MAX)) - page_off;
                    let to_write = (data.len() - offset).min(can_write);
                    let page = state
                        .memory_pages
                        .entry(base)
                        .or_insert_with(|| vec![0u8; usize::try_from(page_size).unwrap_or(usize::MAX)]);
                    if page.len() < usize::try_from(page_size).unwrap_or(usize::MAX) {
                        page.resize(usize::try_from(page_size).unwrap_or(usize::MAX), 0);
                    }
                    page[page_off..page_off + to_write]
                        .copy_from_slice(&data[offset..offset + to_write]);
                    offset += to_write;
                    cur_addr += to_write as u64;
                }
            }
            EventKind::Call { to, .. } | EventKind::Return { to, .. } => {
                state.registers.insert("rip".into(), *to);
            }
            EventKind::SyscallEnter { nr, args } => {
                state.registers.insert("rax".into(), u64::from(*nr));
                state.registers.insert("rdi".into(), args[0]);
                state.registers.insert("rsi".into(), args[1]);
                state.registers.insert("rdx".into(), args[2]);
            }
            EventKind::SyscallExit { ret, .. } => {
                state.registers.insert("rax".into(), *ret);
            }
            EventKind::ThreadCreate { tid } | EventKind::ThreadExit { tid, .. } => {
                state.thread_id = *tid;
            }
            EventKind::MemRead { .. }
            | EventKind::Exception { .. }
            | EventKind::Breakpoint { .. } => {}
        }
    }
}

impl std::fmt::Debug for ReplayEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReplayEngine")
            .field("event_index", &self.event_index)
            .field("current_pos", &self.current_pos)
            .field("breakpoints", &self.breakpoints.len())
            .field("watchpoints", &self.watchpoints.len())
            .field("snapshot_cache", &self.snapshot_cache)
            .finish_non_exhaustive()
    }
}

// ─── TtdRecordingFile ─────────────────────────────────────────────────────────

/// Magic bytes for the recording file format.
const RECORDING_MAGIC: &[u8; 8] = b"RSTRETTD";
const RECORDING_VERSION: u32 = 1;

/// A serializable trace recording — binary format with magic header.
pub struct TtdRecordingFile {
    pub metadata: TraceMetadata,
    pub events: Vec<TraceEvent>,
}

impl TtdRecordingFile {
    #[must_use]
    pub const fn new(metadata: TraceMetadata) -> Self {
        Self {
            metadata,
            events: Vec::new(),
        }
    }

    pub fn from_trace(trace: &TtdTrace) -> Self {
        Self {
            metadata: trace.metadata.clone(),
            events: trace.all_events(),
        }
    }

    /// Serialize to a writer using a simple binary format:
    /// `[magic(8)] [version(u32le)] [metadata_len(u32le)] [metadata_json]
    ///  [event_count(u64le)] [event0_len(u32le)] [event0_json] ...`
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn write_to<W: IoWrite>(&self, w: &mut W) -> Result<(), ReplayError> {
        w.write_all(RECORDING_MAGIC)?;
        w.write_all(&RECORDING_VERSION.to_le_bytes())?;
        let meta_json = serde_json::to_string(&self.metadata)
            .map_err(|e| ReplayError::SerializationError(e.to_string()))?;
        let meta_bytes = meta_json.as_bytes();
        let meta_len_u32 = u32::try_from(meta_bytes.len())
            .map_err(|_| ReplayError::SerializationError("metadata too large for u32 length field".into()))?;
        w.write_all(&meta_len_u32.to_le_bytes())?;
        w.write_all(meta_bytes)?;
        w.write_all(&(self.events.len() as u64).to_le_bytes())?;
        for event in &self.events {
            let evt_json = serde_json::to_string(event)
                .map_err(|e| ReplayError::SerializationError(e.to_string()))?;
            let evt_bytes = evt_json.as_bytes();
            let evt_len_u32 = u32::try_from(evt_bytes.len())
                .map_err(|_| ReplayError::SerializationError("event too large for u32 length field".into()))?;
            w.write_all(&evt_len_u32.to_le_bytes())?;
            w.write_all(evt_bytes)?;
        }
        Ok(())
    }

    /// Deserialize from a reader.
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn read_from<R: IoRead>(r: &mut R) -> Result<Self, ReplayError> {
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)?;
        if &magic != RECORDING_MAGIC {
            return Err(ReplayError::InvalidTrace("bad magic".into()));
        }
        let mut ver_buf = [0u8; 4];
        r.read_exact(&mut ver_buf)?;
        let version = u32::from_le_bytes(ver_buf);
        if version != RECORDING_VERSION {
            return Err(ReplayError::InvalidTrace(format!(
                "unsupported version {version}"
            )));
        }
        let mut meta_len_buf = [0u8; 4];
        r.read_exact(&mut meta_len_buf)?;
        let meta_len = u32::from_le_bytes(meta_len_buf) as usize;
        // Guard against maliciously large metadata length (>= 64 MiB).
        if meta_len > 64 * 1024 * 1024 {
            return Err(ReplayError::SerializationError(format!(
                "metadata length {meta_len} exceeds 64 MiB limit"
            )));
        }
        let mut meta_bytes = vec![0u8; meta_len];
        r.read_exact(&mut meta_bytes)?;
        let metadata: TraceMetadata = serde_json::from_slice(&meta_bytes)
            .map_err(|e| ReplayError::SerializationError(e.to_string()))?;

        let mut count_buf = [0u8; 8];
        r.read_exact(&mut count_buf)?;
        let event_count_raw = u64::from_le_bytes(count_buf);
        // Guard against excessively large event counts (> 100 million events).
        if event_count_raw > 100_000_000 {
            return Err(ReplayError::SerializationError(format!(
                "event count {event_count_raw} exceeds 100M limit"
            )));
        }
        let event_count = usize::try_from(event_count_raw)
            .map_err(|_| ReplayError::SerializationError("event count too large for this platform".into()))?;
        // Reserve conservatively to avoid large upfront allocation on untrusted input.
        let mut events = Vec::with_capacity(event_count.min(4096));
        for _ in 0..event_count {
            let mut len_buf = [0u8; 4];
            r.read_exact(&mut len_buf)?;
            let len = u32::from_le_bytes(len_buf) as usize;
            // Guard against per-event blobs exceeding 16 MiB.
            if len > 16 * 1024 * 1024 {
                return Err(ReplayError::SerializationError(format!(
                    "event length {len} exceeds 16 MiB limit"
                )));
            }
            let mut evt_bytes = vec![0u8; len];
            r.read_exact(&mut evt_bytes)?;
            let event: TraceEvent = serde_json::from_slice(&evt_bytes)
                .map_err(|e| ReplayError::SerializationError(e.to_string()))?;
            events.push(event);
        }
        Ok(Self { metadata, events })
    }

    /// Convert back to a `TtdTrace`.
    #[must_use]
    pub fn into_trace(self) -> Arc<TtdTrace> {
        let trace = Arc::new(TtdTrace::new(self.metadata));
        for event in self.events {
            trace.add_event(event);
        }
        trace
    }
}

impl std::fmt::Debug for TtdRecordingFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TtdRecordingFile")
            .field("process", &self.metadata.process_name)
            .field("events", &self.events.len())
            .finish_non_exhaustive()
    }
}

// ─── EngineStateDb ────────────────────────────────────────────────────────────

/// `SQLite` persistence for engine state (breakpoints, watchpoints, history).
pub struct EngineStateDb {
    conn: Connection,
}

impl EngineStateDb {
    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn open_in_memory() -> Result<Self, ReplayError> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS breakpoints (
                id INTEGER PRIMARY KEY, address INTEGER NOT NULL,
                enabled INTEGER NOT NULL, hit_count INTEGER NOT NULL,
                condition TEXT
            );
            CREATE TABLE IF NOT EXISTS watchpoints (
                id INTEGER PRIMARY KEY, address INTEGER NOT NULL,
                size INTEGER NOT NULL, kind TEXT NOT NULL, enabled INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS history (
                idx INTEGER PRIMARY KEY AUTOINCREMENT,
                seq INTEGER NOT NULL, step INTEGER NOT NULL
            );
        ",
        )?;
        Ok(Self { conn })
    }

    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn save_breakpoints(&self, bps: &[ReplayBreakpoint]) -> Result<(), ReplayError> {
        self.conn.execute("DELETE FROM breakpoints", [])?;
        for bp in bps {
            let cond = bp
                .condition
                .as_ref()
                .and_then(|c| serde_json::to_string(c).ok());
            self.conn.execute(
                "INSERT INTO breakpoints (id, address, enabled, hit_count, condition) VALUES (?1,?2,?3,?4,?5)",
                params![bp.id, bp.address, i32::from(bp.enabled), bp.hit_count, cond],
            )?;
        }
        Ok(())
    }

    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn load_breakpoints(&self) -> Result<Vec<ReplayBreakpoint>, ReplayError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, address, enabled, hit_count, condition FROM breakpoints ORDER BY id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, i32>(2)?,
                row.get::<_, u64>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })?;
        let mut bps = Vec::new();
        for row in rows {
            let (id, address, enabled, hit_count, cond_str) = row?;
            let condition = cond_str.and_then(|s| serde_json::from_str(&s).ok());
            bps.push(ReplayBreakpoint {
                id,
                address,
                enabled: enabled != 0,
                hit_count,
                condition,
            });
        }
        Ok(bps)
    }

    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn save_watchpoints(&self, wps: &[Watchpoint]) -> Result<(), ReplayError> {
        self.conn.execute("DELETE FROM watchpoints", [])?;
        for wp in wps {
            let kind = serde_json::to_string(&wp.kind)
                .map_err(|e| ReplayError::SerializationError(e.to_string()))?;
            self.conn.execute(
                "INSERT INTO watchpoints (id, address, size, kind, enabled) VALUES (?1,?2,?3,?4,?5)",
                params![wp.id, wp.address, u32::try_from(wp.size).unwrap_or(u32::MAX), kind, i32::from(wp.enabled)],
            )?;
        }
        Ok(())
    }

    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn load_watchpoints(&self) -> Result<Vec<Watchpoint>, ReplayError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, address, size, kind, enabled FROM watchpoints ORDER BY id")?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, u32>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i32>(4)?,
            ))
        })?;
        let mut wps = Vec::new();
        for row in rows {
            let (id, address, size, kind_str, enabled) = row?;
            let kind: WatchpointKind = serde_json::from_str(&kind_str)
                .map_err(|e| ReplayError::SerializationError(e.to_string()))?;
            wps.push(Watchpoint {
                id,
                address,
                size: size as usize,
                kind,
                enabled: enabled != 0,
            });
        }
        Ok(wps)
    }

    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn save_history(&self, history: &[TracePosition]) -> Result<(), ReplayError> {
        self.conn.execute("DELETE FROM history", [])?;
        for pos in history {
            self.conn.execute(
                "INSERT INTO history (seq, step) VALUES (?1, ?2)",
                params![pos.sequence, pos.step],
            )?;
        }
        Ok(())
    }

    ///
    /// # Errors
    /// Returns an error if the operation fails.
    pub fn load_history(&self) -> Result<Vec<TracePosition>, ReplayError> {
        let mut stmt = self
            .conn
            .prepare("SELECT seq, step FROM history ORDER BY idx")?;
        let rows = stmt.query_map([], |row| {
            Ok(TracePosition::new(
                row.get::<_, u64>(0)?,
                row.get::<_, u64>(1)?,
            ))
        })?;
        let mut hist = Vec::new();
        for row in rows {
            hist.push(row?);
        }
        Ok(hist)
    }
}

impl std::fmt::Debug for EngineStateDb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineStateDb").finish_non_exhaustive()
    }
}

// ─── MemoryAccessStats ────────────────────────────────────────────────────────

/// Statistics about memory access patterns for a range.
#[derive(Debug, Clone, Default)]
pub struct MemoryAccessStats {
    pub read_count: u64,
    pub write_count: u64,
    pub unique_addresses: std::collections::HashSet<u64>,
    pub first_access: Option<TracePosition>,
    pub last_access: Option<TracePosition>,
}

impl MemoryAccessStats {
    #[must_use]
    pub const fn total_accesses(&self) -> u64 {
        self.read_count + self.write_count
    }
}

impl std::fmt::Display for MemoryAccessStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MemoryAccessStats {{ reads: {}, writes: {}, unique_addrs: {} }}",
            self.read_count,
            self.write_count,
            self.unique_addresses.len()
        )
    }
}

/// Compute memory access statistics for an address range over the full trace.
pub fn compute_memory_access_stats(
    trace: &TtdTrace,
    range_start: u64,
    range_end: u64,
) -> MemoryAccessStats {
    let events = trace.all_events();
    let mut stats = MemoryAccessStats::default();
    for event in &events {
        match &event.kind {
            EventKind::MemRead { addr, len } => {
                let end = addr.saturating_add(*len as u64);
                if *addr < range_end && end > range_start {
                    stats.read_count += 1;
                    stats.unique_addresses.insert(*addr);
                    if stats.first_access.is_none() {
                        stats.first_access = Some(event.position);
                    }
                    stats.last_access = Some(event.position);
                }
            }
            EventKind::MemWrite { addr, data } => {
                let end = addr.saturating_add(data.len() as u64);
                if *addr < range_end && end > range_start {
                    stats.write_count += 1;
                    stats.unique_addresses.insert(*addr);
                    if stats.first_access.is_none() {
                        stats.first_access = Some(event.position);
                    }
                    stats.last_access = Some(event.position);
                }
            }
            _ => {}
        }
    }
    stats
}

// ─── CallGraph ────────────────────────────────────────────────────────────────

/// Edge in the call graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEdge {
    pub from: u64,
    pub to: u64,
    pub count: u64,
}

/// Build a call-count table from a trace.
pub fn build_call_graph(trace: &TtdTrace) -> Vec<CallEdge> {
    let events = trace.all_events();
    let mut counts: HashMap<(u64, u64), u64> = HashMap::new();
    for event in &events {
        if let EventKind::Call { from, to } = &event.kind {
            *counts.entry((*from, *to)).or_insert(0) += 1;
        }
    }
    counts
        .into_iter()
        .map(|((from, to), count)| CallEdge { from, to, count })
        .collect()
}

// ─── Thread timeline ──────────────────────────────────────────────────────────

/// A slice of the trace belonging to one thread.
#[derive(Debug, Clone)]
pub struct ThreadTimeline {
    pub tid: u32,
    pub events: Vec<TraceEvent>,
    pub first_pos: Option<TracePosition>,
    pub last_pos: Option<TracePosition>,
}

impl ThreadTimeline {
    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.events.len()
    }
}

/// Split the trace into per-thread timelines.
pub fn split_by_thread(trace: &TtdTrace) -> HashMap<u32, ThreadTimeline> {
    let events = trace.all_events();
    let mut map: HashMap<u32, ThreadTimeline> = HashMap::new();
    for event in events {
        let tl = map
            .entry(event.thread_id)
            .or_insert_with(|| ThreadTimeline {
                tid: event.thread_id,
                events: Vec::new(),
                first_pos: None,
                last_pos: None,
            });
        if tl.first_pos.is_none() {
            tl.first_pos = Some(event.position);
        }
        tl.last_pos = Some(event.position);
        tl.events.push(event);
    }
    map
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_ttd::{TraceMetadata, TracePosition};

    // ── helpers ──────────────────────────────────────────────────────────────

    fn make_meta() -> TraceMetadata {
        TraceMetadata {
            version: 1,
            process_name: "test".into(),
            pid: 1,
            arch: "x86_64".into(),
            start_time: 0,
            end_time: 100,
            thread_count: 1,
            ..Default::default()
        }
    }

    fn make_trace(n: u64) -> Arc<TtdTrace> {
        let t = Arc::new(TtdTrace::new(make_meta()));
        for i in 0..n {
            let kind = match i % 6 {
                0 => EventKind::MemRead {
                    addr: 0x1000 + i * 4,
                    len: 4,
                },
                1 => EventKind::MemWrite {
                    addr: 0x2000 + i * 4,
                    data: vec![0xaa, 0xbb],
                },
                2 => EventKind::Call {
                    from: 0x3000,
                    to: 0x4000 + i,
                },
                3 => EventKind::Return {
                    from: 0x4000 + i,
                    to: 0x3004,
                },
                4 => EventKind::SyscallEnter {
                    nr: u32::try_from(i).unwrap_or(u32::MAX),
                    args: [i; 6],
                },
                _ => EventKind::SyscallExit {
                    nr: u32::try_from(i).unwrap_or(u32::MAX),
                    ret: i * 2,
                },
            };
            t.add_event(TraceEvent {
                position: TracePosition::new(i, 0),
                thread_id: 1,
                kind,
            });
        }
        t
    }

    fn make_write_trace() -> Arc<TtdTrace> {
        let t = Arc::new(TtdTrace::new(make_meta()));
        t.add_event(TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::MemWrite {
                addr: 0x1000,
                data: vec![1, 2, 3, 4],
            },
        });
        t.add_event(TraceEvent {
            position: TracePosition::new(1, 0),
            thread_id: 1,
            kind: EventKind::MemRead {
                addr: 0x1000,
                len: 4,
            },
        });
        t.add_event(TraceEvent {
            position: TracePosition::new(2, 0),
            thread_id: 1,
            kind: EventKind::MemWrite {
                addr: 0x1000,
                data: vec![5, 6, 7, 8],
            },
        });
        t.add_event(TraceEvent {
            position: TracePosition::new(3, 0),
            thread_id: 1,
            kind: EventKind::Call {
                from: 0x5000,
                to: 0x6000,
            },
        });
        t
    }

    // ── MemPage ───────────────────────────────────────────────────────────────

    #[test]
    fn mem_page_new() {
        let p = MemPage::new(0x1000);
        assert_eq!(p.base, 0x1000);
        assert_eq!(p.data.len(), PAGE_SIZE);
        assert!(!p.dirty);
    }

    // ── MemoryState ───────────────────────────────────────────────────────────

    #[test]
    fn memory_state_write_and_read() {
        let mut m = MemoryState::new();
        m.apply_write(0x1000, &[1, 2, 3, 4]);
        let r = m.read(0x1000, 4).unwrap();
        assert_eq!(r, vec![1, 2, 3, 4]);
    }

    #[test]
    fn memory_state_read_unmap_returns_none() {
        let m = MemoryState::new();
        assert!(m.read(0x9999_0000, 4).is_none());
    }

    #[test]
    fn memory_state_write_cross_page() {
        let mut m = MemoryState::new();
        let addr = PAGE_SIZE as u64 - 2;
        m.apply_write(addr, &[0xAA, 0xBB, 0xCC, 0xDD]);
        let r = m.read(addr, 4).unwrap();
        assert_eq!(r, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn memory_state_diff_same() {
        let m1 = MemoryState::new();
        let m2 = MemoryState::new();
        assert!(m1.diff(&m2).is_empty());
    }

    #[test]
    fn memory_state_diff_different() {
        let mut m1 = MemoryState::new();
        let mut m2 = MemoryState::new();
        m1.apply_write(0x1000, &[1, 2, 3, 4]);
        m2.apply_write(0x1000, &[5, 6, 7, 8]);
        let diffs = m1.diff(&m2);
        assert_eq!(diffs.len(), 1);
        // address is the page base containing 0x1000 (0x1000 is already page-aligned)
        assert_eq!(diffs[0].address, 0x1000);
    }

    #[test]
    fn memory_state_page_count() {
        let mut m = MemoryState::new();
        m.apply_write(0x1000, &[1]);
        m.apply_write(0x5000, &[2]);
        assert_eq!(m.page_count(), 2);
    }

    #[test]
    fn memory_state_read_zero_len() {
        let m = MemoryState::new();
        assert_eq!(m.read(0x1000, 0), Some(vec![]));
    }

    // ── SnapshotCache ─────────────────────────────────────────────────────────

    #[test]
    fn snapshot_cache_nearest_before() {
        let mut cache = SnapshotCache::new(100);
        let snap = Snapshot::new(
            TracePosition::new(50, 0),
            MemoryState::new(),
            HashMap::new(),
        );
        cache.insert(snap);
        let found = cache.nearest_before(TracePosition::new(75, 0));
        assert!(found.is_some());
        assert_eq!(found.unwrap().position, TracePosition::new(50, 0));
    }

    #[test]
    fn snapshot_cache_nearest_before_none() {
        let cache = SnapshotCache::new(100);
        assert!(cache.nearest_before(TracePosition::new(10, 0)).is_none());
    }

    #[test]
    fn snapshot_cache_count() {
        let mut cache = SnapshotCache::new(100);
        assert_eq!(cache.snapshot_count(), 0);
        cache.insert(Snapshot::new(
            TracePosition::new(1, 0),
            MemoryState::new(),
            HashMap::new(),
        ));
        assert_eq!(cache.snapshot_count(), 1);
        cache.clear();
        assert_eq!(cache.snapshot_count(), 0);
    }

    #[test]
    fn snapshot_cache_contains() {
        let mut cache = SnapshotCache::new(10);
        let pos = TracePosition::new(10, 0);
        cache.insert(Snapshot::new(pos, MemoryState::new(), HashMap::new()));
        assert!(cache.contains(pos));
        assert!(!cache.contains(TracePosition::new(11, 0)));
    }

    // ── ReplayBreakpoint ──────────────────────────────────────────────────────

    #[test]
    fn breakpoint_new_and_display() {
        let bp = ReplayBreakpoint::new(1, 0x4000);
        assert!(bp.enabled);
        assert_eq!(bp.hit_count, 0);
        assert!(bp.to_string().contains("0x4000"));
    }

    #[test]
    fn breakpoint_fires_always() {
        let regs = HashMap::new();
        let mem = MemoryState::new();
        let bp = ReplayBreakpoint::new(1, 0x4000);
        assert!(bp.fires(0x4000, &regs, &mem));
        assert!(!bp.fires(0x5000, &regs, &mem));
    }

    #[test]
    fn breakpoint_fires_register_equals() {
        let mut regs = HashMap::new();
        regs.insert("rax".into(), 42u64);
        let mem = MemoryState::new();
        let bp =
            ReplayBreakpoint::new(1, 0x4000).with_condition(BreakpointCondition::RegisterEquals {
                reg: "rax".into(),
                value: 42,
            });
        assert!(bp.fires(0x4000, &regs, &mem));
        regs.insert("rax".into(), 99);
        assert!(!bp.fires(0x4000, &regs, &mem));
    }

    #[test]
    fn breakpoint_fires_disabled() {
        let regs = HashMap::new();
        let mem = MemoryState::new();
        let mut bp = ReplayBreakpoint::new(1, 0x4000);
        bp.enabled = false;
        assert!(!bp.fires(0x4000, &regs, &mem));
    }

    #[test]
    fn breakpoint_fires_hit_count_multiple() {
        let regs = HashMap::new();
        let mem = MemoryState::new();
        let bp = ReplayBreakpoint {
            id: 1,
            address: 0x1000,
            enabled: true,
            hit_count: 2,
            condition: Some(BreakpointCondition::HitCountMultiple(3)),
        };
        assert!(bp.fires(0x1000, &regs, &mem)); // (2+1) % 3 == 0
    }

    // ── Watchpoint ────────────────────────────────────────────────────────────

    #[test]
    fn watchpoint_overlaps() {
        let wp = Watchpoint::new(1, 0x1000, 16, WatchpointKind::Write);
        assert!(wp.overlaps(0x1008, 4));
        assert!(wp.overlaps(0x0ff8, 16));
        assert!(!wp.overlaps(0x1010, 4));
    }

    #[test]
    fn watchpoint_display() {
        let wp = Watchpoint::new(2, 0x2000, 8, WatchpointKind::ReadWrite);
        assert!(wp.to_string().contains("0x2000"));
    }

    // ── WatchpointSet ─────────────────────────────────────────────────────────

    #[test]
    fn watchpoint_set_add_remove() {
        let mut ws = WatchpointSet::new();
        ws.add(0x1000, 4);
        ws.add(0x2000, 8);
        assert_eq!(ws.watchpoints.len(), 2);
        assert!(ws.remove(0x1000));
        assert!(!ws.remove(0x9999));
    }

    #[test]
    fn watchpoint_set_matches() {
        let mut ws = WatchpointSet::new();
        ws.add(0x1000, 16);
        assert!(ws.matches(0x1000, 4));
        assert!(!ws.matches(0x2000, 4));
    }

    #[test]
    fn watchpoint_set_display() {
        let ws = WatchpointSet::new();
        assert!(ws.to_string().contains("count: 0"));
    }

    // ── ReplayEngine navigation ────────────────────────────────────────────────

    #[test]
    fn engine_step_forward_basic() {
        let trace = make_trace(5);
        let mut eng = ReplayEngine::new(trace);
        let r = eng.step_forward().unwrap();
        assert!(matches!(r, ReplayStopReason::StepComplete { .. }));
        assert_eq!(eng.current_position(), TracePosition::new(0, 0));
    }

    #[test]
    fn engine_step_forward_to_end() {
        let trace = make_trace(3);
        let mut eng = ReplayEngine::new(trace);
        for _ in 0..3 {
            eng.step_forward().unwrap();
        }
        let r = eng.step_forward().unwrap();
        assert!(matches!(r, ReplayStopReason::End));
    }

    #[test]
    fn engine_step_backward_at_start() {
        let trace = make_trace(5);
        let mut eng = ReplayEngine::new(trace);
        let r = eng.step_backward().unwrap();
        assert!(matches!(r, ReplayStopReason::Start));
    }

    #[test]
    fn engine_step_backward_after_steps() {
        let trace = make_trace(10);
        let mut eng = ReplayEngine::new(trace);
        eng.step_forward().unwrap();
        eng.step_forward().unwrap();
        eng.step_forward().unwrap();
        let r = eng.step_backward().unwrap();
        assert!(matches!(r, ReplayStopReason::StepComplete { .. }));
        assert_eq!(eng.current_position(), TracePosition::new(1, 0));
    }

    #[test]
    fn engine_go_to_start() {
        let trace = make_trace(10);
        let mut eng = ReplayEngine::new(trace);
        eng.step_forward().unwrap();
        eng.step_forward().unwrap();
        let r = eng.go_to_start().unwrap();
        assert!(matches!(r, ReplayStopReason::Start));
        assert_eq!(eng.current_position(), TracePosition::start());
    }

    #[test]
    fn engine_go_to_end() {
        let trace = make_trace(5);
        let mut eng = ReplayEngine::new(trace);
        let r = eng.go_to_end().unwrap();
        assert!(matches!(r, ReplayStopReason::End));
        assert_eq!(eng.current_position(), TracePosition::new(4, 0));
    }

    #[test]
    fn engine_run_forward_to_position() {
        let trace = make_trace(10);
        let mut eng = ReplayEngine::new(trace);
        let r = eng
            .run_forward_to_position(TracePosition::new(5, 0))
            .unwrap();
        assert!(matches!(r, ReplayStopReason::StepComplete { .. }));
        assert_eq!(eng.current_position(), TracePosition::new(5, 0));
    }

    #[test]
    fn engine_run_forward_to_position_invalid() {
        let trace = make_trace(5);
        let mut eng = ReplayEngine::new(trace);
        assert!(
            eng.run_forward_to_position(TracePosition::new(999, 0))
                .is_err()
        );
    }

    #[test]
    fn engine_run_backward_to_position() {
        let trace = make_trace(10);
        let mut eng = ReplayEngine::new(trace);
        eng.go_to_end().unwrap();
        let r = eng
            .run_backward_to_position(TracePosition::new(3, 0))
            .unwrap();
        assert!(matches!(r, ReplayStopReason::StepComplete { .. }));
        assert_eq!(eng.current_position(), TracePosition::new(3, 0));
    }

    #[test]
    fn engine_run_to_next_event_of_kind_call() {
        let trace = make_trace(10);
        let mut eng = ReplayEngine::new(trace);
        let r = eng
            .run_to_next_event_of_kind(&|k| matches!(k, EventKind::Call { .. }))
            .unwrap();
        assert!(matches!(r, ReplayStopReason::EventKindMatch { .. }));
    }

    #[test]
    fn engine_run_to_next_event_of_kind_end() {
        let trace = make_trace(3);
        let mut eng = ReplayEngine::new(trace);
        // No exceptions in the trace
        let r = eng
            .run_to_next_event_of_kind(&|k| matches!(k, EventKind::Exception { .. }))
            .unwrap();
        assert!(matches!(r, ReplayStopReason::End));
    }

    // ── Breakpoints ───────────────────────────────────────────────────────────

    #[test]
    fn engine_breakpoint_hit_on_call() {
        let t = Arc::new(TtdTrace::new(make_meta()));
        t.add_event(TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::Call {
                from: 0x3000,
                to: 0x4000,
            },
        });
        let mut eng = ReplayEngine::new(t);
        eng.add_breakpoint(0x4000);
        let r = eng.run_to_breakpoint_forward().unwrap();
        assert!(matches!(r, ReplayStopReason::BreakpointHit { .. }));
    }

    #[test]
    fn engine_add_remove_breakpoint() {
        let trace = make_trace(5);
        let mut eng = ReplayEngine::new(trace);
        let id = eng.add_breakpoint(0x1000);
        assert_eq!(eng.breakpoints().len(), 1);
        assert!(eng.remove_breakpoint(id));
        assert_eq!(eng.breakpoints().len(), 0);
        assert!(!eng.remove_breakpoint(id));
    }

    #[test]
    fn engine_enable_disable_breakpoint() {
        let trace = make_trace(5);
        let mut eng = ReplayEngine::new(trace);
        let id = eng.add_breakpoint(0x1000);
        assert!(eng.disable_breakpoint(id));
        assert!(!eng.breakpoints()[0].enabled);
        assert!(eng.enable_breakpoint(id));
        assert!(eng.breakpoints()[0].enabled);
    }

    #[test]
    fn engine_add_remove_watchpoint() {
        let trace = make_trace(5);
        let mut eng = ReplayEngine::new(trace);
        let id = eng.add_watchpoint(0x2000, 4, WatchpointKind::Write);
        assert_eq!(eng.watchpoints().len(), 1);
        assert!(eng.remove_watchpoint(id));
        assert_eq!(eng.watchpoints().len(), 0);
    }

    #[test]
    fn engine_watchpoint_fires_on_write() {
        let t = Arc::new(TtdTrace::new(make_meta()));
        t.add_event(TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::MemWrite {
                addr: 0x2000,
                data: vec![0xde, 0xad],
            },
        });
        let mut eng = ReplayEngine::new(t);
        eng.add_watchpoint(0x2000, 4, WatchpointKind::Write);
        let r = eng.step_forward().unwrap();
        assert!(matches!(r, ReplayStopReason::WatchpointHit { .. }));
    }

    // ── Query APIs ────────────────────────────────────────────────────────────

    #[test]
    fn engine_find_first_write_to() {
        let trace = make_write_trace();
        let eng = ReplayEngine::new(trace);
        let pos = eng.find_first_write_to(0x1000);
        assert_eq!(pos, Some(TracePosition::new(0, 0)));
    }

    #[test]
    fn engine_find_last_write_to() {
        let trace = make_write_trace();
        let eng = ReplayEngine::new(trace);
        let pos = eng.find_last_write_to(0x1000);
        assert_eq!(pos, Some(TracePosition::new(2, 0)));
    }

    #[test]
    fn engine_find_all_writes_to() {
        let trace = make_write_trace();
        let eng = ReplayEngine::new(trace);
        let writes = eng.find_all_writes_to(0x1000);
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].0, TracePosition::new(0, 0));
        assert_eq!(writes[1].0, TracePosition::new(2, 0));
    }

    #[test]
    fn engine_find_all_reads_from() {
        let trace = make_write_trace();
        let eng = ReplayEngine::new(trace);
        let reads = eng.find_all_reads_from(0x1000);
        assert_eq!(reads.len(), 1);
        assert_eq!(reads[0], TracePosition::new(1, 0));
    }

    #[test]
    fn engine_find_all_calls_to() {
        let trace = make_write_trace();
        let eng = ReplayEngine::new(trace);
        let calls = eng.find_all_calls_to(0x6000);
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn engine_find_all_calls_from() {
        let trace = make_write_trace();
        let eng = ReplayEngine::new(trace);
        let calls = eng.find_all_calls_from(0x5000);
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn engine_find_value_at() {
        let trace = make_write_trace();
        let eng = ReplayEngine::new(trace);
        let positions = eng.find_value_at(0x1000, &[5, 6, 7, 8]);
        assert_eq!(positions.len(), 1);
        assert_eq!(positions[0], TracePosition::new(2, 0));
    }

    #[test]
    fn engine_get_memory_at() {
        let trace = make_write_trace();
        let eng = ReplayEngine::new(trace);
        let mem = eng.get_memory_at(TracePosition::new(0, 0), 0x1000, 4);
        assert_eq!(mem, Some(vec![1, 2, 3, 4]));
    }

    #[test]
    fn engine_get_memory_at_after_second_write() {
        let trace = make_write_trace();
        let eng = ReplayEngine::new(trace);
        let mem = eng.get_memory_at(TracePosition::new(2, 0), 0x1000, 4);
        assert_eq!(mem, Some(vec![5, 6, 7, 8]));
    }

    #[test]
    fn engine_get_register_at_call() {
        let t = Arc::new(TtdTrace::new(make_meta()));
        t.add_event(TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::Call {
                from: 0x3000,
                to: 0x4000,
            },
        });
        let eng = ReplayEngine::new(t);
        let rip = eng.get_register_at(TracePosition::new(0, 0), 1, "rip");
        assert_eq!(rip, Some(0x4000));
    }

    #[test]
    fn engine_get_register_at_missing() {
        let trace = make_trace(3);
        let eng = ReplayEngine::new(trace);
        assert!(
            eng.get_register_at(TracePosition::new(999, 0), 1, "rax")
                .is_none()
        );
    }

    // ── Snapshot index ────────────────────────────────────────────────────────

    #[test]
    fn engine_build_snapshot_index() {
        let trace = make_trace(100);
        let mut eng = ReplayEngine::with_snapshot_interval(trace, 10);
        eng.build_snapshot_index();
        assert!(eng.snapshot_cache().snapshot_count() > 0);
    }

    #[test]
    fn engine_snapshot_enables_fast_backward() {
        let trace = make_trace(50);
        let mut eng = ReplayEngine::with_snapshot_interval(trace, 5);
        eng.go_to_end().unwrap();
        let r = eng
            .run_backward_to_position(TracePosition::new(10, 0))
            .unwrap();
        assert!(matches!(r, ReplayStopReason::StepComplete { .. }));
        assert_eq!(eng.current_position(), TracePosition::new(10, 0));
    }

    // ── Legacy APIs ───────────────────────────────────────────────────────────

    #[test]
    fn engine_legacy_step_forward_state() {
        let trace = make_trace(5);
        let mut eng = ReplayEngine::new(trace);
        let state = eng.step_forward_state().unwrap();
        assert_eq!(state.position, TracePosition::new(0, 0));
    }

    #[test]
    fn engine_legacy_goto() {
        let trace = make_trace(10);
        let mut eng = ReplayEngine::new(trace);
        let state = eng.goto(TracePosition::new(7, 0)).unwrap();
        assert_eq!(state.position, TracePosition::new(7, 0));
    }

    #[test]
    fn engine_legacy_goto_invalid() {
        let trace = make_trace(5);
        let mut eng = ReplayEngine::new(trace);
        assert!(eng.goto(TracePosition::new(999, 0)).is_err());
    }

    #[test]
    fn engine_legacy_save_restore_checkpoint() {
        let trace = make_trace(10);
        let mut eng = ReplayEngine::new(trace);
        eng.goto(TracePosition::new(4, 0)).unwrap();
        let cp = eng.save_checkpoint();
        eng.goto(TracePosition::new(8, 0)).unwrap();
        eng.restore_checkpoint(&cp).unwrap();
        assert_eq!(eng.current_position(), TracePosition::new(4, 0));
    }

    #[test]
    fn engine_legacy_set_watchpoints() {
        let trace = make_trace(5);
        let mut eng = ReplayEngine::new(trace);
        let mut ws = WatchpointSet::new();
        ws.add(0x1000, 4);
        eng.set_watchpoints(ws);
        assert_eq!(eng.watchpoints().len(), 1);
    }

    #[test]
    fn engine_debug_format() {
        let trace = make_trace(3);
        let eng = ReplayEngine::new(trace);
        let d = format!("{eng:?}");
        assert!(d.contains("ReplayEngine"));
    }

    // ── MemoryDelta ───────────────────────────────────────────────────────────

    #[test]
    fn delta_compressor_roundtrip() {
        let before = vec![0u8; 4];
        let after = vec![1u8, 2, 3, 4];
        let delta = DeltaCompressor::compute_delta(0x1000, &before, &after);
        let restored = DeltaCompressor::apply_delta(&before, &delta);
        assert_eq!(restored, after);
    }

    #[test]
    fn delta_compressor_extends_base() {
        let base = vec![0u8; 2];
        let delta = DeltaCompressor::compute_delta(0, &base, &[1, 2, 3, 4]);
        let result = DeltaCompressor::apply_delta(&base, &delta);
        assert_eq!(result, [1, 2, 3, 4]);
    }

    #[test]
    fn memory_delta_display() {
        let d = MemoryDelta {
            address: 0x1000,
            before: vec![],
            after: vec![1],
        };
        assert!(d.to_string().contains("0x1000"));
    }

    // ── TtdRecordingFile ──────────────────────────────────────────────────────

    #[test]
    fn recording_file_roundtrip() {
        let trace = make_trace(20);
        let rec = TtdRecordingFile::from_trace(&trace);
        let mut buf = Vec::new();
        rec.write_to(&mut buf).unwrap();
        let rec2 = TtdRecordingFile::read_from(&mut buf.as_slice()).unwrap();
        assert_eq!(rec2.events.len(), 20);
        assert_eq!(rec2.metadata.process_name, "test");
    }

    #[test]
    fn recording_file_into_trace() {
        let trace = make_trace(10);
        let rec = TtdRecordingFile::from_trace(&trace);
        let trace2 = rec.into_trace();
        assert_eq!(trace2.event_count(), 10);
    }

    #[test]
    fn recording_file_bad_magic() {
        let bad: &[u8] = b"BADBADBA\x01\x00\x00\x00";
        let mut cursor = std::io::Cursor::new(bad);
        let r = TtdRecordingFile::read_from(&mut cursor);
        assert!(r.is_err());
    }

    #[test]
    fn recording_file_debug() {
        let rec = TtdRecordingFile::new(make_meta());
        let d = format!("{rec:?}");
        assert!(d.contains("TtdRecordingFile"));
    }

    // ── EngineStateDb ─────────────────────────────────────────────────────────

    #[test]
    fn engine_state_db_breakpoints_roundtrip() {
        let db = EngineStateDb::open_in_memory().unwrap();
        let bps = vec![
            ReplayBreakpoint::new(1, 0x1000),
            ReplayBreakpoint {
                id: 2,
                address: 0x2000,
                enabled: false,
                hit_count: 5,
                condition: Some(BreakpointCondition::Always),
            },
        ];
        db.save_breakpoints(&bps).unwrap();
        let loaded = db.load_breakpoints().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].address, 0x1000);
        assert!(!loaded[1].enabled);
        assert_eq!(loaded[1].hit_count, 5);
    }

    #[test]
    fn engine_state_db_watchpoints_roundtrip() {
        let db = EngineStateDb::open_in_memory().unwrap();
        let wps = vec![Watchpoint::new(1, 0x3000, 8, WatchpointKind::ReadWrite)];
        db.save_watchpoints(&wps).unwrap();
        let loaded = db.load_watchpoints().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].address, 0x3000);
        assert_eq!(loaded[0].kind, WatchpointKind::ReadWrite);
    }

    #[test]
    fn engine_state_db_history_roundtrip() {
        let db = EngineStateDb::open_in_memory().unwrap();
        let hist = vec![
            TracePosition::new(0, 0),
            TracePosition::new(1, 0),
            TracePosition::new(5, 0),
        ];
        db.save_history(&hist).unwrap();
        let loaded = db.load_history().unwrap();
        assert_eq!(loaded, hist);
    }

    // ── compute_memory_access_stats ───────────────────────────────────────────

    #[test]
    fn memory_access_stats_basic() {
        let trace = make_write_trace();
        let stats = compute_memory_access_stats(&trace, 0x1000, 0x2000);
        assert_eq!(stats.read_count, 1);
        assert_eq!(stats.write_count, 2);
        assert!(stats.total_accesses() == 3);
        assert!(stats.first_access.is_some());
        assert!(stats.last_access.is_some());
    }

    #[test]
    fn memory_access_stats_out_of_range() {
        let trace = make_write_trace();
        let stats = compute_memory_access_stats(&trace, 0xffff_0000, 0xffff_ffff);
        assert_eq!(stats.total_accesses(), 0);
    }

    #[test]
    fn memory_access_stats_display() {
        let s = MemoryAccessStats::default();
        let d = s.to_string();
        assert!(d.contains("reads: 0"));
    }

    // ── build_call_graph ──────────────────────────────────────────────────────

    #[test]
    fn call_graph_basic() {
        let t = Arc::new(TtdTrace::new(make_meta()));
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
                from: 0x1000,
                to: 0x2000,
            },
        });
        let graph = build_call_graph(&t);
        assert_eq!(graph.len(), 1);
        assert_eq!(graph[0].count, 2);
    }

    // ── split_by_thread ───────────────────────────────────────────────────────

    #[test]
    fn split_by_thread_basic() {
        let t = Arc::new(TtdTrace::new(make_meta()));
        for i in 0u64..4 {
            t.add_event(TraceEvent {
                position: TracePosition::new(i, 0),
                thread_id: if i.is_multiple_of(2) { 1 } else { 2 },
                kind: EventKind::MemRead {
                    addr: 0x1000,
                    len: 4,
                },
            });
        }
        let timelines = split_by_thread(&t);
        assert_eq!(timelines[&1].event_count(), 2);
        assert_eq!(timelines[&2].event_count(), 2);
    }

    // ── ReplayStopReason display ──────────────────────────────────────────────

    #[test]
    fn stop_reason_display_end() {
        assert_eq!(ReplayStopReason::End.to_string(), "End");
    }

    #[test]
    fn stop_reason_display_bp_hit() {
        let r = ReplayStopReason::BreakpointHit {
            bp_id: 3,
            position: TracePosition::new(5, 0),
        };
        assert!(r.to_string().contains("id=3"));
    }

    #[test]
    fn stop_reason_display_wp_hit() {
        let r = ReplayStopReason::WatchpointHit {
            wp_id: 2,
            position: TracePosition::new(1, 0),
            old_value: vec![],
            new_value: vec![1],
        };
        assert!(r.to_string().contains("id=2"));
    }

    // ── ReplayError ───────────────────────────────────────────────────────────

    #[test]
    fn replay_error_invalid_trace() {
        let e = ReplayError::InvalidTrace("bad".into());
        assert!(e.to_string().contains("bad"));
    }

    #[test]
    fn replay_error_position_not_found() {
        let e = ReplayError::PositionNotFound(TracePosition::new(5, 0));
        assert!(e.to_string().contains("5:0"));
    }

    #[test]
    fn replay_error_state_restore() {
        let e = ReplayError::StateRestoreError("oops".into());
        assert!(e.to_string().contains("oops"));
    }

    #[test]
    fn replay_error_serialization() {
        let e = ReplayError::SerializationError("json err".into());
        assert!(e.to_string().contains("json err"));
    }

    // ── run_to_breakpoint_backward ────────────────────────────────────────────

    #[test]
    fn engine_run_to_breakpoint_backward_no_bp() {
        let trace = make_trace(10);
        let mut eng = ReplayEngine::new(trace);
        eng.go_to_end().unwrap();
        // No breakpoints set — should reach Start
        let r = eng.run_to_breakpoint_backward().unwrap();
        assert!(matches!(r, ReplayStopReason::Start));
    }

    #[test]
    fn engine_run_to_breakpoint_forward_no_bp() {
        let trace = make_trace(5);
        let mut eng = ReplayEngine::new(trace);
        let r = eng.run_to_breakpoint_forward().unwrap();
        assert!(matches!(r, ReplayStopReason::End));
    }

    // ── history ───────────────────────────────────────────────────────────────

    #[test]
    fn engine_history_grows_on_step() {
        let trace = make_trace(5);
        let mut eng = ReplayEngine::new(trace);
        eng.step_forward().unwrap();
        eng.step_forward().unwrap();
        assert_eq!(eng.history().len(), 2);
    }

    #[test]
    fn engine_history_cleared_on_go_to_start() {
        let trace = make_trace(5);
        let mut eng = ReplayEngine::new(trace);
        eng.step_forward().unwrap();
        eng.go_to_start().unwrap();
        assert!(eng.history().is_empty());
    }

    // ── mem_diff ──────────────────────────────────────────────────────────────

    #[test]
    fn mem_diff_display() {
        let d = MemDiff {
            address: 0x5000,
            before: vec![0],
            after: vec![1],
        };
        assert!(d.to_string().contains("0x5000"));
    }

    // ── MemPage display ───────────────────────────────────────────────────────

    #[test]
    fn watch_address_display() {
        let w = WatchAddress {
            addr: 0xdead,
            size: 4,
        };
        assert!(w.to_string().contains("0xdead"));
    }

    // ── ReplayState ───────────────────────────────────────────────────────────

    #[test]
    fn replay_state_default() {
        let s = ReplayState::default();
        assert_eq!(s.position, TracePosition::start());
        assert!(s.registers.contains_key("rip"));
    }

    #[test]
    fn replay_state_display() {
        let s = ReplayState::default();
        assert!(s.to_string().contains("ReplayState"));
    }

    // ── apply_event_to_state ──────────────────────────────────────────────────

    #[test]
    fn apply_event_mem_write() {
        let mut s = ReplayState::default();
        let e = TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::MemWrite {
                addr: 0x5000,
                data: vec![0xde, 0xad],
            },
        };
        ReplayEngine::apply_event_to_state(&mut s, &e);
        // `apply_event_to_state` now uses full 4 KiB page-aligned storage to
        // mirror `MemoryState::apply_write`; the written bytes live at the
        // start of the page rooted at `0x5000`.
        let page = s.memory_pages.get(&0x5000).unwrap();
        assert_eq!(&page[..2], &[0xde, 0xad]);
        assert_eq!(page.len(), 0x1000);
    }

    #[test]
    fn apply_event_call_updates_rip() {
        let mut s = ReplayState::default();
        let e = TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::Call {
                from: 0x1000,
                to: 0x2000,
            },
        };
        ReplayEngine::apply_event_to_state(&mut s, &e);
        assert_eq!(s.registers["rip"], 0x2000);
    }

    #[test]
    fn apply_event_syscall_exit_rax() {
        let mut s = ReplayState::default();
        let e = TraceEvent {
            position: TracePosition::new(0, 0),
            thread_id: 1,
            kind: EventKind::SyscallExit { nr: 1, ret: 42 },
        };
        ReplayEngine::apply_event_to_state(&mut s, &e);
        assert_eq!(s.registers["rax"], 42);
    }
}
