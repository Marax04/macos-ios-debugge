//! Execution timeline: structured view over a TTD trace.
//!
//! `TimelineEvent` provides richer semantic labels than the raw `TraceEvent`.
//! `TimelineBuilder` converts a `TtdTrace` into a `Timeline`.
//! Filtering APIs allow narrowing by thread, type, address range, etc.
//! `Timeline::export_to_json` serialises the timeline for external tools.

use std::collections::HashMap;
use std::fmt;
use serde::{Deserialize, Serialize};

use crate::{TtdTrace, TraceEvent};

// ─── TimelineEventKind ────────────────────────────────────────────────────────

/// Semantic kind of a timeline event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TimelineEventKind {
    /// A function call (Call or `SyscallEntry`).
    Call,
    /// A function return (Return or `SyscallExit`).
    Return,
    /// A CPU / software exception / signal.
    Exception,
    /// A kernel-originated memory write.
    MemoryWrite,
    /// Thread creation.
    ThreadCreate,
    /// Thread exit.
    ThreadExit,
    /// Module load event.
    ModuleLoad,
    /// Module unload event.
    ModuleUnload,
    /// A custom / user-defined event.
    Custom,
}

impl fmt::Display for TimelineEventKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Call         => "call",
            Self::Return       => "return",
            Self::Exception    => "exception",
            Self::MemoryWrite  => "mem-write",
            Self::ThreadCreate => "thread-create",
            Self::ThreadExit   => "thread-exit",
            Self::ModuleLoad   => "module-load",
            Self::ModuleUnload => "module-unload",
            Self::Custom       => "custom",
        };
        write!(f, "{s}")
    }
}

// ─── TimelineEvent ────────────────────────────────────────────────────────────

/// One rich-annotated event in the execution timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    /// Trace tick.
    pub tick: u64,
    /// Semantic kind.
    pub kind: TimelineEventKind,
    /// Logical thread ID (0 = unknown).
    pub thread_id: u64,
    /// Target address (call target, write address, signal PC).
    pub address: Option<u64>,
    /// Module name (if known).
    pub module: Option<String>,
    /// Function / symbol name (if known).
    pub symbol: Option<String>,
    /// Associated syscall number (for Call/Return events).
    pub syscall_nr: Option<u64>,
    /// Return value (for Return events).
    pub return_value: Option<i64>,
    /// Memory write bytes (for `MemoryWrite` events).
    pub write_data: Option<Vec<u8>>,
    /// Signal number (for Exception events).
    pub signal: Option<i32>,
    /// Arbitrary extra data.
    pub metadata: HashMap<String, String>,
}

impl TimelineEvent {
    /// Create a minimal call event.
    #[must_use]
    pub fn call(tick: u64, thread_id: u64, nr: u64) -> Self {
        Self {
            tick, kind: TimelineEventKind::Call, thread_id,
            address: None, module: None, symbol: None,
            syscall_nr: Some(nr), return_value: None,
            write_data: None, signal: None, metadata: HashMap::new(),
        }
    }

    /// Create a return event.
    #[must_use]
    pub fn ret(tick: u64, thread_id: u64, nr: u64, retval: i64) -> Self {
        Self {
            tick, kind: TimelineEventKind::Return, thread_id,
            address: None, module: None, symbol: None,
            syscall_nr: Some(nr), return_value: Some(retval),
            write_data: None, signal: None, metadata: HashMap::new(),
        }
    }

    /// Create a memory-write event.
    #[must_use]
    pub fn mem_write(tick: u64, thread_id: u64, addr: u64, data: Vec<u8>) -> Self {
        Self {
            tick, kind: TimelineEventKind::MemoryWrite, thread_id,
            address: Some(addr), module: None, symbol: None,
            syscall_nr: None, return_value: None,
            write_data: Some(data), signal: None, metadata: HashMap::new(),
        }
    }

    /// Create an exception/signal event.
    #[must_use]
    pub fn exception(tick: u64, thread_id: u64, signal: i32, pc: u64) -> Self {
        Self {
            tick, kind: TimelineEventKind::Exception, thread_id,
            address: Some(pc), module: None, symbol: None,
            syscall_nr: None, return_value: None,
            write_data: None, signal: Some(signal), metadata: HashMap::new(),
        }
    }

    /// Attach a symbol name.
    #[must_use]
    pub fn with_symbol(mut self, symbol: impl Into<String>) -> Self {
        self.symbol = Some(symbol.into());
        self
    }

    /// Attach a module name.
    #[must_use]
    pub fn with_module(mut self, module: impl Into<String>) -> Self {
        self.module = Some(module.into());
        self
    }

    /// Add a metadata key-value pair.
    pub fn add_meta(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }
}

impl fmt::Display for TimelineEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{:016}] {:12} thr={}", self.tick, self.kind, self.thread_id)?;
        if let Some(nr) = self.syscall_nr { write!(f, " nr={nr}")?; }
        if let Some(addr) = self.address  { write!(f, " addr={addr:#x}")?; }
        if let Some(ret) = self.return_value { write!(f, " retval={ret}")?; }
        Ok(())
    }
}

// ─── Timeline ─────────────────────────────────────────────────────────────────

/// An ordered, filterable sequence of `TimelineEvent`s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Timeline {
    /// All events, sorted by tick ascending.
    pub events: Vec<TimelineEvent>,
    /// Source trace metadata.
    pub trace_min_tick: u64,
    pub trace_max_tick: u64,
}

impl Timeline {
    /// Create an empty timeline.
    #[must_use]
    pub const fn new() -> Self {
        Self { events: vec![], trace_min_tick: 0, trace_max_tick: 0 }
    }

    /// Number of events.
    #[must_use]
    pub const fn len(&self) -> usize { self.events.len() }

    /// True if empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool { self.events.is_empty() }

    /// Filter events by kind.
    #[must_use]
    pub fn filter_by_type(&self, kind: TimelineEventKind) -> Vec<&TimelineEvent> {
        self.events.iter().filter(|e| e.kind == kind).collect()
    }

    /// Filter events by thread ID.
    #[must_use]
    pub fn filter_by_thread(&self, thread_id: u64) -> Vec<&TimelineEvent> {
        self.events.iter().filter(|e| e.thread_id == thread_id).collect()
    }

    /// Filter events whose `address` falls within `[lo, hi)`.
    #[must_use]
    pub fn filter_by_address_range(&self, lo: u64, hi: u64) -> Vec<&TimelineEvent> {
        self.events.iter()
            .filter(|e| e.address.is_some_and(|a| a >= lo && a < hi))
            .collect()
    }

    /// Filter events in tick range `[from, to]`.
    #[must_use]
    pub fn filter_by_tick_range(&self, from: u64, to: u64) -> Vec<&TimelineEvent> {
        self.events.iter().filter(|e| e.tick >= from && e.tick <= to).collect()
    }

    /// Filter by syscall number.
    #[must_use]
    pub fn filter_by_syscall(&self, nr: u64) -> Vec<&TimelineEvent> {
        self.events.iter()
            .filter(|e| e.syscall_nr == Some(nr))
            .collect()
    }

    /// Filter memory-write events that touch `[addr, addr+size)`.
    #[must_use]
    pub fn filter_writes_to(&self, addr: u64, size: usize) -> Vec<&TimelineEvent> {
        self.events.iter().filter(|e| {
            if e.kind != TimelineEventKind::MemoryWrite { return false; }
            let Some(ea) = e.address else { return false; };
            let data_len = e.write_data.as_ref().map_or(0, std::vec::Vec::len);
            let end_addr = addr + size as u64;
            let write_end = ea + data_len as u64;
            ea < end_addr && addr < write_end
        }).collect()
    }

    /// Count events of each kind.
    #[must_use]
    pub fn count_by_kind(&self) -> HashMap<TimelineEventKind, usize> {
        let mut m: HashMap<TimelineEventKind, usize> = HashMap::new();
        for e in &self.events {
            *m.entry(e.kind).or_insert(0) += 1;
        }
        m
    }

    /// Unique thread IDs present in the timeline.
    #[must_use]
    pub fn thread_ids(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.events.iter().map(|e| e.thread_id).collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Serialise the timeline to a JSON string.
    ///
    /// # Errors
    /// Returns a `serde_json::Error` string on failure.
    pub fn export_to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    /// Import a timeline from a JSON string.
    ///
    /// # Errors
    /// Returns a `serde_json::Error` string on failure.
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| e.to_string())
    }
}

impl Default for Timeline {
    fn default() -> Self { Self::new() }
}

// ─── TimelineBuilder ─────────────────────────────────────────────────────────

/// Converts a `TtdTrace` into a `Timeline`.
///
/// Thread assignment heuristic: each unpaired `SyscallEntry` opens a "thread slot";
/// a matching `SyscallExit` closes it.  In practice most traces are single-threaded
/// and all events get `thread_id=0`.
#[derive(Debug, Default)]
pub struct TimelineBuilder {
    /// Syscall name database: nr → name.
    syscall_names: HashMap<u64, String>,
    /// Module map: (base, end) → name.
    module_map: Vec<(u64, u64, String)>,
    /// Current open syscalls: `thread_slot` → (nr, `entry_tick`).
    open_syscalls: Vec<(u64, u64)>,
}

impl TimelineBuilder {
    /// Create a builder.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Register a syscall name.
    pub fn add_syscall_name(&mut self, nr: u64, name: impl Into<String>) {
        self.syscall_names.insert(nr, name.into());
    }

    /// Register a module address range.
    pub fn add_module(&mut self, base: u64, end: u64, name: impl Into<String>) {
        self.module_map.push((base, end, name.into()));
    }

    /// Populate Linux x86-64 syscall names (subset).
    pub fn add_linux_x86_64_syscalls(&mut self) {
        let names = [
            (0, "read"), (1, "write"), (2, "open"), (3, "close"),
            (4, "stat"), (5, "fstat"), (6, "lstat"), (9, "mmap"),
            (11, "munmap"), (12, "brk"), (21, "access"), (32, "dup"),
            (59, "execve"), (60, "exit"), (62, "kill"), (231, "exit_group"),
        ];
        for (nr, name) in names {
            self.add_syscall_name(nr, name);
        }
    }

    /// Resolve an address to a module name.
    fn module_for_addr(&self, addr: u64) -> Option<&str> {
        self.module_map.iter()
            .find(|(base, end, _)| addr >= *base && addr < *end)
            .map(|(_, _, name)| name.as_str())
    }

    /// Resolve a syscall number to a name.
    fn syscall_name(&self, nr: u64) -> Option<&str> {
        self.syscall_names.get(&nr).map(std::string::String::as_str)
    }

    /// Build a `Timeline` from `trace`.
    #[must_use]
    pub fn build(&mut self, trace: &TtdTrace) -> Timeline {
        let mut events = Vec::with_capacity(trace.events.len() * 2);
        let min_tick = trace.min_tick();
        let max_tick = trace.max_tick();

        for raw in &trace.events {
            match raw {
                TraceEvent::SyscallEntry { tick, nr, .. } => {
                    let mut ev = TimelineEvent::call(*tick, 0, *nr);
                    if let Some(name) = self.syscall_name(*nr) {
                        ev.symbol = Some(name.to_string());
                    }
                    self.open_syscalls.push((*nr, *tick));
                    events.push(ev);
                }
                TraceEvent::SyscallExit { tick, retval, mem_writes } => {
                    let nr = self.open_syscalls.pop().map_or(0, |(n, _)| n);
                    let mut ev = TimelineEvent::ret(*tick, 0, nr, *retval);
                    if let Some(name) = self.syscall_name(nr) {
                        ev.symbol = Some(name.to_string());
                    }
                    events.push(ev);

                    // Emit one MemoryWrite event per write record
                    for wr in mem_writes {
                        let mut mev = TimelineEvent::mem_write(*tick, 0, wr.addr, wr.data.clone());
                        if let Some(m) = self.module_for_addr(wr.addr) {
                            mev.module = Some(m.to_string());
                        }
                        events.push(mev);
                    }
                }
                TraceEvent::SignalDelivered { tick, signal, pc } => {
                    let mut ev = TimelineEvent::exception(*tick, 0, *signal, *pc);
                    if let Some(m) = self.module_for_addr(*pc) {
                        ev.module = Some(m.to_string());
                    }
                    events.push(ev);
                }
            }
        }

        // Sort by tick (stable, preserving insertion order for same-tick events)
        events.sort_by_key(|e| e.tick);

        Timeline { events, trace_min_tick: min_tick, trace_max_tick: max_tick }
    }
}

// ─── TimelineDiff ─────────────────────────────────────────────────────────────

/// Difference between two timelines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineDiff {
    /// Events in `a` but not in `b` (by tick+kind combination).
    pub only_in_a: Vec<TimelineEvent>,
    /// Events in `b` but not in `a`.
    pub only_in_b: Vec<TimelineEvent>,
    /// Tick ranges where both timelines have events.
    pub common_ticks: Vec<u64>,
}

impl TimelineDiff {
    /// Compute a shallow diff between two timelines.
    #[must_use]
    pub fn compute(a: &Timeline, b: &Timeline) -> Self {
        let a_ticks: std::collections::HashSet<u64> =
            a.events.iter().map(|e| e.tick).collect();
        let b_ticks: std::collections::HashSet<u64> =
            b.events.iter().map(|e| e.tick).collect();

        let only_in_a = a.events.iter()
            .filter(|e| !b_ticks.contains(&e.tick))
            .cloned().collect();
        let only_in_b = b.events.iter()
            .filter(|e| !a_ticks.contains(&e.tick))
            .cloned().collect();
        let mut common_ticks: Vec<u64> = a_ticks.intersection(&b_ticks).copied().collect();
        common_ticks.sort_unstable();

        Self { only_in_a, only_in_b, common_ticks }
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TraceBuilder, MemWriteRecord};

    fn build_timeline() -> Timeline {
        let mut tb = TraceBuilder::new(256);
        tb.syscall_entry(1, [0; 6]);
        tb.syscall_exit(0, vec![]);
        tb.syscall_entry(2, [0; 6]);
        tb.syscall_exit(42, vec![
            MemWriteRecord::new(0x5000, vec![0x01, 0x02, 0x03, 0x04]),
        ]);
        tb.signal(11, 0x4000);
        let trace = tb.build();
        let mut builder = TimelineBuilder::new();
        builder.add_linux_x86_64_syscalls();
        builder.build(&trace)
    }

    #[test]
    fn test_timeline_basic_build() {
        let tl = build_timeline();
        assert!(!tl.is_empty());
        // Call + Return pairs + MemWrite + Exception
        assert!(tl.len() >= 5);
    }

    #[test]
    fn test_timeline_filter_by_type_call() {
        let tl = build_timeline();
        let calls = tl.filter_by_type(TimelineEventKind::Call);
        assert!(!calls.is_empty());
    }

    #[test]
    fn test_timeline_filter_by_type_mem_write() {
        let tl = build_timeline();
        let writes = tl.filter_by_type(TimelineEventKind::MemoryWrite);
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].address, Some(0x5000));
    }

    #[test]
    fn test_timeline_filter_by_type_exception() {
        let tl = build_timeline();
        let excs = tl.filter_by_type(TimelineEventKind::Exception);
        assert_eq!(excs.len(), 1);
        assert_eq!(excs[0].signal, Some(11));
    }

    #[test]
    fn test_timeline_filter_by_thread() {
        let tl = build_timeline();
        let evs = tl.filter_by_thread(0);
        assert_eq!(evs.len(), tl.len()); // all thread_id=0
    }

    #[test]
    fn test_timeline_filter_by_address_range() {
        let tl = build_timeline();
        let evs = tl.filter_by_address_range(0x4000, 0x6000);
        assert!(!evs.is_empty());
    }

    #[test]
    fn test_timeline_filter_writes_to() {
        let tl = build_timeline();
        let writes = tl.filter_writes_to(0x5000, 4);
        assert_eq!(writes.len(), 1);
    }

    #[test]
    fn test_timeline_filter_writes_to_no_match() {
        let tl = build_timeline();
        let writes = tl.filter_writes_to(0x9999, 4);
        assert!(writes.is_empty());
    }

    #[test]
    fn test_timeline_count_by_kind() {
        let tl = build_timeline();
        let counts = tl.count_by_kind();
        assert!(counts.get(&TimelineEventKind::Call).copied().unwrap_or(0) > 0);
        assert!(counts.get(&TimelineEventKind::MemoryWrite).copied().unwrap_or(0) > 0);
    }

    #[test]
    fn test_timeline_thread_ids() {
        let tl = build_timeline();
        let ids = tl.thread_ids();
        assert_eq!(ids, vec![0]);
    }

    #[test]
    fn test_timeline_export_import_json() {
        let tl = build_timeline();
        let json = tl.export_to_json().unwrap();
        let re_imported = Timeline::from_json(&json).unwrap();
        assert_eq!(re_imported.len(), tl.len());
    }

    #[test]
    fn test_timeline_event_display() {
        let e = TimelineEvent::call(100, 0, 1);
        let s = format!("{e}");
        assert!(s.contains("call"));
        assert!(s.contains("100"));
    }

    #[test]
    fn test_timeline_event_with_symbol_module() {
        let e = TimelineEvent::call(1, 0, 1)
            .with_symbol("write")
            .with_module("libc.so");
        assert_eq!(e.symbol.as_deref(), Some("write"));
        assert_eq!(e.module.as_deref(), Some("libc.so"));
    }

    #[test]
    fn test_timeline_diff() {
        let t1 = build_timeline();
        let t2 = build_timeline();
        let diff = TimelineDiff::compute(&t1, &t2);
        assert!(diff.only_in_a.is_empty());
        assert!(diff.only_in_b.is_empty());
        assert!(!diff.common_ticks.is_empty());
    }

    #[test]
    fn test_timeline_builder_module_resolution() {
        let mut b = TimelineBuilder::new();
        b.add_module(0x4000, 0x8000, "my_module");
        assert_eq!(b.module_for_addr(0x5000), Some("my_module"));
        assert_eq!(b.module_for_addr(0x9000), None);
    }

    #[test]
    fn test_timeline_filter_by_tick_range() {
        let tl = build_timeline();
        let evs = tl.filter_by_tick_range(0, 2);
        assert!(evs.iter().all(|e| e.tick <= 2));
    }

    #[test]
    fn test_timeline_kind_display() {
        assert_eq!(TimelineEventKind::Call.to_string(), "call");
        assert_eq!(TimelineEventKind::MemoryWrite.to_string(), "mem-write");
        assert_eq!(TimelineEventKind::Exception.to_string(), "exception");
    }

    #[test]
    fn test_timeline_empty() {
        let tl = Timeline::new();
        assert!(tl.is_empty());
        assert_eq!(tl.len(), 0);
    }
}
