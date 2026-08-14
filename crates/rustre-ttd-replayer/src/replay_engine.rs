// TTD Replay Engine — forward/backward stepping over a recorded execution
// trace.  The engine operates on `TtdTrace` (from lib.rs) but adds:
//   * Tick-indexed event lookup (O(log n))
//   * Forward step / backward step at instruction granularity
//   * Seek to absolute tick with state reconstruction
//   * Breakpoints (address, register-change, memory-write, event-type)
//   * Run-until (forward/backward) until breakpoint or end-of-trace

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

// ── Primitive types ───────────────────────────────────────────────────────────

pub type Tick = u64;
pub type Addr = u64;
pub type RegVal = u64;

// ── Register file ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegisterFile {
    pub regs: HashMap<String, RegVal>,
    pub flags: u64,
    pub pc: u64,
    pub sp: u64,
}

impl RegisterFile {
    pub fn set(&mut self, name: &str, val: RegVal) {
        match name {
            "pc" | "rip" | "eip" => self.pc = val,
            "sp" | "rsp" | "esp" => self.sp = val,
            "flags" | "rflags" | "eflags" => self.flags = val,
            _ => { self.regs.insert(name.to_string(), val); }
        }
    }
    #[must_use] 
    pub fn get(&self, name: &str) -> Option<RegVal> {
        match name {
            "pc" | "rip" | "eip" => Some(self.pc),
            "sp" | "rsp" | "esp" => Some(self.sp),
            "flags" | "rflags" | "eflags" => Some(self.flags),
            _ => self.regs.get(name).copied(),
        }
    }
    #[must_use] 
    pub fn diff(&self, other: &Self) -> Vec<(String, RegVal, RegVal)> {
        let mut diffs = Vec::new();
        if self.pc != other.pc { diffs.push(("pc".into(), self.pc, other.pc)); }
        if self.sp != other.sp { diffs.push(("sp".into(), self.sp, other.sp)); }
        if self.flags != other.flags { diffs.push(("flags".into(), self.flags, other.flags)); }
        for (k, &v) in &self.regs {
            let ov = other.regs.get(k).copied().unwrap_or(0);
            if v != ov { diffs.push((k.clone(), v, ov)); }
        }
        diffs
    }
}

// ── Memory snapshot ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct MemorySnapshot {
    /// Sparse page map: `page_addr` → 4096-byte page.
    pub pages: BTreeMap<Addr, Box<[u8; 4096]>>,
}

impl MemorySnapshot {
    const PAGE_SIZE: u64 = 4096;

    #[must_use] 
    pub fn read_byte(&self, addr: Addr) -> Option<u8> {
        let page_addr = addr & !(Self::PAGE_SIZE - 1);
        let offset = (addr - page_addr) as usize;
        self.pages.get(&page_addr).map(|p| p[offset])
    }

    pub fn write_byte(&mut self, addr: Addr, val: u8) {
        let page_addr = addr & !(Self::PAGE_SIZE - 1);
        let offset = (addr - page_addr) as usize;
        let page = self.pages.entry(page_addr).or_insert_with(|| Box::new([0u8; 4096]));
        page[offset] = val;
    }

    #[must_use] 
    pub fn read_slice(&self, addr: Addr, len: usize) -> Vec<u8> {
        (0..len as u64).map(|i| self.read_byte(addr + i).unwrap_or(0)).collect()
    }

    pub fn write_slice(&mut self, addr: Addr, data: &[u8]) {
        for (i, &b) in data.iter().enumerate() {
            self.write_byte(addr + i as u64, b);
        }
    }

    #[must_use] 
    pub fn read_u64_le(&self, addr: Addr) -> u64 {
        let b = self.read_slice(addr, 8);
        u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))
    }

    #[must_use] 
    pub fn read_u32_le(&self, addr: Addr) -> u32 {
        let b = self.read_slice(addr, 4);
        u32::from_le_bytes(b.try_into().unwrap_or([0; 4]))
    }

    pub fn write_u64_le(&mut self, addr: Addr, val: u64) {
        self.write_slice(addr, &val.to_le_bytes());
    }

    /// Return the number of mapped bytes.
    #[must_use] 
    pub fn mapped_bytes(&self) -> u64 {
        self.pages.len() as u64 * Self::PAGE_SIZE
    }

    /// Clone only pages that overlap [start, start+len).
    #[must_use] 
    pub fn clone_range(&self, start: Addr, len: u64) -> Self {
        let page_start = start & !(Self::PAGE_SIZE - 1);
        let page_end = (start + len + Self::PAGE_SIZE - 1) & !(Self::PAGE_SIZE - 1);
        let mut snap = Self::default();
        for (&pa, page) in self.pages.range(page_start..page_end) {
            snap.pages.insert(pa, page.clone());
        }
        snap
    }
}

// ── Trace event (minimal, from external trace file) ──────────────────────────

#[derive(Debug, Clone)]
pub struct TraceEvent {
    pub tick: Tick,
    pub kind: EventKind,
    pub thread_id: u32,
    pub module_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventKind {
    InstructionExecuted { pc: u64 },
    MemoryWrite { addr: u64, size: u8, value: u64 },
    MemoryRead  { addr: u64, size: u8 },
    ModuleLoad  { base: u64, size: u64, name: String },
    ModuleUnload { base: u64 },
    ThreadCreate { id: u32 },
    ThreadExit   { id: u32, exit_code: u32 },
    Exception    { code: u32, addr: u64 },
    SyscallEnter { number: u32 },
    SyscallExit  { number: u32, retval: i64 },
    RegisterChange { name: String, old_val: u64, new_val: u64 },
    Custom(String),
}

// ── Trace container ───────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct TraceData {
    pub events: Vec<TraceEvent>,
    /// Tick-indexed range: events[`tick_index`[t]..`tick_index`[t+1]] happen at tick t.
    tick_index: BTreeMap<Tick, usize>,
    /// Full-state checkpoints at key ticks for fast backward seek.
    pub checkpoints: BTreeMap<Tick, EngineState>,
    pub module_map: BTreeMap<u64, (u64, String)>,
    pub first_tick: Tick,
    pub last_tick: Tick,
}

impl TraceData {
    pub fn build_index(&mut self) {
        self.tick_index.clear();
        for (i, ev) in self.events.iter().enumerate() {
            self.tick_index.entry(ev.tick).or_insert(i);
        }
        self.first_tick = self.events.first().map_or(0, |e| e.tick);
        self.last_tick = self.events.last().map_or(0, |e| e.tick);
    }

    #[must_use] 
    pub fn events_at_tick(&self, tick: Tick) -> &[TraceEvent] {
        let start = match self.tick_index.get(&tick) {
            Some(&i) => i,
            None => return &[],
        };
        // Find end
        let end = self.tick_index.range(tick + 1..)
            .next()
            .map_or(self.events.len(), |(_, &i)| i);
        &self.events[start..end]
    }

    #[must_use] 
    pub fn events_in_range(&self, from: Tick, to: Tick) -> &[TraceEvent] {
        let start = self.tick_index.range(from..)
            .next().map_or(self.events.len(), |(_, &i)| i);
        let end = self.tick_index.range(to + 1..)
            .next().map_or(self.events.len(), |(_, &i)| i);
        &self.events[start..end]
    }

    /// Add a checkpoint every `interval` ticks while replaying forward.
    pub fn add_checkpoint(&mut self, tick: Tick, state: EngineState) {
        self.checkpoints.insert(tick, state);
    }

    #[must_use] 
    pub fn nearest_checkpoint_before(&self, tick: Tick) -> Option<(Tick, &EngineState)> {
        self.checkpoints.range(..=tick).next_back().map(|(&t, s)| (t, s))
    }
}

// ── Full engine state (register file + memory) ────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct EngineState {
    pub tick: Tick,
    pub regs: RegisterFile,
    pub memory: MemorySnapshot,
}

impl EngineState {
    pub fn apply_event(&mut self, ev: &TraceEvent) {
        self.tick = ev.tick;
        match &ev.kind {
            EventKind::InstructionExecuted { pc } => {
                self.regs.pc = *pc;
            }
            EventKind::MemoryWrite { addr, size, value } => {
                let bytes = value.to_le_bytes();
                for i in 0..*size as usize {
                    self.memory.write_byte(addr + i as u64, bytes[i]);
                }
            }
            EventKind::RegisterChange { name, new_val, .. } => {
                self.regs.set(name, *new_val);
            }
            _ => {}
        }
    }

    pub fn unapply_event(&mut self, ev: &TraceEvent) {
        // Reverse the effect of an event (for backward stepping)
        match &ev.kind {
            EventKind::MemoryWrite { addr, size, .. } => {
                // We'd need old values to truly undo — zero is a fallback
                for i in 0..*size as usize {
                    self.memory.write_byte(addr + i as u64, 0);
                }
            }
            EventKind::RegisterChange { name, old_val, .. } => {
                self.regs.set(name, *old_val);
            }
            _ => {}
        }
    }
}

// ── Breakpoint types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum Breakpoint {
    /// Stop when PC reaches this address.
    ExecuteAddress(u64),
    /// Stop when any write to [addr, addr+len) occurs.
    MemoryWrite { addr: u64, len: u64 },
    /// Stop when any read of [addr, addr+len) occurs.
    MemoryRead { addr: u64, len: u64 },
    /// Stop when register `name` changes.
    RegisterChange { name: String },
    /// Stop on this event kind tag.
    EventKindTag(String),
    /// Stop on module load.
    ModuleLoad { name_contains: String },
    /// Stop when tick reaches value.
    TickEquals(Tick),
}

impl Breakpoint {
    #[must_use] 
    pub fn matches(&self, ev: &TraceEvent, _state: &EngineState) -> bool {
        match self {
            Self::ExecuteAddress(target) => {
                matches!(&ev.kind, EventKind::InstructionExecuted { pc } if *pc == *target)
            }
            Self::MemoryWrite { addr, len } => {
                if let EventKind::MemoryWrite { addr: a, size, .. } = &ev.kind {
                    let start = *a;
                    let end = start + u64::from(*size);
                    start < addr + len && end > *addr
                } else { false }
            }
            Self::MemoryRead { addr, len } => {
                if let EventKind::MemoryRead { addr: a, size } = &ev.kind {
                    let start = *a;
                    let end = start + u64::from(*size);
                    start < addr + len && end > *addr
                } else { false }
            }
            Self::RegisterChange { name } => {
                matches!(&ev.kind, EventKind::RegisterChange { name: n, .. } if n == name)
            }
            Self::EventKindTag(tag) => format!("{:?}", ev.kind).contains(tag.as_str()),
            Self::ModuleLoad { name_contains } => {
                matches!(&ev.kind, EventKind::ModuleLoad { name, .. } if name.contains(name_contains.as_str()))
            }
            Self::TickEquals(t) => ev.tick == *t,
        }
    }
}

// ── Step result ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum StepResult {
    /// Successfully stepped; current tick.
    Stepped(Tick),
    /// Breakpoint was hit.
    BreakpointHit { tick: Tick, bp_index: usize },
    /// Reached the end of the trace.
    EndOfTrace,
    /// Reached the beginning of the trace (backward step).
    BeginningOfTrace,
    /// No events found near the requested tick.
    NoEvents,
}

// ── Replay engine ─────────────────────────────────────────────────────────────

pub struct ReplayEngine {
    pub trace: Arc<TraceData>,
    pub state: EngineState,
    pub cursor: usize,   // current index into trace.events
    pub breakpoints: Vec<Breakpoint>,
    pub checkpoint_interval: u64,
    steps_since_checkpoint: u64,
    pub stats: EngineStats,
}

#[derive(Debug, Default, Clone)]
pub struct EngineStats {
    pub forward_steps: u64,
    pub backward_steps: u64,
    pub seeks: u64,
    pub breakpoint_hits: u64,
    pub checkpoint_saves: u64,
    pub checkpoint_loads: u64,
}

impl ReplayEngine {
    #[must_use] 
    pub fn new(trace: Arc<TraceData>) -> Self {
        Self {
            trace,
            state: EngineState::default(),
            cursor: 0,
            breakpoints: Vec::new(),
            checkpoint_interval: 1000,
            steps_since_checkpoint: 0,
            stats: EngineStats::default(),
        }
    }

    #[must_use] 
    pub const fn current_tick(&self) -> Tick { self.state.tick }

    pub fn add_breakpoint(&mut self, bp: Breakpoint) -> usize {
        let idx = self.breakpoints.len();
        self.breakpoints.push(bp);
        idx
    }

    pub fn remove_breakpoint(&mut self, idx: usize) -> bool {
        if idx < self.breakpoints.len() {
            self.breakpoints.remove(idx);
            true
        } else { false }
    }

    /// Step forward by exactly one event.
    pub fn step_forward(&mut self) -> StepResult {
        if self.cursor >= self.trace.events.len() {
            return StepResult::EndOfTrace;
        }
        let ev = &self.trace.events[self.cursor].clone();
        self.state.apply_event(ev);
        self.cursor += 1;
        self.stats.forward_steps += 1;
        self.steps_since_checkpoint += 1;

        // Auto-checkpoint
        if self.steps_since_checkpoint >= self.checkpoint_interval {
            self.steps_since_checkpoint = 0;
            self.stats.checkpoint_saves += 1;
            // Note: we can't mutate trace.checkpoints from here (Arc).
            // In practice the engine would hold the TraceData directly.
        }

        // Check breakpoints
        for (i, bp) in self.breakpoints.iter().enumerate() {
            if bp.matches(ev, &self.state) {
                self.stats.breakpoint_hits += 1;
                return StepResult::BreakpointHit { tick: ev.tick, bp_index: i };
            }
        }

        StepResult::Stepped(self.state.tick)
    }

    /// Step backward by one event using checkpoint + forward-replay.
    pub fn step_backward(&mut self) -> StepResult {
        if self.cursor == 0 {
            return StepResult::BeginningOfTrace;
        }
        let target_tick = if self.cursor > 0 {
            self.trace.events[self.cursor - 1].tick.saturating_sub(1)
        } else { 0 };
        self.seek_to(target_tick);
        self.stats.backward_steps += 1;
        StepResult::Stepped(self.state.tick)
    }

    /// Seek to the state just before `tick` using checkpoint + replay.
    pub fn seek_to(&mut self, tick: Tick) -> StepResult {
        self.stats.seeks += 1;
        // Find nearest checkpoint at or before tick
        let (checkpoint_tick, base_state) = match self.trace.nearest_checkpoint_before(tick) {
            Some((t, s)) => (t, s.clone()),
            None => (0, EngineState::default()),
        };

        self.state = base_state;
        self.stats.checkpoint_loads += 1;

        // Find cursor position for checkpoint_tick
        self.cursor = self.trace.tick_index.range(..=checkpoint_tick)
            .next_back()
            .map_or(0, |(_, &i)| i);

        // Replay forward to just before tick
        loop {
            if self.cursor >= self.trace.events.len() { break; }
            if self.trace.events[self.cursor].tick >= tick { break; }
            let ev = self.trace.events[self.cursor].clone();
            self.state.apply_event(&ev);
            self.cursor += 1;
        }

        StepResult::Stepped(self.state.tick)
    }

    /// Run forward until a breakpoint is hit or end of trace.
    pub fn run_forward(&mut self) -> StepResult {
        loop {
            match self.step_forward() {
                StepResult::Stepped(_) => continue,
                other => return other,
            }
        }
    }

    /// Run backward (repeated `step_backward`) until a breakpoint is hit.
    pub fn run_backward(&mut self) -> StepResult {
        let start_cursor = self.cursor;
        // Walk backwards through event list checking breakpoints
        let mut cur = start_cursor;
        let mut hit: Option<(Tick, usize)> = None;
        while cur > 0 {
            cur -= 1;
            let ev = &self.trace.events[cur];
            let mut found = false;
            for (i, bp) in self.breakpoints.iter().enumerate() {
                // We need state at that tick — approximate with current state
                if bp.matches(ev, &self.state) {
                    hit = Some((ev.tick, i));
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }
        if let Some((tick, bp_index)) = hit {
            self.seek_to(tick);
            self.stats.breakpoint_hits += 1;
            return StepResult::BreakpointHit { tick, bp_index };
        }
        self.seek_to(0);
        StepResult::BeginningOfTrace
    }

    /// Step over a function call: run forward until return to same stack depth.
    pub fn step_over(&mut self, return_addr: u64) -> StepResult {
        // Run until PC == return_addr
        let bp_idx = self.add_breakpoint(Breakpoint::ExecuteAddress(return_addr));
        let result = self.run_forward();
        self.remove_breakpoint(bp_idx);
        result
    }

    /// Collect all events of a given `EventKind` tag name in range.
    #[must_use] 
    pub fn collect_events_tagged(&self, tag: &str, from: Tick, to: Tick) -> Vec<&TraceEvent> {
        self.trace.events_in_range(from, to)
            .iter()
            .filter(|ev| format!("{:?}", ev.kind).starts_with(tag))
            .collect()
    }

    /// Find the first write to `addr` after the current tick.
    pub fn find_next_write(&mut self, addr: u64, size: u64) -> Option<Tick> {
        let bp_idx = self.add_breakpoint(Breakpoint::MemoryWrite { addr, len: size });
        let result = self.run_forward();
        self.remove_breakpoint(bp_idx);
        match result {
            StepResult::BreakpointHit { tick, .. } => Some(tick),
            _ => None,
        }
    }

    /// Find the previous write to `addr` before the current tick.
    pub fn find_prev_write(&mut self, addr: u64, size: u64) -> Option<Tick> {
        let bp_idx = self.add_breakpoint(Breakpoint::MemoryWrite { addr, len: size });
        let result = self.run_backward();
        self.remove_breakpoint(bp_idx);
        match result {
            StepResult::BreakpointHit { tick, .. } => Some(tick),
            _ => None,
        }
    }

    #[must_use] 
    pub fn read_memory(&self, addr: u64, len: usize) -> Vec<u8> {
        self.state.memory.read_slice(addr, len)
    }

    #[must_use] 
    pub fn read_register(&self, name: &str) -> Option<RegVal> {
        self.state.regs.get(name)
    }
}

// ── Trace builder ─────────────────────────────────────────────────────────────

/// Helper for constructing synthetic traces for testing.
pub struct TraceBuilder {
    events: Vec<TraceEvent>,
    tick: Tick,
    thread: u32,
}

impl TraceBuilder {
    #[must_use] 
    pub const fn new() -> Self { Self { events: Vec::new(), tick: 0, thread: 1 } }

    #[must_use] 
    pub const fn with_thread(mut self, tid: u32) -> Self { self.thread = tid; self }

    #[must_use] 
    pub fn exec(mut self, pc: u64) -> Self {
        self.events.push(TraceEvent {
            tick: self.tick,
            kind: EventKind::InstructionExecuted { pc },
            thread_id: self.thread,
            module_name: None,
        });
        self.tick += 1;
        self
    }

    #[must_use] 
    pub fn write_mem(mut self, addr: u64, size: u8, value: u64) -> Self {
        self.events.push(TraceEvent {
            tick: self.tick,
            kind: EventKind::MemoryWrite { addr, size, value },
            thread_id: self.thread,
            module_name: None,
        });
        self.tick += 1;
        self
    }

    #[must_use] 
    pub fn reg_change(mut self, name: &str, old: u64, new: u64) -> Self {
        self.events.push(TraceEvent {
            tick: self.tick,
            kind: EventKind::RegisterChange { name: name.into(), old_val: old, new_val: new },
            thread_id: self.thread,
            module_name: None,
        });
        self.tick += 1;
        self
    }

    #[must_use] 
    pub fn exception(mut self, code: u32, addr: u64) -> Self {
        self.events.push(TraceEvent {
            tick: self.tick,
            kind: EventKind::Exception { code, addr },
            thread_id: self.thread,
            module_name: None,
        });
        self.tick += 1;
        self
    }

    #[must_use] 
    pub fn build(self) -> TraceData {
        let mut td = TraceData { events: self.events, ..Default::default() };
        td.build_index();
        td
    }
}

impl Default for TraceBuilder {
    fn default() -> Self { Self::new() }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn simple_trace() -> Arc<TraceData> {
        let td = TraceBuilder::new()
            .exec(0x1000)
            .exec(0x1004)
            .write_mem(0xDEAD_0000, 8, 0xCAFE_BABE)
            .exec(0x1008)
            .reg_change("rax", 0, 42)
            .exec(0x100C)
            .build();
        Arc::new(td)
    }

    #[test]
    fn test_step_forward() {
        let trace = simple_trace();
        let mut engine = ReplayEngine::new(trace);
        let r = engine.step_forward();
        assert!(matches!(r, StepResult::Stepped(_)));
        assert_eq!(engine.state.regs.pc, 0x1000);
    }

    #[test]
    fn test_run_to_end() {
        let trace = simple_trace();
        let mut engine = ReplayEngine::new(trace);
        loop {
            match engine.step_forward() {
                StepResult::EndOfTrace => break,
                StepResult::Stepped(_) => continue,
                other => panic!("unexpected: {other:?}"),
            }
        }
        assert_eq!(engine.state.regs.pc, 0x100C);
    }

    #[test]
    fn test_breakpoint_execute() {
        let trace = simple_trace();
        let mut engine = ReplayEngine::new(trace);
        engine.add_breakpoint(Breakpoint::ExecuteAddress(0x1008));
        let result = engine.run_forward();
        assert!(matches!(result, StepResult::BreakpointHit { .. }));
        assert_eq!(engine.state.regs.pc, 0x1008);
    }

    #[test]
    fn test_breakpoint_memory_write() {
        let trace = simple_trace();
        let mut engine = ReplayEngine::new(trace);
        engine.add_breakpoint(Breakpoint::MemoryWrite { addr: 0xDEAD_0000, len: 8 });
        let result = engine.run_forward();
        assert!(matches!(result, StepResult::BreakpointHit { .. }));
    }

    #[test]
    fn test_register_read() {
        let trace = simple_trace();
        let mut engine = ReplayEngine::new(trace);
        // Step until rax changes
        engine.add_breakpoint(Breakpoint::RegisterChange { name: "rax".into() });
        engine.run_forward();
        assert_eq!(engine.read_register("rax"), Some(42));
    }

    #[test]
    fn test_seek_to() {
        let trace = simple_trace();
        let mut engine = ReplayEngine::new(trace);
        engine.seek_to(3);
        // At tick 3 we've processed events at ticks 0, 1, 2
        assert_eq!(engine.state.regs.pc, 0x1004);
    }

    #[test]
    fn test_memory_after_write() {
        let trace = simple_trace();
        let mut engine = ReplayEngine::new(trace);
        engine.seek_to(10); // past the write
        let bytes = engine.read_memory(0xDEAD_0000, 8);
        let val = u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]));
        assert_eq!(val, 0xCAFE_BABE);
    }

    #[test]
    fn test_register_file_diff() {
        let mut a = RegisterFile::default();
        let mut b = RegisterFile::default();
        a.set("rax", 1);
        b.set("rax", 2);
        let diffs = a.diff(&b);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].0, "rax");
    }

    #[test]
    fn test_memory_snapshot_rw() {
        let mut snap = MemorySnapshot::default();
        snap.write_u64_le(0x1000, 0x1122_3344_5566_7788);
        assert_eq!(snap.read_u64_le(0x1000), 0x1122_3344_5566_7788);
        assert_eq!(snap.read_byte(0x1000), Some(0x88));
    }
}
