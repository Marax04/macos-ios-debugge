//! `rustre-ttd-replay::thread_replay`
//!
//! Per-thread replay state, step counters, context-switch detection, and
//! thread-local register files.
//!
//! Key types:
//! * [`ThreadReplayState`] — full register + metadata state for one thread.
//! * [`ThreadLocalRegs`] — a typed x86-64 register file.
//! * [`ThreadSchedule`] — describes when each thread is active (quantum slices).
//! * [`ContextSwitch`] — a recorded context-switch event.
//! * [`MultiThreadReplay`] — orchestrates per-thread replay over a shared trace.

use std::collections::HashMap;

pub use std::collections::BTreeMap;
use std::fmt;

use rustre_ttd::{EventKind, TraceEvent, TracePosition};
use serde::{Deserialize, Serialize};

use crate::MemoryState;

// ─── RegisterFile ─────────────────────────────────────────────────────────────

/// Full x86-64 integer register file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterFile {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    /// Segment registers (CS, DS, ES, FS, GS, SS).
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
    /// FS/GS base (MSRs).
    pub fs_base: u64,
    pub gs_base: u64,
}

impl Default for RegisterFile {
    fn default() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0x7fff_0000,
            rsp: 0x7fff_0000,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0x202, // IF set, reserved bit 1
            cs: 0x33,
            ds: 0,
            es: 0,
            fs: 0x2b,
            gs: 0x53,
            ss: 0x2b,
            fs_base: 0,
            gs_base: 0,
        }
    }
}

impl RegisterFile {
    /// Read a register by name (case-insensitive).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<u64> {
        match name.to_lowercase().as_str() {
            "rax" => Some(self.rax),
            "eax" => Some(self.rax & 0xFFFF_FFFF),
            "rbx" => Some(self.rbx),
            "ebx" => Some(self.rbx & 0xFFFF_FFFF),
            "rcx" => Some(self.rcx),
            "ecx" => Some(self.rcx & 0xFFFF_FFFF),
            "rdx" => Some(self.rdx),
            "edx" => Some(self.rdx & 0xFFFF_FFFF),
            "rsi" => Some(self.rsi),
            "esi" => Some(self.rsi & 0xFFFF_FFFF),
            "rdi" => Some(self.rdi),
            "edi" => Some(self.rdi & 0xFFFF_FFFF),
            "rbp" => Some(self.rbp),
            "ebp" => Some(self.rbp & 0xFFFF_FFFF),
            "rsp" => Some(self.rsp),
            "esp" => Some(self.rsp & 0xFFFF_FFFF),
            "r8" => Some(self.r8),
            "r9" => Some(self.r9),
            "r10" => Some(self.r10),
            "r11" => Some(self.r11),
            "r12" => Some(self.r12),
            "r13" => Some(self.r13),
            "r14" => Some(self.r14),
            "r15" => Some(self.r15),
            "rip" | "eip" | "pc" => Some(self.rip),
            "rflags" | "eflags" | "flags" => Some(self.rflags),
            "fs_base" => Some(self.fs_base),
            "gs_base" => Some(self.gs_base),
            _ => None,
        }
    }

    /// Set a register by name.  Returns `false` for unknown registers.
    pub fn set(&mut self, name: &str, value: u64) -> bool {
        match name.to_lowercase().as_str() {
            "rax" | "eax" => {
                self.rax = value;
                true
            }
            "rbx" | "ebx" => {
                self.rbx = value;
                true
            }
            "rcx" | "ecx" => {
                self.rcx = value;
                true
            }
            "rdx" | "edx" => {
                self.rdx = value;
                true
            }
            "rsi" | "esi" => {
                self.rsi = value;
                true
            }
            "rdi" | "edi" => {
                self.rdi = value;
                true
            }
            "rbp" | "ebp" => {
                self.rbp = value;
                true
            }
            "rsp" | "esp" => {
                self.rsp = value;
                true
            }
            "r8" => {
                self.r8 = value;
                true
            }
            "r9" => {
                self.r9 = value;
                true
            }
            "r10" => {
                self.r10 = value;
                true
            }
            "r11" => {
                self.r11 = value;
                true
            }
            "r12" => {
                self.r12 = value;
                true
            }
            "r13" => {
                self.r13 = value;
                true
            }
            "r14" => {
                self.r14 = value;
                true
            }
            "r15" => {
                self.r15 = value;
                true
            }
            "rip" | "eip" | "pc" => {
                self.rip = value;
                true
            }
            "rflags" | "eflags" | "flags" => {
                self.rflags = value;
                true
            }
            "fs_base" => {
                self.fs_base = value;
                true
            }
            "gs_base" => {
                self.gs_base = value;
                true
            }
            _ => false,
        }
    }

    /// Snapshot as a `HashMap<String, u64>`.
    #[must_use]
    pub fn to_map(&self) -> HashMap<String, u64> {
        let names = [
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15", "rip", "rflags", "fs_base", "gs_base",
        ];
        names
            .iter()
            .filter_map(|&n| self.get(n).map(|v| (n.to_string(), v)))
            .collect()
    }

    /// Apply a register delta map (partial update).
    pub fn apply_map(&mut self, delta: &HashMap<String, u64>) {
        for (k, &v) in delta {
            self.set(k, v);
        }
    }

    /// Whether the zero flag is set.
    #[must_use]
    pub const fn zf(&self) -> bool {
        (self.rflags & 0x40) != 0
    }
    /// Whether the carry flag is set.
    #[must_use]
    pub const fn cf(&self) -> bool {
        (self.rflags & 0x01) != 0
    }
    /// Whether the sign flag is set.
    #[must_use]
    pub const fn sf(&self) -> bool {
        (self.rflags & 0x80) != 0
    }
    /// Whether the overflow flag is set.
    #[must_use]
    pub const fn of(&self) -> bool {
        (self.rflags & 0x800) != 0
    }
}

impl fmt::Display for RegisterFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}",
            self.rax, self.rbx, self.rcx, self.rdx
        )?;
        writeln!(
            f,
            "rsi={:#018x} rdi={:#018x} rbp={:#018x} rsp={:#018x}",
            self.rsi, self.rdi, self.rbp, self.rsp
        )?;
        writeln!(
            f,
            "r8 ={:#018x} r9 ={:#018x} r10={:#018x} r11={:#018x}",
            self.r8, self.r9, self.r10, self.r11
        )?;
        writeln!(
            f,
            "r12={:#018x} r13={:#018x} r14={:#018x} r15={:#018x}",
            self.r12, self.r13, self.r14, self.r15
        )?;
        write!(f, "rip={:#018x} rflags={:#018x}", self.rip, self.rflags)
    }
}

// ─── ThreadStatus ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreadStatus {
    /// Thread has not yet been created.
    NotStarted,
    /// Thread is currently executing (has the CPU).
    Running,
    /// Thread is alive but not currently executing.
    Suspended,
    /// Thread has exited.
    Exited { exit_code: u32 },
}

impl fmt::Display for ThreadStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotStarted => write!(f, "NotStarted"),
            Self::Running => write!(f, "Running"),
            Self::Suspended => write!(f, "Suspended"),
            Self::Exited { exit_code } => write!(f, "Exited({exit_code})"),
        }
    }
}

// ─── ThreadReplayState ────────────────────────────────────────────────────────

/// Full replay state for a single thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadReplayState {
    /// OS thread ID.
    pub tid: u32,
    /// Current register file.
    pub registers: RegisterFile,
    /// Current thread status.
    pub status: ThreadStatus,
    /// Number of steps (trace events) processed for this thread.
    pub step_count: u64,
    /// Number of instructions (calls + returns + syscalls) processed.
    pub instruction_count: u64,
    /// Position of the last event that involved this thread.
    pub last_position: TracePosition,
    /// Position when this thread was created.
    pub create_position: TracePosition,
    /// Position when this thread exited (zero if still alive).
    pub exit_position: Option<TracePosition>,
    /// TEB address (Thread Environment Block) — x64 Windows convention.
    pub teb_address: Option<u64>,
    /// Thread name if set by the process (e.g. via `SetThreadDescription`).
    pub name: Option<String>,
}

impl ThreadReplayState {
    #[must_use]
    pub fn new(tid: u32, create_pos: TracePosition) -> Self {
        Self {
            tid,
            registers: RegisterFile::default(),
            status: ThreadStatus::NotStarted,
            step_count: 0,
            instruction_count: 0,
            last_position: create_pos,
            create_position: create_pos,
            exit_position: None,
            teb_address: None,
            name: None,
        }
    }

    pub fn apply_event(&mut self, event: &TraceEvent) {
        debug_assert_eq!(event.thread_id, self.tid);
        self.step_count += 1;
        self.last_position = event.position;
        match &event.kind {
            EventKind::Call { to, from } => {
                self.registers.rip = *to;
                self.registers.set("call_from", *from);
                self.instruction_count += 1;
                self.status = ThreadStatus::Running;
            }
            EventKind::Return { to, .. } => {
                self.registers.rip = *to;
                self.instruction_count += 1;
            }
            EventKind::SyscallEnter { nr, args } => {
                self.registers.rax = u64::from(*nr);
                self.registers.rdi = args[0];
                self.registers.rsi = args[1];
                self.registers.rdx = args[2];
                self.registers.r10 = args[3];
                self.registers.r8 = args[4];
                self.registers.r9 = args[5];
                self.instruction_count += 1;
            }
            EventKind::SyscallExit { ret, .. } => {
                self.registers.rax = *ret;
            }
            EventKind::ThreadCreate { .. } => {
                self.status = ThreadStatus::Running;
            }
            EventKind::ThreadExit { tid, .. } => {
                if *tid == self.tid {
                    self.status = ThreadStatus::Exited { exit_code: 0 };
                    self.exit_position = Some(event.position);
                }
            }
            EventKind::MemWrite { .. }
            | EventKind::MemRead { .. }
            | EventKind::Exception { .. }
            | EventKind::Breakpoint { .. } => {}
        }
    }

    #[must_use]
    pub const fn is_alive(&self) -> bool {
        !matches!(
            self.status,
            ThreadStatus::Exited { .. } | ThreadStatus::NotStarted
        )
    }

    #[must_use]
    pub const fn elapsed_steps(&self) -> u64 {
        self.step_count
    }

    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    #[must_use]
    pub const fn with_teb(mut self, teb: u64) -> Self {
        self.teb_address = Some(teb);
        self
    }

    /// Display name for UI: custom name > "tid:<tid>".
    #[must_use]
    pub fn display_name(&self) -> String {
        self.name
            .clone()
            .unwrap_or_else(|| format!("tid:{}", self.tid))
    }
}

impl fmt::Display for ThreadReplayState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Thread[{}] status={} steps={} instrs={} rip={:#x}",
            self.display_name(),
            self.status,
            self.step_count,
            self.instruction_count,
            self.registers.rip
        )
    }
}

// ─── ContextSwitch ────────────────────────────────────────────────────────────

/// A recorded context-switch: the CPU moved from `from_tid` to `to_tid`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSwitch {
    pub position: TracePosition,
    pub from_tid: u32,
    pub to_tid: u32,
    /// How many steps `from_tid` ran in its quantum.
    pub quantum_steps: u64,
}

impl ContextSwitch {
    #[must_use]
    pub const fn new(position: TracePosition, from: u32, to: u32, quantum: u64) -> Self {
        Self {
            position,
            from_tid: from,
            to_tid: to,
            quantum_steps: quantum,
        }
    }
}

impl fmt::Display for ContextSwitch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CtxSwitch@{}: tid={} -> tid={} (quantum={})",
            self.position, self.from_tid, self.to_tid, self.quantum_steps
        )
    }
}

// ─── ThreadQuantum ────────────────────────────────────────────────────────────

/// A contiguous slice of the trace during which one thread held the CPU.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadQuantum {
    pub tid: u32,
    pub start_position: TracePosition,
    pub end_position: TracePosition,
    pub step_count: u64,
}

impl ThreadQuantum {
    #[must_use]
    pub const fn duration_steps(&self) -> u64 {
        self.step_count
    }
}

impl fmt::Display for ThreadQuantum {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Quantum[tid={}, {}..{}, steps={}]",
            self.tid, self.start_position, self.end_position, self.step_count
        )
    }
}

// ─── ThreadSchedule ───────────────────────────────────────────────────────────

/// The complete scheduling history: ordered list of thread quanta, context switches.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ThreadSchedule {
    pub quanta: Vec<ThreadQuantum>,
    pub switches: Vec<ContextSwitch>,
}

impl ThreadSchedule {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_quantum(&mut self, q: ThreadQuantum) {
        self.quanta.push(q);
    }
    pub fn add_switch(&mut self, cs: ContextSwitch) {
        self.switches.push(cs);
    }

    /// Which thread was running at `pos`?
    #[must_use]
    pub fn thread_at(&self, pos: TracePosition) -> Option<u32> {
        for q in &self.quanta {
            if pos >= q.start_position && pos <= q.end_position {
                return Some(q.tid);
            }
        }
        None
    }

    /// All quanta for `tid`.
    #[must_use]
    pub fn quanta_for_thread(&self, tid: u32) -> Vec<&ThreadQuantum> {
        self.quanta.iter().filter(|q| q.tid == tid).collect()
    }

    /// Total steps `tid` spent running.
    #[must_use]
    pub fn total_steps_for_thread(&self, tid: u32) -> u64 {
        self.quanta_for_thread(tid)
            .iter()
            .map(|q| q.step_count)
            .sum()
    }

    /// All context switches involving `tid` (either side).
    #[must_use]
    pub fn switches_for_thread(&self, tid: u32) -> Vec<&ContextSwitch> {
        self.switches
            .iter()
            .filter(|s| s.from_tid == tid || s.to_tid == tid)
            .collect()
    }

    #[must_use]
    pub const fn switch_count(&self) -> usize {
        self.switches.len()
    }
    #[must_use]
    pub const fn quantum_count(&self) -> usize {
        self.quanta.len()
    }
}

// ─── MultiThreadReplay ────────────────────────────────────────────────────────

/// Orchestrates per-thread replay state over a shared trace.
///
/// Processes events in trace order, routing each to the owning thread's
/// [`ThreadReplayState`] and detecting context switches.
pub struct MultiThreadReplay {
    /// Per-thread state.
    pub threads: HashMap<u32, ThreadReplayState>,
    /// Detected context switches.
    pub schedule: ThreadSchedule,
    /// Current active thread (most recently seen).
    pub current_tid: Option<u32>,
    /// Global step counter across all threads.
    pub global_step: u64,
    /// Shared memory state (writes from any thread affect this).
    pub memory: MemoryState,
    /// Last seen position.
    pub last_position: TracePosition,
    /// Per-thread step counter at start of current quantum.
    quantum_start_steps: HashMap<u32, u64>,
    /// Position at start of current quantum per thread.
    quantum_start_positions: HashMap<u32, TracePosition>,
}

impl MultiThreadReplay {
    #[must_use]
    pub fn new() -> Self {
        Self {
            threads: HashMap::new(),
            schedule: ThreadSchedule::new(),
            current_tid: None,
            global_step: 0,
            memory: MemoryState::new(),
            last_position: TracePosition::start(),
            quantum_start_steps: HashMap::new(),
            quantum_start_positions: HashMap::new(),
        }
    }

    /// Process a single event.
    pub fn process_event(&mut self, event: &TraceEvent) {
        let tid = event.thread_id;

        // Ensure thread entry exists and record the latest position seen.
        let thread = self
            .threads
            .entry(tid)
            .or_insert_with(|| ThreadReplayState::new(tid, event.position));
        thread.last_position = event.position;

        // Detect context switch.
        if let Some(prev_tid) = self.current_tid {
            if prev_tid != tid {
                // Close previous quantum.
                let prev_steps = self.threads.get(&prev_tid).map_or(0, |t| t.step_count);
                let q_start_steps = self
                    .quantum_start_steps
                    .get(&prev_tid)
                    .copied()
                    .unwrap_or(0);
                let q_start_pos = self
                    .quantum_start_positions
                    .get(&prev_tid)
                    .copied()
                    .unwrap_or_default();

                let quantum_steps = prev_steps.saturating_sub(q_start_steps);
                let cs = ContextSwitch::new(event.position, prev_tid, tid, quantum_steps);

                if q_start_pos != event.position {
                    self.schedule.add_quantum(ThreadQuantum {
                        tid: prev_tid,
                        start_position: q_start_pos,
                        end_position: self.last_position,
                        step_count: quantum_steps,
                    });
                }
                self.schedule.add_switch(cs);

                // Start new quantum for `tid`.
                let new_steps = self.threads.get(&tid).map_or(0, |t| t.step_count);
                self.quantum_start_steps.insert(tid, new_steps);
                self.quantum_start_positions.insert(tid, event.position);
            }
        } else {
            // First event ever.
            self.quantum_start_steps.insert(tid, 0);
            self.quantum_start_positions.insert(tid, event.position);
        }

        self.current_tid = Some(tid);
        self.last_position = event.position;
        self.global_step += 1;

        // Apply to memory.
        if let EventKind::MemWrite { addr, data } = &event.kind {
            self.memory.apply_write(*addr, data);
        }

        // Apply to thread state.
        if let Some(ts) = self.threads.get_mut(&tid) {
            ts.apply_event(event);
        }
    }

    /// Process all events in `events`.
    pub fn process_events(&mut self, events: &[TraceEvent]) {
        for e in events {
            self.process_event(e);
        }
    }

    /// Reconstruct the multi-thread state at `pos` by replaying all events up
    /// to and including `pos`.
    #[must_use]
    pub fn state_at(events: &[TraceEvent], pos: TracePosition) -> Self {
        let mut replay = Self::new();
        for e in events {
            if e.position > pos {
                break;
            }
            replay.process_event(e);
        }
        replay
    }

    /// All active thread IDs (alive at end of processed events).
    #[must_use]
    pub fn active_thread_ids(&self) -> Vec<u32> {
        self.threads
            .values()
            .filter(|t| t.is_alive())
            .map(|t| t.tid)
            .collect()
    }

    /// Get state for `tid`.
    #[must_use]
    pub fn thread_state(&self, tid: u32) -> Option<&ThreadReplayState> {
        self.threads.get(&tid)
    }

    /// Get mutable state for `tid`.
    pub fn thread_state_mut(&mut self, tid: u32) -> Option<&mut ThreadReplayState> {
        self.threads.get_mut(&tid)
    }

    /// Total number of steps across all threads.
    #[must_use]
    pub const fn total_steps(&self) -> u64 {
        self.global_step
    }

    /// The thread with the highest step count (most active).
    #[must_use]
    pub fn most_active_thread(&self) -> Option<&ThreadReplayState> {
        self.threads.values().max_by_key(|t| t.step_count)
    }

    /// Read a register for `tid` at the current replay point.
    #[must_use]
    pub fn read_register(&self, tid: u32, name: &str) -> Option<u64> {
        self.threads.get(&tid)?.registers.get(name)
    }

    /// Read memory at current replay point.
    #[must_use]
    pub fn read_memory(&self, addr: u64, len: usize) -> Option<Vec<u8>> {
        self.memory.read(addr, len)
    }

    /// Detect all context switches in an event stream (without maintaining state).
    #[must_use]
    pub fn detect_context_switches(events: &[TraceEvent]) -> Vec<ContextSwitch> {
        let mut switches = Vec::new();
        let mut prev_tid: Option<u32> = None;
        let mut quantum_steps: HashMap<u32, u64> = HashMap::new();

        for e in events {
            let tid = e.thread_id;
            *quantum_steps.entry(tid).or_insert(0) += 1;

            if let Some(pt) = prev_tid
                && pt != tid
            {
                let steps = quantum_steps.get(&pt).copied().unwrap_or(0);
                switches.push(ContextSwitch::new(e.position, pt, tid, steps));
                quantum_steps.insert(pt, 0); // reset quantum for old thread
            }
            prev_tid = Some(tid);
        }
        switches
    }

    /// Per-thread event count summary.
    #[must_use]
    pub fn events_per_thread(&self) -> HashMap<u32, u64> {
        self.threads
            .iter()
            .map(|(&tid, t)| (tid, t.step_count))
            .collect()
    }
}

impl Default for MultiThreadReplay {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MultiThreadReplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultiThreadReplay")
            .field("threads", &self.threads.len())
            .field("global_step", &self.global_step)
            .field("current_tid", &self.current_tid)
            .field("switch_count", &self.schedule.switch_count())
            .finish_non_exhaustive()
    }
}

// ─── ThreadDiff ───────────────────────────────────────────────────────────────

/// Register-level diff between two `ThreadReplayState`s (same thread).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadDiff {
    pub tid: u32,
    pub before_position: TracePosition,
    pub after_position: TracePosition,
    pub register_changes: Vec<(String, u64, u64)>, // (name, before, after)
    pub step_delta: u64,
}

impl ThreadDiff {
    ///
    /// # Panics
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn compute(before: &ThreadReplayState, after: &ThreadReplayState) -> Self {
        assert_eq!(before.tid, after.tid);
        let b_map = before.registers.to_map();
        let a_map = after.registers.to_map();
        let mut changes = Vec::new();
        for (name, &bval) in &b_map {
            if let Some(&aval) = a_map.get(name)
                && bval != aval
            {
                changes.push((name.clone(), bval, aval));
            }
        }
        changes.sort_by(|a, b| a.0.cmp(&b.0));
        Self {
            tid: before.tid,
            before_position: before.last_position,
            after_position: after.last_position,
            register_changes: changes,
            step_delta: after.step_count.saturating_sub(before.step_count),
        }
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.register_changes.is_empty()
    }
    #[must_use]
    pub const fn changed_register_count(&self) -> usize {
        self.register_changes.len()
    }
}

impl fmt::Display for ThreadDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "ThreadDiff[tid={}, +{} steps, {} regs changed]:",
            self.tid,
            self.step_delta,
            self.register_changes.len()
        )?;
        for (name, before, after) in &self.register_changes {
            writeln!(f, "  {name}: {before:#x} -> {after:#x}")?;
        }
        Ok(())
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rustre_ttd::{EventKind, TraceEvent, TracePosition};
    

    fn pos(seq: u64) -> TracePosition {
        TracePosition::new(seq, 0)
    }

    fn make_events_two_threads() -> Vec<TraceEvent> {
        vec![
            TraceEvent {
                position: pos(0),
                thread_id: 1,
                kind: EventKind::Call {
                    from: 0x1000,
                    to: 0x2000,
                },
            },
            TraceEvent {
                position: pos(1),
                thread_id: 1,
                kind: EventKind::Return {
                    from: 0x2050,
                    to: 0x1004,
                },
            },
            TraceEvent {
                position: pos(2),
                thread_id: 2,
                kind: EventKind::Call {
                    from: 0x3000,
                    to: 0x4000,
                },
            },
            TraceEvent {
                position: pos(3),
                thread_id: 1,
                kind: EventKind::SyscallEnter {
                    nr: 1,
                    args: [1, 2, 3, 4, 5, 6],
                },
            },
            TraceEvent {
                position: pos(4),
                thread_id: 2,
                kind: EventKind::Return {
                    from: 0x4050,
                    to: 0x3004,
                },
            },
        ]
    }

    // ── RegisterFile ──────────────────────────────────────────────────────────

    #[test]
    fn register_file_default() {
        let rf = RegisterFile::default();
        assert_eq!(rf.rip, 0);
        assert_eq!(rf.rflags, 0x202);
    }

    #[test]
    fn register_file_get_set() {
        let mut rf = RegisterFile::default();
        rf.set("rax", 0xDEAD_BEEF);
        assert_eq!(rf.get("rax"), Some(0xDEAD_BEEF));
        assert_eq!(rf.get("eax"), Some(0xDEAD_BEEF & 0xFFFF_FFFF));
    }

    #[test]
    fn register_file_get_unknown() {
        let rf = RegisterFile::default();
        assert!(rf.get("xyz_nonexistent").is_none());
    }

    #[test]
    fn register_file_to_map() {
        let rf = RegisterFile::default();
        let map = rf.to_map();
        assert!(map.contains_key("rip"));
        assert!(map.contains_key("rsp"));
    }

    #[test]
    fn register_file_apply_map() {
        let mut rf = RegisterFile::default();
        let mut delta = HashMap::new();
        delta.insert("rax".to_string(), 42u64);
        rf.apply_map(&delta);
        assert_eq!(rf.rax, 42);
    }

    #[test]
    fn register_file_flags() {
        let rf = RegisterFile {
            rflags: 0x40, // ZF
            ..RegisterFile::default()
        };
        assert!(rf.zf());
        assert!(!rf.cf());
    }

    #[test]
    fn register_file_display() {
        let rf = RegisterFile::default();
        assert!(rf.to_string().contains("rip="));
    }

    // ── ThreadReplayState ─────────────────────────────────────────────────────

    #[test]
    fn thread_state_new() {
        let ts = ThreadReplayState::new(1, pos(0));
        assert_eq!(ts.tid, 1);
        assert_eq!(ts.status, ThreadStatus::NotStarted);
        assert_eq!(ts.step_count, 0);
    }

    #[test]
    fn thread_state_apply_call() {
        let mut ts = ThreadReplayState::new(1, pos(0));
        ts.apply_event(&TraceEvent {
            position: pos(0),
            thread_id: 1,
            kind: EventKind::Call {
                from: 0x1000,
                to: 0x2000,
            },
        });
        assert_eq!(ts.registers.rip, 0x2000);
        assert_eq!(ts.step_count, 1);
        assert_eq!(ts.instruction_count, 1);
    }

    #[test]
    fn thread_state_apply_syscall() {
        let mut ts = ThreadReplayState::new(1, pos(0));
        ts.apply_event(&TraceEvent {
            position: pos(0),
            thread_id: 1,
            kind: EventKind::SyscallEnter {
                nr: 42,
                args: [1, 2, 3, 4, 5, 6],
            },
        });
        assert_eq!(ts.registers.rax, 42);
        assert_eq!(ts.registers.rdi, 1);
    }

    #[test]
    fn thread_state_apply_thread_exit() {
        let mut ts = ThreadReplayState::new(1, pos(0));
        ts.status = ThreadStatus::Running;
        ts.apply_event(&TraceEvent {
            position: pos(5),
            thread_id: 1,
            kind: EventKind::ThreadExit {
                tid: 1,
                code: 0,
            },
        });
        assert!(matches!(ts.status, ThreadStatus::Exited { .. }));
        assert_eq!(ts.exit_position, Some(pos(5)));
    }

    #[test]
    fn thread_state_is_alive() {
        let mut ts = ThreadReplayState::new(1, pos(0));
        ts.status = ThreadStatus::Running;
        assert!(ts.is_alive());
        ts.status = ThreadStatus::Exited { exit_code: 0 };
        assert!(!ts.is_alive());
    }

    #[test]
    fn thread_state_display_name() {
        let ts = ThreadReplayState::new(5, pos(0)).with_name("worker");
        assert_eq!(ts.display_name(), "worker");
        let ts2 = ThreadReplayState::new(7, pos(0));
        assert_eq!(ts2.display_name(), "tid:7");
    }

    #[test]
    fn thread_state_display() {
        let ts = ThreadReplayState::new(1, pos(0));
        assert!(ts.to_string().contains("Thread"));
    }

    // ── ContextSwitch ─────────────────────────────────────────────────────────

    #[test]
    fn context_switch_display() {
        let cs = ContextSwitch::new(pos(10), 1, 2, 5);
        assert!(cs.to_string().contains("tid=1"));
        assert!(cs.to_string().contains("tid=2"));
    }

    // ── ThreadQuantum ─────────────────────────────────────────────────────────

    #[test]
    fn thread_quantum_display() {
        let q = ThreadQuantum {
            tid: 1,
            start_position: pos(0),
            end_position: pos(9),
            step_count: 10,
        };
        assert!(q.to_string().contains("tid=1"));
        assert_eq!(q.duration_steps(), 10);
    }

    // ── ThreadSchedule ────────────────────────────────────────────────────────

    #[test]
    fn thread_schedule_thread_at() {
        let mut sched = ThreadSchedule::new();
        sched.add_quantum(ThreadQuantum {
            tid: 1,
            start_position: pos(0),
            end_position: pos(4),
            step_count: 5,
        });
        sched.add_quantum(ThreadQuantum {
            tid: 2,
            start_position: pos(5),
            end_position: pos(9),
            step_count: 5,
        });
        assert_eq!(sched.thread_at(pos(2)), Some(1));
        assert_eq!(sched.thread_at(pos(7)), Some(2));
        assert_eq!(sched.thread_at(pos(15)), None);
    }

    #[test]
    fn thread_schedule_total_steps() {
        let mut sched = ThreadSchedule::new();
        sched.add_quantum(ThreadQuantum {
            tid: 1,
            start_position: pos(0),
            end_position: pos(4),
            step_count: 5,
        });
        sched.add_quantum(ThreadQuantum {
            tid: 1,
            start_position: pos(10),
            end_position: pos(14),
            step_count: 5,
        });
        assert_eq!(sched.total_steps_for_thread(1), 10);
    }

    // ── MultiThreadReplay ─────────────────────────────────────────────────────

    #[test]
    fn multi_thread_process_events() {
        let events = make_events_two_threads();
        let mut replay = MultiThreadReplay::new();
        replay.process_events(&events);
        assert_eq!(replay.threads.len(), 2);
        assert_eq!(replay.global_step, 5);
    }

    #[test]
    fn multi_thread_active_threads() {
        let events = make_events_two_threads();
        let mut replay = MultiThreadReplay::new();
        replay.process_events(&events);
        let active = replay.active_thread_ids();
        // Both threads are alive (no ThreadExit events)
        assert_eq!(active.len(), 2);
    }

    #[test]
    fn multi_thread_read_register() {
        let events = make_events_two_threads();
        let mut replay = MultiThreadReplay::new();
        replay.process_events(&events);
        // Thread 1 last event was SyscallEnter with nr=1 -> rax=1
        let rax = replay.read_register(1, "rax");
        assert_eq!(rax, Some(1));
    }

    #[test]
    fn multi_thread_memory() {
        let events = vec![TraceEvent {
            position: pos(0),
            thread_id: 1,
            kind: EventKind::MemWrite {
                addr: 0x1000,
                data: vec![1, 2, 3, 4],
            },
        }];
        let mut replay = MultiThreadReplay::new();
        replay.process_events(&events);
        let bytes = replay.read_memory(0x1000, 4).unwrap();
        assert_eq!(bytes, vec![1, 2, 3, 4]);
    }

    #[test]
    fn multi_thread_context_switches_detected() {
        let events = make_events_two_threads();
        let switches = MultiThreadReplay::detect_context_switches(&events);
        // Thread 1 -> 2 at pos(2), Thread 2 -> 1 at pos(3), Thread 1 -> 2 at pos(4)
        assert!(switches.len() >= 2);
    }

    #[test]
    fn multi_thread_most_active() {
        let events = make_events_two_threads();
        let mut replay = MultiThreadReplay::new();
        replay.process_events(&events);
        let ma = replay.most_active_thread().unwrap();
        assert_eq!(ma.tid, 1); // thread 1 has 3 events
    }

    #[test]
    fn multi_thread_state_at() {
        let events = make_events_two_threads();
        let replay = MultiThreadReplay::state_at(&events, pos(1));
        // Only events at pos 0 and 1 processed — both are thread 1
        assert!(replay.thread_state(1).is_some());
    }

    #[test]
    fn multi_thread_events_per_thread() {
        let events = make_events_two_threads();
        let mut replay = MultiThreadReplay::new();
        replay.process_events(&events);
        let counts = replay.events_per_thread();
        assert_eq!(counts.get(&1).copied(), Some(3)); // events at pos 0, 1, 3
        assert_eq!(counts.get(&2).copied(), Some(2)); // events at pos 2, 4
    }

    #[test]
    fn multi_thread_debug() {
        let replay = MultiThreadReplay::new();
        assert!(format!("{replay:?}").contains("MultiThreadReplay"));
    }

    // ── ThreadDiff ────────────────────────────────────────────────────────────

    #[test]
    fn thread_diff_compute() {
        let mut before = ThreadReplayState::new(1, pos(0));
        before.registers.rax = 0;
        let mut after = ThreadReplayState::new(1, pos(5));
        after.registers.rax = 42;
        after.step_count = 5;
        let diff = ThreadDiff::compute(&before, &after);
        assert!(!diff.is_empty());
        assert!(
            diff.register_changes
                .iter()
                .any(|(n, b, a)| n == "rax" && *b == 0 && *a == 42)
        );
    }

    #[test]
    fn thread_diff_empty_when_no_change() {
        let ts = ThreadReplayState::new(1, pos(0));
        let diff = ThreadDiff::compute(&ts, &ts);
        assert!(diff.is_empty());
    }

    #[test]
    fn thread_diff_display() {
        let before = ThreadReplayState::new(1, pos(0));
        let mut after = ThreadReplayState::new(1, pos(2));
        after.registers.rax = 99;
        after.step_count = 2;
        let diff = ThreadDiff::compute(&before, &after);
        assert!(diff.to_string().contains("ThreadDiff"));
    }

    // ── ThreadStatus ──────────────────────────────────────────────────────────

    #[test]
    fn thread_status_display() {
        assert_eq!(ThreadStatus::Running.to_string(), "Running");
        assert_eq!(ThreadStatus::Suspended.to_string(), "Suspended");
        assert_eq!(ThreadStatus::NotStarted.to_string(), "NotStarted");
        assert!(
            ThreadStatus::Exited { exit_code: 1 }
                .to_string()
                .contains('1')
        );
    }
}
