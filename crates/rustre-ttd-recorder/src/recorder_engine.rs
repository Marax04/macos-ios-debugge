//! TTD recorder engine — process attach/detach, snapshot scheduling,
//! trace file format writing, position sequences, thread state, memory diffs.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors produced by the recorder engine.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("process not found: {0}")]
    ProcessNotFound(u32),
    #[error("already attached to pid {0}")]
    AlreadyAttached(u32),
    #[error("not attached to any process")]
    NotAttached,
    #[error("snapshot error: {0}")]
    Snapshot(String),
    #[error("trace write error: {0}")]
    TraceWrite(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("position overflow")]
    PositionOverflow,
}

pub type Result<T> = std::result::Result<T, EngineError>;

// ── Position types ────────────────────────────────────────────────────────────

/// A position in the TTD trace identified by major (instruction count) and
/// minor (micro-step within an instruction) counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TracePos {
    pub major: u64,
    pub minor: u32,
}

impl TracePos {
    #[must_use]
    pub const fn new(major: u64, minor: u32) -> Self {
        Self { major, minor }
    }

    #[must_use]
    pub const fn start() -> Self {
        Self { major: 0, minor: 0 }
    }

    /// Advance by one instruction.
    ///
    /// # Errors
    /// Returns `EngineError::PositionOverflow` if major wraps.
    pub fn next_instruction(&self) -> Result<Self> {
        Ok(Self {
            major: self.major.checked_add(1).ok_or(EngineError::PositionOverflow)?,
            minor: 0,
        })
    }

    /// Advance by one micro-step.
    ///
    /// # Errors
    /// Returns `EngineError::PositionOverflow` if minor overflows.
    pub fn next_step(&self) -> Result<Self> {
        if self.minor == u32::MAX {
            self.next_instruction()
        } else {
            Ok(Self { major: self.major, minor: self.minor + 1 })
        }
    }
}

impl std::fmt::Display for TracePos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}

// ── Thread state ──────────────────────────────────────────────────────────────

/// CPU register file snapshot for a thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterFile {
    pub rax: u64, pub rbx: u64, pub rcx: u64, pub rdx: u64,
    pub rsi: u64, pub rdi: u64, pub rbp: u64, pub rsp: u64,
    pub r8:  u64, pub r9:  u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
    pub cs: u16, pub ss: u16, pub ds: u16, pub es: u16,
    pub fs: u16, pub gs: u16,
}

impl Default for RegisterFile {
    fn default() -> Self {
        Self {
            rax: 0, rbx: 0, rcx: 0, rdx: 0,
            rsi: 0, rdi: 0, rbp: 0, rsp: 0x7fff_ffff_0000,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rip: 0x0000_0000_0040_0000,
            rflags: 0x0000_0000_0000_0202,
            cs: 0x33, ss: 0x2b, ds: 0x2b, es: 0x2b,
            fs: 0x53, gs: 0x2b,
        }
    }
}

/// State of a single thread at one point in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadState {
    pub tid: u32,
    pub regs: RegisterFile,
    pub position: TracePos,
    pub suspended: bool,
    /// User-mode TEB address.
    pub teb_addr: u64,
    /// Name set by the OS/program (may be empty).
    pub name: String,
}

impl ThreadState {
    #[must_use]
    pub fn new(tid: u32) -> Self {
        Self {
            tid,
            regs: RegisterFile::default(),
            position: TracePos::start(),
            suspended: false,
            teb_addr: 0x7fff_f000_0000 + u64::from(tid) * 0x1000,
            name: format!("Thread-{tid}"),
        }
    }
}

// ── Memory diff ───────────────────────────────────────────────────────────────

/// A diff of memory between two consecutive trace positions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryDiff {
    /// Virtual address of the first changed byte.
    pub addr: u64,
    /// Previous bytes (before the change).
    pub before: Vec<u8>,
    /// New bytes (after the change).
    pub after: Vec<u8>,
    /// Position at which the diff was observed.
    pub position: TracePos,
    /// Thread that triggered the write.
    pub tid: u32,
}

impl MemoryDiff {
    /// Number of bytes changed.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.after.len()
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.after.is_empty()
    }
}

// ── Trace events ─────────────────────────────────────────────────────────────

/// The kind of event recorded at a trace position.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecordedEvent {
    /// An instruction was executed.
    Instruction {
        tid: u32,
        ip: u64,
        opcode: Vec<u8>,
        len: u8,
    },
    /// A memory write occurred.
    MemWrite(MemoryDiff),
    /// A memory read occurred.
    MemRead { tid: u32, addr: u64, len: u32 },
    /// A system call was entered.
    SyscallEnter { tid: u32, nr: u32, args: [u64; 6] },
    /// A system call returned.
    SyscallReturn { tid: u32, nr: u32, retval: i64 },
    /// A module was loaded.
    ModuleLoad { base: u64, size: u64, name: String },
    /// A module was unloaded.
    ModuleUnload { base: u64, name: String },
    /// A thread was created.
    ThreadCreate { tid: u32, start_addr: u64 },
    /// A thread exited.
    ThreadExit { tid: u32, exit_code: u32 },
    /// An exception was raised.
    Exception { tid: u32, code: u32, addr: u64, first_chance: bool },
}

/// A single entry in the trace event stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEntry {
    pub position: TracePos,
    pub event: RecordedEvent,
    pub timestamp_ns: u64,
}

// ── Snapshot scheduling ───────────────────────────────────────────────────────

/// Policy that controls when the engine takes automatic snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotPolicy {
    /// Take a snapshot every N instructions (0 = disabled).
    pub every_n_instructions: u64,
    /// Take a snapshot every N seconds of wall clock (0 = disabled).
    pub every_n_secs: u64,
    /// Maximum number of snapshots to retain (oldest are dropped).
    pub max_snapshots: usize,
    /// Take a snapshot before each system call.
    pub on_syscall: bool,
    /// Take a snapshot before each exception.
    pub on_exception: bool,
}

impl Default for SnapshotPolicy {
    fn default() -> Self {
        Self {
            every_n_instructions: 1_000_000,
            every_n_secs: 0,
            max_snapshots: 16,
            on_syscall: false,
            on_exception: true,
        }
    }
}

/// A scheduled snapshot trigger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotTrigger {
    pub policy: SnapshotPolicy,
    pub next_instruction: u64,
    pub last_snapshot_time: u64,
}

impl SnapshotTrigger {
    #[must_use]
    pub const fn new(policy: SnapshotPolicy) -> Self {
        let next = policy.every_n_instructions;
        Self {
            policy,
            next_instruction: next,
            last_snapshot_time: 0,
        }
    }

    /// Return true if a snapshot should be taken at `pos` now.
    pub const fn should_snap(&mut self, pos: TracePos, now_secs: u64, reason: &RecordedEvent) -> bool {
        if self.policy.on_exception && matches!(reason, RecordedEvent::Exception { .. }) {
            return true;
        }
        if self.policy.on_syscall && matches!(reason, RecordedEvent::SyscallEnter { .. }) {
            return true;
        }
        if self.policy.every_n_instructions > 0 && pos.major >= self.next_instruction {
            self.next_instruction = pos.major.saturating_add(self.policy.every_n_instructions);
            return true;
        }
        if self.policy.every_n_secs > 0 {
            let delta = now_secs.saturating_sub(self.last_snapshot_time);
            if delta >= self.policy.every_n_secs {
                self.last_snapshot_time = now_secs;
                return true;
            }
        }
        false
    }
}

// ── Module info ───────────────────────────────────────────────────────────────

/// A loaded module (DLL / shared object).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub path: String,
    pub loaded_at: TracePos,
}

impl ModuleInfo {
    /// Return true if `addr` falls within this module's address range.
    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.base + self.size
    }
}

// ── Recorder engine state ─────────────────────────────────────────────────────

/// The live state managed by the recorder engine.
#[derive(Debug)]
pub struct RecorderEngineState {
    pub pid: u32,
    pub threads: HashMap<u32, ThreadState>,
    pub modules: Vec<ModuleInfo>,
    pub current_pos: TracePos,
    pub instruction_count: u64,
    pub event_count: u64,
    pub start_time: Instant,
    pub start_time_unix: u64,
}

impl RecorderEngineState {
    fn new(pid: u32) -> Self {
        let start_time_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut threads = HashMap::new();
        threads.insert(1, ThreadState::new(1));
        Self {
            pid,
            threads,
            modules: Vec::new(),
            current_pos: TracePos::start(),
            instruction_count: 0,
            event_count: 0,
            start_time: Instant::now(),
            start_time_unix,
        }
    }
}

// ── Recorder engine ───────────────────────────────────────────────────────────

/// Main TTD recorder engine.
///
/// Manages the lifecycle of a trace recording session: process attach/detach,
/// event ingestion, snapshot scheduling, and trace file writing.
pub struct RecorderEngine {
    state: RwLock<Option<RecorderEngineState>>,
    events: Mutex<VecDeque<TraceEntry>>,
    snap_trigger: Mutex<SnapshotTrigger>,
    output_dir: PathBuf,
    running: AtomicBool,
    /// Monotonic nanosecond counter (simulated).
    ns_counter: AtomicU64,
    /// Events ring-buffer capacity (0 = unlimited).
    ring_capacity: usize,
}

impl RecorderEngine {
    /// Create a new engine that will write traces to `output_dir`.
    #[must_use]
    pub fn new(output_dir: impl AsRef<Path>) -> Self {
        Self {
            state: RwLock::new(None),
            events: Mutex::new(VecDeque::with_capacity(4096)),
            snap_trigger: Mutex::new(SnapshotTrigger::new(SnapshotPolicy::default())),
            output_dir: output_dir.as_ref().to_path_buf(),
            running: AtomicBool::new(false),
            ns_counter: AtomicU64::new(0),
            ring_capacity: 0,
        }
    }

    /// Set a custom snapshot policy.
    pub fn set_snapshot_policy(&self, policy: SnapshotPolicy) {
        *self.snap_trigger.lock() = SnapshotTrigger::new(policy);
    }

    /// Set ring-buffer capacity (evicts oldest events when full).
    #[must_use]
    pub const fn with_ring_capacity(mut self, cap: usize) -> Self {
        self.ring_capacity = cap;
        self
    }

    /// Attach to a process by PID and start recording.
    ///
    /// # Errors
    /// Returns `EngineError::AlreadyAttached` if already recording.
    pub fn attach(&self, pid: u32) -> Result<()> {
        if self.running.load(Ordering::Acquire) {
            let guard = self.state.read();
            if let Some(s) = guard.as_ref() {
                return Err(EngineError::AlreadyAttached(s.pid));
            }
        }
        if pid == 0 {
            return Err(EngineError::ProcessNotFound(0));
        }
        *self.state.write() = Some(RecorderEngineState::new(pid));
        self.running.store(true, Ordering::Release);
        Ok(())
    }

    /// Detach from the current process.
    ///
    /// # Errors
    /// Returns `EngineError::NotAttached` if no session is active.
    pub fn detach(&self) -> Result<TraceStats> {
        if !self.running.swap(false, Ordering::AcqRel) {
            return Err(EngineError::NotAttached);
        }
        let state = self.state.write().take();
        let stats = if let Some(s) = state {
            TraceStats {
                pid: s.pid,
                instruction_count: s.instruction_count,
                event_count: s.event_count,
                thread_count: u32::try_from(s.threads.len()).unwrap_or(u32::MAX),
                module_count: u32::try_from(s.modules.len()).unwrap_or(u32::MAX),
                elapsed: s.start_time.elapsed(),
            }
        } else {
            TraceStats::default()
        };
        Ok(stats)
    }

    /// Ingest a recorded event at the current trace position.
    ///
    /// # Errors
    /// Returns `EngineError::NotAttached` if no session is active.
    pub fn ingest_event(&self, event: RecordedEvent) -> Result<TracePos> {
        if !self.running.load(Ordering::Acquire) {
            return Err(EngineError::NotAttached);
        }

        let ns = self.ns_counter.fetch_add(100, Ordering::Relaxed);
        let pos;

        {
            let mut guard = self.state.write();
            let state = guard.as_mut().ok_or(EngineError::NotAttached)?;

            // Advance position for instruction events.
            if let RecordedEvent::Instruction { tid, ip, .. } = &event {
                state.instruction_count += 1;
                state.current_pos = state.current_pos.next_instruction()?;
                if let Some(ts) = state.threads.get_mut(tid) {
                    ts.regs.rip = *ip;
                    ts.position = state.current_pos;
                }
            }

            // Handle thread/module lifecycle events.
            match &event {
                RecordedEvent::ThreadCreate { tid, start_addr } => {
                    let mut ts = ThreadState::new(*tid);
                    ts.regs.rip = *start_addr;
                    state.threads.insert(*tid, ts);
                }
                RecordedEvent::ThreadExit { tid, .. } => {
                    state.threads.remove(tid);
                }
                RecordedEvent::ModuleLoad { base, size, name } => {
                    state.modules.push(ModuleInfo {
                        name: name.clone(),
                        base: *base,
                        size: *size,
                        path: name.clone(),
                        loaded_at: state.current_pos,
                    });
                }
                RecordedEvent::ModuleUnload { base, .. } => {
                    state.modules.retain(|m| m.base != *base);
                }
                _ => {}
            }

            pos = state.current_pos;
            state.event_count += 1;
        }

        let entry = TraceEntry { position: pos, event, timestamp_ns: ns };

        {
            let mut events = self.events.lock();
            if self.ring_capacity > 0 && events.len() >= self.ring_capacity {
                events.pop_front();
            }
            events.push_back(entry);
        }

        Ok(pos)
    }

    /// Return a snapshot of all buffered events.
    #[must_use]
    pub fn drain_events(&self) -> Vec<TraceEntry> {
        self.events.lock().drain(..).collect()
    }

    /// Peek at buffered events without draining.
    #[must_use]
    pub fn peek_events(&self) -> Vec<TraceEntry> {
        self.events.lock().iter().cloned().collect()
    }

    /// Return current thread states.
    #[must_use]
    pub fn thread_states(&self) -> Vec<ThreadState> {
        self.state.read()
            .as_ref()
            .map(|s| s.threads.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Return loaded modules.
    #[must_use]
    pub fn modules(&self) -> Vec<ModuleInfo> {
        self.state.read()
            .as_ref()
            .map(|s| s.modules.clone())
            .unwrap_or_default()
    }

    /// Return the current trace position.
    #[must_use]
    pub fn current_position(&self) -> TracePos {
        self.state.read()
            .as_ref()
            .map_or(TracePos::start(), |s| s.current_pos)
    }

    /// Return true if the engine is actively recording.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Acquire)
    }

    /// Write the accumulated trace events to a `.ttde` binary file.
    ///
    /// # Errors
    /// Returns `EngineError::TraceWrite` on failure.
    pub fn flush_to_file(&self, filename: &str) -> Result<u64> {
        let path = self.output_dir.join(filename);
        let events = self.peek_events();
        let json = serde_json::to_vec(&events)
            .map_err(|e| EngineError::TraceWrite(e.to_string()))?;
        std::fs::write(&path, &json)?;
        Ok(u64::try_from(json.len()).unwrap_or(u64::MAX))
    }

    /// Simulate ingesting `n` synthetic instruction events (useful for testing).
    ///
    /// # Errors
    /// Returns `EngineError` on failure.
    pub fn simulate_instructions(&self, n: u64) -> Result<TracePos> {
        let mut last = TracePos::start();
        for i in 0..n {
            let ip = 0x0040_0000u64 + i * 4;
            last = self.ingest_event(RecordedEvent::Instruction {
                tid: 1,
                ip,
                opcode: vec![0x90],
                len: 1,
            })?;
        }
        Ok(last)
    }
}

// ── Trace statistics ──────────────────────────────────────────────────────────

/// Statistics collected at the end of a recording session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceStats {
    pub pid: u32,
    pub instruction_count: u64,
    pub event_count: u64,
    pub thread_count: u32,
    pub module_count: u32,
    #[serde(skip)]
    pub elapsed: Duration,
}

impl std::fmt::Display for TraceStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "pid={} instructions={} events={} threads={} modules={} elapsed={:.2}s",
            self.pid,
            self.instruction_count,
            self.event_count,
            self.thread_count,
            self.module_count,
            self.elapsed.as_secs_f64()
        )
    }
}

// ── Position sequence ─────────────────────────────────────────────────────────

/// A sorted, deduplicated sequence of trace positions (e.g. for breakpoints).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PositionSequence {
    positions: BTreeMap<TracePos, String>,
}

impl PositionSequence {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a labelled position.
    pub fn insert(&mut self, pos: TracePos, label: impl Into<String>) {
        self.positions.insert(pos, label.into());
    }

    /// Return the label for `pos` if it exists.
    #[must_use]
    pub fn label(&self, pos: TracePos) -> Option<&str> {
        self.positions.get(&pos).map(String::as_str)
    }

    /// Return the next position at or after `pos`.
    #[must_use]
    pub fn next_from(&self, pos: TracePos) -> Option<TracePos> {
        self.positions.range(pos..).next().map(|(p, _)| *p)
    }

    /// Return all positions in order.
    #[must_use]
    pub fn all(&self) -> Vec<(TracePos, &str)> {
        self.positions.iter().map(|(p, l)| (*p, l.as_str())).collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.positions.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.positions.is_empty()
    }
}

// ── Shared engine handle ──────────────────────────────────────────────────────

/// A reference-counted, shareable handle to a `RecorderEngine`.
pub type SharedEngine = Arc<RecorderEngine>;

/// Create a new `SharedEngine`.
#[must_use]
pub fn new_shared_engine(output_dir: impl AsRef<Path>) -> SharedEngine {
    Arc::new(RecorderEngine::new(output_dir))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> RecorderEngine {
        RecorderEngine::new(std::env::temp_dir())
    }

    #[test]
    fn test_attach_detach() {
        let eng = make_engine();
        assert!(!eng.is_running());
        eng.attach(1234).unwrap();
        assert!(eng.is_running());
        let stats = eng.detach().unwrap();
        assert_eq!(stats.pid, 1234);
        assert!(!eng.is_running());
    }

    #[test]
    fn test_double_attach_fails() {
        let eng = make_engine();
        eng.attach(1).unwrap();
        assert!(eng.attach(2).is_err());
        eng.detach().unwrap();
    }

    #[test]
    fn test_ingest_instructions() {
        let eng = make_engine();
        eng.attach(42).unwrap();
        let pos = eng.simulate_instructions(10).unwrap();
        assert_eq!(pos.major, 10);
        let events = eng.drain_events();
        assert_eq!(events.len(), 10);
        eng.detach().unwrap();
    }

    #[test]
    fn test_thread_create_event() {
        let eng = make_engine();
        eng.attach(99).unwrap();
        eng.ingest_event(RecordedEvent::ThreadCreate { tid: 2, start_addr: 0x1234 }).unwrap();
        let threads = eng.thread_states();
        assert!(threads.iter().any(|t| t.tid == 2));
        eng.detach().unwrap();
    }

    #[test]
    fn test_module_load_unload() {
        let eng = make_engine();
        eng.attach(77).unwrap();
        eng.ingest_event(RecordedEvent::ModuleLoad {
            base: 0x7fff_0000,
            size: 0x10000,
            name: "ntdll.dll".into(),
        }).unwrap();
        assert_eq!(eng.modules().len(), 1);
        eng.ingest_event(RecordedEvent::ModuleUnload {
            base: 0x7fff_0000,
            name: "ntdll.dll".into(),
        }).unwrap();
        assert!(eng.modules().is_empty());
        eng.detach().unwrap();
    }

    #[test]
    fn test_position_sequence() {
        let mut seq = PositionSequence::new();
        seq.insert(TracePos::new(10, 0), "loop_start");
        seq.insert(TracePos::new(20, 0), "loop_end");
        assert_eq!(seq.len(), 2);
        assert_eq!(seq.label(TracePos::new(10, 0)), Some("loop_start"));
        let next = seq.next_from(TracePos::new(5, 0)).unwrap();
        assert_eq!(next, TracePos::new(10, 0));
    }

    #[test]
    fn test_ring_capacity() {
        let eng = RecorderEngine::new(std::env::temp_dir()).with_ring_capacity(5);
        eng.attach(55).unwrap();
        eng.simulate_instructions(10).unwrap();
        let events = eng.peek_events();
        assert_eq!(events.len(), 5);
        eng.detach().unwrap();
    }

    #[test]
    fn test_trace_pos_ordering() {
        let a = TracePos::new(5, 0);
        let b = TracePos::new(5, 1);
        let c = TracePos::new(6, 0);
        assert!(a < b);
        assert!(b < c);
        assert!(a < c);
    }

    #[test]
    fn test_snapshot_trigger_instruction_based() {
        let policy = SnapshotPolicy {
            every_n_instructions: 100,
            every_n_secs: 0,
            max_snapshots: 4,
            on_syscall: false,
            on_exception: false,
        };
        let mut trigger = SnapshotTrigger::new(policy);
        let dummy = RecordedEvent::Instruction { tid: 1, ip: 0, opcode: vec![], len: 1 };
        assert!(!trigger.should_snap(TracePos::new(99, 0), 0, &dummy));
        assert!(trigger.should_snap(TracePos::new(100, 0), 0, &dummy));
        assert!(!trigger.should_snap(TracePos::new(100, 0), 0, &dummy));
        assert!(trigger.should_snap(TracePos::new(200, 0), 0, &dummy));
    }

    #[test]
    fn test_snapshot_trigger_on_exception() {
        let policy = SnapshotPolicy {
            every_n_instructions: 0,
            on_exception: true,
            ..Default::default()
        };
        let mut trigger = SnapshotTrigger::new(policy);
        let exc = RecordedEvent::Exception { tid: 1, code: 0xC000_0005, addr: 0x1234, first_chance: true };
        assert!(trigger.should_snap(TracePos::start(), 0, &exc));
    }

    #[test]
    fn test_stats_display() {
        let stats = TraceStats {
            pid: 1,
            instruction_count: 100,
            event_count: 200,
            thread_count: 3,
            module_count: 5,
            elapsed: Duration::from_secs(2),
        };
        let s = stats.to_string();
        assert!(s.contains("pid=1"));
        assert!(s.contains("instructions=100"));
    }
}
