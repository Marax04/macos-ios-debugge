//! TTD event query: exception events, thread lifecycle events, module loads/unloads.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::ttd_memory_query::MemoryPosition;

// ---------------------------------------------------------------------------
// ExceptionEvent
// ---------------------------------------------------------------------------

/// Classification of exception severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExceptionSeverity {
    /// First-chance — the debugger sees it before the application.
    FirstChance,
    /// Second-chance — the application did not handle it.
    SecondChance,
    /// Non-continuable exception.
    NonContinuable,
}

impl std::fmt::Display for ExceptionSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FirstChance => f.write_str("FirstChance"),
            Self::SecondChance => f.write_str("SecondChance"),
            Self::NonContinuable => f.write_str("NonContinuable"),
        }
    }
}

/// An exception event recorded in the TTD trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionEvent {
    /// Trace position.
    pub position: MemoryPosition,
    /// Windows exception code (e.g., 0xC0000005 = access violation).
    pub code: u32,
    /// Address where the exception occurred.
    pub exception_address: u64,
    /// Thread that triggered the exception.
    pub thread_id: u32,
    /// Exception severity.
    pub severity: ExceptionSeverity,
    /// Exception-specific parameters (e.g., fault address for AV).
    pub parameters: Vec<u64>,
    /// Whether the exception was handled.
    pub handled: bool,
}

impl ExceptionEvent {
    /// Create a new exception event.
    #[must_use]
    pub const fn new(
        position: MemoryPosition,
        code: u32,
        exception_address: u64,
        thread_id: u32,
        severity: ExceptionSeverity,
    ) -> Self {
        Self {
            position,
            code,
            exception_address,
            thread_id,
            severity,
            parameters: Vec::new(),
            handled: false,
        }
    }

    /// Returns a human-readable description of the exception code.
    #[must_use]
    pub const fn code_name(&self) -> &'static str {
        windows_exception_name(self.code)
    }

    /// Whether this is an access violation (0xC0000005).
    #[must_use]
    pub const fn is_access_violation(&self) -> bool {
        self.code == 0xC000_0005
    }

    /// Whether this is a breakpoint exception (0x80000003).
    #[must_use]
    pub const fn is_breakpoint(&self) -> bool {
        self.code == 0x8000_0003
    }

    /// Whether this is a stack overflow (0xC00000FD).
    #[must_use]
    pub const fn is_stack_overflow(&self) -> bool {
        self.code == 0xC000_00FD
    }

    /// The faulting address for an access violation (parameter 1), if present.
    #[must_use]
    pub fn av_fault_address(&self) -> Option<u64> {
        if self.is_access_violation() {
            self.parameters.get(1).copied()
        } else {
            None
        }
    }

    /// Whether the access violation was a write (parameter 0 == 1).
    #[must_use]
    pub fn av_is_write(&self) -> Option<bool> {
        if self.is_access_violation() {
            self.parameters.first().map(|&p| p == 1)
        } else {
            None
        }
    }
}

impl std::fmt::Display for ExceptionEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Exception @ {} code={:#010x} ({}) addr={:#x} tid={} {}",
            self.position,
            self.code,
            self.code_name(),
            self.exception_address,
            self.thread_id,
            self.severity
        )
    }
}

const fn windows_exception_name(code: u32) -> &'static str {
    match code {
        0xC000_0005 => "ACCESS_VIOLATION",
        0xC000_0006 => "IN_PAGE_ERROR",
        0xC000_001D => "ILLEGAL_INSTRUCTION",
        0xC000_0025 => "NONCONTINUABLE_EXCEPTION",
        0xC000_008C => "ARRAY_BOUNDS_EXCEEDED",
        0xC000_008D => "FLOAT_DENORMAL_OPERAND",
        0xC000_008E => "FLOAT_DIVIDE_BY_ZERO",
        0xC000_008F => "FLOAT_INEXACT_RESULT",
        0xC000_0090 => "FLOAT_INVALID_OPERATION",
        0xC000_0091 => "FLOAT_OVERFLOW",
        0xC000_0092 => "FLOAT_STACK_CHECK",
        0xC000_0093 => "FLOAT_UNDERFLOW",
        0xC000_0094 => "INTEGER_DIVIDE_BY_ZERO",
        0xC000_0095 => "INTEGER_OVERFLOW",
        0xC000_0096 => "PRIVILEGED_INSTRUCTION",
        0xC000_00FD => "STACK_OVERFLOW",
        0xC000_0135 => "DLL_NOT_FOUND",
        0xC000_013A => "CONTROL_C_EXIT",
        0xC000_0142 => "DLL_INIT_FAILED",
        0x8000_0002 => "DATATYPE_MISALIGNMENT",
        0x8000_0003 => "BREAKPOINT",
        0x8000_0004 => "SINGLE_STEP",
        0xC000_041D => "FATAL_USER_CALLBACK_EXCEPTION",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// ThreadEvent
// ---------------------------------------------------------------------------

/// The type of a thread lifecycle event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreadEventKind {
    /// A new thread was created.
    Create,
    /// An existing thread exited.
    Exit,
    /// Thread was suspended.
    Suspend,
    /// Thread was resumed.
    Resume,
}

impl std::fmt::Display for ThreadEventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Create => f.write_str("Create"),
            Self::Exit => f.write_str("Exit"),
            Self::Suspend => f.write_str("Suspend"),
            Self::Resume => f.write_str("Resume"),
        }
    }
}

/// A thread lifecycle event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadEvent {
    /// Trace position.
    pub position: MemoryPosition,
    /// The affected thread ID.
    pub thread_id: u32,
    /// Kind of event.
    pub kind: ThreadEventKind,
    /// Exit code (for `Exit` events).
    pub exit_code: Option<u32>,
    /// Start address of the thread (for `Create` events).
    pub start_address: Option<u64>,
    /// Creating thread ID (for `Create` events).
    pub creator_thread_id: Option<u32>,
}

impl ThreadEvent {
    /// Create a thread-creation event.
    #[must_use]
    pub const fn new_create(
        position: MemoryPosition,
        thread_id: u32,
        start_address: u64,
        creator_thread_id: u32,
    ) -> Self {
        Self {
            position,
            thread_id,
            kind: ThreadEventKind::Create,
            exit_code: None,
            start_address: Some(start_address),
            creator_thread_id: Some(creator_thread_id),
        }
    }

    /// Create a thread-exit event.
    #[must_use]
    pub const fn new_exit(position: MemoryPosition, thread_id: u32, exit_code: u32) -> Self {
        Self {
            position,
            thread_id,
            kind: ThreadEventKind::Exit,
            exit_code: Some(exit_code),
            start_address: None,
            creator_thread_id: None,
        }
    }
}

impl std::fmt::Display for ThreadEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Thread {} {} @ {}",
            self.kind, self.thread_id, self.position
        )?;
        if let Some(code) = self.exit_code {
            write!(f, " exit={code:#x}")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ModuleEvent
// ---------------------------------------------------------------------------

/// Module load or unload event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModuleEvent {
    /// Trace position.
    pub position: MemoryPosition,
    /// Module base address.
    pub base_address: u64,
    /// Module size in bytes.
    pub size: u64,
    /// Module path (e.g., `C:\Windows\System32\ntdll.dll`).
    pub path: String,
    /// Whether this is a load (true) or unload (false) event.
    pub is_load: bool,
    /// Optional checksum.
    pub checksum: Option<u32>,
    /// Optional timestamp.
    pub timestamp: Option<u32>,
}

impl ModuleEvent {
    /// Create a module-load event.
    #[must_use]
    pub fn new_load(
        position: MemoryPosition,
        base_address: u64,
        size: u64,
        path: impl Into<String>,
    ) -> Self {
        Self {
            position,
            base_address,
            size,
            path: path.into(),
            is_load: true,
            checksum: None,
            timestamp: None,
        }
    }

    /// Create a module-unload event.
    #[must_use]
    pub fn new_unload(position: MemoryPosition, base_address: u64, path: impl Into<String>) -> Self {
        Self {
            position,
            base_address,
            size: 0,
            path: path.into(),
            is_load: false,
            checksum: None,
            timestamp: None,
        }
    }

    /// Exclusive end address of the module.
    #[must_use]
    pub const fn end_address(&self) -> u64 {
        self.base_address.saturating_add(self.size)
    }

    /// Whether `addr` falls within this module's address range.
    #[must_use]
    pub const fn contains_address(&self, addr: u64) -> bool {
        self.size > 0 && addr >= self.base_address && addr < self.end_address()
    }

    /// Module file name (without directory).
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(&self.path)
    }
}

impl std::fmt::Display for ModuleEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let action = if self.is_load { "Load" } else { "Unload" };
        write!(
            f,
            "Module {} {} base={:#x} size={:#x} @ {}",
            action,
            self.file_name(),
            self.base_address,
            self.size,
            self.position
        )
    }
}

// ---------------------------------------------------------------------------
// TtdEvent — unified event enum
// ---------------------------------------------------------------------------

/// A unified TTD event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TtdEvent {
    Exception(ExceptionEvent),
    Thread(ThreadEvent),
    Module(ModuleEvent),
}

impl TtdEvent {
    /// The position of this event.
    #[must_use]
    pub const fn position(&self) -> MemoryPosition {
        match self {
            Self::Exception(e) => e.position,
            Self::Thread(t) => t.position,
            Self::Module(m) => m.position,
        }
    }

    /// Whether this is an exception event.
    #[must_use]
    pub const fn is_exception(&self) -> bool {
        matches!(self, Self::Exception(_))
    }

    /// Whether this is a thread event.
    #[must_use]
    pub const fn is_thread(&self) -> bool {
        matches!(self, Self::Thread(_))
    }

    /// Whether this is a module event.
    #[must_use]
    pub const fn is_module(&self) -> bool {
        matches!(self, Self::Module(_))
    }
}

impl std::fmt::Display for TtdEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exception(e) => write!(f, "{e}"),
            Self::Thread(t) => write!(f, "{t}"),
            Self::Module(m) => write!(f, "{m}"),
        }
    }
}

// ---------------------------------------------------------------------------
// TtdEventQuery
// ---------------------------------------------------------------------------

/// Query engine for TTD events: exceptions, thread lifecycle, and module loads.
pub struct TtdEventQuery {
    /// All events sorted by position
    events: BTreeMap<MemoryPosition, Vec<TtdEvent>>,
    /// Thread state: `thread_id` -> list of lifecycle events
    thread_events: HashMap<u32, Vec<ThreadEvent>>,
    /// Module state: `base_address` -> latest load/unload event
    module_events: Vec<ModuleEvent>,
    /// Exception events sorted by position
    exception_events: Vec<ExceptionEvent>,
}

impl TtdEventQuery {
    /// Create an empty event query engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: BTreeMap::new(),
            thread_events: HashMap::new(),
            module_events: Vec::new(),
            exception_events: Vec::new(),
        }
    }

    /// Record an exception event.
    pub fn record_exception(&mut self, event: ExceptionEvent) {
        let pos = event.position;
        self.events
            .entry(pos)
            .or_default()
            .push(TtdEvent::Exception(event.clone()));
        self.exception_events.push(event);
    }

    /// Record a thread event.
    pub fn record_thread_event(&mut self, event: ThreadEvent) {
        let pos = event.position;
        let tid = event.thread_id;
        self.events
            .entry(pos)
            .or_default()
            .push(TtdEvent::Thread(event.clone()));
        self.thread_events.entry(tid).or_default().push(event);
    }

    /// Record a module event.
    pub fn record_module_event(&mut self, event: ModuleEvent) {
        let pos = event.position;
        self.events
            .entry(pos)
            .or_default()
            .push(TtdEvent::Module(event.clone()));
        self.module_events.push(event);
    }

    /// Return all events in a position range.
    #[must_use]
    pub fn events_in_range(
        &self,
        from: MemoryPosition,
        to: MemoryPosition,
    ) -> Vec<&TtdEvent> {
        use std::ops::Bound;
        self.events
            .range((Bound::Included(&from), Bound::Included(&to)))
            .flat_map(|(_, evs)| evs.iter())
            .collect()
    }

    /// Return all exception events.
    #[must_use]
    pub fn all_exceptions(&self) -> &[ExceptionEvent] {
        &self.exception_events
    }

    /// Return exceptions filtered by code.
    #[must_use]
    pub fn exceptions_by_code(&self, code: u32) -> Vec<&ExceptionEvent> {
        self.exception_events
            .iter()
            .filter(|e| e.code == code)
            .collect()
    }

    /// Return all access violation exceptions.
    #[must_use]
    pub fn access_violations(&self) -> Vec<&ExceptionEvent> {
        self.exceptions_by_code(0xC000_0005)
    }

    /// Return all thread creation events.
    #[must_use]
    pub fn thread_creations(&self) -> Vec<&ThreadEvent> {
        self.thread_events
            .values()
            .flat_map(|evs| evs.iter())
            .filter(|e| e.kind == ThreadEventKind::Create)
            .collect()
    }

    /// Return all thread exit events.
    #[must_use]
    pub fn thread_exits(&self) -> Vec<&ThreadEvent> {
        self.thread_events
            .values()
            .flat_map(|evs| evs.iter())
            .filter(|e| e.kind == ThreadEventKind::Exit)
            .collect()
    }

    /// Return all events for a specific thread.
    #[must_use]
    pub fn events_for_thread(&self, thread_id: u32) -> &[ThreadEvent] {
        self.thread_events
            .get(&thread_id)
            .map_or(&[], Vec::as_slice)
    }

    /// Return all module load events.
    #[must_use]
    pub fn module_loads(&self) -> Vec<&ModuleEvent> {
        self.module_events.iter().filter(|m| m.is_load).collect()
    }

    /// Return all module unload events.
    #[must_use]
    pub fn module_unloads(&self) -> Vec<&ModuleEvent> {
        self.module_events.iter().filter(|m| !m.is_load).collect()
    }

    /// Return the loaded module that contains `addr` at position `pos`.
    #[must_use]
    pub fn module_at_address(&self, addr: u64, pos: MemoryPosition) -> Option<&ModuleEvent> {
        // Find the last load before pos for a module containing addr
        self.module_events
            .iter()
            .filter(|m| m.is_load && m.position <= pos && m.contains_address(addr))
            .max_by_key(|m| m.position)
    }

    /// Return all modules loaded at position `pos`.
    #[must_use]
    pub fn loaded_modules_at(&self, pos: MemoryPosition) -> Vec<&ModuleEvent> {
        let mut base_to_event: HashMap<u64, &ModuleEvent> = HashMap::new();
        for ev in self.module_events.iter().filter(|m| m.position <= pos) {
            if ev.is_load {
                base_to_event.insert(ev.base_address, ev);
            } else {
                base_to_event.remove(&ev.base_address);
            }
        }
        let mut result: Vec<&ModuleEvent> = base_to_event.into_values().collect();
        result.sort_by_key(|m| m.base_address);
        result
    }

    /// Count exceptions by code.
    #[must_use]
    pub fn exception_histogram(&self) -> HashMap<u32, usize> {
        let mut hist: HashMap<u32, usize> = HashMap::new();
        for e in &self.exception_events {
            *hist.entry(e.code).or_default() += 1;
        }
        hist
    }

    /// All unique thread IDs that have events.
    #[must_use]
    pub fn all_thread_ids(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self.thread_events.keys().copied().collect();
        ids.sort_unstable();
        ids
    }

    /// Total event count.
    #[must_use]
    pub fn total_events(&self) -> usize {
        self.events.values().map(std::vec::Vec::len).sum()
    }

    /// Find exceptions at a specific address.
    #[must_use]
    pub fn exceptions_at_address(&self, addr: u64) -> Vec<&ExceptionEvent> {
        self.exception_events
            .iter()
            .filter(|e| e.exception_address == addr)
            .collect()
    }

    /// Find threads that exited with a non-zero exit code.
    #[must_use]
    pub fn failed_thread_exits(&self) -> Vec<&ThreadEvent> {
        self.thread_events
            .values()
            .flat_map(|evs| evs.iter())
            .filter(|e| e.kind == ThreadEventKind::Exit && e.exit_code != Some(0))
            .collect()
    }

    /// Return the first exception in the trace.
    #[must_use]
    pub fn first_exception(&self) -> Option<&ExceptionEvent> {
        self.exception_events
            .iter()
            .min_by_key(|e| e.position)
    }

    /// Return second-chance exceptions (likely fatal crashes).
    #[must_use]
    pub fn second_chance_exceptions(&self) -> Vec<&ExceptionEvent> {
        self.exception_events
            .iter()
            .filter(|e| e.severity == ExceptionSeverity::SecondChance)
            .collect()
    }

    /// Find the module that was loaded closest before `pos` (most recently loaded at `pos`).
    #[must_use]
    pub fn last_module_load_before(&self, pos: MemoryPosition) -> Option<&ModuleEvent> {
        self.module_events
            .iter()
            .filter(|m| m.is_load && m.position <= pos)
            .max_by_key(|m| m.position)
    }
}

impl Default for TtdEventQuery {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TtdEventQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TtdEventQuery")
            .field("total_events", &self.total_events())
            .field("exceptions", &self.exception_events.len())
            .field("modules", &self.module_events.len())
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn pos(seq: u64) -> MemoryPosition {
        MemoryPosition::new(seq, 0)
    }

    #[test]
    fn test_exception_code_name() {
        let e = ExceptionEvent::new(pos(1), 0xC000_0005, 0x1234, 1, ExceptionSeverity::FirstChance);
        assert_eq!(e.code_name(), "ACCESS_VIOLATION");
        assert!(e.is_access_violation());
    }

    #[test]
    fn test_exception_with_params() {
        let mut e = ExceptionEvent::new(
            pos(1),
            0xC000_0005,
            0xBEEF,
            1,
            ExceptionSeverity::SecondChance,
        );
        e.parameters = vec![1, 0xDEAD_0000]; // write AV at 0xDEAD0000
        assert_eq!(e.av_fault_address(), Some(0xDEAD_0000));
        assert_eq!(e.av_is_write(), Some(true));
    }

    #[test]
    fn test_thread_events() {
        let mut q = TtdEventQuery::new();
        q.record_thread_event(ThreadEvent::new_create(pos(1), 42, 0x5000, 1));
        q.record_thread_event(ThreadEvent::new_exit(pos(10), 42, 0));

        let creates = q.thread_creations();
        assert_eq!(creates.len(), 1);
        assert_eq!(creates[0].thread_id, 42);

        let exits = q.thread_exits();
        assert_eq!(exits.len(), 1);
        assert_eq!(exits[0].exit_code, Some(0));
    }

    #[test]
    fn test_module_events() {
        let mut q = TtdEventQuery::new();
        q.record_module_event(ModuleEvent::new_load(
            pos(1),
            0x7FFF_0000,
            0x1_0000,
            "ntdll.dll",
        ));
        q.record_module_event(ModuleEvent::new_load(
            pos(2),
            0x6FFF_0000,
            0x5000,
            "kernel32.dll",
        ));

        let loads = q.module_loads();
        assert_eq!(loads.len(), 2);

        let loaded = q.loaded_modules_at(pos(5));
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn test_module_contains_address() {
        let m = ModuleEvent::new_load(pos(1), 0x1000_0000, 0x1000, "test.dll");
        assert!(m.contains_address(0x1000_0500));
        assert!(!m.contains_address(0x2000_0000));
    }

    #[test]
    fn test_module_unload() {
        let mut q = TtdEventQuery::new();
        q.record_module_event(ModuleEvent::new_load(pos(1), 0x4000_0000, 0x8000, "foo.dll"));
        q.record_module_event(ModuleEvent::new_unload(pos(5), 0x4000_0000, "foo.dll"));

        let loaded = q.loaded_modules_at(pos(3));
        assert_eq!(loaded.len(), 1);

        let loaded_after = q.loaded_modules_at(pos(6));
        assert!(loaded_after.is_empty());
    }

    #[test]
    fn test_exception_histogram() {
        let mut q = TtdEventQuery::new();
        for i in 0..3u64 {
            q.record_exception(ExceptionEvent::new(
                pos(i + 1),
                0xC000_0005,
                0x1000 + i,
                1,
                ExceptionSeverity::FirstChance,
            ));
        }
        q.record_exception(ExceptionEvent::new(
            pos(10),
            0x8000_0003,
            0x2000,
            1,
            ExceptionSeverity::FirstChance,
        ));

        let hist = q.exception_histogram();
        assert_eq!(*hist.get(&0xC000_0005).unwrap(), 3);
        assert_eq!(*hist.get(&0x8000_0003).unwrap(), 1);
    }

    #[test]
    fn test_second_chance_exceptions() {
        let mut q = TtdEventQuery::new();
        q.record_exception(ExceptionEvent::new(
            pos(1),
            0xC000_0005,
            0x1000,
            1,
            ExceptionSeverity::FirstChance,
        ));
        q.record_exception(ExceptionEvent::new(
            pos(2),
            0xC000_0005,
            0x1000,
            1,
            ExceptionSeverity::SecondChance,
        ));

        let sc = q.second_chance_exceptions();
        assert_eq!(sc.len(), 1);
    }

    #[test]
    fn test_failed_thread_exits() {
        let mut q = TtdEventQuery::new();
        q.record_thread_event(ThreadEvent::new_exit(pos(5), 1, 0));
        q.record_thread_event(ThreadEvent::new_exit(pos(6), 2, 1));

        let failed = q.failed_thread_exits();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].thread_id, 2);
    }

    #[test]
    fn test_module_file_name() {
        let m = ModuleEvent::new_load(pos(1), 0, 0, r"C:\Windows\System32\ntdll.dll");
        assert_eq!(m.file_name(), "ntdll.dll");
    }
}
