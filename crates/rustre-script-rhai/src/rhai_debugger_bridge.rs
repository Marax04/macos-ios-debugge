//! `rhai_debugger_bridge` — Bridge between Rhai scripts and the `RustRE` debugger.
//!
//! Provides [`RhaiDebuggerBridge`], [`DebugAction`], and [`BreakpointHandler`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

// ── DebugAction ───────────────────────────────────────────────────────────────

/// An action the debugger should take in response to a script request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DebugAction {
    /// Continue execution until the next breakpoint.
    Continue,
    /// Execute exactly one instruction then pause.
    StepInto,
    /// Execute until the current function returns.
    StepOver,
    /// Step out of the current function.
    StepOut,
    /// Pause execution immediately.
    Pause,
    /// Terminate the target process.
    Kill,
    /// Set a software breakpoint at the given address.
    SetBreakpoint { address: u64, id: u32 },
    /// Remove a breakpoint by id.
    RemoveBreakpoint { id: u32 },
    /// Read memory at `address` for `size` bytes.
    ReadMemory { address: u64, size: u32 },
    /// Write `bytes` to memory at `address`.
    WriteMemory { address: u64, bytes: Vec<u8> },
    /// Read a named register's value.
    ReadRegister { name: String },
    /// Write a value to a named register.
    WriteRegister { name: String, value: u64 },
    /// Evaluate an expression in the debugger's context.
    Evaluate { expr: String },
}

impl std::fmt::Display for DebugAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Continue => write!(f, "Continue"),
            Self::StepInto => write!(f, "StepInto"),
            Self::StepOver => write!(f, "StepOver"),
            Self::StepOut => write!(f, "StepOut"),
            Self::Pause => write!(f, "Pause"),
            Self::Kill => write!(f, "Kill"),
            Self::SetBreakpoint { address, id } => write!(f, "SetBreakpoint({address:#x}, id={id})"),
            Self::RemoveBreakpoint { id } => write!(f, "RemoveBreakpoint({id})"),
            Self::ReadMemory { address, size } => write!(f, "ReadMemory({address:#x}, {size})"),
            Self::WriteMemory { address, bytes } => write!(f, "WriteMemory({address:#x}, {} bytes)", bytes.len()),
            Self::ReadRegister { name } => write!(f, "ReadRegister({name})"),
            Self::WriteRegister { name, value } => write!(f, "WriteRegister({name}, {value:#x})"),
            Self::Evaluate { expr } => write!(f, "Evaluate({expr})"),
        }
    }
}

// ── DebugEvent ────────────────────────────────────────────────────────────────

/// An event reported from the debugger to the Rhai script layer.
#[derive(Debug, Clone)]
pub enum DebugEvent {
    /// Execution stopped at a breakpoint.
    BreakpointHit { id: u32, address: u64, thread_id: u32 },
    /// Execution paused after single-step.
    SingleStep { address: u64 },
    /// Target process exited.
    ProcessExited { exit_code: i32 },
    /// An exception/signal occurred.
    Exception { code: u32, address: u64, description: String },
    /// Memory read completed.
    MemoryRead { address: u64, data: Vec<u8> },
    /// Register read completed.
    RegisterValue { name: String, value: u64 },
    /// Expression evaluation result.
    EvalResult { expr: String, result: String },
    /// A log message from the debugger.
    Log { message: String },
}

impl std::fmt::Display for DebugEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BreakpointHit { id, address, thread_id } => {
                write!(f, "BreakpointHit(id={id}, addr={address:#x}, tid={thread_id})")
            }
            Self::SingleStep { address } => write!(f, "SingleStep({address:#x})"),
            Self::ProcessExited { exit_code } => write!(f, "ProcessExited({exit_code})"),
            Self::Exception { code, address, description } => {
                write!(f, "Exception(code={code:#x}, addr={address:#x}, {description})")
            }
            Self::MemoryRead { address, data } => {
                write!(f, "MemoryRead({address:#x}, {} bytes)", data.len())
            }
            Self::RegisterValue { name, value } => write!(f, "RegisterValue({name}={value:#x})"),
            Self::EvalResult { expr, result } => write!(f, "EvalResult({expr} => {result})"),
            Self::Log { message } => write!(f, "Log({message})"),
        }
    }
}

// ── BreakpointHandler ─────────────────────────────────────────────────────────

/// A Rhai-side breakpoint handler: stores a script body to run when hit.
#[derive(Debug, Clone)]
pub struct BreakpointHandler {
    pub breakpoint_id: u32,
    pub address: u64,
    /// Rhai script snippet invoked when the breakpoint is hit.
    pub script: String,
    /// Whether the breakpoint is enabled.
    pub enabled: bool,
    /// Hit count.
    pub hit_count: u64,
    /// If set, only trigger every `stride`-th hit.
    pub stride: Option<u64>,
    /// Optional label.
    pub label: String,
    /// Condition expression (Rhai code that must evaluate to `true` for the bp to fire).
    pub condition: Option<String>,
}

impl BreakpointHandler {
    /// Create a new handler.
    #[must_use]
    pub fn new(breakpoint_id: u32, address: u64, script: impl Into<String>) -> Self {
        Self {
            breakpoint_id,
            address,
            script: script.into(),
            enabled: true,
            hit_count: 0,
            stride: None,
            label: String::new(),
            condition: None,
        }
    }

    /// Attach a label.
    #[must_use]
    pub fn labeled(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    /// Set a stride (fire every N hits).
    #[must_use]
    pub const fn with_stride(mut self, n: u64) -> Self {
        self.stride = Some(n);
        self
    }

    /// Set a condition expression.
    #[must_use]
    pub fn with_condition(mut self, cond: impl Into<String>) -> Self {
        self.condition = Some(cond.into());
        self
    }

    /// Record a hit and return whether the script should be invoked.
    pub const fn on_hit(&mut self) -> bool {
        if !self.enabled {
            return false;
        }
        self.hit_count += 1;
        if let Some(stride) = self.stride {
            if stride == 0 {
                return true;
            }
            self.hit_count.is_multiple_of(stride)
        } else {
            true
        }
    }

    /// Disable this handler.
    pub const fn disable(&mut self) {
        self.enabled = false;
    }

    /// Enable this handler.
    pub const fn enable(&mut self) {
        self.enabled = true;
    }
}

// ── ActionQueue ───────────────────────────────────────────────────────────────

/// A thread-safe queue of pending debugger actions.
#[derive(Debug, Default, Clone)]
pub struct ActionQueue {
    inner: Arc<Mutex<Vec<DebugAction>>>,
}

impl ActionQueue {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push an action into the queue.
    pub fn push(&self, action: DebugAction) {
        let mut g = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        g.push(action);
    }

    /// Drain all pending actions.
    pub fn drain(&self) -> Vec<DebugAction> {
        let mut g = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *g)
    }

    /// Number of pending actions.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len()
    }

    /// Whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ── EventLog ──────────────────────────────────────────────────────────────────

/// A bounded log of debugger events received during a session.
#[derive(Debug, Default)]
pub struct EventLog {
    events: Vec<DebugEvent>,
    max_size: usize,
}

impl EventLog {
    /// Create a new log with the given capacity.
    #[must_use]
    pub const fn new(max_size: usize) -> Self {
        Self {
            events: Vec::new(),
            max_size,
        }
    }

    /// Append an event.
    pub fn push(&mut self, event: DebugEvent) {
        if self.events.len() >= self.max_size {
            self.events.remove(0);
        }
        self.events.push(event);
    }

    /// All events.
    #[must_use]
    pub fn all(&self) -> &[DebugEvent] {
        &self.events
    }

    /// Most recent event.
    #[must_use]
    pub fn last(&self) -> Option<&DebugEvent> {
        self.events.last()
    }

    /// Events matching breakpoint hits.
    #[must_use]
    pub fn breakpoint_hits(&self) -> Vec<&DebugEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e, DebugEvent::BreakpointHit { .. }))
            .collect()
    }

    /// Total events logged.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.events.len()
    }

    /// Return `true` if the log is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Clear the log.
    pub fn clear(&mut self) {
        self.events.clear();
    }
}

// ── RhaiDebuggerBridge ────────────────────────────────────────────────────────

/// Bridges Rhai script calls to debugger actions and processes incoming events.
///
/// Maintains a map of breakpoint handlers, an action queue for outgoing commands,
/// and an event log for incoming notifications.
#[derive(Debug)]
pub struct RhaiDebuggerBridge {
    /// Registered breakpoint handlers keyed by breakpoint id.
    pub handlers: HashMap<u32, BreakpointHandler>,
    /// Outbound action queue (script → debugger).
    pub actions: ActionQueue,
    /// Inbound event log (debugger → script).
    pub events: EventLog,
    /// Whether the target is currently running.
    pub is_running: bool,
    /// Current program counter (updated on each event).
    pub current_pc: u64,
    /// Next breakpoint id to assign.
    next_bp_id: u32,
    /// Register cache from the last register-read event.
    registers: HashMap<String, u64>,
}

impl RhaiDebuggerBridge {
    /// Create a new bridge.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
            actions: ActionQueue::new(),
            events: EventLog::new(1024),
            is_running: false,
            current_pc: 0,
            next_bp_id: 1,
            registers: HashMap::new(),
        }
    }

    // ── Breakpoint management ─────────────────────────────────────────────────

    /// Register a breakpoint at `address` with a Rhai `script` body.
    /// Returns the assigned breakpoint id.
    pub fn set_breakpoint(&mut self, address: u64, script: impl Into<String>) -> u32 {
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        let handler = BreakpointHandler::new(id, address, script);
        self.handlers.insert(id, handler);
        self.actions.push(DebugAction::SetBreakpoint { address, id });
        id
    }

    /// Remove a breakpoint by id.
    pub fn remove_breakpoint(&mut self, id: u32) {
        self.handlers.remove(&id);
        self.actions.push(DebugAction::RemoveBreakpoint { id });
    }

    /// Enable a breakpoint.
    pub fn enable_breakpoint(&mut self, id: u32) {
        if let Some(h) = self.handlers.get_mut(&id) {
            h.enable();
        }
    }

    /// Disable a breakpoint.
    pub fn disable_breakpoint(&mut self, id: u32) {
        if let Some(h) = self.handlers.get_mut(&id) {
            h.disable();
        }
    }

    /// Get the hit count for a breakpoint.
    #[must_use]
    pub fn hit_count(&self, id: u32) -> u64 {
        self.handlers.get(&id).map_or(0, |h| h.hit_count)
    }

    // ── Execution control ─────────────────────────────────────────────────────

    /// Queue a Continue action.
    pub fn do_continue(&mut self) {
        self.is_running = true;
        self.actions.push(DebugAction::Continue);
    }

    /// Queue a `StepInto` action.
    pub fn step_into(&mut self) {
        self.actions.push(DebugAction::StepInto);
    }

    /// Queue a `StepOver` action.
    pub fn step_over(&mut self) {
        self.actions.push(DebugAction::StepOver);
    }

    /// Queue a `StepOut` action.
    pub fn step_out(&mut self) {
        self.actions.push(DebugAction::StepOut);
    }

    /// Queue a Pause action.
    pub fn pause(&mut self) {
        self.is_running = false;
        self.actions.push(DebugAction::Pause);
    }

    /// Queue a Kill action.
    pub fn kill(&mut self) {
        self.is_running = false;
        self.actions.push(DebugAction::Kill);
    }

    // ── Memory / register access ──────────────────────────────────────────────

    /// Queue a memory read request.
    pub fn read_memory(&mut self, address: u64, size: u32) {
        self.actions.push(DebugAction::ReadMemory { address, size });
    }

    /// Queue a memory write request.
    pub fn write_memory(&mut self, address: u64, bytes: Vec<u8>) {
        self.actions.push(DebugAction::WriteMemory { address, bytes });
    }

    /// Queue a register read request.
    pub fn read_register(&mut self, name: impl Into<String>) {
        self.actions.push(DebugAction::ReadRegister { name: name.into() });
    }

    /// Queue a register write request.
    pub fn write_register(&mut self, name: impl Into<String>, value: u64) {
        self.actions.push(DebugAction::WriteRegister { name: name.into(), value });
    }

    /// Return the last known value of a register from the cache.
    #[must_use]
    pub fn cached_register(&self, name: &str) -> Option<u64> {
        self.registers.get(name).copied()
    }

    // ── Event processing ──────────────────────────────────────────────────────

    /// Process an incoming event from the debugger.
    /// Returns the Rhai script bodies to execute (from matching handlers).
    pub fn process_event(&mut self, event: DebugEvent) -> Vec<String> {
        let mut scripts = Vec::new();

        match &event {
            DebugEvent::BreakpointHit { id, address, .. } => {
                self.is_running = false;
                self.current_pc = *address;
                let id = *id;
                if let Some(handler) = self.handlers.get_mut(&id)
                    && handler.on_hit() {
                    scripts.push(handler.script.clone());
                }
            }
            DebugEvent::SingleStep { address } => {
                self.is_running = false;
                self.current_pc = *address;
            }
            DebugEvent::ProcessExited { .. } => {
                self.is_running = false;
            }
            DebugEvent::RegisterValue { name, value } => {
                self.registers.insert(name.clone(), *value);
            }
            _ => {}
        }

        self.events.push(event);
        scripts
    }

    /// Drain pending actions for transmission to the debugger backend.
    pub fn drain_actions(&mut self) -> Vec<DebugAction> {
        self.actions.drain()
    }

    /// Total number of registered handlers.
    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }

    /// All breakpoint addresses.
    #[must_use]
    pub fn breakpoint_addresses(&self) -> Vec<u64> {
        self.handlers.values().map(|h| h.address).collect()
    }
}

impl Default for RhaiDebuggerBridge {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_action_display() {
        let a = DebugAction::Continue;
        assert_eq!(a.to_string(), "Continue");
        let b = DebugAction::SetBreakpoint { address: 0x1000, id: 1 };
        assert!(b.to_string().contains("0x1000"));
    }

    #[test]
    fn test_debug_event_display() {
        let e = DebugEvent::BreakpointHit { id: 1, address: 0x2000, thread_id: 4 };
        assert!(e.to_string().contains("0x2000"));
    }

    #[test]
    fn test_breakpoint_handler_hit_basic() {
        let mut h = BreakpointHandler::new(1, 0x1000, "rustre_log(\"hit\");");
        assert!(h.on_hit());
        assert_eq!(h.hit_count, 1);
    }

    #[test]
    fn test_breakpoint_handler_disabled() {
        let mut h = BreakpointHandler::new(2, 0x2000, "");
        h.disable();
        assert!(!h.on_hit());
    }

    #[test]
    fn test_breakpoint_handler_stride() {
        let mut h = BreakpointHandler::new(3, 0x3000, "").with_stride(3);
        assert!(!h.on_hit()); // hit 1
        assert!(!h.on_hit()); // hit 2
        assert!(h.on_hit());  // hit 3
    }

    #[test]
    fn test_breakpoint_handler_labeled() {
        let h = BreakpointHandler::new(4, 0x4000, "").labeled("my bp");
        assert_eq!(h.label, "my bp");
    }

    #[test]
    fn test_action_queue_push_drain() {
        let q = ActionQueue::new();
        q.push(DebugAction::Continue);
        q.push(DebugAction::Pause);
        assert_eq!(q.len(), 2);
        let drained = q.drain();
        assert_eq!(drained.len(), 2);
        assert!(q.is_empty());
    }

    #[test]
    fn test_event_log_push_and_last() {
        let mut log = EventLog::new(5);
        log.push(DebugEvent::Log { message: "hello".to_string() });
        assert_eq!(log.len(), 1);
        assert!(matches!(log.last(), Some(DebugEvent::Log { .. })));
    }

    #[test]
    fn test_event_log_max_size() {
        let mut log = EventLog::new(3);
        for i in 0..10 {
            log.push(DebugEvent::SingleStep { address: i });
        }
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn test_event_log_breakpoint_hits_filter() {
        let mut log = EventLog::new(20);
        log.push(DebugEvent::BreakpointHit { id: 1, address: 0x1000, thread_id: 1 });
        log.push(DebugEvent::SingleStep { address: 0x1001 });
        log.push(DebugEvent::BreakpointHit { id: 2, address: 0x2000, thread_id: 1 });
        assert_eq!(log.breakpoint_hits().len(), 2);
    }

    #[test]
    fn test_bridge_set_breakpoint() {
        let mut b = RhaiDebuggerBridge::new();
        let id = b.set_breakpoint(0x1000, "print(\"hit\");");
        assert_eq!(id, 1);
        assert_eq!(b.handler_count(), 1);
        assert!(!b.actions.is_empty());
    }

    #[test]
    fn test_bridge_remove_breakpoint() {
        let mut b = RhaiDebuggerBridge::new();
        let id = b.set_breakpoint(0x1000, "");
        b.remove_breakpoint(id);
        assert_eq!(b.handler_count(), 0);
    }

    #[test]
    fn test_bridge_continue_sets_running() {
        let mut b = RhaiDebuggerBridge::new();
        b.do_continue();
        assert!(b.is_running);
    }

    #[test]
    fn test_bridge_pause_clears_running() {
        let mut b = RhaiDebuggerBridge::new();
        b.is_running = true;
        b.pause();
        assert!(!b.is_running);
    }

    #[test]
    fn test_bridge_process_breakpoint_hit() {
        let mut b = RhaiDebuggerBridge::new();
        let id = b.set_breakpoint(0x5000, "print(\"stop\");");
        let scripts = b.process_event(DebugEvent::BreakpointHit {
            id,
            address: 0x5000,
            thread_id: 1,
        });
        assert!(!scripts.is_empty());
        assert_eq!(b.current_pc, 0x5000);
        assert!(!b.is_running);
    }

    #[test]
    fn test_bridge_process_register_value_caches() {
        let mut b = RhaiDebuggerBridge::new();
        b.process_event(DebugEvent::RegisterValue {
            name: "rax".to_string(),
            value: 0xDEAD,
        });
        assert_eq!(b.cached_register("rax"), Some(0xDEAD));
    }

    #[test]
    fn test_bridge_drain_actions() {
        let mut b = RhaiDebuggerBridge::new();
        b.step_into();
        b.step_over();
        let actions = b.drain_actions();
        assert_eq!(actions.len(), 2);
        assert!(b.actions.is_empty());
    }

    #[test]
    fn test_bridge_breakpoint_addresses() {
        let mut b = RhaiDebuggerBridge::new();
        b.set_breakpoint(0xAAAA, "");
        b.set_breakpoint(0xBBBB, "");
        let addrs = b.breakpoint_addresses();
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn test_bridge_hit_count() {
        let mut b = RhaiDebuggerBridge::new();
        let id = b.set_breakpoint(0x1000, "");
        b.process_event(DebugEvent::BreakpointHit { id, address: 0x1000, thread_id: 1 });
        b.process_event(DebugEvent::BreakpointHit { id, address: 0x1000, thread_id: 1 });
        assert_eq!(b.hit_count(id), 2);
    }

    #[test]
    fn test_bridge_disable_enable_breakpoint() {
        let mut b = RhaiDebuggerBridge::new();
        let id = b.set_breakpoint(0x1000, "");
        b.disable_breakpoint(id);
        assert!(!b.handlers[&id].enabled);
        b.enable_breakpoint(id);
        assert!(b.handlers[&id].enabled);
    }

    #[test]
    fn test_bridge_kill_clears_running() {
        let mut b = RhaiDebuggerBridge::new();
        b.is_running = true;
        b.kill();
        assert!(!b.is_running);
    }
}
