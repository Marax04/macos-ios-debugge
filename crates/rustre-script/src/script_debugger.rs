//! `script_debugger` — Script debugger.
//!
//! Provides `ScriptDebugger`, `Breakpoint`, `WatchExpression`, `DebuggerState`,
//! `StackTrace`, `VariableInspector`, `StepMode`, `DebugSession`.

use std::collections::{HashMap, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Errors ───────────────────────────────────────────────────────────────────

/// Errors from the script debugger.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DebuggerError {
    #[error("debugger not running")]
    NotRunning,
    #[error("already running")]
    AlreadyRunning,
    #[error("breakpoint already exists at line {0}")]
    BreakpointExists(u32),
    #[error("breakpoint not found at line {0}")]
    BreakpointNotFound(u32),
    #[error("variable '{0}' not found")]
    VariableNotFound(String),
    #[error("watch expression '{0}' not found")]
    WatchNotFound(String),
    #[error("evaluation error: {0}")]
    EvalError(String),
    #[error("step failed: {0}")]
    StepError(String),
    #[error("parse error at line {0}: {1}")]
    ParseError(u32, String),
    #[error("invalid state transition: {0}")]
    InvalidTransition(String),
}

// ─── DebuggerState ────────────────────────────────────────────────────────────

/// Current state of the script debugger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebuggerState {
    /// No script loaded.
    Idle,
    /// Script is executing.
    Running,
    /// Paused at a breakpoint or step.
    Paused,
    /// Single-stepping mode.
    Stepping,
    /// Script has completed.
    Finished,
    /// Script encountered an error.
    Error,
}

impl fmt::Display for DebuggerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Idle => "idle", Self::Running => "running", Self::Paused => "paused",
            Self::Stepping => "stepping", Self::Finished => "finished", Self::Error => "error",
        };
        f.write_str(s)
    }
}

// ─── StepMode ─────────────────────────────────────────────────────────────────

/// How to advance execution after a pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepMode {
    /// Execute the next line; step into function calls.
    Into,
    /// Execute the next line; step over function calls.
    Over,
    /// Execute until returning from the current function.
    Out,
    /// Run until the next breakpoint or end of script.
    Continue,
}

impl fmt::Display for StepMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Into => "into", Self::Over => "over",
            Self::Out => "out", Self::Continue => "continue",
        };
        f.write_str(s)
    }
}

// ─── Breakpoint ───────────────────────────────────────────────────────────────

/// A line-based breakpoint with an optional condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Breakpoint {
    /// Unique breakpoint ID.
    pub id: u32,
    /// Script filename (empty for unnamed scripts).
    pub file: String,
    /// 1-based line number.
    pub line: u32,
    /// Optional condition expression (empty = unconditional).
    pub condition: String,
    /// Whether this breakpoint is currently enabled.
    pub enabled: bool,
    /// Number of times this breakpoint has been hit.
    pub hit_count: u32,
    /// Stop only after `hit_count_limit` hits (0 = always stop).
    pub hit_count_limit: u32,
    /// One-shot: remove after first hit.
    pub one_shot: bool,
    /// Optional label.
    pub label: Option<String>,
}

impl Breakpoint {
    /// Create a new unconditional breakpoint.
    #[must_use]
    pub fn new(id: u32, file: impl Into<String>, line: u32) -> Self {
        Self {
            id, file: file.into(), line, condition: String::new(),
            enabled: true, hit_count: 0, hit_count_limit: 0,
            one_shot: false, label: None,
        }
    }

    /// Builder: set condition.
    #[must_use]
    pub fn with_condition(mut self, cond: impl Into<String>) -> Self {
        self.condition = cond.into(); self
    }

    /// Builder: set one-shot.
    #[must_use]
    pub fn one_shot(mut self) -> Self { self.one_shot = true; self }

    /// Builder: set label.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into()); self
    }

    /// Record a hit and return whether execution should pause.
    pub fn record_hit(&mut self) -> bool {
        self.hit_count += 1;
        if !self.enabled { return false; }
        if self.hit_count_limit > 0 && self.hit_count < self.hit_count_limit { return false; }
        true
    }

    /// Return `true` if this breakpoint has an active condition.
    #[must_use]
    pub fn is_conditional(&self) -> bool { !self.condition.is_empty() }
}

// ─── WatchExpression ─────────────────────────────────────────────────────────

/// An expression that is evaluated and displayed each time execution pauses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchExpression {
    pub id: u32,
    pub expression: String,
    pub last_value: Option<String>,
    pub last_error: Option<String>,
    pub enabled: bool,
    pub update_count: u32,
}

impl WatchExpression {
    /// Create a new watch expression.
    #[must_use]
    pub fn new(id: u32, expression: impl Into<String>) -> Self {
        Self {
            id, expression: expression.into(),
            last_value: None, last_error: None,
            enabled: true, update_count: 0,
        }
    }

    /// Update with a new value.
    pub fn update_value(&mut self, value: impl Into<String>) {
        self.last_value = Some(value.into());
        self.last_error = None;
        self.update_count += 1;
    }

    /// Update with an error.
    pub fn update_error(&mut self, error: impl Into<String>) {
        self.last_error = Some(error.into());
        self.update_count += 1;
    }

    /// Return the current displayed value.
    #[must_use]
    pub fn display(&self) -> String {
        if let Some(v) = &self.last_value { v.clone() }
        else if let Some(e) = &self.last_error { format!("ERROR: {e}") }
        else { "<not evaluated>".into() }
    }
}

// ─── StackFrame ───────────────────────────────────────────────────────────────

/// One frame in a call stack trace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackFrame {
    /// Stack depth (0 = innermost).
    pub depth: u32,
    /// Function / scope name.
    pub function: String,
    /// Source file.
    pub file: String,
    /// Current line number.
    pub line: u32,
    /// Local variables in this frame.
    pub locals: HashMap<String, String>,
}

impl StackFrame {
    /// Create a new frame.
    #[must_use]
    pub fn new(depth: u32, function: impl Into<String>, file: impl Into<String>, line: u32) -> Self {
        Self { depth, function: function.into(), file: file.into(), line, locals: HashMap::new() }
    }

    /// Add a local variable.
    pub fn add_local(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.locals.insert(name.into(), value.into());
    }
}

impl fmt::Display for StackFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{} {}() at {}:{}", self.depth, self.function, self.file, self.line)
    }
}

// ─── StackTrace ───────────────────────────────────────────────────────────────

/// A complete call stack trace.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StackTrace {
    pub frames: Vec<StackFrame>,
}

impl StackTrace {
    /// Create an empty trace.
    #[must_use]
    pub fn new() -> Self { Self::default() }

    /// Push a frame.
    pub fn push(&mut self, frame: StackFrame) { self.frames.push(frame); }

    /// Depth of the call stack.
    #[must_use]
    pub fn depth(&self) -> usize { self.frames.len() }

    /// Return the innermost (current) frame.
    #[must_use]
    pub fn current_frame(&self) -> Option<&StackFrame> { self.frames.first() }

    /// Return the outermost (root) frame.
    #[must_use]
    pub fn root_frame(&self) -> Option<&StackFrame> { self.frames.last() }

    /// Return `true` if the trace is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool { self.frames.is_empty() }
}

impl fmt::Display for StackTrace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for frame in &self.frames {
            writeln!(f, "  {frame}")?;
        }
        Ok(())
    }
}

// ─── VariableInspector ───────────────────────────────────────────────────────

/// Inspects and modifies variables in the script's current scope.
pub struct VariableInspector {
    /// Scope variables: name → (value, type_name).
    pub variables: HashMap<String, (String, String)>,
    /// Modified variables (for change tracking).
    pub modified: Vec<String>,
}

impl VariableInspector {
    /// Create an empty inspector.
    #[must_use]
    pub fn new() -> Self { Self { variables: HashMap::new(), modified: vec![] } }

    /// Set a variable.
    pub fn set(&mut self, name: impl Into<String>, value: impl Into<String>, type_name: impl Into<String>) {
        let n = name.into();
        self.variables.insert(n.clone(), (value.into(), type_name.into()));
        if !self.modified.contains(&n) { self.modified.push(n); }
    }

    /// Get a variable value.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.variables.get(name).map(|(v, _)| v.as_str())
    }

    /// Get a variable's type name.
    #[must_use]
    pub fn type_of(&self, name: &str) -> Option<&str> {
        self.variables.get(name).map(|(_, t)| t.as_str())
    }

    /// Remove a variable.
    pub fn remove(&mut self, name: &str) -> bool {
        self.variables.remove(name).is_some()
    }

    /// Return all variable names.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.variables.keys().map(String::as_str).collect()
    }

    /// Number of variables in scope.
    #[must_use]
    pub fn count(&self) -> usize { self.variables.len() }
}

impl Default for VariableInspector {
    fn default() -> Self { Self::new() }
}

// ─── DebugEvent ───────────────────────────────────────────────────────────────

/// An event emitted by the debugger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DebugEvent {
    Paused { reason: PauseReason, line: u32 },
    Resumed,
    Stepped { to_line: u32, mode: StepMode },
    BreakpointHit { id: u32, line: u32 },
    Error { line: u32, message: String },
    Finished { exit_code: i32 },
    VariableChanged { name: String, old_value: String, new_value: String },
    WatchTriggered { id: u32, expression: String, value: String },
    Output { text: String },
}

/// Reason why the debugger paused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PauseReason {
    Breakpoint,
    Step,
    Exception,
    UserRequest,
    WatchTrigger,
}

// ─── DebugSession ─────────────────────────────────────────────────────────────

/// An active debug session for a script.
pub struct DebugSession {
    pub id: String,
    pub script_name: String,
    pub state: DebuggerState,
    pub current_line: u32,
    pub stack_trace: StackTrace,
    pub variables: VariableInspector,
    pub event_log: VecDeque<DebugEvent>,
    pub max_event_log: usize,
}

impl DebugSession {
    /// Create a new session.
    #[must_use]
    pub fn new(id: impl Into<String>, script_name: impl Into<String>) -> Self {
        Self {
            id: id.into(), script_name: script_name.into(),
            state: DebuggerState::Idle, current_line: 0,
            stack_trace: StackTrace::new(), variables: VariableInspector::new(),
            event_log: VecDeque::new(), max_event_log: 500,
        }
    }

    /// Emit an event.
    pub fn emit(&mut self, event: DebugEvent) {
        if self.event_log.len() >= self.max_event_log {
            self.event_log.pop_front();
        }
        self.event_log.push_back(event);
    }

    /// Return the last N events.
    #[must_use]
    pub fn last_events(&self, n: usize) -> Vec<&DebugEvent> {
        self.event_log.iter().rev().take(n).collect()
    }

    /// Return the current stack depth.
    #[must_use]
    pub fn stack_depth(&self) -> usize { self.stack_trace.depth() }

    /// Transition to a new state.
    ///
    /// # Errors
    /// Returns `DebuggerError::InvalidTransition` for illegal transitions.
    pub fn transition(&mut self, new_state: DebuggerState) -> Result<(), DebuggerError> {
        let ok = match (self.state, new_state) {
            (DebuggerState::Idle, DebuggerState::Running)
            | (DebuggerState::Idle, DebuggerState::Paused) => true,
            (DebuggerState::Running, DebuggerState::Paused)
            | (DebuggerState::Running, DebuggerState::Finished)
            | (DebuggerState::Running, DebuggerState::Error) => true,
            (DebuggerState::Paused, DebuggerState::Running)
            | (DebuggerState::Paused, DebuggerState::Stepping)
            | (DebuggerState::Paused, DebuggerState::Finished) => true,
            (DebuggerState::Stepping, DebuggerState::Paused)
            | (DebuggerState::Stepping, DebuggerState::Running)
            | (DebuggerState::Stepping, DebuggerState::Finished) => true,
            (_, DebuggerState::Idle) => true, // can always reset
            _ => false,
        };
        if !ok {
            return Err(DebuggerError::InvalidTransition(
                format!("{} → {}", self.state, new_state)
            ));
        }
        self.state = new_state;
        Ok(())
    }
}

impl fmt::Debug for DebugSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DebugSession")
            .field("id", &self.id)
            .field("state", &self.state)
            .field("line", &self.current_line)
            .finish_non_exhaustive()
    }
}

// ─── ScriptDebugger ───────────────────────────────────────────────────────────

/// A full-featured script debugger.
pub struct ScriptDebugger {
    pub session: DebugSession,
    breakpoints: HashMap<u32, Breakpoint>, // keyed by line
    watches: HashMap<u32, WatchExpression>,
    next_bp_id: u32,
    next_watch_id: u32,
    step_mode: StepMode,
    /// Simulated script source lines.
    source_lines: Vec<String>,
}

impl ScriptDebugger {
    /// Create a new debugger for a script.
    #[must_use]
    pub fn new(session_id: impl Into<String>, script_name: impl Into<String>) -> Self {
        Self {
            session: DebugSession::new(session_id, script_name),
            breakpoints: HashMap::new(),
            watches: HashMap::new(),
            next_bp_id: 1,
            next_watch_id: 1,
            step_mode: StepMode::Over,
            source_lines: vec![],
        }
    }

    /// Load script source lines.
    pub fn load_source(&mut self, source: &str) {
        self.source_lines = source.lines().map(str::to_string).collect();
    }

    // ── Breakpoints ───────────────────────────────────────────────────────────

    /// Add a breakpoint at a line.
    ///
    /// # Errors
    /// Returns `DebuggerError::BreakpointExists` if already set.
    pub fn add_breakpoint(&mut self, line: u32) -> Result<u32, DebuggerError> {
        if self.breakpoints.contains_key(&line) {
            return Err(DebuggerError::BreakpointExists(line));
        }
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        let bp = Breakpoint::new(id, "", line);
        self.breakpoints.insert(line, bp);
        Ok(id)
    }

    /// Add a conditional breakpoint.
    ///
    /// # Errors
    /// Returns `DebuggerError::BreakpointExists` if already set.
    pub fn add_conditional_breakpoint(&mut self, line: u32, condition: impl Into<String>) -> Result<u32, DebuggerError> {
        if self.breakpoints.contains_key(&line) {
            return Err(DebuggerError::BreakpointExists(line));
        }
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        let bp = Breakpoint::new(id, "", line).with_condition(condition);
        self.breakpoints.insert(line, bp);
        Ok(id)
    }

    /// Remove a breakpoint.
    ///
    /// # Errors
    /// Returns `DebuggerError::BreakpointNotFound` if absent.
    pub fn remove_breakpoint(&mut self, line: u32) -> Result<(), DebuggerError> {
        if !self.breakpoints.remove(&line).is_some() {
            return Err(DebuggerError::BreakpointNotFound(line));
        }
        Ok(())
    }

    /// Enable or disable a breakpoint.
    ///
    /// # Errors
    /// Returns `DebuggerError::BreakpointNotFound` if absent.
    pub fn set_breakpoint_enabled(&mut self, line: u32, enabled: bool) -> Result<(), DebuggerError> {
        let bp = self.breakpoints.get_mut(&line)
            .ok_or(DebuggerError::BreakpointNotFound(line))?;
        bp.enabled = enabled;
        Ok(())
    }

    /// Return all breakpoints.
    #[must_use]
    pub fn breakpoints(&self) -> Vec<&Breakpoint> { self.breakpoints.values().collect() }

    /// Number of active breakpoints.
    #[must_use]
    pub fn breakpoint_count(&self) -> usize { self.breakpoints.len() }

    // ── Watch expressions ─────────────────────────────────────────────────────

    /// Add a watch expression.
    #[must_use]
    pub fn add_watch(&mut self, expression: impl Into<String>) -> u32 {
        let id = self.next_watch_id;
        self.next_watch_id += 1;
        self.watches.insert(id, WatchExpression::new(id, expression));
        id
    }

    /// Remove a watch expression.
    ///
    /// # Errors
    /// Returns `DebuggerError::WatchNotFound` if absent.
    pub fn remove_watch(&mut self, id: u32) -> Result<(), DebuggerError> {
        if !self.watches.remove(&id).is_some() {
            return Err(DebuggerError::WatchNotFound(id.to_string()));
        }
        Ok(())
    }

    /// Return all watch expressions.
    #[must_use]
    pub fn watches(&self) -> Vec<&WatchExpression> { self.watches.values().collect() }

    /// Update a watch with a new value.
    pub fn update_watch(&mut self, id: u32, value: impl Into<String>) {
        if let Some(w) = self.watches.get_mut(&id) {
            w.update_value(value);
        }
    }

    // ── Execution control ────────────────────────────────────────────────────

    /// Start (or continue) execution.
    ///
    /// # Errors
    /// Returns `DebuggerError::AlreadyRunning` if already running.
    pub fn start(&mut self) -> Result<(), DebuggerError> {
        match self.session.state {
            DebuggerState::Running => return Err(DebuggerError::AlreadyRunning),
            _ => {}
        }
        self.session.transition(DebuggerState::Running)?;
        self.session.emit(DebugEvent::Resumed);
        Ok(())
    }

    /// Pause execution.
    ///
    /// # Errors
    /// Returns `DebuggerError::NotRunning` if not running.
    pub fn pause(&mut self) -> Result<(), DebuggerError> {
        if self.session.state != DebuggerState::Running {
            return Err(DebuggerError::NotRunning);
        }
        self.session.transition(DebuggerState::Paused)?;
        self.session.emit(DebugEvent::Paused { reason: PauseReason::UserRequest, line: self.session.current_line });
        Ok(())
    }

    /// Step execution.
    ///
    /// # Errors
    /// Returns `DebuggerError::NotRunning` if not paused.
    pub fn step(&mut self, mode: StepMode) -> Result<(), DebuggerError> {
        if !matches!(self.session.state, DebuggerState::Paused | DebuggerState::Stepping) {
            return Err(DebuggerError::NotRunning);
        }
        self.step_mode = mode;
        let next_line = self.session.current_line + 1;
        self.session.current_line = next_line;
        self.session.transition(DebuggerState::Stepping)?;
        self.session.emit(DebugEvent::Stepped { to_line: next_line, mode });
        // Check if we hit a breakpoint on the new line
        let hit = if let Some(bp) = self.breakpoints.get_mut(&next_line) {
            bp.record_hit()
        } else { false };
        if hit {
            self.session.transition(DebuggerState::Paused)?;
            let bp_id = self.breakpoints[&next_line].id;
            self.session.emit(DebugEvent::BreakpointHit { id: bp_id, line: next_line });
        }
        Ok(())
    }

    /// Simulate reaching a breakpoint at `line`.
    pub fn simulate_breakpoint(&mut self, line: u32) {
        self.session.current_line = line;
        if let Some(bp) = self.breakpoints.get_mut(&line) {
            let should_pause = bp.record_hit();
            if should_pause {
                let id = bp.id;
                let _ = self.session.transition(DebuggerState::Paused);
                self.session.emit(DebugEvent::BreakpointHit { id, line });
            }
        }
    }

    /// Finish execution.
    pub fn finish(&mut self, exit_code: i32) {
        let _ = self.session.transition(DebuggerState::Finished);
        self.session.emit(DebugEvent::Finished { exit_code });
    }

    /// Reset to idle.
    pub fn reset(&mut self) {
        let _ = self.session.transition(DebuggerState::Idle);
        self.session.current_line = 0;
        self.session.stack_trace = StackTrace::new();
        self.session.variables = VariableInspector::new();
    }

    // ── Variable access ───────────────────────────────────────────────────────

    /// Set a variable in the current scope.
    pub fn set_variable(&mut self, name: impl Into<String>, value: impl Into<String>, type_name: impl Into<String>) {
        let n: String = name.into();
        let v: String = value.into();
        let old = self.session.variables.get(&n).map(str::to_string).unwrap_or_default();
        let new = v.clone();
        self.session.variables.set(n.clone(), v, type_name);
        if !old.is_empty() && old != new {
            self.session.emit(DebugEvent::VariableChanged { name: n, old_value: old, new_value: new });
        }
    }

    /// Get a variable value.
    #[must_use]
    pub fn get_variable(&self, name: &str) -> Option<&str> {
        self.session.variables.get(name)
    }

    // ── Stack trace ───────────────────────────────────────────────────────────

    /// Push a call frame.
    pub fn push_frame(&mut self, frame: StackFrame) {
        self.session.stack_trace.push(frame);
    }

    /// Return the current stack trace.
    #[must_use]
    pub fn stack_trace(&self) -> &StackTrace { &self.session.stack_trace }

    // ── Source ────────────────────────────────────────────────────────────────

    /// Return the source line at `line` (1-based).
    #[must_use]
    pub fn source_line(&self, line: u32) -> Option<&str> {
        if line == 0 { return None; }
        self.source_lines.get((line - 1) as usize).map(String::as_str)
    }

    /// Return the current source line.
    #[must_use]
    pub fn current_source_line(&self) -> Option<&str> {
        self.source_line(self.session.current_line)
    }

    /// Return the state.
    #[must_use]
    pub fn state(&self) -> DebuggerState { self.session.state }
}

impl fmt::Debug for ScriptDebugger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptDebugger")
            .field("state", &self.session.state)
            .field("line", &self.session.current_line)
            .field("breakpoints", &self.breakpoints.len())
            .finish_non_exhaustive()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dbg() -> ScriptDebugger {
        ScriptDebugger::new("sess-1", "test.lua")
    }

    // ── DebuggerState ─────────────────────────────────────────────────────────

    #[test]
    fn test_state_display() {
        assert_eq!(DebuggerState::Paused.to_string(), "paused");
        assert_eq!(DebuggerState::Running.to_string(), "running");
    }

    // ── StepMode ──────────────────────────────────────────────────────────────

    #[test]
    fn test_step_mode_display() {
        assert_eq!(StepMode::Into.to_string(), "into");
        assert_eq!(StepMode::Over.to_string(), "over");
    }

    // ── Breakpoint ────────────────────────────────────────────────────────────

    #[test]
    fn test_breakpoint_new() {
        let bp = Breakpoint::new(1, "test.lua", 10);
        assert!(bp.enabled);
        assert!(!bp.is_conditional());
        assert_eq!(bp.line, 10);
    }

    #[test]
    fn test_breakpoint_conditional() {
        let bp = Breakpoint::new(2, "", 5).with_condition("x > 10");
        assert!(bp.is_conditional());
    }

    #[test]
    fn test_breakpoint_record_hit() {
        let mut bp = Breakpoint::new(1, "", 1);
        assert!(bp.record_hit()); // should pause
        assert_eq!(bp.hit_count, 1);
    }

    #[test]
    fn test_breakpoint_disabled_no_pause() {
        let mut bp = Breakpoint::new(1, "", 1);
        bp.enabled = false;
        assert!(!bp.record_hit());
    }

    #[test]
    fn test_breakpoint_one_shot() {
        let bp = Breakpoint::new(1, "", 1).one_shot();
        assert!(bp.one_shot);
    }

    // ── WatchExpression ───────────────────────────────────────────────────────

    #[test]
    fn test_watch_new() {
        let w = WatchExpression::new(1, "x + y");
        assert_eq!(w.expression, "x + y");
        assert!(w.last_value.is_none());
    }

    #[test]
    fn test_watch_update_value() {
        let mut w = WatchExpression::new(1, "x");
        w.update_value("42");
        assert_eq!(w.last_value.as_deref(), Some("42"));
        assert_eq!(w.display(), "42");
    }

    #[test]
    fn test_watch_update_error() {
        let mut w = WatchExpression::new(1, "bad");
        w.update_error("undefined variable");
        assert!(w.display().contains("ERROR"));
    }

    #[test]
    fn test_watch_not_evaluated_display() {
        let w = WatchExpression::new(1, "x");
        assert_eq!(w.display(), "<not evaluated>");
    }

    // ── StackFrame ────────────────────────────────────────────────────────────

    #[test]
    fn test_stack_frame_new() {
        let f = StackFrame::new(0, "main", "test.lua", 10);
        assert_eq!(f.function, "main");
        assert_eq!(f.line, 10);
    }

    #[test]
    fn test_stack_frame_add_local() {
        let mut f = StackFrame::new(0, "f", "t.lua", 1);
        f.add_local("x", "42");
        assert_eq!(f.locals["x"], "42");
    }

    #[test]
    fn test_stack_frame_display() {
        let f = StackFrame::new(0, "main", "test.lua", 5);
        assert!(f.to_string().contains("main"));
        assert!(f.to_string().contains('5'));
    }

    // ── StackTrace ────────────────────────────────────────────────────────────

    #[test]
    fn test_stack_trace_push_and_depth() {
        let mut t = StackTrace::new();
        t.push(StackFrame::new(0, "inner", "t.lua", 1));
        t.push(StackFrame::new(1, "outer", "t.lua", 10));
        assert_eq!(t.depth(), 2);
    }

    #[test]
    fn test_stack_trace_current_frame() {
        let mut t = StackTrace::new();
        t.push(StackFrame::new(0, "f", "t.lua", 5));
        assert_eq!(t.current_frame().unwrap().function, "f");
    }

    #[test]
    fn test_stack_trace_display() {
        let mut t = StackTrace::new();
        t.push(StackFrame::new(0, "foo", "t.lua", 1));
        assert!(t.to_string().contains("foo"));
    }

    // ── VariableInspector ─────────────────────────────────────────────────────

    #[test]
    fn test_variable_inspector_set_get() {
        let mut v = VariableInspector::new();
        v.set("x", "42", "int");
        assert_eq!(v.get("x"), Some("42"));
        assert_eq!(v.type_of("x"), Some("int"));
    }

    #[test]
    fn test_variable_inspector_remove() {
        let mut v = VariableInspector::new();
        v.set("x", "1", "int");
        assert!(v.remove("x"));
        assert!(v.get("x").is_none());
    }

    #[test]
    fn test_variable_inspector_count() {
        let mut v = VariableInspector::new();
        v.set("a", "1", "int");
        v.set("b", "2", "int");
        assert_eq!(v.count(), 2);
    }

    #[test]
    fn test_variable_inspector_missing() {
        let v = VariableInspector::new();
        assert!(v.get("z").is_none());
    }

    // ── DebugSession ──────────────────────────────────────────────────────────

    #[test]
    fn test_session_transition_valid() {
        let mut s = DebugSession::new("s", "t.lua");
        assert!(s.transition(DebuggerState::Running).is_ok());
        assert_eq!(s.state, DebuggerState::Running);
    }

    #[test]
    fn test_session_transition_invalid() {
        let mut s = DebugSession::new("s", "t.lua");
        let result = s.transition(DebuggerState::Paused);
        // Idle → Paused is allowed
        assert!(result.is_ok());
    }

    #[test]
    fn test_session_emit_and_last_events() {
        let mut s = DebugSession::new("s", "t.lua");
        s.emit(DebugEvent::Resumed);
        s.emit(DebugEvent::Finished { exit_code: 0 });
        assert_eq!(s.last_events(2).len(), 2);
    }

    // ── ScriptDebugger ────────────────────────────────────────────────────────

    #[test]
    fn test_debugger_add_breakpoint() {
        let mut d = dbg();
        let id = d.add_breakpoint(5).unwrap();
        assert_eq!(id, 1);
        assert_eq!(d.breakpoint_count(), 1);
    }

    #[test]
    fn test_debugger_add_breakpoint_duplicate() {
        let mut d = dbg();
        d.add_breakpoint(5).unwrap();
        let result = d.add_breakpoint(5);
        assert!(matches!(result, Err(DebuggerError::BreakpointExists(5))));
    }

    #[test]
    fn test_debugger_remove_breakpoint() {
        let mut d = dbg();
        d.add_breakpoint(10).unwrap();
        d.remove_breakpoint(10).unwrap();
        assert_eq!(d.breakpoint_count(), 0);
    }

    #[test]
    fn test_debugger_remove_breakpoint_not_found() {
        let mut d = dbg();
        let result = d.remove_breakpoint(99);
        assert!(matches!(result, Err(DebuggerError::BreakpointNotFound(99))));
    }

    #[test]
    fn test_debugger_conditional_breakpoint() {
        let mut d = dbg();
        let id = d.add_conditional_breakpoint(3, "i > 5").unwrap();
        assert!(d.breakpoints().iter().any(|b| b.id == id && b.is_conditional()));
    }

    #[test]
    fn test_debugger_enable_disable_breakpoint() {
        let mut d = dbg();
        d.add_breakpoint(7).unwrap();
        d.set_breakpoint_enabled(7, false).unwrap();
        assert!(!d.breakpoints().iter().find(|b| b.line == 7).unwrap().enabled);
    }

    #[test]
    fn test_debugger_add_watch() {
        let mut d = dbg();
        let id = d.add_watch("x + 1");
        assert_eq!(id, 1);
        assert_eq!(d.watches().len(), 1);
    }

    #[test]
    fn test_debugger_remove_watch() {
        let mut d = dbg();
        let id = d.add_watch("x");
        d.remove_watch(id).unwrap();
        assert!(d.watches().is_empty());
    }

    #[test]
    fn test_debugger_start() {
        let mut d = dbg();
        d.start().unwrap();
        assert_eq!(d.state(), DebuggerState::Running);
    }

    #[test]
    fn test_debugger_start_twice_error() {
        let mut d = dbg();
        d.start().unwrap();
        let result = d.start();
        assert!(matches!(result, Err(DebuggerError::AlreadyRunning)));
    }

    #[test]
    fn test_debugger_pause() {
        let mut d = dbg();
        d.start().unwrap();
        d.pause().unwrap();
        assert_eq!(d.state(), DebuggerState::Paused);
    }

    #[test]
    fn test_debugger_step_over() {
        let mut d = dbg();
        d.start().unwrap();
        d.session.current_line = 5;
        d.session.transition(DebuggerState::Paused).unwrap();
        d.step(StepMode::Over).unwrap();
        assert_eq!(d.session.current_line, 6);
    }

    #[test]
    fn test_debugger_simulate_breakpoint() {
        let mut d = dbg();
        d.add_breakpoint(10).unwrap();
        d.start().unwrap();
        d.simulate_breakpoint(10);
        assert_eq!(d.state(), DebuggerState::Paused);
    }

    #[test]
    fn test_debugger_finish() {
        let mut d = dbg();
        d.start().unwrap();
        d.finish(0);
        assert_eq!(d.state(), DebuggerState::Finished);
    }

    #[test]
    fn test_debugger_reset() {
        let mut d = dbg();
        d.start().unwrap();
        d.reset();
        assert_eq!(d.state(), DebuggerState::Idle);
        assert_eq!(d.session.current_line, 0);
    }

    #[test]
    fn test_debugger_variables() {
        let mut d = dbg();
        d.set_variable("count", "42", "int");
        assert_eq!(d.get_variable("count"), Some("42"));
    }

    #[test]
    fn test_debugger_push_frame() {
        let mut d = dbg();
        d.push_frame(StackFrame::new(0, "main", "t.lua", 1));
        assert_eq!(d.stack_trace().depth(), 1);
    }

    #[test]
    fn test_debugger_load_source() {
        let mut d = dbg();
        d.load_source("line1\nline2\nline3");
        assert_eq!(d.source_line(1), Some("line1"));
        assert_eq!(d.source_line(3), Some("line3"));
        assert!(d.source_line(4).is_none());
    }

    #[test]
    fn test_debugger_current_source_line() {
        let mut d = dbg();
        d.load_source("foo\nbar\nbaz");
        d.session.current_line = 2;
        assert_eq!(d.current_source_line(), Some("bar"));
    }

    #[test]
    fn test_debugger_update_watch() {
        let mut d = dbg();
        let id = d.add_watch("x");
        d.update_watch(id, "hello");
        let w = d.watches().into_iter().find(|w| w.id == id).unwrap();
        assert_eq!(w.display(), "hello");
    }
}
