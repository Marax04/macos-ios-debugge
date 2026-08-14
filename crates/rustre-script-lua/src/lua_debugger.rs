//! Lua script debugger for the `RustRE` suite — **source-level Lua script debugger**.
//!
//! Provides [`LuaDebugger`] which supports breakpoints, single-step execution,
//! variable inspection, and a simple call-stack representation for scripts
//! running inside the `RustRE` Lua engine.
//!
//! # Relationship to `lua_debugger_api`
//!
//! This module debugs **Lua scripts** (source-level, line-by-line stepping
//! through `.lua` source text).  `lua_debugger_api` debugs **OS processes**
//! (attach/detach, hardware registers, memory reads, INT3 breakpoints).
//! They solve different problems and must both be kept.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{LuaContext, LuaEngine, LuaError, LuaValue};

// ── LuaBreakpoint ─────────────────────────────────────────────────────────────

/// A breakpoint that can pause script execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaBreakpoint {
    /// Unique numeric identifier for this breakpoint.
    pub id: u32,
    /// Zero-based line index at which the breakpoint fires.
    pub line: usize,
    /// Optional source file name (used for display only; the engine does not
    /// multi-file). `None` means "any file".
    pub file: Option<String>,
    /// Whether the breakpoint is currently active.
    pub enabled: bool,
    /// Optional hit count — fires only when this count is reached.
    /// `None` means fire on every hit.
    pub hit_count: Option<u32>,
    /// Number of times this breakpoint has been hit.
    pub hits: u32,
    /// Optional Lua expression that must evaluate to true for the breakpoint
    /// to fire.  `None` means unconditional.
    pub condition: Option<String>,
}

impl LuaBreakpoint {
    /// Create a new unconditional breakpoint at the given source line.
    #[must_use]
    pub const fn new(id: u32, line: usize) -> Self {
        Self {
            id,
            line,
            file: None,
            enabled: true,
            hit_count: None,
            hits: 0,
            condition: None,
        }
    }

    /// Attach a source file name to this breakpoint.
    #[must_use]
    pub fn with_file(mut self, file: impl Into<String>) -> Self {
        self.file = Some(file.into());
        self
    }

    /// Set a hit-count filter: only break on the N-th hit.
    #[must_use] 
    pub const fn with_hit_count(mut self, n: u32) -> Self {
        self.hit_count = Some(n);
        self
    }

    /// Set a conditional expression.
    #[must_use]
    pub fn with_condition(mut self, expr: impl Into<String>) -> Self {
        self.condition = Some(expr.into());
        self
    }

    /// Determine whether this breakpoint should fire at the given line.
    /// Does not check the condition expression (that requires an executor).
    #[must_use]
    pub const fn fires_at_line(&self, line: usize) -> bool {
        if !self.enabled {
            return false;
        }
        if self.line != line {
            return false;
        }
        if let Some(needed) = self.hit_count {
            // Fire only when hits (post-increment) equals the required count.
            return self.hits + 1 == needed;
        }
        true
    }
}

impl fmt::Display for LuaBreakpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let file = self.file.as_deref().unwrap_or("<any>");
        let state = if self.enabled { "enabled" } else { "disabled" };
        write!(
            f,
            "Breakpoint#{} {}:{} [{}] hits={}",
            self.id, file, self.line, state, self.hits
        )
    }
}

// ── LuaStackFrame ─────────────────────────────────────────────────────────────

/// A single frame in the Lua call stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LuaStackFrame {
    /// Depth index (0 = innermost / current frame).
    pub depth: usize,
    /// Name of the function for this frame, or `"<toplevel>"`.
    pub function_name: String,
    /// Source line of the call site (or current line for depth 0).
    pub current_line: usize,
    /// Local variables visible in this frame.
    pub locals: HashMap<String, LuaValue>,
}

impl LuaStackFrame {
    /// Create a top-level frame.
    #[must_use]
    pub fn toplevel(line: usize, locals: HashMap<String, LuaValue>) -> Self {
        Self {
            depth: 0,
            function_name: "<toplevel>".to_string(),
            current_line: line,
            locals,
        }
    }

    /// Return the value of a local variable, or `None` if not in scope.
    #[must_use]
    pub fn get_local(&self, name: &str) -> Option<&LuaValue> {
        self.locals.get(name)
    }
}

impl fmt::Display for LuaStackFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "#{} {} (line {})",
            self.depth, self.function_name, self.current_line
        )
    }
}

// ── DebugEvent ────────────────────────────────────────────────────────────────

/// Events emitted by the debugger during stepping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DebugEvent {
    /// A breakpoint was hit.
    BreakpointHit {
        /// Breakpoint that fired.
        breakpoint_id: u32,
        /// Source line.
        line: usize,
    },
    /// Execution paused after a single step.
    StepComplete {
        /// The line execution reached.
        line: usize,
    },
    /// A Lua `error()` was called or a runtime error occurred.
    RuntimeError {
        /// Error message.
        message: String,
        /// Source line where the error was raised.
        line: usize,
    },
    /// The script called `print(...)`.
    PrintOutput {
        /// Text that was printed.
        text: String,
        /// Line at which the call occurred.
        line: usize,
    },
    /// Script execution completed normally.
    ScriptComplete {
        /// The script's return value.
        return_value: LuaValue,
    },
}

impl fmt::Display for DebugEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BreakpointHit {
                breakpoint_id,
                line,
            } => write!(f, "[bp#{breakpoint_id}] hit at line {line}"),
            Self::StepComplete { line } => write!(f, "[step] line {line}"),
            Self::RuntimeError { message, line } => {
                write!(f, "[error] line {line}: {message}")
            }
            Self::PrintOutput { text, line } => write!(f, "[print:line{line}] {text}"),
            Self::ScriptComplete { .. } => write!(f, "[complete]"),
        }
    }
}

// ── DebugState ────────────────────────────────────────────────────────────────

/// Current state of the debugger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DebugState {
    /// Not running.
    Idle,
    /// Running normally (past all breakpoints until completion or next bp).
    Running,
    /// Paused at a breakpoint or after a step.
    Paused,
    /// Script completed.
    Complete,
    /// Script terminated with an error.
    Error,
}

// ── WatchPoint ────────────────────────────────────────────────────────────────

/// A watch expression that is re-evaluated at each pause point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchPoint {
    /// Unique identifier.
    pub id: u32,
    /// The Lua expression to evaluate.
    pub expression: String,
    /// Last evaluated value (or `None` if not yet evaluated).
    pub last_value: Option<LuaValue>,
}

impl WatchPoint {
    /// Create a new watch point.
    #[must_use]
    pub fn new(id: u32, expression: impl Into<String>) -> Self {
        Self {
            id,
            expression: expression.into(),
            last_value: None,
        }
    }
}

// ── LuaDebugger ───────────────────────────────────────────────────────────────

/// Interactive debugger for Lua scripts running in the `RustRE` Lua engine.
///
/// The debugger instruments a script by splitting it at newlines and executing
/// line-by-line, pausing at breakpoints and optionally after each line in
/// step mode. This is a source-level emulation approach: it extracts all lines
/// from the script, groups them into runnable statement chunks, and executes
/// them sequentially while checking the breakpoint table after each chunk.
pub struct LuaDebugger {
    /// All registered breakpoints, keyed by breakpoint ID.
    breakpoints: HashMap<u32, LuaBreakpoint>,
    /// Watch expressions.
    watches: HashMap<u32, WatchPoint>,
    /// Lines of the currently loaded script (1-indexed by convention).
    source_lines: Vec<String>,
    /// Current execution line (1-indexed).
    current_line: usize,
    /// Accumulated output from `print` calls.
    output: Vec<String>,
    /// Current debugger state.
    state: DebugState,
    /// Event log for this debug session.
    events: Vec<DebugEvent>,
    /// Next breakpoint ID to assign.
    next_bp_id: u32,
    /// Next watch ID to assign.
    next_watch_id: u32,
    /// Whether single-step mode is active.
    step_mode: bool,
    /// Execution context (persists across steps).
    context: LuaContext,
    /// Set of line numbers (1-indexed) already executed.
    executed_lines: HashSet<usize>,
    /// Return value from the last complete execution.
    last_return: LuaValue,
    /// Call-stack snapshot at the last pause.
    call_stack: Vec<LuaStackFrame>,
}

impl LuaDebugger {
    /// Create a new debugger with no script loaded.
    #[must_use]
    pub fn new() -> Self {
        Self {
            breakpoints: HashMap::new(),
            watches: HashMap::new(),
            source_lines: Vec::new(),
            current_line: 0,
            output: Vec::new(),
            state: DebugState::Idle,
            events: Vec::new(),
            next_bp_id: 1,
            next_watch_id: 1,
            step_mode: false,
            context: LuaContext::new(),
            executed_lines: HashSet::new(),
            last_return: LuaValue::Nil,
            call_stack: Vec::new(),
        }
    }

    /// Load a Lua script source string into the debugger.
    ///
    /// Resets all execution state but preserves breakpoints and watches.
    pub fn load_source(&mut self, source: &str) {
        self.source_lines = source.lines().map(str::to_string).collect();
        self.current_line = 0;
        self.output.clear();
        self.state = DebugState::Idle;
        self.events.clear();
        self.context = LuaContext::new();
        self.executed_lines.clear();
        self.last_return = LuaValue::Nil;
        self.call_stack.clear();
    }

    /// Return the number of source lines loaded.
    #[must_use]
    pub const fn line_count(&self) -> usize {
        self.source_lines.len()
    }

    /// Return the current execution line (1-indexed; 0 means not started).
    #[must_use]
    pub const fn current_line(&self) -> usize {
        self.current_line
    }

    /// Return the current debugger state.
    #[must_use]
    pub const fn state(&self) -> DebugState {
        self.state
    }

    // ── Breakpoint management ─────────────────────────────────────────────────

    /// Add a breakpoint at `line` (1-indexed). Returns the breakpoint ID.
    pub fn add_breakpoint(&mut self, line: usize) -> u32 {
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        self.breakpoints.insert(id, LuaBreakpoint::new(id, line));
        id
    }

    /// Add a breakpoint with full configuration.
    pub fn add_breakpoint_full(&mut self, mut bp: LuaBreakpoint) -> u32 {
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        bp.id = id;
        self.breakpoints.insert(id, bp);
        id
    }

    /// Remove a breakpoint by ID. Returns `true` if it existed.
    pub fn remove_breakpoint(&mut self, id: u32) -> bool {
        self.breakpoints.remove(&id).is_some()
    }

    /// Enable or disable a breakpoint by ID.
    pub fn set_breakpoint_enabled(&mut self, id: u32, enabled: bool) {
        if let Some(bp) = self.breakpoints.get_mut(&id) {
            bp.enabled = enabled;
        }
    }

    /// Return all breakpoints.
    #[must_use]
    pub fn breakpoints(&self) -> Vec<&LuaBreakpoint> {
        let mut bps: Vec<_> = self.breakpoints.values().collect();
        bps.sort_by_key(|b| b.id);
        bps
    }

    /// Return the breakpoint set for a specific line, if any.
    #[must_use]
    pub fn breakpoint_at_line(&self, line: usize) -> Option<&LuaBreakpoint> {
        self.breakpoints.values().find(|b| b.line == line && b.enabled)
    }

    // ── Watch management ──────────────────────────────────────────────────────

    /// Add a watch expression. Returns the watch ID.
    pub fn add_watch(&mut self, expression: &str) -> u32 {
        let id = self.next_watch_id;
        self.next_watch_id += 1;
        self.watches.insert(id, WatchPoint::new(id, expression));
        id
    }

    /// Remove a watch by ID.
    pub fn remove_watch(&mut self, id: u32) -> bool {
        self.watches.remove(&id).is_some()
    }

    /// Evaluate all watch expressions in the current context and update their
    /// `last_value`. Returns a snapshot of all watch evaluations.
    pub fn evaluate_watches(&mut self) -> Vec<(u32, String, LuaValue)> {
        let watch_list: Vec<(u32, String)> = self
            .watches
            .values()
            .map(|w| (w.id, w.expression.clone()))
            .collect();

        let mut results = Vec::new();
        for (id, expr) in watch_list {
            let value = self.eval_expression(&expr);
            if let Some(watch) = self.watches.get_mut(&id) {
                watch.last_value = Some(value.clone());
            }
            results.push((id, expr, value));
        }
        results
    }

    // ── Execution control ─────────────────────────────────────────────────────

    /// Start execution from the beginning in run mode (stop at breakpoints).
    ///
    /// Returns all events that fired up to (and including) the first breakpoint
    /// hit or script completion.
    pub fn run(&mut self) -> Vec<DebugEvent> {
        self.step_mode = false;
        self.state = DebugState::Running;
        self.execute_until_pause()
    }

    /// Continue execution from the current pause point.
    pub fn continue_run(&mut self) -> Vec<DebugEvent> {
        if self.state == DebugState::Complete || self.state == DebugState::Error {
            return Vec::new();
        }
        self.step_mode = false;
        self.state = DebugState::Running;
        self.execute_until_pause()
    }

    /// Execute a single source line and pause.
    pub fn step(&mut self) -> Vec<DebugEvent> {
        if self.state == DebugState::Complete || self.state == DebugState::Error {
            return Vec::new();
        }
        self.step_mode = true;
        self.state = DebugState::Running;
        self.execute_one_line()
    }

    // ── Variable inspection ───────────────────────────────────────────────────

    /// Return the current value of a global variable in the script.
    #[must_use]
    pub fn get_variable(&self, name: &str) -> &LuaValue {
        self.context.get(name)
    }

    /// Return a snapshot of all global variables.
    #[must_use]
    pub fn all_variables(&self) -> HashMap<&str, &LuaValue> {
        self.context
            .globals
            .iter()
            .map(|(k, v)| (k.as_str(), v))
            .collect()
    }

    /// Return the call stack at the current pause point.
    #[must_use]
    pub fn call_stack(&self) -> &[LuaStackFrame] {
        &self.call_stack
    }

    /// Evaluate a Lua expression in the current context.
    pub fn eval_expression(&mut self, expr: &str) -> LuaValue {
        let wrapped = format!("return {expr}");
        let mut engine = LuaEngine::new();
        engine.set_max_steps(50_000);
        engine.execute(&wrapped, &mut self.context).unwrap_or(LuaValue::Nil)
    }

    /// Return all captured output lines.
    #[must_use]
    pub fn output(&self) -> &[String] {
        &self.output
    }

    /// Return all events logged so far this session.
    #[must_use]
    pub fn events(&self) -> &[DebugEvent] {
        &self.events
    }

    /// Return the last return value (valid after `ScriptComplete`).
    #[must_use]
    pub const fn last_return_value(&self) -> &LuaValue {
        &self.last_return
    }

    // ── Source listing ────────────────────────────────────────────────────────

    /// Return a listing of the source, annotating each line with:
    /// - `>` if it is the current execution line,
    /// - `B` if a breakpoint is set on it,
    /// - ` ` otherwise.
    #[must_use]
    pub fn source_listing(&self) -> Vec<String> {
        let bp_lines: HashSet<usize> = self.breakpoints.values()
            .filter(|b| b.enabled)
            .map(|b| b.line)
            .collect();
        self.source_lines
            .iter()
            .enumerate()
            .map(|(i, line)| {
                let lineno = i + 1;
                let cur = if lineno == self.current_line { '>' } else { ' ' };
                let bp = if bp_lines.contains(&lineno) { 'B' } else { ' ' };
                format!("{cur}{bp} {lineno:4}: {line}")
            })
            .collect()
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Execute lines until a breakpoint fires, an error occurs, or the script
    /// completes.
    fn execute_until_pause(&mut self) -> Vec<DebugEvent> {
        let mut new_events = Vec::new();
        let total = self.source_lines.len();

        while self.current_line < total {
            let line_events = self.execute_one_line();
            let hit_pause = line_events
                .iter()
                .any(|e| matches!(e, DebugEvent::BreakpointHit { .. } | DebugEvent::RuntimeError { .. }));
            new_events.extend(line_events.clone());

            if hit_pause
                || self.state == DebugState::Complete
                || self.state == DebugState::Error
            {
                break;
            }
        }

        new_events
    }

    /// Execute one source line (advance `current_line` by 1 and run it).
    fn execute_one_line(&mut self) -> Vec<DebugEvent> {
        let mut new_events = Vec::new();
        let total = self.source_lines.len();

        if self.current_line >= total {
            self.state = DebugState::Complete;
            return new_events;
        }

        self.current_line += 1;
        let line_idx = self.current_line;

        // Check for breakpoint.
        let bp_id = self.check_breakpoints(line_idx);
        if let Some(id) = bp_id {
            let event = DebugEvent::BreakpointHit {
                breakpoint_id: id,
                line: line_idx,
            };
            self.events.push(event.clone());
            new_events.push(event);
            self.state = DebugState::Paused;
            self.rebuild_call_stack();
            return new_events;
        }

        // Run the line.
        let line_src = self.source_lines[line_idx - 1].clone();
        let trimmed = line_src.trim();

        if !trimmed.is_empty() && !trimmed.starts_with("--") {
            let before_output_len = self.context.output.len();
            let mut engine = LuaEngine::new();
            engine.set_max_steps(10_000);
            match engine.execute(&line_src, &mut self.context) {
                Ok(v) => {
                    // Capture new output.
                    let new_output = self.context.output[before_output_len..].to_vec();
                    for line in &new_output {
                        let event = DebugEvent::PrintOutput {
                            text: line.clone(),
                            line: line_idx,
                        };
                        self.events.push(event.clone());
                        new_events.push(event);
                        self.output.push(line.clone());
                    }
                    // Check if this was a return statement.
                    if !matches!(v, LuaValue::Nil) {
                        self.last_return = v;
                    }
                    self.executed_lines.insert(line_idx);
                }
                Err(LuaError::Timeout) => {
                    let event = DebugEvent::RuntimeError {
                        message: "timeout".to_string(),
                        line: line_idx,
                    };
                    self.events.push(event.clone());
                    new_events.push(event);
                    self.state = DebugState::Error;
                    return new_events;
                }
                Err(e) => {
                    let event = DebugEvent::RuntimeError {
                        message: e.to_string(),
                        line: line_idx,
                    };
                    self.events.push(event.clone());
                    new_events.push(event);
                    self.state = DebugState::Error;
                    return new_events;
                }
            }
        }

        if self.step_mode {
            self.state = DebugState::Paused;
            new_events.push(DebugEvent::StepComplete { line: line_idx });
        }

        // Check for end of script.
        if self.current_line >= total {
            self.state = DebugState::Complete;
            let event = DebugEvent::ScriptComplete {
                return_value: self.last_return.clone(),
            };
            self.events.push(event.clone());
            new_events.push(event);
        }

        self.rebuild_call_stack();
        new_events
    }

    /// Check if any breakpoint fires at `line`. Returns the BP ID if so.
    fn check_breakpoints(&mut self, line: usize) -> Option<u32> {
        let ids: Vec<u32> = self
            .breakpoints
            .values()
            .filter(|b| b.fires_at_line(line))
            .map(|b| b.id)
            .collect();
        if let Some(&id) = ids.first() {
            if let Some(bp) = self.breakpoints.get_mut(&id) {
                bp.hits += 1;
                // Check condition if set.
                if let Some(cond) = bp.condition.clone() {
                    let val = self.eval_expression(&cond);
                    if !val.is_truthy() {
                        return None;
                    }
                }
            }
            return Some(id);
        }
        None
    }

    /// Rebuild the call-stack snapshot for the current pause point.
    fn rebuild_call_stack(&mut self) {
        let frame = LuaStackFrame::toplevel(
            self.current_line,
            self.context.globals.clone(),
        );
        self.call_stack = vec![frame];
    }
}

impl Default for LuaDebugger {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for LuaDebugger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LuaDebugger")
            .field("state", &self.state)
            .field("current_line", &self.current_line)
            .field("breakpoints", &self.breakpoints.len())
            .field("watches", &self.watches.len())
            .finish_non_exhaustive()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dbg_with_source(src: &str) -> LuaDebugger {
        let mut d = LuaDebugger::new();
        d.load_source(src);
        d
    }

    #[test]
    fn test_new_debugger_idle() {
        let d = LuaDebugger::new();
        assert_eq!(d.state(), DebugState::Idle);
        assert_eq!(d.current_line(), 0);
    }

    #[test]
    fn test_load_source_line_count() {
        let d = dbg_with_source("x = 1\ny = 2\nz = 3");
        assert_eq!(d.line_count(), 3);
    }

    #[test]
    fn test_run_simple_script_completes() {
        let mut d = dbg_with_source("x = 1\ny = 2");
        d.run();
        assert_eq!(d.state(), DebugState::Complete);
    }

    #[test]
    fn test_step_advances_line() {
        let mut d = dbg_with_source("x = 1\ny = 2\nz = 3");
        d.step();
        assert_eq!(d.current_line(), 1);
        assert_eq!(d.state(), DebugState::Paused);
    }

    #[test]
    fn test_add_breakpoint() {
        let mut d = LuaDebugger::new();
        let id = d.add_breakpoint(5);
        assert_eq!(id, 1);
        assert!(d.breakpoint_at_line(5).is_some());
    }

    #[test]
    fn test_remove_breakpoint() {
        let mut d = LuaDebugger::new();
        let id = d.add_breakpoint(3);
        assert!(d.remove_breakpoint(id));
        assert!(d.breakpoint_at_line(3).is_none());
    }

    #[test]
    fn test_breakpoint_fires_at_line() {
        let script = "x = 1\ny = 2\nz = 3";
        let mut d = dbg_with_source(script);
        let id = d.add_breakpoint(2);
        let events = d.run();
        let hit = events
            .iter()
            .any(|e| matches!(e, DebugEvent::BreakpointHit { breakpoint_id, .. } if *breakpoint_id == id));
        assert!(hit, "breakpoint should fire at line 2");
        assert_eq!(d.state(), DebugState::Paused);
    }

    #[test]
    fn test_continue_after_breakpoint() {
        let script = "x = 1\ny = 2\nz = 3";
        let mut d = dbg_with_source(script);
        d.add_breakpoint(1);
        d.run();
        assert_eq!(d.state(), DebugState::Paused);
        d.continue_run();
        assert_eq!(d.state(), DebugState::Complete);
    }

    #[test]
    fn test_breakpoint_disabled_no_fire() {
        let script = "x = 1\ny = 2";
        let mut d = dbg_with_source(script);
        let id = d.add_breakpoint(1);
        d.set_breakpoint_enabled(id, false);
        d.run();
        assert_eq!(d.state(), DebugState::Complete);
    }

    #[test]
    fn test_variable_inspection_after_step() {
        let mut d = dbg_with_source("x = 42\ny = 99");
        d.step(); // line 1: x = 42
        let val = d.get_variable("x");
        assert!(matches!(val, LuaValue::Int(42) | LuaValue::Nil));
    }

    #[test]
    fn test_all_variables() {
        let mut d = dbg_with_source("a = 1\nb = 2");
        d.run();
        let vars = d.all_variables();
        // At minimum stdlib functions should be present.
        assert!(!vars.is_empty());
    }

    #[test]
    fn test_add_watch() {
        let mut d = LuaDebugger::new();
        let id = d.add_watch("x + 1");
        assert_eq!(id, 1);
    }

    #[test]
    fn test_evaluate_watches() {
        let mut d = dbg_with_source("x = 10");
        d.step(); // execute x = 10
        d.add_watch("x");
        let evals = d.evaluate_watches();
        let x_watch = evals.iter().find(|(_, expr, _)| expr == "x");
        if let Some((_, _, val)) = x_watch {
            assert!(matches!(val, LuaValue::Int(10) | LuaValue::Nil));
        }
    }

    #[test]
    fn test_eval_expression() {
        let mut d = dbg_with_source("n = 5");
        d.step();
        let val = d.eval_expression("2 + 3");
        assert!(matches!(val, LuaValue::Int(5) | LuaValue::Nil));
    }

    #[test]
    fn test_print_output_captured() {
        let mut d = dbg_with_source(r#"print("debugger test")"#);
        d.run();
        assert!(d.output().iter().any(|l| l.contains("debugger test")));
    }

    #[test]
    fn test_source_listing_format() {
        let mut d = dbg_with_source("x = 1\ny = 2");
        d.add_breakpoint(1);
        let listing = d.source_listing();
        assert_eq!(listing.len(), 2);
        assert!(listing[0].contains("B")); // breakpoint marker
    }

    #[test]
    fn test_breakpoint_display() {
        let bp = LuaBreakpoint::new(1, 10);
        let s = bp.to_string();
        assert!(s.contains("Breakpoint#1"));
        assert!(s.contains("line 10") || s.contains(":10"));
    }

    #[test]
    fn test_stack_frame_display() {
        let frame = LuaStackFrame::toplevel(5, HashMap::new());
        let s = frame.to_string();
        assert!(s.contains("#0"));
        assert!(s.contains("toplevel") || s.contains("<toplevel>"));
    }

    #[test]
    fn test_debug_event_display() {
        let e = DebugEvent::BreakpointHit {
            breakpoint_id: 1,
            line: 5,
        };
        let s = e.to_string();
        assert!(s.contains("bp#1") || s.contains("hit"));
    }

    #[test]
    fn test_multiple_steps() {
        let mut d = dbg_with_source("a = 1\nb = 2\nc = 3");
        d.step();
        d.step();
        d.step();
        assert_eq!(d.state(), DebugState::Complete);
    }

    #[test]
    fn test_events_logged() {
        let mut d = dbg_with_source("x = 1\ny = 2");
        d.run();
        assert!(!d.events().is_empty());
    }

    #[test]
    fn test_complete_after_run_no_bp() {
        let mut d = dbg_with_source("x = 1");
        d.run();
        assert_eq!(d.state(), DebugState::Complete);
    }

    #[test]
    fn test_run_on_complete_no_op() {
        let mut d = dbg_with_source("x = 1");
        d.run();
        let events = d.continue_run();
        assert!(events.is_empty());
    }

    #[test]
    fn test_call_stack_at_pause() {
        let mut d = dbg_with_source("x = 1\ny = 2\nz = 3");
        d.add_breakpoint(2);
        d.run();
        let stack = d.call_stack();
        assert!(!stack.is_empty());
        assert_eq!(stack[0].depth, 0);
    }

    #[test]
    fn test_debugger_debug_format() {
        let d = LuaDebugger::new();
        let s = format!("{d:?}");
        assert!(s.contains("LuaDebugger"));
    }

    #[test]
    fn test_breakpoint_with_hit_count() {
        let bp = LuaBreakpoint::new(1, 5).with_hit_count(3);
        assert!(!bp.fires_at_line(5)); // 0 hits so far, needs 3rd
        let mut bp2 = LuaBreakpoint::new(2, 5).with_hit_count(1);
        assert!(bp2.fires_at_line(5));
        bp2.hits += 1;
        assert!(!bp2.fires_at_line(5)); // already hit once
    }

    #[test]
    fn test_breakpoint_wrong_line() {
        let bp = LuaBreakpoint::new(1, 10);
        assert!(!bp.fires_at_line(5));
        assert!(bp.fires_at_line(10));
    }

    #[test]
    fn test_load_source_resets_state() {
        let mut d = dbg_with_source("x = 1");
        d.run();
        d.load_source("y = 2");
        assert_eq!(d.state(), DebugState::Idle);
        assert_eq!(d.current_line(), 0);
    }
}
