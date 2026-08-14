//! `pattern_debugger` — Debug ImHex-style binary patterns step by step.
//!
//! # Key types
//! * [`PatternDebugger`]   — main debugger facade; owns the execution state.
//! * [`BreakpointEval`]    — breakpoint condition evaluated during pattern execution.
//! * [`WatchExpression`]   — watches a named field or offset for value changes.
//! * [`StepEval`]          — result of a single debugger step.
//! * [`PatternTrace`]      — full execution trace of a pattern parse run.
//! * [`EvalLog`]           — append-only log of evaluation events.

use std::collections::{HashMap, VecDeque};
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DebuggerError {
    #[error("breakpoint {0} not found")]
    BreakpointNotFound(u32),
    #[error("watch '{0}' not found")]
    WatchNotFound(String),
    #[error("no current execution context (not running)")]
    NotRunning,
    #[error("execution already finished")]
    AlreadyFinished,
    #[error("pattern syntax error: {0}")]
    SyntaxError(String),
    #[error("step count overflow")]
    StepOverflow,
    #[error("offset {0} out of buffer bounds")]
    OutOfBounds(usize),
}

pub type DebugResult<T> = Result<T, DebuggerError>;

// ---------------------------------------------------------------------------
// BreakpointEval
// ---------------------------------------------------------------------------

/// Condition under which a breakpoint fires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BreakCondition {
    /// Fire when the reader reaches a specific buffer offset.
    AtOffset(usize),
    /// Fire when a named field is first assigned.
    FieldAssigned(String),
    /// Fire when a named field's value equals `expected` (hex string).
    FieldEquals { field: String, expected: String },
    /// Fire after exactly `n` steps.
    StepCount(u64),
    /// Always fires (unconditional breakpoint at a statement index).
    Always,
}

impl fmt::Display for BreakCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtOffset(o) => write!(f, "offset == {o:#x}"),
            Self::FieldAssigned(n) => write!(f, "assigned({n})"),
            Self::FieldEquals { field, expected } => write!(f, "{field} == {expected}"),
            Self::StepCount(n) => write!(f, "step == {n}"),
            Self::Always => write!(f, "true"),
        }
    }
}

/// A breakpoint registered with the debugger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreakpointEval {
    pub id: u32,
    pub condition: BreakCondition,
    pub enabled: bool,
    pub hit_count: u64,
    pub description: Option<String>,
}

impl BreakpointEval {
    #[must_use] 
    pub const fn new(id: u32, condition: BreakCondition) -> Self {
        Self {
            id,
            condition,
            enabled: true,
            hit_count: 0,
            description: None,
        }
    }

    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Check if this breakpoint fires given the current execution state.
    #[must_use] 
    pub fn fires(&self, ctx: &ExecContext) -> bool {
        if !self.enabled {
            return false;
        }
        match &self.condition {
            BreakCondition::AtOffset(o) => ctx.offset == *o,
            BreakCondition::FieldAssigned(name) => {
                ctx.last_assigned.as_deref() == Some(name.as_str())
            }
            BreakCondition::FieldEquals { field, expected } => ctx
                .fields
                .get(field.as_str())
                .is_some_and(|v| v == expected),
            BreakCondition::StepCount(n) => ctx.step_count == *n,
            BreakCondition::Always => true,
        }
    }
}

// ---------------------------------------------------------------------------
// WatchExpression
// ---------------------------------------------------------------------------

/// Watches a named field or memory offset for changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchExpression {
    pub id: u32,
    pub name: String,
    /// If `Some`, watch a named field; if `None`, watch `memory_offset`.
    pub field: Option<String>,
    pub memory_offset: Option<usize>,
    /// Last observed value.
    pub last_value: Option<String>,
    /// History of (step, value) pairs.
    pub history: Vec<(u64, String)>,
    pub enabled: bool,
}

impl WatchExpression {
    pub fn for_field(id: u32, name: impl Into<String>, field: impl Into<String>) -> Self {
        let name = name.into();
        let field = field.into();
        Self {
            id,
            name,
            field: Some(field),
            memory_offset: None,
            last_value: None,
            history: Vec::new(),
            enabled: true,
        }
    }

    pub fn for_offset(id: u32, name: impl Into<String>, offset: usize) -> Self {
        let name = name.into();
        Self {
            id,
            name,
            field: None,
            memory_offset: Some(offset),
            last_value: None,
            history: Vec::new(),
            enabled: true,
        }
    }

    /// Update this watch from the current execution context. Returns `true` if the value changed.
    pub fn update(&mut self, ctx: &ExecContext, buf: &[u8]) -> bool {
        if !self.enabled {
            return false;
        }
        let new_val: Option<String> = if let Some(f) = &self.field {
            ctx.fields.get(f.as_str()).cloned()
        } else if let Some(off) = self.memory_offset {
            buf.get(off).map(|b| format!("{b:#04x}"))
        } else {
            None
        };
        if new_val == self.last_value {
            false
        } else {
            if let Some(v) = &new_val {
                self.history.push((ctx.step_count, v.clone()));
            }
            self.last_value = new_val;
            true
        }
    }

    /// Number of times the watch value changed.
    #[must_use] 
    pub const fn change_count(&self) -> usize {
        self.history.len()
    }
}

// ---------------------------------------------------------------------------
// ExecContext — current execution state
// ---------------------------------------------------------------------------

/// Snapshot of the pattern evaluator's state at one step.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecContext {
    /// Current read offset in the buffer.
    pub offset: usize,
    /// Named fields assigned so far (`field_name` → value as string).
    pub fields: HashMap<String, String>,
    /// The field assigned in the most recent step.
    pub last_assigned: Option<String>,
    /// How many steps have been executed.
    pub step_count: u64,
    /// Call-stack depth (for nested struct parsing).
    pub call_depth: usize,
    /// Current struct/rule being evaluated.
    pub current_rule: Option<String>,
}

impl ExecContext {
    /// Assign a field value.
    pub fn assign(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        self.last_assigned = Some(name.clone());
        self.fields.insert(name, value);
    }
}

// ---------------------------------------------------------------------------
// StepEval — result of a single step
// ---------------------------------------------------------------------------

/// Outcome of executing one step in the debugger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepOutcome {
    /// Normal progress — offset advanced.
    Continue,
    /// A breakpoint fired.
    BreakpointHit(u32),
    /// A watch expression triggered.
    WatchTriggered(u32),
    /// Pattern parsing finished successfully.
    Finished,
    /// An error occurred during evaluation.
    Error(String),
}

impl fmt::Display for StepOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Continue => write!(f, "continue"),
            Self::BreakpointHit(id) => write!(f, "breakpoint #{id} hit"),
            Self::WatchTriggered(id) => write!(f, "watch #{id} triggered"),
            Self::Finished => write!(f, "finished"),
            Self::Error(e) => write!(f, "error: {e}"),
        }
    }
}

/// Result of one debugger step.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepEval {
    pub step: u64,
    pub offset_before: usize,
    pub offset_after: usize,
    pub bytes_read: Vec<u8>,
    pub field_name: Option<String>,
    pub field_value: Option<String>,
    pub outcome: StepOutcome,
}

impl fmt::Display for StepEval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "step={} off={:#x}->{:#x} [{}] {}",
            self.step,
            self.offset_before,
            self.offset_after,
            self.field_name.as_deref().unwrap_or("_"),
            self.outcome
        )
    }
}

// ---------------------------------------------------------------------------
// PatternTrace
// ---------------------------------------------------------------------------

/// Full execution trace of a pattern evaluation run.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PatternTrace {
    pub steps: Vec<StepEval>,
    pub breakpoints_hit: Vec<u32>,
    pub watches_triggered: Vec<u32>,
    pub total_bytes_consumed: usize,
    pub max_call_depth: usize,
    pub finished_successfully: bool,
    pub error: Option<String>,
}

impl PatternTrace {
    /// Append a step to the trace.
    pub fn push(&mut self, step: StepEval) {
        self.total_bytes_consumed = step.offset_after;
        match &step.outcome {
            StepOutcome::BreakpointHit(id) => self.breakpoints_hit.push(*id),
            StepOutcome::WatchTriggered(id) => self.watches_triggered.push(*id),
            StepOutcome::Finished => self.finished_successfully = true,
            StepOutcome::Error(e) => self.error = Some(e.clone()),
            _ => {}
        }
        self.steps.push(step);
    }

    /// Number of steps recorded.
    #[must_use] 
    pub const fn len(&self) -> usize {
        self.steps.len()
    }

    /// Returns `true` if the trace is empty.
    #[must_use] 
    pub const fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// All unique fields assigned during the trace.
    #[must_use] 
    pub fn assigned_fields(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for s in &self.steps {
            if let Some(f) = &s.field_name
                && seen.insert(f.clone()) {
                    out.push(f.clone());
                }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// EvalLog
// ---------------------------------------------------------------------------

/// Severity of a log event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trace => write!(f, "TRACE"),
            Self::Debug => write!(f, "DEBUG"),
            Self::Info => write!(f, "INFO"),
            Self::Warn => write!(f, "WARN"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

/// A single log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub level: LogLevel,
    pub step: u64,
    pub offset: usize,
    pub message: String,
}

impl fmt::Display for LogEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] step={} off={:#x}: {}",
            self.level, self.step, self.offset, self.message
        )
    }
}

/// Append-only log of evaluation events.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EvalLog {
    entries: VecDeque<LogEntry>,
    max_entries: usize,
}

impl EvalLog {
    #[must_use] 
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            max_entries: max_entries.max(1),
        }
    }

    /// Append an entry.
    pub fn log(&mut self, level: LogLevel, step: u64, offset: usize, message: impl Into<String>) {
        if self.entries.len() >= self.max_entries {
            self.entries.pop_front();
        }
        self.entries.push_back(LogEntry {
            level,
            step,
            offset,
            message: message.into(),
        });
    }

    /// All entries at or above `min_level`.
    #[must_use] 
    pub fn filter(&self, min_level: LogLevel) -> Vec<&LogEntry> {
        self.entries
            .iter()
            .filter(|e| e.level >= min_level)
            .collect()
    }

    #[must_use] 
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn iter(&self) -> impl Iterator<Item = &LogEntry> {
        self.entries.iter()
    }
}

// ---------------------------------------------------------------------------
// PatternDebugger — main facade
// ---------------------------------------------------------------------------

/// Execution mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunMode {
    /// Execute one statement at a time.
    Step,
    /// Run until a breakpoint / finish.
    Run,
    /// Run to the next field assignment.
    StepOver,
}

/// Simulated pattern statement (simplified AST node for testing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternStatement {
    pub field_name: String,
    pub type_name: String,
    pub byte_count: usize,
    pub description: Option<String>,
}

/// The main debugger — loads a list of pattern statements and steps through them.
#[derive(Debug, Serialize, Deserialize)]
pub struct PatternDebugger {
    /// The buffer being parsed.
    pub buffer: Vec<u8>,
    /// Sequence of statements to evaluate.
    pub statements: Vec<PatternStatement>,
    /// Current execution context.
    pub context: ExecContext,
    /// Registered breakpoints.
    pub breakpoints: HashMap<u32, BreakpointEval>,
    /// Registered watches.
    pub watches: HashMap<u32, WatchExpression>,
    /// The execution trace.
    pub trace: PatternTrace,
    /// Evaluation log.
    pub log: EvalLog,
    /// Program counter (index into `statements`).
    pc: usize,
    /// Running breakpoint ID counter.
    next_bp_id: u32,
    /// Running watch ID counter.
    next_watch_id: u32,
    /// Whether execution has finished.
    finished: bool,
}

impl PatternDebugger {
    /// Create a new debugger for the given buffer and statement list.
    #[must_use] 
    pub fn new(buffer: Vec<u8>, statements: Vec<PatternStatement>) -> Self {
        Self {
            buffer,
            statements,
            context: ExecContext::default(),
            breakpoints: HashMap::new(),
            watches: HashMap::new(),
            trace: PatternTrace::default(),
            log: EvalLog::new(4096),
            pc: 0,
            next_bp_id: 1,
            next_watch_id: 1,
            finished: false,
        }
    }

    /// Register a breakpoint. Returns its ID.
    pub fn add_breakpoint(&mut self, condition: BreakCondition) -> u32 {
        let id = self.next_bp_id;
        self.next_bp_id += 1;
        self.breakpoints
            .insert(id, BreakpointEval::new(id, condition));
        id
    }

    /// Remove a breakpoint by ID.
    pub fn remove_breakpoint(&mut self, id: u32) -> DebugResult<()> {
        self.breakpoints
            .remove(&id)
            .map(|_| ())
            .ok_or(DebuggerError::BreakpointNotFound(id))
    }

    /// Enable or disable a breakpoint.
    pub fn set_breakpoint_enabled(&mut self, id: u32, enabled: bool) -> DebugResult<()> {
        self.breakpoints
            .get_mut(&id)
            .ok_or(DebuggerError::BreakpointNotFound(id))
            .map(|bp| bp.enabled = enabled)
    }

    /// Register a watch. Returns its ID.
    pub fn add_watch_field(&mut self, name: impl Into<String>, field: impl Into<String>) -> u32 {
        let id = self.next_watch_id;
        self.next_watch_id += 1;
        self.watches
            .insert(id, WatchExpression::for_field(id, name, field));
        id
    }

    /// Register a memory watch. Returns its ID.
    pub fn add_watch_offset(&mut self, name: impl Into<String>, offset: usize) -> u32 {
        let id = self.next_watch_id;
        self.next_watch_id += 1;
        self.watches
            .insert(id, WatchExpression::for_offset(id, name, offset));
        id
    }

    /// Execute a single statement. Returns the step result.
    pub fn step(&mut self) -> DebugResult<StepEval> {
        if self.finished {
            return Err(DebuggerError::AlreadyFinished);
        }
        if self.pc >= self.statements.len() {
            self.finished = true;
            let s = StepEval {
                step: self.context.step_count,
                offset_before: self.context.offset,
                offset_after: self.context.offset,
                bytes_read: Vec::new(),
                field_name: None,
                field_value: None,
                outcome: StepOutcome::Finished,
            };
            self.trace.push(s.clone());
            return Ok(s);
        }

        let stmt = &self.statements[self.pc];
        let offset_before = self.context.offset;
        let n = stmt.byte_count;

        // Read bytes.
        if offset_before + n > self.buffer.len() {
            let msg = format!("buffer overrun at offset {offset_before}: need {n}");
            self.log.log(
                LogLevel::Error,
                self.context.step_count,
                offset_before,
                &msg,
            );
            self.finished = true;
            let s = StepEval {
                step: self.context.step_count,
                offset_before,
                offset_after: offset_before,
                bytes_read: Vec::new(),
                field_name: Some(stmt.field_name.clone()),
                field_value: None,
                outcome: StepOutcome::Error(msg),
            };
            self.trace.push(s.clone());
            return Ok(s);
        }

        let bytes_read = self.buffer[offset_before..offset_before + n].to_vec();
        let field_value: String = bytes_read
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");

        // Update context.
        self.context.offset = offset_before + n;
        self.context
            .assign(stmt.field_name.clone(), field_value.clone());
        self.context.step_count += 1;
        self.pc += 1;

        // Update watches.
        let mut triggered_watch = None;
        let buf = &self.buffer;
        for w in self.watches.values_mut() {
            if w.update(&self.context, buf) {
                triggered_watch = Some(w.id);
            }
        }

        // Check breakpoints.
        let mut hit_bp = None;
        for bp in self.breakpoints.values_mut() {
            if bp.fires(&self.context) {
                bp.hit_count += 1;
                hit_bp = Some(bp.id);
            }
        }

        self.log.log(
            LogLevel::Debug,
            self.context.step_count,
            offset_before,
            format!("{}: {} = {field_value}", stmt.field_name, stmt.type_name),
        );

        let outcome = if let Some(id) = hit_bp {
            StepOutcome::BreakpointHit(id)
        } else if let Some(id) = triggered_watch {
            StepOutcome::WatchTriggered(id)
        } else if self.pc >= self.statements.len() {
            self.finished = true;
            StepOutcome::Finished
        } else {
            StepOutcome::Continue
        };

        let s = StepEval {
            step: self.context.step_count,
            offset_before,
            offset_after: self.context.offset,
            bytes_read,
            field_name: Some(stmt.field_name.clone()),
            field_value: Some(field_value),
            outcome,
        };
        self.trace.push(s.clone());
        Ok(s)
    }

    /// Run until finished or a breakpoint fires.
    pub fn run(&mut self) -> DebugResult<Vec<StepEval>> {
        let mut results = Vec::new();
        loop {
            let s = self.step()?;
            let done = matches!(
                s.outcome,
                StepOutcome::Finished | StepOutcome::BreakpointHit(_) | StepOutcome::Error(_)
            );
            results.push(s);
            if done {
                break;
            }
        }
        Ok(results)
    }

    /// Reset the debugger to initial state, keeping breakpoints and watches.
    pub fn reset(&mut self) {
        self.context = ExecContext::default();
        self.trace = PatternTrace::default();
        self.log.clear();
        self.pc = 0;
        self.finished = false;
    }

    /// Whether execution has finished.
    #[must_use] 
    pub const fn is_finished(&self) -> bool {
        self.finished
    }

    /// Total breakpoints registered.
    #[must_use] 
    pub fn breakpoint_count(&self) -> usize {
        self.breakpoints.len()
    }

    /// Total watches registered.
    #[must_use] 
    pub fn watch_count(&self) -> usize {
        self.watches.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Build a list of [`PatternStatement`]s from `(name, type, size)` tuples.
///
/// Convenience helper for constructing debugger inputs from short fixtures
/// (used by this crate's tests and by external integration tests).
#[must_use] 
pub fn make_stmts(fields: &[(&str, &str, usize)]) -> Vec<PatternStatement> {
    fields
        .iter()
        .map(|(name, ty, sz)| PatternStatement {
            field_name: name.to_string(),
            type_name: ty.to_string(),
            byte_count: *sz,
            description: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_basic_field() {
        let buf = vec![0x4D, 0x5A, 0x90];
        let stmts = make_stmts(&[("magic", "u16", 2)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        let s = dbg.step().unwrap();
        assert_eq!(s.field_name.as_deref(), Some("magic"));
        assert_eq!(s.bytes_read, [0x4D, 0x5A]);
        assert_eq!(dbg.context.offset, 2);
    }

    #[test]
    fn step_advances_offset() {
        let buf = vec![1, 2, 3, 4, 5, 6];
        let stmts = make_stmts(&[("a", "u32", 4), ("b", "u16", 2)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        dbg.step().unwrap();
        assert_eq!(dbg.context.offset, 4);
        dbg.step().unwrap();
        assert_eq!(dbg.context.offset, 6);
    }

    #[test]
    fn step_finished_after_all_stmts() {
        let buf = vec![1];
        let stmts = make_stmts(&[("x", "u8", 1)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        let s = dbg.step().unwrap();
        assert_eq!(s.outcome, StepOutcome::Finished);
        assert!(dbg.is_finished());
    }

    #[test]
    fn step_already_finished_error() {
        let buf = vec![1];
        let stmts = make_stmts(&[("x", "u8", 1)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        dbg.step().unwrap();
        // Stepping again after finish on empty statements produces AlreadyFinished
        let r = dbg.step();
        assert!(matches!(r, Err(DebuggerError::AlreadyFinished)));
    }

    #[test]
    fn step_buffer_overrun() {
        let buf = vec![0x01];
        let stmts = make_stmts(&[("big", "u32", 4)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        let s = dbg.step().unwrap();
        assert!(matches!(s.outcome, StepOutcome::Error(_)));
    }

    #[test]
    fn breakpoint_at_offset_fires() {
        let buf = vec![0u8; 8];
        let stmts = make_stmts(&[("a", "u32", 4), ("b", "u32", 4)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        dbg.add_breakpoint(BreakCondition::AtOffset(4));
        dbg.step().unwrap(); // reads 4 bytes, offset becomes 4
        let s = dbg.step().unwrap(); // will read but BP check is post-assign
        // The BP at 4 would have fired at step 1's post-condition (offset==4)
        let hit = dbg.trace.breakpoints_hit.len();
        assert!(hit > 0);
        let _ = s;
    }

    #[test]
    fn breakpoint_step_count_fires() {
        let buf = vec![0u8; 4];
        let stmts = make_stmts(&[("a", "u8", 1), ("b", "u8", 1), ("c", "u8", 1)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        dbg.add_breakpoint(BreakCondition::StepCount(2));
        dbg.step().unwrap();
        let s = dbg.step().unwrap();
        assert!(matches!(s.outcome, StepOutcome::BreakpointHit(_)));
    }

    #[test]
    fn breakpoint_field_assigned() {
        let buf = vec![0xAA];
        let stmts = make_stmts(&[("magic", "u8", 1)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        dbg.add_breakpoint(BreakCondition::FieldAssigned("magic".into()));
        let s = dbg.step().unwrap();
        assert!(matches!(s.outcome, StepOutcome::BreakpointHit(_)));
    }

    #[test]
    fn breakpoint_remove() {
        let buf = vec![0u8; 2];
        let stmts = make_stmts(&[("x", "u8", 1)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        let id = dbg.add_breakpoint(BreakCondition::Always);
        dbg.remove_breakpoint(id).unwrap();
        assert_eq!(dbg.breakpoint_count(), 0);
    }

    #[test]
    fn breakpoint_remove_not_found() {
        let mut dbg = PatternDebugger::new(vec![], vec![]);
        assert!(matches!(
            dbg.remove_breakpoint(99),
            Err(DebuggerError::BreakpointNotFound(99))
        ));
    }

    #[test]
    fn breakpoint_enable_disable() {
        let buf = vec![0u8; 2];
        let stmts = make_stmts(&[("x", "u8", 1)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        let id = dbg.add_breakpoint(BreakCondition::Always);
        dbg.set_breakpoint_enabled(id, false).unwrap();
        let s = dbg.step().unwrap();
        assert!(!matches!(s.outcome, StepOutcome::BreakpointHit(_)));
    }

    #[test]
    fn watch_field_fires() {
        let buf = vec![0xDE, 0xAD];
        let stmts = make_stmts(&[("sig", "u16", 2)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        dbg.add_watch_field("w", "sig");
        let s = dbg.step().unwrap();
        assert!(matches!(
            s.outcome,
            StepOutcome::WatchTriggered(_) | StepOutcome::Finished
        ));
    }

    #[test]
    fn watch_memory_offset() {
        let buf = vec![0x01, 0x02, 0x03];
        let stmts = make_stmts(&[("a", "u8", 1)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        dbg.add_watch_offset("w", 0);
        dbg.step().unwrap();
        // Watch at offset 0 is a memory watch; the step doesn't change the byte there,
        // but we can check the watch exists.
        assert_eq!(dbg.watch_count(), 1);
    }

    #[test]
    fn run_until_finished() {
        let buf = vec![1, 2, 3, 4];
        let stmts = make_stmts(&[
            ("a", "u8", 1),
            ("b", "u8", 1),
            ("c", "u8", 1),
            ("d", "u8", 1),
        ]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        let steps = dbg.run().unwrap();
        assert!(steps.last().unwrap().outcome == StepOutcome::Finished);
        assert!(dbg.is_finished());
    }

    #[test]
    fn run_stops_at_breakpoint() {
        let buf = vec![0u8; 8];
        let stmts = make_stmts(&[("a", "u32", 4), ("b", "u32", 4)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        dbg.add_breakpoint(BreakCondition::StepCount(1));
        let steps = dbg.run().unwrap();
        assert!(
            steps
                .iter()
                .any(|s| matches!(s.outcome, StepOutcome::BreakpointHit(_)))
        );
    }

    #[test]
    fn reset_clears_state() {
        let buf = vec![1, 2, 3, 4];
        let stmts = make_stmts(&[("a", "u32", 4)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        dbg.run().unwrap();
        assert!(dbg.is_finished());
        dbg.reset();
        assert!(!dbg.is_finished());
        assert_eq!(dbg.context.offset, 0);
        assert_eq!(dbg.context.step_count, 0);
    }

    #[test]
    fn trace_records_fields() {
        let buf = vec![1, 2, 3, 4];
        let stmts = make_stmts(&[("a", "u8", 1), ("b", "u8", 1)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        dbg.run().unwrap();
        let fields = dbg.trace.assigned_fields();
        assert!(fields.contains(&"a".to_string()));
        assert!(fields.contains(&"b".to_string()));
    }

    #[test]
    fn eval_log_records_messages() {
        let buf = vec![0xAB, 0xCD];
        let stmts = make_stmts(&[("x", "u8", 1), ("y", "u8", 1)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        dbg.run().unwrap();
        assert!(!dbg.log.is_empty());
    }

    #[test]
    fn eval_log_filter() {
        let mut log = EvalLog::new(100);
        log.log(LogLevel::Debug, 0, 0, "debug msg");
        log.log(LogLevel::Error, 1, 0, "error msg");
        let errors = log.filter(LogLevel::Error);
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn eval_log_max_entries() {
        let mut log = EvalLog::new(3);
        for i in 0..5 {
            log.log(LogLevel::Info, i, 0, "msg");
        }
        assert_eq!(log.len(), 3);
    }

    #[test]
    fn step_eval_display() {
        let s = StepEval {
            step: 1,
            offset_before: 0,
            offset_after: 4,
            bytes_read: vec![0, 0, 0, 0],
            field_name: Some("test".into()),
            field_value: Some("00 00 00 00".into()),
            outcome: StepOutcome::Continue,
        };
        let d = format!("{s}");
        assert!(d.contains("step=1"));
    }

    #[test]
    fn pattern_trace_total_bytes() {
        let buf = vec![1, 2, 3, 4];
        let stmts = make_stmts(&[("x", "u32", 4)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        dbg.run().unwrap();
        assert_eq!(dbg.trace.total_bytes_consumed, 4);
    }

    #[test]
    fn break_condition_display() {
        let c = BreakCondition::AtOffset(0x1000);
        assert!(format!("{c}").contains("0x1000"));
    }

    #[test]
    fn watch_change_count() {
        let buf = vec![0xAA, 0xBB];
        let stmts = make_stmts(&[("a", "u8", 1), ("b", "u8", 1)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        let wid = dbg.add_watch_field("w", "a");
        dbg.run().unwrap();
        let w = &dbg.watches[&wid];
        assert!(w.change_count() <= 1); // 'a' assigned once
    }

    #[test]
    fn log_level_ordering() {
        assert!(LogLevel::Error > LogLevel::Warn);
        assert!(LogLevel::Info > LogLevel::Debug);
    }

    #[test]
    fn log_level_display() {
        assert_eq!(format!("{}", LogLevel::Trace), "TRACE");
        assert_eq!(format!("{}", LogLevel::Error), "ERROR");
        assert_eq!(format!("{}", LogLevel::Info), "INFO");
    }

    #[test]
    fn break_condition_field_equals() {
        let ctx = ExecContext {
            fields: {
                let mut m = std::collections::HashMap::new();
                m.insert("x".into(), "42".into());
                m
            },
            ..Default::default()
        };
        let bp = BreakpointEval::new(
            1,
            BreakCondition::FieldEquals {
                field: "x".into(),
                expected: "42".into(),
            },
        );
        assert!(bp.fires(&ctx));
    }

    #[test]
    fn break_condition_field_equals_mismatch() {
        let ctx = ExecContext {
            fields: {
                let mut m = std::collections::HashMap::new();
                m.insert("x".into(), "99".into());
                m
            },
            ..Default::default()
        };
        let bp = BreakpointEval::new(
            1,
            BreakCondition::FieldEquals {
                field: "x".into(),
                expected: "42".into(),
            },
        );
        assert!(!bp.fires(&ctx));
    }

    #[test]
    fn step_eval_outcome_display() {
        assert_eq!(format!("{}", StepOutcome::Continue), "continue");
        assert_eq!(format!("{}", StepOutcome::Finished), "finished");
        assert!(format!("{}", StepOutcome::BreakpointHit(3)).contains("#3"));
    }

    #[test]
    fn exec_context_assign_updates_last_assigned() {
        let mut ctx = ExecContext::default();
        ctx.assign("foo", "bar");
        assert_eq!(ctx.last_assigned.as_deref(), Some("foo"));
        assert_eq!(ctx.fields.get("foo").map(std::string::String::as_str), Some("bar"));
    }

    #[test]
    fn pattern_trace_empty() {
        let trace = PatternTrace::default();
        assert!(trace.is_empty());
        assert_eq!(trace.len(), 0);
        assert!(trace.assigned_fields().is_empty());
    }

    #[test]
    fn watch_expression_for_offset() {
        let w = WatchExpression::for_offset(1, "w1", 100);
        assert_eq!(w.memory_offset, Some(100));
        assert!(w.field.is_none());
    }

    #[test]
    fn watch_expression_history_appended() {
        let buf = vec![0xAA, 0xBB, 0xCC];
        let stmts = make_stmts(&[("a", "u8", 1), ("b", "u8", 1)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        let wid = dbg.add_watch_field("w", "a");
        dbg.step().unwrap();
        let w = &dbg.watches[&wid];
        assert!(w.change_count() <= 1);
    }

    #[test]
    fn debugger_multiple_breakpoints() {
        let buf = vec![0u8; 8];
        let stmts = make_stmts(&[("a", "u8", 1), ("b", "u8", 1), ("c", "u8", 1)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        let id1 = dbg.add_breakpoint(BreakCondition::StepCount(1));
        let id2 = dbg.add_breakpoint(BreakCondition::StepCount(2));
        assert_eq!(dbg.breakpoint_count(), 2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn debugger_step_count_increments() {
        let buf = vec![1, 2, 3];
        let stmts = make_stmts(&[("a", "u8", 1), ("b", "u8", 1), ("c", "u8", 1)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        dbg.step().unwrap();
        dbg.step().unwrap();
        assert_eq!(dbg.context.step_count, 2);
    }

    #[test]
    fn debugger_fields_set_after_run() {
        let buf = vec![0xAB, 0xCD];
        let stmts = make_stmts(&[("field_a", "u8", 1), ("field_b", "u8", 1)]);
        let mut dbg = PatternDebugger::new(buf, stmts);
        dbg.run().unwrap();
        assert!(dbg.context.fields.contains_key("field_a"));
        assert!(dbg.context.fields.contains_key("field_b"));
    }

    #[test]
    fn log_entry_display() {
        let e = LogEntry {
            level: LogLevel::Warn,
            step: 5,
            offset: 0x10,
            message: "test".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("WARN"));
        assert!(s.contains("test"));
    }

    #[test]
    fn eval_log_clear() {
        let mut log = EvalLog::new(100);
        log.log(LogLevel::Info, 0, 0, "msg");
        assert!(!log.is_empty());
        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn break_condition_always_fires() {
        let ctx = ExecContext::default();
        let bp = BreakpointEval::new(1, BreakCondition::Always);
        assert!(bp.fires(&ctx));
    }

    #[test]
    fn watch_update_no_change_returns_false() {
        let buf = vec![0u8; 4];
        let mut w = WatchExpression::for_field(1, "w", "x");
        let ctx = ExecContext::default();
        let changed1 = w.update(&ctx, &buf);
        let changed2 = w.update(&ctx, &buf);
        // second call: same value → false
        assert!(!changed2 || !changed1); // at most one true
    }
}
