//! Async / coroutine execution support for the embedded Lua engine.
//!
//! Provides:
//! - `CoroutineStatus` — lifecycle states.
//! - `YieldValue` — value exchanged on yield.
//! - `ResumeResult` — the result of resuming a coroutine.
//! - `LuaCoroutine` — a suspendable Lua execution unit backed by the engine.
//! - `LuaAsync` — non-blocking wrapper that drives coroutines step-by-step.

use std::collections::VecDeque;

use crate::{LuaContext, LuaEngine, LuaError, LuaValue};

// ---------------------------------------------------------------------------
// CoroutineStatus
// ---------------------------------------------------------------------------

/// The lifecycle state of a [`LuaCoroutine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CoroutineStatus {
    /// The coroutine has been created but not yet started.
    Suspended,
    /// The coroutine is currently running (actively executing on the call stack).
    Running,
    /// The coroutine completed successfully and returned a value.
    Dead,
    /// The coroutine terminated with an unrecoverable error.
    Failed,
}

impl std::fmt::Display for CoroutineStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Suspended => write!(f, "suspended"),
            Self::Running => write!(f, "running"),
            Self::Dead => write!(f, "dead"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

// ---------------------------------------------------------------------------
// YieldValue
// ---------------------------------------------------------------------------

/// A value that is exchanged when a coroutine yields or is resumed.
#[derive(Debug, Clone)]
pub struct YieldValue {
    /// The actual Lua value being passed.
    pub value: LuaValue,
    /// An optional tag identifying the reason for the yield.
    pub tag: Option<String>,
}

impl YieldValue {
    /// Create a yield value from a `LuaValue`.
    #[must_use]
    pub const fn new(value: LuaValue) -> Self {
        Self { value, tag: None }
    }

    /// Attach a tag to the yield value.
    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tag = Some(tag.into());
        self
    }

    /// Create a nil yield value.
    #[must_use]
    pub const fn nil() -> Self {
        Self::new(LuaValue::Nil)
    }

    /// Create an integer yield value.
    #[must_use]
    pub const fn int(n: i64) -> Self {
        Self::new(LuaValue::Int(n))
    }

    /// Create a string yield value.
    #[must_use]
    pub fn string(s: impl Into<String>) -> Self {
        Self::new(LuaValue::String(s.into()))
    }
}

impl std::fmt::Display for YieldValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(t) = &self.tag {
            write!(f, "YieldValue({}, tag={t})", self.value)
        } else {
            write!(f, "YieldValue({})", self.value)
        }
    }
}

// ---------------------------------------------------------------------------
// ResumeResult
// ---------------------------------------------------------------------------

/// The result returned after one resume of a [`LuaCoroutine`].
#[derive(Debug, Clone)]
pub enum ResumeResult {
    /// The coroutine yielded a value and is now suspended again.
    Yielded(YieldValue),
    /// The coroutine ran to completion and returned a value.
    Returned(LuaValue),
    /// The coroutine encountered an error.
    Error(String),
}

impl ResumeResult {
    /// Whether the coroutine is still alive (yielded or returned normally).
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        !matches!(self, Self::Error(_))
    }

    /// Whether the coroutine finished (returned or errored).
    #[must_use]
    pub const fn is_finished(&self) -> bool {
        matches!(self, Self::Returned(_) | Self::Error(_))
    }

    /// Extract the yielded value, if any.
    #[must_use]
    pub const fn yielded_value(&self) -> Option<&YieldValue> {
        match self {
            Self::Yielded(v) => Some(v),
            _ => None,
        }
    }

    /// Extract the returned value, if any.
    #[must_use]
    pub const fn returned_value(&self) -> Option<&LuaValue> {
        match self {
            Self::Returned(v) => Some(v),
            _ => None,
        }
    }
}

impl std::fmt::Display for ResumeResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Yielded(v) => write!(f, "Yielded({v})"),
            Self::Returned(v) => write!(f, "Returned({v})"),
            Self::Error(e) => write!(f, "Error({e})"),
        }
    }
}

// ---------------------------------------------------------------------------
// LuaCoroutine
// ---------------------------------------------------------------------------

/// A suspendable Lua execution unit.
///
/// This is a *cooperative* coroutine: it runs its script in one or more
/// steps.  Because the underlying engine does not support true coroutine
/// continuations, we simulate stepping by running at most `max_steps` Lua
/// instructions per resume and treating execution timeouts as yields.
pub struct LuaCoroutine {
    /// Unique identifier for this coroutine.
    pub id: u64,
    /// Human-readable label (optional).
    pub name: String,
    /// The Lua script this coroutine runs.
    pub script: String,
    /// Current lifecycle status.
    pub status: CoroutineStatus,
    /// Engine used for execution.
    engine: LuaEngine,
    /// Context (global variable scope + output).
    pub context: LuaContext,
    /// Values yielded by this coroutine so far.
    pub yielded_values: Vec<YieldValue>,
    /// Maximum steps executed per resume (simulates cooperative scheduling).
    pub steps_per_resume: u64,
    /// Total steps executed across all resumes.
    pub total_steps: u64,
    /// The final return value (if `Dead`).
    return_value: Option<LuaValue>,
    /// Last error message (if `Failed`).
    error_message: Option<String>,
}

impl LuaCoroutine {
    /// Create a new coroutine from a Lua script string.
    #[must_use]
    pub fn new(id: u64, name: impl Into<String>, script: impl Into<String>) -> Self {
        let mut engine = LuaEngine::new();
        engine.set_max_steps(200);
        Self {
            id,
            name: name.into(),
            script: script.into(),
            status: CoroutineStatus::Suspended,
            engine,
            context: LuaContext::new(),
            yielded_values: Vec::new(),
            steps_per_resume: 200,
            total_steps: 0,
            return_value: None,
            error_message: None,
        }
    }

    /// Set the maximum number of steps per resume.
    #[must_use]
    pub const fn with_steps_per_resume(mut self, n: u64) -> Self {
        self.steps_per_resume = n;
        self.engine.set_max_steps(n);
        self
    }

    /// Set a global variable visible to the coroutine script.
    pub fn set_global(&mut self, name: impl Into<String>, val: LuaValue) {
        self.context.set(name.into(), val);
    }

    /// Resume the coroutine, optionally sending a value in.
    ///
    /// Returns a `ResumeResult` describing what happened.
    pub fn resume(&mut self, _send: Option<YieldValue>) -> ResumeResult {
        match self.status {
            CoroutineStatus::Dead | CoroutineStatus::Failed => {
                return ResumeResult::Error("cannot resume a dead or failed coroutine".to_string());
            }
            _ => {}
        }

        self.status = CoroutineStatus::Running;
        self.engine.set_max_steps(self.steps_per_resume);

        let result = self.engine.execute(&self.script.clone(), &mut self.context);
        let steps_this_run = self.engine.step_count();
        self.total_steps += steps_this_run;

        match result {
            Ok(val) => {
                self.status = CoroutineStatus::Dead;
                self.return_value = Some(val.clone());
                ResumeResult::Returned(val)
            }
            Err(LuaError::Timeout) => {
                // Simulated yield: the script hit its step limit.
                self.status = CoroutineStatus::Suspended;
                let yv = YieldValue::int(crate::casts::u64_to_i64(steps_this_run)).with_tag("timeout-yield");
                self.yielded_values.push(yv.clone());
                ResumeResult::Yielded(yv)
            }
            Err(e) => {
                self.status = CoroutineStatus::Failed;
                let msg = e.to_string();
                self.error_message = Some(msg.clone());
                ResumeResult::Error(msg)
            }
        }
    }

    /// Convenience: resume with no incoming value.
    pub fn start(&mut self) -> ResumeResult {
        self.resume(None)
    }

    /// Whether this coroutine can still be resumed.
    #[must_use]
    pub const fn is_alive(&self) -> bool {
        matches!(
            self.status,
            CoroutineStatus::Suspended | CoroutineStatus::Running
        )
    }

    /// Return the final value if the coroutine has completed.
    #[must_use]
    pub const fn return_value(&self) -> Option<&LuaValue> {
        self.return_value.as_ref()
    }

    /// Return the error message if the coroutine failed.
    #[must_use]
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    /// Number of yields so far.
    #[must_use]
    pub const fn yield_count(&self) -> usize {
        self.yielded_values.len()
    }
}

impl std::fmt::Debug for LuaCoroutine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LuaCoroutine(id={}, name={:?}, status={}, steps={})",
            self.id, self.name, self.status, self.total_steps
        )
    }
}

// ---------------------------------------------------------------------------
// LuaAsync — non-blocking multi-coroutine scheduler
// ---------------------------------------------------------------------------

/// A simple non-blocking scheduler that runs multiple Lua coroutines in
/// a round-robin fashion, processing one step per coroutine per tick.
pub struct LuaAsync {
    /// Ready-to-run coroutines.
    ready_queue: VecDeque<LuaCoroutine>,
    /// Coroutines that have completed (returned or failed).
    finished: Vec<LuaCoroutine>,
    /// Monotonically increasing ID counter.
    next_id: u64,
}

impl LuaAsync {
    /// Create a new scheduler.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
            finished: Vec::new(),
            next_id: 1,
        }
    }

    /// Spawn a new coroutine from a Lua script string.
    /// Returns the ID assigned to the coroutine.
    pub fn spawn(&mut self, name: impl Into<String>, script: impl Into<String>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let coro = LuaCoroutine::new(id, name, script);
        self.ready_queue.push_back(coro);
        id
    }

    /// Spawn a coroutine with a pre-configured step limit.
    pub fn spawn_with_steps(
        &mut self,
        name: impl Into<String>,
        script: impl Into<String>,
        steps: u64,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let coro = LuaCoroutine::new(id, name, script).with_steps_per_resume(steps);
        self.ready_queue.push_back(coro);
        id
    }

    /// Run one scheduling tick: resume each ready coroutine once.
    /// Returns the number of coroutines still alive after this tick.
    pub fn tick(&mut self) -> usize {
        let count = self.ready_queue.len();
        for _ in 0..count {
            if let Some(mut coro) = self.ready_queue.pop_front() {
                let result = coro.resume(None);
                if result.is_finished() {
                    self.finished.push(coro);
                } else {
                    self.ready_queue.push_back(coro);
                }
            }
        }
        self.ready_queue.len()
    }

    /// Run ticks until all coroutines finish or `max_ticks` is reached.
    /// Returns the number of ticks actually executed.
    pub fn run_to_completion(&mut self, max_ticks: usize) -> usize {
        let mut ticks = 0;
        while !self.ready_queue.is_empty() && ticks < max_ticks {
            self.tick();
            ticks += 1;
        }
        ticks
    }

    /// Return the number of coroutines still running.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.ready_queue.len()
    }

    /// Return the number of finished coroutines.
    #[must_use]
    pub const fn finished_count(&self) -> usize {
        self.finished.len()
    }

    /// Borrow the finished coroutines for inspection.
    #[must_use]
    pub fn finished(&self) -> &[LuaCoroutine] {
        &self.finished
    }

    /// Collect all output from finished coroutines.
    #[must_use]
    pub fn collect_output(&self) -> Vec<String> {
        self.finished
            .iter()
            .flat_map(|c| c.context.output.iter().cloned())
            .collect()
    }

    /// Whether all spawned coroutines have completed.
    #[must_use]
    pub fn all_done(&self) -> bool {
        self.ready_queue.is_empty()
    }
}

impl Default for LuaAsync {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for LuaAsync {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "LuaAsync(active={}, finished={})",
            self.active_count(),
            self.finished_count()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── CoroutineStatus ──────────────────────────────────────────────────────

    #[test]
    fn test_coroutine_status_display() {
        assert_eq!(CoroutineStatus::Suspended.to_string(), "suspended");
        assert_eq!(CoroutineStatus::Running.to_string(), "running");
        assert_eq!(CoroutineStatus::Dead.to_string(), "dead");
        assert_eq!(CoroutineStatus::Failed.to_string(), "failed");
    }

    #[test]
    fn test_coroutine_status_eq() {
        assert_eq!(CoroutineStatus::Dead, CoroutineStatus::Dead);
        assert_ne!(CoroutineStatus::Dead, CoroutineStatus::Suspended);
    }

    // ── YieldValue ───────────────────────────────────────────────────────────

    #[test]
    fn test_yield_value_nil() {
        let yv = YieldValue::nil();
        assert!(matches!(yv.value, LuaValue::Nil));
        assert!(yv.tag.is_none());
    }

    #[test]
    fn test_yield_value_int() {
        let yv = YieldValue::int(42);
        assert_eq!(yv.value.as_int(), Some(42));
    }

    #[test]
    fn test_yield_value_with_tag() {
        let yv = YieldValue::string("hello").with_tag("io");
        assert_eq!(yv.tag, Some("io".to_string()));
    }

    #[test]
    fn test_yield_value_display() {
        let yv = YieldValue::int(7).with_tag("step");
        let s = yv.to_string();
        assert!(s.contains('7'));
        assert!(s.contains("step"));
    }

    // ── ResumeResult ─────────────────────────────────────────────────────────

    #[test]
    fn test_resume_result_yielded_is_ok() {
        let rr = ResumeResult::Yielded(YieldValue::nil());
        assert!(rr.is_ok());
        assert!(!rr.is_finished());
    }

    #[test]
    fn test_resume_result_returned_is_finished() {
        let rr = ResumeResult::Returned(LuaValue::Int(1));
        assert!(rr.is_ok());
        assert!(rr.is_finished());
    }

    #[test]
    fn test_resume_result_error_not_ok() {
        let rr = ResumeResult::Error("oops".into());
        assert!(!rr.is_ok());
        assert!(rr.is_finished());
    }

    #[test]
    fn test_resume_result_yielded_value_accessor() {
        let yv = YieldValue::int(5);
        let rr = ResumeResult::Yielded(yv);
        assert!(rr.yielded_value().is_some());
        assert!(rr.returned_value().is_none());
    }

    // ── LuaCoroutine ─────────────────────────────────────────────────────────

    #[test]
    fn test_coroutine_initial_status_suspended() {
        let coro = LuaCoroutine::new(1, "test", "x = 1");
        assert_eq!(coro.status, CoroutineStatus::Suspended);
        assert!(coro.is_alive());
    }

    #[test]
    fn test_coroutine_simple_script_returns_dead() {
        let mut coro = LuaCoroutine::new(1, "test", "x = 42").with_steps_per_resume(10_000);
        let result = coro.start();
        assert!(result.is_finished());
        assert_eq!(coro.status, CoroutineStatus::Dead);
    }

    #[test]
    fn test_coroutine_dead_cannot_resume() {
        let mut coro = LuaCoroutine::new(1, "test", "x = 1").with_steps_per_resume(10_000);
        coro.start();
        let result = coro.resume(None);
        assert!(!result.is_ok());
    }

    #[test]
    fn test_coroutine_set_global_visible_in_script() {
        let mut coro = LuaCoroutine::new(1, "test", "y = x + 1").with_steps_per_resume(10_000);
        coro.set_global("x", LuaValue::Int(10));
        coro.start();
        let y = coro.context.get("y").as_int();
        assert_eq!(y, Some(11));
    }

    #[test]
    fn test_coroutine_error_script_fails() {
        let mut coro = LuaCoroutine::new(1, "fail", "error(\"bad\")").with_steps_per_resume(10_000);
        let result = coro.start();
        assert!(!result.is_ok());
        assert_eq!(coro.status, CoroutineStatus::Failed);
    }

    #[test]
    fn test_coroutine_total_steps_increment() {
        let mut coro = LuaCoroutine::new(1, "steps", "x = 1 + 2").with_steps_per_resume(10_000);
        coro.start();
        assert!(coro.total_steps > 0);
    }

    // ── LuaAsync ─────────────────────────────────────────────────────────────

    #[test]
    fn test_lua_async_spawn_and_run() {
        let mut sched = LuaAsync::new();
        let _id = sched.spawn("hello", r#"print("hello")"#);
        sched.run_to_completion(100);
        assert!(sched.all_done());
        assert_eq!(sched.finished_count(), 1);
    }

    #[test]
    fn test_lua_async_multiple_coroutines() {
        let mut sched = LuaAsync::new();
        sched.spawn("a", "x = 1");
        sched.spawn("b", "y = 2");
        sched.spawn("c", "z = 3");
        sched.run_to_completion(100);
        assert_eq!(sched.finished_count(), 3);
        assert_eq!(sched.active_count(), 0);
    }

    #[test]
    fn test_lua_async_collect_output() {
        let mut sched = LuaAsync::new();
        sched.spawn("out", r#"print("result")"#);
        sched.run_to_completion(100);
        let output = sched.collect_output();
        assert!(!output.is_empty());
        assert!(output.iter().any(|s| s.contains("result")));
    }

    #[test]
    fn test_lua_async_spawn_returns_unique_ids() {
        let mut sched = LuaAsync::new();
        let id1 = sched.spawn("a", "x = 1");
        let id2 = sched.spawn("b", "y = 2");
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_lua_async_debug_format() {
        let sched = LuaAsync::new();
        let s = format!("{sched:?}");
        assert!(s.contains("LuaAsync"));
    }
}
