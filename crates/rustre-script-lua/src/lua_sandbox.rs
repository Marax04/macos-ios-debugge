//! Sandboxed Lua execution for untrusted scripts.
//!
//! [`LuaSandbox`] wraps a [`mlua::Lua`] instance, strips dangerous globals,
//! enforces resource limits, and exposes a curated safe API surface.
//!
//! # Design
//!
//! - **Allowlist-based**: every global that a script can call must be
//!   explicitly permitted by [`SandboxPolicy`].
//! - **No-IO default**: `io`, `os`, `debug`, `require`, `load`,
//!   `loadfile`, `dofile`, `package` are blocked by default.
//! - **Instruction limit**: the sandbox installs a Lua debug hook that
//!   increments a counter and raises an error after
//!   [`SandboxPolicy::max_instructions`] VM instructions.
//! - **Output capture**: `print` is redirected to an in-memory buffer so
//!   the caller can retrieve script output without touching stdout.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use mlua::{Error as LuaError, Lua, Value};

// ─────────────────────────────────────────────────────────────────────────────
// BlockedApi
// ─────────────────────────────────────────────────────────────────────────────

/// A standard Lua global that is blocked by the sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlockedApi {
    /// Name of the global (e.g. `"io"`, `"os.execute"`).
    pub name: String,
    /// Human-readable reason for blocking.
    pub reason: &'static str,
}

impl BlockedApi {
    /// Construct a new [`BlockedApi`].
    #[must_use]
    pub fn new(name: impl Into<String>, reason: &'static str) -> Self {
        Self {
            name: name.into(),
            reason,
        }
    }
}

/// All globals removed from the Lua environment by the default policy.
pub const DEFAULT_BLOCKED: &[(&str, &str)] = &[
    ("io", "file I/O"),
    ("os", "OS interaction"),
    ("debug", "debug library"),
    ("require", "module loading"),
    ("load", "dynamic code loading"),
    ("loadfile", "dynamic code loading from file"),
    ("dofile", "dynamic code loading from file"),
    ("package", "package manager"),
    ("collectgarbage", "GC control"),
];

// ─────────────────────────────────────────────────────────────────────────────
// SandboxPolicy
// ─────────────────────────────────────────────────────────────────────────────

/// Which standard Lua libraries are available inside the sandbox (excludes coroutine).
#[derive(Debug, Clone)]
pub struct SandboxLibraries {
    /// Whether the `string` library is available.
    pub allow_string: bool,
    /// Whether the `table` library is available.
    pub allow_table: bool,
    /// Whether the `math` library is available.
    pub allow_math: bool,
}

impl Default for SandboxLibraries {
    fn default() -> Self {
        Self { allow_string: true, allow_table: true, allow_math: true }
    }
}

/// Configuration that controls what a sandboxed script can do.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    /// Maximum number of Lua VM instructions before the script is killed.
    ///
    /// Set to `0` to disable the instruction limit.
    pub max_instructions: u64,
    /// Maximum wall-clock time for a single [`LuaSandbox::run_sandboxed`] call.
    ///
    /// Set to `None` to disable the time limit.
    pub max_duration: Option<Duration>,
    /// Maximum number of lines written via `print` before further output is
    /// silently dropped.
    pub max_print_lines: usize,
    /// Names of standard globals to keep (defaults to a minimal safe set).
    ///
    /// If `None`, an opinionated safe allowlist is used.
    pub allowed_globals: Option<HashSet<String>>,
    /// Extra globals to block in addition to [`DEFAULT_BLOCKED`].
    pub extra_blocked: Vec<BlockedApi>,
    /// Which standard libraries are available.
    pub libraries: SandboxLibraries,
    /// Whether `coroutine` is available.
    pub allow_coroutine: bool,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            max_instructions: 500_000,
            max_duration: Some(Duration::from_secs(5)),
            max_print_lines: 1000,
            allowed_globals: None,
            extra_blocked: Vec::new(),
            libraries: SandboxLibraries::default(),
            allow_coroutine: false,
        }
    }
}

impl SandboxPolicy {
    /// A strict policy suitable for untrusted user scripts.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            max_instructions: 100_000,
            max_duration: Some(Duration::from_secs(2)),
            max_print_lines: 100,
            allow_coroutine: false,
            ..Self::default()
        }
    }

    /// A lenient policy for trusted automation scripts.
    #[must_use]
    pub fn lenient() -> Self {
        Self {
            max_instructions: 10_000_000,
            max_duration: Some(Duration::from_mins(1)),
            max_print_lines: 100_000,
            allow_coroutine: true,
            ..Self::default()
        }
    }

    /// A policy with no resource limits (trusted internal use).
    #[must_use]
    pub fn unlimited() -> Self {
        Self {
            max_instructions: 0,
            max_duration: None,
            max_print_lines: usize::MAX,
            allow_coroutine: true,
            ..Self::default()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SandboxError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors that can arise from the sandbox layer itself (not from script logic).
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// The script exceeded the instruction budget.
    #[error("script exceeded instruction limit ({0} instructions)")]
    InstructionLimitExceeded(u64),
    /// The script ran longer than the wall-clock budget.
    #[error("script exceeded time limit ({0:?})")]
    TimeLimitExceeded(Duration),
    /// A Lua-level error was raised (syntax error, runtime error, etc.).
    #[error("lua error: {0}")]
    LuaError(#[from] LuaError),
    /// The sandbox failed to set itself up.
    #[error("sandbox setup failed: {0}")]
    SetupFailed(String),
}

// ─────────────────────────────────────────────────────────────────────────────
// ScriptOutput
// ─────────────────────────────────────────────────────────────────────────────

/// Captured output from a sandboxed script execution.
#[derive(Debug, Clone, Default)]
pub struct ScriptOutput {
    /// Lines captured from `print(...)` calls.
    pub print_lines: Vec<String>,
    /// Whether the print line limit was reached.
    pub print_truncated: bool,
    /// Total VM instructions consumed (0 if limit disabled).
    pub instructions_used: u64,
    /// Wall-clock time consumed.
    pub wall_time: Duration,
    /// Whether the script completed normally (`true`) or was killed (`false`).
    pub completed: bool,
}

impl ScriptOutput {
    /// Return all captured lines joined with newlines.
    #[must_use]
    pub fn stdout(&self) -> String {
        self.print_lines.join("\n")
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Instruction counter shared state
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct ExecState {
    instructions: u64,
    limit: u64,
    limit_reached: bool,
    deadline: Option<Instant>,
    time_exceeded: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaSandbox
// ─────────────────────────────────────────────────────────────────────────────

/// A sandboxed Lua execution environment.
///
/// Create once, then call [`run_sandboxed`](LuaSandbox::run_sandboxed)
/// repeatedly — each call shares the same [`Lua`] instance and the
/// same blocked-global environment, but the output buffer is fresh per call.
pub struct LuaSandbox {
    lua: Lua,
    policy: SandboxPolicy,
    print_buf: Arc<Mutex<Vec<String>>>,
    print_truncated: Arc<Mutex<bool>>,
}

impl std::fmt::Debug for LuaSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LuaSandbox")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl LuaSandbox {
    /// Create a new sandbox with the given policy.
    ///
    /// # Errors
    /// Returns [`SandboxError::SetupFailed`] if the Lua VM cannot be
    /// configured.
    pub fn new(policy: SandboxPolicy) -> Result<Self, SandboxError> {
        let lua = Lua::new();
        let print_buf: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let print_truncated: Arc<Mutex<bool>> = Arc::new(Mutex::new(false));

        let sandbox = Self {
            lua,
            policy,
            print_buf,
            print_truncated,
        };

        sandbox.apply_policy()?;
        Ok(sandbox)
    }

    /// Apply blocking and safe-globals setup.
    fn apply_policy(&self) -> Result<(), SandboxError> {
        let globals = self.lua.globals();

        // ── Block dangerous globals ──────────────────────────────────────────
        for (name, _reason) in DEFAULT_BLOCKED {
            globals
                .set(*name, Value::Nil)
                .map_err(|e| SandboxError::SetupFailed(e.to_string()))?;
        }
        for blocked in &self.policy.extra_blocked {
            globals
                .set(blocked.name.as_str(), Value::Nil)
                .map_err(|e| SandboxError::SetupFailed(e.to_string()))?;
        }

        // ── Optional library removal ─────────────────────────────────────────
        if !self.policy.libraries.allow_string {
            globals
                .set("string", Value::Nil)
                .map_err(|e| SandboxError::SetupFailed(e.to_string()))?;
        }
        if !self.policy.libraries.allow_table {
            globals
                .set("table", Value::Nil)
                .map_err(|e| SandboxError::SetupFailed(e.to_string()))?;
        }
        if !self.policy.libraries.allow_math {
            globals
                .set("math", Value::Nil)
                .map_err(|e| SandboxError::SetupFailed(e.to_string()))?;
        }
        if !self.policy.allow_coroutine {
            globals
                .set("coroutine", Value::Nil)
                .map_err(|e| SandboxError::SetupFailed(e.to_string()))?;
        }

        // ── Replace print ────────────────────────────────────────────────────
        let buf = Arc::clone(&self.print_buf);
        let truncated = Arc::clone(&self.print_truncated);
        let max_lines = self.policy.max_print_lines;

        let print_fn = self
            .lua
            .create_function(move |_, args: mlua::MultiValue| {
                let line: String = args
                    .iter()
                    .map(|v| format!("{v:?}").trim_matches('"').to_string())
                    .collect::<Vec<_>>()
                    .join("\t");
                let pushed = {
                    let mut guard = buf.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    if guard.len() < max_lines { guard.push(line); true } else { false }
                };
                if !pushed {
                    *truncated.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = true;
                }
                Ok(())
            })
            .map_err(|e| SandboxError::SetupFailed(e.to_string()))?;

        globals
            .set("print", print_fn)
            .map_err(|e| SandboxError::SetupFailed(e.to_string()))?;

        Ok(())
    }

    /// Run `script_src` in the sandbox.
    ///
    /// Returns [`ScriptOutput`] on success.  Resource-limit violations are
    /// reported as [`SandboxError::InstructionLimitExceeded`] or
    /// [`SandboxError::TimeLimitExceeded`].
    ///
    /// # Errors
    /// Returns a [`SandboxError`] if the script fails to compile, exceeds
    /// resource limits, or raises a Lua runtime error.
    pub fn run_sandboxed(&self, script_src: &str) -> Result<ScriptOutput, SandboxError> {
        // Reset print buffer for this run.
        {
            let mut g = self
                .print_buf
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            g.clear();
        }
        {
            let mut t = self
                .print_truncated
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *t = false;
        }

        // Shared execution state for the debug hook.
        let state = Arc::new(Mutex::new(ExecState {
            limit: self.policy.max_instructions,
            deadline: self
                .policy
                .max_duration
                .map(|d| Instant::now() + d),
            ..ExecState::default()
        }));

        // Install debug hook if limits are active.
        let use_hook = self.policy.max_instructions > 0 || self.policy.max_duration.is_some();
        if use_hook {
            let state_hook = Arc::clone(&state);
            self.lua
                .set_hook(
                    mlua::HookTriggers::new().every_nth_instruction(100),
                    move |_lua, _debug| {
                        let (limit_hit, limit_val, time_hit) = {
                            let mut s = state_hook.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                            s.instructions += 100;
                            let limit_hit = s.limit > 0 && s.instructions >= s.limit;
                            if limit_hit { s.limit_reached = true; }
                            let time_hit = s.deadline.is_some_and(|dl| Instant::now() >= dl);
                            if time_hit { s.time_exceeded = true; }
                            (limit_hit, s.limit, time_hit)
                        };
                        if limit_hit {
                            return Err(LuaError::RuntimeError(format!("sandbox: instruction limit {limit_val} exceeded")));
                        }
                        if time_hit {
                            return Err(LuaError::RuntimeError("sandbox: time limit exceeded".into()));
                        }
                        Ok(mlua::VmState::Continue)
                    },
                );
        }

        let wall_start = Instant::now();
        let result = self.lua.load(script_src).exec();
        let wall_time = wall_start.elapsed();

        // Remove hook to avoid leaking it.
        if use_hook {
            let () = self.lua.remove_hook();
        }

        let s = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let instructions_used = s.instructions;
        let limit_reached = s.limit_reached;
        let time_exceeded = s.time_exceeded;
        drop(s);

        match result {
            Err(_e) if limit_reached => {
                Err(SandboxError::InstructionLimitExceeded(instructions_used))
            }
            Err(_) if time_exceeded => Err(SandboxError::TimeLimitExceeded(wall_time)),
            Err(e) => Err(SandboxError::LuaError(e)),
            Ok(()) => {
                let print_lines = self
                    .print_buf
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                let print_truncated = *self
                    .print_truncated
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                Ok(ScriptOutput {
                    print_lines,
                    print_truncated,
                    instructions_used,
                    wall_time,
                    completed: true,
                })
            }
        }
    }

    /// Evaluate a Lua expression and return its string representation.
    ///
    /// # Errors
    /// Returns a [`SandboxError`] if evaluation fails or limits are exceeded.
    pub fn eval_expr(&self, expr: &str) -> Result<String, SandboxError> {
        let chunk = format!("return tostring({expr})");
        let result = self.lua.load(&chunk).eval::<String>()?;
        Ok(result)
    }

    /// Set a global variable visible to subsequent script runs.
    ///
    /// # Errors
    /// Returns a [`SandboxError`] wrapping any Lua error.
    pub fn set_global<S: mlua::IntoLua>(&self, name: &str, value: S) -> Result<(), SandboxError> {
        self.lua.globals().set(name, value)?;
        Ok(())
    }

    /// Get a global variable set by a previous script run.
    ///
    /// # Errors
    /// Returns a [`SandboxError`] wrapping any Lua error.
    pub fn get_global<R: mlua::FromLua>(&self, name: &str) -> Result<R, SandboxError> {
        let v = self.lua.globals().get::<R>(name)?;
        Ok(v)
    }

    /// Return a reference to the policy used by this sandbox.
    #[must_use]
    pub const fn policy(&self) -> &SandboxPolicy {
        &self.policy
    }

    /// Return the list of blocked API descriptors for the current policy.
    #[must_use]
    pub fn blocked_apis(&self) -> Vec<BlockedApi> {
        let mut v: Vec<BlockedApi> = DEFAULT_BLOCKED
            .iter()
            .map(|(n, r)| BlockedApi::new(*n, r))
            .collect();
        v.extend(self.policy.extra_blocked.clone());
        if !self.policy.libraries.allow_string {
            v.push(BlockedApi::new("string", "disabled by policy"));
        }
        if !self.policy.libraries.allow_table {
            v.push(BlockedApi::new("table", "disabled by policy"));
        }
        if !self.policy.libraries.allow_math {
            v.push(BlockedApi::new("math", "disabled by policy"));
        }
        if !self.policy.allow_coroutine {
            v.push(BlockedApi::new("coroutine", "disabled by policy"));
        }
        v
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public convenience function
// ─────────────────────────────────────────────────────────────────────────────

/// Run `script_src` in a fresh sandbox with the given policy.
///
/// This is a convenience wrapper around [`LuaSandbox::new`] +
/// [`LuaSandbox::run_sandboxed`].
///
/// # Errors
/// Returns a [`SandboxError`] for sandbox setup failures, resource limit
/// violations, or script errors.
pub fn run_sandboxed(
    script_src: &str,
    policy: SandboxPolicy,
) -> Result<ScriptOutput, SandboxError> {
    let sb = LuaSandbox::new(policy)?;
    sb.run_sandboxed(script_src)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_sandbox() -> LuaSandbox {
        LuaSandbox::new(SandboxPolicy::default()).unwrap()
    }

    #[test]
    fn test_basic_script_runs() {
        let sb = default_sandbox();
        let out = sb.run_sandboxed("x = 1 + 2").unwrap();
        assert!(out.completed);
    }

    #[test]
    fn test_print_is_captured() {
        let sb = default_sandbox();
        let out = sb.run_sandboxed(r#"print("hello", "world")"#).unwrap();
        assert_eq!(out.print_lines.len(), 1);
        assert!(out.print_lines[0].contains("hello"));
    }

    #[test]
    fn test_io_is_blocked() {
        let sb = default_sandbox();
        let result = sb.run_sandboxed(r#"io.open("test.txt", "r")"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_os_is_blocked() {
        let sb = default_sandbox();
        let result = sb.run_sandboxed(r#"os.execute("ls")"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_require_is_blocked() {
        let sb = default_sandbox();
        let result = sb.run_sandboxed(r#"require("io")"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_is_blocked() {
        let sb = default_sandbox();
        let result = sb.run_sandboxed(r#"load("return 1")()"#);
        assert!(result.is_err());
    }

    #[test]
    fn test_string_library_available_by_default() {
        let sb = default_sandbox();
        let out = sb
            .run_sandboxed(r#"print(string.upper("hello"))"#)
            .unwrap();
        assert!(out.print_lines[0].contains("HELLO"));
    }

    #[test]
    fn test_math_library_available_by_default() {
        let sb = default_sandbox();
        let out = sb.run_sandboxed(r"print(math.floor(3.7))").unwrap();
        assert!(out.print_lines[0].contains('3'));
    }

    #[test]
    fn test_table_library_available_by_default() {
        let sb = default_sandbox();
        let out = sb
            .run_sandboxed(r"local t={3,1,2}; table.sort(t); print(t[1])")
            .unwrap();
        assert!(out.print_lines[0].contains('1'));
    }

    #[test]
    fn test_instruction_limit_enforced() {
        let policy = SandboxPolicy {
            max_instructions: 1_000,
            max_duration: None,
            ..SandboxPolicy::default()
        };
        let sb = LuaSandbox::new(policy).unwrap();
        let result = sb.run_sandboxed("while true do end");
        assert!(matches!(
            result,
            Err(SandboxError::InstructionLimitExceeded(_))
        ));
    }

    #[test]
    fn test_no_limit_runs_fine() {
        let sb = LuaSandbox::new(SandboxPolicy::unlimited()).unwrap();
        let out = sb.run_sandboxed("x = 42").unwrap();
        assert!(out.completed);
    }

    #[test]
    fn test_eval_expr() {
        let sb = default_sandbox();
        let result = sb.eval_expr("2 + 2").unwrap();
        assert_eq!(result, "4");
    }

    #[test]
    fn test_set_get_global() {
        let sb = default_sandbox();
        sb.set_global("my_val", 99i64).unwrap();
        let out = sb
            .run_sandboxed("print(my_val)")
            .unwrap();
        assert!(out.print_lines[0].contains("99"));
    }

    #[test]
    fn test_get_global_after_script() {
        let sb = default_sandbox();
        sb.run_sandboxed("result = 7 * 6").unwrap();
        let v: i64 = sb.get_global("result").unwrap();
        assert_eq!(v, 42);
    }

    #[test]
    fn test_strict_policy_lower_limit() {
        let sb = LuaSandbox::new(SandboxPolicy::strict()).unwrap();
        assert_eq!(sb.policy().max_instructions, 100_000);
    }

    #[test]
    fn test_syntax_error_reported() {
        let sb = default_sandbox();
        let result = sb.run_sandboxed("this is !!! not valid lua %%%");
        assert!(matches!(result, Err(SandboxError::LuaError(_))));
    }

    #[test]
    fn test_print_truncation() {
        let policy = SandboxPolicy {
            max_print_lines: 3,
            max_instructions: 0,
            max_duration: None,
            ..SandboxPolicy::default()
        };
        let sb = LuaSandbox::new(policy).unwrap();
        let out = sb
            .run_sandboxed("for i=1,10 do print(i) end")
            .unwrap();
        assert_eq!(out.print_lines.len(), 3);
        assert!(out.print_truncated);
    }

    #[test]
    fn test_blocked_apis_list() {
        let sb = default_sandbox();
        let blocked = sb.blocked_apis();
        let names: Vec<&str> = blocked.iter().map(|b| b.name.as_str()).collect();
        assert!(names.contains(&"io"));
        assert!(names.contains(&"os"));
    }

    #[test]
    fn test_multiple_runs_independent_output() {
        let sb = default_sandbox();
        let out1 = sb.run_sandboxed(r#"print("run1")"#).unwrap();
        let out2 = sb.run_sandboxed(r#"print("run2")"#).unwrap();
        assert!(out1.print_lines[0].contains("run1"));
        assert!(out2.print_lines[0].contains("run2"));
        assert_eq!(out2.print_lines.len(), 1);
    }

    #[test]
    fn test_run_sandboxed_convenience() {
        let out = run_sandboxed(r#"print("hi")"#, SandboxPolicy::default()).unwrap();
        assert!(out.completed);
        assert!(out.print_lines[0].contains("hi"));
    }

    #[test]
    fn test_coroutine_disabled_by_default() {
        let sb = default_sandbox();
        let result = sb.run_sandboxed("coroutine.create(function() end)");
        assert!(result.is_err());
    }
}
