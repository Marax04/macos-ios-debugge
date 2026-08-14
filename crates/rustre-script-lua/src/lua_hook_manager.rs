//! Lua hook management for the `RustRE` scripting layer.
//!
//! A *hook* is a named Lua callback that fires when a [`HookPoint`] is
//! triggered.  Multiple hooks can be registered for the same point; they are
//! invoked in registration order.  Each hook can be enabled or disabled
//! individually without being removed.
//!
//! # Example
//!
//! ```no_run
//! use mlua::Lua;
//! use rustre_script_lua::lua_hook_manager::{LuaHookManager, HookPoint};
//!
//! let lua = Lua::new();
//! let mut mgr = LuaHookManager::new(&lua).unwrap();
//!
//! mgr.register_hook(
//!     &lua,
//!     HookPoint::OnFunctionEnter,
//!     "log_fn",
//!     r#"function(addr) print("enter", string.format("0x%x", addr)) end"#,
//! ).unwrap();
//!
//! mgr.trigger(&lua, HookPoint::OnFunctionEnter, &[mlua::Value::Integer(0xdeadbeef)])
//!     .unwrap();
//! ```

use std::sync::atomic::{AtomicU64, Ordering};

use mlua::{Function, Lua, Result as LuaResult, Value};

// ─────────────────────────────────────────────────────────────────────────────
// HookPoint
// ─────────────────────────────────────────────────────────────────────────────

/// Well-known points in the analysis pipeline at which hooks can fire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HookPoint {
    /// Fired when a function is entered during analysis.  Argument: address (u64).
    OnFunctionEnter,
    /// Fired when a function is exited.  Argument: address (u64).
    OnFunctionExit,
    /// Fired when a basic block is entered.  Argument: address (u64).
    OnBasicBlockEnter,
    /// Fired when a basic block is exited.  Argument: address (u64).
    OnBasicBlockExit,
    /// Fired when a memory read is observed.  Arguments: address (u64), size (u32).
    OnMemoryRead,
    /// Fired when a memory write is observed.  Arguments: address (u64), size (u32), value (u64).
    OnMemoryWrite,
    /// Fired when a system call is observed.  Argument: syscall number (u64).
    OnSyscall,
    /// Fired when a breakpoint is hit.  Argument: address (u64).
    OnBreakpoint,
    /// Fired when a new module is loaded.  Argument: module name (string).
    OnModuleLoad,
    /// Fired when a module is unloaded.  Argument: module name (string).
    OnModuleUnload,
    /// Fired when binary analysis starts.  No arguments.
    OnAnalysisStart,
    /// Fired when binary analysis ends.  No arguments.
    OnAnalysisEnd,
    /// Fired when an obfuscation pattern is detected.  Argument: pattern name (string).
    OnObfuscationDetected,
    /// A user-defined hook point identified by a string tag.
    Custom,
}

impl HookPoint {
    /// Return a short human-readable name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::OnFunctionEnter => "on_function_enter",
            Self::OnFunctionExit => "on_function_exit",
            Self::OnBasicBlockEnter => "on_basic_block_enter",
            Self::OnBasicBlockExit => "on_basic_block_exit",
            Self::OnMemoryRead => "on_memory_read",
            Self::OnMemoryWrite => "on_memory_write",
            Self::OnSyscall => "on_syscall",
            Self::OnBreakpoint => "on_breakpoint",
            Self::OnModuleLoad => "on_module_load",
            Self::OnModuleUnload => "on_module_unload",
            Self::OnAnalysisStart => "on_analysis_start",
            Self::OnAnalysisEnd => "on_analysis_end",
            Self::OnObfuscationDetected => "on_obfuscation_detected",
            Self::Custom => "custom",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaHook
// ─────────────────────────────────────────────────────────────────────────────

/// A handle to a registered Lua hook callback.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LuaHook {
    /// Opaque numeric id assigned at registration time.
    pub id: u64,
    /// The hook point this hook is registered on.
    pub point: HookPoint,
    /// Optional custom tag for [`HookPoint::Custom`].
    pub custom_tag: Option<String>,
    /// Human-readable name for this hook (useful for debugging).
    pub name: String,
    /// Whether this hook is currently enabled.
    pub enabled: bool,
    /// Number of times this hook has been invoked.
    pub invocation_count: u64,
}

impl LuaHook {
    /// Whether the hook matches a given point (and optional custom tag).
    #[must_use]
    pub fn matches(&self, point: HookPoint, custom_tag: Option<&str>) -> bool {
        if self.point != point {
            return false;
        }
        if point == HookPoint::Custom {
            match (self.custom_tag.as_deref(), custom_tag) {
                (Some(a), Some(b)) => a == b,
                (None, None) => true,
                _ => false,
            }
        } else {
            true
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HookError
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the hook manager.
#[derive(Debug, thiserror::Error)]
pub enum HookError {
    /// A Lua-level error occurred while registering or invoking a hook.
    #[error("lua error: {0}")]
    LuaError(#[from] mlua::Error),
    /// No hook with the given id exists.
    #[error("hook id {0} not found")]
    NotFound(u64),
    /// The Lua expression did not evaluate to a function.
    #[error("hook body did not evaluate to a Lua function")]
    NotAFunction,
}

// ─────────────────────────────────────────────────────────────────────────────
// InvokeResult
// ─────────────────────────────────────────────────────────────────────────────

/// Result of triggering a hook point.
#[derive(Debug, Default, Clone)]
pub struct InvokeResult {
    /// Total number of hooks that were invoked.
    pub invoked: usize,
    /// Number of hooks that errored.
    pub errors: usize,
    /// Error messages from any hooks that failed.
    pub error_messages: Vec<String>,
    /// Whether triggering was aborted early because a hook returned `false`.
    pub aborted: bool,
}

impl InvokeResult {
    /// Whether all hooks completed without error.
    #[must_use]
    pub const fn all_ok(&self) -> bool {
        self.errors == 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal slot
// ─────────────────────────────────────────────────────────────────────────────

struct HookSlot {
    meta: LuaHook,
    /// Key used to look up the stored Lua function in the registry table.
    registry_key: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// LuaHookManager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages a collection of named Lua hook callbacks.
///
/// Hooks are stored in a Lua table in the global environment so that they
/// survive across multiple `load().exec()` calls on the same Lua instance.
pub struct LuaHookManager {
    slots: Vec<HookSlot>,
    next_id: AtomicU64,
    /// Name of the internal Lua table holding callbacks.
    registry_table: String,
}

impl std::fmt::Debug for LuaHookManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LuaHookManager")
            .field("hook_count", &self.slots.len())
            .finish_non_exhaustive()
    }
}

impl LuaHookManager {
    /// Create a new manager and initialise the internal Lua registry table.
    ///
    /// # Errors
    /// Returns a [`HookError`] if the Lua table cannot be created.
    pub fn new(lua: &Lua) -> Result<Self, HookError> {
        let registry_table = "__rustre_hook_registry".to_string();
        let tbl = lua.create_table()?;
        lua.globals().set(registry_table.as_str(), tbl)?;
        Ok(Self {
            slots: Vec::new(),
            next_id: AtomicU64::new(1),
            registry_table,
        })
    }

    /// Register a hook by evaluating `fn_expr` as a Lua function.
    ///
    /// `fn_expr` must be a valid Lua expression that evaluates to a function,
    /// for example `"function(addr) print(addr) end"`.
    ///
    /// Returns the assigned [`LuaHook`] handle.
    ///
    /// # Errors
    /// Returns [`HookError::LuaError`] if `fn_expr` fails to compile,
    /// or [`HookError::NotAFunction`] if it doesn't return a function.
    pub fn register_hook(
        &mut self,
        lua: &Lua,
        point: HookPoint,
        name: &str,
        fn_expr: &str,
    ) -> Result<LuaHook, HookError> {
        self.register_hook_with_tag(lua, point, None, name, fn_expr)
    }

    /// Register a hook for a [`HookPoint::Custom`] point with `tag`.
    ///
    /// # Errors
    /// See [`register_hook`](Self::register_hook).
    pub fn register_custom_hook(
        &mut self,
        lua: &Lua,
        tag: impl Into<String>,
        name: &str,
        fn_expr: &str,
    ) -> Result<LuaHook, HookError> {
        self.register_hook_with_tag(lua, HookPoint::Custom, Some(tag.into()), name, fn_expr)
    }

    fn register_hook_with_tag(
        &mut self,
        lua: &Lua,
        point: HookPoint,
        custom_tag: Option<String>,
        name: &str,
        fn_expr: &str,
    ) -> Result<LuaHook, HookError> {
        // Evaluate the expression.
        let chunk = format!("return {fn_expr}");
        let val: Value = lua.load(&chunk).eval()?;
        let Value::Function(func) = val else { return Err(HookError::NotAFunction) };

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let registry_key = format!("hook_{id}");

        // Store the function in the registry table.
        let tbl: mlua::Table = lua.globals().get(self.registry_table.as_str())?;
        tbl.set(registry_key.as_str(), func)?;

        let meta = LuaHook {
            id,
            point,
            custom_tag,
            name: name.to_string(),
            enabled: true,
            invocation_count: 0,
        };

        let hook_copy = meta.clone();
        self.slots.push(HookSlot { meta, registry_key });
        Ok(hook_copy)
    }

    /// Trigger all enabled hooks registered for `point`.
    ///
    /// `args` are the Lua values passed to each hook.  If a hook returns
    /// `false` (boolean), triggering stops early and `InvokeResult::aborted`
    /// is set.  All other return values are ignored.
    ///
    /// Hook errors are collected into [`InvokeResult`] rather than
    /// propagated, so that a single broken hook cannot block subsequent ones.
    ///
    /// # Errors
    /// Returns a [`HookError::LuaError`] only if the registry table itself
    /// cannot be accessed.
    pub fn trigger(
        &mut self,
        lua: &Lua,
        point: HookPoint,
        args: &[Value],
    ) -> Result<InvokeResult, HookError> {
        self.trigger_tagged(lua, point, None, args)
    }

    /// Trigger hooks for [`HookPoint::Custom`] with the given `tag`.
    ///
    /// # Errors
    /// See [`trigger`](Self::trigger).
    pub fn trigger_custom(
        &mut self,
        lua: &Lua,
        tag: &str,
        args: &[Value],
    ) -> Result<InvokeResult, HookError> {
        self.trigger_tagged(lua, HookPoint::Custom, Some(tag), args)
    }

    fn trigger_tagged(
        &mut self,
        lua: &Lua,
        point: HookPoint,
        tag: Option<&str>,
        args: &[Value],
    ) -> Result<InvokeResult, HookError> {
        let tbl: mlua::Table = lua.globals().get(self.registry_table.as_str())?;
        let mut result = InvokeResult::default();

        for slot in &mut self.slots {
            if !slot.meta.enabled {
                continue;
            }
            if !slot.meta.matches(point, tag) {
                continue;
            }
            let func: Function = match tbl.get(slot.registry_key.as_str()) {
                Ok(f) => f,
                Err(e) => {
                    result.errors += 1;
                    result.error_messages.push(format!(
                        "[{}] failed to load function: {e}",
                        slot.meta.name
                    ));
                    continue;
                }
            };
            let call_result: LuaResult<Value> = func.call(args.to_vec());
            result.invoked += 1;
            slot.meta.invocation_count += 1;
            match call_result {
                Ok(Value::Boolean(false)) => {
                    result.aborted = true;
                    break;
                }
                Ok(_) => {}
                Err(e) => {
                    result.errors += 1;
                    result.error_messages.push(format!(
                        "[{}] runtime error: {e}",
                        slot.meta.name
                    ));
                }
            }
        }
        Ok(result)
    }

    /// Enable or disable a hook by id.
    ///
    /// # Errors
    /// Returns [`HookError::NotFound`] if no hook with `id` is registered.
    pub fn set_enabled(&mut self, id: u64, enabled: bool) -> Result<(), HookError> {
        self.slot_mut(id).map(|s| s.meta.enabled = enabled)
    }

    /// Remove a hook by id, freeing its Lua function from the registry.
    ///
    /// # Errors
    /// Returns [`HookError::NotFound`] if `id` is not registered.
    /// Returns [`HookError::LuaError`] if the Lua registry cannot be updated.
    pub fn remove_hook(&mut self, lua: &Lua, id: u64) -> Result<(), HookError> {
        let pos = self
            .slots
            .iter()
            .position(|s| s.meta.id == id)
            .ok_or(HookError::NotFound(id))?;
        let slot = self.slots.remove(pos);
        let tbl: mlua::Table = lua.globals().get(self.registry_table.as_str())?;
        tbl.set(slot.registry_key.as_str(), Value::Nil)?;
        Ok(())
    }

    /// Remove all hooks for a given point.
    ///
    /// # Errors
    /// Returns [`HookError::LuaError`] if the registry cannot be updated.
    pub fn remove_all_for_point(&mut self, lua: &Lua, point: HookPoint) -> Result<usize, HookError> {
        let tbl: mlua::Table = lua.globals().get(self.registry_table.as_str())?;
        let mut removed = 0;
        let to_remove: Vec<usize> = self
            .slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.meta.point == point)
            .map(|(i, _)| i)
            .collect();
        for i in to_remove.into_iter().rev() {
            let slot = self.slots.remove(i);
            tbl.set(slot.registry_key.as_str(), Value::Nil)?;
            removed += 1;
        }
        Ok(removed)
    }

    /// Retrieve a snapshot of metadata for all registered hooks.
    #[must_use]
    pub fn all_hooks(&self) -> Vec<LuaHook> {
        self.slots.iter().map(|s| s.meta.clone()).collect()
    }

    /// Retrieve metadata for a single hook by id.
    ///
    /// Returns `None` if not found.
    #[must_use]
    pub fn get_hook(&self, id: u64) -> Option<&LuaHook> {
        self.slots.iter().find(|s| s.meta.id == id).map(|s| &s.meta)
    }

    /// Number of registered hooks (enabled or disabled).
    #[must_use]
    pub const fn len(&self) -> usize {
        self.slots.len()
    }

    /// Whether no hooks are registered.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Remove all registered hooks and clear the Lua registry table.
    ///
    /// # Errors
    /// Returns [`HookError::LuaError`] if the registry cannot be cleared.
    pub fn clear(&mut self, lua: &Lua) -> Result<(), HookError> {
        let tbl: mlua::Table = lua.globals().get(self.registry_table.as_str())?;
        for slot in self.slots.drain(..) {
            tbl.set(slot.registry_key.as_str(), Value::Nil)?;
        }
        Ok(())
    }

    fn slot_mut(&mut self, id: u64) -> Result<&mut HookSlot, HookError> {
        self.slots
            .iter_mut()
            .find(|s| s.meta.id == id)
            .ok_or(HookError::NotFound(id))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public convenience
// ─────────────────────────────────────────────────────────────────────────────

/// Register a hook using the [`LuaHookManager`] attached to a Lua instance.
///
/// This creates a temporary manager to expose a simple one-shot API.
/// For persistent use across multiple triggers, keep the manager alive.
///
/// # Errors
/// Returns a [`HookError`] if registration fails.
pub fn register_hook(
    lua: &Lua,
    point: HookPoint,
    name: &str,
    fn_expr: &str,
) -> Result<(LuaHookManager, LuaHook), HookError> {
    let mut mgr = LuaHookManager::new(lua)?;
    let hook = mgr.register_hook(lua, point, name, fn_expr)?;
    Ok((mgr, hook))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_lua() -> Lua {
        Lua::new()
    }

    #[test]
    fn test_register_and_trigger() {
        let lua = make_lua();
        let mut mgr = LuaHookManager::new(&lua).unwrap();
        let hook = mgr
            .register_hook(
                &lua,
                HookPoint::OnFunctionEnter,
                "test_hook",
                "function(addr) end",
            )
            .unwrap();
        assert_eq!(hook.name, "test_hook");
        assert_eq!(hook.point, HookPoint::OnFunctionEnter);
        assert!(hook.enabled);

        let result = mgr
            .trigger(&lua, HookPoint::OnFunctionEnter, &[Value::Integer(0x1000)])
            .unwrap();
        assert_eq!(result.invoked, 1);
        assert_eq!(result.errors, 0);
        assert!(!result.aborted);
    }

    #[test]
    fn test_hook_not_called_for_other_point() {
        let lua = make_lua();
        let mut mgr = LuaHookManager::new(&lua).unwrap();
        mgr.register_hook(
            &lua,
            HookPoint::OnFunctionEnter,
            "fn_hook",
            "function() end",
        )
        .unwrap();
        let result = mgr
            .trigger(&lua, HookPoint::OnFunctionExit, &[])
            .unwrap();
        assert_eq!(result.invoked, 0);
    }

    #[test]
    fn test_multiple_hooks_same_point() {
        let lua = make_lua();
        let mut mgr = LuaHookManager::new(&lua).unwrap();
        mgr.register_hook(&lua, HookPoint::OnBreakpoint, "a", "function() end")
            .unwrap();
        mgr.register_hook(&lua, HookPoint::OnBreakpoint, "b", "function() end")
            .unwrap();
        let result = mgr.trigger(&lua, HookPoint::OnBreakpoint, &[]).unwrap();
        assert_eq!(result.invoked, 2);
    }

    #[test]
    fn test_disabled_hook_not_called() {
        let lua = make_lua();
        let mut mgr = LuaHookManager::new(&lua).unwrap();
        let hook = mgr
            .register_hook(&lua, HookPoint::OnSyscall, "syscall_h", "function() end")
            .unwrap();
        mgr.set_enabled(hook.id, false).unwrap();
        let result = mgr.trigger(&lua, HookPoint::OnSyscall, &[]).unwrap();
        assert_eq!(result.invoked, 0);
    }

    #[test]
    fn test_abort_on_false_return() {
        let lua = make_lua();
        let mut mgr = LuaHookManager::new(&lua).unwrap();
        mgr.register_hook(
            &lua,
            HookPoint::OnMemoryRead,
            "abort_hook",
            "function() return false end",
        )
        .unwrap();
        mgr.register_hook(
            &lua,
            HookPoint::OnMemoryRead,
            "second_hook",
            "function() end",
        )
        .unwrap();
        let result = mgr.trigger(&lua, HookPoint::OnMemoryRead, &[]).unwrap();
        assert!(result.aborted);
        assert_eq!(result.invoked, 1); // only the first hook ran
    }

    #[test]
    fn test_remove_hook() {
        let lua = make_lua();
        let mut mgr = LuaHookManager::new(&lua).unwrap();
        let hook = mgr
            .register_hook(&lua, HookPoint::OnModuleLoad, "rm_hook", "function() end")
            .unwrap();
        assert_eq!(mgr.len(), 1);
        mgr.remove_hook(&lua, hook.id).unwrap();
        assert_eq!(mgr.len(), 0);
    }

    #[test]
    fn test_remove_all_for_point() {
        let lua = make_lua();
        let mut mgr = LuaHookManager::new(&lua).unwrap();
        mgr.register_hook(&lua, HookPoint::OnAnalysisStart, "s1", "function() end")
            .unwrap();
        mgr.register_hook(&lua, HookPoint::OnAnalysisStart, "s2", "function() end")
            .unwrap();
        mgr.register_hook(&lua, HookPoint::OnAnalysisEnd, "e1", "function() end")
            .unwrap();
        let removed = mgr
            .remove_all_for_point(&lua, HookPoint::OnAnalysisStart)
            .unwrap();
        assert_eq!(removed, 2);
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn test_custom_hook_tagged() {
        let lua = make_lua();
        let mut mgr = LuaHookManager::new(&lua).unwrap();
        mgr.register_custom_hook(&lua, "my_event", "custom1", "function() end")
            .unwrap();
        mgr.register_custom_hook(&lua, "other_event", "custom2", "function() end")
            .unwrap();
        let result = mgr
            .trigger_custom(&lua, "my_event", &[])
            .unwrap();
        assert_eq!(result.invoked, 1);
    }

    #[test]
    fn test_not_a_function_error() {
        let lua = make_lua();
        let mut mgr = LuaHookManager::new(&lua).unwrap();
        let result = mgr.register_hook(&lua, HookPoint::OnSyscall, "bad", "42");
        assert!(matches!(result, Err(HookError::NotAFunction)));
    }

    #[test]
    fn test_not_found_error() {
        let mut mgr = LuaHookManager::new(&Lua::new()).unwrap();
        let result = mgr.set_enabled(9999, false);
        assert!(matches!(result, Err(HookError::NotFound(9999))));
    }

    #[test]
    fn test_invocation_count_increments() {
        let lua = make_lua();
        let mut mgr = LuaHookManager::new(&lua).unwrap();
        let h = mgr
            .register_hook(&lua, HookPoint::OnBasicBlockEnter, "cnt", "function() end")
            .unwrap();
        mgr.trigger(&lua, HookPoint::OnBasicBlockEnter, &[]).unwrap();
        mgr.trigger(&lua, HookPoint::OnBasicBlockEnter, &[]).unwrap();
        let meta = mgr.get_hook(h.id).unwrap();
        assert_eq!(meta.invocation_count, 2);
    }

    #[test]
    fn test_hook_runtime_error_collected() {
        let lua = make_lua();
        let mut mgr = LuaHookManager::new(&lua).unwrap();
        mgr.register_hook(
            &lua,
            HookPoint::OnObfuscationDetected,
            "err_hook",
            r#"function() error("oops") end"#,
        )
        .unwrap();
        let result = mgr
            .trigger(&lua, HookPoint::OnObfuscationDetected, &[])
            .unwrap();
        assert_eq!(result.errors, 1);
        assert_eq!(result.invoked, 1);
        assert!(!result.all_ok());
    }

    #[test]
    fn test_clear() {
        let lua = make_lua();
        let mut mgr = LuaHookManager::new(&lua).unwrap();
        mgr.register_hook(&lua, HookPoint::OnAnalysisEnd, "h", "function() end")
            .unwrap();
        mgr.clear(&lua).unwrap();
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_all_hooks_snapshot() {
        let lua = make_lua();
        let mut mgr = LuaHookManager::new(&lua).unwrap();
        mgr.register_hook(&lua, HookPoint::OnFunctionEnter, "a", "function() end")
            .unwrap();
        mgr.register_hook(&lua, HookPoint::OnFunctionExit, "b", "function() end")
            .unwrap();
        let all = mgr.all_hooks();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].name, "a");
        assert_eq!(all[1].name, "b");
    }

    #[test]
    fn test_register_hook_convenience() {
        let lua = make_lua();
        let (mut mgr, hook) =
            register_hook(&lua, HookPoint::OnAnalysisStart, "conv", "function() end").unwrap();
        assert_eq!(hook.point, HookPoint::OnAnalysisStart);
        let r = mgr
            .trigger(&lua, HookPoint::OnAnalysisStart, &[])
            .unwrap();
        assert_eq!(r.invoked, 1);
    }

    #[test]
    fn test_hook_point_name() {
        assert_eq!(HookPoint::OnFunctionEnter.name(), "on_function_enter");
        assert_eq!(HookPoint::Custom.name(), "custom");
    }

    #[test]
    fn test_matches_custom_tag() {
        let hook = LuaHook {
            id: 1,
            point: HookPoint::Custom,
            custom_tag: Some("ev".into()),
            name: "h".into(),
            enabled: true,
            invocation_count: 0,
        };
        assert!(hook.matches(HookPoint::Custom, Some("ev")));
        assert!(!hook.matches(HookPoint::Custom, Some("other")));
        assert!(!hook.matches(HookPoint::OnSyscall, None));
    }
}
