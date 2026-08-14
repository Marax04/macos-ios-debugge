// rustre-plugin-lua/src/lua_state_manager.rs
//
// Pooled Lua VM management.

use mlua::Lua;
use parking_lot::Mutex;
use std::sync::Arc;
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum StateError {
    #[error("Lua error: {0}")]
    Lua(#[from] mlua::Error),
    #[error("state pool exhausted (limit {0})")]
    Exhausted(usize),
}

// ── LuaState ─────────────────────────────────────────────────────────────────

/// A wrapper around a single `mlua::Lua` VM that records simple metadata.
pub struct LuaState {
    lua: Lua,
    id: u64,
}

impl std::fmt::Debug for LuaState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LuaState").field("id", &self.id).finish_non_exhaustive()
    }
}

impl LuaState {
    /// Construct a fresh Lua VM.
    #[must_use]
    pub fn new(id: u64) -> Self {
        Self {
            lua: Lua::new(),
            id,
        }
    }

    /// The id assigned by the pool.
    #[must_use]
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Borrow the underlying `mlua::Lua` for direct API calls.
    #[must_use]
    pub const fn raw(&self) -> &Lua {
        &self.lua
    }

    /// Evaluate `code` and return the chunk's textual result.
    ///
    /// # Errors
    ///
    /// Returns the underlying `mlua::Error` when parsing or execution fails.
    pub fn eval_string(&self, code: &str) -> Result<String, StateError> {
        let value: mlua::Value = self.lua.load(code).eval()?;
        Ok(value_to_string(&value))
    }

    /// Execute `code` for side effects only.
    ///
    /// # Errors
    ///
    /// Returns the underlying `mlua::Error` when parsing or execution fails.
    pub fn exec_string(&self, code: &str) -> Result<(), StateError> {
        self.lua.load(code).exec()?;
        Ok(())
    }
}

fn value_to_string(v: &mlua::Value) -> String {
    match v {
        mlua::Value::Nil => "nil".to_string(),
        mlua::Value::Boolean(b) => b.to_string(),
        mlua::Value::Integer(i) => i.to_string(),
        mlua::Value::Number(n) => n.to_string(),
        mlua::Value::String(s) => s.to_str().map_or_else(
            |_| "<non-utf8 string>".to_string(),
            |c| c.to_string(),
        ),
        other => format!("<{}>", other.type_name()),
    }
}

// ── StatePool ────────────────────────────────────────────────────────────────

/// Configuration controlling how many VMs the pool may keep alive at once.
#[derive(Debug, Clone, Copy)]
pub struct StatePool {
    pub max_states: usize,
}

impl Default for StatePool {
    fn default() -> Self {
        Self { max_states: 8 }
    }
}

// ── LuaStateManager ──────────────────────────────────────────────────────────

/// Manages a pool of `LuaState` instances. Hands out fresh or recycled VMs.
pub struct LuaStateManager {
    config: StatePool,
    available: Mutex<Vec<Arc<LuaState>>>,
    next_id: Mutex<u64>,
    issued: Mutex<usize>,
}

impl std::fmt::Debug for LuaStateManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LuaStateManager")
            .field("max_states", &self.config.max_states)
            .field("available", &self.available.lock().len())
            .field("issued", &*self.issued.lock())
            .finish_non_exhaustive()
    }
}

impl LuaStateManager {
    /// Create a new manager with the given pool configuration.
    #[must_use]
    pub const fn new(config: StatePool) -> Self {
        Self {
            config,
            available: Mutex::new(Vec::new()),
            next_id: Mutex::new(0),
            issued: Mutex::new(0),
        }
    }

    /// Acquire a Lua state — either recycled or freshly constructed.
    ///
    /// # Errors
    ///
    /// Returns [`StateError::Exhausted`] if the pool is at its `max_states`
    /// budget and no recycled state is available.
    pub fn acquire(&self) -> Result<Arc<LuaState>, StateError> {
        // Hold `issued` across the recycled-state path so the cap check and
        // the counter increment are atomic with respect to other threads.
        let mut issued = self.issued.lock();
        let popped = self.available.lock().pop();
        if let Some(state) = popped {
            if *issued >= self.config.max_states {
                // Put the state back and fall through to the exhausted error so
                // the caller sees a consistent failure instead of silently
                // exceeding the configured pool cap.
                self.available.lock().push(state);
            } else {
                *issued += 1;
                return Ok(state);
            }
        }
        if *issued >= self.config.max_states {
            return Err(StateError::Exhausted(self.config.max_states));
        }
        *issued += 1;
        drop(issued);
        let id = {
            let mut id_guard = self.next_id.lock();
            let id = *id_guard;
            *id_guard += 1;
            id
        };
        Ok(Arc::new(LuaState::new(id)))
    }

    /// Return a state to the pool for reuse.  If the state has outstanding
    /// strong references, it is dropped instead.
    pub fn release(&self, state: Arc<LuaState>) {
        // Decrement the issued counter first under a single lock acquisition so
        // we never hold two separate `issued` locks at once (parking_lot mutexes
        // are non-reentrant and the double-lock in the original code would
        // deadlock on the same thread in debug builds).
        let mut issued = self.issued.lock();
        *issued = issued.saturating_sub(1);
        drop(issued);

        // Only park the VM back in the available pool when we are the sole
        // remaining owner and the pool still has capacity.
        if Arc::strong_count(&state) == 1 {
            let mut avail = self.available.lock();
            if avail.len() < self.config.max_states {
                avail.push(state);
            }
        }
    }

    /// How many states are currently checked out.
    #[must_use]
    pub fn issued(&self) -> usize {
        *self.issued.lock()
    }

    /// How many recycled states are sitting idle in the pool.
    #[must_use]
    pub fn idle(&self) -> usize {
        self.available.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_default() {
        let p = StatePool::default();
        assert_eq!(p.max_states, 8);
    }

    #[test]
    fn acquire_release() {
        let mgr = LuaStateManager::new(StatePool::default());
        let s = mgr.acquire().unwrap();
        assert_eq!(mgr.issued(), 1);
        mgr.release(s);
        assert_eq!(mgr.issued(), 0);
        assert_eq!(mgr.idle(), 1);
    }

    #[test]
    fn exhaustion() {
        let mgr = LuaStateManager::new(StatePool { max_states: 1 });
        let _a = mgr.acquire().unwrap();
        assert!(matches!(mgr.acquire(), Err(StateError::Exhausted(1))));
    }

    #[test]
    fn eval_simple() {
        let s = LuaState::new(0);
        assert_eq!(s.eval_string("return 1 + 2").unwrap(), "3");
    }

    #[test]
    fn exec_simple() {
        let s = LuaState::new(0);
        s.exec_string("x = 1").unwrap();
        assert_eq!(s.eval_string("return x").unwrap(), "1");
    }

    #[test]
    fn eval_string_value() {
        let s = LuaState::new(0);
        assert_eq!(s.eval_string("return 'hi'").unwrap(), "hi");
    }

    #[test]
    fn eval_bool() {
        let s = LuaState::new(0);
        assert_eq!(s.eval_string("return true").unwrap(), "true");
    }

    #[test]
    fn eval_nil() {
        let s = LuaState::new(0);
        assert_eq!(s.eval_string("return nil").unwrap(), "nil");
    }

    #[test]
    fn syntax_error() {
        let s = LuaState::new(0);
        assert!(s.eval_string("this is not lua!!!").is_err());
    }
}
