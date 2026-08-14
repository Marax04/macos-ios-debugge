// rustre-plugin-lua/src/lua_api_provider.rs
//
// Exposes host-side API surfaces to Lua scripts.

use mlua::{Function, Lua, Table};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

// ── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Lua error: {0}")]
    Lua(#[from] mlua::Error),
    #[error("API '{0}' already registered")]
    Duplicate(String),
}

// ── ApiFunction ──────────────────────────────────────────────────────────────

/// A Rust callback that Lua code can invoke.
pub type ApiCallback =
    Arc<dyn Fn(&Lua, Vec<mlua::Value>) -> mlua::Result<mlua::Value> + Send + Sync + 'static>;

/// A single host-exposed function plus minimal documentation.
#[derive(Clone)]
pub struct ApiFunction {
    pub name: String,
    pub doc: String,
    pub callback: ApiCallback,
}

impl std::fmt::Debug for ApiFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiFunction")
            .field("name", &self.name)
            .field("doc", &self.doc)
            .finish_non_exhaustive()
    }
}

impl ApiFunction {
    /// Construct a new entry from a closure.
    pub fn new<F>(name: impl Into<String>, doc: impl Into<String>, f: F) -> Self
    where
        F: Fn(&Lua, Vec<mlua::Value>) -> mlua::Result<mlua::Value> + Send + Sync + 'static,
    {
        Self {
            name: name.into(),
            doc: doc.into(),
            callback: Arc::new(f),
        }
    }
}

// ── ApiTable ─────────────────────────────────────────────────────────────────

/// A namespace of related API functions, exposed as a single Lua table.
#[derive(Debug, Clone, Default)]
pub struct ApiTable {
    pub name: String,
    pub functions: Vec<ApiFunction>,
}

impl ApiTable {
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            functions: Vec::new(),
        }
    }

    /// Append a function to the table.
    #[must_use]
    pub fn with_function(mut self, f: ApiFunction) -> Self {
        self.functions.push(f);
        self
    }
}

// ── LuaApiProvider ───────────────────────────────────────────────────────────

/// Installs host-defined API tables into a Lua VM under the global
/// `rustre` namespace.
#[derive(Default)]
pub struct LuaApiProvider {
    tables: Mutex<HashMap<String, ApiTable>>,
}

impl std::fmt::Debug for LuaApiProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LuaApiProvider")
            .field("tables", &self.tables.lock().len())
            .finish()
    }
}

impl LuaApiProvider {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new API table.
    ///
    /// # Errors
    ///
    /// Returns [`ApiError::Duplicate`] when an identically-named table is
    /// already registered.
    pub fn register_table(&self, table: ApiTable) -> Result<(), ApiError> {
        {
            let mut guard = self.tables.lock();
            if guard.contains_key(&table.name) {
                return Err(ApiError::Duplicate(table.name));
            }
            guard.insert(table.name.clone(), table);
        }
        Ok(())
    }

    /// Install all registered tables into `lua` under `rustre.<table>.<fn>`.
    ///
    /// # Errors
    ///
    /// Forwards any `mlua::Error` raised while building Lua tables.
    pub fn install(&self, lua: &Lua) -> Result<(), ApiError> {
        let root: Table = lua.create_table()?;
        for (name, table) in self.tables.lock().iter() {
            let sub: Table = lua.create_table()?;
            for func in &table.functions {
                let cb = func.callback.clone();
                let f: Function = lua.create_function(move |l, args: mlua::Variadic<mlua::Value>| {
                    let v: Vec<mlua::Value> = args.into_iter().collect();
                    cb(l, v)
                })?;
                sub.set(func.name.as_str(), f)?;
            }
            root.set(name.as_str(), sub)?;
        }
        lua.globals().set("rustre", root)?;
        Ok(())
    }

    /// Number of registered tables.
    #[must_use]
    pub fn table_count(&self) -> usize {
        self.tables.lock().len()
    }

    /// Sorted list of registered table names.
    #[must_use]
    pub fn table_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.tables.lock().keys().cloned().collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_provider() {
        let p = LuaApiProvider::new();
        assert_eq!(p.table_count(), 0);
    }

    #[test]
    fn register_and_install() {
        let p = LuaApiProvider::new();
        let table = ApiTable::new("math2").with_function(ApiFunction::new(
            "double",
            "Multiply by 2",
            |_, args| {
                let n: i64 = match args.into_iter().next() {
                    Some(mlua::Value::Integer(i)) => i,
                    _ => 0,
                };
                Ok(mlua::Value::Integer(n * 2))
            },
        ));
        p.register_table(table).unwrap();
        let lua = Lua::new();
        p.install(&lua).unwrap();
        let v: i64 = lua.load("return rustre.math2.double(21)").eval().unwrap();
        assert_eq!(v, 42);
    }

    #[test]
    fn duplicate_rejected() {
        let p = LuaApiProvider::new();
        p.register_table(ApiTable::new("ns")).unwrap();
        assert!(matches!(
            p.register_table(ApiTable::new("ns")),
            Err(ApiError::Duplicate(_))
        ));
    }

    #[test]
    fn names_sorted() {
        let p = LuaApiProvider::new();
        p.register_table(ApiTable::new("b")).unwrap();
        p.register_table(ApiTable::new("a")).unwrap();
        assert_eq!(p.table_names(), vec!["a", "b"]);
    }

    #[test]
    fn api_function_debug() {
        let f = ApiFunction::new("x", "y", |_, _| Ok(mlua::Value::Nil));
        let d = format!("{f:?}");
        assert!(d.contains("ApiFunction"));
    }
}
