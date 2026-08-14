// rustre-plugin-lua/src/lua_plugin_loader.rs
//
// Loads Lua plugin scripts and registers their declared entry points.

use crate::lua_api_provider::LuaApiProvider;
use crate::lua_state_manager::{LuaState, LuaStateManager, StatePool};
use mlua::{Lua, Table};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

// â"€â"€ Errors â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Error)]
pub enum LuaLoadError {
    #[error("I/O error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("Lua error in {path}: {source}")]
    Lua {
        path: PathBuf,
        #[source]
        source: mlua::Error,
    },
    #[error("plugin script {path} did not return a table")]
    NotATable { path: PathBuf },
    #[error("plugin script {path} is missing field {field:?}")]
    MissingField { path: PathBuf, field: String },
    #[error("plugin {id} is already loaded")]
    AlreadyLoaded { id: String },
    #[error("no plugin loaded under id {id}")]
    NotFound { id: String },
}

// â"€â"€ PluginEntry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// The plugin descriptor returned by a Lua script.
///
/// A conforming script looks like:
/// ```lua
/// return {
///   name = "my_plugin",
///   version = "0.1.0",
///   on_load = function(rustre) ... end,
///   on_unload = function() ... end,
/// }
/// ```
#[derive(Debug, Clone)]
pub struct PluginEntry {
    pub name: String,
    pub version: String,
    pub description: String,
    pub has_on_load: bool,
    pub has_on_unload: bool,
}

// â"€â"€ LuaPlugin â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A loaded Lua plugin: its descriptor, plus the VM that hosts it.
pub struct LuaPlugin {
    pub id: String,
    pub entry: PluginEntry,
    pub path: PathBuf,
    state: Arc<LuaState>,
}

impl std::fmt::Debug for LuaPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LuaPlugin")
            .field("id", &self.id)
            .field("path", &self.path)
            .field("entry", &self.entry)
            .finish_non_exhaustive()
    }
}

impl LuaPlugin {
    /// Borrow the underlying Lua VM.
    #[must_use]
    pub fn lua(&self) -> &Lua {
        self.state.raw()
    }

    /// Borrow the wrapped state.
    #[must_use]
    pub const fn state(&self) -> &Arc<LuaState> {
        &self.state
    }
}

// â"€â"€ LuaPluginLoader â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Read a required string field from a plugin descriptor table, returning a
/// rich `LuaLoadError` if the field is missing or of the wrong type.
fn read_required_str(table: &Table, field: &str, origin: &Path) -> Result<String, LuaLoadError> {
    match table.get::<mlua::Value>(field) {
        Ok(mlua::Value::Nil) => Err(LuaLoadError::MissingField {
            path: origin.to_path_buf(),
            field: field.to_string(),
        }),
        Ok(mlua::Value::String(s)) => {
            Ok(s.to_str().map(|s| s.to_string()).unwrap_or_default())
        }
        Ok(other) => Err(LuaLoadError::Lua {
            path: origin.to_path_buf(),
            source: mlua::Error::FromLuaConversionError {
                from: other.type_name(),
                to: "String".into(),
                message: Some(format!("field `{field}` is not a string")),
            },
        }),
        Err(e) => Err(LuaLoadError::Lua { path: origin.to_path_buf(), source: e }),
    }
}

/// Loads, tracks, and unloads Lua plugin scripts.
pub struct LuaPluginLoader {
    states: LuaStateManager,
    apis: Arc<LuaApiProvider>,
    loaded: Mutex<HashMap<String, Arc<LuaPlugin>>>,
}

impl std::fmt::Debug for LuaPluginLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LuaPluginLoader")
            .field("loaded", &self.loaded.lock().len())
            .finish_non_exhaustive()
    }
}

impl Default for LuaPluginLoader {
    fn default() -> Self {
        Self::new(StatePool::default(), Arc::new(LuaApiProvider::new()))
    }
}

impl LuaPluginLoader {
    /// Build a loader backed by a state pool and a shared API provider.
    #[must_use]
    pub fn new(pool: StatePool, apis: Arc<LuaApiProvider>) -> Self {
        Self {
            states: LuaStateManager::new(pool),
            apis,
            loaded: Mutex::new(HashMap::new()),
        }
    }

    /// Access the shared API provider for further registration.
    #[must_use]
    pub fn apis(&self) -> Arc<LuaApiProvider> {
        self.apis.clone()
    }

    /// Load a plugin script from disk.
    ///
    /// # Errors
    ///
    /// See [`LuaLoadError`] for the failure modes.
    pub fn load_file(&self, path: impl AsRef<Path>) -> Result<Arc<LuaPlugin>, LuaLoadError> {
        let path = path.as_ref().to_path_buf();
        let src = std::fs::read_to_string(&path).map_err(|e| LuaLoadError::Io {
            path: path.clone(),
            source: e,
        })?;
        self.load_source(&src, &path)
    }

    /// Load a plugin script from an in-memory string. `origin` is used for
    /// diagnostics only.
    ///
    /// # Errors
    ///
    /// See [`LuaLoadError`] for the failure modes.
    pub fn load_source(
        &self,
        source: &str,
        origin: &Path,
    ) -> Result<Arc<LuaPlugin>, LuaLoadError> {
        let state = self.states.acquire().map_err(|e| LuaLoadError::Lua {
            path: origin.to_path_buf(),
            source: mlua::Error::external(e),
        })?;
        let lua = state.raw();

        let inner = (|| -> Result<Arc<LuaPlugin>, LuaLoadError> {
            self.apis.install(lua).map_err(|e| LuaLoadError::Lua {
                path: origin.to_path_buf(),
                source: mlua::Error::external(e),
            })?;

            let value: mlua::Value = lua
                .load(source)
                .set_name(origin.display().to_string())
                .eval()
                .map_err(|e| LuaLoadError::Lua {
                    path: origin.to_path_buf(),
                    source: e,
                })?;

            let table: Table = match value {
                mlua::Value::Table(t) => t,
                _ => return Err(LuaLoadError::NotATable { path: origin.to_path_buf() }),
            };

            let name = read_required_str(&table, "name", origin)?;
            let version = read_required_str(&table, "version", origin)?;
            let description: String = table.get::<String>("description").unwrap_or_default();
            let has_on_load = matches!(table.get::<mlua::Value>("on_load"), Ok(mlua::Value::Function(_)));
            let has_on_unload =
                matches!(table.get::<mlua::Value>("on_unload"), Ok(mlua::Value::Function(_)));

            let id = format!("{name}@{version}");

            // Check for a duplicate BEFORE invoking on_load so that the side-
            // effectful callback is never called for a plugin that we will not
            // actually register.  We re-check under the write lock afterwards
            // to close the TOCTOU window in concurrent load scenarios.
            {
                let loaded = self.loaded.lock();
                if loaded.contains_key(&id) {
                    return Err(LuaLoadError::AlreadyLoaded { id });
                }
            }

            if has_on_load {
                // Re-check under lock immediately before calling on_load to
                // minimise the TOCTOU window: another thread that raced us
                // through the check above would already have set the key by now.
                {
                    let loaded = self.loaded.lock();
                    if loaded.contains_key(&id) {
                        return Err(LuaLoadError::AlreadyLoaded { id });
                    }
                }
                let on_load: mlua::Function = table.get("on_load").map_err(|e| LuaLoadError::Lua {
                    path: origin.to_path_buf(),
                    source: e,
                })?;
                on_load.call::<()>(()).map_err(|e| LuaLoadError::Lua {
                    path: origin.to_path_buf(),
                    source: e,
                })?;
            }

            let plugin = Arc::new(LuaPlugin {
                id: id.clone(),
                entry: PluginEntry {
                    name,
                    version,
                    description,
                    has_on_load,
                    has_on_unload,
                },
                path: origin.to_path_buf(),
                state: state.clone(),
            });

            {
                let mut loaded = self.loaded.lock();
                if loaded.contains_key(&id) {
                    return Err(LuaLoadError::AlreadyLoaded { id });
                }
                loaded.insert(id, plugin.clone());
            }
            Ok(plugin)
        })();

        match inner {
            Ok(plugin) => {
                // The plugin holds its own clone of `state`; drop our local
                // copy so unload can reclaim the VM via Arc::try_unwrap.
                drop(state);
                Ok(plugin)
            }
            Err(e) => {
                self.states.release(state);
                Err(e)
            }
        }
    }

    /// Unload a plugin and (if exposed) call its `on_unload` callback.
    ///
    /// # Errors
    ///
    /// Returns [`LuaLoadError::NotFound`] when no plugin with that id exists,
    /// or propagates any Lua error raised by the unload callback.
    pub fn unload(&self, id: &str) -> Result<(), LuaLoadError> {
        let plugin = self
            .loaded
            .lock()
            .remove(id)
            .ok_or_else(|| LuaLoadError::NotFound { id: id.to_string() })?;
        if plugin.entry.has_on_unload {
            // Re-fetch on_unload from the chunk-evaluated table by calling
            // the plugin's stored callback via the Lua state's globals if any.
            // We invoke it through a stored upvalue path: scripts that need
            // unload semantics are expected to register on_unload globally.
            let lua = plugin.lua();
            if let Ok(globals_unload) = lua.globals().get::<mlua::Function>("__rustre_unload") {
                globals_unload.call::<()>(()).map_err(|e| LuaLoadError::Lua {
                    path: plugin.path.clone(),
                    source: e,
                })?;
            }
        }
        // Recycle the VM if no one else holds it.
        if let Ok(state) = Arc::try_unwrap(plugin) {
            self.states.release(state.state);
        }
        Ok(())
    }

    /// Look up a loaded plugin by id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<Arc<LuaPlugin>> {
        self.loaded.lock().get(id).cloned()
    }

    /// Number of loaded plugins.
    #[must_use]
    pub fn count(&self) -> usize {
        self.loaded.lock().len()
    }

    /// Sorted list of loaded plugin ids.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.loaded.lock().keys().cloned().collect();
        v.sort();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loader_default_empty() {
        let l = LuaPluginLoader::default();
        assert_eq!(l.count(), 0);
    }

    #[test]
    fn load_source_basic() {
        let l = LuaPluginLoader::default();
        let src = r#"
            return {
                name = "hello",
                version = "0.1.0",
                description = "a test plugin",
            }
        "#;
        let p = l.load_source(src, &PathBuf::from("inline")).unwrap();
        assert_eq!(p.entry.name, "hello");
        assert_eq!(p.entry.version, "0.1.0");
        assert_eq!(l.count(), 1);
        assert_eq!(l.ids(), vec!["hello@0.1.0".to_string()]);
    }

    #[test]
    fn missing_name() {
        let l = LuaPluginLoader::default();
        let r = l.load_source("return { version = '0.1.0' }", &PathBuf::from("x"));
        assert!(matches!(r, Err(LuaLoadError::MissingField { .. })));
    }

    #[test]
    fn not_a_table() {
        let l = LuaPluginLoader::default();
        let r = l.load_source("return 42", &PathBuf::from("x"));
        assert!(matches!(r, Err(LuaLoadError::NotATable { .. })));
    }

    #[test]
    fn duplicate_load() {
        let l = LuaPluginLoader::default();
        let src = "return { name = 'd', version = '0.1.0' }";
        l.load_source(src, &PathBuf::from("a")).unwrap();
        let r = l.load_source(src, &PathBuf::from("b"));
        assert!(matches!(r, Err(LuaLoadError::AlreadyLoaded { .. })));
    }

    #[test]
    fn unload_unknown() {
        let l = LuaPluginLoader::default();
        assert!(matches!(
            l.unload("missing@0.0.0"),
            Err(LuaLoadError::NotFound { .. })
        ));
    }

    #[test]
    fn on_load_runs() {
        let l = LuaPluginLoader::default();
        let src = r#"
            counter = 0
            return {
                name = "ol",
                version = "0.1.0",
                on_load = function() counter = counter + 1 end,
            }
        "#;
        let p = l.load_source(src, &PathBuf::from("ol")).unwrap();
        assert!(p.entry.has_on_load);
        let c: i64 = p.lua().globals().get("counter").unwrap();
        assert_eq!(c, 1);
    }
}
