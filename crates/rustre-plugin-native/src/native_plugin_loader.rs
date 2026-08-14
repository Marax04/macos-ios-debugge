// rustre-plugin-native/src/native_plugin_loader.rs
//
// Dynamic loading of `.dll` / `.so` / `.dylib` plugin shared libraries.

use crate::native_abi_bridge::{
    NativeAbiBridge, PLUGIN_REGISTER_SYMBOL, PluginRegisterFn, PluginVTable,
};
use crate::native_symbol_resolver::NativeSymbolResolver;
use libloading::Library;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum NativeLoadError {
    #[error("failed to open shared library {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: libloading::Error,
    },
    #[error("missing entry symbol {symbol:?} in {path}: {source}")]
    MissingEntry {
        path: PathBuf,
        symbol: String,
        #[source]
        source: libloading::Error,
    },
    #[error("plugin {path} returned a null vtable")]
    NullVtable { path: PathBuf },
    #[error("ABI rejected by {path}: {reason}")]
    Abi { path: PathBuf, reason: String },
    #[error("plugin name in {path} is not valid UTF-8")]
    InvalidName { path: PathBuf },
    #[error("plugin with id {id} is already loaded")]
    AlreadyLoaded { id: String },
    #[error("no plugin loaded under id {id}")]
    NotFound { id: String },
}

// ── DylibHandle ──────────────────────────────────────────────────────────────

/// Opaque handle that ties a loaded `Library` to its symbol resolver.
///
/// The handle is reference-counted so the host can share it with the
/// `NativePlugin` value it produces without giving up ownership.  Dropping the
/// final handle unloads the library.
#[derive(Clone)]
pub struct DylibHandle {
    inner: Arc<DylibInner>,
}

struct DylibInner {
    path: PathBuf,
    library: Library,
    resolver: Mutex<NativeSymbolResolver>,
}

impl std::fmt::Debug for DylibHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DylibHandle")
            .field("path", &self.inner.path)
            .finish()
    }
}

impl DylibHandle {
    /// Path the library was loaded from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// Borrow the underlying library for raw symbol access.
    #[must_use]
    pub fn library(&self) -> &Library {
        &self.inner.library
    }

    /// Run a closure with mutable access to the symbol resolver.
    pub fn with_resolver<R>(&self, f: impl FnOnce(&mut NativeSymbolResolver) -> R) -> R {
        let mut guard = self.inner.resolver.lock();
        f(&mut guard)
    }
}

// ── NativePlugin ─────────────────────────────────────────────────────────────

/// Metadata extracted from a loaded plugin's vtable.
#[derive(Debug, Clone)]
pub struct NativePlugin {
    pub id: String,
    pub name: String,
    pub version: String,
    pub path: PathBuf,
    pub handle: DylibHandle,
}

impl NativePlugin {
    /// Unique identifier formed from `<name>@<version>`.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

// ── NativePluginLoader ───────────────────────────────────────────────────────

/// Loads, tracks, and unloads native plugin libraries.
#[derive(Default)]
pub struct NativePluginLoader {
    loaded: parking_lot::Mutex<HashMap<String, NativePlugin>>,
}

impl std::fmt::Debug for NativePluginLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativePluginLoader")
            .field("loaded", &self.loaded.lock().len())
            .finish()
    }
}

impl NativePluginLoader {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a shared library from disk, invoke its `rustre_plugin_register`
    /// entry, validate the returned vtable, and track the plugin under its
    /// `<name>@<version>` id.
    ///
    /// # Errors
    ///
    /// Returns a [`NativeLoadError`] describing the failure mode.
    pub fn load(&self, path: impl AsRef<Path>) -> Result<NativePlugin, NativeLoadError> {
        let path = path.as_ref().to_path_buf();

        // SAFETY: loading arbitrary native code is inherently unsafe; the
        // caller is responsible for trusting the path.
        let library = unsafe { Library::new(&path) }.map_err(|e| NativeLoadError::Open {
            path: path.clone(),
            source: e,
        })?;

        let register: libloading::Symbol<'_, PluginRegisterFn> =
            unsafe { library.get(PLUGIN_REGISTER_SYMBOL) }.map_err(|e| {
                NativeLoadError::MissingEntry {
                    path: path.clone(),
                    symbol: String::from_utf8_lossy(PLUGIN_REGISTER_SYMBOL).into_owned(),
                    source: e,
                }
            })?;

        let vtable_ptr = unsafe { (*register)() };
        if vtable_ptr.is_null() {
            return Err(NativeLoadError::NullVtable { path });
        }
        let vtable: &PluginVTable = unsafe { &*vtable_ptr };
        NativeAbiBridge::validate_vtable(vtable)
            .map_err(|reason| NativeLoadError::Abi { path: path.clone(), reason })?;

        let name = unsafe { NativeAbiBridge::read_cstr(vtable.name) }
            .ok_or_else(|| NativeLoadError::InvalidName { path: path.clone() })?
            .to_string();
        // version is also untrusted FFI input; propagate as InvalidName rather
        // than silently falling back to a placeholder, so callers cannot be
        // deceived by a plugin that provides a non-UTF-8 version string.
        let version = unsafe { NativeAbiBridge::read_cstr(vtable.version) }
            .ok_or_else(|| NativeLoadError::InvalidName { path: path.clone() })?
            .to_string();
        let id = format!("{name}@{version}");

        // The symbol borrow (`register`) is released when it goes out of scope
        // below; no explicit drop needed.
        let handle = DylibHandle {
            inner: Arc::new(DylibInner {
                path: path.clone(),
                library,
                resolver: Mutex::new(NativeSymbolResolver::new()),
            }),
        };

        let plugin = NativePlugin {
            id: id.clone(),
            name,
            version,
            path,
            handle,
        };

        {
            let mut loaded = self.loaded.lock();
            if loaded.contains_key(&id) {
                return Err(NativeLoadError::AlreadyLoaded { id });
            }
            loaded.insert(id, plugin.clone());
        }
        Ok(plugin)
    }

    /// Look up a previously-loaded plugin by id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<NativePlugin> {
        self.loaded.lock().get(id).cloned()
    }

    /// Remove a plugin from the loader; the underlying library is unloaded
    /// once all outstanding [`DylibHandle`] clones are dropped.
    ///
    /// # Errors
    ///
    /// Returns [`NativeLoadError::NotFound`] when no such plugin exists.
    pub fn unload(&self, id: &str) -> Result<(), NativeLoadError> {
        let removed = {
            let mut loaded = self.loaded.lock();
            loaded.remove(id)
        };
        removed.ok_or_else(|| NativeLoadError::NotFound { id: id.to_string() })?;
        Ok(())
    }

    /// Number of currently-tracked plugins.
    #[must_use]
    pub fn count(&self) -> usize {
        self.loaded.lock().len()
    }

    /// Sorted list of currently-loaded plugin ids.
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
    fn loader_starts_empty() {
        let l = NativePluginLoader::new();
        assert_eq!(l.count(), 0);
        assert!(l.ids().is_empty());
    }

    #[test]
    fn missing_path_errors() {
        let l = NativePluginLoader::new();
        let err = l
            .load("/definitely/not/here/plugin.dll")
            .expect_err("should fail");
        match err {
            NativeLoadError::Open { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn unload_unknown_errors() {
        let l = NativePluginLoader::new();
        assert!(matches!(
            l.unload("nope@0.0.0").unwrap_err(),
            NativeLoadError::NotFound { .. }
        ));
    }

    #[test]
    fn get_unknown_none() {
        let l = NativePluginLoader::new();
        assert!(l.get("missing@0.0.0").is_none());
    }
}
