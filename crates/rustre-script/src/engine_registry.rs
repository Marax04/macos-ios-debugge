//! Sub-crate engine registry.
//!
//! Wires every concrete scripting-engine adapter sub-crate into the hub so
//! callers can enumerate available engines and construct the primary engine
//! type for each language without depending on the sub-crates directly.

use rustre_script_lua::LuaEngine;
use rustre_script_python::{PythonEngine, PythonScriptEngine};
use rustre_script_rhai::RhaiScriptEngine;

/// Identifies one of the wired scripting engine sub-crates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EngineKind {
    /// `rustre-script-lua` — sandboxed Lua-subset interpreter.
    Lua,
    /// `rustre-script-python` — pure-Rust Python-subset interpreter.
    Python,
    /// `rustre-script-python` — CPython-backed engine via `pyo3`.
    PythonCPython,
    /// `rustre-script-rhai` — Rhai-backed engine.
    Rhai,
}

impl EngineKind {
    /// Short name for this engine, suitable for lookup.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Lua => "lua",
            Self::Python => "python",
            Self::PythonCPython => "python-cpython",
            Self::Rhai => "rhai",
        }
    }

    /// File extensions this engine handles.
    #[must_use]
    pub const fn file_extensions(self) -> &'static [&'static str] {
        match self {
            Self::Lua => &["lua"],
            Self::Python | Self::PythonCPython => &["py"],
            Self::Rhai => &["rhai"],
        }
    }
}

/// A constructed engine instance from one of the wired sub-crates.
pub enum WiredEngine {
    /// `LuaEngine` from `rustre-script-lua`.
    Lua(LuaEngine),
    /// Pure-Rust `PythonEngine` from `rustre-script-python`.
    Python(PythonEngine),
    /// CPython-backed `PythonScriptEngine` from `rustre-script-python`.
    PythonCPython(PythonScriptEngine),
    /// `RhaiScriptEngine` from `rustre-script-rhai`.
    Rhai(RhaiScriptEngine),
}

impl WiredEngine {
    /// Return the `EngineKind` for this concrete instance.
    #[must_use]
    pub const fn kind(&self) -> EngineKind {
        match self {
            Self::Lua(_) => EngineKind::Lua,
            Self::Python(_) => EngineKind::Python,
            Self::PythonCPython(_) => EngineKind::PythonCPython,
            Self::Rhai(_) => EngineKind::Rhai,
        }
    }
}

/// Registry of every scripting engine sub-crate wired into the hub.
///
/// The registry is intentionally `Default`-constructible: it carries no state,
/// just the list of `EngineKind`s known at compile time.
#[derive(Debug, Default, Clone)]
pub struct SubCrateRegistry;

impl SubCrateRegistry {
    /// Create a new registry.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Return every wired engine kind.
    #[must_use]
    pub fn all_kinds(&self) -> Vec<EngineKind> {
        vec![
            EngineKind::Lua,
            EngineKind::Python,
            EngineKind::PythonCPython,
            EngineKind::Rhai,
        ]
    }

    /// Look up an engine kind by its short name.
    #[must_use]
    pub fn find_by_name(&self, name: &str) -> Option<EngineKind> {
        self.all_kinds().into_iter().find(|k| k.name() == name)
    }

    /// Look up an engine kind by file extension.
    #[must_use]
    pub fn find_by_extension(&self, ext: &str) -> Option<EngineKind> {
        self.all_kinds()
            .into_iter()
            .find(|k| k.file_extensions().contains(&ext))
    }

    /// Construct a fresh instance of the requested engine.
    ///
    /// # Errors
    /// Returns an error string if the CPython interpreter (for
    /// `EngineKind::PythonCPython`) cannot be initialised.
    pub fn create(&self, kind: EngineKind) -> Result<WiredEngine, String> {
        Ok(match kind {
            EngineKind::Lua => WiredEngine::Lua(LuaEngine::new()),
            EngineKind::Python => WiredEngine::Python(PythonEngine::new()),
            EngineKind::PythonCPython => WiredEngine::PythonCPython(
                PythonScriptEngine::new().map_err(|e| e.to_string())?,
            ),
            EngineKind::Rhai => WiredEngine::Rhai(RhaiScriptEngine::with_re_api()),
        })
    }
}
