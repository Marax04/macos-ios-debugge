// rustre-plugin-python/src/python_error_handler.rs
//
// Structured error handling for the Python plugin host.

use pyo3::exceptions::{
    PyAttributeError, PyImportError, PyKeyError, PyRuntimeError, PyTypeError, PyValueError,
};
use pyo3::prelude::*;
use pyo3::types::PyTraceback;
use std::fmt;

// ── ErrorContext ─────────────────────────────────────────────────────────────

/// Context describing where a Python error originated, used for diagnostics.
#[derive(Debug, Clone, Default)]
pub struct ErrorContext {
    pub plugin: Option<String>,
    pub script: Option<String>,
    pub function: Option<String>,
}

impl ErrorContext {
    /// Empty context.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Attach a plugin id.
    #[must_use]
    pub fn with_plugin(mut self, plugin: impl Into<String>) -> Self {
        self.plugin = Some(plugin.into());
        self
    }

    /// Attach a script path or identifier.
    #[must_use]
    pub fn with_script(mut self, script: impl Into<String>) -> Self {
        self.script = Some(script.into());
        self
    }

    /// Attach the function name where the error happened.
    #[must_use]
    pub fn with_function(mut self, function: impl Into<String>) -> Self {
        self.function = Some(function.into());
        self
    }
}

impl fmt::Display for ErrorContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::with_capacity(3);
        if let Some(p) = &self.plugin {
            parts.push(format!("plugin={p}"));
        }
        if let Some(s) = &self.script {
            parts.push(format!("script={s}"));
        }
        if let Some(fun) = &self.function {
            parts.push(format!("fn={fun}"));
        }
        if parts.is_empty() {
            write!(f, "<no-context>")
        } else {
            write!(f, "[{}]", parts.join(" "))
        }
    }
}

// ── PyError ──────────────────────────────────────────────────────────────────

/// Categorised mirror of a `PyErr` that can be transferred outside the GIL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PyError {
    Type(String),
    Value(String),
    Key(String),
    Attribute(String),
    Import(String),
    Runtime(String),
    /// Any other exception. The first string is the exception class name; the
    /// second is its message.
    Other { class: String, message: String },
}

impl PyError {
    /// Short kind name for diagnostics.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Type(_) => "TypeError",
            Self::Value(_) => "ValueError",
            Self::Key(_) => "KeyError",
            Self::Attribute(_) => "AttributeError",
            Self::Import(_) => "ImportError",
            Self::Runtime(_) => "RuntimeError",
            Self::Other { .. } => "Other",
        }
    }

    /// Human-readable message body.
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Type(s)
            | Self::Value(s)
            | Self::Key(s)
            | Self::Attribute(s)
            | Self::Import(s)
            | Self::Runtime(s) => s,
            Self::Other { message, .. } => message,
        }
    }
}

impl fmt::Display for PyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other { class, message } => write!(f, "{class}: {message}"),
            other => write!(f, "{}: {}", other.kind(), other.message()),
        }
    }
}

impl std::error::Error for PyError {}

// ── PythonErrorHandler ───────────────────────────────────────────────────────

/// Captures and converts `PyErr` values plus their tracebacks into the
/// language-agnostic [`PyError`].
#[derive(Debug, Default)]
pub struct PythonErrorHandler;

impl PythonErrorHandler {
    /// Convert a live `PyErr` into a [`PyError`], extracting class name and
    /// message text.
    #[must_use]
    pub fn classify(py: Python<'_>, err: &PyErr) -> PyError {
        let message = err.to_string();
        let cls = err.get_type(py).name().map_or_else(
            |_| "Exception".to_string(),
            |n| n.to_string(),
        );
        if err.is_instance_of::<PyTypeError>(py) {
            PyError::Type(message)
        } else if err.is_instance_of::<PyValueError>(py) {
            PyError::Value(message)
        } else if err.is_instance_of::<PyKeyError>(py) {
            PyError::Key(message)
        } else if err.is_instance_of::<PyAttributeError>(py) {
            PyError::Attribute(message)
        } else if err.is_instance_of::<PyImportError>(py) {
            PyError::Import(message)
        } else if err.is_instance_of::<PyRuntimeError>(py) {
            PyError::Runtime(message)
        } else {
            PyError::Other { class: cls, message }
        }
    }

    /// Format the traceback attached to a `PyErr` as a multi-line string.
    /// Returns an empty string when no traceback is present.
    #[must_use]
    pub fn traceback(py: Python<'_>, err: &PyErr) -> String {
        match err.traceback(py) {
            Some(tb) => Self::format_traceback(&tb),
            None => String::new(),
        }
    }

    fn format_traceback(tb: &Bound<'_, PyTraceback>) -> String {
        tb.format().unwrap_or_else(|e| format!("<traceback unavailable: {e}>"))
    }

    /// Convert a [`PyError`] into a fresh `PyErr` of the same class.
    #[must_use]
    pub fn rebuild(err: &PyError) -> PyErr {
        match err {
            PyError::Type(s) => PyTypeError::new_err(s.clone()),
            PyError::Value(s) => PyValueError::new_err(s.clone()),
            PyError::Key(s) => PyKeyError::new_err(s.clone()),
            PyError::Attribute(s) => PyAttributeError::new_err(s.clone()),
            PyError::Import(s) => PyImportError::new_err(s.clone()),
            PyError::Runtime(s) => PyRuntimeError::new_err(s.clone()),
            PyError::Other { class, message } => {
                PyRuntimeError::new_err(format!("{class}: {message}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctx_empty() {
        let c = ErrorContext::empty();
        assert!(c.plugin.is_none());
        assert!(c.script.is_none());
        assert!(c.function.is_none());
        assert!(c.to_string().contains("no-context"));
    }

    #[test]
    fn ctx_builder() {
        let c = ErrorContext::empty()
            .with_plugin("p")
            .with_script("s.py")
            .with_function("f");
        let s = c.to_string();
        assert!(s.contains("plugin=p"));
        assert!(s.contains("script=s.py"));
        assert!(s.contains("fn=f"));
    }

    #[test]
    fn pyerror_kinds() {
        assert_eq!(PyError::Type(String::new()).kind(), "TypeError");
        assert_eq!(PyError::Value(String::new()).kind(), "ValueError");
        assert_eq!(PyError::Key(String::new()).kind(), "KeyError");
        assert_eq!(PyError::Attribute(String::new()).kind(), "AttributeError");
        assert_eq!(PyError::Import(String::new()).kind(), "ImportError");
        assert_eq!(PyError::Runtime(String::new()).kind(), "RuntimeError");
        assert_eq!(
            PyError::Other {
                class: "X".into(),
                message: "y".into()
            }
            .kind(),
            "Other"
        );
    }

    #[test]
    fn classify_value_error() {
        Python::with_gil(|py| {
            let err = PyValueError::new_err("bad value");
            let cls = PythonErrorHandler::classify(py, &err);
            assert!(matches!(cls, PyError::Value(_)));
            assert!(cls.message().contains("bad value"));
        });
    }

    #[test]
    fn classify_runtime_error() {
        Python::with_gil(|py| {
            let err = PyRuntimeError::new_err("boom");
            assert!(matches!(
                PythonErrorHandler::classify(py, &err),
                PyError::Runtime(_)
            ));
        });
    }

    #[test]
    fn classify_type_error() {
        Python::with_gil(|py| {
            let err = PyTypeError::new_err("nope");
            assert!(matches!(
                PythonErrorHandler::classify(py, &err),
                PyError::Type(_)
            ));
        });
    }

    #[test]
    fn rebuild_preserves_kind() {
        Python::with_gil(|py| {
            let original = PyError::Value("x".into());
            let rebuilt = PythonErrorHandler::rebuild(&original);
            let reclassified = PythonErrorHandler::classify(py, &rebuilt);
            assert_eq!(reclassified.kind(), original.kind());
        });
    }

    #[test]
    fn traceback_empty_for_fresh_err() {
        Python::with_gil(|py| {
            let err = PyValueError::new_err("no tb");
            let tb = PythonErrorHandler::traceback(py, &err);
            assert!(tb.is_empty());
        });
    }
}
