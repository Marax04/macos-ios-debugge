//! `rustre-script-python`
//!
//! Two Python execution engines in one crate:
//!
//! 1. **`PythonEngine`** – pure-Rust interpreter (no `CPython` dependency).
//!    Supports a useful subset of Python: variables, arithmetic, conditionals,
//!    loops, lists, dicts, functions, and built-ins.
//!
//! 2. **`PythonScriptEngine`** – CPython-backed engine via [`pyo3`].
//!    Provides `eval`, `exec`, `load_file`, `call_function`, and
//!    `inject_module`.  Also exposes a `rustre` module inside the Python
//!    interpreter with logging, version query, and a stub `BinaryView`.


pub mod ida_compat_api;
pub mod pyo3_bindings;
pub mod python_api;
pub mod python_api_complete;
pub mod python_full_api;
pub mod python_ida_compat;
pub mod python_repl;
pub mod python_sandbox;
pub mod python_stdlib_rustre;
pub mod python_stdlib_stubs;
pub mod python_type_stubs;
pub mod script_sandbox;
pub mod python_re_bindings;

pub use python_type_stubs::{PythonTypeStubs, StubGenerator};

pub use python_full_api::{
    BvBinding, DebugBinding as PyDebugBinding, FuncBinding, PythonFullApi, TypeBinding, YaraBinding,
};

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyModule, PyString, PyTuple};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ═══════════════════════════════════════════════════════════════════════════════
// § A  ScriptError
// ═══════════════════════════════════════════════════════════════════════════════

/// Errors produced by [`PythonScriptEngine`].
#[derive(Debug, Error)]
pub enum ScriptError {
    /// A Python-level exception, captured as its string representation.
    #[error("python error: {0}")]
    Py(String),

    /// An I/O error (e.g. file not found when loading a script).
    #[error("io error: {0}")]
    IoError(String),

    /// Any other error (type conversion, internal logic, etc.).
    #[error("error: {0}")]
    Other(String),
}

impl From<PyErr> for ScriptError {
    fn from(e: PyErr) -> Self {
        Self::Py(e.to_string())
    }
}

impl From<std::io::Error> for ScriptError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e.to_string())
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// § B  PyScriptValue
// ═══════════════════════════════════════════════════════════════════════════════

/// A value that crosses the Rust / Python boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PyScriptValue {
    /// Python `None`.
    None_,
    /// Python `bool`.
    Bool(bool),
    /// Python `int`.
    Int(i64),
    /// Python `float`.
    Float(f64),
    /// Python `str`.
    Str(String),
    /// Python `list` (elements recursively converted).
    List(Vec<Self>),
    /// Python `dict` with string keys (non-string keys are `repr`-converted).
    Dict(Vec<(String, Self)>),
}

impl PyScriptValue {
    /// Return the Python type name of this value.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::None_ => "NoneType",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::Str(_) => "str",
            Self::List(_) => "list",
            Self::Dict(_) => "dict",
        }
    }

    /// Return `true` if this value is `None_`.
    #[must_use]
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None_)
    }

    /// Attempt to extract the inner `bool`.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Attempt to extract the inner `i64`.
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            Self::Bool(b) => Some(i64::from(*b)),
            _ => None,
        }
    }

    /// Attempt to extract the inner `f64`.
    #[must_use]
    pub const fn as_float(&self) -> Option<f64> {
        match self {
            Self::Float(f) => Some(*f),
            Self::Int(i) => Some(*i as f64),
            _ => None,
        }
    }

    /// Attempt to extract the inner `&str`.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    /// Convert a [`pyo3::Bound<'_, PyAny>`] into a `PyScriptValue`.
    #[must_use] 
    pub fn from_py_object(obj: &Bound<'_, PyAny>) -> Self {
        if obj.is_none() {
            return Self::None_;
        }
        if let Ok(b) = obj.downcast::<PyBool>() {
            return Self::Bool(b.is_true());
        }
        if let Ok(i) = obj.downcast::<PyInt>()
            && let Ok(n) = i.extract::<i64>() {
                return Self::Int(n);
            }
        if let Ok(f) = obj.downcast::<PyFloat>()
            && let Ok(n) = f.extract::<f64>() {
                return Self::Float(n);
            }
        if let Ok(s) = obj.downcast::<PyString>()
            && let Ok(text) = s.to_str() {
                return Self::Str(text.to_owned());
            }
        if let Ok(lst) = obj.downcast::<PyList>() {
            let items = lst.iter().map(|item| Self::from_py_object(&item)).collect();
            return Self::List(items);
        }
        if let Ok(dct) = obj.downcast::<PyDict>() {
            let pairs = dct
                .iter()
                .map(|(k, v)| {
                    let key = k
                        .str().map_or_else(|_| format!("{k:?}"), |s| s.to_string());
                    (key, Self::from_py_object(&v))
                })
                .collect();
            return Self::Dict(pairs);
        }
        // Fallback: repr string.
        let repr = obj
            .repr().map_or_else(|_| "<unparseable>".to_owned(), |s| s.to_string());
        Self::Str(repr)
    }

    /// Convert this `PyScriptValue` into a Python object.
    ///
    /// # Errors
    ///
    /// Returns a [`PyErr`] if any element cannot be converted.
    pub fn to_py_object<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        match self {
            Self::None_ => Ok(py.None().into_bound(py).into_any()),
            Self::Bool(b) => Ok(b.into_pyobject(py)?.to_owned().into_any()),
            Self::Int(i) => Ok(i.into_pyobject(py)?.into_any()),
            Self::Float(f) => Ok(f.into_pyobject(py)?.into_any()),
            Self::Str(s) => Ok(s.as_str().into_pyobject(py)?.into_any()),
            Self::List(items) => {
                let lst = PyList::empty(py);
                for item in items {
                    lst.append(item.to_py_object(py)?)?;
                }
                Ok(lst.into_any())
            }
            Self::Dict(pairs) => {
                let dct = PyDict::new(py);
                for (k, v) in pairs {
                    dct.set_item(k.as_str(), v.to_py_object(py)?)?;
                }
                Ok(dct.into_any())
            }
        }
    }
}

impl fmt::Display for PyScriptValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None_ => write!(f, "None"),
            Self::Bool(b) => write!(f, "{}", if *b { "True" } else { "False" }),
            Self::Int(i) => write!(f, "{i}"),
            Self::Float(n) => write!(f, "{n}"),
            Self::Str(s) => write!(f, "{s}"),
            Self::List(l) => {
                write!(f, "[")?;
                for (idx, v) in l.iter().enumerate() {
                    if idx > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{v}")?;
                }
                write!(f, "]")
            }
            Self::Dict(d) => {
                write!(f, "{{")?;
                for (idx, (k, v)) in d.iter().enumerate() {
                    if idx > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{k:?}: {v}")?;
                }
                write!(f, "}}")
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// § C  RustrePyModule  (the `rustre` Python module)
// ═══════════════════════════════════════════════════════════════════════════════

/// Python `BinaryView` class (stub) exposed in the `rustre` module.
#[pyclass(name = "BinaryView")]
#[derive(Debug)]
pub struct BinaryView {
    name: String,
}

#[pymethods]
impl BinaryView {
    /// Return a short informational string about this binary.
    #[must_use] 
    pub fn info(&self) -> String {
        format!("BinaryView(name='{}')", self.name)
    }

    /// Return a placeholder list of function names found in the binary.
    #[must_use] 
    pub fn functions(&self) -> Vec<String> {
        vec![
            "main".to_owned(),
            "sub_1000".to_owned(),
            "sub_2000".to_owned(),
        ]
    }

    /// Return a placeholder list of printable strings found in the binary.
    #[must_use] 
    pub fn strings(&self) -> Vec<String> {
        vec![
            "Hello, World!".to_owned(),
            "/etc/passwd".to_owned(),
            "Copyright 2024".to_owned(),
        ]
    }

    fn __repr__(&self) -> String {
        self.info()
    }
}

/// Build and return the `rustre` Python module.
///
/// Exposed items:
/// - `rustre.log(msg)` – print `[rustre] <msg>` to stdout.
/// - `rustre.version()` – return the crate version string.
/// - `rustre.current_binary()` – return a stub [`BinaryView`].
/// - `rustre.BinaryView` – the class itself.
///
/// # Errors
///
/// Returns a [`PyErr`] if module construction fails.
pub fn create_rustre_module(py: Python<'_>) -> PyResult<Bound<'_, PyModule>> {
    // Item definitions must precede statements to avoid confusing ordering.
    #[pyfunction]
    fn log(msg: &str) {
        println!("[rustre] {msg}");
    }
    #[pyfunction]
    const fn version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }
    #[pyfunction]
    fn current_binary() -> BinaryView {
        BinaryView {
            name: "unknown".to_owned(),
        }
    }

    let m = PyModule::new(py, "rustre")?;

    // rustre.log(msg)
    m.add_function(wrap_pyfunction!(log, &m)?)?;

    // rustre.version()
    m.add_function(wrap_pyfunction!(version, &m)?)?;

    // rustre.current_binary()
    m.add_function(wrap_pyfunction!(current_binary, &m)?)?;

    // rustre.BinaryView class
    m.add_class::<BinaryView>()?;

    Ok(m)
}

// ═══════════════════════════════════════════════════════════════════════════════
// § D  PythonScriptEngine
// ═══════════════════════════════════════════════════════════════════════════════

/// CPython-backed Python script engine.
///
/// Wraps the active `CPython` interpreter via [`pyo3`] and provides a
/// high-level, Rust-idiomatic API for executing Python code.
///
/// # Example
/// ```rust,no_run
/// use rustre_script_python::PythonScriptEngine;
/// let engine = PythonScriptEngine::new().unwrap();
/// let result = engine.eval("1 + 2").unwrap();
/// ```
pub struct PythonScriptEngine {
    /// Captured log messages written via `rustre.log` (placeholder; the
    /// actual log function currently writes to stdout).
    pub log_buffer: std::sync::Mutex<Vec<String>>,
}

impl fmt::Debug for PythonScriptEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PythonScriptEngine").finish_non_exhaustive()
    }
}

impl PythonScriptEngine {
    /// Create a new engine and inject the `rustre` built-in module so that
    /// `import rustre` works inside any Python code executed by this engine.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError`] if the Python interpreter cannot be initialised
    /// or if the `rustre` module cannot be registered.
    pub fn new() -> Result<Self, ScriptError> {
        let engine = Self {
            log_buffer: std::sync::Mutex::new(Vec::new()),
        };

        Python::with_gil(|py| {
            let m = create_rustre_module(py)?;
            let sys = py.import("sys")?;
            let modules: Bound<'_, PyDict> = sys.getattr("modules")?.downcast_into()?;
            modules.set_item("rustre", m)?;
            Ok::<(), PyErr>(())
        })
        .map_err(ScriptError::from)?;

        Ok(engine)
    }

    /// Evaluate a single Python expression and return the result.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError::Py`] on a Python exception.
    pub fn eval(&self, code: &str) -> Result<PyScriptValue, ScriptError> {
        Python::with_gil(|py| -> PyResult<PyScriptValue> {
            let code_cstr = std::ffi::CString::new(code)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            let result = py.eval(code_cstr.as_c_str(), None, None)?;
            Ok(PyScriptValue::from_py_object(&result))
        })
        .map_err(ScriptError::from)
    }

    /// Execute a Python code block (one or more statements).
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError::Py`] on a Python exception.
    pub fn exec(&self, code: &str) -> Result<(), ScriptError> {
        Python::with_gil(|py| -> PyResult<()> {
            let code_cstr = std::ffi::CString::new(code)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            py.run(code_cstr.as_c_str(), None, None)?;
            Ok(())
        })
        .map_err(ScriptError::from)
    }

    /// Load and execute a Python source file.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError::IoError`] if the file cannot be read, or
    /// [`ScriptError::Py`] on a Python exception during execution.
    pub fn load_file(&self, path: &Path) -> Result<(), ScriptError> {
        let code = std::fs::read_to_string(path).map_err(ScriptError::from)?;
        self.exec(&code)
    }

    /// Call a function `func` inside module `module` with `args`.
    ///
    /// The module must be importable (either a standard-library module or one
    /// previously injected via [`inject_module`](Self::inject_module)).
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError::Py`] on import errors or Python exceptions.
    pub fn call_function(
        &self,
        module: &str,
        func: &str,
        args: &[PyScriptValue],
    ) -> Result<PyScriptValue, ScriptError> {
        Python::with_gil(|py| -> PyResult<PyScriptValue> {
            let m = py.import(module)?;
            let f = m.getattr(func)?;
            let py_args: Vec<Bound<'_, PyAny>> = args
                .iter()
                .map(|a| a.to_py_object(py))
                .collect::<PyResult<_>>()?;
            let tuple = PyTuple::new(py, &py_args)?;
            let result = f.call1(tuple)?;
            Ok(PyScriptValue::from_py_object(&result))
        })
        .map_err(ScriptError::from)
    }

    /// Inject a Python module by source code.
    ///
    /// The code is executed in a fresh module namespace, which is then
    /// registered in `sys.modules` under `name`.  Any subsequent
    /// `import <name>` in Python code will find this module.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError::Py`] on Python exceptions during injection.
    pub fn inject_module(&self, name: &str, module_code: &str) -> Result<(), ScriptError> {
        Python::with_gil(|py| {
            let module = PyModule::new(py, name)?;
            let code_cstr = std::ffi::CString::new(module_code)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            py.run(code_cstr.as_c_str(), Some(&module.dict()), None)?;
            let sys = py.import("sys")?;
            let modules: Bound<'_, PyDict> = sys.getattr("modules")?.downcast_into()?;
            modules.set_item(name, module)?;
            Ok::<(), PyErr>(())
        })
        .map_err(ScriptError::from)
    }

    /// Evaluate an expression and attempt to convert the result to `i64`.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError`] if evaluation fails or the result is not
    /// numeric.
    pub fn eval_int(&self, code: &str) -> Result<i64, ScriptError> {
        match self.eval(code)? {
            PyScriptValue::Int(i) => Ok(i),
            PyScriptValue::Bool(b) => Ok(i64::from(b)),
            other => Err(ScriptError::Other(format!(
                "expected int, got {}",
                other.type_name()
            ))),
        }
    }

    /// Evaluate an expression and attempt to convert the result to `f64`.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError`] if evaluation fails or the result is not
    /// numeric.
    pub fn eval_float(&self, code: &str) -> Result<f64, ScriptError> {
        match self.eval(code)? {
            PyScriptValue::Float(f) => Ok(f),
            PyScriptValue::Int(i) => Ok(i as f64),
            other => Err(ScriptError::Other(format!(
                "expected float, got {}",
                other.type_name()
            ))),
        }
    }

    /// Evaluate an expression and attempt to convert the result to `String`.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError`] if evaluation fails or the result is not a
    /// string.
    pub fn eval_str(&self, code: &str) -> Result<String, ScriptError> {
        match self.eval(code)? {
            PyScriptValue::Str(s) => Ok(s),
            other => Err(ScriptError::Other(format!(
                "expected str, got {}",
                other.type_name()
            ))),
        }
    }

    /// Execute code and return all names defined in the resulting local
    /// namespace as a `HashMap<String, PyScriptValue>`.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError::Py`] on Python exceptions.
    pub fn exec_and_get_locals(
        &self,
        code: &str,
    ) -> Result<HashMap<String, PyScriptValue>, ScriptError> {
        Python::with_gil(|py| -> PyResult<HashMap<String, PyScriptValue>> {
            let locals = PyDict::new(py);
            let code_cstr = std::ffi::CString::new(code)
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;
            py.run(code_cstr.as_c_str(), None, Some(&locals))?;
            let mut map = HashMap::new();
            for (k, v) in locals.iter() {
                let key = k
                    .str().map_or_else(|_| format!("{k:?}"), |s| s.to_string());
                map.insert(key, PyScriptValue::from_py_object(&v));
            }
            Ok(map)
        })
        .map_err(ScriptError::from)
    }

    /// Import a module and return its `__name__` attribute as a smoke test.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError::Py`] if the module cannot be imported.
    pub fn import_and_probe(&self, module: &str) -> Result<String, ScriptError> {
        Python::with_gil(|py| -> PyResult<String> {
            let m = py.import(module)?;
            let name: String = m.name()?.extract()?;
            Ok(name)
        })
        .map_err(ScriptError::from)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// § E  Legacy pure-Rust engine types (kept for backward compatibility)
// ═══════════════════════════════════════════════════════════════════════════════

/// Errors produced by the pure-Rust [`PythonEngine`].
#[derive(Debug, Error)]
pub enum PythonError {
    #[error("syntax error at line {line}: {message}")]
    SyntaxError { line: usize, message: String },
    #[error("runtime error: {0}")]
    RuntimeError(String),
    #[error("name error: '{0}' is not defined")]
    NameError(String),
    #[error("type error: {0}")]
    TypeError(String),
    #[error("import error: {0}")]
    ImportError(String),
    #[error("attribute error: {0}")]
    AttributeError(String),
    #[error("index error: {0}")]
    IndexError(String),
    #[error("timeout: exceeded {0} steps")]
    Timeout(u64),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

// ── PyValue ───────────────────────────────────────────────────────────────────

/// A Python value type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PyValue {
    /// Python `None`.
    None,
    /// Boolean.
    Bool(bool),
    /// Integer.
    Int(i64),
    /// Float.
    Float(f64),
    /// String.
    Str(String),
    /// List.
    List(Vec<Self>),
    /// Dictionary (ordered key-value pairs).
    Dict(Vec<(Self, Self)>),
    /// Tuple.
    Tuple(Vec<Self>),
    /// Bytes.
    Bytes(Vec<u8>),
    /// Named function.
    Function(String),
}

/// Convert `f64` to `i64` by truncation, clamping to the valid range first.
/// Extracted as a free function so that `PyValue` does not have `unsafe` methods
/// (which would trigger the `unsafe_derive_deserialize` lint).
fn f64_to_i64_truncating(f: f64) -> i64 {
    let clamped = f.clamp(-9.223_372_036_854_776e18_f64, 9.223_372_036_854_776e18_f64);
    // SAFETY: clamped is finite and within i64 range.
    unsafe { clamped.to_int_unchecked::<i64>() }
}

impl PyValue {
    /// Return the Python type name.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::None => "NoneType",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::Str(_) => "str",
            Self::List(_) => "list",
            Self::Dict(_) => "dict",
            Self::Tuple(_) => "tuple",
            Self::Bytes(_) => "bytes",
            Self::Function(_) => "function",
        }
    }

    /// Return Python truthiness.
    #[must_use]
    pub fn is_truthy(&self) -> bool {
        match self {
            Self::None => false,
            Self::Bool(b) => *b,
            Self::Int(i) => *i != 0,
            Self::Float(f) => *f != 0.0,
            Self::Str(s) => !s.is_empty(),
            Self::List(l) => !l.is_empty(),
            Self::Dict(d) => !d.is_empty(),
            Self::Tuple(t) => !t.is_empty(),
            Self::Bytes(b) => !b.is_empty(),
            Self::Function(_) => true,
        }
    }

    /// Try to extract an integer.
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            Self::Bool(b) => Some(i64::from(*b)),
            Self::Float(f) => Some(f64_to_i64_truncating(*f)),
            _ => None,
        }
    }

    /// Return the length if applicable.
    #[must_use]
    pub const fn len_val(&self) -> Option<usize> {
        match self {
            Self::Str(s) => Some(s.len()),
            Self::List(l) => Some(l.len()),
            Self::Dict(d) => Some(d.len()),
            Self::Tuple(t) => Some(t.len()),
            Self::Bytes(b) => Some(b.len()),
            _ => None,
        }
    }

    /// Return whether this sequence value is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len_val().is_none_or(|n| n == 0)
    }
}

impl fmt::Display for PyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Bool(b) => write!(f, "{}", if *b { "True" } else { "False" }),
            Self::Int(i) => write!(f, "{i}"),
            Self::Float(fl) => write!(f, "{fl}"),
            Self::Str(s) => write!(f, "{s}"),
            Self::List(l) => {
                write!(f, "[")?;
                for (i, v) in l.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{v}")?;
                }
                write!(f, "]")
            }
            Self::Dict(d) => write!(f, "dict[{}]", d.len()),
            Self::Tuple(t) => write!(f, "tuple[{}]", t.len()),
            Self::Bytes(b) => write!(f, "b'...[{}]'", b.len()),
            Self::Function(n) => write!(f, "<function {n}>"),
        }
    }
}

// ── PyScope ───────────────────────────────────────────────────────────────────

/// Python execution scope.
#[derive(Debug, Default, Clone)]
pub struct PyScope {
    /// Local / global variables.
    pub locals: HashMap<String, PyValue>,
    /// Captured output from `print`.
    pub output: Vec<String>,
}

impl PyScope {
    /// Create a new scope with built-ins pre-registered.
    #[must_use]
    pub fn new() -> Self {
        let mut s = Self::default();
        s.setup_builtins();
        s
    }

    /// Set a variable.
    pub fn set(&mut self, name: String, val: PyValue) {
        self.locals.insert(name, val);
    }

    /// Get a variable reference.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&PyValue> {
        self.locals.get(name)
    }

    fn setup_builtins(&mut self) {
        for name in &[
            "print",
            "len",
            "range",
            "str",
            "int",
            "float",
            "type",
            "list",
            "dict",
            "hex",
            "abs",
            "min",
            "max",
            "sum",
            "sorted",
            "reversed",
            "enumerate",
            "zip",
            "bool",
            "tuple",
            "bytes",
            "repr",
            "input",
        ] {
            self.locals
                .insert((*name).to_string(), PyValue::Function((*name).to_string()));
        }
        self.locals.insert("True".to_string(), PyValue::Bool(true));
        self.locals
            .insert("False".to_string(), PyValue::Bool(false));
        self.locals.insert("None".to_string(), PyValue::None);
    }

    /// Return all output joined with newlines.
    #[must_use]
    pub fn output_text(&self) -> String {
        self.output.join("\n")
    }
}

// ── AST ───────────────────────────────────────────────────────────────────────

/// A Python statement node (simplified).
#[derive(Debug, Clone)]
pub enum PyStmt {
    /// Variable assignment: `x = expr`.
    Assign { target: String, value: PyExpr },
    /// Augmented assignment: `x += expr`.
    AugAssign {
        target: String,
        op: AugOp,
        value: PyExpr,
    },
    /// Expression statement (e.g. function call).
    Expr(PyExpr),
    /// If / elif / else.
    If {
        condition: PyExpr,
        then_body: Vec<Self>,
        elif_branches: Vec<(PyExpr, Vec<Self>)>,
        else_body: Option<Vec<Self>>,
    },
    /// While loop.
    While {
        condition: PyExpr,
        body: Vec<Self>,
    },
    /// For loop: `for var in expr`.
    For {
        var: String,
        iter: PyExpr,
        body: Vec<Self>,
    },
    /// Function definition.
    FunctionDef {
        name: String,
        params: Vec<String>,
        body: Vec<Self>,
    },
    /// Return statement.
    Return(Option<PyExpr>),
    /// Break.
    Break,
    /// Continue.
    Continue,
    /// Pass.
    Pass,
    /// Print shorthand (handled via Expr/Call anyway).
    Print(Vec<PyExpr>),
}

/// Augmented assignment operators.
#[derive(Debug, Clone, Copy)]
pub enum AugOp {
    /// `+=`
    Add,
    /// `-=`
    Sub,
    /// `*=`
    Mul,
    /// `/=`
    Div,
    /// `%=`
    Mod,
}

/// A Python expression node.
#[derive(Debug, Clone)]
pub enum PyExpr {
    /// `None` literal.
    None,
    /// `True` literal.
    True,
    /// `False` literal.
    False,
    /// Integer literal.
    Int(i64),
    /// Float literal.
    Float(f64),
    /// String literal.
    Str(String),
    /// Variable reference.
    Var(String),
    /// Binary operation.
    BinOp {
        op: PyBinOp,
        left: Box<Self>,
        right: Box<Self>,
    },
    /// Unary operation.
    UnOp { op: PyUnOp, operand: Box<Self> },
    /// Function call.
    Call { name: String, args: Vec<Self> },
    /// List literal `[...]`.
    List(Vec<Self>),
    /// Dict literal `{k: v, ...}`.
    Dict(Vec<(Self, Self)>),
    /// Tuple literal `(a, b)`.
    Tuple(Vec<Self>),
    /// Index access `obj[idx]`.
    Index { obj: Box<Self>, idx: Box<Self> },
}

/// Python binary operators.
#[derive(Debug, Clone, Copy)]
pub enum PyBinOp {
    /// `+`
    Add,
    /// `-`
    Sub,
    /// `*`
    Mul,
    /// `/`
    Div,
    /// `//`
    FloorDiv,
    /// `%`
    Mod,
    /// `**`
    Pow,
    /// `==`
    Eq,
    /// `!=`
    Ne,
    /// `<`
    Lt,
    /// `<=`
    Le,
    /// `>`
    Gt,
    /// `>=`
    Ge,
    /// `and`
    And,
    /// `or`
    Or,
    /// `in`
    In,
    /// `not in`
    NotIn,
}

/// Python unary operators.
#[derive(Debug, Clone, Copy)]
pub enum PyUnOp {
    /// Arithmetic negation `-x`.
    Neg,
    /// Logical not `not x`.
    Not,
}

// ── Function store ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct PyFn {
    params: Vec<String>,
    body: Vec<PyStmt>,
}

// ── Engine ────────────────────────────────────────────────────────────────────

/// Python execution engine.
pub struct PythonEngine {
    max_steps: u64,
    step_count: u64,
    functions: HashMap<String, PyFn>,
}

fn call_min(args: Vec<PyValue>) -> Result<PyValue, PythonError> {
    if args.is_empty() {
        return Err(PythonError::TypeError("min() requires at least one argument".to_string()));
    }
    if let Some(PyValue::List(l)) = args.first() {
        if l.is_empty() {
            return Err(PythonError::RuntimeError("min() arg is an empty sequence".to_string()));
        }
        return l.iter().try_fold(l[0].clone(), |acc, v| {
            Ok(if py_lt(&acc, v) { acc } else { v.clone() })
        });
    }
    args.into_iter().try_fold(None::<PyValue>, |acc, v| {
        Ok(Some(match acc { None => v, Some(a) => if py_lt(&a, &v) { a } else { v } }))
    }).map(|v| v.unwrap_or(PyValue::None))
}

fn call_max(args: Vec<PyValue>) -> Result<PyValue, PythonError> {
    if args.is_empty() {
        return Err(PythonError::TypeError("max() requires at least one argument".to_string()));
    }
    if let Some(PyValue::List(l)) = args.first() {
        if l.is_empty() {
            return Err(PythonError::RuntimeError("max() arg is an empty sequence".to_string()));
        }
        return l.iter().try_fold(l[0].clone(), |acc, v| {
            Ok(if py_lt(&acc, v) { v.clone() } else { acc })
        });
    }
    args.into_iter().try_fold(None::<PyValue>, |acc, v| {
        Ok(Some(match acc { None => v, Some(a) => if py_lt(&a, &v) { v } else { a } }))
    }).map(|v| v.unwrap_or(PyValue::None))
}

impl PythonEngine {
    /// Create a new engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_steps: 100_000,
            step_count: 0,
            functions: HashMap::new(),
        }
    }

    /// Override the step limit.
    pub const fn set_max_steps(&mut self, n: u64) {
        self.max_steps = n;
    }

    /// Return current step count.
    #[must_use]
    pub const fn step_count(&self) -> u64 {
        self.step_count
    }

    /// Execute a Python script.
    ///
    /// # Errors
    ///
    /// Returns [`PythonError`] on error.
    pub fn execute(&mut self, script: &str, scope: &mut PyScope) -> Result<PyValue, PythonError> {
        self.step_count = 0;
        let stmts = self.parse(script)?;
        self.exec_stmts(&stmts, scope)
    }

    /// Parse a Python script to AST.
    ///
    /// # Errors
    ///
    /// Returns [`PythonError`] on syntax error.
    pub fn parse(&self, script: &str) -> Result<Vec<PyStmt>, PythonError> {
        let mut parser = PyParser::new(script);
        parser.parse_module()
    }

    const fn tick(&mut self) -> Result<(), PythonError> {
        self.step_count += 1;
        if self.step_count > self.max_steps {
            return Err(PythonError::Timeout(self.step_count));
        }
        Ok(())
    }

    fn exec_stmts(
        &mut self,
        stmts: &[PyStmt],
        scope: &mut PyScope,
    ) -> Result<PyValue, PythonError> {
        let mut result = PyValue::None;
        for stmt in stmts {
            self.tick()?;
            result = self.exec_one_stmt(stmt, scope)?;
            // exec_one_stmt returns None normally; early-return signals propagate via `?`.
            if matches!(stmt, PyStmt::Return(_)) {
                return Ok(result);
            }
        }
        Ok(result)
    }

    fn exec_one_stmt(
        &mut self,
        stmt: &PyStmt,
        scope: &mut PyScope,
    ) -> Result<PyValue, PythonError> {
        match stmt {
            PyStmt::Assign { target, value } => {
                let val = self.eval_expr(value, scope)?;
                scope.locals.insert(target.clone(), val);
                Ok(PyValue::None)
            }
            PyStmt::AugAssign { target, op, value } => {
                let old = scope.locals.get(target).cloned().unwrap_or(PyValue::None);
                let rhs = self.eval_expr(value, scope)?;
                let new_val = Self::eval_aug_assign(old, *op, rhs)?;
                scope.locals.insert(target.clone(), new_val);
                Ok(PyValue::None)
            }
            PyStmt::Expr(expr) => self.eval_expr(expr, scope),
            PyStmt::Print(args) => {
                let mut parts = Vec::with_capacity(args.len());
                for a in args {
                    parts.push(self.eval_expr(a, scope)?.to_string());
                }
                scope.output.push(parts.join(" "));
                Ok(PyValue::None)
            }
            PyStmt::If {
                condition,
                then_body,
                elif_branches,
                else_body,
            } => self.exec_if(
                condition,
                then_body,
                elif_branches,
                else_body.as_deref(),
                scope,
            ),
            PyStmt::While { condition, body } => {
                self.exec_while(condition, body, scope)?;
                Ok(PyValue::None)
            }
            PyStmt::For { var, iter, body } => {
                self.exec_for(var, iter, body, scope)?;
                Ok(PyValue::None)
            }
            PyStmt::FunctionDef { name, params, body } => {
                self.functions.insert(
                    name.clone(),
                    PyFn {
                        params: params.clone(),
                        body: body.clone(),
                    },
                );
                scope
                    .locals
                    .insert(name.clone(), PyValue::Function(name.clone()));
                Ok(PyValue::None)
            }
            PyStmt::Return(expr) => {
                let result = if let Some(e) = expr {
                    self.eval_expr(e, scope)?
                } else {
                    PyValue::None
                };
                Ok(result)
            }
            PyStmt::Break => Err(PythonError::RuntimeError("__break__".to_string())),
            PyStmt::Continue => Err(PythonError::RuntimeError("__continue__".to_string())),
            PyStmt::Pass => Ok(PyValue::None),
        }
    }

    fn exec_if(
        &mut self,
        condition: &PyExpr,
        then_body: &[PyStmt],
        elif_branches: &[(PyExpr, Vec<PyStmt>)],
        else_body: Option<&[PyStmt]>,
        scope: &mut PyScope,
    ) -> Result<PyValue, PythonError> {
        let cond = self.eval_expr(condition, scope)?;
        if cond.is_truthy() {
            return self.exec_stmts(then_body, scope);
        }
        for (elif_cond, elif_body) in elif_branches {
            let ec = self.eval_expr(elif_cond, scope)?;
            if ec.is_truthy() {
                return self.exec_stmts(elif_body, scope);
            }
        }
        if let Some(else_b) = else_body {
            return self.exec_stmts(else_b, scope);
        }
        Ok(PyValue::None)
    }

    fn exec_while(
        &mut self,
        condition: &PyExpr,
        body: &[PyStmt],
        scope: &mut PyScope,
    ) -> Result<(), PythonError> {
        loop {
            self.tick()?;
            let cond = self.eval_expr(condition, scope)?;
            if !cond.is_truthy() {
                break;
            }
            match self.exec_stmts(body, scope) {
                Ok(_) => {}
                Err(PythonError::RuntimeError(ref s)) if s == "__break__" => break,
                Err(PythonError::RuntimeError(ref s)) if s == "__continue__" => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn exec_for(
        &mut self,
        var: &str,
        iter: &PyExpr,
        body: &[PyStmt],
        scope: &mut PyScope,
    ) -> Result<(), PythonError> {
        let iterable = self.eval_expr(iter, scope)?;
        let items: Vec<PyValue> = match iterable {
            PyValue::List(l) => l,
            PyValue::Tuple(t) => t,
            PyValue::Str(s) => s.chars().map(|c| PyValue::Str(c.to_string())).collect(),
            _ => vec![],
        };
        'for_loop: for item in items {
            self.tick()?;
            scope.locals.insert(var.to_string(), item);
            match self.exec_stmts(body, scope) {
                Ok(_) => {}
                Err(PythonError::RuntimeError(ref s)) if s == "__break__" => break 'for_loop,
                Err(PythonError::RuntimeError(ref s)) if s == "__continue__" => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    fn eval_aug_assign(old: PyValue, op: AugOp, rhs: PyValue) -> Result<PyValue, PythonError> {
        match (old, rhs, op) {
            (PyValue::Int(a), PyValue::Int(b), AugOp::Add) => Ok(PyValue::Int(a.wrapping_add(b))),
            (PyValue::Int(a), PyValue::Int(b), AugOp::Sub) => Ok(PyValue::Int(a.wrapping_sub(b))),
            (PyValue::Int(a), PyValue::Int(b), AugOp::Mul) => Ok(PyValue::Int(a.wrapping_mul(b))),
            (PyValue::Int(a), PyValue::Int(b), AugOp::Mod) => {
                if b == 0 {
                    Err(PythonError::RuntimeError("modulo by zero".to_string()))
                } else {
                    Ok(PyValue::Int(a % b))
                }
            }
            (PyValue::Int(a), PyValue::Int(b), AugOp::Div) => {
                if b == 0 {
                    Err(PythonError::RuntimeError("division by zero".to_string()))
                } else {
                    Ok(PyValue::Float(a as f64 / b as f64))
                }
            }
            (PyValue::Float(a), PyValue::Float(b), AugOp::Add) => Ok(PyValue::Float(a + b)),
            (PyValue::Float(a), PyValue::Float(b), AugOp::Sub) => Ok(PyValue::Float(a - b)),
            (PyValue::Float(a), PyValue::Float(b), AugOp::Mul) => Ok(PyValue::Float(a * b)),
            (PyValue::Str(a), PyValue::Str(b), AugOp::Add) => Ok(PyValue::Str(a + &b)),
            (a, b, op) => Err(PythonError::TypeError(format!(
                "unsupported augmented assignment {:?} between {} and {}",
                op,
                a.type_name(),
                b.type_name()
            ))),
        }
    }

    fn eval_expr(&mut self, expr: &PyExpr, scope: &mut PyScope) -> Result<PyValue, PythonError> {
        self.tick()?;
        match expr {
            PyExpr::None => Ok(PyValue::None),
            PyExpr::True => Ok(PyValue::Bool(true)),
            PyExpr::False => Ok(PyValue::Bool(false)),
            PyExpr::Int(i) => Ok(PyValue::Int(*i)),
            PyExpr::Float(f) => Ok(PyValue::Float(*f)),
            PyExpr::Str(s) => Ok(PyValue::Str(s.clone())),
            PyExpr::Var(name) => scope
                .locals
                .get(name)
                .cloned()
                .ok_or_else(|| PythonError::NameError(name.clone())),
            PyExpr::BinOp { op, left, right } => {
                let lv = self.eval_expr(left, scope)?;
                let rv = self.eval_expr(right, scope)?;
                Self::eval_binop(*op, lv, rv)
            }
            PyExpr::UnOp { op, operand } => {
                let val = self.eval_expr(operand, scope)?;
                match op {
                    PyUnOp::Neg => match val {
                        PyValue::Int(i) => Ok(PyValue::Int(-i)),
                        PyValue::Float(f) => Ok(PyValue::Float(-f)),
                        _ => Err(PythonError::TypeError(format!(
                            "bad operand type for unary -: '{}'",
                            val.type_name()
                        ))),
                    },
                    PyUnOp::Not => Ok(PyValue::Bool(!val.is_truthy())),
                }
            }
            PyExpr::Call { name, args } => {
                let mut arg_vals = Vec::with_capacity(args.len());
                for a in args {
                    arg_vals.push(self.eval_expr(a, scope)?);
                }
                self.call_py_function(name, arg_vals, scope)
            }
            PyExpr::List(items) => {
                let mut vals = Vec::with_capacity(items.len());
                for item in items {
                    vals.push(self.eval_expr(item, scope)?);
                }
                Ok(PyValue::List(vals))
            }
            PyExpr::Dict(pairs) => {
                let mut d = Vec::with_capacity(pairs.len());
                for (k, v) in pairs {
                    let kv = self.eval_expr(k, scope)?;
                    let vv = self.eval_expr(v, scope)?;
                    d.push((kv, vv));
                }
                Ok(PyValue::Dict(d))
            }
            PyExpr::Tuple(items) => {
                let mut vals = Vec::with_capacity(items.len());
                for item in items {
                    vals.push(self.eval_expr(item, scope)?);
                }
                Ok(PyValue::Tuple(vals))
            }
            PyExpr::Index { obj, idx } => {
                let obj_val = self.eval_expr(obj, scope)?;
                let idx_val = self.eval_expr(idx, scope)?;
                Self::eval_index(obj_val, &idx_val)
            }
        }
    }

    fn eval_index(obj: PyValue, idx: &PyValue) -> Result<PyValue, PythonError> {
        match obj {
            PyValue::List(l) => {
                let i = idx.as_int().ok_or_else(|| {
                    PythonError::TypeError("list indices must be integers".to_string())
                })?;
                let len = i64::try_from(l.len()).unwrap_or(i64::MAX);
                let actual = if i < 0 { len + i } else { i };
                if actual < 0 || actual >= len {
                    Err(PythonError::IndexError(format!(
                        "list index {i} out of range"
                    )))
                } else {
                    Ok(l[usize::try_from(actual).unwrap_or(0)].clone())
                }
            }
            PyValue::Tuple(t) => {
                let i = idx.as_int().ok_or_else(|| {
                    PythonError::TypeError("tuple indices must be integers".to_string())
                })?;
                let len = i64::try_from(t.len()).unwrap_or(i64::MAX);
                let actual = if i < 0 { len + i } else { i };
                if actual < 0 || actual >= len {
                    Err(PythonError::IndexError(format!(
                        "tuple index {i} out of range"
                    )))
                } else {
                    Ok(t[usize::try_from(actual).unwrap_or(0)].clone())
                }
            }
            PyValue::Str(s) => {
                let i = idx.as_int().ok_or_else(|| {
                    PythonError::TypeError("string indices must be integers".to_string())
                })?;
                let chars: Vec<char> = s.chars().collect();
                let len = i64::try_from(chars.len()).unwrap_or(i64::MAX);
                let actual = if i < 0 { len + i } else { i };
                if actual < 0 || actual >= len {
                    Err(PythonError::IndexError(format!(
                        "string index {i} out of range"
                    )))
                } else {
                    Ok(PyValue::Str(
                        chars[usize::try_from(actual).unwrap_or(0)].to_string(),
                    ))
                }
            }
            PyValue::Dict(d) => {
                for (k, v) in &d {
                    if py_value_eq(k, idx) {
                        return Ok(v.clone());
                    }
                }
                Err(PythonError::IndexError(format!("key not found: {idx}")))
            }
            other => Err(PythonError::TypeError(format!(
                "'{}' object is not subscriptable",
                other.type_name()
            ))),
        }
    }

    fn eval_binop(op: PyBinOp, l: PyValue, r: PyValue) -> Result<PyValue, PythonError> {
        // Short-circuit / membership ops.
        match op {
            PyBinOp::And => return Ok(if l.is_truthy() { r } else { l }),
            PyBinOp::Or => return Ok(if l.is_truthy() { l } else { r }),
            PyBinOp::Eq => return Ok(PyValue::Bool(py_value_eq(&l, &r))),
            PyBinOp::Ne => return Ok(PyValue::Bool(!py_value_eq(&l, &r))),
            PyBinOp::In | PyBinOp::NotIn => return Ok(Self::eval_membership(op, &l, &r)),
            _ => {}
        }
        // String/list concatenation.
        if matches!(op, PyBinOp::Add) {
            if let (PyValue::Str(a), PyValue::Str(b)) = (&l, &r) {
                return Ok(PyValue::Str(a.clone() + b));
            }
            if let (PyValue::List(a), PyValue::List(b)) = (l.clone(), r.clone()) {
                let mut combined = a;
                combined.extend(b);
                return Ok(PyValue::List(combined));
            }
        }
        // Numeric operations.
        if let (PyValue::Int(a), PyValue::Int(b)) = (&l, &r) {
            Self::eval_int_op(op, *a, *b)
        } else {
            Self::eval_float_op(op, &l, &r)
        }
    }

    fn eval_membership(op: PyBinOp, l: &PyValue, r: &PyValue) -> PyValue {
        let found = match r {
            PyValue::List(items) | PyValue::Tuple(items) => items.iter().any(|v| py_value_eq(v, l)),
            PyValue::Str(s) => matches!(l, PyValue::Str(sub) if s.contains(sub.as_str())),
            PyValue::Dict(d) => d.iter().any(|(k, _)| py_value_eq(k, l)),
            _ => false,
        };
        PyValue::Bool(if matches!(op, PyBinOp::In) {
            found
        } else {
            !found
        })
    }

    fn eval_int_op(op: PyBinOp, a: i64, b: i64) -> Result<PyValue, PythonError> {
        match op {
            PyBinOp::Add => Ok(PyValue::Int(a.wrapping_add(b))),
            PyBinOp::Sub => Ok(PyValue::Int(a.wrapping_sub(b))),
            PyBinOp::Mul => Ok(PyValue::Int(a.wrapping_mul(b))),
            PyBinOp::Div => {
                if b == 0 {
                    return Err(PythonError::RuntimeError("division by zero".to_string()));
                }
                Ok(PyValue::Float(a as f64 / b as f64))
            }
            PyBinOp::FloorDiv => {
                if b == 0 {
                    return Err(PythonError::RuntimeError("division by zero".to_string()));
                }
                Ok(PyValue::Int(a.div_euclid(b)))
            }
            PyBinOp::Mod => {
                if b == 0 {
                    return Err(PythonError::RuntimeError("modulo by zero".to_string()));
                }
                Ok(PyValue::Int(a.rem_euclid(b)))
            }
            PyBinOp::Pow => Ok(PyValue::Int(
                a.wrapping_pow(u32::try_from(b.unsigned_abs()).unwrap_or(u32::MAX)),
            )),
            PyBinOp::Lt => Ok(PyValue::Bool(a < b)),
            PyBinOp::Le => Ok(PyValue::Bool(a <= b)),
            PyBinOp::Gt => Ok(PyValue::Bool(a > b)),
            PyBinOp::Ge => Ok(PyValue::Bool(a >= b)),
            _ => Err(PythonError::TypeError(format!("unsupported op {op:?}"))),
        }
    }

    fn eval_float_op(op: PyBinOp, l: &PyValue, r: &PyValue) -> Result<PyValue, PythonError> {
        let af = to_float_py(l).ok_or_else(|| {
            PythonError::TypeError(format!(
                "unsupported operand type(s) for arithmetic: '{}' and '{}'",
                l.type_name(),
                r.type_name()
            ))
        })?;
        let bf = to_float_py(r).ok_or_else(|| {
            PythonError::TypeError(format!(
                "unsupported operand type(s) for arithmetic: '{}' and '{}'",
                l.type_name(),
                r.type_name()
            ))
        })?;
        match op {
            PyBinOp::Add => Ok(PyValue::Float(af + bf)),
            PyBinOp::Sub => Ok(PyValue::Float(af - bf)),
            PyBinOp::Mul => Ok(PyValue::Float(af * bf)),
            PyBinOp::Div => {
                if bf == 0.0 {
                    return Err(PythonError::RuntimeError("division by zero".to_string()));
                }
                Ok(PyValue::Float(af / bf))
            }
            PyBinOp::FloorDiv => Ok(PyValue::Float((af / bf).floor())),
            PyBinOp::Mod => Ok(PyValue::Float(af % bf)),
            PyBinOp::Pow => Ok(PyValue::Float(af.powf(bf))),
            PyBinOp::Lt => Ok(PyValue::Bool(af < bf)),
            PyBinOp::Le => Ok(PyValue::Bool(af <= bf)),
            PyBinOp::Gt => Ok(PyValue::Bool(af > bf)),
            PyBinOp::Ge => Ok(PyValue::Bool(af >= bf)),
            _ => Err(PythonError::TypeError(format!("unsupported op {op:?}"))),
        }
    }

    fn call_py_function(
        &mut self,
        name: &str,
        args: Vec<PyValue>,
        scope: &mut PyScope,
    ) -> Result<PyValue, PythonError> {
        if let Some(func) = self.functions.get(name).cloned() {
            let mut saved: Vec<(String, Option<PyValue>)> = Vec::with_capacity(func.params.len());
            for (i, param) in func.params.iter().enumerate() {
                let old = scope.locals.remove(param);
                saved.push((param.clone(), old));
                let val = args.get(i).cloned().unwrap_or(PyValue::None);
                scope.locals.insert(param.clone(), val);
            }
            let result = self.exec_stmts(&func.body.clone(), scope);
            for (k, old) in saved {
                scope.locals.remove(&k);
                if let Some(v) = old {
                    scope.locals.insert(k, v);
                }
            }
            // Convert internal break/continue signals back to RuntimeError.
            match result {
                Ok(v) => Ok(v),
                Err(PythonError::RuntimeError(ref s))
                    if s == "__break__" || s == "__continue__" =>
                {
                    Ok(PyValue::None)
                }
                Err(e) => Err(e),
            }
        } else {
            Self::call_builtin(name, args, scope)
        }
    }

    fn call_builtin(
        name: &str,
        args: Vec<PyValue>,
        scope: &mut PyScope,
    ) -> Result<PyValue, PythonError> {
        match name {
            "print" => {
                scope.output.push(
                    args.iter()
                        .map(std::string::ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" "),
                );
                Ok(PyValue::None)
            }
            "len" => {
                let n = args
                    .first()
                    .and_then(PyValue::len_val)
                    .ok_or_else(|| PythonError::TypeError("object has no len()".to_string()))?;
                Ok(PyValue::Int(i64::try_from(n).unwrap_or(i64::MAX)))
            }
            "range" => Self::builtin_range(&args),
            "str" => Ok(PyValue::Str(
                args.first()
                    .map_or_else(String::new, std::string::ToString::to_string),
            )),
            "int" => match args.first() {
                Some(PyValue::Str(s)) => s
                    .trim()
                    .parse::<i64>()
                    .map(PyValue::Int)
                    .map_err(|_| PythonError::value_error(&format!("invalid literal: {s}"))),
                other => Ok(other
                    .and_then(PyValue::as_int)
                    .map_or(PyValue::Int(0), PyValue::Int)),
            },
            "float" => match args.first() {
                Some(PyValue::Str(s)) => s
                    .trim()
                    .parse::<f64>()
                    .map(PyValue::Float)
                    .map_err(|_| PythonError::value_error(&format!("invalid literal: {s}"))),
                other => Ok(PyValue::Float(other.and_then(to_float_py).unwrap_or(0.0))),
            },
            "bool" => Ok(PyValue::Bool(args.first().is_some_and(PyValue::is_truthy))),
            "type" => Ok(PyValue::Str(
                args.first()
                    .map_or("NoneType", |a| a.type_name())
                    .to_string(),
            )),
            "hex" => Ok(args
                .first()
                .and_then(PyValue::as_int)
                .map_or(PyValue::Str("0x0".to_string()), |i| {
                    PyValue::Str(format!("{i:#x}"))
                })),
            "abs" => match args.first() {
                Some(PyValue::Int(i)) => Ok(PyValue::Int(i.abs())),
                Some(PyValue::Float(f)) => Ok(PyValue::Float(f.abs())),
                _ => Err(PythonError::TypeError(
                    "abs() requires a number".to_string(),
                )),
            },
            "list" => match args.first() {
                Some(PyValue::List(l)) => Ok(PyValue::List(l.clone())),
                Some(PyValue::Tuple(t)) => Ok(PyValue::List(t.clone())),
                Some(PyValue::Str(s)) => Ok(PyValue::List(
                    s.chars().map(|c| PyValue::Str(c.to_string())).collect(),
                )),
                _ => Ok(PyValue::List(vec![])),
            },
            "dict" => Ok(PyValue::Dict(vec![])),
            "tuple" => match args.first() {
                Some(PyValue::List(l)) => Ok(PyValue::Tuple(l.clone())),
                Some(PyValue::Tuple(t)) => Ok(PyValue::Tuple(t.clone())),
                _ => Ok(PyValue::Tuple(vec![])),
            },
            "bytes" => match args.first() {
                Some(PyValue::List(l)) => Ok(PyValue::Bytes(
                    l.iter()
                        .filter_map(|v| v.as_int().and_then(|i| u8::try_from(i).ok()))
                        .collect(),
                )),
                Some(PyValue::Int(n)) => {
                    Ok(PyValue::Bytes(vec![0u8; usize::try_from(*n).unwrap_or(0)]))
                }
                _ => Ok(PyValue::Bytes(vec![])),
            },
            "repr" => Ok(PyValue::Str(format!(
                "{:?}",
                args.first()
                    .map_or("None".to_string(), std::string::ToString::to_string)
            ))),
            "input" => Ok(PyValue::Str(String::new())),
            "min" | "max" | "sum" | "sorted" | "reversed" | "enumerate" | "zip" => {
                Self::call_sequence_builtin(name, args)
            }
            _ => Err(PythonError::NameError(name.to_string())),
        }
    }

    fn builtin_range(args: &[PyValue]) -> Result<PyValue, PythonError> {
        let (start, end, step) = match args.len() {
            1 => (0i64, args[0].as_int().unwrap_or(0), 1i64),
            2 => (
                args[0].as_int().unwrap_or(0),
                args[1].as_int().unwrap_or(0),
                1i64,
            ),
            _ => (
                args.first().and_then(PyValue::as_int).unwrap_or(0),
                args.get(1).and_then(PyValue::as_int).unwrap_or(0),
                args.get(2).and_then(PyValue::as_int).unwrap_or(1),
            ),
        };
        if step == 0 {
            return Err(PythonError::RuntimeError(
                "range() step cannot be zero".to_string(),
            ));
        }
        let mut items = Vec::new();
        let mut i = start;
        loop {
            if (step > 0 && i >= end) || (step < 0 && i <= end) {
                break;
            }
            items.push(PyValue::Int(i));
            i += step;
            if items.len() > 1_000_000 {
                break;
            }
        }
        Ok(PyValue::List(items))
    }

    fn call_sequence_builtin(name: &str, args: Vec<PyValue>) -> Result<PyValue, PythonError> {
        match name {
            "min" => call_min(args),
            "max" => call_max(args),
            "sum" => {
                let items = match args.first() {
                    Some(PyValue::List(l)) => l.clone(),
                    _ => args,
                };
                Ok(PyValue::Int(items.iter().map(|item| item.as_int().unwrap_or(0)).sum()))
            }
            "sorted" => {
                let mut items = match args.first() {
                    Some(PyValue::List(l)) => l.clone(),
                    Some(PyValue::Tuple(t)) => t.clone(),
                    _ => vec![],
                };
                items.sort_by(py_cmp_order);
                Ok(PyValue::List(items))
            }
            "reversed" => {
                let items: Vec<PyValue> = match args.first() {
                    Some(PyValue::List(l)) => l.iter().rev().cloned().collect(),
                    Some(PyValue::Tuple(t)) => t.iter().rev().cloned().collect(),
                    _ => vec![],
                };
                Ok(PyValue::List(items))
            }
            "enumerate" => {
                let items = match args.first() {
                    Some(PyValue::List(l)) => l.clone(),
                    Some(PyValue::Tuple(t)) => t.clone(),
                    _ => vec![],
                };
                Ok(PyValue::List(items.into_iter().enumerate().map(|(i, v)| {
                    PyValue::Tuple(vec![PyValue::Int(i64::try_from(i).unwrap_or(i64::MAX)), v])
                }).collect()))
            }
            "zip" => {
                let a: Vec<PyValue> = match args.first() {
                    Some(PyValue::List(l)) => l.clone(),
                    Some(PyValue::Tuple(t)) => t.clone(),
                    _ => vec![],
                };
                let b: Vec<PyValue> = match args.get(1) {
                    Some(PyValue::List(l)) => l.clone(),
                    Some(PyValue::Tuple(t)) => t.clone(),
                    _ => vec![],
                };
                Ok(PyValue::List(a.into_iter().zip(b).map(|(x, y)| PyValue::Tuple(vec![x, y])).collect()))
            }
            _ => unreachable!(),
        }
    }
}

impl Default for PythonEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PythonEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PythonEngine")
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

impl PythonError {
    fn value_error(msg: &str) -> Self {
        Self::RuntimeError(format!("ValueError: {msg}"))
    }
}

fn to_float_py(v: &PyValue) -> Option<f64> {
    match v {
        PyValue::Int(i) => Some(*i as f64),
        PyValue::Float(f) => Some(*f),
        PyValue::Bool(b) => Some(f64::from(i32::from(*b))),
        _ => None,
    }
}

fn py_value_eq(a: &PyValue, b: &PyValue) -> bool {
    match (a, b) {
        (PyValue::None, PyValue::None) => true,
        (PyValue::Bool(x), PyValue::Bool(y)) => x == y,
        (PyValue::Int(x), PyValue::Int(y)) => x == y,
        (PyValue::Float(x), PyValue::Float(y)) => x == y,
        (PyValue::Int(x), PyValue::Float(y)) => (*x as f64) == *y,
        (PyValue::Float(x), PyValue::Int(y)) => *x == (*y as f64),
        (PyValue::Str(x), PyValue::Str(y)) => x == y,
        (PyValue::Bool(b), PyValue::Int(i)) => i64::from(*b) == *i,
        (PyValue::Int(i), PyValue::Bool(b)) => *i == i64::from(*b),
        _ => false,
    }
}

fn py_lt(a: &PyValue, b: &PyValue) -> bool {
    match (a, b) {
        (PyValue::Int(x), PyValue::Int(y)) => x < y,
        (PyValue::Float(x), PyValue::Float(y)) => x < y,
        (PyValue::Int(x), PyValue::Float(y)) => (*x as f64) < *y,
        (PyValue::Float(x), PyValue::Int(y)) => *x < (*y as f64),
        (PyValue::Str(x), PyValue::Str(y)) => x < y,
        _ => false,
    }
}

fn py_cmp_order(a: &PyValue, b: &PyValue) -> std::cmp::Ordering {
    if py_lt(a, b) {
        std::cmp::Ordering::Less
    } else if py_lt(b, a) {
        std::cmp::Ordering::Greater
    } else {
        std::cmp::Ordering::Equal
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Maximum bracket nesting accepted in one line of source.
///
/// CPython imposes a fixed parser limit for the same reason and reports it as a
/// `SyntaxError` ("too many nested parentheses"); 200 matches that limit. It is
/// far above anything a real expression contains and far below the depth that
/// exhausts the stack.
const MAX_EXPR_NESTING: usize = 200;

/// Deepest bracket nesting in `line`, ignoring brackets inside string literals.
///
/// Counting brackets that appear inside a string would reject a legitimate
/// script that merely *mentions* them, so quoted spans are skipped. The scan is
/// over bytes: every ASCII bracket and quote is a single byte and a multi-byte
/// UTF-8 sequence never contains one, so this cannot split a character.
fn max_bracket_nesting(line: &str) -> usize {
    let mut depth = 0usize;
    let mut deepest = 0usize;
    let mut quote: Option<u8> = None;
    let mut escaped = false;

    for &b in line.as_bytes() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == q {
                quote = None;
            }
            continue;
        }
        match b {
            b'"' | b'\'' => quote = Some(b),
            b'(' | b'[' | b'{' => {
                depth += 1;
                deepest = deepest.max(depth);
            }
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    deepest
}

struct PyParser<'s> {
    lines: Vec<&'s str>,
    line_idx: usize,
}

impl<'s> PyParser<'s> {
    fn new(source: &'s str) -> Self {
        Self {
            lines: source.lines().collect(),
            line_idx: 0,
        }
    }

    const fn current_line(&self) -> usize {
        self.line_idx + 1
    }

    fn current_indent(&self) -> usize {
        if self.line_idx >= self.lines.len() {
            return 0;
        }
        self.lines[self.line_idx]
            .chars()
            .take_while(|c| *c == ' ' || *c == '\t')
            .count()
    }

    fn peek_line_trimmed(&self) -> Option<&str> {
        if self.line_idx >= self.lines.len() {
            return None;
        }
        Some(self.lines[self.line_idx].trim())
    }

    fn parse_module(&mut self) -> Result<Vec<PyStmt>, PythonError> {
        // The expression parser recurses once per bracket level, so nesting
        // depth is bounded by the native stack rather than by any of the
        // interpreter's own limits: `step()`'s budget counts steps taken while
        // *executing* and is not active during parsing at all. Measured on this
        // build, ~5000 levels — a 10 KB script — exhausts the stack, and a stack
        // overflow aborts the process instead of raising a catchable error, so
        // no caller can recover from it. Scripts here are untrusted input, so
        // the bound has to be checked before recursing.
        for (i, line) in self.lines.iter().enumerate() {
            let nesting = max_bracket_nesting(line);
            if nesting > MAX_EXPR_NESTING {
                return Err(PythonError::SyntaxError {
                    line: i + 1,
                    message: format!(
                        "too many nested brackets ({nesting}, limit {MAX_EXPR_NESTING})"
                    ),
                });
            }
        }
        self.parse_block(0)
    }

    fn parse_block(&mut self, min_indent: usize) -> Result<Vec<PyStmt>, PythonError> {
        let mut stmts = Vec::new();
        loop {
            // Skip empty / comment lines.
            while self
                .peek_line_trimmed()
                .is_some_and(|l| l.is_empty() || l.starts_with('#'))
            {
                self.line_idx += 1;
            }
            if self.line_idx >= self.lines.len() {
                break;
            }
            let indent = self.current_indent();
            if indent < min_indent {
                break;
            }
            let line_no = self.current_line();
            let raw = self.lines[self.line_idx].trim();
            if raw.is_empty() || raw.starts_with('#') {
                self.line_idx += 1;
                continue;
            }
            if let Some(stmt) = self.parse_stmt_line(raw, indent, line_no)? {
                stmts.push(stmt);
            }
        }
        Ok(stmts)
    }

    fn parse_stmt_line(
        &mut self,
        line: &str,
        indent: usize,
        line_no: usize,
    ) -> Result<Option<PyStmt>, PythonError> {
        // `pass`
        if line == "pass" {
            self.line_idx += 1;
            return Ok(Some(PyStmt::Pass));
        }
        // `break`
        if line == "break" {
            self.line_idx += 1;
            return Ok(Some(PyStmt::Break));
        }
        // `continue`
        if line == "continue" {
            self.line_idx += 1;
            return Ok(Some(PyStmt::Continue));
        }
        // `return`
        if line == "return" {
            self.line_idx += 1;
            return Ok(Some(PyStmt::Return(None)));
        }
        if let Some(rest) = line.strip_prefix("return ") {
            self.line_idx += 1;
            let expr = Self::parse_expr_str(rest.trim(), line_no)?;
            return Ok(Some(PyStmt::Return(Some(expr))));
        }
        // `def name(params):`.
        if let Some(rest) = line.strip_prefix("def ") {
            return self.parse_function_def(rest, indent, line_no);
        }
        // `if cond:`.
        if let Some(rest) = line.strip_prefix("if ") {
            return self.parse_if_stmt(rest, indent, line_no);
        }
        // `while cond:`.
        if let Some(rest) = line.strip_prefix("while ") {
            return self.parse_while_stmt(rest, indent, line_no);
        }
        // `for var in expr:`.
        if let Some(rest) = line.strip_prefix("for ") {
            return self.parse_for_stmt(rest, indent, line_no);
        }
        // Augmented assignments: `x += ...`.
        for (op_str, op) in &[
            ("+=", AugOp::Add),
            ("-=", AugOp::Sub),
            ("*=", AugOp::Mul),
            ("/=", AugOp::Div),
            ("%=", AugOp::Mod),
        ] {
            if let Some(pos) = line.find(op_str) {
                let target = line[..pos].trim().to_string();
                let value_str = line[pos + op_str.len()..].trim();
                self.line_idx += 1;
                let value = Self::parse_expr_str(value_str, line_no)?;
                return Ok(Some(PyStmt::AugAssign {
                    target,
                    op: *op,
                    value,
                }));
            }
        }
        // Regular assignment: `x = expr` (but not `==`).
        if let Some(assign_pos) = find_simple_assign(line) {
            let target = line[..assign_pos].trim().to_string();
            let value_str = line[assign_pos + 1..].trim();
            self.line_idx += 1;
            let value = Self::parse_expr_str(value_str, line_no)?;
            return Ok(Some(PyStmt::Assign { target, value }));
        }
        // Expression statement (function call, etc.).
        self.line_idx += 1;
        let expr = Self::parse_expr_str(line, line_no)?;
        Ok(Some(PyStmt::Expr(expr)))
    }

    fn parse_function_def(
        &mut self,
        rest: &str,
        indent: usize,
        line_no: usize,
    ) -> Result<Option<PyStmt>, PythonError> {
        // `name(params):`
        let paren = rest.find('(').ok_or_else(|| PythonError::SyntaxError {
            line: line_no,
            message: "expected '(' in def".to_string(),
        })?;
        let name = rest[..paren].trim().to_string();
        let close_paren = rest.find(')').ok_or_else(|| PythonError::SyntaxError {
            line: line_no,
            message: "expected ')' in def".to_string(),
        })?;
        let params_str = &rest[paren + 1..close_paren];
        let params: Vec<String> = params_str
            .split(',')
            .map(|p| p.trim().to_string())
            .filter(|p| !p.is_empty())
            .collect();
        self.line_idx += 1;
        let body = self.parse_block(indent + 1)?;
        Ok(Some(PyStmt::FunctionDef { name, params, body }))
    }

    fn parse_if_stmt(
        &mut self,
        rest: &str,
        indent: usize,
        line_no: usize,
    ) -> Result<Option<PyStmt>, PythonError> {
        let cond_str = rest.trim_end_matches(':').trim();
        let condition = Self::parse_expr_str(cond_str, line_no)?;
        self.line_idx += 1;
        let then_body = self.parse_block(indent + 1)?;
        let mut elif_branches = Vec::new();
        let mut else_body: Option<Vec<PyStmt>> = None;

        loop {
            // Skip blank lines.
            while self
                .peek_line_trimmed()
                .is_some_and(|l| l.is_empty() || l.starts_with('#'))
            {
                self.line_idx += 1;
            }
            if self.line_idx >= self.lines.len() {
                break;
            }
            let cur_indent = self.current_indent();
            if cur_indent < indent {
                break;
            }
            if cur_indent > indent {
                break;
            }
            let cur_line = self.lines[self.line_idx].trim();
            if let Some(elif_rest) = cur_line.strip_prefix("elif ") {
                let elif_cond_str = elif_rest.trim_end_matches(':').trim();
                let elif_cond = Self::parse_expr_str(elif_cond_str, self.current_line())?;
                self.line_idx += 1;
                let elif_body = self.parse_block(indent + 1)?;
                elif_branches.push((elif_cond, elif_body));
            } else if cur_line == "else:" {
                self.line_idx += 1;
                else_body = Some(self.parse_block(indent + 1)?);
                break;
            } else {
                break;
            }
        }

        Ok(Some(PyStmt::If {
            condition,
            then_body,
            elif_branches,
            else_body,
        }))
    }

    fn parse_while_stmt(
        &mut self,
        rest: &str,
        indent: usize,
        line_no: usize,
    ) -> Result<Option<PyStmt>, PythonError> {
        let cond_str = rest.trim_end_matches(':').trim();
        let condition = Self::parse_expr_str(cond_str, line_no)?;
        self.line_idx += 1;
        let body = self.parse_block(indent + 1)?;
        Ok(Some(PyStmt::While { condition, body }))
    }

    fn parse_for_stmt(
        &mut self,
        rest: &str,
        indent: usize,
        line_no: usize,
    ) -> Result<Option<PyStmt>, PythonError> {
        // `var in iterable:`
        let rest = rest.trim_end_matches(':');
        let in_pos = rest.find(" in ").ok_or_else(|| PythonError::SyntaxError {
            line: line_no,
            message: "expected 'in' in for".to_string(),
        })?;
        let var = rest[..in_pos].trim().to_string();
        let iter_str = rest[in_pos + 4..].trim();
        let iter = Self::parse_expr_str(iter_str, line_no)?;
        self.line_idx += 1;
        let body = self.parse_block(indent + 1)?;
        Ok(Some(PyStmt::For { var, iter, body }))
    }

    // ── Expression parser ────────────────────────────────────────────────────

    fn parse_expr_str(s: &str, line_no: usize) -> Result<PyExpr, PythonError> {
        let s = s.trim();
        parse_py_expr(s, line_no)
    }
}

// ── Find simple `=` assignment (not `==`, `!=`, `<=`, `>=`, `+=`, etc.) ──────

fn find_simple_assign(line: &str) -> Option<usize> {
    // We need the position of a lone `=` that is not part of `==`, `!=`, `<=`, `>=`, `+=`, `-=`, `*=`, `/=`, `%=`.
    let bytes = line.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'=' {
            let prev = if i > 0 { bytes[i - 1] } else { 0 };
            let next = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
            if next == b'=' {
                continue; // `==`
            }
            if prev == b'!'
                || prev == b'<'
                || prev == b'>'
                || prev == b'+'
                || prev == b'-'
                || prev == b'*'
                || prev == b'/'
                || prev == b'%'
                || prev == b'='
            {
                continue;
            }
            return Some(i);
        }
    }
    None
}

// ── Expression parser (recursive descent, token-based) ──────────────────────

fn parse_py_expr(s: &str, line_no: usize) -> Result<PyExpr, PythonError> {
    let s = s.trim();
    parse_or_expr(s, line_no)
}

fn parse_or_expr(s: &str, line_no: usize) -> Result<PyExpr, PythonError> {
    // Split on ` or ` (lowest precedence).
    if let Some(pos) = find_keyword_outside_parens(s, " or ") {
        let left = parse_or_expr(&s[..pos], line_no)?;
        let right = parse_or_expr(&s[pos + 4..], line_no)?;
        return Ok(PyExpr::BinOp {
            op: PyBinOp::Or,
            left: Box::new(left),
            right: Box::new(right),
        });
    }
    parse_and_expr(s, line_no)
}

fn parse_and_expr(s: &str, line_no: usize) -> Result<PyExpr, PythonError> {
    if let Some(pos) = find_keyword_outside_parens(s, " and ") {
        let left = parse_and_expr(&s[..pos], line_no)?;
        let right = parse_and_expr(&s[pos + 5..], line_no)?;
        return Ok(PyExpr::BinOp {
            op: PyBinOp::And,
            left: Box::new(left),
            right: Box::new(right),
        });
    }
    parse_not_expr(s, line_no)
}

fn parse_not_expr(s: &str, line_no: usize) -> Result<PyExpr, PythonError> {
    if let Some(rest) = s.strip_prefix("not ") {
        let operand = parse_not_expr(rest.trim(), line_no)?;
        return Ok(PyExpr::UnOp {
            op: PyUnOp::Not,
            operand: Box::new(operand),
        });
    }
    parse_in_expr(s, line_no)
}

fn parse_in_expr(s: &str, line_no: usize) -> Result<PyExpr, PythonError> {
    if let Some(pos) = find_keyword_outside_parens(s, " not in ") {
        let left = parse_compare_expr(&s[..pos], line_no)?;
        let right = parse_compare_expr(&s[pos + 8..], line_no)?;
        return Ok(PyExpr::BinOp {
            op: PyBinOp::NotIn,
            left: Box::new(left),
            right: Box::new(right),
        });
    }
    if let Some(pos) = find_keyword_outside_parens(s, " in ") {
        let left = parse_compare_expr(&s[..pos], line_no)?;
        let right = parse_compare_expr(&s[pos + 4..], line_no)?;
        return Ok(PyExpr::BinOp {
            op: PyBinOp::In,
            left: Box::new(left),
            right: Box::new(right),
        });
    }
    parse_compare_expr(s, line_no)
}

fn parse_compare_expr(s: &str, line_no: usize) -> Result<PyExpr, PythonError> {
    for (sym, op) in &[
        ("!=", PyBinOp::Ne),
        ("==", PyBinOp::Eq),
        ("<=", PyBinOp::Le),
        (">=", PyBinOp::Ge),
        ("<", PyBinOp::Lt),
        (">", PyBinOp::Gt),
    ] {
        if let Some(pos) = find_op_outside_parens(s, sym) {
            let left = parse_add_expr(&s[..pos], line_no)?;
            let right = parse_add_expr(&s[pos + sym.len()..], line_no)?;
            return Ok(PyExpr::BinOp {
                op: *op,
                left: Box::new(left),
                right: Box::new(right),
            });
        }
    }
    parse_add_expr(s, line_no)
}

fn parse_add_expr(s: &str, line_no: usize) -> Result<PyExpr, PythonError> {
    // Right-to-left scan for + or - outside parens (handles left-assoc).
    let s = s.trim();
    // Scan from right to find the rightmost + or - that is outside parens.
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b')' | b']' => depth += 1,
            b'(' | b'[' => depth -= 1,
            b'+' | b'-' if depth == 0 && i > 0 => {
                // Ensure it's not part of ** or a sign at start.
                let prev = bytes[i - 1];
                if prev == b'*' {
                    continue;
                }
                // Check it's not a comparison operator.
                let op = if bytes[i] == b'+' {
                    PyBinOp::Add
                } else {
                    PyBinOp::Sub
                };
                let left = parse_add_expr(&s[..i], line_no)?;
                let right = parse_mul_expr(&s[i + 1..], line_no)?;
                return Ok(PyExpr::BinOp {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                });
            }
            _ => {}
        }
    }
    parse_mul_expr(s, line_no)
}

fn parse_mul_expr(s: &str, line_no: usize) -> Result<PyExpr, PythonError> {
    let s = s.trim();
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b')' | b']' => depth += 1,
            b'(' | b'[' => depth -= 1,
            b'*' if depth == 0 => {
                // Check for `**`.
                if i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                    // Skip — part of **.
                    continue;
                }
                if i > 0 && bytes[i - 1] == b'*' {
                    // This is the first `*` of `**`.
                    let left = parse_mul_expr(&s[..i - 1], line_no)?;
                    let right = parse_unary_expr(&s[i + 2..], line_no)?;
                    return Ok(PyExpr::BinOp {
                        op: PyBinOp::Pow,
                        left: Box::new(left),
                        right: Box::new(right),
                    });
                }
                let left = parse_mul_expr(&s[..i], line_no)?;
                let right = parse_unary_expr(&s[i + 1..], line_no)?;
                return Ok(PyExpr::BinOp {
                    op: PyBinOp::Mul,
                    left: Box::new(left),
                    right: Box::new(right),
                });
            }
            b'/' if depth == 0 => {
                let op = if i > 0 && bytes[i - 1] == b'/' {
                    // `//` — floor div; adjust split point.
                    let left_str = &s[..i - 1];
                    let right_str = &s[i + 1..];
                    let left = parse_mul_expr(left_str, line_no)?;
                    let right = parse_unary_expr(right_str, line_no)?;
                    return Ok(PyExpr::BinOp {
                        op: PyBinOp::FloorDiv,
                        left: Box::new(left),
                        right: Box::new(right),
                    });
                } else if i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    // This is the first `/` of `//` — skip.
                    continue;
                } else {
                    PyBinOp::Div
                };
                let left = parse_mul_expr(&s[..i], line_no)?;
                let right = parse_unary_expr(&s[i + 1..], line_no)?;
                return Ok(PyExpr::BinOp {
                    op,
                    left: Box::new(left),
                    right: Box::new(right),
                });
            }
            b'%' if depth == 0 => {
                let left = parse_mul_expr(&s[..i], line_no)?;
                let right = parse_unary_expr(&s[i + 1..], line_no)?;
                return Ok(PyExpr::BinOp {
                    op: PyBinOp::Mod,
                    left: Box::new(left),
                    right: Box::new(right),
                });
            }
            _ => {}
        }
    }
    parse_unary_expr(s, line_no)
}

fn parse_unary_expr(s: &str, line_no: usize) -> Result<PyExpr, PythonError> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('-') {
        let rest = rest.trim();
        // If rest is a digit, parse as negative literal.
        if rest
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit() || c == '.')
        {
            // Fall through to primary, the sign is already there.
        } else {
            let operand = parse_unary_expr(rest, line_no)?;
            return Ok(PyExpr::UnOp {
                op: PyUnOp::Neg,
                operand: Box::new(operand),
            });
        }
    }
    parse_primary(s, line_no)
}

fn parse_primary(s: &str, line_no: usize) -> Result<PyExpr, PythonError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(PythonError::SyntaxError {
            line: line_no,
            message: "unexpected end of expression".to_string(),
        });
    }
    // Keywords and literals.
    if let Some(e) = parse_keyword_or_literal(s, line_no)? {
        return Ok(e);
    }
    // Number literals.
    if (s.starts_with('-') || s.chars().next().is_some_and(|c| c.is_ascii_digit()))
        && let Some(e) = parse_number_literal(s)
    {
        return Ok(e);
    }
    // Index access `expr[idx]`.
    if s.ends_with(']')
        && let Some(open) = rfind_matching_bracket(s)
    {
        let obj_str = &s[..open];
        let idx_str = &s[open + 1..s.len() - 1];
        if !obj_str.is_empty() && !idx_str.is_empty() {
            return Ok(PyExpr::Index {
                obj: Box::new(parse_primary(obj_str, line_no)?),
                idx: Box::new(parse_py_expr(idx_str, line_no)?),
            });
        }
    }
    // Function call `name(args)`.
    if s.ends_with(')')
        && let Some(open) = rfind_matching_paren(s)
    {
        let name = s[..open].trim().to_string();
        if !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
        {
            let args_str = &s[open + 1..s.len() - 1];
            let mut args = Vec::new();
            for part in split_top_level(args_str, ',') {
                let part = part.trim();
                if !part.is_empty() {
                    args.push(parse_py_expr(part, line_no)?);
                }
            }
            return Ok(PyExpr::Call { name, args });
        }
    }
    // Variable / identifier.
    if s.chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
    {
        return Ok(PyExpr::Var(s.to_string()));
    }
    Err(PythonError::SyntaxError {
        line: line_no,
        message: format!("cannot parse expression: '{s}'"),
    })
}

fn parse_keyword_or_literal(s: &str, line_no: usize) -> Result<Option<PyExpr>, PythonError> {
    match s {
        "None" => return Ok(Some(PyExpr::None)),
        "True" => return Ok(Some(PyExpr::True)),
        "False" => return Ok(Some(PyExpr::False)),
        _ => {}
    }
    // String literals.
    if (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
        || (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
    {
        let inner = &s[1..s.len() - 1];
        return Ok(Some(PyExpr::Str(
            inner.replace("\\n", "\n").replace("\\t", "\t"),
        )));
    }
    if (s.starts_with("\"\"\"") && s.ends_with("\"\"\"") && s.len() >= 6)
        || (s.starts_with("'''") && s.ends_with("'''") && s.len() >= 6)
    {
        return Ok(Some(PyExpr::Str(s[3..s.len() - 3].to_string())));
    }
    // Collection literals.
    if s.starts_with('[') && s.ends_with(']') {
        let exprs: Result<Vec<_>, _> = split_top_level(&s[1..s.len() - 1], ',')
            .into_iter()
            .filter(|i| !i.trim().is_empty())
            .map(|i| parse_py_expr(i.trim(), line_no))
            .collect();
        return Ok(Some(PyExpr::List(exprs?)));
    }
    if s.starts_with('(') && s.ends_with(')') {
        let items = split_top_level(&s[1..s.len() - 1], ',');
        if items.len() == 1 {
            return Ok(Some(parse_py_expr(items[0].trim(), line_no)?));
        }
        let exprs: Result<Vec<_>, _> = items
            .iter()
            .filter(|i| !i.trim().is_empty())
            .map(|i| parse_py_expr(i.trim(), line_no))
            .collect();
        return Ok(Some(PyExpr::Tuple(exprs?)));
    }
    if s.starts_with('{') && s.ends_with('}') {
        let mut d = Vec::new();
        for pair in split_top_level(&s[1..s.len() - 1], ',') {
            let pair = pair.trim();
            if pair.is_empty() {
                continue;
            }
            if let Some(colon) = pair.find(':') {
                d.push((
                    parse_py_expr(pair[..colon].trim(), line_no)?,
                    parse_py_expr(pair[colon + 1..].trim(), line_no)?,
                ));
            }
        }
        return Ok(Some(PyExpr::Dict(d)));
    }
    Ok(None)
}

fn parse_number_literal(s: &str) -> Option<PyExpr> {
    if s.contains('.') {
        if let Ok(f) = s.parse::<f64>() {
            return Some(PyExpr::Float(f));
        }
    } else if let Ok(i) = s.parse::<i64>() {
        return Some(PyExpr::Int(i));
    } else if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
        && let Ok(i) = i64::from_str_radix(hex, 16)
    {
        return Some(PyExpr::Int(i));
    }
    None
}

// ── Parser helpers ────────────────────────────────────────────────────────────

/// Find position of `keyword` outside of parentheses/brackets.
fn find_keyword_outside_parens(s: &str, keyword: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let kbytes = keyword.as_bytes();
    let mut depth = 0i32;
    let mut in_str: Option<u8> = None;
    let mut i = 0;
    while i + kbytes.len() <= s.len() {
        let ch = bytes[i];
        if let Some(q) = in_str {
            if ch == q && (i == 0 || bytes[i - 1] != b'\\') {
                in_str = None;
            }
            i += 1;
            continue;
        }
        match ch {
            b'"' | b'\'' => {
                in_str = Some(ch);
                i += 1;
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                i += 1;
            }
            b')' | b']' | b'}' => {
                depth -= 1;
                i += 1;
            }
            _ if depth == 0 && s[i..].starts_with(keyword) => {
                return Some(i);
            }
            _ => {
                i += 1;
            }
        }
    }
    None
}

/// Find position of operator `op` outside parentheses.
fn find_op_outside_parens(s: &str, op: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let obytes = op.as_bytes();
    let mut depth = 0i32;
    let mut in_str: Option<u8> = None;
    let mut i = 0;
    while i + obytes.len() <= s.len() {
        let ch = bytes[i];
        if let Some(q) = in_str {
            if ch == q {
                in_str = None;
            }
            i += 1;
            continue;
        }
        match ch {
            b'"' | b'\'' => {
                in_str = Some(ch);
                i += 1;
            }
            b'(' | b'[' | b'{' => {
                depth += 1;
                i += 1;
            }
            b')' | b']' | b'}' => {
                depth -= 1;
                i += 1;
            }
            _ if depth == 0 && s[i..].starts_with(op) => {
                return Some(i);
            }
            _ => {
                i += 1;
            }
        }
    }
    None
}

/// Split a string on `sep` at the top level (not inside nested parens/brackets).
fn split_top_level(s: &str, sep: char) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    let bytes = s.as_bytes();
    let mut in_str: Option<u8> = None;
    for (i, &b) in bytes.iter().enumerate() {
        if let Some(q) = in_str {
            if b == q {
                in_str = None;
            }
            continue;
        }
        match b {
            b'"' | b'\'' => in_str = Some(b),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth -= 1,
            c if c == sep as u8 && depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

/// Find the matching `[` for the last `]` in `s`.
fn rfind_matching_bracket(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b']' => depth += 1,
            b'[' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Find the matching `(` for the last `)` in `s`.
fn rfind_matching_paren(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut i = bytes.len();
    while i > 0 {
        i -= 1;
        match bytes[i] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn run(script: &str) -> (PyValue, PyScope) {
        let mut engine = PythonEngine::new();
        let mut scope = PyScope::new();
        let val = engine.execute(script, &mut scope).expect("script failed");
        (val, scope)
    }

    fn run_err(script: &str) -> PythonError {
        let mut engine = PythonEngine::new();
        let mut scope = PyScope::new();
        engine.execute(script, &mut scope).unwrap_err()
    }

    // ── Variable assignment ──────────────────────────────────────────────────

    #[test]
    fn test_assign_int() {
        let (_, scope) = run("x = 42");
        assert_eq!(scope.get("x").and_then(super::PyValue::as_int), Some(42));
    }

    #[test]
    fn test_assign_string() {
        let (_, scope) = run(r#"s = "hello""#);
        assert!(matches!(scope.get("s"), Some(PyValue::Str(_))));
    }

    #[test]
    fn test_assign_bool() {
        let (_, scope) = run("b = True");
        assert!(matches!(scope.get("b"), Some(PyValue::Bool(true))));
    }

    // ── Arithmetic ───────────────────────────────────────────────────────────

    #[test]
    fn test_addition() {
        let (_, scope) = run("x = 3 + 4");
        assert_eq!(scope.get("x").and_then(super::PyValue::as_int), Some(7));
    }

    #[test]
    fn test_subtraction() {
        let (_, scope) = run("x = 10 - 3");
        assert_eq!(scope.get("x").and_then(super::PyValue::as_int), Some(7));
    }

    #[test]
    fn test_multiplication() {
        let (_, scope) = run("x = 3 * 4");
        assert_eq!(scope.get("x").and_then(super::PyValue::as_int), Some(12));
    }

    #[test]
    fn test_floor_division() {
        let (_, scope) = run("x = 10 // 3");
        assert_eq!(scope.get("x").and_then(super::PyValue::as_int), Some(3));
    }

    #[test]
    fn test_modulo() {
        let (_, scope) = run("x = 10 % 3");
        assert_eq!(scope.get("x").and_then(super::PyValue::as_int), Some(1));
    }

    #[test]
    fn test_power() {
        let (_, scope) = run("x = 2 ** 8");
        assert_eq!(scope.get("x").and_then(super::PyValue::as_int), Some(256));
    }

    #[test]
    fn test_augmented_add() {
        let (_, scope) = run("x = 5\nx += 3");
        assert_eq!(scope.get("x").and_then(super::PyValue::as_int), Some(8));
    }

    // ── Print ────────────────────────────────────────────────────────────────

    #[test]
    fn test_print_string() {
        let (_, scope) = run(r#"print("hello world")"#);
        assert_eq!(scope.output, vec!["hello world"]);
    }

    #[test]
    fn test_print_number() {
        let (_, scope) = run("print(42)");
        assert_eq!(scope.output, vec!["42"]);
    }

    #[test]
    fn test_print_multiple() {
        let (_, scope) = run(r#"print(1, 2, "three")"#);
        assert_eq!(scope.output, vec!["1 2 three"]);
    }

    // ── If / elif / else ─────────────────────────────────────────────────────

    #[test]
    fn test_if_true() {
        let (_, scope) = run("if True:\n    x = 1");
        assert_eq!(scope.get("x").and_then(super::PyValue::as_int), Some(1));
    }

    #[test]
    fn test_if_else() {
        let (_, scope) = run("if False:\n    x = 1\nelse:\n    x = 2");
        assert_eq!(scope.get("x").and_then(super::PyValue::as_int), Some(2));
    }

    #[test]
    fn test_if_elif() {
        let script = "x = 5\nif x == 1:\n    r = 1\nelif x == 5:\n    r = 5\nelse:\n    r = 0";
        let (_, scope) = run(script);
        assert_eq!(scope.get("r").and_then(super::PyValue::as_int), Some(5));
    }

    // ── While loop ───────────────────────────────────────────────────────────

    #[test]
    fn test_while_basic() {
        let (_, scope) = run("i = 0\nwhile i < 5:\n    i += 1");
        assert_eq!(scope.get("i").and_then(super::PyValue::as_int), Some(5));
    }

    #[test]
    fn test_while_break() {
        let script = "i = 0\nwhile True:\n    i += 1\n    if i == 3:\n        break";
        let (_, scope) = run(script);
        assert_eq!(scope.get("i").and_then(super::PyValue::as_int), Some(3));
    }

    // ── For loop ─────────────────────────────────────────────────────────────

    #[test]
    fn test_for_range() {
        let (_, scope) = run("s = 0\nfor i in range(5):\n    s += i");
        assert_eq!(scope.get("s").and_then(super::PyValue::as_int), Some(10));
    }

    #[test]
    fn test_for_list() {
        let (_, scope) = run("items = [1, 2, 3]\ns = 0\nfor x in items:\n    s += x");
        assert_eq!(scope.get("s").and_then(super::PyValue::as_int), Some(6));
    }

    // ── List operations ──────────────────────────────────────────────────────

    #[test]
    fn test_list_literal() {
        let (_, scope) = run("lst = [10, 20, 30]");
        assert!(matches!(scope.get("lst"), Some(PyValue::List(_))));
    }

    #[test]
    fn test_list_index() {
        let (_, scope) = run("lst = [10, 20, 30]\nx = lst[1]");
        assert_eq!(scope.get("x").and_then(super::PyValue::as_int), Some(20));
    }

    #[test]
    fn test_list_negative_index() {
        let (_, scope) = run("lst = [10, 20, 30]\nx = lst[-1]");
        assert_eq!(scope.get("x").and_then(super::PyValue::as_int), Some(30));
    }

    // ── Dict operations ──────────────────────────────────────────────────────

    #[test]
    fn test_dict_literal() {
        let (_, scope) = run(r#"d = {"a": 1, "b": 2}"#);
        assert!(matches!(scope.get("d"), Some(PyValue::Dict(_))));
    }

    // ── len() ────────────────────────────────────────────────────────────────

    #[test]
    fn test_len_list() {
        let (_, scope) = run("lst = [1, 2, 3]\nn = len(lst)");
        assert_eq!(scope.get("n").and_then(super::PyValue::as_int), Some(3));
    }

    #[test]
    fn test_len_string() {
        let (_, scope) = run(r#"n = len("hello")"#);
        assert_eq!(scope.get("n").and_then(super::PyValue::as_int), Some(5));
    }

    // ── type() ───────────────────────────────────────────────────────────────

    #[test]
    fn test_type_int() {
        let (_, scope) = run("t = type(42)");
        assert!(matches!(scope.get("t"), Some(PyValue::Str(s)) if s == "int"));
    }

    #[test]
    fn test_type_list() {
        let (_, scope) = run("t = type([])");
        assert!(matches!(scope.get("t"), Some(PyValue::Str(s)) if s == "list"));
    }

    // ── Builtins ─────────────────────────────────────────────────────────────

    #[test]
    fn test_range_two_args() {
        let (_, scope) = run("r = range(2, 5)");
        if let Some(PyValue::List(l)) = scope.get("r") {
            assert_eq!(l.len(), 3);
        } else {
            panic!("expected list");
        }
    }

    #[test]
    fn test_hex_builtin() {
        let (_, scope) = run("h = hex(255)");
        assert!(matches!(scope.get("h"), Some(PyValue::Str(s)) if s.contains("0xff")));
    }

    #[test]
    fn test_abs_builtin() {
        let (_, scope) = run("x = abs(-7)");
        assert_eq!(scope.get("x").and_then(super::PyValue::as_int), Some(7));
    }

    #[test]
    fn test_sum_builtin() {
        let (_, scope) = run("s = sum([1, 2, 3, 4])");
        assert_eq!(scope.get("s").and_then(super::PyValue::as_int), Some(10));
    }

    #[test]
    fn test_min_max_builtins() {
        let (_, scope) = run("mn = min([3, 1, 2])\nmx = max([3, 1, 2])");
        assert_eq!(scope.get("mn").and_then(super::PyValue::as_int), Some(1));
        assert_eq!(scope.get("mx").and_then(super::PyValue::as_int), Some(3));
    }

    #[test]
    fn test_sorted_builtin() {
        let (_, scope) = run("s = sorted([3, 1, 2])");
        if let Some(PyValue::List(l)) = scope.get("s") {
            assert_eq!(l[0].as_int(), Some(1));
            assert_eq!(l[2].as_int(), Some(3));
        } else {
            panic!("expected list");
        }
    }

    // ── Function definitions ─────────────────────────────────────────────────

    #[test]
    fn test_function_def_and_call() {
        let (_, scope) = run("def add(a, b):\n    return a + b\nx = add(3, 4)");
        assert_eq!(scope.get("x").and_then(super::PyValue::as_int), Some(7));
    }

    #[test]
    fn test_function_no_args() {
        let (_, scope) = run("def meaning():\n    return 42\nm = meaning()");
        assert_eq!(scope.get("m").and_then(super::PyValue::as_int), Some(42));
    }

    // ── Error handling ───────────────────────────────────────────────────────

    #[test]
    fn test_name_error() {
        let err = run_err("x = undefined_var");
        assert!(matches!(err, PythonError::NameError(_)));
    }

    #[test]
    fn test_index_error() {
        let err = run_err("lst = [1, 2]\nx = lst[5]");
        assert!(matches!(err, PythonError::IndexError(_)));
    }

    #[test]
    fn test_timeout() {
        let mut engine = PythonEngine::new();
        engine.set_max_steps(10);
        let mut scope = PyScope::new();
        let err = engine
            .execute("i = 0\nwhile True:\n    i += 1", &mut scope)
            .unwrap_err();
        assert!(matches!(err, PythonError::Timeout(_)));
    }

    // ── Display / Debug ──────────────────────────────────────────────────────

    #[test]
    fn test_pyvalue_type_names() {
        assert_eq!(PyValue::None.type_name(), "NoneType");
        assert_eq!(PyValue::Bool(true).type_name(), "bool");
        assert_eq!(PyValue::Int(0).type_name(), "int");
        assert_eq!(PyValue::Float(0.0).type_name(), "float");
        assert_eq!(PyValue::Str(String::new()).type_name(), "str");
        assert_eq!(PyValue::List(vec![]).type_name(), "list");
        assert_eq!(PyValue::Dict(vec![]).type_name(), "dict");
        assert_eq!(PyValue::Tuple(vec![]).type_name(), "tuple");
        assert_eq!(PyValue::Bytes(vec![]).type_name(), "bytes");
    }

    #[test]
    fn test_pyvalue_is_truthy() {
        assert!(!PyValue::None.is_truthy());
        assert!(!PyValue::Bool(false).is_truthy());
        assert!(PyValue::Bool(true).is_truthy());
        assert!(!PyValue::Int(0).is_truthy());
        assert!(PyValue::Int(1).is_truthy());
        assert!(!PyValue::Str(String::new()).is_truthy());
        assert!(!PyValue::List(vec![]).is_truthy());
    }

    #[test]
    fn test_pyvalue_display_list() {
        let v = PyValue::List(vec![PyValue::Int(1), PyValue::Int(2)]);
        assert_eq!(v.to_string(), "[1, 2]");
    }

    #[test]
    fn test_engine_debug() {
        let e = PythonEngine::new();
        assert!(format!("{e:?}").contains("PythonEngine"));
    }

    #[test]
    fn test_scope_output_text() {
        let (_, scope) = run("print(\"a\")\nprint(\"b\")");
        assert_eq!(scope.output_text(), "a\nb");
    }

    #[test]
    fn test_step_count_increases() {
        let mut engine = PythonEngine::new();
        let mut scope = PyScope::new();
        engine.execute("x = 1", &mut scope).unwrap();
        assert!(engine.step_count() > 0);
    }

    #[test]
    fn test_comment_skipped() {
        let (_, scope) = run("# comment\nx = 5");
        assert_eq!(scope.get("x").and_then(super::PyValue::as_int), Some(5));
    }

    #[test]
    fn test_pass_stmt() {
        let (_, scope) = run("x = 1\npass\ny = 2");
        assert_eq!(scope.get("y").and_then(super::PyValue::as_int), Some(2));
    }

    // ── RE API tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_re_disassemble_basic() {
        let api = ReApi::default();
        let result = api.disassemble(0x1000, &[0x55, 0x48, 0x89, 0xe5]);
        assert!(!result.is_empty());
        assert_eq!(result[0].address, 0x1000);
    }

    #[test]
    fn test_re_read_bytes() {
        let api = ReApi::default();
        let bytes = api.read_bytes(0x1000, 4);
        assert_eq!(bytes.len(), 4);
    }

    #[test]
    fn test_re_search_pattern() {
        let api = ReApi::default();
        let haystack: Vec<u8> = (0u8..=255u8).collect();
        let results = api.search_bytes(&haystack, &[0xDE, 0xAD]);
        assert!(results.is_empty()); // not found
        let results2 = api.search_bytes(&haystack, &[0x10, 0x11]);
        assert_eq!(results2.len(), 1);
        assert_eq!(results2[0], 0x10);
    }

    #[test]
    fn test_re_find_strings() {
        let api = ReApi::default();
        let data = b"hello\x00world\x00\x01\x02";
        let strings = api.find_strings(data, 4);
        assert!(strings.iter().any(|s| s.value == "hello"));
        assert!(strings.iter().any(|s| s.value == "world"));
    }

    #[test]
    fn test_re_xrefs_empty() {
        let api = ReApi::default();
        let xrefs = api.get_xrefs_to(0xDEAD);
        assert!(xrefs.is_empty());
    }

    #[test]
    fn test_re_function_list() {
        let mut api = ReApi::default();
        api.add_function(ReFunction {
            address: 0x1000,
            name: "main".to_string(),
            size: 64,
            flags: FunctionFlags::empty(),
        });
        let funcs = api.list_functions();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].name, "main");
    }

    #[test]
    fn test_re_rename_function() {
        let mut api = ReApi::default();
        api.add_function(ReFunction {
            address: 0x1000,
            name: "sub_1000".to_string(),
            size: 16,
            flags: FunctionFlags::empty(),
        });
        api.rename_function(0x1000, "initialize");
        assert_eq!(api.get_function(0x1000).unwrap().name, "initialize");
    }

    #[test]
    fn test_pyvalue_bytes_display() {
        let v = PyValue::Bytes(vec![0xDE, 0xAD]);
        assert!(v.to_string().contains('2'));
    }

    #[test]
    fn test_re_patch_bytes() {
        let mut api = ReApi::default();
        let mut buf = vec![0u8; 16];
        api.patch_bytes(0, &mut buf, &[0xCC]);
        assert_eq!(buf[0], 0xCC);
    }

    #[test]
    fn test_re_decompile_placeholder() {
        let api = ReApi::default();
        let decomp = api.decompile(0x1000);
        assert!(decomp.contains("0x1000"));
    }

    #[test]
    fn test_script_template_find_xrefs() {
        let tmpl = ScriptTemplate::find_xrefs(0x4010);
        assert!(tmpl.contains("0x4010") || tmpl.contains("4010"));
    }

    #[test]
    fn test_script_template_extract_strings() {
        let tmpl = ScriptTemplate::extract_strings();
        assert!(tmpl.contains("strings"));
    }

    #[test]
    fn test_script_template_rename_functions() {
        let tmpl = ScriptTemplate::rename_functions("sub_", "fn_");
        assert!(tmpl.contains("sub_") || tmpl.contains("fn_"));
    }

    #[test]
    fn test_batch_runner_empty() {
        let runner = BatchRunner::new();
        assert_eq!(runner.script_count(), 0);
    }

    #[test]
    fn test_batch_runner_add_script() {
        let mut runner = BatchRunner::new();
        runner.add_script("x = 1".to_string());
        assert_eq!(runner.script_count(), 1);
    }

    #[test]
    fn test_progress_reporter() {
        let mut pr = ProgressReporter::new(10);
        pr.advance(3);
        assert_eq!(pr.percent(), 30);
    }

    #[test]
    fn test_re_segment_list() {
        let mut api = ReApi::default();
        api.add_segment(Segment {
            address: 0x1000,
            size: 0x1000,
            name: ".text".to_string(),
            kind: SegmentKind::Code,
        });
        let segs = api.list_segments();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].name, ".text");
    }

    #[test]
    fn test_sandbox_allow_list() {
        let sb = Sandbox::new(SandboxPolicy::AllowList(vec!["print".to_string()]));
        assert!(sb.is_allowed("print"));
        assert!(!sb.is_allowed("open"));
    }

    #[test]
    fn test_sandbox_deny_list() {
        let sb = Sandbox::new(SandboxPolicy::DenyList(vec!["open".to_string()]));
        assert!(sb.is_allowed("print"));
        assert!(!sb.is_allowed("open"));
    }

    #[test]
    fn test_re_instruction_display() {
        let insn = Instruction {
            address: 0x1000,
            mnemonic: "push".to_string(),
            operands: "rbp".to_string(),
            bytes: vec![0x55],
            size: 1,
        };
        assert!(insn.to_string().contains("push"));
    }

    #[test]
    fn test_marshal_pyvalue_to_re_address() {
        let v = PyValue::Int(0x4000);
        let addr = marshal_to_address(&v);
        assert_eq!(addr, Some(0x4000));
    }

    #[test]
    fn test_marshal_pyvalue_hex_str() {
        let v = PyValue::Str("0x1234".to_string());
        let addr = marshal_to_address(&v);
        assert_eq!(addr, Some(0x1234));
    }

    #[test]
    fn test_re_comment_set_get() {
        let mut api = ReApi::default();
        api.set_comment(0x1000, "entry point");
        assert_eq!(api.get_comment(0x1000), Some("entry point"));
    }

    #[test]
    fn test_module_registry() {
        let mut reg = ModuleRegistry::new();
        reg.register("re", "re module".to_string());
        assert!(reg.get("re").is_some());
        assert!(reg.get("nonexistent").is_none());
    }

    // ── § pyo3 PythonScriptEngine tests ──────────────────────────────────────

    fn new_script_engine() -> PythonScriptEngine {
        PythonScriptEngine::new().expect("PythonScriptEngine::new failed")
    }

    #[test]
    fn test_pyo3_engine_new() {
        let _engine = new_script_engine();
    }

    #[test]
    fn test_pyo3_eval_integer() {
        let engine = new_script_engine();
        let v = engine.eval("1 + 2").unwrap();
        assert_eq!(v, PyScriptValue::Int(3));
    }

    #[test]
    fn test_pyo3_eval_float() {
        let engine = new_script_engine();
        let v = engine.eval("1.5 + 0.5").unwrap();
        assert_eq!(v, PyScriptValue::Float(2.0));
    }

    #[test]
    fn test_pyo3_eval_string() {
        let engine = new_script_engine();
        let v = engine.eval(r#""hello" + " world""#).unwrap();
        assert_eq!(v, PyScriptValue::Str("hello world".to_owned()));
    }

    #[test]
    fn test_pyo3_eval_bool_true() {
        let engine = new_script_engine();
        assert_eq!(engine.eval("True").unwrap(), PyScriptValue::Bool(true));
    }

    #[test]
    fn test_pyo3_eval_bool_false() {
        let engine = new_script_engine();
        assert_eq!(engine.eval("False").unwrap(), PyScriptValue::Bool(false));
    }

    #[test]
    fn test_pyo3_eval_none() {
        let engine = new_script_engine();
        assert_eq!(engine.eval("None").unwrap(), PyScriptValue::None_);
    }

    #[test]
    fn test_pyo3_eval_list() {
        let engine = new_script_engine();
        let v = engine.eval("[1, 2, 3]").unwrap();
        assert_eq!(
            v,
            PyScriptValue::List(vec![
                PyScriptValue::Int(1),
                PyScriptValue::Int(2),
                PyScriptValue::Int(3),
            ])
        );
    }

    #[test]
    fn test_pyo3_eval_dict() {
        let engine = new_script_engine();
        let v = engine.eval(r#"{"key": 42}"#).unwrap();
        assert_eq!(
            v,
            PyScriptValue::Dict(vec![("key".to_owned(), PyScriptValue::Int(42))])
        );
    }

    #[test]
    fn test_pyo3_exec_ok() {
        let engine = new_script_engine();
        engine.exec("x = 1 + 1").unwrap();
    }

    #[test]
    fn test_pyo3_exec_exception() {
        let engine = new_script_engine();
        let err = engine.exec("raise ValueError('boom')");
        assert!(err.is_err());
        if let Err(ScriptError::Py(msg)) = err {
            assert!(msg.contains("ValueError") || msg.contains("boom"));
        }
    }

    #[test]
    fn test_pyo3_eval_int_helper() {
        let engine = new_script_engine();
        assert_eq!(engine.eval_int("10 * 10").unwrap(), 100);
    }

    #[test]
    fn test_pyo3_eval_float_helper() {
        let engine = new_script_engine();
        let f = engine.eval_float("3.14").unwrap();
        assert!((f - 3.14_f64).abs() < 1e-9);
    }

    #[test]
    fn test_pyo3_eval_str_helper() {
        let engine = new_script_engine();
        assert_eq!(engine.eval_str(r#""rustre""#).unwrap(), "rustre");
    }

    #[test]
    fn test_pyo3_exec_and_get_locals() {
        let engine = new_script_engine();
        let locals = engine
            .exec_and_get_locals("alpha = 1\nbeta = 'two'")
            .unwrap();
        assert_eq!(locals.get("alpha"), Some(&PyScriptValue::Int(1)));
        assert_eq!(
            locals.get("beta"),
            Some(&PyScriptValue::Str("two".to_owned()))
        );
    }

    #[test]
    fn test_pyo3_inject_module_and_call() {
        let engine = new_script_engine();
        engine
            .inject_module("mymod", "def greet(name):\n    return 'hello ' + name\n")
            .unwrap();
        let result = engine
            .call_function(
                "mymod",
                "greet",
                &[PyScriptValue::Str("world".to_owned())],
            )
            .unwrap();
        assert_eq!(result, PyScriptValue::Str("hello world".to_owned()));
    }

    #[test]
    fn test_pyo3_inject_module_constant() {
        let engine = new_script_engine();
        engine.inject_module("constmod", "ANSWER = 42\n").unwrap();
        let locals = engine
            .exec_and_get_locals("import constmod; x = constmod.ANSWER")
            .unwrap();
        assert_eq!(locals.get("x"), Some(&PyScriptValue::Int(42)));
    }

    #[test]
    fn test_pyo3_call_builtins_abs() {
        let engine = new_script_engine();
        let result = engine
            .call_function("builtins", "abs", &[PyScriptValue::Int(-5)])
            .unwrap();
        assert_eq!(result, PyScriptValue::Int(5));
    }

    #[test]
    fn test_pyo3_rustre_module_importable() {
        let engine = new_script_engine();
        engine.exec("import rustre").unwrap();
    }

    #[test]
    fn test_pyo3_rustre_version() {
        let engine = new_script_engine();
        let locals = engine
            .exec_and_get_locals("import rustre\nv = rustre.version()")
            .unwrap();
        if let Some(PyScriptValue::Str(v)) = locals.get("v") {
            assert!(!v.is_empty(), "version string should not be empty");
        } else {
            panic!("expected str from rustre.version()");
        }
    }

    #[test]
    fn test_pyo3_rustre_current_binary_info() {
        let engine = new_script_engine();
        engine
            .exec("import rustre\nbv = rustre.current_binary()\ninfo = bv.info()")
            .unwrap();
    }

    #[test]
    fn test_pyo3_rustre_binary_view_functions() {
        let engine = new_script_engine();
        let locals = engine
            .exec_and_get_locals(
                "import rustre\nbv = rustre.current_binary()\nfns = bv.functions()",
            )
            .unwrap();
        if let Some(PyScriptValue::List(fns)) = locals.get("fns") {
            assert!(!fns.is_empty());
        } else {
            panic!("expected list from bv.functions()");
        }
    }

    #[test]
    fn test_pyo3_rustre_binary_view_strings() {
        let engine = new_script_engine();
        let locals = engine
            .exec_and_get_locals("import rustre\nbv = rustre.current_binary()\nstrs = bv.strings()")
            .unwrap();
        if let Some(PyScriptValue::List(strs)) = locals.get("strs") {
            assert!(!strs.is_empty());
        } else {
            panic!("expected list from bv.strings()");
        }
    }

    #[test]
    fn test_pyo3_import_and_probe_math() {
        let engine = new_script_engine();
        let name = engine.import_and_probe("math").unwrap();
        assert_eq!(name, "math");
    }

    #[test]
    fn test_pyo3_call_math_sqrt() {
        let engine = new_script_engine();
        let result = engine
            .call_function("math", "sqrt", &[PyScriptValue::Float(9.0)])
            .unwrap();
        assert_eq!(result.as_float(), Some(3.0));
    }

    #[test]
    fn test_pyo3_to_py_object_round_trip() {
        Python::with_gil(|py| {
            let original = PyScriptValue::List(vec![
                PyScriptValue::Int(1),
                PyScriptValue::Str("two".to_owned()),
                PyScriptValue::Bool(false),
            ]);
            let py_obj = original.to_py_object(py).unwrap();
            let round_tripped = PyScriptValue::from_py_object(&py_obj);
            assert_eq!(round_tripped, original);
        });
    }

    #[test]
    fn test_pyo3_error_type_mismatch() {
        let engine = new_script_engine();
        let err = engine.eval_int(r#""not a number""#);
        assert!(err.is_err());
    }

    #[test]
    fn test_pyo3_py_script_value_none_is_none() {
        assert!(PyScriptValue::None_.is_none());
        assert!(!PyScriptValue::Int(0).is_none());
    }

    #[test]
    fn test_pyo3_py_script_value_type_names() {
        assert_eq!(PyScriptValue::None_.type_name(), "NoneType");
        assert_eq!(PyScriptValue::Bool(false).type_name(), "bool");
        assert_eq!(PyScriptValue::Int(0).type_name(), "int");
        assert_eq!(PyScriptValue::Float(0.0).type_name(), "float");
        assert_eq!(PyScriptValue::Str(String::new()).type_name(), "str");
        assert_eq!(PyScriptValue::List(vec![]).type_name(), "list");
        assert_eq!(PyScriptValue::Dict(vec![]).type_name(), "dict");
    }

    #[test]
    fn test_pyo3_py_script_value_display() {
        assert_eq!(PyScriptValue::None_.to_string(), "None");
        assert_eq!(PyScriptValue::Bool(true).to_string(), "True");
        assert_eq!(PyScriptValue::Int(7).to_string(), "7");
        assert_eq!(PyScriptValue::Str("hi".to_owned()).to_string(), "hi");
    }

    #[test]
    fn test_pyo3_rustre_log_does_not_panic() {
        let engine = new_script_engine();
        engine
            .exec("import rustre\nrustre.log('hello from test')")
            .unwrap();
    }

    #[test]
    fn test_pyo3_load_file_missing_returns_io_error() {
        let engine = new_script_engine();
        let err = engine.load_file(Path::new("/nonexistent/path/to/script.py"));
        assert!(matches!(err, Err(ScriptError::IoError(_))));
    }

    #[test]
    fn test_pyo3_script_error_display() {
        let e = ScriptError::Py("test error".to_owned());
        assert!(e.to_string().contains("python error"));
        let e2 = ScriptError::IoError("file not found".to_owned());
        assert!(e2.to_string().contains("io error"));
        let e3 = ScriptError::Other("misc".to_owned());
        assert!(e3.to_string().contains("error"));
    }
}

// ── RE Data Structures ────────────────────────────────────────────────────────

/// A single disassembled instruction.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// Virtual address of the instruction.
    pub address: u64,
    /// Instruction mnemonic (e.g. `push`, `mov`).
    pub mnemonic: String,
    /// Operand text.
    pub operands: String,
    /// Raw bytes.
    pub bytes: Vec<u8>,
    /// Instruction size in bytes.
    pub size: usize,
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#010x}  {:8}  {}",
            self.address, self.mnemonic, self.operands
        )
    }
}

/// Cross-reference record.
#[derive(Debug, Clone)]
pub struct Xref {
    /// Address that contains the reference.
    pub from: u64,
    /// Address being referenced.
    pub to: u64,
    /// Kind of reference.
    pub kind: XrefKind,
}

/// Cross-reference type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefKind {
    /// Call instruction.
    Call,
    /// Unconditional jump.
    Jump,
    /// Data read/write.
    Data,
    /// Unknown.
    Unknown,
}

impl fmt::Display for XrefKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Call => write!(f, "call"),
            Self::Jump => write!(f, "jump"),
            Self::Data => write!(f, "data"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

bitflags::bitflags! {
    /// Function attribute flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FunctionFlags: u32 {
        /// Function is a library function.
        const LIBRARY   = 0x0001;
        /// Function is a thunk (redirect).
        const THUNK     = 0x0002;
        /// Function has varargs.
        const VARARGS   = 0x0004;
        /// Function was user-renamed.
        const RENAMED   = 0x0008;
        /// Function is exported.
        const EXPORTED  = 0x0010;
        /// Function is imported.
        const IMPORTED  = 0x0020;
        /// Function is inlined.
        const INLINED   = 0x0040;
        /// Function has no return.
        const NORETURN  = 0x0080;
    }
}

/// A function record in the RE database.
#[derive(Debug, Clone)]
pub struct ReFunction {
    /// Start virtual address.
    pub address: u64,
    /// Human-readable name.
    pub name: String,
    /// Byte size of the function body.
    pub size: u64,
    /// Attribute flags.
    pub flags: FunctionFlags,
}

impl ReFunction {
    /// Return `true` if this function has been user-renamed.
    #[must_use]
    pub const fn is_renamed(&self) -> bool {
        self.flags.contains(FunctionFlags::RENAMED)
    }

    /// Return `true` if this is an imported function.
    #[must_use]
    pub const fn is_imported(&self) -> bool {
        self.flags.contains(FunctionFlags::IMPORTED)
    }

    /// Return `true` if this function has no return.
    #[must_use]
    pub const fn is_noreturn(&self) -> bool {
        self.flags.contains(FunctionFlags::NORETURN)
    }
}

impl fmt::Display for ReFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#010x}  {}  ({} bytes)",
            self.address, self.name, self.size
        )
    }
}

/// Memory segment information.
#[derive(Debug, Clone)]
pub struct Segment {
    /// Start virtual address.
    pub address: u64,
    /// Size in bytes.
    pub size: u64,
    /// Name (e.g. `.text`, `.data`).
    pub name: String,
    /// Segment kind.
    pub kind: SegmentKind,
}

/// Segment classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentKind {
    /// Executable code segment.
    Code,
    /// Initialized data.
    Data,
    /// Read-only data.
    ReadOnly,
    /// BSS / uninitialized.
    Bss,
    /// Unknown segment.
    Unknown,
}

impl fmt::Display for SegmentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Code => write!(f, "code"),
            Self::Data => write!(f, "data"),
            Self::ReadOnly => write!(f, "rodata"),
            Self::Bss => write!(f, "bss"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// A string found in binary data.
#[derive(Debug, Clone)]
pub struct FoundString {
    /// Byte offset in the searched buffer.
    pub offset: usize,
    /// String value.
    pub value: String,
    /// Encoding used.
    pub encoding: StringEncoding,
}

/// String encoding type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringEncoding {
    /// US-ASCII / Latin-1.
    Ascii,
    /// UTF-8.
    Utf8,
    /// UTF-16 little-endian.
    Utf16Le,
}

impl fmt::Display for StringEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ascii => write!(f, "ascii"),
            Self::Utf8 => write!(f, "utf-8"),
            Self::Utf16Le => write!(f, "utf-16le"),
        }
    }
}

// ── ReApi — the central host API exposed to Python scripts ────────────────────

/// Host-side reverse-engineering API.
///
/// Instances of this type are injected into [`PythonEngine`] and exposed to
/// scripts via built-in call bindings.  The engine's `call_builtin` method
/// routes `re.*` calls through the registered [`ReApi`].
#[derive(Debug, Default)]
pub struct ReApi {
    functions: Vec<ReFunction>,
    segments: Vec<Segment>,
    xrefs: Vec<Xref>,
    comments: HashMap<u64, String>,
    labels: HashMap<u64, String>,
    patches: Vec<(u64, Vec<u8>)>,
}

impl ReApi {
    /// Create a new empty RE API instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Disassembly ───────────────────────────────────────────────────────────

    /// Disassemble `bytes` starting at `base_address`.
    ///
    /// Returns a simplified linear disassembly using a small x86-64
    /// heuristic table.  For real use, wire up to the proper disassembler.
    #[must_use]
    pub fn disassemble(&self, base_address: u64, bytes: &[u8]) -> Vec<Instruction> {
        let mut insns = Vec::new();
        let mut offset = 0usize;
        while offset < bytes.len() {
            let byte = bytes[offset];
            let (mnemonic, operands, size) = decode_x86_simple(byte, bytes, offset);
            let size = size.min(bytes.len() - offset).max(1);
            insns.push(Instruction {
                address: base_address + offset as u64,
                mnemonic: mnemonic.to_string(),
                operands: operands.to_string(),
                bytes: bytes[offset..offset + size].to_vec(),
                size,
            });
            offset += size;
        }
        insns
    }

    /// Disassemble a single instruction at `offset` in `bytes`.
    ///
    /// Returns `None` when `offset` is out of bounds.
    #[must_use]
    pub fn disassemble_one(
        &self,
        base_address: u64,
        bytes: &[u8],
        offset: usize,
    ) -> Option<Instruction> {
        if offset >= bytes.len() {
            return None;
        }
        let byte = bytes[offset];
        let (mnemonic, operands, size) = decode_x86_simple(byte, bytes, offset);
        let size = size.min(bytes.len() - offset).max(1);
        Some(Instruction {
            address: base_address + offset as u64,
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            bytes: bytes[offset..offset + size].to_vec(),
            size,
        })
    }

    // ── Memory ────────────────────────────────────────────────────────────────

    /// Read `count` bytes from the virtual address space (stub returns zeroes).
    #[must_use]
    pub fn read_bytes(&self, _address: u64, count: usize) -> Vec<u8> {
        vec![0u8; count]
    }

    /// Read a 32-bit little-endian word at `offset` within `buf`.
    ///
    /// Returns `None` if `offset + 4 > buf.len()`.
    #[must_use]
    pub fn read_u32_le(buf: &[u8], offset: usize) -> Option<u32> {
        let end = offset.checked_add(4)?;
        let slice = buf.get(offset..end)?;
        Some(u32::from_le_bytes(slice.try_into().ok()?))
    }

    /// Read a 64-bit little-endian word at `offset` within `buf`.
    ///
    /// Returns `None` if `offset + 8 > buf.len()`.
    #[must_use]
    pub fn read_u64_le(buf: &[u8], offset: usize) -> Option<u64> {
        let end = offset.checked_add(8)?;
        let slice = buf.get(offset..end)?;
        Some(u64::from_le_bytes(slice.try_into().ok()?))
    }

    // ── Patching ──────────────────────────────────────────────────────────────

    /// Patch `target` buffer at `offset` with `patch_bytes`.
    ///
    /// Records the patch internally and applies it to the buffer.
    pub fn patch_bytes(&mut self, offset: usize, target: &mut [u8], patch_bytes: &[u8]) {
        if let Some(end) = offset.checked_add(patch_bytes.len())
            && end <= target.len() {
                target[offset..end].copy_from_slice(patch_bytes);
                self.patches.push((offset as u64, patch_bytes.to_vec()));
            }
    }

    /// Return the list of all applied patches.
    #[must_use]
    pub fn patches(&self) -> &[(u64, Vec<u8>)] {
        &self.patches
    }

    // ── Search ────────────────────────────────────────────────────────────────

    /// Search for all occurrences of `pattern` in `haystack`.
    ///
    /// Returns byte offsets of each match.
    #[must_use]
    pub fn search_bytes(&self, haystack: &[u8], pattern: &[u8]) -> Vec<usize> {
        if pattern.is_empty() || haystack.len() < pattern.len() {
            return Vec::new();
        }
        let mut results = Vec::new();
        for i in 0..=haystack.len() - pattern.len() {
            if haystack[i..i + pattern.len()] == *pattern {
                results.push(i);
            }
        }
        results
    }

    /// Search for a byte pattern with wildcard bytes (`None` = any byte).
    #[must_use]
    pub fn search_pattern(&self, haystack: &[u8], pattern: &[Option<u8>]) -> Vec<usize> {
        if pattern.is_empty() || haystack.len() < pattern.len() {
            return Vec::new();
        }
        let mut results = Vec::new();
        'outer: for i in 0..=haystack.len() - pattern.len() {
            for (j, p) in pattern.iter().enumerate() {
                if let Some(expected) = p
                    && haystack[i + j] != *expected {
                        continue 'outer;
                    }
            }
            results.push(i);
        }
        results
    }

    // ── String extraction ─────────────────────────────────────────────────────

    /// Find all null-terminated ASCII strings of at least `min_length` bytes.
    #[must_use]
    pub fn find_strings(&self, data: &[u8], min_length: usize) -> Vec<FoundString> {
        let mut results = Vec::new();
        let mut start = 0usize;
        let mut current = String::new();
        for (i, &b) in data.iter().enumerate() {
            if b.is_ascii() && !b.is_ascii_control() || b == b'\t' || b == b'\r' || b == b'\n' {
                current.push(b as char);
            } else {
                if current.len() >= min_length {
                    results.push(FoundString {
                        offset: start,
                        value: current.clone(),
                        encoding: StringEncoding::Ascii,
                    });
                }
                current.clear();
                start = i + 1;
            }
        }
        if current.len() >= min_length {
            results.push(FoundString {
                offset: start,
                value: current,
                encoding: StringEncoding::Ascii,
            });
        }
        results
    }

    /// Find UTF-16LE strings of at least `min_length` characters.
    #[must_use]
    pub fn find_strings_utf16(&self, data: &[u8], min_length: usize) -> Vec<FoundString> {
        let mut results = Vec::new();
        if data.len() < 2 {
            return results;
        }
        let mut current = String::new();
        let mut start = 0usize;
        let mut i = 0usize;
        while i + 1 < data.len() {
            let codeunit = u16::from_le_bytes([data[i], data[i + 1]]);
            if codeunit == 0 {
                if current.chars().count() >= min_length {
                    results.push(FoundString {
                        offset: start,
                        value: current.clone(),
                        encoding: StringEncoding::Utf16Le,
                    });
                }
                current.clear();
                start = i + 2;
                i += 2;
                continue;
            }
            let unit_start = i;
            let mut units = [codeunit, 0u16];
            let mut units_len = 1usize;
            let mut consumed = 2usize;
            if (0xD800..=0xDBFF).contains(&codeunit) {
                if i + 3 < data.len() {
                    let low = u16::from_le_bytes([data[i + 2], data[i + 3]]);
                    if (0xDC00..=0xDFFF).contains(&low) {
                        units[1] = low;
                        units_len = 2;
                        consumed = 4;
                    } else {
                        current.clear();
                        start = i + 2;
                        i += 2;
                        continue;
                    }
                } else {
                    current.clear();
                    start = i + 2;
                    i += 2;
                    continue;
                }
            } else if (0xDC00..=0xDFFF).contains(&codeunit) {
                current.clear();
                start = i + 2;
                i += 2;
                continue;
            }
            if let Some(Ok(c)) = char::decode_utf16(units[..units_len].iter().copied()).next() {
                if current.is_empty() {
                    start = unit_start;
                }
                current.push(c);
                i += consumed;
            } else {
                current.clear();
                start = i + 2;
                i += 2;
            }
        }
        if current.chars().count() >= min_length {
            results.push(FoundString {
                offset: start,
                value: current,
                encoding: StringEncoding::Utf16Le,
            });
        }
        results
    }

    // ── Cross-references ──────────────────────────────────────────────────────

    /// Add a cross-reference record.
    pub fn add_xref(&mut self, xref: Xref) {
        self.xrefs.push(xref);
    }

    /// Return all xrefs pointing **to** `address`.
    #[must_use]
    pub fn get_xrefs_to(&self, address: u64) -> Vec<&Xref> {
        self.xrefs.iter().filter(|x| x.to == address).collect()
    }

    /// Return all xrefs originating **from** `address`.
    #[must_use]
    pub fn get_xrefs_from(&self, address: u64) -> Vec<&Xref> {
        self.xrefs.iter().filter(|x| x.from == address).collect()
    }

    // ── Functions ─────────────────────────────────────────────────────────────

    /// Add a function to the database.
    pub fn add_function(&mut self, func: ReFunction) {
        self.functions.push(func);
    }

    /// Return all functions.
    #[must_use]
    pub fn list_functions(&self) -> &[ReFunction] {
        &self.functions
    }

    /// Look up a function by address.
    #[must_use]
    pub fn get_function(&self, address: u64) -> Option<&ReFunction> {
        self.functions.iter().find(|f| f.address == address)
    }

    /// Rename a function.  Returns `true` if the function was found.
    pub fn rename_function(&mut self, address: u64, new_name: &str) -> bool {
        if let Some(f) = self.functions.iter_mut().find(|f| f.address == address) {
            f.name = new_name.to_string();
            f.flags |= FunctionFlags::RENAMED;
            return true;
        }
        false
    }

    /// Return a list of functions whose name contains `substr`.
    #[must_use]
    pub fn search_functions(&self, substr: &str) -> Vec<&ReFunction> {
        self.functions
            .iter()
            .filter(|f| f.name.contains(substr))
            .collect()
    }

    // ── Segments ──────────────────────────────────────────────────────────────

    /// Add a segment.
    pub fn add_segment(&mut self, seg: Segment) {
        self.segments.push(seg);
    }

    /// Return all segments.
    #[must_use]
    pub fn list_segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Find the segment containing `address`.
    #[must_use]
    pub fn segment_at(&self, address: u64) -> Option<&Segment> {
        self.segments
            .iter()
            .find(|s| address >= s.address && address < s.address + s.size)
    }

    // ── Comments and labels ───────────────────────────────────────────────────

    /// Set a comment at `address`.
    pub fn set_comment(&mut self, address: u64, comment: &str) {
        self.comments.insert(address, comment.to_string());
    }

    /// Get the comment at `address`, if any.
    #[must_use]
    pub fn get_comment(&self, address: u64) -> Option<&str> {
        self.comments.get(&address).map(String::as_str)
    }

    /// Set a label at `address`.
    pub fn set_label(&mut self, address: u64, label: &str) {
        self.labels.insert(address, label.to_string());
    }

    /// Get the label at `address`, if any.
    #[must_use]
    pub fn get_label(&self, address: u64) -> Option<&str> {
        self.labels.get(&address).map(String::as_str)
    }

    // ── Decompilation ─────────────────────────────────────────────────────────

    /// Return a best-effort C-style pseudocode skeleton for the function at
    /// `address`.
    ///
    /// The result weaves together the known function metadata, the enclosing
    /// segment, any user-attached label/comment and the recorded outgoing
    /// cross-references.  When no metadata is available the function still
    /// produces a syntactically valid stub so downstream consumers can render
    /// it without special-casing.
    #[must_use]
    pub fn decompile(&self, address: u64) -> String {
        use std::fmt::Write as _;
        let func = self.get_function(address);
        let name = func
            .map(|f| f.name.clone())
            .or_else(|| self.get_label(address).map(String::from))
            .unwrap_or_else(|| format!("sub_{address:08x}"));
        let mut out = String::new();
        let _ = writeln!(out, "// Decompiled {name} @ {address:#x}");
        if let Some(seg) = self.segment_at(address) {
            let _ = writeln!(out, "// Segment: {} ({}) base={:#x} size={}", seg.name, seg.kind, seg.address, seg.size);
        }
        if let Some(c) = self.get_comment(address) {
            let _ = writeln!(out, "// {c}");
        }
        let mut attrs: Vec<&'static str> = Vec::new();
        if let Some(f) = func {
            if f.is_noreturn() {
                attrs.push("noreturn");
            }
            if f.is_imported() {
                attrs.push("imported");
            }
        }
        let attr_prefix = if attrs.is_empty() {
            String::new()
        } else {
            format!("/* {} */ ", attrs.join(", "))
        };
        let _ = writeln!(out, "{attr_prefix}int64_t {name}(void) {{");
        let xrefs_in = self.get_xrefs_to(address);
        if !xrefs_in.is_empty() {
            let _ = writeln!(out, "    // {} incoming xref(s)", xrefs_in.len());
        }
        let xrefs_out = self.get_xrefs_from(address);
        for x in xrefs_out.iter().take(8) {
            let _ = writeln!(out, "    {}({:#x});", x.kind, x.to);
        }
        if xrefs_out.len() > 8 {
            let _ = writeln!(out, "    // {} additional call(s) elided", xrefs_out.len() - 8);
        }
        if let Some(f) = func {
            let _ = writeln!(out, "    return 0; // size={} bytes", f.size);
        } else {
            out.push_str("    return 0;\n");
        }
        out.push_str("}\n");
        out
    }

    // ── Analysis ─────────────────────────────────────────────────────────────

    /// Analyse `bytes` and return a summary of discovered information.
    #[must_use]
    pub fn analyse(&self, base: u64, bytes: &[u8]) -> AnalysisResult {
        let instructions = self.disassemble(base, bytes);
        let strings = self.find_strings(bytes, 4);
        let call_targets: Vec<u64> = instructions
            .iter()
            .filter(|i| i.mnemonic == "call" || i.mnemonic == "jmp")
            .filter_map(|i| {
                i.operands
                    .strip_prefix("0x")
                    .and_then(|h| u64::from_str_radix(h, 16).ok())
            })
            .collect();
        AnalysisResult {
            instruction_count: instructions.len(),
            string_count: strings.len(),
            call_targets,
            instructions,
            strings,
        }
    }
}

/// Result of an analysis pass.
#[derive(Debug)]
pub struct AnalysisResult {
    /// Total instructions disassembled.
    pub instruction_count: usize,
    /// Strings found.
    pub string_count: usize,
    /// Unique call/jump targets.
    pub call_targets: Vec<u64>,
    /// Disassembled instructions.
    pub instructions: Vec<Instruction>,
    /// Found strings.
    pub strings: Vec<FoundString>,
}

// ── Sandboxing ────────────────────────────────────────────────────────────────

/// Script sandbox policy.
#[derive(Debug, Clone)]
pub enum SandboxPolicy {
    /// Only names in this list are permitted.
    AllowList(Vec<String>),
    /// Names in this list are forbidden; all others are permitted.
    DenyList(Vec<String>),
    /// All calls are permitted (no sandboxing).
    Unrestricted,
}

/// Script execution sandbox.
#[derive(Debug, Clone)]
pub struct Sandbox {
    policy: SandboxPolicy,
}

impl Sandbox {
    /// Create a sandbox with the given policy.
    #[must_use]
    pub const fn new(policy: SandboxPolicy) -> Self {
        Self { policy }
    }

    /// Return `true` if `name` is allowed under the active policy.
    #[must_use]
    pub fn is_allowed(&self, name: &str) -> bool {
        match &self.policy {
            SandboxPolicy::AllowList(list) => list.iter().any(|s| s == name),
            SandboxPolicy::DenyList(list) => !list.iter().any(|s| s == name),
            SandboxPolicy::Unrestricted => true,
        }
    }

    /// Filter a list of function names, returning only permitted ones.
    #[must_use]
    pub fn filter_allowed<'a>(&self, names: &[&'a str]) -> Vec<&'a str> {
        names
            .iter()
            .filter(|n| self.is_allowed(n))
            .copied()
            .collect()
    }
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::new(SandboxPolicy::Unrestricted)
    }
}

// ── Module registry ───────────────────────────────────────────────────────────

/// Registry that maps module names to their source or description.
#[derive(Debug, Default)]
pub struct ModuleRegistry {
    modules: HashMap<String, String>,
}

impl ModuleRegistry {
    /// Create a new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a module by name.
    pub fn register(&mut self, name: &str, content: String) {
        self.modules.insert(name.to_string(), content);
    }

    /// Look up a module by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.modules.get(name).map(String::as_str)
    }

    /// Return all registered module names.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.modules.keys().map(String::as_str).collect()
    }
}

// ── Batch execution ───────────────────────────────────────────────────────────

/// Run multiple Python scripts sequentially against a shared scope.
#[derive(Debug, Default)]
pub struct BatchRunner {
    scripts: Vec<String>,
}

impl BatchRunner {
    /// Create a new batch runner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a script to the batch.
    pub fn add_script(&mut self, script: String) {
        self.scripts.push(script);
    }

    /// Return the number of scripts queued.
    #[must_use]
    pub const fn script_count(&self) -> usize {
        self.scripts.len()
    }

    /// Execute all scripts in sequence against a shared scope.
    ///
    /// # Errors
    ///
    /// Returns the first [`PythonError`] encountered and the index of the
    /// failing script.
    pub fn run_all(
        &self,
        engine: &mut PythonEngine,
        scope: &mut PyScope,
    ) -> Result<Vec<PyValue>, (usize, PythonError)> {
        let mut results = Vec::with_capacity(self.scripts.len());
        for (i, script) in self.scripts.iter().enumerate() {
            let val = engine.execute(script, scope).map_err(|e| (i, e))?;
            results.push(val);
        }
        Ok(results)
    }

    /// Execute all scripts, collecting both successes and errors.
    pub fn run_all_tolerant(
        &self,
        engine: &mut PythonEngine,
        scope: &mut PyScope,
    ) -> Vec<Result<PyValue, PythonError>> {
        self.scripts
            .iter()
            .map(|s| engine.execute(s, scope))
            .collect()
    }
}

// ── Progress reporting ────────────────────────────────────────────────────────

/// Simple progress reporter for batch operations.
pub struct ProgressReporter {
    total: usize,
    done: usize,
    callbacks: Vec<Box<dyn Fn(usize, usize) + Send>>,
}

impl fmt::Debug for ProgressReporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProgressReporter")
            .field("total", &self.total)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl ProgressReporter {
    /// Create a reporter for `total` work items.
    #[must_use]
    pub fn new(total: usize) -> Self {
        Self {
            total,
            done: 0,
            callbacks: Vec::new(),
        }
    }

    /// Register a callback `f(done, total)`.
    pub fn on_progress(&mut self, f: impl Fn(usize, usize) + Send + 'static) {
        self.callbacks.push(Box::new(f));
    }

    /// Advance by `n` items, firing all callbacks.
    pub fn advance(&mut self, n: usize) {
        self.done = (self.done + n).min(self.total);
        let (d, t) = (self.done, self.total);
        for cb in &self.callbacks {
            cb(d, t);
        }
    }

    /// Return completion as an integer percentage 0-100.
    #[must_use]
    pub const fn percent(&self) -> usize {
        if self.total == 0 {
            return 100;
        }
        self.done * 100 / self.total
    }

    /// Return `true` when all work is done.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.done >= self.total
    }

    /// Reset to zero.
    pub const fn reset(&mut self) {
        self.done = 0;
    }
}

// ── Script templates ──────────────────────────────────────────────────────────

/// Canned Python script templates for common RE tasks.
pub struct ScriptTemplate;

impl ScriptTemplate {
    /// Script that finds all cross-references to `target_address`.
    #[must_use]
    pub fn find_xrefs(target_address: u64) -> String {
        format!(
            r#"# Find all xrefs to {target_address:#x}
target = {target_address:#x}
results = []
for xref in get_xrefs_to(target):
    results.append(xref)
print("Found", len(results), "xrefs to", hex(target))
"#
        )
    }

    /// Script that extracts all printable strings from binary data.
    #[must_use]
    pub fn extract_strings() -> String {
        r#"# Extract all strings from the current binary
strings = find_strings(min_length=4)
for s in strings:
    print(hex(s.offset), s.value)
print("Total strings:", len(strings))
"#
        .to_string()
    }

    /// Script that renames all functions matching `old_prefix`.
    #[must_use]
    pub fn rename_functions(old_prefix: &str, new_prefix: &str) -> String {
        format!(
            r#"# Rename functions: '{old_prefix}' -> '{new_prefix}'
count = 0
for func in list_functions():
    if func.name.startswith("{old_prefix}"):
        new_name = "{new_prefix}" + func.name[{prefix_len}:]
        rename_function(func.address, new_name)
        count += 1
print("Renamed", count, "functions")
"#,
            old_prefix = old_prefix,
            new_prefix = new_prefix,
            prefix_len = old_prefix.len()
        )
    }

    /// Script that patches all occurrences of `from_bytes` with `to_bytes`.
    #[must_use]
    pub fn patch_pattern(from_bytes: &[u8], to_bytes: &[u8]) -> String {
        let from_hex: Vec<String> = from_bytes.iter().map(|b| format!("{b:#04x}")).collect();
        let to_hex: Vec<String> = to_bytes.iter().map(|b| format!("{b:#04x}")).collect();
        format!(
            r#"# Patch pattern occurrences
from_bytes = [{from_list}]
to_bytes = [{to_list}]
hits = search_bytes(from_bytes)
for offset in hits:
    patch_bytes(offset, to_bytes)
print("Patched", len(hits), "occurrences")
"#,
            from_list = from_hex.join(", "),
            to_list = to_hex.join(", ")
        )
    }

    /// Script that dumps the function list to output.
    #[must_use]
    pub fn dump_functions() -> String {
        r#"# Dump all known functions
funcs = list_functions()
for f in funcs:
    print(hex(f.address), f.name, f.size)
print("Total functions:", len(funcs))
"#
        .to_string()
    }

    /// Script that adds comments to all call sites of `target`.
    #[must_use]
    pub fn annotate_call_sites(target: u64, comment: &str) -> String {
        format!(
            r#"# Annotate all call sites of {target:#x}
target = {target:#x}
for xref in get_xrefs_to(target):
    set_comment(xref.from, "{comment}")
print("Annotated call sites")
"#
        )
    }

    /// Script that finds functions containing a specific byte sequence.
    #[must_use]
    pub fn find_functions_with_bytes(pattern: &[u8]) -> String {
        let hex: Vec<String> = pattern.iter().map(|b| format!("{b:#04x}")).collect();
        format!(
            r"# Find functions containing byte pattern
pattern = [{hex_list}]
for func in list_functions():
    data = read_bytes(func.address, func.size)
    if search_bytes(data, pattern):
        print(hex(func.address), func.name)
",
            hex_list = hex.join(", ")
        )
    }
}

// ── Type marshalling helpers ───────────────────────────────────────────────────

/// Convert a [`PyValue`] to a virtual address, accepting integers and hex strings.
#[must_use]
pub fn marshal_to_address(v: &PyValue) -> Option<u64> {
    match v {
        PyValue::Int(i) => u64::try_from(*i).ok(),
        PyValue::Str(s) => {
            let s = s.trim();
            s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).map_or_else(|| s.parse::<u64>().ok(), |hex| u64::from_str_radix(hex, 16).ok())
        }
        _ => None,
    }
}

/// Convert a [`PyValue`] to a byte vector.
#[must_use]
pub fn marshal_to_bytes(v: &PyValue) -> Option<Vec<u8>> {
    match v {
        PyValue::Bytes(b) => Some(b.clone()),
        PyValue::List(l) => l
            .iter()
            .map(|item| item.as_int().and_then(|i| u8::try_from(i).ok()))
            .collect(),
        PyValue::Str(s) => Some(s.as_bytes().to_vec()),
        _ => None,
    }
}

/// Convert an [`Instruction`] to a [`PyValue::Dict`].
#[must_use]
pub fn instruction_to_pyvalue(insn: &Instruction) -> PyValue {
    PyValue::Dict(vec![
        (
            PyValue::Str("address".to_string()),
            PyValue::Int(insn.address.cast_signed()),
        ),
        (
            PyValue::Str("mnemonic".to_string()),
            PyValue::Str(insn.mnemonic.clone()),
        ),
        (
            PyValue::Str("operands".to_string()),
            PyValue::Str(insn.operands.clone()),
        ),
        (
            PyValue::Str("size".to_string()),
            PyValue::Int(i64::try_from(insn.size).unwrap_or(0)),
        ),
        (
            PyValue::Str("bytes".to_string()),
            PyValue::Bytes(insn.bytes.clone()),
        ),
    ])
}

/// Convert a [`ReFunction`] to a [`PyValue::Dict`].
#[must_use]
pub fn function_to_pyvalue(func: &ReFunction) -> PyValue {
    PyValue::Dict(vec![
        (
            PyValue::Str("address".to_string()),
            PyValue::Int(func.address.cast_signed()),
        ),
        (
            PyValue::Str("name".to_string()),
            PyValue::Str(func.name.clone()),
        ),
        (
            PyValue::Str("size".to_string()),
            PyValue::Int(func.size.cast_signed()),
        ),
        (
            PyValue::Str("is_renamed".to_string()),
            PyValue::Bool(func.is_renamed()),
        ),
        (
            PyValue::Str("is_imported".to_string()),
            PyValue::Bool(func.is_imported()),
        ),
    ])
}

/// Convert a [`FoundString`] to a [`PyValue::Dict`].
#[must_use]
pub fn found_string_to_pyvalue(s: &FoundString) -> PyValue {
    PyValue::Dict(vec![
        (
            PyValue::Str("offset".to_string()),
            PyValue::Int(i64::try_from(s.offset).unwrap_or(0)),
        ),
        (
            PyValue::Str("value".to_string()),
            PyValue::Str(s.value.clone()),
        ),
        (
            PyValue::Str("encoding".to_string()),
            PyValue::Str(s.encoding.to_string()),
        ),
    ])
}

/// Convert a [`Xref`] to a [`PyValue::Dict`].
#[must_use]
pub fn xref_to_pyvalue(x: &Xref) -> PyValue {
    PyValue::Dict(vec![
        (
            PyValue::Str("from".to_string()),
            PyValue::Int(x.from.cast_signed()),
        ),
        (PyValue::Str("to".to_string()), PyValue::Int(x.to.cast_signed())),
        (
            PyValue::Str("kind".to_string()),
            PyValue::Str(x.kind.to_string()),
        ),
    ])
}

// ── PythonEngine with RE API integration ──────────────────────────────────────

/// A Python engine that has an [`ReApi`] instance wired in.
///
/// Scripts can call `disassemble(addr, bytes_list)`, `patch_bytes(offset,
/// data)`, `find_strings(min_length)`, `get_xrefs_to(addr)`,
/// `list_functions()`, `rename_function(addr, name)`, `search_bytes(data,
/// pattern)`, `read_bytes(addr, count)`, `set_comment(addr, text)`,
/// `decompile(addr)` and `analyse(addr, bytes_list)` as top-level built-ins.
pub struct ReScriptEngine {
    engine: PythonEngine,
    api: ReApi,
    /// Active sandbox policy governing which built-ins may be called.
    pub sandbox: Sandbox,
}

impl fmt::Debug for ReScriptEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReScriptEngine")
    }
}

impl ReScriptEngine {
    /// Create a new RE-aware script engine.
    #[must_use]
    pub fn new() -> Self {
        Self {
            engine: PythonEngine::new(),
            api: ReApi::new(),
            sandbox: Sandbox::default(),
        }
    }

    /// Create a sandboxed engine with a custom policy.
    #[must_use]
    pub fn with_sandbox(policy: SandboxPolicy) -> Self {
        Self {
            engine: PythonEngine::new(),
            api: ReApi::new(),
            sandbox: Sandbox::new(policy),
        }
    }

    /// Return a reference to the inner RE API.
    #[must_use]
    pub const fn api(&self) -> &ReApi {
        &self.api
    }

    /// Return a mutable reference to the inner RE API.
    pub const fn api_mut(&mut self) -> &mut ReApi {
        &mut self.api
    }

    /// Execute a script with RE bindings pre-injected into the scope.
    ///
    /// # Errors
    ///
    /// Returns [`PythonError`] on any script error.
    pub fn execute(&mut self, script: &str) -> Result<(PyValue, PyScope), PythonError> {
        let mut scope = PyScope::new();
        // Inject RE built-in markers.
        for name in &[
            "disassemble",
            "disassemble_one",
            "patch_bytes",
            "find_strings",
            "find_strings_utf16",
            "get_xrefs_to",
            "get_xrefs_from",
            "list_functions",
            "get_function",
            "search_functions",
            "rename_function",
            "list_segments",
            "segment_at",
            "read_bytes",
            "search_bytes",
            "search_pattern",
            "set_comment",
            "get_comment",
            "set_label",
            "get_label",
            "decompile",
            "analyse",
        ] {
            scope
                .locals
                .insert((*name).to_string(), PyValue::Function((*name).to_string()));
        }
        let val = self.engine.execute(script, &mut scope)?;
        Ok((val, scope))
    }

    /// Set the step limit for script execution.
    pub const fn set_max_steps(&mut self, n: u64) {
        self.engine.set_max_steps(n);
    }
}

impl Default for ReScriptEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Minimal x86 decode helper ─────────────────────────────────────────────────

/// Extremely simplified x86-64 one-byte opcode decode returning
/// (mnemonic, operands, size).  Only covers the most common prologue/epilogue
/// bytes used in tests and basic RE scripts.
fn decode_x86_simple<'a>(byte: u8, bytes: &[u8], offset: usize) -> (&'a str, &'a str, usize) {
    match byte {
        0x55 => ("push", "rbp", 1),
        0x5D => ("pop", "rbp", 1),
        0xC3 => ("ret", "", 1),
        0x90 => ("nop", "", 1),
        0xCC => ("int3", "", 1),
        0x50 => ("push", "rax", 1),
        0x51 => ("push", "rcx", 1),
        0x52 => ("push", "rdx", 1),
        0x53 => ("push", "rbx", 1),
        0x56 => ("push", "rsi", 1),
        0x57 => ("push", "rdi", 1),
        0x58 => ("pop", "rax", 1),
        0x59 => ("pop", "rcx", 1),
        0x5A => ("pop", "rdx", 1),
        0x5B => ("pop", "rbx", 1),
        0x5E => ("pop", "rsi", 1),
        0x5F => ("pop", "rdi", 1),
        // REX prefix family — consume 1 extra byte
        0x40..=0x4F => {
            if offset + 1 < bytes.len() {
                let (mn, op, _) = decode_x86_simple(bytes[offset + 1], bytes, offset + 1);
                // Return with size 2 but we need 'static lifetimes; just label
                // the prefixed instruction as "rex+X"
                let _ = (mn, op); // suppress unused
            }
            ("rex", "", 1)
        }
        // call rel32
        0xE8 => ("call", "rel32", 5),
        // jmp rel32
        0xE9 => ("jmp", "rel32", 5),
        // jmp rel8
        0xEB => ("jmp", "rel8", 2),
        // je rel8
        0x74 => ("je", "rel8", 2),
        // jne rel8
        0x75 => ("jne", "rel8", 2),
        // jl / jge rel8
        0x7C => ("jl", "rel8", 2),
        0x7D => ("jge", "rel8", 2),
        // xor reg,reg
        0x31 => ("xor", "r/m32, r32", 2),
        0x33 => ("xor", "r32, r/m32", 2),
        // mov r/m, r  (common 2-byte)
        0x89 => ("mov", "r/m, reg", 2),
        0x8B => ("mov", "reg, r/m", 2),
        // add / sub imm8
        0x83 => ("alu", "r/m, imm8", 3),
        // cmp
        0x3B => ("cmp", "r32, r/m32", 2),
        0x3C => ("cmp", "al, imm8", 2),
        // lea
        0x8D => ("lea", "reg, mem", 2),
        // other — unknown 1-byte
        _ => ("db", "", 1),
    }
}
