// rustre-plugin-python/src/python_type_bridge.rs
//
// Bidirectional conversion between Rust and Python values.

use pyo3::prelude::*;
use pyo3::types::{PyBool, PyBytes, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use std::collections::HashMap;

/// Maximum nesting depth for Python ↔ Rust value conversion.
/// Prevents stack overflow when converting deeply nested structures from
/// untrusted input (e.g. a Python object built by adversarial script code).
const MAX_BRIDGE_DEPTH: usize = 64;

// ── BridgeValue ──────────────────────────────────────────────────────────────

/// A language-agnostic value that can be moved across the Rust/Python boundary.
#[derive(Debug, Clone, PartialEq)]
pub enum BridgeValue {
    None,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    List(Vec<BridgeValue>),
    Tuple(Vec<BridgeValue>),
    Dict(HashMap<String, BridgeValue>),
}

impl BridgeValue {
    /// Short type name for diagnostics.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::None => "None",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::Str(_) => "str",
            Self::Bytes(_) => "bytes",
            Self::List(_) => "list",
            Self::Tuple(_) => "tuple",
            Self::Dict(_) => "dict",
        }
    }
}

// ── RustToPy / PyToRust traits ───────────────────────────────────────────────

/// Convert a Rust [`BridgeValue`] into a Python object.
pub trait RustToPy {
    /// Convert `self` into a Python object bound to `py`.
    ///
    /// # Errors
    ///
    /// Returns a `PyErr` if any Python allocation or conversion fails.
    fn to_py<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>>;
}

/// Convert a Python object into a Rust [`BridgeValue`].
pub trait PyToRust {
    /// Convert `obj` into a [`BridgeValue`].
    ///
    /// # Errors
    ///
    /// Returns a `PyErr` if any object cannot be downcast or extracted.
    fn from_py(obj: &Bound<'_, PyAny>) -> PyResult<Self>
    where
        Self: Sized;
}

impl BridgeValue {
    /// Depth-bounded conversion to Python. Called recursively; `depth` counts
    /// how many container levels we have already entered.
    fn to_py_inner<'py>(&self, py: Python<'py>, depth: usize) -> PyResult<Bound<'py, PyAny>> {
        if depth > MAX_BRIDGE_DEPTH {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "BridgeValue nesting depth exceeds MAX_BRIDGE_DEPTH (64): \
                 possible adversarial input",
            ));
        }
        match self {
            Self::None => Ok(py.None().into_bound(py)),
            Self::Bool(b) => Ok(PyBool::new(py, *b).to_owned().into_any()),
            Self::Int(i) => Ok(i.into_pyobject(py)?.into_any()),
            Self::Float(f) => Ok(f.into_pyobject(py)?.into_any()),
            Self::Str(s) => Ok(PyString::new(py, s).into_any()),
            Self::Bytes(b) => Ok(PyBytes::new(py, b).into_any()),
            Self::List(items) => {
                let list = PyList::empty(py);
                for v in items {
                    list.append(v.to_py_inner(py, depth + 1)?)?;
                }
                Ok(list.into_any())
            }
            Self::Tuple(items) => {
                let mut py_items: Vec<Bound<'py, PyAny>> = Vec::with_capacity(items.len());
                for v in items {
                    py_items.push(v.to_py_inner(py, depth + 1)?);
                }
                Ok(PyTuple::new(py, py_items)?.into_any())
            }
            Self::Dict(map) => {
                let d = PyDict::new(py);
                for (k, v) in map {
                    d.set_item(k.as_str(), v.to_py_inner(py, depth + 1)?)?;
                }
                Ok(d.into_any())
            }
        }
    }

    /// Depth-bounded conversion from Python. Called recursively; `depth` counts
    /// how many container levels we have already entered.
    fn from_py_inner(obj: &Bound<'_, PyAny>, depth: usize) -> PyResult<Self> {
        if depth > MAX_BRIDGE_DEPTH {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "Python object nesting depth exceeds MAX_BRIDGE_DEPTH (64): \
                 possible adversarial input",
            ));
        }
        if obj.is_none() {
            return Ok(Self::None);
        }
        if let Ok(b) = obj.downcast::<PyBool>() {
            return Ok(Self::Bool(b.is_true()));
        }
        if let Ok(i) = obj.downcast::<PyInt>() {
            return Ok(Self::Int(i.extract()?));
        }
        if let Ok(f) = obj.downcast::<PyFloat>() {
            return Ok(Self::Float(f.extract()?));
        }
        if let Ok(s) = obj.downcast::<PyString>() {
            return Ok(Self::Str(s.to_str()?.to_string()));
        }
        if let Ok(b) = obj.downcast::<PyBytes>() {
            return Ok(Self::Bytes(b.as_bytes().to_vec()));
        }
        if let Ok(t) = obj.downcast::<PyTuple>() {
            let mut out = Vec::with_capacity(t.len());
            for item in t.iter() {
                out.push(Self::from_py_inner(&item, depth + 1)?);
            }
            return Ok(Self::Tuple(out));
        }
        if let Ok(l) = obj.downcast::<PyList>() {
            let mut out = Vec::with_capacity(l.len());
            for item in l.iter() {
                out.push(Self::from_py_inner(&item, depth + 1)?);
            }
            return Ok(Self::List(out));
        }
        if let Ok(d) = obj.downcast::<PyDict>() {
            let mut out = HashMap::with_capacity(d.len());
            for (k, v) in d.iter() {
                let key: String = k.extract()?;
                out.insert(key, Self::from_py_inner(&v, depth + 1)?);
            }
            return Ok(Self::Dict(out));
        }
        // Fallback: stringify.
        Ok(Self::Str(obj.str()?.to_string()))
    }
}

impl RustToPy for BridgeValue {
    fn to_py<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.to_py_inner(py, 0)
    }
}

impl PyToRust for BridgeValue {
    fn from_py(obj: &Bound<'_, PyAny>) -> PyResult<Self> {
        Self::from_py_inner(obj, 0)
    }
}

// ── PythonTypeBridge ─────────────────────────────────────────────────────────

/// High-level wrapper that performs the common conversion patterns.
#[derive(Debug, Default)]
pub struct PythonTypeBridge;

impl PythonTypeBridge {
    /// Convert a Rust value into a Python object.
    ///
    /// # Errors
    ///
    /// Forwards PyO3 conversion failures.
    pub fn to_python<'py>(py: Python<'py>, v: &BridgeValue) -> PyResult<Bound<'py, PyAny>> {
        v.to_py(py)
    }

    /// Convert a Python object into a Rust [`BridgeValue`].
    ///
    /// # Errors
    ///
    /// Forwards PyO3 conversion failures.
    pub fn from_python(obj: &Bound<'_, PyAny>) -> PyResult<BridgeValue> {
        BridgeValue::from_py(obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_names() {
        assert_eq!(BridgeValue::None.type_name(), "None");
        assert_eq!(BridgeValue::Bool(true).type_name(), "bool");
        assert_eq!(BridgeValue::Int(0).type_name(), "int");
        assert_eq!(BridgeValue::Float(0.0).type_name(), "float");
        assert_eq!(BridgeValue::Str(String::new()).type_name(), "str");
        assert_eq!(BridgeValue::Bytes(Vec::new()).type_name(), "bytes");
    }

    #[test]
    fn roundtrip_int() {
        Python::with_gil(|py| {
            let v = BridgeValue::Int(42);
            let obj = v.to_py(py).unwrap();
            let back = BridgeValue::from_py(&obj).unwrap();
            assert_eq!(back, BridgeValue::Int(42));
        });
    }

    #[test]
    fn roundtrip_str() {
        Python::with_gil(|py| {
            let v = BridgeValue::Str("hello".to_string());
            let obj = v.to_py(py).unwrap();
            let back = BridgeValue::from_py(&obj).unwrap();
            assert_eq!(back, BridgeValue::Str("hello".to_string()));
        });
    }

    #[test]
    fn roundtrip_list() {
        Python::with_gil(|py| {
            let v =
                BridgeValue::List(vec![BridgeValue::Int(1), BridgeValue::Int(2), BridgeValue::Int(3)]);
            let obj = v.to_py(py).unwrap();
            let back = BridgeValue::from_py(&obj).unwrap();
            assert_eq!(back, v);
        });
    }

    #[test]
    fn roundtrip_dict() {
        Python::with_gil(|py| {
            let mut map = HashMap::new();
            map.insert("k".to_string(), BridgeValue::Int(1));
            let v = BridgeValue::Dict(map);
            let obj = v.to_py(py).unwrap();
            let back = BridgeValue::from_py(&obj).unwrap();
            assert_eq!(back, v);
        });
    }

    #[test]
    fn none_roundtrip() {
        Python::with_gil(|py| {
            let v = BridgeValue::None;
            let obj = v.to_py(py).unwrap();
            let back = BridgeValue::from_py(&obj).unwrap();
            assert_eq!(back, BridgeValue::None);
        });
    }
}
