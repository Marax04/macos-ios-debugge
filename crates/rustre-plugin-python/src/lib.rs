//! `rustre-plugin-python`
//!
//! Python integration layer for RustRE plugins: exposes the RE platform
//! via a native Python module, bridges Rust and Python type systems, and
//! provides structured Python error handling.

pub mod python_re_module;
pub mod python_type_bridge;
pub mod python_error_handler;

pub use python_error_handler::{ErrorContext, PyError, PythonErrorHandler};
pub use python_re_module::{PyClass, PyFunction, PythonReModule};
pub use python_type_bridge::{PyToRust, PythonTypeBridge, RustToPy};
