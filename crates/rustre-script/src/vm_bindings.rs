//! `vm_bindings` — VM-agnostic script bindings.
//!
//! This module provides the low-level value and function representation layer
//! that sits between a scripting VM (Rhai, Lua, Python, …) and the `RustRE`
//! host.  It is deliberately independent of any specific VM crate.
//!
//! # Types
//!
//! * [`ScriptValue`] — already defined in the crate root; re-exported here for
//!   convenience.
//! * [`VmValue`] — the canonical "VM wire type" used at the binding boundary.
//!   Intentionally isomorphic to [`ScriptValue`] but with explicit From/Into
//!   conversions.
//! * [`ScriptFunction`] — a named, arity-annotated callable.
//! * [`ScriptCallable`] — trait for objects that can be called from scripts.
//! * Type-conversion helpers: `try_into_*`, `coerce_*`.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use crate::{ScriptError, ScriptValue};

// ─── VmValue ─────────────────────────────────────────────────────────────────

/// The canonical VM wire value.
///
/// Structurally identical to [`ScriptValue`] but lives in this module so that
/// VM adapter crates can depend on `rustre-script` without needing to import
/// the full crate root.
#[derive(Debug, Clone, PartialEq)]
pub enum VmValue {
    /// No value / nil.
    Null,
    /// Boolean.
    Bool(bool),
    /// Signed 64-bit integer.
    Int(i64),
    /// 64-bit floating-point.
    Float(f64),
    /// UTF-8 string.
    String(String),
    /// Opaque byte array.
    Bytes(Vec<u8>),
    /// Ordered list.
    List(Vec<Self>),
    /// String-keyed map.
    Map(HashMap<String, Self>),
    /// Virtual address.
    Address(u64),
    /// Reference to a named callable.
    Callable(String),
}

impl VmValue {
    /// Return the type name as a static string.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::String(_) => "string",
            Self::Bytes(_) => "bytes",
            Self::List(_) => "list",
            Self::Map(_) => "map",
            Self::Address(_) => "address",
            Self::Callable(_) => "callable",
        }
    }

    /// Return `true` if the value is logically truthy.
    #[must_use]
    pub fn is_truthy(&self) -> bool {
        match self {
            Self::Null => false,
            Self::Bool(b) => *b,
            Self::Int(n) => *n != 0,
            Self::Float(f) => *f != 0.0,
            Self::String(s) => !s.is_empty(),
            Self::Bytes(b) => !b.is_empty(),
            Self::List(l) => !l.is_empty(),
            Self::Map(m) => !m.is_empty(),
            Self::Address(_) | Self::Callable(_) => true,
        }
    }

    /// Coerce to `i64`.
    ///
    /// # Errors
    /// Returns `ScriptError::TypeMismatch` when coercion is not possible.
    pub fn as_int(&self) -> Result<i64, ScriptError> {
        match self {
            Self::Int(n) => Ok(*n),
            Self::Float(f) => Ok(*f as i64),
            Self::Bool(b) => Ok(i64::from(*b)),
            other => Err(ScriptError::TypeMismatch {
                expected: "int".into(),
                got: other.type_name().into(),
            }),
        }
    }

    /// Coerce to `f64`.
    ///
    /// # Errors
    /// Returns `ScriptError::TypeMismatch` when coercion is not possible.
    pub fn as_float(&self) -> Result<f64, ScriptError> {
        match self {
            Self::Float(f) => Ok(*f),
            Self::Int(n) => Ok(*n as f64),
            Self::Bool(b) => Ok(if *b { 1.0 } else { 0.0 }),
            other => Err(ScriptError::TypeMismatch {
                expected: "float".into(),
                got: other.type_name().into(),
            }),
        }
    }

    /// Borrow the inner string.
    ///
    /// # Errors
    /// Returns `ScriptError::TypeMismatch` when the value is not a string.
    pub fn as_str(&self) -> Result<&str, ScriptError> {
        match self {
            Self::String(s) => Ok(s.as_str()),
            other => Err(ScriptError::TypeMismatch {
                expected: "string".into(),
                got: other.type_name().into(),
            }),
        }
    }

    /// Borrow the inner bytes.
    ///
    /// # Errors
    /// Returns `ScriptError::TypeMismatch` when the value is not bytes.
    pub fn as_bytes(&self) -> Result<&[u8], ScriptError> {
        match self {
            Self::Bytes(b) => Ok(b.as_slice()),
            other => Err(ScriptError::TypeMismatch {
                expected: "bytes".into(),
                got: other.type_name().into(),
            }),
        }
    }

    /// Coerce to `bool`.
    ///
    /// # Errors
    /// Returns `ScriptError::TypeMismatch` when the value is not a bool.
    pub fn as_bool(&self) -> Result<bool, ScriptError> {
        match self {
            Self::Bool(b) => Ok(*b),
            other => Err(ScriptError::TypeMismatch {
                expected: "bool".into(),
                got: other.type_name().into(),
            }),
        }
    }

    /// Coerce to a `u64` address.
    ///
    /// # Errors
    /// Returns `ScriptError::TypeMismatch` when the value is not an address or int.
    pub fn as_address(&self) -> Result<u64, ScriptError> {
        match self {
            Self::Address(a) => Ok(*a),
            Self::Int(n) => Ok(*n as u64),
            other => Err(ScriptError::TypeMismatch {
                expected: "address".into(),
                got: other.type_name().into(),
            }),
        }
    }

    /// Return `true` if this is `VmValue::Null`.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

impl fmt::Display for VmValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => write!(f, "null"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(n) => write!(f, "{n}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::String(s) => write!(f, "{s}"),
            Self::Bytes(b) => write!(f, "bytes({})", b.len()),
            Self::List(l) => write!(f, "list({})", l.len()),
            Self::Map(m) => write!(f, "map({})", m.len()),
            Self::Address(a) => write!(f, "0x{a:x}"),
            Self::Callable(n) => write!(f, "<fn:{n}>"),
        }
    }
}

// ─── VmValue ↔ ScriptValue conversions ────────────────────────────────────────

impl From<VmValue> for ScriptValue {
    fn from(v: VmValue) -> Self {
        match v {
            VmValue::Null => Self::Null,
            VmValue::Bool(b) => Self::Bool(b),
            VmValue::Int(n) => Self::Int(n),
            VmValue::Float(f) => Self::Float(f),
            VmValue::String(s) => Self::String(s),
            VmValue::Bytes(b) => Self::Bytes(b),
            VmValue::Address(a) => Self::Address(a),
            VmValue::Callable(n) => Self::Callable(n),
            VmValue::List(l) => Self::List(l.into_iter().map(Into::into).collect()),
            VmValue::Map(m) => Self::Map(m.into_iter().map(|(k, v)| (k, v.into())).collect()),
        }
    }
}

impl From<ScriptValue> for VmValue {
    fn from(v: ScriptValue) -> Self {
        match v {
            ScriptValue::Null => Self::Null,
            ScriptValue::Bool(b) => Self::Bool(b),
            ScriptValue::Int(n) => Self::Int(n),
            ScriptValue::Float(f) => Self::Float(f),
            ScriptValue::String(s) => Self::String(s),
            ScriptValue::Bytes(b) => Self::Bytes(b),
            ScriptValue::Address(a) => Self::Address(a),
            ScriptValue::Callable(n) => Self::Callable(n),
            ScriptValue::List(l) => Self::List(l.into_iter().map(Self::from).collect()),
            ScriptValue::Map(m) => {
                Self::Map(m.into_iter().map(|(k, v)| (k, Self::from(v))).collect())
            }
        }
    }
}

// ─── Primitive From impls ─────────────────────────────────────────────────────

impl From<i64> for VmValue {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}
impl From<i32> for VmValue {
    fn from(v: i32) -> Self {
        Self::Int(i64::from(v))
    }
}
impl From<u32> for VmValue {
    fn from(v: u32) -> Self {
        Self::Int(i64::from(v))
    }
}
impl From<f64> for VmValue {
    fn from(v: f64) -> Self {
        Self::Float(v)
    }
}
impl From<bool> for VmValue {
    fn from(v: bool) -> Self {
        Self::Bool(v)
    }
}
impl From<String> for VmValue {
    fn from(v: String) -> Self {
        Self::String(v)
    }
}
impl From<&str> for VmValue {
    fn from(v: &str) -> Self {
        Self::String(v.to_owned())
    }
}
impl From<Vec<u8>> for VmValue {
    fn from(v: Vec<u8>) -> Self {
        Self::Bytes(v)
    }
}
impl From<u64> for VmValue {
    fn from(v: u64) -> Self {
        Self::Address(v)
    }
}

// ─── ScriptCallable trait ─────────────────────────────────────────────────────

/// Trait for objects that can be called from the script VM layer.
///
/// This is the VM-layer counterpart of [`crate::ScriptFn`]: it operates on
/// [`VmValue`] instead of [`ScriptValue`] so adapters can avoid converting
/// every argument twice.
pub trait ScriptCallable: Send + Sync {
    /// Call this object with `args`, returning a [`VmValue`].
    ///
    /// # Errors
    /// Returns `ScriptError` on failure.
    fn call_vm(&self, args: Vec<VmValue>) -> Result<VmValue, ScriptError>;

    /// Declared arity.  `None` = variadic.
    fn arity(&self) -> Option<usize> {
        None
    }

    /// Name for diagnostics.
    fn name(&self) -> &str {
        "<callable>"
    }
}

// ─── ScriptFunction ───────────────────────────────────────────────────────────

/// A named, arity-annotated callable registered in the VM bindings layer.
pub struct ScriptFunction {
    /// Function name.
    pub name: String,
    /// Declared arity (`None` = variadic).
    pub arity: Option<usize>,
    /// Inner callable.
    inner: Arc<dyn ScriptCallable>,
}

impl fmt::Debug for ScriptFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptFunction")
            .field("name", &self.name)
            .field("arity", &self.arity)
            .finish_non_exhaustive()
    }
}

impl ScriptFunction {
    /// Wrap a [`ScriptCallable`] into a `ScriptFunction`.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        arity: Option<usize>,
        callable: Arc<dyn ScriptCallable>,
    ) -> Self {
        Self {
            name: name.into(),
            arity,
            inner: callable,
        }
    }

    /// Create a `ScriptFunction` from a closure.
    #[must_use]
    pub fn from_closure<F>(name: impl Into<String>, arity: Option<usize>, f: F) -> Self
    where
        F: Fn(Vec<VmValue>) -> Result<VmValue, ScriptError> + Send + Sync + 'static,
    {
        struct ClosureCallable<F> {
            f: F,
            name_: String,
            arity_: Option<usize>,
        }
        impl<F: Fn(Vec<VmValue>) -> Result<VmValue, ScriptError> + Send + Sync> ScriptCallable
            for ClosureCallable<F>
        {
            fn call_vm(&self, args: Vec<VmValue>) -> Result<VmValue, ScriptError> {
                (self.f)(args)
            }
            fn arity(&self) -> Option<usize> {
                self.arity_
            }
            fn name(&self) -> &str {
                &self.name_
            }
        }
        let callable = Arc::new(ClosureCallable {
            f,
            name_: name.into(),
            arity_: arity,
        });
        Self {
            name: callable.name().to_owned(),
            arity,
            inner: callable,
        }
    }

    /// Invoke this function with `VmValue` arguments.
    ///
    /// # Errors
    /// Propagates errors from the inner callable or arity check.
    pub fn call(&self, args: Vec<VmValue>) -> Result<VmValue, ScriptError> {
        if let Some(expected) = self.arity
            && args.len() != expected
        {
            return Err(ScriptError::ArityMismatch {
                name: self.name.clone(),
                expected,
                got: args.len(),
            });
        }
        self.inner.call_vm(args)
    }

    /// Invoke this function by converting [`ScriptValue`] arguments.
    ///
    /// # Errors
    /// Propagates conversion and callable errors.
    pub fn call_with_script_values(
        &self,
        args: Vec<ScriptValue>,
    ) -> Result<ScriptValue, ScriptError> {
        let vm_args: Vec<VmValue> = args.into_iter().map(Into::into).collect();
        let result = self.call(vm_args)?;
        Ok(result.into())
    }
}

// ─── ScriptFunctionRegistry ───────────────────────────────────────────────────

/// A registry of named [`ScriptFunction`]s, keyed by name.
#[derive(Default)]
pub struct ScriptFunctionRegistry {
    fns: HashMap<String, ScriptFunction>,
}

impl fmt::Debug for ScriptFunctionRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptFunctionRegistry")
            .field("count", &self.fns.len())
            .finish_non_exhaustive()
    }
}

impl ScriptFunctionRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a function.  Overwrites any existing entry with the same name.
    pub fn register(&mut self, f: ScriptFunction) {
        self.fns.insert(f.name.clone(), f);
    }

    /// Look up a function by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&ScriptFunction> {
        self.fns.get(name)
    }

    /// Return the number of registered functions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fns.len()
    }

    /// Return `true` if no functions are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fns.is_empty()
    }

    /// Return all function names.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.fns.keys().map(String::as_str).collect()
    }

    /// Remove a function by name.
    pub fn remove(&mut self, name: &str) -> bool {
        self.fns.remove(name).is_some()
    }
}

// ─── Type-conversion helpers ──────────────────────────────────────────────────

/// Try to extract an `i64` from a [`VmValue`].
///
/// # Errors
/// Returns `ScriptError::TypeMismatch` on failure.
pub fn try_into_int(v: &VmValue) -> Result<i64, ScriptError> {
    v.as_int()
}

/// Try to extract a `f64` from a [`VmValue`].
///
/// # Errors
/// Returns `ScriptError::TypeMismatch` on failure.
pub fn try_into_float(v: &VmValue) -> Result<f64, ScriptError> {
    v.as_float()
}

/// Try to extract a `&str` from a [`VmValue`].
///
/// # Errors
/// Returns `ScriptError::TypeMismatch` on failure.
pub fn try_into_str(v: &VmValue) -> Result<&str, ScriptError> {
    v.as_str()
}

/// Try to extract a byte slice from a [`VmValue`].
///
/// # Errors
/// Returns `ScriptError::TypeMismatch` on failure.
pub fn try_into_bytes(v: &VmValue) -> Result<&[u8], ScriptError> {
    v.as_bytes()
}

/// Coerce any [`VmValue`] to a `bool` via truthiness rules.
#[must_use]
pub fn coerce_to_bool(v: &VmValue) -> bool {
    v.is_truthy()
}

/// Coerce a [`VmValue`] to a display string (best-effort, never errors).
#[must_use]
pub fn coerce_to_string(v: &VmValue) -> String {
    v.to_string()
}

/// Convert a `Vec<VmValue>` to a `Vec<ScriptValue>`.
#[must_use]
pub fn vm_values_to_script(values: Vec<VmValue>) -> Vec<ScriptValue> {
    values.into_iter().map(Into::into).collect()
}

/// Convert a `Vec<ScriptValue>` to a `Vec<VmValue>`.
#[must_use]
pub fn script_values_to_vm(values: Vec<ScriptValue>) -> Vec<VmValue> {
    values.into_iter().map(Into::into).collect()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── VmValue ─────────────────────────────────────────────────────────────

    #[test]
    fn test_vm_value_type_names() {
        assert_eq!(VmValue::Null.type_name(), "null");
        assert_eq!(VmValue::Bool(true).type_name(), "bool");
        assert_eq!(VmValue::Int(1).type_name(), "int");
        assert_eq!(VmValue::Float(1.0).type_name(), "float");
        assert_eq!(VmValue::String("s".into()).type_name(), "string");
        assert_eq!(VmValue::Bytes(vec![]).type_name(), "bytes");
        assert_eq!(VmValue::List(vec![]).type_name(), "list");
        assert_eq!(VmValue::Map(HashMap::new()).type_name(), "map");
        assert_eq!(VmValue::Address(0).type_name(), "address");
        assert_eq!(VmValue::Callable("f".into()).type_name(), "callable");
    }

    #[test]
    fn test_vm_value_truthy() {
        assert!(!VmValue::Null.is_truthy());
        assert!(!VmValue::Bool(false).is_truthy());
        assert!(VmValue::Bool(true).is_truthy());
        assert!(!VmValue::Int(0).is_truthy());
        assert!(VmValue::Int(1).is_truthy());
        assert!(VmValue::Address(0x1000).is_truthy());
        assert!(!VmValue::String(String::new()).is_truthy());
        assert!(VmValue::String("hi".into()).is_truthy());
    }

    #[test]
    fn test_vm_value_as_int() {
        assert_eq!(VmValue::Int(42).as_int().unwrap(), 42);
        assert_eq!(VmValue::Float(3.9).as_int().unwrap(), 3);
        assert_eq!(VmValue::Bool(true).as_int().unwrap(), 1);
        assert!(VmValue::Null.as_int().is_err());
    }

    #[test]
    fn test_vm_value_as_float() {
        assert_eq!(VmValue::Float(1.5).as_float().unwrap(), 1.5);
        assert_eq!(VmValue::Int(2).as_float().unwrap(), 2.0);
        assert!(VmValue::Null.as_float().is_err());
    }

    #[test]
    fn test_vm_value_as_str() {
        let v = VmValue::String("hello".into());
        assert_eq!(v.as_str().unwrap(), "hello");
        assert!(VmValue::Int(1).as_str().is_err());
    }

    #[test]
    fn test_vm_value_as_bytes() {
        let v = VmValue::Bytes(vec![0xAA]);
        assert_eq!(v.as_bytes().unwrap(), &[0xAA]);
    }

    #[test]
    fn test_vm_value_as_address() {
        assert_eq!(VmValue::Address(0x1000).as_address().unwrap(), 0x1000);
        assert_eq!(VmValue::Int(0x2000).as_address().unwrap(), 0x2000);
        assert!(VmValue::Null.as_address().is_err());
    }

    #[test]
    fn test_vm_value_is_null() {
        assert!(VmValue::Null.is_null());
        assert!(!VmValue::Int(0).is_null());
    }

    #[test]
    fn test_vm_value_display() {
        assert_eq!(VmValue::Null.to_string(), "null");
        assert_eq!(VmValue::Int(42).to_string(), "42");
        assert_eq!(VmValue::Address(0xff).to_string(), "0xff");
    }

    // ── Conversion ─────────────────────────────────────────────────────────

    #[test]
    fn test_vm_to_script_roundtrip() {
        let original = VmValue::Int(99);
        let sv: ScriptValue = original.clone().into();
        let back: VmValue = sv.into();
        assert_eq!(back, original);
    }

    #[test]
    fn test_vm_list_conversion() {
        let vm = VmValue::List(vec![VmValue::Int(1), VmValue::Bool(true)]);
        let sv: ScriptValue = vm.into();
        if let ScriptValue::List(items) = sv {
            assert_eq!(items.len(), 2);
        } else {
            panic!("expected list");
        }
    }

    #[test]
    fn test_vm_map_conversion() {
        let mut map = HashMap::new();
        map.insert("key".into(), VmValue::Int(5));
        let vm = VmValue::Map(map);
        let sv: ScriptValue = vm.into();
        if let ScriptValue::Map(m) = sv {
            assert_eq!(m["key"], ScriptValue::Int(5));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn test_from_primitives() {
        assert_eq!(VmValue::from(42i64), VmValue::Int(42));
        assert_eq!(VmValue::from(1.0f64), VmValue::Float(1.0));
        assert_eq!(VmValue::from(true), VmValue::Bool(true));
        assert_eq!(VmValue::from("hi"), VmValue::String("hi".into()));
        assert_eq!(VmValue::from(0x1000u64), VmValue::Address(0x1000));
        assert_eq!(VmValue::from(vec![0xAAu8]), VmValue::Bytes(vec![0xAA]));
    }

    // ── ScriptFunction ──────────────────────────────────────────────────────

    #[test]
    fn test_script_function_call() {
        let f = ScriptFunction::from_closure("add_one", Some(1), |args| {
            let n = args[0].as_int()?;
            Ok(VmValue::Int(n + 1))
        });
        let result = f.call(vec![VmValue::Int(41)]).unwrap();
        assert_eq!(result, VmValue::Int(42));
    }

    #[test]
    fn test_script_function_arity_check() {
        let f = ScriptFunction::from_closure("strict", Some(2), |_| Ok(VmValue::Null));
        let result = f.call(vec![VmValue::Int(1)]);
        assert!(matches!(result, Err(ScriptError::ArityMismatch { .. })));
    }

    #[test]
    fn test_script_function_variadic() {
        let f = ScriptFunction::from_closure("variadic", None, |args| {
            Ok(VmValue::Int(args.len() as i64))
        });
        let result = f
            .call(vec![VmValue::Int(1), VmValue::Int(2), VmValue::Int(3)])
            .unwrap();
        assert_eq!(result, VmValue::Int(3));
    }

    #[test]
    fn test_call_with_script_values() {
        let f = ScriptFunction::from_closure("double", Some(1), |args| {
            let n = args[0].as_int()?;
            Ok(VmValue::Int(n * 2))
        });
        let sv = ScriptValue::Int(21);
        let result = f.call_with_script_values(vec![sv]).unwrap();
        assert_eq!(result, ScriptValue::Int(42));
    }

    #[test]
    fn test_script_function_debug() {
        let f = ScriptFunction::from_closure("fn_name", Some(0), |_| Ok(VmValue::Null));
        let s = format!("{f:?}");
        assert!(s.contains("fn_name"));
    }

    // ── ScriptFunctionRegistry ──────────────────────────────────────────────

    #[test]
    fn test_registry_register_and_get() {
        let mut reg = ScriptFunctionRegistry::new();
        let f = ScriptFunction::from_closure("foo", None, |_| Ok(VmValue::Null));
        reg.register(f);
        assert!(reg.get("foo").is_some());
    }

    #[test]
    fn test_registry_len() {
        let mut reg = ScriptFunctionRegistry::new();
        assert_eq!(reg.len(), 0);
        reg.register(ScriptFunction::from_closure("a", None, |_| {
            Ok(VmValue::Null)
        }));
        reg.register(ScriptFunction::from_closure("b", None, |_| {
            Ok(VmValue::Null)
        }));
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn test_registry_remove() {
        let mut reg = ScriptFunctionRegistry::new();
        reg.register(ScriptFunction::from_closure("del", None, |_| {
            Ok(VmValue::Null)
        }));
        assert!(reg.remove("del"));
        assert!(!reg.remove("del"));
    }

    #[test]
    fn test_registry_names() {
        let mut reg = ScriptFunctionRegistry::new();
        reg.register(ScriptFunction::from_closure("x", None, |_| {
            Ok(VmValue::Null)
        }));
        assert!(reg.names().contains(&"x"));
    }

    #[test]
    fn test_registry_debug() {
        let reg = ScriptFunctionRegistry::new();
        let s = format!("{reg:?}");
        assert!(s.contains("ScriptFunctionRegistry"));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    #[test]
    fn test_try_into_int() {
        assert_eq!(try_into_int(&VmValue::Int(7)).unwrap(), 7);
        assert!(try_into_int(&VmValue::Null).is_err());
    }

    #[test]
    fn test_try_into_float() {
        assert!((try_into_float(&VmValue::Float(1.5)).unwrap() - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_try_into_str() {
        assert_eq!(try_into_str(&VmValue::String("hi".into())).unwrap(), "hi");
    }

    #[test]
    fn test_try_into_bytes() {
        let b = vec![0xFFu8];
        assert_eq!(
            try_into_bytes(&VmValue::Bytes(b.clone())).unwrap(),
            b.as_slice()
        );
    }

    #[test]
    fn test_coerce_to_bool() {
        assert!(coerce_to_bool(&VmValue::Int(1)));
        assert!(!coerce_to_bool(&VmValue::Null));
    }

    #[test]
    fn test_coerce_to_string() {
        assert_eq!(coerce_to_string(&VmValue::Int(42)), "42");
        assert_eq!(coerce_to_string(&VmValue::Null), "null");
    }

    #[test]
    fn test_vm_values_to_script_and_back() {
        let vm = vec![VmValue::Int(1), VmValue::Bool(true)];
        let sv = vm_values_to_script(vm);
        let vm2 = script_values_to_vm(sv);
        assert_eq!(vm2[0], VmValue::Int(1));
        assert_eq!(vm2[1], VmValue::Bool(true));
    }
}
