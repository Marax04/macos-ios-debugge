// python_api.rs — Python-callable API for RustRE binary navigation and analysis.
// Pure-Rust bridge layer (no pyo3). Defines callable function descriptors,
// argument/return type system, and an API registry usable from the pure-Rust
// Python interpreter implemented elsewhere in this crate.

use std::collections::HashMap;
use std::fmt;

// ── Value types ───────────────────────────────────────────────────────────────

/// Dynamically typed value exchanged between the Python layer and the Rust API.
#[derive(Debug, Clone, PartialEq)]
pub enum PyValue {
    None,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Bytes(Vec<u8>),
    List(Vec<Self>),
    Dict(Vec<(String, Self)>),
}

impl PyValue {
    #[must_use] 
    pub const fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }

    #[must_use] 
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            Self::Bool(b) => Some(i64::from(*b)),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            Self::Int(i) => Some(*i != 0),
            _ => None,
        }
    }

    #[must_use] 
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    #[must_use] 
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::None => "NoneType",
            Self::Bool(_) => "bool",
            Self::Int(_) => "int",
            Self::Float(_) => "float",
            Self::Str(_) => "str",
            Self::Bytes(_) => "bytes",
            Self::List(_) => "list",
            Self::Dict(_) => "dict",
        }
    }
}

impl fmt::Display for PyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Bool(b) => write!(f, "{}", if *b { "True" } else { "False" }),
            Self::Int(i) => write!(f, "{i}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Str(s) => write!(f, "{s}"),
            Self::Bytes(b) => write!(f, "b<{} bytes>", b.len()),
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
            Self::Dict(d) => {
                write!(f, "{{")?;
                for (i, (k, v)) in d.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{k}: {v}")?;
                }
                write!(f, "}}")
            }
        }
    }
}

// ── Argument descriptors ──────────────────────────────────────────────────────

/// The expected type of a function argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgType {
    Any,
    NoneType,
    Bool,
    Int,
    Float,
    Str,
    Bytes,
    List,
    Dict,
    IntOrStr,
}

impl ArgType {
    #[must_use] 
    pub const fn matches(&self, v: &PyValue) -> bool {
        match self {
            Self::Any => true,
            Self::NoneType => v.is_none(),
            Self::Bool => matches!(v, PyValue::Bool(_)),
            Self::Int => matches!(v, PyValue::Int(_) | PyValue::Bool(_)),
            Self::Float => matches!(v, PyValue::Float(_) | PyValue::Int(_)),
            Self::Str => matches!(v, PyValue::Str(_)),
            Self::Bytes => matches!(v, PyValue::Bytes(_)),
            Self::List => matches!(v, PyValue::List(_)),
            Self::Dict => matches!(v, PyValue::Dict(_)),
            Self::IntOrStr => {
                matches!(v, PyValue::Int(_) | PyValue::Str(_) | PyValue::Bool(_))
            }
        }
    }
}

/// Description of a single function argument.
#[derive(Debug, Clone)]
pub struct PyArg {
    pub name: String,
    pub arg_type: ArgType,
    pub optional: bool,
    pub default: Option<PyValue>,
    pub doc: String,
}

impl PyArg {
    pub fn required(name: impl Into<String>, arg_type: ArgType, doc: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            arg_type,
            optional: false,
            default: None,
            doc: doc.into(),
        }
    }

    pub fn optional(
        name: impl Into<String>,
        arg_type: ArgType,
        default: PyValue,
        doc: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            arg_type,
            optional: true,
            default: Some(default),
            doc: doc.into(),
        }
    }
}

// ── Return descriptor ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PyReturn {
    pub return_type: ArgType,
    pub doc: String,
    pub can_return_none: bool,
}

impl PyReturn {
    pub fn new(return_type: ArgType, doc: impl Into<String>) -> Self {
        Self { return_type, doc: doc.into(), can_return_none: false }
    }

    #[must_use] 
    pub const fn nullable(mut self) -> Self {
        self.can_return_none = true;
        self
    }
}

// ── Error bridge ──────────────────────────────────────────────────────────────

/// Errors raised when an API function is called with wrong arguments or fails.
#[derive(Debug, Clone)]
pub enum ApiError {
    WrongArgCount { expected: usize, got: usize },
    WrongArgType { arg_name: String, expected: ArgType, got: String },
    NotFound(String),
    PermissionDenied(String),
    InvalidAddress(u64),
    OutOfRange { value: i64, min: i64, max: i64 },
    InternalError(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongArgCount { expected, got } => {
                write!(f, "TypeError: expected {expected} args, got {got}")
            }
            Self::WrongArgType { arg_name, expected, got } => {
                write!(
                    f,
                    "TypeError: arg '{arg_name}' expected {expected:?}, got '{got}'"
                )
            }
            Self::NotFound(s) => write!(f, "LookupError: {s} not found"),
            Self::PermissionDenied(s) => write!(f, "PermissionError: {s}"),
            Self::InvalidAddress(a) => write!(f, "ValueError: invalid address 0x{a:016X}"),
            Self::OutOfRange { value, min, max } => {
                write!(f, "ValueError: {value} out of range [{min}, {max}]")
            }
            Self::InternalError(s) => write!(f, "RuntimeError: {s}"),
        }
    }
}

// ── API function type ─────────────────────────────────────────────────────────

/// Trait object signature for an API function handler.
pub type ApiFn =
    Box<dyn Fn(&ApiContext, Vec<PyValue>) -> Result<PyValue, ApiError> + Send + Sync>;

/// Descriptor for a Python-callable API function.
pub struct PyApiFunction {
    pub module: String,
    pub name: String,
    pub args: Vec<PyArg>,
    pub returns: PyReturn,
    pub doc: String,
    pub handler: ApiFn,
}

impl PyApiFunction {
    pub fn new(
        module: impl Into<String>,
        name: impl Into<String>,
        args: Vec<PyArg>,
        returns: PyReturn,
        doc: impl Into<String>,
        handler: ApiFn,
    ) -> Self {
        Self {
            module: module.into(),
            name: name.into(),
            args,
            returns,
            doc: doc.into(),
            handler,
        }
    }

    #[must_use] 
    pub fn full_name(&self) -> String {
        format!("{}.{}", self.module, self.name)
    }

    pub fn validate_args(&self, args: &[PyValue]) -> Result<(), ApiError> {
        let required_count = self.args.iter().filter(|a| !a.optional).count();
        if args.len() < required_count || args.len() > self.args.len() {
            return Err(ApiError::WrongArgCount {
                expected: self.args.len(),
                got: args.len(),
            });
        }
        for (i, arg_desc) in self.args.iter().enumerate() {
            let val = if i < args.len() {
                &args[i]
            } else if let Some(def) = &arg_desc.default {
                def
            } else {
                return Err(ApiError::WrongArgCount {
                    expected: required_count,
                    got: args.len(),
                });
            };
            if !arg_desc.arg_type.matches(val) {
                return Err(ApiError::WrongArgType {
                    arg_name: arg_desc.name.clone(),
                    expected: arg_desc.arg_type.clone(),
                    got: val.type_name().to_string(),
                });
            }
        }
        Ok(())
    }

    /// Fill in default values for missing optional arguments.
    #[must_use] 
    pub fn fill_defaults(&self, mut args: Vec<PyValue>) -> Vec<PyValue> {
        for i in args.len()..self.args.len() {
            if let Some(def) = &self.args[i].default {
                args.push(def.clone());
            }
        }
        args
    }

    pub fn call(&self, ctx: &ApiContext, args: Vec<PyValue>) -> Result<PyValue, ApiError> {
        self.validate_args(&args)?;
        let args = self.fill_defaults(args);
        (self.handler)(ctx, args)
    }
}

// ── Context ───────────────────────────────────────────────────────────────────

/// Runtime context passed to every API function call.
/// Holds read-only binary data and metadata.
#[derive(Debug, Default)]
pub struct ApiContext {
    /// Raw binary image bytes.
    pub binary: Vec<u8>,
    /// Virtual base address.
    pub base_address: u64,
    /// Architecture tag (e.g. "`x86_64`", "arm64").
    pub arch: String,
    /// Named exports: name → virtual address.
    pub exports: HashMap<String, u64>,
    /// Named imports: name → target VA.
    pub imports: HashMap<String, u64>,
    /// String table: VA → string content.
    pub strings: HashMap<u64, String>,
    /// Function boundaries: VA → (VA, size).
    pub functions: HashMap<u64, (u64, u64)>,
}

impl ApiContext {
    pub fn new(binary: Vec<u8>, base_address: u64, arch: impl Into<String>) -> Self {
        Self {
            binary,
            base_address,
            arch: arch.into(),
            exports: HashMap::new(),
            imports: HashMap::new(),
            strings: HashMap::new(),
            functions: HashMap::new(),
        }
    }

    #[must_use] 
    pub fn read_bytes(&self, va: u64, len: usize) -> Option<&[u8]> {
        if va < self.base_address {
            return None;
        }
        let offset = usize::try_from(va - self.base_address).unwrap_or(0);
        let end = offset.checked_add(len)?;
        if end > self.binary.len() {
            return None;
        }
        Some(&self.binary[offset..end])
    }

    #[must_use] 
    pub fn read_u8(&self, va: u64) -> Option<u8> {
        self.read_bytes(va, 1).map(|b| b[0])
    }

    #[must_use] 
    pub fn read_u32_le(&self, va: u64) -> Option<u32> {
        let b = self.read_bytes(va, 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    #[must_use] 
    pub fn read_u64_le(&self, va: u64) -> Option<u64> {
        let b = self.read_bytes(va, 8)?;
        Some(u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    }
}

// ── API registry ──────────────────────────────────────────────────────────────

/// Central registry of Python-callable API functions.
pub struct ApiBinding {
    functions: HashMap<String, PyApiFunction>,
}

impl ApiBinding {
    #[must_use] 
    pub fn new() -> Self {
        Self { functions: HashMap::new() }
    }

    pub fn register(&mut self, func: PyApiFunction) {
        self.functions.insert(func.full_name(), func);
    }

    pub fn call(
        &self,
        full_name: &str,
        ctx: &ApiContext,
        args: Vec<PyValue>,
    ) -> Result<PyValue, ApiError> {
        let func = self
            .functions
            .get(full_name)
            .ok_or_else(|| ApiError::NotFound(full_name.to_string()))?;
        func.call(ctx, args)
    }

    #[must_use] 
    pub fn list_functions(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.functions.keys().map(std::string::String::as_str).collect();
        names.sort_unstable();
        names
    }

    #[must_use]
    pub fn help(&self, full_name: &str) -> Option<String> {
        use std::fmt::Write as _;
        let f = self.functions.get(full_name)?;
        let mut out = format!("{}(", f.name);
        for (i, a) in f.args.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            if a.optional {
                let _ = write!(out, "[{}]", a.name);
            } else {
                out.push_str(&a.name);
            }
        }
        let _ = write!(out, ") -> {:?}\n{}", f.returns.return_type, f.doc);
        Some(out)
    }

    #[must_use] 
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }
}

impl Default for ApiBinding {
    fn default() -> Self {
        Self::new()
    }
}

fn register_memory_api(api: &mut ApiBinding) {
    api.register(PyApiFunction::new(
        "rustre", "read_bytes",
        vec![
            PyArg::required("address", ArgType::Int, "Virtual address to read from"),
            PyArg::required("length", ArgType::Int, "Number of bytes to read"),
        ],
        PyReturn::new(ArgType::Bytes, "Raw bytes at the given address").nullable(),
        "Read raw bytes from the binary image at a virtual address.",
        Box::new(|ctx, args| {
            let va = args[0].as_int().unwrap_or(0).cast_unsigned();
            let len = usize::try_from(args[1].as_int().unwrap_or(0)).unwrap_or(0);
            if len == 0 { return Ok(PyValue::Bytes(vec![])); }
            ctx.read_bytes(va, len).map_or(Err(ApiError::InvalidAddress(va)), |b| Ok(PyValue::Bytes(b.to_vec())))
        }),
    ));
    api.register(PyApiFunction::new(
        "rustre", "read_u32",
        vec![PyArg::required("address", ArgType::Int, "Virtual address")],
        PyReturn::new(ArgType::Int, "32-bit little-endian integer").nullable(),
        "Read a 32-bit little-endian integer from the binary.",
        Box::new(|ctx, args| {
            let va = args[0].as_int().unwrap_or(0).cast_unsigned();
            ctx.read_u32_le(va).map_or(Err(ApiError::InvalidAddress(va)), |v| Ok(PyValue::Int(i64::from(v))))
        }),
    ));
    api.register(PyApiFunction::new(
        "rustre", "read_u64",
        vec![PyArg::required("address", ArgType::Int, "Virtual address")],
        PyReturn::new(ArgType::Int, "64-bit little-endian integer").nullable(),
        "Read a 64-bit little-endian integer from the binary.",
        Box::new(|ctx, args| {
            let va = args[0].as_int().unwrap_or(0).cast_unsigned();
            ctx.read_u64_le(va).map_or(Err(ApiError::InvalidAddress(va)), |v| Ok(PyValue::Int(v.cast_signed())))
        }),
    ));
}

fn register_symbol_api(api: &mut ApiBinding) {
    api.register(PyApiFunction::new(
        "rustre", "get_export",
        vec![PyArg::required("name", ArgType::Str, "Export symbol name")],
        PyReturn::new(ArgType::Int, "Virtual address of the export").nullable(),
        "Look up a named export and return its virtual address.",
        Box::new(|ctx, args| {
            let name = args[0].as_str().unwrap_or("");
            match ctx.exports.get(name) {
                Some(&va) => Ok(PyValue::Int(va.cast_signed())),
                None => Ok(PyValue::None),
            }
        }),
    ));
    api.register(PyApiFunction::new(
        "rustre", "list_exports",
        vec![],
        PyReturn::new(ArgType::List, "List of (name, address) pairs"),
        "Return a list of all exports as [name, address] pairs.",
        Box::new(|ctx, _args| {
            let mut list = Vec::new();
            let mut names: Vec<_> = ctx.exports.iter().collect();
            names.sort_by_key(|(k, _)| k.as_str());
            for (name, &va) in names {
                list.push(PyValue::List(vec![PyValue::Str(name.clone()), PyValue::Int(va.cast_signed())]));
            }
            Ok(PyValue::List(list))
        }),
    ));
    api.register(PyApiFunction::new(
        "rustre", "get_string",
        vec![PyArg::required("address", ArgType::Int, "Virtual address of string")],
        PyReturn::new(ArgType::Str, "String content at the address").nullable(),
        "Retrieve a known string from the string table.",
        Box::new(|ctx, args| {
            let va = args[0].as_int().unwrap_or(0).cast_unsigned();
            ctx.strings.get(&va).map_or(Ok(PyValue::None), |s| Ok(PyValue::Str(s.clone())))
        }),
    ));
}

fn register_binary_info_api(api: &mut ApiBinding) {
    api.register(PyApiFunction::new(
        "rustre", "get_arch",
        vec![],
        PyReturn::new(ArgType::Str, "Architecture tag string"),
        "Return the architecture of the loaded binary.",
        Box::new(|ctx, _args| Ok(PyValue::Str(ctx.arch.clone()))),
    ));
    api.register(PyApiFunction::new(
        "rustre", "base_address",
        vec![],
        PyReturn::new(ArgType::Int, "Virtual base address"),
        "Return the base virtual address of the loaded binary.",
        Box::new(|ctx, _args| Ok(PyValue::Int(ctx.base_address.cast_signed()))),
    ));
    api.register(PyApiFunction::new(
        "rustre", "binary_size",
        vec![],
        PyReturn::new(ArgType::Int, "Size of the binary image in bytes"),
        "Return the size of the binary image in bytes.",
        Box::new(|ctx, _args| Ok(PyValue::Int(i64::try_from(ctx.binary.len()).unwrap_or(i64::MAX)))),
    ));
    api.register(PyApiFunction::new(
        "rustre", "find_bytes",
        vec![
            PyArg::required("pattern", ArgType::Bytes, "Byte sequence to search for"),
            PyArg::optional("start", ArgType::Int, PyValue::Int(0), "Starting virtual address"),
        ],
        PyReturn::new(ArgType::Int, "Virtual address of first match").nullable(),
        "Search for a byte pattern in the binary, return first match address.",
        Box::new(|ctx, args| {
            let pattern = args[0].as_bytes().unwrap_or(&[]).to_vec();
            let start_va = args[1].as_int().unwrap_or(0).cast_unsigned();
            if pattern.is_empty() { return Ok(PyValue::None); }
            let start_off = if start_va >= ctx.base_address {
                usize::try_from(start_va - ctx.base_address).unwrap_or(0)
            } else { 0 };
            let haystack = &ctx.binary[start_off.min(ctx.binary.len())..];
            for i in 0..haystack.len().saturating_sub(pattern.len() - 1) {
                if haystack[i..].starts_with(&pattern) {
                    let va = ctx.base_address + u64::try_from(start_off).unwrap_or(0) + u64::try_from(i).unwrap_or(0);
                    return Ok(PyValue::Int(va.cast_signed()));
                }
            }
            Ok(PyValue::None)
        }),
    ));
}

/// Build the standard `RustRE` Python API bindings.
#[must_use]
pub fn build_standard_api() -> ApiBinding {
    let mut api = ApiBinding::new();
    register_memory_api(&mut api);
    register_symbol_api(&mut api);
    register_binary_info_api(&mut api);
    api
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> ApiContext {
        let mut ctx = ApiContext::new(vec![0x41u8; 64], 0x1000, "x86_64");
        ctx.exports.insert("main".to_string(), 0x1010);
        ctx.imports.insert("printf".to_string(), 0x2000);
        ctx.strings.insert(0x1020, "Hello, World!".to_string());
        ctx
    }

    #[test]
    fn test_py_value_type_names() {
        assert_eq!(PyValue::None.type_name(), "NoneType");
        assert_eq!(PyValue::Int(1).type_name(), "int");
        assert_eq!(PyValue::Str("x".into()).type_name(), "str");
        assert_eq!(PyValue::Bytes(vec![]).type_name(), "bytes");
    }

    #[test]
    fn test_py_value_display() {
        assert_eq!(format!("{}", PyValue::None), "None");
        assert_eq!(format!("{}", PyValue::Bool(true)), "True");
        assert_eq!(format!("{}", PyValue::Int(42)), "42");
        assert_eq!(
            format!("{}", PyValue::List(vec![PyValue::Int(1), PyValue::Int(2)])),
            "[1, 2]"
        );
    }

    #[test]
    fn test_arg_type_matches() {
        assert!(ArgType::Int.matches(&PyValue::Int(5)));
        assert!(ArgType::Int.matches(&PyValue::Bool(true)));
        assert!(!ArgType::Int.matches(&PyValue::Str("x".into())));
        assert!(ArgType::Any.matches(&PyValue::None));
        assert!(ArgType::Float.matches(&PyValue::Int(3)));
    }

    #[test]
    fn test_api_read_bytes() {
        let api = build_standard_api();
        let ctx = make_ctx();
        let result = api.call("rustre.read_bytes", &ctx, vec![PyValue::Int(0x1000), PyValue::Int(4)]).unwrap();
        assert_eq!(result, PyValue::Bytes(vec![0x41, 0x41, 0x41, 0x41]));
    }

    #[test]
    fn test_api_read_bytes_out_of_range() {
        let api = build_standard_api();
        let ctx = make_ctx();
        let err = api.call("rustre.read_bytes", &ctx, vec![PyValue::Int(0x9000), PyValue::Int(4)]).unwrap_err();
        assert!(matches!(err, ApiError::InvalidAddress(_)));
    }

    #[test]
    fn test_api_get_export() {
        let api = build_standard_api();
        let ctx = make_ctx();
        let v = api.call("rustre.get_export", &ctx, vec![PyValue::Str("main".into())]).unwrap();
        assert_eq!(v, PyValue::Int(0x1010));
    }

    #[test]
    fn test_api_get_export_missing() {
        let api = build_standard_api();
        let ctx = make_ctx();
        let v = api.call("rustre.get_export", &ctx, vec![PyValue::Str("missing".into())]).unwrap();
        assert_eq!(v, PyValue::None);
    }

    #[test]
    fn test_api_list_exports() {
        let api = build_standard_api();
        let ctx = make_ctx();
        let v = api.call("rustre.list_exports", &ctx, vec![]).unwrap();
        match v {
            PyValue::List(l) => assert_eq!(l.len(), 1),
            _ => panic!("expected list"),
        }
    }

    #[test]
    fn test_api_get_arch() {
        let api = build_standard_api();
        let ctx = make_ctx();
        let v = api.call("rustre.get_arch", &ctx, vec![]).unwrap();
        assert_eq!(v, PyValue::Str("x86_64".into()));
    }

    #[test]
    fn test_api_binary_size() {
        let api = build_standard_api();
        let ctx = make_ctx();
        let v = api.call("rustre.binary_size", &ctx, vec![]).unwrap();
        assert_eq!(v, PyValue::Int(64));
    }

    #[test]
    fn test_api_base_address() {
        let api = build_standard_api();
        let ctx = make_ctx();
        let v = api.call("rustre.base_address", &ctx, vec![]).unwrap();
        assert_eq!(v, PyValue::Int(0x1000));
    }

    #[test]
    fn test_api_find_bytes() {
        let api = build_standard_api();
        let ctx = make_ctx();
        // The binary is 0x41 repeated, so searching for [0x41, 0x41] should hit at base.
        let v = api.call(
            "rustre.find_bytes",
            &ctx,
            vec![PyValue::Bytes(vec![0x41, 0x41]), PyValue::Int(0x1000)],
        ).unwrap();
        assert_eq!(v, PyValue::Int(0x1000));
    }

    #[test]
    fn test_api_find_bytes_not_found() {
        let api = build_standard_api();
        let ctx = make_ctx();
        let v = api.call(
            "rustre.find_bytes",
            &ctx,
            vec![PyValue::Bytes(vec![0xDE, 0xAD]), PyValue::Int(0x1000)],
        ).unwrap();
        assert_eq!(v, PyValue::None);
    }

    #[test]
    fn test_wrong_arg_count() {
        let api = build_standard_api();
        let ctx = make_ctx();
        let err = api.call("rustre.read_bytes", &ctx, vec![PyValue::Int(0x1000)]).unwrap_err();
        assert!(matches!(err, ApiError::WrongArgCount { .. }));
    }

    #[test]
    fn test_not_found() {
        let api = build_standard_api();
        let ctx = make_ctx();
        let err = api.call("rustre.nonexistent", &ctx, vec![]).unwrap_err();
        assert!(matches!(err, ApiError::NotFound(_)));
    }

    #[test]
    fn test_api_error_display() {
        let e = ApiError::InvalidAddress(0xDEAD);
        assert!(e.to_string().contains("0x"));
        let e2 = ApiError::WrongArgCount { expected: 2, got: 1 };
        assert!(e2.to_string().contains("TypeError"));
    }

    #[test]
    fn test_api_help() {
        let api = build_standard_api();
        let h = api.help("rustre.read_bytes").unwrap();
        assert!(h.contains("read_bytes"));
        assert!(h.contains("address"));
    }

    #[test]
    fn test_function_count() {
        let api = build_standard_api();
        assert!(api.function_count() >= 9);
    }
}
