//! `host_api` — Script host API bindings.
//!
//! This module defines [`ScriptHostApi`], the trait that scripting engines
//! call to perform reverse-engineering operations on the currently loaded
//! binary.  Every method on the trait maps to a named host function that
//! scripts can invoke, e.g. `re.get_function("main")`.
//!
//! # Trait surface area
//!
//! | Method | Description |
//! |--------|-------------|
//! | `get_function` | Look up a function by name or address |
//! | `set_comment` | Attach a comment to an address |
//! | `define_type` | Register a named type in the type database |
//! | `create_symbol` | Create or update a named symbol |
//! | `run_analysis_pass` | Trigger a named analysis pass |
//! | `get_memory_bytes` | Read raw bytes from the binary at a virtual address |
//! | `search_pattern` | Search the image for a byte-pattern sequence |
//!
//! # Mock implementation
//!
//! [`MockHostApi`] is a fully in-memory implementation suitable for unit
//! tests.  It does not require an actual binary to be loaded.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::ScriptValue;

// ─── FunctionInfo ────────────────────────────────────────────────────────────

/// Information about a function exposed through the host API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionInfo {
    /// Function name (possibly demangled).
    pub name: String,
    /// Virtual address of the function entry point.
    pub address: u64,
    /// Size in bytes (0 if unknown).
    pub size: u64,
    /// Architecture tag for this function.
    pub arch: String,
}

impl FunctionInfo {
    /// Construct a `FunctionInfo`.
    #[must_use]
    pub fn new(name: impl Into<String>, address: u64, size: u64, arch: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            address,
            size,
            arch: arch.into(),
        }
    }

    /// Convert to a [`ScriptValue::Map`] for script consumption.
    #[must_use]
    pub fn to_script_value(&self) -> ScriptValue {
        let mut m = HashMap::new();
        m.insert("name".into(), ScriptValue::String(self.name.clone()));
        m.insert("address".into(), ScriptValue::Address(self.address));
        m.insert("size".into(), ScriptValue::Int(self.size.cast_signed()));
        m.insert("arch".into(), ScriptValue::String(self.arch.clone()));
        ScriptValue::Map(m)
    }
}

// ─── TypeDefinition ──────────────────────────────────────────────────────────

/// A named type registered in the type database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeDefinition {
    /// Type name.
    pub name: String,
    /// Size in bytes (0 for opaque / unknown types).
    pub size: usize,
    /// Kind tag: `"struct"`, `"union"`, `"enum"`, `"typedef"`, `"primitive"`.
    pub kind: String,
    /// Raw type source (e.g. C declaration).
    pub source: String,
}

impl TypeDefinition {
    /// Construct a `TypeDefinition`.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        size: usize,
        kind: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            size,
            kind: kind.into(),
            source: source.into(),
        }
    }

    /// Convert to a [`ScriptValue::Map`].
    #[must_use]
    pub fn to_script_value(&self) -> ScriptValue {
        let mut m = HashMap::new();
        m.insert("name".into(), ScriptValue::String(self.name.clone()));
        m.insert("size".into(), ScriptValue::Int(self.size as i64));
        m.insert("kind".into(), ScriptValue::String(self.kind.clone()));
        m.insert("source".into(), ScriptValue::String(self.source.clone()));
        ScriptValue::Map(m)
    }
}

// ─── SymbolDefinition ────────────────────────────────────────────────────────

/// A symbol created or updated through the host API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolDefinition {
    /// Symbol name.
    pub name: String,
    /// Virtual address.
    pub address: u64,
    /// Kind tag: `"function"`, `"data"`, `"label"`.
    pub kind: String,
}

impl SymbolDefinition {
    /// Construct a `SymbolDefinition`.
    #[must_use]
    pub fn new(name: impl Into<String>, address: u64, kind: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            address,
            kind: kind.into(),
        }
    }
}

// ─── PatternMatch ────────────────────────────────────────────────────────────

/// A single match returned by [`ScriptHostApi::search_pattern`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternMatch {
    /// Virtual address where the match begins.
    pub address: u64,
    /// The matched bytes.
    pub bytes: Vec<u8>,
}

impl PatternMatch {
    /// Construct a `PatternMatch`.
    #[must_use]
    pub const fn new(address: u64, bytes: Vec<u8>) -> Self {
        Self { address, bytes }
    }

    /// Convert to a [`ScriptValue::Map`].
    #[must_use]
    pub fn to_script_value(&self) -> ScriptValue {
        let mut m = HashMap::new();
        m.insert("address".into(), ScriptValue::Address(self.address));
        m.insert("bytes".into(), ScriptValue::Bytes(self.bytes.clone()));
        ScriptValue::Map(m)
    }
}

// ─── HostApiError ────────────────────────────────────────────────────────────

/// Errors returned by [`ScriptHostApi`] methods.
#[derive(Debug, thiserror::Error, Clone)]
pub enum HostApiError {
    /// Function was not found.
    #[error("function not found: {0}")]
    FunctionNotFound(String),
    /// Address is out of range.
    #[error("address out of range: 0x{0:x}")]
    AddressOutOfRange(u64),
    /// Type already registered.
    #[error("type already registered: {0}")]
    TypeAlreadyRegistered(String),
    /// Invalid argument.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// Analysis pass not found.
    #[error("analysis pass not found: {0}")]
    PassNotFound(String),
    /// Generic error.
    #[error("{0}")]
    Other(String),
}

// ─── ScriptHostApi trait ─────────────────────────────────────────────────────

/// The interface that scripting engines use to interrogate and modify the
/// reverse-engineering session.
///
/// Implementations may be backed by an actual binary view
/// (production) or by an in-memory mock (testing).
pub trait ScriptHostApi: Send + Sync {
    // ── Read operations ───────────────────────────────────────────────────────

    /// Look up a function by name, returning its information.
    ///
    /// # Errors
    /// Returns [`HostApiError::FunctionNotFound`] when no matching function exists.
    fn get_function(&self, name: &str) -> Result<FunctionInfo, HostApiError>;

    /// Look up a function by virtual address.
    ///
    /// # Errors
    /// Returns [`HostApiError::FunctionNotFound`] when no function covers `address`.
    fn get_function_at(&self, address: u64) -> Result<FunctionInfo, HostApiError>;

    /// Read `length` bytes from the binary at virtual address `address`.
    ///
    /// # Errors
    /// Returns [`HostApiError::AddressOutOfRange`] if the range falls outside
    /// the mapped image.
    fn get_memory_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, HostApiError>;

    /// Search the binary image for the given byte pattern, returning all matches.
    ///
    /// `pattern` elements are either a concrete byte value (`Some(b)`) or a
    /// wildcard (`None`).
    ///
    /// # Errors
    /// Returns [`HostApiError::Other`] on internal error.
    fn search_pattern(&self, pattern: &[Option<u8>]) -> Result<Vec<PatternMatch>, HostApiError>;

    // ── Write operations ──────────────────────────────────────────────────────

    /// Attach a comment to a virtual address.
    ///
    /// # Errors
    /// Returns an error if the address is not mapped.
    fn set_comment(&self, address: u64, comment: &str) -> Result<(), HostApiError>;

    /// Register a named type in the type database.
    ///
    /// # Errors
    /// Returns [`HostApiError::TypeAlreadyRegistered`] if the name is taken and
    /// `overwrite` is `false`.
    fn define_type(&self, def: TypeDefinition, overwrite: bool) -> Result<(), HostApiError>;

    /// Create or update a named symbol.
    ///
    /// # Errors
    /// Returns an error if the address is invalid or the arguments are malformed.
    fn create_symbol(&self, sym: SymbolDefinition) -> Result<(), HostApiError>;

    /// Trigger a named analysis pass.
    ///
    /// # Errors
    /// Returns [`HostApiError::PassNotFound`] if no pass with that name is registered.
    fn run_analysis_pass(&self, pass_name: &str) -> Result<(), HostApiError>;

    // ── Listing ───────────────────────────────────────────────────────────────

    /// Return all function names known to the host.
    fn list_functions(&self) -> Vec<String>;

    /// Return all type names defined in the type database.
    fn list_types(&self) -> Vec<String>;

    /// Return all comment addresses.
    fn list_comment_addresses(&self) -> Vec<u64>;
}

// ─── MockHostApi ─────────────────────────────────────────────────────────────

/// Fully in-memory mock implementation of [`ScriptHostApi`].
///
/// Suitable for unit tests and CI environments where no binary is loaded.
/// Data can be pre-populated via the `with_*` builder methods, or mutated
/// directly through the inner `Arc<Mutex<MockState>>`.
#[derive(Debug, Clone)]
pub struct MockHostApi {
    state: Arc<Mutex<MockState>>,
}

#[derive(Debug, Default)]
struct MockState {
    functions: HashMap<String, FunctionInfo>,
    types: HashMap<String, TypeDefinition>,
    symbols: HashMap<String, SymbolDefinition>,
    comments: HashMap<u64, String>,
    memory: Vec<u8>,
    memory_base: u64,
    available_passes: Vec<String>,
    ran_passes: Vec<String>,
}

impl Default for MockHostApi {
    fn default() -> Self {
        Self::new()
    }
}

impl MockHostApi {
    /// Create an empty mock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(MockState::default())),
        }
    }

    /// Pre-populate with a memory image.
    ///
    /// # Panics
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn with_memory(self, base: u64, data: Vec<u8>) -> Self {
        let mut s = self.state.lock().unwrap();
        s.memory_base = base;
        s.memory = data;
        drop(s);
        self
    }

    /// Register a function.
    ///
    /// # Panics
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn with_function(self, info: FunctionInfo) -> Self {
        self.state
            .lock()
            .unwrap()
            .functions
            .insert(info.name.clone(), info);
        self
    }

    /// Register an available analysis pass.
    ///
    /// # Panics
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn with_pass(self, name: impl Into<String>) -> Self {
        self.state
            .lock()
            .unwrap()
            .available_passes
            .push(name.into());
        self
    }

    /// Return all pass names that have been run.
    ///
    /// # Panics
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn ran_passes(&self) -> Vec<String> {
        self.state.lock().unwrap().ran_passes.clone()
    }

    /// Return comments stored in the mock.
    ///
    /// # Panics
    /// Panics if internal invariants are violated.
    #[must_use]
    pub fn comments(&self) -> HashMap<u64, String> {
        self.state.lock().unwrap().comments.clone()
    }
}

impl ScriptHostApi for MockHostApi {
    fn get_function(&self, name: &str) -> Result<FunctionInfo, HostApiError> {
        self.state
            .lock()
            .unwrap()
            .functions
            .get(name)
            .cloned()
            .ok_or_else(|| HostApiError::FunctionNotFound(name.to_owned()))
    }

    fn get_function_at(&self, address: u64) -> Result<FunctionInfo, HostApiError> {
        let s = self.state.lock().unwrap();
        s.functions
            .values()
            .find(|f| address >= f.address && (f.size == 0 || address < f.address + f.size))
            .cloned()
            .ok_or_else(|| HostApiError::FunctionNotFound(format!("0x{address:x}")))
    }

    fn get_memory_bytes(&self, address: u64, length: usize) -> Result<Vec<u8>, HostApiError> {
        let s = self.state.lock().unwrap();
        if s.memory.is_empty() {
            return Ok(vec![0u8; length]);
        }
        let offset = address
            .checked_sub(s.memory_base)
            .ok_or(HostApiError::AddressOutOfRange(address))? as usize;
        let end = offset
            .checked_add(length)
            .ok_or(HostApiError::AddressOutOfRange(address))?;
        if end > s.memory.len() {
            return Err(HostApiError::AddressOutOfRange(address));
        }
        Ok(s.memory[offset..end].to_vec())
    }

    fn search_pattern(&self, pattern: &[Option<u8>]) -> Result<Vec<PatternMatch>, HostApiError> {
        if pattern.is_empty() {
            return Ok(vec![]);
        }
        let s = self.state.lock().unwrap();
        let data = &s.memory;
        let base = s.memory_base;
        let plen = pattern.len();
        let mut matches = Vec::new();

        if data.len() < plen {
            return Ok(matches);
        }

        for i in 0..=(data.len() - plen) {
            if pattern
                .iter()
                .zip(&data[i..])
                .all(|(p, b)| p.is_none_or(|x| x == *b))
            {
                matches.push(PatternMatch::new(
                    base + i as u64,
                    data[i..i + plen].to_vec(),
                ));
            }
        }
        Ok(matches)
    }

    fn set_comment(&self, address: u64, comment: &str) -> Result<(), HostApiError> {
        self.state
            .lock()
            .unwrap()
            .comments
            .insert(address, comment.to_owned());
        Ok(())
    }

    fn define_type(&self, def: TypeDefinition, overwrite: bool) -> Result<(), HostApiError> {
        let mut s = self.state.lock().unwrap();
        if s.types.contains_key(&def.name) && !overwrite {
            return Err(HostApiError::TypeAlreadyRegistered(def.name));
        }
        s.types.insert(def.name.clone(), def);
        Ok(())
    }

    fn create_symbol(&self, sym: SymbolDefinition) -> Result<(), HostApiError> {
        self.state
            .lock()
            .unwrap()
            .symbols
            .insert(sym.name.clone(), sym);
        Ok(())
    }

    fn run_analysis_pass(&self, pass_name: &str) -> Result<(), HostApiError> {
        let mut s = self.state.lock().unwrap();
        if !s.available_passes.iter().any(|p| p == pass_name) {
            return Err(HostApiError::PassNotFound(pass_name.to_owned()));
        }
        s.ran_passes.push(pass_name.to_owned());
        Ok(())
    }

    fn list_functions(&self) -> Vec<String> {
        self.state
            .lock()
            .unwrap()
            .functions
            .keys()
            .cloned()
            .collect()
    }

    fn list_types(&self) -> Vec<String> {
        self.state.lock().unwrap().types.keys().cloned().collect()
    }

    fn list_comment_addresses(&self) -> Vec<u64> {
        self.state
            .lock()
            .unwrap()
            .comments
            .keys()
            .copied()
            .collect()
    }
}

// ─── HostApiAdapter ──────────────────────────────────────────────────────────

/// Bridges a `Box<dyn ScriptHostApi>` into a set of [`crate::NativeFunction`]s
/// that can be registered into a [`crate::ScriptContext`].
///
/// Provides a single [`HostApiAdapter::into_module`] method returning a
/// [`crate::ScriptModule`] that wraps every host-API method.
pub struct HostApiAdapter {
    api: Arc<dyn ScriptHostApi>,
}

impl HostApiAdapter {
    /// Construct an adapter wrapping `api`.
    #[must_use]
    pub fn new(api: Arc<dyn ScriptHostApi>) -> Self {
        Self { api }
    }

    /// Build a [`crate::ScriptModule`] containing wrappers for all host-API
    /// methods.
    #[must_use]
    pub fn into_module(self) -> crate::ScriptModule {
        let mut m = crate::ScriptModule::new("host");

        // get_function
        {
            let api = Arc::clone(&self.api);
            m.add_fn(
                "get_function",
                crate::native_fn(move |args| -> Result<ScriptValue, crate::ScriptError> {
                    let name = args
                        .first()
                        .ok_or_else(|| crate::ScriptError::ArityMismatch {
                            name: "get_function".into(),
                            expected: 1,
                            got: 0,
                        })?
                        .as_str()?;
                    api.get_function(name)
                        .map(|f| f.to_script_value())
                        .map_err(|e| crate::ScriptError::RuntimeError(e.to_string()))
                }),
            );
        }

        // set_comment
        {
            let api = Arc::clone(&self.api);
            m.add_fn(
                "set_comment",
                crate::native_fn(move |args| -> Result<ScriptValue, crate::ScriptError> {
                    if args.len() < 2 {
                        return Err(crate::ScriptError::ArityMismatch {
                            name: "set_comment".into(),
                            expected: 2,
                            got: args.len(),
                        });
                    }
                    let addr = args[0].as_address()?;
                    let text = args[1].as_str()?;
                    api.set_comment(addr, text)
                        .map(|()| ScriptValue::Null)
                        .map_err(|e| crate::ScriptError::RuntimeError(e.to_string()))
                }),
            );
        }

        // get_memory_bytes
        {
            let api = Arc::clone(&self.api);
            m.add_fn(
                "get_memory_bytes",
                crate::native_fn(move |args| -> Result<ScriptValue, crate::ScriptError> {
                    if args.len() < 2 {
                        return Err(crate::ScriptError::ArityMismatch {
                            name: "get_memory_bytes".into(),
                            expected: 2,
                            got: args.len(),
                        });
                    }
                    let addr = args[0].as_address()?;
                    let len = args[1].as_int()? as usize;
                    api.get_memory_bytes(addr, len)
                        .map(ScriptValue::Bytes)
                        .map_err(|e| crate::ScriptError::RuntimeError(e.to_string()))
                }),
            );
        }

        // run_analysis_pass
        {
            let api = Arc::clone(&self.api);
            m.add_fn(
                "run_analysis_pass",
                crate::native_fn(move |args| -> Result<ScriptValue, crate::ScriptError> {
                    let name = args
                        .first()
                        .ok_or_else(|| crate::ScriptError::ArityMismatch {
                            name: "run_analysis_pass".into(),
                            expected: 1,
                            got: 0,
                        })?
                        .as_str()?;
                    api.run_analysis_pass(name)
                        .map(|()| ScriptValue::Null)
                        .map_err(|e| crate::ScriptError::RuntimeError(e.to_string()))
                }),
            );
        }

        // list_functions
        {
            let api = Arc::clone(&self.api);
            m.add_fn(
                "list_functions",
                crate::native_fn(move |_args| -> Result<ScriptValue, crate::ScriptError> {
                    let names = api.list_functions();
                    Ok(ScriptValue::List(
                        names.into_iter().map(ScriptValue::String).collect(),
                    ))
                }),
            );
        }

        m
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_api() -> MockHostApi {
        MockHostApi::new()
            .with_memory(0x1000, vec![0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x61, 0x73, 0x6D])
            .with_function(FunctionInfo::new("main", 0x1000, 0x100, "x86_64"))
            .with_function(FunctionInfo::new("helper", 0x1100, 0x50, "x86_64"))
            .with_pass("linear_sweep")
            .with_pass("type_inference")
    }

    #[test]
    fn test_get_function_found() {
        let api = sample_api();
        let f = api.get_function("main").unwrap();
        assert_eq!(f.name, "main");
        assert_eq!(f.address, 0x1000);
    }

    #[test]
    fn test_get_function_not_found() {
        let api = sample_api();
        let result = api.get_function("missing");
        assert!(matches!(result, Err(HostApiError::FunctionNotFound(_))));
    }

    #[test]
    fn test_get_function_at_hit() {
        let api = sample_api();
        let f = api.get_function_at(0x1050).unwrap();
        assert_eq!(f.name, "main");
    }

    #[test]
    fn test_get_function_at_miss() {
        let api = sample_api();
        let result = api.get_function_at(0x9999);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_memory_bytes() {
        let api = sample_api();
        let bytes = api.get_memory_bytes(0x1000, 4).unwrap();
        assert_eq!(bytes, vec![0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_get_memory_bytes_out_of_range() {
        let api = sample_api();
        let result = api.get_memory_bytes(0x2000, 4);
        assert!(matches!(result, Err(HostApiError::AddressOutOfRange(_))));
    }

    #[test]
    fn test_search_pattern_exact() {
        let api = sample_api();
        let matches = api.search_pattern(&[Some(0xAA), Some(0xBB)]).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].address, 0x1000);
    }

    #[test]
    fn test_search_pattern_wildcard() {
        let api = sample_api();
        // Pattern: 0xAA, wildcard, 0xCC
        let matches = api.search_pattern(&[Some(0xAA), None, Some(0xCC)]).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].bytes, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_search_pattern_wasm_magic() {
        let api = sample_api();
        let patt = [Some(0x00), Some(0x61), Some(0x73), Some(0x6D)];
        let matches = api.search_pattern(&patt).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].address, 0x1004);
    }

    #[test]
    fn test_search_pattern_empty_pattern() {
        let api = sample_api();
        let matches = api.search_pattern(&[]).unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn test_set_comment() {
        let api = sample_api();
        api.set_comment(0x1000, "entry point").unwrap();
        let comments = api.comments();
        assert_eq!(comments.get(&0x1000).unwrap(), "entry point");
    }

    #[test]
    fn test_set_multiple_comments() {
        let api = sample_api();
        api.set_comment(0x1000, "fn start").unwrap();
        api.set_comment(0x1010, "branch here").unwrap();
        let addrs = api.list_comment_addresses();
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn test_define_type_ok() {
        let api = sample_api();
        let td = TypeDefinition::new("MyStruct", 16, "struct", "struct MyStruct { int a; }");
        api.define_type(td, false).unwrap();
        let types = api.list_types();
        assert!(types.contains(&"MyStruct".to_owned()));
    }

    #[test]
    fn test_define_type_duplicate_no_overwrite() {
        let api = sample_api();
        let td = TypeDefinition::new("T", 4, "primitive", "");
        api.define_type(td.clone(), false).unwrap();
        let result = api.define_type(td, false);
        assert!(matches!(
            result,
            Err(HostApiError::TypeAlreadyRegistered(_))
        ));
    }

    #[test]
    fn test_define_type_overwrite() {
        let api = sample_api();
        let td1 = TypeDefinition::new("T", 4, "primitive", "");
        let td2 = TypeDefinition::new("T", 8, "primitive", "");
        api.define_type(td1, false).unwrap();
        api.define_type(td2, true).unwrap(); // should not error
    }

    #[test]
    fn test_create_symbol() {
        let api = sample_api();
        api.create_symbol(SymbolDefinition::new("entry", 0x1000, "function"))
            .unwrap();
        // No error expected.
    }

    #[test]
    fn test_run_analysis_pass_ok() {
        let api = sample_api();
        api.run_analysis_pass("linear_sweep").unwrap();
        assert_eq!(api.ran_passes(), vec!["linear_sweep"]);
    }

    #[test]
    fn test_run_analysis_pass_not_found() {
        let api = sample_api();
        let result = api.run_analysis_pass("nonexistent_pass");
        assert!(matches!(result, Err(HostApiError::PassNotFound(_))));
    }

    #[test]
    fn test_list_functions() {
        let api = sample_api();
        let names = api.list_functions();
        assert!(names.contains(&"main".to_owned()));
        assert!(names.contains(&"helper".to_owned()));
    }

    #[test]
    fn test_function_info_to_script_value() {
        let f = FunctionInfo::new("main", 0x1000, 64, "x86_64");
        let v = f.to_script_value();
        if let ScriptValue::Map(m) = &v {
            assert!(m.contains_key("name"));
            assert!(m.contains_key("address"));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn test_type_definition_to_script_value() {
        let td = TypeDefinition::new("Foo", 8, "struct", "struct Foo {};");
        let v = td.to_script_value();
        if let ScriptValue::Map(m) = &v {
            assert_eq!(m["name"], ScriptValue::String("Foo".into()));
            assert_eq!(m["size"], ScriptValue::Int(8));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn test_pattern_match_to_script_value() {
        let pm = PatternMatch::new(0x2000, vec![0x90, 0x90]);
        let v = pm.to_script_value();
        if let ScriptValue::Map(m) = &v {
            assert_eq!(m["address"], ScriptValue::Address(0x2000));
        } else {
            panic!("expected map");
        }
    }

    #[test]
    fn test_host_api_adapter_module() {
        let api: Arc<dyn ScriptHostApi> = Arc::new(sample_api());
        let adapter = HostApiAdapter::new(api);
        let module = adapter.into_module();
        assert!(module.get_fn("get_function").is_some());
        assert!(module.get_fn("set_comment").is_some());
        assert!(module.get_fn("get_memory_bytes").is_some());
        assert!(module.get_fn("run_analysis_pass").is_some());
        assert!(module.get_fn("list_functions").is_some());
    }

    #[test]
    fn test_mock_host_api_default() {
        let api = MockHostApi::default();
        assert!(api.list_functions().is_empty());
        assert!(api.list_types().is_empty());
    }

    #[test]
    fn test_host_api_error_display() {
        let e = HostApiError::FunctionNotFound("foo".into());
        assert!(e.to_string().contains("foo"));
        let e2 = HostApiError::AddressOutOfRange(0xDEAD);
        assert!(e2.to_string().contains("dead"));
    }
}
