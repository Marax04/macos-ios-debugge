/// Rhai RE API module: exposes reverse-engineering functions to Rhai scripts.
///
/// This module builds a Rhai `Module` that scripts can import, providing:
/// - `disasm(addr, len)` — disassemble `len` bytes at `addr`
/// - `read_bytes(addr, len)` — read raw bytes from a memory provider
/// - `symbol_at(addr)` — look up the symbol nearest to `addr`
/// - `find_symbol(name)` — look up a symbol by name
/// - `function_at(addr)` — find the function containing `addr`
/// - `xrefs_to(addr)` — list cross-references to `addr`
///
/// All functions are stateless from the script's perspective; the actual
/// implementation is provided via an `Arc<dyn ReBackend>` trait object.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};

use crate::rhai_type_wrappers::{Address, Instruction, ReFunction, Symbol};
use crate::sat_i64_to_usize;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, thiserror::Error)]
pub enum ReApiError {
    #[error("backend not initialised")]
    BackendMissing,
    #[error("address {0:#x} is out of range")]
    AddressOutOfRange(u64),
    #[error("symbol not found: {0}")]
    SymbolNotFound(String),
    #[error("no function at address {0:#x}")]
    NoFunctionAt(u64),
    #[error("read of {len} bytes at {addr:#x} failed: {reason}")]
    ReadFailed { addr: u64, len: usize, reason: String },
    #[error("disassembly failed at {0:#x}: {1}")]
    DisasmFailed(u64, String),
    #[error("xref lookup failed at {0:#x}")]
    XrefFailed(u64),
}

// ---------------------------------------------------------------------------
// ReBackend — the interface that the host provides
// ---------------------------------------------------------------------------

/// Trait that host code must implement to provide RE operations to scripts.
pub trait ReBackend: Send + Sync {
    /// Disassemble up to `max_insns` instructions starting at `addr`.
    ///
    /// # Errors
    /// Returns `Err` if disassembly fails or the address is out of range.
    fn disasm(&self, addr: u64, max_insns: usize) -> Result<Vec<Instruction>, ReApiError>;
    /// Read `len` raw bytes starting at `addr`.
    ///
    /// # Errors
    /// Returns `Err` if the address range cannot be read.
    fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, ReApiError>;
    /// Find the symbol nearest to (or at) `addr`.
    ///
    /// # Errors
    /// Returns `Err` if the symbol lookup fails.
    fn symbol_at(&self, addr: u64) -> Result<Option<Symbol>, ReApiError>;
    /// Find a symbol by exact name.
    ///
    /// # Errors
    /// Returns `Err` if the symbol lookup fails.
    fn find_symbol(&self, name: &str) -> Result<Option<Symbol>, ReApiError>;
    /// Find the function containing `addr`.
    ///
    /// # Errors
    /// Returns `Err` if the function lookup fails.
    fn function_at(&self, addr: u64) -> Result<Option<ReFunction>, ReApiError>;
    /// List addresses that reference `addr`.
    ///
    /// # Errors
    /// Returns `Err` if the xref lookup fails.
    fn xrefs_to(&self, addr: u64) -> Result<Vec<u64>, ReApiError>;
}

// ---------------------------------------------------------------------------
// RegisteredFn — metadata about a function registered in the module
// ---------------------------------------------------------------------------

/// Metadata about one function exported from the RE API module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredFn {
    pub name: String,
    pub arity: usize,
    pub description: String,
}

// ---------------------------------------------------------------------------
// ApiModule — the Rhai module descriptor
// ---------------------------------------------------------------------------

/// Describes the complete set of functions registered in the RE API module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiModule {
    pub name: String,
    pub functions: Vec<RegisteredFn>,
}

impl ApiModule {
    #[must_use]
    pub fn re_api() -> Self {
        Self {
            name: "re".into(),
            functions: vec![
                RegisteredFn {
                    name: "disasm".into(),
                    arity: 2,
                    description: "disasm(addr, max_insns) → array of instruction strings".into(),
                },
                RegisteredFn {
                    name: "read_bytes".into(),
                    arity: 2,
                    description: "read_bytes(addr, len) → blob as array of ints".into(),
                },
                RegisteredFn {
                    name: "symbol_at".into(),
                    arity: 1,
                    description: "symbol_at(addr) → symbol name or empty string".into(),
                },
                RegisteredFn {
                    name: "find_symbol".into(),
                    arity: 1,
                    description: "find_symbol(name) → address (i64) or -1 if not found".into(),
                },
                RegisteredFn {
                    name: "function_at".into(),
                    arity: 1,
                    description: "function_at(addr) → function name or empty string".into(),
                },
                RegisteredFn {
                    name: "xrefs_to".into(),
                    arity: 1,
                    description: "xrefs_to(addr) → array of referencing addresses (i64)".into(),
                },
            ],
        }
    }

    #[must_use]
    pub const fn function_count(&self) -> usize {
        self.functions.len()
    }
}

// ---------------------------------------------------------------------------
// RhaiReApi — the registered function table / dispatcher
// ---------------------------------------------------------------------------

/// Holds the backend and exposes free functions suitable for Rhai registration.
///
/// The `Arc<Mutex<...>>` wrapper is required because Rhai closures must be
/// `'static + Send + Sync` and we need interior mutability for call-count tracking.
pub struct RhaiReApi {
    backend: Arc<dyn ReBackend>,
    call_counts: Mutex<HashMap<String, u64>>,
    module: ApiModule,
}

impl RhaiReApi {
    pub fn new(backend: Arc<dyn ReBackend>) -> Self {
        Self {
            backend,
            call_counts: Mutex::new(HashMap::new()),
            module: ApiModule::re_api(),
        }
    }

    fn increment(&self, name: &str) {
        if let Ok(mut m) = self.call_counts.lock() {
            *m.entry(name.to_string()).or_insert(0) += 1;
        }
    }

    // ------------------------------------------------------------------
    // Exposed functions (called by Rhai engine wrappers)
    // ------------------------------------------------------------------

    /// Disassemble `max_insns` instructions at `addr`. Returns a Vec of
    /// human-readable assembly strings.
    pub fn disasm(&self, addr: i64, max_insns: i64) -> Vec<String> {
        self.increment("disasm");
        let addr = addr.cast_unsigned();
        let max = sat_i64_to_usize(max_insns.max(1));
        self.backend.disasm(addr, max).map_or_else(
            |_| Vec::new(),
            |insns| insns.iter().map(Instruction::to_asm_string).collect(),
        )
    }

    /// Read `len` bytes at `addr`. Returns bytes as a `Vec<i64>`.
    pub fn read_bytes(&self, addr: i64, len: i64) -> Vec<i64> {
        self.increment("read_bytes");
        let len = sat_i64_to_usize(len.max(0)).min(65536);
        self.backend.read_bytes(addr.cast_unsigned(), len).map_or_else(
            |_| Vec::new(),
            |bytes| bytes.iter().map(|&b| i64::from(b)).collect(),
        )
    }

    /// Find the symbol at `addr`. Returns the name or an empty string.
    pub fn symbol_at(&self, addr: i64) -> String {
        self.increment("symbol_at");
        match self.backend.symbol_at(addr.cast_unsigned()) {
            Ok(Some(sym)) => sym.name_str().to_string(),
            _ => String::new(),
        }
    }

    /// Find the address of the symbol named `name`. Returns `-1` if not found.
    pub fn find_symbol(&self, name: String) -> i64 {
        self.increment("find_symbol");
        match self.backend.find_symbol(&name) {
            Ok(Some(sym)) => sym.address.raw().cast_signed(),
            _ => -1,
        }
    }

    /// Find the function containing `addr`. Returns the function name or empty.
    pub fn function_at(&self, addr: i64) -> String {
        self.increment("function_at");
        match self.backend.function_at(addr.cast_unsigned()) {
            Ok(Some(f)) => f.name_str().to_string(),
            _ => String::new(),
        }
    }

    /// List addresses referencing `addr`. Returns them as `Vec<i64>`.
    pub fn xrefs_to(&self, addr: i64) -> Vec<i64> {
        self.increment("xrefs_to");
        self.backend.xrefs_to(addr.cast_unsigned()).map_or_else(
            |_| Vec::new(),
            |refs| refs.iter().map(|&a| a.cast_signed()).collect(),
        )
    }

    // ------------------------------------------------------------------
    // Introspection
    // ------------------------------------------------------------------

    /// Return a snapshot of call counts for all registered functions.
    pub fn call_counts(&self) -> HashMap<String, u64> {
        self.call_counts.lock().map(|m| m.clone()).unwrap_or_default()
    }

    /// Module descriptor.
    #[must_use]
    pub const fn module(&self) -> &ApiModule {
        &self.module
    }
}

// ---------------------------------------------------------------------------
// NullBackend — a no-op backend for testing
// ---------------------------------------------------------------------------

/// A backend that returns empty/default values for all queries. Used in tests
/// and as a placeholder when no analysis database is loaded.
pub struct NullBackend;

impl ReBackend for NullBackend {
    fn disasm(&self, _addr: u64, _max_insns: usize) -> Result<Vec<Instruction>, ReApiError> {
        Ok(Vec::new())
    }
    fn read_bytes(&self, _addr: u64, len: usize) -> Result<Vec<u8>, ReApiError> {
        Ok(vec![0u8; len])
    }
    fn symbol_at(&self, _addr: u64) -> Result<Option<Symbol>, ReApiError> {
        Ok(None)
    }
    fn find_symbol(&self, name: &str) -> Result<Option<Symbol>, ReApiError> {
        let _ = name;
        Ok(None)
    }
    fn function_at(&self, _addr: u64) -> Result<Option<ReFunction>, ReApiError> {
        Ok(None)
    }
    fn xrefs_to(&self, _addr: u64) -> Result<Vec<u64>, ReApiError> {
        Ok(Vec::new())
    }
}

// ---------------------------------------------------------------------------
// MockBackend — a configurable backend for tests
// ---------------------------------------------------------------------------

/// A configurable backend that serves canned responses from in-memory tables.
pub struct MockBackend {
    symbols_by_addr: HashMap<u64, Symbol>,
    symbols_by_name: HashMap<String, Symbol>,
    functions: HashMap<u64, ReFunction>,
    xrefs: HashMap<u64, Vec<u64>>,
    memory: HashMap<u64, u8>,
}

impl MockBackend {
    #[must_use]
    pub fn new() -> Self {
        Self {
            symbols_by_addr: HashMap::new(),
            symbols_by_name: HashMap::new(),
            functions: HashMap::new(),
            xrefs: HashMap::new(),
            memory: HashMap::new(),
        }
    }

    pub fn add_symbol(&mut self, sym: Symbol) {
        self.symbols_by_name.insert(sym.name_str().to_string(), sym.clone());
        self.symbols_by_addr.insert(sym.address.raw(), sym);
    }

    pub fn add_function(&mut self, f: ReFunction) {
        self.functions.insert(f.address.raw(), f);
    }

    pub fn add_xref(&mut self, target: u64, from: u64) {
        self.xrefs.entry(target).or_default().push(from);
    }

    pub fn write_memory(&mut self, addr: u64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            self.memory.insert(addr + i as u64, b);
        }
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ReBackend for MockBackend {
    fn disasm(&self, addr: u64, max_insns: usize) -> Result<Vec<Instruction>, ReApiError> {
        // Produce fake NOP instructions from memory bytes.
        let mut result = Vec::new();
        let mut cur = addr;
        for _ in 0..max_insns {
            let byte = self.memory.get(&cur).copied().unwrap_or(0x90);
            let insn = Instruction::new(
                Address::new(cur),
                "nop",
                Vec::new(),
                vec![byte],
            )
            .map_err(|e| ReApiError::DisasmFailed(cur, e.to_string()))?;
            result.push(insn);
            cur = cur.wrapping_add(1);
        }
        Ok(result)
    }

    fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, ReApiError> {
        let bytes: Vec<u8> = (0..len)
            .map(|i| self.memory.get(&(addr + i as u64)).copied().unwrap_or(0))
            .collect();
        Ok(bytes)
    }

    fn symbol_at(&self, addr: u64) -> Result<Option<Symbol>, ReApiError> {
        Ok(self.symbols_by_addr.get(&addr).cloned())
    }

    fn find_symbol(&self, name: &str) -> Result<Option<Symbol>, ReApiError> {
        Ok(self.symbols_by_name.get(name).cloned())
    }

    fn function_at(&self, addr: u64) -> Result<Option<ReFunction>, ReApiError> {
        let result = self.functions.values().find(|f| f.contains(Address::new(addr))).cloned();
        Ok(result)
    }

    fn xrefs_to(&self, addr: u64) -> Result<Vec<u64>, ReApiError> {
        Ok(self.xrefs.get(&addr).cloned().unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rhai_type_wrappers::SymbolKind;

    fn api_with_mock() -> (RhaiReApi, Arc<MockBackend>) {
        let mut mock = MockBackend::new();
        mock.add_symbol(
            Symbol::new(Address::new(0x1000), "main", SymbolKind::Function)
                .unwrap()
                .with_size(0x100),
        );
        mock.add_function(ReFunction::new(Address::new(0x1000), "main", 0x100));
        mock.add_xref(0x1000, 0x2000);
        mock.add_xref(0x1000, 0x3000);
        mock.write_memory(0x1000, &[0x55, 0x48, 0x89, 0xE5]);
        let arc = Arc::new(mock);
        (RhaiReApi::new(arc.clone()), arc)
    }

    #[test]
    fn test_symbol_at_found() {
        let (api, _) = api_with_mock();
        assert_eq!(api.symbol_at(0x1000i64), "main");
    }

    #[test]
    fn test_symbol_at_not_found() {
        let (api, _) = api_with_mock();
        assert_eq!(api.symbol_at(0x9999i64), "");
    }

    #[test]
    fn test_find_symbol() {
        let (api, _) = api_with_mock();
        assert_eq!(api.find_symbol("main".into()), 0x1000i64);
        assert_eq!(api.find_symbol("nonexistent".into()), -1i64);
    }

    #[test]
    fn test_function_at() {
        let (api, _) = api_with_mock();
        assert_eq!(api.function_at(0x1050i64), "main");
        assert_eq!(api.function_at(0x9999i64), "");
    }

    #[test]
    fn test_xrefs_to() {
        let (api, _) = api_with_mock();
        let mut refs = api.xrefs_to(0x1000i64);
        refs.sort();
        assert_eq!(refs, vec![0x2000i64, 0x3000i64]);
    }

    #[test]
    fn test_read_bytes() {
        let (api, _) = api_with_mock();
        let bytes = api.read_bytes(0x1000i64, 4i64);
        assert_eq!(bytes, vec![0x55i64, 0x48, 0x89, 0xE5]);
    }

    #[test]
    fn test_disasm_returns_strings() {
        let (api, _) = api_with_mock();
        let insns = api.disasm(0x1000i64, 2i64);
        assert_eq!(insns.len(), 2);
        for s in &insns {
            assert!(s.contains("nop"));
        }
    }

    #[test]
    fn test_call_counts_tracked() {
        let (api, _) = api_with_mock();
        api.symbol_at(0x1000i64);
        api.symbol_at(0x2000i64);
        api.find_symbol("main".into());
        let counts = api.call_counts();
        assert_eq!(counts.get("symbol_at"), Some(&2));
        assert_eq!(counts.get("find_symbol"), Some(&1));
    }

    #[test]
    fn test_api_module_descriptor() {
        let (api, _) = api_with_mock();
        let module = api.module();
        assert_eq!(module.name, "re");
        assert_eq!(module.function_count(), 6);
    }

    #[test]
    fn test_null_backend_returns_defaults() {
        let api = RhaiReApi::new(Arc::new(NullBackend));
        assert_eq!(api.symbol_at(0i64), "");
        assert_eq!(api.find_symbol("x".into()), -1i64);
        assert!(api.disasm(0i64, 1i64).is_empty());
        let bytes = api.read_bytes(0i64, 4i64);
        assert_eq!(bytes, vec![0i64; 4]);
    }
}
