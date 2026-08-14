//! WebAssembly plugin runtime — abstract interface for hosting WASM plugins.
//!
//! Provides a `WasmRuntime` trait and an in-process mock implementation
//! (`MockWasmRuntime`) that exercises the full host-function registration
//! and memory-management API without requiring an actual WebAssembly engine.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};

// ─── Error ────────────────────────────────────────────────────────────────────

/// Errors from the WASM plugin runtime.
#[derive(Debug, Clone)]
pub enum WasmRuntimeError {
    /// The module bytecode is malformed or not valid WASM.
    InvalidModule(String),
    /// A requested export was not found in the module.
    ExportNotFound(String),
    /// A requested import was not found in the host registry.
    ImportNotFound(String),
    /// The plugin attempted an out-of-bounds memory access.
    MemoryOutOfBounds { offset: u32, size: u32, cap: u32 },
    /// Host function returned an error.
    HostFunctionError(String),
    /// Plugin trapped (unreachable, division by zero, etc.).
    Trap(String),
    /// Instance has been dropped or was never created.
    NotInstantiated,
    /// Generic runtime error.
    Other(String),
}

impl fmt::Display for WasmRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidModule(s) => write!(f, "invalid WASM module: {s}"),
            Self::ExportNotFound(s) => write!(f, "export not found: {s}"),
            Self::ImportNotFound(s) => write!(f, "import not found: {s}"),
            Self::MemoryOutOfBounds { offset, size, cap } => {
                write!(f, "memory OOB: offset={offset} size={size} cap={cap}")
            }
            Self::HostFunctionError(s) => write!(f, "host function error: {s}"),
            Self::Trap(s) => write!(f, "wasm trap: {s}"),
            Self::NotInstantiated => write!(f, "wasm instance not ready"),
            Self::Other(s) => write!(f, "wasm error: {s}"),
        }
    }
}

impl std::error::Error for WasmRuntimeError {}

// ─── WasmValue ────────────────────────────────────────────────────────────────

/// A WebAssembly value type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WasmValue {
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    V128(u128),
    FuncRef(Option<u32>),
    ExternRef(Option<u32>),
}

impl WasmValue {
    /// As i32 if variant matches.
    #[must_use]
    pub fn as_i32(&self) -> Option<i32> {
        if let Self::I32(v) = self { Some(*v) } else { None }
    }

    /// As i64 if variant matches.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        if let Self::I64(v) = self { Some(*v) } else { None }
    }

    /// As f64 if variant matches.
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        if let Self::F64(v) = self { Some(*v) } else { None }
    }
}

impl fmt::Display for WasmValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::I32(v) => write!(f, "i32({v})"),
            Self::I64(v) => write!(f, "i64({v})"),
            Self::F32(v) => write!(f, "f32({v})"),
            Self::F64(v) => write!(f, "f64({v})"),
            Self::V128(v) => write!(f, "v128({v:#034x})"),
            Self::FuncRef(r) => write!(f, "funcref({r:?})"),
            Self::ExternRef(r) => write!(f, "externref({r:?})"),
        }
    }
}

// ─── HostFunctionSignature ────────────────────────────────────────────────────

/// Type signature of a host function exposed to WASM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostFunctionSignature {
    /// Module name in the WASM import namespace.
    pub module: String,
    /// Function name.
    pub name: String,
    /// Parameter types.
    pub params: Vec<WasmValueType>,
    /// Return types.
    pub results: Vec<WasmValueType>,
}

/// A WebAssembly value type (not a concrete value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WasmValueType {
    I32,
    I64,
    F32,
    F64,
    V128,
    FuncRef,
    ExternRef,
}

impl fmt::Display for WasmValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::I32 => write!(f, "i32"),
            Self::I64 => write!(f, "i64"),
            Self::F32 => write!(f, "f32"),
            Self::F64 => write!(f, "f64"),
            Self::V128 => write!(f, "v128"),
            Self::FuncRef => write!(f, "funcref"),
            Self::ExternRef => write!(f, "externref"),
        }
    }
}

// ─── WasmMemory ───────────────────────────────────────────────────────────────

/// Linear memory abstraction for a WASM instance.
#[derive(Debug)]
pub struct WasmMemory {
    /// Raw memory pages (each page = 64 KiB).
    pages: Vec<[u8; 65536]>,
    /// Current page count.
    page_count: u32,
    /// Maximum page count (0 = unlimited).
    max_pages: u32,
}

impl WasmMemory {
    const PAGE_SIZE: usize = 65536;

    /// Create a new memory with `initial` pages.
    #[must_use]
    pub fn new(initial_pages: u32, max_pages: u32) -> Self {
        let count = initial_pages as usize;
        let pages = (0..count).map(|_| [0u8; Self::PAGE_SIZE]).collect();
        Self {
            pages,
            page_count: initial_pages,
            max_pages,
        }
    }

    /// Current byte size of the memory.
    #[must_use]
    pub fn byte_size(&self) -> usize {
        self.page_count as usize * Self::PAGE_SIZE
    }

    /// Read `len` bytes starting at `offset`.
    ///
    /// # Errors
    /// Returns `WasmRuntimeError::MemoryOutOfBounds` if the range exceeds memory.
    pub fn read(&self, offset: u32, len: u32) -> Result<Vec<u8>, WasmRuntimeError> {
        let start = offset as usize;
        let end = start.checked_add(len as usize).ok_or(WasmRuntimeError::MemoryOutOfBounds {
            offset,
            size: len,
            cap: self.byte_size() as u32,
        })?;
        let cap = self.byte_size();
        if end > cap {
            return Err(WasmRuntimeError::MemoryOutOfBounds {
                offset,
                size: len,
                cap: cap as u32,
            });
        }
        let page_idx = start / Self::PAGE_SIZE;
        let page_off = start % Self::PAGE_SIZE;
        // Fast path: fits in one page
        if page_off + len as usize <= Self::PAGE_SIZE {
            return Ok(self.pages[page_idx][page_off..page_off + len as usize].to_vec());
        }
        // Slow path: cross-page read
        let mut buf = Vec::with_capacity(len as usize);
        let mut remaining = len as usize;
        let mut byte_off = start;
        while remaining > 0 {
            let pg = byte_off / Self::PAGE_SIZE;
            let pg_off = byte_off % Self::PAGE_SIZE;
            let to_read = remaining.min(Self::PAGE_SIZE - pg_off);
            buf.extend_from_slice(&self.pages[pg][pg_off..pg_off + to_read]);
            byte_off += to_read;
            remaining -= to_read;
        }
        Ok(buf)
    }

    /// Write `data` at `offset`.
    ///
    /// # Errors
    /// Returns `WasmRuntimeError::MemoryOutOfBounds` if the write exceeds memory.
    pub fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), WasmRuntimeError> {
        let start = offset as usize;
        let end = start.checked_add(data.len()).ok_or(WasmRuntimeError::MemoryOutOfBounds {
            offset,
            size: data.len() as u32,
            cap: self.byte_size() as u32,
        })?;
        let cap = self.byte_size();
        if end > cap {
            return Err(WasmRuntimeError::MemoryOutOfBounds {
                offset,
                size: data.len() as u32,
                cap: cap as u32,
            });
        }
        let mut written = 0usize;
        let mut byte_off = start;
        while written < data.len() {
            let pg = byte_off / Self::PAGE_SIZE;
            let pg_off = byte_off % Self::PAGE_SIZE;
            let to_write = (data.len() - written).min(Self::PAGE_SIZE - pg_off);
            self.pages[pg][pg_off..pg_off + to_write]
                .copy_from_slice(&data[written..written + to_write]);
            byte_off += to_write;
            written += to_write;
        }
        Ok(())
    }

    /// Grow memory by `delta` pages.
    ///
    /// Returns the previous page count on success or an error if the limit would
    /// be exceeded.
    ///
    /// # Errors
    /// Returns `WasmRuntimeError::Other` if the max page limit is exceeded.
    pub fn grow(&mut self, delta: u32) -> Result<u32, WasmRuntimeError> {
        let prev = self.page_count;
        let new_count = prev.checked_add(delta).ok_or_else(|| {
            WasmRuntimeError::Other("memory grow: page count overflow".into())
        })?;
        if self.max_pages > 0 && new_count > self.max_pages {
            return Err(WasmRuntimeError::Other(format!(
                "memory grow: {new_count} pages would exceed max {}", self.max_pages
            )));
        }
        for _ in 0..delta {
            self.pages.push([0u8; Self::PAGE_SIZE]);
        }
        self.page_count = new_count;
        Ok(prev)
    }

    /// Read a null-terminated UTF-8 string from `offset`.
    ///
    /// # Errors
    /// Returns an error on OOB or invalid UTF-8.
    pub fn read_cstring(&self, offset: u32) -> Result<String, WasmRuntimeError> {
        const MAX_CSTRING_LEN: usize = 65536;
        let mut bytes = Vec::new();
        let mut i = offset;
        loop {
            if bytes.len() >= MAX_CSTRING_LEN {
                return Err(WasmRuntimeError::Other(
                    "read_cstring: string exceeds maximum length".into(),
                ));
            }
            let b = self
                .read(i, 1)
                .map_err(|e| WasmRuntimeError::Other(e.to_string()))?;
            if b[0] == 0 {
                break;
            }
            bytes.push(b[0]);
            i = i.checked_add(1).ok_or_else(|| {
                WasmRuntimeError::Other("read_cstring: offset overflow".into())
            })?;
        }
        String::from_utf8(bytes)
            .map_err(|e| WasmRuntimeError::Other(format!("invalid UTF-8: {e}")))
    }

    /// Write a null-terminated UTF-8 string at `offset`.
    pub fn write_cstring(&mut self, offset: u32, s: &str) -> Result<(), WasmRuntimeError> {
        let mut data = s.as_bytes().to_vec();
        data.push(0);
        self.write(offset, &data)
    }
}

// ─── WasmRuntime trait ────────────────────────────────────────────────────────

/// Abstract interface for a WASM plugin runtime.
///
/// Implementations could wrap `wasmtime`, `wasmer`, `wasm3`, or a mock.
pub trait WasmRuntime: Send + Sync {
    /// Load and validate a WASM module from bytes.
    ///
    /// # Errors
    /// Returns `WasmRuntimeError::InvalidModule` if the bytes are not a valid WASM module.
    fn load_module(&self, wasm_bytes: &[u8]) -> Result<ModuleHandle, WasmRuntimeError>;

    /// Instantiate a previously loaded module with a given set of host functions.
    ///
    /// # Errors
    /// Returns `WasmRuntimeError` if instantiation fails.
    fn instantiate(
        &self,
        module: &ModuleHandle,
        host_functions: &HostFunctionRegistry,
    ) -> Result<InstanceHandle, WasmRuntimeError>;

    /// Call an exported function by name with the given arguments.
    ///
    /// # Errors
    /// Returns `WasmRuntimeError` if the export does not exist or the call traps.
    fn call(
        &self,
        instance: &InstanceHandle,
        func_name: &str,
        args: &[WasmValue],
    ) -> Result<Vec<WasmValue>, WasmRuntimeError>;

    /// Get a shared reference to the instance's linear memory.
    ///
    /// # Errors
    /// Returns `WasmRuntimeError::NotInstantiated` if the instance has no memory.
    fn memory(&self, instance: &InstanceHandle) -> Result<Arc<Mutex<WasmMemory>>, WasmRuntimeError>;

    /// Drop an instance, releasing its resources.
    fn drop_instance(&self, instance: InstanceHandle);

    /// Drop a module, releasing its compiled code.
    fn drop_module(&self, module: ModuleHandle);

    /// Name of this runtime implementation.
    fn runtime_name(&self) -> &'static str;
}

// ─── Handles ─────────────────────────────────────────────────────────────────

/// Opaque handle to a compiled WASM module.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModuleHandle(pub u64);

/// Opaque handle to a running WASM instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InstanceHandle(pub u64);

// ─── HostFunctionRegistry ─────────────────────────────────────────────────────

/// Type alias for a boxed host function implementation.
pub type HostFn = Box<
    dyn Fn(&[WasmValue], Arc<Mutex<WasmMemory>>) -> Result<Vec<WasmValue>, WasmRuntimeError>
        + Send
        + Sync,
>;

/// Registry of host functions that WASM modules can import.
pub struct HostFunctionRegistry {
    functions: RwLock<HashMap<String, HostFn>>,
    signatures: RwLock<HashMap<String, HostFunctionSignature>>,
}

impl HostFunctionRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            functions: RwLock::new(HashMap::new()),
            signatures: RwLock::new(HashMap::new()),
        }
    }

    /// Register a host function under `module::name`.
    pub fn register(
        &self,
        module: impl Into<String>,
        name: impl Into<String>,
        sig: HostFunctionSignature,
        func: impl Fn(&[WasmValue], Arc<Mutex<WasmMemory>>) -> Result<Vec<WasmValue>, WasmRuntimeError>
            + Send
            + Sync
            + 'static,
    ) {
        let key = format!("{}::{}", sig.module, sig.name);
        self.functions.write().unwrap().insert(key.clone(), Box::new(func));
        self.signatures.write().unwrap().insert(key, sig);
        let _ = (module, name);
    }

    /// Look up a host function by `module::name`.
    ///
    /// # Errors
    /// Returns `WasmRuntimeError::ImportNotFound` if no function is registered.
    pub fn get(
        &self,
        module: &str,
        name: &str,
    ) -> Result<(), WasmRuntimeError> {
        let key = format!("{module}::{name}");
        if self.functions.read().unwrap().contains_key(&key) {
            Ok(())
        } else {
            Err(WasmRuntimeError::ImportNotFound(key))
        }
    }

    /// Call a registered host function.
    ///
    /// # Errors
    /// Returns `WasmRuntimeError::ImportNotFound` if no function is registered,
    /// or the error returned by the function itself.
    pub fn call(
        &self,
        module: &str,
        name: &str,
        args: &[WasmValue],
        mem: Arc<Mutex<WasmMemory>>,
    ) -> Result<Vec<WasmValue>, WasmRuntimeError> {
        let key = format!("{module}::{name}");
        let guard = self.functions.read().unwrap();
        let f = guard
            .get(&key)
            .ok_or_else(|| WasmRuntimeError::ImportNotFound(key.clone()))?;
        f(args, mem)
    }

    /// Number of registered host functions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.functions.read().unwrap().len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// All registered function keys (`module::name`).
    #[must_use]
    pub fn keys(&self) -> Vec<String> {
        self.signatures.read().unwrap().keys().cloned().collect()
    }
}

impl Default for HostFunctionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for HostFunctionRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HostFunctionRegistry {{ len: {} }}", self.len())
    }
}

// ─── MockWasmRuntime ──────────────────────────────────────────────────────────

/// A mock WASM runtime for testing that simulates the full API without executing
/// real WebAssembly bytecode.
#[derive(Debug)]
pub struct MockWasmRuntime {
    next_id: Mutex<u64>,
    /// Simulate a 4-page (256 KiB) memory per instance.
    memories: RwLock<HashMap<u64, Arc<Mutex<WasmMemory>>>>,
    /// Exported functions that the mock responds to: name → return values.
    exported_fns: RwLock<HashMap<String, Vec<WasmValue>>>,
}

impl MockWasmRuntime {
    /// Create a new mock runtime.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_id: Mutex::new(1),
            memories: RwLock::new(HashMap::new()),
            exported_fns: RwLock::new(HashMap::new()),
        }
    }

    /// Pre-register a mock export so calls to it return `result`.
    pub fn register_export(&self, name: impl Into<String>, result: Vec<WasmValue>) {
        self.exported_fns.write().unwrap().insert(name.into(), result);
    }

    fn next_id(&self) -> u64 {
        let mut id = self.next_id.lock().unwrap();
        let v = *id;
        *id += 1;
        v
    }
}

impl Default for MockWasmRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl WasmRuntime for MockWasmRuntime {
    fn load_module(&self, wasm_bytes: &[u8]) -> Result<ModuleHandle, WasmRuntimeError> {
        // Validate WASM magic number: 0x00 0x61 0x73 0x6D
        if wasm_bytes.len() < 4 || &wasm_bytes[0..4] != b"\x00asm" {
            return Err(WasmRuntimeError::InvalidModule(
                "missing WASM magic 0x00 'asm'".into(),
            ));
        }
        Ok(ModuleHandle(self.next_id()))
    }

    fn instantiate(
        &self,
        module: &ModuleHandle,
        _host_functions: &HostFunctionRegistry,
    ) -> Result<InstanceHandle, WasmRuntimeError> {
        let id = self.next_id();
        let mem = Arc::new(Mutex::new(WasmMemory::new(4, 256)));
        self.memories.write().unwrap().insert(id, mem);
        // Suppress unused variable warning.
        let _ = module;
        Ok(InstanceHandle(id))
    }

    fn call(
        &self,
        instance: &InstanceHandle,
        func_name: &str,
        _args: &[WasmValue],
    ) -> Result<Vec<WasmValue>, WasmRuntimeError> {
        // Verify the instance exists.
        if !self.memories.read().unwrap().contains_key(&instance.0) {
            return Err(WasmRuntimeError::NotInstantiated);
        }
        // Look up mock export.
        let guard = self.exported_fns.read().unwrap();
        if let Some(ret) = guard.get(func_name) {
            return Ok(ret.clone());
        }
        // Default: return a single i32(0).
        Ok(vec![WasmValue::I32(0)])
    }

    fn memory(&self, instance: &InstanceHandle) -> Result<Arc<Mutex<WasmMemory>>, WasmRuntimeError> {
        self.memories
            .read()
            .unwrap()
            .get(&instance.0)
            .cloned()
            .ok_or(WasmRuntimeError::NotInstantiated)
    }

    fn drop_instance(&self, instance: InstanceHandle) {
        self.memories.write().unwrap().remove(&instance.0);
    }

    fn drop_module(&self, _module: ModuleHandle) {
        // Nothing to drop in the mock.
    }

    fn runtime_name(&self) -> &'static str {
        "MockWasmRuntime"
    }
}

// ─── WasmPluginManager ────────────────────────────────────────────────────────

/// Manages the lifecycle of WASM plugins: load, instantiate, call, unload.
pub struct WasmPluginManager {
    runtime: Arc<dyn WasmRuntime>,
    host_functions: HostFunctionRegistry,
    modules: RwLock<HashMap<String, ModuleHandle>>,
    instances: RwLock<HashMap<String, InstanceHandle>>,
}

impl WasmPluginManager {
    /// Create a new manager backed by `runtime`.
    #[must_use]
    pub fn new(runtime: Arc<dyn WasmRuntime>) -> Self {
        Self {
            runtime,
            host_functions: HostFunctionRegistry::new(),
            modules: RwLock::new(HashMap::new()),
            instances: RwLock::new(HashMap::new()),
        }
    }

    /// Register a host function available to all loaded plugins.
    pub fn register_host_fn(
        &self,
        module: impl Into<String>,
        name: impl Into<String>,
        sig: HostFunctionSignature,
        func: impl Fn(&[WasmValue], Arc<Mutex<WasmMemory>>) -> Result<Vec<WasmValue>, WasmRuntimeError>
            + Send
            + Sync
            + 'static,
    ) {
        let m = module.into();
        let n = name.into();
        self.host_functions.register(m, n, sig, func);
    }

    /// Load a WASM plugin from bytes and associate it with `plugin_id`.
    ///
    /// # Errors
    /// Returns `WasmRuntimeError` if the module is invalid.
    pub fn load(&self, plugin_id: impl Into<String>, wasm_bytes: &[u8]) -> Result<(), WasmRuntimeError> {
        let id = plugin_id.into();
        let module = self.runtime.load_module(wasm_bytes)?;
        let instance = self.runtime.instantiate(&module, &self.host_functions)?;
        self.modules.write().unwrap().insert(id.clone(), module);
        self.instances.write().unwrap().insert(id, instance);
        Ok(())
    }

    /// Unload a plugin by ID.
    pub fn unload(&self, plugin_id: &str) {
        if let Some(inst) = self.instances.write().unwrap().remove(plugin_id) {
            self.runtime.drop_instance(inst);
        }
        if let Some(module) = self.modules.write().unwrap().remove(plugin_id) {
            self.runtime.drop_module(module);
        }
    }

    /// Call an exported function on a loaded plugin.
    ///
    /// # Errors
    /// Returns `WasmRuntimeError` if the plugin is not loaded or the call fails.
    pub fn call(
        &self,
        plugin_id: &str,
        func_name: &str,
        args: &[WasmValue],
    ) -> Result<Vec<WasmValue>, WasmRuntimeError> {
        let guard = self.instances.read().unwrap();
        let inst = guard
            .get(plugin_id)
            .ok_or_else(|| WasmRuntimeError::NotInstantiated)?;
        self.runtime.call(inst, func_name, args)
    }

    /// Access the linear memory of a loaded plugin.
    ///
    /// # Errors
    /// Returns `WasmRuntimeError` if the plugin is not loaded.
    pub fn memory(&self, plugin_id: &str) -> Result<Arc<Mutex<WasmMemory>>, WasmRuntimeError> {
        let guard = self.instances.read().unwrap();
        let inst = guard
            .get(plugin_id)
            .ok_or_else(|| WasmRuntimeError::NotInstantiated)?;
        self.runtime.memory(inst)
    }

    /// Whether a plugin with the given ID is currently loaded.
    #[must_use]
    pub fn is_loaded(&self, plugin_id: &str) -> bool {
        self.instances.read().unwrap().contains_key(plugin_id)
    }

    /// Number of loaded plugins.
    #[must_use]
    pub fn loaded_count(&self) -> usize {
        self.instances.read().unwrap().len()
    }

    /// IDs of all loaded plugins.
    #[must_use]
    pub fn loaded_ids(&self) -> Vec<String> {
        self.instances.read().unwrap().keys().cloned().collect()
    }

    /// Runtime name.
    #[must_use]
    pub fn runtime_name(&self) -> &'static str {
        self.runtime.runtime_name()
    }
}

impl fmt::Debug for WasmPluginManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "WasmPluginManager {{ runtime={}, loaded={} }}",
            self.runtime.runtime_name(),
            self.loaded_count()
        )
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const MOCK_WASM: &[u8] = b"\x00asm\x01\x00\x00\x00";

    fn mock_manager() -> WasmPluginManager {
        WasmPluginManager::new(Arc::new(MockWasmRuntime::new()))
    }

    // ── WasmMemory ────────────────────────────────────────────────────────

    #[test]
    fn test_memory_read_write() {
        let mut mem = WasmMemory::new(1, 0);
        mem.write(0, &[1, 2, 3]).unwrap();
        let data = mem.read(0, 3).unwrap();
        assert_eq!(data, vec![1, 2, 3]);
    }

    #[test]
    fn test_memory_oob_read() {
        let mem = WasmMemory::new(1, 0);
        let result = mem.read(65534, 5);
        assert!(matches!(result, Err(WasmRuntimeError::MemoryOutOfBounds { .. })));
    }

    #[test]
    fn test_memory_grow() {
        let mut mem = WasmMemory::new(1, 10);
        let prev = mem.grow(2).unwrap();
        assert_eq!(prev, 1);
        assert_eq!(mem.page_count, 3);
    }

    #[test]
    fn test_memory_grow_exceeds_max() {
        let mut mem = WasmMemory::new(1, 2);
        assert!(mem.grow(5).is_err());
    }

    #[test]
    fn test_memory_cstring_round_trip() {
        let mut mem = WasmMemory::new(1, 0);
        mem.write_cstring(100, "hello WASM").unwrap();
        let s = mem.read_cstring(100).unwrap();
        assert_eq!(s, "hello WASM");
    }

    #[test]
    fn test_memory_byte_size() {
        let mem = WasmMemory::new(2, 0);
        assert_eq!(mem.byte_size(), 2 * 65536);
    }

    // ── MockWasmRuntime ───────────────────────────────────────────────────

    #[test]
    fn test_load_valid_module() {
        let rt = MockWasmRuntime::new();
        let handle = rt.load_module(MOCK_WASM).unwrap();
        assert_eq!(handle.0, 1);
    }

    #[test]
    fn test_load_invalid_module() {
        let rt = MockWasmRuntime::new();
        let result = rt.load_module(b"not wasm");
        assert!(matches!(result, Err(WasmRuntimeError::InvalidModule(_))));
    }

    #[test]
    fn test_instantiate_and_call() {
        let rt = MockWasmRuntime::new();
        let module = rt.load_module(MOCK_WASM).unwrap();
        let registry = HostFunctionRegistry::new();
        let inst = rt.instantiate(&module, &registry).unwrap();
        let result = rt.call(&inst, "main", &[]).unwrap();
        assert_eq!(result, vec![WasmValue::I32(0)]);
    }

    #[test]
    fn test_mock_registered_export() {
        let rt = MockWasmRuntime::new();
        rt.register_export("my_func", vec![WasmValue::I32(42)]);
        let module = rt.load_module(MOCK_WASM).unwrap();
        let registry = HostFunctionRegistry::new();
        let inst = rt.instantiate(&module, &registry).unwrap();
        let result = rt.call(&inst, "my_func", &[]).unwrap();
        assert_eq!(result, vec![WasmValue::I32(42)]);
    }

    #[test]
    fn test_drop_instance() {
        let rt = Arc::new(MockWasmRuntime::new());
        let module = rt.load_module(MOCK_WASM).unwrap();
        let registry = HostFunctionRegistry::new();
        let inst = rt.instantiate(&module, &registry).unwrap();
        let id = inst.0;
        rt.drop_instance(inst);
        assert!(!rt.memories.read().unwrap().contains_key(&id));
    }

    #[test]
    fn test_runtime_name() {
        let rt = MockWasmRuntime::new();
        assert_eq!(rt.runtime_name(), "MockWasmRuntime");
    }

    // ── HostFunctionRegistry ──────────────────────────────────────────────

    #[test]
    fn test_registry_register_and_call() {
        let registry = HostFunctionRegistry::new();
        let sig = HostFunctionSignature {
            module: "env".into(),
            name: "add".into(),
            params: vec![WasmValueType::I32, WasmValueType::I32],
            results: vec![WasmValueType::I32],
        };
        registry.register("env", "add", sig, |args, _mem| {
            let a = args[0].as_i32().unwrap_or(0);
            let b = args[1].as_i32().unwrap_or(0);
            Ok(vec![WasmValue::I32(a + b)])
        });
        let mem = Arc::new(Mutex::new(WasmMemory::new(1, 0)));
        let result = registry
            .call("env", "add", &[WasmValue::I32(3), WasmValue::I32(4)], mem)
            .unwrap();
        assert_eq!(result, vec![WasmValue::I32(7)]);
    }

    #[test]
    fn test_registry_not_found() {
        let registry = HostFunctionRegistry::new();
        let mem = Arc::new(Mutex::new(WasmMemory::new(1, 0)));
        let result = registry.call("env", "missing", &[], mem);
        assert!(matches!(result, Err(WasmRuntimeError::ImportNotFound(_))));
    }

    #[test]
    fn test_registry_len() {
        let registry = HostFunctionRegistry::new();
        assert_eq!(registry.len(), 0);
        assert!(registry.is_empty());
    }

    // ── WasmPluginManager ─────────────────────────────────────────────────

    #[test]
    fn test_manager_load_and_is_loaded() {
        let mgr = mock_manager();
        mgr.load("my-plugin", MOCK_WASM).unwrap();
        assert!(mgr.is_loaded("my-plugin"));
        assert_eq!(mgr.loaded_count(), 1);
    }

    #[test]
    fn test_manager_unload() {
        let mgr = mock_manager();
        mgr.load("my-plugin", MOCK_WASM).unwrap();
        mgr.unload("my-plugin");
        assert!(!mgr.is_loaded("my-plugin"));
        assert_eq!(mgr.loaded_count(), 0);
    }

    #[test]
    fn test_manager_call() {
        let rt = Arc::new(MockWasmRuntime::new());
        rt.register_export("greet", vec![WasmValue::I32(1)]);
        let mgr = WasmPluginManager::new(rt);
        mgr.load("plugin-a", MOCK_WASM).unwrap();
        let result = mgr.call("plugin-a", "greet", &[]).unwrap();
        assert_eq!(result, vec![WasmValue::I32(1)]);
    }

    #[test]
    fn test_manager_call_not_loaded() {
        let mgr = mock_manager();
        let result = mgr.call("ghost", "fn", &[]);
        assert!(matches!(result, Err(WasmRuntimeError::NotInstantiated)));
    }

    #[test]
    fn test_manager_memory_access() {
        let mgr = mock_manager();
        mgr.load("plugin-b", MOCK_WASM).unwrap();
        let mem_arc = mgr.memory("plugin-b").unwrap();
        let mut mem = mem_arc.lock().unwrap();
        mem.write(0, b"hello").unwrap();
        let bytes = mem.read(0, 5).unwrap();
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn test_manager_loaded_ids() {
        let mgr = mock_manager();
        mgr.load("p1", MOCK_WASM).unwrap();
        mgr.load("p2", MOCK_WASM).unwrap();
        let ids = mgr.loaded_ids();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&"p1".to_string()));
    }

    #[test]
    fn test_manager_runtime_name() {
        let mgr = mock_manager();
        assert_eq!(mgr.runtime_name(), "MockWasmRuntime");
    }

    #[test]
    fn test_manager_debug() {
        let mgr = mock_manager();
        let s = format!("{mgr:?}");
        assert!(s.contains("WasmPluginManager"));
    }

    // ── WasmValue ─────────────────────────────────────────────────────────

    #[test]
    fn test_wasm_value_as_i32() {
        let v = WasmValue::I32(-7);
        assert_eq!(v.as_i32(), Some(-7));
        assert_eq!(WasmValue::F64(1.0).as_i32(), None);
    }

    #[test]
    fn test_wasm_value_display() {
        assert_eq!(WasmValue::I32(42).to_string(), "i32(42)");
        assert_eq!(WasmValue::I64(99).to_string(), "i64(99)");
    }

    #[test]
    fn test_wasm_value_type_display() {
        assert_eq!(WasmValueType::I32.to_string(), "i32");
        assert_eq!(WasmValueType::F64.to_string(), "f64");
    }

    // ── WasmRuntimeError ─────────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let e = WasmRuntimeError::ExportNotFound("_start".into());
        assert!(e.to_string().contains("_start"));
        let e2 = WasmRuntimeError::Trap("unreachable".into());
        assert!(e2.to_string().contains("unreachable"));
    }

    #[test]
    fn test_error_oob_display() {
        let e = WasmRuntimeError::MemoryOutOfBounds {
            offset: 100,
            size: 50,
            cap: 64,
        };
        assert!(e.to_string().contains("OOB"));
    }
}
