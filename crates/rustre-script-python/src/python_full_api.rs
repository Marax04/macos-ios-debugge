//! Complete Python API for `RustRE`.
//!
//! Provides `PythonFullApi`, `BvBinding`, `FuncBinding`, `TypeBinding`,
//! `DebugBinding`, and `YaraBinding` — the complete Python scripting surface
//! for the `RustRE` platform, built on top of `PyO3`.

use std::collections::HashMap;

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList, PyModule};
use serde::{Deserialize, Serialize};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ── Mock domain types ─────────────────────────────────────────────────────────

/// Mock binary metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockBinary {
    pub id: String,
    pub path: String,
    pub format: String,
    pub arch: String,
    pub entry_point: u64,
}

impl MockBinary {
    fn new(path: &str) -> Self {
        Self {
            id: format!("bin-{}", path.len()),
            path: path.to_string(),
            format: "PE".into(),
            arch: "x86_64".into(),
            entry_point: 0x1400,
        }
    }
}

/// Mock function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockFunction {
    pub addr: u64,
    pub name: String,
    pub size: u64,
    pub return_type: String,
    pub call_conv: String,
}

impl MockFunction {
    fn new(addr: u64, name: &str) -> Self {
        Self {
            addr,
            name: name.to_string(),
            size: 64,
            return_type: "int64_t".into(),
            call_conv: "cdecl".into(),
        }
    }
}

/// Mock type definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockType {
    pub name: String,
    pub kind: String,
    pub size_bytes: u32,
    pub fields: Vec<(String, String)>, // (name, type)
}

impl MockType {
    fn new(name: &str, kind: &str) -> Self {
        Self {
            name: name.to_string(),
            kind: kind.to_string(),
            size_bytes: 8,
            fields: Vec::new(),
        }
    }
}

/// Mock debug register set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockRegisters {
    pub rip: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rflags: u64,
}

impl MockRegisters {
    const fn at(rip: u64) -> Self {
        Self {
            rip,
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsp: 0x7fff_0000,
            rbp: 0x7fff_0100,
            rflags: 0x202,
        }
    }
}

/// YARA match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatchResult {
    pub rule_name: String,
    pub offsets: Vec<u64>,
    pub family: String,
    pub confidence: u8,
}

// ── BvBinding ─────────────────────────────────────────────────────────────────

/// Python-accessible binary view binding.
#[pyclass(name = "BvBinding")]
#[derive(Debug, Default)]
pub struct BvBinding {
    binaries: HashMap<String, MockBinary>,
}

#[pymethods]
impl BvBinding {
    #[new]
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a binary and return its ID.
    pub fn open(&mut self, path: &str) -> String {
        let b = MockBinary::new(path);
        let id = b.id.clone();
        self.binaries.insert(id.clone(), b);
        id
    }

    /// Close a binary by ID.
    pub fn close(&mut self, id: &str) -> bool {
        self.binaries.remove(id).is_some()
    }

    /// List open binary IDs.
    #[must_use] 
    pub fn list_ids(&self) -> Vec<String> {
        let mut ids: Vec<_> = self.binaries.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Get binary metadata as a dict.
    #[must_use] 
    pub fn info<'py>(&self, py: Python<'py>, id: &str) -> Option<Bound<'py, PyDict>> {
        let b = self.binaries.get(id)?;
        let d = PyDict::new(py);
        d.set_item("id", &b.id).ok()?;
        d.set_item("path", &b.path).ok()?;
        d.set_item("format", &b.format).ok()?;
        d.set_item("arch", &b.arch).ok()?;
        d.set_item("entry_point", b.entry_point).ok()?;
        Some(d)
    }

    /// Read bytes from the binary.
    #[must_use] 
    pub fn read_bytes(&self, id: &str, addr: u64, length: usize) -> Option<Vec<u8>> {
        if !self.binaries.contains_key(id) {
            return None;
        }
        Some(vec![(addr & 0xff) as u8; length])
    }

    /// Get all strings in the binary (mock).
    #[must_use] 
    pub fn get_strings<'py>(&self, py: Python<'py>, id: &str) -> Bound<'py, PyList> {
        let list = PyList::empty(py);
        if self.binaries.contains_key(id) {
            let _ = list.append("CreateRemoteThread");
            let _ = list.append("WriteProcessMemory");
            let _ = list.append("cmd.exe");
        }
        list
    }

    /// Number of open binaries.
    #[must_use] 
    pub fn count(&self) -> usize {
        self.binaries.len()
    }
}

// ── FuncBinding ───────────────────────────────────────────────────────────────

/// Python-accessible function binding.
#[pyclass(name = "FuncBinding")]
#[derive(Debug, Default)]
pub struct FuncBinding {
    /// Binary ID → functions.
    functions: HashMap<String, Vec<MockFunction>>,
    /// Renamed functions log.
    renames: Vec<(String, u64, String)>,
}

#[pymethods]
impl FuncBinding {
    #[new]
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed mock functions for a binary.
    pub fn seed(&mut self, binary_id: &str) {
        self.functions.insert(
            binary_id.to_string(),
            vec![
                MockFunction::new(0x1400, "entry"),
                MockFunction::new(0x1480, "main"),
                MockFunction::new(0x14C0, "sub_14C0"),
                MockFunction::new(0x1500, "WinMain"),
            ],
        );
    }

    /// Get all functions for a binary.
    #[must_use] 
    pub fn get_functions<'py>(&self, py: Python<'py>, binary_id: &str) -> Bound<'py, PyList> {
        let list = PyList::empty(py);
        if let Some(fns) = self.functions.get(binary_id) {
            for f in fns {
                let d = PyDict::new(py);
                let _ = d.set_item("addr", f.addr);
                let _ = d.set_item("name", &f.name);
                let _ = d.set_item("size", f.size);
                let _ = d.set_item("return_type", &f.return_type);
                let _ = list.append(d);
            }
        }
        list
    }

    /// Rename a function.
    pub fn rename(&mut self, binary_id: &str, addr: u64, new_name: &str) -> bool {
        if let Some(fns) = self.functions.get_mut(binary_id)
            && let Some(f) = fns.iter_mut().find(|f| f.addr == addr) {
                f.name = new_name.to_string();
                self.renames
                    .push((binary_id.to_string(), addr, new_name.to_string()));
                return true;
            }
        false
    }

    /// Get the decompiled pseudo-C for a function.
    #[must_use] 
    pub fn decompile(&self, _binary_id: &str, addr: u64) -> String {
        format!("int64_t sub_{addr:x}(void) {{\n    // body\n    return 0;\n}}")
    }

    /// Get xrefs to an address.
    #[must_use] 
    pub fn xrefs_to(&self, _binary_id: &str, addr: u64) -> Vec<u64> {
        vec![addr.wrapping_sub(0x10), addr.wrapping_sub(0x50)]
    }

    /// Count rename operations performed.
    #[must_use] 
    pub const fn rename_count(&self) -> usize {
        self.renames.len()
    }
}

// ── TypeBinding ───────────────────────────────────────────────────────────────

/// Python-accessible type binding.
#[pyclass(name = "TypeBinding")]
#[derive(Debug, Default)]
pub struct TypeBinding {
    types: HashMap<String, MockType>,
}

#[pymethods]
impl TypeBinding {
    #[new]
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Define a struct type.
    pub fn define_struct(&mut self, name: &str, fields: Vec<(String, String)>) -> bool {
        let mut t = MockType::new(name, "struct");
        t.fields = fields;
        t.size_bytes = u32::try_from(t.fields.len()).unwrap_or(u32::MAX) * 8;
        self.types.insert(name.to_string(), t);
        true
    }

    /// Define an enum type.
    pub fn define_enum(&mut self, name: &str, variants: Vec<String>) -> bool {
        let mut t = MockType::new(name, "enum");
        t.fields = variants.into_iter().map(|v| (v, "u32".into())).collect();
        self.types.insert(name.to_string(), t);
        true
    }

    /// Get type info as dict.
    #[must_use] 
    pub fn get_type<'py>(&self, py: Python<'py>, name: &str) -> Option<Bound<'py, PyDict>> {
        let t = self.types.get(name)?;
        let d = PyDict::new(py);
        d.set_item("name", &t.name).ok()?;
        d.set_item("kind", &t.kind).ok()?;
        d.set_item("size_bytes", t.size_bytes).ok()?;
        Some(d)
    }

    /// Check if a type is defined.
    #[must_use] 
    pub fn contains(&self, name: &str) -> bool {
        self.types.contains_key(name)
    }

    /// Remove a type.
    pub fn remove_type(&mut self, name: &str) -> bool {
        self.types.remove(name).is_some()
    }

    /// List all type names.
    #[must_use] 
    pub fn type_names(&self) -> Vec<String> {
        let mut names: Vec<_> = self.types.keys().cloned().collect();
        names.sort();
        names
    }

    /// Apply a type to an address.
    #[must_use] 
    pub fn apply_type(&self, _binary_id: &str, _addr: u64, name: &str) -> bool {
        self.types.contains_key(name)
    }

    /// Number of defined types.
    #[must_use] 
    pub fn count(&self) -> usize {
        self.types.len()
    }
}

// ── DebugBinding ──────────────────────────────────────────────────────────────

/// Python-accessible debugger binding.
#[pyclass(name = "DebugBinding")]
#[derive(Debug, Default)]
pub struct DebugBinding {
    sessions: HashMap<String, u32>, // id → pid
    breakpoints: HashMap<String, Vec<u64>>,
    current_ip: HashMap<String, u64>,
}

#[pymethods]
impl DebugBinding {
    #[new]
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Launch a process (mock).
    pub fn launch(&mut self, path: &str) -> String {
        let id = format!("dbg-{}", path.len());
        self.sessions.insert(id.clone(), 1000 + u32::try_from(path.len()).unwrap_or(0));
        self.breakpoints.insert(id.clone(), Vec::new());
        self.current_ip.insert(id.clone(), 0x1400);
        id
    }

    /// Attach to a running process.
    pub fn attach(&mut self, pid: u32) -> String {
        let id = format!("dbg-{pid}");
        self.sessions.insert(id.clone(), pid);
        self.breakpoints.insert(id.clone(), Vec::new());
        self.current_ip.insert(id.clone(), 0x0);
        id
    }

    /// Detach.
    pub fn detach(&mut self, session_id: &str) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    /// Set a breakpoint.
    pub fn set_breakpoint(&mut self, session_id: &str, addr: u64) -> bool {
        self.breakpoints.get_mut(session_id).is_some_and(|bps| {
            if !bps.contains(&addr) {
                bps.push(addr);
            }
            true
        })
    }

    /// Remove a breakpoint.
    pub fn remove_breakpoint(&mut self, session_id: &str, addr: u64) -> bool {
        self.breakpoints.get_mut(session_id).is_some_and(|bps| {
            let before = bps.len();
            bps.retain(|&b| b != addr);
            bps.len() < before
        })
    }

    /// List all breakpoints.
    #[must_use] 
    pub fn list_breakpoints(&self, session_id: &str) -> Vec<u64> {
        self.breakpoints
            .get(session_id)
            .cloned()
            .unwrap_or_default()
    }

    /// Get current instruction pointer.
    #[must_use] 
    pub fn get_ip(&self, session_id: &str) -> Option<u64> {
        self.current_ip.get(session_id).copied()
    }

    /// Get registers as dict.
    #[must_use] 
    pub fn get_registers<'py>(
        &self,
        py: Python<'py>,
        session_id: &str,
    ) -> Option<Bound<'py, PyDict>> {
        let ip = self.current_ip.get(session_id)?;
        let regs = MockRegisters::at(*ip);
        let d = PyDict::new(py);
        d.set_item("rip", regs.rip).ok()?;
        d.set_item("rax", regs.rax).ok()?;
        d.set_item("rsp", regs.rsp).ok()?;
        d.set_item("rbp", regs.rbp).ok()?;
        d.set_item("rflags", regs.rflags).ok()?;
        Some(d)
    }

    /// Step one instruction.
    pub fn step(&mut self, session_id: &str) -> bool {
        self.current_ip.get_mut(session_id).is_some_and(|ip| {
            *ip += 3; // mock: every instruction is 3 bytes
            true
        })
    }

    /// Read memory.
    #[must_use] 
    pub fn read_memory(&self, session_id: &str, addr: u64, length: usize) -> Option<Vec<u8>> {
        if !self.sessions.contains_key(session_id) {
            return None;
        }
        Some(vec![(addr & 0xff) as u8; length])
    }

    /// Write memory (mock).
    #[must_use] 
    pub fn write_memory(&self, session_id: &str, _addr: u64, _data: Vec<u8>) -> bool {
        self.sessions.contains_key(session_id)
    }

    /// Number of active sessions.
    #[must_use] 
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

// ── YaraBinding ───────────────────────────────────────────────────────────────

/// Python-accessible YARA binding.
#[pyclass(name = "YaraBinding")]
#[derive(Debug, Default)]
pub struct YaraBinding {
    rules: HashMap<String, String>, // name → source
}

#[pymethods]
impl YaraBinding {
    #[new]
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a YARA rule.
    pub fn add_rule(&mut self, name: &str, source: &str) -> bool {
        self.rules.insert(name.to_string(), source.to_string());
        true
    }

    /// Load rules from a string (mock: splits on `rule ` keyword).
    pub fn load_rules(&mut self, source: &str) -> usize {
        let count = source.matches("rule ").count();
        if count > 0 {
            self.rules
                .insert(format!("loaded_{}", now_secs()), source.to_string());
        }
        count
    }

    /// Remove a rule.
    pub fn remove_rule(&mut self, name: &str) -> bool {
        self.rules.remove(name).is_some()
    }

    /// Scan content against all rules.
    #[must_use] 
    pub fn scan<'py>(&self, py: Python<'py>, content: &[u8]) -> Bound<'py, PyList> {
        let results = PyList::empty(py);
        for (name, source) in &self.rules {
            // Mock: match if content contains the rule name as bytes.
            let lower = String::from_utf8_lossy(content).to_ascii_lowercase();
            if lower.contains(&name.to_ascii_lowercase()) {
                let d = PyDict::new(py);
                let _ = d.set_item("rule", name);
                let _ = d.set_item("offsets", vec![0u64]);
                let _ = d.set_item("family", source.contains("malware").to_string());
                let _ = results.append(d);
            }
        }
        results
    }

    /// Scan a file path (mock).
    #[must_use] 
    pub fn scan_file<'py>(&self, py: Python<'py>, _path: &str) -> Bound<'py, PyList> {
        PyList::empty(py)
    }

    /// Number of loaded rules.
    #[must_use] 
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// List rule names.
    #[must_use] 
    pub fn rule_names(&self) -> Vec<String> {
        let mut names: Vec<_> = self.rules.keys().cloned().collect();
        names.sort();
        names
    }
}

// ── PythonFullApi ─────────────────────────────────────────────────────────────

/// Top-level Python API coordinator.
///
/// Provides access to all sub-APIs via a single Python object: `api.bv`,
/// `api.func`, `api.types`, `api.debug`, `api.yara`.
#[pyclass(name = "PythonFullApi")]
pub struct PythonFullApi {
    #[pyo3(get)]
    pub bv: Py<BvBinding>,
    #[pyo3(get)]
    pub func: Py<FuncBinding>,
    #[pyo3(get)]
    pub types: Py<TypeBinding>,
    #[pyo3(get)]
    pub debug: Py<DebugBinding>,
    #[pyo3(get)]
    pub yara: Py<YaraBinding>,
    /// Script execution log.
    log: Vec<ApiLogEntry>,
}

/// Log entry for the Python API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiLogEntry {
    pub timestamp: u64,
    pub action: String,
    pub detail: String,
}

#[pymethods]
impl PythonFullApi {
    #[new]
    pub fn new(py: Python) -> PyResult<Self> {
        Ok(Self {
            bv: Py::new(py, BvBinding::new())?,
            func: Py::new(py, FuncBinding::new())?,
            types: Py::new(py, TypeBinding::new())?,
            debug: Py::new(py, DebugBinding::new())?,
            yara: Py::new(py, YaraBinding::new())?,
            log: Vec::new(),
        })
    }

    /// Log an action.
    pub fn log_action(&mut self, action: &str, detail: &str) {
        self.log.push(ApiLogEntry {
            timestamp: now_secs(),
            action: action.to_string(),
            detail: detail.to_string(),
        });
    }

    /// Return the log length.
    #[must_use] 
    pub const fn log_len(&self) -> usize {
        self.log.len()
    }

    /// Clear the log.
    pub fn clear_log(&mut self) {
        self.log.clear();
    }

    /// Return the API version string.
    #[must_use] 
    pub const fn version(&self) -> &'static str {
        "0.1.0"
    }

    /// Return all sub-API names.
    #[must_use] 
    pub fn sub_apis(&self) -> Vec<&str> {
        vec!["bv", "func", "types", "debug", "yara"]
    }
}

/// Register the `rustre` Python module.
pub fn register_module(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<BvBinding>()?;
    m.add_class::<FuncBinding>()?;
    m.add_class::<TypeBinding>()?;
    m.add_class::<DebugBinding>()?;
    m.add_class::<YaraBinding>()?;
    m.add_class::<PythonFullApi>()?;
    // Stamp the running Python's version into the module for introspection.
    let sys = py.import("sys")?;
    let version = sys.getattr("version")?;
    m.add("__python_version__", version)?;
    Ok(())
}

// ── PythonVersionInfo ─────────────────────────────────────────────────────────

/// Version and environment information for the Python API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PythonVersionInfo {
    pub rustre_version: String,
    pub pyo3_version: String,
    pub api_version: u32,
    pub supported_python_versions: Vec<String>,
    pub features: Vec<String>,
}

impl Default for PythonVersionInfo {
    fn default() -> Self {
        Self {
            rustre_version: "0.1.0".into(),
            pyo3_version: "0.23".into(),
            api_version: 1,
            supported_python_versions: vec![
                "3.8".into(),
                "3.9".into(),
                "3.10".into(),
                "3.11".into(),
                "3.12".into(),
            ],
            features: vec![
                "bv".into(),
                "func".into(),
                "types".into(),
                "debug".into(),
                "yara".into(),
            ],
        }
    }
}

impl PythonVersionInfo {
    /// Return `true` if the given Python version is supported.
    #[must_use]
    pub fn supports_python(&self, version: &str) -> bool {
        self.supported_python_versions.iter().any(|v| v == version)
    }

    /// Return `true` if the given feature is available.
    #[must_use]
    pub fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }
}

// ── PythonAnalysisProxy ───────────────────────────────────────────────────────

/// A high-level proxy that wraps `FuncBinding` + `TypeBinding` and exposes
/// combined analysis operations.
#[derive(Debug, Default)]
pub struct PythonAnalysisProxy {
    pub func: FuncBinding,
    pub types: TypeBinding,
    pub operation_log: Vec<String>,
}

impl PythonAnalysisProxy {
    /// Create a new proxy.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a binary (seeds functions).
    pub fn load_binary(&mut self, binary_id: &str) {
        self.func.seed(binary_id);
        self.operation_log
            .push(format!("loaded binary: {binary_id}"));
    }

    /// Rename a function and log it.
    pub fn rename(&mut self, binary_id: &str, addr: u64, name: &str) -> bool {
        let ok = self.func.rename(binary_id, addr, name);
        if ok {
            self.operation_log
                .push(format!("renamed 0x{addr:x} → {name}"));
        }
        ok
    }

    /// Define a struct type and log it.
    pub fn define_struct(&mut self, name: &str, fields: Vec<(String, String)>) -> bool {
        let ok = self.types.define_struct(name, fields);
        if ok {
            self.operation_log.push(format!("defined struct: {name}"));
        }
        ok
    }

    /// Return operation count.
    #[must_use]
    pub const fn operation_count(&self) -> usize {
        self.operation_log.len()
    }

    /// Clear the operation log.
    pub fn clear_log(&mut self) {
        self.operation_log.clear();
    }

    /// Return a summary of operations.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "PythonAnalysisProxy: {} operations, {} types, {} renames",
            self.operation_count(),
            self.types.count(),
            self.func.rename_count(),
        )
    }
}

// ── PythonDebugSession ────────────────────────────────────────────────────────

/// A named debug session wrapper with convenience methods.
#[derive(Debug)]
pub struct PythonDebugSession {
    pub session_id: String,
    pub inner: DebugBinding,
    pub event_log: Vec<String>,
}

impl PythonDebugSession {
    /// Create a session attached to the given PID.
    #[must_use]
    pub fn attach(pid: u32) -> Self {
        let mut inner = DebugBinding::new();
        let session_id = inner.attach(pid);
        Self {
            session_id,
            inner,
            event_log: Vec::new(),
        }
    }

    /// Set a breakpoint and log it.
    pub fn set_bp(&mut self, addr: u64) -> bool {
        let ok = self.inner.set_breakpoint(&self.session_id, addr);
        if ok {
            self.event_log.push(format!("bp set: 0x{addr:x}"));
        }
        ok
    }

    /// Step and log.
    pub fn step(&mut self) -> Option<u64> {
        if self.inner.step(&self.session_id) {
            let ip = self.inner.get_ip(&self.session_id);
            self.event_log
                .push(format!("step → ip=0x{:x}", ip.unwrap_or(0)));
            ip
        } else {
            None
        }
    }

    /// Return all logged events.
    #[must_use]
    pub fn events(&self) -> &[String] {
        &self.event_log
    }

    /// Event count.
    #[must_use]
    pub const fn event_count(&self) -> usize {
        self.event_log.len()
    }
}

// ── PythonScriptSession ───────────────────────────────────────────────────────

/// A named script session that groups multiple executions under one context.
#[derive(Debug)]
pub struct PythonScriptSession {
    /// Session identifier.
    pub id: String,
    /// Variables persisted across script executions.
    pub variables: HashMap<String, serde_json::Value>,
    /// Execution history (code snippet → result).
    pub history: Vec<(String, String)>,
    /// Maximum history entries.
    pub max_history: usize,
}

impl PythonScriptSession {
    /// Create a new session.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            variables: HashMap::new(),
            history: Vec::new(),
            max_history: 100,
        }
    }

    /// Record an execution.
    pub fn record(&mut self, code: impl Into<String>, result: impl Into<String>) {
        self.history.push((code.into(), result.into()));
        if self.history.len() > self.max_history {
            self.history.remove(0);
        }
    }

    /// Set a session variable.
    pub fn set_var(&mut self, name: impl Into<String>, value: serde_json::Value) {
        self.variables.insert(name.into(), value);
    }

    /// Get a session variable.
    #[must_use]
    pub fn get_var(&self, name: &str) -> Option<&serde_json::Value> {
        self.variables.get(name)
    }

    /// Number of history entries.
    #[must_use]
    pub const fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Clear execution history.
    pub fn clear_history(&mut self) {
        self.history.clear();
    }
}

// ── PythonTypeStubGenerator ───────────────────────────────────────────────────

/// Generates Python type stubs (`.pyi`) for `RustRE` `PyO3` bindings.
#[derive(Debug, Default)]
pub struct PythonTypeStubGenerator {
    classes: Vec<StubClass>,
}

/// A class stub definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StubClass {
    pub name: String,
    pub methods: Vec<StubMethod>,
    pub docstring: String,
}

/// A method stub definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StubMethod {
    pub name: String,
    pub params: Vec<String>,
    pub return_type: String,
    pub docstring: String,
}

impl PythonTypeStubGenerator {
    /// Create a new generator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a class stub.
    pub fn add_class(&mut self, cls: StubClass) {
        self.classes.push(cls);
    }

    /// Generate stub source for all registered classes.
    #[must_use]
    pub fn generate(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(256 + self.classes.len() * 128);
        out.push_str("# Auto-generated type stubs for rustre Python bindings\n");
        out.push_str("from typing import Optional, List, Dict, Any\n\n");
        for cls in &self.classes {
            let _ = writeln!(out, "class {}:", cls.name);
            if !cls.docstring.is_empty() {
                let _ = writeln!(out, "    \"\"\"{}\"\"\"", cls.docstring);
            }
            for m in &cls.methods {
                if m.params.is_empty() {
                    let _ = writeln!(out, "    def {}(self) -> {}: ...", m.name, m.return_type);
                } else {
                    let _ = writeln!(
                        out,
                        "    def {}(self, {}) -> {}: ...",
                        m.name,
                        m.params.join(", "),
                        m.return_type
                    );
                }
            }
            out.push('\n');
        }
        // Trim trailing newline to preserve previous join("\n") semantics.
        if out.ends_with('\n') {
            out.pop();
        }
        out
    }

    /// Number of classes.
    #[must_use]
    pub const fn class_count(&self) -> usize {
        self.classes.len()
    }

    /// Generate stubs for the standard `RustRE` API.
    #[must_use]
    pub fn rustre_stubs() -> Self {
        let mut gen_ = Self::new();
        gen_.add_class(StubClass {
            name: "BvBinding".into(),
            docstring: "Binary view binding.".into(),
            methods: vec![
                StubMethod {
                    name: "open".into(),
                    params: vec!["path: str".into()],
                    return_type: "str".into(),
                    docstring: "Open a binary.".into(),
                },
                StubMethod {
                    name: "close".into(),
                    params: vec!["id: str".into()],
                    return_type: "bool".into(),
                    docstring: "Close a binary.".into(),
                },
                StubMethod {
                    name: "list_ids".into(),
                    params: vec![],
                    return_type: "List[str]".into(),
                    docstring: "List open IDs.".into(),
                },
            ],
        });
        gen_.add_class(StubClass {
            name: "DebugBinding".into(),
            docstring: "Debugger binding.".into(),
            methods: vec![
                StubMethod {
                    name: "attach".into(),
                    params: vec!["pid: int".into()],
                    return_type: "str".into(),
                    docstring: "Attach to PID.".into(),
                },
                StubMethod {
                    name: "set_breakpoint".into(),
                    params: vec!["session_id: str".into(), "addr: int".into()],
                    return_type: "bool".into(),
                    docstring: "Set BP.".into(),
                },
            ],
        });
        gen_
    }
}

// ── PythonApiConfig ───────────────────────────────────────────────────────────

/// Configuration for the Python full API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PythonApiConfig {
    /// Whether to expose debug bindings.
    pub expose_debug: bool,
    /// Whether to expose YARA bindings.
    pub expose_yara: bool,
    /// Maximum YARA rule set size.
    pub max_yara_rules: usize,
    /// Script execution timeout in seconds (0 = unlimited).
    pub timeout_secs: u64,
    /// Whether to enable sandbox mode (restricts filesystem/network access).
    pub sandbox: bool,
    /// Module name in Python.
    pub module_name: String,
}

impl Default for PythonApiConfig {
    fn default() -> Self {
        Self {
            expose_debug: true,
            expose_yara: true,
            max_yara_rules: 1000,
            timeout_secs: 30,
            sandbox: true,
            module_name: "rustre".into(),
        }
    }
}

impl PythonApiConfig {
    /// Create with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a permissive config (no sandbox).
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            sandbox: false,
            timeout_secs: 0,
            ..Default::default()
        }
    }

    /// Validate the config, returning error messages.
    #[must_use]
    pub fn validate(&self) -> Vec<String> {
        let mut errors: Vec<String> = Vec::with_capacity(2);
        if self.module_name.is_empty() {
            errors.push("module_name must not be empty".into());
        }
        if self.max_yara_rules == 0 {
            errors.push("max_yara_rules must be > 0".into());
        }
        errors
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── BvBinding ────────────────────────────────────────────────────────────

    #[test]
    fn test_bv_open_and_list() {
        pyo3::prepare_freethreaded_python();
        let mut bv = BvBinding::new();
        let id = bv.open("/tmp/test.exe");
        assert!(!id.is_empty());
        assert!(bv.list_ids().contains(&id));
    }

    #[test]
    fn test_bv_close() {
        pyo3::prepare_freethreaded_python();
        let mut bv = BvBinding::new();
        let id = bv.open("/tmp/t.exe");
        assert!(bv.close(&id));
        assert!(!bv.list_ids().contains(&id));
    }

    #[test]
    fn test_bv_read_bytes() {
        pyo3::prepare_freethreaded_python();
        let mut bv = BvBinding::new();
        let id = bv.open("/tmp/t.exe");
        let bytes = bv.read_bytes(&id, 0x1000, 8).unwrap();
        assert_eq!(bytes.len(), 8);
    }

    #[test]
    fn test_bv_count() {
        pyo3::prepare_freethreaded_python();
        let mut bv = BvBinding::new();
        assert_eq!(bv.count(), 0);
        bv.open("/tmp/a.exe");
        assert_eq!(bv.count(), 1);
    }

    #[test]
    fn test_bv_info_python() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let mut bv = BvBinding::new();
            let id = bv.open("/tmp/test.exe");
            let info = bv.info(py, &id).unwrap();
            let format: String = info.get_item("format").unwrap().unwrap().extract().unwrap();
            assert_eq!(format, "PE");
        });
    }

    #[test]
    fn test_bv_get_strings_python() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let mut bv = BvBinding::new();
            let id = bv.open("/tmp/t.exe");
            let strings = bv.get_strings(py, &id);
            assert!(strings.len() > 0);
        });
    }

    // ── FuncBinding ──────────────────────────────────────────────────────────

    #[test]
    fn test_func_seed_and_get() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let mut fb = FuncBinding::new();
            fb.seed("bv1");
            let fns = fb.get_functions(py, "bv1");
            assert!(fns.len() > 0);
        });
    }

    #[test]
    fn test_func_rename() {
        pyo3::prepare_freethreaded_python();
        let mut fb = FuncBinding::new();
        fb.seed("bv1");
        assert!(fb.rename("bv1", 0x1480, "init_malware"));
        assert_eq!(fb.rename_count(), 1);
    }

    #[test]
    fn test_func_decompile() {
        pyo3::prepare_freethreaded_python();
        let fb = FuncBinding::new();
        let code = fb.decompile("bv1", 0x1480);
        assert!(code.contains("sub_1480"));
    }

    #[test]
    fn test_func_xrefs_to() {
        pyo3::prepare_freethreaded_python();
        let fb = FuncBinding::new();
        let xrefs = fb.xrefs_to("bv1", 0x1480);
        assert!(!xrefs.is_empty());
    }

    // ── TypeBinding ──────────────────────────────────────────────────────────

    #[test]
    fn test_type_define_struct() {
        pyo3::prepare_freethreaded_python();
        let mut tb = TypeBinding::new();
        assert!(tb.define_struct(
            "POINT",
            vec![
                ("x".into(), "int32_t".into()),
                ("y".into(), "int32_t".into())
            ]
        ));
        assert!(tb.contains("POINT"));
    }

    #[test]
    fn test_type_define_enum() {
        pyo3::prepare_freethreaded_python();
        let mut tb = TypeBinding::new();
        assert!(tb.define_enum("Color", vec!["Red".into(), "Green".into(), "Blue".into()]));
        assert!(tb.contains("Color"));
    }

    #[test]
    fn test_type_remove() {
        pyo3::prepare_freethreaded_python();
        let mut tb = TypeBinding::new();
        tb.define_struct("T", vec![]);
        assert!(tb.remove_type("T"));
        assert!(!tb.contains("T"));
    }

    #[test]
    fn test_type_names() {
        pyo3::prepare_freethreaded_python();
        let mut tb = TypeBinding::new();
        tb.define_struct("Alpha", vec![]);
        tb.define_struct("Beta", vec![]);
        let names = tb.type_names();
        assert!(names.contains(&"Alpha".to_string()));
        assert!(names.contains(&"Beta".to_string()));
    }

    #[test]
    fn test_type_apply() {
        pyo3::prepare_freethreaded_python();
        let mut tb = TypeBinding::new();
        tb.define_struct("POINT", vec![]);
        assert!(tb.apply_type("bv1", 0x1000, "POINT"));
        assert!(!tb.apply_type("bv1", 0x1000, "MISSING"));
    }

    #[test]
    fn test_type_get_python() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let mut tb = TypeBinding::new();
            tb.define_struct("RECT", vec![("left".into(), "int32_t".into())]);
            let info = tb.get_type(py, "RECT").unwrap();
            let kind: String = info.get_item("kind").unwrap().unwrap().extract().unwrap();
            assert_eq!(kind, "struct");
        });
    }

    // ── DebugBinding ─────────────────────────────────────────────────────────

    #[test]
    fn test_debug_attach() {
        pyo3::prepare_freethreaded_python();
        let mut dbg = DebugBinding::new();
        let id = dbg.attach(1234);
        assert_eq!(id, "dbg-1234");
        assert_eq!(dbg.session_count(), 1);
    }

    #[test]
    fn test_debug_set_breakpoint() {
        pyo3::prepare_freethreaded_python();
        let mut dbg = DebugBinding::new();
        let id = dbg.attach(1234);
        assert!(dbg.set_breakpoint(&id, 0x0040_1000));
        assert!(dbg.list_breakpoints(&id).contains(&0x0040_1000));
    }

    #[test]
    fn test_debug_remove_breakpoint() {
        pyo3::prepare_freethreaded_python();
        let mut dbg = DebugBinding::new();
        let id = dbg.attach(1234);
        dbg.set_breakpoint(&id, 0x0040_1000);
        assert!(dbg.remove_breakpoint(&id, 0x0040_1000));
        assert!(!dbg.list_breakpoints(&id).contains(&0x0040_1000));
    }

    #[test]
    fn test_debug_step() {
        pyo3::prepare_freethreaded_python();
        let mut dbg = DebugBinding::new();
        let id = dbg.launch("/tmp/test.exe");
        let ip_before = dbg.get_ip(&id).unwrap();
        assert!(dbg.step(&id));
        let ip_after = dbg.get_ip(&id).unwrap();
        assert!(ip_after > ip_before);
    }

    #[test]
    fn test_debug_read_memory() {
        pyo3::prepare_freethreaded_python();
        let mut dbg = DebugBinding::new();
        let id = dbg.attach(1234);
        let mem = dbg.read_memory(&id, 0x1000, 4).unwrap();
        assert_eq!(mem.len(), 4);
    }

    #[test]
    fn test_debug_registers_python() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let mut dbg = DebugBinding::new();
            let id = dbg.attach(1234);
            let regs = dbg.get_registers(py, &id).unwrap();
            let rsp: u64 = regs.get_item("rsp").unwrap().unwrap().extract().unwrap();
            assert!(rsp > 0);
        });
    }

    #[test]
    fn test_debug_write_memory() {
        pyo3::prepare_freethreaded_python();
        let mut dbg = DebugBinding::new();
        let id = dbg.attach(1234);
        assert!(dbg.write_memory(&id, 0x1000, vec![0x90; 5]));
    }

    // ── YaraBinding ──────────────────────────────────────────────────────────

    #[test]
    fn test_yara_add_rule() {
        pyo3::prepare_freethreaded_python();
        let mut yb = YaraBinding::new();
        assert!(yb.add_rule("detect_emotet", "rule detect_emotet { ... }"));
        assert_eq!(yb.rule_count(), 1);
    }

    #[test]
    fn test_yara_remove_rule() {
        pyo3::prepare_freethreaded_python();
        let mut yb = YaraBinding::new();
        yb.add_rule("r1", "rule r1 {}");
        assert!(yb.remove_rule("r1"));
        assert_eq!(yb.rule_count(), 0);
    }

    #[test]
    fn test_yara_scan_match() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let mut yb = YaraBinding::new();
            yb.add_rule("detect_emotet", "rule detect_emotet { ... }");
            let results = yb.scan(py, b"detect_emotet sample binary");
            assert!(results.len() > 0);
        });
    }

    #[test]
    fn test_yara_scan_no_match() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let mut yb = YaraBinding::new();
            yb.add_rule("detect_emotet", "rule detect_emotet { ... }");
            let results = yb.scan(py, b"totally_clean_binary_data");
            assert_eq!(results.len(), 0);
        });
    }

    #[test]
    fn test_yara_load_rules() {
        pyo3::prepare_freethreaded_python();
        let mut yb = YaraBinding::new();
        let src = "rule a { condition: true }\nrule b { condition: true }";
        let count = yb.load_rules(src);
        assert_eq!(count, 2);
    }

    #[test]
    fn test_yara_rule_names() {
        pyo3::prepare_freethreaded_python();
        let mut yb = YaraBinding::new();
        yb.add_rule("r_alpha", "rule r_alpha {}");
        yb.add_rule("r_beta", "rule r_beta {}");
        let names = yb.rule_names();
        assert!(names.contains(&"r_alpha".to_string()));
        assert!(names.contains(&"r_beta".to_string()));
    }

    // ── PythonFullApi ────────────────────────────────────────────────────────

    #[test]
    fn test_python_full_api_creation() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let api = PythonFullApi::new(py).unwrap();
            assert_eq!(api.version(), "0.1.0");
            assert_eq!(api.sub_apis().len(), 5);
        });
    }

    #[test]
    fn test_python_full_api_log() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let mut api = PythonFullApi::new(py).unwrap();
            api.log_action("open_binary", "/tmp/test.exe");
            assert_eq!(api.log_len(), 1);
            api.clear_log();
            assert_eq!(api.log_len(), 0);
        });
    }

    #[test]
    fn test_python_full_api_sub_apis() {
        pyo3::prepare_freethreaded_python();
        Python::with_gil(|py| {
            let api = PythonFullApi::new(py).unwrap();
            let subs = api.sub_apis();
            assert!(subs.contains(&"bv"));
            assert!(subs.contains(&"yara"));
            assert!(subs.contains(&"debug"));
        });
    }

    // ── PythonScriptSession ──────────────────────────────────────────────────

    #[test]
    fn test_session_record_history() {
        let mut s = PythonScriptSession::new("sess-1");
        s.record("print(1)", "1");
        assert_eq!(s.history_len(), 1);
    }

    #[test]
    fn test_session_set_get_var() {
        let mut s = PythonScriptSession::new("s");
        s.set_var("x", serde_json::json!(42));
        assert_eq!(s.get_var("x").unwrap(), &serde_json::json!(42));
    }

    #[test]
    fn test_session_clear_history() {
        let mut s = PythonScriptSession::new("s");
        s.record("code", "result");
        s.clear_history();
        assert_eq!(s.history_len(), 0);
    }

    #[test]
    fn test_session_max_history_pruning() {
        let mut s = PythonScriptSession::new("s");
        s.max_history = 3;
        for i in 0..5 {
            s.record(format!("code_{i}"), "r");
        }
        assert_eq!(s.history_len(), 3);
    }

    // ── PythonTypeStubGenerator ──────────────────────────────────────────────

    #[test]
    fn test_stub_generator_class_count() {
        let gen_ = PythonTypeStubGenerator::rustre_stubs();
        assert!(gen_.class_count() >= 2);
    }

    #[test]
    fn test_stub_generator_output() {
        let gen_ = PythonTypeStubGenerator::rustre_stubs();
        let stubs = gen_.generate();
        assert!(stubs.contains("class BvBinding"));
        assert!(stubs.contains("def open"));
    }

    #[test]
    fn test_stub_generator_add_class() {
        let mut gen_ = PythonTypeStubGenerator::new();
        gen_.add_class(StubClass {
            name: "CustomApi".into(),
            docstring: "Custom.".into(),
            methods: vec![],
        });
        assert_eq!(gen_.class_count(), 1);
    }

    // ── PythonApiConfig ──────────────────────────────────────────────────────

    #[test]
    fn test_config_defaults() {
        let cfg = PythonApiConfig::new();
        assert!(cfg.expose_debug);
        assert!(cfg.expose_yara);
        assert!(cfg.sandbox);
        assert_eq!(cfg.module_name, "rustre");
    }

    #[test]
    fn test_config_permissive() {
        let cfg = PythonApiConfig::permissive();
        assert!(!cfg.sandbox);
        assert_eq!(cfg.timeout_secs, 0);
    }

    #[test]
    fn test_config_validate_ok() {
        let cfg = PythonApiConfig::new();
        assert!(cfg.validate().is_empty());
    }

    #[test]
    fn test_config_validate_empty_name() {
        let mut cfg = PythonApiConfig::new();
        cfg.module_name = String::new();
        assert!(!cfg.validate().is_empty());
    }

    #[test]
    fn test_config_validate_zero_rules() {
        let mut cfg = PythonApiConfig::new();
        cfg.max_yara_rules = 0;
        assert!(!cfg.validate().is_empty());
    }

    // ── PythonAnalysisProxy ──────────────────────────────────────────────────

    #[test]
    fn test_analysis_proxy_load_binary() {
        let mut proxy = PythonAnalysisProxy::new();
        proxy.load_binary("bv1");
        assert_eq!(proxy.operation_count(), 1);
    }

    #[test]
    fn test_analysis_proxy_rename() {
        let mut proxy = PythonAnalysisProxy::new();
        proxy.load_binary("bv1");
        assert!(proxy.rename("bv1", 0x1480, "init_malware"));
        assert_eq!(proxy.func.rename_count(), 1);
    }

    #[test]
    fn test_analysis_proxy_define_struct() {
        let mut proxy = PythonAnalysisProxy::new();
        proxy.define_struct("POINT", vec![("x".into(), "i32".into())]);
        assert!(proxy.types.contains("POINT"));
    }

    #[test]
    fn test_analysis_proxy_summary() {
        let proxy = PythonAnalysisProxy::new();
        let s = proxy.summary();
        assert!(s.contains("PythonAnalysisProxy"));
    }

    #[test]
    fn test_analysis_proxy_clear_log() {
        let mut proxy = PythonAnalysisProxy::new();
        proxy.load_binary("bv1");
        proxy.clear_log();
        assert_eq!(proxy.operation_count(), 0);
    }

    // ── PythonDebugSession ───────────────────────────────────────────────────

    #[test]
    fn test_debug_session_attach() {
        let session = PythonDebugSession::attach(1234);
        assert!(!session.session_id.is_empty());
    }

    #[test]
    fn test_debug_session_set_bp() {
        let mut session = PythonDebugSession::attach(1234);
        assert!(session.set_bp(0x0040_1000));
        assert_eq!(session.event_count(), 1);
    }

    #[test]
    fn test_debug_session_step() {
        let mut session = PythonDebugSession::attach(1234);
        let ip = session.step();
        assert!(ip.is_some());
        assert_eq!(session.event_count(), 1);
    }

    // ── PythonVersionInfo ────────────────────────────────────────────────────

    #[test]
    fn test_version_info_defaults() {
        let v = PythonVersionInfo::default();
        assert_eq!(v.rustre_version, "0.1.0");
        assert_eq!(v.api_version, 1);
    }

    #[test]
    fn test_version_info_supports_python() {
        let v = PythonVersionInfo::default();
        assert!(v.supports_python("3.10"));
        assert!(!v.supports_python("2.7"));
    }

    #[test]
    fn test_version_info_has_feature() {
        let v = PythonVersionInfo::default();
        assert!(v.has_feature("bv"));
        assert!(v.has_feature("yara"));
        assert!(!v.has_feature("nonexistent"));
    }

    #[test]
    fn test_debug_session_events() {
        let mut session = PythonDebugSession::attach(9999);
        session.set_bp(0x1000);
        session.step();
        assert_eq!(session.events().len(), 2);
    }
}
