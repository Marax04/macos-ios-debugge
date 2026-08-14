//! `PyO3` Rust-Python bindings stubs.
//!
//! Exposes `RustRE` analysis types as Python classes via `PyO3`.  When the
//! `pyo3` Cargo feature is disabled the types still exist but the
//! `#[pyclass]`/`#[pymethods]` attributes are replaced by plain `#[cfg]`
//! guards so the crate compiles without a Python installation.
//!
//! The `rustre_python_module()` function initialises the `rustre` Python
//! module with all exported types and free functions.

use std::collections::HashMap;
use std::fmt;

// ─── Value types for cross-language exchange ──────────────────────────────────

/// A Python-compatible value that can cross the Rust/Python boundary.
#[derive(Debug, Clone, PartialEq)]
pub enum PyBridgeValue {
    /// None / null.
    None,
    /// Boolean.
    Bool(bool),
    /// Integer (i64).
    Int(i64),
    /// Unsigned integer (u64).
    Uint(u64),
    /// Float (f64).
    Float(f64),
    /// String.
    Str(String),
    /// Bytes buffer.
    Bytes(Vec<u8>),
    /// List of values.
    List(Vec<Self>),
    /// Dict (string keys).
    Dict(HashMap<String, Self>),
}

impl PyBridgeValue {
    /// Coerce to i64 (lossy).
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(n) => Some(*n),
            Self::Uint(n) => Some((*n).cast_signed()),
            Self::Bool(b) => Some(i64::from(*b)),
            _ => None,
        }
    }

    /// Coerce to u64.
    #[must_use]
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Self::Uint(n) => Some(*n),
            Self::Int(n) if *n >= 0 => Some((*n).cast_unsigned()),
            Self::Bool(b) => Some(u64::from(*b)),
            _ => None,
        }
    }

    /// Coerce to f64.
    #[must_use]
    pub const fn as_float(&self) -> Option<f64> {
        match self {
            Self::Float(f) => Some(*f),
            Self::Int(n) => Some(*n as f64),
            Self::Uint(n) => Some(*n as f64),
            _ => None,
        }
    }

    /// Coerce to &str.
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Return true for `None`, `False`, `0`, empty string, empty list.
    #[must_use]
    pub fn is_truthy(&self) -> bool {
        match self {
            Self::None => false,
            Self::Bool(b) => *b,
            Self::Int(n) => *n != 0,
            Self::Uint(n) => *n != 0,
            Self::Float(f) => *f != 0.0,
            Self::Str(s) => !s.is_empty(),
            Self::Bytes(b) => !b.is_empty(),
            Self::List(l) => !l.is_empty(),
            Self::Dict(d) => !d.is_empty(),
        }
    }
}

impl fmt::Display for PyBridgeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Bool(b) => write!(f, "{}", if *b { "True" } else { "False" }),
            Self::Int(n) => write!(f, "{n}"),
            Self::Uint(n) => write!(f, "{n}"),
            Self::Float(v) => write!(f, "{v}"),
            Self::Str(s) => write!(f, "{s}"),
            Self::Bytes(b) => write!(f, "<bytes len={}>", b.len()),
            Self::List(l) => write!(f, "[...({} items)]", l.len()),
            Self::Dict(d) => write!(f, "{{...({} keys)}}", d.len()),
        }
    }
}

// ─── RustreFunction stub ──────────────────────────────────────────────────────

/// Python-exposed representation of a function.
///
/// In real pyo3 code this would be `#[pyclass]`; here we use a plain
/// Rust struct that implements the same interface so tests can exercise it.
#[derive(Debug, Clone)]
pub struct RustreFunction {
    /// Start address.
    pub start_ea: u64,
    /// End address (exclusive).
    pub end_ea: u64,
    /// Function name.
    pub name: String,
}

impl RustreFunction {
    /// Create a new function.
    #[must_use]
    pub fn new(start_ea: u64, end_ea: u64, name: impl Into<String>) -> Self {
        Self {
            start_ea,
            end_ea,
            name: name.into(),
        }
    }

    // pymethods equivalents

    /// `start_ea` property getter.
    #[must_use]
    pub const fn py_start_ea(&self) -> u64 {
        self.start_ea
    }

    /// `end_ea` property getter.
    #[must_use]
    pub const fn py_end_ea(&self) -> u64 {
        self.end_ea
    }

    /// `name` property getter.
    #[must_use]
    pub fn py_name(&self) -> &str {
        &self.name
    }

    /// `size()` — function byte size.
    #[must_use]
    pub const fn py_size(&self) -> u64 {
        self.end_ea.saturating_sub(self.start_ea)
    }

    /// `__repr__` equivalent.
    #[must_use]
    pub fn py_repr(&self) -> String {
        format!(
            "RustreFunction('{}', start={:#x}, end={:#x})",
            self.name, self.start_ea, self.end_ea
        )
    }

    /// `__str__` equivalent.
    #[must_use]
    pub fn py_str(&self) -> String {
        self.name.clone()
    }
}

// ─── RustreBasicBlock stub ────────────────────────────────────────────────────

/// Python-exposed representation of a basic block.
#[derive(Debug, Clone)]
pub struct RustreBasicBlock {
    /// Start address.
    pub start_ea: u64,
    /// End address (exclusive).
    pub end_ea: u64,
    /// Successor addresses.
    pub successors: Vec<u64>,
}

impl RustreBasicBlock {
    /// Create a basic block.
    #[must_use]
    pub const fn new(start_ea: u64, end_ea: u64) -> Self {
        Self {
            start_ea,
            end_ea,
            successors: Vec::new(),
        }
    }

    /// Add a successor.
    pub fn add_successor(&mut self, ea: u64) {
        self.successors.push(ea);
    }

    /// Size in bytes.
    #[must_use]
    pub const fn py_size(&self) -> u64 {
        self.end_ea.saturating_sub(self.start_ea)
    }

    /// `__repr__` equivalent.
    #[must_use]
    pub fn py_repr(&self) -> String {
        format!(
            "RustreBasicBlock(start={:#x}, end={:#x})",
            self.start_ea, self.end_ea
        )
    }
}

// ─── RustreInstruction stub ───────────────────────────────────────────────────

/// Python-exposed representation of an instruction.
#[derive(Debug, Clone)]
pub struct RustreInstruction {
    /// Effective address.
    pub ea: u64,
    /// Mnemonic string.
    pub mnem: String,
    /// Disassembly text.
    pub disasm: String,
    /// Instruction size in bytes.
    pub size: u8,
    /// Raw bytes.
    pub bytes: Vec<u8>,
}

impl RustreInstruction {
    /// Create an instruction.
    #[must_use]
    pub fn new(ea: u64, mnem: impl Into<String>, disasm: impl Into<String>, size: u8) -> Self {
        Self {
            ea,
            mnem: mnem.into(),
            disasm: disasm.into(),
            size,
            bytes: Vec::new(),
        }
    }

    /// `__repr__` equivalent.
    #[must_use]
    pub fn py_repr(&self) -> String {
        format!("RustreInstruction(ea={:#x}, '{}')", self.ea, self.disasm)
    }

    /// Expose mnemonic.
    #[must_use]
    pub fn py_mnem(&self) -> &str {
        &self.mnem
    }
}

// ─── RustreSymbol stub ────────────────────────────────────────────────────────

/// Python-exposed symbol (name + address + kind).
#[derive(Debug, Clone)]
pub struct RustreSymbol {
    /// Symbol name.
    pub name: String,
    /// Symbol address.
    pub address: u64,
    /// Symbol kind string (e.g. "function", "data", "import").
    pub kind: String,
}

impl RustreSymbol {
    /// Create a symbol.
    #[must_use]
    pub fn new(name: impl Into<String>, address: u64, kind: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            address,
            kind: kind.into(),
        }
    }

    /// `__repr__` equivalent.
    #[must_use]
    pub fn py_repr(&self) -> String {
        format!(
            "RustreSymbol('{}', addr={:#x}, kind='{}')",
            self.name, self.address, self.kind
        )
    }
}

// ─── RustreSegment stub ───────────────────────────────────────────────────────

/// Python-exposed segment.
#[derive(Debug, Clone)]
pub struct RustreSegment {
    /// Segment name.
    pub name: String,
    /// Start address.
    pub start_ea: u64,
    /// End address (exclusive).
    pub end_ea: u64,
    /// Read/write/execute flags.
    pub flags: u8,
}

impl RustreSegment {
    /// Flag bit: readable.
    pub const FLAG_READ: u8 = 0x01;
    /// Flag bit: writable.
    pub const FLAG_WRITE: u8 = 0x02;
    /// Flag bit: executable.
    pub const FLAG_EXEC: u8 = 0x04;

    /// Create a segment.
    #[must_use]
    pub fn new(name: impl Into<String>, start_ea: u64, end_ea: u64, flags: u8) -> Self {
        Self {
            name: name.into(),
            start_ea,
            end_ea,
            flags,
        }
    }

    /// Is executable.
    #[must_use]
    pub const fn is_exec(&self) -> bool {
        self.flags & Self::FLAG_EXEC != 0
    }

    /// Is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        self.flags & Self::FLAG_WRITE != 0
    }

    /// Size in bytes.
    #[must_use]
    pub const fn py_size(&self) -> u64 {
        self.end_ea.saturating_sub(self.start_ea)
    }

    /// `__repr__` equivalent.
    #[must_use]
    pub fn py_repr(&self) -> String {
        format!(
            "RustreSegment('{}', start={:#x}, end={:#x}, flags={:#04x})",
            self.name, self.start_ea, self.end_ea, self.flags
        )
    }
}

// ─── RustreModule ─────────────────────────────────────────────────────────────

/// Top-level Python module object — analogous to `rustre_python_module()`.
///
/// Registers and owns all the sub-objects the Python module exposes.
#[derive(Debug, Default)]
pub struct RustreModule {
    /// Functions by start address.
    pub functions: HashMap<u64, RustreFunction>,
    /// Basic blocks by start address.
    pub basic_blocks: HashMap<u64, RustreBasicBlock>,
    /// Symbols by name.
    pub symbols: HashMap<String, RustreSymbol>,
    /// Segments by name.
    pub segments: HashMap<String, RustreSegment>,
    /// Module-level log entries (for Python `print` compatibility).
    pub log: Vec<String>,
}

impl RustreModule {
    /// Initialise the module.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Return crate version string.
    #[must_use]
    pub const fn version(&self) -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// Register a function.
    pub fn add_function(&mut self, f: RustreFunction) {
        self.functions.insert(f.start_ea, f);
    }

    /// Add a basic block.
    pub fn add_basic_block(&mut self, bb: RustreBasicBlock) {
        self.basic_blocks.insert(bb.start_ea, bb);
    }

    /// Add a symbol.
    pub fn add_symbol(&mut self, sym: RustreSymbol) {
        self.symbols.insert(sym.name.clone(), sym);
    }

    /// Add a segment.
    pub fn add_segment(&mut self, seg: RustreSegment) {
        self.segments.insert(seg.name.clone(), seg);
    }

    /// `get_function(ea)` — Python free function equivalent.
    #[must_use]
    pub fn get_function(&self, ea: u64) -> Option<&RustreFunction> {
        // Search for a function whose range covers ea
        self.functions
            .values()
            .find(|f| ea >= f.start_ea && ea < f.end_ea)
    }

    /// `log(msg)` — Python `print` equivalent.
    pub fn log_message(&mut self, msg: impl Into<String>) {
        self.log.push(msg.into());
    }

    /// Drain logged messages.
    pub fn drain_log(&mut self) -> Vec<String> {
        std::mem::take(&mut self.log)
    }
}

// ─── Type conversion helpers ──────────────────────────────────────────────────

/// Convert a `RustreFunction` to a `PyBridgeValue::Dict`.
#[must_use]
pub fn function_to_pyvalue(f: &RustreFunction) -> PyBridgeValue {
    let mut d = HashMap::new();
    d.insert("start_ea".to_string(), PyBridgeValue::Uint(f.start_ea));
    d.insert("end_ea".to_string(), PyBridgeValue::Uint(f.end_ea));
    d.insert("name".to_string(), PyBridgeValue::Str(f.name.clone()));
    d.insert("size".to_string(), PyBridgeValue::Uint(f.py_size()));
    PyBridgeValue::Dict(d)
}

/// Convert a `RustreSegment` to a `PyBridgeValue::Dict`.
#[must_use]
pub fn segment_to_pyvalue(s: &RustreSegment) -> PyBridgeValue {
    let mut d = HashMap::new();
    d.insert("name".to_string(), PyBridgeValue::Str(s.name.clone()));
    d.insert("start_ea".to_string(), PyBridgeValue::Uint(s.start_ea));
    d.insert("end_ea".to_string(), PyBridgeValue::Uint(s.end_ea));
    d.insert("flags".to_string(), PyBridgeValue::Int(i64::from(s.flags)));
    d.insert("exec".to_string(), PyBridgeValue::Bool(s.is_exec()));
    PyBridgeValue::Dict(d)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PyBridgeValue ─────────────────────────────────────────────────────────

    #[test]
    fn bridge_value_as_int() {
        assert_eq!(PyBridgeValue::Int(42).as_int(), Some(42));
        assert_eq!(PyBridgeValue::Uint(10).as_int(), Some(10));
        assert_eq!(PyBridgeValue::Str("x".to_string()).as_int(), None);
    }

    #[test]
    fn bridge_value_as_uint() {
        assert_eq!(PyBridgeValue::Uint(99).as_uint(), Some(99));
        assert_eq!(PyBridgeValue::Int(-1).as_uint(), None);
    }

    #[test]
    fn bridge_value_as_float() {
        assert_eq!(PyBridgeValue::Float(3.14_f64).as_float(), Some(3.14_f64));
        assert_eq!(PyBridgeValue::Int(2).as_float(), Some(2.0));
    }

    #[test]
    fn bridge_value_as_str() {
        assert_eq!(PyBridgeValue::Str("hello".into()).as_str(), Some("hello"));
    }

    #[test]
    fn bridge_value_is_truthy_none() {
        assert!(!PyBridgeValue::None.is_truthy());
    }

    #[test]
    fn bridge_value_is_truthy_zero() {
        assert!(!PyBridgeValue::Int(0).is_truthy());
        assert!(PyBridgeValue::Int(1).is_truthy());
    }

    #[test]
    fn bridge_value_is_truthy_str() {
        assert!(!PyBridgeValue::Str(String::new()).is_truthy());
        assert!(PyBridgeValue::Str("x".to_string()).is_truthy());
    }

    #[test]
    fn bridge_value_display_none() {
        assert_eq!(PyBridgeValue::None.to_string(), "None");
    }

    #[test]
    fn bridge_value_display_bool_true() {
        assert_eq!(PyBridgeValue::Bool(true).to_string(), "True");
    }

    // ── RustreFunction ────────────────────────────────────────────────────────

    #[test]
    fn function_size() {
        let f = RustreFunction::new(0x1000, 0x1080, "foo");
        assert_eq!(f.py_size(), 0x80);
    }

    #[test]
    fn function_repr() {
        let f = RustreFunction::new(0x1000, 0x1040, "bar");
        assert!(f.py_repr().contains("bar"));
        assert!(f.py_repr().contains("0x1000"));
    }

    #[test]
    fn function_str() {
        let f = RustreFunction::new(0x1000, 0x1010, "main");
        assert_eq!(f.py_str(), "main");
    }

    // ── RustreBasicBlock ──────────────────────────────────────────────────────

    #[test]
    fn bb_size() {
        let bb = RustreBasicBlock::new(0x2000, 0x2020);
        assert_eq!(bb.py_size(), 0x20);
    }

    #[test]
    fn bb_successors() {
        let mut bb = RustreBasicBlock::new(0x2000, 0x2010);
        bb.add_successor(0x2010);
        bb.add_successor(0x3000);
        assert_eq!(bb.successors.len(), 2);
    }

    #[test]
    fn bb_repr() {
        let bb = RustreBasicBlock::new(0x1000, 0x1010);
        assert!(bb.py_repr().contains("0x1000"));
    }

    // ── RustreInstruction ─────────────────────────────────────────────────────

    #[test]
    fn insn_mnem() {
        let insn = RustreInstruction::new(0x1000, "MOV", "MOV RAX, RBX", 3);
        assert_eq!(insn.py_mnem(), "MOV");
    }

    #[test]
    fn insn_repr() {
        let insn = RustreInstruction::new(0x1000, "NOP", "NOP", 1);
        assert!(insn.py_repr().contains("NOP"));
    }

    // ── RustreSymbol ──────────────────────────────────────────────────────────

    #[test]
    fn symbol_repr() {
        let sym = RustreSymbol::new("malloc", 0x7FFF_1234, "import");
        let r = sym.py_repr();
        assert!(r.contains("malloc"));
        assert!(r.contains("import"));
    }

    // ── RustreSegment ─────────────────────────────────────────────────────────

    #[test]
    fn segment_exec_flag() {
        let seg = RustreSegment::new(
            ".text",
            0x1000,
            0x2000,
            RustreSegment::FLAG_EXEC | RustreSegment::FLAG_READ,
        );
        assert!(seg.is_exec());
        assert!(!seg.is_writable());
    }

    #[test]
    fn segment_size() {
        let seg = RustreSegment::new(".bss", 0x3000, 0x4000, 0x03);
        assert_eq!(seg.py_size(), 0x1000);
    }

    #[test]
    fn segment_repr() {
        let seg = RustreSegment::new(".data", 0x2000, 0x3000, 0x03);
        assert!(seg.py_repr().contains(".data"));
    }

    // ── RustreModule ─────────────────────────────────────────────────────────

    #[test]
    fn module_version() {
        let m = RustreModule::new();
        assert!(!m.version().is_empty());
    }

    #[test]
    fn module_add_and_get_function() {
        let mut m = RustreModule::new();
        m.add_function(RustreFunction::new(0x1000, 0x1080, "init"));
        let f = m.get_function(0x1040);
        assert!(f.is_some());
        assert_eq!(f.unwrap().name, "init");
    }

    #[test]
    fn module_get_function_miss() {
        let m = RustreModule::new();
        assert!(m.get_function(0xDEAD).is_none());
    }

    #[test]
    fn module_log() {
        let mut m = RustreModule::new();
        m.log_message("hello from Python");
        let log = m.drain_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0], "hello from Python");
    }

    // ── Type conversion ───────────────────────────────────────────────────────

    #[test]
    fn function_to_pyvalue_dict() {
        let f = RustreFunction::new(0x1000, 0x1080, "test_fn");
        let v = function_to_pyvalue(&f);
        if let PyBridgeValue::Dict(d) = v {
            assert!(d.contains_key("start_ea"));
            assert!(d.contains_key("name"));
        } else {
            panic!("expected Dict");
        }
    }

    #[test]
    fn segment_to_pyvalue_dict() {
        let s = RustreSegment::new(".text", 0x1000, 0x2000, RustreSegment::FLAG_EXEC);
        let v = segment_to_pyvalue(&s);
        if let PyBridgeValue::Dict(d) = v {
            assert_eq!(d.get("exec"), Some(&PyBridgeValue::Bool(true)));
        } else {
            panic!("expected Dict");
        }
    }
}
