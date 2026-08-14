//! Rhai custom types: `RhaiAddress`, `RhaiSymbol`, `RhaiFunction`, `RhaiBasicBlock`.
//!
//! Provides [`RhaiTypeModule`], type registration helpers, and `type_system_plugin()`.

use std::fmt;

/// Re-export of [`std::collections::HashMap`] for callers that build
/// auxiliary Rhai type metadata tables alongside this module.
pub use std::collections::HashMap;

/// Re-exports of shared-ownership primitives for callers that wrap Rhai
/// custom types in interior-mutable handles.
pub use std::sync::{Arc, Mutex};

use rhai::{Engine, EvalAltResult, Module};

use crate::sat_usize_to_i64;

/// Re-exports of Rhai's [`Array`] and [`Dynamic`] value types for callers
/// constructing Rhai values around `RustRE`'s custom type registrations.
pub use rhai::{Array, Dynamic};

// ─── RhaiAddress ──────────────────────────────────────────────────────────────

/// A 64-bit virtual address usable as a Rhai custom type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RhaiAddress {
    pub value: u64,
    pub segment: Option<String>,
}

impl RhaiAddress {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self {
            value,
            segment: None,
        }
    }

    #[must_use]
    pub fn with_segment(mut self, seg: &str) -> Self {
        self.segment = Some(seg.to_string());
        self
    }

    #[must_use]
    pub const fn is_null(&self) -> bool {
        self.value == 0
    }

    #[must_use]
    pub fn offset(&self, delta: i64) -> Self {
        Self {
            value: (self.value.cast_signed())
                .wrapping_add(delta)
                .cast_unsigned(),
            segment: self.segment.clone(),
        }
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        format!("0x{:016x}", self.value)
    }

    #[must_use]
    pub const fn to_i64(&self) -> i64 {
        self.value.cast_signed()
    }

    #[must_use]
    pub const fn aligned(&self, align: u64) -> bool {
        align > 0 && self.value.is_multiple_of(align)
    }
}

impl fmt::Display for RhaiAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(seg) = &self.segment {
            write!(f, "{seg}:0x{:016x}", self.value)
        } else {
            write!(f, "0x{:016x}", self.value)
        }
    }
}

// ─── RhaiSymbol ───────────────────────────────────────────────────────────────

/// A symbolic name bound to an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RhaiSymbol {
    pub address: RhaiAddress,
    pub name: String,
    pub demangled: Option<String>,
    pub module: String,
    pub kind: SymbolKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Data,
    Import,
    Export,
    Label,
    Unknown,
}

impl SymbolKind {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Function => "function",
            Self::Data => "data",
            Self::Import => "import",
            Self::Export => "export",
            Self::Label => "label",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for SymbolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl RhaiSymbol {
    #[must_use]
    pub fn new(address: u64, name: &str, module: &str, kind: SymbolKind) -> Self {
        Self {
            address: RhaiAddress::new(address),
            name: name.to_string(),
            demangled: None,
            module: module.to_string(),
            kind,
        }
    }

    #[must_use]
    pub fn with_demangled(mut self, d: &str) -> Self {
        self.demangled = Some(d.to_string());
        self
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        self.demangled.as_deref().unwrap_or(&self.name)
    }

    #[must_use]
    pub fn is_function(&self) -> bool {
        self.kind == SymbolKind::Function
    }

    #[must_use]
    pub fn full_name(&self) -> String {
        format!("{}!{}", self.module, self.name)
    }
}

impl fmt::Display for RhaiSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.full_name(), self.address)
    }
}

// ─── RhaiFunction ─────────────────────────────────────────────────────────────

/// An analysis function (procedure) with start, end, and basic block list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RhaiFunction {
    pub start: RhaiAddress,
    pub end: RhaiAddress,
    pub name: String,
    pub basic_block_count: u32,
    pub instruction_count: u32,
    pub calling_convention: String,
    pub is_thunk: bool,
    pub is_noreturn: bool,
    pub local_var_count: u32,
    pub arg_count: u32,
}

impl RhaiFunction {
    #[must_use]
    pub fn new(start: u64, end: u64, name: &str) -> Self {
        Self {
            start: RhaiAddress::new(start),
            end: RhaiAddress::new(end),
            name: name.to_string(),
            basic_block_count: 0,
            instruction_count: 0,
            calling_convention: "unknown".into(),
            is_thunk: false,
            is_noreturn: false,
            local_var_count: 0,
            arg_count: 0,
        }
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.value.saturating_sub(self.start.value)
    }

    #[must_use]
    pub fn complexity_estimate(&self) -> f64 {
        // Cyclomatic complexity approximation: basic_blocks - edges + 2
        // Simplified: just use basic block count
        f64::from(self.basic_block_count) + 1.0
    }

    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start.value && addr < self.end.value
    }
}

impl fmt::Display for RhaiFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}({} @ {} - {})",
            self.name,
            if self.is_thunk { "thunk" } else { "func" },
            self.start,
            self.end
        )
    }
}

// ─── RhaiBasicBlock ───────────────────────────────────────────────────────────

/// A basic block within a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RhaiBasicBlock {
    pub start: RhaiAddress,
    pub end: RhaiAddress,
    pub instruction_count: u32,
    pub successors: Vec<u64>,
    pub predecessors: Vec<u64>,
    pub is_entry: bool,
    pub is_exit: bool,
    pub dominates: Vec<u64>,
}

impl RhaiBasicBlock {
    #[must_use]
    pub const fn new(start: u64, end: u64) -> Self {
        Self {
            start: RhaiAddress::new(start),
            end: RhaiAddress::new(end),
            instruction_count: 0,
            successors: Vec::new(),
            predecessors: Vec::new(),
            is_entry: false,
            is_exit: false,
            dominates: Vec::new(),
        }
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.end.value.saturating_sub(self.start.value)
    }

    pub fn add_successor(&mut self, addr: u64) {
        if !self.successors.contains(&addr) {
            self.successors.push(addr);
        }
    }

    pub fn add_predecessor(&mut self, addr: u64) {
        if !self.predecessors.contains(&addr) {
            self.predecessors.push(addr);
        }
    }

    #[must_use]
    pub const fn is_conditional_branch(&self) -> bool {
        self.successors.len() >= 2
    }

    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start.value && addr < self.end.value
    }
}

impl fmt::Display for RhaiBasicBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = if self.is_entry {
            " [entry]"
        } else if self.is_exit {
            " [exit]"
        } else {
            ""
        };
        write!(f, "BB({} - {}{})", self.start, self.end, kind)
    }
}

// ─── RhaiTypeModule ───────────────────────────────────────────────────────────

/// Registers all custom Rhai types and their getters/setters.
pub struct RhaiTypeModule;

impl RhaiTypeModule {
    /// Register all custom types into an Engine.
    pub fn register_into(engine: &mut Engine) {
        Self::register_address(engine);
        Self::register_symbol(engine);
        Self::register_function(engine);
        Self::register_basic_block(engine);
    }

    fn register_address(engine: &mut Engine) {
        engine.register_type_with_name::<RhaiAddress>("Address");

        engine.register_fn("address", |value: i64| {
            RhaiAddress::new(value.cast_unsigned())
        });
        engine.register_fn("address_from_hex", |hex: String| {
            let clean = hex.trim_start_matches("0x").trim_start_matches("0X");
            let value = u64::from_str_radix(clean, 16).unwrap_or(0);
            RhaiAddress::new(value)
        });

        engine.register_get("value", |a: &mut RhaiAddress| a.value.cast_signed());
        engine.register_get("is_null", |a: &mut RhaiAddress| a.is_null());
        engine.register_get("hex", |a: &mut RhaiAddress| a.to_hex());

        engine.register_fn("offset", |a: &mut RhaiAddress, delta: i64| a.offset(delta));
        engine.register_fn("aligned", |a: &mut RhaiAddress, n: i64| {
            a.aligned(n.cast_unsigned())
        });
        engine.register_fn("to_string", |a: &mut RhaiAddress| a.to_string());
        engine.register_fn("to_int", |a: &mut RhaiAddress| a.to_i64());

        // Comparison
        engine.register_fn("==", |a: &mut RhaiAddress, b: RhaiAddress| a == &b);
        engine.register_fn("!=", |a: &mut RhaiAddress, b: RhaiAddress| a != &b);
        engine.register_fn("<", |a: &mut RhaiAddress, b: RhaiAddress| a.value < b.value);
        engine.register_fn(">", |a: &mut RhaiAddress, b: RhaiAddress| a.value > b.value);
        engine.register_fn("<=", |a: &mut RhaiAddress, b: RhaiAddress| {
            a.value <= b.value
        });
        engine.register_fn(">=", |a: &mut RhaiAddress, b: RhaiAddress| {
            a.value >= b.value
        });
    }

    fn register_symbol(engine: &mut Engine) {
        engine.register_type_with_name::<RhaiSymbol>("Symbol");

        engine.register_fn("symbol", |addr: i64, name: String, module: String| {
            RhaiSymbol::new(addr.cast_unsigned(), &name, &module, SymbolKind::Unknown)
        });

        engine.register_get("address", |s: &mut RhaiSymbol| s.address.clone());
        engine.register_get("name", |s: &mut RhaiSymbol| s.name.clone());
        engine.register_get("module", |s: &mut RhaiSymbol| s.module.clone());
        engine.register_get("kind", |s: &mut RhaiSymbol| s.kind.to_string());
        engine.register_get("is_function", |s: &mut RhaiSymbol| s.is_function());
        engine.register_get("display_name", |s: &mut RhaiSymbol| {
            s.display_name().to_string()
        });
        engine.register_get("full_name", |s: &mut RhaiSymbol| s.full_name());
        engine.register_fn("to_string", |s: &mut RhaiSymbol| s.to_string());
    }

    fn register_function(engine: &mut Engine) {
        engine.register_type_with_name::<RhaiFunction>("Function");

        engine.register_fn("function", |start: i64, end: i64, name: String| {
            RhaiFunction::new(start.cast_unsigned(), end.cast_unsigned(), &name)
        });

        engine.register_get("start", |f: &mut RhaiFunction| f.start.clone());
        engine.register_get("end", |f: &mut RhaiFunction| f.end.clone());
        engine.register_get("name", |f: &mut RhaiFunction| f.name.clone());
        engine.register_get("size", |f: &mut RhaiFunction| f.size().cast_signed());
        engine.register_get("basic_block_count", |f: &mut RhaiFunction| {
            i64::from(f.basic_block_count)
        });
        engine.register_get("instruction_count", |f: &mut RhaiFunction| {
            i64::from(f.instruction_count)
        });
        engine.register_get("calling_convention", |f: &mut RhaiFunction| {
            f.calling_convention.clone()
        });
        engine.register_get("is_thunk", |f: &mut RhaiFunction| f.is_thunk);
        engine.register_get("is_noreturn", |f: &mut RhaiFunction| f.is_noreturn);
        engine.register_get("arg_count", |f: &mut RhaiFunction| i64::from(f.arg_count));
        engine.register_get("local_var_count", |f: &mut RhaiFunction| {
            i64::from(f.local_var_count)
        });
        engine.register_get("complexity", |f: &mut RhaiFunction| f.complexity_estimate());
        engine.register_fn("contains", |f: &mut RhaiFunction, addr: i64| {
            f.contains(addr.cast_unsigned())
        });
        engine.register_fn("to_string", |f: &mut RhaiFunction| f.to_string());
    }

    fn register_basic_block(engine: &mut Engine) {
        engine.register_type_with_name::<RhaiBasicBlock>("BasicBlock");

        engine.register_fn("basic_block", |start: i64, end: i64| {
            RhaiBasicBlock::new(start.cast_unsigned(), end.cast_unsigned())
        });

        engine.register_get("start", |b: &mut RhaiBasicBlock| b.start.clone());
        engine.register_get("end", |b: &mut RhaiBasicBlock| b.end.clone());
        engine.register_get("size", |b: &mut RhaiBasicBlock| b.size().cast_signed());
        engine.register_get("instruction_count", |b: &mut RhaiBasicBlock| {
            i64::from(b.instruction_count)
        });
        engine.register_get("is_entry", |b: &mut RhaiBasicBlock| b.is_entry);
        engine.register_get("is_exit", |b: &mut RhaiBasicBlock| b.is_exit);
        engine.register_get("is_conditional", |b: &mut RhaiBasicBlock| {
            b.is_conditional_branch()
        });
        engine.register_get("successor_count", |b: &mut RhaiBasicBlock| {
            sat_usize_to_i64(b.successors.len())
        });
        engine.register_get("predecessor_count", |b: &mut RhaiBasicBlock| {
            sat_usize_to_i64(b.predecessors.len())
        });
        engine.register_fn("contains", |b: &mut RhaiBasicBlock, addr: i64| {
            b.contains(addr.cast_unsigned())
        });
        engine.register_fn("to_string", |b: &mut RhaiBasicBlock| b.to_string());
    }
}

/// Build and return the full type system plugin module.
#[must_use]
pub fn type_system_plugin() -> Module {
    let mut m = Module::new();

    m.set_native_fn(
        "make_address",
        |value: i64| -> Result<RhaiAddress, Box<EvalAltResult>> {
            Ok(RhaiAddress::new(value.cast_unsigned()))
        },
    );

    m.set_native_fn(
        "make_symbol",
        |addr: i64, name: String, module: String| -> Result<RhaiSymbol, Box<EvalAltResult>> {
            Ok(RhaiSymbol::new(
                addr.cast_unsigned(),
                &name,
                &module,
                SymbolKind::Unknown,
            ))
        },
    );

    m.set_native_fn(
        "make_function",
        |start: i64, end: i64, name: String| -> Result<RhaiFunction, Box<EvalAltResult>> {
            Ok(RhaiFunction::new(
                start.cast_unsigned(),
                end.cast_unsigned(),
                &name,
            ))
        },
    );

    m.set_native_fn(
        "make_basic_block",
        |start: i64, end: i64| -> Result<RhaiBasicBlock, Box<EvalAltResult>> {
            Ok(RhaiBasicBlock::new(
                start.cast_unsigned(),
                end.cast_unsigned(),
            ))
        },
    );

    m
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> Engine {
        let mut engine = Engine::new();
        RhaiTypeModule::register_into(&mut engine);
        engine
    }

    #[test]
    fn test_address_create() {
        let engine = make_engine();
        let addr: RhaiAddress = engine.eval("address(0x1000)").unwrap();
        assert_eq!(addr.value, 0x1000);
    }

    #[test]
    fn test_address_from_hex() {
        let engine = make_engine();
        let addr: RhaiAddress = engine.eval(r#"address_from_hex("0xDEAD1000")"#).unwrap();
        assert_eq!(addr.value, 0xDEAD1000);
    }

    #[test]
    fn test_address_is_null_true() {
        let a = RhaiAddress::new(0);
        assert!(a.is_null());
    }

    #[test]
    fn test_address_is_null_false() {
        let a = RhaiAddress::new(0x1000);
        assert!(!a.is_null());
    }

    #[test]
    fn test_address_offset_positive() {
        let a = RhaiAddress::new(0x1000);
        let b = a.offset(0x100);
        assert_eq!(b.value, 0x1100);
    }

    #[test]
    fn test_address_offset_negative() {
        let a = RhaiAddress::new(0x1000);
        let b = a.offset(-0x100);
        assert_eq!(b.value, 0x0F00);
    }

    #[test]
    fn test_address_hex_format() {
        let a = RhaiAddress::new(0x401000);
        assert_eq!(a.to_hex(), "0x0000000000401000");
    }

    #[test]
    fn test_address_aligned() {
        let a = RhaiAddress::new(0x1000);
        assert!(a.aligned(4096));
        assert!(a.aligned(8));
        assert!(!a.aligned(8192));
    }

    #[test]
    fn test_address_to_i64() {
        let a = RhaiAddress::new(0x401000);
        assert_eq!(a.to_i64(), 0x401000);
    }

    #[test]
    fn test_address_display_with_segment() {
        let a = RhaiAddress::new(0x1000).with_segment(".text");
        let s = a.to_string();
        assert!(s.contains(".text"));
    }

    #[test]
    fn test_symbol_create() {
        let s = RhaiSymbol::new(0x401000, "main", "target.exe", SymbolKind::Function);
        assert_eq!(s.name, "main");
        assert!(s.is_function());
    }

    #[test]
    fn test_symbol_full_name() {
        let s = RhaiSymbol::new(0x401000, "main", "target", SymbolKind::Function);
        assert_eq!(s.full_name(), "target!main");
    }

    #[test]
    fn test_symbol_demangled() {
        let s = RhaiSymbol::new(0x401000, "_Z4mainii", "target", SymbolKind::Function)
            .with_demangled("main(int, int)");
        assert_eq!(s.display_name(), "main(int, int)");
    }

    #[test]
    fn test_function_create() {
        let f = RhaiFunction::new(0x401000, 0x401100, "vuln_func");
        assert_eq!(f.name, "vuln_func");
        assert_eq!(f.size(), 0x100);
    }

    #[test]
    fn test_function_contains_yes() {
        let f = RhaiFunction::new(0x401000, 0x401100, "f");
        assert!(f.contains(0x401050));
    }

    #[test]
    fn test_function_contains_no() {
        let f = RhaiFunction::new(0x401000, 0x401100, "f");
        assert!(!f.contains(0x402000));
    }

    #[test]
    fn test_function_complexity() {
        let mut f = RhaiFunction::new(0x401000, 0x401100, "f");
        f.basic_block_count = 5;
        assert_eq!(f.complexity_estimate(), 6.0);
    }

    #[test]
    fn test_basic_block_create() {
        let bb = RhaiBasicBlock::new(0x401000, 0x401020);
        assert_eq!(bb.size(), 0x20);
    }

    #[test]
    fn test_basic_block_successors() {
        let mut bb = RhaiBasicBlock::new(0x401000, 0x401020);
        bb.add_successor(0x401020);
        bb.add_successor(0x402000);
        assert!(bb.is_conditional_branch());
    }

    #[test]
    fn test_basic_block_contains() {
        let bb = RhaiBasicBlock::new(0x401000, 0x401020);
        assert!(bb.contains(0x401010));
        assert!(!bb.contains(0x402000));
    }

    #[test]
    fn test_basic_block_no_duplicates() {
        let mut bb = RhaiBasicBlock::new(0x1000, 0x2000);
        bb.add_successor(0x2000);
        bb.add_successor(0x2000);
        assert_eq!(bb.successors.len(), 1);
    }

    #[test]
    fn test_rhai_address_get_value() {
        let engine = make_engine();
        let val: i64 = engine.eval("address(0x1234).value").unwrap();
        assert_eq!(val, 0x1234);
    }

    #[test]
    fn test_rhai_address_get_is_null() {
        let engine = make_engine();
        let null: bool = engine.eval("address(0).is_null").unwrap();
        assert!(null);
        let not_null: bool = engine.eval("address(100).is_null").unwrap();
        assert!(!not_null);
    }

    #[test]
    fn test_rhai_address_get_hex() {
        let engine = make_engine();
        let hex: String = engine.eval("address(0x401000).hex").unwrap();
        assert!(hex.contains("401000"));
    }

    #[test]
    fn test_rhai_function_size() {
        let engine = make_engine();
        let size: i64 = engine
            .eval(r#"function(0x1000, 0x2000, "f").size"#)
            .unwrap();
        assert_eq!(size, 0x1000);
    }

    #[test]
    fn test_rhai_function_name() {
        let engine = make_engine();
        let name: String = engine
            .eval(r#"function(0, 100, "test_func").name"#)
            .unwrap();
        assert_eq!(name, "test_func");
    }

    #[test]
    fn test_rhai_basic_block_size() {
        let engine = make_engine();
        let size: i64 = engine.eval("basic_block(0x1000, 0x1020).size").unwrap();
        assert_eq!(size, 0x20);
    }

    #[test]
    fn test_type_system_plugin_not_empty() {
        let m = type_system_plugin();
        assert!(!m.is_empty());
    }
}

// ─── RhaiXref ─────────────────────────────────────────────────────────────────

/// A cross-reference between two addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RhaiXref {
    pub from_addr: RhaiAddress,
    pub to_addr: RhaiAddress,
    pub kind: XrefKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XrefKind {
    Call,
    Jump,
    Data,
    Unknown,
}

impl XrefKind {
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Jump => "jump",
            Self::Data => "data",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for XrefKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl RhaiXref {
    #[must_use]
    pub const fn new(from: u64, to: u64, kind: XrefKind) -> Self {
        Self {
            from_addr: RhaiAddress::new(from),
            to_addr: RhaiAddress::new(to),
            kind,
        }
    }
}

impl std::fmt::Display for RhaiXref {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} --{}--> {}", self.from_addr, self.kind, self.to_addr)
    }
}

// ─── RhaiSegment ──────────────────────────────────────────────────────────────

/// A binary segment / section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RhaiSegment {
    pub start: RhaiAddress,
    pub size: u64,
    pub name: String,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_readable: bool,
}

impl RhaiSegment {
    #[must_use]
    pub fn new(start: u64, size: u64, name: &str) -> Self {
        Self {
            start: RhaiAddress::new(start),
            size,
            name: name.to_string(),
            is_executable: false,
            is_writable: false,
            is_readable: true,
        }
    }

    #[must_use]
    pub const fn end(&self) -> u64 {
        self.start.value + self.size
    }

    #[must_use]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start.value && addr < self.end()
    }

    #[must_use]
    pub fn permissions(&self) -> String {
        let r = if self.is_readable { 'r' } else { '-' };
        let w = if self.is_writable { 'w' } else { '-' };
        let x = if self.is_executable { 'x' } else { '-' };
        format!("{r}{w}{x}")
    }
}

impl std::fmt::Display for RhaiSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({} - 0x{:x}, {})",
            self.name,
            self.start,
            self.end(),
            self.permissions()
        )
    }
}

// ─── Extended type registration ───────────────────────────────────────────────

impl RhaiTypeModule {
    /// Register xref and segment types.
    pub fn register_extended(engine: &mut Engine) {
        Self::register_xref(engine);
        Self::register_segment(engine);
    }

    fn register_xref(engine: &mut Engine) {
        engine.register_type_with_name::<RhaiXref>("Xref");

        engine.register_fn("xref", |from: i64, to: i64, kind: String| {
            let xk = match kind.as_str() {
                "call" => XrefKind::Call,
                "jump" => XrefKind::Jump,
                "data" => XrefKind::Data,
                _ => XrefKind::Unknown,
            };
            RhaiXref::new(from.cast_unsigned(), to.cast_unsigned(), xk)
        });

        engine.register_get("from_addr", |x: &mut RhaiXref| x.from_addr.clone());
        engine.register_get("to_addr", |x: &mut RhaiXref| x.to_addr.clone());
        engine.register_get("kind", |x: &mut RhaiXref| x.kind.to_string());
        engine.register_fn("to_string", |x: &mut RhaiXref| x.to_string());
    }

    fn register_segment(engine: &mut Engine) {
        engine.register_type_with_name::<RhaiSegment>("Segment");

        engine.register_fn("segment", |start: i64, size: i64, name: String| {
            RhaiSegment::new(start.cast_unsigned(), size.cast_unsigned(), &name)
        });

        engine.register_get("start", |s: &mut RhaiSegment| s.start.clone());
        engine.register_get("size", |s: &mut RhaiSegment| s.size.cast_signed());
        engine.register_get("name", |s: &mut RhaiSegment| s.name.clone());
        engine.register_get("is_executable", |s: &mut RhaiSegment| s.is_executable);
        engine.register_get("is_writable", |s: &mut RhaiSegment| s.is_writable);
        engine.register_get("is_readable", |s: &mut RhaiSegment| s.is_readable);
        engine.register_get("permissions", |s: &mut RhaiSegment| s.permissions());
        engine.register_fn("contains", |s: &mut RhaiSegment, addr: i64| {
            s.contains(addr.cast_unsigned())
        });
        engine.register_fn("to_string", |s: &mut RhaiSegment| s.to_string());
    }
}

// ─── Additional tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod extra_tests {
    use super::*;

    fn make_full_engine() -> Engine {
        let mut engine = Engine::new();
        RhaiTypeModule::register_into(&mut engine);
        RhaiTypeModule::register_extended(&mut engine);
        engine
    }

    #[test]
    fn test_xref_create() {
        let x = RhaiXref::new(0x1000, 0x2000, XrefKind::Call);
        assert_eq!(x.from_addr.value, 0x1000);
        assert_eq!(x.to_addr.value, 0x2000);
    }

    #[test]
    fn test_xref_display() {
        let x = RhaiXref::new(0x1000, 0x2000, XrefKind::Jump);
        let s = x.to_string();
        assert!(s.contains("jump"));
    }

    #[test]
    fn test_xref_kind_display() {
        assert_eq!(XrefKind::Call.to_string(), "call");
        assert_eq!(XrefKind::Data.to_string(), "data");
    }

    #[test]
    fn test_segment_create() {
        let s = RhaiSegment::new(0x400000, 0x10000, ".text");
        assert_eq!(s.name, ".text");
        assert_eq!(s.size, 0x10000);
    }

    #[test]
    fn test_segment_end() {
        let s = RhaiSegment::new(0x400000, 0x10000, ".text");
        assert_eq!(s.end(), 0x410000);
    }

    #[test]
    fn test_segment_contains() {
        let s = RhaiSegment::new(0x400000, 0x10000, ".text");
        assert!(s.contains(0x401000));
        assert!(!s.contains(0x500000));
    }

    #[test]
    fn test_segment_permissions() {
        let mut s = RhaiSegment::new(0x400000, 0x10000, ".text");
        s.is_readable = true;
        s.is_executable = true;
        s.is_writable = false;
        assert_eq!(s.permissions(), "r-x");
    }

    #[test]
    fn test_rhai_xref_create() {
        let engine = make_full_engine();
        let x: RhaiXref = engine.eval(r#"xref(0x1000, 0x2000, "call")"#).unwrap();
        assert_eq!(x.kind, XrefKind::Call);
    }

    #[test]
    fn test_rhai_xref_kind_get() {
        let engine = make_full_engine();
        let kind: String = engine.eval(r#"xref(0x1000, 0x2000, "jump").kind"#).unwrap();
        assert_eq!(kind, "jump");
    }

    #[test]
    fn test_rhai_segment_create() {
        let engine = make_full_engine();
        let seg: RhaiSegment = engine
            .eval(r#"segment(0x400000, 0x10000, ".text")"#)
            .unwrap();
        assert_eq!(seg.name, ".text");
    }

    #[test]
    fn test_rhai_segment_size_get() {
        let engine = make_full_engine();
        let sz: i64 = engine
            .eval(r#"segment(0x400000, 0x1000, ".data").size"#)
            .unwrap();
        assert_eq!(sz, 0x1000);
    }

    #[test]
    fn test_rhai_segment_contains_fn() {
        let engine = make_full_engine();
        let result: bool = engine
            .eval(r#"segment(0x400000, 0x10000, ".text").contains(0x401000)"#)
            .unwrap();
        assert!(result);
    }

    #[test]
    fn test_rhai_symbol_create() {
        let engine = make_full_engine();
        let sym: RhaiSymbol = engine
            .eval(r#"symbol(0x401000, "main", "target.exe")"#)
            .unwrap();
        assert_eq!(sym.name, "main");
    }

    #[test]
    fn test_rhai_bb_is_entry_get() {
        let engine = make_full_engine();
        let is_entry: bool = engine.eval("basic_block(0x1000, 0x1020).is_entry").unwrap();
        assert!(!is_entry); // newly created is not entry by default
    }

    #[test]
    fn test_rhai_function_is_thunk_get() {
        let engine = make_full_engine();
        let thunk: bool = engine.eval(r#"function(0, 10, "f").is_thunk"#).unwrap();
        assert!(!thunk);
    }

    #[test]
    fn test_rhai_address_comparison() {
        let engine = make_full_engine();
        let result: bool = engine.eval("address(0x1000) < address(0x2000)").unwrap();
        assert!(result);
    }

    #[test]
    fn test_rhai_address_equality() {
        let engine = make_full_engine();
        let result: bool = engine.eval("address(0x1000) == address(0x1000)").unwrap();
        assert!(result);
    }
}
