//! `context_propagation` — Propagation of RE analysis context between tool calls.
//!
//! Carries binary view state, type info, symbol table, analysis results, and
//! provides selective injection per tool call.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ─────────────────────────────────────────────────────────────────────────────
// BinaryView
// ─────────────────────────────────────────────────────────────────────────────

/// Snapshot of the current binary view state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BinaryView {
    /// Full path to the binary on disk.
    pub path: Option<String>,
    /// SHA-256 hex digest.
    pub sha256: Option<String>,
    /// Architecture string (e.g. "x86_64", "arm64").
    pub arch: Option<String>,
    /// Operating system / file format (e.g. "pe", "elf", "macho").
    pub format: Option<String>,
    /// Bitness (32 or 64).
    pub bits: Option<u32>,
    /// Current cursor / selected address (hex string).
    pub current_address: Option<String>,
    /// Name of the currently selected function.
    pub current_function: Option<String>,
    /// Start address of the selected region.
    pub selection_start: Option<String>,
    /// End address of the selected region.
    pub selection_end: Option<String>,
    /// Loaded base address (hex string).
    pub image_base: Option<String>,
    /// Entry-point address (hex string).
    pub entry_point: Option<String>,
    /// Whether ASLR is detected.
    pub has_aslr: Option<bool>,
}

impl BinaryView {
    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    #[must_use]
    pub fn with_arch(mut self, arch: impl Into<String>) -> Self {
        self.arch = Some(arch.into());
        self
    }

    #[must_use]
    pub fn at_address(mut self, addr: impl Into<String>) -> Self {
        self.current_address = Some(addr.into());
        self
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeContext
// ─────────────────────────────────────────────────────────────────────────────

/// A single reconstructed type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeEntry {
    pub name: String,
    pub kind: String, // "struct", "enum", "typedef", "function", …
    pub definition: String,
    pub size_bytes: Option<u32>,
    pub source: String, // which tool produced this
}

/// Accumulated type information from the analysis session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TypeContext {
    pub types: HashMap<String, TypeEntry>,
}

impl TypeContext {
    pub fn add(&mut self, entry: TypeEntry) {
        self.types.insert(entry.name.clone(), entry);
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&TypeEntry> {
        self.types.get(name)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.types.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Return all type names.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.types.keys().map(String::as_str).collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SymbolTable
// ─────────────────────────────────────────────────────────────────────────────

/// Kind of a symbol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SymbolKind {
    Function,
    Data,
    Import,
    Export,
    Label,
    String,
    Unknown,
}

/// A single symbol entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    pub address: u64,
    pub name: String,
    pub kind: SymbolKind,
    pub size: Option<u32>,
    pub demangled: Option<String>,
    pub source: String,
}

impl Symbol {
    #[must_use]
    pub fn new(address: u64, name: impl Into<String>, kind: SymbolKind) -> Self {
        Self {
            address,
            name: name.into(),
            kind,
            size: None,
            demangled: None,
            source: "unknown".into(),
        }
    }
}

/// Accumulated symbol table.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SymbolTable {
    by_address: HashMap<u64, Symbol>,
    by_name: HashMap<String, u64>,
}

impl SymbolTable {
    pub fn insert(&mut self, sym: Symbol) {
        self.by_name.insert(sym.name.clone(), sym.address);
        self.by_address.insert(sym.address, sym);
    }

    #[must_use]
    pub fn by_address(&self, addr: u64) -> Option<&Symbol> {
        self.by_address.get(&addr)
    }

    #[must_use]
    pub fn by_name(&self, name: &str) -> Option<&Symbol> {
        self.by_name.get(name).and_then(|a| self.by_address.get(a))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_address.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_address.is_empty()
    }

    /// Functions only.
    #[must_use]
    pub fn functions(&self) -> Vec<&Symbol> {
        self.by_address
            .values()
            .filter(|s| s.kind == SymbolKind::Function)
            .collect()
    }

    /// Exports only.
    #[must_use]
    pub fn exports(&self) -> Vec<&Symbol> {
        self.by_address
            .values()
            .filter(|s| s.kind == SymbolKind::Export)
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisResult — generic accumulated analysis output
// ─────────────────────────────────────────────────────────────────────────────

/// A single analysis result produced by a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub tool: String,
    pub server: String,
    pub key: String,
    pub value: Value,
    pub produced_at_ms: u64,
    pub confidence: Option<f64>,
}

impl AnalysisResult {
    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }

    #[must_use]
    pub fn new(tool: impl Into<String>, server: impl Into<String>, key: impl Into<String>, value: Value) -> Self {
        Self {
            tool: tool.into(),
            server: server.into(),
            key: key.into(),
            value,
            produced_at_ms: Self::now_ms(),
            confidence: None,
        }
    }

    #[must_use]
    pub fn with_confidence(mut self, conf: f64) -> Self {
        self.confidence = Some(conf);
        self
    }
}

/// Collection of accumulated analysis results across tools and servers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisResults {
    /// All results ordered by insertion time.
    pub results: Vec<AnalysisResult>,
}

impl AnalysisResults {
    pub fn push(&mut self, result: AnalysisResult) {
        self.results.push(result);
    }

    /// Lookup by key (returns the most recently pushed result with that key).
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&AnalysisResult> {
        self.results.iter().rev().find(|r| r.key == key)
    }

    #[must_use]
    pub fn by_tool(&self, tool: &str) -> Vec<&AnalysisResult> {
        self.results.iter().filter(|r| r.tool == tool).collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.results.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ContextMask — controls what gets injected into a call
// ─────────────────────────────────────────────────────────────────────────────

/// Bitmask controlling which context pieces are injected.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContextMask {
    pub binary_view: bool,
    pub type_context: bool,
    pub symbol_table: bool,
    pub analysis_results: bool,
    /// Inject only analysis results with these keys.
    pub result_keys: Vec<String>,
    /// Inject only symbol types matching these kinds.
    pub symbol_kinds: Vec<SymbolKind>,
    /// Maximum number of symbols to inject (0 = no limit).
    pub max_symbols: usize,
    /// Maximum number of analysis results to inject (0 = no limit).
    pub max_results: usize,
}

impl ContextMask {
    #[must_use]
    pub fn all() -> Self {
        Self {
            binary_view: true,
            type_context: true,
            symbol_table: true,
            analysis_results: true,
            result_keys: Vec::new(),
            symbol_kinds: Vec::new(),
            max_symbols: 0,
            max_results: 0,
        }
    }

    #[must_use]
    pub fn binary_only() -> Self {
        Self { binary_view: true, ..Default::default() }
    }

    #[must_use]
    pub fn with_results(keys: Vec<String>) -> Self {
        Self {
            analysis_results: true,
            result_keys: keys,
            ..Default::default()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AnalysisContext — the full session context
// ─────────────────────────────────────────────────────────────────────────────

/// The full analysis context for a RE session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisContext {
    pub binary_view: BinaryView,
    pub types: TypeContext,
    pub symbols: SymbolTable,
    pub results: AnalysisResults,
    /// Arbitrary extra key/value pairs.
    pub extra: HashMap<String, Value>,
}

impl AnalysisContext {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set binary view.
    pub fn set_binary_view(&mut self, view: BinaryView) {
        self.binary_view = view;
    }

    /// Add a type entry.
    pub fn add_type(&mut self, entry: TypeEntry) {
        self.types.add(entry);
    }

    /// Insert a symbol.
    pub fn add_symbol(&mut self, sym: Symbol) {
        self.symbols.insert(sym);
    }

    /// Push an analysis result.
    pub fn push_result(&mut self, result: AnalysisResult) {
        self.results.push(result);
    }

    /// Insert extra key-value metadata.
    pub fn set_extra(&mut self, key: impl Into<String>, value: Value) {
        self.extra.insert(key.into(), value);
    }

    /// Merge another context into this one (union).
    pub fn merge(&mut self, other: AnalysisContext) {
        // Binary view: update non-None fields
        if other.binary_view.path.is_some() { self.binary_view.path = other.binary_view.path; }
        if other.binary_view.arch.is_some() { self.binary_view.arch = other.binary_view.arch; }
        if other.binary_view.current_address.is_some() {
            self.binary_view.current_address = other.binary_view.current_address;
        }
        // Types
        for (_, entry) in other.types.types {
            self.types.add(entry);
        }
        // Symbols
        for (_, sym) in other.symbols.by_address {
            self.symbols.insert(sym);
        }
        // Results
        for r in other.results.results {
            self.results.push(r);
        }
        // Extra
        self.extra.extend(other.extra);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ContextInjector
// ─────────────────────────────────────────────────────────────────────────────

/// Selectively injects context into tool call parameters.
pub struct ContextInjector<'a> {
    ctx: &'a AnalysisContext,
}

impl<'a> ContextInjector<'a> {
    #[must_use]
    pub fn new(ctx: &'a AnalysisContext) -> Self {
        Self { ctx }
    }

    /// Inject context into `params` according to the given mask.
    #[must_use]
    pub fn inject(&self, mut params: Value, mask: &ContextMask) -> Value {
        let Value::Object(ref mut map) = params else {
            return params;
        };

        let mut ctx_obj = serde_json::Map::new();

        if mask.binary_view {
            if let Ok(v) = serde_json::to_value(&self.ctx.binary_view) {
                ctx_obj.insert("binary_view".into(), v);
            }
        }

        if mask.type_context && !self.ctx.types.is_empty() {
            let type_list: Vec<Value> = self
                .ctx
                .types
                .types
                .values()
                .filter_map(|t| serde_json::to_value(t).ok())
                .collect();
            ctx_obj.insert("types".into(), Value::Array(type_list));
        }

        if mask.symbol_table && !self.ctx.symbols.is_empty() {
            let mut syms: Vec<&Symbol> = if mask.symbol_kinds.is_empty() {
                self.ctx.symbols.by_address.values().collect()
            } else {
                self.ctx
                    .symbols
                    .by_address
                    .values()
                    .filter(|s| mask.symbol_kinds.contains(&s.kind))
                    .collect()
            };
            if mask.max_symbols > 0 && syms.len() > mask.max_symbols {
                syms.truncate(mask.max_symbols);
            }
            let sym_list: Vec<Value> =
                syms.iter().filter_map(|s| serde_json::to_value(s).ok()).collect();
            ctx_obj.insert("symbols".into(), Value::Array(sym_list));
        }

        if mask.analysis_results && !self.ctx.results.is_empty() {
            let mut results: Vec<&AnalysisResult> = if mask.result_keys.is_empty() {
                self.ctx.results.results.iter().collect()
            } else {
                self.ctx
                    .results
                    .results
                    .iter()
                    .filter(|r| mask.result_keys.contains(&r.key))
                    .collect()
            };
            if mask.max_results > 0 && results.len() > mask.max_results {
                results = results.into_iter().rev().take(mask.max_results).collect();
            }
            let res_list: Vec<Value> =
                results.iter().filter_map(|r| serde_json::to_value(r).ok()).collect();
            ctx_obj.insert("analysis_results".into(), Value::Array(res_list));
        }

        if !ctx_obj.is_empty() {
            map.insert("__ctx".into(), Value::Object(ctx_obj));
        }

        params
    }

    /// Strip `__ctx` from params (before forwarding to servers that don't expect it).
    #[must_use]
    pub fn strip(mut params: Value) -> Value {
        if let Value::Object(ref mut map) = params {
            map.remove("__ctx");
        }
        params
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ContextExtractor — parse tool output and update the context
// ─────────────────────────────────────────────────────────────────────────────

/// Extracts context-relevant data from tool outputs and updates `AnalysisContext`.
pub struct ContextExtractor;

impl ContextExtractor {
    /// Attempt to extract symbols from a tool result (heuristic).
    pub fn extract_symbols(ctx: &mut AnalysisContext, tool: &str, server: &str, result: &Value) {
        // Look for common patterns: `{"symbols": [...]}`, `{"functions": [...]}`
        for key in &["symbols", "functions", "exports", "imports"] {
            if let Some(arr) = result.get(key).and_then(Value::as_array) {
                let kind = match *key {
                    "exports" => SymbolKind::Export,
                    "imports" => SymbolKind::Import,
                    "functions" => SymbolKind::Function,
                    _ => SymbolKind::Unknown,
                };
                for item in arr {
                    let name = item.get("name").or_else(|| item.get("symbol"))
                        .and_then(Value::as_str).unwrap_or("?").to_string();
                    let addr = item.get("address").or_else(|| item.get("addr"))
                        .and_then(Value::as_str)
                        .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
                        .unwrap_or(0);
                    let mut sym = Symbol::new(addr, name, kind.clone());
                    sym.source = format!("{server}/{tool}");
                    ctx.add_symbol(sym);
                }
            }
        }
    }

    /// Extract types from decompiler output.
    pub fn extract_types(ctx: &mut AnalysisContext, tool: &str, server: &str, result: &Value) {
        if let Some(arr) = result.get("types").and_then(Value::as_array) {
            for item in arr {
                let name = item.get("name").and_then(Value::as_str).unwrap_or("?").to_string();
                let kind = item.get("kind").and_then(Value::as_str).unwrap_or("unknown").to_string();
                let def = item.get("definition").and_then(Value::as_str).unwrap_or("").to_string();
                ctx.add_type(TypeEntry {
                    name,
                    kind,
                    definition: def,
                    size_bytes: item.get("size").and_then(Value::as_u64).map(|s| s as u32),
                    source: format!("{server}/{tool}"),
                });
            }
        }
    }

    /// Store a generic analysis result.
    pub fn store_result(
        ctx: &mut AnalysisContext,
        tool: impl Into<String>,
        server: impl Into<String>,
        key: impl Into<String>,
        value: Value,
        confidence: Option<f64>,
    ) {
        let mut r = AnalysisResult::new(tool, server, key, value);
        if let Some(c) = confidence {
            r = r.with_confidence(c);
        }
        ctx.push_result(r);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> AnalysisContext {
        let mut ctx = AnalysisContext::new();
        ctx.set_binary_view(BinaryView::default().with_path("/bin/test").with_arch("x86_64"));
        ctx.add_symbol(Symbol::new(0x1000, "main", SymbolKind::Function));
        ctx.add_type(TypeEntry {
            name: "HANDLE".into(),
            kind: "typedef".into(),
            definition: "typedef void* HANDLE;".into(),
            size_bytes: Some(8),
            source: "manual".into(),
        });
        ctx.push_result(AnalysisResult::new("decompile", "ghidra", "decompiled_code", serde_json::json!({"code": "int main(){}"})));
        ctx
    }

    #[test]
    fn test_inject_all() {
        let ctx = make_ctx();
        let injector = ContextInjector::new(&ctx);
        let params = serde_json::json!({"address": "0x1000"});
        let injected = injector.inject(params, &ContextMask::all());
        assert!(injected.get("__ctx").is_some());
        let c = &injected["__ctx"];
        assert!(c.get("binary_view").is_some());
        assert!(c.get("symbols").is_some());
        assert!(c.get("types").is_some());
        assert!(c.get("analysis_results").is_some());
    }

    #[test]
    fn test_inject_binary_only() {
        let ctx = make_ctx();
        let injector = ContextInjector::new(&ctx);
        let params = serde_json::json!({});
        let injected = injector.inject(params, &ContextMask::binary_only());
        let c = &injected["__ctx"];
        assert!(c.get("binary_view").is_some());
        assert!(c.get("symbols").is_none());
    }

    #[test]
    fn test_inject_result_keys_filter() {
        let ctx = make_ctx();
        let injector = ContextInjector::new(&ctx);
        let params = serde_json::json!({});
        let mask = ContextMask::with_results(vec!["decompiled_code".into()]);
        let injected = injector.inject(params, &mask);
        let results = &injected["__ctx"]["analysis_results"];
        assert!(results.is_array());
        assert!(!results.as_array().unwrap().is_empty());
    }

    #[test]
    fn test_strip() {
        let params = serde_json::json!({"x": 1, "__ctx": {"binary_view": {}}});
        let stripped = ContextInjector::strip(params);
        assert!(stripped.get("__ctx").is_none());
        assert_eq!(stripped["x"], 1);
    }

    #[test]
    fn test_symbol_table_by_name() {
        let mut ctx = AnalysisContext::new();
        ctx.add_symbol(Symbol::new(0x4000, "strcmp", SymbolKind::Import));
        assert_eq!(ctx.symbols.by_name("strcmp").unwrap().address, 0x4000);
    }

    #[test]
    fn test_type_context() {
        let mut tc = TypeContext::default();
        tc.add(TypeEntry {
            name: "DWORD".into(),
            kind: "typedef".into(),
            definition: "typedef uint32_t DWORD;".into(),
            size_bytes: Some(4),
            source: "test".into(),
        });
        assert!(tc.get("DWORD").is_some());
        assert_eq!(tc.len(), 1);
    }

    #[test]
    fn test_analysis_results_get() {
        let mut ar = AnalysisResults::default();
        ar.push(AnalysisResult::new("t", "s", "key1", serde_json::json!(1)));
        ar.push(AnalysisResult::new("t", "s", "key1", serde_json::json!(2)));
        // Most recent should be returned
        assert_eq!(ar.get("key1").unwrap().value, serde_json::json!(2));
    }

    #[test]
    fn test_extract_symbols() {
        let mut ctx = AnalysisContext::new();
        let result = serde_json::json!({
            "functions": [
                {"name": "sub_1000", "address": "0x1000"},
                {"name": "sub_2000", "address": "0x2000"}
            ]
        });
        ContextExtractor::extract_symbols(&mut ctx, "disasm", "ghidra", &result);
        assert_eq!(ctx.symbols.len(), 2);
        assert!(ctx.symbols.by_name("sub_1000").is_some());
    }

    #[test]
    fn test_extract_types() {
        let mut ctx = AnalysisContext::new();
        let result = serde_json::json!({
            "types": [
                {"name": "MyStruct", "kind": "struct", "definition": "struct MyStruct { int x; };", "size": 4}
            ]
        });
        ContextExtractor::extract_types(&mut ctx, "decompile", "ghidra", &result);
        assert!(ctx.types.get("MyStruct").is_some());
    }

    #[test]
    fn test_context_merge() {
        let mut a = AnalysisContext::new();
        a.set_binary_view(BinaryView::default().with_path("/bin/a"));
        let mut b = AnalysisContext::new();
        b.set_binary_view(BinaryView::default().with_path("/bin/b"));
        b.add_symbol(Symbol::new(0x100, "sym", SymbolKind::Function));
        a.merge(b);
        assert_eq!(a.binary_view.path, Some("/bin/b".into()));
        assert_eq!(a.symbols.len(), 1);
    }
}
