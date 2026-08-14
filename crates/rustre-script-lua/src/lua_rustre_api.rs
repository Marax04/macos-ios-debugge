//! Lua bindings to the `RustRE` analysis API — **trait-based abstract layer**.
//!
//! `LuaRustreApi` exposes core `RustRE` functions to Lua scripts via the
//! `AnalysisApi` trait.  The trait decouples the Lua surface from any concrete
//! backend; `MockApi` is the in-process test implementation.
//!
//! # Relationship to other API modules
//!
//! | Module | Role |
//! |---|---|
//! | `lua_rustre_api` (this) | Abstract trait + mock; uses internal `LuaValue` |
//! | `lua_api_bindings` | Function registry with metadata and doc generation |
//! | `lua_api_complete` | Concrete implementation with real file I/O and PE parsing |
//!
//! These three modules are **intentionally distinct layers** and should not be
//! merged: the trait layer enables testing, the registry layer enables
//! discoverability, and the complete layer provides the real functionality.

use crate::LuaValue;
use std::collections::HashMap;

// ── AnalysisApi trait ─────────────────────────────────────────────────────────

/// Core analysis operations that a `RustRE` backend must provide.
pub trait AnalysisApi: Send + Sync {
    /// Get the function that contains `ea`. Returns the function name and its
    /// start address.
    fn get_function(&self, ea: u64) -> Option<(u64, String)>;

    /// Get the basic blocks of the function at `ea`. Each block is described
    /// by (`start_addr`, `end_addr`, `list_of_successor_addrs`).
    fn get_basic_blocks(&self, ea: u64) -> Vec<(u64, u64, Vec<u64>)>;

    /// Get all cross-references *to* `ea`. Returns a list of (`from_addr`, kind).
    fn get_xrefs_to(&self, ea: u64) -> Vec<(u64, String)>;

    /// Set a comment at `ea`.
    fn set_comment(&self, ea: u64, comment: &str);

    /// Create a symbol (name) at `ea`.
    fn create_symbol(&self, ea: u64, name: &str);

    /// Read `len` bytes starting at `ea`. Returns `None` if out of range.
    fn get_bytes(&self, ea: u64, len: usize) -> Option<Vec<u8>>;

    /// Search for a byte pattern in the binary. Returns all matching addresses.
    /// Pattern uses hex bytes separated by spaces; `??` is a wildcard.
    fn search_pattern(&self, pattern: &str) -> Vec<u64>;

    /// Get all strings found in the binary. Returns (addr, value, encoding).
    fn get_strings(&self) -> Vec<(u64, String, String)>;

    /// Run an analysis pass by name. Returns `true` if the pass succeeded.
    fn run_analysis(&self, pass_name: &str) -> bool;
}

// ── MockApi ───────────────────────────────────────────────────────────────────

/// An in-memory mock of the analysis API for testing.
#[derive(Default)]
pub struct MockApi {
    pub binary: Vec<u8>,
    pub functions: HashMap<u64, String>,
    pub comments: parking_lot::Mutex<HashMap<u64, String>>,
    pub symbols: parking_lot::Mutex<HashMap<u64, String>>,
    pub strings: Vec<(u64, String, String)>,
}

impl MockApi {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_function(&mut self, addr: u64, name: impl Into<String>) {
        self.functions.insert(addr, name.into());
    }

    pub fn add_string(&mut self, addr: u64, value: impl Into<String>, enc: impl Into<String>) {
        self.strings.push((addr, value.into(), enc.into()));
    }

    pub fn get_comment(&self, ea: u64) -> Option<String> {
        self.comments.lock().get(&ea).cloned()
    }

    pub fn get_symbol(&self, ea: u64) -> Option<String> {
        self.symbols.lock().get(&ea).cloned()
    }
}

impl AnalysisApi for MockApi {
    fn get_function(&self, ea: u64) -> Option<(u64, String)> {
        // Find the function whose start ≤ ea and is closest.
        self.functions
            .iter()
            .filter(|&(&addr, _)| addr <= ea)
            .max_by_key(|&(&addr, _)| addr)
            .map(|(&addr, name)| (addr, name.clone()))
    }

    fn get_basic_blocks(&self, ea: u64) -> Vec<(u64, u64, Vec<u64>)> {
        // Synthetic: return one block covering ea..ea+16 with no successors.
        if self.functions.values().any(|_| true) {
            vec![(ea, ea + 16, vec![])]
        } else {
            vec![]
        }
    }

    fn get_xrefs_to(&self, ea: u64) -> Vec<(u64, String)> {
        // Synthetic: return a call reference from ea-32 if functions exist.
        if self.functions.is_empty() {
            vec![]
        } else {
            vec![(ea.saturating_sub(32), "call".to_string())]
        }
    }

    fn set_comment(&self, ea: u64, comment: &str) {
        self.comments.lock().insert(ea, comment.to_string());
    }

    fn create_symbol(&self, ea: u64, name: &str) {
        self.symbols.lock().insert(ea, name.to_string());
    }

    fn get_bytes(&self, ea: u64, len: usize) -> Option<Vec<u8>> {
        let start = crate::casts::u64_to_usize(ea);
        let end = start.checked_add(len)?;
        if end > self.binary.len() {
            return None;
        }
        Some(self.binary[start..end].to_vec())
    }

    fn search_pattern(&self, pattern: &str) -> Vec<u64> {
        // Parse the pattern into Option<u8> bytes.
        let pat: Vec<Option<u8>> = pattern
            .split_whitespace()
            .map(|t| {
                if t == "??" || t == ".." {
                    None
                } else {
                    u8::from_str_radix(t, 16).ok()
                }
            })
            .collect();
        if pat.is_empty() {
            return vec![];
        }
        let mut results = Vec::new();
        for start in 0..self.binary.len().saturating_sub(pat.len() - 1) {
            let matched = pat
                .iter()
                .enumerate()
                .all(|(i, &b)| b.is_none_or(|expected| self.binary[start + i] == expected));
            if matched {
                results.push(start as u64);
            }
        }
        results
    }

    fn get_strings(&self) -> Vec<(u64, String, String)> {
        self.strings.clone()
    }

    fn run_analysis(&self, _pass_name: &str) -> bool {
        true
    }
}

// ── LuaRustreApi ─────────────────────────────────────────────────────────────

/// Exposes the `RustRE` analysis API to Lua scripts.
///
/// Each method converts between Lua values and the underlying `AnalysisApi`.
pub struct LuaRustreApi<A: AnalysisApi> {
    api: A,
}

impl<A: AnalysisApi> LuaRustreApi<A> {
    pub const fn new(api: A) -> Self {
        Self { api }
    }

    /// `get_function(ea)` → `{start=..., name=...}` or nil.
    pub fn lua_get_function(&self, ea: i64) -> LuaValue {
        match self.api.get_function(crate::casts::i64_to_u64(ea)) {
            None => LuaValue::Nil,
            Some((start, name)) => LuaValue::Table(vec![
                (
                    LuaValue::String("start".to_string()),
                    LuaValue::Int(crate::casts::u64_to_i64(start)),
                ),
                (LuaValue::String("name".to_string()), LuaValue::String(name)),
            ]),
        }
    }

    /// `get_basic_blocks(ea)` → table of `{start, end, successors=[...]}`.
    pub fn lua_get_basic_blocks(&self, ea: i64) -> LuaValue {
        let blocks = self.api.get_basic_blocks(crate::casts::i64_to_u64(ea));
        let entries: Vec<(LuaValue, LuaValue)> = blocks
            .into_iter()
            .enumerate()
            .map(|(i, (start, end, succs))| {
                let succ_table = LuaValue::Table(
                    succs
                        .into_iter()
                        .enumerate()
                        .map(|(j, s)| (LuaValue::Int(crate::casts::usize_to_i64(j) + 1), LuaValue::Int(crate::casts::u64_to_i64(s))))
                        .collect(),
                );
                let block = LuaValue::Table(vec![
                    (
                        LuaValue::String("start".to_string()),
                        LuaValue::Int(crate::casts::u64_to_i64(start)),
                    ),
                    (
                        LuaValue::String("end".to_string()),
                        LuaValue::Int(crate::casts::u64_to_i64(end)),
                    ),
                    (LuaValue::String("successors".to_string()), succ_table),
                ]);
                (LuaValue::Int(crate::casts::usize_to_i64(i) + 1), block)
            })
            .collect();
        LuaValue::Table(entries)
    }

    /// `get_xrefs_to(ea)` → table of `{from=..., kind=...}`.
    pub fn lua_get_xrefs_to(&self, ea: i64) -> LuaValue {
        let xrefs = self.api.get_xrefs_to(crate::casts::i64_to_u64(ea));
        let entries: Vec<(LuaValue, LuaValue)> = xrefs
            .into_iter()
            .enumerate()
            .map(|(i, (from, kind))| {
                let xref = LuaValue::Table(vec![
                    (
                        LuaValue::String("from".to_string()),
                        LuaValue::Int(crate::casts::u64_to_i64(from)),
                    ),
                    (LuaValue::String("kind".to_string()), LuaValue::String(kind)),
                ]);
                (LuaValue::Int(crate::casts::usize_to_i64(i) + 1), xref)
            })
            .collect();
        LuaValue::Table(entries)
    }

    /// `set_comment(ea, comment)`.
    pub fn lua_set_comment(&self, ea: i64, comment: &str) {
        self.api.set_comment(crate::casts::i64_to_u64(ea), comment);
    }

    /// `create_symbol(ea, name)`.
    pub fn lua_create_symbol(&self, ea: i64, name: &str) {
        self.api.create_symbol(crate::casts::i64_to_u64(ea), name);
    }

    /// `get_bytes(ea, len)` → string (raw bytes) or nil.
    pub fn lua_get_bytes(&self, ea: i64, len: i64) -> LuaValue {
        self.api.get_bytes(crate::casts::i64_to_u64(ea), crate::casts::i64_to_usize(len)).map_or(LuaValue::Nil, |bytes| {
            // Return as a hex string for portability.
            let hex: String = bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            LuaValue::String(hex)
        })
    }

    /// `search_pattern(pattern)` → table of addresses.
    pub fn lua_search_pattern(&self, pattern: &str) -> LuaValue {
        let addrs = self.api.search_pattern(pattern);
        let entries: Vec<(LuaValue, LuaValue)> = addrs
            .into_iter()
            .enumerate()
            .map(|(i, addr)| (LuaValue::Int(crate::casts::usize_to_i64(i) + 1), LuaValue::Int(crate::casts::u64_to_i64(addr))))
            .collect();
        LuaValue::Table(entries)
    }

    /// `get_strings()` → table of `{addr, value, encoding}`.
    pub fn lua_get_strings(&self) -> LuaValue {
        let strings = self.api.get_strings();
        let entries: Vec<(LuaValue, LuaValue)> = strings
            .into_iter()
            .enumerate()
            .map(|(i, (addr, value, enc))| {
                let entry = LuaValue::Table(vec![
                    (
                        LuaValue::String("addr".to_string()),
                        LuaValue::Int(crate::casts::u64_to_i64(addr)),
                    ),
                    (
                        LuaValue::String("value".to_string()),
                        LuaValue::String(value),
                    ),
                    (
                        LuaValue::String("encoding".to_string()),
                        LuaValue::String(enc),
                    ),
                ]);
                (LuaValue::Int(crate::casts::usize_to_i64(i) + 1), entry)
            })
            .collect();
        LuaValue::Table(entries)
    }

    /// `run_analysis(pass_name)` → bool.
    pub fn lua_run_analysis(&self, pass_name: &str) -> LuaValue {
        LuaValue::Bool(self.api.run_analysis(pass_name))
    }

    /// Dispatch a function call by name, forwarding `args`.
    pub fn dispatch(&self, name: &str, args: &[LuaValue]) -> LuaValue {
        match name {
            "get_function" => {
                let ea = args.first().and_then(super::LuaValue::as_int).unwrap_or(0);
                self.lua_get_function(ea)
            }
            "get_basic_blocks" => {
                let ea = args.first().and_then(super::LuaValue::as_int).unwrap_or(0);
                self.lua_get_basic_blocks(ea)
            }
            "get_xrefs_to" => {
                let ea = args.first().and_then(super::LuaValue::as_int).unwrap_or(0);
                self.lua_get_xrefs_to(ea)
            }
            "set_comment" => {
                let ea = args.first().and_then(super::LuaValue::as_int).unwrap_or(0);
                let comment = args
                    .get(1)
                    .and_then(|v| v.as_str().map(std::string::ToString::to_string))
                    .unwrap_or_default();
                self.lua_set_comment(ea, &comment);
                LuaValue::Nil
            }
            "create_symbol" => {
                let ea = args.first().and_then(super::LuaValue::as_int).unwrap_or(0);
                let name = args
                    .get(1)
                    .and_then(|v| v.as_str().map(std::string::ToString::to_string))
                    .unwrap_or_default();
                self.lua_create_symbol(ea, &name);
                LuaValue::Nil
            }
            "get_bytes" => {
                let ea = args.first().and_then(super::LuaValue::as_int).unwrap_or(0);
                let len = args.get(1).and_then(super::LuaValue::as_int).unwrap_or(16);
                self.lua_get_bytes(ea, len)
            }
            "search_pattern" => {
                let pat = args
                    .first()
                    .and_then(|v| v.as_str().map(std::string::ToString::to_string))
                    .unwrap_or_default();
                self.lua_search_pattern(&pat)
            }
            "get_strings" => self.lua_get_strings(),
            "run_analysis" => {
                let pass = args
                    .first()
                    .and_then(|v| v.as_str().map(std::string::ToString::to_string))
                    .unwrap_or_default();
                self.lua_run_analysis(&pass)
            }
            _ => LuaValue::Nil,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_api() -> LuaRustreApi<MockApi> {
        let mut mock = MockApi::new();
        mock.binary = vec![0x55u8, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x00, 0xAA, 0xBB, 0xCC];
        mock.add_function(0x1000, "main");
        mock.add_function(0x2000, "helper");
        mock.add_string(0x500, "hello", "ascii");
        mock.add_string(0x510, "world", "ascii");
        LuaRustreApi::new(mock)
    }

    // ── get_function ──────────────────────────────────────────────────────────

    #[test]
    fn test_get_function_found() {
        let api = make_api();
        let v = api.lua_get_function(0x1000);
        assert!(matches!(v, LuaValue::Table(_)));
        if let LuaValue::Table(t) = v {
            let start = t
                .iter()
                .find(|(k, _)| matches!(k, LuaValue::String(s) if s == "start"))
                .and_then(|(_, v)| v.as_int());
            assert_eq!(start, Some(0x1000));
        }
    }

    #[test]
    fn test_get_function_inside() {
        let api = make_api();
        let v = api.lua_get_function(0x1008);
        assert!(matches!(v, LuaValue::Table(_)));
    }

    #[test]
    fn test_get_function_not_found() {
        let mock = MockApi::new();
        let api = LuaRustreApi::new(mock);
        let v = api.lua_get_function(0x9999);
        assert!(matches!(v, LuaValue::Nil));
    }

    // ── get_basic_blocks ──────────────────────────────────────────────────────

    #[test]
    fn test_get_basic_blocks_returns_table() {
        let api = make_api();
        let v = api.lua_get_basic_blocks(0x1000);
        assert!(matches!(v, LuaValue::Table(_)));
    }

    #[test]
    fn test_get_basic_blocks_has_start_end() {
        let api = make_api();
        if let LuaValue::Table(t) = api.lua_get_basic_blocks(0x1000) {
            assert!(!t.is_empty());
            if let (_, LuaValue::Table(block)) = &t[0] {
                let has_start = block
                    .iter()
                    .any(|(k, _)| matches!(k, LuaValue::String(s) if s == "start"));
                assert!(has_start);
            }
        }
    }

    // ── get_xrefs_to ──────────────────────────────────────────────────────────

    #[test]
    fn test_get_xrefs_to_returns_table() {
        let api = make_api();
        let v = api.lua_get_xrefs_to(0x1000);
        assert!(matches!(v, LuaValue::Table(_)));
    }

    #[test]
    fn test_get_xrefs_to_has_from_and_kind() {
        let api = make_api();
        if let LuaValue::Table(t) = api.lua_get_xrefs_to(0x1000)
            && !t.is_empty()
                && let (_, LuaValue::Table(xref)) = &t[0] {
                    let has_kind = xref
                        .iter()
                        .any(|(k, _)| matches!(k, LuaValue::String(s) if s == "kind"));
                    assert!(has_kind);
                }
    }

    // ── set_comment ───────────────────────────────────────────────────────────

    #[test]
    fn test_set_comment_stores() {
        let api = make_api();
        api.lua_set_comment(0x1000, "this is main");
        let got = api.api.get_comment(0x1000);
        assert_eq!(got, Some("this is main".to_string()));
    }

    #[test]
    fn test_set_comment_overwrite() {
        let api = make_api();
        api.lua_set_comment(0x1000, "first");
        api.lua_set_comment(0x1000, "second");
        assert_eq!(api.api.get_comment(0x1000), Some("second".to_string()));
    }

    // ── create_symbol ─────────────────────────────────────────────────────────

    #[test]
    fn test_create_symbol_stores() {
        let api = make_api();
        api.lua_create_symbol(0x4000, "my_func");
        assert_eq!(api.api.get_symbol(0x4000), Some("my_func".to_string()));
    }

    // ── get_bytes ─────────────────────────────────────────────────────────────

    #[test]
    fn test_get_bytes_valid() {
        let api = make_api();
        let v = api.lua_get_bytes(0, 4);
        assert!(matches!(v, LuaValue::String(_)));
        if let LuaValue::String(s) = v {
            assert!(s.starts_with("55 8b"));
        }
    }

    #[test]
    fn test_get_bytes_out_of_range() {
        let api = make_api();
        let v = api.lua_get_bytes(0, 1000);
        assert!(matches!(v, LuaValue::Nil));
    }

    #[test]
    fn test_get_bytes_zero_len() {
        let api = make_api();
        let v = api.lua_get_bytes(0, 0);
        assert!(matches!(v, LuaValue::String(s) if s.is_empty()));
    }

    // ── search_pattern ────────────────────────────────────────────────────────

    #[test]
    fn test_search_pattern_found() {
        let api = make_api();
        let v = api.lua_search_pattern("55 8B EC");
        if let LuaValue::Table(t) = v {
            assert!(!t.is_empty());
            if let (_, LuaValue::Int(addr)) = &t[0] {
                assert_eq!(*addr, 0);
            }
        }
    }

    #[test]
    fn test_search_pattern_wildcard() {
        let api = make_api();
        let v = api.lua_search_pattern("55 ?? EC");
        if let LuaValue::Table(t) = v {
            assert!(!t.is_empty());
        }
    }

    #[test]
    fn test_search_pattern_not_found() {
        let api = make_api();
        let v = api.lua_search_pattern("FF FF FF FF");
        if let LuaValue::Table(t) = v {
            assert!(t.is_empty());
        }
    }

    // ── get_strings ───────────────────────────────────────────────────────────

    #[test]
    fn test_get_strings_count() {
        let api = make_api();
        let v = api.lua_get_strings();
        if let LuaValue::Table(t) = v {
            assert_eq!(t.len(), 2);
        }
    }

    #[test]
    fn test_get_strings_has_fields() {
        let api = make_api();
        if let LuaValue::Table(t) = api.lua_get_strings()
            && let (_, LuaValue::Table(entry)) = &t[0] {
                let has_value = entry
                    .iter()
                    .any(|(k, _)| matches!(k, LuaValue::String(s) if s == "value"));
                assert!(has_value);
            }
    }

    #[test]
    fn test_get_strings_empty() {
        let api = LuaRustreApi::new(MockApi::new());
        let v = api.lua_get_strings();
        assert!(matches!(v, LuaValue::Table(t) if t.is_empty()));
    }

    // ── run_analysis ──────────────────────────────────────────────────────────

    #[test]
    fn test_run_analysis_returns_bool() {
        let api = make_api();
        let v = api.lua_run_analysis("auto_analysis");
        assert!(matches!(v, LuaValue::Bool(true)));
    }

    // ── dispatch ──────────────────────────────────────────────────────────────

    #[test]
    fn test_dispatch_get_function() {
        let api = make_api();
        let v = api.dispatch("get_function", &[LuaValue::Int(0x1000)]);
        assert!(matches!(v, LuaValue::Table(_)));
    }

    #[test]
    fn test_dispatch_get_bytes() {
        let api = make_api();
        let v = api.dispatch("get_bytes", &[LuaValue::Int(0), LuaValue::Int(2)]);
        assert!(matches!(v, LuaValue::String(_)));
    }

    #[test]
    fn test_dispatch_search_pattern() {
        let api = make_api();
        let v = api.dispatch("search_pattern", &[LuaValue::String("55".to_string())]);
        assert!(matches!(v, LuaValue::Table(_)));
    }

    #[test]
    fn test_dispatch_get_strings() {
        let api = make_api();
        let v = api.dispatch("get_strings", &[]);
        assert!(matches!(v, LuaValue::Table(_)));
    }

    #[test]
    fn test_dispatch_run_analysis() {
        let api = make_api();
        let v = api.dispatch("run_analysis", &[LuaValue::String("pass".to_string())]);
        assert!(matches!(v, LuaValue::Bool(true)));
    }

    #[test]
    fn test_dispatch_unknown_returns_nil() {
        let api = make_api();
        let v = api.dispatch("nonexistent_function", &[]);
        assert!(matches!(v, LuaValue::Nil));
    }

    #[test]
    fn test_dispatch_set_comment() {
        let api = make_api();
        api.dispatch(
            "set_comment",
            &[LuaValue::Int(0x2000), LuaValue::String("note".to_string())],
        );
        assert_eq!(api.api.get_comment(0x2000), Some("note".to_string()));
    }

    #[test]
    fn test_dispatch_create_symbol() {
        let api = make_api();
        api.dispatch(
            "create_symbol",
            &[LuaValue::Int(0x5000), LuaValue::String("sym".to_string())],
        );
        assert_eq!(api.api.get_symbol(0x5000), Some("sym".to_string()));
    }

    #[test]
    fn test_dispatch_get_xrefs_to() {
        let api = make_api();
        let v = api.dispatch("get_xrefs_to", &[LuaValue::Int(0x1000)]);
        assert!(matches!(v, LuaValue::Table(_)));
    }

    #[test]
    fn test_dispatch_get_basic_blocks() {
        let api = make_api();
        let v = api.dispatch("get_basic_blocks", &[LuaValue::Int(0x1000)]);
        assert!(matches!(v, LuaValue::Table(_)));
    }
}
