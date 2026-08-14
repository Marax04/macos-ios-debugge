//! Rhai bindings for the `RustRE` analysis API.
//!
//! Provides [`RhaiRustreModule`], the primary bridge between the Rhai scripting
//! engine and the core `RustRE` analysis functions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rhai::{Array, Dynamic, Engine, EvalAltResult, Module};

use crate::{sat_i64_to_usize, sat_u64_to_usize, sat_usize_to_i64};

/// Re-export of [`rhai::NativeCallContext`] for downstream consumers that
/// register native callbacks against the `RustRE` Rhai API surface.
pub use rhai::NativeCallContext;

// ─── RhaiValue ────────────────────────────────────────────────────────────────

/// Type bridge between `RustRE`'s native types and Rhai's Dynamic.
#[derive(Debug, Clone)]
pub enum RhaiValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<Self>),
    Map(HashMap<String, Self>),
}

impl RhaiValue {
    pub fn to_dynamic(&self) -> Dynamic {
        match self {
            Self::Null => Dynamic::UNIT,
            Self::Bool(b) => Dynamic::from(*b),
            Self::Int(i) => Dynamic::from(*i),
            Self::Float(f) => Dynamic::from(*f),
            Self::String(s) => Dynamic::from(s.clone()),
            Self::Bytes(b) => {
                let arr: Array = b
                    .iter()
                    .map(|&byte| Dynamic::from(i64::from(byte)))
                    .collect();
                Dynamic::from(arr)
            }
            Self::Array(arr) => {
                let arr: Array = arr.iter().map(Self::to_dynamic).collect();
                Dynamic::from(arr)
            }
            Self::Map(map) => {
                let mut rhai_map = rhai::Map::new();
                for (k, v) in map {
                    rhai_map.insert(k.clone().into(), v.to_dynamic());
                }
                Dynamic::from(rhai_map)
            }
        }
    }

    #[must_use]
    pub fn from_dynamic(d: &Dynamic) -> Self {
        if d.is_unit() {
            Self::Null
        } else if d.is_bool() {
            Self::Bool(d.as_bool().unwrap_or(false))
        } else if d.is_int() {
            Self::Int(d.as_int().unwrap_or(0))
        } else if d.is_float() {
            Self::Float(d.as_float().unwrap_or(0.0))
        } else {
            Self::String(d.to_string())
        }
    }
}

// ─── AnalysisBackend ──────────────────────────────────────────────────────────

/// Mock analysis backend used by Rhai functions.
/// In production this would delegate to the actual `RustRE` analysis session.
#[derive(Debug, Default, Clone)]
pub struct AnalysisBackend {
    /// Binary data loaded for analysis.
    pub data: Vec<u8>,
    /// Simulated function table: address → name.
    pub functions: HashMap<u64, String>,
    /// Simulated symbol table: address → name.
    pub symbols: HashMap<u64, String>,
    /// Simulated comment table: address → comment.
    pub comments: HashMap<u64, String>,
    /// Simulated xrefs: `from_addr` → [`to_addr`].
    pub xrefs: HashMap<u64, Vec<u64>>,
    /// Simulated strings: address → value.
    pub strings: HashMap<u64, String>,
    /// Simulated cross-references reverse: `to_addr` → [`from_addr`].
    pub xrefs_to: HashMap<u64, Vec<u64>>,
}

impl AnalysisBackend {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    pub fn add_function(&mut self, addr: u64, name: &str) {
        self.functions.insert(addr, name.to_string());
        self.symbols.insert(addr, name.to_string());
    }

    pub fn add_xref(&mut self, from: u64, to: u64) {
        self.xrefs.entry(from).or_default().push(to);
        self.xrefs_to.entry(to).or_default().push(from);
    }

    pub fn add_string(&mut self, addr: u64, s: &str) {
        self.strings.insert(addr, s.to_string());
    }

    pub fn get_function(&self, addr: u64) -> Option<&str> {
        self.functions.get(&addr).map(String::as_str)
    }

    #[must_use]
    pub fn get_xrefs_from(&self, addr: u64) -> Vec<u64> {
        self.xrefs.get(&addr).cloned().unwrap_or_default()
    }

    #[must_use]
    pub fn get_xrefs_to(&self, addr: u64) -> Vec<u64> {
        self.xrefs_to.get(&addr).cloned().unwrap_or_default()
    }

    pub fn set_comment(&mut self, addr: u64, comment: &str) {
        self.comments.insert(addr, comment.to_string());
    }

    #[must_use]
    pub fn get_bytes(&self, addr: u64, len: usize) -> Vec<u8> {
        let off = sat_u64_to_usize(addr);
        if off >= self.data.len() {
            return Vec::new();
        }
        let end = (off + len).min(self.data.len());
        self.data[off..end].to_vec()
    }

    #[must_use]
    pub fn search_bytes(&self, pattern: &[u8]) -> Vec<u64> {
        let mut hits = Vec::new();
        if pattern.is_empty() {
            return hits;
        }
        let n = pattern.len();
        for i in 0..self.data.len().saturating_sub(n - 1) {
            if &self.data[i..i + n] == pattern {
                hits.push(i as u64);
            }
        }
        hits
    }

    #[must_use]
    pub fn get_all_strings(&self) -> Vec<(u64, String)> {
        let mut v: Vec<(u64, String)> = self.strings.iter().map(|(&k, v)| (k, v.clone())).collect();
        v.sort_by_key(|(k, _)| *k);
        v
    }
}

// ─── RhaiRustreModule ─────────────────────────────────────────────────────────

/// Registers all `RustRE` analysis functions into a Rhai module.
pub struct RhaiRustreModule {
    backend: Arc<Mutex<AnalysisBackend>>,
}

impl RhaiRustreModule {
    #[must_use]
    pub fn new(backend: AnalysisBackend) -> Self {
        Self {
            backend: Arc::new(Mutex::new(backend)),
        }
    }

    #[must_use]
    pub fn backend(&self) -> Arc<Mutex<AnalysisBackend>> {
        Arc::clone(&self.backend)
    }

    /// Register all functions into the given Rhai [`Engine`].
    ///
    /// # Panics
    /// Panics if the internal backend mutex is poisoned.
    pub fn register_into(&self, engine: &mut Engine) {
        let b = Arc::clone(&self.backend);
        self.register_query_fns(engine, &b);
        self.register_write_fns(engine, &b);
        self.register_info_fns(engine, &b);
    }

    fn register_query_fns(&self, engine: &mut Engine, b: &Arc<Mutex<AnalysisBackend>>) {
        let _ = self;
        // rhai_get_function(ea: i64) -> String
        engine.register_fn("get_function", {
            let b = Arc::clone(b);
            move |ea: i64| -> String {
                b.lock().unwrap().get_function(ea.cast_unsigned()).unwrap_or("<unknown>").to_string()
            }
        });
        // rhai_get_xrefs(ea: i64) -> Array of i64
        engine.register_fn("get_xrefs", {
            let b = Arc::clone(b);
            move |ea: i64| -> Array {
                b.lock().unwrap().get_xrefs_from(ea.cast_unsigned())
                    .into_iter().map(|a| Dynamic::from(a.cast_signed())).collect()
            }
        });
        // rhai_get_xrefs_to(ea: i64) -> Array of i64
        engine.register_fn("get_xrefs_to", {
            let b = Arc::clone(b);
            move |ea: i64| -> Array {
                b.lock().unwrap().get_xrefs_to(ea.cast_unsigned())
                    .into_iter().map(|a| Dynamic::from(a.cast_signed())).collect()
            }
        });
        // rhai_get_bytes(ea: i64, len: i64) -> Array of i64
        engine.register_fn("get_bytes", {
            let b = Arc::clone(b);
            move |ea: i64, len: i64| -> Array {
                b.lock().unwrap().get_bytes(ea.cast_unsigned(), sat_i64_to_usize(len.max(0)))
                    .into_iter().map(|byte| Dynamic::from(i64::from(byte))).collect()
            }
        });
        // rhai_search_bytes(pattern_hex: String) -> Array of i64
        engine.register_fn("search_bytes", {
            let b = Arc::clone(b);
            move |pattern_hex: String| -> Array {
                let pattern = hex_decode(&pattern_hex);
                b.lock().unwrap().search_bytes(&pattern)
                    .into_iter().map(|a| Dynamic::from(a.cast_signed())).collect()
            }
        });
    }

    fn register_write_fns(&self, engine: &mut Engine, b: &Arc<Mutex<AnalysisBackend>>) {
        let _ = self;
        // rhai_set_comment(ea: i64, comment: String)
        engine.register_fn("set_comment", {
            let b = Arc::clone(b);
            move |ea: i64, comment: String| {
                b.lock().unwrap().set_comment(ea.cast_unsigned(), &comment);
            }
        });
        // has_function(ea: i64) -> bool
        engine.register_fn("has_function", {
            let b = Arc::clone(b);
            move |ea: i64| -> bool {
                b.lock().unwrap().functions.contains_key(&(ea.cast_unsigned()))
            }
        });
        // function_count() -> i64
        engine.register_fn("function_count", {
            let b = Arc::clone(b);
            move || -> i64 { sat_usize_to_i64(b.lock().unwrap().functions.len()) }
        });
        // get_data_size() -> i64
        engine.register_fn("data_size", {
            let b = Arc::clone(b);
            move || -> i64 { sat_usize_to_i64(b.lock().unwrap().data.len()) }
        });
    }

    fn register_info_fns(&self, engine: &mut Engine, b: &Arc<Mutex<AnalysisBackend>>) {
        let _ = self;
        // rhai_get_strings() -> Array of Maps
        engine.register_fn("get_strings", {
            let b = Arc::clone(b);
            move || -> Array {
                b.lock().unwrap().get_all_strings().into_iter()
                    .map(|(addr, s)| {
                        let mut map = rhai::Map::new();
                        map.insert("address".into(), Dynamic::from(addr.cast_signed()));
                        map.insert("value".into(), Dynamic::from(s));
                        Dynamic::from(map)
                    })
                    .collect()
            }
        });
        // list_functions() -> Array of Maps
        engine.register_fn("list_functions", {
            let b = Arc::clone(b);
            move || -> Array {
                let mut funcs: Vec<(u64, String)> = {
                    let bk = b.lock().unwrap();
                    bk.functions.iter().map(|(&k, v)| (k, v.clone())).collect()
                };
                funcs.sort_by_key(|(k, _)| *k);
                funcs.into_iter().map(|(addr, name)| {
                    let mut map = rhai::Map::new();
                    map.insert("address".into(), Dynamic::from(addr.cast_signed()));
                    map.insert("name".into(), Dynamic::from(name));
                    Dynamic::from(map)
                }).collect()
            }
        });
        // get_comment(ea: i64) -> String
        engine.register_fn("get_comment", {
            let b = Arc::clone(b);
            move |ea: i64| -> String {
                b.lock().unwrap().comments.get(&(ea.cast_unsigned())).cloned().unwrap_or_default()
            }
        });
    }

    /// Build a standalone Module for use with `import`.
    ///
    /// # Panics
    /// Panics if the internal backend mutex is poisoned.
    #[must_use]
    pub fn build_module(&self) -> Module {
        let mut m = Module::new();
        let b = Arc::clone(&self.backend);

        let b1 = Arc::clone(&b);
        m.set_native_fn(
            "get_function",
            move |ea: i64| -> Result<String, Box<EvalAltResult>> {
                Ok(b1
                    .lock()
                    .unwrap()
                    .get_function(ea.cast_unsigned())
                    .unwrap_or("<unknown>")
                    .to_string())
            },
        );

        let b2 = Arc::clone(&b);
        m.set_native_fn(
            "get_xrefs",
            move |ea: i64| -> Result<Array, Box<EvalAltResult>> {
                Ok(b2
                    .lock()
                    .unwrap()
                    .get_xrefs_from(ea.cast_unsigned())
                    .into_iter()
                    .map(|a| Dynamic::from(a.cast_signed()))
                    .collect())
            },
        );

        let b3 = Arc::clone(&b);
        m.set_native_fn(
            "get_bytes",
            move |ea: i64, len: i64| -> Result<Array, Box<EvalAltResult>> {
                Ok(b3
                    .lock()
                    .unwrap()
                    .get_bytes(ea.cast_unsigned(), sat_i64_to_usize(len.max(0)))
                    .into_iter()
                    .map(|byte| Dynamic::from(i64::from(byte)))
                    .collect())
            },
        );

        m
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Decode a hex string to bytes (e.g. "DEADBEEF" → [0xDE, 0xAD, 0xBE, 0xEF]).
#[must_use]
pub fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.replace(' ', "").replace("0x", "").replace("0X", "");
    (0..s.len())
        .step_by(2)
        .filter_map(|i| {
            if i + 2 <= s.len() {
                u8::from_str_radix(&s[i..i + 2], 16).ok()
            } else {
                None
            }
        })
        .collect()
}

/// Format bytes as a hex string.
#[must_use]
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| { use std::fmt::Write; let _ = write!(acc, "{b:02x}"); acc })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_backend() -> AnalysisBackend {
        let mut b = AnalysisBackend::new().with_data(vec![
            0x55, 0x48, 0x89, 0xE5, 0x90, 0x5D, 0xC3, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00,
            0x00, 0x00,
        ]);
        b.add_function(0, "main");
        b.add_function(4, "helper");
        b.add_xref(0, 4);
        b.add_xref(0, 8);
        b.add_string(0, "Hello, World!");
        b.add_string(8, "Test string");
        b.set_comment(0, "Entry point");
        b
    }

    fn make_engine() -> (Engine, RhaiRustreModule) {
        let mut engine = Engine::new();
        let m = RhaiRustreModule::new(make_backend());
        m.register_into(&mut engine);
        (engine, m)
    }

    #[test]
    fn test_get_function_known() {
        let (engine, _m) = make_engine();
        let result: String = engine.eval("get_function(0)").unwrap();
        assert_eq!(result, "main");
    }

    #[test]
    fn test_get_function_unknown() {
        let (engine, _m) = make_engine();
        let result: String = engine.eval("get_function(99999)").unwrap();
        assert_eq!(result, "<unknown>");
    }

    #[test]
    fn test_get_xrefs_from() {
        let (engine, _m) = make_engine();
        let result: Array = engine.eval("get_xrefs(0)").unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_get_xrefs_to() {
        let (engine, _m) = make_engine();
        let result: Array = engine.eval("get_xrefs_to(4)").unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_set_and_get_comment() {
        let (engine, _m) = make_engine();
        engine
            .eval::<()>(r#"set_comment(0x100, "test comment")"#)
            .unwrap();
        let result: String = engine.eval("get_comment(0x100)").unwrap();
        assert_eq!(result, "test comment");
    }

    #[test]
    fn test_get_bytes() {
        let (engine, _m) = make_engine();
        let result: Array = engine.eval("get_bytes(0, 4)").unwrap();
        assert_eq!(result.len(), 4);
        assert_eq!(result[0].clone().cast::<i64>(), 0x55);
    }

    #[test]
    fn test_get_bytes_zero_len() {
        let (engine, _m) = make_engine();
        let result: Array = engine.eval("get_bytes(0, 0)").unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_search_bytes_found() {
        let (engine, _m) = make_engine();
        let result: Array = engine.eval(r#"search_bytes("DEADBEEF")"#).unwrap();
        assert!(!result.is_empty());
        assert_eq!(result[0].clone().cast::<i64>(), 8);
    }

    #[test]
    fn test_search_bytes_not_found() {
        let (engine, _m) = make_engine();
        let result: Array = engine.eval(r#"search_bytes("AABBCCDD")"#).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_get_strings() {
        let (engine, _m) = make_engine();
        let result: Array = engine.eval("get_strings()").unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_has_function_true() {
        let (engine, _m) = make_engine();
        let result: bool = engine.eval("has_function(0)").unwrap();
        assert!(result);
    }

    #[test]
    fn test_has_function_false() {
        let (engine, _m) = make_engine();
        let result: bool = engine.eval("has_function(99)").unwrap();
        assert!(!result);
    }

    #[test]
    fn test_function_count() {
        let (engine, _m) = make_engine();
        let count: i64 = engine.eval("function_count()").unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_list_functions() {
        let (engine, _m) = make_engine();
        let result: Array = engine.eval("list_functions()").unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_data_size() {
        let (engine, _m) = make_engine();
        let size: i64 = engine.eval("data_size()").unwrap();
        assert_eq!(size, 16);
    }

    #[test]
    fn test_hex_decode_basic() {
        let bytes = hex_decode("DEADBEEF");
        assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_hex_decode_with_spaces() {
        let bytes = hex_decode("DE AD BE EF");
        assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_hex_decode_empty() {
        let bytes = hex_decode("");
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_hex_encode() {
        let s = hex_encode(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(s, "deadbeef");
    }

    #[test]
    fn test_rhai_value_bool_to_dynamic() {
        let v = RhaiValue::Bool(true);
        let d = v.to_dynamic();
        assert!(d.as_bool().unwrap());
    }

    #[test]
    fn test_rhai_value_int_to_dynamic() {
        let v = RhaiValue::Int(42);
        let d = v.to_dynamic();
        assert_eq!(d.as_int().unwrap(), 42);
    }

    #[test]
    fn test_rhai_value_string_to_dynamic() {
        let v = RhaiValue::String("hello".into());
        let d = v.to_dynamic();
        assert_eq!(d.to_string(), "hello");
    }

    #[test]
    fn test_rhai_value_from_dynamic_int() {
        let d = Dynamic::from(99i64);
        let v = RhaiValue::from_dynamic(&d);
        assert!(matches!(v, RhaiValue::Int(99)));
    }

    #[test]
    fn test_backend_search_bytes() {
        let b = make_backend();
        let hits = b.search_bytes(&[0x55, 0x48]);
        assert_eq!(hits, vec![0]);
    }

    #[test]
    fn test_backend_get_all_strings_sorted() {
        let b = make_backend();
        let strings = b.get_all_strings();
        assert!(strings.windows(2).all(|w| w[0].0 <= w[1].0));
    }

    #[test]
    fn test_build_module() {
        let b = make_backend();
        let m = RhaiRustreModule::new(b);
        let module = m.build_module();
        assert!(!module.is_empty());
    }

    #[test]
    fn test_rhai_inline_script() {
        let (engine, _m) = make_engine();
        let script = r#"
            let f = get_function(0);
            let refs = get_xrefs(0);
            f + " " + refs.len().to_string()
        "#;
        let result: String = engine.eval(script).unwrap();
        assert!(result.contains("main"));
    }

    #[test]
    fn test_get_bytes_out_of_bounds() {
        let (engine, _m) = make_engine();
        // requesting bytes beyond data returns what's available
        let result: Array = engine.eval("get_bytes(100, 10)").unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_search_bytes_empty_pattern() {
        let (engine, _m) = make_engine();
        let result: Array = engine.eval(r#"search_bytes("")"#).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_get_strings_contains_hello() {
        let (engine, _m) = make_engine();
        let result: Array = engine.eval("get_strings()").unwrap();
        let values: Vec<String> = result
            .iter()
            .map(|m| {
                m.clone()
                    .try_cast::<rhai::Map>()
                    .and_then(|map| map.get("value").cloned())
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            })
            .collect();
        assert!(values.iter().any(|v| v.contains("Hello")));
    }

    #[test]
    fn test_rhai_value_bytes_to_dynamic() {
        let v = RhaiValue::Bytes(vec![0xDE, 0xAD]);
        let d = v.to_dynamic();
        // Should be an array
        assert!(d.is_array());
    }

    #[test]
    fn test_rhai_value_null_to_dynamic() {
        let v = RhaiValue::Null;
        let d = v.to_dynamic();
        assert!(d.is_unit());
    }

    #[test]
    fn test_rhai_value_array_to_dynamic() {
        let v = RhaiValue::Array(vec![RhaiValue::Int(1), RhaiValue::Int(2)]);
        let d = v.to_dynamic();
        assert!(d.is_array());
    }

    #[test]
    fn test_hex_decode_with_prefix() {
        let bytes = hex_decode("0xDEAD");
        assert_eq!(bytes, vec![0xDE, 0xAD]);
    }

    #[test]
    fn test_hex_encode_empty() {
        let s = hex_encode(&[]);
        assert_eq!(s, "");
    }

    #[test]
    fn test_backend_xrefs_to_empty() {
        let b = make_backend();
        let refs = b.get_xrefs_to(9999);
        assert!(refs.is_empty());
    }

    #[test]
    fn test_backend_get_bytes_partial() {
        let b = make_backend();
        // Request more bytes than available
        let bytes = b.get_bytes(14, 10);
        assert_eq!(bytes.len(), 2); // only 2 bytes left from offset 14 in 16-byte data
    }

    #[test]
    fn test_backend_search_bytes_multiple_hits() {
        let b = AnalysisBackend::new().with_data(vec![0xAA, 0xBB, 0xAA, 0xBB, 0xCC]);
        let hits = b.search_bytes(&[0xAA, 0xBB]);
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn test_backend_set_comment_overwrite() {
        let mut b = make_backend();
        b.set_comment(0, "first");
        b.set_comment(0, "second");
        assert_eq!(b.comments.get(&0).unwrap(), "second");
    }

    #[test]
    fn test_backend_add_function_adds_symbol() {
        let mut b = AnalysisBackend::new();
        b.add_function(0x1000, "my_func");
        assert!(b.symbols.contains_key(&0x1000));
    }

    #[test]
    fn test_backend_xref_bidirectional() {
        let mut b = AnalysisBackend::new();
        b.add_xref(0x100, 0x200);
        assert_eq!(b.get_xrefs_from(0x100), vec![0x200]);
        assert_eq!(b.get_xrefs_to(0x200), vec![0x100]);
    }

    #[test]
    fn test_rhai_value_float_to_dynamic() {
        let v = RhaiValue::Float(3.14_f64);
        let d = v.to_dynamic();
        assert!(d.is_float());
    }

    #[test]
    fn test_rhai_value_from_dynamic_bool() {
        let d = Dynamic::from(true);
        let v = RhaiValue::from_dynamic(&d);
        assert!(matches!(v, RhaiValue::Bool(true)));
    }

    #[test]
    fn test_backend_no_xrefs_initially() {
        let b = AnalysisBackend::new();
        assert!(b.get_xrefs_from(0).is_empty());
        assert!(b.get_xrefs_to(0).is_empty());
    }

    #[test]
    fn test_backend_get_function_not_found() {
        let b = AnalysisBackend::new();
        assert!(b.get_function(0xDEAD).is_none());
    }

    #[test]
    fn test_hex_decode_odd_length_ignores_last() {
        // Odd-length hex strings: last nibble is dropped
        let bytes = hex_decode("ABC");
        assert_eq!(bytes, vec![0xAB]);
    }

    #[test]
    fn test_rhai_module_has_functions() {
        let b = make_backend();
        let m = RhaiRustreModule::new(b);
        let module = m.build_module();
        // Module should have at least 3 registered functions
        assert!(!module.is_empty());
    }
}
