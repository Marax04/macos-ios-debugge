//! `rustre-script` — API bindings
//!
//! Exposes every capability of the RustRE core as a callable `ScriptValue`-based
//! function.  Each subsystem (BinaryView, FunctionTable, SymbolTable, XrefEngine,
//! PatchSet, TypeSystem, Decompiler, Debugger, MemoryProvider) is represented by
//! a `ScriptModule` that can be loaded into any `ScriptContext`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use crate::{native_fn, ScriptError, ScriptModule, ScriptValue};

// ── shared state stubs ──────────────────────────────────────────────────────
//
// In a real integration these would hold `Arc<dyn ...>` handles to the actual
// engine components.  Here they are lightweight in-memory representations that
// demonstrate the full binding surface without pulling in crate dependencies
// that may not be available in every build configuration.

/// Represents an open binary image (stub).
#[derive(Debug, Default)]
pub struct BinaryViewState {
    pub path: String,
    pub is_open: bool,
    pub is_analyzed: bool,
    pub base_address: u64,
    pub size: u64,
}

/// Entry in the function table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionEntry {
    pub address: u64,
    pub name: String,
    pub type_signature: String,
    pub is_analyzed: bool,
}

/// A symbol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolEntry {
    pub address: u64,
    pub name: String,
    pub kind: String, // "function", "data", "import", "export"
}

/// A cross-reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefEntry {
    pub from: u64,
    pub to: u64,
    pub kind: String, // "call", "data", "branch"
}

/// A patch record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchRecord {
    pub address: u64,
    pub original: Vec<u8>,
    pub patched: Vec<u8>,
    pub description: String,
    pub applied: bool,
}

/// A type definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDef {
    pub name: String,
    pub kind: String, // "struct", "enum", "typedef"
    pub body: String, // C-like definition
}

/// Shared in-memory state backing all API modules.
#[derive(Debug, Default)]
pub struct ApiState {
    pub view: BinaryViewState,
    pub functions: Vec<FunctionEntry>,
    pub symbols: Vec<SymbolEntry>,
    pub xrefs: Vec<XrefEntry>,
    pub patches: Vec<PatchRecord>,
    pub types: HashMap<String, TypeDef>,
    /// Debugger-like register file.
    pub registers: HashMap<String, u64>,
    /// Simulated memory regions: (start, data).
    pub memory_regions: Vec<(u64, Vec<u8>)>,
    /// Decompiler cache: address → pseudo-C.
    pub decompiler_cache: HashMap<u64, String>,
    /// Decompiler options.
    pub decompiler_options: HashMap<String, String>,
    /// Debugger attach status.
    pub debugger_attached: bool,
    pub debugger_pid: u32,
    /// Breakpoints.
    pub breakpoints: Vec<u64>,
}

/// Thread-safe wrapper around `ApiState`.
pub type SharedApiState = Arc<Mutex<ApiState>>;

/// Create a new, empty shared API state.
#[must_use]
pub fn new_state() -> SharedApiState {
    Arc::new(Mutex::new(ApiState::default()))
}

// ── Helper ──────────────────────────────────────────────────────────────────

fn lock_state(state: &SharedApiState) -> Result<std::sync::MutexGuard<'_, ApiState>, ScriptError> {
    state
        .lock()
        .map_err(|e| ScriptError::RuntimeError(format!("state lock poisoned: {e}")))
}

fn require_arg<'a>(args: &'a [ScriptValue], idx: usize, fn_name: &str) -> Result<&'a ScriptValue, ScriptError> {
    args.get(idx).ok_or_else(|| ScriptError::ArityMismatch {
        name: fn_name.into(),
        expected: idx + 1,
        got: args.len(),
    })
}

fn require_str<'a>(v: &'a ScriptValue, fn_name: &str) -> Result<&'a str, ScriptError> {
    v.as_str().map_err(|_| ScriptError::TypeMismatch {
        expected: "string".into(),
        got: format!("{} (in {})", v.type_name(), fn_name),
    })
}

fn require_addr(v: &ScriptValue, fn_name: &str) -> Result<u64, ScriptError> {
    v.as_address().map_err(|_| ScriptError::TypeMismatch {
        expected: "address or int".into(),
        got: format!("{} (in {})", v.type_name(), fn_name),
    })
}

fn entry_to_map<T: Serialize>(entry: &T) -> ScriptValue {
    let json = serde_json::to_value(entry).unwrap_or_default();
    ScriptValue::from_json(json)
}

// ── BinaryView module ────────────────────────────────────────────────────────

/// Build the `binary_view` module.
///
/// Exposed functions:
/// - `binary_view.open(path: string) -> string`
/// - `binary_view.close() -> null`
/// - `binary_view.analyze() -> string`
/// - `binary_view.info() -> map`
/// - `binary_view.is_open() -> bool`
/// - `binary_view.base_address() -> address`
/// - `binary_view.size() -> int`
#[must_use]
pub fn binary_view_module(state: SharedApiState) -> ScriptModule {
    let mut m = ScriptModule::new("binary_view");

    // open
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "open",
            native_fn(move |args| {
                let path = require_str(require_arg(args, 0, "binary_view.open")?, "binary_view.open")?;
                let mut st = lock_state(&s)?;
                if st.view.is_open {
                    return Err(ScriptError::RuntimeError(format!(
                        "binary_view.open: a binary is already open ({})",
                        st.view.path
                    )));
                }
                st.view.path = path.to_owned();
                st.view.is_open = true;
                st.view.is_analyzed = false;
                st.view.base_address = 0x0040_0000;
                st.view.size = 0; // unknown until analyzed
                Ok(ScriptValue::String(format!("opened: {path}")))
            }),
        );
    }

    // close
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "close",
            native_fn(move |_args| {
                let mut st = lock_state(&s)?;
                if !st.view.is_open {
                    return Err(ScriptError::RuntimeError(
                        "binary_view.close: no binary is open".into(),
                    ));
                }
                st.view = BinaryViewState::default();
                st.functions.clear();
                st.symbols.clear();
                st.xrefs.clear();
                Ok(ScriptValue::Null)
            }),
        );
    }

    // analyze
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "analyze",
            native_fn(move |_args| {
                let mut st = lock_state(&s)?;
                if !st.view.is_open {
                    return Err(ScriptError::RuntimeError(
                        "binary_view.analyze: no binary is open".into(),
                    ));
                }
                st.view.is_analyzed = true;
                st.view.size = 0x0010_0000; // stub: 1 MiB
                Ok(ScriptValue::String(format!(
                    "analysis complete: {}",
                    st.view.path
                )))
            }),
        );
    }

    // info
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "info",
            native_fn(move |_args| {
                let st = lock_state(&s)?;
                let mut map = HashMap::new();
                map.insert("path".into(), ScriptValue::String(st.view.path.clone()));
                map.insert("is_open".into(), ScriptValue::Bool(st.view.is_open));
                map.insert("is_analyzed".into(), ScriptValue::Bool(st.view.is_analyzed));
                map.insert("base_address".into(), ScriptValue::Address(st.view.base_address));
                map.insert("size".into(), ScriptValue::Int(i64::try_from(st.view.size).map_err(|_| ScriptError::TypeMismatch { expected: "size within i64 range".into(), got: "u64 too large".into() })?));
                Ok(ScriptValue::Map(map))
            }),
        );
    }

    // is_open
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "is_open",
            native_fn(move |_args| {
                let st = lock_state(&s)?;
                Ok(ScriptValue::Bool(st.view.is_open))
            }),
        );
    }

    // base_address
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "base_address",
            native_fn(move |_args| {
                let st = lock_state(&s)?;
                Ok(ScriptValue::Address(st.view.base_address))
            }),
        );
    }

    // size
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "size",
            native_fn(move |_args| {
                let st = lock_state(&s)?;
                Ok(ScriptValue::Int(i64::try_from(st.view.size).map_err(|_| ScriptError::TypeMismatch { expected: "size within i64 range".into(), got: "u64 too large".into() })?))
            }),
        );
    }

    m
}

// ── FunctionTable module ─────────────────────────────────────────────────────

/// Build the `function_table` module.
///
/// Exposed functions:
/// - `function_table.list() -> list[map]`
/// - `function_table.get(address) -> map | null`
/// - `function_table.rename(address, new_name) -> bool`
/// - `function_table.set_type(address, type_sig) -> bool`
/// - `function_table.add(address, name) -> bool`
/// - `function_table.count() -> int`
#[must_use]
pub fn function_table_module(state: SharedApiState) -> ScriptModule {
    let mut m = ScriptModule::new("function_table");

    // list
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "list",
            native_fn(move |_args| {
                let st = lock_state(&s)?;
                let items: Vec<ScriptValue> = st.functions.iter().map(entry_to_map).collect();
                Ok(ScriptValue::List(items))
            }),
        );
    }

    // get(address)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "get",
            native_fn(move |args| {
                let addr = require_addr(require_arg(args, 0, "function_table.get")?, "function_table.get")?;
                let st = lock_state(&s)?;
                let entry = st.functions.iter().find(|f| f.address == addr);
                Ok(entry.map_or(ScriptValue::Null, entry_to_map))
            }),
        );
    }

    // rename(address, new_name)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "rename",
            native_fn(move |args| {
                let addr = require_addr(require_arg(args, 0, "function_table.rename")?, "function_table.rename")?;
                let name = require_str(require_arg(args, 1, "function_table.rename")?, "function_table.rename")?.to_owned();
                let mut st = lock_state(&s)?;
                if let Some(f) = st.functions.iter_mut().find(|f| f.address == addr) {
                    f.name = name;
                    return Ok(ScriptValue::Bool(true));
                }
                Ok(ScriptValue::Bool(false))
            }),
        );
    }

    // set_type(address, type_sig)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "set_type",
            native_fn(move |args| {
                let addr = require_addr(require_arg(args, 0, "function_table.set_type")?, "function_table.set_type")?;
                let sig = require_str(require_arg(args, 1, "function_table.set_type")?, "function_table.set_type")?.to_owned();
                let mut st = lock_state(&s)?;
                if let Some(f) = st.functions.iter_mut().find(|f| f.address == addr) {
                    f.type_signature = sig;
                    return Ok(ScriptValue::Bool(true));
                }
                Ok(ScriptValue::Bool(false))
            }),
        );
    }

    // add(address, name)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "add",
            native_fn(move |args| {
                let addr = require_addr(require_arg(args, 0, "function_table.add")?, "function_table.add")?;
                let name = require_str(require_arg(args, 1, "function_table.add")?, "function_table.add")?.to_owned();
                let mut st = lock_state(&s)?;
                if st.functions.iter().any(|f| f.address == addr) {
                    return Ok(ScriptValue::Bool(false)); // already exists
                }
                st.functions.push(FunctionEntry {
                    address: addr,
                    name,
                    type_signature: String::new(),
                    is_analyzed: false,
                });
                Ok(ScriptValue::Bool(true))
            }),
        );
    }

    // count()
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "count",
            native_fn(move |_args| {
                let st = lock_state(&s)?;
                Ok(ScriptValue::Int(i64::try_from(st.functions.len()).map_err(|_| ScriptError::TypeMismatch { expected: "count within i64 range".into(), got: "usize too large".into() })?))
            }),
        );
    }

    m
}

// ── SymbolTable module ───────────────────────────────────────────────────────

/// Build the `symbol_table` module.
///
/// Exposed functions:
/// - `symbol_table.lookup(name) -> map | null`
/// - `symbol_table.lookup_addr(address) -> map | null`
/// - `symbol_table.add(address, name, kind) -> bool`
/// - `symbol_table.remove(address) -> bool`
/// - `symbol_table.list() -> list[map]`
/// - `symbol_table.search(pattern) -> list[map]`
#[must_use]
pub fn symbol_table_module(state: SharedApiState) -> ScriptModule {
    let mut m = ScriptModule::new("symbol_table");

    // lookup(name)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "lookup",
            native_fn(move |args| {
                let name = require_str(require_arg(args, 0, "symbol_table.lookup")?, "symbol_table.lookup")?;
                let st = lock_state(&s)?;
                let sym = st.symbols.iter().find(|s| s.name == name);
                Ok(sym.map_or(ScriptValue::Null, entry_to_map))
            }),
        );
    }

    // lookup_addr(address)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "lookup_addr",
            native_fn(move |args| {
                let addr = require_addr(require_arg(args, 0, "symbol_table.lookup_addr")?, "symbol_table.lookup_addr")?;
                let st = lock_state(&s)?;
                let sym = st.symbols.iter().find(|s| s.address == addr);
                Ok(sym.map_or(ScriptValue::Null, entry_to_map))
            }),
        );
    }

    // add(address, name, kind)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "add",
            native_fn(move |args| {
                let addr = require_addr(require_arg(args, 0, "symbol_table.add")?, "symbol_table.add")?;
                let name = require_str(require_arg(args, 1, "symbol_table.add")?, "symbol_table.add")?.to_owned();
                let kind = args.get(2).and_then(|v| v.as_str().ok().map(str::to_owned)).unwrap_or_else(|| "function".into());
                let mut st = lock_state(&s)?;
                st.symbols.retain(|s| s.address != addr);
                st.symbols.push(SymbolEntry { address: addr, name, kind });
                Ok(ScriptValue::Bool(true))
            }),
        );
    }

    // remove(address)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "remove",
            native_fn(move |args| {
                let addr = require_addr(require_arg(args, 0, "symbol_table.remove")?, "symbol_table.remove")?;
                let mut st = lock_state(&s)?;
                let before = st.symbols.len();
                st.symbols.retain(|s| s.address != addr);
                Ok(ScriptValue::Bool(st.symbols.len() < before))
            }),
        );
    }

    // list()
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "list",
            native_fn(move |_args| {
                let st = lock_state(&s)?;
                let items: Vec<ScriptValue> = st.symbols.iter().map(entry_to_map).collect();
                Ok(ScriptValue::List(items))
            }),
        );
    }

    // search(pattern) — substring match on name
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "search",
            native_fn(move |args| {
                let pat = require_str(require_arg(args, 0, "symbol_table.search")?, "symbol_table.search")?;
                let st = lock_state(&s)?;
                let items: Vec<ScriptValue> = st
                    .symbols
                    .iter()
                    .filter(|s| s.name.contains(pat))
                    .map(entry_to_map)
                    .collect();
                Ok(ScriptValue::List(items))
            }),
        );
    }

    m
}

// ── XrefEngine module ────────────────────────────────────────────────────────

/// Build the `xref_engine` module.
///
/// Exposed functions:
/// - `xref_engine.query_forward(from_addr) -> list[map]`
/// - `xref_engine.query_backward(to_addr) -> list[map]`
/// - `xref_engine.add(from, to, kind) -> null`
/// - `xref_engine.remove(from, to) -> bool`
/// - `xref_engine.all() -> list[map]`
#[must_use]
pub fn xref_engine_module(state: SharedApiState) -> ScriptModule {
    let mut m = ScriptModule::new("xref_engine");

    // query_forward(from)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "query_forward",
            native_fn(move |args| {
                let from = require_addr(require_arg(args, 0, "xref_engine.query_forward")?, "xref_engine.query_forward")?;
                let st = lock_state(&s)?;
                let items: Vec<ScriptValue> = st
                    .xrefs
                    .iter()
                    .filter(|x| x.from == from)
                    .map(entry_to_map)
                    .collect();
                Ok(ScriptValue::List(items))
            }),
        );
    }

    // query_backward(to)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "query_backward",
            native_fn(move |args| {
                let to = require_addr(require_arg(args, 0, "xref_engine.query_backward")?, "xref_engine.query_backward")?;
                let st = lock_state(&s)?;
                let items: Vec<ScriptValue> = st
                    .xrefs
                    .iter()
                    .filter(|x| x.to == to)
                    .map(entry_to_map)
                    .collect();
                Ok(ScriptValue::List(items))
            }),
        );
    }

    // add(from, to, kind)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "add",
            native_fn(move |args| {
                let from = require_addr(require_arg(args, 0, "xref_engine.add")?, "xref_engine.add")?;
                let to = require_addr(require_arg(args, 1, "xref_engine.add")?, "xref_engine.add")?;
                let kind = args.get(2).and_then(|v| v.as_str().ok().map(str::to_owned)).unwrap_or_else(|| "call".into());
                let mut st = lock_state(&s)?;
                st.xrefs.push(XrefEntry { from, to, kind });
                Ok(ScriptValue::Null)
            }),
        );
    }

    // remove(from, to)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "remove",
            native_fn(move |args| {
                let from = require_addr(require_arg(args, 0, "xref_engine.remove")?, "xref_engine.remove")?;
                let to = require_addr(require_arg(args, 1, "xref_engine.remove")?, "xref_engine.remove")?;
                let mut st = lock_state(&s)?;
                let before = st.xrefs.len();
                st.xrefs.retain(|x| !(x.from == from && x.to == to));
                Ok(ScriptValue::Bool(st.xrefs.len() < before))
            }),
        );
    }

    // all()
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "all",
            native_fn(move |_args| {
                let st = lock_state(&s)?;
                let items: Vec<ScriptValue> = st.xrefs.iter().map(entry_to_map).collect();
                Ok(ScriptValue::List(items))
            }),
        );
    }

    m
}

// ── PatchSet module ──────────────────────────────────────────────────────────

/// Build the `patch_set` module.
///
/// Exposed functions:
/// - `patch_set.apply(address, bytes_hex, description) -> bool`
/// - `patch_set.undo(address) -> bool`
/// - `patch_set.save(path) -> string`
/// - `patch_set.list() -> list[map]`
/// - `patch_set.clear() -> int`
#[must_use]
pub fn patch_set_module(state: SharedApiState) -> ScriptModule {
    let mut m = ScriptModule::new("patch_set");

    // apply(address, bytes_hex, description)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "apply",
            native_fn(move |args| {
                let addr = require_addr(require_arg(args, 0, "patch_set.apply")?, "patch_set.apply")?;
                let hex = require_str(require_arg(args, 1, "patch_set.apply")?, "patch_set.apply")?;
                let desc = args.get(2).and_then(|v| v.as_str().ok().map(str::to_owned)).unwrap_or_default();
                let hex_clean = hex.trim_start_matches("0x").trim_start_matches("0X");
                if hex_clean.len() % 2 != 0 {
                    return Err(ScriptError::RuntimeError("patch_set.apply: odd-length hex string".into()));
                }
                let patched: Result<Vec<u8>, _> = (0..hex_clean.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex_clean[i..i + 2], 16))
                    .collect();
                let patched = patched.map_err(|e| ScriptError::RuntimeError(format!("patch_set.apply: invalid hex: {e}")))?;
                let mut st = lock_state(&s)?;
                // Capture original bytes from memory if available.
                let original = st
                    .memory_regions
                    .iter()
                    .find_map(|(start, data)| {
                        let end = *start + data.len() as u64;
                        if addr >= *start && addr + patched.len() as u64 <= end {
                            let off = (addr - start) as usize;
                            Some(data[off..off + patched.len()].to_vec())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_else(|| vec![0u8; patched.len()]);
                st.patches.push(PatchRecord { address: addr, original, patched, description: desc, applied: true });
                Ok(ScriptValue::Bool(true))
            }),
        );
    }

    // undo(address)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "undo",
            native_fn(move |args| {
                let addr = require_addr(require_arg(args, 0, "patch_set.undo")?, "patch_set.undo")?;
                let mut st = lock_state(&s)?;
                if let Some(p) = st.patches.iter_mut().rev().find(|p| p.address == addr && p.applied) {
                    p.applied = false;
                    return Ok(ScriptValue::Bool(true));
                }
                Ok(ScriptValue::Bool(false))
            }),
        );
    }

    // save(path)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "save",
            native_fn(move |args| {
                let path = require_str(require_arg(args, 0, "patch_set.save")?, "patch_set.save")?;
                let st = lock_state(&s)?;
                let json = serde_json::to_string_pretty(&st.patches)
                    .map_err(|e| ScriptError::RuntimeError(format!("patch_set.save: {e}")))?;
                std::fs::write(path, json)
                    .map_err(|e| ScriptError::IoError(format!("patch_set.save: {e}")))?;
                Ok(ScriptValue::String(format!("saved {} patches to {path}", st.patches.len())))
            }),
        );
    }

    // list()
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "list",
            native_fn(move |_args| {
                let st = lock_state(&s)?;
                let items: Vec<ScriptValue> = st.patches.iter().map(entry_to_map).collect();
                Ok(ScriptValue::List(items))
            }),
        );
    }

    // clear()
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "clear",
            native_fn(move |_args| {
                let mut st = lock_state(&s)?;
                let n = st.patches.len();
                st.patches.clear();
                Ok(ScriptValue::Int(i64::try_from(n).map_err(|_| ScriptError::TypeMismatch { expected: "count within i64 range".into(), got: "usize too large".into() })?))
            }),
        );
    }

    m
}

// ── TypeSystem module ────────────────────────────────────────────────────────

/// Build the `type_system` module.
///
/// Exposed functions:
/// - `type_system.define_struct(name, body) -> bool`
/// - `type_system.define_enum(name, body) -> bool`
/// - `type_system.resolve(name) -> map | null`
/// - `type_system.list() -> list[map]`
/// - `type_system.remove(name) -> bool`
#[must_use]
pub fn type_system_module(state: SharedApiState) -> ScriptModule {
    let mut m = ScriptModule::new("type_system");

    // define_struct(name, body)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "define_struct",
            native_fn(move |args| {
                let name = require_str(require_arg(args, 0, "type_system.define_struct")?, "type_system.define_struct")?.to_owned();
                let body = require_str(require_arg(args, 1, "type_system.define_struct")?, "type_system.define_struct")?.to_owned();
                let mut st = lock_state(&s)?;
                st.types.insert(name.clone(), TypeDef { name, kind: "struct".into(), body });
                Ok(ScriptValue::Bool(true))
            }),
        );
    }

    // define_enum(name, body)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "define_enum",
            native_fn(move |args| {
                let name = require_str(require_arg(args, 0, "type_system.define_enum")?, "type_system.define_enum")?.to_owned();
                let body = require_str(require_arg(args, 1, "type_system.define_enum")?, "type_system.define_enum")?.to_owned();
                let mut st = lock_state(&s)?;
                st.types.insert(name.clone(), TypeDef { name, kind: "enum".into(), body });
                Ok(ScriptValue::Bool(true))
            }),
        );
    }

    // resolve(name)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "resolve",
            native_fn(move |args| {
                let name = require_str(require_arg(args, 0, "type_system.resolve")?, "type_system.resolve")?;
                let st = lock_state(&s)?;
                let td = st.types.get(name);
                Ok(td.map_or(ScriptValue::Null, entry_to_map))
            }),
        );
    }

    // list()
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "list",
            native_fn(move |_args| {
                let st = lock_state(&s)?;
                let items: Vec<ScriptValue> = st.types.values().map(entry_to_map).collect();
                Ok(ScriptValue::List(items))
            }),
        );
    }

    // remove(name)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "remove",
            native_fn(move |args| {
                let name = require_str(require_arg(args, 0, "type_system.remove")?, "type_system.remove")?;
                let mut st = lock_state(&s)?;
                Ok(ScriptValue::Bool(st.types.remove(name).is_some()))
            }),
        );
    }

    m
}

// ── Decompiler module ────────────────────────────────────────────────────────

/// Build the `decompiler` module.
///
/// Exposed functions:
/// - `decompiler.decompile_function(address) -> string`
/// - `decompiler.set_option(key, value) -> null`
/// - `decompiler.get_option(key) -> string | null`
/// - `decompiler.clear_cache() -> int`
#[must_use]
pub fn decompiler_module(state: SharedApiState) -> ScriptModule {
    let mut m = ScriptModule::new("decompiler");

    // decompile_function(address)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "decompile_function",
            native_fn(move |args| {
                let addr = require_addr(require_arg(args, 0, "decompiler.decompile_function")?, "decompiler.decompile_function")?;
                let mut st = lock_state(&s)?;
                if let Some(cached) = st.decompiler_cache.get(&addr) {
                    return Ok(ScriptValue::String(cached.clone()));
                }
                // Find the function by address and generate stub pseudo-C.
                let name = st
                    .functions
                    .iter()
                    .find(|f| f.address == addr)
                    .map(|f| f.name.clone())
                    .unwrap_or_else(|| format!("sub_{addr:x}"));
                let pseudo_c = format!(
                    "// Decompiled {name} @ 0x{addr:x}\nvoid {name}() {{\n    // TODO: decompile\n}}"
                );
                st.decompiler_cache.insert(addr, pseudo_c.clone());
                Ok(ScriptValue::String(pseudo_c))
            }),
        );
    }

    // set_option(key, value)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "set_option",
            native_fn(move |args| {
                let key = require_str(require_arg(args, 0, "decompiler.set_option")?, "decompiler.set_option")?.to_owned();
                let val = require_str(require_arg(args, 1, "decompiler.set_option")?, "decompiler.set_option")?.to_owned();
                let mut st = lock_state(&s)?;
                st.decompiler_options.insert(key, val);
                Ok(ScriptValue::Null)
            }),
        );
    }

    // get_option(key)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "get_option",
            native_fn(move |args| {
                let key = require_str(require_arg(args, 0, "decompiler.get_option")?, "decompiler.get_option")?;
                let st = lock_state(&s)?;
                Ok(st.decompiler_options.get(key).map_or(ScriptValue::Null, |v| ScriptValue::String(v.clone())))
            }),
        );
    }

    // clear_cache()
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "clear_cache",
            native_fn(move |_args| {
                let mut st = lock_state(&s)?;
                let n = st.decompiler_cache.len();
                st.decompiler_cache.clear();
                Ok(ScriptValue::Int(n as i64))
            }),
        );
    }

    m
}

// ── Debugger module ──────────────────────────────────────────────────────────

/// Build the `debugger` module.
///
/// Exposed functions:
/// - `debugger.attach(pid) -> bool`
/// - `debugger.detach() -> bool`
/// - `debugger.set_breakpoint(address) -> bool`
/// - `debugger.remove_breakpoint(address) -> bool`
/// - `debugger.breakpoints() -> list[address]`
/// - `debugger.run() -> string`
/// - `debugger.step() -> string`
/// - `debugger.read_register(name) -> int | null`
/// - `debugger.write_register(name, value) -> bool`
/// - `debugger.read_memory(address, length) -> bytes`
#[must_use]
pub fn debugger_module(state: SharedApiState) -> ScriptModule {
    let mut m = ScriptModule::new("debugger");

    // attach(pid)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "attach",
            native_fn(move |args| {
                let pid_v = require_arg(args, 0, "debugger.attach")?;
                let pid_i = pid_v.as_int()?;
                let pid = u32::try_from(pid_i).map_err(|_| ScriptError::TypeMismatch { expected: "valid PID (u32)".into(), got: format!("{pid_i}") })?;
                let mut st = lock_state(&s)?;
                if st.debugger_attached {
                    return Err(ScriptError::RuntimeError(format!(
                        "debugger.attach: already attached to PID {}",
                        st.debugger_pid
                    )));
                }
                st.debugger_attached = true;
                st.debugger_pid = pid;
                Ok(ScriptValue::Bool(true))
            }),
        );
    }

    // detach()
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "detach",
            native_fn(move |_args| {
                let mut st = lock_state(&s)?;
                if !st.debugger_attached {
                    return Ok(ScriptValue::Bool(false));
                }
                st.debugger_attached = false;
                st.debugger_pid = 0;
                Ok(ScriptValue::Bool(true))
            }),
        );
    }

    // set_breakpoint(address)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "set_breakpoint",
            native_fn(move |args| {
                let addr = require_addr(require_arg(args, 0, "debugger.set_breakpoint")?, "debugger.set_breakpoint")?;
                let mut st = lock_state(&s)?;
                if !st.breakpoints.contains(&addr) {
                    st.breakpoints.push(addr);
                }
                Ok(ScriptValue::Bool(true))
            }),
        );
    }

    // remove_breakpoint(address)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "remove_breakpoint",
            native_fn(move |args| {
                let addr = require_addr(require_arg(args, 0, "debugger.remove_breakpoint")?, "debugger.remove_breakpoint")?;
                let mut st = lock_state(&s)?;
                let before = st.breakpoints.len();
                st.breakpoints.retain(|&b| b != addr);
                Ok(ScriptValue::Bool(st.breakpoints.len() < before))
            }),
        );
    }

    // breakpoints()
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "breakpoints",
            native_fn(move |_args| {
                let st = lock_state(&s)?;
                let list: Vec<ScriptValue> = st.breakpoints.iter().copied().map(ScriptValue::Address).collect();
                Ok(ScriptValue::List(list))
            }),
        );
    }

    // run()
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "run",
            native_fn(move |_args| {
                let st = lock_state(&s)?;
                if !st.debugger_attached {
                    return Err(ScriptError::RuntimeError("debugger.run: not attached".into()));
                }
                Ok(ScriptValue::String(format!("process {} running", st.debugger_pid)))
            }),
        );
    }

    // step()
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "step",
            native_fn(move |_args| {
                let st = lock_state(&s)?;
                if !st.debugger_attached {
                    return Err(ScriptError::RuntimeError("debugger.step: not attached".into()));
                }
                let rip = *st.registers.get("rip").unwrap_or(&0);
                Ok(ScriptValue::String(format!("stepped to 0x{rip:x}")))
            }),
        );
    }

    // read_register(name)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "read_register",
            native_fn(move |args| {
                let name = require_str(require_arg(args, 0, "debugger.read_register")?, "debugger.read_register")?;
                let st = lock_state(&s)?;
                if !st.debugger_attached {
                    return Err(ScriptError::RuntimeError("debugger.read_register: not attached".into()));
                }
                Ok(st.registers.get(name).map_or(ScriptValue::Null, |&v| ScriptValue::Int(v as i64)))
            }),
        );
    }

    // write_register(name, value)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "write_register",
            native_fn(move |args| {
                let name = require_str(require_arg(args, 0, "debugger.write_register")?, "debugger.write_register")?.to_owned();
                let val = require_arg(args, 1, "debugger.write_register")?.as_int()? as u64;
                let mut st = lock_state(&s)?;
                if !st.debugger_attached {
                    return Err(ScriptError::RuntimeError("debugger.write_register: not attached".into()));
                }
                st.registers.insert(name, val);
                Ok(ScriptValue::Bool(true))
            }),
        );
    }

    // read_memory(address, length)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "read_memory",
            native_fn(move |args| {
                let addr = require_addr(require_arg(args, 0, "debugger.read_memory")?, "debugger.read_memory")?;
                let len_i = require_arg(args, 1, "debugger.read_memory")?.as_int()?;
                let len = usize::try_from(len_i).map_err(|_| ScriptError::TypeMismatch { expected: "non-negative length".into(), got: format!("{len_i}") })?;
                let st = lock_state(&s)?;
                if !st.debugger_attached {
                    return Err(ScriptError::RuntimeError("debugger.read_memory: not attached".into()));
                }
                for (start, data) in &st.memory_regions {
                    let end = *start + data.len() as u64;
                    if addr >= *start && addr + len as u64 <= end {
                        let off = (addr - start) as usize;
                        return Ok(ScriptValue::Bytes(data[off..off + len].to_vec()));
                    }
                }
                // Return zeroes if region not mapped.
                Ok(ScriptValue::Bytes(vec![0u8; len]))
            }),
        );
    }

    m
}

// ── MemoryProvider module ────────────────────────────────────────────────────

/// Build the `memory_provider` module.
///
/// Exposed functions:
/// - `memory_provider.read(address, length) -> bytes`
/// - `memory_provider.write(address, bytes_hex) -> bool`
/// - `memory_provider.regions() -> list[map]`
/// - `memory_provider.add_region(address, bytes_hex) -> bool`
/// - `memory_provider.remove_region(address) -> bool`
#[must_use]
pub fn memory_provider_module(state: SharedApiState) -> ScriptModule {
    let mut m = ScriptModule::new("memory_provider");

    // read(address, length)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "read",
            native_fn(move |args| {
                let addr = require_addr(require_arg(args, 0, "memory_provider.read")?, "memory_provider.read")?;
                let len_i = require_arg(args, 1, "memory_provider.read")?.as_int()?;
                let len = usize::try_from(len_i).map_err(|_| ScriptError::TypeMismatch { expected: "non-negative length".into(), got: format!("{len_i}") })?;
                let st = lock_state(&s)?;
                for (start, data) in &st.memory_regions {
                    let end = *start + data.len() as u64;
                    if addr >= *start && addr + len as u64 <= end {
                        let off = (addr - *start) as usize;
                        return Ok(ScriptValue::Bytes(data[off..off + len].to_vec()));
                    }
                }
                Err(ScriptError::RuntimeError(format!(
                    "memory_provider.read: address 0x{addr:x} not mapped"
                )))
            }),
        );
    }

    // write(address, bytes_hex)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "write",
            native_fn(move |args| {
                let addr = require_addr(require_arg(args, 0, "memory_provider.write")?, "memory_provider.write")?;
                let hex = require_str(require_arg(args, 1, "memory_provider.write")?, "memory_provider.write")?;
                let hex_clean = hex.trim_start_matches("0x").trim_start_matches("0X");
                if hex_clean.len() % 2 != 0 {
                    return Err(ScriptError::RuntimeError("memory_provider.write: odd-length hex".into()));
                }
                let bytes: Result<Vec<u8>, _> = (0..hex_clean.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex_clean[i..i + 2], 16))
                    .collect();
                let bytes = bytes.map_err(|e| ScriptError::RuntimeError(format!("memory_provider.write: {e}")))?;
                let mut st = lock_state(&s)?;
                for (start, data) in st.memory_regions.iter_mut() {
                    let end = *start + data.len() as u64;
                    if addr >= *start && addr + bytes.len() as u64 <= end {
                        let off = (addr - *start) as usize;
                        data[off..off + bytes.len()].copy_from_slice(&bytes);
                        return Ok(ScriptValue::Bool(true));
                    }
                }
                Err(ScriptError::RuntimeError(format!(
                    "memory_provider.write: address 0x{addr:x} not mapped"
                )))
            }),
        );
    }

    // regions()
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "regions",
            native_fn(move |_args| {
                let st = lock_state(&s)?;
                let items: Vec<ScriptValue> = st
                    .memory_regions
                    .iter()
                    .map(|(start, data)| {
                        let mut map = HashMap::new();
                        map.insert("start".into(), ScriptValue::Address(*start));
                        map.insert("size".into(), ScriptValue::Int(data.len() as i64));
                        map.insert("end".into(), ScriptValue::Address(start + data.len() as u64));
                        ScriptValue::Map(map)
                    })
                    .collect();
                Ok(ScriptValue::List(items))
            }),
        );
    }

    // add_region(address, bytes_hex)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "add_region",
            native_fn(move |args| {
                let addr = require_addr(require_arg(args, 0, "memory_provider.add_region")?, "memory_provider.add_region")?;
                let hex = require_str(require_arg(args, 1, "memory_provider.add_region")?, "memory_provider.add_region")?;
                let hex_clean = hex.trim_start_matches("0x").trim_start_matches("0X");
                if hex_clean.len() % 2 != 0 {
                    return Err(ScriptError::RuntimeError("memory_provider.add_region: odd-length hex".into()));
                }
                let bytes: Result<Vec<u8>, _> = (0..hex_clean.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex_clean[i..i + 2], 16))
                    .collect();
                let bytes = bytes.map_err(|e| ScriptError::RuntimeError(format!("memory_provider.add_region: {e}")))?;
                let mut st = lock_state(&s)?;
                st.memory_regions.push((addr, bytes));
                Ok(ScriptValue::Bool(true))
            }),
        );
    }

    // remove_region(address)
    {
        let s = Arc::clone(&state);
        m.add_fn(
            "remove_region",
            native_fn(move |args| {
                let addr = require_addr(require_arg(args, 0, "memory_provider.remove_region")?, "memory_provider.remove_region")?;
                let mut st = lock_state(&s)?;
                let before = st.memory_regions.len();
                st.memory_regions.retain(|(start, _)| *start != addr);
                Ok(ScriptValue::Bool(st.memory_regions.len() < before))
            }),
        );
    }

    m
}

// ── Public API: register all modules ─────────────────────────────────────────

/// Register every API module into a `ScriptContext`.
///
/// After calling this, the context will have the following module namespaces
/// available as top-level global maps containing callable functions:
/// `binary_view`, `function_table`, `symbol_table`, `xref_engine`,
/// `patch_set`, `type_system`, `decompiler`, `debugger`, `memory_provider`.
///
/// All modules share the same `SharedApiState` so they operate on a single
/// coherent view of the binary.
pub fn register_all_modules(
    ctx: &mut crate::ScriptContext,
    state: &SharedApiState,
) {
    for module in all_modules(state) {
        // Flatten each module's functions into global `module_name_fn_name` vars.
        // This approach works with any scripting backend without needing dot-access.
        let prefix = module.name.clone();
        for (fn_name, f) in &module.functions {
            let global_name = format!("{prefix}_{fn_name}");
            ctx.register_fn(global_name, Arc::clone(f));
        }
    }
}

/// Return all API modules backed by the given state.
#[must_use]
pub fn all_modules(state: &SharedApiState) -> Vec<ScriptModule> {
    vec![
        binary_view_module(Arc::clone(state)),
        function_table_module(Arc::clone(state)),
        symbol_table_module(Arc::clone(state)),
        xref_engine_module(Arc::clone(state)),
        patch_set_module(Arc::clone(state)),
        type_system_module(Arc::clone(state)),
        decompiler_module(Arc::clone(state)),
        debugger_module(Arc::clone(state)),
        memory_provider_module(Arc::clone(state)),
    ]
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> SharedApiState {
        let state = new_state();
        // Pre-populate with a memory region and a few functions.
        {
            let mut st = state.lock().unwrap();
            st.memory_regions.push((0x1000, vec![0xCC, 0x90, 0x48, 0x89, 0xE5]));
            st.functions.push(FunctionEntry {
                address: 0x1000,
                name: "main".into(),
                type_signature: "int main()".into(),
                is_analyzed: true,
            });
            st.symbols.push(SymbolEntry {
                address: 0x1000,
                name: "main".into(),
                kind: "function".into(),
            });
            st.xrefs.push(XrefEntry { from: 0x2000, to: 0x1000, kind: "call".into() });
            st.debugger_attached = false;
            st.registers.insert("rip".into(), 0x1000);
            st.registers.insert("rsp".into(), 0x7fff_0000);
        }
        state
    }

    #[test]
    fn test_binary_view_open_close() {
        let state = new_state();
        let m = binary_view_module(Arc::clone(&state));
        let open_fn = m.get_fn("open").unwrap();
        let result = open_fn.call(&[ScriptValue::String("/bin/ls".into())]).unwrap();
        assert!(result.to_display_string().contains("/bin/ls"));

        let close_fn = m.get_fn("close").unwrap();
        let r2 = close_fn.call(&[]).unwrap();
        assert_eq!(r2, ScriptValue::Null);
    }

    #[test]
    fn test_binary_view_double_open_fails() {
        let state = new_state();
        let m = binary_view_module(Arc::clone(&state));
        let open_fn = m.get_fn("open").unwrap();
        open_fn.call(&[ScriptValue::String("/bin/ls".into())]).unwrap();
        let err = open_fn.call(&[ScriptValue::String("/bin/cat".into())]).unwrap_err();
        assert!(err.to_string().contains("already open"));
    }

    #[test]
    fn test_function_table_list_and_rename() {
        let state = make_state();
        let m = function_table_module(Arc::clone(&state));
        let list_fn = m.get_fn("list").unwrap();
        let items = list_fn.call(&[]).unwrap();
        assert_eq!(items.as_list().unwrap().len(), 1);

        let rename_fn = m.get_fn("rename").unwrap();
        let ok = rename_fn.call(&[ScriptValue::Address(0x1000), ScriptValue::String("entry_point".into())]).unwrap();
        assert_eq!(ok, ScriptValue::Bool(true));

        let get_fn = m.get_fn("get").unwrap();
        let entry = get_fn.call(&[ScriptValue::Address(0x1000)]).unwrap();
        let map = entry.as_map().unwrap();
        assert_eq!(map.get("name"), Some(&ScriptValue::String("entry_point".into())));
    }

    #[test]
    fn test_symbol_table_lookup_and_remove() {
        let state = make_state();
        let m = symbol_table_module(Arc::clone(&state));

        let lookup_fn = m.get_fn("lookup").unwrap();
        let sym = lookup_fn.call(&[ScriptValue::String("main".into())]).unwrap();
        assert!(!sym.is_null());

        let remove_fn = m.get_fn("remove").unwrap();
        let ok = remove_fn.call(&[ScriptValue::Address(0x1000)]).unwrap();
        assert_eq!(ok, ScriptValue::Bool(true));

        let sym2 = lookup_fn.call(&[ScriptValue::String("main".into())]).unwrap();
        assert!(sym2.is_null());
    }

    #[test]
    fn test_xref_engine_forward_backward() {
        let state = make_state();
        let m = xref_engine_module(Arc::clone(&state));

        let fwd = m.get_fn("query_forward").unwrap();
        let res = fwd.call(&[ScriptValue::Address(0x2000)]).unwrap();
        assert_eq!(res.as_list().unwrap().len(), 1);

        let bwd = m.get_fn("query_backward").unwrap();
        let res2 = bwd.call(&[ScriptValue::Address(0x1000)]).unwrap();
        assert_eq!(res2.as_list().unwrap().len(), 1);
    }

    #[test]
    fn test_patch_set_apply_list_undo() {
        let state = make_state();
        let m = patch_set_module(Arc::clone(&state));

        let apply_fn = m.get_fn("apply").unwrap();
        apply_fn.call(&[
            ScriptValue::Address(0x1000),
            ScriptValue::String("9090".into()),
            ScriptValue::String("nop sled".into()),
        ]).unwrap();

        let list_fn = m.get_fn("list").unwrap();
        let patches = list_fn.call(&[]).unwrap();
        assert_eq!(patches.as_list().unwrap().len(), 1);

        let undo_fn = m.get_fn("undo").unwrap();
        let ok = undo_fn.call(&[ScriptValue::Address(0x1000)]).unwrap();
        assert_eq!(ok, ScriptValue::Bool(true));
    }

    #[test]
    fn test_type_system_define_and_resolve() {
        let state = make_state();
        let m = type_system_module(Arc::clone(&state));

        let def_fn = m.get_fn("define_struct").unwrap();
        def_fn.call(&[
            ScriptValue::String("MyStruct".into()),
            ScriptValue::String("{ int x; int y; }".into()),
        ]).unwrap();

        let resolve_fn = m.get_fn("resolve").unwrap();
        let td = resolve_fn.call(&[ScriptValue::String("MyStruct".into())]).unwrap();
        assert!(!td.is_null());
        assert_eq!(td.as_map().unwrap().get("kind"), Some(&ScriptValue::String("struct".into())));
    }

    #[test]
    fn test_decompiler_decompile_function() {
        let state = make_state();
        let m = decompiler_module(Arc::clone(&state));

        let decomp_fn = m.get_fn("decompile_function").unwrap();
        let pseudo_c = decomp_fn.call(&[ScriptValue::Address(0x1000)]).unwrap();
        let s = pseudo_c.as_str().unwrap();
        assert!(s.contains("main") || s.contains("sub_"));

        // Second call should hit cache.
        let pseudo_c2 = decomp_fn.call(&[ScriptValue::Address(0x1000)]).unwrap();
        assert_eq!(pseudo_c, pseudo_c2);
    }

    #[test]
    fn test_debugger_attach_detach() {
        let state = make_state();
        let m = debugger_module(Arc::clone(&state));

        let attach = m.get_fn("attach").unwrap();
        attach.call(&[ScriptValue::Int(1234)]).unwrap();

        let read_reg = m.get_fn("read_register").unwrap();
        let rip = read_reg.call(&[ScriptValue::String("rip".into())]).unwrap();
        assert_eq!(rip, ScriptValue::Int(0x1000));

        let detach = m.get_fn("detach").unwrap();
        let ok = detach.call(&[]).unwrap();
        assert_eq!(ok, ScriptValue::Bool(true));
    }

    #[test]
    fn test_memory_provider_read_write() {
        let state = make_state();
        let m = memory_provider_module(Arc::clone(&state));

        let read_fn = m.get_fn("read").unwrap();
        let bytes = read_fn.call(&[ScriptValue::Address(0x1000), ScriptValue::Int(2)]).unwrap();
        assert_eq!(bytes.as_bytes().unwrap(), &[0xCC, 0x90]);

        let write_fn = m.get_fn("write").unwrap();
        write_fn.call(&[ScriptValue::Address(0x1000), ScriptValue::String("9090".into())]).unwrap();
        let bytes2 = read_fn.call(&[ScriptValue::Address(0x1000), ScriptValue::Int(2)]).unwrap();
        assert_eq!(bytes2.as_bytes().unwrap(), &[0x90, 0x90]);
    }

    #[test]
    fn test_all_modules_count() {
        let state = new_state();
        let modules = all_modules(&state);
        assert_eq!(modules.len(), 9);
    }
}
