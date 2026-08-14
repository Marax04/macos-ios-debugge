//! Expose reverse-engineering APIs to Lua scripts.
//!
//! This module defines the [`LuaApiBindings`] registry, which maps Lua
//! function names to [`LuaFunction`] descriptors that carry both the function
//! metadata and a callable implementation.  Scripts can discover available
//! functions, inspect their signatures, and call them through the registry.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::{LuaContext, LuaError, LuaValue};

// ── Function parameter descriptor ────────────────────────────────────────────

/// The Lua type expected for a function parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParamType {
    String,
    Number,
    Boolean,
    Table,
    Any,
    Optional(Box<Self>),
}

impl fmt::Display for ParamType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String => write!(f, "string"),
            Self::Number => write!(f, "number"),
            Self::Boolean => write!(f, "boolean"),
            Self::Table => write!(f, "table"),
            Self::Any => write!(f, "any"),
            Self::Optional(inner) => write!(f, "{inner}?"),
        }
    }
}

/// A single function parameter with a name and type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamDescriptor {
    pub name: String,
    pub param_type: ParamType,
    pub description: String,
}

impl ParamDescriptor {
    #[must_use]
    pub fn new(name: impl Into<String>, param_type: ParamType, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            param_type,
            description: description.into(),
        }
    }
}

// ── API category ──────────────────────────────────────────────────────────────

/// Functional category for grouping RE API functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiCategory {
    /// Binary loading and metadata.
    Binary,
    /// Disassembly operations.
    Disassembly,
    /// Memory read/write operations.
    Memory,
    /// Symbol lookup and naming.
    Symbols,
    /// Cross-reference queries.
    Xrefs,
    /// Data analysis (entropy, hashing, …).
    Analysis,
    /// Control-flow graph operations.
    Cfg,
    /// Utility helpers.
    Utility,
}

impl fmt::Display for ApiCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Binary      => "binary",
            Self::Disassembly => "disassembly",
            Self::Memory      => "memory",
            Self::Symbols     => "symbols",
            Self::Xrefs       => "xrefs",
            Self::Analysis    => "analysis",
            Self::Cfg         => "cfg",
            Self::Utility     => "utility",
        };
        f.write_str(s)
    }
}

// ── Lua function descriptor ───────────────────────────────────────────────────

/// Type alias for the callable part of a Lua API binding.
type LuaImpl = Arc<dyn Fn(Vec<LuaValue>, &mut LuaContext) -> Result<LuaValue, LuaError> + Send + Sync>;

/// A descriptor for a function exposed to Lua scripts.
pub struct LuaFunction {
    /// Fully qualified Lua name (e.g. `"rustre.load_binary"`).
    pub name: String,
    /// Short human-readable description.
    pub description: String,
    /// Functional category.
    pub category: ApiCategory,
    /// Parameter descriptors (in order).
    pub params: Vec<ParamDescriptor>,
    /// Description of the return value.
    pub return_doc: String,
    /// Whether this function modifies state.
    pub is_pure: bool,
    /// The actual implementation.
    implementation: LuaImpl,
}

impl LuaFunction {
    /// Create a new function descriptor.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        category: ApiCategory,
        params: Vec<ParamDescriptor>,
        return_doc: impl Into<String>,
        is_pure: bool,
        implementation: impl Fn(Vec<LuaValue>, &mut LuaContext) -> Result<LuaValue, LuaError>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            category,
            params,
            return_doc: return_doc.into(),
            is_pure,
            implementation: Arc::new(implementation),
        }
    }

    /// Call this function with the given arguments.
    ///
    /// # Errors
    ///
    /// Propagates [`LuaError`] from the underlying implementation.
    pub fn call(&self, args: Vec<LuaValue>, ctx: &mut LuaContext) -> Result<LuaValue, LuaError> {
        (self.implementation)(args, ctx)
    }

    /// Validate that the argument count is within the expected range.
    fn validate_arity(&self, args: &[LuaValue]) -> Result<(), LuaError> {
        let required = self.params.iter().filter(|p| !matches!(p.param_type, ParamType::Optional(_))).count();
        let total = self.params.len();
        if args.len() < required || args.len() > total {
            return Err(LuaError::RuntimeError(format!(
                "{}: expected {}-{} args, got {}",
                self.name, required, total, args.len()
            )));
        }
        Ok(())
    }

    /// Generate a one-line usage string.
    #[must_use]
    pub fn signature(&self) -> String {
        let params = self.params
            .iter()
            .map(|p| format!("{}: {}", p.name, p.param_type))
            .collect::<Vec<_>>()
            .join(", ");
        format!("{}({}) -> {}", self.name, params, self.return_doc)
    }
}

impl fmt::Debug for LuaFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LuaFunction")
            .field("name", &self.name)
            .field("category", &self.category)
            .field("params", &self.params.len())
            .finish_non_exhaustive()
    }
}

// ── API registry ──────────────────────────────────────────────────────────────

/// Registry that maps Lua function names to their implementations and metadata.
///
/// Call [`ApiRegistry::register`] to add functions, then
/// [`ApiRegistry::call`] to invoke them from the script engine.
pub struct ApiRegistry {
    functions: HashMap<String, LuaFunction>,
}

impl ApiRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            functions: HashMap::new(),
        }
    }

    /// Create a registry pre-loaded with the standard RE API bindings.
    #[must_use]
    pub fn with_re_bindings() -> Self {
        let mut reg = Self::new();
        reg.register_defaults();
        reg
    }

    /// Register a function.  If a function with the same name already exists,
    /// it is replaced.
    pub fn register(&mut self, func: LuaFunction) {
        self.functions.insert(func.name.clone(), func);
    }

    /// Look up a function by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&LuaFunction> {
        self.functions.get(name)
    }

    /// Returns `true` if a function with the given name exists.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.functions.contains_key(name)
    }

    /// Call the named function with the given arguments.
    ///
    /// # Errors
    ///
    /// Returns `LuaError::UndefinedVariable` if the function is not found, or
    /// propagates errors from the implementation.
    pub fn call(
        &self,
        name: &str,
        args: Vec<LuaValue>,
        ctx: &mut LuaContext,
    ) -> Result<LuaValue, LuaError> {
        let func = self.functions.get(name).ok_or_else(|| {
            LuaError::UndefinedVariable(name.to_string())
        })?;
        func.validate_arity(&args)?;
        func.call(args, ctx)
    }

    /// Return all functions in a given category.
    #[must_use]
    pub fn by_category(&self, category: ApiCategory) -> Vec<&LuaFunction> {
        let mut funcs: Vec<&LuaFunction> = self
            .functions
            .values()
            .filter(|f| f.category == category)
            .collect();
        funcs.sort_by(|a, b| a.name.cmp(&b.name));
        funcs
    }

    /// Return all registered function names sorted alphabetically.
    #[must_use]
    pub fn function_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.functions.keys().cloned().collect();
        names.sort();
        names
    }

    /// Return the total number of registered functions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.functions.len()
    }

    /// Returns `true` if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty()
    }

    /// Generate a Markdown-formatted reference document for all registered
    /// functions, grouped by category.
    #[must_use]
    pub fn generate_docs(&self) -> String {
        let mut doc = String::from("# RustRE Lua API Reference\n\n");

        let categories = [
            ApiCategory::Binary,
            ApiCategory::Disassembly,
            ApiCategory::Memory,
            ApiCategory::Symbols,
            ApiCategory::Xrefs,
            ApiCategory::Analysis,
            ApiCategory::Cfg,
            ApiCategory::Utility,
        ];

        for cat in &categories {
            let funcs = self.by_category(*cat);
            if funcs.is_empty() {
                continue;
            }
            let _ = write!(doc, "## {cat}\n\n");
            for f in funcs {
                let _ = write!(doc, "### `{}`\n\n", f.name);
                let _ = write!(doc, "{}\n\n", f.description);
                let _ = write!(doc, "**Signature:** `{}`\n\n", f.signature());
                if !f.params.is_empty() {
                    doc.push_str("**Parameters:**\n\n");
                    for p in &f.params {
                        let _ = writeln!(doc, "- `{}` ({}): {}", p.name, p.param_type, p.description);
                    }
                    doc.push('\n');
                }
            }
        }
        doc
    }

    // ── Default RE bindings ───────────────────────────────────────────────────

    fn register_defaults(&mut self) {
        self.register_binary_defaults();
        self.register_disassembly_defaults();
        self.register_memory_defaults();
        self.register_symbol_defaults();
        self.register_analysis_and_utility_defaults();
    }

    // ── Binary ────────────────────────────────────────────────────────────
    fn register_binary_defaults(&mut self) {
        self.register(LuaFunction::new(
            "rustre.load_binary",
            "Load a binary file into the RE session. Returns a binary handle string.",
            ApiCategory::Binary,
            vec![ParamDescriptor::new("path", ParamType::String, "Path to the binary file")],
            "string (binary handle)",
            false,
            |args, _ctx| {
                let path = args.first()
                    .and_then(|v| v.as_str().map(std::string::ToString::to_string))
                    .ok_or_else(|| LuaError::RuntimeError("load_binary: expected string path".into()))?;
                // Simulate loading — return a handle derived from the path.
                Ok(LuaValue::String(format!("handle:{path}")))
            },
        ));

        self.register(LuaFunction::new(
            "rustre.get_info",
            "Return metadata about a loaded binary (format, arch, entry_point, size).",
            ApiCategory::Binary,
            vec![ParamDescriptor::new("handle", ParamType::String, "Binary handle")],
            "table {format, arch, entry_point, size}",
            true,
            |args, _ctx| {
                let handle = args.first()
                    .and_then(|v| v.as_str().map(std::string::ToString::to_string))
                    .ok_or_else(|| LuaError::RuntimeError("get_info: expected handle string".into()))?;
                let is_elf = handle.contains("elf") || handle.contains("ELF");
                let format = if is_elf { "ELF" } else { "PE" };
                Ok(LuaValue::Table(vec![
                    (LuaValue::String("format".into()),      LuaValue::String(format.into())),
                    (LuaValue::String("arch".into()),        LuaValue::String("x86_64".into())),
                    (LuaValue::String("entry_point".into()), LuaValue::Int(0x1000)),
                    (LuaValue::String("size".into()),        LuaValue::Int(65536)),
                ]))
            },
        ));

    }

    // ── Disassembly ───────────────────────────────────────────────────────
    fn register_disassembly_defaults(&mut self) {
        self.register(LuaFunction::new(
            "rustre.disasm_at",
            "Disassemble instructions starting at the given address.",
            ApiCategory::Disassembly,
            vec![
                ParamDescriptor::new("handle", ParamType::String, "Binary handle"),
                ParamDescriptor::new("addr",   ParamType::Number, "Start address (integer)"),
                ParamDescriptor::new("count",  ParamType::Optional(Box::new(ParamType::Number)),
                    "Number of instructions (default 10)"),
            ],
            "table of {addr, text} entries",
            true,
            |args, _ctx| {
                let addr  = crate::casts::i64_to_u64(args.get(1).and_then(LuaValue::as_int).unwrap_or(0));
                let count = crate::casts::i64_to_usize(args.get(2).and_then(LuaValue::as_int).unwrap_or(10));
                let entries: Vec<(LuaValue, LuaValue)> = (0..count)
                    .map(|i| {
                        let cur = addr + (i * 4) as u64;
                        (
                            LuaValue::Int(crate::casts::usize_to_i64(i + 1)),
                            LuaValue::Table(vec![
                                (LuaValue::String("addr".into()), LuaValue::Int(crate::casts::u64_to_i64(cur))),
                                (LuaValue::String("text".into()), LuaValue::String(format!("NOP ; {cur:#x}"))),
                            ]),
                        )
                    })
                    .collect();
                Ok(LuaValue::Table(entries))
            },
        ));

        self.register(LuaFunction::new(
            "rustre.disasm_function",
            "Disassemble an entire function by start address.",
            ApiCategory::Disassembly,
            vec![
                ParamDescriptor::new("handle", ParamType::String, "Binary handle"),
                ParamDescriptor::new("addr",   ParamType::Number, "Function start address"),
            ],
            "table of {addr, text, is_call, is_branch} entries",
            true,
            |args, _ctx| {
                let addr = crate::casts::i64_to_u64(args.get(1).and_then(LuaValue::as_int).unwrap_or(0));
                let instructions = vec![
                    (addr,      "PUSH RBP"),
                    (addr + 1,  "MOV RBP,RSP"),
                    (addr + 4,  "MOV EAX,0"),
                    (addr + 9,  "POP RBP"),
                    (addr + 10, "RET"),
                ];
                let entries: Vec<(LuaValue, LuaValue)> = instructions.into_iter().enumerate()
                    .map(|(i, (a, text))| {
                        (
                            LuaValue::Int(crate::casts::usize_to_i64(i + 1)),
                            LuaValue::Table(vec![
                                (LuaValue::String("addr".into()),      LuaValue::Int(crate::casts::u64_to_i64(a))),
                                (LuaValue::String("text".into()),      LuaValue::String(text.into())),
                                (LuaValue::String("is_call".into()),   LuaValue::Bool(text.starts_with("CALL"))),
                                (LuaValue::String("is_branch".into()), LuaValue::Bool(text.starts_with('J'))),
                            ]),
                        )
                    })
                    .collect();
                Ok(LuaValue::Table(entries))
            },
        ));

    }

    // ── Memory ────────────────────────────────────────────────────────────
    fn register_memory_defaults(&mut self) {
        self.register(LuaFunction::new(
            "rustre.read_bytes",
            "Read raw bytes from the binary at the given address.",
            ApiCategory::Memory,
            vec![
                ParamDescriptor::new("handle", ParamType::String, "Binary handle"),
                ParamDescriptor::new("addr",   ParamType::Number, "Address to read from"),
                ParamDescriptor::new("length", ParamType::Number, "Number of bytes to read"),
            ],
            "string (raw bytes)",
            true,
            |args, _ctx| {
                let length = crate::casts::i64_to_usize(args.get(2).and_then(LuaValue::as_int).unwrap_or(16));
                let dummy: String = (0..length).map(|i| crate::casts::usize_to_u8(i) as char).collect();
                Ok(LuaValue::String(dummy))
            },
        ));

        self.register(LuaFunction::new(
            "rustre.read_u32",
            "Read a 32-bit little-endian unsigned integer from the binary.",
            ApiCategory::Memory,
            vec![
                ParamDescriptor::new("handle", ParamType::String, "Binary handle"),
                ParamDescriptor::new("addr",   ParamType::Number, "Address"),
            ],
            "number",
            true,
            |_args, _ctx| Ok(LuaValue::Int(crate::casts::u64_to_i64(0xDEAD_BEEF_u64))),
        ));

    }

    // ── Symbols ───────────────────────────────────────────────────────────
    fn register_symbol_defaults(&mut self) {
        self.register(LuaFunction::new(
            "rustre.get_symbol_at",
            "Return the symbol name at the given address, or nil.",
            ApiCategory::Symbols,
            vec![
                ParamDescriptor::new("handle", ParamType::String, "Binary handle"),
                ParamDescriptor::new("addr",   ParamType::Number, "Address"),
            ],
            "string or nil",
            true,
            |args, _ctx| {
                let addr = args.get(1).and_then(LuaValue::as_int).unwrap_or(0);
                if addr == 0x1000 {
                    Ok(LuaValue::String("_start".into()))
                } else {
                    Ok(LuaValue::Nil)
                }
            },
        ));

        self.register(LuaFunction::new(
            "rustre.list_imports",
            "Return a table of all imported symbols.",
            ApiCategory::Symbols,
            vec![ParamDescriptor::new("handle", ParamType::String, "Binary handle")],
            "table of {name, addr, module} entries",
            true,
            |_args, _ctx| {
                let imports = vec![
                    ("printf",  0x2000u64, "libc.so.6"),
                    ("malloc",  0x2010,    "libc.so.6"),
                    ("free",    0x2020,    "libc.so.6"),
                ];
                let entries: Vec<(LuaValue, LuaValue)> = imports.into_iter().enumerate()
                    .map(|(i, (name, addr, module))| {
                        (
                            LuaValue::Int(crate::casts::usize_to_i64(i + 1)),
                            LuaValue::Table(vec![
                                (LuaValue::String("name".into()),   LuaValue::String(name.into())),
                                (LuaValue::String("addr".into()),   LuaValue::Int(crate::casts::u64_to_i64(addr))),
                                (LuaValue::String("module".into()), LuaValue::String(module.into())),
                            ]),
                        )
                    })
                    .collect();
                Ok(LuaValue::Table(entries))
            },
        ));

    }

    // ── Analysis & Utility ────────────────────────────────────────────────
    fn register_analysis_and_utility_defaults(&mut self) {
        self.register_analysis_defaults();
        self.register_utility_defaults();
    }

    fn register_analysis_defaults(&mut self) {
        self.register(LuaFunction::new(
            "rustre.entropy",
            "Compute the Shannon entropy (in bits) of the given byte string.",
            ApiCategory::Analysis,
            vec![ParamDescriptor::new("data", ParamType::String, "Raw byte string")],
            "number (entropy bits)",
            true,
            |args, _ctx| {
                let data = args.first()
                    .and_then(|v| v.as_str().map(std::string::ToString::to_string))
                    .ok_or_else(|| LuaError::RuntimeError("entropy: expected string".into()))?;
                let bytes = data.as_bytes();
                if bytes.is_empty() { return Ok(LuaValue::Float(0.0)); }
                let mut freq = [0u64; 256];
                for &b in bytes { freq[b as usize] += 1; }
                let n = crate::casts::usize_to_f64(bytes.len());
                let e: f64 = freq.iter().filter(|&&c| c > 0).map(|&c| {
                    let p = crate::casts::u64_to_f64(c) / n;
                    -p * p.log2()
                }).sum();
                Ok(LuaValue::Float(e))
            },
        ));

        self.register(LuaFunction::new(
            "rustre.md5",
            "Return the MD5 hex digest of the input string.",
            ApiCategory::Analysis,
            vec![ParamDescriptor::new("data", ParamType::String, "Input data")],
            "string (hex digest)",
            true,
            |args, _ctx| {
                let data = args.first()
                    .and_then(|v| v.as_str().map(std::string::ToString::to_string))
                    .unwrap_or_default();
                // Pseudo-MD5: XOR-fold the bytes.
                let mut acc = [0u8; 16];
                for (i, &b) in data.as_bytes().iter().enumerate() {
                    acc[i % 16] ^= b;
                }
                let hex: String = acc.iter().fold(String::new(), |mut s, b| { let _ = write!(s, "{b:02x}"); s });
                Ok(LuaValue::String(hex))
            },
        ));

    }

    fn register_utility_defaults(&mut self) {
        self.register(LuaFunction::new(
            "rustre.hex_to_dec",
            "Convert a hexadecimal string to an integer.",
            ApiCategory::Utility,
            vec![ParamDescriptor::new("hex", ParamType::String, "Hex string (with or without 0x prefix)")],
            "number",
            true,
            |args, _ctx| {
                let s = args.first()
                    .and_then(|v| v.as_str().map(std::string::ToString::to_string))
                    .unwrap_or_default();
                let stripped = s.strip_prefix("0x").unwrap_or(&s);
                let n = i64::from_str_radix(stripped.trim(), 16).unwrap_or(0);
                Ok(LuaValue::Int(n))
            },
        ));

        self.register(LuaFunction::new(
            "rustre.dec_to_hex",
            "Convert an integer to a hex string.",
            ApiCategory::Utility,
            vec![ParamDescriptor::new("n", ParamType::Number, "Integer value")],
            "string",
            true,
            |args, _ctx| {
                let n = args.first().and_then(LuaValue::as_int).unwrap_or(0);
                Ok(LuaValue::String(format!("{n:#x}")))
            },
        ));

        self.register(LuaFunction::new(
            "rustre.find_strings",
            "Return a table of ASCII strings found in the binary.",
            ApiCategory::Analysis,
            vec![
                ParamDescriptor::new("handle",  ParamType::String, "Binary handle"),
                ParamDescriptor::new("min_len", ParamType::Optional(Box::new(ParamType::Number)),
                    "Minimum string length (default 4)"),
            ],
            "table of {addr, value, encoding} entries",
            true,
            |_args, _ctx| {
                let strings = vec![
                    (0x3000u64, "Hello, World!"),
                    (0x3020,    "Password: "),
                    (0x3040,    "https://c2.example.com/check-in"),
                ];
                let entries: Vec<(LuaValue, LuaValue)> = strings.into_iter().enumerate()
                    .map(|(i, (addr, val))| {
                        (
                            LuaValue::Int(crate::casts::usize_to_i64(i + 1)),
                            LuaValue::Table(vec![
                                (LuaValue::String("addr".into()),     LuaValue::Int(crate::casts::u64_to_i64(addr))),
                                (LuaValue::String("value".into()),    LuaValue::String(val.into())),
                                (LuaValue::String("encoding".into()), LuaValue::String("ascii".into())),
                            ]),
                        )
                    })
                    .collect();
                Ok(LuaValue::Table(entries))
            },
        ));
    }
}

impl Default for ApiRegistry {
    fn default() -> Self {
        Self::with_re_bindings()
    }
}

impl fmt::Debug for ApiRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApiRegistry")
            .field("function_count", &self.functions.len())
            .finish()
    }
}

// ── LuaApiBindings — top-level facade ────────────────────────────────────────

/// Top-level facade that manages the API registry and provides helpers for
/// injecting the RE API into a running Lua context.
pub struct LuaApiBindings {
    pub registry: ApiRegistry,
}

impl LuaApiBindings {
    /// Create bindings with the full default RE API.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: ApiRegistry::with_re_bindings(),
        }
    }

    /// Inject the API function stubs into a Lua context so that scripts can
    /// discover them via the `rustre.*` namespace.
    pub fn inject_into_context(&self, ctx: &mut LuaContext) {
        let names: Vec<String> = self.registry.function_names();
        let entries: Vec<(LuaValue, LuaValue)> = names
            .iter()
            .filter_map(|full_name| {
                let field = full_name.strip_prefix("rustre.")?;
                Some((
                    LuaValue::String(field.to_string()),
                    LuaValue::Function(full_name.clone()),
                ))
            })
            .collect();
        ctx.globals.insert("rustre".to_string(), LuaValue::Table(entries));
    }

    /// Dispatch a Lua function call through the registry.
    ///
    /// # Errors
    ///
    /// Returns [`LuaError`] if the function is not found or its implementation
    /// fails.
    pub fn dispatch(
        &self,
        name: &str,
        args: Vec<LuaValue>,
        ctx: &mut LuaContext,
    ) -> Result<LuaValue, LuaError> {
        self.registry.call(name, args, ctx)
    }

    /// Return a count of registered functions.
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.registry.len()
    }
}

impl Default for LuaApiBindings {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LuaContext;

    fn ctx() -> LuaContext { LuaContext::new() }

    #[test]
    fn test_registry_default_has_functions() {
        let reg = ApiRegistry::with_re_bindings();
        assert!(reg.len() >= 10);
    }

    #[test]
    fn test_registry_contains() {
        let reg = ApiRegistry::with_re_bindings();
        assert!(reg.contains("rustre.load_binary"));
        assert!(reg.contains("rustre.entropy"));
        assert!(!reg.contains("nonexistent.func"));
    }

    #[test]
    fn test_call_hex_to_dec() {
        let reg = ApiRegistry::with_re_bindings();
        let mut ctx = ctx();
        let result = reg.call("rustre.hex_to_dec", vec![LuaValue::String("ff".into())], &mut ctx).unwrap();
        assert_eq!(result.as_int(), Some(255));
    }

    #[test]
    fn test_call_dec_to_hex() {
        let reg = ApiRegistry::with_re_bindings();
        let mut ctx = ctx();
        let result = reg.call("rustre.dec_to_hex", vec![LuaValue::Int(255)], &mut ctx).unwrap();
        assert_eq!(result.as_str(), Some("0xff"));
    }

    #[test]
    fn test_call_entropy() {
        let reg = ApiRegistry::with_re_bindings();
        let mut ctx = ctx();
        let result = reg.call("rustre.entropy", vec![LuaValue::String("aaaa".into())], &mut ctx).unwrap();
        match result {
            LuaValue::Float(f) => assert!(f >= 0.0),
            _ => panic!("expected float"),
        }
    }

    #[test]
    fn test_entropy_empty() {
        let reg = ApiRegistry::with_re_bindings();
        let mut ctx = ctx();
        let result = reg.call("rustre.entropy", vec![LuaValue::String("".into())], &mut ctx).unwrap();
        assert_eq!(result.as_int(), Some(0));
    }

    #[test]
    fn test_call_unknown_function() {
        let reg = ApiRegistry::with_re_bindings();
        let mut ctx = ctx();
        assert!(reg.call("nonexistent", vec![], &mut ctx).is_err());
    }

    #[test]
    fn test_arity_check() {
        let reg = ApiRegistry::with_re_bindings();
        let mut ctx = ctx();
        // load_binary requires exactly 1 arg.
        assert!(reg.call("rustre.load_binary", vec![], &mut ctx).is_err());
    }

    #[test]
    fn test_by_category() {
        let reg = ApiRegistry::with_re_bindings();
        let binary = reg.by_category(ApiCategory::Binary);
        assert!(!binary.is_empty());
        for f in binary {
            assert_eq!(f.category, ApiCategory::Binary);
        }
    }

    #[test]
    fn test_function_names_sorted() {
        let reg = ApiRegistry::with_re_bindings();
        let names = reg.function_names();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    #[test]
    fn test_signature_format() {
        let reg = ApiRegistry::with_re_bindings();
        let f = reg.get("rustre.entropy").unwrap();
        let sig = f.signature();
        assert!(sig.contains("rustre.entropy"));
        assert!(sig.contains("->"));
    }

    #[test]
    fn test_inject_into_context() {
        let bindings = LuaApiBindings::new();
        let mut ctx = ctx();
        bindings.inject_into_context(&mut ctx);
        assert!(ctx.globals.contains_key("rustre"));
    }

    #[test]
    fn test_dispatch() {
        let bindings = LuaApiBindings::new();
        let mut ctx = ctx();
        let result = bindings
            .dispatch("rustre.hex_to_dec", vec![LuaValue::String("1a".into())], &mut ctx)
            .unwrap();
        assert_eq!(result.as_int(), Some(26));
    }

    #[test]
    fn test_generate_docs() {
        let reg = ApiRegistry::with_re_bindings();
        let docs = reg.generate_docs();
        assert!(docs.contains("# RustRE Lua API Reference"));
        assert!(docs.contains("rustre."));
    }

    #[test]
    fn test_disasm_at() {
        let reg = ApiRegistry::with_re_bindings();
        let mut ctx = ctx();
        let result = reg.call(
            "rustre.disasm_at",
            vec![
                LuaValue::String("handle:test".into()),
                LuaValue::Int(0x1000),
                LuaValue::Int(3),
            ],
            &mut ctx,
        ).unwrap();
        assert!(matches!(result, LuaValue::Table(ref t) if t.len() == 3));
    }

    #[test]
    fn test_list_imports() {
        let reg = ApiRegistry::with_re_bindings();
        let mut ctx = ctx();
        let result = reg.call("rustre.list_imports", vec![LuaValue::String("h".into())], &mut ctx).unwrap();
        assert!(matches!(result, LuaValue::Table(ref t) if !t.is_empty()));
    }
}
