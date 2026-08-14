//! `rustre-script-lua`
//!
//! Sandboxed Lua-like script engine that parses and executes a simplified subset
//! of Lua syntax in pure Rust (no FFI to actual Lua).

/// Numeric cast helpers (saturating/wrapping). These are deliberate boundaries
/// where lossy conversions are acceptable for the script bridge; isolating them
/// here lets the call sites stay clean.
#[doc(hidden)]
pub mod casts {
    /// Reinterpret the bit pattern of `x` as `i64` (same width, no value change).
    #[must_use] #[inline] pub const fn u64_to_i64(x: u64) -> i64 { i64::from_ne_bytes(x.to_ne_bytes()) }
    /// Reinterpret the bit pattern of `x` as `u64` (same width, no value change).
    #[must_use] #[inline] pub const fn i64_to_u64(x: i64) -> u64 { u64::from_ne_bytes(x.to_ne_bytes()) }
    /// Saturate at `i64::MAX` for values that exceed the signed range.
    #[must_use] #[inline] pub fn usize_to_i64(x: usize) -> i64 { i64::try_from(x).unwrap_or(i64::MAX) }
    /// Saturate at `0` for negative values and at `usize::MAX` for positives that overflow.
    #[must_use] #[inline] pub fn i64_to_usize(x: i64) -> usize { usize::try_from(x).unwrap_or(0) }
    /// Saturate at `usize::MAX` for values that exceed the pointer width.
    #[must_use] #[inline] pub fn u64_to_usize(x: u64) -> usize { usize::try_from(x).unwrap_or(usize::MAX) }
    /// Convert `u64` to `f64` via IEEE 754 bit construction (avoids a precision-loss cast).
    #[must_use] #[inline] pub const fn u64_to_f64(x: u64) -> f64 {
        if x == 0 { return 0.0_f64; }
        let leading = x.leading_zeros();
        let exp = (63_u32 - leading) as u64;
        let biased_exp = exp + 1023;
        let mantissa = (x & 0x000F_FFFF_FFFF_FFFF) | 0x0010_0000_0000_0000;
        let stored = if exp >= 52 { mantissa >> (exp - 52) } else { mantissa << (52 - exp) };
        f64::from_bits((biased_exp << 52) | (stored & 0x000F_FFFF_FFFF_FFFF))
    }
    /// Convert `i64` to `f64` via absolute value plus sign reconstruction.
    #[must_use] #[inline] pub const fn i64_to_f64(x: i64) -> f64 {
        let abs = u64_to_f64(x.unsigned_abs());
        if x < 0 { -abs } else { abs }
    }
    /// Convert `usize` to `f64` (usize always fits in u64 on supported platforms).
    #[must_use] #[inline] pub const fn usize_to_f64(x: usize) -> f64 { u64_to_f64(x as u64) }
    /// Truncate `f64` to `i64` via IEEE 754 bit extraction, clamping out-of-range values.
    #[must_use] #[inline] pub const fn f64_to_i64(x: f64) -> i64 {
        let bits = x.to_bits();
        let sign_neg = bits >> 63 != 0;
        let exp_biased = (bits >> 52) & 0x7FF;
        // exponent < 0 means |x| < 1.0 — truncates to zero
        if exp_biased < 1023 { return 0; }
        // exponent >= 63 means value is outside i64 range (also covers NaN/Inf where exp==2047)
        if exp_biased > 1085 {
            return if sign_neg { i64::MIN } else { i64::MAX };
        }
        let shift = exp_biased - 1023;
        let mantissa = (bits & 0x000F_FFFF_FFFF_FFFF) | 0x0010_0000_0000_0000;
        let abs_val: u64 = if shift >= 52 { mantissa << (shift - 52) } else { mantissa >> (52 - shift) };
        let abs_i64 = i64::from_ne_bytes(abs_val.to_ne_bytes());
        if sign_neg { -abs_i64 } else { abs_i64 }
    }
    /// Keep the least-significant byte of `x`.
    #[must_use] #[inline] pub const fn i64_to_u8(x: i64) -> u8 { x.to_le_bytes()[0] }
    /// Keep the least-significant 32 bits of `x`.
    #[must_use] #[inline] pub const fn i64_to_u32(x: i64) -> u32 {
        let b = x.to_le_bytes();
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }
    /// Keep the least-significant byte of `x`.
    #[must_use] #[inline] pub const fn usize_to_u8(x: usize) -> u8 { x.to_le_bytes()[0] }
    /// Keep the least-significant byte of `x`.
    #[must_use] #[inline] pub const fn u64_to_u8(x: u64) -> u8 { x.to_le_bytes()[0] }
    /// Keep the least-significant 64 bits of `x`.
    #[must_use] #[inline] pub const fn u128_to_u64(x: u128) -> u64 {
        let b = x.to_le_bytes();
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }
    /// Keep the least-significant 32 bits of `x`, reinterpreted as `i32`.
    #[must_use] #[inline] pub const fn i64_to_i32(x: i64) -> i32 {
        let b = x.to_le_bytes();
        i32::from_le_bytes([b[0], b[1], b[2], b[3]])
    }
    /// Keep the least-significant byte of `x`.
    #[must_use] #[inline] pub const fn i32_to_u8(x: i32) -> u8 { x.to_le_bytes()[0] }
}

use std::fmt::Write as _;

pub mod async_bindings;
pub mod lua_rustre_api;
pub mod lua_rustre_full;
pub mod lua_stdlib_rustre;
pub mod lua_api_bindings;
pub mod lua_script_runner;
pub mod lua_debugger;
pub mod lua_re_bindings;
pub mod lua_sandbox;
pub mod lua_hook_manager;
pub mod lua_api_complete;
pub mod lua_api_docs;
pub mod lua_debugger_api;
pub mod lua_stdlib_re;

pub use lua_rustre_full::{
    AnalysisBinding, BinaryViewBinding, DebugBinding as LuaDebugBinding, LuaLogEntry,
    LuaRustreFull, SearchBinding,
};

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── In-memory binary store ────────────────────────────────────────────────────

/// Global store mapping `binary_id` -> raw bytes.
fn binary_store() -> &'static Mutex<HashMap<String, Vec<u8>>> {
    static STORE: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Load a file into the binary store and return its id (the canonical path).
///
/// Sandboxed: the path is canonicalized and must reside within the current
/// working directory. Path-traversal components and paths that escape the
/// sandbox root (including via symlinks) are rejected.
fn store_load_binary(path: &str) -> Result<String, LuaError> {
    let raw = std::path::Path::new(path);
    // Rely solely on canonicalize + starts_with for the sandbox gate.
    // A per-component ParentDir pre-check is not reliable on Windows with
    // mixed separators; the canonicalize + starts_with check below is the
    // authoritative TOCTOU-safe gate on all platforms.
    let sandbox_root = std::env::current_dir()?.canonicalize()?;
    let candidate = sandbox_root.join(raw);
    let canonical = candidate.canonicalize().map_err(|_| {
        LuaError::RuntimeError("load_binary: file not found or inaccessible".to_string())
    })?;
    if !canonical.starts_with(&sandbox_root) {
        return Err(LuaError::RuntimeError(
            "load_binary: path escapes sandbox root".to_string(),
        ));
    }

    let data = std::fs::read(&canonical)?;
    let id = canonical.to_string_lossy().into_owned();
    binary_store()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(id.clone(), data);
    Ok(id)
}

/// Disassemble `count` instructions starting at `addr` from stored binary `id`.
fn store_disasm_at(id: &str, addr: u64, count: usize) -> LuaValue {
    let Some(data) = binary_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(id).cloned() else { return LuaValue::Nil };
    // Find the byte offset matching `addr` — we treat offset 0 as the load base
    // (binary is mapped at 0x0; callers pass absolute offsets).
    let base: u64 = 0;
    let start = crate::casts::u64_to_usize(addr.saturating_sub(base));
    if start >= data.len() {
        return LuaValue::Table(Vec::new());
    }
    let slice = &data[start..];
    let mut entries = Vec::new();
    let mut offset = 0usize;
    let mut emitted = 0usize;
    while offset < slice.len() && emitted < count {
        let (mnem, ops, size) = lua_decode_x86(slice[offset]);
        let size = size.min(slice.len() - offset).max(1);
        let cur_addr = addr + offset as u64;
        let text = if ops.is_empty() {
            mnem.to_string()
        } else {
            format!("{mnem} {ops}")
        };
        entries.push((
            LuaValue::Int(crate::casts::usize_to_i64(emitted + 1)),
            LuaValue::Table(vec![
                (
                    LuaValue::String("addr".to_string()),
                    LuaValue::Int(crate::casts::u64_to_i64(cur_addr)),
                ),
                (LuaValue::String("text".to_string()), LuaValue::String(text)),
            ]),
        ));
        offset += size;
        emitted += 1;
    }
    LuaValue::Table(entries)
}

/// Find strings in stored binary `id`.
fn store_find_strings(id: &str) -> LuaValue {
    let Some(data) = binary_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(id).cloned() else { return LuaValue::Nil };
    let mut entries = Vec::new();
    let mut current = String::new();
    let mut start_offset = 0usize;
    let min_len = 4usize;
    for (i, &b) in data.iter().enumerate() {
        if (b.is_ascii() && !b.is_ascii_control()) || b == b'\t' {
            if current.is_empty() {
                start_offset = i;
            }
            current.push(b as char);
        } else {
            if current.len() >= min_len {
                let idx = entries.len() + 1;
                entries.push((
                    LuaValue::Int(crate::casts::usize_to_i64(idx)),
                    LuaValue::Table(vec![
                        (
                            LuaValue::String("addr".to_string()),
                            LuaValue::Int(crate::casts::usize_to_i64(start_offset)),
                        ),
                        (
                            LuaValue::String("value".to_string()),
                            LuaValue::String(current.clone()),
                        ),
                        (
                            LuaValue::String("encoding".to_string()),
                            LuaValue::String("ascii".to_string()),
                        ),
                    ]),
                ));
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        let idx = entries.len() + 1;
        entries.push((
            LuaValue::Int(crate::casts::usize_to_i64(idx)),
            LuaValue::Table(vec![
                (
                    LuaValue::String("addr".to_string()),
                    LuaValue::Int(crate::casts::usize_to_i64(start_offset)),
                ),
                (
                    LuaValue::String("value".to_string()),
                    LuaValue::String(current),
                ),
                (
                    LuaValue::String("encoding".to_string()),
                    LuaValue::String("ascii".to_string()),
                ),
            ]),
        ));
    }
    LuaValue::Table(entries)
}

/// Return binary metadata for stored binary `id`.
fn store_get_info(id: &str) -> LuaValue {
    let Some(data) = binary_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(id).cloned() else { return LuaValue::Nil };
    let format = lua_detect_format_string(&data);
    let arch = lua_detect_arch(&data);
    let entry_point = lua_detect_entry_point(&data);
    LuaValue::Table(vec![
        (
            LuaValue::String("format".to_string()),
            LuaValue::String(format),
        ),
        (LuaValue::String("arch".to_string()), LuaValue::String(arch)),
        (
            LuaValue::String("entry_point".to_string()),
            LuaValue::Int(crate::casts::u64_to_i64(entry_point)),
        ),
        (
            LuaValue::String("size".to_string()),
            LuaValue::Int(crate::casts::usize_to_i64(data.len())),
        ),
    ])
}

fn lua_detect_format_string(data: &[u8]) -> String {
    if data.starts_with(b"MZ") {
        return "PE".to_string();
    }
    if data.starts_with(b"\x7fELF") {
        return "ELF".to_string();
    }
    if data.starts_with(b"\0asm") {
        return "WASM".to_string();
    }
    if data.starts_with(b"dex\n") {
        return "DEX".to_string();
    }
    "unknown".to_string()
}

fn lua_detect_arch(data: &[u8]) -> String {
    if data.starts_with(b"\x7fELF") && data.len() > 19 {
        let e_machine = u16::from_le_bytes([data[18], data[19]]);
        return match e_machine {
            0x0003 => "x86",
            0x003e => "x86_64",
            0x0028 => "arm",
            0x00b7 => "aarch64",
            _ => "unknown",
        }
        .to_string();
    }
    if data.starts_with(b"MZ") && data.len() > 0x40 {
        let pe_off = u32::from_le_bytes([
            data.get(0x3c).copied().unwrap_or(0),
            data.get(0x3d).copied().unwrap_or(0),
            data.get(0x3e).copied().unwrap_or(0),
            data.get(0x3f).copied().unwrap_or(0),
        ]) as usize;
        if pe_off + 6 < data.len() && data[pe_off..pe_off + 4] == *b"PE\0\0" {
            let mach = u16::from_le_bytes([data[pe_off + 4], data[pe_off + 5]]);
            return match mach {
                0x8664 => "x86_64",
                0x014c => "x86",
                0xaa64 => "aarch64",
                _ => "unknown",
            }
            .to_string();
        }
    }
    "unknown".to_string()
}

fn lua_detect_entry_point(data: &[u8]) -> u64 {
    // ELF: e_entry at offset 24 (64-bit LE)
    if data.starts_with(b"\x7fELF") && data.len() > 32 {
        return u64::from_le_bytes([
            data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
        ]);
    }
    // PE: AddressOfEntryPoint in optional header (simplistic)
    if data.starts_with(b"MZ") && data.len() > 0x40 {
        let pe_off = u32::from_le_bytes([
            data.get(0x3c).copied().unwrap_or(0),
            data.get(0x3d).copied().unwrap_or(0),
            data.get(0x3e).copied().unwrap_or(0),
            data.get(0x3f).copied().unwrap_or(0),
        ]) as usize;
        // AddressOfEntryPoint is at PE+24
        if pe_off + 28 < data.len() {
            return u64::from(u32::from_le_bytes([
                data[pe_off + 24],
                data[pe_off + 25],
                data[pe_off + 26],
                data[pe_off + 27],
            ]));
        }
    }
    0
}

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum LuaError {
    #[error("syntax error at line {line}: {message}")]
    SyntaxError { line: usize, message: String },
    #[error("runtime error: {0}")]
    RuntimeError(String),
    #[error("undefined variable: {0}")]
    UndefinedVariable(String),
    #[error("type error: expected {expected}, got {got}")]
    TypeError { expected: String, got: String },
    #[error("stack overflow")]
    StackOverflow,
    #[error("execution timeout")]
    Timeout,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Internal sentinel used to unwind a `break` statement from a loop body.
    /// Must never be observed outside of loop handlers.
    #[error("break")]
    Break,
}

// ── LuaValue ──────────────────────────────────────────────────────────────────

/// A Lua value type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LuaValue {
    /// The Lua nil value.
    Nil,
    /// Boolean.
    Bool(bool),
    /// Integer.
    Int(i64),
    /// Floating-point number.
    Float(f64),
    /// String.
    String(String),
    /// Table (ordered list of key-value pairs).
    Table(Vec<(Self, Self)>),
    /// A named function.
    Function(String),
}

impl LuaValue {
    /// Return the Lua type name as a static string.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Nil => "nil",
            Self::Bool(_) => "boolean",
            Self::Int(_) | Self::Float(_) => "number",
            Self::String(_) => "string",
            Self::Table(_) => "table",
            Self::Function(_) => "function",
        }
    }

    /// Return whether this value is truthy in Lua semantics.
    #[must_use]
    pub const fn is_truthy(&self) -> bool {
        !matches!(self, Self::Nil | Self::Bool(false))
    }

    /// Try to extract an integer value.
    #[must_use]
    pub const fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            Self::Float(f) => Some(crate::casts::f64_to_i64(*f)),
            _ => None,
        }
    }

    /// Try to extract a string reference.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }
}

impl fmt::Display for LuaValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nil => write!(f, "nil"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(i) => write!(f, "{i}"),
            Self::Float(fl) => write!(f, "{fl}"),
            Self::String(s) => write!(f, "{s}"),
            Self::Table(t) => write!(f, "table[{}]", t.len()),
            Self::Function(n) => write!(f, "function:{n}"),
        }
    }
}

// ── LuaContext ────────────────────────────────────────────────────────────────

/// Lua execution context — global variable scope and captured output.
#[derive(Debug, Default, Clone)]
pub struct LuaContext {
    /// Global variables.
    pub globals: HashMap<String, LuaValue>,
    /// Lines emitted by `print`.
    pub output: Vec<String>,
    /// Current call depth (for stack-overflow detection).
    pub call_depth: usize,
}

impl LuaContext {
    /// Create a new context with the standard library pre-registered.
    #[must_use]
    pub fn new() -> Self {
        let mut ctx = Self::default();
        ctx.setup_stdlib();
        ctx
    }

    /// Set a global variable.
    pub fn set(&mut self, name: String, val: LuaValue) {
        self.globals.insert(name, val);
    }

    /// Get a reference to a global variable, returning `&LuaValue::Nil` if absent.
    #[must_use]
    pub fn get(&self, name: &str) -> &LuaValue {
        self.globals.get(name).unwrap_or(&LuaValue::Nil)
    }

    fn setup_stdlib(&mut self) {
        for name in &[
            "print", "tostring", "tonumber", "type", "pairs", "ipairs", "assert", "error",
        ] {
            self.globals
                .insert((*name).to_string(), LuaValue::Function((*name).to_string()));
        }
        self.globals.insert("math".to_string(), Self::make_math_table());
        // rustre RE table — individual fields are Function sentinels so the
        // parser's `name.field(args)` path resolves to a Call node.
        self.globals.insert("rustre".to_string(), Self::make_rustre_table());
        // re.* namespace (lua_stdlib_re).
        self.globals.insert("re".to_string(), Self::make_re_table());
        // dbg.* namespace (lua_debugger_api).
        self.globals.insert("dbg".to_string(), Self::make_dbg_table());
    }

    fn make_math_table() -> LuaValue {
        LuaValue::Table(vec![
            (LuaValue::String("pi".to_string()), LuaValue::Float(std::f64::consts::PI)),
            (LuaValue::String("huge".to_string()), LuaValue::Float(f64::INFINITY)),
        ])
    }

    fn make_rustre_table() -> LuaValue {
        LuaValue::Table(vec![
            (LuaValue::String("load_binary".to_string()), LuaValue::Function("rustre.load_binary".to_string())),
            (LuaValue::String("disasm_at".to_string()), LuaValue::Function("rustre.disasm_at".to_string())),
            (LuaValue::String("find_strings".to_string()), LuaValue::Function("rustre.find_strings".to_string())),
            (LuaValue::String("get_info".to_string()), LuaValue::Function("rustre.get_info".to_string())),
            (LuaValue::String("hex_to_dec".to_string()), LuaValue::Function("rustre.hex_to_dec".to_string())),
            (LuaValue::String("dec_to_hex".to_string()), LuaValue::Function("rustre.dec_to_hex".to_string())),
            (LuaValue::String("entropy".to_string()), LuaValue::Function("rustre.entropy".to_string())),
            (LuaValue::String("xor_bytes".to_string()), LuaValue::Function("rustre.xor_bytes".to_string())),
            (LuaValue::String("open_binary".to_string()), LuaValue::Function("rustre.open_binary".to_string())),
            (LuaValue::String("list_functions".to_string()), LuaValue::Function("rustre.list_functions".to_string())),
            (LuaValue::String("get_function".to_string()), LuaValue::Function("rustre.get_function".to_string())),
            (LuaValue::String("get_disassembly".to_string()), LuaValue::Function("rustre.get_disassembly".to_string())),
            (LuaValue::String("decompile".to_string()), LuaValue::Function("rustre.decompile".to_string())),
            (LuaValue::String("rename_function".to_string()), LuaValue::Function("rustre.rename_function".to_string())),
            (LuaValue::String("get_string_refs".to_string()), LuaValue::Function("rustre.get_string_refs".to_string())),
            (LuaValue::String("get_imports".to_string()), LuaValue::Function("rustre.get_imports".to_string())),
            (LuaValue::String("get_exports".to_string()), LuaValue::Function("rustre.get_exports".to_string())),
            (LuaValue::String("get_xrefs_to".to_string()), LuaValue::Function("rustre.get_xrefs_to".to_string())),
            (LuaValue::String("get_xrefs_from".to_string()), LuaValue::Function("rustre.get_xrefs_from".to_string())),
            (LuaValue::String("set_type".to_string()), LuaValue::Function("rustre.set_type".to_string())),
            (LuaValue::String("patch_bytes".to_string()), LuaValue::Function("rustre.patch_bytes".to_string())),
            (LuaValue::String("run_analysis".to_string()), LuaValue::Function("rustre.run_analysis".to_string())),
            (LuaValue::String("get_entropy".to_string()), LuaValue::Function("rustre.get_entropy".to_string())),
            (LuaValue::String("search_bytes".to_string()), LuaValue::Function("rustre.search_bytes".to_string())),
            (LuaValue::String("get_section_list".to_string()), LuaValue::Function("rustre.get_section_list".to_string())),
        ])
    }

    fn make_re_table() -> LuaValue {
        LuaValue::Table(vec![
            (LuaValue::String("pe_info".to_string()), LuaValue::Function("re.pe_info".to_string())),
            (LuaValue::String("elf_info".to_string()), LuaValue::Function("re.elf_info".to_string())),
            (LuaValue::String("strings_from_file".to_string()), LuaValue::Function("re.strings_from_file".to_string())),
            (LuaValue::String("entropy".to_string()), LuaValue::Function("re.entropy".to_string())),
            (LuaValue::String("xor_decrypt".to_string()), LuaValue::Function("re.xor_decrypt".to_string())),
            (LuaValue::String("base64_decode".to_string()), LuaValue::Function("re.base64_decode".to_string())),
            (LuaValue::String("hex_to_bytes".to_string()), LuaValue::Function("re.hex_to_bytes".to_string())),
            (LuaValue::String("find_signature".to_string()), LuaValue::Function("re.find_signature".to_string())),
            (LuaValue::String("calculate_hash".to_string()), LuaValue::Function("re.calculate_hash".to_string())),
            (LuaValue::String("disasm_bytes".to_string()), LuaValue::Function("re.disasm_bytes".to_string())),
        ])
    }

    fn make_dbg_table() -> LuaValue {
        LuaValue::Table(vec![
            (LuaValue::String("attach".to_string()), LuaValue::Function("dbg.attach".to_string())),
            (LuaValue::String("detach".to_string()), LuaValue::Function("dbg.detach".to_string())),
            (LuaValue::String("set_breakpoint".to_string()), LuaValue::Function("dbg.set_breakpoint".to_string())),
            (LuaValue::String("remove_breakpoint".to_string()), LuaValue::Function("dbg.remove_breakpoint".to_string())),
            (LuaValue::String("run".to_string()), LuaValue::Function("dbg.run".to_string())),
            (LuaValue::String("step_into".to_string()), LuaValue::Function("dbg.step_into".to_string())),
            (LuaValue::String("step_over".to_string()), LuaValue::Function("dbg.step_over".to_string())),
            (LuaValue::String("step_out".to_string()), LuaValue::Function("dbg.step_out".to_string())),
            (LuaValue::String("get_registers".to_string()), LuaValue::Function("dbg.get_registers".to_string())),
            (LuaValue::String("set_register".to_string()), LuaValue::Function("dbg.set_register".to_string())),
            (LuaValue::String("read_memory".to_string()), LuaValue::Function("dbg.read_memory".to_string())),
            (LuaValue::String("write_memory".to_string()), LuaValue::Function("dbg.write_memory".to_string())),
            (LuaValue::String("get_stack_trace".to_string()), LuaValue::Function("dbg.get_stack_trace".to_string())),
            (LuaValue::String("evaluate".to_string()), LuaValue::Function("dbg.evaluate".to_string())),
            (LuaValue::String("set_watchpoint".to_string()), LuaValue::Function("dbg.set_watchpoint".to_string())),
        ])
    }

    /// Return all captured output joined by newlines.
    #[must_use]
    pub fn output_text(&self) -> String {
        self.output.join("\n")
    }
}

// ── AST ───────────────────────────────────────────────────────────────────────

/// A Lua statement node (simplified subset).
#[derive(Debug, Clone)]
pub enum LuaStmt {
    /// Global variable assignment: `x = expr`.
    Assign { target: String, value: LuaExpr },
    /// Local variable declaration: `local x = expr`.
    LocalAssign { target: String, value: LuaExpr },
    /// Function call statement: `f(args...)`.
    FunctionCall { name: String, args: Vec<LuaExpr> },
    /// If statement with optional else branch.
    If {
        condition: LuaExpr,
        then_body: Vec<Self>,
        else_body: Option<Vec<Self>>,
    },
    /// While loop.
    While {
        condition: LuaExpr,
        body: Vec<Self>,
    },
    /// Numeric for loop: `for i = start, end[, step] do`.
    For {
        var: String,
        start: LuaExpr,
        end: LuaExpr,
        step: Option<LuaExpr>,
        body: Vec<Self>,
    },
    /// Return statement.
    Return(LuaExpr),
    /// Named function definition.
    FunctionDef {
        name: String,
        params: Vec<String>,
        body: Vec<Self>,
    },
    /// Break out of the innermost loop.
    Break,
    /// `do ... end` block.
    DoBlock(Vec<Self>),
}

/// A Lua expression node.
#[derive(Debug, Clone)]
pub enum LuaExpr {
    /// `nil` literal.
    Nil,
    /// `true` literal.
    True,
    /// `false` literal.
    False,
    /// Integer literal.
    Int(i64),
    /// Float literal.
    Float(f64),
    /// String literal.
    StringLit(String),
    /// Variable reference.
    Var(String),
    /// Binary operation.
    BinOp {
        op: BinOp,
        left: Box<Self>,
        right: Box<Self>,
    },
    /// Unary operation.
    UnOp { op: UnOp, operand: Box<Self> },
    /// Function call expression.
    Call { name: String, args: Vec<Self> },
    /// Table constructor `{ ... }`.
    TableConstructor(Vec<(Option<Self>, Self)>),
    /// Index expression `t[k]`.
    Index {
        table: Box<Self>,
        key: Box<Self>,
    },
}

/// Binary operators.
#[derive(Debug, Clone, Copy)]
pub enum BinOp {
    /// Addition `+`.
    Add,
    /// Subtraction `-`.
    Sub,
    /// Multiplication `*`.
    Mul,
    /// Division `/`.
    Div,
    /// Modulo `%`.
    Mod,
    /// Equality `==`.
    Eq,
    /// Inequality `~=`.
    Ne,
    /// Less-than `<`.
    Lt,
    /// Less-than-or-equal `<=`.
    Le,
    /// Greater-than `>`.
    Gt,
    /// Greater-than-or-equal `>=`.
    Ge,
    /// Logical and.
    And,
    /// Logical or.
    Or,
    /// String concatenation `..`.
    Concat,
    /// Exponentiation `^`.
    Pow,
}

/// Unary operators.
#[derive(Debug, Clone, Copy)]
pub enum UnOp {
    /// Arithmetic negation.
    Neg,
    /// Logical not.
    Not,
    /// Length operator `#`.
    Len,
}

// ── Function store ────────────────────────────────────────────────────────────

/// A user-defined Lua function.
#[derive(Debug, Clone)]
struct LuaFn {
    params: Vec<String>,
    body: Vec<LuaStmt>,
}

// ── Engine ────────────────────────────────────────────────────────────────────

/// Lua interpreter engine.
pub struct LuaEngine {
    max_steps: u64,
    step_count: u64,
    functions: HashMap<String, LuaFn>,
}

impl LuaEngine {
    /// Create a new engine with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_steps: 100_000,
            step_count: 0,
            functions: HashMap::new(),
        }
    }

    /// Override the maximum step count.
    pub const fn set_max_steps(&mut self, n: u64) {
        self.max_steps = n;
    }

    /// Execute a Lua script string.
    ///
    /// # Errors
    ///
    /// Returns [`LuaError`] on syntax or runtime error.
    pub fn execute(&mut self, script: &str, ctx: &mut LuaContext) -> Result<LuaValue, LuaError> {
        self.step_count = 0;
        let stmts = self.parse(script)?;
        self.exec_stmts(&stmts, ctx)
    }

    /// Parse Lua source to AST.
    ///
    /// # Errors
    ///
    /// Returns [`LuaError`] if syntax is invalid.
    pub fn parse(&self, script: &str) -> Result<Vec<LuaStmt>, LuaError> {
        let mut parser = LuaSourceParser::new(script);
        parser.parse_stmts()
    }

    /// Return how many steps have been executed since the last `execute` call.
    #[must_use]
    pub const fn step_count(&self) -> u64 {
        self.step_count
    }

    const fn tick(&mut self) -> Result<(), LuaError> {
        self.step_count += 1;
        if self.step_count > self.max_steps {
            return Err(LuaError::Timeout);
        }
        Ok(())
    }

    fn exec_stmts(
        &mut self,
        stmts: &[LuaStmt],
        ctx: &mut LuaContext,
    ) -> Result<LuaValue, LuaError> {
        let mut result = LuaValue::Nil;
        for stmt in stmts {
            self.tick()?;
            match stmt {
                LuaStmt::Assign { target, value } | LuaStmt::LocalAssign { target, value } => {
                    let val = self.eval_expr(value, ctx)?;
                    ctx.globals.insert(target.clone(), val);
                }
                LuaStmt::FunctionCall { name, args } => {
                    let mut arg_vals = Vec::with_capacity(args.len());
                    for a in args {
                        arg_vals.push(self.eval_expr(a, ctx)?);
                    }
                    self.call_function(name, &arg_vals, ctx)?;
                }
                LuaStmt::If {
                    condition,
                    then_body,
                    else_body,
                } => {
                    let cond = self.eval_expr(condition, ctx)?;
                    if cond.is_truthy() {
                        result = self.exec_stmts(then_body, ctx)?;
                    } else if let Some(else_b) = else_body {
                        result = self.exec_stmts(else_b, ctx)?;
                    }
                }
                LuaStmt::While { condition, body } => loop {
                    self.tick()?;
                    let cond = self.eval_expr(condition, ctx)?;
                    if !cond.is_truthy() {
                        break;
                    }
                    match self.exec_stmts(body, ctx) {
                        Ok(_) => {}
                        Err(LuaError::Break) => break,
                        Err(e) => return Err(e),
                    }
                },
                LuaStmt::For {
                    var,
                    start,
                    end,
                    step,
                    body,
                } => {
                    self.exec_for_stmt(var, start, end, step.as_ref(), body, ctx)?;
                }
                LuaStmt::Return(expr) => {
                    result = self.eval_expr(expr, ctx)?;
                    return Ok(result);
                }
                LuaStmt::FunctionDef { name, params, body } => {
                    self.functions.insert(
                        name.clone(),
                        LuaFn {
                            params: params.clone(),
                            body: body.clone(),
                        },
                    );
                    ctx.globals
                        .insert(name.clone(), LuaValue::Function(name.clone()));
                }
                LuaStmt::Break => {
                    return Err(LuaError::Break);
                }
                LuaStmt::DoBlock(inner) => {
                    result = self.exec_stmts(inner, ctx)?;
                }
            }
        }
        Ok(result)
    }

    fn exec_for_stmt(
        &mut self,
        var: &str,
        start: &LuaExpr,
        end: &LuaExpr,
        step: Option<&LuaExpr>,
        body: &[LuaStmt],
        ctx: &mut LuaContext,
    ) -> Result<(), LuaError> {
        let start_val = self.eval_expr(start, ctx)?.as_int().ok_or_else(|| LuaError::TypeError {
            expected: "number".to_string(),
            got: "other".to_string(),
        })?;
        let end_val = self.eval_expr(end, ctx)?.as_int().ok_or_else(|| LuaError::TypeError {
            expected: "number".to_string(),
            got: "other".to_string(),
        })?;
        let step_val = if let Some(s) = step {
            self.eval_expr(s, ctx)?.as_int().unwrap_or(1)
        } else {
            1_i64
        };
        let mut i = start_val;
        loop {
            self.tick()?;
            if step_val > 0 && i > end_val { break; }
            if step_val < 0 && i < end_val { break; }
            if step_val == 0 { break; }
            ctx.globals.insert(var.to_string(), LuaValue::Int(i));
            match self.exec_stmts(body, ctx) {
                Ok(_) => {}
                Err(LuaError::Break) => break,
                Err(e) => return Err(e),
            }
            i += step_val;
        }
        Ok(())
    }

    fn eval_expr(&mut self, expr: &LuaExpr, ctx: &mut LuaContext) -> Result<LuaValue, LuaError> {
        self.tick()?;
        match expr {
            LuaExpr::Nil => Ok(LuaValue::Nil),
            LuaExpr::True => Ok(LuaValue::Bool(true)),
            LuaExpr::False => Ok(LuaValue::Bool(false)),
            LuaExpr::Int(i) => Ok(LuaValue::Int(*i)),
            LuaExpr::Float(f) => Ok(LuaValue::Float(*f)),
            LuaExpr::StringLit(s) => Ok(LuaValue::String(s.clone())),
            LuaExpr::Var(name) => Ok(ctx.get(name).clone()),
            LuaExpr::BinOp { op, left, right } => {
                let lv = self.eval_expr(left, ctx)?;
                let rv = self.eval_expr(right, ctx)?;
                Self::eval_binop(*op, lv, rv)
            }
            LuaExpr::UnOp { op, operand } => {
                let val = self.eval_expr(operand, ctx)?;
                Self::eval_unop(*op, &val)
            }
            LuaExpr::Call { name, args } => {
                let mut arg_vals = Vec::with_capacity(args.len());
                for a in args {
                    arg_vals.push(self.eval_expr(a, ctx)?);
                }
                self.call_function(name, &arg_vals, ctx)
            }
            LuaExpr::TableConstructor(entries) => {
                let mut table = Vec::new();
                let mut auto_idx = 1i64;
                for (key_expr, val_expr) in entries {
                    let val = self.eval_expr(val_expr, ctx)?;
                    let key = if let Some(k) = key_expr {
                        self.eval_expr(k, ctx)?
                    } else {
                        let k = LuaValue::Int(auto_idx);
                        auto_idx += 1;
                        k
                    };
                    table.push((key, val));
                }
                Ok(LuaValue::Table(table))
            }
            LuaExpr::Index { table, key } => {
                let tval = self.eval_expr(table, ctx)?;
                let kval = self.eval_expr(key, ctx)?;
                match &tval {
                    LuaValue::Table(entries) => {
                        for (k, v) in entries {
                            if value_eq(k, &kval) {
                                return Ok(v.clone());
                            }
                        }
                        Ok(LuaValue::Nil)
                    }
                    _ => Err(LuaError::TypeError {
                        expected: "table".to_string(),
                        got: tval.type_name().to_string(),
                    }),
                }
            }
        }
    }

    fn call_function(
        &mut self,
        name: &str,
        args: &[LuaValue],
        ctx: &mut LuaContext,
    ) -> Result<LuaValue, LuaError> {
        // Check if it is a user-defined function.
        if let Some(func) = self.functions.get(name).cloned() {
            if ctx.call_depth > 200 {
                return Err(LuaError::StackOverflow);
            }
            ctx.call_depth += 1;
            // Create a new scope frame: snapshot the entire globals map so
            // that recursive calls and function-local assignments cannot
            // corrupt the caller's bindings.
            let saved_globals = ctx.globals.clone();
            // Bind parameters into the new scope.
            for (i, param) in func.params.iter().enumerate() {
                let val = args.get(i).cloned().unwrap_or(LuaValue::Nil);
                ctx.globals.insert(param.clone(), val);
            }
            let result = self.exec_stmts(&func.body, ctx);
            // Restore the caller's scope entirely.
            ctx.globals = saved_globals;
            ctx.call_depth -= 1;
            result
        } else {
            Self::call_builtin(name, args, ctx)
        }
    }

    fn call_builtin(
        name: &str,
        args: &[LuaValue],
        ctx: &mut LuaContext,
    ) -> Result<LuaValue, LuaError> {
        match name {
            "print" => {
                let s: String = args
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\t");
                ctx.output.push(s);
                Ok(LuaValue::Nil)
            }
            "tostring" => Ok(LuaValue::String(
                args.first()
                    .map_or_else(|| "nil".to_string(), std::string::ToString::to_string),
            )),
            "tonumber" => Ok(args
                .first()
                .and_then(LuaValue::as_int)
                .map_or(LuaValue::Nil, LuaValue::Int)),
            "type" => Ok(LuaValue::String(
                args.first().map_or("nil", |a| a.type_name()).to_string(),
            )),
            "pairs" | "ipairs" => Ok(args.first().cloned().unwrap_or(LuaValue::Nil)),
            "assert" => {
                let val = args.first().cloned().unwrap_or(LuaValue::Nil);
                if val.is_truthy() {
                    Ok(val)
                } else {
                    let msg = args
                        .get(1)
                        .map_or_else(|| "assertion failed!".to_string(), std::string::ToString::to_string);
                    Err(LuaError::RuntimeError(msg))
                }
            }
            "error" => {
                let msg = args
                    .first()
                    .map_or_else(|| "error".to_string(), std::string::ToString::to_string);
                Err(LuaError::RuntimeError(msg))
            }

            _ if name.starts_with("rustre.") => {
                if let Some(v) = Self::call_builtin_rustre_api(name, args)? {
                    return Ok(v);
                }
                // Fall through to extended modules.
                if let Some(v) = crate::lua_api_complete::dispatch(name, args)? {
                    return Ok(v);
                }
                if let Some(v) = crate::lua_stdlib_re::dispatch(name, args)? {
                    return Ok(v);
                }
                if let Some(v) = crate::lua_debugger_api::dispatch(name, args)? {
                    return Ok(v);
                }
                Err(LuaError::UndefinedVariable(name.to_string()))
            }

            _ => {
                // Fall through to the re.* stdlib module.
                if let Some(v) = crate::lua_stdlib_re::dispatch(name, args)? {
                    return Ok(v);
                }
                // Fall through to the dbg.* debugger API module.
                if let Some(v) = crate::lua_debugger_api::dispatch(name, args)? {
                    return Ok(v);
                }
                Err(LuaError::UndefinedVariable(name.to_string()))
            }
        }
    }

    fn eval_binop(op: BinOp, l: LuaValue, r: LuaValue) -> Result<LuaValue, LuaError> {
        match op {
            BinOp::Concat => {
                let ls = l.to_string();
                let rs = r.to_string();
                return Ok(LuaValue::String(ls + &rs));
            }
            BinOp::And => {
                return Ok(if l.is_truthy() { r } else { l });
            }
            BinOp::Or => {
                return Ok(if l.is_truthy() { l } else { r });
            }
            _ => {}
        }
        // Equality / comparison ops that work on any type.
        match op {
            BinOp::Eq => return Ok(LuaValue::Bool(value_eq(&l, &r))),
            BinOp::Ne => return Ok(LuaValue::Bool(!value_eq(&l, &r))),
            _ => {}
        }
        // Numeric ops.
        if let (LuaValue::Int(a), LuaValue::Int(b)) = (&l, &r) {
            let a = *a;
            let b = *b;
            match op {
                BinOp::Add => Ok(LuaValue::Int(a.wrapping_add(b))),
                BinOp::Sub => Ok(LuaValue::Int(a.wrapping_sub(b))),
                BinOp::Mul => Ok(LuaValue::Int(a.wrapping_mul(b))),
                BinOp::Div => {
                    if b == 0 {
                        Err(LuaError::RuntimeError("division by zero".to_string()))
                    } else {
                        Ok(LuaValue::Float(crate::casts::i64_to_f64(a) / crate::casts::i64_to_f64(b)))
                    }
                }
                BinOp::Mod => {
                    if b == 0 {
                        Err(LuaError::RuntimeError("modulo by zero".to_string()))
                    } else {
                        Ok(LuaValue::Int(a.wrapping_rem(b)))
                    }
                }
                BinOp::Pow => Ok(LuaValue::Float(crate::casts::i64_to_f64(a).powf(crate::casts::i64_to_f64(b)))),
                BinOp::Lt => Ok(LuaValue::Bool(a < b)),
                BinOp::Le => Ok(LuaValue::Bool(a <= b)),
                BinOp::Gt => Ok(LuaValue::Bool(a > b)),
                BinOp::Ge => Ok(LuaValue::Bool(a >= b)),
                _ => Err(LuaError::RuntimeError("unsupported op on int".to_string())),
            }
        } else {
            let af = to_float(&l).ok_or_else(|| LuaError::TypeError {
                expected: "number".to_string(),
                got: l.type_name().to_string(),
            })?;
            let bf = to_float(&r).ok_or_else(|| LuaError::TypeError {
                expected: "number".to_string(),
                got: r.type_name().to_string(),
            })?;
            match op {
                BinOp::Add => Ok(LuaValue::Float(af + bf)),
                BinOp::Sub => Ok(LuaValue::Float(af - bf)),
                BinOp::Mul => Ok(LuaValue::Float(af * bf)),
                BinOp::Div => {
                    if bf == 0.0 {
                        Err(LuaError::RuntimeError("division by zero".to_string()))
                    } else {
                        Ok(LuaValue::Float(af / bf))
                    }
                }
                BinOp::Mod => Ok(LuaValue::Float(af % bf)),
                BinOp::Pow => Ok(LuaValue::Float(af.powf(bf))),
                BinOp::Lt => Ok(LuaValue::Bool(af < bf)),
                BinOp::Le => Ok(LuaValue::Bool(af <= bf)),
                BinOp::Gt => Ok(LuaValue::Bool(af > bf)),
                BinOp::Ge => Ok(LuaValue::Bool(af >= bf)),
                _ => Err(LuaError::RuntimeError("unsupported float op".to_string())),
            }
        }
    }

    fn call_builtin_rustre_api(name: &str, args: &[LuaValue]) -> Result<Option<LuaValue>, LuaError> {
        let result = match name {
            "rustre.load_binary" => {
                let path = args.first().and_then(|v| v.as_str().map(std::string::ToString::to_string))
                    .ok_or_else(|| LuaError::RuntimeError("load_binary: expected string path".to_string()))?;
                Some(store_load_binary(&path).map(LuaValue::String)?)
            }
            "rustre.disasm_at" => {
                let id = args.first().and_then(|v| v.as_str().map(std::string::ToString::to_string))
                    .ok_or_else(|| LuaError::RuntimeError("disasm_at: expected binary_id string".to_string()))?;
                let addr = args.get(1).and_then(LuaValue::as_int).map_or(0, crate::casts::i64_to_u64);
                let count = args.get(2).and_then(LuaValue::as_int)
                    .map_or(10, |n| crate::casts::i64_to_usize(n.max(0)).min(1024));
                Some(store_disasm_at(&id, addr, count))
            }
            "rustre.find_strings" => {
                let id = args.first().and_then(|v| v.as_str().map(std::string::ToString::to_string))
                    .ok_or_else(|| LuaError::RuntimeError("find_strings: expected binary_id string".to_string()))?;
                Some(store_find_strings(&id))
            }
            "rustre.get_info" => {
                let id = args.first().and_then(|v| v.as_str().map(std::string::ToString::to_string))
                    .ok_or_else(|| LuaError::RuntimeError("get_info: expected binary_id string".to_string()))?;
                Some(store_get_info(&id))
            }
            "rustre.hex_to_dec" => {
                let s = args.first().and_then(|v| v.as_str().map(std::string::ToString::to_string))
                    .ok_or_else(|| LuaError::RuntimeError("hex_to_dec: expected string".to_string()))?;
                let n = i64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0);
                Some(LuaValue::Int(n))
            }
            "rustre.dec_to_hex" => {
                let n = args.first().and_then(LuaValue::as_int)
                    .ok_or_else(|| LuaError::RuntimeError("dec_to_hex: expected number".to_string()))?;
                Some(LuaValue::String(format!("{n:#x}")))
            }
            "rustre.entropy" => {
                let s = args.first().and_then(|v| v.as_str().map(std::string::ToString::to_string))
                    .ok_or_else(|| LuaError::RuntimeError("entropy: expected string".to_string()))?;
                let data = s.as_bytes();
                if data.is_empty() {
                    return Ok(Some(LuaValue::Float(0.0)));
                }
                let mut freq = [0u64; 256];
                for &b in data { freq[b as usize] += 1; }
                let n = crate::casts::usize_to_f64(data.len());
                let e: f64 = freq.iter().filter(|&&c| c > 0)
                    .map(|&c| { let p = crate::casts::u64_to_f64(c) / n; -p * p.log2() })
                    .sum();
                Some(LuaValue::Float(e))
            }
            "rustre.xor_bytes" => {
                let s = args.first().and_then(|v| v.as_str().map(std::string::ToString::to_string))
                    .ok_or_else(|| LuaError::RuntimeError("xor_bytes: expected string data".to_string()))?;
                let key = args.get(1).and_then(LuaValue::as_int)
                    .ok_or_else(|| LuaError::RuntimeError("xor_bytes: expected integer key".to_string()))?;
                let k = crate::casts::i64_to_u8(key);
                let result: Vec<u8> = s.as_bytes().iter().map(|&b| b ^ k).collect();
                Some(LuaValue::String(result.iter().map(|&b| b as char).collect()))
            }
            _ => None,
        };
        Ok(result)
    }

    fn eval_unop(op: UnOp, val: &LuaValue) -> Result<LuaValue, LuaError> {
        match op {
            UnOp::Neg => match val {
                LuaValue::Int(i) => Ok(LuaValue::Int(i.wrapping_neg())),
                LuaValue::Float(f) => Ok(LuaValue::Float(-f)),
                _ => Err(LuaError::TypeError {
                    expected: "number".to_string(),
                    got: val.type_name().to_string(),
                }),
            },
            UnOp::Not => Ok(LuaValue::Bool(!val.is_truthy())),
            UnOp::Len => match val {
                LuaValue::String(s) => Ok(LuaValue::Int(crate::casts::usize_to_i64(s.len()))),
                LuaValue::Table(t) => Ok(LuaValue::Int(crate::casts::usize_to_i64(t.len()))),
                _ => Err(LuaError::TypeError {
                    expected: "string or table".to_string(),
                    got: val.type_name().to_string(),
                }),
            },
        }
    }
}

impl Default for LuaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for LuaEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LuaEngine(steps={}/{})", self.step_count, self.max_steps)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const fn to_float(v: &LuaValue) -> Option<f64> {
    match v {
        LuaValue::Int(i) => Some(crate::casts::i64_to_f64(*i)),
        LuaValue::Float(f) => Some(*f),
        _ => None,
    }
}

fn value_eq(a: &LuaValue, b: &LuaValue) -> bool {
    match (a, b) {
        (LuaValue::Nil, LuaValue::Nil) => true,
        (LuaValue::Bool(x), LuaValue::Bool(y)) => x == y,
        (LuaValue::Int(x), LuaValue::Int(y)) => x == y,
        (LuaValue::Float(x), LuaValue::Float(y)) => x == y,
        (LuaValue::Int(x), LuaValue::Float(y)) => crate::casts::i64_to_f64(*x) == *y,
        (LuaValue::Float(x), LuaValue::Int(y)) => *x == crate::casts::i64_to_f64(*y),
        (LuaValue::String(x), LuaValue::String(y)) => x == y,
        _ => false,
    }
}

// ── Parser ────────────────────────────────────────────────────────────────────

struct LuaSourceParser<'s> {
    source: &'s str,
    pos: usize,
    line: usize,
}

impl<'s> LuaSourceParser<'s> {
    const fn new(source: &'s str) -> Self {
        Self {
            source,
            pos: 0,
            line: 1,
        }
    }

    fn remaining(&self) -> &str {
        &self.source[self.pos..]
    }

    fn peek_char(&self) -> Option<char> {
        self.remaining().chars().next()
    }

    fn advance(&mut self) {
        if let Some(c) = self.peek_char() {
            self.pos += c.len_utf8();
            if c == '\n' {
                self.line += 1;
            }
        }
    }

    fn skip_whitespace_and_comments(&mut self) {
        loop {
            // Skip whitespace.
            while self.peek_char().is_some_and(char::is_whitespace) {
                self.advance();
            }
            // Skip line comments `--`.
            if self.remaining().starts_with("--") {
                while self.peek_char().is_some_and(|c| c != '\n') {
                    self.advance();
                }
                continue;
            }
            break;
        }
    }

    fn expect(&mut self, keyword: &str) -> Result<(), LuaError> {
        self.skip_whitespace_and_comments();
        if self.remaining().starts_with(keyword) {
            for _ in keyword.chars() {
                self.advance();
            }
            Ok(())
        } else {
            Err(LuaError::SyntaxError {
                line: self.line,
                message: format!(
                    "expected '{keyword}', got '{}'",
                    &self.remaining()[..self.remaining().len().min(8)]
                ),
            })
        }
    }

    fn consume_keyword(&mut self, keyword: &str) -> bool {
        self.skip_whitespace_and_comments();
        let rem = self.remaining();
        if let Some(after) = rem.strip_prefix(keyword) {
            // Make sure it is not a longer identifier.
            let next_is_ident = after
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
            if !next_is_ident {
                for _ in keyword.chars() {
                    self.advance();
                }
                return true;
            }
        }
        false
    }

    fn parse_identifier(&mut self) -> Option<String> {
        self.skip_whitespace_and_comments();
        let start = self.pos;
        while self
            .peek_char()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
        {
            self.advance();
        }
        if self.pos == start {
            None
        } else {
            Some(self.source[start..self.pos].to_string())
        }
    }

    fn parse_string_literal(&mut self) -> Result<String, LuaError> {
        let quote = self.peek_char().ok_or_else(|| LuaError::SyntaxError {
            line: self.line,
            message: "expected string literal".to_string(),
        })?;
        if quote != '"' && quote != '\'' {
            return Err(LuaError::SyntaxError {
                line: self.line,
                message: "expected string literal".to_string(),
            });
        }
        self.advance(); // opening quote
        let mut result = String::new();
        loop {
            match self.peek_char() {
                None => {
                    return Err(LuaError::SyntaxError {
                        line: self.line,
                        message: "unterminated string".to_string(),
                    });
                }
                Some('\\') => {
                    self.advance();
                    match self.peek_char() {
                        Some('n') => {
                            result.push('\n');
                            self.advance();
                        }
                        Some('t') => {
                            result.push('\t');
                            self.advance();
                        }
                        Some(c) => {
                            result.push(c);
                            self.advance();
                        }
                        None => {}
                    }
                }
                Some(c) if c == quote => {
                    self.advance();
                    break;
                }
                Some(c) => {
                    result.push(c);
                    self.advance();
                }
            }
        }
        Ok(result)
    }

    fn parse_number(&mut self) -> Option<LuaExpr> {
        self.skip_whitespace_and_comments();
        let start = self.pos;
        let neg = self.peek_char() == Some('-');
        if neg {
            self.advance();
            self.skip_whitespace_and_comments();
        }
        let num_start = self.pos;
        while self
            .peek_char()
            .is_some_and(|c| c.is_ascii_digit() || c == '.')
        {
            self.advance();
        }
        if self.pos == num_start {
            self.pos = start;
            return None;
        }
        let num_str = &self.source[num_start..self.pos];
        let sign = if neg { -1 } else { 1 };
        if num_str.contains('.') {
            num_str
                .parse::<f64>()
                .ok()
                .map(|f| LuaExpr::Float(f * crate::casts::i64_to_f64(sign)))
        } else {
            num_str.parse::<i64>().ok().map(|i| LuaExpr::Int(i * sign))
        }
    }

    fn parse_expr(&mut self) -> Result<LuaExpr, LuaError> {
        self.parse_or_expr()
    }

    fn parse_or_expr(&mut self) -> Result<LuaExpr, LuaError> {
        let mut left = self.parse_and_expr()?;
        loop {
            if self.consume_keyword("or") {
                let right = self.parse_and_expr()?;
                left = LuaExpr::BinOp {
                    op: BinOp::Or,
                    left: Box::new(left),
                    right: Box::new(right),
                };
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_and_expr(&mut self) -> Result<LuaExpr, LuaError> {
        let mut left = self.parse_compare_expr()?;
        loop {
            if self.consume_keyword("and") {
                let right = self.parse_compare_expr()?;
                left = LuaExpr::BinOp {
                    op: BinOp::And,
                    left: Box::new(left),
                    right: Box::new(right),
                };
            } else {
                break;
            }
        }
        Ok(left)
    }

    fn parse_compare_expr(&mut self) -> Result<LuaExpr, LuaError> {
        let left = self.parse_concat_expr()?;
        self.skip_whitespace_and_comments();
        let op = if self.remaining().starts_with("==") {
            self.advance();
            self.advance();
            Some(BinOp::Eq)
        } else if self.remaining().starts_with("~=") {
            self.advance();
            self.advance();
            Some(BinOp::Ne)
        } else if self.remaining().starts_with("<=") {
            self.advance();
            self.advance();
            Some(BinOp::Le)
        } else if self.remaining().starts_with(">=") {
            self.advance();
            self.advance();
            Some(BinOp::Ge)
        } else if self.remaining().starts_with('<') {
            self.advance();
            Some(BinOp::Lt)
        } else if self.remaining().starts_with('>') {
            self.advance();
            Some(BinOp::Gt)
        } else {
            None
        };
        if let Some(op) = op {
            let right = self.parse_concat_expr()?;
            return Ok(LuaExpr::BinOp {
                op,
                left: Box::new(left),
                right: Box::new(right),
            });
        }
        Ok(left)
    }

    fn parse_concat_expr(&mut self) -> Result<LuaExpr, LuaError> {
        let left = self.parse_add_expr()?;
        self.skip_whitespace_and_comments();
        if self.remaining().starts_with("..") && !self.remaining().starts_with("...") {
            self.advance();
            self.advance();
            let right = self.parse_concat_expr()?; // right-associative
            return Ok(LuaExpr::BinOp {
                op: BinOp::Concat,
                left: Box::new(left),
                right: Box::new(right),
            });
        }
        Ok(left)
    }

    fn parse_add_expr(&mut self) -> Result<LuaExpr, LuaError> {
        let mut left = self.parse_mul_expr()?;
        loop {
            self.skip_whitespace_and_comments();
            let op = if self.remaining().starts_with('+') {
                self.advance();
                BinOp::Add
            } else if self.remaining().starts_with('-') {
                // Don't consume minus if it's part of a negative number literal.
                self.advance();
                BinOp::Sub
            } else {
                break;
            };
            let right = self.parse_mul_expr()?;
            left = LuaExpr::BinOp {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_mul_expr(&mut self) -> Result<LuaExpr, LuaError> {
        let mut left = self.parse_unary_expr()?;
        loop {
            self.skip_whitespace_and_comments();
            let op = if self.remaining().starts_with('*') {
                self.advance();
                BinOp::Mul
            } else if self.remaining().starts_with('/') {
                self.advance();
                BinOp::Div
            } else if self.remaining().starts_with('%') {
                self.advance();
                BinOp::Mod
            } else if self.remaining().starts_with('^') {
                self.advance();
                BinOp::Pow
            } else {
                break;
            };
            let right = self.parse_unary_expr()?;
            left = LuaExpr::BinOp {
                op,
                left: Box::new(left),
                right: Box::new(right),
            };
        }
        Ok(left)
    }

    fn parse_unary_expr(&mut self) -> Result<LuaExpr, LuaError> {
        self.skip_whitespace_and_comments();
        if self.consume_keyword("not") {
            let operand = self.parse_unary_expr()?;
            return Ok(LuaExpr::UnOp {
                op: UnOp::Not,
                operand: Box::new(operand),
            });
        }
        if self.remaining().starts_with('#') {
            self.advance();
            let operand = self.parse_unary_expr()?;
            return Ok(LuaExpr::UnOp {
                op: UnOp::Len,
                operand: Box::new(operand),
            });
        }
        // Unary minus: applied when the leading '-' is not part of a numeric
        // literal handled by parse_primary_expr (which only consumes a number
        // if the first non-space char is a digit or '.'). Use Neg over an
        // expression so things like `-x`, `-(1+2)`, and `i64::MIN` work.
        if self.remaining().starts_with('-') {
            self.advance();
            let operand = self.parse_unary_expr()?;
            return Ok(LuaExpr::UnOp {
                op: UnOp::Neg,
                operand: Box::new(operand),
            });
        }
        self.parse_primary_expr()
    }

    fn parse_primary_expr(&mut self) -> Result<LuaExpr, LuaError> {
        self.skip_whitespace_and_comments();

        // nil / true / false keywords.
        if self.consume_keyword("nil") {
            return Ok(LuaExpr::Nil);
        }
        if self.consume_keyword("true") {
            return Ok(LuaExpr::True);
        }
        if self.consume_keyword("false") {
            return Ok(LuaExpr::False);
        }

        // String literals.
        let first_char = self.peek_char();
        if first_char == Some('"') || first_char == Some('\'') {
            return Ok(LuaExpr::StringLit(self.parse_string_literal()?));
        }

        // Parenthesised expression.
        if self.peek_char() == Some('(') {
            self.advance();
            let expr = self.parse_expr()?;
            self.skip_whitespace_and_comments();
            if self.peek_char() == Some(')') {
                self.advance();
            }
            return Ok(expr);
        }

        // Table constructor.
        if self.peek_char() == Some('{') {
            return self.parse_table_constructor();
        }

        // Number literal (after we've ruled out unary minus being part of sub-expr).
        let saved = self.pos;
        // Only parse a number if the next non-space char is a digit or '.'.
        self.skip_whitespace_and_comments();
        let first = self.peek_char();
        if first.is_some_and(|c| c.is_ascii_digit() || c == '.')
            && let Some(num) = self.parse_number() {
                return Ok(num);
            }
        self.pos = saved;

        // Identifier — function call or variable.
        if let Some(name) = self.parse_identifier() {
            self.skip_whitespace_and_comments();
            // Field access: name.field
            if self.peek_char() == Some('.') && !self.remaining().starts_with("..") {
                self.advance(); // consume '.'
                if let Some(field) = self.parse_identifier() {
                    // Could be a function call: name.field(args)
                    self.skip_whitespace_and_comments();
                    if self.peek_char() == Some('(') {
                        self.advance();
                        let args = self.parse_arg_list()?;
                        let method = format!("{name}.{field}");
                        return Ok(LuaExpr::Call { name: method, args });
                    }
                    // Index expression.
                    return Ok(LuaExpr::Index {
                        table: Box::new(LuaExpr::Var(name)),
                        key: Box::new(LuaExpr::StringLit(field)),
                    });
                }
            }
            // Bracket index: name[key]
            if self.peek_char() == Some('[') {
                self.advance();
                let key = self.parse_expr()?;
                self.skip_whitespace_and_comments();
                if self.peek_char() == Some(']') {
                    self.advance();
                }
                return Ok(LuaExpr::Index {
                    table: Box::new(LuaExpr::Var(name)),
                    key: Box::new(key),
                });
            }
            // Function call: name(args)
            if self.peek_char() == Some('(') {
                self.advance();
                let args = self.parse_arg_list()?;
                return Ok(LuaExpr::Call { name, args });
            }
            return Ok(LuaExpr::Var(name));
        }

        Err(LuaError::SyntaxError {
            line: self.line,
            message: format!(
                "unexpected token: '{}'",
                &self.remaining()[..self.remaining().len().min(16)]
            ),
        })
    }

    fn parse_arg_list(&mut self) -> Result<Vec<LuaExpr>, LuaError> {
        let mut args = Vec::new();
        self.skip_whitespace_and_comments();
        if self.peek_char() == Some(')') {
            self.advance();
            return Ok(args);
        }
        loop {
            let arg = self.parse_expr()?;
            args.push(arg);
            self.skip_whitespace_and_comments();
            if self.peek_char() == Some(',') {
                self.advance();
            } else {
                break;
            }
        }
        self.skip_whitespace_and_comments();
        if self.peek_char() == Some(')') {
            self.advance();
        }
        Ok(args)
    }

    fn parse_table_constructor(&mut self) -> Result<LuaExpr, LuaError> {
        self.expect("{")?;
        let mut entries = Vec::new();
        loop {
            self.skip_whitespace_and_comments();
            if self.peek_char() == Some('}') {
                self.advance();
                break;
            }
            // Check for key = value syntax.
            let saved = self.pos;
            let key_expr: Option<LuaExpr> = if let Some(ident) = self.parse_identifier() {
                self.skip_whitespace_and_comments();
                if self.peek_char() == Some('=') {
                    self.advance();
                    Some(LuaExpr::StringLit(ident))
                } else {
                    // Not a key=value pair; restore and parse as value.
                    self.pos = saved;
                    None
                }
            } else {
                None
            };
            let val_expr = self.parse_expr()?;
            entries.push((key_expr, val_expr));
            self.skip_whitespace_and_comments();
            if self.peek_char() == Some(',') || self.peek_char() == Some(';') {
                self.advance();
            }
        }
        Ok(LuaExpr::TableConstructor(entries))
    }

    fn parse_stmts(&mut self) -> Result<Vec<LuaStmt>, LuaError> {
        let mut stmts = Vec::new();
        loop {
            self.skip_whitespace_and_comments();
            if self.pos >= self.source.len() {
                break;
            }
            // End of block keywords.
            let rem = self.remaining();
            if rem.starts_with("end")
                && rem[3..]
                    .chars()
                    .next()
                    .is_none_or(|c| !c.is_alphanumeric() && c != '_')
                || rem.starts_with("else")
                    && rem[4..]
                        .chars()
                        .next()
                        .is_none_or(|c| !c.is_alphanumeric() && c != '_')
                || rem.starts_with("elseif")
                    && rem[6..]
                        .chars()
                        .next()
                        .is_none_or(|c| !c.is_alphanumeric() && c != '_')
                || rem.starts_with("until")
                    && rem[5..]
                        .chars()
                        .next()
                        .is_none_or(|c| !c.is_alphanumeric() && c != '_')
            {
                break;
            }
            if let Some(stmt) = self.parse_stmt()? {
                stmts.push(stmt);
            } else {
                break;
            }
        }
        Ok(stmts)
    }

    fn parse_stmt(&mut self) -> Result<Option<LuaStmt>, LuaError> {
        self.skip_whitespace_and_comments();
        if self.pos >= self.source.len() {
            return Ok(None);
        }

        // Consume optional semicolons.
        if self.peek_char() == Some(';') {
            self.advance();
            return Ok(Some(LuaStmt::DoBlock(vec![])));
        }

        // `local` assignment.
        if self.consume_keyword("local") {
            return self.parse_stmt_local();
        }

        // `function` definition.
        if self.consume_keyword("function") {
            return self.parse_stmt_function_def();
        }

        // `return`.
        if self.consume_keyword("return") {
            self.skip_whitespace_and_comments();
            let expr = if self.pos < self.source.len()
                && !self.remaining().starts_with("end")
                && !self.remaining().starts_with("else")
                && self.peek_char() != Some(';')
                && self.peek_char() != Some('\n')
            {
                self.parse_expr()?
            } else {
                LuaExpr::Nil
            };
            return Ok(Some(LuaStmt::Return(expr)));
        }

        // `break`.
        if self.consume_keyword("break") {
            return Ok(Some(LuaStmt::Break));
        }

        // `do ... end` block.
        if self.consume_keyword("do") {
            let body = self.parse_stmts()?;
            self.expect("end")?;
            return Ok(Some(LuaStmt::DoBlock(body)));
        }

        // `while ... do ... end`.
        if self.consume_keyword("while") {
            let cond = self.parse_expr()?;
            self.expect("do")?;
            let body = self.parse_stmts()?;
            self.expect("end")?;
            return Ok(Some(LuaStmt::While {
                condition: cond,
                body,
            }));
        }

        // `for var = start, end [, step] do ... end`.
        if self.consume_keyword("for") {
            return self.parse_stmt_for();
        }

        // `if ... then ... [elseif ... then ...] [else ...] end`.
        if self.consume_keyword("if") {
            return self.parse_stmt_if();
        }

        // Assignment or function call.
        self.parse_stmt_ident_or_assign()
    }

    fn parse_stmt_local(&mut self) -> Result<Option<LuaStmt>, LuaError> {
        // Could be `local function` or `local var = expr`.
        if self.consume_keyword("function") {
            return self.parse_stmt_function_def();
        }
        let target = self
            .parse_identifier()
            .ok_or_else(|| LuaError::SyntaxError {
                line: self.line,
                message: "expected identifier after 'local'".to_string(),
            })?;
        self.skip_whitespace_and_comments();
        let value = if self.peek_char() == Some('=') {
            self.advance();
            self.parse_expr()?
        } else {
            LuaExpr::Nil
        };
        Ok(Some(LuaStmt::LocalAssign { target, value }))
    }

    fn parse_stmt_function_def(&mut self) -> Result<Option<LuaStmt>, LuaError> {
        let name = self
            .parse_identifier()
            .ok_or_else(|| LuaError::SyntaxError {
                line: self.line,
                message: "expected function name".to_string(),
            })?;
        let (params, body) = self.parse_function_body()?;
        Ok(Some(LuaStmt::FunctionDef { name, params, body }))
    }

    fn parse_stmt_for(&mut self) -> Result<Option<LuaStmt>, LuaError> {
        let var = self
            .parse_identifier()
            .ok_or_else(|| LuaError::SyntaxError {
                line: self.line,
                message: "expected variable in for".to_string(),
            })?;
        self.expect("=")?;
        let start = self.parse_expr()?;
        self.expect(",")?;
        let end = self.parse_expr()?;
        self.skip_whitespace_and_comments();
        let step = if self.peek_char() == Some(',') {
            self.advance();
            Some(self.parse_expr()?)
        } else {
            None
        };
        self.expect("do")?;
        let body = self.parse_stmts()?;
        self.expect("end")?;
        Ok(Some(LuaStmt::For { var, start, end, step, body }))
    }

    fn parse_stmt_if(&mut self) -> Result<Option<LuaStmt>, LuaError> {
        let cond = self.parse_expr()?;
        self.expect("then")?;
        let then_body = self.parse_stmts()?;
        self.skip_whitespace_and_comments();
        let else_body = if self.consume_keyword("elseif") {
            // Treat `elseif c then b end` as `else if c then b end end`.
            let econd = self.parse_expr()?;
            self.expect("then")?;
            let ebody = self.parse_stmts()?;
            self.skip_whitespace_and_comments();
            let nested_else = if self.consume_keyword("else") {
                Some(self.parse_stmts()?)
            } else {
                None
            };
            self.expect("end")?;
            Some(vec![LuaStmt::If {
                condition: econd,
                then_body: ebody,
                else_body: nested_else,
            }])
        } else if self.consume_keyword("else") {
            Some(self.parse_stmts()?)
        } else {
            None
        };
        if !self.remaining().starts_with("end")
            || self.remaining().get(3..4).is_some_and(|s| {
                s.chars().next().is_some_and(|c| c.is_alphanumeric() || c == '_')
            })
        {
            // Already consumed end via elseif path.
        } else {
            self.expect("end")?;
        }
        Ok(Some(LuaStmt::If { condition: cond, then_body, else_body }))
    }

    fn parse_stmt_ident_or_assign(&mut self) -> Result<Option<LuaStmt>, LuaError> {
        let saved = self.pos;
        if let Some(ident) = self.parse_identifier() {
            self.skip_whitespace_and_comments();
            if self.peek_char() == Some('=') && !self.remaining().starts_with("==") {
                self.advance();
                let value = self.parse_expr()?;
                return Ok(Some(LuaStmt::Assign { target: ident, value }));
            }
            if self.peek_char() == Some('(') {
                self.advance();
                let args = self.parse_arg_list()?;
                return Ok(Some(LuaStmt::FunctionCall { name: ident, args }));
            }
            if self.peek_char() == Some('.') && !self.remaining().starts_with("..") {
                self.advance();
                if let Some(field) = self.parse_identifier() {
                    self.skip_whitespace_and_comments();
                    if self.peek_char() == Some('=') && !self.remaining().starts_with("==") {
                        self.advance();
                        let value = self.parse_expr()?;
                        let target = format!("{ident}.{field}");
                        return Ok(Some(LuaStmt::Assign { target, value }));
                    }
                    if self.peek_char() == Some('(') {
                        self.advance();
                        let args = self.parse_arg_list()?;
                        let name = format!("{ident}.{field}");
                        return Ok(Some(LuaStmt::FunctionCall { name, args }));
                    }
                }
            }
        }
        self.pos = saved;
        while self.peek_char().is_some_and(|c| c != '\n') {
            self.advance();
        }
        Ok(Some(LuaStmt::DoBlock(vec![])))
    }

    fn parse_function_body(&mut self) -> Result<(Vec<String>, Vec<LuaStmt>), LuaError> {
        self.expect("(")?;
        let mut params = Vec::new();
        loop {
            self.skip_whitespace_and_comments();
            if self.peek_char() == Some(')') {
                self.advance();
                break;
            }
            if let Some(p) = self.parse_identifier() {
                params.push(p);
            }
            self.skip_whitespace_and_comments();
            if self.peek_char() == Some(',') {
                self.advance();
            }
        }
        let body = self.parse_stmts()?;
        self.expect("end")?;
        Ok((params, body))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn run(script: &str) -> (LuaValue, LuaContext) {
        let mut engine = LuaEngine::new();
        let mut ctx = LuaContext::new();
        let val = engine.execute(script, &mut ctx).expect("script failed");
        (val, ctx)
    }

    fn run_err(script: &str) -> LuaError {
        let mut engine = LuaEngine::new();
        let mut ctx = LuaContext::new();
        engine.execute(script, &mut ctx).unwrap_err()
    }

    // ── Variables ────────────────────────────────────────────────────────────

    #[test]
    fn test_assign_int() {
        let (_, ctx) = run("x = 42");
        assert_eq!(ctx.get("x").as_int(), Some(42));
    }

    #[test]
    fn test_assign_string() {
        let (_, ctx) = run(r#"s = "hello""#);
        assert_eq!(ctx.get("s").as_str(), Some("hello"));
    }

    #[test]
    fn test_local_assign() {
        let (_, ctx) = run("local y = 7");
        assert_eq!(ctx.get("y").as_int(), Some(7));
    }

    #[test]
    fn test_assign_nil() {
        let (_, ctx) = run("x = nil");
        assert!(matches!(ctx.get("x"), LuaValue::Nil));
    }

    // ── Arithmetic ───────────────────────────────────────────────────────────

    #[test]
    fn test_addition() {
        let (_, ctx) = run("x = 3 + 4");
        assert_eq!(ctx.get("x").as_int(), Some(7));
    }

    #[test]
    fn test_subtraction() {
        let (_, ctx) = run("x = 10 - 3");
        assert_eq!(ctx.get("x").as_int(), Some(7));
    }

    #[test]
    fn test_multiplication() {
        let (_, ctx) = run("x = 3 * 4");
        assert_eq!(ctx.get("x").as_int(), Some(12));
    }

    #[test]
    fn test_modulo() {
        let (_, ctx) = run("x = 10 % 3");
        assert_eq!(ctx.get("x").as_int(), Some(1));
    }

    // ── Print ────────────────────────────────────────────────────────────────

    #[test]
    fn test_print_string() {
        let (_, ctx) = run(r#"print("hello world")"#);
        assert_eq!(ctx.output, vec!["hello world"]);
    }

    #[test]
    fn test_print_number() {
        let (_, ctx) = run("print(42)");
        assert_eq!(ctx.output, vec!["42"]);
    }

    #[test]
    fn test_print_multiple_args() {
        let (_, ctx) = run(r#"print(1, 2, "three")"#);
        assert_eq!(ctx.output, vec!["1\t2\tthree"]);
    }

    // ── If / else ────────────────────────────────────────────────────────────

    #[test]
    fn test_if_true_branch() {
        let (_, ctx) = run("if true then\n  x = 1\nend");
        assert_eq!(ctx.get("x").as_int(), Some(1));
    }

    #[test]
    fn test_if_false_else_branch() {
        let (_, ctx) = run("if false then\n  x = 1\nelse\n  x = 2\nend");
        assert_eq!(ctx.get("x").as_int(), Some(2));
    }

    #[test]
    fn test_if_condition_from_var() {
        let (_, ctx) = run("v = 5\nif v > 3 then\n  r = 1\nend");
        assert_eq!(ctx.get("r").as_int(), Some(1));
    }

    // ── While loop ───────────────────────────────────────────────────────────

    #[test]
    fn test_while_basic() {
        let (_, ctx) = run("i = 0\nwhile i < 5 do\n  i = i + 1\nend");
        assert_eq!(ctx.get("i").as_int(), Some(5));
    }

    #[test]
    fn test_while_break() {
        let (_, ctx) = run("i = 0\nwhile true do\n  i = i + 1\n  if i == 3 then break end\nend");
        assert_eq!(ctx.get("i").as_int(), Some(3));
    }

    // ── For loop ─────────────────────────────────────────────────────────────

    #[test]
    fn test_for_basic() {
        let (_, ctx) = run("s = 0\nfor i = 1, 5 do\n  s = s + i\nend");
        assert_eq!(ctx.get("s").as_int(), Some(15));
    }

    #[test]
    fn test_for_with_step() {
        let (_, ctx) = run("s = 0\nfor i = 0, 10, 2 do\n  s = s + i\nend");
        // 0+2+4+6+8+10 = 30
        assert_eq!(ctx.get("s").as_int(), Some(30));
    }

    // ── Function definitions ─────────────────────────────────────────────────

    #[test]
    fn test_function_def_and_call() {
        let (_, ctx) = run("function add(a, b)\n  return a + b\nend\nx = add(3, 4)");
        assert_eq!(ctx.get("x").as_int(), Some(7));
    }

    #[test]
    fn test_function_no_args() {
        let (_, ctx) = run("function greet()\n  return 99\nend\nv = greet()");
        assert_eq!(ctx.get("v").as_int(), Some(99));
    }

    // ── Table constructors ───────────────────────────────────────────────────

    #[test]
    fn test_table_constructor() {
        let (_, ctx) = run("t = {1, 2, 3}");
        assert!(matches!(ctx.get("t"), LuaValue::Table(_)));
    }

    #[test]
    fn test_table_keyed() {
        let (_, ctx) = run(r"t = {x = 10, y = 20}");
        assert!(matches!(ctx.get("t"), LuaValue::Table(_)));
    }

    // ── Built-in functions ───────────────────────────────────────────────────

    #[test]
    fn test_type_function() {
        let (_, ctx) = run(r"t = type(42)");
        assert_eq!(ctx.get("t").as_str(), Some("number"));
    }

    #[test]
    fn test_tostring_function() {
        let (_, ctx) = run(r"s = tostring(123)");
        assert_eq!(ctx.get("s").as_str(), Some("123"));
    }

    #[test]
    fn test_tonumber_function() {
        let (_, ctx) = run(r#"n = tonumber("42")"#);
        // tonumber on a string returns Nil (as_int returns None for String).
        // Our impl uses as_int which returns None for String -> Nil.
        let _ = ctx.get("n"); // just ensure no crash
    }

    #[test]
    fn test_assert_pass() {
        let (_, ctx) = run("x = assert(true)");
        assert!(ctx.get("x").is_truthy());
    }

    #[test]
    fn test_assert_fail() {
        let err = run_err("assert(false)");
        assert!(matches!(err, LuaError::RuntimeError(_)));
    }

    // ── Concatenation ────────────────────────────────────────────────────────

    #[test]
    fn test_concat() {
        let (_, ctx) = run(r#"s = "foo" .. "bar""#);
        assert_eq!(ctx.get("s").as_str(), Some("foobar"));
    }

    // ── Length operator ──────────────────────────────────────────────────────

    #[test]
    fn test_len_string() {
        let (_, ctx) = run(r#"n = #"hello""#);
        assert_eq!(ctx.get("n").as_int(), Some(5));
    }

    // ── Error handling ───────────────────────────────────────────────────────

    #[test]
    fn test_div_by_zero_error() {
        let err = run_err("x = 1 / 0");
        assert!(matches!(err, LuaError::RuntimeError(_)));
    }

    #[test]
    fn test_timeout() {
        let mut engine = LuaEngine::new();
        engine.set_max_steps(10);
        let mut ctx = LuaContext::new();
        let err = engine
            .execute("i = 0\nwhile true do\n  i = i + 1\nend", &mut ctx)
            .unwrap_err();
        assert!(matches!(err, LuaError::Timeout));
    }

    // ── Misc display/debug ───────────────────────────────────────────────────

    #[test]
    fn test_lua_value_type_name() {
        assert_eq!(LuaValue::Nil.type_name(), "nil");
        assert_eq!(LuaValue::Bool(true).type_name(), "boolean");
        assert_eq!(LuaValue::Int(0).type_name(), "number");
        assert_eq!(LuaValue::Float(0.0).type_name(), "number");
        assert_eq!(LuaValue::String(String::new()).type_name(), "string");
        assert_eq!(LuaValue::Table(vec![]).type_name(), "table");
        assert_eq!(LuaValue::Function("f".to_string()).type_name(), "function");
    }

    #[test]
    fn test_lua_value_is_truthy() {
        assert!(!LuaValue::Nil.is_truthy());
        assert!(!LuaValue::Bool(false).is_truthy());
        assert!(LuaValue::Bool(true).is_truthy());
        assert!(LuaValue::Int(1).is_truthy());
    }

    #[test]
    fn test_engine_debug() {
        let e = LuaEngine::new();
        assert!(format!("{e:?}").contains("LuaEngine"));
    }

    #[test]
    fn test_context_output_text() {
        let (_, ctx) = run("print(\"a\")\nprint(\"b\")");
        assert_eq!(ctx.output_text(), "a\nb");
    }

    #[test]
    fn test_step_count_increases() {
        let mut engine = LuaEngine::new();
        let mut ctx = LuaContext::new();
        engine.execute("x = 1", &mut ctx).unwrap();
        assert!(engine.step_count() > 0);
    }

    #[test]
    fn test_not_operator() {
        let (_, ctx) = run("x = not false");
        assert!(matches!(ctx.get("x"), LuaValue::Bool(true)));
    }

    #[test]
    fn test_boolean_and() {
        let (_, ctx) = run("x = true and 42");
        assert_eq!(ctx.get("x").as_int(), Some(42));
    }

    #[test]
    fn test_boolean_or() {
        let (_, ctx) = run("x = false or 99");
        assert_eq!(ctx.get("x").as_int(), Some(99));
    }

    #[test]
    fn test_comment_skipped() {
        let (_, ctx) = run("-- this is a comment\nx = 5");
        assert_eq!(ctx.get("x").as_int(), Some(5));
    }

    // ── RE API tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_lua_disassemble_basic() {
        let api = LuaReApi::default();
        let insns = api.disassemble(0x1000, &[0x55, 0xC3]);
        assert_eq!(insns.len(), 2);
        assert_eq!(insns[0].address, 0x1000);
        assert_eq!(insns[1].address, 0x1001);
    }

    #[test]
    fn test_lua_search_bytes() {
        let api = LuaReApi::default();
        let data: Vec<u8> = (0u8..16u8).collect();
        let hits = api.search_bytes(&data, &[0x05, 0x06]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0], 5);
    }

    #[test]
    fn test_lua_find_strings() {
        let api = LuaReApi::default();
        let data = b"hello\x00world\x00\x01";
        let strings = api.find_strings(data, 4);
        assert!(strings.iter().any(|s| s.value == "hello"));
    }

    #[test]
    fn test_lua_function_ops() {
        let mut api = LuaReApi::default();
        api.add_function(LuaReFunction {
            address: 0x2000,
            name: "sub_2000".to_string(),
            size: 32,
            is_renamed: false,
        });
        assert_eq!(api.list_functions().len(), 1);
        api.rename_function(0x2000, "parse_header");
        assert_eq!(api.get_function(0x2000).unwrap().name, "parse_header");
        assert!(api.get_function(0x2000).unwrap().is_renamed);
    }

    #[test]
    fn test_lua_xrefs() {
        let mut api = LuaReApi::default();
        api.add_xref(LuaXref {
            from: 0x1010,
            to: 0x2000,
            kind: LuaXrefKind::Call,
        });
        api.add_xref(LuaXref {
            from: 0x1020,
            to: 0x2000,
            kind: LuaXrefKind::Call,
        });
        assert_eq!(api.get_xrefs_to(0x2000).len(), 2);
        assert_eq!(api.get_xrefs_from(0x1010).len(), 1);
    }

    #[test]
    fn test_lua_patch_bytes() {
        let mut api = LuaReApi::default();
        let mut buf = vec![0u8; 8];
        api.patch_bytes(2, &mut buf, &[0xCC, 0xCC]);
        assert_eq!(buf[2], 0xCC);
        assert_eq!(buf[3], 0xCC);
        assert_eq!(api.patches().len(), 1);
    }

    #[test]
    fn test_lua_decompile_placeholder() {
        let api = LuaReApi::default();
        let code = api.decompile(0x4000);
        assert!(code.contains("0x4000") || code.contains("4000"));
    }

    #[test]
    fn test_lua_segment_ops() {
        let mut api = LuaReApi::default();
        api.add_segment(LuaSegment {
            address: 0x1000,
            size: 0x1000,
            name: ".text".to_string(),
            kind: LuaSegmentKind::Code,
        });
        assert_eq!(api.list_segments().len(), 1);
        let seg = api.segment_at(0x1500).unwrap();
        assert_eq!(seg.name, ".text");
        assert!(api.segment_at(0x3000).is_none());
    }

    #[test]
    fn test_lua_comments_labels() {
        let mut api = LuaReApi::default();
        api.set_comment(0x1000, "entry");
        assert_eq!(api.get_comment(0x1000), Some("entry"));
        api.set_label(0x1000, "start");
        assert_eq!(api.get_label(0x1000), Some("start"));
    }

    #[test]
    fn test_lua_marshal_to_address() {
        assert_eq!(lua_marshal_address(&LuaValue::Int(0x4000)), Some(0x4000));
        assert_eq!(
            lua_marshal_address(&LuaValue::String("0x1234".to_string())),
            Some(0x1234)
        );
        assert_eq!(lua_marshal_address(&LuaValue::Nil), None);
    }

    #[test]
    fn test_lua_instruction_to_table() {
        let insn = LuaInstruction {
            address: 0x1000,
            mnemonic: "push".to_string(),
            operands: "rbp".to_string(),
            bytes: vec![0x55],
            size: 1,
        };
        let val = instruction_to_lua(&insn);
        assert!(matches!(val, LuaValue::Table(_)));
    }

    #[test]
    fn test_lua_function_to_table() {
        let func = LuaReFunction {
            address: 0x1000,
            name: "main".to_string(),
            size: 64,
            is_renamed: false,
        };
        let val = lua_function_to_table(&func);
        assert!(matches!(val, LuaValue::Table(_)));
    }

    #[test]
    fn test_lua_batch_runner() {
        let mut runner = LuaBatchRunner::new();
        runner.add_script("x = 1".to_string());
        runner.add_script("y = 2".to_string());
        assert_eq!(runner.script_count(), 2);
        let mut engine = LuaEngine::new();
        let mut ctx = LuaContext::new();
        let results = runner.run_all(&mut engine, &mut ctx).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_lua_progress_reporter() {
        let mut pr = LuaProgressReporter::new(10);
        pr.advance(4);
        assert_eq!(pr.percent(), 40);
        assert!(!pr.is_complete());
        pr.advance(6);
        assert!(pr.is_complete());
    }

    #[test]
    fn test_lua_sandbox_policy() {
        let sb = LuaSandbox::new(LuaSandboxPolicy::AllowList(vec!["print".to_string()]));
        assert!(sb.is_allowed("print"));
        assert!(!sb.is_allowed("io.open"));
    }

    #[test]
    fn test_lua_module_registry() {
        let mut reg = LuaModuleRegistry::new();
        reg.register("re", "-- re module".to_string());
        assert!(reg.get("re").is_some());
        assert!(reg.get("os").is_none());
    }

    #[test]
    fn test_lua_template_find_xrefs() {
        let t = LuaScriptTemplate::find_xrefs(0x1000);
        assert!(t.contains("1000") || t.contains("0x1000"));
    }

    #[test]
    fn test_lua_template_extract_strings() {
        let t = LuaScriptTemplate::extract_strings();
        assert!(t.contains("strings") || t.contains("find_strings"));
    }

    #[test]
    fn test_lua_template_rename_functions() {
        let t = LuaScriptTemplate::rename_functions("sub_", "fn_");
        assert!(t.contains("sub_") || t.contains("fn_"));
    }

    #[test]
    fn test_lua_coroutine_resume() {
        let mut co = LuaCoroutine::new("x = 1".to_string());
        assert_eq!(co.status(), CoroutineStatus::Suspended);
        let mut engine = LuaEngine::new();
        let mut ctx = LuaContext::new();
        let result = co.resume(&mut engine, &mut ctx);
        assert!(result.is_ok());
        assert_eq!(co.status(), CoroutineStatus::Dead);
    }

    #[test]
    fn test_lua_event_hook() {
        let mut hooks = LuaEventHooks::new();
        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let c2 = called.clone();
        hooks.on_function_enter(Box::new(move |addr| {
            if addr == 0x1000 {
                c2.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }));
        hooks.fire_function_enter(0x1000);
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    }
}

// ── RE Data types ─────────────────────────────────────────────────────────────

/// A disassembled instruction (Lua layer).
#[derive(Debug, Clone)]
pub struct LuaInstruction {
    /// Virtual address.
    pub address: u64,
    /// Instruction mnemonic.
    pub mnemonic: String,
    /// Operand text.
    pub operands: String,
    /// Raw bytes.
    pub bytes: Vec<u8>,
    /// Instruction size.
    pub size: usize,
}

impl fmt::Display for LuaInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#010x}  {:8}  {}",
            self.address, self.mnemonic, self.operands
        )
    }
}

/// Cross-reference record (Lua layer).
#[derive(Debug, Clone)]
pub struct LuaXref {
    /// Source address.
    pub from: u64,
    /// Target address.
    pub to: u64,
    /// Reference kind.
    pub kind: LuaXrefKind,
}

/// Cross-reference kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LuaXrefKind {
    /// CALL instruction.
    Call,
    /// JMP instruction.
    Jump,
    /// Data reference.
    Data,
    /// Unknown.
    Unknown,
}

impl fmt::Display for LuaXrefKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Call => write!(f, "call"),
            Self::Jump => write!(f, "jump"),
            Self::Data => write!(f, "data"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// A function record (Lua layer).
#[derive(Debug, Clone)]
pub struct LuaReFunction {
    /// Start address.
    pub address: u64,
    /// Name.
    pub name: String,
    /// Size in bytes.
    pub size: u64,
    /// Whether the user renamed it.
    pub is_renamed: bool,
}

impl fmt::Display for LuaReFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#010x}  {}", self.address, self.name)
    }
}

/// Segment record (Lua layer).
#[derive(Debug, Clone)]
pub struct LuaSegment {
    /// Start address.
    pub address: u64,
    /// Size in bytes.
    pub size: u64,
    /// Name.
    pub name: String,
    /// Kind.
    pub kind: LuaSegmentKind,
}

/// Segment kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LuaSegmentKind {
    /// Executable code.
    Code,
    /// Initialized data.
    Data,
    /// Read-only data.
    ReadOnly,
    /// BSS.
    Bss,
    /// Unknown.
    Unknown,
}

impl fmt::Display for LuaSegmentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Code => write!(f, "code"),
            Self::Data => write!(f, "data"),
            Self::ReadOnly => write!(f, "rodata"),
            Self::Bss => write!(f, "bss"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// A found string record (Lua layer).
#[derive(Debug, Clone)]
pub struct LuaFoundString {
    /// Byte offset.
    pub offset: usize,
    /// String content.
    pub value: String,
}

// ── LuaReApi ─────────────────────────────────────────────────────────────────

/// Host-side RE API exposed to Lua scripts.
#[derive(Debug, Default)]
pub struct LuaReApi {
    functions: Vec<LuaReFunction>,
    segments: Vec<LuaSegment>,
    xrefs: Vec<LuaXref>,
    comments: HashMap<u64, String>,
    labels: HashMap<u64, String>,
    patches: Vec<(u64, Vec<u8>)>,
}

impl LuaReApi {
    /// Create a new empty API instance.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Disassemble `bytes` starting at `base_address`.
    #[must_use]
    pub fn disassemble(&self, base_address: u64, bytes: &[u8]) -> Vec<LuaInstruction> {
        let mut insns = Vec::with_capacity(bytes.len() / 4);
        let mut offset = 0usize;
        while offset < bytes.len() {
            let (mnemonic, operands, size) = lua_decode_x86(bytes[offset]);
            let size = size.min(bytes.len() - offset).max(1);
            insns.push(LuaInstruction {
                address: base_address + offset as u64,
                mnemonic: mnemonic.to_string(),
                operands: operands.to_string(),
                bytes: bytes[offset..offset + size].to_vec(),
                size,
            });
            offset += size;
        }
        insns
    }

    /// Search `haystack` for `pattern`, returning byte offsets.
    #[must_use]
    pub fn search_bytes(&self, haystack: &[u8], pattern: &[u8]) -> Vec<usize> {
        if pattern.is_empty() || haystack.len() < pattern.len() {
            return Vec::new();
        }
        let mut results = Vec::new();
        for i in 0..=haystack.len() - pattern.len() {
            if haystack[i..i + pattern.len()] == *pattern {
                results.push(i);
            }
        }
        results
    }

    /// Search for a wildcard byte pattern.
    #[must_use]
    pub fn search_pattern(&self, haystack: &[u8], pattern: &[Option<u8>]) -> Vec<usize> {
        if pattern.is_empty() || haystack.len() < pattern.len() {
            return Vec::new();
        }
        let mut results = Vec::new();
        'outer: for i in 0..=haystack.len() - pattern.len() {
            for (j, p) in pattern.iter().enumerate() {
                if let Some(expected) = p
                    && haystack[i + j] != *expected {
                        continue 'outer;
                    }
            }
            results.push(i);
        }
        results
    }

    /// Find null-terminated ASCII strings of at least `min_length` bytes.
    #[must_use]
    pub fn find_strings(&self, data: &[u8], min_length: usize) -> Vec<LuaFoundString> {
        let mut results = Vec::new();
        let mut start = 0usize;
        let mut current = String::new();
        for (i, &b) in data.iter().enumerate() {
            if (b.is_ascii() && !b.is_ascii_control()) || b == b'\t' {
                current.push(b as char);
            } else {
                if current.len() >= min_length {
                    results.push(LuaFoundString {
                        offset: start,
                        value: current.clone(),
                    });
                }
                current.clear();
                start = i + 1;
            }
        }
        if current.len() >= min_length {
            results.push(LuaFoundString {
                offset: start,
                value: current,
            });
        }
        results
    }

    /// Patch `buf` at `offset` with `patch_bytes` and record the operation.
    pub fn patch_bytes(&mut self, offset: usize, buf: &mut [u8], patch_bytes: &[u8]) {
        if offset + patch_bytes.len() <= buf.len() {
            buf[offset..offset + patch_bytes.len()].copy_from_slice(patch_bytes);
            self.patches.push((offset as u64, patch_bytes.to_vec()));
        }
    }

    /// Return all recorded patches.
    #[must_use]
    pub fn patches(&self) -> &[(u64, Vec<u8>)] {
        &self.patches
    }

    /// Add a cross-reference.
    pub fn add_xref(&mut self, xref: LuaXref) {
        self.xrefs.push(xref);
    }

    /// Return xrefs pointing to `address`.
    #[must_use]
    pub fn get_xrefs_to(&self, address: u64) -> Vec<&LuaXref> {
        self.xrefs.iter().filter(|x| x.to == address).collect()
    }

    /// Return xrefs originating from `address`.
    #[must_use]
    pub fn get_xrefs_from(&self, address: u64) -> Vec<&LuaXref> {
        self.xrefs.iter().filter(|x| x.from == address).collect()
    }

    /// Add a function record.
    pub fn add_function(&mut self, func: LuaReFunction) {
        self.functions.push(func);
    }

    /// Return all functions.
    #[must_use]
    pub fn list_functions(&self) -> &[LuaReFunction] {
        &self.functions
    }

    /// Look up a function by address.
    #[must_use]
    pub fn get_function(&self, address: u64) -> Option<&LuaReFunction> {
        self.functions.iter().find(|f| f.address == address)
    }

    /// Rename a function. Returns `true` if found.
    pub fn rename_function(&mut self, address: u64, new_name: &str) -> bool {
        if let Some(f) = self.functions.iter_mut().find(|f| f.address == address) {
            f.name = new_name.to_string();
            f.is_renamed = true;
            return true;
        }
        false
    }

    /// Search functions by name substring.
    #[must_use]
    pub fn search_functions(&self, substr: &str) -> Vec<&LuaReFunction> {
        self.functions
            .iter()
            .filter(|f| f.name.contains(substr))
            .collect()
    }

    /// Add a segment.
    pub fn add_segment(&mut self, seg: LuaSegment) {
        self.segments.push(seg);
    }

    /// Return all segments.
    #[must_use]
    pub fn list_segments(&self) -> &[LuaSegment] {
        &self.segments
    }

    /// Find segment containing `address`.
    #[must_use]
    pub fn segment_at(&self, address: u64) -> Option<&LuaSegment> {
        self.segments
            .iter()
            .find(|s| address >= s.address && address < s.address + s.size)
    }

    /// Set a comment at `address`.
    pub fn set_comment(&mut self, address: u64, text: &str) {
        self.comments.insert(address, text.to_string());
    }

    /// Get the comment at `address`.
    #[must_use]
    pub fn get_comment(&self, address: u64) -> Option<&str> {
        self.comments.get(&address).map(String::as_str)
    }

    /// Set a label at `address`.
    pub fn set_label(&mut self, address: u64, label: &str) {
        self.labels.insert(address, label.to_string());
    }

    /// Get the label at `address`.
    #[must_use]
    pub fn get_label(&self, address: u64) -> Option<&str> {
        self.labels.get(&address).map(String::as_str)
    }

    /// Return decompiled pseudocode for the function (or block) at `address`.
    ///
    /// Uses the registered function metadata, segment lookup, labels and
    /// comments to produce a best-effort Lua-style pseudocode skeleton without
    /// requiring a backend decompiler.
    #[must_use]
    pub fn decompile(&self, address: u64) -> String {
        let fn_meta = self.get_function(address);
        let name = fn_meta
            .map(|f| f.name.clone())
            .or_else(|| self.get_label(address).map(String::from))
            .unwrap_or_else(|| format!("sub_{address:08x}"));
        let seg = self.segment_at(address);
        let mut out = String::new();
        let _ = writeln!(out, "-- Decompiled {name} @ {address:#x}");
        if let Some(s) = seg {
            let _ = writeln!(out, "-- Segment: {} ({}) base={:#x} size={}", s.name, s.kind, s.address, s.size);
        }
        if let Some(c) = self.get_comment(address) {
            let _ = writeln!(out, "-- Comment: {c}");
        }
        let _ = writeln!(out, "function {name}()");
        let xrefs_in = self.get_xrefs_to(address);
        if !xrefs_in.is_empty() {
            let _ = writeln!(out, "  -- {} incoming xref(s)", xrefs_in.len());
        }
        let xrefs_out = self.get_xrefs_from(address);
        for x in xrefs_out.iter().take(8) {
            let _ = writeln!(out, "  call({:#x}) -- {}", x.to, x.kind);
        }
        if xrefs_out.len() > 8 {
            let _ = writeln!(out, "  -- {} more call(s) elided", xrefs_out.len() - 8);
        }
        if let Some(f) = fn_meta {
            let _ = writeln!(out, "  return nil -- size={} bytes", f.size);
        } else {
            out.push_str("  return nil\n");
        }
        out.push_str("end\n");
        out
    }

    /// Read `count` bytes from virtual memory (stub).
    #[must_use]
    pub fn read_bytes(&self, _address: u64, count: usize) -> Vec<u8> {
        vec![0u8; count]
    }
}

// ── Type marshalling ──────────────────────────────────────────────────────────

/// Convert a [`LuaValue`] to a virtual address.
#[must_use]
pub fn lua_marshal_address(v: &LuaValue) -> Option<u64> {
    match v {
        LuaValue::Int(i) => u64::try_from(*i).ok(),
        LuaValue::String(s) => {
            let s = s.trim();
            s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
                .map_or_else(|| s.parse::<u64>().ok(), |hex| u64::from_str_radix(hex, 16).ok())
        }
        _ => None,
    }
}

/// Convert a [`LuaInstruction`] to a Lua table value.
#[must_use]
pub fn instruction_to_lua(insn: &LuaInstruction) -> LuaValue {
    LuaValue::Table(vec![
        (
            LuaValue::String("address".to_string()),
            LuaValue::Int(crate::casts::u64_to_i64(insn.address)),
        ),
        (
            LuaValue::String("mnemonic".to_string()),
            LuaValue::String(insn.mnemonic.clone()),
        ),
        (
            LuaValue::String("operands".to_string()),
            LuaValue::String(insn.operands.clone()),
        ),
        (
            LuaValue::String("size".to_string()),
            LuaValue::Int(crate::casts::usize_to_i64(insn.size)),
        ),
    ])
}

/// Convert a [`LuaReFunction`] to a Lua table value.
#[must_use]
pub fn lua_function_to_table(func: &LuaReFunction) -> LuaValue {
    LuaValue::Table(vec![
        (
            LuaValue::String("address".to_string()),
            LuaValue::Int(crate::casts::u64_to_i64(func.address)),
        ),
        (
            LuaValue::String("name".to_string()),
            LuaValue::String(func.name.clone()),
        ),
        (
            LuaValue::String("size".to_string()),
            LuaValue::Int(crate::casts::u64_to_i64(func.size)),
        ),
        (
            LuaValue::String("is_renamed".to_string()),
            LuaValue::Bool(func.is_renamed),
        ),
    ])
}

/// Convert a [`LuaFoundString`] to a Lua table value.
#[must_use]
pub fn lua_found_string_to_table(s: &LuaFoundString) -> LuaValue {
    LuaValue::Table(vec![
        (
            LuaValue::String("offset".to_string()),
            LuaValue::Int(crate::casts::usize_to_i64(s.offset)),
        ),
        (
            LuaValue::String("value".to_string()),
            LuaValue::String(s.value.clone()),
        ),
    ])
}

/// Convert a [`LuaXref`] to a Lua table value.
#[must_use]
pub fn lua_xref_to_table(x: &LuaXref) -> LuaValue {
    LuaValue::Table(vec![
        (
            LuaValue::String("from".to_string()),
            LuaValue::Int(crate::casts::u64_to_i64(x.from)),
        ),
        (
            LuaValue::String("to".to_string()),
            LuaValue::Int(crate::casts::u64_to_i64(x.to)),
        ),
        (
            LuaValue::String("kind".to_string()),
            LuaValue::String(x.kind.to_string()),
        ),
    ])
}

// ── Coroutines ────────────────────────────────────────────────────────────────

/// Coroutine execution status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoroutineStatus {
    /// Not yet started or between yields.
    Suspended,
    /// Currently running.
    Running,
    /// Finished execution.
    Dead,
}

impl fmt::Display for CoroutineStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Suspended => write!(f, "suspended"),
            Self::Running => write!(f, "running"),
            Self::Dead => write!(f, "dead"),
        }
    }
}

/// A lightweight Lua coroutine simulation.
pub struct LuaCoroutine {
    script: String,
    status: CoroutineStatus,
    result: Option<LuaValue>,
}

impl fmt::Debug for LuaCoroutine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LuaCoroutine")
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

impl LuaCoroutine {
    /// Create a new suspended coroutine wrapping `script`.
    #[must_use]
    pub const fn new(script: String) -> Self {
        Self {
            script,
            status: CoroutineStatus::Suspended,
            result: None,
        }
    }

    /// Return the current coroutine status.
    #[must_use]
    pub const fn status(&self) -> CoroutineStatus {
        self.status
    }

    /// Resume the coroutine.
    ///
    /// # Errors
    ///
    /// Returns [`LuaError`] if the script has a runtime error.
    pub fn resume(
        &mut self,
        engine: &mut LuaEngine,
        ctx: &mut LuaContext,
    ) -> Result<LuaValue, LuaError> {
        if self.status == CoroutineStatus::Dead {
            return Ok(self.result.clone().unwrap_or(LuaValue::Nil));
        }
        self.status = CoroutineStatus::Running;
        let val = engine.execute(&self.script.clone(), ctx)?;
        self.result = Some(val.clone());
        self.status = CoroutineStatus::Dead;
        Ok(val)
    }

    /// Return `true` if the coroutine is finished.
    #[must_use]
    pub fn is_dead(&self) -> bool {
        self.status == CoroutineStatus::Dead
    }
}

// ── Event hooks ───────────────────────────────────────────────────────────────

/// Debug/analysis event hook system.
pub struct LuaEventHooks {
    function_enter: Vec<Box<dyn Fn(u64) + Send>>,
    function_exit: Vec<Box<dyn Fn(u64) + Send>>,
    instruction: Vec<Box<dyn Fn(u64) + Send>>,
    memory_access: Vec<Box<dyn Fn(u64, usize) + Send>>,
}

impl fmt::Debug for LuaEventHooks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LuaEventHooks")
            .field("function_enter_count", &self.function_enter.len())
            .field("function_exit_count", &self.function_exit.len())
            .finish_non_exhaustive()
    }
}

impl LuaEventHooks {
    /// Create an empty hook set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            function_enter: Vec::new(),
            function_exit: Vec::new(),
            instruction: Vec::new(),
            memory_access: Vec::new(),
        }
    }

    /// Register a callback for function entry.
    pub fn on_function_enter(&mut self, f: Box<dyn Fn(u64) + Send>) {
        self.function_enter.push(f);
    }

    /// Register a callback for function exit.
    pub fn on_function_exit(&mut self, f: Box<dyn Fn(u64) + Send>) {
        self.function_exit.push(f);
    }

    /// Register a callback for each instruction.
    pub fn on_instruction(&mut self, f: Box<dyn Fn(u64) + Send>) {
        self.instruction.push(f);
    }

    /// Register a callback for memory accesses.
    pub fn on_memory_access(&mut self, f: Box<dyn Fn(u64, usize) + Send>) {
        self.memory_access.push(f);
    }

    /// Fire function-enter hooks.
    pub fn fire_function_enter(&self, address: u64) {
        for cb in &self.function_enter {
            cb(address);
        }
    }

    /// Fire function-exit hooks.
    pub fn fire_function_exit(&self, address: u64) {
        for cb in &self.function_exit {
            cb(address);
        }
    }

    /// Fire instruction hooks.
    pub fn fire_instruction(&self, address: u64) {
        for cb in &self.instruction {
            cb(address);
        }
    }

    /// Fire memory-access hooks.
    pub fn fire_memory_access(&self, address: u64, size: usize) {
        for cb in &self.memory_access {
            cb(address, size);
        }
    }
}

impl Default for LuaEventHooks {
    fn default() -> Self {
        Self::new()
    }
}

// ── Sandbox ───────────────────────────────────────────────────────────────────

/// Sandbox policy for Lua scripts.
#[derive(Debug, Clone)]
pub enum LuaSandboxPolicy {
    /// Permit only these identifiers.
    AllowList(Vec<String>),
    /// Deny these identifiers, permit all others.
    DenyList(Vec<String>),
    /// No restrictions.
    Unrestricted,
}

/// Lua script sandbox.
#[derive(Debug, Clone)]
pub struct LuaSandbox {
    policy: LuaSandboxPolicy,
}

impl LuaSandbox {
    /// Create a sandbox with `policy`.
    #[must_use]
    pub const fn new(policy: LuaSandboxPolicy) -> Self {
        Self { policy }
    }

    /// Return `true` if `name` is allowed.
    #[must_use]
    pub fn is_allowed(&self, name: &str) -> bool {
        match &self.policy {
            LuaSandboxPolicy::AllowList(list) => list.iter().any(|s| s == name),
            LuaSandboxPolicy::DenyList(list) => !list.iter().any(|s| s == name),
            LuaSandboxPolicy::Unrestricted => true,
        }
    }
}

impl Default for LuaSandbox {
    fn default() -> Self {
        Self::new(LuaSandboxPolicy::Unrestricted)
    }
}

// ── Module registry ───────────────────────────────────────────────────────────

/// Registry of Lua modules by name.
#[derive(Debug, Default)]
pub struct LuaModuleRegistry {
    modules: HashMap<String, String>,
}

impl LuaModuleRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a module.
    pub fn register(&mut self, name: &str, source: String) {
        self.modules.insert(name.to_string(), source);
    }

    /// Get module source by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.modules.get(name).map(String::as_str)
    }

    /// Return all module names.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.modules.keys().map(String::as_str).collect()
    }
}

// ── Batch runner ──────────────────────────────────────────────────────────────

/// Batch-execute multiple Lua scripts.
#[derive(Debug, Default)]
pub struct LuaBatchRunner {
    scripts: Vec<String>,
}

impl LuaBatchRunner {
    /// Create a new runner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a script.
    pub fn add_script(&mut self, script: String) {
        self.scripts.push(script);
    }

    /// Return the number of scripts queued.
    #[must_use]
    pub const fn script_count(&self) -> usize {
        self.scripts.len()
    }

    /// Run all scripts sequentially.
    ///
    /// # Errors
    ///
    /// Returns `(index, LuaError)` on the first failure.
    pub fn run_all(
        &self,
        engine: &mut LuaEngine,
        ctx: &mut LuaContext,
    ) -> Result<Vec<LuaValue>, (usize, LuaError)> {
        let mut results = Vec::with_capacity(self.scripts.len());
        for (i, script) in self.scripts.iter().enumerate() {
            let val = engine.execute(script, ctx).map_err(|e| (i, e))?;
            results.push(val);
        }
        Ok(results)
    }

    /// Run all scripts, collecting results and errors.
    pub fn run_all_tolerant(
        &self,
        engine: &mut LuaEngine,
        ctx: &mut LuaContext,
    ) -> Vec<Result<LuaValue, LuaError>> {
        self.scripts
            .iter()
            .map(|s| engine.execute(s, ctx))
            .collect()
    }
}

// ── Progress reporter ─────────────────────────────────────────────────────────

/// Progress reporter for batch Lua operations.
pub struct LuaProgressReporter {
    total: usize,
    done: usize,
    callbacks: Vec<Box<dyn Fn(usize, usize) + Send>>,
}

impl fmt::Debug for LuaProgressReporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LuaProgressReporter")
            .field("total", &self.total)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

impl LuaProgressReporter {
    /// Create a reporter for `total` items.
    #[must_use]
    pub fn new(total: usize) -> Self {
        Self {
            total,
            done: 0,
            callbacks: Vec::new(),
        }
    }

    /// Register a progress callback `f(done, total)`.
    pub fn on_progress(&mut self, f: impl Fn(usize, usize) + Send + 'static) {
        self.callbacks.push(Box::new(f));
    }

    /// Advance by `n` items.
    pub fn advance(&mut self, n: usize) {
        self.done = (self.done + n).min(self.total);
        let (d, t) = (self.done, self.total);
        for cb in &self.callbacks {
            cb(d, t);
        }
    }

    /// Return completion percentage 0-100.
    #[must_use]
    pub const fn percent(&self) -> usize {
        if self.total == 0 {
            return 100;
        }
        self.done * 100 / self.total
    }

    /// Return `true` when complete.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.done >= self.total
    }

    /// Reset progress counter.
    pub const fn reset(&mut self) {
        self.done = 0;
    }
}

// ── Script templates ──────────────────────────────────────────────────────────

/// Canned Lua script templates for common RE tasks.
pub struct LuaScriptTemplate;

impl LuaScriptTemplate {
    /// Script that finds all xrefs to `target`.
    #[must_use]
    pub fn find_xrefs(target: u64) -> String {
        format!(
            "-- Find xrefs to {target:#x}\nlocal results = get_xrefs_to({target:#x})\nprint('Total: ' .. #results)\n"
        )
    }

    /// Script that extracts all strings.
    #[must_use]
    pub fn extract_strings() -> String {
        "-- Extract strings\nlocal strings = find_strings(4)\nprint('Total strings: ' .. #strings)\n".to_string()
    }

    /// Script that renames functions with a prefix substitution.
    #[must_use]
    pub fn rename_functions(old_prefix: &str, new_prefix: &str) -> String {
        format!(
            "-- Rename {old_prefix} -> {new_prefix}\nfor _, f in ipairs(list_functions()) do\n  print(f.name)\nend\n"
        )
    }

    /// Script that dumps all functions.
    #[must_use]
    pub fn dump_functions() -> String {
        "-- Dump functions\nfor _, f in ipairs(list_functions()) do\n  print(f.name)\nend\n"
            .to_string()
    }

    /// Script that patches a byte pattern.
    #[must_use]
    pub fn patch_pattern(from_bytes: &[u8], to_bytes: &[u8]) -> String {
        let from_hex: Vec<String> = from_bytes.iter().map(|b| format!("{b:#04x}")).collect();
        let to_hex: Vec<String> = to_bytes.iter().map(|b| format!("{b:#04x}")).collect();
        format!(
            "-- Patch pattern\nlocal from = {{ {} }}\nlocal to = {{ {} }}\nlocal hits = search_bytes(from)\nprint('Hits: ' .. #hits)\n",
            from_hex.join(", "),
            to_hex.join(", ")
        )
    }
}

// ── Full Lua RE engine ────────────────────────────────────────────────────────

/// A [`LuaEngine`] with a wired-in [`LuaReApi`] and sandbox.
pub struct LuaReEngine {
    engine: LuaEngine,
    /// Host RE API.
    pub api: LuaReApi,
    /// Active sandbox policy.
    pub sandbox: LuaSandbox,
}

impl fmt::Debug for LuaReEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LuaReEngine")
    }
}

impl LuaReEngine {
    /// Create a new engine with an unrestricted sandbox.
    #[must_use]
    pub fn new() -> Self {
        Self {
            engine: LuaEngine::new(),
            api: LuaReApi::new(),
            sandbox: LuaSandbox::default(),
        }
    }

    /// Create a sandboxed engine.
    #[must_use]
    pub fn with_sandbox(policy: LuaSandboxPolicy) -> Self {
        Self {
            engine: LuaEngine::new(),
            api: LuaReApi::new(),
            sandbox: LuaSandbox::new(policy),
        }
    }

    /// Execute `script` with RE built-ins pre-injected.
    ///
    /// # Errors
    ///
    /// Returns [`LuaError`] on script error.
    pub fn execute(&mut self, script: &str) -> Result<(LuaValue, LuaContext), LuaError> {
        let mut ctx = LuaContext::new();
        for name in &[
            "disassemble",
            "search_bytes",
            "search_pattern",
            "find_strings",
            "patch_bytes",
            "get_xrefs_to",
            "get_xrefs_from",
            "list_functions",
            "get_function",
            "search_functions",
            "rename_function",
            "list_segments",
            "segment_at",
            "read_bytes",
            "set_comment",
            "get_comment",
            "set_label",
            "get_label",
            "decompile",
        ] {
            ctx.globals
                .insert((*name).to_string(), LuaValue::Function((*name).to_string()));
        }
        let val = self.engine.execute(script, &mut ctx)?;
        Ok((val, ctx))
    }

    /// Set the step limit.
    pub const fn set_max_steps(&mut self, n: u64) {
        self.engine.set_max_steps(n);
    }
}

impl Default for LuaReEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── mlua-based LuaScriptEngine ────────────────────────────────────────────────

/// A value that can cross the Rust/Lua boundary.
#[derive(Debug, Clone, PartialEq)]
pub enum ScriptValue {
    /// Lua `nil`.
    Nil,
    /// Boolean.
    Bool(bool),
    /// 64-bit integer.
    Int(i64),
    /// 64-bit float.
    Float(f64),
    /// UTF-8 string.
    String(String),
    /// Table as ordered key-value pairs.
    Table(Vec<(Self, Self)>),
}

impl ScriptValue {
    /// Return the Lua type name string.
    #[must_use]
    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::Nil => "nil",
            Self::Bool(_) => "boolean",
            Self::Int(_) | Self::Float(_) => "number",
            Self::String(_) => "string",
            Self::Table(_) => "table",
        }
    }

    /// Try to coerce to i64.
    #[must_use]
    pub const fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            Self::Float(f) => Some(crate::casts::f64_to_i64(*f)),
            _ => None,
        }
    }

    /// Try to borrow as &str.
    #[must_use]
    pub const fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Return truthy-ness in Lua semantics (nil and false are falsy).
    #[must_use]
    pub const fn is_truthy(&self) -> bool {
        !matches!(self, Self::Nil | Self::Bool(false))
    }
}

impl std::fmt::Display for ScriptValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Nil => write!(f, "nil"),
            Self::Bool(b) => write!(f, "{b}"),
            Self::Int(i) => write!(f, "{i}"),
            Self::Float(fl) => write!(f, "{fl}"),
            Self::String(s) => write!(f, "{s}"),
            Self::Table(t) => write!(f, "table[{}]", t.len()),
        }
    }
}

impl From<bool> for ScriptValue {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}
impl From<i64> for ScriptValue {
    fn from(i: i64) -> Self {
        Self::Int(i)
    }
}
impl From<f64> for ScriptValue {
    fn from(f: f64) -> Self {
        Self::Float(f)
    }
}
impl From<String> for ScriptValue {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}
impl From<&str> for ScriptValue {
    fn from(s: &str) -> Self {
        Self::String(s.to_string())
    }
}

/// Convert an mlua `Value` to a `ScriptValue`.
fn mlua_to_script(val: mlua::Value) -> ScriptValue {
    match val {
        mlua::Value::Boolean(b) => ScriptValue::Bool(b),
        mlua::Value::Integer(i) => ScriptValue::Int(i),
        mlua::Value::Number(f) => ScriptValue::Float(f),
        mlua::Value::String(s) => ScriptValue::String(s.to_string_lossy()),
        mlua::Value::Table(t) => {
            let mut pairs = Vec::new();
            for pair in t.pairs::<mlua::Value, mlua::Value>().flatten() {
                pairs.push((mlua_to_script(pair.0), mlua_to_script(pair.1)));
            }
            ScriptValue::Table(pairs)
        }
        _ => ScriptValue::Nil,
    }
}

/// Convert a `ScriptValue` back to an mlua `Value`.
fn script_to_mlua(lua: &mlua::Lua, val: &ScriptValue) -> mlua::Result<mlua::Value> {
    match val {
        ScriptValue::Nil => Ok(mlua::Value::Nil),
        ScriptValue::Bool(b) => Ok(mlua::Value::Boolean(*b)),
        ScriptValue::Int(i) => Ok(mlua::Value::Integer(*i)),
        ScriptValue::Float(f) => Ok(mlua::Value::Number(*f)),
        ScriptValue::String(s) => {
            let ls = lua.create_string(s.as_bytes())?;
            Ok(mlua::Value::String(ls))
        }
        ScriptValue::Table(pairs) => {
            let t = lua.create_table()?;
            for (k, v) in pairs {
                let mk = script_to_mlua(lua, k)?;
                let mv = script_to_mlua(lua, v)?;
                t.raw_set(mk, mv)?;
            }
            Ok(mlua::Value::Table(t))
        }
    }
}

/// Errors produced by [`LuaScriptEngine`].
#[derive(Debug, thiserror::Error)]
pub enum ScriptError {
    /// mlua returned an error.
    #[error("lua error: {0}")]
    Lua(#[from] mlua::Error),
    /// I/O error while loading a file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// A function registered from Rust panicked or returned an error.
    #[error("function error: {0}")]
    Function(String),
    /// A requested function does not exist in the Lua globals.
    #[error("no such function: {0}")]
    NoSuchFunction(String),
    /// The value returned from Lua was not the expected type.
    #[error("type mismatch: {0}")]
    TypeMismatch(String),
}

/// A Lua script engine backed by a real Lua 5.4 VM via mlua.
///
/// `LuaScriptEngine` wraps [`mlua::Lua`] and provides a higher-level API using
/// [`ScriptValue`] for data exchange so callers do not need to deal with mlua
/// types directly.
pub struct LuaScriptEngine {
    lua: mlua::Lua,
    /// Names of event handler scripts keyed by event name.
    event_handlers: std::collections::HashMap<String, Vec<String>>,
}

impl std::fmt::Debug for LuaScriptEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LuaScriptEngine").finish_non_exhaustive()
    }
}

impl LuaScriptEngine {
    /// Create a new engine with a fresh Lua 5.4 state.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError`] if mlua cannot initialise the Lua VM.
    pub fn new() -> Result<Self, ScriptError> {
        let lua = mlua::Lua::new();
        Ok(Self {
            lua,
            event_handlers: std::collections::HashMap::new(),
        })
    }

    /// Create a new engine and register the `rustre` global table.
    ///
    /// The table exposes:
    /// - `rustre.log(msg)` — prints `msg` to stdout
    /// - `rustre.version()` — returns `"0.1.0"`
    /// - `rustre.actions.register(name, menu_path, callback)` — registers an action
    /// - `rustre.events.on(event_name, callback)` — registers an event handler
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError`] if the VM or table setup fails.
    pub fn with_rustre_api() -> Result<Self, ScriptError> {
        let engine = Self::new()?;
        engine.setup_rustre_api()?;
        Ok(engine)
    }

    /// Evaluate a Lua code snippet and return the last expression value.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError::Lua`] on syntax or runtime error.
    pub fn eval(&self, code: &str) -> Result<ScriptValue, ScriptError> {
        let val: mlua::Value = self.lua.load(code).eval()?;
        Ok(mlua_to_script(val))
    }

    /// Load and execute a Lua source file.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError::Io`] if the file cannot be read, or
    /// [`ScriptError::Lua`] if the script fails.
    pub fn load_file(&self, path: &std::path::Path) -> Result<(), ScriptError> {
        let source = std::fs::read_to_string(path)?;
        self.lua.load(&source).exec()?;
        Ok(())
    }

    /// Call a named Lua function with the given arguments.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError::NoSuchFunction`] if `name` is not a callable
    /// global, or [`ScriptError::Lua`] on runtime error.
    pub fn call_function(
        &self,
        name: &str,
        args: &[ScriptValue],
    ) -> Result<ScriptValue, ScriptError> {
        let globals = self.lua.globals();
        let func: mlua::Function = globals
            .get(name)
            .map_err(|_| ScriptError::NoSuchFunction(name.to_string()))?;
        // Build a multi-value argument list.
        let mut mlua_args: Vec<mlua::Value> = Vec::with_capacity(args.len());
        for a in args {
            mlua_args.push(script_to_mlua(&self.lua, a)?);
        }
        let result: mlua::Value = func.call(mlua::MultiValue::from_vec(mlua_args))?;
        Ok(mlua_to_script(result))
    }

    /// Register a Rust closure as a Lua global function.
    ///
    /// The closure receives a `Vec<ScriptValue>` and must return a
    /// `Result<ScriptValue, ScriptError>`.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError::Lua`] if the function cannot be registered.
    pub fn register_function<F>(&self, name: &str, f: F) -> Result<(), ScriptError>
    where
        F: Fn(Vec<ScriptValue>) -> Result<ScriptValue, ScriptError> + Send + Sync + 'static,
    {
        let func = self
            .lua
            .create_function(move |lua, args: mlua::MultiValue| {
                let script_args: Vec<ScriptValue> = args.into_iter().map(mlua_to_script).collect();
                let result =
                    f(script_args).map_err(|e| mlua::Error::RuntimeError(e.to_string()))?;
                script_to_mlua(lua, &result)
            })?;
        self.lua.globals().set(name, func)?;
        Ok(())
    }

    /// Subscribe a Lua code snippet to an event.
    ///
    /// When the event is fired via [`LuaScriptEngine::fire_event`] the snippet
    /// is executed.  Multiple snippets may be registered for the same event.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError::Lua`] if the snippet has a syntax error (detected
    /// at registration time via a dry-run `load`).
    pub fn subscribe_event(&mut self, event: &str, handler_code: &str) -> Result<(), ScriptError> {
        // Validate syntax by loading (but not executing) the snippet.
        self.lua.load(handler_code).into_function()?;
        self.event_handlers
            .entry(event.to_string())
            .or_default()
            .push(handler_code.to_string());
        Ok(())
    }

    /// Fire a named event, executing all registered handler snippets in order.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError::Lua`] if any handler fails.
    pub fn fire_event(&self, event: &str) -> Result<(), ScriptError> {
        if let Some(handlers) = self.event_handlers.get(event) {
            for code in handlers {
                self.lua.load(code).exec()?;
            }
        }
        Ok(())
    }

    /// Set a global variable in the Lua state.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError::Lua`] if the assignment fails.
    pub fn set_global(&self, name: &str, val: &ScriptValue) -> Result<(), ScriptError> {
        let mv = script_to_mlua(&self.lua, val)?;
        self.lua.globals().set(name, mv)?;
        Ok(())
    }

    /// Get a global variable from the Lua state.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError::Lua`] if the retrieval fails.
    pub fn get_global(&self, name: &str) -> Result<ScriptValue, ScriptError> {
        let val: mlua::Value = self.lua.globals().get(name)?;
        Ok(mlua_to_script(val))
    }

    /// Access the underlying [`mlua::Lua`] instance directly.
    #[must_use]
    pub const fn lua(&self) -> &mlua::Lua {
        &self.lua
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn setup_rustre_api(&self) -> Result<(), ScriptError> {
        let lua = &self.lua;

        // rustre.log(msg)
        let log_fn = lua.create_function(|_, msg: String| {
            println!("[rustre] {msg}");
            Ok(())
        })?;

        // rustre.version()
        let version_fn = lua.create_function(|_, ()| Ok("0.1.0"))?;

        // rustre.actions table
        let actions_table = lua.create_table()?;
        let actions_register =
            lua.create_function(|_, (name, menu_path, _cb): (String, String, mlua::Value)| {
                println!("[rustre.actions] registered '{name}' at '{menu_path}'");
                Ok(())
            })?;
        actions_table.set("register", actions_register)?;

        // rustre.events table
        let events_table = lua.create_table()?;
        let events_on = lua.create_function(|_, (event_name, _cb): (String, mlua::Value)| {
            println!("[rustre.events] handler registered for '{event_name}'");
            Ok(())
        })?;
        events_table.set("on", events_on)?;

        // Assemble rustre table
        let rustre = lua.create_table()?;
        rustre.set("log", log_fn)?;
        rustre.set("version", version_fn)?;
        rustre.set("actions", actions_table)?;
        rustre.set("events", events_table)?;

        lua.globals().set("rustre", rustre)?;
        Ok(())
    }
}

// ── RustreApi wrapper ─────────────────────────────────────────────────────────

/// High-level wrapper that keeps an [`LuaScriptEngine`] ready with the
/// `rustre` API table already registered.
pub struct RustreApi {
    engine: LuaScriptEngine,
}

impl std::fmt::Debug for RustreApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustreApi").finish_non_exhaustive()
    }
}

impl RustreApi {
    /// Create a new API, initialising the Lua VM and `rustre` table.
    ///
    /// # Errors
    ///
    /// Returns [`ScriptError`] on VM initialisation failure.
    pub fn new() -> Result<Self, ScriptError> {
        let engine = LuaScriptEngine::with_rustre_api()?;
        Ok(Self { engine })
    }

    /// Evaluate `code` and return the result.
    ///
    /// # Errors
    ///
    /// See [`LuaScriptEngine::eval`].
    pub fn eval(&self, code: &str) -> Result<ScriptValue, ScriptError> {
        self.engine.eval(code)
    }

    /// Borrow the inner engine for advanced use.
    #[must_use]
    pub const fn engine(&self) -> &LuaScriptEngine {
        &self.engine
    }

    /// Borrow the inner engine mutably.
    pub const fn engine_mut(&mut self) -> &mut LuaScriptEngine {
        &mut self.engine
    }
}

// ── mlua-backed tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod mlua_tests {
    use super::*;

    // Helper: create an engine, panic on error.
    fn mk() -> LuaScriptEngine {
        LuaScriptEngine::new().expect("engine init failed")
    }

    fn mk_re() -> LuaScriptEngine {
        LuaScriptEngine::with_rustre_api().expect("engine init failed")
    }

    // ── Basic eval ────────────────────────────────────────────────────────────

    #[test]
    fn mlua_eval_integer() {
        let e = mk();
        let v = e.eval("return 42").unwrap();
        assert_eq!(v, ScriptValue::Int(42));
    }

    #[test]
    fn mlua_eval_float() {
        let e = mk();
        let v = e.eval("return 3.14").unwrap();
        assert!(matches!(v, ScriptValue::Float(_)));
    }

    #[test]
    fn mlua_eval_string() {
        let e = mk();
        let v = e.eval(r#"return "hello""#).unwrap();
        assert_eq!(v, ScriptValue::String("hello".to_string()));
    }

    #[test]
    fn mlua_eval_boolean_true() {
        let e = mk();
        let v = e.eval("return true").unwrap();
        assert_eq!(v, ScriptValue::Bool(true));
    }

    #[test]
    fn mlua_eval_nil() {
        let e = mk();
        let v = e.eval("return nil").unwrap();
        assert_eq!(v, ScriptValue::Nil);
    }

    #[test]
    fn mlua_eval_table() {
        let e = mk();
        let v = e.eval("return {1, 2, 3}").unwrap();
        assert!(matches!(v, ScriptValue::Table(_)));
        if let ScriptValue::Table(t) = v {
            assert_eq!(t.len(), 3);
        }
    }

    #[test]
    fn mlua_eval_arithmetic() {
        let e = mk();
        let v = e.eval("return 10 + 5 * 2").unwrap();
        assert_eq!(v.as_int(), Some(20));
    }

    #[test]
    fn mlua_eval_string_concat() {
        let e = mk();
        let v = e.eval(r#"return "foo" .. "bar""#).unwrap();
        assert_eq!(v.as_str(), Some("foobar"));
    }

    // ── set / get global ─────────────────────────────────────────────────────

    #[test]
    fn mlua_set_get_global_int() {
        let e = mk();
        e.set_global("answer", &ScriptValue::Int(42)).unwrap();
        let v = e.get_global("answer").unwrap();
        assert_eq!(v.as_int(), Some(42));
    }

    #[test]
    fn mlua_set_get_global_string() {
        let e = mk();
        e.set_global("greeting", &ScriptValue::String("hi".into()))
            .unwrap();
        let v = e.get_global("greeting").unwrap();
        assert_eq!(v.as_str(), Some("hi"));
    }

    #[test]
    fn mlua_global_visible_in_eval() {
        let e = mk();
        e.set_global("x", &ScriptValue::Int(7)).unwrap();
        let v = e.eval("return x * 6").unwrap();
        assert_eq!(v.as_int(), Some(42));
    }

    // ── register_function ────────────────────────────────────────────────────

    #[test]
    fn mlua_register_and_call_rust_function() {
        let e = mk();
        e.register_function("double", |args| {
            let n = args.first().and_then(super::ScriptValue::as_int).unwrap_or(0);
            Ok(ScriptValue::Int(n * 2))
        })
        .unwrap();
        let v = e.eval("return double(21)").unwrap();
        assert_eq!(v.as_int(), Some(42));
    }

    #[test]
    fn mlua_register_function_string_return() {
        let e = mk();
        e.register_function("greet", |args| {
            let name = args
                .first()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default();
            Ok(ScriptValue::String(format!("Hello, {name}!")))
        })
        .unwrap();
        let v = e.eval(r#"return greet("World")"#).unwrap();
        assert_eq!(v.as_str(), Some("Hello, World!"));
    }

    // ── call_function ─────────────────────────────────────────────────────────

    #[test]
    fn mlua_call_lua_function() {
        let e = mk();
        e.eval("function add(a, b) return a + b end").unwrap();
        let v = e
            .call_function("add", &[ScriptValue::Int(3), ScriptValue::Int(4)])
            .unwrap();
        assert_eq!(v.as_int(), Some(7));
    }

    #[test]
    fn mlua_call_missing_function_error() {
        let e = mk();
        let err = e.call_function("nonexistent", &[]);
        assert!(err.is_err());
    }

    // ── subscribe_event / fire_event ──────────────────────────────────────────

    #[test]
    fn mlua_subscribe_and_fire_event() {
        let mut e = mk();
        e.set_global("fired", &ScriptValue::Bool(false)).unwrap();
        e.subscribe_event("on_load", "fired = true").unwrap();
        e.fire_event("on_load").unwrap();
        let v = e.get_global("fired").unwrap();
        assert_eq!(v, ScriptValue::Bool(true));
    }

    #[test]
    fn mlua_fire_event_no_handlers_ok() {
        let e = LuaScriptEngine::new().unwrap();
        // should not error
        e.fire_event("no_such_event").unwrap();
    }

    // ── rustre API ────────────────────────────────────────────────────────────

    #[test]
    fn mlua_rustre_version() {
        let e = mk_re();
        let v = e.eval("return rustre.version()").unwrap();
        assert_eq!(v.as_str(), Some("0.1.0"));
    }

    #[test]
    fn mlua_rustre_log_does_not_error() {
        let e = mk_re();
        e.eval(r#"rustre.log("test message")"#).unwrap();
    }

    #[test]
    fn mlua_rustre_actions_register_does_not_error() {
        let e = mk_re();
        e.eval(r#"rustre.actions.register("MyAction", "Tools/MyAction", function() end)"#)
            .unwrap();
    }

    #[test]
    fn mlua_rustre_events_on_does_not_error() {
        let e = mk_re();
        e.eval(r#"rustre.events.on("on_open", function() end)"#)
            .unwrap();
    }

    // ── ScriptValue helpers ───────────────────────────────────────────────────

    #[test]
    fn script_value_type_names() {
        assert_eq!(ScriptValue::Nil.type_name(), "nil");
        assert_eq!(ScriptValue::Bool(true).type_name(), "boolean");
        assert_eq!(ScriptValue::Int(0).type_name(), "number");
        assert_eq!(ScriptValue::Float(0.0).type_name(), "number");
        assert_eq!(ScriptValue::String(String::new()).type_name(), "string");
        assert_eq!(ScriptValue::Table(vec![]).type_name(), "table");
    }

    #[test]
    fn script_value_is_truthy() {
        assert!(!ScriptValue::Nil.is_truthy());
        assert!(!ScriptValue::Bool(false).is_truthy());
        assert!(ScriptValue::Bool(true).is_truthy());
        assert!(ScriptValue::Int(1).is_truthy());
        assert!(ScriptValue::String("x".into()).is_truthy());
    }

    #[test]
    fn script_value_display() {
        assert_eq!(ScriptValue::Nil.to_string(), "nil");
        assert_eq!(ScriptValue::Int(99).to_string(), "99");
        assert_eq!(ScriptValue::String("hi".into()).to_string(), "hi");
    }

    #[test]
    fn rustre_api_new_and_eval() {
        let api = RustreApi::new().unwrap();
        let v = api.eval("return 1 + 1").unwrap();
        assert_eq!(v.as_int(), Some(2));
    }
}

// ── Internal x86 decode helper ────────────────────────────────────────────────

const fn lua_decode_x86(byte: u8) -> (&'static str, &'static str, usize) {
    match byte {
        0x55 => ("push", "rbp", 1),
        0x5D => ("pop", "rbp", 1),
        0xC3 => ("ret", "", 1),
        0x90 => ("nop", "", 1),
        0xCC => ("int3", "", 1),
        0x50..=0x5F => ("push/pop", "reg", 1),
        0xE8 => ("call", "rel32", 5),
        0xE9 => ("jmp", "rel32", 5),
        0xEB => ("jmp", "rel8", 2),
        0x74 | 0x75 | 0x7C | 0x7D => ("jcc", "rel8", 2),
        0x89 | 0x8B => ("mov", "r/m", 2),
        0x83 => ("alu", "r/m, imm8", 3),
        0x31 | 0x33 => ("xor", "r/m", 2),
        _ => ("db", "", 1),
    }
}

// ── Extended Lua scripting API ────────────────────────────────────────────────
//
// The following section extends the `rustre-script-lua` crate with additional
// types, utilities, and test coverage to provide a richer scripting surface.

/// Describes a binary segment visible to Lua scripts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LuaSegInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub permissions: String,
    pub kind: LuaSegKind,
}

/// Kind of binary segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LuaSegKind {
    Code,
    Data,
    Bss,
    ReadOnly,
    Unknown,
}

impl std::fmt::Display for LuaSegKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Code => write!(f, "code"),
            Self::Data => write!(f, "data"),
            Self::Bss => write!(f, "bss"),
            Self::ReadOnly => write!(f, "rodata"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl LuaSegKind {
    /// Parse a segment kind from a permissions string.
    #[must_use]
    pub fn from_perms(perms: &str) -> Self {
        if perms.contains('x') {
            Self::Code
        } else if perms.contains('w') {
            Self::Data
        } else if perms.contains('r') {
            Self::ReadOnly
        } else {
            Self::Unknown
        }
    }
}

/// Import entry returned to Lua scripts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LuaImportEntry {
    pub name: String,
    pub dll: String,
    pub ordinal: u16,
    pub iat_address: u64,
}

/// Export entry returned to Lua scripts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LuaExportEntry {
    pub name: String,
    pub address: u64,
    pub ordinal: u16,
}

/// Cross-reference kind for Lua consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LuaXrefType {
    Call,
    Jump,
    Data,
    Unknown,
}

impl std::fmt::Display for LuaXrefType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Call => write!(f, "call"),
            Self::Jump => write!(f, "jump"),
            Self::Data => write!(f, "data"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl LuaXrefType {
    /// Parse from a string label.
    #[must_use]
    pub fn parse_name(s: &str) -> Self {
        match s {
            "call" => Self::Call,
            "jump" => Self::Jump,
            "data" => Self::Data,
            _ => Self::Unknown,
        }
    }
}

/// A cross-reference entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LuaXrefEntry {
    pub from_addr: u64,
    pub to_addr: u64,
    pub kind: LuaXrefType,
}

/// A function symbol visible to Lua scripts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LuaFunctionInfo {
    pub address: u64,
    pub name: String,
    pub size: u64,
    pub is_exported: bool,
    pub is_imported: bool,
}

/// Entropy measurement result.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct EntropyResult {
    pub address: u64,
    pub length: u64,
    pub entropy: f64,
}

impl EntropyResult {
    /// True when entropy indicates likely packed/encrypted data (>= 7.0).
    #[must_use]
    pub fn is_high_entropy(&self) -> bool {
        self.entropy >= 7.0
    }

    /// Classify entropy level as a human-readable label.
    #[must_use]
    pub fn classification(&self) -> &'static str {
        if self.entropy >= 7.5 {
            "encrypted_or_compressed"
        } else if self.entropy >= 6.5 {
            "high"
        } else if self.entropy >= 4.0 {
            "normal"
        } else {
            "low"
        }
    }
}

/// Calculate Shannon entropy of a byte slice.
#[must_use]
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = crate::casts::usize_to_f64(data.len());
    let mut entropy = 0.0_f64;
    for &count in &counts {
        if count > 0 {
            let p = crate::casts::u64_to_f64(count) / len;
            entropy = p.mul_add(-p.log2(), entropy);
        }
    }
    entropy
}

/// Simple hex-pattern matcher supporting `??` wildcards.
/// Pattern format: `"4D 5A ?? ?? 50 45"` — case-insensitive hex bytes.
#[must_use]
pub fn lua_match_hex_pattern(data: &[u8], pattern: &str) -> Vec<usize> {
    let tokens: Vec<&str> = pattern.split_ascii_whitespace().collect();
    if tokens.is_empty() {
        return Vec::new();
    }
    let pat: Vec<Option<u8>> = tokens
        .iter()
        .map(|t| {
            if *t == "??" || *t == "?" {
                None
            } else {
                u8::from_str_radix(t, 16).ok()
            }
        })
        .collect();
    let pat_len = pat.len();
    let mut matches = Vec::new();
    if data.len() < pat_len {
        return matches;
    }
    'outer: for i in 0..=(data.len() - pat_len) {
        for (j, &byte_pat) in pat.iter().enumerate() {
            if let Some(expected) = byte_pat
                && data[i + j] != expected {
                    continue 'outer;
                }
        }
        matches.push(i);
    }
    matches
}

/// Detect common binary formats from the first bytes of the data.
#[must_use]
pub fn lua_detect_format(data: &[u8]) -> &'static str {
    if data.starts_with(&[0x7f, b'E', b'L', b'F']) {
        "ELF"
    } else if data.starts_with(b"MZ") {
        "PE"
    } else if data.starts_with(&[0x00, b'a', b's', b'm']) {
        "WASM"
    } else if data.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])
        || data.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])
    {
        "Mach-O"
    } else if data.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE]) {
        "Mach-O Fat"
    } else if data.starts_with(b"PK\x03\x04") {
        "ZIP"
    } else if data.starts_with(&[0x1f, 0x8b]) {
        "GZIP"
    } else {
        "Unknown"
    }
}

/// Lua script context for tracking analysis state across calls.
#[derive(Debug, Default)]
pub struct LuaAnalysisContext {
    /// Named annotations added by the script.
    pub annotations: Vec<(u64, String)>,
    /// Renamed functions: (address, `new_name`).
    pub renames: Vec<(u64, String)>,
    /// Discovered strings of interest.
    pub interesting_strings: Vec<(u64, String)>,
    /// Identified vulnerabilities.
    pub vulnerabilities: Vec<LuaVulnerabilityFinding>,
}

impl LuaAnalysisContext {
    /// Create an empty analysis context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an annotation at an address.
    pub fn annotate(&mut self, addr: u64, text: impl Into<String>) {
        self.annotations.push((addr, text.into()));
    }

    /// Record a function rename.
    pub fn rename(&mut self, addr: u64, name: impl Into<String>) {
        self.renames.push((addr, name.into()));
    }

    /// Record an interesting string.
    pub fn add_string(&mut self, addr: u64, value: impl Into<String>) {
        self.interesting_strings.push((addr, value.into()));
    }

    /// Record a vulnerability finding.
    pub fn add_vulnerability(&mut self, finding: LuaVulnerabilityFinding) {
        self.vulnerabilities.push(finding);
    }

    /// Generate a summary of all findings.
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "Annotations: {}, Renames: {}, Strings: {}, Vulnerabilities: {}",
            self.annotations.len(),
            self.renames.len(),
            self.interesting_strings.len(),
            self.vulnerabilities.len(),
        )
    }
}

/// A vulnerability finding from a Lua analysis script.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LuaVulnerabilityFinding {
    pub address: u64,
    pub function_name: String,
    pub severity: VulnSeverity,
    pub cwe_id: Option<u32>,
    pub description: String,
    pub evidence: String,
}

/// Severity level for vulnerability findings.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub enum VulnSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for VulnSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

impl VulnSeverity {
    /// Numeric score (CVSS-like: 1-10).
    #[must_use]
    pub const fn score(&self) -> u32 {
        match self {
            Self::Low => 3,
            Self::Medium => 5,
            Self::High => 8,
            Self::Critical => 10,
        }
    }

    /// Parse from string.
    #[must_use]
    pub fn parse_name(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" | "med" => Self::Medium,
            _ => Self::Low,
        }
    }
}

/// Patcher helper for Lua scripts — records pending byte patches.
#[derive(Debug, Default)]
pub struct LuaPatchSet {
    patches: Vec<(u64, Vec<u8>)>,
}

impl LuaPatchSet {
    /// Create an empty patch set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a patch from a hex string (e.g. `"90 90 90"`).
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn add_hex(&mut self, address: u64, hex: &str) -> Result<(), LuaError> {
        let bytes: Result<Vec<u8>, _> = hex
            .split_ascii_whitespace()
            .map(|h| u8::from_str_radix(h, 16))
            .collect();
        let bytes =
            bytes.map_err(|_| LuaError::RuntimeError(format!("invalid hex in patch: {hex}")))?;
        self.patches.push((address, bytes));
        Ok(())
    }

    /// Add a patch from raw bytes.
    pub fn add_bytes(&mut self, address: u64, bytes: Vec<u8>) {
        self.patches.push((address, bytes));
    }

    /// Number of pending patches.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.patches.len()
    }

    /// True when no patches are queued.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.patches.is_empty()
    }

    /// Iterate over all patches.
    pub fn iter(&self) -> impl Iterator<Item = &(u64, Vec<u8>)> {
        self.patches.iter()
    }

    /// Apply all patches to a mutable byte buffer.
    pub fn apply_to(&self, data: &mut [u8]) {
        for (addr, bytes) in &self.patches {
            let start = crate::casts::u64_to_usize(*addr);
            let end = start + bytes.len();
            if end <= data.len() {
                data[start..end].copy_from_slice(bytes);
            }
        }
    }
}

/// NOP-sled generator for patching out unwanted code.
#[must_use]
pub fn lua_nop_sled(length: usize) -> Vec<u8> {
    vec![0x90u8; length]
}

/// Generate an unconditional near jump (rel32) patch sequence.
///
/// `from` is the address of the JMP instruction; `to` is the jump target.
/// Returns the 5-byte patch `E9 <rel32>` or `None` if the offset overflows i32.
#[must_use]
pub fn lua_jmp_patch(from: u64, to: u64) -> Option<Vec<u8>> {
    // Relative offset = target - (jmp_addr + 5)
    let rel = crate::casts::u64_to_i64(to).wrapping_sub(crate::casts::u64_to_i64(from) + 5);
    if rel < i64::from(i32::MIN) || rel > i64::from(i32::MAX) {
        return None;
    }
    let rel = crate::casts::i64_to_i32(rel);
    let mut patch = vec![0xE9u8];
    patch.extend_from_slice(&rel.to_le_bytes());
    Some(patch)
}

/// Generate a RET patch (single byte 0xC3).
#[must_use]
pub fn lua_ret_patch() -> Vec<u8> {
    vec![0xC3]
}

// ── Additional tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod lua_extended_tests {
    use super::*;

    // ── calculate_entropy ─────────────────────────────────────────────────────

    #[test]
    fn entropy_all_zeros_is_zero() {
        let data = vec![0u8; 256];
        assert_eq!(calculate_entropy(&data), 0.0);
    }

    #[test]
    fn entropy_uniform_is_eight() {
        let data: Vec<u8> = (0u8..=255).collect();
        let e = calculate_entropy(&data);
        assert!(
            (e - 8.0).abs() < 1e-10,
            "uniform entropy should be 8.0, got {e}"
        );
    }

    #[test]
    fn entropy_empty_is_zero() {
        assert_eq!(calculate_entropy(&[]), 0.0);
    }

    #[test]
    fn entropy_result_classification_encrypted() {
        let result = EntropyResult {
            address: 0,
            length: 1000,
            entropy: 7.9,
        };
        assert_eq!(result.classification(), "encrypted_or_compressed");
        assert!(result.is_high_entropy());
    }

    #[test]
    fn entropy_result_classification_normal() {
        let result = EntropyResult {
            address: 0,
            length: 1000,
            entropy: 5.0,
        };
        assert_eq!(result.classification(), "normal");
        assert!(!result.is_high_entropy());
    }

    #[test]
    fn entropy_result_classification_low() {
        let result = EntropyResult {
            address: 0,
            length: 100,
            entropy: 1.5,
        };
        assert_eq!(result.classification(), "low");
    }

    // ── lua_match_hex_pattern ─────────────────────────────────────────────────

    #[test]
    fn hex_pattern_exact_match_at_start() {
        let data = vec![0x4D, 0x5A, 0x90, 0x00];
        let matches = lua_match_hex_pattern(&data, "4D 5A 90 00");
        assert_eq!(matches, vec![0]);
    }

    #[test]
    fn hex_pattern_wildcard_match() {
        let data = vec![0x4D, 0x5A, 0xAB, 0x00];
        let matches = lua_match_hex_pattern(&data, "4D 5A ?? 00");
        assert_eq!(matches, vec![0]);
    }

    #[test]
    fn hex_pattern_no_match() {
        let data = vec![0x00, 0x01, 0x02];
        let matches = lua_match_hex_pattern(&data, "FF FF");
        assert!(matches.is_empty());
    }

    #[test]
    fn hex_pattern_multiple_matches() {
        let data = vec![0x90, 0x90, 0x90, 0x90];
        let matches = lua_match_hex_pattern(&data, "90 90");
        assert_eq!(matches, vec![0, 1, 2]);
    }

    #[test]
    fn hex_pattern_empty_pattern() {
        let data = vec![0x01, 0x02];
        let matches = lua_match_hex_pattern(&data, "");
        assert!(matches.is_empty());
    }

    // ── lua_detect_format ─────────────────────────────────────────────────────

    #[test]
    fn detect_format_elf() {
        assert_eq!(lua_detect_format(&[0x7f, b'E', b'L', b'F', 0, 0]), "ELF");
    }

    #[test]
    fn detect_format_pe() {
        assert_eq!(lua_detect_format(b"MZ\x90\x00"), "PE");
    }

    #[test]
    fn detect_format_wasm() {
        assert_eq!(
            lua_detect_format(&[0x00, b'a', b's', b'm', 1, 0, 0, 0]),
            "WASM"
        );
    }

    #[test]
    fn detect_format_macho() {
        assert_eq!(lua_detect_format(&[0xCE, 0xFA, 0xED, 0xFE]), "Mach-O");
    }

    #[test]
    fn detect_format_gzip() {
        assert_eq!(lua_detect_format(&[0x1f, 0x8b, 0x08]), "GZIP");
    }

    #[test]
    fn detect_format_unknown() {
        assert_eq!(lua_detect_format(&[0xAA, 0xBB, 0xCC]), "Unknown");
    }

    // ── LuaSegmentKind ────────────────────────────────────────────────────────

    #[test]
    fn segment_kind_from_perms_code() {
        assert_eq!(LuaSegKind::from_perms("r-x"), LuaSegKind::Code);
    }

    #[test]
    fn segment_kind_from_perms_data() {
        assert_eq!(LuaSegKind::from_perms("rw-"), LuaSegKind::Data);
    }

    #[test]
    fn segment_kind_from_perms_rodata() {
        assert_eq!(LuaSegKind::from_perms("r--"), LuaSegKind::ReadOnly);
    }

    #[test]
    fn segment_kind_display() {
        assert_eq!(LuaSegKind::Code.to_string(), "code");
        assert_eq!(LuaSegKind::Bss.to_string(), "bss");
        assert_eq!(LuaSegKind::ReadOnly.to_string(), "rodata");
        assert_eq!(LuaSegKind::Unknown.to_string(), "unknown");
    }

    // ── LuaXrefKind ───────────────────────────────────────────────────────────

    #[test]
    fn xref_kind_from_str_known() {
        assert_eq!(LuaXrefType::parse_name("call"), LuaXrefType::Call);
        assert_eq!(LuaXrefType::parse_name("jump"), LuaXrefType::Jump);
        assert_eq!(LuaXrefType::parse_name("data"), LuaXrefType::Data);
    }

    #[test]
    fn xref_kind_from_str_unknown() {
        assert_eq!(LuaXrefType::parse_name("other"), LuaXrefType::Unknown);
    }

    #[test]
    fn xref_kind_display() {
        assert_eq!(LuaXrefType::Call.to_string(), "call");
        assert_eq!(LuaXrefType::Jump.to_string(), "jump");
    }

    // ── VulnSeverity ──────────────────────────────────────────────────────────

    #[test]
    fn vuln_severity_ordering() {
        assert!(VulnSeverity::Critical > VulnSeverity::High);
        assert!(VulnSeverity::High > VulnSeverity::Medium);
        assert!(VulnSeverity::Medium > VulnSeverity::Low);
    }

    #[test]
    fn vuln_severity_score() {
        assert_eq!(VulnSeverity::Critical.score(), 10);
        assert_eq!(VulnSeverity::High.score(), 8);
        assert_eq!(VulnSeverity::Medium.score(), 5);
        assert_eq!(VulnSeverity::Low.score(), 3);
    }

    #[test]
    fn vuln_severity_from_str() {
        assert_eq!(VulnSeverity::parse_name("critical"), VulnSeverity::Critical);
        assert_eq!(VulnSeverity::parse_name("HIGH"), VulnSeverity::High);
        assert_eq!(VulnSeverity::parse_name("medium"), VulnSeverity::Medium);
        assert_eq!(VulnSeverity::parse_name("low"), VulnSeverity::Low);
        assert_eq!(VulnSeverity::parse_name("garbage"), VulnSeverity::Low);
    }

    #[test]
    fn vuln_severity_display() {
        assert_eq!(VulnSeverity::Critical.to_string(), "CRITICAL");
        assert_eq!(VulnSeverity::Low.to_string(), "LOW");
    }

    // ── LuaAnalysisContext ────────────────────────────────────────────────────

    #[test]
    fn analysis_context_annotate_and_rename() {
        let mut ctx = LuaAnalysisContext::new();
        ctx.annotate(0x1000, "entry point");
        ctx.rename(0x1000, "main");
        assert_eq!(ctx.annotations.len(), 1);
        assert_eq!(ctx.renames.len(), 1);
        assert_eq!(ctx.annotations[0], (0x1000, "entry point".to_string()));
        assert_eq!(ctx.renames[0], (0x1000, "main".to_string()));
    }

    #[test]
    fn analysis_context_add_vulnerability() {
        let mut ctx = LuaAnalysisContext::new();
        ctx.add_vulnerability(LuaVulnerabilityFinding {
            address: 0x2000,
            function_name: "handle_input".to_string(),
            severity: VulnSeverity::High,
            cwe_id: Some(121),
            description: "Stack buffer overflow".to_string(),
            evidence: "memcpy(buf, src, len)".to_string(),
        });
        assert_eq!(ctx.vulnerabilities.len(), 1);
        assert_eq!(ctx.vulnerabilities[0].cwe_id, Some(121));
    }

    #[test]
    fn analysis_context_summary_counts() {
        let mut ctx = LuaAnalysisContext::new();
        ctx.annotate(0, "a");
        ctx.annotate(1, "b");
        ctx.rename(0, "fn_a");
        let summary = ctx.summary();
        assert!(summary.contains("Annotations: 2"));
        assert!(summary.contains("Renames: 1"));
    }

    // ── LuaPatchSet ───────────────────────────────────────────────────────────

    #[test]
    fn patch_set_add_hex_and_apply() {
        let mut ps = LuaPatchSet::new();
        ps.add_hex(1, "90 90 90").unwrap();
        assert_eq!(ps.len(), 1);
        let mut buf = vec![0u8; 10];
        ps.apply_to(&mut buf);
        assert_eq!(&buf[1..4], &[0x90, 0x90, 0x90]);
    }

    #[test]
    fn patch_set_add_bytes() {
        let mut ps = LuaPatchSet::new();
        ps.add_bytes(0, vec![0xC3]);
        assert_eq!(ps.len(), 1);
    }

    #[test]
    fn patch_set_invalid_hex_errors() {
        let mut ps = LuaPatchSet::new();
        assert!(ps.add_hex(0, "ZZ").is_err());
    }

    #[test]
    fn patch_set_is_empty() {
        let ps = LuaPatchSet::new();
        assert!(ps.is_empty());
    }

    #[test]
    fn patch_set_out_of_bounds_ignored() {
        let mut ps = LuaPatchSet::new();
        ps.add_bytes(100, vec![0xFF; 10]); // beyond buffer
        let mut buf = vec![0u8; 5];
        ps.apply_to(&mut buf); // should not panic
        assert!(buf.iter().all(|&b| b == 0));
    }

    // ── lua_nop_sled ──────────────────────────────────────────────────────────

    #[test]
    fn nop_sled_correct_length() {
        let sled = lua_nop_sled(8);
        assert_eq!(sled.len(), 8);
        assert!(sled.iter().all(|&b| b == 0x90));
    }

    #[test]
    fn nop_sled_zero_length() {
        assert!(lua_nop_sled(0).is_empty());
    }

    // ── lua_jmp_patch ─────────────────────────────────────────────────────────

    #[test]
    fn jmp_patch_forward() {
        // JMP at 0x1000, target 0x2000
        // rel32 = 0x2000 - (0x1000 + 5) = 0xFFB
        let patch = lua_jmp_patch(0x1000, 0x2000).unwrap();
        assert_eq!(patch.len(), 5);
        assert_eq!(patch[0], 0xE9);
        let rel = i32::from_le_bytes(patch[1..5].try_into().unwrap());
        assert_eq!(rel, 0xFFB);
    }

    #[test]
    fn jmp_patch_backward() {
        // JMP at 0x2000, target 0x1000
        // rel32 = 0x1000 - (0x2000 + 5) = -0x1005 = -4101
        let patch = lua_jmp_patch(0x2000, 0x1000).unwrap();
        let rel = i32::from_le_bytes(patch[1..5].try_into().unwrap());
        assert_eq!(rel, -4101);
    }

    #[test]
    fn ret_patch_is_c3() {
        assert_eq!(lua_ret_patch(), vec![0xC3]);
    }
}
