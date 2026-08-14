//! Reverse-engineering Lua bindings for the `RustRE` Suite.
//!
//! Registers a `rustre` table in a [`mlua::Lua`] instance with functions
//! covering binary analysis, disassembly helpers, and data utilities.
//!
//! # Usage
//!
//! ```no_run
//! use mlua::Lua;
//! use rustre_script_lua::lua_re_bindings::LuaReBindings;
//!
//! let lua = Lua::new();
//! LuaReBindings::default().register_all(&lua).unwrap();
//! lua.load(r#"
//!     local info = rustre.detect_format("\x7fELF")
//!     print(info)
//! "#).exec().unwrap();
//! ```

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use mlua::{Lua, Result as LuaResult, Table, Value};

// ─────────────────────────────────────────────────────────────────────────────
// In-process binary store
// ─────────────────────────────────────────────────────────────────────────────

/// Thread-safe store mapping binary id → raw bytes.
#[derive(Debug, Default, Clone)]
pub struct DataStore {
    inner: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl DataStore {
    /// Create a new empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a binary by id.
    pub fn insert(&self, id: String, data: Vec<u8>) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, data);
    }

    /// Retrieve a binary by id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<Vec<u8>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .cloned()
    }

    /// Remove a binary by id.
    pub fn remove(&self, id: &str) {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(id);
    }

    /// List all stored binary ids.
    #[must_use]
    pub fn list(&self) -> Vec<String> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .cloned()
            .collect()
    }

    /// Number of binaries in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FunctionBinding / DataBinding
// ─────────────────────────────────────────────────────────────────────────────

/// Descriptor for a single Lua function registered in the `rustre` table.
#[derive(Debug, Clone)]
pub struct FunctionBinding {
    /// Name of the function within the `rustre` table.
    pub name: &'static str,
    /// One-line description of what the function does.
    pub description: &'static str,
    /// Expected argument types (informational).
    pub arg_types: &'static [&'static str],
    /// Return type description (informational).
    pub return_type: &'static str,
}

/// Descriptor for a data value registered in the `rustre` table.
#[derive(Debug, Clone)]
pub struct DataBinding {
    /// Name of the key within the `rustre` table.
    pub name: &'static str,
    /// One-line description.
    pub description: &'static str,
}

/// All function bindings provided by [`LuaReBindings`].
pub const FUNCTION_BINDINGS: &[FunctionBinding] = &[
    FunctionBinding {
        name: "load_bytes",
        description: "Load a raw byte string into the binary store; returns its id",
        arg_types: &["string"],
        return_type: "string",
    },
    FunctionBinding {
        name: "load_hex",
        description: "Parse a hex string and load the decoded bytes; returns id",
        arg_types: &["string"],
        return_type: "string",
    },
    FunctionBinding {
        name: "unload",
        description: "Remove a binary from the store by id",
        arg_types: &["string"],
        return_type: "nil",
    },
    FunctionBinding {
        name: "list_binaries",
        description: "Return a table of all loaded binary ids",
        arg_types: &[],
        return_type: "table",
    },
    FunctionBinding {
        name: "detect_format",
        description: "Detect the file format of a binary given its first bytes",
        arg_types: &["string"],
        return_type: "string",
    },
    FunctionBinding {
        name: "bytes_at",
        description: "Return a hex string of `count` bytes at `offset` from binary id",
        arg_types: &["string", "integer", "integer"],
        return_type: "string",
    },
    FunctionBinding {
        name: "entropy",
        description: "Compute Shannon entropy (bits per byte) of a byte string",
        arg_types: &["string"],
        return_type: "number",
    },
    FunctionBinding {
        name: "xor_bytes",
        description: "XOR each byte in a string with key (integer 0–255)",
        arg_types: &["string", "integer"],
        return_type: "string",
    },
    FunctionBinding {
        name: "find_pattern",
        description: "Search binary id for hex pattern; returns offset or nil",
        arg_types: &["string", "string"],
        return_type: "integer|nil",
    },
    FunctionBinding {
        name: "find_strings",
        description: "Extract printable strings (min_len default 4) from binary id",
        arg_types: &["string", "integer?"],
        return_type: "table",
    },
    FunctionBinding {
        name: "hex_encode",
        description: "Encode a binary string to lowercase hex",
        arg_types: &["string"],
        return_type: "string",
    },
    FunctionBinding {
        name: "hex_decode",
        description: "Decode a hex string to binary bytes",
        arg_types: &["string"],
        return_type: "string",
    },
    FunctionBinding {
        name: "crc32",
        description: "Compute the CRC-32 (IEEE) of a byte string",
        arg_types: &["string"],
        return_type: "integer",
    },
    FunctionBinding {
        name: "adler32",
        description: "Compute the Adler-32 checksum of a byte string",
        arg_types: &["string"],
        return_type: "integer",
    },
    FunctionBinding {
        name: "rot13",
        description: "Apply ROT-13 to an ASCII string",
        arg_types: &["string"],
        return_type: "string",
    },
    FunctionBinding {
        name: "byte_histogram",
        description: "Return a table of 256 byte-frequency counts for binary id",
        arg_types: &["string"],
        return_type: "table",
    },
    FunctionBinding {
        name: "version",
        description: "Return the rustre binding version string",
        arg_types: &[],
        return_type: "string",
    },
];

/// All data bindings provided by [`LuaReBindings`].
pub const DATA_BINDINGS: &[DataBinding] = &[
    DataBinding {
        name: "VERSION",
        description: "RustRE Lua binding version",
    },
];

// ─────────────────────────────────────────────────────────────────────────────
// LuaReBindings
// ─────────────────────────────────────────────────────────────────────────────

/// Registers all `RustRE` reverse-engineering functions into a Lua instance.
///
/// All functions are placed into a global table named `rustre`.  The table
/// is created fresh; if it already exists it is extended (existing keys are
/// preserved).
#[derive(Debug, Default, Clone)]
pub struct LuaReBindings {
    /// Shared binary store.  If `None`, a fresh store is created per `Lua`.
    pub store: Option<DataStore>,
    /// Whether to register the `rustre.VERSION` constant.
    pub include_version: bool,
}

impl LuaReBindings {
    /// Create a new binding set with a fresh data store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: Some(DataStore::new()),
            include_version: true,
        }
    }

    /// Create a binding set sharing the given data store.
    #[must_use]
    pub const fn with_store(store: DataStore) -> Self {
        Self {
            store: Some(store),
            include_version: true,
        }
    }

    /// Register all bindings into `lua`.
    ///
    /// Creates or updates the global `rustre` table.
    ///
    /// # Errors
    /// Returns a [`mlua::Error`] if any registration step fails.
    pub fn register_all(&self, lua: &Lua) -> LuaResult<()> {
        let store = self.store.clone().unwrap_or_default();
        let tbl = get_or_create_rustre_table(lua)?;
        Self::register_io_fns(lua, &tbl, store.clone())?;
        Self::register_static_fns(lua, &tbl)?;
        Self::register_search_fns(lua, &tbl, store)?;
        if self.include_version {
            tbl.set("VERSION", "0.1.0")?;
        }
        lua.globals().set("rustre", tbl)?;
        Ok(())
    }

    fn register_io_fns(lua: &Lua, tbl: &Table, store: DataStore) -> LuaResult<()> {
        // ── load_bytes ────────────────────────────────────────────────────────
        {
            let s = store.clone();
            tbl.set("load_bytes", lua.create_function(move |_, bytes: mlua::String| {
                let data = bytes.as_bytes().to_vec();
                let id = format!("binary_{}", s.len());
                s.insert(id.clone(), data);
                Ok(id)
            })?)?;
        }
        // ── load_hex ─────────────────────────────────────────────────────────
        {
            let s = store.clone();
            tbl.set("load_hex", lua.create_function(move |_, hex: String| {
                let cleaned: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
                let bytes = hex_decode_str(&cleaned);
                let id = format!("binary_{}", s.len());
                s.insert(id.clone(), bytes);
                Ok(id)
            })?)?;
        }
        // ── unload ────────────────────────────────────────────────────────────
        {
            let s = store.clone();
            tbl.set("unload", lua.create_function(move |_, id: String| { s.remove(&id); Ok(()) })?)?;
        }
        // ── list_binaries ─────────────────────────────────────────────────────
        {
            let s = store.clone();
            tbl.set("list_binaries", lua.create_function(move |lua, (): ()| {
                let ids = s.list();
                let t = lua.create_table()?;
                for (i, id) in ids.iter().enumerate() { t.set(i + 1, id.as_str())?; }
                Ok(t)
            })?)?;
        }
        // ── bytes_at ─────────────────────────────────────────────────────────
        {
            let s = store;
            tbl.set("bytes_at", lua.create_function(move |_, (id, offset, count): (String, usize, usize)| {
                let data = s.get(&id).unwrap_or_default();
                let end = (offset + count).min(data.len());
                let slice = if offset < data.len() { &data[offset..end] } else { &[] };
                let hex: String = slice.iter().fold(String::new(), |mut st, b: &u8| { let _ = write!(st, "{b:02x}"); st });
                Ok(hex)
            })?)?;
        }
        Ok(())
    }

    fn register_static_fns(lua: &Lua, tbl: &Table) -> LuaResult<()> {
        // ── detect_format ─────────────────────────────────────────────────────
        tbl.set("detect_format", lua.create_function(|_, bytes: mlua::String| {
            let b: Vec<u8> = bytes.as_bytes().to_vec();
            Ok(detect_format(&b))
        })?)?;
        // ── entropy ───────────────────────────────────────────────────────────
        tbl.set("entropy", lua.create_function(|_, bytes: mlua::String| {
            let data: Vec<u8> = bytes.as_bytes().to_vec();
            Ok(compute_entropy(&data))
        })?)?;
        // ── xor_bytes ─────────────────────────────────────────────────────────
        tbl.set("xor_bytes", lua.create_function(|lua, (bytes, key): (mlua::String, u8)| {
            let raw: Vec<u8> = bytes.as_bytes().to_vec();
            let result: Vec<u8> = raw.iter().map(|&b| b ^ key).collect();
            lua.create_string(result.as_slice())
        })?)?;
        // ── hex_encode ────────────────────────────────────────────────────────
        tbl.set("hex_encode", lua.create_function(|_, bytes: mlua::String| {
            let raw: Vec<u8> = bytes.as_bytes().to_vec();
            let hex: String = raw.iter().fold(String::new(), |mut s, b| { let _ = write!(s, "{b:02x}"); s });
            Ok(hex)
        })?)?;
        // ── hex_decode ────────────────────────────────────────────────────────
        tbl.set("hex_decode", lua.create_function(|lua, hex: String| {
            lua.create_string(hex_decode_str(&hex).as_slice())
        })?)?;
        // ── crc32 ─────────────────────────────────────────────────────────────
        tbl.set("crc32", lua.create_function(|_, bytes: mlua::String| {
            let raw: Vec<u8> = bytes.as_bytes().to_vec();
            Ok(i64::from(compute_crc32(&raw)))
        })?)?;
        // ── adler32 ───────────────────────────────────────────────────────────
        tbl.set("adler32", lua.create_function(|_, bytes: mlua::String| {
            let raw: Vec<u8> = bytes.as_bytes().to_vec();
            Ok(i64::from(compute_adler32(&raw)))
        })?)?;
        // ── rot13 ─────────────────────────────────────────────────────────────
        tbl.set("rot13", lua.create_function(|_, s: String| {
            let result: String = s.chars().map(|c| match c {
                'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
                'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
                _ => c,
            }).collect();
            Ok(result)
        })?)?;
        // ── version ───────────────────────────────────────────────────────────
        tbl.set("version", lua.create_function(|_, ()| Ok("rustre-lua-bindings/0.1.0"))?)?;
        Ok(())
    }

    fn register_search_fns(lua: &Lua, tbl: &Table, store: DataStore) -> LuaResult<()> {
        // ── find_pattern ──────────────────────────────────────────────────────
        {
            let s = store.clone();
            tbl.set("find_pattern", lua.create_function(move |_, (id, hex_pattern): (String, String)| {
                let data = s.get(&id).unwrap_or_default();
                let pattern = hex_decode_str(&hex_pattern);
                if pattern.is_empty() { return Ok(Value::Nil); }
                for i in 0..data.len().saturating_sub(pattern.len() - 1) {
                    if data[i..i + pattern.len()] == pattern[..] {
                        return Ok(Value::Integer(crate::casts::usize_to_i64(i)));
                    }
                }
                Ok(Value::Nil)
            })?)?;
        }
        // ── find_strings ──────────────────────────────────────────────────────
        {
            let s = store.clone();
            tbl.set("find_strings", lua.create_function(move |lua, (id, min_len): (String, Option<usize>)| {
                let data = s.get(&id).unwrap_or_default();
                let strings = extract_strings(&data, min_len.unwrap_or(4));
                let t = lua.create_table()?;
                for (i, (offset, sv)) in strings.iter().enumerate() {
                    let entry = lua.create_table()?;
                    entry.set("offset", *offset)?;
                    entry.set("value", sv.as_str())?;
                    t.set(i + 1, entry)?;
                }
                Ok(t)
            })?)?;
        }
        // ── byte_histogram ────────────────────────────────────────────────────
        {
            let s = store;
            tbl.set("byte_histogram", lua.create_function(move |lua, id: String| {
                let data = s.get(&id).unwrap_or_default();
                let mut freq = [0u64; 256];
                for &b in &data { freq[b as usize] += 1; }
                let t = lua.create_table()?;
                for (i, &count) in freq.iter().enumerate() { t.set(i, count)?; }
                Ok(t)
            })?)?;
        }
        Ok(())
    }

    /// Return the list of function descriptors.
    #[must_use]
    pub const fn function_bindings() -> &'static [FunctionBinding] {
        FUNCTION_BINDINGS
    }

    /// Return the list of data descriptors.
    #[must_use]
    pub const fn data_bindings() -> &'static [DataBinding] {
        DATA_BINDINGS
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Public registration helper
// ─────────────────────────────────────────────────────────────────────────────

/// Register all RE bindings into `lua` using a fresh shared store.
///
/// This is the most convenient entry point for users who don't need to
/// share the store between multiple Lua instances.
///
/// # Errors
/// Returns a [`mlua::Error`] if registration fails.
pub fn register_bindings(lua: &Lua) -> LuaResult<()> {
    LuaReBindings::new().register_all(lua)
}

/// Register bindings sharing the given [`DataStore`].
///
/// # Errors
/// Returns a [`mlua::Error`] if registration fails.
pub fn register_bindings_with_store(lua: &Lua, store: DataStore) -> LuaResult<()> {
    LuaReBindings::with_store(store).register_all(lua)
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure Rust helpers (no Lua dependency)
// ─────────────────────────────────────────────────────────────────────────────

/// Detect the file format from the first bytes of a binary.
#[must_use]
pub fn detect_format(data: &[u8]) -> &'static str {
    if data.starts_with(b"MZ") {
        "PE"
    } else if data.starts_with(b"\x7fELF") {
        "ELF"
    } else if data.starts_with(b"\xCA\xFE\xBA\xBE")
        || data.starts_with(b"\xCE\xFA\xED\xFE")
        || data.starts_with(b"\xCF\xFA\xED\xFE")
    {
        "Mach-O"
    } else if data.starts_with(b"\0asm") {
        "WASM"
    } else if data.starts_with(b"dex\n") {
        "DEX"
    } else if data.starts_with(b"PK\x03\x04") {
        "ZIP/JAR/APKXLSX"
    } else if data.starts_with(&[0x7F, 0x45, 0x4C, 0x46]) {
        "ELF"
    } else {
        "unknown"
    }
}

/// Compute Shannon entropy of a byte slice (bits per byte).
#[must_use]
pub fn compute_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = crate::casts::usize_to_f64(data.len());
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = crate::casts::u64_to_f64(c) / n;
            -p * p.log2()
        })
        .sum()
}

/// Decode a hex string (ignoring whitespace) into bytes.
#[must_use]
pub fn hex_decode_str(hex: &str) -> Vec<u8> {
    let hex: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    (0..hex.len().saturating_sub(hex.len() % 2))
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap_or(0))
        .collect()
}

/// Extract printable ASCII strings from `data` with minimum length `min_len`.
#[must_use]
pub fn extract_strings(data: &[u8], min_len: usize) -> Vec<(usize, String)> {
    let mut results = Vec::new();
    let mut current = String::new();
    let mut start = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
            if current.is_empty() {
                start = i;
            }
            current.push(b as char);
        } else {
            if current.len() >= min_len {
                results.push((start, current.clone()));
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        results.push((start, current));
    }
    results
}

/// Compute the CRC-32 (IEEE 802.3) checksum.
#[must_use]
pub fn compute_crc32(data: &[u8]) -> u32 {
    const POLY: u32 = 0xEDB8_8320;
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ POLY;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Compute the Adler-32 checksum.
#[must_use]
pub fn compute_adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + u32::from(byte)) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Get or create the global `rustre` table.
fn get_or_create_rustre_table(lua: &Lua) -> LuaResult<Table> {
    let globals = lua.globals();
    if let Ok(tbl) = globals.get::<Table>("rustre") { Ok(tbl) } else {
        let tbl = lua.create_table()?;
        globals.set("rustre", tbl.clone())?;
        Ok(tbl)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mlua::Function;

    #[test]
    fn test_detect_format_elf() {
        assert_eq!(detect_format(b"\x7fELF\x02\x01"), "ELF");
    }

    #[test]
    fn test_detect_format_pe() {
        assert_eq!(detect_format(b"MZ\x90\x00"), "PE");
    }

    #[test]
    fn test_detect_format_unknown() {
        assert_eq!(detect_format(b"\x00\x00\x00\x00"), "unknown");
    }

    #[test]
    fn test_entropy_uniform() {
        // 256 distinct bytes → entropy = 8.0
        let data: Vec<u8> = (0u8..=255).collect();
        let e = compute_entropy(&data);
        assert!((e - 8.0).abs() < 1e-9, "got {e}");
    }

    #[test]
    fn test_entropy_constant() {
        let data = vec![0xABu8; 100];
        let e = compute_entropy(&data);
        assert_eq!(e, 0.0);
    }

    #[test]
    fn test_hex_decode_roundtrip() {
        let original = b"\xDE\xAD\xBE\xEF";
        let hex = "deadbeef";
        let decoded = hex_decode_str(hex);
        assert_eq!(decoded.as_slice(), original);
    }

    #[test]
    fn test_extract_strings_basic() {
        let data = b"hello\x00world\x00ab\x00";
        let strings = extract_strings(data, 4);
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].1, "hello");
        assert_eq!(strings[1].1, "world");
    }

    #[test]
    fn test_crc32_empty() {
        assert_eq!(compute_crc32(b""), 0x0000_0000);
    }

    #[test]
    fn test_crc32_known() {
        // CRC32("123456789") = 0xCBF43926
        assert_eq!(compute_crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn test_adler32_known() {
        // adler32("Wikipedia") = 0x11E60398
        assert_eq!(compute_adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn test_data_store_insert_get() {
        let store = DataStore::new();
        store.insert("id1".to_string(), vec![1, 2, 3]);
        assert_eq!(store.get("id1"), Some(vec![1, 2, 3]));
    }

    #[test]
    fn test_data_store_remove() {
        let store = DataStore::new();
        store.insert("x".to_string(), vec![0]);
        store.remove("x");
        assert!(store.get("x").is_none());
    }

    #[test]
    fn test_register_bindings() {
        let lua = Lua::new();
        register_bindings(&lua).unwrap();
        let rustre: mlua::Table = lua.globals().get("rustre").unwrap();
        let version: String = rustre.get::<Function>("version").unwrap()
            .call::<String>(()).unwrap();
        assert!(version.contains("rustre"));
    }

    #[test]
    fn test_lua_detect_format() {
        let lua = Lua::new();
        register_bindings(&lua).unwrap();
        let result: String = lua
            .load(r#"return rustre.detect_format("\x7fELF\x02\x01")"#)
            .eval()
            .unwrap();
        assert_eq!(result, "ELF");
    }

    #[test]
    fn test_lua_entropy() {
        let lua = Lua::new();
        register_bindings(&lua).unwrap();
        let e: f64 = lua
            .load(r#"return rustre.entropy("AAAA")"#)
            .eval()
            .unwrap();
        assert_eq!(e, 0.0);
    }

    #[test]
    fn test_lua_xor_bytes() {
        let lua = Lua::new();
        register_bindings(&lua).unwrap();
        // XOR "A" (0x41) with 0xFF → 0xBE
        let result: mlua::String = lua
            .load(r#"return rustre.xor_bytes("A", 0xFF)"#)
            .eval()
            .unwrap();
        assert_eq!(result.as_bytes()[0], 0x41 ^ 0xFF);
    }

    #[test]
    fn test_lua_hex_encode_decode() {
        let lua = Lua::new();
        register_bindings(&lua).unwrap();
        let hex: String = lua
            .load(r#"return rustre.hex_encode("\xDE\xAD")"#)
            .eval()
            .unwrap();
        assert_eq!(hex, "dead");
    }

    #[test]
    fn test_lua_crc32() {
        let lua = Lua::new();
        register_bindings(&lua).unwrap();
        let crc: i64 = lua
            .load(r#"return rustre.crc32("123456789")"#)
            .eval()
            .unwrap();
        assert_eq!(crate::casts::i64_to_u32(crc), 0xCBF4_3926);
    }

    #[test]
    fn test_lua_rot13() {
        let lua = Lua::new();
        register_bindings(&lua).unwrap();
        let r: String = lua
            .load(r#"return rustre.rot13("Hello")"#)
            .eval()
            .unwrap();
        assert_eq!(r, "Uryyb");
    }
}
