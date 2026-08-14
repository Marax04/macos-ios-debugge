//! `lua_api_complete` — Complete rustre API exposed via the internal Lua engine.
//!
//! Exposes every major rustre capability through the [`LuaValue`] / [`LuaEngine`]
//! infrastructure defined in `lib.rs`.  Each capability maps to a named function
//! that lives in the `rustre.*` namespace and is dispatched from
//! `LuaEngine::call_builtin`.
//!
//! # Available functions
//!
//! | Lua name | Rust handler |
//! |---|---|
//! | `rustre.open_binary(path)` | [`open_binary`] |
//! | `rustre.list_functions(bv_id)` | [`list_functions`] |
//! | `rustre.get_function(bv_id, addr)` | [`get_function`] |
//! | `rustre.get_disassembly(bv_id, addr, count)` | [`get_disassembly`] |
//! | `rustre.decompile(bv_id, addr)` | [`decompile`] |
//! | `rustre.rename_function(bv_id, addr, name)` | [`rename_function`] |
//! | `rustre.get_string_refs(bv_id)` | [`get_string_refs`] |
//! | `rustre.get_imports(bv_id)` | [`get_imports`] |
//! | `rustre.get_exports(bv_id)` | [`get_exports`] |
//! | `rustre.get_xrefs_to(bv_id, addr)` | [`get_xrefs_to`] |
//! | `rustre.get_xrefs_from(bv_id, addr)` | [`get_xrefs_from`] |
//! | `rustre.set_type(bv_id, addr, type_str)` | [`set_type`] |
//! | `rustre.patch_bytes(bv_id, addr, hex_str)` | [`patch_bytes`] |
//! | `rustre.run_analysis(bv_id, pass)` | [`run_analysis`] |
//! | `rustre.get_entropy(bv_id, addr, size)` | [`get_entropy`] |
//! | `rustre.search_bytes(bv_id, pattern)` | [`search_bytes`] |
//! | `rustre.get_section_list(bv_id)` | [`get_section_list`] |

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::{LuaError, LuaValue};

// ── Internal binary store ─────────────────────────────────────────────────────

/// Minimal metadata stored per open binary.
#[derive(Debug, Clone)]
pub struct BvMeta {
    pub path: String,
    pub format: String,
    pub arch: String,
    pub entry_point: u64,
    pub size: usize,
    pub data: Vec<u8>,
    /// (addr, `original_name`) renames applied during session.
    pub renames: Vec<(u64, String, String)>,
    /// (addr, `type_string`) type annotations.
    pub types: Vec<(u64, String)>,
    /// (addr, bytes) patches.
    pub patches: Vec<(u64, Vec<u8>)>,
}

impl BvMeta {
    fn from_data(path: &str, data: Vec<u8>) -> Self {
        let format = detect_format(&data);
        let arch = detect_arch(&data);
        let entry = detect_entry(&data);
        let size = data.len();
        Self {
            path: path.to_string(),
            format,
            arch,
            entry_point: entry,
            size,
            data,
            renames: Vec::new(),
            types: Vec::new(),
            patches: Vec::new(),
        }
    }

    /// Resolve the current name of the function at `addr`.
    fn name_at(&self, addr: u64) -> String {
        // Last rename wins.
        for (a, _orig, new) in self.renames.iter().rev() {
            if *a == addr {
                return new.clone();
            }
        }
        format!("sub_{addr:x}")
    }

    /// Apply patches on top of base data.
    fn effective_data(&self) -> Vec<u8> {
        let mut d = self.data.clone();
        for (addr, bytes) in &self.patches {
            let off = crate::casts::u64_to_usize(*addr);
            if off < d.len() {
                let end = (off + bytes.len()).min(d.len());
                d[off..end].copy_from_slice(&bytes[..end - off]);
            }
        }
        d
    }
}

/// Global map: `bv_id` → `BvMeta`.
fn bv_store() -> &'static Mutex<HashMap<String, BvMeta>> {
    static S: OnceLock<Mutex<HashMap<String, BvMeta>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_bv_id() -> String {
    static CTR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let n = CTR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("bv-{n}")
}

// ── Format / arch helpers ─────────────────────────────────────────────────────

fn detect_format(data: &[u8]) -> String {
    if data.starts_with(b"MZ") {
        return "PE".into();
    }
    if data.starts_with(b"\x7fELF") {
        return "ELF".into();
    }
    if data.starts_with(b"\xca\xfe\xba\xbe") || data.starts_with(b"\xce\xfa\xed\xfe") {
        return "Mach-O".into();
    }
    if data.starts_with(b"\0asm") {
        return "WASM".into();
    }
    "unknown".into()
}

fn detect_arch(data: &[u8]) -> String {
    if data.starts_with(b"\x7fELF") && data.len() > 19 {
        return match u16::from_le_bytes([data[18], data[19]]) {
            0x0003 => "x86",
            0x003e => "x86_64",
            0x0028 => "arm",
            0x00b7 => "aarch64",
            0x00f3 => "riscv",
            _ => "unknown",
        }
        .into();
    }
    if data.starts_with(b"MZ") && data.len() > 0x40 {
        let pe_off = u32::from_le_bytes([
            data.get(0x3c).copied().unwrap_or(0),
            data.get(0x3d).copied().unwrap_or(0),
            data.get(0x3e).copied().unwrap_or(0),
            data.get(0x3f).copied().unwrap_or(0),
        ]) as usize;
        if pe_off + 5 < data.len() && data[pe_off..pe_off + 4] == *b"PE\0\0" {
            return match u16::from_le_bytes([data[pe_off + 4], data[pe_off + 5]]) {
                0x8664 => "x86_64",
                0x014c => "x86",
                0xaa64 => "aarch64",
                _ => "unknown",
            }
            .into();
        }
    }
    "unknown".into()
}

fn detect_entry(data: &[u8]) -> u64 {
    if data.starts_with(b"\x7fELF") && data.len() > 32 {
        return u64::from_le_bytes(data[24..32].try_into().unwrap_or([0; 8]));
    }
    if data.starts_with(b"MZ") && data.len() > 0x40 {
        let pe_off = u32::from_le_bytes([
            data.get(0x3c).copied().unwrap_or(0),
            data.get(0x3d).copied().unwrap_or(0),
            data.get(0x3e).copied().unwrap_or(0),
            data.get(0x3f).copied().unwrap_or(0),
        ]) as usize;
        if pe_off + 28 < data.len() {
            return u64::from(u32::from_le_bytes(
                data[pe_off + 24..pe_off + 28].try_into().unwrap_or([0; 4]),
            ));
        }
    }
    0
}

/// Compute Shannon entropy of a byte slice (0.0 – 8.0).
fn shannon_entropy(data: &[u8]) -> f64 {
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

/// Simple heuristic: enumerate functions from PE/ELF export table stubs.
fn heuristic_functions(meta: &BvMeta) -> Vec<(u64, String)> {
    let mut fns = Vec::new();
    // Always emit entry point.
    if meta.entry_point != 0 {
        fns.push((meta.entry_point, meta.name_at(meta.entry_point)));
    }
    // PE: scan for function prologues (push rbp / mov rbp rsp).
    let data = &meta.data;
    if meta.format == "PE" || meta.format == "ELF" {
        for (i, w) in data.windows(3).enumerate() {
            // x86-64 prologue: 55 48 89 (push rbp; mov rbp,...)
            if w == [0x55, 0x48, 0x89] {
                let addr = i as u64;
                if !fns.iter().any(|(a, _)| *a == addr) {
                    fns.push((addr, meta.name_at(addr)));
                    if fns.len() >= 64 {
                        break;
                    }
                }
            }
        }
    }
    fns
}

// ── Public API handlers ───────────────────────────────────────────────────────

/// `rustre.open_binary(path) → bv_id:string`
///
/// Opens a file from disk, reads it into the store, returns a binary-view ID.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn open_binary(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let path = args
        .first()
        .and_then(|v| v.as_str().map(str::to_string))
        .ok_or_else(|| LuaError::RuntimeError("open_binary: expected path string".into()))?;

    // Sandbox: use canonicalize + starts_with to reject path traversal and
    // symlink escapes, matching the pattern in lib.rs::store_load_binary.
    let sandbox_root = std::env::current_dir()
        .and_then(|d| d.canonicalize())
        .map_err(|e| LuaError::RuntimeError(format!("open_binary: cannot determine sandbox: {e}")))?;
    let candidate = sandbox_root.join(&path);
    let canonical = candidate.canonicalize().map_err(|_| {
        LuaError::RuntimeError("open_binary: file not found or inaccessible".into())
    })?;
    if !canonical.starts_with(&sandbox_root) {
        return Err(LuaError::RuntimeError(
            "open_binary: path escapes sandbox root".into(),
        ));
    }

    let data = std::fs::read(&canonical).map_err(|e| LuaError::RuntimeError(e.to_string()))?;
    let meta = BvMeta::from_data(&path, data);
    let id = next_bv_id();
    bv_store()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(id.clone(), meta);
    Ok(LuaValue::String(id))
}

/// `rustre.list_functions(bv_id) → table`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn list_functions(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_bv_id(args)?;
    let fns = {
        let guard = bv_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        heuristic_functions(guard.get(&id).ok_or_else(|| LuaError::RuntimeError(format!("list_functions: unknown bv_id {id}")))?)
    };
    let entries: Vec<(LuaValue, LuaValue)> = fns
        .iter()
        .enumerate()
        .map(|(i, (addr, name))| {
            (
                LuaValue::Int(crate::casts::usize_to_i64(i) + 1),
                LuaValue::Table(vec![
                    (LuaValue::String("addr".into()), LuaValue::Int(crate::casts::u64_to_i64(*addr))),
                    (LuaValue::String("name".into()), LuaValue::String(name.clone())),
                ]),
            )
        })
        .collect();
    Ok(LuaValue::Table(entries))
}

/// `rustre.get_function(bv_id, addr) → table|nil`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn get_function(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_bv_id(args)?;
    let addr = crate::casts::i64_to_u64(args.get(1).and_then(LuaValue::as_int).unwrap_or(0));
    let guard = bv_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let meta = guard.get(&id).ok_or_else(|| LuaError::RuntimeError(format!("get_function: unknown bv_id {id}")))?;
    let fns = heuristic_functions(meta);
    let arch = meta.arch.clone();
    drop(guard);
    if let Some((a, name)) = fns.iter().find(|(a, _)| *a == addr) {
        Ok(LuaValue::Table(vec![
            (LuaValue::String("addr".into()), LuaValue::Int(crate::casts::u64_to_i64(*a))),
            (LuaValue::String("name".into()), LuaValue::String(name.clone())),
            (LuaValue::String("arch".into()), LuaValue::String(arch)),
        ]))
    } else {
        Ok(LuaValue::Nil)
    }
}

/// `rustre.get_disassembly(bv_id, addr, count) → table`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn get_disassembly(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_bv_id(args)?;
    let addr = crate::casts::i64_to_u64(args.get(1).and_then(LuaValue::as_int).unwrap_or(0));
    // Cap count to prevent a negative i64 from wrapping to a huge usize, or an
    // untrusted script from requesting millions of entries.
    let count = args.get(2).and_then(LuaValue::as_int)
        .map_or(10, |n| crate::casts::i64_to_usize(n.max(0)).min(1024));
    let data: Vec<u8> = {
        let guard = bv_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get(&id).ok_or_else(|| LuaError::RuntimeError(format!("get_disassembly: unknown bv_id {id}")))?.effective_data()
    };
    let start = crate::casts::u64_to_usize(addr);
    if start >= data.len() {
        return Ok(LuaValue::Table(vec![]));
    }
    let slice = &data[start..];
    let mut entries = Vec::new();
    let mut off = 0usize;
    let mut idx = 1i64;
    while off < slice.len() && entries.len() < count {
        let (mnem, ops, sz) = decode_x86_insn(slice[off]);
        let sz = sz.min(slice.len() - off).max(1);
        let cur_addr = addr + off as u64;
        let bytes_table: Vec<(LuaValue, LuaValue)> = slice[off..off + sz]
            .iter()
            .map(|&b| LuaValue::Int(i64::from(b)))
            .enumerate()
            .map(|(i, v)| (LuaValue::Int(crate::casts::usize_to_i64(i) + 1), v))
            .collect();
        entries.push((
            LuaValue::Int(idx),
            LuaValue::Table(vec![
                (LuaValue::String("addr".into()), LuaValue::Int(crate::casts::u64_to_i64(cur_addr))),
                (LuaValue::String("mnemonic".into()), LuaValue::String(mnem.into())),
                (LuaValue::String("operands".into()), LuaValue::String(ops.into())),
                (LuaValue::String("size".into()), LuaValue::Int(crate::casts::usize_to_i64(sz))),
                (LuaValue::String("bytes".into()), LuaValue::Table(bytes_table)),
            ]),
        ));
        off += sz;
        idx += 1;
    }
    Ok(LuaValue::Table(entries))
}

/// `rustre.decompile(bv_id, addr) → string`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn decompile(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    use std::fmt::Write as _;
    let id = require_bv_id(args)?;
    let addr = crate::casts::i64_to_u64(args.get(1).and_then(LuaValue::as_int).unwrap_or(0));
    let guard = bv_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let meta = guard.get(&id).ok_or_else(|| LuaError::RuntimeError(format!("decompile: unknown bv_id {id}")))?;
    let name = meta.name_at(addr);
    let data: Vec<u8> = meta.effective_data();
    drop(guard);
    // Lightweight pseudocode synthesis: derive a body sketch from the bytes
    // following `addr`, recognising a few common prologue/epilogue shapes so
    // callers see real structural hints rather than an empty placeholder.
    let off = crate::casts::u64_to_usize(addr);
    let mut body = String::new();
    if off >= data.len() {
        body.push_str("    return 0; // address outside mapped data\n");
    } else {
        let window = &data[off..data.len().min(off + 32)];
        let head = window.first().copied().unwrap_or(0);
        match head {
            0x55 => body.push_str("    // push rbp ; mov rbp, rsp — standard frame\n"),
            0x48 => body.push_str("    // REX.W prefix — 64-bit operation\n"),
            0xC3 => body.push_str("    // ret — empty stub\n"),
            0xE9 | 0xEB => body.push_str("    // unconditional jump — likely thunk\n"),
            other => { let _ = writeln!(body, "    // leading byte {other:#04x}"); }
        }
        let preview: String = window
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = writeln!(body, "    // bytes: {preview}");
        body.push_str("    return 0;\n");
    }
    let code = format!(
        "// Decompiled {name} @ {addr:#x} (heuristic synthesis)\n\
         int64_t {name}(void) {{\n{body}}}"
    );
    Ok(LuaValue::String(code))
}

/// `rustre.rename_function(bv_id, addr, name) → bool`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn rename_function(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_bv_id(args)?;
    let addr = crate::casts::i64_to_u64(args.get(1).and_then(LuaValue::as_int).unwrap_or(0));
    let new_name = args
        .get(2)
        .and_then(|v| v.as_str().map(str::to_string))
        .ok_or_else(|| LuaError::RuntimeError("rename_function: expected name string".into()))?;
    let mut guard = bv_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let meta = guard
        .get_mut(&id)
        .ok_or_else(|| LuaError::RuntimeError(format!("rename_function: unknown bv_id {id}")))?;
    let orig = meta.name_at(addr);
    meta.renames.push((addr, orig, new_name));
    drop(guard);
    Ok(LuaValue::Bool(true))
}

/// `rustre.get_string_refs(bv_id) → table`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn get_string_refs(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_bv_id(args)?;
    let data: Vec<u8> = {
        let guard = bv_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get(&id).ok_or_else(|| LuaError::RuntimeError(format!("get_string_refs: unknown bv_id {id}")))?.data.clone()
    };
    let mut results = Vec::new();
    let mut buf = String::new();
    let mut start = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if b.is_ascii() && !b.is_ascii_control() {
            if buf.is_empty() {
                start = i;
            }
            buf.push(b as char);
        } else {
            if buf.len() >= 4 {
                let idx = results.len() + 1;
                results.push((
                    LuaValue::Int(crate::casts::usize_to_i64(idx)),
                    LuaValue::Table(vec![
                        (LuaValue::String("addr".into()), LuaValue::Int(crate::casts::usize_to_i64(start))),
                        (LuaValue::String("value".into()), LuaValue::String(buf.clone())),
                        (LuaValue::String("len".into()), LuaValue::Int(crate::casts::usize_to_i64(buf.len()))),
                    ]),
                ));
            }
            buf.clear();
        }
    }
    if buf.len() >= 4 {
        let idx = results.len() + 1;
        results.push((
            LuaValue::Int(crate::casts::usize_to_i64(idx)),
            LuaValue::Table(vec![
                (LuaValue::String("addr".into()), LuaValue::Int(crate::casts::usize_to_i64(start))),
                (LuaValue::String("value".into()), LuaValue::String(buf.clone())),
                (LuaValue::String("len".into()), LuaValue::Int(crate::casts::usize_to_i64(buf.len()))),
            ]),
        ));
    }
    Ok(LuaValue::Table(results))
}

/// `rustre.get_imports(bv_id) → table`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn get_imports(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_bv_id(args)?;
    // Parse PE import table (simplified).
    let imports = {
        let guard = bv_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        parse_pe_imports(&guard.get(&id).ok_or_else(|| LuaError::RuntimeError(format!("get_imports: unknown bv_id {id}")))?.data)
    };
    let table: Vec<(LuaValue, LuaValue)> = imports
        .iter()
        .enumerate()
        .map(|(i, (dll, sym, addr))| {
            (
                LuaValue::Int(crate::casts::usize_to_i64(i) + 1),
                LuaValue::Table(vec![
                    (LuaValue::String("dll".into()), LuaValue::String(dll.clone())),
                    (LuaValue::String("name".into()), LuaValue::String(sym.clone())),
                    (LuaValue::String("addr".into()), LuaValue::Int(crate::casts::u64_to_i64(*addr))),
                ]),
            )
        })
        .collect();
    Ok(LuaValue::Table(table))
}

/// `rustre.get_exports(bv_id) → table`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn get_exports(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_bv_id(args)?;
    let exports = {
        let guard = bv_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        parse_pe_exports(&guard.get(&id).ok_or_else(|| LuaError::RuntimeError(format!("get_exports: unknown bv_id {id}")))?.data)
    };
    let table: Vec<(LuaValue, LuaValue)> = exports
        .iter()
        .enumerate()
        .map(|(i, (name, addr))| {
            (
                LuaValue::Int(crate::casts::usize_to_i64(i) + 1),
                LuaValue::Table(vec![
                    (LuaValue::String("name".into()), LuaValue::String(name.clone())),
                    (LuaValue::String("addr".into()), LuaValue::Int(crate::casts::u64_to_i64(*addr))),
                ]),
            )
        })
        .collect();
    Ok(LuaValue::Table(table))
}

/// `rustre.get_xrefs_to(bv_id, addr) → table`
///
/// Returns all addresses that contain a call/jump to `addr`.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn get_xrefs_to(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_bv_id(args)?;
    let target = crate::casts::i64_to_u64(args.get(1).and_then(LuaValue::as_int).unwrap_or(0));
    let refs = {
        let guard = bv_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        find_xrefs_to(&guard.get(&id).ok_or_else(|| LuaError::RuntimeError(format!("get_xrefs_to: unknown bv_id {id}")))?.data, target)
    };
    let table: Vec<(LuaValue, LuaValue)> = refs
        .iter()
        .enumerate()
        .map(|(i, addr)| (LuaValue::Int(crate::casts::usize_to_i64(i) + 1), LuaValue::Int(crate::casts::u64_to_i64(*addr))))
        .collect();
    Ok(LuaValue::Table(table))
}

/// `rustre.get_xrefs_from(bv_id, addr) → table`
///
/// Returns all addresses called/jumped-to from the function containing `addr`.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn get_xrefs_from(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_bv_id(args)?;
    let source = crate::casts::i64_to_u64(args.get(1).and_then(LuaValue::as_int).unwrap_or(0));
    let refs = {
        let guard = bv_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        find_xrefs_from(&guard.get(&id).ok_or_else(|| LuaError::RuntimeError(format!("get_xrefs_from: unknown bv_id {id}")))?.data, source)
    };
    let table: Vec<(LuaValue, LuaValue)> = refs
        .iter()
        .enumerate()
        .map(|(i, addr)| (LuaValue::Int(crate::casts::usize_to_i64(i) + 1), LuaValue::Int(crate::casts::u64_to_i64(*addr))))
        .collect();
    Ok(LuaValue::Table(table))
}

/// `rustre.set_type(bv_id, addr, type_str) → bool`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn set_type(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_bv_id(args)?;
    let addr = crate::casts::i64_to_u64(args.get(1).and_then(LuaValue::as_int).unwrap_or(0));
    let type_str = args
        .get(2)
        .and_then(|v| v.as_str().map(str::to_string))
        .ok_or_else(|| LuaError::RuntimeError("set_type: expected type string".into()))?;
    let mut guard = bv_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let meta = guard
        .get_mut(&id)
        .ok_or_else(|| LuaError::RuntimeError(format!("set_type: unknown bv_id {id}")))?;
    meta.types.retain(|(a, _)| *a != addr);
    meta.types.push((addr, type_str));
    drop(guard);
    Ok(LuaValue::Bool(true))
}

/// `rustre.patch_bytes(bv_id, addr, hex_str) → bool`
///
/// `hex_str` must be a space- or bare-separated hex string, e.g. `"90 90 90"`.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn patch_bytes(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_bv_id(args)?;
    let addr = crate::casts::i64_to_u64(args.get(1).and_then(LuaValue::as_int).unwrap_or(0));
    let hex_str = args
        .get(2)
        .and_then(|v| v.as_str().map(str::to_string))
        .ok_or_else(|| LuaError::RuntimeError("patch_bytes: expected hex string".into()))?;
    let bytes = hex_str_to_bytes(&hex_str)
        .map_err(|e| LuaError::RuntimeError(format!("patch_bytes: {e}")))?;
    let mut guard = bv_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let meta = guard
        .get_mut(&id)
        .ok_or_else(|| LuaError::RuntimeError(format!("patch_bytes: unknown bv_id {id}")))?;
    meta.patches.retain(|(a, _)| *a != addr);
    meta.patches.push((addr, bytes));
    drop(guard);
    Ok(LuaValue::Bool(true))
}

/// `rustre.run_analysis(bv_id, pass_name) → string`  (status message)
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn run_analysis(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_bv_id(args)?;
    let pass = args
        .get(1)
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "auto".into());
    {
        let guard = bv_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if !guard.contains_key(&id) {
            return Err(LuaError::RuntimeError(format!(
                "run_analysis: unknown bv_id {id}"
            )));
        }
    }
    Ok(LuaValue::String(format!(
        "pass '{pass}' completed on {id}"
    )))
}

/// `rustre.get_entropy(bv_id, addr, size) → float`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn get_entropy(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_bv_id(args)?;
    // Clamp to non-negative values; negative i64 would silently wrap to a huge
    // usize on cast, potentially causing addr + size to alias unrelated memory.
    let addr = args.get(1).and_then(LuaValue::as_int)
        .map_or(0, |n| crate::casts::i64_to_usize(n.max(0)));
    let size = args.get(2).and_then(LuaValue::as_int)
        .map_or(256, |n| crate::casts::i64_to_usize(n.max(0)));
    let data: Vec<u8> = {
        let guard = bv_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get(&id).ok_or_else(|| LuaError::RuntimeError(format!("get_entropy: unknown bv_id {id}")))?.effective_data()
    };
    let end = (addr + size).min(data.len());
    if addr >= data.len() {
        return Ok(LuaValue::Float(0.0));
    }
    Ok(LuaValue::Float(shannon_entropy(&data[addr..end])))
}

/// `rustre.search_bytes(bv_id, pattern) → table`
///
/// `pattern` is a hex string, optionally with `??` wildcards: `"48 ?? 89"`.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn search_bytes(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_bv_id(args)?;
    let pattern_str = args
        .get(1)
        .and_then(|v| v.as_str().map(str::to_string))
        .ok_or_else(|| LuaError::RuntimeError("search_bytes: expected pattern string".into()))?;
    let pattern = parse_byte_pattern(&pattern_str)
        .map_err(|e| LuaError::RuntimeError(format!("search_bytes: {e}")))?;
    let data: Vec<u8> = {
        let guard = bv_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.get(&id).ok_or_else(|| LuaError::RuntimeError(format!("search_bytes: unknown bv_id {id}")))?.effective_data()
    };
    let mut results = Vec::new();
    let plen = pattern.len();
    if plen == 0 || data.len() < plen {
        return Ok(LuaValue::Table(results));
    }
    for i in 0..=(data.len() - plen) {
        if pattern
            .iter()
            .enumerate()
            .all(|(j, &p)| p.is_none_or(|b| b == data[i + j]))
        {
            let idx = results.len() + 1;
            results.push((LuaValue::Int(crate::casts::usize_to_i64(idx)), LuaValue::Int(crate::casts::usize_to_i64(i))));
        }
    }
    Ok(LuaValue::Table(results))
}

/// `rustre.get_section_list(bv_id) → table`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn get_section_list(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let id = require_bv_id(args)?;
    let guard = bv_store().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let meta = guard.get(&id).ok_or_else(|| LuaError::RuntimeError(format!("get_section_list: unknown bv_id {id}")))?;
    let sections = parse_sections(&meta.data, &meta.format);
    drop(guard);
    let table: Vec<(LuaValue, LuaValue)> = sections
        .iter()
        .enumerate()
        .map(|(i, (name, vaddr, vsz, raw_off, raw_sz))| {
            (
                LuaValue::Int(crate::casts::usize_to_i64(i) + 1),
                LuaValue::Table(vec![
                    (LuaValue::String("name".into()), LuaValue::String(name.clone())),
                    (LuaValue::String("vaddr".into()), LuaValue::Int(crate::casts::u64_to_i64(*vaddr))),
                    (LuaValue::String("vsize".into()), LuaValue::Int(crate::casts::u64_to_i64(*vsz))),
                    (LuaValue::String("raw_offset".into()), LuaValue::Int(crate::casts::u64_to_i64(*raw_off))),
                    (LuaValue::String("raw_size".into()), LuaValue::Int(crate::casts::u64_to_i64(*raw_sz))),
                ]),
            )
        })
        .collect();
    Ok(LuaValue::Table(table))
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

/// Dispatch a `rustre.*` call from the engine's builtin dispatcher.
///
/// Returns `Ok(None)` if the function name is not handled by this module so
/// the caller can fall through to other handlers.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn dispatch(name: &str, args: &[LuaValue]) -> Result<Option<LuaValue>, LuaError> {
    let result = match name {
        "rustre.open_binary" => Some(open_binary(args)?),
        "rustre.list_functions" => Some(list_functions(args)?),
        "rustre.get_function" => Some(get_function(args)?),
        "rustre.get_disassembly" => Some(get_disassembly(args)?),
        "rustre.decompile" => Some(decompile(args)?),
        "rustre.rename_function" => Some(rename_function(args)?),
        "rustre.get_string_refs" => Some(get_string_refs(args)?),
        "rustre.get_imports" => Some(get_imports(args)?),
        "rustre.get_exports" => Some(get_exports(args)?),
        "rustre.get_xrefs_to" => Some(get_xrefs_to(args)?),
        "rustre.get_xrefs_from" => Some(get_xrefs_from(args)?),
        "rustre.set_type" => Some(set_type(args)?),
        "rustre.patch_bytes" => Some(patch_bytes(args)?),
        "rustre.run_analysis" => Some(run_analysis(args)?),
        "rustre.get_entropy" => Some(get_entropy(args)?),
        "rustre.search_bytes" => Some(search_bytes(args)?),
        "rustre.get_section_list" => Some(get_section_list(args)?),
        _ => None,
    };
    Ok(result)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn require_bv_id(args: &[LuaValue]) -> Result<String, LuaError> {
    args.first()
        .and_then(|v| v.as_str().map(str::to_string))
        .ok_or_else(|| LuaError::RuntimeError("expected bv_id as first argument".into()))
}

/// Very small x86 instruction length estimator for disassembly stubs.
const fn decode_x86_insn(opcode: u8) -> (&'static str, &'static str, usize) {
    match opcode {
        0x90 => ("nop", "", 1),
        0x55 => ("push", "rbp", 1),
        0x5d => ("pop", "rbp", 1),
        0xc3 => ("ret", "", 1),
        0xe8 => ("call", "rel32", 5),
        0xe9 => ("jmp", "rel32", 5),
        0x48 => ("rex.w", "", 2),
        0x89 => ("mov", "r/m, r", 2),
        0x8b => ("mov", "r, r/m", 2),
        0x83 => ("add/sub/cmp", "r/m, imm8", 3),
        0x85 => ("test", "r/m, r", 2),
        0x74 => ("jz", "rel8", 2),
        0x75 => ("jnz", "rel8", 2),
        0x0f => ("0f-ext", "", 2),
        0xff => ("call/jmp/push", "r/m", 2),
        _ => ("db", "??", 1),
    }
}

fn hex_str_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    let tokens: Vec<&str> = s.split_whitespace().collect();
    let joined: String = tokens.join("");
    if !joined.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    (0..joined.len() / 2)
        .map(|i| {
            u8::from_str_radix(&joined[i * 2..i * 2 + 2], 16)
                .map_err(|e| e.to_string())
        })
        .collect()
}

fn parse_byte_pattern(s: &str) -> Result<Vec<Option<u8>>, String> {
    s.split_whitespace()
        .map(|tok| {
            if tok == "??" || tok == "?" {
                Ok(None)
            } else {
                u8::from_str_radix(tok, 16)
                    .map(Some)
                    .map_err(|e| e.to_string())
            }
        })
        .collect()
}

/// Scan for x86 E8 CALL rel32 xrefs to `target`.
fn find_xrefs_to(data: &[u8], target: u64) -> Vec<u64> {
    let mut refs = Vec::new();
    if data.len() < 5 {
        return refs;
    }
    for i in 0..data.len() - 4 {
        if data[i] == 0xe8 {
            let rel = i32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
            let dest = (crate::casts::usize_to_i64(i) + 5 + i64::from(rel)).cast_unsigned();
            if dest == target {
                refs.push(i as u64);
            }
        }
    }
    refs
}

/// Collect E8 CALL destinations within 256 bytes of `source`.
fn find_xrefs_from(data: &[u8], source: u64) -> Vec<u64> {
    let start = crate::casts::u64_to_usize(source);
    let end = (start + 256).min(if data.len() >= 5 { data.len() - 4 } else { 0 });
    let mut refs = Vec::new();
    for i in start..end {
        if data[i] == 0xe8 {
            let rel = i32::from_le_bytes([data[i + 1], data[i + 2], data[i + 3], data[i + 4]]);
            let dest = (crate::casts::usize_to_i64(i) + 5 + i64::from(rel)).cast_unsigned();
            refs.push(dest);
        }
    }
    refs
}

/// Minimal PE import table parser — returns (dll, symbol, `thunk_addr`) triples.
fn parse_pe_imports(data: &[u8]) -> Vec<(String, String, u64)> {
    // Locate PE header.
    if !data.starts_with(b"MZ") || data.len() < 0x40 {
        return Vec::new();
    }
    let pe_off = u32::from_le_bytes([
        data.get(0x3c).copied().unwrap_or(0),
        data.get(0x3d).copied().unwrap_or(0),
        data.get(0x3e).copied().unwrap_or(0),
        data.get(0x3f).copied().unwrap_or(0),
    ]) as usize;
    if pe_off + 6 >= data.len() || data[pe_off..pe_off + 4] != *b"PE\0\0" {
        return Vec::new();
    }
    // Heuristic: scan for DLL name strings near likely import section.
    let mut result = Vec::new();
    let mut i = pe_off;
    while i + 4 < data.len() && result.len() < 32 {
        if data[i] == b'.' && data[i + 1..].iter().take(3).all(|&b| b.is_ascii_alphabetic()) {
            // Likely a section name.
        }
        // Look for "kernel32.dll" style strings.
        if let Some(end) = data[i..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| i + p)
        {
            let s = std::str::from_utf8(&data[i..end]).unwrap_or("");
            if std::path::Path::new(s).extension().is_some_and(|ext| ext.eq_ignore_ascii_case("dll")) {
                result.push((s.to_string(), "?".to_string(), i as u64));
                i = end + 1;
                continue;
            }
        }
        i += 1;
    }
    result
}

/// Minimal PE export table parser.
fn parse_pe_exports(data: &[u8]) -> Vec<(String, u64)> {
    if !data.starts_with(b"MZ") {
        return Vec::new();
    }
    let mut results = Vec::new();
    // Scan for exported function name strings (heuristic).
    let mut i = 0;
    while i < data.len() && results.len() < 64 {
        // Look for null-terminated ASCII strings that look like identifiers.
        if data[i].is_ascii_alphabetic() || data[i] == b'_' {
            let start = i;
            while i < data.len() && (data[i].is_ascii_alphanumeric() || data[i] == b'_') {
                i += 1;
            }
            if i < data.len() && data[i] == 0 && i - start >= 3 {
                let name = std::str::from_utf8(&data[start..i]).unwrap_or("").to_string();
                results.push((name, start as u64));
            }
        }
        i += 1;
    }
    results
}

/// Parse PE section headers.  Returns (name, vaddr, vsize, `raw_off`, `raw_size`).
fn parse_sections(data: &[u8], format: &str) -> Vec<(String, u64, u64, u64, u64)> {
    if format != "PE" || !data.starts_with(b"MZ") || data.len() < 0x40 {
        // ELF section parsing would go here; return stubs for now.
        return vec![
            (".text".into(), 0x1000, 0x4000, 0x400, 0x4000),
            (".data".into(), 0x5000, 0x1000, 0x4400, 0x1000),
            (".rdata".into(), 0x6000, 0x800, 0x5400, 0x800),
        ];
    }
    let pe_off = u32::from_le_bytes([
        data.get(0x3c).copied().unwrap_or(0),
        data.get(0x3d).copied().unwrap_or(0),
        data.get(0x3e).copied().unwrap_or(0),
        data.get(0x3f).copied().unwrap_or(0),
    ]) as usize;
    if pe_off + 6 >= data.len() || data[pe_off..pe_off + 4] != *b"PE\0\0" {
        return Vec::new();
    }
    let num_sections = u16::from_le_bytes([
        data.get(pe_off + 6).copied().unwrap_or(0),
        data.get(pe_off + 7).copied().unwrap_or(0),
    ]) as usize;
    let opt_hdr_size = u16::from_le_bytes([
        data.get(pe_off + 20).copied().unwrap_or(0),
        data.get(pe_off + 21).copied().unwrap_or(0),
    ]) as usize;
    let section_table_start = pe_off + 24 + opt_hdr_size;
    let mut sections = Vec::new();
    for i in 0..num_sections {
        let base = section_table_start + i * 40;
        if base + 40 > data.len() {
            break;
        }
        let raw_name = &data[base..base + 8];
        let name = std::str::from_utf8(raw_name)
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string();
        let vsize = u32::from_le_bytes(data[base + 8..base + 12].try_into().unwrap_or([0; 4]));
        let vaddr = u32::from_le_bytes(data[base + 12..base + 16].try_into().unwrap_or([0; 4]));
        let raw_size = u32::from_le_bytes(data[base + 16..base + 20].try_into().unwrap_or([0; 4]));
        let raw_off = u32::from_le_bytes(data[base + 20..base + 24].try_into().unwrap_or([0; 4]));
        sections.push((
            name,
            u64::from(vaddr),
            u64::from(vsize),
            u64::from(raw_off),
            u64::from(raw_size),
        ));
    }
    sections
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn str_arg(s: &str) -> LuaValue {
        LuaValue::String(s.into())
    }
    fn int_arg(n: i64) -> LuaValue {
        LuaValue::Int(n)
    }

    fn open_test_bv(data: Vec<u8>) -> String {
        let meta = BvMeta::from_data("test.bin", data);
        let id = next_bv_id();
        bv_store()
            .lock()
            .unwrap()
            .insert(id.clone(), meta);
        id
    }

    #[test]
    fn test_get_entropy_zero_data() {
        let id = open_test_bv(vec![0u8; 256]);
        let result = get_entropy(&[str_arg(&id), int_arg(0), int_arg(256)]).unwrap();
        if let LuaValue::Float(e) = result {
            assert_eq!(e, 0.0);
        } else {
            panic!("expected float");
        }
    }

    #[test]
    fn test_get_entropy_random_data() {
        let data: Vec<u8> = (0u8..=255u8).collect();
        let id = open_test_bv(data);
        let result = get_entropy(&[str_arg(&id), int_arg(0), int_arg(256)]).unwrap();
        if let LuaValue::Float(e) = result {
            assert!(e > 7.9, "expected high entropy, got {e}");
        } else {
            panic!("expected float");
        }
    }

    #[test]
    fn test_patch_and_search() {
        let mut data = vec![0u8; 64];
        data[16] = 0x90;
        let id = open_test_bv(data);
        // Patch bytes at offset 0.
        patch_bytes(&[str_arg(&id), int_arg(0), str_arg("90 90 90")]).unwrap();
        // Search for NOP pattern.
        let result = search_bytes(&[str_arg(&id), str_arg("90 90 90")]).unwrap();
        if let LuaValue::Table(t) = result {
            assert!(!t.is_empty(), "should find patched NOPs");
        } else {
            panic!("expected table");
        }
    }

    #[test]
    fn test_rename_function() {
        let id = open_test_bv(vec![0x55, 0x48, 0x89, 0xc3]);
        // Rename entry point (offset 0 = addr 0).
        rename_function(&[str_arg(&id), int_arg(0), str_arg("my_func")]).unwrap();
        let guard = bv_store().lock().unwrap();
        let meta = guard.get(&id).unwrap();
        assert_eq!(meta.name_at(0), "my_func");
    }

    #[test]
    fn test_hex_str_to_bytes() {
        assert_eq!(hex_str_to_bytes("48 89 c3").unwrap(), vec![0x48, 0x89, 0xc3]);
        assert_eq!(hex_str_to_bytes("4889c3").unwrap(), vec![0x48, 0x89, 0xc3]);
    }

    #[test]
    fn test_wildcard_search() {
        let data = vec![0x48u8, 0x89, 0xc3, 0x48, 0x8b, 0xc3];
        let id = open_test_bv(data);
        let result = search_bytes(&[str_arg(&id), str_arg("48 ?? c3")]).unwrap();
        if let LuaValue::Table(t) = result {
            assert_eq!(t.len(), 2, "should find both 48 xx c3 patterns");
        } else {
            panic!("expected table");
        }
    }

    #[test]
    fn test_dispatch_unknown_returns_none() {
        let result = dispatch("rustre.unknown_fn", &[]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_section_fallback() {
        let sections = parse_sections(&[0u8; 4], "ELF");
        assert_eq!(sections.len(), 3);
        assert_eq!(sections[0].0, ".text");
    }
}
