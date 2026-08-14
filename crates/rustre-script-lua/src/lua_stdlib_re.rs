//! `lua_stdlib_re` — Reverse-engineering standard library for Lua scripts.
//!
//! Pure-Rust helper functions with no open binary required.  These work on raw
//! byte buffers passed as Lua strings (or hex strings) and return structured
//! Lua values.
//!
//! # Lua namespace: `re`
//!
//! | Function | Description |
//! |---|---|
//! | `re.pe_info(path)` | Parse PE header, return info table |
//! | `re.elf_info(path)` | Parse ELF header, return info table |
//! | `re.strings_from_file(path, min_len)` | Extract printable strings |
//! | `re.entropy(data)` | Shannon entropy of a Lua string |
//! | `re.xor_decrypt(data, key)` | XOR every byte with key (int or string) |
//! | `re.base64_decode(s)` | Decode base64 to Lua string |
//! | `re.hex_to_bytes(s)` | Convert hex string to byte string |
//! | `re.find_signature(data, sig)` | Find byte pattern in binary string |
//! | `re.calculate_hash(data, algo)` | md5/sha1/sha256 (simple implementations) |
//! | `re.disasm_bytes(arch, data, base)` | Disassemble raw bytes, return table |

use crate::{LuaError, LuaValue};

// ── Shannon entropy ───────────────────────────────────────────────────────────

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let n = crate::casts::usize_to_f64(data.len());
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

// ── PE info parser ────────────────────────────────────────────────────────────

/// Maximum file size allowed for `pe_info` / `elf_info` / `strings_from_file`.
const MAX_FILE_SIZE: u64 = 512 * 1024 * 1024; // 512 MiB

/// `re.pe_info(path) → table`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn pe_info(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    use std::io::Read as _;
    let path = require_string_arg(args, 0, "pe_info")?;
    let mut f = std::fs::File::open(&path).map_err(|e| LuaError::RuntimeError(e.to_string()))?;
    let file_size = f.metadata().map_or(0, |m| m.len());
    if file_size > MAX_FILE_SIZE {
        return Err(LuaError::RuntimeError(format!(
            "pe_info: file too large ({file_size} bytes, limit {MAX_FILE_SIZE})"
        )));
    }
    // Read from the already-open handle to avoid a TOCTOU race between the
    // size check above and a second open via fs::read.
    let mut data = Vec::new();
    f.read_to_end(&mut data).map_err(|e| LuaError::RuntimeError(e.to_string()))?;
    drop(f);
    if !data.starts_with(b"MZ") {
        return Err(LuaError::RuntimeError(format!(
            "pe_info: {path} is not a PE file"
        )));
    }
    if data.len() < 0x40 {
        return Err(LuaError::RuntimeError("pe_info: file too small".into()));
    }
    let pe_off = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    // `pe_off + 24` is the start of the optional header; we need indices up to
    // `pe_off + 23` (characteristics), so the guard must be `> data.len()`,
    // not `>=` (the original `>=` would reject a file where pe_off+24 == len,
    // but would still allow indexing pe_off+23 when pe_off+24 > len).
    if pe_off.saturating_add(24) > data.len() || data[pe_off..pe_off + 4] != *b"PE\0\0" {
        return Err(LuaError::RuntimeError("pe_info: invalid PE signature".into()));
    }
    let machine = u16::from_le_bytes([data[pe_off + 4], data[pe_off + 5]]);
    let num_sections = u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]);
    let timestamp = u32::from_le_bytes([
        data[pe_off + 8], data[pe_off + 9],
        data[pe_off + 10], data[pe_off + 11],
    ]);
    let characteristics = u16::from_le_bytes([data[pe_off + 22], data[pe_off + 23]]);
    let arch = match machine {
        0x8664 => "x86_64",
        0x014c => "x86",
        0xaa64 => "aarch64",
        0x01c4 => "arm",
        _ => "unknown",
    };
    // Optional header magic (PE32 / PE32+).
    let opt_off = pe_off + 24;
    let (entry_rva, image_base, image_size) = if opt_off + 4 < data.len() {
        let magic = u16::from_le_bytes([data[opt_off], data[opt_off + 1]]);
        let entry = u64::from(u32::from_le_bytes([
            data.get(opt_off + 16).copied().unwrap_or(0),
            data.get(opt_off + 17).copied().unwrap_or(0),
            data.get(opt_off + 18).copied().unwrap_or(0),
            data.get(opt_off + 19).copied().unwrap_or(0),
        ]));
        let (base, size) = if magic == 0x20b {
            // PE32+
            let b = u64::from_le_bytes([
                data.get(opt_off + 24).copied().unwrap_or(0),
                data.get(opt_off + 25).copied().unwrap_or(0),
                data.get(opt_off + 26).copied().unwrap_or(0),
                data.get(opt_off + 27).copied().unwrap_or(0),
                data.get(opt_off + 28).copied().unwrap_or(0),
                data.get(opt_off + 29).copied().unwrap_or(0),
                data.get(opt_off + 30).copied().unwrap_or(0),
                data.get(opt_off + 31).copied().unwrap_or(0),
            ]);
            let s = u64::from(u32::from_le_bytes([
                data.get(opt_off + 56).copied().unwrap_or(0),
                data.get(opt_off + 57).copied().unwrap_or(0),
                data.get(opt_off + 58).copied().unwrap_or(0),
                data.get(opt_off + 59).copied().unwrap_or(0),
            ]));
            (b, s)
        } else {
            let b = u64::from(u32::from_le_bytes([
                data.get(opt_off + 28).copied().unwrap_or(0),
                data.get(opt_off + 29).copied().unwrap_or(0),
                data.get(opt_off + 30).copied().unwrap_or(0),
                data.get(opt_off + 31).copied().unwrap_or(0),
            ]));
            let s = u64::from(u32::from_le_bytes([
                data.get(opt_off + 56).copied().unwrap_or(0),
                data.get(opt_off + 57).copied().unwrap_or(0),
                data.get(opt_off + 58).copied().unwrap_or(0),
                data.get(opt_off + 59).copied().unwrap_or(0),
            ]));
            (b, s)
        };
        (entry, base, size)
    } else {
        (0, 0, 0)
    };
    let is_dll = (characteristics & 0x2000) != 0;
    let is_exe = (characteristics & 0x0002) != 0;
    Ok(LuaValue::Table(vec![
        (LuaValue::String("format".into()), LuaValue::String("PE".into())),
        (LuaValue::String("arch".into()), LuaValue::String(arch.into())),
        (LuaValue::String("machine".into()), LuaValue::Int(i64::from(machine))),
        (LuaValue::String("num_sections".into()), LuaValue::Int(i64::from(num_sections))),
        (LuaValue::String("timestamp".into()), LuaValue::Int(i64::from(timestamp))),
        (LuaValue::String("entry_rva".into()), LuaValue::Int(crate::casts::u64_to_i64(entry_rva))),
        (LuaValue::String("image_base".into()), LuaValue::Int(crate::casts::u64_to_i64(image_base))),
        (LuaValue::String("image_size".into()), LuaValue::Int(crate::casts::u64_to_i64(image_size))),
        (LuaValue::String("is_dll".into()), LuaValue::Bool(is_dll)),
        (LuaValue::String("is_exe".into()), LuaValue::Bool(is_exe)),
        (LuaValue::String("file_size".into()), LuaValue::Int(crate::casts::usize_to_i64(data.len()))),
    ]))
}

// ── ELF info parser ───────────────────────────────────────────────────────────

/// `re.elf_info(path) → table`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn elf_info(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    use std::io::Read as _;
    let path = require_string_arg(args, 0, "elf_info")?;
    let mut f = std::fs::File::open(&path).map_err(|e| LuaError::RuntimeError(e.to_string()))?;
    let file_size = f.metadata().map_or(0, |m| m.len());
    if file_size > MAX_FILE_SIZE {
        return Err(LuaError::RuntimeError(format!(
            "elf_info: file too large ({file_size} bytes, limit {MAX_FILE_SIZE})"
        )));
    }
    // Read from the already-open handle to avoid a TOCTOU race.
    let mut data = Vec::new();
    f.read_to_end(&mut data).map_err(|e| LuaError::RuntimeError(e.to_string()))?;
    drop(f);
    if !data.starts_with(b"\x7fELF") {
        return Err(LuaError::RuntimeError(format!(
            "elf_info: {path} is not an ELF file"
        )));
    }
    if data.len() < 64 {
        return Err(LuaError::RuntimeError("elf_info: file too small".into()));
    }
    let ei_class = data[4]; // 1=32-bit, 2=64-bit
    let ei_data = data[5];  // 1=LE, 2=BE
    let e_type = u16::from_le_bytes([data[16], data[17]]);
    let e_machine = u16::from_le_bytes([data[18], data[19]]);
    let e_version = u32::from_le_bytes([data[20], data[21], data[22], data[23]]);
    let bits = if ei_class == 2 { 64u8 } else { 32u8 };
    let endian = if ei_data == 1 { "little" } else { "big" };
    let arch = match e_machine {
        0x0003 => "x86",
        0x003e => "x86_64",
        0x0028 => "arm",
        0x00b7 => "aarch64",
        0x00f3 => "riscv",
        0x00f4 => "riscv64",
        0x00b6 => "mips",
        _ => "unknown",
    };
    let file_type = match e_type {
        1 => "relocatable",
        2 => "executable",
        3 => "shared",
        4 => "core",
        _ => "unknown",
    };
    let e_entry = if bits == 64 && data.len() >= 32 {
        u64::from_le_bytes(data[24..32].try_into().unwrap_or([0; 8]))
    } else if data.len() >= 28 {
        u64::from(u32::from_le_bytes(data[24..28].try_into().unwrap_or([0; 4])))
    } else {
        0
    };
    let prog_hdr_count = u16::from_le_bytes([
        data.get(if bits == 64 { 56 } else { 44 }).copied().unwrap_or(0),
        data.get(if bits == 64 { 57 } else { 45 }).copied().unwrap_or(0),
    ]);
    let sect_hdr_count = u16::from_le_bytes([
        data.get(if bits == 64 { 60 } else { 48 }).copied().unwrap_or(0),
        data.get(if bits == 64 { 61 } else { 49 }).copied().unwrap_or(0),
    ]);
    Ok(LuaValue::Table(vec![
        (LuaValue::String("format".into()), LuaValue::String("ELF".into())),
        (LuaValue::String("arch".into()), LuaValue::String(arch.into())),
        (LuaValue::String("bits".into()), LuaValue::Int(i64::from(bits))),
        (LuaValue::String("endian".into()), LuaValue::String(endian.into())),
        (LuaValue::String("file_type".into()), LuaValue::String(file_type.into())),
        (LuaValue::String("machine".into()), LuaValue::Int(i64::from(e_machine))),
        (LuaValue::String("version".into()), LuaValue::Int(i64::from(e_version))),
        (LuaValue::String("entry_point".into()), LuaValue::Int(crate::casts::u64_to_i64(e_entry))),
        (LuaValue::String("num_program_headers".into()), LuaValue::Int(i64::from(prog_hdr_count))),
        (LuaValue::String("num_section_headers".into()), LuaValue::Int(i64::from(sect_hdr_count))),
        (LuaValue::String("file_size".into()), LuaValue::Int(crate::casts::usize_to_i64(data.len()))),
    ]))
}

// ── String extraction ─────────────────────────────────────────────────────────

/// `re.strings_from_file(path, min_len) → table`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn strings_from_file(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    use std::io::Read as _;
    let path = require_string_arg(args, 0, "strings_from_file")?;
    // Clamp min_len: a negative or absurdly large value from user input should
    // not cause unexpected behaviour (negative i64 would wrap to huge usize).
    let min_len = args.get(1).and_then(LuaValue::as_int)
        .map_or(4, |n| crate::casts::i64_to_usize(n.max(0)));
    let mut f = std::fs::File::open(&path).map_err(|e| LuaError::RuntimeError(e.to_string()))?;
    let file_size = f.metadata().map_or(0, |m| m.len());
    if file_size > MAX_FILE_SIZE {
        return Err(LuaError::RuntimeError(format!(
            "strings_from_file: file too large ({file_size} bytes, limit {MAX_FILE_SIZE})"
        )));
    }
    // Read from the already-open handle to avoid a TOCTOU race.
    let mut data = Vec::new();
    f.read_to_end(&mut data).map_err(|e| LuaError::RuntimeError(e.to_string()))?;
    drop(f);
    let mut results = Vec::new();
    let mut buf = String::new();
    let mut start = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if b.is_ascii() && !b.is_ascii_control() {
            if buf.is_empty() {
                start = i;
            }
            buf.push(b as char);
        } else if buf.len() >= min_len {
            let idx = results.len() + 1;
            let taken = std::mem::take(&mut buf);
            let len = taken.len();
            results.push((
                LuaValue::Int(crate::casts::usize_to_i64(idx)),
                LuaValue::Table(vec![
                    (LuaValue::String("offset".into()), LuaValue::Int(crate::casts::usize_to_i64(start))),
                    (LuaValue::String("value".into()), LuaValue::String(taken)),
                    (LuaValue::String("len".into()), LuaValue::Int(crate::casts::usize_to_i64(len))),
                    (LuaValue::String("encoding".into()), LuaValue::String("ascii".into())),
                ]),
            ));
        } else {
            buf.clear();
        }
    }
    if buf.len() >= min_len {
        let idx = results.len() + 1;
        let len = buf.len();
        results.push((
            LuaValue::Int(crate::casts::usize_to_i64(idx)),
            LuaValue::Table(vec![
                (LuaValue::String("offset".into()), LuaValue::Int(crate::casts::usize_to_i64(start))),
                (LuaValue::String("value".into()), LuaValue::String(buf)),
                (LuaValue::String("len".into()), LuaValue::Int(crate::casts::usize_to_i64(len))),
                (LuaValue::String("encoding".into()), LuaValue::String("ascii".into())),
            ]),
        ));
    }
    Ok(LuaValue::Table(results))
}

// ── Entropy ───────────────────────────────────────────────────────────────────

/// `re.entropy(data:string) → float`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn entropy(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let s = require_string_arg(args, 0, "entropy")?;
    let bytes: Vec<u8> = s.chars().map(|c| c as u8).collect();
    Ok(LuaValue::Float(shannon_entropy(&bytes)))
}

// ── XOR decrypt ───────────────────────────────────────────────────────────────

/// `re.xor_decrypt(data:string, key:int|string) → string`
///
/// If `key` is a string, it is used as a repeating multi-byte XOR key.
/// If `key` is an integer, it is used as a single-byte key.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn xor_decrypt(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let data = require_string_arg(args, 0, "xor_decrypt")?;
    let key_val = args
        .get(1)
        .ok_or_else(|| LuaError::RuntimeError("xor_decrypt: expected key argument".into()))?;
    let key_bytes: Vec<u8> = match key_val {
        LuaValue::Int(n) => vec![crate::casts::i64_to_u8(*n)],
        LuaValue::String(s) => s.bytes().collect(),
        _ => {
            return Err(LuaError::TypeError {
                expected: "number or string".into(),
                got: key_val.type_name().to_string(),
            })
        }
    };
    if key_bytes.is_empty() {
        return Ok(LuaValue::String(data));
    }
    let result: String = data
        .chars()
        .map(|c| c as u8)
        .enumerate()
        .map(|(i, b)| (b ^ key_bytes[i % key_bytes.len()]) as char)
        .collect();
    Ok(LuaValue::String(result))
}

// ── Base64 decode ─────────────────────────────────────────────────────────────

/// `re.base64_decode(s:string) → string`
///
/// Pure-Rust RFC 4648 base64 decoder (no padding variants).
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn base64_decode(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let s = require_string_arg(args, 0, "base64_decode")?;
    let decoded = b64_decode(s.as_bytes())
        .map_err(|e| LuaError::RuntimeError(format!("base64_decode: {e}")))?;
    // Return as a Lua string (Latin-1 encoding).
    let result: String = decoded.iter().map(|&b| b as char).collect();
    Ok(LuaValue::String(result))
}

fn b64_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut rev = [0xFF_u8; 256];
    for (i, &c) in TABLE.iter().enumerate() {
        rev[c as usize] = crate::casts::usize_to_u8(i);
    }
    // Strip '=' padding without allocating a separate Vec.
    let input: &[u8] = {
        let end = input.iter().rposition(|&b| b != b'=').map_or(0, |i| i + 1);
        &input[..end]
    };
    if input.len() % 4 == 1 {
        return Err("invalid base64 length".into());
    }
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for chunk in input.chunks(4) {
        // Decode each byte in-place using a fixed-size array — no per-chunk allocation.
        let mut v = [0u8; 4];
        for (slot, &b) in v.iter_mut().zip(chunk.iter()) {
            let decoded = if (b as usize) < rev.len() { rev[b as usize] } else { 0xFF };
            if decoded == 0xFF {
                return Err("invalid base64 character".into());
            }
            *slot = decoded;
        }
        let combined = (u32::from(v[0]) << 18)
            | (u32::from(v[1]) << 12)
            | (u32::from(v[2]) << 6)
            | u32::from(v[3]);
        out.push(((combined >> 16) & 0xff) as u8);
        if chunk.len() >= 3 {
            out.push(((combined >> 8) & 0xff) as u8);
        }
        if chunk.len() >= 4 {
            out.push((combined & 0xff) as u8);
        }
    }
    Ok(out)
}

// ── Hex to bytes ──────────────────────────────────────────────────────────────

/// `re.hex_to_bytes(s:string) → string`
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn hex_to_bytes(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let s = require_string_arg(args, 0, "hex_to_bytes")?;
    let joined: String = s.split_whitespace().collect();
    if !joined.len().is_multiple_of(2) {
        return Err(LuaError::RuntimeError(
            "hex_to_bytes: odd number of hex digits".into(),
        ));
    }
    let bytes: Result<Vec<u8>, _> = (0..joined.len() / 2)
        .map(|i| u8::from_str_radix(&joined[i * 2..i * 2 + 2], 16))
        .collect();
    let bytes = bytes.map_err(|e| LuaError::RuntimeError(format!("hex_to_bytes: {e}")))?;
    let result: String = bytes.iter().map(|&b| b as char).collect();
    Ok(LuaValue::String(result))
}

// ── Find signature ────────────────────────────────────────────────────────────

/// `re.find_signature(data:string, sig:string) → int|nil`
///
/// `sig` is a hex string with optional `??` wildcards, e.g. `"48 ?? c3"`.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn find_signature(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let data = require_string_arg(args, 0, "find_signature")?;
    let sig_str = require_string_arg(args, 1, "find_signature")?;
    let pattern: Vec<Option<u8>> = sig_str
        .split_whitespace()
        .map(|tok| {
            if tok == "??" || tok == "?" {
                Ok(None)
            } else {
                u8::from_str_radix(tok, 16)
                    .map(Some)
                    .map_err(|e| LuaError::RuntimeError(format!("find_signature: bad byte {e}")))
            }
        })
        .collect::<Result<_, _>>()?;
    let data_bytes: Vec<u8> = data.chars().map(|c| c as u8).collect();
    let data = data_bytes.as_slice();
    let plen = pattern.len();
    if plen == 0 || data.len() < plen {
        return Ok(LuaValue::Nil);
    }
    for i in 0..=(data.len() - plen) {
        if pattern
            .iter()
            .enumerate()
            .all(|(j, &p)| p.is_none_or(|b| b == data[i + j]))
        {
            return Ok(LuaValue::Int(crate::casts::usize_to_i64(i)));
        }
    }
    Ok(LuaValue::Nil)
}

// ── Hash calculation ──────────────────────────────────────────────────────────

/// `re.calculate_hash(data:string, algo:string) → string`
///
/// Supported algorithms: `"md5"`, `"sha1"`, `"sha256"`, `"crc32"`, `"fnv1a"`.
/// These are simple software implementations for RE use — not
/// cryptographically audited.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn calculate_hash(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let data = require_string_arg(args, 0, "calculate_hash")?;
    let algo = args
        .get(1)
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| "sha256".into());
    let bytes = data.as_bytes();
    let hex = match algo.to_lowercase().as_str() {
        "crc32" => format!("{:08x}", crc32(bytes)),
        "fnv1a" | "fnv" => format!("{:016x}", fnv1a_64(bytes)),
        "adler32" => format!("{:08x}", adler32(bytes)),
        "sha256" => sha256_hex(bytes),
        "sha1" => sha1_hex(bytes),
        "md5" => md5_hex(bytes),
        other => {
            return Err(LuaError::RuntimeError(format!(
                "calculate_hash: unknown algorithm '{other}'"
            )))
        }
    };
    Ok(LuaValue::String(hex))
}

// ── Disassemble bytes ─────────────────────────────────────────────────────────

/// `re.disasm_bytes(arch:string, data:string, base:int) → table`
///
/// Disassembles `data` (a Lua byte string) from `base` address.
/// `arch` must be `"x86"`, `"x86_64"`, or `"arm"` (stub decoders for all).
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
/// # Errors
///
/// Returns an error if the underlying operation fails.
pub fn disasm_bytes(args: &[LuaValue]) -> Result<LuaValue, LuaError> {
    let arch = require_string_arg(args, 0, "disasm_bytes")?;
    let data = require_string_arg(args, 1, "disasm_bytes")?;
    let base = crate::casts::i64_to_u64(args.get(2).and_then(LuaValue::as_int).unwrap_or(0));
    let bytes: Vec<u8> = data.chars().map(|c| c as u8).collect();
    let bytes = bytes.as_slice();
    let mut entries = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() && entries.len() < 256 {
        let (mnem, ops, sz) = disasm_one(&arch, bytes, off);
        let sz = sz.max(1).min(bytes.len() - off);
        let addr = base + off as u64;
        let idx = entries.len() + 1;
        entries.push((
            LuaValue::Int(crate::casts::usize_to_i64(idx)),
            LuaValue::Table(vec![
                (LuaValue::String("addr".into()), LuaValue::Int(crate::casts::u64_to_i64(addr))),
                (LuaValue::String("mnemonic".into()), LuaValue::String(mnem)),
                (LuaValue::String("operands".into()), LuaValue::String(ops)),
                (LuaValue::String("size".into()), LuaValue::Int(crate::casts::usize_to_i64(sz))),
            ]),
        ));
        off += sz;
    }
    Ok(LuaValue::Table(entries))
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

/// Dispatch a `re.*` call. Returns `Ok(None)` if not handled here.
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
        "re.pe_info" => Some(pe_info(args)?),
        "re.elf_info" => Some(elf_info(args)?),
        "re.strings_from_file" => Some(strings_from_file(args)?),
        "re.entropy" => Some(entropy(args)?),
        "re.xor_decrypt" => Some(xor_decrypt(args)?),
        "re.base64_decode" => Some(base64_decode(args)?),
        "re.hex_to_bytes" => Some(hex_to_bytes(args)?),
        "re.find_signature" => Some(find_signature(args)?),
        "re.calculate_hash" => Some(calculate_hash(args)?),
        "re.disasm_bytes" => Some(disasm_bytes(args)?),
        _ => None,
    };
    Ok(result)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn require_string_arg(args: &[LuaValue], idx: usize, fn_name: &str) -> Result<String, LuaError> {
    args.get(idx)
        .and_then(|v| v.as_str().map(str::to_string))
        .ok_or_else(|| {
            LuaError::RuntimeError(format!("{fn_name}: expected string argument at position {idx}"))
        })
}

fn disasm_one(arch: &str, data: &[u8], off: usize) -> (String, String, usize) {
    let b = data[off];
    match arch.to_lowercase().as_str() {
        "arm" | "arm64" | "aarch64" => {
            // ARM instructions are 4 bytes (Thumb would need more logic).
            if off + 4 <= data.len() {
                let insn = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
                let mnem = arm_opcode_mnem(insn);
                (mnem, format!("{insn:#010x}"), 4)
            } else {
                (".word".into(), format!("{b:#04x}"), 1)
            }
        }
        _ => {
            // x86 stub decoder.
            let (mnem, ops, sz) = x86_stub(b);
            (mnem.into(), ops.into(), sz)
        }
    }
}

fn arm_opcode_mnem(insn: u32) -> String {
    let group = (insn >> 25) & 0x7;
    match group {
        0b000 | 0b001 => "dp_imm".into(),
        0b010 => "br".into(),
        0b011 => "load_store".into(),
        0b100 | 0b101 => "dp_reg".into(),
        0b110 | 0b111 => "simd".into(),
        _ => "unknown".into(),
    }
}

const fn x86_stub(opcode: u8) -> (&'static str, &'static str, usize) {
    match opcode {
        0x90 => ("nop", "", 1),
        0x55 => ("push", "rbp", 1),
        0x5d => ("pop", "rbp", 1),
        0xc3 => ("ret", "", 1),
        0xe8 => ("call", "rel32", 5),
        0xe9 => ("jmp", "rel32", 5),
        0x89 => ("mov", "r/m,r", 2),
        0x8b => ("mov", "r,r/m", 2),
        0x83 => ("op", "r/m,imm8", 3),
        0x48 => ("rex.w", "prefix", 1),
        0x0f => ("esc", "two-byte", 2),
        0xcc => ("int3", "", 1),
        0x50..=0x57 => ("push", "reg", 1),
        0x58..=0x5f => ("pop", "reg", 1),
        0x74 => ("jz", "rel8", 2),
        0x75 => ("jnz", "rel8", 2),
        _ => ("db", "", 1),
    }
}

// ── Hash implementations ──────────────────────────────────────────────────────

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &b in data {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
    }
    hash
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// Minimal SHA-256 (FIPS 180-4).
fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5,
        0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
        0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
        0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
        0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc,
        0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
        0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7,
        0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
        0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
        0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
        0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3,
        0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
        0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5,
        0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
        0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
        0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
    ];
    let mut sha_state: [u32; 8] = [
        0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a,
        0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19,
    ];
    // Pre-processing.
    let bit_len = data.len() as u64 * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    // Process blocks.
    for chunk in msg.chunks(64) {
        let mut msg_sched = [0u32; 64];
        for (blk_i, blk_b) in chunk.chunks(4).enumerate().take(16) {
            msg_sched[blk_i] = u32::from_be_bytes([blk_b[0], blk_b[1], blk_b[2], blk_b[3]]);
        }
        for ri in 16..64 {
            let s0 = msg_sched[ri - 15].rotate_right(7) ^ msg_sched[ri - 15].rotate_right(18) ^ (msg_sched[ri - 15] >> 3);
            let s1 = msg_sched[ri - 2].rotate_right(17) ^ msg_sched[ri - 2].rotate_right(19) ^ (msg_sched[ri - 2] >> 10);
            msg_sched[ri] = msg_sched[ri - 16]
                .wrapping_add(s0)
                .wrapping_add(msg_sched[ri - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut ee, mut ff, mut gg, mut hh] = sha_state;
        for ri in 0..64 {
            let s1 = ee.rotate_right(6) ^ ee.rotate_right(11) ^ ee.rotate_right(25);
            let ch = (ee & ff) ^ ((!ee) & gg);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[ri])
                .wrapping_add(msg_sched[ri]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            hh = gg;
            gg = ff;
            ff = ee;
            ee = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        sha_state[0] = sha_state[0].wrapping_add(a);
        sha_state[1] = sha_state[1].wrapping_add(b);
        sha_state[2] = sha_state[2].wrapping_add(c);
        sha_state[3] = sha_state[3].wrapping_add(d);
        sha_state[4] = sha_state[4].wrapping_add(ee);
        sha_state[5] = sha_state[5].wrapping_add(ff);
        sha_state[6] = sha_state[6].wrapping_add(gg);
        sha_state[7] = sha_state[7].wrapping_add(hh);
    }
    let mut out = String::with_capacity(64);
    for v in &sha_state { use std::fmt::Write as _; let _ = write!(out, "{v:08x}"); }
    out
}

/// Minimal SHA-1.
fn sha1_hex(data: &[u8]) -> String {
    let mut sha1_state: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let bit_len = data.len() as u64 * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut msg_sched = [0u32; 80];
        for (blk_i, blk_b) in chunk.chunks(4).enumerate().take(16) {
            msg_sched[blk_i] = u32::from_be_bytes([blk_b[0], blk_b[1], blk_b[2], blk_b[3]]);
        }
        for ri in 16..80 {
            msg_sched[ri] = (msg_sched[ri - 3] ^ msg_sched[ri - 8] ^ msg_sched[ri - 14] ^ msg_sched[ri - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut ee] = [sha1_state[0], sha1_state[1], sha1_state[2], sha1_state[3], sha1_state[4]];
        for (ri, &sched_val) in msg_sched.iter().enumerate() {
            let (round_f, round_k) = match ri {
                0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999_u32),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(round_f)
                .wrapping_add(ee)
                .wrapping_add(round_k)
                .wrapping_add(sched_val);
            ee = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        sha1_state[0] = sha1_state[0].wrapping_add(a);
        sha1_state[1] = sha1_state[1].wrapping_add(b);
        sha1_state[2] = sha1_state[2].wrapping_add(c);
        sha1_state[3] = sha1_state[3].wrapping_add(d);
        sha1_state[4] = sha1_state[4].wrapping_add(ee);
    }
    let mut out = String::with_capacity(40);
    for v in &sha1_state { use std::fmt::Write as _; let _ = write!(out, "{v:08x}"); }
    out
}

/// Minimal MD5.
fn md5_hex(data: &[u8]) -> String {
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    const K: [u32; 64] = [
        0xd76a_a478, 0xe8c7_b756, 0x2420_70db, 0xc1bd_ceee, 0xf57c_0faf, 0x4787_c62a, 0xa830_4613,
        0xfd46_9501, 0x6980_98d8, 0x8b44_f7af, 0xffff_5bb1, 0x895c_d7be, 0x6b90_1122, 0xfd98_7193,
        0xa679_438e, 0x49b4_0821, 0xf61e_2562, 0xc040_b340, 0x265e_5a51, 0xe9b6_c7aa, 0xd62f_105d,
        0x0244_1453, 0xd8a1_e681, 0xe7d3_fbc8, 0x21e1_cde6, 0xc337_07d6, 0xf4d5_0d87, 0x455a_14ed,
        0xa9e3_e905, 0xfcef_a3f8, 0x676f_02d9, 0x8d2a_4c8a, 0xfffa_3942, 0x8771_f681, 0x6d9d_6122,
        0xfde5_380c, 0xa4be_ea44, 0x4bde_cfa9, 0xf6bb_4b60, 0xbebf_bc70, 0x289b_7ec6, 0xeaa1_27fa,
        0xd4ef_3085, 0x0488_1d05, 0xd9d4_d039, 0xe6db_99e5, 0x1fa2_7cf8, 0xc4ac_5665, 0xf429_2244,
        0x432a_ff97, 0xab94_23a7, 0xfc93_a039, 0x655b_59c3, 0x8f0c_cc92, 0xffef_f47d, 0x8584_5dd1,
        0x6fa8_7e4f, 0xfe2c_e6e0, 0xa301_4314, 0x4e08_11a1, 0xf753_7e82, 0xbd3a_f235, 0x2ad7_d2bb,
        0xeb86_d391,
    ];
    let msg_len = data.len();
    let bit_len = msg_len as u64 * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());
    let mut a0 = 0x6745_2301_u32;
    let mut b0 = 0xEFCD_AB89_u32;
    let mut c0 = 0x98BA_DCFE_u32;
    let mut d0 = 0x1032_5476_u32;
    for chunk in msg.chunks(64) {
        let mut block_w = [0u32; 16];
        for (blk_i, blk_b) in chunk.chunks(4).enumerate() {
            block_w[blk_i] = u32::from_le_bytes([blk_b[0], blk_b[1], blk_b[2], blk_b[3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for ri in 0..64usize {
            let (mix_f, idx_g) = match ri {
                0..=15 => ((b & c) | ((!b) & d), ri),
                16..=31 => ((d & b) | ((!d) & c), (5 * ri + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * ri + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * ri) % 16),
            };
            let mix_val = mix_f
                .wrapping_add(a)
                .wrapping_add(K[ri])
                .wrapping_add(block_w[idx_g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(mix_val.rotate_left(S[ri]));
        }
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }
    let bytes = [
        a0.to_le_bytes(), b0.to_le_bytes(), c0.to_le_bytes(), d0.to_le_bytes(),
    ];
    let mut out = String::with_capacity(32);
    for byte in bytes.iter().flatten() { use std::fmt::Write as _; let _ = write!(out, "{byte:02x}"); }
    out
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

    #[test]
    fn test_entropy_uniform() {
        let s: String = (0u8..=255u8).map(|b| b as char).collect();
        let result = entropy(&[str_arg(&s)]).unwrap();
        if let LuaValue::Float(e) = result {
            assert!(e > 7.9, "uniform entropy should be ~8, got {e}");
        }
    }

    #[test]
    fn test_entropy_constant() {
        let s = "aaaaaaa";
        let result = entropy(&[str_arg(s)]).unwrap();
        assert_eq!(result.as_int(), Some(0));
    }

    #[test]
    fn test_xor_decrypt_single_key() {
        let data = "\x41\x42\x43"; // ABC
        let result = xor_decrypt(&[str_arg(data), int_arg(0x01)]).unwrap();
        // A^1=@, B^1=C, C^1=B
        if let LuaValue::String(s) = result {
            assert_eq!(s.as_bytes(), &[0x40, 0x43, 0x42]);
        }
    }

    #[test]
    fn test_xor_decrypt_roundtrip() {
        let orig = "Hello, World!";
        let enc = xor_decrypt(&[str_arg(orig), int_arg(0xAA)]).unwrap();
        if let LuaValue::String(ref s) = enc {
            let dec = xor_decrypt(&[LuaValue::String(s.clone()), int_arg(0xAA)]).unwrap();
            if let LuaValue::String(d) = dec {
                assert_eq!(d, orig);
            }
        }
    }

    #[test]
    fn test_hex_to_bytes() {
        let result = hex_to_bytes(&[str_arg("48 65 6c 6c 6f")]).unwrap();
        if let LuaValue::String(s) = result {
            assert_eq!(s, "Hello");
        }
    }

    #[test]
    fn test_base64_decode_hello() {
        // "Hello" in base64 = "SGVsbG8="
        let result = base64_decode(&[str_arg("SGVsbG8")]).unwrap();
        if let LuaValue::String(s) = result {
            assert_eq!(s, "Hello");
        }
    }

    #[test]
    fn test_find_signature_found() {
        let data: String = b"\x48\x89\xc3\x90\x90".iter().map(|&b| b as char).collect();
        let result = find_signature(&[str_arg(&data), str_arg("48 ?? c3")]).unwrap();
        assert_eq!(result.as_int(), Some(0));
    }

    #[test]
    fn test_find_signature_not_found() {
        let data = "aabbcc";
        let result = find_signature(&[str_arg(data), str_arg("ff ff")]).unwrap();
        assert!(matches!(result, LuaValue::Nil));
    }

    #[test]
    fn test_calculate_hash_crc32_empty() {
        // CRC32 of empty = 0x0000_0000
        let result = calculate_hash(&[str_arg(""), str_arg("crc32")]).unwrap();
        if let LuaValue::String(s) = result {
            assert_eq!(s, "00000000");
        }
    }

    #[test]
    fn test_sha256_empty() {
        let result = calculate_hash(&[str_arg(""), str_arg("sha256")]).unwrap();
        if let LuaValue::String(s) = result {
            // SHA-256 of "" = e3b0c44298fc1c149afb...
            assert!(s.starts_with("e3b0c4"), "got {s}");
        }
    }

    #[test]
    fn test_disasm_bytes_x86() {
        let data: String = b"\x90\x55\xc3".iter().map(|&b| b as char).collect();
        let result = disasm_bytes(&[str_arg("x86_64"), str_arg(&data), int_arg(0x1000)]).unwrap();
        if let LuaValue::Table(t) = result {
            assert_eq!(t.len(), 3);
        }
    }

    #[test]
    fn test_dispatch_unknown_returns_none() {
        let result = dispatch("re.unknown", &[]).unwrap();
        assert!(result.is_none());
    }
}
