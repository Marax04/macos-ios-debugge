//! `rhai_stdlib_re` — custom RE standard library for Rhai scripts.
//!
//! Provides type converters, format helpers, hex/base64 utilities, and common
//! RE helper functions accessible from Rhai scripts.

use std::fmt::Write as FmtWrite;

use rhai::{Dynamic, Engine, Map as RhaiMap};

// ─────────────────────────────────────────────────────────────────────────────
// Hex utilities
// ─────────────────────────────────────────────────────────────────────────────

/// Encode bytes as lowercase hex.
#[must_use]
pub fn re_hex_encode(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data { let _ = write!(s, "{b:02x}"); }
    s
}

/// Encode bytes as uppercase hex.
#[must_use]
pub fn re_hex_encode_upper(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data { let _ = write!(s, "{b:02X}"); }
    s
}

/// Decode hex string (with or without "0x" prefix, spaces OK) to bytes.
#[must_use]
pub fn re_hex_decode(hex: &str) -> Vec<u8> {
    let clean: String = hex
        .replace("0x", "").replace("0X", "")
        .chars().filter(|c| !c.is_whitespace()).collect();
    let mut out = Vec::with_capacity(clean.len() / 2);
    let bytes = clean.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = u8::try_from((bytes[i] as char).to_digit(16).unwrap_or(0)).unwrap_or(0);
        let lo = u8::try_from((bytes[i+1] as char).to_digit(16).unwrap_or(0)).unwrap_or(0);
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

/// Encode as space-separated hex bytes.
#[must_use]
pub fn re_hex_bytes(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

/// Parse a hex integer string (e.g. "0xDEAD" or "DEAD") to u64.
#[must_use]
pub fn re_parse_hex(s: &str) -> u64 {
    let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u64::from_str_radix(s, 16).unwrap_or(0)
}

/// Format a u64 as hex with "0x" prefix.
#[must_use]
pub fn re_fmt_hex(n: u64) -> String {
    format!("0x{n:X}")
}

/// Format a u64 as hex with leading zeros to fill `width` hex digits.
#[must_use]
pub fn re_fmt_hex_pad(n: u64, width: usize) -> String {
    format!("0x{n:0>width$X}")
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64 utilities (self-contained, no external crate needed)
// ─────────────────────────────────────────────────────────────────────────────

const B64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode bytes as standard base64.
#[must_use]
pub fn re_base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i];
        let b1 = data.get(i + 1).copied().unwrap_or(0);
        let b2 = data.get(i + 2).copied().unwrap_or(0);
        let n = u32::from(b0) << 16 | u32::from(b1) << 8 | u32::from(b2);
        out.push(B64_CHARS[((n >> 18) & 63) as usize] as char);
        out.push(B64_CHARS[((n >> 12) & 63) as usize] as char);
        if i + 1 < data.len() {
            out.push(B64_CHARS[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < data.len() {
            out.push(B64_CHARS[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

const fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode standard base64 to bytes.  Returns empty on error.
#[must_use]
pub fn re_base64_decode(s: &str) -> Vec<u8> {
    let clean: Vec<u8> = s.bytes().filter(|&b| b != b'\n' && b != b'\r' && b != b' ').collect();
    let mut out = Vec::with_capacity(clean.len() / 4 * 3);
    let mut i = 0;
    while i + 3 < clean.len() {
        let v0 = match b64_val(clean[i]) { Some(v) => u32::from(v), None => break };
        let v1 = match b64_val(clean[i+1]) { Some(v) => u32::from(v), None => break };
        let v2 = if clean[i+2] == b'=' { 0u32 } else { u32::from(b64_val(clean[i+2]).unwrap_or(0)) };
        let v3 = if clean[i+3] == b'=' { 0u32 } else { u32::from(b64_val(clean[i+3]).unwrap_or(0)) };
        let n = v0 << 18 | v1 << 12 | v2 << 6 | v3;
        out.push(((n >> 16) & 0xFF) as u8);
        if clean[i+2] != b'=' { out.push(((n >> 8) & 0xFF) as u8); }
        if clean[i+3] != b'=' { out.push((n & 0xFF) as u8); }
        i += 4;
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Integer / address helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Convert a little-endian byte slice to u64.
#[must_use]
pub fn re_le_to_u64(data: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = data.len().min(8);
    buf[..len].copy_from_slice(&data[..len]);
    u64::from_le_bytes(buf)
}

/// Convert a big-endian byte slice to u64.
#[must_use]
pub fn re_be_to_u64(data: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = data.len().min(8);
    buf[8 - len..].copy_from_slice(&data[..len]);
    u64::from_be_bytes(buf)
}

/// Pack a u64 as little-endian bytes.
#[must_use]
pub fn re_u64_to_le(n: u64, width: usize) -> Vec<u8> {
    let bytes = n.to_le_bytes();
    bytes[..width.min(8)].to_vec()
}

/// Pack a u64 as big-endian bytes.
#[must_use]
pub fn re_u64_to_be(n: u64, width: usize) -> Vec<u8> {
    let bytes = n.to_be_bytes();
    let start = 8_usize.saturating_sub(width.min(8));
    bytes[start..].to_vec()
}

/// Align `addr` up to the next multiple of `align` (must be power of two).
#[must_use]
pub const fn re_align_up(addr: u64, align: u64) -> u64 {
    if align == 0 { return addr; }
    (addr + align - 1) & !(align - 1)
}

/// Align `addr` down to the previous multiple of `align`.
#[must_use]
pub const fn re_align_down(addr: u64, align: u64) -> u64 {
    if align == 0 { return addr; }
    addr & !(align - 1)
}

/// Check whether `addr` is aligned to `align`.
#[must_use]
pub const fn re_is_aligned(addr: u64, align: u64) -> bool {
    if align == 0 { return true; }
    addr & (align - 1) == 0
}

// ─────────────────────────────────────────────────────────────────────────────
// Binary data analysis helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Count occurrences of each byte value in `data`.
#[must_use]
pub fn re_byte_histogram(data: &[u8]) -> [u64; 256] {
    let mut hist = [0u64; 256];
    for &b in data { hist[b as usize] += 1; }
    hist
}

/// Return the most frequent byte value in `data`.
#[must_use]
pub fn re_most_common_byte(data: &[u8]) -> u8 {
    let hist = re_byte_histogram(data);
    hist.iter().enumerate().max_by_key(|&(_, &c)| c).map_or(0, |(i, _)| u8::try_from(i).unwrap_or(0))
}

/// Return the count of null bytes in `data`.
#[must_use]
pub fn re_null_count(data: &[u8]) -> usize {
    data.iter().fold(0usize, |acc, &b| acc + usize::from(b == 0))
}

/// Check if `data` looks like it contains valid x86 instructions (heuristic).
#[must_use]
pub fn re_looks_like_code(data: &[u8]) -> bool {
    if data.is_empty() { return false; }
    let code_bytes: usize = data.iter().filter(|&&b| matches!(b,
        0x00..=0x0F | 0x20..=0x3F | 0x48..=0x5F | 0x68 |
        0x74 | 0x75 | 0x83 | 0x89 | 0x8B | 0x90 | 0xC3 | 0xE8 | 0xEB | 0xFF
    )).count();
    code_bytes * 3 > data.len()
}

/// Detect repeated byte sequences (packing/encryption artifact).
#[must_use]
pub fn re_detect_repetition(data: &[u8], window: usize) -> f64 {
    if data.len() < window * 2 { return 0.0; }
    let mut matches = 0usize;
    let chunks = data.len() / window;
    for i in 1..chunks {
        if data[(i-1)*window..i*window] == data[i*window..(i+1)*window] {
            matches += 1;
        }
    }
    f64::from(u32::try_from(matches).unwrap_or(u32::MAX)) / f64::from(u32::try_from(chunks).unwrap_or(u32::MAX))
}

/// Compare two byte slices and return an edit distance (Hamming where len equal, else -1).
#[must_use]
pub fn re_compare_bytes(a: &[u8], b: &[u8]) -> i64 {
    if a.len() != b.len() { return -1; }
    i64::try_from(a.iter().zip(b.iter()).filter(|(x, y)| x != y).count()).unwrap_or(i64::MAX)
}

// ─────────────────────────────────────────────────────────────────────────────
// Pattern / signature helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build a simple byte-string signature from a byte slice (first 16 bytes as hex).
#[must_use]
pub fn re_make_signature(data: &[u8]) -> String {
    let len = data.len().min(16);
    data[..len].iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

/// Check whether `data` starts with the given hex pattern (spaces ignored, `??` = wildcard).
#[must_use]
pub fn re_match_pattern(data: &[u8], pattern: &str) -> bool {
    let tokens: Vec<&str> = pattern.split_whitespace().collect();
    if tokens.len() > data.len() { return false; }
    tokens.iter().enumerate().all(|(i, tok)| {
        *tok == "??" || *tok == "?" ||
        u8::from_str_radix(tok, 16).is_ok_and(|b| data[i] == b)
    })
}

/// Scan `data` for all matches of the hex-with-wildcard pattern.
#[must_use]
pub fn re_scan_pattern(data: &[u8], pattern: &str) -> Vec<usize> {
    let tokens: Vec<Option<u8>> = pattern.split_whitespace().map(|t| {
        if t == "??" || t == "?" { None } else { u8::from_str_radix(t, 16).ok() }
    }).collect();
    if tokens.is_empty() || tokens.len() > data.len() { return Vec::new(); }
    let mut hits = Vec::new();
    let mut i = 0;
    while i + tokens.len() <= data.len() {
        if tokens.iter().enumerate().all(|(j, mb)| mb.is_none_or(|b| data[i+j] == b)) {
            hits.push(i);
            i += tokens.len();
        } else {
            i += 1;
        }
    }
    hits
}

// ─────────────────────────────────────────────────────────────────────────────
// Format helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Format an address as `0x0000000000401000` (16-digit zero-padded).
#[must_use]
pub fn re_fmt_addr(addr: u64) -> String {
    format!("0x{addr:016X}")
}

/// Format an address as `0x00401000` (8-digit, for 32-bit).
#[must_use]
pub fn re_fmt_addr32(addr: u32) -> String {
    format!("0x{addr:08X}")
}

/// Format bytes with an optional separator.
#[must_use]
pub fn re_fmt_bytes(data: &[u8], sep: &str) -> String {
    data.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(sep)
}

/// Truncate a string to `max` **characters** with "..." suffix.
#[must_use]
pub fn re_truncate(s: &str, max: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max {
        s.to_string()
    } else {
        // Take `max - 3` chars (or 0 if max < 3) and append "...".
        let keep = max.saturating_sub(3);
        let truncated: String = s.chars().take(keep).collect();
        format!("{truncated}...")
    }
}

/// Pad a string on the right to `width` characters with spaces.
#[must_use]
pub fn re_pad_right(s: &str, width: usize) -> String {
    format!("{s:<width$}")
}

/// Pad a string on the left to `width` characters with spaces.
#[must_use]
pub fn re_pad_left(s: &str, width: usize) -> String {
    format!("{s:>width$}")
}

/// Build a simple ASCII table from rows.
#[must_use]
pub fn re_ascii_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let num_cols = headers.len();
    let mut col_widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in rows {
        for (j, cell) in row.iter().enumerate() {
            if j < num_cols {
                col_widths[j] = col_widths[j].max(cell.len());
            }
        }
    }
    let mut out = String::new();
    // Header
    for (j, h) in headers.iter().enumerate() {
        let _ = write!(out, " {:<width$} |", h, width = col_widths[j]);
    }
    out.push('\n');
    // Separator
    for &w in &col_widths {
        let _ = write!(out, "-{:-<width$}-+", "", width = w);
    }
    out.push('\n');
    // Rows
    for row in rows {
        for (j, &w) in col_widths.iter().enumerate() {
            let cell = row.get(j).map_or("", String::as_str);
            let _ = write!(out, " {cell:<w$} |");
        }
        out.push('\n');
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Type-conversion helpers exposed to Rhai
// ─────────────────────────────────────────────────────────────────────────────

/// Convert an `i64` to a 4-byte little-endian blob.
#[must_use]
pub fn re_i64_to_le32(n: i64) -> Vec<u8> {
    u32::try_from(n & 0xFFFF_FFFF).unwrap_or(0).to_le_bytes().to_vec()
}

/// Convert an `i64` to an 8-byte little-endian blob.
#[must_use]
pub fn re_i64_to_le64(n: i64) -> Vec<u8> {
    n.to_le_bytes().to_vec()
}

/// Read a little-endian i32 from a blob at `offset`.
#[must_use]
pub fn re_read_le32(data: &[u8], offset: usize) -> i64 {
    if offset + 4 > data.len() { return 0; }
    i64::from(i32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0;4])))
}

/// Read a little-endian u64 from a blob at `offset`.
#[must_use]
pub fn re_read_le64(data: &[u8], offset: usize) -> i64 {
    if offset + 8 > data.len() { return 0; }
    i64::from_le_bytes(data[offset..offset + 8].try_into().unwrap_or([0;8]))
}

/// Read a little-endian u16 from a blob at `offset`.
#[must_use]
pub fn re_read_le16(data: &[u8], offset: usize) -> i64 {
    if offset + 2 > data.len() { return 0; }
    i64::from(u16::from_le_bytes([data[offset], data[offset+1]]))
}

/// Read a single byte from a blob at `offset`.
#[must_use]
pub fn re_read_byte(data: &[u8], offset: usize) -> i64 {
    i64::from(data.get(offset).copied().unwrap_or(0))
}

/// Write a byte to a blob at `offset`.
pub fn re_write_byte(data: &mut Vec<u8>, offset: usize, val: u8) {
    if offset < data.len() {
        data[offset] = val;
    } else if offset == data.len() {
        data.push(val);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JSON helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Serialize a simple Rhai map to JSON (strings, integers, booleans).
#[must_use]
pub fn re_map_to_json(map: &RhaiMap) -> String {
    let mut parts = Vec::new();
    let mut keys: Vec<&str> = map.keys().map(AsRef::as_ref).collect();
    keys.sort_unstable();
    for key in keys {
        if let Some(val) = map.get(key) {
            let json_val = if val.is::<bool>() {
                format!("{}", val.clone().cast::<bool>())
            } else if val.is::<i64>() {
                format!("{}", val.clone().cast::<i64>())
            } else if val.is::<f64>() {
                format!("{}", val.clone().cast::<f64>())
            } else if val.is::<rhai::ImmutableString>() {
                let s = val.clone().cast::<rhai::ImmutableString>();
                format!("\"{}\"", s.replace('"', "\\\""))
            } else {
                format!("\"{val}\"")
            };
            parts.push(format!("\"{key}\":{json_val}"));
        }
    }
    format!("{{{}}}", parts.join(","))
}

// ─────────────────────────────────────────────────────────────────────────────
// RhaiStdlibRe — registers everything into an Engine
// ─────────────────────────────────────────────────────────────────────────────

/// Registers the RE standard library into `engine`.
pub struct RhaiStdlibRe;

impl RhaiStdlibRe {
    /// Register all stdlib functions.
    pub fn register(engine: &mut Engine) {
        Self::register_core(engine);
        Self::register_blob_ops(engine);
    }

    fn register_core(engine: &mut Engine) {
        // Hex
        engine.register_fn("re_hex_encode", |d: rhai::Blob| -> String { re_hex_encode(&d) });
        engine.register_fn("re_hex_encode_upper", |d: rhai::Blob| -> String { re_hex_encode_upper(&d) });
        engine.register_fn("re_hex_decode", |s: &str| -> rhai::Blob { re_hex_decode(s) });
        engine.register_fn("re_hex_bytes", |d: rhai::Blob| -> String { re_hex_bytes(&d) });
        engine.register_fn("re_parse_hex", |s: &str| -> i64 { re_parse_hex(s).cast_signed() });
        engine.register_fn("re_fmt_hex", |n: i64| -> String { re_fmt_hex(n.cast_unsigned()) });
        engine.register_fn("re_fmt_hex_pad", |n: i64, w: i64| -> String {
            re_fmt_hex_pad(n.cast_unsigned(), usize::try_from(w).unwrap_or(0))
        });
        // Base64
        engine.register_fn("re_base64_encode", |d: rhai::Blob| -> String { re_base64_encode(&d) });
        engine.register_fn("re_base64_decode", |s: &str| -> rhai::Blob { re_base64_decode(s) });
        // Integer/address
        engine.register_fn("re_le_u64", |d: rhai::Blob| -> i64 { re_le_to_u64(&d).cast_signed() });
        engine.register_fn("re_be_u64", |d: rhai::Blob| -> i64 { re_be_to_u64(&d).cast_signed() });
        engine.register_fn("re_u64_le", |n: i64, w: i64| -> rhai::Blob {
            re_u64_to_le(n.cast_unsigned(), usize::try_from(w).unwrap_or(0))
        });
        engine.register_fn("re_u64_be", |n: i64, w: i64| -> rhai::Blob {
            re_u64_to_be(n.cast_unsigned(), usize::try_from(w).unwrap_or(0))
        });
        engine.register_fn("re_align_up", |a: i64, align: i64| -> i64 {
            re_align_up(a.cast_unsigned(), align.cast_unsigned()).cast_signed()
        });
        engine.register_fn("re_align_down", |a: i64, align: i64| -> i64 {
            re_align_down(a.cast_unsigned(), align.cast_unsigned()).cast_signed()
        });
        engine.register_fn("re_is_aligned", |a: i64, align: i64| -> bool {
            re_is_aligned(a.cast_unsigned(), align.cast_unsigned())
        });
        // Binary analysis
        engine.register_fn("re_most_common_byte", |d: rhai::Blob| -> i64 { i64::from(re_most_common_byte(&d)) });
        engine.register_fn("re_null_count", |d: rhai::Blob| -> i64 { i64::try_from(re_null_count(&d)).unwrap_or(i64::MAX) });
        engine.register_fn("re_looks_like_code", |d: rhai::Blob| -> bool { re_looks_like_code(&d) });
        engine.register_fn("re_detect_repetition", |d: rhai::Blob, w: i64| -> f64 {
            re_detect_repetition(&d, usize::try_from(w).unwrap_or(0))
        });
        engine.register_fn("re_compare_bytes", |a: rhai::Blob, b: rhai::Blob| -> i64 { re_compare_bytes(&a, &b) });
        // Pattern helpers
        engine.register_fn("re_make_signature", |d: rhai::Blob| -> String { re_make_signature(&d) });
        engine.register_fn("re_match_pattern", |d: rhai::Blob, p: &str| -> bool { re_match_pattern(&d, p) });
        engine.register_fn("re_scan_pattern", |d: rhai::Blob, p: &str| -> rhai::Array {
            re_scan_pattern(&d, p).into_iter().map(|i| Dynamic::from(i64::try_from(i).unwrap_or(i64::MAX))).collect()
        });
        // Format helpers
        engine.register_fn("re_fmt_addr", |n: i64| -> String { re_fmt_addr(n.cast_unsigned()) });
        engine.register_fn("re_fmt_addr32", |n: i64| -> String { re_fmt_addr32(u32::try_from(n).unwrap_or(u32::MAX)) });
        engine.register_fn("re_fmt_bytes", |d: rhai::Blob, sep: &str| -> String { re_fmt_bytes(&d, sep) });
        engine.register_fn("re_truncate", |s: &str, max: i64| -> String { re_truncate(s, usize::try_from(max).unwrap_or(0)) });
        engine.register_fn("re_pad_right", |s: &str, w: i64| -> String { re_pad_right(s, usize::try_from(w).unwrap_or(0)) });
        engine.register_fn("re_pad_left", |s: &str, w: i64| -> String { re_pad_left(s, usize::try_from(w).unwrap_or(0)) });
        // Type converters
        engine.register_fn("re_i64_le32", |n: i64| -> rhai::Blob { re_i64_to_le32(n) });
        engine.register_fn("re_i64_le64", |n: i64| -> rhai::Blob { re_i64_to_le64(n) });
        engine.register_fn("re_read_le32", |d: rhai::Blob, off: i64| -> i64 {
            re_read_le32(&d, usize::try_from(off).unwrap_or(usize::MAX))
        });
        engine.register_fn("re_read_le64", |d: rhai::Blob, off: i64| -> i64 {
            re_read_le64(&d, usize::try_from(off).unwrap_or(usize::MAX))
        });
        engine.register_fn("re_read_le16", |d: rhai::Blob, off: i64| -> i64 {
            re_read_le16(&d, usize::try_from(off).unwrap_or(usize::MAX))
        });
        engine.register_fn("re_read_byte", |d: rhai::Blob, off: i64| -> i64 {
            re_read_byte(&d, usize::try_from(off).unwrap_or(usize::MAX))
        });
        // JSON + constants
        engine.register_fn("re_map_to_json", |m: RhaiMap| -> String { re_map_to_json(&m) });
        engine.register_fn("re_const_pe_sig", || -> rhai::Blob { b"MZ".to_vec() });
        engine.register_fn("re_const_elf_sig", || -> rhai::Blob { b"\x7fELF".to_vec() });
        engine.register_fn("re_const_page_size", || -> i64 { 0x1000 });
    }

    fn register_blob_ops(engine: &mut Engine) {
        engine.register_fn("re_slice", |d: rhai::Blob, start: i64, len: i64| -> rhai::Blob {
            let s = usize::try_from(start).unwrap_or(0).min(d.len());
            let take = usize::try_from(len).unwrap_or(0);
            let e = s.saturating_add(take).min(d.len());
            d[s..e].to_vec()
        });
        engine.register_fn("re_concat", |mut a: rhai::Blob, b: rhai::Blob| -> rhai::Blob {
            a.extend_from_slice(&b);
            a
        });
        engine.register_fn("re_repeat", |val: i64, count: i64| -> rhai::Blob {
            let n = usize::try_from(count).unwrap_or(0);
            vec![u8::try_from(val & 0xFF).unwrap_or(0); n]
        });
        engine.register_fn("re_xor", |data: rhai::Blob, key: i64| -> rhai::Blob {
            let k = u8::try_from(key & 0xFF).unwrap_or(0);
            data.iter().map(|&b| b ^ k).collect()
        });
        engine.register_fn("re_add_bytes", |data: rhai::Blob, key: i64| -> rhai::Blob {
            let k = u8::try_from(key & 0xFF).unwrap_or(0);
            data.iter().map(|&b| b.wrapping_add(k)).collect()
        });
        engine.register_fn("re_sub_bytes", |data: rhai::Blob, key: i64| -> rhai::Blob {
            let k = u8::try_from(key & 0xFF).unwrap_or(0);
            data.iter().map(|&b| b.wrapping_sub(k)).collect()
        });
        engine.register_fn("re_not_bytes", |data: rhai::Blob| -> rhai::Blob {
            data.iter().map(|&b| !b).collect()
        });
        engine.register_fn("re_rol_bytes", |data: rhai::Blob, n: i64| -> rhai::Blob {
            let shift = u32::from(u8::try_from(n & 7).unwrap_or(0));
            data.iter().map(|&b| b.rotate_left(shift)).collect()
        });
        engine.register_fn("re_ror_bytes", |data: rhai::Blob, n: i64| -> rhai::Blob {
            let shift = u32::from(u8::try_from(n & 7).unwrap_or(0));
            data.iter().map(|&b| b.rotate_right(shift)).collect()
        });
        engine.register_fn("re_is_zero", |data: rhai::Blob| -> bool { data.iter().all(|&b| b == 0) });
        engine.register_fn("re_reverse", |mut data: rhai::Blob| -> rhai::Blob { data.reverse(); data });
        engine.register_fn("re_byte_freq", |data: rhai::Blob, byte: i64| -> i64 {
            let target = u8::try_from(byte & 0xFF).unwrap_or(0);
            i64::try_from(data.iter().fold(0usize, |acc, &b| acc + usize::from(b == target))).unwrap_or(i64::MAX)
        });
        engine.register_fn("re_str_to_bytes", |s: &str| -> rhai::Blob { s.as_bytes().to_vec() });
        engine.register_fn("re_bytes_to_str", |d: rhai::Blob| -> String { String::from_utf8_lossy(&d).into_owned() });
        engine.register_fn("re_chunks", |data: rhai::Blob, size: i64| -> rhai::Array {
            let sz = usize::try_from(size).unwrap_or(0).max(1);
            data.chunks(sz).map(|c| Dynamic::from_blob(c.to_vec())).collect()
        });
        engine.register_fn("re_join_blobs", |arr: rhai::Array| -> rhai::Blob {
            arr.into_iter().filter_map(rhai::Dynamic::try_cast::<rhai::Blob>).flatten().collect()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_encode_decode() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let encoded = re_hex_encode(&data);
        assert_eq!(encoded, "deadbeef");
        let decoded = re_hex_decode(&encoded);
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_hex_encode_upper() {
        assert_eq!(re_hex_encode_upper(&[0xAB, 0xCD]), "ABCD");
    }

    #[test]
    fn test_parse_hex() {
        assert_eq!(re_parse_hex("0xDEAD"), 0xDEAD);
        assert_eq!(re_parse_hex("BEEF"), 0xBEEF);
        assert_eq!(re_parse_hex("  0XFF  "), 0xFF);
    }

    #[test]
    fn test_fmt_hex() {
        assert_eq!(re_fmt_hex(0xDEAD), "0xDEAD");
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, RustRE! This is a test.";
        let encoded = re_base64_encode(data);
        let decoded = re_base64_decode(&encoded);
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_known() {
        // "Man" → "TWFu"
        let encoded = re_base64_encode(b"Man");
        assert_eq!(encoded, "TWFu");
    }

    #[test]
    fn test_le_u64() {
        let data = 0xDEADBEEFu64.to_le_bytes().to_vec();
        assert_eq!(re_le_to_u64(&data), 0xDEADBEEF);
    }

    #[test]
    fn test_be_u64() {
        let data = 0xDEADBEEFu64.to_be_bytes().to_vec();
        assert_eq!(re_be_to_u64(&data), 0xDEADBEEF);
    }

    #[test]
    fn test_align_up() {
        assert_eq!(re_align_up(0x1001, 0x1000), 0x2000);
        assert_eq!(re_align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(re_align_up(0, 4), 0);
    }

    #[test]
    fn test_align_down() {
        assert_eq!(re_align_down(0x1FFF, 0x1000), 0x1000);
    }

    #[test]
    fn test_match_pattern() {
        let data = &[0x90, 0x90, 0xE8, 0x00, 0x00];
        assert!(re_match_pattern(data, "90 90 ??"));
        assert!(re_match_pattern(data, "90 90 E8"));
        assert!(!re_match_pattern(data, "90 91"));
    }

    #[test]
    fn test_scan_pattern() {
        let data: Vec<u8> = vec![0x90, 0xEB, 0x90, 0x90, 0xEB];
        let hits = re_scan_pattern(&data, "90 ??");
        assert_eq!(hits.len(), 2); // at index 0 and 2
    }

    #[test]
    fn test_read_le32() {
        let data: Vec<u8> = 0x12345678u32.to_le_bytes().to_vec();
        assert_eq!(re_read_le32(&data, 0), 0x12345678);
    }

    #[test]
    fn test_re_fmt_addr() {
        assert_eq!(re_fmt_addr(0x401000), "0x0000000000401000");
    }

    #[test]
    fn test_truncate() {
        assert_eq!(re_truncate("hello world", 8), "hello...");
        assert_eq!(re_truncate("hi", 10), "hi");
    }

    #[test]
    fn test_most_common_byte() {
        let data = vec![0x90u8; 100];
        assert_eq!(re_most_common_byte(&data), 0x90);
    }

    #[test]
    fn test_re_make_signature() {
        let data = vec![0xABu8, 0xCD, 0xEF];
        let sig = re_make_signature(&data);
        assert!(sig.contains("AB"));
        assert!(sig.contains("CD"));
    }
}
