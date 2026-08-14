//! `rhai_api_bindings` — Rhai bindings for `RustRE` analysis APIs.
//!
//! Registers functions for disassembly, symbol lookup, hex dump, string search,
//! and section enumeration into a Rhai engine.  All functions operate on binary
//! blobs, file paths, or pre-loaded binary identifiers.

use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::sync::Mutex;

use rhai::{Dynamic, Engine, Map as RhaiMap};

// ─────────────────────────────────────────────────────────────────────────────
// Supporting data types
// ─────────────────────────────────────────────────────────────────────────────

/// A single disassembled instruction returned to Rhai scripts.
#[derive(Debug, Clone)]
pub struct DisasmInstruction {
    pub address: u64,
    pub mnemonic: String,
    pub operands: String,
    pub bytes: Vec<u8>,
    pub size: usize,
}

impl DisasmInstruction {
    /// Format as a Rhai map.
    #[must_use]
    pub fn to_rhai_map(&self) -> RhaiMap {
        let mut m = RhaiMap::new();
        m.insert("address".into(), Dynamic::from(self.address.cast_signed()));
        m.insert("mnemonic".into(), Dynamic::from(self.mnemonic.clone()));
        m.insert("operands".into(), Dynamic::from(self.operands.clone()));
        m.insert("size".into(), Dynamic::from(crate::sat_usize_to_i64(self.size)));
        let hex: String = self.bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
        m.insert("hex".into(), Dynamic::from(hex));
        m
    }
}

/// A symbol record.
#[derive(Debug, Clone)]
pub struct Symbol {
    pub address: u64,
    pub name: String,
    pub kind: String,
    pub size: u64,
    pub is_imported: bool,
    pub is_exported: bool,
}

impl Symbol {
    #[must_use]
    pub fn to_rhai_map(&self) -> RhaiMap {
        let mut m = RhaiMap::new();
        m.insert("address".into(), Dynamic::from(self.address.cast_signed()));
        m.insert("name".into(), Dynamic::from(self.name.clone()));
        m.insert("kind".into(), Dynamic::from(self.kind.clone()));
        m.insert("size".into(), Dynamic::from(self.size.cast_signed()));
        m.insert("imported".into(), Dynamic::from(self.is_imported));
        m.insert("exported".into(), Dynamic::from(self.is_exported));
        m
    }
}

/// Permission flags for a binary section, packed into a single byte.
#[derive(Debug, Clone, Copy, Default)]
pub struct SectionPermissions(u8);

impl SectionPermissions {
    const BIT_CODE: u8 = 0x01;
    const BIT_DATA: u8 = 0x02;
    const BIT_WRITABLE: u8 = 0x04;
    const BIT_EXECUTABLE: u8 = 0x08;

    /// Construct from a raw packed byte (`BIT_CODE | BIT_DATA | BIT_WRITABLE | BIT_EXECUTABLE`).
    #[must_use]
    pub const fn from_raw(bits: u8) -> Self { Self(bits) }

    /// Whether this section contains code.
    #[must_use]
    pub const fn is_code(self) -> bool { self.0 & Self::BIT_CODE != 0 }
    /// Whether this section contains initialised data.
    #[must_use]
    pub const fn is_data(self) -> bool { self.0 & Self::BIT_DATA != 0 }
    /// Whether this section is writable at runtime.
    #[must_use]
    pub const fn is_writable(self) -> bool { self.0 & Self::BIT_WRITABLE != 0 }
    /// Whether this section is executable.
    #[must_use]
    pub const fn is_executable(self) -> bool { self.0 & Self::BIT_EXECUTABLE != 0 }
}

/// A section/segment descriptor.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_offset: u64,
    pub raw_size: u64,
    pub flags: u32,
    pub permissions: SectionPermissions,
    pub entropy: f64,
}

impl SectionInfo {
    /// Whether this section contains code.
    #[must_use]
    pub const fn is_code(&self) -> bool { self.permissions.is_code() }
    /// Whether this section contains data.
    #[must_use]
    pub const fn is_data(&self) -> bool { self.permissions.is_data() }
    /// Whether this section is writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool { self.permissions.is_writable() }
    /// Whether this section is executable.
    #[must_use]
    pub const fn is_executable(&self) -> bool { self.permissions.is_executable() }

    #[must_use]
    pub fn to_rhai_map(&self) -> RhaiMap {
        let mut m = RhaiMap::new();
        m.insert("name".into(), Dynamic::from(self.name.clone()));
        m.insert("virtual_address".into(), Dynamic::from(self.virtual_address.cast_signed()));
        m.insert("virtual_size".into(), Dynamic::from(self.virtual_size.cast_signed()));
        m.insert("raw_offset".into(), Dynamic::from(self.raw_offset.cast_signed()));
        m.insert("raw_size".into(), Dynamic::from(self.raw_size.cast_signed()));
        m.insert("flags".into(), Dynamic::from(i64::from(self.flags)));
        m.insert("is_code".into(), Dynamic::from(self.permissions.is_code()));
        m.insert("is_data".into(), Dynamic::from(self.permissions.is_data()));
        m.insert("is_writable".into(), Dynamic::from(self.permissions.is_writable()));
        m.insert("is_executable".into(), Dynamic::from(self.permissions.is_executable()));
        m.insert("entropy".into(), Dynamic::from(self.entropy));
        m
    }
}

/// A found string with offset.
#[derive(Debug, Clone)]
pub struct FoundString {
    pub offset: usize,
    pub value: String,
    pub encoding: String,
}

impl FoundString {
    #[must_use]
    pub fn to_rhai_map(&self) -> RhaiMap {
        let mut m = RhaiMap::new();
        m.insert("offset".into(), Dynamic::from(crate::sat_usize_to_i64(self.offset)));
        m.insert("value".into(), Dynamic::from(self.value.clone()));
        m.insert("encoding".into(), Dynamic::from(self.encoding.clone()));
        m
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared binary store
// ─────────────────────────────────────────────────────────────────────────────

/// Global in-memory binary store used by the API bindings.
fn binary_store() -> &'static Mutex<HashMap<String, Vec<u8>>> {
    static STORE: std::sync::OnceLock<Mutex<HashMap<String, Vec<u8>>>> = std::sync::OnceLock::new();
    STORE.get_or_init(|| Mutex::new(HashMap::new()))
}


fn store_put(id: String, data: Vec<u8>) {
    binary_store()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(id, data);
}

// ─────────────────────────────────────────────────────────────────────────────
// Disassembly API
// ─────────────────────────────────────────────────────────────────────────────

/// Decode a single x86/x64 opcode byte into (mnemonic, operands, size).
const fn decode_x86_simple(opcode: u8) -> (&'static str, &'static str, usize) {
    match opcode {
        0x00 => ("add", "[mem], al", 2),
        0x01 => ("add", "[mem], eax", 6),
        0x03 => ("add", "eax, [mem]", 6),
        0x08 => ("or", "[mem], al", 2),
        0x0F => ("(prefix)", "", 1),
        0x20 => ("and", "[mem], al", 2),
        0x25 => ("dup", "", 1),
        0x26 => ("pop", "", 1),
        0x27 => ("jmp", "far", 5),
        0x28 => ("call", "near", 5),
        0x29 => ("sub", "[mem], eax", 6),
        0x2A | 0xC3 => ("ret", "", 1),
        0x2B => ("br.s", "", 2),
        0x2C => ("brfalse.s", "", 2),
        0x31 => ("xor", "[mem], eax", 6),
        0x38 => ("br", "", 5),
        0x39 => ("cmp", "[mem], eax", 6),
        0x40..=0x47 => ("inc", "reg", 1),
        0x48..=0x4F => ("dec", "reg", 1),
        0x50..=0x57 => ("push", "reg", 1),
        0x58..=0x5F => ("pop", "reg", 1),
        0x60 => ("pushad", "", 1),
        0x61 => ("popad", "", 1),
        0x68 => ("push", "imm32", 5),
        0x6A => ("push", "imm8", 2),
        0x70 => ("jo", "rel8", 2),
        0x71 => ("jno", "rel8", 2),
        0x72 => ("jb", "rel8", 2),
        0x73 => ("jnb", "rel8", 2),
        0x74 => ("jz", "rel8", 2),
        0x75 => ("jnz", "rel8", 2),
        0x76 => ("jbe", "rel8", 2),
        0x77 => ("ja", "rel8", 2),
        0x78 => ("js", "rel8", 2),
        0x79 => ("jns", "rel8", 2),
        0x7A => ("throw", "", 1),
        0x7C => ("jl", "rel8", 2),
        0x7D => ("jge", "rel8", 2),
        0x7E => ("jle", "rel8", 2),
        0x7F => ("jg", "rel8", 2),
        0x80 | 0x83 => ("alu", "[mem], imm8", 3),
        0x81 => ("alu", "[mem], imm32", 6),
        0x84 => ("test", "[mem], al", 2),
        0x85 => ("test", "[mem], eax", 6),
        0x88 => ("mov", "[mem], al", 2),
        0x89 => ("mov", "[mem], eax", 6),
        0x8A => ("mov", "al, [mem]", 2),
        0x8B => ("mov", "eax, [mem]", 6),
        0x8C => ("box", "", 5),
        0x8D => ("lea", "eax, [mem]", 6),
        0x8E => ("ldlen", "", 1),
        0x90 => ("nop", "", 1),
        0xB0..=0xB7 => ("mov", "reg8, imm8", 2),
        0xB8..=0xBF => ("mov", "reg, imm32", 5),
        0xC0 | 0xC1 => ("rol/ror", "[mem], imm8", 3),
        0xC6 => ("mov", "[mem], imm8", 3),
        0xC7 => ("mov", "[mem], imm32", 6),
        0xCC => ("int3", "", 1),
        0xCD => ("int", "imm8", 2),
        0xD0..=0xD3 => ("shift", "[mem], cl", 2),
        0xE2 => ("loop", "rel8", 2),
        0xE8 => ("call", "rel32", 5),
        0xE9 => ("jmp", "rel32", 5),
        0xEB => ("jmp", "rel8", 2),
        0xF0 => ("lock", "(prefix)", 1),
        0xF3 => ("rep", "(prefix)", 1),
        0xF4 => ("hlt", "", 1),
        0xF6 => ("test/not", "[mem], imm8", 3),
        0xF7 => ("test/not/neg/mul/div", "[mem]", 2),
        0xFE => ("inc/dec", "[mem]", 2),
        0xFF => ("jmp/call", "[mem]", 6),
        _ => ("db", "", 1),
    }
}

/// Disassemble bytes starting at `base_address`, returning Rhai maps.
#[must_use]
pub fn disassemble_bytes(data: &[u8], base_address: u64, max_insns: usize) -> Vec<RhaiMap> {
    let mut result = Vec::new();
    let mut offset = 0usize;
    let mut count = 0usize;

    while offset < data.len() && count < max_insns {
        let opcode = data[offset];
        let (mnem, ops, size) = decode_x86_simple(opcode);
        let size = size.min(data.len() - offset).max(1);
        let insn = DisasmInstruction {
            address: base_address + u64::try_from(offset).unwrap_or(u64::MAX),
            mnemonic: mnem.to_string(),
            operands: ops.to_string(),
            bytes: data[offset..offset + size].to_vec(),
            size,
        };
        result.push(insn.to_rhai_map());
        offset += size;
        count += 1;
    }
    result
}

/// Disassemble a file section starting at `offset`.
#[must_use]
pub fn disassemble_file(path: &str, file_offset: usize, length: usize, base_va: u64, max_insns: usize) -> Vec<RhaiMap> {
    let Ok(data) = std::fs::read(path) else { return Vec::new() };
    if file_offset >= data.len() {
        return Vec::new();
    }
    let end = (file_offset + length).min(data.len());
    disassemble_bytes(&data[file_offset..end], base_va, max_insns)
}

// ─────────────────────────────────────────────────────────────────────────────
// Symbol lookup
// ─────────────────────────────────────────────────────────────────────────────

/// Parse PE export table and return symbols.
#[must_use]
pub fn parse_pe_exports(data: &[u8]) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    if !data.starts_with(b"MZ") || data.len() < 0x40 {
        return symbols;
    }
    let pe_off = usize::try_from(u32::from_le_bytes([
        data.get(0x3C).copied().unwrap_or(0),
        data.get(0x3D).copied().unwrap_or(0),
        data.get(0x3E).copied().unwrap_or(0),
        data.get(0x3F).copied().unwrap_or(0),
    ])).unwrap_or(usize::MAX);
    if pe_off + 24 > data.len() || &data[pe_off..pe_off + 4] != b"PE\0\0" {
        return symbols;
    }
    let machine = u16::from_le_bytes([data[pe_off + 4], data[pe_off + 5]]);
    let is64 = machine == 0x8664;
    let opt_off = pe_off + 24;
    let data_dir_base = if is64 { opt_off + 112 } else { opt_off + 96 };
    if data_dir_base + 8 > data.len() {
        return symbols;
    }
    let export_rva = usize::try_from(u32::from_le_bytes([
        data.get(data_dir_base).copied().unwrap_or(0),
        data.get(data_dir_base + 1).copied().unwrap_or(0),
        data.get(data_dir_base + 2).copied().unwrap_or(0),
        data.get(data_dir_base + 3).copied().unwrap_or(0),
    ])).unwrap_or(usize::MAX);
    if export_rva == 0 {
        return symbols;
    }
    // Map export RVA to file offset (simplified: identity for non-sectioned data)
    let export_off = export_rva;
    if export_off + 40 > data.len() {
        return symbols;
    }
    let num_names = usize::try_from(u32::from_le_bytes([
        data.get(export_off + 24).copied().unwrap_or(0),
        data.get(export_off + 25).copied().unwrap_or(0),
        data.get(export_off + 26).copied().unwrap_or(0),
        data.get(export_off + 27).copied().unwrap_or(0),
    ])).unwrap_or(usize::MAX);
    let names_rva = usize::try_from(u32::from_le_bytes([
        data.get(export_off + 32).copied().unwrap_or(0),
        data.get(export_off + 33).copied().unwrap_or(0),
        data.get(export_off + 34).copied().unwrap_or(0),
        data.get(export_off + 35).copied().unwrap_or(0),
    ])).unwrap_or(usize::MAX);

    for i in 0..num_names.min(256) {
        let name_ptr_off = names_rva + i * 4;
        if name_ptr_off + 4 > data.len() {
            break;
        }
        let name_rva_off = usize::try_from(u32::from_le_bytes([
            data.get(name_ptr_off).copied().unwrap_or(0),
            data.get(name_ptr_off + 1).copied().unwrap_or(0),
            data.get(name_ptr_off + 2).copied().unwrap_or(0),
            data.get(name_ptr_off + 3).copied().unwrap_or(0),
        ])).unwrap_or(usize::MAX);
        if name_rva_off == 0 || name_rva_off >= data.len() {
            continue;
        }
        let name_end = data[name_rva_off..].iter().position(|&b| b == 0).unwrap_or(32) + name_rva_off;
        let name = String::from_utf8_lossy(&data[name_rva_off..name_end.min(data.len())]).into_owned();
        symbols.push(Symbol {
            address: 0,
            name,
            kind: "export".to_string(),
            size: 0,
            is_imported: false,
            is_exported: true,
        });
    }
    symbols
}

/// Look up a symbol by name in the global symbol table.
#[must_use]
pub fn lookup_symbol(symbols: &[Symbol], name: &str) -> Option<RhaiMap> {
    symbols.iter().find(|s| s.name == name).map(Symbol::to_rhai_map)
}

/// Find all symbols whose names contain the given substring.
#[must_use]
pub fn find_symbols_containing(symbols: &[Symbol], pattern: &str) -> Vec<RhaiMap> {
    symbols.iter()
        .filter(|s| s.name.contains(pattern))
        .map(Symbol::to_rhai_map)
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Hex dump
// ─────────────────────────────────────────────────────────────────────────────

/// Format `data` as a classic hex dump string (16 bytes per line).
#[must_use]
pub fn hex_dump(data: &[u8], base_address: u64) -> String {
    let mut out = String::with_capacity(data.len() * 4);
    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + 16).min(data.len());
        let line = &data[offset..end];
        let _ = write!(out, "{:08X}  ", base_address + u64::try_from(offset).unwrap_or(u64::MAX));
        for (i, &b) in line.iter().enumerate() {
            if i == 8 { out.push(' '); }
            let _ = write!(out, "{b:02X} ");
        }
        // Pad if less than 16 bytes
        let pad_count = 16 - line.len();
        for i in 0..pad_count {
            if (line.len() + i) == 8 { out.push(' '); }
            out.push_str("   ");
        }
        out.push_str(" |");
        for &b in line {
            let ch = if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' };
            out.push(ch);
        }
        out.push('|');
        out.push('\n');
        offset += 16;
    }
    out
}

/// Generate a hex dump of `length` bytes from a file at `file_offset`.
#[must_use]
pub fn hex_dump_file(path: &str, file_offset: usize, length: usize, base_va: u64) -> String {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return format!("error: {e}"),
    };
    // Note: reading path may fail; the error variant is returned as a string above.
    if file_offset >= data.len() {
        return "error: offset out of range".to_string();
    }
    let end = (file_offset + length).min(data.len());
    hex_dump(&data[file_offset..end], base_va)
}

// ─────────────────────────────────────────────────────────────────────────────
// String search
// ─────────────────────────────────────────────────────────────────────────────

/// Extract printable ASCII strings of at least `min_len` from `data`.
#[must_use]
pub fn find_strings(data: &[u8], min_len: usize) -> Vec<FoundString> {
    let mut result = Vec::new();
    let mut start = 0usize;
    let mut current = String::new();
    for (i, &b) in data.iter().enumerate() {
        if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
            if current.is_empty() { start = i; }
            current.push(char::from(b));
        } else if current.len() >= min_len {
            result.push(FoundString {
                offset: start,
                value: std::mem::take(&mut current),
                encoding: "ascii".to_string(),
            });
        } else {
            current.clear();
        }
    }
    if current.len() >= min_len {
        result.push(FoundString {
            offset: start,
            value: current,
            encoding: "ascii".to_string(),
        });
    }
    result
}

/// Search for UTF-16LE strings in `data`.
#[must_use]
pub fn find_utf16le_strings(data: &[u8], min_len: usize) -> Vec<FoundString> {
    let mut result = Vec::new();
    if data.len() < 2 {
        return result;
    }
    let mut start = 0usize;
    let mut current = String::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let lo = data[i];
        let hi = data[i + 1];
        if hi == 0 && lo.is_ascii_graphic() || lo == b' ' {
            if current.is_empty() { start = i; }
            current.push(char::from(lo));
            i += 2;
        } else {
            if current.len() >= min_len {
                result.push(FoundString {
                    offset: start,
                    value: std::mem::take(&mut current),
                    encoding: "utf16le".to_string(),
                });
            } else {
                current.clear();
            }
            i += 1;
        }
    }
    if current.len() >= min_len {
        result.push(FoundString {
            offset: start,
            value: current,
            encoding: "utf16le".to_string(),
        });
    }
    result
}

/// Search for strings in a file.
#[must_use]
pub fn find_strings_in_file(path: &str, min_len: usize, include_utf16: bool) -> Vec<RhaiMap> {
    let Ok(data) = std::fs::read(path) else { return Vec::new() };
    let mut result: Vec<FoundString> = find_strings(&data, min_len);
    if include_utf16 {
        result.extend(find_utf16le_strings(&data, min_len));
    }
    result.sort_by_key(|s| s.offset);
    result.iter().map(FoundString::to_rhai_map).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Section enumeration
// ─────────────────────────────────────────────────────────────────────────────

/// Compute Shannon entropy of a byte slice.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut freq = [0u64; 256];
    for &b in data { freq[usize::from(b)] += 1; }
    // data.len() fits in u32 on all practical platforms; u32→f64 is lossless.
    let n_u32 = u32::try_from(data.len()).unwrap_or(u32::MAX);
    let n = f64::from(n_u32);
    let mut h = 0.0f64;
    for &c in &freq {
        if c > 0 {
            // c is a count ≤ data.len() ≤ u32::MAX, so c fits in u32.
            let p = f64::from(u32::try_from(c).unwrap_or(u32::MAX)) / n;
            h = p.mul_add(-p.log2(), h);
        }
    }
    h
}

/// Parse PE sections from raw bytes.
#[must_use]
pub fn parse_pe_sections(data: &[u8]) -> Vec<SectionInfo> {
    let mut sections = Vec::new();
    if !data.starts_with(b"MZ") || data.len() < 0x40 {
        return sections;
    }
    let pe_off = usize::try_from(u32::from_le_bytes([
        data.get(0x3C).copied().unwrap_or(0),
        data.get(0x3D).copied().unwrap_or(0),
        data.get(0x3E).copied().unwrap_or(0),
        data.get(0x3F).copied().unwrap_or(0),
    ])).unwrap_or(usize::MAX);
    if pe_off + 24 > data.len() || &data[pe_off..pe_off.saturating_add(4)] != b"PE\0\0" {
        return sections;
    }
    let num_sections = usize::from(u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]));
    let opt_size = usize::from(u16::from_le_bytes([data[pe_off + 20], data[pe_off + 21]]));
    let section_table_off = pe_off + 24 + opt_size;

    for i in 0..num_sections {
        let sec = section_table_off + i * 40;
        if sec + 40 > data.len() { break; }
        let name_bytes: Vec<u8> = data[sec..sec + 8].iter().take_while(|&&b| b != 0).copied().collect();
        let name = String::from_utf8_lossy(&name_bytes).into_owned();
        let virt_size = u64::from(u32::from_le_bytes([data[sec + 8], data[sec + 9], data[sec + 10], data[sec + 11]]));
        let virt_addr = u64::from(u32::from_le_bytes([data[sec + 12], data[sec + 13], data[sec + 14], data[sec + 15]]));
        let raw_size = u64::from(u32::from_le_bytes([data[sec + 16], data[sec + 17], data[sec + 18], data[sec + 19]]));
        let raw_off = u64::from(u32::from_le_bytes([data[sec + 20], data[sec + 21], data[sec + 22], data[sec + 23]]));
        let flags = u32::from_le_bytes([data[sec + 36], data[sec + 37], data[sec + 38], data[sec + 39]]);
        let is_code = flags & 0x20 != 0;
        let is_data = flags & 0x40 != 0 || flags & 0x80 != 0;
        let is_writable = flags & 0x8000_0000 != 0;
        let is_executable = flags & 0x2000_0000 != 0;

        let raw_start = usize::try_from(raw_off).unwrap_or(usize::MAX);
        let raw_end = (raw_start.saturating_add(usize::try_from(raw_size).unwrap_or(usize::MAX))).min(data.len());
        let entropy = if raw_end > raw_start {
            shannon_entropy(&data[raw_start..raw_end])
        } else {
            0.0
        };

        sections.push(SectionInfo {
            name,
            virtual_address: virt_addr,
            virtual_size: virt_size,
            raw_offset: raw_off,
            raw_size,
            flags,
            permissions: SectionPermissions::from_raw(
                u8::from(is_code)
                | (u8::from(is_data) << 1)
                | (u8::from(is_writable) << 2)
                | (u8::from(is_executable) << 3)
            ),
            entropy,
        });
    }
    sections
}

/// Parse ELF sections.
#[must_use]
pub fn parse_elf_sections(data: &[u8]) -> Vec<SectionInfo> {
    let mut sections = Vec::new();
    if !data.starts_with(b"\x7fELF") || data.len() < 40 { return sections; }
    let is64 = data[4] == 2;
    if is64 && data.len() < 64 { return sections; }
    let (shoff, shnum, shstrndx, shentsize): (usize, usize, usize, usize) = if is64 {
        let shoff = usize::try_from(u64::from_le_bytes(data[40..48].try_into().unwrap_or([0;8]))).unwrap_or(usize::MAX);
        let shnum = usize::from(u16::from_le_bytes([data[60], data[61]]));
        let shstrndx = usize::from(u16::from_le_bytes([data[62], data[63]]));
        let shentsize = usize::from(u16::from_le_bytes([data[58], data[59]]));
        (shoff, shnum, shstrndx, shentsize)
    } else {
        let shoff = usize::try_from(u32::from_le_bytes(data[32..36].try_into().unwrap_or([0;4]))).unwrap_or(usize::MAX);
        let shnum = usize::from(u16::from_le_bytes([data[48], data[49]]));
        let shstrndx = usize::from(u16::from_le_bytes([data[50], data[51]]));
        let shentsize = usize::from(u16::from_le_bytes([data[46], data[47]]));
        (shoff, shnum, shstrndx, shentsize)
    };
    if shoff == 0 || shentsize == 0 { return sections; }

    // Get string table offset
    let strtab_off = {
        let sh = shoff + shstrndx * shentsize;
        if sh + shentsize > data.len() { 0 }
        else if is64 {
            usize::try_from(u64::from_le_bytes(data[sh + 24..sh + 32].try_into().unwrap_or([0;8]))).unwrap_or(usize::MAX)
        } else {
            u32::from_le_bytes(data[sh + 16..sh + 20].try_into().unwrap_or([0;4])) as usize
        }
    };

    for i in 0..shnum {
        let sh = shoff + i * shentsize;
        if sh + shentsize > data.len() { break; }
        let name_idx = usize::try_from(u32::from_le_bytes(data[sh..sh + 4].try_into().unwrap_or([0;4]))).unwrap_or(usize::MAX);
        let (flags, addr, off, size) = if is64 {
            let flags = u32::try_from(u64::from_le_bytes(data[sh + 8..sh + 16].try_into().unwrap_or([0;8]))).unwrap_or(u32::MAX);
            let addr = u64::from_le_bytes(data[sh + 16..sh + 24].try_into().unwrap_or([0;8]));
            let off = usize::try_from(u64::from_le_bytes(data[sh + 24..sh + 32].try_into().unwrap_or([0;8]))).unwrap_or(usize::MAX);
            let size = u64::from_le_bytes(data[sh + 32..sh + 40].try_into().unwrap_or([0;8]));
            (flags, addr, off, size)
        } else {
            let flags = u32::from_le_bytes(data[sh + 8..sh + 12].try_into().unwrap_or([0;4]));
            let addr = u64::from(u32::from_le_bytes(data[sh + 12..sh + 16].try_into().unwrap_or([0;4])));
            let off = usize::try_from(u32::from_le_bytes(data[sh + 16..sh + 20].try_into().unwrap_or([0;4]))).unwrap_or(usize::MAX);
            let size = u64::from(u32::from_le_bytes(data[sh + 20..sh + 24].try_into().unwrap_or([0;4])));
            (flags, addr, off, size)
        };

        let name = if strtab_off > 0 && strtab_off + name_idx < data.len() {
            let end = data[strtab_off + name_idx..].iter().position(|&b| b == 0)
                .unwrap_or(32) + strtab_off + name_idx;
            String::from_utf8_lossy(&data[strtab_off + name_idx..end.min(data.len())]).into_owned()
        } else {
            format!("sec_{i}")
        };

        let end_off = (off.saturating_add(usize::try_from(size).unwrap_or(usize::MAX))).min(data.len());
        let entropy = if end_off > off { shannon_entropy(&data[off..end_off]) } else { 0.0 };
        let is_executable = flags & 0x4 != 0;
        let is_writable = flags & 0x1 != 0;

        sections.push(SectionInfo {
            name,
            virtual_address: addr,
            virtual_size: size,
            raw_offset: u64::try_from(off).unwrap_or(u64::MAX),
            raw_size: size,
            flags,
            permissions: SectionPermissions::from_raw(
                u8::from(is_executable)
                | (u8::from(!is_executable) << 1)
                | (u8::from(is_writable) << 2)
                | (u8::from(is_executable) << 3)
            ),
            entropy,
        });
    }
    sections
}

// ─────────────────────────────────────────────────────────────────────────────
// RhaiApiBindings — registers all functions into an Engine
// ─────────────────────────────────────────────────────────────────────────────

/// Registers all `RustRE` analysis API functions into `engine`.
pub struct RhaiApiBindings;

/// Parse sections from a raw binary blob, detecting PE or ELF format.
fn parse_sections_from_bytes(data: &[u8]) -> Vec<SectionInfo> {
    if data.starts_with(b"MZ") {
        parse_pe_sections(data)
    } else if data.starts_with(b"\x7fELF") {
        parse_elf_sections(data)
    } else {
        Vec::new()
    }
}

impl RhaiApiBindings {
    /// Register all bindings.
    pub fn register(engine: &mut Engine) {
        Self::register_load(engine);
        Self::register_disasm(engine);
        Self::register_sym(engine);
        Self::register_hex(engine);
        Self::register_strings(engine);
        Self::register_sections(engine);
        Self::register_xrefs(engine);
    }

    fn register_load(engine: &mut Engine) {
        // ── load_binary_api(path) → id ─────────────────────────────────────
        engine.register_fn("load_binary_api", |path: &str| -> String {
            match std::fs::read(path) {
                Ok(data) => {
                    store_put(path.to_string(), data);
                    path.to_string()
                }
                Err(e) => format!("error:{e}"),
            }
        });
    }

    fn register_disasm(engine: &mut Engine) {
        // ── disasm(data: blob, base_addr: int, max_insns: int) → [map] ─────
        engine.register_fn("disasm", |data: rhai::Blob, base: i64, max: i64| -> rhai::Array {
            disassemble_bytes(&data, base.cast_unsigned(), usize::try_from(max).unwrap_or(usize::MAX))
                .into_iter().map(Dynamic::from).collect()
        });

        // ── disasm_file(path, offset, len, base_va, max_insns) → [map] ─────
        engine.register_fn("disasm_file",
            |path: &str, off: i64, len: i64, base: i64, max: i64| -> rhai::Array {
                disassemble_file(
                    path,
                    usize::try_from(off).unwrap_or(usize::MAX),
                    usize::try_from(len).unwrap_or(usize::MAX),
                    base.cast_unsigned(),
                    usize::try_from(max).unwrap_or(usize::MAX),
                ).into_iter().map(Dynamic::from).collect()
            }
        );
    }

    fn register_sym(engine: &mut Engine) {
        // ── sym_lookup(data: blob, name: str) → map | () ──────────────────
        engine.register_fn("sym_lookup", |data: rhai::Blob, name: &str| -> Dynamic {
            lookup_symbol(&parse_pe_exports(&data), name).map_or(Dynamic::UNIT, Dynamic::from)
        });

        // ── sym_find(data: blob, pattern: str) → [map] ────────────────────
        engine.register_fn("sym_find", |data: rhai::Blob, pattern: &str| -> rhai::Array {
            find_symbols_containing(&parse_pe_exports(&data), pattern)
                .into_iter().map(Dynamic::from).collect()
        });

        // ── sym_list(data: blob) → [map] ──────────────────────────────────
        engine.register_fn("sym_list", |data: rhai::Blob| -> rhai::Array {
            parse_pe_exports(&data).iter().map(|s| Dynamic::from(s.to_rhai_map())).collect()
        });
    }

    fn register_hex(engine: &mut Engine) {
        // ── hex_dump(data: blob, base: int) → str ─────────────────────────
        engine.register_fn("hex_dump", |data: rhai::Blob, base: i64| -> String {
            hex_dump(&data, base.cast_unsigned())
        });

        // ── hex_dump_file(path, offset, len, base) → str ──────────────────
        engine.register_fn("hex_dump_file",
            |path: &str, off: i64, len: i64, base: i64| -> String {
                hex_dump_file(
                    path,
                    usize::try_from(off).unwrap_or(usize::MAX),
                    usize::try_from(len).unwrap_or(usize::MAX),
                    base.cast_unsigned(),
                )
            }
        );
    }

    fn register_strings(engine: &mut Engine) {
        // ── strings(data: blob, min_len: int) → [map] ─────────────────────
        engine.register_fn("strings", |data: rhai::Blob, min_len: i64| -> rhai::Array {
            find_strings(&data, usize::try_from(min_len).unwrap_or(usize::MAX))
                .iter().map(|s| Dynamic::from(s.to_rhai_map())).collect()
        });

        // ── strings_file(path, min_len, utf16) → [map] ────────────────────
        engine.register_fn("strings_file",
            |path: &str, min_len: i64, utf16: bool| -> rhai::Array {
                find_strings_in_file(path, usize::try_from(min_len).unwrap_or(usize::MAX), utf16)
                    .into_iter().map(Dynamic::from).collect()
            }
        );
    }

    fn register_sections(engine: &mut Engine) {
        // ── sections(data: blob) → [map] ──────────────────────────────────
        engine.register_fn("sections", |data: rhai::Blob| -> rhai::Array {
            parse_sections_from_bytes(&data).iter().map(|s| Dynamic::from(s.to_rhai_map())).collect()
        });

        // ── sections_file(path) → [map] ────────────────────────────────────
        engine.register_fn("sections_file", |path: &str| -> rhai::Array {
            let Ok(data) = std::fs::read(path) else { return Vec::new() };
            parse_sections_from_bytes(&data).iter().map(|s| Dynamic::from(s.to_rhai_map())).collect()
        });

        // ── section_data(data: blob, name: str) → blob ────────────────────
        engine.register_fn("section_data", |data: rhai::Blob, name: &str| -> rhai::Blob {
            for sec in &parse_sections_from_bytes(&data) {
                if sec.name == name {
                    let start = usize::try_from(sec.raw_offset).unwrap_or(usize::MAX);
                    let end = start
                        .saturating_add(usize::try_from(sec.raw_size).unwrap_or(usize::MAX))
                        .min(data.len());
                    return data[start..end].to_vec();
                }
            }
            Vec::new()
        });
    }

    fn register_xrefs(engine: &mut Engine) {
        // ── xref_scan(data: blob, target_va: int) → [int] ─────────────────
        engine.register_fn("xref_scan", |data: rhai::Blob, target_va: i64| -> rhai::Array {
            scan_call_xrefs(&data, target_va.cast_unsigned(), 0x0040_0000)
                .into_iter().map(|a| Dynamic::from(a.cast_signed())).collect()
        });

        // ── va_to_offset(data: blob, va: int) → int ───────────────────────
        engine.register_fn("va_to_offset", |data: rhai::Blob, va: i64| -> i64 {
            rva_to_file_offset(&data, va.cast_unsigned()).unwrap_or(u64::MAX).cast_signed()
        });
    }
}

/// Scan for CALL rel32 instructions that target a given VA.
#[must_use]
pub fn scan_call_xrefs(data: &[u8], target_va: u64, image_base: u64) -> Vec<u64> {
    let mut results = Vec::new();
    if data.len() < 5 { return results; }
    for i in 0..data.len() - 5 {
        if data[i] == 0xE8 {
            let rel = i32::from_le_bytes([data[i+1], data[i+2], data[i+3], data[i+4]]);
            let call_va = image_base + u64::try_from(i).unwrap_or(u64::MAX);
            let target = call_va.wrapping_add(5).wrapping_add(u64::from(rel.cast_unsigned()));
            if target == target_va {
                results.push(call_va);
            }
        }
    }
    results
}

/// Convert a relative virtual address to a file offset in a PE binary.
#[must_use]
pub fn rva_to_file_offset(data: &[u8], rva: u64) -> Option<u64> {
    if !data.starts_with(b"MZ") || data.len() < 0x40 { return None; }
    let pe_off = usize::try_from(u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?)).ok()?;
    if pe_off + 24 > data.len() { return None; }
    let num_sections = usize::from(u16::from_le_bytes([data[pe_off + 6], data[pe_off + 7]]));
    let opt_size = usize::from(u16::from_le_bytes([data[pe_off + 20], data[pe_off + 21]]));
    let sec_table = pe_off + 24 + opt_size;
    for i in 0..num_sections {
        let sec = sec_table + i * 40;
        if sec + 40 > data.len() { break; }
        let virt_size = u64::from(u32::from_le_bytes([data[sec + 8], data[sec + 9], data[sec + 10], data[sec + 11]]));
        let virt_addr = u64::from(u32::from_le_bytes([data[sec + 12], data[sec + 13], data[sec + 14], data[sec + 15]]));
        let raw_size = u64::from(u32::from_le_bytes([data[sec + 16], data[sec + 17], data[sec + 18], data[sec + 19]]));
        let raw_ptr = u64::from(u32::from_le_bytes([data[sec + 20], data[sec + 21], data[sec + 22], data[sec + 23]]));
        let mapped_size = virt_size.max(raw_size);
        if rva >= virt_addr && rva < virt_addr + mapped_size {
            return Some(rva - virt_addr + raw_ptr);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_dump_basic() {
        let data: Vec<u8> = (0..32).collect();
        let dump = hex_dump(&data, 0x1000);
        assert!(dump.contains("1000"));
        assert!(dump.contains("00 01 02"));
    }

    #[test]
    fn test_find_strings_basic() {
        let data = b"hello\x00world\x00\x01\x02short\x00good string here";
        let strs = find_strings(data, 5);
        assert!(strs.iter().any(|s| s.value == "hello"));
        assert!(strs.iter().any(|s| s.value == "world"));
        assert!(strs.iter().any(|s| s.value.contains("good string")));
    }

    #[test]
    fn test_find_strings_min_len() {
        let data = b"ab\x00abcde\x00";
        let strs = find_strings(data, 5);
        assert!(strs.iter().all(|s| s.value.len() >= 5));
    }

    #[test]
    fn test_disassemble_nops() {
        let data = vec![0x90u8; 8];
        let insns = disassemble_bytes(&data, 0x1000, 100);
        assert_eq!(insns.len(), 8);
        for m in &insns {
            assert_eq!(m.get("mnemonic").and_then(|v| v.clone().into_string().ok()).as_deref(), Some("nop"));
        }
    }

    #[test]
    fn test_disassemble_max_insns() {
        let data = vec![0x90u8; 64];
        let insns = disassemble_bytes(&data, 0, 10);
        assert_eq!(insns.len(), 10);
    }

    #[test]
    fn test_scan_call_xrefs_no_calls() {
        let data = vec![0x90u8; 64];
        let xrefs = scan_call_xrefs(&data, 0x401000, 0x400000);
        assert!(xrefs.is_empty());
    }

    #[test]
    fn test_utf16le_strings() {
        let mut data = Vec::new();
        for ch in b"hello" {
            data.push(*ch);
            data.push(0);
        }
        data.push(0); data.push(0); // null terminator
        let strs = find_utf16le_strings(&data, 3);
        assert!(!strs.is_empty());
        assert_eq!(strs[0].encoding, "utf16le");
    }

    #[test]
    fn test_decode_x86_ret() {
        let (mnem, _, size) = decode_x86_simple(0xC3);
        assert_eq!(mnem, "ret");
        assert_eq!(size, 1);
    }

    #[test]
    fn test_decode_x86_call() {
        let (mnem, _, size) = decode_x86_simple(0xE8);
        assert_eq!(mnem, "call");
        assert_eq!(size, 5);
    }
}
