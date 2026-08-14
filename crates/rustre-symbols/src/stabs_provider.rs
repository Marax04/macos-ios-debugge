//! STABS symbol provider — parses STABS debug info from old Unix / Linux binaries.
//!
//! Handles:
//! * `N_FUN`, `N_GSYM`, `N_STSYM`, `N_LSYM`, `N_PSYM`, `N_RSYM` — function/variable stabs.
//! * `N_SO`, `N_SOL` — source file entries.
//! * STABS type string parser: `i`, `f`, `d`, `c`, `s`, `*`, `a`, `r`, `(n,m)` references.
//! * Implements [`SymbolProvider`] for drop-in use.

use crate::{
    LegacySymbolSource, SourceLocation, SymKind, Symbol, SymbolBinding, SymbolProvider,
    SymbolVisibility, TypeInfo,
};
use std::collections::HashMap;
use std::fmt;

// ── Stabs type constants (n_type field) ───────────────────────────────────────

/// `N_GSYM` — a global-variable stab (the value lives elsewhere, not in `n_value`).
pub const N_GSYM: u8 = 0x20; // global symbol
/// `N_FUN` — a function name-and-type stab; `n_value` is the function address.
pub const N_FUN: u8 = 0x24; // function
/// `N_STSYM` — a file-scope static data symbol (`.data`).
pub const N_STSYM: u8 = 0x26; // static symbol
/// `N_LSYM` — a stack-local variable or a type definition.
pub const N_LSYM: u8 = 0x80; // local symbol (stack var)
/// `N_SOL` — the name of an included source file.
pub const N_SOL: u8 = 0x84; // source file (included)
/// `N_PSYM` — a function parameter.
pub const N_PSYM: u8 = 0xa0; // parameter
/// `N_RSYM` — a register variable.
pub const N_RSYM: u8 = 0x40; // register symbol
/// `N_SO` — the main source file (or compilation directory) name.
pub const N_SO: u8 = 0x64; // main source file / directory

// ── StabEntry ─────────────────────────────────────────────────────────────────

/// A single STABS entry as it appears in an `.stab` section.
#[derive(Debug, Clone)]
pub struct StabEntry {
    /// Index into `.stabstr` — resolved to `string` during parsing.
    pub strx: u32,
    /// Stabs type code (`N_FUN`, `N_SO`, …).
    pub n_type: u8,
    /// Stabs other field.
    pub n_other: u8,
    /// Stabs descriptor (line number for most records).
    pub n_desc: u16,
    /// Value — usually the symbol's address or offset.
    pub n_value: u64,
    /// Resolved string (from `.stabstr`).
    pub string: String,
}

impl StabEntry {
    /// Return just the name part of `string` (strip `:type_str` suffix).
    #[must_use]
    pub fn name_part(&self) -> &str {
        match self.string.find(':') {
            Some(pos) => &self.string[..pos],
            None => &self.string,
        }
    }
    /// Return just the type-string part (after the first `:`), if any.
    #[must_use]
    pub fn type_str_part(&self) -> Option<&str> {
        self.string.find(':').map(|pos| &self.string[pos + 1..])
    }
}

impl fmt::Display for StabEntry {
    /// Renders a stab entry roughly the way `objdump --stabs` does:
    /// `<n_type:#04x> <n_desc> <n_value:#x> <string>`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:#04x} {} {:#x} {}",
            self.n_type, self.n_desc, self.n_value, self.string,
        )
    }
}

// ── STABS type-string parser ──────────────────────────────────────────────────

/// Parse a STABS type descriptor string into a [`TypeInfo`].
///
/// Handles:
/// * Basic: `i`=int32, `u`=uint32, `c`=char, `f`=float, `d`=double, `v`=void
/// * `*<type>` = pointer
/// * `ar<range>;<count>;<elem_type>` = array
/// * `s<size><fields>` = struct (simplified)
/// * `(n,m)` = type reference → `Named("(n,m)")`
#[must_use]
pub fn parse_stabs_type(s: &str) -> TypeInfo {
    parse_type_str(s).0
}

const fn parse_int_type(width: u8, signed: bool) -> TypeInfo {
    TypeInfo::Int { width, signed }
}

fn parse_struct_type(s: &str) -> (TypeInfo, usize) {
    let size_end = s[1..]
        .find(|c: char| !c.is_ascii_digit())
        .map_or(s.len(), |p| p + 1);
    let name = format!("struct_{}", &s[1..size_end]);
    (TypeInfo::Struct { name, fields: vec![] }, size_end)
}

fn parse_array_type(s: &str) -> (TypeInfo, usize) {
    // ar<range>;0;<count>;<elem>
    let after_ar = &s[2..];
    let mut semi_count = 0;
    let elem_start = after_ar
        .char_indices()
        .find(|(_, c)| {
            if *c == ';' {
                semi_count += 1;
            }
            semi_count >= 2
        })
        .map_or(after_ar.len(), |(i, _)| i + 1);
    let elem_s = &after_ar[elem_start..];
    let count_s = if semi_count >= 2 {
        after_ar[..elem_start.saturating_sub(1)]
            .rsplit(';')
            .next()
            .unwrap_or("0")
    } else {
        "0"
    };
    let count = count_s.parse::<u64>().unwrap_or(0);
    let (elem_type, _) = parse_type_str(elem_s);
    (TypeInfo::Array { element: Box::new(elem_type), count }, s.len())
}

fn parse_type_str(s: &str) -> (TypeInfo, usize) {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return (TypeInfo::Unknown, 0);
    }
    match bytes[0] {
        b'i' => (parse_int_type(32, true), 1),
        b'u' => (parse_int_type(32, false), 1),
        b's' if s.len() > 1 && bytes[1].is_ascii_digit() => parse_struct_type(s),
        b'c' => (parse_int_type(8, true), 1),
        b'b' => (parse_int_type(8, false), 1),
        b'w' => (parse_int_type(16, true), 1),
        b'h' => (parse_int_type(16, false), 1),
        b'l' => (parse_int_type(64, true), 1),
        b'm' => (parse_int_type(64, false), 1),
        b'f' => (TypeInfo::Float { width: 32 }, 1),
        b'd' => (TypeInfo::Float { width: 64 }, 1),
        b'v' => (TypeInfo::Void, 1),
        b'B' => (TypeInfo::Bool, 1),
        b'*' => {
            let (inner, consumed) = parse_type_str(&s[1..]);
            (TypeInfo::Pointer { target: Box::new(inner), size: 8 }, 1 + consumed)
        }
        b'a' if s.starts_with("ar") => parse_array_type(s),
        b'(' => {
            // (n,m) type reference
            let end = s.find(')').map_or(s.len(), |i| i + 1);
            (TypeInfo::Named(s[..end].to_string()), end)
        }
        b'r' => (parse_int_type(32, true), s.len()),
        _ => (TypeInfo::Unknown, 1),
    }
}

// ── Parse raw stabs bytes ─────────────────────────────────────────────────────

/// Parse a raw `.stab` section into a list of [`StabEntry`]s.
///
/// `stab_data` is the `.stab` section bytes (each record is 12 bytes).
/// `str_data` is the `.stabstr` section bytes (NUL-terminated strings).
/// `is_64bit` controls whether `n_value` is read as 8 or 4 bytes.
#[must_use]
pub fn parse_stab_section(stab_data: &[u8], str_data: &[u8], is_64bit: bool) -> Vec<StabEntry> {
    let stride = if is_64bit { 16 } else { 12 };
    let mut entries = Vec::new();
    let mut off = 0usize;
    while off + stride <= stab_data.len() {
        let strx = read_u32_le(stab_data, off).unwrap_or(0);
        let n_type = stab_data.get(off + 4).copied().unwrap_or(0);
        let n_other = stab_data.get(off + 5).copied().unwrap_or(0);
        let n_desc = read_u16_le(stab_data, off + 6).unwrap_or(0);
        let n_value = if is_64bit {
            read_u64_le(stab_data, off + 8).unwrap_or(0)
        } else {
            u64::from(read_u32_le(stab_data, off + 8).unwrap_or(0))
        };
        let string = read_stab_str(str_data, strx as usize);
        entries.push(StabEntry {
            strx,
            n_type,
            n_other,
            n_desc,
            n_value,
            string,
        });
        off += stride;
    }
    entries
}

fn read_stab_str(str_data: &[u8], off: usize) -> String {
    if off >= str_data.len() {
        return String::new();
    }
    let end = str_data[off..]
        .iter()
        .position(|&b| b == 0)
        .map_or(str_data.len(), |p| off + p);
    std::str::from_utf8(&str_data[off..end])
        .unwrap_or("")
        .to_string()
}

fn read_u16_le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn read_u32_le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn read_u64_le(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

// ── Address fixup for relative N_FUN offsets ──────────────────────────────────

/// Post-process stab entries: `N_FUN` entries with value==0 after the first one
/// represent line-number sub-entries; we skip them for symbol purposes.
fn make_fun_symbol(entry: &StabEntry, source_file: Option<String>) -> Symbol {
    let name = entry.name_part().to_string();
    let addr = entry.n_value;
    Symbol {
        id: addr,
        name,
        demangled_name: None,
        address: addr,
        size: None,
        kind: SymKind::Function,
        binding: SymbolBinding::Global,
        visibility: SymbolVisibility::Default,
        section_index: None,
        file_offset: None,
        source: LegacySymbolSource::Debug,
        source_file,
        source_line: Some(u32::from(entry.n_desc)),
        ordinal: None,
        tags: vec!["stabs".into()],
    }
}

fn make_data_symbol(
    entry: &StabEntry,
    binding: SymbolBinding,
    source_file: Option<String>,
    extra_tag: Option<&'static str>,
) -> Symbol {
    let name = entry.name_part().to_string();
    let addr = entry.n_value;
    let mut tags = vec!["stabs".into()];
    if let Some(t) = extra_tag {
        tags.push(t.into());
    }
    Symbol {
        id: addr,
        name,
        demangled_name: None,
        address: addr,
        size: None,
        kind: SymKind::Data,
        binding,
        visibility: SymbolVisibility::Default,
        section_index: None,
        file_offset: None,
        source: LegacySymbolSource::Debug,
        source_file,
        source_line: Some(u32::from(entry.n_desc)),
        ordinal: None,
        tags,
    }
}

fn materialize_symbols(entries: &[StabEntry]) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    let mut current_so: Option<String> = None;
    let mut current_sol: Option<String> = None;

    for entry in entries {
        match entry.n_type {
            N_SO => {
                let s = entry.string.trim_end_matches('/');
                if !s.is_empty() {
                    current_so = Some(s.to_string());
                }
            }
            N_SOL => {
                if !entry.string.is_empty() {
                    current_sol = Some(entry.string.clone());
                }
            }
            N_FUN if !entry.name_part().is_empty() && entry.n_value != 0 => {
                let file = current_sol.clone().or_else(|| current_so.clone());
                symbols.push(make_fun_symbol(entry, file));
            }
            // Closing N_FUN stab (empty name): its value is the function size
            // (GCC) or end address (some assemblers). Attach it to the most
            // recent function symbol that lacks a size.
            N_FUN if entry.name_part().is_empty() && entry.n_value != 0 => {
                if let Some(last_fn) = symbols
                    .iter_mut()
                    .rev()
                    .find(|s| s.kind == SymKind::Function)
                    && last_fn.size.is_none()
                {
                    let v = entry.n_value;
                    last_fn.size = Some(if v > last_fn.address {
                        v - last_fn.address // end address form
                    } else {
                        v // size form
                    });
                }
            }
            N_GSYM if !entry.name_part().is_empty() => {
                symbols.push(make_data_symbol(entry, SymbolBinding::Global, current_so.clone(), Some("gsym")));
            }
            N_STSYM if !entry.name_part().is_empty() => {
                symbols.push(make_data_symbol(entry, SymbolBinding::Local, current_so.clone(), Some("stsym")));
            }
            // Stack/register locals and parameters. `n_value` is NOT an
            // address here — it is a frame-pointer-relative offset (N_LSYM),
            // a parameter offset (N_PSYM), or a register number (N_RSYM).
            // Emitting it as the symbol address planted entries at the very
            // top and bottom of the address space, polluting `lookup_nearest`
            // and every merged table. Anchor them to the enclosing function
            // instead and keep the raw value as a tag.
            N_LSYM | N_PSYM | N_RSYM if !entry.name_part().is_empty() => {
                let tag = n_type_tag(entry.n_type);
                let enclosing = symbols
                    .iter()
                    .rev()
                    .find(|s| s.kind == SymKind::Function)
                    .map(|s| s.address);
                // Without an enclosing function the entry has no meaningful
                // address at all; drop it rather than claim address 0.
                if let Some(fn_addr) = enclosing {
                    let raw = entry.n_value;
                    let mut sym = make_data_symbol(
                        entry,
                        SymbolBinding::Local,
                        current_so.clone(),
                        None,
                    );
                    sym.address = fn_addr;
                    sym.id = fn_addr;
                    sym.tags.push(tag.into());
                    sym.tags.push(format!("frame_offset:{raw:#x}"));
                    symbols.push(sym);
                }
            }
            _ => {}
        }
    }
    symbols
}

const fn n_type_tag(n_type: u8) -> &'static str {
    match n_type {
        N_LSYM => "lsym",
        N_PSYM => "psym",
        N_RSYM => "rsym",
        _ => "stabs",
    }
}

// ── Source-line index ─────────────────────────────────────────────────────────

/// Maps address ranges to source location via stab entries.
#[derive(Debug, Default)]
pub struct StabsSourceIndex {
    /// Sorted (addr, file, line) triples.
    entries: Vec<(u64, String, u32)>,
}

impl StabsSourceIndex {
    /// Build an address→source-location index from parsed stab entries,
    /// tracking the current file via `N_SO`/`N_SOL` and mapping `N_FUN` addresses.
    #[must_use]
    pub fn build(stab_entries: &[StabEntry]) -> Self {
        let mut entries = Vec::new();
        let mut current_file = String::new();
        for e in stab_entries {
            match e.n_type {
                N_SO | N_SOL if !e.string.is_empty() => {
                    current_file = e.string.trim_end_matches('/').to_string();
                }
                N_FUN if !e.name_part().is_empty() && e.n_value != 0 => {
                    entries.push((e.n_value, current_file.clone(), u32::from(e.n_desc)));
                }
                _ => {}
            }
        }
        entries.sort_by_key(|&(a, _, _)| a);
        Self { entries }
    }

    /// Resolve `addr` to its nearest-below source location, if any.
    #[must_use]
    pub fn lookup(&self, addr: u64) -> Option<SourceLocation> {
        let idx = match self.entries.binary_search_by_key(&addr, |&(a, _, _)| a) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        let (_, file, line) = &self.entries[idx];
        Some(SourceLocation {
            file: file.clone(),
            line: *line,
            column: 0,
        })
    }
}

// ── StabsProvider ─────────────────────────────────────────────────────────────

/// [`SymbolProvider`] backed by STABS debug info.
#[derive(Debug)]
pub struct StabsProvider {
    provider_name: String,
    entries: Vec<StabEntry>,
    symbols: Vec<Symbol>,
    by_addr: HashMap<u64, usize>,
    by_name: HashMap<String, usize>,
    source_index: StabsSourceIndex,
}

impl StabsProvider {
    /// Build from pre-parsed [`StabEntry`]s.
    #[must_use]
    pub fn from_entries(name: impl Into<String>, entries: Vec<StabEntry>) -> Self {
        let source_index = StabsSourceIndex::build(&entries);
        let mut symbols = materialize_symbols(&entries);
        symbols.sort_by_key(|s| s.address);
        let by_addr: HashMap<u64, usize> = symbols
            .iter()
            .enumerate()
            .map(|(i, s)| (s.address, i))
            .collect();
        let by_name: HashMap<String, usize> = symbols
            .iter()
            .enumerate()
            .map(|(i, s)| (s.name.clone(), i))
            .collect();
        Self {
            provider_name: name.into(),
            entries,
            symbols,
            by_addr,
            by_name,
            source_index,
        }
    }

    /// Parse from raw section bytes.
    pub fn from_raw(
        name: impl Into<String>,
        stab_data: &[u8],
        str_data: &[u8],
        is_64bit: bool,
    ) -> Self {
        let entries = parse_stab_section(stab_data, str_data, is_64bit);
        Self::from_entries(name, entries)
    }

    /// All parsed stab entries (including non-symbol ones like `N_SO`).
    #[must_use]
    pub fn entries(&self) -> &[StabEntry] {
        &self.entries
    }

    /// Number of materialised symbols.
    #[must_use]
    pub const fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    /// Collect all source file paths mentioned in `N_SO` entries.
    #[must_use]
    pub fn source_files(&self) -> Vec<String> {
        let mut files: Vec<String> = self
            .entries
            .iter()
            .filter(|e| e.n_type == N_SO && !e.string.is_empty())
            .map(|e| e.string.trim_end_matches('/').to_string())
            .collect();
        files.sort();
        files.dedup();
        files
    }

    /// Collect all type strings found in the stab entries.
    #[must_use]
    pub fn type_strings(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter_map(|e| e.type_str_part().map(std::string::ToString::to_string))
            .filter(|s| !s.is_empty())
            .collect()
    }

    /// Parse the type of a stab entry.
    #[must_use]
    pub fn parsed_type(&self, entry_idx: usize) -> Option<TypeInfo> {
        let e = self.entries.get(entry_idx)?;
        let type_str = e.type_str_part()?;
        Some(parse_stabs_type(type_str))
    }

    /// Project the materialised symbols into the spec §7
    /// [`crate::UnifiedSymbol`] taxonomy (source = [`crate::SymbolSource::Stabs`]).
    #[must_use]
    pub fn to_unified_symbols(&self) -> Vec<crate::UnifiedSymbol> {
        use crate::{SymbolSource, UnifiedSymbol};
        self.symbols
            .iter()
            .map(|s| {
                // Shared with DWARF and the merger: one exhaustive table instead
                // of three copies whose catch-alls disagreed.
                let kind = crate::symbol_merger::legacy_to_unified_kind(s.kind);
                let mut u =
                    UnifiedSymbol::new(s.name.clone(), s.address, kind, SymbolSource::Stabs);
                u.size = s.size;
                u.is_external = matches!(s.binding, SymbolBinding::Global | SymbolBinding::Weak);
                u.module.clone_from(&s.source_file);
                u
            })
            .collect()
    }
}

impl SymbolProvider for StabsProvider {
    fn name(&self) -> &str {
        &self.provider_name
    }

    fn lookup_name(&self, name: &str) -> Option<Symbol> {
        self.by_name.get(name).map(|&i| self.symbols[i].clone())
    }

    fn lookup_address(&self, addr: u64) -> Option<Symbol> {
        self.by_addr.get(&addr).map(|&i| self.symbols[i].clone())
    }

    fn lookup_nearest(&self, addr: u64) -> Option<Symbol> {
        let idx = match self.symbols.binary_search_by_key(&addr, |s| s.address) {
            Ok(i) => i,
            Err(0) => return None,
            Err(i) => i - 1,
        };
        Some(self.symbols[idx].clone())
    }

    fn all_symbols(&self) -> Vec<Symbol> {
        self.symbols.clone()
    }

    fn all_functions(&self) -> Vec<Symbol> {
        self.symbols
            .iter()
            .filter(|s| s.kind == SymKind::Function)
            .cloned()
            .collect()
    }

    fn source_line_for_address(&self, addr: u64) -> Option<SourceLocation> {
        self.source_index.lookup(addr)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(n_type: u8, string: &str, n_value: u64) -> StabEntry {
        StabEntry {
            strx: 0,
            n_type,
            n_other: 0,
            n_desc: 10,
            n_value,
            string: string.into(),
        }
    }

    // ── StabEntry helpers ────────────────────────────────────────────────────

    #[test]
    fn name_part_no_colon() {
        let e = make_entry(N_FUN, "main", 0x1000);
        assert_eq!(e.name_part(), "main");
        assert!(e.type_str_part().is_none());
    }

    #[test]
    fn name_part_with_type() {
        let e = make_entry(N_FUN, "foo:F(0,1)", 0x1000);
        assert_eq!(e.name_part(), "foo");
        assert_eq!(e.type_str_part(), Some("F(0,1)"));
    }

    #[test]
    fn name_part_data_var() {
        let e = make_entry(N_GSYM, "global_x:i", 0x4000);
        assert_eq!(e.name_part(), "global_x");
        assert_eq!(e.type_str_part(), Some("i"));
    }

    // ── Type string parser ────────────────────────────────────────────────

    #[test]
    fn parse_type_int() {
        let ti = parse_stabs_type("i");
        assert!(matches!(
            ti,
            TypeInfo::Int {
                width: 32,
                signed: true
            }
        ));
    }

    #[test]
    fn parse_type_uint() {
        let ti = parse_stabs_type("u");
        assert!(matches!(
            ti,
            TypeInfo::Int {
                width: 32,
                signed: false
            }
        ));
    }

    #[test]
    fn parse_type_char() {
        let ti = parse_stabs_type("c");
        assert!(matches!(
            ti,
            TypeInfo::Int {
                width: 8,
                signed: true
            }
        ));
    }

    #[test]
    fn parse_type_float() {
        let ti = parse_stabs_type("f");
        assert!(matches!(ti, TypeInfo::Float { width: 32 }));
    }

    #[test]
    fn parse_type_double() {
        let ti = parse_stabs_type("d");
        assert!(matches!(ti, TypeInfo::Float { width: 64 }));
    }

    #[test]
    fn parse_type_void() {
        let ti = parse_stabs_type("v");
        assert!(matches!(ti, TypeInfo::Void));
    }

    #[test]
    fn parse_type_pointer() {
        let ti = parse_stabs_type("*i");
        if let TypeInfo::Pointer { target, size } = ti {
            assert!(matches!(
                *target,
                TypeInfo::Int {
                    width: 32,
                    signed: true
                }
            ));
            assert_eq!(size, 8);
        } else {
            panic!("expected pointer");
        }
    }

    #[test]
    fn parse_type_struct() {
        let ti = parse_stabs_type("s8x:i,0,32;");
        assert!(matches!(ti, TypeInfo::Struct { .. }));
    }

    #[test]
    fn parse_type_reference() {
        let ti = parse_stabs_type("(0,1)");
        assert!(matches!(ti, TypeInfo::Named(_)));
    }

    #[test]
    fn parse_type_bool() {
        let ti = parse_stabs_type("B");
        assert!(matches!(ti, TypeInfo::Bool));
    }

    #[test]
    fn parse_type_unknown_returns_unknown() {
        let ti = parse_stabs_type("X");
        assert!(matches!(ti, TypeInfo::Unknown));
    }

    // ── materialize_symbols ───────────────────────────────────────────────

    #[test]
    fn n_fun_creates_function_symbol() {
        let entries = vec![make_entry(N_FUN, "main:F(0,1)", 0x0040_1000)];
        let p = StabsProvider::from_entries("t", entries);
        let sym = p.lookup_name("main").unwrap();
        assert_eq!(sym.kind, SymKind::Function);
        assert_eq!(sym.address, 0x0040_1000);
    }

    #[test]
    fn n_fun_zero_value_ignored() {
        let entries = vec![make_entry(N_FUN, "line_entry:f", 0)];
        let p = StabsProvider::from_entries("t", entries);
        assert!(p.lookup_name("line_entry").is_none());
    }

    #[test]
    fn n_gsym_creates_data_symbol() {
        let entries = vec![make_entry(N_GSYM, "g_count:i", 0x5000)];
        let p = StabsProvider::from_entries("t", entries);
        let sym = p.lookup_name("g_count").unwrap();
        assert_eq!(sym.kind, SymKind::Data);
        assert_eq!(sym.binding, SymbolBinding::Global);
    }

    #[test]
    fn n_stsym_creates_local_data() {
        let entries = vec![make_entry(N_STSYM, "s_var:i", 0x6000)];
        let p = StabsProvider::from_entries("t", entries);
        let sym = p.lookup_name("s_var").unwrap();
        assert_eq!(sym.binding, SymbolBinding::Local);
    }

    #[test]
    fn n_so_sets_source_file() {
        let entries = vec![
            make_entry(N_SO, "main.c", 0),
            make_entry(N_FUN, "foo:F(0,1)", 0x1000),
        ];
        let p = StabsProvider::from_entries("t", entries);
        let sym = p.lookup_name("foo").unwrap();
        assert_eq!(sym.source_file.as_deref(), Some("main.c"));
    }

    // ── StabsProvider ────────────────────────────────────────────────────

    #[test]
    fn provider_empty() {
        let p = StabsProvider::from_entries("t", vec![]);
        assert_eq!(p.symbol_count(), 0);
        assert!(p.all_symbols().is_empty());
    }

    #[test]
    fn provider_lookup_address() {
        let entries = vec![make_entry(N_FUN, "f:F(0,1)", 0x2000)];
        let p = StabsProvider::from_entries("t", entries);
        assert!(p.lookup_address(0x2000).is_some());
        assert!(p.lookup_address(0x9999).is_none());
    }

    #[test]
    fn provider_lookup_nearest() {
        let entries = vec![
            make_entry(N_FUN, "f1:F", 0x1000),
            make_entry(N_FUN, "f2:F", 0x2000),
        ];
        let p = StabsProvider::from_entries("t", entries);
        let s = p.lookup_nearest(0x1500).unwrap();
        assert_eq!(s.name, "f1");
    }

    #[test]
    fn provider_all_functions_count() {
        let entries = vec![
            make_entry(N_FUN, "fn1:F", 0x1000),
            make_entry(N_GSYM, "var1:i", 0x3000),
        ];
        let p = StabsProvider::from_entries("t", entries);
        assert_eq!(p.all_functions().len(), 1);
    }

    #[test]
    fn provider_name() {
        let p = StabsProvider::from_entries("stabs_test", vec![]);
        assert_eq!(p.name(), "stabs_test");
    }

    #[test]
    fn provider_source_files() {
        let entries = vec![
            make_entry(N_SO, "alpha.c", 0),
            make_entry(N_SO, "beta.c", 0),
        ];
        let p = StabsProvider::from_entries("t", entries);
        let files = p.source_files();
        assert_eq!(files.len(), 2);
        assert!(files.contains(&"alpha.c".to_string()));
    }

    #[test]
    fn provider_type_strings() {
        let entries = vec![
            make_entry(N_GSYM, "x:i", 0x1000),
            make_entry(N_GSYM, "y:f", 0x2000),
        ];
        let p = StabsProvider::from_entries("t", entries);
        let ts = p.type_strings();
        assert!(ts.contains(&"i".to_string()));
        assert!(ts.contains(&"f".to_string()));
    }

    // ── parse_stab_section ────────────────────────────────────────────────

    #[test]
    fn parse_raw_empty_stab() {
        let entries = parse_stab_section(&[], &[], false);
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_raw_single_entry_32bit() {
        // 12 bytes: strx(4) type(1) other(1) desc(2) value(4)
        let mut stab = vec![0u8; 12];
        stab[4] = N_FUN;
        stab[8..12].copy_from_slice(&0x1000u32.to_le_bytes());
        let str_section = b"main:F(0,1)\0";
        let entries = parse_stab_section(&stab, str_section, false);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].n_type, N_FUN);
        assert_eq!(entries[0].n_value, 0x1000);
        assert_eq!(entries[0].string, "main:F(0,1)");
    }

    // ── StabsSourceIndex ──────────────────────────────────────────────────

    #[test]
    fn source_index_lookup_hit() {
        let entries = vec![
            make_entry(N_SO, "foo.c", 0),
            make_entry(N_FUN, "bar:F", 0x4000),
        ];
        let idx = StabsSourceIndex::build(&entries);
        let loc = idx.lookup(0x4000).unwrap();
        assert_eq!(loc.file, "foo.c");
    }

    #[test]
    fn source_index_lookup_miss() {
        let idx = StabsSourceIndex::build(&[]);
        assert!(idx.lookup(0x1000).is_none());
    }

    #[test]
    fn source_line_for_address_via_provider() {
        let entries = vec![
            make_entry(N_SO, "test.c", 0),
            make_entry(N_FUN, "run:F", 0x8000),
        ];
        let p = StabsProvider::from_entries("t", entries);
        let loc = p.source_line_for_address(0x8000).unwrap();
        assert_eq!(loc.file, "test.c");
    }

    // ── lsym / psym / rsym ───────────────────────────────────────────────

    // For N_LSYM/N_PSYM/N_RSYM the stab's `n_value` is a frame offset, a
    // parameter offset, or a register number -- never an address. These
    // symbols are therefore anchored to the enclosing N_FUN, and the raw value
    // is preserved as a `frame_offset:` tag.

    #[test]
    fn n_lsym_creates_local_sym() {
        let entries = vec![
            make_entry(N_FUN, "outer:F", 0x4000),
            make_entry(N_LSYM, "local_var:i", 0xffff_ffc8),
        ];
        let p = StabsProvider::from_entries("t", entries);
        assert_eq!(p.symbol_count(), 2);
        let sym = p.lookup_name("local_var").unwrap();
        assert!(sym.tags.contains(&"lsym".to_string()));
        assert_eq!(sym.address, 0x4000, "anchored to the enclosing function");
        assert!(sym.tags.iter().any(|t| t.starts_with("frame_offset:")));
    }

    #[test]
    fn n_psym_creates_param_sym() {
        let entries = vec![
            make_entry(N_FUN, "outer:F", 0x4000),
            make_entry(N_PSYM, "param:i", 8),
        ];
        let p = StabsProvider::from_entries("t", entries);
        let sym = p.lookup_name("param").unwrap();
        assert!(sym.tags.contains(&"psym".to_string()));
        assert_eq!(sym.address, 0x4000);
    }

    #[test]
    fn n_rsym_creates_register_sym() {
        let entries = vec![
            make_entry(N_FUN, "outer:F", 0x4000),
            make_entry(N_RSYM, "reg_var:i", 3),
        ];
        let p = StabsProvider::from_entries("t", entries);
        let sym = p.lookup_name("reg_var").unwrap();
        assert!(sym.tags.contains(&"rsym".to_string()));
        assert_eq!(sym.address, 0x4000, "register number is not an address");
    }

    #[test]
    fn locals_never_land_at_bogus_addresses() {
        // A frame offset of -8 sign-extends to 0xFFFF_FFFF_FFFF_FFF8. Emitting
        // that as an address planted an entry at the top of the address space
        // and poisoned lookup_nearest for every later query.
        let entries = vec![
            make_entry(N_FUN, "outer:F", 0x4000),
            make_entry(N_LSYM, "x:i", 0xffff_ffff_ffff_fff8),
            make_entry(N_RSYM, "r:i", 3),
        ];
        let p = StabsProvider::from_entries("t", entries);
        for sym in &p.symbols {
            assert!(
                sym.address == 0x4000,
                "unexpected address {:#x} for {}",
                sym.address,
                sym.name
            );
        }
    }

    #[test]
    fn local_without_enclosing_function_is_dropped() {
        // No N_FUN in scope: there is no meaningful address, so the entry is
        // skipped rather than emitted at address 0.
        let entries = vec![make_entry(N_LSYM, "orphan:i", 0xffff_ffc8)];
        let p = StabsProvider::from_entries("t", entries);
        assert_eq!(p.symbol_count(), 0);
    }

    #[test]
    fn empty_name_ignored() {
        let entries = vec![make_entry(N_LSYM, "", 0x100)];
        let p = StabsProvider::from_entries("t", entries);
        assert_eq!(p.symbol_count(), 0);
    }

    // ── parsed_type ───────────────────────────────────────────────────────

    #[test]
    fn parsed_type_for_fun_entry() {
        let entries = vec![make_entry(N_FUN, "f:F(0,1)", 0x1000)];
        let p = StabsProvider::from_entries("t", entries);
        // entry 0 is the N_FUN; its type_str_part is "F(0,1)"
        // parse_stabs_type("F(0,1)") → Unknown (F is unknown type prefix)
        // Just assert it doesn't panic and returns Some
        let ti = p.parsed_type(0);
        assert!(ti.is_some());
    }

    // ── N_FUN size inference ───────────────────────────────────────────────

    #[test]
    fn fun_size_from_closing_stab_size_form() {
        let entries = vec![
            make_entry(N_FUN, "f:F1", 0x1000),
            make_entry(N_FUN, "", 0x40), // size form (value < addr)
        ];
        let p = StabsProvider::from_entries("t", entries);
        assert_eq!(p.lookup_name("f").unwrap().size, Some(0x40));
    }

    #[test]
    fn fun_size_from_closing_stab_end_address_form() {
        let entries = vec![
            make_entry(N_FUN, "g:F1", 0x1000),
            make_entry(N_FUN, "", 0x1080), // end-address form (value > addr)
        ];
        let p = StabsProvider::from_entries("t", entries);
        assert_eq!(p.lookup_name("g").unwrap().size, Some(0x80));
    }

    #[test]
    fn fun_without_closing_stab_has_no_size() {
        let entries = vec![make_entry(N_FUN, "h:F1", 0x2000)];
        let p = StabsProvider::from_entries("t", entries);
        assert_eq!(p.lookup_name("h").unwrap().size, None);
    }

    // ── Unified symbols ────────────────────────────────────────────────────

    #[test]
    fn to_unified_symbols_maps_kind_and_source() {
        let entries = vec![
            make_entry(N_FUN, "f:F1", 0x1000),
            make_entry(N_FUN, "", 0x20),
            make_entry(N_GSYM, "g_x:G1", 0x4000),
        ];
        let p = StabsProvider::from_entries("t", entries);
        let unified = p.to_unified_symbols();
        assert_eq!(unified.len(), 2);
        let f = unified.iter().find(|u| u.name == "f").unwrap();
        assert_eq!(f.kind, crate::SymbolKind::Function);
        assert_eq!(f.source, crate::SymbolSource::Stabs);
        assert_eq!(f.size, Some(0x20));
        let g = unified.iter().find(|u| u.name == "g_x").unwrap();
        assert_eq!(g.kind, crate::SymbolKind::Variable);
        assert!(g.is_external);
    }
}
