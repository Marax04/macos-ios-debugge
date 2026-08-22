//! Symbol exporter — serialise a symbol table to JSON, CSV, IDA IDC script,
//! IDA Python script, MAP, or Ghidra bookmark CSV.
//!
//! # Key types
//!
//! * [`SymbolExporter`] — stateless export engine.
//! * [`ExportFormat`] — target format selector.
//! * [`ExportResult`] — export output with metadata.
//! * [`ExportOptions`] — fine-grained options (filter, sort, base-address offset).
//! * Free function [`export_to_idc`] — convenience wrapper.

use crate::{Symbol, SymKind, SymbolError, UnifiedSymbol, UnifiedSymbolTable};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

// ── ExportFormat ──────────────────────────────────────────────────────────────

/// Output format produced by [`SymbolExporter`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportFormat {
    /// Pretty-printed JSON array of symbol objects.
    Json,
    /// Comma-separated values with header row.
    Csv,
    /// IDA Pro IDC script (`MakeName` + optional `MakeFunction`).
    IdaIdc,
    /// IDA Pro Python script (`idc.set_name` + optional `idc.add_func`).
    IdaPython,
    /// GNU/Watcom MAP file (`address  name`).
    Map,
    /// Ghidra `bookmarks.csv` import format.
    GhidraBookmarks,
    /// Radare2 flag file (`f name addr`).
    Radare2Flags,
    /// LLDB target module symbol-file format (address tab name).
    Lldb,
}

impl ExportFormat {
    /// Returns the conventional file extension for the format.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            // Both CSV and Ghidra bookmarks use the same `.csv` extension.
            Self::Csv | Self::GhidraBookmarks => "csv",
            Self::IdaIdc => "idc",
            Self::IdaPython => "py",
            Self::Map => "map",
            Self::Radare2Flags => "r2",
            Self::Lldb => "txt",
        }
    }
}

impl std::fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => write!(f, "JSON"),
            Self::Csv => write!(f, "CSV"),
            Self::IdaIdc => write!(f, "IDA IDC"),
            Self::IdaPython => write!(f, "IDA Python"),
            Self::Map => write!(f, "MAP"),
            Self::GhidraBookmarks => write!(f, "Ghidra Bookmarks CSV"),
            Self::Radare2Flags => write!(f, "Radare2 Flags"),
            Self::Lldb => write!(f, "LLDB"),
        }
    }
}

// ── ExportOptions ─────────────────────────────────────────────────────────────

/// Options controlling symbol export behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportOptions {
    /// Include only symbols whose kind is in this list.  Empty = include all.
    pub include_kinds: Vec<SymKind>,
    /// Exclude symbols whose name starts with any of these prefixes.
    pub exclude_prefixes: Vec<String>,
    /// Minimum address to export (inclusive).
    pub addr_min: Option<u64>,
    /// Maximum address to export (inclusive).
    pub addr_max: Option<u64>,
    /// Sort output by address.
    pub sort_by_address: bool,
    /// Include demangled names in formats that support it.
    pub include_demangled: bool,
    /// Add this value to every address before output (useful for rebased images).
    pub base_offset: i64,
    /// Maximum number of symbols to export.  0 = unlimited.
    pub max_symbols: usize,
    /// For IDC/Python: emit `MakeFunction`/`idc.add_func` for function symbols.
    pub emit_make_function: bool,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            include_kinds: Vec::new(),
            exclude_prefixes: Vec::new(),
            addr_min: None,
            addr_max: None,
            sort_by_address: true,
            include_demangled: true,
            base_offset: 0,
            max_symbols: 0,
            emit_make_function: true,
        }
    }
}

impl ExportOptions {
    /// Create a new options set with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter symbols according to these options.
    #[must_use]
    pub fn filter<'a>(&self, symbols: &'a [Symbol]) -> Vec<&'a Symbol> {
        let mut filtered: Vec<&Symbol> = symbols
            .iter()
            .filter(|s| {
                if !self.include_kinds.is_empty() && !self.include_kinds.contains(&s.kind) {
                    return false;
                }
                if self
                    .exclude_prefixes
                    .iter()
                    .any(|pfx| s.name.starts_with(pfx.as_str()))
                {
                    return false;
                }
                if let Some(lo) = self.addr_min
                    && s.address < lo {
                        return false;
                    }
                if let Some(hi) = self.addr_max
                    && s.address > hi {
                        return false;
                    }
                true
            })
            .collect();

        if self.sort_by_address {
            filtered.sort_by_key(|s| s.address);
        }

        if self.max_symbols > 0 {
            filtered.truncate(self.max_symbols);
        }

        filtered
    }

    /// Apply the `base_offset` to a raw address.
    #[must_use]
    pub const fn apply_offset(&self, addr: u64) -> u64 {
        if self.base_offset >= 0 {
            addr.wrapping_add(self.base_offset.cast_unsigned())
        } else {
            // `unsigned_abs`, not `-x`: `base_offset` is a public `i64` and
            // negating `i64::MIN` overflows — it has no positive counterpart.
            addr.wrapping_sub(self.base_offset.unsigned_abs())
        }
    }
}

// ── ExportResult ──────────────────────────────────────────────────────────────

/// Result of a symbol export operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportResult {
    /// The rendered export content (text or JSON).
    pub content: String,
    /// Which format was used.
    pub format: ExportFormat,
    /// Number of symbols included in the export.
    pub symbol_count: usize,
    /// Number of symbols skipped by the options filter.
    pub skipped_count: usize,
}

impl ExportResult {
    /// Byte length of `content`.
    #[must_use]
    pub const fn byte_len(&self) -> usize {
        self.content.len()
    }
}

impl std::fmt::Display for ExportResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ExportResult({}, {} symbols, {} bytes)",
            self.format,
            self.symbol_count,
            self.byte_len()
        )
    }
}

// ── SymbolExporter ────────────────────────────────────────────────────────────

/// Stateless symbol exporter.
///
/// All methods take `&[Symbol]` plus optional [`ExportOptions`] and return
/// [`ExportResult`] or a [`SymbolError`].
pub struct SymbolExporter;

impl SymbolExporter {
    // ── JSON ──────────────────────────────────────────────────────────────────

    /// Export `symbols` to a pretty-printed JSON array.
    ///
    /// # Errors
    /// Returns [`SymbolError::Other`] if serialisation fails.
    pub fn to_json(symbols: &[Symbol], opts: &ExportOptions) -> Result<ExportResult, SymbolError> {
        let filtered = opts.filter(symbols);
        let skipped = symbols.len() - filtered.len();

        // Build a lightweight serialisable form
        let items: Vec<serde_json::Value> = filtered
            .iter()
            .map(|s| {
                let addr = opts.apply_offset(s.address);
                serde_json::json!({
                    "address": format!("{addr:#x}"),
                    "name": s.name,
                    "demangled": s.demangled_name,
                    "kind": format!("{:?}", s.kind),
                    "size": s.size,
                    "source": format!("{:?}", s.source),
                })
            })
            .collect();

        let content = serde_json::to_string_pretty(&items)
            .map_err(|e| SymbolError::Other(e.to_string()))?;

        Ok(ExportResult {
            content,
            format: ExportFormat::Json,
            symbol_count: filtered.len(),
            skipped_count: skipped,
        })
    }

    // ── CSV ───────────────────────────────────────────────────────────────────

    /// Export `symbols` to CSV.
    #[must_use]
    pub fn to_csv(symbols: &[Symbol], opts: &ExportOptions) -> ExportResult {
        let filtered = opts.filter(symbols);
        let skipped = symbols.len() - filtered.len();
        let mut out = String::from("address,name,demangled,kind,size,source\n");

        for s in &filtered {
            let addr = opts.apply_offset(s.address);
            writeln!(
                out,
                "{addr:#x},{},{},{:?},{},{:?}",
                csv_escape(&s.name),
                csv_escape(s.demangled_name.as_deref().unwrap_or("")),
                s.kind,
                s.size.map_or_else(|| "?".into(), |n| n.to_string()),
                s.source,
            )
            .expect("writing to String never fails");
        }

        ExportResult {
            content: out,
            format: ExportFormat::Csv,
            symbol_count: filtered.len(),
            skipped_count: skipped,
        }
    }

    // ── IDA IDC ───────────────────────────────────────────────────────────────

    /// Export `symbols` to an IDA Pro IDC script.
    #[must_use]
    pub fn to_idc(symbols: &[Symbol], opts: &ExportOptions) -> ExportResult {
        let filtered = opts.filter(symbols);
        let skipped = symbols.len() - filtered.len();
        let mut out = String::from(
            "// Generated by rustre-symbols\n\
             #include <idc.idc>\n\
             static main() {\n",
        );

        for s in &filtered {
            let addr = opts.apply_offset(s.address);
            let name = if opts.include_demangled {
                s.demangled_name.as_deref().unwrap_or(&s.name)
            } else {
                &s.name
            };
            let escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
            writeln!(out, "  MakeName({addr:#x}, \"{escaped}\");")
                .expect("writing to String never fails");
            if opts.emit_make_function && s.kind == SymKind::Function {
                writeln!(out, "  MakeFunction({addr:#x}, BADADDR);")
                    .expect("writing to String never fails");
            }
        }

        out.push_str("}\n");

        ExportResult {
            content: out,
            format: ExportFormat::IdaIdc,
            symbol_count: filtered.len(),
            skipped_count: skipped,
        }
    }

    // ── IDA Python ────────────────────────────────────────────────────────────

    /// Export `symbols` to an IDA Pro Python script.
    #[must_use]
    pub fn to_ida_python(symbols: &[Symbol], opts: &ExportOptions) -> ExportResult {
        let filtered = opts.filter(symbols);
        let skipped = symbols.len() - filtered.len();
        let mut out = String::from(
            "# Generated by rustre-symbols\n\
             import idc\n\n\
             def apply_symbols():\n",
        );

        for s in &filtered {
            let addr = opts.apply_offset(s.address);
            let name = if opts.include_demangled {
                s.demangled_name.as_deref().unwrap_or(&s.name)
            } else {
                &s.name
            };
            let escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
            writeln!(out, "    idc.set_name({addr:#x}, \"{escaped}\", idc.SN_FORCE)")
                .expect("writing to String never fails");
            if opts.emit_make_function && s.kind == SymKind::Function {
                writeln!(out, "    idc.add_func({addr:#x})")
                    .expect("writing to String never fails");
            }
        }

        out.push_str("\napply_symbols()\n");

        ExportResult {
            content: out,
            format: ExportFormat::IdaPython,
            symbol_count: filtered.len(),
            skipped_count: skipped,
        }
    }

    // ── MAP ───────────────────────────────────────────────────────────────────

    /// Export `symbols` to a GNU linker-style MAP file.
    #[must_use]
    pub fn to_map(symbols: &[Symbol], opts: &ExportOptions) -> ExportResult {
        let filtered = opts.filter(symbols);
        let skipped = symbols.len() - filtered.len();
        let mut out = String::from("# Symbol map — generated by rustre-symbols\n\
                                    # address              name\n");

        for s in &filtered {
            let addr = opts.apply_offset(s.address);
            writeln!(out, "{addr:#018x}  {}", s.name)
                .expect("writing to String never fails");
        }

        ExportResult {
            content: out,
            format: ExportFormat::Map,
            symbol_count: filtered.len(),
            skipped_count: skipped,
        }
    }

    // ── Ghidra Bookmarks ─────────────────────────────────────────────────────

    /// Export `symbols` as a Ghidra bookmarks CSV import file.
    #[must_use]
    pub fn to_ghidra_bookmarks(symbols: &[Symbol], opts: &ExportOptions) -> ExportResult {
        let filtered = opts.filter(symbols);
        let skipped = symbols.len() - filtered.len();
        let mut out = String::from("Address,Category,Description\n");

        for s in &filtered {
            let addr = opts.apply_offset(s.address);
            let desc = if opts.include_demangled {
                s.demangled_name.as_deref().unwrap_or(&s.name)
            } else {
                &s.name
            };
            writeln!(
                out,
                "{addr:#x},{:?},{}",
                s.kind,
                csv_escape(desc),
            )
            .expect("writing to String never fails");
        }

        ExportResult {
            content: out,
            format: ExportFormat::GhidraBookmarks,
            symbol_count: filtered.len(),
            skipped_count: skipped,
        }
    }

    // ── Radare2 flags ─────────────────────────────────────────────────────────

    /// Export `symbols` as a Radare2 flag file (`f name addr`).
    #[must_use]
    pub fn to_radare2_flags(symbols: &[Symbol], opts: &ExportOptions) -> ExportResult {
        let filtered = opts.filter(symbols);
        let skipped = symbols.len() - filtered.len();
        let mut out = String::from("# Radare2 flags — generated by rustre-symbols\n");

        for s in &filtered {
            let addr = opts.apply_offset(s.address);
            let name = s.name.replace(' ', "_");
            let size_part = s.size.map_or_else(String::new, |sz| format!(" {sz}"));
            writeln!(out, "f {name}{size_part} {addr:#x}")
                .expect("writing to String never fails");
        }

        ExportResult {
            content: out,
            format: ExportFormat::Radare2Flags,
            symbol_count: filtered.len(),
            skipped_count: skipped,
        }
    }

    // ── LLDB ─────────────────────────────────────────────────────────────────

    /// Export `symbols` in LLDB module symbol format (`address\tname`).
    #[must_use]
    pub fn to_lldb(symbols: &[Symbol], opts: &ExportOptions) -> ExportResult {
        let filtered = opts.filter(symbols);
        let skipped = symbols.len() - filtered.len();
        let mut out = String::new();

        for s in &filtered {
            let addr = opts.apply_offset(s.address);
            writeln!(out, "{addr:#018x}\t{}", s.name)
                .expect("writing to String never fails");
        }

        ExportResult {
            content: out,
            format: ExportFormat::Lldb,
            symbol_count: filtered.len(),
            skipped_count: skipped,
        }
    }

    // ── Dispatch ──────────────────────────────────────────────────────────────

    /// Export `symbols` in the given `format` with `opts`.
    ///
    /// # Errors
    /// Returns [`SymbolError`] for formats that can fail (e.g. JSON serialisation).
    pub fn export(
        symbols: &[Symbol],
        format: ExportFormat,
        opts: &ExportOptions,
    ) -> Result<ExportResult, SymbolError> {
        match format {
            ExportFormat::Json => Self::to_json(symbols, opts),
            ExportFormat::Csv => Ok(Self::to_csv(symbols, opts)),
            ExportFormat::IdaIdc => Ok(Self::to_idc(symbols, opts)),
            ExportFormat::IdaPython => Ok(Self::to_ida_python(symbols, opts)),
            ExportFormat::Map => Ok(Self::to_map(symbols, opts)),
            ExportFormat::GhidraBookmarks => Ok(Self::to_ghidra_bookmarks(symbols, opts)),
            ExportFormat::Radare2Flags => Ok(Self::to_radare2_flags(symbols, opts)),
            ExportFormat::Lldb => Ok(Self::to_lldb(symbols, opts)),
        }
    }

    // ── UnifiedSymbolTable helpers ────────────────────────────────────────────

    /// Export a [`UnifiedSymbolTable`] to IDC.
    #[must_use]
    pub fn unified_to_idc(table: &UnifiedSymbolTable) -> String {
        let opts = ExportOptions::default();
        let symbols: Vec<Symbol> = table
            .iter_by_address()
            .map(unified_to_legacy)
            .collect();
        Self::to_idc(&symbols, &opts).content
    }

    /// Export a [`UnifiedSymbolTable`] to JSON.
    ///
    /// # Errors
    /// Returns [`SymbolError`] on serialisation failure.
    pub fn unified_to_json(table: &UnifiedSymbolTable) -> Result<String, SymbolError> {
        let opts = ExportOptions::default();
        let symbols: Vec<Symbol> = table
            .iter_by_address()
            .map(unified_to_legacy)
            .collect();
        Self::to_json(&symbols, &opts).map(|r| r.content)
    }
}

// ── Free function helpers ─────────────────────────────────────────────────────

/// Export `symbols` to an IDA IDC script with default options.
///
/// This is a convenience wrapper over [`SymbolExporter::to_idc`].
#[must_use]
pub fn export_to_idc(symbols: &[Symbol]) -> String {
    let opts = ExportOptions::default();
    SymbolExporter::to_idc(symbols, &opts).content
}

/// Export `symbols` to CSV with default options.
#[must_use]
pub fn export_to_csv(symbols: &[Symbol]) -> String {
    let opts = ExportOptions::default();
    SymbolExporter::to_csv(symbols, &opts).content
}

/// Export `symbols` to JSON with default options.
///
/// # Errors
/// Returns [`SymbolError`] on serialisation failure.
pub fn export_to_json(symbols: &[Symbol]) -> Result<String, SymbolError> {
    let opts = ExportOptions::default();
    SymbolExporter::to_json(symbols, &opts).map(|r| r.content)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Quote-wrap a CSV field and double any embedded quotes, per RFC 4180.
///
/// Shared with the two exporters in `lib.rs`: a demangled C++ name such as
/// `Widget::draw(int, char const*)` contains commas and would otherwise split
/// one row into extra fields.
pub(crate) fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') || s.contains('\r') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_owned()
    }
}

fn unified_to_legacy(u: &UnifiedSymbol) -> Symbol {
    use crate::{LegacySymbolSource, SymbolVisibility};
    Symbol {
        id: u.address,
        name: u.name.clone(),
        demangled_name: u.demangled_name.clone(),
        address: u.address,
        size: u.size,
        // Exhaustive on purpose: the reverse map `legacy_to_unified_kind` in
        // `symbol_merger` has no catch-all, so the compiler checks it, while the
        // `_ => Function` this replaces silently absorbed every kind nobody
        // listed. `Module` was the casualty — the reverse map pairs
        // `SymKind::File` with `SymbolKind::Module`, yet a compilation unit came
        // out of here labelled as executable code with a call target.
        kind: match u.kind {
            crate::SymbolKind::Variable => SymKind::Data,
            crate::SymbolKind::Label => SymKind::Label,
            crate::SymbolKind::Section => SymKind::Section,
            crate::SymbolKind::Namespace => SymKind::Namespace,
            crate::SymbolKind::Module => SymKind::File,
            // `SymKind` has no Thunk/Import/Export, and the reverse map never
            // produces them; all three are executable code, so `Function` is
            // the nearest honest answer rather than a silent default. They are
            // listed beside `Function` (rather than in an arm of their own)
            // only because the answer coincides — the arm stays explicit so a
            // newly added `SymbolKind` still fails to compile here.
            crate::SymbolKind::Function
            | crate::SymbolKind::Thunk
            | crate::SymbolKind::Import
            | crate::SymbolKind::Export => SymKind::Function,
        },
        binding: crate::SymbolBinding::Global,
        visibility: SymbolVisibility::Default,
        section_index: None,
        file_offset: None,
        source: LegacySymbolSource::Debug,
        source_file: u.module.clone(),
        source_line: None,
        ordinal: None,
        tags: Vec::new(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LegacySymbolSource, SymKind, SymbolBinding, SymbolVisibility};

    fn make_sym(name: &str, addr: u64, kind: SymKind) -> Symbol {
        Symbol {
            id: addr,
            name: name.to_string(),
            demangled_name: None,
            address: addr,
            size: Some(0x10),
            kind,
            binding: SymbolBinding::Global,
            visibility: SymbolVisibility::Default,
            section_index: None,
            file_offset: None,
            source: LegacySymbolSource::Debug,
            source_file: None,
            source_line: None,
            ordinal: None,
            tags: Vec::new(),
        }
    }

    fn default_syms() -> Vec<Symbol> {
        vec![
            make_sym("main", 0x0040_1000, SymKind::Function),
            make_sym("g_counter", 0x0060_2000, SymKind::Data),
            make_sym("helper", 0x0040_1200, SymKind::Function),
        ]
    }

    #[test]
    fn test_export_format_extension() {
        assert_eq!(ExportFormat::Json.extension(), "json");
        assert_eq!(ExportFormat::IdaIdc.extension(), "idc");
        assert_eq!(ExportFormat::IdaPython.extension(), "py");
        assert_eq!(ExportFormat::Map.extension(), "map");
        assert_eq!(ExportFormat::Radare2Flags.extension(), "r2");
    }

    #[test]
    fn test_export_format_display() {
        assert_eq!(ExportFormat::Json.to_string(), "JSON");
        assert_eq!(ExportFormat::IdaIdc.to_string(), "IDA IDC");
    }

    #[test]
    fn test_csv_basic() {
        let syms = default_syms();
        let result = SymbolExporter::to_csv(&syms, &ExportOptions::default());
        assert_eq!(result.format, ExportFormat::Csv);
        assert_eq!(result.symbol_count, 3);
        assert!(result.content.contains("address,name"));
        assert!(result.content.contains("main"));
    }

    #[test]
    fn test_idc_basic() {
        let syms = default_syms();
        let result = SymbolExporter::to_idc(&syms, &ExportOptions::default());
        assert_eq!(result.format, ExportFormat::IdaIdc);
        assert!(result.content.contains("MakeName"));
        assert!(result.content.contains("main"));
        assert!(result.content.starts_with("// Generated"));
    }

    #[test]
    fn test_idc_make_function_only_for_functions() {
        let syms = default_syms();
        let opts = ExportOptions {
            emit_make_function: true,
            ..ExportOptions::default()
        };
        let result = SymbolExporter::to_idc(&syms, &opts);
        // Functions get MakeFunction; data does not
        assert!(result.content.contains("MakeFunction(0x401000"));
        assert!(!result.content.contains("MakeFunction(0x602000"));
    }

    #[test]
    fn test_idc_no_make_function() {
        let syms = default_syms();
        let opts = ExportOptions {
            emit_make_function: false,
            ..ExportOptions::default()
        };
        let result = SymbolExporter::to_idc(&syms, &opts);
        assert!(!result.content.contains("MakeFunction"));
    }

    #[test]
    fn test_ida_python_basic() {
        let syms = default_syms();
        let result = SymbolExporter::to_ida_python(&syms, &ExportOptions::default());
        assert_eq!(result.format, ExportFormat::IdaPython);
        assert!(result.content.contains("idc.set_name"));
        assert!(result.content.contains("main"));
    }

    #[test]
    fn test_map_basic() {
        let syms = default_syms();
        let result = SymbolExporter::to_map(&syms, &ExportOptions::default());
        assert_eq!(result.format, ExportFormat::Map);
        assert!(result.content.contains("main"));
        assert!(result.content.contains("0x0000000000401000"));
    }

    #[test]
    fn test_json_basic() {
        let syms = default_syms();
        let result = SymbolExporter::to_json(&syms, &ExportOptions::default()).unwrap();
        assert_eq!(result.format, ExportFormat::Json);
        assert!(result.content.contains("\"main\""));
    }

    #[test]
    fn test_ghidra_bookmarks() {
        let syms = default_syms();
        let result = SymbolExporter::to_ghidra_bookmarks(&syms, &ExportOptions::default());
        assert!(result.content.contains("Address,Category,Description"));
        assert!(result.content.contains("main"));
    }

    #[test]
    fn test_radare2_flags() {
        let syms = default_syms();
        let result = SymbolExporter::to_radare2_flags(&syms, &ExportOptions::default());
        assert_eq!(result.format, ExportFormat::Radare2Flags);
        assert!(result.content.contains("f main"));
    }

    #[test]
    fn test_lldb_basic() {
        let syms = default_syms();
        let result = SymbolExporter::to_lldb(&syms, &ExportOptions::default());
        assert_eq!(result.format, ExportFormat::Lldb);
        assert!(result.content.contains("main"));
    }

    #[test]
    fn test_filter_by_kind() {
        let syms = default_syms();
        let opts = ExportOptions {
            include_kinds: vec![SymKind::Function],
            ..ExportOptions::default()
        };
        let filtered = opts.filter(&syms);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_filter_by_addr_range() {
        let syms = default_syms();
        let opts = ExportOptions {
            addr_min: Some(0x0040_0000),
            addr_max: Some(0x0041_0000),
            ..ExportOptions::default()
        };
        let filtered = opts.filter(&syms);
        // g_counter at 0x602000 is outside
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_filter_exclude_prefix() {
        let syms = default_syms();
        let opts = ExportOptions {
            exclude_prefixes: vec!["g_".into()],
            ..ExportOptions::default()
        };
        let filtered = opts.filter(&syms);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_max_symbols() {
        let syms = default_syms();
        let opts = ExportOptions {
            max_symbols: 2,
            ..ExportOptions::default()
        };
        let filtered = opts.filter(&syms);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_base_offset_positive() {
        let opts = ExportOptions {
            base_offset: 0x1000,
            ..Default::default()
        };
        assert_eq!(opts.apply_offset(0x2000), 0x3000);
    }

    #[test]
    fn test_base_offset_negative() {
        let opts = ExportOptions {
            base_offset: -0x1000,
            ..Default::default()
        };
        assert_eq!(opts.apply_offset(0x2000), 0x1000);
    }

    #[test]
    fn test_export_result_display() {
        let r = ExportResult {
            content: "hello".into(),
            format: ExportFormat::Map,
            symbol_count: 3,
            skipped_count: 1,
        };
        let s = r.to_string();
        assert!(s.contains("3 symbols"));
    }

    #[test]
    fn test_dispatch_csv() {
        let syms = default_syms();
        let result = SymbolExporter::export(&syms, ExportFormat::Csv, &ExportOptions::default())
            .unwrap();
        assert_eq!(result.format, ExportFormat::Csv);
    }

    #[test]
    fn test_free_fn_export_to_idc() {
        let syms = default_syms();
        let out = export_to_idc(&syms);
        assert!(out.contains("MakeName"));
    }

    #[test]
    fn test_free_fn_export_to_csv() {
        let syms = default_syms();
        let out = export_to_csv(&syms);
        assert!(out.starts_with("address,name"));
    }

    #[test]
    fn test_free_fn_export_to_json() {
        let syms = default_syms();
        let out = export_to_json(&syms).unwrap();
        assert!(out.starts_with('['));
    }

    #[test]
    fn test_csv_escape_commas() {
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("plain"), "plain");
    }

    #[test]
    fn test_sort_by_address() {
        let syms = vec![
            make_sym("b", 0x2000, SymKind::Function),
            make_sym("a", 0x1000, SymKind::Function),
        ];
        let opts = ExportOptions::default();
        let filtered = opts.filter(&syms);
        assert_eq!(filtered[0].name, "a");
        assert_eq!(filtered[1].name, "b");
    }

    #[test]
    fn test_skipped_count_in_result() {
        let syms = default_syms();
        let opts = ExportOptions {
            include_kinds: vec![SymKind::Function],
            ..ExportOptions::default()
        };
        let result = SymbolExporter::to_csv(&syms, &opts);
        assert_eq!(result.skipped_count, 1); // g_counter skipped
    }
}
