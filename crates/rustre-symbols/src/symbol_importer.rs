//! Symbol importer — parse symbol exports from IDA Pro, Ghidra, Radare2,
//! LLDB, MAP files, and generic JSON into a [`crate::UnifiedSymbolTable`].
//!
//! # Key types
//!
//! * [`SymbolImporter`] — stateless import engine.
//! * [`ImportFormat`] — source format selector.
//! * [`ImportResult`] — parsed symbols with metadata.
//! * [`ImportOptions`] — control deduplication, filtering, base-address rebasing.
//! * Free function [`import_from_json`] — convenience wrapper.

use crate::{
    SymbolError, SymbolKind as UnifiedSymbolKind, SymbolSource,
    UnifiedSymbol, UnifiedSymbolTable,
};
use serde::{Deserialize, Serialize};

// ── ImportFormat ──────────────────────────────────────────────────────────────

/// Format of the data being imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportFormat {
    /// JSON array produced by [`crate::symbol_exporter::SymbolExporter::to_json`] or IDA/Ghidra.
    Json,
    /// CSV with `address,name[,…]` columns.
    Csv,
    /// IDA Pro IDC script (`MakeName(addr, "name")`).
    IdaIdc,
    /// GNU linker MAP file (`address  name`).
    Map,
    /// Ghidra exported symbols CSV (`Name,Location,Type,…`).
    GhidraExport,
    /// Radare2 flags file (`f name [size] addr`).
    Radare2Flags,
    /// LLDB module symbol list (`address\tname`).
    Lldb,
    /// Binary Ninja BNDB symbol export (address,name,type).
    BinaryNinja,
}

impl std::fmt::Display for ImportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => write!(f, "JSON"),
            Self::Csv => write!(f, "CSV"),
            Self::IdaIdc => write!(f, "IDA IDC"),
            Self::Map => write!(f, "MAP"),
            Self::GhidraExport => write!(f, "Ghidra Export"),
            Self::Radare2Flags => write!(f, "Radare2 Flags"),
            Self::Lldb => write!(f, "LLDB"),
            Self::BinaryNinja => write!(f, "Binary Ninja"),
        }
    }
}

// ── ImportOptions ─────────────────────────────────────────────────────────────

/// Options controlling symbol import behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportOptions {
    /// Skip symbols whose names match any of these exact strings.
    pub skip_names: Vec<String>,
    /// Skip symbols whose address is less than `addr_min`.
    pub addr_min: Option<u64>,
    /// Skip symbols whose address is greater than `addr_max`.
    pub addr_max: Option<u64>,
    /// Add this value to every parsed address (for rebased images).
    pub base_offset: i64,
    /// When `true`, strip leading underscores from symbol names.
    pub strip_leading_underscore: bool,
    /// When `true`, silently skip duplicate (address, name) pairs.
    pub skip_duplicates: bool,
    /// Maximum number of symbols to import.  0 = unlimited.
    pub max_symbols: usize,
    /// Override the symbol source tag.  `None` = derive from format.
    pub force_source: Option<SymbolSource>,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            skip_names: Vec::new(),
            addr_min: None,
            addr_max: None,
            base_offset: 0,
            strip_leading_underscore: false,
            skip_duplicates: true,
            max_symbols: 0,
            force_source: None,
        }
    }
}

impl ImportOptions {
    /// Create a new options set with defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply the `base_offset` to `addr`.
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

    /// Return `true` when `addr` passes the address filter.
    #[must_use]
    pub const fn addr_ok(&self, addr: u64) -> bool {
        if let Some(lo) = self.addr_min
            && addr < lo {
                return false;
            }
        if let Some(hi) = self.addr_max
            && addr > hi {
                return false;
            }
        true
    }

    /// Normalise a symbol name according to options.
    #[must_use]
    pub fn normalise_name<'a>(&self, name: &'a str) -> &'a str {
        if self.strip_leading_underscore {
            name.strip_prefix('_').unwrap_or(name)
        } else {
            name
        }
    }
}

// ── ImportResult ──────────────────────────────────────────────────────────────

/// Result of an import operation.
#[derive(Debug, Clone)]
pub struct ImportResult {
    /// The successfully parsed symbols.
    pub symbols: Vec<UnifiedSymbol>,
    /// Number of lines/entries that could not be parsed.
    pub parse_errors: usize,
    /// Number of entries skipped by the options filter or deduplication.
    pub skipped: usize,
    /// Source format used for this import.
    pub format: ImportFormat,
}

impl ImportResult {
    /// Number of symbols successfully imported.
    #[must_use]
    pub const fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    /// Consume the result and return the symbol list.
    #[must_use]
    pub fn into_symbols(self) -> Vec<UnifiedSymbol> {
        self.symbols
    }

    /// Insert all parsed symbols into `table`.
    pub fn apply_to_table(self, table: &mut UnifiedSymbolTable) {
        for sym in self.symbols {
            table.add_or_upgrade(sym);
        }
    }
}

impl std::fmt::Display for ImportResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ImportResult({}, {} symbols, {} errors, {} skipped)",
            self.format,
            self.symbol_count(),
            self.parse_errors,
            self.skipped
        )
    }
}

// ── SymbolImporter ────────────────────────────────────────────────────────────

/// Stateless symbol importer supporting multiple source formats.
pub struct SymbolImporter;

impl SymbolImporter {
    // ── JSON ──────────────────────────────────────────────────────────────────

    /// Parse symbols from a JSON string.
    ///
    /// Accepts both the native rustre export format (array of objects with
    /// `address` and `name` fields) and the IDA JSON export format.
    ///
    /// # Errors
    /// Returns [`SymbolError::Parse`] on malformed JSON.
    pub fn from_json(text: &str, opts: &ImportOptions) -> Result<ImportResult, SymbolError> {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|e| SymbolError::Parse(e.to_string()))?;

        let arr = match &value {
            serde_json::Value::Array(a) => a.clone(),
            serde_json::Value::Object(o) => {
                // IDA JSON format wraps the list under a key
                if let Some(serde_json::Value::Array(inner)) = o.get("functions")
                    .or_else(|| o.get("symbols"))
                    .or_else(|| o.get("names"))
                {
                    inner.clone()
                } else {
                    return Err(SymbolError::Parse("expected JSON array or object with 'functions'/'symbols'/'names' key".into()));
                }
            }
            _ => return Err(SymbolError::Parse("expected JSON array at root".into())),
        };

        let source = opts
            .force_source
            .unwrap_or(SymbolSource::Manual);

        let mut symbols = Vec::new();
        let mut parse_errors = 0usize;
        let mut skipped = 0usize;

        for item in &arr {
            if opts.max_symbols > 0 && symbols.len() >= opts.max_symbols {
                break;
            }
            let addr_raw = parse_json_addr(item);
            let name_raw = item.get("name")
                .or_else(|| item.get("n"))
                .and_then(|v| v.as_str())
                .map(str::to_owned);

            let (Some(addr_raw), Some(name_raw)) = (addr_raw, name_raw) else {
                parse_errors += 1;
                continue;
            };

            let addr = opts.apply_offset(addr_raw);
            if !opts.addr_ok(addr) {
                skipped += 1;
                continue;
            }
            let name = opts.normalise_name(&name_raw).to_owned();
            if opts.skip_names.contains(&name) {
                skipped += 1;
                continue;
            }

            let kind_str = item.get("kind").and_then(|v| v.as_str()).unwrap_or("Function");
            let kind = parse_kind_str(kind_str);
            let demangled = item.get("demangled").and_then(|v| v.as_str()).map(str::to_owned);
            let size = item.get("size").and_then(serde_json::Value::as_u64);

            let mut sym = UnifiedSymbol::new(name, addr, kind, source);
            sym.demangled_name = demangled;
            sym.size = size;
            symbols.push(sym);
        }

        Ok(ImportResult {
            symbols,
            parse_errors,
            skipped,
            format: ImportFormat::Json,
        })
    }

    // ── CSV ───────────────────────────────────────────────────────────────────

    /// Parse symbols from a CSV string.
    ///
    /// Expects a header row with at least `address` and `name` columns.
    /// Accepts variations: `addr`, `offset`, `ea` for the address column.
    ///
    /// # Errors
    /// Returns [`SymbolError::Parse`] if the header is missing or malformed.
    pub fn from_csv(text: &str, opts: &ImportOptions) -> Result<ImportResult, SymbolError> {
        let source = opts.force_source.unwrap_or(SymbolSource::Manual);
        let mut lines = text.lines();

        let header_line = lines.next().ok_or_else(|| SymbolError::Parse("empty input".into()))?;
        let headers: Vec<&str> = header_line.split(',').map(str::trim).collect();

        let addr_col = headers.iter().position(|&h| {
            matches!(h.to_ascii_lowercase().as_str(), "address" | "addr" | "offset" | "ea" | "va")
        }).ok_or_else(|| SymbolError::Parse("CSV missing address column".into()))?;

        let name_col = headers.iter().position(|&h| {
            matches!(h.to_ascii_lowercase().as_str(), "name" | "symbol" | "label")
        }).ok_or_else(|| SymbolError::Parse("CSV missing name column".into()))?;

        let kind_col = headers.iter().position(|&h| h.eq_ignore_ascii_case("kind"));
        let size_col = headers.iter().position(|&h| h.eq_ignore_ascii_case("size"));
        let demangled_col = headers.iter().position(|&h| h.eq_ignore_ascii_case("demangled"));

        let mut symbols = Vec::new();
        let mut parse_errors = 0usize;
        let mut skipped = 0usize;

        for line in lines {
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            if opts.max_symbols > 0 && symbols.len() >= opts.max_symbols {
                break;
            }
            let cols = split_csv_line(line);
            let addr_raw = cols.get(addr_col).and_then(|s| parse_hex_or_dec(s.trim()));
            let name_raw = cols.get(name_col).map(|s| s.trim().to_owned());

            let (Some(addr_raw), Some(name_raw)) = (addr_raw, name_raw) else {
                parse_errors += 1;
                continue;
            };
            if name_raw.is_empty() {
                parse_errors += 1;
                continue;
            }

            let addr = opts.apply_offset(addr_raw);
            if !opts.addr_ok(addr) {
                skipped += 1;
                continue;
            }
            let name = opts.normalise_name(&name_raw).to_owned();
            if opts.skip_names.contains(&name) {
                skipped += 1;
                continue;
            }

            let kind = kind_col
                .and_then(|c| cols.get(c))
                .map_or(UnifiedSymbolKind::Function, |s| parse_kind_str(s.trim()));
            let size = size_col
                .and_then(|c| cols.get(c))
                .and_then(|s| parse_hex_or_dec(s.trim()));
            let demangled = demangled_col
                .and_then(|c| cols.get(c))
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty());

            let mut sym = UnifiedSymbol::new(name, addr, kind, source);
            sym.size = size;
            sym.demangled_name = demangled;
            symbols.push(sym);
        }

        Ok(ImportResult {
            symbols,
            parse_errors,
            skipped,
            format: ImportFormat::Csv,
        })
    }

    // ── IDA IDC ───────────────────────────────────────────────────────────────

    /// Parse symbols from an IDA Pro IDC script.
    ///
    /// Recognises `MakeName(addr, "name")` calls.
    ///
    /// # Errors
    /// Returns [`SymbolError::Parse`] on critical parse failures.
    pub fn from_idc(text: &str, opts: &ImportOptions) -> Result<ImportResult, SymbolError> {
        let source = opts.force_source.unwrap_or(SymbolSource::Manual);
        let mut symbols = Vec::new();
        let mut parse_errors = 0usize;
        let mut skipped = 0usize;

        for line in text.lines() {
            let trimmed = line.trim();
            // Match: MakeName(0xADDR, "name");
            if let Some(rest) = trimmed.strip_prefix("MakeName(") {
                if opts.max_symbols > 0 && symbols.len() >= opts.max_symbols {
                    break;
                }
                if let Some((addr_raw, name_raw)) = parse_idc_make_name(rest) {
                    let addr = opts.apply_offset(addr_raw);
                    if !opts.addr_ok(addr) {
                        skipped += 1;
                        continue;
                    }
                    let name = opts.normalise_name(&name_raw).to_owned();
                    if opts.skip_names.contains(&name) {
                        skipped += 1;
                        continue;
                    }
                    symbols.push(UnifiedSymbol::new(
                        name,
                        addr,
                        UnifiedSymbolKind::Function,
                        source,
                    ));
                } else {
                    parse_errors += 1;
                }
            }
        }

        Ok(ImportResult {
            symbols,
            parse_errors,
            skipped,
            format: ImportFormat::IdaIdc,
        })
    }

    // ── MAP ───────────────────────────────────────────────────────────────────

    /// Parse symbols from a GNU/Watcom MAP file.
    ///
    /// Expects lines of the form `0xADDRESS  name` (optional leading whitespace).
    ///
    /// # Errors
    /// Returns [`SymbolError::Parse`] on critical failures.
    pub fn from_map(text: &str, opts: &ImportOptions) -> Result<ImportResult, SymbolError> {
        let source = opts.force_source.unwrap_or(SymbolSource::Manual);
        let mut symbols = Vec::new();
        let mut parse_errors = 0usize;
        let mut skipped = 0usize;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }
            if opts.max_symbols > 0 && symbols.len() >= opts.max_symbols {
                break;
            }
            let mut parts = trimmed.splitn(2, char::is_whitespace);
            let Some(addr_str) = parts.next() else {
                parse_errors += 1;
                continue;
            };
            let name_str = parts.next().map_or("", str::trim).to_owned();

            let Some(addr_raw) = parse_hex_or_dec(addr_str) else {
                parse_errors += 1;
                continue;
            };
            if name_str.is_empty() {
                parse_errors += 1;
                continue;
            }

            let addr = opts.apply_offset(addr_raw);
            if !opts.addr_ok(addr) {
                skipped += 1;
                continue;
            }
            let name = opts.normalise_name(&name_str).to_owned();
            if opts.skip_names.contains(&name) {
                skipped += 1;
                continue;
            }
            symbols.push(UnifiedSymbol::new(
                name,
                addr,
                UnifiedSymbolKind::Function,
                source,
            ));
        }

        Ok(ImportResult {
            symbols,
            parse_errors,
            skipped,
            format: ImportFormat::Map,
        })
    }

    // ── Ghidra Export ─────────────────────────────────────────────────────────

    /// Parse a Ghidra symbol export CSV (`Name,Location,Type,Namespace,…`).
    ///
    /// # Errors
    /// Returns [`SymbolError::Parse`] if the header is absent.
    pub fn from_ghidra_export(text: &str, opts: &ImportOptions) -> Result<ImportResult, SymbolError> {
        let source = opts.force_source.unwrap_or(SymbolSource::Manual);
        let mut lines = text.lines();

        let header_line = lines.next().ok_or_else(|| SymbolError::Parse("empty input".into()))?;
        let headers: Vec<String> = header_line
            .split(',')
            .map(|h| h.trim().to_ascii_lowercase())
            .collect();

        let name_col = headers.iter().position(|h| h == "name" || h == "label")
            .ok_or_else(|| SymbolError::Parse("Ghidra CSV missing 'Name' column".into()))?;
        let loc_col = headers.iter().position(|h| h == "location" || h == "address" || h == "addr")
            .ok_or_else(|| SymbolError::Parse("Ghidra CSV missing 'Location' column".into()))?;
        let type_col = headers.iter().position(|h| h == "type" || h == "kind");
        let ns_col = headers.iter().position(|h| h == "namespace");

        let mut symbols = Vec::new();
        let mut parse_errors = 0usize;
        let mut skipped = 0usize;

        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if opts.max_symbols > 0 && symbols.len() >= opts.max_symbols {
                break;
            }
            let cols = split_csv_line(trimmed);
            let name_raw = cols.get(name_col).map(|s| s.trim().to_owned());
            let loc_raw = cols.get(loc_col).and_then(|s| parse_hex_or_dec(s.trim()));

            let (Some(name_raw), Some(addr_raw)) = (name_raw, loc_raw) else {
                parse_errors += 1;
                continue;
            };

            let addr = opts.apply_offset(addr_raw);
            if !opts.addr_ok(addr) {
                skipped += 1;
                continue;
            }
            let name = opts.normalise_name(&name_raw).to_owned();
            if name.is_empty() || opts.skip_names.contains(&name) {
                skipped += 1;
                continue;
            }

            let kind = type_col
                .and_then(|c| cols.get(c))
                .map_or(UnifiedSymbolKind::Function, |s| parse_kind_str(s.trim()));

            let module = ns_col
                .and_then(|c| cols.get(c))
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty());

            let mut sym = UnifiedSymbol::new(name, addr, kind, source);
            sym.module = module;
            symbols.push(sym);
        }

        Ok(ImportResult {
            symbols,
            parse_errors,
            skipped,
            format: ImportFormat::GhidraExport,
        })
    }

    // ── Radare2 flags ─────────────────────────────────────────────────────────

    /// Parse a Radare2 flag file (`f name [size] addr` or `f name addr`).
    ///
    /// # Errors
    /// Returns [`SymbolError::Parse`] on critical failures.
    pub fn from_radare2_flags(text: &str, opts: &ImportOptions) -> Result<ImportResult, SymbolError> {
        let source = opts.force_source.unwrap_or(SymbolSource::Manual);
        let mut symbols = Vec::new();
        let mut parse_errors = 0usize;
        let mut skipped = 0usize;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if opts.max_symbols > 0 && symbols.len() >= opts.max_symbols {
                break;
            }
            // "f name [size] addr"
            let Some(rest) = trimmed.strip_prefix("f ") else {
                continue;
            };
            let parts: Vec<&str> = rest.split_whitespace().collect();
            let (name_raw, size_opt, addr_raw) = match parts.as_slice() {
                [name, addr] => (*name, None, parse_hex_or_dec(addr)),
                [name, size, addr] => (*name, parse_hex_or_dec(size), parse_hex_or_dec(addr)),
                _ => {
                    parse_errors += 1;
                    continue;
                }
            };

            let Some(addr_raw) = addr_raw else {
                parse_errors += 1;
                continue;
            };

            let addr = opts.apply_offset(addr_raw);
            if !opts.addr_ok(addr) {
                skipped += 1;
                continue;
            }
            let name = opts.normalise_name(name_raw).to_owned();
            if opts.skip_names.contains(&name) {
                skipped += 1;
                continue;
            }
            let mut sym = UnifiedSymbol::new(name, addr, UnifiedSymbolKind::Function, source);
            sym.size = size_opt;
            symbols.push(sym);
        }

        Ok(ImportResult {
            symbols,
            parse_errors,
            skipped,
            format: ImportFormat::Radare2Flags,
        })
    }

    // ── LLDB ──────────────────────────────────────────────────────────────────

    /// Parse an LLDB module symbol list (`address\tname`).
    ///
    /// # Errors
    /// Returns [`SymbolError::Parse`] on critical failures.
    pub fn from_lldb(text: &str, opts: &ImportOptions) -> Result<ImportResult, SymbolError> {
        let source = opts.force_source.unwrap_or(SymbolSource::Manual);
        let mut symbols = Vec::new();
        let mut parse_errors = 0usize;
        let mut skipped = 0usize;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if opts.max_symbols > 0 && symbols.len() >= opts.max_symbols {
                break;
            }
            let mut parts = trimmed.splitn(2, '\t');
            let addr_str = if let Some(s) = parts.next() { s.trim() } else {
                parse_errors += 1;
                continue;
            };
            let name_str = parts.next().map_or("", str::trim).to_owned();

            let Some(addr_raw) = parse_hex_or_dec(addr_str) else {
                parse_errors += 1;
                continue;
            };
            if name_str.is_empty() {
                parse_errors += 1;
                continue;
            }

            let addr = opts.apply_offset(addr_raw);
            if !opts.addr_ok(addr) {
                skipped += 1;
                continue;
            }
            let name = opts.normalise_name(&name_str).to_owned();
            if opts.skip_names.contains(&name) {
                skipped += 1;
                continue;
            }
            symbols.push(UnifiedSymbol::new(
                name,
                addr,
                UnifiedSymbolKind::Function,
                source,
            ));
        }

        Ok(ImportResult {
            symbols,
            parse_errors,
            skipped,
            format: ImportFormat::Lldb,
        })
    }

    // ── Dispatch ──────────────────────────────────────────────────────────────

    /// Dispatch to the appropriate parser based on `format`.
    ///
    /// # Errors
    /// Propagates parser errors.
    pub fn import(
        text: &str,
        format: ImportFormat,
        opts: &ImportOptions,
    ) -> Result<ImportResult, SymbolError> {
        match format {
            ImportFormat::Json => Self::from_json(text, opts),
            // Binary Ninja symbol export uses the same CSV schema.
            ImportFormat::Csv | ImportFormat::BinaryNinja => Self::from_csv(text, opts),
            ImportFormat::IdaIdc => Self::from_idc(text, opts),
            ImportFormat::Map => Self::from_map(text, opts),
            ImportFormat::GhidraExport => Self::from_ghidra_export(text, opts),
            ImportFormat::Radare2Flags => Self::from_radare2_flags(text, opts),
            ImportFormat::Lldb => Self::from_lldb(text, opts),
        }
    }
}

// ── Free function helpers ─────────────────────────────────────────────────────

/// Import symbols from a JSON string with default options.
///
/// # Errors
/// Returns [`SymbolError::Parse`] on malformed JSON.
pub fn import_from_json(text: &str) -> Result<Vec<UnifiedSymbol>, SymbolError> {
    let opts = ImportOptions::default();
    SymbolImporter::from_json(text, &opts).map(|r| r.symbols)
}

/// Import symbols from an IDA IDC script with default options.
///
/// # Errors
/// Returns [`SymbolError::Parse`] on critical parse failures.
pub fn import_from_idc(text: &str) -> Result<Vec<UnifiedSymbol>, SymbolError> {
    let opts = ImportOptions::default();
    SymbolImporter::from_idc(text, &opts).map(|r| r.symbols)
}

/// Import symbols from a MAP file with default options.
///
/// # Errors
/// Returns [`SymbolError::Parse`] on critical parse failures.
pub fn import_from_map(text: &str) -> Result<Vec<UnifiedSymbol>, SymbolError> {
    let opts = ImportOptions::default();
    SymbolImporter::from_map(text, &opts).map(|r| r.symbols)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Parse a hex (`0x...`) or decimal integer string.
fn parse_hex_or_dec(s: &str) -> Option<u64> {
    let s = s.trim();
    let cleaned: String = s.chars().filter(|c| *c != '_').collect();
    let s = cleaned.as_str();
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .map_or_else(|| s.parse::<u64>().ok(), |hex| u64::from_str_radix(hex, 16).ok())
}

/// Parse the `address, "name");` tail of a `MakeName(...)` call.
fn parse_idc_make_name(rest: &str) -> Option<(u64, String)> {
    // rest = `0xADDR, "name");`
    let comma = rest.find(',')?;
    let addr_str = rest[..comma].trim();
    let addr = parse_hex_or_dec(addr_str)?;

    let after_comma = rest[comma + 1..].trim();
    // strip leading quote
    let after_quote = after_comma.strip_prefix('"')?;
    // find closing quote, honoring \" and \\ escapes
    let bytes = after_quote.as_bytes();
    let mut end_quote: Option<usize> = None;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == b'"' {
            end_quote = Some(i);
            break;
        }
        i += 1;
    }
    let end_quote = end_quote?;
    let name = after_quote[..end_quote]
        .replace("\\\"", "\"")
        .replace("\\\\", "\\");
    Some((addr, name))
}

/// Split a single CSV line, respecting double-quoted fields.
fn split_csv_line(line: &str) -> Vec<String> {
    let mut cols = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' if !in_quotes => in_quotes = true,
            '"' if in_quotes => {
                if chars.peek() == Some(&'"') {
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            }
            ',' if !in_quotes => {
                cols.push(current.clone());
                current.clear();
            }
            other => current.push(other),
        }
    }
    cols.push(current);
    cols
}

/// Parse the `address` field from a JSON value object.
fn parse_json_addr(item: &serde_json::Value) -> Option<u64> {
    // Try "address" first (hex string), then "ea", then "addr", then "offset"
    for key in &["address", "ea", "addr", "offset", "start"] {
        if let Some(v) = item.get(key) {
            match v {
                serde_json::Value::Number(n) => {
                    if let Some(u) = n.as_u64() {
                        return Some(u);
                    }
                }
                serde_json::Value::String(s) => {
                    if let Some(result) = parse_hex_or_dec(s) {
                        return Some(result);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// Map a type/kind string to a [`UnifiedSymbolKind`].
fn parse_kind_str(s: &str) -> UnifiedSymbolKind {
    match s.to_ascii_lowercase().as_str() {
        "variable" | "data" | "var" | "global" => UnifiedSymbolKind::Variable,
        "label" | "loc" => UnifiedSymbolKind::Label,
        "thunk" | "trampoline" => UnifiedSymbolKind::Thunk,
        "import" | "imported" => UnifiedSymbolKind::Import,
        "export" | "exported" => UnifiedSymbolKind::Export,
        "section" | "seg" | "segment" => UnifiedSymbolKind::Section,
        "module" | "compilation-unit" => UnifiedSymbolKind::Module,
        "namespace" | "ns" => UnifiedSymbolKind::Namespace,
        // Explicit function aliases ("function" | "func" | "fn" | "sub") and
        // any unknown kind both default to Function.
        _ => UnifiedSymbolKind::Function,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── JSON ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_json_basic() {
        let json = r#"[
            {"address": "0x0040_1000", "name": "main", "kind": "Function"},
            {"address": "0x401200", "name": "helper", "kind": "Function"}
        ]"#;
        let opts = ImportOptions::default();
        let result = SymbolImporter::from_json(json, &opts).unwrap();
        assert_eq!(result.symbol_count(), 2);
        assert_eq!(result.format, ImportFormat::Json);
        assert_eq!(result.symbols[0].name, "main");
        assert_eq!(result.symbols[0].address, 0x0040_1000);
    }

    #[test]
    fn test_json_numeric_address() {
        let json = r#"[{"address": 4198400, "name": "start"}]"#;
        let opts = ImportOptions::default();
        let result = SymbolImporter::from_json(json, &opts).unwrap();
        assert_eq!(result.symbol_count(), 1);
        assert_eq!(result.symbols[0].address, 4_198_400);
    }

    #[test]
    fn test_json_malformed() {
        let json = "not json";
        assert!(SymbolImporter::from_json(json, &ImportOptions::default()).is_err());
    }

    #[test]
    fn test_json_addr_filter() {
        let json = r#"[
            {"address": "0x1000", "name": "low"},
            {"address": "0x5000", "name": "high"}
        ]"#;
        let opts = ImportOptions {
            addr_min: Some(0x2000),
            ..ImportOptions::default()
        };
        let result = SymbolImporter::from_json(json, &opts).unwrap();
        assert_eq!(result.symbol_count(), 1);
        assert_eq!(result.symbols[0].name, "high");
    }

    #[test]
    fn test_json_base_offset() {
        let json = r#"[{"address": "0x1000", "name": "fn"}]"#;
        let opts = ImportOptions {
            base_offset: 0x0040_0000,
            ..ImportOptions::default()
        };
        let result = SymbolImporter::from_json(json, &opts).unwrap();
        assert_eq!(result.symbols[0].address, 0x0040_1000);
    }

    // ── CSV ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_csv_basic() {
        let csv = "address,name,kind\n0x0040_1000,main,Function\n0x401200,helper,Function\n";
        let opts = ImportOptions::default();
        let result = SymbolImporter::from_csv(csv, &opts).unwrap();
        assert_eq!(result.symbol_count(), 2);
        assert_eq!(result.symbols[0].name, "main");
    }

    #[test]
    fn test_csv_missing_header() {
        let csv = "0x1000,foo\n";
        assert!(SymbolImporter::from_csv(csv, &ImportOptions::default()).is_err());
    }

    #[test]
    fn test_csv_skip_names() {
        let csv = "address,name\n0x1000,main\n0x2000,__init\n";
        let opts = ImportOptions {
            skip_names: vec!["__init".into()],
            ..ImportOptions::default()
        };
        let result = SymbolImporter::from_csv(csv, &opts).unwrap();
        assert_eq!(result.symbol_count(), 1);
        assert_eq!(result.skipped, 1);
    }

    // ── IDC ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_idc_basic() {
        let idc = r#"
#include <idc.idc>
static main() {
  MakeName(0x0040_1000, "main");
  MakeName(0x401100, "helper");
}
"#;
        let opts = ImportOptions::default();
        let result = SymbolImporter::from_idc(idc, &opts).unwrap();
        assert_eq!(result.symbol_count(), 2);
        assert_eq!(result.symbols[0].name, "main");
        assert_eq!(result.symbols[0].address, 0x0040_1000);
    }

    #[test]
    fn test_idc_with_escaped_quotes() {
        let idc = "  MakeName(0x1000, \"foo\\\"bar\");\n";
        let result = SymbolImporter::from_idc(idc, &ImportOptions::default()).unwrap();
        assert_eq!(result.symbol_count(), 1);
        assert_eq!(result.symbols[0].name, "foo\"bar");
    }

    // ── MAP ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_map_basic() {
        let map = "# Symbol map\n\
                   0x0000000000401000  main\n\
                   0x0000000000401200  helper\n";
        let opts = ImportOptions::default();
        let result = SymbolImporter::from_map(map, &opts).unwrap();
        assert_eq!(result.symbol_count(), 2);
    }

    #[test]
    fn test_map_empty_lines_skipped() {
        let map = "\n\n0x1000  foo\n\n0x2000  bar\n";
        let result = SymbolImporter::from_map(map, &ImportOptions::default()).unwrap();
        assert_eq!(result.symbol_count(), 2);
    }

    // ── Radare2 ───────────────────────────────────────────────────────────────

    #[test]
    fn test_r2_flags_basic() {
        let r2 = "# flags\nf main 0x10 0x0040_1000\nf helper 0x401200\n";
        let result = SymbolImporter::from_radare2_flags(r2, &ImportOptions::default()).unwrap();
        assert_eq!(result.symbol_count(), 2);
        assert_eq!(result.symbols[0].name, "main");
        assert_eq!(result.symbols[0].size, Some(0x10));
        assert_eq!(result.symbols[0].address, 0x0040_1000);
    }

    // ── LLDB ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_lldb_basic() {
        let lldb = "0x0000000000401000\tmain\n0x0000000000401200\thelper\n";
        let result = SymbolImporter::from_lldb(lldb, &ImportOptions::default()).unwrap();
        assert_eq!(result.symbol_count(), 2);
    }

    // ── Options ───────────────────────────────────────────────────────────────

    #[test]
    fn test_strip_leading_underscore() {
        let json = r#"[{"address":"0x1000","name":"_foo"}]"#;
        let opts = ImportOptions {
            strip_leading_underscore: true,
            ..ImportOptions::default()
        };
        let result = SymbolImporter::from_json(json, &opts).unwrap();
        assert_eq!(result.symbols[0].name, "foo");
    }

    #[test]
    fn test_max_symbols() {
        let json = r#"[
            {"address":"0x1000","name":"a"},
            {"address":"0x2000","name":"b"},
            {"address":"0x3000","name":"c"}
        ]"#;
        let opts = ImportOptions {
            max_symbols: 2,
            ..ImportOptions::default()
        };
        let result = SymbolImporter::from_json(json, &opts).unwrap();
        assert_eq!(result.symbol_count(), 2);
    }

    #[test]
    fn test_import_result_display() {
        let r = ImportResult {
            symbols: Vec::new(),
            parse_errors: 0,
            skipped: 1,
            format: ImportFormat::Json,
        };
        assert!(r.to_string().contains("JSON"));
    }

    #[test]
    fn test_import_result_apply_to_table() {
        let json = r#"[{"address":"0x1000","name":"main"}]"#;
        let result = SymbolImporter::from_json(json, &ImportOptions::default()).unwrap();
        let mut table = UnifiedSymbolTable::new();
        result.apply_to_table(&mut table);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_free_fn_import_from_json() {
        let json = r#"[{"address":"0x5000","name":"test_fn"}]"#;
        let syms = import_from_json(json).unwrap();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "test_fn");
    }

    #[test]
    fn test_free_fn_import_from_idc() {
        let idc = "  MakeName(0x8000, \"my_func\");\n";
        let syms = import_from_idc(idc).unwrap();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].address, 0x8000);
    }

    #[test]
    fn test_free_fn_import_from_map() {
        let map = "0x9000  entry_point\n";
        let syms = import_from_map(map).unwrap();
        assert_eq!(syms.len(), 1);
        assert_eq!(syms[0].name, "entry_point");
    }

    #[test]
    fn test_parse_kind_str() {
        assert_eq!(parse_kind_str("function"), UnifiedSymbolKind::Function);
        assert_eq!(parse_kind_str("DATA"), UnifiedSymbolKind::Variable);
        assert_eq!(parse_kind_str("import"), UnifiedSymbolKind::Import);
        assert_eq!(parse_kind_str("unknown_kind"), UnifiedSymbolKind::Function);
    }

    #[test]
    fn test_parse_hex_or_dec() {
        assert_eq!(parse_hex_or_dec("0x1000"), Some(0x1000));
        assert_eq!(parse_hex_or_dec("4096"), Some(4096));
        assert_eq!(parse_hex_or_dec("0X2000"), Some(0x2000));
        assert_eq!(parse_hex_or_dec("xyz"), None);
    }

    #[test]
    fn test_dispatch() {
        let json = r#"[{"address":"0xABC","name":"fn"}]"#;
        let result = SymbolImporter::import(json, ImportFormat::Json, &ImportOptions::default()).unwrap();
        assert_eq!(result.symbol_count(), 1);
    }
}
