//! `export.rs` — Project export engine for RustRE.
//!
//! Converts project data (functions, comments, symbols, xrefs) to a variety of
//! output formats consumable by other reverse-engineering tools or humans.
//!
//! Supported export formats:
//! - [`ExportFormat::Json`]          — machine-readable JSON
//! - [`ExportFormat::Csv`]           — spreadsheet-friendly CSV
//! - [`ExportFormat::IdaIdc`]        — IDA Pro IDC script (MakeName / MakeComment / MakeCode)
//! - [`ExportFormat::GhidraScript`]  — Ghidra Java import script
//! - [`ExportFormat::BinaryNinjaJson`] — Binary Ninja analysis JSON
//! - [`ExportFormat::HtmlReport`]    — self-contained Bootstrap HTML report
//! - [`ExportFormat::Markdown`]      — GitHub-flavoured Markdown report

use std::fmt::Write as FmtWrite;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{FunctionEntry, Project, ProjectError};

// ── Errors ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ExportError {
    #[error("project error: {0}")]
    Project(#[from] ProjectError),
    #[error("serialization error: {0}")]
    Serialization(#[source] serde_json::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("no binary found: {0}")]
    BinaryNotFound(u64),
    #[error("format error: {0}")]
    Format(String),
}

pub type Result<T> = std::result::Result<T, ExportError>;

// ── ExportFormat ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExportFormat {
    Json,
    Csv,
    IdaIdc,
    GhidraScript,
    BinaryNinjaJson,
    HtmlReport,
    Markdown,
}

impl ExportFormat {
    /// Canonical file extension for this format.
    #[must_use]
    pub fn extension(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Csv => "csv",
            Self::IdaIdc => "idc",
            Self::GhidraScript => "java",
            Self::BinaryNinjaJson => "binja.json",
            Self::HtmlReport => "html",
            Self::Markdown => "md",
        }
    }

    /// Human-readable name.
    #[must_use] 
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Json => "JSON",
            Self::Csv => "CSV",
            Self::IdaIdc => "IDA IDC Script",
            Self::GhidraScript => "Ghidra Import Script",
            Self::BinaryNinjaJson => "Binary Ninja JSON",
            Self::HtmlReport => "HTML Report",
            Self::Markdown => "Markdown Report",
        }
    }

    /// All supported formats.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Json,
            Self::Csv,
            Self::IdaIdc,
            Self::GhidraScript,
            Self::BinaryNinjaJson,
            Self::HtmlReport,
            Self::Markdown,
        ]
    }
}

impl std::fmt::Display for ExportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ── AddressRange ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

impl AddressRange {
    #[must_use] 
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }
    #[must_use] 
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
    #[must_use] 
    pub fn full() -> Self {
        Self {
            start: 0,
            end: u64::MAX,
        }
    }
}

// ── ExportOptions ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportOptions {
    /// Include user and auto-generated comments.
    #[serde(default = "default_true")]
    pub include_comments: bool,
    /// Include type information (structs, enums, typedefs).
    #[serde(default = "default_true")]
    pub include_types: bool,
    /// Include function records.
    #[serde(default = "default_true")]
    pub include_functions: bool,
    /// Include cross-references.
    #[serde(default)]
    pub include_xrefs: bool,
    /// Include string literals.
    #[serde(default = "default_true")]
    pub include_strings: bool,
    /// Include bookmarks.
    #[serde(default = "default_true")]
    pub include_bookmarks: bool,
    /// Include patch records.
    #[serde(default)]
    pub include_patches: bool,
    /// Address range filter; `None` means export everything.
    pub address_range: Option<AddressRange>,
    /// Maximum number of functions to export (0 = unlimited).
    pub max_functions: usize,
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            include_comments: true,
            include_types: true,
            include_functions: true,
            include_xrefs: false,
            include_strings: true,
            include_bookmarks: true,
            include_patches: false,
            address_range: None,
            max_functions: 0,
        }
    }
}

impl ExportOptions {
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }
    #[must_use] 
    pub fn with_xrefs(mut self) -> Self {
        self.include_xrefs = true;
        self
    }
    #[must_use] 
    pub fn with_patches(mut self) -> Self {
        self.include_patches = true;
        self
    }
    #[must_use] 
    pub fn address_range(mut self, range: AddressRange) -> Self {
        self.address_range = Some(range);
        self
    }
    #[must_use] 
    pub fn max_functions(mut self, n: usize) -> Self {
        self.max_functions = n;
        self
    }

    fn filter_functions(&self, functions: Vec<FunctionEntry>) -> Vec<FunctionEntry> {
        let filtered: Vec<FunctionEntry> = functions.into_iter().filter(|f| {
                self.address_range.map_or(true, |range| range.contains(f.addr))
            })
            .collect();
        if self.max_functions > 0 {
            filtered.into_iter().take(self.max_functions).collect()
        } else {
            filtered
        }
    }
}

fn default_true() -> bool {
    true
}

// ── ExportData ────────────────────────────────────────────────────────────────

/// Collected data gathered from the project for export.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportData {
    project_name: String,
    binary_id: u64,
    binary_path: String,
    binary_sha256: String,
    binary_format: String,
    binary_arch: String,
    functions: Vec<FunctionEntry>,
    comments: Vec<ExportComment>,
    strings: Vec<ExportString>,
    bookmarks: Vec<ExportBookmark>,
    symbols: Vec<ExportSymbol>,
    xrefs: Vec<ExportXref>,
    patches: Vec<ExportPatch>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportComment {
    pub address: u64,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportString {
    pub address: u64,
    pub value: String,
    pub encoding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportBookmark {
    pub address: u64,
    pub label: String,
    pub color: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportSymbol {
    pub address: u64,
    pub name: String,
    pub symbol_type: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportXref {
    pub from: u64,
    pub to: u64,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportPatch {
    pub address: u64,
    pub original_hex: String,
    pub patched_hex: String,
    pub description: String,
}

// ── ProjectExporter ───────────────────────────────────────────────────────────

/// The main export entry point: gather data from a [`Project`] and render to a
/// chosen [`ExportFormat`].
pub struct ProjectExporter<'p> {
    project: &'p Project,
    binary_id: u64,
    options: ExportOptions,
}

impl<'p> ProjectExporter<'p> {
    #[must_use] 
    pub fn new(project: &'p Project, binary_id: u64) -> Self {
        Self {
            project,
            binary_id,
            options: ExportOptions::default(),
        }
    }

    #[must_use] 
    pub fn with_options(mut self, options: ExportOptions) -> Self {
        self.options = options;
        self
    }

    /// Gather data from the project.
    fn collect(&self) -> Result<ExportData> {
        let binary = self
            .project
            .list_binaries()
            .into_iter()
            .find(|b| b.id == self.binary_id)
            .ok_or(ExportError::BinaryNotFound(self.binary_id))?;

        let all_functions = self.project.list_functions(self.binary_id);
        let functions = self
            .options
            .filter_functions(all_functions)
            .into_iter()
            .collect();

        let comments = if self.options.include_comments {
            // Collect from DB by querying all addresses with comments
            let db = self.project.db_path();
            if let Ok(conn) = rusqlite::Connection::open(&db) {
                let mut stmt = conn
                    .prepare("SELECT addr,body FROM comments WHERE binary_id=?1 ORDER BY addr")
                    .unwrap_or_else(|_| conn.prepare("SELECT 1,'' WHERE 0").unwrap());
                stmt.query_map(rusqlite::params![self.binary_id as i64], |r| {
                    Ok(ExportComment {
                        address: r.get::<_, i64>(0)? as u64,
                        text: r.get(1)?,
                    })
                })
                .ok()
                .map(|rows| rows.filter_map(std::result::Result::ok).collect())
                .unwrap_or_default()
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        let strings =
            if self.options.include_strings {
                let db = self.project.db_path();
                if let Ok(conn) = rusqlite::Connection::open(&db) {
                    let mut stmt = conn.prepare(
                    "SELECT addr,value,encoding FROM strings WHERE binary_id=?1 ORDER BY addr"
                ).unwrap_or_else(|_| conn.prepare("SELECT 1,'','' WHERE 0").unwrap());
                    stmt.query_map(rusqlite::params![self.binary_id as i64], |r| {
                        Ok(ExportString {
                            address: r.get::<_, i64>(0)? as u64,
                            value: r.get(1)?,
                            encoding: r.get(2)?,
                        })
                    })
                    .ok()
                    .map(|rows| rows.filter_map(std::result::Result::ok).collect())
                    .unwrap_or_default()
                } else {
                    vec![]
                }
            } else {
                vec![]
            };

        let bookmarks = if self.options.include_bookmarks {
            self.project
                .list_bookmarks(self.binary_id)
                .into_iter()
                .map(|(addr, label, color)| ExportBookmark {
                    address: addr,
                    label,
                    color,
                })
                .collect()
        } else {
            vec![]
        };

        let symbols = {
            let db = self.project.db_path();
            if let Ok(conn) = rusqlite::Connection::open(&db) {
                let mut stmt = conn.prepare(
                    "SELECT addr,name,symbol_type,source FROM symbols WHERE binary_id=?1 ORDER BY addr"
                ).unwrap_or_else(|_| conn.prepare("SELECT 1,'','','' WHERE 0").unwrap());
                stmt.query_map(rusqlite::params![self.binary_id as i64], |r| {
                    Ok(ExportSymbol {
                        address: r.get::<_, i64>(0)? as u64,
                        name: r.get(1)?,
                        symbol_type: r.get(2)?,
                        source: r.get(3)?,
                    })
                })
                .ok()
                .map(|rows| rows.filter_map(std::result::Result::ok).collect())
                .unwrap_or_default()
            } else {
                vec![]
            }
        };

        let xrefs = if self.options.include_xrefs {
            let db = self.project.db_path();
            if let Ok(conn) = rusqlite::Connection::open(&db) {
                let mut stmt = conn.prepare(
                    "SELECT from_addr,to_addr,xref_type FROM xrefs WHERE binary_id=?1 ORDER BY from_addr"
                ).unwrap_or_else(|_| conn.prepare("SELECT 1,1,'' WHERE 0").unwrap());
                stmt.query_map(rusqlite::params![self.binary_id as i64], |r| {
                    Ok(ExportXref {
                        from: r.get::<_, i64>(0)? as u64,
                        to: r.get::<_, i64>(1)? as u64,
                        kind: r.get(2)?,
                    })
                })
                .ok()
                .map(|rows| rows.filter_map(std::result::Result::ok).collect())
                .unwrap_or_default()
            } else {
                vec![]
            }
        } else {
            vec![]
        };

        let patches = if self.options.include_patches {
            self.project
                .list_patches(self.binary_id)
                .into_iter()
                .map(|(addr, orig, patched, desc)| ExportPatch {
                    address: addr,
                    original_hex: hex_encode(&orig),
                    patched_hex: hex_encode(&patched),
                    description: desc,
                })
                .collect()
        } else {
            vec![]
        };

        Ok(ExportData {
            project_name: self.project.name().to_string(),
            binary_id: self.binary_id,
            binary_path: binary.path.clone(),
            binary_sha256: binary.sha256.clone(),
            binary_format: binary.format.clone(),
            binary_arch: binary.arch,
            functions,
            comments,
            strings,
            bookmarks,
            symbols,
            xrefs,
            patches,
        })
    }

    /// Export to the given format, returning the rendered content as a `String`.
    pub fn export(&self, format: ExportFormat) -> Result<String> {
        let data = self.collect()?;
        match format {
            ExportFormat::Json => JsonExporter::render(&data),
            ExportFormat::Csv => CsvExporter::render(&data),
            ExportFormat::IdaIdc => IDAIdcExporter::render(&data),
            ExportFormat::GhidraScript => GhidraScriptExporter::render(&data),
            ExportFormat::BinaryNinjaJson => BinaryNinjaJsonExporter::render(&data),
            ExportFormat::HtmlReport => HtmlReportExporter::render(&data),
            ExportFormat::Markdown => MarkdownExporter::render(&data),
        }
    }

    /// Export to a file, inferring the path from `base_name` + format extension.
    pub fn export_to_file(&self, format: ExportFormat, base_name: &str) -> Result<PathBuf> {
        let content = self.export(format)?;
        let mut path_str = String::with_capacity(base_name.len() + 1 + format.extension().len());
        path_str.push_str(base_name);
        path_str.push('.');
        path_str.push_str(format.extension());
        let path = PathBuf::from(path_str);
        std::fs::write(&path, &content)?;
        Ok(path)
    }

    /// Export to an explicit file path.
    pub fn export_to_path(&self, format: ExportFormat, path: impl AsRef<Path>) -> Result<()> {
        let content = self.export(format)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

// ── JsonExporter ──────────────────────────────────────────────────────────────

struct JsonExporter;
impl JsonExporter {
    fn render(data: &ExportData) -> Result<String> {
        serde_json::to_string_pretty(data).map_err(ExportError::Serialization)
    }
}

// ── CsvExporter ───────────────────────────────────────────────────────────────

struct CsvExporter;
impl CsvExporter {
    fn render(data: &ExportData) -> Result<String> {
        // Rough heuristic: average ~80 bytes per row across sections.
        let est = 128
            + data.functions.len() * 96
            + data.comments.len() * 64
            + data.strings.len() * 80;
        let mut out = String::with_capacity(est);
        // Functions sheet
        writeln!(out, "# Functions").unwrap();
        writeln!(out, "address,name,size,is_thunk,calling_conv,return_type").unwrap();
        for f in &data.functions {
            writeln!(
                out,
                "{:#x},{},{},{},{},{}",
                f.addr,
                csv_escape(&f.name),
                f.size_bytes.map_or("?".into(), |s| s.to_string()),
                f.is_thunk,
                f.calling_conv.as_deref().unwrap_or(""),
                f.return_type.as_deref().unwrap_or(""),
            )
            .unwrap();
        }
        // Comments sheet
        if !data.comments.is_empty() {
            writeln!(out).unwrap();
            writeln!(out, "# Comments").unwrap();
            writeln!(out, "address,text").unwrap();
            for c in &data.comments {
                writeln!(out, "{:#x},{}", c.address, csv_escape(&c.text)).unwrap();
            }
        }
        // Strings sheet
        if !data.strings.is_empty() {
            writeln!(out).unwrap();
            writeln!(out, "# Strings").unwrap();
            writeln!(out, "address,encoding,value").unwrap();
            for s in &data.strings {
                writeln!(
                    out,
                    "{:#x},{},{}",
                    s.address,
                    s.encoding,
                    csv_escape(&s.value)
                )
                .unwrap();
            }
        }
        Ok(out)
    }
}

fn csv_escape(s: &str) -> std::borrow::Cow<'_, str> {
    if s.bytes().any(|b| b == b',' || b == b'"' || b == b'\n') {
        std::borrow::Cow::Owned(format!("\"{}\"", s.replace('"', "\"\"")))
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

// ── IDAIdcExporter ────────────────────────────────────────────────────────────

/// Generates an IDA Pro IDC script with `MakeName`, `MakeCode`, `MakeComment`,
/// and `SetType` calls.
pub struct IDAIdcExporter;
impl IDAIdcExporter {
    pub fn render(data: &ExportData) -> Result<String> {
        // Rough estimate: header ~200 bytes + ~120 bytes per function + ~80 per comment/symbol
        let est = 200
            + data.functions.len() * 120
            + data.comments.len() * 80
            + data.symbols.len() * 60
            + data.bookmarks.len() * 60;
        let mut out = String::with_capacity(est);
        writeln!(out, "#include <idc.idc>").unwrap();
        writeln!(out, "// Generated by RustRE export engine").unwrap();
        writeln!(
            out,
            "// Binary: {} ({})",
            data.binary_path, data.binary_format
        )
        .unwrap();
        writeln!(out, "// SHA-256: {}", data.binary_sha256).unwrap();
        writeln!(out, "static main() {{").unwrap();
        writeln!(out, "  auto ea;").unwrap();
        writeln!(out).unwrap();

        // Functions
        if !data.functions.is_empty() {
            writeln!(
                out,
                "  // ── Functions ──────────────────────────────────────────"
            )
            .unwrap();
            for f in &data.functions {
                let safe_name = idc_escape_str(&f.name);
                writeln!(out, "  MakeName({:#x}, \"{safe_name}\");", f.addr).unwrap();
                writeln!(out, "  MakeCode({:#x});", f.addr).unwrap();
                if let Some(rt) = &f.return_type {
                    writeln!(out, "  SetType({:#x}, \"{rt} {safe_name}()\");", f.addr).unwrap();
                }
            }
            writeln!(out).unwrap();
        }

        // Symbols
        if !data.symbols.is_empty() {
            writeln!(
                out,
                "  // ── Symbols ────────────────────────────────────────────"
            )
            .unwrap();
            for s in &data.symbols {
                if !data.functions.iter().any(|f| f.addr == s.address) {
                    writeln!(
                        out,
                        "  MakeName({:#x}, \"{}\");",
                        s.address,
                        idc_escape_str(&s.name)
                    )
                    .unwrap();
                }
            }
            writeln!(out).unwrap();
        }

        // Comments
        if !data.comments.is_empty() {
            writeln!(
                out,
                "  // ── Comments ───────────────────────────────────────────"
            )
            .unwrap();
            for c in &data.comments {
                writeln!(
                    out,
                    "  MakeComment({:#x}, \"{}\");",
                    c.address,
                    idc_escape_str(&c.text)
                )
                .unwrap();
            }
            writeln!(out).unwrap();
        }

        // Bookmarks as comments
        if !data.bookmarks.is_empty() {
            writeln!(
                out,
                "  // ── Bookmarks ──────────────────────────────────────────"
            )
            .unwrap();
            for b in &data.bookmarks {
                writeln!(
                    out,
                    "  MakeComment({:#x}, \"[BM] {}\");",
                    b.address,
                    idc_escape_str(&b.label)
                )
                .unwrap();
            }
            writeln!(out).unwrap();
        }

        writeln!(
            out,
            "  Message(\"RustRE import complete: {} functions.\\n\");",
            data.functions.len()
        )
        .unwrap();
        writeln!(out, "}}").unwrap();
        Ok(out)
    }
}

fn idc_escape_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            // Replace embedded double-quotes with two single-quotes so the
            // escaped string never contains a raw `"` character (the IDC
            // generator wraps values in double-quotes).
            '"' => out.push_str("''"),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

// ── GhidraScriptExporter ──────────────────────────────────────────────────────

/// Generates a Ghidra Java import script (runs via Script Manager → Run Script).
pub struct GhidraScriptExporter;
impl GhidraScriptExporter {
    pub fn render(data: &ExportData) -> Result<String> {
        // Rough estimate: header ~400 bytes + ~180 bytes per function + ~100 per comment
        let est = 400 + data.functions.len() * 180 + data.comments.len() * 100;
        let mut out = String::with_capacity(est);
        writeln!(out, "// Generated by RustRE export engine").unwrap();
        writeln!(
            out,
            "// Binary: {} | SHA-256: {}",
            data.binary_path, data.binary_sha256
        )
        .unwrap();
        writeln!(out, "// @category RustRE").unwrap();
        writeln!(out, "import ghidra.app.script.GhidraScript;").unwrap();
        writeln!(out, "import ghidra.program.model.address.*;").unwrap();
        writeln!(out, "import ghidra.program.model.symbol.*;").unwrap();
        writeln!(out, "import ghidra.program.model.listing.*;").unwrap();
        writeln!(out).unwrap();
        writeln!(out, "public class RustREImport extends GhidraScript {{").unwrap();
        writeln!(out, "  @Override public void run() throws Exception {{").unwrap();
        writeln!(
            out,
            "    SymbolTable symTable = currentProgram.getSymbolTable();"
        )
        .unwrap();
        writeln!(out, "    Listing listing = currentProgram.getListing();").unwrap();
        writeln!(
            out,
            "    AddressFactory addrFactory = currentProgram.getAddressFactory();"
        )
        .unwrap();
        writeln!(out).unwrap();
        writeln!(
            out,
            "    // ── Functions ──────────────────────────────────────────────────────────────"
        )
        .unwrap();
        for f in &data.functions {
            let safe_name = java_escape(&f.name);
            writeln!(
                out,
                "    {{ Address a = addrFactory.getAddress(\"{:#x}\");",
                f.addr
            )
            .unwrap();
            writeln!(
                out,
                "      symTable.createLabel(a, \"{safe_name}\", SourceType.IMPORTED);"
            )
            .unwrap();
            writeln!(
                out,
                "      listing.createFunction(\"{safe_name}\", a, null, SourceType.IMPORTED); }}"
            )
            .unwrap();
        }
        writeln!(out).unwrap();
        writeln!(
            out,
            "    // ── Comments ───────────────────────────────────────────────────────────────"
        )
        .unwrap();
        for c in &data.comments {
            writeln!(
                out,
                "    {{ CodeUnit cu = listing.getCodeUnitAt(addrFactory.getAddress(\"{:#x}\"));",
                c.address
            )
            .unwrap();
            writeln!(
                out,
                "      if (cu != null) cu.setComment(CodeUnit.PLATE_COMMENT, \"{}\"); }}",
                java_escape(&c.text)
            )
            .unwrap();
        }
        writeln!(out).unwrap();
        writeln!(
            out,
            "    println(\"RustRE import complete: {} functions.\");",
            data.functions.len()
        )
        .unwrap();
        writeln!(out, "  }}").unwrap();
        writeln!(out, "}}").unwrap();
        Ok(out)
    }
}

fn java_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

// ── BinaryNinjaJsonExporter ───────────────────────────────────────────────────

pub struct BinaryNinjaJsonExporter;
impl BinaryNinjaJsonExporter {
    pub fn render(data: &ExportData) -> Result<String> {
        #[derive(Serialize)]
        struct BnFunc<'a> {
            address: u64,
            name: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            size: Option<i64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            calling_convention: Option<&'a str>,
        }
        #[derive(Serialize)]
        struct BnComment<'a> {
            address: u64,
            text: &'a str,
        }
        #[derive(Serialize)]
        struct BnExport<'a> {
            schema: &'static str,
            binary: &'a str,
            sha256: &'a str,
            functions: Vec<BnFunc<'a>>,
            comments: Vec<BnComment<'a>>,
        }
        let export = BnExport {
            schema: "rustre-binja-v1",
            binary: &data.binary_path,
            sha256: &data.binary_sha256,
            functions: data
                .functions
                .iter()
                .map(|f| BnFunc {
                    address: f.addr,
                    name: &f.name,
                    size: f.size_bytes,
                    calling_convention: f.calling_conv.as_deref(),
                })
                .collect(),
            comments: data
                .comments
                .iter()
                .map(|c| BnComment {
                    address: c.address,
                    text: &c.text,
                })
                .collect(),
        };
        serde_json::to_string_pretty(&export).map_err(ExportError::Serialization)
    }
}

// ── HtmlReportExporter ────────────────────────────────────────────────────────

/// Generates a self-contained Bootstrap 5 HTML report.
pub struct HtmlReportExporter;
impl HtmlReportExporter {
    pub fn render(data: &ExportData) -> Result<String> {
        // Rough estimate: boilerplate ~2KB + ~200 bytes per function/string/comment
        let est = 2048
            + data.functions.len() * 200
            + data.strings.len().min(500) * 160
            + data.comments.len() * 120;
        let mut out = String::with_capacity(est);
        writeln!(out, "<!DOCTYPE html>").unwrap();
        writeln!(out, "<html lang=\"en\">").unwrap();
        writeln!(out, "<head><meta charset=\"UTF-8\">").unwrap();
        writeln!(
            out,
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        )
        .unwrap();
        writeln!(
            out,
            "<title>RustRE — {}</title>",
            html_escape(&data.project_name)
        )
        .unwrap();
        // Inline Bootstrap 5 CDN
        writeln!(out, "<link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css\" rel=\"stylesheet\">").unwrap();
        writeln!(out, "<style>").unwrap();
        writeln!(
            out,
            "body {{ font-family: 'Consolas', monospace; background: #1a1a2e; color: #e0e0e0; }}"
        )
        .unwrap();
        writeln!(
            out,
            ".card {{ background: #16213e; border: 1px solid #0f3460; }}"
        )
        .unwrap();
        writeln!(
            out,
            ".badge-fn {{ background-color: #0f3460; }} .badge-sym {{ background-color: #533483; }}"
        )
        .unwrap();
        writeln!(
            out,
            "th {{ color: #a8dadc; }} td code {{ color: #e07a5f; }}"
        )
        .unwrap();
        writeln!(out, "</style>").unwrap();
        writeln!(out, "</head><body>").unwrap();
        writeln!(out, "<div class=\"container-fluid py-3\">").unwrap();

        // Header
        writeln!(out, "<div class=\"card mb-3 p-3\">").unwrap();
        writeln!(out, "<h2 class=\"mb-1\">RustRE Analysis Report</h2>").unwrap();
        writeln!(
            out,
            "<p class=\"mb-0 text-muted\">Project: <strong>{}</strong></p>",
            html_escape(&data.project_name)
        )
        .unwrap();
        writeln!(
            out,
            "<p class=\"mb-0 text-muted\">Binary: <code>{}</code></p>",
            html_escape(&data.binary_path)
        )
        .unwrap();
        writeln!(
            out,
            "<p class=\"mb-0 text-muted\">Format: {} | Arch: {} | SHA-256: <code>{}</code></p>",
            html_escape(&data.binary_format),
            html_escape(&data.binary_arch),
            html_escape(&data.binary_sha256)
        )
        .unwrap();
        writeln!(
            out,
            "<p class=\"mb-0 text-muted\">Functions: {} | Strings: {} | Comments: {}</p>",
            data.functions.len(),
            data.strings.len(),
            data.comments.len()
        )
        .unwrap();
        writeln!(out, "</div>").unwrap();

        // Functions table
        if !data.functions.is_empty() {
            writeln!(out, "<div class=\"card mb-3 p-3\">").unwrap();
            writeln!(out, "<h4>Functions ({})</h4>", data.functions.len()).unwrap();
            writeln!(out, "<div class=\"table-responsive\"><table class=\"table table-sm table-dark table-hover\">").unwrap();
            writeln!(out, "<thead><tr><th>Address</th><th>Name</th><th>Size</th><th>Thunk</th><th>Calling Conv</th><th>Return Type</th></tr></thead>").unwrap();
            writeln!(out, "<tbody>").unwrap();
            for f in &data.functions {
                writeln!(out, "<tr><td><code>{:#010x}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    f.addr, html_escape(&f.name),
                    f.size_bytes.map_or("-".into(), |s| s.to_string()),
                    if f.is_thunk { "✓" } else { "" },
                    f.calling_conv.as_deref().unwrap_or("-"),
                    f.return_type.as_deref().unwrap_or("-"),
                ).unwrap();
            }
            writeln!(out, "</tbody></table></div></div>").unwrap();
        }

        // Strings table
        if !data.strings.is_empty() {
            writeln!(out, "<div class=\"card mb-3 p-3\">").unwrap();
            writeln!(out, "<h4>Strings ({})</h4>", data.strings.len()).unwrap();
            writeln!(out, "<div class=\"table-responsive\"><table class=\"table table-sm table-dark table-hover\">").unwrap();
            writeln!(
                out,
                "<thead><tr><th>Address</th><th>Encoding</th><th>Value</th></tr></thead><tbody>"
            )
            .unwrap();
            for s in data.strings.iter().take(500) {
                writeln!(
                    out,
                    "<tr><td><code>{:#010x}</code></td><td>{}</td><td><code>{}</code></td></tr>",
                    s.address,
                    html_escape(&s.encoding),
                    html_escape(&s.value)
                )
                .unwrap();
            }
            if data.strings.len() > 500 {
                writeln!(
                    out,
                    "<tr><td colspan=\"3\" class=\"text-muted\">… {} more strings …</td></tr>",
                    data.strings.len() - 500
                )
                .unwrap();
            }
            writeln!(out, "</tbody></table></div></div>").unwrap();
        }

        // Comments table
        if !data.comments.is_empty() {
            writeln!(out, "<div class=\"card mb-3 p-3\">").unwrap();
            writeln!(out, "<h4>Comments ({})</h4>", data.comments.len()).unwrap();
            writeln!(
                out,
                "<div class=\"table-responsive\"><table class=\"table table-sm table-dark\">"
            )
            .unwrap();
            writeln!(
                out,
                "<thead><tr><th>Address</th><th>Comment</th></tr></thead><tbody>"
            )
            .unwrap();
            for c in &data.comments {
                writeln!(
                    out,
                    "<tr><td><code>{:#010x}</code></td><td>{}</td></tr>",
                    c.address,
                    html_escape(&c.text)
                )
                .unwrap();
            }
            writeln!(out, "</tbody></table></div></div>").unwrap();
        }

        writeln!(out, "</div>").unwrap(); // container
        writeln!(out, "<script src=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js\"></script>").unwrap();
        writeln!(out, "</body></html>").unwrap();
        Ok(out)
    }
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out
}

// ── MarkdownExporter ──────────────────────────────────────────────────────────

pub struct MarkdownExporter;
impl MarkdownExporter {
    pub fn render(data: &ExportData) -> Result<String> {
        // Rough estimate: header ~300 bytes + ~100 bytes per function/comment/string
        let est = 300
            + data.functions.len() * 100
            + data.comments.len() * 80
            + data.strings.len().min(100) * 80;
        let mut out = String::with_capacity(est);
        writeln!(out, "# RustRE Analysis Report — {}", data.project_name).unwrap();
        writeln!(out).unwrap();
        writeln!(out, "| Field | Value |").unwrap();
        writeln!(out, "|-------|-------|").unwrap();
        writeln!(out, "| Binary | `{}` |", data.binary_path).unwrap();
        writeln!(out, "| Format | {} |", data.binary_format).unwrap();
        writeln!(out, "| Arch | {} |", data.binary_arch).unwrap();
        writeln!(out, "| SHA-256 | `{}` |", data.binary_sha256).unwrap();
        writeln!(out, "| Functions | {} |", data.functions.len()).unwrap();
        writeln!(out, "| Strings | {} |", data.strings.len()).unwrap();
        writeln!(out, "| Comments | {} |", data.comments.len()).unwrap();
        writeln!(out).unwrap();

        if !data.functions.is_empty() {
            writeln!(out, "## Functions").unwrap();
            writeln!(out).unwrap();
            writeln!(out, "| Address | Name | Size | Thunk | Calling Conv |").unwrap();
            writeln!(out, "|---------|------|------|-------|--------------|").unwrap();
            for f in &data.functions {
                writeln!(
                    out,
                    "| `{:#010x}` | `{}` | {} | {} | {} |",
                    f.addr,
                    f.name,
                    f.size_bytes.map_or("-".into(), |s| s.to_string()),
                    if f.is_thunk { "yes" } else { "no" },
                    f.calling_conv.as_deref().unwrap_or("-"),
                )
                .unwrap();
            }
            writeln!(out).unwrap();
        }

        if !data.comments.is_empty() {
            writeln!(out, "## Comments").unwrap();
            writeln!(out).unwrap();
            writeln!(out, "| Address | Comment |").unwrap();
            writeln!(out, "|---------|---------|").unwrap();
            for c in &data.comments {
                writeln!(
                    out,
                    "| `{:#010x}` | {} |",
                    c.address,
                    c.text.replace('|', "\\|")
                )
                .unwrap();
            }
            writeln!(out).unwrap();
        }

        if !data.strings.is_empty() {
            writeln!(out, "## Strings (first 100)").unwrap();
            writeln!(out).unwrap();
            writeln!(out, "| Address | Value |").unwrap();
            writeln!(out, "|---------|-------|").unwrap();
            for s in data.strings.iter().take(100) {
                writeln!(
                    out,
                    "| `{:#010x}` | `{}` |",
                    s.address,
                    s.value.replace('`', "\\`").replace('|', "\\|")
                )
                .unwrap();
            }
            writeln!(out).unwrap();
        }

        Ok(out)
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut acc = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(acc, "{b:02x}");
    }
    acc
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn tmp() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn make_project(dir: &TempDir) -> (Project, u64) {
        let p = Project::new("export-test", dir.path()).unwrap();
        let bin = dir.path().join("test.elf");
        fs::write(&bin, b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00\x01\x00\x00\x00").unwrap();
        let entry = p.add_binary_from_path(&bin).unwrap();
        let bid = entry.id;
        p.add_function_record(bid, 0x1000, "main").unwrap();
        p.add_function_record(bid, 0x2000, "init_proc").unwrap();
        p.add_comment_record(bid, 0x1000, "entry point").unwrap();
        p.add_string(bid, 0x3000, "Hello, World!", "utf8").unwrap();
        p.add_symbol(bid, 0x1000, "main", "function", "export")
            .unwrap();
        p.add_bookmark(bid, 0x1000, "entry", "#ff0000").unwrap();
        (p, bid)
    }

    // ── ExportFormat ──────────────────────────────────────────────────────────

    #[test]
    fn format_extensions() {
        assert_eq!(ExportFormat::Json.extension(), "json");
        assert_eq!(ExportFormat::IdaIdc.extension(), "idc");
        assert_eq!(ExportFormat::GhidraScript.extension(), "java");
        assert_eq!(ExportFormat::HtmlReport.extension(), "html");
        assert_eq!(ExportFormat::Markdown.extension(), "md");
    }
    #[test]
    fn format_all_count() {
        assert_eq!(ExportFormat::all().len(), 7);
    }
    #[test]
    fn format_display() {
        assert!(ExportFormat::Json.to_string().contains("JSON"));
    }

    // ── AddressRange ──────────────────────────────────────────────────────────

    #[test]
    fn addr_range_contains() {
        let r = AddressRange::new(0x1000, 0x2000);
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1fff));
        assert!(!r.contains(0x2000));
    }
    #[test]
    fn addr_range_full() {
        let r = AddressRange::full();
        assert!(r.contains(0));
        assert!(r.contains(u64::MAX - 1));
    }

    // ── ExportOptions ─────────────────────────────────────────────────────────

    #[test]
    fn options_defaults() {
        let o = ExportOptions::default();
        assert!(o.include_functions);
        assert!(o.include_comments);
        assert!(!o.include_xrefs);
    }
    #[test]
    fn options_builders() {
        let o = ExportOptions::new()
            .with_xrefs()
            .with_patches()
            .max_functions(10);
        assert!(o.include_xrefs);
        assert!(o.include_patches);
        assert_eq!(o.max_functions, 10);
    }
    #[test]
    fn options_filter_max() {
        let funcs: Vec<FunctionEntry> = (0..20u64)
            .map(|i| FunctionEntry {
                id: i,
                binary_id: 1,
                addr: i * 0x100,
                name: format!("f{i}"),
                size_bytes: None,
                is_thunk: false,
                calling_conv: None,
                return_type: None,
                flags: 0,
                created_at: 0,
                updated_at: 0,
            })
            .collect();
        let opts = ExportOptions::new().max_functions(5);
        assert_eq!(opts.filter_functions(funcs).len(), 5);
    }

    // ── Collect / export ──────────────────────────────────────────────────────

    #[test]
    fn json_export() {
        let d = tmp();
        let (p, bid) = make_project(&d);
        let exp = ProjectExporter::new(&p, bid);
        let json = exp.export(ExportFormat::Json).unwrap();
        assert!(json.contains("main"));
        assert!(json.contains("Hello, World!"));
    }
    #[test]
    fn csv_export() {
        let d = tmp();
        let (p, bid) = make_project(&d);
        let csv = ProjectExporter::new(&p, bid)
            .export(ExportFormat::Csv)
            .unwrap();
        assert!(csv.contains("main"));
        assert!(csv.contains("address"));
    }
    #[test]
    fn idc_export() {
        let d = tmp();
        let (p, bid) = make_project(&d);
        let idc = ProjectExporter::new(&p, bid)
            .export(ExportFormat::IdaIdc)
            .unwrap();
        assert!(idc.contains("MakeName"));
        assert!(idc.contains("main"));
        assert!(idc.contains("MakeCode"));
    }
    #[test]
    fn idc_escape_quotes() {
        let s = idc_escape_str("he said \"hi\"");
        assert!(!s.contains('"'));
    }
    #[test]
    fn ghidra_export() {
        let d = tmp();
        let (p, bid) = make_project(&d);
        let java = ProjectExporter::new(&p, bid)
            .export(ExportFormat::GhidraScript)
            .unwrap();
        assert!(java.contains("createFunction"));
        assert!(java.contains("main"));
    }
    #[test]
    fn binja_export() {
        let d = tmp();
        let (p, bid) = make_project(&d);
        let j = ProjectExporter::new(&p, bid)
            .export(ExportFormat::BinaryNinjaJson)
            .unwrap();
        assert!(j.contains("rustre-binja-v1"));
        assert!(j.contains("main"));
    }
    #[test]
    fn html_export() {
        let d = tmp();
        let (p, bid) = make_project(&d);
        let html = ProjectExporter::new(&p, bid)
            .export(ExportFormat::HtmlReport)
            .unwrap();
        assert!(html.contains("bootstrap"));
        assert!(html.contains("main"));
        assert!(html.contains("<!DOCTYPE html>"));
    }
    #[test]
    fn markdown_export() {
        let d = tmp();
        let (p, bid) = make_project(&d);
        let md = ProjectExporter::new(&p, bid)
            .export(ExportFormat::Markdown)
            .unwrap();
        assert!(md.contains("# RustRE"));
        assert!(md.contains("main"));
        assert!(md.contains('|'));
    }
    #[test]
    fn export_to_file() {
        let d = tmp();
        let (p, bid) = make_project(&d);
        let base = d.path().join("out").to_string_lossy().into_owned();
        let path = ProjectExporter::new(&p, bid)
            .export_to_file(ExportFormat::Json, &base)
            .unwrap();
        assert!(path.exists());
    }
    #[test]
    fn export_to_path() {
        let d = tmp();
        let (p, bid) = make_project(&d);
        let path = d.path().join("report.md");
        ProjectExporter::new(&p, bid)
            .export_to_path(ExportFormat::Markdown, &path)
            .unwrap();
        assert!(path.exists());
    }
    #[test]
    fn export_missing_binary_err() {
        let d = tmp();
        let p = Project::new("empty", d.path()).unwrap();
        let err = ProjectExporter::new(&p, 9999).export(ExportFormat::Json);
        assert!(matches!(err, Err(ExportError::BinaryNotFound(9999))));
    }

    // ── Address range filter ──────────────────────────────────────────────────

    #[test]
    fn export_address_range_filter() {
        let d = tmp();
        let (p, bid) = make_project(&d);
        let opts = ExportOptions::new().address_range(AddressRange::new(0x1000, 0x2000));
        let json = ProjectExporter::new(&p, bid)
            .with_options(opts)
            .export(ExportFormat::Json)
            .unwrap();
        // 0x2000 should not be in the functions array
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let fns = v["functions"].as_array().unwrap();
        assert!(fns.iter().all(|f| f["addr"].as_u64().unwrap() < 0x2000));
    }

    // ── csv_escape ────────────────────────────────────────────────────────────

    #[test]
    fn csv_escape_plain() {
        assert_eq!(csv_escape("hello"), "hello");
    }
    #[test]
    fn csv_escape_comma() {
        assert!(csv_escape("a,b").starts_with('"'));
    }
    #[test]
    fn csv_escape_quote() {
        assert!(csv_escape("say \"hi\"").contains("\"\""));
    }

    // ── html_escape ───────────────────────────────────────────────────────────

    #[test]
    fn html_escape_test() {
        let s = html_escape("<script>alert('xss')</script>");
        assert!(!s.contains('<'));
        assert!(s.contains("&lt;"));
    }
}
