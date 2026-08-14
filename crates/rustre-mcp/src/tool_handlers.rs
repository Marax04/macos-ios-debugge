//! Built-in RustRE MCP tool handler implementations.
//!
//! Each handler is a free function matching the signature
//! `fn(serde_json::Value) -> Result<serde_json::Value, HandlerError>`.
//!
//! Handlers provided:
//! * [`handle_analyze_binary`]   — PE/ELF metadata analysis.
//! * [`handle_decompile_function`] — pseudo-C decompilation stub.
//! * [`handle_get_xrefs`]        — cross-reference lookup.
//! * [`handle_search_symbol`]    — symbol name search.
//! * [`handle_add_comment`]      — annotate an address.
//! * [`handle_run_yara`]         — run a YARA rule set against a binary.
//! * [`handle_get_strings`]      — extract printable strings.
//! * [`handle_get_imports`]      — list imports.
//! * [`handle_get_exports`]      — list exports.
//!
//! All handlers validate their required parameters and return structured JSON.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

// ─── HandlerError ─────────────────────────────────────────────────────────────

/// Errors produced by individual tool handlers.
#[derive(Debug, Error)]
pub enum HandlerError {
    /// Required parameter is missing from the request.
    #[error("missing required parameter: {0}")]
    MissingParam(String),
    /// Parameter has an unexpected type.
    #[error("wrong type for parameter '{param}': expected {expected}, got {actual}")]
    WrongParamType {
        /// Parameter name.
        param: String,
        /// Expected JSON type.
        expected: String,
        /// Actual JSON type.
        actual: String,
    },
    /// Parameter value is invalid (e.g. out of range).
    #[error("invalid parameter value for '{0}': {1}")]
    InvalidParamValue(String, String),
    /// The requested binary is not loaded.
    #[error("binary '{0}' not found")]
    BinaryNotFound(String),
    /// The requested address is outside the binary's address space.
    #[error("address {0:#x} out of range")]
    AddressOutOfRange(u64),
    /// YARA rule compilation error.
    #[error("yara rule error: {0}")]
    YaraError(String),
    /// Internal handler error.
    #[error("internal error: {0}")]
    Internal(String),
}

impl HandlerError {
    /// Construct a missing-param error.
    #[must_use]
    pub fn missing(param: impl Into<String>) -> Self {
        Self::MissingParam(param.into())
    }

    /// Construct a wrong-type error.
    #[must_use]
    pub fn wrong_type(param: impl Into<String>, expected: &str, actual: &str) -> Self {
        Self::WrongParamType {
            param: param.into(),
            expected: expected.to_string(),
            actual: actual.to_string(),
        }
    }

    /// Return `true` if this is a missing-param error.
    #[must_use]
    pub fn is_missing(&self) -> bool {
        matches!(self, Self::MissingParam(_))
    }
}

// ─── Param extraction helpers ─────────────────────────────────────────────────

fn require_str<'a>(params: &'a Value, key: &str) -> Result<&'a str, HandlerError> {
    params[key].as_str().ok_or_else(|| {
        if params[key].is_null() {
            HandlerError::missing(key)
        } else {
            HandlerError::wrong_type(key, "string", json_type(&params[key]))
        }
    })
}

fn optional_str<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params[key].as_str()
}

fn require_u64(params: &Value, key: &str) -> Result<u64, HandlerError> {
    params[key].as_u64().ok_or_else(|| {
        if params[key].is_null() {
            HandlerError::missing(key)
        } else {
            HandlerError::wrong_type(key, "integer", json_type(&params[key]))
        }
    })
}

fn optional_u64(params: &Value, key: &str) -> Option<u64> {
    params[key].as_u64()
}

fn optional_bool(params: &Value, key: &str) -> Option<bool> {
    params[key].as_bool()
}

fn json_type(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ─── AnalyzeBinaryResult ──────────────────────────────────────────────────────

/// Structured result from `analyze_binary`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeBinaryResult {
    /// Binary identifier.
    pub binary_id: String,
    /// Detected file format.
    pub format: String,
    /// Architecture string.
    pub architecture: String,
    /// Whether the binary is 64-bit.
    pub is_64bit: bool,
    /// Whether the binary is a DLL.
    pub is_dll: bool,
    /// Entry point address.
    pub entry_point: u64,
    /// Section count.
    pub section_count: usize,
    /// Import count.
    pub import_count: usize,
    /// Export count.
    pub export_count: usize,
    /// ASLR enabled.
    pub aslr: bool,
    /// DEP/NX enabled.
    pub nx: bool,
    /// CFG enabled.
    pub cfg: bool,
    /// Whether it appears packed (any section entropy > 7.0).
    pub likely_packed: bool,
    /// Maximum section entropy.
    pub max_entropy: f64,
    /// Whether an overlay (data after sections) was detected.
    pub has_overlay: bool,
}

impl fmt::Display for AnalyzeBinaryResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} ep={:#x} sections={}",
            self.binary_id, self.format, self.architecture, self.entry_point, self.section_count
        )
    }
}

// ─── handle_analyze_binary ────────────────────────────────────────────────────

/// Handler for `analyze_binary`.
///
/// Expected parameters:
/// * `binary_id` (string, required) — identifier of the loaded binary.
/// * `deep` (boolean, optional, default false) — whether to run deep analysis.
///
/// Returns a stub [`AnalyzeBinaryResult`] populated from the `binary_id`.
///
/// # Errors
///
/// Returns [`HandlerError::MissingParam`] if `binary_id` is absent.
pub fn handle_analyze_binary(params: Value) -> Result<Value, HandlerError> {
    let binary_id = require_str(&params, "binary_id")?;
    let deep = optional_bool(&params, "deep").unwrap_or(false);

    // Stub: in production, look up the binary from the project.
    let result = AnalyzeBinaryResult {
        binary_id: binary_id.to_string(),
        format: "PE".to_string(),
        architecture: if binary_id.contains("64") {
            "x86_64"
        } else {
            "x86"
        }
        .to_string(),
        is_64bit: binary_id.contains("64"),
        is_dll: std::path::Path::new(binary_id).extension().is_some_and(|e| e.eq_ignore_ascii_case("dll")),
        entry_point: 0x1400_1000,
        section_count: 5,
        import_count: 42,
        export_count: if std::path::Path::new(binary_id).extension().is_some_and(|e| e.eq_ignore_ascii_case("dll")) { 12 } else { 0 },
        aslr: true,
        nx: true,
        cfg: true,
        likely_packed: false,
        max_entropy: 5.2,
        has_overlay: false,
    };

    Ok(serde_json::json!({
        "binary_id": result.binary_id,
        "format": result.format,
        "architecture": result.architecture,
        "is_64bit": result.is_64bit,
        "is_dll": result.is_dll,
        "entry_point": result.entry_point,
        "section_count": result.section_count,
        "import_count": result.import_count,
        "export_count": result.export_count,
        "security": {
            "aslr": result.aslr,
            "nx": result.nx,
            "cfg": result.cfg,
        },
        "likely_packed": result.likely_packed,
        "max_entropy": result.max_entropy,
        "has_overlay": result.has_overlay,
        "deep": deep,
    }))
}

// ─── handle_decompile_function ────────────────────────────────────────────────

/// Handler for `decompile_function`.
///
/// Expected parameters:
/// * `binary_id` (string, required)
/// * `address` (integer, required) — function entry-point RVA.
/// * `language` (string, optional) — target pseudo-language ("c", "c++").
///
/// # Errors
///
/// Returns [`HandlerError`] if required params are missing.
pub fn handle_decompile_function(params: Value) -> Result<Value, HandlerError> {
    let binary_id = require_str(&params, "binary_id")?;
    let address = require_u64(&params, "address")?;
    let language = optional_str(&params, "language").unwrap_or("c");

    // `binary_id` is the binary path in this crate's convention.
    //
    // A file we cannot read is an honest failure, not a result. Checking it here
    // buys a PRECISE error: `decompile` below now returns its own failure (it
    // used to answer an unloadable binary with a manufactured `void sub_X()`
    // body and invented disassembly), but it cannot tell "no such file" from
    // "address not in any function". One `is_file` syscall keeps that
    // distinction for the caller.
    if !std::path::Path::new(binary_id).is_file() {
        return Err(HandlerError::BinaryNotFound(binary_id.to_string()));
    }

    let req =
        rustre_mcp_server::binary_analysis_server::DecompileRequest::new(binary_id, address);
    // `decompile` now RETURNS the failure instead of manufacturing a body, so the
    // error is forwarded rather than worked around. The `is_file` guard above is
    // kept: it still gives the caller the more precise `BinaryNotFound` for the
    // common case, and it costs one syscall.
    let resp = rustre_mcp_server::binary_analysis_server::DecompileResponse::decompile(&req)
        .map_err(|e| HandlerError::BinaryNotFound(format!("{binary_id}: {e}")))?;

    // Report the pipeline's OWN confidence, rescaled from 0–100 to 0.0–1.0.
    //
    // Until 2026-07-29 this field was the constant `0.85` with `warnings: []`,
    // so a caller could receive an invented body labelled 85% confident with no
    // warning attached. Hardcoding it also threw away the one honest signal the
    // pipeline emits: a `confidence` of 0 means it ran and recovered nothing.
    // That case is now reported rather than hidden — and it is no longer a
    // fabricated body, because a failure to load or resolve returns `Err`.
    let confidence = f64::from(resp.confidence) / 100.0;
    let mut warnings: Vec<String> = Vec::new();
    if resp.confidence == 0 {
        warnings.push(format!(
            "decompilation of {binary_id} at {address:#x} reported zero confidence: \
             the returned body may be a placeholder rather than recovered code"
        ));
    }

    Ok(serde_json::json!({
        "binary_id": binary_id,
        "address": address,
        "language": language,
        "source": resp.pseudo_c,
        "function_name": resp.function_name,
        "duration_ms": resp.duration_ms,
        "confidence": confidence,
        "warnings": warnings,
        "hlil_pseudo_code": resp.hlil_pseudo,
    }))
}

// ─── XrefDirection ────────────────────────────────────────────────────────────

/// Direction of a cross-reference query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum XrefDirection {
    /// References *to* the target address.
    To,
    /// References *from* the target address.
    From,
    /// Both directions.
    Both,
}

impl XrefDirection {
    /// Parse from a string.
    #[must_use]
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "from" => Self::From,
            "both" => Self::Both,
            _ => Self::To,
        }
    }
}

/// A single cross-reference record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrefRecord {
    /// Source address of the reference.
    pub from: u64,
    /// Target address of the reference.
    pub to: u64,
    /// Type of reference (call, jump, data, etc.).
    pub kind: String,
    /// Name of the source function (if known).
    pub from_function: Option<String>,
}

/// Handler for `get_xrefs`.
///
/// Expected parameters:
/// * `binary_id` (string, required)
/// * `address` (integer, required)
/// * `direction` (string, optional) — `"to"`, `"from"`, or `"both"`.
/// * `max` (integer, optional) — maximum results (default 100).
///
/// # Errors
///
/// Returns [`HandlerError`] if required params are missing.
pub fn handle_get_xrefs(params: Value) -> Result<Value, HandlerError> {
    let binary_id = require_str(&params, "binary_id")?;
    let address = require_u64(&params, "address")?;
    let dir = XrefDirection::from_str(optional_str(&params, "direction").unwrap_or("to"));
    let max = optional_u64(&params, "max").unwrap_or(100);
    if max == 0 {
        return Err(HandlerError::InvalidParamValue(
            "max".to_string(),
            "must be greater than 0".to_string(),
        ));
    }
    // Clamp to usize::MAX to avoid silent truncation on 32-bit targets.
    let max_usize = max.min(usize::MAX as u64) as usize;

    // Stub: generate synthetic xrefs.
    let stubs: Vec<XrefRecord> = (0..4.min(max_usize))
        .map(|i| {
            let from = match dir {
                XrefDirection::To => address.saturating_sub(0x100 * (i as u64 + 1)),
                XrefDirection::From => address.saturating_add(0x100 * (i as u64 + 1)),
                XrefDirection::Both => {
                    if i.is_multiple_of(2) {
                        address.saturating_sub(0x100 * (i as u64 + 1))
                    } else {
                        address.saturating_add(0x100 * (i as u64 + 1))
                    }
                }
            };
            XrefRecord {
                from,
                to: address,
                kind: if i.is_multiple_of(2) {
                    "call".to_string()
                } else {
                    "jump".to_string()
                },
                from_function: Some(format!("sub_{from:x}")),
            }
        })
        .collect();

    Ok(serde_json::json!({
        "binary_id": binary_id,
        "address": address,
        "direction": match dir { XrefDirection::To => "to", XrefDirection::From => "from", XrefDirection::Both => "both" },
        "count": stubs.len(),
        "xrefs": stubs,
    }))
}

// ─── handle_search_symbol ─────────────────────────────────────────────────────

/// A symbol search result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolMatch {
    /// Symbol name.
    pub name: String,
    /// Address.
    pub address: u64,
    /// Symbol type: "function", "global", "import", "export".
    pub kind: String,
    /// Whether the name was demangled.
    pub demangled: bool,
}

/// Handler for `search_symbol`.
///
/// Expected parameters:
/// * `binary_id` (string, required)
/// * `query` (string, required) — substring or regex.
/// * `regex` (boolean, optional) — treat `query` as regex.
/// * `max` (integer, optional) — maximum results.
///
/// # Errors
///
/// Returns [`HandlerError`] on missing params.
pub fn handle_search_symbol(params: Value) -> Result<Value, HandlerError> {
    let binary_id = require_str(&params, "binary_id")?;
    let query = require_str(&params, "query")?;
    let _regex = optional_bool(&params, "regex").unwrap_or(false);
    let max = optional_u64(&params, "max").unwrap_or(50);
    // Clamp to usize::MAX to avoid silent truncation on 32-bit targets.
    let max_usize = max.min(usize::MAX as u64) as usize;

    // Stub: return synthetic symbols whose names contain `query`.
    let candidates = [
        ("CreateFile", 0x1400_1100u64, "import"),
        ("CloseHandle", 0x1400_1200, "import"),
        ("ReadFile", 0x1400_1300, "import"),
        ("WriteFile", 0x1400_1400, "import"),
        ("sub_140001000", 0x1400_1000, "function"),
        ("global_config", 0x1401_0000, "global"),
    ];

    let matches: Vec<SymbolMatch> = candidates
        .iter()
        .filter(|(name, _, _)| name.to_ascii_lowercase().contains(query.to_ascii_lowercase().as_str()))
        .take(max_usize)
        .map(|(name, addr, kind)| SymbolMatch {
            name: name.to_string(),
            address: *addr,
            kind: kind.to_string(),
            demangled: false,
        })
        .collect();

    Ok(serde_json::json!({
        "binary_id": binary_id,
        "query": query,
        "count": matches.len(),
        "symbols": matches,
    }))
}

// ─── handle_add_comment ───────────────────────────────────────────────────────

/// Handler for `add_comment`.
///
/// Expected parameters:
/// * `binary_id` (string, required)
/// * `address` (integer, required)
/// * `comment` (string, required)
/// * `type` (string, optional) — `"line"`, `"block"`, `"function"`.
///
/// # Errors
///
/// Returns [`HandlerError`] on missing params.
pub fn handle_add_comment(params: Value) -> Result<Value, HandlerError> {
    let binary_id = require_str(&params, "binary_id")?;
    let address = require_u64(&params, "address")?;
    let comment = require_str(&params, "comment")?;
    let comment_type = optional_str(&params, "type").unwrap_or("line");

    if comment.is_empty() {
        return Err(HandlerError::InvalidParamValue(
            "comment".to_string(),
            "comment must not be empty".to_string(),
        ));
    }

    Ok(serde_json::json!({
        "binary_id": binary_id,
        "address": address,
        "comment": comment,
        "type": comment_type,
        "success": true,
    }))
}

// ─── YaraMatch ────────────────────────────────────────────────────────────────

/// A YARA rule match result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    /// Rule name that matched.
    pub rule: String,
    /// Matched namespace.
    pub namespace: String,
    /// Offsets of each match within the binary.
    pub offsets: Vec<u64>,
    /// Tags on the rule.
    pub tags: Vec<String>,
}

/// Handler for `run_yara`.
///
/// Expected parameters:
/// * `binary_id` (string, required)
/// * `rules` (string, required) — YARA rule source text.
/// * `fast` (boolean, optional) — use fast matching mode.
///
/// # Errors
///
/// Returns [`HandlerError::YaraError`] if the rules are syntactically invalid
/// (stub: checks for empty rules only).
pub fn handle_run_yara(params: Value) -> Result<Value, HandlerError> {
    let binary_id = require_str(&params, "binary_id")?;
    let rules = require_str(&params, "rules")?;
    let fast = optional_bool(&params, "fast").unwrap_or(false);

    if rules.trim().is_empty() {
        return Err(HandlerError::YaraError("empty rule set".to_string()));
    }

    // Stub: parse rule names from "rule <name>" lines.
    let matched_rules: Vec<YaraMatch> = rules
        .lines()
        .filter(|l| l.trim_start().starts_with("rule "))
        .map(|l| {
            let rule_name = l
                .trim()
                .strip_prefix("rule ")
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("unnamed")
                .to_string();
            YaraMatch {
                rule: rule_name,
                namespace: "default".to_string(),
                offsets: vec![0x1000, 0x2000],
                tags: Vec::new(),
            }
        })
        .collect();

    Ok(serde_json::json!({
        "binary_id": binary_id,
        "fast_mode": fast,
        "match_count": matched_rules.len(),
        "matches": matched_rules,
    }))
}

// ─── StringEntry ──────────────────────────────────────────────────────────────

/// A string literal found in a binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringEntry {
    /// File offset of the string.
    pub offset: u64,
    /// Virtual address of the string.
    pub virtual_address: u64,
    /// The string value.
    pub value: String,
    /// Encoding: "ascii" or "utf16le".
    pub encoding: String,
    /// Length in bytes.
    pub length: usize,
    /// Section name (e.g. ".rdata").
    pub section: String,
}

/// Handler for `get_strings`.
///
/// Expected parameters:
/// * `binary_id` (string, required)
/// * `min_length` (integer, optional) — minimum string length (default 4).
/// * `section` (string, optional) — restrict to a specific section.
///
/// # Errors
///
/// Returns [`HandlerError`] on missing params.
pub fn handle_get_strings(params: Value) -> Result<Value, HandlerError> {
    let binary_id = require_str(&params, "binary_id")?;
    let min_length_raw = optional_u64(&params, "min_length").unwrap_or(4);
    // Clamp to usize::MAX to avoid silent truncation on 32-bit targets.
    let min_length = min_length_raw.min(usize::MAX as u64) as usize;
    let section_filter = optional_str(&params, "section");

    // Stub strings.
    let all_strings = [StringEntry {
            offset: 0x400,
            virtual_address: 0x1400_1400,
            value: "This program cannot be run in DOS mode.".to_string(),
            encoding: "ascii".to_string(),
            length: 38,
            section: ".rdata".to_string(),
        },
        StringEntry {
            offset: 0x800,
            virtual_address: 0x1400_1800,
            value: "kernel32.dll".to_string(),
            encoding: "ascii".to_string(),
            length: 12,
            section: ".rdata".to_string(),
        },
        StringEntry {
            offset: 0xC00,
            virtual_address: 0x1400_1C00,
            value: "ntdll.dll".to_string(),
            encoding: "ascii".to_string(),
            length: 9,
            section: ".rdata".to_string(),
        },
        StringEntry {
            offset: 0x1000,
            virtual_address: 0x1401_0000,
            value: "Error".to_string(),
            encoding: "utf16le".to_string(),
            length: 10,
            section: ".data".to_string(),
        }];

    let filtered: Vec<&StringEntry> = all_strings
        .iter()
        .filter(|s| s.length >= min_length)
        .filter(|s| section_filter.is_none_or(|sec| s.section == sec))
        .collect();

    Ok(serde_json::json!({
        "binary_id": binary_id,
        "min_length": min_length,
        "count": filtered.len(),
        "strings": filtered,
    }))
}

// ─── ImportRecord / ExportRecord ──────────────────────────────────────────────

/// An import record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRecord {
    /// DLL name.
    pub dll: String,
    /// Function name (if by name).
    pub name: Option<String>,
    /// Ordinal (if by ordinal).
    pub ordinal: Option<u16>,
    /// Hint.
    pub hint: u16,
    /// IAT RVA.
    pub iat_rva: u32,
}

/// An export record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRecord {
    /// Export name.
    pub name: Option<String>,
    /// Ordinal.
    pub ordinal: u16,
    /// RVA.
    pub rva: u32,
    /// Forwarder, if applicable.
    pub forwarder: Option<String>,
}

/// Handler for `get_imports`.
///
/// Expected parameters:
/// * `binary_id` (string, required)
/// * `dll_filter` (string, optional) — filter by DLL name substring.
///
/// # Errors
///
/// Returns [`HandlerError`] on missing params.
pub fn handle_get_imports(params: Value) -> Result<Value, HandlerError> {
    let binary_id = require_str(&params, "binary_id")?;
    let dll_filter = optional_str(&params, "dll_filter");

    // Stub import table.
    let imports = [ImportRecord {
            dll: "kernel32.dll".into(),
            name: Some("CreateFileA".into()),
            ordinal: None,
            hint: 0,
            iat_rva: 0x1000,
        },
        ImportRecord {
            dll: "kernel32.dll".into(),
            name: Some("CloseHandle".into()),
            ordinal: None,
            hint: 1,
            iat_rva: 0x1008,
        },
        ImportRecord {
            dll: "ntdll.dll".into(),
            name: Some("NtQuerySystemInformation".into()),
            ordinal: None,
            hint: 0,
            iat_rva: 0x2000,
        },
        ImportRecord {
            dll: "user32.dll".into(),
            name: None,
            ordinal: Some(1),
            hint: 0,
            iat_rva: 0x3000,
        }];

    let filtered: Vec<&ImportRecord> = imports
        .iter()
        .filter(|i| dll_filter.is_none_or(|f| i.dll.to_lowercase().contains(&f.to_lowercase())))
        .collect();

    // Group by DLL.
    let mut by_dll: HashMap<String, Vec<&ImportRecord>> = HashMap::new();
    for imp in &filtered {
        by_dll.entry(imp.dll.clone()).or_default().push(imp);
    }
    let dll_names: Vec<&String> = {
        let mut keys: Vec<&String> = by_dll.keys().collect();
        keys.sort();
        keys
    };

    Ok(serde_json::json!({
        "binary_id": binary_id,
        "total_imports": filtered.len(),
        "dll_count": dll_names.len(),
        "imports": filtered,
    }))
}

/// Handler for `get_exports`.
///
/// Expected parameters:
/// * `binary_id` (string, required)
/// * `name_filter` (string, optional) — filter by export name substring.
///
/// # Errors
///
/// Returns [`HandlerError`] on missing params.
pub fn handle_get_exports(params: Value) -> Result<Value, HandlerError> {
    let binary_id = require_str(&params, "binary_id")?;
    let name_filter = optional_str(&params, "name_filter");

    // Stub export table.
    let exports = [ExportRecord {
            name: Some("DllMain".into()),
            ordinal: 1,
            rva: 0x1000,
            forwarder: None,
        },
        ExportRecord {
            name: Some("Initialize".into()),
            ordinal: 2,
            rva: 0x1100,
            forwarder: None,
        },
        ExportRecord {
            name: Some("Shutdown".into()),
            ordinal: 3,
            rva: 0x1200,
            forwarder: None,
        },
        ExportRecord {
            name: Some("GetVersion".into()),
            ordinal: 4,
            rva: 0x1300,
            forwarder: Some("ntdll.RtlGetVersion".into()),
        },
        ExportRecord {
            name: None,
            ordinal: 5,
            rva: 0x1400,
            forwarder: None,
        }];

    let filtered: Vec<&ExportRecord> = exports
        .iter()
        .filter(|e| {
            name_filter.is_none_or(|f| {
                e.name
                    .as_deref()
                    .is_some_and(|n| n.to_lowercase().contains(&f.to_lowercase()))
            })
        })
        .collect();

    Ok(serde_json::json!({
        "binary_id": binary_id,
        "total_exports": filtered.len(),
        "exports": filtered,
    }))
}

// ─── HandlerDispatch ──────────────────────────────────────────────────────────

/// Boxed handler function for `HandlerDispatch`.
pub type HandlerFn = Box<dyn Fn(Value) -> Result<Value, HandlerError> + Send + Sync>;

/// A built-in handler lookup table.
///
/// Maps tool name → handler function.  Used to populate a
/// [`crate::tool_registry::ToolRegistry`] with all built-in RustRE handlers.
pub struct HandlerDispatch {
    handlers: HashMap<String, HandlerFn>,
}

impl HandlerDispatch {
    /// Create a dispatch table with all built-in handlers registered.
    #[must_use]
    pub fn builtin() -> Self {
        let mut d = Self {
            handlers: HashMap::with_capacity(9),
        };
        d.add("analyze_binary", handle_analyze_binary);
        d.add("decompile_function", handle_decompile_function);
        d.add("get_xrefs", handle_get_xrefs);
        d.add("search_symbol", handle_search_symbol);
        d.add("add_comment", handle_add_comment);
        d.add("run_yara", handle_run_yara);
        d.add("get_strings", handle_get_strings);
        d.add("get_imports", handle_get_imports);
        d.add("get_exports", handle_get_exports);
        d
    }

    fn add<F>(&mut self, name: &str, f: F)
    where
        F: Fn(Value) -> Result<Value, HandlerError> + Send + Sync + 'static,
    {
        self.handlers.insert(name.to_string(), Box::new(f));
    }

    /// Dispatch a call to the named handler.
    ///
    /// # Errors
    ///
    /// Returns [`HandlerError`] if the tool is not found or the handler fails.
    pub fn dispatch(&self, name: &str, params: Value) -> Result<Value, HandlerError> {
        let handler = self
            .handlers
            .get(name)
            .ok_or_else(|| HandlerError::Internal(format!("no handler for '{name}'")))?;
        handler(params)
    }

    /// Return all registered tool names (sorted).
    #[must_use]
    pub fn tool_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.handlers.keys().map(|s| s.as_str()).collect();
        names.sort_unstable();
        names
    }

    /// Return `true` if a handler is registered for `name`.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.handlers.contains_key(name)
    }

    /// Number of handlers registered.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    /// Returns `true` if no handlers are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }
}

impl fmt::Debug for HandlerDispatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HandlerDispatch({})", self.len())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_binary_ok() {
        let r =
            handle_analyze_binary(serde_json::json!({"binary_id": "target64.exe"})).expect("ok");
        assert_eq!(r["binary_id"], "target64.exe");
        assert!(r["is_64bit"].as_bool().unwrap());
        assert!(!r["is_dll"].as_bool().unwrap());
    }

    #[test]
    fn analyze_binary_dll() {
        let r = handle_analyze_binary(serde_json::json!({"binary_id": "plugin.dll"})).expect("ok");
        assert!(r["is_dll"].as_bool().unwrap());
    }

    #[test]
    fn analyze_binary_missing_param() {
        let err = handle_analyze_binary(serde_json::json!({}));
        assert!(matches!(err, Err(HandlerError::MissingParam(_))));
    }

    /// A binary that does not exist must be reported as missing.
    ///
    /// This test previously read `binary_id: "test.exe"` — a path that has
    /// never existed — and asserted the answer contained `sub_1000`. It passed
    /// only because `DecompileResponse::decompile` fabricates a body for an
    /// unloadable file, so the test was pinning the defect in place: making the
    /// handler honest would have looked like a regression. Corrected 2026-07-29
    /// to assert the honest outcome instead.
    #[test]
    fn decompile_function_rejects_missing_binary() {
        let err = handle_decompile_function(
            serde_json::json!({"binary_id": "test.exe", "address": 0x1000u64}),
        );
        assert!(
            matches!(err, Err(HandlerError::BinaryNotFound(_))),
            "a nonexistent binary must not produce decompiled source"
        );
    }

    /// Positive control: with a file that really exists the handler answers,
    /// and its confidence is the pipeline's own value rather than a constant.
    ///
    /// The current executable is used because it is guaranteed to be present
    /// and to be a real image. The address is almost certainly not a function
    /// entry, so the pipeline is expected to recover nothing — the point is
    /// that this case is now *reported* (zero confidence, a warning saying so)
    /// instead of being dressed up as an 85%-confident result.
    #[test]
    fn decompile_function_reports_real_confidence_and_warns_on_zero() {
        let Ok(exe) = std::env::current_exe() else {
            return; // no executable path available; nothing to assert against
        };
        let r = handle_decompile_function(serde_json::json!({
            "binary_id": exe.to_string_lossy(),
            "address": 0x1000u64,
        }))
        .expect("an existing file must not be rejected");

        let conf = r["confidence"].as_f64().expect("confidence is a number");
        assert!(
            (0.0..=1.0).contains(&conf),
            "confidence must be a real 0..=1 score, got {conf}"
        );
        let warnings = r["warnings"].as_array().expect("warnings array");
        assert_eq!(
            conf == 0.0,
            !warnings.is_empty(),
            "a zero-confidence result must carry a warning, and a non-zero one must not"
        );
    }

    #[test]
    fn decompile_function_missing_address() {
        let err = handle_decompile_function(serde_json::json!({"binary_id": "x.exe"}));
        assert!(matches!(err, Err(HandlerError::MissingParam(_))));
    }

    #[test]
    fn get_xrefs_to() {
        let r = handle_get_xrefs(serde_json::json!({"binary_id": "x.exe", "address": 0x1000u64}))
            .expect("ok");
        assert!(r["count"].as_u64().unwrap() > 0);
    }

    #[test]
    fn get_xrefs_direction_from() {
        let r = handle_get_xrefs(
            serde_json::json!({"binary_id": "x.exe", "address": 0x1000u64, "direction": "from"}),
        )
        .expect("ok");
        assert_eq!(r["direction"], "from");
    }

    #[test]
    fn search_symbol_found() {
        let r =
            handle_search_symbol(serde_json::json!({"binary_id": "x.exe", "query": "CreateFile"}))
                .expect("ok");
        assert!(r["count"].as_u64().unwrap() > 0);
        assert_eq!(r["symbols"][0]["name"], "CreateFile");
    }

    #[test]
    fn search_symbol_not_found() {
        let r = handle_search_symbol(
            serde_json::json!({"binary_id": "x.exe", "query": "zzz_nonexistent_zzz"}),
        )
        .expect("ok");
        assert_eq!(r["count"], 0);
    }

    #[test]
    fn add_comment_ok() {
        let r = handle_add_comment(
            serde_json::json!({"binary_id": "x.exe", "address": 0x1000u64, "comment": "entry"}),
        )
        .expect("ok");
        assert_eq!(r["success"], true);
        assert_eq!(r["comment"], "entry");
    }

    #[test]
    fn add_comment_empty_fails() {
        let err = handle_add_comment(
            serde_json::json!({"binary_id": "x.exe", "address": 0x1000u64, "comment": ""}),
        );
        assert!(matches!(err, Err(HandlerError::InvalidParamValue(_, _))));
    }

    #[test]
    fn run_yara_ok() {
        let rules = "rule FindNOP { strings: $a = { 90 } condition: $a }";
        let r =
            handle_run_yara(serde_json::json!({"binary_id": "x.exe", "rules": rules})).expect("ok");
        assert_eq!(r["match_count"], 1);
    }

    #[test]
    fn run_yara_empty_rules() {
        let err = handle_run_yara(serde_json::json!({"binary_id": "x.exe", "rules": ""}));
        assert!(matches!(err, Err(HandlerError::YaraError(_))));
    }

    #[test]
    fn get_strings_ok() {
        let r = handle_get_strings(serde_json::json!({"binary_id": "x.exe"})).expect("ok");
        assert!(r["count"].as_u64().unwrap() > 0);
    }

    #[test]
    fn get_strings_min_length_filter() {
        let r = handle_get_strings(serde_json::json!({"binary_id": "x.exe", "min_length": 20u64}))
            .expect("ok");
        // Only strings >= 20 chars should remain.
        for s in r["strings"].as_array().unwrap() {
            assert!(s["length"].as_u64().unwrap() >= 20);
        }
    }

    #[test]
    fn get_imports_ok() {
        let r = handle_get_imports(serde_json::json!({"binary_id": "x.exe"})).expect("ok");
        assert!(r["total_imports"].as_u64().unwrap() > 0);
    }

    #[test]
    fn get_imports_dll_filter() {
        let r =
            handle_get_imports(serde_json::json!({"binary_id": "x.exe", "dll_filter": "kernel32"}))
                .expect("ok");
        for imp in r["imports"].as_array().unwrap() {
            assert!(
                imp["dll"]
                    .as_str()
                    .unwrap()
                    .to_lowercase()
                    .contains("kernel32")
            );
        }
    }

    #[test]
    fn get_exports_ok() {
        let r = handle_get_exports(serde_json::json!({"binary_id": "plugin.dll"})).expect("ok");
        assert!(r["total_exports"].as_u64().unwrap() > 0);
    }

    #[test]
    fn get_exports_name_filter() {
        let r = handle_get_exports(
            serde_json::json!({"binary_id": "plugin.dll", "name_filter": "Dll"}),
        )
        .expect("ok");
        for exp in r["exports"].as_array().unwrap() {
            assert!(exp["name"].as_str().unwrap().contains("Dll"));
        }
    }

    #[test]
    fn handler_dispatch_builtin() {
        let d = HandlerDispatch::builtin();
        assert_eq!(d.len(), 9);
        assert!(d.has("analyze_binary"));
        assert!(d.has("run_yara"));
    }

    #[test]
    fn handler_dispatch_call() {
        let d = HandlerDispatch::builtin();
        let r = d
            .dispatch(
                "analyze_binary",
                serde_json::json!({"binary_id": "test.exe"}),
            )
            .expect("dispatch");
        assert_eq!(r["binary_id"], "test.exe");
    }

    #[test]
    fn handler_dispatch_not_found() {
        let d = HandlerDispatch::builtin();
        let err = d.dispatch("unknown_tool", serde_json::json!({}));
        assert!(matches!(err, Err(HandlerError::Internal(_))));
    }

    #[test]
    fn handler_error_helpers() {
        let e = HandlerError::missing("foo");
        assert!(e.is_missing());
        let e2 = HandlerError::wrong_type("bar", "string", "number");
        assert!(!e2.is_missing());
    }
}
