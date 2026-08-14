//! `lua_api_docs` — documentation generator for the `RustRE` Lua scripting API.
//!
//! Provides [`LuaApiDocs`], a registry of [`FunctionDoc`] entries organised into
//! [`ApiCategory`] groups, a Markdown [`DocGenerator`], and a [`DocValidator`]
//! that checks completeness and consistency.

use std::collections::HashMap;
use std::fmt;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

// ── ApiCategory ───────────────────────────────────────────────────────────────

/// Logical grouping of API functions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApiCategory {
    /// Binary analysis functions (disassembly, lifting, etc.).
    Analysis,
    /// Symbol management (rename, type info, comments).
    Symbols,
    /// Dynamic debug / runtime inspection.
    Debug,
    /// Cryptographic utilities (hash, XOR, entropy).
    Crypto,
    /// Network / IOC analysis helpers.
    Network,
    /// Miscellaneous utilities that don't fit other categories.
    Utility,
    /// Custom category with a user-supplied name.
    Custom(String),
}

impl fmt::Display for ApiCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Analysis => write!(f, "Analysis"),
            Self::Symbols => write!(f, "Symbols"),
            Self::Debug => write!(f, "Debug"),
            Self::Crypto => write!(f, "Crypto"),
            Self::Network => write!(f, "Network"),
            Self::Utility => write!(f, "Utility"),
            Self::Custom(s) => write!(f, "{s}"),
        }
    }
}

impl ApiCategory {
    /// Return all built-in (non-Custom) categories.
    #[must_use]
    pub fn all_builtin() -> Vec<Self> {
        vec![
            Self::Analysis,
            Self::Symbols,
            Self::Debug,
            Self::Crypto,
            Self::Network,
            Self::Utility,
        ]
    }

    /// Parse a category from its display string (case-insensitive).
    #[must_use]
    pub fn parse_name(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "analysis" => Self::Analysis,
            "symbols" => Self::Symbols,
            "debug" => Self::Debug,
            "crypto" => Self::Crypto,
            "network" => Self::Network,
            "utility" => Self::Utility,
            other => Self::Custom(other.to_string()),
        }
    }
}

// ── CodeExample ──────────────────────────────────────────────────────────────

/// A code example attached to a function's documentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeExample {
    /// Human-readable description of what the example demonstrates.
    pub description: String,
    /// Lua source code.
    pub code: String,
    /// Expected output, if any.
    pub expected_output: Option<String>,
}

impl CodeExample {
    /// Create a new code example.
    #[must_use]
    pub fn new(description: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            code: code.into(),
            expected_output: None,
        }
    }

    /// Attach expected output.
    #[must_use]
    pub fn with_output(mut self, output: impl Into<String>) -> Self {
        self.expected_output = Some(output.into());
        self
    }
}

// ── ParamDoc ─────────────────────────────────────────────────────────────────

/// Documentation for a single function parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamDoc {
    /// Parameter name.
    pub name: String,
    /// Lua type annotation (e.g. `"string"`, `"number"`, `"table"`).
    pub type_hint: String,
    /// Whether the parameter is optional.
    pub optional: bool,
    /// Default value description (for optional params).
    pub default: Option<String>,
    /// Short description of what this parameter represents.
    pub description: String,
}

impl ParamDoc {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        type_hint: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            type_hint: type_hint.into(),
            optional: false,
            default: None,
            description: description.into(),
        }
    }

    #[must_use]
    pub fn optional(mut self, default: impl Into<String>) -> Self {
        self.optional = true;
        self.default = Some(default.into());
        self
    }
}

// ── FunctionDoc ───────────────────────────────────────────────────────────────

/// Documentation for a single Lua API function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDoc {
    /// Function name as callable from Lua (e.g. `"rustre.load_binary"`).
    pub name: String,
    /// Full Lua signature string (e.g. `"rustre.load_binary(path: string) -> string"`).
    pub signature: String,
    /// Short one-line description.
    pub description: String,
    /// Extended documentation with details, caveats, etc.
    pub long_description: Option<String>,
    /// Parameter documentation.
    pub params: Vec<ParamDoc>,
    /// Return type hint.
    pub return_type: String,
    /// Return value description.
    pub return_description: String,
    /// Code examples.
    pub examples: Vec<CodeExample>,
    /// API category.
    pub category: ApiCategory,
    /// Whether this function was added since the last major version.
    pub is_new: bool,
    /// Whether this function is deprecated.
    pub deprecated: bool,
    /// Deprecation message (set when `deprecated` is true).
    pub deprecation_note: Option<String>,
    /// Cross-references to related functions.
    pub see_also: Vec<String>,
    /// Since which version this function is available.
    pub since_version: Option<String>,
}

impl FunctionDoc {
    /// Create a minimal function doc.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        signature: impl Into<String>,
        description: impl Into<String>,
        category: ApiCategory,
    ) -> Self {
        Self {
            name: name.into(),
            signature: signature.into(),
            description: description.into(),
            long_description: None,
            params: Vec::new(),
            return_type: "nil".to_string(),
            return_description: String::new(),
            examples: Vec::new(),
            category,
            is_new: false,
            deprecated: false,
            deprecation_note: None,
            see_also: Vec::new(),
            since_version: None,
        }
    }

    /// Set the return type and description.
    #[must_use]
    pub fn returns(mut self, ty: impl Into<String>, desc: impl Into<String>) -> Self {
        self.return_type = ty.into();
        self.return_description = desc.into();
        self
    }

    /// Add a parameter.
    #[must_use]
    pub fn param(mut self, p: ParamDoc) -> Self {
        self.params.push(p);
        self
    }

    /// Add an example.
    #[must_use]
    pub fn example(mut self, ex: CodeExample) -> Self {
        self.examples.push(ex);
        self
    }

    /// Add a long description.
    #[must_use]
    pub fn long_desc(mut self, desc: impl Into<String>) -> Self {
        self.long_description = Some(desc.into());
        self
    }

    /// Mark as deprecated.
    #[must_use]
    pub fn deprecated(mut self, note: impl Into<String>) -> Self {
        self.deprecated = true;
        self.deprecation_note = Some(note.into());
        self
    }

    /// Add a see-also reference.
    #[must_use]
    pub fn see(mut self, func: impl Into<String>) -> Self {
        self.see_also.push(func.into());
        self
    }

    /// Set the since-version annotation.
    #[must_use]
    pub fn since(mut self, version: impl Into<String>) -> Self {
        self.since_version = Some(version.into());
        self
    }

    /// Mark as new.
    #[must_use]
    pub const fn mark_new(mut self) -> Self {
        self.is_new = true;
        self
    }

    /// Return `true` if this function has at least one example.
    #[must_use]
    pub const fn has_examples(&self) -> bool {
        !self.examples.is_empty()
    }

    /// Return the number of parameters.
    #[must_use]
    pub const fn param_count(&self) -> usize {
        self.params.len()
    }

    /// Return `true` if all parameters are documented.
    #[must_use]
    pub fn all_params_documented(&self) -> bool {
        self.params.iter().all(|p| !p.description.is_empty())
    }
}

// ── LuaApiDocs ────────────────────────────────────────────────────────────────

/// Registry of all Lua API documentation entries.
#[derive(Debug, Default)]
pub struct LuaApiDocs {
    entries: Vec<FunctionDoc>,
}

impl LuaApiDocs {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry pre-populated with the standard `RustRE` Lua API docs.
    #[must_use]
    pub fn standard() -> Self {
        let mut docs = Self::new();
        Self::register_analysis_docs(&mut docs);
        Self::register_utility_docs(&mut docs);
        docs
    }

    fn register_analysis_docs(docs: &mut Self) {
        docs.register(
            FunctionDoc::new(
                "rustre.load_binary",
                "rustre.load_binary(path: string) -> string",
                "Load a binary file into the RustRE binary store and return its id.",
                ApiCategory::Analysis,
            )
            .param(ParamDoc::new("path", "string", "Absolute or relative path to the binary file."))
            .returns("string", "Binary id used with other rustre.* functions.")
            .example(CodeExample::new(
                "Load a PE file",
                r#"local id = rustre.load_binary("/tmp/malware.exe")
print("loaded: " .. id)"#,
            ))
            .since("0.1.0"),
        );

        docs.register(
            FunctionDoc::new(
                "rustre.disasm_at",
                "rustre.disasm_at(id: string, addr: number, count: number) -> table",
                "Disassemble `count` instructions from `addr` in the stored binary.",
                ApiCategory::Analysis,
            )
            .param(ParamDoc::new("id", "string", "Binary id returned by load_binary."))
            .param(ParamDoc::new("addr", "number", "Virtual address to start disassembly."))
            .param(ParamDoc::new("count", "number", "Maximum number of instructions to decode.").optional("10"))
            .returns("table", "Array of {addr, text} records.")
            .see("rustre.load_binary")
            .since("0.1.0"),
        );

        docs.register(
            FunctionDoc::new(
                "rustre.find_strings",
                "rustre.find_strings(id: string) -> table",
                "Find all printable ASCII strings of length >= 4 in the stored binary.",
                ApiCategory::Analysis,
            )
            .param(ParamDoc::new("id", "string", "Binary id."))
            .returns("table", "Array of {addr, value, encoding} records.")
            .since("0.1.0"),
        );

        docs.register(
            FunctionDoc::new(
                "rustre.get_info",
                "rustre.get_info(id: string) -> table",
                "Return metadata about the stored binary (format, arch, size, entry point).",
                ApiCategory::Analysis,
            )
            .param(ParamDoc::new("id", "string", "Binary id."))
            .returns("table", "Keys: format, arch, entry_point, size.")
            .example(CodeExample::new(
                "Print binary metadata",
                r#"local info = rustre.get_info(id)
print("format: " .. info.format)
print("arch: " .. info.arch)"#,
            ))
            .since("0.1.0"),
        );

        docs.register(
            FunctionDoc::new(
                "rustre.entropy",
                "rustre.entropy(data: string) -> number",
                "Compute the Shannon entropy (bits per symbol) of the given data string.",
                ApiCategory::Crypto,
            )
            .param(ParamDoc::new("data", "string", "Byte string to measure."))
            .returns("number", "Entropy value in [0.0, 8.0].")
            .example(CodeExample::new("Measure entropy", r#"print(rustre.entropy("AAAA"))"#)
                .with_output("0.0"))
            .since("0.1.0"),
        );

        docs.register(
            FunctionDoc::new(
                "rustre.xor_bytes",
                "rustre.xor_bytes(data: string, key: number) -> string",
                "XOR every byte of `data` with the single-byte `key`.",
                ApiCategory::Crypto,
            )
            .param(ParamDoc::new("data", "string", "Input byte string."))
            .param(ParamDoc::new("key", "number", "Single-byte XOR key (0–255)."))
            .returns("string", "XOR-decoded byte string.")
            .since("0.1.0"),
        );

    }

    fn register_utility_docs(docs: &mut Self) {
        docs.register(
            FunctionDoc::new(
                "rustre.hex_to_dec",
                "rustre.hex_to_dec(hex: string) -> number",
                "Parse a hexadecimal string (with or without 0x prefix) to a decimal integer.",
                ApiCategory::Utility,
            )
            .param(ParamDoc::new("hex", "string", "Hex string, e.g. \"0x1a\" or \"1a\"."))
            .returns("number", "Parsed integer value.")
            .since("0.1.0"),
        );

        docs.register(
            FunctionDoc::new(
                "rustre.dec_to_hex",
                "rustre.dec_to_hex(n: number) -> string",
                "Format an integer as a lower-case hexadecimal string with 0x prefix.",
                ApiCategory::Utility,
            )
            .param(ParamDoc::new("n", "number", "Integer to format."))
            .returns("string", "Hex string, e.g. \"0x1a\".")
            .since("0.1.0"),
        );
    }

    /// Register a function doc entry.
    pub fn register(&mut self, doc: FunctionDoc) {
        self.entries.push(doc);
    }

    /// Look up a function by name.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&FunctionDoc> {
        self.entries.iter().find(|d| d.name == name)
    }

    /// Return all entries in a given category.
    #[must_use]
    pub fn by_category(&self, cat: &ApiCategory) -> Vec<&FunctionDoc> {
        self.entries.iter().filter(|d| &d.category == cat).collect()
    }

    /// Return all deprecated entries.
    #[must_use]
    pub fn deprecated_entries(&self) -> Vec<&FunctionDoc> {
        self.entries.iter().filter(|d| d.deprecated).collect()
    }

    /// Return all entries marked as new.
    #[must_use]
    pub fn new_entries(&self) -> Vec<&FunctionDoc> {
        self.entries.iter().filter(|d| d.is_new).collect()
    }

    /// Return all entries.
    #[must_use]
    pub fn all(&self) -> &[FunctionDoc] {
        &self.entries
    }

    /// Total number of documented functions.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if no functions are documented.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return function names as a sorted list.
    #[must_use]
    pub fn function_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.entries.iter().map(|d| d.name.as_str()).collect();
        names.sort_unstable();
        names
    }
}

// ── DocGenerator ─────────────────────────────────────────────────────────────

/// Renders [`LuaApiDocs`] to various output formats.
pub struct DocGenerator<'a> {
    docs: &'a LuaApiDocs,
}

impl<'a> DocGenerator<'a> {
    /// Create a generator backed by `docs`.
    #[must_use]
    pub const fn new(docs: &'a LuaApiDocs) -> Self {
        Self { docs }
    }

    /// Render the full API reference as GitHub-flavoured Markdown.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut out = String::from("# RustRE Lua API Reference\n\n");

        for cat in ApiCategory::all_builtin() {
            let funcs = self.docs.by_category(&cat);
            if funcs.is_empty() {
                continue;
            }
            let _ = write!(out, "## {cat}\n\n");
            for f in funcs {
                out.push_str(&self.render_function(f));
                out.push('\n');
            }
        }

        out
    }

    /// Render a single function as Markdown.
    #[must_use]
    pub fn render_function(&self, f: &FunctionDoc) -> String {
        let mut out = format!("### `{}`\n\n", f.name);

        if f.deprecated {
            out.push_str("> **Deprecated**");
            if let Some(note) = &f.deprecation_note {
                let _ = write!(out, ": {note}");
            }
            out.push_str("\n\n");
        }

        let _ = write!(out, "```lua\n{}\n```\n\n", f.signature);
        let _ = write!(out, "{}\n\n", f.description);

        if let Some(long) = &f.long_description {
            let _ = write!(out, "{long}\n\n");
        }

        if !f.params.is_empty() {
            out.push_str("**Parameters:**\n\n");
            for p in &f.params {
                let opt = if p.optional {
                    format!(" *(optional, default: {})*", p.default.as_deref().unwrap_or("nil"))
                } else {
                    String::new()
                };
                let _ = writeln!(out, "- `{}` (`{}`){}: {}", p.name, p.type_hint, opt, p.description);
            }
            out.push('\n');
        }

        if !f.return_type.is_empty() && f.return_type != "nil" {
            let _ = write!(out, "**Returns:** `{}` — {}\n\n", f.return_type, f.return_description);
        }

        for ex in &f.examples {
            let _ = write!(out, "**Example:** {}\n\n", ex.description);
            let _ = write!(out, "```lua\n{}\n```\n", ex.code);
            if let Some(expected) = &ex.expected_output {
                let _ = writeln!(out, "Output: `{expected}`");
            }
            out.push('\n');
        }

        if !f.see_also.is_empty() {
            let refs: Vec<String> = f.see_also.iter().map(|s| format!("`{s}`")).collect();
            let _ = write!(out, "**See also:** {}\n\n", refs.join(", "));
        }

        if let Some(since) = &f.since_version {
            let _ = write!(out, "*Available since: v{since}*\n\n");
        }

        out
    }

    /// Render as a simple plain-text summary table.
    #[must_use]
    pub fn to_summary_table(&self) -> String {
        let mut rows = Vec::with_capacity(self.docs.len() + 2);
        rows.push("| Function | Category | Description |".to_string());
        rows.push("| --- | --- | --- |".to_string());
        for f in self.docs.all() {
            let desc = if f.description.len() > 60 {
                format!("{}…", &f.description[..60])
            } else {
                f.description.clone()
            };
            rows.push(format!("| `{}` | {} | {} |", f.name, f.category, desc));
        }
        rows.join("\n")
    }

    /// Render as JSON (compact serialisation of all entries).
    ///
    /// # Errors
    /// Returns `serde_json` error text if serialisation fails.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self.docs.all()).map_err(|e| e.to_string())
    }
}

// ── DocValidator ─────────────────────────────────────────────────────────────

/// Validates the completeness and consistency of a [`LuaApiDocs`] registry.
#[derive(Debug, Default)]
pub struct DocValidator {
    /// Issues found during validation.
    issues: Vec<String>,
}

/// Summary of a validation run.
#[derive(Debug, Clone)]
pub struct ValidationReport {
    /// All issues found (empty = valid).
    pub issues: Vec<String>,
    /// Functions with no examples.
    pub missing_examples: Vec<String>,
    /// Functions with undocumented parameters.
    pub undocumented_params: Vec<String>,
    /// Functions with no return type description.
    pub missing_return_desc: Vec<String>,
}

impl ValidationReport {
    /// Returns `true` if no issues were found.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.issues.is_empty()
    }

    /// Total number of issues.
    #[must_use]
    pub const fn issue_count(&self) -> usize {
        self.issues.len()
    }
}

impl DocValidator {
    /// Create a new validator.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate `docs` and return a report.
    #[must_use]
    pub fn validate(&mut self, docs: &LuaApiDocs) -> ValidationReport {
        self.issues.clear();
        let mut missing_examples = Vec::new();
        let mut undocumented_params = Vec::new();
        let mut missing_return_desc = Vec::new();

        // Check for duplicate names.
        let mut seen: HashMap<&str, usize> = HashMap::with_capacity(docs.len());
        for (i, f) in docs.all().iter().enumerate() {
            if let Some(prev) = seen.insert(f.name.as_str(), i) {
                self.issues.push(format!(
                    "Duplicate function name '{}' at indices {} and {}", f.name, prev, i
                ));
            }

            // Check examples.
            if f.examples.is_empty() && !f.deprecated {
                missing_examples.push(f.name.clone());
            }

            // Check params.
            for p in &f.params {
                if p.description.trim().is_empty() {
                    undocumented_params.push(format!("{}::{}", f.name, p.name));
                    self.issues.push(format!(
                        "Parameter '{}' of '{}' has no description.", p.name, f.name
                    ));
                }
            }

            // Check return desc.
            if f.return_type != "nil" && f.return_description.trim().is_empty() {
                missing_return_desc.push(f.name.clone());
                self.issues.push(format!(
                    "Function '{}' has return type '{}' but no return description.",
                    f.name, f.return_type
                ));
            }

            // Check for empty description.
            if f.description.trim().is_empty() {
                self.issues.push(format!("Function '{}' has no description.", f.name));
            }
        }

        ValidationReport {
            issues: self.issues.clone(),
            missing_examples,
            undocumented_params,
            missing_return_desc,
        }
    }

    /// Clear accumulated issues.
    pub fn clear(&mut self) {
        self.issues.clear();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_doc() -> FunctionDoc {
        FunctionDoc::new(
            "rustre.test_fn",
            "rustre.test_fn(x: number) -> string",
            "A test function.",
            ApiCategory::Utility,
        )
        .param(ParamDoc::new("x", "number", "Input value."))
        .returns("string", "Formatted result.")
        .example(CodeExample::new("Basic usage", r"print(rustre.test_fn(1))"))
        .since("0.1.0")
    }

    // ── ApiCategory ──────────────────────────────────────────────────────────

    #[test]
    fn test_api_category_display() {
        assert_eq!(ApiCategory::Analysis.to_string(), "Analysis");
        assert_eq!(ApiCategory::Crypto.to_string(), "Crypto");
        assert_eq!(ApiCategory::Custom("My".to_string()).to_string(), "My");
    }

    #[test]
    fn test_api_category_all_builtin() {
        let cats = ApiCategory::all_builtin();
        assert!(cats.contains(&ApiCategory::Analysis));
        assert!(cats.contains(&ApiCategory::Symbols));
        assert!(cats.contains(&ApiCategory::Debug));
    }

    #[test]
    fn test_api_category_from_str() {
        assert_eq!(ApiCategory::parse_name("analysis"), ApiCategory::Analysis);
        assert_eq!(ApiCategory::parse_name("CRYPTO"), ApiCategory::Crypto);
        assert_eq!(ApiCategory::parse_name("custom_thing"), ApiCategory::Custom("custom_thing".to_string()));
    }

    // ── FunctionDoc ──────────────────────────────────────────────────────────

    #[test]
    fn test_function_doc_new() {
        let doc = FunctionDoc::new("fn_x", "fn_x()", "desc", ApiCategory::Debug);
        assert_eq!(doc.name, "fn_x");
        assert!(!doc.deprecated);
        assert!(!doc.is_new);
    }

    #[test]
    fn test_function_doc_with_params() {
        let doc = sample_doc();
        assert_eq!(doc.param_count(), 1);
        assert!(doc.all_params_documented());
    }

    #[test]
    fn test_function_doc_has_examples() {
        let doc = sample_doc();
        assert!(doc.has_examples());
    }

    #[test]
    fn test_function_doc_returns() {
        let doc = sample_doc();
        assert_eq!(doc.return_type, "string");
        assert!(!doc.return_description.is_empty());
    }

    #[test]
    fn test_function_doc_deprecated() {
        let doc = FunctionDoc::new("old_fn", "old_fn()", "old", ApiCategory::Utility)
            .deprecated("use new_fn instead");
        assert!(doc.deprecated);
        assert_eq!(doc.deprecation_note.as_deref(), Some("use new_fn instead"));
    }

    #[test]
    fn test_function_doc_see_also() {
        let doc = sample_doc().see("rustre.load_binary").see("rustre.disasm_at");
        assert_eq!(doc.see_also.len(), 2);
    }

    #[test]
    fn test_function_doc_mark_new() {
        let doc = sample_doc().mark_new();
        assert!(doc.is_new);
    }

    #[test]
    fn test_function_doc_long_desc() {
        let doc = sample_doc().long_desc("Extended details.");
        assert_eq!(doc.long_description.as_deref(), Some("Extended details."));
    }

    #[test]
    fn test_function_doc_since() {
        let doc = sample_doc();
        assert_eq!(doc.since_version.as_deref(), Some("0.1.0"));
    }

    // ── LuaApiDocs ───────────────────────────────────────────────────────────

    #[test]
    fn test_lua_api_docs_register_and_find() {
        let mut docs = LuaApiDocs::new();
        docs.register(sample_doc());
        assert!(docs.find("rustre.test_fn").is_some());
        assert!(docs.find("nonexistent").is_none());
    }

    #[test]
    fn test_lua_api_docs_by_category() {
        let mut docs = LuaApiDocs::new();
        docs.register(sample_doc());
        let utility = docs.by_category(&ApiCategory::Utility);
        assert_eq!(utility.len(), 1);
        let analysis = docs.by_category(&ApiCategory::Analysis);
        assert!(analysis.is_empty());
    }

    #[test]
    fn test_lua_api_docs_standard_populates() {
        let docs = LuaApiDocs::standard();
        assert!(docs.len() > 0);
        assert!(docs.find("rustre.load_binary").is_some());
        assert!(docs.find("rustre.entropy").is_some());
    }

    #[test]
    fn test_lua_api_docs_function_names_sorted() {
        let docs = LuaApiDocs::standard();
        let names = docs.function_names();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }

    #[test]
    fn test_lua_api_docs_deprecated_entries() {
        let mut docs = LuaApiDocs::new();
        docs.register(FunctionDoc::new("old", "old()", "old", ApiCategory::Utility).deprecated("use new"));
        docs.register(sample_doc());
        assert_eq!(docs.deprecated_entries().len(), 1);
    }

    #[test]
    fn test_lua_api_docs_new_entries() {
        let mut docs = LuaApiDocs::new();
        docs.register(sample_doc().mark_new());
        assert_eq!(docs.new_entries().len(), 1);
    }

    #[test]
    fn test_lua_api_docs_len_and_empty() {
        let docs = LuaApiDocs::new();
        assert!(docs.is_empty());
        let mut docs2 = LuaApiDocs::new();
        docs2.register(sample_doc());
        assert!(!docs2.is_empty());
        assert_eq!(docs2.len(), 1);
    }

    // ── DocGenerator ─────────────────────────────────────────────────────────

    #[test]
    fn test_doc_generator_to_markdown_contains_function_name() {
        let docs = LuaApiDocs::standard();
        let doc_gen = DocGenerator::new(&docs);
        let md = doc_gen.to_markdown();
        assert!(md.contains("rustre.load_binary"));
        assert!(md.contains("## Analysis"));
    }

    #[test]
    fn test_doc_generator_render_function_contains_signature() {
        let doc = sample_doc();
        let docs = LuaApiDocs::new();
        let doc_gen = DocGenerator::new(&docs);
        let rendered = doc_gen.render_function(&doc);
        assert!(rendered.contains("rustre.test_fn(x: number) -> string"));
    }

    #[test]
    fn test_doc_generator_render_deprecated() {
        let mut docs = LuaApiDocs::new();
        docs.register(FunctionDoc::new("old", "old()", "old", ApiCategory::Utility).deprecated("x"));
        let doc_gen = DocGenerator::new(&docs);
        let old = docs.find("old").unwrap();
        let r = doc_gen.render_function(old);
        assert!(r.contains("Deprecated"));
    }

    #[test]
    fn test_doc_generator_summary_table() {
        let docs = LuaApiDocs::standard();
        let doc_gen = DocGenerator::new(&docs);
        let tbl = doc_gen.to_summary_table();
        assert!(tbl.contains("| Function |"));
        assert!(tbl.contains("rustre.entropy"));
    }

    #[test]
    fn test_doc_generator_to_json() {
        let docs = LuaApiDocs::standard();
        let doc_gen = DocGenerator::new(&docs);
        let json = doc_gen.to_json().unwrap();
        assert!(json.contains("rustre.load_binary"));
    }

    // ── DocValidator ─────────────────────────────────────────────────────────

    #[test]
    fn test_doc_validator_valid_docs() {
        let docs = LuaApiDocs::standard();
        let mut val = DocValidator::new();
        let report = val.validate(&docs);
        // Standard docs should have return descriptions set.
        // Empty description issues should be zero.
        let desc_issues: Vec<&String> = report.issues.iter()
            .filter(|i| i.contains("no description"))
            .collect();
        assert!(desc_issues.is_empty());
    }

    #[test]
    fn test_doc_validator_detects_duplicate_names() {
        let mut docs = LuaApiDocs::new();
        docs.register(FunctionDoc::new("fn_x", "fn_x()", "a", ApiCategory::Utility));
        docs.register(FunctionDoc::new("fn_x", "fn_x()", "b", ApiCategory::Utility));
        let mut val = DocValidator::new();
        let report = val.validate(&docs);
        assert!(!report.is_valid());
        assert!(report.issues.iter().any(|i| i.contains("Duplicate")));
    }

    #[test]
    fn test_doc_validator_detects_empty_param_description() {
        let mut docs = LuaApiDocs::new();
        let mut f = FunctionDoc::new("fn_y", "fn_y(x)", "desc", ApiCategory::Utility);
        f.params.push(ParamDoc { name: "x".to_string(), type_hint: "number".to_string(), optional: false, default: None, description: "".to_string() });
        docs.register(f);
        let mut val = DocValidator::new();
        let report = val.validate(&docs);
        assert!(!report.undocumented_params.is_empty());
    }

    #[test]
    fn test_doc_validator_detects_missing_return_desc() {
        let mut docs = LuaApiDocs::new();
        docs.register(
            FunctionDoc::new("fn_z", "fn_z() -> string", "desc", ApiCategory::Utility)
                .returns("string", ""),
        );
        let mut val = DocValidator::new();
        let report = val.validate(&docs);
        assert!(!report.missing_return_desc.is_empty());
    }

    #[test]
    fn test_doc_validator_report_is_valid_when_no_issues() {
        let docs = LuaApiDocs::new();
        let mut val = DocValidator::new();
        let report = val.validate(&docs);
        assert!(report.is_valid());
        assert_eq!(report.issue_count(), 0);
    }

    #[test]
    fn test_doc_validator_clear() {
        let mut val = DocValidator::new();
        val.issues.push("test issue".to_string());
        val.clear();
        assert!(val.issues.is_empty());
    }

    // ── CodeExample ──────────────────────────────────────────────────────────

    #[test]
    fn test_code_example_with_output() {
        let ex = CodeExample::new("test", "print(1)").with_output("1");
        assert_eq!(ex.expected_output.as_deref(), Some("1"));
    }

    #[test]
    fn test_code_example_no_output() {
        let ex = CodeExample::new("no output", "local x = 1");
        assert!(ex.expected_output.is_none());
    }

    // ── ParamDoc ─────────────────────────────────────────────────────────────

    #[test]
    fn test_param_doc_optional() {
        let p = ParamDoc::new("n", "number", "count").optional("10");
        assert!(p.optional);
        assert_eq!(p.default.as_deref(), Some("10"));
    }

    #[test]
    fn test_param_doc_required() {
        let p = ParamDoc::new("path", "string", "file path");
        assert!(!p.optional);
        assert!(p.default.is_none());
    }
}
