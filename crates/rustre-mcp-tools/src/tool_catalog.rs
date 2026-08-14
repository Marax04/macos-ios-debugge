//! `tool_catalog` — Tool catalog for the MCP tools crate.
//!
//! Provides [`ToolCatalog`], [`ToolEntry`], [`ToolCategory`], [`ToolVersion`],
//! [`ToolDependency`], and [`CatalogSearch`] for registering, discovering,
//! and searching MCP tools.

use std::collections::HashMap;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Error ───────────────────────────────────────────────────────────────────

/// Errors produced by the catalog subsystem.
#[derive(Debug, Error, Clone)]
pub enum CatalogError {
    #[error("tool '{0}' not found in catalog")]
    NotFound(String),

    #[error("tool '{0}' already registered")]
    AlreadyRegistered(String),

    #[error("version parse error for '{0}': {1}")]
    VersionParse(String, String),

    #[error("dependency cycle detected: {0}")]
    DependencyCycle(String),

    #[error("incompatible dependency: '{0}' requires '{1}' >= {2}")]
    IncompatibleDependency(String, String, String),

    #[error("catalog is read-only")]
    ReadOnly,

    #[error("invalid tool config: {0}")]
    InvalidConfig(String),
}

// ─── ToolCategory ─────────────────────────────────────────────────────────────

/// High-level category for a tool.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ToolCategory {
    Disassembly,
    Decompilation,
    Analysis,
    Patching,
    Debugging,
    Emulation,
    Fuzzing,
    Signature,
    ThreatIntel,
    Scripting,
    Utilities,
    Visualization,
    Export,
    Import,
    Custom(String),
}

impl std::fmt::Display for ToolCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Custom(s) => write!(f, "custom:{s}"),
            _ => write!(f, "{self:?}"),
        }
    }
}

impl ToolCategory {
    /// Parse loosely from a string.
    #[must_use]
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "disassembly" | "disasm" => Self::Disassembly,
            "decompilation" | "decompile" => Self::Decompilation,
            "analysis" | "analyze" => Self::Analysis,
            "patch" | "patching" => Self::Patching,
            "debug" | "debugging" => Self::Debugging,
            "emulation" | "emu" => Self::Emulation,
            "fuzzing" | "fuzz" => Self::Fuzzing,
            "signature" | "sig" | "yara" => Self::Signature,
            "threat_intel" | "ti" | "threatintel" => Self::ThreatIntel,
            "script" | "scripting" => Self::Scripting,
            "util" | "utilities" => Self::Utilities,
            "visual" | "visualization" => Self::Visualization,
            "export" => Self::Export,
            "import" => Self::Import,
            other => Self::Custom(other.to_string()),
        }
    }
}

// ─── ToolVersion ──────────────────────────────────────────────────────────────

/// Semantic version of a tool.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ToolVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub pre: String,
}

impl ToolVersion {
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
            pre: String::new(),
        }
    }

    #[must_use]
    pub fn with_pre(mut self, pre: impl Into<String>) -> Self {
        self.pre = pre.into();
        self
    }

    /// Parse a semver string like `"1.2.3"` or `"1.2.3-beta"`.
    ///
    /// # Errors
    /// Returns `Err` if the string is not a valid semver version.
    pub fn parse(s: &str) -> Result<Self, CatalogError> {
        let (ver_part, pre) = if let Some((v, p)) = s.split_once('-') {
            (v, p.to_string())
        } else {
            (s, String::new())
        };
        let parts: Vec<&str> = ver_part.split('.').collect();
        if parts.len() < 2 {
            return Err(CatalogError::VersionParse(
                s.to_string(),
                "expected at least major.minor".to_string(),
            ));
        }
        let major = parts[0]
            .parse()
            .map_err(|_| CatalogError::VersionParse(s.to_string(), "bad major".to_string()))?;
        let minor = parts[1]
            .parse()
            .map_err(|_| CatalogError::VersionParse(s.to_string(), "bad minor".to_string()))?;
        let patch = if parts.len() > 2 {
            parts[2]
                .parse()
                .map_err(|_| CatalogError::VersionParse(s.to_string(), "bad patch".to_string()))?
        } else {
            0
        };
        Ok(Self {
            major,
            minor,
            patch,
            pre,
        })
    }

    /// Is this version compatible with `other` (same major, >= minor)?
    #[must_use]
    pub const fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major && self.minor >= other.minor
    }
}

impl std::fmt::Display for ToolVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.pre.is_empty() {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        } else {
            write!(
                f,
                "{}.{}.{}-{}",
                self.major, self.minor, self.patch, self.pre
            )
        }
    }
}

// ─── ToolDependency ───────────────────────────────────────────────────────────

/// A dependency declaration on another tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDependency {
    pub tool_name: String,
    pub min_version: ToolVersion,
    pub optional: bool,
}

impl ToolDependency {
    #[must_use]
    pub fn required(tool_name: impl Into<String>, min_version: ToolVersion) -> Self {
        Self {
            tool_name: tool_name.into(),
            min_version,
            optional: false,
        }
    }

    #[must_use]
    pub fn optional(tool_name: impl Into<String>, min_version: ToolVersion) -> Self {
        Self {
            tool_name: tool_name.into(),
            min_version,
            optional: true,
        }
    }
}

// ─── ToolEntry ────────────────────────────────────────────────────────────────

/// Full metadata record for a tool in the catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolEntry {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub category: ToolCategory,
    pub version: ToolVersion,
    pub author: String,
    pub license: String,
    pub homepage: String,
    pub tags: Vec<String>,
    pub dependencies: Vec<ToolDependency>,
    pub parameters_schema: serde_json::Value,
    pub enabled: bool,
    pub deprecated: bool,
    pub deprecation_note: String,
    pub call_count: u64,
}

impl ToolEntry {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        display_name: impl Into<String>,
        description: impl Into<String>,
        category: ToolCategory,
        version: ToolVersion,
    ) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
            description: description.into(),
            category,
            version,
            author: String::new(),
            license: "MIT".to_string(),
            homepage: String::new(),
            tags: Vec::new(),
            dependencies: Vec::new(),
            parameters_schema: serde_json::json!({"type": "object"}),
            enabled: true,
            deprecated: false,
            deprecation_note: String::new(),
            call_count: 0,
        }
    }

    #[must_use]
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = author.into();
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    #[must_use]
    pub fn with_dep(mut self, dep: ToolDependency) -> Self {
        self.dependencies.push(dep);
        self
    }

    #[must_use]
    pub fn with_schema(mut self, schema: serde_json::Value) -> Self {
        self.parameters_schema = schema;
        self
    }

    #[must_use]
    pub fn deprecated_with(mut self, note: impl Into<String>) -> Self {
        self.deprecated = true;
        self.deprecation_note = note.into();
        self
    }

    /// Increment call count.
    pub const fn increment_call_count(&mut self) {
        self.call_count += 1;
    }

    #[must_use]
    pub const fn is_usable(&self) -> bool {
        self.enabled && !self.deprecated
    }
}

// ─── CatalogSearch ────────────────────────────────────────────────────────────

/// Search query builder for the catalog.
#[derive(Debug, Default)]
pub struct CatalogSearch {
    pub keyword: Option<String>,
    pub category: Option<ToolCategory>,
    pub tag: Option<String>,
    pub enabled_only: bool,
    pub exclude_deprecated: bool,
    pub max_results: Option<usize>,
}

impl CatalogSearch {
    #[must_use]
    pub fn new() -> Self {
        Self {
            enabled_only: true,
            exclude_deprecated: true,
            ..Default::default()
        }
    }

    #[must_use]
    pub fn keyword(mut self, kw: impl Into<String>) -> Self {
        self.keyword = Some(kw.into());
        self
    }

    #[must_use]
    pub fn category(mut self, cat: ToolCategory) -> Self {
        self.category = Some(cat);
        self
    }

    #[must_use]
    pub fn tag(mut self, t: impl Into<String>) -> Self {
        self.tag = Some(t.into());
        self
    }

    #[must_use]
    pub const fn include_disabled(mut self) -> Self {
        self.enabled_only = false;
        self
    }

    #[must_use]
    pub const fn include_deprecated(mut self) -> Self {
        self.exclude_deprecated = false;
        self
    }

    #[must_use]
    pub const fn limit(mut self, n: usize) -> Self {
        self.max_results = Some(n);
        self
    }

    /// Apply search to an iterator of tool entries.
    pub fn apply<'a>(&self, entries: impl Iterator<Item = &'a ToolEntry>) -> Vec<&'a ToolEntry> {
        let kw = self.keyword.as_deref().map(str::to_lowercase);
        let mut results: Vec<&ToolEntry> = entries
            .filter(|e| {
                if self.enabled_only && !e.enabled {
                    return false;
                }
                if self.exclude_deprecated && e.deprecated {
                    return false;
                }
                if let Some(cat) = &self.category
                    && &e.category != cat {
                        return false;
                    }
                if let Some(tag) = &self.tag
                    && !e.tags.iter().any(|t| t == tag) {
                        return false;
                    }
                if let Some(kw) = &kw {
                    let kw_ref: &str = kw;
                    if !e.name.to_lowercase().contains(kw_ref)
                        && !e.description.to_lowercase().contains(kw_ref)
                        && !e.tags.iter().any(|t| t.to_lowercase().contains(kw_ref))
                    {
                        return false;
                    }
                }
                true
            })
            .collect();
        if let Some(n) = self.max_results {
            results.truncate(n);
        }
        results
    }
}

// ─── ToolCatalog ──────────────────────────────────────────────────────────────

/// Central registry of all MCP tools available in the platform.
pub struct ToolCatalog {
    entries: RwLock<HashMap<String, ToolEntry>>,
    read_only: bool,
}

impl ToolCatalog {
    /// Create an empty catalog.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            read_only: false,
        }
    }

    /// Create a catalog pre-populated with built-in RE tools.
    #[must_use]
    pub fn with_builtins() -> Self {
        let cat = Self::new();
        for entry in builtin_entries() {
            cat.entries.write().insert(entry.name.clone(), entry);
        }
        cat
    }

    /// Register a new tool entry.
    ///
    /// # Errors
    /// Returns `Err` if the catalog is read-only or the tool is already registered.
    pub fn register(&self, entry: ToolEntry) -> Result<(), CatalogError> {
        if self.read_only {
            return Err(CatalogError::ReadOnly);
        }
        let mut guard = self.entries.write();
        if guard.contains_key(&entry.name) {
            return Err(CatalogError::AlreadyRegistered(entry.name));
        }
        guard.insert(entry.name.clone(), entry);
        drop(guard);
        Ok(())
    }

    /// Update or replace a tool entry.
    ///
    /// # Errors
    /// Returns `Err` if the catalog is read-only.
    pub fn upsert(&self, entry: ToolEntry) -> Result<(), CatalogError> {
        if self.read_only {
            return Err(CatalogError::ReadOnly);
        }
        self.entries.write().insert(entry.name.clone(), entry);
        Ok(())
    }

    /// Remove a tool by name.
    pub fn remove(&self, name: &str) -> Option<ToolEntry> {
        self.entries.write().remove(name)
    }

    /// Look up a tool by name.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<ToolEntry> {
        self.entries.read().get(name).cloned()
    }

    /// Total number of registered tools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// List all tool names.
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.entries.read().keys().cloned().collect();
        names.sort();
        names
    }

    /// Execute a catalog search.
    #[must_use]
    pub fn search(&self, query: &CatalogSearch) -> Vec<ToolEntry> {
        let guard = self.entries.read();
        query.apply(guard.values()).into_iter().cloned().collect()
    }

    /// List all tools in a category.
    #[must_use]
    pub fn by_category(&self, cat: &ToolCategory) -> Vec<ToolEntry> {
        self.entries
            .read()
            .values()
            .filter(|e| &e.category == cat)
            .cloned()
            .collect()
    }

    /// List all unique categories present.
    #[must_use]
    pub fn categories(&self) -> Vec<ToolCategory> {
        let mut cats: Vec<ToolCategory> = self
            .entries
            .read()
            .values()
            .map(|e| e.category.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        cats.sort_by_key(std::string::ToString::to_string);
        cats
    }

    /// Increment the call count for a named tool.
    pub fn record_call(&self, name: &str) {
        if let Some(e) = self.entries.write().get_mut(name) {
            e.increment_call_count();
        }
    }

    /// Return tools sorted by call count (most-used first).
    #[must_use]
    pub fn most_used(&self, n: usize) -> Vec<ToolEntry> {
        let mut entries: Vec<ToolEntry> = self.entries.read().values().cloned().collect();
        entries.sort_by(|a, b| b.call_count.cmp(&a.call_count));
        entries.truncate(n);
        entries
    }

    /// Disable a tool.
    pub fn disable(&self, name: &str) {
        if let Some(e) = self.entries.write().get_mut(name) {
            e.enabled = false;
        }
    }

    /// Enable a tool.
    pub fn enable(&self, name: &str) {
        if let Some(e) = self.entries.write().get_mut(name) {
            e.enabled = true;
        }
    }

    /// Make catalog read-only.
    pub const fn seal(&mut self) {
        self.read_only = true;
    }

    /// Resolve dependencies for a given tool (returns required tool names).
    ///
    /// # Errors
    /// Returns `Err` if the tool is not found in the catalog.
    pub fn resolve_deps(&self, name: &str) -> Result<Vec<String>, CatalogError> {
        let entry = self
            .entries
            .read()
            .get(name)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound(name.to_string()))?;

        let mut resolved = Vec::new();
        for dep in &entry.dependencies {
            if dep.optional {
                continue;
            }
            match self.entries.read().get(&dep.tool_name) {
                None => {
                    return Err(CatalogError::IncompatibleDependency(
                        name.to_string(),
                        dep.tool_name.clone(),
                        dep.min_version.to_string(),
                    ));
                }
                Some(dep_entry) => {
                    if !dep_entry.version.is_compatible_with(&dep.min_version) {
                        return Err(CatalogError::IncompatibleDependency(
                            name.to_string(),
                            dep.tool_name.clone(),
                            dep.min_version.to_string(),
                        ));
                    }
                    resolved.push(dep.tool_name.clone());
                }
            }
        }
        Ok(resolved)
    }
}

impl Default for ToolCatalog {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Built-in entries ─────────────────────────────────────────────────────────

fn builtin_entries() -> Vec<ToolEntry> {
    let mut out = builtin_core_entries();
    out.extend(builtin_analysis_entries());
    out.extend(builtin_utility_entries());
    out
}

fn builtin_core_entries() -> Vec<ToolEntry> {
    let v1 = ToolVersion::new(1, 0, 0);
    vec![
        ToolEntry::new(
            "disassemble_function",
            "Disassemble Function",
            "Disassemble a function by address",
            ToolCategory::Disassembly,
            v1.clone(),
        )
        .with_tag("disasm")
        .with_tag("function"),
        ToolEntry::new(
            "decompile_function",
            "Decompile Function",
            "Decompile a function to pseudo-C",
            ToolCategory::Decompilation,
            v1.clone(),
        )
        .with_tag("decompile")
        .with_tag("pseudocode"),
        ToolEntry::new(
            "decompile_batch_all",
            "Decompile All Functions",
            "Decompile every detected function in a binary and dump per-function .c files",
            ToolCategory::Decompilation,
            v1.clone(),
        )
        .with_tag("decompile")
        .with_tag("batch"),
        ToolEntry::new(
            "get_function_xrefs",
            "Get Function Cross-References",
            "Get all cross-references to/from a function",
            ToolCategory::Analysis,
            v1.clone(),
        )
        .with_tag("xref"),
        ToolEntry::new(
            "analysis_xref_call_graph_root_functions",
            "Call-Graph Root Functions",
            "Return function entries with zero incoming direct-call xrefs",
            ToolCategory::Analysis,
            v1.clone(),
        )
        .with_tag("xref")
        .with_tag("callgraph"),
        ToolEntry::new(
            "analysis_xref_string_ref_counts",
            "String-Literal Reference Counts",
            "Count how many xrefs target each supplied string-literal address",
            ToolCategory::Analysis,
            v1.clone(),
        )
        .with_tag("xref")
        .with_tag("strings"),
        ToolEntry::new(
            "rename_function",
            "Rename Function",
            "Rename a function at a given address",
            ToolCategory::Analysis,
            v1.clone(),
        )
        .with_tag("rename"),
        ToolEntry::new(
            "set_type",
            "Set Variable/Parameter Type",
            "Apply a C type to a variable or parameter",
            ToolCategory::Analysis,
            v1.clone(),
        )
        .with_tag("type"),
        ToolEntry::new(
            "add_comment",
            "Add Comment",
            "Add inline comment at an address",
            ToolCategory::Analysis,
            v1.clone(),
        )
        .with_tag("comment"),
        ToolEntry::new(
            "list_imports",
            "List Imports",
            "List all imported symbols",
            ToolCategory::Analysis,
            v1.clone(),
        )
        .with_tag("imports")
        .with_tag("symbols"),
        ToolEntry::new(
            "list_exports",
            "List Exports",
            "List all exported symbols",
            ToolCategory::Analysis,
            v1.clone(),
        )
        .with_tag("exports")
        .with_tag("symbols"),
        ToolEntry::new(
            "list_strings",
            "List Strings",
            "Extract strings from a binary",
            ToolCategory::Analysis,
            v1.clone(),
        )
        .with_tag("strings"),
        ToolEntry::new(
            "list_functions",
            "List Functions",
            "List all functions in the binary",
            ToolCategory::Analysis,
            v1.clone(),
        )
        .with_tag("functions"),
    ]
}

fn builtin_analysis_entries() -> Vec<ToolEntry> {
    let v1 = ToolVersion::new(1, 0, 0);
    vec![
        ToolEntry::new(
            "yara_scan",
            "YARA Scan",
            "Scan binary with YARA rules",
            ToolCategory::Signature,
            v1.clone(),
        )
        .with_tag("yara")
        .with_tag("signature"),
        ToolEntry::new(
            "apply_patch",
            "Apply Binary Patch",
            "Apply a byte patch at an address",
            ToolCategory::Patching,
            v1.clone(),
        )
        .with_tag("patch"),
        ToolEntry::new(
            "set_breakpoint",
            "Set Breakpoint",
            "Set a debugging breakpoint",
            ToolCategory::Debugging,
            v1.clone(),
        )
        .with_tag("debug")
        .with_tag("breakpoint"),
        ToolEntry::new(
            "emulate_function",
            "Emulate Function",
            "Emulate a function using Unicorn",
            ToolCategory::Emulation,
            v1.clone(),
        )
        .with_tag("emulate")
        .with_tag("unicorn"),
        ToolEntry::new(
            "generate_flirt_sig",
            "Generate FLIRT Signature",
            "Generate a FLIRT signature for a function",
            ToolCategory::Signature,
            v1.clone(),
        )
        .with_tag("flirt"),
        ToolEntry::new(
            "apply_flirt_signatures",
            "Apply FLIRT Signatures",
            "Scan a loaded binary with FLIRT signature packs and rename sub_* functions",
            ToolCategory::Signature,
            v1.clone(),
        )
        .with_tag("flirt")
        .with_tag("autoname"),
    ]
}

fn builtin_utility_entries() -> Vec<ToolEntry> {
    let v1 = ToolVersion::new(1, 0, 0);
    vec![
        ToolEntry::new(
            "function_list_by_kind",
            "List Functions by Kind",
            "List functions filtered by library/user classification (feature K). \
             Mirrors the library-vs-user split shown by mainstream disassemblers.",
            ToolCategory::Analysis,
            v1.clone(),
        )
        .with_tag("library")
        .with_tag("classification")
        .with_tag("functions")
        .with_schema(serde_json::json!({
            "type": "object",
            "required": ["binary_path"],
            "properties": {
                "binary_path":    { "type": "string" },
                "kind":           { "type": "string", "enum": ["library", "user", "all"] },
                "lib_name":       { "type": "string" },
                "limit":          { "type": "integer", "minimum": 0 },
                "min_confidence": { "type": "integer", "minimum": 0, "maximum": 100 }
            }
        })),
        ToolEntry::new(
            "lookup_threat_intel",
            "Lookup Threat Intel",
            "Query threat intelligence for a hash or domain",
            ToolCategory::ThreatIntel,
            v1.clone(),
        )
        .with_tag("ti")
        .with_tag("ioc"),
        ToolEntry::new(
            "run_script",
            "Run Script",
            "Execute a Python/Lua script in the analysis context",
            ToolCategory::Scripting,
            v1.clone(),
        )
        .with_tag("script"),
        ToolEntry::new(
            "export_binary",
            "Export Binary",
            "Export the current binary to a file",
            ToolCategory::Export,
            v1.clone(),
        )
        .with_tag("export"),
        ToolEntry::new(
            "import_symbols",
            "Import Symbols",
            "Import symbol information from PDB/DWARF",
            ToolCategory::Import,
            v1.clone(),
        )
        .with_tag("symbols")
        .with_tag("pdb"),
        ToolEntry::new(
            "show_callgraph",
            "Show Callgraph",
            "Visualize function call graph",
            ToolCategory::Visualization,
            v1.clone(),
        )
        .with_tag("graph")
        .with_tag("callgraph"),
        ToolEntry::new(
            "hex_view",
            "Hex View",
            "View raw bytes at an address",
            ToolCategory::Utilities,
            v1.clone(),
        )
        .with_tag("hex"),
        ToolEntry::new(
            "search_bytes",
            "Search Bytes",
            "Search for a byte pattern in the binary",
            ToolCategory::Analysis,
            v1.clone(),
        )
        .with_tag("search")
        .with_tag("bytes"),
        ToolEntry::new(
            "diff_functions",
            "Diff Functions",
            "Diff two function versions",
            ToolCategory::Analysis,
            v1.clone(),
        )
        .with_tag("diff"),
        ToolEntry::new(
            "stack_trace",
            "Stack Trace",
            "Get the current stack trace during debugging",
            ToolCategory::Debugging,
            v1.clone(),
        )
        .with_tag("debug")
        .with_tag("stack"),
        ToolEntry::new(
            "survey_binary",
            "Survey Binary",
            "One-shot triage aggregator: loads a binary and returns loader metadata, \
             imports, sections, top-20 strings, function count, section entropy, and \
             call-target count in a single JSON object.",
            ToolCategory::Analysis,
            v1.clone(),
        )
        .with_tag("triage")
        .with_tag("survey")
        .with_tag("aggregator")
        .with_schema(serde_json::json!({
            "type": "object",
            "properties": {
                "session_id": { "type": "string" },
                "path":       { "type": "string" }
            }
        })),
        ToolEntry::new(
            "analysis.noreturn_infer",
            "Infer Noreturn Functions",
            "Run the gap-H noreturn inference pass (symbol + body + tail-call + \
             propagation) over the current view and return an addr -> evidence \
             map. Detects panic_fmt, panic_bounds_check, abort, ExitProcess, \
             rust_begin_unwind, __cxa_throw, and any function whose last \
             reachable block tail-calls one of them.",
            ToolCategory::Analysis,
            v1,
        )
        .with_tag("noreturn")
        .with_tag("signature")
        .with_tag("panic")
        .with_schema(serde_json::json!({
            "type": "object",
            "properties": {
                "binary_id": { "type": "string" },
                "propagation_threshold": { "type": "number", "minimum": 0.0, "maximum": 1.0 },
                "arch": { "type": "string", "enum": ["x86_64", "x86_32", "arm64"] }
            },
            "required": ["binary_id"]
        })),
    ]
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn cat() -> ToolCatalog {
        ToolCatalog::with_builtins()
    }

    // ── ToolVersion ───────────────────────────────────────────────────────────

    #[test]
    fn test_version_new() {
        let v = ToolVersion::new(1, 2, 3);
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn test_version_display() {
        assert_eq!(ToolVersion::new(1, 0, 0).to_string(), "1.0.0");
        assert_eq!(ToolVersion::new(2, 3, 4).to_string(), "2.3.4");
        assert_eq!(
            ToolVersion::new(1, 0, 0).with_pre("beta").to_string(),
            "1.0.0-beta"
        );
    }

    #[test]
    fn test_version_parse_ok() {
        let v = ToolVersion::parse("2.3.4").unwrap();
        assert_eq!(v, ToolVersion::new(2, 3, 4));
    }

    #[test]
    fn test_version_parse_with_pre() {
        let v = ToolVersion::parse("1.0.0-alpha").unwrap();
        assert_eq!(v.pre, "alpha");
    }

    #[test]
    fn test_version_parse_short() {
        let v = ToolVersion::parse("1.0").unwrap();
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_version_parse_error() {
        assert!(ToolVersion::parse("bad").is_err());
        assert!(ToolVersion::parse("1").is_err());
    }

    #[test]
    fn test_version_compatibility() {
        let v1 = ToolVersion::new(1, 2, 0);
        let v2 = ToolVersion::new(1, 1, 0);
        assert!(v1.is_compatible_with(&v2));
        assert!(!v2.is_compatible_with(&v1));
        let v3 = ToolVersion::new(2, 0, 0);
        assert!(!v1.is_compatible_with(&v3));
    }

    #[test]
    fn test_version_ordering() {
        assert!(ToolVersion::new(1, 2, 0) > ToolVersion::new(1, 1, 9));
        assert!(ToolVersion::new(2, 0, 0) > ToolVersion::new(1, 9, 9));
    }

    // ── ToolCategory ──────────────────────────────────────────────────────────

    #[test]
    fn test_category_display() {
        assert_eq!(ToolCategory::Disassembly.to_string(), "Disassembly");
        assert_eq!(ToolCategory::Custom("x".into()).to_string(), "custom:x");
    }

    #[test]
    fn test_category_from_str_loose() {
        assert_eq!(
            ToolCategory::from_str_loose("disasm"),
            ToolCategory::Disassembly
        );
        assert_eq!(
            ToolCategory::from_str_loose("YARA"),
            ToolCategory::Signature
        );
    }

    // ── ToolEntry ─────────────────────────────────────────────────────────────

    #[test]
    fn test_tool_entry_new() {
        let e = ToolEntry::new(
            "t1",
            "T1",
            "d",
            ToolCategory::Analysis,
            ToolVersion::new(1, 0, 0),
        );
        assert!(e.enabled);
        assert!(!e.deprecated);
        assert_eq!(e.call_count, 0);
    }

    #[test]
    fn test_tool_entry_is_usable() {
        let e = ToolEntry::new(
            "t",
            "T",
            "d",
            ToolCategory::Utilities,
            ToolVersion::new(1, 0, 0),
        );
        assert!(e.is_usable());
        let dep = e.deprecated_with("use v2");
        assert!(!dep.is_usable());
    }

    #[test]
    fn test_tool_entry_increment_call_count() {
        let mut e = ToolEntry::new(
            "t",
            "T",
            "d",
            ToolCategory::Utilities,
            ToolVersion::new(1, 0, 0),
        );
        e.increment_call_count();
        e.increment_call_count();
        assert_eq!(e.call_count, 2);
    }

    // ── ToolCatalog registration ───────────────────────────────────────────────

    #[test]
    fn test_catalog_with_builtins() {
        let c = cat();
        assert!(c.len() >= 20);
    }

    #[test]
    fn test_catalog_register_ok() {
        let c = ToolCatalog::new();
        let e = ToolEntry::new(
            "my_tool",
            "My",
            "d",
            ToolCategory::Utilities,
            ToolVersion::new(1, 0, 0),
        );
        c.register(e).unwrap();
        assert_eq!(c.len(), 1);
    }

    #[test]
    fn test_catalog_register_duplicate() {
        let c = ToolCatalog::new();
        let e = ToolEntry::new(
            "t",
            "T",
            "d",
            ToolCategory::Utilities,
            ToolVersion::new(1, 0, 0),
        );
        c.register(e.clone()).unwrap();
        let err = c.register(e).unwrap_err();
        assert!(matches!(err, CatalogError::AlreadyRegistered(_)));
    }

    #[test]
    fn test_catalog_upsert() {
        let c = ToolCatalog::new();
        let e1 = ToolEntry::new(
            "t",
            "T",
            "v1",
            ToolCategory::Utilities,
            ToolVersion::new(1, 0, 0),
        );
        let e2 = ToolEntry::new(
            "t",
            "T",
            "v2",
            ToolCategory::Utilities,
            ToolVersion::new(2, 0, 0),
        );
        c.upsert(e1).unwrap();
        c.upsert(e2).unwrap();
        assert_eq!(c.get("t").unwrap().version, ToolVersion::new(2, 0, 0));
    }

    #[test]
    fn test_catalog_remove() {
        let c = cat();
        assert!(c.remove("hex_view").is_some());
        assert!(c.get("hex_view").is_none());
    }

    #[test]
    fn test_catalog_get_not_found() {
        assert!(cat().get("nonexistent").is_none());
    }

    #[test]
    fn test_catalog_names_sorted() {
        let names = cat().names();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    // ── CatalogSearch ─────────────────────────────────────────────────────────

    #[test]
    fn test_search_keyword() {
        let c = cat();
        let results = c.search(&CatalogSearch::new().keyword("disasm"));
        assert!(!results.is_empty());
    }

    #[test]
    fn test_search_category() {
        let c = cat();
        let results = c.search(&CatalogSearch::new().category(ToolCategory::Disassembly));
        assert!(!results.is_empty());
        for r in &results {
            assert_eq!(r.category, ToolCategory::Disassembly);
        }
    }

    #[test]
    fn test_search_tag() {
        let c = cat();
        let results = c.search(&CatalogSearch::new().tag("xref"));
        assert!(!results.is_empty());
    }

    #[test]
    fn test_search_limit() {
        let c = cat();
        let results = c.search(&CatalogSearch::new().limit(3));
        assert!(results.len() <= 3);
    }

    #[test]
    fn test_search_no_match() {
        let c = cat();
        let results = c.search(&CatalogSearch::new().keyword("xyzzy_nope_xyz"));
        assert!(results.is_empty());
    }

    // ── Enable/disable/call count ─────────────────────────────────────────────

    #[test]
    fn test_catalog_enable_disable() {
        let c = cat();
        c.disable("hex_view");
        assert!(!c.get("hex_view").unwrap().enabled);
        c.enable("hex_view");
        assert!(c.get("hex_view").unwrap().enabled);
    }

    #[test]
    fn test_catalog_record_call() {
        let c = cat();
        c.record_call("hex_view");
        c.record_call("hex_view");
        assert_eq!(c.get("hex_view").unwrap().call_count, 2);
    }

    #[test]
    fn test_catalog_most_used() {
        let c = cat();
        c.record_call("hex_view");
        c.record_call("hex_view");
        c.record_call("disassemble_function");
        let most = c.most_used(2);
        assert_eq!(most.len(), 2);
        assert_eq!(most[0].name, "hex_view");
    }

    // ── Categories ────────────────────────────────────────────────────────────

    #[test]
    fn test_catalog_categories_non_empty() {
        let cats = cat().categories();
        assert!(!cats.is_empty());
        assert!(cats.contains(&ToolCategory::Disassembly));
    }

    #[test]
    fn test_catalog_by_category() {
        let tools = cat().by_category(&ToolCategory::Debugging);
        assert!(!tools.is_empty());
    }

    // ── Dependency resolution ─────────────────────────────────────────────────

    #[test]
    fn test_resolve_deps_no_deps() {
        let c = cat();
        let deps = c.resolve_deps("hex_view").unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn test_resolve_deps_not_found() {
        let c = cat();
        let err = c.resolve_deps("ghost").unwrap_err();
        assert!(matches!(err, CatalogError::NotFound(_)));
    }

    // ── CatalogError display ──────────────────────────────────────────────────

    #[test]
    fn test_catalog_error_display() {
        let e = CatalogError::NotFound("x".into());
        assert!(e.to_string().contains('x'));
        let e2 = CatalogError::AlreadyRegistered("y".into());
        assert!(e2.to_string().contains('y'));
        let e3 = CatalogError::DependencyCycle("cycle".into());
        assert!(e3.to_string().contains("cycle"));
    }
}
