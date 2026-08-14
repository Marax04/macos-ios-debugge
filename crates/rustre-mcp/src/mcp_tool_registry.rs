//! High-level MCP tool registry for the MCP server.
//!
//! Provides [`ToolRegistry`] for registering tools with structured
//! [`ToolDef`] / [`ToolParam`] definitions, routing tool calls to handlers,
//! validating inputs, generating Markdown documentation, and emitting MCP
//! `tools/list` JSON.
//!
//! # Distinction from `tool_registry`
//!
//! This module is the **high-level** definition layer.  Tools are described
//! via [`ToolDef`] + [`ToolParam`] structs that carry category, deprecation
//! metadata, enum constraints, and default values.  The registry tracks
//! call and error counts via atomic counters, and can produce a `CategoryIndex`
//! for O(1) category lookups.  Use this module when implementing the MCP
//! protocol `tools/list` and `tools/call` endpoints.
//!
//! [`crate::tool_registry`] is the **low-level** handler store: tools are
//! registered as opaque closures alongside a lightweight [`crate::tool_registry::InputSchema`].
//! It offers `Arc`-clone semantics, tag filtering, and cross-registry merging.
//! Use that module when you need a cheap-to-share dispatcher without full
//! tool-definition metadata.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

// ─────────────────────────────────────────────────────────────────────────────
// Error
// ─────────────────────────────────────────────────────────────────────────────

/// Errors produced by the tool registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// No tool was found under the given name.
    NotFound(String),
    /// Input validation failed.
    ValidationError { tool: String, message: String },
    /// The handler returned an error.
    HandlerError { tool: String, message: String },
    /// A tool with the given name was already registered.
    AlreadyRegistered(String),
    /// The JSON schema for a parameter was malformed.
    BadSchema { param: String, message: String },
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(n) => write!(f, "tool not found: {n}"),
            Self::ValidationError { tool, message } => {
                write!(f, "validation error in '{tool}': {message}")
            }
            Self::HandlerError { tool, message } => {
                write!(f, "handler error in '{tool}': {message}")
            }
            Self::AlreadyRegistered(n) => write!(f, "tool already registered: {n}"),
            Self::BadSchema { param, message } => {
                write!(f, "bad schema for param '{param}': {message}")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

// ─────────────────────────────────────────────────────────────────────────────
// ParamType — JSON Schema primitive types
// ─────────────────────────────────────────────────────────────────────────────

/// A JSON Schema primitive type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamType {
    /// JSON string.
    String,
    /// JSON number (integer or float).
    Number,
    /// JSON integer.
    Integer,
    /// JSON boolean.
    Boolean,
    /// JSON array.
    Array,
    /// JSON object.
    Object,
    /// JSON null.
    Null,
    /// Any JSON value.
    Any,
}

impl ParamType {
    /// Parse from a JSON Schema `"type"` string.
    #[must_use]
    pub fn from_str(s: &str) -> Self {
        match s {
            "string" => Self::String,
            "number" => Self::Number,
            "integer" => Self::Integer,
            "boolean" => Self::Boolean,
            "array" => Self::Array,
            "object" => Self::Object,
            "null" => Self::Null,
            _ => Self::Any,
        }
    }

    /// Return the JSON Schema string for this type.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Number => "number",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
            Self::Array => "array",
            Self::Object => "object",
            Self::Null => "null",
            Self::Any => "any",
        }
    }

    /// Return `true` if a JSON value matches this type.
    #[must_use]
    pub fn matches(&self, v: &serde_json::Value) -> bool {
        match self {
            Self::String => v.is_string(),
            Self::Number => v.is_number(),
            Self::Integer => v.is_i64() || v.is_u64(),
            Self::Boolean => v.is_boolean(),
            Self::Array => v.is_array(),
            Self::Object => v.is_object(),
            Self::Null => v.is_null(),
            Self::Any => true,
        }
    }
}

impl fmt::Display for ParamType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolParam — one parameter definition
// ─────────────────────────────────────────────────────────────────────────────

/// One parameter in a tool's JSON Schema input definition.
#[derive(Debug, Clone)]
pub struct ToolParam {
    /// Parameter name.
    pub name: String,
    /// Expected JSON type.
    pub ty: ParamType,
    /// Human-readable description.
    pub description: String,
    /// Whether this parameter must be present.
    pub required: bool,
    /// Default value (used in documentation only — not auto-applied).
    pub default: Option<serde_json::Value>,
    /// Enumeration of allowed values, if constrained.
    pub enum_values: Vec<serde_json::Value>,
}

impl ToolParam {
    /// Create a required string parameter.
    #[must_use]
    pub fn required_string(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ty: ParamType::String,
            description: description.into(),
            required: true,
            default: None,
            enum_values: Vec::new(),
        }
    }

    /// Create a required integer parameter.
    #[must_use]
    pub fn required_integer(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ty: ParamType::Integer,
            description: description.into(),
            required: true,
            default: None,
            enum_values: Vec::new(),
        }
    }

    /// Create an optional parameter of the given type.
    #[must_use]
    pub fn optional(
        name: impl Into<String>,
        ty: ParamType,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            ty,
            description: description.into(),
            required: false,
            default: None,
            enum_values: Vec::new(),
        }
    }

    /// Set the default value.
    #[must_use]
    pub fn with_default(mut self, v: serde_json::Value) -> Self {
        self.default = Some(v);
        self
    }

    /// Restrict to a set of allowed values.
    #[must_use]
    pub fn with_enum(mut self, values: Vec<serde_json::Value>) -> Self {
        self.enum_values = values;
        self
    }

    /// Validate `value` against this parameter's constraints.
    ///
    /// Returns `Ok(())` if the value is acceptable, or an error message.
    pub fn validate(&self, value: &serde_json::Value) -> Result<(), String> {
        if !self.ty.matches(value) && !matches!(self.ty, ParamType::Any) {
            return Err(format!(
                "expected type '{}' but got '{}'",
                self.ty,
                json_type_name(value)
            ));
        }
        if !self.enum_values.is_empty() && !self.enum_values.contains(value) {
            return Err(format!(
                "value not in allowed enum: {:?}",
                self.enum_values
            ));
        }
        Ok(())
    }

    /// Serialise this parameter to a JSON Schema property object.
    #[must_use]
    pub fn to_json_schema(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({
            "type": self.ty.as_str(),
            "description": self.description,
        });
        if !self.enum_values.is_empty() {
            obj["enum"] = serde_json::Value::Array(self.enum_values.clone());
        }
        if let Some(def) = &self.default {
            obj["default"] = def.clone();
        }
        obj
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolDef — complete tool definition
// ─────────────────────────────────────────────────────────────────────────────

/// The complete definition of one MCP tool: name, description, parameters.
#[derive(Debug, Clone)]
pub struct ToolDef {
    /// Unique tool name (e.g. `"binary.load"`).
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Version string for this tool definition.
    pub version: String,
    /// Category (for documentation grouping).
    pub category: String,
    /// All accepted parameters.
    pub params: Vec<ToolParam>,
    /// Whether this tool is deprecated.
    pub deprecated: bool,
    /// Replacement tool name if deprecated.
    pub deprecated_replacement: Option<String>,
}

impl ToolDef {
    /// Create a new tool definition.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        version: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            version: version.into(),
            category: String::from("general"),
            params: Vec::new(),
            deprecated: false,
            deprecated_replacement: None,
        }
    }

    /// Set the category.
    #[must_use]
    pub fn with_category(mut self, cat: impl Into<String>) -> Self {
        self.category = cat.into();
        self
    }

    /// Add a parameter.
    #[must_use]
    pub fn with_param(mut self, p: ToolParam) -> Self {
        self.params.push(p);
        self
    }

    /// Mark this tool as deprecated.
    #[must_use]
    pub fn deprecated(mut self, replacement: impl Into<String>) -> Self {
        self.deprecated = true;
        self.deprecated_replacement = Some(replacement.into());
        self
    }

    /// Return names of all required parameters.
    #[must_use]
    pub fn required_params(&self) -> Vec<&str> {
        self.params
            .iter()
            .filter(|p| p.required)
            .map(|p| p.name.as_str())
            .collect()
    }

    /// Return names of all optional parameters.
    #[must_use]
    pub fn optional_params(&self) -> Vec<&str> {
        self.params
            .iter()
            .filter(|p| !p.required)
            .map(|p| p.name.as_str())
            .collect()
    }

    /// Find a parameter by name.
    #[must_use]
    pub fn param(&self, name: &str) -> Option<&ToolParam> {
        self.params.iter().find(|p| p.name == name)
    }

    /// Validate `input` (a JSON object) against all parameters.
    pub fn validate_input(&self, input: &serde_json::Value) -> Result<(), RegistryError> {
        let obj = input.as_object().ok_or_else(|| RegistryError::ValidationError {
            tool: self.name.clone(),
            message: "input must be a JSON object".into(),
        })?;

        for p in &self.params {
            if p.required && !obj.contains_key(&p.name) {
                return Err(RegistryError::ValidationError {
                    tool: self.name.clone(),
                    message: format!("missing required parameter '{}'", p.name),
                });
            }
            if let Some(v) = obj.get(&p.name) {
                p.validate(v).map_err(|msg| RegistryError::ValidationError {
                    tool: self.name.clone(),
                    message: format!("parameter '{}': {msg}", p.name),
                })?;
            }
        }
        Ok(())
    }

    /// Generate a JSON Schema object for the `inputSchema` field of an MCP tool listing.
    #[must_use]
    pub fn input_schema(&self) -> serde_json::Value {
        let mut properties = serde_json::Map::new();
        let required: Vec<serde_json::Value> = self
            .params
            .iter()
            .filter(|p| p.required)
            .map(|p| serde_json::Value::String(p.name.clone()))
            .collect();

        for p in &self.params {
            properties.insert(p.name.clone(), p.to_json_schema());
        }

        serde_json::json!({
            "type": "object",
            "properties": properties,
            "required": required,
        })
    }

    /// Generate Markdown documentation for this tool.
    #[must_use]
    pub fn to_markdown(&self) -> String {
        let mut md = format!("## `{}`\n\n", self.name);
        if self.deprecated {
            md.push_str(&format!(
                "> **Deprecated.** Use `{}` instead.\n\n",
                self.deprecated_replacement.as_deref().unwrap_or("(none)")
            ));
        }
        md.push_str(&format!("{}\n\n", self.description));
        md.push_str(&format!("**Version:** {}\n\n", self.version));
        md.push_str(&format!("**Category:** {}\n\n", self.category));

        if !self.params.is_empty() {
            md.push_str("### Parameters\n\n");
            md.push_str("| Name | Type | Required | Description |\n");
            md.push_str("|------|------|----------|-------------|\n");
            for p in &self.params {
                md.push_str(&format!(
                    "| `{}` | `{}` | {} | {} |\n",
                    p.name,
                    p.ty,
                    if p.required { "yes" } else { "no" },
                    p.description
                ));
            }
            md.push('\n');
        }
        md
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolResult — the output from a handler invocation
// ─────────────────────────────────────────────────────────────────────────────

/// The result of a tool handler invocation.
#[derive(Debug, Clone)]
pub struct ToolResult {
    /// Tool name that produced this result.
    pub tool: String,
    /// The result payload as a JSON value.
    pub content: serde_json::Value,
    /// Whether the result is an error (content is the error description).
    pub is_error: bool,
    /// Elapsed time in microseconds.
    pub elapsed_us: u64,
    /// Non-fatal warnings emitted during execution.
    pub warnings: Vec<String>,
}

impl ToolResult {
    /// Create a successful result.
    #[must_use]
    pub fn ok(tool: impl Into<String>, content: serde_json::Value, elapsed_us: u64) -> Self {
        Self {
            tool: tool.into(),
            content,
            is_error: false,
            elapsed_us,
            warnings: Vec::new(),
        }
    }

    /// Create an error result.
    #[must_use]
    pub fn error(tool: impl Into<String>, message: impl Into<String>, elapsed_us: u64) -> Self {
        Self {
            tool: tool.into(),
            content: serde_json::Value::String(message.into()),
            is_error: true,
            elapsed_us,
            warnings: Vec::new(),
        }
    }

    /// Attach a warning.
    #[must_use]
    pub fn with_warning(mut self, w: impl Into<String>) -> Self {
        self.warnings.push(w.into());
        self
    }

    /// Return `true` if execution succeeded.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        !self.is_error
    }

    /// Serialise to the MCP `tools/call` response format.
    #[must_use]
    pub fn to_mcp_response(&self) -> serde_json::Value {
        serde_json::json!({
            "content": [
                {
                    "type": "text",
                    "text": self.content.to_string(),
                }
            ],
            "isError": self.is_error,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolHandler — callable function type
// ─────────────────────────────────────────────────────────────────────────────

/// A boxed handler function: takes JSON input and returns [`ToolResult`].
pub type ToolHandler = Arc<dyn Fn(serde_json::Value) -> ToolResult + Send + Sync>;

// ─────────────────────────────────────────────────────────────────────────────
// RegistryEntry — internal
// ─────────────────────────────────────────────────────────────────────────────

struct RegistryEntry {
    def: ToolDef,
    handler: ToolHandler,
    call_count: std::sync::atomic::AtomicU64,
    error_count: std::sync::atomic::AtomicU64,
}

impl fmt::Debug for RegistryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegistryEntry")
            .field("name", &self.def.name)
            .finish_non_exhaustive()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolRegistry
// ─────────────────────────────────────────────────────────────────────────────

/// Registry of MCP tools: stores [`ToolDef`]s and their [`ToolHandler`]s,
/// validates inputs, routes calls, and tracks per-tool metrics.
pub struct ToolRegistry {
    entries: parking_lot::RwLock<HashMap<String, Arc<RegistryEntry>>>,
}

impl fmt::Debug for ToolRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolRegistry")
            .field("tool_count", &self.entries.read().len())
            .finish_non_exhaustive()
    }
}

impl ToolRegistry {
    /// Create a new, empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    // ── Registration ─────────────────────────────────────────────────────────

    /// Register a tool definition with its handler.
    ///
    /// # Errors
    /// Returns [`RegistryError::AlreadyRegistered`] if a tool with the same
    /// name already exists. Use [`register_or_replace`] to overwrite.
    pub fn register(&self, def: ToolDef, handler: ToolHandler) -> Result<(), RegistryError> {
        let name = def.name.clone();
        let mut guard = self.entries.write();
        if guard.contains_key(&name) {
            return Err(RegistryError::AlreadyRegistered(name));
        }
        guard.insert(
            name,
            Arc::new(RegistryEntry {
                def,
                handler,
                call_count: std::sync::atomic::AtomicU64::new(0),
                error_count: std::sync::atomic::AtomicU64::new(0),
            }),
        );
        Ok(())
    }

    /// Register a tool, overwriting any existing tool with the same name.
    pub fn register_or_replace(&self, def: ToolDef, handler: ToolHandler) {
        let name = def.name.clone();
        self.entries.write().insert(
            name,
            Arc::new(RegistryEntry {
                def,
                handler,
                call_count: std::sync::atomic::AtomicU64::new(0),
                error_count: std::sync::atomic::AtomicU64::new(0),
            }),
        );
    }

    /// Unregister a tool by name. Returns `true` if it existed.
    pub fn unregister(&self, name: &str) -> bool {
        self.entries.write().remove(name).is_some()
    }

    // ── Lookup ───────────────────────────────────────────────────────────────

    /// Look up a tool definition by name.
    #[must_use]
    pub fn get_def(&self, name: &str) -> Option<ToolDef> {
        self.entries.read().get(name).map(|e| e.def.clone())
    }

    /// Return `true` if a tool with the given name is registered.
    #[must_use]
    pub fn has_tool(&self, name: &str) -> bool {
        self.entries.read().contains_key(name)
    }

    /// Return definitions of all registered tools (sorted by name).
    #[must_use]
    pub fn all_defs(&self) -> Vec<ToolDef> {
        let guard = self.entries.read();
        let mut defs: Vec<ToolDef> = guard.values().map(|e| e.def.clone()).collect();
        defs.sort_by(|a, b| a.name.cmp(&b.name));
        defs
    }

    /// Number of registered tools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// Return `true` if no tools are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// Return names of all registered tools (sorted).
    #[must_use]
    pub fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.entries.read().keys().cloned().collect();
        names.sort();
        names
    }

    // ── Call ─────────────────────────────────────────────────────────────────

    /// Call a tool by name with the given JSON input.
    ///
    /// Validates the input against the tool's parameter schema before invoking
    /// the handler. Returns a [`ToolResult`] (never panics on handler error).
    ///
    /// # Errors
    /// Returns [`RegistryError::NotFound`] or [`RegistryError::ValidationError`].
    pub fn call(&self, name: &str, input: serde_json::Value) -> Result<ToolResult, RegistryError> {
        let entry = self
            .entries
            .read()
            .get(name)
            .cloned()
            .ok_or_else(|| RegistryError::NotFound(name.to_string()))?;

        entry.def.validate_input(&input)?;

        let start = std::time::Instant::now();
        let result = (entry.handler)(input);
        let elapsed_us = start.elapsed().as_micros() as u64;

        entry
            .call_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if result.is_error {
            entry
                .error_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        Ok(ToolResult { elapsed_us, ..result })
    }

    // ── Metrics ──────────────────────────────────────────────────────────────

    /// Return per-tool call and error counts: `(call_count, error_count)`.
    #[must_use]
    pub fn metrics(&self, name: &str) -> Option<(u64, u64)> {
        self.entries.read().get(name).map(|e| {
            (
                e.call_count.load(std::sync::atomic::Ordering::Relaxed),
                e.error_count.load(std::sync::atomic::Ordering::Relaxed),
            )
        })
    }

    /// Return aggregate metrics across all tools: `(total_calls, total_errors)`.
    #[must_use]
    pub fn aggregate_metrics(&self) -> (u64, u64) {
        self.entries.read().values().fold((0u64, 0u64), |acc, e| {
            (
                acc.0 + e.call_count.load(std::sync::atomic::Ordering::Relaxed),
                acc.1 + e.error_count.load(std::sync::atomic::Ordering::Relaxed),
            )
        })
    }

    // ── Documentation ────────────────────────────────────────────────────────

    /// Generate a Markdown reference document for all registered tools.
    #[must_use]
    pub fn generate_docs(&self) -> String {
        let defs = self.all_defs();
        let mut md = String::from("# Tool Reference\n\n");

        // Group by category
        let mut by_category: HashMap<String, Vec<&ToolDef>> = HashMap::new();
        for def in &defs {
            by_category
                .entry(def.category.clone())
                .or_default()
                .push(def);
        }

        let mut cats: Vec<&String> = by_category.keys().collect();
        cats.sort();

        for cat in cats {
            md.push_str(&format!("# Category: {cat}\n\n"));
            for def in by_category[cat].iter() {
                md.push_str(&def.to_markdown());
            }
        }
        md
    }

    /// Serialise all tool definitions to the MCP `tools/list` response format.
    #[must_use]
    pub fn to_mcp_tools_list(&self) -> serde_json::Value {
        let tools: Vec<serde_json::Value> = self
            .all_defs()
            .into_iter()
            .map(|d| {
                serde_json::json!({
                    "name": d.name,
                    "description": d.description,
                    "inputSchema": d.input_schema(),
                })
            })
            .collect();

        serde_json::json!({ "tools": tools })
    }

    /// Return all tool definitions in the given category.
    #[must_use]
    pub fn tools_in_category(&self, cat: &str) -> Vec<ToolDef> {
        self.entries
            .read()
            .values()
            .filter(|e| e.def.category == cat)
            .map(|e| e.def.clone())
            .collect()
    }

    /// Return all deprecated tool definitions.
    #[must_use]
    pub fn deprecated_tools(&self) -> Vec<ToolDef> {
        self.entries
            .read()
            .values()
            .filter(|e| e.def.deprecated)
            .map(|e| e.def.clone())
            .collect()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ToolRegistryBuilder — fluent API
// ─────────────────────────────────────────────────────────────────────────────

/// Fluent builder for constructing a [`ToolRegistry`] with multiple tools.
pub struct ToolRegistryBuilder {
    registry: ToolRegistry,
}

impl ToolRegistryBuilder {
    /// Create a new builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: ToolRegistry::new(),
        }
    }

    /// Register a tool.
    ///
    /// # Panics
    /// Panics if a tool with the same name was already added in this builder.
    #[must_use]
    pub fn tool(self, def: ToolDef, handler: ToolHandler) -> Self {
        self.registry
            .register(def, handler)
            .expect("duplicate tool in builder");
        self
    }

    /// Finish building and return the registry.
    #[must_use]
    pub fn build(self) -> ToolRegistry {
        self.registry
    }
}

impl Default for ToolRegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CategoryIndex — secondary index for category-based lookups
// ─────────────────────────────────────────────────────────────────────────────

/// A secondary index that maps category strings to tool names.
///
/// Constructed from a snapshot of a [`ToolRegistry`] and is not kept
/// automatically in sync; rebuild after mutations.
#[derive(Debug, Default)]
pub struct CategoryIndex {
    index: HashMap<String, Vec<String>>,
}

impl CategoryIndex {
    /// Build from a tool registry snapshot.
    #[must_use]
    pub fn build(registry: &ToolRegistry) -> Self {
        let mut index: HashMap<String, Vec<String>> = HashMap::new();
        for def in registry.all_defs() {
            index.entry(def.category).or_default().push(def.name);
        }
        for names in index.values_mut() {
            names.sort();
        }
        Self { index }
    }

    /// Return all tool names in a category.
    #[must_use]
    pub fn tools_in(&self, cat: &str) -> &[String] {
        self.index.get(cat).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Return all known categories (sorted).
    #[must_use]
    pub fn categories(&self) -> Vec<&str> {
        let mut cats: Vec<&str> = self.index.keys().map(|s| s.as_str()).collect();
        cats.sort();
        cats
    }

    /// Return the number of categories.
    #[must_use]
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// Return `true` if no categories are indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn echo_handler() -> ToolHandler {
        Arc::new(|input| ToolResult::ok("echo", input, 0))
    }

    fn make_def(name: &str) -> ToolDef {
        ToolDef::new(name, "Test tool", "1.0")
            .with_param(ToolParam::required_string("query", "the query"))
    }

    #[test]
    fn register_and_call() {
        let reg = ToolRegistry::new();
        reg.register(make_def("search"), echo_handler()).unwrap();
        let result = reg
            .call("search", serde_json::json!({ "query": "hello" }))
            .unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn missing_required_param_returns_validation_error() {
        let reg = ToolRegistry::new();
        reg.register(make_def("search"), echo_handler()).unwrap();
        let err = reg
            .call("search", serde_json::json!({}))
            .unwrap_err();
        assert!(matches!(err, RegistryError::ValidationError { .. }));
    }

    #[test]
    fn unknown_tool_returns_not_found() {
        let reg = ToolRegistry::new();
        let err = reg
            .call("nonexistent", serde_json::json!({}))
            .unwrap_err();
        assert!(matches!(err, RegistryError::NotFound(_)));
    }

    #[test]
    fn duplicate_registration_returns_error() {
        let reg = ToolRegistry::new();
        reg.register(make_def("t"), echo_handler()).unwrap();
        let err = reg.register(make_def("t"), echo_handler()).unwrap_err();
        assert!(matches!(err, RegistryError::AlreadyRegistered(_)));
    }

    #[test]
    fn register_or_replace_overwrites() {
        let reg = ToolRegistry::new();
        reg.register(make_def("t"), echo_handler()).unwrap();
        reg.register_or_replace(make_def("t"), echo_handler());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn generate_docs_non_empty() {
        let reg = ToolRegistry::new();
        reg.register(make_def("a.b"), echo_handler()).unwrap();
        let docs = reg.generate_docs();
        assert!(docs.contains("a.b"));
    }

    #[test]
    fn mcp_tools_list_format() {
        let reg = ToolRegistry::new();
        reg.register(make_def("my_tool"), echo_handler()).unwrap();
        let listing = reg.to_mcp_tools_list();
        assert!(listing["tools"].is_array());
        let tools = listing["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "my_tool");
    }

    #[test]
    fn metrics_track_calls() {
        let reg = ToolRegistry::new();
        reg.register(make_def("counter"), echo_handler()).unwrap();
        reg.call("counter", serde_json::json!({ "query": "x" }))
            .unwrap();
        reg.call("counter", serde_json::json!({ "query": "y" }))
            .unwrap();
        let (calls, errors) = reg.metrics("counter").unwrap();
        assert_eq!(calls, 2);
        assert_eq!(errors, 0);
    }

    #[test]
    fn category_index_build() {
        let reg = ToolRegistry::new();
        let def = ToolDef::new("a.b", "desc", "1.0").with_category("analysis");
        reg.register(def, echo_handler()).unwrap();
        let idx = CategoryIndex::build(&reg);
        assert!(idx.tools_in("analysis").contains(&"a.b".to_string()));
    }
}
