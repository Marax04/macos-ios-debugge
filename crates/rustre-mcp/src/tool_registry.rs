//! Low-level MCP tool registry with JSON-Schema validation, versioning, tagging, and invocation.
//!
//! [`ToolRegistry`] stores [`McpToolEntry`] objects.  Each entry bundles:
//! * A handler function `Box<dyn Fn(Value) -> Result<Value, RegistryError>>`.
//! * A full JSON Schema for the `input` parameter (as a `serde_json::Value`).
//! * A semantic [`ToolVersion`] triple.
//! * A human-readable description and optional tags.
//!
//! The registry is cheap to clone (internally `Arc`-backed) and thread-safe.
//!
//! # Distinction from `mcp_tool_registry`
//!
//! This module is the **low-level** handler store: tools are registered as
//! opaque `Box<dyn Fn>` closures alongside an [`InputSchema`].  It offers
//! `Arc`-clone semantics, tag-based filtering, invocation counters, and
//! cross-registry merging via [`ToolRegistry::merge_from`].
//!
//! [`crate::mcp_tool_registry`] is the **high-level** definition layer: tools
//! are described via [`crate::mcp_tool_registry::ToolDef`] /
//! [`crate::mcp_tool_registry::ToolParam`] structs, with richer per-tool
//! metrics (call + error counts), category grouping, Markdown doc generation,
//! and MCP `tools/list` serialisation.  Use that module when you need
//! structured tool definitions for the MCP protocol handshake.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

// ─── RegistryError ────────────────────────────────────────────────────────────

/// Errors produced by the tool registry.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// A tool with the given name is not registered.
    #[error("tool not found: {0}")]
    ToolNotFound(String),
    /// A tool with the given name is already registered.
    #[error("tool already registered: {0}")]
    AlreadyRegistered(String),
    /// JSON schema validation failed.
    #[error("parameter validation failed for '{tool}': {detail}")]
    ValidationFailed {
        /// Tool name.
        tool: String,
        /// Validation error details.
        detail: String,
    },
    /// The handler returned an error.
    #[error("handler error in '{tool}': {detail}")]
    HandlerError {
        /// Tool name.
        tool: String,
        /// Error detail.
        detail: String,
    },
    /// Serialization/deserialization error.
    #[error("serde: {0}")]
    Serde(#[from] serde_json::Error),
    /// Invalid tool name (empty or contains illegal characters).
    #[error("invalid tool name: {0}")]
    InvalidName(String),
}

impl RegistryError {
    /// Construct a handler error for a named tool.
    #[must_use]
    pub fn handler(tool: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::HandlerError {
            tool: tool.into(),
            detail: detail.into(),
        }
    }

    /// Construct a validation error.
    #[must_use]
    pub fn validation(tool: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::ValidationFailed {
            tool: tool.into(),
            detail: detail.into(),
        }
    }

    /// Return `true` if the error is a not-found error.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::ToolNotFound(_))
    }
}

// ─── SchemaType ───────────────────────────────────────────────────────────────

/// A simple structural JSON schema type descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SchemaType {
    String,
    Number,
    Integer,
    Boolean,
    Array,
    Object,
    Null,
}

impl fmt::Display for SchemaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::String => "string",
            Self::Number => "number",
            Self::Integer => "integer",
            Self::Boolean => "boolean",
            Self::Array => "array",
            Self::Object => "object",
            Self::Null => "null",
        };
        write!(f, "{s}")
    }
}

// ─── InputSchema ──────────────────────────────────────────────────────────────

/// A lightweight JSON Schema for validating tool parameters.
///
/// This is a subset of JSON Schema sufficient for MCP tool definitions:
/// `type: object`, `properties`, `required`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct InputSchema {
    /// Required property names.
    pub required: Vec<String>,
    /// Property name → type map.
    pub properties: HashMap<String, SchemaType>,
    /// Property name → description map.
    pub descriptions: HashMap<String, String>,
    /// Whether additional properties are allowed (default: true).
    pub additional_properties: bool,
}

impl InputSchema {
    /// Create an empty schema (accepts any input).
    #[must_use]
    pub fn any() -> Self {
        Self {
            additional_properties: true,
            ..Default::default()
        }
    }

    /// Add a required property.
    #[must_use]
    pub fn require(mut self, name: impl Into<String>, ty: SchemaType) -> Self {
        let n = name.into();
        self.required.push(n.clone());
        self.properties.insert(n, ty);
        self
    }

    /// Add an optional property.
    #[must_use]
    pub fn optional(mut self, name: impl Into<String>, ty: SchemaType) -> Self {
        self.properties.insert(name.into(), ty);
        self
    }

    /// Add a description for a property.
    #[must_use]
    pub fn describe(mut self, name: impl Into<String>, desc: impl Into<String>) -> Self {
        self.descriptions.insert(name.into(), desc.into());
        self
    }

    /// Validate a `Value` against this schema.
    ///
    /// # Errors
    ///
    /// Returns a description of the first validation failure, or `Ok(())`.
    pub fn validate(&self, tool: &str, params: &Value) -> Result<(), RegistryError> {
        let obj = match params.as_object() {
            Some(o) => o,
            None => {
                return Err(RegistryError::validation(
                    tool,
                    "params must be a JSON object",
                ));
            }
        };

        for req in &self.required {
            if !obj.contains_key(req.as_str()) {
                return Err(RegistryError::validation(
                    tool,
                    format!("missing required field '{req}'"),
                ));
            }
        }

        for (name, expected_ty) in &self.properties {
            if let Some(val) = obj.get(name.as_str()) {
                let actual = json_type_name(val);
                let expected_s = expected_ty.to_string();
                // "integer" is a subtype of "number" in JSON Schema.
                let ok = actual == expected_s
                    || (expected_s == "integer" && actual == "number")
                    || (expected_s == "number" && actual == "integer");
                if !ok {
                    return Err(RegistryError::validation(
                        tool,
                        format!("field '{name}' expected {expected_ty} but got {actual}"),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Serialise to a full JSON Schema object suitable for MCP `initialize`.
    #[must_use]
    pub fn to_json_schema(&self) -> Value {
        let mut properties = serde_json::Map::new();
        for (name, ty) in &self.properties {
            let desc = self.descriptions.get(name).cloned().unwrap_or_default();
            properties.insert(
                name.clone(),
                serde_json::json!({ "type": ty.to_string(), "description": desc }),
            );
        }
        let required: Vec<Value> = self
            .required
            .iter()
            .map(|r| Value::String(r.clone()))
            .collect();
        serde_json::json!({
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": self.additional_properties,
        })
    }
}

fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ─── ToolVersion ──────────────────────────────────────────────────────────────

/// Semantic version for a tool.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ToolVersion {
    /// Major version.
    pub major: u32,
    /// Minor version.
    pub minor: u32,
    /// Patch version.
    pub patch: u32,
}

impl ToolVersion {
    /// Create a version triple.
    #[must_use]
    pub fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Version 1.0.0.
    #[must_use]
    pub fn v1() -> Self {
        Self::new(1, 0, 0)
    }

    /// Parse a semver string `"M.N.P"`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let mut parts = s.splitn(3, '.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        Some(Self {
            major,
            minor,
            patch,
        })
    }

    /// Returns `true` if this version is backwards-compatible with `other`
    /// (same major, greater-or-equal minor.patch).
    #[must_use]
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major && *self >= *other
    }
}

impl fmt::Display for ToolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

// ─── McpToolEntry ─────────────────────────────────────────────────────────────

/// An entry in the [`ToolRegistry`].
pub struct McpToolEntry {
    /// Unique tool name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Semantic version.
    pub version: ToolVersion,
    /// Input schema.
    pub schema: InputSchema,
    /// Handler function.
    handler: Box<dyn Fn(Value) -> Result<Value, RegistryError> + Send + Sync>,
    /// Invocation count (updated on every call).
    pub invocation_count: u64,
    /// Tags for grouping/filtering.
    pub tags: Vec<String>,
}

impl McpToolEntry {
    /// Return the tool name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return a reference to the handler.
    fn handler(&self) -> &dyn Fn(Value) -> Result<Value, RegistryError> {
        self.handler.as_ref()
    }

    /// Export a descriptor (without the handler closure).
    #[must_use]
    pub fn descriptor(&self) -> ToolDescriptor {
        ToolDescriptor {
            name: self.name.clone(),
            description: self.description.clone(),
            version: self.version.to_string(),
            input_schema: self.schema.to_json_schema(),
            tags: self.tags.clone(),
            invocation_count: self.invocation_count,
        }
    }
}

impl fmt::Debug for McpToolEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpToolEntry")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("invocation_count", &self.invocation_count)
            .finish_non_exhaustive()
    }
}

// ─── ToolDescriptor ───────────────────────────────────────────────────────────

/// A serialisable description of a registered tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDescriptor {
    /// Tool name.
    pub name: String,
    /// Tool description.
    pub description: String,
    /// Semantic version string.
    pub version: String,
    /// JSON Schema for tool input.
    pub input_schema: Value,
    /// Tags.
    pub tags: Vec<String>,
    /// Total invocation count.
    pub invocation_count: u64,
}

impl fmt::Display for ToolDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} v{}", self.name, self.version)
    }
}

// ─── ToolBuilder ──────────────────────────────────────────────────────────────

/// Builder for constructing an [`McpToolEntry`].
/// Boxed handler function for a registered tool.
pub type ToolHandler = Box<dyn Fn(Value) -> Result<Value, RegistryError> + Send + Sync>;

pub struct ToolBuilder {
    name: String,
    description: String,
    version: ToolVersion,
    schema: InputSchema,
    handler: Option<ToolHandler>,
    tags: Vec<String>,
}

impl ToolBuilder {
    /// Start building a tool with the given name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            version: ToolVersion::v1(),
            schema: InputSchema::any(),
            handler: None,
            tags: Vec::new(),
        }
    }

    /// Set the description.
    #[must_use]
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the version.
    #[must_use]
    pub fn version(mut self, version: ToolVersion) -> Self {
        self.version = version;
        self
    }

    /// Set the input schema.
    #[must_use]
    pub fn schema(mut self, schema: InputSchema) -> Self {
        self.schema = schema;
        self
    }

    /// Set the handler.
    #[must_use]
    pub fn handler<F>(mut self, f: F) -> Self
    where
        F: Fn(Value) -> Result<Value, RegistryError> + Send + Sync + 'static,
    {
        self.handler = Some(Box::new(f));
        self
    }

    /// Add a tag.
    #[must_use]
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Build the entry.
    ///
    /// # Panics
    ///
    /// Panics if no handler was provided.
    #[must_use]
    pub fn build(self) -> McpToolEntry {
        McpToolEntry {
            name: self.name,
            description: self.description,
            version: self.version,
            schema: self.schema,
            handler: self.handler.expect("handler must be set before build()"),
            invocation_count: 0,
            tags: self.tags,
        }
    }
}

// ─── ToolRegistry ─────────────────────────────────────────────────────────────

/// Thread-safe registry of MCP tools.
///
/// All mutable operations acquire a write lock; reads are lock-free on the
/// fast path via [`Arc`].
pub struct ToolRegistry {
    inner: Arc<RwLock<RegistryInner>>,
}

struct RegistryInner {
    tools: HashMap<String, McpToolEntry>,
}

impl ToolRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(RegistryInner {
                tools: HashMap::new(),
            })),
        }
    }

    /// Register a tool from a pre-built [`McpToolEntry`].
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::AlreadyRegistered`] if a tool with that name
    /// already exists.
    pub fn register(&self, entry: McpToolEntry) -> Result<(), RegistryError> {
        let name = entry.name.clone();
        if name.is_empty() {
            return Err(RegistryError::InvalidName(name));
        }
        let mut inner = self.inner.write();
        if inner.tools.contains_key(&name) {
            return Err(RegistryError::AlreadyRegistered(name));
        }
        inner.tools.insert(name, entry);
        Ok(())
    }

    /// Register a tool, replacing any existing entry with the same name.
    pub fn register_or_replace(&self, entry: McpToolEntry) {
        self.inner.write().tools.insert(entry.name.clone(), entry);
    }

    /// Register a tool using a [`ToolBuilder`].
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::AlreadyRegistered`] if a tool with that name
    /// already exists.
    pub fn register_builder(&self, builder: ToolBuilder) -> Result<(), RegistryError> {
        self.register(builder.build())
    }

    /// Remove a tool by name.  Returns `true` if a tool was removed.
    pub fn remove(&self, name: &str) -> bool {
        self.inner.write().tools.remove(name).is_some()
    }

    /// Return `true` if a tool with the given name is registered.
    #[must_use]
    pub fn has(&self, name: &str) -> bool {
        self.inner.read().tools.contains_key(name)
    }

    /// Return the number of registered tools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().tools.len()
    }

    /// Returns `true` if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// List all registered tool names (sorted).
    #[must_use]
    pub fn list(&self) -> Vec<String> {
        let mut names: Vec<_> = self.inner.read().tools.keys().cloned().collect();
        names.sort();
        names
    }

    /// Return descriptors for all registered tools (sorted by name).
    #[must_use]
    pub fn descriptors(&self) -> Vec<ToolDescriptor> {
        let inner = self.inner.read();
        let mut out: Vec<ToolDescriptor> = inner.tools.values().map(|e| e.descriptor()).collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Return descriptors for tools matching any of the given tags.
    #[must_use]
    pub fn by_tag(&self, tag: &str) -> Vec<ToolDescriptor> {
        let inner = self.inner.read();
        let mut out: Vec<ToolDescriptor> = inner
            .tools
            .values()
            .filter(|e| e.tags.iter().any(|t| t == tag))
            .map(|e| e.descriptor())
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Invoke a registered tool by name.
    ///
    /// Parameter validation is performed before calling the handler.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] on validation failure or handler error.
    pub fn invoke(&self, name: &str, params: Value) -> Result<Value, RegistryError> {
        // Validate schema first (hold read lock briefly).
        {
            let inner = self.inner.read();
            let entry = inner
                .tools
                .get(name)
                .ok_or_else(|| RegistryError::ToolNotFound(name.to_string()))?;
            entry.schema.validate(name, &params)?;
        }

        // Invoke the handler (re-acquire read lock; handler may be slow).
        let result = {
            let inner = self.inner.read();
            let entry = inner
                .tools
                .get(name)
                .ok_or_else(|| RegistryError::ToolNotFound(name.to_string()))?;
            (entry.handler())(params)
        };

        // Increment invocation counter.
        {
            let mut inner = self.inner.write();
            if let Some(entry) = inner.tools.get_mut(name) {
                entry.invocation_count += 1;
            }
        }

        result
    }

    /// Return the invocation count for a tool, or `None` if not found.
    #[must_use]
    pub fn invocation_count(&self, name: &str) -> Option<u64> {
        self.inner
            .read()
            .tools
            .get(name)
            .map(|e| e.invocation_count)
    }

    /// Look up a tool's version, or `None` if not found.
    #[must_use]
    pub fn version(&self, name: &str) -> Option<ToolVersion> {
        self.inner.read().tools.get(name).map(|e| e.version.clone())
    }

    /// Merge all tools from `other` into this registry.  Tools already present
    /// in `self` are skipped.
    ///
    /// Returns the number of tools successfully merged.
    pub fn merge_from(&self, other: &Self) -> usize {
        let names = other.list();
        let mut merged = 0usize;
        // We cannot easily move entries across two Arc<RwLock<>> without
        // re-constructing them; instead we expose a snapshot approach.
        // For the purposes of this registry we only copy descriptors + a
        // stub handler that returns the tool's description as JSON.
        for name in &names {
            if self.has(name) {
                continue;
            }
            let desc = {
                let inner = other.inner.read();
                inner.tools.get(name.as_str()).map(|e| e.descriptor())
            };
            if let Some(d) = desc {
                let tool_name = d.name.clone();
                let entry = ToolBuilder::new(d.name.clone())
                    .description(d.description.clone())
                    .version(ToolVersion::parse(&d.version).unwrap_or_else(ToolVersion::v1))
                    .handler(move |_| Ok(serde_json::json!({ "stub": true, "name": tool_name })))
                    .build();
                let _ = self.register(entry);
                merged += 1;
            }
        }
        merged
    }

    /// Clear all registered tools.
    pub fn clear(&self) {
        self.inner.write().tools.clear();
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ToolRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ToolRegistry({})", self.len())
    }
}

impl Clone for ToolRegistry {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_echo_entry() -> McpToolEntry {
        ToolBuilder::new("echo")
            .description("Echo the input")
            .handler(Ok)
            .build()
    }

    fn make_add_entry() -> McpToolEntry {
        ToolBuilder::new("add")
            .description("Add two numbers")
            .schema(
                InputSchema::any()
                    .require("a", SchemaType::Number)
                    .require("b", SchemaType::Number),
            )
            .handler(|p| {
                let a = p["a"].as_f64().unwrap_or(0.0);
                let b = p["b"].as_f64().unwrap_or(0.0);
                Ok(serde_json::json!({ "result": a + b }))
            })
            .build()
    }

    #[test]
    fn register_and_list() {
        let reg = ToolRegistry::new();
        reg.register(make_echo_entry()).expect("register echo");
        assert_eq!(reg.len(), 1);
        assert!(reg.has("echo"));
        let names = reg.list();
        assert_eq!(names, vec!["echo"]);
    }

    #[test]
    fn register_duplicate_fails() {
        let reg = ToolRegistry::new();
        reg.register(make_echo_entry()).expect("first");
        let err = reg.register(make_echo_entry());
        assert!(matches!(err, Err(RegistryError::AlreadyRegistered(_))));
    }

    #[test]
    fn register_or_replace() {
        let reg = ToolRegistry::new();
        reg.register(make_echo_entry()).expect("first");
        reg.register_or_replace(make_echo_entry()); // no error
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn invoke_echo() {
        let reg = ToolRegistry::new();
        reg.register(make_echo_entry()).expect("register");
        let result = reg
            .invoke("echo", serde_json::json!({"hello": "world"}))
            .expect("invoke");
        assert_eq!(result["hello"], "world");
    }

    #[test]
    fn invoke_not_found() {
        let reg = ToolRegistry::new();
        let err = reg.invoke("missing", serde_json::json!({}));
        assert!(matches!(err, Err(RegistryError::ToolNotFound(_))));
    }

    #[test]
    fn schema_validation_ok() {
        let reg = ToolRegistry::new();
        reg.register(make_add_entry()).expect("register");
        let result = reg
            .invoke("add", serde_json::json!({"a": 3.0, "b": 4.0}))
            .expect("invoke");
        assert_eq!(result["result"], 7.0);
    }

    #[test]
    fn schema_validation_missing_field() {
        let reg = ToolRegistry::new();
        reg.register(make_add_entry()).expect("register");
        let err = reg.invoke("add", serde_json::json!({"a": 1.0}));
        assert!(matches!(err, Err(RegistryError::ValidationFailed { .. })));
    }

    #[test]
    fn schema_validation_wrong_type() {
        let reg = ToolRegistry::new();
        reg.register(make_add_entry()).expect("register");
        let err = reg.invoke("add", serde_json::json!({"a": "not-a-number", "b": 2.0}));
        assert!(matches!(err, Err(RegistryError::ValidationFailed { .. })));
    }

    #[test]
    fn remove_tool() {
        let reg = ToolRegistry::new();
        reg.register(make_echo_entry()).expect("register");
        assert!(reg.remove("echo"));
        assert!(!reg.has("echo"));
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn remove_nonexistent() {
        let reg = ToolRegistry::new();
        assert!(!reg.remove("ghost"));
    }

    #[test]
    fn invocation_count_increments() {
        let reg = ToolRegistry::new();
        reg.register(make_echo_entry()).expect("register");
        reg.invoke("echo", serde_json::json!({})).expect("1");
        reg.invoke("echo", serde_json::json!({})).expect("2");
        assert_eq!(reg.invocation_count("echo"), Some(2));
    }

    #[test]
    fn descriptors_sorted() {
        let reg = ToolRegistry::new();
        reg.register(make_echo_entry()).expect("echo");
        reg.register(make_add_entry()).expect("add");
        let descs = reg.descriptors();
        assert_eq!(descs[0].name, "add");
        assert_eq!(descs[1].name, "echo");
    }

    #[test]
    fn tags_filter() {
        let reg = ToolRegistry::new();
        let entry = ToolBuilder::new("tagged_tool")
            .description("has tags")
            .tag("math")
            .tag("utils")
            .handler(|_| Ok(serde_json::json!({})))
            .build();
        reg.register(entry).expect("register");
        assert_eq!(reg.by_tag("math").len(), 1);
        assert_eq!(reg.by_tag("unknown").len(), 0);
    }

    #[test]
    fn version_accessors() {
        let reg = ToolRegistry::new();
        let entry = ToolBuilder::new("v_tool")
            .version(ToolVersion::new(2, 3, 4))
            .handler(|_| Ok(Value::Null))
            .build();
        reg.register(entry).expect("register");
        let v = reg.version("v_tool").expect("version");
        assert_eq!(v, ToolVersion::new(2, 3, 4));
        assert_eq!(v.to_string(), "2.3.4");
    }

    #[test]
    fn tool_version_parse() {
        let v = ToolVersion::parse("1.2.3").expect("parse");
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn tool_version_compatibility() {
        let v1 = ToolVersion::new(1, 2, 0);
        let v2 = ToolVersion::new(1, 1, 0);
        assert!(v1.is_compatible_with(&v2));
        let v3 = ToolVersion::new(2, 0, 0);
        assert!(!v1.is_compatible_with(&v3));
    }

    #[test]
    fn input_schema_to_json_schema() {
        let schema = InputSchema::any()
            .require("name", SchemaType::String)
            .optional("count", SchemaType::Integer)
            .describe("name", "User name");
        let js = schema.to_json_schema();
        assert_eq!(js["type"], "object");
        assert!(js["properties"]["name"]["type"] == "string");
    }

    #[test]
    fn registry_clone_shares_state() {
        let reg = ToolRegistry::new();
        reg.register(make_echo_entry()).expect("register");
        let reg2 = reg.clone();
        assert!(reg2.has("echo"));
        // Modify through clone.
        reg2.remove("echo");
        assert!(!reg.has("echo"));
    }

    #[test]
    fn registry_clear() {
        let reg = ToolRegistry::new();
        reg.register(make_echo_entry()).expect("register");
        reg.register(make_add_entry()).expect("register");
        reg.clear();
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn registry_error_helpers() {
        let e = RegistryError::handler("foo", "bad");
        assert!(e.to_string().contains("foo"));
        assert!(!RegistryError::AlreadyRegistered("x".into()).is_not_found());
        assert!(RegistryError::ToolNotFound("y".into()).is_not_found());
    }
}
