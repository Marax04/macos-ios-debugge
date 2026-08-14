//! `mcp_tool_registry` — **Dynamic registry layer** of the MCP tool stack.
//!
//! [`McpToolRegistry`] holds a map of tool names → [`ToolDef`]. Callers register
//! tools with their JSON Schema and a handler closure, then use [`ToolDispatcher`]
//! to route incoming JSON-RPC `tools/call` requests.
//!
//! # `ToolSchema` naming collision
//!
//! This module's [`ToolSchema`] is backed by `HashMap<String, Value>` and a
//! builder API; it generates full JSON Schema objects for the MCP `tools/list`
//! response. [`rustre_tools`] also has a `ToolSchema` type, but that one uses a
//! `Vec<ParamDef>` for simple presence-of-required-fields validation. The two
//! types serve different purposes and are not interchangeable.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

// ─── ToolSchema ───────────────────────────────────────────────────────────────

/// JSON-Schema description of a single MCP tool parameter set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSchema {
    /// JSON Schema `type` (always "object" for MCP tools).
    pub schema_type: String,
    /// Required property names.
    pub required: Vec<String>,
    /// Property definitions: name → {"type": ..., "description": ...}.
    pub properties: HashMap<String, Value>,
}

impl ToolSchema {
    /// Create an empty object schema.
    #[must_use] 
    pub fn new() -> Self {
        Self {
            schema_type: "object".into(),
            required: Vec::new(),
            properties: HashMap::new(),
        }
    }

    /// Add a required string property.
    #[must_use] 
    pub fn string(mut self, name: &str, description: &str) -> Self {
        self.properties.insert(
            name.into(),
            json!({"type": "string", "description": description}),
        );
        self.required.push(name.into());
        self
    }

    /// Add a required integer property.
    #[must_use] 
    pub fn integer(mut self, name: &str, description: &str) -> Self {
        self.properties.insert(
            name.into(),
            json!({"type": "integer", "description": description}),
        );
        self.required.push(name.into());
        self
    }

    /// Add a required boolean property.
    #[must_use] 
    pub fn boolean(mut self, name: &str, description: &str) -> Self {
        self.properties.insert(
            name.into(),
            json!({"type": "boolean", "description": description}),
        );
        self.required.push(name.into());
        self
    }

    /// Add an optional string property.
    #[must_use] 
    pub fn optional_string(mut self, name: &str, description: &str) -> Self {
        self.properties.insert(
            name.into(),
            json!({"type": "string", "description": description}),
        );
        self
    }

    /// Add an optional integer property.
    #[must_use] 
    pub fn optional_integer(mut self, name: &str, description: &str) -> Self {
        self.properties.insert(
            name.into(),
            json!({"type": "integer", "description": description}),
        );
        self
    }

    /// Serialize to JSON Value.
    #[must_use] 
    pub fn to_json(&self) -> Value {
        json!({
            "type": self.schema_type,
            "required": self.required,
            "properties": self.properties,
        })
    }
}

impl Default for ToolSchema {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ToolDef ─────────────────────────────────────────────────────────────────

/// Complete definition of a registered MCP tool.
#[derive(Clone)]
pub struct ToolDef {
    /// Short identifier used in JSON-RPC (e.g. `"disassemble"`).
    pub name: String,
    /// Human-readable description shown in tool listing.
    pub description: String,
    /// Parameter schema.
    pub schema: ToolSchema,
    /// Callable handler. Takes validated params, returns result JSON or error.
    pub handler: Arc<dyn Fn(Value) -> Result<Value> + Send + Sync>,
}

impl std::fmt::Debug for ToolDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolDef")
            .field("name", &self.name)
            .field("description", &self.description)
            .finish()
    }
}

impl ToolDef {
    /// Build a new tool definition.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        schema: ToolSchema,
        handler: impl Fn(Value) -> Result<Value> + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            schema,
            handler: Arc::new(handler),
        }
    }

    /// Invoke the handler with the given params.
    pub fn call(&self, params: Value) -> Result<Value> {
        (self.handler)(params)
    }

    /// Produce the MCP tool-list entry for this tool.
    #[must_use] 
    pub fn to_list_entry(&self) -> Value {
        json!({
            "name": self.name,
            "description": self.description,
            "inputSchema": self.schema.to_json(),
        })
    }
}

// ─── RegistrationError ───────────────────────────────────────────────────────

/// Errors from registry operations.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("tool already registered: {0}")]
    AlreadyRegistered(String),
    #[error("tool not found: {0}")]
    NotFound(String),
    #[error("parameter validation failed for '{tool}': {reason}")]
    ValidationFailed { tool: String, reason: String },
    #[error("tool handler error: {0}")]
    HandlerError(#[from] anyhow::Error),
}

// ─── McpToolRegistry ─────────────────────────────────────────────────────────

/// Central registry of all MCP tools exposed by `RustRE`.
///
/// Supports dynamic registration, listing, validation, and dispatch.
#[derive(Default)]
pub struct McpToolRegistry {
    tools: HashMap<String, ToolDef>,
    /// Registration order, for deterministic listing.
    order: Vec<String>,
}

impl McpToolRegistry {
    /// Create an empty registry.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry pre-populated with the standard `RustRE` tool set.
    #[must_use] 
    pub fn with_rustre_defaults() -> Self {
        let mut reg = Self::new();
        reg.register_default_tools();
        reg
    }

    /// Register a new tool. Returns error if a tool with the same name already exists.
    pub fn register(&mut self, def: ToolDef) -> Result<(), RegistryError> {
        if self.tools.contains_key(&def.name) {
            return Err(RegistryError::AlreadyRegistered(def.name));
        }
        self.order.push(def.name.clone());
        self.tools.insert(def.name.clone(), def);
        Ok(())
    }

    /// Register or replace a tool (no error on duplicate).
    pub fn register_or_replace(&mut self, def: ToolDef) {
        if !self.tools.contains_key(&def.name) {
            self.order.push(def.name.clone());
        }
        self.tools.insert(def.name.clone(), def);
    }

    /// Remove a registered tool. Returns true if it existed.
    pub fn unregister(&mut self, name: &str) -> bool {
        if self.tools.remove(name).is_some() {
            self.order.retain(|n| n != name);
            true
        } else {
            false
        }
    }

    /// Look up a tool by name.
    #[must_use] 
    pub fn get(&self, name: &str) -> Option<&ToolDef> {
        self.tools.get(name)
    }

    /// Return the number of registered tools.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Return true if no tools are registered.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    /// List all tool names in registration order.
    #[must_use] 
    pub fn tool_names(&self) -> &[String] {
        &self.order
    }

    /// Build the MCP `tools/list` response body.
    #[must_use] 
    pub fn list_tools_response(&self) -> Value {
        let entries: Vec<Value> = self
            .order
            .iter()
            .filter_map(|n| self.tools.get(n))
            .map(ToolDef::to_list_entry)
            .collect();
        json!({ "tools": entries })
    }

    /// Validate that all required parameters are present.
    fn validate_params(&self, def: &ToolDef, params: &Value) -> Result<(), RegistryError> {
        let obj = params.as_object().ok_or_else(|| RegistryError::ValidationFailed {
            tool: def.name.clone(),
            reason: "params must be a JSON object".into(),
        })?;
        for req in &def.schema.required {
            if !obj.contains_key(req) {
                return Err(RegistryError::ValidationFailed {
                    tool: def.name.clone(),
                    reason: format!("missing required parameter '{req}'"),
                });
            }
        }
        Ok(())
    }

    /// Dispatch a tool call by name with params. Validates params first.
    pub fn dispatch(&self, tool_name: &str, params: Value) -> Result<Value, RegistryError> {
        let def = self
            .tools
            .get(tool_name)
            .ok_or_else(|| RegistryError::NotFound(tool_name.into()))?;
        self.validate_params(def, &params)?;
        def.call(params).map_err(RegistryError::HandlerError)
    }

    /// Register the standard set of `RustRE` MCP tools with no-op handlers.
    fn register_default_tools(&mut self) {
        self.tools.reserve(8);
        self.order.reserve(8);
        let tools: Vec<ToolDef> = vec![
            ToolDef::new(
                "rustre/disassemble",
                "Disassemble bytes at a given address in the loaded binary",
                ToolSchema::new()
                    .integer("address", "Start address (hex or decimal)")
                    .integer("length", "Number of bytes to disassemble"),
                |params| {
                    let addr = params["address"].as_u64().unwrap_or(0);
                    let len = params["length"].as_u64().unwrap_or(64);
                    Ok(json!({
                        "address": format!("0x{:x}", addr),
                        "length": len,
                        "instructions": [],
                        "note": "handler stub — wire up to disassembler engine"
                    }))
                },
            ),
            ToolDef::new(
                "rustre/decompile",
                "Decompile a function to pseudo-C",
                ToolSchema::new().integer("address", "Function address"),
                |params| {
                    let addr = params["address"].as_u64().unwrap_or(0);
                    Ok(json!({
                        "address": format!("0x{:x}", addr),
                        "pseudocode": "// decompilation not yet wired up"
                    }))
                },
            ),
            ToolDef::new(
                "rustre/symbols",
                "List symbols in the loaded binary",
                ToolSchema::new().optional_string("filter", "Optional substring filter"),
                |params| {
                    let filter = params["filter"].as_str().unwrap_or("").to_string();
                    Ok(json!({ "filter": filter, "symbols": [] }))
                },
            ),
            ToolDef::new(
                "rustre/strings",
                "Extract strings from the loaded binary",
                ToolSchema::new()
                    .optional_integer("min_length", "Minimum string length (default 4)")
                    .optional_string("encoding", "Encoding: ascii or utf16"),
                |params| {
                    let min_len = params["min_length"].as_u64().unwrap_or(4);
                    Ok(json!({ "min_length": min_len, "strings": [] }))
                },
            ),
            ToolDef::new(
                "rustre/xrefs_to",
                "Find cross-references to an address",
                ToolSchema::new().integer("address", "Target address"),
                |params| {
                    let addr = params["address"].as_u64().unwrap_or(0);
                    Ok(json!({ "address": format!("0x{:x}", addr), "xrefs": [] }))
                },
            ),
            ToolDef::new(
                "rustre/xrefs_from",
                "Find cross-references from an address",
                ToolSchema::new().integer("address", "Source address"),
                |params| {
                    let addr = params["address"].as_u64().unwrap_or(0);
                    Ok(json!({ "address": format!("0x{:x}", addr), "xrefs": [] }))
                },
            ),
            ToolDef::new(
                "rustre/analyze_taint",
                "Run taint analysis from a source register/address",
                ToolSchema::new()
                    .string("source", "Source specification (reg:rdi or mem:0x1000)")
                    .optional_string("policy", "Taint policy preset: strict|permissive"),
                |params| {
                    let source = params["source"].as_str().unwrap_or("").to_string();
                    Ok(json!({ "source": source, "findings": [] }))
                },
            ),
            ToolDef::new(
                "rustre/crypto_detect",
                "Detect cryptographic algorithms in a binary region",
                ToolSchema::new()
                    .integer("address", "Start of region")
                    .integer("size", "Region size in bytes"),
                |params| {
                    let addr = params["address"].as_u64().unwrap_or(0);
                    let size = params["size"].as_u64().unwrap_or(4096);
                    Ok(json!({ "address": format!("0x{:x}", addr), "size": size, "detections": [] }))
                },
            ),
        ];
        for tool in tools {
            self.register_or_replace(tool);
        }
    }
}

// ─── ToolDispatcher ───────────────────────────────────────────────────────────

/// Routes MCP `tools/call` JSON-RPC requests through the registry.
pub struct ToolDispatcher {
    registry: Arc<McpToolRegistry>,
}

impl ToolDispatcher {
    /// Create a dispatcher backed by the given registry.
    #[must_use] 
    pub const fn new(registry: Arc<McpToolRegistry>) -> Self {
        Self { registry }
    }

    /// Create a dispatcher with default `RustRE` tools pre-registered.
    #[must_use] 
    pub fn with_defaults() -> Self {
        Self::new(Arc::new(McpToolRegistry::with_rustre_defaults()))
    }

    /// Process a raw MCP `tools/call` request body.
    ///
    /// Expected shape: `{ "name": "...", "arguments": { ... } }`
    #[must_use] 
    pub fn handle_call(&self, request: &Value) -> Value {
        let name = match request["name"].as_str() {
            Some(n) => n,
            None => {
                return json!({
                    "isError": true,
                    "content": [{ "type": "text", "text": "missing 'name' field" }]
                });
            }
        };
        let params = request.get("arguments").cloned().unwrap_or(json!({}));
        match self.registry.dispatch(name, params) {
            Ok(result) => json!({
                "content": [{ "type": "text", "text": result.to_string() }]
            }),
            Err(e) => json!({
                "isError": true,
                "content": [{ "type": "text", "text": e.to_string() }]
            }),
        }
    }

    /// Process a `tools/list` request.
    #[must_use] 
    pub fn handle_list(&self) -> Value {
        self.registry.list_tools_response()
    }

    /// Borrow the underlying registry.
    #[must_use] 
    pub fn registry(&self) -> &McpToolRegistry {
        &self.registry
    }
}

// ─── SchemaBuilder ────────────────────────────────────────────────────────────

/// Fluent builder for complex tool schemas with nested properties.
pub struct SchemaBuilder {
    schema: ToolSchema,
}

impl SchemaBuilder {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            schema: ToolSchema::new(),
        }
    }

    #[must_use] 
    pub fn required_string(mut self, name: &str, description: &str) -> Self {
        self.schema = self.schema.string(name, description);
        self
    }

    #[must_use] 
    pub fn required_integer(mut self, name: &str, description: &str) -> Self {
        self.schema = self.schema.integer(name, description);
        self
    }

    #[must_use] 
    pub fn required_boolean(mut self, name: &str, description: &str) -> Self {
        self.schema = self.schema.boolean(name, description);
        self
    }

    #[must_use] 
    pub fn optional_string(mut self, name: &str, description: &str) -> Self {
        self.schema = self.schema.optional_string(name, description);
        self
    }

    #[must_use] 
    pub fn optional_integer(mut self, name: &str, description: &str) -> Self {
        self.schema = self.schema.optional_integer(name, description);
        self
    }

    #[must_use] 
    pub fn array_property(mut self, name: &str, item_type: &str, description: &str) -> Self {
        self.schema.properties.insert(
            name.into(),
            json!({
                "type": "array",
                "items": { "type": item_type },
                "description": description
            }),
        );
        self
    }

    #[must_use] 
    pub fn build(self) -> ToolSchema {
        self.schema
    }
}

impl Default for SchemaBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── ToolCategory ────────────────────────────────────────────────────────────

/// Logical grouping of tools for documentation / discovery.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ToolCategory {
    Disassembly,
    Decompilation,
    Taint,
    Crypto,
    Symbols,
    Trace,
    BinaryInfo,
    Custom(String),
}

impl ToolCategory {
    #[must_use] 
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Disassembly => "disassembly",
            Self::Decompilation => "decompilation",
            Self::Taint => "taint",
            Self::Crypto => "crypto",
            Self::Symbols => "symbols",
            Self::Trace => "trace",
            Self::BinaryInfo => "binary_info",
            Self::Custom(s) => s.as_str(),
        }
    }
}

/// Categorized registry that groups tools by domain.
pub struct CategorizedRegistry {
    registry: McpToolRegistry,
    categories: HashMap<String, ToolCategory>,
}

impl CategorizedRegistry {
    #[must_use] 
    pub fn new() -> Self {
        Self {
            registry: McpToolRegistry::new(),
            categories: HashMap::new(),
        }
    }

    pub fn register_in(
        &mut self,
        def: ToolDef,
        category: ToolCategory,
    ) -> Result<(), RegistryError> {
        self.categories.insert(def.name.clone(), category);
        self.registry.register(def)
    }

    #[must_use] 
    pub fn tools_in_category(&self, category: &ToolCategory) -> Vec<&ToolDef> {
        self.categories
            .iter()
            .filter(|(_, c)| *c == category)
            .filter_map(|(name, _)| self.registry.get(name))
            .collect()
    }

    #[must_use] 
    pub const fn registry(&self) -> &McpToolRegistry {
        &self.registry
    }

    pub fn dispatch(&self, name: &str, params: Value) -> Result<Value, RegistryError> {
        self.registry.dispatch(name, params)
    }
}

impl Default for CategorizedRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_schema_required_fields() {
        let schema = ToolSchema::new()
            .string("path", "Binary path")
            .integer("offset", "Offset");
        assert_eq!(schema.required.len(), 2);
        assert!(schema.properties.contains_key("path"));
        assert!(schema.properties.contains_key("offset"));
    }

    #[test]
    fn test_tool_schema_optional_not_in_required() {
        let schema = ToolSchema::new()
            .optional_string("filter", "Optional filter");
        assert!(schema.required.is_empty());
        assert!(schema.properties.contains_key("filter"));
    }

    #[test]
    fn test_registry_register_and_get() {
        let mut reg = McpToolRegistry::new();
        let def = ToolDef::new(
            "test_tool",
            "A test tool",
            ToolSchema::new(),
            |_| Ok(json!("ok")),
        );
        reg.register(def).unwrap();
        assert!(reg.get("test_tool").is_some());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn test_registry_duplicate_returns_error() {
        let mut reg = McpToolRegistry::new();
        let make = || {
            ToolDef::new("dup", "Dup", ToolSchema::new(), |_| Ok(json!("ok")))
        };
        reg.register(make()).unwrap();
        assert!(reg.register(make()).is_err());
    }

    #[test]
    fn test_registry_unregister() {
        let mut reg = McpToolRegistry::new();
        reg.register(ToolDef::new("t", "T", ToolSchema::new(), |_| Ok(json!("")))).unwrap();
        assert!(reg.unregister("t"));
        assert!(!reg.unregister("t"));
        assert!(reg.is_empty());
    }

    #[test]
    fn test_dispatch_tool_found() {
        let mut reg = McpToolRegistry::new();
        reg.register(ToolDef::new(
            "echo",
            "Echo input",
            ToolSchema::new().string("msg", "Message to echo"),
            |params| Ok(json!({ "echoed": params["msg"] })),
        ))
        .unwrap();
        let result = reg.dispatch("echo", json!({ "msg": "hello" })).unwrap();
        assert_eq!(result["echoed"], "hello");
    }

    #[test]
    fn test_dispatch_tool_not_found() {
        let reg = McpToolRegistry::new();
        let err = reg.dispatch("nonexistent", json!({}));
        assert!(matches!(err, Err(RegistryError::NotFound(_))));
    }

    #[test]
    fn test_dispatch_missing_required_param() {
        let mut reg = McpToolRegistry::new();
        reg.register(ToolDef::new(
            "need_param",
            "Needs a param",
            ToolSchema::new().string("required_field", "Must be present"),
            |_| Ok(json!("ok")),
        ))
        .unwrap();
        let err = reg.dispatch("need_param", json!({}));
        assert!(matches!(err, Err(RegistryError::ValidationFailed { .. })));
    }

    #[test]
    fn test_list_tools_response_shape() {
        let reg = McpToolRegistry::with_rustre_defaults();
        let resp = reg.list_tools_response();
        let tools = resp["tools"].as_array().unwrap();
        assert!(!tools.is_empty());
        for tool in tools {
            assert!(tool["name"].is_string());
            assert!(tool["description"].is_string());
            assert!(tool["inputSchema"].is_object());
        }
    }

    #[test]
    fn test_dispatcher_handle_list() {
        let disp = ToolDispatcher::with_defaults();
        let list = disp.handle_list();
        assert!(list["tools"].as_array().unwrap().len() > 0);
    }

    #[test]
    fn test_dispatcher_handle_call_success() {
        let disp = ToolDispatcher::with_defaults();
        let req = json!({
            "name": "rustre/disassemble",
            "arguments": { "address": 0x1000, "length": 32 }
        });
        let result = disp.handle_call(&req);
        assert!(result.get("isError").is_none());
        assert!(result["content"].as_array().is_some());
    }

    #[test]
    fn test_dispatcher_handle_call_missing_name() {
        let disp = ToolDispatcher::with_defaults();
        let result = disp.handle_call(&json!({}));
        assert_eq!(result["isError"], true);
    }

    #[test]
    fn test_schema_builder() {
        let schema = SchemaBuilder::new()
            .required_string("path", "Binary path")
            .optional_integer("offset", "Optional offset")
            .array_property("sections", "string", "Sections to analyze")
            .build();
        assert!(schema.required.contains(&"path".to_string()));
        assert!(!schema.required.contains(&"offset".to_string()));
        assert!(schema.properties.contains_key("sections"));
    }

    #[test]
    fn test_categorized_registry() {
        let mut creg = CategorizedRegistry::new();
        creg.register_in(
            ToolDef::new("cat_test", "Cat test", ToolSchema::new(), |_| Ok(json!("ok"))),
            ToolCategory::Disassembly,
        )
        .unwrap();
        let dis_tools = creg.tools_in_category(&ToolCategory::Disassembly);
        assert_eq!(dis_tools.len(), 1);
        let taint_tools = creg.tools_in_category(&ToolCategory::Taint);
        assert_eq!(taint_tools.len(), 0);
    }

    #[test]
    fn test_tool_category_as_str() {
        assert_eq!(ToolCategory::Disassembly.as_str(), "disassembly");
        assert_eq!(ToolCategory::Custom("xyz".into()).as_str(), "xyz");
    }

    #[test]
    fn test_registry_order_preserved() {
        let mut reg = McpToolRegistry::new();
        for i in 0..5 {
            reg.register(ToolDef::new(
                format!("tool_{i}"),
                "desc",
                ToolSchema::new(),
                |_| Ok(json!(null)),
            ))
            .unwrap();
        }
        let names = reg.tool_names();
        for i in 0..5 {
            assert_eq!(names[i], format!("tool_{i}"));
        }
    }
}
