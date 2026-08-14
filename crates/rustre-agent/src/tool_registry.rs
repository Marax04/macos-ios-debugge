//! Agent tool registry: `AgentTool` trait, `ToolRegistry`, JSON schema validation,
//! built-in RE analysis tools, and result serialization.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// â"€â"€â"€ Errors â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("tool '{0}' not found")]
    NotFound(String),
    #[error("invalid arguments: {0}")]
    InvalidArguments(String),
    #[error("schema validation failed: {0}")]
    SchemaValidation(String),
    #[error("execution failed: {0}")]
    Execution(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

// â"€â"€â"€ ToolInputSchema â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single property in a JSON Schema `properties` object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaProperty {
    /// JSON Schema type string, e.g. `"string"`, `"integer"`, `"boolean"`, `"array"`.
    pub r#type: String,
    /// Human-readable description of this property.
    pub description: String,
    /// Whether this property is required.
    #[serde(default)]
    pub required: bool,
    /// Enum values if the property is an enumeration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#enum: Option<Vec<serde_json::Value>>,
    /// Default value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<serde_json::Value>,
}

impl SchemaProperty {
    /// Create a required string property.
    #[must_use]
    pub fn required_string(description: impl Into<String>) -> Self {
        Self {
            r#type: "string".to_string(),
            description: description.into(),
            required: true,
            r#enum: None,
            default: None,
        }
    }

    /// Create an optional integer property.
    #[must_use]
    pub fn optional_integer(description: impl Into<String>, default: i64) -> Self {
        Self {
            r#type: "integer".to_string(),
            description: description.into(),
            required: false,
            r#enum: None,
            default: Some(serde_json::Value::Number(default.into())),
        }
    }

    /// Create an optional boolean property.
    #[must_use]
    pub fn optional_bool(description: impl Into<String>, default: bool) -> Self {
        Self {
            r#type: "boolean".to_string(),
            description: description.into(),
            required: false,
            r#enum: None,
            default: Some(serde_json::Value::Bool(default)),
        }
    }

    /// Create an optional string property.
    #[must_use]
    pub fn optional_string(description: impl Into<String>) -> Self {
        Self {
            r#type: "string".to_string(),
            description: description.into(),
            required: false,
            r#enum: None,
            default: None,
        }
    }
}

/// JSON Schema for the input of an agent tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInputSchema {
    pub r#type: String,
    pub properties: HashMap<String, SchemaProperty>,
    pub required: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ToolInputSchema {
    /// Create a new schema with `type: "object"`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            r#type: "object".to_string(),
            properties: HashMap::new(),
            required: Vec::new(),
            description: None,
        }
    }

    /// Add a property; if `prop.required` is true, also add to `required`.
    #[must_use]
    pub fn with_property(mut self, name: impl Into<String>, prop: SchemaProperty) -> Self {
        let name_str = name.into();
        if prop.required {
            self.required.push(name_str.clone());
        }
        self.properties.insert(name_str, prop);
        self
    }

    /// Validate a JSON value against this schema.
    ///
    /// # Errors
    /// Returns `ToolError::SchemaValidation` if required properties are missing
    /// or if a property type does not match.
    pub fn validate(&self, input: &serde_json::Value) -> Result<(), ToolError> {
        let obj = input.as_object().ok_or_else(|| {
            ToolError::SchemaValidation("input must be a JSON object".to_string())
        })?;

        // Check required fields are present.
        for req in &self.required {
            if !obj.contains_key(req.as_str()) {
                return Err(ToolError::SchemaValidation(format!(
                    "required field '{req}' is missing"
                )));
            }
        }

        // Type-check present fields.
        for (key, value) in obj {
            if let Some(prop) = self.properties.get(key.as_str()) {
                let type_ok = match prop.r#type.as_str() {
                    "string" => value.is_string(),
                    "integer" | "number" => value.is_number(),
                    "boolean" => value.is_boolean(),
                    "array" => value.is_array(),
                    "object" => value.is_object(),
                    "null" => value.is_null(),
                    _ => true, // unknown type —  pass
                };
                if !type_ok {
                    return Err(ToolError::SchemaValidation(format!(
                        "field '{key}' expected type '{}' but got '{}'",
                        prop.r#type,
                        json_type_name(value)
                    )));
                }
                // Enum check.
                if let Some(allowed) = &prop.r#enum
                    && !allowed.contains(value) {
                        return Err(ToolError::SchemaValidation(format!(
                            "field '{key}' value not in allowed enum"
                        )));
                    }
            }
        }
        Ok(())
    }
}

impl Default for ToolInputSchema {
    fn default() -> Self {
        Self::new()
    }
}

const fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

// â"€â"€â"€ ToolResult â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// The result of invoking an agent tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// Whether the tool call succeeded.
    pub success: bool,
    /// The output value (may be null on failure).
    pub output: serde_json::Value,
    /// Optional human-readable message.
    pub message: Option<String>,
    /// Duration of the tool call in milliseconds.
    pub duration_ms: u64,
    /// Metadata key/value pairs (e.g. token counts).
    pub metadata: HashMap<String, serde_json::Value>,
}

impl ToolResult {
    /// Create a successful result.
    #[must_use]
    pub fn success(output: serde_json::Value, duration_ms: u64) -> Self {
        Self {
            success: true,
            output,
            message: None,
            duration_ms,
            metadata: HashMap::new(),
        }
    }

    /// Create a successful result with a message.
    #[must_use]
    pub fn success_msg(
        output: serde_json::Value,
        message: impl Into<String>,
        duration_ms: u64,
    ) -> Self {
        Self {
            success: true,
            output,
            message: Some(message.into()),
            duration_ms,
            metadata: HashMap::new(),
        }
    }

    /// Create a failure result.
    #[must_use]
    pub fn failure(message: impl Into<String>) -> Self {
        Self {
            success: false,
            output: serde_json::Value::Null,
            message: Some(message.into()),
            duration_ms: 0,
            metadata: HashMap::new(),
        }
    }

    /// Serialize this result to a JSON string.
    ///
    /// # Errors
    /// Returns `ToolError::Serialization` if serialization fails.
    pub fn to_json(&self) -> Result<String, ToolError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| ToolError::Serialization(e.to_string()))
    }

    /// Add a metadata entry.
    #[must_use]
    pub fn with_meta(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

// â"€â"€â"€ AgentTool trait â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Every tool that can be called by an agent must implement this trait.
#[async_trait]
pub trait AgentTool: Send + Sync {
    /// Short machine-readable name, e.g. `"run_analysis"`.
    fn name(&self) -> &str;

    /// One-sentence description shown to the LLM.
    fn description(&self) -> &str;

    /// JSON Schema for the tool's input object.
    fn input_schema(&self) -> ToolInputSchema;

    /// Execute the tool with the given JSON arguments.
    ///
    /// # Errors
    /// Returns `ToolError` on any failure.
    async fn execute(&self, args: serde_json::Value) -> Result<ToolResult, ToolError>;

    /// Validate input before executing (calls `input_schema().validate()`).
    /// # Errors
    /// Returns `ToolError::SchemaValidation` if the args fail schema validation.
    fn validate_input(&self, args: &serde_json::Value) -> Result<(), ToolError> {
        self.input_schema().validate(args)
    }
}

// â"€â"€â"€ ToolRegistry â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Registry of all tools available to the agent.
pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn AgentTool>>,
}

impl ToolRegistry {
    /// Create a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// Register a tool.  Overwrites any previously registered tool with the same name.
    pub fn register(&mut self, tool: Arc<dyn AgentTool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    /// Register all built-in RE tools.
    pub fn register_builtins(&mut self) {
        self.register(Arc::new(RunAnalysisTool::new()));
        self.register(Arc::new(GetDecompilationTool::new()));
        self.register(Arc::new(SearchSymbolsTool::new()));
        self.register(Arc::new(AddCommentTool::new()));
        self.register(Arc::new(RunScriptTool::new()));
    }

    /// List all registered tool names, sorted.
    #[must_use]
    pub fn list(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.tools.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }

    /// Find a tool by name.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<Arc<dyn AgentTool>> {
        self.tools.get(name).cloned()
    }

    /// Invoke a tool by name after validating the input against its schema.
    ///
    /// # Errors
    /// Returns `ToolError::NotFound` if the name is unknown.
    /// Returns `ToolError::SchemaValidation` if validation fails.
    /// Returns any execution error the tool itself may produce.
    pub async fn invoke(
        &self,
        name: &str,
        args: serde_json::Value,
    ) -> Result<ToolResult, ToolError> {
        let tool = self
            .tools
            .get(name)
            .ok_or_else(|| ToolError::NotFound(name.to_string()))?
            .clone();

        tool.validate_input(&args)?;
        tool.execute(args).await
    }

    /// Return JSON Schema representations for all tools (useful for LLM system prompt).
    #[must_use]
    pub fn schema_list(&self) -> Vec<serde_json::Value> {
        let mut names: Vec<&str> = self.tools.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
            .into_iter()
            .filter_map(|n| self.tools.get(n))
            .map(|t| {
                serde_json::json!({
                    "name": t.name(),
                    "description": t.description(),
                    "input_schema": t.input_schema(),
                })
            })
            .collect()
    }

    /// Number of registered tools.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tools.len()
    }

    /// Returns `true` if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€â"€ Built-in tools â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

// â"€â"€ run_analysis â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Runs a disassembly/decompilation analysis on a function at a given address.
pub struct RunAnalysisTool {
    /// Simulated analysis database (address â†' pseudocode).
    db: parking_lot::Mutex<HashMap<u64, String>>,
}

impl RunAnalysisTool {
    #[must_use]
    pub fn new() -> Self {
        let mut db = HashMap::new();
        db.insert(0x1000, "int sub_1000() { return 42; }".to_string());
        db.insert(0x2000, "void main() { sub_1000(); }".to_string());
        Self {
            db: parking_lot::Mutex::new(db),
        }
    }
}

impl Default for RunAnalysisTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AgentTool for RunAnalysisTool {
    fn name(&self) -> &'static str {
        "run_analysis"
    }

    fn description(&self) -> &'static str {
        "Run disassembly and decompilation analysis on a function at the given address."
    }

    fn input_schema(&self) -> ToolInputSchema {
        ToolInputSchema::new()
            .with_property(
                "address",
                SchemaProperty {
                    r#type: "integer".to_string(),
                    description: "Virtual address of the function to analyse".to_string(),
                    required: true,
                    r#enum: None,
                    default: None,
                },
            )
            .with_property(
                "depth",
                SchemaProperty::optional_integer("Analysis depth (number of call levels)", 1),
            )
    }

    async fn execute(&self, args: serde_json::Value) -> Result<ToolResult, ToolError> {
        let t0 = std::time::Instant::now();
        let addr = args["address"]
            .as_u64()
            .ok_or_else(|| ToolError::InvalidArguments("address must be an integer".into()))?;

        let result = {
            let db = self.db.lock();
            db.get(&addr).cloned().unwrap_or_else(|| {
                format!("// No decompilation available for 0x{addr:016x}")
            })
        };

        Ok(ToolResult::success(
            serde_json::json!({ "address": format!("0x{addr:016x}"), "decompilation": result }),
            u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        ))
    }
}

// â"€â"€ get_decompilation â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Retrieves cached decompiled pseudocode for an address range.
pub struct GetDecompilationTool;

impl GetDecompilationTool {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for GetDecompilationTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AgentTool for GetDecompilationTool {
    fn name(&self) -> &'static str {
        "get_decompilation"
    }

    fn description(&self) -> &'static str {
        "Retrieve decompiled pseudocode for a function or address range."
    }

    fn input_schema(&self) -> ToolInputSchema {
        ToolInputSchema::new()
            .with_property("address", SchemaProperty::required_string("Start address as hex string (e.g. '0x401000')"))
            .with_property("length", SchemaProperty::optional_integer("Number of bytes to decompile (0 = whole function)", 0))
    }

    async fn execute(&self, args: serde_json::Value) -> Result<ToolResult, ToolError> {
        let t0 = std::time::Instant::now();
        let addr_str = args["address"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArguments("address must be a string".into()))?;

        let addr = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16)
            .map_err(|_| ToolError::InvalidArguments(format!("invalid hex address: {addr_str}")))?;

        let pseudocode = format!(
            "// Decompilation of 0x{addr:x}\nvoid func_{addr:x}(void) {{\n    // body\n}}"
        );

        Ok(ToolResult::success(
            serde_json::json!({ "address": addr_str, "pseudocode": pseudocode }),
            u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        ))
    }
}

// â"€â"€ search_symbols â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Searches the symbol table for names matching a query.
pub struct SearchSymbolsTool {
    symbols: parking_lot::RwLock<Vec<(u64, String)>>,
}

impl SearchSymbolsTool {
    #[must_use]
    pub fn new() -> Self {
        let syms = vec![
            (0x1000u64, "sub_1000".to_string()),
            (0x2000u64, "main".to_string()),
            (0x3000u64, "malloc_wrapper".to_string()),
            (0x4000u64, "decrypt_config".to_string()),
            (0x5000u64, "connect_c2".to_string()),
            (0x6000u64, "exfiltrate_data".to_string()),
        ];
        Self {
            symbols: parking_lot::RwLock::new(syms),
        }
    }

    /// Add a symbol to the simulated symbol table.
    pub fn add_symbol(&self, addr: u64, name: impl Into<String>) {
        self.symbols.write().push((addr, name.into()));
    }
}

impl Default for SearchSymbolsTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AgentTool for SearchSymbolsTool {
    fn name(&self) -> &'static str {
        "search_symbols"
    }

    fn description(&self) -> &'static str {
        "Search the binary's symbol table for functions or variables matching a query string."
    }

    fn input_schema(&self) -> ToolInputSchema {
        ToolInputSchema::new()
            .with_property("query", SchemaProperty::required_string("Search query (substring match, case-insensitive)"))
            .with_property("max_results", SchemaProperty::optional_integer("Maximum number of results to return", 50))
    }

    async fn execute(&self, args: serde_json::Value) -> Result<ToolResult, ToolError> {
        let t0 = std::time::Instant::now();
        let query = args["query"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArguments("query must be a string".into()))?
            .to_ascii_lowercase();

        let max = crate::casts::u64_to_usize(args["max_results"].as_u64().unwrap_or(50).min(10_000));

        let matches: Vec<serde_json::Value> = {
            let syms = self.symbols.read();
            syms.iter()
                .filter(|(_, name)| name.to_ascii_lowercase().contains(&query))
                .take(max)
                .map(|(addr, name)| {
                    serde_json::json!({ "address": format!("0x{addr:016x}"), "name": name })
                })
                .collect()
        };

        Ok(ToolResult::success(
            serde_json::json!({ "count": matches.len(), "symbols": matches }),
            u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        ))
    }
}

// â"€â"€ add_comment â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Adds an analyst comment at a specific address in the disassembly.
pub struct AddCommentTool {
    comments: parking_lot::Mutex<HashMap<u64, Vec<String>>>,
}

impl AddCommentTool {
    #[must_use]
    pub fn new() -> Self {
        Self {
            comments: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// Retrieve stored comments for an address (for testing).
    #[must_use]
    pub fn get_comments(&self, addr: u64) -> Vec<String> {
        self.comments.lock().get(&addr).cloned().unwrap_or_default()
    }
}

impl Default for AddCommentTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AgentTool for AddCommentTool {
    fn name(&self) -> &'static str {
        "add_comment"
    }

    fn description(&self) -> &'static str {
        "Add an analyst comment at a given address in the disassembly view."
    }

    fn input_schema(&self) -> ToolInputSchema {
        ToolInputSchema::new()
            .with_property(
                "address",
                SchemaProperty {
                    r#type: "integer".to_string(),
                    description: "Virtual address where the comment should be placed".to_string(),
                    required: true,
                    r#enum: None,
                    default: None,
                },
            )
            .with_property(
                "comment",
                SchemaProperty::required_string("The comment text"),
            )
            .with_property(
                "overwrite",
                SchemaProperty::optional_bool("Overwrite existing comments at this address", false),
            )
    }

    async fn execute(&self, args: serde_json::Value) -> Result<ToolResult, ToolError> {
        let t0 = std::time::Instant::now();
        let addr = args["address"]
            .as_u64()
            .ok_or_else(|| ToolError::InvalidArguments("address must be an integer".into()))?;
        let comment = args["comment"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArguments("comment must be a string".into()))?
            .to_string();
        let overwrite = args["overwrite"].as_bool().unwrap_or(false);

        let mut map = self.comments.lock();
        let entry = map.entry(addr).or_default();
        if overwrite {
            entry.clear();
        }
        entry.push(comment.clone());
        drop(map);

        Ok(ToolResult::success_msg(
            serde_json::json!({ "address": format!("0x{addr:016x}"), "comment": comment }),
            "Comment added successfully",
            u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        ))
    }
}

// â"€â"€ run_script â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Executes a small script (Python/IDAPython/Ghidra) in the disassembler.
pub struct RunScriptTool;

impl RunScriptTool {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for RunScriptTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AgentTool for RunScriptTool {
    fn name(&self) -> &'static str {
        "run_script"
    }

    fn description(&self) -> &'static str {
        "Execute a script (Python/IDAPython/Ghidra/JavaScript) inside the disassembler environment."
    }

    fn input_schema(&self) -> ToolInputSchema {
        ToolInputSchema::new()
            .with_property("code", SchemaProperty::required_string("The script source code to execute"))
            .with_property(
                "engine",
                SchemaProperty {
                    r#type: "string".to_string(),
                    description: "Script engine: 'python', 'idapython', 'ghidra', 'js'".to_string(),
                    required: false,
                    r#enum: Some(vec![
                        serde_json::json!("python"),
                        serde_json::json!("idapython"),
                        serde_json::json!("ghidra"),
                        serde_json::json!("js"),
                    ]),
                    default: Some(serde_json::json!("python")),
                },
            )
            .with_property(
                "timeout_ms",
                SchemaProperty::optional_integer("Script execution timeout in milliseconds", 30_000),
            )
    }

    async fn execute(&self, args: serde_json::Value) -> Result<ToolResult, ToolError> {
        let t0 = std::time::Instant::now();
        let code = args["code"]
            .as_str()
            .ok_or_else(|| ToolError::InvalidArguments("code must be a string".into()))?;
        let engine = args["engine"].as_str().unwrap_or("python");

        // In production this would forward to the actual disassembler IPC.
        let simulated_output = format!(
            "[{engine}] Executed {} bytes of script. (simulated)",
            code.len()
        );

        Ok(ToolResult::success(
            serde_json::json!({
                "engine": engine,
                "output": simulated_output,
                "return_code": 0,
            }),
            u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX),
        ))
    }
}

// â"€â"€â"€ Tests â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;

    fn make_registry() -> ToolRegistry {
        let mut reg = ToolRegistry::new();
        reg.register_builtins();
        reg
    }

    #[test]
    fn test_registry_list_builtins() {
        let reg = make_registry();
        let names = reg.list();
        assert!(names.contains(&"run_analysis"));
        assert!(names.contains(&"get_decompilation"));
        assert!(names.contains(&"search_symbols"));
        assert!(names.contains(&"add_comment"));
        assert!(names.contains(&"run_script"));
        assert_eq!(reg.len(), 5);
    }

    #[test]
    fn test_registry_find() {
        let reg = make_registry();
        assert!(reg.find("run_analysis").is_some());
        assert!(reg.find("nonexistent").is_none());
    }

    #[tokio::test]
    async fn test_run_analysis_known_address() {
        let reg = make_registry();
        let result = reg
            .invoke("run_analysis", serde_json::json!({"address": 0x1000u64}))
            .await
            .unwrap();
        assert!(result.success);
        let decomp = result.output["decompilation"].as_str().unwrap();
        assert!(decomp.contains("42"));
    }

    #[tokio::test]
    async fn test_run_analysis_unknown_address() {
        let reg = make_registry();
        let result = reg
            .invoke("run_analysis", serde_json::json!({"address": 0xdeadu64}))
            .await
            .unwrap();
        assert!(result.success);
        let decomp = result.output["decompilation"].as_str().unwrap();
        assert!(decomp.contains("No decompilation"));
    }

    #[tokio::test]
    async fn test_get_decompilation() {
        let reg = make_registry();
        let result = reg
            .invoke("get_decompilation", serde_json::json!({"address": "0x401000"}))
            .await
            .unwrap();
        assert!(result.success);
        assert!(result.output["pseudocode"].as_str().unwrap().contains("func_401000"));
    }

    #[tokio::test]
    async fn test_get_decompilation_bad_address() {
        let reg = make_registry();
        let err = reg
            .invoke("get_decompilation", serde_json::json!({"address": "not_hex"}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::InvalidArguments(_)));
    }

    #[tokio::test]
    async fn test_search_symbols() {
        let reg = make_registry();
        let result = reg
            .invoke("search_symbols", serde_json::json!({"query": "c2"}))
            .await
            .unwrap();
        assert!(result.success);
        let count = result.output["count"].as_u64().unwrap();
        assert!(count >= 1);
    }

    #[tokio::test]
    async fn test_search_symbols_no_match() {
        let reg = make_registry();
        let result = reg
            .invoke("search_symbols", serde_json::json!({"query": "xyzzy_nonexistent"}))
            .await
            .unwrap();
        assert!(result.success);
        assert_eq!(result.output["count"].as_u64().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_add_comment() {
        let tool = Arc::new(AddCommentTool::new());
        let mut reg = ToolRegistry::new();
        reg.register(tool.clone());
        let result = reg
            .invoke(
                "add_comment",
                serde_json::json!({"address": 0x1000u64, "comment": "This is a test comment"}),
            )
            .await
            .unwrap();
        assert!(result.success);
        let comments = tool.get_comments(0x1000);
        assert_eq!(comments.len(), 1);
        assert_eq!(comments[0], "This is a test comment");
    }

    #[tokio::test]
    async fn test_run_script_python() {
        let reg = make_registry();
        let result = reg
            .invoke(
                "run_script",
                serde_json::json!({"code": "print('hello')", "engine": "python"}),
            )
            .await
            .unwrap();
        assert!(result.success);
        assert_eq!(result.output["return_code"].as_i64().unwrap(), 0);
    }

    #[tokio::test]
    async fn test_invoke_not_found() {
        let reg = make_registry();
        let err = reg
            .invoke("ghost_tool", serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, ToolError::NotFound(_)));
    }

    #[test]
    fn test_schema_validation_missing_required() {
        let schema = ToolInputSchema::new()
            .with_property("addr", SchemaProperty::required_string("address"));
        let err = schema.validate(&serde_json::json!({})).unwrap_err();
        assert!(matches!(err, ToolError::SchemaValidation(_)));
    }

    #[test]
    fn test_schema_validation_wrong_type() {
        let schema = ToolInputSchema::new()
            .with_property("addr", SchemaProperty::required_string("address"));
        // Providing a number instead of a string.
        let err = schema
            .validate(&serde_json::json!({"addr": 42}))
            .unwrap_err();
        assert!(matches!(err, ToolError::SchemaValidation(_)));
    }

    #[test]
    fn test_schema_validation_ok() {
        let schema = ToolInputSchema::new()
            .with_property("addr", SchemaProperty::required_string("address"));
        assert!(schema
            .validate(&serde_json::json!({"addr": "0x1000"}))
            .is_ok());
    }

    #[test]
    fn test_tool_result_serialization() {
        let r = ToolResult::success(serde_json::json!({"val": 1}), 5);
        let json = r.to_json().unwrap();
        let back: ToolResult = serde_json::from_str(&json).unwrap();
        assert!(back.success);
        assert_eq!(back.duration_ms, 5);
    }

    #[test]
    fn test_schema_list_returns_all() {
        let reg = make_registry();
        let list = reg.schema_list();
        assert_eq!(list.len(), 5);
        assert!(list.iter().any(|v| v["name"] == "run_analysis"));
    }
}
