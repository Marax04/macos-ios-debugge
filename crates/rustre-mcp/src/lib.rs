//! `rustre-mcp`
//!
//! Model Context Protocol (MCP) coordinator for the RustRE Suite.
//!
//! Provides the [`McpTool`] trait, [`McpCoordinator`] registry, middleware
//! pipeline, batch dispatch, schema validation, rate limiting, per-tool
//! metrics, tool categories, streaming context propagation, and supporting
//! types for AI-assisted reverse-engineering tooling.
//!
//! ## Sub-modules
//!
//! * [`tool_registry`]  — JSON-Schema-validated tool registry with versioning.
//! * [`federation`]     — Multi-upstream MCP federation and tool proxying.
//! * [`tool_handlers`]  — Built-in RustRE MCP tool handler implementations.

// opt-1: replace the system allocator with mimalloc to reduce heap
// fragmentation on the MCP hot path (many small, short-lived JSON allocations).
use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

pub mod federation;
pub mod subcrates;

/// Run the `RustRE` MCP server over stdio with cross-cutting wire-mcp
/// tools (`rustre-mcp-tools::wire_tools::*`) registered into the catalog
/// in addition to the built-in handlers.
///
/// This is the entry point used by the `rustre-mcp` binary so the
/// path-aware analysis tools (`analysis_fn_detect_functions_path`,
/// `analysis_string_scan_path`, `analysis_crypto_scan_path`, plus the
/// rest of the wire-mcp surface) are exposed over MCP without creating
/// a `rustre-mcp-server` → `rustre-mcp-tools` dependency cycle.
///
/// # Errors
/// Propagates errors from the rmcp transport layer.
pub async fn run_stdio_wired() -> anyhow::Result<()> {
    let mut inner = rustre_mcp_server::RustReMcpServer::new();
    rustre_mcp_tools::wire_tools::wire_into_server(&mut inner);
    let server = rustre_mcp_server::RustREMcpServer::from_inner(inner);
    rustre_mcp_server::run_stdio_from(server).await
}

/// Same as [`run_stdio_wired`] but over HTTP/SSE.
///
/// # Errors
/// Propagates errors from the rmcp transport layer.
pub async fn run_http_wired(bind: &str) -> anyhow::Result<()> {
    let mut inner = rustre_mcp_server::RustReMcpServer::new();
    rustre_mcp_tools::wire_tools::wire_into_server(&mut inner);
    let server = rustre_mcp_server::RustREMcpServer::from_inner(inner);
    rustre_mcp_server::run_http_from(server, bind).await
}
pub mod mcp_capability_negotiator;
pub mod mcp_error_types;
pub mod mcp_notification_handler;
pub mod mcp_protocol_handler;
pub mod mcp_resource_provider;
pub mod mcp_tool_registry;
pub mod mcp_capabilities;
pub mod mcp_client;
pub mod mcp_protocol;
pub mod mcp_server_impl;
pub mod tool_handlers;
pub mod tool_pipeline;
pub mod tool_registry;

pub use mcp_capabilities::{
    CapabilityNegotiation, CapabilityVersion, ClientCapabilities, McpCapabilities,
    PromptCapability, ResourceCapability, SamplingCapability, ToolCapability,
};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Error types
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// All errors produced by the MCP subsystem.
#[derive(Error, Debug)]
pub enum McpError {
    /// No tool is registered under the requested name.
    #[error("Tool not found: {0}")]
    ToolNotFound(String),

    /// The request payload was structurally malformed.
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// The tool's [`McpTool::execute`] call returned an error.
    #[error("Execution error in '{tool}': {detail}")]
    Execution { tool: String, detail: String },

    /// JSON serialisation / deserialisation error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Schema validation failed for request parameters.
    #[error("Schema validation: {0}")]
    SchemaValidation(String),

    /// Rate limit exceeded for the given tool.
    #[error("Rate limit exceeded for tool '{0}'")]
    RateLimited(String),

    /// Middleware aborted the request.
    #[error("Middleware rejected request: {0}")]
    MiddlewareRejected(String),

    /// Timeout waiting for tool execution.
    #[error("Timeout executing tool '{0}'")]
    Timeout(String),

    /// Tool is in a category that is not enabled.
    #[error("Tool category '{0}' is disabled")]
    CategoryDisabled(String),

    /// Batch request contained more items than the configured limit.
    #[error("Batch too large: {count} > {limit}")]
    BatchTooLarge { count: usize, limit: usize },

    /// Internal coordinator error.
    #[error("Internal error: {0}")]
    Internal(String),
}

impl McpError {
    /// Construct an execution error for a named tool.
    #[must_use]
    pub fn execution(tool: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::Execution {
            tool: tool.into(),
            detail: detail.into(),
        }
    }

    /// Return `true` if this error is transient and may succeed on retry.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::RateLimited(_) | Self::Timeout(_))
    }

    /// Return `true` if the error is caused by bad client input.
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            Self::InvalidRequest(_)
                | Self::SchemaValidation(_)
                | Self::ToolNotFound(_)
                | Self::BatchTooLarge { .. }
        )
    }

    /// Map this error to a JSON-RPC 2.0 error code.
    #[must_use]
    pub fn rpc_code(&self) -> i32 {
        match self {
            Self::ToolNotFound(_) => -32601,
            Self::InvalidRequest(_) => -32600,
            Self::SchemaValidation(_) => -32602,
            Self::Serialization(_) => -32700,
            Self::RateLimited(_) => -32000,
            Self::MiddlewareRejected(_) => -32001,
            Self::Timeout(_) => -32002,
            Self::CategoryDisabled(_) => -32003,
            Self::BatchTooLarge { .. } => -32004,
            Self::Execution { .. } | Self::Internal(_) => -32603,
        }
    }

    /// Convert to an [`RpcError`] payload suitable for embedding in a response.
    #[must_use]
    pub fn to_rpc_error(&self) -> RpcError {
        RpcError {
            code: self.rpc_code(),
            message: self.to_string(),
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// McpCapability
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A discrete capability advertised by an [`McpTool`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpCapability {
    /// Short machine-readable name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Semantic version string.
    pub version: String,
}

impl McpCapability {
    /// Construct a new capability descriptor.
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
        }
    }
}

impl fmt::Display for McpCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.version)
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ToolCategory
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// High-level category that groups related MCP tools.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ToolCategory {
    /// Static analysis tools (disassembly, decompilation, …).
    Analysis,
    /// Dynamic / debugging tools.
    Debug,
    /// File-format loaders and parsers.
    Loader,
    /// Symbol resolution and type recovery.
    Symbols,
    /// Scripting and automation helpers.
    Script,
    /// Threat-intelligence integrations.
    ThreatIntel,
    /// Reporting and visualisation.
    Visualize,
    /// Utility / miscellaneous tools.
    Utility,
    /// Custom category.
    Custom(String),
}

impl ToolCategory {
    /// Return the canonical string name of this category.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Analysis => "analysis",
            Self::Debug => "debug",
            Self::Loader => "loader",
            Self::Symbols => "symbols",
            Self::Script => "script",
            Self::ThreatIntel => "threat_intel",
            Self::Visualize => "visualize",
            Self::Utility => "utility",
            Self::Custom(s) => s.as_str(),
        }
    }
}

impl fmt::Display for ToolCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ToolSchema
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// JSON-schema (subset) used to validate incoming request parameters.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolSchema {
    /// List of required top-level parameter names.
    pub required: Vec<String>,
    /// Expected type for each named parameter (`"string"`, `"number"`, …).
    pub param_types: HashMap<String, String>,
    /// Optional description of each parameter.
    pub param_descriptions: HashMap<String, String>,
}

impl ToolSchema {
    /// Build a schema with no constraints (accepts anything).
    #[must_use]
    pub fn any() -> Self {
        Self::default()
    }

    /// Require a parameter with a given type.
    #[must_use]
    pub fn require(mut self, name: impl Into<String>, ty: impl Into<String>) -> Self {
        let n = name.into();
        self.required.push(n.clone());
        self.param_types.insert(n, ty.into());
        self
    }

    /// Declare an optional parameter with a given type.
    #[must_use]
    pub fn optional(mut self, name: impl Into<String>, ty: impl Into<String>) -> Self {
        self.param_types.insert(name.into(), ty.into());
        self
    }

    /// Validate a JSON params object against this schema.
    ///
    /// # Errors
    /// Returns [`McpError::SchemaValidation`] if a required field is missing or
    /// if a field value has an unexpected type.
    pub fn validate(&self, params: &serde_json::Value) -> Result<(), McpError> {
        let obj = params
            .as_object()
            .ok_or_else(|| McpError::SchemaValidation("params must be a JSON object".into()))?;

        for req in &self.required {
            if !obj.contains_key(req.as_str()) {
                return Err(McpError::SchemaValidation(format!(
                    "missing required field '{req}'"
                )));
            }
        }

        for (name, expected_ty) in &self.param_types {
            if let Some(val) = obj.get(name.as_str()) {
                let actual = json_type_name(val);
                if actual != expected_ty.as_str() {
                    return Err(McpError::SchemaValidation(format!(
                        "field '{name}' expected {expected_ty} but got {actual}"
                    )));
                }
            }
        }

        Ok(())
    }
}

/// Return a short JSON type name for a value.
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

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// RequestContext
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Contextual metadata propagated through the dispatch pipeline.
#[derive(Debug, Clone, Default)]
pub struct RequestContext {
    /// Caller identity (e.g. agent name, session ID).
    pub caller: Option<String>,
    /// Trace/span ID for distributed tracing.
    pub trace_id: Option<String>,
    /// Unix epoch timestamp (ms) when the request was received.
    pub received_at_ms: u64,
    /// Arbitrary key/value metadata.
    pub metadata: HashMap<String, String>,
}

impl RequestContext {
    /// Create a context stamped with the current time.
    #[must_use]
    pub fn now() -> Self {
        Self {
            received_at_ms: epoch_ms(),
            ..Default::default()
        }
    }

    /// Attach a caller label.
    #[must_use]
    pub fn with_caller(mut self, caller: impl Into<String>) -> Self {
        self.caller = Some(caller.into());
        self
    }

    /// Attach a trace ID.
    #[must_use]
    pub fn with_trace_id(mut self, id: impl Into<String>) -> Self {
        self.trace_id = Some(id.into());
        self
    }

    /// Insert a metadata key/value pair.
    #[must_use]
    pub fn with_meta(mut self, k: impl Into<String>, v: impl Into<String>) -> Self {
        self.metadata.insert(k.into(), v.into());
        self
    }

    /// How many milliseconds ago this context was created.
    #[must_use]
    pub fn age_ms(&self) -> u64 {
        epoch_ms().saturating_sub(self.received_at_ms)
    }
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .min(u64::MAX as u128) as u64
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// McpRequest / McpResponse / RpcError
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// An inbound MCP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRequest {
    /// Unique request identifier (caller-assigned).
    pub id: String,
    /// Method / tool name to dispatch.
    pub method: String,
    /// Arbitrary JSON parameters for the tool.
    pub params: serde_json::Value,
}

impl McpRequest {
    /// Construct a request with no parameters.
    #[must_use]
    pub fn new(id: impl Into<String>, method: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            method: method.into(),
            params: serde_json::Value::Object(Default::default()),
        }
    }

    /// Construct a request with JSON parameters.
    #[must_use]
    pub fn with_params(
        id: impl Into<String>,
        method: impl Into<String>,
        params: serde_json::Value,
    ) -> Self {
        Self {
            id: id.into(),
            method: method.into(),
            params,
        }
    }
}

/// JSON-RPC-style error object embedded in an [`McpResponse`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcError {
    /// Numeric error code.
    pub code: i32,
    /// Human-readable message.
    pub message: String,
}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

/// An outbound MCP response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResponse {
    /// Correlates to the originating [`McpRequest::id`].
    pub id: String,
    /// Successful result payload.
    pub result: Option<serde_json::Value>,
    /// Structured error, if execution failed.
    pub error: Option<RpcError>,
    /// Execution duration in milliseconds.
    pub elapsed_ms: u64,
}

impl McpResponse {
    /// Build a successful response.
    #[must_use]
    pub fn ok(id: impl Into<String>, result: serde_json::Value, elapsed_ms: u64) -> Self {
        Self {
            id: id.into(),
            result: Some(result),
            error: None,
            elapsed_ms,
        }
    }

    /// Build an error response.
    #[must_use]
    pub fn err(id: impl Into<String>, error: RpcError, elapsed_ms: u64) -> Self {
        Self {
            id: id.into(),
            result: None,
            error: Some(error),
            elapsed_ms,
        }
    }

    /// Return `true` if this response represents a successful execution.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ToolMetrics
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Per-tool execution metrics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolMetrics {
    /// Total successful invocations.
    pub success_count: u64,
    /// Total failed invocations.
    pub error_count: u64,
    /// Total accumulated execution time (Âµs).
    pub total_us: u64,
    /// Fastest recorded execution (Âµs).
    pub min_us: u64,
    /// Slowest recorded execution (Âµs).
    pub max_us: u64,
    /// Latest error message recorded.
    pub last_error: Option<String>,
}

impl ToolMetrics {
    /// Record a completed invocation.
    pub fn record(&mut self, elapsed: Duration, ok: bool, error_msg: Option<String>) {
        let us = elapsed.as_micros().min(u64::MAX as u128) as u64;
        self.total_us = self.total_us.saturating_add(us);
        if self.total_calls() == 0 || us < self.min_us {
            self.min_us = us;
        }
        if us > self.max_us {
            self.max_us = us;
        }
        if ok {
            self.success_count += 1;
        } else {
            self.error_count += 1;
            self.last_error = error_msg;
        }
    }

    /// Total invocations.
    #[must_use]
    pub fn total_calls(&self) -> u64 {
        self.success_count + self.error_count
    }

    /// Average execution time in microseconds, or 0 if no calls.
    #[must_use]
    pub fn avg_us(&self) -> u64 {
        let t = self.total_calls();
        if t == 0 { 0 } else { self.total_us / t }
    }

    /// Error rate in [0.0, 1.0].
    #[must_use]
    pub fn error_rate(&self) -> f64 {
        let t = self.total_calls();
        if t == 0 {
            0.0
        } else {
            self.error_count as f64 / t as f64
        }
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// RateLimiter
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A token-bucket-style rate limiter (per tool).
#[derive(Debug)]
pub struct RateLimiter {
    /// Maximum calls allowed per window.
    pub max_calls: u64,
    /// Window duration.
    pub window: Duration,
    /// Timestamps of recent calls (ring buffer).
    calls: VecDeque<Instant>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    #[must_use]
    pub fn new(max_calls: u64, window: Duration) -> Self {
        Self {
            max_calls,
            window,
            calls: VecDeque::new(),
        }
    }

    /// Check whether a call is allowed right now; if so, record it.
    ///
    /// Returns `true` if the call is within the rate limit.
    pub fn allow(&mut self) -> bool {
        let now = Instant::now();
        // Evict old entries.
        while let Some(&front) = self.calls.front() {
            if now.duration_since(front) > self.window {
                self.calls.pop_front();
            } else {
                break;
            }
        }
        if self.calls.len() as u64 >= self.max_calls {
            return false;
        }
        self.calls.push_back(now);
        true
    }

    /// Current call count within the active window.
    #[must_use]
    pub fn current_count(&self) -> usize {
        self.calls.len()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ToolEntry (internal registry entry)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

struct ToolEntry {
    tool: Arc<dyn McpTool>,
    category: ToolCategory,
    schema: ToolSchema,
    rate_limiter: Option<RwLock<RateLimiter>>,
    metrics: RwLock<ToolMetrics>,
    /// Optional per-tool execution timeout in milliseconds.
    timeout_ms: Option<u64>,
}

impl fmt::Debug for ToolEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolEntry")
            .field("name", &self.tool.name())
            .field("category", &self.category)
            .finish_non_exhaustive()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// McpTool trait
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single MCP-compatible tool that can be dispatched by the coordinator.
#[async_trait::async_trait]
pub trait McpTool: Send + Sync {
    /// Short, unique tool identifier.
    fn name(&self) -> &str;

    /// Human-readable description.
    fn description(&self) -> &str;

    /// Category grouping for this tool.
    fn category(&self) -> ToolCategory {
        ToolCategory::Utility
    }

    /// Parameter schema for validation.  Override to enable schema checking.
    fn schema(&self) -> ToolSchema {
        ToolSchema::any()
    }

    /// List of capabilities exposed by this tool.
    fn capabilities(&self) -> Vec<McpCapability>;

    /// Execute the tool with the provided JSON parameters.
    ///
    /// # Errors
    /// Returns [`McpError`] on failure.
    async fn execute(
        &self,
        params: serde_json::Value,
        ctx: &RequestContext,
    ) -> Result<serde_json::Value, McpError>;
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Middleware
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A middleware hook that runs before tool dispatch.
///
/// Return `Ok(())` to allow the request, or `Err(McpError::MiddlewareRejected(…))`
/// to abort.
pub trait McpMiddleware: Send + Sync + fmt::Debug {
    /// Called before the tool is invoked.
    ///
    /// # Errors
    /// Returns [`McpError`] to abort dispatch.
    fn before(&self, req: &McpRequest, ctx: &RequestContext) -> Result<(), McpError>;
    /// Called after the tool returns (success or failure).
    fn after(&self, req: &McpRequest, resp: &McpResponse, ctx: &RequestContext);
}

/// A middleware that logs all requests via `tracing`.
#[derive(Debug, Clone, Default)]
pub struct LoggingMiddleware;

impl McpMiddleware for LoggingMiddleware {
    fn before(&self, req: &McpRequest, ctx: &RequestContext) -> Result<(), McpError> {
        tracing::debug!(
            id = %req.id,
            method = %req.method,
            caller = ?ctx.caller,
            "MCP dispatch"
        );
        Ok(())
    }

    fn after(&self, req: &McpRequest, resp: &McpResponse, _ctx: &RequestContext) {
        if resp.is_ok() {
            tracing::debug!(id = %req.id, elapsed_ms = %resp.elapsed_ms, "MCP ok");
        } else {
            tracing::warn!(
                id = %req.id,
                error = ?resp.error,
                "MCP error"
            );
        }
    }
}

/// A middleware that rejects requests from an explicit deny-list of callers.
#[derive(Debug)]
pub struct DenyListMiddleware {
    denied_callers: Vec<String>,
}

impl DenyListMiddleware {
    /// Create from a list of denied caller names.
    #[must_use]
    pub fn new(denied_callers: Vec<String>) -> Self {
        Self { denied_callers }
    }
}

impl McpMiddleware for DenyListMiddleware {
    fn before(&self, _req: &McpRequest, ctx: &RequestContext) -> Result<(), McpError> {
        if let Some(caller) = &ctx.caller
            && self.denied_callers.iter().any(|d| d == caller) {
                return Err(McpError::MiddlewareRejected(format!(
                    "caller '{caller}' is in the deny-list"
                )));
            }
        Ok(())
    }

    fn after(&self, _req: &McpRequest, _resp: &McpResponse, _ctx: &RequestContext) {}
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ToolRegistration (builder)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Builder returned by [`McpCoordinator::builder`].
pub struct ToolRegistration {
    tool: Arc<dyn McpTool>,
    category: ToolCategory,
    schema: ToolSchema,
    rate_limiter: Option<RateLimiter>,
    /// Optional execution timeout in milliseconds.
    timeout_ms: Option<u64>,
}

impl ToolRegistration {
    fn new(tool: Arc<dyn McpTool>) -> Self {
        let category = tool.category();
        let schema = tool.schema();
        Self {
            tool,
            category,
            schema,
            rate_limiter: None,
            timeout_ms: None,
        }
    }

    /// Override the category.
    #[must_use]
    pub fn category(mut self, cat: ToolCategory) -> Self {
        self.category = cat;
        self
    }

    /// Override the parameter schema.
    #[must_use]
    pub fn schema(mut self, schema: ToolSchema) -> Self {
        self.schema = schema;
        self
    }

    /// Attach a rate limiter.
    #[must_use]
    pub fn rate_limit(mut self, max_calls: u64, window: Duration) -> Self {
        self.rate_limiter = Some(RateLimiter::new(max_calls, window));
        self
    }

    /// Set a per-tool execution timeout in milliseconds.
    ///
    /// If the tool's [`McpTool::execute`] does not complete within this
    /// duration, the dispatch returns [`McpError::Timeout`].
    #[must_use]
    pub fn timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = Some(ms);
        self
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// BatchRequest / BatchResponse
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A batch of MCP requests executed in sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRequest {
    /// Individual requests in this batch.
    pub requests: Vec<McpRequest>,
}

impl BatchRequest {
    /// Construct from a list of requests.
    #[must_use]
    pub fn new(requests: Vec<McpRequest>) -> Self {
        Self { requests }
    }

    /// Number of requests in the batch.
    #[must_use]
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Return `true` if the batch is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }
}

/// The results of a batch dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResponse {
    /// Individual responses in the same order as the requests.
    pub responses: Vec<McpResponse>,
}

impl BatchResponse {
    /// Number of successful responses.
    #[must_use]
    pub fn success_count(&self) -> usize {
        self.responses.iter().filter(|r| r.is_ok()).count()
    }

    /// Number of failed responses.
    #[must_use]
    pub fn error_count(&self) -> usize {
        self.responses.iter().filter(|r| !r.is_ok()).count()
    }

    /// Return all error responses.
    #[must_use]
    pub fn errors(&self) -> Vec<&McpResponse> {
        self.responses.iter().filter(|r| !r.is_ok()).collect()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// AuditEntry
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A single audit-log entry produced for every dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Request ID.
    pub request_id: String,
    /// Tool name.
    pub tool: String,
    /// Caller identity.
    pub caller: Option<String>,
    /// Whether the call succeeded.
    pub success: bool,
    /// Epoch-ms timestamp.
    pub timestamp_ms: u64,
    /// Duration in milliseconds.
    pub elapsed_ms: u64,
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// McpCoordinator
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Registry and dispatcher for [`McpTool`] implementations.
///
/// Thread-safe and cheap to clone via [`Arc`].
pub struct McpCoordinator {
    tools: RwLock<HashMap<String, Arc<ToolEntry>>>,
    middleware: RwLock<Vec<Arc<dyn McpMiddleware>>>,
    disabled_categories: RwLock<Vec<ToolCategory>>,
    audit_log: RwLock<VecDeque<AuditEntry>>,
    audit_log_max: usize,
    batch_limit: usize,
}

impl fmt::Debug for McpCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("McpCoordinator")
            .field("tool_count", &self.tools.read().len())
            .field("middleware_count", &self.middleware.read().len())
            .finish_non_exhaustive()
    }
}

impl McpCoordinator {
    /// Create a new, empty coordinator with default limits.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tools: RwLock::new(HashMap::new()),
            middleware: RwLock::new(Vec::new()),
            disabled_categories: RwLock::new(Vec::new()),
            audit_log: RwLock::new(VecDeque::new()),
            audit_log_max: 10_000,
            batch_limit: 100,
        }
    }

    /// Create with custom audit-log size and batch limit.
    #[must_use]
    pub fn with_limits(audit_log_max: usize, batch_limit: usize) -> Self {
        Self {
            audit_log_max,
            batch_limit,
            ..Self::new()
        }
    }

    // â"€â"€ Tool registration â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Register a tool from a [`ToolRegistration`] builder.
    pub fn register(&self, reg: ToolRegistration) {
        let entry = Arc::new(ToolEntry {
            category: reg.category,
            schema: reg.schema,
            rate_limiter: reg.rate_limiter.map(RwLock::new),
            metrics: RwLock::new(ToolMetrics::default()),
            tool: reg.tool,
            timeout_ms: reg.timeout_ms,
        });
        self.tools
            .write()
            .insert(entry.tool.name().to_string(), entry);
    }

    /// Register a tool directly (uses the tool's own category/schema).
    pub fn register_tool(&self, tool: Arc<dyn McpTool>) {
        self.register(ToolRegistration::new(tool));
    }

    /// Begin building a registration for the given tool.
    #[must_use]
    pub fn builder(tool: Arc<dyn McpTool>) -> ToolRegistration {
        ToolRegistration::new(tool)
    }

    /// Remove a tool by name. Returns `true` if a tool was removed.
    pub fn remove_tool(&self, name: &str) -> bool {
        self.tools.write().remove(name).is_some()
    }

    /// Return `true` if a tool with the given name is registered.
    #[must_use]
    pub fn has_tool(&self, name: &str) -> bool {
        self.tools.read().contains_key(name)
    }

    /// Return the names of all registered tools (sorted).
    #[must_use]
    pub fn tool_names(&self) -> Vec<String> {
        let mut names: Vec<_> = self.tools.read().keys().cloned().collect();
        names.sort();
        names
    }

    /// Total number of registered tools.
    #[must_use]
    pub fn tool_count(&self) -> usize {
        self.tools.read().len()
    }

    /// Collect all capabilities across all registered tools.
    #[must_use]
    pub fn all_capabilities(&self) -> Vec<McpCapability> {
        self.tools
            .read()
            .values()
            .flat_map(|e| e.tool.capabilities())
            .collect()
    }

    /// Return tools in the given category.
    #[must_use]
    pub fn tools_by_category(&self, cat: &ToolCategory) -> Vec<String> {
        self.tools
            .read()
            .values()
            .filter(|e| &e.category == cat)
            .map(|e| e.tool.name().to_string())
            .collect()
    }

    // â"€â"€ Middleware â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Append a middleware to the pipeline.
    pub fn add_middleware(&self, mw: Arc<dyn McpMiddleware>) {
        self.middleware.write().push(mw);
    }

    /// Remove all middleware.
    pub fn clear_middleware(&self) {
        self.middleware.write().clear();
    }

    /// Number of middleware in the pipeline.
    #[must_use]
    pub fn middleware_count(&self) -> usize {
        self.middleware.read().len()
    }

    // â"€â"€ Category control â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Disable an entire tool category.
    pub fn disable_category(&self, cat: ToolCategory) {
        let mut cats = self.disabled_categories.write();
        if !cats.contains(&cat) {
            cats.push(cat);
        }
    }

    /// Re-enable a previously disabled category.
    pub fn enable_category(&self, cat: &ToolCategory) {
        self.disabled_categories.write().retain(|c| c != cat);
    }

    /// Return `true` if the category is currently enabled.
    #[must_use]
    pub fn is_category_enabled(&self, cat: &ToolCategory) -> bool {
        !self.disabled_categories.read().contains(cat)
    }

    // â"€â"€ Metrics â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Snapshot the metrics for a named tool.
    #[must_use]
    pub fn metrics(&self, name: &str) -> Option<ToolMetrics> {
        self.tools
            .read()
            .get(name)
            .map(|e| e.metrics.read().clone())
    }

    /// Return metrics for all tools.
    #[must_use]
    pub fn all_metrics(&self) -> HashMap<String, ToolMetrics> {
        self.tools
            .read()
            .iter()
            .map(|(k, e)| (k.clone(), e.metrics.read().clone()))
            .collect()
    }

    // â"€â"€ Audit log â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Recent audit entries, oldest first.
    #[must_use]
    pub fn audit_log(&self) -> Vec<AuditEntry> {
        self.audit_log.read().iter().cloned().collect()
    }

    /// Clear the audit log.
    pub fn clear_audit_log(&self) {
        self.audit_log.write().clear();
    }

    /// Number of entries in the audit log.
    #[must_use]
    pub fn audit_log_len(&self) -> usize {
        self.audit_log.read().len()
    }

    fn push_audit(&self, entry: AuditEntry) {
        let mut log = self.audit_log.write();
        if log.len() >= self.audit_log_max {
            log.pop_front();
        }
        log.push_back(entry);
    }

    // â"€â"€ Dispatch â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    /// Dispatch an [`McpRequest`] to the appropriate tool.
    ///
    /// All middleware is invoked; metrics and audit log are updated.
    pub async fn dispatch(&self, req: McpRequest) -> McpResponse {
        self.dispatch_with_context(req, RequestContext::now()).await
    }

    /// Dispatch with an explicit [`RequestContext`].
    pub async fn dispatch_with_context(&self, req: McpRequest, ctx: RequestContext) -> McpResponse {
        let start = Instant::now();

        // Run before-middleware.
        let mw_snapshot: Vec<Arc<dyn McpMiddleware>> = self.middleware.read().clone();
        for mw in &mw_snapshot {
            if let Err(e) = mw.before(&req, &ctx) {
                let elapsed_ms = start.elapsed().as_millis().min(u64::MAX as u128) as u64;
                let rpc_err = e.to_rpc_error();
                let resp = McpResponse::err(req.id.clone(), rpc_err, elapsed_ms);
                for mw2 in &mw_snapshot {
                    mw2.after(&req, &resp, &ctx);
                }
                return resp;
            }
        }

        // Look up tool entry.
        let entry = match self.tools.read().get(&req.method).cloned() {
            Some(e) => e,
            None => {
                let elapsed_ms = start.elapsed().as_millis().min(u64::MAX as u128) as u64;
                let err = McpError::ToolNotFound(req.method.clone());
                let rpc_err = err.to_rpc_error();
                let resp = McpResponse::err(req.id.clone(), rpc_err, elapsed_ms);
                for mw in &mw_snapshot {
                    mw.after(&req, &resp, &ctx);
                }
                return resp;
            }
        };

        // Category check.
        if !self.is_category_enabled(&entry.category) {
            let elapsed_ms = start.elapsed().as_millis().min(u64::MAX as u128) as u64;
            let err = McpError::CategoryDisabled(entry.category.to_string());
            let rpc_err = err.to_rpc_error();
            let resp = McpResponse::err(req.id.clone(), rpc_err, elapsed_ms);
            for mw in &mw_snapshot {
                mw.after(&req, &resp, &ctx);
            }
            return resp;
        }

        // Rate limit check.
        if let Some(rl) = &entry.rate_limiter
            && !rl.write().allow() {
                let elapsed_ms = start.elapsed().as_millis().min(u64::MAX as u128) as u64;
                let err = McpError::RateLimited(req.method.clone());
                let rpc_err = err.to_rpc_error();
                let resp = McpResponse::err(req.id.clone(), rpc_err, elapsed_ms);
                for mw in &mw_snapshot {
                    mw.after(&req, &resp, &ctx);
                }
                self.push_audit(AuditEntry {
                    request_id: req.id,
                    tool: req.method,
                    caller: ctx.caller.clone(),
                    success: false,
                    timestamp_ms: ctx.received_at_ms,
                    elapsed_ms,
                });
                return resp;
            }

        // Schema validation.
        if let Err(e) = entry.schema.validate(&req.params) {
            let elapsed_ms = start.elapsed().as_millis().min(u64::MAX as u128) as u64;
            let rpc_err = e.to_rpc_error();
            let resp = McpResponse::err(req.id.clone(), rpc_err, elapsed_ms);
            for mw in &mw_snapshot {
                mw.after(&req, &resp, &ctx);
            }
            return resp;
        }

        // Execute the tool, honouring per-tool timeout if configured.
        let exec_result = if let Some(ms) = entry.timeout_ms {
            match tokio::time::timeout(
                Duration::from_millis(ms),
                entry.tool.execute(req.params.clone(), &ctx),
            )
            .await
            {
                Ok(result) => result,
                Err(_elapsed) => Err(McpError::Timeout(req.method.clone())),
            }
        } else {
            entry.tool.execute(req.params.clone(), &ctx).await
        };
        let elapsed = start.elapsed();
        let elapsed_ms = elapsed.as_millis().min(u64::MAX as u128) as u64;

        let (resp, ok, err_msg) = match exec_result {
            Ok(val) => (McpResponse::ok(req.id.clone(), val, elapsed_ms), true, None),
            Err(e) => {
                let msg = e.to_string();
                let rpc_err = e.to_rpc_error();
                (
                    McpResponse::err(req.id.clone(), rpc_err, elapsed_ms),
                    false,
                    Some(msg),
                )
            }
        };

        // Update metrics.
        entry.metrics.write().record(elapsed, ok, err_msg);

        // Append audit entry.
        self.push_audit(AuditEntry {
            request_id: req.id.clone(),
            tool: req.method.clone(),
            caller: ctx.caller.clone(),
            success: ok,
            timestamp_ms: ctx.received_at_ms,
            elapsed_ms,
        });

        // Run after-middleware.
        for mw in &mw_snapshot {
            mw.after(&req, &resp, &ctx);
        }

        resp
    }

    /// Dispatch a [`BatchRequest`], returning a [`BatchResponse`].
    ///
    /// All requests in the batch are executed **concurrently** via
    /// [`futures::future::join_all`]. This means a large batch can saturate
    /// per-tool rate-limiters in a single call; callers that need ordered,
    /// sequential semantics should dispatch requests individually.
    ///
    /// # Errors
    /// Returns [`McpError::BatchTooLarge`] if the batch exceeds the limit.
    pub async fn dispatch_batch(
        &self,
        batch: BatchRequest,
        ctx: RequestContext,
    ) -> Result<BatchResponse, McpError> {
        let count = batch.requests.len();
        if count > self.batch_limit {
            return Err(McpError::BatchTooLarge {
                count,
                limit: self.batch_limit,
            });
        }
        // Dispatch all requests concurrently instead of sequentially.
        let futures: Vec<_> = batch
            .requests
            .into_iter()
            .map(|req| {
                let ctx = ctx.clone();
                self.dispatch_with_context(req, ctx)
            })
            .collect();
        let responses = futures::future::join_all(futures).await;
        Ok(BatchResponse { responses })
    }
}

impl Default for McpCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Built-in tools
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A tool that echoes its input parameters back as the result.
#[derive(Debug, Clone)]
pub struct EchoTool;

#[async_trait::async_trait]
impl McpTool for EchoTool {
    fn name(&self) -> &str {
        "echo"
    }
    fn description(&self) -> &str {
        "Echoes the input parameters back as the result"
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Utility
    }
    fn capabilities(&self) -> Vec<McpCapability> {
        vec![McpCapability::new("echo", "Echo parameters back", "1.0.0")]
    }

    async fn execute(
        &self,
        params: serde_json::Value,
        _ctx: &RequestContext,
    ) -> Result<serde_json::Value, McpError> {
        Ok(params)
    }
}

/// A tool that always returns an execution error.
#[derive(Debug, Clone)]
pub struct FailingTool;

#[async_trait::async_trait]
impl McpTool for FailingTool {
    fn name(&self) -> &str {
        "fail"
    }
    fn description(&self) -> &str {
        "Always returns an execution error"
    }
    fn capabilities(&self) -> Vec<McpCapability> {
        vec![]
    }

    async fn execute(
        &self,
        _params: serde_json::Value,
        _ctx: &RequestContext,
    ) -> Result<serde_json::Value, McpError> {
        Err(McpError::execution("fail", "intentional failure"))
    }
}

/// A tool that returns metadata about the coordinator.
#[derive(Debug)]
pub struct IntrospectTool {
    coordinator: Arc<McpCoordinator>,
}

impl IntrospectTool {
    /// Create bound to the given coordinator.
    #[must_use]
    pub fn new(coordinator: Arc<McpCoordinator>) -> Self {
        Self { coordinator }
    }
}

#[async_trait::async_trait]
impl McpTool for IntrospectTool {
    fn name(&self) -> &str {
        "introspect"
    }
    fn description(&self) -> &str {
        "Returns metadata about all registered tools"
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Utility
    }
    fn capabilities(&self) -> Vec<McpCapability> {
        vec![McpCapability::new(
            "introspect",
            "List registered tools",
            "1.0.0",
        )]
    }

    async fn execute(
        &self,
        _params: serde_json::Value,
        _ctx: &RequestContext,
    ) -> Result<serde_json::Value, McpError> {
        let names = self.coordinator.tool_names();
        Ok(serde_json::json!({
            "tool_count": names.len(),
            "tools": names,
        }))
    }
}

/// A tool that produces a diagnostic JSON blob with coordinator health.
#[derive(Debug, Clone)]
pub struct HealthTool;

#[async_trait::async_trait]
impl McpTool for HealthTool {
    fn name(&self) -> &str {
        "health"
    }
    fn description(&self) -> &str {
        "Returns coordinator health status"
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Utility
    }
    fn capabilities(&self) -> Vec<McpCapability> {
        vec![McpCapability::new(
            "health",
            "Coordinator health check",
            "1.0.0",
        )]
    }

    async fn execute(
        &self,
        _params: serde_json::Value,
        _ctx: &RequestContext,
    ) -> Result<serde_json::Value, McpError> {
        Ok(serde_json::json!({ "status": "ok", "timestamp_ms": epoch_ms() }))
    }
}

/// A tool that validates its own parameter schema before execution.
#[derive(Debug, Clone)]
pub struct ValidatedTool {
    tool_name: String,
    required_field: String,
}

impl ValidatedTool {
    /// Create a tool that requires the given field name.
    #[must_use]
    pub fn new(tool_name: impl Into<String>, required_field: impl Into<String>) -> Self {
        Self {
            tool_name: tool_name.into(),
            required_field: required_field.into(),
        }
    }
}

#[async_trait::async_trait]
impl McpTool for ValidatedTool {
    fn name(&self) -> &str {
        &self.tool_name
    }
    fn description(&self) -> &str {
        "A schema-validated tool example"
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Utility
    }
    fn schema(&self) -> ToolSchema {
        ToolSchema::any().require(self.required_field.clone(), "string")
    }
    fn capabilities(&self) -> Vec<McpCapability> {
        vec![]
    }

    async fn execute(
        &self,
        params: serde_json::Value,
        _ctx: &RequestContext,
    ) -> Result<serde_json::Value, McpError> {
        Ok(serde_json::json!({ "received": params }))
    }
}

/// A counter tool that increments an internal counter and returns its value.
#[derive(Debug)]
pub struct CounterTool {
    count: RwLock<u64>,
}

impl CounterTool {
    /// Create a new counter starting at zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            count: RwLock::new(0),
        }
    }

    /// Current counter value.
    #[must_use]
    pub fn value(&self) -> u64 {
        *self.count.read()
    }
}

impl Default for CounterTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl McpTool for CounterTool {
    fn name(&self) -> &str {
        "counter"
    }
    fn description(&self) -> &str {
        "Increments and returns an internal counter"
    }
    fn category(&self) -> ToolCategory {
        ToolCategory::Utility
    }
    fn capabilities(&self) -> Vec<McpCapability> {
        vec![McpCapability::new("counter", "Stateful counter", "1.0.0")]
    }

    async fn execute(
        &self,
        _params: serde_json::Value,
        _ctx: &RequestContext,
    ) -> Result<serde_json::Value, McpError> {
        let mut c = self.count.write();
        *c += 1;
        Ok(serde_json::json!({ "count": *c }))
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// ToolRegistry snapshot
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A serialisable snapshot of the tools registered in a coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDescriptor {
    /// Tool name.
    pub name: String,
    /// Tool description.
    pub description: String,
    /// Category.
    pub category: String,
    /// Capabilities.
    pub capabilities: Vec<McpCapability>,
}

impl McpCoordinator {
    /// Return descriptors for all registered tools.
    #[must_use]
    pub fn tool_descriptors(&self) -> Vec<ToolDescriptor> {
        let guard = self.tools.read();
        let mut out: Vec<ToolDescriptor> = guard
            .values()
            .map(|e| ToolDescriptor {
                name: e.tool.name().to_string(),
                description: e.tool.description().to_string(),
                category: e.category.to_string(),
                capabilities: e.tool.capabilities(),
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// §30.2 McpCapabilityFlags — server-level capability advertisement
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Server-level capability flags advertised during MCP session negotiation
/// (spec §30.2).  Each field corresponds to one capability category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct McpCapabilityFlags {
    /// Server exposes callable tools.
    pub tools: bool,
    /// Server exposes addressable resources (URIs).
    pub resources: bool,
    /// Server provides prompt templates.
    pub prompts: bool,
    /// Server supports structured logging.
    pub logging: bool,
}

impl McpCapabilityFlags {
    /// Capability set with everything enabled.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            tools: true,
            resources: true,
            prompts: true,
            logging: true,
        }
    }

    /// Capability set with only tools enabled.
    #[must_use]
    pub const fn tools_only() -> Self {
        Self {
            tools: true,
            resources: false,
            prompts: false,
            logging: false,
        }
    }

    /// Return `true` if at least one capability is enabled.
    #[must_use]
    pub fn any(&self) -> bool {
        self.tools || self.resources || self.prompts || self.logging
    }

    /// Serialize to a JSON object suitable for an MCP `initialize` response.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "tools":     { "enabled": self.tools },
            "resources": { "enabled": self.resources },
            "prompts":   { "enabled": self.prompts },
            "logging":   { "enabled": self.logging },
        })
    }
}

impl fmt::Display for McpCapabilityFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = Vec::with_capacity(4);
        if self.tools {
            flags.push("tools");
        }
        if self.resources {
            flags.push("resources");
        }
        if self.prompts {
            flags.push("prompts");
        }
        if self.logging {
            flags.push("logging");
        }
        write!(f, "[{}]", flags.join(", "))
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// §30.2 McpToolDef — static definition of a single MCP tool
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A static definition of an MCP tool (spec §30.2).
///
/// `input_schema` must be a valid JSON Schema object describing the `input`
/// parameter of the tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolDef {
    /// Unique tool identifier, e.g. `"project.open"`.
    pub name: String,
    /// Human-readable description surfaced to the LLM.
    pub description: String,
    /// JSON Schema describing accepted input parameters.
    pub input_schema: serde_json::Value,
}

impl McpToolDef {
    /// Construct a tool definition.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        input_schema: serde_json::Value,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            input_schema,
        }
    }

    /// Build a simple schema with a fixed set of required string/number/boolean
    /// properties.  Each item is `(property_name, json_type, description)`.
    #[must_use]
    pub fn simple_schema(props: &[(&str, &str, &str)]) -> serde_json::Value {
        let mut properties = serde_json::Map::new();
        let mut required: Vec<serde_json::Value> = Vec::with_capacity(props.len());
        for (name, ty, desc) in props {
            properties.insert(
                (*name).to_owned(),
                serde_json::json!({ "type": ty, "description": desc }),
            );
            required.push(serde_json::Value::String((*name).to_owned()));
        }
        serde_json::json!({
            "type": "object",
            "properties": properties,
            "required": required,
        })
    }
}

impl fmt::Display for McpToolDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "McpToolDef({})", self.name)
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// §30.2 McpResourceDef — static definition of a single MCP resource
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// A static definition of an MCP resource (spec §30.2).
///
/// Resources are addressable by URI and returned as text or binary blobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResourceDef {
    /// The resource URI, e.g. `"rustre://project/current"`.
    pub uri: String,
    /// Short display name.
    pub name: String,
    /// Human-readable description surfaced to the LLM.
    pub description: String,
    /// MIME type of the resource content, e.g. `"application/json"`.
    pub mime_type: String,
}

impl McpResourceDef {
    /// Construct a resource definition.
    #[must_use]
    pub fn new(
        uri: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        mime_type: impl Into<String>,
    ) -> Self {
        Self {
            uri: uri.into(),
            name: name.into(),
            description: description.into(),
            mime_type: mime_type.into(),
        }
    }

    /// Return `true` if the MIME type is a text variant.
    #[must_use]
    pub fn is_text(&self) -> bool {
        self.mime_type.starts_with("text/") || self.mime_type == "application/json"
    }
}

impl fmt::Display for McpResourceDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "McpResourceDef({} -> {})", self.name, self.uri)
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// §30.3 RustreCapabilities — full tool + resource catalogue
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Static catalogue of all RustRE MCP tools and resources (spec §30.3).
///
/// This is the authoritative source-of-truth for the tool list exposed by the
/// `rustre-mcp-server` crate.  Consumers call [`RustreCapabilities::list_tools`]
/// and [`RustreCapabilities::list_resources`] to obtain the definitions they
/// need to register with an [`McpCoordinator`] or to populate an MCP
/// `initialize` response.
pub struct RustreCapabilities;

impl RustreCapabilities {
    /// Return all 20+ RustRE tools as [`McpToolDef`] instances (spec §30.3).
    ///
    /// Tools are grouped by namespace:
    /// * `project.*`  — project lifecycle
    /// * `binary.*`   — binary metadata and loading
    /// * `disasm.*`   — disassembly
    /// * `analyze.*`  — static analysis
    /// * `decompile.*`— decompilation
    /// * `symbols.*`  — symbol management
    /// * `types.*`    — type system
    /// * `xref.*`     — cross-references
    /// * `search.*`   — pattern and string search
    /// * `patch.*`    — binary patching
    /// * `debug.*`    — debugger integration
    /// * `script.*`   — scripting engine
    #[must_use]
    pub fn list_tools() -> Vec<McpToolDef> {
        vec![
            // â"€â"€ project.* â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            McpToolDef::new(
                "project.open",
                "Open a new or existing RustRE project at the given path.",
                McpToolDef::simple_schema(&[(
                    "path",
                    "string",
                    "Absolute path to the project directory or .rustre file",
                )]),
            ),
            McpToolDef::new(
                "project.close",
                "Close the currently open project, flushing all unsaved analysis data.",
                serde_json::json!({ "type": "object", "properties": {}, "required": [] }),
            ),
            McpToolDef::new(
                "project.info",
                "Return metadata about the currently open project (name, path, binary count, …).",
                serde_json::json!({ "type": "object", "properties": {}, "required": [] }),
            ),
            McpToolDef::new(
                "project.save",
                "Persist all pending analysis results to the project file.",
                serde_json::json!({ "type": "object", "properties": {}, "required": [] }),
            ),
            // â"€â"€ binary.* â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            McpToolDef::new(
                "binary.load",
                "Load a binary file into the current project for analysis.",
                McpToolDef::simple_schema(&[(
                    "path",
                    "string",
                    "Absolute path to the binary file to load",
                )]),
            ),
            McpToolDef::new(
                "binary.info",
                "Return metadata about a loaded binary: format, architecture, entry point, sections.",
                McpToolDef::simple_schema(&[(
                    "binary_id",
                    "string",
                    "Opaque binary identifier returned by binary.load",
                )]),
            ),
            McpToolDef::new(
                "binary.list",
                "List all binaries currently loaded in the project.",
                serde_json::json!({ "type": "object", "properties": {}, "required": [] }),
            ),
            McpToolDef::new(
                "binary.unload",
                "Unload a binary and free associated analysis data.",
                McpToolDef::simple_schema(&[(
                    "binary_id",
                    "string",
                    "Binary identifier to unload",
                )]),
            ),
            // â"€â"€ disasm.* â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            McpToolDef::new(
                "disasm.at",
                "Disassemble `count` instructions starting at `addr` inside the given binary.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string", "description": "Target binary identifier" },
                        "addr":      { "type": "integer", "description": "Virtual address to start disassembly" },
                        "count":     { "type": "integer", "description": "Number of instructions to decode (default 16)" }
                    },
                    "required": ["binary_id", "addr"]
                }),
            ),
            McpToolDef::new(
                "disasm.function",
                "Disassemble all basic blocks of the function at `addr`.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string", "description": "Target binary identifier" },
                        "addr":      { "type": "integer", "description": "Function entry-point virtual address" }
                    },
                    "required": ["binary_id", "addr"]
                }),
            ),
            McpToolDef::new(
                "disasm.range",
                "Disassemble all instructions in the virtual address range [start, end).",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string", "description": "Target binary identifier" },
                        "start":     { "type": "integer", "description": "Range start (inclusive)" },
                        "end":       { "type": "integer", "description": "Range end (exclusive)" }
                    },
                    "required": ["binary_id", "start", "end"]
                }),
            ),
            // â"€â"€ analyze.* â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            McpToolDef::new(
                "analyze.function",
                "Run the full analysis pipeline (CFG, data-flow, calling convention) on the function at `addr`.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string", "description": "Target binary identifier" },
                        "addr":      { "type": "integer", "description": "Function entry-point virtual address" }
                    },
                    "required": ["binary_id", "addr"]
                }),
            ),
            McpToolDef::new(
                "analyze.all",
                "Trigger full automatic analysis of all loaded binaries.",
                serde_json::json!({ "type": "object", "properties": {}, "required": [] }),
            ),
            McpToolDef::new(
                "analyze.callgraph",
                "Return the inter-procedural call graph rooted at `addr` up to `depth` levels.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string", "description": "Target binary identifier" },
                        "addr":      { "type": "integer", "description": "Root function address" },
                        "depth":     { "type": "integer", "description": "Maximum call-graph depth (default 3)" }
                    },
                    "required": ["binary_id", "addr"]
                }),
            ),
            McpToolDef::new(
                "analyze.cfg",
                "Return the control-flow graph (basic blocks and edges) for the function at `addr`.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string", "description": "Target binary identifier" },
                        "addr":      { "type": "integer", "description": "Function entry-point virtual address" }
                    },
                    "required": ["binary_id", "addr"]
                }),
            ),
            // â"€â"€ decompile.* â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            McpToolDef::new(
                "decompile.function",
                "Decompile the function at `addr` to pseudo-C source code.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string", "description": "Target binary identifier" },
                        "addr":      { "type": "integer", "description": "Function entry-point virtual address" }
                    },
                    "required": ["binary_id", "addr"]
                }),
            ),
            McpToolDef::new(
                "decompile.range",
                "Decompile all functions that overlap with the virtual address range [start, end).",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string", "description": "Target binary identifier" },
                        "start":     { "type": "integer", "description": "Range start address" },
                        "end":       { "type": "integer", "description": "Range end address" }
                    },
                    "required": ["binary_id", "start", "end"]
                }),
            ),
            // â"€â"€ symbols.* â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            McpToolDef::new(
                "symbols.list",
                "List all symbols (functions, globals, imports, exports) in the binary.",
                McpToolDef::simple_schema(&[("binary_id", "string", "Target binary identifier")]),
            ),
            McpToolDef::new(
                "symbols.rename",
                "Rename a symbol at the given address.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string", "description": "Target binary identifier" },
                        "addr":      { "type": "integer", "description": "Symbol address" },
                        "new_name":  { "type": "string",  "description": "New symbol name" }
                    },
                    "required": ["binary_id", "addr", "new_name"]
                }),
            ),
            McpToolDef::new(
                "symbols.lookup",
                "Look up a symbol by name and return its address and type.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string", "description": "Target binary identifier" },
                        "name":      { "type": "string",  "description": "Symbol name to look up" }
                    },
                    "required": ["binary_id", "name"]
                }),
            ),
            McpToolDef::new(
                "symbols.import_pdb",
                "Import symbol names from a PDB file and annotate the binary.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string", "description": "Target binary identifier" },
                        "pdb_path":  { "type": "string",  "description": "Absolute path to the PDB file" }
                    },
                    "required": ["binary_id", "pdb_path"]
                }),
            ),
            // â"€â"€ types.* â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            McpToolDef::new(
                "types.define",
                "Define or update a type (struct, enum, typedef) in the type library.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id":   { "type": "string", "description": "Target binary identifier" },
                        "type_source": { "type": "string", "description": "C-like type definition source" }
                    },
                    "required": ["binary_id", "type_source"]
                }),
            ),
            McpToolDef::new(
                "types.apply",
                "Apply a type to a variable or memory location.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string",  "description": "Target binary identifier" },
                        "addr":      { "type": "integer", "description": "Target address" },
                        "type_name": { "type": "string",  "description": "Type name from the type library" }
                    },
                    "required": ["binary_id", "addr", "type_name"]
                }),
            ),
            // â"€â"€ xref.* â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            McpToolDef::new(
                "xref.to",
                "Return all cross-references *to* the given address.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string",  "description": "Target binary identifier" },
                        "addr":      { "type": "integer", "description": "Target address" }
                    },
                    "required": ["binary_id", "addr"]
                }),
            ),
            McpToolDef::new(
                "xref.from",
                "Return all cross-references *from* the given address.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string",  "description": "Target binary identifier" },
                        "addr":      { "type": "integer", "description": "Source address" }
                    },
                    "required": ["binary_id", "addr"]
                }),
            ),
            // â"€â"€ search.* â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            McpToolDef::new(
                "search.bytes",
                "Search for a byte pattern (hex string, e.g. `\"4889E5\"` or `\"48 89 E5\"`) in the binary.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string", "description": "Target binary identifier" },
                        "pattern":   { "type": "string", "description": "Hex byte pattern, spaces optional" }
                    },
                    "required": ["binary_id", "pattern"]
                }),
            ),
            McpToolDef::new(
                "search.string",
                "Search for ASCII or Unicode string literals in the binary's data sections.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string", "description": "Target binary identifier" },
                        "query":     { "type": "string", "description": "Substring or regex to match against" },
                        "regex":     { "type": "boolean","description": "Treat query as a regular expression (default false)" }
                    },
                    "required": ["binary_id", "query"]
                }),
            ),
            McpToolDef::new(
                "search.function",
                "Search for functions whose name matches a substring or regex.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string",  "description": "Target binary identifier" },
                        "query":     { "type": "string",  "description": "Name substring or regex" },
                        "regex":     { "type": "boolean", "description": "Treat query as a regex (default false)" }
                    },
                    "required": ["binary_id", "query"]
                }),
            ),
            // â"€â"€ patch.* â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            McpToolDef::new(
                "patch.bytes",
                "Overwrite bytes at `addr` with the provided hex-encoded replacement bytes.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string",  "description": "Target binary identifier" },
                        "addr":      { "type": "integer", "description": "Virtual address to patch" },
                        "bytes":     { "type": "string",  "description": "Hex-encoded replacement bytes" }
                    },
                    "required": ["binary_id", "addr", "bytes"]
                }),
            ),
            McpToolDef::new(
                "patch.nop",
                "NOP out `count` bytes starting at `addr`.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "binary_id": { "type": "string",  "description": "Target binary identifier" },
                        "addr":      { "type": "integer", "description": "Virtual address to NOP" },
                        "count":     { "type": "integer", "description": "Number of bytes to NOP out" }
                    },
                    "required": ["binary_id", "addr", "count"]
                }),
            ),
            // â"€â"€ debug.* â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            McpToolDef::new(
                "debug.launch",
                "Launch a process under the RustRE debugger and suspend at entry point.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Absolute path to the executable to launch" },
                        "args": { "type": "array",  "description": "Command-line arguments", "items": { "type": "string" } }
                    },
                    "required": ["path"]
                }),
            ),
            McpToolDef::new(
                "debug.attach",
                "Attach the debugger to a running process by PID.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "pid": { "type": "integer", "description": "Process identifier to attach to" }
                    },
                    "required": ["pid"]
                }),
            ),
            McpToolDef::new(
                "debug.breakpoint.set",
                "Set a software breakpoint at a virtual address.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string",  "description": "Debug session identifier" },
                        "addr":       { "type": "integer", "description": "Virtual address for the breakpoint" }
                    },
                    "required": ["session_id", "addr"]
                }),
            ),
            McpToolDef::new(
                "debug.continue",
                "Continue execution of a paused debug session until the next breakpoint.",
                McpToolDef::simple_schema(&[("session_id", "string", "Debug session identifier")]),
            ),
            McpToolDef::new(
                "debug.read_memory",
                "Read `length` bytes from the debuggee's memory at `addr`.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string",  "description": "Debug session identifier" },
                        "addr":       { "type": "integer", "description": "Virtual address to read from" },
                        "length":     { "type": "integer", "description": "Number of bytes to read" }
                    },
                    "required": ["session_id", "addr", "length"]
                }),
            ),
            // â"€â"€ script.* â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
            McpToolDef::new(
                "script.run",
                "Execute a RustRE script (Lua, Python, or Rhai) by path.",
                McpToolDef::simple_schema(&[
                    ("path", "string", "Absolute path to the script file"),
                    (
                        "language",
                        "string",
                        "Script language: \"lua\", \"python\", or \"rhai\"",
                    ),
                ]),
            ),
            McpToolDef::new(
                "script.eval",
                "Evaluate an inline script expression and return its result.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "code":     { "type": "string", "description": "Source code to evaluate" },
                        "language": { "type": "string", "description": "Script language: \"lua\", \"python\", or \"rhai\"" }
                    },
                    "required": ["code", "language"]
                }),
            ),
        ]
    }

    /// Return the RustRE MCP resource catalogue (spec §30.3).
    ///
    /// Resources are readable via `resources/read` requests and surfaced to
    /// LLM toolchain consumers as structured context.
    #[must_use]
    pub fn list_resources() -> Vec<McpResourceDef> {
        vec![
            McpResourceDef::new(
                "rustre://project/current",
                "Current Project",
                "JSON metadata for the currently open RustRE project (name, path, binary list, analysis state).",
                "application/json",
            ),
            McpResourceDef::new(
                "rustre://binary/{binary_id}/info",
                "Binary Info",
                "JSON metadata for a specific loaded binary: format, architecture, entry point, sections, imports, exports.",
                "application/json",
            ),
            McpResourceDef::new(
                "rustre://binary/{binary_id}/strings",
                "Binary Strings",
                "All string literals found in the binary's data and read-only sections.",
                "application/json",
            ),
            McpResourceDef::new(
                "rustre://binary/{binary_id}/functions",
                "Function List",
                "JSON array of all detected functions (address, name, size, calling convention).",
                "application/json",
            ),
            McpResourceDef::new(
                "rustre://binary/{binary_id}/symbols",
                "Symbol Table",
                "Full symbol table for the binary including imports, exports, and debug symbols.",
                "application/json",
            ),
            McpResourceDef::new(
                "rustre://binary/{binary_id}/sections",
                "Section Map",
                "PE/ELF/Mach-O section list with virtual addresses, sizes, and permissions.",
                "application/json",
            ),
            McpResourceDef::new(
                "rustre://binary/{binary_id}/disasm/{addr}",
                "Disassembly at Address",
                "Disassembled instructions at or near a given virtual address.",
                "text/plain",
            ),
            McpResourceDef::new(
                "rustre://binary/{binary_id}/decompile/{addr}",
                "Decompiled Function",
                "Pseudo-C decompilation of the function at the specified address.",
                "text/plain",
            ),
            McpResourceDef::new(
                "rustre://binary/{binary_id}/xrefs/{addr}",
                "Cross-References",
                "All cross-references to and from a given address as a JSON object.",
                "application/json",
            ),
            McpResourceDef::new(
                "rustre://types/library",
                "Type Library",
                "All user-defined and auto-inferred types (structs, enums, typedefs) in the project.",
                "application/json",
            ),
            McpResourceDef::new(
                "rustre://analysis/log",
                "Analysis Log",
                "Timestamped log of analysis events, warnings, and errors for the current session.",
                "text/plain",
            ),
            McpResourceDef::new(
                "rustre://debug/{session_id}/state",
                "Debug Session State",
                "JSON snapshot of the current debugger state: registers, breakpoints, call stack.",
                "application/json",
            ),
            McpResourceDef::new(
                "rustre://debug/{session_id}/memory/{addr}",
                "Process Memory",
                "Raw bytes from the debuggee's virtual address space at the specified address.",
                "application/octet-stream",
            ),
            McpResourceDef::new(
                "rustre://plugins/list",
                "Plugin Registry",
                "JSON list of all loaded RustRE plugins with their names, versions, and capabilities.",
                "application/json",
            ),
            McpResourceDef::new(
                "rustre://config",
                "Configuration",
                "Current RustRE configuration as a JSON object.",
                "application/json",
            ),
        ]
    }

    /// Return the [`McpCapabilityFlags`] advertised by the RustRE MCP server.
    #[must_use]
    pub fn capability_flags() -> McpCapabilityFlags {
        McpCapabilityFlags::all()
    }

    /// Return the total number of tools in the catalogue.
    #[must_use]
    pub fn tool_count() -> usize {
        Self::list_tools().len()
    }

    /// Return the total number of resources in the catalogue.
    #[must_use]
    pub fn resource_count() -> usize {
        Self::list_resources().len()
    }

    /// Look up a tool definition by name.
    #[must_use]
    pub fn find_tool(name: &str) -> Option<McpToolDef> {
        Self::list_tools().into_iter().find(|t| t.name == name)
    }

    /// Look up a resource definition by name.
    #[must_use]
    pub fn find_resource(name: &str) -> Option<McpResourceDef> {
        Self::list_resources().into_iter().find(|r| r.name == name)
    }

    /// Return tool names grouped by namespace prefix (the part before the first `.`).
    #[must_use]
    pub fn tools_by_namespace() -> std::collections::HashMap<String, Vec<String>> {
        let mut map: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for tool in Self::list_tools() {
            let ns = tool.name.split('.').next().unwrap_or("misc").to_owned();
            map.entry(ns).or_default().push(tool.name);
        }
        map
    }
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Tests
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn coord() -> McpCoordinator {
        McpCoordinator::new()
    }

    fn ctx() -> RequestContext {
        RequestContext::now()
    }

    // â"€â"€ McpCapability â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_capability_fields() {
        let cap = McpCapability::new("decompile", "Decompile a function", "2.1.0");
        assert_eq!(cap.name, "decompile");
        assert_eq!(cap.description, "Decompile a function");
        assert_eq!(cap.version, "2.1.0");
    }

    #[test]
    fn test_capability_display() {
        let cap = McpCapability::new("disasm", "Disassemble bytes", "1.0.0");
        assert_eq!(cap.to_string(), "disasm@1.0.0");
    }

    #[test]
    fn test_capability_serde_roundtrip() {
        let cap = McpCapability::new("search", "Search strings", "0.9.0");
        let json = serde_json::to_string(&cap).unwrap();
        let back: McpCapability = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "search");
        assert_eq!(back.version, "0.9.0");
    }

    // â"€â"€ ToolCategory â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_tool_category_as_str() {
        assert_eq!(ToolCategory::Analysis.as_str(), "analysis");
        assert_eq!(ToolCategory::Debug.as_str(), "debug");
        assert_eq!(ToolCategory::Custom("x".into()).as_str(), "x");
    }

    #[test]
    fn test_tool_category_display() {
        assert_eq!(ToolCategory::Script.to_string(), "script");
    }

    // â"€â"€ ToolSchema â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_schema_any_accepts_everything() {
        let schema = ToolSchema::any();
        schema.validate(&serde_json::json!({})).unwrap();
    }

    #[test]
    fn test_schema_require_ok() {
        let schema = ToolSchema::any().require("addr", "number");
        schema
            .validate(&serde_json::json!({"addr": 0x1000}))
            .unwrap();
    }

    #[test]
    fn test_schema_require_missing() {
        let schema = ToolSchema::any().require("addr", "number");
        let err = schema.validate(&serde_json::json!({})).unwrap_err();
        assert!(err.to_string().contains("addr"));
    }

    #[test]
    fn test_schema_wrong_type() {
        let schema = ToolSchema::any().require("addr", "number");
        let err = schema
            .validate(&serde_json::json!({"addr": "notanumber"}))
            .unwrap_err();
        assert!(err.to_string().contains("addr"));
    }

    #[test]
    fn test_schema_not_object() {
        let schema = ToolSchema::any();
        let err = schema.validate(&serde_json::json!(42)).unwrap_err();
        assert!(matches!(err, McpError::SchemaValidation(_)));
    }

    #[test]
    fn test_schema_optional_present_correct_type() {
        let schema = ToolSchema::any().optional("count", "number");
        schema.validate(&serde_json::json!({"count": 5})).unwrap();
    }

    #[test]
    fn test_schema_optional_absent_ok() {
        let schema = ToolSchema::any().optional("count", "number");
        schema.validate(&serde_json::json!({})).unwrap();
    }

    // â"€â"€ RequestContext â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_context_now() {
        let ctx = RequestContext::now();
        assert!(ctx.received_at_ms > 0);
        assert!(ctx.age_ms() < 1000);
    }

    #[test]
    fn test_context_builder() {
        let ctx = RequestContext::now()
            .with_caller("agent-1")
            .with_trace_id("trace-abc")
            .with_meta("env", "test");
        assert_eq!(ctx.caller.as_deref(), Some("agent-1"));
        assert_eq!(ctx.trace_id.as_deref(), Some("trace-abc"));
        assert_eq!(ctx.metadata.get("env").map(String::as_str), Some("test"));
    }

    // â"€â"€ McpRequest / McpResponse â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_request_new() {
        let req = McpRequest::new("req-1", "echo");
        assert_eq!(req.id, "req-1");
        assert_eq!(req.method, "echo");
        assert!(req.params.is_object());
    }

    #[test]
    fn test_request_serde_roundtrip() {
        let req = McpRequest::with_params("id1", "tool", serde_json::json!({"x": 1}));
        let json = serde_json::to_string(&req).unwrap();
        let back: McpRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "id1");
        assert_eq!(back.params["x"], 1);
    }

    #[test]
    fn test_response_ok() {
        let r = McpResponse::ok("r1", serde_json::json!("success"), 10);
        assert!(r.is_ok());
        assert_eq!(r.elapsed_ms, 10);
    }

    #[test]
    fn test_response_err() {
        let rpc = RpcError {
            code: -1,
            message: "oops".into(),
        };
        let r = McpResponse::err("r2", rpc, 5);
        assert!(!r.is_ok());
    }

    // â"€â"€ McpError â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_mcp_error_rpc_codes() {
        assert_eq!(McpError::ToolNotFound("x".into()).rpc_code(), -32601);
        assert_eq!(McpError::RateLimited("y".into()).rpc_code(), -32000);
        assert_eq!(
            McpError::BatchTooLarge {
                count: 200,
                limit: 100
            }
            .rpc_code(),
            -32004
        );
    }

    #[test]
    fn test_mcp_error_is_transient() {
        assert!(McpError::RateLimited("t".into()).is_transient());
        assert!(McpError::Timeout("t".into()).is_transient());
        assert!(!McpError::ToolNotFound("t".into()).is_transient());
    }

    #[test]
    fn test_mcp_error_is_client_error() {
        assert!(McpError::InvalidRequest("bad".into()).is_client_error());
        assert!(!McpError::Internal("internal".into()).is_client_error());
    }

    #[test]
    fn test_mcp_error_execution_constructor() {
        let e = McpError::execution("my_tool", "something broke");
        assert!(e.to_string().contains("my_tool"));
        assert!(e.to_string().contains("something broke"));
    }

    // â"€â"€ RateLimiter â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_rate_limiter_allows_up_to_limit() {
        let mut rl = RateLimiter::new(3, Duration::from_secs(60));
        assert!(rl.allow());
        assert!(rl.allow());
        assert!(rl.allow());
        assert!(!rl.allow()); // 4th call rejected
    }

    #[test]
    fn test_rate_limiter_current_count() {
        let mut rl = RateLimiter::new(5, Duration::from_secs(60));
        rl.allow();
        rl.allow();
        assert_eq!(rl.current_count(), 2);
    }

    // â"€â"€ ToolMetrics â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_tool_metrics_record() {
        let mut m = ToolMetrics::default();
        m.record(Duration::from_millis(10), true, None);
        m.record(Duration::from_millis(20), false, Some("err".into()));
        assert_eq!(m.success_count, 1);
        assert_eq!(m.error_count, 1);
        assert_eq!(m.total_calls(), 2);
        assert_eq!(m.avg_us(), 15_000);
        assert!((m.error_rate() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn test_tool_metrics_zero_calls() {
        let m = ToolMetrics::default();
        assert_eq!(m.total_calls(), 0);
        assert_eq!(m.avg_us(), 0);
        assert_eq!(m.error_rate(), 0.0);
    }

    // â"€â"€ EchoTool â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[tokio::test]
    async fn test_echo_tool_echoes() {
        let tool = EchoTool;
        let params = serde_json::json!({"message": "hello"});
        let result = tool.execute(params.clone(), &ctx()).await.unwrap();
        assert_eq!(result, params);
    }

    #[test]
    fn test_echo_tool_metadata() {
        let tool = EchoTool;
        assert_eq!(tool.name(), "echo");
        assert!(!tool.description().is_empty());
        assert_eq!(tool.capabilities().len(), 1);
    }

    // â"€â"€ FailingTool â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[tokio::test]
    async fn test_failing_tool_returns_error() {
        let tool = FailingTool;
        let err = tool
            .execute(serde_json::json!({}), &ctx())
            .await
            .unwrap_err();
        assert!(matches!(err, McpError::Execution { .. }));
    }

    // â"€â"€ CounterTool â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[tokio::test]
    async fn test_counter_tool_increments() {
        let tool = Arc::new(CounterTool::new());
        tool.execute(serde_json::json!({}), &ctx()).await.unwrap();
        tool.execute(serde_json::json!({}), &ctx()).await.unwrap();
        assert_eq!(tool.value(), 2);
    }

    // â"€â"€ McpCoordinator â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_coordinator_new_empty() {
        let c = coord();
        assert_eq!(c.tool_count(), 0);
        assert!(c.tool_names().is_empty());
    }

    #[test]
    fn test_coordinator_register_and_find() {
        let c = coord();
        c.register_tool(Arc::new(EchoTool));
        assert!(c.has_tool("echo"));
        assert!(!c.has_tool("missing"));
    }

    #[test]
    fn test_coordinator_tool_names_sorted() {
        let c = coord();
        c.register_tool(Arc::new(EchoTool));
        c.register_tool(Arc::new(FailingTool));
        let names = c.tool_names();
        assert_eq!(names, vec!["echo", "fail"]);
    }

    #[test]
    fn test_coordinator_remove_tool() {
        let c = coord();
        c.register_tool(Arc::new(EchoTool));
        assert!(c.remove_tool("echo"));
        assert!(!c.remove_tool("echo"));
    }

    #[tokio::test]
    async fn test_coordinator_dispatch_echo() {
        let c = McpCoordinator::default();
        c.register_tool(Arc::new(EchoTool));
        let req = McpRequest::with_params("1", "echo", serde_json::json!({"x": 1}));
        let resp = c.dispatch(req).await;
        assert!(resp.is_ok());
        assert_eq!(resp.result.unwrap()["x"], 1);
    }

    #[tokio::test]
    async fn test_coordinator_dispatch_tool_not_found() {
        let c = coord();
        let req = McpRequest::new("2", "unknown_tool");
        let resp = c.dispatch(req).await;
        assert!(!resp.is_ok());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[tokio::test]
    async fn test_coordinator_dispatch_failing_tool() {
        let c = coord();
        c.register_tool(Arc::new(FailingTool));
        let req = McpRequest::new("3", "fail");
        let resp = c.dispatch(req).await;
        assert!(!resp.is_ok());
        assert_eq!(resp.error.unwrap().code, -32603);
    }

    #[tokio::test]
    async fn test_coordinator_metrics_updated() {
        let c = coord();
        c.register_tool(Arc::new(EchoTool));
        let req = McpRequest::new("m1", "echo");
        c.dispatch(req).await;
        let m = c.metrics("echo").unwrap();
        assert_eq!(m.success_count, 1);
        assert_eq!(m.error_count, 0);
    }

    #[tokio::test]
    async fn test_coordinator_metrics_error_counted() {
        let c = coord();
        c.register_tool(Arc::new(FailingTool));
        let req = McpRequest::new("m2", "fail");
        c.dispatch(req).await;
        let m = c.metrics("fail").unwrap();
        assert_eq!(m.error_count, 1);
    }

    #[tokio::test]
    async fn test_coordinator_audit_log_grows() {
        let c = coord();
        c.register_tool(Arc::new(EchoTool));
        c.dispatch(McpRequest::new("a1", "echo")).await;
        c.dispatch(McpRequest::new("a2", "echo")).await;
        assert_eq!(c.audit_log_len(), 2);
    }

    #[test]
    fn test_coordinator_clear_audit_log() {
        let c = coord();
        // Force an audit entry via internal helper.
        c.push_audit(AuditEntry {
            request_id: "x".into(),
            tool: "echo".into(),
            caller: None,
            success: true,
            timestamp_ms: 0,
            elapsed_ms: 0,
        });
        assert_eq!(c.audit_log_len(), 1);
        c.clear_audit_log();
        assert_eq!(c.audit_log_len(), 0);
    }

    #[test]
    fn test_coordinator_disable_category() {
        let c = coord();
        c.register_tool(Arc::new(EchoTool)); // category = Utility
        c.disable_category(ToolCategory::Utility);
        assert!(!c.is_category_enabled(&ToolCategory::Utility));
    }

    #[tokio::test]
    async fn test_coordinator_category_disabled_blocks_dispatch() {
        let c = coord();
        c.register_tool(Arc::new(EchoTool));
        c.disable_category(ToolCategory::Utility);
        let resp = c.dispatch(McpRequest::new("cat1", "echo")).await;
        assert!(!resp.is_ok());
        assert_eq!(resp.error.unwrap().code, -32003);
    }

    #[test]
    fn test_coordinator_enable_category() {
        let c = coord();
        c.disable_category(ToolCategory::Debug);
        c.enable_category(&ToolCategory::Debug);
        assert!(c.is_category_enabled(&ToolCategory::Debug));
    }

    #[test]
    fn test_coordinator_middleware_count() {
        let c = coord();
        c.add_middleware(Arc::new(LoggingMiddleware));
        assert_eq!(c.middleware_count(), 1);
        c.clear_middleware();
        assert_eq!(c.middleware_count(), 0);
    }

    #[tokio::test]
    async fn test_deny_list_middleware_blocks() {
        let c = coord();
        c.register_tool(Arc::new(EchoTool));
        c.add_middleware(Arc::new(DenyListMiddleware::new(vec!["evil-agent".into()])));
        let ctx = RequestContext::now().with_caller("evil-agent");
        let req = McpRequest::new("d1", "echo");
        let resp = c.dispatch_with_context(req, ctx).await;
        assert!(!resp.is_ok());
        assert_eq!(resp.error.unwrap().code, -32001);
    }

    #[tokio::test]
    async fn test_deny_list_middleware_allows_others() {
        let c = coord();
        c.register_tool(Arc::new(EchoTool));
        c.add_middleware(Arc::new(DenyListMiddleware::new(vec!["evil-agent".into()])));
        let ctx = RequestContext::now().with_caller("good-agent");
        let req = McpRequest::new("d2", "echo");
        let resp = c.dispatch_with_context(req, ctx).await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn test_batch_dispatch_ok() {
        let c = coord();
        c.register_tool(Arc::new(EchoTool));
        let batch = BatchRequest::new(vec![
            McpRequest::new("b1", "echo"),
            McpRequest::new("b2", "echo"),
        ]);
        let result = c.dispatch_batch(batch, ctx()).await.unwrap();
        assert_eq!(result.success_count(), 2);
        assert_eq!(result.error_count(), 0);
    }

    #[tokio::test]
    async fn test_batch_dispatch_too_large() {
        let c = McpCoordinator::with_limits(100, 2);
        let reqs = (0..3)
            .map(|i| McpRequest::new(i.to_string(), "echo"))
            .collect();
        let batch = BatchRequest::new(reqs);
        let err = c.dispatch_batch(batch, ctx()).await.unwrap_err();
        assert!(matches!(err, McpError::BatchTooLarge { .. }));
    }

    #[test]
    fn test_batch_request_len() {
        let b = BatchRequest::new(vec![McpRequest::new("1", "a"), McpRequest::new("2", "b")]);
        assert_eq!(b.len(), 2);
        assert!(!b.is_empty());
    }

    #[test]
    fn test_coordinator_tool_descriptors() {
        let c = coord();
        c.register_tool(Arc::new(EchoTool));
        c.register_tool(Arc::new(FailingTool));
        let descs = c.tool_descriptors();
        assert_eq!(descs.len(), 2);
        assert_eq!(descs[0].name, "echo");
    }

    #[test]
    fn test_coordinator_all_capabilities() {
        let c = coord();
        c.register_tool(Arc::new(EchoTool));
        let caps = c.all_capabilities();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].name, "echo");
    }

    #[test]
    fn test_coordinator_tools_by_category() {
        let c = coord();
        c.register_tool(Arc::new(EchoTool));
        c.register_tool(Arc::new(HealthTool));
        let utility = c.tools_by_category(&ToolCategory::Utility);
        assert!(utility.contains(&"echo".to_string()));
    }

    #[test]
    fn test_coordinator_debug_format() {
        let c = coord();
        c.register_tool(Arc::new(EchoTool));
        let s = format!("{c:?}");
        assert!(s.contains("McpCoordinator"));
    }

    #[test]
    fn test_coordinator_all_metrics_empty() {
        let c = coord();
        c.register_tool(Arc::new(EchoTool));
        let m = c.all_metrics();
        assert!(m.contains_key("echo"));
    }

    // â"€â"€ §30.2 McpCapabilityFlags â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_capability_flags_all() {
        let f = McpCapabilityFlags::all();
        assert!(f.tools && f.resources && f.prompts && f.logging);
        assert!(f.any());
    }

    #[test]
    fn test_capability_flags_tools_only() {
        let f = McpCapabilityFlags::tools_only();
        assert!(f.tools);
        assert!(!f.resources && !f.prompts && !f.logging);
        assert!(f.any());
    }

    #[test]
    fn test_capability_flags_default_none() {
        let f = McpCapabilityFlags::default();
        assert!(!f.any());
    }

    #[test]
    fn test_capability_flags_to_json() {
        let f = McpCapabilityFlags::all();
        let j = f.to_json();
        assert_eq!(j["tools"]["enabled"], true);
        assert_eq!(j["resources"]["enabled"], true);
    }

    #[test]
    fn test_capability_flags_display() {
        let f = McpCapabilityFlags::all();
        let s = f.to_string();
        assert!(s.contains("tools"));
        assert!(s.contains("resources"));
        assert!(s.contains("prompts"));
        assert!(s.contains("logging"));
    }

    #[test]
    fn test_capability_flags_serde_roundtrip() {
        let f = McpCapabilityFlags::all();
        let json = serde_json::to_string(&f).unwrap();
        let back: McpCapabilityFlags = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    // â"€â"€ §30.2 McpToolDef â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_mcp_tool_def_new() {
        let def = McpToolDef::new(
            "project.open",
            "Open a project",
            serde_json::json!({ "type": "object" }),
        );
        assert_eq!(def.name, "project.open");
        assert!(!def.description.is_empty());
    }

    #[test]
    fn test_mcp_tool_def_simple_schema() {
        let schema = McpToolDef::simple_schema(&[
            ("path", "string", "File path"),
            ("count", "integer", "Item count"),
        ]);
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["path"]["type"] == "string");
        assert!(schema["required"].as_array().unwrap().len() == 2);
    }

    #[test]
    fn test_mcp_tool_def_display() {
        let def = McpToolDef::new("echo", "Echo", serde_json::json!({}));
        assert_eq!(def.to_string(), "McpToolDef(echo)");
    }

    #[test]
    fn test_mcp_tool_def_serde_roundtrip() {
        let def = McpToolDef::new("my.tool", "My tool", serde_json::json!({"x": 1}));
        let json = serde_json::to_string(&def).unwrap();
        let back: McpToolDef = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "my.tool");
        assert_eq!(back.input_schema["x"], 1);
    }

    // â"€â"€ §30.2 McpResourceDef â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_mcp_resource_def_new() {
        let r = McpResourceDef::new(
            "rustre://project/current",
            "Current Project",
            "Project metadata",
            "application/json",
        );
        assert_eq!(r.uri, "rustre://project/current");
        assert!(r.is_text());
    }

    #[test]
    fn test_mcp_resource_def_binary_not_text() {
        let r = McpResourceDef::new(
            "rustre://memory",
            "Memory",
            "Raw memory",
            "application/octet-stream",
        );
        assert!(!r.is_text());
    }

    #[test]
    fn test_mcp_resource_def_display() {
        let r = McpResourceDef::new("rustre://x", "X", "desc", "text/plain");
        assert!(r.to_string().contains("rustre://x"));
    }

    #[test]
    fn test_mcp_resource_def_serde_roundtrip() {
        let r = McpResourceDef::new("rustre://x", "X", "desc", "application/json");
        let json = serde_json::to_string(&r).unwrap();
        let back: McpResourceDef = serde_json::from_str(&json).unwrap();
        assert_eq!(back.uri, "rustre://x");
        assert_eq!(back.mime_type, "application/json");
    }

    // â"€â"€ §30.3 RustreCapabilities â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    #[test]
    fn test_rustre_capabilities_tool_count_at_least_20() {
        assert!(
            RustreCapabilities::tool_count() >= 20,
            "Expected at least 20 tools, got {}",
            RustreCapabilities::tool_count()
        );
    }

    #[test]
    fn test_rustre_capabilities_resource_count() {
        assert!(RustreCapabilities::resource_count() > 0);
    }

    #[test]
    fn test_rustre_capabilities_tool_names_unique() {
        let tools = RustreCapabilities::list_tools();
        let mut names = tools.iter().map(|t| t.name.as_str()).collect::<Vec<_>>();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "Duplicate tool names detected");
    }

    #[test]
    fn test_rustre_capabilities_all_tools_have_descriptions() {
        for tool in RustreCapabilities::list_tools() {
            assert!(
                !tool.description.is_empty(),
                "Tool '{}' has no description",
                tool.name
            );
        }
    }

    #[test]
    fn test_rustre_capabilities_all_tools_have_object_schema() {
        for tool in RustreCapabilities::list_tools() {
            assert_eq!(
                tool.input_schema["type"], "object",
                "Tool '{}' input_schema.type must be 'object'",
                tool.name
            );
        }
    }

    #[test]
    fn test_rustre_capabilities_all_resources_have_uris() {
        for res in RustreCapabilities::list_resources() {
            assert!(!res.uri.is_empty(), "Resource '{}' has empty URI", res.name);
            assert!(
                res.uri.starts_with("rustre://"),
                "Resource '{}' URI doesn't start with rustre://",
                res.name
            );
        }
    }

    #[test]
    fn test_rustre_capabilities_find_tool_exists() {
        let t = RustreCapabilities::find_tool("project.open");
        assert!(t.is_some());
        assert_eq!(t.unwrap().name, "project.open");
    }

    #[test]
    fn test_rustre_capabilities_find_tool_missing() {
        assert!(RustreCapabilities::find_tool("nonexistent.tool").is_none());
    }

    #[test]
    fn test_rustre_capabilities_find_resource_exists() {
        let r = RustreCapabilities::find_resource("Current Project");
        assert!(r.is_some());
    }

    #[test]
    fn test_rustre_capabilities_specific_tools_present() {
        let required = &[
            "project.open",
            "binary.info",
            "disasm.at",
            "analyze.function",
            "decompile.function",
            "symbols.list",
            "symbols.rename",
            "xref.to",
            "xref.from",
            "search.bytes",
            "search.string",
            "patch.bytes",
            "debug.launch",
            "script.run",
        ];
        let tools = RustreCapabilities::list_tools();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        for req in required {
            assert!(names.contains(req), "Required tool '{}' is missing", req);
        }
    }

    #[test]
    fn test_rustre_capabilities_tools_by_namespace() {
        let ns = RustreCapabilities::tools_by_namespace();
        assert!(ns.contains_key("project"), "Missing 'project' namespace");
        assert!(ns.contains_key("binary"), "Missing 'binary' namespace");
        assert!(ns.contains_key("disasm"), "Missing 'disasm' namespace");
        assert!(ns.contains_key("analyze"), "Missing 'analyze' namespace");
    }

    #[test]
    fn test_rustre_capabilities_flags() {
        let f = RustreCapabilities::capability_flags();
        assert!(f.tools && f.resources);
    }

    #[test]
    fn test_rustre_capabilities_disasm_at_schema_fields() {
        let t = RustreCapabilities::find_tool("disasm.at").unwrap();
        let props = &t.input_schema["properties"];
        assert!(
            props.get("binary_id").is_some(),
            "disasm.at missing binary_id"
        );
        assert!(props.get("addr").is_some(), "disasm.at missing addr");
        // count is optional so may be absent from required but should be in properties
        let required = t.input_schema["required"].as_array().unwrap();
        let req_names: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
        assert!(req_names.contains(&"binary_id"));
        assert!(req_names.contains(&"addr"));
    }

    #[tokio::test]
    async fn test_validated_tool_ok() {
        let c = coord();
        c.register_tool(Arc::new(ValidatedTool::new("validated", "name")));
        let req = McpRequest::with_params("v1", "validated", serde_json::json!({"name": "test"}));
        let resp = c.dispatch(req).await;
        assert!(resp.is_ok());
    }

    #[tokio::test]
    async fn test_validated_tool_schema_fail() {
        let c = coord();
        c.register_tool(Arc::new(ValidatedTool::new("validated", "name")));
        let req = McpRequest::with_params("v2", "validated", serde_json::json!({}));
        let resp = c.dispatch(req).await;
        assert!(!resp.is_ok());
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn test_health_tool() {
        let c = coord();
        c.register_tool(Arc::new(HealthTool));
        let req = McpRequest::new("h1", "health");
        let resp = c.dispatch(req).await;
        assert!(resp.is_ok());
        assert_eq!(resp.result.unwrap()["status"], "ok");
    }
}

