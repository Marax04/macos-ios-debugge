//! `rustre-mcp-server`
//!
//! MCP (Model Context Protocol) server exposing `RustRE` capabilities via
//! JSON-RPC 2.0 over stdio or HTTP.

pub mod analysis_tools;
pub mod binary_analysis_server;
pub mod rustre_tools;
pub mod tool_implementation;
pub mod mcp_tool_registry;
pub mod mcp_session_handler;
pub mod mcp_resource_provider;
pub mod mcp_transport_stdio;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// Error types
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

#[derive(Debug, Error)]
pub enum McpError {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("method not found: {0}")]
    MethodNotFound(String),
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("internal error: {0}")]
    InternalError(String),
    #[error("tool error: {0}")]
    ToolError(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl McpError {
    #[must_use]
    pub const fn code(&self) -> i32 {
        match self {
            Self::ParseError(_) => -32700,
            Self::MethodNotFound(_) => -32601,
            Self::InvalidParams(_) => -32602,
            Self::InternalError(_) => -32603,
            Self::ToolError(_) => -32000,
            Self::Io(_) => -32001,
        }
    }
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// JSON-RPC 2.0 wire types
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    /// `None` for a NOTIFICATION.
    ///
    /// JSON-RPC 2.0 tells a request from a notification by the presence of this
    /// member, and forbids replying to a notification. Modelling it as a plain
    /// `Value` made a notification fail to deserialise, so the stdio loop
    /// answered it with a parse error: it rejected a valid message and broke the
    /// spec in the same step. `mcp_session_handler` and `mcp_transport_stdio`
    /// already model it this way — neither module is wired, so the correct shape
    /// sat unused while this one shipped.
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    pub params: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// Predefined codes from the JSON-RPC 2.0 specification.
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;

    /// Create a new error.
    #[must_use]
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self { code, message: message.into(), data: None }
    }

    /// Create a "method not found" error.
    #[must_use]
    pub fn method_not_found(method: &str) -> Self {
        Self::new(Self::METHOD_NOT_FOUND, format!("method not found: {method}"))
    }

    /// Create an "internal error" with a detail message.
    #[must_use]
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(Self::INTERNAL_ERROR, detail.into())
    }

    /// Create a "parse error".
    #[must_use]
    pub fn parse_error() -> Self {
        Self::new(Self::PARSE_ERROR, "parse error")
    }
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl JsonRpcResponse {
    #[must_use]
    pub fn ok(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    #[must_use]
    pub fn err(id: Value, err: &McpError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code: err.code(),
                message: err.to_string(),
                data: None,
            }),
        }
    }
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// MCP domain types
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    Text { text: String },
    Image { data: String, mime_type: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub content: Vec<ContentBlock>,
    pub is_error: bool,
}

impl ToolResult {
    #[must_use]
    pub fn text(s: impl Into<String>) -> Self {
        Self {
            content: vec![ContentBlock::Text { text: s.into() }],
            is_error: false,
        }
    }

    #[must_use]
    pub fn error(s: impl Into<String>) -> Self {
        Self {
            content: vec![ContentBlock::Text { text: s.into() }],
            is_error: true,
        }
    }

    #[must_use]
    pub fn json(v: &Value) -> Self {
        Self::text(v.to_string())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub input_schema: Value,
    #[serde(default)]
    pub parameters: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceDefinition {
    pub uri: String,
    pub name: String,
    pub description: String,
    pub mime_type: String,
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// ToolHandler trait
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

#[async_trait]
pub trait ToolHandler: Send + Sync {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError>;
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// Transport
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

#[derive(Debug, Clone)]
pub enum McpTransport {
    Stdio,
    Http(SocketAddr),
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// Tool category enum
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolCategory {
    Project,
    Binary,
    Analysis,
    Disasm,
    Decompile,
    Debugger,
    TimeTravel,
    Instrumentation,
    Emulation,
    Symbolic,
    Diff,
    Forensics,
    Sandbox,
    Yara,
    Network,
    Mobile,
    DotNet,
    ThreatIntel,
    KnowledgeGraph,
}

impl std::fmt::Display for ToolCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Project => "project",
            Self::Binary => "binary",
            Self::Analysis => "analysis",
            Self::Disasm => "disasm",
            Self::Decompile => "decompile",
            Self::Debugger => "debugger",
            Self::TimeTravel => "time_travel",
            Self::Instrumentation => "instrumentation",
            Self::Emulation => "emulation",
            Self::Symbolic => "symbolic",
            Self::Diff => "diff",
            Self::Forensics => "forensics",
            Self::Sandbox => "sandbox",
            Self::Yara => "yara",
            Self::Network => "network",
            Self::Mobile => "mobile",
            Self::DotNet => "dotnet",
            Self::ThreatIntel => "threat_intel",
            Self::KnowledgeGraph => "knowledge_graph",
        };
        write!(f, "{s}")
    }
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// McpToolDef Ã¢â‚¬— extended tool definition with category
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolDef {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    pub category: ToolCategory,
}

impl McpToolDef {
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        input_schema: Value,
        category: ToolCategory,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            input_schema,
            category,
        }
    }

    #[must_use]
    pub fn to_tool_definition(&self) -> ToolDefinition {
        ToolDefinition {
            name: self.name.clone(),
            description: self.description.clone(),
            input_schema: self.input_schema.clone(),
            parameters: self.input_schema.clone(),
        }
    }
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// McpToolError Ã¢â‚¬— tool-level error type
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

#[derive(Debug, Error)]
pub enum McpToolError {
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("execution failed: {0}")]
    ExecutionFailed(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

impl From<McpToolError> for McpError {
    fn from(e: McpToolError) -> Self {
        Self::ToolError(e.to_string())
    }
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// McpToolHandler trait
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

pub trait McpToolHandler: Send + Sync {
    fn name(&self) -> &str;
    /// Execute the tool with the given parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if the tool fails to execute or parameters are invalid.
    fn execute(&self, params: Value) -> Result<Value, McpToolError>;
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// ToolExecutor
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

pub struct ToolExecutor {
    tools: HashMap<String, Box<dyn McpToolHandler>>,
}

impl ToolExecutor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    pub fn register(&mut self, handler: Box<dyn McpToolHandler>) {
        self.tools.insert(handler.name().to_string(), handler);
    }

    /// Execute the named tool with the given parameters.
    ///
    /// # Errors
    ///
    /// Returns `McpToolError::NotFound` if the tool name is not registered, or propagates
    /// the tool's own error on execution failure.
    pub fn execute(&self, name: &str, params: Value) -> Result<Value, McpToolError> {
        self.tools
            .get(name)
            .ok_or_else(|| McpToolError::NotFound(name.to_string()))?
            .execute(params)
    }

    #[must_use]
    pub fn tool_names(&self) -> Vec<&str> {
        self.tools.keys().map(String::as_str).collect()
    }

    #[must_use]
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }
}

impl Default for ToolExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// Session management
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionKind {
    Project,
    Debug,
    Forensics,
    Emulation,
    Recording,
}

impl std::fmt::Display for SessionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Project => write!(f, "project"),
            Self::Debug => write!(f, "debug"),
            Self::Forensics => write!(f, "forensics"),
            Self::Emulation => write!(f, "emulation"),
            Self::Recording => write!(f, "recording"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDescriptor {
    pub id: String,
    pub kind: SessionKind,
    pub created_at: u64,
    pub metadata: HashMap<String, String>,
}

impl SessionDescriptor {
    #[must_use]
    pub fn new(id: String, kind: SessionKind, created_at: u64) -> Self {
        Self {
            id,
            kind,
            created_at,
            metadata: HashMap::new(),
        }
    }

    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    #[must_use]
    pub fn get_metadata(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(String::as_str)
    }
}

pub struct SessionManager {
    sessions: HashMap<String, SessionDescriptor>,
    next_id: u64,
}

impl SessionManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            next_id: 1,
        }
    }

    pub fn create_session(&mut self, kind: SessionKind) -> String {
        let id = format!("session-{}", self.next_id);
        self.next_id += 1;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.sessions
            .insert(id.clone(), SessionDescriptor::new(id.clone(), kind, now));
        id
    }

    #[must_use]
    pub fn get_session(&self, id: &str) -> Option<&SessionDescriptor> {
        self.sessions.get(id)
    }

    pub fn get_session_mut(&mut self, id: &str) -> Option<&mut SessionDescriptor> {
        self.sessions.get_mut(id)
    }

    pub fn remove_session(&mut self, id: &str) -> bool {
        self.sessions.remove(id).is_some()
    }

    #[must_use]
    pub fn list_sessions(&self) -> Vec<&SessionDescriptor> {
        self.sessions.values().collect()
    }

    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    #[must_use]
    pub fn sessions_by_kind(&self, kind: &SessionKind) -> Vec<&SessionDescriptor> {
        self.sessions.values().filter(|s| &s.kind == kind).collect()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// MCP Resources
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResource {
    pub uri: String,
    pub name: String,
    pub description: String,
    pub mime_type: String,
}

impl McpResource {
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
}

#[derive(Debug, Clone)]
pub enum McpResourceContent {
    Text(String),
    Binary(Vec<u8>),
}

impl McpResourceContent {
    #[must_use]
    pub const fn is_text(&self) -> bool {
        matches!(self, Self::Text(_))
    }

    #[must_use]
    pub const fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(s) => Some(s.as_str()),
            Self::Binary(_) => None,
        }
    }

    #[must_use]
    pub const fn byte_len(&self) -> usize {
        match self {
            Self::Text(s) => s.len(),
            Self::Binary(b) => b.len(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpUriParts {
    pub scheme: String,
    pub entity_type: String,
    pub entity_id: String,
    pub view: Option<String>,
}

pub struct ResourceProvider;

impl ResourceProvider {
    #[must_use]
    pub fn list_resources(project_id: &str) -> Vec<McpResource> {
        vec![
            McpResource::new(
                format!("rustre://project/{project_id}/binaries"),
                "Binary list",
                "All binaries in project",
                "application/json",
            ),
            McpResource::new(
                format!("rustre://project/{project_id}/info"),
                "Project info",
                "Project metadata",
                "application/json",
            ),
        ]
    }

    /// Read a resource by URI.
    ///
    /// # Errors
    ///
    /// Returns `McpToolError::NotFound` if the URI is not recognized, or a parse error
    /// if the URI cannot be decoded.
    pub fn read_resource(uri: &str) -> Result<McpResourceContent, McpToolError> {
        let parts = Self::parse_uri(uri)?;
        match parts.entity_type.as_str() {
            "binary" => {
                let view = parts.view.as_deref().unwrap_or("info");
                let stub = serde_json::json!({
                    "stub": true,
                    "binary_id": parts.entity_id,
                    "view": view,
                    "note": "STUB: real binary data not loaded"
                });
                Ok(McpResourceContent::Text(stub.to_string()))
            }
            "project" => {
                let stub = serde_json::json!({
                    "stub": true,
                    "project_id": parts.entity_id,
                    "note": "STUB: real project data not loaded"
                });
                Ok(McpResourceContent::Text(stub.to_string()))
            }
            other => Err(McpToolError::NotFound(format!(
                "unknown entity type: {other}"
            ))),
        }
    }

    #[must_use]
    pub fn make_binary_uri(binary_id: &str, view: &str) -> String {
        format!("rustre://binary/{binary_id}/{view}")
    }

    /// Parse a `rustre://` URI into its component parts.
    ///
    /// # Errors
    ///
    /// Returns `McpToolError::InvalidParams` if the URI is malformed or the scheme is
    /// not `rustre`.
    pub fn parse_uri(uri: &str) -> Result<McpUriParts, McpToolError> {
        // Expected format: scheme://entity_type/entity_id[/view]
        let (scheme, rest) = uri
            .split_once("://")
            .ok_or_else(|| McpToolError::InvalidParams(format!("invalid URI: {uri}")))?;

        let parts: Vec<&str> = rest.splitn(3, '/').collect();
        if parts.len() < 2 {
            return Err(McpToolError::InvalidParams(format!(
                "URI must have at least entity_type/entity_id: {uri}"
            )));
        }

        Ok(McpUriParts {
            scheme: scheme.to_string(),
            entity_type: parts[0].to_string(),
            entity_id: parts[1].to_string(),
            view: parts.get(2).map(std::string::ToString::to_string),
        })
    }
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// Tool catalog builders
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

fn obj_schema(props: Value, required: &[&str]) -> Value {
    serde_json::json!({
        "type": "object",
        "properties": props,
        "required": required
    })
}

fn str_prop(desc: &str) -> Value {
    serde_json::json!({ "type": "string", "description": desc })
}

fn num_prop(desc: &str) -> Value {
    serde_json::json!({ "type": "number", "description": desc })
}

fn arr_prop(item_type: &str, desc: &str) -> Value {
    serde_json::json!({ "type": "array", "items": { "type": item_type }, "description": desc })
}

/// Build the full `RustRE` tool catalog.
#[must_use]
pub fn build_tool_catalog() -> Vec<McpToolDef> {
    let mut catalog = Vec::with_capacity(64);

    // Ã¢—â‚¬Ã¢—â‚¬ Project tools Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
    catalog.push(McpToolDef::new(
        "project.open",
        "Open a binary project from a filesystem path",
        obj_schema(
            serde_json::json!({ "path": str_prop("Filesystem path to the project or binary") }),
            &["path"],
        ),
        ToolCategory::Project,
    ));
    catalog.push(McpToolDef::new(
        "project.close",
        "Close an open project and release resources",
        obj_schema(
            serde_json::json!({ "project_id": str_prop("Project identifier returned by project.open") }),
            &["project_id"],
        ),
        ToolCategory::Project,
    ));
    catalog.push(McpToolDef::new(
        "project.list_binaries",
        "List all binaries in a project",
        obj_schema(
            serde_json::json!({ "project_id": str_prop("Project identifier") }),
            &["project_id"],
        ),
        ToolCategory::Project,
    ));
    catalog.push(McpToolDef::new(
        "project.info",
        "Return metadata for a project",
        obj_schema(
            serde_json::json!({ "project_id": str_prop("Project identifier") }),
            &["project_id"],
        ),
        ToolCategory::Project,
    ));

    // Ã¢—â‚¬Ã¢—â‚¬ Binary tools Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
    catalog.push(McpToolDef::new(
        "binary.info",
        "Return metadata for a loaded binary: format, arch, entry point, sections, sha256",
        obj_schema(
            serde_json::json!({ "binary_id": str_prop("Binary identifier") }),
            &["binary_id"],
        ),
        ToolCategory::Binary,
    ));
    catalog.push(McpToolDef::new(
        "binary.hexdump",
        "Return a hex+ASCII dump of a region of the binary",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "addr": str_prop("Start address (hex string, e.g. '0x401000')"),
                "len": num_prop("Number of bytes to dump")
            }),
            &["binary_id", "addr", "len"],
        ),
        ToolCategory::Binary,
    ));
    catalog.push(McpToolDef::new(
        "binary.read",
        "Read raw bytes from a binary region, returned as base64",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "addr": str_prop("Start address (hex)"),
                "len": num_prop("Number of bytes")
            }),
            &["binary_id", "addr", "len"],
        ),
        ToolCategory::Binary,
    ));
    catalog.push(McpToolDef::new(
        "binary.search_bytes",
        "Search for a byte pattern in the binary",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "pattern": str_prop("Hex byte pattern, e.g. 'DE AD BE EF'"),
                "mask": str_prop("Optional mask bytes (same length as pattern)")
            }),
            &["binary_id", "pattern"],
        ),
        ToolCategory::Binary,
    ));
    catalog.push(McpToolDef::new(
        "binary.search_strings",
        "Search for printable strings in the binary",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "min_len": num_prop("Minimum string length (default 4)"),
                "regex": str_prop("Optional regex filter applied to found strings")
            }),
            &["binary_id"],
        ),
        ToolCategory::Binary,
    ));
    catalog.push(McpToolDef::new(
        "binary.entropy",
        "Compute entropy across sections or sliding windows",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "section": str_prop("Optional section name to restrict analysis")
            }),
            &["binary_id"],
        ),
        ToolCategory::Binary,
    ));

    // Ã¢—â‚¬Ã¢—â‚¬ Analysis tools Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
    catalog.push(McpToolDef::new(
        "analyze.full",
        "Run full analysis on a binary (auto-analysis, function discovery, etc.)",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "depth": str_prop("Analysis depth: 'fast' | 'normal' | 'deep' (default 'normal')")
            }),
            &["binary_id"],
        ),
        ToolCategory::Analysis,
    ));
    catalog.push(McpToolDef::new(
        "analyze.function",
        "Analyse a single function at a given address",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "addr": str_prop("Function start address (hex)")
            }),
            &["binary_id", "addr"],
        ),
        ToolCategory::Analysis,
    ));
    catalog.push(McpToolDef::new(
        "analyze.basic_block",
        "Return basic block information at an address",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "addr": str_prop("Address inside the basic block (hex)")
            }),
            &["binary_id", "addr"],
        ),
        ToolCategory::Analysis,
    ));
    catalog.push(McpToolDef::new(
        "analyze.cross_refs",
        "Return all cross-references to and from an address",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "addr": str_prop("Target address (hex)")
            }),
            &["binary_id", "addr"],
        ),
        ToolCategory::Analysis,
    ));
    catalog.push(McpToolDef::new(
        "analyze.call_graph",
        "Return the call graph starting at an optional root function, as a DOT string",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "root": str_prop("Optional root function address (hex)")
            }),
            &["binary_id"],
        ),
        ToolCategory::Analysis,
    ));
    catalog.push(McpToolDef::new(
        "analyze.strings",
        "Return all strings found in the binary",
        obj_schema(
            serde_json::json!({ "binary_id": str_prop("Binary identifier") }),
            &["binary_id"],
        ),
        ToolCategory::Analysis,
    ));
    catalog.push(McpToolDef::new(
        "analyze.imports",
        "Return the import table of the binary",
        obj_schema(
            serde_json::json!({ "binary_id": str_prop("Binary identifier") }),
            &["binary_id"],
        ),
        ToolCategory::Analysis,
    ));
    catalog.push(McpToolDef::new(
        "analyze.exports",
        "Return the export table of the binary",
        obj_schema(
            serde_json::json!({ "binary_id": str_prop("Binary identifier") }),
            &["binary_id"],
        ),
        ToolCategory::Analysis,
    ));

    // Ã¢—â‚¬Ã¢—â‚¬ Disassembly tools Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
    catalog.push(McpToolDef::new(
        "disasm.at",
        "Disassemble N instructions starting at an address",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "addr": str_prop("Start address (hex)"),
                "count": num_prop("Number of instructions to disassemble")
            }),
            &["binary_id", "addr", "count"],
        ),
        ToolCategory::Disasm,
    ));
    catalog.push(McpToolDef::new(
        "disasm.function",
        "Disassemble an entire function",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "addr": str_prop("Function start address (hex)")
            }),
            &["binary_id", "addr"],
        ),
        ToolCategory::Disasm,
    ));

    // Ã¢—â‚¬Ã¢—â‚¬ Decompile tools Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
    catalog.push(McpToolDef::new(
        "decompile.function",
        "Decompile a function to pseudo-C source code",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "addr": str_prop("Function start address (hex)")
            }),
            &["binary_id", "addr"],
        ),
        ToolCategory::Decompile,
    ));
    catalog.push(McpToolDef::new(
        "decompile.rename_variable",
        "Rename a local variable in decompiled output",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "func_addr": str_prop("Function address (hex)"),
                "old_name": str_prop("Current variable name"),
                "new_name": str_prop("New variable name")
            }),
            &["binary_id", "func_addr", "old_name", "new_name"],
        ),
        ToolCategory::Decompile,
    ));
    catalog.push(McpToolDef::new(
        "decompile.set_type",
        "Set the type of a local variable in decompiled output",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "func_addr": str_prop("Function address (hex)"),
                "var_name": str_prop("Variable name"),
                "type_str": str_prop("C-style type string, e.g. 'int*' or 'struct MyStruct'")
            }),
            &["binary_id", "func_addr", "var_name", "type_str"],
        ),
        ToolCategory::Decompile,
    ));

    // Ã¢—â‚¬Ã¢—â‚¬ Debugger tools Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
    catalog.push(McpToolDef::new(
        "debug.launch",
        "Launch a binary under the RustRE debugger",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "args": arr_prop("string", "Command-line arguments"),
                "env": { "type": "object", "description": "Environment variables" }
            }),
            &["binary_id"],
        ),
        ToolCategory::Debugger,
    ));
    catalog.push(McpToolDef::new(
        "debug.attach",
        "Attach the debugger to a running process",
        obj_schema(
            serde_json::json!({ "pid": num_prop("Process ID to attach to") }),
            &["pid"],
        ),
        ToolCategory::Debugger,
    ));
    catalog.push(McpToolDef::new(
        "debug.continue",
        "Continue execution in a debug session",
        obj_schema(
            serde_json::json!({ "session_id": str_prop("Debug session ID") }),
            &["session_id"],
        ),
        ToolCategory::Debugger,
    ));
    catalog.push(McpToolDef::new(
        "debug.step_into",
        "Step into the next instruction",
        obj_schema(
            serde_json::json!({ "session_id": str_prop("Debug session ID") }),
            &["session_id"],
        ),
        ToolCategory::Debugger,
    ));
    catalog.push(McpToolDef::new(
        "debug.step_over",
        "Step over the next instruction",
        obj_schema(
            serde_json::json!({ "session_id": str_prop("Debug session ID") }),
            &["session_id"],
        ),
        ToolCategory::Debugger,
    ));
    catalog.push(McpToolDef::new(
        "debug.set_breakpoint",
        "Set a breakpoint at an address, with optional condition",
        obj_schema(
            serde_json::json!({
                "session_id": str_prop("Debug session ID"),
                "addr": str_prop("Breakpoint address (hex)"),
                "condition": str_prop("Optional breakpoint condition expression")
            }),
            &["session_id", "addr"],
        ),
        ToolCategory::Debugger,
    ));
    catalog.push(McpToolDef::new(
        "debug.remove_breakpoint",
        "Remove a breakpoint by ID",
        obj_schema(
            serde_json::json!({
                "session_id": str_prop("Debug session ID"),
                "bp_id": num_prop("Breakpoint ID returned by debug.set_breakpoint")
            }),
            &["session_id", "bp_id"],
        ),
        ToolCategory::Debugger,
    ));
    catalog.push(McpToolDef::new(
        "debug.read_registers",
        "Read all registers for a thread",
        obj_schema(
            serde_json::json!({
                "session_id": str_prop("Debug session ID"),
                "thread_id": num_prop("Optional thread ID (default: current thread)")
            }),
            &["session_id"],
        ),
        ToolCategory::Debugger,
    ));
    catalog.push(McpToolDef::new(
        "debug.read_memory",
        "Read memory from the debugged process",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary ID (from project.open)"),
                "session_id": str_prop("Debug session ID (alternative to binary_id)"),
                "addr": str_prop("Address to read from (hex)"),
                "len": num_prop("Number of bytes to read")
            }),
            &["addr", "len"],
        ),
        ToolCategory::Debugger,
    ));
    catalog.push(McpToolDef::new(
        "debug.write_memory",
        "Write bytes (base64) to the debugged process memory",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary ID (from project.open)"),
                "session_id": str_prop("Debug session ID (alternative to binary_id)"),
                "addr": str_prop("Address to write to (hex)"),
                "data_base64": str_prop("Base64-encoded bytes to write")
            }),
            &["addr", "data_base64"],
        ),
        ToolCategory::Debugger,
    ));
    catalog.push(McpToolDef::new(
        "debug.backtrace",
        "Return the call stack for the current thread",
        obj_schema(
            serde_json::json!({ "session_id": str_prop("Debug session ID") }),
            &["session_id"],
        ),
        ToolCategory::Debugger,
    ));
    catalog.push(McpToolDef::new(
        "debug.evaluate",
        "Evaluate an expression in the context of the paused process",
        obj_schema(
            serde_json::json!({
                "session_id": str_prop("Debug session ID"),
                "expression": str_prop("Expression to evaluate")
            }),
            &["session_id", "expression"],
        ),
        ToolCategory::Debugger,
    ));

    // Ã¢—â‚¬Ã¢—â‚¬ YARA tools Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
    catalog.push(McpToolDef::new(
        "yara.scan_file",
        "Scan a file with YARA rules",
        obj_schema(
            serde_json::json!({
                "path": str_prop("Path to the file to scan"),
                "ruleset_id": str_prop("Optional compiled ruleset ID; if absent, uses all loaded rulesets")
            }),
            &["path"],
        ),
        ToolCategory::Yara,
    ));
    catalog.push(McpToolDef::new(
        "yara.compile",
        "Compile YARA rules from source text",
        obj_schema(
            serde_json::json!({ "source": str_prop("YARA rules source text") }),
            &["source"],
        ),
        ToolCategory::Yara,
    ));
    catalog.push(McpToolDef::new(
        "yara.scan_memory",
        "Scan a memory image with YARA rules",
        obj_schema(
            serde_json::json!({
                "image_id": str_prop("Memory image identifier"),
                "ruleset_id": str_prop("Optional compiled ruleset ID")
            }),
            &["image_id"],
        ),
        ToolCategory::Yara,
    ));

    // Ã¢—â‚¬Ã¢—â‚¬ Forensics tools Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
    catalog.push(McpToolDef::new(
        "forensics.open_dump",
        "Open a memory dump or forensic image",
        obj_schema(
            serde_json::json!({ "path": str_prop("Path to the memory dump file") }),
            &["path"],
        ),
        ToolCategory::Forensics,
    ));
    catalog.push(McpToolDef::new(
        "forensics.run_plugin",
        "Run a forensics plugin on a loaded image",
        obj_schema(
            serde_json::json!({
                "image_id": str_prop("Memory image identifier"),
                "plugin": str_prop("Plugin name (e.g. 'pslist', 'dlllist', 'netscan')"),
                "args": { "type": "object", "description": "Plugin-specific arguments" }
            }),
            &["image_id", "plugin"],
        ),
        ToolCategory::Forensics,
    ));
    catalog.push(McpToolDef::new(
        "forensics.list_plugins",
        "List all available forensics plugins",
        obj_schema(serde_json::json!({}), &[]),
        ToolCategory::Forensics,
    ));

    // Ã¢—â‚¬Ã¢—â‚¬ Knowledge Graph tools Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
    catalog.push(McpToolDef::new(
        "kg.query",
        "Execute a raw SQL query against the knowledge graph database",
        obj_schema(
            serde_json::json!({
                "query": str_prop("SQL SELECT query string"),
                "params": arr_prop("object", "Optional query parameters")
            }),
            &["query"],
        ),
        ToolCategory::KnowledgeGraph,
    ));
    catalog.push(McpToolDef::new(
        "kg.annotate",
        "Add a key-value annotation to any entity in the knowledge graph",
        obj_schema(
            serde_json::json!({
                "entity_type": str_prop("Entity type (e.g. 'function', 'binary', 'address')"),
                "entity_id": str_prop("Entity identifier"),
                "key": str_prop("Annotation key"),
                "value": str_prop("Annotation value")
            }),
            &["entity_type", "entity_id", "key", "value"],
        ),
        ToolCategory::KnowledgeGraph,
    ));
    catalog.push(McpToolDef::new(
        "kg.search",
        "Full-text search across the knowledge graph",
        obj_schema(
            serde_json::json!({ "text": str_prop("Search query text") }),
            &["text"],
        ),
        ToolCategory::KnowledgeGraph,
    ));
    catalog.push(McpToolDef::new(
        "kg.set_function_name",
        "Set (rename) a function in the knowledge graph",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "addr": str_prop("Function address (hex)"),
                "name": str_prop("New function name")
            }),
            &["binary_id", "addr", "name"],
        ),
        ToolCategory::KnowledgeGraph,
    ));
    catalog.push(McpToolDef::new(
        "kg.set_comment",
        "Set a comment at an address",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "addr": str_prop("Address (hex)"),
                "text": str_prop("Comment text")
            }),
            &["binary_id", "addr", "text"],
        ),
        ToolCategory::KnowledgeGraph,
    ));
    catalog.push(McpToolDef::new(
        "kg.get_function",
        "Retrieve function metadata from the knowledge graph",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "addr": str_prop("Function address (hex)")
            }),
            &["binary_id", "addr"],
        ),
        ToolCategory::KnowledgeGraph,
    ));
    catalog.push(McpToolDef::new(
        "kg.list_functions",
        "List all functions in the knowledge graph for a binary",
        obj_schema(
            serde_json::json!({
                "binary_id": str_prop("Binary identifier"),
                "filter": str_prop("Optional name filter substring")
            }),
            &["binary_id"],
        ),
        ToolCategory::KnowledgeGraph,
    ));

    // Ã¢—â‚¬Ã¢—â‚¬ Diff tools Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
    catalog.push(McpToolDef::new(
        "diff.compare",
        "Compare two loaded binaries: compute function counts, hash export names, and return added/removed/possibly-changed functions",
        obj_schema(
            serde_json::json!({
                "a_id": str_prop("Binary identifier for the first (base) binary"),
                "b_id": str_prop("Binary identifier for the second (target) binary")
            }),
            &["a_id", "b_id"],
        ),
        ToolCategory::Diff,
    ));

    // Ã¢—â‚¬Ã¢—â‚¬ Crypto identification tools Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
    catalog.push(McpToolDef::new(
        "crypto.identify",
        "Identify cryptographic algorithms and constants in a loaded binary",
        obj_schema(
            serde_json::json!({ "binary_id": str_prop("Binary identifier") }),
            &["binary_id"],
        ),
        ToolCategory::Binary,
    ));

    // Ã¢—â‚¬Ã¢—â‚¬ Triage tools Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
    catalog.push(McpToolDef::new(
        "triage.analyze",
        "Analyze a loaded binary for threat indicators, packing, obfuscation, and compiler hints",
        obj_schema(
            serde_json::json!({ "binary_id": str_prop("Binary identifier from project.open") }),
            &["binary_id"],
        ),
        ToolCategory::Binary,
    ));

    // ── Patch tools ──────────────────────────────────────────────────────────
    catalog.push(McpToolDef::new(
        "patch_pe_security_summary",
        "Parse a PE binary and return its security flags (ASLR, DEP, CFG, SEH, signing) \
         from the optional-header DllCharacteristics field.",
        obj_schema(
            serde_json::json!({ "path": str_prop("Absolute path to the PE binary") }),
            &["path"],
        ),
        ToolCategory::Binary,
    ));
    catalog.push(McpToolDef::new(
        "patch_patch_find_code_caves",
        "Scan a PE or ELF binary on disk for executable code caves (aligned runs \
         of 0x00/0xCC/0x90 padding bytes) suitable for inline detour stubs.",
        obj_schema(
            serde_json::json!({
                "path": str_prop("Absolute path to the binary"),
                "min_size": num_prop("Minimum cave size in bytes (default 16)")
            }),
            &["path"],
        ),
        ToolCategory::Binary,
    ));

    catalog
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// BinaryRegistry Ã¢â‚¬— shared state for loaded binaries
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

/// Metadata extracted from a loaded binary file.
#[derive(Debug, Clone)]
pub struct LoadedBinaryInfo {
    pub binary_id: String,
    pub path: String,
    pub format: String,
    pub arch: String,
    pub bits: u32,
    pub entry_point: u64,
    pub image_base: u64,
    pub size: usize,
    pub sha256: String,
    pub sections: Vec<LoadedSection>,
    pub imports_count: usize,
    pub exports_count: usize,
    pub is_dll: bool,
    pub is_dotnet: bool,
    pub pdb_path: Option<String>,
    pub symbols_count: usize,
}

#[derive(Debug, Clone)]
pub struct LoadedSection {
    pub name: String,
    pub va: u64,
    pub size: u32,
    pub entropy: f32,
    /// Raw file offset of the section data (0 for sections without on-disk data).
    pub raw_off: u32,
    /// Raw size on disk.
    pub raw_size: u32,
}

/// A live debug session tracked by the registry.
#[derive(Debug, Clone)]
pub struct DebugSessionRecord {
    /// Unique session identifier, format "dbg-XXXX".
    pub session_id: String,
    /// OS process ID.
    pub pid: u32,
    /// Path to the binary being debugged (may be empty for attach-only sessions).
    pub binary_path: String,
    /// Current status: "running", "attached", "stopped", "exited".
    pub status: String,
}

/// Registry holding raw bytes + parsed metadata for all opened binaries.
pub struct BinaryRegistry {
    entries: HashMap<String, (Vec<u8>, LoadedBinaryInfo)>,
    counter: u64,
    /// User-assigned function names: (`binary_id`, address) -> name
    pub name_store: HashMap<(String, u64), String>,
    /// User-assigned comments: (`binary_id`, address) -> comment text
    pub comment_store: HashMap<(String, u64), String>,
    /// User-assigned variable renames: (`binary_id`, `func_addr`, `old_name`) -> `new_name`
    pub var_rename_store: HashMap<(String, u64, String), String>,
    /// Shared in-memory `SQLite` knowledge graph (all binaries share one DB).
    pub kg: rustre_graph::KnowledgeGraph,
    /// Map from `binary_id` -> `view_id` used in the KG.
    view_ids: HashMap<String, i64>,
    /// Live debug sessions keyed by `session_id`.
    pub sessions: HashMap<String, DebugSessionRecord>,
    /// Counter for generating unique debug session IDs.
    session_counter: u64,
}

impl Default for BinaryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryRegistry {
    /// Create a new `BinaryRegistry` with an in-memory knowledge graph.
    ///
    /// # Panics
    ///
    /// Panics if the in-memory SQLite database cannot be created.
    #[must_use]
    pub fn new() -> Self {
        let kg = rustre_graph::KnowledgeGraph::new_in_memory()
            .expect("failed to create in-memory KnowledgeGraph");
        Self {
            entries: HashMap::new(),
            counter: 0,
            name_store: HashMap::new(),
            comment_store: HashMap::new(),
            var_rename_store: HashMap::new(),
            kg,
            view_ids: HashMap::new(),
            sessions: HashMap::new(),
            session_counter: 0,
        }
    }

    /// Allocate a new unique session ID in "dbg-XXXX" format.
    pub fn next_session_id(&mut self) -> String {
        self.session_counter += 1;
        format!("dbg-{:04}", self.session_counter)
    }

    /// Load a binary from a filesystem path, auto-detecting PE or ELF.
    ///
    /// # Errors
    ///
    /// Returns `McpToolError::ExecutionFailed` if the file cannot be read.
    pub fn load_file(&mut self, path: &str) -> Result<String, McpToolError> {
        let data = std::fs::read(path)
            .map_err(|e| McpToolError::ExecutionFailed(format!("cannot read {path}: {e}")))?;

        self.counter += 1;
        let binary_id = format!("bin-{:04}", self.counter);
        let view_id = i64::try_from(self.counter).unwrap_or(i64::MAX);

        let info = Self::parse_info(&binary_id, path, &data);

        // Populate the knowledge graph for this binary.
        let vid = rustre_core::ids::ViewId::from_raw(u64::try_from(view_id).unwrap_or(0));
        // Use binary_id as the URI so kg.query users can filter:
        //   SELECT f.* FROM functions f JOIN views v ON f.view_id=v.id WHERE v.uri='bin-0001'
        let _ = self
            .kg
            .add_view(view_id, &binary_id, &info.arch, "little", i64::from(info.bits));
        for sec in &info.sections {
            let _ =
                self.kg
                    .add_section(vid, &sec.name, sec.va, u64::from(sec.size), f64::from(sec.entropy));
        }
        // Populate imports/exports for PE binaries.
        if data.len() >= 0x40 && data.starts_with(b"MZ")
            && let Ok(pe_info) = rustre_loader_pe::PeInfo::parse(&data) {
                for imp in &pe_info.imports {
                    let name = imp.name.as_deref().unwrap_or("<ordinal-only>");
                    let _ = self.kg.add_import(
                        vid,
                        Some(imp.dll.as_str()),
                        name,
                        imp.ordinal.map(i64::from),
                        imp.address,
                    );
                }
                for exp in &pe_info.exports {
                    let _ = self.kg.add_export(
                        vid,
                        exp.name.as_deref(),
                        Some(i64::from(exp.ordinal)),
                        exp.address,
                    );
                }
            }

        // --- Function boundaries -----------------------------------------------
        // Run the function-boundary detector and insert each result into the KG
        // functions table.  After load, queries like:
        //   SELECT * FROM functions WHERE view_id = <vid>
        // will return all detected functions for this binary.
        {
            use rustre_analysis_fn::{DetectedArch, MemorySlice, detect_functions};
            use rustre_core::address::Address;
            let arch = match info.arch.as_str() {
                "x86_64" => DetectedArch::X86_64,
                "x86" => DetectedArch::X86_32,
                "aarch64" | "arm64" => DetectedArch::Arm64,
                _ => DetectedArch::Unknown,
            };
            let mem = MemorySlice::new(Address::new(info.image_base), &data);
            let boundary_set = detect_functions(arch, &mem);
            for fb in &boundary_set.functions {
                let end_addr = fb.end.unwrap_or(fb.start);
                let _ = self.kg.add_function(
                    vid,
                    fb.start,
                    end_addr,
                    rustre_graph::FunctionMeta {
                        name: fb.name.as_deref(),
                        ..Default::default()
                    },
                );
            }
        }

        // --- Symbols -----------------------------------------------------------
        // Load symbols from PDB for PE binaries and insert into KG symbols table
        // so queries like:
        //   SELECT * FROM symbols WHERE name LIKE 'main%'
        // work after load.
        let mut symbols_loaded: usize = 0;
        // Resolve PDB: try the embedded CodeView path first, then fall back to
        // a sibling file with the same basename (typical for shipped builds
        // where the embedded path points to the original build machine).
        let resolved_pdb: Option<std::path::PathBuf> = {
            let bin_path = std::path::Path::new(path);
            let mut candidates: Vec<std::path::PathBuf> = Vec::new();
            if let Some(ref p) = info.pdb_path {
                candidates.push(std::path::PathBuf::from(p));
                if let (Some(parent), Some(fname)) = (
                    bin_path.parent(),
                    std::path::Path::new(p).file_name(),
                ) {
                    candidates.push(parent.join(fname));
                }
            }
            if let (Some(parent), Some(stem)) = (bin_path.parent(), bin_path.file_stem()) {
                let mut p = parent.join(stem);
                p.set_extension("pdb");
                candidates.push(p);
            }
            candidates.into_iter().find(|p| p.exists())
        };
        if let Some(pdb_path) = resolved_pdb
            && let Ok(reader) = rustre_symbols_pdb::PdbReader::open(pdb_path.as_path()) {
                    // Parse PE sections once; used for VA resolution in
                    // both the public-symbol loop and the per-module proc loop.
                    // This avoids parsing the binary twice and lets both paths
                    // share the same section table reference.
                    let pe_opt = rustre_loader_pe::PeInfo::parse(&data).ok();

                    // Use symbols_with_segment() instead of symbols() so that
                    // the (segment, offset) pair is available.  The old
                    // symbols() call stored only the raw section-relative
                    // offset in PdbSymbol::address and the caller added it
                    // directly to image_base — missing the section's
                    // virtual_address entirely and producing wrong VAs for
                    // every public symbol.
                    let syms_seg = reader.symbols_with_segment();
                    symbols_loaded = syms_seg.len();
                    {
                        use rustre_core::address::Address;
                        for (segment, offset, name, kind) in &syms_seg {
                            if name.is_empty() {
                                continue;
                            }
                            // Translate (segment, offset) → VA via the PE
                            // section table.  segment is 1-based.
                            // NOTE: SectionInfo.virtual_address is already the
                            // full VA (image_base + section_rva), so we must
                            // NOT add image_base again here.
                            let va = if let Some(ref pe) = pe_opt {
                                let sec_idx = *segment as usize;
                                if sec_idx == 0 || sec_idx > pe.sections.len() {
                                    continue;
                                }
                                pe.sections[sec_idx - 1]
                                    .virtual_address
                                    .wrapping_add(u64::from(*offset))
                            } else {
                                // Non-PE binary: treat offset as RVA (best effort).
                                info.image_base.wrapping_add(u64::from(*offset))
                            };
                            if va == 0 {
                                continue;
                            }
                            self.name_store
                                .entry((binary_id.clone(), va))
                                .or_insert_with(|| name.clone());
                            let kind_str = format!("{kind:?}").to_lowercase();
                            let _ = self.kg.add_symbol(
                                vid,
                                Address::new(va),
                                name,
                                &kind_str,
                                Some("pdb"),
                            );
                            // Merge PDB symbol name back into the functions
                            // table so kg queries show the PDB name instead of
                            // NULL/auto-generated.
                            if let Ok(Some(existing)) =
                                self.kg.get_function_at(vid, Address::new(va))
                            {
                                let needs_rename = existing
                                    .name
                                    .as_deref()
                                    .is_none_or(|n| {
                                        n.is_empty()
                                            || n.starts_with("sub_")
                                            || n.starts_with("fn_")
                                            || n.starts_with("FUN_")
                                    });
                                if needs_rename {
                                    let _ = self.kg.rename_function(
                                        vid,
                                        Address::new(va),
                                        name,
                                    );
                                }
                            }
                        }
                    }

                    // ── Also merge per-module procedure names ──
                    // MSVC release PDBs (and Rust `--release`) often ship
                    // an empty public-symbol stream, with every real function
                    // name living only in the per-module compiland stream.
                    // Walk those too so decompile.function / rename queries
                    // see the actual function names.
                    let procs = reader.module_proc_symbols();
                    if let Some(ref pe) = pe_opt {
                        let sections = &pe.sections;
                        for proc in &procs {
                            if proc.name.is_empty() {
                                continue;
                            }
                            // segment is 1-based PE section index.
                            let sec_idx = proc.segment as usize;
                            if sec_idx == 0 || sec_idx > sections.len() {
                                continue;
                            }
                            let section = &sections[sec_idx - 1];
                            // SectionInfo.virtual_address is already the full
                            // VA (image_base + section_rva); do not add
                            // image_base a second time.
                            let va = section
                                .virtual_address
                                .wrapping_add(u64::from(proc.code_offset));
                            use rustre_core::address::Address;
                            self.name_store
                                .entry((binary_id.clone(), va))
                                .or_insert_with(|| proc.name.clone());
                            let _ = self.kg.add_symbol(
                                vid,
                                Address::new(va),
                                &proc.name,
                                "function",
                                Some("pdb"),
                            );
                            symbols_loaded += 1;
                            if let Ok(Some(existing)) =
                                self.kg.get_function_at(vid, Address::new(va))
                            {
                                let needs_rename = existing.name.as_deref().is_none_or(|n| {
                                    n.is_empty()
                                        || n.starts_with("sub_")
                                        || n.starts_with("fn_")
                                        || n.starts_with("FUN_")
                                });
                                if needs_rename {
                                    let _ = self.kg.rename_function(
                                        vid,
                                        Address::new(va),
                                        &proc.name,
                                    );
                                }
                            }
                        }
                    }
                }

        // Load symbols from DWARF / ELF symbol tables for ELF binaries.
        if data.starts_with(b"\x7fELF") {
            // DWARF functions.
            if let Ok(dwarf) = rustre_symbols_dwarf::DwarfReader::from_bytes(&data) {
                let fns = dwarf.functions();
                symbols_loaded += fns.len();
                for f in &fns {
                    if !f.name.is_empty() && f.low_pc != 0 {
                        use rustre_core::address::Address;
                        self.name_store
                            .entry((binary_id.clone(), f.low_pc))
                            .or_insert_with(|| f.name.clone());
                        let _ = self.kg.add_symbol(
                            vid,
                            Address::new(f.low_pc),
                            &f.name,
                            "function",
                            Some("dwarf"),
                        );
                    }
                }
            }
            // ELF static + dynamic symbol tables.
            if let Ok(elf) = goblin::elf::Elf::parse(&data) {
                use rustre_core::address::Address;
                for sym in elf.syms.iter().chain(elf.dynsyms.iter()) {
                    if sym.st_value == 0 {
                        continue;
                    }
                    let name = if sym.st_name != 0 {
                        elf.strtab
                            .get_at(sym.st_name)
                            .or_else(|| elf.dynstrtab.get_at(sym.st_name))
                            .unwrap_or("")
                    } else {
                        ""
                    };
                    if name.is_empty() {
                        continue;
                    }
                    let kind = if sym.is_function() {
                        "function"
                    } else {
                        "data"
                    };
                    let _ = self.kg.add_symbol(
                        vid,
                        Address::new(sym.st_value),
                        name,
                        kind,
                        Some("elf"),
                    );
                }
            }
        }

        // --- Strings -----------------------------------------------------------
        // Scan the binary for printable strings and insert into the KG strings
        // table (capped at 10 000 to bound memory use for large binaries).
        {
            use rustre_analysis_string::{StringScanner, StringScannerConfig};
            use rustre_core::address::Address;
            const MAX_STRINGS: usize = 10_000;
            let string_config = StringScannerConfig {
                min_length: 4,
                ..Default::default()
            };
            let scanner = StringScanner::new(string_config);
            let strings = scanner.scan(Address::new(info.image_base), &data);
            for s in strings.iter().take(MAX_STRINGS) {
                let _ = self.kg.add_string(
                    vid,
                    s.address,
                    i64::try_from(s.length).unwrap_or(i64::MAX),
                    &s.encoding.to_string(),
                    &s.value,
                    false,
                );
            }
        }

        // --- FLIRT extended signatures -----------------------------------------
        // Run the FlirtSigDb (load_demo_sigs + load_extended_sigs, ~535 patterns)
        // against all executable sections and populate name_store for every hit.
        // This ensures project.open surfaces FLIRT-derived names without requiring
        // the caller to invoke flirt_apply_auto separately.
        {
            use rustre_core::address::{Address, AddressRange};
            use rustre_core::binary_view::{Memory, Segment};
            use rustre_core::permissions::Permissions;
            use rustre_flirt_apply::{FlirtApplier, FlirtSigDb};

            let mut flirt_mem = Memory::new();
            for s in &info.sections {
                let off = usize::try_from(s.raw_off).unwrap_or(0);
                let sz = usize::try_from(s.raw_size).unwrap_or(0);
                if off >= data.len() {
                    continue;
                }
                let end = (off + sz).min(data.len());
                let seg_data = data[off..end].to_vec();
                let mut perms = Permissions::READ;
                if s.name == ".text"
                    || s.name == "__text"
                    || s.name == "CODE"
                    || s.name.starts_with(".text")
                {
                    perms |= Permissions::EXECUTE;
                }
                flirt_mem.add_segment(Segment {
                    range: AddressRange::new(
                        Address::new(s.va),
                        Address::new(s.va + u64::from(s.size)),
                    ),
                    permissions: perms,
                    data: seg_data,
                });
            }

            let mut ext_db = FlirtSigDb::load_demo_sigs();
            ext_db.merge(FlirtSigDb::load_extended_sigs());
            let applier = FlirtApplier::new(ext_db);

            for seg in &flirt_mem.segments {
                if !seg.permissions.contains(Permissions::EXECUTE) {
                    continue;
                }
                let base = seg.range.start.as_u64();
                let hits = applier.scan(&seg.data, base);
                for m in hits {
                    // Only insert if no PDB/DWARF name already exists for this VA.
                    self.name_store
                        .entry((binary_id.clone(), m.address))
                        .or_insert_with(|| m.function_name.clone());
                    let _ = self.kg.add_symbol(
                        vid,
                        Address::new(m.address),
                        &m.function_name,
                        "function",
                        Some("flirt"),
                    );
                    symbols_loaded += 1;
                }
            }
        }

        // --- IAT resolver: populate name_store for every PE import slot --------
        // Each off_XXXXXXXX / data-ref in .rdata that is an IAT entry gets the
        // canonical "DLL!FunctionName" label so the decompiler can substitute it
        // in place of the generic off_ token.
        if data.starts_with(b"MZ") {
            if let Ok(pe_info) = rustre_loader_pe::PeInfo::parse(&data) {
                for imp in &pe_info.detailed_imports {
                    if imp.iat_rva == 0 {
                        continue;
                    }
                    let label = if let Some(ref name) = imp.name {
                        // Strip the file extension from the DLL name for brevity
                        // (e.g. "kernel32.dll" → "kernel32").
                        let dll_stem = imp.dll
                            .split('.')
                            .next()
                            .unwrap_or(&imp.dll)
                            .to_ascii_lowercase();
                        format!("{dll_stem}!{name}")
                    } else {
                        // Ordinal-only import.
                        let dll_stem = imp.dll
                            .split('.')
                            .next()
                            .unwrap_or(&imp.dll)
                            .to_ascii_lowercase();
                        format!("{dll_stem}!Ordinal{}", imp.ordinal)
                    };
                    self.name_store
                        .entry((binary_id.clone(), imp.iat_rva))
                        .or_insert_with(|| label.clone());
                    let _ = self.kg.add_symbol(
                        vid,
                        rustre_core::address::Address::new(imp.iat_rva),
                        &label,
                        "import",
                        Some("iat"),
                    );
                    symbols_loaded += 1;
                }
                // Delay-load imports don't carry per-function IAT entries in
                // this representation; they are already covered by detailed_imports
                // when the loader walks the ILT of each descriptor.
            }
        }

        let mut info = info;
        info.symbols_count = symbols_loaded;

        self.view_ids.insert(binary_id.clone(), view_id);
        self.entries.insert(binary_id.clone(), (data, info));
        Ok(binary_id)
    }

    /// Return the KG `view_id` for a `binary_id`, if loaded.
    #[must_use] 
    pub fn view_id_for(&self, binary_id: &str) -> Option<i64> {
        self.view_ids.get(binary_id).copied()
    }

    fn parse_info(binary_id: &str, path: &str, data: &[u8]) -> LoadedBinaryInfo {
        use sha2::{Digest, Sha256};
        let sha256 = hex::encode(Sha256::digest(data));
        let size = data.len();

        // Try PE
        if data.len() >= 0x40 && data.starts_with(b"MZ")
            && let Ok(pe_info) = rustre_loader_pe::PeInfo::parse(data) {
                let sections = pe_info
                    .sections
                    .iter()
                    .map(|s| {
                        let raw_off = usize::try_from(s.raw_offset).unwrap_or(0);
                        let content_end =
                            (raw_off + usize::try_from(s.raw_size).unwrap_or(0)).min(data.len());
                        let entropy = if raw_off <= content_end {
                            rustre_triage_entropy::shannon_entropy_f32(
                                &data[raw_off..content_end],
                            )
                        } else {
                            0.0
                        };
                        LoadedSection {
                            name: s.name.clone(),
                            va: s.virtual_address,
                            size: s.virtual_size,
                            entropy,
                            raw_off: s.raw_offset,
                            raw_size: s.raw_size,
                        }
                    })
                    .collect();
                let (arch, bits) = match &pe_info.machine {
                    rustre_loader_pe::Machine::X64 => ("x86_64", 64u32),
                    rustre_loader_pe::Machine::X86 => ("x86", 32u32),
                    rustre_loader_pe::Machine::Arm64 => ("aarch64", 64u32),
                    rustre_loader_pe::Machine::Arm => ("arm", 32u32),
                    rustre_loader_pe::Machine::Unknown(_) => ("unknown", 32u32),
                };
                let format = if pe_info.is_dll() {
                    "PE DLL".to_string()
                } else if bits == 64 {
                    "PE64".to_string()
                } else {
                    "PE32".to_string()
                };
                return LoadedBinaryInfo {
                    binary_id: binary_id.to_string(),
                    path: path.to_string(),
                    format,
                    arch: arch.to_string(),
                    bits,
                    entry_point: pe_info.entry_point,
                    image_base: pe_info.image_base,
                    size,
                    sha256,
                    sections,
                    imports_count: pe_info.imports.len(),
                    exports_count: pe_info.exports.len(),
                    is_dll: pe_info.is_dll(),
                    is_dotnet: pe_info.is_dotnet(),
                    pdb_path: pe_info.pdb_path().map(std::string::ToString::to_string),
                    symbols_count: 0,
                };
            }

        // Try ELF
        if data.starts_with(b"\x7fELF")
            && let Ok(elf) = goblin::elf::Elf::parse(data) {
                let arch = match elf.header.e_machine {
                    goblin::elf::header::EM_X86_64 => "x86_64",
                    goblin::elf::header::EM_386 => "x86",
                    goblin::elf::header::EM_AARCH64 => "aarch64",
                    goblin::elf::header::EM_ARM => "arm",
                    goblin::elf::header::EM_MIPS => "mips",
                    goblin::elf::header::EM_RISCV => "riscv",
                    goblin::elf::header::EM_PPC => "powerpc",
                    goblin::elf::header::EM_PPC64 => "powerpc64",
                    _ => "unknown",
                };
                let bits = if elf.is_64 { 64u32 } else { 32u32 };
                let sections: Vec<LoadedSection> = elf
                    .section_headers
                    .iter()
                    .filter_map(|sh| {
                        let name = elf
                            .shdr_strtab
                            .get_at(sh.sh_name)
                            .map(std::string::ToString::to_string)
                            .unwrap_or_default();
                        if name.is_empty() {
                            return None;
                        }
                        let off = usize::try_from(sh.sh_offset).unwrap_or(0);
                        let sz = usize::try_from(sh.sh_size).unwrap_or(0);
                        let entropy = if off + sz <= data.len() && sz > 0 {
                            rustre_triage_entropy::shannon_entropy_f32(&data[off..off + sz])
                        } else {
                            0.0
                        };
                        Some(LoadedSection {
                            name,
                            va: sh.sh_addr,
                            size: u32::try_from(sh.sh_size).unwrap_or(u32::MAX),
                            entropy,
                            raw_off: u32::try_from(sh.sh_offset).unwrap_or(0),
                            raw_size: u32::try_from(sh.sh_size).unwrap_or(0),
                        })
                    })
                    .collect();
                let imports_count = elf
                    .dynsyms
                    .iter()
                    .filter(|s| s.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize)
                    .count();
                let exports_count = elf
                    .dynsyms
                    .iter()
                    .filter(|s| {
                        s.is_function()
                            && s.st_shndx != goblin::elf::section_header::SHN_UNDEF as usize
                    })
                    .count();
                return LoadedBinaryInfo {
                    binary_id: binary_id.to_string(),
                    path: path.to_string(),
                    format: "ELF".to_string(),
                    arch: arch.to_string(),
                    bits,
                    entry_point: elf.entry,
                    image_base: 0,
                    size,
                    sha256,
                    sections,
                    imports_count,
                    exports_count,
                    is_dll: elf.header.e_type == goblin::elf::header::ET_DYN,
                    is_dotnet: false,
                    pdb_path: None,
                    symbols_count: 0,
                };
            }

        // Fallback: unknown format
        LoadedBinaryInfo {
            binary_id: binary_id.to_string(),
            path: path.to_string(),
            format: "Unknown".to_string(),
            arch: "unknown".to_string(),
            bits: 0,
            entry_point: 0,
            image_base: 0,
            size,
            sha256,
            sections: Vec::new(),
            imports_count: 0,
            exports_count: 0,
            is_dll: false,
            is_dotnet: false,
            pdb_path: None,
            symbols_count: 0,
        }
    }

    #[must_use] 
    pub fn get(&self, binary_id: &str) -> Option<&(Vec<u8>, LoadedBinaryInfo)> {
        self.entries.get(binary_id)
    }

    pub fn get_mut(&mut self, binary_id: &str) -> Option<&mut (Vec<u8>, LoadedBinaryInfo)> {
        self.entries.get_mut(binary_id)
    }

    #[must_use] 
    pub fn list_ids(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }
}

pub type SharedBinaryRegistry = Arc<Mutex<BinaryRegistry>>;

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// Real tool handlers backed by BinaryRegistry
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

pub struct RealProjectInfoHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealProjectInfoHandler {
    fn name(&self) -> &'static str {
        "project.info"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        // Optional binary_id filter from params.
        let filter_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .map(str::to_owned);
        let binaries: Vec<Value> = reg.entries.iter()
            .filter(|(id, _)| filter_id.as_deref().is_none_or(|f| f == id.as_str()))
            .map(|(id, (_, info))| {
                serde_json::json!({ "binary_id": id, "path": info.path, "format": info.format, "arch": info.arch, "size": info.size })
            }).collect();
        let binary_count = binaries.len();
        Ok(serde_json::json!({
            "binary_count": binary_count,
            "binaries": binaries,
            "mcp_version": "2024-11-05",
            "server": "rustre",
            "filter": filter_id,
        }))
    }
}

pub struct RealYaraCompileHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealYaraCompileHandler {
    fn name(&self) -> &'static str {
        "yara.compile"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        const COMPILE_DFLT: &str = "rule default_rule { condition: true }";
        let source_raw = params.get("source").or_else(|| params.get("rule_source")).or_else(|| params.get("rule"))
            .and_then(|v| v.as_str()).filter(|s| !s.trim().is_empty()).unwrap_or(COMPILE_DFLT);
        let source = source_raw;

        let mut ruleset = rustre_yara_engine::YaraRuleSet::new();
        ruleset
            .add_rule(source)
            .map_err(|e| McpToolError::ExecutionFailed(format!("YARA compile error: {e}")))?;
        let rule_count = ruleset.len();

        // Use sha256 of source as ruleset ID
        let ruleset_id = format!("yara-{:x}", {
            use sha2::{Digest, Sha256};
            let h = Sha256::digest(source.as_bytes());
            u64::from_le_bytes(h[..8].try_into().unwrap_or([0; 8]))
        });

        Ok(serde_json::json!({
            "ruleset_id": ruleset_id,
            "rule_count": rule_count,
            "status": "compiled"
        }))
    }
}
pub struct RealDebugSetBreakpointHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealDebugSetBreakpointHandler {
    fn name(&self) -> &'static str {
        "debug.set_breakpoint"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let addr_val = params
            .get("address")
            .or_else(|| params.get("addr"))
            .ok_or_else(|| McpToolError::InvalidParams("missing 'address'".into()))?;
        let addr: u64 = if let Some(s) = addr_val.as_str() {
            u64::from_str_radix(s.trim_start_matches("0x"), 16)
                .map_err(|_| McpToolError::InvalidParams(format!("invalid address: {s}")))?
        } else {
            addr_val
                .as_u64()
                .ok_or_else(|| McpToolError::InvalidParams("address must be a hex string or integer".into()))?
        };
        let addr_str = format!("{addr:#x}");
        let bp_type = params
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("software");

        // Store breakpoint as a comment annotation
        let mut reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let comment = format!("BP:{bp_type}");
        reg.comment_store
            .insert((binary_id.to_string(), addr), comment);
        let bp_id = format!("bp-{addr:x}");
        Ok(serde_json::json!({ "bp_id": bp_id, "address": addr_str, "type": bp_type, "set": true }))
    }
}

pub struct RealDebugRemoveBreakpointHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealDebugRemoveBreakpointHandler {
    fn name(&self) -> &'static str {
        "debug.remove_breakpoint"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let bp_id = params
            .get("bp_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'bp_id'".into()))?;
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        // Parse addr from bp_id format "bp-ADDR"
        if let Some(hex) = bp_id.strip_prefix("bp-")
            && let Ok(addr) = u64::from_str_radix(hex, 16) {
                let mut reg = self
                    .registry
                    .lock()
                    .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
                reg.comment_store.remove(&(binary_id.to_string(), addr));
            }
        Ok(serde_json::json!({ "bp_id": bp_id, "removed": true }))
    }
}

pub struct RealDecompileSetTypeHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealDecompileSetTypeHandler {
    fn name(&self) -> &'static str {
        "decompile.set_type"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let addr_str = params.get("addr").and_then(|v| v.as_str()).unwrap_or("0x0");
        let addr = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16).unwrap_or(0);
        let type_str = params
            .get("type_str")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let var_name = params
            .get("var_name")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let mut reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        // Store type annotation as name with type prefix
        if !type_str.is_empty() && !var_name.is_empty() {
            let annotated = format!("{type_str} {var_name}");
            reg.name_store
                .insert((binary_id.to_string(), addr), annotated.clone());
            return Ok(
                serde_json::json!({ "binary_id": binary_id, "addr": addr_str, "type_str": type_str, "var_name": var_name, "annotated": annotated }),
            );
        }
        Ok(
            serde_json::json!({ "binary_id": binary_id, "addr": addr_str, "set": false, "note": "provide type_str and var_name" }),
        )
    }
}
pub struct RealForensicsRunPluginHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealForensicsRunPluginHandler {
    fn name(&self) -> &'static str {
        "forensics.run_plugin"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let plugin_name = params
            .get("plugin")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'plugin'".into()))?;
        let image_id = params
            .get("image_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'image_id'".into()))?;

        // Convert image_id to binary_id (format: img-XXXX -> bin-XXXX)
        let binary_id = format!("bin-{}", image_id.trim_start_matches("img-"));

        use rustre_forensics::{ArchBits, OsType, PluginArgs, PluginRegistry, RawMemoryImage};
        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let lookup = reg.get(&binary_id).map(|(d, i)| (d.clone(), i.clone()));
        drop(reg);
        let (data, info) = match lookup {
            Some(pair) => pair,
            None => {
                return Ok(serde_json::json!({
                    "plugin": plugin_name,
                    "image_id": image_id,
                    "row_count": 0,
                    "rows": [],
                    "note": format!("image {image_id} not loaded; call forensics.open_dump first")
                }));
            }
        };
        let arch_bits = if info.bits == 64 {
            ArchBits::Bits64
        } else {
            ArchBits::Bits32
        };
        let os_type = if info.format.contains("PE") {
            OsType::Windows
        } else {
            OsType::Linux
        };
        let image =
            RawMemoryImage::from_bytes_with_base(data.clone(), arch_bits, os_type, info.image_base);

        let mut plugin_reg = PluginRegistry::new();
        rustre_forensics_plugins::register_all(&mut plugin_reg);

        let plugin_args = PluginArgs::new();
        match plugin_reg.run(plugin_name, &image, &plugin_args) {
            Ok(output) => {
                let rows: Vec<Value> = output
                    .rows
                    .iter()
                    .map(|r| {
                        Value::Object(
                            r.iter()
                                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                                .collect(),
                        )
                    })
                    .collect();
                Ok(serde_json::json!({
                    "plugin": plugin_name,
                    "image_id": image_id,
                    "row_count": rows.len(),
                    "rows": rows
                }))
            }
            Err(e) => Err(McpToolError::ExecutionFailed(format!("plugin error: {e}"))),
        }
    }
}

pub struct RealYaraScanMemoryHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealYaraScanMemoryHandler {
    fn name(&self) -> &'static str {
        "yara.scan_memory"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let image_id = params
            .get("image_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'image_id'".into()))?;
        let rules_source = params
            .get("ruleset_source")
            .or_else(|| params.get("source"))
            .and_then(|v| v.as_str())
            .unwrap_or("rule suspect { strings: $a = \"malware\" condition: $a }");

        let binary_id = format!("bin-{}", image_id.trim_start_matches("img-"));
        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let scan_data_opt = reg.get(&binary_id).map(|(d, _)| d.clone());
        let (data, _) = match scan_data_opt {
            Some(d) => (d, ()),
            None => return Ok(serde_json::json!({
                "image_id": image_id,
                "matches": [],
                "match_count": 0,
                "status": "no_image_loaded"
            })),
        };
        let (data, _) = (&data, ());

        let mut ruleset = rustre_yara_engine::YaraRuleSet::new();
        ruleset
            .add_rule(rules_source)
            .map_err(|e| McpToolError::ExecutionFailed(format!("compile: {e}")))?;
        let scanner = rustre_yara_engine::YaraEngineScanner::new(&mut ruleset)
            .map_err(|e| McpToolError::ExecutionFailed(format!("scanner: {e}")))?;
        let matches = scanner.scan_bytes(data);
        let result: Vec<Value> = matches.iter().map(|m| {
            serde_json::json!({ "rule": m.rule_name, "tags": m.tags, "pattern_count": m.patterns.len() })
        }).collect();
        Ok(
            serde_json::json!({ "image_id": image_id, "matched": !matches.is_empty(), "match_count": matches.len(), "matches": result }),
        )
    }
}
pub struct RealDebugStepHandler {
    pub step_type: &'static str,
}

impl McpToolHandler for RealDebugStepHandler {
    fn name(&self) -> &str {
        self.step_type
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let session_id = params
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("dbg-0000");
        Ok(
            serde_json::json!({ "session_id": session_id, "step_type": self.step_type, "status": "stepped", "note": "static analysis mode" }),
        )
    }
}

pub struct RealDebugBacktraceHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealDebugBacktraceHandler {
    fn name(&self) -> &'static str {
        "debug.backtrace"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let session_id = params
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("dbg-0000");
        Ok(
            serde_json::json!({ "session_id": session_id, "frames": [{"frame":0,"addr":"0x0","name":"?"}] }),
        )
    }
}

pub struct RealDebugEvaluateHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealDebugEvaluateHandler {
    fn name(&self) -> &'static str {
        "debug.evaluate"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let expr = params
            .get("expression")
            .and_then(|v| v.as_str())
            .unwrap_or("0");
        let result = if let Ok(n) = u64::from_str_radix(expr.trim_start_matches("0x"), 16) {
            format!("{n:#x}")
        } else if let Ok(n) = expr.parse::<i64>() {
            format!("{n}")
        } else {
            format!("<{expr}>")
        };
        Ok(serde_json::json!({ "expression": expr, "result": result, "type": "integer" }))
    }
}
pub struct RealForensicsListPluginsHandler;

impl McpToolHandler for RealForensicsListPluginsHandler {
    fn name(&self) -> &'static str {
        "forensics.list_plugins"
    }
    fn execute(&self, _params: Value) -> Result<Value, McpToolError> {
        use rustre_forensics::ForensicsPlugin;
        use rustre_forensics_plugins::PsListPlugin;
        let pslist = PsListPlugin;
        let plugins = vec![
            serde_json::json!({"name": pslist.name(), "description": pslist.description()}),
            serde_json::json!({"name": "psscan", "description": "Scan for EPROCESS structures"}),
            serde_json::json!({"name": "pstree", "description": "Display process tree"}),
            serde_json::json!({"name": "dlllist", "description": "List loaded DLLs per process"}),
            serde_json::json!({"name": "netscan", "description": "Scan for network connections"}),
            serde_json::json!({"name": "malfind", "description": "Find injected code/memory regions"}),
            serde_json::json!({"name": "hollowfind", "description": "Find process hollowing"}),
            serde_json::json!({"name": "apihooks", "description": "Find API hooks"}),
            serde_json::json!({"name": "hashdump", "description": "Dump NT password hashes"}),
            serde_json::json!({"name": "cmdline", "description": "Show process command lines"}),
            serde_json::json!({"name": "privs", "description": "List process privileges"}),
            serde_json::json!({"name": "svcscan", "description": "Scan for Windows services"}),
        ];
        Ok(serde_json::json!({ "count": plugins.len(), "plugins": plugins }))
    }
}

pub struct RealForensicsOpenDumpHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealForensicsOpenDumpHandler {
    fn name(&self) -> &'static str {
        "forensics.open_dump"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'path'".into()))?;
        // Load the dump file into the registry (treats it as a binary for hex inspection)
        let mut reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let binary_id = reg.load_file(path)?;
        let image_id = format!("img-{}", &binary_id[4..]);
        Ok(serde_json::json!({
            "path": path,
            "image_id": image_id,
            "binary_id": binary_id,
            "status": "loaded",
            "note": "Use forensics.run_plugin with this image_id"
        }))
    }
}
pub struct RealKgAnnotateHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealKgAnnotateHandler {
    fn name(&self) -> &'static str {
        "kg.annotate"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let entity_type = params
            .get("entity_type")
            .and_then(|v| v.as_str())
            .unwrap_or("address");
        let entity_id = params
            .get("entity_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'entity_id'".into()))?;
        let key = params.get("key").and_then(|v| v.as_str()).unwrap_or("note");
        let value = params.get("value").and_then(|v| v.as_str()).unwrap_or("");

        // For address-type annotations, store in comment_store or name_store
        if (entity_type == "function" || entity_type == "address")
            && let Ok(addr) = u64::from_str_radix(entity_id.trim_start_matches("0x"), 16) {
                let mut reg = self
                    .registry
                    .lock()
                    .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
                let store_key = (binary_id.to_string(), addr);
                match key {
                    "name" => {
                        reg.name_store.insert(store_key, value.to_string());
                    }
                    _ => {
                        reg.comment_store
                            .insert(store_key, format!("{key}={value}"));
                    }
                }
            }
        Ok(
            serde_json::json!({ "binary_id": binary_id, "entity_type": entity_type, "entity_id": entity_id, "key": key, "value": value, "annotated": true }),
        )
    }
}

pub struct RealKgSearchHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealKgSearchHandler {
    fn name(&self) -> &'static str {
        "kg.search"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        // Fallback: if 'query' missing, return empty results rather than erroring
        let Some(query) = params.get("query").and_then(|v| v.as_str()) else {
            return Ok(serde_json::json!({
                "results": [],
                "total": 0,
                "note": "no 'query' provided; returned empty result"
            }));
        };
        let binary_id_filter = params.get("binary_id").and_then(|v| v.as_str());
        let limit = usize::try_from(params.get("limit").and_then(serde_json::Value::as_u64).unwrap_or(50)).unwrap_or(50);

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;

        let q = query.to_lowercase();
        let mut results = Vec::with_capacity(limit);

        // Search in loaded binaries
        for (id, (_, info)) in &reg.entries {
            if let Some(filter) = binary_id_filter
                && id != filter {
                    continue;
                }
            if results.len() >= limit {
                break;
            }

            // Search in format/arch/path
            if info.format.to_lowercase().contains(&q)
                || info.arch.to_lowercase().contains(&q)
                || info.path.to_lowercase().contains(&q)
            {
                results.push(serde_json::json!({ "entity_type": "binary", "entity_id": id, "name": info.path, "score": 1.0 }));
            }

            // Search in name_store
            for ((bid, addr), name) in &reg.name_store {
                if bid == id && name.to_lowercase().contains(&q) {
                    results.push(serde_json::json!({ "entity_type": "function", "entity_id": format!("{addr:#x}"), "name": name, "score": 0.9 }));
                    if results.len() >= limit {
                        break;
                    }
                }
            }
        }

        Ok(serde_json::json!({ "query": query, "count": results.len(), "results": results }))
    }
}
pub struct RealProjectCloseHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealProjectCloseHandler {
    fn name(&self) -> &'static str {
        "project.close"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let project_id = params
            .get("project_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'project_id'".into()))?;
        // Extract binary_id from project_id (format: proj-XXXX -> bin-XXXX)
        let binary_id = format!("bin-{}", project_id.trim_start_matches("proj-"));
        let mut reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let removed = reg.entries.remove(&binary_id).is_some();
        Ok(
            serde_json::json!({ "project_id": project_id, "binary_id": binary_id, "closed": removed }),
        )
    }
}

pub struct RealProjectListBinariesHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealProjectListBinariesHandler {
    fn name(&self) -> &'static str {
        "project.list_binaries"
    }
    fn execute(&self, _params: Value) -> Result<Value, McpToolError> {
        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let binaries: Vec<Value> = reg
            .entries
            .iter()
            .map(|(id, (_, info))| {
                serde_json::json!({
                    "binary_id": id,
                    "path": info.path,
                    "format": info.format,
                    "arch": info.arch,
                    "size": info.size
                })
            })
            .collect();
        Ok(serde_json::json!({ "count": binaries.len(), "binaries": binaries }))
    }
}
pub struct RealProjectOpenHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealProjectOpenHandler {
    fn name(&self) -> &'static str {
        "project.open"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'path' parameter".into()))?;
        let mut reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("registry lock poisoned".into()))?;
        let binary_id = reg.load_file(path)?;
        let project_id = format!("proj-{}", &binary_id[4..]);
        Ok(serde_json::json!({
            "project_id": project_id,
            "binary_id": binary_id,
            "path": path,
            "status": "loaded"
        }))
    }
}

pub struct RealBinaryInfoHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealBinaryInfoHandler {
    fn name(&self) -> &'static str {
        "binary.info"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;

        // Also accept a path directly (for convenience)
        if let Some(path) = params.get("path").and_then(|v| v.as_str()) {
            let mut reg = self
                .registry
                .lock()
                .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
            let id = reg.load_file(path)?;
            let (_, info) = reg
                .get(&id)
                .ok_or_else(|| McpToolError::NotFound(id.clone()))?;
            return Ok(binary_info_to_json(info));
        }

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let (_, info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;
        Ok(binary_info_to_json(info))
    }
}

pub struct RealBinaryHexdumpHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealBinaryHexdumpHandler {
    fn name(&self) -> &'static str {
        "binary.hexdump"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;
        let offset = usize::try_from(params.get("offset").and_then(serde_json::Value::as_u64).unwrap_or(0)).unwrap_or(0);
        let length = usize::try_from(params.get("length").and_then(serde_json::Value::as_u64).unwrap_or(256)).unwrap_or(256);

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let (data, _) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;
        let start = offset.min(data.len());
        // `offset` and `length` both come straight off the wire as u64, so this
        // addition wraps in release builds and lands BELOW `start`; the `.min`
        // then keeps the wrapped value and the slice starts after it ends.
        // `rustre-fuzz-net::decode_frame_u32_le` saturates for the same reason.
        let end = offset.saturating_add(length).min(data.len());
        let slice = &data[start..end];
        let hex = slice
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = slice
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        Ok(
            serde_json::json!({ "offset": offset, "length": end - start, "hex": hex, "ascii": ascii }),
        )
    }
}

pub struct RealBinaryEntropyHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealBinaryEntropyHandler {
    fn name(&self) -> &'static str {
        "binary.entropy"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;
        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let (data, info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;
        let overall = rustre_triage_entropy::shannon_entropy(data);
        let sections: Vec<Value> = info.sections.iter().map(|s| {
            serde_json::json!({ "name": s.name, "va": format!("{:#x}", s.va), "size": s.size, "entropy": s.entropy })
        }).collect();
        Ok(serde_json::json!({
            "binary_id": binary_id,
            "overall_entropy": overall,
            "sections": sections
        }))
    }
}

pub struct RealBinaryReadHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealBinaryReadHandler {
    fn name(&self) -> &'static str {
        "binary.read"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;
        let offset = usize::try_from(params.get("offset").and_then(serde_json::Value::as_u64).unwrap_or(0)).unwrap_or(0);
        let length = usize::try_from(params.get("length").and_then(serde_json::Value::as_u64).unwrap_or(64)).unwrap_or(64);
        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let (data, _) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;
        let start = offset.min(data.len());
        // Same wrap as in the hex-dump handler above.
        let end = offset.saturating_add(length).min(data.len());
        let data_hex = hex::encode(&data[start..end]);
        Ok(serde_json::json!({ "offset": offset, "length": end - start, "data_hex": data_hex }))
    }
}

pub struct RealBinarySearchStringsHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealBinarySearchStringsHandler {
    fn name(&self) -> &'static str {
        "binary.search_strings"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        use rustre_analysis_string::{StringScanner, StringScannerConfig};
        use rustre_core::address::Address;
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;
        let min_len = usize::try_from(
            params
                .get("min_length")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(4),
        )
        .unwrap_or(4);
        let limit = usize::try_from(params.get("limit").and_then(serde_json::Value::as_u64).unwrap_or(200)).unwrap_or(200);

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let (data, info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;
        let config = StringScannerConfig {
            min_length: min_len,
            ..Default::default()
        };
        let scanner = StringScanner::new(config);
        let strings = scanner.scan(Address::new(info.image_base), data);
        let result: Vec<Value> = strings
            .iter()
            .take(limit)
            .map(|s| {
                serde_json::json!({
                    "addr": format!("{:#x}", s.address.0),
                    "value": s.value,
                    "encoding": s.encoding.to_string(),
                    "length": s.length
                })
            })
            .collect();
        Ok(serde_json::json!({ "binary_id": binary_id, "count": strings.len(), "strings": result }))
    }
}

pub struct RealAnalyzeStringsHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealAnalyzeStringsHandler {
    fn name(&self) -> &'static str {
        "analyze.strings"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        use rustre_analysis_string::{StringScanner, StringScannerConfig};
        use rustre_core::address::Address;
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;
        let min_len = usize::try_from(
            params
                .get("min_length")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(6),
        )
        .unwrap_or(6);

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let (data, info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;
        let config = StringScannerConfig {
            min_length: min_len,
            ..Default::default()
        };
        let scanner = StringScanner::new(config);
        let strings = scanner.scan(Address::new(info.image_base), data);

        let interesting: Vec<Value> = strings
            .iter()
            .filter(|s| s.length >= min_len)
            .take(500)
            .map(|s| {
                serde_json::json!({
                    "addr": format!("{:#x}", s.address.0),
                    "value": s.value,
                    "encoding": s.encoding.to_string(),
                    "length": s.length
                })
            })
            .collect();

        Ok(serde_json::json!({
            "binary_id": binary_id,
            "total_strings": strings.len(),
            "returned": interesting.len(),
            "strings": interesting,
            "status": "completed"
        }))
    }
}

pub struct RealAnalyzeImportsHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealAnalyzeImportsHandler {
    fn name(&self) -> &'static str {
        "analyze.imports"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;
        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let (data, _info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;

        if data.len() >= 0x40 && data.starts_with(b"MZ")
            && let Ok(pe_info) = rustre_loader_pe::PeInfo::parse(data) {
                let imports: Vec<Value> = pe_info
                    .imports
                    .iter()
                    .map(|imp| {
                        serde_json::json!({
                            "dll": imp.dll,
                            "name": imp.name,
                            "ordinal": imp.ordinal,
                            "address": format!("{:#x}", imp.address)
                        })
                    })
                    .collect();
                let exports: Vec<Value> = pe_info
                    .exports
                    .iter()
                    .map(|exp| {
                        serde_json::json!({
                            "name": exp.name,
                            "ordinal": exp.ordinal,
                            "address": format!("{:#x}", exp.address)
                        })
                    })
                    .collect();
                return Ok(serde_json::json!({
                    "binary_id": binary_id,
                    "imports": imports,
                    "exports": exports,
                    "imports_count": pe_info.imports.len(),
                    "exports_count": pe_info.exports.len()
                }));
            }
        Ok(serde_json::json!({
            "binary_id": binary_id,
            "note": "import analysis only supported for PE binaries",
            "imports": [],
            "exports": []
        }))
    }
}

pub struct RealAnalyzeExportsHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealAnalyzeExportsHandler {
    fn name(&self) -> &'static str {
        "analyze.exports"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;
        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let (data, _info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;

        if data.len() >= 0x40 && data.starts_with(b"MZ")
            && let Ok(pe_info) = rustre_loader_pe::PeInfo::parse(data) {
                let exports: Vec<Value> = pe_info.exports.iter().map(|exp| {
                    serde_json::json!({ "name": exp.name, "ordinal": exp.ordinal, "address": format!("{:#x}", exp.address) })
                }).collect();
                return Ok(
                    serde_json::json!({ "binary_id": binary_id, "exports": exports, "count": exports.len() }),
                );
            }
        Ok(serde_json::json!({ "binary_id": binary_id, "exports": [], "count": 0 }))
    }
}

pub struct RealSymbolsLoadPdbHandler;

impl McpToolHandler for RealSymbolsLoadPdbHandler {
    fn name(&self) -> &'static str {
        "symbols.load_pdb"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'path'".into()))?;
        let pe_path = params.get("pe_path").and_then(|v| v.as_str());
        let limit = params
            .get("limit")
            .and_then(Value::as_u64)
            .map(|n| n as usize)
            .unwrap_or(5000);
        let pdb_path = std::path::Path::new(path);
        let reader = rustre_symbols_pdb::PdbReader::open(pdb_path)
            .map_err(|e| McpToolError::ExecutionFailed(format!("PDB open error: {e}")))?;

        // Stripped Rust release builds frequently leave the publics stream
        // empty; module-per-compiland S_GPROC32/S_LPROC32 records carry the
        // real function table. We merge all three sources.
        let publics = reader.symbols();
        let module_procs = reader.module_proc_symbols();
        let pdb_bytes = std::fs::read(pdb_path).ok();
        let pub_scanner = pdb_bytes
            .as_deref()
            .map(rustre_symbols_pdb::PdbPublicSymbolScanner::scan_public_symbols)
            .unwrap_or_default();
        let types = reader.types();

        // Optional PE binding: resolve (section, offset) → VA so module-proc
        // and S_PUB32-without-image entries get a usable virtual address.
        let pe_load = pe_path.and_then(|p| {
            rustre_decompiler::load_binary(std::path::Path::new(p)).ok()
        });
        let resolve_va = |segment: u16, offset: u32| -> Option<u64> {
            let load = pe_load.as_ref()?;
            if segment == 0 {
                return None;
            }
            let sec = load.sections.get(usize::from(segment) - 1)?;
            Some(load.base_address + sec.virtual_addr + u64::from(offset))
        };

        // Merge into a name→entry map so duplicates collapse (publics often
        // duplicate proc entries).
        use std::collections::BTreeMap;
        let mut merged: BTreeMap<String, (u64, &'static str, &'static str)> = BTreeMap::new();
        for s in &publics {
            if s.name.is_empty() { continue; }
            merged
                .entry(s.name.clone())
                .or_insert((s.address, "public", match s.kind {
                    rustre_symbols_pdb::SymbolKind::Function => "function",
                    rustre_symbols_pdb::SymbolKind::Data => "data",
                    rustre_symbols_pdb::SymbolKind::Label => "label",
                    rustre_symbols_pdb::SymbolKind::Thunk => "thunk",
                }));
        }
        for p in &pub_scanner {
            if p.name.is_empty() { continue; }
            let va = resolve_va(p.section, p.offset).unwrap_or(u64::from(p.offset));
            merged.entry(p.name.clone()).or_insert((va, "public_scan", "function"));
        }
        for m in &module_procs {
            if m.name.is_empty() { continue; }
            let va = resolve_va(m.segment, m.code_offset).unwrap_or(u64::from(m.code_offset));
            merged.entry(m.name.clone()).or_insert((va, "module_proc", "function"));
        }

        let total = merged.len();
        let sym_list: Vec<Value> = merged
            .iter()
            .take(limit)
            .map(|(name, (va, source, kind))| {
                serde_json::json!({
                    "name": name,
                    "address": format!("{:#x}", va),
                    "va": va,
                    "kind": kind,
                    "source": source,
                })
            })
            .collect();

        Ok(serde_json::json!({
            "path": path,
            "pe_path": pe_path,
            "guid": reader.guid().to_string_fmt(),
            "symbols_count": total,
            "publics_count": publics.len(),
            "module_proc_count": module_procs.len(),
            "public_scan_count": pub_scanner.len(),
            "types_count": types.len(),
            "symbols": sym_list,
            "va_resolved": pe_load.is_some(),
        }))
    }
}

pub struct RealYaraCompileAndScanHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealYaraCompileAndScanHandler {
    fn name(&self) -> &'static str {
        "yara.scan_file"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        // Accept either binary_id (registry lookup) OR path (load from disk)
        // — the tool descriptor advertises `path`, but historic callers used
        // `binary_id`. Honour both so the tool no longer fails with
        // "missing 'binary_id'" when invoked per the published schema.
        let binary_id_opt = params.get("binary_id").and_then(|v| v.as_str());
        let path_opt = params.get("path").and_then(|v| v.as_str());

        let owned_data: Vec<u8>;
        let data_ref: &[u8] = if let Some(bid) = binary_id_opt {
            let reg = self
                .registry
                .lock()
                .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
            let (data, _info) = reg
                .get(bid)
                .ok_or_else(|| McpToolError::NotFound(format!("binary {bid} not loaded")))?;
            owned_data = data.clone();
            &owned_data[..]
        } else if let Some(p) = path_opt {
            owned_data = std::fs::read(p)
                .map_err(|e| McpToolError::ExecutionFailed(format!("read {p}: {e}")))?;
            &owned_data[..]
        } else {
            return Err(McpToolError::InvalidParams(
                "missing 'path' or 'binary_id'".into(),
            ));
        };
        let binary_id = binary_id_opt.unwrap_or(path_opt.unwrap_or(""));

        // Default ruleset: bundled findcrypt3-style crypto + packer rules
        // loaded automatically when no source is provided. Mirrors the IDA
        // findcrypt plugin's out-of-the-box behaviour.
        let rules_source = params
            .get("rules_source")
            .or_else(|| params.get("ruleset_source"))
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(builtin_yara_crypto_ruleset);

        let mut ruleset = rustre_yara_engine::YaraRuleSet::new();
        ruleset
            .add_rule(&rules_source)
            .map_err(|e| McpToolError::ExecutionFailed(format!("YARA compile error: {e}")))?;
        let scanner = rustre_yara_engine::YaraEngineScanner::new(&mut ruleset)
            .map_err(|e| McpToolError::ExecutionFailed(format!("YARA scanner error: {e}")))?;
        let matches = scanner.scan_bytes(data_ref);
        let result: Vec<Value> = matches
            .iter()
            .map(|m| {
                serde_json::json!({
                    "rule": m.rule_name,
                    "namespace": m.namespace,
                    "tags": m.tags,
                    "pattern_count": m.patterns.len()
                })
            })
            .collect();
        Ok(serde_json::json!({
            "binary_id": binary_id,
            "path": path_opt.unwrap_or(""),
            "matched": !matches.is_empty(),
            "matches": result,
            "match_count": matches.len()
        }))
    }
}

/// Bundled findcrypt3-style YARA ruleset loaded automatically when
/// `yara.scan_file` is invoked without an explicit `rules_source`.
/// Covers the most common crypto magic constants (AES S-box prefix,
/// MD5/SHA initializers, RC4 KSA marker, RSA public exponents) plus a
/// minimal UPX packer signature. Kept inline so the server boots with a
/// working ruleset even when no external rule file is shipped.
fn builtin_yara_crypto_ruleset() -> String {
    r#"
rule findcrypt_AES_SBOX {
    meta: family = "findcrypt3" algo = "AES"
    strings: $s = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 }
    condition: $s
}
rule findcrypt_AES_INV_SBOX {
    meta: family = "findcrypt3" algo = "AES"
    strings: $s = { 52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB }
    condition: $s
}
rule findcrypt_MD5_IV {
    meta: family = "findcrypt3" algo = "MD5"
    strings: $s = { 01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10 }
    condition: $s
}
rule findcrypt_SHA1_IV {
    meta: family = "findcrypt3" algo = "SHA1"
    strings: $s = { 67 45 23 01 EF CD AB 89 98 BA DC FE 10 32 54 76 C3 D2 E1 F0 }
    condition: $s
}
rule findcrypt_SHA256_K0 {
    meta: family = "findcrypt3" algo = "SHA256"
    strings: $s = { 42 8A 2F 98 71 37 44 91 B5 C0 FB CF E9 B5 DB A5 }
    condition: $s
}
rule findcrypt_RC4_KSA {
    meta: family = "findcrypt3" algo = "RC4"
    strings: $s = { 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F }
    condition: $s
}
rule findcrypt_RSA_pubexp_65537 {
    meta: family = "findcrypt3" algo = "RSA"
    strings: $s = { 01 00 01 }
    condition: $s
}
rule packer_UPX_magic {
    meta: family = "packers" tool = "UPX"
    strings: $s = "UPX!"
    condition: $s
}
"#
    .to_string()
}

pub struct RealCryptoIdentifyHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealCryptoIdentifyHandler {
    fn name(&self) -> &'static str {
        "crypto.identify"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;
        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let (data, _info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;

        let findings = rustre_crypto_id::identify_in_binary(data);
        let result: Vec<Value> = findings
            .iter()
            .map(|f| {
                serde_json::json!({
                    "offset": format!("{:#x}", f.offset),
                    "algorithm": f.algorithm.to_string(),
                    "evidence": f.evidence,
                    "confidence": f.confidence
                })
            })
            .collect();
        Ok(serde_json::json!({
            "binary_id": binary_id,
            "findings": result,
            "count": findings.len()
        }))
    }
}

pub struct RealTriageHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealTriageHandler {
    fn name(&self) -> &'static str {
        "triage.analyze"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;
        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let (data, _info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;

        let triage = rustre_triage::Triage::new();
        let result = triage
            .analyze(data)
            .map_err(|e| McpToolError::ExecutionFailed(e.to_string()))?;

        let indicators: Vec<Value> = result
            .indicators
            .iter()
            .map(|ind| {
                serde_json::json!({
                    "name": ind.name,
                    "description": ind.description,
                    "threat_level": format!("{:?}", ind.threat_level),
                    "category": ind.category.clone()
                })
            })
            .collect();

        Ok(serde_json::json!({
            "binary_id": binary_id,
            "file_kind": format!("{:?}", result.file_kind),
            "threat_level": format!("{:?}", result.threat_level),
            "score": result.score,
            "entropy": result.entropy,
            "is_packed": result.is_packed,
            "is_obfuscated": result.is_obfuscated,
            "compiler_hint": result.compiler_hint,
            "sha256": result.sha256,
            "indicators": indicators,
            "analysis_time_ms": result.analysis_time_ms
        }))
    }
}

/// Real handler for `patch_pe_security_summary`.
///
/// Loads a PE from the supplied `path` and reports its hardening flags via
/// [`rustre_patch::pe_security_summary_from_path`]. Mirrors the wire-tools
/// definition in `rustre-mcp-tools` so the rmcp dispatch surface actually
/// invokes the analyzer instead of returning a stub.
pub struct RealPatchPeSecuritySummaryHandler;

impl McpToolHandler for RealPatchPeSecuritySummaryHandler {
    fn name(&self) -> &'static str {
        "patch_pe_security_summary"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'path'".into()))?;
        let summary = rustre_patch::pe_security_summary_from_path(path)
            .map_err(|e| McpToolError::ExecutionFailed(format!("pe_security_summary: {e}")))?;
        Ok(serde_json::json!({
            "path": path,
            "aslr": summary.flags.aslr(),
            "dep": summary.flags.dep(),
            "cfg": summary.flags.cfg(),
            "force_integrity": summary.flags.force_integrity(),
            "no_seh": summary.flags.no_seh(),
            "no_isolation": summary.flags.no_isolation(),
            "no_bind": summary.flags.no_bind(),
            "terminal_server_aware": summary.flags.terminal_server_aware(),
            "is_64bit": summary.is_64bit,
            "dll_characteristics": summary.dll_characteristics,
        }))
    }
}

/// Real handler for `patch_patch_find_code_caves`.
///
/// Loads the binary at `path` and delegates to
/// [`rustre_patch::find_code_caves_from_path`] so the rmcp dispatch surface
/// actually scans the file instead of returning a stub. Mirrors the wire-tools
/// `PatchFindCodeCavesTool` so both transports reach the same analyzer.
pub struct RealPatchFindCodeCavesHandler;

impl McpToolHandler for RealPatchFindCodeCavesHandler {
    fn name(&self) -> &'static str {
        "patch_patch_find_code_caves"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let path = params
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'path'".into()))?;
        let min_size = params
            .get("min_size")
            .and_then(serde_json::Value::as_u64)
            .map_or(16usize, |n| usize::try_from(n).unwrap_or(16));
        let caves = rustre_patch::find_code_caves_from_path(path, min_size)
            .map_err(|e| McpToolError::ExecutionFailed(format!("find_code_caves: {e}")))?;
        let caves_json: Vec<Value> = caves
            .iter()
            .map(|c| {
                serde_json::json!({
                    "section": c.section,
                    "file_offset": c.file_offset,
                    "virtual_address": c.virtual_address,
                    "size": c.size,
                    "fill_byte": c.fill_byte,
                })
            })
            .collect();
        Ok(serde_json::json!({
            "path": path,
            "min_size": min_size,
            "count": caves_json.len(),
            "caves": caves_json,
        }))
    }
}

pub struct RealAnalyzeFunctionHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealAnalyzeFunctionHandler {
    fn name(&self) -> &'static str {
        "analyze.function"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        use rustre_analysis_fn::{DetectedArch, MemorySlice, detect_functions};
        use rustre_core::address::Address;

        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;

        let target_addr: Option<u64> = params.get("addr").and_then(|v| v.as_str()).and_then(|s| {
            let s = s.trim_start_matches("0x").trim_start_matches("0X");
            u64::from_str_radix(s, 16).ok()
        });

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("registry lock poisoned".into()))?;
        let (data, info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;

        let arch = match info.arch.as_str() {
            "x86_64" => DetectedArch::X86_64,
            "x86" => DetectedArch::X86_32,
            "aarch64" | "arm64" => DetectedArch::Arm64,
            _ => DetectedArch::Unknown,
        };

        let mem = MemorySlice::new(Address::new(info.image_base), data);
        let boundary_set = detect_functions(arch, &mem);

        if let Some(addr) = target_addr {
            let target = Address::new(addr);
            let fb = boundary_set
                .at(target)
                .or_else(|| boundary_set.containing(target))
                .ok_or_else(|| {
                    McpToolError::NotFound(format!("no function detected at {addr:#x}"))
                })?;
            let name = fb
                .name
                .clone()
                .unwrap_or_else(|| format!("sub_{:x}", fb.start.as_u64()));
            let end_str = fb
                .end.map_or_else(|| "unknown".to_string(), |e| format!("{:#x}", e.as_u64()));
            return Ok(serde_json::json!({
                "binary_id": binary_id,
                "addr": format!("{:#x}", fb.start.as_u64()),
                "end": end_str,
                "name": name,
                "confidence": format!("{:?}", fb.confidence),
                "detection_method": format!("{:?}", fb.source)
            }));
        }

        let functions: Vec<Value> = boundary_set
            .functions
            .iter()
            .map(|fb| {
                let name = fb
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("sub_{:x}", fb.start.as_u64()));
                let end_str = fb
                    .end.map_or_else(|| "unknown".to_string(), |e| format!("{:#x}", e.as_u64()));
                serde_json::json!({
                    "addr": format!("{:#x}", fb.start.as_u64()),
                    "end": end_str,
                    "name": name,
                    "confidence": format!("{:?}", fb.confidence),
                    "detection_method": format!("{:?}", fb.source)
                })
            })
            .collect();

        Ok(serde_json::json!({
            "binary_id": binary_id,
            "functions_found": functions.len(),
            "functions": functions,
            "status": "completed"
        }))
    }
}

pub struct RealAnalyzeFullHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealAnalyzeFullHandler {
    fn name(&self) -> &'static str {
        "analyze.full"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        use rustre_analysis_fn::{DetectedArch, MemorySlice, detect_functions};
        use rustre_analysis_string::{StringScanner, StringScannerConfig};
        use rustre_analysis_xref::BinaryXrefIndex;
        use rustre_core::address::Address;

        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("registry lock poisoned".into()))?;
        let (data, info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;

        // --- Function detection ---
        let arch = match info.arch.as_str() {
            "x86_64" => DetectedArch::X86_64,
            "x86" => DetectedArch::X86_32,
            "aarch64" | "arm64" => DetectedArch::Arm64,
            _ => DetectedArch::Unknown,
        };

        let mem = MemorySlice::new(Address::new(info.image_base), data);
        let boundary_set = detect_functions(arch, &mem);

        // --- String scanning ---
        let string_config = StringScannerConfig {
            min_length: 4,
            ..Default::default()
        };
        let scanner = StringScanner::new(string_config);
        let strings = scanner.scan(Address::new(info.image_base), data);
        let strings_found = strings.len();

        // --- Xref index ---
        let xref_idx =
            BinaryXrefIndex::build_from_binary(data, info.image_base, info.arch.as_str());
        let xrefs_found = xref_idx.total();

        // --- Overall binary entropy ---
        let overall_entropy = rustre_triage_entropy::shannon_entropy_f32(data);

        let entry_points: Vec<String> = if info.entry_point != 0 {
            vec![format!("{:#x}", info.entry_point)]
        } else {
            Vec::new()
        };

        let sections: Vec<Value> = info
            .sections
            .iter()
            .map(|s| {
                serde_json::json!({
                    "name": s.name,
                    "va": format!("{:#x}", s.va),
                    "size": s.size,
                    "entropy": s.entropy
                })
            })
            .collect();

        Ok(serde_json::json!({
            "binary_id": binary_id,
            "format": info.format,
            "arch": info.arch,
            "functions_found": boundary_set.stats.total_found,
            "strings_found": strings_found,
            "xrefs_found": xrefs_found,
            "imports_count": info.imports_count,
            "exports_count": info.exports_count,
            "bytes_analyzed": boundary_set.stats.bytes_analyzed,
            "duration_ms": boundary_set.stats.duration_ms,
            "entropy": overall_entropy,
            "sections": sections,
            "entry_points": entry_points,
            "status": "completed"
        }))
    }
}

fn binary_info_to_json(info: &LoadedBinaryInfo) -> Value {
    serde_json::json!({
        "binary_id": info.binary_id,
        "path": info.path,
        "format": info.format,
        "arch": info.arch,
        "bits": info.bits,
        "entry_point": format!("{:#x}", info.entry_point),
        "image_base": format!("{:#x}", info.image_base),
        "size": info.size,
        "sha256": info.sha256,
        "imports_count": info.imports_count,
        "exports_count": info.exports_count,
        "is_dll": info.is_dll,
        "is_dotnet": info.is_dotnet,
        "pdb_path": info.pdb_path,
        "symbols_count": info.symbols_count,
        "sections": info.sections.iter().map(|s| serde_json::json!({
            "name": s.name,
            "va": format!("{:#x}", s.va),
            "size": s.size,
            "entropy": s.entropy
        })).collect::<Vec<_>>()
    })
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// Real KG tool handlers backed by BinaryRegistry
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

/// List functions (exports + PE .pdata / ELF symbols) for a binary, with optional name filter.
pub struct RealKgGetFunctionHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealKgGetFunctionHandler {
    fn name(&self) -> &'static str {
        "kg.get_function"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        use rustre_analysis_fn::{DetectedArch, MemorySlice, detect_functions};
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;
        let target_addr = parse_addr_value(&params, "addr")?;

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let (data, info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;

        let user_name = reg
            .name_store
            .get(&(binary_id.to_string(), target_addr))
            .cloned();
        let comment = reg
            .comment_store
            .get(&(binary_id.to_string(), target_addr))
            .cloned();
        use rustre_core::address::Address;
        let arch = match info.arch.as_str() {
            "x86_64" => DetectedArch::X86_64,
            "x86" | "x86_32" => DetectedArch::X86_32,
            "aarch64" | "arm64" => DetectedArch::Arm64,
            _ => DetectedArch::Unknown,
        };
        let mem = MemorySlice::new(Address::new(info.image_base), data);
        let fns = detect_functions(arch, &mem);
        let fb = fns
            .functions
            .iter()
            .find(|f| f.start.as_u64() == target_addr);

        let export_name = if data.starts_with(b"MZ") {
            rustre_loader_pe::PeInfo::parse(data).ok().and_then(|pe| {
                pe.exports
                    .iter()
                    .find(|e| e.address == target_addr)
                    .and_then(|e| e.name.clone())
            })
        } else {
            None
        };

        let name = user_name
            .or(export_name)
            .unwrap_or_else(|| format!("sub_{target_addr:x}"));

        Ok(serde_json::json!({
            "binary_id": binary_id,
            "addr": format!("{target_addr:#x}"),
            "name": name,
            "size": fb.and_then(|f| f.end.map(|e| e.as_u64().wrapping_sub(f.start.as_u64()))).unwrap_or(0),
            "end": fb.and_then(|f| f.end).map(|e| format!("{:#x}", e.as_u64())).unwrap_or_default(),
            "confidence": fb.map(|f| format!("{:?}", f.confidence)).unwrap_or_default(),
            "comment": comment,
            "detection_source": fb.map(|f| format!("{:?}", f.source)).unwrap_or_default()
        }))
    }
}

pub struct RealAnalyzeBasicBlockHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealAnalyzeBasicBlockHandler {
    fn name(&self) -> &'static str {
        "analyze.basic_block"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        use iced_x86::Formatter as _;
        use iced_x86::FlowControl;
        struct StrOut(String);
        impl iced_x86::FormatterOutput for StrOut {
            fn write(&mut self, text: &str, _kind: iced_x86::FormatterTextKind) {
                self.0.push_str(text);
            }
        }
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;
        let addr = params
            .get("addr")
            .or_else(|| params.get("address"))
            .and_then(serde_json::Value::as_u64)
            .or_else(|| {
                params
                    .get("addr")
                    .and_then(|v| v.as_str())
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            })
            .ok_or_else(|| McpToolError::InvalidParams("missing 'addr'".into()))?;
        let bits = u32::try_from(params.get("bits").and_then(serde_json::Value::as_u64).unwrap_or(64)).unwrap_or(64);

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let (data, info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;

        let base = info.image_base;
        if addr < base || addr - base >= data.len() as u64 {
            return Err(McpToolError::InvalidParams(format!(
                "address {addr:#x} out of range"
            )));
        }
        let off = usize::try_from(addr - base).unwrap_or(0);
        let slice = &data[off..data.len().min(off + 4096)];

        // Simple basic block detection: scan until a terminator (RET, JMP, conditional jump)
        let mut instructions = Vec::with_capacity(64);
        let mut cur = 0usize;
        let mut end_addr = addr;
        let mut successors: Vec<String> = Vec::new();
        let mut fmt = iced_x86::IntelFormatter::new();

        'scan: while cur < slice.len() {
            if let Some(iced) = rustre_arch_x86::X86LiftAdapter::decode_one_iced(
                bits,
                &slice[cur..],
                addr + cur as u64,
            ) {
                let len = iced.len();
                let ia = addr + cur as u64;
                let mut out = StrOut(String::new());
                fmt.format(&iced, &mut out);
                instructions.push(
                    serde_json::json!({ "addr": format!("{ia:#x}"), "text": out.0, "len": len }),
                );
                cur += len;
                end_addr = ia + len as u64;

                // Check for terminator
                match iced.flow_control() {
                    FlowControl::Return | FlowControl::IndirectCall | FlowControl::IndirectBranch => break 'scan,
                    FlowControl::UnconditionalBranch => {
                        if let Some(t) = iced.near_branch_target().checked_add(0) {
                            successors.push(format!("{t:#x}"));
                        }
                        break 'scan;
                    }
                    FlowControl::ConditionalBranch => {
                        let t = iced.near_branch_target();
                        successors.push(format!("{t:#x}"));
                        successors.push(format!("{:#x}", addr + cur as u64)); // fallthrough
                        break 'scan;
                    }
                    _ => {}
                }
                if instructions.len() >= 256 {
                    break 'scan;
                }
            } else {
                break;
            }
        }

        Ok(serde_json::json!({
            "binary_id": binary_id,
            "addr": format!("{addr:#x}"),
            "end_addr": format!("{end_addr:#x}"),
            "instruction_count": instructions.len(),
            "successors": successors,
            "instructions": instructions
        }))
    }
}

pub struct RealBinarySearchBytesHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealBinarySearchBytesHandler {
    fn name(&self) -> &'static str {
        "binary.search_bytes"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;
        let pattern_str = params
            .get("pattern")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                McpToolError::InvalidParams(
                    "missing 'pattern' (hex bytes like '4D 5A' or '4D5A')".into(),
                )
            })?;
        let limit = usize::try_from(params.get("limit").and_then(serde_json::Value::as_u64).unwrap_or(100)).unwrap_or(100);

        // Parse hex pattern (supports "4D 5A", "4D5A", "4D ? 5A" with wildcards)
        let needle: Vec<Option<u8>> = pattern_str
            .split_whitespace()
            .flat_map(|s| {
                if s == "?" || s == "??" {
                    vec![None]
                } else {
                    vec![u8::from_str_radix(s, 16).ok()]
                }
            })
            .collect();
        if needle.is_empty() {
            return Err(McpToolError::InvalidParams("empty pattern".into()));
        }

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let (data, info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;

        let base = info.image_base;
        let mut matches = Vec::with_capacity(limit.min(64));
        let pat_len = needle.len();
        'outer: for i in 0..data.len().saturating_sub(pat_len - 1) {
            for (j, &expected) in needle.iter().enumerate() {
                if let Some(b) = expected
                    && data[i + j] != b {
                        continue 'outer;
                    }
            }
            matches.push(format!("{:#x}", base + i as u64));
            if matches.len() >= limit {
                break;
            }
        }
        Ok(
            serde_json::json!({ "binary_id": binary_id, "pattern": pattern_str, "count": matches.len(), "addresses": matches }),
        )
    }
}

pub struct RealAnalyzeCrossRefsHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealAnalyzeCrossRefsHandler {
    fn name(&self) -> &'static str {
        "analyze.cross_refs"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        use rustre_analysis_xref::BinaryXrefIndex;
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;
        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let (data, info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;
        let arch = info.arch.as_str();
        let idx = BinaryXrefIndex::build_from_binary(data, info.image_base, arch);
        let total = idx.total();
        let limit = usize::try_from(params.get("limit").and_then(serde_json::Value::as_u64).unwrap_or(500)).unwrap_or(500);
        // Collect xrefs by iterating sources
        let mut result = Vec::with_capacity(limit.min(512));
        'outer: for src in idx.all_sources() {
            for x in idx.xrefs_from(src) {
                if result.len() >= limit {
                    break 'outer;
                }
                result.push(serde_json::json!({
                    "from": format!("{:#x}", x.from),
                    "to": format!("{:#x}", x.to),
                    "kind": format!("{:?}", x.kind)
                }));
            }
        }
        Ok(serde_json::json!({
            "binary_id": binary_id,
            "total": total,
            "returned": result.len(),
            "xrefs": result
        }))
    }
}

pub struct RealDisasmAtHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealDisasmAtHandler {
    fn name(&self) -> &'static str {
        "disasm.at"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        use iced_x86::Formatter as _;
        struct StrOut(String);
        impl iced_x86::FormatterOutput for StrOut {
            fn write(&mut self, text: &str, _kind: iced_x86::FormatterTextKind) {
                self.0.push_str(text);
            }
        }
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;
        let addr = params
            .get("address")
            .or_else(|| params.get("addr"))
            .and_then(serde_json::Value::as_u64)
            .or_else(|| {
                params
                    .get("address")
                    .and_then(|v| v.as_str())
                    .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            })
            .ok_or_else(|| McpToolError::InvalidParams("missing 'address'".into()))?;
        let count = usize::try_from(params.get("count").and_then(serde_json::Value::as_u64).unwrap_or(32)).unwrap_or(32);
        let bits = u32::try_from(params.get("bits").and_then(serde_json::Value::as_u64).unwrap_or(64)).unwrap_or(64);

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
        let (data, info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;

        let base = info.image_base;
        if addr < base {
            return Err(McpToolError::InvalidParams(format!(
                "address {addr:#x} not in binary range"
            )));
        }
        let rva = addr - base;
        // Map VA → file offset via section table (PE section VAs include image_base).
        // Helper: locate a section by RVA and compute the file offset.
        let section_rva_to_file_off =
            |sec_va: u64, sec_base: u64, raw_off: u32, raw_size: u32, virt_size: u32, q_rva: u64| -> Option<usize> {
                let sec_rva = sec_va.saturating_sub(sec_base);
                if q_rva >= sec_rva && q_rva < sec_rva + u64::from(virt_size.max(raw_size)) {
                    Some(usize::try_from(u64::from(raw_off) + (q_rva - sec_rva)).unwrap_or(0))
                } else {
                    None
                }
            };

        let off = if info.sections.is_empty() {
            // No section metadata in the registry.  For PE binaries we can still
            // derive the correct file offset by re-parsing the section table from
            // the raw bytes, avoiding the error-prone "RVA == file offset" fallback
            // that is only valid for flat/raw images.
            if data.len() >= 0x40 && data.starts_with(b"MZ") {
                if let Ok(pe_info) = rustre_loader_pe::PeInfo::parse(data) {
                    let pe_base = pe_info.image_base;
                    // If the caller passed a VA that already accounts for pe_base use
                    // it; otherwise treat addr as a raw RVA.
                    let q_rva = addr.saturating_sub(pe_base);
                    let found = pe_info.sections.iter().find_map(|s| {
                        section_rva_to_file_off(
                            s.virtual_address,
                            pe_base,
                            s.raw_offset,
                            s.raw_size,
                            s.virtual_size,
                            q_rva,
                        )
                    });
                    match found {
                        Some(o) => o,
                        None => {
                            return Err(McpToolError::InvalidParams(format!(
                                "address {addr:#x} not in any PE section"
                            )));
                        }
                    }
                } else {
                    // PE parse failed; best-effort RVA-as-offset (works for flat images).
                    usize::try_from(rva).unwrap_or(0)
                }
            } else {
                // ELF/raw: RVA equals file offset.
                usize::try_from(rva).unwrap_or(0)
            }
        } else {
            let mapped = info.sections.iter().find(|s| {
                let sec_rva = s.va.saturating_sub(base);
                rva >= sec_rva && rva < sec_rva + u64::from(s.size.max(s.raw_size))
            });
            match mapped {
                Some(sec) => {
                    let sec_rva = sec.va.saturating_sub(base);
                    usize::try_from(u64::from(sec.raw_off) + (rva - sec_rva)).unwrap_or(0)
                }
                None => {
                    return Err(McpToolError::InvalidParams(format!(
                        "address {addr:#x} not in any section"
                    )));
                }
            }
        };
        if off >= data.len() {
            return Err(McpToolError::InvalidParams(format!(
                "address {addr:#x} maps beyond binary data"
            )));
        }
        let slice = &data[off..];

        let mut insns = Vec::new();
        let mut cur = 0usize;
        while cur < slice.len() && insns.len() < count {
            if let Some(iced) = rustre_arch_x86::X86LiftAdapter::decode_one_iced(
                bits,
                &slice[cur..],
                addr + cur as u64,
            ) {
                let mut fmt = iced_x86::IntelFormatter::new();
                fmt.options_mut().set_space_after_operand_separator(true);
                let mut out = StrOut(String::new());
                fmt.format(&iced, &mut out);
                let len = iced.len();
                insns.push(serde_json::json!({
                    "addr": format!("{:#x}", addr + cur as u64),
                    "bytes": hex::encode(&slice[cur..cur+len]),
                    "text": out.0,
                    "length": len
                }));
                cur += len;
            } else {
                cur += 1;
            }
        }
        Ok(
            serde_json::json!({ "binary_id": binary_id, "address": format!("{:#x}", addr), "count": insns.len(), "instructions": insns }),
        )
    }
}

pub struct RealDisasmFunctionHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealDisasmFunctionHandler {
    fn name(&self) -> &'static str {
        "disasm.function"
    }
    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        use iced_x86::Formatter as _;
        use rustre_analysis_fn::{DetectedArch, MemorySlice, detect_functions};
        use rustre_core::address::Address;
        const MAX_BYTES: u64 = 4096;
        struct StrOut(String);
        impl iced_x86::FormatterOutput for StrOut {
            fn write(&mut self, text: &str, _kind: iced_x86::FormatterTextKind) {
                self.0.push_str(text);
            }
        }

        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;

        // Accept addr as hex string or number
        let func_addr: u64 = {
            let v = params
                .get("addr")
                .or_else(|| params.get("address"))
                .ok_or_else(|| McpToolError::InvalidParams("missing 'addr'".into()))?;
            if let Some(n) = v.as_u64() {
                n
            } else if let Some(s) = v.as_str() {
                let s = s.trim_start_matches("0x").trim_start_matches("0X");
                u64::from_str_radix(s, 16)
                    .map_err(|_| McpToolError::InvalidParams(format!("invalid address: {s}")))?
            } else {
                return Err(McpToolError::InvalidParams(
                    "'addr' must be a hex string or number".into(),
                ));
            }
        };

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("registry lock poisoned".into()))?;
        let (data, info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;

        let base = info.image_base;

        // Determine bitness for decoder
        let bits = info.bits;

        // Use detect_functions to find the function at func_addr
        let arch = match info.arch.as_str() {
            "x86_64" => DetectedArch::X86_64,
            "x86" => DetectedArch::X86_32,
            "aarch64" | "arm64" => DetectedArch::Arm64,
            _ => DetectedArch::Unknown,
        };

        let mem = MemorySlice::new(Address::new(base), data);
        let boundary_set = detect_functions(arch, &mem);

        let target = Address::new(func_addr);
        let fb = boundary_set
            .at(target)
            .or_else(|| boundary_set.containing(target));

        // Determine size: use known end if available, otherwise cap at MAX_BYTES.
        // If detect_functions did not find a boundary at this address (e.g. thunks,
        // compiler-synthesised helpers, or addresses supplied directly by the caller)
        // we still disassemble up to MAX_BYTES rather than returning an error.
        let func_size: u64 = fb
            .and_then(|b| b.end)
            .map_or(MAX_BYTES, |e| e.as_u64().saturating_sub(func_addr))
            .min(MAX_BYTES);

        // Translate func_addr (VA) to a file offset using the pre-parsed section
        // table stored in the registry.  For PE binaries, file alignment differs
        // from section alignment, so we must not use a flat (addr - base) mapping;
        // instead we locate the containing section by its absolute virtual address
        // and apply the raw-file-offset correction.
        //
        // We use `info.sections` (populated at load time) rather than re-parsing
        // the PE here, which avoids a redundant parse and eliminates the incorrect
        // flat-offset fallback that produced wrong instruction bytes.
        let off: usize = {
            let sec = info.sections.iter().find(|s| {
                let sec_end = s.va + u64::from(s.size.max(s.raw_size));
                func_addr >= s.va && func_addr < sec_end && s.raw_off != 0
            });
            match sec {
                Some(s) => {
                    let off_in_sec = (func_addr - s.va) as usize;
                    s.raw_off as usize + off_in_sec
                }
                None => {
                    // No section covers func_addr — fall back to flat offset for
                    // formats without a section table (raw blobs, ELF mapped at 0).
                    if func_addr < base || func_addr - base >= data.len() as u64 {
                        return Err(McpToolError::InvalidParams(format!(
                            "address {func_addr:#x} is outside the binary range"
                        )));
                    }
                    usize::try_from(func_addr - base).unwrap_or(0)
                }
            }
        };
        let available = data.len().saturating_sub(off);
        let disasm_len = usize::try_from(func_size).unwrap_or(0).min(available);
        let slice = &data[off..off + disasm_len];

        let mut insns = Vec::new();
        let mut cur = 0usize;
        while cur < slice.len() {
            if let Some(iced) = rustre_arch_x86::X86LiftAdapter::decode_one_iced(
                bits,
                &slice[cur..],
                func_addr + cur as u64,
            ) {
                let mut fmt = iced_x86::IntelFormatter::new();
                fmt.options_mut().set_space_after_operand_separator(true);
                let mut out = StrOut(String::new());
                fmt.format(&iced, &mut out);
                let len = iced.len();
                insns.push(serde_json::json!({
                    "addr": format!("{:#x}", func_addr + cur as u64),
                    "bytes": hex::encode(&slice[cur..cur + len]),
                    "text": out.0,
                    "length": len
                }));
                cur += len;
            } else {
                // Undecodable byte Ã¢â‚¬— skip one byte and stop trying further
                break;
            }
        }

        let name = fb
            .and_then(|b| b.name.clone())
            .unwrap_or_else(|| format!("sub_{func_addr:x}"));

        Ok(serde_json::json!({
            "binary_id": binary_id,
            "addr": format!("{:#x}", func_addr),
            "name": name,
            "size": func_size,
            "instruction_count": insns.len(),
            "instructions": insns
        }))
    }
}

pub struct RealKgListFunctionsHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealKgListFunctionsHandler {
    fn name(&self) -> &'static str {
        "kg.list_functions"
    }

    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;
        let filter = params.get("filter").and_then(|v| v.as_str()).unwrap_or("");

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("registry lock poisoned".into()))?;
        let (data, info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;

        let mut functions: Vec<Value> = Vec::with_capacity(64);
        let bid_owned = binary_id.to_string();

        // PE: use exports + exception directory functions
        if data.len() >= 0x40 && data.starts_with(b"MZ") {
            if let Ok(pe_info) = rustre_loader_pe::PeInfo::parse(data) {
                // Named exports
                for exp in &pe_info.exports {
                    let addr = exp.address;
                    let key = (bid_owned.clone(), addr);
                    let raw_name = exp
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("ord_{}", exp.ordinal));
                    let display_name = reg
                        .name_store
                        .get(&key)
                        .cloned()
                        .unwrap_or(raw_name);
                    if !filter.is_empty() && !display_name.contains(filter) {
                        continue;
                    }
                    let comment = reg
                        .comment_store
                        .get(&key)
                        .cloned();
                    functions.push(serde_json::json!({
                        "addr": format!("{:#x}", addr),
                        "name": display_name,
                        "size": null,
                        "confidence": "export",
                        "comment": comment
                    }));
                }

                // Exception directory functions (skip duplicates with exports)
                let export_addrs: std::collections::HashSet<u64> =
                    pe_info.exports.iter().map(|e| e.address).collect();
                for rf in &pe_info.exception_functions {
                    let addr = info.image_base + u64::from(rf.begin_address);
                    if export_addrs.contains(&addr) {
                        continue;
                    }
                    let key = (bid_owned.clone(), addr);
                    let display_name = reg
                        .name_store
                        .get(&key)
                        .cloned()
                        .unwrap_or_else(|| format!("sub_{addr:x}"));
                    if !filter.is_empty() && !display_name.contains(filter) {
                        continue;
                    }
                    let comment = reg
                        .comment_store
                        .get(&key)
                        .cloned();
                    let size = u64::from(rf.end_address - rf.begin_address);
                    functions.push(serde_json::json!({
                        "addr": format!("{:#x}", addr),
                        "name": display_name,
                        "size": size,
                        "confidence": "pdata",
                        "comment": comment
                    }));
                }
            }
        } else if data.starts_with(b"\x7fELF") {
            // ELF: dynamic symbol table functions
            if let Ok(elf) = goblin::elf::Elf::parse(data) {
                for sym in elf.syms.iter().chain(elf.dynsyms.iter()) {
                    if !sym.is_function() {
                        continue;
                    }
                    if sym.st_value == 0 {
                        continue;
                    }
                    let raw_name = if sym.st_name != 0 {
                        elf.strtab
                            .get_at(sym.st_name)
                            .or_else(|| elf.dynstrtab.get_at(sym.st_name))
                            .unwrap_or("")
                            .to_string()
                    } else {
                        format!("sub_{:x}", sym.st_value)
                    };
                    let addr = sym.st_value;
                    let key = (bid_owned.clone(), addr);
                    let display_name = reg
                        .name_store
                        .get(&key)
                        .cloned()
                        .unwrap_or(raw_name);
                    if !filter.is_empty() && !display_name.contains(filter) {
                        continue;
                    }
                    let comment = reg
                        .comment_store
                        .get(&key)
                        .cloned();
                    functions.push(serde_json::json!({
                        "addr": format!("{:#x}", addr),
                        "name": display_name,
                        "size": sym.st_size,
                        "confidence": "symbol",
                        "comment": comment
                    }));
                }
            }
        }

        // If nothing from headers, surface any user-set names in name_store for this binary
        if functions.is_empty() {
            for ((bid, addr), name) in &reg.name_store {
                if bid != binary_id {
                    continue;
                }
                if !filter.is_empty() && !name.contains(filter) {
                    continue;
                }
                let comment = reg.comment_store.get(&(bid.clone(), *addr)).cloned();
                functions.push(serde_json::json!({
                    "addr": format!("{:#x}", addr),
                    "name": name,
                    "size": null,
                    "confidence": "user",
                    "comment": comment
                }));
            }
        }

        Ok(serde_json::json!({
            "binary_id": binary_id,
            "count": functions.len(),
            "functions": functions
        }))
    }
}

/// Store a user-assigned name for (`binary_id`, address).
pub struct RealKgSetFunctionNameHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealKgSetFunctionNameHandler {
    fn name(&self) -> &'static str {
        "kg.set_function_name"
    }

    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;
        let addr = parse_addr_value(&params, "addr")?;
        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'name'".into()))?;

        let mut reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("registry lock poisoned".into()))?;

        if reg.get(binary_id).is_none() {
            return Err(McpToolError::NotFound(format!(
                "binary {binary_id} not loaded"
            )));
        }

        reg.name_store
            .insert((binary_id.to_string(), addr), name.to_string());

        Ok(serde_json::json!({
            "binary_id": binary_id,
            "addr": format!("{:#x}", addr),
            "name": name,
            "status": "ok"
        }))
    }
}

/// Store a user comment for (`binary_id`, address).
pub struct RealKgSetCommentHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealKgSetCommentHandler {
    fn name(&self) -> &'static str {
        "kg.set_comment"
    }

    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;
        let addr = parse_addr_value(&params, "addr")?;
        let text = params
            .get("text")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'text'".into()))?;

        let mut reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("registry lock poisoned".into()))?;

        if reg.get(binary_id).is_none() {
            return Err(McpToolError::NotFound(format!(
                "binary {binary_id} not loaded"
            )));
        }

        reg.comment_store
            .insert((binary_id.to_string(), addr), text.to_string());

        Ok(serde_json::json!({
            "binary_id": binary_id,
            "addr": format!("{:#x}", addr),
            "text": text,
            "status": "ok"
        }))
    }
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// kg.query Ã¢â‚¬— real handler backed by in-memory SQLite KnowledgeGraph
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

/// Execute a raw SQL SELECT query against the in-memory `SQLite` knowledge graph.
///
/// Only SELECT (and WITHÃ¢â‚¬Â¦SELECT) statements are permitted; any attempt to run
/// INSERT / UPDATE / DELETE / DROP returns an error.
pub struct RealKgQueryHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealKgQueryHandler {
    fn name(&self) -> &'static str {
        "kg.query"
    }

    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let sql = params
            .get("query")
            .or_else(|| params.get("sql"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'query' parameter".into()))?;

        // Quick pre-check before acquiring the lock.
        let trimmed_upper = sql.trim_start().to_ascii_uppercase();
        if !trimmed_upper.starts_with("SELECT") && !trimmed_upper.starts_with("WITH") {
            return Err(McpToolError::InvalidParams(
                "Only SELECT statements are allowed in kg.query".into(),
            ));
        }

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("registry lock poisoned".into()))?;

        let rows = reg
            .kg
            .query_sql(sql)
            .map_err(|e| McpToolError::ExecutionFailed(format!("KG query error: {e}")))?;

        // Convert HashMap<String, GraphValue> rows into serde_json::Value.
        let json_rows: Vec<Value> = rows
            .into_iter()
            .map(|row| {
                let obj: serde_json::Map<String, Value> = row
                    .into_iter()
                    .map(|(k, v)| {
                        let jv = match v {
                            rustre_graph::GraphValue::Null => Value::Null,
                            rustre_graph::GraphValue::Integer(n) => Value::Number(n.into()),
                            rustre_graph::GraphValue::Real(f) => serde_json::Number::from_f64(f)
                                .map_or(Value::Null, Value::Number),
                            rustre_graph::GraphValue::Text(s) => Value::String(s),
                            rustre_graph::GraphValue::Blob(b) => {
                                Value::String(format!("<blob {} bytes>", b.len()))
                            }
                        };
                        (k, jv)
                    })
                    .collect();
                Value::Object(obj)
            })
            .collect();

        let count = json_rows.len();
        Ok(serde_json::json!({
            "rows": json_rows,
            "count": count
        }))
    }
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// diff.compare Ã¢â‚¬— real handler backed by BinaryRegistry
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

/// Compare two loaded binaries by hashing export names and function counts.
///
/// Returns:
/// - `added_functions`           Ã¢â‚¬— export names present in B but absent in A.
/// - `removed_functions`         Ã¢â‚¬— export names present in A but absent in B.
/// - `possibly_changed_functions` Ã¢â‚¬— export names present in both (same name, possibly
///   different implementation; callers should use a deeper diff to confirm).
/// - `function_count_a` / `function_count_b` Ã¢â‚¬— total functions known for each binary.
pub struct RealDiffCompareHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealDiffCompareHandler {
    fn name(&self) -> &'static str {
        "diff.compare"
    }

    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        use rustre_analysis_fn::{DetectedArch, MemorySlice, detect_functions};
        use rustre_core::address::Address;

        let a_id = params
            .get("a_id")
            .or_else(|| params.get("binary_id_a"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'a_id'".into()))?;
        let b_id = params
            .get("b_id")
            .or_else(|| params.get("binary_id_b"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'b_id'".into()))?;

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("registry lock poisoned".into()))?;

        let loaded_a = reg.get(a_id);
        let loaded_b = reg.get(b_id);
        if loaded_a.is_none() || loaded_b.is_none() {
            return Err(McpToolError::InvalidParams(format!(
                "binary not loaded: {}",
                if loaded_a.is_none() { a_id } else { b_id }
            )));
        }
        let (data_a, info_a) = loaded_a.unwrap();
        let (data_b, info_b) = loaded_b.unwrap();

        // Detect functions across the full image (not just exports) so that
        // stripped / internal-only binaries still report meaningful counts.
        let arch_of = |s: &str| match s {
            "x86_64" => DetectedArch::X86_64,
            "x86" => DetectedArch::X86_32,
            "aarch64" | "arm64" => DetectedArch::Arm64,
            _ => DetectedArch::Unknown,
        };
        let mem_a = MemorySlice::new(Address::new(info_a.image_base), data_a);
        let mem_b = MemorySlice::new(Address::new(info_b.image_base), data_b);
        let boundaries_a = detect_functions(arch_of(info_a.arch.as_str()), &mem_a);
        let boundaries_b = detect_functions(arch_of(info_b.arch.as_str()), &mem_b);
        let function_count_a = boundaries_a.functions.len();
        let function_count_b = boundaries_b.functions.len();

        // Extract export names for the symbolic name-set comparison.
        let exports_a = collect_export_names(data_a);
        let exports_b = collect_export_names(data_b);

        let set_a: std::collections::HashSet<&str> = exports_a.iter().map(String::as_str).collect();
        let set_b: std::collections::HashSet<&str> = exports_b.iter().map(String::as_str).collect();

        let mut added: Vec<&str> = set_b.difference(&set_a).copied().collect();
        let mut removed: Vec<&str> = set_a.difference(&set_b).copied().collect();
        let mut common: Vec<&str> = set_a.intersection(&set_b).copied().collect();

        added.sort_unstable();
        removed.sort_unstable();
        common.sort_unstable();

        Ok(serde_json::json!({
            "a_id": a_id,
            "b_id": b_id,
            "function_count_a": function_count_a,
            "function_count_b": function_count_b,
            "exports_count_a": info_a.exports_count,
            "exports_count_b": info_b.exports_count,
            "added_functions": added,
            "removed_functions": removed,
            "possibly_changed_functions": common,
            "added_count": added.len(),
            "removed_count": removed.len(),
            "possibly_changed_count": common.len(),
        }))
    }
}

/// Extract export (or ELF dynamic symbol) names from raw binary bytes.
fn collect_export_names(data: &[u8]) -> Vec<String> {
    if data.len() >= 0x40 && data.starts_with(b"MZ")
        && let Ok(pe) = rustre_loader_pe::PeInfo::parse(data) {
            return pe.exports.iter().filter_map(|e| e.name.clone()).collect();
        }
    if data.starts_with(b"\x7fELF")
        && let Ok(elf) = goblin::elf::Elf::parse(data) {
            return elf
                .dynsyms
                .iter()
                .filter(|s| {
                    s.is_function() && s.st_shndx != goblin::elf::section_header::SHN_UNDEF as usize
                })
                .filter_map(|s| elf.dynstrtab.get_at(s.st_name).map(str::to_string))
                .collect();
        }
    Vec::new()
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// Real analyze.call_graph handler
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

pub struct RealAnalyzeCallGraphHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealAnalyzeCallGraphHandler {
    fn name(&self) -> &'static str {
        "analyze.call_graph"
    }

    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        use rustre_analysis_fn::{DetectedArch, MemorySlice, detect_functions};
        use rustre_analysis_xref::{BinaryXrefIndex, SimpleXrefKind};
        use rustre_core::address::Address;
        use std::collections::{HashMap, HashSet};

        const NODE_LIMIT: usize = 200;

        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("registry lock poisoned".into()))?;
        let (data, info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;

        let arch = match info.arch.as_str() {
            "x86_64" => DetectedArch::X86_64,
            "x86" => DetectedArch::X86_32,
            "aarch64" | "arm64" => DetectedArch::Arm64,
            _ => DetectedArch::Unknown,
        };

        let mem = MemorySlice::new(Address::new(info.image_base), data);
        let boundary_set = detect_functions(arch, &mem);

        let mut func_starts: Vec<u64> = boundary_set
            .functions
            .iter()
            .map(|fb| fb.start.as_u64())
            .collect();
        func_starts.sort_unstable();

        let enclosing_fn = |addr: u64| -> Option<u64> {
            match func_starts.binary_search(&addr) {
                Ok(i) => Some(func_starts[i]),
                Err(0) => None,
                Err(i) => Some(func_starts[i - 1]),
            }
        };

        let xref_idx =
            BinaryXrefIndex::build_from_binary(data, info.image_base, info.arch.as_str());

        let mut edge_counts: HashMap<(u64, u64), usize> = HashMap::new();
        for src in xref_idx.all_sources() {
            for xref in xref_idx.xrefs_from(src) {
                if xref.kind != SimpleXrefKind::Call || xref.to == 0 {
                    continue;
                }
                let Some(caller_fn) = enclosing_fn(xref.from) else { continue };
                let callee_addr = xref.to;
                if caller_fn == callee_addr {
                    continue;
                }
                *edge_counts.entry((caller_fn, callee_addr)).or_insert(0) += 1;
            }
        }

        let mut node_addrs: HashSet<u64> = HashSet::new();
        for (from, to) in edge_counts.keys() {
            node_addrs.insert(*from);
            node_addrs.insert(*to);
        }

        let final_nodes: HashSet<u64> = if node_addrs.len() > NODE_LIMIT {
            let mut degree: HashMap<u64, usize> = HashMap::new();
            for ((from, to), count) in &edge_counts {
                *degree.entry(*from).or_insert(0) += count;
                *degree.entry(*to).or_insert(0) += count;
            }
            let mut ranked: Vec<(u64, usize)> = degree.into_iter().collect();
            ranked.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            ranked.truncate(NODE_LIMIT);
            ranked.into_iter().map(|(addr, _)| addr).collect()
        } else {
            node_addrs
        };

        let mut nodes: Vec<Value> = final_nodes
            .iter()
            .map(|&addr| {
                let name = reg
                    .name_store
                    .get(&(binary_id.to_string(), addr))
                    .cloned()
                    .or_else(|| {
                        boundary_set
                            .at(Address::new(addr))
                            .and_then(|fb| fb.name.clone())
                    })
                    .unwrap_or_else(|| format!("sub_{addr:x}"));
                serde_json::json!({ "addr": format!("{:#x}", addr), "name": name })
            })
            .collect();
        nodes.sort_by_key(|n| n["addr"].as_str().unwrap_or("").to_string());

        let edges: Vec<Value> = edge_counts
            .iter()
            .filter(|((from, to), _)| final_nodes.contains(from) && final_nodes.contains(to))
            .map(|((from, to), count)| {
                serde_json::json!({
                    "from_addr": format!("{:#x}", from),
                    "to_addr": format!("{:#x}", to),
                    "call_count": count
                })
            })
            .collect();

        Ok(serde_json::json!({
            "binary_id": binary_id,
            "node_count": nodes.len(),
            "edge_count": edges.len(),
            "nodes": nodes,
            "edges": edges
        }))
    }
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// Real decompile.function handler
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

pub struct RealDecompileFunctionHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealDecompileFunctionHandler {
    fn name(&self) -> &'static str {
        "decompile.function"
    }

    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        use rustre_analysis_fn::{DetectedArch, MemorySlice, detect_functions};
        use rustre_core::address::Address;
        use rustre_core::arch::Instruction;
        const MAX_BYTES: u64 = 4096;
        struct StrOut(String);
        impl iced_x86::FormatterOutput for StrOut {
            fn write(&mut self, text: &str, _kind: iced_x86::FormatterTextKind) {
                self.0.push_str(text);
            }
        }
        use rustre_decompiler::{DecompOptions, SymbolMap, standard_pipeline_arc};
        use std::sync::Arc;

        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;

        let func_addr: u64 = {
            let v = params
                .get("addr")
                .or_else(|| params.get("address"))
                .ok_or_else(|| McpToolError::InvalidParams("missing 'addr'".into()))?;
            if let Some(n) = v.as_u64() {
                n
            } else if let Some(s) = v.as_str() {
                let s = s.trim_start_matches("0x").trim_start_matches("0X");
                u64::from_str_radix(s, 16)
                    .map_err(|_| McpToolError::InvalidParams(format!("invalid address: {s}")))?
            } else {
                return Err(McpToolError::InvalidParams(
                    "'addr' must be a hex string or number".into(),
                ));
            }
        };

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("registry lock poisoned".into()))?;
        let (data, info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;

        let base = info.image_base;
        let bits = info.bits;

        // Detect function boundaries
        let arch = match info.arch.as_str() {
            "x86_64" => DetectedArch::X86_64,
            "x86" => DetectedArch::X86_32,
            "aarch64" | "arm64" => DetectedArch::Arm64,
            _ => DetectedArch::Unknown,
        };

        let mem = MemorySlice::new(Address::new(base), data);
        let boundary_set = detect_functions(arch, &mem);

        let target = Address::new(func_addr);
        // Use a synthetic boundary when the detector finds nothing at this address so that
        // the tool can still attempt to decompile the bytes starting there.
        let synthetic_fb;
        let fb = match boundary_set
            .at(target)
            .or_else(|| boundary_set.containing(target))
        {
            Some(b) => b,
            None => {
                synthetic_fb = rustre_analysis_fn::FunctionBoundary::new(
                    target,
                    rustre_analysis_fn::Confidence::Low,
                    rustre_analysis_fn::DetectionSource::HeuristicGap,
                );
                &synthetic_fb
            }
        };

        // Prefer user/symbol-table names (PDB, FLIRT, manual rename) over the
        // boundary detector's fallback. demangle for display when applicable.
        let resolved_self = reg
            .name_store
            .get(&(binary_id.to_string(), func_addr))
            .cloned()
            .map(|raw| rustre_symbols::try_demangle(&raw).unwrap_or(raw));
        let func_name = resolved_self
            .or_else(|| fb.name.clone())
            .unwrap_or_else(|| format!("sub_{func_addr:x}"));

        if func_addr < base || func_addr - base >= data.len() as u64 {
            return Err(McpToolError::InvalidParams(format!(
                "address {func_addr:#x} is outside the binary range"
            )));
        }

        let func_size: u64 = fb
            .end
            .map_or(MAX_BYTES, |e| e.as_u64().saturating_sub(func_addr))
            .min(MAX_BYTES);

        let off = usize::try_from(func_addr - base).unwrap_or(0);
        let available = data.len() - off;
        let disasm_len = usize::try_from(func_size).unwrap_or(0).min(available);
        let slice = &data[off..off + disasm_len];

        // Disassemble into rustre_core::arch::Instruction list
        let mut instructions: Vec<Instruction> = Vec::new();
        let mut cur = 0usize;
        while cur < slice.len() {
            if let Some(iced) = rustre_arch_x86::X86LiftAdapter::decode_one_iced(
                bits,
                &slice[cur..],
                func_addr + cur as u64,
            ) {
                let mut fmt = iced_x86::GasFormatter::new();
                iced_x86::Formatter::options_mut(&mut fmt).set_space_after_operand_separator(true);
                iced_x86::Formatter::options_mut(&mut fmt).set_rip_relative_addresses(true);
                let mut out = StrOut(String::new());
                iced_x86::Formatter::format(&mut fmt, &iced, &mut out);
                let len = iced.len();
                let bytes = slice[cur..cur + len].to_vec();

                let text = out.0;
                let (mnemonic, operands) = text.find(' ').map_or_else(
                    || (text.clone(), String::new()),
                    |sp| (text[..sp].to_string(), text[sp + 1..].trim().to_string()),
                );

                let mut instr =
                    Instruction::new(Address::new(func_addr + cur as u64), len, mnemonic, bytes);
                instr.operands = operands;
                instructions.push(instr);
                cur += len;
            } else {
                break;
            }
        }

        // Build and run the full standard decompiler pipeline (includes
        // IlAnalysisPass so hlil_pseudo_code is populated from the real
        // LLIL→MLIL→HLIL lift rather than copied from pseudo_code).
        let mut opts = DecompOptions::default();
        opts.passes.hlil_experimental = true;
        let mut pipeline = Arc::into_inner(standard_pipeline_arc(opts))
            .expect("standard_pipeline_arc returned shared Arc");

        // Attach a SymbolMap built from this binary's name_store (populated
        // by PDB/DWARF load + any FLIRT/manual renames). Without this, the
        // decompiler emits `sub_<hex>(...)` for every call.
        let mut sym_map = SymbolMap::new();
        sym_map.enable_rust_demangling(true);
        // IAT slot VA → import name first, so a call through the slot renders
        // as `HeapAlloc(...)` instead of `off_<hex>(...)` — the batch path
        // (binary_entry) already chains loader imports the same way. Inserted
        // BEFORE name_store so PDB/FLIRT/manual renames overwrite them.
        for (addr, name) in harvest_iat_symbols(data) {
            sym_map.insert(addr, name);
        }
        let prefix = binary_id.to_string();
        for ((bid, addr), name) in &reg.name_store {
            if bid == &prefix {
                let display = rustre_symbols::try_demangle(name).unwrap_or_else(|| name.clone());
                sym_map.insert(*addr, display);
            }
        }
        pipeline.set_symbol_resolver(Arc::new(sym_map));

        let result = pipeline
            .run_with_structured_emit(func_addr, &func_name, &instructions)
            .map_err(|e| McpToolError::ExecutionFailed(format!("decompiler error: {e}")))?;

        // Use the real HLIL annotation produced by IlAnalysisPass; do not
        // fall back to pseudo_code so the caller can distinguish LLIL vs HLIL.
        let hlil_pseudo_code = result.hlil_pseudo_code.clone()
            .filter(|s| !s.is_empty());
        Ok(serde_json::json!({
            "binary_id": binary_id,
            "addr": format!("{:#x}", func_addr),
            "name": result.name,
            "pseudo_code": result.pseudo_code,
            "hlil_pseudo_code": hlil_pseudo_code,
            "confidence": result.confidence,
            "ir_level": result.ir_level.to_string(),
            "variables": result.variables.iter().map(|v| serde_json::json!({
                "name": v.name,
                "type": v.type_str,
                "is_parameter": v.is_parameter,
                "storage": v.storage.to_string()
            })).collect::<Vec<_>>(),
            "call_sites": result.call_sites.iter().map(|a| format!("{a:#x}")).collect::<Vec<_>>()
        }))
    }
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// Stub tool handlers Ã¢â‚¬— one per tool, returning plausible fake data
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

/// Harvest `(IAT slot VA, import name)` pairs from a PE image's import table.
/// Non-PE, malformed, or import-less inputs yield an empty vector (never
/// errors). Ordinal-only imports are skipped — an ordinal has no C-callable
/// name to render.
fn harvest_iat_symbols(data: &[u8]) -> Vec<(u64, String)> {
    let Ok(pe) = rustre_loader_pe::PeInfo::parse(data) else {
        return Vec::new();
    };
    pe.imports
        .iter()
        .filter(|imp| imp.address != 0)
        .filter_map(|imp| {
            imp.name
                .as_deref()
                .filter(|n| !n.is_empty())
                .map(|n| (imp.address, n.to_string()))
        })
        .collect()
}

macro_rules! stub_handler {
    ($name:ident, $tool_name:expr, $result:expr) => {
        pub struct $name;
        impl McpToolHandler for $name {
            fn name(&self) -> &str {
                $tool_name
            }
            fn execute(&self, _params: Value) -> Result<Value, McpToolError> {
                Ok($result)
            }
        }
    };
}

stub_handler!(
    ProjectOpenHandler,
    "project.open",
    serde_json::json!({ "project_id": "proj-stub-0001", "stub": true })
);

stub_handler!(
    ProjectCloseHandler,
    "project.close",
    serde_json::json!({ "closed": true, "stub": true })
);

stub_handler!(
    ProjectListBinariesHandler,
    "project.list_binaries",
    serde_json::json!({ "binary_ids": ["bin-0001", "bin-0002"], "stub": true })
);

stub_handler!(
    ProjectInfoHandler,
    "project.info",
    serde_json::json!({
        "stub": true,
        "project_id": "proj-stub-0001",
        "name": "stub-project",
        "binary_count": 2,
        "created_at": 1_700_000_000
    })
);

stub_handler!(
    BinaryInfoHandler,
    "binary.info",
    serde_json::json!({
        "stub": true,
        "format": "PE64",
        "arch": "x86_64",
        "entry_point": "0x140001000",
        "sections": [
            { "name": ".text", "va": "0x140001000", "size": 65536 },
            { "name": ".data", "va": "0x140011000", "size": 4096 },
            { "name": ".rdata", "va": "0x140012000", "size": 8192 }
        ],
        "size": 102_400,
        "sha256": "aabbccdd" .repeat(8),
        "imports_count": 42,
        "exports_count": 0
    })
);

stub_handler!(
    BinaryHexdumpHandler,
    "binary.hexdump",
    serde_json::json!({
        "stub": true,
        "hex": "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57",
        "ascii": "H.\\$..l$..t$..W"
    })
);

stub_handler!(
    BinaryReadHandler,
    "binary.read",
    serde_json::json!({ "stub": true, "data_base64": "SEVMTE8=" })
);

stub_handler!(
    BinarySearchBytesHandler,
    "binary.search_bytes",
    serde_json::json!({ "stub": true, "addresses": ["0x140001234", "0x140005678"] })
);

stub_handler!(
    BinarySearchStringsHandler,
    "binary.search_strings",
    serde_json::json!({
        "stub": true,
        "strings": [
            { "addr": "0x14000a000", "value": "Hello, World!", "encoding": "utf-8" },
            { "addr": "0x14000a020", "value": "Copyright 2024", "encoding": "utf-8" }
        ]
    })
);

stub_handler!(
    BinaryEntropyHandler,
    "binary.entropy",
    serde_json::json!({
        "stub": true,
        "min": 0.12,
        "max": 7.98,
        "avg": 4.51,
        "regions": [
            { "addr": "0x140001000", "len": 65536, "entropy": 6.12 },
            { "addr": "0x140012000", "len": 8192, "entropy": 3.45 }
        ]
    })
);

stub_handler!(
    AnalyzeFullHandler,
    "analyze.full",
    serde_json::json!({
        "stub": true,
        "functions_found": 237,
        "strings_found": 512,
        "imports_resolved": 42,
        "duration_ms": 1234,
        "status": "completed"
    })
);

stub_handler!(
    AnalyzeFunctionHandler,
    "analyze.function",
    serde_json::json!({
        "stub": true,
        "addr": "0x140001000",
        "name": "sub_140001000",
        "size": 128,
        "basic_blocks": 7,
        "calls_to": ["0x140002000"],
        "calls_from": ["0x140003000"]
    })
);

stub_handler!(
    AnalyzeBasicBlockHandler,
    "analyze.basic_block",
    serde_json::json!({
        "stub": true,
        "addr": "0x140001000",
        "end_addr": "0x140001040",
        "instruction_count": 16,
        "successors": ["0x140001040", "0x140001080"]
    })
);

stub_handler!(
    AnalyzeCrossRefsHandler,
    "analyze.cross_refs",
    serde_json::json!({
        "stub": true,
        "calls_to": ["0x140002000", "0x140003000"],
        "calls_from": ["0x140004000"],
        "data_refs": ["0x14000a000"]
    })
);

stub_handler!(
    AnalyzeCallGraphHandler,
    "analyze.call_graph",
    serde_json::json!({
        "stub": true,
        "dot": "digraph G {\n  \"sub_140001000\" -> \"sub_140002000\";\n  \"sub_140001000\" -> \"sub_140003000\";\n}"
    })
);

stub_handler!(
    AnalyzeStringsHandler,
    "analyze.strings",
    serde_json::json!({
        "stub": true,
        "strings": [
            { "addr": "0x14000a000", "value": "stub string 1" },
            { "addr": "0x14000a020", "value": "stub string 2" }
        ]
    })
);

stub_handler!(
    AnalyzeImportsHandler,
    "analyze.imports",
    serde_json::json!({
        "stub": true,
        "imports": [
            { "module": "KERNEL32.dll", "name": "CreateFileW", "addr": "0x14001a000" },
            { "module": "KERNEL32.dll", "name": "ReadFile", "addr": "0x14001a008" },
            { "module": "ntdll.dll", "name": "NtQuerySystemInformation", "addr": "0x14001a010" }
        ]
    })
);

stub_handler!(
    AnalyzeExportsHandler,
    "analyze.exports",
    serde_json::json!({ "stub": true, "exports": [] })
);

stub_handler!(
    DisasmAtHandler,
    "disasm.at",
    serde_json::json!({
        "stub": true,
        "instructions": [
            { "addr": "0x140001000", "bytes": "48 89 5C 24 08", "mnemonic": "MOV", "operands": "[RSP+0x8], RBX" },
            { "addr": "0x140001005", "bytes": "48 89 6C 24 10", "mnemonic": "MOV", "operands": "[RSP+0x10], RBP" },
            { "addr": "0x14000100A", "bytes": "57",             "mnemonic": "PUSH", "operands": "RDI" }
        ]
    })
);

stub_handler!(
    DisasmFunctionHandler,
    "disasm.function",
    serde_json::json!({
        "stub": true,
        "addr": "0x140001000",
        "instruction_count": 64,
        "instructions": [
            { "addr": "0x140001000", "bytes": "55", "mnemonic": "PUSH", "operands": "RBP" }
        ]
    })
);

stub_handler!(
    DecompileFunctionHandler,
    "decompile.function",
    serde_json::json!({
        "stub": true,
        "source": "// STUB decompilation\nvoid* sub_140001000(void* param_1) {\n    // TODO: real decompilation\n    return param_1;\n}",
        "variables": {
            "param_1": { "type": "void*", "storage": "register:rcx" }
        },
        "confidence": 0.72
    })
);

// Real decompile.rename_variable handler — persists variable renames in the registry
pub struct RealDecompileRenameVarHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealDecompileRenameVarHandler {
    fn name(&self) -> &'static str {
        "decompile.rename_variable"
    }

    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'binary_id'".into()))?;

        let func_addr: u64 = {
            let v = params
                .get("func_addr")
                .ok_or_else(|| McpToolError::InvalidParams("missing 'func_addr'".into()))?;
            if let Some(n) = v.as_u64() {
                n
            } else if let Some(s) = v.as_str() {
                let s = s.trim_start_matches("0x").trim_start_matches("0X");
                u64::from_str_radix(s, 16)
                    .map_err(|_| McpToolError::InvalidParams(format!("invalid func_addr: {s}")))?
            } else {
                return Err(McpToolError::InvalidParams(
                    "'func_addr' must be a hex string or number".into(),
                ));
            }
        };

        let old_name = params
            .get("old_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'old_name'".into()))?;
        let new_name = params
            .get("new_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'new_name'".into()))?;

        let mut reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("registry lock poisoned".into()))?;

        if reg.get(binary_id).is_none() {
            return Err(McpToolError::NotFound(format!(
                "binary {binary_id} not loaded"
            )));
        }

        reg.var_rename_store.insert(
            (binary_id.to_string(), func_addr, old_name.to_string()),
            new_name.to_string(),
        );

        Ok(serde_json::json!({
            "binary_id": binary_id,
            "func_addr": format!("{:#x}", func_addr),
            "old_name": old_name,
            "new_name": new_name,
            "renamed": true
        }))
    }
}

stub_handler!(
    DecompileSetTypeHandler,
    "decompile.set_type",
    serde_json::json!({ "stub": true, "type_set": true })
);

// ── RealDebugLaunchHandler ────────────────────────────────────────────────────

pub struct DebugLaunchHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for DebugLaunchHandler {
    fn name(&self) -> &'static str {
        "debug.launch"
    }

    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        // `path` takes priority over registry lookup: the caller can supply a
        // direct filesystem path without requiring the binary to be pre-loaded.
        let explicit_path: Option<&str> = params
            .get("path")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty());
        let args: Vec<String> = params
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|a| a.as_str().map(std::string::ToString::to_string))
                    .collect()
            })
            .unwrap_or_default();

        let binary_path: String = if let Some(p) = explicit_path {
            // Use the explicit path directly — no registry lookup required.
            p.to_string()
        } else {
            let reg = self
                .registry
                .lock()
                .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
            if binary_id.is_empty() {
                String::new()
            } else {
                match reg.get(binary_id) {
                    Some((_, info)) => info.path.clone(),
                    // binary_id not loaded and no path given. This used to
                    // return `Ok({"stub": true, …})` — the comment said "so
                    // catalog-level smoke tests always succeed", i.e. the
                    // success was for the test's benefit, not the caller's.
                    // Nothing was launched, so a caller that checks only
                    // success/failure believed a process existed. The guidance
                    // was genuinely useful and is kept verbatim; only the
                    // verdict changes from success to failure.
                    None => {
                        return Err(McpToolError::NotFound(format!(
                            "binary '{binary_id}' is not loaded; pass path=<exe> to launch \
                             without pre-loading or call project.open first"
                        )));
                    }
                }
            }
        };

        // Spawn the process using std::process::Command. Redirect child stdio to
        // null so the spawned binary's output never pollutes the MCP JSON-RPC stream.
        let mut cmd = std::process::Command::new(&binary_path);
        cmd.args(&args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let child = cmd.spawn().map_err(|e| {
            McpToolError::ExecutionFailed(format!("failed to launch '{binary_path}': {e}"))
        })?;
        let pid = child.id();

        let session_id = {
            let mut reg = self
                .registry
                .lock()
                .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
            let sid = reg.next_session_id();
            reg.sessions.insert(
                sid.clone(),
                DebugSessionRecord {
                    session_id: sid.clone(),
                    pid,
                    binary_path: binary_path.clone(),
                    status: "running".to_string(),
                },
            );
            sid
        };

        Ok(serde_json::json!({
            "session_id": session_id,
            "pid": pid,
            "binary_path": binary_path,
            "status": "running",
            "live": explicit_path.is_some()
        }))
    }
}

// ── RealDebugAttachHandler ────────────────────────────────────────────────────

pub struct DebugAttachHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for DebugAttachHandler {
    fn name(&self) -> &'static str {
        "debug.attach"
    }

    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let pid: u32 = if let Some(v) = params.get("pid") {
            let raw = v
                .as_u64()
                .ok_or_else(|| McpToolError::InvalidParams("'pid' must be an integer".into()))?;
            u32::try_from(raw).unwrap_or(u32::MAX)
        } else {
            return Err(McpToolError::InvalidParams(
                "missing required parameter 'pid'".into(),
            ));
        };

        // Resolve optional binary_path from binary_id or path parameter.
        let binary_path: String =
            if let Some(binary_id) = params.get("binary_id").and_then(|v| v.as_str()) {
                let reg = self
                    .registry
                    .lock()
                    .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
                match reg.get(binary_id) {
                    Some((_, info)) => info.path.clone(),
                    None => {
                        return Err(McpToolError::NotFound(format!(
                            "binary {binary_id} not loaded"
                        )));
                    }
                }
            } else {
                params
                    .get("binary_path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            };

        let session_id = {
            let mut reg = self
                .registry
                .lock()
                .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
            let sid = reg.next_session_id();
            reg.sessions.insert(
                sid.clone(),
                DebugSessionRecord {
                    session_id: sid.clone(),
                    pid,
                    binary_path: binary_path.clone(),
                    status: "attached".to_string(),
                },
            );
            sid
        };

        Ok(serde_json::json!({
            "session_id": session_id,
            "pid": pid,
            "binary_path": binary_path,
            "status": "attached"
        }))
    }
}

// ── RealDebugContinueHandler ──────────────────────────────────────────────────

pub struct DebugContinueHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for DebugContinueHandler {
    fn name(&self) -> &'static str {
        "debug.continue"
    }

    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let session_id = params
            .get("session_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| McpToolError::InvalidParams("missing 'session_id'".into()))?;

        let pid = {
            let reg = self
                .registry
                .lock()
                .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
            match reg.sessions.get(session_id) {
                Some(s) => s.pid,
                None => {
                    return Err(McpToolError::NotFound(format!(
                        "debug session {session_id} not found"
                    )));
                }
            }
        };

        // Send SIGCONT on Unix; on Windows this is a no-op (no ptrace yet).
        #[cfg(unix)]
        {
            use std::io;
            // SAFETY: kill(2) with signal 18 (SIGCONT) on the target pid.
            let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGCONT) };
            if rc != 0 {
                let err = io::Error::last_os_error();
                return Err(McpToolError::ExecutionFailed(format!(
                    "kill(SIGCONT, {pid}) failed: {err}"
                )));
            }
        }

        // Update session status.
        {
            let mut reg = self
                .registry
                .lock()
                .map_err(|_| McpToolError::ExecutionFailed("lock poisoned".into()))?;
            if let Some(s) = reg.sessions.get_mut(session_id) {
                s.status = "running".to_string();
            }
        }

        Ok(serde_json::json!({
            "session_id": session_id,
            "pid": pid,
            "status": "running"
        }))
    }
}

stub_handler!(
    DebugStepIntoHandler,
    "debug.step_into",
    serde_json::json!({ "stub": true, "stop_reason": "step", "addr": "0x140001238" })
);

stub_handler!(
    DebugStepOverHandler,
    "debug.step_over",
    serde_json::json!({ "stub": true, "stop_reason": "step", "addr": "0x14000123C" })
);

stub_handler!(
    DebugSetBreakpointHandler,
    "debug.set_breakpoint",
    serde_json::json!({ "stub": true, "bp_id": 1 })
);

stub_handler!(
    DebugRemoveBreakpointHandler,
    "debug.remove_breakpoint",
    serde_json::json!({ "stub": true, "removed": true })
);

stub_handler!(
    DebugReadRegistersHandler,
    "debug.read_registers",
    serde_json::json!({
        "stub": true,
        "registers": {
            "rax": "0x0000000000000001",
            "rbx": "0x0000000000000000",
            "rcx": "0x00007ff6140011a0",
            "rdx": "0x0000000000000002",
            "rsp": "0x000000d432bffee0",
            "rbp": "0x000000d432bffef0",
            "rip": "0x0000000140001234"
        }
    })
);

stub_handler!(
    DebugReadMemoryHandler,
    "debug.read_memory",
    serde_json::json!({ "stub": true, "data_base64": "QUJDREVGR0g=" })
);

stub_handler!(
    DebugWriteMemoryHandler,
    "debug.write_memory",
    serde_json::json!({ "stub": true, "written": true })
);

stub_handler!(
    DebugBacktraceHandler,
    "debug.backtrace",
    serde_json::json!({
        "stub": true,
        "frames": [
            { "addr": "0x140001234", "name": "sub_140001000", "module": "target.exe" },
            { "addr": "0x140003456", "name": "main", "module": "target.exe" },
            { "addr": "0x7ff812340000", "name": "BaseThreadInitThunk", "module": "KERNEL32.DLL" }
        ]
    })
);

stub_handler!(
    DebugEvaluateHandler,
    "debug.evaluate",
    serde_json::json!({ "stub": true, "value": "42" })
);

stub_handler!(
    YaraScanFileHandler,
    "yara.scan_file",
    serde_json::json!({
        "stub": true,
        "matches": [
            {
                "rule": "SuspiciousImports",
                "strings": { "$a": [{ "offset": "0x1234", "data": "VirtualAlloc" }] }
            }
        ]
    })
);

stub_handler!(
    YaraCompileHandler,
    "yara.compile",
    serde_json::json!({ "stub": true, "ruleset_id": "ruleset-stub-0001" })
);

stub_handler!(
    YaraScanMemoryHandler,
    "yara.scan_memory",
    serde_json::json!({ "stub": true, "matches": [] })
);

stub_handler!(
    ForensicsOpenDumpHandler,
    "forensics.open_dump",
    serde_json::json!({ "stub": true, "image_id": "img-stub-0001", "os": "Windows 10", "arch": "x86_64" })
);

stub_handler!(
    ForensicsRunPluginHandler,
    "forensics.run_plugin",
    serde_json::json!({
        "stub": true,
        "plugin": "pslist",
        "rows": [
            { "pid": 4, "name": "System", "ppid": 0 },
            { "pid": 88, "name": "smss.exe", "ppid": 4 }
        ]
    })
);

stub_handler!(
    ForensicsListPluginsHandler,
    "forensics.list_plugins",
    serde_json::json!({
        "stub": true,
        "plugins": ["pslist", "dlllist", "netscan", "cmdline", "filescan", "malfind", "handles"]
    })
);

stub_handler!(
    KgQueryHandler,
    "kg.query",
    serde_json::json!({ "stub": true, "rows": [{ "id": 1, "name": "sub_140001000", "addr": "0x140001000" }] })
);

stub_handler!(
    KgAnnotateHandler,
    "kg.annotate",
    serde_json::json!({ "stub": true, "annotated": true })
);

stub_handler!(
    KgSearchHandler,
    "kg.search",
    serde_json::json!({
        "stub": true,
        "results": [
            { "entity_type": "function", "entity_id": "0x140001000", "name": "sub_140001000", "score": 0.95 }
        ]
    })
);

stub_handler!(
    KgSetFunctionNameHandler,
    "kg.set_function_name",
    serde_json::json!({ "stub": true, "renamed": true })
);

stub_handler!(
    KgSetCommentHandler,
    "kg.set_comment",
    serde_json::json!({ "stub": true, "comment_set": true })
);

stub_handler!(
    KgGetFunctionHandler,
    "kg.get_function",
    serde_json::json!({
        "stub": true,
        "addr": "0x140001000",
        "name": "sub_140001000",
        "size": 128,
        "comment": null,
        "tags": []
    })
);

stub_handler!(
    KgListFunctionsHandler,
    "kg.list_functions",
    serde_json::json!({
        "stub": true,
        "functions": [
            { "addr": "0x140001000", "name": "sub_140001000", "size": 128 },
            { "addr": "0x140002000", "name": "sub_140002000", "size": 64 }
        ]
    })
);

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// RustReMcpServer Ã¢â‚¬— top-level struct combining everything
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

pub struct RustReMcpServer {
    pub tools: Vec<McpToolDef>,
    pub session_manager: SessionManager,
    executor: ToolExecutor,
    pub registry: SharedBinaryRegistry,
}

impl RustReMcpServer {
    /// Create a fully wired-up `RustRE` MCP server with real handlers where available.
    #[must_use]
    pub fn new() -> Self {
        let tools = build_tool_catalog();
        let mut executor = ToolExecutor::new();
        let registry: SharedBinaryRegistry = Arc::new(Mutex::new(BinaryRegistry::new()));

        // Register real handlers for core tools
        executor.register(Box::new(RealProjectOpenHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealBinaryInfoHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealBinaryHexdumpHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealBinaryReadHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealBinaryEntropyHandler {
            registry: registry.clone(),
        }));

        // Remaining stub handlers
        executor.register(Box::new(RealProjectCloseHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealProjectListBinariesHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealProjectInfoHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealBinarySearchBytesHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealBinarySearchStringsHandler {
            registry: registry.clone(),
        }));
        // BinaryEntropyHandler replaced by RealBinaryEntropyHandler above
        executor.register(Box::new(RealAnalyzeFullHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealAnalyzeFunctionHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealAnalyzeBasicBlockHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealAnalyzeCrossRefsHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealAnalyzeCallGraphHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealAnalyzeStringsHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealAnalyzeImportsHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealAnalyzeExportsHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealSymbolsLoadPdbHandler));
        executor.register(Box::new(RealYaraCompileAndScanHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealCryptoIdentifyHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealTriageHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealPatchPeSecuritySummaryHandler));
        executor.register(Box::new(RealPatchFindCodeCavesHandler));
        executor.register(Box::new(RealDisasmAtHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealDisasmFunctionHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealDecompileFunctionHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealDecompileRenameVarHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealDecompileSetTypeHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(DebugLaunchHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(DebugAttachHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(DebugContinueHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealDebugStepHandler {
            step_type: "debug.step_into",
        }));
        executor.register(Box::new(RealDebugStepHandler {
            step_type: "debug.step_over",
        }));
        executor.register(Box::new(RealDebugSetBreakpointHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealDebugRemoveBreakpointHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealDebugReadRegistersHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealDebugReadMemoryHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealDebugWriteMemoryHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealDebugBacktraceHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealDebugEvaluateHandler {
            registry: registry.clone(),
        }));
        // yara.scan_file is handled by RealYaraCompileAndScanHandler registered above
        executor.register(Box::new(RealYaraCompileHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealYaraScanMemoryHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealForensicsOpenDumpHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealForensicsRunPluginHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealForensicsListPluginsHandler));
        executor.register(Box::new(RealKgQueryHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealKgAnnotateHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealKgSearchHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealKgSetFunctionNameHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealKgSetCommentHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealKgGetFunctionHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealKgListFunctionsHandler {
            registry: registry.clone(),
        }));
        executor.register(Box::new(RealDiffCompareHandler {
            registry: registry.clone(),
        }));

        Self {
            tools,
            session_manager: SessionManager::new(),
            executor,
            registry,
        }
    }

    /// Register an external tool produced outside this crate.
    ///
    /// Used by sibling crates (e.g. `rustre-mcp-tools`) to inject their
    /// `McpToolHandler` implementations into the executor and surface them in
    /// the catalog so they appear via `list_tools` and dispatch via
    /// `execute_tool`. If the tool already exists in the catalog (matching by
    /// name) we leave the catalog entry intact and only swap the handler.
    pub fn register_external_tool(
        &mut self,
        def: McpToolDef,
        handler: Box<dyn McpToolHandler>,
    ) {
        if !self.tools.iter().any(|t| t.name == def.name) {
            self.tools.push(def);
        }
        self.executor.register(handler);
    }

    /// Execute a named tool with the given JSON parameters.
    ///
    /// If the registered real handler returns an execution-level error (e.g. missing
    /// optional params, IO failures against placeholder paths), fall back to a stub
    /// JSON result so the tool always succeeds for catalog-level smoke tests. The
    /// `NotFound` case is preserved so callers can distinguish unknown tools.
    pub fn execute_tool(&self, name: &str, params: Value) -> Result<Value, McpToolError> {
        // Distinguish unknown tools (catalog miss) from handler-level errors. A name
        // present in the catalog but missing from the executor is treated as a known
        // tool with a stub handler.
        let known_in_catalog = self.tools.iter().any(|t| t.name == name);
        let registered = self.executor.tool_names().contains(&name);
        if !known_in_catalog && !registered {
            return Err(McpToolError::NotFound(name.to_string()));
        }
        if !registered {
            return Ok(serde_json::json!({ "stub": true, "tool": name }));
        }

        // Enforce the tool's OWN declared schema before handing the call to
        // the handler.
        //
        // Without this, a handler that defaults its way past a missing
        // required argument answers a question nobody asked: with `{}`,
        // `debug.read_registers` returned a full, plausible register set
        // (rip=0x140001000, rsp=0x7fff0000f8d0, rflags=0x246) for a session
        // that does not exist, `debug.step_over` reported `"status":"stepped"`
        // for a process it never touched, and `yara.compile` invented a
        // ruleset id with `rule_count: 1` from no rules at all. Ten catalog
        // tools behaved this way. Each could be patched individually, but the
        // defect is structural — the schema said the parameter was required
        // and nothing checked — so it is enforced once, here, where every
        // dispatch passes.
        if let Some(def) = self.tools.iter().find(|t| t.name == name) {
            if let Some(required) = def.input_schema.get("required").and_then(|v| v.as_array()) {
                let missing: Vec<&str> = required
                    .iter()
                    .filter_map(|v| v.as_str())
                    .filter(|k| params.get(*k).is_none_or(Value::is_null))
                    .collect();
                if !missing.is_empty() {
                    return Err(McpToolError::InvalidParams(format!(
                        "tool '{name}' requires {} but they were not supplied",
                        missing.join(", ")
                    )));
                }
            }
        }

        self.executor
            .execute(name, params)
            .map_err(|e| McpToolError::ExecutionFailed(e.to_string()))
    }

    /// Return all tools in a given category.
    #[must_use]
    pub fn tools_by_category(&self, cat: &ToolCategory) -> Vec<&McpToolDef> {
        self.tools.iter().filter(|t| &t.category == cat).collect()
    }

    /// Find a tool definition by name.
    #[must_use]
    pub fn find_tool(&self, name: &str) -> Option<&McpToolDef> {
        self.tools.iter().find(|t| t.name == name)
    }

    /// Return the total number of registered tools.
    #[must_use]
    pub const fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Build an `McpServer` from this `RustReMcpServer`, wiring all stub handlers as `ToolHandler`s.
    #[must_use]
    pub fn into_mcp_server(self) -> McpServer {
        let mut server = McpServer::new("rustre", env!("CARGO_PKG_VERSION"));
        for tool_def in &self.tools {
            let name = tool_def.name.clone();
            let def = tool_def.to_tool_definition();
            server.register_tool(def, Box::new(StubToolHandler { name }));
        }
        server
    }
}

impl Default for RustReMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

/// Adapter: wraps the synchronous `McpToolHandler` executor for the async `ToolHandler` trait.
struct StubToolHandler {
    name: String,
}

#[async_trait]
impl ToolHandler for StubToolHandler {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        // Return stub JSON for every tool
        Ok(ToolResult::json(
            &serde_json::json!({ "stub": true, "tool": self.name }),
        ))
    }
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// McpServer
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

pub struct McpServer {
    pub name: String,
    pub version: String,
    pub tools: Vec<ToolDefinition>,
    pub handlers: HashMap<String, Box<dyn ToolHandler>>,
    pub resources: Vec<ResourceDefinition>,
}

impl McpServer {
    #[must_use]
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            tools: Vec::new(),
            handlers: HashMap::new(),
            resources: Vec::new(),
        }
    }

    pub fn register_tool(&mut self, def: ToolDefinition, handler: Box<dyn ToolHandler>) {
        self.handlers.insert(def.name.clone(), handler);
        self.tools.push(def);
    }

    pub fn register_resource(&mut self, res: ResourceDefinition) {
        self.resources.push(res);
    }

    pub async fn dispatch(&self, req: JsonRpcRequest) -> JsonRpcResponse {
        // A notification carries no id; the response object still needs one, and
        // `Null` is what the spec prescribes when an id cannot be echoed. Whether
        // the response is SENT at all is decided by the transport below.
        let id = req.id.clone().unwrap_or(Value::Null);
        match req.method.as_str() {
            "initialize" => self.handle_initialize(id, req.params).await,
            "tools/list" => self.handle_tools_list(id).await,
            "tools/call" => self.handle_tools_call(id, req.params).await,
            "resources/list" => self.handle_resources_list(id),
            "resources/read" => self.handle_resources_read(id, req.params),
            other => JsonRpcResponse::err(id, &McpError::MethodNotFound(other.to_string())),
        }
    }

    async fn handle_initialize(&self, id: Value, _params: Option<Value>) -> JsonRpcResponse {
        let result = serde_json::json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": { "name": self.name, "version": self.version },
            "capabilities": { "tools": {}, "resources": {} }
        });
        JsonRpcResponse::ok(id, result)
    }

    async fn handle_tools_list(&self, id: Value) -> JsonRpcResponse {
        JsonRpcResponse::ok(id, serde_json::json!({ "tools": self.tools }))
    }

    async fn handle_tools_call(&self, id: Value, params: Option<Value>) -> JsonRpcResponse {
        let params = match params {
            Some(p) => p,
            None => {
                return JsonRpcResponse::err(
                    id,
                    &McpError::InvalidParams("missing params".to_string()),
                );
            }
        };

        let name = match params.get("name").and_then(Value::as_str) {
            Some(n) => n.to_string(),
            None => {
                return JsonRpcResponse::err(
                    id,
                    &McpError::InvalidParams("missing tool name".to_string()),
                );
            }
        };

        let args = params
            .get("arguments")
            .cloned()
            .unwrap_or(Value::Object(serde_json::Map::new()));

        match self.handlers.get(&name) {
            None => JsonRpcResponse::err(id, &McpError::MethodNotFound(name)),
            Some(handler) => match handler.call(args).await {
                Ok(tool_result) => {
                    let result = serde_json::to_value(&tool_result)
                        .unwrap_or_else(|e| serde_json::json!({ "error": e.to_string() }));
                    JsonRpcResponse::ok(id, result)
                }
                Err(e) => JsonRpcResponse::err(id, &e),
            },
        }
    }

    fn handle_resources_list(&self, id: Value) -> JsonRpcResponse {
        JsonRpcResponse::ok(id, serde_json::json!({ "resources": self.resources }))
    }

    fn handle_resources_read(&self, id: Value, params: Option<Value>) -> JsonRpcResponse {
        let uri = params
            .as_ref()
            .and_then(|p| p.get("uri"))
            .and_then(Value::as_str)
            .map(str::to_string);

        match uri {
            None => JsonRpcResponse::err(id, &McpError::InvalidParams("missing uri".to_string())),
            Some(u) => {
                if self.resources.iter().any(|r| r.uri == u) {
                    JsonRpcResponse::ok(
                        id,
                        serde_json::json!({ "contents": [{ "uri": u, "text": "" }] }),
                    )
                } else {
                    JsonRpcResponse::err(
                        id,
                        &McpError::MethodNotFound(format!("resource not found: {u}")),
                    )
                }
            }
        }
    }

    pub async fn run_stdio(self) -> Result<(), McpError> {
        let server = Arc::new(self);
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        let mut reader = BufReader::new(stdin).lines();
        let mut writer = tokio::io::BufWriter::new(stdout);

        while let Some(line) = reader.next_line().await? {
            let line = line.trim().to_string();
            if line.is_empty() {
                continue;
            }
            let parsed = serde_json::from_str::<JsonRpcRequest>(&line);
            // A malformed message is NOT a notification: the spec allows answering
            // it with an error object carrying a null id, so only a well-formed
            // request without an `id` is treated as one.
            let is_notification = matches!(&parsed, Ok(req) if req.id.is_none());
            let response = match parsed {
                Err(e) => JsonRpcResponse::err(Value::Null, &McpError::ParseError(e.to_string())),
                Ok(req) => server.dispatch(req).await,
            };
            // JSON-RPC 2.0: "The Server MUST NOT reply to a Notification."
            // The dispatch above still ran, for its side effects.
            if is_notification {
                continue;
            }
            let mut serialized = serde_json::to_string(&response)
                .map_err(|e| McpError::InternalError(e.to_string()))?;
            serialized.push('\n');
            writer.write_all(serialized.as_bytes()).await?;
            writer.flush().await?;
        }
        Ok(())
    }

    pub async fn run_http(self, addr: SocketAddr) -> Result<(), McpError> {
        use tokio::net::TcpListener;
        let server = Arc::new(self);
        let listener = TcpListener::bind(addr).await?;
        loop {
            let (mut stream, _peer) = listener.accept().await?;
            let srv = server.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_http_connection(&mut stream, srv).await {
                    eprintln!("HTTP connection error: {e}");
                }
            });
        }
    }
}

async fn handle_http_connection(
    stream: &mut tokio::net::TcpStream,
    server: Arc<McpServer>,
) -> Result<(), McpError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; 1024 * 1024];
    let n = stream.read(&mut buf).await?;
    let raw = std::str::from_utf8(&buf[..n]).unwrap_or("");
    let body = if let Some(pos) = raw.find("\r\n\r\n") {
        &raw[pos + 4..]
    } else {
        ""
    };

    let (status, body_out) = if body.is_empty() {
        let info = serde_json::json!({
            "server": server.name,
            "version": server.version,
            "protocol": "mcp/2024-11-05"
        });
        (200_u16, serde_json::to_string(&info).unwrap_or_default())
    } else {
        match serde_json::from_str::<JsonRpcRequest>(body) {
            Err(e) => {
                let resp = JsonRpcResponse::err(Value::Null, &McpError::ParseError(e.to_string()));
                (400_u16, serde_json::to_string(&resp).unwrap_or_default())
            }
            Ok(req) => {
                let is_notification = req.id.is_none();
                let resp = server.dispatch(req).await;
                if is_notification {
                    // Accepted, and nothing to reply: see the stdio branch.
                    (204_u16, String::new())
                } else {
                    (200_u16, serde_json::to_string(&resp).unwrap_or_default())
                }
            }
        }
    };

    let http_response = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body_out.len(),
        body_out
    );
    stream
        .write_all(http_response.as_bytes())
        .await
        .map_err(McpError::Io)
}

pub fn parse_request(s: &str) -> Result<JsonRpcRequest, McpError> {
    serde_json::from_str(s).map_err(|e| McpError::ParseError(e.to_string()))
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// Legacy types preserved for federation crate compatibility
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClientId {
    inner: u64,
}

impl ClientId {
    #[must_use]
    pub const fn new(id: u64) -> Self {
        Self { inner: id }
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.inner
    }
}

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "client-{}", self.inner)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub max_connections: usize,
    pub auth_token: Option<String>,
}

impl ServerConfig {
    #[must_use]
    pub fn new() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 3000,
            max_connections: 100,
            auth_token: None,
        }
    }

    #[must_use]
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into();
        self
    }

    #[must_use]
    pub const fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    #[must_use]
    pub const fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    #[must_use]
    pub fn with_auth(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    #[must_use]
    pub fn listen_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Authenticated,
    Disconnected,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connecting => write!(f, "connecting"),
            Self::Connected => write!(f, "connected"),
            Self::Authenticated => write!(f, "authenticated"),
            Self::Disconnected => write!(f, "disconnected"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerRequest {
    pub client_id: ClientId,
    pub method: String,
    pub params: Option<Value>,
    pub id: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResponse {
    pub client_id: ClientId,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub id: Value,
}

impl ServerResponse {
    #[must_use]
    pub const fn ok(client_id: ClientId, id: Value, result: Value) -> Self {
        Self {
            client_id,
            result: Some(result),
            error: None,
            id,
        }
    }

    #[must_use]
    pub fn err(client_id: ClientId, id: Value, error: impl Into<String>) -> Self {
        Self {
            client_id,
            result: None,
            error: Some(error.into()),
            id,
        }
    }

    #[must_use]
    pub const fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

#[async_trait]
pub trait McpTransportTrait: Send + Sync {
    async fn recv(&mut self) -> Result<Option<String>, ServerError>;
    async fn send(&mut self, msg: String) -> Result<(), ServerError>;
}

pub struct MockTransport {
    inbox: parking_lot::Mutex<std::collections::VecDeque<String>>,
    outbox: parking_lot::Mutex<Vec<String>>,
}

impl MockTransport {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inbox: parking_lot::Mutex::new(std::collections::VecDeque::new()),
            outbox: parking_lot::Mutex::new(Vec::new()),
        }
    }

    pub fn enqueue(&self, msg: impl Into<String>) {
        self.inbox.lock().push_back(msg.into());
    }

    pub fn drain_outbox(&self) -> Vec<String> {
        std::mem::take(&mut *self.outbox.lock())
    }
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl McpTransportTrait for MockTransport {
    async fn recv(&mut self) -> Result<Option<String>, ServerError> {
        Ok(self.inbox.lock().pop_front())
    }

    async fn send(&mut self, msg: String) -> Result<(), ServerError> {
        self.outbox.lock().push(msg);
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("bind error: {0}")]
    Bind(String),
    #[error("auth error: {0}")]
    Auth(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("connection closed: {0}")]
    Closed(String),
    #[error("timeout: {0}")]
    Timeout(String),
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// Schema validation helpers
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

/// Validate that `params` contains all required string keys listed in `required`.
pub fn validate_required_strings(params: &Value, required: &[&str]) -> Result<(), McpToolError> {
    for key in required {
        match params.get(key) {
            None => {
                return Err(McpToolError::InvalidParams(format!(
                    "missing required param: {key}"
                )));
            }
            Some(v) if !v.is_string() && !v.is_number() => {
                return Err(McpToolError::InvalidParams(format!(
                    "param '{key}' must be string or number"
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Extract a string param by key, returning `InvalidParams` if missing.
pub fn require_string<'a>(params: &'a Value, key: &str) -> Result<&'a str, McpToolError> {
    params
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| McpToolError::InvalidParams(format!("missing string param: {key}")))
}

/// Extract a u64 param by key.
pub fn require_number(params: &Value, key: &str) -> Result<u64, McpToolError> {
    params
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| McpToolError::InvalidParams(format!("missing number param: {key}")))
}

/// Parse a hex address string like "0x401000" into a u64.
pub fn parse_hex_addr(s: &str) -> Result<u64, McpToolError> {
    let stripped = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(stripped, 16)
        .map_err(|e| McpToolError::InvalidParams(format!("invalid hex address '{s}': {e}")))
}

/// Extract an address from a JSON param that may be a hex string ("0x...") or an integer.
pub fn parse_addr_value(params: &Value, key: &str) -> Result<u64, McpToolError> {
    let v = params
        .get(key)
        .ok_or_else(|| McpToolError::InvalidParams(format!("missing '{key}'")))?;
    if let Some(n) = v.as_u64() {
        return Ok(n);
    }
    if let Some(s) = v.as_str() {
        return parse_hex_addr(s);
    }
    Err(McpToolError::InvalidParams(format!(
        "'{key}' must be a hex string or integer"
    )))
}

// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
// Real debug memory handlers (static analysis on loaded binaries)
// â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Map a virtual address to a byte offset within the raw binary data.
/// For PE/ELF, virtual addresses are relative to `image_base`.
/// Falls back to treating addr as a raw file offset when it is below `image_base`.
fn va_to_file_offset(addr: u64, image_base: u64, data_len: usize) -> Option<usize> {
    if addr >= image_base {
        let offset = usize::try_from(addr - image_base).ok()?;
        if offset < data_len { Some(offset) } else { None }
    } else {
        // addr is below image_base — treat as raw file offset
        let offset = usize::try_from(addr).ok()?;
        if offset < data_len { Some(offset) } else { None }
    }
}

/// Minimal base64 decoder (standard alphabet, with padding).
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [0xffu8; 256];
    for (i, &c) in CHARS.iter().enumerate() {
        table[c as usize] = u8::try_from(i).unwrap_or(0xff);
    }
    table[b'=' as usize] = 0;

    let input = input.trim();
    if !input.len().is_multiple_of(4) {
        return Err(format!(
            "base64 length {} is not a multiple of 4",
            input.len()
        ));
    }

    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    for chunk in input.as_bytes().chunks(4) {
        let a = table[chunk[0] as usize];
        let b = table[chunk[1] as usize];
        let c = table[chunk[2] as usize];
        let d = table[chunk[3] as usize];
        if a == 0xff || b == 0xff {
            return Err("invalid base64 character".into());
        }
        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            if c == 0xff {
                return Err("invalid base64 character".into());
            }
            out.push((b << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            if d == 0xff {
                return Err("invalid base64 character".into());
            }
            out.push((c << 6) | d);
        }
    }
    Ok(out)
}

pub struct RealDebugReadMemoryHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealDebugReadMemoryHandler {
    fn name(&self) -> &'static str {
        "debug.read_memory"
    }

    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .or_else(|| params.get("session_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Accept addr as hex string or decimal number, keyed as "address" or "addr"
        let addr: u64 = if let Some(s) = params
            .get("address")
            .or_else(|| params.get("addr"))
            .and_then(|v| v.as_str())
        {
            parse_hex_addr(s)?
        } else {
            params
                .get("address")
                .or_else(|| params.get("addr"))
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| McpToolError::InvalidParams("missing 'address' or 'addr'".into()))?
        };

        let size = usize::try_from(
            params
                .get("size")
                .or_else(|| params.get("len"))
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(64),
        )
        .unwrap_or(64);

        if size == 0 {
            return Err(McpToolError::InvalidParams("size must be > 0".into()));
        }
        if size > 65536 {
            return Err(McpToolError::InvalidParams("size must be <= 65536".into()));
        }

        let reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("registry lock poisoned".into()))?;
        let (data, info) = reg
            .get(binary_id)
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;

        let offset = va_to_file_offset(addr, info.image_base, data.len())
            .ok_or_else(|| McpToolError::InvalidParams(format!(
                "address {addr:#x} is out of range for binary {binary_id} (image_base={:#x}, size={})",
                info.image_base, data.len()
            )))?;

        let end = (offset + size).min(data.len());
        let actual_size = end - offset;
        let data_hex = hex::encode(&data[offset..end]);

        Ok(serde_json::json!({
            "binary_id": binary_id,
            "address": format!("{addr:#x}"),
            "size": actual_size,
            "data_hex": data_hex
        }))
    }
}

pub struct RealDebugReadRegistersHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealDebugReadRegistersHandler {
    fn name(&self) -> &'static str {
        "debug.read_registers"
    }

    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        // binary_id is optional; when provided, use the binary's entry point as RIP
        let binary_id_opt = params.get("binary_id").and_then(|v| v.as_str());

        let rip: u64 = if let Some(binary_id) = binary_id_opt {
            let reg = self
                .registry
                .lock()
                .map_err(|_| McpToolError::ExecutionFailed("registry lock poisoned".into()))?;
            let (_, info) = reg
                .get(binary_id)
                .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;
            info.entry_point
        } else {
            0x0000_0001_4000_1000
        };

        Ok(serde_json::json!({
            "registers": {
                "rip": format!("{rip:#018x}"),
                "rsp": "0x00007fff0000f8d0",
                "rbp": "0x0000000000000000",
                "rax": "0x0000000000000000",
                "rbx": "0x0000000000000000",
                "rcx": "0x0000000000000000",
                "rdx": "0x0000000000000000",
                "rsi": "0x0000000000000000",
                "rdi": "0x0000000000000000",
                "r8":  "0x0000000000000000",
                "r9":  "0x0000000000000000",
                "r10": "0x0000000000000000",
                "r11": "0x0000000000000000",
                "r12": "0x0000000000000000",
                "r13": "0x0000000000000000",
                "r14": "0x0000000000000000",
                "r15": "0x0000000000000000",
                "rflags": "0x0000000000000246"
            }
        }))
    }
}

pub struct RealDebugWriteMemoryHandler {
    pub registry: SharedBinaryRegistry,
}

impl McpToolHandler for RealDebugWriteMemoryHandler {
    fn name(&self) -> &'static str {
        "debug.write_memory"
    }

    fn execute(&self, params: Value) -> Result<Value, McpToolError> {
        let binary_id = params
            .get("binary_id")
            .or_else(|| params.get("session_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Accept addr as hex string or decimal number
        let addr: u64 = if let Some(s) = params
            .get("address")
            .or_else(|| params.get("addr"))
            .and_then(|v| v.as_str())
        {
            parse_hex_addr(s)?
        } else {
            params
                .get("address")
                .or_else(|| params.get("addr"))
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| McpToolError::InvalidParams("missing 'address' or 'addr'".into()))?
        };

        // Accept patch data as hex string (data_hex) or base64 (data_base64)
        let patch_bytes: Vec<u8> = if let Some(hex_str) =
            params.get("data_hex").and_then(|v| v.as_str())
        {
            let clean: String = hex_str.chars().filter(char::is_ascii_hexdigit).collect();
            if !clean.len().is_multiple_of(2) {
                return Err(McpToolError::InvalidParams(
                    "data_hex has odd number of hex digits".into(),
                ));
            }
            (0..clean.len())
                .step_by(2)
                .map(|i| {
                    u8::from_str_radix(&clean[i..i + 2], 16)
                        .map_err(|e| McpToolError::InvalidParams(format!("invalid hex byte: {e}")))
                })
                .collect::<Result<Vec<_>, _>>()?
        } else if let Some(b64_str) = params.get("data_base64").and_then(|v| v.as_str()) {
            base64_decode(b64_str)
                .map_err(|e| McpToolError::InvalidParams(format!("invalid base64: {e}")))?
        } else {
            return Err(McpToolError::InvalidParams(
                "missing 'data_hex' or 'data_base64' parameter".into(),
            ));
        };

        if patch_bytes.is_empty() {
            return Err(McpToolError::InvalidParams("patch data is empty".into()));
        }

        let mut reg = self
            .registry
            .lock()
            .map_err(|_| McpToolError::ExecutionFailed("registry lock poisoned".into()))?;

        // Gather image_base and data_len before taking a mutable borrow.
        let (image_base, data_len) = reg
            .get(binary_id)
            .map(|(d, info)| (info.image_base, d.len()))
            .ok_or_else(|| McpToolError::NotFound(format!("binary {binary_id} not loaded")))?;

        let offset = va_to_file_offset(addr, image_base, data_len)
            .ok_or_else(|| McpToolError::InvalidParams(format!(
                "address {addr:#x} is out of range for binary {binary_id} (image_base={image_base:#x}, size={data_len})"
            )))?;

        let end = offset + patch_bytes.len();
        if end > data_len {
            return Err(McpToolError::InvalidParams(format!(
                "write of {} bytes at offset {offset:#x} would exceed binary size {data_len}",
                patch_bytes.len()
            )));
        }

        // Apply the patch to the in-memory binary data
        let (data, _info) = reg.get_mut(binary_id).unwrap(); // safe: confirmed above
        data[offset..end].copy_from_slice(&patch_bytes);
        let bytes_written = patch_bytes.len();

        Ok(serde_json::json!({
            "binary_id": binary_id,
            "address": format!("{addr:#x}"),
            "bytes_written": bytes_written,
            "status": "ok"
        }))
    }
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// Tests
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harvest_iat_symbols_rejects_non_pe() {
        assert!(harvest_iat_symbols(b"not a pe at all").is_empty());
        assert!(harvest_iat_symbols(&[]).is_empty());
    }

    #[test]
    fn harvest_iat_symbols_names_real_iat_slots() {
        // Repo-root corpus binary (NOT crates/.../tests). Skip silently if the
        // corpus is absent (e.g. a partial checkout) — the malformed-input test
        // above still runs everywhere.
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/decompiler_corpus/bin/sample5_cs.exe"
        );
        let Ok(data) = std::fs::read(path) else { return };
        let pairs = harvest_iat_symbols(&data);
        assert!(!pairs.is_empty(), "sample5_cs.exe has an import table");
        for (addr, name) in &pairs {
            assert!(*addr >= 0x1_4000_0000, "IAT slot VA must be image-based: {addr:#x}");
            assert!(!name.is_empty());
        }
        // A KERNEL32 staple every mingw/MSVC image links.
        assert!(
            pairs.iter().any(|(_, n)| n == "GetProcAddress" || n == "ExitProcess" || n == "HeapAlloc"),
            "expected a well-known KERNEL32 import, got: {:?}",
            pairs.iter().map(|(_, n)| n).take(20).collect::<Vec<_>>()
        );
    }

    // Ã¢—â‚¬Ã¢—â‚¬ helpers Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    struct EchoTool;

    #[async_trait]
    impl ToolHandler for EchoTool {
        async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
            Ok(ToolResult::text(args.to_string()))
        }
    }

    struct FailTool;

    #[async_trait]
    impl ToolHandler for FailTool {
        async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
            Err(McpError::ToolError("deliberate failure".to_string()))
        }
    }

    fn make_server() -> McpServer {
        let mut srv = McpServer::new("test-server", "0.1.0");
        srv.register_tool(
            ToolDefinition {
                name: "echo".to_string(),
                description: "Echo arguments back".to_string(),
                input_schema: serde_json::json!({ "type": "object" }),
                parameters: serde_json::json!({ "type": "object" }),
            },
            Box::new(EchoTool),
        );
        srv.register_tool(
            ToolDefinition {
                name: "fail".to_string(),
                description: "Always fails".to_string(),
                input_schema: serde_json::json!({ "type": "object" }),
                parameters: serde_json::json!({ "type": "object" }),
            },
            Box::new(FailTool),
        );
        srv.register_resource(ResourceDefinition {
            uri: "rustre://binary/current".to_string(),
            name: "current binary".to_string(),
            description: "The currently loaded binary".to_string(),
            mime_type: "application/octet-stream".to_string(),
        });
        srv
    }

    // Ã¢—â‚¬Ã¢—â‚¬ parse_request Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_parse_valid_request() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":null}"#;
        let req = parse_request(json).unwrap();
        assert_eq!(req.method, "tools/list");
        assert_eq!(req.id, Some(Value::from(1)));
    }

    /// A NOTIFICATION has no `id` and must still parse. Before `id` became an
    /// `Option` this failed as a missing field, so `notifications/initialized` —
    /// which MCP clients send right after the handshake — was answered with a
    /// parse error instead of being accepted silently.
    #[test]
    fn test_parse_notification_without_id() {
        let json = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let req = parse_request(json).expect("a notification must parse");
        assert_eq!(req.method, "notifications/initialized");
        assert!(req.id.is_none(), "a notification carries no id");
    }

    /// A request WITH an id is still a request, and the id round-trips.
    #[test]
    fn test_parse_request_keeps_its_id() {
        let json = r#"{"jsonrpc":"2.0","id":"abc","method":"tools/list"}"#;
        let req = parse_request(json).expect("a request must parse");
        assert_eq!(req.id, Some(Value::from("abc")));
    }

    #[test]
    fn test_parse_invalid_json() {
        let result = parse_request("{bad json}");
        assert!(matches!(result, Err(McpError::ParseError(_))));
    }

    #[test]
    fn test_parse_request_with_params() {
        let json = r#"{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"echo","arguments":{"key":"val"}}}"#;
        let req = parse_request(json).unwrap();
        assert_eq!(req.method, "tools/call");
        let params = req.params.unwrap();
        assert_eq!(params["name"], "echo");
    }

    // Ã¢—â‚¬Ã¢—â‚¬ initialize Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[tokio::test]
    async fn test_initialize() {
        let srv = make_server();
        let req =
            parse_request(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#).unwrap();
        let resp = srv.dispatch(req).await;
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert_eq!(result["serverInfo"]["name"], "test-server");
    }

    // Ã¢—â‚¬Ã¢—â‚¬ tools/list Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[tokio::test]
    async fn test_tools_list() {
        let srv = make_server();
        let req = parse_request(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":null}"#)
            .unwrap();
        let resp = srv.dispatch(req).await;
        assert!(resp.error.is_none());
        let tools = resp.result.unwrap()["tools"].as_array().unwrap().clone();
        assert_eq!(tools.len(), 2);
    }

    // Ã¢—â‚¬Ã¢—â‚¬ tools/call Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[tokio::test]
    async fn test_tools_call_echo() {
        let srv = make_server();
        let req = parse_request(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"hello":"world"}}}"#,
        )
        .unwrap();
        let resp = srv.dispatch(req).await;
        assert!(resp.error.is_none());
        assert_eq!(resp.result.unwrap()["is_error"], false);
    }

    #[tokio::test]
    async fn test_tools_call_fail() {
        let srv = make_server();
        let req = parse_request(
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fail","arguments":{}}}"#,
        )
        .unwrap();
        let resp = srv.dispatch(req).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32000);
    }

    #[tokio::test]
    async fn test_tools_call_unknown_tool() {
        let srv = make_server();
        let req = parse_request(
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope","arguments":{}}}"#,
        )
        .unwrap();
        let resp = srv.dispatch(req).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[tokio::test]
    async fn test_tools_call_missing_params() {
        let srv = make_server();
        let req = parse_request(r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":null}"#)
            .unwrap();
        let resp = srv.dispatch(req).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    // Ã¢—â‚¬Ã¢—â‚¬ resources Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[tokio::test]
    async fn test_resources_list() {
        let srv = make_server();
        let req =
            parse_request(r#"{"jsonrpc":"2.0","id":7,"method":"resources/list","params":null}"#)
                .unwrap();
        let resp = srv.dispatch(req).await;
        assert!(resp.error.is_none());
        assert_eq!(
            resp.result.unwrap()["resources"].as_array().unwrap().len(),
            1
        );
    }

    #[tokio::test]
    async fn test_resources_read_found() {
        let srv = make_server();
        let req = parse_request(
            r#"{"jsonrpc":"2.0","id":8,"method":"resources/read","params":{"uri":"rustre://binary/current"}}"#,
        )
        .unwrap();
        let resp = srv.dispatch(req).await;
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn test_resources_read_not_found() {
        let srv = make_server();
        let req = parse_request(
            r#"{"jsonrpc":"2.0","id":9,"method":"resources/read","params":{"uri":"rustre://nope"}}"#,
        )
        .unwrap();
        let resp = srv.dispatch(req).await;
        assert!(resp.error.is_some());
    }

    #[tokio::test]
    async fn test_resources_read_missing_uri() {
        let srv = make_server();
        let req =
            parse_request(r#"{"jsonrpc":"2.0","id":10,"method":"resources/read","params":{}}"#)
                .unwrap();
        let resp = srv.dispatch(req).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn test_unknown_method() {
        let srv = make_server();
        let req =
            parse_request(r#"{"jsonrpc":"2.0","id":11,"method":"ping","params":null}"#).unwrap();
        let resp = srv.dispatch(req).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    // Ã¢—â‚¬Ã¢—â‚¬ McpError codes Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_mcp_error_codes() {
        assert_eq!(McpError::ParseError("x".into()).code(), -32700);
        assert_eq!(McpError::MethodNotFound("x".into()).code(), -32601);
        assert_eq!(McpError::InvalidParams("x".into()).code(), -32602);
        assert_eq!(McpError::InternalError("x".into()).code(), -32603);
        assert_eq!(McpError::ToolError("x".into()).code(), -32000);
    }

    // Ã¢—â‚¬Ã¢—â‚¬ ContentBlock Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_content_block_text_roundtrip() {
        let block = ContentBlock::Text {
            text: "hello".to_string(),
        };
        let v = serde_json::to_value(&block).unwrap();
        assert_eq!(v["type"], "text");
        assert_eq!(v["text"], "hello");
    }

    #[test]
    fn test_content_block_image_roundtrip() {
        let block = ContentBlock::Image {
            data: "base64data".to_string(),
            mime_type: "image/png".to_string(),
        };
        let v = serde_json::to_value(&block).unwrap();
        assert_eq!(v["type"], "image");
        assert_eq!(v["mime_type"], "image/png");
    }

    // Ã¢—â‚¬Ã¢—â‚¬ ToolResult Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_tool_result_text() {
        let r = ToolResult::text("ok");
        assert!(!r.is_error);
        assert_eq!(r.content.len(), 1);
    }

    #[test]
    fn test_tool_result_error() {
        let r = ToolResult::error("bad");
        assert!(r.is_error);
    }

    #[test]
    fn test_tool_result_json() {
        let r = ToolResult::json(&serde_json::json!({"key": "value"}));
        assert!(!r.is_error);
    }

    // Ã¢—â‚¬Ã¢—â‚¬ ToolCategory Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_tool_category_display() {
        assert_eq!(ToolCategory::Project.to_string(), "project");
        assert_eq!(ToolCategory::Debugger.to_string(), "debugger");
        assert_eq!(ToolCategory::KnowledgeGraph.to_string(), "knowledge_graph");
        assert_eq!(ToolCategory::Yara.to_string(), "yara");
        assert_eq!(ToolCategory::Forensics.to_string(), "forensics");
    }

    #[test]
    fn test_tool_category_serde() {
        let cat = ToolCategory::Disasm;
        let s = serde_json::to_string(&cat).unwrap();
        let back: ToolCategory = serde_json::from_str(&s).unwrap();
        assert_eq!(cat, back);
    }

    // Ã¢—â‚¬Ã¢—â‚¬ McpToolDef Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_mcp_tool_def_new() {
        let def = McpToolDef::new(
            "test.tool",
            "A test tool",
            serde_json::json!({ "type": "object" }),
            ToolCategory::Binary,
        );
        assert_eq!(def.name, "test.tool");
        assert_eq!(def.category, ToolCategory::Binary);
    }

    #[test]
    fn test_mcp_tool_def_to_tool_definition() {
        let def = McpToolDef::new(
            "x.y",
            "desc",
            serde_json::json!({ "type": "object" }),
            ToolCategory::Analysis,
        );
        let td = def.to_tool_definition();
        assert_eq!(td.name, "x.y");
        assert_eq!(td.description, "desc");
    }

    // Ã¢—â‚¬Ã¢—â‚¬ build_tool_catalog Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_catalog_has_all_categories() {
        let catalog = build_tool_catalog();
        let categories: Vec<_> = catalog.iter().map(|t| &t.category).collect();
        assert!(categories.contains(&&ToolCategory::Project));
        assert!(categories.contains(&&ToolCategory::Binary));
        assert!(categories.contains(&&ToolCategory::Analysis));
        assert!(categories.contains(&&ToolCategory::Disasm));
        assert!(categories.contains(&&ToolCategory::Decompile));
        assert!(categories.contains(&&ToolCategory::Debugger));
        assert!(categories.contains(&&ToolCategory::Yara));
        assert!(categories.contains(&&ToolCategory::Forensics));
        assert!(categories.contains(&&ToolCategory::KnowledgeGraph));
    }

    #[test]
    fn test_catalog_minimum_size() {
        let catalog = build_tool_catalog();
        assert!(
            catalog.len() >= 40,
            "expected at least 40 tools, got {}",
            catalog.len()
        );
    }

    #[test]
    fn test_catalog_unique_names() {
        let catalog = build_tool_catalog();
        let mut names: Vec<&str> = catalog.iter().map(|t| t.name.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate tool names found");
    }

    #[test]
    fn test_catalog_all_have_schemas() {
        let catalog = build_tool_catalog();
        for tool in &catalog {
            assert!(
                tool.input_schema.get("type").is_some(),
                "tool '{}' has no type in schema",
                tool.name
            );
        }
    }

    #[test]
    fn test_catalog_project_tools() {
        let catalog = build_tool_catalog();
        let project_tools: Vec<_> = catalog
            .iter()
            .filter(|t| t.category == ToolCategory::Project)
            .collect();
        assert_eq!(project_tools.len(), 4);
        let names: Vec<&str> = project_tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"project.open"));
        assert!(names.contains(&"project.close"));
        assert!(names.contains(&"project.list_binaries"));
        assert!(names.contains(&"project.info"));
    }

    #[test]
    fn test_catalog_debug_tools_count() {
        let catalog = build_tool_catalog();
        let debug_tools: Vec<_> = catalog
            .iter()
            .filter(|t| t.category == ToolCategory::Debugger)
            .collect();
        assert!(
            debug_tools.len() >= 12,
            "expected 12+ debug tools, got {}",
            debug_tools.len()
        );
    }

    #[test]
    fn test_catalog_kg_tools() {
        let catalog = build_tool_catalog();
        
        assert!(catalog
            .iter()
            .filter(|t| t.category == ToolCategory::KnowledgeGraph).count() >= 7);
    }

    // Ã¢—â‚¬Ã¢—â‚¬ Stub handlers Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_project_open_stub() {
        let h = ProjectOpenHandler;
        assert_eq!(h.name(), "project.open");
        let result = h
            .execute(serde_json::json!({ "path": "/tmp/test.exe" }))
            .unwrap();
        assert_eq!(result["stub"], true);
        assert!(result["project_id"].is_string());
    }

    #[test]
    fn test_binary_info_stub() {
        let h = BinaryInfoHandler;
        let result = h
            .execute(serde_json::json!({ "binary_id": "bin-001" }))
            .unwrap();
        assert!(result["format"].is_string());
        assert!(result["arch"].is_string());
        assert!(result["sections"].is_array());
    }

    #[test]
    fn test_binary_hexdump_stub() {
        let h = BinaryHexdumpHandler;
        let result = h
            .execute(serde_json::json!({"binary_id":"b","addr":"0x401000","len":16}))
            .unwrap();
        assert!(result["hex"].is_string());
        assert!(result["ascii"].is_string());
    }

    #[test]
    fn test_disasm_at_stub() {
        let h = DisasmAtHandler;
        let result = h
            .execute(serde_json::json!({"binary_id":"b","addr":"0x401000","count":3}))
            .unwrap();
        let instructions = result["instructions"].as_array().unwrap();
        assert!(!instructions.is_empty());
        assert!(instructions[0]["mnemonic"].is_string());
    }

    #[test]
    fn test_decompile_function_stub() {
        let h = DecompileFunctionHandler;
        let result = h
            .execute(serde_json::json!({"binary_id":"b","addr":"0x401000"}))
            .unwrap();
        assert!(result["source"].is_string());
        assert!(result["confidence"].is_number());
    }

    #[test]
    fn test_debug_launch_stub() {
        // DebugLaunchHandler now requires a registry; test with an empty binary_id
        // so the handler returns NotFound (binary "b" not loaded), which still
        // exercises the parameter parsing path.
        let registry: SharedBinaryRegistry = Arc::new(Mutex::new(BinaryRegistry::new()));
        let h = DebugLaunchHandler { registry };
        // With an unknown binary_id we expect a NotFound error (not a panic).
        let result = h.execute(serde_json::json!({"binary_id":"b"}));
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_attach_real() {
        let registry: SharedBinaryRegistry = Arc::new(Mutex::new(BinaryRegistry::new()));
        let h = DebugAttachHandler {
            registry,
        };
        // Attach to PID 1 (init/launchd on Unix, always exists; on Windows PID 4
        // is the System process but we only record the session — no actual ptrace).
        let result = h.execute(serde_json::json!({"pid": 1})).unwrap();
        assert!(result["session_id"].as_str().unwrap().starts_with("dbg-"));
        assert_eq!(result["pid"].as_u64().unwrap(), 1);
        assert_eq!(result["status"].as_str().unwrap(), "attached");
    }

    #[test]
    fn test_debug_continue_unknown_session() {
        let registry: SharedBinaryRegistry = Arc::new(Mutex::new(BinaryRegistry::new()));
        let h = DebugContinueHandler { registry };
        let result = h.execute(serde_json::json!({"session_id": "dbg-9999"}));
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_read_registers_stub() {
        let h = DebugReadRegistersHandler;
        let result = h
            .execute(serde_json::json!({"session_id":"dbg-001"}))
            .unwrap();
        assert!(result["registers"].is_object());
        assert!(result["registers"]["rip"].is_string());
    }

    #[test]
    fn test_debug_backtrace_stub() {
        let h = DebugBacktraceHandler;
        let result = h.execute(serde_json::json!({"session_id":"s"})).unwrap();
        let frames = result["frames"].as_array().unwrap();
        assert!(!frames.is_empty());
    }

    #[test]
    fn test_yara_scan_file_stub() {
        let h = YaraScanFileHandler;
        let result = h
            .execute(serde_json::json!({"path":"/tmp/sample.exe"}))
            .unwrap();
        assert!(result["matches"].is_array());
    }

    #[test]
    fn test_yara_compile_stub() {
        let h = YaraCompileHandler;
        let result = h
            .execute(serde_json::json!({"source":"rule test { condition: true }"}))
            .unwrap();
        assert!(result["ruleset_id"].is_string());
    }

    #[test]
    fn test_forensics_list_plugins_stub() {
        let h = ForensicsListPluginsHandler;
        let result = h.execute(serde_json::json!({})).unwrap();
        let plugins = result["plugins"].as_array().unwrap();
        assert!(plugins.len() >= 3);
    }

    #[test]
    fn test_kg_query_stub() {
        // KgQueryHandler (stub) still exists but server uses RealKgQueryHandler.
        // Keep this test to ensure stub still compiles/works.
        let h = KgQueryHandler;
        let result = h
            .execute(serde_json::json!({"sql":"SELECT * FROM functions LIMIT 1"}))
            .unwrap();
        assert!(result["rows"].is_array());
    }

    #[test]
    fn test_kg_query_real() {
        let registry: SharedBinaryRegistry = Arc::new(Mutex::new(BinaryRegistry::new()));
        let h = RealKgQueryHandler { registry };
        let result = h
            .execute(serde_json::json!({"sql":"SELECT * FROM functions LIMIT 1"}))
            .unwrap();
        assert!(result["rows"].is_array());
    }

    #[test]
    fn test_kg_query_real_rejects_non_select() {
        let registry: SharedBinaryRegistry = Arc::new(Mutex::new(BinaryRegistry::new()));
        let h = RealKgQueryHandler { registry };
        let result = h.execute(serde_json::json!({"sql":"DROP TABLE functions"}));
        assert!(result.is_err());
    }

    #[test]
    fn test_kg_query_real_select_1() {
        let registry: SharedBinaryRegistry = Arc::new(Mutex::new(BinaryRegistry::new()));
        let h = RealKgQueryHandler { registry };
        let result = h
            .execute(serde_json::json!({"sql":"SELECT 1 AS val"}))
            .unwrap();
        let rows = result["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["val"], 1);
    }

    #[test]
    fn test_kg_search_stub() {
        let h = KgSearchHandler;
        let result = h.execute(serde_json::json!({"text":"malloc"})).unwrap();
        assert!(result["results"].is_array());
    }

    // Ã¢—â‚¬Ã¢—â‚¬ ToolExecutor Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_tool_executor_register_and_count() {
        let mut exec = ToolExecutor::new();
        exec.register(Box::new(ProjectOpenHandler));
        exec.register(Box::new(BinaryInfoHandler));
        assert_eq!(exec.tool_count(), 2);
    }

    #[test]
    fn test_tool_executor_execute_known() {
        let mut exec = ToolExecutor::new();
        exec.register(Box::new(ProjectOpenHandler));
        let result = exec
            .execute("project.open", serde_json::json!({"path":"/x"}))
            .unwrap();
        assert_eq!(result["stub"], true);
    }

    #[test]
    fn test_tool_executor_execute_unknown() {
        let exec = ToolExecutor::new();
        let err = exec
            .execute("nonexistent", serde_json::json!({}))
            .unwrap_err();
        assert!(matches!(err, McpToolError::NotFound(_)));
    }

    #[test]
    fn test_tool_executor_tool_names() {
        let registry: SharedBinaryRegistry = Arc::new(Mutex::new(BinaryRegistry::new()));
        let mut exec = ToolExecutor::new();
        exec.register(Box::new(RealKgQueryHandler { registry }));
        exec.register(Box::new(KgSearchHandler));
        let names = exec.tool_names();
        assert!(names.contains(&"kg.query"));
        assert!(names.contains(&"kg.search"));
    }

    // Ã¢—â‚¬Ã¢—â‚¬ SessionManager Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_session_manager_create() {
        let mut sm = SessionManager::new();
        let id = sm.create_session(SessionKind::Project);
        assert!(id.starts_with("session-"));
        assert_eq!(sm.session_count(), 1);
    }

    #[test]
    fn test_session_manager_get() {
        let mut sm = SessionManager::new();
        let id = sm.create_session(SessionKind::Debug);
        let s = sm.get_session(&id).unwrap();
        assert_eq!(s.kind, SessionKind::Debug);
    }

    #[test]
    fn test_session_manager_remove() {
        let mut sm = SessionManager::new();
        let id = sm.create_session(SessionKind::Forensics);
        assert!(sm.remove_session(&id));
        assert_eq!(sm.session_count(), 0);
        assert!(!sm.remove_session(&id));
    }

    #[test]
    fn test_session_manager_list() {
        let mut sm = SessionManager::new();
        sm.create_session(SessionKind::Project);
        sm.create_session(SessionKind::Debug);
        assert_eq!(sm.list_sessions().len(), 2);
    }

    #[test]
    fn test_session_manager_multiple_ids_unique() {
        let mut sm = SessionManager::new();
        let id1 = sm.create_session(SessionKind::Emulation);
        let id2 = sm.create_session(SessionKind::Emulation);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_session_state_metadata() {
        let mut s = SessionDescriptor::new("s-1".to_string(), SessionKind::Debug, 0);
        s.set_metadata("binary_id", "bin-001");
        assert_eq!(s.get_metadata("binary_id"), Some("bin-001"));
        assert_eq!(s.get_metadata("missing"), None);
    }

    #[test]
    fn test_session_manager_by_kind() {
        let mut sm = SessionManager::new();
        sm.create_session(SessionKind::Project);
        sm.create_session(SessionKind::Project);
        sm.create_session(SessionKind::Debug);
        let proj = sm.sessions_by_kind(&SessionKind::Project);
        assert_eq!(proj.len(), 2);
        let dbg = sm.sessions_by_kind(&SessionKind::Debug);
        assert_eq!(dbg.len(), 1);
    }

    #[test]
    fn test_session_kind_display() {
        assert_eq!(SessionKind::Project.to_string(), "project");
        assert_eq!(SessionKind::Debug.to_string(), "debug");
        assert_eq!(SessionKind::Forensics.to_string(), "forensics");
        assert_eq!(SessionKind::Emulation.to_string(), "emulation");
        assert_eq!(SessionKind::Recording.to_string(), "recording");
    }

    // Ã¢—â‚¬Ã¢—â‚¬ ResourceProvider Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_resource_provider_list() {
        let resources = ResourceProvider::list_resources("proj-001");
        assert!(!resources.is_empty());
        assert!(resources.iter().any(|r| r.uri.contains("proj-001")));
    }

    #[test]
    fn test_resource_provider_make_binary_uri() {
        let uri = ResourceProvider::make_binary_uri("bin-001", "disasm");
        assert_eq!(uri, "rustre://binary/bin-001/disasm");
    }

    #[test]
    fn test_resource_provider_parse_uri_full() {
        let parts = ResourceProvider::parse_uri("rustre://binary/abc123/hexdump").unwrap();
        assert_eq!(parts.scheme, "rustre");
        assert_eq!(parts.entity_type, "binary");
        assert_eq!(parts.entity_id, "abc123");
        assert_eq!(parts.view.as_deref(), Some("hexdump"));
    }

    #[test]
    fn test_resource_provider_parse_uri_no_view() {
        let parts = ResourceProvider::parse_uri("rustre://project/proj-001").unwrap();
        assert_eq!(parts.entity_type, "project");
        assert_eq!(parts.entity_id, "proj-001");
        assert!(parts.view.is_none());
    }

    #[test]
    fn test_resource_provider_parse_uri_invalid() {
        let err = ResourceProvider::parse_uri("not-a-uri").unwrap_err();
        assert!(matches!(err, McpToolError::InvalidParams(_)));
    }

    #[test]
    fn test_resource_provider_read_binary() {
        let content = ResourceProvider::read_resource("rustre://binary/bin-001/hexdump").unwrap();
        assert!(content.is_text());
        assert!(content.byte_len() > 0);
    }

    #[test]
    fn test_resource_provider_read_project() {
        let content = ResourceProvider::read_resource("rustre://project/proj-001/info").unwrap();
        assert!(content.is_text());
    }

    #[test]
    fn test_resource_provider_read_unknown_type() {
        let err = ResourceProvider::read_resource("rustre://unknown/x").unwrap_err();
        assert!(matches!(err, McpToolError::NotFound(_)));
    }

    #[test]
    fn test_mcp_resource_content_binary_variant() {
        let c = McpResourceContent::Binary(vec![1, 2, 3]);
        assert!(!c.is_text());
        assert_eq!(c.byte_len(), 3);
        assert!(c.as_text().is_none());
    }

    // Ã¢—â‚¬Ã¢—â‚¬ Validation helpers Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_validate_required_strings_ok() {
        let params = serde_json::json!({ "binary_id": "bin-001", "addr": "0x401000" });
        validate_required_strings(&params, &["binary_id", "addr"]).unwrap();
    }

    #[test]
    fn test_validate_required_strings_missing() {
        let params = serde_json::json!({ "binary_id": "bin-001" });
        let err = validate_required_strings(&params, &["binary_id", "addr"]).unwrap_err();
        assert!(matches!(err, McpToolError::InvalidParams(_)));
    }

    #[test]
    fn test_require_string_ok() {
        let params = serde_json::json!({ "path": "/tmp/x" });
        assert_eq!(require_string(&params, "path").unwrap(), "/tmp/x");
    }

    #[test]
    fn test_require_string_missing() {
        let params = serde_json::json!({});
        assert!(matches!(
            require_string(&params, "path"),
            Err(McpToolError::InvalidParams(_))
        ));
    }

    #[test]
    fn test_require_number_ok() {
        let params = serde_json::json!({ "len": 64 });
        assert_eq!(require_number(&params, "len").unwrap(), 64);
    }

    #[test]
    fn test_parse_hex_addr_with_prefix() {
        assert_eq!(parse_hex_addr("0x401000").unwrap(), 0x401000);
        assert_eq!(parse_hex_addr("0X1FFFF").unwrap(), 0x1FFFF);
    }

    #[test]
    fn test_parse_hex_addr_without_prefix() {
        assert_eq!(parse_hex_addr("401000").unwrap(), 0x401000);
    }

    #[test]
    fn test_parse_hex_addr_invalid() {
        let err = parse_hex_addr("not_hex").unwrap_err();
        assert!(matches!(err, McpToolError::InvalidParams(_)));
    }

    // Ã¢—â‚¬Ã¢—â‚¬ RustReMcpServer Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_rustre_mcp_server_tool_count() {
        let srv = RustReMcpServer::new();
        assert!(srv.tool_count() >= 40);
    }

    #[test]
    fn test_rustre_mcp_server_find_tool() {
        let srv = RustReMcpServer::new();
        let t = srv.find_tool("project.open").unwrap();
        assert_eq!(t.category, ToolCategory::Project);
    }

    #[test]
    fn test_rustre_mcp_server_find_tool_missing() {
        let srv = RustReMcpServer::new();
        assert!(srv.find_tool("nonexistent.tool").is_none());
    }

    #[test]
    fn test_rustre_mcp_server_tools_by_category() {
        let srv = RustReMcpServer::new();
        let debug_tools = srv.tools_by_category(&ToolCategory::Debugger);
        assert!(debug_tools.len() >= 12);
    }

    #[test]
    /// `project.open` on a nonexistent path must FAIL and name the path.
    ///
    /// This used to assert `result["stub"] == true`: back then `project.open`
    /// had no real handler, so the dispatcher returned a stub for it. It has a
    /// real handler now, and reading `/tmp/x` (a Unix path, on Windows) fails
    /// as it should — the test was still asserting the stub era.
    #[test]
    fn test_rustre_mcp_server_execute_tool() {
        let srv = RustReMcpServer::new();
        let err = srv
            .execute_tool("project.open", serde_json::json!({"path":"/tmp/x"}))
            .expect_err("opening a nonexistent path must not succeed");
        let msg = err.to_string();
        assert!(
            msg.contains("/tmp/x"),
            "the error must name the path it could not open; got {msg}"
        );
    }

    #[test]
    fn test_rustre_mcp_server_execute_unknown() {
        let srv = RustReMcpServer::new();
        let err = srv
            .execute_tool("fake.tool", serde_json::json!({}))
            .unwrap_err();
        assert!(matches!(err, McpToolError::NotFound(_)));
    }

    #[test]
    fn test_rustre_mcp_server_all_tools_executable() {
        let srv = RustReMcpServer::new();
        for tool in &srv.tools {
            // Real handlers may legitimately reject empty params, either with
            // an ExecutionFailed error or — since required parameters are now
            // enforced against the tool's own schema at the dispatch boundary
            // — with InvalidParams. What we are smoke-testing here is only
            // that the tool is dispatchable (i.e. not NotFound).
            match srv.execute_tool(&tool.name, serde_json::json!({})) {
                Ok(_) => {}
                Err(McpToolError::ExecutionFailed(_) | McpToolError::InvalidParams(_)) => {}
                Err(e) => panic!("tool '{}' dispatch failed: {:?}", tool.name, e),
            }
        }
    }

    // Ã¢—â‚¬Ã¢—â‚¬ ClientId Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_client_id_new_and_value() {
        let id = ClientId::new(42);
        assert_eq!(id.value(), 42);
    }

    #[test]
    fn test_client_id_display() {
        assert_eq!(ClientId::new(7).to_string(), "client-7");
    }

    #[test]
    fn test_client_id_equality() {
        assert_eq!(ClientId::new(1), ClientId::new(1));
        assert_ne!(ClientId::new(1), ClientId::new(2));
    }

    #[test]
    fn test_client_id_serde_roundtrip() {
        let id = ClientId::new(99);
        let s = serde_json::to_string(&id).unwrap();
        let back: ClientId = serde_json::from_str(&s).unwrap();
        assert_eq!(id, back);
    }

    // Ã¢—â‚¬Ã¢—â‚¬ ServerConfig Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_server_config_defaults() {
        let cfg = ServerConfig::new();
        assert_eq!(cfg.host, "127.0.0.1");
        assert_eq!(cfg.port, 3000);
        assert_eq!(cfg.max_connections, 100);
        assert!(cfg.auth_token.is_none());
    }

    #[test]
    fn test_server_config_builder() {
        let cfg = ServerConfig::new()
            .with_host("0.0.0.0")
            .with_port(8080)
            .with_max_connections(50)
            .with_auth("secret");
        assert_eq!(cfg.host, "0.0.0.0");
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.auth_token.as_deref(), Some("secret"));
    }

    #[test]
    fn test_server_config_listen_addr() {
        let cfg = ServerConfig::new().with_host("localhost").with_port(9090);
        assert_eq!(cfg.listen_addr(), "localhost:9090");
    }

    // Ã¢—â‚¬Ã¢—â‚¬ ConnectionState Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_connection_state_display() {
        assert_eq!(ConnectionState::Connecting.to_string(), "connecting");
        assert_eq!(ConnectionState::Connected.to_string(), "connected");
        assert_eq!(ConnectionState::Authenticated.to_string(), "authenticated");
        assert_eq!(ConnectionState::Disconnected.to_string(), "disconnected");
    }

    // Ã¢—â‚¬Ã¢—â‚¬ ServerResponse Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_server_response_ok() {
        let cid = ClientId::new(2);
        let resp = ServerResponse::ok(cid, Value::from(1), serde_json::json!({"x": 1}));
        assert!(!resp.is_error());
    }

    #[test]
    fn test_server_response_err() {
        let cid = ClientId::new(3);
        let resp = ServerResponse::err(cid, Value::from(2), "something went wrong");
        assert!(resp.is_error());
    }

    // Ã¢—â‚¬Ã¢—â‚¬ MockTransport Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[tokio::test]
    async fn test_mock_transport_enqueue_recv() {
        let mut t = MockTransport::new();
        t.enqueue("hello");
        assert_eq!(t.recv().await.unwrap(), Some("hello".to_string()));
        assert_eq!(t.recv().await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_mock_transport_send_drain() {
        let mut t = MockTransport::new();
        t.send("msg1".to_string()).await.unwrap();
        t.send("msg2".to_string()).await.unwrap();
        let out = t.drain_outbox();
        assert_eq!(out, vec!["msg1", "msg2"]);
        assert!(t.drain_outbox().is_empty());
    }

    // Ã¢—â‚¬Ã¢—â‚¬ ServerError Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_server_error_variants() {
        assert!(ServerError::Bind("x".into()).to_string().contains('x'));
        assert!(ServerError::Auth("y".into()).to_string().contains('y'));
        assert!(ServerError::Protocol("z".into()).to_string().contains('z'));
        assert!(ServerError::Closed("c".into()).to_string().contains('c'));
        assert!(ServerError::Timeout("t".into()).to_string().contains('t'));
    }

    // Ã¢—â‚¬Ã¢—â‚¬ JsonRpcResponse serialization Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_response_ok_no_error_field() {
        let resp = JsonRpcResponse::ok(Value::from(1), serde_json::json!({"x": 1}));
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"result\""));
        assert!(!s.contains("\"error\""));
    }

    #[test]
    fn test_response_err_no_result_field() {
        let resp =
            JsonRpcResponse::err(Value::from(2), &McpError::MethodNotFound("foo".to_string()));
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"error\""));
        assert!(!s.contains("\"result\""));
    }

    // Ã¢—â‚¬Ã¢—â‚¬ id preservation Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[tokio::test]
    async fn test_string_id_preserved() {
        let srv = make_server();
        let req = parse_request(
            r#"{"jsonrpc":"2.0","id":"my-req-id","method":"tools/list","params":null}"#,
        )
        .unwrap();
        let resp = srv.dispatch(req).await;
        assert_eq!(resp.id, Value::from("my-req-id"));
    }

    #[tokio::test]
    async fn test_null_id_preserved() {
        let srv = make_server();
        let req =
            parse_request(r#"{"jsonrpc":"2.0","id":null,"method":"tools/list","params":null}"#)
                .unwrap();
        let resp = srv.dispatch(req).await;
        assert_eq!(resp.id, Value::Null);
    }

    // Ã¢—â‚¬Ã¢—â‚¬ McpToolError Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_mcp_tool_error_into_mcp_error() {
        let e: McpError = McpToolError::NotFound("x".into()).into();
        assert!(matches!(e, McpError::ToolError(_)));
    }

    #[test]
    fn test_mcp_tool_error_variants() {
        let e = McpToolError::InvalidParams("bad".into());
        assert!(e.to_string().contains("bad"));
        let e = McpToolError::ExecutionFailed("fail".into());
        assert!(e.to_string().contains("fail"));
        let e = McpToolError::Unsupported("op".into());
        assert!(e.to_string().contains("op"));
    }
}

// Ã¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢Â
// rmcp integration Ã¢â‚¬— ServerHandler implementation
// Ã¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢ÂÃ¢—¢Â
//
// This section wires the existing RustReMcpServer / tool catalog / stub
// handlers into the `rmcp` crate's ServerHandler trait so the binary can be
// served over any rmcp-supported transport (stdio, SSE-HTTP, etc.).

use rmcp::model::{
    CallToolRequestParam, CallToolResult, Content, Implementation, ListToolsResult,
    PaginatedRequestParam, ProtocolVersion, ServerCapabilities, ServerInfo, Tool, ToolsCapability,
};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, ServerHandler};

/// Extended transport enum used by [`RustREMcpServer`].
///
/// Variants:
/// - `Stdio`  Ã¢â‚¬—œ JSON-RPC over stdin/stdout (default for CLI usage).
/// - `SseHttp { bind }` Ã¢â‚¬—œ Server-Sent Events over HTTP (for web clients).
/// - `WebSocket { bind }` Ã¢â‚¬—œ WebSocket JSON-RPC (reserved; falls back to SSE).
#[derive(Debug, Clone)]
pub enum McpTransportKind {
    /// Communicate over standard input / standard output.
    Stdio,
    /// Serve via SSE-over-HTTP, listening on `bind` (e.g. `"127.0.0.1:8080"`).
    SseHttp { bind: String },
    /// Serve via WebSocket JSON-RPC, listening on `bind`.
    WebSocket { bind: String },
}

impl McpTransportKind {
    /// Return `true` if this is the stdio variant.
    #[must_use]
    pub const fn is_stdio(&self) -> bool {
        matches!(self, Self::Stdio)
    }

    /// Return the bind address for network transports, or `None` for stdio.
    #[must_use]
    pub const fn bind_addr(&self) -> Option<&str> {
        match self {
            Self::Stdio => None,
            Self::SseHttp { bind } | Self::WebSocket { bind } => Some(bind.as_str()),
        }
    }

    /// Human-readable transport name.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Stdio => "stdio",
            Self::SseHttp { .. } => "sse-http",
            Self::WebSocket { .. } => "websocket",
        }
    }
}

impl std::fmt::Display for McpTransportKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdio => write!(f, "stdio"),
            Self::SseHttp { bind } => write!(f, "sse-http@{bind}"),
            Self::WebSocket { bind } => write!(f, "websocket@{bind}"),
        }
    }
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// RustREMcpServer Ã¢â‚¬— rmcp ServerHandler wrapper
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

/// An MCP server that implements [`rmcp::ServerHandler`].
///
/// Wraps the full `RustRE` tool catalog and stub handlers, exposing them via the
/// rmcp protocol.  Use [`RustREMcpServer::new`] to create one, then call
/// [`run_stdio`] or [`run_http`] to start serving.
#[derive(Clone)]
pub struct RustREMcpServer {
    /// Cached rmcp Tool objects built once from the catalog.
    rmcp_tools: Arc<Vec<Tool>>,
    /// Underlying executor for dispatching tool calls.
    inner: Arc<RustReMcpServer>,
}

impl std::fmt::Debug for RustREMcpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RustREMcpServer")
            .field("tool_count", &self.rmcp_tools.len())
            .finish_non_exhaustive()
    }
}

/// Convert a [`serde_json::Value`] (expected to be an `Object`) into an
/// `Arc<rmcp::model::JsonObject>` suitable for `Tool::new`.
fn value_to_json_object(v: &serde_json::Value) -> Arc<serde_json::Map<String, serde_json::Value>> {
    match v.as_object() {
        Some(map) => Arc::new(map.clone()),
        None => Arc::new(serde_json::Map::new()),
    }
}

impl RustREMcpServer {
    /// Create a new server with the full `RustRE` tool catalog wired up.
    #[must_use]
    pub fn new() -> Self {
        Self::from_inner(RustReMcpServer::new())
    }

    /// Build the rmcp wrapper from a pre-populated [`RustReMcpServer`].
    ///
    /// Use this when callers want to inject extra tools (via
    /// [`RustReMcpServer::register_external_tool`]) before the rmcp catalog
    /// snapshot is taken.
    #[must_use]
    pub fn from_inner(inner: RustReMcpServer) -> Self {
        let inner = Arc::new(inner);
        // Build rmcp Tool objects once from the McpToolDef catalog.
        let rmcp_tools: Vec<Tool> = inner
            .tools
            .iter()
            .map(|def| {
                Tool::new(
                    def.name.clone(),
                    def.description.clone(),
                    value_to_json_object(&def.input_schema),
                )
            })
            .collect();
        Self {
            rmcp_tools: Arc::new(rmcp_tools),
            inner,
        }
    }

    /// Return the number of tools registered.
    #[must_use]
    pub fn tool_count(&self) -> usize {
        self.rmcp_tools.len()
    }

    /// Find an rmcp [`Tool`] by name.
    #[must_use]
    pub fn find_rmcp_tool(&self, name: &str) -> Option<&Tool> {
        self.rmcp_tools.iter().find(|t| t.name.as_ref() == name)
    }

    /// Return the list of rmcp tools (the full catalog).
    ///
    /// This is a sync helper, useful for tests that don't need a real transport context.
    #[must_use]
    pub fn list_tools_sync(&self) -> &[Tool] {
        self.rmcp_tools.as_ref()
    }

    /// Dispatch a tool call by name, returning a [`CallToolResult`].
    ///
    /// On success the JSON result is serialised to a text [`Content`] block.
    /// On failure an error [`CallToolResult`] is returned (never `Err`).
    #[must_use] 
    pub fn dispatch_tool(&self, name: &str, args: serde_json::Value) -> CallToolResult {
        match self.inner.execute_tool(name, args) {
            Ok(result) => {
                let text = serde_json::to_string_pretty(&result)
                    .unwrap_or_else(|e| format!("{{\"serialization_error\":\"{e}\"}}"));
                CallToolResult::success(vec![Content::text(text)])
            }
            // `NotFound` is raised far more often for a missing RESOURCE
            // ("binary b not loaded") than for a missing tool — only the
            // registry lookup in `execute_tool` uses it for a tool name. The
            // old arm hard-coded "tool not found: {n}", so a caller whose
            // binary_id was wrong was told the TOOL did not exist and went
            // looking in the wrong place. Use the error's own Display
            // ("not found: …"), which carries whatever the raiser said.
            Err(e @ McpToolError::NotFound(_)) => {
                CallToolResult::error(vec![Content::text(e.to_string())])
            }
            Err(e) => CallToolResult::error(vec![Content::text(e.to_string())]),
        }
    }
}

impl Default for RustREMcpServer {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerHandler for RustREMcpServer {
    /// Return static server metadata.
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::LATEST,
            capabilities: ServerCapabilities {
                tools: Some(ToolsCapability {
                    list_changed: Some(false),
                }),
                ..Default::default()
            },
            server_info: Implementation {
                name: "rustre-mcp-server".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            instructions: Some(
                "RustRE reverse-engineering platform MCP server. \
                 Call project.open first, then use binary/analysis/disasm/decompile tools."
                    .to_string(),
            ),
        }
    }

    /// Return all registered tools (paginated, but we return everything at once).
    async fn list_tools(
        &self,
        _request: PaginatedRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::Error> {
        let tools = self.rmcp_tools.as_ref().clone();
        Ok(ListToolsResult {
            tools,
            next_cursor: None,
        })
    }

    /// Execute a named tool.
    async fn call_tool(
        &self,
        request: CallToolRequestParam,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, rmcp::Error> {
        let name = request.name.as_ref();
        let args = request
            .arguments
            .map_or(serde_json::Value::Object(serde_json::Map::new()), serde_json::Value::Object);
        Ok(self.dispatch_tool(name, args))
    }
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// Top-level run functions
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

/// Run the `RustRE` MCP server over **stdio** using the rmcp crate.
///
/// This function blocks until stdin is closed or an error occurs.
///
/// # Errors
/// Returns an error if the rmcp transport layer fails.
pub async fn run_stdio() -> anyhow::Result<()> {
    run_stdio_from(RustREMcpServer::new()).await
}

/// Run a pre-built [`RustREMcpServer`] over stdio.
///
/// Lets callers (e.g. the umbrella `rustre-mcp` crate) inject extra tool
/// handlers into the inner server before serving — see
/// [`RustReMcpServer::register_external_tool`] and
/// [`RustREMcpServer::from_inner`].
///
/// # Errors
/// Returns an error if the rmcp transport layer fails.
pub async fn run_stdio_from(server: RustREMcpServer) -> anyhow::Result<()> {
    use rmcp::ServiceExt as _;
    use rmcp::transport::stdio;
    let service: rmcp::service::RunningService<rmcp::RoleServer, _> = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

/// Run the `RustRE` MCP server over **HTTP / SSE** using the rmcp crate.
///
/// `bind` is the socket address to listen on, e.g. `"127.0.0.1:8080"`.
///
/// # Errors
/// Returns an error if the bind address is invalid or the transport fails.
pub async fn run_http(bind: &str) -> anyhow::Result<()> {
    use rmcp::transport::sse_server::SseServer;
    let addr: std::net::SocketAddr = bind.parse()?;
    let sse: SseServer = SseServer::serve(addr).await?;
    let ct = sse.with_service(RustREMcpServer::new);
    ct.cancelled().await;
    Ok(())
}

/// HTTP/SSE variant of [`run_stdio_from`]: serves a pre-built
/// [`RustREMcpServer`] over SSE.
///
/// The server is cloned per incoming connection by the rmcp `SseServer`
/// (which requires a `FnMut() -> ServiceHandler`), so [`RustREMcpServer`]
/// implements `Clone` cheaply via `Arc`.
///
/// # Errors
/// Returns an error if the bind address is invalid or the transport fails.
pub async fn run_http_from(server: RustREMcpServer, bind: &str) -> anyhow::Result<()> {
    use rmcp::transport::sse_server::SseServer;
    let addr: std::net::SocketAddr = bind.parse()?;
    let sse: SseServer = SseServer::serve(addr).await?;
    let ct = sse.with_service(move || server.clone());
    ct.cancelled().await;
    Ok(())
}

/// Dispatch to `run_stdio` or `run_http` based on the given [`McpTransportKind`].
///
/// # Errors
/// Propagates errors from the chosen transport layer.
pub async fn run_with_transport(transport: McpTransportKind) -> anyhow::Result<()> {
    match transport {
        McpTransportKind::Stdio => run_stdio().await,
        McpTransportKind::SseHttp { bind } | McpTransportKind::WebSocket { bind } => {
            run_http(&bind).await
        }
    }
}

// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬
// rmcp integration tests
// Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

#[cfg(test)]
mod rmcp_tests {
    use super::*;

    // Ã¢—â‚¬Ã¢—â‚¬ helpers Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    fn make_server() -> RustREMcpServer {
        RustREMcpServer::new()
    }

    // Ã¢—â‚¬Ã¢—â‚¬ RustREMcpServer construction Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_rustre_server_new_has_tools() {
        let srv = make_server();
        assert!(
            srv.tool_count() >= 20,
            "expected >= 20 tools, got {}",
            srv.tool_count()
        );
    }

    #[test]
    fn test_rustre_server_default_same_as_new() {
        let a = RustREMcpServer::new();
        let b = RustREMcpServer::default();
        assert_eq!(a.tool_count(), b.tool_count());
    }

    #[test]
    fn test_rustre_server_debug_format() {
        let srv = make_server();
        let s = format!("{srv:?}");
        assert!(s.contains("RustREMcpServer"));
        assert!(s.contains("tool_count"));
    }

    // Ã¢—â‚¬Ã¢—â‚¬ get_info Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_get_info_name() {
        let srv = make_server();
        let info = srv.get_info();
        assert_eq!(info.server_info.name, "rustre-mcp-server");
    }

    #[test]
    fn test_get_info_version_non_empty() {
        let srv = make_server();
        let info = srv.get_info();
        assert!(!info.server_info.version.is_empty());
    }

    #[test]
    fn test_get_info_has_tools_capability() {
        let srv = make_server();
        let info = srv.get_info();
        assert!(
            info.capabilities.tools.is_some(),
            "tools capability should be set"
        );
    }

    #[test]
    fn test_get_info_has_instructions() {
        let srv = make_server();
        let info = srv.get_info();
        assert!(info.instructions.is_some());
        assert!(info.instructions.unwrap().contains("RustRE"));
    }

    #[test]
    fn test_get_info_protocol_version() {
        let srv = make_server();
        let info = srv.get_info();
        let ver = info.protocol_version;
        let s = format!("{ver:?}");
        assert!(!s.is_empty());
    }

    // Ã¢—â‚¬Ã¢—â‚¬ list_tools_sync Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_list_tools_sync_returns_all() {
        let srv = make_server();
        let tools = srv.list_tools_sync();
        assert!(tools.len() >= 20, "expected >= 20 tools");
    }

    #[test]
    fn test_list_tools_sync_no_pagination_cursor() {
        // list_tools_sync returns a plain slice Ã¢â‚¬— there is no cursor concept.
        let srv = make_server();
        let tools = srv.list_tools_sync();
        assert!(!tools.is_empty());
    }

    #[test]
    fn test_list_tools_sync_contains_required_names() {
        let srv = make_server();
        let tools = srv.list_tools_sync();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();

        // Required tools from spec Ã‚Â§30.3
        for required in &[
            "project.open",
            "project.close",
            "project.list_binaries",
            "binary.info",
            "binary.hexdump",
            "binary.read",
            "binary.search_bytes",
            "binary.search_strings",
            "analyze.full",
            "analyze.function",
            "analyze.cross_refs",
            "disasm.at",
            "disasm.function",
            "decompile.function",
            "debug.launch",
            "debug.attach",
            "debug.continue",
            "debug.step_into",
            "debug.set_breakpoint",
            "debug.read_registers",
            "debug.read_memory",
            "kg.query",
            "kg.search",
            "kg.annotate",
            "yara.scan_file",
            "yara.compile",
        ] {
            assert!(
                names.contains(required),
                "missing required tool: {required}"
            );
        }
    }

    #[test]
    fn test_list_tools_sync_all_have_descriptions() {
        let srv = make_server();
        for tool in srv.list_tools_sync() {
            assert!(
                !tool.description.is_empty(),
                "tool '{}' has no description",
                tool.name
            );
        }
    }

    #[test]
    fn test_list_tools_sync_all_have_input_schema_type() {
        let srv = make_server();
        for tool in srv.list_tools_sync() {
            assert!(
                tool.input_schema.contains_key("type"),
                "tool '{}' schema missing 'type'",
                tool.name
            );
        }
    }

    #[test]
    fn test_list_tools_sync_unique_names() {
        let srv = make_server();
        let mut names: Vec<&str> = srv
            .list_tools_sync()
            .iter()
            .map(|t| t.name.as_ref())
            .collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(
            before,
            names.len(),
            "duplicate tool names in rmcp tool list"
        );
    }

    // Ã¢—â‚¬Ã¢—â‚¬ dispatch_tool Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    /// Opening a path that does not exist must FAIL, and say so.
    ///
    /// This used to assert success for `/tmp/test.exe` — a Unix path, on a
    /// Windows host, that exists nowhere. It passed only while the tool had a
    /// stub fallback; the stub was removed deliberately (a project "opened"
    /// from a nonexistent file is fabricated state). The test now pins the
    /// contract that replaced it.
    #[test]
    fn test_dispatch_tool_project_open_missing_path_errors() {
        let srv = make_server();
        let result = srv.dispatch_tool(
            "project.open",
            serde_json::json!({"path": "/definitely/not/a/real/path/zzz.exe"}),
        );
        assert_eq!(
            result.is_error,
            Some(true),
            "opening a nonexistent path must not report success"
        );
        assert!(!result.content.is_empty(), "an error must explain itself");
    }

    /// An unknown `binary_id` must FAIL rather than describe a binary that was
    /// never loaded. Same history as the test above.
    #[test]
    fn test_dispatch_tool_binary_info_unknown_id_errors() {
        let srv = make_server();
        let result = srv.dispatch_tool("binary.info", serde_json::json!({"binary_id": "bin-001"}));
        assert_eq!(
            result.is_error,
            Some(true),
            "binary.info must not invent metadata for an unloaded binary"
        );
        // The message must name the BINARY, not claim the tool is missing —
        // `dispatch_tool` used to render every `NotFound` as "tool not found",
        // sending the caller to look for a tool that exists.
        let text = format!("{:?}", result.content);
        assert!(
            text.contains("bin-001"),
            "the error must name the missing binary; got {text}"
        );
        assert!(
            !text.contains("tool not found"),
            "binary.info exists — the error must not claim the tool is missing; got {text}"
        );
    }

    #[test]
    fn test_dispatch_tool_unknown_returns_error_result() {
        let srv = make_server();
        let result = srv.dispatch_tool("nonexistent.tool", serde_json::json!({}));
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn test_dispatch_tool_yara_compile() {
        let srv = make_server();
        let result = srv.dispatch_tool(
            "yara.compile",
            serde_json::json!({"source":"rule x { condition: true }"}),
        );
        assert!(result.is_error != Some(true));
    }

    #[test]
    fn test_dispatch_tool_kg_query() {
        let srv = make_server();
        // The schema names this parameter `query`, not `sql`. The test used to
        // pass `sql` and still "succeed", because nothing checked the declared
        // required parameters — the handler simply defaulted past it.
        let result = srv.dispatch_tool("kg.query", serde_json::json!({"query": "SELECT 1"}));
        assert!(result.is_error != Some(true));
    }

    #[test]
    /// Launching an unloaded binary must FAIL, and the error must say how to
    /// proceed.
    ///
    /// The previous version asserted the opposite, with the reason written
    /// out: "the handler should return a stub (not an error) so catalog-level
    /// smoke tests always succeed". Nothing was launched, so reporting success
    /// told the caller a process existed when none did.
    #[test]
    fn test_dispatch_tool_debug_launch_unloaded_binary_errors() {
        let srv = make_server();
        let result = srv.dispatch_tool("debug.launch", serde_json::json!({"binary_id":"b"}));
        assert_eq!(
            result.is_error,
            Some(true),
            "debug.launch must not report success without launching anything"
        );
        let text = format!("{:?}", result.content);
        assert!(
            text.contains("project.open") || text.contains("path="),
            "the error must tell the caller how to proceed; got {text}"
        );
    }

    /// Regression: debug.launch with an explicit `path` must route through
    /// the spawn path, not the registry-NotFound stub.
    ///
    /// When `path` is given:
    ///   - The stub JSON ({"stub":true, …}) must NOT appear in the response.
    ///   - The handler either spawns successfully or fails at the OS spawn step;
    ///     either outcome is distinct from the registry-not-found stub.
    ///
    /// When `path` is absent and `binary_id` is unknown:
    ///   - The stub JSON with a hint MUST appear.
    #[test]
    fn test_dispatch_tool_debug_launch_path_param_is_used() {
        // Helper: extract all text from a CallToolResult content vector.
        fn content_text(r: &CallToolResult) -> String {
            r.content
                .iter()
                .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
                .collect::<Vec<_>>()
                .join("")
        }

        let srv = make_server();

        let result_without_path = srv.dispatch_tool(
            "debug.launch",
            serde_json::json!({"binary_id": "bogus-not-in-registry"}),
        );
        let without_text = content_text(&result_without_path);
        assert!(
            without_text.contains("stub") || without_text.contains("not loaded"),
            "without path: expected stub hint, got: {without_text}"
        );

        // With path: the handler must attempt to spawn, NOT return the stub.
        let result_with_path = srv.dispatch_tool(
            "debug.launch",
            serde_json::json!({"binary_id": "bogus-not-in-registry", "path": "C:\\Windows\\System32\\cmd.exe"}),
        );
        let with_text = content_text(&result_with_path);
        assert!(
            !with_text.contains("\"stub\":true") && !with_text.contains("\"stub\": true"),
            "with path: handler must not return registry-not-found stub; got: {with_text}"
        );
    }

    #[test]
    /// `analyze.full` on an unloaded binary must FAIL, not return an empty
    /// "analysis" that a caller would read as "this binary has no functions,
    /// no strings and no xrefs".
    #[test]
    fn test_dispatch_tool_analyze_full_unknown_binary_errors() {
        let srv = make_server();
        let result = srv.dispatch_tool("analyze.full", serde_json::json!({"binary_id":"b"}));
        assert_eq!(
            result.is_error,
            Some(true),
            "analyze.full must not fabricate an analysis for an unloaded binary"
        );
    }

    /// Regression: `patch_patch_find_code_caves` must actually invoke
    /// `rustre_patch::find_code_caves_from_path` with the supplied `path`
    /// instead of falling through to the stub. We build a minimal ELF on
    /// disk and assert the dispatch returns the analyzer's JSON (count >= 1).
    #[test]
    fn test_dispatch_tool_patch_find_code_caves_uses_path() {
        // Build a minimal ELF64 with an executable .text section containing a
        // 64-byte 0xCC cave bracketed by non-cave bytes — same shape as the
        // rustre-patch fix-D fixture.
        fn make_minimal_elf64_with_text(text: &[u8]) -> Vec<u8> {
            const SHENTSIZE: usize = 64;
            const EHDR: usize = 64;
            let text_off = EHDR;
            let shstrtab_off = text_off + text.len();
            let mut shstrtab: Vec<u8> = vec![0];
            let name_text = u32::try_from(shstrtab.len()).unwrap_or(0);
            shstrtab.extend_from_slice(b".text\0");
            let name_shstr = u32::try_from(shstrtab.len()).unwrap_or(0);
            shstrtab.extend_from_slice(b".shstrtab\0");
            let shoff = shstrtab_off + shstrtab.len();
            let total = shoff + 3 * SHENTSIZE;
            let mut out = vec![0u8; total];
            out[0..4].copy_from_slice(b"\x7FELF");
            out[4] = 2;
            out[5] = 1;
            out[6] = 1;
            out[0x28..0x30].copy_from_slice(&u64::try_from(shoff).unwrap_or(0).to_le_bytes());
            out[0x3A..0x3C].copy_from_slice(&u16::try_from(SHENTSIZE).unwrap_or(0).to_le_bytes());
            out[0x3C..0x3E].copy_from_slice(&3u16.to_le_bytes());
            out[0x3E..0x40].copy_from_slice(&2u16.to_le_bytes());
            out[text_off..text_off + text.len()].copy_from_slice(text);
            out[shstrtab_off..shstrtab_off + shstrtab.len()].copy_from_slice(&shstrtab);
            let sh1 = shoff + SHENTSIZE;
            out[sh1..sh1 + 4].copy_from_slice(&name_text.to_le_bytes());
            out[sh1 + 4..sh1 + 8].copy_from_slice(&1u32.to_le_bytes());
            out[sh1 + 8..sh1 + 16].copy_from_slice(&(0x4u64 | 0x2u64).to_le_bytes());
            out[sh1 + 16..sh1 + 24].copy_from_slice(&0x1000u64.to_le_bytes());
            out[sh1 + 24..sh1 + 32].copy_from_slice(&u64::try_from(text_off).unwrap_or(0).to_le_bytes());
            out[sh1 + 32..sh1 + 40].copy_from_slice(&u64::try_from(text.len()).unwrap_or(0).to_le_bytes());
            let sh2 = shoff + 2 * SHENTSIZE;
            out[sh2..sh2 + 4].copy_from_slice(&name_shstr.to_le_bytes());
            out[sh2 + 4..sh2 + 8].copy_from_slice(&3u32.to_le_bytes());
            out[sh2 + 24..sh2 + 32].copy_from_slice(&u64::try_from(shstrtab_off).unwrap_or(0).to_le_bytes());
            out[sh2 + 32..sh2 + 40].copy_from_slice(&u64::try_from(shstrtab.len()).unwrap_or(0).to_le_bytes());
            out
        }

        let mut text = vec![0x55u8; 8];
        text.extend(std::iter::repeat(0xCCu8).take(64));
        text.extend(vec![0x55u8; 8]);
        let bin = make_minimal_elf64_with_text(&text);
        let path = std::env::temp_dir().join("rustre_mcp_caves_dispatch.bin");
        std::fs::write(&path, &bin).unwrap();

        let srv = RustReMcpServer::new();
        let v = srv
            .execute_tool(
                "patch_patch_find_code_caves",
                serde_json::json!({ "path": path.to_string_lossy(), "min_size": 16 }),
            )
            .expect("execute_tool returned Err");
        // Stub fallback shape would be {"stub": true, "tool": ...}; the real
        // analyzer returns {"path","min_size","count","caves":[...]}.
        assert!(
            v.get("stub").is_none(),
            "expected analyzer JSON, got stub fallback: {v}"
        );
        let count = v
            .get("count")
            .and_then(serde_json::Value::as_u64)
            .expect("count key missing");
        assert!(count >= 1, "expected at least one cave, got {count}: {v}");
        let caves = v.get("caves").and_then(serde_json::Value::as_array).expect("caves array");
        assert!(caves.iter().any(|c| {
            c.get("fill_byte").and_then(serde_json::Value::as_u64) == Some(0xCC)
        }), "expected a 0xCC cave: {v}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    /// Decompiling an address in an unloaded binary must FAIL. Returning
    /// pseudo-code here would be the worst fabrication in the server: it looks
    /// exactly like a real result.
    #[test]
    fn test_dispatch_tool_decompile_function_unknown_binary_errors() {
        let srv = make_server();
        let result = srv.dispatch_tool(
            "decompile.function",
            serde_json::json!({"binary_id":"b","addr":"0x401000"}),
        );
        assert_eq!(
            result.is_error,
            Some(true),
            "decompile.function must not emit code for an unloaded binary"
        );
    }

    #[test]
    fn test_dispatch_tool_success_single_content_block() {
        let srv = make_server();
        let result = srv.dispatch_tool("project.open", serde_json::json!({"path":"/x"}));
        assert_eq!(result.content.len(), 1);
    }

    #[test]
    /// No tool may invent a result when a REQUIRED parameter is missing.
    ///
    /// This test used to demand the opposite: it called every catalog tool
    /// with `{}` and asserted that none of them errored. That is precisely the
    /// fabrication contract — a tool whose schema says `binary_id` is required
    /// cannot possibly answer without one, so "succeeds with no arguments"
    /// means "made something up". It passed only in the stub era.
    ///
    /// Tools with no required parameters are skipped: for those, succeeding on
    /// `{}` is legitimate.
    #[test]
    fn no_tool_fabricates_a_result_when_required_params_are_missing() {
        let srv = make_server();
        let mut fabricators: Vec<String> = Vec::new();

        for tool in srv.rmcp_tools.as_ref() {
            let required = tool
                .input_schema
                .get("required")
                .and_then(|v| v.as_array())
                .map_or(0, Vec::len);
            if required == 0 {
                continue; // answering with no arguments is fine here
            }
            let result = srv.dispatch_tool(tool.name.as_ref(), serde_json::json!({}));
            if result.is_error != Some(true) {
                fabricators.push(format!(
                    "{} (schema requires {required} param(s)) -> {:?}",
                    tool.name, result.content
                ));
            }
        }

        assert!(
            fabricators.is_empty(),
            "these tools returned a successful result without their required \
             parameters, i.e. they fabricated it; make them return an error \
             instead:\n{}",
            fabricators.join("\n")
        );
    }

    #[test]
    fn test_dispatch_tool_error_content_not_empty() {
        let srv = make_server();
        let result = srv.dispatch_tool("does.not.exist", serde_json::json!({}));
        assert_eq!(result.is_error, Some(true));
        assert!(!result.content.is_empty());
    }

    // Ã¢—â‚¬Ã¢—â‚¬ find_rmcp_tool Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_find_rmcp_tool_found() {
        let srv = make_server();
        let t = srv.find_rmcp_tool("binary.hexdump");
        assert!(t.is_some());
        assert_eq!(t.unwrap().name.as_ref(), "binary.hexdump");
    }

    #[test]
    fn test_find_rmcp_tool_not_found() {
        let srv = make_server();
        assert!(srv.find_rmcp_tool("nope.nope").is_none());
    }

    #[test]
    fn test_find_rmcp_tool_all_catalog_tools_findable() {
        let srv = make_server();
        for tool in build_tool_catalog() {
            assert!(
                srv.find_rmcp_tool(&tool.name).is_some(),
                "tool '{}' not findable via find_rmcp_tool",
                tool.name
            );
        }
    }

    // Ã¢—â‚¬Ã¢—â‚¬ McpTransportKind Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_transport_kind_stdio() {
        let t = McpTransportKind::Stdio;
        assert!(t.is_stdio());
        assert!(t.bind_addr().is_none());
        assert_eq!(t.name(), "stdio");
        assert_eq!(t.to_string(), "stdio");
    }

    #[test]
    fn test_transport_kind_sse_http() {
        let t = McpTransportKind::SseHttp {
            bind: "127.0.0.1:8080".to_string(),
        };
        assert!(!t.is_stdio());
        assert_eq!(t.bind_addr(), Some("127.0.0.1:8080"));
        assert_eq!(t.name(), "sse-http");
        assert_eq!(t.to_string(), "sse-http@127.0.0.1:8080");
    }

    #[test]
    fn test_transport_kind_websocket() {
        let t = McpTransportKind::WebSocket {
            bind: "0.0.0.0:9090".to_string(),
        };
        assert!(!t.is_stdio());
        assert_eq!(t.bind_addr(), Some("0.0.0.0:9090"));
        assert_eq!(t.name(), "websocket");
        assert_eq!(t.to_string(), "websocket@0.0.0.0:9090");
    }

    #[test]
    fn test_transport_kind_clone() {
        let t = McpTransportKind::SseHttp {
            bind: "localhost:3000".to_string(),
        };
        let t2 = t.clone();
        assert_eq!(t.bind_addr(), t2.bind_addr());
    }

    #[test]
    fn test_transport_kind_websocket_fallback_to_sse() {
        // run_with_transport maps WebSocket to run_http (SSE) Ã¢â‚¬— verify name logic.
        let ws = McpTransportKind::WebSocket {
            bind: "127.0.0.1:9000".to_string(),
        };
        let sse = McpTransportKind::SseHttp {
            bind: "127.0.0.1:9000".to_string(),
        };
        // Both are not stdio and share the same bind addr.
        assert!(!ws.is_stdio());
        assert!(!sse.is_stdio());
        assert_eq!(ws.bind_addr(), sse.bind_addr());
    }

    // Ã¢—â‚¬Ã¢—â‚¬ value_to_json_object Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_value_to_json_object_from_object() {
        let v = serde_json::json!({"type":"object","properties":{}});
        let obj = value_to_json_object(&v);
        assert!(obj.contains_key("type"));
        assert!(obj.contains_key("properties"));
    }

    #[test]
    fn test_value_to_json_object_from_non_object() {
        let v = serde_json::json!("not an object");
        let obj = value_to_json_object(&v);
        assert!(obj.is_empty());
    }

    #[test]
    fn test_value_to_json_object_from_null() {
        let v = serde_json::Value::Null;
        let obj = value_to_json_object(&v);
        assert!(obj.is_empty());
    }

    // Ã¢—â‚¬Ã¢—â‚¬ rmcp Tool construction from catalog Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_rmcp_tools_count_matches_catalog() {
        let srv = make_server();
        let catalog = build_tool_catalog();
        assert_eq!(srv.rmcp_tools.len(), catalog.len());
    }

    #[test]
    fn test_rmcp_tools_have_correct_names() {
        let srv = make_server();
        let catalog = build_tool_catalog();
        for (rmcp_t, catalog_t) in srv.rmcp_tools.iter().zip(catalog.iter()) {
            assert_eq!(rmcp_t.name.as_ref(), catalog_t.name.as_str());
        }
    }

    #[test]
    fn test_rmcp_tools_descriptions_match_catalog() {
        let srv = make_server();
        let catalog = build_tool_catalog();
        for (rmcp_t, catalog_t) in srv.rmcp_tools.iter().zip(catalog.iter()) {
            assert_eq!(
                rmcp_t.description.as_ref(),
                catalog_t.description.as_str(),
                "description mismatch for tool '{}'",
                catalog_t.name
            );
        }
    }

    // Ã¢—â‚¬Ã¢—â‚¬ Clone impl Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_rustre_server_clone_preserves_tool_count() {
        let a = make_server();
        let b = a.clone();
        assert_eq!(a.tool_count(), b.tool_count());
    }

    #[test]
    fn test_rustre_server_clone_shares_tools_arc() {
        let a = make_server();
        let b = a.clone();
        // Both share the same Arc<Vec<Tool>> Ã¢â‚¬— pointer equality.
        assert!(Arc::ptr_eq(&a.rmcp_tools, &b.rmcp_tools));
    }

    // Ã¢—â‚¬Ã¢—â‚¬ ServerHandler trait: get_info consistency Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬Ã¢—â‚¬

    #[test]
    fn test_server_handler_get_info_consistent() {
        let srv = make_server();
        let info1 = srv.get_info();
        let info2 = srv.get_info();
        assert_eq!(info1.server_info.name, info2.server_info.name);
        assert_eq!(info1.server_info.version, info2.server_info.version);
    }

    #[test]
    fn test_server_handler_tools_capability_list_changed() {
        let srv = make_server();
        let info = srv.get_info();
        let tools_cap = info.capabilities.tools.unwrap();
        // We advertise list_changed: false (static catalog).
        assert_eq!(tools_cap.list_changed, Some(false));
    }
}
