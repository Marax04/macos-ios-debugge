//! MCP wrappers for the rustre-rhai crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct RhaiEntropyBytesTool;

pub struct RhaiHexEncodeBytesTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (RhaiEntropyBytesTool::definition(), Box::new(RhaiEntropyBytesTool)),
        (RhaiHexEncodeBytesTool::definition(), Box::new(RhaiHexEncodeBytesTool)),
    ]
}
