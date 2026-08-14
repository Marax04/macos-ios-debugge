//! MCP wrappers for the rustre-recover crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct RecoverStructsTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (RecoverStructsTool::definition(), Box::new(RecoverStructsTool)),
    ]
}
