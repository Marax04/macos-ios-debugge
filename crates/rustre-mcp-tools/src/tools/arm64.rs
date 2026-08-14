//! MCP wrappers for the rustre-arm64 crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct Arm64AlignUpTool;

pub struct Arm64AlignDownTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (Arm64AlignUpTool::definition(), Box::new(Arm64AlignUpTool)),
        (Arm64AlignDownTool::definition(), Box::new(Arm64AlignDownTool)),
    ]
}
