//! MCP wrappers for the rustre-decompiler_type crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct DecompilerTypeIntByteSizeTool;

pub struct DecompilerTypeIntCNameTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DecompilerTypeIntByteSizeTool::definition(), Box::new(DecompilerTypeIntByteSizeTool)),
        (DecompilerTypeIntCNameTool::definition(), Box::new(DecompilerTypeIntCNameTool)),
    ]
}
