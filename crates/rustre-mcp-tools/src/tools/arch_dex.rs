//! MCP wrappers for the rustre-arch_dex crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct ArchDexVregTool;

pub struct ArchDexPregTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ArchDexVregTool::definition(), Box::new(ArchDexVregTool)),
        (ArchDexPregTool::definition(), Box::new(ArchDexPregTool)),
    ]
}
