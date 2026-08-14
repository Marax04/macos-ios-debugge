//! MCP wrappers for the rustre-debug_windbg crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct DebugWindbgExecutionStatusNoDebuggeeTool;

pub struct DebugWindbgDefaultModuleCountTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DebugWindbgExecutionStatusNoDebuggeeTool::definition(), Box::new(DebugWindbgExecutionStatusNoDebuggeeTool)),
        (DebugWindbgDefaultModuleCountTool::definition(), Box::new(DebugWindbgDefaultModuleCountTool)),
    ]
}
