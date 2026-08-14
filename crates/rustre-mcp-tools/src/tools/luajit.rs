//! MCP wrappers for the rustre-luajit crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct LuajitInstrOpTool;

pub struct LuajitInstrATool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (LuajitInstrOpTool::definition(), Box::new(LuajitInstrOpTool)),
        (LuajitInstrATool::definition(), Box::new(LuajitInstrATool)),
    ]
}
