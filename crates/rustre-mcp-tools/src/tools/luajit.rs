//! MCP wrappers for the rustre-luajit crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct LuajitInstrOpTool;

pub struct LuajitInstrATool;

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (LuajitInstrOpTool::definition(), Box::new(LuajitInstrOpTool)),
        (LuajitInstrATool::definition(), Box::new(LuajitInstrATool)),
    ]
}
