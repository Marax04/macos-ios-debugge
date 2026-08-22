//! MCP wrappers for the rustre-mips crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct MipsEncodeNopTool;

pub struct MipsGprNameTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (MipsEncodeNopTool::definition(), Box::new(MipsEncodeNopTool)),
        (MipsGprNameTool::definition(), Box::new(MipsGprNameTool)),
    ]
}
