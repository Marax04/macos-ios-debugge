//! MCP wrappers for the rustre-avr crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct AvrEncodeNopTool;

pub struct AvrEncodeRetTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (AvrEncodeNopTool::definition(), Box::new(AvrEncodeNopTool)),
        (AvrEncodeRetTool::definition(), Box::new(AvrEncodeRetTool)),
    ]
}
