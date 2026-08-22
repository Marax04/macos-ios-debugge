//! MCP wrappers for the rustre-msp430 crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct Msp430RegNameTool;

pub struct Msp430BwSuffixTool;

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (Msp430RegNameTool::definition(), Box::new(Msp430RegNameTool)),
        (Msp430BwSuffixTool::definition(), Box::new(Msp430BwSuffixTool)),
    ]
}
