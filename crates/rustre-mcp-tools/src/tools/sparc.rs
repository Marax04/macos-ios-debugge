//! MCP wrappers for the rustre-sparc crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct SparcEncodeNopTool;

pub struct SparcEncodeCallTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (SparcEncodeNopTool::definition(), Box::new(SparcEncodeNopTool)),
        (SparcEncodeCallTool::definition(), Box::new(SparcEncodeCallTool)),
    ]
}
