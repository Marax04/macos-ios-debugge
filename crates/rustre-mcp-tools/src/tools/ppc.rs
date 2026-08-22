//! MCP wrappers for the rustre-ppc crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct PpcEncodeBlTool;

pub struct PpcEncodeLisTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (PpcEncodeBlTool::definition(), Box::new(PpcEncodeBlTool)),
        (PpcEncodeLisTool::definition(), Box::new(PpcEncodeLisTool)),
    ]
}
