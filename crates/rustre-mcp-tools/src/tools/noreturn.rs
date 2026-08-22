//! MCP wrappers for the rustre-noreturn crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct NoreturnInferTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (NoreturnInferTool::definition(), Box::new(NoreturnInferTool)),
    ]
}
