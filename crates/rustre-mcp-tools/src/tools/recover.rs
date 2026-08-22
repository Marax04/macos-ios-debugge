//! MCP wrappers for the rustre-recover crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct RecoverStructsTool;

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (RecoverStructsTool::definition(), Box::new(RecoverStructsTool)),
    ]
}
