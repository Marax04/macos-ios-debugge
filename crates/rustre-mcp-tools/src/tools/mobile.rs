//! MCP wrappers for the rustre-mobile crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct MobileRegistryAllTool;

pub struct MobileRegistryCountTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (MobileRegistryAllTool::definition(), Box::new(MobileRegistryAllTool)),
        (MobileRegistryCountTool::definition(), Box::new(MobileRegistryCountTool)),
    ]
}
