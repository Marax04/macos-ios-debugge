//! MCP wrappers for the rustre-rv crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct RvBrev8_32Tool;

pub struct RvCClassifyTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (RvBrev8_32Tool::definition(), Box::new(RvBrev8_32Tool)),
        (RvCClassifyTool::definition(), Box::new(RvCClassifyTool)),
    ]
}
