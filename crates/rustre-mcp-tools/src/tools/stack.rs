//! MCP wrappers for the rustre-stack crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct StackFrameReportAsyncTool;

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (StackFrameReportAsyncTool::definition(), Box::new(StackFrameReportAsyncTool)),
    ]
}
