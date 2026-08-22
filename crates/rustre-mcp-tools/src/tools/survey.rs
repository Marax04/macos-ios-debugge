//! MCP wrappers for the rustre-survey crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct SurveyBinaryTool;

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (SurveyBinaryTool::definition(), Box::new(SurveyBinaryTool)),
    ]
}
