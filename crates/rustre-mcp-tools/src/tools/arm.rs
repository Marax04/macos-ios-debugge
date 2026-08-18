//! MCP wrappers for the rustre-arm crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct ArmSregNameTool;

pub struct ArmDregNameTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ArmSregNameTool::definition(), Box::new(ArmSregNameTool)),
        (ArmDregNameTool::definition(), Box::new(ArmDregNameTool)),
    ]
}
