//! MCP wrappers for the rustre-ti_opencti crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct TiOpenctiGraphqlUrlTool;

pub struct TiOpenctiConfidenceClampTool;

pub struct TiOpenctiConfidenceIsHighTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TiOpenctiGraphqlUrlTool::definition(), Box::new(TiOpenctiGraphqlUrlTool)),
        (TiOpenctiConfidenceClampTool::definition(), Box::new(TiOpenctiConfidenceClampTool)),
        (TiOpenctiConfidenceIsHighTool::definition(), Box::new(TiOpenctiConfidenceIsHighTool)),
    ]
}
