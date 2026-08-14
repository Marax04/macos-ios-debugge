//! MCP wrappers for the rustre-bpf crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct BpfLookupHelperTool;

pub struct BpfLookupHelperByNameTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (BpfLookupHelperTool::definition(), Box::new(BpfLookupHelperTool)),
        (BpfLookupHelperByNameTool::definition(), Box::new(BpfLookupHelperByNameTool)),
    ]
}
