//! MCP wrappers for the rustre-wire crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct WireBytesLenTool;

pub struct WireBytesHexEncodeTool;

pub struct WireEchoStringTool;

pub struct WireStringLenTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (WireBytesLenTool::definition(), Box::new(WireBytesLenTool)),
        (WireBytesHexEncodeTool::definition(), Box::new(WireBytesHexEncodeTool)),
        (WireEchoStringTool::definition(), Box::new(WireEchoStringTool)),
        (WireStringLenTool::definition(), Box::new(WireStringLenTool)),
    ]
}
