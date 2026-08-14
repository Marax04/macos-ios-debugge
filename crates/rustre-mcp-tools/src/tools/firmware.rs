//! MCP wrappers for the rustre-firmware crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct FirmwareDetectKindV2Tool;

pub struct FirmwareScanEmbeddedSignaturesTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (FirmwareDetectKindV2Tool::definition(), Box::new(FirmwareDetectKindV2Tool)),
        (FirmwareScanEmbeddedSignaturesTool::definition(), Box::new(FirmwareScanEmbeddedSignaturesTool)),
    ]
}
