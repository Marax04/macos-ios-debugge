//! MCP wrappers for the rustre-firmware crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct FirmwareDetectKindV2Tool;

pub struct FirmwareScanEmbeddedSignaturesTool;

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (FirmwareDetectKindV2Tool::definition(), Box::new(FirmwareDetectKindV2Tool)),
        (FirmwareScanEmbeddedSignaturesTool::definition(), Box::new(FirmwareScanEmbeddedSignaturesTool)),
    ]
}
