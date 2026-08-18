//! MCP wrappers for the rustre-mobile_ios crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct MobileIosSwiftMangledTool;

pub struct MobileIosDecodeTypeEncodingTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (MobileIosSwiftMangledTool::definition(), Box::new(MobileIosSwiftMangledTool)),
        (MobileIosDecodeTypeEncodingTool::definition(), Box::new(MobileIosDecodeTypeEncodingTool)),
    ]
}
