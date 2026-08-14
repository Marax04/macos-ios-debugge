//! MCP wrappers for the rustre-arch_cil crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct ArchCilDecodeCompressedUintTool;

pub struct ArchCilMaxLocalSlotTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ArchCilDecodeCompressedUintTool::definition(), Box::new(ArchCilDecodeCompressedUintTool)),
        (ArchCilMaxLocalSlotTool::definition(), Box::new(ArchCilMaxLocalSlotTool)),
    ]
}
