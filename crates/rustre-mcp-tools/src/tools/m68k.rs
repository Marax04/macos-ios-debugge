//! MCP wrappers for the rustre-m68k crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct M68kDecodeInstrTool;

pub struct M68kVariantInfoTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (M68kDecodeInstrTool::definition(), Box::new(M68kDecodeInstrTool)),
        (M68kVariantInfoTool::definition(), Box::new(M68kVariantInfoTool)),
    ]
}
