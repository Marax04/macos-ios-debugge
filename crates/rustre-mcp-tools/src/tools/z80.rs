//! MCP wrappers for the rustre-z80 crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct Z80EncodeNopTool;

pub struct Z80EncodeHaltTool;

pub struct Z80EncodeRetTool;

pub struct Z80EncodeEiTool;

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (Z80EncodeNopTool::definition(), Box::new(Z80EncodeNopTool)),
        (Z80EncodeHaltTool::definition(), Box::new(Z80EncodeHaltTool)),
        (Z80EncodeRetTool::definition(), Box::new(Z80EncodeRetTool)),
        (Z80EncodeEiTool::definition(), Box::new(Z80EncodeEiTool)),
    ]
}
