//! MCP wrappers for the rustre-arch_lua crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct ArchLuaGetBx54Tool;

pub struct ArchLuaGetAx54Tool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ArchLuaGetBx54Tool::definition(), Box::new(ArchLuaGetBx54Tool)),
        (ArchLuaGetAx54Tool::definition(), Box::new(ArchLuaGetAx54Tool)),
    ]
}
