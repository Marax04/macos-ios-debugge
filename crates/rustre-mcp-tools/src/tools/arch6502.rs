//! MCP wrappers for the rustre-arch6502 crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct Arch6502CyclesTool;

pub struct Arch6502BranchTargetTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (Arch6502CyclesTool::definition(), Box::new(Arch6502CyclesTool)),
        (Arch6502BranchTargetTool::definition(), Box::new(Arch6502BranchTargetTool)),
    ]
}
