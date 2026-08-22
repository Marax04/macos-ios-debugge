//! MCP wrappers for the rustre-smali crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct SmaliRegDisplayTool;

pub struct SmaliOpcodeToMnemonicTool;

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (SmaliRegDisplayTool::definition(), Box::new(SmaliRegDisplayTool)),
        (SmaliOpcodeToMnemonicTool::definition(), Box::new(SmaliOpcodeToMnemonicTool)),
    ]
}
