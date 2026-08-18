//! MCP wrappers for the rustre-arch_jvm crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct ArchJvmDecodeTool;

pub struct ArchJvmDecodeAtTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ArchJvmDecodeTool::definition(), Box::new(ArchJvmDecodeTool)),
        (ArchJvmDecodeAtTool::definition(), Box::new(ArchJvmDecodeAtTool)),
    ]
}
