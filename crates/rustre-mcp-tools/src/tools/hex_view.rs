//! MCP wrappers for the rustre-hex_view crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct HexViewFormatHexDumpTool;

pub struct HexViewFormatHexDumpAnsiTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (HexViewFormatHexDumpTool::definition(), Box::new(HexViewFormatHexDumpTool)),
        (HexViewFormatHexDumpAnsiTool::definition(), Box::new(HexViewFormatHexDumpAnsiTool)),
    ]
}
