//! MCP wrappers for the rustre-ttd_recorder crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct TtdRecorderPositionStartTool;

pub struct TtdRecorderValidExtensionTool;

pub struct TtdRecorderCheckPlatformSupportTool;

pub struct TtdRecorderValidateTraceTool;

pub struct TtdRecorderIsValidExtensionTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TtdRecorderPositionStartTool::definition(), Box::new(TtdRecorderPositionStartTool)),
        (TtdRecorderValidExtensionTool::definition(), Box::new(TtdRecorderValidExtensionTool)),
        (TtdRecorderCheckPlatformSupportTool::definition(), Box::new(TtdRecorderCheckPlatformSupportTool)),
        (TtdRecorderValidateTraceTool::definition(), Box::new(TtdRecorderValidateTraceTool)),
        (TtdRecorderIsValidExtensionTool::definition(), Box::new(TtdRecorderIsValidExtensionTool)),
    ]
}
