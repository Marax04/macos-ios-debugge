//! MCP wrappers for the rustre-ti_otx crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct TiOtxPulseUrlTool;

pub struct TiOtxSamplePulseTool;

pub struct TiOtxThreatLevelTool;

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TiOtxPulseUrlTool::definition(), Box::new(TiOtxPulseUrlTool)),
        (TiOtxSamplePulseTool::definition(), Box::new(TiOtxSamplePulseTool)),
        (TiOtxThreatLevelTool::definition(), Box::new(TiOtxThreatLevelTool)),
    ]
}
