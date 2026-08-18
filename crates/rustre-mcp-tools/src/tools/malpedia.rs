//! MCP wrappers for the rustre-malpedia crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct MalpediaTlshDistanceTool;

pub struct MalpediaBatchLookupTool;

pub struct MalpediaCheckRulesetQualityTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (MalpediaTlshDistanceTool::definition(), Box::new(MalpediaTlshDistanceTool)),
        (MalpediaBatchLookupTool::definition(), Box::new(MalpediaBatchLookupTool)),
        (MalpediaCheckRulesetQualityTool::definition(), Box::new(MalpediaCheckRulesetQualityTool)),
    ]
}
