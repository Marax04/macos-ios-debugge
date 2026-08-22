//! MCP wrappers for the rustre-mhcde crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct MhcdeOpaquePredicateDetectTool;

pub struct MhcdeJunkCodeDetectTool;

pub struct MhcdeOrchestratorAnalyzeTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (MhcdeOpaquePredicateDetectTool::definition(), Box::new(MhcdeOpaquePredicateDetectTool)),
        (MhcdeJunkCodeDetectTool::definition(), Box::new(MhcdeJunkCodeDetectTool)),
        (MhcdeOrchestratorAnalyzeTool::definition(), Box::new(MhcdeOrchestratorAnalyzeTool)),
    ]
}
