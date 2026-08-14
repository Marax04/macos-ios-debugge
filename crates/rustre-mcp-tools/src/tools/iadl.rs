//! MCP wrappers for the rustre-iadl crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct IadlConvergenceMovingAverageTool;

pub struct IadlConvergenceEmaTool;

pub struct IadlConvergenceTrendSlopeTool;

pub struct IadlAnalyzeBinaryForProtectionsTool;

pub struct IadlComputeHashTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (IadlConvergenceMovingAverageTool::definition(), Box::new(IadlConvergenceMovingAverageTool)),
        (IadlConvergenceEmaTool::definition(), Box::new(IadlConvergenceEmaTool)),
        (IadlConvergenceTrendSlopeTool::definition(), Box::new(IadlConvergenceTrendSlopeTool)),
        (IadlAnalyzeBinaryForProtectionsTool::definition(), Box::new(IadlAnalyzeBinaryForProtectionsTool)),
        (IadlComputeHashTool::definition(), Box::new(IadlComputeHashTool)),
    ]
}
