//! MCP wrappers for the rustre-llm crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct LlmTokenCountEstimateTool;

pub struct LlmCompressMessageTool;

pub struct LlmTrimToBudgetTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (LlmTokenCountEstimateTool::definition(), Box::new(LlmTokenCountEstimateTool)),
        (LlmCompressMessageTool::definition(), Box::new(LlmCompressMessageTool)),
        (LlmTrimToBudgetTool::definition(), Box::new(LlmTrimToBudgetTool)),
    ]
}
