//! MCP wrappers for the rustre-dotnet crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct DotnetDecompileCilOpcodesTool;

pub struct DotnetDecompileDefaultOptionsTool;

pub struct DotnetMethodFlagsDecodeTool;

pub struct DotnetCilSimpleInstrTool;

pub struct DotnetDecompileSimplifyExprTool;

pub struct DotnetDecompileStackEffectTool;

pub struct DotnetEncodeTokenTool;

pub struct DotnetTokenTableNameTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DotnetDecompileCilOpcodesTool::definition(), Box::new(DotnetDecompileCilOpcodesTool)),
        (DotnetDecompileDefaultOptionsTool::definition(), Box::new(DotnetDecompileDefaultOptionsTool)),
        (DotnetMethodFlagsDecodeTool::definition(), Box::new(DotnetMethodFlagsDecodeTool)),
        (DotnetCilSimpleInstrTool::definition(), Box::new(DotnetCilSimpleInstrTool)),
        (DotnetDecompileSimplifyExprTool::definition(), Box::new(DotnetDecompileSimplifyExprTool)),
        (DotnetDecompileStackEffectTool::definition(), Box::new(DotnetDecompileStackEffectTool)),
        (DotnetEncodeTokenTool::definition(), Box::new(DotnetEncodeTokenTool)),
        (DotnetTokenTableNameTool::definition(), Box::new(DotnetTokenTableNameTool)),
    ]
}
