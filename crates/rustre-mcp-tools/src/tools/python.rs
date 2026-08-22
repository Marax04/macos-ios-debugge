//! MCP wrappers for the rustre-python crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct PythonScriptPyValueNoneTypeNameTool;

pub struct PythonScriptEngineInitialStepCountTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (PythonScriptPyValueNoneTypeNameTool::definition(), Box::new(PythonScriptPyValueNoneTypeNameTool)),
        (PythonScriptEngineInitialStepCountTool::definition(), Box::new(PythonScriptEngineInitialStepCountTool)),
    ]
}
