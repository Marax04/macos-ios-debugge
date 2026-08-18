//! MCP wrappers for the rustre-plugin crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct PluginLuaLoaderDefaultCountTool;

pub struct PluginLuaLoadInlineTool;

pub struct PluginPythonStubSignatureTool;

pub struct PluginPythonModuleCountsTool;

pub struct PluginNativeLoaderCountTool;

pub struct PluginNativeLoaderIdsTool;

pub struct PluginPythonGenerateStubTool;

pub struct PluginPythonClassMethodsTaggedTool;

pub struct PluginPythonFormatErrorTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (PluginLuaLoaderDefaultCountTool::definition(), Box::new(PluginLuaLoaderDefaultCountTool)),
        (PluginLuaLoadInlineTool::definition(), Box::new(PluginLuaLoadInlineTool)),
        (PluginPythonStubSignatureTool::definition(), Box::new(PluginPythonStubSignatureTool)),
        (PluginPythonModuleCountsTool::definition(), Box::new(PluginPythonModuleCountsTool)),
        (PluginNativeLoaderCountTool::definition(), Box::new(PluginNativeLoaderCountTool)),
        (PluginNativeLoaderIdsTool::definition(), Box::new(PluginNativeLoaderIdsTool)),
        (PluginPythonGenerateStubTool::definition(), Box::new(PluginPythonGenerateStubTool)),
        (PluginPythonClassMethodsTaggedTool::definition(), Box::new(PluginPythonClassMethodsTaggedTool)),
        (PluginPythonFormatErrorTool::definition(), Box::new(PluginPythonFormatErrorTool)),
    ]
}
