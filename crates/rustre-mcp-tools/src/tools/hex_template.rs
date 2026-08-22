//! MCP wrappers for the rustre-hex_template crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct HexTemplateWavTool;

pub struct HexTemplateRiffChunkTool;

pub struct HexTemplateBuiltinTemplatesTool;

pub struct HexTemplateBuiltinNamesTool;

pub struct HexTemplateBitfieldExtractTool;

pub struct HexTemplateElf32PhdrTool;

pub struct HexTemplateElf64PhdrTool;

pub struct HexTemplateRiffChunkWireTool;

pub struct HexTemplateWavWireTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (HexTemplateWavTool::definition(), Box::new(HexTemplateWavTool)),
        (HexTemplateRiffChunkTool::definition(), Box::new(HexTemplateRiffChunkTool)),
        (HexTemplateBuiltinTemplatesTool::definition(), Box::new(HexTemplateBuiltinTemplatesTool)),
        (HexTemplateBuiltinNamesTool::definition(), Box::new(HexTemplateBuiltinNamesTool)),
        (HexTemplateBitfieldExtractTool::definition(), Box::new(HexTemplateBitfieldExtractTool)),
        (HexTemplateElf32PhdrTool::definition(), Box::new(HexTemplateElf32PhdrTool)),
        (HexTemplateElf64PhdrTool::definition(), Box::new(HexTemplateElf64PhdrTool)),
        (HexTemplateRiffChunkWireTool::definition(), Box::new(HexTemplateRiffChunkWireTool)),
        (HexTemplateWavWireTool::definition(), Box::new(HexTemplateWavWireTool)),
    ]
}
