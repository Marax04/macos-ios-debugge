//! MCP wrappers for the rustre-pe crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct PeXorSectionTool;

pub struct PeCertHeaderBytesTool;

pub struct PeRc4ProcessTool;

pub struct PeImportEntryDisplayTool;

pub struct PePatchDisplayTool;

pub struct PeToolsComputeEntropyTool;

pub struct PeToolsComputePeChecksumTool;

pub struct PeToolsRichHeaderParseTool;

pub struct PeRebuildIsMemoryPeTool;

pub struct PeRebuildComputeEntropyTool;

pub struct PeRebuildCrc16CcittTool;

pub struct PeRebuildFindPeCandidatesTool;

pub struct PeRebuildCalculatePeChecksumTool;

pub struct PeRebuildInferCharacteristicsTool;

pub struct PeRebuildIsMemoryPeWireTool;

pub struct PeRebuildComputeEntropyWireTool;

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (PeXorSectionTool::definition(), Box::new(PeXorSectionTool)),
        (PeCertHeaderBytesTool::definition(), Box::new(PeCertHeaderBytesTool)),
        (PeRc4ProcessTool::definition(), Box::new(PeRc4ProcessTool)),
        (PeImportEntryDisplayTool::definition(), Box::new(PeImportEntryDisplayTool)),
        (PePatchDisplayTool::definition(), Box::new(PePatchDisplayTool)),
        (PeToolsComputeEntropyTool::definition(), Box::new(PeToolsComputeEntropyTool)),
        (PeToolsComputePeChecksumTool::definition(), Box::new(PeToolsComputePeChecksumTool)),
        (PeToolsRichHeaderParseTool::definition(), Box::new(PeToolsRichHeaderParseTool)),
        (PeRebuildIsMemoryPeTool::definition(), Box::new(PeRebuildIsMemoryPeTool)),
        (PeRebuildComputeEntropyTool::definition(), Box::new(PeRebuildComputeEntropyTool)),
        (PeRebuildCrc16CcittTool::definition(), Box::new(PeRebuildCrc16CcittTool)),
        (PeRebuildFindPeCandidatesTool::definition(), Box::new(PeRebuildFindPeCandidatesTool)),
        (PeRebuildCalculatePeChecksumTool::definition(), Box::new(PeRebuildCalculatePeChecksumTool)),
        (PeRebuildInferCharacteristicsTool::definition(), Box::new(PeRebuildInferCharacteristicsTool)),
        (PeRebuildIsMemoryPeWireTool::definition(), Box::new(PeRebuildIsMemoryPeWireTool)),
        (PeRebuildComputeEntropyWireTool::definition(), Box::new(PeRebuildComputeEntropyWireTool)),
    ]
}
