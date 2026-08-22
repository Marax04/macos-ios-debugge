//! MCP wrappers for the rustre-patch crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct PatchPeSecuritySummaryTool;

pub struct PatchFindCodeCavesTool;

pub struct PatchParseHexBytesTool;

pub struct PatchAssembleSimpleTool;

pub struct PatchComputePeChecksumTool;

pub struct PatchPeSecuritySetTool;

pub struct PatchBinaryDiffTool;

pub struct PatchBinaryPatchTool;

pub struct PatchBytesAtVaTool;

pub struct PatchNopRangeAtVaTool;

pub struct PatchAsmAtVaTool;

pub struct PatchPeVaToFileOffsetTool;

pub struct PatchPatchXorRegionAtVaTool;

pub struct PatchBuildDeltaTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (PatchPeSecuritySummaryTool::definition(), Box::new(PatchPeSecuritySummaryTool)),
        (PatchFindCodeCavesTool::definition(), Box::new(PatchFindCodeCavesTool)),
        (PatchParseHexBytesTool::definition(), Box::new(PatchParseHexBytesTool)),
        (PatchAssembleSimpleTool::definition(), Box::new(PatchAssembleSimpleTool)),
        (PatchComputePeChecksumTool::definition(), Box::new(PatchComputePeChecksumTool)),
        (PatchPeSecuritySetTool::definition(), Box::new(PatchPeSecuritySetTool)),
        (PatchBinaryDiffTool::definition(), Box::new(PatchBinaryDiffTool)),
        (PatchBinaryPatchTool::definition(), Box::new(PatchBinaryPatchTool)),
        (PatchBytesAtVaTool::definition(), Box::new(PatchBytesAtVaTool)),
        (PatchNopRangeAtVaTool::definition(), Box::new(PatchNopRangeAtVaTool)),
        (PatchAsmAtVaTool::definition(), Box::new(PatchAsmAtVaTool)),
        (PatchPeVaToFileOffsetTool::definition(), Box::new(PatchPeVaToFileOffsetTool)),
        (PatchPatchXorRegionAtVaTool::definition(), Box::new(PatchPatchXorRegionAtVaTool)),
        (PatchBuildDeltaTool::definition(), Box::new(PatchBuildDeltaTool)),
    ]
}
