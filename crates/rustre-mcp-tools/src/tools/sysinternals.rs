//! MCP wrappers for the rustre-sysinternals crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct SysinternalsPeHasSignatureTool;

pub struct SysinternalsAutorunsScanAllTool;

pub struct SysinternalsNetworkSnapshotTool;

pub struct SysinternalsListeningPortsTool;

pub struct SysinternalsProcessScanTool;

pub struct SysinternalsHasPeSignatureTool;

pub struct SysinternalsEmptySnapshotTool;

pub struct SysinternalsSignatureUnsignedTool;

pub struct SysinternalsMemoryInfoRatioTool;

pub struct SysinternalsProcessInTempDirTool;

pub struct SysinternalsAutorunSuspiciousPathTool;

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (SysinternalsPeHasSignatureTool::definition(), Box::new(SysinternalsPeHasSignatureTool)),
        (SysinternalsAutorunsScanAllTool::definition(), Box::new(SysinternalsAutorunsScanAllTool)),
        (SysinternalsNetworkSnapshotTool::definition(), Box::new(SysinternalsNetworkSnapshotTool)),
        (SysinternalsListeningPortsTool::definition(), Box::new(SysinternalsListeningPortsTool)),
        (SysinternalsProcessScanTool::definition(), Box::new(SysinternalsProcessScanTool)),
        (SysinternalsHasPeSignatureTool::definition(), Box::new(SysinternalsHasPeSignatureTool)),
        (SysinternalsEmptySnapshotTool::definition(), Box::new(SysinternalsEmptySnapshotTool)),
        (SysinternalsSignatureUnsignedTool::definition(), Box::new(SysinternalsSignatureUnsignedTool)),
        (SysinternalsMemoryInfoRatioTool::definition(), Box::new(SysinternalsMemoryInfoRatioTool)),
        (SysinternalsProcessInTempDirTool::definition(), Box::new(SysinternalsProcessInTempDirTool)),
        (SysinternalsAutorunSuspiciousPathTool::definition(), Box::new(SysinternalsAutorunSuspiciousPathTool)),
    ]
}
