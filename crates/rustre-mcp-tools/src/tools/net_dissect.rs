//! MCP wrappers for the rustre-net_dissect crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct NetDissectByteEntropyTool;

pub struct NetDissectSmb2SensitiveShareTool;

pub struct NetDissectScanHttpAttacksDecodedTool;

pub struct NetDissectDnp3AppFcNameTool;

pub struct NetDissectIcmpStreamTunnelHeuristicTool;

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (NetDissectByteEntropyTool::definition(), Box::new(NetDissectByteEntropyTool)),
        (NetDissectSmb2SensitiveShareTool::definition(), Box::new(NetDissectSmb2SensitiveShareTool)),
        (NetDissectScanHttpAttacksDecodedTool::definition(), Box::new(NetDissectScanHttpAttacksDecodedTool)),
        (NetDissectDnp3AppFcNameTool::definition(), Box::new(NetDissectDnp3AppFcNameTool)),
        (NetDissectIcmpStreamTunnelHeuristicTool::definition(), Box::new(NetDissectIcmpStreamTunnelHeuristicTool)),
    ]
}
