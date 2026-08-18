//! MCP wrappers for the rustre-net_pcap crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{ToolDefinition, ToolHandler};

pub struct NetPcapLinkTypeFromU16Tool;

pub struct NetPcapFileParseInfoTool;

pub struct NetPcapMergeFilesTool;

pub struct NetPcapSplitByCountTool;

pub struct NetPcapSplitByTimeTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (NetPcapLinkTypeFromU16Tool::definition(), Box::new(NetPcapLinkTypeFromU16Tool)),
        (NetPcapFileParseInfoTool::definition(), Box::new(NetPcapFileParseInfoTool)),
        (NetPcapMergeFilesTool::definition(), Box::new(NetPcapMergeFilesTool)),
        (NetPcapSplitByCountTool::definition(), Box::new(NetPcapSplitByCountTool)),
        (NetPcapSplitByTimeTool::definition(), Box::new(NetPcapSplitByTimeTool)),
    ]
}
