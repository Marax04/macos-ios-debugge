//! MCP wrappers for the rustre-trace_pt crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes, hex_decode, hex_encode};

pub struct TracePtDecodeBufferTool;

pub struct TracePtCoverageTool;

pub struct TracePtDrcovTool;

pub struct TracePtDecoderRemainingBytesTool;
impl TracePtDecoderRemainingBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_pt_decoder_remaining_bytes".to_string(), description: "rustre_trace_pt::PtDecoder::remaining_bytes after optional feed.".to_string(), input_schema: json!({ "type": "object", "properties": { "bytes_hex": { "type": "string" } }, "required": [] }), parameters: json!({ "type": "object", "properties": { "bytes_hex": { "type": "string" } }, "required": [] }), } } }
#[async_trait]
impl ToolHandler for TracePtDecoderRemainingBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let mut dec = rustre_trace_pt::PtDecoder::new(); if let Some(hex) = args.get("bytes_hex").and_then(Value::as_str) { let bytes = hex_decode(hex)?; dec.feed(&bytes); } let _ = (args_to_bytes, hex_encode); Ok(ToolResult::text(json!({ "remaining_bytes": dec.remaining_bytes(), "source": "rustre_trace_pt::PtDecoder::remaining_bytes" }).to_string())) } }

pub struct TracePtFlowEventCountTool;
impl TracePtFlowEventCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_pt_flow_event_count".to_string(), description: "rustre_trace_pt::PtFlow::event_count for a fresh flow.".to_string(), input_schema: json!({ "type": "object", "properties": {}, "required": [] }), parameters: json!({ "type": "object", "properties": {}, "required": [] }), } } }
#[async_trait]
impl ToolHandler for TracePtFlowEventCountTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let flow = rustre_trace_pt::PtFlow::new(); Ok(ToolResult::text(json!({ "event_count": flow.event_count(), "source": "rustre_trace_pt::PtFlow::event_count" }).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TracePtDecodeBufferTool::definition(), Box::new(TracePtDecodeBufferTool)),
        (TracePtCoverageTool::definition(), Box::new(TracePtCoverageTool)),
        (TracePtDrcovTool::definition(), Box::new(TracePtDrcovTool)),
        (TracePtDecoderRemainingBytesTool::definition(), Box::new(TracePtDecoderRemainingBytesTool)),
        (TracePtFlowEventCountTool::definition(), Box::new(TracePtFlowEventCountTool)),
    ]
}
