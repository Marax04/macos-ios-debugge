//! MCP wrappers for the rustre-mem_diff crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{hex_encode};
use crate::wire_tools::{__mem_hex_decode_v2};

pub struct MemDiffBytesTool;

pub struct MemDiffProvidersHexTool;
impl MemDiffProvidersHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_diff_providers_hex".to_string(), description: "Diff two hex buffers mapped as virtual memory providers.".to_string(), input_schema: json!({"type": "object", "required": ["a_hex", "b_hex"], "properties": {"a_hex": {"type": "string"}, "b_hex": {"type": "string"}, "base_addr": {"type": "integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemDiffProvidersHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base_addr = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let a_hex = args.get("a_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'a_hex'".into()))?;
        let b_hex = args.get("b_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'b_hex'".into()))?;
        let a = crate::hex_decode(a_hex.trim())?;
        let b = crate::hex_decode(b_hex.trim())?;
        let len = a.len().min(b.len()) as u64;
        let mut pa = rustre_mem::VirtualMemoryProvider::new();
        let mut pb = rustre_mem::VirtualMemoryProvider::new();
        pa.map(rustre_core::address::Address::new(base_addr), a, rustre_core::permissions::Permissions::READ | rustre_core::permissions::Permissions::WRITE);
        pb.map(rustre_core::address::Address::new(base_addr), b, rustre_core::permissions::Permissions::READ | rustre_core::permissions::Permissions::WRITE);
        let range = rustre_core::address::AddressRange::new(rustre_core::address::Address::new(base_addr), rustre_core::address::Address::new(base_addr + len));
        let spans = rustre_mem::diff::diff_providers(&pa, &pb, range);
        let items: Vec<Value> = spans.iter().map(|s| json!({"start": s.range.start.as_u64(), "end": s.range.end.as_u64(), "len": s.len()})).collect();
        Ok(ToolResult::text(json!({"count": items.len(), "spans": items, "source": "rustre_mem::diff::diff_providers"}).to_string()))
    }
}

pub struct MemDiffBytesAtBaseWire2Tool;
impl MemDiffBytesAtBaseWire2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_diff_bytes_at_base_wire2".to_string(), description: "rustre_mem::diff::diff_bytes over two hex buffers at base_addr.".to_string(), input_schema: json!({"type":"object","properties":{"a_hex":{"type":"string"},"b_hex":{"type":"string"},"base_addr":{"type":"integer"}},"required":["a_hex","b_hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemDiffBytesAtBaseWire2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = __mem_hex_decode_v2(args.get("a_hex").and_then(Value::as_str).unwrap_or(""))?; let b = __mem_hex_decode_v2(args.get("b_hex").and_then(Value::as_str).unwrap_or(""))?; let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0); let spans = rustre_mem::diff::diff_bytes(rustre_core::address::Address::new(base), &a, &b); let items: Vec<Value> = spans.iter().map(|s| json!({"start": s.range.start.as_u64(), "end": s.range.end.as_u64(), "len": s.len()})).collect(); Ok(ToolResult::text(json!({"span_count": items.len(), "spans": items, "source": "rustre_mem::diff::diff_bytes"}).to_string())) } }

pub struct MemDiffBytesSpanCountWireTool;
impl MemDiffBytesSpanCountWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_diff_bytes_span_count_wire".to_string(), description: "Number of differing spans between two hex buffers.".to_string(), input_schema: json!({"type":"object","properties":{"a_hex":{"type":"string"},"b_hex":{"type":"string"}},"required":["a_hex","b_hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemDiffBytesSpanCountWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = __mem_hex_decode_v2(args.get("a_hex").and_then(Value::as_str).unwrap_or(""))?; let b = __mem_hex_decode_v2(args.get("b_hex").and_then(Value::as_str).unwrap_or(""))?; let spans = rustre_mem::diff::diff_bytes(rustre_core::address::Address::new(0), &a, &b); Ok(ToolResult::text(json!({"span_count": spans.len(), "source": "rustre_mem::diff::diff_bytes"}).to_string())) } }

pub struct MemDiffBytesTotalChangedWireTool;
impl MemDiffBytesTotalChangedWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_diff_bytes_total_changed_wire".to_string(), description: "Sum DiffSpan::changed_byte_count across all spans.".to_string(), input_schema: json!({"type":"object","properties":{"a_hex":{"type":"string"},"b_hex":{"type":"string"}},"required":["a_hex","b_hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemDiffBytesTotalChangedWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = __mem_hex_decode_v2(args.get("a_hex").and_then(Value::as_str).unwrap_or(""))?; let b = __mem_hex_decode_v2(args.get("b_hex").and_then(Value::as_str).unwrap_or(""))?; let spans = rustre_mem::diff::diff_bytes(rustre_core::address::Address::new(0), &a, &b); let total: usize = spans.iter().map(|s| s.changed_byte_count()).sum(); Ok(ToolResult::text(json!({"total_changed": total, "span_count": spans.len(), "source": "rustre_mem::DiffSpan::changed_byte_count"}).to_string())) } }

pub struct MemDiffBytesFirstSpanOffsetWireTool;
impl MemDiffBytesFirstSpanOffsetWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_diff_bytes_first_span_offset_wire".to_string(), description: "Offset of first differing span or -1 if identical.".to_string(), input_schema: json!({"type":"object","properties":{"a_hex":{"type":"string"},"b_hex":{"type":"string"}},"required":["a_hex","b_hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemDiffBytesFirstSpanOffsetWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = __mem_hex_decode_v2(args.get("a_hex").and_then(Value::as_str).unwrap_or(""))?; let b = __mem_hex_decode_v2(args.get("b_hex").and_then(Value::as_str).unwrap_or(""))?; let spans = rustre_mem::diff::diff_bytes(rustre_core::address::Address::new(0), &a, &b); let off: i64 = spans.first().map(|s| s.range.start.as_u64() as i64).unwrap_or(-1); Ok(ToolResult::text(json!({"first_offset": off, "source": "rustre_mem::diff::diff_bytes"}).to_string())) } }

pub struct MemDiffBytesV3Tool;
impl MemDiffBytesV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_diff_bytes_v3".to_string(), description: "rustre_mem::diff::diff_bytes span count between two hex buffers.".to_string(), input_schema: json!({"type":"object","required":["a_hex","b_hex"],"properties":{"a_hex":{"type":"string"},"b_hex":{"type":"string"},"base_addr":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemDiffBytesV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = __mem_hex_decode_v2(args.get("a_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'a_hex'".into()))?)?; let b = __mem_hex_decode_v2(args.get("b_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'b_hex'".into()))?)?; let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0); let spans = rustre_mem::diff::diff_bytes(rustre_core::address::Address::new(base), &a, &b); let total: usize = spans.iter().map(|s| s.old_bytes.len()).sum(); Ok(ToolResult::text(json!({"span_count":spans.len(),"total_changed_bytes":total,"source":"rustre_mem::diff::diff_bytes"}).to_string())) } }

pub struct MemDiffSpanLenV5Tool;
impl MemDiffSpanLenV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_diff_span_len_v5".to_string(), description: "Construct rustre_mem::DiffSpan and return len().".to_string(), input_schema: json!({"type":"object","required":["start","old_hex","new_hex"],"properties":{"start":{"type":"integer","minimum":0},"old_hex":{"type":"string"},"new_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemDiffSpanLenV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let start = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))?; let old = __mem_hex_decode_v2(args.get("old_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'old_hex'".into()))?)?; let new = __mem_hex_decode_v2(args.get("new_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'new_hex'".into()))?)?; if old.len() != new.len() { return Err(McpError::InvalidParams("length mismatch".into())); } let end = start.saturating_add(old.len() as u64); let span = rustre_mem::DiffSpan { range: rustre_core::address::AddressRange::new(rustre_core::address::Address::new(start), rustre_core::address::Address::new(end)), old_bytes: old, new_bytes: new }; Ok(ToolResult::text(json!({"len":span.len(),"source":"rustre_mem::DiffSpan"}).to_string())) } }

pub struct MemDiffBytesSpansListV4Tool;
impl MemDiffBytesSpansListV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_diff_bytes_spans_list_v4".to_string(), description: "rustre_mem::diff::diff_bytes: list each DiffSpan.".to_string(), input_schema: json!({"type":"object","required":["base","a_hex","b_hex"],"properties":{"base":{"type":"integer"},"a_hex":{"type":"string"},"b_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemDiffBytesSpansListV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing base".into()))?; let ah = args.get("a_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing a_hex".into()))?; let bh = args.get("b_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing b_hex".into()))?; let a = crate::hex_decode(ah)?; let b = crate::hex_decode(bh)?; let spans = rustre_mem::diff::diff_bytes(rustre_core::address::Address::new(base), &a, &b); let items: Vec<_> = spans.iter().map(|s| json!({"start":s.range.start.as_u64(),"end":s.range.end.as_u64(),"old_hex":hex_encode(&s.old_bytes),"new_hex":hex_encode(&s.new_bytes)})).collect(); Ok(ToolResult::text(json!({"span_count":items.len(),"spans":items,"source":"rustre_mem::diff::diff_bytes"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (MemDiffBytesTool::definition(), Box::new(MemDiffBytesTool)),
        (MemDiffProvidersHexTool::definition(), Box::new(MemDiffProvidersHexTool)),
        (MemDiffBytesAtBaseWire2Tool::definition(), Box::new(MemDiffBytesAtBaseWire2Tool)),
        (MemDiffBytesSpanCountWireTool::definition(), Box::new(MemDiffBytesSpanCountWireTool)),
        (MemDiffBytesTotalChangedWireTool::definition(), Box::new(MemDiffBytesTotalChangedWireTool)),
        (MemDiffBytesFirstSpanOffsetWireTool::definition(), Box::new(MemDiffBytesFirstSpanOffsetWireTool)),
        (MemDiffBytesV3Tool::definition(), Box::new(MemDiffBytesV3Tool)),
        (MemDiffSpanLenV5Tool::definition(), Box::new(MemDiffSpanLenV5Tool)),
        (MemDiffBytesSpansListV4Tool::definition(), Box::new(MemDiffBytesSpansListV4Tool)),
    ]
}
