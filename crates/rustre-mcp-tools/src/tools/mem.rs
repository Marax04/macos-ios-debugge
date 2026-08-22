//! MCP wrappers for the rustre-mem crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes, hex_encode};
use crate::wire_tools::{__mem_hex_decode_v2, _mem_prov_from_hex};

pub struct MemShannonEntropyTool;

pub struct MemPageIndexTool;

pub struct MemPageAlignUpTool;

pub struct MemPageAlignDownTool;

pub struct MemPageContainingTool;

pub struct MemHighEntropySpansTool;

pub struct MemShannonEntropyWireTool;

pub struct MemPageAlignUpWireTool;

pub struct MemPageRangeIndicesTool;

pub struct MemEntropyClassifyTool;

pub struct MemSearchBytesWithMaskHexTool;
impl MemSearchBytesWithMaskHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_search_bytes_with_mask_hex".to_string(), description: "Search a hex buffer for a masked byte pattern.".to_string(), input_schema: json!({"type": "object", "required": ["buffer_hex", "pattern_hex", "mask_hex"], "properties": {"buffer_hex": {"type": "string"}, "pattern_hex": {"type": "string"}, "mask_hex": {"type": "string"}, "base_addr": {"type": "integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemSearchBytesWithMaskHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base_addr = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let pat_hex = args.get("pattern_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern_hex'".into()))?;
        let mask_hex = args.get("mask_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'mask_hex'".into()))?;
        let buf = crate::hex_decode(buf_hex.trim())?;
        let pat = crate::hex_decode(pat_hex.trim())?;
        let mask = crate::hex_decode(mask_hex.trim())?;
        if pat.len() != mask.len() { return Err(McpError::InvalidParams("pattern and mask must have equal length".into())); }
        let mut prov = rustre_mem::VirtualMemoryProvider::new();
        let len = buf.len();
        prov.map(rustre_core::address::Address::new(base_addr), buf, rustre_core::permissions::Permissions::READ | rustre_core::permissions::Permissions::WRITE);
        let range = rustre_core::address::AddressRange::new(rustre_core::address::Address::new(base_addr), rustre_core::address::Address::new(base_addr + len as u64));
        let hits = rustre_mem::helpers::search_bytes_with_mask(&prov, &pat, &mask, range);
        let addrs: Vec<u64> = hits.iter().map(|a| a.as_u64()).collect();
        Ok(ToolResult::text(json!({"count": addrs.len(), "matches": addrs, "source": "rustre_mem::helpers::search_bytes_with_mask"}).to_string()))
    }
}

pub struct MemSearchBytesHexTool;
impl MemSearchBytesHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_search_bytes_hex".to_string(), description: "Search a hex buffer for a literal byte pattern.".to_string(), input_schema: json!({"type": "object", "required": ["buffer_hex", "pattern_hex"], "properties": {"buffer_hex": {"type": "string"}, "pattern_hex": {"type": "string"}, "base_addr": {"type": "integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemSearchBytesHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base_addr = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let pat_hex = args.get("pattern_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern_hex'".into()))?;
        let buf = crate::hex_decode(buf_hex.trim())?;
        let pat = crate::hex_decode(pat_hex.trim())?;
        let mut prov = rustre_mem::VirtualMemoryProvider::new();
        let len = buf.len();
        prov.map(rustre_core::address::Address::new(base_addr), buf, rustre_core::permissions::Permissions::READ);
        let range = rustre_core::address::AddressRange::new(rustre_core::address::Address::new(base_addr), rustre_core::address::Address::new(base_addr + len as u64));
        let hits = rustre_mem::helpers::search_bytes(&prov, &pat, range);
        let addrs: Vec<u64> = hits.iter().map(|a| a.as_u64()).collect();
        Ok(ToolResult::text(json!({"count": addrs.len(), "matches": addrs, "source": "rustre_mem::helpers::search_bytes"}).to_string()))
    }
}

pub struct MemEntropyBlocksHexTool;
impl MemEntropyBlocksHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_entropy_blocks_hex".to_string(), description: "Compute per-block Shannon entropy over a hex buffer.".to_string(), input_schema: json!({"type": "object", "required": ["buffer_hex"], "properties": {"buffer_hex": {"type": "string"}, "base_addr": {"type": "integer"}, "block_size": {"type": "integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemEntropyBlocksHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base_addr = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let block_size = args.get("block_size").and_then(Value::as_u64).unwrap_or(256).max(1) as usize;
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let buf = crate::hex_decode(buf_hex.trim())?;
        let mut prov = rustre_mem::VirtualMemoryProvider::new();
        prov.map(rustre_core::address::Address::new(base_addr), buf, rustre_core::permissions::Permissions::READ);
        let blocks = rustre_mem::entropy::entropy_blocks(&prov, block_size);
        let items: Vec<Value> = blocks.iter().map(|b| json!({"address": b.address.as_u64(), "size": b.size, "entropy": b.entropy})).collect();
        Ok(ToolResult::text(json!({"count": items.len(), "blocks": items, "source": "rustre_mem::entropy::entropy_blocks"}).to_string()))
    }
}

pub struct MemReadTypedAtHexTool;
impl MemReadTypedAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_read_typed_at_hex".to_string(), description: "Read a typed value at an offset from a hex buffer.".to_string(), input_schema: json!({"type": "object", "required": ["buffer_hex", "kind"], "properties": {"buffer_hex": {"type": "string"}, "kind": {"type": "string"}, "offset": {"type": "integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemReadTypedAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let kind = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let buf = crate::hex_decode(buf_hex.trim())?;
        let mut p = rustre_mem::VirtualMemoryProvider::new();
        p.map(rustre_core::address::Address::new(0), buf, rustre_core::permissions::Permissions::READ | rustre_core::permissions::Permissions::WRITE);
        let a = rustre_core::address::Address::new(offset);
        let val: Value = match kind {
            "u8" => rustre_mem::helpers::read_u8_at(&p, a).map(|v| json!(v)).unwrap_or(Value::Null),
            "u16_le" => rustre_mem::helpers::read_u16_le_at(&p, a).map(|v| json!(v)).unwrap_or(Value::Null),
            "u16_be" => rustre_mem::helpers::read_u16_be_at(&p, a).map(|v| json!(v)).unwrap_or(Value::Null),
            "u32_le" => rustre_mem::helpers::read_u32_le_at(&p, a).map(|v| json!(v)).unwrap_or(Value::Null),
            "u32_be" => rustre_mem::helpers::read_u32_be_at(&p, a).map(|v| json!(v)).unwrap_or(Value::Null),
            "u64_le" => rustre_mem::helpers::read_u64_le_at(&p, a).map(|v| json!(v)).unwrap_or(Value::Null),
            "u64_be" => rustre_mem::helpers::read_u64_be_at(&p, a).map(|v| json!(v)).unwrap_or(Value::Null),
            "i8" => rustre_mem::helpers::read_i8_at(&p, a).map(|v| json!(v)).unwrap_or(Value::Null),
            "i16_le" => rustre_mem::helpers::read_i16_le_at(&p, a).map(|v| json!(v)).unwrap_or(Value::Null),
            "i32_le" => rustre_mem::helpers::read_i32_le_at(&p, a).map(|v| json!(v)).unwrap_or(Value::Null),
            "i64_le" => rustre_mem::helpers::read_i64_le_at(&p, a).map(|v| json!(v)).unwrap_or(Value::Null),
            "f32_le" => rustre_mem::helpers::read_f32_le_at(&p, a).map(|v| json!(v)).unwrap_or(Value::Null),
            "f64_le" => rustre_mem::helpers::read_f64_le_at(&p, a).map(|v| json!(v)).unwrap_or(Value::Null),
            "f32_be" => rustre_mem::helpers::read_f32_be_at(&p, a).map(|v| json!(v)).unwrap_or(Value::Null),
            "f64_be" => rustre_mem::helpers::read_f64_be_at(&p, a).map(|v| json!(v)).unwrap_or(Value::Null),
            other => return Err(McpError::InvalidParams(format!("unknown kind '{other}'"))),
        };
        Ok(ToolResult::text(json!({"kind": kind, "offset": offset, "value": val, "source": "rustre_mem::helpers::read_*_at"}).to_string()))
    }
}

pub struct MemWriteTypedAtHexTool;
impl MemWriteTypedAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_write_typed_at_hex".to_string(), description: "Write a typed value at an offset into a hex buffer and return updated hex.".to_string(), input_schema: json!({"type": "object", "required": ["buffer_hex", "kind", "value"], "properties": {"buffer_hex": {"type": "string"}, "kind": {"type": "string"}, "offset": {"type": "integer"}, "value": {"type": "number"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemWriteTypedAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let kind = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let value = args.get("value").cloned().unwrap_or(Value::Null);
        let buf = crate::hex_decode(buf_hex.trim())?;
        let buf_len = buf.len();
        let mut p = rustre_mem::VirtualMemoryProvider::new();
        p.map(rustre_core::address::Address::new(0), buf, rustre_core::permissions::Permissions::READ | rustre_core::permissions::Permissions::WRITE);
        let a = rustre_core::address::Address::new(offset);
        let as_u = |v: &Value| v.as_u64();
        let as_i = |v: &Value| v.as_i64();
        let as_f = |v: &Value| v.as_f64();
        let res: Result<(), rustre_mem::MemError> = match kind {
            "u8" => rustre_mem::helpers::write_u8_at(&mut p, a, as_u(&value).unwrap_or(0) as u8),
            "u16_le" => rustre_mem::helpers::write_u16_le_at(&mut p, a, as_u(&value).unwrap_or(0) as u16),
            "u16_be" => rustre_mem::helpers::write_u16_be_at(&mut p, a, as_u(&value).unwrap_or(0) as u16),
            "u32_le" => rustre_mem::helpers::write_u32_le_at(&mut p, a, as_u(&value).unwrap_or(0) as u32),
            "u32_be" => rustre_mem::helpers::write_u32_be_at(&mut p, a, as_u(&value).unwrap_or(0) as u32),
            "u64_le" => rustre_mem::helpers::write_u64_le_at(&mut p, a, as_u(&value).unwrap_or(0)),
            "u64_be" => rustre_mem::helpers::write_u64_be_at(&mut p, a, as_u(&value).unwrap_or(0)),
            "i32_le" => rustre_mem::helpers::write_i32_le_at(&mut p, a, as_i(&value).unwrap_or(0) as i32),
            "i64_le" => rustre_mem::helpers::write_i64_le_at(&mut p, a, as_i(&value).unwrap_or(0)),
            "f32_le" => rustre_mem::helpers::write_f32_le_at(&mut p, a, as_f(&value).unwrap_or(0.0) as f32),
            "f64_le" => rustre_mem::helpers::write_f64_le_at(&mut p, a, as_f(&value).unwrap_or(0.0)),
            other => return Err(McpError::InvalidParams(format!("unknown kind '{other}'"))),
        };
        res.map_err(|e| McpError::InvalidParams(format!("write failed: {e}")))?;
        let data = <rustre_mem::VirtualMemoryProvider as rustre_mem::MemoryProvider>::read(&p, rustre_core::address::Address::new(0), buf_len).unwrap_or_default();
        let hex: String = data.iter().map(|b| format!("{b:02x}")).collect();
        Ok(ToolResult::text(json!({"kind": kind, "offset": offset, "buffer_hex": hex, "source": "rustre_mem::helpers::write_*_at"}).to_string()))
    }
}

pub struct MemPermsFromRwxTool;
impl MemPermsFromRwxTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_perms_from_rwx".to_string(), description: "Parse an rwx-string into permission flags.".to_string(), input_schema: json!({"type": "object", "required": ["s"], "properties": {"s": {"type": "string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemPermsFromRwxTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("s").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 's'".into()))?;
        match rustre_core::permissions::Permissions::from_rwx_string(s) {
            Some(p) => Ok(ToolResult::text(json!({"input": s, "readable": p.is_readable(), "writable": p.is_writable(), "executable": p.is_executable(), "bits": p.bits(), "source": "rustre_core::permissions::Permissions::from_rwx_string"}).to_string())),
            None => Err(McpError::InvalidParams(format!("invalid rwx string: {s}"))),
        }
    }
}

pub struct MemRegionKindListTool;
impl MemRegionKindListTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_region_kind_list".to_string(), description: "List the known memory region kinds recognised by rustre_mem::RegionKind.".to_string(), input_schema: json!({"type": "object", "properties": {}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemRegionKindListTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_mem::RegionKind::*;
        let kinds = [Code, Data, ReadOnlyData, Bss, ImportTable, ExportTable, ThreadLocalStorage, ExceptionHandling, Debug, SymbolTable, StringTable, DynamicLinker, Heap, Stack, MappedFile, KernelSpecial, Device, Guard, Unknown];
        let names: Vec<String> = kinds.iter().map(|k| format!("{k:?}")).collect();
        Ok(ToolResult::text(json!({"count": names.len(), "kinds": names, "source": "rustre_mem::RegionKind"}).to_string()))
    }
}

pub struct MemReadU128LeAtHexTool;
impl MemReadU128LeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_read_u128_le_at_hex".to_string(), description: "Read a little-endian u128 at offset via rustre_mem::read_u128_le_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex"],"properties":{"buffer_hex":{"type":"string"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemReadU128LeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (prov, _len) = _mem_prov_from_hex(buf_hex, base)?;
        let v = rustre_mem::helpers::read_u128_le_at(&prov, rustre_core::address::Address::new(base + offset));
        Ok(ToolResult::text(json!({"value_hex": v.map(|x| format!("{x:032x}")), "found": v.is_some(), "source":"rustre_mem::read_u128_le_at"}).to_string()))
    }
}

pub struct MemReadF32BeAtHexTool;
impl MemReadF32BeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_read_f32_be_at_hex".to_string(), description: "Read a big-endian f32 via rustre_mem::read_f32_be_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex"],"properties":{"buffer_hex":{"type":"string"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemReadF32BeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (prov, _len) = _mem_prov_from_hex(buf_hex, base)?;
        let v = rustre_mem::helpers::read_f32_be_at(&prov, rustre_core::address::Address::new(base + offset));
        Ok(ToolResult::text(json!({"value": v, "found": v.is_some(), "source":"rustre_mem::read_f32_be_at"}).to_string()))
    }
}

pub struct MemReadF64BeAtHexTool;
impl MemReadF64BeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_read_f64_be_at_hex".to_string(), description: "Read a big-endian f64 via rustre_mem::read_f64_be_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex"],"properties":{"buffer_hex":{"type":"string"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemReadF64BeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (prov, _len) = _mem_prov_from_hex(buf_hex, base)?;
        let v = rustre_mem::helpers::read_f64_be_at(&prov, rustre_core::address::Address::new(base + offset));
        Ok(ToolResult::text(json!({"value": v, "found": v.is_some(), "source":"rustre_mem::read_f64_be_at"}).to_string()))
    }
}

pub struct MemWriteU16BeAtHexTool;
impl MemWriteU16BeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_write_u16_be_at_hex".to_string(), description: "Write a big-endian u16 via rustre_mem::write_u16_be_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex","value"],"properties":{"buffer_hex":{"type":"string"},"value":{"type":"integer"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemWriteU16BeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let value = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))? as u16;
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (mut prov, len) = _mem_prov_from_hex(buf_hex, base)?;
        let ok = rustre_mem::helpers::write_u16_be_at(&mut prov, rustre_core::address::Address::new(base + offset), value).is_ok();
        use rustre_mem::MemoryProvider;
        let out = prov.read(rustre_core::address::Address::new(base), len).unwrap_or_default();
        Ok(ToolResult::text(json!({"ok": ok, "buffer_hex": hex_encode(&out), "source":"rustre_mem::write_u16_be_at"}).to_string()))
    }
}

pub struct MemWriteU32BeAtHexTool;
impl MemWriteU32BeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_write_u32_be_at_hex".to_string(), description: "Write a big-endian u32 via rustre_mem::write_u32_be_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex","value"],"properties":{"buffer_hex":{"type":"string"},"value":{"type":"integer"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemWriteU32BeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let value = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))? as u32;
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (mut prov, len) = _mem_prov_from_hex(buf_hex, base)?;
        let ok = rustre_mem::helpers::write_u32_be_at(&mut prov, rustre_core::address::Address::new(base + offset), value).is_ok();
        use rustre_mem::MemoryProvider;
        let out = prov.read(rustre_core::address::Address::new(base), len).unwrap_or_default();
        Ok(ToolResult::text(json!({"ok": ok, "buffer_hex": hex_encode(&out), "source":"rustre_mem::write_u32_be_at"}).to_string()))
    }
}

pub struct MemWriteU64BeAtHexTool;
impl MemWriteU64BeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_write_u64_be_at_hex".to_string(), description: "Write a big-endian u64 via rustre_mem::write_u64_be_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex","value"],"properties":{"buffer_hex":{"type":"string"},"value":{"type":"integer"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemWriteU64BeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let value = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (mut prov, len) = _mem_prov_from_hex(buf_hex, base)?;
        let ok = rustre_mem::helpers::write_u64_be_at(&mut prov, rustre_core::address::Address::new(base + offset), value).is_ok();
        use rustre_mem::MemoryProvider;
        let out = prov.read(rustre_core::address::Address::new(base), len).unwrap_or_default();
        Ok(ToolResult::text(json!({"ok": ok, "buffer_hex": hex_encode(&out), "source":"rustre_mem::write_u64_be_at"}).to_string()))
    }
}

pub struct MemSearchBytesRangeHexTool;
impl MemSearchBytesRangeHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_search_bytes_range_hex".to_string(), description: "Search a hex buffer for a literal byte pattern via rustre_mem::helpers::search_bytes.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex","pattern_hex"],"properties":{"buffer_hex":{"type":"string"},"pattern_hex":{"type":"string"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemSearchBytesRangeHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let pat_hex = args.get("pattern_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern_hex'".into()))?;
        let (prov, len) = _mem_prov_from_hex(buf_hex, base)?;
        let pat = crate::hex_decode(pat_hex.trim())?;
        if pat.is_empty() { return Err(McpError::InvalidParams("pattern must not be empty".into())); }
        let range = rustre_core::address::AddressRange::new(rustre_core::address::Address::new(base), rustre_core::address::Address::new(base + len as u64));
        let hits: Vec<u64> = rustre_mem::helpers::search_bytes(&prov, &pat, range).into_iter().map(|a| a.as_u64()).collect();
        Ok(ToolResult::text(json!({"count": hits.len(), "hits": hits, "source":"rustre_mem::helpers::search_bytes"}).to_string()))
    }
}

pub struct MemHighEntropySpansFromHexTool;
impl MemHighEntropySpansFromHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_high_entropy_spans_from_hex".to_string(), description: "Find high-entropy spans in a hex buffer via rustre_mem::entropy::high_entropy_spans.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex"],"properties":{"buffer_hex":{"type":"string"},"base_addr":{"type":"integer"},"block_size":{"type":"integer"},"threshold":{"type":"number"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemHighEntropySpansFromHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let block_size = args.get("block_size").and_then(Value::as_u64).unwrap_or(256) as usize;
        let threshold = args.get("threshold").and_then(Value::as_f64).unwrap_or(7.0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (prov, _len) = _mem_prov_from_hex(buf_hex, base)?;
        let blocks = rustre_mem::entropy::entropy_blocks(&prov, block_size);
        let spans = rustre_mem::entropy::high_entropy_spans(&blocks, threshold);
        let out: Vec<Value> = spans.iter().map(|s| json!({
            "start": s.start.as_u64(),
            "end": s.end.as_u64(),
            "len": s.len(),
            "mean_entropy": s.mean_entropy,
            "block_count": s.block_count,
        })).collect();
        Ok(ToolResult::text(json!({"count": out.len(), "spans": out, "source":"rustre_mem::entropy::high_entropy_spans"}).to_string()))
    }
}

pub struct MemReadU8AtHexTool;
impl MemReadU8AtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_read_u8_at_hex".to_string(), description: "Read a u8 via rustre_mem::read_u8_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex"],"properties":{"buffer_hex":{"type":"string"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemReadU8AtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (prov, _len) = _mem_prov_from_hex(buf_hex, base)?;
        let v = rustre_mem::helpers::read_u8_at(&prov, rustre_core::address::Address::new(base + offset));
        Ok(ToolResult::text(json!({"value": v, "found": v.is_some(), "source":"rustre_mem::read_u8_at"}).to_string()))
    }
}

pub struct MemReadI8AtHexTool;
impl MemReadI8AtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_read_i8_at_hex".to_string(), description: "Read an i8 via rustre_mem::read_i8_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex"],"properties":{"buffer_hex":{"type":"string"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemReadI8AtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (prov, _len) = _mem_prov_from_hex(buf_hex, base)?;
        let v = rustre_mem::helpers::read_i8_at(&prov, rustre_core::address::Address::new(base + offset));
        Ok(ToolResult::text(json!({"value": v, "found": v.is_some(), "source":"rustre_mem::read_i8_at"}).to_string()))
    }
}

pub struct MemReadI16LeAtHexTool;
impl MemReadI16LeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_read_i16_le_at_hex".to_string(), description: "Read an LE i16 via rustre_mem::read_i16_le_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex"],"properties":{"buffer_hex":{"type":"string"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemReadI16LeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (prov, _len) = _mem_prov_from_hex(buf_hex, base)?;
        let v = rustre_mem::helpers::read_i16_le_at(&prov, rustre_core::address::Address::new(base + offset));
        Ok(ToolResult::text(json!({"value": v, "found": v.is_some(), "source":"rustre_mem::read_i16_le_at"}).to_string()))
    }
}

pub struct MemReadI32LeAtHexTool;
impl MemReadI32LeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_read_i32_le_at_hex".to_string(), description: "Read an LE i32 via rustre_mem::read_i32_le_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex"],"properties":{"buffer_hex":{"type":"string"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemReadI32LeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (prov, _len) = _mem_prov_from_hex(buf_hex, base)?;
        let v = rustre_mem::helpers::read_i32_le_at(&prov, rustre_core::address::Address::new(base + offset));
        Ok(ToolResult::text(json!({"value": v, "found": v.is_some(), "source":"rustre_mem::read_i32_le_at"}).to_string()))
    }
}

pub struct MemReadI64LeAtHexTool;
impl MemReadI64LeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_read_i64_le_at_hex".to_string(), description: "Read an LE i64 via rustre_mem::read_i64_le_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex"],"properties":{"buffer_hex":{"type":"string"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemReadI64LeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (prov, _len) = _mem_prov_from_hex(buf_hex, base)?;
        let v = rustre_mem::helpers::read_i64_le_at(&prov, rustre_core::address::Address::new(base + offset));
        Ok(ToolResult::text(json!({"value": v, "found": v.is_some(), "source":"rustre_mem::read_i64_le_at"}).to_string()))
    }
}

pub struct MemReadF32LeAtHexTool;
impl MemReadF32LeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_read_f32_le_at_hex".to_string(), description: "Read an LE f32 via rustre_mem::read_f32_le_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex"],"properties":{"buffer_hex":{"type":"string"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemReadF32LeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (prov, _len) = _mem_prov_from_hex(buf_hex, base)?;
        let v = rustre_mem::helpers::read_f32_le_at(&prov, rustre_core::address::Address::new(base + offset));
        Ok(ToolResult::text(json!({"value": v, "found": v.is_some(), "source":"rustre_mem::read_f32_le_at"}).to_string()))
    }
}

pub struct MemReadF64LeAtHexTool;
impl MemReadF64LeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_read_f64_le_at_hex".to_string(), description: "Read an LE f64 via rustre_mem::read_f64_le_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex"],"properties":{"buffer_hex":{"type":"string"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemReadF64LeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (prov, _len) = _mem_prov_from_hex(buf_hex, base)?;
        let v = rustre_mem::helpers::read_f64_le_at(&prov, rustre_core::address::Address::new(base + offset));
        Ok(ToolResult::text(json!({"value": v, "found": v.is_some(), "source":"rustre_mem::read_f64_le_at"}).to_string()))
    }
}

pub struct MemWriteI32LeAtHexTool;
impl MemWriteI32LeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_write_i32_le_at_hex".to_string(), description: "Write an LE i32 via rustre_mem::write_i32_le_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex","value"],"properties":{"buffer_hex":{"type":"string"},"value":{"type":"integer"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemWriteI32LeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let value = args.get("value").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))? as i32;
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (mut prov, len) = _mem_prov_from_hex(buf_hex, base)?;
        let ok = rustre_mem::helpers::write_i32_le_at(&mut prov, rustre_core::address::Address::new(base + offset), value).is_ok();
        use rustre_mem::MemoryProvider;
        let out = prov.read(rustre_core::address::Address::new(base), len).unwrap_or_default();
        Ok(ToolResult::text(json!({"ok": ok, "buffer_hex": hex_encode(&out), "source":"rustre_mem::write_i32_le_at"}).to_string()))
    }
}

pub struct MemWriteI64LeAtHexTool;
impl MemWriteI64LeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_write_i64_le_at_hex".to_string(), description: "Write an LE i64 via rustre_mem::write_i64_le_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex","value"],"properties":{"buffer_hex":{"type":"string"},"value":{"type":"integer"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemWriteI64LeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let value = args.get("value").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (mut prov, len) = _mem_prov_from_hex(buf_hex, base)?;
        let ok = rustre_mem::helpers::write_i64_le_at(&mut prov, rustre_core::address::Address::new(base + offset), value).is_ok();
        use rustre_mem::MemoryProvider;
        let out = prov.read(rustre_core::address::Address::new(base), len).unwrap_or_default();
        Ok(ToolResult::text(json!({"ok": ok, "buffer_hex": hex_encode(&out), "source":"rustre_mem::write_i64_le_at"}).to_string()))
    }
}

pub struct MemWriteF32LeAtHexTool;
impl MemWriteF32LeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_write_f32_le_at_hex".to_string(), description: "Write an LE f32 via rustre_mem::write_f32_le_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex","value"],"properties":{"buffer_hex":{"type":"string"},"value":{"type":"number"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemWriteF32LeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let value = args.get("value").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))? as f32;
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (mut prov, len) = _mem_prov_from_hex(buf_hex, base)?;
        let ok = rustre_mem::helpers::write_f32_le_at(&mut prov, rustre_core::address::Address::new(base + offset), value).is_ok();
        use rustre_mem::MemoryProvider;
        let out = prov.read(rustre_core::address::Address::new(base), len).unwrap_or_default();
        Ok(ToolResult::text(json!({"ok": ok, "buffer_hex": hex_encode(&out), "source":"rustre_mem::write_f32_le_at"}).to_string()))
    }
}

pub struct MemWriteF64LeAtHexTool;
impl MemWriteF64LeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_write_f64_le_at_hex".to_string(), description: "Write an LE f64 via rustre_mem::write_f64_le_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex","value"],"properties":{"buffer_hex":{"type":"string"},"value":{"type":"number"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemWriteF64LeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let value = args.get("value").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (mut prov, len) = _mem_prov_from_hex(buf_hex, base)?;
        let ok = rustre_mem::helpers::write_f64_le_at(&mut prov, rustre_core::address::Address::new(base + offset), value).is_ok();
        use rustre_mem::MemoryProvider;
        let out = prov.read(rustre_core::address::Address::new(base), len).unwrap_or_default();
        Ok(ToolResult::text(json!({"ok": ok, "buffer_hex": hex_encode(&out), "source":"rustre_mem::write_f64_le_at"}).to_string()))
    }
}

pub struct MemReadU16LeAtHexTool;
impl MemReadU16LeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_read_u16_le_at_hex".to_string(), description: "Read a little-endian u16 via rustre_mem::read_u16_le_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex"],"properties":{"buffer_hex":{"type":"string"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemReadU16LeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (prov, _len) = _mem_prov_from_hex(buf_hex, base)?;
        let v = rustre_mem::helpers::read_u16_le_at(&prov, rustre_core::address::Address::new(base + offset));
        Ok(ToolResult::text(json!({"value": v, "found": v.is_some(), "source":"rustre_mem::read_u16_le_at"}).to_string()))
    }
}

pub struct MemReadU16BeAtHexTool;
impl MemReadU16BeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_read_u16_be_at_hex".to_string(), description: "Read a big-endian u16 via rustre_mem::read_u16_be_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex"],"properties":{"buffer_hex":{"type":"string"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemReadU16BeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (prov, _len) = _mem_prov_from_hex(buf_hex, base)?;
        let v = rustre_mem::helpers::read_u16_be_at(&prov, rustre_core::address::Address::new(base + offset));
        Ok(ToolResult::text(json!({"value": v, "found": v.is_some(), "source":"rustre_mem::read_u16_be_at"}).to_string()))
    }
}

pub struct MemReadU32LeAtHexTool;
impl MemReadU32LeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_read_u32_le_at_hex".to_string(), description: "Read a little-endian u32 via rustre_mem::read_u32_le_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex"],"properties":{"buffer_hex":{"type":"string"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemReadU32LeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (prov, _len) = _mem_prov_from_hex(buf_hex, base)?;
        let v = rustre_mem::helpers::read_u32_le_at(&prov, rustre_core::address::Address::new(base + offset));
        Ok(ToolResult::text(json!({"value": v, "found": v.is_some(), "source":"rustre_mem::read_u32_le_at"}).to_string()))
    }
}

pub struct MemReadU32BeAtHexTool;
impl MemReadU32BeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_read_u32_be_at_hex".to_string(), description: "Read a big-endian u32 via rustre_mem::read_u32_be_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex"],"properties":{"buffer_hex":{"type":"string"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemReadU32BeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (prov, _len) = _mem_prov_from_hex(buf_hex, base)?;
        let v = rustre_mem::helpers::read_u32_be_at(&prov, rustre_core::address::Address::new(base + offset));
        Ok(ToolResult::text(json!({"value": v, "found": v.is_some(), "source":"rustre_mem::read_u32_be_at"}).to_string()))
    }
}

pub struct MemReadU64LeAtHexTool;
impl MemReadU64LeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_read_u64_le_at_hex".to_string(), description: "Read a little-endian u64 via rustre_mem::read_u64_le_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex"],"properties":{"buffer_hex":{"type":"string"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemReadU64LeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (prov, _len) = _mem_prov_from_hex(buf_hex, base)?;
        let v = rustre_mem::helpers::read_u64_le_at(&prov, rustre_core::address::Address::new(base + offset));
        Ok(ToolResult::text(json!({"value": v, "found": v.is_some(), "source":"rustre_mem::read_u64_le_at"}).to_string()))
    }
}

pub struct MemReadU64BeAtHexTool;
impl MemReadU64BeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_read_u64_be_at_hex".to_string(), description: "Read a big-endian u64 via rustre_mem::read_u64_be_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex"],"properties":{"buffer_hex":{"type":"string"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemReadU64BeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (prov, _len) = _mem_prov_from_hex(buf_hex, base)?;
        let v = rustre_mem::helpers::read_u64_be_at(&prov, rustre_core::address::Address::new(base + offset));
        Ok(ToolResult::text(json!({"value": v, "found": v.is_some(), "source":"rustre_mem::read_u64_be_at"}).to_string()))
    }
}

pub struct MemWriteU8AtHexTool;
impl MemWriteU8AtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_write_u8_at_hex".to_string(), description: "Write a u8 via rustre_mem::write_u8_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex","value"],"properties":{"buffer_hex":{"type":"string"},"value":{"type":"integer"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemWriteU8AtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let value = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))? as u8;
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (mut prov, len) = _mem_prov_from_hex(buf_hex, base)?;
        let ok = rustre_mem::helpers::write_u8_at(&mut prov, rustre_core::address::Address::new(base + offset), value).is_ok();
        use rustre_mem::MemoryProvider;
        let out = prov.read(rustre_core::address::Address::new(base), len).unwrap_or_default();
        Ok(ToolResult::text(json!({"ok": ok, "buffer_hex": hex_encode(&out), "source":"rustre_mem::write_u8_at"}).to_string()))
    }
}

pub struct MemWriteU16LeAtHexTool;
impl MemWriteU16LeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_write_u16_le_at_hex".to_string(), description: "Write a little-endian u16 via rustre_mem::write_u16_le_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex","value"],"properties":{"buffer_hex":{"type":"string"},"value":{"type":"integer"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemWriteU16LeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let value = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))? as u16;
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (mut prov, len) = _mem_prov_from_hex(buf_hex, base)?;
        let ok = rustre_mem::helpers::write_u16_le_at(&mut prov, rustre_core::address::Address::new(base + offset), value).is_ok();
        use rustre_mem::MemoryProvider;
        let out = prov.read(rustre_core::address::Address::new(base), len).unwrap_or_default();
        Ok(ToolResult::text(json!({"ok": ok, "buffer_hex": hex_encode(&out), "source":"rustre_mem::write_u16_le_at"}).to_string()))
    }
}

pub struct MemWriteU32LeAtHexTool;
impl MemWriteU32LeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_write_u32_le_at_hex".to_string(), description: "Write a little-endian u32 via rustre_mem::write_u32_le_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex","value"],"properties":{"buffer_hex":{"type":"string"},"value":{"type":"integer"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemWriteU32LeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let value = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))? as u32;
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (mut prov, len) = _mem_prov_from_hex(buf_hex, base)?;
        let ok = rustre_mem::helpers::write_u32_le_at(&mut prov, rustre_core::address::Address::new(base + offset), value).is_ok();
        use rustre_mem::MemoryProvider;
        let out = prov.read(rustre_core::address::Address::new(base), len).unwrap_or_default();
        Ok(ToolResult::text(json!({"ok": ok, "buffer_hex": hex_encode(&out), "source":"rustre_mem::write_u32_le_at"}).to_string()))
    }
}

pub struct MemWriteU64LeAtHexTool;
impl MemWriteU64LeAtHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_write_u64_le_at_hex".to_string(), description: "Write a little-endian u64 via rustre_mem::write_u64_le_at.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex","value"],"properties":{"buffer_hex":{"type":"string"},"value":{"type":"integer"},"offset":{"type":"integer"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemWriteU64LeAtHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let value = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let (mut prov, len) = _mem_prov_from_hex(buf_hex, base)?;
        let ok = rustre_mem::helpers::write_u64_le_at(&mut prov, rustre_core::address::Address::new(base + offset), value).is_ok();
        use rustre_mem::MemoryProvider;
        let out = prov.read(rustre_core::address::Address::new(base), len).unwrap_or_default();
        Ok(ToolResult::text(json!({"ok": ok, "buffer_hex": hex_encode(&out), "source":"rustre_mem::write_u64_le_at"}).to_string()))
    }
}

pub struct MemSearchBytesAllHexTool;
impl MemSearchBytesAllHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "mem_search_bytes_all_hex".to_string(), description: "Search hex buffer for all occurrences of a literal pattern via rustre_mem::helpers::search_bytes.".to_string(), input_schema: json!({"type":"object","required":["buffer_hex","pattern_hex"],"properties":{"buffer_hex":{"type":"string"},"pattern_hex":{"type":"string"},"base_addr":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for MemSearchBytesAllHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0);
        let buf_hex = args.get("buffer_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'buffer_hex'".into()))?;
        let pat_hex = args.get("pattern_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern_hex'".into()))?;
        let pat = crate::hex_decode(pat_hex.trim())?;
        let (prov, len) = _mem_prov_from_hex(buf_hex, base)?;
        let range = rustre_core::address::AddressRange::new(rustre_core::address::Address::new(base), rustre_core::address::Address::new(base + len as u64));
        let hits = rustre_mem::helpers::search_bytes(&prov, &pat, range);
        let addrs: Vec<u64> = hits.iter().map(|a| a.as_u64()).collect();
        Ok(ToolResult::text(json!({"count": addrs.len(), "matches": addrs, "source":"rustre_mem::helpers::search_bytes"}).to_string()))
    }
}

pub struct MemShannonEntropyMaxBlockWireTool;
impl MemShannonEntropyMaxBlockWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_shannon_entropy_max_block_wire".to_string(), description: "Max Shannon entropy across chunks via rustre_mem::shannon_entropy.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"},"block_size":{"type":"integer"}},"required":["hex","block_size"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemShannonEntropyMaxBlockWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = __mem_hex_decode_v2(args.get("hex").and_then(Value::as_str).unwrap_or(""))?; let bs = args.get("block_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'block_size'".into()))? as usize; if bs == 0 { return Err(McpError::InvalidParams("'block_size' must be > 0".into())); } let mut max_e: f64 = 0.0; let mut count = 0usize; let mut i = 0; while i < data.len() { let end = (i + bs).min(data.len()); let e = rustre_mem::shannon_entropy(&data[i..end]); if e > max_e { max_e = e; } count += 1; i = end; } Ok(ToolResult::text(json!({"max_entropy": max_e, "block_count": count, "source": "rustre_mem::shannon_entropy"}).to_string())) } }

pub struct MemShannonEntropyMinBlockWireTool;
impl MemShannonEntropyMinBlockWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_shannon_entropy_min_block_wire".to_string(), description: "Min Shannon entropy across chunks via rustre_mem::shannon_entropy.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"},"block_size":{"type":"integer"}},"required":["hex","block_size"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemShannonEntropyMinBlockWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = __mem_hex_decode_v2(args.get("hex").and_then(Value::as_str).unwrap_or(""))?; let bs = args.get("block_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'block_size'".into()))? as usize; if bs == 0 { return Err(McpError::InvalidParams("'block_size' must be > 0".into())); } let mut min_e: f64 = 8.0; let mut count = 0usize; let mut i = 0; if data.is_empty() { min_e = 0.0; } while i < data.len() { let end = (i + bs).min(data.len()); let e = rustre_mem::shannon_entropy(&data[i..end]); if e < min_e { min_e = e; } count += 1; i = end; } Ok(ToolResult::text(json!({"min_entropy": min_e, "block_count": count, "source": "rustre_mem::shannon_entropy"}).to_string())) } }

pub struct MemShannonEntropyMeanBlockWireTool;
impl MemShannonEntropyMeanBlockWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_shannon_entropy_mean_block_wire".to_string(), description: "Mean Shannon entropy across chunks.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"},"block_size":{"type":"integer"}},"required":["hex","block_size"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemShannonEntropyMeanBlockWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = __mem_hex_decode_v2(args.get("hex").and_then(Value::as_str).unwrap_or(""))?; let bs = args.get("block_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'block_size'".into()))? as usize; if bs == 0 { return Err(McpError::InvalidParams("'block_size' must be > 0".into())); } let mut sum: f64 = 0.0; let mut count = 0usize; let mut i = 0; while i < data.len() { let end = (i + bs).min(data.len()); sum += rustre_mem::shannon_entropy(&data[i..end]); count += 1; i = end; } let mean = if count > 0 { sum / count as f64 } else { 0.0 }; Ok(ToolResult::text(json!({"mean_entropy": mean, "block_count": count, "source": "rustre_mem::shannon_entropy"}).to_string())) } }

pub struct MemEntropyClassifyValueWireTool;
impl MemEntropyClassifyValueWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_entropy_classify_value_wire".to_string(), description: "Classify entropy via rustre_mem::EntropyBlock::classification.".to_string(), input_schema: json!({"type":"object","properties":{"entropy":{"type":"number"}},"required":["entropy"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemEntropyClassifyValueWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let e = args.get("entropy").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing 'entropy'".into()))?; let block = rustre_mem::EntropyBlock { address: rustre_core::address::Address::new(0), size: 0, entropy: e }; Ok(ToolResult::text(json!({"entropy": e, "classification": block.classification(), "source": "rustre_mem::EntropyBlock::classification"}).to_string())) } }

pub struct MemPageAlignUpManyWireTool;
impl MemPageAlignUpManyWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_page_align_up_many_wire".to_string(), description: "Bulk rustre_mem::page_align_up for many addresses.".to_string(), input_schema: json!({"type":"object","properties":{"addrs":{"type":"array","items":{"type":"integer"}},"page_size":{"type":"integer"}},"required":["addrs","page_size"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemPageAlignUpManyWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addrs = args.get("addrs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'addrs'".into()))?; let ps = args.get("page_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'page_size'".into()))?; if !ps.is_power_of_two() { return Err(McpError::InvalidParams("'page_size' must be a power of two".into())); } let out: Vec<u64> = addrs.iter().filter_map(Value::as_u64).map(|a| rustre_mem::page_align_up(rustre_core::address::Address::new(a), ps).as_u64()).collect(); Ok(ToolResult::text(json!({"aligned": out, "page_size": ps, "source": "rustre_mem::page_align_up"}).to_string())) } }

pub struct MemPageAlignDownManyWireTool;
impl MemPageAlignDownManyWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_page_align_down_many_wire".to_string(), description: "Bulk rustre_mem::page_align_down.".to_string(), input_schema: json!({"type":"object","properties":{"addrs":{"type":"array","items":{"type":"integer"}},"page_size":{"type":"integer"}},"required":["addrs","page_size"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemPageAlignDownManyWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addrs = args.get("addrs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'addrs'".into()))?; let ps = args.get("page_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'page_size'".into()))?; if !ps.is_power_of_two() { return Err(McpError::InvalidParams("'page_size' must be a power of two".into())); } let out: Vec<u64> = addrs.iter().filter_map(Value::as_u64).map(|a| rustre_mem::page_align_down(rustre_core::address::Address::new(a), ps).as_u64()).collect(); Ok(ToolResult::text(json!({"aligned": out, "page_size": ps, "source": "rustre_mem::page_align_down"}).to_string())) } }

pub struct MemPageIndexManyWireTool;
impl MemPageIndexManyWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_page_index_many_wire".to_string(), description: "Bulk rustre_mem::page_index.".to_string(), input_schema: json!({"type":"object","properties":{"addrs":{"type":"array","items":{"type":"integer"}},"page_size":{"type":"integer"}},"required":["addrs","page_size"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemPageIndexManyWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addrs = args.get("addrs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'addrs'".into()))?; let ps = args.get("page_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'page_size'".into()))?; if ps == 0 { return Err(McpError::InvalidParams("'page_size' must be non-zero".into())); } let out: Vec<u64> = addrs.iter().filter_map(Value::as_u64).map(|a| rustre_mem::page_index(rustre_core::address::Address::new(a), ps)).collect(); Ok(ToolResult::text(json!({"indices": out, "page_size": ps, "source": "rustre_mem::page_index"}).to_string())) } }

pub struct MemPageContainingLenWireTool;
impl MemPageContainingLenWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_page_containing_len_wire".to_string(), description: "Length of page-containing range from rustre_mem::page_containing.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"page_size":{"type":"integer"}},"required":["addr","page_size"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemPageContainingLenWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let ps = args.get("page_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'page_size'".into()))?; if !ps.is_power_of_two() { return Err(McpError::InvalidParams("'page_size' must be a power of two".into())); } let range = rustre_mem::page_containing(rustre_core::address::Address::new(addr), ps); Ok(ToolResult::text(json!({"start": range.start.as_u64(), "end": range.end.as_u64(), "len": range.len(), "source": "rustre_mem::page_containing"}).to_string())) } }

pub struct MemShannonEntropyV3Tool;
impl MemShannonEntropyV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_shannon_entropy_v3".to_string(), description: "rustre_mem::shannon_entropy on hex bytes.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemShannonEntropyV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let data = __mem_hex_decode_v2(hex)?; let e = rustre_mem::shannon_entropy(&data); Ok(ToolResult::text(json!({"len":data.len(),"entropy":e,"source":"rustre_mem::shannon_entropy"}).to_string())) } }

pub struct MemPageAlignUpV3Tool;
impl MemPageAlignUpV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_page_align_up_v3".to_string(), description: "rustre_mem::page_align_up.".to_string(), input_schema: json!({"type":"object","required":["addr","page_size"],"properties":{"addr":{"type":"integer"},"page_size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemPageAlignUpV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let ps = args.get("page_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'page_size'".into()))?; if ps == 0 { return Err(McpError::InvalidParams("page_size==0".into())); } let a = rustre_mem::page_align_up(rustre_core::address::Address::new(addr), ps); Ok(ToolResult::text(json!({"aligned":a.as_u64(),"source":"rustre_mem::page_align_up"}).to_string())) } }

pub struct MemPageAlignDownV3Tool;
impl MemPageAlignDownV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_page_align_down_v3".to_string(), description: "rustre_mem::page_align_down.".to_string(), input_schema: json!({"type":"object","required":["addr","page_size"],"properties":{"addr":{"type":"integer"},"page_size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemPageAlignDownV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let ps = args.get("page_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'page_size'".into()))?; if ps == 0 { return Err(McpError::InvalidParams("page_size==0".into())); } let a = rustre_mem::page_align_down(rustre_core::address::Address::new(addr), ps); Ok(ToolResult::text(json!({"aligned":a.as_u64(),"source":"rustre_mem::page_align_down"}).to_string())) } }

pub struct MemEntropyBlocksHexV3Tool;
impl MemEntropyBlocksHexV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_entropy_blocks_hex_v3".to_string(), description: "Per-block rustre_mem::shannon_entropy over hex bytes.".to_string(), input_schema: json!({"type":"object","required":["hex","block_size"],"properties":{"hex":{"type":"string"},"block_size":{"type":"integer","minimum":1}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemEntropyBlocksHexV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let bs = args.get("block_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'block_size'".into()))? as usize; if bs == 0 { return Err(McpError::InvalidParams("block_size==0".into())); } let data = __mem_hex_decode_v2(hex)?; let mut entropies: Vec<f64> = Vec::new(); for chunk in data.chunks(bs) { entropies.push(rustre_mem::shannon_entropy(chunk)); } Ok(ToolResult::text(json!({"count":entropies.len(),"block_size":bs,"entropies":entropies,"source":"rustre_mem::shannon_entropy"}).to_string())) } }

pub struct MemHighEntropySpansV3Tool;
impl MemHighEntropySpansV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_high_entropy_spans_v3".to_string(), description: "Group blocks via rustre_mem::entropy::high_entropy_spans.".to_string(), input_schema: json!({"type":"object","required":["hex","block_size","threshold"],"properties":{"hex":{"type":"string"},"block_size":{"type":"integer","minimum":1},"threshold":{"type":"number"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemHighEntropySpansV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let bs = args.get("block_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'block_size'".into()))? as usize; if bs == 0 { return Err(McpError::InvalidParams("block_size==0".into())); } let thr = args.get("threshold").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing 'threshold'".into()))?; let data = __mem_hex_decode_v2(hex)?; let mut blocks: Vec<rustre_mem::EntropyBlock> = Vec::new(); for (i, chunk) in data.chunks(bs).enumerate() { blocks.push(rustre_mem::EntropyBlock { address: rustre_core::address::Address::new((i * bs) as u64), size: chunk.len(), entropy: rustre_mem::shannon_entropy(chunk) }); } let spans = rustre_mem::entropy::high_entropy_spans(&blocks, thr); Ok(ToolResult::text(json!({"span_count":spans.len(),"threshold":thr,"source":"rustre_mem::entropy::high_entropy_spans"}).to_string())) } }

pub struct MemReadU128LeAtHexV2Tool;
impl MemReadU128LeAtHexV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_read_u128_le_at_hex_v2".to_string(), description: "Read u128 LE at offset from hex bytes.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"},"offset":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemReadU128LeAtHexV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let off = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize; let data = __mem_hex_decode_v2(hex)?; if off + 16 > data.len() { return Err(McpError::InvalidParams("range out of bounds".into())); } let mut a = [0u8; 16]; a.copy_from_slice(&data[off..off+16]); Ok(ToolResult::text(json!({"value":u128::from_le_bytes(a).to_string(),"source":"u128::from_le_bytes"}).to_string())) } }

pub struct MemReadF32BeAtHexV2Tool;
impl MemReadF32BeAtHexV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_read_f32_be_at_hex_v2".to_string(), description: "Read f32 BE at offset from hex bytes.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"},"offset":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemReadF32BeAtHexV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let off = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize; let data = __mem_hex_decode_v2(hex)?; if off + 4 > data.len() { return Err(McpError::InvalidParams("range out of bounds".into())); } let mut a = [0u8; 4]; a.copy_from_slice(&data[off..off+4]); Ok(ToolResult::text(json!({"value":f32::from_be_bytes(a),"source":"f32::from_be_bytes"}).to_string())) } }

pub struct MemReadF64BeAtHexV2Tool;
impl MemReadF64BeAtHexV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_read_f64_be_at_hex_v2".to_string(), description: "Read f64 BE at offset from hex bytes.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"},"offset":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemReadF64BeAtHexV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let off = args.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize; let data = __mem_hex_decode_v2(hex)?; if off + 8 > data.len() { return Err(McpError::InvalidParams("range out of bounds".into())); } let mut a = [0u8; 8]; a.copy_from_slice(&data[off..off+8]); Ok(ToolResult::text(json!({"value":f64::from_be_bytes(a),"source":"f64::from_be_bytes"}).to_string())) } }

pub struct MemSearchBytesHexV2Tool;
impl MemSearchBytesHexV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_search_bytes_hex_v2".to_string(), description: "Find all offsets of pattern_hex in hex haystack.".to_string(), input_schema: json!({"type":"object","required":["hex","pattern_hex"],"properties":{"hex":{"type":"string"},"pattern_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemSearchBytesHexV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let pat_hex = args.get("pattern_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern_hex'".into()))?; let data = __mem_hex_decode_v2(hex)?; let pat = __mem_hex_decode_v2(pat_hex)?; if pat.is_empty() { return Err(McpError::InvalidParams("empty pattern".into())); } let mut hits: Vec<usize> = Vec::new(); if pat.len() <= data.len() { for i in 0..=(data.len() - pat.len()) { if data[i..i+pat.len()] == pat[..] { hits.push(i); } } } let count = hits.len(); Ok(ToolResult::text(json!({"hits":hits,"count":count,"source":"rustre_mem-inline-search"}).to_string())) } }

pub struct MemPageAlignUpV5Tool;
impl MemPageAlignUpV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_page_align_up_v5".to_string(), description: "rustre_mem::page_align_up with is_aligned info.".to_string(), input_schema: json!({"type":"object","required":["addr","page_size"],"properties":{"addr":{"type":"integer","minimum":0},"page_size":{"type":"integer","minimum":1}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemPageAlignUpV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let ps = args.get("page_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'page_size'".into()))?; if ps == 0 { return Err(McpError::InvalidParams("page_size==0".into())); } let a = rustre_mem::page_align_up(rustre_core::address::Address::new(addr), ps); Ok(ToolResult::text(json!({"aligned":a.as_u64(),"was_aligned":a.as_u64()==addr,"source":"rustre_mem::page_align_up"}).to_string())) } }

pub struct MemPageAlignDownV5Tool;
impl MemPageAlignDownV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_page_align_down_v5".to_string(), description: "rustre_mem::page_align_down with is_aligned info.".to_string(), input_schema: json!({"type":"object","required":["addr","page_size"],"properties":{"addr":{"type":"integer","minimum":0},"page_size":{"type":"integer","minimum":1}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemPageAlignDownV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let ps = args.get("page_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'page_size'".into()))?; if ps == 0 { return Err(McpError::InvalidParams("page_size==0".into())); } let a = rustre_mem::page_align_down(rustre_core::address::Address::new(addr), ps); Ok(ToolResult::text(json!({"aligned":a.as_u64(),"was_aligned":a.as_u64()==addr,"source":"rustre_mem::page_align_down"}).to_string())) } }

pub struct MemPageContainingV5Tool;
impl MemPageContainingV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_page_containing_v5".to_string(), description: "rustre_mem::page_containing returns the base of the page.".to_string(), input_schema: json!({"type":"object","required":["addr","page_size"],"properties":{"addr":{"type":"integer","minimum":0},"page_size":{"type":"integer","minimum":1}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemPageContainingV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let ps = args.get("page_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'page_size'".into()))?; if ps == 0 { return Err(McpError::InvalidParams("page_size==0".into())); } let base = rustre_mem::page_containing(rustre_core::address::Address::new(addr), ps); Ok(ToolResult::text(json!({"page_base":base.start.as_u64(),"page_end":base.end.as_u64(),"source":"rustre_mem::page_containing"}).to_string())) } }

pub struct MemPageIndexV5Tool;
impl MemPageIndexV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_page_index_v5".to_string(), description: "rustre_mem::page_index (addr / page_size).".to_string(), input_schema: json!({"type":"object","required":["addr","page_size"],"properties":{"addr":{"type":"integer","minimum":0},"page_size":{"type":"integer","minimum":1}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemPageIndexV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let ps = args.get("page_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'page_size'".into()))?; if ps == 0 { return Err(McpError::InvalidParams("page_size==0".into())); } let idx = rustre_mem::page_index(rustre_core::address::Address::new(addr), ps); Ok(ToolResult::text(json!({"index":idx,"source":"rustre_mem::page_index"}).to_string())) } }

pub struct MemPageRangeIndicesV5Tool;
impl MemPageRangeIndicesV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_page_range_indices_v5".to_string(), description: "rustre_mem::page_range_indices over [start,end).".to_string(), input_schema: json!({"type":"object","required":["start","end","page_size"],"properties":{"start":{"type":"integer","minimum":0},"end":{"type":"integer","minimum":0},"page_size":{"type":"integer","minimum":1}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemPageRangeIndicesV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))?; let e = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'end'".into()))?; let ps = args.get("page_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'page_size'".into()))?; if ps == 0 || s > e { return Err(McpError::InvalidParams("bad range or page_size==0".into())); } let range = rustre_core::address::AddressRange::new(rustre_core::address::Address::new(s), rustre_core::address::Address::new(e)); let (a, b) = rustre_mem::page_range_indices(&range, ps); Ok(ToolResult::text(json!({"first":a,"last":b,"source":"rustre_mem::page_range_indices"}).to_string())) } }

pub struct MemShannonEntropyFromBytesV5Tool;
impl MemShannonEntropyFromBytesV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_shannon_entropy_from_bytes_v5".to_string(), description: "rustre_mem::shannon_entropy on hex bytes with len info.".to_string(), input_schema: json!({"type":"object","required":["hex"],"properties":{"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemShannonEntropyFromBytesV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let data = __mem_hex_decode_v2(hex)?; let e = rustre_mem::shannon_entropy(&data); Ok(ToolResult::text(json!({"len":data.len(),"entropy":e,"is_zero":e==0.0,"source":"rustre_mem::shannon_entropy"}).to_string())) } }

pub struct MemPermsFromRwxV5Tool;
impl MemPermsFromRwxV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_perms_from_rwx_v5".to_string(), description: "rustre_core::permissions::Permissions::from_rwx_string.".to_string(), input_schema: json!({"type":"object","required":["rwx"],"properties":{"rwx":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemPermsFromRwxV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let rwx = args.get("rwx").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'rwx'".into()))?; let p = rustre_core::permissions::Permissions::from_rwx_string(rwx).ok_or_else(|| McpError::InvalidParams("bad rwx".into()))?; Ok(ToolResult::text(json!({"r":p.is_readable(),"w":p.is_writable(),"x":p.is_executable(),"source":"Permissions::from_rwx_string"}).to_string())) } }

pub struct MemVirtualProviderReadU8V5Tool;
impl MemVirtualProviderReadU8V5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_virtual_provider_read_u8_v5".to_string(), description: "Map hex bytes at addr and read_u8_at.".to_string(), input_schema: json!({"type":"object","required":["addr","hex"],"properties":{"addr":{"type":"integer","minimum":0},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemVirtualProviderReadU8V5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let data = __mem_hex_decode_v2(hex)?; if data.is_empty() { return Err(McpError::InvalidParams("empty data".into())); } let mut p = rustre_mem::VirtualMemoryProvider::new(); p.map(rustre_core::address::Address::new(addr), data, rustre_core::permissions::Permissions::READ | rustre_core::permissions::Permissions::WRITE); let v = rustre_mem::read_u8_at(&p, rustre_core::address::Address::new(addr)); Ok(ToolResult::text(json!({"value":v,"source":"rustre_mem::read_u8_at"}).to_string())) } }

pub struct MemVirtualProviderReadU32LeV5Tool;
impl MemVirtualProviderReadU32LeV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_virtual_provider_read_u32_le_v5".to_string(), description: "Map hex bytes at addr and read_u32_le_at.".to_string(), input_schema: json!({"type":"object","required":["addr","hex"],"properties":{"addr":{"type":"integer","minimum":0},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemVirtualProviderReadU32LeV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let data = __mem_hex_decode_v2(hex)?; if data.len() < 4 { return Err(McpError::InvalidParams("need >=4 bytes".into())); } let mut p = rustre_mem::VirtualMemoryProvider::new(); p.map(rustre_core::address::Address::new(addr), data, rustre_core::permissions::Permissions::READ | rustre_core::permissions::Permissions::WRITE); let v = rustre_mem::read_u32_le_at(&p, rustre_core::address::Address::new(addr)); Ok(ToolResult::text(json!({"value":v,"source":"rustre_mem::read_u32_le_at"}).to_string())) } }

pub struct MemVirtualProviderReadU64LeV5Tool;
impl MemVirtualProviderReadU64LeV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_virtual_provider_read_u64_le_v5".to_string(), description: "Map hex bytes at addr and read_u64_le_at.".to_string(), input_schema: json!({"type":"object","required":["addr","hex"],"properties":{"addr":{"type":"integer","minimum":0},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemVirtualProviderReadU64LeV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let data = __mem_hex_decode_v2(hex)?; if data.len() < 8 { return Err(McpError::InvalidParams("need >=8 bytes".into())); } let mut p = rustre_mem::VirtualMemoryProvider::new(); p.map(rustre_core::address::Address::new(addr), data, rustre_core::permissions::Permissions::READ | rustre_core::permissions::Permissions::WRITE); let v = rustre_mem::read_u64_le_at(&p, rustre_core::address::Address::new(addr)); Ok(ToolResult::text(json!({"value":v.map(|x| x.to_string()),"source":"rustre_mem::read_u64_le_at"}).to_string())) } }

pub struct MemVirtualProviderWriteU32LeV5Tool;
impl MemVirtualProviderWriteU32LeV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_virtual_provider_write_u32_le_v5".to_string(), description: "write_u32_le_at then read back.".to_string(), input_schema: json!({"type":"object","required":["addr","value"],"properties":{"addr":{"type":"integer","minimum":0},"value":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemVirtualProviderWriteU32LeV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let value = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?; let value = u32::try_from(value).map_err(|_| McpError::InvalidParams("value > u32".into()))?; let mut p = rustre_mem::VirtualMemoryProvider::new(); p.map(rustre_core::address::Address::new(addr), vec![0u8; 8], rustre_core::permissions::Permissions::READ | rustre_core::permissions::Permissions::WRITE); rustre_mem::write_u32_le_at(&mut p, rustre_core::address::Address::new(addr), value).map_err(|e| McpError::InternalError(format!("write: {e}")))?; let v = rustre_mem::read_u32_le_at(&p, rustre_core::address::Address::new(addr)); Ok(ToolResult::text(json!({"written":value,"read_back":v,"source":"rustre_mem::write_u32_le_at"}).to_string())) } }

pub struct MemFindBytesProviderV5Tool;
impl MemFindBytesProviderV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_find_bytes_provider_v5".to_string(), description: "Map hex bytes and call VirtualMemoryProvider::find_bytes.".to_string(), input_schema: json!({"type":"object","required":["addr","hex","pattern_hex"],"properties":{"addr":{"type":"integer","minimum":0},"hex":{"type":"string"},"pattern_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemFindBytesProviderV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let pat = args.get("pattern_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern_hex'".into()))?; let data = __mem_hex_decode_v2(hex)?; let pat = __mem_hex_decode_v2(pat)?; if pat.is_empty() { return Err(McpError::InvalidParams("empty pattern".into())); } let mut p = rustre_mem::VirtualMemoryProvider::new(); p.map(rustre_core::address::Address::new(addr), data, rustre_core::permissions::Permissions::READ | rustre_core::permissions::Permissions::WRITE); let found = <rustre_mem::VirtualMemoryProvider as rustre_mem::MemoryProvider>::find_bytes(&p, &pat, rustre_core::address::Address::new(addr)); Ok(ToolResult::text(json!({"found":found.map(|a| a.as_u64()),"source":"VirtualMemoryProvider::find_bytes"}).to_string())) } }

pub struct MemSearchBytesWithMaskV5Tool;
impl MemSearchBytesWithMaskV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_search_bytes_with_mask_v5".to_string(), description: "rustre_mem::search_bytes_with_mask over a VirtualMemoryProvider.".to_string(), input_schema: json!({"type":"object","required":["addr","hex","pattern_hex","mask_hex"],"properties":{"addr":{"type":"integer","minimum":0},"hex":{"type":"string"},"pattern_hex":{"type":"string"},"mask_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemSearchBytesWithMaskV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?; let pat_hex = args.get("pattern_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern_hex'".into()))?; let mask_hex = args.get("mask_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'mask_hex'".into()))?; let data = __mem_hex_decode_v2(hex)?; let pat = __mem_hex_decode_v2(pat_hex)?; let mask = __mem_hex_decode_v2(mask_hex)?; if pat.is_empty() || pat.len() != mask.len() { return Err(McpError::InvalidParams("bad pattern/mask".into())); } let end = addr.saturating_add(data.len() as u64); let mut p = rustre_mem::VirtualMemoryProvider::new(); p.map(rustre_core::address::Address::new(addr), data, rustre_core::permissions::Permissions::READ | rustre_core::permissions::Permissions::WRITE); let range = rustre_core::address::AddressRange::new(rustre_core::address::Address::new(addr), rustre_core::address::Address::new(end)); let hits = rustre_mem::search_bytes_with_mask(&p, &pat, &mask, range); let hits_u: Vec<u64> = hits.iter().map(|a| a.as_u64()).collect(); Ok(ToolResult::text(json!({"count":hits_u.len(),"hits":hits_u,"source":"rustre_mem::search_bytes_with_mask"}).to_string())) } }

pub struct MemCompositeFirstWinsV5Tool;
impl MemCompositeFirstWinsV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_composite_first_wins_v5".to_string(), description: "Priority read from rustre_mem::CompositeMemoryProvider.".to_string(), input_schema: json!({"type":"object","required":["addr","hi_hex","lo_hex"],"properties":{"addr":{"type":"integer","minimum":0},"hi_hex":{"type":"string"},"lo_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemCompositeFirstWinsV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let hi = __mem_hex_decode_v2(args.get("hi_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hi_hex'".into()))?)?; let lo = __mem_hex_decode_v2(args.get("lo_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'lo_hex'".into()))?)?; if hi.is_empty() || lo.is_empty() { return Err(McpError::InvalidParams("empty inputs".into())); } let n = hi.len().min(lo.len()); let mut a = rustre_mem::VirtualMemoryProvider::new(); a.map(rustre_core::address::Address::new(addr), hi, rustre_core::permissions::Permissions::READ | rustre_core::permissions::Permissions::WRITE); let mut b = rustre_mem::VirtualMemoryProvider::new(); b.map(rustre_core::address::Address::new(addr), lo, rustre_core::permissions::Permissions::READ | rustre_core::permissions::Permissions::WRITE); let mut c = rustre_mem::CompositeMemoryProvider::new(); c.add_provider(Box::new(a), 10); c.add_provider(Box::new(b), 5); let data = <rustre_mem::CompositeMemoryProvider as rustre_mem::MemoryProvider>::read(&c, rustre_core::address::Address::new(addr), n).map_err(|e| McpError::InternalError(format!("read: {e}")))?; Ok(ToolResult::text(json!({"len":data.len(),"first_byte":data.first(),"source":"rustre_mem::CompositeMemoryProvider"}).to_string())) } }

pub struct MemPatchedReadV5Tool;
impl MemPatchedReadV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_patched_read_v5".to_string(), description: "PatchedMemoryProvider intercepts patched bytes.".to_string(), input_schema: json!({"type":"object","required":["addr","base_hex","patch_hex"],"properties":{"addr":{"type":"integer","minimum":0},"base_hex":{"type":"string"},"patch_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemPatchedReadV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let base = __mem_hex_decode_v2(args.get("base_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'base_hex'".into()))?)?; let patch = __mem_hex_decode_v2(args.get("patch_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'patch_hex'".into()))?)?; if base.is_empty() || patch.is_empty() || patch.len() > base.len() { return Err(McpError::InvalidParams("bad inputs".into())); } let mut vp = rustre_mem::VirtualMemoryProvider::new(); vp.map(rustre_core::address::Address::new(addr), base, rustre_core::permissions::Permissions::READ | rustre_core::permissions::Permissions::WRITE); let mut p = rustre_mem::PatchedMemoryProvider::new(vp); let plen = patch.len(); p.add_patch(rustre_core::address::Address::new(addr), patch, None); let data = <rustre_mem::PatchedMemoryProvider<rustre_mem::VirtualMemoryProvider> as rustre_mem::MemoryProvider>::read(&p, rustre_core::address::Address::new(addr), plen).map_err(|e| McpError::InternalError(format!("read: {e}")))?; Ok(ToolResult::text(json!({"len":data.len(),"first":data.first(),"source":"rustre_mem::PatchedMemoryProvider"}).to_string())) } }

pub struct MemNullProviderReadV5Tool;
impl MemNullProviderReadV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_null_provider_read_v5".to_string(), description: "NullMemoryProvider::read must fail on any address.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer","minimum":0},"len":{"type":"integer","minimum":1}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemNullProviderReadV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0x1000); let len = args.get("len").and_then(Value::as_u64).unwrap_or(4) as usize; let p = rustre_mem::NullMemoryProvider::new(); let err = <rustre_mem::NullMemoryProvider as rustre_mem::MemoryProvider>::read(&p, rustre_core::address::Address::new(addr), len).is_err(); let regions_empty = <rustre_mem::NullMemoryProvider as rustre_mem::MemoryProvider>::regions(&p).is_empty(); Ok(ToolResult::text(json!({"read_errored":err,"regions_empty":regions_empty,"source":"rustre_mem::NullMemoryProvider"}).to_string())) } }

pub struct MemArenaNewV5Tool;
impl MemArenaNewV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_arena_new_v5".to_string(), description: "Create MemoryArena and alloc_zeroed some bytes.".to_string(), input_schema: json!({"type":"object","required":["capacity","alloc_size"],"properties":{"capacity":{"type":"integer","minimum":1},"alloc_size":{"type":"integer","minimum":1},"base":{"type":"integer","minimum":0}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemArenaNewV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cap = args.get("capacity").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'capacity'".into()))? as usize; let sz = args.get("alloc_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'alloc_size'".into()))? as usize; let base = args.get("base").and_then(Value::as_u64).unwrap_or(0x1000); let mut arena = rustre_mem::MemoryArena::new(cap, rustre_core::address::Address::new(base)); let a = arena.alloc_zeroed(sz, 1).map_err(|e| McpError::InternalError(format!("alloc: {e:?}")))?; let stats = arena.stats(); Ok(ToolResult::text(json!({"alloc_offset":a.offset,"alloc_size":a.size,"total_allocations":stats.total_allocations,"source":"rustre_mem::MemoryArena"}).to_string())) } }

pub struct MemPageCacheReadV5Tool;
impl MemPageCacheReadV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_page_cache_read_v5".to_string(), description: "PageCache::new then read via fetch closure.".to_string(), input_schema: json!({"type":"object","required":["addr","len"],"properties":{"addr":{"type":"integer","minimum":0},"len":{"type":"integer","minimum":1},"fill_byte":{"type":"integer","minimum":0,"maximum":255}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemPageCacheReadV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let len = args.get("len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'len'".into()))? as usize; let fill = args.get("fill_byte").and_then(Value::as_u64).unwrap_or(0xAA) as u8; let mut cache = rustre_mem::PageCache::new(4096, 2); let was_empty = cache.is_empty(); let r = cache.read::<String, _>(rustre_core::address::Address::new(addr), len, |_start, ps| Ok(vec![fill; ps])).map_err(|e| McpError::InternalError(format!("cache: {e}")))?; Ok(ToolResult::text(json!({"was_empty":was_empty,"read_len":r.len(),"first":r.first(),"pages_now":cache.len(),"source":"rustre_mem::PageCache"}).to_string())) } }

pub struct MemEntropyBlockNewV5Tool;
impl MemEntropyBlockNewV5Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_entropy_block_new_v5".to_string(), description: "Construct rustre_mem::EntropyBlock and echo fields.".to_string(), input_schema: json!({"type":"object","required":["address","size","entropy"],"properties":{"address":{"type":"integer","minimum":0},"size":{"type":"integer","minimum":0},"entropy":{"type":"number"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemEntropyBlockNewV5Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?; let sz = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as usize; let e = args.get("entropy").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing 'entropy'".into()))?; let b = rustre_mem::EntropyBlock { address: rustre_core::address::Address::new(addr), size: sz, entropy: e }; Ok(ToolResult::text(json!({"address":b.address.as_u64(),"size":b.size,"entropy":b.entropy,"source":"rustre_mem::EntropyBlock"}).to_string())) } }

pub struct MemEntropyBlockClassifyBytesV4Tool;
impl MemEntropyBlockClassifyBytesV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_entropy_block_classify_bytes_v4".to_string(), description: "shannon_entropy(data) then EntropyBlock::classification.".to_string(), input_schema: json!({"type":"object","properties":{"address":{"type":"integer"},"hex":{"type":"string"},"bytes":{"type":"array","items":{"type":"integer"}}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemEntropyBlockClassifyBytesV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("address").and_then(Value::as_u64).unwrap_or(0); let d = args_to_bytes(&args)?; let ent = rustre_mem::shannon_entropy(&d); let block = rustre_mem::entropy::EntropyBlock { address: rustre_core::address::Address::new(addr), size: d.len(), entropy: ent }; Ok(ToolResult::text(json!({"address":addr,"size":d.len(),"entropy":ent,"classification":block.classification(),"source":"rustre_mem::entropy::EntropyBlock::classification"}).to_string())) } }

pub struct MemHighEntropySpansFromBytesV4Tool;
impl MemHighEntropySpansFromBytesV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "mem_high_entropy_spans_from_bytes_v4".to_string(), description: "Chunk bytes into EntropyBlocks and run entropy::high_entropy_spans.".to_string(), input_schema: json!({"type":"object","required":["block_size","threshold"],"properties":{"base":{"type":"integer"},"block_size":{"type":"integer","minimum":1},"threshold":{"type":"number"},"hex":{"type":"string"},"bytes":{"type":"array","items":{"type":"integer"}}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for MemHighEntropySpansFromBytesV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let base = args.get("base").and_then(Value::as_u64).unwrap_or(0); let bs = args.get("block_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing block_size".into()))? as usize; if bs == 0 { return Err(McpError::InvalidParams("block_size must be > 0".into())); } let th = args.get("threshold").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing threshold".into()))?; let d = args_to_bytes(&args)?; let mut blocks: Vec<rustre_mem::entropy::EntropyBlock> = Vec::new(); let mut off = 0usize; while off < d.len() { let end = (off + bs).min(d.len()); let e = rustre_mem::shannon_entropy(&d[off..end]); blocks.push(rustre_mem::entropy::EntropyBlock { address: rustre_core::address::Address::new(base + off as u64), size: end - off, entropy: e }); off = end; } let spans = rustre_mem::entropy::high_entropy_spans(&blocks, th); let items: Vec<_> = spans.iter().map(|s| json!({"start":s.start.as_u64(),"end":s.end.as_u64(),"len":s.len(),"is_empty":s.is_empty(),"mean_entropy":s.mean_entropy,"block_count":s.block_count})).collect(); Ok(ToolResult::text(json!({"block_count":blocks.len(),"span_count":items.len(),"spans":items,"source":"rustre_mem::entropy::high_entropy_spans"}).to_string())) } }

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (MemShannonEntropyTool::definition(), Box::new(MemShannonEntropyTool)),
        (MemPageIndexTool::definition(), Box::new(MemPageIndexTool)),
        (MemPageAlignUpTool::definition(), Box::new(MemPageAlignUpTool)),
        (MemPageAlignDownTool::definition(), Box::new(MemPageAlignDownTool)),
        (MemPageContainingTool::definition(), Box::new(MemPageContainingTool)),
        (MemHighEntropySpansTool::definition(), Box::new(MemHighEntropySpansTool)),
        (MemShannonEntropyWireTool::definition(), Box::new(MemShannonEntropyWireTool)),
        (MemPageAlignUpWireTool::definition(), Box::new(MemPageAlignUpWireTool)),
        (MemPageRangeIndicesTool::definition(), Box::new(MemPageRangeIndicesTool)),
        (MemEntropyClassifyTool::definition(), Box::new(MemEntropyClassifyTool)),
        (MemSearchBytesWithMaskHexTool::definition(), Box::new(MemSearchBytesWithMaskHexTool)),
        (MemSearchBytesHexTool::definition(), Box::new(MemSearchBytesHexTool)),
        (MemEntropyBlocksHexTool::definition(), Box::new(MemEntropyBlocksHexTool)),
        (MemReadTypedAtHexTool::definition(), Box::new(MemReadTypedAtHexTool)),
        (MemWriteTypedAtHexTool::definition(), Box::new(MemWriteTypedAtHexTool)),
        (MemPermsFromRwxTool::definition(), Box::new(MemPermsFromRwxTool)),
        (MemRegionKindListTool::definition(), Box::new(MemRegionKindListTool)),
        (MemReadU128LeAtHexTool::definition(), Box::new(MemReadU128LeAtHexTool)),
        (MemReadF32BeAtHexTool::definition(), Box::new(MemReadF32BeAtHexTool)),
        (MemReadF64BeAtHexTool::definition(), Box::new(MemReadF64BeAtHexTool)),
        (MemWriteU16BeAtHexTool::definition(), Box::new(MemWriteU16BeAtHexTool)),
        (MemWriteU32BeAtHexTool::definition(), Box::new(MemWriteU32BeAtHexTool)),
        (MemWriteU64BeAtHexTool::definition(), Box::new(MemWriteU64BeAtHexTool)),
        (MemSearchBytesRangeHexTool::definition(), Box::new(MemSearchBytesRangeHexTool)),
        (MemHighEntropySpansFromHexTool::definition(), Box::new(MemHighEntropySpansFromHexTool)),
        (MemReadU8AtHexTool::definition(), Box::new(MemReadU8AtHexTool)),
        (MemReadI8AtHexTool::definition(), Box::new(MemReadI8AtHexTool)),
        (MemReadI16LeAtHexTool::definition(), Box::new(MemReadI16LeAtHexTool)),
        (MemReadI32LeAtHexTool::definition(), Box::new(MemReadI32LeAtHexTool)),
        (MemReadI64LeAtHexTool::definition(), Box::new(MemReadI64LeAtHexTool)),
        (MemReadF32LeAtHexTool::definition(), Box::new(MemReadF32LeAtHexTool)),
        (MemReadF64LeAtHexTool::definition(), Box::new(MemReadF64LeAtHexTool)),
        (MemWriteI32LeAtHexTool::definition(), Box::new(MemWriteI32LeAtHexTool)),
        (MemWriteI64LeAtHexTool::definition(), Box::new(MemWriteI64LeAtHexTool)),
        (MemWriteF32LeAtHexTool::definition(), Box::new(MemWriteF32LeAtHexTool)),
        (MemWriteF64LeAtHexTool::definition(), Box::new(MemWriteF64LeAtHexTool)),
        (MemReadU16LeAtHexTool::definition(), Box::new(MemReadU16LeAtHexTool)),
        (MemReadU16BeAtHexTool::definition(), Box::new(MemReadU16BeAtHexTool)),
        (MemReadU32LeAtHexTool::definition(), Box::new(MemReadU32LeAtHexTool)),
        (MemReadU32BeAtHexTool::definition(), Box::new(MemReadU32BeAtHexTool)),
        (MemReadU64LeAtHexTool::definition(), Box::new(MemReadU64LeAtHexTool)),
        (MemReadU64BeAtHexTool::definition(), Box::new(MemReadU64BeAtHexTool)),
        (MemWriteU8AtHexTool::definition(), Box::new(MemWriteU8AtHexTool)),
        (MemWriteU16LeAtHexTool::definition(), Box::new(MemWriteU16LeAtHexTool)),
        (MemWriteU32LeAtHexTool::definition(), Box::new(MemWriteU32LeAtHexTool)),
        (MemWriteU64LeAtHexTool::definition(), Box::new(MemWriteU64LeAtHexTool)),
        (MemSearchBytesAllHexTool::definition(), Box::new(MemSearchBytesAllHexTool)),
        (MemShannonEntropyMaxBlockWireTool::definition(), Box::new(MemShannonEntropyMaxBlockWireTool)),
        (MemShannonEntropyMinBlockWireTool::definition(), Box::new(MemShannonEntropyMinBlockWireTool)),
        (MemShannonEntropyMeanBlockWireTool::definition(), Box::new(MemShannonEntropyMeanBlockWireTool)),
        (MemEntropyClassifyValueWireTool::definition(), Box::new(MemEntropyClassifyValueWireTool)),
        (MemPageAlignUpManyWireTool::definition(), Box::new(MemPageAlignUpManyWireTool)),
        (MemPageAlignDownManyWireTool::definition(), Box::new(MemPageAlignDownManyWireTool)),
        (MemPageIndexManyWireTool::definition(), Box::new(MemPageIndexManyWireTool)),
        (MemPageContainingLenWireTool::definition(), Box::new(MemPageContainingLenWireTool)),
        (MemShannonEntropyV3Tool::definition(), Box::new(MemShannonEntropyV3Tool)),
        (MemPageAlignUpV3Tool::definition(), Box::new(MemPageAlignUpV3Tool)),
        (MemPageAlignDownV3Tool::definition(), Box::new(MemPageAlignDownV3Tool)),
        (MemEntropyBlocksHexV3Tool::definition(), Box::new(MemEntropyBlocksHexV3Tool)),
        (MemHighEntropySpansV3Tool::definition(), Box::new(MemHighEntropySpansV3Tool)),
        (MemReadU128LeAtHexV2Tool::definition(), Box::new(MemReadU128LeAtHexV2Tool)),
        (MemReadF32BeAtHexV2Tool::definition(), Box::new(MemReadF32BeAtHexV2Tool)),
        (MemReadF64BeAtHexV2Tool::definition(), Box::new(MemReadF64BeAtHexV2Tool)),
        (MemSearchBytesHexV2Tool::definition(), Box::new(MemSearchBytesHexV2Tool)),
        (MemPageAlignUpV5Tool::definition(), Box::new(MemPageAlignUpV5Tool)),
        (MemPageAlignDownV5Tool::definition(), Box::new(MemPageAlignDownV5Tool)),
        (MemPageContainingV5Tool::definition(), Box::new(MemPageContainingV5Tool)),
        (MemPageIndexV5Tool::definition(), Box::new(MemPageIndexV5Tool)),
        (MemPageRangeIndicesV5Tool::definition(), Box::new(MemPageRangeIndicesV5Tool)),
        (MemShannonEntropyFromBytesV5Tool::definition(), Box::new(MemShannonEntropyFromBytesV5Tool)),
        (MemPermsFromRwxV5Tool::definition(), Box::new(MemPermsFromRwxV5Tool)),
        (MemVirtualProviderReadU8V5Tool::definition(), Box::new(MemVirtualProviderReadU8V5Tool)),
        (MemVirtualProviderReadU32LeV5Tool::definition(), Box::new(MemVirtualProviderReadU32LeV5Tool)),
        (MemVirtualProviderReadU64LeV5Tool::definition(), Box::new(MemVirtualProviderReadU64LeV5Tool)),
        (MemVirtualProviderWriteU32LeV5Tool::definition(), Box::new(MemVirtualProviderWriteU32LeV5Tool)),
        (MemFindBytesProviderV5Tool::definition(), Box::new(MemFindBytesProviderV5Tool)),
        (MemSearchBytesWithMaskV5Tool::definition(), Box::new(MemSearchBytesWithMaskV5Tool)),
        (MemCompositeFirstWinsV5Tool::definition(), Box::new(MemCompositeFirstWinsV5Tool)),
        (MemPatchedReadV5Tool::definition(), Box::new(MemPatchedReadV5Tool)),
        (MemNullProviderReadV5Tool::definition(), Box::new(MemNullProviderReadV5Tool)),
        (MemArenaNewV5Tool::definition(), Box::new(MemArenaNewV5Tool)),
        (MemPageCacheReadV5Tool::definition(), Box::new(MemPageCacheReadV5Tool)),
        (MemEntropyBlockNewV5Tool::definition(), Box::new(MemEntropyBlockNewV5Tool)),
        (MemEntropyBlockClassifyBytesV4Tool::definition(), Box::new(MemEntropyBlockClassifyBytesV4Tool)),
        (MemHighEntropySpansFromBytesV4Tool::definition(), Box::new(MemHighEntropySpansFromBytesV4Tool)),
    ]
}
