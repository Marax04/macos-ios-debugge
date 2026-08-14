//! MCP wrappers for the rustre-gdb crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes, hex_encode};

pub struct GdbPacketChecksumTool;

pub struct GdbPacketEncodeTool;

pub struct GdbPacketDecodeWireTool;
impl GdbPacketDecodeWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_packet_decode".to_string(),
            description: "Decode a raw GDB RSP $data#XX packet string.".to_string(),
            input_schema: json!({"type":"object","properties":{"raw":{"type":"string"}},"required":["raw"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbPacketDecodeWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let raw = args.get("raw").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'raw'".into()))?;
        match rustre_debug_gdb::GdbPacket::decode(raw) {
            Ok(p) => Ok(ToolResult::text(json!({"ok":true,"data":p.data}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
        }
    }
}

pub struct GdbPacketEscapeDataWireTool;
impl GdbPacketEscapeDataWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_packet_escape_data".to_string(),
            description: "Apply GDB RSP wire-format escape to raw bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array"},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbPacketEscapeDataWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let escaped = rustre_debug_gdb::GdbPacket::escape_data(&data);
        Ok(ToolResult::text(json!({"escaped_hex": hex_encode(escaped.as_bytes()), "escaped_len": escaped.len(), "input_len": data.len()}).to_string()))
    }
}

pub struct GdbPacketUnescapeDataWireTool;
impl GdbPacketUnescapeDataWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_packet_unescape_data".to_string(),
            description: "Reverse GDB RSP escaping.".to_string(),
            input_schema: json!({"type":"object","properties":{"data":{"type":"string"}},"required":["data"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbPacketUnescapeDataWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args.get("data").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data'".into()))?;
        let out = rustre_debug_gdb::GdbPacket::unescape_data(data);
        Ok(ToolResult::text(json!({"unescaped_hex": hex_encode(&out), "unescaped_len": out.len()}).to_string()))
    }
}

pub struct GdbTargetXmlParseWireTool;
impl GdbTargetXmlParseWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_target_xml_parse".to_string(),
            description: "Parse a GDB target.xml register description.".to_string(),
            input_schema: json!({"type":"object","properties":{"xml":{"type":"string"}},"required":["xml"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbTargetXmlParseWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let xml = args.get("xml").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'xml'".into()))?;
        match rustre_debug_gdb::GdbTargetXml::parse(xml) {
            Ok(t) => Ok(ToolResult::text(json!({"ok":true,"architecture":t.architecture,"register_count":t.registers.len(),"total_bytes":t.total_register_bytes()}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
        }
    }
}

pub struct GdbRegisterCodecEncodePWireTool;
impl GdbRegisterCodecEncodePWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_register_codec_encode_p".to_string(),
            description: "Build a GDB RSP 'P regnum=value' command.".to_string(),
            input_schema: json!({"type":"object","properties":{"xml":{"type":"string"},"regnum":{"type":"integer"},"value":{"type":"integer"}},"required":["xml","regnum","value"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbRegisterCodecEncodePWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let xml = args.get("xml").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'xml'".into()))?;
        let regnum = args.get("regnum").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'regnum'".into()))? as u32;
        let value = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let target = rustre_debug_gdb::GdbTargetXml::parse(xml).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        let codec = rustre_debug_gdb::GdbRegisterCodec::new(target);
        Ok(ToolResult::text(json!({"command":codec.encode_p_command(regnum, value)}).to_string()))
    }
}

pub struct GdbRegisterCodecDecodePWireTool;
impl GdbRegisterCodecDecodePWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_register_codec_decode_p".to_string(),
            description: "Decode a 'p' single-register response.".to_string(),
            input_schema: json!({"type":"object","properties":{"xml":{"type":"string"},"regnum":{"type":"integer"},"hex":{"type":"string"}},"required":["xml","regnum","hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbRegisterCodecDecodePWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let xml = args.get("xml").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'xml'".into()))?;
        let regnum = args.get("regnum").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'regnum'".into()))? as u32;
        let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?;
        let target = rustre_debug_gdb::GdbTargetXml::parse(xml).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        let codec = rustre_debug_gdb::GdbRegisterCodec::new(target);
        match codec.decode_p_response(regnum, hex) {
            Ok(v) => Ok(ToolResult::text(json!({"ok":true,"value":v,"value_hex":format!("{:x}",v)}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
        }
    }
}

pub struct GdbStopReplyParseWireTool;
impl GdbStopReplyParseWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_stop_reply_parse".to_string(),
            description: "Parse a GDB RSP stop-reply packet (S/T/W/X).".to_string(),
            input_schema: json!({"type":"object","properties":{"reply":{"type":"string"},"pid":{"type":"integer"}},"required":["reply"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbStopReplyParseWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let reply = args.get("reply").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'reply'".into()))?;
        let pid = args.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32;
        match rustre_debug_gdb::GdbStopReplyParser::parse(reply, rustre_debug::ProcessId(pid)) {
            Ok(r) => Ok(ToolResult::text(json!({"ok":true,"reason":format!("{:?}",r)}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string()}).to_string())),
        }
    }
}

pub struct GdbMemoryReadCmdWireTool;
impl GdbMemoryReadCmdWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_memory_read_cmd".to_string(),
            description: "Build 'm addr,len' memory-read command.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"len":{"type":"integer"}},"required":["addr","len"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbMemoryReadCmdWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let len = args.get("len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'len'".into()))? as usize;
        Ok(ToolResult::text(json!({"command":rustre_debug_gdb::GdbMemoryOps::read_cmd(rustre_core::address::Address::new(addr), len)}).to_string()))
    }
}

pub struct GdbMemoryWriteCmdWireTool;
impl GdbMemoryWriteCmdWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_memory_write_cmd".to_string(),
            description: "Build 'M addr,len:data' memory-write command.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"bytes":{"type":"array"},"hex":{"type":"string"}},"required":["addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbMemoryWriteCmdWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let data = args_to_bytes(&args)?;
        Ok(ToolResult::text(json!({"command":rustre_debug_gdb::GdbMemoryOps::write_cmd(rustre_core::address::Address::new(addr), &data),"bytes":data.len()}).to_string()))
    }
}

pub struct GdbMemoryMapParseWireTool;
impl GdbMemoryMapParseWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_memory_map_parse".to_string(),
            description: "Parse qXfer:memory-map:read XML into regions.".to_string(),
            input_schema: json!({"type":"object","properties":{"xml":{"type":"string"}},"required":["xml"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbMemoryMapParseWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let xml = args.get("xml").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'xml'".into()))?;
        let maps = rustre_debug_gdb::GdbMemoryOps::parse_memory_map_xml(xml);
        let out: Vec<Value> = maps.iter().map(|m| json!({"base":m.base.as_u64(),"size":m.size,"readable":m.readable,"writable":m.writable,"executable":m.executable,"name":m.name})).collect();
        Ok(ToolResult::text(json!({"count":out.len(),"regions":out}).to_string()))
    }
}

pub struct GdbBreakpointSwCmdWireTool;
impl GdbBreakpointSwCmdWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_breakpoint_sw_cmd".to_string(),
            description: "Build GDB SW breakpoint insert/remove (Z0/z0).".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}},"required":["addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbBreakpointSwCmdWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let a = rustre_core::address::Address::new(addr);
        Ok(ToolResult::text(json!({"insert":rustre_debug_gdb::GdbBreakpointOps::set_sw_bp_cmd(a),"remove":rustre_debug_gdb::GdbBreakpointOps::remove_sw_bp_cmd(a)}).to_string()))
    }
}

pub struct GdbBreakpointHwCmdWireTool;
impl GdbBreakpointHwCmdWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_breakpoint_hw_cmd".to_string(),
            description: "Build GDB HW breakpoint insert/remove (Z1/z1).".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}},"required":["addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbBreakpointHwCmdWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let a = rustre_core::address::Address::new(addr);
        Ok(ToolResult::text(json!({"insert":rustre_debug_gdb::GdbBreakpointOps::set_hw_bp_cmd(a),"remove":rustre_debug_gdb::GdbBreakpointOps::remove_hw_bp_cmd(a)}).to_string()))
    }
}

pub struct GdbWatchpointCmdWireTool;
impl GdbWatchpointCmdWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_watchpoint_cmd".to_string(),
            description: "Build GDB watchpoint insert/remove. kind: write|read|readwrite.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"len":{"type":"integer"},"kind":{"type":"string"}},"required":["addr","len","kind"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbWatchpointCmdWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let len = args.get("len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'len'".into()))? as u8;
        let kind_s = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let kind = match kind_s {
            "read" => rustre_debug::BreakpointKind::DataRead,
            "readwrite" | "rw" => rustre_debug::BreakpointKind::DataReadWrite,
            _ => rustre_debug::BreakpointKind::DataWrite,
        };
        let a = rustre_core::address::Address::new(addr);
        Ok(ToolResult::text(json!({"insert":rustre_debug_gdb::GdbBreakpointOps::set_watchpoint_cmd(a,kind,len),"remove":rustre_debug_gdb::GdbBreakpointOps::remove_watchpoint_cmd(a,kind,len)}).to_string()))
    }
}

pub struct GdbTargetXmlRegisterByNameWireTool;
impl GdbTargetXmlRegisterByNameWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_target_xml_register_by_name".to_string(),
            description: "Parse target.xml then look up a register definition by name.".to_string(),
            input_schema: json!({"type":"object","properties":{"xml":{"type":"string"},"name":{"type":"string"}},"required":["xml","name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbTargetXmlRegisterByNameWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let xml = args.get("xml").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'xml'".into()))?;
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let t = rustre_debug_gdb::GdbTargetXml::parse(xml).map_err(|e| McpError::InternalError(format!("parse: {e}")))?;
        let reg = t.register_by_name(name);
        Ok(ToolResult::text(json!({
            "found": reg.is_some(),
            "name": reg.map(|r| r.name.clone()),
            "bitsize": reg.map(|r| r.bitsize),
            "regnum": reg.and_then(|r| r.regnum),
            "type": reg.map(|r| r.type_.clone()),
            "group": reg.and_then(|r| r.group.clone()),
            "source":"rustre_debug_gdb::GdbTargetXml::register_by_name"
        }).to_string()))
    }
}

pub struct GdbTargetXmlRegisterByNumWireTool;
impl GdbTargetXmlRegisterByNumWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_target_xml_register_by_num".to_string(),
            description: "Parse target.xml then look up a register definition by regnum.".to_string(),
            input_schema: json!({"type":"object","properties":{"xml":{"type":"string"},"regnum":{"type":"integer"}},"required":["xml","regnum"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbTargetXmlRegisterByNumWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let xml = args.get("xml").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'xml'".into()))?;
        let num = args.get("regnum").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'regnum'".into()))? as u32;
        let t = rustre_debug_gdb::GdbTargetXml::parse(xml).map_err(|e| McpError::InternalError(format!("parse: {e}")))?;
        let reg = t.register_by_num(num);
        Ok(ToolResult::text(json!({
            "found": reg.is_some(),
            "name": reg.map(|r| r.name.clone()),
            "bitsize": reg.map(|r| r.bitsize),
            "regnum": reg.and_then(|r| r.regnum),
            "byte_size": reg.map(rustre_debug_gdb::GdbRegisterDef::byte_size),
            "source":"rustre_debug_gdb::GdbTargetXml::register_by_num"
        }).to_string()))
    }
}

pub struct GdbTargetXmlTotalBytesWireTool;
impl GdbTargetXmlTotalBytesWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_target_xml_total_bytes".to_string(),
            description: "Total bytes required for a full 'g' packet given target.xml.".to_string(),
            input_schema: json!({"type":"object","properties":{"xml":{"type":"string"}},"required":["xml"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbTargetXmlTotalBytesWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let xml = args.get("xml").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'xml'".into()))?;
        let t = rustre_debug_gdb::GdbTargetXml::parse(xml).map_err(|e| McpError::InternalError(format!("parse: {e}")))?;
        Ok(ToolResult::text(json!({
            "architecture": t.architecture,
            "register_count": t.registers.len(),
            "total_bytes": t.total_register_bytes(),
            "source":"rustre_debug_gdb::GdbTargetXml::total_register_bytes"
        }).to_string()))
    }
}

pub struct GdbRegisterDefByteSizeWireTool;
impl GdbRegisterDefByteSizeWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_register_def_byte_size".to_string(),
            description: "Byte size (rounded up) for a register of given bit width.".to_string(),
            input_schema: json!({"type":"object","properties":{"bitsize":{"type":"integer"}},"required":["bitsize"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbRegisterDefByteSizeWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bitsize = args.get("bitsize").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bitsize'".into()))? as u32;
        let def = rustre_debug_gdb::GdbRegisterDef {
            name: String::new(),
            bitsize,
            regnum: None,
            type_: String::new(),
            group: None,
        };
        Ok(ToolResult::text(json!({
            "bitsize": bitsize,
            "byte_size": def.byte_size(),
            "source":"rustre_debug_gdb::GdbRegisterDef::byte_size"
        }).to_string()))
    }
}

pub struct GdbRegisterCodecDecodeGWireTool;
impl GdbRegisterCodecDecodeGWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_register_codec_decode_g".to_string(),
            description: "Decode a 'g' packet hex payload against target.xml.".to_string(),
            input_schema: json!({"type":"object","properties":{"xml":{"type":"string"},"hex":{"type":"string"}},"required":["xml","hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbRegisterCodecDecodeGWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let xml = args.get("xml").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'xml'".into()))?;
        let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?;
        let t = rustre_debug_gdb::GdbTargetXml::parse(xml).map_err(|e| McpError::InternalError(format!("parse: {e}")))?;
        let codec = rustre_debug_gdb::GdbRegisterCodec::new(t.clone());
        let regs = codec.decode_g_packet(hex).map_err(|e| McpError::InternalError(format!("decode: {e}")))?;
        let mut map = serde_json::Map::new();
        for r in &t.registers {
            if let Some(v) = regs.get(&r.name) {
                map.insert(r.name.clone(), json!(v));
            }
        }
        Ok(ToolResult::text(json!({
            "pc": regs.pc,
            "sp": regs.sp,
            "fp": regs.fp,
            "lr": regs.lr,
            "registers": Value::Object(map),
            "source":"rustre_debug_gdb::GdbRegisterCodec::decode_g_packet"
        }).to_string()))
    }
}

pub struct GdbRegisterCodecEncodeGWireTool;
impl GdbRegisterCodecEncodeGWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_register_codec_encode_g".to_string(),
            description: "Encode a register-values map into a 'G' packet payload.".to_string(),
            input_schema: json!({"type":"object","properties":{"xml":{"type":"string"},"values":{"type":"object"}},"required":["xml"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbRegisterCodecEncodeGWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let xml = args.get("xml").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'xml'".into()))?;
        let t = rustre_debug_gdb::GdbTargetXml::parse(xml).map_err(|e| McpError::InternalError(format!("parse: {e}")))?;
        let codec = rustre_debug_gdb::GdbRegisterCodec::new(t);
        let mut set = rustre_debug::RegisterSet::new();
        if let Some(obj) = args.get("values").and_then(Value::as_object) {
            for (k, v) in obj {
                if let Some(n) = v.as_u64() {
                    set.set(k, n);
                }
            }
        }
        let payload = codec.encode_g_packet(&set);
        Ok(ToolResult::text(json!({
            "payload": payload,
            "length": payload.len(),
            "source":"rustre_debug_gdb::GdbRegisterCodec::encode_g_packet"
        }).to_string()))
    }
}

pub struct GdbMemoryReadResponseParseWireTool;
impl GdbMemoryReadResponseParseWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_memory_read_response_parse".to_string(),
            description: "Parse hex payload from an 'm' memory-read response.".to_string(),
            input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbMemoryReadResponseParseWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?;
        let bytes = rustre_debug_gdb::GdbMemoryOps::parse_read_response(hex).map_err(|e| McpError::InternalError(format!("parse: {e}")))?;
        Ok(ToolResult::text(json!({
            "bytes": bytes.len(),
            "hex": hex_encode(&bytes),
            "source":"rustre_debug_gdb::GdbMemoryOps::parse_read_response"
        }).to_string()))
    }
}

pub struct GdbMemoryWriteBinaryCmdWireTool;
impl GdbMemoryWriteBinaryCmdWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_memory_write_binary_cmd".to_string(),
            description: "Build 'X addr,len:binary' command (bytes escaped).".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"bytes":{"type":"array"},"hex":{"type":"string"}},"required":["addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbMemoryWriteBinaryCmdWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let data = args_to_bytes(&args)?;
        let cmd = rustre_debug_gdb::GdbMemoryOps::write_binary_cmd(rustre_core::address::Address::new(addr), &data);
        Ok(ToolResult::text(json!({
            "command_hex": hex_encode(&cmd),
            "length": cmd.len(),
            "input_bytes": data.len(),
            "source":"rustre_debug_gdb::GdbMemoryOps::write_binary_cmd"
        }).to_string()))
    }
}

pub struct GdbStepRangePacketWireTool;
impl GdbStepRangePacketWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_step_range_packet".to_string(),
            description: "Build 'vCont;r start,end[:tid]' step-range packet.".to_string(),
            input_schema: json!({"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"},"thread":{"type":"integer"}},"required":["start","end"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbStepRangePacketWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let start = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))?;
        let end = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'end'".into()))?;
        let tid = args.get("thread").and_then(Value::as_u64).map(|t| rustre_debug::ThreadId(t as u32));
        let pkt = rustre_debug_gdb::step_range_packet(rustre_core::address::Address::new(start), rustre_core::address::Address::new(end), tid);
        Ok(ToolResult::text(json!({
            "packet": pkt,
            "source":"rustre_debug_gdb::step_range_packet"
        }).to_string()))
    }
}

pub struct GdbStubOkPacketWireTool;
impl GdbStubOkPacketWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_stub_ok_packet".to_string(),
            description: "Framed 'OK' RSP packet.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbStubOkPacketWireTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({
            "packet": rustre_debug_gdb::GdbStubServer::ok_packet(),
            "source":"rustre_debug_gdb::GdbStubServer::ok_packet"
        }).to_string()))
    }
}

pub struct GdbStubErrorPacketWireTool;
impl GdbStubErrorPacketWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_stub_error_packet".to_string(),
            description: "Framed 'Exx' RSP error packet.".to_string(),
            input_schema: json!({"type":"object","properties":{"code":{"type":"integer"}},"required":["code"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbStubErrorPacketWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let code = args.get("code").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'code'".into()))? as u8;
        Ok(ToolResult::text(json!({
            "packet": rustre_debug_gdb::GdbStubServer::error_packet(code),
            "source":"rustre_debug_gdb::GdbStubServer::error_packet"
        }).to_string()))
    }
}

pub struct GdbStubEmptyPacketWireTool;
impl GdbStubEmptyPacketWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_stub_empty_packet".to_string(),
            description: "Framed empty (unsupported) RSP packet.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbStubEmptyPacketWireTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({
            "packet": rustre_debug_gdb::GdbStubServer::empty_packet(),
            "source":"rustre_debug_gdb::GdbStubServer::empty_packet"
        }).to_string()))
    }
}

pub struct GdbTargetDescX8664LinuxWireTool;
impl GdbTargetDescX8664LinuxWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_target_desc_x86_64_linux".to_string(),
            description: "Return the x86-64 Linux target.xml register description.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbTargetDescX8664LinuxWireTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let xml = rustre_debug_gdb::TargetDescriptionXml::x86_64_linux();
        Ok(ToolResult::text(json!({
            "xml": xml,
            "source":"rustre_debug_gdb::TargetDescriptionXml::x86_64_linux"
        }).to_string()))
    }
}

pub struct GdbTargetDescAarch64LinuxWireTool;
impl GdbTargetDescAarch64LinuxWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "gdb_target_desc_aarch64_linux".to_string(),
            description: "Return the AArch64 Linux target.xml register description.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for GdbTargetDescAarch64LinuxWireTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let xml = rustre_debug_gdb::TargetDescriptionXml::aarch64_linux();
        Ok(ToolResult::text(json!({
            "xml": xml,
            "source":"rustre_debug_gdb::TargetDescriptionXml::aarch64_linux"
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (GdbPacketChecksumTool::definition(), Box::new(GdbPacketChecksumTool)),
        (GdbPacketEncodeTool::definition(), Box::new(GdbPacketEncodeTool)),
        (GdbPacketDecodeWireTool::definition(), Box::new(GdbPacketDecodeWireTool)),
        (GdbPacketEscapeDataWireTool::definition(), Box::new(GdbPacketEscapeDataWireTool)),
        (GdbPacketUnescapeDataWireTool::definition(), Box::new(GdbPacketUnescapeDataWireTool)),
        (GdbTargetXmlParseWireTool::definition(), Box::new(GdbTargetXmlParseWireTool)),
        (GdbRegisterCodecEncodePWireTool::definition(), Box::new(GdbRegisterCodecEncodePWireTool)),
        (GdbRegisterCodecDecodePWireTool::definition(), Box::new(GdbRegisterCodecDecodePWireTool)),
        (GdbStopReplyParseWireTool::definition(), Box::new(GdbStopReplyParseWireTool)),
        (GdbMemoryReadCmdWireTool::definition(), Box::new(GdbMemoryReadCmdWireTool)),
        (GdbMemoryWriteCmdWireTool::definition(), Box::new(GdbMemoryWriteCmdWireTool)),
        (GdbMemoryMapParseWireTool::definition(), Box::new(GdbMemoryMapParseWireTool)),
        (GdbBreakpointSwCmdWireTool::definition(), Box::new(GdbBreakpointSwCmdWireTool)),
        (GdbBreakpointHwCmdWireTool::definition(), Box::new(GdbBreakpointHwCmdWireTool)),
        (GdbWatchpointCmdWireTool::definition(), Box::new(GdbWatchpointCmdWireTool)),
        (GdbTargetXmlRegisterByNameWireTool::definition(), Box::new(GdbTargetXmlRegisterByNameWireTool)),
        (GdbTargetXmlRegisterByNumWireTool::definition(), Box::new(GdbTargetXmlRegisterByNumWireTool)),
        (GdbTargetXmlTotalBytesWireTool::definition(), Box::new(GdbTargetXmlTotalBytesWireTool)),
        (GdbRegisterDefByteSizeWireTool::definition(), Box::new(GdbRegisterDefByteSizeWireTool)),
        (GdbRegisterCodecDecodeGWireTool::definition(), Box::new(GdbRegisterCodecDecodeGWireTool)),
        (GdbRegisterCodecEncodeGWireTool::definition(), Box::new(GdbRegisterCodecEncodeGWireTool)),
        (GdbMemoryReadResponseParseWireTool::definition(), Box::new(GdbMemoryReadResponseParseWireTool)),
        (GdbMemoryWriteBinaryCmdWireTool::definition(), Box::new(GdbMemoryWriteBinaryCmdWireTool)),
        (GdbStepRangePacketWireTool::definition(), Box::new(GdbStepRangePacketWireTool)),
        (GdbStubOkPacketWireTool::definition(), Box::new(GdbStubOkPacketWireTool)),
        (GdbStubErrorPacketWireTool::definition(), Box::new(GdbStubErrorPacketWireTool)),
        (GdbStubEmptyPacketWireTool::definition(), Box::new(GdbStubEmptyPacketWireTool)),
        (GdbTargetDescX8664LinuxWireTool::definition(), Box::new(GdbTargetDescX8664LinuxWireTool)),
        (GdbTargetDescAarch64LinuxWireTool::definition(), Box::new(GdbTargetDescAarch64LinuxWireTool)),
    ]
}
