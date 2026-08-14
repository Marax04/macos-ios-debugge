//! MCP wrappers for the rustre-kgdb crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct KgdbBytesToHexTool;

pub struct KgdbHexToBytesTool;

pub struct KgdbBytesToHexV2Tool;
impl KgdbBytesToHexV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_bytes_to_hex_v2".to_string(),
            description: "Encode byte slice to lowercase hex via rustre_debug_kgdb::bytes_to_hex.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}}},"required":["bytes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbBytesToHexV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bytes = args.get("bytes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'bytes'".into()))?
            .iter().map(|v| v.as_u64().map(|x| x as u8).unwrap_or(0)).collect::<Vec<u8>>();
        let hex = rustre_debug_kgdb::bytes_to_hex(&bytes);
        Ok(ToolResult::text(json!({"hex": hex, "len": bytes.len(), "source": "rustre_debug_kgdb::bytes_to_hex"}).to_string()))
    }
}

pub struct KgdbHexToBytesV2Tool;
impl KgdbHexToBytesV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_hex_to_bytes_v2".to_string(),
            description: "Decode a lowercase hex string to bytes via rustre_debug_kgdb::hex_to_bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbHexToBytesV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?;
        match rustre_debug_kgdb::hex_to_bytes(hex) {
            Ok(b) => { let n = b.len(); Ok(ToolResult::text(json!({"bytes": b, "len": n, "source": "rustre_debug_kgdb::hex_to_bytes"}).to_string())) }
            Err(e) => Err(McpError::InvalidParams(e)),
        }
    }
}

pub struct KgdbU64ToHexLeTool;
impl KgdbU64ToHexLeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_u64_to_hex_le".to_string(),
            description: "Encode u64 as little-endian hex (16 digits) via rustre_debug_kgdb::u64_to_hex_le.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{"type":"integer"}},"required":["value"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbU64ToHexLeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        Ok(ToolResult::text(json!({"hex": rustre_debug_kgdb::u64_to_hex_le(v), "source": "rustre_debug_kgdb::u64_to_hex_le"}).to_string()))
    }
}

pub struct KgdbU32ToHexLeTool;
impl KgdbU32ToHexLeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_u32_to_hex_le".to_string(),
            description: "Encode u32 as little-endian hex (8 digits) via rustre_debug_kgdb::u32_to_hex_le.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{"type":"integer"}},"required":["value"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbU32ToHexLeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let v = u32::try_from(v).map_err(|_| McpError::InvalidParams("value out of u32 range".into()))?;
        Ok(ToolResult::text(json!({"hex": rustre_debug_kgdb::u32_to_hex_le(v), "source": "rustre_debug_kgdb::u32_to_hex_le"}).to_string()))
    }
}

pub struct KgdbHexLeToU64Tool;
impl KgdbHexLeToU64Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_hex_le_to_u64".to_string(),
            description: "Decode little-endian hex to u64 via rustre_debug_kgdb::hex_le_to_u64.".to_string(),
            input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbHexLeToU64Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?;
        match rustre_debug_kgdb::hex_le_to_u64(hex) {
            Ok(v) => Ok(ToolResult::text(json!({"value": v, "value_hex": format!("{v:#x}"), "source": "rustre_debug_kgdb::hex_le_to_u64"}).to_string())),
            Err(e) => Err(McpError::InvalidParams(e)),
        }
    }
}

pub struct KgdbRleEncodeTool;
impl KgdbRleEncodeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_rle_encode".to_string(),
            description: "GDB RSP run-length encode a payload via rustre_debug_kgdb::rle_encode.".to_string(),
            input_schema: json!({"type":"object","properties":{"data":{"type":"string"}},"required":["data"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbRleEncodeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let d = args.get("data").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'data'".into()))?;
        let out = rustre_debug_kgdb::rle_encode(d);
        Ok(ToolResult::text(json!({"encoded": out, "input_len": d.len(), "source": "rustre_debug_kgdb::rle_encode"}).to_string()))
    }
}

pub struct KgdbRleDecodeTool;
impl KgdbRleDecodeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_rle_decode".to_string(),
            description: "GDB RSP run-length decode a payload via rustre_debug_kgdb::rle_decode.".to_string(),
            input_schema: json!({"type":"object","properties":{"data":{"type":"string"}},"required":["data"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbRleDecodeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let d = args.get("data").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'data'".into()))?;
        Ok(ToolResult::text(json!({"decoded": rustre_debug_kgdb::rle_decode(d), "source": "rustre_debug_kgdb::rle_decode"}).to_string()))
    }
}

pub struct KgdbIsKernelAddressTool;
impl KgdbIsKernelAddressTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_is_kernel_address".to_string(),
            description: "Test address in canonical Linux kernel VA range via rustre_debug_kgdb::is_kernel_address.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}},"required":["addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbIsKernelAddressTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("addr").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        Ok(ToolResult::text(json!({
            "is_kernel": rustre_debug_kgdb::is_kernel_address(a),
            "is_kernel_text": rustre_debug_kgdb::is_kernel_text_address(a),
            "source": "rustre_debug_kgdb::is_kernel_address"
        }).to_string()))
    }
}

pub struct KgdbPageAlignTool;
impl KgdbPageAlignTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_page_align".to_string(),
            description: "4 KiB page-align addr down and up via rustre_debug_kgdb::page_align_{down,up}.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}},"required":["addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbPageAlignTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("addr").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let d = rustre_debug_kgdb::page_align_down(a);
        let u = rustre_debug_kgdb::page_align_up(a);
        Ok(ToolResult::text(json!({
            "down": d, "up": u,
            "down_hex": format!("{d:#x}"), "up_hex": format!("{u:#x}"),
            "source": "rustre_debug_kgdb::page_align_down/up"
        }).to_string()))
    }
}

pub struct KgdbKvirtToPhysTool;
impl KgdbKvirtToPhysTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_kvirt_to_phys".to_string(),
            description: "Kernel virtual to physical via direct-map heuristic (rustre_debug_kgdb::kvirt_to_phys).".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}},"required":["addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbKvirtToPhysTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("addr").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let p = rustre_debug_kgdb::kvirt_to_phys(a);
        Ok(ToolResult::text(json!({"phys": p, "phys_hex": p.map(|x| format!("{x:#x}")), "source": "rustre_debug_kgdb::kvirt_to_phys"}).to_string()))
    }
}

pub struct KgdbRspChecksumTool;
impl KgdbRspChecksumTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_rsp_checksum".to_string(),
            description: "GDB RSP payload checksum via rustre_debug_kgdb::rsp_checksum.".to_string(),
            input_schema: json!({"type":"object","properties":{"data":{"type":"string"}},"required":["data"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbRspChecksumTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let d = args.get("data").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'data'".into()))?;
        let cs = rustre_debug_kgdb::rsp_checksum(d);
        Ok(ToolResult::text(json!({"checksum": cs, "checksum_hex": format!("{cs:02x}"), "source": "rustre_debug_kgdb::rsp_checksum"}).to_string()))
    }
}

pub struct KgdbVerifyRspChecksumTool;
impl KgdbVerifyRspChecksumTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_verify_rsp_checksum".to_string(),
            description: "Verify $data#XX wire packet checksum via rustre_debug_kgdb::verify_rsp_checksum.".to_string(),
            input_schema: json!({"type":"object","properties":{"wire":{"type":"string"}},"required":["wire"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbVerifyRspChecksumTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let w = args.get("wire").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'wire'".into()))?;
        Ok(ToolResult::text(json!({"valid": rustre_debug_kgdb::verify_rsp_checksum(w), "source": "rustre_debug_kgdb::verify_rsp_checksum"}).to_string()))
    }
}

pub struct KgdbParseKernelCallstackTool;
impl KgdbParseKernelCallstackTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_parse_kernel_callstack".to_string(),
            description: "Parse Linux kernel oops/panic call stack via rustre_debug_kgdb::parse_kernel_callstack.".to_string(),
            input_schema: json!({"type":"object","properties":{"log":{"type":"string"}},"required":["log"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbParseKernelCallstackTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let log = args.get("log").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'log'".into()))?;
        let frames = rustre_debug_kgdb::parse_kernel_callstack(log);
        let out: Vec<_> = frames.iter().map(|f| json!({"display": f.display()})).collect();
        Ok(ToolResult::text(json!({"frames": out, "count": frames.len(), "source": "rustre_debug_kgdb::parse_kernel_callstack"}).to_string()))
    }
}

pub struct KgdbTargetXmlX8664Tool;
impl KgdbTargetXmlX8664Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_target_xml_x86_64".to_string(),
            description: "Minimal x86_64 GDB target-description XML via rustre_debug_kgdb::target_xml_x86_64.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbTargetXmlX8664Tool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({"xml": rustre_debug_kgdb::target_xml_x86_64(), "source": "rustre_debug_kgdb::target_xml_x86_64"}).to_string()))
    }
}

pub struct KgdbTargetXmlArm64Tool;
impl KgdbTargetXmlArm64Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_target_xml_arm64".to_string(),
            description: "Minimal arm64 GDB target-description XML via rustre_debug_kgdb::target_xml_arm64.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbTargetXmlArm64Tool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({"xml": rustre_debug_kgdb::target_xml_arm64(), "source": "rustre_debug_kgdb::target_xml_arm64"}).to_string()))
    }
}

pub struct KgdbGdbPacketToWireTool;
impl KgdbGdbPacketToWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_gdb_packet_to_wire".to_string(),
            description: "Wrap a payload into $data#XX via rustre_debug_kgdb::GdbPacket::new+to_wire.".to_string(),
            input_schema: json!({"type":"object","properties":{"data":{"type":"string"}},"required":["data"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbGdbPacketToWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let d = args.get("data").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'data'".into()))?;
        let p = rustre_debug_kgdb::GdbPacket::new(d.to_owned());
        Ok(ToolResult::text(json!({"wire": p.to_wire(), "checksum": p.checksum, "source": "rustre_debug_kgdb::GdbPacket::to_wire"}).to_string()))
    }
}

pub struct KgdbGdbPacketParseTool;
impl KgdbGdbPacketParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_gdb_packet_parse".to_string(),
            description: "Parse $data#XX wire packet via rustre_debug_kgdb::GdbPacket::parse.".to_string(),
            input_schema: json!({"type":"object","properties":{"wire":{"type":"string"}},"required":["wire"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbGdbPacketParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let w = args.get("wire").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'wire'".into()))?;
        match rustre_debug_kgdb::GdbPacket::parse(w) {
            Ok(p) => Ok(ToolResult::text(json!({"data": p.data, "checksum": p.checksum, "source": "rustre_debug_kgdb::GdbPacket::parse"}).to_string())),
            Err(e) => Err(McpError::InvalidParams(e.to_string())),
        }
    }
}

pub struct KgdbParseQSupportedTool;
impl KgdbParseQSupportedTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_parse_qsupported".to_string(),
            description: "Parse a GDB qSupported response into features via rustre_debug_kgdb::parse_qsupported.".to_string(),
            input_schema: json!({"type":"object","properties":{"response":{"type":"string"}},"required":["response"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbParseQSupportedTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let r = args.get("response").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'response'".into()))?;
        let feats = rustre_debug_kgdb::parse_qsupported(r);
        let names: Vec<String> = feats.iter().map(|f| format!("{f:?}")).collect();
        Ok(ToolResult::text(json!({"count": names.len(), "features": names, "source": "rustre_debug_kgdb::parse_qsupported"}).to_string()))
    }
}

pub struct KgdbParseThreadListTool;
impl KgdbParseThreadListTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_parse_thread_list".to_string(),
            description: "Parse qfThreadInfo/qsThreadInfo response via rustre_debug_kgdb::parse_thread_list.".to_string(),
            input_schema: json!({"type":"object","properties":{"response":{"type":"string"}},"required":["response"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbParseThreadListTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let r = args.get("response").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'response'".into()))?;
        match rustre_debug_kgdb::parse_thread_list(r) {
            Ok(tids) => {
                let s: Vec<String> = tids.iter().map(|t| format!("{t:?}")).collect();
                Ok(ToolResult::text(json!({"count": s.len(), "threads": s, "source": "rustre_debug_kgdb::parse_thread_list"}).to_string()))
            }
            Err(e) => Err(McpError::InvalidParams(e)),
        }
    }
}

pub struct KgdbRspChecksumBytesTool;
impl KgdbRspChecksumBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_rsp_checksum_bytes".to_string(),
            description: "GDB RSP checksum over a raw byte slice via rustre_debug_kgdb::rsp_checksum_bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}}},"required":["bytes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbRspChecksumBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("bytes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'bytes'".into()))?;
        let d: Vec<u8> = arr.iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect();
        let cs = rustre_debug_kgdb::rsp_checksum_bytes(&d);
        Ok(ToolResult::text(json!({"checksum": cs, "checksum_hex": format!("{cs:02x}"), "source": "rustre_debug_kgdb::rsp_checksum_bytes"}).to_string()))
    }
}

pub struct KgdbRspVerifyChecksumBytesTool;
impl KgdbRspVerifyChecksumBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_rsp_verify_checksum_bytes".to_string(),
            description: "Verify checksum_hex against data bytes via rustre_debug_kgdb::rsp_verify_checksum_bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"checksum_hex":{"type":"string"}},"required":["bytes","checksum_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbRspVerifyChecksumBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("bytes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'bytes'".into()))?;
        let cs = args.get("checksum_hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'checksum_hex'".into()))?;
        let d: Vec<u8> = arr.iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect();
        match rustre_debug_kgdb::rsp_verify_checksum_bytes(&d, cs) {
            Ok(()) => Ok(ToolResult::text(json!({"valid": true, "source": "rustre_debug_kgdb::rsp_verify_checksum_bytes"}).to_string())),
            Err(e) => Ok(ToolResult::text(json!({"valid": false, "error": e, "source": "rustre_debug_kgdb::rsp_verify_checksum_bytes"}).to_string())),
        }
    }
}

pub struct KgdbRspEncodePacketBytesTool;
impl KgdbRspEncodePacketBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_rsp_encode_packet_bytes".to_string(),
            description: "Encode a raw byte payload as $<data>#<cs> via rustre_debug_kgdb::rsp_encode_packet_bytes.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}}},"required":["bytes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbRspEncodePacketBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("bytes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'bytes'".into()))?;
        let d: Vec<u8> = arr.iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect();
        let out = rustre_debug_kgdb::rsp_encode_packet_bytes(&d);
        Ok(ToolResult::text(json!({"packet": out, "len": d.len(), "source": "rustre_debug_kgdb::rsp_encode_packet_bytes"}).to_string()))
    }
}

pub struct KgdbEncodeHexBufTool;
impl KgdbEncodeHexBufTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_encode_hex_buf".to_string(),
            description: "Encode bytes as lowercase hex g-packet buffer via rustre_debug_kgdb::encode_hex_buf.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}}},"required":["bytes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbEncodeHexBufTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("bytes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'bytes'".into()))?;
        let d: Vec<u8> = arr.iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect();
        let hex = rustre_debug_kgdb::encode_hex_buf(&d);
        Ok(ToolResult::text(json!({"hex": hex, "len": d.len(), "source": "rustre_debug_kgdb::encode_hex_buf"}).to_string()))
    }
}

pub struct KgdbDecodeHexBufTool;
impl KgdbDecodeHexBufTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_decode_hex_buf".to_string(),
            description: "Decode a hex g-packet buffer to bytes via rustre_debug_kgdb::decode_hex_buf.".to_string(),
            input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbDecodeHexBufTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let h = args.get("hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?;
        match rustre_debug_kgdb::decode_hex_buf(h) {
            Ok(b) => { let n = b.len(); Ok(ToolResult::text(json!({"bytes": b, "len": n, "source": "rustre_debug_kgdb::decode_hex_buf"}).to_string())) }
            Err(e) => Err(McpError::InvalidParams(e)),
        }
    }
}

pub struct KgdbReadU64LeHexTool;
impl KgdbReadU64LeHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_read_u64_le_hex".to_string(),
            description: "Read a little-endian u64 from a 16-char hex g-packet field via rustre_debug_kgdb::read_u64_le_hex.".to_string(),
            input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbReadU64LeHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let h = args.get("hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?;
        match rustre_debug_kgdb::read_u64_le_hex(h) {
            Ok(v) => Ok(ToolResult::text(json!({"value": v, "value_hex": format!("{v:#x}"), "source": "rustre_debug_kgdb::read_u64_le_hex"}).to_string())),
            Err(e) => Err(McpError::InvalidParams(e)),
        }
    }
}

pub struct KgdbRspEscapeTool;
impl KgdbRspEscapeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_rsp_escape".to_string(),
            description: "Escape a byte payload for RSP transmission via rustre_debug_kgdb::rsp_escape.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}}},"required":["bytes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbRspEscapeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("bytes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'bytes'".into()))?;
        let d: Vec<u8> = arr.iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect();
        let out = rustre_debug_kgdb::rsp_escape(&d);
        Ok(ToolResult::text(json!({"escaped": out, "input_len": d.len(), "source": "rustre_debug_kgdb::rsp_escape"}).to_string()))
    }
}

pub struct KgdbRspUnescapeTool;
impl KgdbRspUnescapeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "kgdb_rsp_unescape".to_string(),
            description: "Unescape a } escape-encoded RSP byte sequence via rustre_debug_kgdb::rsp_unescape.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}}},"required":["bytes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for KgdbRspUnescapeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("bytes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'bytes'".into()))?;
        let d: Vec<u8> = arr.iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect();
        let out = rustre_debug_kgdb::rsp_unescape(&d);
        Ok(ToolResult::text(json!({"unescaped": out, "input_len": d.len(), "source": "rustre_debug_kgdb::rsp_unescape"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (KgdbBytesToHexTool::definition(), Box::new(KgdbBytesToHexTool)),
        (KgdbHexToBytesTool::definition(), Box::new(KgdbHexToBytesTool)),
        (KgdbBytesToHexV2Tool::definition(), Box::new(KgdbBytesToHexV2Tool)),
        (KgdbHexToBytesV2Tool::definition(), Box::new(KgdbHexToBytesV2Tool)),
        (KgdbU64ToHexLeTool::definition(), Box::new(KgdbU64ToHexLeTool)),
        (KgdbU32ToHexLeTool::definition(), Box::new(KgdbU32ToHexLeTool)),
        (KgdbHexLeToU64Tool::definition(), Box::new(KgdbHexLeToU64Tool)),
        (KgdbRleEncodeTool::definition(), Box::new(KgdbRleEncodeTool)),
        (KgdbRleDecodeTool::definition(), Box::new(KgdbRleDecodeTool)),
        (KgdbIsKernelAddressTool::definition(), Box::new(KgdbIsKernelAddressTool)),
        (KgdbPageAlignTool::definition(), Box::new(KgdbPageAlignTool)),
        (KgdbKvirtToPhysTool::definition(), Box::new(KgdbKvirtToPhysTool)),
        (KgdbRspChecksumTool::definition(), Box::new(KgdbRspChecksumTool)),
        (KgdbVerifyRspChecksumTool::definition(), Box::new(KgdbVerifyRspChecksumTool)),
        (KgdbParseKernelCallstackTool::definition(), Box::new(KgdbParseKernelCallstackTool)),
        (KgdbTargetXmlX8664Tool::definition(), Box::new(KgdbTargetXmlX8664Tool)),
        (KgdbTargetXmlArm64Tool::definition(), Box::new(KgdbTargetXmlArm64Tool)),
        (KgdbGdbPacketToWireTool::definition(), Box::new(KgdbGdbPacketToWireTool)),
        (KgdbGdbPacketParseTool::definition(), Box::new(KgdbGdbPacketParseTool)),
        (KgdbParseQSupportedTool::definition(), Box::new(KgdbParseQSupportedTool)),
        (KgdbParseThreadListTool::definition(), Box::new(KgdbParseThreadListTool)),
        (KgdbRspChecksumBytesTool::definition(), Box::new(KgdbRspChecksumBytesTool)),
        (KgdbRspVerifyChecksumBytesTool::definition(), Box::new(KgdbRspVerifyChecksumBytesTool)),
        (KgdbRspEncodePacketBytesTool::definition(), Box::new(KgdbRspEncodePacketBytesTool)),
        (KgdbEncodeHexBufTool::definition(), Box::new(KgdbEncodeHexBufTool)),
        (KgdbDecodeHexBufTool::definition(), Box::new(KgdbDecodeHexBufTool)),
        (KgdbReadU64LeHexTool::definition(), Box::new(KgdbReadU64LeHexTool)),
        (KgdbRspEscapeTool::definition(), Box::new(KgdbRspEscapeTool)),
        (KgdbRspUnescapeTool::definition(), Box::new(KgdbRspUnescapeTool)),
    ]
}
