//! MCP wrappers for the rustre-windbg crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{hex_encode};

pub struct WindbgKdnetPacketTypeIdTool;
impl WindbgKdnetPacketTypeIdTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "windbg_kdnet_packet_type_id".to_string(),
            description: "Return numeric type_id for a KDNET packet type name via rustre_debug_windbg::KdNetPacketType::type_id.".to_string(),
            input_schema: json!({"type":"object","required":["kind"],"properties":{"kind":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for WindbgKdnetPacketTypeIdTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let kind = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let t = match kind.to_ascii_lowercase().as_str() {
            "breakpoint" => rustre_debug_windbg::KdNetPacketType::Breakpoint,
            "statechange" | "state_change" => rustre_debug_windbg::KdNetPacketType::StateChange,
            "manipulatestate" | "manipulate_state" => rustre_debug_windbg::KdNetPacketType::ManipulateState,
            "controlrequest" | "control_request" => rustre_debug_windbg::KdNetPacketType::ControlRequest,
            "acknowledge" | "ack" => rustre_debug_windbg::KdNetPacketType::Acknowledge,
            "resend" => rustre_debug_windbg::KdNetPacketType::Resend,
            "debug" => rustre_debug_windbg::KdNetPacketType::Debug,
            other => return Err(McpError::InvalidParams(format!("unknown kind: {other}"))),
        };
        Ok(ToolResult::text(json!({"type_id": t.type_id(), "source":"rustre_debug_windbg::KdNetPacketType::type_id"}).to_string()))
    }
}

pub struct WindbgKdnetPacketFromIdTool;
impl WindbgKdnetPacketFromIdTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "windbg_kdnet_packet_from_id".to_string(),
            description: "Resolve KdNetPacketType from a numeric type_id via rustre_debug_windbg::KdNetPacketType::from_id.".to_string(),
            input_schema: json!({"type":"object","required":["type_id"],"properties":{"type_id":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for WindbgKdnetPacketFromIdTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let id = args.get("type_id").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'type_id'".into()))? as u16;
        let k = rustre_debug_windbg::KdNetPacketType::from_id(id);
        Ok(ToolResult::text(json!({"kind": k.map(|v| format!("{v:?}")), "source":"rustre_debug_windbg::KdNetPacketType::from_id"}).to_string()))
    }
}

pub struct WindbgKdnetPacketChecksumTool;
impl WindbgKdnetPacketChecksumTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "windbg_kdnet_packet_checksum".to_string(),
            description: "Compute the additive KDNET packet checksum via rustre_debug_windbg::KdNetPacket::compute_checksum.".to_string(),
            input_schema: json!({"type":"object","required":["data_hex"],"properties":{"data_hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for WindbgKdnetPacketChecksumTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data_hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let data = crate::hex_decode(data_hex)?;
        let c = rustre_debug_windbg::KdNetPacket::compute_checksum(&data);
        Ok(ToolResult::text(json!({"checksum": c, "source":"rustre_debug_windbg::KdNetPacket::compute_checksum"}).to_string()))
    }
}

pub struct WindbgKdnetPacketEncodeTool;
impl WindbgKdnetPacketEncodeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "windbg_kdnet_packet_encode".to_string(),
            description: "Encode a KDNET Debug-type packet to wire bytes via rustre_debug_windbg::KdNetPacket::new + encode.".to_string(),
            input_schema: json!({"type":"object","required":["packet_id","data_hex"],"properties":{"packet_id":{"type":"integer"},"data_hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for WindbgKdnetPacketEncodeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pid = args.get("packet_id").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'packet_id'".into()))? as u32;
        let data_hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let data = crate::hex_decode(data_hex)?;
        let pkt = rustre_debug_windbg::KdNetPacket::new(rustre_debug_windbg::KdNetPacketType::Debug, pid, data);
        let bytes = pkt.encode();
        let verified = pkt.verify();
        Ok(ToolResult::text(json!({
            "bytes_hex": hex_encode(&bytes),
            "byte_count": pkt.byte_count,
            "checksum": pkt.checksum,
            "verified": verified,
            "source":"rustre_debug_windbg::KdNetPacket::encode"
        }).to_string()))
    }
}

pub struct WindbgMinidumpStreamTypeNameTool;
impl WindbgMinidumpStreamTypeNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "windbg_minidump_stream_type_name".to_string(),
            description: "Return human-readable name for a minidump stream type via rustre_debug_windbg::MinidumpStreamType::name.".to_string(),
            input_schema: json!({"type":"object","required":["stream_id"],"properties":{"stream_id":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for WindbgMinidumpStreamTypeNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let id = args.get("stream_id").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'stream_id'".into()))?;
        let s = match id {
            0 => Some(rustre_debug_windbg::MinidumpStreamType::UnusedStream),
            3 => Some(rustre_debug_windbg::MinidumpStreamType::ThreadListStream),
            4 => Some(rustre_debug_windbg::MinidumpStreamType::ModuleListStream),
            5 => Some(rustre_debug_windbg::MinidumpStreamType::MemoryListStream),
            6 => Some(rustre_debug_windbg::MinidumpStreamType::ExceptionStream),
            7 => Some(rustre_debug_windbg::MinidumpStreamType::SystemInfoStream),
            9 => Some(rustre_debug_windbg::MinidumpStreamType::Memory64ListStream),
            15 => Some(rustre_debug_windbg::MinidumpStreamType::MiscInfoStream),
            16 => Some(rustre_debug_windbg::MinidumpStreamType::MemoryInfoListStream),
            _ => None,
        };
        Ok(ToolResult::text(json!({"name": s.map(|v| v.name()), "source":"rustre_debug_windbg::MinidumpStreamType::name"}).to_string()))
    }
}

pub struct WindbgDbgModuleInfoContainsTool;
impl WindbgDbgModuleInfoContainsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "windbg_dbg_module_info_contains".to_string(),
            description: "Check if an address falls within a module range via rustre_debug_windbg::DbgModuleInfo::contains.".to_string(),
            input_schema: json!({"type":"object","required":["base","size","addr"],"properties":{"base":{"type":"integer"},"size":{"type":"integer"},"addr":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for WindbgDbgModuleInfoContainsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))?;
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let m = rustre_debug_windbg::DbgModuleInfo::new(base, size, "mod".to_string());
        Ok(ToolResult::text(json!({"contains": m.contains(addr), "source":"rustre_debug_windbg::DbgModuleInfo::contains"}).to_string()))
    }
}

pub struct WindbgExtensionRegistryStandardCountTool;
impl WindbgExtensionRegistryStandardCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "windbg_extension_registry_standard_count".to_string(),
            description: "Return the number of built-in extension commands from rustre_debug_windbg::ExtensionRegistry::standard.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for WindbgExtensionRegistryStandardCountTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let r = rustre_debug_windbg::ExtensionRegistry::standard();
        Ok(ToolResult::text(json!({"count": r.count(), "source":"rustre_debug_windbg::ExtensionRegistry::standard"}).to_string()))
    }
}

pub struct WindbgExtensionRegistryFindTool;
impl WindbgExtensionRegistryFindTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "windbg_extension_registry_find".to_string(),
            description: "Look up a standard WinDbg extension command by name via rustre_debug_windbg::ExtensionRegistry::find.".to_string(),
            input_schema: json!({"type":"object","required":["name"],"properties":{"name":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for WindbgExtensionRegistryFindTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let r = rustre_debug_windbg::ExtensionRegistry::standard();
        let found = r.find(name).map(|c| json!({"name": c.name, "description": c.description, "dll_name": c.dll_name}));
        Ok(ToolResult::text(json!({"command": found, "source":"rustre_debug_windbg::ExtensionRegistry::find"}).to_string()))
    }
}

pub struct WindbgCommandParserParseTool;
impl WindbgCommandParserParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "windbg_command_parser_parse".to_string(),
            description: "Parse a WinDbg command string into a structured DbgCommand via rustre_debug_windbg::WinDbgCommandParser::parse.".to_string(),
            input_schema: json!({"type":"object","required":["input"],"properties":{"input":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for WindbgCommandParserParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let input = args.get("input").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'input'".into()))?;
        let p = rustre_debug_windbg::WinDbgCommandParser::new();
        let cmd = p.parse(input);
        Ok(ToolResult::text(json!({
            "debug": format!("{cmd:?}"),
            "display": cmd.to_string(),
            "source":"rustre_debug_windbg::WinDbgCommandParser::parse"
        }).to_string()))
    }
}

pub struct WindbgExprEvaluatorEvaluateTool;
impl WindbgExprEvaluatorEvaluateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "windbg_expr_evaluator_evaluate".to_string(),
            description: "Evaluate a WinDbg-style hex/register expression via rustre_debug_windbg::WinDbgExprEvaluator::evaluate.".to_string(),
            input_schema: json!({"type":"object","required":["expr"],"properties":{"expr":{"type":"string"},"registers":{"type":"object"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for WindbgExprEvaluatorEvaluateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let expr = args.get("expr").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'expr'".into()))?;
        let mut e = rustre_debug_windbg::WinDbgExprEvaluator::new();
        if let Some(regs) = args.get("registers").and_then(Value::as_object) {
            for (k, v) in regs {
                if let Some(val) = v.as_u64() {
                    e.set_reg(k, val);
                }
            }
        }
        let value = e.evaluate(expr);
        Ok(ToolResult::text(json!({"value": value, "source":"rustre_debug_windbg::WinDbgExprEvaluator::evaluate"}).to_string()))
    }
}

pub struct WindbgModuleListParseLmTool;
impl WindbgModuleListParseLmTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "windbg_module_list_parse_lm".to_string(),
            description: "Parse WinDbg `lm` command output into structured module entries via rustre_debug_windbg::WinDbgModuleList::parse_lm_output.".to_string(),
            input_schema: json!({"type":"object","required":["text"],"properties":{"text":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for WindbgModuleListParseLmTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?;
        let mut l = rustre_debug_windbg::WinDbgModuleList::new();
        l.parse_lm_output(text);
        let entries: Vec<_> = l.entries.iter().map(|e| json!({
            "start": e.start, "end": e.end, "size": e.size(), "name": e.name, "path": e.path
        })).collect();
        Ok(ToolResult::text(json!({
            "count": l.count(),
            "entries": entries,
            "source":"rustre_debug_windbg::WinDbgModuleList::parse_lm_output"
        }).to_string()))
    }
}

pub struct WindbgParsedDbgOutputKeyValuesTool;
impl WindbgParsedDbgOutputKeyValuesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "windbg_parsed_dbg_output_key_values".to_string(),
            description: "Parse `key: value` and `key=value` lines from WinDbg output via rustre_debug_windbg::ParsedDbgOutput::parse_key_values.".to_string(),
            input_schema: json!({"type":"object","required":["text"],"properties":{"text":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for WindbgParsedDbgOutputKeyValuesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?;
        let p = rustre_debug_windbg::ParsedDbgOutput::parse_key_values(text);
        Ok(ToolResult::text(json!({
            "fields": p.fields,
            "addresses": p.addresses,
            "source":"rustre_debug_windbg::ParsedDbgOutput::parse_key_values"
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (WindbgKdnetPacketTypeIdTool::definition(), Box::new(WindbgKdnetPacketTypeIdTool)),
        (WindbgKdnetPacketFromIdTool::definition(), Box::new(WindbgKdnetPacketFromIdTool)),
        (WindbgKdnetPacketChecksumTool::definition(), Box::new(WindbgKdnetPacketChecksumTool)),
        (WindbgKdnetPacketEncodeTool::definition(), Box::new(WindbgKdnetPacketEncodeTool)),
        (WindbgMinidumpStreamTypeNameTool::definition(), Box::new(WindbgMinidumpStreamTypeNameTool)),
        (WindbgDbgModuleInfoContainsTool::definition(), Box::new(WindbgDbgModuleInfoContainsTool)),
        (WindbgExtensionRegistryStandardCountTool::definition(), Box::new(WindbgExtensionRegistryStandardCountTool)),
        (WindbgExtensionRegistryFindTool::definition(), Box::new(WindbgExtensionRegistryFindTool)),
        (WindbgCommandParserParseTool::definition(), Box::new(WindbgCommandParserParseTool)),
        (WindbgExprEvaluatorEvaluateTool::definition(), Box::new(WindbgExprEvaluatorEvaluateTool)),
        (WindbgModuleListParseLmTool::definition(), Box::new(WindbgModuleListParseLmTool)),
        (WindbgParsedDbgOutputKeyValuesTool::definition(), Box::new(WindbgParsedDbgOutputKeyValuesTool)),
    ]
}
