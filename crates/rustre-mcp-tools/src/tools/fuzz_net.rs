//! MCP wrappers for the rustre-fuzz_net crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes, hex_encode};
use crate::wire_tools::{pe_editor_hex_decode};

pub struct FuzzNetXorChecksumTool;

pub struct FuzzNetAddChecksumTool;

pub struct FuzzNetFrameU32LeTool;
impl FuzzNetFrameU32LeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_net_frame_u32_le".to_string(),
            description: "Encode a payload with a 4-byte little-endian length prefix via rustre_fuzz_net::frame_u32_le.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex":   { "type": "string" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzNetFrameU32LeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let out = rustre_fuzz_net::frame_u32_le(&data)
            .map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "hex":    hex_encode(&out),
            "length": out.len(),
            "source": "rustre_fuzz_net::frame_u32_le",
        }).to_string()))
    }
}

pub struct FuzzNetFrameU32BeTool;
impl FuzzNetFrameU32BeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_net_frame_u32_be".to_string(),
            description: "Encode a payload with a 4-byte big-endian length prefix via rustre_fuzz_net::frame_u32_be.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex":   { "type": "string" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzNetFrameU32BeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let out = rustre_fuzz_net::frame_u32_be(&data)
            .map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "hex":    hex_encode(&out),
            "length": out.len(),
            "source": "rustre_fuzz_net::frame_u32_be",
        }).to_string()))
    }
}

pub struct FuzzNetDecodeFrameU32LeTool;
impl FuzzNetDecodeFrameU32LeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_net_decode_frame_u32_le".to_string(),
            description: "Decode a u32-LE length-prefixed frame via rustre_fuzz_net::decode_frame_u32_le.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex":   { "type": "string" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzNetDecodeFrameU32LeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        match rustre_fuzz_net::decode_frame_u32_le(&data) {
            Some((total, payload)) => Ok(ToolResult::text(json!({
                "found":         true,
                "total_len":     total,
                "payload_len":   payload.len(),
                "payload_hex":   hex_encode(&payload),
                "source": "rustre_fuzz_net::decode_frame_u32_le",
            }).to_string())),
            None => Ok(ToolResult::text(json!({
                "found":  false,
                "source": "rustre_fuzz_net::decode_frame_u32_le",
            }).to_string())),
        }
    }
}

pub struct FuzzNetInterestingIntMutationTool;
impl FuzzNetInterestingIntMutationTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_net_interesting_int_mutation".to_string(),
            description: "Produce a mutated integer using rustre_fuzz_net::interesting_int_mutation with a fresh XorShift RNG.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "current": {"type": "integer"},
                    "size_bytes": {"type": "integer", "description": "1, 2, or 4"}
                },
                "required": ["current", "size_bytes"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzNetInterestingIntMutationTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let current = args.get("current").and_then(Value::as_i64)
            .ok_or_else(|| McpError::InvalidParams("missing 'current'".into()))?;
        let size_bytes = args.get("size_bytes").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'size_bytes'".into()))? as u8;
        let mut rng = rustre_fuzz_afl::XorShiftRng::default();
        let mutated = rustre_fuzz_net::interesting_int_mutation(current, size_bytes, &mut rng);
        Ok(ToolResult::text(json!({
            "current": current, "size_bytes": size_bytes, "mutated": mutated,
            "source": "rustre_fuzz_net::interesting_int_mutation",
        }).to_string()))
    }
}

pub struct FuzzNetInterestingConstantsTool;
impl FuzzNetInterestingConstantsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_net_interesting_constants".to_string(),
            description: "Return the boundary-value tables INTERESTING_U8/U16/U32 from rustre_fuzz_net.".to_string(),
            input_schema: json!({"type": "object", "properties": {}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzNetInterestingConstantsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        Ok(ToolResult::text(json!({
            "u8": rustre_fuzz_net::INTERESTING_U8,
            "u16": rustre_fuzz_net::INTERESTING_U16,
            "u32": rustre_fuzz_net::INTERESTING_U32,
            "source": "rustre_fuzz_net::INTERESTING_*",
        }).to_string()))
    }
}

pub struct FuzzNetResponseMatcherFindTool;
impl FuzzNetResponseMatcherFindTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_net_response_matcher_find".to_string(),
            description: "Find first occurrence of a hex pattern in a hex buffer via rustre_fuzz_net::ResponseMatcher::find.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pattern_hex": {"type": "string"},
                    "buf_hex": {"type": "string"}
                },
                "required": ["pattern_hex", "buf_hex"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzNetResponseMatcherFindTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pat = pe_editor_hex_decode(args.get("pattern_hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'pattern_hex'".into()))?)?;
        let buf = pe_editor_hex_decode(args.get("buf_hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'buf_hex'".into()))?)?;
        let m = rustre_fuzz_net::ResponseMatcher::new(pat);
        let idx = m.find(&buf);
        Ok(ToolResult::text(json!({
            "found": idx.is_some(),
            "index": idx,
            "source": "rustre_fuzz_net::ResponseMatcher::find",
        }).to_string()))
    }
}

pub struct FuzzNetResponseMatcherMatchesTool;
impl FuzzNetResponseMatcherMatchesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_net_response_matcher_matches".to_string(),
            description: "Test whether a hex buffer contains a hex pattern via rustre_fuzz_net::ResponseMatcher::matches.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pattern_hex": {"type": "string"},
                    "buf_hex": {"type": "string"}
                },
                "required": ["pattern_hex", "buf_hex"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzNetResponseMatcherMatchesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let pat = pe_editor_hex_decode(args.get("pattern_hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'pattern_hex'".into()))?)?;
        let buf = pe_editor_hex_decode(args.get("buf_hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'buf_hex'".into()))?)?;
        let m = rustre_fuzz_net::ResponseMatcher::new(pat);
        Ok(ToolResult::text(json!({
            "matches": m.matches(&buf),
            "source": "rustre_fuzz_net::ResponseMatcher::matches",
        }).to_string()))
    }
}

pub struct FuzzNetCrashClassifierTool;
impl FuzzNetCrashClassifierTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_net_crash_classify".to_string(),
            description: "Classify a target response using rustre_fuzz_net::FuzzCrashClassifier::classify.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "response_hex": {"type": "string"},
                    "expected_hex": {"type": "string"}
                },
                "required": ["response_hex", "expected_hex"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzNetCrashClassifierTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let resp = pe_editor_hex_decode(args.get("response_hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'response_hex'".into()))?)?;
        let exp = pe_editor_hex_decode(args.get("expected_hex").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'expected_hex'".into()))?)?;
        let kind = rustre_fuzz_net::FuzzCrashClassifier::classify(&resp, &exp);
        Ok(ToolResult::text(json!({
            "kind": kind.label(),
            "is_crash": rustre_fuzz_net::FuzzCrashClassifier::is_crash(kind),
            "is_interesting": rustre_fuzz_net::FuzzCrashClassifier::is_interesting(kind),
            "source": "rustre_fuzz_net::FuzzCrashClassifier::classify",
        }).to_string()))
    }
}

pub struct FuzzNetCrashClassifyReasonTool;
impl FuzzNetCrashClassifyReasonTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_net_crash_classify_reason".to_string(),
            description: "Classify a crash-logger reason string via rustre_fuzz_net::FuzzCrashClassifier::classify_reason.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {"reason": {"type": "string"}},
                "required": ["reason"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzNetCrashClassifyReasonTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let reason = args.get("reason").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'reason'".into()))?;
        let kind = rustre_fuzz_net::FuzzCrashClassifier::classify_reason(reason);
        Ok(ToolResult::text(json!({
            "reason": reason,
            "kind": kind.label(),
            "is_crash": rustre_fuzz_net::FuzzCrashClassifier::is_crash(kind),
            "source": "rustre_fuzz_net::FuzzCrashClassifier::classify_reason",
        }).to_string()))
    }
}

pub struct FuzzNetProtocolLoadYamlTool;
impl FuzzNetProtocolLoadYamlTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_net_protocol_load_yaml".to_string(),
            description: "Load a ProtocolDef from YAML and report state/edge summary via rustre_fuzz_net::ProtocolDef::load_from_yaml.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {"yaml": {"type": "string"}},
                "required": ["yaml"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzNetProtocolLoadYamlTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let yaml = args.get("yaml").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'yaml'".into()))?;
        let proto = rustre_fuzz_net::ProtocolDef::load_from_yaml(yaml)
            .map_err(|e| McpError::InvalidParams(format!("yaml: {e}")))?;
        let edges: Vec<String> = proto.edges().iter().map(|(a, b)| format!("{a}->{b}")).collect();
        let states: Vec<String> = proto.state_names().iter().map(|s| (*s).to_string()).collect();
        let errors = proto.validate();
        Ok(ToolResult::text(json!({
            "initial_state": proto.initial_state,
            "state_count": proto.state_count(),
            "states": states,
            "edges": edges,
            "validation_errors": errors,
            "source": "rustre_fuzz_net::ProtocolDef::load_from_yaml",
        }).to_string()))
    }
}

pub struct FuzzNetProtocolDrivePathTool;
impl FuzzNetProtocolDrivePathTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_net_protocol_drive_path".to_string(),
            description: "Load a YAML ProtocolDef and BFS-drive to `target`; return the visited path via rustre_fuzz_net::StateMachineDriver.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "yaml": {"type": "string"},
                    "target": {"type": "string"}
                },
                "required": ["yaml", "target"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzNetProtocolDrivePathTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let yaml = args.get("yaml").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'yaml'".into()))?;
        let target = args.get("target").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'target'".into()))?;
        let proto = rustre_fuzz_net::ProtocolDef::load_from_yaml(yaml)
            .map_err(|e| McpError::InvalidParams(format!("yaml: {e}")))?;
        let mut driver = rustre_fuzz_net::StateMachineDriver::new(proto);
        driver.drive_to_state(target)
            .map_err(|e| McpError::InvalidParams(format!("drive: {e}")))?;
        Ok(ToolResult::text(json!({
            "target": target,
            "current_state": driver.current_state(),
            "history": driver.transition_history(),
            "can_advance": driver.can_advance(),
            "source": "rustre_fuzz_net::StateMachineDriver::drive_to_state",
        }).to_string()))
    }
}

pub struct FuzzNetCrashKindLabelTool;
impl FuzzNetCrashKindLabelTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_net_crash_kind_labels".to_string(),
            description: "List all rustre_fuzz_net::CrashKind variants and their labels.".to_string(),
            input_schema: json!({"type": "object", "properties": {}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzNetCrashKindLabelTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_fuzz_net::CrashKind;
        let items: Vec<Value> = [
            CrashKind::Disconnect, CrashKind::Timeout, CrashKind::UnexpectedResponse,
            CrashKind::ProtocolError, CrashKind::Success,
        ].iter().map(|k| json!({
            "label": k.label(),
            "is_crash": rustre_fuzz_net::FuzzCrashClassifier::is_crash(*k),
            "is_interesting": rustre_fuzz_net::FuzzCrashClassifier::is_interesting(*k),
        })).collect();
        Ok(ToolResult::text(json!({
            "kinds": items,
            "source": "rustre_fuzz_net::CrashKind::label",
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (FuzzNetXorChecksumTool::definition(), Box::new(FuzzNetXorChecksumTool)),
        (FuzzNetAddChecksumTool::definition(), Box::new(FuzzNetAddChecksumTool)),
        (FuzzNetFrameU32LeTool::definition(), Box::new(FuzzNetFrameU32LeTool)),
        (FuzzNetFrameU32BeTool::definition(), Box::new(FuzzNetFrameU32BeTool)),
        (FuzzNetDecodeFrameU32LeTool::definition(), Box::new(FuzzNetDecodeFrameU32LeTool)),
        (FuzzNetInterestingIntMutationTool::definition(), Box::new(FuzzNetInterestingIntMutationTool)),
        (FuzzNetInterestingConstantsTool::definition(), Box::new(FuzzNetInterestingConstantsTool)),
        (FuzzNetResponseMatcherFindTool::definition(), Box::new(FuzzNetResponseMatcherFindTool)),
        (FuzzNetResponseMatcherMatchesTool::definition(), Box::new(FuzzNetResponseMatcherMatchesTool)),
        (FuzzNetCrashClassifierTool::definition(), Box::new(FuzzNetCrashClassifierTool)),
        (FuzzNetCrashClassifyReasonTool::definition(), Box::new(FuzzNetCrashClassifyReasonTool)),
        (FuzzNetProtocolLoadYamlTool::definition(), Box::new(FuzzNetProtocolLoadYamlTool)),
        (FuzzNetProtocolDrivePathTool::definition(), Box::new(FuzzNetProtocolDrivePathTool)),
        (FuzzNetCrashKindLabelTool::definition(), Box::new(FuzzNetCrashKindLabelTool)),
    ]
}
