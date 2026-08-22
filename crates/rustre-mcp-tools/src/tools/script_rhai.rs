//! MCP wrappers for the rustre-script_rhai crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes};
use crate::wire_tools::{pe_editor_hex_decode};

pub struct ScriptRhaiEntropyClassifyTool;

pub struct ScriptRhaiHexEncodeTool;

pub struct ScriptRhaiSha256BytesWireTool;
impl ScriptRhaiSha256BytesWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_sha256_bytes".to_string(),
            description: "Compute SHA-256 hex digest of bytes via rustre_script_rhai::sha256_bytes_impl.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiSha256BytesWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let h = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let data = pe_editor_hex_decode(h)?;
        let digest = rustre_script_rhai::sha256_bytes_impl(&data);
        Ok(ToolResult::text(json!({"sha256":digest,"len":data.len(),"source":"rustre_script_rhai::sha256_bytes_impl"}).to_string()))
    }
}

pub struct ScriptRhaiHexDecodeWireTool;
impl ScriptRhaiHexDecodeWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_hex_decode".to_string(),
            description: "Decode a hex string to bytes via rustre_script_rhai::hex_decode_impl.".to_string(),
            input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiHexDecodeWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let h = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?;
        let out = rustre_script_rhai::hex_decode_impl(h);
        Ok(ToolResult::text(json!({"len":out.len(),"bytes_hex":rustre_script_rhai::hex_encode_impl(&out),"source":"rustre_script_rhai::hex_decode_impl"}).to_string()))
    }
}

pub struct ScriptRhaiFindPatternWireTool;
impl ScriptRhaiFindPatternWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_find_pattern".to_string(),
            description: "Find all offsets of a space-separated hex pattern (with ?? wildcards) in bytes via rustre_script_rhai::find_pattern_impl.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"},"pattern":{"type":"string"}},"required":["data_hex","pattern"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiFindPatternWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let h = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let pat = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let data = pe_editor_hex_decode(h)?;
        let hits = rustre_script_rhai::find_pattern_impl(&data, pat);
        let offsets: Vec<i64> = hits.iter().filter_map(|d| d.clone().try_cast::<i64>()).collect();
        Ok(ToolResult::text(json!({"count":offsets.len(),"offsets":offsets,"source":"rustre_script_rhai::find_pattern_impl"}).to_string()))
    }
}

pub struct ScriptRhaiXorBytesWireTool;
impl ScriptRhaiXorBytesWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_xor_bytes".to_string(),
            description: "XOR every byte with a single-byte key via rustre_script_rhai::xor_bytes_impl.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"},"key":{"type":"integer"}},"required":["data_hex","key"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiXorBytesWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let h = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let k = args.get("key").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'key'".into()))?;
        let data = pe_editor_hex_decode(h)?;
        let out = rustre_script_rhai::xor_bytes_impl(&data, (k & 0xff) as u8);
        Ok(ToolResult::text(json!({"len":out.len(),"out_hex":rustre_script_rhai::hex_encode_impl(&out),"source":"rustre_script_rhai::xor_bytes_impl"}).to_string()))
    }
}

pub struct ScriptRhaiRotateBytesWireTool;
impl ScriptRhaiRotateBytesWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_rotate_bytes".to_string(),
            description: "Rotate each byte left or right by n bits via rustre_script_rhai::rotate_bytes_impl.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"},"n":{"type":"integer"},"rol":{"type":"boolean"}},"required":["data_hex","n","rol"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiRotateBytesWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let h = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let rol = args.get("rol").and_then(Value::as_bool).ok_or_else(|| McpError::InvalidParams("missing 'rol'".into()))?;
        let data = pe_editor_hex_decode(h)?;
        let out = rustre_script_rhai::rotate_bytes_impl(&data, (n & 0xff) as u8, rol);
        Ok(ToolResult::text(json!({"len":out.len(),"out_hex":rustre_script_rhai::hex_encode_impl(&out),"source":"rustre_script_rhai::rotate_bytes_impl"}).to_string()))
    }
}

pub struct ScriptRhaiFindStringsWireTool;
impl ScriptRhaiFindStringsWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_find_strings".to_string(),
            description: "Extract printable ASCII strings of at least min_len chars via rustre_script_rhai::find_strings_in_blob.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"},"min_len":{"type":"integer"}},"required":["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiFindStringsWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let h = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let m = args.get("min_len").and_then(Value::as_u64).unwrap_or(4) as usize;
        let data = pe_editor_hex_decode(h)?;
        let arr = rustre_script_rhai::find_strings_in_blob(&data, m);
        let strs: Vec<String> = arr.iter().filter_map(|d| d.clone().try_cast::<String>()).collect();
        Ok(ToolResult::text(json!({"count":strs.len(),"strings":strs,"source":"rustre_script_rhai::find_strings_in_blob"}).to_string()))
    }
}

pub struct ScriptRhaiDetectFormatWireTool;
impl ScriptRhaiDetectFormatWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_detect_format".to_string(),
            description: "Detect binary format (PE/ELF/MachO/WASM/DEX) from magic bytes via rustre_script_rhai::detect_format.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiDetectFormatWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let h = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let data = pe_editor_hex_decode(h)?;
        Ok(ToolResult::text(json!({"format":rustre_script_rhai::detect_format(&data),"source":"rustre_script_rhai::detect_format"}).to_string()))
    }
}

pub struct ScriptRhaiDetectArchWireTool;
impl ScriptRhaiDetectArchWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_detect_arch".to_string(),
            description: "Detect architecture from binary magic bytes via rustre_script_rhai::detect_arch.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiDetectArchWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let h = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let data = pe_editor_hex_decode(h)?;
        Ok(ToolResult::text(json!({"arch":rustre_script_rhai::detect_arch(&data),"source":"rustre_script_rhai::detect_arch"}).to_string()))
    }
}

pub struct ScriptRhaiEntropyImplWireTool;
impl ScriptRhaiEntropyImplWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_entropy_impl".to_string(),
            description: "Compute Shannon entropy (bits/byte, 0.0-8.0) via rustre_script_rhai::entropy_impl.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiEntropyImplWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let h = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let data = pe_editor_hex_decode(h)?;
        let e = rustre_script_rhai::entropy_impl(&data);
        Ok(ToolResult::text(json!({"entropy":e,"len":data.len(),"source":"rustre_script_rhai::entropy_impl"}).to_string()))
    }
}

pub struct ScriptRhaiBinaryInfoWireTool;
impl ScriptRhaiBinaryInfoWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_binary_info".to_string(),
            description: "Return combined format+arch+entropy+sha256 for a byte blob using rustre-script-rhai primitives.".to_string(),
            input_schema: json!({"type":"object","properties":{"data_hex":{"type":"string"}},"required":["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiBinaryInfoWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let h = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let data = pe_editor_hex_decode(h)?;
        let e = rustre_script_rhai::entropy_impl(&data);
        Ok(ToolResult::text(json!({
            "size": data.len(),
            "format": rustre_script_rhai::detect_format(&data),
            "arch": rustre_script_rhai::detect_arch(&data),
            "entropy": e,
            "entropy_verdict": rustre_script_rhai::entropy_classify(e),
            "sha256": rustre_script_rhai::sha256_bytes_impl(&data),
            "source": "rustre_script_rhai::{detect_format,detect_arch,entropy_impl,sha256_bytes_impl}",
        }).to_string()))
    }
}

pub struct ScriptRhaiComputeEntropyV2Tool;
impl ScriptRhaiComputeEntropyV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_compute_entropy_v2".to_string(),
            description: "Shannon entropy over bytes via rustre_script_rhai::rhai_compute_entropy.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array"},"bytes_hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiComputeEntropyV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let h = rustre_script_rhai::rhai_compute_entropy(&data);
        Ok(ToolResult::text(json!({"entropy":h,"len":data.len(),"source":"rustre_script_rhai::rhai_compute_entropy"}).to_string()))
    }
}

pub struct ScriptRhaiMatchPatternTool;
impl ScriptRhaiMatchPatternTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_match_pattern".to_string(),
            description: "Match hex pattern (with ?? wildcards) via rustre_script_rhai::rhai_match_pattern.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array"},"bytes_hex":{"type":"string"},"pattern":{"type":"string"}},"required":["pattern"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiMatchPatternTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let pat = args.get("pattern").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let hits = rustre_script_rhai::rhai_match_pattern(&data, pat);
        Ok(ToolResult::text(json!({"count":hits.len(),"offsets":hits,"source":"rustre_script_rhai::rhai_match_pattern"}).to_string()))
    }
}

pub struct ScriptRhaiDetectFormatStaticTool;
impl ScriptRhaiDetectFormatStaticTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_detect_format_static".to_string(),
            description: "Detect binary format from magic via rustre_script_rhai::rhai_detect_format.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array"},"bytes_hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiDetectFormatStaticTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let fmt = rustre_script_rhai::rhai_detect_format(&data);
        Ok(ToolResult::text(json!({"format":fmt,"source":"rustre_script_rhai::rhai_detect_format"}).to_string()))
    }
}

pub struct ScriptRhaiLoadBinaryTool;
impl ScriptRhaiLoadBinaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_load_binary".to_string(),
            description: "Load a binary from disk into the legacy Rhai store via rustre_script_rhai::rhai_load_binary_impl.".to_string(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiLoadBinaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let id = rustre_script_rhai::rhai_load_binary_impl(path).map_err(|e| McpError::InvalidParams(format!("load_binary: {e}")))?;
        Ok(ToolResult::text(json!({"id":id,"source":"rustre_script_rhai::rhai_load_binary_impl"}).to_string()))
    }
}

pub struct ScriptRhaiGetInfoTool;
impl ScriptRhaiGetInfoTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_get_info".to_string(),
            description: "Fetch binary metadata by id from the legacy Rhai store via rustre_script_rhai::rhai_get_info_impl.".to_string(),
            input_schema: json!({"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiGetInfoTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let id = args.get("id").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'id'".into()))?;
        let m = rustre_script_rhai::rhai_get_info_impl(id);
        let format = m.get("format").and_then(|v| v.clone().try_cast::<String>()).unwrap_or_default();
        let arch = m.get("arch").and_then(|v| v.clone().try_cast::<String>()).unwrap_or_default();
        let size = m.get("size").and_then(|v| v.as_int().ok()).unwrap_or(0);
        let entry = m.get("entry_point").and_then(|v| v.as_int().ok()).unwrap_or(0);
        Ok(ToolResult::text(json!({"id":id,"format":format,"arch":arch,"size":size,"entry_point":entry,"source":"rustre_script_rhai::rhai_get_info_impl"}).to_string()))
    }
}

pub struct ScriptRhaiNewBinaryStoreTool;
impl ScriptRhaiNewBinaryStoreTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_new_binary_store".to_string(),
            description: "Construct an empty per-engine BinaryStore via rustre_script_rhai::new_binary_store; returns initial state.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiNewBinaryStoreTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_script_rhai::new_binary_store();
        let len = s.lock().map(|g| g.len()).unwrap_or(0);
        Ok(ToolResult::text(json!({"created":true,"initial_len":len,"source":"rustre_script_rhai::new_binary_store"}).to_string()))
    }
}

pub struct ScriptRhaiLoadBinaryIntoTool;
impl ScriptRhaiLoadBinaryIntoTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_load_binary_into".to_string(),
            description: "Load a binary into a fresh per-engine store via rustre_script_rhai::rhai_load_binary_into.".to_string(),
            input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiLoadBinaryIntoTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let store = rustre_script_rhai::new_binary_store();
        let id = rustre_script_rhai::rhai_load_binary_into(&store, path).map_err(|e| McpError::InvalidParams(format!("load: {e}")))?;
        let m = rustre_script_rhai::rhai_get_info_from(&store, &id);
        let size = m.get("size").and_then(|v| v.as_int().ok()).unwrap_or(0);
        Ok(ToolResult::text(json!({"id":id,"size":size,"source":"rustre_script_rhai::rhai_load_binary_into"}).to_string()))
    }
}

pub struct ScriptRhaiRhaiValueUnitTool;
impl ScriptRhaiRhaiValueUnitTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_rhai_value_is_unit".to_string(),
            description: "Construct a RhaiValue::Unit and report is_unit/display via rustre_script_rhai::RhaiValue.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiRhaiValueUnitTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let v = rustre_script_rhai::RhaiValue::Unit;
        Ok(ToolResult::text(json!({"is_unit":v.is_unit(),"display":v.to_string(),"source":"rustre_script_rhai::RhaiValue"}).to_string()))
    }
}

pub struct ScriptRhaiEventBusNewTool;
impl ScriptRhaiEventBusNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_event_bus_new".to_string(),
            description: "Construct an empty EventBus via rustre_script_rhai::EventBus::new; report handler count.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiEventBusNewTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let bus = rustre_script_rhai::EventBus::new();
        Ok(ToolResult::text(json!({"handler_count":bus.handler_count(),"registered_events":bus.registered_events(),"source":"rustre_script_rhai::EventBus::new"}).to_string()))
    }
}

pub struct ScriptRhaiEventHookSystemNewTool;
impl ScriptRhaiEventHookSystemNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_rhai_event_hook_system_new".to_string(),
            description: "Construct an empty EventHookSystem via rustre_script_rhai::EventHookSystem::new; report hook count.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRhaiEventHookSystemNewTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let h = rustre_script_rhai::EventHookSystem::new();
        Ok(ToolResult::text(json!({"hook_count":h.hook_count(),"source":"rustre_script_rhai::EventHookSystem::new"}).to_string()))
    }
}

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ScriptRhaiEntropyClassifyTool::definition(), Box::new(ScriptRhaiEntropyClassifyTool)),
        (ScriptRhaiHexEncodeTool::definition(), Box::new(ScriptRhaiHexEncodeTool)),
        (ScriptRhaiSha256BytesWireTool::definition(), Box::new(ScriptRhaiSha256BytesWireTool)),
        (ScriptRhaiHexDecodeWireTool::definition(), Box::new(ScriptRhaiHexDecodeWireTool)),
        (ScriptRhaiFindPatternWireTool::definition(), Box::new(ScriptRhaiFindPatternWireTool)),
        (ScriptRhaiXorBytesWireTool::definition(), Box::new(ScriptRhaiXorBytesWireTool)),
        (ScriptRhaiRotateBytesWireTool::definition(), Box::new(ScriptRhaiRotateBytesWireTool)),
        (ScriptRhaiFindStringsWireTool::definition(), Box::new(ScriptRhaiFindStringsWireTool)),
        (ScriptRhaiDetectFormatWireTool::definition(), Box::new(ScriptRhaiDetectFormatWireTool)),
        (ScriptRhaiDetectArchWireTool::definition(), Box::new(ScriptRhaiDetectArchWireTool)),
        (ScriptRhaiEntropyImplWireTool::definition(), Box::new(ScriptRhaiEntropyImplWireTool)),
        (ScriptRhaiBinaryInfoWireTool::definition(), Box::new(ScriptRhaiBinaryInfoWireTool)),
        (ScriptRhaiComputeEntropyV2Tool::definition(), Box::new(ScriptRhaiComputeEntropyV2Tool)),
        (ScriptRhaiMatchPatternTool::definition(), Box::new(ScriptRhaiMatchPatternTool)),
        (ScriptRhaiDetectFormatStaticTool::definition(), Box::new(ScriptRhaiDetectFormatStaticTool)),
        (ScriptRhaiLoadBinaryTool::definition(), Box::new(ScriptRhaiLoadBinaryTool)),
        (ScriptRhaiGetInfoTool::definition(), Box::new(ScriptRhaiGetInfoTool)),
        (ScriptRhaiNewBinaryStoreTool::definition(), Box::new(ScriptRhaiNewBinaryStoreTool)),
        (ScriptRhaiLoadBinaryIntoTool::definition(), Box::new(ScriptRhaiLoadBinaryIntoTool)),
        (ScriptRhaiRhaiValueUnitTool::definition(), Box::new(ScriptRhaiRhaiValueUnitTool)),
        (ScriptRhaiEventBusNewTool::definition(), Box::new(ScriptRhaiEventBusNewTool)),
        (ScriptRhaiEventHookSystemNewTool::definition(), Box::new(ScriptRhaiEventHookSystemNewTool)),
    ]
}
