//! MCP wrappers for the rustre-script crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes, hex_encode};
use crate::wire_tools::{script_read_helper_new, script_write_helper_new};

pub struct ScriptBuiltinHexToBytesTool;

pub struct ScriptBuiltinBytesToHexTool;

pub struct ScriptHexToBytesTool;

pub struct ScriptBytesToHexTool;

pub struct ScriptXorBytesTool;

pub struct ScriptBytesConcatTool;

pub struct ScriptBytesSliceTool;

pub struct ScriptBytesFindTool;

pub struct ScriptErrorIsRecoverableTool;

pub struct ScriptErrorRuntimeTool;

pub struct ScriptReadU32Tool;

pub struct ScriptBytesFillTool;

pub struct ScriptValueIsTruthyTool;
impl ScriptValueIsTruthyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_value_is_truthy".to_string(),
            description: "Evaluate truthiness of a JSON value via ScriptValue::is_truthy.".to_string(),
            input_schema: json!({"type":"object","required":["value"],"properties":{"value":{}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptValueIsTruthyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").cloned().unwrap_or(Value::Null);
        let sv = rustre_script::ScriptValue::from_json(v);
        Ok(ToolResult::text(json!({
            "truthy": sv.is_truthy(),
            "type": sv.type_name(),
            "source": "rustre_script::ScriptValue::is_truthy"
        }).to_string()))
    }
}

pub struct ScriptValueDisplayTool;
impl ScriptValueDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_value_display".to_string(),
            description: "Format a JSON value as ScriptValue::to_display_string.".to_string(),
            input_schema: json!({"type":"object","required":["value"],"properties":{"value":{}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptValueDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").cloned().unwrap_or(Value::Null);
        let sv = rustre_script::ScriptValue::from_json(v);
        Ok(ToolResult::text(json!({
            "display": sv.to_display_string(),
            "type": sv.type_name(),
            "source": "rustre_script::ScriptValue::to_display_string"
        }).to_string()))
    }
}

pub struct ScriptValueTypeofNativeTool;
impl ScriptValueTypeofNativeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_value_typeof_native".to_string(),
            description: "Call builtin_typeof on a JSON value.".to_string(),
            input_schema: json!({"type":"object","required":["value"],"properties":{"value":{}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptValueTypeofNativeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").cloned().unwrap_or(Value::Null);
        let sv = rustre_script::ScriptValue::from_json(v);
        let out = rustre_script::builtin_typeof(&[sv]).map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "type": out.to_display_string(),
            "source": "rustre_script::builtin_typeof"
        }).to_string()))
    }
}

pub struct ScriptValueLenBuiltinTool;
impl ScriptValueLenBuiltinTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_value_len_builtin".to_string(),
            description: "Call builtin_len on a JSON collection value.".to_string(),
            input_schema: json!({"type":"object","required":["value"],"properties":{"value":{}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptValueLenBuiltinTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").cloned().unwrap_or(Value::Null);
        let sv = rustre_script::ScriptValue::from_json(v);
        let out = rustre_script::builtin_len(&[sv]).map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "len": out.as_int().unwrap_or(0),
            "source": "rustre_script::builtin_len"
        }).to_string()))
    }
}

pub struct ScriptReModuleInfoTool;
impl ScriptReModuleInfoTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_re_module_info".to_string(),
            description: "Return function and constant names exported by re_module().".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptReModuleInfoTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let m = rustre_script::re_module();
        let mut fns: Vec<String> = m.functions.keys().cloned().collect();
        fns.sort();
        let mut consts: Vec<String> = m.constants.keys().cloned().collect();
        consts.sort();
        Ok(ToolResult::text(json!({
            "name": m.name,
            "functions": fns,
            "constants": consts,
            "symbol_count": m.symbol_count(),
            "source": "rustre_script::re_module"
        }).to_string()))
    }
}

pub struct ScriptSandboxPolicyPresetTool;
impl ScriptSandboxPolicyPresetTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_sandbox_policy_preset".to_string(),
            description: "Return a SandboxPolicy preset (deny_all|allow_all|read_only).".to_string(),
            input_schema: json!({"type":"object","required":["preset"],"properties":{"preset":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptSandboxPolicyPresetTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let p = args.get("preset").and_then(Value::as_str).unwrap_or("deny_all");
        let policy = match p {
            "allow_all" => rustre_script::SandboxPolicy::allow_all(),
            "read_only" => rustre_script::SandboxPolicy::read_only(),
            _ => rustre_script::SandboxPolicy::deny_all(),
        };
        Ok(ToolResult::text(json!({
            "preset": p,
            "allow_fs_read": policy.allow_fs_read,
            "allow_fs_write": policy.allow_fs_write,
            "allow_network": policy.allow_network,
            "allow_subprocess": policy.allow_subprocess,
            "max_time_ms": policy.max_time_ms,
            "max_call_depth": policy.max_call_depth,
            "source": "rustre_script::SandboxPolicy"
        }).to_string()))
    }
}

pub struct ScriptVariableFrameProbeTool;
impl ScriptVariableFrameProbeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_variable_frame_probe".to_string(),
            description: "Bind name->int in root frame, create child, assign, lookup.".to_string(),
            input_schema: json!({"type":"object","required":["name","value","new_value"],"properties":{
                "name":{"type":"string"},"value":{"type":"integer"},"new_value":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptVariableFrameProbeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let v = args.get("value").and_then(Value::as_i64).unwrap_or(0);
        let nv = args.get("new_value").and_then(Value::as_i64).unwrap_or(0);
        let mut root = rustre_script::VariableFrame::root();
        root.bind(name, rustre_script::ScriptValue::Int(v));
        let mut child = rustre_script::VariableFrame::child(root);
        let assigned = child.assign(name, rustre_script::ScriptValue::Int(nv));
        let looked = child.lookup(name).map(rustre_script::ScriptValue::to_display_string);
        Ok(ToolResult::text(json!({
            "assigned": assigned,
            "lookup": looked,
            "local_count": child.local_count(),
            "source": "rustre_script::VariableFrame"
        }).to_string()))
    }
}

pub struct ScriptPipelineStepLabelTool;
impl ScriptPipelineStepLabelTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_pipeline_step_label".to_string(),
            description: "Build a PipelineStep with label and echo fields.".to_string(),
            input_schema: json!({"type":"object","required":["engine","code"],"properties":{
                "engine":{"type":"string"},"code":{"type":"string"},"label":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptPipelineStepLabelTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let engine = args.get("engine").and_then(Value::as_str).unwrap_or("rhai").to_string();
        let code = args.get("code").and_then(Value::as_str).unwrap_or("").to_string();
        let label = args.get("label").and_then(Value::as_str).map(str::to_string);
        let mut step = rustre_script::PipelineStep::new(engine, code);
        if let Some(l) = label { step = step.with_label(l); }
        Ok(ToolResult::text(json!({
            "engine": step.engine_name,
            "code_len": step.code.len(),
            "label": step.label,
            "source": "rustre_script::PipelineStep"
        }).to_string()))
    }
}

pub struct ScriptCompiledUnitInfoTool;
impl ScriptCompiledUnitInfoTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_compiled_unit_info".to_string(),
            description: "Construct a CompiledScript, add a warning, report its fields.".to_string(),
            input_schema: json!({"type":"object","required":["engine","source"],"properties":{
                "engine":{"type":"string"},"source":{"type":"string"},"warning":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptCompiledUnitInfoTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let engine = args.get("engine").and_then(Value::as_str).unwrap_or("rhai").to_string();
        let source = args.get("source").and_then(Value::as_str).unwrap_or("").to_string();
        let mut cs = rustre_script::CompiledScript::new(engine, source);
        if let Some(w) = args.get("warning").and_then(Value::as_str) {
            cs.add_warning(w);
        }
        Ok(ToolResult::text(json!({
            "engine": cs.engine_name,
            "is_empty": cs.is_empty(),
            "warnings": cs.warnings,
            "source_ref": "rustre_script::CompiledScript"
        }).to_string()))
    }
}

pub struct ScriptRegistryListTool;
impl ScriptRegistryListTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_registry_list".to_string(),
            description: "Return the (empty) list of engines from a fresh ScriptEngineRegistry.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptRegistryListTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let reg = rustre_script::ScriptEngineRegistry::new();
        Ok(ToolResult::text(json!({
            "count": reg.count(),
            "engines": reg.list_engines(),
            "source": "rustre_script::ScriptEngineRegistry"
        }).to_string()))
    }
}

pub struct ScriptResultFailureTool;
impl ScriptResultFailureTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_result_failure".to_string(),
            description: "Build a failing ScriptResult and report has_errors + stderr join.".to_string(),
            input_schema: json!({"type":"object","required":["message"],"properties":{"message":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptResultFailureTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let msg = args.get("message").and_then(Value::as_str).unwrap_or("error");
        let r = rustre_script::ScriptResult::failure(msg);
        Ok(ToolResult::text(json!({
            "success": r.success,
            "has_errors": r.has_errors(),
            "stderr": r.stderr_joined(),
            "source": "rustre_script::ScriptResult::failure"
        }).to_string()))
    }
}

pub struct ScriptBytesFillCheckedTool;
impl ScriptBytesFillCheckedTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_bytes_fill_checked".to_string(),
            description: "Invoke builtin_bytes_fill and return length + first bytes.".to_string(),
            input_schema: json!({"type":"object","required":["count","byte"],"properties":{
                "count":{"type":"integer"},"byte":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptBytesFillCheckedTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let count = args.get("count").and_then(Value::as_i64).unwrap_or(0);
        let byte = args.get("byte").and_then(Value::as_i64).unwrap_or(0);
        let out = rustre_script::builtin_bytes_fill(&[
            rustre_script::ScriptValue::Int(count),
            rustre_script::ScriptValue::Int(byte),
        ]).map_err(|e| McpError::InternalError(e.to_string()))?;
        let b = out.as_bytes().map_err(|e| McpError::InternalError(e.to_string()))?;
        let preview: Vec<u8> = b.iter().take(16).copied().collect();
        Ok(ToolResult::text(json!({
            "len": b.len(),
            "preview": preview,
            "source": "rustre_script::builtin_bytes_fill"
        }).to_string()))
    }
}

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ScriptBuiltinHexToBytesTool::definition(), Box::new(ScriptBuiltinHexToBytesTool)),
        (ScriptBuiltinBytesToHexTool::definition(), Box::new(ScriptBuiltinBytesToHexTool)),
        (ScriptHexToBytesTool::definition(), Box::new(ScriptHexToBytesTool)),
        (ScriptBytesToHexTool::definition(), Box::new(ScriptBytesToHexTool)),
        (ScriptXorBytesTool::definition(), Box::new(ScriptXorBytesTool)),
        (ScriptBytesConcatTool::definition(), Box::new(ScriptBytesConcatTool)),
        (ScriptBytesSliceTool::definition(), Box::new(ScriptBytesSliceTool)),
        (ScriptBytesFindTool::definition(), Box::new(ScriptBytesFindTool)),
        (ScriptErrorIsRecoverableTool::definition(), Box::new(ScriptErrorIsRecoverableTool)),
        (ScriptErrorRuntimeTool::definition(), Box::new(ScriptErrorRuntimeTool)),
        (ScriptReadU32Tool::definition(), Box::new(ScriptReadU32Tool)),
        (ScriptBytesFillTool::definition(), Box::new(ScriptBytesFillTool)),
        (ScriptValueIsTruthyTool::definition(), Box::new(ScriptValueIsTruthyTool)),
        (ScriptValueDisplayTool::definition(), Box::new(ScriptValueDisplayTool)),
        (ScriptValueTypeofNativeTool::definition(), Box::new(ScriptValueTypeofNativeTool)),
        (ScriptValueLenBuiltinTool::definition(), Box::new(ScriptValueLenBuiltinTool)),
        (ScriptReModuleInfoTool::definition(), Box::new(ScriptReModuleInfoTool)),
        (ScriptSandboxPolicyPresetTool::definition(), Box::new(ScriptSandboxPolicyPresetTool)),
        (ScriptVariableFrameProbeTool::definition(), Box::new(ScriptVariableFrameProbeTool)),
        (ScriptPipelineStepLabelTool::definition(), Box::new(ScriptPipelineStepLabelTool)),
        (ScriptCompiledUnitInfoTool::definition(), Box::new(ScriptCompiledUnitInfoTool)),
        (ScriptRegistryListTool::definition(), Box::new(ScriptRegistryListTool)),
        (ScriptResultFailureTool::definition(), Box::new(ScriptResultFailureTool)),
        (ScriptBytesFillCheckedTool::definition(), Box::new(ScriptBytesFillCheckedTool)),
    ]
}

pub struct ScriptReadU8ToolNew;
impl ScriptReadU8ToolNew {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "script_read_u8_new".to_string(), description: "Read u8 via rustre-script `read_u8`.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"offset":{"type":"integer"}},"required":["offset"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for ScriptReadU8ToolNew {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (v, d, off) = script_read_helper_new(&args, rustre_script::builtin_read_u8, "read_u8")?;
        Ok(ToolResult::text(json!({"value":v,"offset":off,"len":d.len(),"source":"rustre_script::builtin_read_u8"}).to_string()))
    }
}

pub struct ScriptReadU16ToolNew;
impl ScriptReadU16ToolNew {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "script_read_u16_new".to_string(), description: "Read LE u16 via rustre-script `read_u16`.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"offset":{"type":"integer"}},"required":["offset"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for ScriptReadU16ToolNew {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (v, d, off) = script_read_helper_new(&args, rustre_script::builtin_read_u16, "read_u16")?;
        Ok(ToolResult::text(json!({"value":v,"offset":off,"len":d.len(),"source":"rustre_script::builtin_read_u16"}).to_string()))
    }
}

pub struct ScriptReadU32BeToolNew;
impl ScriptReadU32BeToolNew {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "script_read_u32_be_new".to_string(), description: "Read BE u32 via rustre-script `read_u32_be`.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"offset":{"type":"integer"}},"required":["offset"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for ScriptReadU32BeToolNew {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (v, d, off) = script_read_helper_new(&args, rustre_script::builtin_read_u32_be, "read_u32_be")?;
        Ok(ToolResult::text(json!({"value":v,"offset":off,"len":d.len(),"source":"rustre_script::builtin_read_u32_be"}).to_string()))
    }
}

pub struct ScriptReadU64ToolNew;
impl ScriptReadU64ToolNew {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "script_read_u64_new".to_string(), description: "Read LE u64 via rustre-script `read_u64`.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"offset":{"type":"integer"}},"required":["offset"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for ScriptReadU64ToolNew {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let off = args.get("offset").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("missing 'offset'".into()))?;
        let sv = rustre_script::builtin_read_u64(&[rustre_script::ScriptValue::Bytes(data.clone()), rustre_script::ScriptValue::Int(off)])
            .map_err(|e| McpError::InvalidParams(e.to_string()))?;
        let addr = match sv { rustre_script::ScriptValue::Address(a) => a, other => return Err(McpError::InternalError(format!("read_u64 returned {}", other.type_name()))) };
        Ok(ToolResult::text(json!({"value":addr,"value_hex":format!("0x{addr:x}"),"offset":off,"len":data.len(),"source":"rustre_script::builtin_read_u64"}).to_string()))
    }
}

pub struct ScriptWriteU8ToolNew;
impl ScriptWriteU8ToolNew {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "script_write_u8_new".to_string(), description: "Write u8 via rustre-script `write_u8`.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"offset":{"type":"integer"},"value":{"type":"integer"}},"required":["offset","value"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for ScriptWriteU8ToolNew {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (b, off) = script_write_helper_new(&args, rustre_script::builtin_write_u8, "write_u8")?;
        Ok(ToolResult::text(json!({"bytes_hex":hex_encode(&b),"len":b.len(),"offset":off,"source":"rustre_script::builtin_write_u8"}).to_string()))
    }
}

pub struct ScriptWriteU16ToolNew;
impl ScriptWriteU16ToolNew {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "script_write_u16_new".to_string(), description: "Write LE u16 via rustre-script `write_u16`.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"offset":{"type":"integer"},"value":{"type":"integer"}},"required":["offset","value"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for ScriptWriteU16ToolNew {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (b, off) = script_write_helper_new(&args, rustre_script::builtin_write_u16, "write_u16")?;
        Ok(ToolResult::text(json!({"bytes_hex":hex_encode(&b),"len":b.len(),"offset":off,"source":"rustre_script::builtin_write_u16"}).to_string()))
    }
}

pub struct ScriptWriteU32ToolNew;
impl ScriptWriteU32ToolNew {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "script_write_u32_new".to_string(), description: "Write LE u32 via rustre-script `write_u32`.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"offset":{"type":"integer"},"value":{"type":"integer"}},"required":["offset","value"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for ScriptWriteU32ToolNew {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (b, off) = script_write_helper_new(&args, rustre_script::builtin_write_u32, "write_u32")?;
        Ok(ToolResult::text(json!({"bytes_hex":hex_encode(&b),"len":b.len(),"offset":off,"source":"rustre_script::builtin_write_u32"}).to_string()))
    }
}

pub struct ScriptWriteU64ToolNew;
impl ScriptWriteU64ToolNew {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "script_write_u64_new".to_string(), description: "Write LE u64 via rustre-script `write_u64`.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"offset":{"type":"integer"},"value":{"type":"integer"}},"required":["offset","value"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for ScriptWriteU64ToolNew {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (b, off) = script_write_helper_new(&args, rustre_script::builtin_write_u64, "write_u64")?;
        Ok(ToolResult::text(json!({"bytes_hex":hex_encode(&b),"len":b.len(),"offset":off,"source":"rustre_script::builtin_write_u64"}).to_string()))
    }
}

pub struct ScriptValueTypeofToolNew;
impl ScriptValueTypeofToolNew {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "script_value_typeof_new".to_string(), description: "Return ScriptValue type name for a JSON value.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{}},"required":["value"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for ScriptValueTypeofToolNew {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let sv = rustre_script::ScriptValue::from_json(args.get("value").cloned().unwrap_or(Value::Null));
        Ok(ToolResult::text(json!({"type":sv.type_name(),"source":"rustre_script::ScriptValue::type_name"}).to_string()))
    }
}

pub struct ScriptValueLenToolNew;
impl ScriptValueLenToolNew {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "script_value_len_new".to_string(), description: "Length of a collection ScriptValue via `builtin_len`.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{}},"required":["value"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for ScriptValueLenToolNew {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let sv = rustre_script::ScriptValue::from_json(args.get("value").cloned().unwrap_or(Value::Null));
        let out = rustre_script::builtin_len(&[sv]).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        let n = match out { rustre_script::ScriptValue::Int(n) => n, _ => 0 };
        Ok(ToolResult::text(json!({"len":n,"source":"rustre_script::builtin_len"}).to_string()))
    }
}

pub struct ScriptValueToStringToolNew;
impl ScriptValueToStringToolNew {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "script_value_to_string_new".to_string(), description: "Convert any ScriptValue to display string.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{}},"required":["value"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for ScriptValueToStringToolNew {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let sv = rustre_script::ScriptValue::from_json(args.get("value").cloned().unwrap_or(Value::Null));
        let out = rustre_script::builtin_to_string(&[sv]).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        let s = match out { rustre_script::ScriptValue::String(s) => s, _ => String::new() };
        Ok(ToolResult::text(json!({"string":s,"source":"rustre_script::builtin_to_string"}).to_string()))
    }
}

pub struct ScriptValueIsTruthyToolNew;
impl ScriptValueIsTruthyToolNew {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "script_value_is_truthy_new".to_string(), description: "Return whether a ScriptValue is truthy.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{}},"required":["value"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for ScriptValueIsTruthyToolNew {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let sv = rustre_script::ScriptValue::from_json(args.get("value").cloned().unwrap_or(Value::Null));
        Ok(ToolResult::text(json!({"truthy":sv.is_truthy(),"type":sv.type_name(),"source":"rustre_script::ScriptValue::is_truthy"}).to_string()))
    }
}

pub struct ScriptBuiltinFunctionsListToolNew;
impl ScriptBuiltinFunctionsListToolNew {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "script_builtin_functions_list_new".to_string(), description: "List all rustre-script builtin function names.".to_string(),
            input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for ScriptBuiltinFunctionsListToolNew {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let map = rustre_script::builtin_functions();
        let mut names: Vec<String> = map.keys().cloned().collect();
        names.sort();
        Ok(ToolResult::text(json!({"count":names.len(),"names":names,"source":"rustre_script::builtin_functions"}).to_string()))
    }
}

pub struct ScriptSandboxPolicyPresetToolNew;
impl ScriptSandboxPolicyPresetToolNew {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "script_sandbox_policy_preset_new".to_string(), description: "Return a SandboxPolicy preset: deny_all|allow_all|read_only.".to_string(),
            input_schema: json!({"type":"object","properties":{"preset":{"type":"string"}},"required":["preset"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for ScriptSandboxPolicyPresetToolNew {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let preset = args.get("preset").and_then(Value::as_str).unwrap_or("deny_all");
        let p = match preset {
            "allow_all" => rustre_script::SandboxPolicy::allow_all(),
            "read_only" => rustre_script::SandboxPolicy::read_only(),
            _ => rustre_script::SandboxPolicy::deny_all(),
        };
        Ok(ToolResult::text(json!({"preset":preset,"policy":serde_json::to_value(&p).unwrap_or(Value::Null),"source":"rustre_script::SandboxPolicy"}).to_string()))
    }
}
