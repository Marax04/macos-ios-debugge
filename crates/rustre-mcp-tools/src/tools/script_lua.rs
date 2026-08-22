//! MCP wrappers for the rustre-script_lua crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{hex_encode};
use crate::wire_tools::{extract_byte_array};

pub struct ScriptLuaCastsU64ToI64Tool;

pub struct ScriptLuaCastsUsizeToI64Tool;

pub struct ScriptLuaCalculateEntropyTool;

pub struct ScriptLuaNopSledTool;

pub struct ScriptLuaCastsI64ToU64Tool;
impl ScriptLuaCastsI64ToU64Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_casts_i64_to_u64".to_string(),
            description: "Reinterpret an i64 bit-pattern as u64 via rustre_script_lua::casts::i64_to_u64.".to_string(),
            input_schema: json!({"type":"object","required":["value"],"properties":{"value":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaCastsI64ToU64Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_i64)
            .ok_or_else(|| McpError::InvalidParams("value: missing/not integer".into()))?;
        let out = rustre_script_lua::casts::i64_to_u64(v);
        Ok(ToolResult::text(json!({"input":v,"output":out,"source":"rustre_script_lua::casts::i64_to_u64"}).to_string()))
    }
}

pub struct ScriptLuaCastsU64ToF64Tool;
impl ScriptLuaCastsU64ToF64Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_casts_u64_to_f64".to_string(),
            description: "Convert a u64 to f64 via rustre_script_lua::casts::u64_to_f64.".to_string(),
            input_schema: json!({"type":"object","required":["value"],"properties":{"value":{"type":"integer","minimum":0}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaCastsU64ToF64Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("value: missing/not u64".into()))?;
        let out = rustre_script_lua::casts::u64_to_f64(v);
        Ok(ToolResult::text(json!({"input":v,"output":out,"source":"rustre_script_lua::casts::u64_to_f64"}).to_string()))
    }
}

pub struct ScriptLuaCastsI64ToF64Tool;
impl ScriptLuaCastsI64ToF64Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_casts_i64_to_f64".to_string(),
            description: "Convert an i64 to f64 via rustre_script_lua::casts::i64_to_f64.".to_string(),
            input_schema: json!({"type":"object","required":["value"],"properties":{"value":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaCastsI64ToF64Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_i64)
            .ok_or_else(|| McpError::InvalidParams("value: missing/not integer".into()))?;
        let out = rustre_script_lua::casts::i64_to_f64(v);
        Ok(ToolResult::text(json!({"input":v,"output":out,"source":"rustre_script_lua::casts::i64_to_f64"}).to_string()))
    }
}

pub struct ScriptLuaCastsF64ToI64Tool;
impl ScriptLuaCastsF64ToI64Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_casts_f64_to_i64".to_string(),
            description: "Truncate an f64 to i64 with saturation via rustre_script_lua::casts::f64_to_i64.".to_string(),
            input_schema: json!({"type":"object","required":["value"],"properties":{"value":{"type":"number"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaCastsF64ToI64Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_f64)
            .ok_or_else(|| McpError::InvalidParams("value: missing/not number".into()))?;
        let out = rustre_script_lua::casts::f64_to_i64(v);
        Ok(ToolResult::text(json!({"input":v,"output":out,"source":"rustre_script_lua::casts::f64_to_i64"}).to_string()))
    }
}

pub struct ScriptLuaCastsUsizeToF64Tool;
impl ScriptLuaCastsUsizeToF64Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_casts_usize_to_f64".to_string(),
            description: "Convert a usize to f64 via rustre_script_lua::casts::usize_to_f64.".to_string(),
            input_schema: json!({"type":"object","required":["value"],"properties":{"value":{"type":"integer","minimum":0}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaCastsUsizeToF64Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("value: missing/not u64".into()))?;
        let out = rustre_script_lua::casts::usize_to_f64(v as usize);
        Ok(ToolResult::text(json!({"input":v,"output":out,"source":"rustre_script_lua::casts::usize_to_f64"}).to_string()))
    }
}

pub struct ScriptLuaCastsI64ToU32Tool;
impl ScriptLuaCastsI64ToU32Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_casts_i64_to_u32".to_string(),
            description: "Keep the low 32 bits of an i64 as u32 via rustre_script_lua::casts::i64_to_u32.".to_string(),
            input_schema: json!({"type":"object","required":["value"],"properties":{"value":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaCastsI64ToU32Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_i64)
            .ok_or_else(|| McpError::InvalidParams("value: missing/not integer".into()))?;
        let out = rustre_script_lua::casts::i64_to_u32(v);
        Ok(ToolResult::text(json!({"input":v,"output":out,"source":"rustre_script_lua::casts::i64_to_u32"}).to_string()))
    }
}

pub struct ScriptLuaCastsI64ToI32Tool;
impl ScriptLuaCastsI64ToI32Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_casts_i64_to_i32".to_string(),
            description: "Keep the low 32 bits of an i64 reinterpreted as i32 via rustre_script_lua::casts::i64_to_i32.".to_string(),
            input_schema: json!({"type":"object","required":["value"],"properties":{"value":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaCastsI64ToI32Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_i64)
            .ok_or_else(|| McpError::InvalidParams("value: missing/not integer".into()))?;
        let out = rustre_script_lua::casts::i64_to_i32(v);
        Ok(ToolResult::text(json!({"input":v,"output":out,"source":"rustre_script_lua::casts::i64_to_i32"}).to_string()))
    }
}

pub struct ScriptLuaExecuteScriptTool;
impl ScriptLuaExecuteScriptTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_execute_script".to_string(),
            description: "Execute a sandboxed Lua-like script via rustre_script_lua::LuaEngine::execute and return the captured print output plus final value.".to_string(),
            input_schema: json!({"type":"object","required":["script"],"properties":{"script":{"type":"string"},"max_steps":{"type":"integer","minimum":1}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaExecuteScriptTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let script = args.get("script").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("script: missing/not string".into()))?;
        let mut engine = rustre_script_lua::LuaEngine::new();
        if let Some(n) = args.get("max_steps").and_then(Value::as_u64) {
            engine.set_max_steps(n);
        }
        let mut ctx = rustre_script_lua::LuaContext::new();
        match engine.execute(script, &mut ctx) {
            Ok(v) => Ok(ToolResult::text(json!({
                "ok": true,
                "result": v.to_string(),
                "type": v.type_name(),
                "output": ctx.output_text(),
                "steps": engine.step_count(),
                "source": "rustre_script_lua::LuaEngine::execute",
            }).to_string())),
            Err(e) => Ok(ToolResult::text(json!({
                "ok": false,
                "error": e.to_string(),
                "output": ctx.output_text(),
                "source": "rustre_script_lua::LuaEngine::execute",
            }).to_string())),
        }
    }
}

pub struct ScriptLuaMatchHexPatternTool;
impl ScriptLuaMatchHexPatternTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_match_hex_pattern".to_string(),
            description: "Match a hex pattern (with '?' wildcards) against bytes via rustre_script_lua::lua_match_hex_pattern.".to_string(),
            input_schema: json!({"type":"object","properties":{"data":{"type":"array"},"data_hex":{"type":"string"},"pattern":{"type":"string"}},"required":["pattern"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaMatchHexPatternTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "data", "data_hex")?;
        let pattern = args.get("pattern").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let hits = rustre_script_lua::lua_match_hex_pattern(&data, pattern);
        let count = hits.len();
        Ok(ToolResult::text(json!({"hits":hits,"count":count,"source":"rustre_script_lua::lua_match_hex_pattern"}).to_string()))
    }
}

pub struct ScriptLuaDetectFormatTool;
impl ScriptLuaDetectFormatTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_detect_format".to_string(),
            description: "Detect binary format from magic bytes via rustre_script_lua::lua_detect_format.".to_string(),
            input_schema: json!({"type":"object","properties":{"data":{"type":"array"},"data_hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaDetectFormatTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = extract_byte_array(&args, "data", "data_hex")?;
        let fmt = rustre_script_lua::lua_detect_format(&data);
        Ok(ToolResult::text(json!({"format":fmt,"source":"rustre_script_lua::lua_detect_format"}).to_string()))
    }
}

pub struct ScriptLuaJmpPatchTool;
impl ScriptLuaJmpPatchTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_jmp_patch".to_string(),
            description: "Build a relative jump patch from `from` to `to` via rustre_script_lua::lua_jmp_patch.".to_string(),
            input_schema: json!({"type":"object","properties":{"from":{"type":"integer"},"to":{"type":"integer"}},"required":["from","to"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaJmpPatchTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let from = args.get("from").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'from'".into()))?;
        let to = args.get("to").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'to'".into()))?;
        let bytes = rustre_script_lua::lua_jmp_patch(from, to);
        Ok(ToolResult::text(json!({
            "ok": bytes.is_some(),
            "bytes_hex": bytes.as_ref().map(|b| hex_encode(b)),
            "len": bytes.as_ref().map(|b| b.len()),
            "source": "rustre_script_lua::lua_jmp_patch",
        }).to_string()))
    }
}

pub struct ScriptLuaRetPatchTool;
impl ScriptLuaRetPatchTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_ret_patch".to_string(),
            description: "Return the ret patch bytes via rustre_script_lua::lua_ret_patch.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaRetPatchTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let bytes = rustre_script_lua::lua_ret_patch();
        Ok(ToolResult::text(json!({"bytes_hex":hex_encode(&bytes),"len":bytes.len(),"source":"rustre_script_lua::lua_ret_patch"}).to_string()))
    }
}

pub struct ScriptLuaCastsI64ToUsizeTool;
impl ScriptLuaCastsI64ToUsizeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_casts_i64_to_usize".to_string(),
            description: "Saturating cast i64 -> usize via rustre_script_lua::casts::i64_to_usize.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{"type":"integer"}},"required":["value"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaCastsI64ToUsizeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let out = rustre_script_lua::casts::i64_to_usize(v);
        Ok(ToolResult::text(json!({"input":v,"output":out,"source":"rustre_script_lua::casts::i64_to_usize"}).to_string()))
    }
}

pub struct ScriptLuaCastsU64ToUsizeTool;
impl ScriptLuaCastsU64ToUsizeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_casts_u64_to_usize".to_string(),
            description: "Saturating cast u64 -> usize via rustre_script_lua::casts::u64_to_usize.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{"type":"integer"}},"required":["value"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaCastsU64ToUsizeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let out = rustre_script_lua::casts::u64_to_usize(v);
        Ok(ToolResult::text(json!({"input":v,"output":out,"source":"rustre_script_lua::casts::u64_to_usize"}).to_string()))
    }
}

pub struct ScriptLuaTemplateFindXrefsTool;
impl ScriptLuaTemplateFindXrefsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_template_find_xrefs".to_string(),
            description: "Render the find_xrefs Lua template via rustre_script_lua::LuaScriptTemplate::find_xrefs.".to_string(),
            input_schema: json!({"type":"object","properties":{"target":{"type":"integer"}},"required":["target"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaTemplateFindXrefsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let target = args.get("target").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'target'".into()))?;
        let script = rustre_script_lua::LuaScriptTemplate::find_xrefs(target);
        Ok(ToolResult::text(json!({"script":script,"source":"rustre_script_lua::LuaScriptTemplate::find_xrefs"}).to_string()))
    }
}

pub struct ScriptLuaTemplateExtractStringsTool;
impl ScriptLuaTemplateExtractStringsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_template_extract_strings".to_string(),
            description: "Render the extract_strings Lua template via rustre_script_lua::LuaScriptTemplate::extract_strings.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaTemplateExtractStringsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let script = rustre_script_lua::LuaScriptTemplate::extract_strings();
        Ok(ToolResult::text(json!({"script":script,"source":"rustre_script_lua::LuaScriptTemplate::extract_strings"}).to_string()))
    }
}

pub struct ScriptLuaTemplateDumpFunctionsTool;
impl ScriptLuaTemplateDumpFunctionsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_template_dump_functions".to_string(),
            description: "Render the dump_functions Lua template via rustre_script_lua::LuaScriptTemplate::dump_functions.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaTemplateDumpFunctionsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let script = rustre_script_lua::LuaScriptTemplate::dump_functions();
        Ok(ToolResult::text(json!({"script":script,"source":"rustre_script_lua::LuaScriptTemplate::dump_functions"}).to_string()))
    }
}

pub struct ScriptLuaTemplateRenameFunctionsTool;
impl ScriptLuaTemplateRenameFunctionsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_template_rename_functions".to_string(),
            description: "Render the rename_functions Lua template via rustre_script_lua::LuaScriptTemplate::rename_functions.".to_string(),
            input_schema: json!({"type":"object","properties":{"old_prefix":{"type":"string"},"new_prefix":{"type":"string"}},"required":["old_prefix","new_prefix"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaTemplateRenameFunctionsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let old = args.get("old_prefix").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'old_prefix'".into()))?;
        let new_p = args.get("new_prefix").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'new_prefix'".into()))?;
        let script = rustre_script_lua::LuaScriptTemplate::rename_functions(old, new_p);
        Ok(ToolResult::text(json!({"script":script,"source":"rustre_script_lua::LuaScriptTemplate::rename_functions"}).to_string()))
    }
}

pub struct ScriptLuaTemplatePatchPatternTool;
impl ScriptLuaTemplatePatchPatternTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_template_patch_pattern".to_string(),
            description: "Render the patch_pattern Lua template via rustre_script_lua::LuaScriptTemplate::patch_pattern.".to_string(),
            input_schema: json!({"type":"object","properties":{"from":{"type":"array"},"from_hex":{"type":"string"},"to":{"type":"array"},"to_hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaTemplatePatchPatternTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let from = extract_byte_array(&args, "from", "from_hex")?;
        let to = extract_byte_array(&args, "to", "to_hex")?;
        let script = rustre_script_lua::LuaScriptTemplate::patch_pattern(&from, &to);
        Ok(ToolResult::text(json!({"script":script,"source":"rustre_script_lua::LuaScriptTemplate::patch_pattern"}).to_string()))
    }
}

pub struct ScriptLuaContextOutputTextTool;
impl ScriptLuaContextOutputTextTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "script_lua_context_output_text".to_string(),
            description: "Execute a Lua script and return the captured print output via LuaContext::output_text.".to_string(),
            input_schema: json!({"type":"object","properties":{"script":{"type":"string"},"max_steps":{"type":"integer"}},"required":["script"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ScriptLuaContextOutputTextTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let script = args.get("script").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'script'".into()))?;
        let mut engine = rustre_script_lua::LuaEngine::new();
        if let Some(n) = args.get("max_steps").and_then(Value::as_u64) {
            engine.set_max_steps(n);
        }
        let mut ctx = rustre_script_lua::LuaContext::new();
        let result = engine.execute(script, &mut ctx);
        let ok = result.is_ok();
        let err = result.as_ref().err().map(|e| e.to_string());
        Ok(ToolResult::text(json!({
            "ok": ok,
            "error": err,
            "output": ctx.output_text(),
            "steps": engine.step_count(),
            "source": "rustre_script_lua::LuaContext::output_text",
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ScriptLuaCastsU64ToI64Tool::definition(), Box::new(ScriptLuaCastsU64ToI64Tool)),
        (ScriptLuaCastsUsizeToI64Tool::definition(), Box::new(ScriptLuaCastsUsizeToI64Tool)),
        (ScriptLuaCalculateEntropyTool::definition(), Box::new(ScriptLuaCalculateEntropyTool)),
        (ScriptLuaNopSledTool::definition(), Box::new(ScriptLuaNopSledTool)),
        (ScriptLuaCastsI64ToU64Tool::definition(), Box::new(ScriptLuaCastsI64ToU64Tool)),
        (ScriptLuaCastsU64ToF64Tool::definition(), Box::new(ScriptLuaCastsU64ToF64Tool)),
        (ScriptLuaCastsI64ToF64Tool::definition(), Box::new(ScriptLuaCastsI64ToF64Tool)),
        (ScriptLuaCastsF64ToI64Tool::definition(), Box::new(ScriptLuaCastsF64ToI64Tool)),
        (ScriptLuaCastsUsizeToF64Tool::definition(), Box::new(ScriptLuaCastsUsizeToF64Tool)),
        (ScriptLuaCastsI64ToU32Tool::definition(), Box::new(ScriptLuaCastsI64ToU32Tool)),
        (ScriptLuaCastsI64ToI32Tool::definition(), Box::new(ScriptLuaCastsI64ToI32Tool)),
        (ScriptLuaExecuteScriptTool::definition(), Box::new(ScriptLuaExecuteScriptTool)),
        (ScriptLuaMatchHexPatternTool::definition(), Box::new(ScriptLuaMatchHexPatternTool)),
        (ScriptLuaDetectFormatTool::definition(), Box::new(ScriptLuaDetectFormatTool)),
        (ScriptLuaJmpPatchTool::definition(), Box::new(ScriptLuaJmpPatchTool)),
        (ScriptLuaRetPatchTool::definition(), Box::new(ScriptLuaRetPatchTool)),
        (ScriptLuaCastsI64ToUsizeTool::definition(), Box::new(ScriptLuaCastsI64ToUsizeTool)),
        (ScriptLuaCastsU64ToUsizeTool::definition(), Box::new(ScriptLuaCastsU64ToUsizeTool)),
        (ScriptLuaTemplateFindXrefsTool::definition(), Box::new(ScriptLuaTemplateFindXrefsTool)),
        (ScriptLuaTemplateExtractStringsTool::definition(), Box::new(ScriptLuaTemplateExtractStringsTool)),
        (ScriptLuaTemplateDumpFunctionsTool::definition(), Box::new(ScriptLuaTemplateDumpFunctionsTool)),
        (ScriptLuaTemplateRenameFunctionsTool::definition(), Box::new(ScriptLuaTemplateRenameFunctionsTool)),
        (ScriptLuaTemplatePatchPatternTool::definition(), Box::new(ScriptLuaTemplatePatchPatternTool)),
        (ScriptLuaContextOutputTextTool::definition(), Box::new(ScriptLuaContextOutputTextTool)),
    ]
}
