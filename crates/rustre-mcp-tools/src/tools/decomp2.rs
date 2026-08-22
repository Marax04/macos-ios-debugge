//! MCP wrappers for the rustre-decomp2 crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct Decomp2SymbolMapInsertLookupTool;
impl Decomp2SymbolMapInsertLookupTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp2_symbol_map_insert_lookup".to_string(),
            description: "rustre_decompiler::SymbolMap::new/insert/len/is_empty".to_string(),
            input_schema: json!({"type":"object","properties":{"pairs":{"type":"array"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for Decomp2SymbolMapInsertLookupTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut m = rustre_decompiler::SymbolMap::new();
        let was_empty = m.is_empty();
        if let Some(arr) = args.get("pairs").and_then(Value::as_array) {
            for p in arr {
                let addr = p.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("addr".into()))?;
                let name = p.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?;
                m.insert(addr, name);
            }
        }
        Ok(ToolResult::text(json!({"was_empty":was_empty,"len":m.len(),"is_empty":m.is_empty(),"source":"rustre_decompiler::SymbolMap"}).to_string()))
    }
}

pub struct Decomp2TypePropagationRoundtripTool;
impl Decomp2TypePropagationRoundtripTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp2_type_propagation_roundtrip".to_string(),
            description: "rustre_decompiler::TypePropagation::new/set_type/get_type/count".to_string(),
            input_schema: json!({"type":"object","properties":{"var":{"type":"string"},"ty":{"type":"string"}},"required":["var","ty"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for Decomp2TypePropagationRoundtripTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let var = args.get("var").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("var".into()))?;
        let ty = args.get("ty").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("ty".into()))?;
        let mut t = rustre_decompiler::TypePropagation::new();
        t.set_type(var, ty);
        let got = t.get_type(var).map(String::from);
        Ok(ToolResult::text(json!({"got":got,"count":t.count(),"source":"rustre_decompiler::TypePropagation"}).to_string()))
    }
}

pub struct Decomp2ExpressionRecoveryCountTool;
impl Decomp2ExpressionRecoveryCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp2_expression_recovery_count".to_string(),
            description: "rustre_decompiler::ExpressionRecovery::new/register_function/call_return_type/known_function_count".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"ret":{"type":"string"}},"required":["name","ret"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for Decomp2ExpressionRecoveryCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?;
        let ret = args.get("ret").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("ret".into()))?;
        let mut e = rustre_decompiler::ExpressionRecovery::new();
        e.register_function(name, ret);
        let ct = e.call_return_type(name).map(String::from);
        Ok(ToolResult::text(json!({"ret":ct,"count":e.known_function_count(),"source":"rustre_decompiler::ExpressionRecovery"}).to_string()))
    }
}

pub struct Decomp2VariableRecoveryStackTool;
impl Decomp2VariableRecoveryStackTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp2_variable_recovery_stack".to_string(),
            description: "rustre_decompiler::VariableRecovery::new/stack_var_name/fresh_var/total_vars".to_string(),
            input_schema: json!({"type":"object","properties":{"offset":{"type":"integer"}},"required":["offset"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for Decomp2VariableRecoveryStackTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let offset = args.get("offset").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("offset".into()))?;
        let mut v = rustre_decompiler::VariableRecovery::new();
        let n = v.stack_var_name(offset);
        let f = v.fresh_var();
        Ok(ToolResult::text(json!({"stack_name":n,"fresh":f,"total":v.total_vars(),"source":"rustre_decompiler::VariableRecovery"}).to_string()))
    }
}

pub struct Decomp2DecompilerCacheMissTool;
impl Decomp2DecompilerCacheMissTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp2_decompiler_cache_miss".to_string(),
            description: "rustre_decompiler::DecompilerCache::new/get/hit_count/miss_count/is_empty".to_string(),
            input_schema: json!({"type":"object","properties":{"capacity":{"type":"integer"},"addr":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for Decomp2DecompilerCacheMissTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cap = args.get("capacity").and_then(Value::as_u64).unwrap_or(4) as usize;
        let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0x1000);
        let mut c = rustre_decompiler::DecompilerCache::new(cap);
        let hit = c.get(addr).is_some();
        Ok(ToolResult::text(json!({"hit":hit,"len":c.len(),"is_empty":c.is_empty(),"hit_count":c.hit_count(),"miss_count":c.miss_count(),"source":"rustre_decompiler::DecompilerCache"}).to_string()))
    }
}

pub struct Decomp2CallingConventionParamRegsTool;
impl Decomp2CallingConventionParamRegsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp2_calling_convention_param_regs".to_string(),
            description: "rustre_decompiler::CallingConvention::from_arch + param_regs".to_string(),
            input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}},"required":["arch"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for Decomp2CallingConventionParamRegsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arch = args.get("arch").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("arch".into()))?;
        let cc = rustre_decompiler::CallingConvention::from_arch(arch);
        let regs: Vec<&str> = cc.param_regs().to_vec();
        let count = regs.len();
        Ok(ToolResult::text(json!({"regs":regs,"count":count,"source":"rustre_decompiler::CallingConvention::param_regs"}).to_string()))
    }
}

pub struct Decomp2AnnotationStoreClearTool;
impl Decomp2AnnotationStoreClearTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp2_annotation_store_clear".to_string(),
            description: "rustre_decompiler::AnnotationStore::new/add/clear + DecompilerAnnotation::comment".to_string(),
            input_schema: json!({"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"},"text":{"type":"string"}},"required":["start","end","text"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for Decomp2AnnotationStoreClearTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let start = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("start".into()))?;
        let end = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("end".into()))?;
        let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("text".into()))?;
        let mut s = rustre_decompiler::AnnotationStore::new();
        s.add(rustre_decompiler::DecompilerAnnotation::comment(start, end, text));
        let at_len = s.at_address(start).len();
        s.clear();
        let after = s.at_address(start).len();
        Ok(ToolResult::text(json!({"at_before_clear":at_len,"at_after_clear":after,"source":"rustre_decompiler::AnnotationStore"}).to_string()))
    }
}

pub struct Decomp2FunctionNameGeneratorTool;
impl Decomp2FunctionNameGeneratorTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp2_function_name_generator_hint".to_string(),
            description: "rustre_decompiler::FunctionNameGenerator::new/name_for".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"hint":{"type":"string"}},"required":["addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for Decomp2FunctionNameGeneratorTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("addr".into()))?;
        let hint = args.get("hint").and_then(Value::as_str);
        let mut g = rustre_decompiler::FunctionNameGenerator::new();
        let n1 = g.name_for(addr, hint);
        let n2 = g.name_for(addr + 4, hint);
        Ok(ToolResult::text(json!({"name1":n1,"name2":n2,"source":"rustre_decompiler::FunctionNameGenerator"}).to_string()))
    }
}

pub struct Decomp2TimingHookTotalTool;
impl Decomp2TimingHookTotalTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp2_timing_hook_total".to_string(),
            description: "rustre_decompiler::TimingHook::new/total_time/pass_times".to_string(),
            input_schema: json!({"type":"object"}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for Decomp2TimingHookTotalTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let h = rustre_decompiler::TimingHook::new();
        let total_us = h.total_time().as_micros() as u64;
        let n = h.pass_times().len();
        Ok(ToolResult::text(json!({"total_us":total_us,"pass_count":n,"source":"rustre_decompiler::TimingHook"}).to_string()))
    }
}

pub struct Decomp2PassRegistryNamesTool;
impl Decomp2PassRegistryNamesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp2_pass_registry_empty".to_string(),
            description: "rustre_decompiler::PassRegistry::new/len/is_empty/names".to_string(),
            input_schema: json!({"type":"object"}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for Decomp2PassRegistryNamesTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let r = rustre_decompiler::PassRegistry::new();
        let names: Vec<String> = r.names().into_iter().map(String::from).collect();
        Ok(ToolResult::text(json!({"len":r.len(),"is_empty":r.is_empty(),"names":names,"source":"rustre_decompiler::PassRegistry"}).to_string()))
    }
}

pub struct Decomp2AnnotationCategoryTool;
impl Decomp2AnnotationCategoryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp2_annotation_category_filter".to_string(),
            description: "rustre_decompiler::AnnotationStore + DecompilerAnnotation::{comment,type_info,symbol_name} + by_category".to_string(),
            input_schema: json!({"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"}},"required":["start","end"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for Decomp2AnnotationCategoryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let start = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("start".into()))?;
        let end = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("end".into()))?;
        let mut s = rustre_decompiler::AnnotationStore::new();
        s.add(rustre_decompiler::DecompilerAnnotation::comment(start, end, "c"));
        s.add(rustre_decompiler::DecompilerAnnotation::type_info(start, end, "int"));
        s.add(rustre_decompiler::DecompilerAnnotation::symbol_name(start, end, "sym"));
        let comments = s.by_category(rustre_decompiler::AnnotationCategory::Comment).len();
        let types = s.by_category(rustre_decompiler::AnnotationCategory::TypeInfo).len();
        let syms = s.by_category(rustre_decompiler::AnnotationCategory::SymbolName).len();
        Ok(ToolResult::text(json!({"comments":comments,"types":types,"symbols":syms,"source":"rustre_decompiler::AnnotationStore::by_category"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (Decomp2SymbolMapInsertLookupTool::definition(), Box::new(Decomp2SymbolMapInsertLookupTool)),
        (Decomp2TypePropagationRoundtripTool::definition(), Box::new(Decomp2TypePropagationRoundtripTool)),
        (Decomp2ExpressionRecoveryCountTool::definition(), Box::new(Decomp2ExpressionRecoveryCountTool)),
        (Decomp2VariableRecoveryStackTool::definition(), Box::new(Decomp2VariableRecoveryStackTool)),
        (Decomp2DecompilerCacheMissTool::definition(), Box::new(Decomp2DecompilerCacheMissTool)),
        (Decomp2CallingConventionParamRegsTool::definition(), Box::new(Decomp2CallingConventionParamRegsTool)),
        (Decomp2AnnotationStoreClearTool::definition(), Box::new(Decomp2AnnotationStoreClearTool)),
        (Decomp2FunctionNameGeneratorTool::definition(), Box::new(Decomp2FunctionNameGeneratorTool)),
        (Decomp2TimingHookTotalTool::definition(), Box::new(Decomp2TimingHookTotalTool)),
        (Decomp2PassRegistryNamesTool::definition(), Box::new(Decomp2PassRegistryNamesTool)),
        (Decomp2AnnotationCategoryTool::definition(), Box::new(Decomp2AnnotationCategoryTool)),
    ]
}
