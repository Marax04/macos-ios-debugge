//! MCP wrappers for the rustre-rlib_dec crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct RlibDecSymbolMapOpsTool;
impl RlibDecSymbolMapOpsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_symbol_map_ops".to_string(), description: "SymbolMap::new+insert+resolve+len".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"name":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecSymbolMapOpsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
    let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
    let mut m = rustre_decompiler::SymbolMap::new();
    m.insert(addr, name);
    let resolved = <rustre_decompiler::SymbolMap as rustre_decompiler::SymbolResolver>::resolve(&m, addr);
    Ok(ToolResult::text(json!({"len":m.len(),"is_empty":m.is_empty(),"resolved":resolved,"source":"rustre_decompiler::SymbolMap"}).to_string()))
} }

pub struct RlibDecSymbolMapFromFlirtPairsTool;
impl RlibDecSymbolMapFromFlirtPairsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_symbol_map_from_flirt_pairs".to_string(), description: "SymbolMap::from_flirt_pairs".to_string(), input_schema: json!({"type":"object","properties":{"pairs":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecSymbolMapFromFlirtPairsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let arr = args.get("pairs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'pairs'".into()))?;
    let pairs: Vec<(u64, String)> = arr.iter().filter_map(|v| {
        let a = v.get("addr")?.as_u64()?; let n = v.get("name")?.as_str()?.to_string(); Some((a, n))
    }).collect();
    let count = pairs.len();
    let m = rustre_decompiler::SymbolMap::from_flirt_pairs(pairs);
    Ok(ToolResult::text(json!({"len":m.len(),"input_count":count,"source":"rustre_decompiler::SymbolMap::from_flirt_pairs"}).to_string()))
} }

pub struct RlibDecFunctionNameGeneratorTool;
impl RlibDecFunctionNameGeneratorTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_function_name_generator".to_string(), description: "FunctionNameGenerator::name_for".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"hint":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecFunctionNameGeneratorTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
    let hint = args.get("hint").and_then(Value::as_str);
    let mut g = rustre_decompiler::FunctionNameGenerator::new();
    let name = g.name_for(addr, hint);
    Ok(ToolResult::text(json!({"name":name,"count":g.count(),"source":"rustre_decompiler::FunctionNameGenerator::name_for"}).to_string()))
} }

pub struct RlibDecTypepropSetGetTool;
impl RlibDecTypepropSetGetTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_typeprop_set_get".to_string(), description: "TypePropagation set_type+get_type".to_string(), input_schema: json!({"type":"object","properties":{"var":{"type":"string"},"ty":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecTypepropSetGetTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let var = args.get("var").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'var'".into()))?;
    let ty = args.get("ty").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'ty'".into()))?;
    let mut tp = rustre_decompiler::TypePropagation::new();
    tp.set_type(var, ty);
    Ok(ToolResult::text(json!({"got":tp.get_type(var),"count":tp.count(),"source":"rustre_decompiler::TypePropagation"}).to_string()))
} }

pub struct RlibDecTypepropPropagateAddTool;
impl RlibDecTypepropPropagateAddTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_typeprop_propagate_add".to_string(), description: "TypePropagation::propagate_add".to_string(), input_schema: json!({"type":"object","properties":{"lhs":{"type":"string"},"lhs_type":{"type":"string"},"rhs_is_const":{"type":"boolean"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecTypepropPropagateAddTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let lhs = args.get("lhs").and_then(Value::as_str).unwrap_or("p");
    let lhs_type = args.get("lhs_type").and_then(Value::as_str).unwrap_or("int*");
    let rhs_c = args.get("rhs_is_const").and_then(Value::as_bool).unwrap_or(true);
    let mut tp = rustre_decompiler::TypePropagation::new();
    tp.set_type(lhs, lhs_type);
    let out = tp.propagate_add(lhs, rhs_c);
    Ok(ToolResult::text(json!({"result":out,"source":"rustre_decompiler::TypePropagation::propagate_add"}).to_string()))
} }

pub struct RlibDecCallingConventionFromArchTool;
impl RlibDecCallingConventionFromArchTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_calling_convention_from_arch".to_string(), description: "CallingConvention::from_arch".to_string(), input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecCallingConventionFromArchTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let arch = args.get("arch").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'arch'".into()))?;
    let cc = rustre_decompiler::CallingConvention::from_arch(arch);
    Ok(ToolResult::text(json!({"cc":cc.to_string(),"param_regs":cc.param_regs(),"source":"rustre_decompiler::CallingConvention::from_arch"}).to_string()))
} }

pub struct RlibDecVarRecoveryStackVarNameTool;
impl RlibDecVarRecoveryStackVarNameTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_var_recovery_stack_var_name".to_string(), description: "VariableRecovery::stack_var_name".to_string(), input_schema: json!({"type":"object","properties":{"offset":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecVarRecoveryStackVarNameTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let offset = args.get("offset").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("missing 'offset'".into()))?;
    let mut vr = rustre_decompiler::VariableRecovery::new();
    let name = vr.stack_var_name(offset);
    Ok(ToolResult::text(json!({"name":name,"total_vars":vr.total_vars(),"source":"rustre_decompiler::VariableRecovery::stack_var_name"}).to_string()))
} }

pub struct RlibDecVarRecoveryFreshVarTool;
impl RlibDecVarRecoveryFreshVarTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_var_recovery_fresh_var".to_string(), description: "VariableRecovery::fresh_var repeated n times".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecVarRecoveryFreshVarTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let n = args.get("n").and_then(Value::as_u64).unwrap_or(3) as usize;
    let mut vr = rustre_decompiler::VariableRecovery::new();
    let names: Vec<String> = (0..n).map(|_| vr.fresh_var()).collect();
    Ok(ToolResult::text(json!({"names":names,"source":"rustre_decompiler::VariableRecovery::fresh_var"}).to_string()))
} }

pub struct RlibDecExprRecoveryKnownCountTool;
impl RlibDecExprRecoveryKnownCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_expr_recovery_known_count".to_string(), description: "ExpressionRecovery register_function+call_return_type".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"ret_ty":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecExprRecoveryKnownCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let name = args.get("name").and_then(Value::as_str).unwrap_or("f");
    let ret_ty = args.get("ret_ty").and_then(Value::as_str).unwrap_or("int");
    let mut er = rustre_decompiler::ExpressionRecovery::new();
    er.register_function(name, ret_ty);
    Ok(ToolResult::text(json!({"count":er.known_function_count(),"return_type":er.call_return_type(name),"source":"rustre_decompiler::ExpressionRecovery"}).to_string()))
} }

pub struct RlibDecCacheHitRateTool;
impl RlibDecCacheHitRateTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_cache_hit_rate".to_string(), description: "DecompilerCache::new(capacity), empty len/is_empty/hit_rate".to_string(), input_schema: json!({"type":"object","properties":{"capacity":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecCacheHitRateTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let cap = args.get("capacity").and_then(Value::as_u64).unwrap_or(16) as usize;
    let c = rustre_decompiler::DecompilerCache::new(cap);
    Ok(ToolResult::text(json!({"len":c.len(),"is_empty":c.is_empty(),"hit_rate":c.hit_rate(),"source":"rustre_decompiler::DecompilerCache"}).to_string()))
} }

pub struct RlibDecCfsFreshGotoLabelTool;
impl RlibDecCfsFreshGotoLabelTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_cfs_fresh_goto_label".to_string(), description: "ControlFlowStructuring::fresh_goto_label n times".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecCfsFreshGotoLabelTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let n = args.get("n").and_then(Value::as_u64).unwrap_or(3) as usize;
    let mut cfs = rustre_decompiler::ControlFlowStructuring::new();
    let labels: Vec<String> = (0..n).map(|_| cfs.fresh_goto_label()).collect();
    Ok(ToolResult::text(json!({"labels":labels,"source":"rustre_decompiler::ControlFlowStructuring::fresh_goto_label"}).to_string()))
} }

pub struct RlibDecCfsDetectLoopTool;
impl RlibDecCfsDetectLoopTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_cfs_detect_loop".to_string(), description: "ControlFlowStructuring::detect_loop".to_string(), input_schema: json!({"type":"object","properties":{"lines":{"type":"array","items":{"type":"string"}}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecCfsDetectLoopTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let arr = args.get("lines").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'lines'".into()))?;
    let lines: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let found = rustre_decompiler::ControlFlowStructuring::detect_loop(&refs);
    Ok(ToolResult::text(json!({"detected":found.is_some(),"source":"rustre_decompiler::ControlFlowStructuring::detect_loop"}).to_string()))
} }

pub struct RlibDecCfsMakeIfElseTool;
impl RlibDecCfsMakeIfElseTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_cfs_make_if_else".to_string(), description: "ControlFlowStructuring::make_if_else".to_string(), input_schema: json!({"type":"object","properties":{"cond":{"type":"string"},"then_body":{"type":"array"},"else_body":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecCfsMakeIfElseTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let cond = args.get("cond").and_then(Value::as_str).unwrap_or("x").to_string();
    let then_body: Vec<String> = args.get("then_body").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
    let else_body: Vec<String> = args.get("else_body").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
    let s = rustre_decompiler::ControlFlowStructuring::make_if_else(cond, then_body, else_body);
    let flat = rustre_decompiler::ControlFlowStructuring::flatten(&[s]);
    Ok(ToolResult::text(json!({"flattened":flat,"source":"rustre_decompiler::ControlFlowStructuring::make_if_else"}).to_string()))
} }

pub struct RlibDecQualityFromSourceTool;
impl RlibDecQualityFromSourceTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_quality_from_source".to_string(), description: "QualityMetrics::from_source+expression_density+readability_score".to_string(), input_schema: json!({"type":"object","properties":{"src":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecQualityFromSourceTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let src = args.get("src").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'src'".into()))?;
    let m = rustre_decompiler::QualityMetrics::from_source(src);
    Ok(ToolResult::text(json!({"expression_density":m.expression_density(),"readability_score":m.readability_score(),"source":"rustre_decompiler::QualityMetrics"}).to_string()))
} }

pub struct RlibDecStatsSuccessRateTool;
impl RlibDecStatsSuccessRateTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_stats_success_rate".to_string(), description: "DecompStats::success_rate+avg_time_ms".to_string(), input_schema: json!({"type":"object","properties":{"decompiled":{"type":"integer"},"failed":{"type":"integer"},"total_time_ms":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecStatsSuccessRateTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let s = rustre_decompiler::DecompStats {
        functions_decompiled: args.get("decompiled").and_then(Value::as_u64).unwrap_or(0),
        functions_failed: args.get("failed").and_then(Value::as_u64).unwrap_or(0),
        total_time_ms: args.get("total_time_ms").and_then(Value::as_u64).unwrap_or(0),
        ir_nodes: 0, variables_recovered: 0, call_sites_found: 0, cache_hits: 0,
    };
    Ok(ToolResult::text(json!({"success_rate":s.success_rate(),"avg_time_ms":s.avg_time_ms(),"source":"rustre_decompiler::DecompStats"}).to_string()))
} }

pub struct RlibDecSymbolMapSetXrefTool;
impl RlibDecSymbolMapSetXrefTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_symbol_map_set_xref".to_string(), description: "SymbolMap::set_xref_count+xref_count.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"count":{"type":"integer"}},"required":["addr","count"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecSymbolMapSetXrefTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let count = args.get("count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'count'".into()))? as usize; let mut m = rustre_decompiler::SymbolMap::new(); m.set_xref_count(addr, count); let got = <rustre_decompiler::SymbolMap as rustre_decompiler::SymbolResolver>::xref_count(&m, addr); Ok(ToolResult::text(json!({"xref_count":got,"source":"rustre_decompiler::SymbolMap::set_xref_count"}).to_string())) } }

pub struct RlibDecSymbolMapExtendPairsTool;
impl RlibDecSymbolMapExtendPairsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_symbol_map_extend_pairs".to_string(), description: "SymbolMap::extend_pairs.".to_string(), input_schema: json!({"type":"object","properties":{"pairs":{"type":"array"}},"required":["pairs"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecSymbolMapExtendPairsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("pairs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'pairs'".into()))?; let pairs: Vec<(u64, String)> = arr.iter().filter_map(|v| { let a = v.get("addr")?.as_u64()?; let n = v.get("name")?.as_str()?.to_string(); Some((a, n)) }).collect(); let mut m = rustre_decompiler::SymbolMap::new(); let input = pairs.len(); m.extend_pairs(pairs); Ok(ToolResult::text(json!({"len":m.len(),"input":input,"source":"rustre_decompiler::SymbolMap::extend_pairs"}).to_string())) } }

pub struct RlibDecSymbolMapEnableDemanglingTool;
impl RlibDecSymbolMapEnableDemanglingTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_symbol_map_enable_demangling".to_string(), description: "SymbolMap::enable_rust_demangling then resolve.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"name":{"type":"string"},"on":{"type":"boolean"}},"required":["addr","name"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecSymbolMapEnableDemanglingTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?; let on = args.get("on").and_then(Value::as_bool).unwrap_or(true); let mut m = rustre_decompiler::SymbolMap::new(); m.enable_rust_demangling(on); m.insert(addr, name); let resolved = <rustre_decompiler::SymbolMap as rustre_decompiler::SymbolResolver>::resolve(&m, addr); Ok(ToolResult::text(json!({"resolved":resolved,"source":"rustre_decompiler::SymbolMap::enable_rust_demangling"}).to_string())) } }

pub struct RlibDecTypepropGetTypeTool;
impl RlibDecTypepropGetTypeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_typeprop_get_type".to_string(), description: "TypePropagation::set_type+get_type.".to_string(), input_schema: json!({"type":"object","properties":{"var":{"type":"string"},"ty":{"type":"string"}},"required":["var","ty"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecTypepropGetTypeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let var = args.get("var").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'var'".into()))?; let ty = args.get("ty").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'ty'".into()))?; let mut t = rustre_decompiler::TypePropagation::new(); t.set_type(var, ty); Ok(ToolResult::text(json!({"get":t.get_type(var),"source":"rustre_decompiler::TypePropagation::get_type"}).to_string())) } }

pub struct RlibDecTypepropCountAllTool;
impl RlibDecTypepropCountAllTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_typeprop_count_all".to_string(), description: "TypePropagation::count+all_typed.".to_string(), input_schema: json!({"type":"object","properties":{"map":{"type":"object"}},"required":["map"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecTypepropCountAllTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let m = args.get("map").and_then(Value::as_object).ok_or_else(|| McpError::InvalidParams("missing 'map'".into()))?; let mut t = rustre_decompiler::TypePropagation::new(); for (k, v) in m { if let Some(s) = v.as_str() { t.set_type(k.clone(), s.to_string()); } } let all: Vec<(String,String)> = t.all_typed().into_iter().map(|(a,b)| (a.to_string(), b.to_string())).collect(); Ok(ToolResult::text(json!({"count":t.count(),"all":all,"source":"rustre_decompiler::TypePropagation::all_typed"}).to_string())) } }

pub struct RlibDecAnnotationStoreOpsTool;
impl RlibDecAnnotationStoreOpsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_annotation_store_ops".to_string(), description: "AnnotationStore::new+add+len+is_empty+clear.".to_string(), input_schema: json!({"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"},"text":{"type":"string"}},"required":["start","end","text"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecAnnotationStoreOpsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))?; let e = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'end'".into()))?; let t = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?; let mut store = rustre_decompiler::AnnotationStore::new(); store.add(rustre_decompiler::DecompilerAnnotation::comment(s, e, t)); let len_after = store.len(); let empty_after = store.is_empty(); store.clear(); Ok(ToolResult::text(json!({"len_after_add":len_after,"empty_after_add":empty_after,"len_after_clear":store.len(),"source":"rustre_decompiler::AnnotationStore"}).to_string())) } }

pub struct RlibDecAnnotationAtAddressTool;
impl RlibDecAnnotationAtAddressTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_annotation_at_address".to_string(), description: "AnnotationStore::at_address+DecompilerAnnotation::covers.".to_string(), input_schema: json!({"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"},"probe":{"type":"integer"}},"required":["start","end","probe"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecAnnotationAtAddressTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))?; let e = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'end'".into()))?; let p = args.get("probe").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'probe'".into()))?; let ann = rustre_decompiler::DecompilerAnnotation::comment(s, e, "note"); let covers = ann.covers(p); let mut store = rustre_decompiler::AnnotationStore::new(); store.add(ann); Ok(ToolResult::text(json!({"covers":covers,"hits":store.at_address(p).len(),"source":"rustre_decompiler::AnnotationStore::at_address"}).to_string())) } }

pub struct RlibDecAnnotationByCategoryTool;
impl RlibDecAnnotationByCategoryTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_annotation_by_category".to_string(), description: "AnnotationStore::by_category Comment/TypeInfo.".to_string(), input_schema: json!({"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"}},"required":["start","end"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecAnnotationByCategoryTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))?; let e = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'end'".into()))?; let mut store = rustre_decompiler::AnnotationStore::new(); store.add(rustre_decompiler::DecompilerAnnotation::comment(s, e, "c")); store.add(rustre_decompiler::DecompilerAnnotation::type_info(s, e, "int")); Ok(ToolResult::text(json!({"comments":store.by_category(rustre_decompiler::AnnotationCategory::Comment).len(),"types":store.by_category(rustre_decompiler::AnnotationCategory::TypeInfo).len(),"source":"rustre_decompiler::AnnotationStore::by_category"}).to_string())) } }

pub struct RlibDecAnnotationTypeInfoTool;
impl RlibDecAnnotationTypeInfoTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_annotation_type_info".to_string(), description: "DecompilerAnnotation::type_info+symbol_name.".to_string(), input_schema: json!({"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"},"text":{"type":"string"}},"required":["start","end","text"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecAnnotationTypeInfoTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))?; let e = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'end'".into()))?; let t = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?; let a = rustre_decompiler::DecompilerAnnotation::type_info(s, e, t); let b = rustre_decompiler::DecompilerAnnotation::symbol_name(s, e, t); Ok(ToolResult::text(json!({"type_info_cat":format!("{:?}",a.category),"symbol_cat":format!("{:?}",b.category),"source":"rustre_decompiler::DecompilerAnnotation"}).to_string())) } }

pub struct RlibDecDiagnosticNewTool;
impl RlibDecDiagnosticNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_diagnostic_new".to_string(), description: "DecompilerDiagnostic::error+warning+at_address+from_pass.".to_string(), input_schema: json!({"type":"object","properties":{"msg":{"type":"string"},"addr":{"type":"integer"},"pass":{"type":"string"}},"required":["msg"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecDiagnosticNewTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let msg = args.get("msg").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'msg'".into()))?; let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0); let pass = args.get("pass").and_then(Value::as_str).unwrap_or("p"); let e = rustre_decompiler::DecompilerDiagnostic::error(msg).at_address(addr).from_pass(pass); let w = rustre_decompiler::DecompilerDiagnostic::warning(msg); Ok(ToolResult::text(json!({"error_sev":format!("{:?}",e.severity),"error_addr":e.address,"error_pass":e.pass,"warn_sev":format!("{:?}",w.severity),"source":"rustre_decompiler::DecompilerDiagnostic"}).to_string())) } }

pub struct RlibDecVarRecoveryOpsTool;
impl RlibDecVarRecoveryOpsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_var_recovery_ops".to_string(), description: "VariableRecovery::new+add_stack_var+add_reg_param+total_vars.".to_string(), input_schema: json!({"type":"object","properties":{"offset":{"type":"integer"},"reg":{"type":"string"}},"required":["offset","reg"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecVarRecoveryOpsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let off = args.get("offset").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("missing 'offset'".into()))?; let reg = args.get("reg").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'reg'".into()))?; let mut r = rustre_decompiler::VariableRecovery::new(); r.add_stack_var(off, "local"); r.add_reg_param(reg, "arg0"); Ok(ToolResult::text(json!({"total":r.total_vars(),"source":"rustre_decompiler::VariableRecovery::total_vars"}).to_string())) } }

pub struct RlibDecCfsFlattenTool;
impl RlibDecCfsFlattenTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_cfs_flatten".to_string(), description: "ControlFlowStructuring::flatten of a Sequence.".to_string(), input_schema: json!({"type":"object","properties":{"lines":{"type":"array","items":{"type":"string"}}},"required":["lines"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecCfsFlattenTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("lines").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'lines'".into()))?; let lines: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(); let structs = vec![rustre_decompiler::CfStructure::Sequence(lines)]; let out = rustre_decompiler::ControlFlowStructuring::flatten(&structs); Ok(ToolResult::text(json!({"out":out,"source":"rustre_decompiler::ControlFlowStructuring::flatten"}).to_string())) } }

pub struct RlibDecCfsStructureCountEmitTool;
impl RlibDecCfsStructureCountEmitTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_cfs_structure_count_emit".to_string(), description: "ControlFlowStructuring::new+add_structure+structure_count+emit.".to_string(), input_schema: json!({"type":"object","properties":{"lines":{"type":"array","items":{"type":"string"}}},"required":["lines"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecCfsStructureCountEmitTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("lines").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'lines'".into()))?; let lines: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(); let mut cfs = rustre_decompiler::ControlFlowStructuring::new(); cfs.add_structure(rustre_decompiler::CfStructure::Sequence(lines)); let emitted = cfs.emit(); Ok(ToolResult::text(json!({"count":cfs.structure_count(),"emit":emitted,"source":"rustre_decompiler::ControlFlowStructuring::emit"}).to_string())) } }

pub struct RlibDecCfsMakeForTool;
impl RlibDecCfsMakeForTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_cfs_make_for".to_string(), description: "ControlFlowStructuring::make_for + emit_lines.".to_string(), input_schema: json!({"type":"object","properties":{"init":{"type":"string"},"cond":{"type":"string"},"step":{"type":"string"},"body":{"type":"array","items":{"type":"string"}}},"required":["init","cond","step","body"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecCfsMakeForTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let init = args.get("init").and_then(Value::as_str).unwrap_or("").to_string(); let cond = args.get("cond").and_then(Value::as_str).unwrap_or("").to_string(); let step = args.get("step").and_then(Value::as_str).unwrap_or("").to_string(); let body: Vec<String> = args.get("body").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(); let s = rustre_decompiler::ControlFlowStructuring::make_for(init, cond, step, body); Ok(ToolResult::text(json!({"emit":s.emit_lines(0),"source":"rustre_decompiler::ControlFlowStructuring::make_for"}).to_string())) } }

pub struct RlibDecCfsMakeSwitchTool;
impl RlibDecCfsMakeSwitchTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_cfs_make_switch".to_string(), description: "ControlFlowStructuring::make_switch + emit_lines.".to_string(), input_schema: json!({"type":"object","properties":{"expr":{"type":"string"},"cases":{"type":"array"}},"required":["expr","cases"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecCfsMakeSwitchTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let expr = args.get("expr").and_then(Value::as_str).unwrap_or("x").to_string(); let cases_arr = args.get("cases").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'cases'".into()))?; let cases: Vec<(String, Vec<String>)> = cases_arr.iter().filter_map(|v| { let label = v.get("label")?.as_str()?.to_string(); let body: Vec<String> = v.get("body")?.as_array()?.iter().filter_map(|x| x.as_str().map(String::from)).collect(); Some((label, body)) }).collect(); let s = rustre_decompiler::ControlFlowStructuring::make_switch(expr, cases); Ok(ToolResult::text(json!({"emit":s.emit_lines(0),"source":"rustre_decompiler::ControlFlowStructuring::make_switch"}).to_string())) } }

pub struct RlibDecCacheOpsTool;
impl RlibDecCacheOpsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_cache_ops".to_string(), description: "DecompilerCache::new+insert+get+len+is_empty+hit_count+miss_count.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"cap":{"type":"integer"}},"required":["addr"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecCacheOpsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let cap = args.get("cap").and_then(Value::as_u64).unwrap_or(16) as usize; let mut c = rustre_decompiler::DecompilerCache::new(cap); c.insert(rustre_decompiler::DecompiledFunction::new(addr, "f", "// body")); let hit = c.get(addr).map(|f| f.name.clone()); let miss = c.get(addr.wrapping_add(1)).map(|f| f.name.clone()); Ok(ToolResult::text(json!({"len":c.len(),"is_empty":c.is_empty(),"hit_name":hit,"miss_name":miss,"hits":c.hit_count(),"misses":c.miss_count(),"source":"rustre_decompiler::DecompilerCache"}).to_string())) } }

pub struct RlibDecCacheEvictOneTool;
impl RlibDecCacheEvictOneTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_cache_evict_one".to_string(), description: "DecompilerCache::evict + clear.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}},"required":["addr"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecCacheEvictOneTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let mut c = rustre_decompiler::DecompilerCache::new(8); c.insert(rustre_decompiler::DecompiledFunction::new(addr, "f", "")); let before = c.len(); c.evict(addr); let after_evict = c.len(); c.insert(rustre_decompiler::DecompiledFunction::new(addr, "f", "")); c.clear(); Ok(ToolResult::text(json!({"before":before,"after_evict":after_evict,"after_clear":c.len(),"source":"rustre_decompiler::DecompilerCache::evict"}).to_string())) } }

pub struct RlibDecPassRegistryOpsTool;
impl RlibDecPassRegistryOpsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_pass_registry_ops".to_string(), description: "PassRegistry::new+len+is_empty+names.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecPassRegistryOpsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let r = rustre_decompiler::PassRegistry::new(); let names: Vec<String> = r.names().iter().map(|s| (*s).to_string()).collect(); Ok(ToolResult::text(json!({"len":r.len(),"is_empty":r.is_empty(),"names":names,"source":"rustre_decompiler::PassRegistry"}).to_string())) } }

pub struct RlibDecFunctionNameGenCounterTool;
impl RlibDecFunctionNameGenCounterTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_function_name_gen_counter".to_string(), description: "FunctionNameGenerator::name_for x2 then count.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"hint":{"type":"string"}},"required":["addr"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecFunctionNameGenCounterTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let hint = args.get("hint").and_then(Value::as_str); let mut g = rustre_decompiler::FunctionNameGenerator::new(); let n1 = g.name_for(addr, hint); let n2 = g.name_for(addr.wrapping_add(0x10), None); Ok(ToolResult::text(json!({"n1":n1,"n2":n2,"count":g.count(),"source":"rustre_decompiler::FunctionNameGenerator::count"}).to_string())) } }

pub struct RlibDecExprRecoveryRegisterFnTool;
impl RlibDecExprRecoveryRegisterFnTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_expr_recovery_register_fn".to_string(), description: "ExpressionRecovery::register_function+call_return_type.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"ret":{"type":"string"}},"required":["name","ret"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecExprRecoveryRegisterFnTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?; let ret = args.get("ret").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'ret'".into()))?; let mut r = rustre_decompiler::ExpressionRecovery::new(); r.register_function(name, ret); Ok(ToolResult::text(json!({"count":r.known_function_count(),"return_type":r.call_return_type(name),"source":"rustre_decompiler::ExpressionRecovery::call_return_type"}).to_string())) } }

pub struct RlibDecCfStructureEmitLinesTool;
impl RlibDecCfStructureEmitLinesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_cf_structure_emit_lines".to_string(), description: "CfStructure::Sequence.emit_lines(indent).".to_string(), input_schema: json!({"type":"object","properties":{"lines":{"type":"array","items":{"type":"string"}},"indent":{"type":"integer"}},"required":["lines"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecCfStructureEmitLinesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("lines").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'lines'".into()))?; let indent = args.get("indent").and_then(Value::as_u64).unwrap_or(0) as usize; let lines: Vec<String> = arr.iter().filter_map(|v| v.as_str().map(String::from)).collect(); let s = rustre_decompiler::CfStructure::Sequence(lines); Ok(ToolResult::text(json!({"emit":s.emit_lines(indent),"source":"rustre_decompiler::CfStructure::emit_lines"}).to_string())) } }

pub struct RlibDecResultErrorsTool;
impl RlibDecResultErrorsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec_result_errors".to_string(), description: "DecompilerResult::new+add_diagnostic+errors+has_errors+total_lines.".to_string(), input_schema: json!({"type":"object","properties":{"msg":{"type":"string"}},"required":["msg"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDecResultErrorsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let msg = args.get("msg").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'msg'".into()))?; let mut r = rustre_decompiler::DecompilerResult::new(vec![rustre_decompiler::DecompiledFunction::new(0x1000, "f", "line1\nline2")], rustre_decompiler::DecompStats::default(), 0); r.add_diagnostic(rustre_decompiler::DecompilerDiagnostic::error(msg)); r.add_diagnostic(rustre_decompiler::DecompilerDiagnostic::warning(msg)); Ok(ToolResult::text(json!({"errors":r.errors().len(),"has_errors":r.has_errors(),"total_lines":r.total_lines(),"source":"rustre_decompiler::DecompilerResult"}).to_string())) } }

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (RlibDecSymbolMapOpsTool::definition(), Box::new(RlibDecSymbolMapOpsTool)),
        (RlibDecSymbolMapFromFlirtPairsTool::definition(), Box::new(RlibDecSymbolMapFromFlirtPairsTool)),
        (RlibDecFunctionNameGeneratorTool::definition(), Box::new(RlibDecFunctionNameGeneratorTool)),
        (RlibDecTypepropSetGetTool::definition(), Box::new(RlibDecTypepropSetGetTool)),
        (RlibDecTypepropPropagateAddTool::definition(), Box::new(RlibDecTypepropPropagateAddTool)),
        (RlibDecCallingConventionFromArchTool::definition(), Box::new(RlibDecCallingConventionFromArchTool)),
        (RlibDecVarRecoveryStackVarNameTool::definition(), Box::new(RlibDecVarRecoveryStackVarNameTool)),
        (RlibDecVarRecoveryFreshVarTool::definition(), Box::new(RlibDecVarRecoveryFreshVarTool)),
        (RlibDecExprRecoveryKnownCountTool::definition(), Box::new(RlibDecExprRecoveryKnownCountTool)),
        (RlibDecCacheHitRateTool::definition(), Box::new(RlibDecCacheHitRateTool)),
        (RlibDecCfsFreshGotoLabelTool::definition(), Box::new(RlibDecCfsFreshGotoLabelTool)),
        (RlibDecCfsDetectLoopTool::definition(), Box::new(RlibDecCfsDetectLoopTool)),
        (RlibDecCfsMakeIfElseTool::definition(), Box::new(RlibDecCfsMakeIfElseTool)),
        (RlibDecQualityFromSourceTool::definition(), Box::new(RlibDecQualityFromSourceTool)),
        (RlibDecStatsSuccessRateTool::definition(), Box::new(RlibDecStatsSuccessRateTool)),
        (RlibDecSymbolMapSetXrefTool::definition(), Box::new(RlibDecSymbolMapSetXrefTool)),
        (RlibDecSymbolMapExtendPairsTool::definition(), Box::new(RlibDecSymbolMapExtendPairsTool)),
        (RlibDecSymbolMapEnableDemanglingTool::definition(), Box::new(RlibDecSymbolMapEnableDemanglingTool)),
        (RlibDecTypepropGetTypeTool::definition(), Box::new(RlibDecTypepropGetTypeTool)),
        (RlibDecTypepropCountAllTool::definition(), Box::new(RlibDecTypepropCountAllTool)),
        (RlibDecAnnotationStoreOpsTool::definition(), Box::new(RlibDecAnnotationStoreOpsTool)),
        (RlibDecAnnotationAtAddressTool::definition(), Box::new(RlibDecAnnotationAtAddressTool)),
        (RlibDecAnnotationByCategoryTool::definition(), Box::new(RlibDecAnnotationByCategoryTool)),
        (RlibDecAnnotationTypeInfoTool::definition(), Box::new(RlibDecAnnotationTypeInfoTool)),
        (RlibDecDiagnosticNewTool::definition(), Box::new(RlibDecDiagnosticNewTool)),
        (RlibDecVarRecoveryOpsTool::definition(), Box::new(RlibDecVarRecoveryOpsTool)),
        (RlibDecCfsFlattenTool::definition(), Box::new(RlibDecCfsFlattenTool)),
        (RlibDecCfsStructureCountEmitTool::definition(), Box::new(RlibDecCfsStructureCountEmitTool)),
        (RlibDecCfsMakeForTool::definition(), Box::new(RlibDecCfsMakeForTool)),
        (RlibDecCfsMakeSwitchTool::definition(), Box::new(RlibDecCfsMakeSwitchTool)),
        (RlibDecCacheOpsTool::definition(), Box::new(RlibDecCacheOpsTool)),
        (RlibDecCacheEvictOneTool::definition(), Box::new(RlibDecCacheEvictOneTool)),
        (RlibDecPassRegistryOpsTool::definition(), Box::new(RlibDecPassRegistryOpsTool)),
        (RlibDecFunctionNameGenCounterTool::definition(), Box::new(RlibDecFunctionNameGenCounterTool)),
        (RlibDecExprRecoveryRegisterFnTool::definition(), Box::new(RlibDecExprRecoveryRegisterFnTool)),
        (RlibDecCfStructureEmitLinesTool::definition(), Box::new(RlibDecCfStructureEmitLinesTool)),
        (RlibDecResultErrorsTool::definition(), Box::new(RlibDecResultErrorsTool)),
    ]
}
