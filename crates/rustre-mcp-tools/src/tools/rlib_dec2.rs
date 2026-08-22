//! MCP wrappers for the rustre-rlib_dec2 crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct RlibDec2VariableNewTool;
impl RlibDec2VariableNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_variable_new".to_string(), description: "Construct DecompVariable + Display".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2VariableNewTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let name = args.get("name").and_then(Value::as_str).unwrap_or("v0").to_string();
    let type_str = args.get("type_str").and_then(Value::as_str).unwrap_or("int").to_string();
    let is_parameter = args.get("is_parameter").and_then(Value::as_bool).unwrap_or(false);
    let reg = args.get("reg").and_then(Value::as_str).unwrap_or("rax").to_string();
    let v = rustre_decompiler::DecompVariable { name, type_str, is_parameter, storage: rustre_decompiler::VarStorage::Register(reg) };
    Ok(ToolResult::text(json!({"display":v.to_string(),"is_parameter":v.is_parameter,"source":"rustre_decompiler::DecompVariable"}).to_string()))
} }

pub struct RlibDec2FunctionNewTool;
impl RlibDec2FunctionNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_function_new".to_string(), description: "DecompiledFunction::new+line_count".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2FunctionNewTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let address = args.get("address").and_then(Value::as_u64).unwrap_or(0x1000);
    let name = args.get("name").and_then(Value::as_str).unwrap_or("f").to_string();
    let code = args.get("code").and_then(Value::as_str).unwrap_or("int f(){return 0;}").to_string();
    let f = rustre_decompiler::DecompiledFunction::new(address, name, code);
    Ok(ToolResult::text(json!({"lines":f.line_count(),"confidence":f.confidence,"address":f.address,"source":"rustre_decompiler::DecompiledFunction::new"}).to_string()))
} }

pub struct RlibDec2FunctionWithConfidenceTool;
impl RlibDec2FunctionWithConfidenceTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_function_with_confidence".to_string(), description: "with_confidence + is_high_confidence".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2FunctionWithConfidenceTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let conf = args.get("conf").and_then(Value::as_u64).unwrap_or(80) as u8;
    let threshold = args.get("threshold").and_then(Value::as_u64).unwrap_or(60) as u8;
    let f = rustre_decompiler::DecompiledFunction::new(0x1000, "f", "").with_confidence(conf);
    Ok(ToolResult::text(json!({"confidence":f.confidence,"high":f.is_high_confidence(threshold),"source":"rustre_decompiler::DecompiledFunction::with_confidence"}).to_string()))
} }

pub struct RlibDec2FunctionParametersTool;
impl RlibDec2FunctionParametersTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_function_parameters".to_string(), description: "with_variable + parameters/locals".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2FunctionParametersTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let pc = args.get("param_count").and_then(Value::as_u64).unwrap_or(2) as usize;
    let lc = args.get("local_count").and_then(Value::as_u64).unwrap_or(3) as usize;
    let mut f = rustre_decompiler::DecompiledFunction::new(0x1000, "f", "");
    for i in 0..pc { f = f.with_variable(rustre_decompiler::DecompVariable { name: format!("p{i}"), type_str: "int".into(), is_parameter: true, storage: rustre_decompiler::VarStorage::Register("rdi".into()) }); }
    for i in 0..lc { f = f.with_variable(rustre_decompiler::DecompVariable { name: format!("l{i}"), type_str: "int".into(), is_parameter: false, storage: rustre_decompiler::VarStorage::Stack(-((i as i64)+8)) }); }
    Ok(ToolResult::text(json!({"params":f.parameters().len(),"locals":f.locals().len(),"source":"rustre_decompiler::DecompiledFunction::parameters"}).to_string()))
} }

pub struct RlibDec2FunctionWithCallSiteTool;
impl RlibDec2FunctionWithCallSiteTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_function_with_call_site".to_string(), description: "with_call_site".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2FunctionWithCallSiteTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let sites: Vec<u64> = args.get("sites").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
    let mut f = rustre_decompiler::DecompiledFunction::new(0x1000, "f", "");
    for a in &sites { f = f.with_call_site(*a); }
    Ok(ToolResult::text(json!({"call_sites":f.call_sites.len(),"source":"rustre_decompiler::DecompiledFunction::with_call_site"}).to_string()))
} }

pub struct RlibDec2StatsSuccessRateTool;
impl RlibDec2StatsSuccessRateTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_stats_success_rate".to_string(), description: "DecompStats success_rate + avg_time_ms".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2StatsSuccessRateTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let mut s = rustre_decompiler::DecompStats::default();
    s.functions_decompiled = args.get("ok").and_then(Value::as_u64).unwrap_or(8);
    s.functions_failed = args.get("fail").and_then(Value::as_u64).unwrap_or(2);
    s.total_time_ms = args.get("time_ms").and_then(Value::as_u64).unwrap_or(100);
    Ok(ToolResult::text(json!({"success_rate":s.success_rate(),"avg_time_ms":s.avg_time_ms(),"display":s.to_string(),"source":"rustre_decompiler::DecompStats"}).to_string()))
} }

pub struct RlibDec2AnnotationCommentTool;
impl RlibDec2AnnotationCommentTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_annotation_comment".to_string(), description: "DecompilerAnnotation::comment + covers".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2AnnotationCommentTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let start = args.get("start").and_then(Value::as_u64).unwrap_or(0x1000);
    let end = args.get("end").and_then(Value::as_u64).unwrap_or(0x1010);
    let text = args.get("text").and_then(Value::as_str).unwrap_or("c").to_string();
    let probe = args.get("probe").and_then(Value::as_u64).unwrap_or(0x1005);
    let a = rustre_decompiler::DecompilerAnnotation::comment(start, end, text);
    Ok(ToolResult::text(json!({"covers":a.covers(probe),"text":a.text,"source":"rustre_decompiler::DecompilerAnnotation::comment"}).to_string()))
} }

pub struct RlibDec2AnnotationTypeInfoTool;
impl RlibDec2AnnotationTypeInfoTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_annotation_type_info".to_string(), description: "DecompilerAnnotation::type_info".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2AnnotationTypeInfoTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let a = rustre_decompiler::DecompilerAnnotation::type_info(
        args.get("start").and_then(Value::as_u64).unwrap_or(0),
        args.get("end").and_then(Value::as_u64).unwrap_or(16),
        args.get("text").and_then(Value::as_str).unwrap_or("int").to_string());
    Ok(ToolResult::text(json!({"start":a.start,"end":a.end,"text":a.text,"source":"rustre_decompiler::DecompilerAnnotation::type_info"}).to_string()))
} }

pub struct RlibDec2AnnotationSymbolNameTool;
impl RlibDec2AnnotationSymbolNameTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_annotation_symbol_name".to_string(), description: "DecompilerAnnotation::symbol_name".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2AnnotationSymbolNameTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let a = rustre_decompiler::DecompilerAnnotation::symbol_name(
        args.get("start").and_then(Value::as_u64).unwrap_or(0),
        args.get("end").and_then(Value::as_u64).unwrap_or(16),
        args.get("text").and_then(Value::as_str).unwrap_or("main").to_string());
    Ok(ToolResult::text(json!({"text":a.text,"source":"rustre_decompiler::DecompilerAnnotation::symbol_name"}).to_string()))
} }

pub struct RlibDec2AnnotationStoreAddLenTool;
impl RlibDec2AnnotationStoreAddLenTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_annotation_store_add_len".to_string(), description: "AnnotationStore new/add/len/is_empty/clear".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2AnnotationStoreAddLenTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let n = args.get("n").and_then(Value::as_u64).unwrap_or(3) as usize;
    let mut s = rustre_decompiler::AnnotationStore::new();
    for i in 0..n { s.add(rustre_decompiler::DecompilerAnnotation::comment(i as u64, i as u64 + 4, "c")); }
    let after = s.len();
    s.clear();
    Ok(ToolResult::text(json!({"added":after,"is_empty_after_clear":s.is_empty(),"source":"rustre_decompiler::AnnotationStore"}).to_string()))
} }

pub struct RlibDec2AnnotationStoreAtAddressTool;
impl RlibDec2AnnotationStoreAtAddressTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_annotation_store_at_address".to_string(), description: "AnnotationStore::at_address".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2AnnotationStoreAtAddressTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let probe = args.get("probe").and_then(Value::as_u64).unwrap_or(0x1005);
    let mut s = rustre_decompiler::AnnotationStore::new();
    s.add(rustre_decompiler::DecompilerAnnotation::comment(0x1000, 0x1010, "c"));
    s.add(rustre_decompiler::DecompilerAnnotation::type_info(0x2000, 0x2004, "int"));
    Ok(ToolResult::text(json!({"hits":s.at_address(probe).len(),"source":"rustre_decompiler::AnnotationStore::at_address"}).to_string()))
} }

pub struct RlibDec2AnnotationStoreByCategoryTool;
impl RlibDec2AnnotationStoreByCategoryTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_annotation_store_by_category".to_string(), description: "AnnotationStore::by_category".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2AnnotationStoreByCategoryTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let mut s = rustre_decompiler::AnnotationStore::new();
    s.add(rustre_decompiler::DecompilerAnnotation::comment(0, 4, "c"));
    s.add(rustre_decompiler::DecompilerAnnotation::type_info(4, 8, "int"));
    Ok(ToolResult::text(json!({"comments":s.by_category(rustre_decompiler::AnnotationCategory::Comment).len(),"types":s.by_category(rustre_decompiler::AnnotationCategory::TypeInfo).len(),"source":"rustre_decompiler::AnnotationStore::by_category"}).to_string()))
} }

pub struct RlibDec2PassRegistryOpsTool;
impl RlibDec2PassRegistryOpsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_pass_registry_ops".to_string(), description: "PassRegistry new/is_empty/len/names".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2PassRegistryOpsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let r = rustre_decompiler::PassRegistry::new();
    Ok(ToolResult::text(json!({"len":r.len(),"is_empty":r.is_empty(),"names":r.names(),"source":"rustre_decompiler::PassRegistry"}).to_string()))
} }

pub struct RlibDec2DefaultPipelineStandardTool;
impl RlibDec2DefaultPipelineStandardTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_default_pipeline_standard".to_string(), description: "DefaultPipelineFactory::standard".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2DefaultPipelineStandardTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let p = rustre_decompiler::DefaultPipelineFactory::standard(rustre_decompiler::DecompOptions::default());
    Ok(ToolResult::text(json!({"pass_count":p.pass_count(),"pass_names":p.pass_names(),"source":"rustre_decompiler::DefaultPipelineFactory::standard"}).to_string()))
} }

pub struct RlibDec2DefaultPipelineDisasmTool;
impl RlibDec2DefaultPipelineDisasmTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_default_pipeline_disasm".to_string(), description: "DefaultPipelineFactory::disassembly_only".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2DefaultPipelineDisasmTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let p = rustre_decompiler::DefaultPipelineFactory::disassembly_only();
    Ok(ToolResult::text(json!({"pass_count":p.pass_count(),"pass_names":p.pass_names(),"source":"rustre_decompiler::DefaultPipelineFactory::disassembly_only"}).to_string()))
} }

pub struct RlibDec2IrLevelDisplayTool;
impl RlibDec2IrLevelDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_ir_level_display".to_string(), description: "IrLevel::Display".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2IrLevelDisplayTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    use rustre_decompiler::IrLevel::*;
    let ls: Vec<String> = [Llil, MlilSsa, Hlil, PseudoC].iter().map(ToString::to_string).collect();
    Ok(ToolResult::text(json!({"levels":ls,"source":"rustre_decompiler::IrLevel"}).to_string()))
} }

pub struct RlibDec2VarStorageDisplayTool;
impl RlibDec2VarStorageDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_var_storage_display".to_string(), description: "VarStorage Display".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2VarStorageDisplayTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    use rustre_decompiler::VarStorage::*;
    let out: Vec<String> = vec![Register("rax".into()).to_string(), Stack(-8).to_string(), Global(0x400000).to_string(), Immediate(42).to_string()];
    Ok(ToolResult::text(json!({"displays":out,"source":"rustre_decompiler::VarStorage"}).to_string()))
} }

pub struct RlibDec2SymbolMapExtendPairsTool;
impl RlibDec2SymbolMapExtendPairsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_symbol_map_extend_pairs".to_string(), description: "SymbolMap extend_pairs + set_xref_count".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2SymbolMapExtendPairsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let arr = args.get("pairs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'pairs'".into()))?;
    let pairs: Vec<(u64, String)> = arr.iter().filter_map(|v| Some((v.get("addr")?.as_u64()?, v.get("name")?.as_str()?.to_string()))).collect();
    let xref = args.get("xref").and_then(Value::as_u64).unwrap_or(3) as usize;
    let mut m = rustre_decompiler::SymbolMap::new();
    let first = pairs.first().map(|(a, _)| *a);
    m.extend_pairs(pairs);
    if let Some(a) = first { m.set_xref_count(a, xref); }
    Ok(ToolResult::text(json!({"len":m.len(),"source":"rustre_decompiler::SymbolMap::extend_pairs"}).to_string()))
} }

pub struct RlibDec2TypepropAllTypedTool;
impl RlibDec2TypepropAllTypedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_typeprop_all_typed".to_string(), description: "TypePropagation::all_typed".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2TypepropAllTypedTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let n = args.get("n").and_then(Value::as_u64).unwrap_or(3) as usize;
    let mut tp = rustre_decompiler::TypePropagation::new();
    for i in 0..n { tp.set_type(format!("v{i}"), "int"); }
    Ok(ToolResult::text(json!({"typed":tp.all_typed().len(),"count":tp.count(),"source":"rustre_decompiler::TypePropagation::all_typed"}).to_string()))
} }

pub struct RlibDec2VarRecoveryAddRegParamTool;
impl RlibDec2VarRecoveryAddRegParamTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_var_recovery_add_reg_param".to_string(), description: "VariableRecovery add_reg_param + add_stack_var".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2VarRecoveryAddRegParamTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let reg = args.get("reg").and_then(Value::as_str).unwrap_or("rdi");
    let pname = args.get("pname").and_then(Value::as_str).unwrap_or("p0");
    let offset = args.get("offset").and_then(Value::as_i64).unwrap_or(-16);
    let sname = args.get("sname").and_then(Value::as_str).unwrap_or("s0");
    let mut vr = rustre_decompiler::VariableRecovery::new();
    vr.add_reg_param(reg, pname);
    vr.add_stack_var(offset, sname);
    Ok(ToolResult::text(json!({"total_vars":vr.total_vars(),"source":"rustre_decompiler::VariableRecovery"}).to_string()))
} }

pub struct RlibDec2CfsFlattenTool;
impl RlibDec2CfsFlattenTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_cfs_flatten".to_string(), description: "ControlFlowStructuring::flatten".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2CfsFlattenTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let lines: Vec<String> = args.get("lines").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_else(|| vec!["a;".into(), "b;".into()]);
    let s = rustre_decompiler::CfStructure::Sequence(lines);
    let out = rustre_decompiler::ControlFlowStructuring::flatten(&[s]);
    Ok(ToolResult::text(json!({"flattened":out,"source":"rustre_decompiler::ControlFlowStructuring::flatten"}).to_string()))
} }

pub struct RlibDec2CfsMakeForTool;
impl RlibDec2CfsMakeForTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_cfs_make_for".to_string(), description: "ControlFlowStructuring::make_for".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2CfsMakeForTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let init = args.get("init").and_then(Value::as_str).unwrap_or("i=0").to_string();
    let cond = args.get("cond").and_then(Value::as_str).unwrap_or("i<10").to_string();
    let step = args.get("step").and_then(Value::as_str).unwrap_or("i++").to_string();
    let body: Vec<String> = args.get("body").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
    let s = rustre_decompiler::ControlFlowStructuring::make_for(init, cond, step, body);
    let flat = rustre_decompiler::ControlFlowStructuring::flatten(&[s]);
    Ok(ToolResult::text(json!({"flattened":flat,"source":"rustre_decompiler::ControlFlowStructuring::make_for"}).to_string()))
} }

pub struct RlibDec2CfsMakeSwitchTool;
impl RlibDec2CfsMakeSwitchTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_cfs_make_switch".to_string(), description: "ControlFlowStructuring::make_switch".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2CfsMakeSwitchTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let expr = args.get("expr").and_then(Value::as_str).unwrap_or("x").to_string();
    let cases = vec![("0".to_string(), vec!["a;".to_string()]), ("1".to_string(), vec!["b;".to_string()])];
    let s = rustre_decompiler::ControlFlowStructuring::make_switch(expr, cases);
    let flat = rustre_decompiler::ControlFlowStructuring::flatten(&[s]);
    Ok(ToolResult::text(json!({"flattened":flat,"source":"rustre_decompiler::ControlFlowStructuring::make_switch"}).to_string()))
} }

pub struct RlibDec2CfsAddStructureTool;
impl RlibDec2CfsAddStructureTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_cfs_add_structure".to_string(), description: "ControlFlowStructuring add_structure/emit".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2CfsAddStructureTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let mut c = rustre_decompiler::ControlFlowStructuring::new();
    c.add_structure(rustre_decompiler::CfStructure::Sequence(vec!["a;".into(), "b;".into()]));
    Ok(ToolResult::text(json!({"count":c.structure_count(),"emit":c.emit(),"source":"rustre_decompiler::ControlFlowStructuring::emit"}).to_string()))
} }

pub struct RlibDec2QualityExpressionDensityTool;
impl RlibDec2QualityExpressionDensityTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_quality_expression_density".to_string(), description: "QualityMetrics expression_density".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2QualityExpressionDensityTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let src = args.get("src").and_then(Value::as_str).unwrap_or("int f(){int a=1+2*3; return a;}");
    let m = rustre_decompiler::QualityMetrics::from_source(src);
    Ok(ToolResult::text(json!({"lines":m.line_count,"statements":m.statement_count,"operators":m.operator_count,"density":m.expression_density(),"source":"rustre_decompiler::QualityMetrics::expression_density"}).to_string()))
} }

pub struct RlibDec2QualityReadabilityScoreTool;
impl RlibDec2QualityReadabilityScoreTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_quality_readability_score".to_string(), description: "QualityMetrics readability_score".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2QualityReadabilityScoreTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let src = args.get("src").and_then(Value::as_str).unwrap_or("int f(){if(x){y;}else{z;} return 0;}");
    let m = rustre_decompiler::QualityMetrics::from_source(src);
    Ok(ToolResult::text(json!({"score":m.readability_score(),"gotos":m.goto_count,"nesting":m.max_nesting,"controls":m.control_constructs,"source":"rustre_decompiler::QualityMetrics::readability_score"}).to_string()))
} }

pub struct RlibDec2NameRecoveryPassTool;
impl RlibDec2NameRecoveryPassTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_name_recovery_pass".to_string(), description: "NameRecoveryPass new+add_symbol+resolve".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2NameRecoveryPassTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
    let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
    let mut p = rustre_decompiler::NameRecoveryPass::new();
    p.add_symbol(addr, name);
    Ok(ToolResult::text(json!({"resolved":p.resolve(addr),"missing":p.resolve(addr.wrapping_add(1)),"source":"rustre_decompiler::NameRecoveryPass"}).to_string()))
} }

pub struct RlibDec2InliningPassIsCandidateTool;
impl RlibDec2InliningPassIsCandidateTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_inlining_pass_is_candidate".to_string(), description: "InliningPass is_candidate".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2InliningPassIsCandidateTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0x1000);
    let body = args.get("body").and_then(Value::as_str).unwrap_or("return 0;").to_string();
    let max = args.get("max").and_then(Value::as_u64).unwrap_or(3) as usize;
    let mut p = rustre_decompiler::InliningPass::new(max);
    p.add_inline_candidate(addr, body);
    Ok(ToolResult::text(json!({"candidate":p.is_candidate(addr),"source":"rustre_decompiler::InliningPass::is_candidate"}).to_string()))
} }

pub struct RlibDec2PluginManagerCountTool;
impl RlibDec2PluginManagerCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_plugin_manager_count".to_string(), description: "DecompilerPluginManager count".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2PluginManagerCountTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let mut m = rustre_decompiler::DecompilerPluginManager::new();
    let reg = m.build_pass_registry();
    m.unload_all();
    Ok(ToolResult::text(json!({"count":m.count(),"passes":m.all_provided_passes().len(),"registry_len":reg.len(),"source":"rustre_decompiler::DecompilerPluginManager"}).to_string()))
} }

pub struct RlibDec2TimingHookTotalTool;
impl RlibDec2TimingHookTotalTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_timing_hook_total".to_string(), description: "TimingHook total_time".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2TimingHookTotalTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let h = rustre_decompiler::TimingHook::new();
    Ok(ToolResult::text(json!({"passes":h.pass_times().len(),"total_ms":h.total_time().as_millis() as u64,"source":"rustre_decompiler::TimingHook"}).to_string()))
} }

pub struct RlibDec2MultibackendStatsTool;
impl RlibDec2MultibackendStatsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_multibackend_stats".to_string(), description: "MultiBackendDecompiler stats".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2MultibackendStatsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let m = rustre_decompiler::MultiBackendDecompiler::new(rustre_decompiler::DecompOptions::default());
    let s = m.stats();
    Ok(ToolResult::text(json!({"backends":m.backend_count(),"success_rate":s.success_rate(),"source":"rustre_decompiler::MultiBackendDecompiler"}).to_string()))
} }

pub struct RlibDec2DecompilationResultIsSuccessTool;
impl RlibDec2DecompilationResultIsSuccessTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_decompilation_result_is_success".to_string(), description: "DecompilationResult is_success".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2DecompilationResultIsSuccessTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let ok = rustre_decompiler::DecompilationResult::Success(rustre_decompiler::DecompiledFunction::new(0x1000, "f", ""));
    let fail = rustre_decompiler::DecompilationResult::Failure { address: 0x2000, message: "boom".into() };
    Ok(ToolResult::text(json!({"ok":ok.is_success(),"fail":fail.is_success(),"source":"rustre_decompiler::DecompilationResult::is_success"}).to_string()))
} }

pub struct RlibDec2InferSignHintsTool;
impl RlibDec2InferSignHintsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_infer_sign_hints".to_string(), description: "infer_register_sign_hints".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2InferSignHintsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let hints = rustre_decompiler::infer_register_sign_hints(&[]);
    Ok(ToolResult::text(json!({"hint_count":hints.len(),"source":"rustre_decompiler::infer_register_sign_hints"}).to_string()))
} }

pub struct RlibDec2CacheInsertGetTool;
impl RlibDec2CacheInsertGetTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_cache_insert_get".to_string(), description: "DecompilerCache insert+get+evict+clear".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2CacheInsertGetTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0x1000);
    let cap = args.get("cap").and_then(Value::as_u64).unwrap_or(4) as usize;
    let mut c = rustre_decompiler::DecompilerCache::new(cap);
    c.insert(rustre_decompiler::DecompiledFunction::new(addr, "f", "return 0;"));
    let after_insert = c.len();
    let hit = c.get(addr).is_some();
    c.evict(addr);
    let after_evict = c.len();
    c.clear();
    Ok(ToolResult::text(json!({"after_insert":after_insert,"hit":hit,"after_evict":after_evict,"is_empty":c.is_empty(),"source":"rustre_decompiler::DecompilerCache"}).to_string()))
} }

pub struct RlibDec2DiagnosticFromPassTool;
impl RlibDec2DiagnosticFromPassTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "rlib_dec2_diagnostic_from_pass".to_string(), description: "DecompilerDiagnostic error/warning + from_pass".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RlibDec2DiagnosticFromPassTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let msg = args.get("msg").and_then(Value::as_str).ok_or_else(|| McpError::InternalError("missing 'msg'".into()))?;
    let pass = args.get("pass").and_then(Value::as_str).unwrap_or("test_pass");
    let e = rustre_decompiler::DecompilerDiagnostic::error(msg).from_pass(pass);
    let w = rustre_decompiler::DecompilerDiagnostic::warning(msg).from_pass(pass);
    Ok(ToolResult::text(json!({"error_msg":e.message,"warn_msg":w.message,"source":"rustre_decompiler::DecompilerDiagnostic"}).to_string()))
} }

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (RlibDec2VariableNewTool::definition(), Box::new(RlibDec2VariableNewTool)),
        (RlibDec2FunctionNewTool::definition(), Box::new(RlibDec2FunctionNewTool)),
        (RlibDec2FunctionWithConfidenceTool::definition(), Box::new(RlibDec2FunctionWithConfidenceTool)),
        (RlibDec2FunctionParametersTool::definition(), Box::new(RlibDec2FunctionParametersTool)),
        (RlibDec2FunctionWithCallSiteTool::definition(), Box::new(RlibDec2FunctionWithCallSiteTool)),
        (RlibDec2StatsSuccessRateTool::definition(), Box::new(RlibDec2StatsSuccessRateTool)),
        (RlibDec2AnnotationCommentTool::definition(), Box::new(RlibDec2AnnotationCommentTool)),
        (RlibDec2AnnotationTypeInfoTool::definition(), Box::new(RlibDec2AnnotationTypeInfoTool)),
        (RlibDec2AnnotationSymbolNameTool::definition(), Box::new(RlibDec2AnnotationSymbolNameTool)),
        (RlibDec2AnnotationStoreAddLenTool::definition(), Box::new(RlibDec2AnnotationStoreAddLenTool)),
        (RlibDec2AnnotationStoreAtAddressTool::definition(), Box::new(RlibDec2AnnotationStoreAtAddressTool)),
        (RlibDec2AnnotationStoreByCategoryTool::definition(), Box::new(RlibDec2AnnotationStoreByCategoryTool)),
        (RlibDec2PassRegistryOpsTool::definition(), Box::new(RlibDec2PassRegistryOpsTool)),
        (RlibDec2DefaultPipelineStandardTool::definition(), Box::new(RlibDec2DefaultPipelineStandardTool)),
        (RlibDec2DefaultPipelineDisasmTool::definition(), Box::new(RlibDec2DefaultPipelineDisasmTool)),
        (RlibDec2IrLevelDisplayTool::definition(), Box::new(RlibDec2IrLevelDisplayTool)),
        (RlibDec2VarStorageDisplayTool::definition(), Box::new(RlibDec2VarStorageDisplayTool)),
        (RlibDec2SymbolMapExtendPairsTool::definition(), Box::new(RlibDec2SymbolMapExtendPairsTool)),
        (RlibDec2TypepropAllTypedTool::definition(), Box::new(RlibDec2TypepropAllTypedTool)),
        (RlibDec2VarRecoveryAddRegParamTool::definition(), Box::new(RlibDec2VarRecoveryAddRegParamTool)),
        (RlibDec2CfsFlattenTool::definition(), Box::new(RlibDec2CfsFlattenTool)),
        (RlibDec2CfsMakeForTool::definition(), Box::new(RlibDec2CfsMakeForTool)),
        (RlibDec2CfsMakeSwitchTool::definition(), Box::new(RlibDec2CfsMakeSwitchTool)),
        (RlibDec2CfsAddStructureTool::definition(), Box::new(RlibDec2CfsAddStructureTool)),
        (RlibDec2QualityExpressionDensityTool::definition(), Box::new(RlibDec2QualityExpressionDensityTool)),
        (RlibDec2QualityReadabilityScoreTool::definition(), Box::new(RlibDec2QualityReadabilityScoreTool)),
        (RlibDec2NameRecoveryPassTool::definition(), Box::new(RlibDec2NameRecoveryPassTool)),
        (RlibDec2InliningPassIsCandidateTool::definition(), Box::new(RlibDec2InliningPassIsCandidateTool)),
        (RlibDec2PluginManagerCountTool::definition(), Box::new(RlibDec2PluginManagerCountTool)),
        (RlibDec2TimingHookTotalTool::definition(), Box::new(RlibDec2TimingHookTotalTool)),
        (RlibDec2MultibackendStatsTool::definition(), Box::new(RlibDec2MultibackendStatsTool)),
        (RlibDec2DecompilationResultIsSuccessTool::definition(), Box::new(RlibDec2DecompilationResultIsSuccessTool)),
        (RlibDec2InferSignHintsTool::definition(), Box::new(RlibDec2InferSignHintsTool)),
        (RlibDec2CacheInsertGetTool::definition(), Box::new(RlibDec2CacheInsertGetTool)),
        (RlibDec2DiagnosticFromPassTool::definition(), Box::new(RlibDec2DiagnosticFromPassTool)),
    ]
}
