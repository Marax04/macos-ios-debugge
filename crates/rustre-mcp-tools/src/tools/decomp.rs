//! MCP wrappers for the rustre-decomp crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{__decomp_parse_int_width};

pub struct DecompRegisterCanonicalTool;

pub struct DecompRegisterWidthBytesTool;

pub struct DecompIsCKeywordTool;

pub struct DecompQualityMetricsFromSourceTool;
impl DecompQualityMetricsFromSourceTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_quality_metrics_from_source".to_string(),
            description: "Compute QualityMetrics (goto/label/line/statement/operator counts, \
                          max_nesting, control_constructs) from pseudo-C source via \
                          rustre_decompiler::QualityMetrics::from_source.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "source": { "type": "string" } },
                "required": ["source"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompQualityMetricsFromSourceTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let src = args.get("source").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'source'".into()))?;
        let m = rustre_decompiler::QualityMetrics::from_source(src);
        Ok(ToolResult::text(json!({
            "goto_count": m.goto_count,
            "label_count": m.label_count,
            "line_count": m.line_count,
            "statement_count": m.statement_count,
            "operator_count": m.operator_count,
            "max_nesting": m.max_nesting,
            "control_constructs": m.control_constructs,
            "source": "rustre_decompiler::QualityMetrics::from_source",
        }).to_string()))
    }
}

pub struct DecompQualityReadabilityScoreTool;
impl DecompQualityReadabilityScoreTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_quality_readability_score".to_string(),
            description: "Compute readability_score (0..=100) and expression_density from \
                          pseudo-C source via rustre_decompiler::QualityMetrics.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "source": { "type": "string" } },
                "required": ["source"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompQualityReadabilityScoreTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let src = args.get("source").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'source'".into()))?;
        let m = rustre_decompiler::QualityMetrics::from_source(src);
        Ok(ToolResult::text(json!({
            "readability_score": m.readability_score(),
            "expression_density": m.expression_density(),
            "goto_count": m.goto_count,
            "max_nesting": m.max_nesting,
            "control_constructs": m.control_constructs,
            "source": "rustre_decompiler::QualityMetrics::readability_score",
        }).to_string()))
    }
}

pub struct DecompPipelinePassCountTool;
impl DecompPipelinePassCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_pipeline_pass_count".to_string(),
            description: "Number of passes in the standard rustre_decompiler::DecompilePipeline \
                          built with DecompOptions::default().".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompPipelinePassCountTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let p = rustre_decompiler::DecompilePipeline::new(
            rustre_decompiler::DecompOptions::default(),
        );
        Ok(ToolResult::text(json!({
            "pass_count": p.pass_count(),
            "source": "rustre_decompiler::DecompilePipeline::pass_count",
        }).to_string()))
    }
}

pub struct DecompCallingConventionFromArchTool;
impl DecompCallingConventionFromArchTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_calling_convention_from_arch".to_string(),
            description: "Infer rustre_decompiler::CallingConvention from an arch string and return integer parameter registers.".to_string(),
            input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}},"required":["arch"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompCallingConventionFromArchTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arch = args.get("arch").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'arch'".into()))?;
        let cc = rustre_decompiler::CallingConvention::from_arch(arch);
        Ok(ToolResult::text(json!({"calling_convention":cc.to_string(),"param_regs":cc.param_regs(),"arch":arch,"source":"rustre_decompiler::CallingConvention::from_arch"}).to_string()))
    }
}

pub struct DecompVariableRecoveryStackNameTool;
impl DecompVariableRecoveryStackNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_variable_recovery_stack_name".to_string(),
            description: "Assign canonical stack-variable name for offset via rustre_decompiler::VariableRecovery::stack_var_name.".to_string(),
            input_schema: json!({"type":"object","properties":{"offset":{"type":"integer"}},"required":["offset"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompVariableRecoveryStackNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let off = args.get("offset").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("missing 'offset'".into()))?;
        let mut vr = rustre_decompiler::VariableRecovery::new();
        let name = vr.stack_var_name(off);
        let fresh = vr.fresh_var();
        Ok(ToolResult::text(json!({"offset":off,"stack_var_name":name,"fresh_var":fresh,"total_vars":vr.total_vars(),"source":"rustre_decompiler::VariableRecovery::stack_var_name"}).to_string()))
    }
}

pub struct DecompTypePropagationAddTool;
impl DecompTypePropagationAddTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_type_propagation_add".to_string(),
            description: "Register type in TypePropagation and query propagate_add via rustre_decompiler::TypePropagation.".to_string(),
            input_schema: json!({"type":"object","properties":{"var":{"type":"string"},"type":{"type":"string"},"rhs_is_const":{"type":"boolean"}},"required":["var","type"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompTypePropagationAddTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let var = args.get("var").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'var'".into()))?;
        let ty = args.get("type").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'type'".into()))?;
        let rhs_is_const = args.get("rhs_is_const").and_then(Value::as_bool).unwrap_or(false);
        let mut tp = rustre_decompiler::TypePropagation::new();
        tp.set_type(var, ty);
        let propagated = tp.propagate_add(var, rhs_is_const);
        Ok(ToolResult::text(json!({"var":var,"type":tp.get_type(var),"propagated_type":propagated,"count":tp.count(),"source":"rustre_decompiler::TypePropagation::propagate_add"}).to_string()))
    }
}

pub struct DecompExpressionRecoveryKnownTool;
impl DecompExpressionRecoveryKnownTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_expression_recovery_known".to_string(),
            description: "Register functions in ExpressionRecovery and look up query via rustre_decompiler::ExpressionRecovery.".to_string(),
            input_schema: json!({"type":"object","properties":{"functions":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"ret_ty":{"type":"string"}},"required":["name","ret_ty"]}},"query":{"type":"string"}},"required":["functions"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompExpressionRecoveryKnownTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let funcs = args.get("functions").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'functions'".into()))?;
        let mut er = rustre_decompiler::ExpressionRecovery::new();
        for f in funcs {
            let n = f.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing name".into()))?;
            let t = f.get("ret_ty").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing ret_ty".into()))?;
            er.register_function(n, t);
        }
        let q = args.get("query").and_then(Value::as_str);
        let ret_ty = q.and_then(|q| er.call_return_type(q).map(str::to_string));
        Ok(ToolResult::text(json!({"known_function_count":er.known_function_count(),"query":q,"return_type":ret_ty,"source":"rustre_decompiler::ExpressionRecovery::call_return_type"}).to_string()))
    }
}

pub struct DecompFunctionNameGeneratorTool;
impl DecompFunctionNameGeneratorTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_function_name_generator".to_string(),
            description: "Produce canonical function name for address via rustre_decompiler::FunctionNameGenerator.".to_string(),
            input_schema: json!({"type":"object","properties":{"address":{"type":"integer"},"hint":{"type":"string"}},"required":["address"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompFunctionNameGeneratorTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?;
        let hint = args.get("hint").and_then(Value::as_str);
        let mut g = rustre_decompiler::FunctionNameGenerator::new();
        let name = g.name_for(addr, hint);
        Ok(ToolResult::text(json!({"address":addr,"hint":hint,"name":name,"count":g.count(),"source":"rustre_decompiler::FunctionNameGenerator::name_for"}).to_string()))
    }
}

pub struct DecompStatsSummaryTool;
impl DecompStatsSummaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_stats_summary".to_string(),
            description: "Build DecompStats and report success_rate and avg_time_ms via rustre_decompiler::DecompStats.".to_string(),
            input_schema: json!({"type":"object","properties":{"functions_decompiled":{"type":"integer"},"functions_failed":{"type":"integer"},"total_time_ms":{"type":"integer"},"ir_nodes":{"type":"integer"},"variables_recovered":{"type":"integer"},"call_sites_found":{"type":"integer"},"cache_hits":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompStatsSummaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut s = rustre_decompiler::DecompStats::default();
        s.functions_decompiled = args.get("functions_decompiled").and_then(Value::as_u64).unwrap_or(0);
        s.functions_failed = args.get("functions_failed").and_then(Value::as_u64).unwrap_or(0);
        s.total_time_ms = args.get("total_time_ms").and_then(Value::as_u64).unwrap_or(0);
        s.ir_nodes = args.get("ir_nodes").and_then(Value::as_u64).unwrap_or(0);
        s.variables_recovered = args.get("variables_recovered").and_then(Value::as_u64).unwrap_or(0);
        s.call_sites_found = args.get("call_sites_found").and_then(Value::as_u64).unwrap_or(0);
        s.cache_hits = args.get("cache_hits").and_then(Value::as_u64).unwrap_or(0);
        Ok(ToolResult::text(json!({"success_rate_pct":s.success_rate(),"avg_time_ms":s.avg_time_ms(),"display":s.to_string(),"source":"rustre_decompiler::DecompStats"}).to_string()))
    }
}

pub struct DecompCacheHitRateTool;
impl DecompCacheHitRateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_cache_hit_rate".to_string(),
            description: "Insert synthetic entries into DecompilerCache, query addresses, report hit_rate via rustre_decompiler::DecompilerCache.".to_string(),
            input_schema: json!({"type":"object","properties":{"capacity":{"type":"integer"},"insert_addresses":{"type":"array","items":{"type":"integer"}},"query_addresses":{"type":"array","items":{"type":"integer"}}},"required":["capacity","insert_addresses","query_addresses"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompCacheHitRateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cap = args.get("capacity").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'capacity'".into()))? as usize;
        let inserts = args.get("insert_addresses").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'insert_addresses'".into()))?;
        let queries = args.get("query_addresses").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'query_addresses'".into()))?;
        let mut cache = rustre_decompiler::DecompilerCache::new(cap);
        for v in inserts {
            let a = v.as_u64().ok_or_else(|| McpError::InvalidParams("insert addr".into()))?;
            cache.insert(rustre_decompiler::DecompiledFunction::new(a, format!("sub_{a:x}"), ""));
        }
        for v in queries {
            let a = v.as_u64().ok_or_else(|| McpError::InvalidParams("query addr".into()))?;
            let _ = cache.get(a);
        }
        Ok(ToolResult::text(json!({"capacity":cap,"len":cache.len(),"hit_count":cache.hit_count(),"miss_count":cache.miss_count(),"hit_rate":cache.hit_rate(),"is_empty":cache.is_empty(),"source":"rustre_decompiler::DecompilerCache::hit_rate"}).to_string()))
    }
}

pub struct DecompCfStructuringMakeIfElseTool;
impl DecompCfStructuringMakeIfElseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_cf_structuring_make_if_else".to_string(),
            description: "Build if/else CfStructure via rustre_decompiler::ControlFlowStructuring::make_if_else and emit lines.".to_string(),
            input_schema: json!({"type":"object","properties":{"cond":{"type":"string"},"then_body":{"type":"array","items":{"type":"string"}},"else_body":{"type":"array","items":{"type":"string"}}},"required":["cond","then_body"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompCfStructuringMakeIfElseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cond = args.get("cond").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'cond'".into()))?.to_string();
        let then_body: Vec<String> = args.get("then_body").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'then_body'".into()))?.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        let else_body: Vec<String> = args.get("else_body").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
        let s = rustre_decompiler::ControlFlowStructuring::make_if_else(cond, then_body, else_body);
        let mut cfs = rustre_decompiler::ControlFlowStructuring::new();
        cfs.add_structure(s);
        let lines = cfs.emit();
        Ok(ToolResult::text(json!({"line_count":lines.len(),"structure_count":cfs.structure_count(),"lines":lines,"source":"rustre_decompiler::ControlFlowStructuring::make_if_else"}).to_string()))
    }
}

pub struct DecompCfFlattenSequencesTool;
impl DecompCfFlattenSequencesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_cf_flatten_sequences".to_string(),
            description: "Flatten Sequence CfStructures via rustre_decompiler::ControlFlowStructuring::flatten.".to_string(),
            input_schema: json!({"type":"object","properties":{"sequences":{"type":"array","items":{"type":"array","items":{"type":"string"}}}},"required":["sequences"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompCfFlattenSequencesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let seqs = args.get("sequences").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'sequences'".into()))?;
        let structs: Vec<rustre_decompiler::CfStructure> = seqs.iter().map(|s| {
            let lines: Vec<String> = s.as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
            rustre_decompiler::CfStructure::Sequence(lines)
        }).collect();
        let flat = rustre_decompiler::ControlFlowStructuring::flatten(&structs);
        Ok(ToolResult::text(json!({"sequence_count":structs.len(),"flat":flat,"line_count":flat.lines().count(),"source":"rustre_decompiler::ControlFlowStructuring::flatten"}).to_string()))
    }
}

pub struct DecompDecompiledFunctionSummaryTool;
impl DecompDecompiledFunctionSummaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_decompiled_function_summary".to_string(),
            description: "Build DecompiledFunction and return summary via rustre_decompiler::DecompiledFunction.".to_string(),
            input_schema: json!({"type":"object","properties":{"address":{"type":"integer"},"name":{"type":"string"},"pseudo_code":{"type":"string"},"confidence":{"type":"integer"},"threshold":{"type":"integer"},"params":{"type":"array","items":{"type":"string"}},"locals":{"type":"array","items":{"type":"string"}},"call_sites":{"type":"array","items":{"type":"integer"}}},"required":["address","name","pseudo_code"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompDecompiledFunctionSummaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?;
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let code = args.get("pseudo_code").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'pseudo_code'".into()))?;
        let mut f = rustre_decompiler::DecompiledFunction::new(addr, name, code);
        if let Some(c) = args.get("confidence").and_then(Value::as_u64) {
            f = f.with_confidence(c.min(255) as u8);
        }
        for p in args.get("params").and_then(Value::as_array).cloned().unwrap_or_default() {
            if let Some(pn) = p.as_str() {
                f = f.with_variable(rustre_decompiler::DecompVariable {
                    name: pn.to_string(),
                    type_str: "uint64_t".to_string(),
                    is_parameter: true,
                    storage: rustre_decompiler::VarStorage::Register("rdi".to_string()),
                });
            }
        }
        for l in args.get("locals").and_then(Value::as_array).cloned().unwrap_or_default() {
            if let Some(ln) = l.as_str() {
                f = f.with_variable(rustre_decompiler::DecompVariable {
                    name: ln.to_string(),
                    type_str: "int64_t".to_string(),
                    is_parameter: false,
                    storage: rustre_decompiler::VarStorage::Stack(-8),
                });
            }
        }
        for cs in args.get("call_sites").and_then(Value::as_array).cloned().unwrap_or_default() {
            if let Some(a) = cs.as_u64() {
                f = f.with_call_site(a);
            }
        }
        let threshold = args.get("threshold").and_then(Value::as_u64).unwrap_or(80).min(255) as u8;
        Ok(ToolResult::text(json!({"address":f.address,"name":f.name,"line_count":f.line_count(),"parameter_count":f.parameters().len(),"local_count":f.locals().len(),"call_sites":f.call_sites,"confidence":f.confidence,"is_high_confidence":f.is_high_confidence(threshold),"source":"rustre_decompiler::DecompiledFunction"}).to_string()))
    }
}

pub struct DecompSymbolMapResolveTool;
impl DecompSymbolMapResolveTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_symbol_map_resolve".to_string(),
            description: "Insert (address,name) bindings into a rustre_decompiler::SymbolMap and resolve a lookup address.".to_string(),
            input_schema: json!({"type":"object","properties":{"bindings":{"type":"array","items":{"type":"object","properties":{"address":{"type":"integer"},"name":{"type":"string"}},"required":["address","name"]}},"lookup":{"type":"integer"},"rust_demangle":{"type":"boolean"}},"required":["bindings","lookup"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompSymbolMapResolveTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_decompiler::SymbolResolver;
        let bindings = args.get("bindings").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'bindings'".into()))?;
        let lookup = args.get("lookup").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lookup'".into()))?;
        let demangle = args.get("rust_demangle").and_then(Value::as_bool).unwrap_or(false);
        let mut sm = rustre_decompiler::SymbolMap::new();
        sm.enable_rust_demangling(demangle);
        for b in bindings {
            let a = b.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("binding address".into()))?;
            let n = b.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("binding name".into()))?;
            sm.insert(a, n);
        }
        let resolved = sm.resolve(lookup);
        Ok(ToolResult::text(json!({"len":sm.len(),"is_empty":sm.is_empty(),"lookup":lookup,"resolved":resolved,"source":"rustre_decompiler::SymbolMap::resolve"}).to_string()))
    }
}

pub struct DecompSymbolMapFromFlirtTool;
impl DecompSymbolMapFromFlirtTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_symbol_map_from_flirt".to_string(),
            description: "Build a rustre_decompiler::SymbolMap from FLIRT-style pairs, attach xref counts, query resolve+xref_count.".to_string(),
            input_schema: json!({"type":"object","properties":{"pairs":{"type":"array","items":{"type":"object","properties":{"address":{"type":"integer"},"name":{"type":"string"}},"required":["address","name"]}},"xrefs":{"type":"array","items":{"type":"object","properties":{"address":{"type":"integer"},"count":{"type":"integer"}},"required":["address","count"]}},"lookup":{"type":"integer"}},"required":["pairs","lookup"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompSymbolMapFromFlirtTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_decompiler::SymbolResolver;
        let pairs = args.get("pairs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'pairs'".into()))?;
        let lookup = args.get("lookup").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lookup'".into()))?;
        let flirt: Vec<(u64,String)> = pairs.iter().filter_map(|p| {
            let a = p.get("address")?.as_u64()?;
            let n = p.get("name")?.as_str()?.to_string();
            Some((a,n))
        }).collect();
        let mut sm = rustre_decompiler::SymbolMap::from_flirt_pairs(flirt);
        if let Some(xr) = args.get("xrefs").and_then(Value::as_array) {
            for x in xr {
                let a = x.get("address").and_then(Value::as_u64).unwrap_or(0);
                let c = x.get("count").and_then(Value::as_u64).unwrap_or(0) as usize;
                sm.set_xref_count(a, c);
            }
        }
        let resolved = sm.resolve(lookup);
        let xref_count = sm.xref_count(lookup);
        Ok(ToolResult::text(json!({"len":sm.len(),"lookup":lookup,"resolved":resolved,"xref_count":xref_count,"source":"rustre_decompiler::SymbolMap::from_flirt_pairs"}).to_string()))
    }
}

pub struct DecompAnnotationStoreByCategoryTool;
impl DecompAnnotationStoreByCategoryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_annotation_store_by_category".to_string(),
            description: "Build AnnotationStore with mixed categories and count via rustre_decompiler::AnnotationStore::by_category.".to_string(),
            input_schema: json!({"type":"object","properties":{"annotations":{"type":"array","items":{"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"},"text":{"type":"string"},"category":{"type":"string","enum":["comment","type_info","symbol_name"]}},"required":["start","end","text","category"]}}},"required":["annotations"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompAnnotationStoreByCategoryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_decompiler::{AnnotationStore, DecompilerAnnotation, AnnotationCategory};
        let anns = args.get("annotations").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'annotations'".into()))?;
        let mut store = AnnotationStore::new();
        for a in anns {
            let s = a.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("ann start".into()))?;
            let e = a.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("ann end".into()))?;
            let t = a.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("ann text".into()))?;
            let cat = a.get("category").and_then(Value::as_str).unwrap_or("comment");
            let ann = match cat {
                "type_info" => DecompilerAnnotation::type_info(s,e,t),
                "symbol_name" => DecompilerAnnotation::symbol_name(s,e,t),
                _ => DecompilerAnnotation::comment(s,e,t),
            };
            store.add(ann);
        }
        let comments = store.by_category(AnnotationCategory::Comment).len();
        let types = store.by_category(AnnotationCategory::TypeInfo).len();
        let symbols = store.by_category(AnnotationCategory::SymbolName).len();
        Ok(ToolResult::text(json!({"total":store.len(),"is_empty":store.is_empty(),"comments":comments,"type_infos":types,"symbol_names":symbols,"source":"rustre_decompiler::AnnotationStore::by_category"}).to_string()))
    }
}

pub struct DecompAnnotationStoreAtAddressTool;
impl DecompAnnotationStoreAtAddressTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_annotation_store_at_address".to_string(),
            description: "Query rustre_decompiler::AnnotationStore::at_address for annotations covering a virtual address.".to_string(),
            input_schema: json!({"type":"object","properties":{"annotations":{"type":"array","items":{"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"},"text":{"type":"string"}},"required":["start","end","text"]}},"address":{"type":"integer"}},"required":["annotations","address"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompAnnotationStoreAtAddressTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_decompiler::{AnnotationStore, DecompilerAnnotation};
        let anns = args.get("annotations").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'annotations'".into()))?;
        let address = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?;
        let mut store = AnnotationStore::new();
        for a in anns {
            let s = a.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("start".into()))?;
            let e = a.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("end".into()))?;
            let t = a.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("text".into()))?;
            store.add(DecompilerAnnotation::comment(s,e,t));
        }
        let hits: Vec<String> = store.at_address(address).iter().map(|a| a.text.clone()).collect();
        Ok(ToolResult::text(json!({"total":store.len(),"address":address,"match_count":hits.len(),"texts":hits,"source":"rustre_decompiler::AnnotationStore::at_address"}).to_string()))
    }
}

pub struct DecompPassRegistryNamesTool;
impl DecompPassRegistryNamesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_pass_registry_names".to_string(),
            description: "Register the built-in decompiler passes via rustre_decompiler::PassRegistry::register.".to_string(),
            input_schema: json!({"type":"object","properties":{"lookup":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompPassRegistryNamesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let lookup = args.get("lookup").and_then(Value::as_str);
        let mut reg = rustre_decompiler::PassRegistry::new();
        reg.register(std::sync::Arc::new(rustre_decompiler::DisassemblyPass));
        reg.register(std::sync::Arc::new(rustre_decompiler::CallSitePass));
        reg.register(std::sync::Arc::new(rustre_decompiler::FunctionHeaderPass));
        reg.register(std::sync::Arc::new(rustre_decompiler::FunctionBodyPass));
        let names: Vec<String> = reg.names().iter().map(|s| (*s).to_string()).collect();
        let found = lookup.map(|n| reg.get(n).is_some());
        Ok(ToolResult::text(json!({"len":reg.len(),"is_empty":reg.is_empty(),"names":names,"lookup":lookup,"found":found,"source":"rustre_decompiler::PassRegistry::register"}).to_string()))
    }
}

pub struct DecompCfDetectLoopTool;
impl DecompCfDetectLoopTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_cf_detect_loop".to_string(),
            description: "Detect a simple loop pattern via rustre_decompiler::ControlFlowStructuring::detect_loop.".to_string(),
            input_schema: json!({"type":"object","properties":{"lines":{"type":"array","items":{"type":"string"}}},"required":["lines"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompCfDetectLoopTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let lines_v = args.get("lines").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'lines'".into()))?;
        let owned: Vec<String> = lines_v.iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        let detected = rustre_decompiler::ControlFlowStructuring::detect_loop(&refs);
        let (found, emitted) = match &detected {
            Some(s) => (true, s.emit_lines(0)),
            None => (false, vec![]),
        };
        Ok(ToolResult::text(json!({"detected":found,"input_line_count":owned.len(),"emitted_line_count":emitted.len(),"emitted":emitted,"source":"rustre_decompiler::ControlFlowStructuring::detect_loop"}).to_string()))
    }
}

pub struct DecompCfFreshGotoLabelTool;
impl DecompCfFreshGotoLabelTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_cf_fresh_goto_label".to_string(),
            description: "Generate N sequential goto labels via rustre_decompiler::ControlFlowStructuring::fresh_goto_label.".to_string(),
            input_schema: json!({"type":"object","properties":{"count":{"type":"integer"}},"required":["count"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompCfFreshGotoLabelTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let count = args.get("count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'count'".into()))? as usize;
        let mut cfs = rustre_decompiler::ControlFlowStructuring::new();
        let labels: Vec<String> = (0..count).map(|_| cfs.fresh_goto_label()).collect();
        Ok(ToolResult::text(json!({"count":count,"labels":labels,"structure_count":cfs.structure_count(),"source":"rustre_decompiler::ControlFlowStructuring::fresh_goto_label"}).to_string()))
    }
}

pub struct DecompCacheEvictClearTool;
impl DecompCacheEvictClearTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_cache_evict_clear".to_string(),
            description: "Exercise rustre_decompiler::DecompilerCache::evict and ::clear.".to_string(),
            input_schema: json!({"type":"object","properties":{"capacity":{"type":"integer"},"insert_addresses":{"type":"array","items":{"type":"integer"}},"evict_addresses":{"type":"array","items":{"type":"integer"}},"query_addresses":{"type":"array","items":{"type":"integer"}}},"required":["capacity","insert_addresses"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompCacheEvictClearTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cap = args.get("capacity").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'capacity'".into()))? as usize;
        let inserts = args.get("insert_addresses").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'insert_addresses'".into()))?;
        let evicts = args.get("evict_addresses").and_then(Value::as_array).cloned().unwrap_or_default();
        let queries = args.get("query_addresses").and_then(Value::as_array).cloned().unwrap_or_default();
        let mut cache = rustre_decompiler::DecompilerCache::new(cap);
        for v in inserts {
            let a = v.as_u64().ok_or_else(|| McpError::InvalidParams("insert addr".into()))?;
            cache.insert(rustre_decompiler::DecompiledFunction::new(a, format!("sub_{a:x}"), ""));
        }
        let len_after_insert = cache.len();
        for v in &evicts {
            if let Some(a) = v.as_u64() { cache.evict(a); }
        }
        let len_after_evict = cache.len();
        for v in &queries {
            if let Some(a) = v.as_u64() { let _ = cache.get(a); }
        }
        let hit = cache.hit_count();
        let miss = cache.miss_count();
        cache.clear();
        Ok(ToolResult::text(json!({"capacity":cap,"len_after_insert":len_after_insert,"len_after_evict":len_after_evict,"len_after_clear":cache.len(),"hit_count":hit,"miss_count":miss,"is_empty_after_clear":cache.is_empty(),"source":"rustre_decompiler::DecompilerCache::evict"}).to_string()))
    }
}

pub struct DecompTypePropagationAllTypedTool;
impl DecompTypePropagationAllTypedTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_type_propagation_all_typed".to_string(),
            description: "List all (variable,type) bindings via rustre_decompiler::TypePropagation::all_typed.".to_string(),
            input_schema: json!({"type":"object","properties":{"bindings":{"type":"array","items":{"type":"object","properties":{"var":{"type":"string"},"type":{"type":"string"}},"required":["var","type"]}}},"required":["bindings"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompTypePropagationAllTypedTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bindings = args.get("bindings").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'bindings'".into()))?;
        let mut tp = rustre_decompiler::TypePropagation::new();
        for b in bindings {
            let v = b.get("var").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("var".into()))?;
            let t = b.get("type").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("type".into()))?;
            tp.set_type(v, t);
        }
        let typed: Vec<(String,String)> = tp.all_typed().into_iter().map(|(a,b)| (a.to_string(), b.to_string())).collect();
        Ok(ToolResult::text(json!({"count":tp.count(),"typed":typed,"source":"rustre_decompiler::TypePropagation::all_typed"}).to_string()))
    }
}

pub struct DecompVariableRecoveryAddRegParamTool;
impl DecompVariableRecoveryAddRegParamTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_variable_recovery_add_reg_param".to_string(),
            description: "Register stack vars and register parameters on rustre_decompiler::VariableRecovery and report emitted lines.".to_string(),
            input_schema: json!({"type":"object","properties":{"stack_vars":{"type":"array","items":{"type":"object","properties":{"offset":{"type":"integer"},"name":{"type":"string"}},"required":["offset","name"]}},"reg_params":{"type":"array","items":{"type":"object","properties":{"reg":{"type":"string"},"name":{"type":"string"}},"required":["reg","name"]}},"indent":{"type":"integer"}},"required":["reg_params"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompVariableRecoveryAddRegParamTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut vr = rustre_decompiler::VariableRecovery::new();
        if let Some(sv) = args.get("stack_vars").and_then(Value::as_array) {
            for s in sv {
                let off = s.get("offset").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("offset".into()))?;
                let name = s.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?;
                vr.add_stack_var(off, name);
            }
        }
        let regs = args.get("reg_params").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'reg_params'".into()))?;
        for r in regs {
            let reg = r.get("reg").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("reg".into()))?;
            let nm = r.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("name".into()))?;
            vr.add_reg_param(reg, nm);
        }
        let _indent = args.get("indent").and_then(Value::as_u64).unwrap_or(0) as usize;
        let fresh1 = vr.fresh_var();
        let fresh2 = vr.fresh_var();
        Ok(ToolResult::text(json!({"total_vars":vr.total_vars(),"fresh_vars":[fresh1,fresh2],"source":"rustre_decompiler::VariableRecovery::add_reg_param"}).to_string()))
    }
}

pub struct DecompSignHintAsBoolTool;
impl DecompSignHintAsBoolTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_sign_hint_as_bool".to_string(),
            description: "Return the as_bool projection for each rustre_decompiler::SignHint variant.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompSignHintAsBoolTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let signed = rustre_decompiler::SignHint::Signed.as_bool();
        let unsigned = rustre_decompiler::SignHint::Unsigned.as_bool();
        let unknown = rustre_decompiler::SignHint::Unknown.as_bool();
        Ok(ToolResult::text(json!({"signed":signed,"unsigned":unsigned,"unknown":unknown,"source":"rustre_decompiler::SignHint::as_bool"}).to_string()))
    }
}

pub struct DecompFunctionNameGeneratorMultiTool;
impl DecompFunctionNameGeneratorMultiTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "decomp_function_name_generator_multi".to_string(),
            description: "Batch-generate names via rustre_decompiler::FunctionNameGenerator::name_for.".to_string(),
            input_schema: json!({"type":"object","properties":{"addresses":{"type":"array","items":{"type":"object","properties":{"address":{"type":"integer"},"hint":{"type":"string"}},"required":["address"]}}},"required":["addresses"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for DecompFunctionNameGeneratorMultiTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addrs = args.get("addresses").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'addresses'".into()))?;
        let mut generator = rustre_decompiler::FunctionNameGenerator::new();
        let mut names: Vec<serde_json::Value> = Vec::new();
        for a in addrs {
            let addr = a.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("address".into()))?;
            let hint = a.get("hint").and_then(Value::as_str);
            let n = generator.name_for(addr, hint);
            names.push(json!({"address":addr,"hint":hint,"name":n}));
        }
        Ok(ToolResult::text(json!({"count":generator.count(),"names":names,"source":"rustre_decompiler::FunctionNameGenerator::name_for"}).to_string()))
    }
}

pub struct DecompTypeCNameIntWpTool;
impl DecompTypeCNameIntWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_c_name_int_wp".to_string(), description: "Return C-like name for DecompType::Int(width).".to_string(), input_schema: json!({"type":"object","properties":{"width":{"type":"string"}},"required":["width"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeCNameIntWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ws = args.get("width").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))?; let w = __decomp_parse_int_width(ws).ok_or_else(|| McpError::InvalidParams("bad width".into()))?; let t = rustre_decompiler_type::DecompType::Int(w); Ok(ToolResult::text(json!({"c_name": t.c_name(), "source":"rustre_decompiler_type::DecompType::c_name"}).to_string())) } }

pub struct DecompTypeBytesizeIntWpTool;
impl DecompTypeBytesizeIntWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_byte_size_int_wp".to_string(), description: "Byte size of DecompType::Int(width).".to_string(), input_schema: json!({"type":"object","properties":{"width":{"type":"string"}},"required":["width"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeBytesizeIntWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ws = args.get("width").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))?; let w = __decomp_parse_int_width(ws).ok_or_else(|| McpError::InvalidParams("bad width".into()))?; let t = rustre_decompiler_type::DecompType::Int(w); Ok(ToolResult::text(json!({"byte_size": t.byte_size(), "source":"rustre_decompiler_type::DecompType::byte_size"}).to_string())) } }

pub struct DecompTypeBytesizePtrWpTool;
impl DecompTypeBytesizePtrWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_byte_size_ptr_wp".to_string(), description: "Byte size of a pointer under given ptr_width.".to_string(), input_schema: json!({"type":"object","properties":{"ptr_width":{"type":"integer"}},"required":["ptr_width"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeBytesizePtrWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pw = args.get("ptr_width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'ptr_width'".into()))? as u8; let t = rustre_decompiler_type::DecompType::Ptr(Box::new(rustre_decompiler_type::DecompType::Void)); Ok(ToolResult::text(json!({"byte_size": t.byte_size_with_ptr_width(pw), "is_pointer": t.is_pointer(), "source":"rustre_decompiler_type::DecompType::byte_size_with_ptr_width"}).to_string())) } }

pub struct DecompTypeAreCompatibleIntsWpTool;
impl DecompTypeAreCompatibleIntsWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_are_compatible_ints_wp".to_string(), description: "Test are_compatible on two DecompType::Int widths.".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}},"required":["a","b"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeAreCompatibleIntsWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = __decomp_parse_int_width(args.get("a").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?).ok_or_else(|| McpError::InvalidParams("bad a".into()))?; let b = __decomp_parse_int_width(args.get("b").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?).ok_or_else(|| McpError::InvalidParams("bad b".into()))?; let ta = rustre_decompiler_type::DecompType::Int(a); let tb = rustre_decompiler_type::DecompType::Int(b); Ok(ToolResult::text(json!({"compatible": rustre_decompiler_type::are_compatible(&ta,&tb), "source":"rustre_decompiler_type::are_compatible"}).to_string())) } }

pub struct DecompTypeIsConvertibleIntsWpTool;
impl DecompTypeIsConvertibleIntsWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_is_convertible_ints_wp".to_string(), description: "Test is_implicitly_convertible on two DecompType::Int widths.".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}},"required":["a","b"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeIsConvertibleIntsWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = __decomp_parse_int_width(args.get("a").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?).ok_or_else(|| McpError::InvalidParams("bad a".into()))?; let b = __decomp_parse_int_width(args.get("b").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?).ok_or_else(|| McpError::InvalidParams("bad b".into()))?; let ta = rustre_decompiler_type::DecompType::Int(a); let tb = rustre_decompiler_type::DecompType::Int(b); Ok(ToolResult::text(json!({"convertible": rustre_decompiler_type::is_implicitly_convertible(&ta,&tb), "source":"rustre_decompiler_type::is_implicitly_convertible"}).to_string())) } }

pub struct DecompTypeEnvSetGetWpTool;
impl DecompTypeEnvSetGetWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_env_set_get_wp".to_string(), description: "TypeEnvironment set then get by name; returns c_name of type.".to_string(), input_schema: json!({"type":"object","properties":{"var":{"type":"string"},"width":{"type":"string"}},"required":["var","width"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeEnvSetGetWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let var = args.get("var").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'var'".into()))?.to_string(); let w = __decomp_parse_int_width(args.get("width").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))?).ok_or_else(|| McpError::InvalidParams("bad width".into()))?; let mut env = rustre_decompiler_type::TypeEnvironment::new(); env.set(var.clone(), rustre_decompiler_type::DecompType::Int(w)); let got = env.get(&var).map(|t| t.c_name()); Ok(ToolResult::text(json!({"var": var, "c_name": got, "source":"rustre_decompiler_type::TypeEnvironment"}).to_string())) } }

pub struct DecompTypeStructFieldAtWpTool;
impl DecompTypeStructFieldAtWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_struct_field_at_wp".to_string(), description: "Build a struct with two int fields and look up field_at(offset).".to_string(), input_schema: json!({"type":"object","properties":{"offset":{"type":"integer"}},"required":["offset"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeStructFieldAtWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let off = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'offset'".into()))?; use rustre_decompiler_type::{StructField, StructType, DecompType}; use rustre_decompiler_expr::IntWidth; let fields = vec![ StructField::new(0, "a", DecompType::Int(IntWidth::I32)), StructField::new(4, "b", DecompType::Int(IntWidth::I32)) ]; let st = StructType::new("S", fields, 8); let f = st.field_at(off).map(|x| x.name.clone()); let exact = st.field_exact(off).map(|x| x.name.clone()); Ok(ToolResult::text(json!({"field_at": f, "field_exact": exact, "source":"rustre_decompiler_type::StructType::field_at"}).to_string())) } }

pub struct DecompTypeDatabaseWindowsCountsWpTool;
impl DecompTypeDatabaseWindowsCountsWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_database_windows_counts_wp".to_string(), description: "TypeDatabase::new + load_windows_types then counts.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeDatabaseWindowsCountsWpTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut db = rustre_decompiler_type::TypeDatabase::new(); db.load_windows_types(); Ok(ToolResult::text(json!({"structs": db.struct_count(), "unions": db.union_count(), "functions": db.function_count(), "typedefs": db.typedef_count(), "source":"rustre_decompiler_type::TypeDatabase::load_windows_types"}).to_string())) } }

pub struct DecompTypeDatabaseLinuxCountsWpTool;
impl DecompTypeDatabaseLinuxCountsWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_database_linux_counts_wp".to_string(), description: "TypeDatabase::new + load_linux_types then counts.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeDatabaseLinuxCountsWpTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut db = rustre_decompiler_type::TypeDatabase::new(); db.load_linux_types(); Ok(ToolResult::text(json!({"structs": db.struct_count(), "unions": db.union_count(), "functions": db.function_count(), "typedefs": db.typedef_count(), "source":"rustre_decompiler_type::TypeDatabase::load_linux_types"}).to_string())) } }

pub struct DecompTypeStdlibDbCountsWpTool;
impl DecompTypeStdlibDbCountsWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_stdlib_db_counts_wp".to_string(), description: "Instantiate stdlib_db() and report counts + emit_all_structs length.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeStdlibDbCountsWpTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let db = rustre_decompiler_type::StandardLibTypes::stdlib_db(); let emitted = db.emit_all_structs(); Ok(ToolResult::text(json!({"structs": db.struct_count(), "unions": db.union_count(), "functions": db.function_count(), "typedefs": db.typedef_count(), "emit_len": emitted.len(), "source":"rustre_decompiler_type::stdlib_db"}).to_string())) } }

pub struct DecompTypeFunctionPrototypeWpTool;
impl DecompTypeFunctionPrototypeWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_function_prototype_wp".to_string(), description: "Build FunctionType, add params, return c_prototype.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"ret_width":{"type":"string"},"params":{"type":"array"}},"required":["name","ret_width"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeFunctionPrototypeWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string(); let rw = __decomp_parse_int_width(args.get("ret_width").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'ret_width'".into()))?).ok_or_else(|| McpError::InvalidParams("bad ret_width".into()))?; let mut f = rustre_decompiler_type::FunctionType::new(name, rustre_decompiler_type::DecompType::Int(rw)); if let Some(arr) = args.get("params").and_then(Value::as_array) { for p in arr { let pn = p.get("name").and_then(Value::as_str).unwrap_or("p").to_string(); let pw = p.get("width").and_then(Value::as_str).and_then(__decomp_parse_int_width).unwrap_or(rustre_decompiler_expr::IntWidth::I32); f.add_param(pn, rustre_decompiler_type::DecompType::Int(pw)); } } Ok(ToolResult::text(json!({"prototype": f.c_prototype(), "source":"rustre_decompiler_type::FunctionType::c_prototype"}).to_string())) } }

pub struct DecompTypeUnionCNameWpTool;
impl DecompTypeUnionCNameWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_union_c_name_wp".to_string(), description: "Build UnionType with two int members and return c_name + total_size.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeUnionCNameWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string(); use rustre_decompiler_type::{StructField, UnionType, DecompType}; use rustre_decompiler_expr::IntWidth; let members = vec![ StructField::new(0, "a", DecompType::Int(IntWidth::I32)), StructField::new(0, "b", DecompType::Int(IntWidth::I64)) ]; let u = UnionType::new(name, members); Ok(ToolResult::text(json!({"c_name": u.c_name(), "total_size": u.total_size, "members": u.members.len(), "source":"rustre_decompiler_type::UnionType::c_name"}).to_string())) } }

pub struct DecompTypeRecoveryRecordGetWpTool;
impl DecompTypeRecoveryRecordGetWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_recovery_record_get_wp".to_string(), description: "TypeRecovery: record int at addr then get + count.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"width":{"type":"string"}},"required":["addr","width"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeRecoveryRecordGetWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let w = __decomp_parse_int_width(args.get("width").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))?).ok_or_else(|| McpError::InvalidParams("bad width".into()))?; let mut r = rustre_decompiler_type::TypeRecovery::new(); r.record(addr, rustre_decompiler_type::DecompType::Int(w)); let got = r.get(addr).map(|t| t.c_name()); Ok(ToolResult::text(json!({"addr": addr, "c_name": got, "count": r.count(), "source":"rustre_decompiler_type::TypeRecovery"}).to_string())) } }

pub struct DecompTypeRecoveryFromAccessSizeWpTool;
impl DecompTypeRecoveryFromAccessSizeWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_recovery_from_access_size_wp".to_string(), description: "TypeRecovery::infer_from_access_size then read c_name.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"bytes":{"type":"integer"}},"required":["addr","bytes"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeRecoveryFromAccessSizeWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let bytes = args.get("bytes").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bytes'".into()))? as u8; let mut r = rustre_decompiler_type::TypeRecovery::new(); r.infer_from_access_size(addr, bytes); let got = r.get(addr).map(|t| t.c_name()); Ok(ToolResult::text(json!({"addr": addr, "bytes": bytes, "c_name": got, "count": r.count(), "source":"rustre_decompiler_type::TypeRecovery::infer_from_access_size"}).to_string())) } }

pub struct DecompTypePointerAnalysisAliasWpTool;
impl DecompTypePointerAnalysisAliasWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_pointer_analysis_alias_wp".to_string(), description: "PointerAnalysis: record_may_alias(a,b) then may_alias_with(a).".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}},"required":["a","b"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypePointerAnalysisAliasWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = args.get("a").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?.to_string(); let b = args.get("b").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?.to_string(); let mut pa = rustre_decompiler_type::PointerAnalysis::new(); pa.record_may_alias(a.clone(), b.clone()); let aliases: Vec<String> = pa.may_alias_with(&a).iter().map(|s| (*s).to_string()).collect(); Ok(ToolResult::text(json!({"a": a, "b": b, "aliases_of_a": aliases, "source":"rustre_decompiler_type::PointerAnalysis::may_alias_with"}).to_string())) } }

pub struct DecompTypePointerAnalysisNotNullWpTool;
impl DecompTypePointerAnalysisNotNullWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_pointer_analysis_not_null_wp".to_string(), description: "PointerAnalysis: record_points_to then is_definitely_not_null + points_to_targets.".to_string(), input_schema: json!({"type":"object","properties":{"ptr":{"type":"string"},"target":{"type":"string"}},"required":["ptr","target"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypePointerAnalysisNotNullWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ptr = args.get("ptr").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'ptr'".into()))?.to_string(); let target = args.get("target").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'target'".into()))?.to_string(); let mut pa = rustre_decompiler_type::PointerAnalysis::new(); pa.record_points_to(ptr.clone(), target.clone()); let targets: Vec<String> = pa.points_to_targets(&ptr).to_vec(); Ok(ToolResult::text(json!({"ptr": ptr, "target": target, "not_null": pa.is_definitely_not_null(&ptr), "targets": targets, "source":"rustre_decompiler_type::PointerAnalysis::is_definitely_not_null"}).to_string())) } }

pub struct DecompTypeAccessWidthSizerWpTool;
impl DecompTypeAccessWidthSizerWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_access_width_sizer_wp".to_string(), description: "AccessWidthSizer: observe(var,bytes), mark_signed, then infer.".to_string(), input_schema: json!({"type":"object","properties":{"var":{"type":"string"},"bytes":{"type":"integer"},"signed":{"type":"boolean"}},"required":["var","bytes"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeAccessWidthSizerWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let var = args.get("var").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'var'".into()))?.to_string(); let bytes = args.get("bytes").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bytes'".into()))? as u8; let signed = args.get("signed").and_then(Value::as_bool).unwrap_or(false); let mut s = rustre_decompiler_type::AccessWidthSizer::new(); s.observe(var.clone(), bytes); if signed { s.mark_signed(var.clone()); } let inferred = s.infer(&var).map(|t| t.c_name()); Ok(ToolResult::text(json!({"var": var, "bytes": bytes, "signed": signed, "c_name": inferred, "count": s.count(), "vars": s.vars(), "source":"rustre_decompiler_type::AccessWidthSizer::infer"}).to_string())) } }

pub struct DecompTypeUnifierCanonicalWpTool;
impl DecompTypeUnifierCanonicalWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_unifier_canonical_wp".to_string(), description: "TypeUnifier: add TypeConstraint(a,b) then canonical(a) + class count.".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}},"required":["a","b"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeUnifierCanonicalWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = args.get("a").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?.to_string(); let b = args.get("b").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?.to_string(); let c = rustre_decompiler_type::TypeConstraint::new(a.clone(), b.clone(), "unify"); let mut u = rustre_decompiler_type::TypeUnifier::new(); u.add_constraint(&c); let canon_a = u.canonical(&a); let classes = u.equivalence_classes(); Ok(ToolResult::text(json!({"a": a, "b": b, "canonical_a": canon_a, "num_classes": classes.len(), "source":"rustre_decompiler_type::TypeUnifier::canonical"}).to_string())) } }

pub struct DecompTypeInferenceAssignmentWpTool;
impl DecompTypeInferenceAssignmentWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_inference_assignment_wp".to_string(), description: "TypeInference::infer_assignment then get_type + type_count.".to_string(), input_schema: json!({"type":"object","properties":{"dst":{"type":"string"},"width":{"type":"string"}},"required":["dst","width"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeInferenceAssignmentWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let dst = args.get("dst").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'dst'".into()))?.to_string(); let w = __decomp_parse_int_width(args.get("width").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))?).ok_or_else(|| McpError::InvalidParams("bad width".into()))?; let mut ti = rustre_decompiler_type::TypeInference::new(); ti.infer_assignment(&dst, rustre_decompiler_type::DecompType::Int(w)); let got = ti.get_type(&dst).map(|t| t.c_name()); Ok(ToolResult::text(json!({"dst": dst, "c_name": got, "type_count": ti.type_count(), "source":"rustre_decompiler_type::TypeInference::infer_assignment"}).to_string())) } }

pub struct DecompTypePropagatorAssignWpTool;
impl DecompTypePropagatorAssignWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_propagator_assign_wp".to_string(), description: "TypePropagator::seed then propagate_through_assign then get.".to_string(), input_schema: json!({"type":"object","properties":{"src":{"type":"string"},"dst":{"type":"string"},"width":{"type":"string"}},"required":["src","dst","width"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypePropagatorAssignWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let src = args.get("src").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'src'".into()))?.to_string(); let dst = args.get("dst").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'dst'".into()))?.to_string(); let w = __decomp_parse_int_width(args.get("width").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))?).ok_or_else(|| McpError::InvalidParams("bad width".into()))?; let mut tp = rustre_decompiler_type::TypePropagator::new(); tp.seed(src.clone(), rustre_decompiler_type::DecompType::Int(w)); tp.propagate_through_assign(&dst, &src); let got = tp.get(&dst).map(|t| t.c_name()); Ok(ToolResult::text(json!({"src": src, "dst": dst, "dst_c_name": got, "source":"rustre_decompiler_type::TypePropagator::propagate_through_assign"}).to_string())) } }

pub struct DecompTypeQualifierFlagsWpTool;
impl DecompTypeQualifierFlagsWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_qualifier_flags_wp".to_string(), description: "TypeQualifier: with_const/with_volatile/with_restrict + qualifier_string.".to_string(), input_schema: json!({"type":"object","properties":{"c":{"type":"boolean"},"v":{"type":"boolean"},"r":{"type":"boolean"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeQualifierFlagsWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let c = args.get("c").and_then(Value::as_bool).unwrap_or(false); let v = args.get("v").and_then(Value::as_bool).unwrap_or(false); let r = args.get("r").and_then(Value::as_bool).unwrap_or(false); let mut q = rustre_decompiler_type::TypeQualifier::NONE; if c { q = q.with_const(); } if v { q = q.with_volatile(); } if r { q = q.with_restrict(); } Ok(ToolResult::text(json!({"is_const": q.is_const(), "is_volatile": q.is_volatile(), "is_restrict": q.is_restrict(), "qualifier_string": q.qualifier_string(), "source":"rustre_decompiler_type::TypeQualifier"}).to_string())) } }

pub struct DecompTypeLayoutPaddedSizeWpTool;
impl DecompTypeLayoutPaddedSizeWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_layout_padded_size_wp".to_string(), description: "TypeLayout::for_struct then padded_size.".to_string(), input_schema: json!({"type":"object","properties":{"total_size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeLayoutPaddedSizeWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let total = args.get("total_size").and_then(Value::as_u64).unwrap_or(9); use rustre_decompiler_type::{StructField, StructType, DecompType, TypeLayout}; use rustre_decompiler_expr::IntWidth; let fields = vec![ StructField::new(0, "a", DecompType::Int(IntWidth::I32)), StructField::new(4, "b", DecompType::Int(IntWidth::I32)) ]; let st = StructType::new("S", fields, total); let layout = TypeLayout::for_struct(&st); Ok(ToolResult::text(json!({"size": layout.size, "alignment": layout.alignment, "padded_size": layout.padded_size(), "num_fields": layout.field_offsets.len(), "source":"rustre_decompiler_type::TypeLayout::padded_size"}).to_string())) } }

pub struct DecompTypeCtypeEmitTypedefWpTool;
impl DecompTypeCtypeEmitTypedefWpTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_ctype_emit_typedef_wp".to_string(), description: "CTypeEmitter::emit_typedef for an int alias.".to_string(), input_schema: json!({"type":"object","properties":{"alias":{"type":"string"},"width":{"type":"string"}},"required":["alias","width"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DecompTypeCtypeEmitTypedefWpTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let alias = args.get("alias").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'alias'".into()))?.to_string(); let w = __decomp_parse_int_width(args.get("width").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))?).ok_or_else(|| McpError::InvalidParams("bad width".into()))?; let em = rustre_decompiler_type::CTypeEmitter::new(); let out = em.emit_typedef(&alias, &rustre_decompiler_type::DecompType::Int(w)); Ok(ToolResult::text(json!({"typedef": out, "source":"rustre_decompiler_type::CTypeEmitter::emit_typedef"}).to_string())) } }

pub struct DecompXRegisterWidthBatchTool;
impl DecompXRegisterWidthBatchTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_x_register_width_batch".to_string(), description: "Batch: rustre_decompiler::x86_register_width::register_width_bytes over an array of register names.".to_string(), input_schema: json!({"type":"object","properties":{"regs":{"type":"array","items":{"type":"string"}}},"required":["regs"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for DecompXRegisterWidthBatchTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let regs = args.get("regs").and_then(Value::as_array).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'regs'".into()))?; let widths: Vec<Value> = regs.iter().filter_map(Value::as_str).map(|r| json!({"reg": r, "width_bytes": rustre_decompiler::x86_register_width::register_width_bytes(r)})).collect(); Ok(ToolResult::text(json!({"widths": widths, "source": "rustre_decompiler::x86_register_width::register_width_bytes"}).to_string())) } }

pub struct DecompXRegisterCanonicalBatchTool;
impl DecompXRegisterCanonicalBatchTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_x_register_canonical_batch".to_string(), description: "Batch: rustre_decompiler::x86_register_width::register_canonical over an array of register names.".to_string(), input_schema: json!({"type":"object","properties":{"regs":{"type":"array","items":{"type":"string"}}},"required":["regs"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for DecompXRegisterCanonicalBatchTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let regs = args.get("regs").and_then(Value::as_array).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'regs'".into()))?; let out: Vec<Value> = regs.iter().filter_map(Value::as_str).map(|r| json!({"reg": r, "canonical": rustre_decompiler::x86_register_width::register_canonical(r)})).collect(); Ok(ToolResult::text(json!({"canonical": out, "source": "rustre_decompiler::x86_register_width::register_canonical"}).to_string())) } }

pub struct DecompXWidthHintBatchTool;
impl DecompXWidthHintBatchTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_x_width_hint_batch".to_string(), description: "Batch: rustre_decompiler::x86_register_width::width_hint_from_instr over (mnemonic, operands) pairs.".to_string(), input_schema: json!({"type":"object","properties":{"instrs":{"type":"array","items":{"type":"object","properties":{"mnemonic":{"type":"string"},"operands":{"type":"string"}}}}},"required":["instrs"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for DecompXWidthHintBatchTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let instrs = args.get("instrs").and_then(Value::as_array).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'instrs'".into()))?; let hints: Vec<Value> = instrs.iter().map(|it| { let m = it.get("mnemonic").and_then(Value::as_str).unwrap_or(""); let o = it.get("operands").and_then(Value::as_str).unwrap_or(""); json!({"mnemonic": m, "operands": o, "hint": rustre_decompiler::x86_register_width::width_hint_from_instr(m, o)}) }).collect(); Ok(ToolResult::text(json!({"hints": hints, "source": "rustre_decompiler::x86_register_width::width_hint_from_instr"}).to_string())) } }

pub struct DecompXIsCKeywordBatchTool;
impl DecompXIsCKeywordBatchTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_x_is_c_keyword_batch".to_string(), description: "Batch: rustre_decompiler::pseudocode_generator::is_c_keyword over identifiers with keyword_count summary.".to_string(), input_schema: json!({"type":"object","properties":{"names":{"type":"array","items":{"type":"string"}}},"required":["names"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for DecompXIsCKeywordBatchTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let names = args.get("names").and_then(Value::as_array).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'names'".into()))?; let mut kw = 0usize; let out: Vec<Value> = names.iter().filter_map(Value::as_str).map(|n| { let b = rustre_decompiler::pseudocode_generator::is_c_keyword(n); if b { kw += 1; } json!({"name": n, "is_keyword": b}) }).collect(); Ok(ToolResult::text(json!({"items": out, "keyword_count": kw, "source": "rustre_decompiler::pseudocode_generator::is_c_keyword"}).to_string())) } }

pub struct DecompXParseMemOperandsCountTool;
impl DecompXParseMemOperandsCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_x_parse_mem_operands_count".to_string(), description: "rustre_decompiler::mem_operand::parse_mem_operands: return count, displacements, and sizes for Intel-syntax operands.".to_string(), input_schema: json!({"type":"object","properties":{"operands":{"type":"string"}},"required":["operands"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for DecompXParseMemOperandsCountTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let ops = args.get("operands").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'operands'".into()))?; let v = rustre_decompiler::mem_operand::parse_mem_operands(ops); Ok(ToolResult::text(json!({"operands": ops, "count": v.len(), "displacements": v.iter().map(|m| m.displacement).collect::<Vec<_>>(), "sizes": v.iter().map(|m| m.size_bytes).collect::<Vec<_>>(), "source": "rustre_decompiler::mem_operand::parse_mem_operands"}).to_string())) } }

pub struct DecompXParseMemOperandsPrefixesTool;
impl DecompXParseMemOperandsPrefixesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_x_parse_mem_operands_prefixes".to_string(), description: "rustre_decompiler::mem_operand::parse_mem_operands + BaseKind::ident_prefix: list identifier prefixes for each parsed memory reference.".to_string(), input_schema: json!({"type":"object","properties":{"operands":{"type":"string"}},"required":["operands"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for DecompXParseMemOperandsPrefixesTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let ops = args.get("operands").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'operands'".into()))?; let v = rustre_decompiler::mem_operand::parse_mem_operands(ops); let prefixes: Vec<String> = v.iter().map(|m| m.base.ident_prefix()).collect(); Ok(ToolResult::text(json!({"count": v.len(), "prefixes": prefixes, "source": "rustre_decompiler::mem_operand::BaseKind::ident_prefix"}).to_string())) } }

pub struct DecompXCallconvLiftMnemonicCountTool;
impl DecompXCallconvLiftMnemonicCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_x_callconv_lift_mnemonic_count".to_string(), description: "rustre_decompiler::callconv_bridge::lift_mnemonic: return count of lifted DetectInstr for a mnemonic+operands.".to_string(), input_schema: json!({"type":"object","properties":{"mnemonic":{"type":"string"},"operands":{"type":"string"}},"required":["mnemonic"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for DecompXCallconvLiftMnemonicCountTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let m = args.get("mnemonic").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'mnemonic'".into()))?; let o = args.get("operands").and_then(Value::as_str).unwrap_or(""); let v = rustre_decompiler::callconv_bridge::lift_mnemonic(m, o); Ok(ToolResult::text(json!({"mnemonic": m, "operands": o, "count": v.len(), "source": "rustre_decompiler::callconv_bridge::lift_mnemonic"}).to_string())) } }

pub struct DecompXCallconvArchFromStrRoundtripTool;
impl DecompXCallconvArchFromStrRoundtripTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_x_callconv_arch_from_str_roundtrip".to_string(), description: "rustre_decompiler::callconv_bridge::arch_from_str: normalize a batch of arch strings.".to_string(), input_schema: json!({"type":"object","properties":{"arches":{"type":"array","items":{"type":"string"}}},"required":["arches"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for DecompXCallconvArchFromStrRoundtripTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let arches = args.get("arches").and_then(Value::as_array).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'arches'".into()))?; let out: Vec<Value> = arches.iter().filter_map(Value::as_str).map(|s| json!({"input": s, "arch": format!("{:?}", rustre_decompiler::callconv_bridge::arch_from_str(s))})).collect(); Ok(ToolResult::text(json!({"items": out, "source": "rustre_decompiler::callconv_bridge::arch_from_str"}).to_string())) } }

pub struct DecompXLoadBinaryInfoTool;
impl DecompXLoadBinaryInfoTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_x_load_binary_info".to_string(), description: "rustre_decompiler::load_binary: return arch, bits, base_address, section count, byte length.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for DecompXLoadBinaryInfoTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let path = args.get("path").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'path'".into()))?; let load = rustre_decompiler::load_binary(std::path::Path::new(path)).map_err(|e| rustre_mcp_server::McpError::InternalError(format!("load: {e}")))?; Ok(ToolResult::text(json!({"path": path, "arch": load.arch, "bits": load.bits, "base_address": load.base_address, "sections": load.sections.len(), "bytes": load.data.len(), "source": "rustre_decompiler::load_binary"}).to_string())) } }

pub struct DecompXDetectFunctionsCountTool;
impl DecompXDetectFunctionsCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_x_detect_functions_count".to_string(), description: "rustre_decompiler::load_binary + detect_functions_in_load: number of detected function boundaries.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for DecompXDetectFunctionsCountTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let path = args.get("path").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'path'".into()))?; let load = rustre_decompiler::load_binary(std::path::Path::new(path)).map_err(|e| rustre_mcp_server::McpError::InternalError(format!("load: {e}")))?; let funcs = rustre_decompiler::detect_functions_in_load(&load); Ok(ToolResult::text(json!({"path": path, "function_count": funcs.len(), "source": "rustre_decompiler::detect_functions_in_load"}).to_string())) } }

pub struct DecompXSliceAtVaLenTool;
impl DecompXSliceAtVaLenTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_x_slice_at_va_len".to_string(), description: "rustre_decompiler::slice_at_va: return (base_va, slice length) for a virtual address in a loaded binary.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"va":{"type":"integer"}},"required":["path","va"]}), parameters: Value::Null } } }
#[async_trait::async_trait] impl ToolHandler for DecompXSliceAtVaLenTool { async fn call(&self, args: Value) -> Result<ToolResult, rustre_mcp_server::McpError> { let path = args.get("path").and_then(Value::as_str).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'path'".into()))?; let va = args.get("va").and_then(Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'va'".into()))?; let load = rustre_decompiler::load_binary(std::path::Path::new(path)).map_err(|e| rustre_mcp_server::McpError::InternalError(format!("load: {e}")))?; let hit = rustre_decompiler::slice_at_va(&load, va); Ok(ToolResult::text(json!({"path": path, "va": va, "hit": hit.is_some(), "base_va": hit.as_ref().map(|(b,_)| *b), "len": hit.as_ref().map(|(_,s)| s.len()), "source": "rustre_decompiler::slice_at_va"}).to_string())) } }

pub struct DecompStatsSuccessRateDcx1Tool;
impl DecompStatsSuccessRateDcx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_stats_success_rate_dcx1".to_string(), description: "DecompStats::success_rate/avg_time_ms via rustre_decompiler::DecompStats.".to_string(), input_schema: json!({"type":"object","properties":{"decompiled":{"type":"integer"},"failed":{"type":"integer"},"total_time_ms":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompStatsSuccessRateDcx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let d = args.get("decompiled").and_then(Value::as_u64).unwrap_or(0); let f = args.get("failed").and_then(Value::as_u64).unwrap_or(0); let t = args.get("total_time_ms").and_then(Value::as_u64).unwrap_or(0); let s = rustre_decompiler::DecompStats { functions_decompiled: d, functions_failed: f, total_time_ms: t, ir_nodes: 0, variables_recovered: 0, call_sites_found: 0, cache_hits: 0 }; Ok(ToolResult::text(json!({"success_rate":s.success_rate(),"avg_time_ms":s.avg_time_ms(),"source":"rustre_decompiler::DecompStats"}).to_string())) } }

pub struct DecompSymbolMapInsertResolveDcx1Tool;
impl DecompSymbolMapInsertResolveDcx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_symbol_map_insert_resolve_dcx1".to_string(), description: "SymbolMap insert+len+resolve via rustre_decompiler::SymbolMap.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"name":{"type":"string"}},"required":["addr","name"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompSymbolMapInsertResolveDcx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_decompiler::SymbolResolver; let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string(); let mut m = rustre_decompiler::SymbolMap::new(); m.insert(addr, name.clone()); m.set_xref_count(addr, 3); Ok(ToolResult::text(json!({"len":m.len(),"is_empty":m.is_empty(),"resolved":m.resolve(addr),"xref_count":m.xref_count(addr),"source":"rustre_decompiler::SymbolMap"}).to_string())) } }

pub struct DecompSymbolMapFromFlirtPairsDcx1Tool;
impl DecompSymbolMapFromFlirtPairsDcx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_symbol_map_from_flirt_pairs_dcx1".to_string(), description: "SymbolMap::from_flirt_pairs via rustre_decompiler::SymbolMap.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompSymbolMapFromFlirtPairsDcx1Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let pairs: Vec<(u64, String)> = vec![(0x1000, "core::mem::swap".to_string()), (0x2000, "alloc::vec::Vec::push".to_string())]; let m = rustre_decompiler::SymbolMap::from_flirt_pairs(pairs); Ok(ToolResult::text(json!({"len":m.len(),"source":"rustre_decompiler::SymbolMap::from_flirt_pairs"}).to_string())) } }

pub struct DecompTypePropagationPropagateAddDcx1Tool;
impl DecompTypePropagationPropagateAddDcx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_type_propagation_propagate_add_dcx1".to_string(), description: "TypePropagation set_type+get_type+propagate_add via rustre_decompiler::TypePropagation.".to_string(), input_schema: json!({"type":"object","properties":{"var":{"type":"string"},"ty":{"type":"string"}},"required":["var","ty"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypePropagationPropagateAddDcx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let var = args.get("var").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'var'".into()))?.to_string(); let ty = args.get("ty").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'ty'".into()))?.to_string(); let mut tp = rustre_decompiler::TypePropagation::new(); tp.set_type(var.clone(), ty.clone()); Ok(ToolResult::text(json!({"count":tp.count(),"get_type":tp.get_type(&var),"propagate_add":tp.propagate_add(&var,true),"all_typed":tp.all_typed().into_iter().map(|(k,v)|(k.to_string(),v.to_string())).collect::<Vec<_>>(),"source":"rustre_decompiler::TypePropagation"}).to_string())) } }

pub struct DecompVariableRecoveryFreshVarDcx1Tool;
impl DecompVariableRecoveryFreshVarDcx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_variable_recovery_fresh_var_dcx1".to_string(), description: "VariableRecovery fresh_var + stack_var_name + total_vars via rustre_decompiler::VariableRecovery.".to_string(), input_schema: json!({"type":"object","properties":{"offset":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompVariableRecoveryFreshVarDcx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let off = args.get("offset").and_then(Value::as_i64).unwrap_or(-8); let mut vr = rustre_decompiler::VariableRecovery::new(); let a = vr.fresh_var(); let b = vr.fresh_var(); let name = vr.stack_var_name(off); vr.add_reg_param("rdi", "param0"); Ok(ToolResult::text(json!({"fresh_a":a,"fresh_b":b,"stack_name":name,"total_vars":vr.total_vars(),"source":"rustre_decompiler::VariableRecovery"}).to_string())) } }

pub struct DecompExpressionRecoveryRegisterDcx1Tool;
impl DecompExpressionRecoveryRegisterDcx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_expression_recovery_register_dcx1".to_string(), description: "ExpressionRecovery register_function + call_return_type + count via rustre_decompiler::ExpressionRecovery.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"ret":{"type":"string"}},"required":["name","ret"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompExpressionRecoveryRegisterDcx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string(); let r = args.get("ret").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'ret'".into()))?.to_string(); let mut er = rustre_decompiler::ExpressionRecovery::new(); er.register_function(n.clone(), r.clone()); Ok(ToolResult::text(json!({"count":er.known_function_count(),"call_return_type":er.call_return_type(&n),"source":"rustre_decompiler::ExpressionRecovery"}).to_string())) } }

pub struct DecompCallingConventionFromArchDcx1Tool;
impl DecompCallingConventionFromArchDcx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_calling_convention_from_arch_dcx1".to_string(), description: "CallingConvention::from_arch + param_regs via rustre_decompiler::CallingConvention.".to_string(), input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}},"required":["arch"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompCallingConventionFromArchDcx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = args.get("arch").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'arch'".into()))?.to_string(); let cc = rustre_decompiler::CallingConvention::from_arch(&a); Ok(ToolResult::text(json!({"cc":format!("{:?}",cc),"param_regs":cc.param_regs(),"source":"rustre_decompiler::CallingConvention::from_arch"}).to_string())) } }

pub struct DecompFunctionNameGeneratorHintDcx1Tool;
impl DecompFunctionNameGeneratorHintDcx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_function_name_generator_hint_dcx1".to_string(), description: "FunctionNameGenerator::name_for with/without hint via rustre_decompiler::FunctionNameGenerator.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"hint":{"type":"string"}},"required":["addr"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompFunctionNameGeneratorHintDcx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let hint = args.get("hint").and_then(Value::as_str); let mut g = rustre_decompiler::FunctionNameGenerator::new(); let a = g.name_for(addr, None); let b = g.name_for(addr.wrapping_add(0x10), hint); Ok(ToolResult::text(json!({"no_hint":a,"with_hint":b,"count":g.count(),"source":"rustre_decompiler::FunctionNameGenerator::name_for"}).to_string())) } }

pub struct DecompDecompilationResultIsSuccessDcx1Tool;
impl DecompDecompilationResultIsSuccessDcx1Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_decompilation_result_is_success_dcx1".to_string(), description: "DecompilationResult::is_success for Success/Failure via rustre_decompiler::DecompilationResult.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompDecompilationResultIsSuccessDcx1Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0x1000); let ok = rustre_decompiler::DecompilationResult::Success(rustre_decompiler::DecompiledFunction::new(addr, "sub_x", "return 0;\n")); let err = rustre_decompiler::DecompilationResult::Failure { address: addr, message: "boom".to_string() }; Ok(ToolResult::text(json!({"success_is_success":ok.is_success(),"failure_is_success":err.is_success(),"source":"rustre_decompiler::DecompilationResult::is_success"}).to_string())) } }

pub struct DecompTypeIntByteSizeWireTool; impl DecompTypeIntByteSizeWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_type_int_byte_size_wire".to_string(), description: "DecompType::Int width byte_size.".to_string(), input_schema: json!({"type":"object","properties":{"width":{"type":"string"}},"required":["width"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeIntByteSizeWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let w = args.get("width").and_then(Value::as_str).unwrap_or("i32"); let iw = match w { "i8"=>rustre_decompiler_expr::IntWidth::I8, "i16"=>rustre_decompiler_expr::IntWidth::I16, "i32"=>rustre_decompiler_expr::IntWidth::I32, "i64"=>rustre_decompiler_expr::IntWidth::I64, "u8"=>rustre_decompiler_expr::IntWidth::U8, "u16"=>rustre_decompiler_expr::IntWidth::U16, "u32"=>rustre_decompiler_expr::IntWidth::U32, "u64"=>rustre_decompiler_expr::IntWidth::U64, _=>return Err(McpError::InvalidParams(format!("bad width {w}"))) }; let ty = rustre_decompiler_type::DecompType::Int(iw); Ok(ToolResult::text(json!({"c_name":ty.c_name(),"byte_size":ty.byte_size(),"is_pointer":ty.is_pointer(),"source":"rustre_decompiler_type::DecompType::byte_size"}).to_string())) } }

pub struct DecompTypePtrWidthWireTool; impl DecompTypePtrWidthWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_type_ptr_width_wire".to_string(), description: "DecompType::Ptr byte_size_with_ptr_width.".to_string(), input_schema: json!({"type":"object","properties":{"ptr_width":{"type":"integer"}},"required":["ptr_width"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypePtrWidthWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pw = u8::try_from(args.get("ptr_width").and_then(Value::as_u64).unwrap_or(8)).unwrap_or(8); let ty = rustre_decompiler_type::DecompType::Ptr(Box::new(rustre_decompiler_type::DecompType::Void)); Ok(ToolResult::text(json!({"byte_size":ty.byte_size_with_ptr_width(pw),"c_name":ty.c_name(),"is_pointer":ty.is_pointer(),"name_prefix":ty.name_prefix(),"source":"rustre_decompiler_type::DecompType::byte_size_with_ptr_width"}).to_string())) } }

pub struct DecompTypeArraySizeWireTool; impl DecompTypeArraySizeWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_type_array_size_wire".to_string(), description: "Array size of DecompType::Array(I32,n).".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeArraySizeWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("n").and_then(Value::as_u64).unwrap_or(4); let ty = rustre_decompiler_type::DecompType::Array(Box::new(rustre_decompiler_type::DecompType::Int(rustre_decompiler_expr::IntWidth::I32)), n); Ok(ToolResult::text(json!({"byte_size":ty.byte_size(),"c_name":ty.c_name(),"source":"rustre_decompiler_type::DecompType::Array"}).to_string())) } }

pub struct DecompStructFieldAtWireTool; impl DecompStructFieldAtWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_struct_field_at_wire".to_string(), description: "StructType field_at/field_exact.".to_string(), input_schema: json!({"type":"object","properties":{"offset":{"type":"integer"}},"required":["offset"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompStructFieldAtWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let off = args.get("offset").and_then(Value::as_u64).unwrap_or(0); let st = rustre_decompiler_type::StructType::new("N", vec![ rustre_decompiler_type::StructField::new(0, "a", rustre_decompiler_type::DecompType::Int(rustre_decompiler_expr::IntWidth::I32)), rustre_decompiler_type::StructField::new(8, "b", rustre_decompiler_type::DecompType::Ptr(Box::new(rustre_decompiler_type::DecompType::Void))), ], 16); let at = st.field_at(off).map(|f| f.name.clone()); let ex = st.field_exact(off).map(|f| f.name.clone()); Ok(ToolResult::text(json!({"field_at":at,"field_exact":ex,"total_size":st.total_size,"source":"rustre_decompiler_type::StructType::field_at"}).to_string())) } }

pub struct DecompTypeEnvSetGetWireTool; impl DecompTypeEnvSetGetWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_type_env_set_get_wire".to_string(), description: "TypeEnvironment set/get.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeEnvSetGetWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).unwrap_or("x"); let mut env = rustre_decompiler_type::TypeEnvironment::new(); env.set(n, rustre_decompiler_type::DecompType::Int(rustre_decompiler_expr::IntWidth::I64)); let got = env.get(n).map(rustre_decompiler_type::DecompType::c_name); Ok(ToolResult::text(json!({"name":n,"got_c_name":got,"source":"rustre_decompiler_type::TypeEnvironment::set"}).to_string())) } }

pub struct DecompTypeEnvStructNamedWireTool; impl DecompTypeEnvStructNamedWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_type_env_struct_named_wire".to_string(), description: "TypeEnvironment struct_named.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeEnvStructNamedWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).unwrap_or("S"); let st = rustre_decompiler_type::StructType::new(n, vec![rustre_decompiler_type::StructField::new(0, "f", rustre_decompiler_type::DecompType::Int(rustre_decompiler_expr::IntWidth::I32))], 4); let mut env = rustre_decompiler_type::TypeEnvironment::new(); env.add_struct(st); let found = env.struct_named(n).map(|s| (s.name.clone(), s.total_size, s.fields.len())); Ok(ToolResult::text(json!({"name":n,"found":found,"source":"rustre_decompiler_type::TypeEnvironment::struct_named"}).to_string())) } }

pub struct DecompTypeQualifierBuilderWireTool; impl DecompTypeQualifierBuilderWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_type_qualifier_builder_wire".to_string(), description: "TypeQualifier composed and qualifier_string.".to_string(), input_schema: json!({"type":"object","properties":{"c":{"type":"boolean"},"v":{"type":"boolean"},"r":{"type":"boolean"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeQualifierBuilderWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let c = args.get("c").and_then(Value::as_bool).unwrap_or(false); let v = args.get("v").and_then(Value::as_bool).unwrap_or(false); let r = args.get("r").and_then(Value::as_bool).unwrap_or(false); let mut q = rustre_decompiler_type::TypeQualifier::NONE; if c { q = q.with_const(); } if v { q = q.with_volatile(); } if r { q = q.with_restrict(); } Ok(ToolResult::text(json!({"is_const":q.is_const(),"is_volatile":q.is_volatile(),"is_restrict":q.is_restrict(),"qualifier_string":q.qualifier_string(),"source":"rustre_decompiler_type::TypeQualifier"}).to_string())) } }

pub struct DecompRenamerRenameWireTool; impl DecompRenamerRenameWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_renamer_rename_wire".to_string(), description: "TypeAwareRenamer::rename for common types.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompRenamerRenameWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut r = rustre_decompiler_type::TypeAwareRenamer::new(); let a = r.rename(&rustre_decompiler_type::DecompType::Int(rustre_decompiler_expr::IntWidth::I32)); let b = r.rename(&rustre_decompiler_type::DecompType::Ptr(Box::new(rustre_decompiler_type::DecompType::Void))); let c = r.rename(&rustre_decompiler_type::DecompType::CStr); let d = r.rename(&rustre_decompiler_type::DecompType::Bool); r.reset(); let a2 = r.rename(&rustre_decompiler_type::DecompType::Int(rustre_decompiler_expr::IntWidth::I32)); Ok(ToolResult::text(json!({"int_name":a,"ptr_name":b,"cstr_name":c,"bool_name":d,"int_after_reset":a2,"source":"rustre_decompiler_type::TypeAwareRenamer::rename"}).to_string())) } }

pub struct DecompRenamerVariablesWireTool; impl DecompRenamerVariablesWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_renamer_variables_wire".to_string(), description: "TypeAwareRenamer::rename_variables on a snippet.".to_string(), input_schema: json!({"type":"object","properties":{"code":{"type":"string"}},"required":["code"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompRenamerVariablesWireTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let code = args.get("code").and_then(Value::as_str).unwrap_or(""); let env = rustre_decompiler_type::TypeEnvironment::new(); let mut r = rustre_decompiler_type::TypeAwareRenamer::new(); let out = r.rename_variables(code, &env); Ok(ToolResult::text(json!({"input":code,"renamed":out,"source":"rustre_decompiler_type::TypeAwareRenamer::rename_variables"}).to_string())) } }

pub struct DecompTypedEmitterEmitWireTool; impl DecompTypedEmitterEmitWireTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decomp_typed_emitter_emit_wire".to_string(), description: "TypedExprEmitter emits arr[i] for `arr+i*4`.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypedEmitterEmitWireTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut env = rustre_decompiler_type::TypeEnvironment::new(); env.set("arr", rustre_decompiler_type::DecompType::Ptr(Box::new(rustre_decompiler_type::DecompType::Int(rustre_decompiler_expr::IntWidth::I32)))); let expr = rustre_decompiler_expr::Expr::BinOp(rustre_decompiler_expr::BinOp::Add, Box::new(rustre_decompiler_expr::Expr::Var("arr".to_string())), Box::new(rustre_decompiler_expr::Expr::BinOp(rustre_decompiler_expr::BinOp::Mul, Box::new(rustre_decompiler_expr::Expr::Var("i".to_string())), Box::new(rustre_decompiler_expr::Expr::Const(4, rustre_decompiler_expr::IntWidth::U64))))); let em = rustre_decompiler_type::TypedExprEmitter::new(&env, 8); let out = em.emit(&expr).map_err(|e| McpError::InternalError(format!("emit: {e}")))?; Ok(ToolResult::text(json!({"expr":out,"source":"rustre_decompiler_type::TypedExprEmitter::emit"}).to_string())) } }

pub struct DecompTypeQualifierFlagsZx2Tool;
impl DecompTypeQualifierFlagsZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_qualifier_flags_zx2".to_string(), description: "Combine const/volatile/restrict via TypeQualifier builder and return qualifier_string + flag bits.".to_string(), input_schema: json!({"type":"object","properties":{"const_q":{"type":"boolean"},"volatile_q":{"type":"boolean"},"restrict_q":{"type":"boolean"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeQualifierFlagsZx2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let mut q = rustre_decompiler_type::TypeQualifier::NONE; if args.get("const_q").and_then(Value::as_bool).unwrap_or(false) { q = q.with_const(); } if args.get("volatile_q").and_then(Value::as_bool).unwrap_or(false) { q = q.with_volatile(); } if args.get("restrict_q").and_then(Value::as_bool).unwrap_or(false) { q = q.with_restrict(); } Ok(ToolResult::text(json!({"qualifier_string": q.qualifier_string(), "is_const": q.is_const(), "is_volatile": q.is_volatile(), "is_restrict": q.is_restrict(), "source":"rustre_decompiler_type::TypeQualifier::qualifier_string"}).to_string())) } }

pub struct DecompTypeQualifiedCNameZx2Tool;
impl DecompTypeQualifiedCNameZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_qualified_c_name_zx2".to_string(), description: "Build QualifiedType with const on DecompType::Int(width) and return c_name.".to_string(), input_schema: json!({"type":"object","properties":{"width":{"type":"string"},"const_q":{"type":"boolean"}},"required":["width"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeQualifiedCNameZx2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ws = args.get("width").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))?; let w = __decomp_parse_int_width(ws).ok_or_else(|| McpError::InvalidParams("bad width".into()))?; let mut q = rustre_decompiler_type::TypeQualifier::NONE; if args.get("const_q").and_then(Value::as_bool).unwrap_or(true) { q = q.with_const(); } let qt = rustre_decompiler_type::QualifiedType::new(rustre_decompiler_type::DecompType::Int(w)).with_qualifiers(q); Ok(ToolResult::text(json!({"c_name": qt.c_name(), "source":"rustre_decompiler_type::QualifiedType::c_name"}).to_string())) } }

pub struct DecompTypeUnionMemberNamedZx2Tool;
impl DecompTypeUnionMemberNamedZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_union_member_named_zx2".to_string(), description: "Construct a UnionType with two members and look up member_named.".to_string(), input_schema: json!({"type":"object","properties":{"probe":{"type":"string"}},"required":["probe"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeUnionMemberNamedZx2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_decompiler_type::{StructField, UnionType, DecompType}; use rustre_decompiler_expr::IntWidth; let probe = args.get("probe").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'probe'".into()))?; let u = UnionType::new("U", vec![StructField::new(0, "x", DecompType::Int(IntWidth::I32)), StructField::new(0, "y", DecompType::Float32)]); let hit = u.member_named(probe).map(|m| m.name.clone()); Ok(ToolResult::text(json!({"member": hit, "members": u.members.len(), "total_size": u.total_size, "source":"rustre_decompiler_type::UnionType::member_named"}).to_string())) } }

pub struct DecompTypeFunctionArityZx2Tool;
impl DecompTypeFunctionArityZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_function_arity_zx2".to_string(), description: "Build FunctionType with N params, return arity() and variadic prototype.".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer","minimum":0,"maximum":16},"variadic":{"type":"boolean"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeFunctionArityZx2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_decompiler_type::{FunctionType, DecompType}; use rustre_decompiler_expr::IntWidth; let n = args.get("n").and_then(Value::as_u64).unwrap_or(2) as usize; let mut f = FunctionType::new("fn_z", DecompType::Int(IntWidth::I32)); for i in 0..n { f.add_param(format!("p{i}"), DecompType::Int(IntWidth::I32)); } f.is_variadic = args.get("variadic").and_then(Value::as_bool).unwrap_or(false); Ok(ToolResult::text(json!({"arity": f.arity(), "prototype": f.c_prototype(), "source":"rustre_decompiler_type::FunctionType::arity"}).to_string())) } }

pub struct DecompTypeCallingConventionZx2Tool;
impl DecompTypeCallingConventionZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_calling_convention_zx2".to_string(), description: "Return CallingConvention::as_str for each variant.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeCallingConventionZx2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_decompiler_type::CallingConvention as C; Ok(ToolResult::text(json!({"cdecl": C::CDecl.as_str(), "stdcall": C::StdCall.as_str(), "fastcall": C::FastCall.as_str(), "thiscall": C::ThisCall.as_str(), "sysv64": C::SysV64.as_str(), "ms_x64": C::MsX64.as_str(), "custom": C::Custom.as_str(), "source":"rustre_decompiler_type::CallingConvention::as_str"}).to_string())) } }

pub struct DecompTypeLayoutPaddedSizeZx2Tool;
impl DecompTypeLayoutPaddedSizeZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_layout_padded_size_zx2".to_string(), description: "Compute TypeLayout::for_struct then padded_size on a 2-field struct.".to_string(), input_schema: json!({"type":"object","properties":{"total_size":{"type":"integer","minimum":1}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeLayoutPaddedSizeZx2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_decompiler_type::{StructField, StructType, TypeLayout, DecompType}; use rustre_decompiler_expr::IntWidth; let ts = args.get("total_size").and_then(Value::as_u64).unwrap_or(7); let st = StructType::new("Foo", vec![StructField::new(0, "a", DecompType::Int(IntWidth::I32)), StructField::new(4, "b", DecompType::Int(IntWidth::I16))], ts); let layout = TypeLayout::for_struct(&st); Ok(ToolResult::text(json!({"size": layout.size, "alignment": layout.alignment, "padded_size": layout.padded_size(), "field_count": layout.field_offsets.len(), "source":"rustre_decompiler_type::TypeLayout::padded_size"}).to_string())) } }

pub struct DecompTypePointerAnalysisZx2Tool;
impl DecompTypePointerAnalysisZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_pointer_analysis_zx2".to_string(), description: "PointerAnalysis: record points-to + may_alias, probe is_definitely_not_null and may_alias_with.".to_string(), input_schema: json!({"type":"object","properties":{"ptr":{"type":"string"},"target":{"type":"string"},"alias":{"type":"string"}},"required":["ptr","target","alias"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypePointerAnalysisZx2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ptr = args.get("ptr").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'ptr'".into()))?.to_string(); let tgt = args.get("target").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'target'".into()))?.to_string(); let al = args.get("alias").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'alias'".into()))?.to_string(); let mut pa = rustre_decompiler_type::PointerAnalysis::new(); pa.record_points_to(ptr.clone(), tgt.clone()); pa.record_may_alias(ptr.clone(), al.clone()); let targets: Vec<String> = pa.points_to_targets(&ptr).to_vec(); let aliases: Vec<String> = pa.may_alias_with(&ptr).into_iter().map(|s| s.to_string()).collect(); let not_null = pa.is_definitely_not_null(&ptr); Ok(ToolResult::text(json!({"points_to": targets, "may_alias_with": aliases, "is_definitely_not_null": not_null, "source":"rustre_decompiler_type::PointerAnalysis"}).to_string())) } }

pub struct DecompTypePointeeCNameZx2Tool;
impl DecompTypePointeeCNameZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_pointee_c_name_zx2".to_string(), description: "Wrap DecompType::pointee: build Ptr(Int(width)) and return pointee c_name.".to_string(), input_schema: json!({"type":"object","properties":{"width":{"type":"string"}},"required":["width"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypePointeeCNameZx2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ws = args.get("width").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))?; let w = __decomp_parse_int_width(ws).ok_or_else(|| McpError::InvalidParams("bad width".into()))?; let ty = rustre_decompiler_type::DecompType::Ptr(Box::new(rustre_decompiler_type::DecompType::Int(w))); let pointee_name = ty.pointee().map(|p| p.c_name()); let void_ptr = rustre_decompiler_type::DecompType::Int(w).pointee().is_some(); Ok(ToolResult::text(json!({"pointee_c_name": pointee_name, "is_pointer": ty.is_pointer(), "int_has_pointee": void_ptr, "source":"rustre_decompiler_type::DecompType::pointee"}).to_string())) } }

pub struct DecompTypeNamePrefixZx2Tool;
impl DecompTypeNamePrefixZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_name_prefix_zx2".to_string(), description: "Return DecompType::name_prefix for a set of built-in types.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeNamePrefixZx2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_decompiler_type::DecompType; use rustre_decompiler_expr::IntWidth; Ok(ToolResult::text(json!({"bool": DecompType::Bool.name_prefix(), "i32": DecompType::Int(IntWidth::I32).name_prefix(), "u32": DecompType::Int(IntWidth::U32).name_prefix(), "ptr": DecompType::Ptr(Box::new(DecompType::Void)).name_prefix(), "cstr": DecompType::CStr.name_prefix(), "f32": DecompType::Float32.name_prefix(), "source":"rustre_decompiler_type::DecompType::name_prefix"}).to_string())) } }

pub struct DecompTypeLatticeJoinZx2Tool;
impl DecompTypeLatticeJoinZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_lattice_join_zx2".to_string(), description: "Join two LatticeType::Integer widths; report is_conflict.".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}},"required":["a","b"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeLatticeJoinZx2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = __decomp_parse_int_width(args.get("a").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?).ok_or_else(|| McpError::InvalidParams("bad a".into()))?; let b = __decomp_parse_int_width(args.get("b").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?).ok_or_else(|| McpError::InvalidParams("bad b".into()))?; let la = rustre_decompiler_type::LatticeType::Integer { width: Some(a) }; let lb = rustre_decompiler_type::LatticeType::Integer { width: Some(b) }; let joined = la.join(&lb); Ok(ToolResult::text(json!({"joined_decomp_c_name": joined.to_decomp().c_name(), "is_conflict": joined.is_conflict(), "source":"rustre_decompiler_type::LatticeType::join"}).to_string())) } }

pub struct DecompTypeLatticeFromDecompZx2Tool;
impl DecompTypeLatticeFromDecompZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_lattice_from_decomp_zx2".to_string(), description: "LatticeType::from_decomp roundtrip via to_decomp for Ptr(Int(width)).".to_string(), input_schema: json!({"type":"object","properties":{"width":{"type":"string"}},"required":["width"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeLatticeFromDecompZx2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ws = args.get("width").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))?; let w = __decomp_parse_int_width(ws).ok_or_else(|| McpError::InvalidParams("bad width".into()))?; let orig = rustre_decompiler_type::DecompType::Ptr(Box::new(rustre_decompiler_type::DecompType::Int(w))); let l = rustre_decompiler_type::LatticeType::from_decomp(&orig); let back = l.to_decomp(); Ok(ToolResult::text(json!({"original_c_name": orig.c_name(), "roundtrip_c_name": back.c_name(), "is_conflict": l.is_conflict(), "source":"rustre_decompiler_type::LatticeType::from_decomp"}).to_string())) } }

pub struct DecompTypeAccessWidthSizerZx2Tool;
impl DecompTypeAccessWidthSizerZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_access_width_sizer_zx2".to_string(), description: "AccessWidthSizer: observe widths, mark_signed, infer type.".to_string(), input_schema: json!({"type":"object","properties":{"var":{"type":"string"},"widths":{"type":"array","items":{"type":"integer"}},"signed":{"type":"boolean"}},"required":["var","widths"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeAccessWidthSizerZx2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let var = args.get("var").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'var'".into()))?.to_string(); let widths = args.get("widths").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'widths'".into()))?; let signed = args.get("signed").and_then(Value::as_bool).unwrap_or(false); let mut s = rustre_decompiler_type::AccessWidthSizer::new(); for w in widths { if let Some(n) = w.as_u64() { s.observe(var.clone(), n as u8); } } if signed { s.mark_signed(var.clone()); } let inferred = s.infer(&var).map(|t| t.c_name()); Ok(ToolResult::text(json!({"var": var, "inferred_c_name": inferred, "count": s.count(), "vars": s.vars(), "source":"rustre_decompiler_type::AccessWidthSizer::infer"}).to_string())) } }

pub struct DecompTypeStructClustererZx2Tool;
impl DecompTypeStructClustererZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_struct_clusterer_zx2".to_string(), description: "StructClusterer::observe offsets/widths for a base pointer then build_struct.".to_string(), input_schema: json!({"type":"object","properties":{"base":{"type":"string"},"observations":{"type":"array","items":{"type":"object","properties":{"offset":{"type":"integer"},"width":{"type":"integer"}},"required":["offset","width"]}}},"required":["base","observations"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeStructClustererZx2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let base = args.get("base").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?.to_string(); let obs = args.get("observations").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'observations'".into()))?; let mut c = rustre_decompiler_type::StructClusterer::new(); for o in obs { let off = o.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("bad offset".into()))?; let w = o.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("bad width".into()))? as u8; c.observe(base.clone(), off, w); } let st = c.build_struct(&base, "Recovered"); let field_count = st.as_ref().map(|s| s.fields.len()).unwrap_or(0); let total = st.as_ref().map(|s| s.total_size).unwrap_or(0); Ok(ToolResult::text(json!({"base_count": c.base_count(), "offsets": c.offsets(&base), "field_count": field_count, "total_size": total, "source":"rustre_decompiler_type::StructClusterer::build_struct"}).to_string())) } }

pub struct DecompTypeArrayMatchZx2Tool;
impl DecompTypeArrayMatchZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_array_match_zx2".to_string(), description: "ArrayInference::match_array_access on synthetic (base + idx*stride) expression.".to_string(), input_schema: json!({"type":"object","properties":{"base":{"type":"string"},"idx":{"type":"string"},"stride":{"type":"integer","minimum":1}},"required":["base","idx","stride"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeArrayMatchZx2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_decompiler_expr::{Expr, BinOp, IntWidth}; let base = args.get("base").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?.to_string(); let idx = args.get("idx").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'idx'".into()))?.to_string(); let stride = args.get("stride").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'stride'".into()))?; let expr = Expr::BinOp(BinOp::Add, Box::new(Expr::Var(base.clone())), Box::new(Expr::BinOp(BinOp::Mul, Box::new(Expr::Var(idx.clone())), Box::new(Expr::Const(stride as i64, IntWidth::I64))))); let m = rustre_decompiler_type::ArrayInference::match_array_access(&expr); let elem_size = match stride { 2 => "uint16_t", 4 => "uint32_t", 8 => "uint64_t", _ => "uint8_t" }; Ok(ToolResult::text(json!({"matched": m.is_some(), "base": m.as_ref().map(|a| a.base.clone()), "index": m.as_ref().map(|a| a.index.clone()), "stride": m.as_ref().map(|a| a.stride), "inferred_elem": elem_size, "source":"rustre_decompiler_type::ArrayInference::match_array_access"}).to_string())) } }

pub struct DecompTypeUnifierClassesZx2Tool;
impl DecompTypeUnifierClassesZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_unifier_classes_zx2".to_string(), description: "TypeUnifier: add constraints and return equivalence class count and canonical for a probe.".to_string(), input_schema: json!({"type":"object","properties":{"pairs":{"type":"array","items":{"type":"array","items":{"type":"string"}}},"probe":{"type":"string"}},"required":["pairs","probe"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeUnifierClassesZx2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pairs = args.get("pairs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'pairs'".into()))?; let probe = args.get("probe").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'probe'".into()))?.to_string(); let mut u = rustre_decompiler_type::TypeUnifier::new(); for p in pairs { if let Some(arr) = p.as_array() { if arr.len() >= 2 { if let (Some(a), Some(b)) = (arr[0].as_str(), arr[1].as_str()) { let c = rustre_decompiler_type::TypeConstraint::new(a, b, "eq"); u.add_constraint(&c); } } } } let can = u.canonical(&probe); let classes = u.equivalence_classes(); Ok(ToolResult::text(json!({"canonical": can, "class_count": classes.len(), "source":"rustre_decompiler_type::TypeUnifier::equivalence_classes"}).to_string())) } }

pub struct DecompTypeEnvStructNamedZx2Tool;
impl DecompTypeEnvStructNamedZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_env_struct_named_zx2".to_string(), description: "TypeEnvironment::add_struct then struct_named lookup.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"probe":{"type":"string"}},"required":["name","probe"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeEnvStructNamedZx2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_decompiler_type::{StructType, StructField, DecompType, TypeEnvironment}; use rustre_decompiler_expr::IntWidth; let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string(); let probe = args.get("probe").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'probe'".into()))?.to_string(); let mut env = TypeEnvironment::new(); let st = StructType::new(name.clone(), vec![StructField::new(0, "a", DecompType::Int(IntWidth::I32))], 4); env.add_struct(st); let found = env.struct_named(&probe).map(|s| s.name.clone()); Ok(ToolResult::text(json!({"registered": name, "probe": probe, "found": found, "source":"rustre_decompiler_type::TypeEnvironment::struct_named"}).to_string())) } }

pub struct DecompTypeAreCompatiblePtrZx2Tool;
impl DecompTypeAreCompatiblePtrZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_are_compatible_ptr_zx2".to_string(), description: "Test are_compatible and is_implicitly_convertible for two Ptr(Int) types.".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}},"required":["a","b"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeAreCompatiblePtrZx2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = __decomp_parse_int_width(args.get("a").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?).ok_or_else(|| McpError::InvalidParams("bad a".into()))?; let b = __decomp_parse_int_width(args.get("b").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?).ok_or_else(|| McpError::InvalidParams("bad b".into()))?; let ta = rustre_decompiler_type::DecompType::Ptr(Box::new(rustre_decompiler_type::DecompType::Int(a))); let tb = rustre_decompiler_type::DecompType::Ptr(Box::new(rustre_decompiler_type::DecompType::Int(b))); Ok(ToolResult::text(json!({"compatible": rustre_decompiler_type::are_compatible(&ta,&tb), "convertible": rustre_decompiler_type::is_implicitly_convertible(&ta,&tb), "source":"rustre_decompiler_type::are_compatible"}).to_string())) } }

pub struct DecompTypeIsPointerZx2Tool;
impl DecompTypeIsPointerZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_is_pointer_zx2".to_string(), description: "DecompType::is_pointer for Ptr, CStr, FnPtr and Int(width).".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeIsPointerZx2Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_decompiler_type::DecompType; use rustre_decompiler_expr::IntWidth; let ptr = DecompType::Ptr(Box::new(DecompType::Void)); let cstr = DecompType::CStr; let fnp = DecompType::FnPtr { ret: Box::new(DecompType::Void), params: vec![] }; let i32t = DecompType::Int(IntWidth::I32); Ok(ToolResult::text(json!({"ptr": ptr.is_pointer(), "cstr": cstr.is_pointer(), "fnptr": fnp.is_pointer(), "int32": i32t.is_pointer(), "source":"rustre_decompiler_type::DecompType::is_pointer"}).to_string())) } }

pub struct DecompTypeStructFieldExactZx2Tool;
impl DecompTypeStructFieldExactZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_struct_field_exact_zx2".to_string(), description: "StructType::field_exact vs field_at for a 2-field struct at arbitrary offsets.".to_string(), input_schema: json!({"type":"object","properties":{"offset":{"type":"integer"}},"required":["offset"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeStructFieldExactZx2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_decompiler_type::{StructField, StructType, DecompType}; use rustre_decompiler_expr::IntWidth; let off = args.get("offset").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'offset'".into()))?; let st = StructType::new("S2", vec![StructField::new(0, "head", DecompType::Int(IntWidth::I64)), StructField::new(8, "tail", DecompType::Int(IntWidth::I32))], 12); let ex = st.field_exact(off).map(|f| f.name.clone()); let at = st.field_at(off).map(|f| f.name.clone()); Ok(ToolResult::text(json!({"offset": off, "field_exact": ex, "field_at": at, "source":"rustre_decompiler_type::StructType::field_exact"}).to_string())) } }

pub struct DecompTypeArrayByteSizeZx2Tool;
impl DecompTypeArrayByteSizeZx2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_type_array_byte_size_zx2".to_string(), description: "Compute byte_size and byte_size_with_ptr_width for DecompType::Array(Int(width), n).".to_string(), input_schema: json!({"type":"object","properties":{"width":{"type":"string"},"n":{"type":"integer","minimum":0},"ptr_width":{"type":"integer","minimum":1}},"required":["width","n"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DecompTypeArrayByteSizeZx2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ws = args.get("width").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))?; let w = __decomp_parse_int_width(ws).ok_or_else(|| McpError::InvalidParams("bad width".into()))?; let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?; let pw = args.get("ptr_width").and_then(Value::as_u64).unwrap_or(8) as u8; let ty = rustre_decompiler_type::DecompType::Array(Box::new(rustre_decompiler_type::DecompType::Int(w)), n); Ok(ToolResult::text(json!({"byte_size": ty.byte_size(), "byte_size_with_ptr_width": ty.byte_size_with_ptr_width(pw), "c_name": ty.c_name(), "source":"rustre_decompiler_type::DecompType::byte_size"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DecompRegisterCanonicalTool::definition(), Box::new(DecompRegisterCanonicalTool)),
        (DecompRegisterWidthBytesTool::definition(), Box::new(DecompRegisterWidthBytesTool)),
        (DecompIsCKeywordTool::definition(), Box::new(DecompIsCKeywordTool)),
        (DecompQualityMetricsFromSourceTool::definition(), Box::new(DecompQualityMetricsFromSourceTool)),
        (DecompQualityReadabilityScoreTool::definition(), Box::new(DecompQualityReadabilityScoreTool)),
        (DecompPipelinePassCountTool::definition(), Box::new(DecompPipelinePassCountTool)),
        (DecompCallingConventionFromArchTool::definition(), Box::new(DecompCallingConventionFromArchTool)),
        (DecompVariableRecoveryStackNameTool::definition(), Box::new(DecompVariableRecoveryStackNameTool)),
        (DecompTypePropagationAddTool::definition(), Box::new(DecompTypePropagationAddTool)),
        (DecompExpressionRecoveryKnownTool::definition(), Box::new(DecompExpressionRecoveryKnownTool)),
        (DecompFunctionNameGeneratorTool::definition(), Box::new(DecompFunctionNameGeneratorTool)),
        (DecompStatsSummaryTool::definition(), Box::new(DecompStatsSummaryTool)),
        (DecompCacheHitRateTool::definition(), Box::new(DecompCacheHitRateTool)),
        (DecompCfStructuringMakeIfElseTool::definition(), Box::new(DecompCfStructuringMakeIfElseTool)),
        (DecompCfFlattenSequencesTool::definition(), Box::new(DecompCfFlattenSequencesTool)),
        (DecompDecompiledFunctionSummaryTool::definition(), Box::new(DecompDecompiledFunctionSummaryTool)),
        (DecompSymbolMapResolveTool::definition(), Box::new(DecompSymbolMapResolveTool)),
        (DecompSymbolMapFromFlirtTool::definition(), Box::new(DecompSymbolMapFromFlirtTool)),
        (DecompAnnotationStoreByCategoryTool::definition(), Box::new(DecompAnnotationStoreByCategoryTool)),
        (DecompAnnotationStoreAtAddressTool::definition(), Box::new(DecompAnnotationStoreAtAddressTool)),
        (DecompPassRegistryNamesTool::definition(), Box::new(DecompPassRegistryNamesTool)),
        (DecompCfDetectLoopTool::definition(), Box::new(DecompCfDetectLoopTool)),
        (DecompCfFreshGotoLabelTool::definition(), Box::new(DecompCfFreshGotoLabelTool)),
        (DecompCacheEvictClearTool::definition(), Box::new(DecompCacheEvictClearTool)),
        (DecompTypePropagationAllTypedTool::definition(), Box::new(DecompTypePropagationAllTypedTool)),
        (DecompVariableRecoveryAddRegParamTool::definition(), Box::new(DecompVariableRecoveryAddRegParamTool)),
        (DecompSignHintAsBoolTool::definition(), Box::new(DecompSignHintAsBoolTool)),
        (DecompFunctionNameGeneratorMultiTool::definition(), Box::new(DecompFunctionNameGeneratorMultiTool)),
        (DecompTypeCNameIntWpTool::definition(), Box::new(DecompTypeCNameIntWpTool)),
        (DecompTypeBytesizeIntWpTool::definition(), Box::new(DecompTypeBytesizeIntWpTool)),
        (DecompTypeBytesizePtrWpTool::definition(), Box::new(DecompTypeBytesizePtrWpTool)),
        (DecompTypeAreCompatibleIntsWpTool::definition(), Box::new(DecompTypeAreCompatibleIntsWpTool)),
        (DecompTypeIsConvertibleIntsWpTool::definition(), Box::new(DecompTypeIsConvertibleIntsWpTool)),
        (DecompTypeEnvSetGetWpTool::definition(), Box::new(DecompTypeEnvSetGetWpTool)),
        (DecompTypeStructFieldAtWpTool::definition(), Box::new(DecompTypeStructFieldAtWpTool)),
        (DecompTypeDatabaseWindowsCountsWpTool::definition(), Box::new(DecompTypeDatabaseWindowsCountsWpTool)),
        (DecompTypeDatabaseLinuxCountsWpTool::definition(), Box::new(DecompTypeDatabaseLinuxCountsWpTool)),
        (DecompTypeStdlibDbCountsWpTool::definition(), Box::new(DecompTypeStdlibDbCountsWpTool)),
        (DecompTypeFunctionPrototypeWpTool::definition(), Box::new(DecompTypeFunctionPrototypeWpTool)),
        (DecompTypeUnionCNameWpTool::definition(), Box::new(DecompTypeUnionCNameWpTool)),
        (DecompTypeRecoveryRecordGetWpTool::definition(), Box::new(DecompTypeRecoveryRecordGetWpTool)),
        (DecompTypeRecoveryFromAccessSizeWpTool::definition(), Box::new(DecompTypeRecoveryFromAccessSizeWpTool)),
        (DecompTypePointerAnalysisAliasWpTool::definition(), Box::new(DecompTypePointerAnalysisAliasWpTool)),
        (DecompTypePointerAnalysisNotNullWpTool::definition(), Box::new(DecompTypePointerAnalysisNotNullWpTool)),
        (DecompTypeAccessWidthSizerWpTool::definition(), Box::new(DecompTypeAccessWidthSizerWpTool)),
        (DecompTypeUnifierCanonicalWpTool::definition(), Box::new(DecompTypeUnifierCanonicalWpTool)),
        (DecompTypeInferenceAssignmentWpTool::definition(), Box::new(DecompTypeInferenceAssignmentWpTool)),
        (DecompTypePropagatorAssignWpTool::definition(), Box::new(DecompTypePropagatorAssignWpTool)),
        (DecompTypeQualifierFlagsWpTool::definition(), Box::new(DecompTypeQualifierFlagsWpTool)),
        (DecompTypeLayoutPaddedSizeWpTool::definition(), Box::new(DecompTypeLayoutPaddedSizeWpTool)),
        (DecompTypeCtypeEmitTypedefWpTool::definition(), Box::new(DecompTypeCtypeEmitTypedefWpTool)),
        (DecompXRegisterWidthBatchTool::definition(), Box::new(DecompXRegisterWidthBatchTool)),
        (DecompXRegisterCanonicalBatchTool::definition(), Box::new(DecompXRegisterCanonicalBatchTool)),
        (DecompXWidthHintBatchTool::definition(), Box::new(DecompXWidthHintBatchTool)),
        (DecompXIsCKeywordBatchTool::definition(), Box::new(DecompXIsCKeywordBatchTool)),
        (DecompXParseMemOperandsCountTool::definition(), Box::new(DecompXParseMemOperandsCountTool)),
        (DecompXParseMemOperandsPrefixesTool::definition(), Box::new(DecompXParseMemOperandsPrefixesTool)),
        (DecompXCallconvLiftMnemonicCountTool::definition(), Box::new(DecompXCallconvLiftMnemonicCountTool)),
        (DecompXCallconvArchFromStrRoundtripTool::definition(), Box::new(DecompXCallconvArchFromStrRoundtripTool)),
        (DecompXLoadBinaryInfoTool::definition(), Box::new(DecompXLoadBinaryInfoTool)),
        (DecompXDetectFunctionsCountTool::definition(), Box::new(DecompXDetectFunctionsCountTool)),
        (DecompXSliceAtVaLenTool::definition(), Box::new(DecompXSliceAtVaLenTool)),
        (DecompStatsSuccessRateDcx1Tool::definition(), Box::new(DecompStatsSuccessRateDcx1Tool)),
        (DecompSymbolMapInsertResolveDcx1Tool::definition(), Box::new(DecompSymbolMapInsertResolveDcx1Tool)),
        (DecompSymbolMapFromFlirtPairsDcx1Tool::definition(), Box::new(DecompSymbolMapFromFlirtPairsDcx1Tool)),
        (DecompTypePropagationPropagateAddDcx1Tool::definition(), Box::new(DecompTypePropagationPropagateAddDcx1Tool)),
        (DecompVariableRecoveryFreshVarDcx1Tool::definition(), Box::new(DecompVariableRecoveryFreshVarDcx1Tool)),
        (DecompExpressionRecoveryRegisterDcx1Tool::definition(), Box::new(DecompExpressionRecoveryRegisterDcx1Tool)),
        (DecompCallingConventionFromArchDcx1Tool::definition(), Box::new(DecompCallingConventionFromArchDcx1Tool)),
        (DecompFunctionNameGeneratorHintDcx1Tool::definition(), Box::new(DecompFunctionNameGeneratorHintDcx1Tool)),
        (DecompDecompilationResultIsSuccessDcx1Tool::definition(), Box::new(DecompDecompilationResultIsSuccessDcx1Tool)),
        (DecompTypeIntByteSizeWireTool::definition(), Box::new(DecompTypeIntByteSizeWireTool)),
        (DecompTypePtrWidthWireTool::definition(), Box::new(DecompTypePtrWidthWireTool)),
        (DecompTypeArraySizeWireTool::definition(), Box::new(DecompTypeArraySizeWireTool)),
        (DecompStructFieldAtWireTool::definition(), Box::new(DecompStructFieldAtWireTool)),
        (DecompTypeEnvSetGetWireTool::definition(), Box::new(DecompTypeEnvSetGetWireTool)),
        (DecompTypeEnvStructNamedWireTool::definition(), Box::new(DecompTypeEnvStructNamedWireTool)),
        (DecompTypeQualifierBuilderWireTool::definition(), Box::new(DecompTypeQualifierBuilderWireTool)),
        (DecompRenamerRenameWireTool::definition(), Box::new(DecompRenamerRenameWireTool)),
        (DecompRenamerVariablesWireTool::definition(), Box::new(DecompRenamerVariablesWireTool)),
        (DecompTypedEmitterEmitWireTool::definition(), Box::new(DecompTypedEmitterEmitWireTool)),
        (DecompTypeQualifierFlagsZx2Tool::definition(), Box::new(DecompTypeQualifierFlagsZx2Tool)),
        (DecompTypeQualifiedCNameZx2Tool::definition(), Box::new(DecompTypeQualifiedCNameZx2Tool)),
        (DecompTypeUnionMemberNamedZx2Tool::definition(), Box::new(DecompTypeUnionMemberNamedZx2Tool)),
        (DecompTypeFunctionArityZx2Tool::definition(), Box::new(DecompTypeFunctionArityZx2Tool)),
        (DecompTypeCallingConventionZx2Tool::definition(), Box::new(DecompTypeCallingConventionZx2Tool)),
        (DecompTypeLayoutPaddedSizeZx2Tool::definition(), Box::new(DecompTypeLayoutPaddedSizeZx2Tool)),
        (DecompTypePointerAnalysisZx2Tool::definition(), Box::new(DecompTypePointerAnalysisZx2Tool)),
        (DecompTypePointeeCNameZx2Tool::definition(), Box::new(DecompTypePointeeCNameZx2Tool)),
        (DecompTypeNamePrefixZx2Tool::definition(), Box::new(DecompTypeNamePrefixZx2Tool)),
        (DecompTypeLatticeJoinZx2Tool::definition(), Box::new(DecompTypeLatticeJoinZx2Tool)),
        (DecompTypeLatticeFromDecompZx2Tool::definition(), Box::new(DecompTypeLatticeFromDecompZx2Tool)),
        (DecompTypeAccessWidthSizerZx2Tool::definition(), Box::new(DecompTypeAccessWidthSizerZx2Tool)),
        (DecompTypeStructClustererZx2Tool::definition(), Box::new(DecompTypeStructClustererZx2Tool)),
        (DecompTypeArrayMatchZx2Tool::definition(), Box::new(DecompTypeArrayMatchZx2Tool)),
        (DecompTypeUnifierClassesZx2Tool::definition(), Box::new(DecompTypeUnifierClassesZx2Tool)),
        (DecompTypeEnvStructNamedZx2Tool::definition(), Box::new(DecompTypeEnvStructNamedZx2Tool)),
        (DecompTypeAreCompatiblePtrZx2Tool::definition(), Box::new(DecompTypeAreCompatiblePtrZx2Tool)),
        (DecompTypeIsPointerZx2Tool::definition(), Box::new(DecompTypeIsPointerZx2Tool)),
        (DecompTypeStructFieldExactZx2Tool::definition(), Box::new(DecompTypeStructFieldExactZx2Tool)),
        (DecompTypeArrayByteSizeZx2Tool::definition(), Box::new(DecompTypeArrayByteSizeZx2Tool)),
    ]
}
