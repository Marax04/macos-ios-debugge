//! MCP wrappers for the rustre-rustre_decompiler crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct RustreDecompilerMemOperandParseTool;
impl RustreDecompilerMemOperandParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_decompiler_mem_operand_parse".to_string(),
            description: "Parse Intel-syntax memory operands into (base, displacement, size_bytes) triples via rustre_decompiler::mem_operand::parse_mem_operands.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["operands"],
                "properties": { "operands": { "type": "string" } }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerMemOperandParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("operands").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'operands'".into()))?;
        let items = rustre_decompiler::mem_operand::parse_mem_operands(s);
        let ops: Vec<Value> = items.iter().map(|m| {
            let base = match &m.base {
                rustre_decompiler::mem_operand::BaseKind::Rbp => "rbp".to_string(),
                rustre_decompiler::mem_operand::BaseKind::Rsp => "rsp".to_string(),
                rustre_decompiler::mem_operand::BaseKind::Reg(r) => r.clone(),
            };
            json!({
                "base": base,
                "ident_prefix": m.base.ident_prefix(),
                "displacement": m.displacement,
                "size_bytes": m.size_bytes,
            })
        }).collect();
        Ok(ToolResult::text(json!({
            "count": ops.len(),
            "operands": ops,
            "source": "rustre_decompiler::mem_operand::parse_mem_operands",
        }).to_string()))
    }
}

pub struct RustreDecompilerCallconvArchFromStrTool;
impl RustreDecompilerCallconvArchFromStrTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_decompiler_callconv_arch_from_str".to_string(),
            description: "Normalize an arch string onto rustre_decompiler::callconv_bridge::arch_from_str.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["arch"],
                "properties": { "arch": { "type": "string" } }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerCallconvArchFromStrTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("arch").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'arch'".into()))?;
        let a = rustre_decompiler::callconv_bridge::arch_from_str(s);
        Ok(ToolResult::text(json!({
            "input": s,
            "arch": format!("{:?}", a),
            "source": "rustre_decompiler::callconv_bridge::arch_from_str",
        }).to_string()))
    }
}

pub struct RustreDecompilerStandardPassSpecsTool;
impl RustreDecompilerStandardPassSpecsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_decompiler_standard_pass_specs".to_string(),
            description: "List the canonical decompiler pass specs from rustre_decompiler::pipeline_coordinator::standard_pass_specs.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerStandardPassSpecsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let specs = rustre_decompiler::pipeline_coordinator::standard_pass_specs();
        let items: Vec<Value> = specs.iter().map(|s| json!({
            "id": s.id.0,
            "depends_on": s.depends_on.iter().map(|d| d.0.clone()).collect::<Vec<_>>(),
            "output_level": s.output_level.to_string(),
            "max_retries": s.max_retries,
            "fallback": s.fallback.as_ref().map(|f| f.0.clone()),
            "is_required": s.is_required,
            "timeout_ms": s.timeout_ms,
        })).collect();
        Ok(ToolResult::text(json!({
            "count": items.len(),
            "passes": items,
            "source": "rustre_decompiler::pipeline_coordinator::standard_pass_specs",
        }).to_string()))
    }
}

pub struct RustreDecompilerX86WidthHintTool;
impl RustreDecompilerX86WidthHintTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_decompiler_x86_width_hint".to_string(),
            description: "Infer width hint (bytes) from an x86 mnemonic+operands via rustre_decompiler::x86_register_width::width_hint_from_instr.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["mnemonic", "operands"],
                "properties": {
                    "mnemonic": { "type": "string" },
                    "operands": { "type": "string" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerX86WidthHintTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mnem = args.get("mnemonic").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'mnemonic'".into()))?;
        let ops = args.get("operands").and_then(Value::as_str).unwrap_or("");
        let hint = rustre_decompiler::x86_register_width::width_hint_from_instr(mnem, ops);
        Ok(ToolResult::text(json!({
            "mnemonic": mnem,
            "operands": ops,
            "width_bytes": hint,
            "source": "rustre_decompiler::x86_register_width::width_hint_from_instr",
        }).to_string()))
    }
}

pub struct RustreDecompilerLoadBinaryInfoTool;
impl RustreDecompilerLoadBinaryInfoTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_decompiler_load_binary_info".to_string(),
            description: "Load a binary via rustre_decompiler::load_binary and return a compact summary.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["path"],
                "properties": { "path": { "type": "string" } }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerLoadBinaryInfoTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let p = args.get("path").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let load = rustre_decompiler::load_binary(std::path::Path::new(p))
            .map_err(|e| McpError::InternalError(format!("load_binary: {e:?}")))?;
        Ok(ToolResult::text(json!({
            "path": p,
            "format": load.format,
            "arch": load.arch,
            "bits": load.bits,
            "endian": load.endian,
            "entry_point": load.entry_point,
            "base_address": load.base_address,
            "section_count": load.sections.len(),
            "symbol_count": load.symbols.len(),
            "import_count": load.imports.len(),
            "export_count": load.exports.len(),
            "data_len": load.data.len(),
            "source": "rustre_decompiler::load_binary",
        }).to_string()))
    }
}

pub struct RustreDecompilerDetectFunctionsPathTool;
impl RustreDecompilerDetectFunctionsPathTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_decompiler_detect_functions_path".to_string(),
            description: "Load a binary and detect function boundaries via rustre_decompiler::detect_functions_in_load.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string" },
                    "max": { "type": "integer" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerDetectFunctionsPathTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let p = args.get("path").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let max = args.get("max").and_then(Value::as_u64).unwrap_or(256) as usize;
        let load = rustre_decompiler::load_binary(std::path::Path::new(p))
            .map_err(|e| McpError::InternalError(format!("load_binary: {e:?}")))?;
        let funcs = rustre_decompiler::detect_functions_in_load(&load);
        let total = funcs.len();
        let sample: Vec<Value> = funcs.iter().take(max).map(|f| json!({
            "start": f.start,
            "end": f.end,
        })).collect();
        Ok(ToolResult::text(json!({
            "path": p,
            "total": total,
            "returned": sample.len(),
            "functions": sample,
            "source": "rustre_decompiler::detect_functions_in_load",
        }).to_string()))
    }
}

pub struct RustreDecompilerDefaultOptionsTool;
impl RustreDecompilerDefaultOptionsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_decompiler_default_options".to_string(),
            description: "Return a compact JSON view of rustre_decompiler::DecompOptions::default().".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerDefaultOptionsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let o = rustre_decompiler::DecompOptions::default();
        Ok(ToolResult::text(json!({
            "target_level": o.target_level.to_string(),
            "max_function_size": o.max_function_size,
            "timeout_ms": o.timeout_ms,
            "min_variable_confidence": o.min_variable_confidence,
            "verbosity": o.verbosity,
            "name_recovery": o.name_recovery,
            "backend": format!("{:?}", o.backend),
            "source": "rustre_decompiler::DecompOptions::default",
        }).to_string()))
    }
}

pub struct RustreDecompilerSymbolMapResolveTool;
impl RustreDecompilerSymbolMapResolveTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_decompiler_symbol_map_resolve".to_string(),
            description: "Insert (addr, name) pairs into a rustre_decompiler::SymbolMap and resolve a list of addresses.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["pairs", "queries"],
                "properties": {
                    "pairs": { "type": "array" },
                    "queries": { "type": "array", "items": { "type": "integer" } },
                    "rust_demangle": { "type": "boolean" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerSymbolMapResolveTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_decompiler::SymbolResolver;
        let mut m = rustre_decompiler::SymbolMap::new();
        if args.get("rust_demangle").and_then(Value::as_bool).unwrap_or(false) {
            m.enable_rust_demangling(true);
        }
        if let Some(arr) = args.get("pairs").and_then(Value::as_array) {
            for it in arr {
                let addr = it.get("addr").and_then(Value::as_u64)
                    .or_else(|| it.get(0).and_then(Value::as_u64));
                let name = it.get("name").and_then(Value::as_str)
                    .or_else(|| it.get(1).and_then(Value::as_str));
                if let (Some(a), Some(n)) = (addr, name) {
                    m.insert(a, n.to_string());
                }
            }
        }
        let queries: Vec<u64> = args.get("queries").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect())
            .unwrap_or_default();
        let results: Vec<Value> = queries.iter().map(|q| json!({
            "addr": q,
            "name": m.resolve(*q),
        })).collect();
        Ok(ToolResult::text(json!({
            "map_len": m.len(),
            "results": results,
            "source": "rustre_decompiler::SymbolMap",
        }).to_string()))
    }
}

pub struct RustreDecompilerCallconvLiftMnemonicTool;
impl RustreDecompilerCallconvLiftMnemonicTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_decompiler_callconv_lift_mnemonic".to_string(),
            description: "Lift a single mnemonic+operands via rustre_decompiler::callconv_bridge::lift_mnemonic.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["mnemonic"],
                "properties": {
                    "mnemonic": { "type": "string" },
                    "operands": { "type": "string" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerCallconvLiftMnemonicTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mnem = args.get("mnemonic").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'mnemonic'".into()))?;
        let ops = args.get("operands").and_then(Value::as_str).unwrap_or("");
        let instrs = rustre_decompiler::callconv_bridge::lift_mnemonic(mnem, ops);
        let summaries: Vec<Value> = instrs.iter().map(|di| json!({
            "kind": format!("{:?}", di),
        })).collect();
        Ok(ToolResult::text(json!({
            "mnemonic": mnem,
            "operands": ops,
            "count": summaries.len(),
            "instrs": summaries,
            "source": "rustre_decompiler::callconv_bridge::lift_mnemonic",
        }).to_string()))
    }
}

pub struct RustreDecompilerBatchIsCKeywordTool;
impl RustreDecompilerBatchIsCKeywordTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_decompiler_batch_is_c_keyword".to_string(),
            description: "Classify a batch of identifiers as C reserved words via rustre_decompiler::pseudocode_generator::is_c_keyword.".to_string(),
            input_schema: json!({
                "type": "object",
                "required": ["names"],
                "properties": { "names": { "type": "array", "items": { "type": "string" } } }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerBatchIsCKeywordTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let names: Vec<String> = args.get("names").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let results: Vec<Value> = names.iter().map(|n| json!({
            "name": n,
            "is_keyword": rustre_decompiler::pseudocode_generator::is_c_keyword(n),
        })).collect();
        let hits = results.iter().filter(|v| v.get("is_keyword").and_then(Value::as_bool).unwrap_or(false)).count();
        Ok(ToolResult::text(json!({
            "count": results.len(),
            "keyword_hits": hits,
            "results": results,
            "source": "rustre_decompiler::pseudocode_generator::is_c_keyword",
        }).to_string()))
    }
}

pub struct RustreDecompilerSymbolMapOpsTool;
impl RustreDecompilerSymbolMapOpsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_decompiler_symbol_map_ops".to_string(), description: "SymbolMap: insert entries, report len/is_empty.".to_string(), input_schema: json!({"type":"object","properties":{"pairs":{"type":"array","items":{"type":"array"}}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerSymbolMapOpsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut m = rustre_decompiler::SymbolMap::new();
        if let Some(arr) = args.get("pairs").and_then(Value::as_array) {
            for p in arr {
                if let (Some(a), Some(n)) = (p.get(0).and_then(Value::as_u64), p.get(1).and_then(Value::as_str)) {
                    m.insert(a, n.to_string());
                }
            }
        }
        Ok(ToolResult::text(json!({"len":m.len(),"is_empty":m.is_empty(),"source":"rustre_decompiler::SymbolMap"}).to_string()))
    }
}

pub struct RustreDecompilerFunctionNameGenCountTool;
impl RustreDecompilerFunctionNameGenCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_decompiler_function_name_gen_count".to_string(), description: "FunctionNameGenerator: generate a name and return counter.".to_string(), input_schema: json!({"type":"object","properties":{"address":{"type":"integer"},"hint":{"type":"string"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerFunctionNameGenCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("address").and_then(Value::as_u64).unwrap_or(0);
        let hint = args.get("hint").and_then(Value::as_str);
        let mut g = rustre_decompiler::FunctionNameGenerator::new();
        let name = g.name_for(addr, hint);
        Ok(ToolResult::text(json!({"name":name,"count":g.count(),"source":"rustre_decompiler::FunctionNameGenerator"}).to_string()))
    }
}

pub struct RustreDecompilerTypePropAddTool;
impl RustreDecompilerTypePropAddTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_decompiler_type_prop_add".to_string(), description: "TypePropagation: seed a variable type then propagate_add.".to_string(), input_schema: json!({"type":"object","properties":{"var":{"type":"string"},"ty":{"type":"string"},"rhs_const":{"type":"boolean"}},"required":["var","ty"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerTypePropAddTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let var = args.get("var").and_then(Value::as_str).unwrap_or("v");
        let ty = args.get("ty").and_then(Value::as_str).unwrap_or("int*");
        let rc = args.get("rhs_const").and_then(Value::as_bool).unwrap_or(true);
        let mut tp = rustre_decompiler::TypePropagation::new();
        tp.set_type(var, ty);
        let out = tp.propagate_add(var, rc);
        Ok(ToolResult::text(json!({"result":out,"count":tp.count(),"source":"rustre_decompiler::TypePropagation::propagate_add"}).to_string()))
    }
}

pub struct RustreDecompilerVarRecoveryStackNameTool;
impl RustreDecompilerVarRecoveryStackNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_decompiler_var_recovery_stack_name".to_string(), description: "VariableRecovery::stack_var_name for a given offset.".to_string(), input_schema: json!({"type":"object","properties":{"offset":{"type":"integer"}},"required":["offset"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerVarRecoveryStackNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let off = args.get("offset").and_then(Value::as_i64).unwrap_or(-8);
        let mut vr = rustre_decompiler::VariableRecovery::new();
        let n = vr.stack_var_name(off);
        Ok(ToolResult::text(json!({"name":n,"total_vars":vr.total_vars(),"source":"rustre_decompiler::VariableRecovery::stack_var_name"}).to_string()))
    }
}

pub struct RustreDecompilerVarRecoveryFreshTool;
impl RustreDecompilerVarRecoveryFreshTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_decompiler_var_recovery_fresh".to_string(), description: "VariableRecovery::fresh_var — generate N fresh variable names.".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerVarRecoveryFreshTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(3) as usize;
        let mut vr = rustre_decompiler::VariableRecovery::new();
        let names: Vec<String> = (0..n).map(|_| vr.fresh_var()).collect();
        Ok(ToolResult::text(json!({"names":names,"source":"rustre_decompiler::VariableRecovery::fresh_var"}).to_string()))
    }
}

pub struct RustreDecompilerExprRecoveryKfcTool;
impl RustreDecompilerExprRecoveryKfcTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_decompiler_expr_recovery_kfc".to_string(), description: "ExpressionRecovery: register functions, report known_function_count.".to_string(), input_schema: json!({"type":"object","properties":{"functions":{"type":"array","items":{"type":"array"}}}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerExprRecoveryKfcTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut er = rustre_decompiler::ExpressionRecovery::new();
        if let Some(arr) = args.get("functions").and_then(Value::as_array) {
            for p in arr {
                if let (Some(n), Some(t)) = (p.get(0).and_then(Value::as_str), p.get(1).and_then(Value::as_str)) {
                    er.register_function(n.to_string(), t.to_string());
                }
            }
        }
        Ok(ToolResult::text(json!({"known_function_count":er.known_function_count(),"source":"rustre_decompiler::ExpressionRecovery"}).to_string()))
    }
}

pub struct RustreDecompilerCfsDetectLoopTool;
impl RustreDecompilerCfsDetectLoopTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_decompiler_cfs_detect_loop".to_string(), description: "ControlFlowStructuring::detect_loop on a line sequence.".to_string(), input_schema: json!({"type":"object","properties":{"lines":{"type":"array","items":{"type":"string"}}},"required":["lines"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerCfsDetectLoopTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let empty = Vec::new();
        let lines = args.get("lines").and_then(Value::as_array).unwrap_or(&empty);
        let strs: Vec<&str> = lines.iter().filter_map(Value::as_str).collect();
        let out = rustre_decompiler::ControlFlowStructuring::detect_loop(&strs);
        Ok(ToolResult::text(json!({"detected":out.is_some(),"source":"rustre_decompiler::ControlFlowStructuring::detect_loop"}).to_string()))
    }
}

pub struct RustreDecompilerDefaultPipelineStandardTool;
impl RustreDecompilerDefaultPipelineStandardTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_decompiler_default_pipeline_standard".to_string(), description: "DefaultPipelineFactory::standard — report pass count and names.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerDefaultPipelineStandardTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let p = rustre_decompiler::DefaultPipelineFactory::standard(rustre_decompiler::DecompOptions::default());
        Ok(ToolResult::text(json!({"pass_count":p.pass_count(),"pass_names":p.pass_names(),"source":"rustre_decompiler::DefaultPipelineFactory::standard"}).to_string()))
    }
}

pub struct RustreDecompilerDefaultPipelineDisasmTool;
impl RustreDecompilerDefaultPipelineDisasmTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_decompiler_default_pipeline_disasm".to_string(), description: "DefaultPipelineFactory::disassembly_only — report pass count and names.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerDefaultPipelineDisasmTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let p = rustre_decompiler::DefaultPipelineFactory::disassembly_only();
        Ok(ToolResult::text(json!({"pass_count":p.pass_count(),"pass_names":p.pass_names(),"source":"rustre_decompiler::DefaultPipelineFactory::disassembly_only"}).to_string()))
    }
}

pub struct RustreDecompilerPluginManagerCountTool;
impl RustreDecompilerPluginManagerCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_decompiler_plugin_manager_count".to_string(), description: "DecompilerPluginManager::new — report count and provided-passes.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerPluginManagerCountTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let pm = rustre_decompiler::DecompilerPluginManager::new();
        Ok(ToolResult::text(json!({"count":pm.count(),"provided_passes":pm.all_provided_passes(),"source":"rustre_decompiler::DecompilerPluginManager"}).to_string()))
    }
}

pub struct RustreDecompilerPassRegistryNewTool;
impl RustreDecompilerPassRegistryNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_decompiler_pass_registry_new".to_string(), description: "PassRegistry::new — report len/is_empty/names.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerPassRegistryNewTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let r = rustre_decompiler::PassRegistry::new();
        let names: Vec<String> = r.names().into_iter().map(str::to_string).collect();
        Ok(ToolResult::text(json!({"len":r.len(),"is_empty":r.is_empty(),"names":names,"source":"rustre_decompiler::PassRegistry"}).to_string()))
    }
}

pub struct RustreDecompilerQualityFromSourceTool;
impl RustreDecompilerQualityFromSourceTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "rustre_decompiler_quality_from_source".to_string(), description: "QualityMetrics::from_source — expression_density and readability_score.".to_string(), input_schema: json!({"type":"object","properties":{"source":{"type":"string"}},"required":["source"]}), parameters: Value::Null }
    }
}
#[async_trait]
impl ToolHandler for RustreDecompilerQualityFromSourceTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let src = args.get("source").and_then(Value::as_str).unwrap_or("");
        let q = rustre_decompiler::QualityMetrics::from_source(src);
        Ok(ToolResult::text(json!({"line_count":q.line_count,"statement_count":q.statement_count,"operator_count":q.operator_count,"goto_count":q.goto_count,"max_nesting":q.max_nesting,"control_constructs":q.control_constructs,"expression_density":q.expression_density(),"readability_score":q.readability_score(),"source":"rustre_decompiler::QualityMetrics"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (RustreDecompilerMemOperandParseTool::definition(), Box::new(RustreDecompilerMemOperandParseTool)),
        (RustreDecompilerCallconvArchFromStrTool::definition(), Box::new(RustreDecompilerCallconvArchFromStrTool)),
        (RustreDecompilerStandardPassSpecsTool::definition(), Box::new(RustreDecompilerStandardPassSpecsTool)),
        (RustreDecompilerX86WidthHintTool::definition(), Box::new(RustreDecompilerX86WidthHintTool)),
        (RustreDecompilerLoadBinaryInfoTool::definition(), Box::new(RustreDecompilerLoadBinaryInfoTool)),
        (RustreDecompilerDetectFunctionsPathTool::definition(), Box::new(RustreDecompilerDetectFunctionsPathTool)),
        (RustreDecompilerDefaultOptionsTool::definition(), Box::new(RustreDecompilerDefaultOptionsTool)),
        (RustreDecompilerSymbolMapResolveTool::definition(), Box::new(RustreDecompilerSymbolMapResolveTool)),
        (RustreDecompilerCallconvLiftMnemonicTool::definition(), Box::new(RustreDecompilerCallconvLiftMnemonicTool)),
        (RustreDecompilerBatchIsCKeywordTool::definition(), Box::new(RustreDecompilerBatchIsCKeywordTool)),
        (RustreDecompilerSymbolMapOpsTool::definition(), Box::new(RustreDecompilerSymbolMapOpsTool)),
        (RustreDecompilerFunctionNameGenCountTool::definition(), Box::new(RustreDecompilerFunctionNameGenCountTool)),
        (RustreDecompilerTypePropAddTool::definition(), Box::new(RustreDecompilerTypePropAddTool)),
        (RustreDecompilerVarRecoveryStackNameTool::definition(), Box::new(RustreDecompilerVarRecoveryStackNameTool)),
        (RustreDecompilerVarRecoveryFreshTool::definition(), Box::new(RustreDecompilerVarRecoveryFreshTool)),
        (RustreDecompilerExprRecoveryKfcTool::definition(), Box::new(RustreDecompilerExprRecoveryKfcTool)),
        (RustreDecompilerCfsDetectLoopTool::definition(), Box::new(RustreDecompilerCfsDetectLoopTool)),
        (RustreDecompilerDefaultPipelineStandardTool::definition(), Box::new(RustreDecompilerDefaultPipelineStandardTool)),
        (RustreDecompilerDefaultPipelineDisasmTool::definition(), Box::new(RustreDecompilerDefaultPipelineDisasmTool)),
        (RustreDecompilerPluginManagerCountTool::definition(), Box::new(RustreDecompilerPluginManagerCountTool)),
        (RustreDecompilerPassRegistryNewTool::definition(), Box::new(RustreDecompilerPassRegistryNewTool)),
        (RustreDecompilerQualityFromSourceTool::definition(), Box::new(RustreDecompilerQualityFromSourceTool)),
    ]
}
