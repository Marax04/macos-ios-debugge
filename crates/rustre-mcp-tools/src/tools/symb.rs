//! MCP wrappers for the rustre-symb crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct SymbEngineWidenSequenceCheckTool;

pub struct SymbEngineWidenSequenceExprTool;

pub struct SymbSymAddConstTool;

pub struct SymbSymXorConstTool;

pub struct SymbEngineDefaultSolverTool;

pub struct SymbEngineDefaultStrategyTool;

pub struct SymbBitvecWidthTool;

pub struct SymbUnsatMessageTool;

pub struct SymbEngineStateManagerNewLenTool;

pub struct SymbEngineExecutorConfigDefaultTool;
impl SymbEngineExecutorConfigDefaultTool {
    #[must_use]
    pub fn definition() -> ToolDefinition { ToolDefinition { name: "symb_engine_executor_config_default".to_string(), description: "Default ExecutorConfig.".to_string(), input_schema: json!({ "type": "object", "properties": {} }), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for SymbEngineExecutorConfigDefaultTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let c = rustre_symb_engine::ExecutorConfig::default();
        Ok(ToolResult::text(json!({"max_states": c.max_states, "max_depth": c.max_depth, "state_merging": c.state_merging, "timeout_ms": c.timeout_ms}).to_string()))
    }
}

pub struct SymbEngineExecConfigDefaultTool;
impl SymbEngineExecConfigDefaultTool {
    #[must_use]
    pub fn definition() -> ToolDefinition { ToolDefinition { name: "symb_engine_exec_config_default".to_string(), description: "Default ExecConfig.".to_string(), input_schema: json!({ "type": "object", "properties": {} }), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for SymbEngineExecConfigDefaultTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let c = rustre_symb_engine::ExecConfig::default();
        Ok(ToolResult::text(json!({"max_steps": c.max_steps, "max_paths": c.max_paths, "explore_both_branches": c.explore_both_branches}).to_string()))
    }
}

pub struct SymbEngineVulnDetectorNewTool;
impl SymbEngineVulnDetectorNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition { ToolDefinition { name: "symb_engine_vuln_detector_new".to_string(), description: "Fresh VulnDetector.".to_string(), input_schema: json!({ "type": "object", "properties": {} }), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for SymbEngineVulnDetectorNewTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let d = rustre_symb_engine::VulnDetector::new();
        Ok(ToolResult::text(json!({"findings_count": d.findings().len()}).to_string()))
    }
}

pub struct SymbEngineLiftedInstrNewTool;
impl SymbEngineLiftedInstrNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition { ToolDefinition { name: "symb_engine_lifted_instr_new".to_string(), description: "Construct LiftedInstr.".to_string(), input_schema: json!({ "type": "object", "properties": { "address": {"type":"integer"}, "mnemonic": {"type":"string"} }, "required":["address","mnemonic"] }), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for SymbEngineLiftedInstrNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("address").and_then(Value::as_u64).unwrap_or(0);
        let m = args.get("mnemonic").and_then(Value::as_str).unwrap_or("").to_string();
        let li = rustre_symb_engine::LiftedInstr::new(addr, m);
        Ok(ToolResult::text(json!({"address": li.address, "original_mnemonic": li.original_mnemonic, "ir_text": li.ir_text}).to_string()))
    }
}

pub struct SymbEngineSymbolicInterpreterStateNewTool;
impl SymbEngineSymbolicInterpreterStateNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition { ToolDefinition { name: "symb_engine_symbolic_interpreter_state_new".to_string(), description: "Fresh SymbolicInterpreterState.".to_string(), input_schema: json!({ "type": "object", "properties": {} }), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for SymbEngineSymbolicInterpreterStateNewTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_symb_engine::SymbolicInterpreterState::new();
        Ok(ToolResult::text(json!({"regs": s.regs.len(), "memory": s.memory.len()}).to_string()))
    }
}

pub struct SymbEngineFunctionSummaryNewTool;

pub struct SymbEngineExecutorConfigDefaultsTool;

pub struct SymbEngineStateManagerNewTool;

pub struct SymbSymTypeBitVecWidthTool;

pub struct SymbPathConstraintNewIsTriviallyFalseTool;

pub struct SymbSymExprBitWidthConstTool;
impl SymbSymExprBitWidthConstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_sym_expr_bit_width_const".to_string(),
            description: "Report SymExpr::bit_width for a ConstBv literal.".to_string(),
            input_schema: json!({"type":"object","required":["val","width"],"properties":{"val":{"type":"integer"},"width":{"type":"integer","minimum":1,"maximum":64}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbSymExprBitWidthConstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let val = args.get("val").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'val'".into()))?;
        let width = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let e = rustre_symb::SymExpr::bv(val, width);
        Ok(ToolResult::text(json!({"val":val,"width":width,"bit_width":e.bit_width(),"is_const":e.is_const(),"as_const_u64":e.as_const_u64(),"source":"rustre_symb::SymExpr::bit_width"}).to_string()))
    }
}

pub struct SymbSymExprAsConstBoolTool;
impl SymbSymExprAsConstBoolTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_sym_expr_as_const_bool".to_string(),
            description: "Return SymExpr::as_const_bool for a ConstBool literal.".to_string(),
            input_schema: json!({"type":"object","required":["val"],"properties":{"val":{"type":"boolean"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbSymExprAsConstBoolTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("val").and_then(Value::as_bool).ok_or_else(|| McpError::InvalidParams("missing 'val'".into()))?;
        let e = rustre_symb::SymExpr::ConstBool(v);
        Ok(ToolResult::text(json!({"input":v,"as_const_bool":e.as_const_bool(),"is_const":e.is_const(),"source":"rustre_symb::SymExpr::as_const_bool"}).to_string()))
    }
}

pub struct SymbSimplifierConstAddTool;
impl SymbSimplifierConstAddTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_simplifier_const_add".to_string(),
            description: "Simplify Add(ConstBv, ConstBv) via SymExprSimplifier.".to_string(),
            input_schema: json!({"type":"object","required":["lhs","rhs","width"],"properties":{"lhs":{"type":"integer"},"rhs":{"type":"integer"},"width":{"type":"integer","minimum":1,"maximum":64}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbSimplifierConstAddTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let lhs = args.get("lhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lhs'".into()))?;
        let rhs = args.get("rhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rhs'".into()))?;
        let width = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let raw = rustre_symb::SymExpr::Add(
            Box::new(rustre_symb::SymExpr::bv(lhs,width)),
            Box::new(rustre_symb::SymExpr::bv(rhs,width)),
        );
        let simplified = rustre_symb::SymExprSimplifier::new().simplify(raw);
        Ok(ToolResult::text(json!({"lhs":lhs,"rhs":rhs,"width":width,"result":simplified.as_const_u64(),"source":"rustre_symb::SymExprSimplifier::simplify"}).to_string()))
    }
}

pub struct SymbPathConstraintTriviallyFalseTool;
impl SymbPathConstraintTriviallyFalseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_path_constraint_trivially_false".to_string(),
            description: "Build PathConstraint from bool terms and report is_trivially_false.".to_string(),
            input_schema: json!({"type":"object","required":["terms"],"properties":{"terms":{"type":"array","items":{"type":"boolean"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbPathConstraintTriviallyFalseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let terms = args.get("terms").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'terms'".into()))?;
        let mut pc = rustre_symb::PathConstraint::new();
        for t in terms {
            if let Some(b) = t.as_bool() {
                pc.add(rustre_symb::SymExpr::ConstBool(b));
            }
        }
        let conj = pc.as_conjunction();
        Ok(ToolResult::text(json!({
            "count": pc.terms.len(),
            "is_trivially_false": pc.is_trivially_false(),
            "conjunction_is_const_bool": conj.as_const_bool(),
            "source": "rustre_symb::PathConstraint"
        }).to_string()))
    }
}

pub struct SymbEngineExecutorConfigDefaultsV3Tool;
impl SymbEngineExecutorConfigDefaultsV3Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_executor_config_defaults_v3".to_string(),
            description: "Return the default ExecutorConfig for rustre-symb-engine.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineExecutorConfigDefaultsV3Tool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let c = rustre_symb_engine::ExecutorConfig::default();
        Ok(ToolResult::text(json!({
            "max_states": c.max_states,
            "max_depth": c.max_depth,
            "state_merging": c.state_merging,
            "solver": format!("{:?}", c.solver),
            "timeout_ms": c.timeout_ms,
            "strategy": format!("{:?}", c.strategy),
            "source": "rustre_symb_engine::ExecutorConfig::default"
        }).to_string()))
    }
}

pub struct SymbEngineSolverTypeListTool;
impl SymbEngineSolverTypeListTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_solver_type_list".to_string(),
            description: "List available SolverType variants in rustre-symb-engine.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineSolverTypeListTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_symb_engine::SolverType;
        let all = [SolverType::BitBlasting, SolverType::SmtLib2, SolverType::Z3];
        let names: Vec<String> = all.iter().map(|s| format!("{s:?}")).collect();
        Ok(ToolResult::text(json!({
            "solvers": names,
            "default": format!("{:?}", SolverType::default()),
            "source": "rustre_symb_engine::SolverType"
        }).to_string()))
    }
}

pub struct SymbEngineExplorationStrategyListTool;
impl SymbEngineExplorationStrategyListTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_exploration_strategy_list".to_string(),
            description: "List ExplorationStrategy variants for the symbolic executor.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineExplorationStrategyListTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_symb_engine::ExplorationStrategy;
        let all = [
            ExplorationStrategy::Dfs, ExplorationStrategy::Bfs,
            ExplorationStrategy::RandomWalk, ExplorationStrategy::CoverageGuided,
        ];
        let names: Vec<String> = all.iter().map(|s| format!("{s:?}")).collect();
        Ok(ToolResult::text(json!({
            "strategies": names,
            "default": format!("{:?}", ExplorationStrategy::default()),
            "source": "rustre_symb_engine::ExplorationStrategy"
        }).to_string()))
    }
}

pub struct SymbEngineStateManagerEmptyStatsTool;
impl SymbEngineStateManagerEmptyStatsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_state_manager_empty_stats".to_string(),
            description: "Return the counters of a freshly-created StateManager (all zero).".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineStateManagerEmptyStatsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let sm = rustre_symb_engine::StateManager::new();
        Ok(ToolResult::text(json!({
            "len": sm.len(),
            "is_empty": sm.is_empty(),
            "total_enqueued": sm.total_enqueued(),
            "pruned": sm.pruned(),
            "source": "rustre_symb_engine::StateManager::new"
        }).to_string()))
    }
}

pub struct SymbEngineFunctionSummaryNewV3Tool;
impl SymbEngineFunctionSummaryNewV3Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_function_summary_new_v3".to_string(),
            description: "Create an empty FunctionSummary for a given address and report its shape.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{"address":{"type":"integer"}},
                "required":["address"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineFunctionSummaryNewV3Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("address").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?;
        let fs = rustre_symb_engine::FunctionSummary::new(addr);
        Ok(ToolResult::text(json!({
            "address": fs.address,
            "has_name": fs.name.is_some(),
            "output_register_count": fs.output_registers.len(),
            "memory_write_count": fs.memory_writes.len(),
            "has_return_value": fs.return_value.is_some(),
            "may_not_return": fs.may_not_return,
            "source": "rustre_symb_engine::FunctionSummary::new"
        }).to_string()))
    }
}

pub struct SymbEngineVulnDetectorEmptyTool;
impl SymbEngineVulnDetectorEmptyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_vuln_detector_empty".to_string(),
            description: "Create a VulnDetector and report the empty findings baseline.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineVulnDetectorEmptyTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let vd = rustre_symb_engine::VulnDetector::new();
        Ok(ToolResult::text(json!({
            "finding_count": vd.findings().len(),
            "source": "rustre_symb_engine::VulnDetector::new"
        }).to_string()))
    }
}

pub struct SymbEngineSymbolicAddressConcreteTool;
impl SymbEngineSymbolicAddressConcreteTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_symbolic_address_concrete".to_string(),
            description: "Wrap a concrete u64 address in SymbolicAddress::Concrete and report predicates.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{"address":{"type":"integer"}},
                "required":["address"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineSymbolicAddressConcreteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("address").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?;
        let sa = rustre_symb_engine::SymbolicAddress::Concrete(addr);
        Ok(ToolResult::text(json!({
            "address": addr,
            "is_concrete": sa.is_concrete(),
            "concrete_value": sa.concrete_value(),
            "source": "rustre_symb_engine::SymbolicAddress::Concrete"
        }).to_string()))
    }
}

pub struct SymbEngineSymbolicExecutorStatsTool;
impl SymbEngineSymbolicExecutorStatsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_symbolic_executor_stats".to_string(),
            description: "Return the initial ExecutorStats of a default SymbolicExecutor.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineSymbolicExecutorStatsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let exe = rustre_symb_engine::SymbolicExecutor::with_default_config();
        let s = exe.stats();
        Ok(ToolResult::text(json!({
            "live_states": s.live_states,
            "total_enqueued": s.total_enqueued,
            "pruned_states": s.pruned_states,
            "visited_addresses": s.visited_addresses,
            "vuln_count": s.vuln_count,
            "source": "rustre_symb_engine::SymbolicExecutor::with_default_config"
        }).to_string()))
    }
}

pub struct SymbEngineExecutorConfigCustomTool;
impl SymbEngineExecutorConfigCustomTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_executor_config_custom".to_string(),
            description: "Build a custom ExecutorConfig and echo its normalized fields.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "max_states":{"type":"integer"},
                    "max_depth":{"type":"integer"},
                    "state_merging":{"type":"boolean"},
                    "timeout_ms":{"type":"integer"}
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineExecutorConfigCustomTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut c = rustre_symb_engine::ExecutorConfig::default();
        if let Some(v) = args.get("max_states").and_then(Value::as_u64) { c.max_states = v as usize; }
        if let Some(v) = args.get("max_depth").and_then(Value::as_u64) { c.max_depth = v as u32; }
        if let Some(v) = args.get("state_merging").and_then(Value::as_bool) { c.state_merging = v; }
        if let Some(v) = args.get("timeout_ms").and_then(Value::as_u64) { c.timeout_ms = v; }
        Ok(ToolResult::text(json!({
            "max_states": c.max_states,
            "max_depth": c.max_depth,
            "state_merging": c.state_merging,
            "solver": format!("{:?}", c.solver),
            "timeout_ms": c.timeout_ms,
            "strategy": format!("{:?}", c.strategy),
            "source": "rustre_symb_engine::ExecutorConfig"
        }).to_string()))
    }
}

pub struct SymbEngineHaltReasonListTool;
impl SymbEngineHaltReasonListTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_halt_reason_list".to_string(),
            description: "Enumerate HaltReason variants with their Display representation.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineHaltReasonListTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_symb_engine::HaltReason;
        let all = [
            HaltReason::MaxSteps,
            HaltReason::ExplicitHalt,
            HaltReason::Unreachable,
            HaltReason::Error("example".to_string()),
        ];
        let names: Vec<String> = all.iter().map(|h| h.to_string()).collect();
        Ok(ToolResult::text(json!({
            "variants": names,
            "source": "rustre_symb_engine::HaltReason"
        }).to_string()))
    }
}

pub struct SymbEngineVulnDetectorRegisterFreeTool;
impl SymbEngineVulnDetectorRegisterFreeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_vuln_detector_register_free".to_string(),
            description: "Register a freed heap address in a fresh VulnDetector and report finding count.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{"address":{"type":"integer"}},
                "required":["address"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineVulnDetectorRegisterFreeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("address").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?;
        let mut vd = rustre_symb_engine::VulnDetector::new();
        vd.register_free(addr);
        Ok(ToolResult::text(json!({
            "freed_address": addr,
            "finding_count": vd.findings().len(),
            "source": "rustre_symb_engine::VulnDetector::register_free"
        }).to_string()))
    }
}

pub struct SymbEngineExprDepthChainAddTool;
impl SymbEngineExprDepthChainAddTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_expr_depth_chain_add".to_string(),
            description: "Build a left-leaning Add chain of `depth` Const nodes and report analysis::expr_depth.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "depth": { "type": "integer", "minimum": 1, "maximum": 64 } },
                "required": ["depth"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineExprDepthChainAddTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_symb_engine::full_symex::SymExpr;
        let depth = args.get("depth").and_then(Value::as_u64).unwrap_or(1).clamp(1, 64) as usize;
        let mut e = SymExpr::Const(1, 8);
        for _ in 1..depth {
            e = SymExpr::Add(Box::new(e), Box::new(SymExpr::Const(1, 8)));
        }
        let d = rustre_symb_engine::analysis::expr_depth(&e);
        Ok(ToolResult::text(json!({
            "depth_input": depth,
            "expr_depth": d,
            "source": "rustre_symb_engine::analysis::expr_depth"
        }).to_string()))
    }
}

pub struct SymbEngineExprNodeCountChainAddTool;
impl SymbEngineExprNodeCountChainAddTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_expr_node_count_chain_add".to_string(),
            description: "Build a left-leaning Add chain of `depth` Const nodes and report analysis::expr_node_count.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "depth": { "type": "integer", "minimum": 1, "maximum": 64 } },
                "required": ["depth"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineExprNodeCountChainAddTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_symb_engine::full_symex::SymExpr;
        let depth = args.get("depth").and_then(Value::as_u64).unwrap_or(1).clamp(1, 64) as usize;
        let mut e = SymExpr::Const(1, 8);
        for _ in 1..depth {
            e = SymExpr::Add(Box::new(e), Box::new(SymExpr::Const(1, 8)));
        }
        let n = rustre_symb_engine::analysis::expr_node_count(&e);
        Ok(ToolResult::text(json!({
            "depth_input": depth,
            "node_count": n,
            "source": "rustre_symb_engine::analysis::expr_node_count"
        }).to_string()))
    }
}

pub struct SymbEngineSimplifyConstraintsLenTool;
impl SymbEngineSimplifyConstraintsLenTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_simplify_constraints_len".to_string(),
            description: "Feed N Const(v,8) constraints to analysis::simplify_constraints and report length.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "values": { "type": "array", "items": { "type": "integer" } }
                },
                "required": ["values"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineSimplifyConstraintsLenTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_symb_engine::full_symex::SymExpr;
        let vals: Vec<u64> = args.get("values").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
        let cs: Vec<SymExpr> = vals.iter().map(|&v| SymExpr::Const(v, 8)).collect();
        let simplified = rustre_symb_engine::analysis::simplify_constraints(&cs);
        Ok(ToolResult::text(json!({
            "input_len": cs.len(),
            "simplified_len": simplified.len(),
            "source": "rustre_symb_engine::analysis::simplify_constraints"
        }).to_string()))
    }
}

pub struct SymbEngineHasContradictionConstTool;
impl SymbEngineHasContradictionConstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_has_contradiction_const".to_string(),
            description: "Detect contradictions on a list of Const values (0 => trivially unsat).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "values": { "type": "array", "items": { "type": "integer" } }
                },
                "required": ["values"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineHasContradictionConstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_symb_engine::full_symex::SymExpr;
        let vals: Vec<u64> = args.get("values").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
        let cs: Vec<SymExpr> = vals.iter().map(|&v| SymExpr::Const(v, 8)).collect();
        let has = rustre_symb_engine::analysis::has_contradiction(&cs);
        Ok(ToolResult::text(json!({
            "input_len": cs.len(),
            "has_contradiction": has,
            "source": "rustre_symb_engine::analysis::has_contradiction"
        }).to_string()))
    }
}

pub struct SymbEngineCheckSatisfiableConstTool;
impl SymbEngineCheckSatisfiableConstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_check_satisfiable_const".to_string(),
            description: "Run full_symex::check_satisfiable on N Const(v,8) constraints.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "values": { "type": "array", "items": { "type": "integer" } }
                },
                "required": ["values"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineCheckSatisfiableConstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_symb_engine::full_symex::SymExpr;
        let vals: Vec<u64> = args.get("values").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
        let cs: Vec<SymExpr> = vals.iter().map(|&v| SymExpr::Const(v, 8)).collect();
        let sat = rustre_symb_engine::full_symex::check_satisfiable(&cs);
        Ok(ToolResult::text(json!({
            "input_len": cs.len(),
            "satisfiable": sat,
            "source": "rustre_symb_engine::full_symex::check_satisfiable"
        }).to_string()))
    }
}

pub struct SymbEngineFormatPathConditionsConstTool;
impl SymbEngineFormatPathConditionsConstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_format_path_conditions_const".to_string(),
            description: "Render a Const-only constraint list via analysis::format_path_conditions.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "values": { "type": "array", "items": { "type": "integer" } }
                },
                "required": ["values"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineFormatPathConditionsConstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_symb_engine::full_symex::SymExpr;
        let vals: Vec<u64> = args.get("values").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
        let cs: Vec<SymExpr> = vals.iter().map(|&v| SymExpr::Const(v, 8)).collect();
        let s = rustre_symb_engine::analysis::format_path_conditions(&cs);
        Ok(ToolResult::text(json!({
            "input_len": cs.len(),
            "formatted": s,
            "source": "rustre_symb_engine::analysis::format_path_conditions"
        }).to_string()))
    }
}

pub struct SymbEngineLoopBoundAnalysisNewTool;
impl SymbEngineLoopBoundAnalysisNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_loop_bound_analysis_new".to_string(),
            description: "Construct analysis::LoopBoundAnalysis with a default bound and report field summary.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "default_bound": { "type": "integer", "minimum": 0 } },
                "required": ["default_bound"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineLoopBoundAnalysisNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let db = args.get("default_bound").and_then(Value::as_u64).unwrap_or(0) as u32;
        let lba = rustre_symb_engine::analysis::LoopBoundAnalysis::new(db);
        Ok(ToolResult::text(json!({
            "default_bound": lba.default_bound,
            "back_edges_len": lba.back_edges.len(),
            "bounds_len": lba.bounds.len(),
            "source": "rustre_symb_engine::analysis::LoopBoundAnalysis::new"
        }).to_string()))
    }
}

pub struct SymbEngineLoopBoundAnalysisAddEdgeTool;
impl SymbEngineLoopBoundAnalysisAddEdgeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_loop_bound_analysis_add_edge".to_string(),
            description: "Add a back-edge and report loop_count/get_bound(header) on LoopBoundAnalysis.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "default_bound": { "type": "integer", "minimum": 0 },
                    "from": { "type": "integer" },
                    "to":   { "type": "integer" }
                },
                "required": ["default_bound", "from", "to"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineLoopBoundAnalysisAddEdgeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let db = args.get("default_bound").and_then(Value::as_u64).unwrap_or(0) as u32;
        let from = args.get("from").and_then(Value::as_u64).unwrap_or(0);
        let to   = args.get("to").and_then(Value::as_u64).unwrap_or(0);
        let mut lba = rustre_symb_engine::analysis::LoopBoundAnalysis::new(db);
        lba.add_back_edge(from, to);
        let bound = lba.get_bound(to);
        let is_header = lba.is_loop_header(to);
        let loop_count = lba.loop_count();
        Ok(ToolResult::text(json!({
            "loop_count": loop_count,
            "bound_for_to": bound,
            "to_is_loop_header": is_header,
            "source": "rustre_symb_engine::analysis::LoopBoundAnalysis"
        }).to_string()))
    }
}

pub struct SymbEngineStateMergerHashConstraintsTool;
impl SymbEngineStateMergerHashConstraintsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_engine_state_merger_hash_constraints".to_string(),
            description: "Hash a Const-only rustre_symb::SymExpr constraint set via state_merger::MergeKey::hash_constraints.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "values": { "type": "array", "items": { "type": "integer" } },
                    "width":  { "type": "integer", "minimum": 1, "maximum": 128 }
                },
                "required": ["values"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbEngineStateMergerHashConstraintsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let width = args.get("width").and_then(Value::as_u64).unwrap_or(64) as u32;
        let vals: Vec<u64> = args.get("values").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
        let cs: Vec<rustre_symb::SymExpr> = vals.iter()
            .map(|&v| rustre_symb::SymExpr::bv(v, width)).collect();
        let h = rustre_symb_engine::state_merger::MergeKey::hash_constraints(&cs);
        Ok(ToolResult::text(json!({
            "input_len": cs.len(),
            "hash": h,
            "source": "rustre_symb_engine::state_merger::MergeKey::hash_constraints"
        }).to_string()))
    }
}

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (SymbEngineWidenSequenceCheckTool::definition(), Box::new(SymbEngineWidenSequenceCheckTool)),
        (SymbEngineWidenSequenceExprTool::definition(), Box::new(SymbEngineWidenSequenceExprTool)),
        (SymbSymAddConstTool::definition(), Box::new(SymbSymAddConstTool)),
        (SymbSymXorConstTool::definition(), Box::new(SymbSymXorConstTool)),
        (SymbEngineDefaultSolverTool::definition(), Box::new(SymbEngineDefaultSolverTool)),
        (SymbEngineDefaultStrategyTool::definition(), Box::new(SymbEngineDefaultStrategyTool)),
        (SymbBitvecWidthTool::definition(), Box::new(SymbBitvecWidthTool)),
        (SymbUnsatMessageTool::definition(), Box::new(SymbUnsatMessageTool)),
        (SymbEngineStateManagerNewLenTool::definition(), Box::new(SymbEngineStateManagerNewLenTool)),
        (SymbEngineExecutorConfigDefaultTool::definition(), Box::new(SymbEngineExecutorConfigDefaultTool)),
        (SymbEngineExecConfigDefaultTool::definition(), Box::new(SymbEngineExecConfigDefaultTool)),
        (SymbEngineVulnDetectorNewTool::definition(), Box::new(SymbEngineVulnDetectorNewTool)),
        (SymbEngineLiftedInstrNewTool::definition(), Box::new(SymbEngineLiftedInstrNewTool)),
        (SymbEngineSymbolicInterpreterStateNewTool::definition(), Box::new(SymbEngineSymbolicInterpreterStateNewTool)),
        (SymbEngineFunctionSummaryNewTool::definition(), Box::new(SymbEngineFunctionSummaryNewTool)),
        (SymbEngineExecutorConfigDefaultsTool::definition(), Box::new(SymbEngineExecutorConfigDefaultsTool)),
        (SymbEngineStateManagerNewTool::definition(), Box::new(SymbEngineStateManagerNewTool)),
        (SymbSymTypeBitVecWidthTool::definition(), Box::new(SymbSymTypeBitVecWidthTool)),
        (SymbPathConstraintNewIsTriviallyFalseTool::definition(), Box::new(SymbPathConstraintNewIsTriviallyFalseTool)),
        (SymbSymExprBitWidthConstTool::definition(), Box::new(SymbSymExprBitWidthConstTool)),
        (SymbSymExprAsConstBoolTool::definition(), Box::new(SymbSymExprAsConstBoolTool)),
        (SymbSimplifierConstAddTool::definition(), Box::new(SymbSimplifierConstAddTool)),
        (SymbPathConstraintTriviallyFalseTool::definition(), Box::new(SymbPathConstraintTriviallyFalseTool)),
        (SymbEngineExecutorConfigDefaultsV3Tool::definition(), Box::new(SymbEngineExecutorConfigDefaultsV3Tool)),
        (SymbEngineSolverTypeListTool::definition(), Box::new(SymbEngineSolverTypeListTool)),
        (SymbEngineExplorationStrategyListTool::definition(), Box::new(SymbEngineExplorationStrategyListTool)),
        (SymbEngineStateManagerEmptyStatsTool::definition(), Box::new(SymbEngineStateManagerEmptyStatsTool)),
        (SymbEngineFunctionSummaryNewV3Tool::definition(), Box::new(SymbEngineFunctionSummaryNewV3Tool)),
        (SymbEngineVulnDetectorEmptyTool::definition(), Box::new(SymbEngineVulnDetectorEmptyTool)),
        (SymbEngineSymbolicAddressConcreteTool::definition(), Box::new(SymbEngineSymbolicAddressConcreteTool)),
        (SymbEngineSymbolicExecutorStatsTool::definition(), Box::new(SymbEngineSymbolicExecutorStatsTool)),
        (SymbEngineExecutorConfigCustomTool::definition(), Box::new(SymbEngineExecutorConfigCustomTool)),
        (SymbEngineHaltReasonListTool::definition(), Box::new(SymbEngineHaltReasonListTool)),
        (SymbEngineVulnDetectorRegisterFreeTool::definition(), Box::new(SymbEngineVulnDetectorRegisterFreeTool)),
        (SymbEngineExprDepthChainAddTool::definition(), Box::new(SymbEngineExprDepthChainAddTool)),
        (SymbEngineExprNodeCountChainAddTool::definition(), Box::new(SymbEngineExprNodeCountChainAddTool)),
        (SymbEngineSimplifyConstraintsLenTool::definition(), Box::new(SymbEngineSimplifyConstraintsLenTool)),
        (SymbEngineHasContradictionConstTool::definition(), Box::new(SymbEngineHasContradictionConstTool)),
        (SymbEngineCheckSatisfiableConstTool::definition(), Box::new(SymbEngineCheckSatisfiableConstTool)),
        (SymbEngineFormatPathConditionsConstTool::definition(), Box::new(SymbEngineFormatPathConditionsConstTool)),
        (SymbEngineLoopBoundAnalysisNewTool::definition(), Box::new(SymbEngineLoopBoundAnalysisNewTool)),
        (SymbEngineLoopBoundAnalysisAddEdgeTool::definition(), Box::new(SymbEngineLoopBoundAnalysisAddEdgeTool)),
        (SymbEngineStateMergerHashConstraintsTool::definition(), Box::new(SymbEngineStateMergerHashConstraintsTool)),
    ]
}

pub struct SymbSymSubConstToolV2;
impl SymbSymSubConstToolV2 {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_sym_sub_const_v2".to_string(),
            description: "Constant-fold `lhs - rhs` via rustre_symb::sym_sub.".to_string(),
            input_schema: json!({"type":"object","required":["lhs","rhs","width"],"properties":{"lhs":{"type":"integer"},"rhs":{"type":"integer"},"width":{"type":"integer","minimum":1,"maximum":64}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbSymSubConstToolV2 {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let lhs = args.get("lhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lhs'".into()))?;
        let rhs = args.get("rhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rhs'".into()))?;
        let width = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let e = rustre_symb::sym_sub(rustre_symb::SymExpr::bv(lhs,width), rustre_symb::SymExpr::bv(rhs,width));
        Ok(ToolResult::text(json!({"lhs":lhs,"rhs":rhs,"width":width,"result":e.as_const_u64(),"source":"rustre_symb::sym_sub"}).to_string()))
    }
}

pub struct SymbSymMulConstToolV2;
impl SymbSymMulConstToolV2 {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_sym_mul_const_v2".to_string(),
            description: "Constant-fold `lhs * rhs` via rustre_symb::sym_mul.".to_string(),
            input_schema: json!({"type":"object","required":["lhs","rhs","width"],"properties":{"lhs":{"type":"integer"},"rhs":{"type":"integer"},"width":{"type":"integer","minimum":1,"maximum":64}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbSymMulConstToolV2 {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let lhs = args.get("lhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lhs'".into()))?;
        let rhs = args.get("rhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rhs'".into()))?;
        let width = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let e = rustre_symb::sym_mul(rustre_symb::SymExpr::bv(lhs,width), rustre_symb::SymExpr::bv(rhs,width));
        Ok(ToolResult::text(json!({"lhs":lhs,"rhs":rhs,"width":width,"result":e.as_const_u64(),"source":"rustre_symb::sym_mul"}).to_string()))
    }
}

pub struct SymbSymAndConstToolV2;
impl SymbSymAndConstToolV2 {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_sym_and_const_v2".to_string(),
            description: "Constant-fold `lhs & rhs` via rustre_symb::sym_and.".to_string(),
            input_schema: json!({"type":"object","required":["lhs","rhs","width"],"properties":{"lhs":{"type":"integer"},"rhs":{"type":"integer"},"width":{"type":"integer","minimum":1,"maximum":64}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbSymAndConstToolV2 {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let lhs = args.get("lhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lhs'".into()))?;
        let rhs = args.get("rhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rhs'".into()))?;
        let width = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let e = rustre_symb::sym_and(rustre_symb::SymExpr::bv(lhs,width), rustre_symb::SymExpr::bv(rhs,width));
        Ok(ToolResult::text(json!({"lhs":lhs,"rhs":rhs,"width":width,"result":e.as_const_u64(),"source":"rustre_symb::sym_and"}).to_string()))
    }
}

pub struct SymbSymOrConstToolV2;
impl SymbSymOrConstToolV2 {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_sym_or_const_v2".to_string(),
            description: "Constant-fold `lhs | rhs` via rustre_symb::sym_or.".to_string(),
            input_schema: json!({"type":"object","required":["lhs","rhs","width"],"properties":{"lhs":{"type":"integer"},"rhs":{"type":"integer"},"width":{"type":"integer","minimum":1,"maximum":64}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbSymOrConstToolV2 {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let lhs = args.get("lhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lhs'".into()))?;
        let rhs = args.get("rhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rhs'".into()))?;
        let width = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let e = rustre_symb::sym_or(rustre_symb::SymExpr::bv(lhs,width), rustre_symb::SymExpr::bv(rhs,width));
        Ok(ToolResult::text(json!({"lhs":lhs,"rhs":rhs,"width":width,"result":e.as_const_u64(),"source":"rustre_symb::sym_or"}).to_string()))
    }
}

pub struct SymbSymNotConstToolV2;
impl SymbSymNotConstToolV2 {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_sym_not_const_v2".to_string(),
            description: "Constant-fold `~x` via rustre_symb::sym_not.".to_string(),
            input_schema: json!({"type":"object","required":["val","width"],"properties":{"val":{"type":"integer"},"width":{"type":"integer","minimum":1,"maximum":64}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbSymNotConstToolV2 {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let val = args.get("val").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'val'".into()))?;
        let width = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let e = rustre_symb::sym_not(rustre_symb::SymExpr::bv(val,width));
        Ok(ToolResult::text(json!({"val":val,"width":width,"result":e.as_const_u64(),"source":"rustre_symb::sym_not"}).to_string()))
    }
}

pub struct SymbSymTypeWidthToolV2;
impl SymbSymTypeWidthToolV2 {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_sym_type_width_v2".to_string(),
            description: "Report SymType::width for bitvec/pointer/bool.".to_string(),
            input_schema: json!({"type":"object","required":["kind"],"properties":{"kind":{"type":"string","enum":["bitvec","pointer","bool"]},"width":{"type":"integer","minimum":1,"maximum":64}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbSymTypeWidthToolV2 {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let kind = args.get("kind").and_then(Value::as_str).unwrap_or("bitvec");
        let ty = match kind {
            "pointer" => rustre_symb::SymType::Pointer,
            "bool" => rustre_symb::SymType::Bool,
            _ => {
                let w = args.get("width").and_then(Value::as_u64).unwrap_or(64) as u32;
                rustre_symb::SymType::BitVec(w)
            }
        };
        Ok(ToolResult::text(json!({"kind":kind,"width":ty.width(),"source":"rustre_symb::SymType::width"}).to_string()))
    }
}
