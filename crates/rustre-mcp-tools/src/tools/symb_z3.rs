//! MCP wrappers for the rustre-symb_z3 crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct SymbZ3ParseCheckSatTool;

pub struct SymbZ3ParseModelTool;

pub struct SymbZ3EmitConstTool;

pub struct SymbZ3ConstBitWidthTool;

pub struct SymbZ3BuilderLogicTool;

pub struct SymbZ3ParseCheckSatWireTool;

pub struct SymbZ3SolverToSmtlib2ConstTool;

pub struct SymbZ3ProveEquivalentConstTool;

pub struct SymbZ3EmitSmtlib2ConstTool;
impl SymbZ3EmitSmtlib2ConstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_emit_smtlib2_const".to_string(),
            description: "Emit SMT-LIB2 text for a bitvector constant via rustre_symb_z3::emit_smtlib2.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{"type":"integer"},"bits":{"type":"integer"}},"required":["value","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3EmitSmtlib2ConstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let s = rustre_symb_z3::emit_smtlib2(&rustre_symb_z3::SymExpr::Const(v, bits));
        Ok(ToolResult::text(json!({"smtlib2": s, "source": "rustre_symb_z3::emit_smtlib2"}).to_string()))
    }
}

pub struct SymbZ3EvalConcreteAddTool;
impl SymbZ3EvalConcreteAddTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_eval_concrete_add".to_string(),
            description: "Evaluate (a + b) concretely on bitvector constants via rustre_symb_z3::eval_concrete.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","b","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3EvalConcreteAddTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let e = rustre_symb_z3::SymExpr::add(rustre_symb_z3::SymExpr::Const(a, bits), rustre_symb_z3::SymExpr::Const(b, bits));
        let env: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
        let r = rustre_symb_z3::eval_concrete(&e, &env);
        Ok(ToolResult::text(json!({"result": r, "source": "rustre_symb_z3::eval_concrete"}).to_string()))
    }
}

pub struct SymbZ3ExtractBitWidthTool;
impl SymbZ3ExtractBitWidthTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_extract_bit_width".to_string(),
            description: "Compute bit-width of SymExpr::Extract(lo,hi) via rustre_symb_z3::SymExpr::bit_width.".to_string(),
            input_schema: json!({"type":"object","properties":{"lo":{"type":"integer"},"hi":{"type":"integer"},"bits":{"type":"integer"}},"required":["lo","hi","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3ExtractBitWidthTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let lo = args.get("lo").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lo'".into()))? as usize;
        let hi = args.get("hi").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'hi'".into()))? as usize;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let e = rustre_symb_z3::SymExpr::extract(rustre_symb_z3::SymExpr::Const(0, bits), lo, hi);
        Ok(ToolResult::text(json!({"bit_width": e.bit_width(), "source": "rustre_symb_z3::SymExpr::bit_width"}).to_string()))
    }
}

pub struct SymbZ3BuilderNewLogicTool;
impl SymbZ3BuilderNewLogicTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_builder_new_logic".to_string(),
            description: "Create SmtLib2Builder with logic and return the header script via rustre_symb_z3::SmtLib2Builder::new.".to_string(),
            input_schema: json!({"type":"object","properties":{"logic":{"type":"string"}},"required":["logic"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3BuilderNewLogicTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let logic = args.get("logic").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'logic'".into()))?;
        let b = rustre_symb_z3::SmtLib2Builder::new(logic);
        Ok(ToolResult::text(json!({"logic": b.logic(), "script": b.as_str(), "source": "rustre_symb_z3::SmtLib2Builder::new"}).to_string()))
    }
}

pub struct SymbZ3CollectSymbolsVarTool;
impl SymbZ3CollectSymbolsVarTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_collect_symbols_var".to_string(),
            description: "Collect symbol IDs of a single Symbol(id,bits,name) via rustre_symb_z3::SymExpr::collect_symbols.".to_string(),
            input_schema: json!({"type":"object","properties":{"id":{"type":"integer"},"bits":{"type":"integer"},"name":{"type":"string"}},"required":["id","bits","name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3CollectSymbolsVarTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let id = args.get("id").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'id'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let e = rustre_symb_z3::SymExpr::var(id, bits, name);
        Ok(ToolResult::text(json!({"symbols": e.collect_symbols(), "source": "rustre_symb_z3::SymExpr::collect_symbols"}).to_string()))
    }
}

pub struct SymbZ3ParseBvLiteralModelTool;
impl SymbZ3ParseBvLiteralModelTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_parse_model_line".to_string(),
            description: "Parse a single model line via rustre_symb_z3::SmtLib2Parser::parse_model.".to_string(),
            input_schema: json!({"type":"object","properties":{"output":{"type":"string"}},"required":["output"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3ParseBvLiteralModelTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let out = args.get("output").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'output'".into()))?;
        let m = rustre_symb_z3::SmtLib2Parser::parse_model(out);
        Ok(ToolResult::text(json!({"model": m, "source": "rustre_symb_z3::SmtLib2Parser::parse_model"}).to_string()))
    }
}

pub struct SymbZ3SolverCheckSatEmptyTool;
impl SymbZ3SolverCheckSatEmptyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_solver_check_sat_empty".to_string(),
            description: "Run rustre_symb_z3::Z3Solver::check_sat on an empty constraint set.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3SolverCheckSatEmptyTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut s = rustre_symb_z3::Z3Solver::new();
        let r = s.check_sat();
        Ok(ToolResult::text(json!({"result": format!("{:?}", r), "cache_size": s.cache_size(), "source": "rustre_symb_z3::Z3Solver::check_sat"}).to_string()))
    }
}

pub struct SymbZ3ProveReflexiveTool;
impl SymbZ3ProveReflexiveTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_prove_reflexive".to_string(),
            description: "Prove SymExpr::Const(v,bits) equivalent to itself via rustre_symb_z3::Z3Solver::prove_equivalent.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{"type":"integer"},"bits":{"type":"integer"}},"required":["value","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3ProveReflexiveTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let e = rustre_symb_z3::SymExpr::Const(v, bits);
        let mut s = rustre_symb_z3::Z3Solver::new();
        let eq = s.prove_equivalent(&e, &e);
        Ok(ToolResult::text(json!({"equivalent": eq, "source": "rustre_symb_z3::Z3Solver::prove_equivalent"}).to_string()))
    }
}

pub struct SymbZ3ParseCheckSatRawTool;
impl SymbZ3ParseCheckSatRawTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_parse_check_sat_raw".to_string(),
            description: "Parse raw solver stdout via rustre_symb_z3::SmtLib2Parser::parse_check_sat.".to_string(),
            input_schema: json!({"type":"object","properties":{"output":{"type":"string"}},"required":["output"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3ParseCheckSatRawTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let out = args.get("output").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'output'".into()))?;
        let r = rustre_symb_z3::SmtLib2Parser::parse_check_sat(out);
        Ok(ToolResult::text(json!({"result": format!("{:?}", r), "source": "rustre_symb_z3::SmtLib2Parser::parse_check_sat"}).to_string()))
    }
}

pub struct SymbZ3Smtlib2AddTool;
impl SymbZ3Smtlib2AddTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_smtlib2_add".to_string(),
            description: "Emit SMT-LIB2 (bvadd a b) via rustre_symb_z3::emit_smtlib2.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","b","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3Smtlib2AddTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let e = rustre_symb_z3::SymExpr::add(rustre_symb_z3::SymExpr::Const(a, bits), rustre_symb_z3::SymExpr::Const(b, bits));
        Ok(ToolResult::text(json!({"smtlib2": rustre_symb_z3::emit_smtlib2(&e), "bit_width": e.bit_width(), "source":"rustre_symb_z3::emit_smtlib2"}).to_string()))
    }
}

pub struct SymbZ3Smtlib2XorTool;
impl SymbZ3Smtlib2XorTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_smtlib2_xor".to_string(),
            description: "Emit SMT-LIB2 (bvxor a b) via rustre_symb_z3::emit_smtlib2.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","b","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3Smtlib2XorTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let e = rustre_symb_z3::SymExpr::bv_xor(rustre_symb_z3::SymExpr::Const(a, bits), rustre_symb_z3::SymExpr::Const(b, bits));
        Ok(ToolResult::text(json!({"smtlib2": rustre_symb_z3::emit_smtlib2(&e), "source":"rustre_symb_z3::emit_smtlib2"}).to_string()))
    }
}

pub struct SymbZ3EvalMulTool;
impl SymbZ3EvalMulTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_eval_mul".to_string(),
            description: "Evaluate SymExpr::mul via rustre_symb_z3::eval_concrete.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","b","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3EvalMulTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let e = rustre_symb_z3::SymExpr::mul(rustre_symb_z3::SymExpr::Const(a, bits), rustre_symb_z3::SymExpr::Const(b, bits));
        let v = rustre_symb_z3::eval_concrete(&e, &std::collections::HashMap::new());
        Ok(ToolResult::text(json!({"value": v, "source":"rustre_symb_z3::eval_concrete"}).to_string()))
    }
}

pub struct SymbZ3EvalXorTool;
impl SymbZ3EvalXorTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_eval_xor".to_string(),
            description: "Evaluate bv_xor via rustre_symb_z3::eval_concrete.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","b","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3EvalXorTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let e = rustre_symb_z3::SymExpr::bv_xor(rustre_symb_z3::SymExpr::Const(a, bits), rustre_symb_z3::SymExpr::Const(b, bits));
        let v = rustre_symb_z3::eval_concrete(&e, &std::collections::HashMap::new());
        Ok(ToolResult::text(json!({"value": v, "source":"rustre_symb_z3::eval_concrete"}).to_string()))
    }
}

pub struct SymbZ3ZeroExtBwTool;
impl SymbZ3ZeroExtBwTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_zero_ext_bw".to_string(),
            description: "Bit-width of ZeroExt via rustre_symb_z3::SymExpr::bit_width.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{"type":"integer"},"bits":{"type":"integer"},"new_size":{"type":"integer"}},"required":["value","bits","new_size"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3ZeroExtBwTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let ns = args.get("new_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'new_size'".into()))? as usize;
        let e = rustre_symb_z3::SymExpr::zero_ext(rustre_symb_z3::SymExpr::Const(v, bits), ns);
        Ok(ToolResult::text(json!({"bit_width": e.bit_width(), "source":"rustre_symb_z3::SymExpr::bit_width"}).to_string()))
    }
}

pub struct SymbZ3ConcatBwTool;
impl SymbZ3ConcatBwTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_concat_bw".to_string(),
            description: "Bit-width of Concat via rustre_symb_z3::SymExpr::bit_width.".to_string(),
            input_schema: json!({"type":"object","properties":{"a_bits":{"type":"integer"},"b_bits":{"type":"integer"}},"required":["a_bits","b_bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3ConcatBwTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ab = args.get("a_bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_bits'".into()))? as usize;
        let bb = args.get("b_bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_bits'".into()))? as usize;
        let e = rustre_symb_z3::SymExpr::concat(vec![rustre_symb_z3::SymExpr::Const(0, ab), rustre_symb_z3::SymExpr::Const(0, bb)]);
        Ok(ToolResult::text(json!({"bit_width": e.bit_width(), "source":"rustre_symb_z3::SymExpr::bit_width"}).to_string()))
    }
}

pub struct SymbZ3ParseBvHexTool;
impl SymbZ3ParseBvHexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_parse_bv_hex".to_string(),
            description: "Parse hex BV literal via rustre_symb_z3::SmtLib2Parser::parse_model.".to_string(),
            input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3ParseBvHexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let h = args.get("hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'hex'".into()))?;
        let line = format!("(define-fun x () (_ BitVec 32) {h})\n");
        let m = rustre_symb_z3::SmtLib2Parser::parse_model(&line);
        Ok(ToolResult::text(json!({"value": m.get("x"), "source":"rustre_symb_z3::SmtLib2Parser::parse_model"}).to_string()))
    }
}

pub struct SymbZ3SolverHitRateTool;
impl SymbZ3SolverHitRateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_solver_hit_rate".to_string(),
            description: "Return initial cache_hit_rate of rustre_symb_z3::Z3Solver.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3SolverHitRateTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_symb_z3::Z3Solver::new();
        Ok(ToolResult::text(json!({"hit_rate": s.cache_hit_rate(), "cache_size": s.cache_size(), "source":"rustre_symb_z3::Z3Solver::cache_hit_rate"}).to_string()))
    }
}

pub struct SymbZ3SymbolBitWidthTool;
impl SymbZ3SymbolBitWidthTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_symbol_bit_width".to_string(),
            description: "Bit-width of SymExpr::var via rustre_symb_z3::SymExpr::bit_width.".to_string(),
            input_schema: json!({"type":"object","properties":{"id":{"type":"integer"},"bits":{"type":"integer"},"name":{"type":"string"}},"required":["id","bits","name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3SymbolBitWidthTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let id = args.get("id").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'id'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let e = rustre_symb_z3::SymExpr::var(id, bits, name);
        Ok(ToolResult::text(json!({"bit_width": e.bit_width(), "symbols": e.collect_symbols(), "source":"rustre_symb_z3::SymExpr::bit_width"}).to_string()))
    }
}

pub struct SymbZ3SolverAssertResetTool;
impl SymbZ3SolverAssertResetTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_solver_assert_reset".to_string(),
            description: "Assert Const then reset via rustre_symb_z3::Z3Solver::reset.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{"type":"integer"},"bits":{"type":"integer"}},"required":["value","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3SolverAssertResetTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let mut s = rustre_symb_z3::Z3Solver::new();
        s.assert(rustre_symb_z3::SymExpr::Const(v, bits));
        let r1 = format!("{:?}", s.check_sat());
        s.reset();
        let r2 = format!("{:?}", s.check_sat());
        Ok(ToolResult::text(json!({"before_reset": r1, "after_reset": r2, "source":"rustre_symb_z3::Z3Solver::reset"}).to_string()))
    }
}

pub struct SymbZ3EvalSubConstTool;
impl SymbZ3EvalSubConstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_eval_sub_const".to_string(),
            description: "Evaluate SymExpr::sub via rustre_symb_z3::eval_concrete.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","b","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3EvalSubConstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let e = rustre_symb_z3::SymExpr::sub(rustre_symb_z3::SymExpr::Const(a, bits), rustre_symb_z3::SymExpr::Const(b, bits));
        let v = rustre_symb_z3::eval_concrete(&e, &std::collections::HashMap::new());
        Ok(ToolResult::text(json!({"value": v, "source":"rustre_symb_z3::eval_concrete"}).to_string()))
    }
}

pub struct SymbZ3EvalAndConstTool;
impl SymbZ3EvalAndConstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_eval_and_const".to_string(),
            description: "Evaluate SymExpr::bv_and via rustre_symb_z3::eval_concrete.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","b","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3EvalAndConstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let e = rustre_symb_z3::SymExpr::bv_and(rustre_symb_z3::SymExpr::Const(a, bits), rustre_symb_z3::SymExpr::Const(b, bits));
        let v = rustre_symb_z3::eval_concrete(&e, &std::collections::HashMap::new());
        Ok(ToolResult::text(json!({"value": v, "source":"rustre_symb_z3::eval_concrete"}).to_string()))
    }
}

pub struct SymbZ3EvalOrConstTool;
impl SymbZ3EvalOrConstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_eval_or_const".to_string(),
            description: "Evaluate SymExpr::bv_or via rustre_symb_z3::eval_concrete.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","b","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3EvalOrConstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let e = rustre_symb_z3::SymExpr::bv_or(rustre_symb_z3::SymExpr::Const(a, bits), rustre_symb_z3::SymExpr::Const(b, bits));
        let v = rustre_symb_z3::eval_concrete(&e, &std::collections::HashMap::new());
        Ok(ToolResult::text(json!({"value": v, "source":"rustre_symb_z3::eval_concrete"}).to_string()))
    }
}

pub struct SymbZ3EvalShlConstTool;
impl SymbZ3EvalShlConstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_eval_shl_const".to_string(),
            description: "Evaluate SymExpr::shl via rustre_symb_z3::eval_concrete.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","b","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3EvalShlConstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let e = rustre_symb_z3::SymExpr::shl(rustre_symb_z3::SymExpr::Const(a, bits), rustre_symb_z3::SymExpr::Const(b, bits));
        let v = rustre_symb_z3::eval_concrete(&e, &std::collections::HashMap::new());
        Ok(ToolResult::text(json!({"value": v, "source":"rustre_symb_z3::eval_concrete"}).to_string()))
    }
}

pub struct SymbZ3EvalLshrConstTool;
impl SymbZ3EvalLshrConstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_eval_lshr_const".to_string(),
            description: "Evaluate SymExpr::lshr via rustre_symb_z3::eval_concrete.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","b","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3EvalLshrConstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let e = rustre_symb_z3::SymExpr::lshr(rustre_symb_z3::SymExpr::Const(a, bits), rustre_symb_z3::SymExpr::Const(b, bits));
        let v = rustre_symb_z3::eval_concrete(&e, &std::collections::HashMap::new());
        Ok(ToolResult::text(json!({"value": v, "source":"rustre_symb_z3::eval_concrete"}).to_string()))
    }
}

pub struct SymbZ3EvalUltConstTool;
impl SymbZ3EvalUltConstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_eval_ult_const".to_string(),
            description: "Evaluate SymExpr::ult via rustre_symb_z3::eval_concrete.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","b","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3EvalUltConstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let e = rustre_symb_z3::SymExpr::ult(rustre_symb_z3::SymExpr::Const(a, bits), rustre_symb_z3::SymExpr::Const(b, bits));
        let v = rustre_symb_z3::eval_concrete(&e, &std::collections::HashMap::new());
        Ok(ToolResult::text(json!({"value": v, "source":"rustre_symb_z3::eval_concrete"}).to_string()))
    }
}

pub struct SymbZ3EvalSignExtNegTool;
impl SymbZ3EvalSignExtNegTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_eval_sign_ext_neg".to_string(),
            description: "Evaluate SymExpr::sign_ext of a negative value via rustre_symb_z3::eval_concrete.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{"type":"integer"},"bits":{"type":"integer"},"new_size":{"type":"integer"}},"required":["value","bits","new_size"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3EvalSignExtNegTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let ns = args.get("new_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'new_size'".into()))? as usize;
        let e = rustre_symb_z3::SymExpr::sign_ext(rustre_symb_z3::SymExpr::Const(v, bits), ns);
        let out = rustre_symb_z3::eval_concrete(&e, &std::collections::HashMap::new());
        Ok(ToolResult::text(json!({"value": out, "bit_width": e.bit_width(), "source":"rustre_symb_z3::eval_concrete"}).to_string()))
    }
}

pub struct SymbZ3EmitIteConstTool;
impl SymbZ3EmitIteConstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_emit_ite_const".to_string(),
            description: "Emit SMT-LIB2 for SymExpr::ite via rustre_symb_z3::emit_smtlib2.".to_string(),
            input_schema: json!({"type":"object","properties":{"cond":{"type":"integer"},"then":{"type":"integer"},"else_":{"type":"integer"},"bits":{"type":"integer"}},"required":["cond","then","else_","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3EmitIteConstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let c = args.get("cond").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'cond'".into()))?;
        let t = args.get("then").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'then'".into()))?;
        let e_ = args.get("else_").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'else_'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let expr = rustre_symb_z3::SymExpr::ite(
            rustre_symb_z3::SymExpr::Const(c, 1),
            rustre_symb_z3::SymExpr::Const(t, bits),
            rustre_symb_z3::SymExpr::Const(e_, bits),
        );
        Ok(ToolResult::text(json!({"smtlib2": rustre_symb_z3::emit_smtlib2(&expr), "source":"rustre_symb_z3::emit_smtlib2"}).to_string()))
    }
}

pub struct SymbZ3SolverWithLogicSmtTool;
impl SymbZ3SolverWithLogicSmtTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_solver_with_logic_smt".to_string(),
            description: "Construct Z3Solver::with_logic, assert Const, dump SMT via rustre_symb_z3::Z3Solver::to_smtlib2.".to_string(),
            input_schema: json!({"type":"object","properties":{"logic":{"type":"string"},"value":{"type":"integer"},"bits":{"type":"integer"}},"required":["logic","value","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3SolverWithLogicSmtTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let logic = args.get("logic").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'logic'".into()))?;
        let v = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let mut s = rustre_symb_z3::Z3Solver::with_logic(logic);
        s.assert(rustre_symb_z3::SymExpr::Const(v, bits));
        let smt = s.to_smtlib2(&[]);
        Ok(ToolResult::text(json!({"smt_len": smt.len(), "cache_size": s.cache_size(), "source":"rustre_symb_z3::Z3Solver::to_smtlib2"}).to_string()))
    }
}

pub struct SymbZ3BuilderPushPopTimeoutTool;
impl SymbZ3BuilderPushPopTimeoutTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_builder_push_pop_timeout".to_string(),
            description: "Exercise SmtLib2Builder::set_timeout/push/pop/get_model via rustre_symb_z3.".to_string(),
            input_schema: json!({"type":"object","properties":{"logic":{"type":"string"},"timeout_ms":{"type":"integer"}},"required":["logic","timeout_ms"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3BuilderPushPopTimeoutTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let logic = args.get("logic").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'logic'".into()))?;
        let ms = args.get("timeout_ms").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'timeout_ms'".into()))?;
        let mut b = rustre_symb_z3::SmtLib2Builder::new(logic);
        b.set_timeout(ms);
        b.push();
        b.check_sat();
        b.get_model();
        b.pop();
        let s = b.into_string();
        Ok(ToolResult::text(json!({"logic": logic, "len": s.len(), "has_timeout": s.contains(":timeout"), "has_push": s.contains("(push 1)"), "has_pop": s.contains("(pop 1)"), "has_model": s.contains("get-model"), "source":"rustre_symb_z3::SmtLib2Builder"}).to_string()))
    }
}

pub struct SymbZ3FindInputSimpleTool;
impl SymbZ3FindInputSimpleTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_find_input_simple".to_string(),
            description: "Call rustre_symb_z3::Z3Solver::find_input for a symbol equal to a target value.".to_string(),
            input_schema: json!({"type":"object","properties":{"target":{"type":"integer"},"bits":{"type":"integer"}},"required":["target","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3FindInputSimpleTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let target = args.get("target").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'target'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let mut s = rustre_symb_z3::Z3Solver::new();
        let x = rustre_symb_z3::SymExpr::var(1, bits, "x");
        let model = s.find_input(&[], &x, target);
        Ok(ToolResult::text(json!({"has_model": model.is_some(), "model_size": model.as_ref().map(|m| m.len()), "source":"rustre_symb_z3::Z3Solver::find_input"}).to_string()))
    }
}

pub struct SymbZ3EmitBvAndTool;
impl SymbZ3EmitBvAndTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "symb_z3_emit_bv_and".to_string(), description: "Emit SMT-LIB2 for (bvand a b) via rustre_symb_z3::emit_smtlib2.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","b","bits"]}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for SymbZ3EmitBvAndTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let a = args.get("a").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'a'".into()))?; let b = args.get("b").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'b'".into()))?; let bits = args.get("bits").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'bits'".into()))? as usize; let e = rustre_symb_z3::SymExpr::bv_and(rustre_symb_z3::SymExpr::Const(a, bits), rustre_symb_z3::SymExpr::Const(b, bits)); let s = rustre_symb_z3::emit_smtlib2(&e); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"smtlib2":s,"source":"rustre_symb_z3::emit_smtlib2"}).to_string())) } }

pub struct SymbZ3EvalSdivConstWireTool;
impl SymbZ3EvalSdivConstWireTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "symb_z3_eval_sdiv_const_wire".to_string(), description: "Evaluate (a sdiv b) concretely via rustre_symb_z3::eval_concrete.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","b","bits"]}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for SymbZ3EvalSdivConstWireTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let a = args.get("a").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'a'".into()))?; let b = args.get("b").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'b'".into()))?; let bits = args.get("bits").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'bits'".into()))? as usize; let e = rustre_symb_z3::SymExpr::sdiv(rustre_symb_z3::SymExpr::Const(a, bits), rustre_symb_z3::SymExpr::Const(b, bits)); let env: std::collections::HashMap<u64,u64> = std::collections::HashMap::new(); let r = rustre_symb_z3::eval_concrete(&e, &env); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"result":r,"source":"rustre_symb_z3::eval_concrete"}).to_string())) } }

pub struct SymbZ3EvalSremConstWireTool;
impl SymbZ3EvalSremConstWireTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "symb_z3_eval_srem_const_wire".to_string(), description: "Evaluate (a srem b) concretely via rustre_symb_z3::eval_concrete.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","b","bits"]}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for SymbZ3EvalSremConstWireTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let a = args.get("a").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'a'".into()))?; let b = args.get("b").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'b'".into()))?; let bits = args.get("bits").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'bits'".into()))? as usize; let e = rustre_symb_z3::SymExpr::srem(rustre_symb_z3::SymExpr::Const(a, bits), rustre_symb_z3::SymExpr::Const(b, bits)); let env: std::collections::HashMap<u64,u64> = std::collections::HashMap::new(); let r = rustre_symb_z3::eval_concrete(&e, &env); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"result":r,"source":"rustre_symb_z3::eval_concrete"}).to_string())) } }

pub struct SymbZ3EvalNegConstTool;
impl SymbZ3EvalNegConstTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "symb_z3_eval_neg_const".to_string(), description: "Evaluate bitvector negation of a constant via rustre_symb_z3::eval_concrete.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"a":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","bits"]}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for SymbZ3EvalNegConstTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let a = args.get("a").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'a'".into()))?; let bits = args.get("bits").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'bits'".into()))? as usize; let e = rustre_symb_z3::SymExpr::Neg(Box::new(rustre_symb_z3::SymExpr::Const(a, bits))); let env: std::collections::HashMap<u64,u64> = std::collections::HashMap::new(); let r = rustre_symb_z3::eval_concrete(&e, &env); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"result":r,"source":"rustre_symb_z3::eval_concrete"}).to_string())) } }

pub struct SymbZ3EvalEqConstTool;
impl SymbZ3EvalEqConstTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "symb_z3_eval_eq_const".to_string(), description: "Evaluate (a == b) on constants via rustre_symb_z3::eval_concrete.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","b","bits"]}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for SymbZ3EvalEqConstTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let a = args.get("a").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'a'".into()))?; let b = args.get("b").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'b'".into()))?; let bits = args.get("bits").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'bits'".into()))? as usize; let e = rustre_symb_z3::SymExpr::eq(rustre_symb_z3::SymExpr::Const(a, bits), rustre_symb_z3::SymExpr::Const(b, bits)); let env: std::collections::HashMap<u64,u64> = std::collections::HashMap::new(); let r = rustre_symb_z3::eval_concrete(&e, &env); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"result":r,"source":"rustre_symb_z3::eval_concrete"}).to_string())) } }

pub struct SymbZ3EvalSltConstV2Tool;
impl SymbZ3EvalSltConstV2Tool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "symb_z3_eval_slt_const_v2".to_string(), description: "Evaluate signed less-than (a slt b) via rustre_symb_z3::eval_concrete.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","b","bits"]}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for SymbZ3EvalSltConstV2Tool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let a = args.get("a").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'a'".into()))?; let b = args.get("b").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'b'".into()))?; let bits = args.get("bits").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'bits'".into()))? as usize; let e = rustre_symb_z3::SymExpr::slt(rustre_symb_z3::SymExpr::Const(a, bits), rustre_symb_z3::SymExpr::Const(b, bits)); let env: std::collections::HashMap<u64,u64> = std::collections::HashMap::new(); let r = rustre_symb_z3::eval_concrete(&e, &env); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"result":r,"source":"rustre_symb_z3::eval_concrete"}).to_string())) } }

pub struct SymbZ3EvalZeroExtConstTool;
impl SymbZ3EvalZeroExtConstTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "symb_z3_eval_zero_ext_const".to_string(), description: "Evaluate zero_extend(a, new_size) via rustre_symb_z3::eval_concrete.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"a":{"type":"integer"},"bits":{"type":"integer"},"new_size":{"type":"integer"}},"required":["a","bits","new_size"]}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for SymbZ3EvalZeroExtConstTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let a = args.get("a").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'a'".into()))?; let bits = args.get("bits").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'bits'".into()))? as usize; let ns = args.get("new_size").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'new_size'".into()))? as usize; if ns < bits { return Err(rustre_mcp_server::McpError::InvalidParams("new_size must be >= bits".into())); } let e = rustre_symb_z3::SymExpr::zero_ext(rustre_symb_z3::SymExpr::Const(a, bits), ns); let env: std::collections::HashMap<u64,u64> = std::collections::HashMap::new(); let r = rustre_symb_z3::eval_concrete(&e, &env); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"result":r,"new_size":ns,"source":"rustre_symb_z3::eval_concrete"}).to_string())) } }

pub struct SymbZ3EvalExtractConstTool;
impl SymbZ3EvalExtractConstTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "symb_z3_eval_extract_const".to_string(), description: "Evaluate extract(inner, lo, hi) on a constant via rustre_symb_z3::eval_concrete.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"a":{"type":"integer"},"bits":{"type":"integer"},"lo":{"type":"integer"},"hi":{"type":"integer"}},"required":["a","bits","lo","hi"]}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for SymbZ3EvalExtractConstTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let a = args.get("a").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'a'".into()))?; let bits = args.get("bits").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'bits'".into()))? as usize; let lo = args.get("lo").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'lo'".into()))? as usize; let hi = args.get("hi").and_then(serde_json::Value::as_u64).ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing 'hi'".into()))? as usize; if hi < lo || hi >= bits { return Err(rustre_mcp_server::McpError::InvalidParams("invalid lo/hi vs bits".into())); } let e = rustre_symb_z3::SymExpr::extract(rustre_symb_z3::SymExpr::Const(a, bits), lo, hi); let env: std::collections::HashMap<u64,u64> = std::collections::HashMap::new(); let r = rustre_symb_z3::eval_concrete(&e, &env); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"result":r,"out_width":hi-lo+1,"source":"rustre_symb_z3::eval_concrete"}).to_string())) } }

pub struct SymbZ3SolverIsSatEmptyTool;
impl SymbZ3SolverIsSatEmptyTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "symb_z3_solver_is_sat_empty".to_string(), description: "Confirm Z3Solver::is_sat_concrete(&[]) returns true (empty constraints are trivially SAT).".to_string(), input_schema: serde_json::json!({"type":"object","properties":{}}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for SymbZ3SolverIsSatEmptyTool { async fn call(&self, _args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let solver = rustre_symb_z3::Z3Solver::new(); let r = solver.is_sat_concrete(&[]); Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"is_sat":r,"source":"rustre_symb_z3::Z3Solver::is_sat_concrete"}).to_string())) } }

pub struct SymbZ3ParserParseUnsatTool;
impl SymbZ3ParserParseUnsatTool { #[must_use] pub fn definition() -> rustre_mcp_server::ToolDefinition { rustre_mcp_server::ToolDefinition { name: "symb_z3_parser_parse_unsat".to_string(), description: "Confirm SmtLib2Parser::parse_check_sat classifies 'unsat' correctly.".to_string(), input_schema: serde_json::json!({"type":"object","properties":{"output":{"type":"string"}}}), parameters: serde_json::Value::Null } } }
#[async_trait::async_trait] impl rustre_mcp_server::ToolHandler for SymbZ3ParserParseUnsatTool { async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> { let out = args.get("output").and_then(serde_json::Value::as_str).unwrap_or("unsat\n"); let r = rustre_symb_z3::SmtLib2Parser::parse_check_sat(out); let kind = match &r { rustre_symb_z3::SolverResult::Sat => "sat", rustre_symb_z3::SolverResult::Unsat => "unsat", rustre_symb_z3::SolverResult::Unknown(_) => "unknown" }; Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({"result":kind,"source":"rustre_symb_z3::SmtLib2Parser::parse_check_sat"}).to_string())) } }

pub struct SymbZ3EvalConcreteSubTool;
impl SymbZ3EvalConcreteSubTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_eval_concrete_sub".to_string(),
            description: "Evaluate Sub(Const,Const) via eval_concrete.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3EvalConcreteSubTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_u64).unwrap_or(10);
        let b = args.get("b").and_then(Value::as_u64).unwrap_or(3);
        let bits = args.get("bits").and_then(Value::as_u64).unwrap_or(32) as usize;
        let e = rustre_symb_z3::SymExpr::sub(rustre_symb_z3::SymExpr::constant(a, bits), rustre_symb_z3::SymExpr::constant(b, bits));
        let env: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
        Ok(ToolResult::text(json!({"value":rustre_symb_z3::eval_concrete(&e, &env),"source":"rustre_symb_z3::eval_concrete"}).to_string()))
    }
}

pub struct SymbZ3EvalConcreteMulConstTool;
impl SymbZ3EvalConcreteMulConstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_eval_concrete_mul_const".to_string(),
            description: "Evaluate Mul(Const,Const) via eval_concrete.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3EvalConcreteMulConstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_u64).unwrap_or(6);
        let b = args.get("b").and_then(Value::as_u64).unwrap_or(7);
        let bits = args.get("bits").and_then(Value::as_u64).unwrap_or(64) as usize;
        let e = rustre_symb_z3::SymExpr::mul(rustre_symb_z3::SymExpr::constant(a, bits), rustre_symb_z3::SymExpr::constant(b, bits));
        let env: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
        Ok(ToolResult::text(json!({"value":rustre_symb_z3::eval_concrete(&e, &env),"source":"rustre_symb_z3::eval_concrete"}).to_string()))
    }
}

pub struct SymbZ3EmitBvNotTool;
impl SymbZ3EmitBvNotTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_emit_bv_not".to_string(),
            description: "Emit SMT-LIB2 for bvnot of a constant.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{"type":"integer"},"bits":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3EmitBvNotTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let value = args.get("value").and_then(Value::as_u64).unwrap_or(0);
        let bits = args.get("bits").and_then(Value::as_u64).unwrap_or(32) as usize;
        let e = rustre_symb_z3::SymExpr::bv_not(rustre_symb_z3::SymExpr::constant(value, bits));
        Ok(ToolResult::text(json!({"smtlib2":rustre_symb_z3::emit_smtlib2(&e),"bit_width":e.bit_width(),"source":"rustre_symb_z3::emit_smtlib2"}).to_string()))
    }
}

pub struct SymbZ3EmitBvOrTool;
impl SymbZ3EmitBvOrTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_emit_bv_or".to_string(),
            description: "Emit SMT-LIB2 for bvor of two constants.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"bits":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3EmitBvOrTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_u64).unwrap_or(1);
        let b = args.get("b").and_then(Value::as_u64).unwrap_or(2);
        let bits = args.get("bits").and_then(Value::as_u64).unwrap_or(32) as usize;
        let e = rustre_symb_z3::SymExpr::bv_or(rustre_symb_z3::SymExpr::constant(a, bits), rustre_symb_z3::SymExpr::constant(b, bits));
        Ok(ToolResult::text(json!({"smtlib2":rustre_symb_z3::emit_smtlib2(&e),"source":"rustre_symb_z3::emit_smtlib2"}).to_string()))
    }
}

pub struct SymbZ3ExtractWidthTool;
impl SymbZ3ExtractWidthTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_extract_width".to_string(),
            description: "Bit-width of Extract(Const, lo, hi).".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{"type":"integer"},"bits":{"type":"integer"},"lo":{"type":"integer"},"hi":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3ExtractWidthTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let value = args.get("value").and_then(Value::as_u64).unwrap_or(0);
        let bits = args.get("bits").and_then(Value::as_u64).unwrap_or(32) as usize;
        let lo = args.get("lo").and_then(Value::as_u64).unwrap_or(0) as usize;
        let hi = args.get("hi").and_then(Value::as_u64).unwrap_or(7) as usize;
        let e = rustre_symb_z3::SymExpr::extract(rustre_symb_z3::SymExpr::constant(value, bits), lo, hi);
        Ok(ToolResult::text(json!({"bit_width":e.bit_width(),"smtlib2":rustre_symb_z3::emit_smtlib2(&e),"source":"rustre_symb_z3::SymExpr::extract"}).to_string()))
    }
}

pub struct SymbZ3CollectSymbolsCountTool;
impl SymbZ3CollectSymbolsCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_collect_symbols_count".to_string(),
            description: "Count symbols in Add(var(id1),var(id2)).".to_string(),
            input_schema: json!({"type":"object","properties":{"id1":{"type":"integer"},"id2":{"type":"integer"},"bits":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3CollectSymbolsCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let id1 = args.get("id1").and_then(Value::as_u64).unwrap_or(1);
        let id2 = args.get("id2").and_then(Value::as_u64).unwrap_or(2);
        let bits = args.get("bits").and_then(Value::as_u64).unwrap_or(32) as usize;
        let a = rustre_symb_z3::SymExpr::var(id1, bits, format!("v{id1}"));
        let b = rustre_symb_z3::SymExpr::var(id2, bits, format!("v{id2}"));
        let e = rustre_symb_z3::SymExpr::add(a, b);
        let syms = e.collect_symbols();
        Ok(ToolResult::text(json!({"count":syms.len(),"ids":syms,"source":"rustre_symb_z3::SymExpr::collect_symbols"}).to_string()))
    }
}

pub struct SymbZ3SolverCheckSatConstTool;
impl SymbZ3SolverCheckSatConstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_solver_check_sat_const".to_string(),
            description: "Z3Solver::check_sat on Const(1,1) assertion.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3SolverCheckSatConstTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut s = rustre_symb_z3::Z3Solver::new();
        s.assert(rustre_symb_z3::SymExpr::constant(1, 1));
        let res = s.check_sat();
        let label = match res { rustre_symb_z3::SolverResult::Sat => "sat", rustre_symb_z3::SolverResult::Unsat => "unsat", rustre_symb_z3::SolverResult::Unknown(_) => "unknown" };
        Ok(ToolResult::text(json!({"result":label,"calls":s.calls_made,"source":"rustre_symb_z3::Z3Solver::check_sat"}).to_string()))
    }
}

pub struct SymbZ3SolverPushPopCycleTool;
impl SymbZ3SolverPushPopCycleTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_solver_push_pop_cycle".to_string(),
            description: "Exercise Z3Solver push/pop/reset/clear_cache.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3SolverPushPopCycleTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut s = rustre_symb_z3::Z3Solver::with_logic("QF_BV");
        s.assert(rustre_symb_z3::SymExpr::constant(1, 1));
        s.push();
        s.assert(rustre_symb_z3::SymExpr::constant(1, 1));
        s.pop();
        let before = s.cache_size();
        s.reset();
        s.clear_cache();
        Ok(ToolResult::text(json!({"cache_before":before,"cache_after":s.cache_size(),"hit_rate":s.cache_hit_rate(),"source":"rustre_symb_z3::Z3Solver"}).to_string()))
    }
}

pub struct SymbZ3ProveEquivReflexTool;
impl SymbZ3ProveEquivReflexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_prove_equiv_reflex".to_string(),
            description: "Prove Const(v,bits) == Const(v,bits).".to_string(),
            input_schema: json!({"type":"object","properties":{"v":{"type":"integer"},"bits":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3ProveEquivReflexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("v").and_then(Value::as_u64).unwrap_or(42);
        let bits = args.get("bits").and_then(Value::as_u64).unwrap_or(32) as usize;
        let mut s = rustre_symb_z3::Z3Solver::new();
        let a = rustre_symb_z3::SymExpr::constant(v, bits);
        let b = rustre_symb_z3::SymExpr::constant(v, bits);
        let ok = s.prove_equivalent(&a, &b);
        Ok(ToolResult::text(json!({"equivalent":ok,"source":"rustre_symb_z3::Z3Solver::prove_equivalent"}).to_string()))
    }
}

pub struct SymbZ3BuilderDeclLogicTool;
impl SymbZ3BuilderDeclLogicTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_builder_decl_logic".to_string(),
            description: "Build SmtLib2Builder(logic), declare a Symbol, return SMT text.".to_string(),
            input_schema: json!({"type":"object","properties":{"logic":{"type":"string"},"bits":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3BuilderDeclLogicTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let logic = args.get("logic").and_then(Value::as_str).unwrap_or("QF_BV");
        let bits = args.get("bits").and_then(Value::as_u64).unwrap_or(32) as usize;
        let mut b = rustre_symb_z3::SmtLib2Builder::new(logic);
        let sym = rustre_symb_z3::SymExpr::var(7, bits, "x");
        b.declare_symbols(&[sym]);
        b.check_sat();
        Ok(ToolResult::text(json!({"logic":b.logic().to_string(),"smt":b.as_str().to_string(),"source":"rustre_symb_z3::SmtLib2Builder"}).to_string()))
    }
}

pub struct SymbZ3ParseCheckSatUnknownTool;
impl SymbZ3ParseCheckSatUnknownTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_parse_check_sat_unknown".to_string(),
            description: "Parse 'unknown ...' via SmtLib2Parser::parse_check_sat.".to_string(),
            input_schema: json!({"type":"object","properties":{"text":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3ParseCheckSatUnknownTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str).unwrap_or("unknown timeout");
        let r = rustre_symb_z3::SmtLib2Parser::parse_check_sat(text);
        let (kind, msg) = match r {
            rustre_symb_z3::SolverResult::Sat => ("sat", String::new()),
            rustre_symb_z3::SolverResult::Unsat => ("unsat", String::new()),
            rustre_symb_z3::SolverResult::Unknown(s) => ("unknown", s),
        };
        Ok(ToolResult::text(json!({"kind":kind,"message":msg,"source":"rustre_symb_z3::SmtLib2Parser::parse_check_sat"}).to_string()))
    }
}

pub struct SymbZ3IsSatConcreteTrivialTool;
impl SymbZ3IsSatConcreteTrivialTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_is_sat_concrete_trivial".to_string(),
            description: "Z3Solver::is_sat_concrete on [Const(1,1)].".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3IsSatConcreteTrivialTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_symb_z3::Z3Solver::new();
        let c = rustre_symb_z3::SymExpr::constant(1, 1);
        Ok(ToolResult::text(json!({"is_sat":s.is_sat_concrete(&[c]),"source":"rustre_symb_z3::Z3Solver::is_sat_concrete"}).to_string()))
    }
}

pub struct SymbZ3EvalBvNotConstTool;
impl SymbZ3EvalBvNotConstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_eval_bv_not_const".to_string(),
            description: "Evaluate SymExpr::bv_not via rustre_symb_z3::eval_concrete.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"bits":{"type":"integer"}},"required":["a","bits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3EvalBvNotConstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let bits = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))? as usize;
        let e = rustre_symb_z3::SymExpr::bv_not(rustre_symb_z3::SymExpr::Const(a, bits));
        let v = rustre_symb_z3::eval_concrete(&e, &std::collections::HashMap::new());
        Ok(ToolResult::text(json!({"value": v, "source":"rustre_symb_z3::eval_concrete"}).to_string()))
    }
}

pub struct SymbZ3SolverCacheSizeTool;
impl SymbZ3SolverCacheSizeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_solver_cache_size".to_string(),
            description: "Report cache size on a fresh Z3Solver via rustre_symb_z3::Z3Solver::cache_size.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3SolverCacheSizeTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_symb_z3::Z3Solver::new();
        Ok(ToolResult::text(json!({"cache_size": s.cache_size(), "source":"rustre_symb_z3::Z3Solver::cache_size"}).to_string()))
    }
}

pub struct SymbZ3SolverClearCacheTool;
impl SymbZ3SolverClearCacheTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "symb_z3_solver_clear_cache".to_string(),
            description: "Clear the Z3Solver cache and report size via rustre_symb_z3::Z3Solver::clear_cache.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SymbZ3SolverClearCacheTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut s = rustre_symb_z3::Z3Solver::new();
        s.clear_cache();
        Ok(ToolResult::text(json!({"cache_size_after": s.cache_size(), "source":"rustre_symb_z3::Z3Solver::clear_cache"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (SymbZ3ParseCheckSatTool::definition(), Box::new(SymbZ3ParseCheckSatTool)),
        (SymbZ3ParseModelTool::definition(), Box::new(SymbZ3ParseModelTool)),
        (SymbZ3EmitConstTool::definition(), Box::new(SymbZ3EmitConstTool)),
        (SymbZ3ConstBitWidthTool::definition(), Box::new(SymbZ3ConstBitWidthTool)),
        (SymbZ3BuilderLogicTool::definition(), Box::new(SymbZ3BuilderLogicTool)),
        (SymbZ3ParseCheckSatWireTool::definition(), Box::new(SymbZ3ParseCheckSatWireTool)),
        (SymbZ3SolverToSmtlib2ConstTool::definition(), Box::new(SymbZ3SolverToSmtlib2ConstTool)),
        (SymbZ3ProveEquivalentConstTool::definition(), Box::new(SymbZ3ProveEquivalentConstTool)),
        (SymbZ3EmitSmtlib2ConstTool::definition(), Box::new(SymbZ3EmitSmtlib2ConstTool)),
        (SymbZ3EvalConcreteAddTool::definition(), Box::new(SymbZ3EvalConcreteAddTool)),
        (SymbZ3ExtractBitWidthTool::definition(), Box::new(SymbZ3ExtractBitWidthTool)),
        (SymbZ3BuilderNewLogicTool::definition(), Box::new(SymbZ3BuilderNewLogicTool)),
        (SymbZ3CollectSymbolsVarTool::definition(), Box::new(SymbZ3CollectSymbolsVarTool)),
        (SymbZ3ParseBvLiteralModelTool::definition(), Box::new(SymbZ3ParseBvLiteralModelTool)),
        (SymbZ3SolverCheckSatEmptyTool::definition(), Box::new(SymbZ3SolverCheckSatEmptyTool)),
        (SymbZ3ProveReflexiveTool::definition(), Box::new(SymbZ3ProveReflexiveTool)),
        (SymbZ3ParseCheckSatRawTool::definition(), Box::new(SymbZ3ParseCheckSatRawTool)),
        (SymbZ3Smtlib2AddTool::definition(), Box::new(SymbZ3Smtlib2AddTool)),
        (SymbZ3Smtlib2XorTool::definition(), Box::new(SymbZ3Smtlib2XorTool)),
        (SymbZ3EvalMulTool::definition(), Box::new(SymbZ3EvalMulTool)),
        (SymbZ3EvalXorTool::definition(), Box::new(SymbZ3EvalXorTool)),
        (SymbZ3ZeroExtBwTool::definition(), Box::new(SymbZ3ZeroExtBwTool)),
        (SymbZ3ConcatBwTool::definition(), Box::new(SymbZ3ConcatBwTool)),
        (SymbZ3ParseBvHexTool::definition(), Box::new(SymbZ3ParseBvHexTool)),
        (SymbZ3SolverHitRateTool::definition(), Box::new(SymbZ3SolverHitRateTool)),
        (SymbZ3SymbolBitWidthTool::definition(), Box::new(SymbZ3SymbolBitWidthTool)),
        (SymbZ3SolverAssertResetTool::definition(), Box::new(SymbZ3SolverAssertResetTool)),
        (SymbZ3EvalSubConstTool::definition(), Box::new(SymbZ3EvalSubConstTool)),
        (SymbZ3EvalAndConstTool::definition(), Box::new(SymbZ3EvalAndConstTool)),
        (SymbZ3EvalOrConstTool::definition(), Box::new(SymbZ3EvalOrConstTool)),
        (SymbZ3EvalShlConstTool::definition(), Box::new(SymbZ3EvalShlConstTool)),
        (SymbZ3EvalLshrConstTool::definition(), Box::new(SymbZ3EvalLshrConstTool)),
        (SymbZ3EvalUltConstTool::definition(), Box::new(SymbZ3EvalUltConstTool)),
        (SymbZ3EvalSignExtNegTool::definition(), Box::new(SymbZ3EvalSignExtNegTool)),
        (SymbZ3EmitIteConstTool::definition(), Box::new(SymbZ3EmitIteConstTool)),
        (SymbZ3SolverWithLogicSmtTool::definition(), Box::new(SymbZ3SolverWithLogicSmtTool)),
        (SymbZ3BuilderPushPopTimeoutTool::definition(), Box::new(SymbZ3BuilderPushPopTimeoutTool)),
        (SymbZ3FindInputSimpleTool::definition(), Box::new(SymbZ3FindInputSimpleTool)),
        (SymbZ3EmitBvAndTool::definition(), Box::new(SymbZ3EmitBvAndTool)),
        (SymbZ3EvalSdivConstWireTool::definition(), Box::new(SymbZ3EvalSdivConstWireTool)),
        (SymbZ3EvalSremConstWireTool::definition(), Box::new(SymbZ3EvalSremConstWireTool)),
        (SymbZ3EvalNegConstTool::definition(), Box::new(SymbZ3EvalNegConstTool)),
        (SymbZ3EvalEqConstTool::definition(), Box::new(SymbZ3EvalEqConstTool)),
        (SymbZ3EvalSltConstV2Tool::definition(), Box::new(SymbZ3EvalSltConstV2Tool)),
        (SymbZ3EvalZeroExtConstTool::definition(), Box::new(SymbZ3EvalZeroExtConstTool)),
        (SymbZ3EvalExtractConstTool::definition(), Box::new(SymbZ3EvalExtractConstTool)),
        (SymbZ3SolverIsSatEmptyTool::definition(), Box::new(SymbZ3SolverIsSatEmptyTool)),
        (SymbZ3ParserParseUnsatTool::definition(), Box::new(SymbZ3ParserParseUnsatTool)),
        (SymbZ3EvalConcreteSubTool::definition(), Box::new(SymbZ3EvalConcreteSubTool)),
        (SymbZ3EvalConcreteMulConstTool::definition(), Box::new(SymbZ3EvalConcreteMulConstTool)),
        (SymbZ3EmitBvNotTool::definition(), Box::new(SymbZ3EmitBvNotTool)),
        (SymbZ3EmitBvOrTool::definition(), Box::new(SymbZ3EmitBvOrTool)),
        (SymbZ3ExtractWidthTool::definition(), Box::new(SymbZ3ExtractWidthTool)),
        (SymbZ3CollectSymbolsCountTool::definition(), Box::new(SymbZ3CollectSymbolsCountTool)),
        (SymbZ3SolverCheckSatConstTool::definition(), Box::new(SymbZ3SolverCheckSatConstTool)),
        (SymbZ3SolverPushPopCycleTool::definition(), Box::new(SymbZ3SolverPushPopCycleTool)),
        (SymbZ3ProveEquivReflexTool::definition(), Box::new(SymbZ3ProveEquivReflexTool)),
        (SymbZ3BuilderDeclLogicTool::definition(), Box::new(SymbZ3BuilderDeclLogicTool)),
        (SymbZ3ParseCheckSatUnknownTool::definition(), Box::new(SymbZ3ParseCheckSatUnknownTool)),
        (SymbZ3IsSatConcreteTrivialTool::definition(), Box::new(SymbZ3IsSatConcreteTrivialTool)),
        (SymbZ3EvalBvNotConstTool::definition(), Box::new(SymbZ3EvalBvNotConstTool)),
        (SymbZ3SolverCacheSizeTool::definition(), Box::new(SymbZ3SolverCacheSizeTool)),
        (SymbZ3SolverClearCacheTool::definition(), Box::new(SymbZ3SolverClearCacheTool)),
    ]
}
