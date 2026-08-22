//! MCP wrappers for the rustre-rustre_symb crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{rsymb_bv, rsymb_v2_val};

pub struct RustreSymbBvConstTool;
impl RustreSymbBvConstTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_bv_const".to_string(),
            description: "Build bv const via rustre_symb::SymExpr::bv.".to_string(),
            input_schema: json!({"type":"object","required":["val","width"],"properties":{"val":{"type":"integer"},"width":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbBvConstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let val = args.get("val").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'val'".into()))?;
        let width = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let e = rustre_symb::SymExpr::bv(val, width);
        Ok(ToolResult::text(json!({"bit_width": e.bit_width(), "is_const": e.is_const(), "as_const_u64": e.as_const_u64(), "source":"rustre_symb::SymExpr::bv"}).to_string()))
    }
}

pub struct RustreSymbSimplifyAddTool;
impl RustreSymbSimplifyAddTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_simplify_add".to_string(),
            description: "Constant-fold via rustre_symb::sym_add.".to_string(),
            input_schema: json!({"type":"object","required":["lhs","rhs","width"],"properties":{"lhs":{"type":"integer"},"rhs":{"type":"integer"},"width":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbSimplifyAddTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let l = args.get("lhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lhs'".into()))?;
        let r = args.get("rhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rhs'".into()))?;
        let w = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let out = rustre_symb::sym_add(rsymb_bv(l, w), rsymb_bv(r, w));
        Ok(ToolResult::text(json!({"result": out.as_const_u64(), "source":"rustre_symb::sym_add"}).to_string()))
    }
}

pub struct RustreSymbSimplifyXorTool;
impl RustreSymbSimplifyXorTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_simplify_xor".to_string(),
            description: "Constant-fold via rustre_symb::sym_xor.".to_string(),
            input_schema: json!({"type":"object","required":["lhs","rhs","width"],"properties":{"lhs":{"type":"integer"},"rhs":{"type":"integer"},"width":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbSimplifyXorTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let l = args.get("lhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lhs'".into()))?;
        let r = args.get("rhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rhs'".into()))?;
        let w = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let out = rustre_symb::sym_xor(rsymb_bv(l, w), rsymb_bv(r, w));
        Ok(ToolResult::text(json!({"result": out.as_const_u64(), "source":"rustre_symb::sym_xor"}).to_string()))
    }
}

pub struct RustreSymbSimplifyNotTool;
impl RustreSymbSimplifyNotTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_simplify_not".to_string(),
            description: "NOT const-fold via rustre_symb::sym_not.".to_string(),
            input_schema: json!({"type":"object","required":["val","width"],"properties":{"val":{"type":"integer"},"width":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbSimplifyNotTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("val").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'val'".into()))?;
        let w = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let out = rustre_symb::sym_not(rsymb_bv(v, w));
        Ok(ToolResult::text(json!({"result": out.as_const_u64(), "source":"rustre_symb::sym_not"}).to_string()))
    }
}

pub struct RustreSymbTypeWidthTool;
impl RustreSymbTypeWidthTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_type_width".to_string(),
            description: "SymType::width for bool|bitvec|pointer.".to_string(),
            input_schema: json!({"type":"object","required":["kind"],"properties":{"kind":{"type":"string"},"width":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbTypeWidthTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let kind = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let w = args.get("width").and_then(Value::as_u64).unwrap_or(32) as u32;
        let ty = match kind {
            "bool" => rustre_symb::SymType::Bool,
            "pointer" => rustre_symb::SymType::Pointer,
            _ => rustre_symb::SymType::BitVec(w),
        };
        Ok(ToolResult::text(json!({"width": ty.width(), "source":"rustre_symb::SymType::width"}).to_string()))
    }
}

pub struct RustreSymbExprWidthTool;
impl RustreSymbExprWidthTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_expr_width".to_string(),
            description: "rustre_symb::expr_width on bv const.".to_string(),
            input_schema: json!({"type":"object","required":["val","width"],"properties":{"val":{"type":"integer"},"width":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbExprWidthTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("val").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'val'".into()))?;
        let w = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let e = rsymb_bv(v, w);
        Ok(ToolResult::text(json!({"width": rustre_symb::expr_width(&e), "source":"rustre_symb::expr_width"}).to_string()))
    }
}

pub struct RustreSymbEvalConcreteTool;
impl RustreSymbEvalConcreteTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_eval_concrete".to_string(),
            description: "Evaluate (a+b) via SymExpr::evaluate.".to_string(),
            input_schema: json!({"type":"object","required":["a","b"],"properties":{"a":{"type":"integer"},"b":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbEvalConcreteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let expr = rustre_symb::SymExpr::Add(
            Box::new(rustre_symb::SymExpr::var("a", rustre_symb::SymType::BitVec(64))),
            Box::new(rustre_symb::SymExpr::var("b", rustre_symb::SymType::BitVec(64))),
        );
        let mut env = std::collections::HashMap::new();
        env.insert("a".to_string(), a);
        env.insert("b".to_string(), b);
        Ok(ToolResult::text(json!({"result": expr.evaluate(&env), "source":"rustre_symb::SymExpr::evaluate"}).to_string()))
    }
}

pub struct RustreSymbStateForkTool;
impl RustreSymbStateForkTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_state_fork".to_string(),
            description: "SymbolicState::fork with ConstBool(true).".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbStateForkTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let st = rustre_symb::SymbolicState::new();
        let child = st.fork(rustre_symb::SymExpr::ConstBool(true));
        Ok(ToolResult::text(json!({"depth": child.depth, "pc_len": child.path_condition.len(), "source":"rustre_symb::SymbolicState::fork"}).to_string()))
    }
}

pub struct RustreSymbPathConjunctionTool;
impl RustreSymbPathConjunctionTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_path_conjunction".to_string(),
            description: "PathConstraint with N true terms + optional false.".to_string(),
            input_schema: json!({"type":"object","properties":{"terms":{"type":"integer"},"include_false":{"type":"boolean"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbPathConjunctionTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("terms").and_then(Value::as_u64).unwrap_or(1);
        let include_false = args.get("include_false").and_then(Value::as_bool).unwrap_or(false);
        let mut pc = rustre_symb::PathConstraint::new();
        for _ in 0..n { pc.add(rustre_symb::SymExpr::ConstBool(true)); }
        if include_false { pc.add(rustre_symb::SymExpr::ConstBool(false)); }
        let conj = pc.as_conjunction();
        Ok(ToolResult::text(json!({"trivially_false": pc.is_trivially_false(), "conj_is_const_bool": conj.as_const_bool(), "source":"rustre_symb::PathConstraint"}).to_string()))
    }
}

pub struct RustreSymbSymWidthInfoTool;
impl RustreSymbSymWidthInfoTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_symwidth_info".to_string(),
            description: "SymWidth bits/bytes/display.".to_string(),
            input_schema: json!({"type":"object","required":["bits"],"properties":{"bits":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbSymWidthInfoTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let b = args.get("bits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bits'".into()))?;
        let w = match b { 8 => rustre_symb::SymWidth::W8, 16 => rustre_symb::SymWidth::W16, 64 => rustre_symb::SymWidth::W64, _ => rustre_symb::SymWidth::W32 };
        Ok(ToolResult::text(json!({"bits": w.bits(), "bytes": w.bytes(), "display": w.to_string(), "source":"rustre_symb::SymWidth"}).to_string()))
    }
}

pub struct RustreSymbSpecEvalTool;
impl RustreSymbSpecEvalTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_spec_eval".to_string(),
            description: "SpecSymExpr::Add(a,b) eval/is_concrete/width.".to_string(),
            input_schema: json!({"type":"object","required":["a","b"],"properties":{"a":{"type":"integer"},"b":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbSpecEvalTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let e = rustre_symb::SpecSymExpr::Add(
            Box::new(rustre_symb::SpecSymExpr::Const { val: a, width: rustre_symb::SymWidth::W64 }),
            Box::new(rustre_symb::SpecSymExpr::Const { val: b, width: rustre_symb::SymWidth::W64 }),
        );
        Ok(ToolResult::text(json!({"concrete": e.is_concrete(), "value": e.eval_concrete(), "width_bits": e.width().map(|w| w.bits()), "source":"rustre_symb::SpecSymExpr"}).to_string()))
    }
}

pub struct RustreSymbSpecSubstituteTool;
impl RustreSymbSpecSubstituteTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_spec_substitute".to_string(),
            description: "SpecSymExpr::substitute x=const then eval x+1.".to_string(),
            input_schema: json!({"type":"object","required":["replacement"],"properties":{"replacement":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbSpecSubstituteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let r = args.get("replacement").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'replacement'".into()))?;
        let e = rustre_symb::SpecSymExpr::Add(
            Box::new(rustre_symb::SpecSymExpr::Var { name: "x".to_string(), width: rustre_symb::SymWidth::W64 }),
            Box::new(rustre_symb::SpecSymExpr::Const { val: 1, width: rustre_symb::SymWidth::W64 }),
        );
        let sub = rustre_symb::SpecSymExpr::Const { val: r, width: rustre_symb::SymWidth::W64 };
        let out = e.substitute("x", &sub);
        Ok(ToolResult::text(json!({"value": out.eval_concrete(), "source":"rustre_symb::SpecSymExpr::substitute"}).to_string()))
    }
}

pub struct RustreSymbV2SymbolicNotTool;
impl RustreSymbV2SymbolicNotTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_v2_symbolic_not".to_string(),
            description: "Bitwise NOT via rustre_symb::symbolic_not.".to_string(),
            input_schema: json!({"type":"object","required":["val","width"],"properties":{"val":{"type":"integer"},"width":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbV2SymbolicNotTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("val").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'val'".into()))?;
        let w = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let out = rustre_symb::symbolic_value::symbolic_not(rsymb_v2_val(v, w));
        Ok(ToolResult::text(json!({
            "result": out.as_concrete(),
            "is_concrete": out.is_concrete(),
            "source": "rustre_symb::symbolic_not"
        }).to_string()))
    }
}

pub struct RustreSymbV2FreshSymIdTool;
impl RustreSymbV2FreshSymIdTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_v2_fresh_sym_id".to_string(),
            description: "Return two monotonically increasing symbolic IDs via rustre_symb::fresh_sym_id.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbV2FreshSymIdTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let a = rustre_symb::symbolic_value::fresh_sym_id();
        let b = rustre_symb::symbolic_value::fresh_sym_id();
        Ok(ToolResult::text(json!({
            "first": a,
            "second": b,
            "monotonic": b > a,
            "source": "rustre_symb::fresh_sym_id"
        }).to_string()))
    }
}

pub struct RustreSymbV2SymexprEqTool;
impl RustreSymbV2SymexprEqTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_v2_symexpr_eq".to_string(),
            description: "Build SymExpr::eq(bv(lhs,w), bv(rhs,w)) and report bit width.".to_string(),
            input_schema: json!({"type":"object","required":["lhs","rhs","width"],"properties":{"lhs":{"type":"integer"},"rhs":{"type":"integer"},"width":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbV2SymexprEqTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let l = args.get("lhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lhs'".into()))?;
        let r = args.get("rhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rhs'".into()))?;
        let w = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let e = rustre_symb::SymExpr::eq(rsymb_bv(l, w), rsymb_bv(r, w));
        Ok(ToolResult::text(json!({
            "bit_width": e.bit_width(),
            "source": "rustre_symb::SymExpr::eq"
        }).to_string()))
    }
}

pub struct RustreSymbV2SymexprUgtTool;
impl RustreSymbV2SymexprUgtTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_v2_symexpr_ugt".to_string(),
            description: "Build SymExpr::ugt(bv(lhs,w), bv(rhs,w)) and report bit width.".to_string(),
            input_schema: json!({"type":"object","required":["lhs","rhs","width"],"properties":{"lhs":{"type":"integer"},"rhs":{"type":"integer"},"width":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbV2SymexprUgtTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let l = args.get("lhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lhs'".into()))?;
        let r = args.get("rhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rhs'".into()))?;
        let w = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let e = rustre_symb::SymExpr::ugt(rsymb_bv(l, w), rsymb_bv(r, w));
        Ok(ToolResult::text(json!({
            "bit_width": e.bit_width(),
            "source": "rustre_symb::SymExpr::ugt"
        }).to_string()))
    }
}

pub struct RustreSymbV2SymexprUgeTool;
impl RustreSymbV2SymexprUgeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_v2_symexpr_uge".to_string(),
            description: "Build SymExpr::uge(bv(lhs,w), bv(rhs,w)) and report bit width.".to_string(),
            input_schema: json!({"type":"object","required":["lhs","rhs","width"],"properties":{"lhs":{"type":"integer"},"rhs":{"type":"integer"},"width":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbV2SymexprUgeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let l = args.get("lhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lhs'".into()))?;
        let r = args.get("rhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rhs'".into()))?;
        let w = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let e = rustre_symb::SymExpr::uge(rsymb_bv(l, w), rsymb_bv(r, w));
        Ok(ToolResult::text(json!({
            "bit_width": e.bit_width(),
            "source": "rustre_symb::SymExpr::uge"
        }).to_string()))
    }
}

pub struct RustreSymbV2SymexprExtractTool;
impl RustreSymbV2SymexprExtractTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_v2_symexpr_extract".to_string(),
            description: "Build SymExpr::extract(bv(val,width), lo, hi) and report result bit width.".to_string(),
            input_schema: json!({"type":"object","required":["val","width","lo","hi"],"properties":{"val":{"type":"integer"},"width":{"type":"integer"},"lo":{"type":"integer"},"hi":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbV2SymexprExtractTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("val").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'val'".into()))?;
        let w = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let lo = args.get("lo").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lo'".into()))? as u32;
        let hi = args.get("hi").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'hi'".into()))? as u32;
        let e = rustre_symb::SymExpr::extract(rsymb_bv(v, w), lo, hi);
        Ok(ToolResult::text(json!({
            "bit_width": e.bit_width(),
            "source": "rustre_symb::SymExpr::extract"
        }).to_string()))
    }
}

pub struct RustreSymbV2SymexprIteTool;
impl RustreSymbV2SymexprIteTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "rustre_symb_v2_symexpr_ite".to_string(),
            description: "Build SymExpr::ite(cond,then,else) from constants and report width.".to_string(),
            input_schema: json!({"type":"object","required":["cond","then_val","else_val","width"],"properties":{"cond":{"type":"integer"},"then_val":{"type":"integer"},"else_val":{"type":"integer"},"width":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for RustreSymbV2SymexprIteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let c = args.get("cond").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'cond'".into()))?;
        let t = args.get("then_val").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'then_val'".into()))?;
        let e_v = args.get("else_val").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'else_val'".into()))?;
        let w = args.get("width").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'width'".into()))? as u32;
        let expr = rustre_symb::SymExpr::ite(rsymb_bv(c, 1), rsymb_bv(t, w), rsymb_bv(e_v, w));
        Ok(ToolResult::text(json!({
            "bit_width": expr.bit_width(),
            "source": "rustre_symb::SymExpr::ite"
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (RustreSymbBvConstTool::definition(), Box::new(RustreSymbBvConstTool)),
        (RustreSymbSimplifyAddTool::definition(), Box::new(RustreSymbSimplifyAddTool)),
        (RustreSymbSimplifyXorTool::definition(), Box::new(RustreSymbSimplifyXorTool)),
        (RustreSymbSimplifyNotTool::definition(), Box::new(RustreSymbSimplifyNotTool)),
        (RustreSymbTypeWidthTool::definition(), Box::new(RustreSymbTypeWidthTool)),
        (RustreSymbExprWidthTool::definition(), Box::new(RustreSymbExprWidthTool)),
        (RustreSymbEvalConcreteTool::definition(), Box::new(RustreSymbEvalConcreteTool)),
        (RustreSymbStateForkTool::definition(), Box::new(RustreSymbStateForkTool)),
        (RustreSymbPathConjunctionTool::definition(), Box::new(RustreSymbPathConjunctionTool)),
        (RustreSymbSymWidthInfoTool::definition(), Box::new(RustreSymbSymWidthInfoTool)),
        (RustreSymbSpecEvalTool::definition(), Box::new(RustreSymbSpecEvalTool)),
        (RustreSymbSpecSubstituteTool::definition(), Box::new(RustreSymbSpecSubstituteTool)),
        (RustreSymbV2SymbolicNotTool::definition(), Box::new(RustreSymbV2SymbolicNotTool)),
        (RustreSymbV2FreshSymIdTool::definition(), Box::new(RustreSymbV2FreshSymIdTool)),
        (RustreSymbV2SymexprEqTool::definition(), Box::new(RustreSymbV2SymexprEqTool)),
        (RustreSymbV2SymexprUgtTool::definition(), Box::new(RustreSymbV2SymexprUgtTool)),
        (RustreSymbV2SymexprUgeTool::definition(), Box::new(RustreSymbV2SymexprUgeTool)),
        (RustreSymbV2SymexprExtractTool::definition(), Box::new(RustreSymbV2SymexprExtractTool)),
        (RustreSymbV2SymexprIteTool::definition(), Box::new(RustreSymbV2SymexprIteTool)),
    ]
}
