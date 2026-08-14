//! MCP wrappers for the rustre-decompiler-expr crate.
//! Manually authored 2026-07-12 to close the decompiler pipeline gap.

use rustre_mcp_server::{ToolDefinition, ToolHandler, ToolResult, McpError};
use serde_json::{json, Value};
use async_trait::async_trait;
use rustre_decompiler_expr::{Expr, SsaAssign, DefUseChain, ExprFolder, ExprSimplifier,
                              ExprNormalizer, ExprComparator, ExprPrinter,
                              has_side_effects, is_safe_to_inline};

// ── schema helpers ────────────────────────────────────────────────────────────

fn schema_expr() -> Value {
    json!({"type":"object","properties":{"expr":{"type":"object","description":"Serialised Expr"}},"required":["expr"]})
}
fn schema_two_exprs() -> Value {
    json!({"type":"object","properties":{"a":{"type":"object","description":"Serialised Expr"},"b":{"type":"object","description":"Serialised Expr"}},"required":["a","b"]})
}
fn schema_assigns() -> Value {
    json!({"type":"object","properties":{"assigns":{"type":"array","items":{"type":"object"},"description":"Array of serialised SsaAssign"}},"required":["assigns"]})
}
fn schema_assigns_name() -> Value {
    json!({"type":"object","properties":{"assigns":{"type":"array","items":{"type":"object"}},"name":{"type":"string"}},"required":["assigns","name"]})
}
fn schema_expr_name_chain() -> Value {
    json!({"type":"object","properties":{"expr":{"type":"object"},"name":{"type":"string"},"assigns":{"type":"array","items":{"type":"object"}}},"required":["expr","name","assigns"]})
}

fn parse_expr(args: &Value, key: &str) -> Result<Expr, McpError> {
    let v = args.get(key).ok_or_else(|| McpError::InvalidParams(format!("missing '{key}'")))?;
    serde_json::from_value(v.clone()).map_err(|e| McpError::InvalidParams(format!("invalid Expr: {e}")))
}
fn parse_assigns(args: &Value) -> Result<Vec<SsaAssign>, McpError> {
    let v = args.get("assigns").and_then(Value::as_array)
        .ok_or_else(|| McpError::InvalidParams("missing 'assigns'".into()))?;
    v.iter().map(|a| serde_json::from_value(a.clone())
        .map_err(|e| McpError::InvalidParams(format!("invalid SsaAssign: {e}"))))
        .collect()
}

// ── wrappers ──────────────────────────────────────────────────────────────────

pub struct DecompilerExprSimplifTool;
impl DecompilerExprSimplifTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_expr_simplify".to_string(), description: "Algebraically simplify an Expr (constant folding, identity elimination).".to_string(), input_schema: schema_expr(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for DecompilerExprSimplifTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let expr = parse_expr(&args, "expr")?;
        let result = ExprSimplifier::new().simplify(expr);
        let s = serde_json::to_string(&result).unwrap_or_default();
        Ok(ToolResult::text(json!({"simplified": s, "source":"rustre_decompiler_expr::ExprSimplifier::simplify"}).to_string()))
    }
}

pub struct DecompilerExprSimplifyAssignsTool;
impl DecompilerExprSimplifyAssignsTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_expr_simplify_assigns".to_string(), description: "Simplify all RHS expressions in a list of SSA assignments.".to_string(), input_schema: schema_assigns(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for DecompilerExprSimplifyAssignsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let assigns = parse_assigns(&args)?;
        let result = ExprSimplifier::new().simplify_assignments(assigns);
        let s = serde_json::to_string(&result).unwrap_or_default();
        Ok(ToolResult::text(json!({"count": result.len(), "assigns": s, "source":"rustre_decompiler_expr::ExprSimplifier::simplify_assignments"}).to_string()))
    }
}

pub struct DecompilerExprNormalizeTool;
impl DecompilerExprNormalizeTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_expr_normalize".to_string(), description: "Bring an Expr into canonical form for structural comparison.".to_string(), input_schema: schema_expr(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for DecompilerExprNormalizeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let expr = parse_expr(&args, "expr")?;
        let result = ExprNormalizer.normalize(expr);
        let s = serde_json::to_string(&result).unwrap_or_default();
        Ok(ToolResult::text(json!({"normalized": s, "source":"rustre_decompiler_expr::ExprNormalizer::normalize"}).to_string()))
    }
}

pub struct DecompilerExprEquivalentTool;
impl DecompilerExprEquivalentTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_expr_equivalent".to_string(), description: "Return true if two Exprs are structurally equivalent after normalisation.".to_string(), input_schema: schema_two_exprs(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for DecompilerExprEquivalentTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = parse_expr(&args, "a")?;
        let b = parse_expr(&args, "b")?;
        let eq = ExprComparator::new().equivalent(&a, &b);
        Ok(ToolResult::text(json!({"equivalent": eq, "source":"rustre_decompiler_expr::ExprComparator::equivalent"}).to_string()))
    }
}

pub struct DecompilerExprSimilarityTool;
impl DecompilerExprSimilarityTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_expr_similarity".to_string(), description: "Compute a structural similarity score [0.0, 1.0] between two Exprs.".to_string(), input_schema: schema_two_exprs(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for DecompilerExprSimilarityTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = parse_expr(&args, "a")?;
        let b = parse_expr(&args, "b")?;
        let sim = ExprComparator::new().similarity(&a, &b);
        Ok(ToolResult::text(json!({"similarity": sim, "source":"rustre_decompiler_expr::ExprComparator::similarity"}).to_string()))
    }
}

pub struct DecompilerExprFoldTool;
impl DecompilerExprFoldTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_expr_fold".to_string(), description: "Inline single-use temporaries in a list of SSA assignments.".to_string(), input_schema: schema_assigns(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for DecompilerExprFoldTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let assigns = parse_assigns(&args)?;
        let folder = ExprFolder::new();
        let result = folder.fold_expressions(&assigns)
            .map_err(|e| McpError::InvalidParams(format!("fold error: {e}")))?;
        let s = serde_json::to_string(&result).unwrap_or_default();
        Ok(ToolResult::text(json!({"count": result.len(), "assigns": s, "source":"rustre_decompiler_expr::ExprFolder::fold_expressions"}).to_string()))
    }
}

pub struct DecompilerExprPrintTool;
impl DecompilerExprPrintTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_expr_print".to_string(), description: "Render an Expr as a C-like expression string.".to_string(), input_schema: schema_expr(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for DecompilerExprPrintTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let expr = parse_expr(&args, "expr")?;
        let s = ExprPrinter::new().print(&expr);
        Ok(ToolResult::text(json!({"printed": s, "source":"rustre_decompiler_expr::ExprPrinter::print"}).to_string()))
    }
}

pub struct DecompilerExprDefUseFromAssignsTool;
impl DecompilerExprDefUseFromAssignsTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_expr_def_use_from_assigns".to_string(), description: "Build a DefUseChain from a list of SSA assignments.".to_string(), input_schema: schema_assigns(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for DecompilerExprDefUseFromAssignsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let assigns = parse_assigns(&args)?;
        let chain = DefUseChain::from_assignments(&assigns);
        let dead = chain.dead_vars().iter().map(|s| s.to_string()).collect::<Vec<_>>();
        Ok(ToolResult::text(json!({"dead_var_count": dead.len(), "dead_vars": dead, "source":"rustre_decompiler_expr::DefUseChain::from_assignments"}).to_string()))
    }
}

pub struct DecompilerExprDeadVarsTool;
impl DecompilerExprDeadVarsTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_expr_dead_vars".to_string(), description: "Return variable names that are defined but never used.".to_string(), input_schema: schema_assigns(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for DecompilerExprDeadVarsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let assigns = parse_assigns(&args)?;
        let chain = DefUseChain::from_assignments(&assigns);
        let dead: Vec<String> = chain.dead_vars().iter().map(|s| s.to_string()).collect();
        Ok(ToolResult::text(json!({"count": dead.len(), "dead_vars": dead, "source":"rustre_decompiler_expr::DefUseChain::dead_vars"}).to_string()))
    }
}

pub struct DecompilerExprSingleDefUseTool;
impl DecompilerExprSingleDefUseTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_expr_single_def_use".to_string(), description: "Return true if a variable has exactly one definition and one use.".to_string(), input_schema: schema_assigns_name(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for DecompilerExprSingleDefUseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let assigns = parse_assigns(&args)?;
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let chain = DefUseChain::from_assignments(&assigns);
        let r = chain.is_single_def_use(name);
        Ok(ToolResult::text(json!({"name": name, "is_single_def_use": r, "source":"rustre_decompiler_expr::DefUseChain::is_single_def_use"}).to_string()))
    }
}

pub struct DecompilerExprHasSideEffectsTool;
impl DecompilerExprHasSideEffectsTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_expr_has_side_effects".to_string(), description: "Return whether an Expr may have observable side-effects.".to_string(), input_schema: schema_expr(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for DecompilerExprHasSideEffectsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let expr = parse_expr(&args, "expr")?;
        let r = has_side_effects(&expr);
        Ok(ToolResult::text(json!({"has_side_effects": r, "source":"rustre_decompiler_expr::has_side_effects"}).to_string()))
    }
}

pub struct DecompilerExprSafeToInlineTool;
impl DecompilerExprSafeToInlineTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_expr_safe_to_inline".to_string(), description: "Return whether an Expr is safe to inline for the named variable.".to_string(), input_schema: schema_expr_name_chain(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for DecompilerExprSafeToInlineTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let expr = parse_expr(&args, "expr")?;
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let assigns = parse_assigns(&args)?;
        let chain = DefUseChain::from_assignments(&assigns);
        let r = is_safe_to_inline(&expr, name, &chain);
        Ok(ToolResult::text(json!({"name": name, "is_safe_to_inline": r, "source":"rustre_decompiler_expr::is_safe_to_inline"}).to_string()))
    }
}

pub struct DecompilerExprDepthTool;
impl DecompilerExprDepthTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_expr_depth".to_string(), description: "Return the maximum depth of an expression tree.".to_string(), input_schema: schema_expr(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for DecompilerExprDepthTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let expr = parse_expr(&args, "expr")?;
        let d = expr.depth();
        Ok(ToolResult::text(json!({"depth": d, "source":"rustre_decompiler_expr::Expr::depth"}).to_string()))
    }
}

pub struct DecompilerExprNodeCountTool;
impl DecompilerExprNodeCountTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_expr_node_count".to_string(), description: "Return the total number of nodes in an expression tree.".to_string(), input_schema: schema_expr(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for DecompilerExprNodeCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let expr = parse_expr(&args, "expr")?;
        let n = expr.node_count();
        Ok(ToolResult::text(json!({"node_count": n, "source":"rustre_decompiler_expr::Expr::node_count"}).to_string()))
    }
}

pub struct DecompilerExprReferencedVarsTool;
impl DecompilerExprReferencedVarsTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "decompiler_expr_referenced_vars".to_string(), description: "Return the names of all variables referenced in an Expr.".to_string(), input_schema: schema_expr(), parameters: Value::Null } }
}
#[async_trait]
impl ToolHandler for DecompilerExprReferencedVarsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let expr = parse_expr(&args, "expr")?;
        let vars = expr.referenced_vars();
        Ok(ToolResult::text(json!({"count": vars.len(), "vars": vars, "source":"rustre_decompiler_expr::Expr::referenced_vars"}).to_string()))
    }
}

// ── registration ──────────────────────────────────────────────────────────────

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DecompilerExprSimplifTool::definition(), Box::new(DecompilerExprSimplifTool)),
        (DecompilerExprSimplifyAssignsTool::definition(), Box::new(DecompilerExprSimplifyAssignsTool)),
        (DecompilerExprNormalizeTool::definition(), Box::new(DecompilerExprNormalizeTool)),
        (DecompilerExprEquivalentTool::definition(), Box::new(DecompilerExprEquivalentTool)),
        (DecompilerExprSimilarityTool::definition(), Box::new(DecompilerExprSimilarityTool)),
        (DecompilerExprFoldTool::definition(), Box::new(DecompilerExprFoldTool)),
        (DecompilerExprPrintTool::definition(), Box::new(DecompilerExprPrintTool)),
        (DecompilerExprDefUseFromAssignsTool::definition(), Box::new(DecompilerExprDefUseFromAssignsTool)),
        (DecompilerExprDeadVarsTool::definition(), Box::new(DecompilerExprDeadVarsTool)),
        (DecompilerExprSingleDefUseTool::definition(), Box::new(DecompilerExprSingleDefUseTool)),
        (DecompilerExprHasSideEffectsTool::definition(), Box::new(DecompilerExprHasSideEffectsTool)),
        (DecompilerExprSafeToInlineTool::definition(), Box::new(DecompilerExprSafeToInlineTool)),
        (DecompilerExprDepthTool::definition(), Box::new(DecompilerExprDepthTool)),
        (DecompilerExprNodeCountTool::definition(), Box::new(DecompilerExprNodeCountTool)),
        (DecompilerExprReferencedVarsTool::definition(), Box::new(DecompilerExprReferencedVarsTool)),
    ]
}
