//! MCP wrappers for the rustre-il-mlil crate.
//! Manually authored 2026-07-12 to close the decompiler pipeline gap.

use rustre_mcp_server::{ToolDefinition, ToolHandler, ToolResult, McpError};
use serde_json::{json, Value};
use async_trait::async_trait;

// ── schema helpers ────────────────────────────────────────────────────────────

fn schema_func() -> Value {
    json!({"type":"object","properties":{"func":{"type":"object","description":"Serialised MlilFunction"}},"required":["func"]})
}
fn schema_expr() -> Value {
    json!({"type":"object","properties":{"expr":{"type":"object","description":"Serialised MlilExpr"}},"required":["expr"]})
}
fn schema_instr() -> Value {
    json!({"type":"object","properties":{"instr":{"type":"object","description":"Serialised MlilInstruction"}},"required":["instr"]})
}

fn not_available(tool: &str) -> Result<ToolResult, McpError> {
    // rustre-il-mlil types (MlilFunction, MlilExpr, etc.) are not yet
    // serde-serializable; JSON round-trip support is a planned extension.
    Ok(ToolResult::text(json!({"status":"stub","reason":"MLIL types lack serde support; JSON interface planned","crate":"rustre_il_mlil","tool":tool}).to_string()))
}

// ── wrappers ──────────────────────────────────────────────────────────────────

pub struct IlMlilFunctionToTextTool;
impl IlMlilFunctionToTextTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_mlil_function_to_text".to_string(), description: "Render a MlilFunction to a human-readable text listing.".to_string(), input_schema: schema_func(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlMlilFunctionToTextTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_mlil_function_to_text") } }

pub struct IlMlilFunctionToDotTool;
impl IlMlilFunctionToDotTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_mlil_function_to_dot".to_string(), description: "Render a MlilFunction as Graphviz DOT.".to_string(), input_schema: schema_func(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlMlilFunctionToDotTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_mlil_function_to_dot") } }

pub struct IlMlilFunctionToJsonTool;
impl IlMlilFunctionToJsonTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_mlil_function_to_json".to_string(), description: "Serialise a MlilFunction to JSON.".to_string(), input_schema: schema_func(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlMlilFunctionToJsonTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_mlil_function_to_json") } }

pub struct IlMlilFunctionToCTool;
impl IlMlilFunctionToCTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_mlil_function_to_c".to_string(), description: "Emit a MlilFunction as pseudo-C source.".to_string(), input_schema: schema_func(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlMlilFunctionToCTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_mlil_function_to_c") } }

pub struct IlMlilExprToCTool;
impl IlMlilExprToCTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_mlil_expr_to_c".to_string(), description: "Emit a MlilExpr as a C expression string.".to_string(), input_schema: schema_expr(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlMlilExprToCTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_mlil_expr_to_c") } }

pub struct IlMlilInstrToCTool;
impl IlMlilInstrToCTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_mlil_instr_to_c".to_string(), description: "Emit a MlilInstruction as a C statement string.".to_string(), input_schema: schema_instr(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlMlilInstrToCTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_mlil_instr_to_c") } }

pub struct IlMlilInferTypesTool;
impl IlMlilInferTypesTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_mlil_infer_types".to_string(), description: "Infer SSA-variable types for a MlilFunction.".to_string(), input_schema: schema_func(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlMlilInferTypesTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_mlil_infer_types") } }

pub struct IlMlilCollectConstantsTool;
impl IlMlilCollectConstantsTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_mlil_collect_constants".to_string(), description: "Collect all integer constants appearing in a MlilFunction.".to_string(), input_schema: schema_func(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlMlilCollectConstantsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_mlil_collect_constants") } }

pub struct IlMlilCollectCallSitesTool;
impl IlMlilCollectCallSitesTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_mlil_collect_call_sites".to_string(), description: "Collect all call-site descriptors from a MlilFunction.".to_string(), input_schema: schema_func(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlMlilCollectCallSitesTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_mlil_collect_call_sites") } }

pub struct IlMlilUseDefChainsTool;
impl IlMlilUseDefChainsTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_mlil_use_def_chains".to_string(), description: "Build use-def chains for all SSA variables in a MlilFunction.".to_string(), input_schema: schema_func(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlMlilUseDefChainsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_mlil_use_def_chains") } }

pub struct IlMlilComputeLivenessTool;
impl IlMlilComputeLivenessTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_mlil_compute_liveness".to_string(), description: "Compute per-block live-in/live-out sets for a MlilFunction.".to_string(), input_schema: schema_func(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlMlilComputeLivenessTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_mlil_compute_liveness") } }

pub struct IlMlilComputeDominatorsTool;
impl IlMlilComputeDominatorsTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_mlil_compute_dominators".to_string(), description: "Compute the immediate-dominator map for a MlilFunction.".to_string(), input_schema: schema_func(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlMlilComputeDominatorsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_mlil_compute_dominators") } }

pub struct IlMlilCollectVarInfoTool;
impl IlMlilCollectVarInfoTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_mlil_collect_var_info".to_string(), description: "Collect metadata about each variable in a MlilFunction.".to_string(), input_schema: schema_func(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlMlilCollectVarInfoTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_mlil_collect_var_info") } }

pub struct IlMlilFoldExprTool;
impl IlMlilFoldExprTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_mlil_fold_expr".to_string(), description: "Constant-fold a MlilExpr; return the result and fold count.".to_string(), input_schema: schema_expr(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlMlilFoldExprTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_mlil_fold_expr") } }

pub struct IlMlilEliminateDeadStoresTool;
impl IlMlilEliminateDeadStoresTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_mlil_eliminate_dead_stores".to_string(), description: "Remove dead store instructions from a MlilFunction; return removal count.".to_string(), input_schema: schema_func(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlMlilEliminateDeadStoresTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_mlil_eliminate_dead_stores") } }

// ── registration ──────────────────────────────────────────────────────────────

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (IlMlilFunctionToTextTool::definition(), Box::new(IlMlilFunctionToTextTool)),
        (IlMlilFunctionToDotTool::definition(), Box::new(IlMlilFunctionToDotTool)),
        (IlMlilFunctionToJsonTool::definition(), Box::new(IlMlilFunctionToJsonTool)),
        (IlMlilFunctionToCTool::definition(), Box::new(IlMlilFunctionToCTool)),
        (IlMlilExprToCTool::definition(), Box::new(IlMlilExprToCTool)),
        (IlMlilInstrToCTool::definition(), Box::new(IlMlilInstrToCTool)),
        (IlMlilInferTypesTool::definition(), Box::new(IlMlilInferTypesTool)),
        (IlMlilCollectConstantsTool::definition(), Box::new(IlMlilCollectConstantsTool)),
        (IlMlilCollectCallSitesTool::definition(), Box::new(IlMlilCollectCallSitesTool)),
        (IlMlilUseDefChainsTool::definition(), Box::new(IlMlilUseDefChainsTool)),
        (IlMlilComputeLivenessTool::definition(), Box::new(IlMlilComputeLivenessTool)),
        (IlMlilComputeDominatorsTool::definition(), Box::new(IlMlilComputeDominatorsTool)),
        (IlMlilCollectVarInfoTool::definition(), Box::new(IlMlilCollectVarInfoTool)),
        (IlMlilFoldExprTool::definition(), Box::new(IlMlilFoldExprTool)),
        (IlMlilEliminateDeadStoresTool::definition(), Box::new(IlMlilEliminateDeadStoresTool)),
    ]
}
