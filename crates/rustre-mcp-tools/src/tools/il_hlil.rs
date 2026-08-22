//! MCP wrappers for the rustre-il-hlil crate.
//! Manually authored 2026-07-12 to close the decompiler pipeline gap.

use rustre_mcp_server::{ToolDefinition, ToolHandler, ToolResult, McpError};
use serde_json::{json, Value};
use async_trait::async_trait;

// ── schema helpers ────────────────────────────────────────────────────────────

fn schema_func() -> Value {
    json!({"type":"object","properties":{"func":{"type":"object","description":"Serialised HlilFunction"}},"required":["func"]})
}
fn schema_type() -> Value {
    json!({"type":"object","properties":{"ty":{"type":"object","description":"Serialised HlilType"}},"required":["ty"]})
}
fn schema_expr() -> Value {
    json!({"type":"object","properties":{"expr":{"type":"object","description":"Serialised HlilExpr"}},"required":["expr"]})
}
fn schema_stmt() -> Value {
    json!({"type":"object","properties":{"stmt":{"type":"object","description":"Serialised HlilStatement"}},"required":["stmt"]})
}
fn schema_expr_var() -> Value {
    json!({"type":"object","properties":{"expr":{"type":"object"},"var":{"type":"object","description":"Serialised HlilVar"}},"required":["expr","var"]})
}
fn schema_stmt_indent() -> Value {
    json!({"type":"object","properties":{"stmt":{"type":"object"},"indent":{"type":"integer","default":0}},"required":["stmt"]})
}
fn schema_print_type() -> Value {
    json!({"type":"object","properties":{"ty":{"type":"object"}},"required":["ty"]})
}

// ── stub helper ───────────────────────────────────────────────────────────────

fn not_available(tool: &str) -> Result<ToolResult, McpError> {
    // rustre-il-hlil types (HlilFunction, HlilExpr, etc.) are not yet
    // serde-serializable; JSON round-trip support is a planned extension.
    Ok(ToolResult::text(json!({"status":"stub","reason":"HLIL types lack serde support; JSON interface planned","crate":"rustre_il_hlil","tool":tool}).to_string()))
}

// ── wrappers ──────────────────────────────────────────────────────────────────

pub struct IlHlilFunctionPrintTool;
impl IlHlilFunctionPrintTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_hlil_function_print".to_string(), description: "Pretty-print a HlilFunction to a C-like string.".to_string(), input_schema: schema_func(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlHlilFunctionPrintTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_hlil_function_print") } }

pub struct IlHlilCallsMadeTool;
impl IlHlilCallsMadeTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_hlil_calls_made".to_string(), description: "Return all call-expression nodes in a HlilFunction.".to_string(), input_schema: schema_func(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlHlilCallsMadeTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_hlil_calls_made") } }

pub struct IlHlilVarsUsedTool;
impl IlHlilVarsUsedTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_hlil_vars_used".to_string(), description: "Return all variables referenced in a HlilFunction.".to_string(), input_schema: schema_func(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlHlilVarsUsedTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_hlil_vars_used") } }

pub struct IlHlilAllStatementsTool;
impl IlHlilAllStatementsTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_hlil_all_statements".to_string(), description: "Iterate over all statements in a HlilFunction.".to_string(), input_schema: schema_func(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlHlilAllStatementsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_hlil_all_statements") } }

pub struct IlHlilTypeByteSizeTool;
impl IlHlilTypeByteSizeTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_hlil_type_byte_size".to_string(), description: "Return the byte-size of a HlilType, if known.".to_string(), input_schema: schema_type(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlHlilTypeByteSizeTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_hlil_type_byte_size") } }

pub struct IlHlilTypeIsPointerTool;
impl IlHlilTypeIsPointerTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_hlil_type_is_pointer".to_string(), description: "Return whether a HlilType is a pointer.".to_string(), input_schema: schema_type(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlHlilTypeIsPointerTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_hlil_type_is_pointer") } }

pub struct IlHlilTypeIsIntegerTool;
impl IlHlilTypeIsIntegerTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_hlil_type_is_integer".to_string(), description: "Return whether a HlilType is an integer.".to_string(), input_schema: schema_type(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlHlilTypeIsIntegerTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_hlil_type_is_integer") } }

pub struct IlHlilExprComplexityTool;
impl IlHlilExprComplexityTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_hlil_expr_complexity".to_string(), description: "Return the node-count complexity of a HlilExpr.".to_string(), input_schema: schema_expr(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlHlilExprComplexityTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_hlil_expr_complexity") } }

pub struct IlHlilExprUsesVarTool;
impl IlHlilExprUsesVarTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_hlil_expr_uses_var".to_string(), description: "Return whether a HlilExpr references a given HlilVar.".to_string(), input_schema: schema_expr_var(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlHlilExprUsesVarTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_hlil_expr_uses_var") } }

pub struct IlHlilExprIsConstTool;
impl IlHlilExprIsConstTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_hlil_expr_is_const".to_string(), description: "If a HlilExpr is a constant, return its i64 value.".to_string(), input_schema: schema_expr(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlHlilExprIsConstTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_hlil_expr_is_const") } }

pub struct IlHlilStmtIsTerminatorTool;
impl IlHlilStmtIsTerminatorTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_hlil_stmt_is_terminator".to_string(), description: "Return whether a HlilStatement is a block terminator.".to_string(), input_schema: schema_stmt(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlHlilStmtIsTerminatorTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_hlil_stmt_is_terminator") } }

pub struct IlHlilStmtContainsReturnTool;
impl IlHlilStmtContainsReturnTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_hlil_stmt_contains_return".to_string(), description: "Return whether a HlilStatement contains a return.".to_string(), input_schema: schema_stmt(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlHlilStmtContainsReturnTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_hlil_stmt_contains_return") } }

pub struct IlHlilPrintTypeTool;
impl IlHlilPrintTypeTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_hlil_print_type".to_string(), description: "Print a HlilType as a C type string.".to_string(), input_schema: schema_print_type(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlHlilPrintTypeTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_hlil_print_type") } }

pub struct IlHlilPrintExprTool;
impl IlHlilPrintExprTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_hlil_print_expr".to_string(), description: "Print a HlilExpr as a C expression string.".to_string(), input_schema: schema_expr(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlHlilPrintExprTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_hlil_print_expr") } }

pub struct IlHlilPrintStatementTool;
impl IlHlilPrintStatementTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "il_hlil_print_statement".to_string(), description: "Print a HlilStatement as an indented C statement string.".to_string(), input_schema: schema_stmt_indent(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for IlHlilPrintStatementTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { not_available("il_hlil_print_statement") } }

// ── registration ──────────────────────────────────────────────────────────────

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (IlHlilFunctionPrintTool::definition(), Box::new(IlHlilFunctionPrintTool)),
        (IlHlilCallsMadeTool::definition(), Box::new(IlHlilCallsMadeTool)),
        (IlHlilVarsUsedTool::definition(), Box::new(IlHlilVarsUsedTool)),
        (IlHlilAllStatementsTool::definition(), Box::new(IlHlilAllStatementsTool)),
        (IlHlilTypeByteSizeTool::definition(), Box::new(IlHlilTypeByteSizeTool)),
        (IlHlilTypeIsPointerTool::definition(), Box::new(IlHlilTypeIsPointerTool)),
        (IlHlilTypeIsIntegerTool::definition(), Box::new(IlHlilTypeIsIntegerTool)),
        (IlHlilExprComplexityTool::definition(), Box::new(IlHlilExprComplexityTool)),
        (IlHlilExprUsesVarTool::definition(), Box::new(IlHlilExprUsesVarTool)),
        (IlHlilExprIsConstTool::definition(), Box::new(IlHlilExprIsConstTool)),
        (IlHlilStmtIsTerminatorTool::definition(), Box::new(IlHlilStmtIsTerminatorTool)),
        (IlHlilStmtContainsReturnTool::definition(), Box::new(IlHlilStmtContainsReturnTool)),
        (IlHlilPrintTypeTool::definition(), Box::new(IlHlilPrintTypeTool)),
        (IlHlilPrintExprTool::definition(), Box::new(IlHlilPrintExprTool)),
        (IlHlilPrintStatementTool::definition(), Box::new(IlHlilPrintStatementTool)),
    ]
}
