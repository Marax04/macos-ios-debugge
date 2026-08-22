//! MCP wrapper for the rustre-debug `conditional_breakpoint` module.
//!
//! Self-contained capability surface: unlike `tools/debug.rs`, this file has no
//! access to that module's private live `LiveSession` registry, so it answers
//! from the `rustre_debug::conditional_breakpoint` public API directly on the
//! inputs the caller provides. Every response is therefore `live: false`, names
//! its real `source` module, and carries a `hint` pointing at the live-session
//! variant as the follow-up.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use std::sync::Arc;
use anyhow::{Result as AnyhowResult, anyhow};

use rustre_core::address::Address;
use rustre_debug::conditional_breakpoint::{
    BreakpointCondition, ConditionalBreakpoint, ConditionalBreakpointSet, MapEvalContext,
};

// ---------------------------------------------------------------------------
// Helper functions (copied verbatim from tools/debug.rs to keep this file
// self-contained — it must compile in isolation).
// ---------------------------------------------------------------------------

fn req_str<'a>(args: &'a Value, key: &str) -> AnyhowResult<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing required field '{key}'"))
}

/// Coerce a JSON value into a `u64`, accepting the several shapes MCP clients
/// actually send an address as: a JSON integer, a hex string (`"0x1400..."`),
/// or a decimal string (`"20"`).
fn coerce_u64(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() {
        return Some(n);
    }
    if let Some(f) = v.as_f64() {
        if f >= 0.0 && f.fract() == 0.0 {
            return Some(f as u64);
        }
    }
    let s = v.as_str()?.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    s.parse::<u64>().ok()
}

fn req_u64(args: &Value, key: &str) -> AnyhowResult<u64> {
    args.get(key)
        .and_then(coerce_u64)
        .ok_or_else(|| anyhow!("missing required field '{key}' (integer)"))
}

// ---------------------------------------------------------------------------
// SyncFnTool — thin adapter that wraps a sync closure as an async ToolHandler
// (copied verbatim from tools/debug.rs).
// ---------------------------------------------------------------------------

type SyncFn = Arc<dyn Fn(Value) -> AnyhowResult<Value> + Send + Sync>;

struct SyncFnTool {
    f: SyncFn,
}

#[async_trait]
impl ToolHandler for SyncFnTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        match (self.f)(args) {
            Ok(v) => Ok(ToolResult::text(v.to_string())),
            Err(e) => Err(McpError::InternalError(e.to_string())),
        }
    }
}

fn make_tool(
    name: &'static str,
    description: &'static str,
    schema: Value,
    f: impl Fn(Value) -> AnyhowResult<Value> + Send + Sync + 'static,
) -> (ToolDefinition, Box<dyn ToolHandler>) {
    let def = ToolDefinition {
        name: name.to_string(),
        description: description.to_string(),
        input_schema: schema,
        parameters: Value::Null,
    };
    let tool = SyncFnTool { f: Arc::new(f) };
    (def, Box::new(tool))
}

// ---------------------------------------------------------------------------
// Source / hint constants for the self-contained capability.
// ---------------------------------------------------------------------------

const SOURCE: &str = "rustre_debug::conditional_breakpoint (ConditionalBreakpointSet/ConditionalBreakpoint/BreakpointCondition)";
const LIVE_HINT: &str = "self-contained capability: this evaluates the condition against the register \
    snapshot you pass in `regs`, not a running process. The live-session variant — arming this \
    breakpoint on a real `debug.launch` session and firing it against actual CPU state — is the \
    follow-up, wired in tools/debug.rs's LiveSession registry.";

/// Build a `MapEvalContext` and whether it came from a LIVE session. When
/// `session_id` names a live session, the register snapshot is the REAL stopped
/// thread's; otherwise it's the optional `{ "rax": 1, ... }` object.
fn ctx_from_regs(args: &Value) -> (MapEvalContext, bool) {
    let mut ctx = MapEvalContext::new();
    if let Some(live) = args.get("session_id").and_then(Value::as_str)
        .and_then(crate::tools::debug::session_registers)
    {
        for (name, val) in live {
            ctx.set_reg(name, val);
        }
        return (ctx, true);
    }
    if let Some(map) = args.get("regs").and_then(Value::as_object) {
        for (name, v) in map {
            if let Some(val) = coerce_u64(v) {
                ctx.set_reg(name.clone(), val);
            }
        }
    }
    (ctx, false)
}

// ---------------------------------------------------------------------------
// handlers_conditional_breakpoints() — debug.* tools for the
// "conditional-breakpoints" capability.
// ---------------------------------------------------------------------------

#[must_use]
pub fn handlers_conditional_breakpoints() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        // ── debug.set_conditional_breakpoint ────────────────────────────────
        make_tool(
            "debug.set_conditional_breakpoint",
            "Define a register-conditioned breakpoint (`register == value` or `register != value`) \
             at an address and evaluate whether it would fire against a supplied register snapshot. \
             Self-contained: computed directly from the rustre_debug conditional_breakpoint public \
             API on the inputs you pass, so the response is always `live: false` with a `hint` for \
             the live-session follow-up.",
            json!({
                "type": "object",
                "required": ["address", "register", "value"],
                "properties": {
                    "address":  { "type": ["integer", "string"], "description": "Breakpoint address (int, 0x-hex, or decimal string)" },
                    "register": { "type": "string", "description": "Register name the condition tests, e.g. \"rax\"" },
                    "value":    { "type": ["integer", "string"], "description": "Value to compare the register against" },
                    "operator": { "type": "string", "enum": ["eq", "ne"], "description": "Comparison operator (default \"eq\")" },
                    "session_id": { "type": "string", "description": "If given and it names a LIVE session, the condition is evaluated against the real stopped thread's registers (live:true); 'regs' is then ignored." },
                    "regs":     { "type": "object", "description": "Register snapshot { name: value } to evaluate the condition against (optional)" }
                },
                "additionalProperties": false
            }),
            |args| {
                let address = req_u64(&args, "address")?;
                let register = req_str(&args, "register")?.to_string();
                let value = req_u64(&args, "value")?;
                let operator = args
                    .get("operator")
                    .and_then(Value::as_str)
                    .unwrap_or("eq")
                    .to_string();

                let condition = match operator.as_str() {
                    "eq" => BreakpointCondition::reg_eq(register.clone(), value),
                    "ne" => BreakpointCondition::reg_ne(register.clone(), value),
                    other => {
                        return Err(anyhow!(
                            "unknown operator '{other}': use \"eq\" or \"ne\""
                        ))
                    }
                };
                let expression = condition.expression.clone();

                // Build the conditional breakpoint via the public API.
                let mut bp = ConditionalBreakpoint::at(Address::from(address));
                bp.add_condition(condition);

                // Register it in a set so we can demonstrate find_firing too.
                let mut set = ConditionalBreakpointSet::new();
                let index = set.add(bp);

                // Evaluate against the live session's registers when a
                // session_id is given, else the supplied snapshot.
                let (ctx, is_live) = ctx_from_regs(&args);
                let has_regs = is_live || args.get("regs").and_then(Value::as_object).is_some();

                // find_firing evaluates should_break internally for us.
                let firing = set.find_firing(Address::from(address), &ctx);
                let would_fire = firing.contains(&index);

                // Surface any evaluation error (e.g. register absent from the
                // snapshot) explicitly rather than silently reporting "no fire".
                let mut eval_error: Option<String> = None;
                if let Some(cbp) = set.get_mut(index) {
                    if let Err(e) = cbp.should_break(&ctx) {
                        eval_error = Some(e.to_string());
                    }
                }

                Ok(json!({
                    "address": address,
                    "register": register,
                    "value": value,
                    "operator": operator,
                    "expression": expression,
                    "breakpoint_index": index,
                    "evaluated": has_regs,
                    "would_fire": would_fire,
                    "eval_error": eval_error,
                    "live": is_live,
                    "source": if is_live { "rustre_debug::conditional_breakpoint (live session registers)" } else { SOURCE },
                    "hint": if is_live { Value::Null } else { json!(LIVE_HINT) }
                }))
            },
        ),
    ]
}
