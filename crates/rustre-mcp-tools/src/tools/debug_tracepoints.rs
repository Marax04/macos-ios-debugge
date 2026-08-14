//! MCP wrappers for the rustre-debug "tracepoints" capability.
//!
//! Self-contained: this module deliberately does NOT reach the live
//! `LiveSession` registry that lives (privately) in `tools/debug.rs`. Instead it
//! answers each request directly against the `rustre_debug` public
//! conditional-breakpoint / tracepoint API, computing the result from the inputs
//! the caller supplies (an in-memory register/memory `EvalContext`). Every
//! response therefore carries `"live": false`, a `"source"` naming the real
//! module, and a `"hint"` pointing at the live-session follow-up variant.
//!
//! Real module: `rustre_debug::conditional_breakpoint`
//!   (`TracepointSet` / `Tracepoint` / `TracepointFormat`).

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use std::sync::Arc;
use anyhow::{Result as AnyhowResult, anyhow};

use rustre_core::address::Address;
use rustre_debug::conditional_breakpoint::{
    ConditionOperand, MapEvalContext, Tracepoint, TracepointFormat, TracepointSet,
};

// ---------------------------------------------------------------------------
// Helper functions — copied verbatim from tools/debug.rs so this file compiles
// in isolation (depends only on the rustre_debug public API + rustre_mcp_server).
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
// SyncFnTool — thin adapter that wraps a sync closure as an async ToolHandler.
// Copied verbatim from tools/debug.rs.
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
// Input parsing helpers for the tracepoint surface
// ---------------------------------------------------------------------------

const SOURCE: &str = "rustre_debug::conditional_breakpoint (TracepointSet/Tracepoint/TracepointFormat)";
const HINT: &str = "computed against a caller-supplied in-memory EvalContext (registers/memory in \
                    the request), not a running process. The live-session variant \
                    (`with_live(session_id, ...)` in tools/debug.rs) that fires tracepoints against a \
                    real stopped thread is the follow-up.";

/// Parse a JSON operand descriptor into a `ConditionOperand`.
/// Accepted shapes:
///   `{"reg": "rax"}` · `{"var": "n"}` · `{"literal": 42}` ·
///   `{"mem": {"addr": 0x..., "width": 4}}`
fn parse_operand(v: &Value) -> AnyhowResult<ConditionOperand> {
    if let Some(r) = v.get("reg").and_then(Value::as_str) {
        return Ok(ConditionOperand::Register(r.to_string()));
    }
    if let Some(name) = v.get("var").and_then(Value::as_str) {
        return Ok(ConditionOperand::Variable(name.to_string()));
    }
    if let Some(lit) = v.get("literal").and_then(coerce_u64) {
        return Ok(ConditionOperand::Literal(lit));
    }
    if let Some(m) = v.get("mem") {
        let addr = m.get("addr").and_then(coerce_u64)
            .ok_or_else(|| anyhow!("operand 'mem' requires integer 'addr'"))?;
        let width = m.get("width").and_then(coerce_u64).unwrap_or(8) as u8;
        return Ok(ConditionOperand::Memory { addr, width });
    }
    Err(anyhow!("unrecognized operand (expected one of reg/var/literal/mem): {v}"))
}

/// Build a `TracepointFormat` from a JSON `format` array whose elements are
/// either `{"text": "..."}` literals or `{"operand": <operand>}` interpolations.
fn parse_format(v: &Value) -> AnyhowResult<TracepointFormat> {
    let arr = v.as_array().ok_or_else(|| anyhow!("'format' must be an array of parts"))?;
    let mut fmt = TracepointFormat::new();
    for part in arr {
        if let Some(text) = part.get("text").and_then(Value::as_str) {
            fmt = fmt.literal(text.to_string());
        } else if let Some(op) = part.get("operand") {
            fmt = fmt.operand(parse_operand(op)?);
        } else {
            return Err(anyhow!("format part must have 'text' or 'operand': {part}"));
        }
    }
    Ok(fmt)
}

/// Build a `MapEvalContext` from an optional `context` object:
///   `{"registers": {"rax": 0xDEAD}, "variables": {"n": 3}, "memory": {"0x1000": [0,1,2,3]}}`
/// Build the eval context and whether it is LIVE. When `args.session_id` names
/// a live session, the register set is the real stopped thread's (overlaying any
/// registers in `context`); otherwise it's purely the caller-supplied `context`.
fn context_for(args: &Value) -> (MapEvalContext, bool) {
    let mut ctx = parse_context(args.get("context"));
    if let Some(live) = args.get("session_id").and_then(Value::as_str)
        .and_then(crate::tools::debug::session_registers)
    {
        for (name, val) in live {
            ctx.set_reg(name, val);
        }
        return (ctx, true);
    }
    (ctx, false)
}

fn parse_context(v: Option<&Value>) -> MapEvalContext {
    let mut ctx = MapEvalContext::new();
    let Some(v) = v else { return ctx };
    if let Some(regs) = v.get("registers").and_then(Value::as_object) {
        for (k, val) in regs {
            if let Some(n) = coerce_u64(val) {
                ctx.set_reg(k.clone(), n);
            }
        }
    }
    if let Some(vars) = v.get("variables").and_then(Value::as_object) {
        for (k, val) in vars {
            if let Some(n) = coerce_u64(val) {
                ctx.set_var(k.clone(), n);
            }
        }
    }
    if let Some(mem) = v.get("memory").and_then(Value::as_object) {
        for (k, val) in mem {
            let Some(addr) = coerce_u64(&Value::String(k.clone())) else { continue };
            if let Some(bytes) = val.as_array() {
                let raw: Vec<u8> = bytes.iter()
                    .filter_map(|b| b.as_u64().map(|n| n as u8))
                    .collect();
                ctx.memory.insert(addr, raw);
            }
        }
    }
    ctx
}

// ---------------------------------------------------------------------------
// handlers_tracepoints() — debug.* tools for the "tracepoints" capability
// ---------------------------------------------------------------------------

pub fn handlers_tracepoints() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    let operand_schema = json!({
        "type": "object",
        "description": "One of: {reg}, {var}, {literal}, {mem:{addr,width}}",
        "properties": {
            "reg":     { "type": "string" },
            "var":     { "type": "string" },
            "literal": { "type": "integer" },
            "mem": {
                "type": "object",
                "properties": {
                    "addr":  { "type": "integer" },
                    "width": { "type": "integer" }
                }
            }
        }
    });

    let context_schema = json!({
        "type": "object",
        "description": "In-memory EvalContext: register/variable values and memory byte arrays.",
        "properties": {
            "registers": { "type": "object" },
            "variables": { "type": "object" },
            "memory":    { "type": "object" }
        }
    });

    vec![
        // ── debug.add_tracepoint ────────────────────────────────────────────
        make_tool(
            "debug.add_tracepoint",
            "Define a non-stopping (dprintf-style) tracepoint against the rustre-debug \
             conditional-breakpoint module and render its message once using a caller-supplied \
             in-memory EvalContext. Self-contained: computes from the provided `context`, not a live \
             process (response carries live:false + hint for the live-session follow-up).",
            json!({
                "type": "object",
                "required": ["addr", "format"],
                "properties": {
                    "addr":    { "type": "integer", "description": "Tracepoint virtual address" },
                    "format": {
                        "type": "array",
                        "description": "Message template parts: {text:\"...\"} or {operand:<operand>}",
                        "items": {
                            "type": "object",
                            "properties": {
                                "text":    { "type": "string" },
                                "operand": operand_schema
                            }
                        }
                    },
                    "conditions": {
                        "type": "array",
                        "description": "Optional AND-conditions: {lhs:<operand>, op:\"==|!=|<|<=|>|>=|&|\\|\", rhs:<operand>}",
                        "items": { "type": "object" }
                    },
                    "context": context_schema
                },
                "additionalProperties": false
            }),
            |args| {
                let addr = req_u64(&args, "addr")?;
                let fmt = parse_format(args.get("format")
                    .ok_or_else(|| anyhow!("missing required field 'format'"))?)?;
                let mut tp = Tracepoint::new(Address::new(addr), fmt);

                // Optional conditions.
                if let Some(conds) = args.get("conditions").and_then(Value::as_array) {
                    for c in conds {
                        let cond = build_condition(c)?;
                        tp.add_condition(cond);
                    }
                }

                let ctx = parse_context(args.get("context"));
                let fired = tp.fire(&ctx).map_err(|e| anyhow!("{e}"))?;

                Ok(json!({
                    "addr": addr,
                    "conditions": tp.conditions.len(),
                    "fired": fired.is_some(),
                    "message": fired.as_ref().map(|e| e.message.clone()),
                    "hit_count": tp.hit_count,
                    "eval_count": tp.eval_count,
                    "live": false,
                    "source": SOURCE,
                    "hint": HINT
                }))
            },
        ),

        // ── debug.tracepoints_fire ──────────────────────────────────────────
        make_tool(
            "debug.tracepoints_fire",
            "Register a set of tracepoints into a rustre-debug TracepointSet and fire every one at a \
             given address against a caller-supplied in-memory EvalContext, returning the log events. \
             Self-contained: computes from the provided `context`, not a live process \
             (response carries live:false + hint for the live-session follow-up).",
            json!({
                "type": "object",
                "required": ["fire_addr", "tracepoints"],
                "properties": {
                    "fire_addr": { "type": "integer", "description": "Address to fire tracepoints at" },
                    "tracepoints": {
                        "type": "array",
                        "description": "Tracepoints to register: each {addr, format, conditions?}",
                        "items": {
                            "type": "object",
                            "properties": {
                                "addr":       { "type": "integer" },
                                "format":     { "type": "array" },
                                "conditions": { "type": "array" }
                            }
                        }
                    },
                    "session_id": { "type": "string", "description": "If given and it names a LIVE session, tracepoint conditions/format evaluate against the real stopped thread's registers (live:true)." },
                    "context": context_schema
                },
                "additionalProperties": false
            }),
            |args| {
                let fire_addr = req_u64(&args, "fire_addr")?;
                let tps = args.get("tracepoints").and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("missing required field 'tracepoints' (array)"))?;

                let mut set = TracepointSet::new();
                for t in tps {
                    let addr = t.get("addr").and_then(coerce_u64)
                        .ok_or_else(|| anyhow!("each tracepoint requires integer 'addr'"))?;
                    let fmt = parse_format(t.get("format")
                        .ok_or_else(|| anyhow!("each tracepoint requires 'format'"))?)?;
                    let mut tp = Tracepoint::new(Address::new(addr), fmt);
                    if let Some(conds) = t.get("conditions").and_then(Value::as_array) {
                        for c in conds {
                            tp.add_condition(build_condition(c)?);
                        }
                    }
                    set.add(tp);
                }

                let (ctx, is_live) = context_for(&args);
                let events = set.fire_at(Address::new(fire_addr), &ctx);
                let json_events: Vec<Value> = events.iter().map(|e| json!({
                    "addr": e.address.as_u64(),
                    "message": e.message,
                    "hit_count": e.hit_count
                })).collect();

                Ok(json!({
                    "fire_addr": fire_addr,
                    "registered": set.len(),
                    "fired_count": json_events.len(),
                    "events": json_events,
                    "live": is_live,
                    "source": if is_live { "rustre_debug::conditional_breakpoint (live session registers)" } else { SOURCE },
                    "hint": if is_live { Value::Null } else { json!(HINT) }
                }))
            },
        ),
    ]
}

/// Build a `BreakpointCondition` from `{lhs, op, rhs}` JSON.
fn build_condition(
    v: &Value,
) -> AnyhowResult<rustre_debug::conditional_breakpoint::BreakpointCondition> {
    use rustre_debug::conditional_breakpoint::{BreakpointCondition, ConditionOperator};
    let lhs = parse_operand(v.get("lhs").ok_or_else(|| anyhow!("condition requires 'lhs'"))?)?;
    let rhs = parse_operand(v.get("rhs").ok_or_else(|| anyhow!("condition requires 'rhs'"))?)?;
    let op = match req_str(v, "op")? {
        "==" => ConditionOperator::Eq,
        "!=" => ConditionOperator::Ne,
        "<"  => ConditionOperator::Lt,
        "<=" => ConditionOperator::Le,
        ">"  => ConditionOperator::Gt,
        ">=" => ConditionOperator::Ge,
        "&"  => ConditionOperator::BitAnd,
        "|"  => ConditionOperator::BitOr,
        other => return Err(anyhow!("unknown condition operator '{other}'")),
    };
    Ok(BreakpointCondition::new(lhs, op, rhs))
}
