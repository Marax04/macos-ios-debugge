//! MCP wrappers for `rustre_debug::live_invariant`.
//!
//! Exposes two tools:
//! - `debug.invariant_check` — check a set of invariant specs against a write
//!   log supplied in the request (offline / replay mode).
//! - `debug.invariant_check_write` — check a single write + value against a
//!   set of invariant specs (real-time watchpoint callback mode).

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use std::sync::Arc;
use anyhow::{Result as AnyhowResult, anyhow};

use rustre_core::address::Address;
use rustre_debug::ThreadId;
use rustre_debug::omniscient_query::{MemoryWrite, OmniscientIndex};
use rustre_debug::live_invariant::{InvariantEngine, InvariantOp, InvariantSpec};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn coerce_u64(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() { return Some(n); }
    if let Some(f) = v.as_f64() {
        if f >= 0.0 && f.fract() == 0.0 { return Some(f as u64); }
    }
    let s = v.as_str()?.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok();
    }
    s.parse::<u64>().ok()
}

fn req_u64(args: &Value, key: &str) -> AnyhowResult<u64> {
    args.get(key).and_then(coerce_u64)
        .ok_or_else(|| anyhow!("missing required field '{key}' (integer)"))
}

type SyncFn = Arc<dyn Fn(Value) -> AnyhowResult<Value> + Send + Sync>;
struct SyncFnTool { f: SyncFn }

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
    (def, Box::new(SyncFnTool { f: Arc::new(f) }))
}

// ---------------------------------------------------------------------------
// Decoders
// ---------------------------------------------------------------------------

fn decode_op(s: &str) -> AnyhowResult<InvariantOp> {
    match s {
        "eq"         => Ok(InvariantOp::Eq),
        "ne"         => Ok(InvariantOp::Ne),
        "lt"         => Ok(InvariantOp::Lt),
        "le"         => Ok(InvariantOp::Le),
        "gt"         => Ok(InvariantOp::Gt),
        "ge"         => Ok(InvariantOp::Ge),
        "bits_clear" => Ok(InvariantOp::BitsClear),
        "bits_set"   => Ok(InvariantOp::BitsSet),
        "non_zero"   => Ok(InvariantOp::NonZero),
        "is_zero"    => Ok(InvariantOp::IsZero),
        other => Err(anyhow!("unknown op '{other}'; valid: eq ne lt le gt ge bits_clear bits_set non_zero is_zero")),
    }
}

fn decode_spec(v: &Value) -> AnyhowResult<InvariantSpec> {
    let op_str = v.get("op").and_then(Value::as_str)
        .ok_or_else(|| anyhow!("spec missing 'op'"))?;
    Ok(InvariantSpec {
        name: v.get("name").and_then(Value::as_str).unwrap_or("unnamed").to_string(),
        address: Address(v.get("address").and_then(coerce_u64)
            .ok_or_else(|| anyhow!("spec missing 'address'"))?),
        op: decode_op(op_str)?,
        rhs: v.get("rhs").and_then(coerce_u64).unwrap_or(0),
    })
}

fn decode_write(v: &Value) -> AnyhowResult<MemoryWrite> {
    Ok(MemoryWrite {
        sequence:       v.get("sequence").and_then(coerce_u64).ok_or_else(|| anyhow!("write missing 'sequence'"))?,
        address: Address(v.get("address").and_then(coerce_u64).ok_or_else(|| anyhow!("write missing 'address'"))?),
        size:           v.get("size").and_then(coerce_u64).unwrap_or(8),
        tid:   ThreadId(v.get("tid").and_then(coerce_u64).unwrap_or(1) as u32),
        writer_pc:      v.get("writer_pc").and_then(coerce_u64).map(Address),
        source_address: v.get("source_address").and_then(coerce_u64).map(Address),
    })
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Returns the two `debug.*` tools for live invariant tracking.
#[must_use]
pub fn handlers_live_invariant() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        // ── Tool 1: offline check against a write log ───────────────────────
        make_tool(
            "debug.invariant_check",
            "Check a set of memory invariants against a recorded write log. \
             Unique capability: no shipping debugger (WinDbg TTD, GDB, rr, x64dbg, IDA) \
             combines watchpoints with expression predicates and scans the full recorded history. \
             Predicate operators: eq ne lt le gt ge bits_clear bits_set non_zero is_zero. \
             Returns every violation event, earliest first, plus a per-invariant summary.",
            json!({
                "type": "object",
                "properties": {
                    "invariants": {
                        "type": "array",
                        "description": "Array of invariant specs. Each: {name?, address, op, rhs?}.",
                        "items": {
                            "type": "object",
                            "properties": {
                                "name":    { "type": "string" },
                                "address": { "type": ["string","integer"], "description": "Memory address (int or 0x hex)." },
                                "op":      { "type": "string", "description": "eq|ne|lt|le|gt|ge|bits_clear|bits_set|non_zero|is_zero" },
                                "rhs":     { "type": ["string","integer"], "description": "Right-hand side (ignored for non_zero/is_zero).", "default": 0 }
                            },
                            "required": ["address","op"]
                        }
                    },
                    "writes": {
                        "type": "array",
                        "description": "Write log from the recorded trace. Each: {sequence,address,size?,tid?,writer_pc?,source_address?}.",
                        "items": { "type": "object" }
                    }
                },
                "required": ["invariants","writes"]
            }),
            |args| {
                let specs = args.get("invariants")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("'invariants' must be an array"))?
                    .iter()
                    .map(decode_spec)
                    .collect::<AnyhowResult<Vec<_>>>()?;

                let writes = args.get("writes")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("'writes' must be an array"))?
                    .iter()
                    .map(decode_write)
                    .collect::<AnyhowResult<Vec<_>>>()?;

                let index = OmniscientIndex::from_writes(writes);
                let engine = InvariantEngine::new(specs);
                // The write log carries no VALUES, so nothing here can be
                // evaluated. The engine used to invent one (the writing pc, or
                // the width of the write) and report violations about it; it
                // now says how many writes it could not check, and this tool
                // passes that on instead of publishing an empty list as a
                // clean bill of health.
                let report = engine.check_against(&index);
                let summary = InvariantEngine::summarize(&report.violations);

                Ok(json!({
                    "source": "rustre_debug::live_invariant",
                    "total_violations": report.violations.len(),
                    "violations": report.violations,
                    "checked_writes": report.checked_writes,
                    "unchecked_writes": report.unchecked_writes,
                    "conclusive": report.is_conclusive(),
                    "note": "this write log carries no stored values, so no invariant could be evaluated; use debug.invariant_check_write with the observed value",
                    "summary": summary,
                    "competitor_gap": "WinDbg/GDB/rr/x64dbg/IDA fire on any write; none evaluate expression predicates over recorded history."
                }))
            },
        ),

        // ── Tool 2: real-time single-write check ────────────────────────────
        make_tool(
            "debug.invariant_check_write",
            "Check a single memory write (+ its observed value) against a set of invariant specs. \
             Intended for real-time use: call from a watchpoint callback to detect the exact moment \
             an invariant breaks during live debugging.  Complement to debug.invariant_check \
             (which scans the full recorded history offline).",
            json!({
                "type": "object",
                "properties": {
                    "invariants": {
                        "type": "array",
                        "description": "Array of invariant specs (same shape as debug.invariant_check).",
                        "items": { "type": "object" }
                    },
                    "write": {
                        "type": "object",
                        "description": "The write event: {sequence,address,size?,tid?,writer_pc?,source_address?}."
                    },
                    "value": {
                        "type": ["string","integer"],
                        "description": "The actual value written (u64 int or 0x hex string)."
                    }
                },
                "required": ["invariants","write","value"]
            }),
            |args| {
                let specs = args.get("invariants")
                    .and_then(Value::as_array)
                    .ok_or_else(|| anyhow!("'invariants' must be an array"))?
                    .iter()
                    .map(decode_spec)
                    .collect::<AnyhowResult<Vec<_>>>()?;

                let write_v = args.get("write")
                    .ok_or_else(|| anyhow!("'write' is required"))?;
                let write = decode_write(write_v)?;
                let value = req_u64(&args, "value")?;

                let engine = InvariantEngine::new(specs);
                let violations = engine.check_write(&write, value);

                Ok(json!({
                    "source": "rustre_debug::live_invariant",
                    "violated": !violations.is_empty(),
                    "violations": violations,
                }))
            },
        ),
    ]
}
