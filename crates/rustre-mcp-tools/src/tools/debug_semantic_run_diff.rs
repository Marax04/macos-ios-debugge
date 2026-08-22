//! MCP wrappers for `rustre_debug::semantic_run_diff`.
//!
//! Exposes two tools:
//! - `debug.semantic_diff_runs` — compare two write logs and return the
//!   globally-earliest divergence point plus all per-address divergences.
//! - `debug.address_timeline` — side-by-side write history for one address
//!   from two runs.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use std::sync::Arc;
use anyhow::{Result as AnyhowResult, anyhow};

use rustre_core::address::Address;
use rustre_debug::ThreadId;
use rustre_debug::omniscient_query::{MemoryWrite, OmniscientIndex};
use rustre_debug::semantic_run_diff::{address_timeline, diff_runs};

// ---------------------------------------------------------------------------
// Helpers (same pattern as every other debug tool file)
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

fn decode_index(args: &Value, key: &str) -> AnyhowResult<OmniscientIndex> {
    match args.get(key) {
        Some(Value::Array(a)) => {
            let writes = a.iter().map(decode_write).collect::<AnyhowResult<Vec<_>>>()?;
            Ok(OmniscientIndex::from_writes(writes))
        }
        // A missing trace used to decode to an EMPTY index. Both call sites
        // declare `trace_a` and `trace_b` required, so that silently turned
        // "you gave me no traces" into "I compared two empty runs" — and the
        // reply, `divergences: []` with `first_divergence: null`, reads as a
        // finding: *the two runs agree*. There is nothing to compare, so say
        // so rather than answering.
        Some(Value::Null) | None => Err(anyhow!(
            "field '{key}' is required and was not supplied; there is no trace to compare"
        )),
        _ => Err(anyhow!("field '{key}' must be an array of writes")),
    }
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

const WRITE_ITEM_SCHEMA: &str = r#"{"type":"object","properties":{"sequence":{"type":["string","integer"]},"address":{"type":["string","integer"]},"size":{"type":["string","integer"]},"tid":{"type":["string","integer"]},"writer_pc":{"type":["string","integer"]},"source_address":{"type":["string","integer"]}},"required":["sequence","address"]}"#;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Returns the two `debug.*` tools for semantic run diffing.
#[must_use]
pub fn handlers_semantic_run_diff() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    let write_schema: Value = serde_json::from_str(WRITE_ITEM_SCHEMA).unwrap_or(json!({"type":"object"}));

    vec![
        // ── Tool 1: full run diff ───────────────────────────────────────────
        make_tool(
            "debug.semantic_diff_runs",
            "Compare two execution traces (write logs) and find the globally earliest divergence \
             point — the first address+instruction where the two runs differ. \
             Unique capability: no shipping debugger (WinDbg TTD, rr, x64dbg, IDA) compares \
             two traces. Closest prior work is academic Chronon (not publicly available). \
             Returns first_divergence (address, sequence, pc_run_a, pc_run_b), all per-address \
             divergences, addresses only in one run, and totals.",
            json!({
                "type": "object",
                "properties": {
                    "trace_a": {
                        "type": "array",
                        "description": "Write log from the reference (good/baseline) run.",
                        "items": write_schema.clone()
                    },
                    "trace_b": {
                        "type": "array",
                        "description": "Write log from the second run to compare.",
                        "items": write_schema.clone()
                    }
                },
                "required": ["trace_a","trace_b"]
            }),
            |args| {
                let a = decode_index(&args, "trace_a")?;
                let b = decode_index(&args, "trace_b")?;
                let diff = diff_runs(&a, &b);
                Ok(json!({
                    "source": "rustre_debug::semantic_run_diff",
                    "competitor_gap": "No shipping debugger compares two traces. WinDbg/rr/x64dbg/IDA replay one trace at a time.",
                    "first_divergence": diff.first_divergence,
                    "divergences": diff.divergences,
                    "only_in_a": diff.only_in_a,
                    "only_in_b": diff.only_in_b,
                    "total_addresses": diff.total_addresses,
                    "divergence_count": diff.divergences.len(),
                }))
            },
        ),

        // ── Tool 2: address timeline ────────────────────────────────────────
        make_tool(
            "debug.address_timeline",
            "Show a side-by-side timeline of writes to a specific address from two runs. \
             Each row is the Nth write to the address in each run, with a 'diverges' flag \
             marking where writer PCs differ.  Use after debug.semantic_diff_runs to drill \
             into a divergence point.",
            json!({
                "type": "object",
                "properties": {
                    "address": {
                        "type": ["string","integer"],
                        "description": "Memory address to compare (int or 0x hex)."
                    },
                    "trace_a": {
                        "type": "array",
                        "description": "Write log from the reference run.",
                        "items": write_schema.clone()
                    },
                    "trace_b": {
                        "type": "array",
                        "description": "Write log from the second run.",
                        "items": write_schema
                    }
                },
                "required": ["address","trace_a","trace_b"]
            }),
            |args| {
                let addr_raw = args.get("address").and_then(coerce_u64)
                    .ok_or_else(|| anyhow!("'address' is required (int or 0x hex)"))?;
                let addr = Address(addr_raw);
                let a = decode_index(&args, "trace_a")?;
                let b = decode_index(&args, "trace_b")?;
                let timeline = address_timeline(addr, &a, &b);
                Ok(json!({
                    "source": "rustre_debug::semantic_run_diff::address_timeline",
                    "address": addr_raw,
                    "rows": timeline,
                    "diverges_at_ordinal": timeline.iter()
                        .find(|r| r.diverges)
                        .map(|r| r.ordinal),
                }))
            },
        ),
    ]
}
