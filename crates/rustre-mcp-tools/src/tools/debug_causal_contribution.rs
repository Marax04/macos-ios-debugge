//! MCP wrapper for `rustre_debug::causal_contribution`.
//!
//! Exposes `debug.causal_contribution_rank`: given a bad address/time and a
//! write log, walk the causal slice backward and annotate each write with a
//! numeric contribution score (Wang et al. depth/fan-in/terminal heuristic).

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use std::sync::Arc;
use anyhow::{Result as AnyhowResult, anyhow};

use rustre_core::address::Address;
use rustre_debug::ThreadId;
use rustre_debug::omniscient_query::{MemoryWrite, OmniscientIndex};
use rustre_debug::causal_contribution::rank_causal_contributions;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn coerce_u64(v: &Value) -> Option<u64> {
    if let Some(n) = v.as_u64() { return Some(n); }
    if let Some(f) = v.as_f64()
        && f >= 0.0 && f.fract() == 0.0 { return Some(f as u64); }
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
// Public entry point
// ---------------------------------------------------------------------------

/// Returns the `debug.causal_contribution_rank` tool.
#[must_use]
pub fn handlers_causal_contribution() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![make_tool(
        "debug.causal_contribution_rank",
        "Walk the causal write chain backward from a bad memory address/time and rank each write \
         by its numeric contribution to the bad value. Uses the Wang et al. (PLDI 2019) \
         depth/fan-in/terminal heuristic: depth-0 (closest to symptom) gets weight 1.0; \
         depth-d gets 1/2^d; fan-in divides blame equally; root (terminal) write gets 1.5x bonus. \
         Scores are normalised to sum to 1.0. \
         Unique capability: GDB/WinDbg/rr/IDA show *what* wrote a bad value but none quantify \
         *how much* each write in the chain is responsible.",
        json!({
            "type": "object",
            "properties": {
                "bad_address": {
                    "type": ["string","integer"],
                    "description": "Address of the observed bad value (int or 0x hex)."
                },
                "bad_time": {
                    "type": ["string","integer"],
                    "description": "Observation sequence number ceiling (default: all writes).",
                    "default": null
                },
                "max_depth": {
                    "type": "integer",
                    "description": "Maximum causal-chain depth to walk (default 32).",
                    "default": 32
                },
                "writes": {
                    "type": "array",
                    "description": "Write log from the trace. Each: {sequence,address,size?,tid?,writer_pc?,source_address?}.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "sequence":       { "type": ["string","integer"] },
                            "address":        { "type": ["string","integer"] },
                            "size":           { "type": ["string","integer"] },
                            "tid":            { "type": ["string","integer"] },
                            "writer_pc":      { "type": ["string","integer"] },
                            "source_address": { "type": ["string","integer"] }
                        },
                        "required": ["sequence","address"]
                    }
                }
            },
            "required": ["bad_address","writes"]
        }),
        |args| {
            let bad_address = Address(
                args.get("bad_address").and_then(coerce_u64)
                    .ok_or_else(|| anyhow!("'bad_address' is required"))?
            );
            let bad_time = args.get("bad_time").and_then(coerce_u64).unwrap_or(u64::MAX);
            let max_depth = args.get("max_depth").and_then(|v| v.as_u64()).unwrap_or(32) as usize;

            let writes = args.get("writes")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow!("'writes' must be an array"))?
                .iter()
                .map(decode_write)
                .collect::<AnyhowResult<Vec<_>>>()?;

            let index = OmniscientIndex::from_writes(writes);
            let report = rank_causal_contributions(&index, bad_address, bad_time, max_depth);

            // Also expose live-session path hint.
            let live = args.get("session_id").and_then(Value::as_str)
                .and_then(crate::tools::debug::session_omniscient_writes);
            let (report, is_live) = if let Some(live_writes) = live {
                let live_idx = OmniscientIndex::from_writes(live_writes);
                (rank_causal_contributions(&live_idx, bad_address, bad_time, max_depth), true)
            } else {
                (report, false)
            };

            Ok(json!({
                "source": "rustre_debug::causal_contribution",
                "live": is_live,
                "competitor_gap": "GDB/WinDbg TTD/rr/IDA show who wrote a bad value but none quantify contribution score per write.",
                "bad_address": bad_address.as_u64(),
                "bad_time": bad_time,
                "chain_length": report.chain_length,
                "chain_complete": report.chain_complete,
                "ranked": report.ranked,
                "top_contributor": report.ranked.first(),
            }))
        },
    )]
}
