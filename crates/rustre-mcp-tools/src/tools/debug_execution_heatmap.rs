//! MCP wrapper for the rustre-debug `execution_heatmap` module.
//!
//! Self-contained: this file cannot reach `debug.rs`'s private `LiveSession`
//! registry, so it computes answers directly from the public
//! `rustre_debug::execution_heatmap` API over inputs supplied in the tool call.
//! Every response carries `"live": false` plus a `"source"` naming the real
//! module and a `"hint"` that a live-session variant (heatmap over an in-flight
//! TTD recording / session log) is the follow-up.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use std::sync::Arc;
use anyhow::{Result as AnyhowResult, anyhow};

use rustre_debug::execution_heatmap::ExecutionHeatmap;
use rustre_debug::time_travel_debug::TracePosition;

// ---------------------------------------------------------------------------
// Helpers (copied verbatim from tools/debug.rs so this file compiles alone)
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

fn opt_u64(args: &Value, key: &str, default: u64) -> u64 {
    args.get(key).and_then(coerce_u64).unwrap_or(default)
}

// ---------------------------------------------------------------------------
// SyncFnTool — thin adapter that wraps a sync closure as an async ToolHandler
// (copied verbatim from tools/debug.rs)
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
// execution-heatmap capability
// ---------------------------------------------------------------------------

const SOURCE: &str = "rustre_debug::execution_heatmap::ExecutionHeatmap";
const HINT: &str = "Stateless heatmap computed from the TTD-position history supplied in this \
    call. The live-session variant (heatmap aggregated over an in-flight TTD recording or \
    SessionLog held in the debug.* LiveSession registry, via \
    ExecutionHeatmap::from_ttd_history / from_session_log) is the follow-up once wired.";

/// Parse the `history` argument into `(TracePosition, pc)` samples.
///
/// Each element is an object `{ "sequence": u64, "offset": u64, "pc": u64|hex }`
/// (`offset` optional, default 0). `pc`/`address` accepts hex or decimal.
fn parse_history(args: &Value) -> AnyhowResult<Vec<(TracePosition, u64)>> {
    let arr = args
        .get("history")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("missing required field 'history' (array of samples)"))?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let sequence = item
            .get("sequence")
            .and_then(coerce_u64)
            .ok_or_else(|| anyhow!("history[{i}]: missing 'sequence' (integer)"))?;
        let offset = item.get("offset").and_then(coerce_u64).unwrap_or(0);
        let pc = item
            .get("pc")
            .or_else(|| item.get("address"))
            .and_then(coerce_u64)
            .ok_or_else(|| anyhow!("history[{i}]: missing 'pc'/'address' (integer)"))?;
        out.push((TracePosition::new(sequence, offset), pc));
    }
    Ok(out)
}

fn hex_pairs(pairs: &[(u64, u64)]) -> Vec<Value> {
    pairs
        .iter()
        .map(|(addr, count)| json!({ "address": format!("0x{addr:x}"), "hits": count }))
        .collect()
}

/// Build the `debug.*` tool set for the "execution-heatmap" capability.
pub fn handlers_execution_heatmap() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![make_tool(
        "debug.execution_heatmap",
        "Build an execution heatmap from a TTD position-history sample: bucket per-address \
         hit counts across a chronological timeline and rank the hottest addresses. Computes \
         directly from the supplied 'history' via rustre_debug::execution_heatmap (live:false).",
        json!({
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "If given and it names a LIVE debug session, the heatmap is built from that session's real TTD navigation history (live:true); 'history' is then optional/ignored."
                },
                "history": {
                    "type": "array",
                    "description": "TTD position-history samples, chronological.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "sequence": { "type": "integer", "description": "TracePosition sequence number." },
                            "offset": { "type": "integer", "description": "Fine instruction offset (default 0)." },
                            "pc": { "description": "Program counter hit at this position (int or hex string)." },
                            "address": { "description": "Alias for 'pc'." }
                        },
                        "required": ["sequence"]
                    }
                },
                "num_buckets": { "type": "integer", "description": "Timeline buckets (default 8)." },
                "top_n": { "type": "integer", "description": "Number of hottest addresses to return (default 10)." }
            }
        }),
        |args| {
            let num_buckets = opt_u64(&args, "num_buckets", 8).max(1) as usize;
            let top_n = opt_u64(&args, "top_n", 10) as usize;
            // Live path: build from the session's real TTD navigation history.
            let live = args.get("session_id").and_then(Value::as_str)
                .and_then(|id| crate::tools::debug::session_ttd_history(id, 4096));
            let (history, is_live) = match live {
                Some(h) => (h, true),
                None => (parse_history(&args)?, false),
            };
            let source = if is_live { "rustre_debug::execution_heatmap::ExecutionHeatmap (live session TTD history)" } else { SOURCE };

            let heatmap = ExecutionHeatmap::from_ttd_history(&history, num_buckets);

            let buckets: Vec<Value> = heatmap
                .buckets
                .iter()
                .map(|b| {
                    json!({
                        "index": b.index,
                        "total_hits": b.total_hits,
                        "top_addresses": hex_pairs(&b.top_addresses(top_n)),
                    })
                })
                .collect();

            let mut out = json!({
                "live": is_live,
                "source": source,
                "samples": history.len(),
                "num_buckets": num_buckets,
                "total_hits": heatmap.total_hits(),
                "hottest": hex_pairs(&heatmap.hottest(top_n)),
                "buckets": buckets,
            });
            if !is_live { out["hint"] = json!(HINT); }
            Ok(out)
        },
    )]
}
