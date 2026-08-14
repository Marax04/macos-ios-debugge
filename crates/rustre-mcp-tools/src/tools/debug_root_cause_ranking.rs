//! MCP wrappers for the rustre-debug **root-cause-ranking** capability.
//!
//! Self-contained sibling of `tools/debug.rs`: it exposes the public
//! `rustre_debug::root_cause_assistant` API (causal-slice + Bayesian pre-filter)
//! as `debug.*` MCP tools, computing answers directly from the writes supplied in
//! the request. It deliberately does NOT reach `debug.rs`'s private `LiveSession`
//! registry (the omniscient index of a running process), so every response is
//! flagged `"live": false` with a `"source"` naming the real module and a
//! `"hint"` that a live-session variant driving a real recording is the follow-up.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use std::sync::Arc;
use anyhow::{Result as AnyhowResult, anyhow};

use rustre_core::address::Address;
use rustre_debug::ThreadId;
use rustre_debug::omniscient_query::{MemoryWrite, OmniscientIndex};
use rustre_debug::root_cause_assistant::{root_cause, RootCauseReport};

// ---------------------------------------------------------------------------
// Helpers — copied verbatim from tools/debug.rs so this file compiles alone.
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

fn opt_u64(args: &Value, key: &str, default: u64) -> u64 {
    args.get(key).and_then(coerce_u64).unwrap_or(default)
}

// ---------------------------------------------------------------------------
// SyncFnTool adapter + make_tool — copied verbatim from tools/debug.rs.
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
// Local input decoding: build an OmniscientIndex from a JSON array of writes.
// ---------------------------------------------------------------------------

const SOURCE: &str = "rustre_debug::root_cause_assistant (crates/rustre-debug/src/root_cause_assistant.rs)";
const HINT: &str = "Stateless computation over writes supplied in the request. A live-session variant \
that runs root_cause() over the omniscient index of a running process is the follow-up — it \
requires the private LiveSession registry in tools/debug.rs (reached via with_live) and a real \
recording/backend, which this self-contained capability intentionally does not touch.";

/// Decode one `{sequence,address,size,tid?,writer_pc?,source_address?}` object.
fn decode_write(v: &Value) -> AnyhowResult<MemoryWrite> {
    let opt_addr = |key: &str| -> Option<Address> {
        v.get(key).and_then(coerce_u64).map(Address)
    };
    Ok(MemoryWrite {
        sequence: v.get("sequence").and_then(coerce_u64)
            .ok_or_else(|| anyhow!("write missing 'sequence'"))?,
        address: v.get("address").and_then(coerce_u64).map(Address)
            .ok_or_else(|| anyhow!("write missing 'address'"))?,
        size: v.get("size").and_then(coerce_u64).unwrap_or(8),
        tid: ThreadId(v.get("tid").and_then(coerce_u64).unwrap_or(1) as u32),
        writer_pc: opt_addr("writer_pc"),
        source_address: opt_addr("source_address"),
    })
}

/// Decode an array field into an `OmniscientIndex`. Missing/empty ⇒ empty index.
fn decode_index(args: &Value, key: &str) -> AnyhowResult<OmniscientIndex> {
    let arr = match args.get(key) {
        Some(Value::Array(a)) => a,
        Some(Value::Null) | None => return Ok(OmniscientIndex::new()),
        Some(_) => return Err(anyhow!("field '{key}' must be an array of writes")),
    };
    let writes = arr.iter().map(decode_write).collect::<AnyhowResult<Vec<_>>>()?;
    Ok(OmniscientIndex::from_writes(writes))
}

fn report_json(report: &RootCauseReport) -> Value {
    json!({
        "top_suspect": report.top_suspect(),
        "has_clean_origin": report.has_clean_origin(),
        "causal_slice_len": report.causal_slice.len(),
        "suspect_count": report.suspects.len(),
        "causal_slice": report.causal_slice,
        "suspects": report.suspects,
    })
}

// ---------------------------------------------------------------------------
// Public entry point.
// ---------------------------------------------------------------------------

/// `debug.*` tools for the "root-cause-ranking" capability. Self-contained:
/// depends only on the rustre-debug public API + rustre_mcp_server.
pub fn handlers_root_cause_ranking() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![make_tool(
        "debug.root_cause",
        "Rank the instruction PCs most likely responsible for a bad memory value. Runs \
         rustre_debug::root_cause_assistant::root_cause over the memory writes supplied in the \
         request: a backward causal slice (trace_origin) plus a Laplace-smoothed Bayesian \
         pre-filter comparing a bad run against a good baseline. Stateless / offline — computes \
         from provided inputs, not a live process.",
        json!({
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "If given and it names a LIVE debug session, the bad-run index is the session's real recorded write log (live:true); 'bad_writes' is then optional/ignored."
                },
                "bad_address": {
                    "type": ["string", "integer"],
                    "description": "Address of the observed bad value (int or hex string)."
                },
                "bad_time": {
                    "type": ["string", "integer"],
                    "description": "Observation time (sequence) in the bad run; writes at/before it count. Default u64::MAX (all).",
                    "default": null
                },
                "bad_writes": {
                    "type": "array",
                    "description": "Writes from the bad run. Each: {sequence, address, size?, tid?, writer_pc?, source_address?}.",
                    "items": { "type": "object" }
                },
                "good_baseline": {
                    "type": "array",
                    "description": "Writes from a known-good baseline run, same shape as bad_writes. Optional; empty ⇒ no baseline.",
                    "items": { "type": "object" }
                }
            },
            "required": ["bad_address"]
        }),
        |args| {
            let _ = req_str; // kept for parity with debug.rs helper set
            let bad_address = Address(req_u64(&args, "bad_address")?);
            let bad_time = opt_u64(&args, "bad_time", u64::MAX);
            // Live path: the bad-run index is the session's real write log.
            let live = args.get("session_id").and_then(Value::as_str)
                .and_then(crate::tools::debug::session_omniscient_writes);
            let (bad_index, is_live) = match live {
                Some(writes) => (OmniscientIndex::from_writes(writes), true),
                None => (decode_index(&args, "bad_writes")?, false),
            };
            let good_baseline = decode_index(&args, "good_baseline")?;

            let report = root_cause(&bad_index, bad_address, bad_time, &good_baseline);

            let mut out = json!({
                "live": is_live,
                "source": if is_live { "rustre_debug::root_cause_assistant (live session write log)" } else { SOURCE },
                "bad_address": bad_address.as_u64(),
                "bad_time": bad_time,
                "bad_index_len": bad_index.len(),
                "report": report_json(&report),
            });
            if !is_live { out["hint"] = json!(HINT); }
            Ok(out)
        },
    )]
}
