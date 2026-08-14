//! MCP wrapper for the "dataflow-dsl-query" capability.
//!
//! Self-contained sibling of `tools/debug.rs`: it exposes the declarative
//! dataflow query DSL (`rustre_debug::dataflow_dsl`) over an
//! `OmniscientIndex` built from the write log the caller supplies in the tool
//! arguments. It deliberately does NOT reach `debug.rs`'s private `LiveSession`
//! registry — that registry is module-private — so every response is marked
//! `"live": false`, names its real backing module in `"source"`, and carries a
//! `"hint"` pointing at the live-session follow-up variant.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use std::sync::Arc;
use anyhow::{Result as AnyhowResult, anyhow};

use rustre_core::address::Address;
use rustre_debug::ThreadId;
use rustre_debug::dataflow_dsl::{self, DslResult};
use rustre_debug::omniscient_query::{MemoryWrite, OmniscientIndex};

// ---------------------------------------------------------------------------
// Helper functions (copied verbatim from tools/debug.rs)
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
// Argument → OmniscientIndex construction
// ---------------------------------------------------------------------------

/// Build a `MemoryWrite` from one `{sequence,address,size,tid,writer_pc,
/// source_address}` JSON object. `writer_pc`/`source_address` are optional and
/// accept hex or decimal; the rest default to 0 when omitted.
fn write_from_json(v: &Value) -> AnyhowResult<MemoryWrite> {
    let obj = v
        .as_object()
        .ok_or_else(|| anyhow!("each entry of 'writes' must be an object"))?;
    let g = |k: &str| obj.get(k).and_then(coerce_u64);
    Ok(MemoryWrite {
        sequence: g("sequence").unwrap_or(0),
        address: Address(
            g("address").ok_or_else(|| anyhow!("write entry missing 'address'"))?,
        ),
        size: g("size").unwrap_or(0),
        tid: ThreadId(g("tid").unwrap_or(0) as u32),
        writer_pc: g("writer_pc").map(Address),
        source_address: g("source_address").map(Address),
    })
}

/// Build an `OmniscientIndex` from the optional `writes` array in the args.
fn index_from_args(args: &Value) -> AnyhowResult<OmniscientIndex> {
    let mut writes = Vec::new();
    if let Some(arr) = args.get("writes") {
        let arr = arr
            .as_array()
            .ok_or_else(|| anyhow!("'writes' must be an array of write objects"))?;
        for entry in arr {
            writes.push(write_from_json(entry)?);
        }
    }
    Ok(OmniscientIndex::from_writes(writes))
}

fn write_to_json(w: &MemoryWrite) -> Value {
    json!({
        "sequence": w.sequence,
        "address": w.address.0,
        "size": w.size,
        "tid": w.tid.0,
        "writer_pc": w.writer_pc.map(|a| a.0),
        "source_address": w.source_address.map(|a| a.0),
    })
}

fn result_to_json(r: &DslResult) -> Value {
    match r {
        DslResult::Origin(hops) => json!({
            "kind": "origin",
            "hops": hops.iter().map(|h| json!({
                "queried_address": h.queried_address.0,
                "write": write_to_json(&h.write),
            })).collect::<Vec<_>>(),
        }),
        DslResult::Writes(writes) => json!({
            "kind": "writes",
            "writes": writes.iter().map(write_to_json).collect::<Vec<_>>(),
        }),
    }
}

const SOURCE: &str = "rustre_debug::dataflow_dsl";
const HINT: &str = "Stateless: this evaluates the DSL against an OmniscientIndex \
built from the 'writes' array in the arguments. A live-session variant \
(query the write log recorded by an in-progress debug.* session) is the \
follow-up — it requires the module-private LiveSession registry in \
tools/debug.rs, which this self-contained tool cannot reach.";

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Return the debug.* tools implementing the "dataflow-dsl-query" capability.
pub fn handlers_dataflow_dsl_query() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![make_tool(
        "debug.dataflow_query",
        "Evaluate a declarative dataflow query (rustre_debug::dataflow_dsl) over an \
omniscient write log. Grammar: `TRACE <addr> BACKWARD [AT <seq>] [UNTIL PC <addr>]` \
walks the writer chain for an address — `AT` traces the chain as of that sequence \
number instead of from the end of the recording, `UNTIL PC` stops once a hop's writer \
PC matches, and the two optional clauses may appear in either order; \
`FIND WRITES TO <addr> BEFORE <seq>` lists writes to an \
address at or before a sequence number. The write log is supplied as the optional \
'writes' array; each entry is {sequence,address,size,tid,writer_pc,source_address}. \
Self-contained/stateless: responses are live:false with a hint about the live-session \
follow-up.",
        json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "DSL query, e.g. 'TRACE 0xdeadbeef BACKWARD', 'TRACE 0xdeadbeef BACKWARD AT 500' (as of sequence 500), or 'FIND WRITES TO 0x2000 BEFORE 100'."
                },
                "session_id": {
                    "type": "string",
                    "description": "If given and it names a LIVE debug session, the query runs against that session's real recorded write log (live:true) and 'writes' is ignored."
                },
                "writes": {
                    "type": "array",
                    "description": "Write log to build the OmniscientIndex from. Each entry: {sequence,address,size,tid,writer_pc,source_address}. address is required; others default to 0/null. Numbers accept hex strings.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "sequence": { "type": ["integer", "string"] },
                            "address": { "type": ["integer", "string"] },
                            "size": { "type": ["integer", "string"] },
                            "tid": { "type": ["integer", "string"] },
                            "writer_pc": { "type": ["integer", "string"] },
                            "source_address": { "type": ["integer", "string"] }
                        },
                        "required": ["address"]
                    }
                }
            },
            "required": ["query"]
        }),
        |args| {
            let query = req_str(&args, "query")?;
            // Live path: run against the session's real recorded write log.
            let live = args.get("session_id").and_then(Value::as_str)
                .and_then(crate::tools::debug::session_omniscient_writes);
            let (index, is_live) = match live {
                Some(writes) => (OmniscientIndex::from_writes(writes), true),
                None => (index_from_args(&args)?, false),
            };
            let source = if is_live { "rustre_debug::dataflow_dsl (live session write log)" } else { SOURCE };

            match dataflow_dsl::run(query, &index) {
                Ok(result) => {
                    let mut out = json!({
                        "live": is_live,
                        "source": source,
                        "query": query,
                        "index_len": index.len(),
                        "result": result_to_json(&result),
                    });
                    if !is_live { out["hint"] = json!(HINT); }
                    Ok(out)
                }
                Err(e) => {
                    let mut out = json!({
                        "live": is_live,
                        "source": source,
                        "query": query,
                        "error": e.to_string(),
                    });
                    if !is_live { out["hint"] = json!(HINT); }
                    Ok(out)
                }
            }
        },
    )]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive the registered tool handler end to end, exactly as an MCP client
    /// would, and return its parsed JSON response.
    async fn call(args: Value) -> Value {
        use rustre_mcp_server::ContentBlock;
        let handlers = handlers_dataflow_dsl_query();
        assert_eq!(handlers.len(), 1);
        let (_, handler) = handlers.into_iter().next().unwrap();
        let res = handler.call(args).await.expect("tool call failed");
        let ContentBlock::Text { text } = &res.content[0] else {
            panic!("expected text content");
        };
        serde_json::from_str(text).expect("tool must return JSON")
    }

    fn writes_arg() -> Value {
        // 0x1000 written at seq 2 (a copy of 0x2000) and again at seq 8.
        json!([
            {"sequence": 0, "address": "0x2000", "size": 4, "writer_pc": "0x401000"},
            {"sequence": 2, "address": "0x1000", "size": 4, "writer_pc": "0x401010",
             "source_address": "0x2000"},
            {"sequence": 8, "address": "0x1000", "size": 4, "writer_pc": "0x401020"}
        ])
    }

    /// The `AT <seq>` clause reaches the engine THROUGH the MCP tool, not just
    /// through the library. The grammar gained `AT` but this tool's
    /// description still advertised only `UNTIL PC`, so a caller reading the
    /// schema — which is how an LLM client learns to build a query — had no
    /// way to know the clause existed.
    #[tokio::test]
    async fn at_clause_works_through_the_mcp_tool() {
        // Without the cutoff, the newest write (seq 8) is the origin.
        let out = call(json!({"query": "TRACE 0x1000 BACKWARD", "writes": writes_arg()})).await;
        assert!(out.get("error").is_none(), "unexpected error: {out}");
        let hops = out["result"]["hops"].as_array().expect("hops array");
        assert_eq!(hops[0]["write"]["sequence"], 8);

        // As of seq 5, the seq-8 write has not happened; the chain starts at
        // seq 2 and follows the copy back to the seq-0 write of 0x2000.
        let out = call(json!({"query": "TRACE 0x1000 BACKWARD AT 5", "writes": writes_arg()})).await;
        assert!(out.get("error").is_none(), "AT must parse, got: {out}");
        let hops = out["result"]["hops"].as_array().expect("hops array");
        assert_eq!(hops[0]["write"]["sequence"], 2);
        assert_eq!(hops.last().unwrap()["write"]["sequence"], 0);
    }

    /// Guard against the description drifting away from the grammar again:
    /// every clause the parser accepts must be named in the text a caller
    /// reads. This is the check whose absence let `AT` go undocumented.
    #[test]
    fn description_documents_every_supported_clause() {
        let (def, _) = handlers_dataflow_dsl_query().into_iter().next().unwrap();
        for clause in ["TRACE", "BACKWARD", "AT <seq>", "UNTIL PC", "FIND WRITES TO", "BEFORE"] {
            assert!(
                def.description.contains(clause),
                "tool description does not mention `{clause}`: {}",
                def.description
            );
        }
    }
}
