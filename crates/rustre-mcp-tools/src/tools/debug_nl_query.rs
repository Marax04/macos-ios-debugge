//! MCP wrappers for the natural-language debug query front-end.
//!
//! Exposes three tools:
//! - `debug.nl_query`       — translate + execute a free-form question
//! - `debug.nl_translate`   — translate only (preview the DSL without running it)
//! - `debug.nl_capabilities` — list the supported NL patterns

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use std::sync::Arc;
use anyhow::{Result as AnyhowResult, anyhow};

use rustre_debug::nl_query::{
    self, NlQuery, NlQueryResult, RULE_BASED_PATTERNS,
};
use rustre_debug::omniscient_query::{MemoryWrite, OmniscientIndex};
use rustre_core::address::Address;
use rustre_debug::ThreadId;

// ---------------------------------------------------------------------------
// SyncFnTool boilerplate (identical to every other debug_*.rs module)
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
    (def, Box::new(SyncFnTool { f: Arc::new(f) }))
}

// ---------------------------------------------------------------------------
// Helpers — build an OmniscientIndex from optional caller-supplied writes
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

fn write_from_json(v: &Value) -> AnyhowResult<MemoryWrite> {
    let obj = v.as_object().ok_or_else(|| anyhow!("write entry must be an object"))?;
    let g = |k: &str| obj.get(k).and_then(coerce_u64);
    Ok(MemoryWrite {
        sequence:       g("sequence").unwrap_or(0),
        address:        Address(g("address").ok_or_else(|| anyhow!("write entry missing 'address'"))?),
        size:           g("size").unwrap_or(0),
        tid:            ThreadId(g("tid").unwrap_or(0) as u32),
        writer_pc:      g("writer_pc").map(Address),
        source_address: g("source_address").map(Address),
    })
}

fn index_from_args(args: &Value) -> AnyhowResult<OmniscientIndex> {
    let mut writes = Vec::new();
    if let Some(arr) = args.get("writes").and_then(Value::as_array) {
        for entry in arr {
            writes.push(write_from_json(entry)?);
        }
    }
    Ok(OmniscientIndex::from_writes(writes))
}

// ---------------------------------------------------------------------------
// Result serialisation
// ---------------------------------------------------------------------------

fn result_to_json(r: &NlQueryResult) -> Value {
    match r {
        NlQueryResult::Writes { address, writes, explanation } => json!({
            "kind": "writes",
            "address": address,
            "count": writes.len(),
            "writes": writes.iter().map(|w| json!({
                "sequence": w.sequence,
                "address": w.address.0,
                "size": w.size,
                "tid": w.tid.0,
                "writer_pc": w.writer_pc.map(|a| a.0),
                "source_address": w.source_address.map(|a| a.0),
            })).collect::<Vec<_>>(),
            "explanation": explanation,
        }),
        NlQueryResult::CausalChain { address, hops, explanation } => json!({
            "kind": "causal_chain",
            "address": address,
            "hop_count": hops.len(),
            "hops": hops.iter().map(|h| json!({
                "queried_address": h.queried_address.0,
                "write": {
                    "sequence": h.write.sequence,
                    "address": h.write.address.0,
                    "writer_pc": h.write.writer_pc.map(|a| a.0),
                },
            })).collect::<Vec<_>>(),
            "explanation": explanation,
        }),
        NlQueryResult::InvariantViolations { address, predicate, violations, explanation } => json!({
            "kind": "invariant_violations",
            "address": address,
            "predicate": predicate,
            "candidate_count": violations.len(),
            "candidates": violations.iter().map(|(seq, _)| json!({ "sequence": seq })).collect::<Vec<_>>(),
            "explanation": explanation,
        }),
        NlQueryResult::DslResult { query, result, explanation } => json!({
            "kind": "dsl_result",
            "query": query,
            "result": result,
            "explanation": explanation,
        }),
        NlQueryResult::Heatmap { heatmap, explanation } => json!({
            "kind": "heatmap",
            "heatmap": format!("{heatmap:?}"),
            "explanation": explanation,
        }),
        NlQueryResult::Text { explanation } => json!({
            "kind": "text",
            "explanation": explanation,
        }),
    }
}

fn query_to_json(q: &NlQuery) -> Value {
    match q {
        NlQuery::WhoWrote { address, at_time } => json!({
            "type": "WhoWrote", "address": format!("{address:#x}"), "at_time": at_time
        }),
        NlQuery::CausalRank { address, at_time, hops } => json!({
            "type": "CausalRank", "address": format!("{address:#x}"), "at_time": at_time, "hops": hops
        }),
        NlQuery::InvariantCheck { address, at_time, predicate } => json!({
            "type": "InvariantCheck", "address": format!("{address:#x}"),
            "at_time": at_time, "predicate": predicate
        }),
        NlQuery::SemanticDiff { run_a, run_b } => json!({
            "type": "SemanticDiff", "run_a": run_a, "run_b": run_b
        }),
        NlQuery::ExecutionHeatmap { top_n } => json!({
            "type": "ExecutionHeatmap", "top_n": top_n
        }),
        NlQuery::InstructionSearch { pattern } => json!({
            "type": "InstructionSearch", "pattern": pattern
        }),
        NlQuery::CallGraph { address } => json!({
            "type": "CallGraph", "address": format!("{address:#x}")
        }),
        NlQuery::DslPassthrough { query } => json!({
            "type": "DslPassthrough", "query": query
        }),
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Returns MCP tool handlers for the natural-language debug query front-end.
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    let writes_schema = json!({
        "type": "array",
        "description": "Optional write log (OmniscientIndex seed). Each entry: {sequence,address,size,tid,writer_pc,source_address}. Numbers accept hex strings.",
        "items": {
            "type": "object",
            "properties": {
                "sequence":       { "type": ["integer","string"] },
                "address":        { "type": ["integer","string"] },
                "size":           { "type": ["integer","string"] },
                "tid":            { "type": ["integer","string"] },
                "writer_pc":      { "type": ["integer","string"] },
                "source_address": { "type": ["integer","string"] }
            },
            "required": ["address"]
        }
    });

    vec![
        // ── debug.nl_query ──────────────────────────────────────────────────
        make_tool(
            "debug.nl_query",
            "Translate a free-form debugging question into a typed debug query and execute it \
             against an OmniscientIndex (supplied as an optional 'writes' array). \
             The rule-based translator handles ~10 common NL patterns (who wrote / when did / \
             trace origin / diff / heatmap / find instruction / call chain). \
             If ANTHROPIC_API_KEY is set and the nl-query-llm feature is compiled in, unmatched \
             questions are forwarded to the Anthropic API. \
             Returns {dsl, result, explanation}.",
            json!({
                "type": "object",
                "properties": {
                    "question": {
                        "type": "string",
                        "description": "Free-form debugging question, e.g. 'who wrote to 0x1234?' or 'when did rax become negative?'"
                    },
                    "session_id": {
                        "type": "string",
                        "description": "Live debug session ID. If given, uses the session's recorded write log instead of 'writes'."
                    },
                    "writes": writes_schema.clone()
                },
                "required": ["question"]
            }),
            |args| {
                let question = args["question"].as_str()
                    .ok_or_else(|| anyhow!("missing required field 'question'"))?;

                // Build the index: prefer a live session's write log when session_id is given.
                let index = match args.get("session_id").and_then(Value::as_str)
                    .and_then(crate::tools::debug::session_omniscient_writes)
                {
                    Some(writes) => OmniscientIndex::from_writes(writes),
                    None         => index_from_args(&args)?,
                };

                let query = nl_query::translate(question)
                    .map_err(|e| anyhow!("translation failed: {e}"))?;
                let result = nl_query::execute(&query, &index);

                Ok(json!({
                    "question": question,
                    "dsl": query_to_json(&query),
                    "result": result_to_json(&result),
                }))
            },
        ),

        // ── debug.nl_translate ──────────────────────────────────────────────
        make_tool(
            "debug.nl_translate",
            "Translate a free-form debugging question into a typed debug query \
             without executing it. Returns {dsl} for preview/inspection before running.",
            json!({
                "type": "object",
                "properties": {
                    "question": {
                        "type": "string",
                        "description": "Free-form debugging question to translate."
                    }
                },
                "required": ["question"]
            }),
            |args| {
                let question = args["question"].as_str()
                    .ok_or_else(|| anyhow!("missing required field 'question'"))?;
                let query = nl_query::translate(question)
                    .map_err(|e| anyhow!("translation failed: {e}"))?;
                Ok(json!({
                    "question": question,
                    "dsl": query_to_json(&query),
                }))
            },
        ),

        // ── debug.nl_capabilities ───────────────────────────────────────────
        make_tool(
            "debug.nl_capabilities",
            "List the natural-language query patterns the rule-based translator handles, \
             and whether the LLM-assisted path is available (ANTHROPIC_API_KEY set).",
            json!({
                "type": "object",
                "properties": {
                    "session_id": {
                        "type": "string",
                        "description": "Optional — currently unused; reserved for future per-session capability flags."
                    }
                }
            }),
            |_args| {
                let llm_available = std::env::var("ANTHROPIC_API_KEY").is_ok();
                let patterns: Vec<Value> = RULE_BASED_PATTERNS
                    .iter()
                    .map(|(pattern, description)| json!({ "pattern": pattern, "description": description }))
                    .collect();
                Ok(json!({
                    "rule_based_patterns": patterns,
                    "llm_assisted": llm_available,
                    "llm_model": if llm_available { "claude-opus-4-5 (via ANTHROPIC_API_KEY)" } else { "not available — set ANTHROPIC_API_KEY" },
                    "source": "rustre_debug::nl_query",
                }))
            },
        ),
    ]
}
