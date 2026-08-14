//! MCP wrappers for `rustre_debug::retroactive_print` — Pernosco-style
//! retroactive print over a recorded OmniscientIndex + SnapshotReplayBackend.
//!
//! Tools exposed:
//! - `debug.retroactive_print`        — evaluate expressions at every write to an address
//! - `debug.retroactive_print_list`   — list active annotations in the in-process store
//! - `debug.retroactive_print_remove` — remove an annotation by id

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use std::sync::{Arc, Mutex};

use rustre_core::address::Address;
use rustre_debug::ThreadId;
use rustre_debug::omniscient_query::{OmniscientIndex, MemoryWrite};
use rustre_debug::time_travel_debug::{SnapshotReplayBackend, TtdState, TracePosition};
use rustre_debug::retroactive_print::{
    retro_print, AnnotationId, AnnotationStore, RetroAnnotation,
};

// ─────────────────────────────────────────────────────────────────────────────
// Shared in-process state
// ─────────────────────────────────────────────────────────────────────────────

/// Shared annotation store for the process lifetime.  A real session manager
/// would key this by `session_id`; here we use a global for simplicity — the
/// same pattern the live-invariant and tracepoint tools follow.
static ANNOTATION_STORE: std::sync::OnceLock<Mutex<AnnotationStore>> =
    std::sync::OnceLock::new();

fn annotation_store() -> &'static Mutex<AnnotationStore> {
    ANNOTATION_STORE.get_or_init(|| Mutex::new(AnnotationStore::new()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: coerce JSON field to u64 (decimal or "0x…" hex string)
// ─────────────────────────────────────────────────────────────────────────────

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

fn req_u64(args: &Value, key: &str) -> Result<u64, McpError> {
    args.get(key).and_then(coerce_u64)
        .ok_or_else(|| McpError::InvalidParams(format!("missing required field '{key}' (integer)")))
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper: build a demo OmniscientIndex + SnapshotReplayBackend from JSON args
// ─────────────────────────────────────────────────────────────────────────────

/// Parse an optional `writes` JSON array into `(OmniscientIndex, SnapshotReplayBackend)`.
///
/// Each element must be:
/// ```json
/// {
///   "sequence": 5,
///   "address": "0x1000",
///   "size": 8,
///   "tid": 1,
///   "writer_pc": "0x401000",
///   "regs": { "rax": 42, "rsp": "0x7000" }
/// }
/// ```
///
/// If `writes` is absent or empty, both structures are returned empty (the
/// function still works correctly — the timeline will simply have zero entries).
fn build_index_and_replay(args: &Value) -> (OmniscientIndex, SnapshotReplayBackend) {
    let mut idx = OmniscientIndex::new();
    let mut replay = SnapshotReplayBackend::new();

    if let Some(arr) = args.get("writes").and_then(Value::as_array) {
        for item in arr {
            let seq = item.get("sequence").and_then(coerce_u64).unwrap_or(0);
            let addr_val = item.get("address").map(coerce_u64).flatten().unwrap_or(0);
            let size = item.get("size").and_then(Value::as_u64).unwrap_or(8);
            let tid = item.get("tid").and_then(Value::as_u64).unwrap_or(1) as u32;
            let pc = item.get("writer_pc").and_then(coerce_u64);

            idx.push(MemoryWrite {
                sequence:       seq,
                address:        Address::new(addr_val),
                size,
                tid:            ThreadId(tid),
                writer_pc:      pc.map(Address::new),
                source_address: None,
            });

            // Build a synthetic TtdState from the optional "regs" sub-object.
            let mut st = TtdState::new(TracePosition::new(seq, 0), pc.unwrap_or(0), 0);
            if let Some(regs_obj) = item.get("regs").and_then(Value::as_object) {
                for (k, v) in regs_obj {
                    if let Some(val) = coerce_u64(v) {
                        st.regs.insert(k.clone(), val);
                    }
                }
            }
            replay.record(st);
        }
    }
    (idx, replay)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool 1: debug.retroactive_print
// ─────────────────────────────────────────────────────────────────────────────

pub struct DebugRetroPrintTool;

impl DebugRetroPrintTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug.retroactive_print".into(),
            description: concat!(
                "Pernosco-style retroactive print: evaluate expressions at every write to a \
                 watched address over a recorded trace, without re-running the target. \
                 Supply 'address' (the watched address) and 'args' (a list of register names \
                 or pointer derefs such as 'rax', '*rsp', 'rax+8'). Optionally provide a \
                 'writes' array with historical register state for each write. \
                 Returns [{sequence, writer_pc, rendered}] ordered most-recent-first."
            ).into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "address": {
                        "description": "Memory address to watch for writes (integer or '0x…' hex string).",
                        "oneOf": [{"type": "integer"}, {"type": "string"}]
                    },
                    "format": {
                        "type": "string",
                        "description": "printf-style format string with {0}, {1}, … placeholders. Defaults to '{0}' when args has one element."
                    },
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Expressions to evaluate: register names ('rax'), '$rax', '*rsp', 'rax+8', '*($rsp+0x10)', or integer literals."
                    },
                    "before": {
                        "description": "Only include writes at or before this trace sequence number (omit for all writes).",
                        "oneOf": [{"type": "integer"}, {"type": "string"}]
                    },
                    "writes": {
                        "type": "array",
                        "description": "Optional: historical write events with register snapshots. Each item: {sequence, address, size?, tid?, writer_pc?, regs?}.",
                        "items": {"type": "object"}
                    },
                    "store": {
                        "type": "boolean",
                        "description": "If true, also store this annotation in the in-process annotation store and return its 'annotation_id'."
                    }
                },
                "required": ["address", "args"]
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for DebugRetroPrintTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let address = req_u64(&args, "address")?;

        let raw_args: Vec<String> = args
            .get("args")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
            .unwrap_or_default();

        let format = args
            .get("format")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| {
                if raw_args.len() == 1 { "{0}".into() }
                else { raw_args.iter().enumerate().map(|(i, _)| format!("{{{i}}}")).collect::<Vec<_>>().join(" ") }
            });

        let before = args.get("before").and_then(coerce_u64).unwrap_or(u64::MAX);

        let ann = RetroAnnotation { address, format, args: raw_args };

        // Optionally store the annotation.
        let annotation_id = if args.get("store").and_then(Value::as_bool).unwrap_or(false) {
            let id = annotation_store().lock().unwrap_or_else(|e| e.into_inner()).insert(ann.clone());
            Some(id.0)
        } else {
            None
        };

        let (idx, replay) = build_index_and_replay(&args);
        let entries = retro_print(&idx, &replay, &ann, before);

        let timeline: Vec<Value> = entries.iter().map(|e| json!({
            "sequence":  e.write.sequence,
            "writer_pc": e.writer_pc.map(|p| format!("{p:#x}")),
            "rendered":  e.rendered,
            "arg_values": e.arg_values.iter().map(|v| v.as_display_string()).collect::<Vec<_>>(),
        })).collect();

        let mut out = json!({
            "address": format!("{address:#x}"),
            "count":   timeline.len(),
            "timeline": timeline,
        });
        if let Some(id) = annotation_id {
            out["annotation_id"] = json!(id);
        }
        Ok(ToolResult::text(out.to_string()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool 2: debug.retroactive_print_list
// ─────────────────────────────────────────────────────────────────────────────

pub struct DebugRetroPrintListTool;

impl DebugRetroPrintListTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug.retroactive_print_list".into(),
            description: "List all active retroactive-print annotations stored in this session.".into(),
            input_schema: json!({"type": "object", "properties": {}}),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for DebugRetroPrintListTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let store = annotation_store().lock().unwrap_or_else(|e| e.into_inner());
        let entries: Vec<Value> = store.iter().map(|(id, ann)| json!({
            "id":      id.0,
            "address": format!("{:#x}", ann.address),
            "format":  ann.format,
            "args":    ann.args,
        })).collect();
        Ok(ToolResult::text(json!({"count": entries.len(), "annotations": entries}).to_string()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tool 3: debug.retroactive_print_remove
// ─────────────────────────────────────────────────────────────────────────────

pub struct DebugRetroPrintRemoveTool;

impl DebugRetroPrintRemoveTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug.retroactive_print_remove".into(),
            description: "Remove a retroactive-print annotation by its annotation_id.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "annotation_id": {
                        "type": "integer",
                        "description": "The id returned by debug.retroactive_print when 'store' was true."
                    }
                },
                "required": ["annotation_id"]
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for DebugRetroPrintRemoveTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let raw_id = args.get("annotation_id").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'annotation_id'".into()))?;
        let removed = annotation_store()
            .lock().unwrap_or_else(|e| e.into_inner())
            .remove(AnnotationId(raw_id));
        Ok(ToolResult::text(json!({"annotation_id": raw_id, "removed": removed}).to_string()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Registration
// ─────────────────────────────────────────────────────────────────────────────

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DebugRetroPrintTool::definition(),       Box::new(DebugRetroPrintTool)),
        (DebugRetroPrintListTool::definition(),   Box::new(DebugRetroPrintListTool)),
        (DebugRetroPrintRemoveTool::definition(), Box::new(DebugRetroPrintRemoveTool)),
    ]
}
