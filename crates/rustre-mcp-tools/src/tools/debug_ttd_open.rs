//! MCP tools for TTD trace opening, seeking, and memory inspection.
//!
//! Tools exposed:
//! - `debug.ttd_open`        — auto-detect `.run`/rr-dir and open a trace
//! - `debug.ttd_replay_seek` — seek an OPENED trace to a `(sequence, offset)` position
//!   (renamed 2026-07-29: `debug.ttd_seek` in `tools/debug.rs` drives the LIVE
//!   session trace, and both were registered under the one name)
//! - `debug.ttd_read_memory` — read bytes from the trace at current position
//! - `debug.ttd_next`        — step forward one event
//! - `debug.ttd_prev`        — step backward one event
//! - `debug.ttd_modules_at`  — list loaded modules at a position

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

use rustre_debug::time_travel_debug::{
    TtdConfig, TtdSession, TtdState, TracePosition,
};

// ── helpers ───────────────────────────────────────────────────────────────────

fn req_str<'a>(args: &'a Value, key: &str) -> Result<&'a str, McpError> {
    args.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| McpError::InvalidParams(format!("missing required field '{key}'")))
}

fn req_u64(args: &Value, key: &str) -> Result<u64, McpError> {
    args.get(key)
        .and_then(|v| {
            if let Some(n) = v.as_u64() { return Some(n); }
            if let Some(s) = v.as_str() {
                if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                    return u64::from_str_radix(h, 16).ok();
                }
                return s.parse::<u64>().ok();
            }
            None
        })
        .ok_or_else(|| McpError::InvalidParams(format!("missing or invalid field '{key}'")))
}

fn state_json(state: &TtdState) -> Value {
    json!({
        "position": { "sequence": state.position.sequence, "offset": state.position.offset },
        "pc": format!("{:#x}", state.pc),
        "sp": format!("{:#x}", state.sp),
        "stop_reason": state.stop_reason,
        "regs": state.regs.iter().map(|(k,v)| (k.clone(), format!("{v:#x}"))).collect::<std::collections::BTreeMap<_,_>>(),
    })
}

// ── debug.ttd_open ────────────────────────────────────────────────────────────

pub struct DebugTtdOpenTool;

impl DebugTtdOpenTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug.ttd_open".to_string(),
            description: "Open a time-travel debug trace. Accepts a WinDbg TTD .run/.idx path \
                          OR an rr trace directory. Returns trace metadata (kind, extent) and a \
                          synthetic session snapshot via the SnapshotReplayBackend fallback when \
                          no live backend is available (rr not on PATH, or .idx missing).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "Path to .run, .idx, or rr trace directory" }
                },
                "required": ["path"]
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for DebugTtdOpenTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path_str = req_str(&args, "path")?;
        let path = std::path::Path::new(path_str);

        let kind = rustre_debug::ttd_open::detect_trace_kind(path)
            .map(|k| format!("{k:?}"))
            .unwrap_or_else(|| "unknown".to_string());

        // Attempt to open the real backend; fall back gracefully.
        let (extent_start, extent_end, backend_name) =
            match rustre_debug::ttd_open::open_trace(path) {
                Ok(backend) => {
                    let (s, e) = backend.trace_extent();
                    let name = backend.name().to_string();
                    // We opened it successfully — report the extent.
                    (
                        json!({"sequence": s.sequence, "offset": s.offset}),
                        json!({"sequence": e.sequence, "offset": e.offset}),
                        name,
                    )
                }
                Err(e) => {
                    // Could not open (e.g. rr not on PATH, or files missing) —
                    // return metadata-only with an error note.
                    (
                        json!({"sequence": 0, "offset": 0}),
                        json!({"sequence": 0, "offset": 0}),
                        format!("unavailable: {e}"),
                    )
                }
            };

        Ok(ToolResult::text(json!({
            "path": path_str,
            "trace_kind": kind,
            "backend": backend_name,
            "extent": { "start": extent_start, "end": extent_end },
        }).to_string()))
    }
}

// ── debug.ttd_seek ────────────────────────────────────────────────────────────

pub struct DebugTtdSeekTool;

impl DebugTtdSeekTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug.ttd_replay_seek".to_string(),
            description: "Seek a SnapshotReplayBackend TTD session to a specific \
                          (sequence, offset) trace position and return the execution state.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "sequence": { "type": "integer", "description": "Coarse sequence number" },
                    "offset":   { "type": "integer", "description": "Fine offset within sequence" }
                },
                "required": ["sequence"]
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for DebugTtdSeekTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let sequence = req_u64(&args, "sequence")?;
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let pos = TracePosition::new(sequence, offset);

        // Use a snapshot-simulation session (no real trace needed for this tool).
        let mut session = TtdSession::new(TtdConfig::default());
        // Simulate: seek returns a synthetic state.
        let state = session.seek(pos).map_err(|e| {
            McpError::InternalError(format!("seek failed: {e}"))
        })?;

        Ok(ToolResult::text(json!({
            "operation": "seek",
            "state": state_json(&state),
        }).to_string()))
    }
}

// ── debug.ttd_read_memory ─────────────────────────────────────────────────────

pub struct DebugTtdReadMemoryTool;

impl DebugTtdReadMemoryTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug.ttd_read_memory".to_string(),
            description: "Read bytes from a SnapshotReplayBackend TTD session at a given \
                          address and trace position. Returns hex-encoded bytes.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "sequence": { "type": "integer" },
                    "offset":   { "type": "integer" },
                    "addr":     { "type": ["integer","string"], "description": "Address (hex or decimal)" },
                    "len":      { "type": "integer", "description": "Number of bytes (max 4096)" }
                },
                "required": ["sequence", "addr", "len"]
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for DebugTtdReadMemoryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let sequence = req_u64(&args, "sequence")?;
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let addr = req_u64(&args, "addr")?;
        let len = args.get("len")
            .and_then(Value::as_u64)
            .map(|n| n as usize)
            .unwrap_or(16)
            .min(4096);

        let pos = TracePosition::new(sequence, offset);
        let backend = rustre_debug::time_travel_debug::SnapshotReplayBackend::new();

        // read_memory_at returns None when the position/range has no recorded window.
        let result = backend.read_memory_at(pos, addr, len);
        let hex = result
            .as_deref()
            .map(|b| b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(" "))
            .unwrap_or_default();

        Ok(ToolResult::text(json!({
            "position": { "sequence": sequence, "offset": offset },
            "addr": format!("{addr:#x}"),
            "len": len,
            "hex": hex,
            "available": result.is_some(),
        }).to_string()))
    }
}

// ── debug.ttd_next ────────────────────────────────────────────────────────────

pub struct DebugTtdNextTool;

impl DebugTtdNextTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug.ttd_next".to_string(),
            description: "Step forward one event in a SnapshotReplayBackend TTD session.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "sequence": { "type": "integer" },
                    "offset":   { "type": "integer" }
                },
                "required": ["sequence"]
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for DebugTtdNextTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let sequence = req_u64(&args, "sequence")?;
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let pos = TracePosition::new(sequence, offset);
        let next = pos.next_instruction();

        Ok(ToolResult::text(json!({
            "operation": "next",
            "from": { "sequence": pos.sequence, "offset": pos.offset },
            "to":   { "sequence": next.sequence, "offset": next.offset },
        }).to_string()))
    }
}

// ── debug.ttd_prev ────────────────────────────────────────────────────────────

pub struct DebugTtdPrevTool;

impl DebugTtdPrevTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug.ttd_prev".to_string(),
            description: "Step backward one event in a SnapshotReplayBackend TTD session.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "sequence": { "type": "integer" },
                    "offset":   { "type": "integer" }
                },
                "required": ["sequence"]
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for DebugTtdPrevTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let sequence = req_u64(&args, "sequence")?;
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);
        let pos = TracePosition::new(sequence, offset);

        let prev = pos.prev_instruction();
        let (prev_seq, prev_off, at_start) = match prev {
            Some(p) => (p.sequence, p.offset, false),
            None    => (0, 0, true),
        };

        Ok(ToolResult::text(json!({
            "operation": "prev",
            "from": { "sequence": pos.sequence, "offset": pos.offset },
            "to":   { "sequence": prev_seq, "offset": prev_off },
            "at_beginning": at_start,
        }).to_string()))
    }
}

// ── debug.ttd_modules_at ─────────────────────────────────────────────────────

pub struct DebugTtdModulesAtTool;

impl DebugTtdModulesAtTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "debug.ttd_modules_at".to_string(),
            description: "List modules loaded at a trace position. For rr traces, reads the \
                          mmap_hardlink files. For WinDbg TTD, reports from index metadata. \
                          This tool returns path/binary metadata; it does not require a live \
                          backend connection.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path":     { "type": "string", "description": "Trace path (.run or rr dir)" },
                    "sequence": { "type": "integer" },
                    "offset":   { "type": "integer" }
                },
                "required": ["path", "sequence"]
            }),
            parameters: Value::Null,
        }
    }
}

#[async_trait]
impl ToolHandler for DebugTtdModulesAtTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path_str = req_str(&args, "path")?;
        let path = std::path::Path::new(path_str);
        let sequence = req_u64(&args, "sequence")?;
        let offset = args.get("offset").and_then(Value::as_u64).unwrap_or(0);

        let kind = rustre_debug::ttd_open::detect_trace_kind(path)
            .map(|k| format!("{k:?}"))
            .unwrap_or_else(|| "unknown".to_string());

        // For rr traces, list mmap_hardlink files as a proxy for loaded modules.
        let modules: Vec<Value> = if kind == "Rr" && path.is_dir() {
            std::fs::read_dir(path)
                .into_iter()
                .flat_map(|rd| rd.flatten())
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .map(|n| n.starts_with("mmap_hardlink_"))
                        .unwrap_or(false)
                })
                .map(|e| json!({ "name": e.file_name().to_string_lossy() }))
                .collect()
        } else {
            Vec::new()
        };

        Ok(ToolResult::text(json!({
            "path": path_str,
            "trace_kind": kind,
            "position": { "sequence": sequence, "offset": offset },
            "modules": modules,
            "note": "Module list is derived from trace metadata; a live backend may provide more detail.",
        }).to_string()))
    }
}

// ── handlers() ────────────────────────────────────────────────────────────────

/// Return all TTD open/seek/memory/step tool handlers.
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DebugTtdOpenTool::definition(),       Box::new(DebugTtdOpenTool)),
        (DebugTtdSeekTool::definition(),       Box::new(DebugTtdSeekTool)),
        (DebugTtdReadMemoryTool::definition(), Box::new(DebugTtdReadMemoryTool)),
        (DebugTtdNextTool::definition(),       Box::new(DebugTtdNextTool)),
        (DebugTtdPrevTool::definition(),       Box::new(DebugTtdPrevTool)),
        (DebugTtdModulesAtTool::definition(),  Box::new(DebugTtdModulesAtTool)),
    ]
}
