//! MCP wrappers for the rustre-ttd_replay crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes, hex_encode};

pub struct TtdReplayBuildCallGraphTool;

pub struct TtdReplaySplitByThreadTool;

pub struct TtdReplayComputeMemoryAccessStatsTool;

pub struct TtdReplayEngineStepForwardTool;
impl TtdReplayEngineStepForwardTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_engine_step_forward".to_string(),
            description: "Step ReplayEngine forward one event on a synthetic n-event trace via rustre_ttd_replay::ReplayEngine::step_forward.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayEngineStepForwardTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let mut eng = rustre_ttd_replay::ReplayEngine::new(trace);
        let r = eng.step_forward().map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "n": n,
            "stop_reason": r.to_string(),
            "position": eng.current_position().to_string(),
            "source": "rustre_ttd_replay::ReplayEngine::step_forward",
        }).to_string()))
    }
}

pub struct TtdReplayEngineGoToEndTool;
impl TtdReplayEngineGoToEndTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_engine_go_to_end".to_string(),
            description: "Fast-forward ReplayEngine to end of synthetic n-event trace via rustre_ttd_replay::ReplayEngine::go_to_end.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayEngineGoToEndTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let mut eng = rustre_ttd_replay::ReplayEngine::new(trace);
        let r = eng.go_to_end().map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "n": n,
            "stop_reason": r.to_string(),
            "final_position": eng.current_position().to_string(),
            "memory_pages": eng.memory_state().page_count(),
            "source": "rustre_ttd_replay::ReplayEngine::go_to_end",
        }).to_string()))
    }
}

pub struct TtdReplayEngineAddBreakpointTool;
impl TtdReplayEngineAddBreakpointTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_engine_add_breakpoint".to_string(),
            description: "Add a breakpoint to a fresh ReplayEngine via rustre_ttd_replay::ReplayEngine::add_breakpoint.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"address":{"type":"integer"}},"required":["n","address"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayEngineAddBreakpointTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let address = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let mut eng = rustre_ttd_replay::ReplayEngine::new(trace);
        let id = eng.add_breakpoint(address);
        Ok(ToolResult::text(json!({
            "bp_id": id,
            "address": address,
            "breakpoint_count": eng.breakpoints().len(),
            "source": "rustre_ttd_replay::ReplayEngine::add_breakpoint",
        }).to_string()))
    }
}

pub struct TtdReplayEngineFindFirstWriteTool;
impl TtdReplayEngineFindFirstWriteTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_engine_find_first_write".to_string(),
            description: "Locate the first MemWrite to addr via rustre_ttd_replay::ReplayEngine::find_first_write_to.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"addr":{"type":"integer"}},"required":["n","addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayEngineFindFirstWriteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let eng = rustre_ttd_replay::ReplayEngine::new(trace);
        let pos = eng.find_first_write_to(addr);
        Ok(ToolResult::text(json!({
            "addr": addr,
            "position": pos.map(|p| p.to_string()),
            "found": pos.is_some(),
            "source": "rustre_ttd_replay::ReplayEngine::find_first_write_to",
        }).to_string()))
    }
}

pub struct TtdReplayEngineGetMemoryAtTool;
impl TtdReplayEngineGetMemoryAtTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_engine_get_memory_at".to_string(),
            description: "Reconstruct memory at (addr,len) at trace position seq via rustre_ttd_replay::ReplayEngine::get_memory_at.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"seq":{"type":"integer"},"addr":{"type":"integer"},"len":{"type":"integer"}},"required":["n","seq","addr","len"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayEngineGetMemoryAtTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let seq = args.get("seq").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'seq'".into()))?;
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let len = args.get("len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'len'".into()))? as usize;
        let trace = rustre_ttd::build_test_trace(n);
        let eng = rustre_ttd_replay::ReplayEngine::new(trace);
        let mem = eng.get_memory_at(rustre_ttd::TracePosition::new(seq, 0), addr, len);
        Ok(ToolResult::text(json!({
            "addr": addr,
            "len": len,
            "found": mem.is_some(),
            "hex": mem.as_ref().map(|b| hex_encode(b)),
            "source": "rustre_ttd_replay::ReplayEngine::get_memory_at",
        }).to_string()))
    }
}

pub struct TtdReplayMemoryStateApplyWriteTool;
impl TtdReplayMemoryStateApplyWriteTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_memory_state_apply_write".to_string(),
            description: "Apply a write to a fresh MemoryState and read it back via rustre_ttd_replay::MemoryState::apply_write.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"data_hex":{"type":"string"}},"required":["addr","data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayMemoryStateApplyWriteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let data = args_to_bytes(args.get("data_hex").ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?)?;
        let mut mem = rustre_ttd_replay::MemoryState::new();
        mem.apply_write(addr, &data);
        let readback = mem.read(addr, data.len()).unwrap_or_default();
        Ok(ToolResult::text(json!({
            "addr": addr,
            "len": data.len(),
            "page_count": mem.page_count(),
            "readback_hex": hex_encode(&readback),
            "roundtrip_ok": readback == data,
            "source": "rustre_ttd_replay::MemoryState::apply_write",
        }).to_string()))
    }
}

pub struct TtdReplaySnapshotCacheInsertTool;
impl TtdReplaySnapshotCacheInsertTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_snapshot_cache_insert".to_string(),
            description: "Insert a snapshot at seq into a SnapshotCache and query nearest_before via rustre_ttd_replay::SnapshotCache.".to_string(),
            input_schema: json!({"type":"object","properties":{"interval":{"type":"integer"},"seq":{"type":"integer"},"query_seq":{"type":"integer"}},"required":["interval","seq","query_seq"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplaySnapshotCacheInsertTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let interval = args.get("interval").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'interval'".into()))?;
        let seq = args.get("seq").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'seq'".into()))?;
        let query_seq = args.get("query_seq").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'query_seq'".into()))?;
        let pos = rustre_ttd::TracePosition::new(seq, 0);
        let snap = rustre_ttd_replay::Snapshot::new(pos, rustre_ttd_replay::MemoryState::new(), std::collections::HashMap::new());
        let mut cache = rustre_ttd_replay::SnapshotCache::new(interval);
        cache.insert(snap);
        let found = cache.nearest_before(rustre_ttd::TracePosition::new(query_seq, 0));
        Ok(ToolResult::text(json!({
            "count": cache.snapshot_count(),
            "contains_seq": cache.contains(pos),
            "nearest_before_position": found.map(|s| s.position.to_string()),
            "source": "rustre_ttd_replay::SnapshotCache",
        }).to_string()))
    }
}

pub struct TtdReplayWatchpointOverlapsTool;
impl TtdReplayWatchpointOverlapsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_watchpoint_overlaps".to_string(),
            description: "Test whether a Watchpoint at (address,size) overlaps a byte range via rustre_ttd_replay::Watchpoint::overlaps.".to_string(),
            input_schema: json!({"type":"object","properties":{"wp_addr":{"type":"integer"},"wp_size":{"type":"integer"},"acc_addr":{"type":"integer"},"acc_len":{"type":"integer"}},"required":["wp_addr","wp_size","acc_addr","acc_len"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayWatchpointOverlapsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let wp_addr = args.get("wp_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'wp_addr'".into()))?;
        let wp_size = args.get("wp_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'wp_size'".into()))? as usize;
        let acc_addr = args.get("acc_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'acc_addr'".into()))?;
        let acc_len = args.get("acc_len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'acc_len'".into()))? as usize;
        let wp = rustre_ttd_replay::Watchpoint::new(1, wp_addr, wp_size, rustre_ttd_replay::WatchpointKind::ReadWrite);
        Ok(ToolResult::text(json!({
            "overlaps": wp.overlaps(acc_addr, acc_len),
            "wp": wp.to_string(),
            "source": "rustre_ttd_replay::Watchpoint::overlaps",
        }).to_string()))
    }
}

pub struct TtdReplayDeltaCompressorRoundtripTool;
impl TtdReplayDeltaCompressorRoundtripTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_delta_compressor_roundtrip".to_string(),
            description: "Compute and apply a MemoryDelta via rustre_ttd_replay::DeltaCompressor.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"before_hex":{"type":"string"},"after_hex":{"type":"string"}},"required":["addr","before_hex","after_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayDeltaCompressorRoundtripTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let before = args_to_bytes(args.get("before_hex").ok_or_else(|| McpError::InvalidParams("missing 'before_hex'".into()))?)?;
        let after = args_to_bytes(args.get("after_hex").ok_or_else(|| McpError::InvalidParams("missing 'after_hex'".into()))?)?;
        let delta = rustre_ttd_replay::DeltaCompressor::compute_delta(addr, &before, &after);
        let restored = rustre_ttd_replay::DeltaCompressor::apply_delta(&before, &delta);
        let ok = restored.len() >= after.len() && restored[..after.len()] == after[..];
        Ok(ToolResult::text(json!({
            "addr": addr,
            "delta_len": delta.after.len(),
            "restored_hex": hex_encode(&restored),
            "roundtrip_ok": ok,
            "source": "rustre_ttd_replay::DeltaCompressor",
        }).to_string()))
    }
}

pub struct TtdReplayRecordingFileRoundtripTool;
impl TtdReplayRecordingFileRoundtripTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_recording_file_roundtrip".to_string(),
            description: "Serialize a synthetic n-event TtdRecordingFile then read it back via rustre_ttd_replay::TtdRecordingFile.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayRecordingFileRoundtripTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let rec = rustre_ttd_replay::TtdRecordingFile::from_trace(&trace);
        let events_in = rec.events.len();
        let mut buf: Vec<u8> = Vec::new();
        rec.write_to(&mut buf).map_err(|e| McpError::InternalError(e.to_string()))?;
        let bytes_written = buf.len();
        let rec2 = rustre_ttd_replay::TtdRecordingFile::read_from(&mut buf.as_slice()).map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "n": n,
            "events_in": events_in,
            "events_out": rec2.events.len(),
            "bytes_written": bytes_written,
            "roundtrip_ok": rec2.events.len() == events_in,
            "source": "rustre_ttd_replay::TtdRecordingFile",
        }).to_string()))
    }
}

pub struct TtdReplayEngineStateDbBreakpointsTool;
impl TtdReplayEngineStateDbBreakpointsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_engine_state_db_breakpoints".to_string(),
            description: "Round-trip a set of ReplayBreakpoints through an in-memory EngineStateDb via rustre_ttd_replay::EngineStateDb.".to_string(),
            input_schema: json!({"type":"object","properties":{"addresses":{"type":"array","items":{"type":"integer"}}},"required":["addresses"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayEngineStateDbBreakpointsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("addresses").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'addresses'".into()))?;
        let bps: Vec<rustre_ttd_replay::ReplayBreakpoint> = arr.iter().enumerate().filter_map(|(i, v)| {
            v.as_u64().map(|a| rustre_ttd_replay::ReplayBreakpoint::new(i as u32 + 1, a))
        }).collect();
        let db = rustre_ttd_replay::EngineStateDb::open_in_memory().map_err(|e| McpError::InternalError(e.to_string()))?;
        db.save_breakpoints(&bps).map_err(|e| McpError::InternalError(e.to_string()))?;
        let loaded = db.load_breakpoints().map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "saved": bps.len(),
            "loaded": loaded.len(),
            "roundtrip_ok": loaded.len() == bps.len(),
            "source": "rustre_ttd_replay::EngineStateDb",
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TtdReplayBuildCallGraphTool::definition(), Box::new(TtdReplayBuildCallGraphTool)),
        (TtdReplaySplitByThreadTool::definition(), Box::new(TtdReplaySplitByThreadTool)),
        (TtdReplayComputeMemoryAccessStatsTool::definition(), Box::new(TtdReplayComputeMemoryAccessStatsTool)),
        (TtdReplayEngineStepForwardTool::definition(), Box::new(TtdReplayEngineStepForwardTool)),
        (TtdReplayEngineGoToEndTool::definition(), Box::new(TtdReplayEngineGoToEndTool)),
        (TtdReplayEngineAddBreakpointTool::definition(), Box::new(TtdReplayEngineAddBreakpointTool)),
        (TtdReplayEngineFindFirstWriteTool::definition(), Box::new(TtdReplayEngineFindFirstWriteTool)),
        (TtdReplayEngineGetMemoryAtTool::definition(), Box::new(TtdReplayEngineGetMemoryAtTool)),
        (TtdReplayMemoryStateApplyWriteTool::definition(), Box::new(TtdReplayMemoryStateApplyWriteTool)),
        (TtdReplaySnapshotCacheInsertTool::definition(), Box::new(TtdReplaySnapshotCacheInsertTool)),
        (TtdReplayWatchpointOverlapsTool::definition(), Box::new(TtdReplayWatchpointOverlapsTool)),
        (TtdReplayDeltaCompressorRoundtripTool::definition(), Box::new(TtdReplayDeltaCompressorRoundtripTool)),
        (TtdReplayRecordingFileRoundtripTool::definition(), Box::new(TtdReplayRecordingFileRoundtripTool)),
        (TtdReplayEngineStateDbBreakpointsTool::definition(), Box::new(TtdReplayEngineStateDbBreakpointsTool)),
    ]
}
