//! Extra wire tools wrapping `rustre-ttd-replay` primitives.

use async_trait::async_trait;
use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Decode a caller-supplied hex payload, refusing what is not hex.
///
/// This returned a bare `Vec<u8>` built with `filter_map(...ok())`, so an odd
/// length, an invalid digit or an embedded space silently produced SHORTER —
/// and therefore different — data, which these tools then wrote into a
/// `MemoryState` and read back as if it were the caller's. Delegates to the
/// crate-canonical decoder, which reports the problem instead.
fn hex_decode(hex: &str) -> Result<Vec<u8>, McpError> {
    crate::hex_decode(hex)
}

pub struct TtdReplayMemStateApplyReadTool;
impl TtdReplayMemStateApplyReadTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_memstate_apply_read".to_string(),
            description: "Apply a write of hex bytes to a fresh MemoryState at addr and read them back via rustre_ttd_replay::MemoryState.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"data_hex":{"type":"string"}},"required":["addr","data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayMemStateApplyReadTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let data = hex_decode(hex)?;
        let mut m = rustre_ttd_replay::MemoryState::new();
        m.apply_write(addr, &data);
        let readback = m.read(addr, data.len()).unwrap_or_default();
        Ok(ToolResult::text(json!({"addr":addr,"len":data.len(),"page_count":m.page_count(),"readback_hex":hex_encode(&readback),"source":"rustre_ttd_replay::MemoryState"}).to_string()))
    }
}

pub struct TtdReplayMemStateDiffTool;
impl TtdReplayMemStateDiffTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_memstate_diff".to_string(),
            description: "Compute page-level diffs between two MemoryStates via rustre_ttd_replay::MemoryState::diff.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr_a":{"type":"integer"},"data_a_hex":{"type":"string"},"addr_b":{"type":"integer"},"data_b_hex":{"type":"string"}},"required":["addr_a","data_a_hex","addr_b","data_b_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayMemStateDiffTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr_a = args.get("addr_a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr_a'".into()))?;
        let addr_b = args.get("addr_b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr_b'".into()))?;
        let da = hex_decode(args.get("data_a_hex").and_then(Value::as_str).unwrap_or(""))?;
        let db = hex_decode(args.get("data_b_hex").and_then(Value::as_str).unwrap_or(""))?;
        let mut a = rustre_ttd_replay::MemoryState::new();
        let mut b = rustre_ttd_replay::MemoryState::new();
        a.apply_write(addr_a, &da);
        b.apply_write(addr_b, &db);
        let diffs = a.diff(&b);
        Ok(ToolResult::text(json!({"diff_count":diffs.len(),"pages_a":a.page_count(),"pages_b":b.page_count(),"source":"rustre_ttd_replay::MemoryState::diff"}).to_string()))
    }
}

pub struct TtdReplayWatchpointOverlapsTool;
impl TtdReplayWatchpointOverlapsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_watchpoint_overlaps_terse".to_string(),
            description: "Test whether a Watchpoint at (addr,size) overlaps a byte range via rustre_ttd_replay::Watchpoint::overlaps. Returns only the boolean; `ttd_replay_watchpoint_overlaps` returns the same answer plus the formatted watchpoint.".to_string(),
            input_schema: json!({"type":"object","properties":{"wp_addr":{"type":"integer"},"wp_size":{"type":"integer"},"acc_addr":{"type":"integer"},"acc_len":{"type":"integer"}},"required":["wp_addr","wp_size","acc_addr","acc_len"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayWatchpointOverlapsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let wa = args.get("wp_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'wp_addr'".into()))?;
        let ws = args.get("wp_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'wp_size'".into()))? as usize;
        let aa = args.get("acc_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'acc_addr'".into()))?;
        let al = args.get("acc_len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'acc_len'".into()))? as usize;
        let wp = rustre_ttd_replay::Watchpoint::new(1, wa, ws, rustre_ttd_replay::WatchpointKind::ReadWrite);
        Ok(ToolResult::text(json!({"overlaps":wp.overlaps(aa,al),"source":"rustre_ttd_replay::Watchpoint::overlaps"}).to_string()))
    }
}

pub struct TtdReplayWatchpointSetMatchesTool;
impl TtdReplayWatchpointSetMatchesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_watchpointset_matches".to_string(),
            description: "Add a watchpoint and query whether an access range matches via rustre_ttd_replay::WatchpointSet.".to_string(),
            input_schema: json!({"type":"object","properties":{"wp_addr":{"type":"integer"},"wp_size":{"type":"integer"},"acc_addr":{"type":"integer"},"acc_size":{"type":"integer"}},"required":["wp_addr","wp_size","acc_addr","acc_size"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayWatchpointSetMatchesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let wa = args.get("wp_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'wp_addr'".into()))?;
        let ws = args.get("wp_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'wp_size'".into()))? as usize;
        let aa = args.get("acc_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'acc_addr'".into()))?;
        let al = args.get("acc_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'acc_size'".into()))? as usize;
        let mut ws_set = rustre_ttd_replay::WatchpointSet::new();
        ws_set.add(wa, ws);
        let m = ws_set.matches(aa, al);
        let removed = ws_set.remove(wa);
        Ok(ToolResult::text(json!({"matches":m,"removed":removed,"count":ws_set.watchpoints.len(),"source":"rustre_ttd_replay::WatchpointSet"}).to_string()))
    }
}

pub struct TtdReplayDeltaCompressorTool;
impl TtdReplayDeltaCompressorTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_delta_compressor".to_string(),
            description: "Compute and re-apply a memory delta via rustre_ttd_replay::DeltaCompressor.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"before_hex":{"type":"string"},"after_hex":{"type":"string"}},"required":["addr","before_hex","after_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayDeltaCompressorTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let before = hex_decode(args.get("before_hex").and_then(Value::as_str).unwrap_or(""))?;
        let after = hex_decode(args.get("after_hex").and_then(Value::as_str).unwrap_or(""))?;
        let delta = rustre_ttd_replay::DeltaCompressor::compute_delta(addr, &before, &after);
        let applied = rustre_ttd_replay::DeltaCompressor::apply_delta(&before, &delta);
        Ok(ToolResult::text(json!({"delta_addr":delta.address,"before_len":delta.before.len(),"after_len":delta.after.len(),"applied_hex":hex_encode(&applied),"source":"rustre_ttd_replay::DeltaCompressor"}).to_string()))
    }
}

pub struct TtdReplayBreakpointFiresTool;
impl TtdReplayBreakpointFiresTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_breakpoint_fires".to_string(),
            description: "Test whether an unconditional ReplayBreakpoint fires when rip==addr via rustre_ttd_replay::ReplayBreakpoint::fires.".to_string(),
            input_schema: json!({"type":"object","properties":{"bp_addr":{"type":"integer"},"rip":{"type":"integer"}},"required":["bp_addr","rip"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayBreakpointFiresTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let bpa = args.get("bp_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bp_addr'".into()))?;
        let rip = args.get("rip").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rip'".into()))?;
        let bp = rustre_ttd_replay::ReplayBreakpoint::new(1, bpa);
        let fires = bp.fires(rip, &std::collections::HashMap::new(), &rustre_ttd_replay::MemoryState::new());
        Ok(ToolResult::text(json!({"fires":fires,"bp_addr":bpa,"rip":rip,"source":"rustre_ttd_replay::ReplayBreakpoint::fires"}).to_string()))
    }
}

pub struct TtdReplayEngineNavigateTool;
impl TtdReplayEngineNavigateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_engine_navigate".to_string(),
            description: "Build a synthetic TTD trace, drive ReplayEngine to end via go_to_end, then rewind via go_to_start.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayEngineNavigateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let mut eng = rustre_ttd_replay::ReplayEngine::new(trace);
        let _ = eng.go_to_end().map_err(|e| McpError::InternalError(e.to_string()))?;
        let end_pos = eng.current_position();
        let _ = eng.go_to_start().map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({"n":n,"end_pos":end_pos.to_string(),"start_pos":eng.current_position().to_string(),"source":"rustre_ttd_replay::ReplayEngine"}).to_string()))
    }
}

pub struct TtdReplayEngineStepForwardTool;
impl TtdReplayEngineStepForwardTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_engine_step_forward_terse".to_string(),
            description: "Step ReplayEngine one event forward via rustre_ttd_replay::ReplayEngine::step_forward. Returns the compact {stop,pos} payload; `ttd_replay_engine_step_forward` returns {n,stop_reason,position}.".to_string(),
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
        let reason = eng.step_forward().map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({"stop":reason.to_string(),"pos":eng.current_position().to_string(),"source":"rustre_ttd_replay::ReplayEngine::step_forward"}).to_string()))
    }
}

pub struct TtdReplayEngineBreakpointsTool;
impl TtdReplayEngineBreakpointsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_engine_breakpoints".to_string(),
            description: "Add, disable, enable, remove a breakpoint in ReplayEngine via rustre_ttd_replay::ReplayEngine.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"addr":{"type":"integer"}},"required":["n","addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayEngineBreakpointsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let mut eng = rustre_ttd_replay::ReplayEngine::new(trace);
        let id = eng.add_breakpoint(addr);
        let disabled = eng.disable_breakpoint(id);
        let enabled = eng.enable_breakpoint(id);
        let removed = eng.remove_breakpoint(id);
        Ok(ToolResult::text(json!({"id":id,"disabled":disabled,"enabled":enabled,"removed":removed,"remaining":eng.breakpoints().len(),"source":"rustre_ttd_replay::ReplayEngine"}).to_string()))
    }
}

pub struct TtdReplayEngineWatchpointsTool;
impl TtdReplayEngineWatchpointsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_engine_watchpoints".to_string(),
            description: "Add and remove a write watchpoint in ReplayEngine via rustre_ttd_replay::ReplayEngine.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"addr":{"type":"integer"},"size":{"type":"integer"}},"required":["n","addr","size"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayEngineWatchpointsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as usize;
        let trace = rustre_ttd::build_test_trace(n);
        let mut eng = rustre_ttd_replay::ReplayEngine::new(trace);
        let id = eng.add_watchpoint(addr, size, rustre_ttd_replay::WatchpointKind::Write);
        let removed = eng.remove_watchpoint(id);
        Ok(ToolResult::text(json!({"id":id,"removed":removed,"remaining":eng.watchpoints().len(),"source":"rustre_ttd_replay::ReplayEngine"}).to_string()))
    }
}

pub struct TtdReplayEngineFindWritesTool;
impl TtdReplayEngineFindWritesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_engine_find_writes".to_string(),
            description: "Query first/last/all write positions to an address via rustre_ttd_replay::ReplayEngine::find_*_write_to.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"addr":{"type":"integer"}},"required":["n","addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayEngineFindWritesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let eng = rustre_ttd_replay::ReplayEngine::new(trace);
        let first = eng.find_first_write_to(addr).map(|p| p.to_string());
        let last = eng.find_last_write_to(addr).map(|p| p.to_string());
        let all = eng.find_all_writes_to(addr).len();
        Ok(ToolResult::text(json!({"first":first,"last":last,"all_count":all,"source":"rustre_ttd_replay::ReplayEngine"}).to_string()))
    }
}

pub struct TtdReplayEngineFindCallsTool;
impl TtdReplayEngineFindCallsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_engine_find_calls".to_string(),
            description: "Query positions of calls to target, calls from site, reads from addr via rustre_ttd_replay::ReplayEngine.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"target":{"type":"integer"},"site":{"type":"integer"}},"required":["n","target","site"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayEngineFindCallsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let target = args.get("target").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'target'".into()))?;
        let site = args.get("site").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'site'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let eng = rustre_ttd_replay::ReplayEngine::new(trace);
        Ok(ToolResult::text(json!({"calls_to":eng.find_all_calls_to(target).len(),"calls_from":eng.find_all_calls_from(site).len(),"reads_from":eng.find_all_reads_from(target).len(),"source":"rustre_ttd_replay::ReplayEngine"}).to_string()))
    }
}

pub struct TtdReplaySnapshotCacheTool;
impl TtdReplaySnapshotCacheTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_snapshot_cache".to_string(),
            description: "Build ReplayEngine with custom snapshot interval, run build_snapshot_index via rustre_ttd_replay::SnapshotCache.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"interval":{"type":"integer"}},"required":["n","interval"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplaySnapshotCacheTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let interval = args.get("interval").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'interval'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let mut eng = rustre_ttd_replay::ReplayEngine::with_snapshot_interval(trace, interval);
        eng.build_snapshot_index();
        Ok(ToolResult::text(json!({"n":n,"interval":interval,"snapshot_count":eng.snapshot_cache().snapshot_count(),"source":"rustre_ttd_replay::SnapshotCache"}).to_string()))
    }
}

pub struct TtdReplayRecordingRoundtripTool;
impl TtdReplayRecordingRoundtripTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_recording_roundtrip".to_string(),
            description: "Serialize a synthetic trace to the RSTRETTD binary format and re-parse it via rustre_ttd_replay::TtdRecordingFile.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayRecordingRoundtripTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let file = rustre_ttd_replay::TtdRecordingFile::from_trace(&trace);
        let mut buf: Vec<u8> = Vec::new();
        file.write_to(&mut buf).map_err(|e| McpError::InternalError(e.to_string()))?;
        let mut cur = std::io::Cursor::new(&buf);
        let parsed = rustre_ttd_replay::TtdRecordingFile::read_from(&mut cur).map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({"n":n,"bytes":buf.len(),"parsed_events":parsed.events.len(),"source":"rustre_ttd_replay::TtdRecordingFile"}).to_string()))
    }
}

pub struct TtdReplayApplyEventToStateTool;
impl TtdReplayApplyEventToStateTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replay_apply_event_to_state".to_string(),
            description: "Apply first k events of a synthetic trace to a legacy ReplayState via rustre_ttd_replay::ReplayEngine::apply_event_to_state.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"k":{"type":"integer"}},"required":["n","k"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayApplyEventToStateTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let k = args.get("k").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'k'".into()))? as usize;
        let trace = rustre_ttd::build_test_trace(n);
        let events = trace.all_events();
        let mut st = rustre_ttd_replay::ReplayState::default();
        for e in events.iter().take(k) {
            rustre_ttd_replay::ReplayEngine::apply_event_to_state(&mut st, e);
        }
        Ok(ToolResult::text(json!({"n":n,"applied":k.min(events.len()),"pages":st.memory_pages.len(),"regs":st.registers.len(),"tid":st.thread_id,"source":"rustre_ttd_replay::ReplayEngine::apply_event_to_state"}).to_string()))
    }
}

#[must_use]
pub fn all_ttd_replay_extra_handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TtdReplayMemStateApplyReadTool::definition(), Box::new(TtdReplayMemStateApplyReadTool)),
        (TtdReplayMemStateDiffTool::definition(), Box::new(TtdReplayMemStateDiffTool)),
        (TtdReplayWatchpointOverlapsTool::definition(), Box::new(TtdReplayWatchpointOverlapsTool)),
        (TtdReplayWatchpointSetMatchesTool::definition(), Box::new(TtdReplayWatchpointSetMatchesTool)),
        (TtdReplayDeltaCompressorTool::definition(), Box::new(TtdReplayDeltaCompressorTool)),
        (TtdReplayBreakpointFiresTool::definition(), Box::new(TtdReplayBreakpointFiresTool)),
        (TtdReplayEngineNavigateTool::definition(), Box::new(TtdReplayEngineNavigateTool)),
        (TtdReplayEngineStepForwardTool::definition(), Box::new(TtdReplayEngineStepForwardTool)),
        (TtdReplayEngineBreakpointsTool::definition(), Box::new(TtdReplayEngineBreakpointsTool)),
        (TtdReplayEngineWatchpointsTool::definition(), Box::new(TtdReplayEngineWatchpointsTool)),
        (TtdReplayEngineFindWritesTool::definition(), Box::new(TtdReplayEngineFindWritesTool)),
        (TtdReplayEngineFindCallsTool::definition(), Box::new(TtdReplayEngineFindCallsTool)),
        (TtdReplaySnapshotCacheTool::definition(), Box::new(TtdReplaySnapshotCacheTool)),
        (TtdReplayRecordingRoundtripTool::definition(), Box::new(TtdReplayRecordingRoundtripTool)),
        (TtdReplayApplyEventToStateTool::definition(), Box::new(TtdReplayApplyEventToStateTool)),
    ]
}
