//! MCP wrappers for the rustre-trace crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct TraceMergeEmptySessionsTool;

pub struct TraceCoresightEtmDecodeStreamTool;

pub struct TraceCoresightTpiuDemuxTool;

pub struct TraceCoresightStmDecodeStreamTool;

pub struct TraceOpenTraceFileTool;

pub struct TraceMergeSessionsTool;

pub struct TraceFilterInstructionsOnlyWireTool;

pub struct TraceCompressorCompressionRatioWireTool;

pub struct TraceCoresightIsValidStreamTool;

pub struct TraceCoresightFindSyncOffsetsTool;

pub struct TraceEventTypeNameWireT1Tool;
impl TraceEventTypeNameWireT1Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_event_type_name_wt1".to_string(),
            description: "Return type_name() for a synthesized TraceEvent by kind.".to_string(),
            input_schema: json!({"type":"object","properties":{"kind":{"type":"string"}},"required":["kind"]}),
            parameters: Value::Null,
        }
    }
    fn make(kind: &str) -> Option<rustre_trace::TraceEvent> {
        use rustre_trace::TraceEvent as E;
        Some(match kind {
            "instruction" => E::Instruction { addr: 0, size: 1 },
            "memread" => E::MemRead { addr: 0, size: 1, value: 0 },
            "memwrite" => E::MemWrite { addr: 0, size: 1, value: 0 },
            "call" => E::Call { from: 0, to: 0 },
            "return" => E::Return { from: 0, to: 0 },
            "exception" => E::Exception { code: 0, addr: 0 },
            "syscall" => E::Syscall { number: 0, args: vec![] },
            "branch" => E::Branch { from: 0, to: 0, taken: true },
            "moduleload" => E::ModuleLoad { base: 0, size: 0, name: String::new() },
            "regchange" => E::RegisterChange { name: String::new(), old_value: 0, new_value: 0 },
            _ => return None,
        })
    }
}
#[async_trait]
impl ToolHandler for TraceEventTypeNameWireT1Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let k = args.get("kind").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let ev = Self::make(k).ok_or_else(|| McpError::InvalidParams("unknown kind".into()))?;
        Ok(ToolResult::text(json!({
            "kind": k, "type_name": ev.type_name(),
            "is_control_flow": ev.is_control_flow(),
            "is_memory_access": ev.is_memory_access(),
            "is_instruction": ev.is_instruction(),
            "is_syscall": ev.is_syscall(),
            "is_exception": ev.is_exception(),
            "source": "rustre_trace::TraceEvent",
        }).to_string()))
    }
}

pub struct TraceSessionInstructionCountWireT1Tool;
impl TraceSessionInstructionCountWireT1Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_session_instruction_count_wt1".to_string(),
            description: "Build a TraceSession from instruction addresses; return counts and duration.".to_string(),
            input_schema: json!({"type":"object","properties":{"addrs":{"type":"array"},"arch":{"type":"string"}},"required":["addrs"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceSessionInstructionCountWireT1Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addrs = args.get("addrs").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'addrs'".into()))?;
        let arch = args.get("arch").and_then(Value::as_str).unwrap_or("x86_64");
        let mut s = rustre_trace::TraceSession::new("wt1", arch);
        for (i, v) in addrs.iter().enumerate() {
            s.push(rustre_trace::TraceEvent::Instruction { addr: v.as_u64().unwrap_or(0), size: 1 }, 1, (i as u64) * 100);
        }
        Ok(ToolResult::text(json!({
            "instruction_count": s.instruction_count(),
            "record_count": s.record_count(),
            "unique_pcs": s.unique_pcs().len(),
            "duration_ns": s.duration_ns(),
            "thread_ids": s.thread_ids().len(),
            "source": "rustre_trace::TraceSession",
        }).to_string()))
    }
}

pub struct TraceFilterMatchesWireT1Tool;
impl TraceFilterMatchesWireT1Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_filter_matches_wt1".to_string(),
            description: "Test whether an instruction record matches a TraceFilter.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"tid":{"type":"integer"},"ts_ns":{"type":"integer"},"min_addr":{"type":"integer"},"max_addr":{"type":"integer"},"thread_id":{"type":"integer"},"min_ts":{"type":"integer"},"max_ts":{"type":"integer"}},"required":["addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceFilterMatchesWireT1Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let tid = args.get("tid").and_then(Value::as_u64).unwrap_or(1) as u32;
        let ts = args.get("ts_ns").and_then(Value::as_u64).unwrap_or(0);
        let mut f = rustre_trace::TraceFilter::new();
        f.min_addr = args.get("min_addr").and_then(Value::as_u64);
        f.max_addr = args.get("max_addr").and_then(Value::as_u64);
        f.thread_id = args.get("thread_id").and_then(Value::as_u64).map(|n| n as u32);
        f.min_timestamp_ns = args.get("min_ts").and_then(Value::as_u64);
        f.max_timestamp_ns = args.get("max_ts").and_then(Value::as_u64);
        let rec = rustre_trace::TraceRecord::new(0, rustre_trace::TraceEvent::Instruction { addr, size: 1 }, tid, ts);
        Ok(ToolResult::text(json!({"matches": f.matches(&rec), "filter_empty": f.is_empty(), "source":"rustre_trace::TraceFilter::matches"}).to_string()))
    }
}

pub struct TraceCompressorRlEncodeWireT1Tool;
impl TraceCompressorRlEncodeWireT1Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_compressor_rle_wt1".to_string(),
            description: "RLE-compress a repeating-instruction session and report ratio.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"count":{"type":"integer"}},"required":["addr","count"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCompressorRlEncodeWireT1Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let n = args.get("count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'count'".into()))?.min(100_000);
        let mut s = rustre_trace::TraceSession::new("wt1", "x86_64");
        for i in 0..n { s.push(rustre_trace::TraceEvent::Instruction { addr, size: 1 }, 1, i * 10); }
        let blocks = rustre_trace::TraceCompressor::compress(&s);
        let ratio = rustre_trace::TraceCompressor::compression_ratio(s.record_count(), blocks.len());
        Ok(ToolResult::text(json!({"input_records": s.record_count(), "block_count": blocks.len(), "compression_ratio": ratio, "source":"rustre_trace::TraceCompressor"}).to_string()))
    }
}

pub struct TraceDiffSimilarityWireT1Tool;
impl TraceDiffSimilarityWireT1Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_diff_similarity_wt1".to_string(),
            description: "Diff two synthesized instruction sessions; return similarity metrics.".to_string(),
            input_schema: json!({"type":"object","properties":{"left_addrs":{"type":"array"},"right_addrs":{"type":"array"}},"required":["left_addrs","right_addrs"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceDiffSimilarityWireT1Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mk = |k: &str| -> rustre_trace::TraceSession {
            let mut s = rustre_trace::TraceSession::new(k, "x86_64");
            if let Some(a) = args.get(k).and_then(Value::as_array) {
                for (i, v) in a.iter().enumerate() {
                    s.push(rustre_trace::TraceEvent::Instruction { addr: v.as_u64().unwrap_or(0), size: 1 }, 1, i as u64);
                }
            }
            s
        };
        let d = rustre_trace::TraceDiff::compute(&mk("left_addrs"), &mk("right_addrs"));
        Ok(ToolResult::text(json!({
            "common_count": d.common_count,
            "only_in_left": d.only_in_left.len(),
            "only_in_right": d.only_in_right.len(),
            "similarity": d.similarity(),
            "is_identical": d.is_identical(),
            "source": "rustre_trace::TraceDiff",
        }).to_string()))
    }
}

pub struct TracePlayerProgressWireT1Tool;
impl TracePlayerProgressWireT1Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_player_progress_wt1".to_string(),
            description: "Create a TracePlayer over n instructions, step, return progress.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"steps":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TracePlayerProgressWireT1Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?.min(10_000);
        let steps = args.get("steps").and_then(Value::as_u64).unwrap_or(0);
        let mut s = rustre_trace::TraceSession::new("wt1", "x86_64");
        for i in 0..n { s.push(rustre_trace::TraceEvent::Instruction { addr: i, size: 1 }, 1, i); }
        let mut p = rustre_trace::TracePlayer::new(s);
        for _ in 0..steps { if p.next().is_none() { break; } }
        Ok(ToolResult::text(json!({"cursor": p.cursor, "total": p.total(), "remaining": p.remaining(), "progress": p.progress(), "is_done": p.is_done(), "source":"rustre_trace::TracePlayer"}).to_string()))
    }
}

pub struct TraceIndexBuildWireT1Tool;
impl TraceIndexBuildWireT1Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_index_build_wt1".to_string(),
            description: "Build a TraceIndex from an instruction session; return index stats.".to_string(),
            input_schema: json!({"type":"object","properties":{"addrs":{"type":"array"}},"required":["addrs"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceIndexBuildWireT1Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addrs = args.get("addrs").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'addrs'".into()))?;
        let mut s = rustre_trace::TraceSession::new("wt1", "x86_64");
        for (i, v) in addrs.iter().enumerate() {
            s.push(rustre_trace::TraceEvent::Instruction { addr: v.as_u64().unwrap_or(0), size: 1 }, 1, i as u64);
        }
        let idx = s.build_index().map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "total_indexed": idx.total_indexed(),
            "address_count": idx.all_addresses().len(),
            "thread_count": idx.all_thread_ids().len(),
            "event_types": idx.all_event_types(),
            "source": "rustre_trace::TraceIndex",
        }).to_string()))
    }
}

pub struct TraceJsonRoundtripWireT1Tool;
impl TraceJsonRoundtripWireT1Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_json_roundtrip_wt1".to_string(),
            description: "Serialize/deserialize a Trace via JSON and binary formats; return sizes.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceJsonRoundtripWireT1Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?.min(10_000);
        let mut s = rustre_trace::TraceSession::new("wt1", "x86_64");
        for i in 0..n { s.push(rustre_trace::TraceEvent::Instruction { addr: i, size: 1 }, 1, i); }
        let t = rustre_trace::Trace::new(s);
        let json = t.to_json().map_err(|e| McpError::InternalError(e.to_string()))?;
        let bin = t.to_binary().map_err(|e| McpError::InternalError(e.to_string()))?;
        let rt = rustre_trace::Trace::from_json(&json).map_err(|e| McpError::InternalError(e.to_string()))?;
        let rt2 = rustre_trace::Trace::from_binary(&bin).map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "json_bytes": json.len(),
            "binary_bytes": bin.len(),
            "records": t.len(),
            "records_after_json": rt.len(),
            "records_after_binary": rt2.len(),
            "source": "rustre_trace::Trace",
        }).to_string()))
    }
}

pub struct TraceVisualizationDataWireT1Tool;
impl TraceVisualizationDataWireT1Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_visualization_data_wt1".to_string(),
            description: "Compute TraceVisualizationData for an instruction session.".to_string(),
            input_schema: json!({"type":"object","properties":{"addrs":{"type":"array"}},"required":["addrs"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceVisualizationDataWireT1Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addrs = args.get("addrs").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'addrs'".into()))?;
        let mut s = rustre_trace::TraceSession::new("wt1", "x86_64");
        for (i, v) in addrs.iter().enumerate() {
            s.push(rustre_trace::TraceEvent::Instruction { addr: v.as_u64().unwrap_or(0), size: 1 }, 1, i as u64 * 10);
        }
        let t = rustre_trace::Trace::new(s);
        let d = t.visualization_data();
        Ok(ToolResult::text(json!({
            "total_events": d.total_events,
            "unique_addresses": d.unique_addresses,
            "thread_count": d.thread_count,
            "event_type_counts": d.event_type_counts,
            "hot_addresses": d.hot_addresses,
            "time_range": [d.time_range.0, d.time_range.1],
            "source": "rustre_trace::TraceVisualizationData",
        }).to_string()))
    }
}

pub struct TraceRecorderRecordWireT1Tool;
impl TraceRecorderRecordWireT1Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_recorder_record_wt1".to_string(),
            description: "Feed n instructions into a bounded TraceRecorder; report fill state.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"max":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceRecorderRecordWireT1Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?.min(10_000);
        let max = args.get("max").and_then(Value::as_u64).unwrap_or(0);
        let mut r = rustre_trace::TraceRecorder::with_max_events("wt1", "x86_64", max);
        for i in 0..n { r.record_instruction(i, 1, 1, i); }
        let ec = r.event_count;
        let full = r.is_full();
        let sess = r.finish();
        Ok(ToolResult::text(json!({"event_count": ec, "is_full": full, "session_len": sess.record_count(), "source":"rustre_trace::TraceRecorder"}).to_string()))
    }
}

pub struct TraceRegistryEnginesWireT1Tool;
impl TraceRegistryEnginesWireT1Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_registry_engines_wt1".to_string(),
            description: "List names of trace engines registered in rustre_trace::registry.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceRegistryEnginesWireT1Tool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let names = rustre_trace::registry::engine_names();
        let engines = rustre_trace::registry::all_engines();
        let live: Vec<&'static str> = engines.iter().map(|e| e.name()).collect();
        Ok(ToolResult::text(json!({"engine_names": names, "live_engines": live, "count": names.len(), "source":"rustre_trace::registry"}).to_string()))
    }
}

pub struct TraceSessionInstructionCountTool;
impl TraceSessionInstructionCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_session_instruction_count".to_string(),
            description: "Build a TraceSession with N Instruction events and return instruction_count.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceSessionInstructionCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let mut s = rustre_trace::TraceSession::new("t", "x86_64");
        for i in 0..n { s.push(rustre_trace::TraceEvent::Instruction { addr: 0x1000 + i, size: 4 }, 1, i * 10); }
        Ok(ToolResult::text(json!({"instruction_count":s.instruction_count(),"unique_pcs":s.unique_pcs().len(),"source":"rustre_trace::TraceSession::instruction_count"}).to_string()))
    }
}

pub struct TraceFilterMatchesTool;
impl TraceFilterMatchesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_filter_matches".to_string(),
            description: "Test TraceFilter::matches for an Instruction record at addr with min/max range.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"min":{"type":"integer"},"max":{"type":"integer"}},"required":["addr","min","max"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceFilterMatchesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let min = args.get("min").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'min'".into()))?;
        let max = args.get("max").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'max'".into()))?;
        let f = rustre_trace::TraceFilter::address_range(min, max);
        let rec = rustre_trace::TraceRecord::new(0, rustre_trace::TraceEvent::Instruction { addr, size: 4 }, 1, 0);
        Ok(ToolResult::text(json!({"matches":f.matches(&rec),"source":"rustre_trace::TraceFilter::matches"}).to_string()))
    }
}

pub struct TraceCompressorRatioTool;
impl TraceCompressorRatioTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_compressor_compression_ratio".to_string(),
            description: "TraceCompressor::compression_ratio(original, blocks).".to_string(),
            input_schema: json!({"type":"object","properties":{"original":{"type":"integer"},"blocks":{"type":"integer"}},"required":["original","blocks"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCompressorRatioTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let o = args.get("original").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'original'".into()))? as usize;
        let b = args.get("blocks").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'blocks'".into()))? as usize;
        Ok(ToolResult::text(json!({"ratio":rustre_trace::TraceCompressor::compression_ratio(o, b),"source":"rustre_trace::TraceCompressor::compression_ratio"}).to_string()))
    }
}

pub struct TraceDiffSimilarityTool;
impl TraceDiffSimilarityTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_diff_similarity_identical".to_string(),
            description: "Build two identical sessions with N instructions and return TraceDiff::similarity.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceDiffSimilarityTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let mut a = rustre_trace::TraceSession::new("a", "x86_64");
        let mut b = rustre_trace::TraceSession::new("b", "x86_64");
        for i in 0..n {
            let ev = rustre_trace::TraceEvent::Instruction { addr: 0x2000 + i, size: 4 };
            a.push(ev.clone(), 1, i);
            b.push(ev, 1, i);
        }
        let d = rustre_trace::TraceDiff::compute(&a, &b);
        Ok(ToolResult::text(json!({"similarity":d.similarity(),"is_identical":d.is_identical(),"common":d.common_count,"source":"rustre_trace::TraceDiff::compute"}).to_string()))
    }
}

pub struct TracePlayerProgressTool;
impl TracePlayerProgressTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_player_progress".to_string(),
            description: "TracePlayer with N records, advance K, report progress.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"k":{"type":"integer"}},"required":["n","k"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TracePlayerProgressTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let k = args.get("k").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'k'".into()))?;
        let mut s = rustre_trace::TraceSession::new("t", "x86_64");
        for i in 0..n { s.push(rustre_trace::TraceEvent::Instruction { addr: 0x3000 + i, size: 4 }, 1, i); }
        let mut p = rustre_trace::TracePlayer::new(s);
        for _ in 0..k { if p.next().is_none() { break; } }
        Ok(ToolResult::text(json!({"progress":p.progress(),"remaining":p.remaining(),"is_done":p.is_done(),"total":p.total(),"source":"rustre_trace::TracePlayer"}).to_string()))
    }
}

pub struct TraceEventTypeNameTool;
impl TraceEventTypeNameTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_event_type_name".to_string(),
            description: "TraceEvent::type_name for a variant selector.".to_string(),
            input_schema: json!({"type":"object","properties":{"kind":{"type":"string"}},"required":["kind"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceEventTypeNameTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let k = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let ev = match k {
            "memread" => rustre_trace::TraceEvent::MemRead { addr: 0, size: 4, value: 0 },
            "memwrite" => rustre_trace::TraceEvent::MemWrite { addr: 0, size: 4, value: 0 },
            "call" => rustre_trace::TraceEvent::Call { from: 0, to: 0 },
            "return" => rustre_trace::TraceEvent::Return { from: 0, to: 0 },
            "branch" => rustre_trace::TraceEvent::Branch { from: 0, to: 0, taken: true },
            "syscall" => rustre_trace::TraceEvent::Syscall { number: 0, args: vec![] },
            "exception" => rustre_trace::TraceEvent::Exception { code: 0, addr: 0 },
            _ => rustre_trace::TraceEvent::Instruction { addr: 0, size: 4 },
        };
        Ok(ToolResult::text(json!({"type_name":ev.type_name(),"is_ctrl_flow":ev.is_control_flow(),"is_mem":ev.is_memory_access(),"source":"rustre_trace::TraceEvent::type_name"}).to_string()))
    }
}

pub struct TraceSessionDurationNsTool;
impl TraceSessionDurationNsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_session_duration_ns".to_string(),
            description: "Push N events with step and return TraceSession::duration_ns.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"step":{"type":"integer"}},"required":["n","step"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceSessionDurationNsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let step = args.get("step").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'step'".into()))?;
        let mut s = rustre_trace::TraceSession::new("t", "x86_64");
        for i in 0..n { s.push(rustre_trace::TraceEvent::Instruction { addr: 0x4000, size: 4 }, 1, i * step); }
        Ok(ToolResult::text(json!({"duration_ns":s.duration_ns(),"records":s.record_count(),"source":"rustre_trace::TraceSession::duration_ns"}).to_string()))
    }
}

pub struct TraceRecorderIsFullTool;
impl TraceRecorderIsFullTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_recorder_is_full".to_string(),
            description: "TraceRecorder::with_max_events(max), record k, return is_full+event_count.".to_string(),
            input_schema: json!({"type":"object","properties":{"max":{"type":"integer"},"k":{"type":"integer"}},"required":["max","k"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceRecorderIsFullTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let max = args.get("max").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'max'".into()))?;
        let k = args.get("k").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'k'".into()))?;
        let mut r = rustre_trace::TraceRecorder::with_max_events("t", "x86_64", max);
        for i in 0..k { r.record_instruction(0x6000 + i, 4, 1, i); }
        Ok(ToolResult::text(json!({"is_full":r.is_full(),"event_count":r.event_count,"source":"rustre_trace::TraceRecorder::is_full"}).to_string()))
    }
}

pub struct TraceRecorderNewTool;
impl TraceRecorderNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_recorder_new".to_string(),
            description: "Create a TraceRecorder via rustre_trace::TraceRecorder::new.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"arch":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceRecorderNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("t");
        let arch = args.get("arch").and_then(Value::as_str).unwrap_or("x86_64");
        let rec = rustre_trace::TraceRecorder::new(name, arch);
        let sess = rec.finish();
        Ok(ToolResult::text(json!({"name": name, "arch": arch, "records": sess.records.len(), "source": "rustre_trace::TraceRecorder::new"}).to_string()))
    }
}

pub struct TraceRecorderRecordInsnTool;
impl TraceRecorderRecordInsnTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_recorder_record_insn".to_string(),
            description: "Record N instruction events via TraceRecorder::record_instruction.".to_string(),
            input_schema: json!({"type":"object","properties":{"count":{"type":"integer"},"base_addr":{"type":"integer"}},"required":["count"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceRecorderRecordInsnTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let count = args.get("count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'count'".into()))?;
        let base = args.get("base_addr").and_then(Value::as_u64).unwrap_or(0x1000);
        let mut rec = rustre_trace::TraceRecorder::new("t", "x86_64");
        for i in 0..count { rec.record_instruction(base + i * 4, 4, 0, i); }
        let sess = rec.finish();
        Ok(ToolResult::text(json!({"recorded": count, "records": sess.records.len(), "source": "rustre_trace::TraceRecorder::record_instruction"}).to_string()))
    }
}

pub struct TraceStatisticsComputeTool;
impl TraceStatisticsComputeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_statistics_compute".to_string(),
            description: "Compute TraceStatistics via rustre_trace::TraceStatistics::compute.".to_string(),
            input_schema: json!({"type":"object","properties":{"arch":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceStatisticsComputeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arch = args.get("arch").and_then(Value::as_str).unwrap_or("x86_64");
        let s = rustre_trace::TraceSession::new("t", arch);
        let stats = rustre_trace::TraceStatistics::compute(&s);
        Ok(ToolResult::text(json!({"total_records": stats.total_records, "instruction_count": stats.instruction_count, "unique_addresses": stats.unique_addresses, "branch_taken_ratio": stats.branch_taken_ratio(), "source": "rustre_trace::TraceStatistics::compute"}).to_string()))
    }
}

pub struct TraceLoopDetectorTool;
impl TraceLoopDetectorTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_loop_detector_detect".to_string(),
            description: "rustre_trace::TraceLoopDetector::detect on an empty session.".to_string(),
            input_schema: json!({"type":"object","properties":{"min_iter":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceLoopDetectorTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let min_iter = args.get("min_iter").and_then(Value::as_u64).unwrap_or(2);
        let s = rustre_trace::TraceSession::new("t", "x86_64");
        let loops = rustre_trace::TraceLoopDetector::detect(&s, min_iter);
        Ok(ToolResult::text(json!({"loops_found": loops.len(), "source": "rustre_trace::TraceLoopDetector::detect"}).to_string()))
    }
}

pub struct TraceAnomalyDetectorTool;
impl TraceAnomalyDetectorTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_anomaly_detector_detect".to_string(),
            description: "rustre_trace::TraceAnomalyDetector::detect on an empty session.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceAnomalyDetectorTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_trace::TraceSession::new("t", "x86_64");
        let anoms = rustre_trace::TraceAnomalyDetector::detect(&s);
        Ok(ToolResult::text(json!({"anomalies": anoms.len(), "source": "rustre_trace::TraceAnomalyDetector::detect"}).to_string()))
    }
}

pub struct TraceFunctionCallTreeBuildTool;
impl TraceFunctionCallTreeBuildTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_function_call_tree_build".to_string(),
            description: "rustre_trace::TraceFunctionCallTree::build.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceFunctionCallTreeBuildTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_trace::TraceSession::new("t", "x86_64");
        let tree = rustre_trace::TraceFunctionCallTree::build(&s);
        Ok(ToolResult::text(json!({"roots": tree.len(), "source": "rustre_trace::TraceFunctionCallTree::build"}).to_string()))
    }
}

pub struct TraceHeatmapFromSessionTool;
impl TraceHeatmapFromSessionTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_heatmap_from_session".to_string(),
            description: "rustre_trace::TraceHeatmap::from_session.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceHeatmapFromSessionTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_trace::TraceSession::new("t", "x86_64");
        let hm = rustre_trace::TraceHeatmap::from_session(&s);
        Ok(ToolResult::text(json!({"hit_at_0x1000": hm.count(0x1000), "source": "rustre_trace::TraceHeatmap::from_session"}).to_string()))
    }
}

pub struct TraceSessionBuildHeatMapTool;
impl TraceSessionBuildHeatMapTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_session_build_heat_map".to_string(),
            description: "rustre_trace::TraceSession::build_heat_map.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceSessionBuildHeatMapTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_trace::TraceSession::new("t", "x86_64");
        let hm = s.build_heat_map();
        Ok(ToolResult::text(json!({"hit_at_0x1000": hm.count(0x1000), "source": "rustre_trace::TraceSession::build_heat_map"}).to_string()))
    }
}

pub struct TraceSessionBuildIndexTool;
impl TraceSessionBuildIndexTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_session_build_index".to_string(),
            description: "rustre_trace::TraceSession::build_index.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceSessionBuildIndexTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_trace::TraceSession::new("t", "x86_64");
        let _idx = s.build_index().map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({"built": true, "source": "rustre_trace::TraceSession::build_index"}).to_string()))
    }
}

pub struct TraceSessionCoverageSetTool;
impl TraceSessionCoverageSetTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_session_coverage_set".to_string(),
            description: "rustre_trace::TraceSession::coverage_set.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceSessionCoverageSetTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_trace::TraceSession::new("t", "x86_64");
        let set = s.coverage_set();
        Ok(ToolResult::text(json!({"unique_addrs": set.len(), "source": "rustre_trace::TraceSession::coverage_set"}).to_string()))
    }
}

pub struct TraceDiffComputeTool;
impl TraceDiffComputeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_diff_compute".to_string(),
            description: "rustre_trace::TraceDiff::compute between two empty sessions.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceDiffComputeTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let a = rustre_trace::TraceSession::new("a", "x86_64");
        let b = rustre_trace::TraceSession::new("b", "x86_64");
        let d = rustre_trace::TraceDiff::compute(&a, &b);
        Ok(ToolResult::text(json!({"common_count": d.common_count, "only_in_left": d.only_in_left.len(), "only_in_right": d.only_in_right.len(), "similarity": d.similarity(), "source": "rustre_trace::TraceDiff::compute"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TraceMergeEmptySessionsTool::definition(), Box::new(TraceMergeEmptySessionsTool)),
        (TraceCoresightEtmDecodeStreamTool::definition(), Box::new(TraceCoresightEtmDecodeStreamTool)),
        (TraceCoresightTpiuDemuxTool::definition(), Box::new(TraceCoresightTpiuDemuxTool)),
        (TraceCoresightStmDecodeStreamTool::definition(), Box::new(TraceCoresightStmDecodeStreamTool)),
        (TraceOpenTraceFileTool::definition(), Box::new(TraceOpenTraceFileTool)),
        (TraceMergeSessionsTool::definition(), Box::new(TraceMergeSessionsTool)),
        (TraceFilterInstructionsOnlyWireTool::definition(), Box::new(TraceFilterInstructionsOnlyWireTool)),
        (TraceCompressorCompressionRatioWireTool::definition(), Box::new(TraceCompressorCompressionRatioWireTool)),
        (TraceCoresightIsValidStreamTool::definition(), Box::new(TraceCoresightIsValidStreamTool)),
        (TraceCoresightFindSyncOffsetsTool::definition(), Box::new(TraceCoresightFindSyncOffsetsTool)),
        (TraceEventTypeNameWireT1Tool::definition(), Box::new(TraceEventTypeNameWireT1Tool)),
        (TraceSessionInstructionCountWireT1Tool::definition(), Box::new(TraceSessionInstructionCountWireT1Tool)),
        (TraceFilterMatchesWireT1Tool::definition(), Box::new(TraceFilterMatchesWireT1Tool)),
        (TraceCompressorRlEncodeWireT1Tool::definition(), Box::new(TraceCompressorRlEncodeWireT1Tool)),
        (TraceDiffSimilarityWireT1Tool::definition(), Box::new(TraceDiffSimilarityWireT1Tool)),
        (TracePlayerProgressWireT1Tool::definition(), Box::new(TracePlayerProgressWireT1Tool)),
        (TraceIndexBuildWireT1Tool::definition(), Box::new(TraceIndexBuildWireT1Tool)),
        (TraceJsonRoundtripWireT1Tool::definition(), Box::new(TraceJsonRoundtripWireT1Tool)),
        (TraceVisualizationDataWireT1Tool::definition(), Box::new(TraceVisualizationDataWireT1Tool)),
        (TraceRecorderRecordWireT1Tool::definition(), Box::new(TraceRecorderRecordWireT1Tool)),
        (TraceRegistryEnginesWireT1Tool::definition(), Box::new(TraceRegistryEnginesWireT1Tool)),
        (TraceSessionInstructionCountTool::definition(), Box::new(TraceSessionInstructionCountTool)),
        (TraceFilterMatchesTool::definition(), Box::new(TraceFilterMatchesTool)),
        (TraceCompressorRatioTool::definition(), Box::new(TraceCompressorRatioTool)),
        (TraceDiffSimilarityTool::definition(), Box::new(TraceDiffSimilarityTool)),
        (TracePlayerProgressTool::definition(), Box::new(TracePlayerProgressTool)),
        (TraceEventTypeNameTool::definition(), Box::new(TraceEventTypeNameTool)),
        (TraceSessionDurationNsTool::definition(), Box::new(TraceSessionDurationNsTool)),
        (TraceRecorderIsFullTool::definition(), Box::new(TraceRecorderIsFullTool)),
        (TraceRecorderNewTool::definition(), Box::new(TraceRecorderNewTool)),
        (TraceRecorderRecordInsnTool::definition(), Box::new(TraceRecorderRecordInsnTool)),
        (TraceStatisticsComputeTool::definition(), Box::new(TraceStatisticsComputeTool)),
        (TraceLoopDetectorTool::definition(), Box::new(TraceLoopDetectorTool)),
        (TraceAnomalyDetectorTool::definition(), Box::new(TraceAnomalyDetectorTool)),
        (TraceFunctionCallTreeBuildTool::definition(), Box::new(TraceFunctionCallTreeBuildTool)),
        (TraceHeatmapFromSessionTool::definition(), Box::new(TraceHeatmapFromSessionTool)),
        (TraceSessionBuildHeatMapTool::definition(), Box::new(TraceSessionBuildHeatMapTool)),
        (TraceSessionBuildIndexTool::definition(), Box::new(TraceSessionBuildIndexTool)),
        (TraceSessionCoverageSetTool::definition(), Box::new(TraceSessionCoverageSetTool)),
        (TraceDiffComputeTool::definition(), Box::new(TraceDiffComputeTool)),
    ]
}
