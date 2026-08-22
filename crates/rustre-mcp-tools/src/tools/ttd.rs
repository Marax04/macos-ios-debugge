//! MCP wrappers for the rustre-ttd crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct TtdBuildTestTraceTool;

pub struct TtdBuildMultiThreadTraceTool;

pub struct TtdPositionMinTool;

pub struct TtdPositionMaxTool;

pub struct TtdPositionEarliestTool;

pub struct TtdTracePositionAsU128Tool;
impl TtdTracePositionAsU128Tool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_trace_position_as_u128".to_string(),
            description: "Encode a (sequence, step) TracePosition as u128 via rustre_ttd::TracePosition::as_u128.".to_string(),
            input_schema: json!({"type":"object","properties":{"sequence":{"type":"integer"},"step":{"type":"integer"}},"required":["sequence","step"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdTracePositionAsU128Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let seq = args.get("sequence").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'sequence'".into()))?;
        let step = args.get("step").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'step'".into()))?;
        let v = rustre_ttd::TracePosition::new(seq, step).as_u128();
        Ok(ToolResult::text(json!({"value":v.to_string(),"source":"rustre_ttd::TracePosition::as_u128"}).to_string()))
    }
}

pub struct TtdTracePositionFromU128Tool;
impl TtdTracePositionFromU128Tool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_trace_position_from_u128".to_string(),
            description: "Reconstruct a TracePosition from u128 via rustre_ttd::TracePosition::from_u128.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{"type":"string"}},"required":["value"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdTracePositionFromU128Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("value").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let v: u128 = s.parse().map_err(|e: std::num::ParseIntError| McpError::InvalidParams(e.to_string()))?;
        let p = rustre_ttd::TracePosition::from_u128(v);
        Ok(ToolResult::text(json!({"sequence":p.sequence,"step":p.step,"source":"rustre_ttd::TracePosition::from_u128"}).to_string()))
    }
}

pub struct TtdTracePositionCompareTool;
impl TtdTracePositionCompareTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_trace_position_compare".to_string(),
            description: "Compare two TracePositions via rustre_ttd::TracePosition ordering.".to_string(),
            input_schema: json!({"type":"object","properties":{"a_seq":{"type":"integer"},"a_step":{"type":"integer"},"b_seq":{"type":"integer"},"b_step":{"type":"integer"}},"required":["a_seq","a_step","b_seq","b_step"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdTracePositionCompareTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a_seq = args.get("a_seq").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_seq'".into()))?;
        let a_step = args.get("a_step").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a_step'".into()))?;
        let b_seq = args.get("b_seq").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_seq'".into()))?;
        let b_step = args.get("b_step").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b_step'".into()))?;
        let a = rustre_ttd::TracePosition::new(a_seq, a_step);
        let b = rustre_ttd::TracePosition::new(b_seq, b_step);
        Ok(ToolResult::text(json!({"is_before":a.is_before(&b),"is_after":a.is_after(&b),"equal":a==b,"source":"rustre_ttd::TracePosition"}).to_string()))
    }
}

pub struct TtdMemorySnapshotReadU32Tool;
impl TtdMemorySnapshotReadU32Tool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_memory_snapshot_read_u32_le".to_string(),
            description: "Read little-endian u32 from a MemorySnapshot via rustre_ttd::MemorySnapshot::read_u32_le.".to_string(),
            input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"data_hex":{"type":"string"},"addr":{"type":"integer"}},"required":["base","data_hex","addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdMemorySnapshotReadU32Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        // `&clean[i..i+2]` andava in panic su hex di lunghezza dispari, uccidendo il
        // tool su un input che lo schema (`{"type":"string"}`) permette.
        let data: Vec<u8> = crate::hex_decode(&clean)?;
        let snap = rustre_ttd::MemorySnapshot::new(base, data);
        Ok(ToolResult::text(json!({"value":snap.read_u32_le(addr),"source":"rustre_ttd::MemorySnapshot::read_u32_le"}).to_string()))
    }
}

pub struct TtdMemorySnapshotContainsTool;
impl TtdMemorySnapshotContainsTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_memory_snapshot_contains".to_string(),
            description: "Check if an addr is inside a MemorySnapshot via rustre_ttd::MemorySnapshot::contains.".to_string(),
            input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"len":{"type":"integer"},"addr":{"type":"integer"}},"required":["base","len","addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdMemorySnapshotContainsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let len = args.get("len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'len'".into()))? as usize;
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let snap = rustre_ttd::MemorySnapshot::new(base, vec![0u8; len]);
        Ok(ToolResult::text(json!({"contains":snap.contains(addr),"end_address":snap.end_address(),"source":"rustre_ttd::MemorySnapshot::contains"}).to_string()))
    }
}

pub struct TtdTraceEventCountTool;
impl TtdTraceEventCountTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_trace_event_count".to_string(),
            description: "Return event_count of a synthetic single-thread TTD trace via rustre_ttd::TtdTrace::event_count.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdTraceEventCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        Ok(ToolResult::text(json!({"count":trace.event_count(),"thread_ids":trace.thread_ids(),"source":"rustre_ttd::TtdTrace::event_count"}).to_string()))
    }
}

pub struct TtdTraceThreadIdsMultiTool;
impl TtdTraceThreadIdsMultiTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_trace_thread_ids_multi".to_string(),
            description: "Return thread ids of a synthetic multi-thread TTD trace via rustre_ttd::TtdTrace::thread_ids.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdTraceThreadIdsMultiTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let trace = rustre_ttd::build_multi_thread_trace(n);
        Ok(ToolResult::text(json!({"thread_ids":trace.thread_ids(),"event_count":trace.event_count(),"source":"rustre_ttd::TtdTrace::thread_ids"}).to_string()))
    }
}

pub struct TtdPositionNextStepTool;
impl TtdPositionNextStepTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_position_next_step".to_string(),
            description: "Return next_step for a TracePosition via rustre_ttd::TracePosition::next_step.".to_string(),
            input_schema: json!({"type":"object","properties":{"seq":{"type":"integer"},"step":{"type":"integer"}},"required":["seq","step"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdPositionNextStepTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let seq = args.get("seq").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'seq'".into()))?;
        let step = args.get("step").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'step'".into()))?;
        let p = rustre_ttd::TracePosition::new(seq, step).next_step();
        Ok(ToolResult::text(json!({"sequence":p.sequence,"step":p.step,"source":"rustre_ttd::TracePosition::next_step"}).to_string()))
    }
}

pub struct TtdPositionNextSequenceTool;
impl TtdPositionNextSequenceTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_position_next_sequence".to_string(),
            description: "Return next_sequence via rustre_ttd::TracePosition::next_sequence.".to_string(),
            input_schema: json!({"type":"object","properties":{"seq":{"type":"integer"},"step":{"type":"integer"}},"required":["seq","step"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdPositionNextSequenceTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let seq = args.get("seq").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'seq'".into()))?;
        let step = args.get("step").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'step'".into()))?;
        let p = rustre_ttd::TracePosition::new(seq, step).next_sequence();
        Ok(ToolResult::text(json!({"sequence":p.sequence,"step":p.step,"source":"rustre_ttd::TracePosition::next_sequence"}).to_string()))
    }
}

pub struct TtdPositionInRangeTool;
impl TtdPositionInRangeTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_position_in_range".to_string(),
            description: "Check if a position is in [start,end) via rustre_ttd::TracePosition::in_range.".to_string(),
            input_schema: json!({"type":"object","properties":{"seq":{"type":"integer"},"step":{"type":"integer"},"start_seq":{"type":"integer"},"start_step":{"type":"integer"},"end_seq":{"type":"integer"},"end_step":{"type":"integer"}},"required":["seq","step","start_seq","start_step","end_seq","end_step"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdPositionInRangeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let g = |k: &str| args.get(k).and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams(format!("missing '{k}'")));
        let p = rustre_ttd::TracePosition::new(g("seq")?, g("step")?);
        let s = rustre_ttd::TracePosition::new(g("start_seq")?, g("start_step")?);
        let e = rustre_ttd::TracePosition::new(g("end_seq")?, g("end_step")?);
        Ok(ToolResult::text(json!({"in_range":p.in_range(&s,&e),"source":"rustre_ttd::TracePosition::in_range"}).to_string()))
    }
}

pub struct TtdMemorySnapshotReadU64Tool;
impl TtdMemorySnapshotReadU64Tool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_memory_snapshot_read_u64_le".to_string(),
            description: "Read little-endian u64 from a MemorySnapshot via rustre_ttd::MemorySnapshot::read_u64_le.".to_string(),
            input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"data_hex":{"type":"string"},"addr":{"type":"integer"}},"required":["base","data_hex","addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdMemorySnapshotReadU64Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data_hex'".into()))?;
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        // `&clean[i..i+2]` andava in panic su hex di lunghezza dispari, uccidendo il
        // tool su un input che lo schema (`{"type":"string"}`) permette.
        let data: Vec<u8> = crate::hex_decode(&clean)?;
        let snap = rustre_ttd::MemorySnapshot::new(base, data);
        Ok(ToolResult::text(json!({"value":snap.read_u64_le(addr),"source":"rustre_ttd::MemorySnapshot::read_u64_le"}).to_string()))
    }
}

pub struct TtdMemorySnapshotApplyWriteTool;
impl TtdMemorySnapshotApplyWriteTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_memory_snapshot_apply_write".to_string(),
            description: "Apply a write patch to a MemorySnapshot via rustre_ttd::MemorySnapshot::apply_write.".to_string(),
            input_schema: json!({"type":"object","properties":{"base":{"type":"integer"},"len":{"type":"integer"},"write_addr":{"type":"integer"},"new_data_hex":{"type":"string"}},"required":["base","len","write_addr","new_data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdMemorySnapshotApplyWriteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?;
        let len = args.get("len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'len'".into()))? as usize;
        let waddr = args.get("write_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'write_addr'".into()))?;
        let hex = args.get("new_data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'new_data_hex'".into()))?;
        let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        // idem: panic su lunghezza dispari.
        let new_data: Vec<u8> = crate::hex_decode(&clean)?;
        let mut snap = rustre_ttd::MemorySnapshot::new(base, vec![0u8; len]);
        let patched = snap.apply_write(waddr, &new_data);
        Ok(ToolResult::text(json!({"bytes_patched":patched,"source":"rustre_ttd::MemorySnapshot::apply_write"}).to_string()))
    }
}

pub struct TtdMemoryRegionContainsTool;
impl TtdMemoryRegionContainsTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_memory_region_contains".to_string(),
            description: "Check MemoryRegion::contains via rustre_ttd::MemoryRegion.".to_string(),
            input_schema: json!({"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"},"addr":{"type":"integer"}},"required":["start","end","addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdMemoryRegionContainsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let start = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))?;
        let end = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'end'".into()))?;
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let r = rustre_ttd::MemoryRegion::new(start, end, "test");
        Ok(ToolResult::text(json!({"contains":r.contains(addr),"size":r.size(),"source":"rustre_ttd::MemoryRegion::contains"}).to_string()))
    }
}

pub struct TtdTraceStatsComputeTool;
impl TtdTraceStatsComputeTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_trace_stats_compute".to_string(),
            description: "Compute TraceStats over a synthetic trace via rustre_ttd::TraceStats::compute.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdTraceStatsComputeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let s = rustre_ttd::TraceStats::compute(&trace);
        Ok(ToolResult::text(json!({
            "total_events":s.total_events,"mem_reads":s.mem_reads,"mem_writes":s.mem_writes,
            "calls":s.calls,"returns":s.returns,"syscall_enters":s.syscall_enters,
            "exceptions":s.exceptions,"bytes_written":s.bytes_written,"bytes_read":s.bytes_read,
            "thread_count":s.thread_count,"source":"rustre_ttd::TraceStats::compute"
        }).to_string()))
    }
}

pub struct TtdMemoryMapFromTraceTool;
impl TtdMemoryMapFromTraceTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_memory_map_from_trace".to_string(),
            description: "Reconstruct MemoryMap from a synthetic trace via rustre_ttd::MemoryMap::from_trace.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdMemoryMapFromTraceTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let map = rustre_ttd::MemoryMap::from_trace(&trace);
        Ok(ToolResult::text(json!({"region_count":map.regions().len(),"source":"rustre_ttd::MemoryMap::from_trace"}).to_string()))
    }
}

pub struct TtdSyscallSummaryFromTraceTool;
impl TtdSyscallSummaryFromTraceTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_syscall_summary_from_trace".to_string(),
            description: "Build SyscallSummary via rustre_ttd::SyscallSummary::from_trace and return total_calls.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdSyscallSummaryFromTraceTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let s = rustre_ttd::SyscallSummary::from_trace(&trace);
        Ok(ToolResult::text(json!({"total_calls":s.total_calls(),"distinct_syscalls":s.by_nr.len(),"source":"rustre_ttd::SyscallSummary::from_trace"}).to_string()))
    }
}

pub struct TtdTraceExportImportRoundtripTool;
impl TtdTraceExportImportRoundtripTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_trace_export_import_roundtrip".to_string(),
            description: "Round-trip a synthetic trace via rustre_ttd::TraceExporter and TraceImporter.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdTraceExportImportRoundtripTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let s = rustre_ttd::TraceExporter::export_to_string(&trace).map_err(|e| McpError::InternalError(e.to_string()))?;
        let reimported = rustre_ttd::TraceImporter::import_from_str(&s).map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({"exported_bytes":s.len(),"reimported_event_count":reimported.event_count(),"source":"rustre_ttd::TraceExporter"}).to_string()))
    }
}

pub struct TtdCallStackFromTraceTool;
impl TtdCallStackFromTraceTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_call_stack_from_trace".to_string(),
            description: "Reconstruct CallStack for thread 0 via rustre_ttd::CallStack::from_trace at last position.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdCallStackFromTraceTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let last = trace.last_position().unwrap_or_else(rustre_ttd::TracePosition::start);
        let stack = rustre_ttd::CallStack::from_trace(&trace, 0, last);
        Ok(ToolResult::text(json!({"depth":stack.depth(),"source":"rustre_ttd::CallStack::from_trace"}).to_string()))
    }
}

pub struct TtdWatchpointFindHitsTool;
impl TtdWatchpointFindHitsTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_watchpoint_find_hits".to_string(),
            description: "Count Watchpoint hits in a synthetic trace via rustre_ttd::Watchpoint::find_hits.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"address":{"type":"integer"},"size":{"type":"integer"},"kind":{"type":"string"}},"required":["n","address","size"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdWatchpointFindHitsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let addr = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?;
        let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))?;
        let kind_s = args.get("kind").and_then(Value::as_str).unwrap_or("readwrite");
        let kind = match kind_s.to_ascii_lowercase().as_str() {
            "read" => rustre_ttd::WatchpointKind::Read,
            "write" => rustre_ttd::WatchpointKind::Write,
            _ => rustre_ttd::WatchpointKind::ReadWrite,
        };
        let trace = rustre_ttd::build_test_trace(n);
        let wp = rustre_ttd::Watchpoint::new(addr, size, kind);
        let hits = wp.find_hits(&trace);
        Ok(ToolResult::text(json!({"hits":hits.len(),"source":"rustre_ttd::Watchpoint::find_hits"}).to_string()))
    }
}

pub struct TtdTraceFilterApplyTool;
impl TtdTraceFilterApplyTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_trace_filter_apply_by_kind".to_string(),
            description: "Apply a ByKind TraceFilter to a synthetic trace via rustre_ttd::TraceFilter::apply.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"kind":{"type":"string"}},"required":["n","kind"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdTraceFilterApplyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let kind = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let events = trace.all_events();
        let f = rustre_ttd::TraceFilter::ByKind(kind.to_string());
        let matched = f.apply(&events);
        Ok(ToolResult::text(json!({"matched":matched.len(),"total":events.len(),"source":"rustre_ttd::TraceFilter::apply"}).to_string()))
    }
}

pub struct TtdIndexTotalEventCountTool;
impl TtdIndexTotalEventCountTool {
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_index_total_event_count".to_string(),
            description: "Index a synthetic trace and return total_event_count via rustre_ttd::TtdIndex.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdIndexTotalEventCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let trace = rustre_ttd::build_test_trace(n);
        let idx = rustre_ttd::TtdIndex::open_in_memory().map_err(|e| McpError::InternalError(e.to_string()))?;
        idx.index_trace(&trace).map_err(|e| McpError::InternalError(e.to_string()))?;
        let total = idx.total_event_count().map_err(|e| McpError::InternalError(e.to_string()))?;
        let by_kind = idx.event_count_by_kind().map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({"total":total,"distinct_kinds":by_kind.len(),"source":"rustre_ttd::TtdIndex::total_event_count"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TtdBuildTestTraceTool::definition(), Box::new(TtdBuildTestTraceTool)),
        (TtdBuildMultiThreadTraceTool::definition(), Box::new(TtdBuildMultiThreadTraceTool)),
        (TtdPositionMinTool::definition(), Box::new(TtdPositionMinTool)),
        (TtdPositionMaxTool::definition(), Box::new(TtdPositionMaxTool)),
        (TtdPositionEarliestTool::definition(), Box::new(TtdPositionEarliestTool)),
        (TtdTracePositionAsU128Tool::definition(), Box::new(TtdTracePositionAsU128Tool)),
        (TtdTracePositionFromU128Tool::definition(), Box::new(TtdTracePositionFromU128Tool)),
        (TtdTracePositionCompareTool::definition(), Box::new(TtdTracePositionCompareTool)),
        (TtdMemorySnapshotReadU32Tool::definition(), Box::new(TtdMemorySnapshotReadU32Tool)),
        (TtdMemorySnapshotContainsTool::definition(), Box::new(TtdMemorySnapshotContainsTool)),
        (TtdTraceEventCountTool::definition(), Box::new(TtdTraceEventCountTool)),
        (TtdTraceThreadIdsMultiTool::definition(), Box::new(TtdTraceThreadIdsMultiTool)),
        (TtdPositionNextStepTool::definition(), Box::new(TtdPositionNextStepTool)),
        (TtdPositionNextSequenceTool::definition(), Box::new(TtdPositionNextSequenceTool)),
        (TtdPositionInRangeTool::definition(), Box::new(TtdPositionInRangeTool)),
        (TtdMemorySnapshotReadU64Tool::definition(), Box::new(TtdMemorySnapshotReadU64Tool)),
        (TtdMemorySnapshotApplyWriteTool::definition(), Box::new(TtdMemorySnapshotApplyWriteTool)),
        (TtdMemoryRegionContainsTool::definition(), Box::new(TtdMemoryRegionContainsTool)),
        (TtdTraceStatsComputeTool::definition(), Box::new(TtdTraceStatsComputeTool)),
        (TtdMemoryMapFromTraceTool::definition(), Box::new(TtdMemoryMapFromTraceTool)),
        (TtdSyscallSummaryFromTraceTool::definition(), Box::new(TtdSyscallSummaryFromTraceTool)),
        (TtdTraceExportImportRoundtripTool::definition(), Box::new(TtdTraceExportImportRoundtripTool)),
        (TtdCallStackFromTraceTool::definition(), Box::new(TtdCallStackFromTraceTool)),
        (TtdWatchpointFindHitsTool::definition(), Box::new(TtdWatchpointFindHitsTool)),
        (TtdTraceFilterApplyTool::definition(), Box::new(TtdTraceFilterApplyTool)),
        (TtdIndexTotalEventCountTool::definition(), Box::new(TtdIndexTotalEventCountTool)),
    ]
}
