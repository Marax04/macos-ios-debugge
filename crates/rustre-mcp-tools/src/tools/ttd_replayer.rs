//! MCP wrappers for the rustre-ttd_replayer crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct TtdReplayerHexDumpTool;

pub struct TtdReplayerFormatTickTool;

pub struct TtdReplayerParseHexTool;

pub struct TtdReplayerBuildSyscallSummariesTool;

pub struct TtdReplayerScanForWritesTool;

pub struct TtdReplayerMemWriteInfoTool;
impl TtdReplayerMemWriteInfoTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_mem_write_info".to_string(),
            description: "Return size and end_addr of a MemWriteRecord via rustre_ttd_replayer::MemWriteRecord.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"data_len":{"type":"integer"}},"required":["addr","data_len"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerMemWriteInfoTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let data_len = args.get("data_len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'data_len'".into()))? as usize;
        let w = rustre_ttd_replayer::MemWriteRecord::new(addr, vec![0u8; data_len]);
        Ok(ToolResult::text(json!({"addr":w.addr,"size":w.size(),"end_addr":w.end_addr(),"source":"rustre_ttd_replayer::MemWriteRecord"}).to_string()))
    }
}

pub struct TtdReplayerMemWriteOverlapsTool;
impl TtdReplayerMemWriteOverlapsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_mem_write_overlaps".to_string(),
            description: "Test whether a MemWriteRecord overlaps a byte range via rustre_ttd_replayer::MemWriteRecord::overlaps.".to_string(),
            input_schema: json!({"type":"object","properties":{"write_addr":{"type":"integer"},"write_len":{"type":"integer"},"range_addr":{"type":"integer"},"range_size":{"type":"integer"}},"required":["write_addr","write_len","range_addr","range_size"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerMemWriteOverlapsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let wa = args.get("write_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'write_addr'".into()))?;
        let wl = args.get("write_len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'write_len'".into()))? as usize;
        let ra = args.get("range_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'range_addr'".into()))?;
        let rs = args.get("range_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'range_size'".into()))? as usize;
        let w = rustre_ttd_replayer::MemWriteRecord::new(wa, vec![0u8; wl]);
        Ok(ToolResult::text(json!({"overlaps":w.overlaps(ra,rs),"source":"rustre_ttd_replayer::MemWriteRecord::overlaps"}).to_string()))
    }
}

pub struct TtdReplayerTraceStatsTool;
impl TtdReplayerTraceStatsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_trace_stats".to_string(),
            description: "Compute aggregate TraceStats over a synthetic trace via rustre_ttd_replayer::TraceStats::compute.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerTraceStatsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_ttd_replayer::{TraceBuilder, MemWriteRecord, DEFAULT_SNAPSHOT_INTERVAL, TraceStats};
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(8);
        let mut b = TraceBuilder::new(DEFAULT_SNAPSHOT_INTERVAL);
        for i in 0..n { b.syscall_entry(i % 4, [0;6]); b.syscall_exit(0, vec![MemWriteRecord::new(0x2000 + i*4, vec![0u8;4])]); }
        let s = TraceStats::compute(&b.build());
        Ok(ToolResult::text(json!({"total_events":s.total_events,"syscall_entries":s.syscall_entries,"syscall_exits":s.syscall_exits,"signals":s.signals,"total_bytes_written":s.total_bytes_written,"min_tick":s.min_tick,"max_tick":s.max_tick,"snapshot_count":s.snapshot_count,"source":"rustre_ttd_replayer::TraceStats::compute"}).to_string()))
    }
}

pub struct TtdReplayerEventCountsTool;
impl TtdReplayerEventCountsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_event_counts".to_string(),
            description: "Count events grouped by kind via rustre_ttd_replayer::TtdTrace::event_counts.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerEventCountsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_ttd_replayer::{TraceBuilder, DEFAULT_SNAPSHOT_INTERVAL};
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(4);
        let mut b = TraceBuilder::new(DEFAULT_SNAPSHOT_INTERVAL);
        for i in 0..n { b.syscall_entry(i,[0;6]); b.syscall_exit(0,vec![]); b.signal(9,0xdead); }
        let counts = b.build().event_counts();
        let map: serde_json::Map<String,Value> = counts.into_iter().map(|(k,v)| (k.to_string(), Value::from(v))).collect();
        Ok(ToolResult::text(json!({"counts":Value::Object(map),"source":"rustre_ttd_replayer::TtdTrace::event_counts"}).to_string()))
    }
}

pub struct TtdReplayerTraceTickBoundsTool;
impl TtdReplayerTraceTickBoundsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_trace_tick_bounds".to_string(),
            description: "Return min_tick, max_tick and event count via rustre_ttd_replayer::TtdTrace.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerTraceTickBoundsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_ttd_replayer::{TraceBuilder, DEFAULT_SNAPSHOT_INTERVAL};
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(8);
        let mut b = TraceBuilder::new(DEFAULT_SNAPSHOT_INTERVAL);
        for i in 0..n { b.syscall_entry(i,[0;6]); }
        let t = b.build();
        Ok(ToolResult::text(json!({"min_tick":t.min_tick(),"max_tick":t.max_tick(),"len":t.len(),"is_empty":t.is_empty(),"source":"rustre_ttd_replayer::TtdTrace"}).to_string()))
    }
}

pub struct TtdReplayerQueryParseKindTool;
impl TtdReplayerQueryParseKindTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_query_parse_kind".to_string(),
            description: "Parse a TTD query DSL string and return the AST variant name via rustre_ttd_replayer::TtdQuery::parse.".to_string(),
            input_schema: json!({"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerQueryParseKindTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let q = args.get("query").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'query'".into()))?;
        match rustre_ttd_replayer::TtdQuery::parse(q) {
            Ok(qq) => {
                let kind = match qq.ast {
                    rustre_ttd_replayer::QueryAst::ReadMem{..} => "ReadMem",
                    rustre_ttd_replayer::QueryAst::FindWrites{..} => "FindWrites",
                    rustre_ttd_replayer::QueryAst::LastWrite{..} => "LastWrite",
                    rustre_ttd_replayer::QueryAst::ListSyscalls{..} => "ListSyscalls",
                    rustre_ttd_replayer::QueryAst::ListSignals => "ListSignals",
                    rustre_ttd_replayer::QueryAst::ReadReg{..} => "ReadReg",
                    rustre_ttd_replayer::QueryAst::CountEvents{..} => "CountEvents",
                    rustre_ttd_replayer::QueryAst::RootCause{..} => "RootCause",
                    rustre_ttd_replayer::QueryAst::MaxTick => "MaxTick",
                    rustre_ttd_replayer::QueryAst::MinTick => "MinTick",
                };
                Ok(ToolResult::text(json!({"ok":true,"kind":kind,"source":"rustre_ttd_replayer::TtdQuery::parse"}).to_string()))
            }
            Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string(),"source":"rustre_ttd_replayer::TtdQuery::parse"}).to_string())),
        }
    }
}

pub struct TtdReplayerQueryExecuteTickTool;
impl TtdReplayerQueryExecuteTickTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_query_execute_tick".to_string(),
            description: "Execute a max_tick/min_tick DSL query against a synthetic replayer via rustre_ttd_replayer::TtdQuery::execute.".to_string(),
            input_schema: json!({"type":"object","properties":{"query":{"type":"string"},"n":{"type":"integer"}},"required":["query"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerQueryExecuteTickTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_ttd_replayer::{TraceBuilder, DEFAULT_SNAPSHOT_INTERVAL, TtdReplayer, TtdQuery};
        let q = args.get("query").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'query'".into()))?;
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(6);
        let mut b = TraceBuilder::new(DEFAULT_SNAPSHOT_INTERVAL);
        for i in 0..n { b.syscall_entry(i,[0;6]); }
        let mut r = TtdReplayer::new(b.build());
        let parsed = TtdQuery::parse(q).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        let val = parsed.execute(&mut r).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({"value":val.to_string(),"source":"rustre_ttd_replayer::TtdQuery::execute"}).to_string()))
    }
}

pub struct TtdReplayerFindRootCauseTool;
impl TtdReplayerFindRootCauseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_find_root_cause".to_string(),
            description: "Run backward causal analysis on a synthetic trace via rustre_ttd_replayer::find_root_cause.".to_string(),
            input_schema: json!({"type":"object","properties":{"crash_addr":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerFindRootCauseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_ttd_replayer::{TraceBuilder, DEFAULT_SNAPSHOT_INTERVAL, MemWriteRecord, TtdReplayer, find_root_cause};
        let addr = args.get("crash_addr").and_then(Value::as_u64).unwrap_or(0x1000);
        let mut b = TraceBuilder::new(DEFAULT_SNAPSHOT_INTERVAL);
        b.syscall_entry(1,[0;6]);
        b.syscall_exit(0, vec![MemWriteRecord::new(addr, vec![0xAA;8])]);
        b.syscall_entry(2,[0;6]);
        b.syscall_exit(0, vec![]);
        b.signal(11, addr);
        let trace = b.build();
        let crash_tick = trace.max_tick();
        let mut r = TtdReplayer::new(trace);
        let report = find_root_cause(&mut r, crash_tick, addr).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({"crash_tick":report.crash_tick,"crash_addr":report.crash_addr,"chain_len":report.chain.len(),"confidence":report.confidence,"summary":report.summary,"source":"rustre_ttd_replayer::find_root_cause"}).to_string()))
    }
}

pub struct TtdReplayerStepForwardTool;
impl TtdReplayerStepForwardTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_step_forward".to_string(),
            description: "Advance a synthetic replayer by one event via rustre_ttd_replayer::TtdReplayer::step_forward.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerStepForwardTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_ttd_replayer::{TraceBuilder, DEFAULT_SNAPSHOT_INTERVAL, TtdReplayer};
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(4);
        let mut b = TraceBuilder::new(DEFAULT_SNAPSHOT_INTERVAL);
        for i in 0..n { b.syscall_entry(i,[0;6]); }
        let mut r = TtdReplayer::new(b.build());
        let kind = r.step_forward().map(|e| e.kind_name()).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({"applied_kind":kind,"current_tick":r.current_tick,"at_end":r.at_end(),"at_start":r.at_start(),"remaining_events":r.remaining_events(),"source":"rustre_ttd_replayer::TtdReplayer::step_forward"}).to_string()))
    }
}

pub struct TtdReplayerGotoTool;
impl TtdReplayerGotoTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_goto".to_string(),
            description: "Seek a synthetic replayer to a target tick via rustre_ttd_replayer::TtdReplayer::goto.".to_string(),
            input_schema: json!({"type":"object","properties":{"tick":{"type":"integer"},"n":{"type":"integer"}},"required":["tick"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerGotoTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_ttd_replayer::{TraceBuilder, DEFAULT_SNAPSHOT_INTERVAL, MemWriteRecord, TtdReplayer};
        let tick = args.get("tick").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'tick'".into()))?;
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(8);
        let mut b = TraceBuilder::new(DEFAULT_SNAPSHOT_INTERVAL);
        for i in 0..n { b.syscall_entry(i,[0;6]); b.syscall_exit(0, vec![MemWriteRecord::new(0x4000 + i*8, vec![i as u8; 8])]); }
        let mut r = TtdReplayer::new(b.build());
        let res = r.goto(tick);
        Ok(ToolResult::text(json!({"ok":res.is_ok(),"error":res.err().map(|e| e.to_string()),"current_tick":r.current_tick,"footprint":r.state.footprint(),"pc":r.pc(),"source":"rustre_ttd_replayer::TtdReplayer::goto"}).to_string()))
    }
}

pub struct TtdReplayerReplayStateFootprintTool;
impl TtdReplayerReplayStateFootprintTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_replay_state_footprint".to_string(),
            description: "Apply a synthetic write to a fresh ReplayState and report footprint via rustre_ttd_replayer::ReplayState::footprint.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"size":{"type":"integer"}},"required":["addr","size"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerReplayStateFootprintTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_ttd_replayer::{ReplayState, MemWriteRecord};
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as usize;
        let mut s = ReplayState::new();
        s.set_reg("rip", 0x400000);
        s.apply_write(&MemWriteRecord::new(addr, vec![0xCC; size]));
        let read = s.read(addr, size.min(16));
        Ok(ToolResult::text(json!({"footprint":s.footprint(),"pc":s.program_counter(),"read_ok":read.is_some(),"source":"rustre_ttd_replayer::ReplayState"}).to_string()))
    }
}

pub struct TtdReplayerSnapshotBoundaryTool;
impl TtdReplayerSnapshotBoundaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_snapshot_boundary".to_string(),
            description: "Report whether the next emitted tick lands on a snapshot boundary via rustre_ttd_replayer::TraceBuilder::next_tick_is_snapshot_boundary.".to_string(),
            input_schema: json!({"type":"object","properties":{"interval":{"type":"integer"},"advance":{"type":"integer"}},"required":["interval"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerSnapshotBoundaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_ttd_replayer::TraceBuilder;
        let interval = args.get("interval").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'interval'".into()))?;
        let advance = args.get("advance").and_then(Value::as_u64).unwrap_or(0);
        let mut b = TraceBuilder::new(interval);
        for i in 0..advance { b.syscall_entry(i,[0;6]); }
        Ok(ToolResult::text(json!({"snapshot_interval":b.snapshot_interval(),"next_is_boundary":b.next_tick_is_snapshot_boundary(),"source":"rustre_ttd_replayer::TraceBuilder"}).to_string()))
    }
}

pub struct TtdReplayerMemWriteBytesInRangeTool;
impl TtdReplayerMemWriteBytesInRangeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_mem_write_bytes_in_range".to_string(),
            description: "Return len of overlap bytes between a MemWriteRecord and a range via rustre_ttd_replayer::MemWriteRecord::bytes_in_range.".to_string(),
            input_schema: json!({"type":"object","properties":{"write_addr":{"type":"integer"},"write_len":{"type":"integer"},"range_addr":{"type":"integer"},"range_size":{"type":"integer"}},"required":["write_addr","write_len","range_addr","range_size"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerMemWriteBytesInRangeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let wa = args.get("write_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'write_addr'".into()))?;
        let wl = args.get("write_len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'write_len'".into()))? as usize;
        let ra = args.get("range_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'range_addr'".into()))?;
        let rs = args.get("range_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'range_size'".into()))? as usize;
        let data: Vec<u8> = (0..wl).map(|i| i as u8).collect();
        let w = rustre_ttd_replayer::MemWriteRecord::new(wa, data);
        let bytes = w.bytes_in_range(ra, rs);
        Ok(ToolResult::text(json!({"len":bytes.len(),"source":"rustre_ttd_replayer::MemWriteRecord::bytes_in_range"}).to_string()))
    }
}

pub struct TtdReplayerTraceMinMaxTickTool;
impl TtdReplayerTraceMinMaxTickTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_trace_min_max_tick".to_string(),
            description: "Return min_tick, max_tick, len, is_empty of a synthetic TtdTrace via rustre_ttd_replayer::TtdTrace.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerTraceMinMaxTickTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_ttd_replayer::{TraceBuilder, DEFAULT_SNAPSHOT_INTERVAL};
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(4);
        let mut b = TraceBuilder::new(DEFAULT_SNAPSHOT_INTERVAL);
        for i in 0..n { b.syscall_entry(i,[0;6]); b.syscall_exit(0, vec![]); }
        let t = b.build();
        Ok(ToolResult::text(json!({"min_tick":t.min_tick(),"max_tick":t.max_tick(),"len":t.len(),"is_empty":t.is_empty(),"source":"rustre_ttd_replayer::TtdTrace"}).to_string()))
    }
}

pub struct TtdReplayerReplayStateProgramCounterTool;
impl TtdReplayerReplayStateProgramCounterTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_replay_state_program_counter".to_string(),
            description: "Set rip/pc/eip on a ReplayState and read program_counter via rustre_ttd_replayer::ReplayState::program_counter.".to_string(),
            input_schema: json!({"type":"object","properties":{"reg":{"type":"string"},"value":{"type":"integer"}},"required":["reg","value"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerReplayStateProgramCounterTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let reg = args.get("reg").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'reg'".into()))?.to_string();
        let val = args.get("value").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let mut s = rustre_ttd_replayer::ReplayState::new();
        s.set_reg(reg.clone(), val);
        let pc = s.program_counter();
        let rv = s.reg(&reg);
        Ok(ToolResult::text(json!({"pc":pc,"reg":reg,"reg_val":rv,"footprint":s.footprint(),"source":"rustre_ttd_replayer::ReplayState::program_counter"}).to_string()))
    }
}

pub struct TtdReplayerReplayStateApplyWriteTool;
impl TtdReplayerReplayStateApplyWriteTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_replay_state_apply_write".to_string(),
            description: "Apply a MemWriteRecord to ReplayState then read it back via rustre_ttd_replayer::ReplayState::apply_write+read.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"data_len":{"type":"integer"}},"required":["addr","data_len"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerReplayStateApplyWriteTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let len = args.get("data_len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'data_len'".into()))? as usize;
        let data: Vec<u8> = (0..len).map(|i| (i & 0xff) as u8).collect();
        let mut s = rustre_ttd_replayer::ReplayState::new();
        let wr = rustre_ttd_replayer::MemWriteRecord::new(addr, data);
        s.apply_write(&wr);
        let read = s.read(addr, len);
        Ok(ToolResult::text(json!({"written":len,"read_len":read.as_ref().map(|v| v.len()),"source":"rustre_ttd_replayer::ReplayState::apply_write"}).to_string()))
    }
}

pub struct TtdReplayerSnapshotPageCountTool;
impl TtdReplayerSnapshotPageCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_snapshot_page_count".to_string(),
            description: "Write data into a TraceSnapshot and return page_count/memory_footprint via rustre_ttd_replayer::TraceSnapshot.".to_string(),
            input_schema: json!({"type":"object","properties":{"tick":{"type":"integer"},"addr":{"type":"integer"},"data_len":{"type":"integer"}},"required":["tick","addr","data_len"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerSnapshotPageCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let tick = args.get("tick").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'tick'".into()))?;
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let len = args.get("data_len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'data_len'".into()))? as usize;
        let data: Vec<u8> = vec![0xAB; len];
        let mut snap = rustre_ttd_replayer::TraceSnapshot::new(tick);
        snap.write_mem(addr, &data);
        snap.set_reg("rip", addr);
        let read = snap.read_mem(addr, len);
        Ok(ToolResult::text(json!({"tick":snap.tick,"page_count":snap.page_count(),"memory_footprint":snap.memory_footprint(),"rip":snap.get_reg("rip"),"read_ok":read.is_some(),"source":"rustre_ttd_replayer::TraceSnapshot"}).to_string()))
    }
}

pub struct TtdReplayerTraceAllWritesTouchingTool;
impl TtdReplayerTraceAllWritesTouchingTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_trace_all_writes_touching".to_string(),
            description: "Count writes overlapping a range across all events via rustre_ttd_replayer::TtdTrace::all_writes_touching.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"addr":{"type":"integer"},"size":{"type":"integer"}},"required":["addr","size"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerTraceAllWritesTouchingTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_ttd_replayer::{TraceBuilder, MemWriteRecord, DEFAULT_SNAPSHOT_INTERVAL};
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(8);
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as usize;
        let mut b = TraceBuilder::new(DEFAULT_SNAPSHOT_INTERVAL);
        for i in 0..n {
            b.syscall_entry(i,[0;6]);
            b.syscall_exit(0, vec![MemWriteRecord::new(addr + i*2, vec![0u8;4])]);
        }
        let t = b.build();
        let hits = t.all_writes_touching(addr, size);
        Ok(ToolResult::text(json!({"hit_count":hits.len(),"source":"rustre_ttd_replayer::TtdTrace::all_writes_touching"}).to_string()))
    }
}

pub struct TtdReplayerTraceEventIndexQueryTool;
impl TtdReplayerTraceEventIndexQueryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_trace_event_index_query".to_string(),
            description: "Query first_event_at_or_after and last_event_at_or_before via rustre_ttd_replayer::TtdTrace.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"},"target":{"type":"integer"}},"required":["target"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerTraceEventIndexQueryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_ttd_replayer::{TraceBuilder, DEFAULT_SNAPSHOT_INTERVAL};
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(8);
        let target = args.get("target").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'target'".into()))?;
        let mut b = TraceBuilder::new(DEFAULT_SNAPSHOT_INTERVAL);
        for i in 0..n { b.syscall_entry(i,[0;6]); b.syscall_exit(0, vec![]); }
        let t = b.build();
        Ok(ToolResult::text(json!({"first_at_or_after":t.first_event_at_or_after(target),"last_at_or_before":t.last_event_at_or_before(target),"source":"rustre_ttd_replayer::TtdTrace"}).to_string()))
    }
}

pub struct TtdReplayerNearestSnapshotBeforeTool;
impl TtdReplayerNearestSnapshotBeforeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_nearest_snapshot_before".to_string(),
            description: "Return tick of the nearest snapshot at or before target via rustre_ttd_replayer::TtdTrace::nearest_snapshot_before.".to_string(),
            input_schema: json!({"type":"object","properties":{"snap_ticks":{"type":"array","items":{"type":"integer"}},"target":{"type":"integer"}},"required":["snap_ticks","target"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerNearestSnapshotBeforeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ticks: Vec<u64> = args.get("snap_ticks").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect())
            .unwrap_or_default();
        let target = args.get("target").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'target'".into()))?;
        let mut t = rustre_ttd_replayer::TtdTrace::new();
        for st in &ticks {
            t.push_snapshot(rustre_ttd_replayer::TraceSnapshot::new(*st));
        }
        let found = t.nearest_snapshot_before(target).map(|s| s.tick);
        Ok(ToolResult::text(json!({"found_tick":found,"snapshot_count":ticks.len(),"source":"rustre_ttd_replayer::TtdTrace::nearest_snapshot_before"}).to_string()))
    }
}

pub struct TtdReplayerCausalStepBuildTool;
impl TtdReplayerCausalStepBuildTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_causal_step_build".to_string(),
            description: "Build a CausalStep with_addr and with_data via rustre_ttd_replayer::CausalStep.".to_string(),
            input_schema: json!({"type":"object","properties":{"tick":{"type":"integer"},"description":{"type":"string"},"addr":{"type":"integer"},"data_len":{"type":"integer"}},"required":["tick","description"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerCausalStepBuildTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let tick = args.get("tick").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'tick'".into()))?;
        let desc = args.get("description").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'description'".into()))?.to_string();
        let addr = args.get("addr").and_then(Value::as_u64);
        let data_len = args.get("data_len").and_then(Value::as_u64).unwrap_or(0) as usize;
        let mut step = rustre_ttd_replayer::CausalStep::new(tick, desc);
        if let Some(a) = addr { step = step.with_addr(a); }
        if data_len > 0 { step = step.with_data(vec![0u8; data_len]); }
        Ok(ToolResult::text(json!({"tick":step.tick,"description":step.description,"addr":step.addr,"data_len":step.data.as_ref().map(|d| d.len()),"source":"rustre_ttd_replayer::CausalStep"}).to_string()))
    }
}

pub struct TtdReplayerRootCauseReportBuildTool;
impl TtdReplayerRootCauseReportBuildTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ttd_replayer_root_cause_report_build".to_string(),
            description: "Build a RootCauseReport, push steps and query earliest_cause via rustre_ttd_replayer::RootCauseReport.".to_string(),
            input_schema: json!({"type":"object","properties":{"crash_tick":{"type":"integer"},"crash_addr":{"type":"integer"},"steps":{"type":"integer"}},"required":["crash_tick","crash_addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TtdReplayerRootCauseReportBuildTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ct = args.get("crash_tick").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'crash_tick'".into()))?;
        let ca = args.get("crash_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'crash_addr'".into()))?;
        let steps = args.get("steps").and_then(Value::as_u64).unwrap_or(3);
        let mut r = rustre_ttd_replayer::RootCauseReport::new(ct, ca);
        for i in 0..steps {
            r.push_step(rustre_ttd_replayer::CausalStep::new(ct.saturating_sub(i+1), format!("step-{i}")));
        }
        let earliest_tick = r.earliest_cause().map(|s| s.tick);
        Ok(ToolResult::text(json!({"chain_len":r.chain.len(),"earliest_tick":earliest_tick,"crash_tick":r.crash_tick,"crash_addr":r.crash_addr,"source":"rustre_ttd_replayer::RootCauseReport"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TtdReplayerHexDumpTool::definition(), Box::new(TtdReplayerHexDumpTool)),
        (TtdReplayerFormatTickTool::definition(), Box::new(TtdReplayerFormatTickTool)),
        (TtdReplayerParseHexTool::definition(), Box::new(TtdReplayerParseHexTool)),
        (TtdReplayerBuildSyscallSummariesTool::definition(), Box::new(TtdReplayerBuildSyscallSummariesTool)),
        (TtdReplayerScanForWritesTool::definition(), Box::new(TtdReplayerScanForWritesTool)),
        (TtdReplayerMemWriteInfoTool::definition(), Box::new(TtdReplayerMemWriteInfoTool)),
        (TtdReplayerMemWriteOverlapsTool::definition(), Box::new(TtdReplayerMemWriteOverlapsTool)),
        (TtdReplayerTraceStatsTool::definition(), Box::new(TtdReplayerTraceStatsTool)),
        (TtdReplayerEventCountsTool::definition(), Box::new(TtdReplayerEventCountsTool)),
        (TtdReplayerTraceTickBoundsTool::definition(), Box::new(TtdReplayerTraceTickBoundsTool)),
        (TtdReplayerQueryParseKindTool::definition(), Box::new(TtdReplayerQueryParseKindTool)),
        (TtdReplayerQueryExecuteTickTool::definition(), Box::new(TtdReplayerQueryExecuteTickTool)),
        (TtdReplayerFindRootCauseTool::definition(), Box::new(TtdReplayerFindRootCauseTool)),
        (TtdReplayerStepForwardTool::definition(), Box::new(TtdReplayerStepForwardTool)),
        (TtdReplayerGotoTool::definition(), Box::new(TtdReplayerGotoTool)),
        (TtdReplayerReplayStateFootprintTool::definition(), Box::new(TtdReplayerReplayStateFootprintTool)),
        (TtdReplayerSnapshotBoundaryTool::definition(), Box::new(TtdReplayerSnapshotBoundaryTool)),
        (TtdReplayerMemWriteBytesInRangeTool::definition(), Box::new(TtdReplayerMemWriteBytesInRangeTool)),
        (TtdReplayerTraceMinMaxTickTool::definition(), Box::new(TtdReplayerTraceMinMaxTickTool)),
        (TtdReplayerReplayStateProgramCounterTool::definition(), Box::new(TtdReplayerReplayStateProgramCounterTool)),
        (TtdReplayerReplayStateApplyWriteTool::definition(), Box::new(TtdReplayerReplayStateApplyWriteTool)),
        (TtdReplayerSnapshotPageCountTool::definition(), Box::new(TtdReplayerSnapshotPageCountTool)),
        (TtdReplayerTraceAllWritesTouchingTool::definition(), Box::new(TtdReplayerTraceAllWritesTouchingTool)),
        (TtdReplayerTraceEventIndexQueryTool::definition(), Box::new(TtdReplayerTraceEventIndexQueryTool)),
        (TtdReplayerNearestSnapshotBeforeTool::definition(), Box::new(TtdReplayerNearestSnapshotBeforeTool)),
        (TtdReplayerCausalStepBuildTool::definition(), Box::new(TtdReplayerCausalStepBuildTool)),
        (TtdReplayerRootCauseReportBuildTool::definition(), Box::new(TtdReplayerRootCauseReportBuildTool)),
    ]
}
