//! MCP wrappers for the rustre-ttd_query crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct TtdQueryParseTool;

pub struct TtdQueryCallTreeTool;

pub struct TtdQueryMemoryReportTool;

pub struct TtdQueryCallFrequencyTool;
impl TtdQueryCallFrequencyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_call_frequency".to_string(), description: "Call-frequency histogram from synthetic query test trace.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryCallFrequencyTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t); let f=e.analyze_call_frequency(); let it: Vec<Value>=f.into_iter().map(|(a,c)| json!({"addr":a,"count":c})).collect(); Ok(ToolResult::text(json!({"items":it,"source":"rustre_ttd_query::QueryEngine::analyze_call_frequency"}).to_string())) } }

pub struct TtdQueryMostCalledTool;
impl TtdQueryMostCalledTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_most_called".to_string(), description: "Top-N most-called functions.".to_string(), input_schema: json!({"type":"object","properties":{"top_n":{"type":"integer"}},"required":["top_n"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryMostCalledTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n=args.get("top_n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'top_n'".into()))? as usize; let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t); let v=e.most_called_functions(n); let it: Vec<Value>=v.into_iter().map(|(a,c)| json!({"addr":a,"count":c})).collect(); Ok(ToolResult::text(json!({"top_n":n,"items":it,"source":"rustre_ttd_query::QueryEngine::most_called_functions"}).to_string())) } }

pub struct TtdQueryMostAccessedAddressesTool;
impl TtdQueryMostAccessedAddressesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_most_accessed_addresses".to_string(), description: "Top-N most-accessed addresses.".to_string(), input_schema: json!({"type":"object","properties":{"top_n":{"type":"integer"}},"required":["top_n"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryMostAccessedAddressesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n=args.get("top_n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'top_n'".into()))? as usize; let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t); let v=e.most_accessed_addresses(n); let it: Vec<Value>=v.into_iter().map(|(a,c)| json!({"addr":a,"count":c})).collect(); Ok(ToolResult::text(json!({"top_n":n,"items":it,"source":"rustre_ttd_query::QueryEngine::most_accessed_addresses"}).to_string())) } }

pub struct TtdQueryHistogramByKindTool;
impl TtdQueryHistogramByKindTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_histogram_by_kind".to_string(), description: "Event-kind histogram.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryHistogramByKindTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t); let h=e.event_histogram_by_kind(); Ok(ToolResult::text(json!({"histogram":h,"source":"rustre_ttd_query::QueryEngine::event_histogram_by_kind"}).to_string())) } }

pub struct TtdQueryHistogramByThreadTool;
impl TtdQueryHistogramByThreadTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_histogram_by_thread".to_string(), description: "Per-thread event histogram.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryHistogramByThreadTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t); let h=e.event_histogram_by_thread(); let it: Vec<Value>=h.into_iter().map(|(tid,c)| json!({"tid":tid,"count":c})).collect(); Ok(ToolResult::text(json!({"items":it,"source":"rustre_ttd_query::QueryEngine::event_histogram_by_thread"}).to_string())) } }

pub struct TtdQueryRecursiveCallsTool;
impl TtdQueryRecursiveCallsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_recursive_calls".to_string(), description: "Detect recursive call chains.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryRecursiveCallsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t); let ch=e.find_recursive_calls(); let it: Vec<Value>=ch.into_iter().map(|c| json!({"addr":c.address,"max_depth":c.max_depth,"count":c.recursion_positions.len()})).collect(); Ok(ToolResult::text(json!({"chains":it,"source":"rustre_ttd_query::QueryEngine::find_recursive_calls"}).to_string())) } }

pub struct TtdQueryDataRacesTool;
impl TtdQueryDataRacesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_data_races".to_string(), description: "Heuristic data-race detection.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryDataRacesTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t); let r=e.find_data_races_heuristic(); let it: Vec<Value>=r.into_iter().map(|c| json!({"addr":c.address,"threads":c.threads,"writes":c.write_positions.len(),"confidence":c.confidence})).collect(); Ok(ToolResult::text(json!({"candidates":it,"source":"rustre_ttd_query::QueryEngine::find_data_races_heuristic"}).to_string())) } }

pub struct TtdQueryHeapOpsTool;
impl TtdQueryHeapOpsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_heap_ops".to_string(), description: "Heap alloc/free heuristic detection.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryHeapOpsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t); let r=e.detect_heap_operations(); Ok(ToolResult::text(json!({"total_allocs":r.total_allocs,"total_frees":r.total_frees,"source":"rustre_ttd_query::QueryEngine::detect_heap_operations"}).to_string())) } }

pub struct TtdQueryStringAccessesTool;
impl TtdQueryStringAccessesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_string_accesses".to_string(), description: "String-like memory accesses.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryStringAccessesTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t); let v=e.find_string_accesses(); let it: Vec<Value>=v.into_iter().map(|s| json!({"addr":s.address,"content":s.content,"accesses":s.access_positions.len()})).collect(); Ok(ToolResult::text(json!({"strings":it,"source":"rustre_ttd_query::QueryEngine::find_string_accesses"}).to_string())) } }

pub struct TtdQuerySyscallSummaryTool;
impl TtdQuerySyscallSummaryTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_syscall_summary".to_string(), description: "Syscall call/error summary.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQuerySyscallSummaryTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t); let m=e.summarize_syscalls(); let it: Vec<Value>=m.into_iter().map(|(nr,s)| json!({"nr":nr,"calls":s.call_count,"errors":s.error_count})).collect(); Ok(ToolResult::text(json!({"syscalls":it,"source":"rustre_ttd_query::QueryEngine::summarize_syscalls"}).to_string())) } }

pub struct TtdQueryMemoryAccessReportTool;
impl TtdQueryMemoryAccessReportTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_memory_access_report".to_string(), description: "Memory access analysis for [start,end).".to_string(), input_schema: json!({"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"}},"required":["start","end"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryMemoryAccessReportTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s=args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))?; let en=args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'end'".into()))?; let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t); let r=e.analyze_memory_access_patterns(s,en); Ok(ToolResult::text(json!({"total_reads":r.total_reads,"total_writes":r.total_writes,"total_read_bytes":r.total_read_bytes,"total_write_bytes":r.total_write_bytes,"source":"rustre_ttd_query::QueryEngine::analyze_memory_access_patterns"}).to_string())) } }

pub struct TtdQueryHistogramOverTimeTool;
impl TtdQueryHistogramOverTimeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_histogram_over_time".to_string(), description: "Bucket events by sequence-bucket size.".to_string(), input_schema: json!({"type":"object","properties":{"bucket_size":{"type":"integer"}},"required":["bucket_size"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryHistogramOverTimeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let bs=args.get("bucket_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'bucket_size'".into()))?; let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t); let v=e.event_histogram_over_time(bs); let it: Vec<Value>=v.into_iter().map(|(p,c)| json!({"sequence":p.sequence,"count":c})).collect(); Ok(ToolResult::text(json!({"bucket_size":bs,"buckets":it,"source":"rustre_ttd_query::QueryEngine::event_histogram_over_time"}).to_string())) } }

pub struct TtdQueryTraceEventCountTool;
impl TtdQueryTraceEventCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_trace_event_count".to_string(), description: "Total event count in synthetic query test trace.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryTraceEventCountTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let t=rustre_ttd_query::build_query_test_trace(); let n=t.event_count(); Ok(ToolResult::text(json!({"event_count":n,"source":"rustre_ttd_query::build_query_test_trace"}).to_string())) } }

pub struct TtdQueryCodeCoverageTool;
impl TtdQueryCodeCoverageTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_code_coverage".to_string(), description: "Compute code coverage for given [start,end) ranges.".to_string(), input_schema: json!({"type":"object","properties":{"ranges":{"type":"array"}},"required":["ranges"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryCodeCoverageTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let arr = args.get("ranges").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'ranges'".into()))?;
    let ranges: Vec<(u64,u64)> = arr.iter().filter_map(|v| { let a=v.as_array()?; Some((a.first()?.as_u64()?, a.get(1)?.as_u64()?)) }).collect();
    let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t);
    let r=e.compute_code_coverage(&ranges);
    Ok(ToolResult::text(json!({"total_range_bytes":r.total_range_bytes,"covered":r.covered_addresses,"pct":r.coverage_percentage,"source":"rustre_ttd_query::QueryEngine::compute_code_coverage"}).to_string()))
} }

pub struct TtdQueryFilterByAddressRangeTool;
impl TtdQueryFilterByAddressRangeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_filter_by_address_range".to_string(), description: "Return mem events in [start,end).".to_string(), input_schema: json!({"type":"object","properties":{"start":{"type":"integer"},"end":{"type":"integer"}},"required":["start","end"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryFilterByAddressRangeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let s=args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))?;
    let en=args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'end'".into()))?;
    let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t);
    let v=e.filter_by_address_range(s,en);
    Ok(ToolResult::text(json!({"count":v.len(),"source":"rustre_ttd_query::QueryEngine::filter_by_address_range"}).to_string()))
} }

pub struct TtdQueryFirstOccurrenceThreadTool;
impl TtdQueryFirstOccurrenceThreadTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_first_occurrence_thread".to_string(), description: "First event on given thread via QueryFilter::Thread.".to_string(), input_schema: json!({"type":"object","properties":{"tid":{"type":"integer"}},"required":["tid"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryFirstOccurrenceThreadTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let tid=args.get("tid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'tid'".into()))? as u32;
    let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t);
    let f=rustre_ttd_query::QueryFilter::Thread{tid};
    let ev=e.first_occurrence(&f);
    Ok(ToolResult::text(json!({"found":ev.is_some(),"source":"rustre_ttd_query::QueryEngine::first_occurrence"}).to_string()))
} }

pub struct TtdQueryLastOccurrenceThreadTool;
impl TtdQueryLastOccurrenceThreadTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_last_occurrence_thread".to_string(), description: "Last event on given thread via QueryFilter::Thread.".to_string(), input_schema: json!({"type":"object","properties":{"tid":{"type":"integer"}},"required":["tid"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryLastOccurrenceThreadTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let tid=args.get("tid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'tid'".into()))? as u32;
    let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t);
    let f=rustre_ttd_query::QueryFilter::Thread{tid};
    let ev=e.last_occurrence(&f);
    Ok(ToolResult::text(json!({"found":ev.is_some(),"source":"rustre_ttd_query::QueryEngine::last_occurrence"}).to_string()))
} }

pub struct TtdQueryCountThreadTool;
impl TtdQueryCountThreadTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_count_thread".to_string(), description: "Count events on given thread via QueryFilter::Thread.".to_string(), input_schema: json!({"type":"object","properties":{"tid":{"type":"integer"}},"required":["tid"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryCountThreadTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let tid=args.get("tid").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'tid'".into()))? as u32;
    let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t);
    let f=rustre_ttd_query::QueryFilter::Thread{tid};
    let n=e.count(&f);
    Ok(ToolResult::text(json!({"count":n,"source":"rustre_ttd_query::QueryEngine::count"}).to_string()))
} }

pub struct TtdQueryExecAllEventsTool;
impl TtdQueryExecAllEventsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_exec_all_events".to_string(), description: "Execute Query::AllEvents on synthetic trace.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryExecAllEventsTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t);
    let r=e.execute(&rustre_ttd_query::Query::AllEvents);
    Ok(ToolResult::text(json!({"matched":r.len(),"scanned":r.events_scanned,"time_ms":r.execution_time_ms,"source":"rustre_ttd_query::QueryEngine::execute"}).to_string()))
} }

pub struct TtdQueryExecLoopsTool;
impl TtdQueryExecLoopsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_exec_loops".to_string(), description: "Execute Query::Loops with min_iterations.".to_string(), input_schema: json!({"type":"object","properties":{"min_iterations":{"type":"integer"}},"required":["min_iterations"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryExecLoopsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let m=args.get("min_iterations").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'min_iterations'".into()))? as u32;
    let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t);
    let r=e.execute(&rustre_ttd_query::Query::Loops{min_iterations:m});
    Ok(ToolResult::text(json!({"matched":r.len(),"source":"rustre_ttd_query::QueryEngine::execute"}).to_string()))
} }

pub struct TtdQueryExecCallChainTool;
impl TtdQueryExecCallChainTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_exec_call_chain".to_string(), description: "Execute Query::CallChain from->to.".to_string(), input_schema: json!({"type":"object","properties":{"from":{"type":"integer"},"to":{"type":"integer"}},"required":["from","to"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryExecCallChainTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let from=args.get("from").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'from'".into()))?;
    let to=args.get("to").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'to'".into()))?;
    let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t);
    let r=e.execute(&rustre_ttd_query::Query::CallChain{from,to});
    Ok(ToolResult::text(json!({"matched":r.len(),"source":"rustre_ttd_query::QueryEngine::execute"}).to_string()))
} }

pub struct TtdQueryExplainTool;
impl TtdQueryExplainTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_explain".to_string(), description: "Return QueryPlan for Query::AllEvents.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryExplainTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let t=rustre_ttd_query::build_query_test_trace(); let e=rustre_ttd_query::QueryEngine::new(t);
    let p=e.explain(&rustre_ttd_query::Query::AllEvents);
    Ok(ToolResult::text(json!({"description":p.description,"estimated_events":p.estimated_events,"uses_index":p.uses_index,"source":"rustre_ttd_query::QueryEngine::explain"}).to_string()))
} }

pub struct TtdQueryTimeRangeContainsTool;
impl TtdQueryTimeRangeContainsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ttd_query_time_range_contains".to_string(), description: "Check if TimeRange contains a given sequence position.".to_string(), input_schema: json!({"type":"object","properties":{"start_seq":{"type":"integer"},"end_seq":{"type":"integer"},"pos_seq":{"type":"integer"}},"required":["start_seq","end_seq","pos_seq"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TtdQueryTimeRangeContainsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    use rustre_ttd::TracePosition;
    let s=args.get("start_seq").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start_seq'".into()))?;
    let e=args.get("end_seq").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'end_seq'".into()))?;
    let p=args.get("pos_seq").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'pos_seq'".into()))?;
    let r=rustre_ttd_query::TimeRange::new(TracePosition::new(s,0),TracePosition::new(e,0));
    let c=r.contains(&TracePosition::new(p,0));
    Ok(ToolResult::text(json!({"contains":c,"source":"rustre_ttd_query::TimeRange::contains"}).to_string()))
} }

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TtdQueryParseTool::definition(), Box::new(TtdQueryParseTool)),
        (TtdQueryCallTreeTool::definition(), Box::new(TtdQueryCallTreeTool)),
        (TtdQueryMemoryReportTool::definition(), Box::new(TtdQueryMemoryReportTool)),
        (TtdQueryCallFrequencyTool::definition(), Box::new(TtdQueryCallFrequencyTool)),
        (TtdQueryMostCalledTool::definition(), Box::new(TtdQueryMostCalledTool)),
        (TtdQueryMostAccessedAddressesTool::definition(), Box::new(TtdQueryMostAccessedAddressesTool)),
        (TtdQueryHistogramByKindTool::definition(), Box::new(TtdQueryHistogramByKindTool)),
        (TtdQueryHistogramByThreadTool::definition(), Box::new(TtdQueryHistogramByThreadTool)),
        (TtdQueryRecursiveCallsTool::definition(), Box::new(TtdQueryRecursiveCallsTool)),
        (TtdQueryDataRacesTool::definition(), Box::new(TtdQueryDataRacesTool)),
        (TtdQueryHeapOpsTool::definition(), Box::new(TtdQueryHeapOpsTool)),
        (TtdQueryStringAccessesTool::definition(), Box::new(TtdQueryStringAccessesTool)),
        (TtdQuerySyscallSummaryTool::definition(), Box::new(TtdQuerySyscallSummaryTool)),
        (TtdQueryMemoryAccessReportTool::definition(), Box::new(TtdQueryMemoryAccessReportTool)),
        (TtdQueryHistogramOverTimeTool::definition(), Box::new(TtdQueryHistogramOverTimeTool)),
        (TtdQueryTraceEventCountTool::definition(), Box::new(TtdQueryTraceEventCountTool)),
        (TtdQueryCodeCoverageTool::definition(), Box::new(TtdQueryCodeCoverageTool)),
        (TtdQueryFilterByAddressRangeTool::definition(), Box::new(TtdQueryFilterByAddressRangeTool)),
        (TtdQueryFirstOccurrenceThreadTool::definition(), Box::new(TtdQueryFirstOccurrenceThreadTool)),
        (TtdQueryLastOccurrenceThreadTool::definition(), Box::new(TtdQueryLastOccurrenceThreadTool)),
        (TtdQueryCountThreadTool::definition(), Box::new(TtdQueryCountThreadTool)),
        (TtdQueryExecAllEventsTool::definition(), Box::new(TtdQueryExecAllEventsTool)),
        (TtdQueryExecLoopsTool::definition(), Box::new(TtdQueryExecLoopsTool)),
        (TtdQueryExecCallChainTool::definition(), Box::new(TtdQueryExecCallChainTool)),
        (TtdQueryExplainTool::definition(), Box::new(TtdQueryExplainTool)),
        (TtdQueryTimeRangeContainsTool::definition(), Box::new(TtdQueryTimeRangeContainsTool)),
    ]
}
