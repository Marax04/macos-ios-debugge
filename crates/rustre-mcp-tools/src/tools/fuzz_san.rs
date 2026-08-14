//! MCP wrappers for the rustre-fuzz_san crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct FuzzSanParseHexU64Tool;

pub struct FuzzSanClassifySeverityTool;

pub struct FuzzSanParseAsanOutputTool;

pub struct FuzzSanParseUbsanOutputTool;

pub struct FuzzSanStackEditDistanceTool;

pub struct FuzzSanUbsanCheckSignedOverflowTool;
impl FuzzSanUbsanCheckSignedOverflowTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_san_ubsan_check_signed_overflow".to_string(),
            description: "Check if signed i64 op (add|sub|mul) between a and b would overflow.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"},"op":{"type":"string"}},"required":["a","b","op"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzSanUbsanCheckSignedOverflowTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("a".into()))?;
        let b = args.get("b").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("b".into()))?;
        let op = args.get("op").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'op'".into()))?;
        let opk = match op { "sub" => rustre_fuzz_sanitizers::ArithOp::Sub, "mul" => rustre_fuzz_sanitizers::ArithOp::Mul, _ => rustre_fuzz_sanitizers::ArithOp::Add };
        let ov = rustre_fuzz_sanitizers::UbSanitizer::check_signed_overflow(a, b, opk);
        Ok(ToolResult::text(json!({"overflow":ov,"a":a,"b":b,"op":op,"source":"rustre_fuzz_sanitizers::UbSanitizer::check_signed_overflow"}).to_string()))
    }
}

pub struct FuzzSanUbsanCheckNullDerefTool;
impl FuzzSanUbsanCheckNullDerefTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_san_ubsan_check_null_deref".to_string(),
            description: "Return true if ptr is a null pointer.".to_string(),
            input_schema: json!({"type":"object","properties":{"ptr":{"type":"integer"}},"required":["ptr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzSanUbsanCheckNullDerefTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ptr = args.get("ptr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("ptr".into()))?;
        Ok(ToolResult::text(json!({"is_null":rustre_fuzz_sanitizers::UbSanitizer::check_null_deref(ptr),"source":"rustre_fuzz_sanitizers::UbSanitizer::check_null_deref"}).to_string()))
    }
}

pub struct FuzzSanUbsanCheckMisalignedTool;
impl FuzzSanUbsanCheckMisalignedTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_san_ubsan_check_misaligned".to_string(),
            description: "Return true if addr is misaligned wrt alignment.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"alignment":{"type":"integer"}},"required":["addr","alignment"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzSanUbsanCheckMisalignedTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("addr".into()))?;
        let al = args.get("alignment").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("alignment".into()))? as usize;
        Ok(ToolResult::text(json!({"misaligned":rustre_fuzz_sanitizers::UbSanitizer::check_misaligned(addr,al),"source":"rustre_fuzz_sanitizers::UbSanitizer::check_misaligned"}).to_string()))
    }
}

pub struct FuzzSanUbsanCheckDivisionTool;
impl FuzzSanUbsanCheckDivisionTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_san_ubsan_check_division".to_string(),
            description: "Return true if divisor is zero.".to_string(),
            input_schema: json!({"type":"object","properties":{"divisor":{"type":"integer"}},"required":["divisor"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzSanUbsanCheckDivisionTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let d = args.get("divisor").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("divisor".into()))?;
        Ok(ToolResult::text(json!({"div_by_zero":rustre_fuzz_sanitizers::UbSanitizer::check_division(d),"source":"rustre_fuzz_sanitizers::UbSanitizer::check_division"}).to_string()))
    }
}

pub struct FuzzSanUbsanCheckedAddTool;
impl FuzzSanUbsanCheckedAddTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_san_ubsan_checked_add".to_string(),
            description: "Signed i64 checked add; returns result or overflow report.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"}},"required":["a","b"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzSanUbsanCheckedAddTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("a".into()))?;
        let b = args.get("b").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("b".into()))?;
        match rustre_fuzz_sanitizers::UbSanitizer::checked_add(a,b) {
            Ok(v) => Ok(ToolResult::text(json!({"ok":true,"result":v,"source":"rustre_fuzz_sanitizers::UbSanitizer::checked_add"}).to_string())),
            Err(r) => Ok(ToolResult::text(json!({"ok":false,"error_kind":r.kind.to_string(),"message":r.message,"source":"rustre_fuzz_sanitizers::UbSanitizer::checked_add"}).to_string())),
        }
    }
}

pub struct FuzzSanUbsanCheckedMulTool;
impl FuzzSanUbsanCheckedMulTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_san_ubsan_checked_mul".to_string(),
            description: "Signed i64 checked multiply; returns result or overflow report.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"integer"},"b":{"type":"integer"}},"required":["a","b"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzSanUbsanCheckedMulTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = args.get("a").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("a".into()))?;
        let b = args.get("b").and_then(Value::as_i64).ok_or_else(|| McpError::InvalidParams("b".into()))?;
        match rustre_fuzz_sanitizers::UbSanitizer::checked_mul(a,b) {
            Ok(v) => Ok(ToolResult::text(json!({"ok":true,"result":v,"source":"rustre_fuzz_sanitizers::UbSanitizer::checked_mul"}).to_string())),
            Err(r) => Ok(ToolResult::text(json!({"ok":false,"error_kind":r.kind.to_string(),"message":r.message,"source":"rustre_fuzz_sanitizers::UbSanitizer::checked_mul"}).to_string())),
        }
    }
}

pub struct FuzzSanUbsanCheckAccessTool;
impl FuzzSanUbsanCheckAccessTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_san_ubsan_check_access".to_string(),
            description: "Check pointer for null and alignment; returns first violation if any.".to_string(),
            input_schema: json!({"type":"object","properties":{"ptr":{"type":"integer"},"alignment":{"type":"integer"}},"required":["ptr","alignment"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzSanUbsanCheckAccessTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ptr = args.get("ptr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("ptr".into()))?;
        let al = args.get("alignment").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("alignment".into()))? as usize;
        match rustre_fuzz_sanitizers::UbSanitizer::check_access(ptr, al) {
            Ok(()) => Ok(ToolResult::text(json!({"ok":true,"source":"rustre_fuzz_sanitizers::UbSanitizer::check_access"}).to_string())),
            Err(r) => Ok(ToolResult::text(json!({"ok":false,"error_kind":r.kind.to_string(),"message":r.message,"source":"rustre_fuzz_sanitizers::UbSanitizer::check_access"}).to_string())),
        }
    }
}

pub struct FuzzSanAsanScenarioTool;
impl FuzzSanAsanScenarioTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_san_asan_scenario".to_string(),
            description: "Simulate ASan: allocs=[{addr,size}], frees=[addr], then check(check_addr,check_size).".to_string(),
            input_schema: json!({"type":"object","properties":{"allocs":{"type":"array"},"frees":{"type":"array"},"check_addr":{"type":"integer"},"check_size":{"type":"integer"}},"required":["check_addr","check_size"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzSanAsanScenarioTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut asan = rustre_fuzz_sanitizers::AddressSanitizer::new();
        if let Some(arr) = args.get("allocs").and_then(Value::as_array) {
            for v in arr {
                let a = v.get("addr").and_then(Value::as_u64).unwrap_or(0);
                let s = v.get("size").and_then(Value::as_u64).unwrap_or(0) as usize;
                asan.track_alloc(a,s);
            }
        }
        let mut free_results = vec![];
        if let Some(arr) = args.get("frees").and_then(Value::as_array) {
            for v in arr {
                if let Some(a) = v.as_u64() {
                    let r = asan.track_free(a);
                    free_results.push(json!({"addr":a,"result":format!("{:?}",r)}));
                }
            }
        }
        let ca = args.get("check_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("check_addr".into()))?;
        let cs = args.get("check_size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("check_size".into()))? as usize;
        let (ok, kind, msg) = match asan.check(ca,cs) {
            Ok(()) => (true, String::new(), String::new()),
            Err(r) => (false, r.kind.to_string(), r.message),
        };
        Ok(ToolResult::text(json!({"ok":ok,"error_kind":kind,"message":msg,"frees":free_results,"source":"rustre_fuzz_sanitizers::AddressSanitizer"}).to_string()))
    }
}

pub struct FuzzSanMsanScenarioTool;
impl FuzzSanMsanScenarioTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_san_msan_scenario".to_string(),
            description: "Simulate MSan: mark defined/undefined ranges, then check(check_addr,check_len).".to_string(),
            input_schema: json!({"type":"object","properties":{"defined":{"type":"array"},"undefined":{"type":"array"},"check_addr":{"type":"integer"},"check_len":{"type":"integer"}},"required":["check_addr","check_len"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzSanMsanScenarioTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut msan = rustre_fuzz_sanitizers::MemorySanitizer::new();
        if let Some(arr) = args.get("defined").and_then(Value::as_array) {
            for v in arr {
                let a = v.get("addr").and_then(Value::as_u64).unwrap_or(0);
                let l = v.get("len").and_then(Value::as_u64).unwrap_or(0) as usize;
                msan.mark_defined(a,l);
            }
        }
        if let Some(arr) = args.get("undefined").and_then(Value::as_array) {
            for v in arr {
                let a = v.get("addr").and_then(Value::as_u64).unwrap_or(0);
                let l = v.get("len").and_then(Value::as_u64).unwrap_or(0) as usize;
                msan.mark_undefined(a,l);
            }
        }
        let ca = args.get("check_addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("check_addr".into()))?;
        let cl = args.get("check_len").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("check_len".into()))? as usize;
        let (ok, kind, msg) = match msan.check(ca,cl) {
            Ok(()) => (true, String::new(), String::new()),
            Err(r) => (false, r.kind.to_string(), r.message),
        };
        Ok(ToolResult::text(json!({"ok":ok,"error_kind":kind,"message":msg,"source":"rustre_fuzz_sanitizers::MemorySanitizer"}).to_string()))
    }
}

pub struct FuzzSanLogParserParseAllTool;
impl FuzzSanLogParserParseAllTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_san_log_parser_parse_all".to_string(),
            description: "Parse ALL sanitizer crash reports (ASAN/MSAN/UBSAN/TSAN) from a text blob.".to_string(),
            input_schema: json!({"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzSanLogParserParseAllTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("text".into()))?;
        let reports = rustre_fuzz_sanitizers::SanitizerLogParser::parse_all(text);
        let summaries: Vec<Value> = reports.iter().map(|r| json!({
            "tool":r.tool.to_string(),
            "error_type":r.error_type,
            "severity":r.severity.to_string(),
            "address":r.address,
            "stack_frames":r.stack_frames.len(),
            "summary":r.summary(),
        })).collect();
        Ok(ToolResult::text(json!({"count":summaries.len(),"reports":summaries,"source":"rustre_fuzz_sanitizers::SanitizerLogParser::parse_all"}).to_string()))
    }
}

pub struct FuzzSanLogParserParseFirstTool;
impl FuzzSanLogParserParseFirstTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_san_log_parser_parse_first".to_string(),
            description: "Parse the FIRST sanitizer crash report from a text blob.".to_string(),
            input_schema: json!({"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzSanLogParserParseFirstTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("text".into()))?;
        let r = rustre_fuzz_sanitizers::SanitizerLogParser::parse(text);
        Ok(ToolResult::text(json!({
            "tool":r.tool.to_string(),
            "error_type":r.error_type,
            "severity":r.severity.to_string(),
            "address":r.address,
            "thread":r.thread,
            "stack_frames":r.stack_frames.len(),
            "top_function":r.top_function(),
            "summary":r.summary(),
            "source":"rustre_fuzz_sanitizers::SanitizerLogParser::parse"
        }).to_string()))
    }
}

pub struct FuzzSanDedupGroupTool;
impl FuzzSanDedupGroupTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_san_crash_dedup_group".to_string(),
            description: "Parse a sanitizer log and return per-report dedup keys + grouped counts.".to_string(),
            input_schema: json!({"type":"object","properties":{"text":{"type":"string"},"stack_depth":{"type":"integer"}},"required":["text"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzSanDedupGroupTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("text".into()))?;
        let mut dedup = rustre_fuzz_sanitizers::CrashDeduplicator::new();
        if let Some(d) = args.get("stack_depth").and_then(Value::as_u64) { dedup.stack_depth = d as usize; }
        let reports = rustre_fuzz_sanitizers::SanitizerLogParser::parse_all(text);
        let keys: Vec<String> = reports.iter().map(|r| dedup.dedup_key(r)).collect();
        let groups = dedup.deduplicate(reports);
        let group_summ: Vec<Value> = groups.iter().map(|g| json!({
            "error_type":g.representative.error_type,
            "duplicate_count":g.duplicate_count,
            "is_recurring":g.is_recurring(),
        })).collect();
        Ok(ToolResult::text(json!({"keys":keys,"groups":group_summ,"source":"rustre_fuzz_sanitizers::CrashDeduplicator"}).to_string()))
    }
}

pub struct FuzzSanCoverageMapSummaryTool;
impl FuzzSanCoverageMapSummaryTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_san_coverage_summary".to_string(),
            description: "Build CoverageMap from edges [{from,to}]; report totals + coverage ratio vs total_known.".to_string(),
            input_schema: json!({"type":"object","properties":{"edges":{"type":"array"},"total_known":{"type":"integer"}},"required":["edges"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzSanCoverageMapSummaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut cov = rustre_fuzz_sanitizers::CoverageMap::new();
        if let Some(arr) = args.get("edges").and_then(Value::as_array) {
            for v in arr {
                let f = v.get("from").and_then(Value::as_u64).unwrap_or(0);
                let t = v.get("to").and_then(Value::as_u64).unwrap_or(0);
                cov.record_edge(f,t);
            }
        }
        let total_known = args.get("total_known").and_then(Value::as_u64).unwrap_or(0) as usize;
        Ok(ToolResult::text(json!({
            "total_edges":cov.total_edges(),
            "total_blocks":cov.total_blocks(),
            "coverage_ratio":cov.coverage_ratio(total_known),
            "source":"rustre_fuzz_sanitizers::CoverageMap"
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (FuzzSanParseHexU64Tool::definition(), Box::new(FuzzSanParseHexU64Tool)),
        (FuzzSanClassifySeverityTool::definition(), Box::new(FuzzSanClassifySeverityTool)),
        (FuzzSanParseAsanOutputTool::definition(), Box::new(FuzzSanParseAsanOutputTool)),
        (FuzzSanParseUbsanOutputTool::definition(), Box::new(FuzzSanParseUbsanOutputTool)),
        (FuzzSanStackEditDistanceTool::definition(), Box::new(FuzzSanStackEditDistanceTool)),
        (FuzzSanUbsanCheckSignedOverflowTool::definition(), Box::new(FuzzSanUbsanCheckSignedOverflowTool)),
        (FuzzSanUbsanCheckNullDerefTool::definition(), Box::new(FuzzSanUbsanCheckNullDerefTool)),
        (FuzzSanUbsanCheckMisalignedTool::definition(), Box::new(FuzzSanUbsanCheckMisalignedTool)),
        (FuzzSanUbsanCheckDivisionTool::definition(), Box::new(FuzzSanUbsanCheckDivisionTool)),
        (FuzzSanUbsanCheckedAddTool::definition(), Box::new(FuzzSanUbsanCheckedAddTool)),
        (FuzzSanUbsanCheckedMulTool::definition(), Box::new(FuzzSanUbsanCheckedMulTool)),
        (FuzzSanUbsanCheckAccessTool::definition(), Box::new(FuzzSanUbsanCheckAccessTool)),
        (FuzzSanAsanScenarioTool::definition(), Box::new(FuzzSanAsanScenarioTool)),
        (FuzzSanMsanScenarioTool::definition(), Box::new(FuzzSanMsanScenarioTool)),
        (FuzzSanLogParserParseAllTool::definition(), Box::new(FuzzSanLogParserParseAllTool)),
        (FuzzSanLogParserParseFirstTool::definition(), Box::new(FuzzSanLogParserParseFirstTool)),
        (FuzzSanDedupGroupTool::definition(), Box::new(FuzzSanDedupGroupTool)),
        (FuzzSanCoverageMapSummaryTool::definition(), Box::new(FuzzSanCoverageMapSummaryTool)),
    ]
}
