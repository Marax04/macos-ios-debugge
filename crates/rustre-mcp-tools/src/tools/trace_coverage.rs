//! MCP wrappers for the rustre-trace_coverage crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct TraceCoveragePercentTool;

pub struct TraceCoverageComputeFunctionStatsTool;

pub struct TraceCoverageParseLcovTool;

pub struct TraceCoverageToCustomBinaryTool;

pub struct TraceCoverageMergeRunsTool;

pub struct TraceCoverageMapWireT1Tool;
impl TraceCoverageMapWireT1Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_map_wt1".to_string(),
            description: "Build a CoverageMap from hit addresses; return unique/total hits, ratio, top-N.".to_string(),
            input_schema: json!({"type":"object","properties":{"addrs":{"type":"array"},"total_addresses":{"type":"integer"},"top_n":{"type":"integer"}},"required":["addrs"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageMapWireT1Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addrs = args.get("addrs").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'addrs'".into()))?;
        let total = args.get("total_addresses").and_then(Value::as_u64).unwrap_or(0);
        let top_n = args.get("top_n").and_then(Value::as_u64).unwrap_or(5) as usize;
        let mut m = rustre_trace::CoverageMap::with_total(total);
        for v in addrs { m.record_hit(v.as_u64().unwrap_or(0)); }
        Ok(ToolResult::text(json!({
            "unique_addresses_hit": m.unique_addresses_hit(),
            "total_hits": m.total_hits(),
            "coverage_ratio": m.coverage_ratio(),
            "hottest": m.hottest_addresses(top_n),
            "source": "rustre_trace::CoverageMap",
        }).to_string()))
    }
}

pub struct TraceCoverageAflBitmapCountTool;
impl TraceCoverageAflBitmapCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_afl_bitmap_count".to_string(),
            description: "Load raw AFL bitmap bytes and return the number of set edges via rustre_trace_coverage::afl_bitmap_coverage.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer","minimum":0,"maximum":255}}},"required":["bytes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageAflBitmapCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("bytes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'bytes'".into()))?;
        let data: Vec<u8> = arr.iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect();
        let bm = rustre_trace_coverage::load_afl_bitmap(&data);
        let count = rustre_trace_coverage::afl_bitmap_coverage(&bm);
        Ok(ToolResult::text(json!({
            "input_len": data.len(),
            "set_edges": count,
            "size_bits": bm.size,
            "source": "rustre_trace_coverage::afl_bitmap_coverage",
        }).to_string()))
    }
}

pub struct TraceCoverageAflNewCoverageTool;
impl TraceCoverageAflNewCoverageTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_afl_new_coverage".to_string(),
            description: "Count edges set in AFL bitmap b but not in a via rustre_trace_coverage::afl_new_coverage.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"array","items":{"type":"integer"}},"b":{"type":"array","items":{"type":"integer"}}},"required":["a","b"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageAflNewCoverageTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a: Vec<u8> = args.get("a").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?
            .iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect();
        let b: Vec<u8> = args.get("b").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?
            .iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect();
        let am = rustre_trace_coverage::load_afl_bitmap(&a);
        let bm = rustre_trace_coverage::load_afl_bitmap(&b);
        let new_edges = rustre_trace_coverage::afl_new_coverage(&am, &bm);
        Ok(ToolResult::text(json!({
            "new_edges": new_edges,
            "source": "rustre_trace_coverage::afl_new_coverage",
        }).to_string()))
    }
}

pub struct TraceCoverageDrcovParseTool;
impl TraceCoverageDrcovParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_drcov_parse".to_string(),
            description: "Parse DRcov text via rustre_trace_coverage::DrcovData::parse.".to_string(),
            input_schema: json!({"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageDrcovParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let txt = args.get("text").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?;
        let data = rustre_trace_coverage::DrcovData::parse(txt);
        let addrs = data.resolve_addresses();
        Ok(ToolResult::text(json!({
            "modules": data.modules.len(),
            "basic_blocks": data.basic_blocks.len(),
            "resolved_addresses": addrs.len(),
            "source": "rustre_trace_coverage::DrcovData::parse",
        }).to_string()))
    }
}

pub struct TraceCoverageParseCustomBinaryTool;
impl TraceCoverageParseCustomBinaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_parse_custom_binary".to_string(),
            description: "Parse (u64 addr, u64 count) pairs via rustre_trace_coverage::parse_custom_binary.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}}},"required":["bytes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageParseCustomBinaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data: Vec<u8> = args.get("bytes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'bytes'".into()))?
            .iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect();
        match rustre_trace_coverage::parse_custom_binary(&data) {
            Ok(run) => Ok(ToolResult::text(json!({
                "unique_bbs": run.unique_bbs(),
                "total_executions": run.total_bb_executions(),
                "source": "rustre_trace_coverage::parse_custom_binary",
            }).to_string())),
            Err(e) => Err(McpError::InvalidParams(e.to_string())),
        }
    }
}

pub struct TraceCoverageAflJaccardTool;
impl TraceCoverageAflJaccardTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_afl_jaccard".to_string(),
            description: "Compute Jaccard similarity between two AFL bitmaps via rustre_trace_coverage::CovBitmap::jaccard.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"array","items":{"type":"integer"}},"b":{"type":"array","items":{"type":"integer"}}},"required":["a","b"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageAflJaccardTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a: Vec<u8> = args.get("a").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?
            .iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect();
        let b: Vec<u8> = args.get("b").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?
            .iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect();
        let am = rustre_trace_coverage::load_afl_bitmap(&a);
        let bm = rustre_trace_coverage::load_afl_bitmap(&b);
        Ok(ToolResult::text(json!({
            "jaccard": am.jaccard(&bm),
            "source": "rustre_trace_coverage::CovBitmap::jaccard",
        }).to_string()))
    }
}

pub struct TraceCoverageCovEdgeDisplayTool;
impl TraceCoverageCovEdgeDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_covedge_display".to_string(),
            description: "Format a control-flow edge via rustre_trace_coverage::CovEdge Display.".to_string(),
            input_schema: json!({"type":"object","properties":{"from":{"type":"integer"},"to":{"type":"integer"}},"required":["from","to"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageCovEdgeDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let from = args.get("from").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'from'".into()))?;
        let to = args.get("to").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'to'".into()))?;
        let e = rustre_trace_coverage::CovEdge::new(from, to);
        Ok(ToolResult::text(json!({
            "display": e.to_string(),
            "source": "rustre_trace_coverage::CovEdge::fmt",
        }).to_string()))
    }
}

pub struct TraceCoverageFunctionStatsPctTool;
impl TraceCoverageFunctionStatsPctTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_function_stats_pct".to_string(),
            description: "Per-function coverage percentage via rustre_trace_coverage::FunctionStats::coverage_pct.".to_string(),
            input_schema: json!({"type":"object","properties":{"total_bb":{"type":"integer"},"covered_bb":{"type":"integer"}},"required":["total_bb","covered_bb"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageFunctionStatsPctTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let total = args.get("total_bb").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'total_bb'".into()))? as usize;
        let covered = args.get("covered_bb").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'covered_bb'".into()))? as usize;
        let mut fs = rustre_trace_coverage::FunctionStats::new("f", 0, 0, total);
        fs.covered_bb = covered;
        Ok(ToolResult::text(json!({
            "coverage_pct": fs.coverage_pct(),
            "is_fully_covered": fs.is_fully_covered(),
            "source": "rustre_trace_coverage::FunctionStats::coverage_pct",
        }).to_string()))
    }
}

pub struct TraceCoverageParseLcovWireTool;
impl TraceCoverageParseLcovWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_parse_lcov_wire".to_string(),
            description: "Parse LCOV text via rustre_trace_coverage::parse_lcov.".to_string(),
            input_schema: json!({"type":"object","properties":{"text":{"type":"string"}},"required":["text"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageParseLcovWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let txt = args.get("text").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'text'".into()))?;
        let recs = rustre_trace_coverage::parse_lcov(txt);
        let files: Vec<&str> = recs.iter().map(|r| r.source_file.as_str()).collect();
        Ok(ToolResult::text(json!({
            "record_count": recs.len(),
            "source_files": files,
            "source": "rustre_trace_coverage::parse_lcov",
        }).to_string()))
    }
}

pub struct TraceCoverageCovBitmapOpsTool;
impl TraceCoverageCovBitmapOpsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_covbitmap_ops".to_string(),
            description: "Union/intersection/difference set-bit counts via rustre_trace_coverage::CovBitmap.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"array","items":{"type":"integer"}},"b":{"type":"array","items":{"type":"integer"}}},"required":["a","b"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageCovBitmapOpsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a: Vec<u8> = args.get("a").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?
            .iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect();
        let b: Vec<u8> = args.get("b").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?
            .iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect();
        let am = rustre_trace_coverage::CovBitmap::from_afl_bitmap(&a);
        let bm = rustre_trace_coverage::CovBitmap::from_afl_bitmap(&b);
        Ok(ToolResult::text(json!({
            "union_set": am.union(&bm).count_set(),
            "intersection_set": am.intersection(&bm).count_set(),
            "difference_a_minus_b_set": am.difference(&bm).count_set(),
            "a_coverage_ratio": am.coverage_ratio(),
            "b_coverage_ratio": bm.coverage_ratio(),
            "source": "rustre_trace_coverage::CovBitmap",
        }).to_string()))
    }
}

pub struct TraceCoverageDiffOverlapPctTool;
impl TraceCoverageDiffOverlapPctTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_diff_overlap_pct".to_string(),
            description: "BB set overlap percentage via rustre_trace_coverage::CoverageDiff::overlap_pct.".to_string(),
            input_schema: json!({"type":"object","properties":{"a":{"type":"array","items":{"type":"integer"}},"b":{"type":"array","items":{"type":"integer"}}},"required":["a","b"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageDiffOverlapPctTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a: Vec<u64> = args.get("a").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?
            .iter().filter_map(Value::as_u64).collect();
        let b: Vec<u64> = args.get("b").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?
            .iter().filter_map(Value::as_u64).collect();
        let mut ra = rustre_trace_coverage::CoverageRun::new("a");
        for x in a { ra.record_bb(x); }
        let mut rb = rustre_trace_coverage::CoverageRun::new("b");
        for x in b { rb.record_bb(x); }
        let d = rustre_trace_coverage::CoverageDiff::compute(&ra, &rb);
        Ok(ToolResult::text(json!({
            "jaccard": d.jaccard,
            "overlap_pct": d.overlap_pct(),
            "new_in_a": d.new_in_a.len(),
            "new_in_b": d.new_in_b.len(),
            "in_both": d.in_both.len(),
            "source": "rustre_trace_coverage::CoverageDiff::overlap_pct",
        }).to_string()))
    }
}

pub struct TraceCoverageHitCountTool;
impl TraceCoverageHitCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_map_hit_count".to_string(),
            description: "Record n hits at addr in CoverageMap and return counts.".to_string(),
            input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"n":{"type":"integer"}},"required":["addr","n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageHitCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0);
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(1);
        let mut m = rustre_trace::CoverageMap::new();
        m.record_hits(addr, n);
        Ok(ToolResult::text(json!({"hit_count":m.hit_count(addr),"unique":m.unique_addresses_hit(),"total_hits":m.total_hits(),"source":"rustre_trace::CoverageMap::record_hits"}).to_string()))
    }
}

pub struct TraceCoverageRatioTool;
impl TraceCoverageRatioTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_map_ratio".to_string(),
            description: "CoverageMap::with_total(total), hit distinct addresses, return coverage_ratio.".to_string(),
            input_schema: json!({"type":"object","properties":{"hit":{"type":"integer"},"total":{"type":"integer"}},"required":["hit","total"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageRatioTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hit = args.get("hit").and_then(Value::as_u64).unwrap_or(0);
        let total = args.get("total").and_then(Value::as_u64).unwrap_or(0);
        let mut m = rustre_trace::CoverageMap::with_total(total);
        for i in 0..hit { m.record_hit(0x5000 + i); }
        Ok(ToolResult::text(json!({"ratio":m.coverage_ratio(),"unique":m.unique_addresses_hit(),"source":"rustre_trace::CoverageMap::coverage_ratio"}).to_string()))
    }
}

pub struct TraceCoverageMapNewTool;
impl TraceCoverageMapNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_map_new".to_string(),
            description: "Create a new empty CoverageMap and record N hits.".to_string(),
            input_schema: json!({"type":"object","properties":{"hits":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageMapNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hits = args.get("hits").and_then(Value::as_u64).unwrap_or(0);
        let mut cm = rustre_trace::CoverageMap::new();
        for i in 0..hits { cm.record_hit(0x1000 + i); }
        Ok(ToolResult::text(json!({"hits_recorded": hits, "coverage_ratio": cm.coverage_ratio(), "source": "rustre_trace::CoverageMap::new"}).to_string()))
    }
}

pub struct TraceCoverageRunHotBbsTool;
impl TraceCoverageRunHotBbsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_run_hot_bbs".to_string(),
            description: "Return top-N hottest basic blocks by hit count from a CoverageRun JSON. Wraps rustre_trace_coverage::CoverageRun::hot_bbs.".to_string(),
            input_schema: json!({"type":"object","properties":{"run":{"type":"string"},"n":{"type":"integer"}},"required":["run"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageRunHotBbsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("run").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'run'".into()))?;
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(10) as usize;
        let run: rustre_trace_coverage::CoverageRun = serde_json::from_str(s)
            .map_err(|e| McpError::InvalidParams(format!("json: {e}")))?;
        let hot = run.hot_bbs(n);
        Ok(ToolResult::text(json!({
            "count": hot.len(),
            "hot": hot.iter().map(|(a,c)| json!([format!("0x{:x}", a), c])).collect::<Vec<_>>(),
            "source": "rustre_trace_coverage::CoverageRun::hot_bbs",
        }).to_string()))
    }
}

pub struct TraceCoverageRunSummaryTool;
impl TraceCoverageRunSummaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_run_summary".to_string(),
            description: "Summarize a CoverageRun: unique BBs, unique edges, total executions. Wraps rustre_trace_coverage::CoverageRun accessors.".to_string(),
            input_schema: json!({"type":"object","properties":{"run":{"type":"string"}},"required":["run"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageRunSummaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("run").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'run'".into()))?;
        let run: rustre_trace_coverage::CoverageRun = serde_json::from_str(s)
            .map_err(|e| McpError::InvalidParams(format!("json: {e}")))?;
        Ok(ToolResult::text(json!({
            "name": run.name,
            "unique_bbs": run.unique_bbs(),
            "unique_edges": run.unique_edges(),
            "total_executions": run.total_bb_executions(),
            "source": "rustre_trace_coverage::CoverageRun",
        }).to_string()))
    }
}

pub struct TraceCoverageRunVisitAtTool;
impl TraceCoverageRunVisitAtTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_run_visit_at".to_string(),
            description: "Report is_covered and visit_count for an address. Wraps rustre_trace_coverage::CoverageRun::visit_count.".to_string(),
            input_schema: json!({"type":"object","properties":{"run":{"type":"string"},"addr":{"type":"integer"}},"required":["run","addr"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageRunVisitAtTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("run").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'run'".into()))?;
        let addr = args.get("addr").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?;
        let run: rustre_trace_coverage::CoverageRun = serde_json::from_str(s)
            .map_err(|e| McpError::InvalidParams(format!("json: {e}")))?;
        Ok(ToolResult::text(json!({
            "addr": format!("0x{:x}", addr),
            "is_covered": run.is_covered(addr),
            "visit_count": run.visit_count(addr),
            "source": "rustre_trace_coverage::CoverageRun::visit_count",
        }).to_string()))
    }
}

pub struct TraceCoverageDataStatsTool;
impl TraceCoverageDataStatsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_data_stats".to_string(),
            description: "Aggregate stats across all runs in CoverageData JSON. Wraps rustre_trace_coverage::CoverageData::total_unique_bbs and run_count.".to_string(),
            input_schema: json!({"type":"object","properties":{"data":{"type":"string"}},"required":["data"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageDataStatsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("data").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'data'".into()))?;
        let data: rustre_trace_coverage::CoverageData = serde_json::from_str(s)
            .map_err(|e| McpError::InvalidParams(format!("json: {e}")))?;
        Ok(ToolResult::text(json!({
            "label": data.label,
            "run_count": data.run_count(),
            "total_unique_bbs": data.total_unique_bbs(),
            "all_bb_addresses_len": data.all_bb_addresses().len(),
            "source": "rustre_trace_coverage::CoverageData",
        }).to_string()))
    }
}

pub struct TraceCoverageCovBitmapClearBitsTool;
impl TraceCoverageCovBitmapClearBitsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_covbitmap_clear_bits".to_string(),
            description: "Return count of clear bits and is_empty/is_full flags for an AFL bitmap. Wraps rustre_trace_coverage::CovBitmap.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}}},"required":["bytes"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageCovBitmapClearBitsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("bytes").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'bytes'".into()))?;
        let data: Vec<u8> = arr.iter().filter_map(|v| v.as_u64().map(|x| x as u8)).collect();
        let bm = rustre_trace_coverage::CovBitmap::from_afl_bitmap(&data);
        Ok(ToolResult::text(json!({
            "size": bm.size,
            "count_set": bm.count_set(),
            "count_clear": bm.count_clear(),
            "is_empty": bm.is_empty(),
            "is_full": bm.is_full(),
            "coverage_ratio": bm.coverage_ratio(),
            "source": "rustre_trace_coverage::CovBitmap",
        }).to_string()))
    }
}

pub struct TraceCoverageCovBitmapRecordEdgeTool;
impl TraceCoverageCovBitmapRecordEdgeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_covbitmap_record_edge".to_string(),
            description: "Record an AFL edge (prev_pc ^ cur_pc) into a fresh CovBitmap of given size. Wraps rustre_trace_coverage::CovBitmap::record_edge.".to_string(),
            input_schema: json!({"type":"object","properties":{"size":{"type":"integer"},"prev_pc":{"type":"integer"},"cur_pc":{"type":"integer"}},"required":["size","prev_pc","cur_pc"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageCovBitmapRecordEdgeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let size = args.get("size").and_then(Value::as_u64).unwrap_or(65536) as usize;
        let prev_pc = args.get("prev_pc").and_then(Value::as_u64).unwrap_or(0);
        let cur_pc = args.get("cur_pc").and_then(Value::as_u64).unwrap_or(0);
        let mut bm = rustre_trace_coverage::CovBitmap::new(size);
        bm.record_edge(prev_pc, cur_pc);
        Ok(ToolResult::text(json!({
            "size": bm.size,
            "count_set": bm.count_set(),
            "source": "rustre_trace_coverage::CovBitmap::record_edge",
        }).to_string()))
    }
}

pub struct TraceCoverageHeatmapHottestTool;
impl TraceCoverageHeatmapHottestTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_heatmap_hottest".to_string(),
            description: "Build CoverageHeatmap from run JSON and return top-N hottest entries. Wraps rustre_trace_coverage::CoverageHeatmap::hottest.".to_string(),
            input_schema: json!({"type":"object","properties":{"run":{"type":"string"},"n":{"type":"integer"}},"required":["run"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageHeatmapHottestTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("run").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'run'".into()))?;
        let n = args.get("n").and_then(Value::as_u64).unwrap_or(10) as usize;
        let run: rustre_trace_coverage::CoverageRun = serde_json::from_str(s)
            .map_err(|e| McpError::InvalidParams(format!("json: {e}")))?;
        let hm = rustre_trace_coverage::CoverageHeatmap::build(&run);
        let top = hm.hottest(n);
        Ok(ToolResult::text(json!({
            "max_count": hm.max_count,
            "entries_total": hm.entries.len(),
            "top": top.iter().map(|(a,h)| json!([format!("0x{:x}", a), h])).collect::<Vec<_>>(),
            "source": "rustre_trace_coverage::CoverageHeatmap::hottest",
        }).to_string()))
    }
}

pub struct TraceCoverageLighthouseRoundtripTool;
impl TraceCoverageLighthouseRoundtripTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_lighthouse_roundtrip".to_string(),
            description: "Convert CoverageRun JSON -> LighthouseJson -> back to run; report equality. Wraps rustre_trace_coverage::LighthouseJson.".to_string(),
            input_schema: json!({"type":"object","properties":{"run":{"type":"string"}},"required":["run"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageLighthouseRoundtripTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("run").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'run'".into()))?;
        let run: rustre_trace_coverage::CoverageRun = serde_json::from_str(s)
            .map_err(|e| McpError::InvalidParams(format!("json: {e}")))?;
        let lh = rustre_trace_coverage::LighthouseJson::from_run(&run);
        let json_str = lh.to_json().map_err(|e| McpError::InvalidParams(format!("json: {e}")))?;
        let back = lh.to_run();
        Ok(ToolResult::text(json!({
            "coverage_len": lh.coverage.len(),
            "json_len": json_str.len(),
            "roundtrip_unique_bbs": back.unique_bbs(),
            "equal_bb_count": back.unique_bbs() == run.unique_bbs(),
            "source": "rustre_trace_coverage::LighthouseJson",
        }).to_string()))
    }
}

pub struct TraceCoverageDrcovResolveTool;
impl TraceCoverageDrcovResolveTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_drcov_resolve".to_string(),
            description: "Parse DRcov text and resolve absolute BB addresses. Wraps rustre_trace_coverage::DrcovData::resolve_addresses.".to_string(),
            input_schema: json!({"type":"object","properties":{"input":{"type":"string"}},"required":["input"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageDrcovResolveTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("input").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'input'".into()))?;
        let d = rustre_trace_coverage::DrcovData::parse(s);
        let addrs = d.resolve_addresses();
        let preview: Vec<String> = addrs.iter().take(16).map(|a| format!("0x{a:x}")).collect();
        Ok(ToolResult::text(json!({
            "modules": d.modules.len(),
            "basic_blocks": d.basic_blocks.len(),
            "resolved_count": addrs.len(),
            "preview": preview,
            "source": "rustre_trace_coverage::DrcovData::resolve_addresses",
        }).to_string()))
    }
}

pub struct TraceCoverageFunctionStatsFlagsTool;
impl TraceCoverageFunctionStatsFlagsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_function_stats_flags".to_string(),
            description: "Report was_called/is_fully_covered/coverage_pct for a FunctionStats built from inputs. Wraps rustre_trace_coverage::FunctionStats.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"start":{"type":"integer"},"end":{"type":"integer"},"total_bb":{"type":"integer"},"covered_bb":{"type":"integer"},"call_count":{"type":"integer"}},"required":["total_bb","covered_bb"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCoverageFunctionStatsFlagsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("f");
        let start = args.get("start").and_then(Value::as_u64).unwrap_or(0);
        let end = args.get("end").and_then(Value::as_u64).unwrap_or(0);
        let total = args.get("total_bb").and_then(Value::as_u64).unwrap_or(0) as usize;
        let covered = args.get("covered_bb").and_then(Value::as_u64).unwrap_or(0) as usize;
        let calls = args.get("call_count").and_then(Value::as_u64).unwrap_or(0);
        let mut fs = rustre_trace_coverage::FunctionStats::new(name, start, end, total);
        fs.covered_bb = covered;
        fs.call_count = calls;
        Ok(ToolResult::text(json!({
            "name": fs.name,
            "coverage_pct": fs.coverage_pct(),
            "was_called": fs.was_called(),
            "is_fully_covered": fs.is_fully_covered(),
            "source": "rustre_trace_coverage::FunctionStats",
        }).to_string()))
    }
}

pub struct TraceCoverageDataAllBbAddressesWire3Tool;
impl TraceCoverageDataAllBbAddressesWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_coverage_data_all_bb_addresses_wire3".to_string(), description: "Total unique BB addresses across a CoverageData via rustre_trace_coverage::CoverageData::all_bb_addresses.".to_string(), input_schema: json!({"type":"object","properties":{"label":{"type":"string"},"addrs":{"type":"array","items":{"type":"integer"}}},"required":["addrs"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TraceCoverageDataAllBbAddressesWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let label = args.get("label").and_then(Value::as_str).unwrap_or("d"); let addrs: Vec<u64> = args.get("addrs").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default(); let mut data = rustre_trace_coverage::CoverageData::new(label); let mut run = rustre_trace_coverage::CoverageRun::new("r1"); for a in &addrs { run.record_bb(*a); } data.add_run(run); Ok(ToolResult::text(json!({"runs":data.run_count(),"total_unique_bbs":data.total_unique_bbs(),"all_bb_addresses":data.all_bb_addresses().len(),"source":"rustre_trace_coverage::CoverageData::all_bb_addresses"}).to_string())) } }

pub struct TraceCoverageLcovLineRatioWire3Tool;
impl TraceCoverageLcovLineRatioWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_coverage_lcov_line_ratio_wire3".to_string(), description: "Compute line & function coverage ratios via rustre_trace_coverage::LcovRecord::line_coverage_ratio.".to_string(), input_schema: json!({"type":"object","properties":{"lines_found":{"type":"integer"},"lines_hit":{"type":"integer"},"functions_found":{"type":"integer"},"functions_hit":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TraceCoverageLcovLineRatioWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let mut rec = rustre_trace_coverage::LcovRecord::new(); rec.lines_found = args.get("lines_found").and_then(Value::as_u64).unwrap_or(10); rec.lines_hit = args.get("lines_hit").and_then(Value::as_u64).unwrap_or(5); rec.functions_found = args.get("functions_found").and_then(Value::as_u64).unwrap_or(4); rec.functions_hit = args.get("functions_hit").and_then(Value::as_u64).unwrap_or(2); Ok(ToolResult::text(json!({"line_ratio":rec.line_coverage_ratio(),"function_ratio":rec.function_coverage_ratio(),"source":"rustre_trace_coverage::LcovRecord::line_coverage_ratio"}).to_string())) } }

pub struct TraceCoverageHeatmapHeatAtWire3Tool;
impl TraceCoverageHeatmapHeatAtWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_coverage_heatmap_heat_at_wire3".to_string(), description: "Query heat at a specific address via rustre_trace_coverage::CoverageHeatmap::heat_at.".to_string(), input_schema: json!({"type":"object","properties":{"addrs":{"type":"array","items":{"type":"integer"}},"query":{"type":"integer"}},"required":["addrs","query"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TraceCoverageHeatmapHeatAtWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addrs: Vec<u64> = args.get("addrs").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default(); let q = args.get("query").and_then(Value::as_u64).unwrap_or(0); let mut run = rustre_trace_coverage::CoverageRun::new("h"); for (i, a) in addrs.iter().enumerate() { run.record_bb_n(*a, (i as u64)+1); } let h = rustre_trace_coverage::CoverageHeatmap::build(&run); Ok(ToolResult::text(json!({"entries":h.entries.len(),"max_count":h.max_count,"heat_at":h.heat_at(q),"source":"rustre_trace_coverage::CoverageHeatmap::heat_at"}).to_string())) } }

pub struct TraceCoverageBlockColorInfoRgbaWire3Tool;
impl TraceCoverageBlockColorInfoRgbaWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_coverage_block_color_info_rgba_wire3".to_string(), description: "Compute RGBA color for a BB via rustre_trace_coverage::BlockColorInfo::rgba_color.".to_string(), input_schema: json!({"type":"object","properties":{"addr":{"type":"integer"},"count":{"type":"integer"},"max":{"type":"integer"}},"required":["addr","count","max"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TraceCoverageBlockColorInfoRgbaWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("addr").and_then(Value::as_u64).unwrap_or(0); let count = args.get("count").and_then(Value::as_u64).unwrap_or(0); let max = args.get("max").and_then(Value::as_u64).unwrap_or(1); let mut run = rustre_trace_coverage::CoverageRun::new("c"); if count > 0 { run.record_bb_n(addr, count); } let info = rustre_trace_coverage::BlockColorInfo::for_addr(&run, addr, max); let (r,g,b,a) = info.rgba_color(); Ok(ToolResult::text(json!({"addr":info.addr,"is_covered":info.is_covered,"visit_count":info.visit_count,"heat":info.heat,"rgba":[r,g,b,a],"source":"rustre_trace_coverage::BlockColorInfo::rgba_color"}).to_string())) } }

pub struct TraceCoverageSessionAddRunWire3Tool;
impl TraceCoverageSessionAddRunWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_coverage_session_add_run_wire3".to_string(), description: "Create a CoverageSession, add a run, and report run_count/bitmap_coverage via rustre_trace_coverage::CoverageSession.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"addrs":{"type":"array","items":{"type":"integer"}}},"required":["addrs"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TraceCoverageSessionAddRunWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).unwrap_or("s"); let addrs: Vec<u64> = args.get("addrs").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default(); let mut sess = rustre_trace_coverage::CoverageSession::new(name); let mut run = rustre_trace_coverage::CoverageRun::new("r"); for a in &addrs { run.record_bb(*a); } sess.add_run(run); let merged = sess.merged(); Ok(ToolResult::text(json!({"run_count":sess.run_count(),"bitmap_coverage":sess.bitmap_coverage(),"merged_unique_bbs":merged.unique_bbs(),"source":"rustre_trace_coverage::CoverageSession::add_run"}).to_string())) } }

pub struct TraceCoverageCovEdgeNewWire3Tool;
impl TraceCoverageCovEdgeNewWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_coverage_covedge_new_wire3".to_string(), description: "Construct CovEdge and format its display via rustre_trace_coverage::CovEdge::new.".to_string(), input_schema: json!({"type":"object","properties":{"from":{"type":"integer"},"to":{"type":"integer"}},"required":["from","to"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TraceCoverageCovEdgeNewWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let from = args.get("from").and_then(Value::as_u64).unwrap_or(0); let to = args.get("to").and_then(Value::as_u64).unwrap_or(0); let e = rustre_trace_coverage::CovEdge::new(from, to); Ok(ToolResult::text(json!({"from":e.from,"to":e.to,"display":e.to_string(),"source":"rustre_trace_coverage::CovEdge::new"}).to_string())) } }

pub struct TraceCoverageRunHeatmapWire3Tool;
impl TraceCoverageRunHeatmapWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_coverage_run_heatmap_wire3".to_string(), description: "Sorted (addr, count) heatmap from a CoverageRun via rustre_trace_coverage::CoverageRun::heatmap.".to_string(), input_schema: json!({"type":"object","properties":{"addrs":{"type":"array","items":{"type":"integer"}}},"required":["addrs"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TraceCoverageRunHeatmapWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addrs: Vec<u64> = args.get("addrs").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default(); let q = addrs.first().copied().unwrap_or(0); let mut run = rustre_trace_coverage::CoverageRun::new("h").with_timestamp(1).with_source_tag("wire3"); for (i, a) in addrs.iter().enumerate() { run.record_bb_n(*a, (i as u64) + 1); } let hm = run.heatmap(); Ok(ToolResult::text(json!({"count":hm.len(),"timestamp":run.timestamp,"source_tag":run.source_tag,"is_covered_first":run.is_covered(q),"source":"rustre_trace_coverage::CoverageRun::heatmap"}).to_string())) } }

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TraceCoveragePercentTool::definition(), Box::new(TraceCoveragePercentTool)),
        (TraceCoverageComputeFunctionStatsTool::definition(), Box::new(TraceCoverageComputeFunctionStatsTool)),
        (TraceCoverageParseLcovTool::definition(), Box::new(TraceCoverageParseLcovTool)),
        (TraceCoverageToCustomBinaryTool::definition(), Box::new(TraceCoverageToCustomBinaryTool)),
        (TraceCoverageMergeRunsTool::definition(), Box::new(TraceCoverageMergeRunsTool)),
        (TraceCoverageMapWireT1Tool::definition(), Box::new(TraceCoverageMapWireT1Tool)),
        (TraceCoverageAflBitmapCountTool::definition(), Box::new(TraceCoverageAflBitmapCountTool)),
        (TraceCoverageAflNewCoverageTool::definition(), Box::new(TraceCoverageAflNewCoverageTool)),
        (TraceCoverageDrcovParseTool::definition(), Box::new(TraceCoverageDrcovParseTool)),
        (TraceCoverageParseCustomBinaryTool::definition(), Box::new(TraceCoverageParseCustomBinaryTool)),
        (TraceCoverageAflJaccardTool::definition(), Box::new(TraceCoverageAflJaccardTool)),
        (TraceCoverageCovEdgeDisplayTool::definition(), Box::new(TraceCoverageCovEdgeDisplayTool)),
        (TraceCoverageFunctionStatsPctTool::definition(), Box::new(TraceCoverageFunctionStatsPctTool)),
        (TraceCoverageParseLcovWireTool::definition(), Box::new(TraceCoverageParseLcovWireTool)),
        (TraceCoverageCovBitmapOpsTool::definition(), Box::new(TraceCoverageCovBitmapOpsTool)),
        (TraceCoverageDiffOverlapPctTool::definition(), Box::new(TraceCoverageDiffOverlapPctTool)),
        (TraceCoverageHitCountTool::definition(), Box::new(TraceCoverageHitCountTool)),
        (TraceCoverageRatioTool::definition(), Box::new(TraceCoverageRatioTool)),
        (TraceCoverageMapNewTool::definition(), Box::new(TraceCoverageMapNewTool)),
        (TraceCoverageRunHotBbsTool::definition(), Box::new(TraceCoverageRunHotBbsTool)),
        (TraceCoverageRunSummaryTool::definition(), Box::new(TraceCoverageRunSummaryTool)),
        (TraceCoverageRunVisitAtTool::definition(), Box::new(TraceCoverageRunVisitAtTool)),
        (TraceCoverageDataStatsTool::definition(), Box::new(TraceCoverageDataStatsTool)),
        (TraceCoverageCovBitmapClearBitsTool::definition(), Box::new(TraceCoverageCovBitmapClearBitsTool)),
        (TraceCoverageCovBitmapRecordEdgeTool::definition(), Box::new(TraceCoverageCovBitmapRecordEdgeTool)),
        (TraceCoverageHeatmapHottestTool::definition(), Box::new(TraceCoverageHeatmapHottestTool)),
        (TraceCoverageLighthouseRoundtripTool::definition(), Box::new(TraceCoverageLighthouseRoundtripTool)),
        (TraceCoverageDrcovResolveTool::definition(), Box::new(TraceCoverageDrcovResolveTool)),
        (TraceCoverageFunctionStatsFlagsTool::definition(), Box::new(TraceCoverageFunctionStatsFlagsTool)),
        (TraceCoverageDataAllBbAddressesWire3Tool::definition(), Box::new(TraceCoverageDataAllBbAddressesWire3Tool)),
        (TraceCoverageLcovLineRatioWire3Tool::definition(), Box::new(TraceCoverageLcovLineRatioWire3Tool)),
        (TraceCoverageHeatmapHeatAtWire3Tool::definition(), Box::new(TraceCoverageHeatmapHeatAtWire3Tool)),
        (TraceCoverageBlockColorInfoRgbaWire3Tool::definition(), Box::new(TraceCoverageBlockColorInfoRgbaWire3Tool)),
        (TraceCoverageSessionAddRunWire3Tool::definition(), Box::new(TraceCoverageSessionAddRunWire3Tool)),
        (TraceCoverageCovEdgeNewWire3Tool::definition(), Box::new(TraceCoverageCovEdgeNewWire3Tool)),
        (TraceCoverageRunHeatmapWire3Tool::definition(), Box::new(TraceCoverageRunHeatmapWire3Tool)),
    ]
}
