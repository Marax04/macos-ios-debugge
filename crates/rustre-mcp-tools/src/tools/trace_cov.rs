//! MCP wrappers for the rustre-trace_cov crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes};

pub struct TraceCovParseLcovTool;

pub struct TraceCovBitmapNewTool;

pub struct TraceCovParseCustomBinaryV2Tool;
impl TraceCovParseCustomBinaryV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_parse_custom_binary_v2".to_string(),
            description: "Parse custom binary coverage.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCovParseCustomBinaryV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        match rustre_trace_coverage::parse_custom_binary(&data) {
            Ok(run) => Ok(ToolResult::text(json!({"unique_bbs":run.unique_bbs(),"total_executions":run.total_bb_executions(),"source":"rustre_trace_coverage::parse_custom_binary"}).to_string())),
            Err(e) => Err(McpError::InvalidParams(format!("parse: {e}"))),
        }
    }
}

pub struct TraceCovToLcovStringV2Tool;
impl TraceCovToLcovStringV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_to_lcov_string_v2".to_string(),
            description: "Serialize LcovRecord list to LCOV info text.".to_string(),
            input_schema: json!({"type":"object","required":["records"],"properties":{"records":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCovToLcovStringV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("records").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'records'".into()))?;
        let recs: Vec<rustre_trace_coverage::LcovRecord> = serde_json::from_str(s).map_err(|e| McpError::InvalidParams(format!("json: {e}")))?;
        let out = rustre_trace_coverage::to_lcov_string(&recs);
        Ok(ToolResult::text(json!({"lcov":out,"records":recs.len(),"source":"rustre_trace_coverage::to_lcov_string"}).to_string()))
    }
}

pub struct TraceCovLoadAflBitmapV2Tool;
impl TraceCovLoadAflBitmapV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_load_afl_bitmap_v2".to_string(),
            description: "Load AFL bitmap stats.".to_string(),
            input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCovLoadAflBitmapV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let bm = rustre_trace_coverage::load_afl_bitmap(&data);
        let set = rustre_trace_coverage::afl_bitmap_coverage(&bm);
        Ok(ToolResult::text(json!({"size":bm.size,"set_bits":set,"is_empty":bm.is_empty(),"ratio":bm.coverage_ratio(),"source":"rustre_trace_coverage::load_afl_bitmap"}).to_string()))
    }
}

pub struct TraceCovAflNewEdgesV2Tool;
impl TraceCovAflNewEdgesV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_afl_new_edges_v2".to_string(),
            description: "Count new edges of b vs a.".to_string(),
            input_schema: json!({"type":"object","required":["a","b"],"properties":{"a":{"type":"array","items":{"type":"integer"}},"b":{"type":"array","items":{"type":"integer"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCovAflNewEdgesV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a: Vec<u8> = args.get("a").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect();
        let b: Vec<u8> = args.get("b").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?.iter().filter_map(|v| v.as_u64().map(|n| n as u8)).collect();
        let ba = rustre_trace_coverage::load_afl_bitmap(&a);
        let bb = rustre_trace_coverage::load_afl_bitmap(&b);
        let new_edges = rustre_trace_coverage::afl_new_coverage(&ba, &bb);
        Ok(ToolResult::text(json!({"new_edges":new_edges,"jaccard":ba.jaccard(&bb),"source":"rustre_trace_coverage::afl_new_coverage"}).to_string()))
    }
}

pub struct TraceCovDrcovToRunV2Tool;
impl TraceCovDrcovToRunV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_drcov_to_run_v2".to_string(),
            description: "Parse DRcov text and summarise CoverageRun.".to_string(),
            input_schema: json!({"type":"object","required":["input"],"properties":{"input":{"type":"string"},"name":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCovDrcovToRunV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let input = args.get("input").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'input'".into()))?;
        let name = args.get("name").and_then(Value::as_str).unwrap_or("drcov").to_string();
        let d = rustre_trace_coverage::DrcovData::parse(input);
        let run = d.to_run(name);
        Ok(ToolResult::text(json!({"modules":d.modules.len(),"basic_blocks":d.basic_blocks.len(),"unique_bbs":run.unique_bbs(),"source":"rustre_trace_coverage::DrcovData::to_run"}).to_string()))
    }
}

pub struct TraceCovLighthouseFromRunV2Tool;
impl TraceCovLighthouseFromRunV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_lighthouse_from_run_v2".to_string(),
            description: "Convert CoverageRun (JSON) to LightHouse JSON.".to_string(),
            input_schema: json!({"type":"object","required":["run"],"properties":{"run":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCovLighthouseFromRunV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("run").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'run'".into()))?;
        let run: rustre_trace_coverage::CoverageRun = serde_json::from_str(s).map_err(|e| McpError::InvalidParams(format!("json: {e}")))?;
        let lh = rustre_trace_coverage::LighthouseJson::from_run(&run);
        let json_str = lh.to_json().map_err(|e| McpError::InvalidParams(format!("ser: {e}")))?;
        Ok(ToolResult::text(json!({"entries":lh.coverage.len(),"name":lh.name,"json":json_str,"source":"rustre_trace_coverage::LighthouseJson::from_run"}).to_string()))
    }
}

pub struct TraceCovHeatmapBuildV2Tool;
impl TraceCovHeatmapBuildV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_heatmap_build_v2".to_string(),
            description: "Build CoverageHeatmap from CoverageRun.".to_string(),
            input_schema: json!({"type":"object","required":["run"],"properties":{"run":{"type":"string"},"top":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCovHeatmapBuildV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("run").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'run'".into()))?;
        let run: rustre_trace_coverage::CoverageRun = serde_json::from_str(s).map_err(|e| McpError::InvalidParams(format!("json: {e}")))?;
        let hm = rustre_trace_coverage::CoverageHeatmap::build(&run);
        let n = args.get("top").and_then(Value::as_u64).unwrap_or(10) as usize;
        let top = hm.hottest(n);
        Ok(ToolResult::text(json!({"entries":hm.entries.len(),"max_count":hm.max_count,"top":top,"source":"rustre_trace_coverage::CoverageHeatmap::build"}).to_string()))
    }
}

pub struct TraceCovBlockColorsV2Tool;
impl TraceCovBlockColorsV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_block_colors_v2".to_string(),
            description: "Generate BlockColorInfo for addrs.".to_string(),
            input_schema: json!({"type":"object","required":["run","addrs"],"properties":{"run":{"type":"string"},"addrs":{"type":"array","items":{"type":"integer"}}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCovBlockColorsV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("run").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'run'".into()))?;
        let run: rustre_trace_coverage::CoverageRun = serde_json::from_str(s).map_err(|e| McpError::InvalidParams(format!("json: {e}")))?;
        let addrs: Vec<u64> = args.get("addrs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'addrs'".into()))?.iter().filter_map(Value::as_u64).collect();
        let colors = rustre_trace_coverage::generate_block_colors(&run, &addrs);
        let covered = colors.iter().filter(|c| c.is_covered).count();
        Ok(ToolResult::text(json!({"count":colors.len(),"covered":covered,"source":"rustre_trace_coverage::generate_block_colors"}).to_string()))
    }
}

pub struct TraceCovDiffComputeV2Tool;
impl TraceCovDiffComputeV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_diff_compute_v2".to_string(),
            description: "Compute CoverageDiff between two runs.".to_string(),
            input_schema: json!({"type":"object","required":["a","b"],"properties":{"a":{"type":"string"},"b":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCovDiffComputeV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let sa = args.get("a").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let sb = args.get("b").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let a: rustre_trace_coverage::CoverageRun = serde_json::from_str(sa).map_err(|e| McpError::InvalidParams(format!("a json: {e}")))?;
        let b: rustre_trace_coverage::CoverageRun = serde_json::from_str(sb).map_err(|e| McpError::InvalidParams(format!("b json: {e}")))?;
        let d = rustre_trace_coverage::CoverageDiff::compute(&a, &b);
        Ok(ToolResult::text(json!({"new_in_a":d.new_in_a.len(),"new_in_b":d.new_in_b.len(),"in_both":d.in_both.len(),"edges_only_in_a":d.edges_only_in_a.len(),"edges_only_in_b":d.edges_only_in_b.len(),"jaccard":d.jaccard,"overlap_pct":d.overlap_pct(),"source":"rustre_trace_coverage::CoverageDiff::compute"}).to_string()))
    }
}

pub struct TraceCovMergeAllRunsV2Tool;
impl TraceCovMergeAllRunsV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_merge_all_runs_v2".to_string(),
            description: "Merge all runs in a CoverageData.".to_string(),
            input_schema: json!({"type":"object","required":["data"],"properties":{"data":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCovMergeAllRunsV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("data").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'data'".into()))?;
        let data: rustre_trace_coverage::CoverageData = serde_json::from_str(s).map_err(|e| McpError::InvalidParams(format!("json: {e}")))?;
        let merged = rustre_trace_coverage::merge_all_runs(&data);
        Ok(ToolResult::text(json!({"runs":data.run_count(),"unique_bbs":merged.unique_bbs(),"unique_edges":merged.unique_edges(),"total_executions":merged.total_bb_executions(),"source":"rustre_trace_coverage::merge_all_runs"}).to_string()))
    }
}

pub struct TraceCovHtmlReportV2Tool;
impl TraceCovHtmlReportV2Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "trace_coverage_html_report_v2".to_string(),
            description: "Generate HTML coverage report.".to_string(),
            input_schema: json!({"type":"object","required":["run","functions"],"properties":{"title":{"type":"string"},"run":{"type":"string"},"functions":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TraceCovHtmlReportV2Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let title = args.get("title").and_then(Value::as_str).unwrap_or("Coverage Report");
        let sr = args.get("run").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'run'".into()))?;
        let sf = args.get("functions").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'functions'".into()))?;
        let run: rustre_trace_coverage::CoverageRun = serde_json::from_str(sr).map_err(|e| McpError::InvalidParams(format!("run json: {e}")))?;
        let fns: Vec<rustre_trace_coverage::FunctionStats> = serde_json::from_str(sf).map_err(|e| McpError::InvalidParams(format!("functions json: {e}")))?;
        let html = rustre_trace_coverage::generate_html_report(title, &run, &fns);
        Ok(ToolResult::text(json!({"html_len":html.len(),"functions":fns.len(),"source":"rustre_trace_coverage::generate_html_report"}).to_string()))
    }
}

pub struct TraceCovBitmapUnionWire3Tool;
impl TraceCovBitmapUnionWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_coverage_covbitmap_union_wire3".to_string(), description: "Bitwise union of two CovBitmaps via rustre_trace_coverage::CovBitmap::union.".to_string(), input_schema: json!({"type":"object","properties":{"a_hex":{"type":"string"},"b_hex":{"type":"string"}},"required":["a_hex","b_hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TraceCovBitmapUnionWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ah: String = args.get("a_hex").and_then(Value::as_str).unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect(); let bh: String = args.get("b_hex").and_then(Value::as_str).unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect(); let a: Vec<u8> = (0..ah.len()).step_by(2).filter_map(|i| u8::from_str_radix(ah.get(i..i+2)?, 16).ok()).collect(); let b: Vec<u8> = (0..bh.len()).step_by(2).filter_map(|i| u8::from_str_radix(bh.get(i..i+2)?, 16).ok()).collect(); let am = rustre_trace_coverage::CovBitmap::from_afl_bitmap(&a); let bm = rustre_trace_coverage::CovBitmap::from_afl_bitmap(&b); let u = am.union(&bm); Ok(ToolResult::text(json!({"size":u.size,"count_set":u.count_set(),"source":"rustre_trace_coverage::CovBitmap::union"}).to_string())) } }

pub struct TraceCovBitmapIntersectionWire3Tool;
impl TraceCovBitmapIntersectionWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_coverage_covbitmap_intersection_wire3".to_string(), description: "Bitwise intersection of two CovBitmaps via rustre_trace_coverage::CovBitmap::intersection.".to_string(), input_schema: json!({"type":"object","properties":{"a_hex":{"type":"string"},"b_hex":{"type":"string"}},"required":["a_hex","b_hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TraceCovBitmapIntersectionWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ah: String = args.get("a_hex").and_then(Value::as_str).unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect(); let bh: String = args.get("b_hex").and_then(Value::as_str).unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect(); let a: Vec<u8> = (0..ah.len()).step_by(2).filter_map(|i| u8::from_str_radix(ah.get(i..i+2)?, 16).ok()).collect(); let b: Vec<u8> = (0..bh.len()).step_by(2).filter_map(|i| u8::from_str_radix(bh.get(i..i+2)?, 16).ok()).collect(); let am = rustre_trace_coverage::CovBitmap::from_afl_bitmap(&a); let bm = rustre_trace_coverage::CovBitmap::from_afl_bitmap(&b); let u = am.intersection(&bm); Ok(ToolResult::text(json!({"size":u.size,"count_set":u.count_set(),"source":"rustre_trace_coverage::CovBitmap::intersection"}).to_string())) } }

pub struct TraceCovBitmapDifferenceWire3Tool;
impl TraceCovBitmapDifferenceWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_coverage_covbitmap_difference_wire3".to_string(), description: "Bitwise A AND NOT B via rustre_trace_coverage::CovBitmap::difference.".to_string(), input_schema: json!({"type":"object","properties":{"a_hex":{"type":"string"},"b_hex":{"type":"string"}},"required":["a_hex","b_hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TraceCovBitmapDifferenceWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ah: String = args.get("a_hex").and_then(Value::as_str).unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect(); let bh: String = args.get("b_hex").and_then(Value::as_str).unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect(); let a: Vec<u8> = (0..ah.len()).step_by(2).filter_map(|i| u8::from_str_radix(ah.get(i..i+2)?, 16).ok()).collect(); let b: Vec<u8> = (0..bh.len()).step_by(2).filter_map(|i| u8::from_str_radix(bh.get(i..i+2)?, 16).ok()).collect(); let am = rustre_trace_coverage::CovBitmap::from_afl_bitmap(&a); let bm = rustre_trace_coverage::CovBitmap::from_afl_bitmap(&b); let u = am.difference(&bm); Ok(ToolResult::text(json!({"size":u.size,"count_set":u.count_set(),"source":"rustre_trace_coverage::CovBitmap::difference"}).to_string())) } }

pub struct TraceCovBitmapIsFullWire3Tool;
impl TraceCovBitmapIsFullWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_coverage_covbitmap_is_full_wire3".to_string(), description: "Report is_full/is_empty/coverage_ratio via rustre_trace_coverage::CovBitmap.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TraceCovBitmapIsFullWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s: String = args.get("hex").and_then(Value::as_str).unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect(); let data: Vec<u8> = (0..s.len()).step_by(2).filter_map(|i| u8::from_str_radix(s.get(i..i+2)?, 16).ok()).collect(); let bm = rustre_trace_coverage::CovBitmap::from_afl_bitmap(&data); Ok(ToolResult::text(json!({"size":bm.size,"is_full":bm.is_full(),"is_empty":bm.is_empty(),"coverage_ratio":bm.coverage_ratio(),"source":"rustre_trace_coverage::CovBitmap::is_full"}).to_string())) } }

pub struct TraceCovBitmapSetBitsWire3Tool;
impl TraceCovBitmapSetBitsWire3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "trace_coverage_covbitmap_set_bits_wire3".to_string(), description: "Enumerate set-bit indices via rustre_trace_coverage::CovBitmap::set_bits.".to_string(), input_schema: json!({"type":"object","properties":{"hex":{"type":"string"}},"required":["hex"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TraceCovBitmapSetBitsWire3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s: String = args.get("hex").and_then(Value::as_str).unwrap_or("").chars().filter(|c| !c.is_whitespace()).collect(); let data: Vec<u8> = (0..s.len()).step_by(2).filter_map(|i| u8::from_str_radix(s.get(i..i+2)?, 16).ok()).collect(); let bm = rustre_trace_coverage::CovBitmap::from_afl_bitmap(&data); let bits = bm.set_bits(); Ok(ToolResult::text(json!({"count":bits.len(),"first16":bits.iter().take(16).collect::<Vec<_>>(),"count_clear":bm.count_clear(),"source":"rustre_trace_coverage::CovBitmap::set_bits"}).to_string())) } }

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TraceCovParseLcovTool::definition(), Box::new(TraceCovParseLcovTool)),
        (TraceCovBitmapNewTool::definition(), Box::new(TraceCovBitmapNewTool)),
        (TraceCovParseCustomBinaryV2Tool::definition(), Box::new(TraceCovParseCustomBinaryV2Tool)),
        (TraceCovToLcovStringV2Tool::definition(), Box::new(TraceCovToLcovStringV2Tool)),
        (TraceCovLoadAflBitmapV2Tool::definition(), Box::new(TraceCovLoadAflBitmapV2Tool)),
        (TraceCovAflNewEdgesV2Tool::definition(), Box::new(TraceCovAflNewEdgesV2Tool)),
        (TraceCovDrcovToRunV2Tool::definition(), Box::new(TraceCovDrcovToRunV2Tool)),
        (TraceCovLighthouseFromRunV2Tool::definition(), Box::new(TraceCovLighthouseFromRunV2Tool)),
        (TraceCovHeatmapBuildV2Tool::definition(), Box::new(TraceCovHeatmapBuildV2Tool)),
        (TraceCovBlockColorsV2Tool::definition(), Box::new(TraceCovBlockColorsV2Tool)),
        (TraceCovDiffComputeV2Tool::definition(), Box::new(TraceCovDiffComputeV2Tool)),
        (TraceCovMergeAllRunsV2Tool::definition(), Box::new(TraceCovMergeAllRunsV2Tool)),
        (TraceCovHtmlReportV2Tool::definition(), Box::new(TraceCovHtmlReportV2Tool)),
        (TraceCovBitmapUnionWire3Tool::definition(), Box::new(TraceCovBitmapUnionWire3Tool)),
        (TraceCovBitmapIntersectionWire3Tool::definition(), Box::new(TraceCovBitmapIntersectionWire3Tool)),
        (TraceCovBitmapDifferenceWire3Tool::definition(), Box::new(TraceCovBitmapDifferenceWire3Tool)),
        (TraceCovBitmapIsFullWire3Tool::definition(), Box::new(TraceCovBitmapIsFullWire3Tool)),
        (TraceCovBitmapSetBitsWire3Tool::definition(), Box::new(TraceCovBitmapSetBitsWire3Tool)),
    ]
}
