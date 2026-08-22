//! MCP wrappers for the rustre-fuzz_cov crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{pe_editor_hex_decode};

pub struct FuzzCovRleEncodeTool;

pub struct FuzzCovCoverageFractionTool;

pub struct FuzzCovRleIsBeneficialTool;

pub struct FuzzCovDrcovParseTool;
impl FuzzCovDrcovParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_cov_drcov_parse".to_string(),
            description: "Parse DRcov file (hex).".to_string(),
            input_schema: json!({"type": "object", "properties": {"data_hex": {"type": "string"}}, "required": ["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzCovDrcovParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing data_hex".into()))?;
        let data = pe_editor_hex_decode(hex)?;
        let f = rustre_fuzz_cov::DrcovFile::parse(&data).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        Ok(ToolResult::text(json!({"version": f.version, "flavor": f.flavor, "modules": f.modules.len(), "bbs": f.bbs.len(), "source": "rustre_fuzz_cov::DrcovFile::parse"}).to_string()))
    }
}

pub struct FuzzCovDrcovHeaderParseTool;
impl FuzzCovDrcovHeaderParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_cov_drcov_header_parse".to_string(),
            description: "Parse DRcov header.".to_string(),
            input_schema: json!({"type": "object", "properties": {"data_hex": {"type": "string"}}, "required": ["data_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzCovDrcovHeaderParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing data_hex".into()))?;
        let data = pe_editor_hex_decode(hex)?;
        let (h, c) = rustre_fuzz_cov::DrcovHeader::parse(&data).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        Ok(ToolResult::text(json!({"version": h.version, "flavor": h.flavor, "module_count": h.module_count, "consumed": c, "source": "rustre_fuzz_cov::DrcovHeader::parse"}).to_string()))
    }
}

pub struct FuzzCovPcGuardDensityTool;
impl FuzzCovPcGuardDensityTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_cov_pcguard_density".to_string(),
            description: "PC-guard density + hits.".to_string(),
            input_schema: json!({"type": "object", "properties": {"bitmap_hex": {"type": "string"}}, "required": ["bitmap_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzCovPcGuardDensityTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("bitmap_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing bitmap_hex".into()))?;
        let bytes = pe_editor_hex_decode(hex)?;
        let bm = rustre_fuzz_cov::PcGuardBitmap::from_bytes(bytes);
        Ok(ToolResult::text(json!({"size": bm.bits.len(), "hit_count": bm.coverage_count(), "density": bm.density(), "hash": format!("{:016x}", bm.hash()), "source": "rustre_fuzz_cov::PcGuardBitmap"}).to_string()))
    }
}

pub struct FuzzCovPcGuardHashTool;
impl FuzzCovPcGuardHashTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_cov_pcguard_hash".to_string(),
            description: "FNV-1a hash of PC-guard bitmap.".to_string(),
            input_schema: json!({"type": "object", "properties": {"bitmap_hex": {"type": "string"}}, "required": ["bitmap_hex"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzCovPcGuardHashTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hex = args.get("bitmap_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing bitmap_hex".into()))?;
        let bytes = pe_editor_hex_decode(hex)?;
        let bm = rustre_fuzz_cov::PcGuardBitmap::from_bytes(bytes);
        Ok(ToolResult::text(json!({"hash": format!("{:016x}", bm.hash()), "source": "rustre_fuzz_cov::PcGuardBitmap::hash"}).to_string()))
    }
}

pub struct FuzzCovLcovParseTool;
impl FuzzCovLcovParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_cov_lcov_parse".to_string(),
            description: "Parse lcov .info body.".to_string(),
            input_schema: json!({"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzCovLcovParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing text".into()))?;
        let mut p = rustre_fuzz_cov::LcovParser::new();
        p.parse(text).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?;
        let src: Vec<String> = p.source_files().into_iter().map(String::from).collect();
        Ok(ToolResult::text(json!({"records": p.records.len(), "total_lines_hit": p.total_lines_hit(), "total_branch_hits": p.total_branch_hits(), "overall_line_coverage_pct": p.overall_line_coverage_pct(), "source_files": src, "source": "rustre_fuzz_cov::LcovParser::parse"}).to_string()))
    }
}

pub struct FuzzCovCorpusPruneTool;
impl FuzzCovCorpusPruneTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_cov_corpus_prune".to_string(),
            description: "Greedy set-cover corpus min.".to_string(),
            input_schema: json!({"type": "object", "properties": {"inputs": {"type": "array"}}, "required": ["inputs"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzCovCorpusPruneTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("inputs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing inputs".into()))?;
        let mut items: Vec<(usize, Vec<u64>)> = Vec::new();
        for it in arr {
            let id = it.get("id").and_then(Value::as_u64).unwrap_or(0) as usize;
            let edges: Vec<u64> = it.get("edges").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
            items.push((id, edges));
        }
        let selected = rustre_fuzz_cov::CorpusPruner::new().prune(items);
        let count = selected.len();
        Ok(ToolResult::text(json!({"selected": selected, "count": count, "source": "rustre_fuzz_cov::CorpusPruner::prune"}).to_string()))
    }
}

pub struct FuzzCovCoverageDiffTool;
impl FuzzCovCoverageDiffTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_cov_coverage_diff".to_string(),
            description: "Set-diff + Jaccard.".to_string(),
            input_schema: json!({"type": "object", "properties": {"a": {"type": "array"}, "b": {"type": "array"}}, "required": ["a", "b"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzCovCoverageDiffTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a: Vec<u64> = args.get("a").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
        let b: Vec<u64> = args.get("b").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
        let mut ra = rustre_fuzz_cov::CoverageRun::new("a");
        for x in &a { ra.hit(*x); }
        let mut rb = rustre_fuzz_cov::CoverageRun::new("b");
        for x in &b { rb.hit(*x); }
        let d = rustre_fuzz_cov::CoverageDatabase::diff(&ra, &rb);
        let jac = d.jaccard();
        let identical = d.is_identical();
        Ok(ToolResult::text(json!({"only_in_a": d.only_in_a, "only_in_b": d.only_in_b, "in_both": d.in_both, "jaccard": jac, "identical": identical, "source": "rustre_fuzz_cov::CoverageDatabase::diff"}).to_string()))
    }
}

pub struct FuzzCovCoverageStatsTool;
impl FuzzCovCoverageStatsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_cov_coverage_stats".to_string(),
            description: "Stats for a run.".to_string(),
            input_schema: json!({"type": "object", "properties": {"hits": {"type": "array"}, "total_known_blocks": {"type": "integer"}}, "required": ["hits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzCovCoverageStatsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("hits").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing hits".into()))?;
        let mut run = rustre_fuzz_cov::CoverageRun::new("r");
        for it in arr {
            if let Some(a) = it.as_array() {
                let addr = a.first().and_then(Value::as_u64).unwrap_or(0);
                let cnt = a.get(1).and_then(Value::as_u64).unwrap_or(1);
                run.hit_n(addr, cnt);
            }
        }
        let total = args.get("total_known_blocks").and_then(Value::as_u64).unwrap_or(0);
        let s = rustre_fuzz_cov::CoverageDatabase::stats(&run, total);
        Ok(ToolResult::text(json!({"total_blocks": s.total_blocks, "hit_blocks": s.hit_blocks, "coverage_pct": s.coverage_pct, "unique_blocks": s.unique_blocks, "max_hit_count": s.max_hit_count, "total_hits": s.total_hits, "source": "rustre_fuzz_cov::CoverageDatabase::stats"}).to_string()))
    }
}

pub struct FuzzCovHistogramTool;
impl FuzzCovHistogramTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_cov_histogram".to_string(),
            description: "Hit-count histogram.".to_string(),
            input_schema: json!({"type": "object", "properties": {"hits": {"type": "array"}}, "required": ["hits"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzCovHistogramTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("hits").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing hits".into()))?;
        let mut run = rustre_fuzz_cov::CoverageRun::new("r");
        for it in arr {
            if let Some(a) = it.as_array() {
                let addr = a.first().and_then(Value::as_u64).unwrap_or(0);
                let cnt = a.get(1).and_then(Value::as_u64).unwrap_or(1);
                run.hit_n(addr, cnt);
            }
        }
        let h = rustre_fuzz_cov::CoverageHistogram::from_run(&run);
        let buckets: Vec<(u64, u64)> = h.buckets.iter().map(|(k,v)| (*k, *v)).collect();
        Ok(ToolResult::text(json!({"buckets": buckets, "total_blocks": h.total_blocks(), "max_bucket": h.max_bucket(), "median": h.median(), "mean": h.mean(), "source": "rustre_fuzz_cov::CoverageHistogram::from_run"}).to_string()))
    }
}

pub struct FuzzCovEdgeMapAnalyzeTool;
impl FuzzCovEdgeMapAnalyzeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "fuzz_cov_edge_map_analyze".to_string(),
            description: "EdgeCoverageMap analysis.".to_string(),
            input_schema: json!({"type": "object", "properties": {"edges": {"type": "array"}, "threshold": {"type": "integer"}}, "required": ["edges"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for FuzzCovEdgeMapAnalyzeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let arr = args.get("edges").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing edges".into()))?;
        let mut m = rustre_fuzz_cov::EdgeCoverageMap::new();
        for it in arr {
            if let Some(a) = it.as_array() {
                let f = a.first().and_then(Value::as_u64).unwrap_or(0);
                let t = a.get(1).and_then(Value::as_u64).unwrap_or(0);
                let c = a.get(2).and_then(Value::as_u64).unwrap_or(1);
                m.record_n(f, t, c);
            }
        }
        let thr = args.get("threshold").and_then(Value::as_u64).unwrap_or(1);
        let hot = m.hot_edges(thr);
        Ok(ToolResult::text(json!({"edge_count": m.edge_count(), "total_traversals": m.total_traversals(), "hot_edges": hot, "source": "rustre_fuzz_cov::EdgeCoverageMap"}).to_string()))
    }
}

pub struct FuzzCovDrcovModuleContainsTool;
impl FuzzCovDrcovModuleContainsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_drcov_module_contains".to_string(), description: "DrcovModule::contains + to_offset + size.".to_string(), input_schema: json!({"type":"object","required":["base","end","addr"],"properties":{"base":{"type":"integer"},"end":{"type":"integer"},"addr":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovDrcovModuleContainsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?; let end = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'end'".into()))?; let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let m = rustre_fuzz_cov::DrcovModule::new(0, "m", base, end).with_checksum(0); Ok(ToolResult::text(json!({"contains": m.contains(addr), "offset": m.to_offset(addr), "size": m.size(), "source":"rustre_fuzz_cov::DrcovModule"}).to_string())) } }

pub struct FuzzCovDrcovBlocksPerModuleTool;
impl FuzzCovDrcovBlocksPerModuleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_drcov_blocks_per_module".to_string(), description: "DrcovFile::blocks_per_module via parsed data.".to_string(), input_schema: json!({"type":"object","required":["data_hex"],"properties":{"data_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovDrcovBlocksPerModuleTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hex = args.get("data_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing data_hex".into()))?; let data = crate::hex_decode(hex)?; let f = rustre_fuzz_cov::DrcovFile::parse(&data).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?; let map = f.blocks_per_module(); let entries: Vec<_> = map.into_iter().map(|(k,v)| json!([k,v])).collect(); Ok(ToolResult::text(json!({"per_module": entries, "source":"rustre_fuzz_cov::DrcovFile::blocks_per_module"}).to_string())) } }

pub struct FuzzCovCoverageRunHotBlocksTool;
impl FuzzCovCoverageRunHotBlocksTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_coverage_run_hot_blocks".to_string(), description: "CoverageRun hot_blocks + singleton_blocks + density.".to_string(), input_schema: json!({"type":"object","required":["hits"],"properties":{"hits":{"type":"array"},"threshold":{"type":"integer"},"total":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovCoverageRunHotBlocksTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("hits").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing hits".into()))?; let mut r = rustre_fuzz_cov::CoverageRun::new("t"); for it in arr { if let Some(a) = it.as_array() { let addr = a.first().and_then(Value::as_u64).unwrap_or(0); let c = a.get(1).and_then(Value::as_u64).unwrap_or(1); r.hit_n(addr, c); } } let thr = args.get("threshold").and_then(Value::as_u64).unwrap_or(2); let total = args.get("total").and_then(Value::as_u64).unwrap_or(0); Ok(ToolResult::text(json!({"hot": r.hot_blocks(thr), "singletons": r.singleton_blocks().len(), "distinct": r.distinct_blocks(), "total_hits": r.total_hits(), "density": r.density(total), "source":"rustre_fuzz_cov::CoverageRun"}).to_string())) } }

pub struct FuzzCovDiffJaccardTool;
impl FuzzCovDiffJaccardTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_diff_jaccard".to_string(), description: "CoverageDiff::jaccard + is_identical from two address sets.".to_string(), input_schema: json!({"type":"object","required":["a","b"],"properties":{"a":{"type":"array"},"b":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovDiffJaccardTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ax = args.get("a").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("a".into()))?; let bx = args.get("b").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("b".into()))?; let mut ra = rustre_fuzz_cov::CoverageRun::new("a"); for v in ax { if let Some(n)=v.as_u64() { ra.hit(n);} } let mut rb = rustre_fuzz_cov::CoverageRun::new("b"); for v in bx { if let Some(n)=v.as_u64() { rb.hit(n);} } let d = rustre_fuzz_cov::CoverageDatabase::diff(&ra,&rb); Ok(ToolResult::text(json!({"jaccard": d.jaccard(), "identical": d.is_identical(), "only_a": d.only_in_a.len(), "only_b": d.only_in_b.len(), "both": d.in_both.len(), "source":"rustre_fuzz_cov::CoverageDiff"}).to_string())) } }

pub struct FuzzCovLcovLinePctTool;
impl FuzzCovLcovLinePctTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_lcov_line_pct".to_string(), description: "LcovParser overall + first record line_coverage_pct/functions_hit.".to_string(), input_schema: json!({"type":"object","required":["text"],"properties":{"text":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovLcovLinePctTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("text".into()))?; let mut p = rustre_fuzz_cov::LcovParser::new(); p.parse(text).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?; let first = p.records.first().map(|r| json!({"line_pct": r.line_coverage_pct(), "functions_hit": r.functions_hit(), "fully_covered": r.is_fully_covered()})); Ok(ToolResult::text(json!({"records": p.records.len(), "overall_pct": p.overall_line_coverage_pct(), "total_lines_hit": p.total_lines_hit(), "total_branch_hits": p.total_branch_hits(), "sources": p.source_files().len(), "first": first, "source":"rustre_fuzz_cov::LcovParser"}).to_string())) } }

pub struct FuzzCovPcguardNewBitsTool;
impl FuzzCovPcguardNewBitsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_pcguard_new_bits".to_string(), description: "PcGuardBitmap::new_bits_from + hit_guards + coverage_count.".to_string(), input_schema: json!({"type":"object","required":["base_hex","other_hex"],"properties":{"base_hex":{"type":"string"},"other_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovPcguardNewBitsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let h = |s:&str| crate::hex_decode(s); let a = h(args.get("base_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'base_hex'".into()))?)?; let b = h(args.get("other_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'other_hex'".into()))?)?; let bm_a = rustre_fuzz_cov::PcGuardBitmap::from_bytes(a); let bm_b = rustre_fuzz_cov::PcGuardBitmap::from_bytes(b); Ok(ToolResult::text(json!({"new_bits": bm_a.new_bits_from(&bm_b), "a_count": bm_a.coverage_count(), "b_count": bm_b.coverage_count(), "hit_guards_a": bm_a.hit_guards(), "source":"rustre_fuzz_cov::PcGuardBitmap"}).to_string())) } }

pub struct FuzzCovPcguardHitGuardsTool;
impl FuzzCovPcguardHitGuardsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_pcguard_hit_guards".to_string(), description: "PcGuardBitmap record_hit + hit_guards + reset roundtrip.".to_string(), input_schema: json!({"type":"object","required":["size","hits"],"properties":{"size":{"type":"integer"},"hits":{"type":"array","items":{"type":"integer"}}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovPcguardHitGuardsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as usize; let mut bm = rustre_fuzz_cov::PcGuardBitmap::new(size); if let Some(arr) = args.get("hits").and_then(Value::as_array) { for v in arr { if let Some(n) = v.as_u64() { bm.record_hit(n as usize); } } } let guards = bm.hit_guards(); let cnt = bm.coverage_count(); let dens = bm.density(); bm.reset(); Ok(ToolResult::text(json!({"guards": guards, "count": cnt, "density": dens, "after_reset": bm.coverage_count(), "source":"rustre_fuzz_cov::PcGuardBitmap"}).to_string())) } }

pub struct FuzzCovEdgeSuccessorsTool;
impl FuzzCovEdgeSuccessorsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_edge_successors".to_string(), description: "EdgeCoverageMap successors + has_edge + edge_hits.".to_string(), input_schema: json!({"type":"object","required":["edges","from"],"properties":{"edges":{"type":"array"},"from":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovEdgeSuccessorsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("edges").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("edges".into()))?; let mut m = rustre_fuzz_cov::EdgeCoverageMap::new(); for it in arr { if let Some(a) = it.as_array() { let f = a.first().and_then(Value::as_u64).unwrap_or(0); let t = a.get(1).and_then(Value::as_u64).unwrap_or(0); m.record(f, t); } } let from = args.get("from").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'from'".into()))?; let succ = m.successors(from); let hits: Vec<_> = succ.iter().map(|t| json!([*t, m.edge_hits(from, *t), m.has_edge(from, *t)])).collect(); Ok(ToolResult::text(json!({"successors": succ, "hits": hits, "source":"rustre_fuzz_cov::EdgeCoverageMap::successors"}).to_string())) } }

pub struct FuzzCovCmplogEntryDiffTool;
impl FuzzCovCmplogEntryDiffTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_cmplog_entry_diff".to_string(), description: "CmplogEntry diff/bit_diff/mask/is_equal.".to_string(), input_schema: json!({"type":"object","required":["lhs","rhs"],"properties":{"pc":{"type":"integer"},"lhs":{"type":"integer"},"rhs":{"type":"integer"},"size":{"type":"integer"},"is_fn_hook":{"type":"boolean"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovCmplogEntryDiffTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pc = args.get("pc").and_then(Value::as_u64).unwrap_or(0); let lhs = args.get("lhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lhs'".into()))?; let rhs = args.get("rhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rhs'".into()))?; let size = args.get("size").and_then(Value::as_u64).unwrap_or(8) as u8; let fh = args.get("is_fn_hook").and_then(Value::as_bool).unwrap_or(false); let e = rustre_fuzz_cov::CmplogEntry::new(pc, lhs, rhs, size, fh); Ok(ToolResult::text(json!({"is_equal": e.is_equal(), "diff": e.diff(), "bit_diff": e.bit_diff(), "mask": e.mask(), "source":"rustre_fuzz_cov::CmplogEntry"}).to_string())) } }

pub struct FuzzCovCmplogSuggestMutationsTool;
impl FuzzCovCmplogSuggestMutationsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_cmplog_suggest_mutations".to_string(), description: "CmplogMap suggest_mutations + unique_pcs + unequal_entries.".to_string(), input_schema: json!({"type":"object","required":["entries"],"properties":{"entries":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovCmplogSuggestMutationsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("entries").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("entries".into()))?; let mut m = rustre_fuzz_cov::CmplogMap::new(); for it in arr { if let Some(a) = it.as_array() { let pc = a.first().and_then(Value::as_u64).unwrap_or(0); let lhs = a.get(1).and_then(Value::as_u64).unwrap_or(0); let rhs = a.get(2).and_then(Value::as_u64).unwrap_or(0); let sz = a.get(3).and_then(Value::as_u64).unwrap_or(8) as u8; m.record(rustre_fuzz_cov::CmplogEntry::new(pc, lhs, rhs, sz, false)); } } let muts: Vec<_> = m.suggest_mutations().iter().map(|b| b.iter().map(|x| format!("{x:02x}")).collect::<String>()).collect(); Ok(ToolResult::text(json!({"len": m.len(), "is_empty": m.is_empty(), "unique_pcs": m.unique_pcs(), "unequal_count": m.unequal_entries().len(), "mutations": muts, "source":"rustre_fuzz_cov::CmplogMap"}).to_string())) } }

pub struct FuzzCovDbAggregateTool;
impl FuzzCovDbAggregateTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_db_aggregate".to_string(), description: "CoverageDatabase aggregate/intersection/union/unique_runs.".to_string(), input_schema: json!({"type":"object","required":["runs"],"properties":{"runs":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovDbAggregateTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("runs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("runs".into()))?; let mut db = rustre_fuzz_cov::CoverageDatabase::new(); for (i, run) in arr.iter().enumerate() { let mut r = rustre_fuzz_cov::CoverageRun::new(format!("r{i}")); if let Some(hits) = run.as_array() { for v in hits { if let Some(n) = v.as_u64() { r.hit(n); } } } db.add_run(r); } let agg = db.aggregate(); Ok(ToolResult::text(json!({"runs": db.runs.len(), "aggregate_blocks": agg.distinct_blocks(), "intersection": db.intersection().len(), "union": db.union_coverage().len(), "unique_runs": db.unique_runs().len(), "source":"rustre_fuzz_cov::CoverageDatabase"}).to_string())) } }

pub struct FuzzCovHistogramStatsTool;
impl FuzzCovHistogramStatsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_histogram_stats".to_string(), description: "CoverageHistogram median/mean/max_bucket/total_blocks.".to_string(), input_schema: json!({"type":"object","required":["hits"],"properties":{"hits":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovHistogramStatsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("hits").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing hits".into()))?; let mut r = rustre_fuzz_cov::CoverageRun::new("t"); for it in arr { if let Some(a) = it.as_array() { let addr = a.first().and_then(Value::as_u64).unwrap_or(0); let c = a.get(1).and_then(Value::as_u64).unwrap_or(1); r.hit_n(addr, c); } } let h = rustre_fuzz_cov::CoverageHistogram::from_run(&r); Ok(ToolResult::text(json!({"total_blocks": h.total_blocks(), "max_bucket": h.max_bucket(), "median": h.median(), "mean": h.mean(), "buckets": h.buckets.len(), "source":"rustre_fuzz_cov::CoverageHistogram"}).to_string())) } }

pub struct FuzzCovDrcovEntryEndAddrTool;
impl FuzzCovDrcovEntryEndAddrTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_drcov_entry_end_addr".to_string(), description: "DrcovEntry::absolute_addr + end_addr against a module base/end.".to_string(), input_schema: json!({"type":"object","required":["base","end","start","size"],"properties":{"base":{"type":"integer"},"end":{"type":"integer"},"start":{"type":"integer"},"size":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovDrcovEntryEndAddrTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?; let end = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'end'".into()))?; let start = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))? as u32; let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as u16; let modules = vec![rustre_fuzz_cov::DrcovModule::new(0, "m", base, end)]; let e = rustre_fuzz_cov::DrcovEntry::new(0, start, size); Ok(ToolResult::text(json!({"abs": e.absolute_addr(&modules), "end": e.end_addr(&modules), "source":"rustre_fuzz_cov::DrcovEntry"}).to_string())) } }

pub struct FuzzCovCoverageRunMergeTool;
impl FuzzCovCoverageRunMergeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_coverage_run_merge".to_string(), description: "CoverageRun::merge two runs and report totals.".to_string(), input_schema: json!({"type":"object","required":["a","b"],"properties":{"a":{"type":"array"},"b":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovCoverageRunMergeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ax = args.get("a").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("a".into()))?; let bx = args.get("b").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("b".into()))?; let mut ra = rustre_fuzz_cov::CoverageRun::new("a"); for v in ax { if let Some(n) = v.as_u64() { ra.hit(n); } } let mut rb = rustre_fuzz_cov::CoverageRun::new("b"); for v in bx { if let Some(n) = v.as_u64() { rb.hit(n); } } ra.merge(&rb); Ok(ToolResult::text(json!({"distinct": ra.distinct_blocks(), "total_hits": ra.total_hits(), "source":"rustre_fuzz_cov::CoverageRun::merge"}).to_string())) } }

pub struct FuzzCovLcovAggregateByFileTool;
impl FuzzCovLcovAggregateByFileTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_lcov_aggregate_by_file".to_string(), description: "LcovParser::aggregate_by_file + source_files listing.".to_string(), input_schema: json!({"type":"object","required":["text"],"properties":{"text":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovLcovAggregateByFileTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("text".into()))?; let mut p = rustre_fuzz_cov::LcovParser::new(); p.parse(text).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?; let agg = p.aggregate_by_file(); let files: Vec<_> = agg.iter().map(|(k,v)| json!({"file": k, "lines": v.len()})).collect(); Ok(ToolResult::text(json!({"files": files, "sources": p.source_files(), "source":"rustre_fuzz_cov::LcovParser::aggregate_by_file"}).to_string())) } }

pub struct FuzzCovPcguardHashMergeTool;
impl FuzzCovPcguardHashMergeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_pcguard_hash_merge".to_string(), description: "PcGuardBitmap::hash before/after merge with a second bitmap.".to_string(), input_schema: json!({"type":"object","required":["a_hex","b_hex"],"properties":{"a_hex":{"type":"string"},"b_hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovPcguardHashMergeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let h = |s:&str| crate::hex_decode(s); let a = h(args.get("a_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'a_hex'".into()))?)?; let b = h(args.get("b_hex").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'b_hex'".into()))?)?; let mut ba = rustre_fuzz_cov::PcGuardBitmap::from_bytes(a); let bb = rustre_fuzz_cov::PcGuardBitmap::from_bytes(b); let h_before = ba.hash(); ba.merge(&bb); Ok(ToolResult::text(json!({"hash_before": h_before, "hash_after": ba.hash(), "density_after": ba.density(), "count_after": ba.coverage_count(), "source":"rustre_fuzz_cov::PcGuardBitmap::merge"}).to_string())) } }

pub struct FuzzCovEdgeHotEdgesTool;
impl FuzzCovEdgeHotEdgesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_edge_hot_edges".to_string(), description: "EdgeCoverageMap hot_edges + total_traversals with counted edges.".to_string(), input_schema: json!({"type":"object","required":["edges"],"properties":{"edges":{"type":"array"},"threshold":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovEdgeHotEdgesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("edges").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("edges".into()))?; let mut m = rustre_fuzz_cov::EdgeCoverageMap::new(); for it in arr { if let Some(a) = it.as_array() { let f = a.first().and_then(Value::as_u64).unwrap_or(0); let t = a.get(1).and_then(Value::as_u64).unwrap_or(0); let c = a.get(2).and_then(Value::as_u64).unwrap_or(1); m.record_n(f, t, c); } } let thr = args.get("threshold").and_then(Value::as_u64).unwrap_or(1); let hot: Vec<_> = m.hot_edges(thr).into_iter().map(|(f,t,c)| json!([f,t,c])).collect(); Ok(ToolResult::text(json!({"edge_count": m.edge_count(), "total_traversals": m.total_traversals(), "hot_edges": hot, "source":"rustre_fuzz_cov::EdgeCoverageMap::hot_edges"}).to_string())) } }

pub struct FuzzCovDrcovBbAbsAddrTool;
impl FuzzCovDrcovBbAbsAddrTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_drcov_bb_abs_addr".to_string(), description: "DrcovBasicBlock::absolute_addr with a module base.".to_string(), input_schema: json!({"type":"object","required":["module_base","start","size","module_id"],"properties":{"module_base":{"type":"integer"},"start":{"type":"integer"},"size":{"type":"integer"},"module_id":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovDrcovBbAbsAddrTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let base = args.get("module_base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'module_base'".into()))?; let start = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))? as u32; let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as u16; let mid = args.get("module_id").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'module_id'".into()))? as u16; let bb = rustre_fuzz_cov::DrcovBasicBlock { start, size, module_id: mid }; Ok(ToolResult::text(json!({"abs": bb.absolute_addr(base), "source":"rustre_fuzz_cov::DrcovBasicBlock::absolute_addr"}).to_string())) } }

pub struct FuzzCovDrcovModuleV2SizeTool;
impl FuzzCovDrcovModuleV2SizeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_drcov_module_v2_size".to_string(), description: "DrcovModuleV2::size + contains for a synthetic module.".to_string(), input_schema: json!({"type":"object","required":["base","end","addr"],"properties":{"base":{"type":"integer"},"end":{"type":"integer"},"entry":{"type":"integer"},"addr":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovDrcovModuleV2SizeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?; let end = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'end'".into()))?; let entry = args.get("entry").and_then(Value::as_u64).unwrap_or(0); let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let m = rustre_fuzz_cov::DrcovModuleV2 { id: 0, base, end, entry, path: "m".to_string() }; Ok(ToolResult::text(json!({"size": m.size(), "contains": m.contains(addr), "source":"rustre_fuzz_cov::DrcovModuleV2"}).to_string())) } }

pub struct FuzzCovHeatmapColorTool;
impl FuzzCovHeatmapColorTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_heatmap_color".to_string(), description: "HeatmapColors::color_for_hits for Lighthouse-style palette.".to_string(), input_schema: json!({"type":"object","required":["hits","max_hits"],"properties":{"hits":{"type":"integer"},"max_hits":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovHeatmapColorTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let hits = args.get("hits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'hits'".into()))? as u32; let mx = args.get("max_hits").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'max_hits'".into()))? as u32; let c = rustre_fuzz_cov::HeatmapColors::color_for_hits(hits, mx); Ok(ToolResult::text(json!({"rgb": c, "source":"rustre_fuzz_cov::HeatmapColors::color_for_hits"}).to_string())) } }

pub struct FuzzCovDrcovHeaderParseV2Tool;
impl FuzzCovDrcovHeaderParseV2Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_drcov_header_parse_v2".to_string(), description: "DrcovHeader::parse from raw text; returns version/flavor/module_count.".to_string(), input_schema: json!({"type":"object","required":["text"],"properties":{"text":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovDrcovHeaderParseV2Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("text".into()))?; let (h, consumed) = rustre_fuzz_cov::DrcovHeader::parse(text.as_bytes()).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?; Ok(ToolResult::text(json!({"version": h.version, "flavor": h.flavor, "module_count": h.module_count, "consumed": consumed, "source":"rustre_fuzz_cov::DrcovHeader::parse"}).to_string())) } }

pub struct FuzzCovCorpusPrunerTool;
impl FuzzCovCorpusPrunerTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_corpus_pruner".to_string(), description: "CorpusPruner::prune minimal set cover over input->edges.".to_string(), input_schema: json!({"type":"object","required":["inputs"],"properties":{"inputs":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovCorpusPrunerTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("inputs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("inputs".into()))?; let mut inputs: Vec<(usize, Vec<u64>)> = Vec::new(); for it in arr { if let Some(a) = it.as_array() { let id = a.first().and_then(Value::as_u64).unwrap_or(0) as usize; let edges: Vec<u64> = a.get(1).and_then(Value::as_array).map(|v| v.iter().filter_map(Value::as_u64).collect()).unwrap_or_default(); inputs.push((id, edges)); } } let pruner = rustre_fuzz_cov::CorpusPruner::new(); let selected = pruner.prune(inputs); let count = selected.len(); Ok(ToolResult::text(json!({"selected": selected, "count": count, "source":"rustre_fuzz_cov::CorpusPruner::prune"}).to_string())) } }

pub struct FuzzCovStatsFullTool;
impl FuzzCovStatsFullTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_stats_full".to_string(), description: "CoverageDatabase::stats full field dump for a synthetic run.".to_string(), input_schema: json!({"type":"object","required":["hits"],"properties":{"hits":{"type":"array"},"total_known":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovStatsFullTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("hits").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("hits".into()))?; let mut r = rustre_fuzz_cov::CoverageRun::new("t"); for it in arr { if let Some(a) = it.as_array() { let addr = a.first().and_then(Value::as_u64).unwrap_or(0); let c = a.get(1).and_then(Value::as_u64).unwrap_or(1); r.hit_n(addr, c); } else if let Some(n) = it.as_u64() { r.hit(n); } } let total = args.get("total_known").and_then(Value::as_u64).unwrap_or(0); let s = rustre_fuzz_cov::CoverageDatabase::stats(&r, total); Ok(ToolResult::text(json!({"total_blocks": s.total_blocks, "hit_blocks": s.hit_blocks, "coverage_pct": s.coverage_pct, "unique_blocks": s.unique_blocks, "max_hit_count": s.max_hit_count, "total_hits": s.total_hits, "source":"rustre_fuzz_cov::CoverageDatabase::stats"}).to_string())) } }

pub struct FuzzCovDrcovModuleToOffsetXTool;
impl FuzzCovDrcovModuleToOffsetXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_drcov_module_to_offset_x".to_string(), description: "DrcovModule::to_offset returning module-relative offset.".to_string(), input_schema: json!({"type":"object","required":["base","end","addr"],"properties":{"base":{"type":"integer"},"end":{"type":"integer"},"addr":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovDrcovModuleToOffsetXTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?; let end = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'end'".into()))?; let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let m = rustre_fuzz_cov::DrcovModule::new(0, "m", base, end); Ok(ToolResult::text(json!({"offset": m.to_offset(addr), "size": m.size(), "source":"rustre_fuzz_cov::DrcovModule::to_offset"}).to_string())) } }

pub struct FuzzCovCoverageRunWasHitXTool;
impl FuzzCovCoverageRunWasHitXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_coverage_run_was_hit_x".to_string(), description: "CoverageRun::was_hit + distinct_blocks after recording addresses.".to_string(), input_schema: json!({"type":"object","required":["addrs","query"],"properties":{"addrs":{"type":"array"},"query":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovCoverageRunWasHitXTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("addrs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing addrs".into()))?; let query = args.get("query").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'query'".into()))?; let mut r = rustre_fuzz_cov::CoverageRun::new("q"); for it in arr { if let Some(a) = it.as_u64() { r.hit(a); } } Ok(ToolResult::text(json!({"was_hit": r.was_hit(query), "distinct": r.distinct_blocks(), "source":"rustre_fuzz_cov::CoverageRun::was_hit"}).to_string())) } }

pub struct FuzzCovDbIntersectionUnionXTool;
impl FuzzCovDbIntersectionUnionXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_db_intersection_union_x".to_string(), description: "CoverageDatabase::intersection + union_coverage + unique_runs.".to_string(), input_schema: json!({"type":"object","required":["runs"],"properties":{"runs":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovDbIntersectionUnionXTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("runs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing runs".into()))?; let mut db = rustre_fuzz_cov::CoverageDatabase::new(); for (i, r) in arr.iter().enumerate() { let mut run = rustre_fuzz_cov::CoverageRun::new(format!("r{i}")); if let Some(list) = r.as_array() { for a in list { if let Some(v) = a.as_u64() { run.hit(v); } } } db.add_run(run); } let inter = db.intersection(); let uni = db.union_coverage(); let unique = db.unique_runs().len(); Ok(ToolResult::text(json!({"intersection": inter, "union": uni, "unique_runs": unique, "source":"rustre_fuzz_cov::CoverageDatabase"}).to_string())) } }

pub struct FuzzCovDbAggregateNewXTool;
impl FuzzCovDbAggregateNewXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_db_aggregate_new_x".to_string(), description: "CoverageDatabase::aggregate collapsing multiple runs.".to_string(), input_schema: json!({"type":"object","required":["runs"],"properties":{"runs":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovDbAggregateNewXTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("runs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing runs".into()))?; let mut db = rustre_fuzz_cov::CoverageDatabase::new(); for (i, r) in arr.iter().enumerate() { let mut run = rustre_fuzz_cov::CoverageRun::new(format!("r{i}")); if let Some(list) = r.as_array() { for a in list { if let Some(v) = a.as_u64() { run.hit(v); } } } db.add_run(run); } let agg = db.aggregate(); Ok(ToolResult::text(json!({"distinct": agg.distinct_blocks(), "total_hits": agg.total_hits(), "source":"rustre_fuzz_cov::CoverageDatabase::aggregate"}).to_string())) } }

pub struct FuzzCovCmplogMaskBitDiffXTool;
impl FuzzCovCmplogMaskBitDiffXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_cmplog_mask_bit_diff_x".to_string(), description: "CmplogEntry::mask + diff + bit_diff + is_equal.".to_string(), input_schema: json!({"type":"object","required":["pc","lhs","rhs","size"],"properties":{"pc":{"type":"integer"},"lhs":{"type":"integer"},"rhs":{"type":"integer"},"size":{"type":"integer"},"fn_hook":{"type":"boolean"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovCmplogMaskBitDiffXTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let pc = args.get("pc").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'pc'".into()))?; let lhs = args.get("lhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'lhs'".into()))?; let rhs = args.get("rhs").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'rhs'".into()))?; let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as u8; let fnh = args.get("fn_hook").and_then(Value::as_bool).unwrap_or(false); let e = rustre_fuzz_cov::CmplogEntry::new(pc, lhs, rhs, size, fnh); Ok(ToolResult::text(json!({"mask": e.mask(), "diff": e.diff(), "bit_diff": e.bit_diff(), "is_equal": e.is_equal(), "source":"rustre_fuzz_cov::CmplogEntry"}).to_string())) } }

pub struct FuzzCovCmplogUniquePcsXTool;
impl FuzzCovCmplogUniquePcsXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_cmplog_unique_pcs_x".to_string(), description: "CmplogMap::unique_pcs + unequal_entries + len.".to_string(), input_schema: json!({"type":"object","required":["entries"],"properties":{"entries":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovCmplogUniquePcsXTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("entries").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing entries".into()))?; let mut m = rustre_fuzz_cov::CmplogMap::new(); for it in arr { if let Some(a) = it.as_array() { let pc = a.first().and_then(Value::as_u64).unwrap_or(0); let lhs = a.get(1).and_then(Value::as_u64).unwrap_or(0); let rhs = a.get(2).and_then(Value::as_u64).unwrap_or(0); let sz = a.get(3).and_then(Value::as_u64).unwrap_or(4) as u8; m.record(rustre_fuzz_cov::CmplogEntry::new(pc, lhs, rhs, sz, false)); } } Ok(ToolResult::text(json!({"unique_pcs": m.unique_pcs(), "unequal": m.unequal_entries().len(), "len": m.len(), "is_empty": m.is_empty(), "source":"rustre_fuzz_cov::CmplogMap"}).to_string())) } }

pub struct FuzzCovPcguardResetHitGuardsXTool;
impl FuzzCovPcguardResetHitGuardsXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_pcguard_reset_hit_guards_x".to_string(), description: "PcGuardBitmap::record_hit + hit_guards + reset roundtrip.".to_string(), input_schema: json!({"type":"object","required":["size","hits"],"properties":{"size":{"type":"integer"},"hits":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovPcguardResetHitGuardsXTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as usize; let hits = args.get("hits").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing hits".into()))?; let mut bm = rustre_fuzz_cov::PcGuardBitmap::new(size); for h in hits { if let Some(i) = h.as_u64() { bm.record_hit(i as usize); } } let before = bm.hit_guards(); let cov = bm.coverage_count(); bm.reset(); Ok(ToolResult::text(json!({"hit_guards_before": before, "coverage_before": cov, "coverage_after_reset": bm.coverage_count(), "source":"rustre_fuzz_cov::PcGuardBitmap"}).to_string())) } }

pub struct FuzzCovEdgeMapHasEdgeXTool;
impl FuzzCovEdgeMapHasEdgeXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_edge_map_has_edge_x".to_string(), description: "EdgeCoverageMap::has_edge + edge_hits + successors after recording.".to_string(), input_schema: json!({"type":"object","required":["edges","from","to"],"properties":{"edges":{"type":"array"},"from":{"type":"integer"},"to":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovEdgeMapHasEdgeXTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let arr = args.get("edges").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing edges".into()))?; let mut m = rustre_fuzz_cov::EdgeCoverageMap::new(); for it in arr { if let Some(a) = it.as_array() { let f = a.first().and_then(Value::as_u64).unwrap_or(0); let t = a.get(1).and_then(Value::as_u64).unwrap_or(0); m.record(f, t); } } let f = args.get("from").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'from'".into()))?; let t = args.get("to").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'to'".into()))?; Ok(ToolResult::text(json!({"has_edge": m.has_edge(f, t), "edge_hits": m.edge_hits(f, t), "successors": m.successors(f), "edge_count": m.edge_count(), "total": m.total_traversals(), "source":"rustre_fuzz_cov::EdgeCoverageMap"}).to_string())) } }

pub struct FuzzCovLcovFullyCoveredXTool;
impl FuzzCovLcovFullyCoveredXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_lcov_fully_covered_x".to_string(), description: "LcovRecord::is_fully_covered + functions_hit + line_coverage_pct.".to_string(), input_schema: json!({"type":"object","required":["text"],"properties":{"text":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovLcovFullyCoveredXTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let text = args.get("text").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing text".into()))?; let mut p = rustre_fuzz_cov::LcovParser::new(); p.parse(text).map_err(|e| McpError::InvalidParams(format!("parse: {e}")))?; let results: Vec<_> = p.records.iter().map(|r| json!({"fully_covered": r.is_fully_covered(), "functions_hit": r.functions_hit(), "line_pct": r.line_coverage_pct()})).collect(); Ok(ToolResult::text(json!({"records": results, "count": p.records.len(), "source":"rustre_fuzz_cov::LcovRecord"}).to_string())) } }

pub struct FuzzCovDrcovBasicBlockAbsAddrXTool;
impl FuzzCovDrcovBasicBlockAbsAddrXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_drcov_basic_block_abs_addr_x".to_string(), description: "DrcovBasicBlock::absolute_addr given a module base.".to_string(), input_schema: json!({"type":"object","required":["start","size","module_id","base"],"properties":{"start":{"type":"integer"},"size":{"type":"integer"},"module_id":{"type":"integer"},"base":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovDrcovBasicBlockAbsAddrXTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let start = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))? as u32; let size = args.get("size").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'size'".into()))? as u16; let module_id = args.get("module_id").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'module_id'".into()))? as u16; let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?; let bb = rustre_fuzz_cov::DrcovBasicBlock { start, size, module_id }; Ok(ToolResult::text(json!({"abs_addr": bb.absolute_addr(base), "start": bb.start, "size": bb.size, "module_id": bb.module_id, "source":"rustre_fuzz_cov::DrcovBasicBlock::absolute_addr"}).to_string())) } }

pub struct FuzzCovDrcovModuleV2ContainsXTool;
impl FuzzCovDrcovModuleV2ContainsXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_drcov_module_v2_contains_x".to_string(), description: "DrcovModuleV2::contains + size using struct literal.".to_string(), input_schema: json!({"type":"object","required":["base","end","addr"],"properties":{"base":{"type":"integer"},"end":{"type":"integer"},"entry":{"type":"integer"},"addr":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovDrcovModuleV2ContainsXTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let base = args.get("base").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'base'".into()))?; let end = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'end'".into()))?; let entry = args.get("entry").and_then(Value::as_u64).unwrap_or(0); let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'addr'".into()))?; let m = rustre_fuzz_cov::DrcovModuleV2 { id: 0, base, end, entry, path: String::new() }; Ok(ToolResult::text(json!({"contains": m.contains(addr), "size": m.size(), "source":"rustre_fuzz_cov::DrcovModuleV2"}).to_string())) } }

pub struct FuzzCovHistogramNewEmptyXTool;
impl FuzzCovHistogramNewEmptyXTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "fuzz_cov_histogram_new_empty_x".to_string(), description: "CoverageHistogram::new + total_blocks + max_bucket on empty histogram.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for FuzzCovHistogramNewEmptyXTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let h = rustre_fuzz_cov::CoverageHistogram::new(); Ok(ToolResult::text(json!({"total_blocks": h.total_blocks(), "max_bucket": h.max_bucket(), "median": h.median(), "mean": h.mean(), "source":"rustre_fuzz_cov::CoverageHistogram::new"}).to_string())) } }

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (FuzzCovRleEncodeTool::definition(), Box::new(FuzzCovRleEncodeTool)),
        (FuzzCovCoverageFractionTool::definition(), Box::new(FuzzCovCoverageFractionTool)),
        (FuzzCovRleIsBeneficialTool::definition(), Box::new(FuzzCovRleIsBeneficialTool)),
        (FuzzCovDrcovParseTool::definition(), Box::new(FuzzCovDrcovParseTool)),
        (FuzzCovDrcovHeaderParseTool::definition(), Box::new(FuzzCovDrcovHeaderParseTool)),
        (FuzzCovPcGuardDensityTool::definition(), Box::new(FuzzCovPcGuardDensityTool)),
        (FuzzCovPcGuardHashTool::definition(), Box::new(FuzzCovPcGuardHashTool)),
        (FuzzCovLcovParseTool::definition(), Box::new(FuzzCovLcovParseTool)),
        (FuzzCovCorpusPruneTool::definition(), Box::new(FuzzCovCorpusPruneTool)),
        (FuzzCovCoverageDiffTool::definition(), Box::new(FuzzCovCoverageDiffTool)),
        (FuzzCovCoverageStatsTool::definition(), Box::new(FuzzCovCoverageStatsTool)),
        (FuzzCovHistogramTool::definition(), Box::new(FuzzCovHistogramTool)),
        (FuzzCovEdgeMapAnalyzeTool::definition(), Box::new(FuzzCovEdgeMapAnalyzeTool)),
        (FuzzCovDrcovModuleContainsTool::definition(), Box::new(FuzzCovDrcovModuleContainsTool)),
        (FuzzCovDrcovBlocksPerModuleTool::definition(), Box::new(FuzzCovDrcovBlocksPerModuleTool)),
        (FuzzCovCoverageRunHotBlocksTool::definition(), Box::new(FuzzCovCoverageRunHotBlocksTool)),
        (FuzzCovDiffJaccardTool::definition(), Box::new(FuzzCovDiffJaccardTool)),
        (FuzzCovLcovLinePctTool::definition(), Box::new(FuzzCovLcovLinePctTool)),
        (FuzzCovPcguardNewBitsTool::definition(), Box::new(FuzzCovPcguardNewBitsTool)),
        (FuzzCovPcguardHitGuardsTool::definition(), Box::new(FuzzCovPcguardHitGuardsTool)),
        (FuzzCovEdgeSuccessorsTool::definition(), Box::new(FuzzCovEdgeSuccessorsTool)),
        (FuzzCovCmplogEntryDiffTool::definition(), Box::new(FuzzCovCmplogEntryDiffTool)),
        (FuzzCovCmplogSuggestMutationsTool::definition(), Box::new(FuzzCovCmplogSuggestMutationsTool)),
        (FuzzCovDbAggregateTool::definition(), Box::new(FuzzCovDbAggregateTool)),
        (FuzzCovHistogramStatsTool::definition(), Box::new(FuzzCovHistogramStatsTool)),
        (FuzzCovDrcovEntryEndAddrTool::definition(), Box::new(FuzzCovDrcovEntryEndAddrTool)),
        (FuzzCovCoverageRunMergeTool::definition(), Box::new(FuzzCovCoverageRunMergeTool)),
        (FuzzCovLcovAggregateByFileTool::definition(), Box::new(FuzzCovLcovAggregateByFileTool)),
        (FuzzCovPcguardHashMergeTool::definition(), Box::new(FuzzCovPcguardHashMergeTool)),
        (FuzzCovEdgeHotEdgesTool::definition(), Box::new(FuzzCovEdgeHotEdgesTool)),
        (FuzzCovDrcovBbAbsAddrTool::definition(), Box::new(FuzzCovDrcovBbAbsAddrTool)),
        (FuzzCovDrcovModuleV2SizeTool::definition(), Box::new(FuzzCovDrcovModuleV2SizeTool)),
        (FuzzCovHeatmapColorTool::definition(), Box::new(FuzzCovHeatmapColorTool)),
        (FuzzCovDrcovHeaderParseV2Tool::definition(), Box::new(FuzzCovDrcovHeaderParseV2Tool)),
        (FuzzCovCorpusPrunerTool::definition(), Box::new(FuzzCovCorpusPrunerTool)),
        (FuzzCovStatsFullTool::definition(), Box::new(FuzzCovStatsFullTool)),
        (FuzzCovDrcovModuleToOffsetXTool::definition(), Box::new(FuzzCovDrcovModuleToOffsetXTool)),
        (FuzzCovCoverageRunWasHitXTool::definition(), Box::new(FuzzCovCoverageRunWasHitXTool)),
        (FuzzCovDbIntersectionUnionXTool::definition(), Box::new(FuzzCovDbIntersectionUnionXTool)),
        (FuzzCovDbAggregateNewXTool::definition(), Box::new(FuzzCovDbAggregateNewXTool)),
        (FuzzCovCmplogMaskBitDiffXTool::definition(), Box::new(FuzzCovCmplogMaskBitDiffXTool)),
        (FuzzCovCmplogUniquePcsXTool::definition(), Box::new(FuzzCovCmplogUniquePcsXTool)),
        (FuzzCovPcguardResetHitGuardsXTool::definition(), Box::new(FuzzCovPcguardResetHitGuardsXTool)),
        (FuzzCovEdgeMapHasEdgeXTool::definition(), Box::new(FuzzCovEdgeMapHasEdgeXTool)),
        (FuzzCovLcovFullyCoveredXTool::definition(), Box::new(FuzzCovLcovFullyCoveredXTool)),
        (FuzzCovDrcovBasicBlockAbsAddrXTool::definition(), Box::new(FuzzCovDrcovBasicBlockAbsAddrXTool)),
        (FuzzCovDrcovModuleV2ContainsXTool::definition(), Box::new(FuzzCovDrcovModuleV2ContainsXTool)),
        (FuzzCovHistogramNewEmptyXTool::definition(), Box::new(FuzzCovHistogramNewEmptyXTool)),
    ]
}
