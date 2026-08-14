//! MCP wrappers for the rustre-analysis_cfg crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};

pub struct AnalysisCfgFlowEdgeKindIsIntraproceduralTool;

pub struct AnalysisCfgFlowEdgeKindIsConditionalTool;

// ── analysis_cfg_extra wrappers (appended 2026-07-12) ─────────────────────────
// These build on top of rustre_analysis_cfg and the an_cfg helper
// (ancfg_build_cfg_from_args / ancfg_edges_schema live in wire_tools.rs).

use async_trait::async_trait;
use crate::wire_tools::{ancfg_build_cfg_from_args, ancfg_edges_schema};

pub struct AnalysisCfgAnalyzeTool;
impl AnalysisCfgAnalyzeTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_cfg_analyze".to_string(), description: "Build a full ControlFlowGraph (blocks + edges + dom trees + loops) from edge list.".to_string(), input_schema: ancfg_edges_schema(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for AnalysisCfgAnalyzeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        Ok(ToolResult::text(json!({"block_count": cfg.block_count(), "edge_count": cfg.edge_count(), "source":"rustre_analysis_cfg::analyze_cfg"}).to_string()))
    }
}

pub struct AnalysisCfgDomTreeComputeTool;
impl AnalysisCfgDomTreeComputeTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_cfg_dom_tree_compute".to_string(), description: "Compute the dominator tree for a CFG and return the idom map.".to_string(), input_schema: ancfg_edges_schema(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for AnalysisCfgDomTreeComputeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let idoms: Vec<Value> = cfg.dom_tree.idom.iter().map(|(k,v)| json!({"node":k.0,"idom":v.map(|a|a.0)})).collect();
        Ok(ToolResult::text(json!({"count": idoms.len(), "idoms": idoms, "source":"rustre_analysis_cfg::DominatorTree::compute"}).to_string()))
    }
}

pub struct AnalysisCfgDominatesTool;
impl AnalysisCfgDominatesTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let mut s = ancfg_edges_schema();
        s["properties"]["a"] = json!({"type":"integer"}); s["properties"]["b"] = json!({"type":"integer"});
        s["required"] = json!(["entry","edges","a","b"]);
        ToolDefinition { name: "analysis_cfg_dominates_v2".to_string(), description: "Return whether address a dominates address b.".to_string(), input_schema: s.clone(), parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisCfgDominatesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let r = cfg.dominates(rustre_core::address::Address::new(a), rustre_core::address::Address::new(b));
        Ok(ToolResult::text(json!({"dominates": r, "source":"rustre_analysis_cfg::DominatorTree::dominates"}).to_string()))
    }
}

pub struct AnalysisCfgStrictlyDominatesTool;
impl AnalysisCfgStrictlyDominatesTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let mut s = ancfg_edges_schema();
        s["properties"]["a"] = json!({"type":"integer"}); s["properties"]["b"] = json!({"type":"integer"});
        s["required"] = json!(["entry","edges","a","b"]);
        ToolDefinition { name: "analysis_cfg_strictly_dominates_v2".to_string(), description: "Return whether a strictly dominates b.".to_string(), input_schema: s.clone(), parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisCfgStrictlyDominatesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let r = cfg.dom_tree.strictly_dominates(rustre_core::address::Address::new(a), rustre_core::address::Address::new(b));
        Ok(ToolResult::text(json!({"strictly_dominates": r, "source":"rustre_analysis_cfg::DominatorTree::strictly_dominates"}).to_string()))
    }
}

pub struct AnalysisCfgDominatedByTool;
impl AnalysisCfgDominatedByTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let mut s = ancfg_edges_schema();
        s["properties"]["node"] = json!({"type":"integer"});
        s["required"] = json!(["entry","edges","node"]);
        ToolDefinition { name: "analysis_cfg_dominated_by_v2".to_string(), description: "Return nodes strictly dominated by `node`.".to_string(), input_schema: s.clone(), parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisCfgDominatedByTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let node = args.get("node").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'node'".into()))?;
        let items: Vec<u64> = cfg.dom_tree.dominated_by(rustre_core::address::Address::new(node)).into_iter().map(|a| a.0).collect();
        Ok(ToolResult::text(json!({"count": items.len(), "dominated": items, "source":"rustre_analysis_cfg::DominatorTree::dominated_by"}).to_string()))
    }
}

pub struct AnalysisCfgDomFrontierTool;
impl AnalysisCfgDomFrontierTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let mut s = ancfg_edges_schema();
        s["properties"]["node"] = json!({"type":"integer"});
        s["required"] = json!(["entry","edges","node"]);
        ToolDefinition { name: "analysis_cfg_dom_frontier_v2".to_string(), description: "Return the dominance frontier of a node.".to_string(), input_schema: s.clone(), parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisCfgDomFrontierTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let node = args.get("node").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'node'".into()))?;
        let df = cfg.dominance_frontier(rustre_core::address::Address::new(node));
        let items: Vec<u64> = df.iter().map(|a| a.0).collect();
        Ok(ToolResult::text(json!({"count": items.len(), "frontier": items, "source":"rustre_analysis_cfg::ControlFlowGraph::dominance_frontier"}).to_string()))
    }
}

pub struct AnalysisCfgDomDepthTool;
impl AnalysisCfgDomDepthTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let mut s = ancfg_edges_schema();
        s["properties"]["node"] = json!({"type":"integer"});
        s["required"] = json!(["entry","edges","node"]);
        ToolDefinition { name: "analysis_cfg_dom_depth_v2".to_string(), description: "Return the dominator-tree depth of a node.".to_string(), input_schema: s.clone(), parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisCfgDomDepthTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let node = args.get("node").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'node'".into()))?;
        let d = cfg.dom_tree.depth(rustre_core::address::Address::new(node));
        Ok(ToolResult::text(json!({"depth": d, "source":"rustre_analysis_cfg::DominatorTree::depth"}).to_string()))
    }
}

pub struct AnalysisCfgPostDominatesTool;
impl AnalysisCfgPostDominatesTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let mut s = ancfg_edges_schema();
        s["properties"]["a"] = json!({"type":"integer"}); s["properties"]["b"] = json!({"type":"integer"});
        s["required"] = json!(["entry","edges","a","b"]);
        ToolDefinition { name: "analysis_cfg_post_dominates_v2".to_string(), description: "Return whether a post-dominates b.".to_string(), input_schema: s.clone(), parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisCfgPostDominatesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let r = cfg.post_dominates(rustre_core::address::Address::new(a), rustre_core::address::Address::new(b));
        Ok(ToolResult::text(json!({"post_dominates": r, "source":"rustre_analysis_cfg::PostDominatorTree::post_dominates"}).to_string()))
    }
}

pub struct AnalysisCfgStatsTool;
impl AnalysisCfgStatsTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_cfg_stats_v2".to_string(), description: "Compute CfgStats for a CFG built from the given edges.".to_string(), input_schema: ancfg_edges_schema(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for AnalysisCfgStatsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let s = rustre_analysis_cfg::CfgStats::compute(&cfg);
        Ok(ToolResult::text(json!({"block_count":s.block_count,"edge_count":s.edge_count,"loop_count":s.loop_count,"max_loop_depth":s.max_loop_depth,"cyclomatic_complexity":s.cyclomatic_complexity,"entry_blocks":s.entry_blocks,"exit_blocks":s.exit_blocks,"source":"rustre_analysis_cfg::CfgStats::compute"}).to_string()))
    }
}

pub struct AnalysisCfgIsComplexTool;
impl AnalysisCfgIsComplexTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_cfg_is_complex_v2".to_string(), description: "Return whether CfgStats reports the CFG as complex.".to_string(), input_schema: ancfg_edges_schema(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for AnalysisCfgIsComplexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let s = rustre_analysis_cfg::CfgStats::compute(&cfg);
        Ok(ToolResult::text(json!({"is_complex": s.is_complex(), "cc": s.cyclomatic_complexity, "source":"rustre_analysis_cfg::CfgStats::is_complex"}).to_string()))
    }
}

pub struct AnalysisCfgToDotTool;
impl AnalysisCfgToDotTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_cfg_to_dot_v2".to_string(), description: "Render a CFG as Graphviz DOT.".to_string(), input_schema: ancfg_edges_schema(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for AnalysisCfgToDotTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let dot = rustre_analysis_cfg::cfg_to_dot(&cfg);
        Ok(ToolResult::text(json!({"dot": dot, "len": dot.len(), "source":"rustre_analysis_cfg::cfg_to_dot"}).to_string()))
    }
}

pub struct AnalysisCfgCyclomaticTool;
impl AnalysisCfgCyclomaticTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_cfg_cyclomatic_v2".to_string(), description: "Compute McCabe cyclomatic complexity.".to_string(), input_schema: ancfg_edges_schema(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for AnalysisCfgCyclomaticTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let cc = rustre_analysis_cfg::cyclomatic_complexity(&cfg);
        Ok(ToolResult::text(json!({"cyclomatic_complexity": cc, "source":"rustre_analysis_cfg::cyclomatic_complexity"}).to_string()))
    }
}

pub struct AnalysisCfgNaturalLoopsTool;
impl AnalysisCfgNaturalLoopsTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_cfg_natural_loops_v2".to_string(), description: "Find all natural loops in a CFG.".to_string(), input_schema: ancfg_edges_schema(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for AnalysisCfgNaturalLoopsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let loops = rustre_analysis_cfg::find_natural_loops(&cfg);
        let items: Vec<Value> = loops.iter().map(|l| json!({"header":l.header.0,"back_edge_src":l.back_edge_src.0,"size":l.size(),"is_innermost":l.is_innermost})).collect();
        Ok(ToolResult::text(json!({"count": items.len(), "loops": items, "source":"rustre_analysis_cfg::find_natural_loops"}).to_string()))
    }
}

pub struct AnalysisCfgRpoTool;
impl AnalysisCfgRpoTool {
    #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "analysis_cfg_rpo_v2".to_string(), description: "Return nodes in reverse-post-order from CFG entry.".to_string(), input_schema: ancfg_edges_schema(), parameters: Value::Null } }
}
#[async_trait] impl ToolHandler for AnalysisCfgRpoTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let rpo: Vec<u64> = cfg.reverse_post_order().iter().map(|a| a.0).collect();
        Ok(ToolResult::text(json!({"count": rpo.len(), "rpo": rpo, "source":"rustre_analysis_cfg::ControlFlowGraph::reverse_post_order"}).to_string()))
    }
}

pub struct AnalysisCfgReachableFromTool;
impl AnalysisCfgReachableFromTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let mut s = ancfg_edges_schema();
        s["properties"]["start"] = json!({"type":"integer"});
        s["required"] = json!(["entry","edges","start"]);
        ToolDefinition { name: "analysis_cfg_reachable_from_v2".to_string(), description: "BFS-reachable node set from a given start address.".to_string(), input_schema: s.clone(), parameters: Value::Null }
    }
}
#[async_trait] impl ToolHandler for AnalysisCfgReachableFromTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let start = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))?;
        let r = cfg.reachable_from(rustre_core::address::Address::new(start));
        let mut v: Vec<u64> = r.iter().map(|a| a.0).collect();
        v.sort_unstable();
        Ok(ToolResult::text(json!({"count": v.len(), "reachable": v, "source":"rustre_analysis_cfg::ControlFlowGraph::reachable_from"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (AnalysisCfgFlowEdgeKindIsIntraproceduralTool::definition(), Box::new(AnalysisCfgFlowEdgeKindIsIntraproceduralTool)),
        (AnalysisCfgFlowEdgeKindIsConditionalTool::definition(), Box::new(AnalysisCfgFlowEdgeKindIsConditionalTool)),
        (AnalysisCfgAnalyzeTool::definition(), Box::new(AnalysisCfgAnalyzeTool)),
        (AnalysisCfgDomTreeComputeTool::definition(), Box::new(AnalysisCfgDomTreeComputeTool)),
        (AnalysisCfgDominatesTool::definition(), Box::new(AnalysisCfgDominatesTool)),
        (AnalysisCfgStrictlyDominatesTool::definition(), Box::new(AnalysisCfgStrictlyDominatesTool)),
        (AnalysisCfgDominatedByTool::definition(), Box::new(AnalysisCfgDominatedByTool)),
        (AnalysisCfgDomFrontierTool::definition(), Box::new(AnalysisCfgDomFrontierTool)),
        (AnalysisCfgDomDepthTool::definition(), Box::new(AnalysisCfgDomDepthTool)),
        (AnalysisCfgPostDominatesTool::definition(), Box::new(AnalysisCfgPostDominatesTool)),
        (AnalysisCfgStatsTool::definition(), Box::new(AnalysisCfgStatsTool)),
        (AnalysisCfgIsComplexTool::definition(), Box::new(AnalysisCfgIsComplexTool)),
        (AnalysisCfgToDotTool::definition(), Box::new(AnalysisCfgToDotTool)),
        (AnalysisCfgCyclomaticTool::definition(), Box::new(AnalysisCfgCyclomaticTool)),
        (AnalysisCfgNaturalLoopsTool::definition(), Box::new(AnalysisCfgNaturalLoopsTool)),
        (AnalysisCfgRpoTool::definition(), Box::new(AnalysisCfgRpoTool)),
        (AnalysisCfgReachableFromTool::definition(), Box::new(AnalysisCfgReachableFromTool)),
    ]
}
