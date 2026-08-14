//! MCP wrappers for the rustre-an_cfg crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{ancfg_build_cfg_from_args, ancfg_edges_schema};

pub struct AnCfgBuildStatsTool;
impl AnCfgBuildStatsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_cfg_build_stats".to_string(),
            description: "Build a CFG from edges and return CfgStats.".to_string(),
            input_schema: ancfg_edges_schema(), parameters: ancfg_edges_schema() }
    }
}
#[async_trait]
impl ToolHandler for AnCfgBuildStatsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let s = rustre_analysis_cfg::CfgStats::compute(&cfg);
        Ok(ToolResult::text(json!({
            "block_count": s.block_count, "edge_count": s.edge_count,
            "loop_count": s.loop_count, "max_loop_depth": s.max_loop_depth,
            "cyclomatic_complexity": s.cyclomatic_complexity,
            "entry_blocks": s.entry_blocks, "exit_blocks": s.exit_blocks,
            "is_complex": s.is_complex(),
            "source": "rustre_analysis_cfg::CfgStats::compute"
        }).to_string()))
    }
}

pub struct AnCfgDominatorTreeTool;
impl AnCfgDominatorTreeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_cfg_dominator_tree".to_string(),
            description: "Compute the immediate-dominator map for a CFG.".to_string(),
            input_schema: ancfg_edges_schema(), parameters: ancfg_edges_schema() }
    }
}
#[async_trait]
impl ToolHandler for AnCfgDominatorTreeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let idoms: Vec<_> = cfg.dom_tree.idom.iter().map(|(k,v)| json!({
            "node": k.0, "idom": v.map(|a| a.0)
        })).collect();
        Ok(ToolResult::text(json!({ "count": idoms.len(), "idoms": idoms,
            "source": "rustre_analysis_cfg::DominatorTree::compute" }).to_string()))
    }
}

pub struct AnCfgPostDominatorTreeTool;
impl AnCfgPostDominatorTreeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_cfg_post_dominator_tree".to_string(),
            description: "Compute post-dominator idom map for a CFG.".to_string(),
            input_schema: ancfg_edges_schema(), parameters: ancfg_edges_schema() }
    }
}
#[async_trait]
impl ToolHandler for AnCfgPostDominatorTreeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let idoms: Vec<_> = cfg.post_dom_tree.idom.iter().map(|(k,v)| json!({
            "node": k.0, "ipdom": v.map(|a| a.0)
        })).collect();
        Ok(ToolResult::text(json!({ "count": idoms.len(), "ipdoms": idoms,
            "source": "rustre_analysis_cfg::PostDominatorTree::compute" }).to_string()))
    }
}

pub struct AnCfgFindNaturalLoopsTool;
impl AnCfgFindNaturalLoopsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_cfg_find_natural_loops".to_string(),
            description: "Find all natural loops.".to_string(),
            input_schema: ancfg_edges_schema(), parameters: ancfg_edges_schema() }
    }
}
#[async_trait]
impl ToolHandler for AnCfgFindNaturalLoopsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let loops: Vec<_> = cfg.loops.iter().map(|l| {
            let mut body: Vec<u64> = l.body.iter().map(|a| a.0).collect();
            body.sort_unstable();
            json!({
                "header": l.header.0, "back_edge_src": l.back_edge_src.0,
                "body": body, "exits": l.exits.iter().map(|a| a.0).collect::<Vec<_>>(),
                "is_innermost": l.is_innermost, "size": l.size(),
            })
        }).collect();
        Ok(ToolResult::text(json!({ "count": loops.len(), "loops": loops,
            "source": "rustre_analysis_cfg::find_natural_loops" }).to_string()))
    }
}

pub struct AnCfgFindBackEdgesTool;
impl AnCfgFindBackEdgesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_cfg_find_back_edges".to_string(),
            description: "Return all back-edges via dominator tree.".to_string(),
            input_schema: ancfg_edges_schema(), parameters: ancfg_edges_schema() }
    }
}
#[async_trait]
impl ToolHandler for AnCfgFindBackEdgesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let be = rustre_analysis_cfg::find_back_edges(&cfg, &cfg.dom_tree);
        let items: Vec<_> = be.iter().map(|(f,t)| json!({"from": f.0, "to": t.0})).collect();
        Ok(ToolResult::text(json!({ "count": items.len(), "back_edges": items,
            "source": "rustre_analysis_cfg::find_back_edges" }).to_string()))
    }
}

pub struct AnCfgIsReducibleTool;
impl AnCfgIsReducibleTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_cfg_is_reducible".to_string(),
            description: "Return true if the CFG is reducible.".to_string(),
            input_schema: ancfg_edges_schema(), parameters: ancfg_edges_schema() }
    }
}
#[async_trait]
impl ToolHandler for AnCfgIsReducibleTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let r = rustre_analysis_cfg::is_reducible(&cfg);
        Ok(ToolResult::text(json!({ "is_reducible": r,
            "source": "rustre_analysis_cfg::is_reducible" }).to_string()))
    }
}

pub struct AnCfgCyclomaticComplexityTool;
impl AnCfgCyclomaticComplexityTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_cfg_cyclomatic_complexity".to_string(),
            description: "Compute McCabe cyclomatic complexity.".to_string(),
            input_schema: ancfg_edges_schema(), parameters: ancfg_edges_schema() }
    }
}
#[async_trait]
impl ToolHandler for AnCfgCyclomaticComplexityTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let cc = rustre_analysis_cfg::cyclomatic_complexity(&cfg);
        Ok(ToolResult::text(json!({ "cyclomatic_complexity": cc,
            "source": "rustre_analysis_cfg::cyclomatic_complexity" }).to_string()))
    }
}

pub struct AnCfgToDotTool;
impl AnCfgToDotTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_cfg_to_dot".to_string(),
            description: "Render CFG as Graphviz DOT.".to_string(),
            input_schema: ancfg_edges_schema(), parameters: ancfg_edges_schema() }
    }
}
#[async_trait]
impl ToolHandler for AnCfgToDotTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let dot = rustre_analysis_cfg::cfg_to_dot(&cfg);
        Ok(ToolResult::text(json!({ "dot": dot, "len": dot.len(),
            "source": "rustre_analysis_cfg::cfg_to_dot" }).to_string()))
    }
}

pub struct AnCfgReachableFromTool;
impl AnCfgReachableFromTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        let mut s = ancfg_edges_schema();
        s["properties"]["start"] = json!({"type":"integer"});
        s["required"] = json!(["entry","edges","start"]);
        ToolDefinition { name: "analysis_cfg_reachable_from".to_string(),
            description: "BFS-reachable node set from 'start'.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgReachableFromTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let start = args.get("start").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'start'".into()))?;
        let r = cfg.reachable_from(rustre_core::address::Address::new(start));
        let mut v: Vec<u64> = r.iter().map(|a| a.0).collect();
        v.sort_unstable();
        Ok(ToolResult::text(json!({ "count": v.len(), "reachable": v,
            "source": "rustre_analysis_cfg::ControlFlowGraph::reachable_from" }).to_string()))
    }
}

pub struct AnCfgReversePostOrderTool;
impl AnCfgReversePostOrderTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition { name: "analysis_cfg_reverse_post_order".to_string(),
            description: "Nodes in reverse post-order from entry.".to_string(),
            input_schema: ancfg_edges_schema(), parameters: ancfg_edges_schema() }
    }
}
#[async_trait]
impl ToolHandler for AnCfgReversePostOrderTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let rpo: Vec<u64> = cfg.reverse_post_order().iter().map(|a| a.0).collect();
        Ok(ToolResult::text(json!({ "count": rpo.len(), "rpo": rpo,
            "source": "rustre_analysis_cfg::ControlFlowGraph::reverse_post_order" }).to_string()))
    }
}

pub struct AnCfgDominatesTool;
impl AnCfgDominatesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        let mut s = ancfg_edges_schema();
        s["properties"]["a"] = json!({"type":"integer"});
        s["properties"]["b"] = json!({"type":"integer"});
        s["required"] = json!(["entry","edges","a","b"]);
        ToolDefinition { name: "analysis_cfg_dominates".to_string(),
            description: "Return whether 'a' dominates and post-dominates 'b'.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgDominatesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let d = cfg.dominates(rustre_core::address::Address::new(a), rustre_core::address::Address::new(b));
        let pd = cfg.post_dominates(rustre_core::address::Address::new(a), rustre_core::address::Address::new(b));
        Ok(ToolResult::text(json!({ "dominates": d, "post_dominates": pd,
            "source": "rustre_analysis_cfg::ControlFlowGraph::dominates" }).to_string()))
    }
}

pub struct AnCfgDominanceFrontierTool;
impl AnCfgDominanceFrontierTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        let mut s = ancfg_edges_schema();
        s["properties"]["node"] = json!({"type":"integer"});
        s["required"] = json!(["entry","edges","node"]);
        ToolDefinition { name: "analysis_cfg_dominance_frontier".to_string(),
            description: "Return dominance frontier of a node.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgDominanceFrontierTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let node = args.get("node").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'node'".into()))?;
        let df = cfg.dominance_frontier(rustre_core::address::Address::new(node));
        let items: Vec<u64> = df.iter().map(|a| a.0).collect();
        Ok(ToolResult::text(json!({ "count": items.len(), "frontier": items,
            "source": "rustre_analysis_cfg::ControlFlowGraph::dominance_frontier" }).to_string()))
    }
}

pub struct AnCfgPostOrderTool;
impl AnCfgPostOrderTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = ancfg_edges_schema();
        ToolDefinition { name: "analysis_cfg_post_order".to_string(),
            description: "Return CFG nodes in post-order (leaves first).".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgPostOrderTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let order: Vec<u64> = cfg.post_order().into_iter().map(|a| a.0).collect();
        Ok(ToolResult::text(json!({"count": order.len(), "order": order,
            "source": "rustre_analysis_cfg::ControlFlowGraph::post_order"}).to_string()))
    }
}

pub struct AnCfgPredecessorsTool;
impl AnCfgPredecessorsTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = json!({"type":"object","properties":{"entry":{"type":"integer"},"edges":{"type":"array"},"node":{"type":"integer"}},"required":["entry","edges","node"]});
        ToolDefinition { name: "analysis_cfg_predecessors".to_string(),
            description: "Return predecessors of a CFG node.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgPredecessorsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let node = args.get("node").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'node'".into()))?;
        let preds: Vec<u64> = cfg.predecessors(rustre_core::address::Address::new(node)).into_iter().map(|a| a.0).collect();
        Ok(ToolResult::text(json!({"count": preds.len(), "predecessors": preds,
            "source": "rustre_analysis_cfg::ControlFlowGraph::predecessors"}).to_string()))
    }
}

pub struct AnCfgSuccessorsTool;
impl AnCfgSuccessorsTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = json!({"type":"object","properties":{"entry":{"type":"integer"},"edges":{"type":"array"},"node":{"type":"integer"}},"required":["entry","edges","node"]});
        ToolDefinition { name: "analysis_cfg_successors".to_string(),
            description: "Return successors of a CFG node.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgSuccessorsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let node = args.get("node").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'node'".into()))?;
        let succs: Vec<u64> = cfg.successors(rustre_core::address::Address::new(node)).into_iter().map(|a| a.0).collect();
        Ok(ToolResult::text(json!({"count": succs.len(), "successors": succs,
            "source": "rustre_analysis_cfg::ControlFlowGraph::successors"}).to_string()))
    }
}

pub struct AnCfgIsBackEdgeTool;
impl AnCfgIsBackEdgeTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = json!({"type":"object","properties":{"entry":{"type":"integer"},"edges":{"type":"array"},"from":{"type":"integer"},"to":{"type":"integer"}},"required":["entry","edges","from","to"]});
        ToolDefinition { name: "analysis_cfg_is_back_edge".to_string(),
            description: "Whether from→to is a back edge.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgIsBackEdgeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let f = args.get("from").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'from'".into()))?;
        let t = args.get("to").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'to'".into()))?;
        let r = cfg.is_back_edge(rustre_core::address::Address::new(f), rustre_core::address::Address::new(t));
        Ok(ToolResult::text(json!({"is_back_edge": r,
            "source": "rustre_analysis_cfg::ControlFlowGraph::is_back_edge"}).to_string()))
    }
}

pub struct AnCfgPostDominatesTool;
impl AnCfgPostDominatesTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = json!({"type":"object","properties":{"entry":{"type":"integer"},"edges":{"type":"array"},"a":{"type":"integer"},"b":{"type":"integer"}},"required":["entry","edges","a","b"]});
        ToolDefinition { name: "analysis_cfg_post_dominates".to_string(),
            description: "Whether a post-dominates b.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgPostDominatesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let r = cfg.post_dominates(rustre_core::address::Address::new(a), rustre_core::address::Address::new(b));
        Ok(ToolResult::text(json!({"post_dominates": r,
            "source": "rustre_analysis_cfg::ControlFlowGraph::post_dominates"}).to_string()))
    }
}

pub struct AnCfgImmediateDominatorTool;
impl AnCfgImmediateDominatorTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = json!({"type":"object","properties":{"entry":{"type":"integer"},"edges":{"type":"array"},"node":{"type":"integer"}},"required":["entry","edges","node"]});
        ToolDefinition { name: "analysis_cfg_immediate_dominator".to_string(),
            description: "Return the immediate dominator of a node.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgImmediateDominatorTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let node = args.get("node").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'node'".into()))?;
        let idom = cfg.immediate_dominator(rustre_core::address::Address::new(node)).map(|a| a.0);
        Ok(ToolResult::text(json!({"idom": idom,
            "source": "rustre_analysis_cfg::ControlFlowGraph::immediate_dominator"}).to_string()))
    }
}

pub struct AnCfgBlockCountTool;
impl AnCfgBlockCountTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = ancfg_edges_schema();
        ToolDefinition { name: "analysis_cfg_block_count".to_string(),
            description: "Return the number of basic blocks in the CFG.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgBlockCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        Ok(ToolResult::text(json!({"block_count": cfg.block_count(),
            "source": "rustre_analysis_cfg::ControlFlowGraph::block_count"}).to_string()))
    }
}

pub struct AnCfgEdgeCountTool;
impl AnCfgEdgeCountTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = ancfg_edges_schema();
        ToolDefinition { name: "analysis_cfg_edge_count".to_string(),
            description: "Return the number of edges in the CFG.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgEdgeCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        Ok(ToolResult::text(json!({"edge_count": cfg.edge_count(),
            "source": "rustre_analysis_cfg::ControlFlowGraph::edge_count"}).to_string()))
    }
}

pub struct AnCfgToFullJsonTool;
impl AnCfgToFullJsonTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = ancfg_edges_schema();
        ToolDefinition { name: "analysis_cfg_to_full_json".to_string(),
            description: "Return full JSON serialization of the CFG.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgToFullJsonTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let s = rustre_analysis_cfg::cfg_to_full_json(&cfg);
        Ok(ToolResult::text(json!({"json_len": s.len(), "json": s,
            "source": "rustre_analysis_cfg::cfg_to_full_json"}).to_string()))
    }
}

pub struct AnCfgToDotAnnotatedTool;
impl AnCfgToDotAnnotatedTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = ancfg_edges_schema();
        ToolDefinition { name: "analysis_cfg_to_dot_annotated".to_string(),
            description: "Return DOT rendering annotated with dominator info.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgToDotAnnotatedTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let dot = rustre_analysis_cfg::cfg_to_dot_annotated(&cfg, &cfg.dom_tree);
        Ok(ToolResult::text(json!({"dot_len": dot.len(), "dot": dot,
            "source": "rustre_analysis_cfg::cfg_to_dot_annotated"}).to_string()))
    }
}

pub struct AnCfgDomStrictlyDominatesTool;
impl AnCfgDomStrictlyDominatesTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = json!({"type":"object","properties":{"entry":{"type":"integer"},"edges":{"type":"array"},"a":{"type":"integer"},"b":{"type":"integer"}},"required":["entry","edges","a","b"]});
        ToolDefinition { name: "analysis_cfg_strictly_dominates".to_string(),
            description: "Whether a strictly dominates b.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgDomStrictlyDominatesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let a = args.get("a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
        let b = args.get("b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
        let r = cfg.dom_tree.strictly_dominates(rustre_core::address::Address::new(a), rustre_core::address::Address::new(b));
        Ok(ToolResult::text(json!({"strictly_dominates": r,
            "source": "rustre_analysis_cfg::DominatorTree::strictly_dominates"}).to_string()))
    }
}

pub struct AnCfgDomDominatedByTool;
impl AnCfgDomDominatedByTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = json!({"type":"object","properties":{"entry":{"type":"integer"},"edges":{"type":"array"},"node":{"type":"integer"}},"required":["entry","edges","node"]});
        ToolDefinition { name: "analysis_cfg_dominated_by".to_string(),
            description: "Return nodes strictly dominated by `node`.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgDomDominatedByTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let node = args.get("node").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'node'".into()))?;
        let items: Vec<u64> = cfg.dom_tree.dominated_by(rustre_core::address::Address::new(node)).into_iter().map(|a| a.0).collect();
        Ok(ToolResult::text(json!({"count": items.len(), "dominated": items,
            "source": "rustre_analysis_cfg::DominatorTree::dominated_by"}).to_string()))
    }
}

pub struct AnCfgDomDepthTool;
impl AnCfgDomDepthTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = json!({"type":"object","properties":{"entry":{"type":"integer"},"edges":{"type":"array"},"node":{"type":"integer"}},"required":["entry","edges","node"]});
        ToolDefinition { name: "analysis_cfg_dom_depth".to_string(),
            description: "Return dominator-tree depth of a node.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgDomDepthTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let node = args.get("node").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'node'".into()))?;
        let d = cfg.dom_tree.depth(rustre_core::address::Address::new(node));
        Ok(ToolResult::text(json!({"depth": d,
            "source": "rustre_analysis_cfg::DominatorTree::depth"}).to_string()))
    }
}

pub struct AnCfgStatsIsComplexTool;
impl AnCfgStatsIsComplexTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = ancfg_edges_schema();
        ToolDefinition { name: "analysis_cfg_stats_is_complex".to_string(),
            description: "Whether the CFG is considered complex (cyclomatic > 10).".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgStatsIsComplexTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let s = rustre_analysis_cfg::CfgStats::compute(&cfg);
        Ok(ToolResult::text(json!({"is_complex": s.is_complex(), "cc": s.cyclomatic_complexity,
            "source": "rustre_analysis_cfg::CfgStats::is_complex"}).to_string()))
    }
}

pub struct AnCfgMetricsComputeTool;
impl AnCfgMetricsComputeTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = ancfg_edges_schema();
        ToolDefinition { name: "analysis_cfg_metrics_compute".to_string(),
            description: "Compute CfgMetrics.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgMetricsComputeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let m = rustre_analysis_cfg::CfgMetrics::compute(&cfg);
        Ok(ToolResult::text(json!({
            "cyclomatic_complexity": m.cyclomatic_complexity,
            "back_edge_count": m.back_edge_count,
            "max_loop_depth": m.max_loop_depth,
            "join_count": m.join_count,
            "branch_count": m.branch_count,
            "is_reducible": m.is_reducible,
            "reachable_count": m.reachable_count,
            "edge_count": m.edge_count,
            "source": "rustre_analysis_cfg::CfgMetrics::compute"}).to_string()))
    }
}

pub struct AnCfgSccComponentsTool;
impl AnCfgSccComponentsTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = ancfg_edges_schema();
        ToolDefinition { name: "analysis_cfg_scc_components".to_string(),
            description: "Compute SCCs.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgSccComponentsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let scc = rustre_analysis_cfg::CfgScc::compute(&cfg);
        let comps: Vec<Value> = scc.components.iter().map(|c| json!({
            "nodes": c.nodes.iter().map(|a| a.0).collect::<Vec<_>>(),
            "is_loop": c.is_loop,
        })).collect();
        Ok(ToolResult::text(json!({"count": scc.len(), "components": comps,
            "source": "rustre_analysis_cfg::CfgScc::compute"}).to_string()))
    }
}

pub struct AnCfgSccLoopsCountTool;
impl AnCfgSccLoopsCountTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = ancfg_edges_schema();
        ToolDefinition { name: "analysis_cfg_scc_loops_count".to_string(),
            description: "Count non-trivial SCCs.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgSccLoopsCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let scc = rustre_analysis_cfg::CfgScc::compute(&cfg);
        Ok(ToolResult::text(json!({"loop_scc_count": scc.loops().len(), "total_scc": scc.len(),
            "source": "rustre_analysis_cfg::CfgScc::loops"}).to_string()))
    }
}

pub struct AnCfgReducibilityTestTool;
impl AnCfgReducibilityTestTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = ancfg_edges_schema();
        ToolDefinition { name: "analysis_cfg_reducibility_test".to_string(),
            description: "Havlak reducibility.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgReducibilityTestTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let r = rustre_analysis_cfg::ReducibilityTest::test(&cfg);
        let reducible = r.is_reducible();
        let irr: Vec<Value> = match &r {
            rustre_analysis_cfg::ReducibilityResult::Irreducible { back_edges } =>
                back_edges.iter().map(|(f,t)| json!({"from": f.0, "to": t.0})).collect(),
            _ => Vec::new(),
        };
        Ok(ToolResult::text(json!({"is_reducible": reducible, "irreducible_back_edges": irr,
            "source": "rustre_analysis_cfg::ReducibilityTest::test"}).to_string()))
    }
}

pub struct AnCfgDominanceFrontierOfTool;
impl AnCfgDominanceFrontierOfTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = json!({"type":"object","properties":{"entry":{"type":"integer"},"edges":{"type":"array"},"node":{"type":"integer"}},"required":["entry","edges","node"]});
        ToolDefinition { name: "analysis_cfg_dominance_frontier_of".to_string(),
            description: "DominanceFrontier::frontier_of.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgDominanceFrontierOfTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let node = args.get("node").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing node".into()))?;
        let df = rustre_analysis_cfg::DominanceFrontier::compute(&cfg.dom_tree, &cfg.edges);
        let items: Vec<u64> = df.frontier_of(rustre_core::address::Address::new(node)).iter().map(|a| a.0).collect();
        Ok(ToolResult::text(json!({"count": items.len(), "frontier": items,
            "source": "rustre_analysis_cfg::DominanceFrontier::frontier_of"}).to_string()))
    }
}

pub struct AnCfgIteratedDominanceFrontierTool;
impl AnCfgIteratedDominanceFrontierTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = json!({"type":"object","properties":{"entry":{"type":"integer"},"edges":{"type":"array"},"seeds":{"type":"array","items":{"type":"integer"}}},"required":["entry","edges","seeds"]});
        ToolDefinition { name: "analysis_cfg_iterated_dominance_frontier".to_string(),
            description: "Iterated DF for SSA.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgIteratedDominanceFrontierTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let seeds_v = args.get("seeds").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing seeds".into()))?;
        let seeds: Vec<rustre_core::address::Address> = seeds_v.iter()
            .filter_map(|v| v.as_u64().map(rustre_core::address::Address::new)).collect();
        let df = rustre_analysis_cfg::DominanceFrontier::compute(&cfg.dom_tree, &cfg.edges);
        let idf: Vec<u64> = df.iterated_frontier(&seeds).into_iter().map(|a| a.0).collect();
        Ok(ToolResult::text(json!({"count": idf.len(), "idf": idf,
            "source": "rustre_analysis_cfg::DominanceFrontier::iterated_frontier"}).to_string()))
    }
}

pub struct AnCfgNaturalLoopCountTool;
impl AnCfgNaturalLoopCountTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = ancfg_edges_schema();
        ToolDefinition { name: "analysis_cfg_natural_loop_count".to_string(),
            description: "Count natural loops.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgNaturalLoopCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let loops = rustre_analysis_cfg::find_natural_loops(&cfg);
        Ok(ToolResult::text(json!({"loop_count": loops.len(),
            "source": "rustre_analysis_cfg::find_natural_loops"}).to_string()))
    }
}

pub struct AnCfgNaturalLoopsInnermostTool;
impl AnCfgNaturalLoopsInnermostTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = ancfg_edges_schema();
        ToolDefinition { name: "analysis_cfg_natural_loops_innermost".to_string(),
            description: "List innermost natural loops.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgNaturalLoopsInnermostTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let loops = rustre_analysis_cfg::find_natural_loops(&cfg);
        let innermost: Vec<Value> = loops.iter().filter(|l| l.is_innermost).map(|l| json!({
            "header": l.header.0,
            "back_edge_src": l.back_edge_src.0,
            "size": l.size(),
            "exits": l.exits.iter().map(|a| a.0).collect::<Vec<_>>(),
        })).collect();
        Ok(ToolResult::text(json!({"count": innermost.len(), "loops": innermost,
            "source": "rustre_analysis_cfg::NaturalLoop"}).to_string()))
    }
}

pub struct AnCfgStatsEntryExitBlocksTool;
impl AnCfgStatsEntryExitBlocksTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = ancfg_edges_schema();
        ToolDefinition { name: "analysis_cfg_stats_entry_exit_blocks".to_string(),
            description: "Entry/exit block counts.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgStatsEntryExitBlocksTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let s = rustre_analysis_cfg::CfgStats::compute(&cfg);
        Ok(ToolResult::text(json!({
            "entry_blocks": s.entry_blocks,
            "exit_blocks": s.exit_blocks,
            "node_count": s.node_count,
            "loop_count": s.loop_count,
            "max_loop_depth": s.max_loop_depth,
            "source": "rustre_analysis_cfg::CfgStats"}).to_string()))
    }
}

pub struct AnCfgReachableCountTool;
impl AnCfgReachableCountTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = ancfg_edges_schema();
        ToolDefinition { name: "analysis_cfg_reachable_count".to_string(),
            description: "Blocks reachable from entry.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgReachableCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let m = rustre_analysis_cfg::CfgMetrics::compute(&cfg);
        Ok(ToolResult::text(json!({"reachable_count": m.reachable_count, "total_blocks": cfg.blocks.len(),
            "source": "rustre_analysis_cfg::CfgMetrics"}).to_string()))
    }
}

pub struct AnCfgJoinBranchCountsTool;
impl AnCfgJoinBranchCountsTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = ancfg_edges_schema();
        ToolDefinition { name: "analysis_cfg_join_branch_counts".to_string(),
            description: "Join and branch counts.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgJoinBranchCountsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let m = rustre_analysis_cfg::CfgMetrics::compute(&cfg);
        Ok(ToolResult::text(json!({
            "join_count": m.join_count,
            "branch_count": m.branch_count,
            "back_edge_count": m.back_edge_count,
            "source": "rustre_analysis_cfg::CfgMetrics"}).to_string()))
    }
}

pub struct AnCfgDotPrinterRenderTool;
impl AnCfgDotPrinterRenderTool {
    #[must_use] pub fn definition() -> ToolDefinition {
        let s = ancfg_edges_schema();
        ToolDefinition { name: "analysis_cfg_dot_printer_render".to_string(),
            description: "CfgDotPrinter::new().print.".to_string(),
            input_schema: s.clone(), parameters: s }
    }
}
#[async_trait]
impl ToolHandler for AnCfgDotPrinterRenderTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let cfg = ancfg_build_cfg_from_args(&args)?;
        let printer = rustre_analysis_cfg::CfgDotPrinter::new();
        let dot = printer.print(&cfg);
        Ok(ToolResult::text(json!({"dot_len": dot.len(), "dot": dot,
            "source": "rustre_analysis_cfg::CfgDotPrinter::print"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (AnCfgBuildStatsTool::definition(), Box::new(AnCfgBuildStatsTool)),
        (AnCfgDominatorTreeTool::definition(), Box::new(AnCfgDominatorTreeTool)),
        (AnCfgPostDominatorTreeTool::definition(), Box::new(AnCfgPostDominatorTreeTool)),
        (AnCfgFindNaturalLoopsTool::definition(), Box::new(AnCfgFindNaturalLoopsTool)),
        (AnCfgFindBackEdgesTool::definition(), Box::new(AnCfgFindBackEdgesTool)),
        (AnCfgIsReducibleTool::definition(), Box::new(AnCfgIsReducibleTool)),
        (AnCfgCyclomaticComplexityTool::definition(), Box::new(AnCfgCyclomaticComplexityTool)),
        (AnCfgToDotTool::definition(), Box::new(AnCfgToDotTool)),
        (AnCfgReachableFromTool::definition(), Box::new(AnCfgReachableFromTool)),
        (AnCfgReversePostOrderTool::definition(), Box::new(AnCfgReversePostOrderTool)),
        (AnCfgDominatesTool::definition(), Box::new(AnCfgDominatesTool)),
        (AnCfgDominanceFrontierTool::definition(), Box::new(AnCfgDominanceFrontierTool)),
        (AnCfgPostOrderTool::definition(), Box::new(AnCfgPostOrderTool)),
        (AnCfgPredecessorsTool::definition(), Box::new(AnCfgPredecessorsTool)),
        (AnCfgSuccessorsTool::definition(), Box::new(AnCfgSuccessorsTool)),
        (AnCfgIsBackEdgeTool::definition(), Box::new(AnCfgIsBackEdgeTool)),
        (AnCfgPostDominatesTool::definition(), Box::new(AnCfgPostDominatesTool)),
        (AnCfgImmediateDominatorTool::definition(), Box::new(AnCfgImmediateDominatorTool)),
        (AnCfgBlockCountTool::definition(), Box::new(AnCfgBlockCountTool)),
        (AnCfgEdgeCountTool::definition(), Box::new(AnCfgEdgeCountTool)),
        (AnCfgToFullJsonTool::definition(), Box::new(AnCfgToFullJsonTool)),
        (AnCfgToDotAnnotatedTool::definition(), Box::new(AnCfgToDotAnnotatedTool)),
        (AnCfgDomStrictlyDominatesTool::definition(), Box::new(AnCfgDomStrictlyDominatesTool)),
        (AnCfgDomDominatedByTool::definition(), Box::new(AnCfgDomDominatedByTool)),
        (AnCfgDomDepthTool::definition(), Box::new(AnCfgDomDepthTool)),
        (AnCfgStatsIsComplexTool::definition(), Box::new(AnCfgStatsIsComplexTool)),
        (AnCfgMetricsComputeTool::definition(), Box::new(AnCfgMetricsComputeTool)),
        (AnCfgSccComponentsTool::definition(), Box::new(AnCfgSccComponentsTool)),
        (AnCfgSccLoopsCountTool::definition(), Box::new(AnCfgSccLoopsCountTool)),
        (AnCfgReducibilityTestTool::definition(), Box::new(AnCfgReducibilityTestTool)),
        (AnCfgDominanceFrontierOfTool::definition(), Box::new(AnCfgDominanceFrontierOfTool)),
        (AnCfgIteratedDominanceFrontierTool::definition(), Box::new(AnCfgIteratedDominanceFrontierTool)),
        (AnCfgNaturalLoopCountTool::definition(), Box::new(AnCfgNaturalLoopCountTool)),
        (AnCfgNaturalLoopsInnermostTool::definition(), Box::new(AnCfgNaturalLoopsInnermostTool)),
        (AnCfgStatsEntryExitBlocksTool::definition(), Box::new(AnCfgStatsEntryExitBlocksTool)),
        (AnCfgReachableCountTool::definition(), Box::new(AnCfgReachableCountTool)),
        (AnCfgJoinBranchCountsTool::definition(), Box::new(AnCfgJoinBranchCountsTool)),
        (AnCfgDotPrinterRenderTool::definition(), Box::new(AnCfgDotPrinterRenderTool)),
    ]
}
