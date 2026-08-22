//! MCP wrappers for the rustre-axr crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{axr_build_db_from_calls};

pub struct AxrDbCallersOfTool;
impl AxrDbCallersOfTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "axr_db_callers_of".to_string(), description: "XrefDatabase::callers_of for a target address.".to_string(), input_schema: json!({"type":"object","required":["addr"],"properties":{"addr":{"type":"integer"},"calls":{"type":"array"},"jumps":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AxrDbCallersOfTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_core::address::Address; let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("addr".into()))?; let db = axr_build_db_from_calls(&args); let v: Vec<u64> = db.callers_of(Address::new(addr)).iter().map(|a| a.as_u64()).collect(); Ok(ToolResult::text(json!({"callers": v}).to_string())) } }

pub struct AxrDbCalleesOfTool;
impl AxrDbCalleesOfTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "axr_db_callees_of".to_string(), description: "XrefDatabase::callees_of for a source address.".to_string(), input_schema: json!({"type":"object","required":["addr"],"properties":{"addr":{"type":"integer"},"calls":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AxrDbCalleesOfTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_core::address::Address; let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("addr".into()))?; let db = axr_build_db_from_calls(&args); let v: Vec<u64> = db.callees_of(Address::new(addr)).iter().map(|a| a.as_u64()).collect(); Ok(ToolResult::text(json!({"callees": v}).to_string())) } }

pub struct AxrDbHotFunctionsTool;
impl AxrDbHotFunctionsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "axr_db_hot_functions".to_string(), description: "XrefDatabase::hot_functions(top_n).".to_string(), input_schema: json!({"type":"object","properties":{"top_n":{"type":"integer"},"calls":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AxrDbHotFunctionsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let top = args.get("top_n").and_then(Value::as_u64).unwrap_or(5) as usize; let db = axr_build_db_from_calls(&args); let v: Vec<(u64, usize)> = db.hot_functions(top).into_iter().map(|(a,c)| (a.as_u64(), c)).collect(); Ok(ToolResult::text(json!({"hot": v}).to_string())) } }

pub struct AxrDbIsLeafFunctionTool;
impl AxrDbIsLeafFunctionTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "axr_db_is_leaf_function".to_string(), description: "XrefDatabase::is_leaf_function.".to_string(), input_schema: json!({"type":"object","required":["addr"],"properties":{"addr":{"type":"integer"},"calls":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AxrDbIsLeafFunctionTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_core::address::Address; let addr = args.get("addr").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("addr".into()))?; let db = axr_build_db_from_calls(&args); Ok(ToolResult::text(json!({"leaf": db.is_leaf_function(Address::new(addr))}).to_string())) } }

pub struct AxrDbAllImportNamesTool;
impl AxrDbAllImportNamesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "axr_db_all_import_names".to_string(), description: "XrefDatabase::all_import_names.".to_string(), input_schema: json!({"type":"object","properties":{"imports":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AxrDbAllImportNamesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let db = axr_build_db_from_calls(&args); let v: Vec<String> = db.all_import_names().into_iter().map(String::from).collect(); Ok(ToolResult::text(json!({"imports": v}).to_string())) } }

pub struct AxrDbAllStringsTool;
impl AxrDbAllStringsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "axr_db_all_strings".to_string(), description: "XrefDatabase::all_strings.".to_string(), input_schema: json!({"type":"object","properties":{"strings":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AxrDbAllStringsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let db = axr_build_db_from_calls(&args); let v: Vec<String> = db.all_strings().into_iter().map(String::from).collect(); Ok(ToolResult::text(json!({"strings": v}).to_string())) } }

pub struct AxrDbToJsonTool;
impl AxrDbToJsonTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "axr_db_to_json".to_string(), description: "XrefDatabase::to_json size.".to_string(), input_schema: json!({"type":"object","properties":{"calls":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AxrDbToJsonTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let db = axr_build_db_from_calls(&args); match db.to_json() { Ok(s) => Ok(ToolResult::text(json!({"ok": true, "bytes": s.len()}).to_string())), Err(e) => Ok(ToolResult::text(json!({"ok": false, "error": e.to_string()}).to_string())) } } }

pub struct AxrGraphCallGraphStatsTool;
impl AxrGraphCallGraphStatsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "axr_graph_call_graph_stats".to_string(), description: "XrefGraph::call_graph nodes/edges.".to_string(), input_schema: json!({"type":"object","properties":{"calls":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AxrGraphCallGraphStatsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let db = axr_build_db_from_calls(&args); let g = rustre_analysis_xref::XrefGraph::call_graph(&db); Ok(ToolResult::text(json!({"nodes": g.node_count(), "edges": g.edge_count()}).to_string())) } }

pub struct AxrGraphReachableFromTool;
impl AxrGraphReachableFromTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "axr_graph_reachable_from".to_string(), description: "XrefGraph::reachable_from over the call graph.".to_string(), input_schema: json!({"type":"object","required":["start"],"properties":{"start":{"type":"integer"},"calls":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AxrGraphReachableFromTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_core::address::Address; let start = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("start".into()))?; let db = axr_build_db_from_calls(&args); let g = rustre_analysis_xref::XrefGraph::call_graph(&db); let set: Vec<u64> = g.reachable_from(Address::new(start)).into_iter().map(|a| a.as_u64()).collect(); Ok(ToolResult::text(json!({"count": set.len(), "reachable": set}).to_string())) } }

pub struct AxrGraphBfsDistancesTool;
impl AxrGraphBfsDistancesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "axr_graph_bfs_distances".to_string(), description: "XrefGraph::bfs_distances from start over call graph.".to_string(), input_schema: json!({"type":"object","required":["start"],"properties":{"start":{"type":"integer"},"calls":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AxrGraphBfsDistancesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_core::address::Address; let start = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("start".into()))?; let db = axr_build_db_from_calls(&args); let g = rustre_analysis_xref::XrefGraph::call_graph(&db); let dists: Vec<(u64, usize)> = g.bfs_distances(Address::new(start)).into_iter().map(|(a,d)| (a.as_u64(), d)).collect(); Ok(ToolResult::text(json!({"distances": dists}).to_string())) } }

pub struct AxrGraphSccTool;
impl AxrGraphSccTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "axr_graph_scc".to_string(), description: "XrefGraph::strongly_connected_components over the call graph.".to_string(), input_schema: json!({"type":"object","properties":{"calls":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AxrGraphSccTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let db = axr_build_db_from_calls(&args); let g = rustre_analysis_xref::XrefGraph::call_graph(&db); let sccs: Vec<Vec<u64>> = g.strongly_connected_components().into_iter().map(|c| c.into_iter().map(|a| a.as_u64()).collect()).collect(); Ok(ToolResult::text(json!({"count": sccs.len(), "sccs": sccs}).to_string())) } }

pub struct AxrGraphTopoSortTool;
impl AxrGraphTopoSortTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "axr_graph_topological_sort".to_string(), description: "XrefGraph::topological_sort over the call graph (None if cyclic).".to_string(), input_schema: json!({"type":"object","properties":{"calls":{"type":"array"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for AxrGraphTopoSortTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let db = axr_build_db_from_calls(&args); let g = rustre_analysis_xref::XrefGraph::call_graph(&db); let order = g.topological_sort().map(|v| v.into_iter().map(|a| a.as_u64()).collect::<Vec<_>>()); Ok(ToolResult::text(json!({"order": order}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (AxrDbCallersOfTool::definition(), Box::new(AxrDbCallersOfTool)),
        (AxrDbCalleesOfTool::definition(), Box::new(AxrDbCalleesOfTool)),
        (AxrDbHotFunctionsTool::definition(), Box::new(AxrDbHotFunctionsTool)),
        (AxrDbIsLeafFunctionTool::definition(), Box::new(AxrDbIsLeafFunctionTool)),
        (AxrDbAllImportNamesTool::definition(), Box::new(AxrDbAllImportNamesTool)),
        (AxrDbAllStringsTool::definition(), Box::new(AxrDbAllStringsTool)),
        (AxrDbToJsonTool::definition(), Box::new(AxrDbToJsonTool)),
        (AxrGraphCallGraphStatsTool::definition(), Box::new(AxrGraphCallGraphStatsTool)),
        (AxrGraphReachableFromTool::definition(), Box::new(AxrGraphReachableFromTool)),
        (AxrGraphBfsDistancesTool::definition(), Box::new(AxrGraphBfsDistancesTool)),
        (AxrGraphSccTool::definition(), Box::new(AxrGraphSccTool)),
        (AxrGraphTopoSortTool::definition(), Box::new(AxrGraphTopoSortTool)),
    ]
}
