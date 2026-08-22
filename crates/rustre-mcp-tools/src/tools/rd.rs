//! MCP wrappers for the rustre-rd crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{__rd_fp_from_args};

pub struct RdFpNewTool;
impl RdFpNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_fp_new_wire".to_string(), description: "rustre_diff::FuncFingerprint::new".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"},"a_addr":{"type":"integer"},"a_name":{"type":"string"}},"required":["a"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RdFpNewTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let fp = __rd_fp_from_args(&args, "a")?; Ok(ToolResult::text(json!({"addr":fp.address,"name":fp.name,"size":fp.size,"hash":fp.hash,"source":"rustre_diff::FuncFingerprint::new"}).to_string())) } }

pub struct RdFpSimilarityTool;
impl RdFpSimilarityTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_fp_similarity_wire".to_string(), description: "rustre_diff::FuncFingerprint::similarity".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}},"required":["a","b"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RdFpSimilarityTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = __rd_fp_from_args(&args, "a")?; let b = __rd_fp_from_args(&args, "b")?; Ok(ToolResult::text(json!({"similarity":a.similarity(&b),"source":"rustre_diff::FuncFingerprint::similarity"}).to_string())) } }

pub struct RdFpDisplayTool;
impl RdFpDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_fp_display_wire".to_string(), description: "rustre_diff::FuncFingerprint Display".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"},"a_addr":{"type":"integer"},"a_name":{"type":"string"}},"required":["a"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RdFpDisplayTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let fp = __rd_fp_from_args(&args, "a")?; Ok(ToolResult::text(json!({"display":fp.to_string(),"source":"rustre_diff::FuncFingerprint::Display"}).to_string())) } }

pub struct RdFuncMatchIdenticalTool;
impl RdFuncMatchIdenticalTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_func_match_identical_wire".to_string(), description: "rustre_diff::FuncMatch::identical".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}},"required":["a","b"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RdFuncMatchIdenticalTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = __rd_fp_from_args(&args, "a")?; let b = __rd_fp_from_args(&args, "b")?; let m = rustre_diff::FuncMatch::identical(a, b); Ok(ToolResult::text(json!({"kind":m.kind.to_string(),"similarity":m.similarity,"confidence":m.confidence,"is_changed":m.is_changed(),"source":"rustre_diff::FuncMatch::identical"}).to_string())) } }

pub struct RdFuncMatchSimilarTool;
impl RdFuncMatchSimilarTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_func_match_similar_wire".to_string(), description: "rustre_diff::FuncMatch::similar".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"},"similarity":{"type":"number"}},"required":["a","b","similarity"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RdFuncMatchSimilarTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = __rd_fp_from_args(&args, "a")?; let b = __rd_fp_from_args(&args, "b")?; let sim = args.get("similarity").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing 'similarity'".into()))?; let m = rustre_diff::FuncMatch::similar(a, b, sim); Ok(ToolResult::text(json!({"kind":m.kind.to_string(),"confidence":m.confidence,"display":m.to_string(),"source":"rustre_diff::FuncMatch::similar"}).to_string())) } }

pub struct RdFuncMatchRenamedTool;
impl RdFuncMatchRenamedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_func_match_renamed_wire".to_string(), description: "rustre_diff::FuncMatch::renamed".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"},"similarity":{"type":"number"}},"required":["a","b","similarity"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RdFuncMatchRenamedTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = __rd_fp_from_args(&args, "a")?; let b = __rd_fp_from_args(&args, "b")?; let sim = args.get("similarity").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing 'similarity'".into()))?; let m = rustre_diff::FuncMatch::renamed(a, b, sim); Ok(ToolResult::text(json!({"kind":m.kind.to_string(),"confidence":m.confidence,"is_changed":m.is_changed(),"source":"rustre_diff::FuncMatch::renamed"}).to_string())) } }

pub struct RdFuncMatchAddedRemovedTool;
impl RdFuncMatchAddedRemovedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_func_match_added_removed_wire".to_string(), description: "rustre_diff::FuncMatch::{added,removed}".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"}},"required":["a"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RdFuncMatchAddedRemovedTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = __rd_fp_from_args(&args, "a")?; let added = rustre_diff::FuncMatch::added(a.clone()); let removed = rustre_diff::FuncMatch::removed(a); Ok(ToolResult::text(json!({"added_kind":added.kind.to_string(),"added_is_changed":added.is_changed(),"removed_kind":removed.kind.to_string(),"removed_is_changed":removed.is_changed(),"source":"rustre_diff::FuncMatch::{added,removed}"}).to_string())) } }

pub struct RdDiffEngineRunTool;
impl RdDiffEngineRunTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_engine_run_wire".to_string(), description: "rustre_diff::DiffEngine::diff".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"},"threshold":{"type":"number"}},"required":["a","b"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RdDiffEngineRunTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let a = __rd_fp_from_args(&args, "a")?; let b = __rd_fp_from_args(&args, "b")?; let th = args.get("threshold").and_then(Value::as_f64).unwrap_or(0.6); let eng = rustre_diff::DiffEngine::new(th); let d = eng.diff(vec![a], &[b], "A".into(), "B".into()).map_err(|e| McpError::InvalidParams(e.to_string()))?; Ok(ToolResult::text(json!({"identical":d.identical_count(),"added":d.added_count(),"removed":d.removed_count(),"changed":d.changed_count(),"similarity_ratio":d.similarity_ratio(),"display":d.to_string(),"source":"rustre_diff::DiffEngine::diff"}).to_string())) } }

pub struct RdDiffEngineDebugTool;
impl RdDiffEngineDebugTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_engine_debug_wire".to_string(), description: "rustre_diff::DiffEngine Debug/Default".to_string(), input_schema: json!({"type":"object","properties":{"threshold":{"type":"number"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RdDiffEngineDebugTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let eng = match args.get("threshold").and_then(Value::as_f64) { Some(t) => rustre_diff::DiffEngine::new(t), None => rustre_diff::DiffEngine::default() }; Ok(ToolResult::text(json!({"debug":format!("{eng:?}"),"source":"rustre_diff::DiffEngine::Debug"}).to_string())) } }

pub struct RdChangeTypeDisplayTool;
impl RdChangeTypeDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_change_type_display_wire".to_string(), description: "rustre_diff::ChangeType Display".to_string(), input_schema: json!({"type":"object","properties":{"similarity":{"type":"number"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RdChangeTypeDisplayTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let sim = args.get("similarity").and_then(Value::as_f64).unwrap_or(0.75); Ok(ToolResult::text(json!({"added":rustre_diff::ChangeType::Added.to_string(),"removed":rustre_diff::ChangeType::Removed.to_string(),"unchanged":rustre_diff::ChangeType::Unchanged.to_string(),"modified":rustre_diff::ChangeType::Modified{similarity:sim}.to_string(),"source":"rustre_diff::ChangeType::Display"}).to_string())) } }

pub struct RdDiffByNameTool;
impl RdDiffByNameTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_by_name_wire".to_string(), description: "rustre_diff::diff_by_name".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"object"},"b":{"type":"object"}},"required":["a","b"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RdDiffByNameTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    fn conv(v: Option<&Value>) -> std::collections::HashMap<String, Vec<u8>> {
        let mut m = std::collections::HashMap::new();
        if let Some(o) = v.and_then(Value::as_object) {
            for (k, val) in o {
                if let Some(s) = val.as_str() {
                    let bytes: Vec<u8> = (0..s.len()).step_by(2).filter_map(|i| s.get(i..i+2).and_then(|c| u8::from_str_radix(c,16).ok())).collect();
                    m.insert(k.clone(), bytes);
                }
            }
        }
        m
    }
    // `conv` accetta `None` e restituisce una mappa vuota, ma lo schema dichiara
    // 'a' e 'b' OBBLIGATORIE: senza, il tool confrontava due insiemi vuoti e
    // riportava "nessuna differenza". Le chiavi vanno pretese qui.
    let va = args.get("a").ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
    let vb = args.get("b").ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
    let ma = conv(Some(va)); let mb = conv(Some(vb));
    let d = rustre_diff::diff_by_name(&ma, &mb);
    Ok(ToolResult::text(json!({"added":d.added_count(),"removed":d.removed_count(),"modified":d.modified_count(),"unchanged":d.unchanged_count(),"overall_similarity":d.overall_similarity,"source":"rustre_diff::diff_by_name"}).to_string()))
} }

pub struct RdExportDiffIsCleanTool;
impl RdExportDiffIsCleanTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_export_is_clean_wire".to_string(), description: "rustre_diff::diff_exports + ExportDiff::is_clean".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"array"},"b":{"type":"array"}},"required":["a","b"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for RdExportDiffIsCleanTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    fn conv(v: Option<&Value>) -> Vec<rustre_diff::ExportEntry> {
        v.and_then(Value::as_array).map(|arr| arr.iter().filter_map(|e| {
            let name = e.get("name").and_then(Value::as_str).map(String::from);
            let ordinal = u32::try_from(e.get("ordinal").and_then(Value::as_u64)?).ok()?;
            let address = e.get("address").and_then(Value::as_u64)?;
            Some(rustre_diff::ExportEntry { name, ordinal, address })
        }).collect()).unwrap_or_default()
    }
    // Stessa correzione: 'a' e 'b' sono `required` nello schema, ma `conv`
    // restituiva un vettore vuoto su chiave assente e il diff risultava "pulito".
    let va = args.get("a").ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?;
    let vb = args.get("b").ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?;
    let a = conv(Some(va)); let b = conv(Some(vb));
    let d = rustre_diff::diff_exports(&a, &b);
    Ok(ToolResult::text(json!({"is_clean":d.is_clean(),"display":d.to_string(),"added":d.added.len(),"removed":d.removed.len(),"moved":d.moved.len(),"unchanged":d.unchanged.len(),"source":"rustre_diff::ExportDiff::is_clean"}).to_string()))
} }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (RdFpNewTool::definition(), Box::new(RdFpNewTool)),
        (RdFpSimilarityTool::definition(), Box::new(RdFpSimilarityTool)),
        (RdFpDisplayTool::definition(), Box::new(RdFpDisplayTool)),
        (RdFuncMatchIdenticalTool::definition(), Box::new(RdFuncMatchIdenticalTool)),
        (RdFuncMatchSimilarTool::definition(), Box::new(RdFuncMatchSimilarTool)),
        (RdFuncMatchRenamedTool::definition(), Box::new(RdFuncMatchRenamedTool)),
        (RdFuncMatchAddedRemovedTool::definition(), Box::new(RdFuncMatchAddedRemovedTool)),
        (RdDiffEngineRunTool::definition(), Box::new(RdDiffEngineRunTool)),
        (RdDiffEngineDebugTool::definition(), Box::new(RdDiffEngineDebugTool)),
        (RdChangeTypeDisplayTool::definition(), Box::new(RdChangeTypeDisplayTool)),
        (RdDiffByNameTool::definition(), Box::new(RdDiffByNameTool)),
        (RdExportDiffIsCleanTool::definition(), Box::new(RdExportDiffIsCleanTool)),
    ]
}
