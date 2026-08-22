//! MCP wrappers for the rustre-diff crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{parse_bindiff_function_info, parse_bindiff_function_info_list, parse_bindiff_matrix, parse_match_kind_bindiff_extra};

pub struct DiffBindiffCfgHashLinearTool;

pub struct DiffBindiffWlHashTool;

pub struct DiffBindiffSimilarityScoreTool;

pub struct DiffBindiffCfgHashTool;

pub struct DiffBindiffJaccardBbScoreTool;

pub struct DiffBindiffCfgSimilarityTool;

pub struct DiffBindiffMatchKindIsReliableTool;
impl DiffBindiffMatchKindIsReliableTool { #[must_use] pub fn definition() -> ToolDefinition {
    ToolDefinition { name: "diff_bindiff_match_kind_is_reliable".to_string(),
        description: "MatchKind::is_reliable via rustre_diff_bindiff.".to_string(),
        input_schema: json!({"type":"object","properties":{"kind":{"type":"string"}},"required":["kind"]}),
        parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffMatchKindIsReliableTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let k = parse_match_kind_bindiff_extra(s).ok_or_else(|| McpError::InvalidParams(format!("unknown kind '{s}'")))?;
        Ok(ToolResult::text(json!({"kind":s,"is_reliable":k.is_reliable(),"source":"rustre_diff_bindiff::MatchKind::is_reliable"}).to_string()))
    } }

pub struct DiffBindiffMatchKindPriorityTool;
impl DiffBindiffMatchKindPriorityTool { #[must_use] pub fn definition() -> ToolDefinition {
    ToolDefinition { name: "diff_bindiff_match_kind_priority".to_string(),
        description: "MatchKind::priority via rustre_diff_bindiff.".to_string(),
        input_schema: json!({"type":"object","properties":{"kind":{"type":"string"}},"required":["kind"]}),
        parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffMatchKindPriorityTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
        let k = parse_match_kind_bindiff_extra(s).ok_or_else(|| McpError::InvalidParams(format!("unknown kind '{s}'")))?;
        Ok(ToolResult::text(json!({"kind":s,"priority":k.priority(),"source":"rustre_diff_bindiff::MatchKind::priority"}).to_string()))
    } }

pub struct DiffBindiffFunctionInfoNewTool;
impl DiffBindiffFunctionInfoNewTool { #[must_use] pub fn definition() -> ToolDefinition {
    ToolDefinition { name: "diff_bindiff_function_info_new".to_string(),
        description: "FunctionInfo::new via rustre_diff_bindiff.".to_string(),
        input_schema: json!({"type":"object","properties":{"address":{"type":"integer"}},"required":["address"]}),
        parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffFunctionInfoNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let addr = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'address'".into()))?;
        let fi = rustre_diff_bindiff::FunctionInfo::new(addr);
        Ok(ToolResult::text(json!({"address":fi.address,"bytes_crc32":fi.bytes_crc32,"in_edges":fi.in_edges,"out_edges":fi.out_edges,"bb_count":fi.bb_count,"md_index":fi.md_index,"source":"rustre_diff_bindiff::FunctionInfo::new"}).to_string()))
    } }

pub struct DiffBindiffFunctionMatchQualityTool;
impl DiffBindiffFunctionMatchQualityTool { #[must_use] pub fn definition() -> ToolDefinition {
    ToolDefinition { name: "diff_bindiff_function_match_quality".to_string(),
        description: "FunctionMatch quality via rustre_diff_bindiff.".to_string(),
        input_schema: json!({"type":"object","properties":{"similarity":{"type":"number"},"confidence":{"type":"number"},"kind":{"type":"string"}},"required":["similarity","confidence","kind"]}),
        parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffFunctionMatchQualityTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_diff_bindiff::{FunctionMatch, MatchKind};
        use rustre_core::address::Address;
        let sim = args.get("similarity").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing 'similarity'".into()))? as f32;
        let conf = args.get("confidence").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing 'confidence'".into()))? as f32;
        let ks = args.get("kind").and_then(Value::as_str).unwrap_or("Heuristic");
        let k = parse_match_kind_bindiff_extra(ks).unwrap_or(MatchKind::Heuristic);
        let mut m = FunctionMatch::new(Address::new(0), Address::new(0), k).with_similarity(sim);
        m.confidence = conf.clamp(0.0, 1.0);
        Ok(ToolResult::text(json!({"similarity":m.similarity,"confidence":m.confidence,"is_identical":m.is_identical(),"is_good_match":m.is_good_match(),"quality_label":m.quality_label(),"source":"rustre_diff_bindiff::FunctionMatch"}).to_string()))
    } }

pub struct DiffBindiffBinDifferDefaultsTool;
impl DiffBindiffBinDifferDefaultsTool { #[must_use] pub fn definition() -> ToolDefinition {
    ToolDefinition { name: "diff_bindiff_bindiffer_defaults".to_string(),
        description: "BinDiffer::new defaults via rustre_diff_bindiff.".to_string(),
        input_schema: json!({"type":"object","properties":{}}),
        parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffBinDifferDefaultsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let d = rustre_diff_bindiff::BinDiffer::new();
        Ok(ToolResult::text(json!({"min_similarity":d.min_similarity,"enable_propagation":d.enable_propagation,"max_candidates":d.max_candidates,"source":"rustre_diff_bindiff::BinDiffer::new"}).to_string()))
    } }
fn parse_bindiff_features_extra(v: &Value) -> rustre_diff_bindiff::FunctionFeatures {
    use rustre_core::address::Address;
    let addr = v.get("address").and_then(Value::as_u64).unwrap_or(0);
    let mut f = rustre_diff_bindiff::FunctionFeatures::new(Address::new(addr));
    let get_u32 = |k: &str| v.get(k).and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).unwrap_or(0);
    let get_u64 = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
    f.basic_block_count = get_u32("basic_block_count");
    f.edge_count = get_u32("edge_count");
    f.instruction_count = get_u32("instruction_count");
    f.call_count = get_u32("call_count");
    f.loop_count = get_u32("loop_count");
    let cc = get_u32("cyclomatic_complexity"); if cc > 0 { f.cyclomatic_complexity = cc; }
    let scc = get_u32("strongly_connected_components"); if scc > 0 { f.strongly_connected_components = scc; }
    f.callee_count = get_u32("callee_count");
    f.caller_count = get_u32("caller_count");
    f.entry_hash = get_u64("entry_hash");
    f.cfg_hash = get_u64("cfg_hash");
    f.byte_hash = get_u64("byte_hash");
    if let Some(arr) = v.get("string_refs").and_then(Value::as_array) {
        f.string_refs = arr.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect();
    }
    f
}

pub struct DiffBindiffFunctionFeaturesSimilarityTool;
impl DiffBindiffFunctionFeaturesSimilarityTool { #[must_use] pub fn definition() -> ToolDefinition {
    ToolDefinition { name: "diff_bindiff_function_features_similarity".to_string(),
        description: "FunctionFeatures::similarity via rustre_diff_bindiff.".to_string(),
        input_schema: json!({"type":"object","properties":{"a":{"type":"object"},"b":{"type":"object"}},"required":["a","b"]}),
        parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffFunctionFeaturesSimilarityTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = parse_bindiff_features_extra(args.get("a").ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?);
        let b = parse_bindiff_features_extra(args.get("b").ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?);
        Ok(ToolResult::text(json!({"score":a.similarity(&b),"source":"rustre_diff_bindiff::FunctionFeatures::similarity"}).to_string()))
    } }

pub struct DiffBindiffFunctionFeaturesCanMatchTool;
impl DiffBindiffFunctionFeaturesCanMatchTool { #[must_use] pub fn definition() -> ToolDefinition {
    ToolDefinition { name: "diff_bindiff_function_features_can_match".to_string(),
        description: "FunctionFeatures::can_match via rustre_diff_bindiff.".to_string(),
        input_schema: json!({"type":"object","properties":{"a":{"type":"object"},"b":{"type":"object"}},"required":["a","b"]}),
        parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffFunctionFeaturesCanMatchTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = parse_bindiff_features_extra(args.get("a").ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?);
        let b = parse_bindiff_features_extra(args.get("b").ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?);
        Ok(ToolResult::text(json!({"can_match":a.can_match(&b),"source":"rustre_diff_bindiff::FunctionFeatures::can_match"}).to_string()))
    } }

pub struct DiffBindiffDetailedSimilarityTool;
impl DiffBindiffDetailedSimilarityTool { #[must_use] pub fn definition() -> ToolDefinition {
    ToolDefinition { name: "diff_bindiff_detailed_similarity".to_string(),
        description: "BinDiffer::detailed_similarity via rustre_diff_bindiff.".to_string(),
        input_schema: json!({"type":"object","properties":{"a":{"type":"object"},"b":{"type":"object"},"min_similarity":{"type":"number"}},"required":["a","b"]}),
        parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffDetailedSimilarityTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let a = parse_bindiff_features_extra(args.get("a").ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?);
        let b = parse_bindiff_features_extra(args.get("b").ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?);
        let mut d = rustre_diff_bindiff::BinDiffer::new();
        if let Some(ms) = args.get("min_similarity").and_then(Value::as_f64) { d = d.with_min_similarity(ms as f32); }
        Ok(ToolResult::text(json!({"score":d.detailed_similarity(&a,&b),"source":"rustre_diff_bindiff::BinDiffer::detailed_similarity"}).to_string()))
    } }

pub struct DiffBindiffBinarySnapshotNewTool;
impl DiffBindiffBinarySnapshotNewTool { #[must_use] pub fn definition() -> ToolDefinition {
    ToolDefinition { name: "diff_bindiff_binary_snapshot_new".to_string(),
        description: "BinarySnapshot::new via rustre_diff_bindiff.".to_string(),
        input_schema: json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}),
        parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffBinarySnapshotNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let path = args.get("path").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'path'".into()))?;
        let s = rustre_diff_bindiff::BinarySnapshot::new(path);
        Ok(ToolResult::text(json!({"path":s.path,"function_count":s.function_count(),"call_edge_count":s.call_edge_count(),"source":"rustre_diff_bindiff::BinarySnapshot::new"}).to_string()))
    } }

pub struct DiffBindiffFunctionInfoFromFeaturesTool;
impl DiffBindiffFunctionInfoFromFeaturesTool { #[must_use] pub fn definition() -> ToolDefinition {
    ToolDefinition { name: "diff_bindiff_function_info_from_features".to_string(),
        description: "FunctionInfo::from(&FunctionFeatures) via rustre_diff_bindiff.".to_string(),
        input_schema: json!({"type":"object","properties":{"features":{"type":"object"}},"required":["features"]}),
        parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffFunctionInfoFromFeaturesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let feats = parse_bindiff_features_extra(args.get("features").ok_or_else(|| McpError::InvalidParams("missing 'features'".into()))?);
        let fi = rustre_diff_bindiff::FunctionInfo::from(&feats);
        Ok(ToolResult::text(json!({"address":fi.address,"bytes_crc32":fi.bytes_crc32,"in_edges":fi.in_edges,"out_edges":fi.out_edges,"bb_count":fi.bb_count,"md_index":fi.md_index,"source":"rustre_diff_bindiff::FunctionInfo::from"}).to_string()))
    } }

pub struct DiffBindiffBinDifferConfigureTool;
impl DiffBindiffBinDifferConfigureTool { #[must_use] pub fn definition() -> ToolDefinition {
    ToolDefinition { name: "diff_bindiff_bindiffer_configure".to_string(),
        description: "BinDiffer with_min_similarity + without_propagation via rustre_diff_bindiff.".to_string(),
        input_schema: json!({"type":"object","properties":{"min_similarity":{"type":"number"},"disable_propagation":{"type":"boolean"}}}),
        parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffBinDifferConfigureTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut d = rustre_diff_bindiff::BinDiffer::new();
        if let Some(ms) = args.get("min_similarity").and_then(Value::as_f64) { d = d.with_min_similarity(ms as f32); }
        if args.get("disable_propagation").and_then(Value::as_bool).unwrap_or(false) { d = d.without_propagation(); }
        Ok(ToolResult::text(json!({"min_similarity":d.min_similarity,"enable_propagation":d.enable_propagation,"max_candidates":d.max_candidates,"source":"rustre_diff_bindiff::BinDiffer"}).to_string()))
    } }

pub struct DiffBindiffMatchKindDisplayTool;
impl DiffBindiffMatchKindDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_match_kind_display".to_string(), description: "MatchKind Display via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{"kind":{"type":"string"}},"required":["kind"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffMatchKindDisplayTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let s = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'kind'".into()))?;
    let k = parse_match_kind_bindiff_extra(s).ok_or_else(|| McpError::InvalidParams(format!("unknown kind '{s}'")))?;
    Ok(ToolResult::text(json!({"kind":s,"display":k.to_string(),"source":"rustre_diff_bindiff::MatchKind Display"}).to_string()))
} }

pub struct DiffBindiffHungarianThresholdTool;
impl DiffBindiffHungarianThresholdTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_hungarian_threshold".to_string(), description: "HUNGARIAN_THRESHOLD constant via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffHungarianThresholdTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    Ok(ToolResult::text(json!({"threshold":rustre_diff_bindiff::HUNGARIAN_THRESHOLD,"source":"rustre_diff_bindiff::HUNGARIAN_THRESHOLD"}).to_string()))
} }

pub struct DiffBindiffFunctionInfoFlagsTool;
impl DiffBindiffFunctionInfoFlagsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_function_info_flags".to_string(), description: "FunctionInfo flags via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{"info":{"type":"object"}},"required":["info"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffFunctionInfoFlagsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let fi = parse_bindiff_function_info(args.get("info").ok_or_else(|| McpError::InvalidParams("missing 'info'".into()))?);
    Ok(ToolResult::text(json!({"has_byte_hash":fi.has_byte_hash(),"has_md_index":fi.has_md_index(),"has_name":fi.has_name(),"name_or_unnamed":fi.name_or_unnamed(),"debug_label":fi.debug_label(),"source":"rustre_diff_bindiff::FunctionInfo"}).to_string()))
} }

pub struct DiffBindiffFunctionInfoCanMatchTool;
impl DiffBindiffFunctionInfoCanMatchTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_function_info_can_match".to_string(), description: "FunctionInfo::can_match via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{"a":{"type":"object"},"b":{"type":"object"}},"required":["a","b"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffFunctionInfoCanMatchTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let a = parse_bindiff_function_info(args.get("a").ok_or_else(|| McpError::InvalidParams("missing 'a'".into()))?);
    let b = parse_bindiff_function_info(args.get("b").ok_or_else(|| McpError::InvalidParams("missing 'b'".into()))?);
    Ok(ToolResult::text(json!({"can_match":a.can_match(&b),"source":"rustre_diff_bindiff::FunctionInfo::can_match"}).to_string()))
} }

pub struct DiffBindiffHungarianSolveTool;
impl DiffBindiffHungarianSolveTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_hungarian_solve".to_string(), description: "HungarianSolver::new+solve+cost+validate via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{"cost_matrix":{"type":"array"}},"required":["cost_matrix"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffHungarianSolveTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let m = parse_bindiff_matrix(args.get("cost_matrix").ok_or_else(|| McpError::InvalidParams("missing 'cost_matrix'".into()))?)?;
    let solver = rustre_diff_bindiff::HungarianSolver::new(m);
    let assignment = solver.solve();
    let cost = solver.assignment_cost(&assignment);
    let valid = solver.validate_assignment(&assignment).is_ok();
    let pairs: Vec<Value> = assignment.iter().map(|(r,c)| json!({"row":r,"col":c})).collect();
    Ok(ToolResult::text(json!({"assignment":pairs,"total_cost":cost,"valid":valid,"original_cols":solver.original_cols(),"original_rows":solver.original_rows(),"source":"rustre_diff_bindiff::HungarianSolver"}).to_string()))
} }

pub struct DiffBindiffHungarianFromSimilarityTool;
impl DiffBindiffHungarianFromSimilarityTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_hungarian_from_similarity".to_string(), description: "HungarianSolver::from_similarity+solve_with_scores via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{"similarity_matrix":{"type":"array"},"original_rows":{"type":"integer"},"original_cols":{"type":"integer"},"min_similarity":{"type":"number"}},"required":["similarity_matrix"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffHungarianFromSimilarityTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let sm = parse_bindiff_matrix(args.get("similarity_matrix").ok_or_else(|| McpError::InvalidParams("missing 'similarity_matrix'".into()))?)?;
    let rows = args.get("original_rows").and_then(Value::as_u64).map(|n| n as usize).unwrap_or(sm.len());
    let cols = args.get("original_cols").and_then(Value::as_u64).map(|n| n as usize).unwrap_or(sm.first().map(|r| r.len()).unwrap_or(0));
    let thr = args.get("min_similarity").and_then(Value::as_f64).unwrap_or(0.0);
    let solver = rustre_diff_bindiff::HungarianSolver::from_similarity(sm);
    let scored = solver.solve_with_scores(rows, cols, thr);
    let count = scored.len();
    let pairs: Vec<Value> = scored.into_iter().map(|(r,c,s)| json!({"row":r,"col":c,"similarity":s})).collect();
    Ok(ToolResult::text(json!({"pairs":pairs,"count":count,"source":"rustre_diff_bindiff::HungarianSolver::from_similarity"}).to_string()))
} }

pub struct DiffBindiffMatchMatrixBuildTool;
impl DiffBindiffMatchMatrixBuildTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_match_matrix_build".to_string(), description: "MatchMatrix::build+rows+cols+best_pair via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{"funcs_a":{"type":"array"},"funcs_b":{"type":"array"}},"required":["funcs_a","funcs_b"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffMatchMatrixBuildTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let a = parse_bindiff_function_info_list(args.get("funcs_a").ok_or_else(|| McpError::InvalidParams("missing 'funcs_a'".into()))?)?;
    let b = parse_bindiff_function_info_list(args.get("funcs_b").ok_or_else(|| McpError::InvalidParams("missing 'funcs_b'".into()))?)?;
    let mm = rustre_diff_bindiff::MatchMatrix::build(&a, &b);
    let best = mm.best_pair().map(|(r,c,s)| json!({"row":r,"col":c,"similarity":s}));
    Ok(ToolResult::text(json!({"rows":mm.rows(),"cols":mm.cols(),"best_pair":best,"source":"rustre_diff_bindiff::MatchMatrix::build"}).to_string()))
} }

pub struct DiffBindiffMatchMatrixAboveThresholdTool;
impl DiffBindiffMatchMatrixAboveThresholdTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_match_matrix_above_threshold".to_string(), description: "MatchMatrix::above_threshold via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{"funcs_a":{"type":"array"},"funcs_b":{"type":"array"},"threshold":{"type":"number"}},"required":["funcs_a","funcs_b","threshold"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffMatchMatrixAboveThresholdTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let a = parse_bindiff_function_info_list(args.get("funcs_a").ok_or_else(|| McpError::InvalidParams("missing 'funcs_a'".into()))?)?;
    let b = parse_bindiff_function_info_list(args.get("funcs_b").ok_or_else(|| McpError::InvalidParams("missing 'funcs_b'".into()))?)?;
    let thr = args.get("threshold").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing 'threshold'".into()))?;
    let mm = rustre_diff_bindiff::MatchMatrix::build(&a, &b);
    let hits: Vec<Value> = mm.above_threshold(thr).into_iter().map(|(r,c,s)| json!({"row":r,"col":c,"similarity":s})).collect();
    Ok(ToolResult::text(json!({"count":hits.len(),"pairs":hits,"source":"rustre_diff_bindiff::MatchMatrix::above_threshold"}).to_string()))
} }

pub struct DiffBindiffMatchMatrixGreedyAssignTool;
impl DiffBindiffMatchMatrixGreedyAssignTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_match_matrix_greedy_assign".to_string(), description: "MatchMatrix::greedy_assign via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{"funcs_a":{"type":"array"},"funcs_b":{"type":"array"},"threshold":{"type":"number"}},"required":["funcs_a","funcs_b","threshold"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffMatchMatrixGreedyAssignTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let a = parse_bindiff_function_info_list(args.get("funcs_a").ok_or_else(|| McpError::InvalidParams("missing 'funcs_a'".into()))?)?;
    let b = parse_bindiff_function_info_list(args.get("funcs_b").ok_or_else(|| McpError::InvalidParams("missing 'funcs_b'".into()))?)?;
    let thr = args.get("threshold").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing 'threshold'".into()))?;
    let mm = rustre_diff_bindiff::MatchMatrix::build(&a, &b);
    let assign: Vec<Value> = mm.greedy_assign(thr).into_iter().map(|(r,c,s)| json!({"row":r,"col":c,"similarity":s})).collect();
    Ok(ToolResult::text(json!({"count":assign.len(),"pairs":assign,"source":"rustre_diff_bindiff::MatchMatrix::greedy_assign"}).to_string()))
} }

pub struct DiffBindiffMatchFunctionsHungarianTool;
impl DiffBindiffMatchFunctionsHungarianTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_match_functions_hungarian".to_string(), description: "match_functions_hungarian via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{"funcs_a":{"type":"array"},"funcs_b":{"type":"array"},"threshold":{"type":"number"}},"required":["funcs_a","funcs_b","threshold"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffMatchFunctionsHungarianTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let a = parse_bindiff_function_info_list(args.get("funcs_a").ok_or_else(|| McpError::InvalidParams("missing 'funcs_a'".into()))?)?;
    let b = parse_bindiff_function_info_list(args.get("funcs_b").ok_or_else(|| McpError::InvalidParams("missing 'funcs_b'".into()))?)?;
    let thr = args.get("threshold").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing 'threshold'".into()))?;
    let matches = rustre_diff_bindiff::match_functions_hungarian(&a, &b, thr);
    let out: Vec<Value> = matches.iter().map(|m| json!({"addr_a":m.address_a.as_u64(),"addr_b":m.address_b.as_u64(),"similarity":m.similarity,"confidence":m.confidence,"kind":m.kind.to_string(),"quality":m.quality_label()})).collect();
    Ok(ToolResult::text(json!({"count":out.len(),"matches":out,"source":"rustre_diff_bindiff::match_functions_hungarian"}).to_string()))
} }

pub struct DiffBindiffMatchFunctionsGreedyTool;
impl DiffBindiffMatchFunctionsGreedyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_match_functions_greedy".to_string(), description: "match_functions_greedy via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{"funcs_a":{"type":"array"},"funcs_b":{"type":"array"},"threshold":{"type":"number"}},"required":["funcs_a","funcs_b","threshold"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffMatchFunctionsGreedyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let a = parse_bindiff_function_info_list(args.get("funcs_a").ok_or_else(|| McpError::InvalidParams("missing 'funcs_a'".into()))?)?;
    let b = parse_bindiff_function_info_list(args.get("funcs_b").ok_or_else(|| McpError::InvalidParams("missing 'funcs_b'".into()))?)?;
    let thr = args.get("threshold").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing 'threshold'".into()))?;
    let matches = rustre_diff_bindiff::match_functions_greedy(&a, &b, thr);
    let out: Vec<Value> = matches.iter().map(|m| json!({"addr_a":m.address_a.as_u64(),"addr_b":m.address_b.as_u64(),"similarity":m.similarity,"confidence":m.confidence,"kind":m.kind.to_string(),"quality":m.quality_label()})).collect();
    Ok(ToolResult::text(json!({"count":out.len(),"matches":out,"source":"rustre_diff_bindiff::match_functions_greedy"}).to_string()))
} }

pub struct DiffBindiffBindiffEngineDefaultsTool;
impl DiffBindiffBindiffEngineDefaultsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_bindiff_engine_defaults".to_string(), description: "BindiffEngine::new + with_similar_threshold via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{"similar_threshold":{"type":"number"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffBindiffEngineDefaultsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let mut e = rustre_diff_bindiff::BindiffEngine::new();
    let default_thr = e.similar_threshold;
    if let Some(t) = args.get("similar_threshold").and_then(Value::as_f64) { e = e.with_similar_threshold(t as f32); }
    Ok(ToolResult::text(json!({"default_similar_threshold":default_thr,"similar_threshold":e.similar_threshold,"debug":format!("{e:?}"),"source":"rustre_diff_bindiff::BindiffEngine"}).to_string()))
} }

pub struct DiffBindiffFunctionMatchLifecycleTool;
impl DiffBindiffFunctionMatchLifecycleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_function_match_lifecycle".to_string(), description: "FunctionMatch::new + with_similarity + is_identical + is_good_match + quality_label via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{"addr_a":{"type":"integer"},"addr_b":{"type":"integer"},"similarity":{"type":"number"}},"required":["addr_a","addr_b","similarity"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffFunctionMatchLifecycleTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let a = args.get("addr_a").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing addr_a".into()))?;
    let b = args.get("addr_b").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing addr_b".into()))?;
    let sim = args.get("similarity").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing similarity".into()))? as f32;
    let m = rustre_diff_bindiff::FunctionMatch::new(rustre_core::address::Address::new(a), rustre_core::address::Address::new(b), rustre_diff_bindiff::MatchKind::Heuristic).with_similarity(sim);
    Ok(ToolResult::text(json!({"similarity":m.similarity,"is_identical":m.is_identical(),"is_good_match":m.is_good_match(),"quality":m.quality_label(),"source":"rustre_diff_bindiff::FunctionMatch"}).to_string()))
} }

pub struct DiffBindiffMatchKindSummaryTool;
impl DiffBindiffMatchKindSummaryTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_match_kind_summary".to_string(), description: "Enumerate all MatchKind variants with priority + is_reliable + Display via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffMatchKindSummaryTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    use rustre_diff_bindiff::MatchKind::*;
    let variants = [ExactHash, CfgHash, CallGraphPropagation, NameMatch, ManualMatch, Heuristic];
    let list: Vec<Value> = variants.iter().map(|k| json!({"name":k.to_string(),"priority":k.priority(),"is_reliable":k.is_reliable()})).collect();
    Ok(ToolResult::text(json!({"variants":list,"count":variants.len(),"source":"rustre_diff_bindiff::MatchKind"}).to_string()))
} }

pub struct DiffBindiffHungarianDimsTool;
impl DiffBindiffHungarianDimsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_hungarian_dims".to_string(), description: "HungarianSolver::original_rows + original_cols after padding via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{"cost_matrix":{"type":"array"}},"required":["cost_matrix"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffHungarianDimsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let rows_v = args.get("cost_matrix").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing cost_matrix".into()))?;
    if rows_v.is_empty() { return Err(McpError::InvalidParams("cost_matrix empty".into())); }
    let mut mat: Vec<Vec<f64>> = Vec::with_capacity(rows_v.len());
    for r in rows_v { let row = r.as_array().ok_or_else(|| McpError::InvalidParams("row not array".into()))?; let mut rv = Vec::with_capacity(row.len()); for c in row { rv.push(c.as_f64().unwrap_or(0.0)); } mat.push(rv); }
    let orig_rows = mat.len();
    let orig_cols = mat[0].len();
    let solver = rustre_diff_bindiff::HungarianSolver::new(mat);
    Ok(ToolResult::text(json!({"original_rows":solver.original_rows(),"original_cols":solver.original_cols(),"input_rows":orig_rows,"input_cols":orig_cols,"source":"rustre_diff_bindiff::HungarianSolver"}).to_string()))
} }

pub struct DiffBindiffBinarySnapshotCallGraphTool;
impl DiffBindiffBinarySnapshotCallGraphTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_binary_snapshot_call_graph".to_string(), description: "BinarySnapshot::new + add_function + add_call + function_count + call_edge_count + call_targets + callers_of via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{"path":{"type":"string"},"functions":{"type":"array"},"calls":{"type":"array"},"query":{"type":"integer"}},"required":["functions","calls","query"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffBinarySnapshotCallGraphTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let path = args.get("path").and_then(Value::as_str).unwrap_or("mem");
    let funcs = args.get("functions").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing functions".into()))?;
    let calls = args.get("calls").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing calls".into()))?;
    let query = args.get("query").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing query".into()))?;
    let mut snap = rustre_diff_bindiff::BinarySnapshot::new(path);
    for f in funcs { let a = f.as_u64().ok_or_else(|| McpError::InvalidParams("func addr".into()))?; snap.add_function(rustre_diff_bindiff::FunctionFeatures::new(rustre_core::address::Address::new(a))); }
    for c in calls { let pair = c.as_array().ok_or_else(|| McpError::InvalidParams("call pair".into()))?; if pair.len() != 2 { return Err(McpError::InvalidParams("pair len".into())); } snap.add_call(pair[0].as_u64().unwrap_or(0), pair[1].as_u64().unwrap_or(0)); }
    Ok(ToolResult::text(json!({"path":snap.path,"function_count":snap.function_count(),"call_edge_count":snap.call_edge_count(),"call_targets":snap.call_targets(query),"callers_of":snap.callers_of(query),"source":"rustre_diff_bindiff::BinarySnapshot"}).to_string()))
} }

pub struct DiffBindiffFunctionFeaturesDefaultTool;
impl DiffBindiffFunctionFeaturesDefaultTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_function_features_default".to_string(), description: "FunctionFeatures::new + self-similarity + can_match via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{"address":{"type":"integer"}},"required":["address"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffFunctionFeaturesDefaultTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let a = args.get("address").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing address".into()))?;
    let f = rustre_diff_bindiff::FunctionFeatures::new(rustre_core::address::Address::new(a));
    Ok(ToolResult::text(json!({"address":f.address.as_u64(),"basic_block_count":f.basic_block_count,"cyclomatic_complexity":f.cyclomatic_complexity,"self_similarity":f.similarity(&f),"can_match_self":f.can_match(&f),"source":"rustre_diff_bindiff::FunctionFeatures"}).to_string()))
} }

pub struct DiffBindiffBinDifferMinSimilarityTool;
impl DiffBindiffBinDifferMinSimilarityTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_bin_differ_min_similarity".to_string(), description: "BinDiffer::new + with_min_similarity via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{"min_similarity":{"type":"number"}},"required":["min_similarity"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffBinDifferMinSimilarityTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let s = args.get("min_similarity").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing min_similarity".into()))? as f32;
    let d = rustre_diff_bindiff::BinDiffer::new().with_min_similarity(s);
    Ok(ToolResult::text(json!({"min_similarity":d.min_similarity,"enable_propagation":d.enable_propagation,"max_candidates":d.max_candidates,"source":"rustre_diff_bindiff::BinDiffer"}).to_string()))
} }

pub struct DiffBindiffBinDifferPropagationToggleTool;
impl DiffBindiffBinDifferPropagationToggleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_bin_differ_propagation_toggle".to_string(), description: "BinDiffer::without_propagation via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffBinDifferPropagationToggleTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    let before = rustre_diff_bindiff::BinDiffer::new();
    let after = rustre_diff_bindiff::BinDiffer::new().without_propagation();
    Ok(ToolResult::text(json!({"before_propagation":before.enable_propagation,"after_propagation":after.enable_propagation,"source":"rustre_diff_bindiff::BinDiffer::without_propagation"}).to_string()))
} }

pub struct DiffBindiffCfgHasherCompareTool;
impl DiffBindiffCfgHasherCompareTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_cfg_hasher_compare".to_string(), description: "Compare CfgHasher::hash_linear vs hash_cfg on an equivalent linear chain via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{"block_count":{"type":"integer"}},"required":["block_count"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffCfgHasherCompareTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let n = args.get("block_count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing block_count".into()))?;
    let n_u32 = u32::try_from(n).map_err(|_| McpError::InvalidParams("block_count u32".into()))?;
    let linear = rustre_diff_bindiff::CfgHasher::hash_linear(n_u32);
    let adj: Vec<(u32, Vec<u32>)> = (0..n_u32).map(|i| (i, if i+1 < n_u32 { vec![i+1] } else { vec![] })).collect();
    let structural = rustre_diff_bindiff::CfgHasher::hash_cfg(&adj);
    Ok(ToolResult::text(json!({"block_count":n_u32,"hash_linear":linear,"hash_cfg":structural,"source":"rustre_diff_bindiff::CfgHasher"}).to_string()))
} }

pub struct DiffBindiffFunctionInfoSelfSimilarityTool;
impl DiffBindiffFunctionInfoSelfSimilarityTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_function_info_self_similarity".to_string(), description: "similarity_score(a, a) via rustre_diff_bindiff (self-consistency check).".to_string(), input_schema: json!({"type":"object","properties":{"info":{"type":"object"}},"required":["info"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffFunctionInfoSelfSimilarityTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
    let info = args.get("info").ok_or_else(|| McpError::InvalidParams("missing info".into()))?;
    let addr = info.get("address").and_then(Value::as_u64).unwrap_or(0);
    let mut fi = rustre_diff_bindiff::FunctionInfo::new(addr);
    fi.name = info.get("name").and_then(Value::as_str).map(String::from);
    fi.bytes_crc32 = info.get("bytes_crc32").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).unwrap_or(0);
    fi.in_edges = info.get("in_edges").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).unwrap_or(0);
    fi.out_edges = info.get("out_edges").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).unwrap_or(0);
    fi.bb_count = info.get("bb_count").and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok()).unwrap_or(0);
    fi.md_index = info.get("md_index").and_then(Value::as_u64).unwrap_or(0);
    let score = rustre_diff_bindiff::similarity_score(&fi, &fi);
    Ok(ToolResult::text(json!({"self_similarity":score,"address":fi.address,"source":"rustre_diff_bindiff::similarity_score"}).to_string()))
} }

pub struct DiffBindiffMatchKindPriorityOrderTool;
impl DiffBindiffMatchKindPriorityOrderTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_bindiff_match_kind_priority_order".to_string(), description: "Return all MatchKind variants sorted descending by priority via rustre_diff_bindiff.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for DiffBindiffMatchKindPriorityOrderTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
    use rustre_diff_bindiff::MatchKind::*;
    let mut v = vec![ExactHash, CfgHash, CallGraphPropagation, NameMatch, ManualMatch, Heuristic];
    v.sort_by(|a, b| b.priority().cmp(&a.priority()));
    let items: Vec<Value> = v.iter().map(|k| json!({"name":k.to_string(),"priority":k.priority()})).collect();
    Ok(ToolResult::text(json!({"ordered":items,"source":"rustre_diff_bindiff::MatchKind::priority"}).to_string()))
} }

pub struct DiffSemanticMinhashSignatureTool;

pub struct DiffSemanticMinhashEstimateJaccardTool;

pub struct DiffSemanticSignatureComputeTool;

pub struct DiffSimpleHashTool;

pub struct DiffLcsSimilarityTool;

pub struct DiffByteHistogramSimilarityTool;

pub struct DiffSemanticMatcherSimilarityTool;

pub struct DiffSemanticMatcherAreEquivalentTool;

pub struct DiffSemanticDifferDiffFunctionPairTool;

pub struct DiffNgramJaccardSimilarityTool;

pub struct DiffCombinedByteSimilarityTool;

pub struct DiffExportsTool;

pub struct DiffSemMinHashNewTool;
impl DiffSemMinHashNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_semantic_minhash_new_wire".to_string(), description: "MinHash::new returns num_hashes.".to_string(), input_schema: json!({"type":"object","properties":{"num_hashes":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DiffSemMinHashNewTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("num_hashes").and_then(Value::as_u64).unwrap_or(64) as usize; let mh = rustre_diff_semantic::MinHash::new(n); let sig = mh.signature(&[1u64,2,3]); Ok(ToolResult::text(json!({"len":sig.len(),"source":"rustre_diff_semantic::MinHash::new"}).to_string())) } }

pub struct DiffSemLshIndexNewTool;
impl DiffSemLshIndexNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_semantic_lsh_index_new_wire".to_string(), description: "LshIndex::new empty.".to_string(), input_schema: json!({"type":"object","properties":{"bands":{"type":"integer"},"rows":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DiffSemLshIndexNewTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let b = args.get("bands").and_then(Value::as_u64).unwrap_or(8) as usize; let r = args.get("rows").and_then(Value::as_u64).unwrap_or(4) as usize; let idx = rustre_diff_semantic::LshIndex::new(b, r); Ok(ToolResult::text(json!({"num_bands":idx.num_bands(),"rows_per_band":idx.rows_per_band(),"is_empty":idx.is_empty(),"len":idx.len(),"source":"rustre_diff_semantic::LshIndex::new"}).to_string())) } }

pub struct DiffSemLshInsertQueryTool;
impl DiffSemLshInsertQueryTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_semantic_lsh_insert_query_wire".to_string(), description: "LshIndex insert/query.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DiffSemLshInsertQueryTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut idx = rustre_diff_semantic::LshIndex::new(4, 2); let mh = rustre_diff_semantic::MinHash::new(8); let sig = mh.signature(&[1,2,3,4]); idx.insert(42, &sig); let cands = idx.query(&sig); Ok(ToolResult::text(json!({"len":idx.len(),"candidates":cands,"source":"rustre_diff_semantic::LshIndex::insert"}).to_string())) } }

pub struct DiffSemCallGraphNewTool;
impl DiffSemCallGraphNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_semantic_call_graph_new_wire".to_string(), description: "CallGraph add_function/add_call.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DiffSemCallGraphNewTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut g = rustre_diff_semantic::CallGraph::new(); g.add_function(0x1000); g.add_call(0x1000, 0x2000); g.add_call(0x1000, 0x3000); Ok(ToolResult::text(json!({"functions":g.function_count(),"calls":g.call_count(),"out_deg_1000":g.out_degree(0x1000),"in_deg_2000":g.in_degree(0x2000),"source":"rustre_diff_semantic::CallGraph::new"}).to_string())) } }

pub struct DiffSemCallGraphLeafRootTool;
impl DiffSemCallGraphLeafRootTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_semantic_call_graph_leaf_root_wire".to_string(), description: "CallGraph is_leaf/is_root.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DiffSemCallGraphLeafRootTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mut g = rustre_diff_semantic::CallGraph::new(); g.add_call(0x1000, 0x2000); Ok(ToolResult::text(json!({"root_1000":g.is_root(0x1000),"leaf_2000":g.is_leaf(0x2000),"callees_1000":g.callees(0x1000),"callers_2000":g.callers(0x2000),"source":"rustre_diff_semantic::CallGraph::is_leaf"}).to_string())) } }

pub struct DiffSemFnRenameHeuristicTool;
impl DiffSemFnRenameHeuristicTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_semantic_fn_rename_heuristic_wire".to_string(), description: "FunctionRenameHeuristic::new.".to_string(), input_schema: json!({"type":"object","properties":{"threshold":{"type":"number"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DiffSemFnRenameHeuristicTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let t = args.get("threshold").and_then(Value::as_f64).unwrap_or(0.8); let h = rustre_diff_semantic::FunctionRenameHeuristic::new(t); Ok(ToolResult::text(json!({"threshold":h.threshold,"source":"rustre_diff_semantic::FunctionRenameHeuristic::new"}).to_string())) } }

pub struct DiffSemSemDiffEngineNewTool;
impl DiffSemSemDiffEngineNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_semantic_diff_engine_new_wire".to_string(), description: "SemanticDiffEngine::new default.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DiffSemSemDiffEngineNewTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let _e = rustre_diff_semantic::SemanticDiffEngine::new(); Ok(ToolResult::text(json!({"ok":true,"source":"rustre_diff_semantic::SemanticDiffEngine::new"}).to_string())) } }

pub struct DiffSemBinarySemDiffNewTool;
impl DiffSemBinarySemDiffNewTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_semantic_binary_diff_new_wire".to_string(), description: "BinarySemanticDiff::with_params.".to_string(), input_schema: json!({"type":"object","properties":{"num_hashes":{"type":"integer"},"threshold":{"type":"number"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DiffSemBinarySemDiffNewTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("num_hashes").and_then(Value::as_u64).unwrap_or(64) as usize; let t = args.get("threshold").and_then(Value::as_f64).unwrap_or(0.8); let bsd = rustre_diff_semantic::BinarySemanticDiff::with_params(n, t); let empty: Vec<rustre_diff_semantic::SemanticFeatures> = vec![]; let (idx, sigs) = bsd.build_lsh_index(&empty); Ok(ToolResult::text(json!({"lsh_len":idx.len(),"sigs_len":sigs.len(),"source":"rustre_diff_semantic::BinarySemanticDiff::with_params"}).to_string())) } }

pub struct DiffSemSemFeaturesEmptyTool;
impl DiffSemSemFeaturesEmptyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_semantic_features_from_empty_wire".to_string(), description: "SemanticFeatures::from_instructions empty.".to_string(), input_schema: json!({"type":"object","properties":{"address":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DiffSemSemFeaturesEmptyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let addr = args.get("address").and_then(Value::as_u64).unwrap_or(0x1000); let f = rustre_diff_semantic::SemanticFeatures::from_instructions(addr, "empty".to_string(), &[]); Ok(ToolResult::text(json!({"address":f.address,"feature_count":f.feature_count(),"branch_count":f.branch_count,"loop_count":f.loop_count,"source":"rustre_diff_semantic::SemanticFeatures::from_instructions"}).to_string())) } }

pub struct DiffSemSemFeaturesSimilarityTool;
impl DiffSemSemFeaturesSimilarityTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_semantic_features_similarity_wire".to_string(), description: "SemanticFeatures::semantic_similarity self=1.0.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DiffSemSemFeaturesSimilarityTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let f = rustre_diff_semantic::SemanticFeatures::from_instructions(0x1000, "x".to_string(), &[]); let sim = f.semantic_similarity(&f); Ok(ToolResult::text(json!({"similarity":sim,"source":"rustre_diff_semantic::SemanticFeatures::semantic_similarity"}).to_string())) } }

pub struct DiffSemMinHashEmptyElementsTool;
impl DiffSemMinHashEmptyElementsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_semantic_minhash_empty_elements_wire".to_string(), description: "MinHash::signature on empty input.".to_string(), input_schema: json!({"type":"object","properties":{"num_hashes":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DiffSemMinHashEmptyElementsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("num_hashes").and_then(Value::as_u64).unwrap_or(32) as usize; let mh = rustre_diff_semantic::MinHash::new(n); let sig = mh.signature(&[]); let all_max = sig.iter().all(|&v| v == u64::MAX); Ok(ToolResult::text(json!({"len":sig.len(),"all_max":all_max,"source":"rustre_diff_semantic::MinHash::signature"}).to_string())) } }

pub struct DiffSemJaccardIdenticalTool;
impl DiffSemJaccardIdenticalTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "diff_semantic_jaccard_identical_wire".to_string(), description: "MinHash::estimate_jaccard on identical signatures.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for DiffSemJaccardIdenticalTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let mh = rustre_diff_semantic::MinHash::new(16); let sig = mh.signature(&[10u64,20,30,40,50]); let j = rustre_diff_semantic::MinHash::estimate_jaccard(&sig, &sig); Ok(ToolResult::text(json!({"jaccard":j,"len":sig.len(),"source":"rustre_diff_semantic::MinHash::estimate_jaccard"}).to_string())) } }

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (DiffBindiffCfgHashLinearTool::definition(), Box::new(DiffBindiffCfgHashLinearTool)),
        (DiffBindiffWlHashTool::definition(), Box::new(DiffBindiffWlHashTool)),
        (DiffBindiffSimilarityScoreTool::definition(), Box::new(DiffBindiffSimilarityScoreTool)),
        (DiffBindiffCfgHashTool::definition(), Box::new(DiffBindiffCfgHashTool)),
        (DiffBindiffJaccardBbScoreTool::definition(), Box::new(DiffBindiffJaccardBbScoreTool)),
        (DiffBindiffCfgSimilarityTool::definition(), Box::new(DiffBindiffCfgSimilarityTool)),
        (DiffBindiffMatchKindIsReliableTool::definition(), Box::new(DiffBindiffMatchKindIsReliableTool)),
        (DiffBindiffMatchKindPriorityTool::definition(), Box::new(DiffBindiffMatchKindPriorityTool)),
        (DiffBindiffFunctionInfoNewTool::definition(), Box::new(DiffBindiffFunctionInfoNewTool)),
        (DiffBindiffFunctionMatchQualityTool::definition(), Box::new(DiffBindiffFunctionMatchQualityTool)),
        (DiffBindiffBinDifferDefaultsTool::definition(), Box::new(DiffBindiffBinDifferDefaultsTool)),
        (DiffBindiffFunctionFeaturesSimilarityTool::definition(), Box::new(DiffBindiffFunctionFeaturesSimilarityTool)),
        (DiffBindiffFunctionFeaturesCanMatchTool::definition(), Box::new(DiffBindiffFunctionFeaturesCanMatchTool)),
        (DiffBindiffDetailedSimilarityTool::definition(), Box::new(DiffBindiffDetailedSimilarityTool)),
        (DiffBindiffBinarySnapshotNewTool::definition(), Box::new(DiffBindiffBinarySnapshotNewTool)),
        (DiffBindiffFunctionInfoFromFeaturesTool::definition(), Box::new(DiffBindiffFunctionInfoFromFeaturesTool)),
        (DiffBindiffBinDifferConfigureTool::definition(), Box::new(DiffBindiffBinDifferConfigureTool)),
        (DiffBindiffMatchKindDisplayTool::definition(), Box::new(DiffBindiffMatchKindDisplayTool)),
        (DiffBindiffHungarianThresholdTool::definition(), Box::new(DiffBindiffHungarianThresholdTool)),
        (DiffBindiffFunctionInfoFlagsTool::definition(), Box::new(DiffBindiffFunctionInfoFlagsTool)),
        (DiffBindiffFunctionInfoCanMatchTool::definition(), Box::new(DiffBindiffFunctionInfoCanMatchTool)),
        (DiffBindiffHungarianSolveTool::definition(), Box::new(DiffBindiffHungarianSolveTool)),
        (DiffBindiffHungarianFromSimilarityTool::definition(), Box::new(DiffBindiffHungarianFromSimilarityTool)),
        (DiffBindiffMatchMatrixBuildTool::definition(), Box::new(DiffBindiffMatchMatrixBuildTool)),
        (DiffBindiffMatchMatrixAboveThresholdTool::definition(), Box::new(DiffBindiffMatchMatrixAboveThresholdTool)),
        (DiffBindiffMatchMatrixGreedyAssignTool::definition(), Box::new(DiffBindiffMatchMatrixGreedyAssignTool)),
        (DiffBindiffMatchFunctionsHungarianTool::definition(), Box::new(DiffBindiffMatchFunctionsHungarianTool)),
        (DiffBindiffMatchFunctionsGreedyTool::definition(), Box::new(DiffBindiffMatchFunctionsGreedyTool)),
        (DiffBindiffBindiffEngineDefaultsTool::definition(), Box::new(DiffBindiffBindiffEngineDefaultsTool)),
        (DiffBindiffFunctionMatchLifecycleTool::definition(), Box::new(DiffBindiffFunctionMatchLifecycleTool)),
        (DiffBindiffMatchKindSummaryTool::definition(), Box::new(DiffBindiffMatchKindSummaryTool)),
        (DiffBindiffHungarianDimsTool::definition(), Box::new(DiffBindiffHungarianDimsTool)),
        (DiffBindiffBinarySnapshotCallGraphTool::definition(), Box::new(DiffBindiffBinarySnapshotCallGraphTool)),
        (DiffBindiffFunctionFeaturesDefaultTool::definition(), Box::new(DiffBindiffFunctionFeaturesDefaultTool)),
        (DiffBindiffBinDifferMinSimilarityTool::definition(), Box::new(DiffBindiffBinDifferMinSimilarityTool)),
        (DiffBindiffBinDifferPropagationToggleTool::definition(), Box::new(DiffBindiffBinDifferPropagationToggleTool)),
        (DiffBindiffCfgHasherCompareTool::definition(), Box::new(DiffBindiffCfgHasherCompareTool)),
        (DiffBindiffFunctionInfoSelfSimilarityTool::definition(), Box::new(DiffBindiffFunctionInfoSelfSimilarityTool)),
        (DiffBindiffMatchKindPriorityOrderTool::definition(), Box::new(DiffBindiffMatchKindPriorityOrderTool)),
        (DiffSemanticMinhashSignatureTool::definition(), Box::new(DiffSemanticMinhashSignatureTool)),
        (DiffSemanticMinhashEstimateJaccardTool::definition(), Box::new(DiffSemanticMinhashEstimateJaccardTool)),
        (DiffSemanticSignatureComputeTool::definition(), Box::new(DiffSemanticSignatureComputeTool)),
        (DiffSimpleHashTool::definition(), Box::new(DiffSimpleHashTool)),
        (DiffLcsSimilarityTool::definition(), Box::new(DiffLcsSimilarityTool)),
        (DiffByteHistogramSimilarityTool::definition(), Box::new(DiffByteHistogramSimilarityTool)),
        (DiffSemanticMatcherSimilarityTool::definition(), Box::new(DiffSemanticMatcherSimilarityTool)),
        (DiffSemanticMatcherAreEquivalentTool::definition(), Box::new(DiffSemanticMatcherAreEquivalentTool)),
        (DiffSemanticDifferDiffFunctionPairTool::definition(), Box::new(DiffSemanticDifferDiffFunctionPairTool)),
        (DiffNgramJaccardSimilarityTool::definition(), Box::new(DiffNgramJaccardSimilarityTool)),
        (DiffCombinedByteSimilarityTool::definition(), Box::new(DiffCombinedByteSimilarityTool)),
        (DiffExportsTool::definition(), Box::new(DiffExportsTool)),
        (DiffSemMinHashNewTool::definition(), Box::new(DiffSemMinHashNewTool)),
        (DiffSemLshIndexNewTool::definition(), Box::new(DiffSemLshIndexNewTool)),
        (DiffSemLshInsertQueryTool::definition(), Box::new(DiffSemLshInsertQueryTool)),
        (DiffSemCallGraphNewTool::definition(), Box::new(DiffSemCallGraphNewTool)),
        (DiffSemCallGraphLeafRootTool::definition(), Box::new(DiffSemCallGraphLeafRootTool)),
        (DiffSemFnRenameHeuristicTool::definition(), Box::new(DiffSemFnRenameHeuristicTool)),
        (DiffSemSemDiffEngineNewTool::definition(), Box::new(DiffSemSemDiffEngineNewTool)),
        (DiffSemBinarySemDiffNewTool::definition(), Box::new(DiffSemBinarySemDiffNewTool)),
        (DiffSemSemFeaturesEmptyTool::definition(), Box::new(DiffSemSemFeaturesEmptyTool)),
        (DiffSemSemFeaturesSimilarityTool::definition(), Box::new(DiffSemSemFeaturesSimilarityTool)),
        (DiffSemMinHashEmptyElementsTool::definition(), Box::new(DiffSemMinHashEmptyElementsTool)),
        (DiffSemJaccardIdenticalTool::definition(), Box::new(DiffSemJaccardIdenticalTool)),
    ]
}
