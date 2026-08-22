//! MCP wrappers for the rustre-triage_die crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::{args_to_bytes, hex_encode};
use crate::wire_tools::{extract_byte_array};

pub struct TriageDieComputeEntropyTool;
impl TriageDieComputeEntropyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_die_compute_entropy".to_string(),
            description: "Compute Shannon entropy (bits/byte) over arbitrary bytes.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex": { "type": "string" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageDieComputeEntropyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let e = rustre_triage_die::compute_entropy(&data);
        Ok(ToolResult::text(json!({ "entropy": e, "bytes": data.len() }).to_string()))
    }
}

pub struct TriageDieFindBytesTool;
impl TriageDieFindBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_die_find_bytes".to_string(),
            description: "Search a byte pattern (space-separated hex, ?? wildcard) in bytes.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex": { "type": "string" },
                    "pattern": { "type": "string" }
                },
                "required": ["pattern"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageDieFindBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let pat = args.get("pattern").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'pattern'".into()))?;
        let off = rustre_triage_die::find_bytes(&data, pat);
        Ok(ToolResult::text(json!({ "offset": off, "found": off.is_some() }).to_string()))
    }
}

pub struct TriageDieGetEntryPointBytesTool;
impl TriageDieGetEntryPointBytesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_die_get_entry_point_bytes".to_string(),
            description: "Return up to 16 raw bytes at the PE entry point.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex": { "type": "string" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageDieGetEntryPointBytesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let ep = rustre_triage_die::get_entry_point_bytes(&data);
        Ok(ToolResult::text(json!({ "hex": hex_encode(&ep), "len": ep.len() }).to_string()))
    }
}

pub struct TriageDieReadPeSectionsTool;
impl TriageDieReadPeSectionsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_die_read_pe_sections".to_string(),
            description: "Return PE section names and their Shannon entropy in section-table order.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex": { "type": "string" }
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageDieReadPeSectionsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let secs = rustre_triage_die::read_pe_sections(&data);
        let arr: Vec<Value> = secs.into_iter()
            .map(|(n, e)| json!({ "name": n, "entropy": e }))
            .collect();
        Ok(ToolResult::text(json!({ "sections": arr }).to_string()))
    }
}

pub struct TriageDieCheckImportsTool;
impl TriageDieCheckImportsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_die_check_imports".to_string(),
            description: "Check whether the PE imports `func` from `dll` (case-insensitive).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex": { "type": "string" },
                    "dll": { "type": "string" },
                    "func": { "type": "string" }
                },
                "required": ["dll", "func"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageDieCheckImportsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let dll = args.get("dll").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'dll'".into()))?;
        let func = args.get("func").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'func'".into()))?;
        let found = rustre_triage_die::check_imports(&data, dll, func);
        Ok(ToolResult::text(json!({ "found": found, "dll": dll, "func": func }).to_string()))
    }
}

pub struct TriageDieMatchRuleConditionTool;
impl TriageDieMatchRuleConditionTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "triage_die_match_rule_condition".to_string(),
            description: "Evaluate a RuleCondition (All/Any/Not of DieConditions) against bytes.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "bytes": { "type": "array", "items": { "type": "integer" } },
                    "hex": { "type": "string" },
                    "rule": { "type": "object", "description": "serde JSON of RuleCondition" }
                },
                "required": ["rule"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TriageDieMatchRuleConditionTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let data = args_to_bytes(&args)?;
        let rule_val = args.get("rule")
            .ok_or_else(|| McpError::InvalidParams("missing 'rule'".into()))?
            .clone();
        let rule: rustre_triage_die::RuleCondition = serde_json::from_value(rule_val)
            .map_err(|e| McpError::InvalidParams(format!("invalid rule: {e}")))?;
        let matched = rustre_triage_die::match_rule_condition(&rule, &data);
        Ok(ToolResult::text(json!({ "matched": matched }).to_string()))
    }
}

pub struct TriageDieComputeEntropyWireTool;

pub struct TriageDieFindBytesWireTool;

pub struct TriageDieHeuristicHasOverlayTool;
impl TriageDieHeuristicHasOverlayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_heuristic_has_overlay".to_string(), description: "rustre_triage_die::heuristic_detector::has_overlay.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieHeuristicHasOverlayTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let has = rustre_triage_die::heuristic_detector::has_overlay(&data); Ok(ToolResult::text(json!({"has_overlay":has,"len":data.len(),"source":"rustre_triage_die::heuristic_detector::has_overlay"}).to_string())) } }

pub struct TriageDieAnalyzeOverlayTool;
impl TriageDieAnalyzeOverlayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_analyze_overlay".to_string(), description: "rustre_triage_die::overlay_analyzer::analyze_overlay.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieAnalyzeOverlayTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let info = rustre_triage_die::overlay_analyzer::analyze_overlay(&data); Ok(ToolResult::text(json!({"offset":info.offset,"size":info.size,"entropy":info.entropy,"confidence":info.confidence,"has_overlay":info.has_overlay(),"likely_packed":info.likely_packed(),"hex_preview":info.hex_preview(),"source":"rustre_triage_die::overlay_analyzer::analyze_overlay"}).to_string())) } }

pub struct TriageDiePackerComputeEntropyTool;
impl TriageDiePackerComputeEntropyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_packer_compute_entropy".to_string(), description: "rustre_triage_die::packer_detector::compute_entropy.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDiePackerComputeEntropyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let e = rustre_triage_die::packer_detector::compute_entropy(&data); Ok(ToolResult::text(json!({"entropy":e,"len":data.len(),"source":"rustre_triage_die::packer_detector::compute_entropy"}).to_string())) } }

pub struct TriageDiePackerFullAnalysisTool;
impl TriageDiePackerFullAnalysisTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_packer_full_analysis".to_string(), description: "rustre_triage_die::packer_detector::full_analysis.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDiePackerFullAnalysisTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let rep = rustre_triage_die::packer_detector::full_analysis(&data); let max_conf = rep.max_confidence(); Ok(ToolResult::text(json!({"max_confidence":max_conf,"report":serde_json::to_value(&rep).unwrap_or(Value::Null),"source":"rustre_triage_die::packer_detector::full_analysis"}).to_string())) } }

pub struct TriageDieScanBytesTool;
impl TriageDieScanBytesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_engine_scan_bytes".to_string(), description: "rustre_triage_die::detector_engine::scan_bytes + format_report.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieScanBytesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let rep = rustre_triage_die::detector_engine::scan_bytes(&data); let text = rustre_triage_die::detector_engine::format_report(&rep); Ok(ToolResult::text(json!({"summary":rep.summary(),"is_packed":rep.is_packed(),"raw_matches":rep.raw_matches.len(),"elapsed_us":rep.elapsed_us,"report":text,"source":"rustre_triage_die::detector_engine::scan_bytes"}).to_string())) } }

pub struct TriageDieDetectVersionsTool;
impl TriageDieDetectVersionsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_detect_versions".to_string(), description: "rustre_triage_die::die_extended::detect_versions.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieDetectVersionsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let versions = rustre_triage_die::die_extended::detect_versions(&data); Ok(ToolResult::text(json!({"count":versions.len(),"versions":serde_json::to_value(&versions).unwrap_or(Value::Null),"source":"rustre_triage_die::die_extended::detect_versions"}).to_string())) } }

pub struct TriageDieCompilerDetectTool;
impl TriageDieCompilerDetectTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_compiler_detect".to_string(), description: "rustre_triage_die::compiler_detector::detect.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieCompilerDetectTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); match rustre_triage_die::compiler_detector::detect(&data) { Ok(r) => Ok(ToolResult::text(json!({"ok":true,"result":serde_json::to_value(&r).unwrap_or(Value::Null),"source":"rustre_triage_die::compiler_detector::detect"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"ok":false,"error":e.to_string(),"source":"rustre_triage_die::compiler_detector::detect"}).to_string())) } } }

pub struct TriageDieCompilerDetectWithThresholdTool;
impl TriageDieCompilerDetectWithThresholdTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_compiler_detect_with_threshold".to_string(), description: "rustre_triage_die::compiler_detector::detect_compiler(data, min_confidence).".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"min_confidence":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieCompilerDetectWithThresholdTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let min_c = args.get("min_confidence").and_then(Value::as_u64).unwrap_or(50).min(100) as u8; match rustre_triage_die::compiler_detector::detect_compiler(&data, min_c) { Ok(r) => Ok(ToolResult::text(json!({"ok":true,"min_confidence":min_c,"result":serde_json::to_value(&r).unwrap_or(Value::Null),"source":"rustre_triage_die::compiler_detector::detect_compiler"}).to_string())), Err(e) => Ok(ToolResult::text(json!({"ok":false,"min_confidence":min_c,"error":e.to_string(),"source":"rustre_triage_die::compiler_detector::detect_compiler"}).to_string())) } } }

pub struct TriageDieScannerScanTool;
impl TriageDieScannerScanTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_scanner_scan".to_string(), description: "rustre_triage_die::DieScanner::new().scan(data).".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieScannerScanTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let scanner = rustre_triage_die::DieScanner::new(); let dets = scanner.scan(&data); Ok(ToolResult::text(json!({"count":dets.len(),"detections":serde_json::to_value(&dets).unwrap_or(Value::Null),"source":"rustre_triage_die::DieScanner::scan"}).to_string())) } }

pub struct TriageDieMatchConditionSingleTool;
impl TriageDieMatchConditionSingleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_match_condition_single".to_string(), description: "rustre_triage_die::match_condition against a single DieCondition JSON.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"condition":{"type":"object"}},"required":["condition"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieMatchConditionSingleTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let cond_val = args.get("condition").cloned().ok_or_else(|| McpError::InvalidParams("missing 'condition'".to_string()))?; let cond: rustre_triage_die::DieCondition = serde_json::from_value(cond_val).map_err(|e| McpError::InvalidParams(format!("invalid DieCondition: {e}")))?; let m = rustre_triage_die::match_condition(&cond, &data); Ok(ToolResult::text(json!({"matched":m,"source":"rustre_triage_die::match_condition"}).to_string())) } }

pub struct TriageDieDetectorWithDefaultsDetectTool;
impl TriageDieDetectorWithDefaultsDetectTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_detector_with_defaults_detect".to_string(), description: "rustre_triage_die::DieDetector::with_defaults().detect(data).".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieDetectorWithDefaultsDetectTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let det = rustre_triage_die::DieDetector::with_defaults(); let r = det.detect(&data).map_err(|e| McpError::InternalError(e.to_string()))?; Ok(ToolResult::text(json!({"detections":r.detections.len(),"is_packed":r.is_packed,"is_protected":r.is_protected,"max_confidence":r.max_confidence(),"file_size":r.file_size,"source":"rustre_triage_die::DieDetector::detect"}).to_string())) } }

pub struct TriageDieDatabaseLoadDefaultsCountTool;
impl TriageDieDatabaseLoadDefaultsCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_database_load_defaults_count".to_string(), description: "rustre_triage_die::DieDatabase::load_defaults().rule_count().".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieDatabaseLoadDefaultsCountTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let db = rustre_triage_die::DieDatabase::load_defaults(); Ok(ToolResult::text(json!({"rule_count":db.rule_count(),"source":"rustre_triage_die::DieDatabase::load_defaults"}).to_string())) } }

pub struct TriageDieSignatureDatabaseScanTool;
impl TriageDieSignatureDatabaseScanTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_signature_database_scan".to_string(), description: "rustre_triage_die::DieSignatureDatabase::new().scan(data).".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieSignatureDatabaseScanTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let db = rustre_triage_die::DieSignatureDatabase::new(); let matches = db.scan(&data); let confident = matches.iter().filter(|m| m.is_confident()).count(); Ok(ToolResult::text(json!({"count":matches.len(),"confident":confident,"matches":serde_json::to_value(&matches).unwrap_or(Value::Null),"source":"rustre_triage_die::DieSignatureDatabase::scan"}).to_string())) } }

pub struct TriageDieSignatureDatabaseEntryCountTool;
impl TriageDieSignatureDatabaseEntryCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_signature_database_entry_count".to_string(), description: "rustre_triage_die::DieSignatureDatabase::new().entry_count().".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieSignatureDatabaseEntryCountTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let db = rustre_triage_die::DieSignatureDatabase::new(); Ok(ToolResult::text(json!({"entry_count":db.entry_count(),"source":"rustre_triage_die::DieSignatureDatabase::entry_count"}).to_string())) } }

pub struct TriageDieResultMaxConfidenceTool;
impl TriageDieResultMaxConfidenceTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_result_max_confidence".to_string(), description: "Run DieDetector::with_defaults().detect and return DieResult::max_confidence().".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieResultMaxConfidenceTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let det = rustre_triage_die::DieDetector::with_defaults(); let r = det.detect(&data).map_err(|e| McpError::InternalError(e.to_string()))?; Ok(ToolResult::text(json!({"max_confidence":r.max_confidence(),"total":r.detections.len(),"source":"rustre_triage_die::DieResult::max_confidence"}).to_string())) } }

pub struct TriageDieResultCategorizedTool;
impl TriageDieResultCategorizedTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_result_categorized".to_string(), description: "Return compilers/packers/protectors counts from DieDetector::detect.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieResultCategorizedTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let det = rustre_triage_die::DieDetector::with_defaults(); let r = det.detect(&data).map_err(|e| McpError::InternalError(e.to_string()))?; Ok(ToolResult::text(json!({"compilers":r.compilers().len(),"packers":r.packers().len(),"protectors":r.protectors().len(),"total":r.detections.len(),"source":"rustre_triage_die::DieResult"}).to_string())) } }

pub struct TriageDieBuiltinRulesYamlLenTool;
impl TriageDieBuiltinRulesYamlLenTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_builtin_rules_yaml_len".to_string(), description: "Length of the embedded rustre_triage_die::BUILTIN_RULES YAML.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieBuiltinRulesYamlLenTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let s = rustre_triage_die::BUILTIN_RULES; Ok(ToolResult::text(json!({"bytes":s.len(),"lines":s.lines().count(),"source":"rustre_triage_die::BUILTIN_RULES"}).to_string())) } }

pub struct TriageDieMatchRuleConditionSingleTool;
impl TriageDieMatchRuleConditionSingleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_match_rule_condition_single".to_string(), description: "rustre_triage_die::match_rule_condition against a single RuleCondition JSON.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"},"rule":{"type":"object"}},"required":["rule"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieMatchRuleConditionSingleTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let rc_val = args.get("rule").cloned().ok_or_else(|| McpError::InvalidParams("missing 'rule'".to_string()))?; let rc: rustre_triage_die::RuleCondition = serde_json::from_value(rc_val).map_err(|e| McpError::InvalidParams(format!("invalid RuleCondition: {e}")))?; let m = rustre_triage_die::match_rule_condition(&rc, &data); Ok(ToolResult::text(json!({"matched":m,"source":"rustre_triage_die::match_rule_condition"}).to_string())) } }

pub struct TriageDiePeSectionsWithEntropyTool;
impl TriageDiePeSectionsWithEntropyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_pe_sections_with_entropy".to_string(), description: "rustre_triage_die::read_pe_sections returning name+entropy pairs.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDiePeSectionsWithEntropyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let secs = rustre_triage_die::read_pe_sections(&data); let rows: Vec<_> = secs.iter().map(|(n,e)| json!({"name":n,"entropy":e})).collect(); Ok(ToolResult::text(json!({"count":secs.len(),"sections":rows,"source":"rustre_triage_die::read_pe_sections"}).to_string())) } }

pub struct TriageDieDetectFileKindTool;
impl TriageDieDetectFileKindTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_detect_file_kind".to_string(), description: "Detect file kind via DieDetector then report DieResult::file_kind.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieDetectFileKindTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let det = rustre_triage_die::DieDetector::with_defaults(); let r = det.detect(&data).map_err(|e| McpError::InternalError(e.to_string()))?; Ok(ToolResult::text(json!({"file_kind":format!("{:?}", r.file_kind),"file_size":r.file_size,"source":"rustre_triage_die::DieResult::file_kind"}).to_string())) } }

pub struct TriageDieDetectionListNamesTool;
impl TriageDieDetectionListNamesTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_detection_list_names".to_string(), description: "Return names+kinds of all DieDetector::with_defaults().detect() detections.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieDetectionListNamesTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let det = rustre_triage_die::DieDetector::with_defaults(); let r = det.detect(&data).map_err(|e| McpError::InternalError(e.to_string()))?; let rows: Vec<_> = r.detections.iter().map(|d| json!({"name":d.name,"kind":format!("{:?}",d.kind),"confidence":d.confidence,"version":d.version})).collect(); Ok(ToolResult::text(json!({"count":r.detections.len(),"items":rows,"source":"rustre_triage_die::DieDetector"}).to_string())) } }

pub struct TriageDieSignatureConfidentOnlyTool;
impl TriageDieSignatureConfidentOnlyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "triage_die_signature_confident_only".to_string(), description: "Return only DieMatchResult items where is_confident() is true.".to_string(), input_schema: json!({"type":"object","properties":{"bytes":{"type":"array","items":{"type":"integer"}},"hex":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TriageDieSignatureConfidentOnlyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let data = extract_byte_array(&args, "bytes", "hex").unwrap_or_default(); let db = rustre_triage_die::DieSignatureDatabase::new(); let matches = db.scan(&data); let confident: Vec<_> = matches.iter().filter(|m| m.is_confident()).cloned().collect(); Ok(ToolResult::text(json!({"count":confident.len(),"matches":serde_json::to_value(&confident).unwrap_or(Value::Null),"source":"rustre_triage_die::DieMatchResult::is_confident"}).to_string())) } }

#[must_use]
pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TriageDieComputeEntropyTool::definition(), Box::new(TriageDieComputeEntropyTool)),
        (TriageDieFindBytesTool::definition(), Box::new(TriageDieFindBytesTool)),
        (TriageDieGetEntryPointBytesTool::definition(), Box::new(TriageDieGetEntryPointBytesTool)),
        (TriageDieReadPeSectionsTool::definition(), Box::new(TriageDieReadPeSectionsTool)),
        (TriageDieCheckImportsTool::definition(), Box::new(TriageDieCheckImportsTool)),
        (TriageDieMatchRuleConditionTool::definition(), Box::new(TriageDieMatchRuleConditionTool)),
        (TriageDieComputeEntropyWireTool::definition(), Box::new(TriageDieComputeEntropyWireTool)),
        (TriageDieFindBytesWireTool::definition(), Box::new(TriageDieFindBytesWireTool)),
        (TriageDieHeuristicHasOverlayTool::definition(), Box::new(TriageDieHeuristicHasOverlayTool)),
        (TriageDieAnalyzeOverlayTool::definition(), Box::new(TriageDieAnalyzeOverlayTool)),
        (TriageDiePackerComputeEntropyTool::definition(), Box::new(TriageDiePackerComputeEntropyTool)),
        (TriageDiePackerFullAnalysisTool::definition(), Box::new(TriageDiePackerFullAnalysisTool)),
        (TriageDieScanBytesTool::definition(), Box::new(TriageDieScanBytesTool)),
        (TriageDieDetectVersionsTool::definition(), Box::new(TriageDieDetectVersionsTool)),
        (TriageDieCompilerDetectTool::definition(), Box::new(TriageDieCompilerDetectTool)),
        (TriageDieCompilerDetectWithThresholdTool::definition(), Box::new(TriageDieCompilerDetectWithThresholdTool)),
        (TriageDieScannerScanTool::definition(), Box::new(TriageDieScannerScanTool)),
        (TriageDieMatchConditionSingleTool::definition(), Box::new(TriageDieMatchConditionSingleTool)),
        (TriageDieDetectorWithDefaultsDetectTool::definition(), Box::new(TriageDieDetectorWithDefaultsDetectTool)),
        (TriageDieDatabaseLoadDefaultsCountTool::definition(), Box::new(TriageDieDatabaseLoadDefaultsCountTool)),
        (TriageDieSignatureDatabaseScanTool::definition(), Box::new(TriageDieSignatureDatabaseScanTool)),
        (TriageDieSignatureDatabaseEntryCountTool::definition(), Box::new(TriageDieSignatureDatabaseEntryCountTool)),
        (TriageDieResultMaxConfidenceTool::definition(), Box::new(TriageDieResultMaxConfidenceTool)),
        (TriageDieResultCategorizedTool::definition(), Box::new(TriageDieResultCategorizedTool)),
        (TriageDieBuiltinRulesYamlLenTool::definition(), Box::new(TriageDieBuiltinRulesYamlLenTool)),
        (TriageDieMatchRuleConditionSingleTool::definition(), Box::new(TriageDieMatchRuleConditionSingleTool)),
        (TriageDiePeSectionsWithEntropyTool::definition(), Box::new(TriageDiePeSectionsWithEntropyTool)),
        (TriageDieDetectFileKindTool::definition(), Box::new(TriageDieDetectFileKindTool)),
        (TriageDieDetectionListNamesTool::definition(), Box::new(TriageDieDetectionListNamesTool)),
        (TriageDieSignatureConfidentOnlyTool::definition(), Box::new(TriageDieSignatureConfidentOnlyTool)),
    ]
}
