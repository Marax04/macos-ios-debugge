//! MCP wrappers for the rustre-sandbox_report crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

// ─────────────────────────────────────────────────────────────────────────────
// Real report input
//
// ⚠ Why this exists. The five tools in this file took NO arguments and called
// `SandboxReport::mock()` / `IocSet::mock()`, then rendered the result as JSON,
// Markdown or HTML. The renderers were always real; the observations were
// invented. So `sandbox_report_mock_json` returned a verdict, a score and a
// malware family for a sample nobody had analysed.
//
// They now take the report itself. A report is `Serialize`/`Deserialize`, so a
// caller that ran an analysis can hand the result straight back for rendering,
// which is what a renderer is for.
// ─────────────────────────────────────────────────────────────────────────────

/// Deserialize the `report` argument, or the synthetic fixture on explicit
/// request.
///
/// # Errors
/// `InvalidParams` when `report` is absent and the fixture was not asked for;
/// `ToolError` when the value is not a valid `SandboxReport`.
fn report_from_args(
    args: &Value,
) -> Result<(rustre_sandbox_report::SandboxReport, bool), McpError> {
    if args.get("use_synthetic_fixture").and_then(Value::as_bool) == Some(true) {
        return Ok((rustre_sandbox_report::SandboxReport::mock(), true));
    }
    let raw = args.get("report").ok_or_else(|| {
        McpError::InvalidParams(
            "'report' is required: a SandboxReport object from a real analysis.              Pass \"use_synthetic_fixture\": true to render the built-in fixture instead;              its verdict is NOT an analysis result."
                .to_string(),
        )
    })?;
    let report: rustre_sandbox_report::SandboxReport = serde_json::from_value(raw.clone())
        .map_err(|e| McpError::ToolError(format!("'report' is not a SandboxReport: {e}")))?;
    Ok((report, false))
}

/// Deserialize the `iocs` argument, or the synthetic fixture on explicit request.
///
/// # Errors
/// As [`report_from_args`], for an `IocSet`.
fn ioc_set_from_args(args: &Value) -> Result<(rustre_sandbox_report::IocSet, bool), McpError> {
    if args.get("use_synthetic_fixture").and_then(Value::as_bool) == Some(true) {
        return Ok((rustre_sandbox_report::IocSet::mock(), true));
    }
    let raw = args.get("iocs").ok_or_else(|| {
        McpError::InvalidParams(
            "'iocs' is required: an IocSet from a real analysis. Pass              \"use_synthetic_fixture\": true to use the built-in fixture instead."
                .to_string(),
        )
    })?;
    let set: rustre_sandbox_report::IocSet = serde_json::from_value(raw.clone())
        .map_err(|e| McpError::ToolError(format!("'iocs' is not an IocSet: {e}")))?;
    Ok((set, false))
}

/// Schema for the report-rendering tools.
fn report_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "report": {"type": "object", "description": "A SandboxReport from a real analysis"},
            "use_synthetic_fixture": {"type": "boolean", "description": "Render the built-in fixture instead. Output is labelled is_synthetic_fixture and is NOT an analysis result."}
        },
        "required": ["report"]
    })
}

/// Schema for the IOC-set tool.
fn ioc_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "iocs": {"type": "object", "description": "An IocSet from a real analysis"},
            "use_synthetic_fixture": {"type": "boolean", "description": "Use the built-in fixture instead."}
        },
        "required": ["iocs"]
    })
}

pub struct SandboxReportMockSummaryTool;
impl SandboxReportMockSummaryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_mock_summary".to_string(),
            description: "Return summary of the mock SandboxReport (rustre_sandbox_report::SandboxReport::mock): verdict, score, family, indicator/behavior/ioc counts.".to_string(),
            input_schema: report_schema(),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportMockSummaryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (r, is_synthetic_fixture) = report_from_args(&args)?;
        Ok(ToolResult::text(json!({
            "sample": r.sample,
            "sha256": r.sha256,
            "verdict": r.verdict.to_string(),
            "score": r.score,
            "family": r.family,
            "indicator_count": r.indicators.len(),
            "behavior_count": r.behaviors.len(),
            "ioc_count": r.iocs.len(),
            "technique_count": r.attack.techniques.len(),
            "tags": r.tags,
            "is_synthetic_fixture": is_synthetic_fixture,
            "source": "rustre_sandbox_report::SandboxReport (supplied by the caller)",
        }).to_string()))
    }
}

pub struct SandboxReportIocSetMockTool;
impl SandboxReportIocSetMockTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_iocset_mock".to_string(),
            description: "Return mock IocSet with dedup + confidence stats (rustre_sandbox_report::IocSet::mock + deduplicate + confident).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "confidence_threshold": {"type": "integer"}
                }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportIocSetMockTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let threshold = args.get("confidence_threshold").and_then(Value::as_u64).unwrap_or(80) as u8;
        let (mut set, is_synthetic_fixture) = ioc_set_from_args(&args)?;
        let before = set.len();
        set.deduplicate();
        let after = set.len();
        let confident = set.confident(threshold).len();
        Ok(ToolResult::text(json!({
            "count_before_dedup": before,
            "count_after_dedup": after,
            "confident_count": confident,
            "threshold": threshold,
            "iocs": set.iocs.iter().map(|i| json!({
                "kind": i.kind.to_string(),
                "value": i.value,
                "confidence": i.confidence,
                "context": i.context,
            })).collect::<Vec<_>>(),
            "is_synthetic_fixture": is_synthetic_fixture,
            "source": "rustre_sandbox_report::IocSet (supplied by the caller)",
        }).to_string()))
    }
}

pub struct SandboxReportAttackMappingFromBehaviorsTool;
impl SandboxReportAttackMappingFromBehaviorsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_attack_mapping_from_behaviors".to_string(),
            description: "Build MITRE ATT&CK mapping from behavior tags (rustre_sandbox_report::AttackMapping::from_behaviors). Valid tags: injection, persistence, anti-analysis, c2, network, dropper, keylogger, ransomware, screenshot, worm.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "tags": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["tags"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportAttackMappingFromBehaviorsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let tags_v = args.get("tags").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'tags' array".into()))?;
        let tags: Vec<String> = tags_v.iter().filter_map(|v| v.as_str().map(String::from)).collect();
        let tag_refs: Vec<&str> = tags.iter().map(String::as_str).collect();
        let mapping = rustre_sandbox_report::AttackMapping::from_behaviors(&tag_refs);
        Ok(ToolResult::text(json!({
            "input_tags": tags,
            "technique_count": mapping.techniques.len(),
            "technique_ids": mapping.technique_ids(),
            "tactics_present": mapping.tactics_present(),
            "high_confidence_count": mapping.high_confidence().len(),
            "techniques": mapping.techniques.iter().map(|t| json!({
                "id": t.full_id(),
                "name": t.name,
                "tactic": t.tactic.to_string(),
                "confidence": t.confidence,
                "evidence": t.evidence,
            })).collect::<Vec<_>>(),
            "source": "rustre_sandbox_report::AttackMapping::from_behaviors",
        }).to_string()))
    }
}

pub struct SandboxReportMockMarkdownTool;
impl SandboxReportMockMarkdownTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_mock_markdown".to_string(),
            description: "Render the mock SandboxReport as Markdown via rustre_sandbox_report::SandboxReport::mock().to_markdown().".to_string(),
            input_schema: report_schema(),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportMockMarkdownTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let md = rustre_sandbox_report::SandboxReport::mock().to_markdown();
        Ok(ToolResult::text(json!({ "markdown": md }).to_string()))
    }
}

pub struct SandboxReportMockHtmlTool;
impl SandboxReportMockHtmlTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_mock_html".to_string(),
            description: "Render the mock SandboxReport as HTML via rustre_sandbox_report::SandboxReport::mock().to_html().".to_string(),
            input_schema: report_schema(),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportMockHtmlTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let html = rustre_sandbox_report::SandboxReport::mock().to_html();
        Ok(ToolResult::text(json!({ "html": html }).to_string()))
    }
}

pub struct SandboxReportClassifyApisTool;
impl SandboxReportClassifyApisTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_classify_apis".to_string(),
            description: "Return the count of API calls categorized by suspicious substring in the mock SandboxReport.".to_string(),
            input_schema: report_schema(),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportClassifyApisTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (r, _is_synthetic_fixture) = report_from_args(&args)?;
        let md = r.to_markdown();
        let suspicious_keywords = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "LoadLibrary", "GetProcAddress"];
        let matches: Vec<&str> = suspicious_keywords.iter().copied()
            .filter(|k| md.contains(k)).collect();
        Ok(ToolResult::text(json!({ "suspicious_apis": matches, "count": matches.len() }).to_string()))
    }
}

pub struct SandboxReportSeverityParseTool;
impl SandboxReportSeverityParseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_severity_parse".to_string(),
            description: "Parse a severity string (info|low|medium|high|critical) via rustre_sandbox_report::Severity::parse and return its numeric score.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "severity": {"type": "string"} },
                "required": ["severity"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportSeverityParseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("severity").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'severity' string".into()))?;
        let sev = rustre_sandbox_report::Severity::parse(s)
            .map_err(|e| McpError::InvalidParams(format!("parse severity: {e}")))?;
        Ok(ToolResult::text(json!({
            "input": s,
            "severity": sev.to_string(),
            "score": sev.score(),
            "source": "rustre_sandbox_report::Severity::parse",
        }).to_string()))
    }
}

pub struct SandboxReportScoreEngineComputeTool;
impl SandboxReportScoreEngineComputeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_score_engine_compute".to_string(),
            description: "Run rustre_sandbox_report::ScoreEngine::compute + verdict on the mock SandboxReport indicators.".to_string(),
            input_schema: report_schema(),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportScoreEngineComputeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (r, _is_synthetic_fixture) = report_from_args(&args)?;
        let engine = rustre_sandbox_report::ScoreEngine::new();
        let score = engine.compute(&r.indicators);
        let verdict = engine.verdict(score);
        let has_critical = rustre_sandbox_report::ScoreEngine::has_critical(&r.indicators);
        Ok(ToolResult::text(json!({
            "indicator_count": r.indicators.len(),
            "score": score,
            "verdict": verdict.to_string(),
            "has_critical": has_critical,
            "source": "rustre_sandbox_report::ScoreEngine::compute",
        }).to_string()))
    }
}

pub struct SandboxReportCriticalIndicatorsTool;
impl SandboxReportCriticalIndicatorsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_critical_indicators".to_string(),
            description: "Return the critical-severity indicators of the mock SandboxReport (rustre_sandbox_report::SandboxReport::critical_indicators).".to_string(),
            input_schema: report_schema(),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportCriticalIndicatorsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (r, _is_synthetic_fixture) = report_from_args(&args)?;
        let crits = r.critical_indicators();
        let items: Vec<Value> = crits.iter().map(|i| json!({
            "name": i.name,
            "desc": i.desc,
            "category": i.category.to_string(),
            "severity": i.severity.to_string(),
            "technique_ids": i.technique_ids,
        })).collect();
        Ok(ToolResult::text(json!({
            "count": items.len(),
            "critical_indicators": items,
            "source": "rustre_sandbox_report::SandboxReport::critical_indicators",
        }).to_string()))
    }
}

pub struct SandboxReportSeverityScoreTool;

pub struct SandboxReportIocIsConfidentTool;

pub struct SandboxReportIocSetByKindTool;
impl SandboxReportIocSetByKindTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_iocset_by_kind".to_string(),
            description: "Filter mock IocSet by kind via IocSet::by_kind.".to_string(),
            input_schema: json!({"type":"object","properties":{"kind":{"type":"string"}},"required":["kind"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportIocSetByKindTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_sandbox_report::IocKind;
        let k = args.get("kind").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'kind'".to_string()))?;
        let kind = match k.to_ascii_lowercase().as_str() {
            "ip" => IocKind::Ip, "domain" => IocKind::Domain, "url" => IocKind::Url,
            "filepath" => IocKind::FilePath, "filehash" => IocKind::FileHash,
            "registry_key" => IocKind::RegistryKey, "mutex" => IocKind::Mutex,
            "email" => IocKind::Email, other => IocKind::Other(other.to_string()),
        };
        let set = rustre_sandbox_report::IocSet::mock();
        let matches: Vec<_> = set.by_kind(&kind).into_iter().map(|i| json!({
            "kind": i.kind.to_string(), "value": i.value, "confidence": i.confidence
        })).collect();
        Ok(ToolResult::text(json!({"count": matches.len(), "iocs": matches, "source":"rustre_sandbox_report::IocSet::by_kind"}).to_string()))
    }
}

pub struct SandboxReportIocSetConfidentTool;
impl SandboxReportIocSetConfidentTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_iocset_confident".to_string(),
            description: "IOCs from mock set with confidence >= threshold.".to_string(),
            input_schema: json!({"type":"object","properties":{"threshold":{"type":"integer"}},"required":["threshold"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportIocSetConfidentTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let t = args.get("threshold").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'threshold'".into()))? as u8;
        let set = rustre_sandbox_report::IocSet::mock();
        let out: Vec<_> = set.confident(t).into_iter().map(|i| json!({
            "kind": i.kind.to_string(), "value": i.value, "confidence": i.confidence
        })).collect();
        Ok(ToolResult::text(json!({"count": out.len(), "iocs": out, "source":"rustre_sandbox_report::IocSet::confident"}).to_string()))
    }
}

pub struct SandboxReportIocSetDedupTool;
impl SandboxReportIocSetDedupTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_iocset_deduplicate".to_string(),
            description: "Deduplicate mock IocSet and report before/after counts.".to_string(),
            input_schema: ioc_schema(),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportIocSetDedupTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (mut set, _is_synthetic_fixture) = ioc_set_from_args(&args)?;
        set.add(rustre_sandbox_report::Ioc::new(rustre_sandbox_report::IocKind::Ip, "185.220.101.1", 95, "dup"));
        let before = set.len();
        set.deduplicate();
        Ok(ToolResult::text(json!({"before": before, "after": set.len(), "source":"rustre_sandbox_report::IocSet::deduplicate"}).to_string()))
    }
}

pub struct SandboxReportAttackTacticsPresentTool;
impl SandboxReportAttackTacticsPresentTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_attack_tactics_present".to_string(),
            description: "ATT&CK tactics present for behavior tags.".to_string(),
            input_schema: json!({"type":"object","properties":{"tags":{"type":"array","items":{"type":"string"}}},"required":["tags"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportAttackTacticsPresentTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let tags: Vec<String> = args.get("tags").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
        let m = rustre_sandbox_report::AttackMapping::from_behaviors(&refs);
        let ids: Vec<String> = m.technique_ids().into_iter().map(String::from).collect();
        Ok(ToolResult::text(json!({"tactics": m.tactics_present(), "technique_ids": ids, "source":"rustre_sandbox_report::AttackMapping::tactics_present"}).to_string()))
    }
}

pub struct SandboxReportAttackHighConfidenceTool;
impl SandboxReportAttackHighConfidenceTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_attack_high_confidence".to_string(),
            description: "High-confidence (>=80) ATT&CK techniques from behavior tags.".to_string(),
            input_schema: json!({"type":"object","properties":{"tags":{"type":"array","items":{"type":"string"}}},"required":["tags"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportAttackHighConfidenceTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let tags: Vec<String> = args.get("tags").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
        let m = rustre_sandbox_report::AttackMapping::from_behaviors(&refs);
        let hc: Vec<_> = m.high_confidence().into_iter().map(|t| json!({
            "id": t.full_id(), "name": t.name, "tactic": t.tactic.to_string(), "confidence": t.confidence
        })).collect();
        Ok(ToolResult::text(json!({"count": hc.len(), "techniques": hc, "source":"rustre_sandbox_report::AttackMapping::high_confidence"}).to_string()))
    }
}

pub struct SandboxReportScoreEngineVerdictTool;
impl SandboxReportScoreEngineVerdictTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_score_engine_verdict".to_string(),
            description: "Map numeric score to Verdict via ScoreEngine::verdict.".to_string(),
            input_schema: json!({"type":"object","properties":{"score":{"type":"integer"}},"required":["score"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportScoreEngineVerdictTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let s = args.get("score").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'score'".into()))? as u32;
        let engine = rustre_sandbox_report::ScoreEngine::new();
        let v = engine.verdict(s);
        Ok(ToolResult::text(json!({"score": s, "verdict": v.to_string(), "source":"rustre_sandbox_report::ScoreEngine::verdict"}).to_string()))
    }
}

pub struct SandboxReportBehaviorClassifyTool;
impl SandboxReportBehaviorClassifyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_behavior_classify".to_string(),
            description: "Classify Windows API names into indicators and behaviors.".to_string(),
            input_schema: json!({"type":"object","properties":{"apis":{"type":"array","items":{"type":"string"}}},"required":["apis"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportBehaviorClassifyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let apis: Vec<String> = args.get("apis").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        let refs: Vec<&str> = apis.iter().map(String::as_str).collect();
        let (inds, behs) = rustre_sandbox_report::BehaviorClassifier::new().classify(&refs);
        let inds_json: Vec<_> = inds.iter().map(|i| json!({"name": i.name, "severity": i.severity.to_string(), "category": i.category.to_string()})).collect();
        let behs_json: Vec<_> = behs.iter().map(|b| json!({"name": b.name, "severity": b.severity.to_string(), "category": b.category})).collect();
        Ok(ToolResult::text(json!({"indicators": inds_json, "behaviors": behs_json, "source":"rustre_sandbox_report::BehaviorClassifier::classify"}).to_string()))
    }
}

pub struct SandboxReportInferFamilyTool;
impl SandboxReportInferFamilyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_infer_family".to_string(),
            description: "Infer malware family from API calls.".to_string(),
            input_schema: json!({"type":"object","properties":{"apis":{"type":"array","items":{"type":"string"}}},"required":["apis"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportInferFamilyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let apis: Vec<String> = args.get("apis").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        let refs: Vec<&str> = apis.iter().map(String::as_str).collect();
        let (inds, _) = rustre_sandbox_report::BehaviorClassifier::new().classify(&refs);
        let family = rustre_sandbox_report::BehaviorClassifier::infer_family(&inds);
        Ok(ToolResult::text(json!({"family": family, "indicator_count": inds.len(), "source":"rustre_sandbox_report::BehaviorClassifier::infer_family"}).to_string()))
    }
}

pub struct SandboxReportMockJsonTool;
impl SandboxReportMockJsonTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_mock_json".to_string(),
            description: "Return mock SandboxReport JSON length and top metrics.".to_string(),
            input_schema: report_schema(),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportMockJsonTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (r, _is_synthetic_fixture) = report_from_args(&args)?;
        let s = r.to_json().map_err(|e| McpError::InternalError(e.to_string()))?;
        Ok(ToolResult::text(json!({"json_len": s.len(), "verdict": r.verdict.to_string(), "score": r.score, "source":"rustre_sandbox_report::SandboxReport::to_json"}).to_string()))
    }
}

pub struct SandboxReportFormatExtensionTool;
impl SandboxReportFormatExtensionTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_format_extension".to_string(),
            description: "File extension for a report format (json/html/pdf/csv/markdown).".to_string(),
            input_schema: json!({"type":"object","properties":{"format":{"type":"string"}},"required":["format"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportFormatExtensionTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let f = args.get("format").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'format'".to_string()))?;
        let fmt = rustre_sandbox_report::ReportFormat::from_extension(f)
            .map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({"format": fmt.to_string(), "extension": fmt.extension(), "source":"rustre_sandbox_report::ReportFormat::extension"}).to_string()))
    }
}

pub struct SandboxReportIndicatorsByCategoryTool;
impl SandboxReportIndicatorsByCategoryTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "sandbox_report_indicators_by_category".to_string(),
            description: "Filter mock SandboxReport indicators by category.".to_string(),
            input_schema: json!({"type":"object","properties":{"category":{"type":"string"}},"required":["category"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for SandboxReportIndicatorsByCategoryTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_sandbox_report::IndicatorCategory;
        let c = args.get("category").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'category'".to_string()))?;
        let cat = match c.to_ascii_lowercase().as_str() {
            "injection" => IndicatorCategory::Injection,
            "network" => IndicatorCategory::Network,
            "persistence" => IndicatorCategory::Persistence,
            "evasion" => IndicatorCategory::Evasion,
            "crypto" => IndicatorCategory::Crypto,
            "dropper" => IndicatorCategory::Dropper,
            "keylogging" => IndicatorCategory::Keylogging,
            "ransomware" => IndicatorCategory::Ransomware,
            "reconnaissance" => IndicatorCategory::Reconnaissance,
            _ => IndicatorCategory::Other,
        };
        let (r, _is_synthetic_fixture) = report_from_args(&args)?;
        let out: Vec<_> = r.indicators_by_category(&cat).into_iter().map(|i| json!({
            "name": i.name, "severity": i.severity.to_string(), "desc": i.desc
        })).collect();
        Ok(ToolResult::text(json!({"count": out.len(), "indicators": out, "source":"rustre_sandbox_report::SandboxReport::indicators_by_category"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (SandboxReportMockSummaryTool::definition(), Box::new(SandboxReportMockSummaryTool)),
        (SandboxReportIocSetMockTool::definition(), Box::new(SandboxReportIocSetMockTool)),
        (SandboxReportAttackMappingFromBehaviorsTool::definition(), Box::new(SandboxReportAttackMappingFromBehaviorsTool)),
        (SandboxReportMockMarkdownTool::definition(), Box::new(SandboxReportMockMarkdownTool)),
        (SandboxReportMockHtmlTool::definition(), Box::new(SandboxReportMockHtmlTool)),
        (SandboxReportClassifyApisTool::definition(), Box::new(SandboxReportClassifyApisTool)),
        (SandboxReportSeverityParseTool::definition(), Box::new(SandboxReportSeverityParseTool)),
        (SandboxReportScoreEngineComputeTool::definition(), Box::new(SandboxReportScoreEngineComputeTool)),
        (SandboxReportCriticalIndicatorsTool::definition(), Box::new(SandboxReportCriticalIndicatorsTool)),
        (SandboxReportSeverityScoreTool::definition(), Box::new(SandboxReportSeverityScoreTool)),
        (SandboxReportIocIsConfidentTool::definition(), Box::new(SandboxReportIocIsConfidentTool)),
        (SandboxReportIocSetByKindTool::definition(), Box::new(SandboxReportIocSetByKindTool)),
        (SandboxReportIocSetConfidentTool::definition(), Box::new(SandboxReportIocSetConfidentTool)),
        (SandboxReportIocSetDedupTool::definition(), Box::new(SandboxReportIocSetDedupTool)),
        (SandboxReportAttackTacticsPresentTool::definition(), Box::new(SandboxReportAttackTacticsPresentTool)),
        (SandboxReportAttackHighConfidenceTool::definition(), Box::new(SandboxReportAttackHighConfidenceTool)),
        (SandboxReportScoreEngineVerdictTool::definition(), Box::new(SandboxReportScoreEngineVerdictTool)),
        (SandboxReportBehaviorClassifyTool::definition(), Box::new(SandboxReportBehaviorClassifyTool)),
        (SandboxReportInferFamilyTool::definition(), Box::new(SandboxReportInferFamilyTool)),
        (SandboxReportMockJsonTool::definition(), Box::new(SandboxReportMockJsonTool)),
        (SandboxReportFormatExtensionTool::definition(), Box::new(SandboxReportFormatExtensionTool)),
        (SandboxReportIndicatorsByCategoryTool::definition(), Box::new(SandboxReportIndicatorsByCategoryTool)),
    ]
}
