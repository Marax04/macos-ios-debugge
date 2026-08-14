//! MCP wrappers for the rustre-ti_vt crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct TiVtMockFileReportTool;
impl TiVtMockFileReportTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_vt_mock_file_report".to_string(),
            description: "Build a mock VirusTotal file report for the given SHA-256.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "sha256": {"type": "string"} },
                "required": ["sha256"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiVtMockFileReportTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let sha256 = args.get("sha256").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'sha256'".into()))?;
        let report = rustre_ti_vt::mock_file_report(sha256);
        Ok(ToolResult::text(serde_json::to_string(&report)
            .map_err(|e| McpError::InternalError(e.to_string()))?))
    }
}

pub struct TiVtMockIpReportTool;
impl TiVtMockIpReportTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_vt_mock_ip_report".to_string(),
            description: "Build a mock VirusTotal IP address report for the given IP.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "ip": {"type": "string"} },
                "required": ["ip"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiVtMockIpReportTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ip = args.get("ip").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'ip'".into()))?;
        let report = rustre_ti_vt::mock_ip_report(ip);
        Ok(ToolResult::text(serde_json::to_string(&report)
            .map_err(|e| McpError::InternalError(e.to_string()))?))
    }
}

pub struct TiVtParseSearchResponseTool;
impl TiVtParseSearchResponseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_vt_parse_search_response".to_string(),
            description: "Parse a VirusTotal Intelligence search response JSON string.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "json": {"type": "string"} },
                "required": ["json"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiVtParseSearchResponseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let text = args.get("json").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'json'".into()))?;
        let resp = rustre_ti_vt::vt_intelligence_search::parse_search_response(text);
        Ok(ToolResult::text(json!({
            "results_count": resp.results.len(),
            "cursor": resp.cursor,
            "total_hits": resp.total_hits,
            "has_next_page": resp.has_next_page(),
        }).to_string()))
    }
}

pub struct TiVtApiKeyIsValidTool;
impl TiVtApiKeyIsValidTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_vt_api_key_is_valid".to_string(),
            description: "Return true if the provided string is a syntactically valid VirusTotal API key (64 hex chars).".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "key": {"type": "string"} },
                "required": ["key"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiVtApiKeyIsValidTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let key = args.get("key").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'key'".into()))?;
        let k = rustre_ti_vt::VtApiKey::public(key.to_string());
        Ok(ToolResult::text(json!({ "is_valid": k.is_valid() }).to_string()))
    }
}

pub struct TiVtAnalysisStatsDetectionRatioTool;
impl TiVtAnalysisStatsDetectionRatioTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_vt_analysis_stats_detection_ratio".to_string(),
            description: "Compute detection ratio string 'malicious/total' from VtAnalysisStats counts.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "malicious": {"type": "integer", "minimum": 0},
                    "suspicious": {"type": "integer", "minimum": 0},
                    "undetected": {"type": "integer", "minimum": 0},
                    "harmless": {"type": "integer", "minimum": 0}
                },
                "required": ["malicious"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiVtAnalysisStatsDetectionRatioTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let get = |k: &str| args.get(k).and_then(Value::as_u64).unwrap_or(0) as u32;
        let stats = rustre_ti_vt::VtAnalysisStats {
            malicious: get("malicious"),
            suspicious: get("suspicious"),
            undetected: get("undetected"),
            harmless: get("harmless"),
            ..Default::default()
        };
        Ok(ToolResult::text(json!({
            "ratio": stats.detection_ratio(),
            "total": stats.total(),
        }).to_string()))
    }
}

pub struct TiVtAvResultClassifyTool;
impl TiVtAvResultClassifyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_vt_av_result_classify".to_string(), description: "Classify a VT per-engine AV result by category (malicious/suspicious).".to_string(), input_schema: json!({"type":"object","required":["category","engine_name"],"properties":{"category":{"type":"string"},"engine_name":{"type":"string"},"result":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiVtAvResultClassifyTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let category = args.get("category").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("category".into()))?.to_string(); let engine_name = args.get("engine_name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("engine_name".into()))?.to_string(); let r = rustre_ti_vt::VtAVResult { category, engine_name, engine_version: None, engine_update: None, result: args.get("result").and_then(Value::as_str).map(String::from), method: None }; Ok(ToolResult::text(json!({"is_malicious": r.is_malicious(), "is_suspicious": r.is_suspicious()}).to_string())) } }

pub struct TiVtAnalysisStatsTotalTool;
impl TiVtAnalysisStatsTotalTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_vt_analysis_stats_total".to_string(), description: "Return the total engine count for a VtAnalysisStats.".to_string(), input_schema: json!({"type":"object","properties":{"malicious":{"type":"integer"},"suspicious":{"type":"integer"},"undetected":{"type":"integer"},"harmless":{"type":"integer"},"timeout":{"type":"integer"},"failure":{"type":"integer"},"type_unsupported":{"type":"integer"},"confirmed_timeout":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiVtAnalysisStatsTotalTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let get = |k: &str| args.get(k).and_then(Value::as_u64).unwrap_or(0) as u32; let s = rustre_ti_vt::VtAnalysisStats { malicious: get("malicious"), suspicious: get("suspicious"), undetected: get("undetected"), harmless: get("harmless"), timeout: get("timeout"), failure: get("failure"), type_unsupported: get("type_unsupported"), confirmed_timeout: get("confirmed_timeout") }; Ok(ToolResult::text(json!({"total": s.total()}).to_string())) } }

pub struct TiVtIpReportSpecIsMaliciousTool;
impl TiVtIpReportSpecIsMaliciousTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_vt_ip_report_spec_is_malicious".to_string(), description: "Return true if VtIpReportSpec has any malicious counts.".to_string(), input_schema: json!({"type":"object","required":["ip"],"properties":{"ip":{"type":"string"},"malicious_count":{"type":"integer"},"suspicious_count":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiVtIpReportSpecIsMaliciousTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ip = args.get("ip").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("ip".into()))?.to_string(); let r = rustre_ti_vt::VtIpReportSpec { ip_address: ip, country: None, as_owner: None, malicious_count: args.get("malicious_count").and_then(Value::as_u64).unwrap_or(0) as u32, suspicious_count: args.get("suspicious_count").and_then(Value::as_u64).unwrap_or(0) as u32 }; Ok(ToolResult::text(json!({"is_malicious": r.is_malicious()}).to_string())) } }

pub struct TiVtFileReportSpecStatsTool;
impl TiVtFileReportSpecStatsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_vt_file_report_spec_stats".to_string(), description: "Compute is_malicious and malicious_count for a mock VtFileReportSpec built from sha256.".to_string(), input_schema: json!({"type":"object","required":["sha256"],"properties":{"sha256":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiVtFileReportSpecStatsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let sha = args.get("sha256").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("sha256".into()))?; let r = rustre_ti_vt::mock_file_report(sha); Ok(ToolResult::text(json!({"is_malicious": r.is_malicious(), "malicious_count": r.malicious_count()}).to_string())) } }

pub struct TiVtTokenBucketAvailableTool;
impl TiVtTokenBucketAvailableTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_vt_token_bucket_available".to_string(), description: "Create a VtTokenBucketLimiter with rpm and return currently available tokens.".to_string(), input_schema: json!({"type":"object","required":["rpm"],"properties":{"rpm":{"type":"integer","minimum":1}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiVtTokenBucketAvailableTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let rpm = args.get("rpm").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("rpm".into()))? as u32; let l = rustre_ti_vt::VtTokenBucketLimiter::new(rpm); Ok(ToolResult::text(json!({"available_tokens": l.available_tokens(), "wait_time": l.wait_time()}).to_string())) } }

pub struct TiVtTokenBucketConsumeTool;
impl TiVtTokenBucketConsumeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_vt_token_bucket_consume".to_string(), description: "Try to consume one token from a VtTokenBucketLimiter.".to_string(), input_schema: json!({"type":"object","required":["rpm"],"properties":{"rpm":{"type":"integer","minimum":1}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiVtTokenBucketConsumeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let rpm = args.get("rpm").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("rpm".into()))? as u32; let l = rustre_ti_vt::VtTokenBucketLimiter::new(rpm); let ok = l.try_consume(); Ok(ToolResult::text(json!({"consumed": ok, "available_tokens_after": l.available_tokens()}).to_string())) } }

pub struct TiVtRateLimiterFreeTierTool;
impl TiVtRateLimiterFreeTierTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_vt_rate_limiter_free_tier".to_string(), description: "Create default free-tier VtRateLimiter (4 rpm) and return available tokens.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiVtRateLimiterFreeTierTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let l = rustre_ti_vt::rate_limit::VtRateLimiter::default_free_tier(); Ok(ToolResult::text(json!({"available_tokens": l.available_tokens()}).to_string())) } }

pub struct TiVtThreatSignalsDetectionRatioTool;
impl TiVtThreatSignalsDetectionRatioTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_vt_threat_signals_detection_ratio".to_string(), description: "Return positives/total_engines detection ratio as f64.".to_string(), input_schema: json!({"type":"object","required":["positives","total_engines"],"properties":{"positives":{"type":"integer"},"total_engines":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiVtThreatSignalsDetectionRatioTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let p = args.get("positives").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'positives'".into()))? as u32; let t = args.get("total_engines").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'total_engines'".into()))? as u32; let s = rustre_ti_vt::threat_score::ThreatSignals::new().with_detections(p, t); Ok(ToolResult::text(json!({"detection_ratio": s.detection_ratio()}).to_string())) } }

pub struct TiVtSandboxVerdictScoreTool;
impl TiVtSandboxVerdictScoreTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_vt_sandbox_verdict_score".to_string(), description: "Classify SandboxVerdict (malicious/suspicious) and compute weighted score.".to_string(), input_schema: json!({"type":"object","required":["verdict"],"properties":{"verdict":{"type":"string"},"malware_family":{"type":"string"},"confidence":{"type":"number"}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiVtSandboxVerdictScoreTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("verdict").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("verdict".into()))?.to_string(); let s = rustre_ti_vt::threat_score::SandboxVerdict { verdict: v, malware_family: args.get("malware_family").and_then(Value::as_str).map(String::from), confidence: args.get("confidence").and_then(Value::as_f64) }; Ok(ToolResult::text(json!({"is_malicious": s.is_malicious(), "is_suspicious": s.is_suspicious(), "weighted_score": s.weighted_score()}).to_string())) } }

pub struct TiVtThreatLevelFromScoreTool;
impl TiVtThreatLevelFromScoreTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_vt_threat_level_from_score".to_string(), description: "Map a 0-100 integer threat score to a ThreatLevel string.".to_string(), input_schema: json!({"type":"object","required":["score"],"properties":{"score":{"type":"integer","minimum":0,"maximum":100}}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiVtThreatLevelFromScoreTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let sc = args.get("score").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("score".into()))?.min(255) as u8; let lvl = rustre_ti_vt::threat_score::ThreatLevel::from_score(sc); Ok(ToolResult::text(json!({"level": lvl.as_str()}).to_string())) } }

pub struct TiVtScoringWeightsAvHeavyTool;
impl TiVtScoringWeightsAvHeavyTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_vt_scoring_weights_av_heavy".to_string(), description: "Return the av_heavy ScoringWeights preset and validate sum.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiVtScoringWeightsAvHeavyTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let w = rustre_ti_vt::threat_score::ScoringWeights::av_heavy(); Ok(ToolResult::text(json!({"detection_weight": w.detection_weight, "community_weight": w.community_weight, "sandbox_weight": w.sandbox_weight, "file_type_weight": w.file_type_weight, "age_weight": w.age_weight, "threat_intel_weight": w.threat_intel_weight, "is_valid": w.is_valid()}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TiVtMockFileReportTool::definition(), Box::new(TiVtMockFileReportTool)),
        (TiVtMockIpReportTool::definition(), Box::new(TiVtMockIpReportTool)),
        (TiVtParseSearchResponseTool::definition(), Box::new(TiVtParseSearchResponseTool)),
        (TiVtApiKeyIsValidTool::definition(), Box::new(TiVtApiKeyIsValidTool)),
        (TiVtAnalysisStatsDetectionRatioTool::definition(), Box::new(TiVtAnalysisStatsDetectionRatioTool)),
        (TiVtAvResultClassifyTool::definition(), Box::new(TiVtAvResultClassifyTool)),
        (TiVtAnalysisStatsTotalTool::definition(), Box::new(TiVtAnalysisStatsTotalTool)),
        (TiVtIpReportSpecIsMaliciousTool::definition(), Box::new(TiVtIpReportSpecIsMaliciousTool)),
        (TiVtFileReportSpecStatsTool::definition(), Box::new(TiVtFileReportSpecStatsTool)),
        (TiVtTokenBucketAvailableTool::definition(), Box::new(TiVtTokenBucketAvailableTool)),
        (TiVtTokenBucketConsumeTool::definition(), Box::new(TiVtTokenBucketConsumeTool)),
        (TiVtRateLimiterFreeTierTool::definition(), Box::new(TiVtRateLimiterFreeTierTool)),
        (TiVtThreatSignalsDetectionRatioTool::definition(), Box::new(TiVtThreatSignalsDetectionRatioTool)),
        (TiVtSandboxVerdictScoreTool::definition(), Box::new(TiVtSandboxVerdictScoreTool)),
        (TiVtThreatLevelFromScoreTool::definition(), Box::new(TiVtThreatLevelFromScoreTool)),
        (TiVtScoringWeightsAvHeavyTool::definition(), Box::new(TiVtScoringWeightsAvHeavyTool)),
    ]
}
