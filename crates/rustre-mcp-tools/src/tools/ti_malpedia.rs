//! MCP wrappers for the rustre-ti_malpedia crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

// ─────────────────────────────────────────────────────────────────────────────
// Real corpus loading
//
// ⚠ Why this exists. Every tool below built a `MalpediaLocalDb` and called
// `populate_mock_data()` on it, then answered questions like "is this hash
// known malware" out of that fixture. There was no argument by which a caller
// could supply real data, and the response named
// `MalpediaLocalDb::populate_mock_data` as its source — truthfully, and
// uselessly, because a client reading a family attribution does not check
// which function produced it.
//
// `corpus_path` is now required and points at a Malpedia JSON export
// (`{"families": [...], "actors": [...], "samples": [...]}`), loaded by the
// real `MalpediaLocalDb::load_path`. The fixture stays reachable only behind
// an explicit opt-in that LABELS its output.
// ─────────────────────────────────────────────────────────────────────────────

/// Build a corpus-backed database from `args`.
///
/// Returns `(db, is_fixture)` so every handler can label its answer.
///
/// # Errors
/// `InvalidParams` when neither `corpus_path` nor the explicit opt-in is
/// given; `ToolError` when the corpus cannot be read or parsed.
fn malpedia_db_from_args(
    args: &Value,
) -> Result<(rustre_ti_malpedia::MalpediaLocalDb, bool), McpError> {
    let db = rustre_ti_malpedia::MalpediaLocalDb::new();
    if args.get("use_synthetic_fixture").and_then(Value::as_bool) == Some(true) {
        db.populate_mock_data();
        return Ok((db, true));
    }
    let path = args.get("corpus_path").and_then(Value::as_str).ok_or_else(|| {
        McpError::InvalidParams(
            "'corpus_path' is required: a Malpedia JSON export with \"families\", \"actors\"              and/or \"samples\". Pass \"use_synthetic_fixture\": true to query the built-in              test fixture instead; its answers are NOT threat intelligence."
                .to_string(),
        )
    })?;
    let counts = db
        .load_path(std::path::Path::new(path))
        .map_err(McpError::ToolError)?;
    if counts.is_empty() {
        return Err(McpError::ToolError(format!(
            "corpus '{path}' loaded 0 records: it has no families, actors or samples"
        )));
    }
    Ok((db, false))
}

/// Add the corpus arguments to an existing tool schema.
fn with_corpus_args(mut schema: Value) -> Value {
    schema["properties"]["corpus_path"] = json!({
        "type": "string",
        "description": "Path to a Malpedia JSON export"
    });
    schema["properties"]["use_synthetic_fixture"] = json!({
        "type": "boolean",
        "description": "Query the built-in test fixture instead of a corpus. Answers are labelled is_synthetic_fixture and are NOT threat intelligence."
    });
    let req = schema["required"].as_array().cloned().unwrap_or_default();
    let mut req: Vec<Value> = req;
    if !req.iter().any(|v| v == "corpus_path") {
        req.push(json!("corpus_path"));
    }
    schema["required"] = Value::Array(req);
    schema
}

pub struct TiMalpediaNormalizeFamilyNameTool;

pub struct TiMalpediaFamilyToMalwareTypeTool;

pub struct TiMalpediaMockStatsTool;
impl TiMalpediaMockStatsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_mock_stats".to_string(),
            description: "Return mock Malpedia knowledge-base statistics (family/actor/sample counts, breakdowns).".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaMockStatsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_ti_malpedia::MalpediaStats::mock();
        Ok(ToolResult::text(json!({
            "family_count": s.family_count,
            "actor_count": s.actor_count,
            "sample_count": s.sample_count,
            "yara_rule_count": s.yara_rule_count,
            "platform_breakdown": s.platform_breakdown,
            "actor_country_breakdown": s.actor_country_breakdown,
            "source": "rustre_ti_malpedia::MalpediaStats::mock",
        }).to_string()))
    }
}

pub struct TiMalpediaMockFamilyResponseTool;
impl TiMalpediaMockFamilyResponseTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_mock_family_response".to_string(),
            description: "Build a mock Malpedia family response for a given family name.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaMockFamilyResponseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let c = rustre_ti_malpedia::MalpediaApiClient::new(None);
        let f = c.mock_family_response(name);
        Ok(ToolResult::text(serde_json::to_string(&f).unwrap_or_default()))
    }
}

pub struct TiMalpediaAliasResolveTool;
impl TiMalpediaAliasResolveTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_alias_resolve".to_string(),
            description: "Resolve a malware family alias to its canonical Malpedia name using built-in defaults.".to_string(),
            input_schema: json!({"type":"object","properties":{"alias":{"type":"string"}},"required":["alias"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaAliasResolveTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let alias = args.get("alias").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'alias'".into()))?;
        let r = rustre_ti_malpedia::FamilyAliasResolver::with_defaults();
        let canonical = r.resolve(alias).map(str::to_string);
        let normalized = r.resolve_or_normalize(alias);
        Ok(ToolResult::text(json!({
            "alias": alias,
            "canonical": canonical,
            "resolved_or_normalized": normalized,
            "total_aliases": r.count(),
            "source": "rustre_ti_malpedia::FamilyAliasResolver::with_defaults",
        }).to_string()))
    }
}

pub struct TiMalpediaClassifyFamilyTool;
impl TiMalpediaClassifyFamilyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_classify_family".to_string(),
            description: "Classify a text blob against the default malware-family keyword classifier and return top match + all scores.".to_string(),
            input_schema: json!({"type":"object","properties":{"content":{"type":"string"}},"required":["content"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaClassifyFamilyTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let content = args.get("content").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'content'".into()))?;
        let c = rustre_ti_malpedia::FamilyClassifier::with_defaults();
        let scores = c.score(content);
        let best = c.classify(content);
        Ok(ToolResult::text(json!({
            "best": best,
            "scores": scores.iter().map(|(n,s)| json!({"family":n,"score":s})).collect::<Vec<_>>(),
            "source": "rustre_ti_malpedia::FamilyClassifier::with_defaults",
        }).to_string()))
    }
}

pub struct TiMalpediaSignatureScoreTool;
impl TiMalpediaSignatureScoreTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_signature_score".to_string(),
            description: "Compute a SignatureScoreResult (score + confidence_pct) for a family given raw and max scores.".to_string(),
            input_schema: json!({"type":"object","properties":{"family":{"type":"string"},"score":{"type":"integer"},"max_score":{"type":"integer"}},"required":["family","score","max_score"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaSignatureScoreTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let family = args.get("family").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'family'".into()))?.to_string();
        let score = args.get("score").and_then(Value::as_u64).unwrap_or(0) as u32;
        let max_score = args.get("max_score").and_then(Value::as_u64).unwrap_or(0) as u32;
        let r = rustre_ti_malpedia::SignatureScoreResult::new(family, score, max_score);
        Ok(ToolResult::text(json!({
            "family": r.family,
            "score": r.score,
            "confidence_pct": r.confidence_pct,
            "source": "rustre_ti_malpedia::SignatureScoreResult::new",
        }).to_string()))
    }
}

pub struct TiMalpediaYaraRuleTextTool;
impl TiMalpediaYaraRuleTextTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_yara_rule_text".to_string(),
            description: "Render a minimal Malpedia YARA rule to text given a rule name and family.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"family":{"type":"string"}},"required":["name","family"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaYaraRuleTextTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string();
        let family = args.get("family").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'family'".into()))?.to_string();
        let r = rustre_ti_malpedia::MalpediaYaraRule::new(name, family);
        Ok(ToolResult::text(json!({
            "yara": r.to_yara_text(),
            "source": "rustre_ti_malpedia::MalpediaYaraRule::to_yara_text",
        }).to_string()))
    }
}

pub struct TiMalpediaMockDbSearchTool;
impl TiMalpediaMockDbSearchTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_mock_db_search".to_string(),
            description: "Search the mock-populated Malpedia local DB for families matching a query.".to_string(),
            input_schema: with_corpus_args(json!({"type":"object","properties":{"query":{"type":"string"}},"required":["query"]})),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaMockDbSearchTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let q = args.get("query").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'query'".into()))?;
        let (db, is_synthetic_fixture) = malpedia_db_from_args(&args)?;
        let results = db.search_families(q);
        let names: Vec<String> = results.iter().map(|f| f.name.clone()).collect();
        Ok(ToolResult::text(json!({
            "count": names.len(),
            "names": names,
            "is_synthetic_fixture": is_synthetic_fixture,
            "source": "rustre_ti_malpedia::MalpediaLocalDb::search_families",
        }).to_string()))
    }
}

pub struct TiMalpediaMockDbFindByHashTool;
impl TiMalpediaMockDbFindByHashTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_mock_db_find_by_hash".to_string(),
            description: "Look up a sample in the mock-populated Malpedia local DB by any hash (SHA-256/SHA-1/MD5).".to_string(),
            input_schema: with_corpus_args(json!({"type":"object","properties":{"hash":{"type":"string"}},"required":["hash"]})),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaMockDbFindByHashTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let h = args.get("hash").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'hash'".into()))?;
        let (db, is_synthetic_fixture) = malpedia_db_from_args(&args)?;
        let found = db.find_by_hash(h);
        Ok(ToolResult::text(json!({
            "found": found.is_some(),
            "sample": found.map(|s| json!({"sha256": s.sha256, "family": s.family})),
            "is_synthetic_fixture": is_synthetic_fixture,
            "source": "rustre_ti_malpedia::MalpediaLocalDb::find_by_hash",
        }).to_string()))
    }
}

pub struct TiMalpediaAttributionMethodDisplayTool;
impl TiMalpediaAttributionMethodDisplayTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_attribution_method_display".to_string(),
            description: "Build an ActorAttribution and return actor, confidence, high-confidence flag, and method display string.".to_string(),
            input_schema: json!({"type":"object","properties":{"actor":{"type":"string"},"confidence":{"type":"integer"},"method":{"type":"string"}},"required":["actor","confidence","method"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaAttributionMethodDisplayTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        use rustre_ti_malpedia::AttributionMethod;
        let actor = args.get("actor").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'actor'".into()))?.to_string();
        let confidence = args.get("confidence").and_then(Value::as_u64).unwrap_or(0).min(100) as u8;
        let method_str = args.get("method").and_then(Value::as_str).unwrap_or("Combined");
        let method = match method_str {
            "SharedInfrastructure" => AttributionMethod::SharedInfrastructure,
            "SharedMalware" => AttributionMethod::SharedMalware,
            "YaraMatch" => AttributionMethod::YaraMatch,
            "SharedTtps" => AttributionMethod::SharedTtps,
            "HumInt" => AttributionMethod::HumInt,
            "OsInt" => AttributionMethod::OsInt,
            "TechnicalIndicators" => AttributionMethod::TechnicalIndicators,
            _ => AttributionMethod::Combined,
        };
        let a = rustre_ti_malpedia::ActorAttribution::new(actor, confidence, method);
        Ok(ToolResult::text(json!({
            "actor": a.actor,
            "confidence": a.confidence,
            "is_high_confidence": a.is_high_confidence(),
            "method": a.method.to_string(),
            "source": "rustre_ti_malpedia::ActorAttribution",
        }).to_string()))
    }
}

pub struct TiMalpediaFamilyPlatformPrefixTool;
impl TiMalpediaFamilyPlatformPrefixTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_family_platform_prefix".to_string(),
            description: "Return the platform prefix (e.g. 'win', 'linux') for a Malpedia canonical family name.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaFamilyPlatformPrefixTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let c = rustre_ti_malpedia::MalpediaApiClient::new(None);
        let f = c.mock_family_response(name);
        Ok(ToolResult::text(json!({
            "family": f.name,
            "platform_prefix": f.platform_prefix(),
            "source": "rustre_ti_malpedia::MalpediaFamilySpec::platform_prefix",
        }).to_string()))
    }
}

pub struct TiMalpediaApiKeyIsValidTool;
impl TiMalpediaApiKeyIsValidTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_api_key_is_valid".to_string(),
            description: "Create a MalpediaApiKey, optionally mark it validated, and return is_valid().".to_string(),
            input_schema: json!({"type":"object","required":["key"],"properties":{"key":{"type":"string"},"validated":{"type":"boolean"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaApiKeyIsValidTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let key = args.get("key").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'key'".into()))?.to_string();
        let validated = args.get("validated").and_then(Value::as_bool).unwrap_or(false);
        let mut k = rustre_ti_malpedia::MalpediaApiKey::new(key);
        if validated { k.mark_validated(); }
        Ok(ToolResult::text(json!({
            "is_valid": k.is_valid(),
            "validated": k.validated,
            "source": "rustre_ti_malpedia::MalpediaApiKey::is_valid",
        }).to_string()))
    }
}

pub struct TiMalpediaSearchQueryBuildTool;
impl TiMalpediaSearchQueryBuildTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_search_query_build".to_string(),
            description: "Build a MalpediaSearchQuery via the builder API and return the serialized form.".to_string(),
            input_schema: json!({"type":"object","properties":{"query":{"type":"string"},"platform":{"type":"string"},"malware_type":{"type":"string"},"limit":{"type":"integer"},"include_yara":{"type":"boolean"},"include_samples":{"type":"boolean"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaSearchQueryBuildTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut q = rustre_ti_malpedia::MalpediaSearchQuery::new();
        if let Some(s) = args.get("query").and_then(Value::as_str) { q = q.with_query(s); }
        if let Some(s) = args.get("platform").and_then(Value::as_str) { q = q.with_platform(s); }
        if let Some(s) = args.get("malware_type").and_then(Value::as_str) { q = q.with_malware_type(s); }
        if let Some(l) = args.get("limit").and_then(Value::as_u64) { q = q.with_limit(l as usize); }
        if args.get("include_yara").and_then(Value::as_bool).unwrap_or(false) { q = q.include_yara(); }
        if args.get("include_samples").and_then(Value::as_bool).unwrap_or(false) { q = q.include_samples(); }
        Ok(ToolResult::text(serde_json::to_string(&q).unwrap_or_default()))
    }
}

pub struct TiMalpediaClassifierScoreAllTool;
impl TiMalpediaClassifierScoreAllTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_classifier_score_all".to_string(),
            description: "Score text against all default FamilyClassifier families and return the full ranked list.".to_string(),
            input_schema: json!({"type":"object","required":["content"],"properties":{"content":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaClassifierScoreAllTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let content = args.get("content").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'content'".into()))?;
        let c = rustre_ti_malpedia::FamilyClassifier::with_defaults();
        let scores = c.score(content);
        Ok(ToolResult::text(json!({
            "scores": scores,
            "source": "rustre_ti_malpedia::FamilyClassifier::score",
        }).to_string()))
    }
}

pub struct TiMalpediaClientGetStatsTool;
impl TiMalpediaClientGetStatsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_client_get_stats".to_string(),
            description: "Return cached mock MalpediaStats via MalpediaApiClient::get_stats.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaClientGetStatsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let c = rustre_ti_malpedia::MalpediaApiClient::new(None);
        let s = c.get_stats().map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(serde_json::to_string(&s).unwrap_or_default()))
    }
}

pub struct TiMalpediaClientGetYaraRulesTool;
impl TiMalpediaClientGetYaraRulesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_client_get_yara_rules".to_string(),
            description: "Return generated YARA rule metadata for a family via MalpediaApiClient::get_yara_rules.".to_string(),
            input_schema: json!({"type":"object","required":["family"],"properties":{"family":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaClientGetYaraRulesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let family = args.get("family").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'family'".into()))?;
        let c = rustre_ti_malpedia::MalpediaApiClient::new(None);
        let rules = c.get_yara_rules(family).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(serde_json::to_string(&rules).unwrap_or_default()))
    }
}

pub struct TiMalpediaClientSearchByHashTool;
impl TiMalpediaClientSearchByHashTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_client_search_by_hash".to_string(),
            description: "Search the mock Malpedia client by hash and return the sample record if found.".to_string(),
            input_schema: json!({"type":"object","required":["hash"],"properties":{"hash":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaClientSearchByHashTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hash = args.get("hash").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'hash'".into()))?;
        let c = rustre_ti_malpedia::MalpediaApiClient::new(None);
        let res = c.search_by_hash(hash).map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(json!({
            "hash": hash,
            "found": res.is_some(),
            "sample": res,
        }).to_string()))
    }
}

pub struct TiMalpediaClientListActorsTool;
impl TiMalpediaClientListActorsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_client_list_actors".to_string(),
            description: "List mock Malpedia threat actors via MalpediaApiClient::list_actors.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaClientListActorsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let c = rustre_ti_malpedia::MalpediaApiClient::new(None);
        let actors = c.list_actors().map_err(|e| McpError::InvalidParams(e.to_string()))?;
        Ok(ToolResult::text(serde_json::to_string(&actors).unwrap_or_default()))
    }
}

pub struct TiMalpediaFamilyHasSampleTool;
impl TiMalpediaFamilyHasSampleTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_family_has_sample".to_string(),
            description: "Check whether a mock family response contains a given SHA-256 sample.".to_string(),
            input_schema: json!({"type":"object","required":["name","sha256"],"properties":{"name":{"type":"string"},"sha256":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaFamilyHasSampleTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let sha = args.get("sha256").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'sha256'".into()))?;
        let c = rustre_ti_malpedia::MalpediaApiClient::new(None);
        let f = c.mock_family_response(name);
        Ok(ToolResult::text(json!({
            "family": f.name,
            "has_sample": f.has_sample(sha),
            "source": "rustre_ti_malpedia::MalpediaFamilySpec::has_sample",
        }).to_string()))
    }
}

pub struct TiMalpediaLocalDbPopulateStatsTool;
impl TiMalpediaLocalDbPopulateStatsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_local_db_populate_stats".to_string(),
            description: "Populate a MalpediaLocalDb with mock data and return family/actor/sample counts.".to_string(),
            input_schema: with_corpus_args(json!({"type":"object","properties":{}})),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaLocalDbPopulateStatsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (db, is_synthetic_fixture) = malpedia_db_from_args(&args)?;
        Ok(ToolResult::text(json!({
            "families": db.family_count(),
            "actors": db.actor_count(),
            "samples": db.sample_count(),
            "source": "rustre_ti_malpedia::MalpediaLocalDb (corpus supplied by the caller)",
            "is_synthetic_fixture": is_synthetic_fixture,
        }).to_string()))
    }
}

pub struct TiMalpediaApiKeyNewTool;
impl TiMalpediaApiKeyNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_api_key_new".to_string(),
            description: "Construct a MalpediaApiKey and report validation state.".to_string(),
            input_schema: json!({"type":"object","properties":{"key":{"type":"string"}},"required":["key"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaApiKeyNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let k = args.get("key").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let mut key = rustre_ti_malpedia::MalpediaApiKey::new(k);
        let before = key.is_valid();
        key.mark_validated();
        Ok(ToolResult::text(json!({
            "created_at": key.created_at,
            "valid_before": before,
            "valid_after": key.is_valid(),
            "source": "rustre_ti_malpedia::MalpediaApiKey::new",
        }).to_string()))
    }
}

pub struct TiMalpediaStatsNewTool;
impl TiMalpediaStatsNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_stats_new".to_string(),
            description: "Create an empty MalpediaStats and report initial counts.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaStatsNewTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_ti_malpedia::MalpediaStats::new();
        Ok(ToolResult::text(json!({
            "family_count": s.family_count,
            "actor_count": s.actor_count,
            "sample_count": s.sample_count,
            "yara_rule_count": s.yara_rule_count,
            "source": "rustre_ti_malpedia::MalpediaStats::new",
        }).to_string()))
    }
}

pub struct TiMalpediaActorAttributionAddEvidenceTool;
impl TiMalpediaActorAttributionAddEvidenceTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_actor_attribution_add_evidence".to_string(),
            description: "Build an ActorAttribution and append evidence items.".to_string(),
            input_schema: json!({"type":"object","properties":{"actor":{"type":"string"},"confidence":{"type":"integer"},"evidence":{"type":"array","items":{"type":"string"}}},"required":["actor","confidence"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaActorAttributionAddEvidenceTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let actor = args.get("actor").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let conf = u8::try_from(args.get("confidence").and_then(|v| v.as_u64()).unwrap_or(50)).unwrap_or(50);
        let mut a = rustre_ti_malpedia::ActorAttribution::new(actor, conf, rustre_ti_malpedia::AttributionMethod::Combined);
        if let Some(arr) = args.get("evidence").and_then(|v| v.as_array()) {
            for e in arr {
                if let Some(s) = e.as_str() { a.add_evidence(s.to_string()); }
            }
        }
        Ok(ToolResult::text(json!({
            "actor": a.actor,
            "confidence": a.confidence,
            "evidence_count": a.evidence.len(),
            "high_confidence": a.is_high_confidence(),
            "method": a.method.to_string(),
            "source": "rustre_ti_malpedia::ActorAttribution::add_evidence",
        }).to_string()))
    }
}

pub struct TiMalpediaActorSpecNewTool;
impl TiMalpediaActorSpecNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_actor_spec_new".to_string(),
            description: "Construct a minimal MalpediaActorSpec.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"}},"required":["name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaActorSpecNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let a = rustre_ti_malpedia::MalpediaActorSpec::new(n);
        Ok(ToolResult::text(json!({
            "name": a.name,
            "attribution_confidence": a.attribution_confidence,
            "source": "rustre_ti_malpedia::MalpediaActorSpec::new",
        }).to_string()))
    }
}

pub struct TiMalpediaSampleSpecNewTool;
impl TiMalpediaSampleSpecNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_sample_spec_new".to_string(),
            description: "Construct a minimal MalpediaSampleSpec.".to_string(),
            input_schema: json!({"type":"object","properties":{"sha256":{"type":"string"},"family":{"type":"string"}},"required":["sha256","family"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaSampleSpecNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let h = args.get("sha256").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let f = args.get("family").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let s = rustre_ti_malpedia::MalpediaSampleSpec::new(h, f);
        Ok(ToolResult::text(json!({
            "sha256": s.sha256,
            "family": s.family,
            "packed": s.packed,
            "source": "rustre_ti_malpedia::MalpediaSampleSpec::new",
        }).to_string()))
    }
}

pub struct TiMalpediaYaraRuleNewTool;
impl TiMalpediaYaraRuleNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_yara_rule_new".to_string(),
            description: "Construct a minimal MalpediaYaraRule.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"family":{"type":"string"}},"required":["name","family"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaYaraRuleNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let f = args.get("family").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let r = rustre_ti_malpedia::MalpediaYaraRule::new(n, f);
        Ok(ToolResult::text(json!({
            "name": r.name,
            "family": r.family,
            "condition": r.condition,
            "source": "rustre_ti_malpedia::MalpediaYaraRule::new",
        }).to_string()))
    }
}

pub struct TiMalpediaSignatureScoreResultTool;
impl TiMalpediaSignatureScoreResultTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_signature_score_result".to_string(),
            description: "Compute a SignatureScoreResult confidence pct from score/max_score.".to_string(),
            input_schema: json!({"type":"object","properties":{"family":{"type":"string"},"score":{"type":"integer"},"max_score":{"type":"integer"}},"required":["family","score","max_score"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaSignatureScoreResultTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let fam = args.get("family").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let s = u32::try_from(args.get("score").and_then(|v| v.as_u64()).unwrap_or(0)).unwrap_or(0);
        let m = u32::try_from(args.get("max_score").and_then(|v| v.as_u64()).unwrap_or(0)).unwrap_or(0);
        let r = rustre_ti_malpedia::SignatureScoreResult::new(fam, s, m);
        Ok(ToolResult::text(json!({
            "family": r.family,
            "score": r.score,
            "confidence_pct": r.confidence_pct,
            "source": "rustre_ti_malpedia::SignatureScoreResult::new",
        }).to_string()))
    }
}

pub struct TiMalpediaAliasResolverCountTool;
impl TiMalpediaAliasResolverCountTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_alias_resolver_count".to_string(),
            description: "Report the number of default-registered family aliases.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaAliasResolverCountTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let r = rustre_ti_malpedia::FamilyAliasResolver::with_defaults();
        Ok(ToolResult::text(json!({
            "count": r.count(),
            "source": "rustre_ti_malpedia::FamilyAliasResolver::with_defaults",
        }).to_string()))
    }
}

pub struct TiMalpediaLocalDbListFamiliesTool;
impl TiMalpediaLocalDbListFamiliesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_local_db_list_families".to_string(),
            description: "List all family names in a mock-populated MalpediaLocalDb.".to_string(),
            input_schema: with_corpus_args(json!({"type":"object","properties":{}})),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaLocalDbListFamiliesTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let (db, is_synthetic_fixture) = malpedia_db_from_args(&args)?;
        let names: Vec<String> = db.list_families().into_iter().map(|f| f.name).collect();
        Ok(ToolResult::text(json!({
            "families": names,
            "is_synthetic_fixture": is_synthetic_fixture,
            "source": "rustre_ti_malpedia::MalpediaLocalDb::list_families",
        }).to_string()))
    }
}

pub struct TiMalpediaClientSearchQueryExecTool;
impl TiMalpediaClientSearchQueryExecTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_malpedia_client_search_query_exec".to_string(),
            description: "Execute MalpediaApiClient::search with a structured query and return matched family names.".to_string(),
            input_schema: json!({"type":"object","properties":{"query":{"type":"string"},"platform":{"type":"string"},"malware_type":{"type":"string"},"limit":{"type":"integer"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMalpediaClientSearchQueryExecTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut q = rustre_ti_malpedia::MalpediaSearchQuery::new();
        if let Some(s) = args.get("query").and_then(|v| v.as_str()) { q = q.with_query(s); }
        if let Some(s) = args.get("platform").and_then(|v| v.as_str()) { q = q.with_platform(s); }
        if let Some(s) = args.get("malware_type").and_then(|v| v.as_str()) { q = q.with_malware_type(s); }
        if let Some(n) = args.get("limit").and_then(|v| v.as_u64()) { q = q.with_limit(n as usize); }
        let c = rustre_ti_malpedia::MalpediaApiClient::new(Some("test-key".to_string()));
        let res = c.search(&q).map_err(|e| McpError::InternalError(e.to_string()))?;
        let names: Vec<String> = res.into_iter().map(|f| f.name).collect();
        Ok(ToolResult::text(json!({
            "matches": names,
            "source": "rustre_ti_malpedia::MalpediaApiClient::search",
        }).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TiMalpediaNormalizeFamilyNameTool::definition(), Box::new(TiMalpediaNormalizeFamilyNameTool)),
        (TiMalpediaFamilyToMalwareTypeTool::definition(), Box::new(TiMalpediaFamilyToMalwareTypeTool)),
        (TiMalpediaMockStatsTool::definition(), Box::new(TiMalpediaMockStatsTool)),
        (TiMalpediaMockFamilyResponseTool::definition(), Box::new(TiMalpediaMockFamilyResponseTool)),
        (TiMalpediaAliasResolveTool::definition(), Box::new(TiMalpediaAliasResolveTool)),
        (TiMalpediaClassifyFamilyTool::definition(), Box::new(TiMalpediaClassifyFamilyTool)),
        (TiMalpediaSignatureScoreTool::definition(), Box::new(TiMalpediaSignatureScoreTool)),
        (TiMalpediaYaraRuleTextTool::definition(), Box::new(TiMalpediaYaraRuleTextTool)),
        (TiMalpediaMockDbSearchTool::definition(), Box::new(TiMalpediaMockDbSearchTool)),
        (TiMalpediaMockDbFindByHashTool::definition(), Box::new(TiMalpediaMockDbFindByHashTool)),
        (TiMalpediaAttributionMethodDisplayTool::definition(), Box::new(TiMalpediaAttributionMethodDisplayTool)),
        (TiMalpediaFamilyPlatformPrefixTool::definition(), Box::new(TiMalpediaFamilyPlatformPrefixTool)),
        (TiMalpediaApiKeyIsValidTool::definition(), Box::new(TiMalpediaApiKeyIsValidTool)),
        (TiMalpediaSearchQueryBuildTool::definition(), Box::new(TiMalpediaSearchQueryBuildTool)),
        (TiMalpediaClassifierScoreAllTool::definition(), Box::new(TiMalpediaClassifierScoreAllTool)),
        (TiMalpediaClientGetStatsTool::definition(), Box::new(TiMalpediaClientGetStatsTool)),
        (TiMalpediaClientGetYaraRulesTool::definition(), Box::new(TiMalpediaClientGetYaraRulesTool)),
        (TiMalpediaClientSearchByHashTool::definition(), Box::new(TiMalpediaClientSearchByHashTool)),
        (TiMalpediaClientListActorsTool::definition(), Box::new(TiMalpediaClientListActorsTool)),
        (TiMalpediaFamilyHasSampleTool::definition(), Box::new(TiMalpediaFamilyHasSampleTool)),
        (TiMalpediaLocalDbPopulateStatsTool::definition(), Box::new(TiMalpediaLocalDbPopulateStatsTool)),
        (TiMalpediaApiKeyNewTool::definition(), Box::new(TiMalpediaApiKeyNewTool)),
        (TiMalpediaStatsNewTool::definition(), Box::new(TiMalpediaStatsNewTool)),
        (TiMalpediaActorAttributionAddEvidenceTool::definition(), Box::new(TiMalpediaActorAttributionAddEvidenceTool)),
        (TiMalpediaActorSpecNewTool::definition(), Box::new(TiMalpediaActorSpecNewTool)),
        (TiMalpediaSampleSpecNewTool::definition(), Box::new(TiMalpediaSampleSpecNewTool)),
        (TiMalpediaYaraRuleNewTool::definition(), Box::new(TiMalpediaYaraRuleNewTool)),
        (TiMalpediaSignatureScoreResultTool::definition(), Box::new(TiMalpediaSignatureScoreResultTool)),
        (TiMalpediaAliasResolverCountTool::definition(), Box::new(TiMalpediaAliasResolverCountTool)),
        (TiMalpediaLocalDbListFamiliesTool::definition(), Box::new(TiMalpediaLocalDbListFamiliesTool)),
        (TiMalpediaClientSearchQueryExecTool::definition(), Box::new(TiMalpediaClientSearchQueryExecTool)),
    ]
}
