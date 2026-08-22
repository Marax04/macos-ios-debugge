//! MCP wrappers for the rustre-ti crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{ti_ext_ioc_type_from_str};

pub struct TiExtIocNewClampConfidenceTool;
impl TiExtIocNewClampConfidenceTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_ext_ioc_new_clamp_confidence".to_string(), description: "Construct a ThreatIoc and verify confidence is clamped to [0,1].".to_string(), input_schema: json!({"type":"object","properties":{"value":{"type":"string"},"confidence":{"type":"number"}},"required":["value","confidence"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiExtIocNewClampConfidenceTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let value = args.get("value").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let conf = args.get("confidence").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing 'confidence'".into()))?;
        let conf_f32 = conf as f32;
        let ioc = rustre_threatintel::ThreatIoc::new(rustre_threatintel::IocType::Sha256, value, "T", conf_f32, "wire");
        Ok(ToolResult::text(json!({"input_confidence":conf_f32,"stored_confidence":ioc.confidence,"clamped":(conf_f32 < 0.0 || conf_f32 > 1.0),"source":"rustre_threatintel::ThreatIoc::new"}).to_string()))
    }
}

pub struct TiExtIocDbAddMultipleTool;
impl TiExtIocDbAddMultipleTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_ext_ioc_db_add_multiple".to_string(), description: "Add N distinct SHA-256 IOCs to a fresh ThreatIndicatorDatabase and report len.".to_string(), input_schema: json!({"type":"object","properties":{"count":{"type":"integer"}},"required":["count"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiExtIocDbAddMultipleTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let count = args.get("count").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'count'".into()))?;
        if count > 10_000 { return Err(McpError::InvalidParams("count too large (max 10000)".into())); }
        let mut db = rustre_threatintel::ThreatIndicatorDatabase::new();
        for i in 0..count {
            db.add_ioc(rustre_threatintel::ThreatIoc::new(rustre_threatintel::IocType::Sha256, format!("hash{i:016x}"), "T", 0.5, "s"));
        }
        Ok(ToolResult::text(json!({"count":count,"db_len":db.len(),"is_empty":db.is_empty(),"source":"rustre_threatintel::ThreatIndicatorDatabase"}).to_string()))
    }
}

pub struct TiExtIocDbGetByIdTool;
impl TiExtIocDbGetByIdTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_ext_ioc_db_get_by_id".to_string(), description: "Add an IOC, retrieve it via the returned IocId and confirm value roundtrip.".to_string(), input_schema: json!({"type":"object","properties":{"value":{"type":"string"}},"required":["value"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiExtIocDbGetByIdTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let value = args.get("value").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let mut db = rustre_threatintel::ThreatIndicatorDatabase::new();
        let id = db.add_ioc(rustre_threatintel::ThreatIoc::new(rustre_threatintel::IocType::Md5, value, "T", 0.7, "s"));
        let got = db.get(id);
        Ok(ToolResult::text(json!({"value":value,"ioc_id":id.0,"found":got.is_some(),"roundtrip_value":got.map(|i| i.value.clone()),"source":"rustre_threatintel::ThreatIndicatorDatabase::get"}).to_string()))
    }
}

pub struct TiExtGroupWithAliasesAndTtpsTool;
impl TiExtGroupWithAliasesAndTtpsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_ext_group_with_aliases_and_ttps".to_string(), description: "Build a ThreatGroup with multiple aliases and TTPs and report counts.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"aliases":{"type":"array","items":{"type":"string"}},"ttps":{"type":"array","items":{"type":"string"}}},"required":["name"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiExtGroupWithAliasesAndTtpsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let aliases: Vec<String> = args.get("aliases").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        let ttps: Vec<String> = args.get("ttps").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default();
        let mut g = rustre_threatintel::ThreatGroup::new(name);
        for a in &aliases { g = g.with_alias(a.clone()); }
        for t in &ttps { g = g.with_ttp(t.clone()); }
        Ok(ToolResult::text(json!({"name":g.name,"alias_count":g.aliases.len(),"ttp_count":g.ttps.len(),"aliases":g.aliases,"ttps":g.ttps,"source":"rustre_threatintel::ThreatGroup"}).to_string()))
    }
}

pub struct TiExtGroupLinkIocsAndCountTool;
impl TiExtGroupLinkIocsAndCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_ext_group_link_iocs_and_count".to_string(), description: "Link N synthetic IocIds to a ThreatGroup and return the linked count.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"n":{"type":"integer"}},"required":["name","n"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiExtGroupLinkIocsAndCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        if n > 100_000 { return Err(McpError::InvalidParams("n too large".into())); }
        let mut g = rustre_threatintel::ThreatGroup::new(name);
        for i in 0..n { g.link_ioc(rustre_threatintel::IocId(i + 1)); }
        Ok(ToolResult::text(json!({"name":g.name,"linked":g.iocs.len(),"source":"rustre_threatintel::ThreatGroup::link_ioc"}).to_string()))
    }
}

pub struct TiExtTrackerSearchAliasCaseTool;
impl TiExtTrackerSearchAliasCaseTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_ext_tracker_search_alias_case".to_string(), description: "Search default ThreatGroupTracker by alias with case-insensitive match.".to_string(), input_schema: json!({"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiExtTrackerSearchAliasCaseTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let query = args.get("query").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'query'".into()))?;
        let tracker = rustre_threatintel::ThreatGroupTracker::new();
        let hits = tracker.search(query);
        let names: Vec<String> = hits.iter().map(|g| g.name.clone()).collect();
        Ok(ToolResult::text(json!({"query":query,"match_count":names.len(),"matches":names,"source":"rustre_threatintel::ThreatGroupTracker::search"}).to_string()))
    }
}

pub struct TiExtIocTypeAllVariantsTool;
impl TiExtIocTypeAllVariantsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_ext_ioc_type_all_variants".to_string(), description: "Return Display strings for every rustre_threatintel::IocType variant.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiExtIocTypeAllVariantsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let all = [
            rustre_threatintel::IocType::Md5,
            rustre_threatintel::IocType::Sha1,
            rustre_threatintel::IocType::Sha256,
            rustre_threatintel::IocType::Sha512,
            rustre_threatintel::IocType::Ip,
            rustre_threatintel::IocType::Domain,
            rustre_threatintel::IocType::Url,
            rustre_threatintel::IocType::Email,
            rustre_threatintel::IocType::Registry,
            rustre_threatintel::IocType::Filename,
            rustre_threatintel::IocType::Mutex,
            rustre_threatintel::IocType::Yara,
        ];
        let labels: Vec<String> = all.iter().map(|t| t.to_string()).collect();
        Ok(ToolResult::text(json!({"count":labels.len(),"labels":labels,"source":"rustre_threatintel::IocType Display"}).to_string()))
    }
}

pub struct TiExtIocTypeStixPatternTool;
impl TiExtIocTypeStixPatternTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_ext_ioc_type_stix_pattern".to_string(), description: "Emit a STIX 2.1 pattern for the given IocType/value via export_stix.".to_string(), input_schema: json!({"type":"object","properties":{"ioc_type":{"type":"string"},"value":{"type":"string"}},"required":["ioc_type","value"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiExtIocTypeStixPatternTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ioc_type_s = args.get("ioc_type").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'ioc_type'".into()))?;
        let value = args.get("value").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let ty = ti_ext_ioc_type_from_str(ioc_type_s).ok_or_else(|| McpError::InvalidParams("unknown ioc_type".into()))?;
        let iocs = vec![rustre_threatintel::ThreatIoc::new(ty, value, "T", 1.0, "s")];
        let bundle = rustre_threatintel::ThreatIndicatorDatabase::export_stix(&iocs);
        let contains_value = bundle.contains(value);
        Ok(ToolResult::text(json!({"ioc_type":ioc_type_s,"value":value,"pattern_present":contains_value,"bundle_len":bundle.len(),"source":"rustre_threatintel::ThreatIndicatorDatabase::export_stix"}).to_string()))
    }
}

pub struct TiExtStixBundleObjectCountTool;
impl TiExtStixBundleObjectCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_ext_stix_bundle_object_count".to_string(), description: "Build a STIX bundle for N synthetic IOCs and count indicator occurrences.".to_string(), input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiExtStixBundleObjectCountTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        if n > 1000 { return Err(McpError::InvalidParams("n too large".into())); }
        let iocs: Vec<_> = (0..n).map(|i| rustre_threatintel::ThreatIoc::new(rustre_threatintel::IocType::Sha256, format!("h{i:064x}"), "T", 0.5, "s")).collect();
        let bundle = rustre_threatintel::ThreatIndicatorDatabase::export_stix(&iocs);
        let obj_count = bundle.matches("\"type\": \"indicator\"").count();
        Ok(ToolResult::text(json!({"n":n,"indicator_object_count":obj_count,"bundle_bytes":bundle.len(),"source":"rustre_threatintel::ThreatIndicatorDatabase::export_stix"}).to_string()))
    }
}

pub struct TiExtMitreTtpFormatTool;
impl TiExtMitreTtpFormatTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_ext_mitre_ttp_format".to_string(), description: "Build a MITRE ATT&CK Ttp and return its Display string plus is_sub_technique.".to_string(), input_schema: json!({"type":"object","properties":{"technique_id":{"type":"string"},"name":{"type":"string"},"tactic":{"type":"string"}},"required":["technique_id","name","tactic"]}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiExtMitreTtpFormatTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let tid = args.get("technique_id").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'technique_id'".into()))?;
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let tactic = args.get("tactic").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'tactic'".into()))?;
        let ttp = rustre_threatintel::Ttp::new(tid, name, tactic);
        Ok(ToolResult::text(json!({"technique_id":ttp.technique_id,"display":ttp.to_string(),"is_sub_technique":ttp.is_sub_technique(),"source":"rustre_threatintel::Ttp"}).to_string()))
    }
}

pub struct TiExtMotivationDisplayTool;
impl TiExtMotivationDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_ext_motivation_display".to_string(), description: "Return Display strings for every Motivation variant.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiExtMotivationDisplayTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let all = [
            rustre_threatintel::Motivation::FinancialGain,
            rustre_threatintel::Motivation::Espionage,
            rustre_threatintel::Motivation::Sabotage,
            rustre_threatintel::Motivation::Hacktivism,
            rustre_threatintel::Motivation::Research,
            rustre_threatintel::Motivation::Unknown,
        ];
        let labels: Vec<String> = all.iter().map(|m| m.to_string()).collect();
        Ok(ToolResult::text(json!({"count":labels.len(),"labels":labels,"source":"rustre_threatintel::Motivation Display"}).to_string()))
    }
}

pub struct TiExtTrackerKnownCountTool;
impl TiExtTrackerKnownCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_ext_tracker_known_count".to_string(), description: "Return the number and sorted names of pre-populated groups in the default ThreatGroupTracker.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiExtTrackerKnownCountTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let tracker = rustre_threatintel::ThreatGroupTracker::new();
        let mut names: Vec<String> = tracker.known_groups.keys().cloned().collect();
        names.sort();
        let has_apt28 = tracker.get("APT28").is_some();
        Ok(ToolResult::text(json!({"count":names.len(),"names":names,"has_apt28":has_apt28,"source":"rustre_threatintel::ThreatGroupTracker::new"}).to_string()))
    }
}

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TiExtIocNewClampConfidenceTool::definition(), Box::new(TiExtIocNewClampConfidenceTool)),
        (TiExtIocDbAddMultipleTool::definition(), Box::new(TiExtIocDbAddMultipleTool)),
        (TiExtIocDbGetByIdTool::definition(), Box::new(TiExtIocDbGetByIdTool)),
        (TiExtGroupWithAliasesAndTtpsTool::definition(), Box::new(TiExtGroupWithAliasesAndTtpsTool)),
        (TiExtGroupLinkIocsAndCountTool::definition(), Box::new(TiExtGroupLinkIocsAndCountTool)),
        (TiExtTrackerSearchAliasCaseTool::definition(), Box::new(TiExtTrackerSearchAliasCaseTool)),
        (TiExtIocTypeAllVariantsTool::definition(), Box::new(TiExtIocTypeAllVariantsTool)),
        (TiExtIocTypeStixPatternTool::definition(), Box::new(TiExtIocTypeStixPatternTool)),
        (TiExtStixBundleObjectCountTool::definition(), Box::new(TiExtStixBundleObjectCountTool)),
        (TiExtMitreTtpFormatTool::definition(), Box::new(TiExtMitreTtpFormatTool)),
        (TiExtMotivationDisplayTool::definition(), Box::new(TiExtMotivationDisplayTool)),
        (TiExtTrackerKnownCountTool::definition(), Box::new(TiExtTrackerKnownCountTool)),
    ]
}
