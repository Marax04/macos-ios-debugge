//! MCP wrappers for the rustre-threatintel crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;
use crate::wire_tools::{ti_parse_ioc_type_v2};

pub struct ThreatintelConfidenceClampW3Tool;
impl ThreatintelConfidenceClampW3Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_confidence_clamp_w3".to_string(),
            description: "Verify ThreatIoc::new clamps confidence to [0,1] via rustre_threatintel::ThreatIoc.".to_string(),
            input_schema: json!({"type":"object","properties":{"confidence":{"type":"number"}},"required":["confidence"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelConfidenceClampW3Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let c32 = crate::confidence_arg(&args, "confidence")?;
        let c = f64::from(c32);
        let ioc = rustre_threatintel::ThreatIoc::new(rustre_threatintel::IocType::Md5, "x", "n", c32, "s");
        Ok(ToolResult::text(json!({"input": c, "clamped": ioc.confidence,
            "source": "rustre_threatintel::ThreatIoc::new"}).to_string()))
    }
}

pub struct ThreatintelDbIsEmptyW3Tool;
impl ThreatintelDbIsEmptyW3Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_db_is_empty_w3".to_string(),
            description: "Return len/is_empty for fresh rustre_threatintel::ThreatIndicatorDatabase.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelDbIsEmptyW3Tool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let db = rustre_threatintel::ThreatIndicatorDatabase::new();
        Ok(ToolResult::text(json!({"len": db.len(), "is_empty": db.is_empty(),
            "source": "rustre_threatintel::ThreatIndicatorDatabase"}).to_string()))
    }
}

pub struct ThreatintelDbGetW3Tool;
impl ThreatintelDbGetW3Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_db_get_w3".to_string(),
            description: "Add an IOC then fetch it by IocId via rustre_threatintel::ThreatIndicatorDatabase::get.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{"type":"string"},"ioc_type":{"type":"string"}},"required":["value"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelDbGetW3Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let t = args.get("ioc_type").and_then(Value::as_str).unwrap_or("sha256");
        let ty = ti_parse_ioc_type_v2(t)?;
        let mut db = rustre_threatintel::ThreatIndicatorDatabase::new();
        let id = db.add_ioc(rustre_threatintel::ThreatIoc::new(ty, v, "n", 0.5, "w"));
        let found = db.get(id).map(|i| i.value.clone());
        Ok(ToolResult::text(json!({"id": id.0, "found_value": found, "len": db.len(),
            "source": "rustre_threatintel::ThreatIndicatorDatabase::get"}).to_string()))
    }
}

pub struct ThreatintelDbStatsW3Tool;
impl ThreatintelDbStatsW3Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_db_stats_w3".to_string(),
            description: "Insert N SHA-256 IOCs and report len via rustre_threatintel::ThreatIndicatorDatabase.".to_string(),
            input_schema: json!({"type":"object","properties":{"n":{"type":"integer"}},"required":["n"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelDbStatsW3Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let n = args.get("n").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'n'".into()))?;
        let n = n.min(1000);
        let mut db = rustre_threatintel::ThreatIndicatorDatabase::new();
        for i in 0..n {
            db.add_ioc(rustre_threatintel::ThreatIoc::new(
                rustre_threatintel::IocType::Sha256, format!("v{i}"), "t", 0.5, "s"));
        }
        Ok(ToolResult::text(json!({"n": n, "len": db.len(), "is_empty": db.is_empty(),
            "source": "rustre_threatintel::ThreatIndicatorDatabase"}).to_string()))
    }
}

pub struct ThreatintelExportStixBatchW3Tool;
impl ThreatintelExportStixBatchW3Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_export_stix_w3".to_string(),
            description: "Export a mixed batch as STIX 2.1 via rustre_threatintel::ThreatIndicatorDatabase::export_stix.".to_string(),
            input_schema: json!({"type":"object","properties":{"hash":{"type":"string"},"domain":{"type":"string"},"ip":{"type":"string"}}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelExportStixBatchW3Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let hash = args.get("hash").and_then(Value::as_str).unwrap_or("deadbeef");
        let domain = args.get("domain").and_then(Value::as_str).unwrap_or("evil.example");
        let ip = args.get("ip").and_then(Value::as_str).unwrap_or("1.2.3.4");
        let iocs = vec![
            rustre_threatintel::ThreatIoc::new(rustre_threatintel::IocType::Sha256, hash, "malware", 0.9, "w"),
            rustre_threatintel::ThreatIoc::new(rustre_threatintel::IocType::Domain, domain, "c2", 0.8, "w"),
            rustre_threatintel::ThreatIoc::new(rustre_threatintel::IocType::Ip, ip, "c2", 0.7, "w"),
        ];
        let stix = rustre_threatintel::ThreatIndicatorDatabase::export_stix(&iocs);
        Ok(ToolResult::text(json!({"count": iocs.len(), "bytes": stix.len(),
            "source": "rustre_threatintel::ThreatIndicatorDatabase::export_stix"}).to_string()))
    }
}

pub struct ThreatintelIocsetByTypeW3Tool;
impl ThreatintelIocsetByTypeW3Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_iocset_by_type_w3".to_string(),
            description: "Insert one IOC per IocType variant and count via rustre_threatintel::ThreatIndicatorDatabase.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelIocsetByTypeW3Tool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_threatintel::{IocType, ThreatIoc, ThreatIndicatorDatabase};
        let types = [IocType::Md5, IocType::Sha1, IocType::Sha256, IocType::Sha512,
            IocType::Ip, IocType::Domain, IocType::Url, IocType::Email,
            IocType::Registry, IocType::Filename, IocType::Mutex, IocType::Yara];
        let mut db = ThreatIndicatorDatabase::new();
        let mut names = Vec::with_capacity(types.len());
        for (i, t) in types.iter().enumerate() {
            names.push(t.to_string());
            db.add_ioc(ThreatIoc::new(t.clone(), format!("v{i}"), "n", 0.5, "s"));
        }
        Ok(ToolResult::text(json!({"types": names, "len": db.len(),
            "source": "rustre_threatintel::ThreatIndicatorDatabase"}).to_string()))
    }
}

pub struct ThreatintelThreatIocConfidenceClampTool;
impl ThreatintelThreatIocConfidenceClampTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_threat_ioc_confidence_clamp".to_string(),
            description: "Verify ThreatIoc::new clamps confidence to [0.0, 1.0].".to_string(),
            input_schema: json!({ "type": "object", "properties": { "raw": { "type": "number" } } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelThreatIocConfidenceClampTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let raw = args.get("raw").and_then(Value::as_f64).unwrap_or(2.5) as f32;
        let ioc = rustre_threatintel::ThreatIoc::new(
            rustre_threatintel::IocType::Ip, "1.2.3.4", "x", raw, "s",
        );
        Ok(ToolResult::text(json!({
            "raw": raw,
            "clamped": ioc.confidence,
            "source": "rustre_threatintel::ThreatIoc::new",
        }).to_string()))
    }
}

pub struct ThreatintelThreatGroupBuilderTool;
impl ThreatintelThreatGroupBuilderTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_threat_group_builder".to_string(),
            description: "Build a ThreatGroup with aliases and TTPs via with_alias/with_ttp.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "name": {"type":"string"} } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelThreatGroupBuilderTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).unwrap_or("TestAPT");
        let g = rustre_threatintel::ThreatGroup::new(name)
            .with_alias("Alias1").with_alias("Alias2")
            .with_ttp("T1059").with_ttp("T1071");
        Ok(ToolResult::text(json!({
            "name": g.name,
            "aliases": g.aliases,
            "ttps": g.ttps,
            "ioc_count": g.iocs.len(),
            "source": "rustre_threatintel::ThreatGroup::with_alias/with_ttp",
        }).to_string()))
    }
}

pub struct ThreatintelThreatGroupLinkIocsTool;
impl ThreatintelThreatGroupLinkIocsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_threat_group_link_iocs".to_string(),
            description: "Insert IOCs and link IocIds into a ThreatGroup via link_ioc.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "count": {"type":"integer"} } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelThreatGroupLinkIocsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let count = args.get("count").and_then(Value::as_u64).unwrap_or(3);
        let mut db = rustre_threatintel::ThreatIndicatorDatabase::new();
        let mut g = rustre_threatintel::ThreatGroup::new("X");
        for i in 0..count {
            let id = db.add_ioc(rustre_threatintel::ThreatIoc::new(
                rustre_threatintel::IocType::Sha256, format!("h{i}"), "n", 0.1, "s"));
            g.link_ioc(id);
        }
        Ok(ToolResult::text(json!({
            "linked": g.iocs.len(),
            "raw_ids": g.iocs.iter().map(|i| i.0).collect::<Vec<_>>(),
            "source": "rustre_threatintel::ThreatGroup::link_ioc",
        }).to_string()))
    }
}

pub struct ThreatintelTrackerDefaultTool;
impl ThreatintelTrackerDefaultTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_tracker_default".to_string(),
            description: "Compare ThreatGroupTracker::default() vs ::new() sizes.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelTrackerDefaultTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let a = rustre_threatintel::ThreatGroupTracker::default();
        let b = rustre_threatintel::ThreatGroupTracker::new();
        Ok(ToolResult::text(json!({
            "default_len": a.known_groups.len(),
            "new_len": b.known_groups.len(),
            "equal": a.known_groups.len() == b.known_groups.len(),
            "source": "rustre_threatintel::ThreatGroupTracker::default",
        }).to_string()))
    }
}

pub struct ThreatintelTrackerGetMutTool;
impl ThreatintelTrackerGetMutTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_tracker_get_mut".to_string(),
            description: "Fetch APT28 via get_mut and add a TTP.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "ttp": {"type":"string"} } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelTrackerGetMutTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let ttp = args.get("ttp").and_then(Value::as_str).unwrap_or("T1566");
        let mut t = rustre_threatintel::ThreatGroupTracker::new();
        let ok = if let Some(g) = t.get_mut("APT28") {
            g.ttps.push(ttp.to_string());
            true
        } else { false };
        Ok(ToolResult::text(json!({
            "found": ok,
            "ttps": t.get("APT28").map(|g| g.ttps.clone()).unwrap_or_default(),
            "source": "rustre_threatintel::ThreatGroupTracker::get_mut",
        }).to_string()))
    }
}

pub struct ThreatintelTrackerCaseInsensitiveSearchTool;
impl ThreatintelTrackerCaseInsensitiveSearchTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_tracker_case_insensitive_search".to_string(),
            description: "Verify ThreatGroupTracker::search is case-insensitive.".to_string(),
            input_schema: json!({ "type": "object", "properties": { "query": {"type":"string"} } }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelTrackerCaseInsensitiveSearchTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let query = args.get("query").and_then(Value::as_str).unwrap_or("FANCY BEAR");
        let t = rustre_threatintel::ThreatGroupTracker::new();
        let hits = t.search(query);
        let names: Vec<String> = hits.iter().map(|g| g.name.clone()).collect();
        Ok(ToolResult::text(json!({
            "query": query,
            "hits": names.len(),
            "names": names,
            "source": "rustre_threatintel::ThreatGroupTracker::search",
        }).to_string()))
    }
}

pub struct ThreatintelExportStixEmptyTool;
impl ThreatintelExportStixEmptyTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_export_stix_empty".to_string(),
            description: "Call export_stix with an empty slice.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelExportStixEmptyTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let s = rustre_threatintel::ThreatIndicatorDatabase::export_stix(&[]);
        Ok(ToolResult::text(json!({
            "len": s.len(),
            "has_bundle": s.contains("\"type\": \"bundle\""),
            "has_spec": s.contains("2.1"),
            "source": "rustre_threatintel::ThreatIndicatorDatabase::export_stix",
        }).to_string()))
    }
}

pub struct ThreatintelExportStixPatternsTool;
impl ThreatintelExportStixPatternsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_export_stix_patterns".to_string(),
            description: "Confirm export_stix produces type-specific STIX patterns.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelExportStixPatternsTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_threatintel::{IocType, ThreatIoc, ThreatIndicatorDatabase};
        let iocs = vec![
            ThreatIoc::new(IocType::Ip, "1.1.1.1", "a", 0.1, "s"),
            ThreatIoc::new(IocType::Domain, "evil.example", "b", 0.2, "s"),
            ThreatIoc::new(IocType::Md5, "cafebabe", "c", 0.3, "s"),
        ];
        let s = ThreatIndicatorDatabase::export_stix(&iocs);
        Ok(ToolResult::text(json!({
            "has_ipv4": s.contains("ipv4-addr:value"),
            "has_domain": s.contains("domain-name:value"),
            "has_md5": s.contains("file:hashes.MD5"),
            "source": "rustre_threatintel::ThreatIndicatorDatabase::export_stix",
        }).to_string()))
    }
}

pub struct ThreatintelThreatIocNewTool;

pub struct ThreatintelExportStixTool;

pub struct ThreatintelXIocNewNetworkFlagTool;
impl ThreatintelXIocNewNetworkFlagTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_x_ioc_new_network_flag".to_string(), description: "Construct an IoC and return its is_network flag.".to_string(), input_schema: json!({"type":"object","properties":{"value":{"type":"string"},"kind":{"type":"string"}},"required":["value","kind"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelXIocNewNetworkFlagTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_threatintel::{IoC, IoCType}; let value = args.get("value").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing value".into()))?; let kind = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing kind".into()))?; let t = match kind.to_lowercase().as_str() { "ip" => IoCType::Ip, "domain" => IoCType::Domain, "url" => IoCType::Url, "email" => IoCType::Email, "md5" => IoCType::Md5, "sha1" => IoCType::Sha1, "sha256" => IoCType::Sha256, other => return Err(McpError::InvalidParams(format!("unknown kind {other}"))) }; let ioc = IoC::new(t, value.to_string(), "wire".to_string()); Ok(ToolResult::text(json!({"value":value,"is_network":ioc.is_network(),"source":"rustre_threatintel::IoC::is_network"}).to_string())) } }

pub struct ThreatintelXIocNewHashFlagTool;
impl ThreatintelXIocNewHashFlagTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_x_ioc_new_hash_flag".to_string(), description: "Construct an IoC and return its is_hash flag.".to_string(), input_schema: json!({"type":"object","properties":{"value":{"type":"string"},"kind":{"type":"string"}},"required":["value","kind"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelXIocNewHashFlagTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_threatintel::{IoC, IoCType}; let value = args.get("value").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing value".into()))?; let kind = args.get("kind").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing kind".into()))?; let t = match kind.to_lowercase().as_str() { "ip" => IoCType::Ip, "domain" => IoCType::Domain, "url" => IoCType::Url, "email" => IoCType::Email, "md5" => IoCType::Md5, "sha1" => IoCType::Sha1, "sha256" => IoCType::Sha256, other => return Err(McpError::InvalidParams(format!("unknown kind {other}"))) }; let ioc = IoC::new(t, value.to_string(), "wire".to_string()); Ok(ToolResult::text(json!({"value":value,"is_hash":ioc.is_hash(),"source":"rustre_threatintel::IoC::is_hash"}).to_string())) } }

pub struct ThreatintelXSeverityOrdCheckTool;
impl ThreatintelXSeverityOrdCheckTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_x_severity_ord_check".to_string(), description: "Verify Severity Low<Medium<High<Critical ordering.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelXSeverityOrdCheckTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_threatintel::Severity; let ok = Severity::Low < Severity::Medium && Severity::Medium < Severity::High && Severity::High < Severity::Critical; Ok(ToolResult::text(json!({"ordered":ok,"source":"rustre_threatintel::Severity"}).to_string())) } }

pub struct ThreatintelXTtpNewSummaryTool;
impl ThreatintelXTtpNewSummaryTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_x_ttp_new_summary".to_string(), description: "Construct a Ttp and return its ID/name/tactic.".to_string(), input_schema: json!({"type":"object","properties":{"id":{"type":"string"},"name":{"type":"string"},"tactic":{"type":"string"}},"required":["id","name","tactic"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelXTtpNewSummaryTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_threatintel::Ttp; let id = args.get("id").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing id".into()))?; let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing name".into()))?; let tactic = args.get("tactic").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing tactic".into()))?; let t = Ttp::new(id, name, tactic); Ok(ToolResult::text(json!({"id":t.technique_id,"name":t.name,"tactic":t.tactic,"source":"rustre_threatintel::Ttp::new"}).to_string())) } }

pub struct ThreatintelXMalwareFamilyAliasCountTool;
impl ThreatintelXMalwareFamilyAliasCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_x_malware_family_alias_count".to_string(), description: "Build MalwareFamily with_alias N times and return alias count.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"aliases":{"type":"array","items":{"type":"string"}}},"required":["name","aliases"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelXMalwareFamilyAliasCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_threatintel::{MalwareFamily, MalwareType}; let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing name".into()))?; let aliases = args.get("aliases").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing aliases".into()))?; let mut fam = MalwareFamily::new(name.to_string(), MalwareType::Trojan); for a in aliases { if let Some(s) = a.as_str() { fam = fam.with_alias(s.to_string()); } } Ok(ToolResult::text(json!({"name":fam.name,"alias_count":fam.aliases.len(),"source":"rustre_threatintel::MalwareFamily"}).to_string())) } }

pub struct ThreatintelXThreatActorTtpCountTool;
impl ThreatintelXThreatActorTtpCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_x_threat_actor_ttp_count".to_string(), description: "Build a ThreatActor with N TTPs and return the count.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"ttp_ids":{"type":"array","items":{"type":"string"}}},"required":["name","ttp_ids"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelXThreatActorTtpCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_threatintel::{ThreatActor, Motivation, Ttp}; let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing name".into()))?; let ids = args.get("ttp_ids").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing ttp_ids".into()))?; let mut a = ThreatActor::new(name.to_string(), Motivation::Espionage); for id in ids { if let Some(s) = id.as_str() { a = a.with_ttp(Ttp::new(s, s, "unknown")); } } Ok(ToolResult::text(json!({"name":a.name,"ttp_count":a.ttps.len(),"source":"rustre_threatintel::ThreatActor::with_ttp"}).to_string())) } }

pub struct ThreatintelXReportAddAndCountTool;
impl ThreatintelXReportAddAndCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_x_report_add_and_count".to_string(), description: "Create a ThreatReport, add N IPs, return ioc_count.".to_string(), input_schema: json!({"type":"object","properties":{"title":{"type":"string"},"ips":{"type":"array","items":{"type":"string"}}},"required":["title","ips"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelXReportAddAndCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_threatintel::{ThreatReport, IoC, IoCType}; let title = args.get("title").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing title".into()))?; let ips = args.get("ips").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing ips".into()))?; let mut r = ThreatReport::new(title.to_string(), "wire".to_string()); for ip in ips { if let Some(s) = ip.as_str() { r.add_ioc(IoC::new(IoCType::Ip, s.to_string(), "wire".to_string())); } } Ok(ToolResult::text(json!({"title":title,"ioc_count":r.ioc_count(),"source":"rustre_threatintel::ThreatReport::add_ioc"}).to_string())) } }

pub struct ThreatintelXReportJsonRoundtripTool;
impl ThreatintelXReportJsonRoundtripTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_x_report_json_roundtrip".to_string(), description: "Serialize and deserialize a ThreatReport, check title equality.".to_string(), input_schema: json!({"type":"object","properties":{"title":{"type":"string"}},"required":["title"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelXReportJsonRoundtripTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_threatintel::ThreatReport; let title = args.get("title").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing title".into()))?; let r = ThreatReport::new(title.to_string(), "wire".to_string()); let json_s = r.to_json().map_err(|e| McpError::InternalError(e.to_string()))?; let back: ThreatReport = serde_json::from_str(&json_s).map_err(|e| McpError::InternalError(e.to_string()))?; Ok(ToolResult::text(json!({"title_ok":back.title==title,"json_len":json_s.len(),"source":"rustre_threatintel::ThreatReport::to_json"}).to_string())) } }

pub struct ThreatintelXIndicatorDbBulkAddTool;
impl ThreatintelXIndicatorDbBulkAddTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_x_indicator_db_bulk_add".to_string(), description: "Bulk-add SHA-256 IOCs and report db length.".to_string(), input_schema: json!({"type":"object","properties":{"hashes":{"type":"array","items":{"type":"string"}}},"required":["hashes"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelXIndicatorDbBulkAddTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_threatintel::{ThreatIndicatorDatabase, ThreatIoc, IocType}; let hashes = args.get("hashes").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing hashes".into()))?; let mut db = ThreatIndicatorDatabase::new(); for h in hashes { if let Some(s) = h.as_str() { db.add_ioc(ThreatIoc::new(IocType::Sha256, s, "bulk", 0.8, "wire")); } } Ok(ToolResult::text(json!({"len":db.len(),"is_empty":db.is_empty(),"source":"rustre_threatintel::ThreatIndicatorDatabase::add_ioc"}).to_string())) } }

pub struct ThreatintelXGroupTrackerAliasSearchCountTool;
impl ThreatintelXGroupTrackerAliasSearchCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_x_group_tracker_alias_search_count".to_string(), description: "Search ThreatGroupTracker for a query and return result count.".to_string(), input_schema: json!({"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelXGroupTrackerAliasSearchCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_threatintel::ThreatGroupTracker; let query = args.get("query").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing query".into()))?; let t = ThreatGroupTracker::new(); let hits = t.search(query); Ok(ToolResult::text(json!({"query":query,"count":hits.len(),"names":hits.iter().map(|g| g.name.clone()).collect::<Vec<_>>(),"source":"rustre_threatintel::ThreatGroupTracker::search"}).to_string())) } }

pub struct ThreatintelXIocTypeDisplayListTool;
impl ThreatintelXIocTypeDisplayListTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_x_ioc_type_display_list".to_string(), description: "Return Display strings for all IocType variants.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelXIocTypeDisplayListTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_threatintel::IocType; let list = [IocType::Md5, IocType::Sha1, IocType::Sha256, IocType::Sha512, IocType::Ip, IocType::Domain, IocType::Url, IocType::Email, IocType::Registry, IocType::Filename, IocType::Mutex, IocType::Yara]; let names: Vec<String> = list.iter().map(std::string::ToString::to_string).collect(); Ok(ToolResult::text(json!({"count":names.len(),"display":names,"source":"rustre_threatintel::IocType::Display"}).to_string())) } }

pub struct ThreatintelXIndicatorDbExportStixCountTool;
impl ThreatintelXIndicatorDbExportStixCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_x_indicator_db_export_stix_count".to_string(), description: "Export N SHA-256 IOCs as STIX and count indicator occurrences.".to_string(), input_schema: json!({"type":"object","properties":{"hashes":{"type":"array","items":{"type":"string"}}},"required":["hashes"]}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelXIndicatorDbExportStixCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { use rustre_threatintel::{ThreatIndicatorDatabase, ThreatIoc, IocType}; let hashes = args.get("hashes").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing hashes".into()))?; let iocs: Vec<ThreatIoc> = hashes.iter().filter_map(|h| h.as_str().map(|s| ThreatIoc::new(IocType::Sha256, s, "bulk", 0.9, "wire"))).collect(); let stix = ThreatIndicatorDatabase::export_stix(&iocs); let indicators = stix.matches("\"type\": \"indicator\"").count(); Ok(ToolResult::text(json!({"input":iocs.len(),"indicators":indicators,"bytes":stix.len(),"source":"rustre_threatintel::ThreatIndicatorDatabase::export_stix"}).to_string())) } }

pub struct ThreatintelEvidenceSignalContributionTool;
impl ThreatintelEvidenceSignalContributionTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_evidence_signal_contribution".to_string(), description: "Build EvidenceSignal::new and return its weighted contribution.".to_string(), input_schema: json!({"type":"object","required":["name","value","weight"],"properties":{"name":{"type":"string"},"value":{"type":"number"},"weight":{"type":"number"},"rationale":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelEvidenceSignalContributionTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let n = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing name".into()))?; let v = args.get("value").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing value".into()))?; let w = args.get("weight").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing weight".into()))?; let r = args.get("rationale").and_then(Value::as_str).unwrap_or(""); let s = rustre_threatintel::EvidenceSignal::new(n, v, w, r); Ok(ToolResult::text(json!({"name":s.name,"value":s.value,"weight":s.weight,"contribution":s.contribution(),"source":"rustre_threatintel::EvidenceSignal::contribution"}).to_string())) } }

pub struct ThreatintelConfidenceModelScorePctTool;
impl ThreatintelConfidenceModelScorePctTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_confidence_model_score_pct".to_string(), description: "Build ConfidenceModel with weighted-mean, add signals, return raw + score_pct + tier.".to_string(), input_schema: json!({"type":"object","required":["signals"],"properties":{"signals":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"value":{"type":"number"},"weight":{"type":"number"}}}},"prior":{"type":"number"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelConfidenceModelScorePctTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let mut m = rustre_threatintel::ConfidenceModel::new(rustre_threatintel::AggregationMethod::WeightedMean); if let Some(p) = args.get("prior").and_then(Value::as_f64) { m = m.with_prior(p); } let sigs = args.get("signals").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing signals".into()))?; for s in sigs { let n = s.get("name").and_then(Value::as_str).unwrap_or("sig"); let v = s.get("value").and_then(Value::as_f64).unwrap_or(0.0); let w = s.get("weight").and_then(Value::as_f64).unwrap_or(1.0); m.add_signal(n, v, w, ""); } Ok(ToolResult::text(json!({"raw":m.raw_score(),"score_pct":m.score_pct(),"tier":m.tier().to_string(),"signal_count":m.signals.len(),"source":"rustre_threatintel::ConfidenceModel::score_pct"}).to_string())) } }

pub struct ThreatintelConfidenceTierFromScoreTool;
impl ThreatintelConfidenceTierFromScoreTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_confidence_tier_from_score".to_string(), description: "Classify a [0,100] score into ConfidenceTier via from_score.".to_string(), input_schema: json!({"type":"object","required":["score"],"properties":{"score":{"type":"integer","minimum":0,"maximum":100}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelConfidenceTierFromScoreTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("score").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing score".into()))?; let sc = u8::try_from(s.min(255)).unwrap_or(0); let t = rustre_threatintel::ConfidenceTier::from_score(sc); Ok(ToolResult::text(json!({"score":sc,"tier":t.to_string(),"lower_bound":t.lower_bound(),"source":"rustre_threatintel::ConfidenceTier::from_score"}).to_string())) } }

pub struct ThreatintelConfidenceTierLowerBoundTool;
impl ThreatintelConfidenceTierLowerBoundTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_confidence_tier_lower_bound".to_string(), description: "Return lower_bound for each ConfidenceTier variant.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelConfidenceTierLowerBoundTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_threatintel::ConfidenceTier as T; let all = [T::VeryLow, T::Low, T::Moderate, T::High, T::VeryHigh]; let out: Vec<_> = all.iter().map(|t| json!({"tier":t.to_string(),"lower_bound":t.lower_bound()})).collect(); Ok(ToolResult::text(json!({"tiers":out,"source":"rustre_threatintel::ConfidenceTier::lower_bound"}).to_string())) } }

pub struct ThreatintelConfidenceDecayScoreAtAgeTool;
impl ThreatintelConfidenceDecayScoreAtAgeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_confidence_decay_score_at_age".to_string(), description: "Return score_at_age for a ConfidenceDecay model.".to_string(), input_schema: json!({"type":"object","required":["initial","half_life","age"],"properties":{"initial":{"type":"number"},"half_life":{"type":"number"},"age":{"type":"number"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelConfidenceDecayScoreAtAgeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let i = args.get("initial").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing initial".into()))?; let h = args.get("half_life").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing half_life".into()))?; let a = args.get("age").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing age".into()))?; let d = rustre_threatintel::ConfidenceDecay::new(i, h); Ok(ToolResult::text(json!({"score":d.score_at_age(a),"initial":d.initial_score,"half_life":d.half_life_secs,"source":"rustre_threatintel::ConfidenceDecay::score_at_age"}).to_string())) } }

pub struct ThreatintelConfidenceDecayPctAtAgeTool;
impl ThreatintelConfidenceDecayPctAtAgeTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_confidence_decay_pct_at_age".to_string(), description: "Return score_pct_at_age for a ConfidenceDecay model.".to_string(), input_schema: json!({"type":"object","required":["initial","half_life","age"],"properties":{"initial":{"type":"number"},"half_life":{"type":"number"},"age":{"type":"number"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelConfidenceDecayPctAtAgeTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let i = args.get("initial").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing initial".into()))?; let h = args.get("half_life").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing half_life".into()))?; let a = args.get("age").and_then(Value::as_f64).ok_or_else(|| McpError::InvalidParams("missing age".into()))?; let d = rustre_threatintel::ConfidenceDecay::new(i, h); Ok(ToolResult::text(json!({"score_pct":d.score_pct_at_age(a),"source":"rustre_threatintel::ConfidenceDecay::score_pct_at_age"}).to_string())) } }

pub struct ThreatintelCampaignComplexityScoreTool;
impl ThreatintelCampaignComplexityScoreTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_campaign_complexity_score".to_string(), description: "Build a Campaign with N TTPs, phases, countries and return complexity_score.".to_string(), input_schema: json!({"type":"object","required":["name"],"properties":{"name":{"type":"string"},"ttps":{"type":"integer","minimum":0},"phases":{"type":"integer","minimum":0},"countries":{"type":"integer","minimum":0},"actor":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelCampaignComplexityScoreTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing name".into()))?.to_string(); let n_ttps = args.get("ttps").and_then(Value::as_u64).unwrap_or(0) as usize; let n_ph = args.get("phases").and_then(Value::as_u64).unwrap_or(0) as usize; let n_co = args.get("countries").and_then(Value::as_u64).unwrap_or(0) as usize; let mut c = rustre_threatintel::Campaign::new(name, rustre_threatintel::TargetingScope::Opportunistic); for i in 0..n_ttps { c = c.with_ttp(rustre_threatintel::Ttp::new(format!("T{i:04}"), "n", "Tactic")); } let phases = [rustre_threatintel::KillChainPhase::Reconnaissance, rustre_threatintel::KillChainPhase::Weaponization, rustre_threatintel::KillChainPhase::Delivery, rustre_threatintel::KillChainPhase::Exploitation, rustre_threatintel::KillChainPhase::Installation, rustre_threatintel::KillChainPhase::CommandAndControl, rustre_threatintel::KillChainPhase::ActionsOnObjective]; for p in phases.iter().take(n_ph) { c = c.with_phase(p.clone()); } for i in 0..n_co { c = c.with_target_country(format!("C{i:02}")); } if let Some(a) = args.get("actor").and_then(Value::as_str) { c = c.with_actor(a.to_string()); } Ok(ToolResult::text(json!({"complexity_score":c.complexity_score(),"ioc_count":c.ioc_count(),"is_attributed":c.is_attributed(),"is_active":c.is_active(),"source":"rustre_threatintel::Campaign::complexity_score"}).to_string())) } }

pub struct ThreatintelCampaignUniqueTacticsTool;
impl ThreatintelCampaignUniqueTacticsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_campaign_unique_tactics".to_string(), description: "Add TTPs to a Campaign and return unique_tactics().".to_string(), input_schema: json!({"type":"object","required":["tactics"],"properties":{"tactics":{"type":"array","items":{"type":"string"}}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelCampaignUniqueTacticsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ts = args.get("tactics").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing tactics".into()))?; let mut c = rustre_threatintel::Campaign::new("t".to_string(), rustre_threatintel::TargetingScope::Opportunistic); for (i, t) in ts.iter().enumerate() { let tactic = t.as_str().unwrap_or("").to_string(); c = c.with_ttp(rustre_threatintel::Ttp::new(format!("T{i:04}"), "n", tactic)); } let u: Vec<String> = c.unique_tactics().into_iter().map(String::from).collect(); Ok(ToolResult::text(json!({"count":u.len(),"tactics":u,"source":"rustre_threatintel::Campaign::unique_tactics"}).to_string())) } }

pub struct ThreatintelCampaignDurationSecsTool;
impl ThreatintelCampaignDurationSecsTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_campaign_duration_secs".to_string(), description: "Set start_date/end_date on a Campaign and read duration_secs.".to_string(), input_schema: json!({"type":"object","required":["start","end"],"properties":{"start":{"type":"integer"},"end":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelCampaignDurationSecsTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let s = args.get("start").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing start".into()))?; let e = args.get("end").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing end".into()))?; let mut c = rustre_threatintel::Campaign::new("c".to_string(), rustre_threatintel::TargetingScope::Opportunistic); c.start_date = Some(s); c.end_date = Some(e); Ok(ToolResult::text(json!({"duration_secs":c.duration_secs(),"is_active":c.is_active(),"source":"rustre_threatintel::Campaign::duration_secs"}).to_string())) } }

pub struct ThreatintelCampaignStoreInsertGetTool;
impl ThreatintelCampaignStoreInsertGetTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_campaign_store_insert_get".to_string(), description: "Insert N campaigns into CampaignStore and roundtrip-fetch by id.".to_string(), input_schema: json!({"type":"object","required":["names"],"properties":{"names":{"type":"array","items":{"type":"string"}}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelCampaignStoreInsertGetTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let names = args.get("names").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing names".into()))?; let mut s = rustre_threatintel::CampaignStore::new(); let mut ids: Vec<u64> = Vec::new(); for n in names { let name = n.as_str().unwrap_or("").to_string(); let c = rustre_threatintel::Campaign::new(name, rustre_threatintel::TargetingScope::Opportunistic); ids.push(s.insert(c)); } let found: Vec<bool> = ids.iter().map(|id| s.get(*id).is_some()).collect(); Ok(ToolResult::text(json!({"count":s.count(),"ids":ids,"found":found,"source":"rustre_threatintel::CampaignStore::insert"}).to_string())) } }

pub struct ThreatintelCampaignStoreByActorCountTool;
impl ThreatintelCampaignStoreByActorCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_campaign_store_by_actor_count".to_string(), description: "Filter CampaignStore by attributed actor.".to_string(), input_schema: json!({"type":"object","required":["actor","campaigns"],"properties":{"actor":{"type":"string"},"campaigns":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"actor":{"type":"string"}}}}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelCampaignStoreByActorCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let actor = args.get("actor").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing actor".into()))?; let cs = args.get("campaigns").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing campaigns".into()))?; let mut s = rustre_threatintel::CampaignStore::new(); for c in cs { let name = c.get("name").and_then(Value::as_str).unwrap_or("").to_string(); let a = c.get("actor").and_then(Value::as_str); let mut cc = rustre_threatintel::Campaign::new(name, rustre_threatintel::TargetingScope::Opportunistic); if let Some(a) = a { cc = cc.with_actor(a.to_string()); } s.insert(cc); } let hits = s.by_actor(actor).len(); Ok(ToolResult::text(json!({"actor":actor,"count":hits,"total":s.count(),"source":"rustre_threatintel::CampaignStore::by_actor"}).to_string())) } }

pub struct ThreatintelCampaignStoreActiveCountTool;
impl ThreatintelCampaignStoreActiveCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_campaign_store_active_count".to_string(), description: "Insert campaigns (some ended) and count active() ones.".to_string(), input_schema: json!({"type":"object","required":["campaigns"],"properties":{"campaigns":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"end_date":{"type":"integer"}}}}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelCampaignStoreActiveCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let cs = args.get("campaigns").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing campaigns".into()))?; let mut s = rustre_threatintel::CampaignStore::new(); for c in cs { let name = c.get("name").and_then(Value::as_str).unwrap_or("").to_string(); let mut cc = rustre_threatintel::Campaign::new(name, rustre_threatintel::TargetingScope::Opportunistic); cc.end_date = c.get("end_date").and_then(Value::as_u64); s.insert(cc); } Ok(ToolResult::text(json!({"active":s.active().len(),"total":s.count(),"source":"rustre_threatintel::CampaignStore::active"}).to_string())) } }

pub struct ThreatintelCampaignStoreByFamilyCountTool;
impl ThreatintelCampaignStoreByFamilyCountTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_campaign_store_by_family_count".to_string(), description: "Filter CampaignStore by malware family (case-insensitive).".to_string(), input_schema: json!({"type":"object","required":["family","campaigns"],"properties":{"family":{"type":"string"},"campaigns":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"families":{"type":"array","items":{"type":"string"}}}}}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelCampaignStoreByFamilyCountTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let family = args.get("family").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing family".into()))?; let cs = args.get("campaigns").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing campaigns".into()))?; let mut s = rustre_threatintel::CampaignStore::new(); for c in cs { let name = c.get("name").and_then(Value::as_str).unwrap_or("").to_string(); let mut cc = rustre_threatintel::Campaign::new(name, rustre_threatintel::TargetingScope::Opportunistic); if let Some(fams) = c.get("families").and_then(Value::as_array) { for f in fams { if let Some(fs) = f.as_str() { cc = cc.with_malware(fs.to_string()); } } } s.insert(cc); } Ok(ToolResult::text(json!({"family":family,"count":s.by_malware_family(family).len(),"total":s.count(),"source":"rustre_threatintel::CampaignStore::by_malware_family"}).to_string())) } }

pub struct ThreatintelTtpIsSubTechniqueTool;
impl ThreatintelTtpIsSubTechniqueTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_ttp_is_sub_technique".to_string(), description: "Build Ttp::new and report is_sub_technique() (false by default).".to_string(), input_schema: json!({"type":"object","required":["technique_id","name","tactic"],"properties":{"technique_id":{"type":"string"},"name":{"type":"string"},"tactic":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelTtpIsSubTechniqueTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let t = rustre_threatintel::Ttp::new(args.get("technique_id").and_then(Value::as_str).unwrap_or("T0000"), args.get("name").and_then(Value::as_str).unwrap_or("n"), args.get("tactic").and_then(Value::as_str).unwrap_or("Discovery")); Ok(ToolResult::text(json!({"is_sub_technique":t.is_sub_technique(),"display":t.to_string(),"source":"rustre_threatintel::Ttp::is_sub_technique"}).to_string())) } }

pub struct ThreatintelConfidenceDominantSignalTool;
impl ThreatintelConfidenceDominantSignalTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_confidence_dominant_signal".to_string(), description: "Return the dominant signal name from ConfidenceModel::dominant_signal.".to_string(), input_schema: json!({"type":"object","required":["signals"],"properties":{"signals":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"},"value":{"type":"number"},"weight":{"type":"number"}}}}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelConfidenceDominantSignalTool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let mut m = rustre_threatintel::ConfidenceModel::new(rustre_threatintel::AggregationMethod::WeightedMean); let sigs = args.get("signals").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing signals".into()))?; for s in sigs { let n = s.get("name").and_then(Value::as_str).unwrap_or("sig"); let v = s.get("value").and_then(Value::as_f64).unwrap_or(0.0); let w = s.get("weight").and_then(Value::as_f64).unwrap_or(1.0); m.add_signal(n, v, w, ""); } let d = m.dominant_signal().map(|s| (s.name.clone(), s.contribution())); Ok(ToolResult::text(json!({"dominant_name":d.as_ref().map(|(n,_)| n.clone()),"dominant_contribution":d.as_ref().map(|(_,c)| *c),"source":"rustre_threatintel::ConfidenceModel::dominant_signal"}).to_string())) } }

pub struct ThreatintelAggregationMethodDisplayTool;
impl ThreatintelAggregationMethodDisplayTool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "threatintel_aggregation_method_display".to_string(), description: "Return Display strings for every AggregationMethod variant.".to_string(), input_schema: json!({"type":"object","properties":{}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for ThreatintelAggregationMethodDisplayTool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_threatintel::AggregationMethod as A; let all = [A::WeightedMean, A::Maximum, A::Minimum, A::WeightedMedian]; let labels: Vec<String> = all.iter().map(std::string::ToString::to_string).collect(); Ok(ToolResult::text(json!({"count":labels.len(),"labels":labels,"source":"rustre_threatintel::AggregationMethod::Display"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ThreatintelConfidenceClampW3Tool::definition(), Box::new(ThreatintelConfidenceClampW3Tool)),
        (ThreatintelDbIsEmptyW3Tool::definition(), Box::new(ThreatintelDbIsEmptyW3Tool)),
        (ThreatintelDbGetW3Tool::definition(), Box::new(ThreatintelDbGetW3Tool)),
        (ThreatintelDbStatsW3Tool::definition(), Box::new(ThreatintelDbStatsW3Tool)),
        (ThreatintelExportStixBatchW3Tool::definition(), Box::new(ThreatintelExportStixBatchW3Tool)),
        (ThreatintelIocsetByTypeW3Tool::definition(), Box::new(ThreatintelIocsetByTypeW3Tool)),
        (ThreatintelThreatIocConfidenceClampTool::definition(), Box::new(ThreatintelThreatIocConfidenceClampTool)),
        (ThreatintelThreatGroupBuilderTool::definition(), Box::new(ThreatintelThreatGroupBuilderTool)),
        (ThreatintelThreatGroupLinkIocsTool::definition(), Box::new(ThreatintelThreatGroupLinkIocsTool)),
        (ThreatintelTrackerDefaultTool::definition(), Box::new(ThreatintelTrackerDefaultTool)),
        (ThreatintelTrackerGetMutTool::definition(), Box::new(ThreatintelTrackerGetMutTool)),
        (ThreatintelTrackerCaseInsensitiveSearchTool::definition(), Box::new(ThreatintelTrackerCaseInsensitiveSearchTool)),
        (ThreatintelExportStixEmptyTool::definition(), Box::new(ThreatintelExportStixEmptyTool)),
        (ThreatintelExportStixPatternsTool::definition(), Box::new(ThreatintelExportStixPatternsTool)),
        (ThreatintelThreatIocNewTool::definition(), Box::new(ThreatintelThreatIocNewTool)),
        (ThreatintelExportStixTool::definition(), Box::new(ThreatintelExportStixTool)),
        (ThreatintelXIocNewNetworkFlagTool::definition(), Box::new(ThreatintelXIocNewNetworkFlagTool)),
        (ThreatintelXIocNewHashFlagTool::definition(), Box::new(ThreatintelXIocNewHashFlagTool)),
        (ThreatintelXSeverityOrdCheckTool::definition(), Box::new(ThreatintelXSeverityOrdCheckTool)),
        (ThreatintelXTtpNewSummaryTool::definition(), Box::new(ThreatintelXTtpNewSummaryTool)),
        (ThreatintelXMalwareFamilyAliasCountTool::definition(), Box::new(ThreatintelXMalwareFamilyAliasCountTool)),
        (ThreatintelXThreatActorTtpCountTool::definition(), Box::new(ThreatintelXThreatActorTtpCountTool)),
        (ThreatintelXReportAddAndCountTool::definition(), Box::new(ThreatintelXReportAddAndCountTool)),
        (ThreatintelXReportJsonRoundtripTool::definition(), Box::new(ThreatintelXReportJsonRoundtripTool)),
        (ThreatintelXIndicatorDbBulkAddTool::definition(), Box::new(ThreatintelXIndicatorDbBulkAddTool)),
        (ThreatintelXGroupTrackerAliasSearchCountTool::definition(), Box::new(ThreatintelXGroupTrackerAliasSearchCountTool)),
        (ThreatintelXIocTypeDisplayListTool::definition(), Box::new(ThreatintelXIocTypeDisplayListTool)),
        (ThreatintelXIndicatorDbExportStixCountTool::definition(), Box::new(ThreatintelXIndicatorDbExportStixCountTool)),
        (ThreatintelEvidenceSignalContributionTool::definition(), Box::new(ThreatintelEvidenceSignalContributionTool)),
        (ThreatintelConfidenceModelScorePctTool::definition(), Box::new(ThreatintelConfidenceModelScorePctTool)),
        (ThreatintelConfidenceTierFromScoreTool::definition(), Box::new(ThreatintelConfidenceTierFromScoreTool)),
        (ThreatintelConfidenceTierLowerBoundTool::definition(), Box::new(ThreatintelConfidenceTierLowerBoundTool)),
        (ThreatintelConfidenceDecayScoreAtAgeTool::definition(), Box::new(ThreatintelConfidenceDecayScoreAtAgeTool)),
        (ThreatintelConfidenceDecayPctAtAgeTool::definition(), Box::new(ThreatintelConfidenceDecayPctAtAgeTool)),
        (ThreatintelCampaignComplexityScoreTool::definition(), Box::new(ThreatintelCampaignComplexityScoreTool)),
        (ThreatintelCampaignUniqueTacticsTool::definition(), Box::new(ThreatintelCampaignUniqueTacticsTool)),
        (ThreatintelCampaignDurationSecsTool::definition(), Box::new(ThreatintelCampaignDurationSecsTool)),
        (ThreatintelCampaignStoreInsertGetTool::definition(), Box::new(ThreatintelCampaignStoreInsertGetTool)),
        (ThreatintelCampaignStoreByActorCountTool::definition(), Box::new(ThreatintelCampaignStoreByActorCountTool)),
        (ThreatintelCampaignStoreActiveCountTool::definition(), Box::new(ThreatintelCampaignStoreActiveCountTool)),
        (ThreatintelCampaignStoreByFamilyCountTool::definition(), Box::new(ThreatintelCampaignStoreByFamilyCountTool)),
        (ThreatintelTtpIsSubTechniqueTool::definition(), Box::new(ThreatintelTtpIsSubTechniqueTool)),
        (ThreatintelConfidenceDominantSignalTool::definition(), Box::new(ThreatintelConfidenceDominantSignalTool)),
        (ThreatintelAggregationMethodDisplayTool::definition(), Box::new(ThreatintelAggregationMethodDisplayTool)),
    ]
}


impl ThreatintelExportStixTool {
    #[must_use]
    pub fn definition() -> rustre_mcp_server::ToolDefinition {
        rustre_mcp_server::ToolDefinition {
            name: "threatintel_export_stix".to_string(),
            description: "Export a list of IOCs as a STIX 2.1 JSON bundle.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": { "iocs": { "type": "array" } },
                "required": ["iocs"]
            }),
            parameters: serde_json::Value::Null,
        }
    }
}

#[async_trait::async_trait]
impl rustre_mcp_server::ToolHandler for ThreatintelExportStixTool {
    async fn call(&self, args: serde_json::Value) -> Result<rustre_mcp_server::ToolResult, rustre_mcp_server::McpError> {
        use rustre_threatintel::{IocType, ThreatIndicatorDatabase, ThreatIoc};
        let arr = args.get("iocs").and_then(serde_json::Value::as_array)
            .ok_or_else(|| rustre_mcp_server::McpError::InvalidParams("missing iocs".into()))?;
        let mut iocs = Vec::with_capacity(arr.len());
        for item in arr {
            let ty_s = item.get("ioc_type").and_then(serde_json::Value::as_str).unwrap_or("Md5");
            let ty = match ty_s.to_ascii_lowercase().as_str() {
                "sha1" | "sha-1" => IocType::Sha1,
                "sha256" | "sha-256" => IocType::Sha256,
                "sha512" | "sha-512" => IocType::Sha512,
                "ip" => IocType::Ip,
                "domain" => IocType::Domain,
                "url" => IocType::Url,
                "email" => IocType::Email,
                "registry" => IocType::Registry,
                "filename" => IocType::Filename,
                "mutex" => IocType::Mutex,
                "yara" => IocType::Yara,
                _ => IocType::Md5,
            };
            let value = item.get("value").and_then(serde_json::Value::as_str).unwrap_or("").to_string();
            let name = item.get("threat_name").and_then(serde_json::Value::as_str).unwrap_or("").to_string();
            let conf = item.get("confidence").and_then(serde_json::Value::as_f64).unwrap_or(0.0) as f32;
            let src = item.get("source").and_then(serde_json::Value::as_str).unwrap_or("").to_string();
            iocs.push(ThreatIoc::new(ty, value, name, conf, src));
        }
        let bundle = ThreatIndicatorDatabase::export_stix(&iocs);
        Ok(rustre_mcp_server::ToolResult::text(serde_json::json!({ "stix_bundle": bundle, "count": iocs.len() }).to_string()))
    }
}

