//! MCP wrappers for the rustre-ti_misp crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct TiMispParseAttributeTypeTool;

pub struct TiMispAttributeTypeRoundtripTool;

pub struct TiMispDistributionLevelFromValueTool;

pub struct TiMispThreatLevelFromValueTool;

pub struct TiMispWarningListMatchesTool;

pub struct TiMispTagSpecNewTool;

pub struct TiMispEventIocCountTool;

pub struct TiMispSharingGroupNewTool;

pub struct TiMispSightingIsFalsePositiveTool;

pub struct TiMispEventSpecHasIdsAttributesTool;

pub struct TiMispAttributeTypeToStrTool;
impl TiMispAttributeTypeToStrTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_attribute_type_to_str".to_string(),
            description: "Convert a MispAttributeType variant name to its MISP wire string.".to_string(),
            input_schema: json!({"type":"object","properties":{"variant":{"type":"string"}},"required":["variant"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispAttributeTypeToStrTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let variant = args.get("variant").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'variant'".into()))?;
        // Try roundtrip lookup by common MISP string aliases; also accept enum debug name.
        let lower = variant.to_ascii_lowercase();
        let s = rustre_ti_misp::MispAttributeType::from_misp_str(&lower)
            .map(|t| t.as_misp_str().to_string());
        Ok(ToolResult::text(json!({
            "input": variant, "misp_str": s,
            "source": "rustre_ti_misp::MispAttributeType",
        }).to_string()))
    }
}

pub struct TiMispSightingNewTool;
impl TiMispSightingNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_sighting_new".to_string(),
            description: "Create a MispSighting record (attribute_uuid, sighting_type 0=sighting,1=fp,2=expire).".to_string(),
            input_schema: json!({"type":"object","properties":{"attribute_uuid":{"type":"string"},"sighting_type":{"type":"integer"}},"required":["attribute_uuid","sighting_type"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispSightingNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let uuid = args.get("attribute_uuid").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'attribute_uuid'".into()))?;
        let st = args.get("sighting_type").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'sighting_type'".into()))? as u8;
        let s = rustre_ti_misp::MispSighting::new(uuid.to_string(), st);
        Ok(ToolResult::text(json!({
            "uuid": s.uuid, "attribute_uuid": s.attribute_uuid,
            "sighting_type": s.sighting_type, "is_false_positive": s.is_false_positive(),
            "date_sighting": s.date_sighting,
            "source": "rustre_ti_misp::MispSighting::new",
        }).to_string()))
    }
}

pub struct TiMispEventFullNewTool;
impl TiMispEventFullNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_event_full_new".to_string(),
            description: "Create a MispEventFull with a title/info and return its uuid and defaults.".to_string(),
            input_schema: json!({"type":"object","properties":{"info":{"type":"string"}},"required":["info"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispEventFullNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let info = args.get("info").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'info'".into()))?;
        let e = rustre_ti_misp::MispEventFull::new(info.to_string());
        Ok(ToolResult::text(json!({
            "uuid": e.uuid, "info": e.info, "published": e.published,
            "threat_level_id": e.threat_level_id, "ioc_count": e.ioc_count(),
            "has_ids_attributes": e.has_ids_attributes(),
            "source": "rustre_ti_misp::MispEventFull::new",
        }).to_string()))
    }
}

pub struct TiMispGalaxyFindClusterTool;
impl TiMispGalaxyFindClusterTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_galaxy_find_cluster".to_string(),
            description: "Build a galaxy with named clusters and look up one by value.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "galaxy_name":{"type":"string"},"clusters":{"type":"array","items":{"type":"string"}},"query":{"type":"string"}
            },"required":["galaxy_name","clusters","query"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispGalaxyFindClusterTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("galaxy_name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'galaxy_name'".into()))?;
        let query = args.get("query").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'query'".into()))?;
        let clusters = args.get("clusters").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'clusters'".into()))?;
        let mut g = rustre_ti_misp::MispGalaxy::new(name.to_string(), "mitre-attack".to_string());
        for (i, c) in clusters.iter().enumerate() {
            if let Some(v) = c.as_str() {
                g.add_cluster(rustre_ti_misp::MispGalaxyCluster::new(
                    format!("uuid-{i}"), v.to_string(), "technique".to_string()));
            }
        }
        let found = g.find_cluster(query).map(|c| c.value.clone());
        Ok(ToolResult::text(json!({
            "galaxy": name, "query": query, "found": found,
            "cluster_count": g.clusters.len(),
            "source": "rustre_ti_misp::MispGalaxy::find_cluster",
        }).to_string()))
    }
}

pub struct TiMispSharingGroupBuildTool;
impl TiMispSharingGroupBuildTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_sharing_group_build".to_string(),
            description: "Build a MispSharingGroup with the given name and member org names.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "id":{"type":"integer"},"name":{"type":"string"},"orgs":{"type":"array","items":{"type":"string"}}
            },"required":["id","name","orgs"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispSharingGroupBuildTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let id = args.get("id").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'id'".into()))?;
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let orgs = args.get("orgs").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'orgs'".into()))?;
        let mut sg = rustre_ti_misp::MispSharingGroup::new(id, name.to_string());
        for (i, o) in orgs.iter().enumerate() {
            if let Some(s) = o.as_str() {
                sg.add_org(rustre_ti_misp::MispOrg::new(i as u64 + 1, s.to_string(), format!("uuid-org-{i}")));
            }
        }
        Ok(ToolResult::text(json!({
            "id": sg.id, "uuid": sg.uuid, "name": sg.name,
            "active": sg.active, "org_count": sg.organisations.len(),
            "source": "rustre_ti_misp::MispSharingGroup",
        }).to_string()))
    }
}

pub struct TiMispSupportedIocTypesTool;
impl TiMispSupportedIocTypesTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_supported_ioc_types".to_string(),
            description: "Return the list of IoC types the MISP TiProvider supports.".to_string(),
            input_schema: json!({"type":"object","properties":{}}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispSupportedIocTypesTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        use rustre_threatintel::TiProvider;
        let c = rustre_ti_misp::MispApiClient::new("https://example.com".into(), "key".into());
        let types: Vec<String> = c.supported_ioc_types().iter().map(|t| format!("{t:?}")).collect();
        Ok(ToolResult::text(json!({
            "provider": c.name(), "rate_limit_per_minute": c.rate_limit_per_minute(),
            "supported_ioc_types": types,
            "source": "rustre_ti_misp::MispApiClient::supported_ioc_types",
        }).to_string()))
    }
}

pub struct TiMispDistributionLevelDescribeTool;
impl TiMispDistributionLevelDescribeTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_distribution_level_describe".to_string(),
            description: "Describe a MispDistributionLevel: numeric value + human-readable name.".to_string(),
            input_schema: json!({"type":"object","properties":{"value":{"type":"integer"}},"required":["value"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispDistributionLevelDescribeTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("value").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))? as u8;
        let lvl = rustre_ti_misp::MispDistributionLevel::from_value(v);
        Ok(ToolResult::text(json!({
            "value": v,
            "level": lvl.map(|l| l.to_string()),
            "numeric": lvl.map(|l| l.value()),
            "source": "rustre_ti_misp::MispDistributionLevel",
        }).to_string()))
    }
}

pub struct TiMispFeedNewTool;
impl TiMispFeedNewTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_feed_new".to_string(),
            description: "Construct a MispFeed with defaults for the given id/name/url.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "id":{"type":"integer"},"name":{"type":"string"},"url":{"type":"string"}
            },"required":["id","name","url"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispFeedNewTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let id = args.get("id").and_then(Value::as_u64)
            .ok_or_else(|| McpError::InvalidParams("missing 'id'".into()))?;
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let url = args.get("url").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'url'".into()))?;
        let f = rustre_ti_misp::MispFeed::new(id, name.to_string(), url.to_string());
        Ok(ToolResult::text(json!({
            "id": f.id, "name": f.name, "url": f.url,
            "source_format": f.source_format, "enabled": f.enabled,
            "source": "rustre_ti_misp::MispFeed::new",
        }).to_string()))
    }
}

pub struct TiMispSearchBuildTool;
impl TiMispSearchBuildTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_search_build".to_string(),
            description: "Build a MispSearch query with optional value/type/tags/limit and return it as JSON.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "value":{"type":"string"},"type":{"type":"string"},
                "tags":{"type":"array","items":{"type":"string"}},
                "not_tags":{"type":"array","items":{"type":"string"}},
                "limit":{"type":"integer"}
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispSearchBuildTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut s = rustre_ti_misp::MispSearch::new();
        if let Some(v) = args.get("value").and_then(Value::as_str) { s = s.with_value(v); }
        if let Some(t) = args.get("type").and_then(Value::as_str) { s = s.with_type(t); }
        if let Some(tags) = args.get("tags").and_then(Value::as_array) {
            for t in tags { if let Some(x) = t.as_str() { s = s.with_tag(x); } }
        }
        if let Some(nt) = args.get("not_tags").and_then(Value::as_array) {
            for t in nt { if let Some(x) = t.as_str() { s = s.without_tag(x); } }
        }
        if let Some(l) = args.get("limit").and_then(Value::as_u64) { s = s.with_limit(l as usize); }
        Ok(ToolResult::text(json!({
            "search": serde_json::to_value(&s).unwrap_or(Value::Null),
            "source": "rustre_ti_misp::MispSearch",
        }).to_string()))
    }
}

pub struct TiMispWarningListCheckTool;
impl TiMispWarningListCheckTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_warning_list_check".to_string(),
            description: "Build a warning list with the given entries and check whether a value matches.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "name":{"type":"string"},"entries":{"type":"array","items":{"type":"string"}},"value":{"type":"string"}
            },"required":["name","entries","value"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispWarningListCheckTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let value = args.get("value").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let entries = args.get("entries").and_then(Value::as_array)
            .ok_or_else(|| McpError::InvalidParams("missing 'entries'".into()))?;
        let mut wl = rustre_ti_misp::MispWarningList::new(1, name.to_string());
        wl.entries = entries.iter().filter_map(|e| e.as_str().map(String::from)).collect();
        Ok(ToolResult::text(json!({
            "name": wl.name, "entry_count": wl.entries.len(),
            "value": value, "matches": wl.matches(value),
            "source": "rustre_ti_misp::MispWarningList::matches",
        }).to_string()))
    }
}

pub struct TiMispDistributionLevelValueWireTool;
impl TiMispDistributionLevelValueWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_distribution_level_value".to_string(),
            description: "Numeric value + display for a MispDistributionLevel index (0..=5).".to_string(),
            input_schema: json!({"type":"object","properties":{"v":{"type":"integer"}},"required":["v"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispDistributionLevelValueWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("v").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'v'".into()))? as u8;
        let lvl = rustre_ti_misp::MispDistributionLevel::from_value(v)
            .ok_or_else(|| McpError::InvalidParams("invalid distribution level".into()))?;
        Ok(ToolResult::text(json!({
            "value": lvl.value(), "display": lvl.to_string(),
            "source":"rustre_ti_misp::MispDistributionLevel::value",
        }).to_string()))
    }
}

pub struct TiMispThreatLevelValueWireTool;
impl TiMispThreatLevelValueWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_threat_level_value".to_string(),
            description: "Numeric value + display for a MispThreatLevelId (1..=4).".to_string(),
            input_schema: json!({"type":"object","properties":{"v":{"type":"integer"}},"required":["v"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispThreatLevelValueWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let v = args.get("v").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'v'".into()))? as u8;
        let tl = rustre_ti_misp::MispThreatLevelId::from_value(v)
            .ok_or_else(|| McpError::InvalidParams("invalid threat level".into()))?;
        Ok(ToolResult::text(json!({
            "value": tl.value(), "display": tl.to_string(),
            "source":"rustre_ti_misp::MispThreatLevelId::value",
        }).to_string()))
    }
}

pub struct TiMispApiClientNewWireTool;
impl TiMispApiClientNewWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_api_client_new".to_string(),
            description: "Construct a MispApiClient and report its configured fields.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "api_url":{"type":"string"},"api_key":{"type":"string"},
                "verify_ssl":{"type":"boolean"},"timeout_secs":{"type":"integer"}
            },"required":["api_url","api_key"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispApiClientNewWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let url = args.get("api_url").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing api_url".into()))?;
        let key = args.get("api_key").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing api_key".into()))?;
        let mut c = rustre_ti_misp::MispApiClient::new(url.to_string(), key.to_string());
        if args.get("verify_ssl").and_then(Value::as_bool) == Some(false) { c = c.without_ssl_verify(); }
        if let Some(t) = args.get("timeout_secs").and_then(Value::as_u64) { c = c.with_timeout(t); }
        Ok(ToolResult::text(json!({
            "api_url": c.api_url, "verify_ssl": c.verify_ssl, "timeout_secs": c.timeout_secs,
            "source":"rustre_ti_misp::MispApiClient::new",
        }).to_string()))
    }
}

pub struct TiMispGalaxyClusterNewWireTool;
impl TiMispGalaxyClusterNewWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_galaxy_cluster_new".to_string(),
            description: "Construct a MispGalaxyCluster and return its normalized fields.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "uuid":{"type":"string"},"value":{"type":"string"},"cluster_type":{"type":"string"}
            },"required":["uuid","value","cluster_type"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispGalaxyClusterNewWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let uuid = args.get("uuid").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing uuid".into()))?;
        let value = args.get("value").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing value".into()))?;
        let ct = args.get("cluster_type").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing cluster_type".into()))?;
        let c = rustre_ti_misp::MispGalaxyCluster::new(uuid.to_string(), value.to_string(), ct.to_string());
        Ok(ToolResult::text(json!({
            "uuid": c.uuid, "value": c.value, "cluster_type": c.cluster_type,
            "source":"rustre_ti_misp::MispGalaxyCluster::new",
        }).to_string()))
    }
}

pub struct TiMispObjectFullNewWireTool;
impl TiMispObjectFullNewWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_object_full_new".to_string(),
            description: "Construct a MispObjectFull, optionally add N attributes, and return summary.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "name":{"type":"string"},"meta_category":{"type":"string"},
                "attr_type":{"type":"string"},"attr_values":{"type":"array","items":{"type":"string"}}
            },"required":["name","meta_category"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispObjectFullNewWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing name".into()))?;
        let mc = args.get("meta_category").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing meta_category".into()))?;
        let mut o = rustre_ti_misp::MispObjectFull::new(name.to_string(), mc.to_string());
        let at = args.get("attr_type").and_then(Value::as_str).unwrap_or("md5").to_string();
        if let Some(vals) = args.get("attr_values").and_then(Value::as_array) {
            for (i, v) in vals.iter().enumerate() {
                if let Some(s) = v.as_str() {
                    o.add_attribute(rustre_ti_misp::MispAttributeFull::new(i as u64 + 1, at.clone(), s.to_string()));
                }
            }
        }
        Ok(ToolResult::text(json!({
            "uuid": o.uuid, "name": o.name, "meta_category": o.meta_category,
            "attribute_count": o.attributes.len(),
            "source":"rustre_ti_misp::MispObjectFull::add_attribute",
        }).to_string()))
    }
}

pub struct TiMispWorkflowNewWireTool;
impl TiMispWorkflowNewWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_workflow_new".to_string(),
            description: "Construct a MispWorkflow and return its fields.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "name":{"type":"string"},"trigger_id":{"type":"string"}
            },"required":["name","trigger_id"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispWorkflowNewWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing name".into()))?;
        let tid = args.get("trigger_id").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing trigger_id".into()))?;
        let w = rustre_ti_misp::MispWorkflow::new(name.to_string(), tid.to_string());
        Ok(ToolResult::text(json!({
            "uuid": w.uuid, "name": w.name, "trigger_id": w.trigger_id,
            "enabled": w.enabled, "steps": w.steps.len(),
            "source":"rustre_ti_misp::MispWorkflow::new",
        }).to_string()))
    }
}

pub struct TiMispRestSearchJsonWireTool;
impl TiMispRestSearchJsonWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_rest_search_json".to_string(),
            description: "Wrap a MispSearch in a JSON MispRestSearch envelope.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "value":{"type":"string"},"limit":{"type":"integer"}
            }}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispRestSearchJsonWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let mut s = rustre_ti_misp::MispSearch::new();
        if let Some(v) = args.get("value").and_then(Value::as_str) { s = s.with_value(v); }
        if let Some(l) = args.get("limit").and_then(Value::as_u64) { s = s.with_limit(l as usize); }
        let rs = rustre_ti_misp::MispRestSearch::json(s);
        Ok(ToolResult::text(json!({
            "format": rs.format, "return_format": rs.return_format,
            "request": serde_json::to_value(&rs.request).unwrap_or(Value::Null),
            "source":"rustre_ti_misp::MispRestSearch::json",
        }).to_string()))
    }
}

pub struct TiMispSearchDateRangeWireTool;
impl TiMispSearchDateRangeWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_search_date_range".to_string(),
            description: "Build a MispSearch with a date range and optional threat level filter.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "date_from":{"type":"string"},"date_to":{"type":"string"},
                "threat_level":{"type":"integer"}
            },"required":["date_from","date_to"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispSearchDateRangeWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let df = args.get("date_from").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing date_from".into()))?;
        let dt = args.get("date_to").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing date_to".into()))?;
        let mut s = rustre_ti_misp::MispSearch::new().with_date_range(df, dt);
        if let Some(tl) = args.get("threat_level").and_then(Value::as_u64) { s = s.with_threat_level(tl as u8); }
        Ok(ToolResult::text(json!({
            "date_from": s.date_from, "date_to": s.date_to, "threat_level_id": s.threat_level_id,
            "source":"rustre_ti_misp::MispSearch::with_date_range",
        }).to_string()))
    }
}

pub struct TiMispEventFullHasIdsWireTool;
impl TiMispEventFullHasIdsWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_event_full_has_ids".to_string(),
            description: "Build a MispEventFull with attributes and report has_ids_attributes.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "info":{"type":"string"},
                "attrs":{"type":"array","items":{"type":"object","properties":{
                    "type":{"type":"string"},"value":{"type":"string"},"to_ids":{"type":"boolean"}
                }}}
            },"required":["info"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispEventFullHasIdsWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let info = args.get("info").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing info".into()))?;
        let mut e = rustre_ti_misp::MispEventFull::new(info.to_string());
        if let Some(arr) = args.get("attrs").and_then(Value::as_array) {
            for (i, a) in arr.iter().enumerate() {
                let t = a.get("type").and_then(Value::as_str).unwrap_or("md5").to_string();
                let v = a.get("value").and_then(Value::as_str).unwrap_or("").to_string();
                let mut af = rustre_ti_misp::MispAttributeFull::new(i as u64 + 1, t, v);
                af.to_ids = a.get("to_ids").and_then(Value::as_bool).unwrap_or(false);
                e.add_attribute(af);
            }
        }
        Ok(ToolResult::text(json!({
            "has_ids_attributes": e.has_ids_attributes(),
            "attribute_count": e.attributes.len(),
            "source":"rustre_ti_misp::MispEventFull::has_ids_attributes",
        }).to_string()))
    }
}

pub struct TiMispOrgNewWireTool;
impl TiMispOrgNewWireTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "ti_misp_org_new".to_string(),
            description: "Construct a MispOrg record and return its fields.".to_string(),
            input_schema: json!({"type":"object","properties":{
                "id":{"type":"integer"},"name":{"type":"string"},"uuid":{"type":"string"}
            },"required":["id","name","uuid"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for TiMispOrgNewWireTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let id = args.get("id").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing id".into()))?;
        let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing name".into()))?;
        let uuid = args.get("uuid").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing uuid".into()))?;
        let o = rustre_ti_misp::MispOrg::new(id, name.to_string(), uuid.to_string());
        Ok(ToolResult::text(json!({
            "id": o.id, "name": o.name, "uuid": o.uuid, "local": o.local,
            "source":"rustre_ti_misp::MispOrg::new",
        }).to_string()))
    }
}

pub struct TiMispTagSpecNewV3Tool;
impl TiMispTagSpecNewV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_tag_spec_new_v3".to_string(), description: "Construct MispTagSpec via rustre_ti_misp::MispTagSpec::new.".to_string(), input_schema: json!({ "type":"object", "properties": { "name": {"type":"string"}, "colour": {"type":"string"} }, "required":["name","colour"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiMispTagSpecNewV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string(); let colour = args.get("colour").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'colour'".into()))?.to_string(); let t = rustre_ti_misp::MispTagSpec::new(name, colour); Ok(ToolResult::text(json!({ "name": t.name, "colour": t.colour, "exportable": t.exportable, "numerical_value": t.numerical_value, "source": "rustre_ti_misp::MispTagSpec::new" }).to_string())) } }

pub struct TiMispOrgNewV3Tool;
impl TiMispOrgNewV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_org_new_v3".to_string(), description: "Construct MispOrg via rustre_ti_misp::MispOrg::new.".to_string(), input_schema: json!({ "type":"object", "properties": { "id": {"type":"integer"}, "name": {"type":"string"}, "uuid": {"type":"string"} }, "required":["id","name","uuid"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiMispOrgNewV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let id = args.get("id").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'id'".into()))?; let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string(); let uuid = args.get("uuid").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'uuid'".into()))?.to_string(); let o = rustre_ti_misp::MispOrg::new(id, name, uuid); Ok(ToolResult::text(json!({ "id": o.id, "name": o.name, "uuid": o.uuid, "local": o.local, "source": "rustre_ti_misp::MispOrg::new" }).to_string())) } }

pub struct TiMispWarningListMatchesV3Tool;
impl TiMispWarningListMatchesV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_warning_list_matches_v3".to_string(), description: "Test whether a value matches any entry in a MispWarningList.".to_string(), input_schema: json!({ "type":"object", "properties": { "entries": {"type":"array"}, "value": {"type":"string"} }, "required":["entries","value"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiMispWarningListMatchesV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let entries: Vec<String> = args.get("entries").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(); let value = args.get("value").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?; let mut wl = rustre_ti_misp::MispWarningList::new(1, "wl".to_string()); wl.entries = entries; let m = wl.matches(value); Ok(ToolResult::text(json!({ "matches": m, "source": "rustre_ti_misp::MispWarningList::matches" }).to_string())) } }

pub struct TiMispDistributionLevelValueV3Tool;
impl TiMispDistributionLevelValueV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_distribution_level_value_v3".to_string(), description: "Return numeric value of a MispDistributionLevel parsed from u8.".to_string(), input_schema: json!({ "type":"object", "properties": { "v": {"type":"integer"} }, "required":["v"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiMispDistributionLevelValueV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("v").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'v'".into()))? as u8; let lvl = rustre_ti_misp::MispDistributionLevel::from_value(v); Ok(ToolResult::text(json!({ "input": v, "value": lvl.map(|l| l.value()), "display": lvl.map(|l| l.to_string()), "source": "rustre_ti_misp::MispDistributionLevel::value" }).to_string())) } }

pub struct TiMispThreatLevelValueV3Tool;
impl TiMispThreatLevelValueV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_threat_level_value_v3".to_string(), description: "Return numeric value of a MispThreatLevelId parsed from u8.".to_string(), input_schema: json!({ "type":"object", "properties": { "v": {"type":"integer"} }, "required":["v"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiMispThreatLevelValueV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("v").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'v'".into()))? as u8; let lvl = rustre_ti_misp::MispThreatLevelId::from_value(v); Ok(ToolResult::text(json!({ "input": v, "value": lvl.map(|l| l.value()), "display": lvl.map(|l| l.to_string()), "source": "rustre_ti_misp::MispThreatLevelId::value" }).to_string())) } }

pub struct TiMispSearchBuilderV3Tool;
impl TiMispSearchBuilderV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_search_builder_v3".to_string(), description: "Build a MispSearch via chained builder calls and report fields.".to_string(), input_schema: json!({ "type":"object", "properties": { "value": {"type":"string"}, "type_attr": {"type":"string"}, "tag": {"type":"string"}, "not_tag": {"type":"string"}, "limit": {"type":"integer"}, "threat_level": {"type":"integer"} } }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiMispSearchBuilderV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let mut s = rustre_ti_misp::MispSearch::new(); if let Some(v) = args.get("value").and_then(Value::as_str) { s = s.with_value(v); } if let Some(v) = args.get("type_attr").and_then(Value::as_str) { s = s.with_type(v); } if let Some(v) = args.get("tag").and_then(Value::as_str) { s = s.with_tag(v); } if let Some(v) = args.get("not_tag").and_then(Value::as_str) { s = s.without_tag(v); } if let Some(v) = args.get("limit").and_then(Value::as_u64) { s = s.with_limit(v as usize); } if let Some(v) = args.get("threat_level").and_then(Value::as_u64) { s = s.with_threat_level(v as u8); } Ok(ToolResult::text(json!({ "value": s.value, "type_attribute": s.type_attribute, "tags": s.tags, "not_tags": s.not_tags, "limit": s.limit, "threat_level_id": s.threat_level_id, "source": "rustre_ti_misp::MispSearch" }).to_string())) } }

pub struct TiMispEventFullIocCountV3Tool;
impl TiMispEventFullIocCountV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_event_full_ioc_count_v3".to_string(), description: "Populate a MispEventFull with attributes and count IoC-type attributes.".to_string(), input_schema: json!({ "type":"object", "properties": { "info": {"type":"string"}, "attrs": {"type":"array"} }, "required":["info","attrs"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiMispEventFullIocCountV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let info = args.get("info").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'info'".into()))?.to_string(); let attrs = args.get("attrs").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'attrs'".into()))?; let mut e = rustre_ti_misp::MispEventFull::new(info); for (i, a) in attrs.iter().enumerate() { let t = a.get("type").and_then(Value::as_str).unwrap_or("other").to_string(); let v = a.get("value").and_then(Value::as_str).unwrap_or("").to_string(); e.add_attribute(rustre_ti_misp::MispAttributeFull::new(i as u64 + 1, t, v)); } let has_ids = e.has_ids_attributes(); Ok(ToolResult::text(json!({ "attributes": e.attributes.len(), "ioc_count": e.ioc_count(), "has_ids": has_ids, "source": "rustre_ti_misp::MispEventFull::ioc_count" }).to_string())) } }

pub struct TiMispSharingGroupAddOrgV3Tool;
impl TiMispSharingGroupAddOrgV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_sharing_group_add_org_v3".to_string(), description: "Create MispSharingGroup, add orgs, and report count.".to_string(), input_schema: json!({ "type":"object", "properties": { "id": {"type":"integer"}, "name": {"type":"string"}, "org_names": {"type":"array"} }, "required":["id","name","org_names"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiMispSharingGroupAddOrgV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let id = args.get("id").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'id'".into()))?; let name = args.get("name").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?.to_string(); let orgs = args.get("org_names").and_then(Value::as_array).ok_or_else(|| McpError::InvalidParams("missing 'org_names'".into()))?; let mut sg = rustre_ti_misp::MispSharingGroup::new(id, name); for (i, o) in orgs.iter().enumerate() { let n = o.as_str().unwrap_or("").to_string(); sg.add_org(rustre_ti_misp::MispOrg::new(i as u64 + 1, n, format!("uuid-{i}"))); } Ok(ToolResult::text(json!({ "id": sg.id, "name": sg.name, "org_count": sg.organisations.len(), "active": sg.active, "source": "rustre_ti_misp::MispSharingGroup::add_org" }).to_string())) } }

pub struct TiMispRestSearchJsonV3Tool;
impl TiMispRestSearchJsonV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_rest_search_json_v3".to_string(), description: "Wrap a MispSearch into a MispRestSearch::json envelope.".to_string(), input_schema: json!({ "type":"object", "properties": { "value": {"type":"string"} } }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiMispRestSearchJsonV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let mut s = rustre_ti_misp::MispSearch::new(); if let Some(v) = args.get("value").and_then(Value::as_str) { s = s.with_value(v); } let rest = rustre_ti_misp::MispRestSearch::json(s); Ok(ToolResult::text(json!({ "format": rest.format, "return_format": rest.return_format, "request_value": rest.request.value, "source": "rustre_ti_misp::MispRestSearch::json" }).to_string())) } }

pub struct TiMispDistributionLevelDisplayV3Tool;
impl TiMispDistributionLevelDisplayV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_distribution_level_display_v3".to_string(), description: "Display string for a MispDistributionLevel parsed from u8.".to_string(), input_schema: json!({ "type":"object", "properties": { "v": {"type":"integer"} }, "required":["v"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiMispDistributionLevelDisplayV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let v = args.get("v").and_then(Value::as_u64).ok_or_else(|| McpError::InvalidParams("missing 'v'".into()))? as u8; let lvl = rustre_ti_misp::MispDistributionLevel::from_value(v); Ok(ToolResult::text(json!({ "input": v, "display": lvl.map(|l| l.to_string()), "recognised": lvl.is_some(), "source": "rustre_ti_misp::MispDistributionLevel::Display" }).to_string())) } }

pub struct TiMispAttributeFullAsIocTypeV3Tool;
impl TiMispAttributeFullAsIocTypeV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_attribute_full_as_ioc_type_v3".to_string(), description: "Create MispAttributeFull and resolve its IoCType via as_ioc_type.".to_string(), input_schema: json!({ "type":"object", "properties": { "type": {"type":"string"}, "value": {"type":"string"} }, "required":["type","value"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiMispAttributeFullAsIocTypeV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let t = args.get("type").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'type'".into()))?.to_string(); let v = args.get("value").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?.to_string(); let a = rustre_ti_misp::MispAttributeFull::new(1, t.clone(), v.clone()); let ioc = a.as_ioc_type(); Ok(ToolResult::text(json!({ "type": t, "value": v, "ioc_type": ioc.as_ref().map(|x| x.as_str().to_string()), "recognised": ioc.is_some(), "source": "rustre_ti_misp::MispAttributeFull::as_ioc_type" }).to_string())) } }

pub struct TiMispGalaxyClusterNewV3Tool;
impl TiMispGalaxyClusterNewV3Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_galaxy_cluster_new_v3".to_string(), description: "Construct MispGalaxyCluster and report fields.".to_string(), input_schema: json!({ "type":"object", "properties": { "uuid": {"type":"string"}, "value": {"type":"string"}, "cluster_type": {"type":"string"} }, "required":["uuid","value","cluster_type"] }), parameters: Value::Null } } }
#[async_trait]
impl ToolHandler for TiMispGalaxyClusterNewV3Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let uuid = args.get("uuid").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'uuid'".into()))?.to_string(); let value = args.get("value").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?.to_string(); let ct = args.get("cluster_type").and_then(Value::as_str).ok_or_else(|| McpError::InvalidParams("missing 'cluster_type'".into()))?.to_string(); let c = rustre_ti_misp::MispGalaxyCluster::new(uuid, value, ct); Ok(ToolResult::text(json!({ "uuid": c.uuid, "value": c.value, "cluster_type": c.cluster_type, "meta_len": c.meta.len(), "source": "rustre_ti_misp::MispGalaxyCluster::new" }).to_string())) } }

pub struct TiMispFeedNewV4Tool;
impl TiMispFeedNewV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_feed_new_v4".to_string(), description: "Construct MispFeed via rustre_ti_misp::MispFeed::new.".to_string(), input_schema: json!({"type":"object","properties":{"id":{"type":"integer"},"name":{"type":"string"},"url":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TiMispFeedNewV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let id = args.get("id").and_then(Value::as_u64).unwrap_or(1); let name = args.get("name").and_then(Value::as_str).unwrap_or("feed").to_string(); let url = args.get("url").and_then(Value::as_str).unwrap_or("https://example.com/feed").to_string(); let f = rustre_ti_misp::MispFeed::new(id, name, url); Ok(ToolResult::text(json!({"id":f.id,"name":f.name,"url":f.url,"source_format":f.source_format,"enabled":f.enabled,"caching_enabled":f.caching_enabled,"source":"rustre_ti_misp::MispFeed::new"}).to_string())) } }

pub struct TiMispWorkflowNewV4Tool;
impl TiMispWorkflowNewV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_workflow_new_v4".to_string(), description: "Construct MispWorkflow via rustre_ti_misp::MispWorkflow::new.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"trigger":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TiMispWorkflowNewV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).unwrap_or("wf").to_string(); let trig = args.get("trigger").and_then(Value::as_str).unwrap_or("event-publish").to_string(); let w = rustre_ti_misp::MispWorkflow::new(name, trig); Ok(ToolResult::text(json!({"name":w.name,"trigger_id":w.trigger_id,"enabled":w.enabled,"steps":w.steps.len(),"uuid_present":!w.uuid.is_empty(),"source":"rustre_ti_misp::MispWorkflow::new"}).to_string())) } }

pub struct TiMispObjectTemplateNewV4Tool;
impl TiMispObjectTemplateNewV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_object_template_new_v4".to_string(), description: "Construct MispObjectTemplate via rustre_ti_misp::MispObjectTemplate::new.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"meta_category":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TiMispObjectTemplateNewV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).unwrap_or("file").to_string(); let mc = args.get("meta_category").and_then(Value::as_str).unwrap_or("file").to_string(); let t = rustre_ti_misp::MispObjectTemplate::new(name, mc); Ok(ToolResult::text(json!({"name":t.name,"meta_category":t.meta_category,"version":t.version,"attribute_count":t.attributes.len(),"source":"rustre_ti_misp::MispObjectTemplate::new"}).to_string())) } }

pub struct TiMispGalaxyClusterNewV4Tool;
impl TiMispGalaxyClusterNewV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_galaxy_cluster_new_v4".to_string(), description: "Construct MispGalaxyCluster via rustre_ti_misp::MispGalaxyCluster::new.".to_string(), input_schema: json!({"type":"object","properties":{"uuid":{"type":"string"},"value":{"type":"string"},"cluster_type":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TiMispGalaxyClusterNewV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let uuid = args.get("uuid").and_then(Value::as_str).unwrap_or("00000000-0000-0000-0000-000000000000").to_string(); let value = args.get("value").and_then(Value::as_str).unwrap_or("APT1").to_string(); let ct = args.get("cluster_type").and_then(Value::as_str).unwrap_or("threat-actor").to_string(); let c = rustre_ti_misp::MispGalaxyCluster::new(uuid, value, ct); Ok(ToolResult::text(json!({"uuid":c.uuid,"value":c.value,"cluster_type":c.cluster_type,"meta_len":c.meta.len(),"source":"rustre_ti_misp::MispGalaxyCluster::new"}).to_string())) } }

pub struct TiMispSearchWithLimitV4Tool;
impl TiMispSearchWithLimitV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_search_with_limit_v4".to_string(), description: "Build MispSearch via with_value/with_type/with_limit.".to_string(), input_schema: json!({"type":"object","properties":{"value":{"type":"string"},"type_attribute":{"type":"string"},"limit":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TiMispSearchWithLimitV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let value = args.get("value").and_then(Value::as_str).unwrap_or("evil.com"); let ty = args.get("type_attribute").and_then(Value::as_str).unwrap_or("domain"); let limit = usize::try_from(args.get("limit").and_then(Value::as_u64).unwrap_or(50)).unwrap_or(50); let s = rustre_ti_misp::MispSearch::new().with_value(value).with_type(ty).with_limit(limit); Ok(ToolResult::text(json!({"value":s.value,"type_attribute":s.type_attribute,"limit":s.limit,"source":"rustre_ti_misp::MispSearch"}).to_string())) } }

pub struct TiMispSearchWithThreatLevelV4Tool;
impl TiMispSearchWithThreatLevelV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_search_with_threat_level_v4".to_string(), description: "Apply MispSearch::with_threat_level.".to_string(), input_schema: json!({"type":"object","properties":{"level":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TiMispSearchWithThreatLevelV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let lvl = u8::try_from(args.get("level").and_then(Value::as_u64).unwrap_or(1)).unwrap_or(1); let s = rustre_ti_misp::MispSearch::new().with_threat_level(lvl); Ok(ToolResult::text(json!({"threat_level_id":s.threat_level_id,"source":"rustre_ti_misp::MispSearch::with_threat_level"}).to_string())) } }

pub struct TiMispSearchTagsV4Tool;
impl TiMispSearchTagsV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_search_tags_v4".to_string(), description: "Chain MispSearch::with_tag and without_tag.".to_string(), input_schema: json!({"type":"object","properties":{"include":{"type":"array","items":{"type":"string"}},"exclude":{"type":"array","items":{"type":"string"}}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TiMispSearchTagsV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let inc: Vec<String> = args.get("include").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(); let exc: Vec<String> = args.get("exclude").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(); let mut s = rustre_ti_misp::MispSearch::new(); for t in &inc { s = s.with_tag(t.clone()); } for t in &exc { s = s.without_tag(t.clone()); } Ok(ToolResult::text(json!({"tags":s.tags,"not_tags":s.not_tags,"source":"rustre_ti_misp::MispSearch::with_tag"}).to_string())) } }

pub struct TiMispDistributionLevelAllValuesV4Tool;
impl TiMispDistributionLevelAllValuesV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_distribution_level_all_values_v4".to_string(), description: "Enumerate MispDistributionLevel via from_value(0..=5).".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TiMispDistributionLevelAllValuesV4Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let out: Vec<Value> = (0u8..=5).filter_map(|v| rustre_ti_misp::MispDistributionLevel::from_value(v).map(|d| json!({"value":d.value(),"display":d.to_string()}))).collect(); let n = out.len(); Ok(ToolResult::text(json!({"levels":out,"count":n,"source":"rustre_ti_misp::MispDistributionLevel"}).to_string())) } }

pub struct TiMispThreatLevelAllValuesV4Tool;
impl TiMispThreatLevelAllValuesV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_threat_level_all_values_v4".to_string(), description: "Enumerate MispThreatLevelId via from_value(1..=4).".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TiMispThreatLevelAllValuesV4Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { let out: Vec<Value> = (1u8..=4).filter_map(|v| rustre_ti_misp::MispThreatLevelId::from_value(v).map(|d| json!({"value":d.value(),"display":d.to_string()}))).collect(); let n = out.len(); Ok(ToolResult::text(json!({"levels":out,"count":n,"source":"rustre_ti_misp::MispThreatLevelId"}).to_string())) } }

pub struct TiMispAnalysisLevelDisplayV4Tool;
impl TiMispAnalysisLevelDisplayV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_analysis_level_display_v4".to_string(), description: "Report Display strings for MispAnalysisLevel variants.".to_string(), input_schema: json!({"type":"object"}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TiMispAnalysisLevelDisplayV4Tool { async fn call(&self, _args: Value) -> Result<ToolResult, McpError> { use rustre_ti_misp::MispAnalysisLevel as A; let items = [A::Initial, A::Ongoing, A::Completed]; let out: Vec<Value> = items.iter().map(|l| json!({"display":l.to_string()})).collect(); Ok(ToolResult::text(json!({"levels":out,"source":"rustre_ti_misp::MispAnalysisLevel"}).to_string())) } }

pub struct TiMispWarningListAddEntriesV4Tool;
impl TiMispWarningListAddEntriesV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_warning_list_add_entries_v4".to_string(), description: "Populate MispWarningList entries and test matches() on a query.".to_string(), input_schema: json!({"type":"object","properties":{"entries":{"type":"array","items":{"type":"string"}},"query":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TiMispWarningListAddEntriesV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let entries: Vec<String> = args.get("entries").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(); let query = args.get("query").and_then(Value::as_str).unwrap_or(""); let mut wl = rustre_ti_misp::MispWarningList::new(1, "custom".to_string()); wl.entries = entries.clone(); let hit = wl.matches(query); Ok(ToolResult::text(json!({"count":wl.entries.len(),"matches":hit,"query":query,"source":"rustre_ti_misp::MispWarningList::matches"}).to_string())) } }

pub struct TiMispObjectFullAddAttrV4Tool;
impl TiMispObjectFullAddAttrV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_object_full_add_attr_v4".to_string(), description: "Construct MispObjectFull and add N attributes.".to_string(), input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"count":{"type":"integer"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TiMispObjectFullAddAttrV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let name = args.get("name").and_then(Value::as_str).unwrap_or("file").to_string(); let n = args.get("count").and_then(Value::as_u64).unwrap_or(3); let mut o = rustre_ti_misp::MispObjectFull::new(name, "file".to_string()); for i in 0..n { o.add_attribute(rustre_ti_misp::MispAttributeFull::new(i + 1, "md5".to_string(), format!("aa{:02x}", i & 0xff))); } Ok(ToolResult::text(json!({"attribute_count":o.attributes.len(),"name":o.name,"source":"rustre_ti_misp::MispObjectFull::add_attribute"}).to_string())) } }

pub struct TiMispAttributeFullIocTypeV4Tool;
impl TiMispAttributeFullIocTypeV4Tool { #[must_use] pub fn definition() -> ToolDefinition { ToolDefinition { name: "ti_misp_attribute_full_ioc_type_v4".to_string(), description: "Build MispAttributeFull::new and return whether as_ioc_type resolves.".to_string(), input_schema: json!({"type":"object","properties":{"type_attribute":{"type":"string"},"value":{"type":"string"}}}), parameters: Value::Null } } }
#[async_trait] impl ToolHandler for TiMispAttributeFullIocTypeV4Tool { async fn call(&self, args: Value) -> Result<ToolResult, McpError> { let ty = args.get("type_attribute").and_then(Value::as_str).unwrap_or("md5").to_string(); let val = args.get("value").and_then(Value::as_str).unwrap_or("d41d8cd98f00b204e9800998ecf8427e").to_string(); let a = rustre_ti_misp::MispAttributeFull::new(1, ty, val); let ioc = a.as_ioc_type().map(|t| format!("{:?}", t)); Ok(ToolResult::text(json!({"type_attribute":a.type_,"ioc_type":ioc,"has_ioc":a.as_ioc_type().is_some(),"source":"rustre_ti_misp::MispAttributeFull::as_ioc_type"}).to_string())) } }

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (TiMispParseAttributeTypeTool::definition(), Box::new(TiMispParseAttributeTypeTool)),
        (TiMispAttributeTypeRoundtripTool::definition(), Box::new(TiMispAttributeTypeRoundtripTool)),
        (TiMispDistributionLevelFromValueTool::definition(), Box::new(TiMispDistributionLevelFromValueTool)),
        (TiMispThreatLevelFromValueTool::definition(), Box::new(TiMispThreatLevelFromValueTool)),
        (TiMispWarningListMatchesTool::definition(), Box::new(TiMispWarningListMatchesTool)),
        (TiMispTagSpecNewTool::definition(), Box::new(TiMispTagSpecNewTool)),
        (TiMispEventIocCountTool::definition(), Box::new(TiMispEventIocCountTool)),
        (TiMispSharingGroupNewTool::definition(), Box::new(TiMispSharingGroupNewTool)),
        (TiMispSightingIsFalsePositiveTool::definition(), Box::new(TiMispSightingIsFalsePositiveTool)),
        (TiMispEventSpecHasIdsAttributesTool::definition(), Box::new(TiMispEventSpecHasIdsAttributesTool)),
        (TiMispAttributeTypeToStrTool::definition(), Box::new(TiMispAttributeTypeToStrTool)),
        (TiMispSightingNewTool::definition(), Box::new(TiMispSightingNewTool)),
        (TiMispEventFullNewTool::definition(), Box::new(TiMispEventFullNewTool)),
        (TiMispGalaxyFindClusterTool::definition(), Box::new(TiMispGalaxyFindClusterTool)),
        (TiMispSharingGroupBuildTool::definition(), Box::new(TiMispSharingGroupBuildTool)),
        (TiMispSupportedIocTypesTool::definition(), Box::new(TiMispSupportedIocTypesTool)),
        (TiMispDistributionLevelDescribeTool::definition(), Box::new(TiMispDistributionLevelDescribeTool)),
        (TiMispFeedNewTool::definition(), Box::new(TiMispFeedNewTool)),
        (TiMispSearchBuildTool::definition(), Box::new(TiMispSearchBuildTool)),
        (TiMispWarningListCheckTool::definition(), Box::new(TiMispWarningListCheckTool)),
        (TiMispDistributionLevelValueWireTool::definition(), Box::new(TiMispDistributionLevelValueWireTool)),
        (TiMispThreatLevelValueWireTool::definition(), Box::new(TiMispThreatLevelValueWireTool)),
        (TiMispApiClientNewWireTool::definition(), Box::new(TiMispApiClientNewWireTool)),
        (TiMispGalaxyClusterNewWireTool::definition(), Box::new(TiMispGalaxyClusterNewWireTool)),
        (TiMispObjectFullNewWireTool::definition(), Box::new(TiMispObjectFullNewWireTool)),
        (TiMispWorkflowNewWireTool::definition(), Box::new(TiMispWorkflowNewWireTool)),
        (TiMispRestSearchJsonWireTool::definition(), Box::new(TiMispRestSearchJsonWireTool)),
        (TiMispSearchDateRangeWireTool::definition(), Box::new(TiMispSearchDateRangeWireTool)),
        (TiMispEventFullHasIdsWireTool::definition(), Box::new(TiMispEventFullHasIdsWireTool)),
        (TiMispOrgNewWireTool::definition(), Box::new(TiMispOrgNewWireTool)),
        (TiMispTagSpecNewV3Tool::definition(), Box::new(TiMispTagSpecNewV3Tool)),
        (TiMispOrgNewV3Tool::definition(), Box::new(TiMispOrgNewV3Tool)),
        (TiMispWarningListMatchesV3Tool::definition(), Box::new(TiMispWarningListMatchesV3Tool)),
        (TiMispDistributionLevelValueV3Tool::definition(), Box::new(TiMispDistributionLevelValueV3Tool)),
        (TiMispThreatLevelValueV3Tool::definition(), Box::new(TiMispThreatLevelValueV3Tool)),
        (TiMispSearchBuilderV3Tool::definition(), Box::new(TiMispSearchBuilderV3Tool)),
        (TiMispEventFullIocCountV3Tool::definition(), Box::new(TiMispEventFullIocCountV3Tool)),
        (TiMispSharingGroupAddOrgV3Tool::definition(), Box::new(TiMispSharingGroupAddOrgV3Tool)),
        (TiMispRestSearchJsonV3Tool::definition(), Box::new(TiMispRestSearchJsonV3Tool)),
        (TiMispDistributionLevelDisplayV3Tool::definition(), Box::new(TiMispDistributionLevelDisplayV3Tool)),
        (TiMispAttributeFullAsIocTypeV3Tool::definition(), Box::new(TiMispAttributeFullAsIocTypeV3Tool)),
        (TiMispGalaxyClusterNewV3Tool::definition(), Box::new(TiMispGalaxyClusterNewV3Tool)),
        (TiMispFeedNewV4Tool::definition(), Box::new(TiMispFeedNewV4Tool)),
        (TiMispWorkflowNewV4Tool::definition(), Box::new(TiMispWorkflowNewV4Tool)),
        (TiMispObjectTemplateNewV4Tool::definition(), Box::new(TiMispObjectTemplateNewV4Tool)),
        (TiMispGalaxyClusterNewV4Tool::definition(), Box::new(TiMispGalaxyClusterNewV4Tool)),
        (TiMispSearchWithLimitV4Tool::definition(), Box::new(TiMispSearchWithLimitV4Tool)),
        (TiMispSearchWithThreatLevelV4Tool::definition(), Box::new(TiMispSearchWithThreatLevelV4Tool)),
        (TiMispSearchTagsV4Tool::definition(), Box::new(TiMispSearchTagsV4Tool)),
        (TiMispDistributionLevelAllValuesV4Tool::definition(), Box::new(TiMispDistributionLevelAllValuesV4Tool)),
        (TiMispThreatLevelAllValuesV4Tool::definition(), Box::new(TiMispThreatLevelAllValuesV4Tool)),
        (TiMispAnalysisLevelDisplayV4Tool::definition(), Box::new(TiMispAnalysisLevelDisplayV4Tool)),
        (TiMispWarningListAddEntriesV4Tool::definition(), Box::new(TiMispWarningListAddEntriesV4Tool)),
        (TiMispObjectFullAddAttrV4Tool::definition(), Box::new(TiMispObjectFullAddAttrV4Tool)),
        (TiMispAttributeFullIocTypeV4Tool::definition(), Box::new(TiMispAttributeFullIocTypeV4Tool)),
    ]
}
