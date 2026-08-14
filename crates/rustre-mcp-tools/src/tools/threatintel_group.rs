//! MCP wrappers for the rustre-threatintel_group crate.
//! Extracted from wire_tools.rs by workflow_split_wire_tools.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct ThreatintelGroupSearchTool;

pub struct ThreatintelGroupAliasesTool;

pub struct ThreatintelGroupListKnownTool;

pub struct ThreatintelGroupInsertCustomW3Tool;
impl ThreatintelGroupInsertCustomW3Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_group_insert_custom_w3".to_string(),
            description: "Insert custom ThreatGroup with alias+ttp via rustre_threatintel::ThreatGroupTracker::insert.".to_string(),
            input_schema: json!({"type":"object","properties":{"name":{"type":"string"},"alias":{"type":"string"},"ttp":{"type":"string"}},"required":["name"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelGroupInsertCustomW3Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".into()))?;
        let alias = args.get("alias").and_then(Value::as_str).unwrap_or("");
        let ttp = args.get("ttp").and_then(Value::as_str).unwrap_or("");
        let mut g = rustre_threatintel::ThreatGroup::new(name);
        if !alias.is_empty() { g = g.with_alias(alias); }
        if !ttp.is_empty() { g = g.with_ttp(ttp); }
        let mut tracker = rustre_threatintel::ThreatGroupTracker::new();
        tracker.insert(g);
        let found = tracker.get(name).map(|g| json!({
            "name": g.name, "aliases": g.aliases, "ttps": g.ttps }));
        Ok(ToolResult::text(json!({"inserted": found,
            "source": "rustre_threatintel::ThreatGroupTracker::insert"}).to_string()))
    }
}

pub struct ThreatintelGroupLinkIocW3Tool;
impl ThreatintelGroupLinkIocW3Tool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_group_link_ioc_w3".to_string(),
            description: "Link an IOC to a group via rustre_threatintel::ThreatGroup::link_ioc + tracker.get_mut.".to_string(),
            input_schema: json!({"type":"object","properties":{"group":{"type":"string"},"value":{"type":"string"}},"required":["group","value"]}),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelGroupLinkIocW3Tool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let group = args.get("group").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'group'".into()))?;
        let value = args.get("value").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'value'".into()))?;
        let mut db = rustre_threatintel::ThreatIndicatorDatabase::new();
        let id = db.add_ioc(rustre_threatintel::ThreatIoc::new(
            rustre_threatintel::IocType::Sha256, value, "n", 0.5, "s"));
        let mut tracker = rustre_threatintel::ThreatGroupTracker::new();
        tracker.insert(rustre_threatintel::ThreatGroup::new(group));
        let linked = if let Some(g) = tracker.get_mut(group) {
            g.link_ioc(id); g.iocs.len()
        } else { 0 };
        Ok(ToolResult::text(json!({"group": group, "ioc_id": id.0, "iocs_len": linked,
            "source": "rustre_threatintel::ThreatGroup::link_ioc"}).to_string()))
    }
}

pub struct ThreatintelGroupInsertCustomTool;
impl ThreatintelGroupInsertCustomTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_group_insert_custom".to_string(),
            description:
                "Insert a custom ThreatGroup with optional alias and TTP into a fresh \
                 ThreatGroupTracker via rustre_threatintel::ThreatGroupTracker::insert."
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "alias": { "type": "string" },
                    "ttp": { "type": "string" }
                },
                "required": ["name"]
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelGroupInsertCustomTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let name = args.get("name").and_then(Value::as_str)
            .ok_or_else(|| McpError::InvalidParams("missing 'name'".to_string()))?;
        let alias = args.get("alias").and_then(Value::as_str).unwrap_or("");
        let ttp = args.get("ttp").and_then(Value::as_str).unwrap_or("");
        let mut group = rustre_threatintel::ThreatGroup::new(name);
        if !alias.is_empty() {
            group = group.with_alias(alias);
        }
        if !ttp.is_empty() {
            group = group.with_ttp(ttp);
        }
        let mut tracker = rustre_threatintel::ThreatGroupTracker::new();
        tracker.insert(group);
        let stored = tracker.get(name);
        Ok(ToolResult::text(json!({
            "name": name,
            "found": stored.is_some(),
            "aliases": stored.map(|g| g.aliases.clone()).unwrap_or_default(),
            "ttps": stored.map(|g| g.ttps.clone()).unwrap_or_default(),
            "source": "rustre_threatintel::ThreatGroupTracker::insert",
        }).to_string()))
    }
}

pub struct ThreatintelGroupLinkIocTool;

pub struct ThreatintelGroupTrackerKnownCountTool;

pub struct ThreatintelGroupTrackerSearchTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ThreatintelGroupSearchTool::definition(), Box::new(ThreatintelGroupSearchTool)),
        (ThreatintelGroupAliasesTool::definition(), Box::new(ThreatintelGroupAliasesTool)),
        (ThreatintelGroupListKnownTool::definition(), Box::new(ThreatintelGroupListKnownTool)),
        (ThreatintelGroupInsertCustomW3Tool::definition(), Box::new(ThreatintelGroupInsertCustomW3Tool)),
        (ThreatintelGroupLinkIocW3Tool::definition(), Box::new(ThreatintelGroupLinkIocW3Tool)),
        (ThreatintelGroupInsertCustomTool::definition(), Box::new(ThreatintelGroupInsertCustomTool)),
        (ThreatintelGroupLinkIocTool::definition(), Box::new(ThreatintelGroupLinkIocTool)),
        (ThreatintelGroupTrackerKnownCountTool::definition(), Box::new(ThreatintelGroupTrackerKnownCountTool)),
        (ThreatintelGroupTrackerSearchTool::definition(), Box::new(ThreatintelGroupTrackerSearchTool)),
    ]
}
