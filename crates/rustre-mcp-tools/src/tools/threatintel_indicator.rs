//! MCP wrappers for the rustre-threatintel_indicator crate.
//! Extracted from `wire_tools.rs` by `workflow_split_wire_tools`.

use rustre_mcp_server::{McpError, ToolDefinition, ToolHandler, ToolResult};
use serde_json::{json, Value};
use async_trait::async_trait;

pub struct ThreatintelIndicatorLookupTool;

pub struct ThreatintelIndicatorExportStixTool;

pub struct ThreatintelIndicatorDbStatsTool;
impl ThreatintelIndicatorDbStatsTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_indicator_db_stats".to_string(),
            description:
                "Return is_empty/len before and after inserting N SHA-256 IOCs into a \
                 fresh rustre_threatintel::ThreatIndicatorDatabase."
                    .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "count": { "type": "integer" } }
            }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelIndicatorDbStatsTool {
    async fn call(&self, args: Value) -> Result<ToolResult, McpError> {
        let count = args.get("count").and_then(Value::as_u64).unwrap_or(3);
        let mut db = rustre_threatintel::ThreatIndicatorDatabase::new();
        let empty_before = db.is_empty();
        let len_before = db.len();
        for i in 0..count {
            db.add_ioc(rustre_threatintel::ThreatIoc::new(
                rustre_threatintel::IocType::Sha256,
                format!("hash{i:016x}"),
                "wire-stats",
                0.5,
                "wire-tool",
            ));
        }
        Ok(ToolResult::text(json!({
            "requested": count,
            "empty_before": empty_before,
            "len_before": len_before,
            "empty_after": db.is_empty(),
            "len_after": db.len(),
            "source": "rustre_threatintel::ThreatIndicatorDatabase::{is_empty,len}",
        }).to_string()))
    }
}

pub struct ThreatintelIndicatorDbGetRoundtripTool;
impl ThreatintelIndicatorDbGetRoundtripTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_indicator_db_get_roundtrip".to_string(),
            description: "Insert then fetch via ThreatIndicatorDatabase::get.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelIndicatorDbGetRoundtripTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut db = rustre_threatintel::ThreatIndicatorDatabase::new();
        let id = db.add_ioc(rustre_threatintel::ThreatIoc::new(
            rustre_threatintel::IocType::Md5, "abc", "Nx", 0.7, "src",
        ));
        let got = db.get(id);
        Ok(ToolResult::text(json!({
            "found": got.is_some(),
            "threat_name": got.map(|g| g.threat_name.clone()),
            "source": "rustre_threatintel::ThreatIndicatorDatabase::get",
        }).to_string()))
    }
}

pub struct ThreatintelIndicatorDbDuplicateLookupTool;
impl ThreatintelIndicatorDbDuplicateLookupTool {
    #[must_use]
    pub fn definition() -> ToolDefinition {
        ToolDefinition {
            name: "threatintel_indicator_db_duplicate_lookup".to_string(),
            description: "Insert same value twice; verify lookup returns both entries.".to_string(),
            input_schema: json!({ "type": "object", "properties": {} }),
            parameters: Value::Null,
        }
    }
}
#[async_trait]
impl ToolHandler for ThreatintelIndicatorDbDuplicateLookupTool {
    async fn call(&self, _args: Value) -> Result<ToolResult, McpError> {
        let mut db = rustre_threatintel::ThreatIndicatorDatabase::new();
        db.add_ioc(rustre_threatintel::ThreatIoc::new(
            rustre_threatintel::IocType::Sha1, "dup", "a", 0.5, "s1"));
        db.add_ioc(rustre_threatintel::ThreatIoc::new(
            rustre_threatintel::IocType::Sha1, "dup", "b", 0.5, "s2"));
        let hits = db.lookup("dup").len();
        let miss = db.lookup("nope").len();
        Ok(ToolResult::text(json!({
            "hits": hits, "miss": miss, "total_len": db.len(),
            "source": "rustre_threatintel::ThreatIndicatorDatabase::lookup",
        }).to_string()))
    }
}

pub struct ThreatintelIndicatorDbIsEmptyTool;

pub struct ThreatintelIndicatorGetByIdTool;

pub struct ThreatintelIndicatorDbLookupTool;

pub fn handlers() -> Vec<(ToolDefinition, Box<dyn ToolHandler>)> {
    vec![
        (ThreatintelIndicatorLookupTool::definition(), Box::new(ThreatintelIndicatorLookupTool)),
        (ThreatintelIndicatorExportStixTool::definition(), Box::new(ThreatintelIndicatorExportStixTool)),
        (ThreatintelIndicatorDbStatsTool::definition(), Box::new(ThreatintelIndicatorDbStatsTool)),
        (ThreatintelIndicatorDbGetRoundtripTool::definition(), Box::new(ThreatintelIndicatorDbGetRoundtripTool)),
        (ThreatintelIndicatorDbDuplicateLookupTool::definition(), Box::new(ThreatintelIndicatorDbDuplicateLookupTool)),
        (ThreatintelIndicatorDbIsEmptyTool::definition(), Box::new(ThreatintelIndicatorDbIsEmptyTool)),
        (ThreatintelIndicatorGetByIdTool::definition(), Box::new(ThreatintelIndicatorGetByIdTool)),
        (ThreatintelIndicatorDbLookupTool::definition(), Box::new(ThreatintelIndicatorDbLookupTool)),
    ]
}
